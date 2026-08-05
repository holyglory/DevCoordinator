#!/usr/bin/env python3
"""Focused state-machine tests for rollback-safe Docker admission."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Mapping, Sequence
from types import SimpleNamespace
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/manage_docker_admission.py"
SPEC = importlib.util.spec_from_file_location("manage_docker_admission", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(callable_object, text: str) -> None:
    try:
        callable_object()
    except MODULE.DockerAdmissionError as error:
        expect(text in str(error), f"unexpected error: {error}")
    else:
        raise AssertionError(f"expected DockerAdmissionError containing {text!r}")


def request_document(operation_id: str) -> dict[str, Any]:
    return MODULE._seal(
        {
            "schema_version": 1,
            "kind": MODULE.REQUEST_KIND,
            "operation_id": operation_id,
            "docker_group": "docker",
            "socket_paths": ["/run/docker.sock"],
            "protected_profile": {
                "path": "/etc/devcoordinator/client-profiles.json",
                "sha256": "b" * 64,
                "clients_sha256": "c" * 64,
                "client_uids": [1001],
            },
            "clients": [
                {
                    "user": "agent",
                    "uid": 1001,
                    "primary_gid": 1001,
                    "project": "/srv/project",
                    "repository_id": "repo-1",
                    "repository_generation": 7,
                }
            ],
            "acl_grants": [
                {"path": "/run/docker.sock", "tag": "user", "qualifier": 1001}
            ],
            "broker_canary": {
                "client_path": "/opt/devcoordinator/releases/" + "a" * 64 + "/skills/codex-dev-coordinator/scripts/dev_coordinator.py",
                "broker_socket": "/run/devcoordinator-authority.sock",
                "user": "agent",
                "uid": 1001,
                "primary_gid": 1001,
                "project": "/srv/project",
                "repository_id": "repo-1",
                "repository_generation": 7,
                "authority_generation": "generation-1",
                "profile_sha256": "b" * 64,
                "release_digest": "a" * 64,
                "client_sha256": "d" * 64,
                "manifest_sha256": "e" * 64,
            },
        }
    )


class FakeHost:
    def __init__(self) -> None:
        self.group = True
        self.acl = True
        self.retained = True
        self.connection = False
        self.issue: str | None = None
        self.socket_inode = 22
        self.socket_ctime = 100
        self.mutations: list[list[str]] = []
        self.failpoint_name: str | None = None
        self.failed_once = False

    def observation(self, request: Mapping[str, Any]) -> dict[str, Any]:
        client = {
            "user": "agent",
            "uid": 1001,
            "primary_gid": 1001,
            "supplementary_gids": [1001, 999] if self.group else [1001],
            "supplementary_groups": ["agent", "docker"] if self.group else ["agent"],
            "docker_group_configured": self.group,
        }
        acl_entries = [
            {"tag": "user", "qualifier": "", "permissions": "rw-"},
            {"tag": "user", "qualifier": "1001", "permissions": "rw-"},
            {"tag": "group", "qualifier": "", "permissions": "rw-"},
            {"tag": "mask", "qualifier": "", "permissions": "rw-"},
            {"tag": "other", "qualifier": "", "permissions": "---"},
        ]
        if not self.acl:
            acl_entries = [item for item in acl_entries if not (item["tag"] == "user" and item["qualifier"] == "1001")]
        actions: list[dict[str, Any]] = []
        if self.group:
            actions.append(
                {
                    "kind": "nss_group_remove",
                    "user": "agent",
                    "uid": 1001,
                    "group": "docker",
                    "argv": ["/usr/bin/gpasswd", "-d", "agent", "docker"],
                }
            )
        if self.acl:
            actions.append(
                {
                    "kind": "acl_remove",
                    "path": "/run/docker.sock",
                    "tag": "user",
                    "qualifier": 1001,
                    "permissions": "rw-",
                    "argv": ["/usr/bin/setfacl", "-x", "u:1001", "--", "/run/docker.sock"],
                }
            )
        socket_identity = {
            "path": "/run/docker.sock",
            "resolved": "/run/docker.sock",
            "device": 1,
            "inode": self.socket_inode,
            "uid": 0,
            "gid": 999,
            "mode": 0o660,
            "ctime_ns": self.socket_ctime,
        }
        configured = {
            "docker_group_gid": 999,
            "docker_group_members": ["agent"] if self.group else [],
            "clients": [client],
            "sockets": [socket_identity],
            "acl_entries": {"/run/docker.sock": acl_entries},
            "missing_declared_acl_grants": [] if self.acl else [["/run/docker.sock", "user", "1001"]],
            "actions": actions,
        }
        processes = []
        if self.retained:
            processes.append(
                {
                    "pid": 501,
                    "start_ticks": 9001,
                    "uid": 1001,
                    "groups": [1001, 999],
                    "namespaces": {"mnt": "mnt:[1]", "net": "net:[1]", "user": "user:[1]"},
                    "docker_group_retained": True,
                    "docker_fds": [],
                }
            )
        connections = []
        if self.connection:
            connections.append({"pid": 502, "start_ticks": 9002, "fd": 7, "uid": 1001})
        return MODULE._seal(
            {
                "schema_version": 1,
                "kind": "devcoordinator-docker-admission-observation",
                "request_sha256": request["document_sha256"],
                "configured": configured,
                "configured_sha256": MODULE._configured_fingerprint(configured),
                "processes": processes,
                "docker_connections": connections,
                "issues": [] if self.issue is None else [self.issue],
                "observed_at_epoch": 1,
            }
        )

    def mutate(self, argv: Sequence[str]) -> None:
        command = list(argv)
        self.mutations.append(command)
        if command == ["/usr/bin/gpasswd", "-d", "agent", "docker"]:
            self.group = False
        elif command == ["/usr/bin/gpasswd", "-a", "agent", "docker"]:
            self.group = True
        elif command == ["/usr/bin/setfacl", "-x", "u:1001", "--", "/run/docker.sock"]:
            self.acl = False
            self.socket_ctime = 101
        elif command == ["/usr/bin/setfacl", "-m", "u:1001:rw-", "--", "/run/docker.sock"]:
            self.acl = True
            self.socket_ctime = 102
        else:
            raise AssertionError(f"unexpected command: {command}")

    def failpoint(self, name: str) -> None:
        if self.failpoint_name == name and not self.failed_once:
            self.failed_once = True
            raise RuntimeError(f"crash at {name}")

    @staticmethod
    def deny(client: Mapping[str, Any], socket_identity: Mapping[str, Any]) -> dict[str, Any]:
        return {"uid": client["uid"], "socket": socket_identity["resolved"], "denied": True, "errno": 13}

    @staticmethod
    def canary(canary: Mapping[str, Any]) -> dict[str, Any]:
        return {"ok": True, "authority_generation": canary["authority_generation"], "repository_id": canary["repository_id"]}

    def hooks(self) -> Any:
        return MODULE.ExecutionHooks(
            observe=self.observation,
            verify_profile=lambda request: {
                "profile_sha256": request["protected_profile"]["sha256"]
            },
            mutate=self.mutate,
            deny_connect=self.deny,
            broker_canary=self.canary,
            failpoint=self.failpoint,
        )


class Harness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.lock = root / "lock"
        self.claim_parent = root / "claims"
        self.claim_parent.mkdir(mode=0o700)
        self.claim = self.claim_parent / "claim.json"
        self.transaction = root / "transaction"
        self.request = request_document(str(uuid.uuid4()))

    def plan(self, host: FakeHost) -> dict[str, Any]:
        return MODULE.plan_transaction(
            self.request,
            transaction=self.transaction,
            hooks=host.hooks(),
            lock_path=self.lock,
            claim_path=self.claim,
        )

    def apply(self, host: FakeHost, plan: Mapping[str, Any]) -> dict[str, Any]:
        return MODULE.apply_transaction(
            transaction=self.transaction,
            plan_id=plan["plan_id"],
            plan_sha256=plan["plan_sha256"],
            hooks=host.hooks(),
            lock_path=self.lock,
            claim_path=self.claim,
        )

    def verify(self, host: FakeHost, apply: Mapping[str, Any]) -> dict[str, Any]:
        return MODULE.verify_transaction(
            transaction=self.transaction,
            apply_sha256=apply["apply_sha256"],
            hooks=host.hooks(),
            lock_path=self.lock,
            claim_path=self.claim,
        )

    def rollback(self, host: FakeHost, binding: str) -> dict[str, Any]:
        return MODULE.rollback_transaction(
            transaction=self.transaction,
            apply_sha256=binding,
            hooks=host.hooks(),
            lock_path=self.lock,
            claim_path=self.claim,
        )


def private_root() -> tempfile.TemporaryDirectory[str]:
    temporary = tempfile.TemporaryDirectory()
    os.chmod(temporary.name, 0o700)
    return temporary


def test_happy_convergence() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        expect(plan["ok"] and harness.claim.exists(), "ready plan did not retain the durable fence")
        applied = harness.apply(host, plan)
        expect(applied["classification"] == "awaiting_session_convergence", "apply did not expose convergence state")
        retained = harness.verify(host, applied)
        expect(not retained["ok"] and retained["retained_sessions"], "retained session did not block verification")
        expect(harness.claim.exists(), "retained session cleared the durable fence")
        host.retained = False
        verified = harness.verify(host, applied)
        expect(verified["ok"] and verified["classification"] == "broker_only", "converged admission was not verified")
        expect(not harness.claim.exists(), "successful verification retained the fence")


def test_exact_rollback() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        applied = harness.apply(host, plan)
        host.retained = False
        rolled = harness.rollback(host, applied["apply_sha256"])
        expect(rolled["ok"] and host.group and host.acl, "rollback did not restore exact grants")
        expect(not harness.claim.exists(), "rollback retained the fence")
        expect(host.mutations[-2:] == [
            ["/usr/bin/setfacl", "-m", "u:1001:rw-", "--", "/run/docker.sock"],
            ["/usr/bin/gpasswd", "-a", "agent", "docker"],
        ], "rollback command order or argv changed")


def test_apply_crash_replay() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        host.failpoint_name = "after-action-0"
        try:
            harness.apply(host, plan)
        except RuntimeError:
            pass
        else:
            raise AssertionError("apply failpoint did not fire")
        expect(harness.claim.exists() and not host.group, "crashed apply lost its durable state")
        replay = harness.apply(host, plan)
        expect(replay["ok"] and not host.acl, "apply replay did not converge uncertain mutation")


def test_rollback_crash_replay() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        applied = harness.apply(host, plan)
        host.failpoint_name = "after-rollback-action-1"
        try:
            harness.rollback(host, applied["apply_sha256"])
        except RuntimeError:
            pass
        else:
            raise AssertionError("rollback failpoint did not fire")
        expect(host.acl and not host.group and harness.claim.exists(), "rollback crash state was not retained")
        result = harness.rollback(host, applied["apply_sha256"])
        expect(result["ok"] and host.group and host.acl, "rollback replay did not restore grants")


def test_drift_and_connection_fail_closed() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        applied = harness.apply(host, plan)
        host.retained = False
        host.socket_inode += 1
        expect_error(lambda: harness.verify(host, applied), "recreated")
        expect(harness.claim.exists(), "verification drift cleared the fence")
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        plan = harness.plan(host)
        applied = harness.apply(host, plan)
        host.retained = False
        host.connection = True
        result = harness.verify(host, applied)
        expect(not result["ok"] and result["retained_sessions"][0]["reason"] == "open_docker_connection", "open connection did not block verification")


def test_blockers_and_contracts() -> None:
    with private_root() as name:
        harness = Harness(Path(name))
        host = FakeHost()
        host.issue = "custom Docker context"
        plan = harness.plan(host)
        expect(not plan["ok"] and plan["classification"] == "blocked", "incomplete host proof was not blocked")
        expect(not harness.claim.exists(), "blocked plan retained the global fence")
    invalid = request_document(str(uuid.uuid4()))
    invalid["docker_group"] = "wheel"
    invalid = MODULE._seal({key: value for key, value in invalid.items() if key != "document_sha256"})
    expect_error(lambda: MODULE._validate_request(invalid), "exact docker group")
    incomplete = request_document(str(uuid.uuid4()))
    incomplete["protected_profile"]["client_uids"] = [1001, 1002]
    incomplete = MODULE._seal(
        {key: value for key, value in incomplete.items() if key != "document_sha256"}
    )
    expect_error(
        lambda: MODULE._validate_request(incomplete),
        "complete protected profile client set",
    )
    action = {
        "kind": "nss_group_remove",
        "user": "agent",
        "uid": 1001,
        "group": "docker",
        "argv": ["/bin/sh", "-c", "id"],
    }
    expect_error(lambda: MODULE._validate_action(action), "fixed command")


def test_parsers() -> None:
    acl = MODULE._parse_acl("# file: /run/docker.sock\nuser::rw-\nuser:1001:rw-\ngroup::rw-\nmask::rw-\nother::---\n")
    expect(acl[1] == {"tag": "user", "qualifier": "1001", "permissions": "rw-"}, "ACL parser lost named UID")
    expect(MODULE._status_ids("Uid:\t1001\t1001\t1001\t1001\nGroups:\t1001 999\n") == (1001, [999, 1001]), "credential parser is wrong")
    stat_payload = "1 (worker name) S " + " ".join(str(index) for index in range(1, 30))
    expect(MODULE._proc_start(stat_payload) == 19, "PID start parser is wrong")
    hosts, contexts, errors = MODULE._docker_cli_options(
        ["docker", "--context", "remote", "-Htcp://example:2375", "ps"]
    )
    expect(hosts == ["tcp://example:2375"] and contexts == ["remote"] and not errors,
           "Docker CLI options were not parsed")
    issues = MODULE._process_context_issues(
        executable="/usr/bin/docker",
        argv=["docker", "--host=ssh://builder", "ps"],
        environment={"DOCKER_CONTEXT": "remote"},
        socket_paths={"/run/docker.sock"},
    )
    expect(
        "Docker CLI selects a custom --host/-H endpoint" in issues
        and "custom Docker context in DOCKER_CONTEXT" in issues,
        "custom Docker process authority was not rejected",
    )
    alternate = MODULE._process_context_issues(
        executable="/usr/bin/podman",
        argv=["podman", "ps"],
        environment={},
        socket_paths={"/run/docker.sock"},
    )
    expect(
        alternate == ["active alternate container engine client: podman"],
        "alternate engine client was not rejected",
    )


def test_anonymous_connection_fails_closed() -> None:
    stat_payload = "12 (dockerd) S " + " ".join(str(index) for index in range(1, 30))

    def proc_read(path: Path, *, binary: bool = False):
        del binary
        if path.name == "status":
            return "Uid:\t0\t0\t0\t0\nGroups:\t0\n"
        return stat_payload

    completed = SimpleNamespace(
        returncode=0,
        stdout=(
            'u_str ESTAB 0 0 /run/docker.sock 1 * 2 '
            'users:(("dockerd",pid=12,fd=3))\n'
        ),
        stderr="",
    )
    with mock.patch.object(MODULE, "_safe_executable", return_value=None), mock.patch.object(
        MODULE.subprocess, "run", return_value=completed
    ), mock.patch.object(MODULE, "_read_proc_file", side_effect=proc_read):
        connections, issues = MODULE._ss_connections({"/run/docker.sock"}, {1001})
    expect(not connections, "foreign Docker connection was attributed to a client")
    expect(
        "a connected Docker socket has an unattributed anonymous peer" in issues,
        "anonymous Docker peer did not fail closed",
    )


def test_request_producer_binds_complete_profile_and_release() -> None:
    operation_id = str(uuid.uuid4())
    draft = {
        "schema_version": 1,
        "kind": MODULE.REQUEST_DRAFT_KIND,
        "operation_id": operation_id,
        "docker_group": "docker",
        "socket_paths": ["/run/docker.sock"],
        "client_projects": [{"user": "agent", "project": "/srv/project"}],
        "acl_grants": [{"path": "/run/docker.sock", "tag": "user", "qualifier": 1001}],
        "protected_profile_path": "/etc/devcoordinator/client-profiles.json",
        "immutable_client_path": (
            "/opt/devcoordinator/releases/" + "a" * 64 +
            "/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        ),
        "broker_canary_user": "agent",
    }
    repository = SimpleNamespace(
        canonical_root="/srv/project",
        repo_id="repo-1",
        generation=7,
        owner_uid=1001,
    )
    profile = SimpleNamespace(
        repository=lambda project: repository if project == "/srv/project" else None,
        service=SimpleNamespace(
            socket_path=Path("/run/devcoordinator-authority.sock"),
            database_generation="generation-1",
        ),
    )
    binding = {
        "path": "/etc/devcoordinator/client-profiles.json",
        "sha256": "b" * 64,
        "clients_sha256": "c" * 64,
        "client_uids": [1001],
    }
    account = SimpleNamespace(pw_name="agent", pw_uid=1001, pw_gid=1001)
    proof = {
        "release_digest": "a" * 64,
        "client_sha256": "d" * 64,
        "manifest_sha256": "e" * 64,
    }
    with mock.patch.object(MODULE, "_profile_state", return_value=({}, binding, {1001: profile})), mock.patch.object(
        MODULE, "_release_client_proof", return_value=proof
    ), mock.patch.object(MODULE.pwd, "getpwnam", return_value=account), mock.patch.object(
        MODULE.pwd, "getpwuid", return_value=account
    ):
        request = MODULE.produce_sealed_request(draft)
    expect(
        request["protected_profile"] == binding
        and request["broker_canary"]["profile_sha256"] == binding["sha256"]
        and request["broker_canary"]["manifest_sha256"] == proof["manifest_sha256"],
        "request producer did not bind the protected profile and immutable release",
    )
    missing = dict(binding, client_uids=[1001, 1002])
    with mock.patch.object(MODULE, "_profile_state", return_value=({}, missing, {1001: profile})), mock.patch.object(
        MODULE.pwd, "getpwnam", return_value=account
    ):
        expect_error(
            lambda: MODULE.produce_sealed_request(draft),
            "does not cover every protected profile client",
        )


def test_profile_state_accepts_root_without_targeting_it_for_revocation() -> None:
    document = {
        "version": 1,
        "service": {},
        "clients": {"0": {"kind": "administrator"}, "1001": {"kind": "client"}},
    }
    raw = json.dumps(document, sort_keys=True).encode("utf-8")

    def profile_from_document(_document, *, effective_uid):
        return SimpleNamespace(client_uid=effective_uid)

    with mock.patch.object(MODULE, "_read_root_regular", return_value=raw), mock.patch.object(
        MODULE, "profile_from_document", side_effect=profile_from_document
    ):
        parsed, binding, profiles = MODULE._profile_state(
            Path("/etc/devcoordinator/client-profiles.json")
        )
    expect(parsed == document, "profile-state parser changed the protected profile")
    expect(
        sorted(profiles) == [0, 1001],
        "profile-state parser dropped the authenticated root administrator",
    )
    expect(
        binding["client_uids"] == [1001],
        "Docker admission targeted root for daemon-access revocation",
    )
    expect(
        binding["clients_sha256"] == MODULE._sha256(MODULE._canonical(document["clients"])),
        "Docker admission stopped binding the complete protected client set",
    )


def test_broker_canary_uses_profile_and_immutable_contract() -> None:
    canary = request_document(str(uuid.uuid4()))["broker_canary"]
    proof = {
        "release_digest": canary["release_digest"],
        "client_sha256": canary["client_sha256"],
        "manifest_sha256": canary["manifest_sha256"],
    }
    output = {
        "authority": {
            "scope": "server-wide",
            "transport": "authenticated-unix-socket",
            "generation": canary["authority_generation"],
        },
        "repositories": [
            {
                "repo_id": canary["repository_id"],
                "canonical_root": canary["project"],
                "generation": canary["repository_generation"],
                "owner_uid": canary["uid"],
            }
        ],
    }
    completed = SimpleNamespace(
        returncode=0,
        stdout=json.dumps(output),
        stderr="",
    )
    account = SimpleNamespace(pw_dir="/home/agent")
    with mock.patch.object(MODULE, "_require_immutable_client", return_value=proof), mock.patch.object(
        MODULE, "_safe_executable", return_value=None
    ), mock.patch.object(MODULE.pwd, "getpwuid", return_value=account), mock.patch.object(
        MODULE.subprocess, "run", return_value=completed
    ) as runner:
        result = MODULE._broker_canary_real(canary)
    command = runner.call_args.args[0]
    environment = runner.call_args.kwargs["env"]
    expect(
        command[:7] == [
            "/usr/bin/setpriv", "--reuid=1001", "--regid=1001", "--clear-groups",
            "/usr/bin/python3", "-I", "-B",
        ],
        "broker canary did not use the fixed isolated clean-group client command",
    )
    expect(
        "DEVCOORDINATOR_BROKER_SOCKET" not in environment
        and result["profile_sha256"] == canary["profile_sha256"],
        "broker canary bypassed or lost the protected profile binding",
    )
    drifted = dict(proof, client_sha256="f" * 64)
    with mock.patch.object(MODULE, "_require_immutable_client", return_value=drifted):
        expect_error(
            lambda: MODULE._broker_canary_real(canary),
            "no longer matches its sealed release",
        )
def main() -> int:
    # The transaction logic uses the exact current identity in its private
    # test fence. Root-only CLI enforcement is tested structurally; the suite
    # remains runnable in unprivileged build environments.
    original = MODULE._require_root
    MODULE._require_root = lambda: None
    try:
        test_happy_convergence()
        test_exact_rollback()
        test_apply_crash_replay()
        test_rollback_crash_replay()
        test_drift_and_connection_fail_closed()
        test_blockers_and_contracts()
        test_parsers()
        test_anonymous_connection_fails_closed()
        test_request_producer_binds_complete_profile_and_release()
        test_profile_state_accepts_root_without_targeting_it_for_revocation()
        test_broker_canary_uses_profile_and_immutable_contract()
    finally:
        MODULE._require_root = original
    print("Docker admission self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
