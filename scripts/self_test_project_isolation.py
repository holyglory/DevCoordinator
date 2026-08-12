#!/usr/bin/env python3
"""Checks for trusted-local project runtime isolation evidence.

Repository identifiers select inventory and cgroup boundaries only.  Every
repository runs under the one developer service account; no owner map,
membership, grant, or controller binding participates in capture or replay.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dev_coordinator  # noqa: E402
from devcoordinator import project_runtime_isolation as isolation  # noqa: E402
from devcoordinator.broker_host import _compose_isolation_override  # noqa: E402
from devcoordinator.schema import SCHEMA_VERSION  # noqa: E402
from devcoordinator.worker_native import project_repository_slice  # noqa: E402


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _capture(
    *,
    metadata: dict[str, object],
    resources: list[dict[str, object]],
    execution_uid: int,
    docker_parent: str,
    process_parent: str,
    boot_id: str,
    now: datetime,
) -> dict[str, object]:
    connection = SimpleNamespace(close=lambda: None)
    contexts = {str(row["repo_id"]): execution_uid for row in resources}
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=metadata),
        mock.patch.object(
            isolation, "_repository_execution_context", return_value=contexts
        ),
        mock.patch.object(isolation, "_active_resources", return_value=resources),
    ):
        return isolation.capture_isolation_audit(
            database_path=Path("/private/authority.db"),
            docker_cgroup_reader=lambda identities: {
                identities[0]: {"cgroup_parent": docker_parent, "running": True}
            },
            process_cgroup_reader=lambda _identity: process_parent,
            boot_id_reader=lambda: boot_id,
            now=lambda: now,
        )


def main() -> int:
    execution_uid = 501
    repository_slice = project_repository_slice(
        uid=execution_uid, repository_id="repo-one"
    )
    expect(
        repository_slice.startswith("devcoordinator-projects-uid501-repo")
        and repository_slice.endswith(".slice"),
        "repository runtime did not receive a bounded cgroup slice",
    )
    expect(
        repository_slice
        != project_repository_slice(uid=execution_uid, repository_id="repo-two"),
        "different repositories share one cgroup leaf",
    )

    launch = dev_coordinator.LaunchSpec(
        argv=("/usr/bin/false",),
        cwd=str(ROOT),
        env_extra={},
        agent="self-test",
        project=str(ROOT),
        source="self-test",
    )
    with (
        mock.patch.dict(os.environ, {"DEVCOORDINATOR_ROLE": "api"}),
        mock.patch.object(dev_coordinator.subprocess, "Popen") as popen,
    ):
        try:
            dev_coordinator.start_process(launch=launch, server_id="server-one")
        except RuntimeError as error:
            expect("forbidden" in str(error), "control-plane launch failed unexpectedly")
        else:
            raise AssertionError("control-plane service launched a project process")
        popen.assert_not_called()

    override = json.loads(
        _compose_isolation_override(
            SimpleNamespace(
                owner_uid=execution_uid,
                repo_id="repo-one",
                services=("api", "worker"),
            )
        )
    )
    expect(
        set(override["services"]) == {"api", "worker"},
        "Compose isolation did not cover all selected services",
    )
    for policy in override["services"].values():
        expect(
            policy["cgroup_parent"] == repository_slice
            and policy["mem_limit"] == "20g"
            and policy["cpus"] == "8.0"
            and policy["pids_limit"] == 4096,
            "Compose isolation omitted a runtime resource ceiling",
        )

    inspect_commands: list[tuple[str, ...]] = []

    def hostile_inspect(
        command: tuple[str, ...], *, timeout_seconds: float, maximum_bytes: int
    ) -> tuple[int, bytes]:
        inspect_commands.append(command)
        return 0, (
            b'{"Id":"'
            + b"a" * 64
            + b'","CgroupParent":"legacy.slice","Running":true,'
            + b'"Env":["SECRET_CANARY=do-not-retain"]}\n'
        )

    with (
        mock.patch.object(
            isolation, "_safe_docker_executable", return_value=Path("/usr/bin/docker")
        ),
        mock.patch.object(
            isolation, "_bounded_command_stdout", side_effect=hostile_inspect
        ),
    ):
        expect(
            isolation.inspect_docker_cgroups(("a" * 64,)) == {},
            "Docker isolation accepted unexpected secret-bearing inspect fields",
        )
    expect(
        len(inspect_commands) == 1
        and ".Config" not in inspect_commands[0][3]
        and ".Mounts" not in inspect_commands[0][3]
        and ".Labels" not in inspect_commands[0][3],
        "Docker isolation requested secret-bearing runtime metadata",
    )

    returncode, excess = isolation._bounded_command_stdout(
        (sys.executable, "-c", "import os; os.write(1, b'x' * 131072)"),
        timeout_seconds=5,
        maximum_bytes=1024,
    )
    expect(
        excess is None and returncode != 0,
        "Docker isolation retained output beyond its hard byte cap",
    )

    authority = mock.MagicMock()
    authority.execute.return_value.fetchall.return_value = [
        {"repo_id": "repo-one"},
        {"repo_id": "repo-two"},
    ]
    with mock.patch.object(isolation.os, "geteuid", return_value=execution_uid):
        expect(
            isolation._repository_execution_uids(authority)
            == {"repo-one": execution_uid, "repo-two": execution_uid},
            "repository runtime contexts are not host-wide developer contexts",
        )
    source = inspect.getsource(isolation)
    for obsolete in (
        "repository_owner_uids",
        "repository_owner_map",
        "repository_membership",
        "control_binding",
        "source_permission",
    ):
        expect(obsolete not in source, f"isolation still references {obsolete}")

    fixed_now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    docker_id = "a" * 64
    replacement_docker_id = "b" * 64
    process_fingerprint = "sha256:" + "c" * 64
    boot_id = str(uuid.UUID("11111111-2222-4333-8444-555555555555"))
    metadata: dict[str, object] = {
        "source_schema_version": SCHEMA_VERSION,
        "database_generation": "generation-one",
        "state_revision": 8,
        "observation_revision": 13,
        "host_id": "host-one",
    }

    def resource_rows(*, container_id: str = docker_id) -> list[dict[str, object]]:
        return [
            {
                "resource_kind": "docker",
                "resource_id": "docker-one",
                "repo_id": "repo-one",
                "execution_uid": execution_uid,
                "runtime_identity": {"full_container_id": container_id},
                "identity_observable": True,
            },
            {
                "resource_kind": "service",
                "resource_id": "service-one",
                "repo_id": "repo-two",
                "execution_uid": execution_uid,
                "runtime_identity": {
                    "attempt_id": "attempt-one",
                    "pid": 2345,
                    "process_start_time": "123456",
                    "process_fingerprint": process_fingerprint,
                },
                "identity_observable": True,
            },
        ]

    process_parent = (
        "/devcoordinator-projects.slice/"
        + project_repository_slice(uid=execution_uid, repository_id="repo-two")
        + "/service.scope"
    )
    audit = _capture(
        metadata=metadata,
        resources=resource_rows(),
        execution_uid=execution_uid,
        docker_parent="legacy.slice",
        process_parent=process_parent,
        boot_id=boot_id,
        now=fixed_now,
    )
    expect(
        audit["counts"]
        == {"compliant": 1, "legacy_requires_recreation": 1, "unobservable": 0},
        "live isolation audit did not classify legacy resources",
    )
    expect(
        audit["source_schema_version"] == SCHEMA_VERSION
        and audit["project_isolation_complete"] is False,
        "isolation evidence is not bound to the current authority schema",
    )
    expect(
        not any(
            key in audit
            for key in (
                "repository_owner_map_sha256",
                "memberships",
                "control_bindings",
                "controller_permissions",
            )
        ),
        "isolation evidence leaked obsolete repository access state",
    )

    connection = SimpleNamespace(close=lambda: None)
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=metadata),
        mock.patch.object(
            isolation,
            "_repository_execution_context",
            return_value={"repo-one": execution_uid, "repo-two": execution_uid},
        ),
    ):
        expect(
            isolation.verify_live_authority_binding(
                audit, database_path=Path("/private/authority.db")
            )["evidence_sha256"]
            == audit["evidence_sha256"],
            "retained isolation audit did not recheck live inventory identity",
        )

    changed_metadata = {**metadata, "state_revision": 9}
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=changed_metadata),
        mock.patch.object(
            isolation,
            "_repository_execution_context",
            return_value={"repo-one": execution_uid, "repo-two": execution_uid},
        ),
    ):
        try:
            isolation.verify_live_authority_binding(
                audit, database_path=Path("/private/authority.db")
            )
        except isolation.ProjectIsolationError:
            pass
        else:
            raise AssertionError("retained isolation audit accepted changed authority")

    ledger = isolation.create_migration_ledger(
        audit,
        deadline=fixed_now + timedelta(hours=12),
        now=fixed_now,
    )
    expect(
        ledger["counts"] == {"pending": 1, "completed": 0, "retired": 0},
        "legacy resource did not create a migration ledger entry",
    )

    replacement_audit = _capture(
        metadata=metadata,
        resources=resource_rows(container_id=replacement_docker_id),
        execution_uid=execution_uid,
        docker_parent=repository_slice,
        process_parent=process_parent,
        boot_id=boot_id,
        now=fixed_now + timedelta(minutes=1),
    )
    operation_id = str(uuid.UUID("22222222-3333-4444-8555-666666666666"))
    completed = isolation.record_migration(
        ledger,
        audit=replacement_audit,
        resource_kind="docker",
        resource_id="docker-one",
        operation_id=operation_id,
        outcome="completed",
        now=fixed_now + timedelta(minutes=1),
    )
    expect(
        completed["counts"] == {"pending": 0, "completed": 1, "retired": 0},
        "replacement identity did not complete the exact migration entry",
    )
    expect(
        isolation.record_migration(
            completed,
            audit=replacement_audit,
            resource_kind="docker",
            resource_id="docker-one",
            operation_id=operation_id,
            outcome="completed",
        )["evidence_sha256"]
        == completed["evidence_sha256"],
        "idempotent migration acknowledgement changed its evidence",
    )

    unobservable = json.loads(json.dumps(audit))
    unobservable["resources"][0]["observed_cgroup"] = None
    unobservable["resources"][0]["classification"] = "unobservable"
    unobservable["resources"][0]["reason_code"] = "cgroup_observation_unavailable"
    unobservable["counts"] = {
        "compliant": 1,
        "legacy_requires_recreation": 0,
        "unobservable": 1,
    }
    unobservable["project_isolation_complete"] = False
    unobservable.pop("evidence_sha256")
    unobservable = isolation._with_fingerprint(unobservable)
    try:
        isolation.create_migration_ledger(
            unobservable,
            deadline=fixed_now + timedelta(hours=12),
            now=fixed_now,
        )
    except isolation.ProjectIsolationError:
        pass
    else:
        raise AssertionError("unobservable resource admitted a migration ledger")

    with tempfile.TemporaryDirectory() as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        audit_file = private / "audit.json"
        isolation.write_private_document(audit_file, audit)
        expect(
            isolation.read_private_document(audit_file)["evidence_sha256"]
            == audit["evidence_sha256"],
            "private isolation evidence did not round-trip",
        )
        try:
            isolation.write_private_document(audit_file, audit)
        except isolation.ProjectIsolationError:
            pass
        else:
            raise AssertionError("isolation evidence publication clobbered a file")

    print("project isolation self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
