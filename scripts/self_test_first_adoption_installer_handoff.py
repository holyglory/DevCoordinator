#!/usr/bin/env python3
"""Focused normal/optimized checks for the first-adoption installer handoff."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile
import time
from types import SimpleNamespace
from unittest import mock
import uuid

import activate_availability_release as activation


RELEASE_DIGEST = "a" * 64
RELEASE = Path("/opt/devcoordinator/releases") / RELEASE_DIGEST
OPERATION_ID = str(uuid.uuid4())
OWNER_UID = max(1, os.geteuid())
COLLABORATOR_UID = OWNER_UID + 10000
ALTERNATE_COLLABORATOR_UID = COLLABORATOR_UID + 1
CANONICAL_PROJECT = "/srv/devcoordinator-canaries/primary"
CANONICAL_REPOSITORY_ID = "82cf1649-48fc-50aa-a305-53232c897eba"
OWNER_USER = "canaryOwner"
COLLABORATOR_USER = "canaryCollaborator"


def target_argv() -> list[str]:
    return [
        "--canonical-project",
        CANONICAL_PROJECT,
        "--canonical-repository-id",
        CANONICAL_REPOSITORY_ID,
        "--owner-user",
        OWNER_USER,
        "--collaborator-user",
        COLLABORATOR_USER,
    ]


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_activation_error(call, text: str) -> None:
    try:
        call()
    except activation.ActivationError as error:
        expect(text in str(error), f"unexpected activation error: {error}")
    else:
        raise RuntimeError(f"expected ActivationError containing {text!r}")


def test_target_validation() -> None:
    with mock.patch.object(
        activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
    ):
        target = activation._final_hard_gate_target(
            canonical_project=CANONICAL_PROJECT,
            canonical_repository_id=CANONICAL_REPOSITORY_ID,
            owner_user=OWNER_USER,
            collaborator_user=COLLABORATOR_USER,
        )
        expect(
            target["canonical_project"] == CANONICAL_PROJECT
            and target["canonical_repository_id"] == CANONICAL_REPOSITORY_ID,
            "explicit hard-gate target changed",
        )
        expect_activation_error(
            lambda: activation._final_hard_gate_target(
                canonical_project="relative/project",
                canonical_repository_id=CANONICAL_REPOSITORY_ID,
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "canonical project is invalid",
        )
        expect_activation_error(
            lambda: activation._final_hard_gate_target(
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=CANONICAL_REPOSITORY_ID.upper(),
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "repository ID is invalid",
        )
        expect_activation_error(
            lambda: activation._final_hard_gate_target(
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=CANONICAL_REPOSITORY_ID,
                owner_user=OWNER_USER,
                collaborator_user=OWNER_USER,
            ),
            "user identities are invalid",
        )


def repository_document(*, account_id: str) -> dict[str, object]:
    return {
        "canonical_root": CANONICAL_PROJECT,
        "repo_id": CANONICAL_REPOSITORY_ID,
        "generation": 17,
        "owner_uid": OWNER_UID,
        "servers": {},
        "containers": {},
        "compose_definition_id": None,
        "account_id": account_id,
        "enabled": True,
        "issued_at": "2026-07-29T00:00:00Z",
        "valid_until_epoch": int(time.time()) + 3600,
    }


def profile_document(*, service_uid: int, service_gid: int) -> dict[str, object]:
    expiry = int(time.time()) + 3600
    clients: dict[str, object] = {}
    for uid, account_id in (
        (OWNER_UID, "owner-account"),
        (COLLABORATOR_UID, "collaborator-account"),
    ):
        clients[str(uid)] = {
            "account_id": account_id,
            "issued_at": "2026-07-29T00:00:00Z",
            "valid_until_epoch": expiry,
            "repositories": [repository_document(account_id=account_id)],
        }
    return {
        "version": 1,
        "service": {
            "socket": activation.cutover.AUTHORITY_SOCKET_PATH,
            "uid": service_uid,
            "gid": service_gid,
            "mode": "0660",
            "database_generation": "schema13-generation",
        },
        "clients": clients,
    }


def fake_passwd(name: str, *, home_root: Path | None = None):
    if name == OWNER_USER:
        uid = OWNER_UID
    elif name == COLLABORATOR_USER:
        uid = COLLABORATOR_UID
    elif name == "alternateCollaborator":
        uid = ALTERNATE_COLLABORATOR_UID
    else:
        raise KeyError(name)
    home = Path(f"/home/{name}") if home_root is None else home_root / name
    return pwd.struct_passwd((name, "x", uid, os.getegid(), "", str(home), "/bin/bash"))


def inventory() -> dict[str, object]:
    return {
        "schema_version": 2,
        "authority": {
            "scope": "server-wide",
            "transport": "authenticated-unix-socket",
            "socket": activation.cutover.AUTHORITY_SOCKET_PATH,
            "service_uid": 0,
            "database_generation": "schema13-generation",
        },
        "repositories": [
            {
                "canonical_root": CANONICAL_PROJECT,
                "repo_id": CANONICAL_REPOSITORY_ID,
                "generation": 17,
            }
        ],
    }


def test_profile_contract(root: Path) -> None:
    profile_parent = root / "profile"
    profile_parent.mkdir(mode=0o700)
    profile = profile_parent / "client-profiles.json"
    document = profile_document(
        service_uid=os.geteuid(), service_gid=os.getegid()
    )
    profile.write_text(json.dumps(document), encoding="utf-8")
    profile.chmod(0o640)
    with mock.patch.object(
        activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
    ):
        result = activation._validate_final_hard_gate_profile(
            profile,
            expected_uid=os.geteuid(),
            canonical_project=CANONICAL_PROJECT,
            canonical_repository_id=CANONICAL_REPOSITORY_ID,
            owner_user=OWNER_USER,
            collaborator_user=COLLABORATOR_USER,
        )
    expect(result["repository_generation"] == 17, "profile generation changed")
    expect(result["owner_uid"] == OWNER_UID, "profile owner changed")
    broken = profile_document(
        service_uid=os.geteuid(), service_gid=os.getegid()
    )
    broken["clients"][str(OWNER_UID)]["repositories"][0].pop("owner_uid")
    profile.write_text(json.dumps(broken), encoding="utf-8")
    profile.chmod(0o640)
    with mock.patch.object(
        activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
    ):
        expect_activation_error(
            lambda: activation._validate_final_hard_gate_profile(
                profile,
                expected_uid=os.geteuid(),
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=CANONICAL_REPOSITORY_ID,
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "strict all-client parsing",
        )


def test_skill_links(root: Path) -> None:
    source_root = root / "source-skills"
    home_root = root / "homes"
    for skill in activation.FINAL_HARD_GATE_SKILLS:
        (source_root / skill).mkdir(parents=True)
    for user in (OWNER_USER, COLLABORATOR_USER):
        for relative in activation.FINAL_HARD_GATE_SKILL_ROOTS:
            install = home_root / user / relative
            install.mkdir(parents=True)
            for skill in activation.FINAL_HARD_GATE_SKILLS:
                (install / skill).symlink_to(source_root / skill)
    with (
        mock.patch.object(activation, "CANONICAL_SKILL_SOURCE_ROOT", source_root),
        mock.patch.object(
            activation.pwd,
            "getpwnam",
            side_effect=lambda name: fake_passwd(name, home_root=home_root),
        ),
    ):
        links = activation._validate_final_hard_gate_skill_links(
            owner_user=OWNER_USER,
            collaborator_user=COLLABORATOR_USER,
        )
        expect(len(links) == 8, "canonical installed link set changed")
        first = Path(links[0]["link"])
        first.unlink()
        first.symlink_to(source_root / activation.FINAL_HARD_GATE_SKILLS[1])
        expect_activation_error(
            lambda: activation._validate_final_hard_gate_skill_links(
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "installed canonical skill link is invalid",
        )


class UnitRunner:
    def __init__(self, unit_root: Path, release: Path) -> None:
        self.unit_root = unit_root
        self.release = release

    def text(self, command: list[str]) -> str:
        unit = command[2]
        fragment_name = (
            "devcoordinator-console@.service"
            if unit.startswith("devcoordinator-console@")
            else unit
        )
        fragment = self.unit_root / fragment_name
        return "\n".join(
            (
                "LoadState=loaded",
                "ActiveState=active",
                "UnitFileState="
                + ("static" if unit.startswith("devcoordinator-console@") else "enabled"),
                f"FragmentPath={fragment}",
            )
        )

    def status(self, command: list[str]) -> int:
        expect(command[-1] == activation.FINAL_HARD_GATE_LEGACY_UNIT, "unexpected status unit")
        return 3


def test_units(root: Path) -> None:
    unit_root = root / "units"
    unit_root.mkdir(mode=0o755)
    units = set(activation.SOCKET_UNITS) | set(
        activation.cutover._candidate_units(RELEASE_DIGEST)
    )
    for unit in units:
        name = (
            "devcoordinator-console@.service"
            if unit.startswith("devcoordinator-console@")
            else unit
        )
        path = unit_root / name
        if path.exists():
            continue
        body = "[Unit]\n"
        if unit.endswith(".service"):
            body += f"ExecStart={RELEASE}/bin/service\n"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o644)
    runner = UnitRunner(unit_root, RELEASE)
    with mock.patch.object(activation, "SYSTEMD_UNIT_ROOT", unit_root):
        evidence = activation._final_hard_gate_units(
            release=RELEASE,
            runner=runner,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
    expect(set(evidence) == units, "final unit evidence changed")


def test_hard_gate_document(root: Path) -> dict[str, object]:
    client = (
        RELEASE
        / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    )
    client_digest = hashlib.sha256(b"# immutable client\n").hexdigest()
    binding = activation.cutover.seal(
        activation.cutover.ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
        {
            "operation_id": OPERATION_ID,
            "outcome": "completed",
            "transaction_journal_sha256": "1" * 64,
            "readiness_rebind_sha256": "2" * 64,
            "port_reservations_sha256": "3" * 64,
            "release_digest": RELEASE_DIGEST,
            "database": "/var/lib/devcoordinator/coordinator.sqlite3",
            "service_unit": activation.FINAL_HARD_GATE_LEGACY_UNIT,
            "service_restored": True,
            "maintenance_cleared": True,
            "completed_at": "2026-07-29T00:00:00Z",
        },
    )
    steps = {name: {"ok": True} for name in activation.FIRST_ADOPTION_STEPS}
    steps["activation_recorded"] = {
        "release_digest": RELEASE_DIGEST,
        "executor_release": str(RELEASE),
        "authority_ready": True,
        "testd_ready": True,
        "console_ready": True,
        "connection_refused_count": 0,
        "project_route_failures": 0,
    }
    steps["complete"] = {"maintenance_cleared": True}
    steps["legacy_writer_committed"] = {"document_sha256": "4" * 64}
    adoption = activation.cutover.seal(
        activation.FIRST_ADOPTION_ATTESTATION_KIND,
        {
            "transaction_id": str(uuid.uuid4()),
            "request_sha256": "5" * 64,
            "journal_sha256": "6" * 64,
            "steps": steps,
            "completed_at": "2026-07-29T00:00:00Z",
        },
    )
    links = [
        {
            "user": user,
            "uid": fake_passwd(user).pw_uid,
            "link": str(
                Path(fake_passwd(user).pw_dir) / relative / skill
            ),
            "source": str(activation.CANONICAL_SKILL_SOURCE_ROOT / skill),
        }
        for user in (OWNER_USER, COLLABORATOR_USER)
        for relative in activation.FINAL_HARD_GATE_SKILL_ROOTS
        for skill in activation.FINAL_HARD_GATE_SKILLS
    ]
    units = {
        unit: {
            "LoadState": "loaded",
            "ActiveState": "active",
            "UnitFileState": (
                "static"
                if unit.startswith("devcoordinator-console@")
                else "enabled"
            ),
            "FragmentPath": f"/etc/systemd/system/{unit}",
        }
        for unit in set(activation.SOCKET_UNITS)
        | set(activation.cutover._candidate_units(RELEASE_DIGEST))
    }
    with (
        mock.patch.object(activation.os, "geteuid", return_value=0),
        mock.patch.object(
            activation.cutover,
            "_immutable_inventory_client",
            return_value=(client, client_digest),
        ),
        mock.patch.object(
            activation,
            "_completed_binding_attestation",
            return_value=binding,
        ),
        mock.patch.object(
            activation,
            "_completed_first_adoption_attestation",
            return_value=adoption,
        ),
        mock.patch.object(
            activation,
            "_validate_final_hard_gate_profile",
            return_value={
                "profile_sha256": "7" * 64,
                "profile_gid": 1,
                "authority_generation": "schema13-generation",
                "repository_generation": 17,
                "owner_user": OWNER_USER,
                "owner_uid": OWNER_UID,
                "collaborator_user": COLLABORATOR_USER,
                "collaborator_uid": COLLABORATOR_UID,
            },
        ),
        mock.patch.object(
            activation.pwd,
            "getpwnam",
            side_effect=lambda name: fake_passwd(name),
        ),
    ):
        document = activation.build_first_adoption_installation_hard_gate(
            operation_id=OPERATION_ID,
            binding_attestation=root / "binding.json",
            first_adoption_attestation=root / "adoption.json",
            release=RELEASE,
            canonical_project=CANONICAL_PROJECT,
            canonical_repository_id=CANONICAL_REPOSITORY_ID,
            owner_user=OWNER_USER,
            collaborator_user=COLLABORATOR_USER,
            expected_uid=0,
            inventory_fetcher=lambda **_kwargs: inventory(),
            skill_link_validator=lambda: links,
            unit_validator=lambda **_kwargs: units,
            verified_at="2026-07-29T01:00:00Z",
        )
    expect(
        document["repository_id"] == CANONICAL_REPOSITORY_ID,
        "hard gate repository changed",
    )
    expect(
        document["canonical_project"] == CANONICAL_PROJECT
        and document["owner_user"] == OWNER_USER
        and document["collaborator_user"] == COLLABORATOR_USER
        and document["collaborator_uid"] == COLLABORATOR_UID,
        "hard gate target identity changed",
    )
    expect(
        document["authority"]["scope"] == "server-wide"
        and document["authority"]["transport"]
        == "authenticated-unix-socket",
        "hard gate authority changed",
    )
    tampered = dict(document)
    tampered["repository_id"] = str(uuid.uuid4())
    unsigned = {key: value for key, value in tampered.items() if key != "document_sha256"}
    tampered["document_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    with mock.patch.object(
        activation.pwd,
        "getpwnam",
        side_effect=lambda name: fake_passwd(name),
    ):
        expect_activation_error(
            lambda: activation.verify_first_adoption_installation_hard_gate(
                tampered,
                operation_id=OPERATION_ID,
                release=RELEASE,
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=CANONICAL_REPOSITORY_ID,
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "hard gate is invalid",
        )
        expect_activation_error(
            lambda: activation.verify_first_adoption_installation_hard_gate(
                document,
                operation_id=OPERATION_ID,
                release=RELEASE,
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=str(uuid.uuid4()),
                owner_user=OWNER_USER,
                collaborator_user=COLLABORATOR_USER,
            ),
            "hard gate is invalid",
        )
        expect_activation_error(
            lambda: activation.verify_first_adoption_installation_hard_gate(
                document,
                operation_id=OPERATION_ID,
                release=RELEASE,
                canonical_project=CANONICAL_PROJECT,
                canonical_repository_id=CANONICAL_REPOSITORY_ID,
                owner_user=OWNER_USER,
                collaborator_user="alternateCollaborator",
            ),
            "hard gate is invalid",
        )
    return document


class FenceHandle:
    def __init__(self) -> None:
        self.completed = False
        self.closed: bool | None = None

    def mark_complete(self) -> None:
        self.completed = True

    def close(self, *, command_succeeded: bool) -> None:
        self.closed = command_succeeded


def test_final_cli(root: Path, document: dict[str, object]) -> None:
    terminal = root / "hard-gate.json"
    handle = FenceHandle()

    def publish(path: Path, value: object, *, uid: int) -> None:
        expect(uid == 0, "hard gate publication UID changed")
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    output = io.StringIO()
    with (
        mock.patch.object(
            activation, "acquire_transaction_fence", return_value=handle
        ) as acquire,
        mock.patch.object(
            activation,
            "build_first_adoption_installation_hard_gate",
            return_value=document,
        ) as build_gate,
        mock.patch.object(
            activation.cutover,
            "_immutable_inventory_client",
            return_value=(root / "client.py", "8" * 64),
        ),
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
        mock.patch.object(activation.cutover, "_publish_evidence", side_effect=publish),
        redirect_stdout(output),
    ):
        code = activation.main(
            [
                "finalize-first-adoption-installation",
                "--binding-attestation",
                str(root / "binding.json"),
                "--operation-id",
                OPERATION_ID,
                "--first-adoption-attestation",
                str(root / "adoption.json"),
                "--release",
                str(RELEASE),
                "--hard-gate-attestation",
                str(terminal),
                "--expected-uid",
                "0",
                *target_argv(),
            ]
        )
    expect(code == 0, "final hard-gate CLI failed")
    expect(handle.completed and handle.closed is True, "final claim was not completed")
    acquire.assert_called_once()
    call = acquire.call_args.kwargs
    expect(
        call["owner_kind"] == activation.FIRST_ADOPTION_INSTALLER_OWNER_KIND
        and call["transaction"] == root / "binding.json"
        and call["terminal"] == terminal,
        "final CLI resumed another installer owner",
    )
    expect(
        build_gate.call_args.kwargs["canonical_project"] == CANONICAL_PROJECT
        and build_gate.call_args.kwargs["canonical_repository_id"]
        == CANONICAL_REPOSITORY_ID
        and build_gate.call_args.kwargs["owner_user"] == OWNER_USER
        and build_gate.call_args.kwargs["collaborator_user"]
        == COLLABORATOR_USER,
        "final CLI did not bind the explicit hard-gate target",
    )
    expect(
        json.loads(output.getvalue())["inventory"]["repository_id"]
        == CANONICAL_REPOSITORY_ID,
        "final CLI output changed",
    )


def test_first_adoption_terminal_replay_clears_claim(
    root: Path, document: dict[str, object]
) -> None:
    terminal = root / "already-published-hard-gate.json"
    terminal.write_text(json.dumps(document), encoding="utf-8")
    terminal.chmod(0o600)
    handle = FenceHandle()
    output = io.StringIO()
    with (
        mock.patch.object(
            activation.cutover,
            "read_private_json",
            side_effect=[{"request": True}, document],
        ),
        mock.patch.object(
            activation,
            "_first_adoption_request",
            return_value={"state": str(root / "state.json")},
        ),
        mock.patch.object(
            activation.cutover,
            "load_state",
            return_value={"release_digest": RELEASE_DIGEST, "release": str(RELEASE)},
        ),
        mock.patch.object(activation, "_completed_binding_attestation"),
        mock.patch.object(
            activation, "acquire_transaction_fence", return_value=handle
        ) as acquire,
        mock.patch.object(
            activation.cutover,
            "_immutable_inventory_client",
            return_value=(RELEASE / "skills/codex-dev-coordinator/scripts/dev_coordinator.py", "9" * 64),
        ),
        mock.patch.object(
            activation,
            "verify_first_adoption_installation_hard_gate",
            return_value=document,
        ) as verify_gate,
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
        redirect_stdout(output),
    ):
        code = activation.main(
            [
                "first-adoption",
                "--request", str(root / "request.json"),
                "--journal", str(root / "journal.json"),
                "--attestation", str(root / "adoption.json"),
                "--rollback-evidence", str(root / "rollback.json"),
                "--binding-attestation", str(root / "binding.json"),
                "--operation-id", OPERATION_ID,
                "--hard-gate-attestation", str(terminal),
                "--expected-uid", "0",
                *target_argv(),
            ]
        )
    expect(code == 0, "first-adoption terminal replay failed")
    expect(
        handle.completed and handle.closed is True,
        "first-adoption terminal replay did not clear the crash-retained claim",
    )
    acquire.assert_called_once()
    expect(
        acquire.call_args.kwargs["owner_kind"]
        == activation.FIRST_ADOPTION_INSTALLER_OWNER_KIND,
        "first-adoption terminal replay acquired another owner",
    )
    expect(
        verify_gate.call_args.kwargs["canonical_project"] == CANONICAL_PROJECT
        and verify_gate.call_args.kwargs["canonical_repository_id"]
        == CANONICAL_REPOSITORY_ID
        and verify_gate.call_args.kwargs["owner_user"] == OWNER_USER
        and verify_gate.call_args.kwargs["collaborator_user"]
        == COLLABORATOR_USER,
        "first-adoption replay did not bind the explicit hard-gate target",
    )


def test_final_cli_rejects_replayed_target_mismatch(
    root: Path, document: dict[str, object]
) -> None:
    terminal = root / "mismatched-hard-gate.json"
    terminal.write_text(json.dumps(document), encoding="utf-8")
    terminal.chmod(0o600)
    handle = FenceHandle()
    mismatched_repository_id = str(uuid.uuid4())
    with (
        mock.patch.object(
            activation, "acquire_transaction_fence", return_value=handle
        ),
        mock.patch.object(
            activation.cutover,
            "_immutable_inventory_client",
            return_value=(root / "client.py", "8" * 64),
        ),
        mock.patch.object(
            activation.cutover, "read_private_json", return_value=document
        ),
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
    ):
        code = activation.main(
            [
                "finalize-first-adoption-installation",
                "--binding-attestation",
                str(root / "binding.json"),
                "--operation-id",
                OPERATION_ID,
                "--first-adoption-attestation",
                str(root / "adoption.json"),
                "--release",
                str(RELEASE),
                "--hard-gate-attestation",
                str(terminal),
                "--expected-uid",
                "0",
                "--canonical-project",
                CANONICAL_PROJECT,
                "--canonical-repository-id",
                mismatched_repository_id,
                "--owner-user",
                OWNER_USER,
                "--collaborator-user",
                COLLABORATOR_USER,
            ]
        )
    expect(code == 1, "final CLI accepted a replay for another target")
    expect(
        handle.completed is False and handle.closed is False,
        "mismatched replay cleared the durable installer claim",
    )


def prepare_first_adoption_argv(root: Path, terminal: Path) -> list[str]:
    return [
        "prepare-first-adoption",
        "--state", str(root / "state.json"),
        "--candidate-slot-source", str(root / "candidate.env"),
        "--rollback-directory", str(root / "candidate-rollback"),
        "--legacy-console-env", str(root / "legacy-console.env"),
        "--legacy-console-uid", "0",
        "--background-project-root", str(root),
        "--background-config-transaction", str(root / "background.json"),
        "--project-isolation-audit", str(root / "isolation.json"),
        "--project-isolation-ledger", str(root / "isolation-ledger.json"),
        "--legacy-authority-database", str(root / "legacy.sqlite3"),
        "--repository-owner-map", str(root / "owners.json"),
        "--graph-evidence", str(root / "graph.json"),
        "--graph-journal", str(root / "graph-journal.json"),
        "--credential-evidence", str(root / "credentials.json"),
        "--port-reservations", str(root / "ports.json"),
        "--port-reservations-sha256", "7" * 64,
        "--binding-attestation", str(root / "binding.json"),
        "--operation-id", OPERATION_ID,
        "--hard-gate-attestation", str(terminal),
        "--authority-uid", "0",
        *target_argv(),
    ]


def test_prepare_first_adoption_retains_exact_successor_claim(root: Path) -> None:
    terminal = root / "future-hard-gate.json"
    handle = FenceHandle()
    state = {
        "release_digest": RELEASE_DIGEST,
        "legacy_authority_database": str(root / "legacy.sqlite3"),
    }
    ports = {
        "document_sha256": "7" * 64,
        "release_digest": RELEASE_DIGEST,
        "authority_database": state["legacy_authority_database"],
        "reservations": {"console_outer": {"port": 31000}},
    }
    output = io.StringIO()
    with (
        mock.patch.object(activation.cutover, "load_state", return_value=state),
        mock.patch.object(
            activation, "_completed_binding_attestation", return_value={"ok": True}
        ) as completed_binding,
        mock.patch.object(
            activation, "acquire_transaction_fence", return_value=handle
        ) as acquire,
        mock.patch.object(
            activation.cutover, "read_private_json", return_value=ports
        ),
        mock.patch.object(
            activation.cutover,
            "verify_first_adoption_port_reservations",
            return_value=ports,
        ),
        mock.patch.object(
            activation.cutover, "verify_first_adoption_port_reservation_rows"
        ),
        mock.patch.object(
            activation,
            "prepare_candidate",
            return_value=(
                {"document_sha256": "8" * 64},
                {"document_sha256": "9" * 64},
            ),
        ) as prepare_candidate,
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
        mock.patch.object(activation.cutover, "_publish_evidence"),
        redirect_stdout(output),
    ):
        code = activation.main(prepare_first_adoption_argv(root, terminal))
    expect(code == 0, "prepare-first-adoption claim recovery failed")
    expect(
        handle.completed is False and handle.closed is True,
        "prepare-first-adoption did not retain the durable successor claim",
    )
    completed_binding.assert_called_once_with(
        root / "binding.json",
        operation_id=OPERATION_ID,
        release_digest=RELEASE_DIGEST,
        expected_uid=0,
    )
    acquire.assert_called_once()
    expect(
        acquire.call_args.kwargs
        == {
            "owner_kind": activation.FIRST_ADOPTION_INSTALLER_OWNER_KIND,
            "operation_id": OPERATION_ID,
            "transaction": root / "binding.json",
            "terminal": terminal,
            "action": "recover",
            "expected_uid": 0,
            "expected_gid": 0,
        },
        "prepare-first-adoption recovered another installer transaction",
    )
    prepare_candidate.assert_called_once()
    expect(
        json.loads(output.getvalue())["phase"] == "prepared",
        "prepare-first-adoption result changed",
    )


def test_prepare_first_adoption_rejects_missing_or_completed_claim(root: Path) -> None:
    terminal = root / "future-hard-gate.json"
    state = {
        "release_digest": RELEASE_DIGEST,
        "legacy_authority_database": str(root / "legacy.sqlite3"),
    }
    with (
        mock.patch.object(activation.cutover, "load_state", return_value=state),
        mock.patch.object(activation, "_completed_binding_attestation"),
        mock.patch.object(
            activation,
            "acquire_transaction_fence",
            side_effect=activation.InstallerFenceError(
                "installer transaction durable owner is missing"
            ),
        ),
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
        mock.patch.object(activation, "prepare_candidate") as prepare_candidate,
    ):
        code = activation.main(prepare_first_adoption_argv(root, terminal))
    expect(code == 1, "prepare-first-adoption accepted a missing successor claim")
    prepare_candidate.assert_not_called()

    terminal.write_text("{}", encoding="utf-8")
    terminal.chmod(0o600)
    with (
        mock.patch.object(activation.cutover, "load_state", return_value=state),
        mock.patch.object(activation, "_completed_binding_attestation") as completed,
        mock.patch.object(
            activation.pwd, "getpwnam", side_effect=lambda name: fake_passwd(name)
        ),
        mock.patch.object(
            activation, "acquire_transaction_fence"
        ) as acquire,
    ):
        code = activation.main(prepare_first_adoption_argv(root, terminal))
    expect(code == 1, "prepare-first-adoption accepted an existing hard gate")
    completed.assert_not_called()
    acquire.assert_not_called()


def main() -> int:
    parser = activation._parser()
    try:
        parser.parse_args(
            [
                "finalize-first-adoption-installation",
                "--binding-attestation",
                "/binding",
                "--operation-id",
                OPERATION_ID,
                "--first-adoption-attestation",
                "/adoption",
                "--release",
                str(RELEASE),
                "--hard-gate-attestation",
                "/hard-gate",
            ]
        )
    except SystemExit as error:
        expect(
            error.code != 0,
            "finalize accepted a missing explicit hard-gate target",
        )
    else:
        raise RuntimeError(
            "finalize accepted a missing explicit hard-gate target"
        )
    try:
        parser.parse_args(
            [
                "first-adoption",
                "--request", "/r",
                "--journal", "/j",
                "--attestation", "/a",
                "--rollback-evidence", "/x",
            ]
        )
    except SystemExit as error:
        expect(error.code != 0, "first-adoption accepted missing handoff identity")
    else:
        raise RuntimeError("first-adoption accepted missing handoff identity")
    try:
        parser.parse_args(
            [
                "prepare-first-adoption",
                "--state", "/state",
            ]
        )
    except SystemExit as error:
        expect(
            error.code != 0,
            "prepare-first-adoption accepted missing successor identity",
        )
    else:
        raise RuntimeError(
            "prepare-first-adoption accepted missing successor identity"
        )
    with tempfile.TemporaryDirectory(prefix="first-adoption-handoff-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        test_target_validation()
        test_profile_contract(root)
        test_skill_links(root)
        test_units(root)
        document = test_hard_gate_document(root)
        test_final_cli(root, document)
        test_first_adoption_terminal_replay_clears_claim(root, document)
        test_final_cli_rejects_replayed_target_mismatch(root, document)
        test_prepare_first_adoption_retains_exact_successor_claim(root)
        test_prepare_first_adoption_rejects_missing_or_completed_claim(root)
    print("first-adoption installer handoff self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
