#!/usr/bin/env python3
"""Fail-closed checks for project process and container isolation policy."""

from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dev_coordinator  # noqa: E402
from devcoordinator.broker_host import _compose_isolation_override  # noqa: E402
from devcoordinator import project_runtime_isolation as isolation  # noqa: E402
from devcoordinator.worker_native import project_repository_slice  # noqa: E402


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    repository_slice = project_repository_slice(uid=501, repository_id="repo-one")
    expect(
        repository_slice.startswith("devcoordinator-projects-uid501-repo")
        and repository_slice.endswith(".slice"),
        "repository runner does not descend from the protected projects hierarchy",
    )
    expect(
        repository_slice
        != project_repository_slice(uid=501, repository_id="repo-two"),
        "different repositories share one leaf slice",
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
            expect(
                "forbidden" in str(error),
                "control-plane launch failed for an unrelated reason",
            )
        else:
            raise AssertionError("control-plane service launched a project process")
        popen.assert_not_called()

    override = json.loads(
        _compose_isolation_override(
            SimpleNamespace(
                owner_uid=501,
                repo_id="repo-one",
                services=("api", "worker"),
            )
        )
    )
    expect(
        set(override["services"]) == {"api", "worker"},
        "Compose isolation overlay did not cover every authorized service",
    )
    for policy in override["services"].values():
        expect(
            policy["cgroup_parent"] == repository_slice
            and policy["mem_limit"] == "20g"
            and policy["cpus"] == "8.0"
            and policy["pids_limit"] == 4096,
            "Compose isolation overlay omitted a project resource ceiling",
        )

    inspect_commands: list[tuple[str, ...]] = []

    def hostile_inspect(
        command: tuple[str, ...], *, timeout_seconds: float, maximum_bytes: int
    ) -> tuple[int, bytes]:
        inspect_commands.append(command)
        return 0, (
            b'{"Id":"' + b"a" * 64
            + b'","CgroupParent":"legacy.slice","Running":true,'
            b'"Env":["SECRET_CANARY=do-not-retain"]}\n'
        )

    with (
        mock.patch.object(isolation, "_safe_docker_executable", return_value=Path("/usr/bin/docker")),
        mock.patch.object(isolation, "_bounded_command_stdout", side_effect=hostile_inspect),
    ):
        expect(
            isolation.inspect_docker_cgroups(("a" * 64,)) == {},
            "Docker isolation audit accepted unexpected secret-bearing inspect fields",
        )
    expect(
        len(inspect_commands) == 1
        and ".Config" not in inspect_commands[0][3]
        and ".Mounts" not in inspect_commands[0][3]
        and ".Labels" not in inspect_commands[0][3]
        and "SECRET_CANARY" not in " ".join(inspect_commands[0]),
        "Docker isolation audit requested secret-bearing runtime metadata",
    )
    returncode, excess = isolation._bounded_command_stdout(
        (
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 131072)",
        ),
        timeout_seconds=5,
        maximum_bytes=1024,
    )
    expect(
        excess is None and returncode != 0,
        "Docker isolation audit retained output beyond its hard byte cap",
    )

    fixed_now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    docker_id = "a" * 64
    replacement_docker_id = "b" * 64
    process_fingerprint = "sha256:" + "c" * 64
    boot_id = str(uuid.UUID("11111111-2222-4333-8444-555555555555"))
    metadata = {
        "source_schema_version": 13,
        "database_generation": "generation-one",
        "state_revision": 8,
        "observation_revision": 13,
        "host_id": "host-one",
    }

    authority = sqlite3.connect(":memory:")
    authority.row_factory = sqlite3.Row
    authority.executescript(
        """
        CREATE TABLE schema_metadata(
            singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL,
            database_generation TEXT NOT NULL, state_revision INTEGER NOT NULL,
            migration_state TEXT NOT NULL
        );
        INSERT INTO schema_metadata VALUES(1, 13, 'generation-one', 8, 'ready');
        CREATE TABLE repositories(
            repo_id TEXT PRIMARY KEY, canonical_root TEXT NOT NULL,
            display_name TEXT NOT NULL, generation INTEGER NOT NULL,
            state TEXT NOT NULL
        );
        CREATE TABLE repository_owners(
            repo_id TEXT PRIMARY KEY, owner_uid INTEGER NOT NULL,
            repository_generation INTEGER NOT NULL
        );
        INSERT INTO repositories VALUES (
            'repo-one', '/srv/repo-one', 'Repo One', 7, 'active'
        );
        INSERT INTO repository_owners VALUES ('repo-one', 501, 7);
        """
    )
    expect(
        isolation._repository_owner_uids_v13(authority) == {"repo-one": 501},
        "schema-13 isolation did not use explicit repository owner authority",
    )
    authority.execute(
        "UPDATE repository_owners SET repository_generation = 6 WHERE repo_id = 'repo-one'"
    )
    try:
        isolation._repository_owner_uids_v13(authority)
    except isolation.ProjectIsolationError:
        pass
    else:
        raise AssertionError("schema-13 isolation accepted stale owner generation")
    authority.close()

    owner_map_path = Path("/root/private/repository-owner-map.json")
    owner_map_document = {
        "document_sha256": "sha256:" + "d" * 64,
        "repositories": [
            {"repository_id": "repo-one", "owner_uid": 501},
            {"repository_id": "repo-two", "owner_uid": 502},
        ],
    }
    with (
        mock.patch.object(isolation.os, "geteuid", return_value=0),
        mock.patch.object(
            isolation, "load_sealed_owner_map", return_value=owner_map_document
        ) as load_owner_map,
        mock.patch.object(
            isolation, "validate_owner_map", return_value=owner_map_document
        ) as validate_map,
    ):
        owner_uids, checked_map = isolation._repository_owner_uids_v12(
            SimpleNamespace(), owner_map_path=owner_map_path
        )
    expect(
        owner_uids == {"repo-one": 501, "repo-two": 502}
        and checked_map == owner_map_document,
        "schema-12 isolation did not derive every owner exclusively from its sealed map",
    )
    load_owner_map.assert_called_once_with(owner_map_path, expected_owner_uid=0)
    validate_map.assert_called_once()
    try:
        isolation._repository_owner_uids_v12(
            SimpleNamespace(), owner_map_path=None
        )
    except isolation.ProjectIsolationError:
        pass
    else:
        raise AssertionError("schema-12 isolation accepted a missing owner map")
    active_resource_source = inspect.getsource(isolation._active_resources)
    expect(
        "effective_uid" not in active_resource_source
        and "execution_uid" not in active_resource_source,
        "isolation inventory still trusts source/policy execution identity as owner authority",
    )

    def resource_rows(*, container_id: str = docker_id) -> list[dict[str, object]]:
        return [
            {
                "resource_kind": "docker",
                "resource_id": "docker-one",
                "repo_id": "repo-one",
                "owner_uid": 501,
                "runtime_identity": {"full_container_id": container_id},
                "authority_observable": True,
            },
            {
                "resource_kind": "service",
                "resource_id": "service-one",
                "repo_id": "repo-two",
                "owner_uid": 502,
                "runtime_identity": {
                    "attempt_id": "attempt-one",
                    "pid": 2345,
                    "process_start_time": "123456",
                    "process_fingerprint": process_fingerprint,
                },
                "authority_observable": True,
            },
        ]

    connection = SimpleNamespace(close=lambda: None)
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=metadata),
        mock.patch.object(
            isolation,
            "_repository_owner_authority",
            return_value=({"repo-one": 501, "repo-two": 502}, None),
        ),
        mock.patch.object(isolation, "_active_resources", return_value=resource_rows()),
    ):
        audit = isolation.capture_isolation_audit(
            database_path=Path("/private/authority.db"),
            docker_cgroup_reader=lambda identities: {
                identities[0]: {"cgroup_parent": "legacy.slice", "running": True}
            },
            process_cgroup_reader=lambda identity: (
                f"/devcoordinator-projects.slice/"
                f"{project_repository_slice(uid=502, repository_id='repo-two')}"
                "/service.scope"
            ),
            boot_id_reader=lambda: boot_id,
            now=lambda: fixed_now,
        )
    expect(
        audit["counts"]
        == {"compliant": 1, "legacy_requires_recreation": 1, "unobservable": 0},
        "exact live isolation audit did not classify legacy resources",
    )
    expect(
        audit["project_isolation_complete"] is False,
        "legacy resource incorrectly passed the isolation gate",
    )
    expect(
        audit["source_schema_version"] == 13
        and audit["repository_owner_map_sha256"] is None,
        "post-split isolation evidence did not bind its schema authority",
    )
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=metadata),
        mock.patch.object(
            isolation,
            "_repository_owner_authority",
            return_value=({"repo-one": 501, "repo-two": 502}, None),
        ),
    ):
        expect(
            isolation.verify_live_authority_binding(
                audit, database_path=Path("/private/authority.db")
            )["evidence_sha256"]
            == audit["evidence_sha256"],
            "retained isolation audit did not recheck its live owner authority",
        )
    changed_metadata = {**metadata, "state_revision": metadata["state_revision"] + 1}
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=changed_metadata),
        mock.patch.object(
            isolation,
            "_repository_owner_authority",
            return_value=({"repo-one": 501, "repo-two": 502}, None),
        ),
    ):
        try:
            isolation.verify_live_authority_binding(
                audit, database_path=Path("/private/authority.db")
            )
        except isolation.ProjectIsolationError:
            pass
        else:
            raise AssertionError("retained isolation audit accepted an advanced authority")
    schema12_metadata = {**metadata, "source_schema_version": 12}
    schema12_map = {
        "document_sha256": "sha256:" + "d" * 64,
        "repositories": [],
    }
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=schema12_metadata),
        mock.patch.object(
            isolation,
            "_repository_owner_authority",
            return_value=({"repo-one": 501, "repo-two": 502}, schema12_map),
        ),
        mock.patch.object(isolation, "_active_resources", return_value=resource_rows()),
    ):
        schema12_audit = isolation.capture_isolation_audit(
            database_path=Path("/private/authority.db"),
            repository_owner_map_path=owner_map_path,
            docker_cgroup_reader=lambda identities: {
                identities[0]: {"cgroup_parent": "legacy.slice", "running": True}
            },
            process_cgroup_reader=lambda identity: (
                f"/devcoordinator-projects.slice/"
                f"{project_repository_slice(uid=502, repository_id='repo-two')}"
                "/service.scope"
            ),
            boot_id_reader=lambda: boot_id,
            now=lambda: fixed_now,
        )
    expect(
        schema12_audit["source_schema_version"] == 12
        and schema12_audit["repository_owner_map_sha256"]
        == schema12_map["document_sha256"],
        "pre-split isolation evidence omitted its sealed owner-map digest",
    )
    ledger = isolation.create_migration_ledger(
        audit,
        deadline=fixed_now + timedelta(hours=12),
        now=fixed_now,
    )
    expect(
        ledger["counts"] == {"pending": 1, "completed": 0, "retired": 0},
        "legacy resource did not create an explicit migration ledger entry",
    )

    expected_docker_parent = project_repository_slice(
        uid=501, repository_id="repo-one"
    )
    with (
        mock.patch.object(isolation, "_database_file", return_value=connection),
        mock.patch.object(isolation, "_metadata", return_value=metadata),
        mock.patch.object(
            isolation,
            "_repository_owner_authority",
            return_value=({"repo-one": 501, "repo-two": 502}, None),
        ),
        mock.patch.object(
            isolation,
            "_active_resources",
            return_value=resource_rows(container_id=replacement_docker_id),
        ),
    ):
        replacement_audit = isolation.capture_isolation_audit(
            database_path=Path("/private/authority.db"),
            docker_cgroup_reader=lambda identities: {
                identities[0]: {
                    "cgroup_parent": expected_docker_parent,
                    "running": True,
                }
            },
            process_cgroup_reader=lambda identity: (
                f"/devcoordinator-projects.slice/"
                f"{project_repository_slice(uid=502, repository_id='repo-two')}"
                "/service.scope"
            ),
            boot_id_reader=lambda: boot_id,
            now=lambda: fixed_now + timedelta(minutes=1),
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
        "migration evidence did not complete the exact ledger entry",
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
    stale_identity_audit = json.loads(json.dumps(replacement_audit))
    stale_identity_audit["resources"][0]["runtime_identity"] = {
        "full_container_id": docker_id
    }
    stale_identity_audit.pop("evidence_sha256")
    stale_identity_audit = isolation._with_fingerprint(stale_identity_audit)
    try:
        isolation.record_migration(
            ledger,
            audit=stale_identity_audit,
            resource_kind="docker",
            resource_id="docker-one",
            operation_id=operation_id,
            outcome="completed",
        )
    except isolation.ProjectIsolationError:
        pass
    else:
        raise AssertionError("unchanged runtime identity completed a migration ledger")

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
        link = private / "audit-link.json"
        link.symlink_to(audit_file)
        try:
            isolation.read_private_document(link)
        except (OSError, isolation.ProjectIsolationError):
            pass
        else:
            raise AssertionError("isolation evidence reader followed a symlink")

    print("project isolation self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
