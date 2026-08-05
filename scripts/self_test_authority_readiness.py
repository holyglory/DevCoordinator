#!/usr/bin/env python3
"""Adversarial tests for the schema-12 authority readiness recovery gate."""

from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
from typing import Mapping
import uuid
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/orchestrate_availability_cutover.py"
SPEC = importlib.util.spec_from_file_location("authority_readiness_cutover", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import availability cutover orchestrator")
CUTOVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CUTOVER
SPEC.loader.exec_module(CUTOVER)

RELEASE_DIGEST = "a" * 64
REBIND_RELEASE_DIGEST = "b" * 64
MAINTENANCE_DEPLOYMENT_ID = "12345678-1234-4234-8234-123456789abc"
OPERATION_ID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
REBIND_OPERATION_ID = "23456789-2345-4234-8234-23456789abcd"
REBIND_MAINTENANCE_DEPLOYMENT_ID = "3456789a-3456-4345-8345-3456789abcde"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (CUTOVER.CutoverError, OSError, sqlite3.Error, RuntimeError):
        return
    raise AssertionError(f"unsafe authority readiness condition was accepted: {label}")


def atomic_bridge_inputs(
    root: Path, *, operation_id: str, transaction_attestation: Path
) -> dict[str, object]:
    return {
        "bridge_transaction": root / "schema12-bridge",
        "bridge_operation_id": "01234567-89ab-4cde-8fab-0123456789ab",
        "bridge_journal_sha256": "c" * 64,
        "bridge_journal_document_sha256": "d" * 64,
        "bridge_profile": root / "client-profiles.json",
        "bridge_socket": root / "broker.sock",
        "bridge_dropin": root / "95-schema12-cutover-bridge.conf",
        "bridge_canary_user": "holyglory",
        "bridge_canary_owner_uid": 1000,
        "bridge_canary_project": root / "repo-1",
        "bridge_canary_repository_id": "repo-1",
        "bridge_canary_repository_generation": 0,
        "post_start_attestation": transaction_attestation.with_name(
            f".{transaction_attestation.name}.{operation_id}.post-start-ready"
        ),
    }


def fake_atomic_post_start_proof(
    *,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    wait_seconds: int = 30,
    expected_uid: int = 0,
) -> dict[str, object]:
    del wait_seconds, expected_uid
    return {
        "operation_id": operation_id,
        "bridge_journal": str(transaction / "bridge-journal.json"),
        "bridge_journal_sha256": expected_journal_sha256,
        "bridge_document_sha256": expected_journal_document_sha256,
        "database": str(database),
        "database_generation": expected_database_generation,
        "profile": str(profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "canary": {
            "user": canary_user,
            "uid": expected_canary_uid,
            "project": str(canary_project),
            "authority": {
                "database_generation": expected_database_generation,
                "socket": str(broker_socket),
                "service_uid": 0,
            },
            "repository": {
                "repository_id": canary_repository_id,
                "canonical_root": str(canary_project),
                "generation": canary_repository_generation,
            },
        },
        "profile_repository": {
            "client_uid": expected_canary_uid,
            "repository_id": canary_repository_id,
            "canonical_root": str(canary_project),
            "generation": canary_repository_generation,
            "owner_uid": expected_canary_uid,
        },
    }


def fake_atomic_post_start_options() -> dict[str, object]:
    return {
        "post_start_verifier": fake_atomic_post_start_proof,
        "post_start_proof_validator": lambda value: dict(value),
    }


def test_atomic_bridge_verifier_signature_matches_production() -> None:
    production = CUTOVER._load_schema12_bridge_verifier().verify_ready_bridge
    expect(
        tuple(inspect.signature(production).parameters)
        == tuple(inspect.signature(fake_atomic_post_start_proof).parameters),
        "atomic orchestrator bridge verifier signature drifted",
    )


def create_authority_database(
    path: Path,
    *,
    enrollments: int = 1,
    open_blocking_conflicts: int = 0,
    partial_v13: bool = False,
) -> None:
    project = path.parent / "repo-1"
    project.mkdir(exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            PRAGMA journal_mode=WAL;
            CREATE TABLE schema_metadata(
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                database_generation TEXT NOT NULL,
                state_revision INTEGER NOT NULL,
                observation_revision INTEGER NOT NULL,
                authority_mode TEXT NOT NULL,
                migration_state TEXT NOT NULL,
                first_sqlite_mutation_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE hosts(
                host_id TEXT PRIMARY KEY,
                machine_fingerprint TEXT NOT NULL,
                platform TEXT NOT NULL,
                hostname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE repositories(
                repo_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES hosts(host_id),
                canonical_root TEXT NOT NULL,
                display_name TEXT NOT NULL,
                state TEXT NOT NULL,
                generation INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE repository_installations(
                repo_id TEXT PRIMARY KEY REFERENCES repositories(repo_id),
                status TEXT NOT NULL,
                startup_fenced INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                operation_id TEXT,
                actor TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE broker_acl_principals(
                uid INTEGER PRIMARY KEY,
                account_id TEXT NOT NULL,
                UNIQUE(uid, account_id)
            );
            CREATE TABLE broker_repository_enrollments(
                uid INTEGER NOT NULL,
                repo_id TEXT NOT NULL REFERENCES repositories(repo_id),
                account_id TEXT NOT NULL,
                PRIMARY KEY(uid, repo_id),
                FOREIGN KEY(uid, account_id)
                    REFERENCES broker_acl_principals(uid, account_id)
            );
            CREATE TABLE migration_conflicts(
                conflict_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                disposition TEXT NOT NULL
            );
            CREATE TABLE port_assignments(
                assignment_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES hosts(host_id),
                repo_id TEXT NOT NULL REFERENCES repositories(repo_id),
                server_name TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                generation INTEGER NOT NULL,
                deactivated_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE leases(
                lease_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES hosts(host_id),
                repo_id TEXT NOT NULL REFERENCES repositories(repo_id),
                server_definition_id TEXT,
                source_id TEXT,
                port INTEGER NOT NULL,
                owner TEXT,
                agent TEXT,
                purpose TEXT,
                status TEXT NOT NULL,
                expires_at TEXT,
                process_fingerprint TEXT,
                generation INTEGER NOT NULL,
                deactivated_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE events(
                event_id TEXT PRIMARY KEY,
                repo_id TEXT REFERENCES repositories(repo_id),
                source_id TEXT,
                operation_id TEXT,
                event_kind TEXT NOT NULL,
                code TEXT,
                message TEXT NOT NULL,
                diagnostic_json TEXT,
                occurred_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO schema_metadata VALUES(1,12,?,7,11,'sqlite','empty',?,?,?)",
            (
                "generation-before",
                "2026-07-16T12:26:48Z",
                "2026-07-16T12:20:00Z",
                "2026-07-28T23:17:37Z",
            ),
        )
        stamp = "2026-07-28T23:17:37Z"
        connection.execute(
            "INSERT INTO hosts VALUES('host-1','machine','linux','host',?,?)",
            (stamp, stamp),
        )
        connection.execute(
            "INSERT INTO repositories VALUES('repo-1','host-1',?,'Repo 1','active',0,?,?)",
            (str(project), stamp, stamp),
        )
        connection.execute(
            "INSERT INTO repository_installations VALUES('repo-1','installed',0,0,NULL,'installer',?)",
            (stamp,),
        )
        connection.execute("INSERT INTO broker_acl_principals VALUES(1000,'agent')")
        if enrollments:
            connection.execute(
                "INSERT INTO broker_repository_enrollments VALUES(1000,'repo-1','agent')"
            )
        for index in range(open_blocking_conflicts):
            connection.execute(
                "INSERT INTO migration_conflicts VALUES(?, 'blocking', 'open')",
                (f"conflict-{index}",),
            )
        if partial_v13:
            connection.execute("CREATE TABLE repository_owners(repo_id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()


def read_json(path: Path, *, uid: int) -> dict[str, object]:
    del uid
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("test evidence is not an object")
    return value


def publish_json(path: Path, document: object, *, uid: int) -> None:
    del uid
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == document:
            return
        raise CUTOVER.CutoverError("test evidence output changed")
    path.write_bytes(CUTOVER._canonical(document) + b"\n")
    path.chmod(0o600)


def identity(path: Path, *, uid: int) -> dict[str, int]:
    del uid
    info = path.stat()
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size}


def backup_producer(
    *,
    database: Path,
    backup: Path,
    attestation: Path,
    expected_uid: int,
    reserve_bytes: int,
) -> dict[str, object]:
    del reserve_bytes
    if attestation.exists():
        return {"ok": True, "created": False, **read_json(attestation, uid=0)}
    if backup.exists():
        raise CUTOVER.CutoverError("orphaned test backup")
    source = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    destination = sqlite3.connect(backup)
    try:
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    backup.chmod(0o600)
    db_identity = identity(database, uid=0)
    document = CUTOVER.seal(
        CUTOVER.BACKUP_KIND,
        {
            "database": str(database),
            "database_device": db_identity["device"],
            "database_inode": db_identity["inode"],
            "database_sha256": CUTOVER._file_digest(database),
            "backup": str(backup),
            "backup_sha256": CUTOVER._file_digest(backup),
            "backup_bytes": backup.stat().st_size,
            "quick_check": "ok",
            "foreign_key_violations": 0,
            "available_bytes": shutil.disk_usage(backup.parent).free,
            "required_bytes": database.stat().st_size,
            "expected_uid": expected_uid,
            "created_at": "2026-07-28T23:20:00Z",
        },
    )
    publish_json(attestation, document, uid=0)
    return {"ok": True, "created": True, **document}


def maintenance_state(**_kwargs):
    return {
        "deployment_id": MAINTENANCE_DEPLOYMENT_ID,
        "message": CUTOVER.PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": 10,
        "started_at": "2026-07-28T23:19:00Z",
    }


def release_verifier(_release: Path) -> dict[str, object]:
    return {
        "ok": True,
        "release_digest": RELEASE_DIGEST,
        "capabilities": {"authority_readiness_recovery": True},
    }


def rebind_release_verifier(release: Path) -> dict[str, object]:
    expected = "release-rebound"
    if release.name != expected:
        raise CUTOVER.CutoverError("unexpected rebind release")
    return {
        "ok": True,
        "release_digest": REBIND_RELEASE_DIGEST,
        "capabilities": {"authority_readiness_recovery": True},
    }


def lock_factory_for(root: Path):
    lock = root / ".broker-service.lock"
    lock.touch(mode=0o600, exist_ok=True)
    lock.chmod(0o600)

    @contextmanager
    def factory(_database: Path):
        info = lock.stat()
        yield {
            "path": str(lock),
            "device": info.st_dev,
            "inode": info.st_ino,
            "uid": 0,
            "mode": "0600",
            "acquired": True,
            "active_broker_excluded": True,
        }

    return factory


@contextmanager
def refusing_lock(_database: Path):
    raise RuntimeError("broker service is active")
    yield  # pragma: no cover


def invocation(root: Path, **overrides):
    arguments = {
        "release": root / "release",
        "database": root / "authority.sqlite3",
        "backup": root / "authority.backup.sqlite3",
        "backup_attestation": root / "authority.backup.json",
        "journal": root / "readiness.intent.json",
        "attestation": root / "readiness.result.json",
        "maintenance_root": root / "maintenance",
        "maintenance_gid": 986,
        "maintenance_deployment_id": MAINTENANCE_DEPLOYMENT_ID,
        "operation_id": OPERATION_ID,
        "reserve_bytes": 0,
        "authority_uid": 0,
        "release_verifier": release_verifier,
        "maintenance_state_reader": maintenance_state,
        "broker_lock_factory": lock_factory_for(root),
        "backup_producer": backup_producer,
        "identity_reader": identity,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        "now_reader": lambda: "2026-07-28T23:20:00Z",
    }
    arguments.update(overrides)
    return CUTOVER.finalize_authority_readiness(**arguments)


class FakeServiceTransaction:
    def __init__(self) -> None:
        self.active = True
        self.enabled = True
        self.maintenance: dict[str, object] | None = None
        self.commands: list[tuple[str, ...]] = []

    def command_status(self, argv: list[str]) -> int:
        self.commands.append(tuple(argv))
        action = argv[1]
        if action == "is-active":
            return 0 if self.active else 3
        if action == "is-enabled":
            return 0 if self.enabled else 1
        if action == "stop":
            self.active = False
            return 0
        if action == "start":
            self.active = True
            return 0
        raise RuntimeError(f"unexpected systemd action: {argv}")

    def activate(self, **values) -> object:
        proposed = {
            "deployment_id": values["deployment_id"],
            "message": values["message"],
            "retry_after_seconds": values["retry_after_seconds"],
            "started_at": values["started_at"],
        }
        if self.maintenance is not None and self.maintenance != proposed:
            raise RuntimeError("another maintenance deployment is active")
        self.maintenance = proposed
        return proposed

    def clear(self, **values) -> bool:
        if (
            self.maintenance is not None
            and self.maintenance["deployment_id"] != values["deployment_id"]
        ):
            raise RuntimeError("maintenance deployment changed")
        self.maintenance = None
        return True

    def read_maintenance(self, **_values):
        return self.maintenance


def service_invocation(
    root: Path, service: FakeServiceTransaction, **overrides
):
    arguments = {
        "release": root / "release",
        "database": root / "authority.sqlite3",
        "backup": root / "authority.backup.sqlite3",
        "backup_attestation": root / "authority.backup.json",
        "journal": root / "readiness.intent.json",
        "attestation": root / "readiness.result.json",
        "transaction_journal": root / "service.intent.json",
        "transaction_attestation": root / "service.result.json",
        "maintenance_root": root / "maintenance",
        "maintenance_gid": 986,
        "maintenance_deployment_id": MAINTENANCE_DEPLOYMENT_ID,
        "operation_id": OPERATION_ID,
        "reserve_bytes": 0,
        "authority_uid": 0,
        "release_verifier": release_verifier,
        "command_status": service.command_status,
        "maintenance_activator": service.activate,
        "maintenance_clearer": service.clear,
        "maintenance_state_reader": service.read_maintenance,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        "now_reader": lambda: "2026-07-28T23:20:00Z",
        "finalizer_options": {
            "broker_lock_factory": lock_factory_for(root),
            "backup_producer": backup_producer,
            "identity_reader": identity,
        },
    }
    arguments.update(overrides)
    return CUTOVER.recover_authority_readiness(**arguments)


def rebind_service_invocation(
    root: Path, service: FakeServiceTransaction, **overrides
):
    arguments = {
        "release": root / "release-rebound",
        "database": root / "authority.sqlite3",
        "prior_attestation": root / "readiness.result.json",
        "attestation": root / "readiness-rebind.result.json",
        "transaction_journal": root / "readiness-rebind.service-intent.json",
        "transaction_attestation": root / "readiness-rebind.service-result.json",
        "maintenance_root": root / "maintenance",
        "maintenance_gid": 986,
        "maintenance_deployment_id": REBIND_MAINTENANCE_DEPLOYMENT_ID,
        "operation_id": REBIND_OPERATION_ID,
        "authority_uid": 0,
        "release_verifier": rebind_release_verifier,
        "command_status": service.command_status,
        "maintenance_activator": service.activate,
        "maintenance_clearer": service.clear,
        "maintenance_state_reader": service.read_maintenance,
        "broker_lock_factory": lock_factory_for(root),
        "identity_reader": identity,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        "now_reader": lambda: "2026-07-29T00:30:00Z",
    }
    arguments.update(overrides)
    return CUTOVER.rebind_authority_readiness(**arguments)


def create_reattest_quiescence(
    root: Path, *, operation_id: str = REBIND_OPERATION_ID
) -> dict[str, object]:
    connection = sqlite3.connect(root / "authority.sqlite3")
    try:
        connection.execute(
            "UPDATE schema_metadata SET state_revision=9, "
            "updated_at='2026-07-29T00:30:00Z'"
        )
        connection.commit()
    finally:
        connection.close()
    created_at = "2026-07-29T00:30:00Z"
    expires_at = "2026-07-29T01:30:00.000Z"
    reservations = {}
    for index, role in enumerate(CUTOVER.FIRST_ADOPTION_PORT_ROLES):
        reservations[role] = {
            "lease_id": str(uuid.uuid5(uuid.NAMESPACE_URL, role)),
            "port": CUTOVER.FIRST_ADOPTION_PORT_RANGE["start"] + index,
            "agent": CUTOVER._first_adoption_port_agent(operation_id),
            "purpose": CUTOVER._first_adoption_port_purpose(
                REBIND_RELEASE_DIGEST, role
            ),
            "status": "active",
            "expires_at": (
                None
                if role in CUTOVER.FIRST_ADOPTION_CONSOLE_PORT_ROLES
                else expires_at
            ),
        }
    document = CUTOVER.verify_atomic_first_adoption_prepared(
        CUTOVER.seal(
            CUTOVER.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
            {
                "operation_id": operation_id,
                "release_digest": REBIND_RELEASE_DIGEST,
                "authority_database": str(root / "authority.sqlite3"),
                "authority_generation": "generation-before",
                "authority_state_revision_before": 8,
                "authority_state_revision_after": 9,
                "repository_id": "repo-1",
                "repository_generation": 0,
                "canonical_root": str(root / "repo-1"),
                "port_range": dict(CUTOVER.FIRST_ADOPTION_PORT_RANGE),
                "handoff_ttl_seconds": 3600,
                "reservations": reservations,
                "port_journal_sha256": "c" * 64,
                "atomic_transaction_journal_sha256": "d" * 64,
                "service_unit": "devcoordinator-broker.service",
                "service_stopped": True,
                "maintenance": {
                    "root": str(root / "maintenance"),
                    "gid": 986,
                    "deployment_id": REBIND_MAINTENANCE_DEPLOYMENT_ID,
                    "message": CUTOVER.PUBLIC_MAINTENANCE_MESSAGE,
                    "retry_after_seconds": 5,
                    "started_at": created_at,
                },
                "created_at": created_at,
                "completed_at": created_at,
            },
        )
    )
    publish_json(root / "first-adoption.pending.json", document, uid=0)
    return document


def reattest_invocation(
    root: Path,
    service: FakeServiceTransaction,
    *,
    quiescence: Mapping[str, object],
    **overrides,
):
    def immutable_observation(database: Path, *, uid: int):
        del uid
        return CUTOVER._immutable_authority_readiness_observation(
            database, uid=os.geteuid()
        )

    arguments = {
        "release": root / "release-rebound",
        "database": root / "authority.sqlite3",
        "prior_attestation": root / "readiness.result.json",
        "quiescence_attestation": root / "first-adoption.pending.json",
        "quiescence_attestation_sha256": quiescence["document_sha256"],
        "journal": root / "readiness-reattest.intent.json",
        "attestation": root / "readiness-reattest.result.json",
        "maintenance_root": root / "maintenance",
        "maintenance_gid": 986,
        "maintenance_deployment_id": REBIND_MAINTENANCE_DEPLOYMENT_ID,
        "operation_id": REBIND_OPERATION_ID,
        "authority_uid": 0,
        "release_verifier": rebind_release_verifier,
        "command_status": service.command_status,
        "maintenance_state_reader": service.read_maintenance,
        "broker_lock_factory": lock_factory_for(root),
        "observation_reader": immutable_observation,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        "now_reader": lambda: "2026-07-29T00:31:00Z",
    }
    arguments.update(overrides)
    return CUTOVER.reattest_authority_readiness(**arguments)


def fresh_root(raw: str, **database_options) -> Path:
    root = Path(raw)
    root.chmod(0o700)
    (root / "release").mkdir(mode=0o555)
    (root / "release-rebound").mkdir(mode=0o555)
    (root / "maintenance").mkdir(mode=0o700)
    create_authority_database(root / "authority.sqlite3", **database_options)
    return root


def prepared_reattest_fixture(
    raw: str,
) -> tuple[Path, dict[str, object], FakeServiceTransaction]:
    root = fresh_root(raw)
    invocation(root)
    quiescence = create_reattest_quiescence(root)
    service = FakeServiceTransaction()
    service.active = False
    marker = quiescence["maintenance"]
    service.maintenance = {
        field: marker[field]
        for field in (
            "deployment_id",
            "message",
            "retry_after_seconds",
            "started_at",
        )
    }
    return root, quiescence, service


def test_success_and_exact_replay() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-success-") as raw:
        root = fresh_root(raw)
        first = invocation(root)
        expect(first["attestation"]["applied"] is True, "mutation was not applied")
        expect(first["attestation"]["recovered"] is False, "fresh mutation was recovery")
        metadata = sqlite3.connect(root / "authority.sqlite3").execute(
            "SELECT migration_state, state_revision, database_generation FROM schema_metadata"
        ).fetchone()
        expect(metadata == ("ready", 8, "generation-before"), "metadata mutation is not exact")
        second = invocation(root)
        expect(second["replayed"] is True, "completed operation did not replay")
        expect(second["attestation"] == first["attestation"], "replay changed the seal")


def test_crash_recovery() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-intent-crash-") as raw:
        root = fresh_root(raw)

        def stop_after_intent(stage: str) -> None:
            if stage == "after-intent":
                raise CUTOVER.CutoverError("simulated crash after intent")

        must_fail(
            lambda: invocation(root, failpoint=stop_after_intent),
            "crash after intent",
        )
        expect((root / "readiness.intent.json").exists(), "intent was not durable")
        expect(not (root / "readiness.result.json").exists(), "result preceded mutation")
        result = invocation(root)
        expect(result["attestation"]["applied"] is True, "intent replay did not apply")

    with tempfile.TemporaryDirectory(prefix="authority-ready-commit-crash-") as raw:
        root = fresh_root(raw)

        def stop_after_commit(stage: str) -> None:
            if stage == "after-commit":
                raise CUTOVER.CutoverError("simulated crash after commit")

        must_fail(
            lambda: invocation(root, failpoint=stop_after_commit),
            "crash after commit",
        )
        expect(not (root / "readiness.result.json").exists(), "crash published a result")
        result = invocation(root)
        expect(result["attestation"]["applied"] is False, "recovery claimed a new mutation")
        expect(result["attestation"]["recovered"] is True, "commit recovery was hidden")


def test_supported_service_transaction() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-service-") as raw:
        root = fresh_root(raw)
        service = FakeServiceTransaction()
        first = service_invocation(root, service)
        expect(service.active is True, "service transaction did not restore the broker")
        expect(service.maintenance is None, "service transaction left maintenance active")
        expect(first["attestation"]["service_restored"] is True, "service restore was not sealed")
        mutations = [command[1] for command in service.commands if command[1] in {"stop", "start"}]
        expect(mutations == ["stop", "start"], "transaction changed more than the legacy broker")
        before = list(service.commands)
        second = service_invocation(root, service)
        expect(second["replayed"] is True, "service transaction did not replay")
        replay_mutations = [
            command[1]
            for command in service.commands[len(before) :]
            if command[1] in {"stop", "start"}
        ]
        expect(replay_mutations == [], "completed replay disrupted the broker")

    with tempfile.TemporaryDirectory(prefix="authority-ready-service-resume-") as raw:
        root = fresh_root(raw)
        service = FakeServiceTransaction()

        def stop_after_intent(stage: str) -> None:
            if stage == "after-intent":
                raise CUTOVER.CutoverError("simulated transaction interruption")

        options = {
            "broker_lock_factory": lock_factory_for(root),
            "backup_producer": backup_producer,
            "identity_reader": identity,
            "failpoint": stop_after_intent,
        }
        must_fail(
            lambda: service_invocation(
                root, service, finalizer_options=options
            ),
            "interrupted supported service transaction",
        )
        expect(service.active is False, "failed transaction unfenced the legacy writer")
        expect(service.maintenance is not None, "failed transaction cleared maintenance")
        resumed = service_invocation(root, service)
        expect(resumed["attestation"]["service_restored"] is True, "resume did not restore service")
        expect(service.active is True and service.maintenance is None, "resume did not converge")


def test_release_rebind_is_explicit_read_only_and_service_fenced() -> None:
    """A completed readiness repair can be rebound to a newer release only by seal.

    The ordinary recovery primitive deliberately accepts only the original
    schema-12 ``empty`` precondition.  This regression keeps that guard while
    proving the separate, broker-fenced rebind path neither mutates nor backs
    up the already-ready authority a second time.
    """

    with tempfile.TemporaryDirectory(prefix="authority-ready-rebind-") as raw:
        root = fresh_root(raw)
        original = invocation(root)["attestation"]
        before_digest = CUTOVER._file_digest(root / "authority.sqlite3")
        before_metadata = CUTOVER._read_authority_readiness_snapshot(
            root / "authority.sqlite3"
        )

        must_fail(
            lambda: invocation(
                root,
                release=root / "release-rebound",
                backup=root / "ordinary-rebind.backup.sqlite3",
                backup_attestation=root / "ordinary-rebind.backup.json",
                journal=root / "ordinary-rebind.intent.json",
                attestation=root / "ordinary-rebind.result.json",
                operation_id=REBIND_OPERATION_ID,
                release_verifier=rebind_release_verifier,
            ),
            "ordinary readiness recovery rebound an already-ready authority",
        )
        expect(
            not (root / "ordinary-rebind.intent.json").exists(),
            "ordinary recovery journaled an already-ready release rebind",
        )
        expect(
            not (root / "ordinary-rebind.backup.sqlite3").exists(),
            "ordinary recovery copied an already-ready authority",
        )

        service = FakeServiceTransaction()
        first = rebind_service_invocation(root, service)
        rebound = read_json(root / "readiness-rebind.result.json", uid=0)
        expect(
            rebound["kind"]
            == "devcoordinator-authority-readiness-release-rebind-attestation",
            "release rebind used the wrong evidence kind",
        )
        expect(
            rebound["prior_attestation"]
            == {
                "path": str(root / "readiness.result.json"),
                "document_sha256": original["document_sha256"],
            },
            "release rebind did not bind the exact prior readiness seal",
        )
        expect(
            rebound["prior_release_digest"] == RELEASE_DIGEST
            and rebound["release_digest"] == REBIND_RELEASE_DIGEST,
            "release rebind did not rotate the immutable release binding",
        )
        expect(
            rebound["database_identity"] == identity(root / "authority.sqlite3", uid=0),
            "release rebind did not retain exact database identity",
        )
        expect(
            rebound["precondition"] == before_metadata
            and rebound["postcondition"] == before_metadata,
            "release rebind changed the exact live readiness snapshot",
        )
        expect(
            rebound["mutation_applied"] is False,
            "release rebind claimed an authority mutation",
        )
        expect(
            CUTOVER._file_digest(root / "authority.sqlite3") == before_digest,
            "release rebind changed authority bytes",
        )
        expect(
            CUTOVER._read_authority_readiness_snapshot(root / "authority.sqlite3")
            == before_metadata,
            "release rebind changed authority metadata or invariants",
        )
        expect(service.active is True, "release rebind did not restore the broker")
        expect(service.maintenance is None, "release rebind left maintenance active")
        mutations = [
            command[1]
            for command in service.commands
            if command[1] in {"stop", "start"}
        ]
        expect(mutations == ["stop", "start"], "release rebind changed another service")
        expect(
            first["attestation"]["readiness_rebind_sha256"]
            == rebound["document_sha256"],
            "service transaction did not seal the rebind result",
        )

        before_commands = list(service.commands)
        replay = rebind_service_invocation(root, service)
        expect(replay["replayed"] is True, "completed release rebind did not replay")
        expect(
            [
                command[1]
                for command in service.commands[len(before_commands) :]
                if command[1] in {"stop", "start"}
            ]
            == [],
            "completed release-rebind replay disrupted the broker",
        )

        service.active = False
        must_fail(
            lambda: rebind_service_invocation(root, service),
            "completed rebind replay ignored broker baseline drift",
        )
        service.active = True
        service.maintenance = {
            "deployment_id": str(uuid.uuid4()),
            "message": CUTOVER.PUBLIC_MAINTENANCE_MESSAGE,
            "retry_after_seconds": 10,
            "started_at": "2026-07-29T00:31:00Z",
        }
        must_fail(
            lambda: rebind_service_invocation(root, service),
            "completed rebind replay ignored a foreign maintenance marker",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-rebind-descendant-"
    ) as raw:
        root = fresh_root(raw)
        original = invocation(root)["attestation"]
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute(
            "UPDATE schema_metadata SET state_revision=9, "
            "observation_revision=12, updated_at='2026-07-29T00:10:00Z'"
        )
        (root / "repo-2").mkdir()
        connection.execute(
            "INSERT INTO repositories VALUES('repo-2','host-1',?,'Repo 2','active',0,?,?)",
            (str(root / "repo-2"), "2026-07-29T00:10:00Z", "2026-07-29T00:10:00Z"),
        )
        connection.execute(
            "INSERT INTO repository_installations VALUES('repo-2','installed',0,0,NULL,'installer',?)",
            ("2026-07-29T00:10:00Z",),
        )
        connection.commit()
        connection.close()
        fenced: dict[str, object] = {}
        ordinary_lock = lock_factory_for(root)

        @contextmanager
        def advancing_lock(database: Path):
            with ordinary_lock(database) as evidence:
                connection = sqlite3.connect(database)
                connection.execute(
                    "UPDATE schema_metadata SET state_revision=10, "
                    "updated_at='2026-07-29T00:20:00Z'"
                )
                connection.commit()
                connection.close()
                fenced["snapshot"] = CUTOVER._read_authority_readiness_snapshot(
                    database
                )
                fenced["identity"] = identity(database, uid=0)
                fenced["database_sha256"] = CUTOVER._file_digest(database)
                yield evidence

        service = FakeServiceTransaction()
        rebind_service_invocation(
            root, service, broker_lock_factory=advancing_lock
        )
        rebound = read_json(root / "readiness-rebind.result.json", uid=0)
        expect(
            rebound["precondition"] == fenced["snapshot"]
            and rebound["postcondition"] == fenced["snapshot"],
            "release rebind did not seal the exact fenced descendant snapshot",
        )
        expect(
            rebound["database_identity"] == fenced["identity"]
            and rebound["database_sha256"] == fenced["database_sha256"],
            "release rebind did not seal the exact fenced descendant digest",
        )
        expect(
            rebound["backup"] == original["backup"],
            "release rebind did not retain the original backup lineage",
        )
        expect(
            rebound["mutation_applied"] is False,
            "release rebind claimed the descendant write as its own mutation",
        )

        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute(
            "UPDATE schema_metadata SET state_revision=11, "
            "observation_revision=13, updated_at='2026-07-29T00:40:00Z'"
        )
        connection.commit()
        connection.close()
        replay = rebind_service_invocation(root, service)
        expect(
            replay["replayed"] is True,
            "completed rebind rejected a valid post-attestation descendant",
        )

    drift_cases = {
        "state revision regression": "UPDATE schema_metadata SET state_revision=7",
        "observation revision regression": (
            "UPDATE schema_metadata SET observation_revision=10"
        ),
        "database generation": (
            "UPDATE schema_metadata SET database_generation='generation-forged'"
        ),
        "schema": "UPDATE schema_metadata SET schema_version=11",
        "authority mode": (
            "UPDATE schema_metadata SET authority_mode='legacy-json'"
        ),
        "migration state": (
            "UPDATE schema_metadata SET migration_state='empty'"
        ),
        "created timestamp": (
            "UPDATE schema_metadata SET created_at='2026-07-16T12:19:59Z'"
        ),
        "first mutation timestamp": (
            "UPDATE schema_metadata SET first_sqlite_mutation_at="
            "'2026-07-16T12:26:47Z'"
        ),
        "updated timestamp regression": (
            "UPDATE schema_metadata SET updated_at='2026-07-28T23:00:00Z'"
        ),
        "repository invariant": (
            "INSERT INTO repositories VALUES('repo-extra','host-1','/tmp/repo-extra',"
            "'Extra','active',0,'2026-07-29T00:00:00Z','2026-07-29T00:00:00Z')"
        ),
    }
    for label, statement in drift_cases.items():
        with tempfile.TemporaryDirectory(
            prefix="authority-ready-rebind-drift-"
        ) as raw:
            root = fresh_root(raw)
            invocation(root)
            connection = sqlite3.connect(root / "authority.sqlite3")
            connection.execute(statement)
            connection.commit()
            connection.close()
            service = FakeServiceTransaction()
            must_fail(
                lambda: rebind_service_invocation(root, service),
                f"release rebind accepted {label} drift",
            )
            expect(service.active is True, f"{label} drift stopped the broker")
            expect(service.maintenance is None, f"{label} drift activated maintenance")
            expect(
                not (root / "readiness-rebind.service-intent.json").exists(),
                f"{label} drift was journaled",
            )

    with tempfile.TemporaryDirectory(prefix="authority-ready-rebind-backup-") as raw:
        root = fresh_root(raw)
        invocation(root)
        with (root / "authority.backup.sqlite3").open("ab") as handle:
            handle.write(b"tamper")
        service = FakeServiceTransaction()
        must_fail(
            lambda: rebind_service_invocation(root, service),
            "release rebind accepted a tampered retained backup",
        )
        expect(service.active is True, "tampered backup stopped the broker")
        expect(service.maintenance is None, "tampered backup activated maintenance")

    with tempfile.TemporaryDirectory(prefix="authority-ready-rebind-identity-") as raw:
        root = fresh_root(raw)
        invocation(root)
        replacement = root / "replacement.sqlite3"
        create_authority_database(replacement)
        connection = sqlite3.connect(replacement)
        connection.execute(
            "UPDATE schema_metadata SET migration_state='ready', state_revision=8"
        )
        connection.commit()
        connection.close()
        os.replace(replacement, root / "authority.sqlite3")
        service = FakeServiceTransaction()
        must_fail(
            lambda: rebind_service_invocation(root, service),
            "release rebind accepted replaced database identity",
        )
        expect(service.active is True, "identity drift stopped the broker")
        expect(service.maintenance is None, "identity drift activated maintenance")


def test_ready_authority_reattestation_is_exact_and_non_mutating() -> None:
    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        before_database = (root / "authority.sqlite3").read_bytes()
        before_snapshot = CUTOVER._read_authority_readiness_snapshot(
            root / "authority.sqlite3"
        )
        first = reattest_invocation(
            root, service, quiescence=quiescence
        )
        result = read_json(
            root / "readiness-reattest.result.json", uid=0
        )
        intent = read_json(
            root / "readiness-reattest.intent.json", uid=0
        )
        expect(
            result["kind"] == CUTOVER.AUTHORITY_READINESS_REATTEST_KIND,
            "readiness re-attestation used the wrong evidence kind",
        )
        expect(
            result["intent"]
            == {
                "path": str(root / "readiness-reattest.intent.json"),
                "document_sha256": intent["document_sha256"],
            },
            "readiness re-attestation did not bind its exact intent",
        )
        expect(
            result["quiescence_attestation"]
            == {
                "path": str(root / "first-adoption.pending.json"),
                "document_sha256": quiescence["document_sha256"],
                "kind": CUTOVER.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
            },
            "readiness re-attestation did not bind prepared quiescence",
        )
        expect(
            result["database_identity_before"]
            == result["database_identity_after"],
            "readiness re-attestation changed database identity",
        )
        expect(
            result["precondition"] == result["postcondition"] == before_snapshot,
            "readiness re-attestation did not seal the exact ready snapshot",
        )
        expect(
            result["mutation_applied"] is False,
            "readiness re-attestation claimed a database mutation",
        )
        expect(
            (root / "authority.sqlite3").read_bytes() == before_database
            and CUTOVER._read_authority_readiness_snapshot(
                root / "authority.sqlite3"
            )
            == before_snapshot,
            "readiness re-attestation changed authority bytes or metadata",
        )
        expect(
            not any(
                command[1] in {"start", "stop"}
                for command in service.commands
            ),
            "readiness re-attestation mutated a service",
        )
        expect(service.active is False, "re-attestation started the broker")
        expect(
            service.maintenance is not None,
            "re-attestation cleared the caller-owned maintenance marker",
        )
        expect(
            stat.S_IMODE(
                (root / "readiness-reattest.intent.json").stat().st_mode
            )
            == 0o600
            and stat.S_IMODE(
                (root / "readiness-reattest.result.json").stat().st_mode
            )
            == 0o600,
            "readiness re-attestation evidence is not private",
        )
        commands_before = list(service.commands)
        replay = reattest_invocation(
            root, service, quiescence=quiescence
        )
        expect(first["replayed"] is False, "fresh re-attestation replayed")
        expect(replay["replayed"] is True, "exact re-attestation did not replay")
        expect(
            replay["attestation"] == first["attestation"],
            "re-attestation replay changed its seal",
        )
        expect(
            not any(
                command[1] in {"start", "stop"}
                for command in service.commands[len(commands_before) :]
            ),
            "re-attestation replay mutated a service",
        )
        verified = CUTOVER._verify_authority_readiness_reattest_references(
            result,
            authority_uid=0,
            evidence_reader=read_json,
        )
        expect(
            verified["intent"]["document_sha256"]
            == intent["document_sha256"],
            "re-attestation lineage verifier lost the intent",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-resume-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)

        def stop_after_intent(stage: str) -> None:
            if stage == "after-intent":
                raise CUTOVER.CutoverError("simulated intent interruption")

        must_fail(
            lambda: reattest_invocation(
                root,
                service,
                quiescence=quiescence,
                failpoint=stop_after_intent,
            ),
            "re-attestation intent interruption",
        )
        expect(
            (root / "readiness-reattest.intent.json").is_file()
            and not (root / "readiness-reattest.result.json").exists(),
            "re-attestation interruption published the wrong artifacts",
        )
        resumed = reattest_invocation(
            root, service, quiescence=quiescence
        )
        expect(
            resumed["replayed"] is False,
            "intent-only recovery claimed terminal replay",
        )


def test_ready_authority_reattestation_fails_closed() -> None:
    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-missing-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        (root / "first-adoption.pending.json").unlink()
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "missing quiescence evidence",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-q-digest-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        must_fail(
            lambda: reattest_invocation(
                root,
                service,
                quiescence=quiescence,
                quiescence_attestation_sha256="f" * 64,
            ),
            "wrong quiescence digest",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-expired-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        must_fail(
            lambda: reattest_invocation(
                root,
                service,
                quiescence=quiescence,
                now_reader=lambda: "2026-07-29T02:00:00Z",
            ),
            "expired quiescence evidence",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-active-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        service.active = True
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "active authority writer",
        )
        expect(
            not (root / "readiness-reattest.intent.json").exists(),
            "active-writer failure was journaled",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-marker-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        service.maintenance = None
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "missing maintenance marker",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-prior-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        prior = root / "readiness.result.json"
        document = json.loads(prior.read_text(encoding="utf-8"))
        document["release_digest"] = "f" * 64
        prior.write_text(json.dumps(document), encoding="utf-8")
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "tampered prior readiness result",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-backup-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        with (root / "authority.backup.sqlite3").open("ab") as handle:
            handle.write(b"tamper")
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "tampered readiness backup",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-stale-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute(
            "UPDATE schema_metadata SET state_revision=10, "
            "updated_at='2026-07-29T00:32:00Z'"
        )
        connection.commit()
        connection.close()
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "stale quiescence revision",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-not-ready-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute(
            "UPDATE schema_metadata SET migration_state='empty'"
        )
        connection.commit()
        connection.close()
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "non-ready authority",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-identity-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        replacement = root / "replacement.sqlite3"
        shutil.copy2(root / "authority.sqlite3", replacement)
        os.replace(replacement, root / "authority.sqlite3")
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "replaced authority inode",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-release-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)

        def wrong_release(_release: Path) -> dict[str, object]:
            return {
                "ok": True,
                "release_digest": "e" * 64,
                "capabilities": {
                    "authority_readiness_reattestation": True
                },
            }

        must_fail(
            lambda: reattest_invocation(
                root,
                service,
                quiescence=quiescence,
                release_verifier=wrong_release,
            ),
            "wrong immutable release",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-toctou-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        baseline = CUTOVER._immutable_authority_readiness_observation(
            root / "authority.sqlite3", uid=os.geteuid()
        )
        calls = 0

        def changing_observation(_database: Path, *, uid: int):
            nonlocal calls
            del uid
            calls += 1
            value = json.loads(json.dumps(baseline))
            if calls > 1:
                value["snapshot"]["metadata"]["observation_revision"] += 1
                value["snapshot"]["metadata"][
                    "updated_at"
                ] = "2026-07-29T00:32:00Z"
                value["database_sha256"] = "f" * 64
            return value

        must_fail(
            lambda: reattest_invocation(
                root,
                service,
                quiescence=quiescence,
                observation_reader=changing_observation,
            ),
            "database TOCTOU after intent",
        )
        expect(
            (root / "readiness-reattest.intent.json").exists()
            and not (root / "readiness-reattest.result.json").exists(),
            "TOCTOU failure published a terminal seal",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-descriptor-"
    ) as raw:
        root, _quiescence, _service = prepared_reattest_fixture(raw)
        database = root / "authority.sqlite3"
        original_reader = CUTOVER._read_authority_readiness_snapshot
        replaced = False

        def replace_path_during_read(path: Path, *, connection=None):
            nonlocal replaced
            if not replaced:
                replacement = root / "descriptor-replacement.sqlite3"
                shutil.copy2(database, replacement)
                os.replace(replacement, database)
                replaced = True
            return original_reader(path, connection=connection)

        with mock.patch.object(
            CUTOVER,
            "_read_authority_readiness_snapshot",
            side_effect=replace_path_during_read,
        ):
            must_fail(
                lambda: CUTOVER._immutable_authority_readiness_observation(
                    database, uid=os.geteuid()
                ),
                "descriptor-anchored database path replacement",
            )
        expect(
            replaced,
            "descriptor replacement test did not exercise its race",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-replay-drift-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        reattest_invocation(root, service, quiescence=quiescence)
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute(
            "UPDATE schema_metadata SET observation_revision=12, "
            "updated_at='2026-07-29T00:33:00Z'"
        )
        connection.commit()
        connection.close()
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "changed database on completed replay",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-reattest-replay-evidence-"
    ) as raw:
        root, quiescence, service = prepared_reattest_fixture(raw)
        reattest_invocation(root, service, quiescence=quiescence)
        (root / "readiness-reattest.intent.json").unlink()
        must_fail(
            lambda: reattest_invocation(
                root, service, quiescence=quiescence
            ),
            "missing intent on completed replay",
        )


def test_atomic_readiness_and_ports_prepare_abort_replay() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-atomic-") as raw:
        root = fresh_root(raw)
        original = invocation(root)["attestation"]
        service = FakeServiceTransaction()
        operation_id = "456789ab-4567-4456-8456-456789abcdef"
        deployment_id = "56789abc-5678-4567-8567-56789abcdef0"
        final_ports = root / "ports.json"
        prepared_ports = root / f".{final_ports.name}.{operation_id}.pending"
        common = {
            "release": root / "release-rebound",
            "database": root / "authority.sqlite3",
            "prior_attestation": root / "readiness.result.json",
            "readiness_attestation": root / "atomic-readiness.json",
            "project_root": root / "repo-1",
            "repository_id": "repo-1",
            "repository_generation": 0,
            "handoff_ttl_seconds": 3600,
            "port_journal": root / "atomic-ports.intent.json",
            "prepared_attestation": prepared_ports,
            "port_attestation": final_ports,
            "transaction_journal": root / "atomic-bindings.intent.json",
            "transaction_attestation": root / "atomic-bindings.result.json",
            **atomic_bridge_inputs(
                root,
                operation_id=operation_id,
                transaction_attestation=root / "atomic-bindings.result.json",
            ),
            "maintenance_root": root / "maintenance",
            "maintenance_gid": 986,
            "maintenance_deployment_id": deployment_id,
            "operation_id": operation_id,
            "authority_uid": 0,
            "release_verifier": rebind_release_verifier,
            "command_status": service.command_status,
            "maintenance_activator": service.activate,
            "maintenance_state_reader": service.read_maintenance,
            "broker_lock_factory": lock_factory_for(root),
            "identity_reader": identity,
            "evidence_reader": read_json,
            "evidence_publisher": publish_json,
            "effective_uid_reader": lambda: 0,
            **fake_atomic_post_start_options(),
            "now_reader": lambda: "2026-07-29T00:30:00Z",
            "port_selector": lambda *, candidates, protocol: (
                candidates[0] if protocol == "tcp" and candidates else None
            ),
        }
        identity_patch = mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        )
        identity_patch.start()
        prepared = CUTOVER.prepare_atomic_first_adoption_bindings(**common)
        expect(prepared["replayed"] is False, "atomic preparation claimed replay")
        evidence = prepared["attestation"]
        expect(
            evidence["kind"] == CUTOVER.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
            "atomic preparation published the wrong evidence kind",
        )
        expect(service.active is False, "atomic preparation restarted the broker")
        expect(service.maintenance is not None, "atomic preparation cleared maintenance")
        expect(
            evidence["authority_state_revision_before"]
            == original["postcondition"]["metadata"]["state_revision"]
            and evidence["authority_state_revision_after"]
            == original["postcondition"]["metadata"]["state_revision"] + 1,
            "atomic preparation did not bind the exact one-revision window",
        )
        commands_before = list(service.commands)
        replay = CUTOVER.prepare_atomic_first_adoption_bindings(**common)
        expect(replay["replayed"] is True, "atomic preparation did not replay")
        expect(
            [
                command
                for command in service.commands[len(commands_before) :]
                if command[1] in {"stop", "start"}
            ]
            == [],
            "atomic preparation replay changed broker state",
        )
        must_fail(
            lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                **{**common, "maintenance_gid": 987}
            ),
            "atomic preparation accepted changed maintenance binding",
        )
        original_prepared = prepared_ports.read_bytes()
        forged_prepared = json.loads(original_prepared)
        forged_prepared["reservations"]["handoff_api"]["port"] += 100
        forged_values = {
            key: value
            for key, value in forged_prepared.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        prepared_ports.write_bytes(
            CUTOVER._canonical(
                CUTOVER.seal(
                    CUTOVER.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
                    forged_values,
                )
            )
            + b"\n"
        )
        must_fail(
            lambda: CUTOVER.prepare_atomic_first_adoption_bindings(**common),
            "atomic preparation accepted forged prepared rows",
        )
        prepared_ports.write_bytes(original_prepared)
        with sqlite3.connect(root / "authority.sqlite3") as connection:
            expect(
                connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 5,
                "atomic preparation did not create all leases",
            )
        abort_options = {
            "state_path": root / "cutover-state.json",
            "transaction_journal": common["transaction_journal"],
            "transaction_attestation": common["transaction_attestation"],
            "authority_uid": 0,
            "command_status": service.command_status,
            "maintenance_clearer": service.clear,
            "maintenance_state_reader": service.read_maintenance,
            "evidence_reader": read_json,
            "evidence_publisher": publish_json,
            "effective_uid_reader": lambda: 0,
            "broker_lock_factory": lock_factory_for(root),
            "now_reader": lambda: "2026-07-29T00:31:00Z",
            **fake_atomic_post_start_options(),
        }

        def crash_after_abort_commit(stage: str) -> None:
            if stage == "after-commit":
                raise CUTOVER.CutoverError("simulated abort crash")

        must_fail(
            lambda: CUTOVER.abort_atomic_first_adoption_bindings(
                **abort_options,
                failpoint=crash_after_abort_commit,
            ),
            "atomic abort post-commit crash",
        )
        expect(service.active is False, "crashed abort restarted the broker")
        expect(
            service.maintenance is not None,
            "crashed abort cleared maintenance before recovery",
        )
        aborted = CUTOVER.abort_atomic_first_adoption_bindings(
            **abort_options,
        )
        expect(
            aborted["attestation"]["outcome"] == "aborted",
            "atomic abort outcome is not explicit",
        )
        expect(service.active is True, "atomic abort did not restore the broker")
        expect(service.maintenance is None, "atomic abort did not clear maintenance")
        with sqlite3.connect(root / "authority.sqlite3") as connection:
            expect(
                connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0,
                "atomic abort retained leases",
            )
        expect(
            CUTOVER._read_authority_readiness_snapshot(root / "authority.sqlite3")
            == original["postcondition"],
            "atomic abort did not restore the exact readiness snapshot",
        )
        original_terminal = common["transaction_attestation"].read_bytes()
        forged_terminal = json.loads(original_terminal)
        forged_values = {
            key: value
            for key, value in forged_terminal.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        forged_values["release_digest"] = "f" * 64
        common["transaction_attestation"].write_bytes(
            CUTOVER._canonical(
                CUTOVER.seal(
                    CUTOVER.ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
                    forged_values,
                )
            )
            + b"\n"
        )
        must_fail(
            lambda: CUTOVER.abort_atomic_first_adoption_bindings(
                **abort_options
            ),
            "atomic abort accepted a forged terminal duplicate",
        )
        common["transaction_attestation"].write_bytes(original_terminal)
        abort_replay = CUTOVER.abort_atomic_first_adoption_bindings(
            state_path=root / "cutover-state.json",
            transaction_journal=common["transaction_journal"],
            transaction_attestation=common["transaction_attestation"],
            authority_uid=0,
            command_status=service.command_status,
            maintenance_clearer=service.clear,
            maintenance_state_reader=service.read_maintenance,
            evidence_reader=read_json,
            evidence_publisher=publish_json,
            effective_uid_reader=lambda: 0,
            broker_lock_factory=lock_factory_for(root),
            **fake_atomic_post_start_options(),
        )
        expect(abort_replay["replayed"] is True, "atomic abort did not replay")
        identity_patch.stop()


def test_atomic_binding_finalize_requires_initialized_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-finalize-") as raw:
        root = fresh_root(raw)
        invocation(root)
        service = FakeServiceTransaction()
        operation_id = "6789abcd-6789-4678-8678-6789abcdef01"
        deployment_id = "789abcde-789a-4789-8789-789abcdef012"
        final_ports = root / "ports.json"
        prepared_ports = root / f".{final_ports.name}.{operation_id}.pending"
        common = {
            "release": root / "release-rebound",
            "database": root / "authority.sqlite3",
            "prior_attestation": root / "readiness.result.json",
            "readiness_attestation": root / "atomic-readiness.json",
            "project_root": root / "repo-1",
            "repository_id": "repo-1",
            "repository_generation": 0,
            "handoff_ttl_seconds": 3600,
            "port_journal": root / "atomic-ports.intent.json",
            "prepared_attestation": prepared_ports,
            "port_attestation": final_ports,
            "transaction_journal": root / "atomic-bindings.intent.json",
            "transaction_attestation": root / "atomic-bindings.result.json",
            **atomic_bridge_inputs(
                root,
                operation_id=operation_id,
                transaction_attestation=root / "atomic-bindings.result.json",
            ),
            "maintenance_root": root / "maintenance",
            "maintenance_gid": 986,
            "maintenance_deployment_id": deployment_id,
            "operation_id": operation_id,
            "authority_uid": 0,
            "release_verifier": rebind_release_verifier,
            "command_status": service.command_status,
            "maintenance_activator": service.activate,
            "maintenance_state_reader": service.read_maintenance,
            "broker_lock_factory": lock_factory_for(root),
            "identity_reader": identity,
            "evidence_reader": read_json,
            "evidence_publisher": publish_json,
            "effective_uid_reader": lambda: 0,
            **fake_atomic_post_start_options(),
            "now_reader": lambda: "2026-07-29T00:30:00Z",
            "port_selector": lambda *, candidates, protocol: (
                candidates[0] if protocol == "tcp" and candidates else None
            ),
        }
        with mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        ):
            prepared = CUTOVER.prepare_atomic_first_adoption_bindings(**common)[
                "attestation"
            ]

            def immutable_observation(database: Path, *, uid: int):
                del uid
                return CUTOVER._immutable_authority_readiness_observation(
                    database, uid=os.geteuid()
                )

            reattested = CUTOVER.reattest_authority_readiness(
                release=common["release"],
                database=common["database"],
                prior_attestation=common["prior_attestation"],
                quiescence_attestation=prepared_ports,
                quiescence_attestation_sha256=prepared[
                    "document_sha256"
                ],
                journal=root / "atomic-readiness-reattest.intent.json",
                attestation=root / "atomic-readiness-reattest.result.json",
                maintenance_root=common["maintenance_root"],
                maintenance_gid=common["maintenance_gid"],
                maintenance_deployment_id=common[
                    "maintenance_deployment_id"
                ],
                operation_id=operation_id,
                authority_uid=0,
                release_verifier=rebind_release_verifier,
                command_status=service.command_status,
                maintenance_state_reader=service.read_maintenance,
                broker_lock_factory=lock_factory_for(root),
                observation_reader=immutable_observation,
                evidence_reader=read_json,
                evidence_publisher=publish_json,
                effective_uid_reader=lambda: 0,
                now_reader=lambda: "2026-07-29T00:30:30Z",
            )
            readiness = reattested["attestation"]
            state_path = root / "cutover-state.json"
            stamp = "2026-07-29T00:30:00Z"
            state = CUTOVER.seal(
                CUTOVER.STATE_KIND,
                {
                    "cutover_id": str(uuid.uuid4()),
                    "phase": "planned",
                    "release": str(common["release"]),
                    "release_digest": REBIND_RELEASE_DIGEST,
                    "rendered_units": str(root / "rendered"),
                    "authority_uid": 0,
                    "testd_uid": 123,
                    "legacy_authority_database": str(common["database"]),
                    "authority_database": str(root / "final-authority.sqlite3"),
                    "test_database": str(root / "tests.sqlite3"),
                    "inventory_canary_project": str(common["project_root"]),
                    "authority_backup_directory": str(root / "authority-backup"),
                    "test_backup_directory": str(root / "test-backup"),
                    "migration_state": str(root / "migration.json"),
                    "drain_proof": str(root / "drain.json"),
                    "cutover_seal": str(root / "seal.json"),
                    "reserve_bytes": 0,
                    "retain_until": "2026-09-01T00:00:00Z",
                    "authority_backup_required": True,
                    "evidence": {
                        "authority-readiness": readiness,
                        "first-adoption-port-reservations": prepared,
                    },
                    "created_at": stamp,
                    "updated_at": stamp,
                    "state_generation": 0,
                },
            )
            CUTOVER.validate_state(state)
            publish_json(state_path, state, uid=0)

            def load_test_state(path, *, authority_uid):
                del authority_uid
                return CUTOVER.validate_state(
                    json.loads(path.read_text(encoding="utf-8"))
                )

            def write_test_state(
                path, document, *, uid, create, expected_generation=None
            ):
                del uid, create, expected_generation
                path.write_bytes(CUTOVER._canonical(document) + b"\n")

            with mock.patch.object(
                CUTOVER, "load_state", side_effect=load_test_state
            ), mock.patch.object(
                CUTOVER, "_write_private_json", side_effect=write_test_state
            ):
                startup_mutated = False

                def startup_command_status(argv: list[str]) -> int:
                    nonlocal startup_mutated
                    result = service.command_status(argv)
                    if argv[1] == "start" and not startup_mutated:
                        connection = sqlite3.connect(common["database"])
                        connection.execute(
                            "UPDATE schema_metadata "
                            "SET state_revision=state_revision + 3, "
                            "updated_at='2026-07-29T00:31:30Z'"
                        )
                        connection.commit()
                        connection.close()
                        startup_mutated = True
                    return result

                finalize_options = {
                    "state_path": state_path,
                    "transaction_journal": common["transaction_journal"],
                    "transaction_attestation": common["transaction_attestation"],
                    "authority_uid": 0,
                    "command_status": startup_command_status,
                    "maintenance_clearer": service.clear,
                    "maintenance_state_reader": service.read_maintenance,
                    "evidence_reader": read_json,
                    "evidence_publisher": publish_json,
                    "effective_uid_reader": lambda: 0,
                    "broker_lock_factory": lock_factory_for(root),
                    "now_reader": lambda: "2026-07-29T00:31:00Z",
                    **fake_atomic_post_start_options(),
                }

                def crash_after_state_swap(stage: str) -> None:
                    if stage == "after-state-swap":
                        raise CUTOVER.CutoverError("simulated state-swap crash")

                must_fail(
                    lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                        **finalize_options,
                        failpoint=crash_after_state_swap,
                    ),
                    "atomic finalization state-swap crash",
                )
                expect(
                    service.active is False and service.maintenance is not None,
                    "state-swap crash escaped the maintenance fence",
                )
                finalization_path = Path(
                    read_json(common["transaction_journal"], uid=0)[
                        "finalization_journal"
                    ]
                )
                original_finalization = finalization_path.read_bytes()
                forged_finalization = json.loads(original_finalization)
                forged_values = {
                    key: value
                    for key, value in forged_finalization.items()
                    if key not in {"schema_version", "kind", "document_sha256"}
                }
                forged_values["final_state_document_sha256"] = "f" * 64
                finalization_path.write_bytes(
                    CUTOVER._canonical(
                        CUTOVER.seal(
                            CUTOVER.ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND,
                            forged_values,
                        )
                    )
                    + b"\n"
                )
                must_fail(
                    lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                        **finalize_options
                    ),
                    "atomic finalization accepted a forged replay ledger digest",
                )
                finalization_path.write_bytes(original_finalization)

                for field in (
                    "authorized_snapshot",
                    "final_port_reservations",
                ):
                    forged_finalization = json.loads(original_finalization)
                    forged_values = {
                        key: value
                        for key, value in forged_finalization.items()
                        if key not in {
                            "schema_version",
                            "kind",
                            "document_sha256",
                        }
                    }
                    if field == "authorized_snapshot":
                        forged_values[field]["metadata"][
                            "observation_revision"
                        ] += 1
                        forged_values[field]["metadata"][
                            "updated_at"
                        ] = "2026-07-29T00:31:01Z"
                    else:
                        nested = {
                            key: value
                            for key, value in forged_values[field].items()
                            if key not in {
                                "schema_version",
                                "kind",
                                "document_sha256",
                            }
                        }
                        nested["completed_at"] = "2026-07-29T00:31:01Z"
                        forged_values[field] = CUTOVER.seal(
                            CUTOVER.FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                            nested,
                        )
                    finalization_path.write_bytes(
                        CUTOVER._canonical(
                            CUTOVER.seal(
                                CUTOVER.ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND,
                                forged_values,
                            )
                        )
                        + b"\n"
                    )
                    must_fail(
                        lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                            **finalize_options
                        ),
                        f"atomic finalization accepted forged {field}",
                    )
                    finalization_path.write_bytes(original_finalization)

                def crash_after_service_start(stage: str) -> None:
                    if stage == "after-service-start":
                        raise CUTOVER.CutoverError("simulated service-start crash")

                must_fail(
                    lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                        **finalize_options,
                        failpoint=crash_after_service_start,
                    ),
                    "atomic finalization service-start crash",
                )
                expect(
                    service.active is True and service.maintenance is not None,
                    "service-start crash cleared maintenance prematurely",
                )
                expect(
                    CUTOVER._read_authority_readiness_snapshot(common["database"])[
                        "metadata"
                    ]["state_revision"]
                    == prepared["authority_state_revision_after"] + 3,
                    "test broker startup did not advance authority revision",
                )

                def crash_after_marker_clear(stage: str) -> None:
                    if stage == "after-maintenance-clear":
                        raise CUTOVER.CutoverError("simulated marker-clear crash")

                must_fail(
                    lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                        **finalize_options,
                        failpoint=crash_after_marker_clear,
                    ),
                    "atomic finalization marker-clear crash",
                )
                expect(
                    service.active is True and service.maintenance is None,
                    "marker-clear crash did not leave the completed service baseline",
                )
                expect(
                    not common["transaction_attestation"].exists(),
                    "marker-clear crash published a false terminal result",
                )
                finalized = CUTOVER.finalize_atomic_first_adoption_bindings(
                    **finalize_options,
                )
                expect(
                    finalized["attestation"]["outcome"] == "completed",
                    "atomic finalization outcome is not explicit",
                )
                expect(
                    service.active is True and service.maintenance is None,
                    "atomic finalization did not restore the service baseline",
                )
                updated = load_test_state(state_path, authority_uid=0)
                final_evidence = updated["evidence"][
                    "first-adoption-port-reservations"
                ]
                expect(
                    final_evidence["kind"]
                    == CUTOVER.FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    "atomic finalization did not replace prepared evidence",
                )
                original_terminal = common[
                    "transaction_attestation"
                ].read_bytes()
                forged_terminal = json.loads(original_terminal)
                forged_values = {
                    key: value
                    for key, value in forged_terminal.items()
                    if key not in {
                        "schema_version",
                        "kind",
                        "document_sha256",
                    }
                }
                forged_values["service_unit"] = "forged-broker.service"
                common["transaction_attestation"].write_bytes(
                    CUTOVER._canonical(
                        CUTOVER.seal(
                            CUTOVER.ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
                            forged_values,
                        )
                    )
                    + b"\n"
                )
                must_fail(
                    lambda: CUTOVER.finalize_atomic_first_adoption_bindings(
                        **finalize_options
                    ),
                    "atomic finalization accepted a forged terminal duplicate",
                )
                common["transaction_attestation"].write_bytes(
                    original_terminal
                )
                commands_before = list(service.commands)
                replay = CUTOVER.finalize_atomic_first_adoption_bindings(
                    state_path=state_path,
                    transaction_journal=common["transaction_journal"],
                    transaction_attestation=common["transaction_attestation"],
                    authority_uid=0,
                    command_status=service.command_status,
                    maintenance_clearer=service.clear,
                    maintenance_state_reader=service.read_maintenance,
                    evidence_reader=read_json,
                    evidence_publisher=publish_json,
                    effective_uid_reader=lambda: 0,
                    broker_lock_factory=lock_factory_for(root),
                    **fake_atomic_post_start_options(),
                )
                expect(replay["replayed"] is True, "atomic finalization did not replay")
                expect(
                    [
                        command
                        for command in service.commands[len(commands_before) :]
                        if command[1] in {"stop", "start"}
                    ]
                    == [],
                    "atomic finalization replay changed broker state",
                )
                prepare_replay = CUTOVER.prepare_atomic_first_adoption_bindings(
                    **common
                )
                expect(
                    prepare_replay["replayed"] is True
                    and prepare_replay["attestation"]["kind"]
                    == CUTOVER.FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    "completed atomic preparation was not idempotent",
                )


def _atomic_test_common(
    root: Path,
    service: FakeServiceTransaction,
    *,
    now_reader=lambda: "2026-07-29T00:30:00Z",
) -> dict[str, object]:
    operation_id = str(uuid.uuid4())
    deployment_id = str(uuid.uuid4())
    final_ports = root / "ports.json"
    transaction_attestation = root / "atomic-bindings.result.json"
    return {
        "release": root / "release-rebound",
        "database": root / "authority.sqlite3",
        "prior_attestation": root / "readiness.result.json",
        "readiness_attestation": root / "atomic-readiness.json",
        "project_root": root / "repo-1",
        "repository_id": "repo-1",
        "repository_generation": 0,
        "handoff_ttl_seconds": 3600,
        "port_journal": root / "atomic-ports.intent.json",
        "prepared_attestation": root
        / f".{final_ports.name}.{operation_id}.pending",
        "port_attestation": final_ports,
        "transaction_journal": root / "atomic-bindings.intent.json",
        "transaction_attestation": transaction_attestation,
        **atomic_bridge_inputs(
            root,
            operation_id=operation_id,
            transaction_attestation=transaction_attestation,
        ),
        "maintenance_root": root / "maintenance",
        "maintenance_gid": 986,
        "maintenance_deployment_id": deployment_id,
        "operation_id": operation_id,
        "authority_uid": 0,
        "release_verifier": rebind_release_verifier,
        "command_status": service.command_status,
        "maintenance_activator": service.activate,
        "maintenance_state_reader": service.read_maintenance,
        "broker_lock_factory": lock_factory_for(root),
        "identity_reader": identity,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        **fake_atomic_post_start_options(),
        "now_reader": now_reader,
        "port_selector": lambda *, candidates, protocol: (
            candidates[0] if protocol == "tcp" and candidates else None
        ),
    }


def _atomic_abort_options(
    root: Path,
    service: FakeServiceTransaction,
    common: Mapping[str, object],
) -> dict[str, object]:
    return {
        "state_path": root / "cutover-state.json",
        "transaction_journal": common["transaction_journal"],
        "transaction_attestation": common["transaction_attestation"],
        "authority_uid": 0,
        "command_status": service.command_status,
        "maintenance_clearer": service.clear,
        "maintenance_state_reader": service.read_maintenance,
        "evidence_reader": read_json,
        "evidence_publisher": publish_json,
        "effective_uid_reader": lambda: 0,
        "broker_lock_factory": lock_factory_for(root),
        "now_reader": lambda: "2026-07-29T00:31:00Z",
        **fake_atomic_post_start_options(),
    }


def test_atomic_prepare_prefixes_recover_and_abort() -> None:
    stages = (
        "after-marker",
        "after-stop",
        "after-readiness",
        "after-intent",
        "after-commit",
        "before-prepared",
    )
    for disposition in ("resume", "abort"):
        for stage in stages:
            with tempfile.TemporaryDirectory(
                prefix=f"authority-ready-atomic-{disposition}-{stage}-"
            ) as raw:
                root = fresh_root(raw)
                original = invocation(root)["attestation"]["postcondition"]
                service = FakeServiceTransaction()
                common = _atomic_test_common(root, service)

                def crash(candidate: str, *, target=stage) -> None:
                    if candidate == target:
                        raise CUTOVER.CutoverError(
                            f"simulated atomic prepare crash at {target}"
                        )

                with mock.patch.object(
                    CUTOVER, "_database_identity", side_effect=identity
                ):
                    must_fail(
                        lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                            **common, failpoint=crash
                        ),
                        f"atomic prepare {stage} crash",
                    )
                    if disposition == "resume":
                        resumed = CUTOVER.prepare_atomic_first_adoption_bindings(
                            **common
                        )
                        expect(
                            resumed["attestation"]["kind"]
                            == CUTOVER.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
                            f"atomic prepare did not resume {stage}",
                        )
                    aborted = CUTOVER.abort_atomic_first_adoption_bindings(
                        **_atomic_abort_options(root, service, common)
                    )
                expect(
                    aborted["attestation"]["outcome"] == "aborted",
                    f"atomic abort did not terminalize {stage}",
                )
                expect(
                    service.active is True and service.maintenance is None,
                    f"atomic abort did not restore service after {stage}",
                )
                with sqlite3.connect(root / "authority.sqlite3") as connection:
                    expect(
                        connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
                        == 0
                        and connection.execute(
                            "SELECT COUNT(*) FROM events WHERE code="
                            "'first_adoption_port_reserved'"
                        ).fetchone()[0]
                        == 0,
                        f"atomic abort retained partial rows after {stage}",
                    )
                current = CUTOVER._read_authority_readiness_snapshot(
                    root / "authority.sqlite3"
                )
                CUTOVER._authority_readiness_ready_descendant(
                    original,
                    current,
                    label=f"atomic abort {stage}",
                )


def test_atomic_abort_rejects_partial_row_sets() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-atomic-partial-") as raw:
        root = fresh_root(raw)
        invocation(root)
        service = FakeServiceTransaction()
        common = _atomic_test_common(root, service)

        def crash(stage: str) -> None:
            if stage == "after-commit":
                raise CUTOVER.CutoverError("simulated committed prepare crash")

        with mock.patch.object(CUTOVER, "_database_identity", side_effect=identity):
            must_fail(
                lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                    **common, failpoint=crash
                ),
                "atomic committed prepare crash",
            )
            with sqlite3.connect(root / "authority.sqlite3") as connection:
                event_id = connection.execute(
                    "SELECT event_id FROM events "
                    "WHERE code='first_adoption_port_reserved' LIMIT 1"
                ).fetchone()[0]
                connection.execute("DELETE FROM events WHERE event_id=?", (event_id,))
                connection.commit()
            must_fail(
                lambda: CUTOVER.abort_atomic_first_adoption_bindings(
                    **_atomic_abort_options(root, service, common)
                ),
                "atomic abort partial row set",
            )
        expect(
            service.active is False and service.maintenance is not None,
            "partial rows escaped the stopped maintenance fence",
        )


def test_atomic_prepare_rejects_expiring_handoff_at_both_fences() -> None:
    scenarios = {
        "before-mutation": (
            [
                "2026-07-29T00:30:00Z",
                "2026-07-29T00:31:00Z",
                "2026-07-29T01:26:00Z",
            ],
            0,
        ),
        "after-commit": (
            [
                "2026-07-29T00:30:00Z",
                "2026-07-29T00:31:00Z",
                "2026-07-29T00:31:00Z",
                "2026-07-29T00:31:00Z",
                "2026-07-29T01:26:00Z",
            ],
            len(CUTOVER.FIRST_ADOPTION_PORT_ROLES),
        ),
    }
    for label, (timestamps, expected_rows_after_failure) in scenarios.items():
        with tempfile.TemporaryDirectory(
            prefix=f"authority-ready-atomic-expiry-{label}-"
        ) as raw:
            root = fresh_root(raw)
            original = invocation(root)["attestation"]["postcondition"]
            service = FakeServiceTransaction()
            values = iter(timestamps)

            def advancing_now() -> str:
                try:
                    return next(values)
                except StopIteration as error:
                    raise AssertionError(
                        f"unexpected time read in {label} expiry test"
                    ) from error

            common = _atomic_test_common(
                root, service, now_reader=advancing_now
            )
            with mock.patch.object(
                CUTOVER, "_database_identity", side_effect=identity
            ):
                must_fail(
                    lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                        **common
                    ),
                    f"atomic prepare accepted {label} expiring handoff",
                )
                with sqlite3.connect(root / "authority.sqlite3") as connection:
                    row_count = connection.execute(
                        "SELECT COUNT(*) FROM leases"
                    ).fetchone()[0]
                expect(
                    row_count == expected_rows_after_failure,
                    f"{label} expiry crossed the wrong mutation fence",
                )
                expect(
                    service.active is False and service.maintenance is not None,
                    f"{label} expiry escaped maintenance",
                )
                aborted = CUTOVER.abort_atomic_first_adoption_bindings(
                    **_atomic_abort_options(root, service, common)
                )
            expect(
                aborted["attestation"]["outcome"] == "aborted",
                f"{label} expiry was not recoverable",
            )
            expect(
                service.active is True and service.maintenance is None,
                f"{label} expiry abort did not restore service",
            )
            with sqlite3.connect(root / "authority.sqlite3") as connection:
                expect(
                    connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
                    == 0,
                    f"{label} expiry abort retained reservations",
                )
            CUTOVER._authority_readiness_ready_descendant(
                original,
                CUTOVER._read_authority_readiness_snapshot(
                    root / "authority.sqlite3"
                ),
                label=f"atomic {label} expiry abort",
            )


def test_atomic_retry_reproves_bridge_before_first_maintenance_mutation() -> None:
    with tempfile.TemporaryDirectory(
        prefix="authority-ready-atomic-initial-preflight-"
    ) as raw:
        root = fresh_root(raw)
        original = invocation(root)["attestation"]["postcondition"]
        service = FakeServiceTransaction()
        common = _atomic_test_common(root, service)

        def unavailable_bridge(**_options) -> dict[str, object]:
            raise RuntimeError("bridge is not live-ready")

        with mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        ):
            must_fail(
                lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                    **{**common, "post_start_verifier": unavailable_bridge}
                ),
                "atomic prepare accepted unavailable bridge",
            )
        expect(
            not common["transaction_journal"].exists(),
            "initial bridge failure published a transaction journal",
        )
        expect(
            service.active is True and service.maintenance is None,
            "initial bridge failure changed the service fence",
        )
        expect(
            CUTOVER._read_authority_readiness_snapshot(
                root / "authority.sqlite3"
            )
            == original,
            "initial bridge failure changed authority readiness",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-atomic-reprobe-"
    ) as raw:
        root = fresh_root(raw)
        original = invocation(root)["attestation"]["postcondition"]
        service = FakeServiceTransaction()
        common = _atomic_test_common(root, service)

        def fail_activation(**_values) -> object:
            raise CUTOVER.CutoverError(
                "simulated maintenance activation failure"
            )

        with mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        ):
            must_fail(
                lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                    **{**common, "maintenance_activator": fail_activation}
                ),
                "atomic prepare activation failure",
            )
            expect(
                common["transaction_journal"].exists(),
                "activation failure did not retain its transaction lineage",
            )
            expect(
                service.active is True and service.maintenance is None,
                "activation failure changed the service fence",
            )

            def drifted_bridge(**_options) -> dict[str, object]:
                raise RuntimeError("protected profile drifted")

            must_fail(
                lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                    **{**common, "post_start_verifier": drifted_bridge}
                ),
                "atomic retry accepted drifted bridge before maintenance",
            )
            aborted = CUTOVER.abort_atomic_first_adoption_bindings(
                **_atomic_abort_options(root, service, common)
            )
        expect(
            service.active is True and service.maintenance is None,
            "bridge reprobe failure activated maintenance or stopped service",
        )
        expect(
            aborted["attestation"]["outcome"] == "aborted",
            "journal-only bridge failure could not be safely aborted",
        )
        with sqlite3.connect(root / "authority.sqlite3") as connection:
            expect(
                connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
                == 0
                and connection.execute(
                    "SELECT COUNT(*) FROM events WHERE code="
                    "'first_adoption_port_reserved'"
                ).fetchone()[0]
                == 0,
                "bridge reprobe failure mutated authority rows",
            )
        expect(
            CUTOVER._read_authority_readiness_snapshot(
                root / "authority.sqlite3"
            )
            == original,
            "bridge reprobe failure changed authority readiness",
        )


def test_atomic_rejects_misbound_bridge_proofs_before_journaling() -> None:
    def wrong_uid(proof: dict[str, object]) -> None:
        proof["canary"]["uid"] += 1

    def wrong_generation(proof: dict[str, object]) -> None:
        proof["canary"]["repository"]["generation"] += 1

    def wrong_profile_owner(proof: dict[str, object]) -> None:
        proof["profile_repository"]["owner_uid"] += 1

    def wrong_authority_socket(proof: dict[str, object]) -> None:
        proof["canary"]["authority"]["socket"] += ".forged"

    cases = {
        "canary uid": wrong_uid,
        "repository generation": wrong_generation,
        "profile owner": wrong_profile_owner,
        "authority socket": wrong_authority_socket,
    }
    for label, mutate in cases.items():
        with tempfile.TemporaryDirectory(
            prefix=f"authority-ready-atomic-misbound-{label.replace(' ', '-')}-"
        ) as raw:
            root = fresh_root(raw)
            invocation(root)
            service = FakeServiceTransaction()
            common = _atomic_test_common(root, service)

            def misbound_probe(**options) -> dict[str, object]:
                proof = fake_atomic_post_start_proof(**options)
                mutate(proof)
                return proof

            with mock.patch.object(
                CUTOVER, "_database_identity", side_effect=identity
            ):
                must_fail(
                    lambda: CUTOVER.prepare_atomic_first_adoption_bindings(
                        **{**common, "post_start_verifier": misbound_probe}
                    ),
                    f"atomic prepare accepted misbound {label}",
                )
            expect(
                not common["transaction_journal"].exists()
                and service.active is True
                and service.maintenance is None,
                f"misbound {label} crossed the pre-journal fence",
            )


def test_atomic_abort_replays_every_post_restore_prefix() -> None:
    for crash_stage in (
        "after-service-start",
        "after-post-start-ready",
        "after-maintenance-clear",
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"authority-ready-atomic-abort-{crash_stage}-"
        ) as raw:
            root = fresh_root(raw)
            invocation(root)
            service = FakeServiceTransaction()
            common = _atomic_test_common(root, service)
            with mock.patch.object(
                CUTOVER, "_database_identity", side_effect=identity
            ):
                CUTOVER.prepare_atomic_first_adoption_bindings(**common)
                revision_advanced = False

                def crash(stage: str) -> None:
                    nonlocal revision_advanced
                    if stage != crash_stage:
                        return
                    if stage == "after-service-start" and not revision_advanced:
                        with sqlite3.connect(
                            root / "authority.sqlite3"
                        ) as connection:
                            connection.execute(
                                "UPDATE schema_metadata "
                                "SET state_revision=state_revision + 3, "
                                "updated_at='2026-07-29T00:31:30Z'"
                            )
                            connection.commit()
                        revision_advanced = True
                    raise CUTOVER.CutoverError(
                        f"simulated abort crash at {stage}"
                    )

                abort_options = _atomic_abort_options(root, service, common)
                must_fail(
                    lambda: CUTOVER.abort_atomic_first_adoption_bindings(
                        **abort_options, failpoint=crash
                    ),
                    f"atomic abort {crash_stage} crash",
                )
                expect(
                    service.active is True,
                    f"atomic abort {crash_stage} did not restore service first",
                )
                proof = common["post_start_attestation"]
                expect(
                    proof.exists()
                    == (crash_stage != "after-service-start"),
                    f"atomic abort {crash_stage} proof publication is misplaced",
                )
                expect(
                    (service.maintenance is None)
                    == (crash_stage == "after-maintenance-clear"),
                    f"atomic abort {crash_stage} maintenance boundary is wrong",
                )
                replay = CUTOVER.abort_atomic_first_adoption_bindings(
                    **abort_options
                )
            expect(
                replay["attestation"]["outcome"] == "aborted",
                f"atomic abort did not replay {crash_stage}",
            )
            expect(
                service.active is True and service.maintenance is None,
                f"atomic abort replay did not converge {crash_stage}",
            )
            expect(
                common["post_start_attestation"].exists(),
                f"atomic abort replay omitted proof after {crash_stage}",
            )


def test_atomic_post_start_failure_retains_fence_and_replay_reprobes() -> None:
    with tempfile.TemporaryDirectory(
        prefix="authority-ready-atomic-post-start-failure-"
    ) as raw:
        root = fresh_root(raw)
        invocation(root)
        service = FakeServiceTransaction()
        common = _atomic_test_common(root, service)
        with mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        ):
            CUTOVER.prepare_atomic_first_adoption_bindings(**common)

            def failed_live_probe(**_options) -> dict[str, object]:
                raise RuntimeError("broker canary is unavailable")

            failed_abort = _atomic_abort_options(root, service, common)
            failed_abort["post_start_verifier"] = failed_live_probe
            must_fail(
                lambda: CUTOVER.abort_atomic_first_adoption_bindings(
                    **failed_abort
                ),
                "atomic abort cleared maintenance after failed live proof",
            )
            expect(
                service.active is True and service.maintenance is not None,
                "failed post-start proof did not retain the maintenance fence",
            )
            expect(
                not common["transaction_attestation"].exists(),
                "failed post-start proof published a terminal result",
            )
            recovered = CUTOVER.abort_atomic_first_adoption_bindings(
                **_atomic_abort_options(root, service, common)
            )
        expect(
            recovered["attestation"]["outcome"] == "aborted"
            and service.active is True
            and service.maintenance is None,
            "atomic abort did not recover after the live proof returned",
        )

    with tempfile.TemporaryDirectory(
        prefix="authority-ready-atomic-post-start-reprobe-"
    ) as raw:
        root = fresh_root(raw)
        invocation(root)
        service = FakeServiceTransaction()
        probe_count = 0

        def counting_probe(**options) -> dict[str, object]:
            nonlocal probe_count
            probe_count += 1
            proof = fake_atomic_post_start_proof(**options)
            proof["verified_at_epoch"] = probe_count
            return proof

        def replace_evidence(
            path: Path,
            document: object,
            *,
            uid: int,
            create: bool,
        ) -> None:
            del uid
            expect(create is False, "post-start replay requested create replacement")
            path.write_bytes(CUTOVER._canonical(document) + b"\n")

        common = _atomic_test_common(root, service)
        common["post_start_verifier"] = counting_probe
        common["post_start_evidence_replacer"] = replace_evidence
        abort_options = _atomic_abort_options(root, service, common)
        abort_options["post_start_verifier"] = counting_probe
        abort_options["post_start_evidence_replacer"] = replace_evidence
        with mock.patch.object(
            CUTOVER, "_database_identity", side_effect=identity
        ):
            CUTOVER.prepare_atomic_first_adoption_bindings(**common)
            CUTOVER.abort_atomic_first_adoption_bindings(**abort_options)
            count_before_replay = probe_count
            retained_before = read_json(
                common["post_start_attestation"], uid=0
            )["verified_at_epoch"]
            replay = CUTOVER.abort_atomic_first_adoption_bindings(
                **abort_options
            )
        retained_after = read_json(
            common["post_start_attestation"], uid=0
        )["verified_at_epoch"]
        expect(replay["replayed"] is True, "post-start terminal did not replay")
        expect(
            probe_count == count_before_replay + 1
            and retained_after == probe_count
            and retained_after > retained_before,
            "post-start replay trusted stale retained proof instead of live probing",
        )


def test_prepared_fence_returns_typed_maintenance_before_socket_connect() -> None:
    """Supported clients must not observe the deliberately absent broker socket."""

    with tempfile.TemporaryDirectory(prefix="authority-ready-client-fence-") as raw:
        root = Path(raw).resolve()
        maintenance_root = root / "maintenance"
        maintenance_root.mkdir(mode=0o750)
        uid = os.geteuid()
        gid = os.getegid()
        CUTOVER.activate_maintenance(
            expected_uid=uid,
            expected_gid=gid,
            deployment_id="89abcdef-89ab-489a-889a-89abcdef0123",
            scope=CUTOVER.CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=CUTOVER.PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at="2026-07-29T00:30:00Z",
            maintenance_root=maintenance_root,
        )
        client = CUTOVER.BrokerClient(
            root / "deliberately-absent-broker.sock",
            expected_broker_uid=uid,
            expected_socket_gid=gid,
            maintenance_root=maintenance_root,
        )
        request = CUTOVER.BrokerRequest(
            operation_id="9abcdef0-9abc-49ab-89ab-9abcdef01234",
            authority_generation="generation-before",
            account_id="account-1",
            project_id="repo-1",
            repository_generation=0,
            resource_id="inventory",
            operation=CUTOVER.BrokerOperation.INVENTORY_READ,
            arguments={},
        )
        with mock.patch.object(
            client,
            "_authenticated_connection",
            side_effect=AssertionError("maintenance client attempted a socket connect"),
        ) as connect:
            try:
                client.call(request)
            except RuntimeError as error:
                expect(
                    getattr(error, "code", None) == "maintenance_in_progress",
                    "prepared fence did not return typed maintenance",
                )
                expect(
                    getattr(error, "retry_after_seconds", None) == 5,
                    "prepared fence lost the retry interval",
                )
            else:
                raise AssertionError("prepared fence unexpectedly reached the broker")
        connect.assert_not_called()


def test_fail_closed_inputs() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-root-") as raw:
        root = fresh_root(raw)
        must_fail(
            lambda: invocation(root, effective_uid_reader=lambda: 1000),
            "non-root caller",
        )
    with tempfile.TemporaryDirectory(prefix="authority-ready-maintenance-") as raw:
        root = fresh_root(raw)
        must_fail(
            lambda: invocation(root, maintenance_state_reader=lambda **_kwargs: None),
            "missing maintenance marker",
        )
    with tempfile.TemporaryDirectory(prefix="authority-ready-lock-") as raw:
        root = fresh_root(raw)
        must_fail(
            lambda: invocation(root, broker_lock_factory=refusing_lock),
            "active broker writer",
        )
    with tempfile.TemporaryDirectory(prefix="authority-ready-empty-") as raw:
        root = fresh_root(raw, enrollments=0)
        must_fail(lambda: invocation(root), "empty enrollment authority")
        expect(not (root / "readiness.intent.json").exists(), "invalid DB was journaled")
    with tempfile.TemporaryDirectory(prefix="authority-ready-conflict-") as raw:
        root = fresh_root(raw, open_blocking_conflicts=1)
        must_fail(lambda: invocation(root), "open blocking conflict")
    with tempfile.TemporaryDirectory(prefix="authority-ready-partial-") as raw:
        root = fresh_root(raw, partial_v13=True)
        must_fail(lambda: invocation(root), "partial schema-13 state")


def test_drift_and_evidence_tampering() -> None:
    def crash_after_intent(root: Path) -> None:
        def failpoint(stage: str) -> None:
            if stage == "after-intent":
                raise CUTOVER.CutoverError("stop")

        must_fail(lambda: invocation(root, failpoint=failpoint), "intent checkpoint")

    with tempfile.TemporaryDirectory(prefix="authority-ready-drift-") as raw:
        root = fresh_root(raw)
        crash_after_intent(root)
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute("UPDATE schema_metadata SET observation_revision=12")
        connection.commit()
        connection.close()
        must_fail(lambda: invocation(root), "source revision drift")

    with tempfile.TemporaryDirectory(prefix="authority-ready-generation-") as raw:
        root = fresh_root(raw)
        crash_after_intent(root)
        connection = sqlite3.connect(root / "authority.sqlite3")
        connection.execute("UPDATE schema_metadata SET database_generation='forged'")
        connection.commit()
        connection.close()
        must_fail(lambda: invocation(root), "database generation drift")

    with tempfile.TemporaryDirectory(prefix="authority-ready-journal-") as raw:
        root = fresh_root(raw)
        crash_after_intent(root)
        journal = root / "readiness.intent.json"
        document = json.loads(journal.read_text(encoding="utf-8"))
        document["operation_id"] = str(uuid.uuid4())
        journal.write_text(json.dumps(document), encoding="utf-8")
        must_fail(lambda: invocation(root), "forged journal")

    with tempfile.TemporaryDirectory(prefix="authority-ready-backup-") as raw:
        root = fresh_root(raw)
        crash_after_intent(root)
        with (root / "authority.backup.sqlite3").open("ab") as handle:
            handle.write(b"tamper")
        must_fail(lambda: invocation(root), "replaced backup")

    with tempfile.TemporaryDirectory(prefix="authority-ready-result-") as raw:
        root = fresh_root(raw)
        invocation(root)
        result_path = root / "readiness.result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["recovered"] = True
        result_path.write_text(json.dumps(result), encoding="utf-8")
        must_fail(lambda: invocation(root), "forged result")


def test_real_wal_aware_backup() -> None:
    with tempfile.TemporaryDirectory(prefix="authority-ready-wal-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        database = root / "source.sqlite3"
        source = sqlite3.connect(database)
        try:
            source.execute("PRAGMA journal_mode=WAL")
            source.execute("CREATE TABLE values_for_backup(value TEXT NOT NULL)")
            source.commit()
            source.execute("INSERT INTO values_for_backup VALUES('in-wal')")
            source.commit()
            expect(
                database.with_name(database.name + "-wal").is_file(),
                "test did not retain an uncheckpointed WAL",
            )
            result = CUTOVER.backup_database(
                database=database,
                backup=root / "backup.sqlite3",
                attestation=root / "backup.json",
                expected_uid=os.geteuid(),
                reserve_bytes=0,
            )
            expect(result["quick_check"] == "ok", "real backup was not checked")
            copied = sqlite3.connect(root / "backup.sqlite3").execute(
                "SELECT value FROM values_for_backup"
            ).fetchone()
            expect(copied == ("in-wal",), "online backup omitted WAL state")
        finally:
            source.close()


def main() -> int:
    test_atomic_bridge_verifier_signature_matches_production()
    test_success_and_exact_replay()
    test_crash_recovery()
    test_supported_service_transaction()
    test_release_rebind_is_explicit_read_only_and_service_fenced()
    test_ready_authority_reattestation_is_exact_and_non_mutating()
    test_ready_authority_reattestation_fails_closed()
    test_atomic_readiness_and_ports_prepare_abort_replay()
    test_atomic_binding_finalize_requires_initialized_ledger()
    test_atomic_prepare_prefixes_recover_and_abort()
    test_atomic_abort_rejects_partial_row_sets()
    test_atomic_prepare_rejects_expiring_handoff_at_both_fences()
    test_atomic_retry_reproves_bridge_before_first_maintenance_mutation()
    test_atomic_rejects_misbound_bridge_proofs_before_journaling()
    test_atomic_abort_replays_every_post_restore_prefix()
    test_atomic_post_start_failure_retains_fence_and_replay_reprobes()
    test_prepared_fence_returns_typed_maintenance_before_socket_connect()
    test_fail_closed_inputs()
    test_drift_and_evidence_tampering()
    test_real_wal_aware_backup()
    print("authority readiness self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
