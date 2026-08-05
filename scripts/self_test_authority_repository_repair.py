#!/usr/bin/env python3
"""Regression tests for the sealed shared-root authority repair."""

from __future__ import annotations

from contextlib import closing, contextmanager, nullcontext
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

SPEC = importlib.util.spec_from_file_location(
    "authority_repository_repair_cutover",
    ROOT / "scripts/orchestrate_availability_cutover.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cutover module cannot be loaded")
cutover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cutover)

from devcoordinator.maintenance import (  # noqa: E402
    CONTROL_PLANE_MAINTENANCE_SCOPE,
    PUBLIC_MAINTENANCE_MESSAGE,
    activate_maintenance,
)
from devcoordinator.schema import REPOSITORY_OWNER_AUTHORITY_DDL  # noqa: E402
from devcoordinator.schema import initialize_schema  # noqa: E402
from devcoordinator.broker_persistence import BROKER_SCHEMA  # noqa: E402


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

    def activate(self, **values: object) -> object:
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

    def clear(self, **values: object) -> bool:
        if (
            self.maintenance is not None
            and self.maintenance["deployment_id"] != values["deployment_id"]
        ):
            raise RuntimeError("maintenance deployment changed")
        self.maintenance = None
        return True

    def read_maintenance(self, **_values: object) -> object:
        return self.maintenance


class FakeRestartLoopServiceTransaction(FakeServiceTransaction):
    def __init__(self) -> None:
        super().__init__()
        self.active_state = "activating"
        self.sub_state = "auto-restart"

    def command_status(self, argv: list[str]) -> int:
        self.commands.append(tuple(argv))
        action = argv[1]
        if action == "stop":
            self.active_state = "inactive"
            self.sub_state = "dead"
            return 0
        if action == "start":
            self.active_state = "active"
            self.sub_state = "running"
            return 0
        raise RuntimeError(f"unexpected systemd action: {argv}")

    def read_service(self, _unit: str) -> dict[str, object]:
        return {
            "loaded": True,
            "enabled": True,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
        }


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
        raise RuntimeError("test evidence changed")
    path.write_bytes(cutover._canonical(document) + b"\n")
    path.chmod(0o600)


class AuthorityRepositoryRepairTests(unittest.TestCase):
    ROOT_PROOF = {
        "device": 42,
        "inode": 4242,
        "mode": "1777",
        "owner_uid": 0,
        "git_metadata_absent": True,
    }

    def _fixture(self, root: Path) -> tuple[Path, Path, Path, str]:
        os.chmod(root, 0o700)
        database = root / "authority.sqlite3"
        repository_id = "eb1dc238-f385-505b-bb7a-cce5107df4e9"
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE schema_metadata(
                    singleton INTEGER PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL,
                    state_revision INTEGER NOT NULL,
                    migration_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repositories(
                    repo_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    canonical_root TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repository_installations(
                    repo_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    startup_fenced INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    operation_id TEXT,
                    disabled_at TEXT,
                    reason TEXT,
                    actor TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE broker_repository_enrollments(
                    repo_id TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    account_id TEXT NOT NULL
                );
                CREATE TABLE startup_policies(
                    policy_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    resource_kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    policy_kind TEXT NOT NULL,
                    current_value TEXT NOT NULL,
                    desired_disabled_value TEXT NOT NULL,
                    immutable_fingerprint TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE startup_policy_restore_states(
                    policy_id TEXT PRIMARY KEY,
                    repo_id TEXT,
                    resource_kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    policy_kind TEXT NOT NULL,
                    policy_immutable_fingerprint TEXT NOT NULL,
                    target_immutable_fingerprint TEXT NOT NULL,
                    control_binding_id TEXT NOT NULL,
                    ownership_fingerprint TEXT NOT NULL,
                    native_identity_fingerprint TEXT NOT NULL,
                    captured_value TEXT NOT NULL,
                    restore_required INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    docker_restart_policy TEXT,
                    supervisor_manager TEXT,
                    supervisor_unit_file_state TEXT,
                    supervisor_loaded INTEGER,
                    supervisor_enabled INTEGER,
                    captured_operation_id TEXT NOT NULL,
                    last_restore_permit_id TEXT,
                    capture_generation INTEGER NOT NULL,
                    captured_at TEXT NOT NULL,
                    restored_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repository_memberships(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE control_bindings(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE port_assignments(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE leases(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE broker_lease_links(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE broker_assignment_links(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE broker_reconciliation_queue(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE broker_lifecycle_links(
                    row_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )
            existing_tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }
            for table in cutover.AUTHORITY_REPOSITORY_PROTECTED_TABLES:
                if table in existing_tables:
                    continue
                if table == "repository_families":
                    connection.execute(
                        """
                        CREATE TABLE repository_families(
                            family_id TEXT PRIMARY KEY,
                            root_repo_id TEXT NOT NULL,
                            payload TEXT NOT NULL
                        )
                        """
                    )
                    continue
                if table == "repository_scopes":
                    connection.execute(
                        """
                        CREATE TABLE repository_scopes(
                            row_id TEXT PRIMARY KEY,
                            repo_id TEXT NOT NULL,
                            family_id TEXT NOT NULL,
                            payload TEXT NOT NULL
                        )
                        """
                    )
                    continue
                selector = (
                    "root_repo_id" if table == "repository_families" else "repo_id"
                )
                connection.execute(
                    f"""
                    CREATE TABLE {table}(
                        row_id TEXT PRIMARY KEY,
                        {selector} TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
            for table, _predicate in cutover.AUTHORITY_REPOSITORY_PENDING_LIFECYCLE:
                columns = {
                    str(row[1])
                    for row in connection.execute(
                        f"PRAGMA table_info({table})"
                    )
                }
                if "status" not in columns:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN status TEXT"
                    )
            connection.execute(
                "INSERT INTO schema_metadata VALUES (1, 12, ?, 7, 'ready', ?)",
                (str(uuid.uuid4()), "2026-07-28T00:00:00Z"),
            )
            connection.execute(
                "INSERT INTO repositories VALUES (?, 'tmp', '/tmp', 2, 'active', ?)",
                (repository_id, "2026-07-28T00:00:00Z"),
            )
            connection.execute(
                """
                INSERT INTO repository_installations
                VALUES (?, 'installed', 0, 3, NULL, NULL, NULL,
                        'legacy-import', '2026-07-28T00:00:00Z')
                """,
                (repository_id,),
            )
            for index in range(20):
                connection.execute(
                    """
                    INSERT INTO startup_policies VALUES (
                        ?, ?, 'server', ?, 'coordinator', 'enabled', 'disabled',
                        ?, 0, '2026-07-28T00:00:00Z'
                    )
                    """,
                    (
                        f"policy-{index:02d}",
                        repository_id,
                        f"server-{index:02d}",
                        "sha256:" + f"{index + 1:064x}",
                    ),
                )
            connection.execute(
                """
                INSERT INTO startup_policy_restore_states VALUES(
                    'policy-00', ?, 'server', 'server-00', 'coordinator',
                    ?, ?, 'binding-00', ?, ?, 'enabled', 1, 'captured',
                    NULL, NULL, NULL, NULL, NULL, 'capture-operation-00',
                    NULL, 2, '2026-07-28T00:00:00Z', NULL,
                    '2026-07-28T00:00:00Z'
                )
                """,
                (
                    repository_id,
                    "sha256:" + f"{1:064x}",
                    "sha256:" + ("a" * 64),
                    "sha256:" + ("b" * 64),
                    "sha256:" + ("c" * 64),
                ),
            )
            for table in cutover.AUTHORITY_REPOSITORY_PROTECTED_TABLES:
                if table in {
                    "broker_repository_enrollments",
                    "startup_policies",
                    "startup_policy_restore_states",
                    *{
                        pending_table
                        for pending_table, _predicate in (
                            cutover.AUTHORITY_REPOSITORY_PENDING_LIFECYCLE
                        )
                    },
                }:
                    continue
                selector_id = repository_id
                if table == "repository_scopes":
                    connection.execute(
                        "INSERT INTO repository_scopes VALUES (?, ?, ?, ?)",
                        (
                            "repository-scopes-row",
                            selector_id,
                            "repository-families-row",
                            "repository-scopes-payload",
                        ),
                    )
                else:
                    connection.execute(
                        f"INSERT INTO {table} VALUES (?, ?, ?)",
                        (f"{table}-row", selector_id, f"{table}-payload"),
                    )
            connection.commit()
        os.chmod(database, 0o600)
        maintenance_root = root / "maintenance"
        maintenance_root.mkdir(mode=0o750)
        deployment_id = str(uuid.uuid4())
        activate_maintenance(
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            deployment_id=deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at="2026-07-28T00:00:00Z",
            maintenance_root=maintenance_root,
        )
        return database, root / "repair-plan.json", maintenance_root, deployment_id

    @staticmethod
    def _state(database: Path) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        with closing(sqlite3.connect(database)) as connection:
            connection.row_factory = sqlite3.Row
            metadata = connection.execute(
                "SELECT * FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            repository = connection.execute("SELECT * FROM repositories").fetchone()
            installation = connection.execute(
                "SELECT * FROM repository_installations"
            ).fetchone()
        if metadata is None or repository is None or installation is None:
            raise AssertionError("fixture state is incomplete")
        return metadata, repository, installation

    @staticmethod
    def _policies(database: Path) -> list[sqlite3.Row]:
        with closing(sqlite3.connect(database)) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM startup_policies ORDER BY policy_id"
            ).fetchall()

    def _plan(self, database: Path, plan: Path) -> dict[str, object]:
        return cutover.plan_authority_repository_disable(
            authority_database=database,
            repository_id="eb1dc238-f385-505b-bb7a-cce5107df4e9",
            plan_path=plan,
            authority_uid=os.geteuid(),
            repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
        )

    def _apply(
        self,
        *,
        plan: Path,
        plan_sha256: str,
        attestation: Path,
        maintenance_root: Path,
        deployment_id: str,
        **hooks: object,
    ) -> dict[str, object]:
        return cutover.apply_authority_repository_disable(
            plan_path=plan,
            plan_document_sha256=plan_sha256,
            attestation=attestation,
            maintenance_root=maintenance_root,
            maintenance_gid=os.getegid(),
            maintenance_deployment_id=deployment_id,
            authority_uid=os.geteuid(),
            repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
            **hooks,
        )

    def _legacy_repaired_fixture(
        self, root: Path
    ) -> tuple[Path, Path, dict[str, object], Path, dict[str, object], Path, str]:
        database, current_plan_path, maintenance, deployment = self._fixture(root)
        self._plan(database, current_plan_path)
        current = cutover.read_private_json(
            current_plan_path, uid=os.geteuid()
        )
        legacy_plan = cutover.seal(
            cutover.AUTHORITY_REPOSITORY_DISABLE_PLAN_KIND,
            {
                field: current[field]
                for field in cutover.LEGACY_AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS
            },
        )
        source_plan = root / "legacy-repair-plan.json"
        publish_json(source_plan, legacy_plan, uid=os.geteuid())
        applied_at = "2026-07-29T00:00:00Z"
        reason = cutover._authority_repair_mutation_reason(
            plan_id=str(legacy_plan["plan_id"]),
            deployment_id=deployment,
            state_revision_before=7,
        )
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                UPDATE repository_installations
                SET status='disabled', startup_fenced=1, generation=4,
                    disabled_at=?, reason=?, actor=?, updated_at=?
                """,
                (
                    applied_at,
                    reason,
                    cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                    applied_at,
                ),
            )
            connection.execute(
                """
                UPDATE repositories
                SET state='missing', generation=3, updated_at=?
                """,
                (applied_at,),
            )
            connection.execute(
                """
                UPDATE schema_metadata
                SET state_revision=8, updated_at=?
                """,
                (applied_at,),
            )
            connection.commit()
        after_identity = cutover._database_identity(
            database, uid=os.geteuid()
        )
        repair = cutover.seal(
            cutover.AUTHORITY_REPOSITORY_DISABLE_RESULT_KIND,
            {
                "plan_id": legacy_plan["plan_id"],
                "plan_document_sha256": legacy_plan["document_sha256"],
                "authority_database": str(database),
                "authority_uid": os.geteuid(),
                "authority_generation": legacy_plan["authority_generation"],
                "maintenance_deployment_id": deployment,
                "database_identity_before": legacy_plan["database_identity"],
                "database_identity_after": after_identity,
                "repository_id": legacy_plan["repository"]["repository_id"],
                "repository_generation_before": 2,
                "repository_generation_after": 3,
                "installation_generation_before": 3,
                "installation_generation_after": 4,
                "state_revision_before": 7,
                "state_revision_after": 8,
                "repository_state": "missing",
                "installation_status": "disabled",
                "startup_fenced": True,
                "enrollment_count": 0,
                "reason": reason,
                "actor": cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                "applied_at": applied_at,
            },
        )
        repair_attestation = root / "legacy-repair-result.json"
        publish_json(repair_attestation, repair, uid=os.geteuid())
        return (
            database,
            source_plan,
            legacy_plan,
            repair_attestation,
            repair,
            maintenance,
            deployment,
        )

    def _plan_reconciliation(
        self,
        *,
        source_plan: Path,
        source_plan_document: dict[str, object],
        repair_attestation: Path,
        repair_document: dict[str, object],
        output: Path,
    ) -> dict[str, object]:
        return cutover.plan_authority_repository_startup_policy_reconciliation(
            repair_plan=source_plan,
            repair_plan_document_sha256=str(
                source_plan_document["document_sha256"]
            ),
            repair_attestation=repair_attestation,
            repair_attestation_document_sha256=str(
                repair_document["document_sha256"]
            ),
            plan_path=output,
            authority_uid=os.geteuid(),
            repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
            now_reader=lambda: "2026-07-29T00:01:00Z",
        )

    def _native_repaired_fixture(
        self, root: Path
    ) -> tuple[Path, Path, dict[str, object], Path, dict[str, object], Path, str]:
        fixture = self._legacy_repaired_fixture(root)
        database = fixture[0]
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                UPDATE startup_policies
                SET policy_kind='docker_restart', current_value='unless-stopped',
                    desired_disabled_value='no'
                """
            )
            connection.execute(
                """
                UPDATE startup_policy_restore_states
                SET policy_kind='docker_restart', captured_value='unless-stopped',
                    docker_restart_policy='unless-stopped'
                """
            )
            connection.commit()
        return fixture

    @staticmethod
    def _protected_rows(database: Path) -> dict[str, list[tuple[object, ...]]]:
        with closing(sqlite3.connect(database)) as connection:
            return {
                table: connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                ).fetchall()
                for table in cutover.AUTHORITY_REPOSITORY_PROTECTED_TABLES
            }

    @staticmethod
    def _database_identity(database: Path, *, uid: int) -> dict[str, int]:
        del uid
        status = database.stat()
        return {
            "device": status.st_dev,
            "inode": status.st_ino,
            "size": status.st_size,
        }

    def _plan_lifecycle_recovery(
        self,
        *,
        source_plan: Path,
        source_plan_document: dict[str, object],
        repair_attestation: Path,
        repair_document: dict[str, object],
        output: Path,
        operation_id: str | None = None,
    ) -> dict[str, object]:
        return cutover.plan_authority_repository_lifecycle_recovery(
            repair_plan=source_plan,
            repair_plan_document_sha256=str(
                source_plan_document["document_sha256"]
            ),
            repair_attestation=repair_attestation,
            repair_attestation_document_sha256=str(
                repair_document["document_sha256"]
            ),
            plan_path=output,
            operation_id=operation_id or str(uuid.uuid4()),
            authority_uid=0,
            database_identity_reader=self._database_identity,
            repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
            now_reader=lambda: "2026-07-29T00:02:00Z",
            effective_uid_reader=lambda: 0,
            evidence_reader=read_json,
            evidence_publisher=publish_json,
        )

    def _apply_lifecycle_recovery(
        self,
        *,
        plan: Path,
        plan_sha256: str,
        attestation: Path,
        maintenance_root: Path,
        deployment_id: str,
        **hooks: object,
    ) -> dict[str, object]:
        maintenance_reader = hooks.pop(
            "maintenance_state_reader",
            lambda **_values: SimpleNamespace(
                deployment_id=deployment_id,
                message=PUBLIC_MAINTENANCE_MESSAGE,
            ),
        )
        maintenance_locker = hooks.pop(
            "maintenance_lock_factory", lambda **_values: nullcontext()
        )
        root_reader = hooks.pop(
            "repository_root_proof_reader",
            lambda _root: dict(self.ROOT_PROOF),
        )
        return cutover.apply_authority_repository_lifecycle_recovery(
            plan_path=plan,
            plan_document_sha256=plan_sha256,
            attestation=attestation,
            maintenance_root=maintenance_root,
            maintenance_gid=os.getegid(),
            maintenance_deployment_id=deployment_id,
            authority_uid=0,
            database_identity_reader=self._database_identity,
            repository_root_proof_reader=root_reader,
            maintenance_state_reader=maintenance_reader,
            effective_uid_reader=lambda: 0,
            evidence_reader=read_json,
            evidence_publisher=publish_json,
            maintenance_lock_factory=maintenance_locker,
            broker_lock_factory=lambda _database: nullcontext(),
            **hooks,
        )

    def test_root_proof_accepts_empty_non_git_placeholder(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-root-proof-") as raw:
            root = Path(raw)
            placeholder = root / ".git"
            placeholder.mkdir(mode=0o555)
            placeholder.chmod(0o555)
            proof = cutover._authoritative_repository_root_proof(
                str(root), prove_git_metadata_absent=True
            )
            self.assertTrue(proof["git_metadata_absent"])

    def test_root_proof_rejects_nonempty_git_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-root-proof-") as raw:
            root = Path(raw)
            metadata = root / ".git"
            metadata.mkdir()
            (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            with self.assertRaisesRegex(cutover.CutoverError, "contains Git metadata"):
                cutover._authoritative_repository_root_proof(
                    str(root), prove_git_metadata_absent=True
                )

    def test_root_proof_rejects_gitfile_and_symlink(self) -> None:
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix="authority-root-proof-"
            ) as raw:
                root = Path(raw)
                metadata = root / ".git"
                if kind == "file":
                    metadata.write_text("gitdir: elsewhere\n", encoding="utf-8")
                else:
                    target = root / "elsewhere"
                    target.mkdir()
                    metadata.symlink_to(target, target_is_directory=True)
                with self.assertRaisesRegex(
                    cutover.CutoverError, "contains Git metadata"
                ):
                    cutover._authoritative_repository_root_proof(
                        str(root), prove_git_metadata_absent=True
                    )

    def test_lifecycle_protected_census_covers_combined_authority_schema(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            initialize_schema(
                connection,
                database_generation=str(uuid.uuid4()),
                timestamp="2026-07-29T00:00:00Z",
            )
            connection.executescript(BROKER_SCHEMA)
            evidence = cutover._authority_repository_protected_rows(
                connection, "repository-census-probe"
            )
            repo_tables: set[str] = set()
            for row in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
            ):
                table = str(row[0])
                columns = {
                    str(column[1])
                    for column in connection.execute(
                        f"PRAGMA table_info({table})"
                    )
                }
                if "repo_id" in columns:
                    repo_tables.add(table)
            expected = (
                repo_tables
                - cutover.AUTHORITY_REPOSITORY_INTENTIONALLY_SEPARATE_TABLES
            ) | {"repository_families"}
            self.assertTrue(expected.issubset(set(evidence["tables"])))
            for child_table in (
                "broker_compose_files",
                "broker_compose_services",
                "cleanup_phase_evidence",
                "operation_target_parameters",
                "operation_targets",
                "server_command_arguments",
            ):
                self.assertIn(child_table, evidence["tables"])
            self.assertEqual(
                cutover._validate_authority_repository_protected_rows(evidence),
                evidence,
            )

    def test_plan_is_no_write_private_and_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, _maintenance, _deployment = self._fixture(root)
            before = self._state(database)
            result = self._plan(database, plan)
            after = self._state(database)
            self.assertEqual(
                [tuple(row) for row in before], [tuple(row) for row in after]
            )
            self.assertFalse(result["writes_performed"])
            self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
            document = cutover.read_private_json(plan, uid=os.geteuid())
            self.assertEqual(document["enrollment_count"], 0)
            self.assertEqual(document["repository"]["canonical_root"], "/tmp")
            self.assertEqual(document["repository"]["root_identity"]["mode"], "1777")
            self.assertTrue(document["git_metadata_absent"])

    def test_apply_is_exact_transactional_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, maintenance, deployment = self._fixture(root)
            planned = self._plan(database, plan)
            result_path = root / "repair-result.json"
            first = self._apply(
                plan=plan,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertFalse(first["replayed"])
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 8)
            self.assertEqual(repository["state"], "missing")
            self.assertEqual(repository["generation"], 3)
            self.assertEqual(installation["status"], "disabled")
            self.assertEqual(installation["startup_fenced"], 1)
            self.assertEqual(installation["generation"], 4)
            self.assertIn(str(planned["plan_id"]), installation["reason"])
            second = self._apply(
                plan=plan,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertTrue(second["replayed"])
            self.assertEqual(first["document_sha256"], second["document_sha256"])

    def test_apply_accepts_unrelated_monotonic_revision_and_database_growth(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, maintenance, deployment = self._fixture(root)
            planned = self._plan(database, plan)
            plan_document = cutover.read_private_json(plan, uid=os.geteuid())
            planned_identity = plan_document["database_identity"]
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE unrelated_authority_state(value BLOB NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO unrelated_authority_state VALUES (zeroblob(262144))"
                )
                connection.execute(
                    "UPDATE schema_metadata SET state_revision = state_revision + 4"
                )
                connection.commit()
            grown = database.stat()
            self.assertEqual(grown.st_dev, planned_identity["device"])
            self.assertEqual(grown.st_ino, planned_identity["inode"])
            self.assertGreater(grown.st_size, planned_identity["size"])

            result_path = root / "repair-result.json"
            applied = self._apply(
                plan=plan,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertFalse(applied["replayed"])
            result = cutover.read_private_json(result_path, uid=os.geteuid())
            self.assertEqual(result["state_revision_before"], 11)
            self.assertEqual(result["state_revision_after"], 12)
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 12)
            self.assertEqual(repository["state"], "missing")
            self.assertEqual(installation["status"], "disabled")

    def test_apply_rejects_target_drift_despite_monotonic_revision(self) -> None:
        drifts = {
            "repository field": (
                "UPDATE repositories SET display_name = 'changed-after-plan'",
                (),
            ),
            "installation reason": (
                "UPDATE repository_installations SET reason = 'changed-after-plan'",
                (),
            ),
            "installation timestamp": (
                "UPDATE repository_installations "
                "SET updated_at = '2026-07-29T01:00:00Z'",
                (),
            ),
            "repository timestamp": (
                "UPDATE repositories "
                "SET updated_at = '2026-07-29T01:00:00Z'",
                (),
            ),
        }
        for name, (statement, parameters) in drifts.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="authority-repair-"
            ) as raw:
                root = Path(raw)
                database, plan, maintenance, deployment = self._fixture(root)
                planned = self._plan(database, plan)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(statement, parameters)
                    connection.execute(
                        "UPDATE schema_metadata SET state_revision = state_revision + 1"
                    )
                    connection.commit()
                with self.assertRaisesRegex(cutover.CutoverError, "drifted"):
                    self._apply(
                        plan=plan,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=root / "repair-result.json",
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                    )
                metadata, repository, installation = self._state(database)
                self.assertEqual(metadata["state_revision"], 8)
                self.assertEqual(repository["state"], "active")
                self.assertEqual(installation["status"], "installed")

    def test_precommit_failure_rolls_back_and_retry_completes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, maintenance, deployment = self._fixture(root)
            planned = self._plan(database, plan)
            result_path = root / "repair-result.json"

            def fail() -> None:
                raise RuntimeError("injected before commit")

            with self.assertRaisesRegex(RuntimeError, "before commit"):
                self._apply(
                    plan=plan,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=result_path,
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                    before_commit_hook=fail,
                )
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 7)
            self.assertEqual(repository["state"], "active")
            self.assertEqual(installation["status"], "installed")
            recovered = self._apply(
                plan=plan,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertFalse(recovered["replayed"])

    def test_postcommit_crash_recovers_without_second_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, maintenance, deployment = self._fixture(root)
            planned = self._plan(database, plan)
            result_path = root / "repair-result.json"

            def crash() -> None:
                raise RuntimeError("injected after commit")

            with self.assertRaisesRegex(RuntimeError, "after commit"):
                self._apply(
                    plan=plan,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=result_path,
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                    after_commit_hook=crash,
                )
            self.assertFalse(result_path.exists())
            recovered = self._apply(
                plan=plan,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertTrue(recovered["replayed"])
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 8)
            self.assertEqual(repository["generation"], 3)
            self.assertEqual(installation["generation"], 4)

    def test_drift_and_missing_maintenance_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-") as raw:
            root = Path(raw)
            database, plan, maintenance, deployment = self._fixture(root)
            planned = self._plan(database, plan)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "INSERT INTO broker_repository_enrollments VALUES (?, 42, 'late')",
                    (planned["repository_id"],),
                )
                connection.execute(
                    "UPDATE schema_metadata SET state_revision = state_revision + 1"
                )
                connection.commit()
            with self.assertRaisesRegex(cutover.CutoverError, "drifted"):
                self._apply(
                    plan=plan,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=root / "repair-result.json",
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                )
            (maintenance / "maintenance.json").unlink()
            with self.assertRaisesRegex(cutover.CutoverError, "maintenance fence"):
                self._apply(
                    plan=plan,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=root / "repair-result.json",
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                )

    def test_legacy_policy_reconciliation_is_exact_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-policy-repair-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._legacy_repaired_fixture(root)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    INSERT INTO startup_policies VALUES(
                        'policy-adjacent', 'other-repository', 'server',
                        'other-server', 'coordinator', 'enabled', 'disabled',
                        ?, 11, '2026-07-28T00:00:00Z'
                    )
                    """,
                    ("sha256:" + ("f" * 64),),
                )
                connection.commit()
            restore_before = None
            with closing(sqlite3.connect(database)) as connection:
                connection.row_factory = sqlite3.Row
                restore_before = dict(
                    connection.execute(
                        "SELECT * FROM startup_policy_restore_states "
                        "WHERE policy_id='policy-00'"
                    ).fetchone()
                )
            before = [dict(row) for row in self._policies(database)]
            plan_path = root / "policy-plan.json"
            planned = self._plan_reconciliation(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
            )
            self.assertFalse(planned["writes_performed"])
            self.assertEqual(before, [dict(row) for row in self._policies(database)])
            self.assertEqual(planned["startup_policy_count"], 20)
            self.assertEqual(planned["startup_policy_update_count"], 20)

            result_path = root / "policy-result.json"
            first = cutover.apply_authority_repository_startup_policy_reconciliation(
                plan_path=plan_path,
                plan_document_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                maintenance_gid=os.getegid(),
                maintenance_deployment_id=deployment,
                authority_uid=os.geteuid(),
                repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
            )
            self.assertFalse(first["replayed"])
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 9)
            self.assertEqual(repository["generation"], 3)
            self.assertEqual(installation["generation"], 4)
            policies = [
                row
                for row in self._policies(database)
                if row["repo_id"]
                == "eb1dc238-f385-505b-bb7a-cce5107df4e9"
            ]
            self.assertEqual(len(policies), 20)
            self.assertTrue(
                all(row["current_value"] == row["desired_disabled_value"] for row in policies)
            )
            self.assertTrue(all(row["generation"] == 1 for row in policies))
            with closing(sqlite3.connect(database)) as connection:
                connection.row_factory = sqlite3.Row
                restore_after = dict(
                    connection.execute(
                        "SELECT * FROM startup_policy_restore_states "
                        "WHERE policy_id='policy-00'"
                    ).fetchone()
                )
            self.assertEqual(restore_after, restore_before)
            self.assertEqual(restore_after["status"], "captured")
            self.assertEqual(restore_after["captured_value"], "enabled")
            with closing(sqlite3.connect(database)) as connection:
                adjacent = connection.execute(
                    """
                    SELECT current_value, generation, updated_at
                    FROM startup_policies WHERE policy_id='policy-adjacent'
                    """
                ).fetchone()
            self.assertEqual(
                adjacent,
                ("enabled", 11, "2026-07-28T00:00:00Z"),
            )

            second = cutover.apply_authority_repository_startup_policy_reconciliation(
                plan_path=plan_path,
                plan_document_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                maintenance_gid=os.getegid(),
                maintenance_deployment_id=deployment,
                authority_uid=os.geteuid(),
                repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
            )
            self.assertTrue(second["replayed"])
            self.assertEqual(self._state(database)[0]["state_revision"], 9)

    def test_startup_policy_reconciliation_cli_plans_and_applies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-policy-cli-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._legacy_repaired_fixture(root)
            plan_path = root / "policy-plan.json"
            result_path = root / "policy-result.json"
            interpreter = [sys.executable]
            if sys.flags.optimize:
                interpreter.append("-O")
            command = interpreter + [
                str(ROOT / "scripts/orchestrate_availability_cutover.py"),
                "plan-authority-repository-startup-policy-reconciliation",
                "--source-repair-plan",
                str(source_plan),
                "--source-repair-plan-document-sha256",
                str(source_plan_document["document_sha256"]),
                "--source-repair-attestation",
                str(repair_attestation),
                "--source-repair-attestation-document-sha256",
                str(repair_document["document_sha256"]),
                "--plan",
                str(plan_path),
                "--authority-uid",
                str(os.geteuid()),
            ]
            planned = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            plan_result = json.loads(planned.stdout)
            self.assertEqual(plan_result["startup_policy_update_count"], 20)
            self.assertTrue(plan_path.is_file())

            applied = subprocess.run(
                interpreter
                + [
                    str(ROOT / "scripts/orchestrate_availability_cutover.py"),
                    "apply-authority-repository-startup-policy-reconciliation",
                    "--plan",
                    str(plan_path),
                    "--plan-document-sha256",
                    str(plan_result["document_sha256"]),
                    "--attestation",
                    str(result_path),
                    "--maintenance-root",
                    str(maintenance),
                    "--maintenance-gid",
                    str(os.getegid()),
                    "--maintenance-deployment-id",
                    deployment,
                    "--authority-uid",
                    str(os.geteuid()),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            apply_result = json.loads(applied.stdout)
            self.assertFalse(apply_result["replayed"])
            self.assertTrue(result_path.is_file())
            self.assertEqual(self._state(database)[0]["state_revision"], 9)
            self.assertTrue(
                all(
                    row["current_value"] == row["desired_disabled_value"]
                    for row in self._policies(database)
                )
            )

    def test_policy_reconciliation_rejects_lineage_and_target_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-policy-drift-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._legacy_repaired_fixture(root)
            with self.assertRaisesRegex(cutover.CutoverError, "lineage"):
                cutover.plan_authority_repository_startup_policy_reconciliation(
                    repair_plan=source_plan,
                    repair_plan_document_sha256="0" * 64,
                    repair_attestation=repair_attestation,
                    repair_attestation_document_sha256=str(
                        repair_document["document_sha256"]
                    ),
                    plan_path=root / "bad-lineage.json",
                    authority_uid=os.geteuid(),
                    repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
                )
            plan_path = root / "policy-plan.json"
            planned = self._plan_reconciliation(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
            )
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE startup_policies
                    SET current_value='tampered', generation=generation + 1
                    WHERE policy_id='policy-00'
                    """
                )
                connection.commit()
            with self.assertRaisesRegex(cutover.CutoverError, "drifted"):
                cutover.apply_authority_repository_startup_policy_reconciliation(
                    plan_path=plan_path,
                    plan_document_sha256=str(planned["document_sha256"]),
                    attestation=root / "policy-result.json",
                    maintenance_root=maintenance,
                    maintenance_gid=os.getegid(),
                    maintenance_deployment_id=deployment,
                    authority_uid=os.geteuid(),
                    repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
                )
            self.assertEqual(self._state(database)[0]["state_revision"], 8)
            self.assertTrue(
                any(
                    row["current_value"] == "enabled"
                    for row in self._policies(database)
                    if row["policy_id"] != "policy-00"
                )
            )

    def test_policy_reconciliation_holds_exact_maintenance_through_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-policy-maintenance-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._legacy_repaired_fixture(root)
            plan_path = root / "policy-plan.json"
            planned = self._plan_reconciliation(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
            )
            reads = 0

            def disappearing_maintenance(**_values: object) -> object:
                nonlocal reads
                reads += 1
                if reads == 1:
                    return SimpleNamespace(
                        deployment_id=deployment,
                        message=PUBLIC_MAINTENANCE_MESSAGE,
                    )
                return None

            with self.assertRaisesRegex(
                cutover.CutoverError, "exact active maintenance"
            ):
                cutover.apply_authority_repository_startup_policy_reconciliation(
                    plan_path=plan_path,
                    plan_document_sha256=str(planned["document_sha256"]),
                    attestation=root / "policy-result.json",
                    maintenance_root=maintenance,
                    maintenance_gid=os.getegid(),
                    maintenance_deployment_id=deployment,
                    authority_uid=os.geteuid(),
                    repository_root_proof_reader=lambda _root: dict(
                        self.ROOT_PROOF
                    ),
                    maintenance_state_reader=disappearing_maintenance,
                    maintenance_lock_factory=lambda **_values: nullcontext(),
                    broker_lock_factory=lambda _database: nullcontext(),
                )
            self.assertEqual(reads, 2)
            self.assertEqual(self._state(database)[0]["state_revision"], 8)
            self.assertTrue(
                all(
                    row["current_value"] == "enabled"
                    for row in self._policies(database)
                    if row["repo_id"]
                    == "eb1dc238-f385-505b-bb7a-cce5107df4e9"
                )
            )

    def test_policy_reconciliation_precommit_rollback_and_postcommit_replay(self) -> None:
        for failure_point in ("before", "after"):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory(
                prefix="authority-policy-failpoint-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._legacy_repaired_fixture(root)
                plan_path = root / "policy-plan.json"
                planned = self._plan_reconciliation(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
                result_path = root / "policy-result.json"

                def fail() -> None:
                    raise RuntimeError(f"injected {failure_point} commit")

                with self.assertRaisesRegex(RuntimeError, failure_point):
                    cutover.apply_authority_repository_startup_policy_reconciliation(
                        plan_path=plan_path,
                        plan_document_sha256=str(planned["document_sha256"]),
                        attestation=result_path,
                        maintenance_root=maintenance,
                        maintenance_gid=os.getegid(),
                        maintenance_deployment_id=deployment,
                        authority_uid=os.geteuid(),
                        repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
                        **{
                            f"{failure_point}_commit_hook": fail,
                        },
                    )
                expected_revision = 8 if failure_point == "before" else 9
                self.assertEqual(
                    self._state(database)[0]["state_revision"], expected_revision
                )
                recovered = (
                    cutover.apply_authority_repository_startup_policy_reconciliation(
                        plan_path=plan_path,
                        plan_document_sha256=str(planned["document_sha256"]),
                        attestation=result_path,
                        maintenance_root=maintenance,
                        maintenance_gid=os.getegid(),
                        maintenance_deployment_id=deployment,
                        authority_uid=os.geteuid(),
                        repository_root_proof_reader=lambda _root: dict(self.ROOT_PROOF),
                    )
                )
                self.assertEqual(
                    recovered["replayed"], failure_point == "after"
                )
                self.assertEqual(self._state(database)[0]["state_revision"], 9)

    def test_lifecycle_recovery_reenables_authority_without_native_row_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-lifecycle-recovery-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._native_repaired_fixture(root)
            before = self._protected_rows(database)
            plan_path = root / "lifecycle-recovery-plan.json"
            planned = self._plan_lifecycle_recovery(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
            )
            self.assertFalse(planned["writes_performed"])
            self.assertEqual(before, self._protected_rows(database))
            result_path = root / "lifecycle-recovery-result.json"
            first = self._apply_lifecycle_recovery(
                plan=plan_path,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertFalse(first["replayed"])
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 9)
            self.assertEqual(repository["state"], "active")
            self.assertEqual(repository["generation"], 4)
            self.assertEqual(installation["status"], "installed")
            self.assertEqual(installation["startup_fenced"], 0)
            self.assertEqual(installation["generation"], 5)
            self.assertEqual(before, self._protected_rows(database))
            second = self._apply_lifecycle_recovery(
                plan=plan_path,
                plan_sha256=str(planned["document_sha256"]),
                attestation=result_path,
                maintenance_root=maintenance,
                deployment_id=deployment,
            )
            self.assertTrue(second["replayed"])
            self.assertEqual(before, self._protected_rows(database))

    def test_lifecycle_recovery_requires_ready_migration_state_at_plan_and_apply(
        self,
    ) -> None:
        for drift_phase in ("plan", "apply"):
            with self.subTest(drift_phase=drift_phase), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-migration-state-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                plan_path = root / "lifecycle-recovery-plan.json"
                if drift_phase == "apply":
                    planned = self._plan_lifecycle_recovery(
                        source_plan=source_plan,
                        source_plan_document=source_plan_document,
                        repair_attestation=repair_attestation,
                        repair_document=repair_document,
                        output=plan_path,
                    )
                    self.assertEqual(
                        read_json(plan_path, uid=0)["authority_migration_state"],
                        "ready",
                    )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET migration_state='preparing'
                        WHERE singleton=1 AND migration_state='ready'
                        """
                    )
                    connection.commit()
                if drift_phase == "plan":
                    with self.assertRaisesRegex(
                        cutover.CutoverError, "ready schema-12 authority"
                    ):
                        self._plan_lifecycle_recovery(
                            source_plan=source_plan,
                            source_plan_document=source_plan_document,
                            repair_attestation=repair_attestation,
                            repair_document=repair_document,
                            output=plan_path,
                        )
                    self.assertFalse(plan_path.exists())
                else:
                    with self.assertRaisesRegex(
                        cutover.CutoverError, "schema changed"
                    ):
                        self._apply_lifecycle_recovery(
                            plan=plan_path,
                            plan_sha256=str(planned["document_sha256"]),
                            attestation=root / "lifecycle-recovery-result.json",
                            maintenance_root=maintenance,
                            deployment_id=deployment,
                        )
                metadata, repository, installation = self._state(database)
                self.assertEqual(metadata["migration_state"], "preparing")
                self.assertEqual(metadata["state_revision"], 8)
                self.assertEqual(repository["state"], "missing")
                self.assertEqual(installation["status"], "disabled")

    def test_lifecycle_recovery_rejects_protected_row_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-lifecycle-drift-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._native_repaired_fixture(root)
            plan_path = root / "lifecycle-recovery-plan.json"
            planned = self._plan_lifecycle_recovery(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
            )
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "UPDATE repository_memberships SET payload='tampered'"
                )
                connection.commit()
            with self.assertRaisesRegex(cutover.CutoverError, "drifted"):
                self._apply_lifecycle_recovery(
                    plan=plan_path,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=root / "lifecycle-recovery-result.json",
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                )
            metadata, repository, installation = self._state(database)
            self.assertEqual(metadata["state_revision"], 8)
            self.assertEqual(repository["state"], "missing")
            self.assertEqual(installation["status"], "disabled")

    def test_lifecycle_recovery_rejects_new_pending_operations_and_cleanup(self) -> None:
        for table in ("operations", "cleanup_plans"):
            with self.subTest(table=table), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-pending-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                plan_path = root / "lifecycle-recovery-plan.json"
                planned = self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        f"""
                        INSERT INTO {table}(row_id, repo_id, payload, status)
                        VALUES (?, ?, 'late lifecycle request', 'planned')
                        """,
                        (f"late-{table}", repair_document["repository_id"]),
                    )
                    connection.commit()
                with self.assertRaisesRegex(
                    cutover.CutoverError, f"pending lifecycle rows in {table}"
                ):
                    self._apply_lifecycle_recovery(
                        plan=plan_path,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=root / "lifecycle-recovery-result.json",
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                    )
                self.assertEqual(self._state(database)[0]["state_revision"], 8)

    def test_lifecycle_recovery_binds_tombstones_and_materialization_revocations(
        self,
    ) -> None:
        for table in (
            "cleanup_tombstones",
            "broker_server_materialization_revocations",
            "broker_repository_materialization_revocations",
        ):
            with self.subTest(table=table), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-terminal-drift-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                plan_path = root / "lifecycle-recovery-plan.json"
                planned = self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        f"UPDATE {table} SET payload='late terminal evidence'"
                    )
                    connection.commit()
                with self.assertRaisesRegex(cutover.CutoverError, "drifted"):
                    self._apply_lifecycle_recovery(
                        plan=plan_path,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=root / "lifecycle-recovery-result.json",
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                    )
                self.assertEqual(self._state(database)[0]["state_revision"], 8)

    def test_lifecycle_recovery_rechecks_maintenance_under_writer_lock(self) -> None:
        for race in ("cleared", "replaced"):
            with self.subTest(race=race), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-maintenance-race-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                plan_path = root / "lifecycle-recovery-plan.json"
                planned = self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
                marker: dict[str, object] = {
                    "value": SimpleNamespace(
                        deployment_id=deployment,
                        message=PUBLIC_MAINTENANCE_MESSAGE,
                    )
                }

                @contextmanager
                def race_lock(**_values: object):
                    marker["value"] = (
                        None
                        if race == "cleared"
                        else SimpleNamespace(
                            deployment_id=str(uuid.uuid4()),
                            message=PUBLIC_MAINTENANCE_MESSAGE,
                        )
                    )
                    yield

                with self.assertRaisesRegex(
                    cutover.CutoverError, "exact maintenance fence"
                ):
                    self._apply_lifecycle_recovery(
                        plan=plan_path,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=root / "lifecycle-recovery-result.json",
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                        maintenance_state_reader=lambda **_values: marker["value"],
                        maintenance_lock_factory=race_lock,
                    )
                metadata, repository, installation = self._state(database)
                self.assertEqual(metadata["state_revision"], 8)
                self.assertEqual(repository["state"], "missing")
                self.assertEqual(installation["status"], "disabled")

    def test_lifecycle_recovery_rechecks_root_before_commit_and_attestation(
        self,
    ) -> None:
        for drift_call, committed in ((2, False), (3, True)):
            with self.subTest(drift_call=drift_call), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-root-race-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                plan_path = root / "lifecycle-recovery-plan.json"
                planned = self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
                calls = 0

                def root_proof(_root: object) -> dict[str, object]:
                    nonlocal calls
                    calls += 1
                    proof = dict(self.ROOT_PROOF)
                    if calls >= drift_call:
                        proof["inode"] = int(proof["inode"]) + 1
                    return proof

                result_path = root / "lifecycle-recovery-result.json"
                with self.assertRaisesRegex(cutover.CutoverError, "root proof changed"):
                    self._apply_lifecycle_recovery(
                        plan=plan_path,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=result_path,
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                        repository_root_proof_reader=root_proof,
                    )
                metadata, repository, installation = self._state(database)
                self.assertEqual(metadata["state_revision"], 9 if committed else 8)
                self.assertEqual(repository["state"], "active" if committed else "missing")
                self.assertEqual(
                    installation["status"], "installed" if committed else "disabled"
                )
                self.assertFalse(result_path.exists())
                replay = self._apply_lifecycle_recovery(
                    plan=plan_path,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=result_path,
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                )
                self.assertEqual(replay["replayed"], committed)

    def test_lifecycle_recovery_rejects_schema13_owner_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-lifecycle-owner-") as raw:
            root = Path(raw)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                maintenance,
                deployment,
            ) = self._native_repaired_fixture(root)
            owner_uid = 12345
            owner_evidence = "sha256:" + ("d" * 64)
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(REPOSITORY_OWNER_AUTHORITY_DDL)
                connection.execute(
                    "UPDATE schema_metadata SET schema_version=13"
                )
                connection.execute(
                    """
                    INSERT INTO repository_owners(
                        repo_id, owner_uid, repository_generation,
                        authority_generation, evidence_sha256, operation_id,
                        established_by, established_at
                    ) VALUES (?, ?, 3, 1, ?, ?, 'owner-map', ?)
                    """,
                    (
                        repair_document["repository_id"],
                        owner_uid,
                        owner_evidence,
                        str(uuid.uuid4()),
                        "2026-07-29T00:00:30Z",
                    ),
                )
                owner_operation = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO repository_owner_transfers(
                        transfer_id, repo_id, prior_owner_uid, owner_uid,
                        repository_generation, authority_generation,
                        evidence_sha256, evidence_json, operation_id, actor,
                        reason, transferred_at
                    ) VALUES (?, ?, NULL, ?, 3, 1, ?, '{}', ?,
                              'owner-map', 'sealed owner map', ?)
                    """,
                    (
                        "initial-owner-transfer",
                        repair_document["repository_id"],
                        owner_uid,
                        owner_evidence,
                        owner_operation,
                        "2026-07-29T00:00:30Z",
                    ),
                )
                connection.execute(
                    "UPDATE repository_owners SET operation_id=? WHERE repo_id=?",
                    (owner_operation, repair_document["repository_id"]),
                )
                connection.commit()
            before = self._protected_rows(database)
            plan_path = root / "lifecycle-recovery-plan.json"
            with self.assertRaisesRegex(cutover.CutoverError, "schema-12 authority"):
                self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )
            with closing(sqlite3.connect(database)) as connection:
                owner = connection.execute(
                    """
                    SELECT owner_uid, repository_generation,
                           authority_generation, operation_id, established_by
                    FROM repository_owners WHERE repo_id=?
                    """,
                    (repair_document["repository_id"],),
                ).fetchone()
                transfer_count = connection.execute(
                    "SELECT COUNT(*) FROM repository_owner_transfers WHERE repo_id=?",
                    (repair_document["repository_id"],),
                ).fetchone()[0]
            self.assertEqual(
                owner,
                (
                    owner_uid,
                    3,
                    1,
                    owner_operation,
                    "owner-map",
                ),
            )
            self.assertEqual(transfer_count, 1)
            self.assertEqual(before, self._protected_rows(database))
            self.assertFalse(plan_path.exists())

    def test_lifecycle_recovery_precommit_rollback_and_postcommit_replay(self) -> None:
        for failure_point in ("before", "after"):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory(
                prefix="authority-lifecycle-failpoint-"
            ) as raw:
                root = Path(raw)
                (
                    database,
                    source_plan,
                    source_plan_document,
                    repair_attestation,
                    repair_document,
                    maintenance,
                    deployment,
                ) = self._native_repaired_fixture(root)
                before = self._protected_rows(database)
                plan_path = root / "lifecycle-recovery-plan.json"
                planned = self._plan_lifecycle_recovery(
                    source_plan=source_plan,
                    source_plan_document=source_plan_document,
                    repair_attestation=repair_attestation,
                    repair_document=repair_document,
                    output=plan_path,
                )

                def fail() -> None:
                    raise RuntimeError(f"injected {failure_point} commit")

                result_path = root / "lifecycle-recovery-result.json"
                with self.assertRaisesRegex(RuntimeError, failure_point):
                    self._apply_lifecycle_recovery(
                        plan=plan_path,
                        plan_sha256=str(planned["document_sha256"]),
                        attestation=result_path,
                        maintenance_root=maintenance,
                        deployment_id=deployment,
                        **{f"{failure_point}_commit_hook": fail},
                    )
                expected_revision = 8 if failure_point == "before" else 9
                self.assertEqual(
                    self._state(database)[0]["state_revision"], expected_revision
                )
                recovered = self._apply_lifecycle_recovery(
                    plan=plan_path,
                    plan_sha256=str(planned["document_sha256"]),
                    attestation=result_path,
                    maintenance_root=maintenance,
                    deployment_id=deployment,
                )
                self.assertEqual(recovered["replayed"], failure_point == "after")
                self.assertEqual(before, self._protected_rows(database))
                self.assertEqual(self._state(database)[0]["state_revision"], 9)

    def test_supported_service_transaction_restores_and_replays(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-repair-service-") as raw:
            root = Path(raw)
            root.chmod(0o700)
            release = root / "release"
            release.mkdir(mode=0o555)
            database = root / "authority.sqlite3"
            database.write_bytes(b"sealed legacy authority fixture")
            database.chmod(0o600)
            database_info = database.stat()
            database_identity = {
                "device": database_info.st_dev,
                "inode": database_info.st_ino,
                "size": database_info.st_size,
            }
            plan_id = str(uuid.uuid4())
            deployment_id = str(uuid.uuid4())
            operation_id = str(uuid.uuid4())
            repository_id = "eb1dc238-f385-505b-bb7a-cce5107df4e9"
            plan_document = cutover.seal(
                cutover.AUTHORITY_REPOSITORY_DISABLE_PLAN_KIND,
                {
                    "plan_id": plan_id,
                    "authority_database": str(database),
                    "authority_uid": 0,
                    "authority_generation": str(uuid.uuid4()),
                    "authority_state_revision": 7,
                    "database_identity": database_identity,
                    "repository": {
                        "repository_id": repository_id,
                        "display_name": "tmp",
                        "canonical_root": "/tmp",
                        "generation": 2,
                        "state": "active",
                        "repository_updated_at": "2026-07-28T00:00:00Z",
                        "installation_status": "installed",
                        "installation_startup_fenced": False,
                        "installation_generation": 3,
                        "installation_operation_id": None,
                        "installation_disabled_at": None,
                        "installation_reason": None,
                        "installation_actor": "legacy-import",
                        "installation_updated_at": "2026-07-28T00:00:00Z",
                        "root_identity": {
                            "device": 42,
                            "inode": 4242,
                            "mode": "1777",
                            "owner_uid": 0,
                        },
                    },
                    "startup_policies": [],
                    "enrollment_count": 0,
                    "shared_temporary_root": True,
                    "git_metadata_absent": True,
                    "target": {
                        "repository_state": "missing",
                        "installation_status": "disabled",
                        "startup_fenced": True,
                    },
                    "reason": cutover.AUTHORITY_REPOSITORY_REPAIR_REASON,
                    "created_at": "2026-07-28T23:59:00Z",
                },
            )
            plan = root / "repair-plan.json"
            publish_json(plan, plan_document, uid=0)
            repair_result = root / "repair-result.json"
            transaction_journal = root / "service-intent.json"
            transaction_result = root / "service-result.json"
            maintenance_root = root / "maintenance"
            maintenance_root.mkdir(mode=0o700)
            service = FakeServiceTransaction()
            release_digest = "a" * 64
            canary_account = pwd.getpwuid(os.getuid())
            broker_socket = root / "broker.sock"

            def release_verifier(_release: Path) -> dict[str, object]:
                return {
                    "release_digest": release_digest,
                    "capabilities": {"authority_repository_repair": True},
                }

            repair_attempts = 0

            def repairer(**values: object) -> dict[str, object]:
                nonlocal repair_attempts
                repair_attempts += 1
                if repair_attempts == 1:
                    raise RuntimeError("injected repository repair failure")
                result = cutover.seal(
                    cutover.AUTHORITY_REPOSITORY_DISABLE_RESULT_KIND,
                    {
                        "plan_id": plan_id,
                        "plan_document_sha256": plan_document["document_sha256"],
                        "authority_database": str(database),
                        "authority_uid": 0,
                        "authority_generation": plan_document[
                            "authority_generation"
                        ],
                        "maintenance_deployment_id": deployment_id,
                        "database_identity_before": database_identity,
                        "database_identity_after": database_identity,
                        "repository_id": repository_id,
                        "repository_generation_before": 2,
                        "repository_generation_after": 3,
                        "installation_generation_before": 3,
                        "installation_generation_after": 4,
                        "state_revision_before": 7,
                        "state_revision_after": 8,
                        "repository_state": "missing",
                        "installation_status": "disabled",
                        "startup_fenced": True,
                        "startup_policy_count": 0,
                        "startup_policy_update_count": 0,
                        "startup_policies": [],
                        "enrollment_count": 0,
                        "reason": cutover._authority_repair_mutation_reason(
                            plan_id=plan_id,
                            deployment_id=deployment_id,
                            state_revision_before=7,
                        ),
                        "actor": cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                        "applied_at": "2026-07-29T00:00:00Z",
                    },
                )
                publish_json(Path(values["attestation"]), result, uid=0)
                return {
                    "ok": True,
                    "document_sha256": result["document_sha256"],
                }

            readiness_failure: str | None = None
            readiness_failure_phase = "preclear"

            def readiness(**values: object) -> dict[str, object]:
                if (
                    values["phase"] == readiness_failure_phase
                    and readiness_failure is not None
                ):
                    raise cutover.CutoverError(readiness_failure)
                binding = values["binding"]
                phase = values["phase"]
                return {
                    "phase": phase,
                    "broker_socket": binding["broker_socket"],
                    "socket_identity": {
                        "device": 9,
                        "inode": 10,
                        "uid": 0,
                        "gid": 986,
                        "mode": 0o660,
                    },
                    "socket_peer": {"pid": 1234, "uid": 0, "gid": 0},
                    "authority_generation": plan_document[
                        "authority_generation"
                    ],
                    "canary": (
                        None
                        if phase == "preclear"
                        else {
                            "user": canary_account.pw_name,
                            "uid": canary_account.pw_uid,
                            "project": str(root),
                            "repository_id": "canary-repository",
                            "repository_generation": 5,
                            "inventory_sha256": "c" * 64,
                        }
                    ),
                    "invariants": {
                        "contract": "schema12-pre-owner-authority-complete-v1",
                        "schema_version": 12,
                        "database_generation": plan_document[
                            "authority_generation"
                        ],
                        "state_revision": 8,
                        "quick_check": "ok",
                        "semantic_violation_count": 0,
                        "database_identity": database_identity,
                    },
                    "verified_at": "2026-07-29T00:00:00Z",
                }

            arguments = {
                "release": release,
                "plan_path": plan,
                "plan_document_sha256": plan_document["document_sha256"],
                "repair_attestation": repair_result,
                "transaction_journal": transaction_journal,
                "transaction_attestation": transaction_result,
                "maintenance_root": maintenance_root,
                "maintenance_gid": 986,
                "maintenance_deployment_id": deployment_id,
                "operation_id": operation_id,
                "broker_socket": broker_socket,
                "canary_user": canary_account.pw_name,
                "canary_uid": canary_account.pw_uid,
                "canary_project": root,
                "canary_repository_id": "canary-repository",
                "canary_repository_generation": 5,
                "authority_uid": 0,
                "release_verifier": release_verifier,
                "command_status": service.command_status,
                "maintenance_activator": service.activate,
                "maintenance_clearer": service.clear,
                "maintenance_state_reader": service.read_maintenance,
                "evidence_reader": read_json,
                "evidence_publisher": publish_json,
                "effective_uid_reader": lambda: 0,
                "now_reader": lambda: "2026-07-29T00:00:00Z",
                "repairer": repairer,
                "service_readiness_verifier": readiness,
            }
            with self.assertRaisesRegex(
                RuntimeError, "injected repository repair failure"
            ):
                cutover.recover_authority_repository_disable(**arguments)
            self.assertTrue(transaction_journal.exists())
            self.assertFalse(repair_result.exists())
            self.assertFalse(transaction_result.exists())
            self.assertTrue(service.active)
            self.assertIsNone(service.maintenance)
            failed_mutations = [
                command[1]
                for command in service.commands
                if command[1] in {"stop", "start"}
            ]
            self.assertEqual(failed_mutations, ["stop", "start"])

            readiness_failure = (
                "authority repository broker socket never became stably ready"
            )
            before_retry = len(service.commands)
            with self.assertRaisesRegex(
                cutover.CutoverError, "never became stably ready"
            ):
                cutover.recover_authority_repository_disable(**arguments)
            self.assertTrue(repair_result.exists())
            self.assertFalse(transaction_result.exists())
            self.assertTrue(service.active)
            self.assertIsNotNone(service.maintenance)
            mutations = [
                command[1]
                for command in service.commands[before_retry:]
                if command[1] in {"stop", "start"}
            ]
            self.assertEqual(mutations, ["stop", "start"])

            readiness_failure = (
                "authority full invariant proof failed: "
                "disabled_repository_enabled_startup_policy"
            )
            before_invariant = len(service.commands)
            with self.assertRaisesRegex(
                cutover.CutoverError, "full invariant proof failed"
            ):
                cutover.recover_authority_repository_disable(**arguments)
            self.assertFalse(transaction_result.exists())
            self.assertIsNotNone(service.maintenance)
            self.assertEqual(
                [
                    command[1]
                    for command in service.commands[before_invariant:]
                    if command[1] in {"stop", "start"}
                ],
                [],
            )

            readiness_failure_phase = "authenticated"
            readiness_failure = "authority repository authenticated canary failed"
            with self.assertRaisesRegex(
                cutover.CutoverError, "authenticated canary failed"
            ):
                cutover.recover_authority_repository_disable(**arguments)
            self.assertFalse(transaction_result.exists())
            self.assertIsNotNone(service.maintenance)

            readiness_failure = None
            first = cutover.recover_authority_repository_disable(**arguments)
            self.assertFalse(first["replayed"])
            self.assertTrue(service.active)
            self.assertIsNone(service.maintenance)
            before = list(service.commands)
            second = cutover.recover_authority_repository_disable(**arguments)
            self.assertTrue(second["replayed"])
            replay_mutations = [
                command[1]
                for command in service.commands[len(before) :]
                if command[1] in {"stop", "start"}
            ]
            self.assertEqual(replay_mutations, [])

    def test_lifecycle_service_transaction_recovers_restart_loop_and_replays(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="authority-lifecycle-service-"
        ) as raw:
            root = Path(raw)
            root.chmod(0o700)
            (
                database,
                source_plan,
                source_plan_document,
                repair_attestation,
                repair_document,
                _fixture_maintenance,
                _fixture_deployment,
            ) = self._native_repaired_fixture(root)
            operation_id = str(uuid.uuid4())
            deployment_id = str(uuid.uuid4())
            plan_path = root / "lifecycle-recovery-plan.json"
            planned = self._plan_lifecycle_recovery(
                source_plan=source_plan,
                source_plan_document=source_plan_document,
                repair_attestation=repair_attestation,
                repair_document=repair_document,
                output=plan_path,
                operation_id=operation_id,
            )
            plan_document = read_json(plan_path, uid=0)
            before = self._protected_rows(database)
            release = root / "availability-release"
            release.mkdir(mode=0o555)
            canary_release = root / "historical-client-release"
            canary_release.mkdir(mode=0o555)
            release_digest = "a" * 64
            canary_release_digest = "b" * 64
            recovery_result = root / "lifecycle-recovery-result.json"
            transaction_journal = root / "lifecycle-service-intent.json"
            transaction_result = root / "lifecycle-service-result.json"
            maintenance_root = root / "service-maintenance"
            maintenance_root.mkdir(mode=0o700)
            broker_socket = root / "broker.sock"
            canary_account = pwd.getpwuid(os.getuid())
            service = FakeRestartLoopServiceTransaction()
            predecessor_transaction = root / "predecessor-transaction"
            predecessor_transaction.mkdir(mode=0o700)
            predecessor_profile = root / "client-profiles.json"
            predecessor_profile.write_text("{}", encoding="utf-8")
            predecessor_dropin = root / "80-schema12-bridge.conf"
            predecessor_dropin.write_text("[Service]\n", encoding="utf-8")
            predecessor_operation_id = str(uuid.uuid4())
            predecessor_journal_sha256 = "d" * 64
            predecessor_journal_document_sha256 = "e" * 64
            predecessor_mode = "digest-mismatch"
            predecessor_preflight_mode = "ready"
            readiness_revision = 9

            def maintenance_reader(**_values: object) -> object:
                state = service.read_maintenance()
                return None if state is None else SimpleNamespace(**state)

            def readiness(**values: object) -> dict[str, object]:
                self.assertEqual(Path(values["release"]), canary_release)
                binding = values["binding"]
                phase = values["phase"]
                identity = self._database_identity(database, uid=0)
                return {
                    "phase": phase,
                    "broker_socket": binding["broker_socket"],
                    "socket_identity": {
                        "device": 9,
                        "inode": 10,
                        "uid": 0,
                        "gid": 986,
                        "mode": 0o660,
                    },
                    "socket_peer": {"pid": 1234, "uid": 0, "gid": 0},
                    "authority_generation": plan_document[
                        "authority_generation"
                    ],
                    "canary": None,
                    "invariants": {
                        "contract": "schema12-pre-owner-authority-complete-v1",
                        "schema_version": 12,
                        "database_generation": plan_document[
                            "authority_generation"
                        ],
                        "state_revision": readiness_revision,
                        "quick_check": "ok",
                        "semantic_violation_count": 0,
                        "database_identity": identity,
                    },
                    "verified_at": "2026-07-29T00:03:00Z",
                }

            def predecessor_verifier(**_values: object) -> dict[str, object]:
                return {
                    "operation_id": predecessor_operation_id,
                    "bridge_journal": str(
                        predecessor_transaction / "journal.json"
                    ),
                    "bridge_journal_sha256": predecessor_journal_sha256,
                    "bridge_document_sha256": (
                        predecessor_journal_document_sha256
                    ),
                    "broker_release": str(root / "loaded-predecessor-release"),
                    "broker_release_digest": (
                        "f" * 64
                        if predecessor_mode == "digest-mismatch"
                        else canary_release_digest
                    ),
                    "historical_client_release": str(canary_release),
                    "historical_client_release_digest": canary_release_digest,
                    "database": str(database),
                    "database_generation": plan_document[
                        "authority_generation"
                    ],
                    "profile": str(predecessor_profile),
                    "legacy_profile_repository": {
                        "client_uid": canary_account.pw_uid,
                        "repository_id": "canary-repository",
                        "canonical_root": str(root),
                        "generation": 5,
                        "owner_uid_present": False,
                    },
                    "broker_socket": str(broker_socket),
                    "socket_identity": {
                        "device": 9,
                        "inode": 10,
                        "uid": 0,
                        "gid": 986,
                        "mode": 0o660,
                    },
                    "socket_peer": {"pid": 1234, "uid": 0, "gid": 0},
                    "dropin": str(predecessor_dropin),
                    "canary": {
                        "user": canary_account.pw_name,
                        "uid": canary_account.pw_uid,
                        "project": str(root),
                        "inventory_sha256": "c" * 64,
                        "authority": {
                            "database_generation": plan_document[
                                "authority_generation"
                            ],
                            "socket": str(broker_socket),
                        },
                        "repository": {
                            "repository_id": "canary-repository",
                            "canonical_root": str(root),
                            "generation": 5,
                        },
                    },
                }

            def predecessor_validator(value: object) -> dict[str, object]:
                if predecessor_mode == "process-mismatch":
                    raise cutover.CutoverError(
                        "loaded predecessor process release mismatch"
                    )
                if not isinstance(value, dict):
                    raise cutover.CutoverError("predecessor proof is invalid")
                return dict(value)

            def predecessor_preflight(**_values: object) -> dict[str, object]:
                return {"mode": predecessor_preflight_mode}

            def predecessor_rearmer(**_values: object) -> dict[str, object]:
                if service.active_state != "active" or service.sub_state != "running":
                    service.command_status(
                        [
                            "/usr/bin/systemctl",
                            "start",
                            "devcoordinator-broker.service",
                        ]
                    )
                return predecessor_verifier()

            arguments = {
                "release": release,
                "canary_release": canary_release,
                "predecessor_transaction": predecessor_transaction,
                "predecessor_operation_id": predecessor_operation_id,
                "predecessor_journal_sha256": predecessor_journal_sha256,
                "predecessor_journal_document_sha256": (
                    predecessor_journal_document_sha256
                ),
                "predecessor_profile": predecessor_profile,
                "predecessor_dropin": predecessor_dropin,
                "plan_path": plan_path,
                "plan_document_sha256": planned["document_sha256"],
                "recovery_attestation": recovery_result,
                "transaction_journal": transaction_journal,
                "transaction_attestation": transaction_result,
                "maintenance_root": maintenance_root,
                "maintenance_gid": 986,
                "maintenance_deployment_id": deployment_id,
                "operation_id": operation_id,
                "broker_socket": broker_socket,
                "canary_user": canary_account.pw_name,
                "canary_uid": canary_account.pw_uid,
                "canary_project": root,
                "canary_repository_id": "canary-repository",
                "canary_repository_generation": 5,
                "authority_uid": 0,
                "release_verifier": lambda _release: {
                    "release_digest": release_digest,
                    "capabilities": {"authority_repository_repair": True},
                },
                "canary_release_verifier": lambda _release: {
                    "release_digest": canary_release_digest,
                    "authority_schema_version": 12,
                },
                "command_status": service.command_status,
                "service_state_reader": service.read_service,
                "maintenance_activator": service.activate,
                "maintenance_state_reader": maintenance_reader,
                "evidence_reader": read_json,
                "evidence_publisher": publish_json,
                "effective_uid_reader": lambda: 0,
                "now_reader": lambda: "2026-07-29T00:03:00Z",
                "recoverer_options": {
                    "database_identity_reader": self._database_identity,
                    "repository_root_proof_reader": (
                        lambda _root: dict(self.ROOT_PROOF)
                    ),
                    "maintenance_lock_factory": (
                        lambda **_values: nullcontext()
                    ),
                    "broker_lock_factory": lambda _database: nullcontext(),
                    "effective_uid_reader": lambda: 0,
                    "evidence_reader": read_json,
                    "evidence_publisher": publish_json,
                },
                "service_readiness_verifier": readiness,
                "predecessor_verifier": predecessor_verifier,
                "predecessor_proof_validator": predecessor_validator,
                "predecessor_preflight": predecessor_preflight,
                "predecessor_rearmer": predecessor_rearmer,
            }
            with self.assertRaisesRegex(
                cutover.CutoverError, "predecessor proof binding changed"
            ):
                cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertFalse(recovery_result.exists())
            self.assertFalse(transaction_result.exists())
            self.assertIsNone(service.maintenance)
            self.assertEqual(service.commands, [])
            self.assertEqual(before, self._protected_rows(database))

            predecessor_mode = "process-mismatch"
            with self.assertRaisesRegex(
                cutover.CutoverError, "predecessor proof is invalid"
            ):
                cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertFalse(transaction_result.exists())
            self.assertIsNone(service.maintenance)

            predecessor_preflight_mode = "restored"
            predecessor_mode = "digest-mismatch"
            with self.assertRaisesRegex(
                cutover.CutoverError, "predecessor proof binding changed"
            ):
                cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertTrue(recovery_result.exists())
            self.assertFalse(transaction_result.exists())
            self.assertIsNotNone(service.maintenance)
            self.assertEqual(
                [command[1] for command in service.commands], ["stop", "start"]
            )

            predecessor_mode = "process-mismatch"
            with self.assertRaisesRegex(
                cutover.CutoverError, "predecessor proof is invalid"
            ):
                cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertFalse(transaction_result.exists())
            self.assertIsNotNone(service.maintenance)

            predecessor_mode = "ok"
            first = cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertFalse(first["replayed"])
            self.assertEqual(service.active_state, "active")
            self.assertEqual(service.sub_state, "running")
            self.assertIsNotNone(service.maintenance)
            self.assertEqual(
                [command[1] for command in service.commands],
                ["stop", "start"],
            )
            journal = read_json(transaction_journal, uid=0)
            self.assertEqual(journal["canary_release"], str(canary_release))
            self.assertEqual(
                journal["canary_release_digest"], canary_release_digest
            )
            self.assertEqual(
                journal["predecessor"]["journal_sha256"],
                predecessor_journal_sha256,
            )
            terminal = read_json(transaction_result, uid=0)
            self.assertEqual(
                terminal["canary_release_digest"], canary_release_digest
            )
            self.assertFalse(terminal["maintenance_cleared"])
            self.assertTrue(terminal["successor_handoff_required"])
            self.assertEqual(
                terminal["maintenance"]["deployment_id"], deployment_id
            )
            self.assertEqual(
                terminal["predecessor_proof"]["broker_release_digest"],
                canary_release_digest,
            )
            self.assertEqual(
                terminal["preclear_readiness"]["invariants"]["state_revision"],
                readiness_revision,
            )
            before_replay = list(service.commands)
            readiness_revision = 10
            with self.assertRaisesRegex(
                cutover.CutoverError, "readiness changed after handoff"
            ):
                cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertEqual(service.commands, before_replay)
            readiness_revision = 9
            second = cutover.recover_authority_repository_lifecycle(**arguments)
            self.assertTrue(second["replayed"])
            self.assertEqual(service.commands, before_replay)
            self.assertEqual(before, self._protected_rows(database))

    def test_full_schema12_invariant_probe_executes_complete_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="authority-invariant-proof-") as raw:
            database = Path(raw) / "authority.sqlite3"
            generation = str(uuid.uuid4())
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    CREATE TABLE schema_metadata(
                        singleton INTEGER PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        database_generation TEXT NOT NULL,
                        state_revision INTEGER NOT NULL,
                        authority_mode TEXT NOT NULL,
                        migration_state TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO schema_metadata VALUES(1, 12, ?, 9, 'sqlite', 'ready')",
                    (generation,),
                )
                connection.commit()
            database.chmod(0o600)
            original = cutover.invariant_violations
            observed: list[dict[str, object]] = []

            def passing(_connection: object, **options: object) -> list[object]:
                observed.append(dict(options))
                return []

            try:
                cutover.invariant_violations = passing
                proof = cutover._authority_repository_full_schema12_invariant_proof(
                    database=database,
                    authority_uid=os.geteuid(),
                    expected_generation=generation,
                )
                self.assertEqual(proof["semantic_violation_count"], 0)
                self.assertEqual(
                    observed,
                    [
                        {
                            "include_foreign_keys": True,
                            "include_owner_authority": False,
                        }
                    ],
                )
                cutover.invariant_violations = lambda *_args, **_options: [
                    SimpleNamespace(
                        code="disabled_repository_enabled_startup_policy"
                    )
                ]
                with self.assertRaisesRegex(
                    cutover.CutoverError,
                    "disabled_repository_enabled_startup_policy",
                ):
                    cutover._authority_repository_full_schema12_invariant_proof(
                        database=database,
                        authority_uid=os.geteuid(),
                        expected_generation=generation,
                    )
            finally:
                cutover.invariant_violations = original

if __name__ == "__main__":
    unittest.main(verbosity=2)
