#!/usr/bin/env python3
"""Focused fault, migration, and read-purity tests for normalized storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from devcoordinator import legacy_import as legacy_import_module
from devcoordinator.legacy_import import LegacyImportError, LegacySourceChanged
from devcoordinator.store import (
    AccountStore,
    MutationTimeout,
    StoreError,
    TransactionBoundaryError,
)


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def git_repository(path: Path) -> Path:
    private_directory(path)
    (path / ".git").mkdir()
    return path.resolve()


def write_source(home: Path, state: dict) -> None:
    private_directory(home)
    path = home / "state.json"
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def legacy_state(
    repository: Path,
    *,
    revision: int = 1,
    server_id: str = "server-a",
    port: int = 3111,
    missing: Path | None = None,
) -> dict:
    servers = {
        server_id: {
            "id": server_id,
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["npm", "run", "dev", "--", "--port", "{port}"],
            "health_url": "http://127.0.0.1:{port}/health",
            "port": port,
            "status": "stopped",
            "stopped_at": "2026-07-14T10:00:00Z",
        }
    }
    if missing is not None:
        servers["missing-worker"] = {
            "id": "missing-worker",
            "name": "worker",
            "project": str(missing),
            "cwd": str(missing),
            "argv": ["python3", "worker.py"],
            "status": "stopped",
        }
    return {
        "version": 2,
        "revision": revision,
        "created_at": "2026-07-14T09:00:00Z",
        "updated_at": "2026-07-14T10:00:00Z",
        "servers": servers,
        "leases": {},
        "port_assignments": {
            f"{repository}::web": {
                "project": str(repository),
                "name": "web",
                "port": port,
            }
        },
        "operations": {},
        "history": [],
        "docker": {"metadata": {}, "stats_history": {}, "last_commands": []},
    }


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store_home = private_directory(self.root / "store")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def open_store(self, name: str = "store") -> AccountStore:
        home = self.store_home if name == "store" else private_directory(self.root / name)
        return AccountStore.open_default(home)

    def test_private_wal_foreign_keys_and_schema_contract(self) -> None:
        store = self.open_store()
        try:
            self.assertEqual(store.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(store.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            tables = {
                row[0]
                for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            required = {
                "repositories",
                "repository_installations",
                "repository_memberships",
                "startup_policies",
                "startup_policy_restore_states",
                "operations",
                "operation_targets",
                "operation_target_parameters",
                "operation_target_dependencies",
                "resource_retirements",
                "observation_snapshots",
                "legacy_imports",
                "migration_conflicts",
                "unassigned_resources",
            }
            self.assertTrue(required <= tables, required - tables)
            indexes = {
                row[0]
                for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            self.assertIn("one_running_observer_per_domain", indexes)
        finally:
            store.close()

    def test_v1_store_upgrades_atomically_without_inventing_restore_state(self) -> None:
        store = self.open_store()
        database = store.path
        try:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
                    ("retained-host", "retained-machine", "test", "host", "now", "now"),
                )
        finally:
            store.close()
        legacy = sqlite3.connect(str(database), isolation_level=None)
        try:
            legacy.execute("BEGIN IMMEDIATE")
            legacy.execute("DROP TABLE startup_policy_restore_states")
            legacy.execute(
                "UPDATE schema_metadata SET schema_version = 1 WHERE singleton = 1"
            )
            legacy.commit()
        finally:
            legacy.close()
        upgraded = AccountStore.open(database)
        try:
            self.assertEqual(upgraded.metadata.schema_version, 2)
            self.assertIsNotNone(
                upgraded.connection.execute(
                    "SELECT 1 FROM hosts WHERE host_id = 'retained-host'"
                ).fetchone()
            )
            self.assertIsNotNone(
                upgraded.connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'startup_policy_restore_states'
                    """
                ).fetchone()
            )
            self.assertEqual(
                upgraded.connection.execute(
                    "SELECT COUNT(*) FROM startup_policy_restore_states"
                ).fetchone()[0],
                0,
            )
        finally:
            upgraded.close()

    def test_unsafe_parent_file_and_symlink_are_rejected(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaises(PermissionError):
            AccountStore.open_default(unsafe)

        target = private_directory(self.root / "target")
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(PermissionError):
            AccountStore.open_default(alias)

        database = self.store_home / "coordinator.sqlite3"
        database.write_bytes(b"")
        database.chmod(0o644)
        with self.assertRaises(PermissionError):
            AccountStore.open_default(self.store_home)

    def test_read_transaction_is_query_only_and_does_not_touch_revisions_or_files(self) -> None:
        store = self.open_store()
        try:
            # Force WAL/SHM creation and settle filesystem timestamps first.
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
                    ("host", "fingerprint", "test", "test", "now", "now"),
                )
            paths = [store.path, Path(f"{store.path}-wal"), Path(f"{store.path}-shm")]
            before = {
                str(path): (path.stat().st_size, path.stat().st_mtime_ns)
                for path in paths
                if path.exists()
            }
            metadata_before = store.metadata
            inventory = store.inventory_v2()
            projection = store.load_legacy_state_projection()
            metadata_after = store.metadata
            after = {
                str(path): (path.stat().st_size, path.stat().st_mtime_ns)
                for path in paths
                if path.exists()
            }
            self.assertEqual(metadata_before, metadata_after)
            self.assertEqual(before, after)
            self.assertEqual(inventory["schema_version"], 2)
            self.assertEqual(projection["revision"], metadata_before.state_revision)
            with self.assertRaises(sqlite3.OperationalError):
                with store.read_transaction() as connection:
                    connection.execute("UPDATE schema_metadata SET state_revision = 99")
        finally:
            store.close()

    def test_read_only_opener_exposes_current_schema_but_never_mutation(self) -> None:
        with self.open_store() as store:
            store.ensure_local_host()
        database = self.store_home / "coordinator.sqlite3"
        before = database.read_bytes()
        with AccountStore.open_read_only(database) as store:
            self.assertEqual(store.metadata.schema_version, 2)
            self.assertEqual(store.inventory_v2()["schema_version"], 2)
            with self.assertRaisesRegex(StoreError, "opened read-only"):
                with store.immediate_transaction():
                    pass
        self.assertEqual(before, database.read_bytes())

    def test_read_only_opener_never_creates_missing_maintenance_lock(self) -> None:
        with self.open_store() as store:
            store.ensure_local_host()
        database = self.store_home / "coordinator.sqlite3"
        maintenance_lock = self.store_home / ".coordinator-maintenance.lock"
        maintenance_lock.unlink()
        before = database.read_bytes()
        with self.assertRaises(FileNotFoundError):
            AccountStore.open_read_only(database)
        self.assertFalse(maintenance_lock.exists())
        self.assertEqual(before, database.read_bytes())

    def test_read_only_opener_rejects_non_wal_store_without_changing_journal_mode(self) -> None:
        with self.open_store() as store:
            store.ensure_local_host()
        database = self.store_home / "coordinator.sqlite3"
        connection = sqlite3.connect(str(database), isolation_level=None)
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0], "delete")
        finally:
            connection.close()
        before = database.read_bytes()
        with self.assertRaisesRegex(StoreError, "journal mode is delete; expected wal"):
            AccountStore.open_read_only(database)
        self.assertEqual(before, database.read_bytes())
        verification = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        try:
            self.assertEqual(verification.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        finally:
            verification.close()

    def test_v2_graph_exposes_authoritative_board_collections_and_bounds_telemetry(self) -> None:
        store = self.open_store()
        try:
            with store.immediate_transaction(revision_kind="observation") as connection:
                now = "2026-07-15T12:00:00Z"
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-board','machine-board','test','board',?,?)",
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo-board','host-board','/repo/board','Board','active',0,?,?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES ('repo-board','installed',0,0,'test',?)
                    """,
                    (now,),
                )
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES ('server-board','repo-board','web','/repo/board',
                              'definition-board',0,?,?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('assignment-board','host-board','repo-board','web',4317,
                              'active',0,?,?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO leases(
                        lease_id, host_id, repo_id, server_definition_id, port,
                        owner, agent, purpose, status, generation, created_at, updated_at
                    ) VALUES ('lease-board','host-board','repo-board','server-board',4317,
                              'tester','tester','web','active',0,?,?)
                    """,
                    (now, now),
                )
                for index in range(31):
                    connection.execute(
                        """
                        INSERT INTO telemetry_samples(
                            sample_id, host_resource_kind, host_resource_id,
                            sampled_at, cpu_percent, memory_bytes
                        ) VALUES (?, 'container', 'container-a', ?, ?, ?)
                        """,
                        (
                            f"sample-a-{index:02d}",
                            f"2026-07-15T12:{index:02d}:00Z",
                            float(index),
                            index,
                        ),
                    )
                for index in range(2):
                    connection.execute(
                        """
                        INSERT INTO telemetry_samples(
                            sample_id, host_resource_kind, host_resource_id,
                            sampled_at, cpu_percent, memory_bytes
                        ) VALUES (?, 'server', 'server-b', ?, ?, ?)
                        """,
                        (
                            f"sample-b-{index:02d}",
                            f"2026-07-15T13:0{index}:00Z",
                            float(index),
                            index,
                        ),
                    )

            inventory = store.inventory_v2()
            self.assertEqual(inventory["schema_version"], 2)
            for key in (
                "coordinator_sources",
                "docker_engines",
                "memberships",
                "control_bindings",
                "leases",
                "port_assignments",
                "backup_evidence",
                "database_backups",
                "database_restore_events",
                "events",
                "unassigned_resources",
                "lifecycle_violations",
            ):
                self.assertIn(key, inventory)
            self.assertEqual(
                set(inventory["resources"]),
                {"servers", "docker", "docker_ports", "databases"},
            )
            self.assertEqual(inventory["database_backups"], [])
            self.assertEqual(inventory["database_restore_events"], [])
            self.assertEqual(
                inventory["leases"][0]["lease_id"],
                "lease-board",
                "schema-v2 leases must not be overwritten by the legacy projection",
            )
            self.assertNotIn("id", inventory["leases"][0])
            self.assertEqual(
                inventory["port_assignments"][0]["assignment_id"],
                "assignment-board",
                "schema-v2 assignments must not be overwritten by the legacy projection",
            )
            self.assertEqual(inventory["port_assignments"][0]["repo_id"], "repo-board")
            self.assertEqual(inventory["port_assignments"][0]["server_name"], "web")
            self.assertNotIn("project", inventory["port_assignments"][0])
            self.assertEqual(
                inventory["v1_compatibility"]["leases"][0]["id"],
                "lease-board",
            )
            self.assertEqual(
                inventory["v1_compatibility"]["port_assignments"][0]["id"],
                "assignment-board",
            )
            self.assertIsNot(
                inventory["database_backups"],
                inventory["backup_evidence"],
                "migration evidence and restorable database artifacts must stay separate",
            )
            telemetry = inventory["observations"]["telemetry"]
            samples_a = [
                item for item in telemetry if item["host_resource_id"] == "container-a"
            ]
            samples_b = [
                item for item in telemetry if item["host_resource_id"] == "server-b"
            ]
            self.assertEqual(len(samples_a), 30)
            self.assertEqual(len(samples_b), 2)
            self.assertEqual(samples_a[0]["sample_id"], "sample-a-30")
            self.assertEqual(samples_a[-1]["sample_id"], "sample-a-01")
            self.assertTrue(
                all("resource_sample_ordinal" not in item for item in telemetry)
            )
        finally:
            store.close()

    def test_v1_projection_is_one_read_of_active_v2_physical_identities(self) -> None:
        store = self.open_store()
        try:
            now = "2026-07-15T12:00:00Z"
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-parity','machine-parity','test','host',?,?)",
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path, effective_uid,
                        status, created_at, updated_at
                    ) VALUES ('source-parity','host-parity','/source','/source/state',1,
                              'imported',?,?)
                    """,
                    (now, now),
                )
                for repo_id, root, status in (
                    ("repo-active", "/repo/active", "installed"),
                    ("repo-disabled", "/repo/disabled", "disabled"),
                ):
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name, state,
                            generation, created_at, updated_at
                        ) VALUES (?, 'host-parity', ?, ?, 'active', 0, ?, ?)
                        """,
                        (repo_id, root, repo_id, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation, actor,
                            disabled_at, updated_at
                        ) VALUES (?, ?, ?, 0, 'test', ?, ?)
                        """,
                        (
                            repo_id,
                            status,
                            int(status == "disabled"),
                            now if status == "disabled" else None,
                            now,
                        ),
                    )
                for server_id, repo_id in (
                    ("server-active", "repo-active"),
                    ("server-disabled", "repo-disabled"),
                ):
                    connection.execute(
                        """
                        INSERT INTO server_definitions(
                            server_definition_id, repo_id, name, cwd,
                            definition_fingerprint, generation, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'sha256:server', 0, ?, ?)
                        """,
                        (server_id, repo_id, server_id, f"/{server_id}", now, now),
                    )
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES ('engine-parity','host-parity','default','available',?,?)
                    """,
                    (now, now),
                )
                containers = (
                    ("container-active", "a" * 64, "active"),
                    ("container-disabled", "b" * 64, "disabled"),
                    ("container-free", "c" * 64, "free"),
                    ("container-retired", "d" * 64, "retired"),
                )
                for resource_id, full_id, name in containers:
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, created_at, updated_at
                        ) VALUES (?, 'engine-parity', ?, ?, ?, ?)
                        """,
                        (resource_id, full_id, name, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO docker_observations(
                            docker_resource_id, lifecycle, sampled_at,
                            observation_fingerprint
                        ) VALUES (?, 'stopped', ?, ?)
                        """,
                        (resource_id, now, f"observation-{resource_id}"),
                    )
                    connection.execute(
                        """
                        INSERT INTO control_bindings(
                            binding_id, repo_id, resource_kind, resource_id,
                            source_id, capability, provenance, authority_state,
                            priority, generation, created_at, updated_at
                        ) VALUES (?, ?, 'container', ?, 'source-parity',
                                  'lifecycle', 'test', 'authoritative', 10, 0, ?, ?)
                        """,
                        (
                            f"binding-{resource_id}",
                            (
                                "repo-active"
                                if name == "active"
                                else "repo-disabled" if name == "disabled" else None
                            ),
                            resource_id,
                            now,
                            now,
                        ),
                    )
                for resource_id, repo_id in (
                    ("container-active", "repo-active"),
                    ("container-disabled", "repo-disabled"),
                ):
                    connection.execute(
                        """
                        INSERT INTO repository_memberships(
                            membership_id, repo_id, resource_kind, host_resource_id,
                            immutable_fingerprint, control_binding_id, created_at
                        ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                        """,
                        (
                            f"membership-{resource_id}",
                            repo_id,
                            resource_id,
                            f"sha256:{resource_id}",
                            f"binding-{resource_id}",
                            now,
                        ),
                    )
                for resource_id, status in (
                    ("container-free", "active"),
                    ("container-retired", "retired"),
                ):
                    connection.execute(
                        """
                        INSERT INTO unassigned_resources(
                            unassigned_id, host_id, resource_kind, resource_id,
                            display_name, reason_code, status, created_at, updated_at
                        ) VALUES (?, 'host-parity', 'container', ?, ?, 'name_only', ?, ?, ?)
                        """,
                        (f"unassigned-{resource_id}", resource_id, resource_id, status, now, now),
                    )
                connection.execute(
                    """
                    INSERT INTO resource_retirements(
                        host_resource_id, resource_kind, immutable_fingerprint,
                        status, actor, reason, started_at, retired_at, updated_at
                    ) VALUES ('container-retired','container','sha256:retired',
                              'retired','test','test',?,?,?)
                    """,
                    (now, now, now),
                )
                for binding_id, resource_id, repo_id in (
                    ("db-active", "container-active", "repo-active"),
                    ("db-disabled", "container-disabled", "repo-disabled"),
                    ("db-free", "container-free", None),
                    ("db-retired", "container-retired", None),
                ):
                    connection.execute(
                        """
                        INSERT INTO database_bindings(
                            database_binding_id, docker_resource_id, repo_id,
                            database_name, engine_kind, created_at, updated_at
                        ) VALUES (?, ?, ?, 'postgres', 'postgres', ?, ?)
                        """,
                        (binding_id, resource_id, repo_id, now, now),
                    )

            statements: list[str] = []
            store.connection.set_trace_callback(statements.append)
            poison = AssertionError("v1 compatibility attempted independent observation or mutation")
            with mock.patch.object(
                store, "load_legacy_state_projection", side_effect=poison
            ), mock.patch.object(
                store, "replace_legacy_state_projection", side_effect=poison
            ), mock.patch.object(store, "ensure_local_host", side_effect=poison):
                inventory = store.inventory_v2()
            store.connection.set_trace_callback(None)

            self.assertEqual(
                [row["repo_id"] for row in inventory["repositories"]],
                ["repo-active"],
            )
            self.assertEqual(
                [row["membership_id"] for row in inventory["memberships"]],
                ["membership-container-active"],
            )
            self.assertEqual(
                [row["resource_id"] for row in inventory["unassigned_resources"]],
                ["container-free"],
            )
            v2_server_ids = {
                row["server_definition_id"] for row in inventory["resources"]["servers"]
            }
            v1_server_ids = {row["id"] for row in inventory["v1_compatibility"]["servers"]}
            self.assertEqual(v1_server_ids, v2_server_ids, {"v1": v1_server_ids, "v2": v2_server_ids})
            v2_container_ids = {
                row["docker_resource_id"] for row in inventory["resources"]["docker"]
            }
            v1_container_ids = {
                row["host_resource_id"]
                for row in inventory["v1_compatibility"]["docker"]["containers"]
            }
            self.assertEqual(v1_container_ids, v2_container_ids)
            self.assertEqual(v2_container_ids, {"container-active", "container-free"})
            v2_database_ids = {
                row["database_binding_id"] for row in inventory["resources"]["databases"]
            }
            v1_database_ids = {
                row["database_binding_id"]
                for row in inventory["v1_compatibility"]["postgres"]
            }
            self.assertEqual(v1_database_ids, v2_database_ids)
            self.assertEqual(v2_database_ids, {"db-active", "db-free"})
            mutating = [
                statement
                for statement in statements
                if statement.lstrip().upper().startswith(
                    ("INSERT", "UPDATE", "DELETE", "REPLACE")
                )
            ]
            self.assertEqual(mutating, [])
        finally:
            store.close()

    def test_bounded_mutation_and_transaction_escape_roll_back(self) -> None:
        store = self.open_store()
        try:
            with self.assertRaises(MutationTimeout):
                with store.immediate_transaction(max_seconds=0.01) as connection:
                    connection.execute(
                        "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
                        ("slow", "slow-fingerprint", "test", "test", "now", "now"),
                    )
                    time.sleep(0.02)
            self.assertIsNone(store.connection.execute("SELECT 1 FROM hosts WHERE host_id='slow'").fetchone())

            with self.assertRaises(sqlite3.DatabaseError):
                with store.immediate_transaction() as connection:
                    connection.commit()
            self.assertFalse(store.connection.in_transaction)
        finally:
            store.close()

    def test_dry_run_reports_real_dedupe_conflicts_and_missing_repository(self) -> None:
        repository = git_repository(self.root / "repo")
        other = git_repository(self.root / "other")
        missing = self.root / "deleted-worktree"
        source_a = self.root / "source-a"
        source_b = self.root / "source-b"
        source_c = self.root / "source-c"
        state_a = legacy_state(repository, server_id="native-a", port=3111, missing=missing)
        state_b = legacy_state(repository, server_id="native-b", port=3111)
        state_c = legacy_state(repository, server_id="native-c", port=3222)
        # Make the 3111 identity the current claim despite its stopped 3222
        # history, then give a distinct repository a simultaneous current
        # claim. This is a real v2 host-port blocker rather than two retained
        # stopped assignments that happen to share an old port.
        state_a["servers"]["native-a"].update(
            {
                "status": "running",
                "pid": 41020,
                "updated_at": "2026-07-14T11:00:00Z",
                "stopped_at": None,
            }
        )
        state_c["servers"]["other-api"] = {
            "id": "other-api",
            "name": "api",
            "project": str(other),
            "cwd": str(other),
            "argv": ["python3", "api.py", "--port", "{port}"],
            "port": 3111,
            "status": "running",
            "pid": 41021,
            "updated_at": "2026-07-14T11:01:00Z",
        }
        state_c["port_assignments"][f"{other}::api"] = {
            "project": str(other), "name": "api", "port": 3111
        }
        write_source(source_a, state_a)
        write_source(source_b, state_b)
        write_source(source_c, state_c)
        backup = private_directory(self.root / "backups")
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source_a, source_b, source_c], backup, dry_run=True
            )
            self.assertFalse(report.committed)
            self.assertGreaterEqual(report.exact_duplicate_count, 2)
            kinds = {item.kind for item in report.conflicts}
            self.assertIn("assignment_identity_conflict", kinds)
            self.assertIn("host_port_conflict", kinds)
            self.assertEqual(report.missing_repository_count, 1)
            self.assertGreaterEqual(report.unassigned_count, 1)
            self.assertEqual(store.metadata.state_revision, 0)
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0],
                0,
            )
            manifests = list(backup.rglob("manifest.json"))
            self.assertEqual(len(manifests), 3)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in manifests))
        finally:
            store.close()

    def test_stopped_historical_variants_do_not_fence_normalized_authority(self) -> None:
        repository = git_repository(self.root / "repo-a")
        other = git_repository(self.root / "repo-b")
        source = self.root / "source"
        state = legacy_state(repository, server_id="web-old", port=3111)
        state["servers"]["web-old"].update(
            {
                "argv": ["python3", "old.py", "--port", "{port}"],
                "updated_at": "2026-07-14T10:00:00Z",
                "stopped_at": "2026-07-14T10:00:00Z",
            }
        )
        # A legacy store can retain several stopped run records for the same
        # logical (canonical repository, server name). The newer stopped
        # definition is retained as restart evidence; the old definition is
        # provenance, not a competing live controller.
        state["servers"]["web-new"] = {
            "id": "web-new",
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["python3", "new.py", "--port", "{port}"],
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T11:00:00Z",
            "stopped_at": "2026-07-14T11:00:00Z",
        }
        # A second stopped repository historically used the same port. Neither
        # stopped claim may win a host-global reservation or fence migration.
        state["servers"]["other-web"] = {
            "id": "other-web",
            "name": "web",
            "project": str(other),
            "cwd": str(other),
            "argv": ["python3", "other.py", "--port", "{port}"],
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T09:00:00Z",
            "stopped_at": "2026-07-14T09:00:00Z",
        }
        state["port_assignments"][f"{other}::web"] = {
            "project": str(other),
            "name": "web",
            "port": 3111,
        }
        write_source(source, state)
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source], private_directory(self.root / "backups")
            )
            conflicts = {
                conflict.kind: conflict for conflict in report.conflicts
            }
            self.assertEqual(
                conflicts["server_definition_conflict"].severity,
                "warning",
            )
            self.assertEqual(conflicts["host_port_conflict"].severity, "warning")
            self.assertEqual(store.metadata.migration_state, "ready")
            self.assertEqual(
                store.connection.execute(
                    """
                    SELECT b.authority_state
                    FROM control_bindings b
                    JOIN server_definitions d
                      ON d.server_definition_id = b.resource_id
                    JOIN repositories r USING(repo_id)
                    WHERE b.resource_kind='server'
                      AND r.canonical_root = ? AND d.name = 'web'
                    """,
                    (str(repository),),
                ).fetchone()[0],
                "authoritative",
            )
            definition_id = store.connection.execute(
                """
                SELECT d.server_definition_id
                FROM server_definitions d JOIN repositories r USING(repo_id)
                WHERE r.canonical_root = ? AND d.name = 'web'
                """,
                (str(repository),),
            ).fetchone()[0]
            self.assertEqual(
                [
                    row[0]
                    for row in store.connection.execute(
                        """
                        SELECT argument FROM server_command_arguments
                        WHERE server_definition_id = ? ORDER BY ordinal
                        """,
                        (definition_id,),
                    )
                ],
                ["python3", "new.py", "--port", "{port}"],
            )
            self.assertEqual(
                {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT status FROM port_assignments WHERE port = 3111"
                    )
                },
                {"inactive"},
            )
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_live_definition_and_port_contradictions_remain_blocking(self) -> None:
        repository = git_repository(self.root / "repo-a")
        other = git_repository(self.root / "repo-b")
        source = self.root / "source"
        state = legacy_state(repository, server_id="web-a", port=3111)
        state["servers"]["web-a"].update(
            {
                "argv": ["python3", "a.py", "--port", "{port}"],
                "status": "running",
                "pid": 41001,
                "updated_at": "2026-07-14T11:00:00Z",
                "stopped_at": None,
            }
        )
        state["servers"]["web-a-conflict"] = {
            "id": "web-a-conflict",
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["python3", "conflict.py", "--port", "{port}"],
            "port": 3111,
            "status": "running",
            "pid": 41002,
            "updated_at": "2026-07-14T11:01:00Z",
        }
        state["servers"]["web-b"] = {
            "id": "web-b",
            "name": "web",
            "project": str(other),
            "cwd": str(other),
            "argv": ["python3", "b.py", "--port", "{port}"],
            "port": 3111,
            "status": "running",
            "pid": 41003,
            "updated_at": "2026-07-14T11:02:00Z",
        }
        state["port_assignments"][f"{other}::web"] = {
            "project": str(other),
            "name": "web",
            "port": 3111,
        }
        write_source(source, state)
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source], private_directory(self.root / "backups")
            )
            conflicts = {
                conflict.kind: conflict for conflict in report.conflicts
            }
            self.assertEqual(
                conflicts["server_definition_conflict"].severity,
                "blocking",
            )
            self.assertEqual(conflicts["host_port_conflict"].severity, "blocking")
            self.assertEqual(store.metadata.migration_state, "conflicted")
            self.assertEqual(
                store.connection.execute(
                    """
                    SELECT b.authority_state
                    FROM control_bindings b
                    JOIN server_definitions d
                      ON d.server_definition_id = b.resource_id
                    JOIN repositories r USING(repo_id)
                    WHERE b.resource_kind='server'
                      AND r.canonical_root = ? AND d.name = 'web'
                    """,
                    (str(repository),),
                ).fetchone()[0],
                "conflicting",
            )
            self.assertEqual(
                {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT status FROM port_assignments WHERE port = 3111"
                    )
                },
                {"inactive"},
            )
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_one_current_port_claim_supersedes_stopped_history_without_fence(self) -> None:
        historical = git_repository(self.root / "repo-historical")
        current = git_repository(self.root / "repo-current")
        source = self.root / "source"
        state = legacy_state(historical, server_id="historical-web", port=3111)
        state["servers"]["current-web"] = {
            "id": "current-web",
            "name": "web",
            "project": str(current),
            "cwd": str(current),
            "argv": ["python3", "current.py", "--port", "{port}"],
            "port": 3111,
            "status": "running",
            "pid": 41010,
            "updated_at": "2026-07-14T12:00:00Z",
        }
        state["port_assignments"][f"{current}::web"] = {
            "project": str(current),
            "name": "web",
            "port": 3111,
        }
        write_source(source, state)
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source], private_directory(self.root / "backups")
            )
            conflict = next(
                item for item in report.conflicts if item.kind == "host_port_conflict"
            )
            self.assertEqual(conflict.severity, "warning")
            self.assertEqual(store.metadata.migration_state, "ready")
            self.assertEqual(
                {
                    row[0]: row[1]
                    for row in store.connection.execute(
                        """
                        SELECT r.canonical_root, p.status
                        FROM port_assignments p JOIN repositories r USING(repo_id)
                        WHERE p.port=3111
                        """
                    )
                },
                {str(historical): "inactive", str(current): "active"},
            )
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_reconcile_old_historical_conflicts_from_verified_backups_without_reset(self) -> None:
        repository = git_repository(self.root / "repo-a")
        other = git_repository(self.root / "repo-b")
        source = self.root / "source"
        source_copy = self.root / "source-copy"
        state = legacy_state(repository, server_id="web-old", port=3111)
        state["servers"]["web-old"].update(
            {
                "argv": ["python3", "old.py", "--port", "{port}"],
                "environment": {"MODE": "old"},
                "updated_at": "2026-07-14T10:00:00Z",
                "stopped_at": "2026-07-14T10:00:00Z",
            }
        )
        state["servers"]["web-new"] = {
            "id": "web-new",
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["python3", "new.py", "--port", "{port}"],
            "environment": {"MODE": "new"},
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T11:00:00Z",
            "stopped_at": "2026-07-14T11:00:00Z",
        }
        state["servers"]["other-web"] = {
            "id": "other-web",
            "name": "web",
            "project": str(other),
            "cwd": str(other),
            "argv": ["python3", "other.py", "--port", "{port}"],
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T09:00:00Z",
            "stopped_at": "2026-07-14T09:00:00Z",
        }
        state["port_assignments"][f"{other}::web"] = {
            "project": str(other),
            "name": "web",
            "port": 3111,
        }
        write_source(source, state)
        write_source(source_copy, state)
        store = self.open_store()
        try:
            store.import_legacy_homes(
                [source, source_copy], private_directory(self.root / "backups")
            )
            definition = store.connection.execute(
                """
                SELECT d.server_definition_id, d.repo_id
                FROM server_definitions d JOIN repositories r USING(repo_id)
                WHERE r.canonical_root = ? AND d.name = 'web'
                """,
                (str(repository),),
            ).fetchone()
            definition_id = str(definition["server_definition_id"])
            old_source = store.connection.execute(
                """
                SELECT sr.source_resource_id, sr.source_id,
                       ss.definition_fingerprint
                FROM source_resources sr
                JOIN server_source_records ss USING(source_resource_id)
                WHERE sr.resource_kind='server' AND sr.native_id='web-old'
                """
            ).fetchone()
            old_fingerprint = str(old_source["definition_fingerprint"])
            # Recreate the exact unsafe v1-classifier result: source-order
            # chose the old definition, made its binding non-actionable, and
            # fenced the whole database even though every row was stopped.
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET definition_fingerprint = ?
                    WHERE server_definition_id = ?
                    """,
                    (old_fingerprint, definition_id),
                )
                connection.execute(
                    "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                    (definition_id,),
                )
                connection.executemany(
                    "INSERT INTO server_command_arguments VALUES (?, ?, ?)",
                    [
                        (definition_id, ordinal, value)
                        for ordinal, value in enumerate(
                            ["python3", "old.py", "--port", "{port}"]
                        )
                    ],
                )
                connection.execute(
                    "DELETE FROM server_environment WHERE server_definition_id = ?",
                    (definition_id,),
                )
                connection.execute(
                    "INSERT INTO server_environment VALUES (?, 'MODE', 'old')",
                    (definition_id,),
                )
                connection.execute(
                    """
                    UPDATE control_bindings
                    SET source_resource_id=?, source_id=?, provenance='legacy_conflict',
                        authority_state='conflicting', priority=0
                    WHERE resource_kind='server' AND resource_id=?
                    """,
                    (
                        old_source["source_resource_id"],
                        old_source["source_id"],
                        definition_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE repository_memberships SET immutable_fingerprint=?
                    WHERE resource_kind='server' AND host_resource_id=?
                    """,
                    (old_fingerprint, definition_id),
                )
                connection.execute(
                    """
                    UPDATE startup_policies SET immutable_fingerprint=?
                    WHERE resource_kind='server' AND resource_id=?
                    """,
                    (old_fingerprint, definition_id),
                )
                connection.execute(
                    """
                    UPDATE migration_conflicts
                    SET severity='blocking', evidence_json='{"classifier_version":1}'
                    WHERE conflict_kind IN (
                        'server_definition_conflict', 'host_port_conflict'
                    )
                    """
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state='conflicted' WHERE singleton=1"
                )
                connection.execute(
                    """
                    INSERT INTO migration_conflicts(
                        conflict_id, import_id, source_id, conflict_kind,
                        logical_key, severity, disposition, evidence_json,
                        created_at, resolved_at
                    )
                    SELECT 'duplicate-server-definition-conflict', li.import_id,
                           mc.source_id, mc.conflict_kind, mc.logical_key,
                           'blocking', 'open', mc.evidence_json,
                           mc.created_at, NULL
                    FROM migration_conflicts mc
                    JOIN legacy_imports li ON li.import_id != mc.import_id
                    WHERE mc.conflict_kind='server_definition_conflict'
                    ORDER BY li.import_id LIMIT 1
                    """
                )
                connection.execute(
                    """
                    UPDATE server_observations
                    SET lifecycle='stopped', pid=NULL, listener_port=3111,
                        health_classification='stopped', health_ok=0,
                        stopped_at='2026-07-15T08:59:00Z',
                        stopped_reason='fresh normalized observation',
                        sampled_at='2026-07-15T09:00:00Z',
                        observation_fingerprint='fresh-normalized-fingerprint'
                    WHERE server_definition_id=?
                    """,
                    (definition_id,),
                )

            self.assertEqual(
                store.connection.execute(
                    """
                    SELECT COUNT(*) FROM migration_conflicts
                    WHERE conflict_kind='server_definition_conflict'
                      AND disposition='open'
                    """
                ).fetchone()[0],
                2,
            )
            # A verified database may be restored or copied to a different
            # private path without changing its committed authority identity.
            # Reconciliation must use that stored identity, not derive a new
            # source ID from this disposable test path.
            relocated_home = private_directory(self.root / "relocated-store")
            relocated_database = relocated_home / "coordinator.sqlite3"
            descriptor = os.open(
                relocated_database,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
            relocated_connection = sqlite3.connect(str(relocated_database))
            try:
                store.connection.backup(relocated_connection)
            finally:
                relocated_connection.close()
            relocated_database.chmod(0o600)
            store.close()
            store = AccountStore.open(relocated_database)

            before = {
                "database_generation": store.metadata.database_generation,
                "state_revision": store.metadata.state_revision,
                "imports": [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT import_id, source_id, source_sha256, backup_id FROM legacy_imports ORDER BY import_id"
                    )
                ],
                "sources": [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT source_resource_id, payload_sha256 FROM source_resources ORDER BY source_resource_id"
                    )
                ],
                "backups": [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT backup_id, manifest_sha256 FROM backup_evidence ORDER BY backup_id"
                    )
                ],
                "repositories": [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT repo_id, canonical_root FROM repositories ORDER BY repo_id"
                    )
                ],
                "observation": dict(
                    store.connection.execute(
                        "SELECT * FROM server_observations WHERE server_definition_id=?",
                        (definition_id,),
                    ).fetchone()
                ),
            }
            report = store.reconcile_imported_legacy_conflicts()
            self.assertTrue(report.attempted)
            self.assertTrue(report.committed)
            self.assertEqual(report.reclassified_count, 3)
            self.assertEqual(report.blocking_conflict_count, 0)
            self.assertEqual(store.metadata.migration_state, "ready")
            self.assertEqual(store.metadata.database_generation, before["database_generation"])
            self.assertEqual(store.metadata.state_revision, before["state_revision"] + 1)
            self.assertEqual(
                [
                    row[0]
                    for row in store.connection.execute(
                        """
                        SELECT argument FROM server_command_arguments
                        WHERE server_definition_id=? ORDER BY ordinal
                        """,
                        (definition_id,),
                    )
                ],
                ["python3", "new.py", "--port", "{port}"],
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT value FROM server_environment WHERE server_definition_id=? AND name='MODE'",
                    (definition_id,),
                ).fetchone()[0],
                "new",
            )
            new_fingerprint = store.connection.execute(
                "SELECT definition_fingerprint FROM server_definitions WHERE server_definition_id=?",
                (definition_id,),
            ).fetchone()[0]
            self.assertNotEqual(new_fingerprint, old_fingerprint)
            binding = store.connection.execute(
                """
                SELECT authority_state, provenance, source_id
                FROM control_bindings
                WHERE resource_kind='server' AND resource_id=?
                """,
                (definition_id,),
            ).fetchone()
            self.assertEqual(
                tuple(binding)[:2],
                ("authoritative", "normalized_historical_import"),
            )
            self.assertIsNone(
                store.connection.execute(
                    "SELECT captured_sha256 FROM coordinator_sources WHERE source_id=?",
                    (binding["source_id"],),
                ).fetchone()[0]
            )
            self.assertEqual(
                store.connection.execute(
                    """
                    SELECT immutable_fingerprint FROM repository_memberships
                    WHERE resource_kind='server' AND host_resource_id=?
                    """,
                    (definition_id,),
                ).fetchone()[0],
                new_fingerprint,
            )
            self.assertEqual(
                store.connection.execute(
                    """
                    SELECT immutable_fingerprint FROM startup_policies
                    WHERE resource_kind='server' AND resource_id=?
                    """,
                    (definition_id,),
                ).fetchone()[0],
                new_fingerprint,
            )
            self.assertEqual(
                {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT status FROM port_assignments WHERE port=3111"
                    )
                },
                {"inactive"},
            )
            self.assertEqual(
                {
                    row[0]
                    for row in store.connection.execute(
                        """
                        SELECT severity FROM migration_conflicts
                        WHERE conflict_kind IN (
                            'server_definition_conflict', 'host_port_conflict'
                        )
                        """
                    )
                },
                {"warning"},
            )
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT import_id, source_id, source_sha256, backup_id FROM legacy_imports ORDER BY import_id"
                    )
                ],
                before["imports"],
            )
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT source_resource_id, payload_sha256 FROM source_resources ORDER BY source_resource_id"
                    )
                ],
                before["sources"],
            )
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT backup_id, manifest_sha256 FROM backup_evidence ORDER BY backup_id"
                    )
                ],
                before["backups"],
            )
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        "SELECT repo_id, canonical_root FROM repositories ORDER BY repo_id"
                    )
                ],
                before["repositories"],
            )
            self.assertEqual(
                dict(
                    store.connection.execute(
                        "SELECT * FROM server_observations WHERE server_definition_id=?",
                        (definition_id,),
                    ).fetchone()
                ),
                before["observation"],
            )
            self.assertFalse(store.check_invariants())
            second = store.reconcile_imported_legacy_conflicts()
            self.assertFalse(second.attempted)
            self.assertFalse(second.committed)
            self.assertEqual(store.metadata.state_revision, before["state_revision"] + 1)
        finally:
            store.close()

    def test_reconcile_rejects_foreign_and_racing_destination_generations(self) -> None:
        repository = git_repository(self.root / "repo")
        source = self.root / "source"
        state = legacy_state(repository, server_id="web-old", port=3111)
        state["servers"]["web-new"] = {
            "id": "web-new",
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["python3", "new.py", "--port", "{port}"],
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T11:00:00Z",
            "stopped_at": "2026-07-14T11:00:00Z",
        }
        write_source(source, state)
        store = self.open_store()
        try:
            store.import_legacy_homes(
                [source], private_directory(self.root / "backups")
            )
            generation = store.metadata.database_generation
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE migration_conflicts SET severity='blocking'
                    WHERE conflict_kind='server_definition_conflict'
                    """
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state='conflicted' WHERE singleton=1"
                )
                connection.execute(
                    "UPDATE legacy_imports SET destination_generation='foreign-generation'"
                )
            before_revision = store.metadata.state_revision
            before_conflicts = [
                tuple(row)
                for row in store.connection.execute(
                    """
                    SELECT conflict_id, severity, disposition, evidence_json
                    FROM migration_conflicts ORDER BY conflict_id
                    """
                )
            ]
            with self.assertRaisesRegex(
                LegacyImportError, "another database generation"
            ):
                store.reconcile_imported_legacy_conflicts()
            self.assertEqual(store.metadata.state_revision, before_revision)
            self.assertEqual(store.metadata.migration_state, "conflicted")
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        """
                        SELECT conflict_id, severity, disposition, evidence_json
                        FROM migration_conflicts ORDER BY conflict_id
                        """
                    )
                ],
                before_conflicts,
            )

            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE legacy_imports SET destination_generation=?",
                    (generation,),
                )
            definition_before = [
                tuple(row)
                for row in store.connection.execute(
                    """
                    SELECT server_definition_id, definition_fingerprint, generation
                    FROM server_definitions ORDER BY server_definition_id
                    """
                )
            ]
            conflicts_before_race = [
                tuple(row)
                for row in store.connection.execute(
                    """
                    SELECT conflict_id, severity, disposition, evidence_json
                    FROM migration_conflicts ORDER BY conflict_id
                    """
                )
            ]
            revision_before_race = store.metadata.state_revision
            original_loader = legacy_import_module._load_committed_import_captures

            def inject_generation_drift(rows, expected_uid):
                captures = original_loader(rows, expected_uid)
                # Simulate evidence changing after the read-side plan but
                # before the writer transaction. Avoid incrementing the state
                # revision so the destination-generation recheck itself must
                # catch the drift.
                store.connection.execute(
                    "UPDATE legacy_imports SET destination_generation='racing-generation'"
                )
                return captures

            with mock.patch.object(
                legacy_import_module,
                "_load_committed_import_captures",
                side_effect=inject_generation_drift,
            ):
                with self.assertRaisesRegex(
                    LegacySourceChanged, "destination generation changed"
                ):
                    store.reconcile_imported_legacy_conflicts()
            self.assertEqual(store.metadata.state_revision, revision_before_race)
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        """
                        SELECT server_definition_id, definition_fingerprint, generation
                        FROM server_definitions ORDER BY server_definition_id
                        """
                    )
                ],
                definition_before,
            )
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        """
                        SELECT conflict_id, severity, disposition, evidence_json
                        FROM migration_conflicts ORDER BY conflict_id
                        """
                    )
                ],
                conflicts_before_race,
            )
        finally:
            store.close()

    def test_reconcile_tampered_import_backup_fails_without_destination_change(self) -> None:
        repository = git_repository(self.root / "repo")
        source = self.root / "source"
        state = legacy_state(repository, server_id="web-old", port=3111)
        state["servers"]["web-old"]["updated_at"] = "2026-07-14T10:00:00Z"
        state["servers"]["web-new"] = {
            "id": "web-new",
            "name": "web",
            "project": str(repository),
            "cwd": str(repository),
            "argv": ["python3", "new.py", "--port", "{port}"],
            "port": 3111,
            "status": "stopped",
            "updated_at": "2026-07-14T11:00:00Z",
            "stopped_at": "2026-07-14T11:00:00Z",
        }
        write_source(source, state)
        store = self.open_store()
        try:
            store.import_legacy_homes(
                [source], private_directory(self.root / "backups")
            )
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE migration_conflicts SET severity='blocking'
                    WHERE conflict_kind='server_definition_conflict'
                    """
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state='conflicted' WHERE singleton=1"
                )
            manifest_path = Path(
                store.connection.execute(
                    "SELECT manifest_path FROM backup_evidence"
                ).fetchone()[0]
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            backup_path = Path(manifest["backup_state"])
            backup_path.write_bytes(backup_path.read_bytes() + b"\n")
            backup_path.chmod(0o600)
            before_revision = store.metadata.state_revision
            before_conflicts = [
                tuple(row)
                for row in store.connection.execute(
                    """
                    SELECT conflict_id, severity, disposition, evidence_json
                    FROM migration_conflicts ORDER BY conflict_id
                    """
                )
            ]
            with self.assertRaisesRegex(
                LegacyImportError, "backup checksum changed"
            ):
                store.reconcile_imported_legacy_conflicts()
            self.assertEqual(store.metadata.state_revision, before_revision)
            self.assertEqual(store.metadata.migration_state, "conflicted")
            self.assertEqual(
                [
                    tuple(row)
                    for row in store.connection.execute(
                        """
                        SELECT conflict_id, severity, disposition, evidence_json
                        FROM migration_conflicts ORDER BY conflict_id
                        """
                    )
                ],
                before_conflicts,
            )
        finally:
            store.close()

    def test_commit_normalizes_exact_duplicates_installations_and_unassigned_reasons(self) -> None:
        repository = git_repository(self.root / "repo")
        missing = self.root / "missing-repo"
        nongit = private_directory(self.root / "ordinary-directory")
        source_a = self.root / "source-a"
        source_b = self.root / "source-b"
        state_a = legacy_state(repository, server_id="native-a", missing=missing)
        state_b = legacy_state(repository, server_id="native-b")
        state_b["servers"]["not-git"] = {
            "name": "worker", "project": str(nongit), "cwd": str(nongit), "status": "stopped"
        }
        state_b["docker"]["metadata"]["name-only"] = {"name": "name-only"}
        write_source(source_a, state_a)
        write_source(source_b, state_b)
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source_a, source_b], private_directory(self.root / "backups")
            )
            self.assertTrue(report.committed)
            active = store.connection.execute(
                """
                SELECT COUNT(*) FROM repositories r JOIN repository_installations i USING(repo_id)
                WHERE r.state='active' AND i.status='installed'
                """
            ).fetchone()[0]
            self.assertEqual(active, 1)
            missing_row = store.connection.execute(
                """
                SELECT r.state, i.status, i.startup_fenced
                FROM repositories r JOIN repository_installations i USING(repo_id)
                WHERE r.canonical_root = ?
                """,
                (str(missing.resolve()),),
            ).fetchone()
            self.assertEqual(tuple(missing_row), ("missing", "disabled", 1))
            reasons = {
                row[0]
                for row in store.connection.execute("SELECT reason_code FROM unassigned_resources")
            }
            self.assertTrue({"missing_repo", "not_git", "ambiguous_control"} <= reasons)
            # Two source-native IDs remain provenance; one logical definition remains authority.
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM source_resources WHERE resource_kind='server'").fetchone()[0],
                4,
            )
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM server_definitions WHERE name='web'").fetchone()[0],
                1,
            )
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_same_container_cross_repository_claims_never_choose_first_source(self) -> None:
        repository = git_repository(self.root / "repo-a")
        other = git_repository(self.root / "repo-b")
        source_a = self.root / "source-a"
        source_b = self.root / "source-b"
        shared_id = "a" * 64
        same_repo_id = "b" * 64
        state_a = legacy_state(repository, server_id="server-a", port=3111)
        state_b = legacy_state(other, server_id="server-b", port=3222)
        state_a["docker"]["metadata"].update(
            {
                "shared-a": {
                    "container_id": shared_id,
                    "name": "shared-postgres",
                    "project": str(repository),
                    "restart_policy": "always",
                },
                "same-a": {
                    "container_id": same_repo_id,
                    "name": "same-repo-postgres",
                    "project": str(repository),
                    "restart_policy": "unless-stopped",
                },
            }
        )
        state_b["docker"]["metadata"].update(
            {
                "shared-b": {
                    "container_id": shared_id,
                    "name": "shared-postgres-renamed",
                    "project": str(other),
                    "restart_policy": "always",
                },
                # False-positive guard: independent sources agreeing on the
                # same exact repository remain one actionable membership.
                "same-b": {
                    "container_id": same_repo_id,
                    "name": "same-repo-postgres",
                    "project": str(repository),
                    "restart_policy": "unless-stopped",
                },
            }
        )
        write_source(source_a, state_a)
        write_source(source_b, state_b)
        store = self.open_store()
        try:
            report = store.import_legacy_homes(
                [source_a, source_b], private_directory(self.root / "backups")
            )
            self.assertTrue(report.committed)
            self.assertIn(
                "docker_repository_claim_conflict",
                {conflict.kind for conflict in report.conflicts},
            )
            shared_resource = store.connection.execute(
                "SELECT docker_resource_id FROM docker_resources WHERE full_container_id = ?",
                (shared_id,),
            ).fetchone()[0]
            same_resource = store.connection.execute(
                "SELECT docker_resource_id FROM docker_resources WHERE full_container_id = ?",
                (same_repo_id,),
            ).fetchone()[0]
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM docker_resources WHERE full_container_id = ?",
                    (shared_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT conflict_state FROM docker_ownership_claims WHERE docker_resource_id = ?",
                        (shared_resource,),
                    )
                },
                {"conflicting"},
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM repository_memberships WHERE resource_kind='container' AND host_resource_id = ?",
                    (shared_resource,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM control_bindings WHERE resource_kind='container' AND resource_id = ? AND authority_state='authoritative'",
                    (shared_resource,),
                ).fetchone()[0],
                0,
            )
            conflict_rows = store.connection.execute(
                """
                SELECT reason_code, status FROM unassigned_resources
                WHERE resource_kind='container' AND resource_id = ?
                """,
                (shared_resource,),
            ).fetchall()
            self.assertEqual([tuple(row) for row in conflict_rows], [("conflicting_claims", "active")])
            self.assertIsNone(
                store.connection.execute(
                    "SELECT repo_id FROM startup_policies WHERE resource_kind='container' AND resource_id = ?",
                    (shared_resource,),
                ).fetchone()[0]
            )

            same_membership = store.connection.execute(
                """
                SELECT r.canonical_root, b.authority_state
                FROM repository_memberships m
                JOIN repositories r USING(repo_id)
                JOIN control_bindings b ON b.binding_id = m.control_binding_id
                WHERE m.resource_kind='container' AND m.host_resource_id = ?
                """,
                (same_resource,),
            ).fetchone()
            self.assertEqual(tuple(same_membership), (str(repository), "authoritative"))
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM unassigned_resources WHERE resource_kind='container' AND resource_id = ?",
                    (same_resource,),
                ).fetchone()[0],
                0,
            )
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_source_revision_drift_aborts_before_destination_change(self) -> None:
        repository = git_repository(self.root / "repo")
        source = self.root / "source"
        state = legacy_state(repository)
        write_source(source, state)
        store = self.open_store()

        def inject(phase: str) -> None:
            if phase == "import.plan_complete":
                changed = legacy_state(repository, revision=2)
                path = source / "state.json"
                path.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
                path.chmod(0o600)

        try:
            with self.assertRaises(LegacySourceChanged):
                store.import_legacy_homes(
                    [source], private_directory(self.root / "backups"), fault_injector=inject
                )
            self.assertEqual(store.metadata.state_revision, 0)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0], 0)
        finally:
            store.close()

    def test_faults_before_commit_are_atomic_and_after_commit_is_complete(self) -> None:
        repository = git_repository(self.root / "repo")
        phases = (
            "import.transaction_started",
            "import.rows_written",
            "import.invariants_passed",
            "import.before_commit",
        )
        for index, phase in enumerate(phases):
            source = self.root / f"source-{index}"
            write_source(source, legacy_state(repository, revision=index + 1))
            store = self.open_store(f"store-{index}")
            try:
                def inject(current: str, expected: str = phase) -> None:
                    if current == expected:
                        raise RuntimeError(f"fault:{expected}")
                with self.assertRaisesRegex(RuntimeError, f"fault:{phase}"):
                    store.import_legacy_homes(
                        [source], private_directory(self.root / f"backup-{index}"), fault_injector=inject
                    )
                self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0], 0)
                self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM legacy_imports").fetchone()[0], 0)
            finally:
                store.close()

        source = self.root / "source-after"
        write_source(source, legacy_state(repository, revision=20))
        store = self.open_store("store-after")
        try:
            def after_commit(current: str) -> None:
                if current == "import.after_commit":
                    raise RuntimeError("fault:after")
            with self.assertRaisesRegex(RuntimeError, "fault:after"):
                store.import_legacy_homes(
                    [source], private_directory(self.root / "backup-after"), fault_injector=after_commit
                )
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0], 1)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM legacy_imports").fetchone()[0], 1)
            self.assertFalse(store.check_invariants())
        finally:
            store.close()

    def test_late_writer_detection_and_projection_revision_cas(self) -> None:
        repository = git_repository(self.root / "repo")
        source = self.root / "source"
        state = legacy_state(repository)
        write_source(source, state)
        store = self.open_store()
        try:
            store.import_legacy_homes([source], private_directory(self.root / "backups"))
            path = source / "state.json"
            changed = legacy_state(repository, revision=2)
            path.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
            path.chmod(0o600)
            changed_sources = store.detect_late_legacy_writers()
            self.assertEqual(len(changed_sources), 1)
            self.assertEqual(
                store.connection.execute(
                    "SELECT status FROM coordinator_sources WHERE source_id = ?",
                    (changed_sources[0],),
                ).fetchone()[0],
                "conflict",
            )

            revision = store.metadata.state_revision
            replacement = legacy_state(repository, revision=100)
            next_revision = store.replace_legacy_state_projection(replacement, expected_revision=revision)
            self.assertEqual(next_revision, revision + 1)
            with self.assertRaises(LegacySourceChanged):
                store.replace_legacy_state_projection(replacement, expected_revision=revision)
            self.assertEqual(store.metadata.state_revision, next_revision)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
