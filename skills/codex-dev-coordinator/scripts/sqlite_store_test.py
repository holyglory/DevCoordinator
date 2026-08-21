#!/usr/bin/env python3
"""Focused fault and read-purity tests for current normalized storage."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from devcoordinator import store as store_module
from devcoordinator.schema import SCHEMA_VERSION
from devcoordinator.store import (
    AccountStore,
    MutationTimeout,
    StoreError,
)


def canonical_test_temp_base() -> Path:
    """Return a writable canonical base outside any host/user Git marker."""

    candidates = (
        os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT"),
        pwd.getpwuid(os.geteuid()).pw_dir,
        tempfile.gettempdir(),
    )
    for raw in dict.fromkeys(value for value in candidates if value):
        base = Path(str(raw)).resolve()
        if not base.is_dir() or not os.access(base, os.W_OK | os.X_OK):
            continue
        cursor = base
        while not ((cursor / ".git").exists() or (cursor / ".git").is_symlink()):
            if cursor.parent == cursor:
                return base
            cursor = cursor.parent
    raise RuntimeError("no writable test temp root exists outside every Git worktree")


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path



class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=canonical_test_temp_base())
        self.root = Path(self.temporary.name).resolve()
        self.store_home = private_directory(self.root / "store")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def open_store(self, name: str = "store") -> AccountStore:
        home = self.store_home if name == "store" else private_directory(self.root / name)
        return AccountStore.open_default(home)

    def test_current_telemetry_read_is_bounded_by_active_resources(self) -> None:
        store = self.open_store()
        try:
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.executemany(
                    """
                    INSERT INTO telemetry_samples(
                        sample_id, host_resource_kind, host_resource_id,
                        sampled_at, cpu_percent
                    ) VALUES (?, 'server', 'retired-server', ?, ?)
                    """,
                    (
                        (
                            f"retired-sample-{index:05d}",
                            f"2026-07-{1 + index // 1440:02d}T"
                            f"{index // 60 % 24:02d}:{index % 60:02d}:00Z",
                            float(index),
                        )
                        for index in range(20_000)
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO telemetry_samples(
                        sample_id, host_resource_kind, host_resource_id,
                        sampled_at, cpu_percent
                    ) VALUES (?, 'server', 'active-server', ?, ?)
                    """,
                    (
                        (
                            f"active-sample-{index:02d}",
                            f"2026-07-27T12:{index:02d}:00Z",
                            float(index),
                        )
                        for index in range(40)
                    ),
                )

            progress_calls = 0

            def reject_historical_scan() -> int:
                nonlocal progress_calls
                progress_calls += 1
                return int(progress_calls > 500)

            with store.read_transaction() as connection:
                connection.set_progress_handler(reject_historical_scan, 100)
                try:
                    samples = store_module._current_telemetry_samples(
                        connection,
                        server_resource_ids={"active-server"},
                        docker_resource_ids=set(),
                        database_resource_ids=set(),
                    )
                finally:
                    connection.set_progress_handler(None, 0)

            self.assertEqual(len(samples), 30)
            self.assertEqual(samples[0]["sample_id"], "active-sample-39")
            self.assertEqual(samples[-1]["sample_id"], "active-sample-10")
            self.assertLess(progress_calls, 500)
        finally:
            store.close()

    def test_current_docker_stats_reuse_latest_evidence_without_history_scan(self) -> None:
        store = self.open_store()
        try:
            now = "2026-07-27T12:00:00Z"
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-current','machine-current','test','host',?,?)",
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, daemon_identity,
                        capability_state, created_at, updated_at
                    ) VALUES (
                        'engine-current', 'host-current', 'default', 'daemon-current',
                        'available', ?, ?
                    )
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, image, created_at, updated_at
                    ) VALUES (
                        'docker-current', 'engine-current', ?, 'current',
                        'fixture/current', ?, ?
                    )
                    """,
                    ("a" * 64, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, sampled_at,
                        observation_fingerprint
                    ) VALUES ('docker-current', 'running', ?, 'observation-current')
                    """,
                    (now,),
                )
                connection.executemany(
                    """
                    INSERT INTO telemetry_samples(
                        sample_id, host_resource_kind, host_resource_id,
                        sampled_at, cpu_percent
                    ) VALUES (?, 'docker', 'docker-retired', ?, ?)
                    """,
                    (
                        (
                            f"retired-docker-sample-{index:05d}",
                            f"2026-07-{1 + index // 1440:02d}T"
                            f"{index // 60 % 24:02d}:{index % 60:02d}:00Z",
                            float(index),
                        )
                        for index in range(20_000)
                    ),
                )
                for sample_id, sampled_at, cpu_percent in (
                    ("docker-current-in-window", "2026-07-27T12:05:00Z", 5.0),
                    ("docker-current-after-window", "2026-07-27T12:20:00Z", 20.0),
                ):
                    connection.execute(
                        """
                        INSERT INTO telemetry_samples(
                            sample_id, host_resource_kind, host_resource_id,
                            sampled_at, cpu_percent
                        ) VALUES (?, 'docker', 'docker-current', ?, ?)
                        """,
                        (sample_id, sampled_at, cpu_percent),
                    )

            progress_calls = 0

            def reject_historical_scan() -> int:
                nonlocal progress_calls
                progress_calls += 1
                return int(progress_calls > 500)

            evidence = store_module.LatestDockerObservation(
                snapshot_id="snapshot-current",
                started_at="2026-07-27T12:00:00Z",
                completed_at="2026-07-27T12:10:00Z",
                resource_ids=frozenset({"docker-current"}),
            )
            with store.read_transaction() as connection:
                connection.set_progress_handler(reject_historical_scan, 100)
                try:
                    current, compatibility = store_module._current_docker_stats(
                        connection,
                        latest_evidence={"host-current": evidence},
                        active_resource_ids={"docker-current"},
                    )
                finally:
                    connection.set_progress_handler(None, 0)

            self.assertEqual(current["docker-current"]["cpu_percent"], 5.0)
            self.assertEqual(compatibility, current)
            self.assertLess(progress_calls, 500)
        finally:
            store.close()

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
                "startup_policies",
                "startup_policy_restore_states",
                "operations",
                "operation_targets",
                "operation_target_parameters",
                "operation_target_dependencies",
                "resource_retirements",
                "observation_snapshots",
                "unassigned_resources",
            }
            self.assertTrue(required <= tables, required - tables)
            self.assertTrue(
                {
                    "repository_memberships",
                    "control_bindings",
                    "repository_owners",
                    "repository_owner_transfers",
                }.isdisjoint(tables)
            )
            indexes = {
                row[0]
                for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            self.assertIn("one_running_observer_per_domain", indexes)
        finally:
            store.close()

    def test_v1_store_requires_explicit_offline_migration_without_startup_writes(
        self,
    ) -> None:
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
        before = database.read_bytes()
        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 1"
        ):
            AccountStore.open(database)
        self.assertEqual(database.read_bytes(), before)
        legacy = sqlite3.connect(str(database))
        try:
            self.assertEqual(
                legacy.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0],
                1,
            )
            self.assertIsNotNone(
                legacy.execute(
                    "SELECT 1 FROM hosts WHERE host_id = 'retained-host'"
                ).fetchone()
            )
            self.assertIsNone(
                legacy.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'startup_policy_restore_states'
                    """
                ).fetchone()
            )
        finally:
            legacy.close()

    def test_local_metadata_is_not_authorization_but_symlinks_are_rejected(self) -> None:
        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        with AccountStore.open_default(shared) as store:
            self.assertEqual(store.metadata.schema_version, SCHEMA_VERSION)

        target = private_directory(self.root / "target")
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(PermissionError):
            AccountStore.open_default(alias)

        database = self.store_home / "coordinator.sqlite3"
        database.write_bytes(b"")
        database.chmod(0o644)
        with AccountStore.open_default(self.store_home) as store:
            self.assertEqual(store.metadata.schema_version, SCHEMA_VERSION)

    def test_disappearing_sqlite_sidecar_is_a_valid_terminal_state(self) -> None:
        database = self.store_home / "coordinator.sqlite3"
        database.write_bytes(b"")
        database.chmod(0o600)
        disappearing = Path(f"{database}-wal")
        original_exists = Path.exists

        def observed_then_removed(path: Path) -> bool:
            if path == disappearing:
                return True
            return original_exists(path)

        with mock.patch.object(Path, "exists", observed_then_removed):
            store_module._validate_private_sqlite_sidecars(database, os.geteuid())

        shared = Path(f"{database}-shm")
        shared.write_bytes(b"sidecar fixture")
        shared.chmod(0o644)
        store_module._validate_private_sqlite_sidecars(database, os.geteuid())

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
            metadata_after = store.metadata
            after = {
                str(path): (path.stat().st_size, path.stat().st_mtime_ns)
                for path in paths
                if path.exists()
            }
            self.assertEqual(metadata_before, metadata_after)
            self.assertEqual(before, after)
            self.assertEqual(inventory["schema_version"], 3)
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
            self.assertEqual(store.metadata.schema_version, SCHEMA_VERSION)
            self.assertEqual(store.inventory_v2()["schema_version"], 3)
            with self.assertRaisesRegex(StoreError, "opened read-only"):
                with store.immediate_transaction():
                    pass
        self.assertEqual(before, database.read_bytes())

    def test_read_only_opener_enables_query_only_before_any_other_sql(self) -> None:
        with self.open_store() as store:
            store.ensure_local_host()
        database = self.store_home / "coordinator.sqlite3"
        real_connect = store_module.sqlite3.connect
        statements: list[list[str]] = []

        class RecordingConnection:
            def __init__(self, connection, connection_statements: list[str]) -> None:
                object.__setattr__(self, "connection", connection)
                object.__setattr__(self, "statements", connection_statements)

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __setattr__(self, name, value) -> None:
                if name in {"connection", "statements"}:
                    object.__setattr__(self, name, value)
                else:
                    setattr(self.connection, name, value)

            def execute(self, sql, *args, **kwargs):
                self.statements.append(str(sql).strip().lower())
                return self.connection.execute(sql, *args, **kwargs)

        def connect_recording(*args, **kwargs):
            connection_statements: list[str] = []
            statements.append(connection_statements)
            return RecordingConnection(real_connect(*args, **kwargs), connection_statements)

        with mock.patch.object(
            store_module.sqlite3,
            "connect",
            side_effect=connect_recording,
        ):
            with AccountStore.open_read_only(database) as store:
                store.connection.execute("PRAGMA query_only = OFF")
                with self.assertRaises(sqlite3.OperationalError):
                    store.connection.execute(
                        "UPDATE schema_metadata SET state_revision = 99 WHERE singleton = 1"
                    )
        self.assertTrue(statements)
        self.assertTrue(all(items[0] == "pragma query_only = on" for items in statements))

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
        before_files = {path.name for path in self.store_home.iterdir()}
        with self.assertRaisesRegex(StoreError, "journal mode is delete; expected wal"):
            AccountStore.open_read_only(database)
        self.assertEqual(before, database.read_bytes())
        self.assertEqual(before_files, {path.name for path in self.store_home.iterdir()})
        verification = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        try:
            self.assertEqual(verification.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        finally:
            verification.close()

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
