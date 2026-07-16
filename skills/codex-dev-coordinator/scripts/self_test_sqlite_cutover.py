#!/usr/bin/env python3
"""Deterministic recall tests for the normalized CLI/store cutover."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("dev_coordinator.py")
SPEC = importlib.util.spec_from_file_location("dev_coordinator_sqlite_cutover", SCRIPT)
assert SPEC and SPEC.loader
coordinator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coordinator
SPEC.loader.exec_module(coordinator)

from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.repository_lifecycle import ResourceKind
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
import devcoordinator.store as store_module
from devcoordinator.store import AccountStore, StoreError, deterministic_id, utc_timestamp


class SQLiteCutoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "account-store"
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CODEX_AGENT_COORDINATOR_HOME": str(self.home),
                # These fixtures exercise the isolated account authority. A
                # real host may have the server-wide profile installed, but
                # that external runtime state must never redirect temporary
                # lifecycle repositories through the production broker.
                "DEVCOORDINATOR_AUTHORITY": "account",
                "DEVCOORDINATOR_STATE_BACKEND": "sqlite",
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def options(self, **changes):
        value = {
            "agent": "cutover-test",
            "project": str(Path(__file__).resolve().parents[3]),
            "max_age_seconds": 0,
            "no_docker": True,
            "backup_dir": None,
            "legacy_home": [],
            "legacy_backup_root": None,
        }
        value.update(changes)
        return value

    def test_fixture_never_loads_an_installed_broker_profile(self) -> None:
        with mock.patch.object(
            coordinator,
            "load_broker_profile",
            side_effect=AssertionError("host broker profile was consulted"),
        ):
            self.assertIsNone(coordinator.configured_broker_profile())

    @staticmethod
    def empty_sample() -> dict:
        return {
            "sampled_at": "2026-07-14T12:00:00Z",
            "inventory": {
                "servers": [],
                "docker": {"available": None, "containers": [], "postgres": []},
            },
        }

    @staticmethod
    def container_sample(
        full_id: str,
        *,
        status: str,
        restart_policy: str | None,
        project: Path | None = None,
        name: str = "fixture-postgres",
    ) -> dict:
        container = {
            "id": full_id[:12],
            "full_id": full_id,
            "name": name,
            "image": "postgres:16",
            "status": status,
            "metadata_source": "coordinator_sidecar" if project is not None else "none",
            "labels": {},
            "port_bindings": [],
            "databases": [],
        }
        if restart_policy is not None:
            container["restart_policy"] = restart_policy
        if project is not None:
            container["project"] = str(project)
        return {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {
                    "available": True,
                    "containers": [container],
                    "postgres": [],
                },
            },
        }

    def observe_sample(self, store: AccountStore, host_id: str, sample: dict) -> None:
        SingleFlightObserver(store).observe(
            host_id=host_id,
            observer_domain="fixture-docker",
            sampler=lambda: sample,
            commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                connection,
                snapshot_id,
                observed,
                host_id=host_id,
                coordinator_home=str(self.home),
            ),
        )

    def test_missing_inventory_is_a_pure_empty_read_and_does_not_create_home(self) -> None:
        result = coordinator.pure_normalized_inventory()
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["servers"], [])
        for key in (
            "coordinator_sources",
            "docker_engines",
            "memberships",
            "leases",
            "port_assignments",
            "backup_evidence",
            "database_backups",
            "database_restore_events",
            "events",
            "unassigned_resources",
            "lifecycle_violations",
            "control_bindings",
        ):
            self.assertEqual(result[key], [], f"empty v2 inventory omitted or populated {key}")
        self.assertEqual(
            result["resources"],
            {"servers": [], "docker": [], "docker_ports": [], "databases": []},
        )
        self.assertEqual(
            result["observations"],
            {
                "servers": [],
                "docker": [],
                "databases": [],
                "telemetry": [],
                "snapshots": [],
            },
        )
        self.assertFalse(self.home.exists(), "pure inventory created durable state")

    def test_existing_inventory_does_not_change_revisions_or_database_bytes(self) -> None:
        with AccountStore.open_default(self.home) as store:
            store.ensure_local_host()
        coordinator.pure_normalized_inventory()
        database = self.home / "coordinator.sqlite3"
        before_bytes = database.read_bytes()
        with AccountStore.open_default(self.home) as store:
            before = store.metadata
        for _ in range(3):
            result = coordinator.pure_normalized_inventory()
            self.assertEqual(result["state_path"], str(database))
        with AccountStore.open_default(self.home) as store:
            after = store.metadata
        self.assertEqual(before.state_revision, after.state_revision)
        self.assertEqual(before.observation_revision, after.observation_revision)
        self.assertEqual(before_bytes, database.read_bytes())

    def test_pure_inventory_rejects_v1_without_upgrading_or_changing_database_bytes(self) -> None:
        source_home = self.root / "stale-schema-source"
        with AccountStore.open_default(source_home) as store:
            store.ensure_local_host()
        source_database = source_home / "coordinator.sqlite3"
        legacy = sqlite3.connect(str(source_database), isolation_level=None)
        try:
            legacy.execute("BEGIN IMMEDIATE")
            legacy.execute("DROP TABLE startup_policy_restore_states")
            legacy.execute(
                "UPDATE schema_metadata SET schema_version = 1 WHERE singleton = 1"
            )
            legacy.commit()
            checkpoint = legacy.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(checkpoint[0], 0, "isolated v1 fixture did not checkpoint cleanly")
        finally:
            legacy.close()

        # Copy only the checkpointed canonical files into the test-owned
        # target. This deterministically starts without WAL/SHM sidecars on
        # every platform while preserving a real WAL-mode database.
        self.home.mkdir(mode=0o700)
        database = self.home / "coordinator.sqlite3"
        database.write_bytes(source_database.read_bytes())
        database.chmod(0o600)
        maintenance_lock = self.home / ".coordinator-maintenance.lock"
        maintenance_lock.write_bytes((source_home / ".coordinator-maintenance.lock").read_bytes())
        maintenance_lock.chmod(0o600)

        before_bytes = database.read_bytes()
        before_files = {path.name for path in self.home.iterdir()}
        self.assertEqual(
            before_files,
            {".coordinator-maintenance.lock", "coordinator.sqlite3"},
            "stale-schema fixture unexpectedly retained SQLite sidecars",
        )
        with self.assertRaisesRegex(StoreError, "unsupported coordinator database schema 1"):
            coordinator.pure_normalized_inventory()
        self.assertEqual(before_bytes, database.read_bytes())
        after_files = {path.name for path in self.home.iterdir()}
        self.assertLessEqual(before_files, after_files, "read-only inventory removed durable files")
        added = after_files - before_files
        self.assertLessEqual(
            added,
            {"coordinator.sqlite3-shm", "coordinator.sqlite3-wal"},
            f"read-only inventory created non-SQLite files: {sorted(added)}",
        )
        for name in added:
            metadata = (self.home / name).lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode), f"unsafe SQLite sidecar: {name}")
            self.assertEqual(metadata.st_uid, os.geteuid(), f"foreign SQLite sidecar: {name}")
            self.assertEqual(
                stat.S_IMODE(metadata.st_mode),
                0o600,
                f"non-private SQLite sidecar: {name}",
            )
        with self.assertRaisesRegex(StoreError, "unsupported coordinator database schema 1"):
            coordinator.pure_normalized_inventory()
        self.assertEqual(
            after_files,
            {path.name for path in self.home.iterdir()},
            "a repeated read-only inventory did not stabilize its coordination files",
        )
        self.assertEqual(before_bytes, database.read_bytes())

        verification = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        try:
            self.assertEqual(
                verification.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0],
                1,
            )
            self.assertIsNone(
                verification.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'startup_policy_restore_states'
                    """
                ).fetchone()
            )
        finally:
            verification.close()

    def test_read_only_open_revalidates_sidecars_after_first_wal_access(self) -> None:
        source_home = self.root / "post-journal-source"
        with AccountStore.open_default(source_home) as store:
            store.ensure_local_host()
            checkpoint = store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(checkpoint[0], 0, "post-journal fixture did not checkpoint cleanly")

        self.home.mkdir(mode=0o700)
        database = self.home / "coordinator.sqlite3"
        database.write_bytes((source_home / "coordinator.sqlite3").read_bytes())
        database.chmod(0o600)
        maintenance_lock = self.home / ".coordinator-maintenance.lock"
        maintenance_lock.write_bytes((source_home / ".coordinator-maintenance.lock").read_bytes())
        maintenance_lock.chmod(0o600)

        real_validator = store_module._validate_private_sqlite_sidecars
        materialized_validation_count = 0

        def reject_materialized_shm(database_path: Path, expected_uid: int) -> None:
            nonlocal materialized_validation_count
            real_validator(database_path, expected_uid)
            shm = Path(f"{database_path}-shm")
            if (
                materialized_validation_count == 0
                and shm.is_file()
                and shm.stat().st_size > 0
            ):
                materialized_validation_count += 1
                raise PermissionError("injected unsafe materialized SQLite SHM")

        with mock.patch.object(
            store_module,
            "_validate_private_sqlite_sidecars",
            side_effect=reject_materialized_shm,
        ):
            with self.assertRaisesRegex(
                PermissionError,
                "injected unsafe materialized SQLite SHM",
            ):
                AccountStore.open_default_read_only(self.home)
        self.assertEqual(
            materialized_validation_count,
            1,
            "read-only open skipped validation after first WAL access",
        )

        # The rejected open must close its SQLite connection and release its
        # shared maintenance descriptor so a subsequent clean open succeeds.
        with AccountStore.open_default_read_only(self.home) as store:
            self.assertEqual(store.metadata.schema_version, 2)

    def test_read_only_open_reports_journal_and_sidecar_failures_together(self) -> None:
        with AccountStore.open_default(self.home) as store:
            store.ensure_local_host()

        real_connect = store_module.sqlite3.connect
        real_validator = store_module._validate_private_sqlite_sidecars
        real_flock = store_module.fcntl.flock
        real_os_close = store_module.os.close
        state = {
            "journal_failed": False,
            "connection_closed": False,
            "maintenance_unlocked": False,
            "descriptor_closed": False,
        }

        class JournalFailureConnection:
            def __init__(self, connection) -> None:
                object.__setattr__(self, "connection", connection)

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __setattr__(self, name, value) -> None:
                if name == "connection":
                    object.__setattr__(self, name, value)
                else:
                    setattr(self.connection, name, value)

            def execute(self, sql, *args, **kwargs):
                if str(sql).strip().lower() == "pragma journal_mode":
                    state["journal_failed"] = True
                    raise sqlite3.OperationalError("injected journal read failure")
                return self.connection.execute(sql, *args, **kwargs)

            def close(self) -> None:
                self.connection.close()
                state["connection_closed"] = True
                raise OSError("injected connection close failure")

        def fail_validation_after_journal(database_path: Path, expected_uid: int) -> None:
            real_validator(database_path, expected_uid)
            if state["journal_failed"]:
                raise PermissionError("injected post-journal validation failure")

        def connect_with_journal_failure(*args, **kwargs):
            if args and "immutable=1" in str(args[0]):
                return real_connect(*args, **kwargs)
            return JournalFailureConnection(real_connect(*args, **kwargs))

        def unlock_then_fail(descriptor: int, operation: int):
            result = real_flock(descriptor, operation)
            if operation == store_module.fcntl.LOCK_UN:
                state["maintenance_unlocked"] = True
                raise OSError("injected maintenance unlock failure")
            return result

        def track_descriptor_close(descriptor: int) -> None:
            real_os_close(descriptor)
            state["descriptor_closed"] = True

        with mock.patch.object(
            store_module.sqlite3,
            "connect",
            side_effect=connect_with_journal_failure,
        ):
            with mock.patch.object(
                store_module,
                "_validate_private_sqlite_sidecars",
                side_effect=fail_validation_after_journal,
            ):
                with mock.patch.object(
                    store_module.fcntl,
                    "flock",
                    side_effect=unlock_then_fail,
                ):
                    with mock.patch.object(
                        store_module.os,
                        "close",
                        side_effect=track_descriptor_close,
                    ):
                        with self.assertRaisesRegex(
                            StoreError,
                            "injected journal read failure.*"
                            "injected post-journal validation failure.*"
                            "injected connection close failure.*"
                            "injected maintenance unlock failure",
                        ):
                            AccountStore.open_default_read_only(self.home)

        self.assertTrue(state["connection_closed"])
        self.assertTrue(state["maintenance_unlocked"])
        self.assertTrue(state["descriptor_closed"])

        with AccountStore.open_default_read_only(self.home) as store:
            self.assertEqual(store.metadata.schema_version, 2)

    def test_pure_inventory_reads_committed_wal_without_changing_database_files(self) -> None:
        now = "2026-07-15T12:00:00Z"
        database = self.home / "coordinator.sqlite3"
        wal = Path(f"{database}-wal")
        maintenance_lock = self.home / ".coordinator-maintenance.lock"
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            store.connection.execute("PRAGMA wal_autocheckpoint = 0")
            checkpoint = store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(checkpoint[0], 0, "WAL visibility fixture did not checkpoint cleanly")
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo-wal-only',?,'/repo/wal-only','WAL Only','active',0,?,?)
                    """,
                    (host_id, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES ('repo-wal-only','installed',0,0,'test',?)
                    """,
                    (now,),
                )

            self.assertTrue(wal.is_file() and wal.stat().st_size > 0, "fixture has no WAL frames")
            main_only = self.root / "checkpointed-main-only.sqlite3"
            main_only.write_bytes(database.read_bytes())
            main_view = sqlite3.connect(
                f"{main_only.as_uri()}?mode=ro&immutable=1",
                uri=True,
                isolation_level=None,
            )
            try:
                self.assertIsNone(
                    main_view.execute(
                        "SELECT 1 FROM repositories WHERE repo_id = 'repo-wal-only'"
                    ).fetchone(),
                    "fixture row was checkpointed instead of remaining WAL-only",
                )
            finally:
                main_view.close()

            before_names = {path.name for path in self.home.iterdir()}
            before_main = (database.stat(), database.read_bytes())
            before_wal = (wal.stat(), wal.read_bytes())
            before_lock = (maintenance_lock.stat(), maintenance_lock.read_bytes())
            result = coordinator.pure_normalized_inventory()
            self.assertIn(
                "repo-wal-only",
                {row["repo_id"] for row in result["repositories"]},
                "pure inventory ignored committed state that exists only in WAL",
            )
            self.assertEqual(before_names, {path.name for path in self.home.iterdir()})
            after_main = database.stat()
            after_wal = wal.stat()
            after_lock = maintenance_lock.stat()
            self.assertEqual(
                (before_main[0].st_dev, before_main[0].st_ino, before_main[1]),
                (after_main.st_dev, after_main.st_ino, database.read_bytes()),
            )
            self.assertEqual(
                (before_wal[0].st_dev, before_wal[0].st_ino, before_wal[1]),
                (after_wal.st_dev, after_wal.st_ino, wal.read_bytes()),
            )
            self.assertEqual(
                (before_lock[0].st_dev, before_lock[0].st_ino, before_lock[1]),
                (after_lock.st_dev, after_lock.st_ino, maintenance_lock.read_bytes()),
            )

    def test_pure_inventory_does_not_checkpoint_orphaned_committed_wal(self) -> None:
        now = "2026-07-15T12:00:00Z"
        database = self.home / "coordinator.sqlite3"
        wal = Path(f"{database}-wal")
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            checkpoint = store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            self.assertEqual(checkpoint[0], 0, "orphaned-WAL fixture did not checkpoint cleanly")

        writer = """
import os, sqlite3, sys
database, host_id, now = sys.argv[1:]
connection = sqlite3.connect(database, isolation_level=None)
connection.execute('PRAGMA wal_autocheckpoint = 0')
connection.execute('BEGIN IMMEDIATE')
connection.execute(
    '''INSERT INTO repositories(
           repo_id, host_id, canonical_root, display_name, state,
           generation, created_at, updated_at
       ) VALUES ('repo-orphaned-wal',?,'/repo/orphaned-wal','Orphaned WAL','active',0,?,?)''',
    (host_id, now, now),
)
connection.execute(
    '''INSERT INTO repository_installations(
           repo_id, status, startup_fenced, generation, actor, updated_at
       ) VALUES ('repo-orphaned-wal','installed',0,0,'test',?)''',
    (now,),
)
connection.commit()
os._exit(0)
"""
        subprocess.run(
            [sys.executable, "-c", writer, str(database), host_id, now],
            check=True,
        )
        self.assertTrue(wal.is_file() and wal.stat().st_size > 0, "child left no committed WAL")

        main_only = self.root / "orphaned-main-only.sqlite3"
        main_only.write_bytes(database.read_bytes())
        main_view = sqlite3.connect(
            f"{main_only.as_uri()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        try:
            self.assertIsNone(
                main_view.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = 'repo-orphaned-wal'"
                ).fetchone(),
                "orphaned fixture row reached the main database before inventory",
            )
        finally:
            main_view.close()

        before_names = {path.name for path in self.home.iterdir()}
        before_main = (database.stat(), database.read_bytes())
        before_wal = (wal.stat(), wal.read_bytes())
        result = coordinator.pure_normalized_inventory()
        self.assertIn(
            "repo-orphaned-wal",
            {row["repo_id"] for row in result["repositories"]},
            "pure inventory ignored the orphaned committed WAL",
        )
        self.assertEqual(before_names, {path.name for path in self.home.iterdir()})
        after_main = database.stat()
        after_wal = wal.stat()
        self.assertEqual(
            (before_main[0].st_dev, before_main[0].st_ino, before_main[1]),
            (after_main.st_dev, after_main.st_ino, database.read_bytes()),
        )
        self.assertEqual(
            (before_wal[0].st_dev, before_wal[0].st_ino, before_wal[1]),
            (after_wal.st_dev, after_wal.st_ino, wal.read_bytes()),
        )

    def test_project_filtered_inventory_preserves_v2_lease_and_assignment_shapes(self) -> None:
        project = Path(__file__).resolve().parents[3]
        now = "2026-07-15T12:00:00Z"
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-board','machine-board','test','board',?,?)",
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo-board','host-board',?,'Board','active',0,?,?)
                    """,
                    (str(project), now, now),
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
                    ) VALUES ('server-board','repo-board','web',?,
                              'definition-board',0,?,?)
                    """,
                    (str(project), now, now),
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

        result = coordinator.pure_normalized_inventory(project=str(project))
        self.assertEqual(result["leases"][0]["lease_id"], "lease-board")
        self.assertEqual(
            result["port_assignments"][0]["assignment_id"],
            "assignment-board",
        )
        self.assertEqual(result["port_assignments"][0]["repo_id"], "repo-board")
        self.assertEqual(result["v1_compatibility"]["leases"][0]["id"], "lease-board")
        self.assertEqual(
            result["v1_compatibility"]["port_assignments"][0]["id"],
            "assignment-board",
        )

    def test_project_filter_removes_every_foreign_normalized_row(self) -> None:
        project = str(Path(__file__).resolve().parents[3])
        foreign = "/foreign/repository"
        compatibility = {
            "coordinator_home": str(self.home),
            "state_path": str(self.home / "coordinator.sqlite3"),
            "project": None,
            "urls": [
                {
                    "project": None,
                    "name": "target",
                    "url": "http://target",
                    "health_url": None,
                    "status": "running",
                },
                {
                    "project": None,
                    "name": "foreign",
                    "url": "http://foreign",
                    "health_url": None,
                    "status": "running",
                },
            ],
            "servers": [
                {
                    "id": "server-target",
                    "project": None,
                    "name": "target",
                    "url": "http://target",
                    "url_is_current": True,
                    "health_url": None,
                    "status": "running",
                    "attribution": {"lifecycle_violation": True},
                },
                {
                    "id": "server-foreign",
                    "project": None,
                    "name": "foreign",
                    "url": "http://foreign",
                    "url_is_current": True,
                    "health_url": None,
                    "status": "running",
                    "attribution": {"lifecycle_violation": True},
                },
            ],
            "leases": [
                {"id": "lease-target", "project": project, "port": 4317},
                {"id": "lease-foreign", "project": foreign, "port": 4318},
            ],
            "port_assignments": [
                {"id": "assignment-target", "project": project, "name": "target"},
                {"id": "assignment-foreign", "project": foreign, "name": "foreign"},
            ],
            "recent_events": [
                {"project": project, "type": "target.event"},
                {"project": foreign, "type": "foreign.event"},
            ],
            "docker": {
                "available": True,
                "containers": [
                    {"id": "docker-target", "project": project},
                    {"id": "docker-foreign", "project": foreign},
                ],
                "postgres": [
                    {"id": "docker-target", "project": project},
                    {"id": "docker-foreign", "project": foreign},
                ],
            },
            "postgres": [
                {"id": "docker-target", "project": project},
                {"id": "docker-foreign", "project": foreign},
            ],
            "backups": [
                {"project": project, "path": "/target.dump"},
                {"project": foreign, "path": "/foreign.dump"},
            ],
            "project_usage": [
                {"project": project, "usage_key": "target"},
                {"project": foreign, "usage_key": "foreign"},
            ],
        }
        inventory = {
            "schema_version": 2,
            "store": {},
            "repositories": [
                {"repo_id": "repo-target", "canonical_root": project},
                {"repo_id": "repo-foreign", "canonical_root": foreign},
            ],
            "coordinator_sources": [
                {"source_id": "source-target"},
                {"source_id": "source-foreign"},
            ],
            "docker_engines": [
                {"engine_id": "engine-target", "capability_state": "unavailable"},
                {"engine_id": "engine-foreign", "capability_state": "available"},
            ],
            "memberships": [
                {
                    "membership_id": "membership-server-target",
                    "repo_id": "repo-target",
                    "resource_kind": "server",
                    "host_resource_id": "server-target",
                },
                {
                    "membership_id": "membership-docker-target",
                    "repo_id": "repo-target",
                    "resource_kind": "container",
                    "host_resource_id": "docker-target",
                },
                {
                    "membership_id": "membership-server-foreign",
                    "repo_id": "repo-foreign",
                    "resource_kind": "server",
                    "host_resource_id": "server-foreign",
                },
                {
                    "membership_id": "membership-docker-foreign",
                    "repo_id": "repo-foreign",
                    "resource_kind": "container",
                    "host_resource_id": "docker-foreign",
                },
            ],
            "control_bindings": [
                {
                    "binding_id": "binding-target",
                    "repo_id": "repo-target",
                    "resource_kind": "server",
                    "resource_id": "server-target",
                    "source_id": "source-target",
                },
                {
                    "binding_id": "binding-control-target",
                    "repo_id": "repo-target",
                    "resource_kind": "container",
                    "resource_id": "docker-control-target",
                    "source_id": "source-target",
                },
                {
                    "binding_id": "binding-foreign",
                    "repo_id": "repo-foreign",
                    "resource_kind": "container",
                    "resource_id": "docker-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "resources": {
                "servers": [
                    {"server_definition_id": "server-target", "repo_id": "repo-target"},
                    {"server_definition_id": "server-foreign", "repo_id": "repo-foreign"},
                ],
                "docker": [
                    {
                        "docker_resource_id": "docker-target",
                        "engine_id": "engine-target",
                    },
                    {
                        "docker_resource_id": "docker-database-target",
                        "engine_id": "engine-target",
                    },
                    {
                        "docker_resource_id": "docker-control-target",
                        "engine_id": "engine-target",
                    },
                    {
                        "docker_resource_id": "docker-foreign",
                        "engine_id": "engine-foreign",
                    },
                ],
                "docker_ports": [
                    {"docker_resource_id": "docker-target", "ordinal": 0},
                    {"docker_resource_id": "docker-database-target", "ordinal": 0},
                    {"docker_resource_id": "docker-control-target", "ordinal": 0},
                    {"docker_resource_id": "docker-foreign", "ordinal": 0},
                ],
                "databases": [
                    {
                        "database_binding_id": "database-target",
                        "docker_resource_id": "docker-database-target",
                        "repo_id": "repo-target",
                    },
                    {
                        "database_binding_id": "database-foreign",
                        "docker_resource_id": "docker-foreign",
                        "repo_id": "repo-foreign",
                    },
                ],
            },
            "leases": [
                {
                    "lease_id": "lease-target",
                    "repo_id": "repo-target",
                    "source_id": "source-target",
                },
                {
                    "lease_id": "lease-foreign",
                    "repo_id": "repo-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "port_assignments": [
                {"assignment_id": "assignment-target", "repo_id": "repo-target"},
                {"assignment_id": "assignment-foreign", "repo_id": "repo-foreign"},
            ],
            "backup_evidence": [
                {
                    "backup_id": "evidence-target",
                    "repo_id": "repo-target",
                    "source_id": "source-target",
                },
                {
                    "backup_id": "evidence-foreign",
                    "repo_id": "repo-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "database_backups": [
                {
                    "database_backup_id": "backup-target",
                    "repo_id": "repo-target",
                    "database_binding_id": "database-target",
                    "docker_resource_id": "docker-database-target",
                    "source_id": "source-target",
                },
                {
                    "database_backup_id": "backup-foreign",
                    "repo_id": "repo-foreign",
                    "database_binding_id": "database-foreign",
                    "docker_resource_id": "docker-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "database_restore_events": [
                {
                    "restore_event_id": "restore-target",
                    "database_backup_id": "backup-target",
                    "target_database_binding_id": "database-target",
                    "target_docker_resource_id": "docker-database-target",
                },
                {
                    "restore_event_id": "restore-foreign",
                    "database_backup_id": "backup-foreign",
                    "target_database_binding_id": "database-foreign",
                    "target_docker_resource_id": "docker-foreign",
                },
            ],
            "events": [
                {
                    "event_id": "event-target",
                    "repo_id": "repo-target",
                    "source_id": "source-target",
                },
                {
                    "event_id": "event-foreign",
                    "repo_id": "repo-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "unassigned_resources": [{"resource_id": "unassigned-host"}],
            "lifecycle_violations": [
                {
                    "resource_id": "server-target",
                    "resource_kind": "server",
                    "affected_repo_id": "repo-target",
                    "affected_canonical_root": project,
                },
                {
                    "resource_id": "server-foreign",
                    "resource_kind": "server",
                    "affected_repo_id": "repo-foreign",
                    "affected_canonical_root": foreign,
                },
            ],
            "observations": {
                "servers": [
                    {"server_definition_id": "server-target"},
                    {"server_definition_id": "server-foreign"},
                ],
                "docker": [
                    {"docker_resource_id": "docker-target"},
                    {"docker_resource_id": "docker-database-target"},
                    {"docker_resource_id": "docker-control-target"},
                    {"docker_resource_id": "docker-foreign"},
                ],
                "databases": [
                    {"database_binding_id": "database-target"},
                    {"database_binding_id": "database-foreign"},
                ],
                "telemetry": [
                    {
                        "sample_id": "sample-server-target",
                        "host_resource_kind": "server",
                        "host_resource_id": "server-target",
                    },
                    {
                        "sample_id": "sample-server-foreign",
                        "host_resource_kind": "server",
                        "host_resource_id": "server-foreign",
                    },
                    {
                        "sample_id": "sample-docker-target",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-target",
                    },
                    {
                        "sample_id": "sample-docker-database-target",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-database-target",
                    },
                    {
                        "sample_id": "sample-docker-control-target",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-control-target",
                    },
                    {
                        "sample_id": "sample-docker-foreign",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-foreign",
                    },
                ],
                "snapshots": [{"snapshot_id": "host-global"}],
            },
            "v1_compatibility": compatibility,
        }
        for key, value in compatibility.items():
            inventory.setdefault(key, copy.deepcopy(value))

        result = coordinator.filter_normalized_inventory_project(inventory, project)

        self.assertEqual([row["repo_id"] for row in result["repositories"]], ["repo-target"])
        self.assertEqual(
            [row["membership_id"] for row in result["memberships"]],
            ["membership-server-target", "membership-docker-target"],
        )
        self.assertEqual(
            [row["binding_id"] for row in result["control_bindings"]],
            ["binding-target", "binding-control-target"],
        )
        self.assertEqual([row["lease_id"] for row in result["leases"]], ["lease-target"])
        self.assertEqual(
            [row["assignment_id"] for row in result["port_assignments"]],
            ["assignment-target"],
        )
        self.assertEqual(
            [row["server_definition_id"] for row in result["resources"]["servers"]],
            ["server-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["resources"]["docker"]],
            ["docker-target", "docker-database-target", "docker-control-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["resources"]["docker_ports"]],
            ["docker-target", "docker-database-target", "docker-control-target"],
        )
        self.assertEqual(
            [row["database_binding_id"] for row in result["resources"]["databases"]],
            ["database-target"],
        )
        self.assertEqual(
            [row["resource_id"] for row in result["lifecycle_violations"]],
            ["server-target"],
        )
        self.assertEqual(result["unassigned_resources"], [])
        self.assertEqual(
            [row["server_definition_id"] for row in result["observations"]["servers"]],
            ["server-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["observations"]["docker"]],
            ["docker-target", "docker-database-target", "docker-control-target"],
        )
        self.assertEqual(
            [row["database_binding_id"] for row in result["observations"]["databases"]],
            ["database-target"],
        )
        self.assertEqual(
            [row["sample_id"] for row in result["observations"]["telemetry"]],
            [
                "sample-server-target",
                "sample-docker-target",
                "sample-docker-database-target",
                "sample-docker-control-target",
            ],
        )
        self.assertEqual(result["observations"]["snapshots"], [])
        self.assertEqual([row["backup_id"] for row in result["backup_evidence"]], ["evidence-target"])
        self.assertEqual(
            [row["database_backup_id"] for row in result["database_backups"]],
            ["backup-target"],
        )
        self.assertEqual(
            [row["restore_event_id"] for row in result["database_restore_events"]],
            ["restore-target"],
        )
        self.assertEqual([row["event_id"] for row in result["events"]], ["event-target"])
        self.assertEqual(
            [row["source_id"] for row in result["coordinator_sources"]],
            ["source-target"],
        )
        self.assertEqual(
            [row["engine_id"] for row in result["docker_engines"]],
            ["engine-target"],
        )
        self.assertEqual(
            [row["id"] for row in result["v1_compatibility"]["servers"]],
            ["server-target"],
        )
        self.assertEqual(
            [row["url"] for row in result["v1_compatibility"]["urls"]],
            ["http://target"],
        )
        self.assertEqual(result["servers"], result["v1_compatibility"]["servers"])

    def test_project_filter_preserves_disabled_repository_violation_context(self) -> None:
        project = str(Path(__file__).resolve().parents[3])
        foreign = "/foreign/repository"
        inventory = {
            "schema_version": 2,
            "store": {},
            # Disabled/removed repositories are intentionally absent from the
            # active repository collection while their corrective evidence
            # remains durable.
            "repositories": [],
            "coordinator_sources": [
                {"source_id": "source-target"},
                {"source_id": "source-foreign"},
            ],
            "docker_engines": [
                {"engine_id": "engine-target"},
                {"engine_id": "engine-foreign"},
            ],
            "memberships": [
                {
                    "membership_id": "membership-target",
                    "repo_id": "repo-disabled",
                    "resource_kind": "container",
                    "host_resource_id": "docker-target",
                },
                {
                    "membership_id": "membership-foreign",
                    "repo_id": "repo-foreign",
                    "resource_kind": "container",
                    "host_resource_id": "docker-foreign",
                },
            ],
            "control_bindings": [
                {
                    "binding_id": "binding-target",
                    "repo_id": "repo-disabled",
                    "resource_kind": "container",
                    "resource_id": "docker-target",
                    "source_id": "source-target",
                },
                {
                    "binding_id": "binding-foreign",
                    "repo_id": "repo-foreign",
                    "resource_kind": "container",
                    "resource_id": "docker-foreign",
                    "source_id": "source-foreign",
                },
            ],
            "resources": {
                "servers": [],
                "docker": [
                    {"docker_resource_id": "docker-target", "engine_id": "engine-target"},
                    {"docker_resource_id": "docker-foreign", "engine_id": "engine-foreign"},
                ],
                "docker_ports": [
                    {"docker_resource_id": "docker-target", "ordinal": 0},
                    {"docker_resource_id": "docker-foreign", "ordinal": 0},
                ],
                "databases": [],
            },
            "leases": [],
            "port_assignments": [],
            "backup_evidence": [],
            "database_backups": [],
            "database_restore_events": [],
            "events": [],
            "unassigned_resources": [],
            "lifecycle_violations": [
                {
                    "unassigned_id": "violation-target",
                    "resource_kind": "container",
                    "resource_id": "docker-target",
                    "affected_repo_id": "repo-disabled",
                    "affected_canonical_root": project,
                },
                {
                    "unassigned_id": "violation-foreign",
                    "resource_kind": "container",
                    "resource_id": "docker-foreign",
                    "affected_repo_id": "repo-foreign",
                    "affected_canonical_root": foreign,
                },
            ],
            "observations": {
                "servers": [],
                "docker": [
                    {"docker_resource_id": "docker-target"},
                    {"docker_resource_id": "docker-foreign"},
                ],
                "databases": [],
                "telemetry": [
                    {
                        "sample_id": "sample-target",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-target",
                    },
                    {
                        "sample_id": "sample-foreign",
                        "host_resource_kind": "docker",
                        "host_resource_id": "docker-foreign",
                    },
                ],
                "snapshots": [],
            },
            "v1_compatibility": {
                "servers": [],
                "leases": [],
                "port_assignments": [],
                "recent_events": [],
                "backups": [],
                "project_usage": [],
                "urls": [],
                "docker": {
                    "available": True,
                    "containers": [
                        {
                            "id": "full-target",
                            "host_resource_id": "docker-target",
                            "project": None,
                            "attribution": {"lifecycle_violation": True},
                        },
                        {
                            "id": "full-foreign",
                            "host_resource_id": "docker-foreign",
                            "project": None,
                            "attribution": {"lifecycle_violation": True},
                        },
                    ],
                    "postgres": [],
                },
                "postgres": [],
            },
        }

        result = coordinator.filter_normalized_inventory_project(inventory, project)

        self.assertEqual(result["repositories"], [])
        self.assertEqual(
            [row["membership_id"] for row in result["memberships"]],
            ["membership-target"],
        )
        self.assertEqual(
            [row["binding_id"] for row in result["control_bindings"]],
            ["binding-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["resources"]["docker"]],
            ["docker-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["resources"]["docker_ports"]],
            ["docker-target"],
        )
        self.assertEqual(
            [row["source_id"] for row in result["coordinator_sources"]],
            ["source-target"],
        )
        self.assertEqual(
            [row["engine_id"] for row in result["docker_engines"]],
            ["engine-target"],
        )
        self.assertEqual(
            [row["unassigned_id"] for row in result["lifecycle_violations"]],
            ["violation-target"],
        )
        self.assertEqual(
            [row["docker_resource_id"] for row in result["observations"]["docker"]],
            ["docker-target"],
        )
        self.assertEqual(
            [row["sample_id"] for row in result["observations"]["telemetry"]],
            ["sample-target"],
        )
        self.assertEqual(
            [row["host_resource_id"] for row in result["v1_compatibility"]["docker"]["containers"]],
            ["docker-target"],
        )
        self.assertEqual(
            result["docker"]["containers"],
            result["v1_compatibility"]["docker"]["containers"],
        )

    def test_observe_reuses_fresh_snapshot_without_running_sampler(self) -> None:
        calls = 0

        def sample(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return self.empty_sample()

        with mock.patch.object(coordinator, "sample_host_inventory_for_normalized_store", sample):
            first = coordinator.coordinated_observe_host(self.options())
            second = coordinator.coordinated_observe_host(
                self.options(max_age_seconds=300)
            )
        self.assertEqual(calls, 1)
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "fresh")
        self.assertFalse(second["observed"])
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])

    def test_normalized_authority_endpoint_coexists_with_same_home_legacy_source(self) -> None:
        database = self.home / "coordinator.sqlite3"
        legacy_state = self.home / "state.json"
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            normalized_id = deterministic_id(
                "normalized-account-source", host_id, str(self.home)
            )
            legacy_id = deterministic_id(
                "legacy-source", store.expected_uid, str(self.home)
            )
            timestamp = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, captured_revision,
                        captured_sha256, imported_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'imported', 7, ?, ?, ?, ?)
                    """,
                    (
                        legacy_id,
                        host_id,
                        str(self.home),
                        str(legacy_state),
                        store.expected_uid,
                        "a" * 64,
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
            self.observe_sample(store, host_id, self.empty_sample())
            with store.read_transaction() as connection:
                sources = {
                    row["source_id"]: dict(row)
                    for row in connection.execute(
                        """
                        SELECT source_id, canonical_home, state_path,
                               captured_revision, captured_sha256
                        FROM coordinator_sources
                        WHERE source_id IN (?, ?)
                        """,
                        (normalized_id, legacy_id),
                    )
                }

        # coordinator_sources.canonical_home is the unique provenance locator.
        # The normalized authority therefore uses its database endpoint while
        # the legacy source keeps the containing directory as its home.
        self.assertEqual(sources[normalized_id]["canonical_home"], str(database))
        self.assertEqual(sources[normalized_id]["state_path"], str(database))
        self.assertEqual(sources[legacy_id]["canonical_home"], str(self.home))
        self.assertEqual(sources[legacy_id]["state_path"], str(legacy_state))
        self.assertEqual(sources[legacy_id]["captured_revision"], 7)
        self.assertEqual(sources[legacy_id]["captured_sha256"], "a" * 64)
        normalized = coordinator.pure_normalized_inventory()
        self.assertEqual(normalized["coordinator_home"], str(self.home))
        self.assertEqual(normalized["state_path"], str(database))

    def test_default_backend_rejects_legacy_projection_gateways(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "normalized domain"):
            coordinator.read_state()
        with self.assertRaisesRegex(RuntimeError, "normalized domain"):
            coordinator.write_state(coordinator.default_state())
        with self.assertRaisesRegex(RuntimeError, "normalized transaction"):
            with coordinator.locked_state():
                pass

    def test_explicit_store_migration_projection_rejects_a_stale_revision(self) -> None:
        with AccountStore.open_default(self.home) as store:
            state = store.load_legacy_state_projection()
            revision = int(state["revision"])
            store.replace_legacy_state_projection(state, expected_revision=revision)
            with self.assertRaisesRegex(Exception, "revision changed"):
                store.replace_legacy_state_projection(state, expected_revision=revision)

    def test_two_process_shaped_refreshes_join_one_host_sampler(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        join_entered = threading.Event()
        calls = 0
        lock = threading.Lock()

        def sample(*_args, **_kwargs):
            nonlocal calls
            with lock:
                calls += 1
            entered.set()
            if not release.wait(3):
                raise AssertionError("test sampler was not released")
            return self.empty_sample()

        original_join = coordinator.SingleFlightObserver._join

        def joined(observer, ticket):
            join_entered.set()
            return original_join(observer, ticket)

        backup_a = self.root / "backup-a"
        backup_b = self.root / "backup-b"
        backup_a.mkdir()
        backup_b.mkdir()
        first_options = self.options(
            backup_dir=[str(backup_a), str(backup_b), str(backup_a)]
        )
        second_options = self.options(
            backup_dir=[str(backup_b), str(backup_a)]
        )
        with mock.patch.object(coordinator, "sample_host_inventory_for_normalized_store", sample), mock.patch.object(
            coordinator.SingleFlightObserver, "_join", joined
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(
                    coordinator.coordinated_observe_host, first_options
                )
                self.assertTrue(entered.wait(2), "owner did not reach host sampler")
                second = executor.submit(
                    coordinator.coordinated_observe_host, second_options
                )
                self.assertTrue(join_entered.wait(2), "joiner did not reach the in-flight ticket")
                release.set()
                outcomes = [first.result(timeout=4), second.result(timeout=4)]
        self.assertEqual(calls, 1)
        self.assertEqual({row["snapshot_id"] for row in outcomes}, {outcomes[0]["snapshot_id"]})
        self.assertEqual(sorted(row["joined"] for row in outcomes), [False, True])

    def test_full_docker_observation_never_joins_no_docker_ticket(self) -> None:
        no_docker_entered = threading.Event()
        release_no_docker = threading.Event()
        full_docker_entered = threading.Event()
        calls: list[bool] = []
        lock = threading.Lock()

        def sample(_store, *, include_docker, backup_dirs):
            del backup_dirs
            with lock:
                calls.append(bool(include_docker))
            if not include_docker:
                no_docker_entered.set()
                if not release_no_docker.wait(3):
                    raise AssertionError("no-Docker sampler was not released")
            else:
                full_docker_entered.set()
            return self.empty_sample()

        with mock.patch.object(
            coordinator, "sample_host_inventory_for_normalized_store", sample
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                no_docker = executor.submit(
                    coordinator.coordinated_observe_host,
                    self.options(no_docker=True),
                )
                self.assertTrue(
                    no_docker_entered.wait(2),
                    "no-Docker owner did not reach its sampler",
                )
                full_docker = executor.submit(
                    coordinator.coordinated_observe_host,
                    self.options(no_docker=False),
                )
                self.assertTrue(
                    full_docker_entered.wait(2),
                    "full-Docker refresh joined the incompatible no-Docker ticket",
                )
                full_result = full_docker.result(timeout=3)
                release_no_docker.set()
                no_docker_result = no_docker.result(timeout=3)

        self.assertEqual(sorted(calls), [False, True])
        self.assertNotEqual(full_result["snapshot_id"], no_docker_result["snapshot_id"])
        self.assertEqual(
            full_result["observer_domain"], coordinator.OBSERVER_DOMAIN_FULL_DOCKER
        )
        self.assertEqual(
            no_docker_result["observer_domain"], coordinator.OBSERVER_DOMAIN_NO_DOCKER
        )

    def test_different_backup_scopes_never_join_or_reuse_each_other(self) -> None:
        backup_a = self.root / "backup-a"
        backup_b = self.root / "backup-b"
        backup_a.mkdir()
        backup_b.mkdir()
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        calls: list[tuple[str, ...]] = []
        lock = threading.Lock()

        def sample(_store, *, include_docker, backup_dirs):
            self.assertFalse(include_docker)
            scope = tuple(str(Path(value).resolve()) for value in (backup_dirs or []))
            with lock:
                calls.append(scope)
            if scope == (str(backup_a.resolve()),):
                first_entered.set()
                if not release_first.wait(3):
                    raise AssertionError("first backup-scope sampler was not released")
            else:
                second_entered.set()
            return self.empty_sample()

        with mock.patch.object(
            coordinator, "sample_host_inventory_for_normalized_store", sample
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(
                    coordinator.coordinated_observe_host,
                    self.options(backup_dir=[str(backup_a)]),
                )
                self.assertTrue(
                    first_entered.wait(2),
                    "first backup scope did not reach its sampler",
                )
                second = executor.submit(
                    coordinator.coordinated_observe_host,
                    self.options(backup_dir=[str(backup_b)]),
                )
                self.assertTrue(
                    second_entered.wait(2),
                    "different backup scope joined the incompatible ticket",
                )
                second_result = second.result(timeout=3)
                release_first.set()
                first_result = first.result(timeout=3)

        self.assertEqual(len(calls), 2)
        self.assertNotEqual(first_result["snapshot_id"], second_result["snapshot_id"])
        self.assertNotEqual(first_result["observer_domain"], second_result["observer_domain"])
        self.assertEqual(
            first_result["observer_domain"],
            coordinator.observation_domain_for_scope(
                include_docker=False, backup_dirs=[str(backup_a)]
            ),
        )
        self.assertEqual(
            second_result["observer_domain"],
            coordinator.observation_domain_for_scope(
                include_docker=False, backup_dirs=[str(backup_b)]
            ),
        )

    def test_observed_database_and_unassigned_action_identity_survive_pure_inventory(self) -> None:
        full_id = "a" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            observer = SingleFlightObserver(store)
            observer.observe(
                host_id=host_id,
                observer_domain="fixture-docker",
                sampler=lambda: {
                    "sampled_at": "2026-07-14T12:00:00Z",
                    "inventory": {
                        "servers": [],
                        "docker": {
                            "available": True,
                            "containers": [
                                {
                                    "id": full_id[:12],
                                    "full_id": full_id,
                                    "name": "kosttracking-prod-copy-pg",
                                    "image": "postgres:16",
                                    "status": "Up 5 minutes",
                                    "metadata_source": "none",
                                    "labels": {},
                                    "port_bindings": [
                                        {
                                            "host_address": "127.0.0.1",
                                            "host_port": 55434,
                                            "container_port": 5432,
                                            "protocol": "tcp",
                                        }
                                    ],
                                    "databases": [{"name": "kosttracking", "size_bytes": 42}],
                                }
                            ],
                            "postgres": [],
                        },
                    },
                },
                commit=lambda connection, snapshot_id, sample: commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    sample,
                    host_id=host_id,
                    coordinator_home=str(self.home),
                ),
            )
        result = coordinator.pure_normalized_inventory()
        self.assertEqual(len(result["postgres"]), 1)
        database = result["postgres"][0]
        self.assertEqual(database["id"], full_id)
        self.assertEqual(database["name"], "kosttracking-prod-copy-pg")
        self.assertEqual(database["database"], "kosttracking")
        self.assertEqual(database["database_size_bytes"], 42)
        self.assertTrue(database["database_available"])
        self.assertEqual(database["status"], "running")
        normalized_database = result["resources"]["databases"][0]
        self.assertNotIn("size_bytes", normalized_database)
        database_observation = result["observations"]["databases"][0]
        self.assertEqual(database_observation["database_binding_id"], normalized_database["database_binding_id"])
        self.assertEqual(database_observation["size_bytes"], 42)
        self.assertEqual(database_observation["available"], 1)
        attribution = database["attribution"]
        for key in (
            "reason_code",
            "explanation",
            "observed_by",
            "controller",
            "host_resource_id",
            "immutable_fingerprint",
            "control_binding_id",
            "ownership_fingerprint",
            "can_attach",
            "can_retire",
        ):
            self.assertIn(key, attribution)
        self.assertTrue(attribution["can_attach"])
        self.assertTrue(attribution["can_retire"])

    def test_pathless_manual_attachment_survives_until_contradictory_exact_claim(self) -> None:
        repo_a = self.root / "repo-a"
        repo_b = self.root / "repo-b"
        for repository in (repo_a, repo_b):
            repository.mkdir()
            (repository / ".git").mkdir()
        repo_a = repo_a.resolve()
        repo_b = repo_b.resolve()
        full_id = "c" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 1 minute", restart_policy="always"),
            )
            repo_a_id = deterministic_id("repository", host_id, str(repo_a))
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'repo-a', 'active', 0, ?, ?)
                    """,
                    (repo_a_id, host_id, str(repo_a), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (repo_a_id, now),
                )
            persistence = SQLiteLifecyclePersistence(store)
            inventory = store.inventory_v2()
            unassigned = next(
                item for item in inventory["unassigned_resources"] if item["resource_kind"] == "container"
            )
            exact = persistence.resolve_standalone_resource(
                ResourceKind.CONTAINER,
                str(unassigned["resource_id"]),
                str(unassigned["control_binding_id"]),
            )
            persistence.attach_resource(
                repo_a_id,
                exact,
                actor="test",
                reason="explicit fixture attachment",
            )

            # Missing path evidence must not erase the explicit operator attach.
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 2 minutes", restart_policy="always"),
            )
            attached = store.connection.execute(
                """
                SELECT m.repo_id, b.repo_id, b.provenance, b.authority_state
                FROM repository_memberships m
                JOIN control_bindings b ON b.binding_id = m.control_binding_id
                WHERE m.resource_kind='container'
                """
            ).fetchone()
            self.assertEqual(
                tuple(attached),
                (repo_a_id, repo_a_id, "operator_attach", "authoritative"),
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM unassigned_resources WHERE status='active'"
                ).fetchone()[0],
                0,
            )
            policy = store.connection.execute(
                """
                SELECT repo_id, current_value FROM startup_policies
                WHERE resource_kind='container' AND resource_id = ?
                """,
                (exact.resource_id,),
            ).fetchone()
            self.assertEqual(tuple(policy), (repo_a_id, "always"))

            # A different exact Git root is positive contradictory evidence.
            self.observe_sample(
                store,
                host_id,
                self.container_sample(
                    full_id,
                    status="Up 3 minutes",
                    restart_policy="always",
                    project=repo_b,
                ),
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM repository_memberships WHERE resource_kind='container'"
                ).fetchone()[0],
                0,
            )
            binding = store.connection.execute(
                """
                SELECT repo_id, authority_state, provenance FROM control_bindings
                WHERE resource_kind='container' AND resource_id = ?
                """,
                (exact.resource_id,),
            ).fetchone()
            self.assertEqual(tuple(binding), (None, "conflicting", "conflicting_exact_claim"))
            active = store.connection.execute(
                """
                SELECT reason_code FROM unassigned_resources
                WHERE resource_kind='container' AND resource_id = ? AND status='active'
                """,
                (exact.resource_id,),
            ).fetchall()
            self.assertEqual([row[0] for row in active], ["conflicting_claims"])

            # A later pathless sample is not evidence that the conflict vanished.
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 4 minutes", restart_policy="always"),
            )
            retained = store.connection.execute(
                """
                SELECT authority_state, provenance FROM control_bindings
                WHERE resource_kind='container' AND resource_id = ?
                """,
                (exact.resource_id,),
            ).fetchone()
            self.assertEqual(tuple(retained), ("conflicting", "conflicting_exact_claim"))
            self.assertFalse(store.check_invariants())

    def test_completed_retirement_stays_hidden_and_running_projects_only_a_violation(self) -> None:
        full_id = "d" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Exited (0)", restart_policy="no"),
            )
            inventory = store.inventory_v2()
            resource = next(
                item for item in inventory["unassigned_resources"] if item["resource_kind"] == "container"
            )
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO resource_retirements(
                        host_resource_id, resource_kind, immutable_fingerprint,
                        status, reason, actor, started_at, retired_at, updated_at
                    ) VALUES (?, 'container', ?, 'retired', 'test retirement',
                              'test', ?, ?, ?)
                    """,
                    (
                        resource["resource_id"],
                        resource["immutable_fingerprint"],
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE control_bindings SET authority_state='retired', updated_at=?
                    WHERE binding_id=?
                    """,
                    (now, resource["control_binding_id"]),
                )
                connection.execute(
                    """
                    UPDATE unassigned_resources SET status='retired', updated_at=?
                    WHERE resource_kind='container' AND resource_id=?
                    """,
                    (now, resource["resource_id"]),
                )

            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Exited (0)", restart_policy="no"),
            )
            stopped = store.inventory_v2()
            self.assertFalse(
                [
                    item
                    for item in stopped["unassigned_resources"]
                    if item["resource_id"] == resource["resource_id"]
                ]
            )
            self.assertFalse(
                [
                    item
                    for item in stopped["docker"]["containers"]
                    if item["host_resource_id"] == resource["resource_id"]
                ]
            )
            self.assertFalse(
                [
                    item
                    for item in stopped["resources"]["docker"]
                    if item["docker_resource_id"] == resource["resource_id"]
                ]
            )

            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 1 minute", restart_policy="always"),
            )
            running = store.inventory_v2()
            violations = [
                item
                for item in running["unassigned_resources"]
                if item["resource_id"] == resource["resource_id"]
            ]
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0]["reason_code"], "start_fence_violated")
            self.assertTrue(violations[0]["lifecycle_violation"])
            self.assertFalse(violations[0]["can_attach"])
            self.assertFalse(violations[0]["can_retire"])
            retained_v2_resources = [
                item
                for item in running["resources"]["docker"]
                if item["docker_resource_id"] == resource["resource_id"]
            ]
            self.assertEqual(len(retained_v2_resources), 1)
            retained = store.connection.execute(
                """
                SELECT b.authority_state, u.status, p.current_value
                FROM control_bindings b
                JOIN unassigned_resources u
                  ON u.resource_kind=b.resource_kind AND u.resource_id=b.resource_id
                JOIN startup_policies p
                  ON p.resource_kind=b.resource_kind AND p.resource_id=b.resource_id
                WHERE b.binding_id=?
                """,
                (resource["control_binding_id"],),
            ).fetchone()
            self.assertEqual(tuple(retained), ("retired", "retired", "no"))
            self.assertFalse(store.check_invariants())

    def test_repository_plan_forces_observation_and_captures_never_stored_restart_policy(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        repository = repository.resolve()
        full_id = "e" * 64
        sample = self.container_sample(
            full_id,
            status="Up 1 minute",
            restart_policy="unless-stopped",
            project=repository,
        )
        args = coordinator.build_parser().parse_args(
            [
                "repository",
                "plan-remove",
                "--project",
                str(repository),
                "--agent",
                "cutover-test",
                "--reason",
                "test current observation",
            ]
        )
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=sample,
        ) as sampler:
            result = coordinator.handle_cli(args)
        self.assertEqual(sampler.call_count, 1)
        self.assertEqual(result["kind"], "repository_decommission")
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(
            [policy["kind"] for policy in result["targets"][0]["policies"]],
            ["docker_restart"],
        )
        with AccountStore.open_default(self.home) as store:
            policy = store.connection.execute(
                """
                SELECT p.current_value, p.repo_id, e.capability_state
                FROM startup_policies p
                JOIN docker_resources d ON d.docker_resource_id = p.resource_id
                JOIN docker_engines e USING(engine_id)
                """
            ).fetchone()
            self.assertEqual(tuple(policy), ("unless-stopped", result["repo_id"], "available"))
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM operations WHERE kind='repository_decommission' AND status='planned'"
                ).fetchone()[0],
                1,
            )

    def test_standalone_plan_forces_observation_before_binding_latest_policy(self) -> None:
        repository = self.root / "request-repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        repository = repository.resolve()
        full_id = "f" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            # This is shaped like an imported/old observation that knew the
            # exact container but omitted its native restart policy.
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 1 minute", restart_policy=None),
            )
            resource = next(
                item
                for item in store.inventory_v2()["unassigned_resources"]
                if item["resource_kind"] == "container"
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM startup_policies WHERE resource_kind='container'"
                ).fetchone()[0],
                0,
            )
        args = coordinator.build_parser().parse_args(
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                "container",
                "--resource-id",
                str(resource["resource_id"]),
                "--immutable-fingerprint",
                str(resource["immutable_fingerprint"]),
                "--control-binding-id",
                str(resource["control_binding_id"]),
                "--ownership-fingerprint",
                str(resource["ownership_fingerprint"]),
                "--request-project",
                str(repository),
                "--agent",
                "cutover-test",
                "--reason",
                "retire exact standalone container",
            ]
        )
        current = self.container_sample(
            full_id, status="Up 2 minutes", restart_policy="always"
        )
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=current,
        ):
            result = coordinator.handle_cli(args)
        self.assertEqual(result["kind"], "standalone_resource_retirement")
        self.assertEqual(
            [policy["kind"] for policy in result["targets"][0]["policies"]],
            ["docker_restart"],
        )
        with AccountStore.open_default(self.home) as store:
            self.assertEqual(
                store.connection.execute(
                    "SELECT current_value FROM startup_policies WHERE resource_kind='container'"
                ).fetchone()[0],
                "always",
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM resource_retirements"
                ).fetchone()[0],
                0,
                "planning must not install the retirement fence",
            )

    def test_failed_current_observation_writes_no_plan_or_fence(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        repository = repository.resolve()
        now = utc_timestamp()
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = deterministic_id("repository", host_id, str(repository))
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'repo', 'active', 0, ?, ?)
                    """,
                    (repo_id, host_id, str(repository), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (repo_id, now),
                )
        args = coordinator.build_parser().parse_args(
            [
                "repository",
                "plan-remove",
                "--project",
                str(repository),
                "--agent",
                "cutover-test",
                "--reason",
                "must fail before planning",
            ]
        )
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            side_effect=RuntimeError("docker observer failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "docker observer failed"):
                coordinator.handle_cli(args)
        with AccountStore.open_default(self.home) as store:
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0],
                0,
            )
            installation = store.connection.execute(
                "SELECT status, startup_fenced, operation_id FROM repository_installations"
            ).fetchone()
            self.assertEqual(tuple(installation), ("installed", 0, None))

    def test_repository_without_container_is_not_blocked_by_unavailable_docker(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        repository = repository.resolve()
        now = utc_timestamp()
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            repo_id = deterministic_id("repository", host_id, str(repository))
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'repo', 'active', 0, ?, ?)
                    """,
                    (repo_id, host_id, str(repository), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (repo_id, now),
                )
        sample = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {"available": False, "containers": [], "postgres": []},
            },
        }
        args = coordinator.build_parser().parse_args(
            [
                "repository",
                "plan-remove",
                "--project",
                str(repository),
                "--agent",
                "cutover-test",
                "--reason",
                "clean no-container control",
            ]
        )
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=sample,
        ):
            result = coordinator.handle_cli(args)
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["blockers"], [])

    def test_standalone_plan_fails_closed_when_current_docker_is_unavailable(self) -> None:
        repository = self.root / "request-repo"
        repository.mkdir()
        (repository / ".git").mkdir()
        repository = repository.resolve()
        full_id = "1" * 64
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            self.observe_sample(
                store,
                host_id,
                self.container_sample(full_id, status="Up 1 minute", restart_policy="always"),
            )
            resource = next(
                item
                for item in store.inventory_v2()["unassigned_resources"]
                if item["resource_kind"] == "container"
            )
        args = coordinator.build_parser().parse_args(
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                "container",
                "--resource-id",
                str(resource["resource_id"]),
                "--immutable-fingerprint",
                str(resource["immutable_fingerprint"]),
                "--control-binding-id",
                str(resource["control_binding_id"]),
                "--ownership-fingerprint",
                str(resource["ownership_fingerprint"]),
                "--request-project",
                str(repository),
                "--agent",
                "cutover-test",
                "--reason",
                "Docker must remain observable",
            ]
        )
        unavailable = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {"available": False, "containers": [], "postgres": []},
            },
        }
        with mock.patch.object(
            coordinator, "discover_same_uid_legacy_homes", return_value=[]
        ), mock.patch.object(
            coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=unavailable,
        ):
            with self.assertRaisesRegex(Exception, "current available Docker observation"):
                coordinator.handle_cli(args)
        with AccountStore.open_default(self.home) as store:
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0],
                0,
            )
            self.assertEqual(
                store.connection.execute("SELECT COUNT(*) FROM resource_retirements").fetchone()[0],
                0,
            )
            self.assertEqual(
                store.connection.execute(
                    "SELECT status FROM unassigned_resources WHERE resource_id=?",
                    (resource["resource_id"],),
                ).fetchone()[0],
                "active",
            )

    def test_legacy_json_backend_requires_its_explicit_test_only_name(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"DEVCOORDINATOR_STATE_BACKEND": coordinator.LEGACY_JSON_BACKEND},
        ):
            state = coordinator.default_state()
            coordinator.write_state(state)
            self.assertTrue((self.home / "state.json").is_file())
            self.assertFalse((self.home / "coordinator.sqlite3").exists())
            self.assertEqual(coordinator.read_state()["version"], coordinator.VERSION)
        with mock.patch.dict(os.environ, {"DEVCOORDINATOR_STATE_BACKEND": "legacy-json"}):
            with self.assertRaisesRegex(ValueError, "test bridge"):
                coordinator.state_backend()


if __name__ == "__main__":
    unittest.main(verbosity=2)
