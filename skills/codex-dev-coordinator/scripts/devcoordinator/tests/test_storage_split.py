from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from devcoordinator import authority_retention
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.storage_split import (
    StorageSplitError,
    split_legacy_storage,
    verify_storage_split_attestation,
)
from devcoordinator.store import AccountStore, CoordinatorStore
import dev_coordinator


NOW = "2026-07-28T12:00:00+00:00"
LATER = "2026-07-28T12:00:01+00:00"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class StorageSplitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="storage-split-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "legacy.sqlite3"
        BrokerPersistence(self.source, expected_uid=os.geteuid())
        for name in ("authority", "inventory", "attestation", "console"):
            (self.root / name).mkdir(mode=0o700)
        self.authority = self.root / "authority" / "authority.sqlite3"
        self.inventory = self.root / "inventory" / "inventory.sqlite3"
        self.attestation = self.root / "attestation" / "split.json"
        self._seed_identity_and_test_history()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_identity_and_test_history(self) -> None:
        with CoordinatorStore.open(self.source) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-a', 'machine-a', 'linux', 'test', ?, ?)",
                    (NOW, NOW),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo-a', 'host-a', '/srv/repo-a', 'Repo A',
                              'active', 1, ?, ?)
                    """,
                    (NOW, NOW),
                )
                connection.execute(
                    """
                    INSERT INTO test_runs(
                        run_id, repo_id, parent_run_id, owner_uid, account_id,
                        actor, suite, run_kind, selection_json,
                        command_fingerprint, status, client_started_at,
                        admitted_at, client_finished_at, recorded_finished_at,
                        duration_seconds, exit_code, case_count, passed_count,
                        failed_count, skipped_count, error_count,
                        finished_operation_id, result_fingerprint,
                        created_at, updated_at
                    ) VALUES (
                        'run-a', 'repo-a', NULL, ?, 'account-a', 'codex',
                        'unit', 'test', '[]', 'sha256:command', 'passed',
                        ?, ?, ?, ?, 1.0, 0, 1, 1, 0, 0, 0,
                        'finish-a', 'sha256:result', ?, ?
                    )
                    """,
                    (os.geteuid(), NOW, NOW, LATER, LATER, NOW, LATER),
                )
                connection.execute(
                    """
                    INSERT INTO test_case_results(
                        run_id, ordinal, test_id, display_name, status,
                        started_at, finished_at, duration_seconds
                    ) VALUES ('run-a', 0, 'case-a', 'Case A', 'passed', ?, ?, 1.0)
                    """,
                    (NOW, LATER),
                )

    def _split(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "source_database": self.source,
            "authority_database": self.authority,
            "inventory_database": self.inventory,
            "attestation_path": self.attestation,
            "expected_uid": os.geteuid(),
            "authority_owner_uid": os.geteuid(),
            "authority_owner_gid": os.getegid(),
            "inventory_owner_uid": os.geteuid(),
            "inventory_owner_gid": os.getegid(),
        }
        arguments.update(overrides)
        return split_legacy_storage(**arguments)  # type: ignore[arg-type]

    def test_exact_authority_projection_excludes_test_history_and_retains_source(self) -> None:
        document = self._split()
        self.assertTrue(self.source.exists())
        self.assertTrue(self.authority.exists())
        self.assertTrue(self.inventory.exists())
        self.assertEqual(
            document["authority"]["test_source_tables"]["test_runs"]["row_count"],
            1,
        )
        with closing(sqlite3.connect(self.authority)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM test_case_results").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        verified = verify_storage_split_attestation(
            document,
            source_database=self.source,
            authority_database=self.authority,
            inventory_database=self.inventory,
            expected_uid=os.geteuid(),
            authority_owner_uid=os.geteuid(),
            inventory_owner_uid=os.geteuid(),
        )
        self.assertEqual(verified["document_sha256"], document["document_sha256"])

    def test_console_access_copy_is_bound_by_exact_digest(self) -> None:
        source = self.root / "console" / "legacy-access.json"
        destination = self.root / "console" / "access-control.json"
        source.write_text('{"version":2,"users":{},"requests":{}}\n', encoding="utf-8")
        destination.write_bytes(source.read_bytes())
        source.chmod(0o600)
        destination.chmod(0o600)
        document = self._split(
            console_access_source=source,
            console_access_destination=destination,
            console_access_source_uid=os.geteuid(),
            console_access_destination_uid=os.geteuid(),
        )
        self.assertTrue(document["console_access"]["present"])
        self.assertEqual(
            document["console_access"]["source_sha256"],
            document["console_access"]["destination_sha256"],
        )

    def test_capacity_failure_leaves_only_legacy_rollback_source(self) -> None:
        with self.assertRaisesRegex(StorageSplitError, "capacity"):
            self._split(capacity_probe=lambda _path: 0)
        self.assertTrue(self.source.exists())
        self.assertFalse(self.authority.exists())
        self.assertFalse(self.inventory.exists())
        self.assertFalse(self.attestation.exists())

    def test_interruption_after_authority_publication_rolls_back_new_outputs(self) -> None:
        def failpoint(stage: str) -> None:
            if stage == "authority-published":
                raise RuntimeError("simulated interruption")

        with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
            self._split(failpoint=failpoint)
        self.assertTrue(self.source.exists())
        self.assertFalse(self.authority.exists())
        self.assertFalse(self.inventory.exists())
        self.assertFalse(self.attestation.exists())

    def test_same_identity_source_content_drift_is_detected(self) -> None:
        before = self.source.stat()

        def failpoint(stage: str) -> None:
            if stage != "inventory-prepared":
                return
            with self.source.open("r+b") as handle:
                handle.seek(100)
                original = handle.read(1)
                handle.seek(100)
                handle.write(bytes([original[0] ^ 1]))
                handle.flush()
                os.fsync(handle.fileno())
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))

        with self.assertRaisesRegex(StorageSplitError, "content changed"):
            self._split(failpoint=failpoint)
        self.assertFalse(self.authority.exists())
        self.assertFalse(self.inventory.exists())

    def test_verifier_recomputes_logical_table_signatures(self) -> None:
        document = self._split()
        with closing(sqlite3.connect(self.authority)) as connection:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                "UPDATE schema_metadata SET state_revision = state_revision + 1 WHERE singleton = 1"
            )
            connection.commit()
        document["authority"]["file"]["size"] = self.authority.stat().st_size
        document["authority"]["file"]["sha256"] = hashlib.sha256(
            self.authority.read_bytes()
        ).hexdigest()
        unsigned = {key: value for key, value in document.items() if key != "document_sha256"}
        document["document_sha256"] = hashlib.sha256(canonical(unsigned)).hexdigest()
        with self.assertRaisesRegex(StorageSplitError, "logical signature"):
            verify_storage_split_attestation(
                document,
                source_database=self.source,
                authority_database=self.authority,
                inventory_database=self.inventory,
                expected_uid=os.geteuid(),
                authority_owner_uid=os.geteuid(),
                inventory_owner_uid=os.geteuid(),
            )

    def test_each_store_rename_crash_window_rolls_back_durably(self) -> None:
        for stage in (
            "authority-renamed",
            "authority-published",
            "inventory-renamed",
            "inventory-published",
        ):
            with self.subTest(stage=stage):
                def failpoint(actual: str, *, expected: str = stage) -> None:
                    if actual == expected:
                        raise RuntimeError(f"interrupted at {expected}")

                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    self._split(failpoint=failpoint)
                self.assertTrue(self.source.exists())
                self.assertFalse(self.authority.exists())
                self.assertFalse(self.inventory.exists())
                self.assertFalse(self.attestation.exists())

    def test_power_loss_after_rename_resumes_exact_journaled_split(self) -> None:
        class PowerLoss(BaseException):
            simulated_power_loss = True

        journal = self.root / "attestation" / "split-operation.json"
        crashed = False

        def failpoint(stage: str) -> None:
            nonlocal crashed
            if stage == "authority-renamed" and not crashed:
                crashed = True
                raise PowerLoss(stage)

        with self.assertRaises(PowerLoss):
            self._split(journal_path=journal, failpoint=failpoint)
        self.assertTrue(self.authority.exists())
        self.assertFalse(self.inventory.exists())
        document = self._split(journal_path=journal)
        self.assertTrue(self.authority.exists())
        self.assertTrue(self.inventory.exists())
        self.assertTrue(self.attestation.exists())
        operation = json.loads(journal.read_text(encoding="utf-8"))
        self.assertEqual(operation["phase"], "complete")
        self.assertEqual(operation["result"], document)

    def test_store_parents_are_fsynced_before_attestation(self) -> None:
        stages: list[str] = []
        fsynced: list[Path] = []

        def failpoint(stage: str) -> None:
            stages.append(stage)

        original = __import__(
            "devcoordinator.storage_split", fromlist=["_fsync_directory"]
        )._fsync_directory

        def record(path: Path) -> None:
            fsynced.append(path)
            original(path)

        with mock.patch(
            "devcoordinator.storage_split._fsync_directory", side_effect=record
        ):
            self._split(failpoint=failpoint)
        authority_published = stages.index("authority-published")
        inventory_published = stages.index("inventory-published")
        self.assertIn(self.authority.parent, fsynced[: authority_published + 1])
        self.assertIn(self.inventory.parent, fsynced[: inventory_published + 1])

    def test_sealed_verification_is_repeatable_and_byte_preserving(self) -> None:
        document = self._split()
        before = self.inventory.stat()
        digest = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        for _ in range(2):
            verify_storage_split_attestation(
                document,
                source_database=self.source,
                authority_database=self.authority,
                inventory_database=self.inventory,
                expected_uid=os.geteuid(),
                authority_owner_uid=os.geteuid(),
                inventory_owner_uid=os.geteuid(),
            )
        after = self.inventory.stat()
        self.assertEqual(
            (before.st_ino, before.st_size, before.st_mtime_ns),
            (after.st_ino, after.st_size, after.st_mtime_ns),
        )
        self.assertEqual(hashlib.sha256(self.inventory.read_bytes()).hexdigest(), digest)
        self.assertFalse(Path(f"{self.inventory}-wal").exists())
        self.assertFalse(Path(f"{self.inventory}-shm").exists())


class AuthorityRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="authority-retention-")
        self.root = Path(self.temporary.name)
        self.database = self.root / "authority.sqlite3"
        BrokerPersistence(self.database, expected_uid=os.geteuid())
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-a', 'machine-a', 'linux', 'test', ?, ?)",
                    (NOW, NOW),
                )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_repeated_authority_writes_remain_within_declared_caps(self) -> None:
        with mock.patch.object(authority_retention, "MAX_EVENT_ROWS", 5), mock.patch.object(
            authority_retention, "MAX_TELEMETRY_SAMPLES_PER_RESOURCE", 3
        ), mock.patch.object(authority_retention, "MAX_SNAPSHOTS_PER_STATUS", 2):
            with CoordinatorStore.open(self.database) as store:
                with store.immediate_transaction(check_invariants=False) as connection:
                    for ordinal in range(9):
                        snapshot_id = f"snapshot-{ordinal}"
                        connection.execute(
                            """
                            INSERT INTO observation_snapshots(
                                snapshot_id, host_id, observer_domain, status,
                                material_fingerprint, started_at, completed_at
                            ) VALUES (?, 'host-a', 'host-runtime-v2:full-docker',
                                      'completed', ?, ?, ?)
                            """,
                            (snapshot_id, f"sha256:{ordinal}", f"{NOW}.{ordinal}", f"{LATER}.{ordinal}"),
                        )
                        connection.execute(
                            """
                            INSERT INTO telemetry_samples(
                                sample_id, host_resource_kind, host_resource_id,
                                sampled_at, cpu_percent, memory_bytes
                            ) VALUES (?, 'server', 'server-a', ?, ?, 1)
                            """,
                            (f"sample-{ordinal}", f"{NOW}.{ordinal}", float(ordinal)),
                        )
                        connection.execute(
                            """
                            INSERT INTO events(
                                event_id, event_kind, message, occurred_at
                            ) VALUES (?, 'test', 'event', ?)
                            """,
                            (f"event-{ordinal}", f"{NOW}.{ordinal}"),
                        )
            with closing(sqlite3.connect(self.database)) as connection:
                self.assertLessEqual(
                    connection.execute("SELECT COUNT(*) FROM observation_snapshots").fetchone()[0],
                    2,
                )
                self.assertLessEqual(
                    connection.execute("SELECT COUNT(*) FROM telemetry_samples").fetchone()[0],
                    3,
                )
                self.assertLessEqual(
                    connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                    5,
                )

    def test_single_flight_observation_path_cannot_regrow_snapshots(self) -> None:
        with mock.patch.object(authority_retention, "MAX_SNAPSHOTS_PER_STATUS", 2):
            with CoordinatorStore.open(self.database) as store:
                observer = SingleFlightObserver(store)
                for ordinal in range(8):
                    observer.observe(
                        host_id="host-a",
                        observer_domain="host-runtime-v2:full-docker",
                        sampler=lambda ordinal=ordinal: {"ordinal": ordinal},
                        commit=lambda _connection, _snapshot, _sample: None,
                    )
            with closing(sqlite3.connect(self.database)) as connection:
                self.assertLessEqual(
                    connection.execute("SELECT COUNT(*) FROM observation_snapshots").fetchone()[0],
                    2,
                )

    def test_snapshot_retention_never_prunes_just_committed_timestamp_tie(self) -> None:
        with mock.patch.object(authority_retention, "MAX_SNAPSHOTS_PER_STATUS", 2):
            with CoordinatorStore.open(self.database) as store:
                for snapshot_id in ("snapshot-z", "snapshot-y", "snapshot-a"):
                    with store.immediate_transaction(
                        revision_kind="observation", check_invariants=False
                    ) as connection:
                        connection.execute(
                            """
                            INSERT INTO observation_snapshots(
                                snapshot_id, host_id, observer_domain, status,
                                material_fingerprint, started_at, completed_at
                            ) VALUES (?, 'host-a', 'host-runtime-v2:full-docker',
                                      'completed', ?, ?, ?)
                            """,
                            (snapshot_id, f"sha256:{snapshot_id}", NOW, LATER),
                        )
            with closing(sqlite3.connect(self.database)) as connection:
                retained = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT snapshot_id FROM observation_snapshots"
                    )
                }
        self.assertEqual(retained, {"snapshot-y", "snapshot-a"})

    def test_public_observe_operation_cannot_regrow_authority_history(self) -> None:
        home = self.root / "observer-home"
        home.mkdir(mode=0o700)
        sample = {
            "sampled_at": NOW,
            "inventory": {
                "servers": [],
                "docker": {
                    "available": False,
                    "containers": [],
                    "postgres": [],
                },
            },
        }
        options = {
            "agent": "devcoordinator-observer",
            "project": str(self.root),
            "max_age_seconds": 0,
            "no_docker": False,
            "backup_dir": None,
            "legacy_home": [],
            "legacy_backup_root": None,
        }
        with mock.patch.object(
            authority_retention, "MAX_SNAPSHOTS_PER_STATUS", 2
        ), mock.patch.object(
            dev_coordinator, "coordinator_home", return_value=home
        ), mock.patch.object(
            dev_coordinator, "authority_mode", return_value="account"
        ), mock.patch.object(
            dev_coordinator,
            "require_identity",
            return_value=("devcoordinator-observer", str(self.root)),
        ), mock.patch.object(
            dev_coordinator, "bootstrap_legacy_import", return_value={}
        ), mock.patch.object(
            dev_coordinator,
            "sample_host_inventory_for_normalized_store",
            return_value=sample,
        ):
            for _ in range(8):
                result = dev_coordinator.coordinated_observe_host(options)
                self.assertTrue(result["observed"])
        with AccountStore.open_default_read_only(home) as store:
            with store.read_transaction() as connection:
                self.assertLessEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM observation_snapshots"
                    ).fetchone()[0],
                    2,
                )


if __name__ == "__main__":
    unittest.main()
