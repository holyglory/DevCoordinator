from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.observer import ObservationError, SingleFlightObserver


class SQLiteTicketStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE observation_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    observer_domain TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
                    material_fingerprint TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_code TEXT,
                    error_message TEXT
                );
                CREATE UNIQUE INDEX one_running_observation_per_domain
                ON observation_snapshots(host_id, observer_domain)
                WHERE status = 'running';
                CREATE TABLE observed_values (
                    snapshot_id TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def immediate_transaction(self, *, max_seconds: float | None = None):
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def read_transaction(self):
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.rollback()
        finally:
            connection.close()


class SingleFlightObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteTicketStore(Path(self.temp.name) / "coordinator.sqlite3")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def commit(connection: sqlite3.Connection, snapshot_id: str, sample: dict) -> None:
        connection.execute(
            "INSERT INTO observed_values(snapshot_id, value) VALUES (?, ?)",
            (snapshot_id, sample["value"]),
        )

    def test_concurrent_same_domain_reaches_boundary_and_samples_exactly_once(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        sample_calls = 0
        sample_lock = threading.Lock()

        def sampler() -> dict:
            nonlocal sample_calls
            with sample_lock:
                sample_calls += 1
            entered.set()
            if not release.wait(3):
                raise AssertionError("fixture sampler was never released")
            return {"value": "one-real-docker-snapshot"}

        first = SingleFlightObserver(self.store, join_timeout=3)
        second = SingleFlightObserver(self.store, join_timeout=3)
        with ThreadPoolExecutor(max_workers=2) as executor:
            owner = executor.submit(
                first.observe,
                host_id="host-1",
                observer_domain="docker:daemon-1",
                sampler=sampler,
                commit=self.commit,
            )
            self.assertTrue(entered.wait(2), "owner never reached the slow observation boundary")
            joiner = executor.submit(
                second.observe,
                host_id="host-1",
                observer_domain="docker:daemon-1",
                sampler=sampler,
                commit=self.commit,
            )
            self._wait_for_running_ticket_count(1)
            time.sleep(0.05)
            self.assertEqual(sample_calls, 1, "joiner launched a duplicate Docker sampler")
            release.set()
            try:
                outcomes = [owner.result(timeout=3), joiner.result(timeout=3)]
            except FutureTimeout as error:
                self.fail(f"single-flight workers timed out after reaching boundary: {error}")

        self.assertEqual(sample_calls, 1)
        self.assertEqual({item.snapshot_id for item in outcomes}, {outcomes[0].snapshot_id})
        self.assertEqual(sorted(item.joined for item in outcomes), [False, True])
        with self.store.read_transaction() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM observed_values").fetchone()[0], 1)

    def test_different_physical_domains_are_not_false_positive_serialized(self) -> None:
        both_entered = threading.Barrier(2)
        release = threading.Event()

        def sampler(value: str) -> dict:
            both_entered.wait(timeout=2)
            if not release.wait(2):
                raise AssertionError("domain fixture was not released")
            return {"value": value}

        observer = SingleFlightObserver(self.store, join_timeout=3)
        with ThreadPoolExecutor(max_workers=2) as executor:
            left = executor.submit(
                observer.observe,
                host_id="host-1",
                observer_domain="docker:daemon-left",
                sampler=lambda: sampler("left"),
                commit=self.commit,
            )
            right = executor.submit(
                observer.observe,
                host_id="host-1",
                observer_domain="docker:daemon-right",
                sampler=lambda: sampler("right"),
                commit=self.commit,
            )
            self._wait_for_running_ticket_count(2)
            release.set()
            self.assertFalse(left.result(timeout=3).joined)
            self.assertFalse(right.result(timeout=3).joined)

    def test_stale_running_owner_is_failed_before_replacement(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "INSERT INTO observation_snapshots(snapshot_id,host_id,observer_domain,status,started_at) VALUES ('old','host-1','docker:daemon-1','running',?)",
                (old,),
            )
        outcome = SingleFlightObserver(
            self.store,
            stale_after=timedelta(seconds=1),
            id_factory=lambda: "replacement",
        ).observe(
            host_id="host-1",
            observer_domain="docker:daemon-1",
            sampler=lambda: {"value": "fresh"},
            commit=self.commit,
        )
        self.assertEqual(outcome.snapshot_id, "replacement")
        with self.store.read_transaction() as connection:
            rows = dict(connection.execute("SELECT snapshot_id,status FROM observation_snapshots"))
        self.assertEqual(rows, {"old": "failed", "replacement": "completed"})

    def test_sampler_failure_is_durable_and_joiner_receives_real_diagnostic(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        join_started = threading.Event()

        def failed_sampler() -> dict:
            entered.set()
            release.wait(2)
            raise RuntimeError("docker daemon disconnected")

        def joining_sleep(seconds: float) -> None:
            join_started.set()
            time.sleep(seconds)

        with ThreadPoolExecutor(max_workers=2) as executor:
            owner = executor.submit(
                SingleFlightObserver(self.store, join_timeout=3).observe,
                host_id="host-1",
                observer_domain="docker:daemon-1",
                sampler=failed_sampler,
                commit=self.commit,
            )
            self.assertTrue(entered.wait(2))
            joiner = executor.submit(
                SingleFlightObserver(
                    self.store,
                    join_timeout=3,
                    sleeper=joining_sleep,
                ).observe,
                host_id="host-1",
                observer_domain="docker:daemon-1",
                sampler=lambda: {"value": "must-not-run"},
                commit=self.commit,
            )
            self.assertTrue(join_started.wait(2), "joiner never reached the in-flight ticket boundary")
            release.set()
            with self.assertRaisesRegex(RuntimeError, "docker daemon disconnected"):
                owner.result(timeout=3)
            with self.assertRaisesRegex(ObservationError, "docker daemon disconnected"):
                joiner.result(timeout=3)
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT status,error_code,error_message FROM observation_snapshots"
            ).fetchone()
        self.assertEqual(row[0], "failed")
        self.assertEqual(row[1], "observer_runtime_error")
        self.assertEqual(row[2], "docker daemon disconnected")

    def test_commit_failure_does_not_publish_a_completed_snapshot(self) -> None:
        def failed_commit(_connection: sqlite3.Connection, _snapshot_id: str, _sample: dict) -> None:
            raise sqlite3.IntegrityError("normalized observation rejected")

        with self.assertRaisesRegex(sqlite3.IntegrityError, "normalized observation rejected"):
            SingleFlightObserver(self.store).observe(
                host_id="host-1",
                observer_domain="docker:daemon-1",
                sampler=lambda: {"value": "sample"},
                commit=failed_commit,
            )
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT status,error_message FROM observation_snapshots"
            ).fetchone()
        self.assertEqual(row, ("failed", "normalized observation rejected"))

    def _wait_for_running_ticket_count(self, expected: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.store.read_transaction() as connection:
                count = connection.execute(
                    "SELECT count(*) FROM observation_snapshots WHERE status='running'"
                ).fetchone()[0]
            if count == expected:
                return
            time.sleep(0.01)
        self.fail(f"expected {expected} running observation ticket(s)")


if __name__ == "__main__":
    unittest.main()
