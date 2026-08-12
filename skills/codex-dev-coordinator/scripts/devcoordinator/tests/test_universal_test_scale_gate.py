from __future__ import annotations

import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid

from devcoordinator.tests.test_universal_test_transport_isolation import (
    InMemoryUnixListener,
)
from devcoordinator.universal_test_service import (
    MAX_TEST_PLANE_RESPONSE_BYTES,
    StoreTestPlaneAdapter,
)
from devcoordinator.universal_test_store import UniversalTestStore
from devcoordinator.universal_test_store import (
    MAX_CASES_PER_CHUNK,
    AttemptResultChunk,
    CaseResult,
)
from devcoordinator.tests.test_universal_test_store_reads import selected_plan
from devcoordinator.universal_test_transport import (
    TestPlaneTransportError,
    UnixTestPlaneClient,
    UnixTestPlaneServer,
)


_NOW = 1_800_000_000.0
_REPOSITORY_COUNT = 50
_HOUR_COUNT = 24
_SAMPLE_COUNT = 40
_CACHED_P99_SECONDS = 0.100
_WARM_PLAN_P99_SECONDS = 0.300
_SUBMIT_ACK_P99_SECONDS = 0.100
_HEALTH_P99_SECONDS = 0.100


class CachedPlanPreviewer:
    """Warm repository-UID boundary double with a fully validated plan."""

    def __init__(self, plan) -> None:
        self.plan = plan

    def preview_as_owner(
        self,
        *,
        repository_id,
        intent,
        actor,
        owner_uid,
        access_uid=None,
        temporary_root=None,
        requested_targets=(),
        execution_timeout_seconds=None,
        launch_timeout_seconds=300,
        launch_deadline_monotonic=None,
    ):
        if (
            repository_id != self.plan.repository_id
            or intent != self.plan.intent
            or not actor
            or owner_uid != 1001
            or access_uid not in {None, 1001}
            or temporary_root is not None
            or requested_targets
            or execution_timeout_seconds is not None
            or launch_timeout_seconds != 300
            or launch_deadline_monotonic is None
        ):
            raise AssertionError("unexpected warm plan preview request")
        resources = {
            name: {
                "cpu_millis": 500,
                "memory_mib": 256,
                "pids": 32,
                "estimated_seconds": 1.0,
                "shard_count": 1,
                "max_attempts": 2,
                "worktree_key": self.plan.source.original_root,
                "exclusive_resources": [],
            }
            for name in self.plan.selected_targets
        }
        return {"plan": self.plan.to_document(), "target_resources": resources}

    def setup_as_owner(self, *, repository_id, owner_uid):
        raise AssertionError("setup is outside the warm plan benchmark")


class UniversalTestScaleGateTests(unittest.TestCase):
    """Exercise the retained fleet read at realistic aggregate-test volume."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="test-scale-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "tests.sqlite3"
        self.store = UniversalTestStore.create(self.database, clock=lambda: _NOW)
        self.repository_ids = tuple(
            f"repo-{index:02d}" for index in range(_REPOSITORY_COUNT)
        )
        self._seed_rollups()

    def _seed_rollups(self) -> None:
        latest = float(int(_NOW) // 3_600 * 3_600)
        rows = []
        for repository_index, repository_id in enumerate(self.repository_ids):
            for offset in range(_HOUR_COUNT):
                failed = int((repository_index + offset) % 41 == 0)
                case_count = 2_000 + repository_index * 10 + offset
                rows.append(
                    (
                        repository_id,
                        latest - float((_HOUR_COUNT - 1 - offset) * 3_600),
                        20,
                        80,
                        80,
                        100,
                        20,
                        case_count,
                        case_count - failed,
                        failed,
                        0,
                        0,
                        12.0,
                        36.0,
                        1_800.0 + offset,
                        600.0,
                        450.0,
                        1,
                        0,
                        1,
                        0,
                        30.0,
                        80 - failed,
                        failed,
                        0,
                    )
                )
        connection = sqlite3.connect(self.database)
        try:
            with connection:
                connection.executemany(
                    """
                    INSERT INTO test_rollup_hourly(
                        repository_id, bucket_start, run_count, attempt_count,
                        selected_target_count, eligible_target_count,
                        avoided_target_count, case_count, passed_count,
                        failed_count, skipped_count, error_count, queue_seconds,
                        attempt_queue_seconds, aggregate_test_seconds,
                        attempt_wall_seconds, wall_seconds, retry_attempt_count,
                        flake_count, slow_count, regression_count,
                        max_attempt_seconds, success_count, failure_count,
                        infrastructure_count
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    rows,
                )
        finally:
            connection.close()

    def _start_transport(self, *, previewer=None) -> UnixTestPlaneClient:
        listener = InMemoryUnixListener()
        server = UnixTestPlaneServer(
            listener,  # type: ignore[arg-type]
            StoreTestPlaneAdapter(self.store, previewer=previewer),
            peer_resolver=lambda _connection: os.geteuid(),
            max_concurrent_requests=8,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.close)
        return UnixTestPlaneClient(
            Path("/unused/in-memory-test-plane.sock"),
            timeout_seconds=2,
            connection_factory=listener.connect,
        )

    @staticmethod
    def _p99(durations: list[float]) -> float:
        return sorted(durations)[max(0, math.ceil(0.99 * len(durations)) - 1)]

    def test_cached_fleet_projection_transport_p99_is_below_100ms(self) -> None:
        client = self._start_transport()
        request = {
            "repository_ids": self.repository_ids,
            "hours": _HOUR_COUNT,
        }
        warm = client.dashboard_fleet(**request)
        self.assertEqual(len(warm["repositories"]), _REPOSITORY_COUNT)
        self.assertEqual(len(warm["hours"]), _HOUR_COUNT)
        self.assertGreater(
            int(warm["summary"]["test_count"]),  # type: ignore[index]
            2_000_000,
        )
        encoded = json.dumps(
            warm, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), MAX_TEST_PLANE_RESPONSE_BYTES)

        durations: list[float] = []
        for _index in range(_SAMPLE_COUNT):
            started = time.perf_counter()
            result = client.dashboard_fleet(**request)
            durations.append(time.perf_counter() - started)
            self.assertEqual(len(result["repositories"]), _REPOSITORY_COUNT)
        p99 = self._p99(durations)
        self.assertLess(
            p99,
            _CACHED_P99_SECONDS,
            f"cached test fleet transport p99 was {p99 * 1_000:.1f}ms",
        )

    def test_fleet_read_burst_is_bounded_and_recovers_after_backpressure(self) -> None:
        client = self._start_transport()
        callers = 32
        barrier = threading.Barrier(callers + 1)
        outcomes: list[tuple[str, float]] = []
        outcome_lock = threading.Lock()

        def request() -> None:
            barrier.wait()
            started = time.perf_counter()
            try:
                client.dashboard_fleet(
                    repository_ids=self.repository_ids,
                    hours=_HOUR_COUNT,
                )
                outcome = "ok"
            except TestPlaneTransportError as error:
                outcome = error.code
            with outcome_lock:
                outcomes.append((outcome, time.perf_counter() - started))

        threads = [threading.Thread(target=request) for _index in range(callers)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(outcomes), callers)
        self.assertTrue(any(outcome == "ok" for outcome, _elapsed in outcomes))
        self.assertTrue(
            all(outcome in {"ok", "server_busy"} for outcome, _elapsed in outcomes)
        )
        self.assertLess(max(elapsed for _outcome, elapsed in outcomes), 2.0)

        recovered = client.dashboard_fleet(
            repository_ids=self.repository_ids,
            hours=_HOUR_COUNT,
        )
        self.assertEqual(len(recovered["repositories"]), _REPOSITORY_COUNT)

    def test_warm_plan_preview_transport_p99_is_below_300ms(self) -> None:
        plan = selected_plan(repository_id="repo-warm-plan")
        client = self._start_transport(previewer=CachedPlanPreviewer(plan))
        request = {
            "repository_id": plan.repository_id,
            "intent": plan.intent,
            "actor": "codex:performance-gate",
            "owner_uid": 1001,
            "launch_timeout_seconds": 300,
        }
        warm = client.preview(**request)
        self.assertEqual(warm["plan"]["plan_id"], plan.plan_id)  # type: ignore[index]

        durations: list[float] = []
        for _index in range(_SAMPLE_COUNT):
            started = time.perf_counter()
            preview = client.preview(**request)
            durations.append(time.perf_counter() - started)
            self.assertEqual(
                preview["plan"]["repository_id"],  # type: ignore[index]
                plan.repository_id,
            )
        p99 = self._p99(durations)
        self.assertLess(
            p99,
            _WARM_PLAN_P99_SECONDS,
            f"warm test-plan preview p99 was {p99 * 1_000:.1f}ms",
        )

    def test_submission_ack_transport_p99_is_below_100ms(self) -> None:
        client = self._start_transport()
        plans = [
            selected_plan(repository_id="repo-submit-gate")
            for _index in range(_SAMPLE_COUNT)
        ]
        for plan in plans:
            client.register_plan(plan.to_document())

        durations: list[float] = []
        for plan in plans:
            started = time.perf_counter()
            result = client.submit(
                plan_id=plan.plan_id,
                repository_id=plan.repository_id,
                operation_id=str(uuid.uuid4()),
                actor="codex:performance-gate",
                owner_uid=1001,
            )
            durations.append(time.perf_counter() - started)
            self.assertEqual(result["state"], "queued")
        p99 = self._p99(durations)
        self.assertLess(
            p99,
            _SUBMIT_ACK_P99_SECONDS,
            f"test submission acknowledgement p99 was {p99 * 1_000:.1f}ms",
        )

    def test_control_plane_health_p99_is_below_100ms_during_max_chunks(self) -> None:
        client = self._start_transport()
        plan = selected_plan(repository_id="repo-ingestion-gate")
        client.register_plan(plan.to_document())
        submitted = client.submit(
            plan_id=plan.plan_id,
            repository_id=plan.repository_id,
            operation_id=str(uuid.uuid4()),
            actor="codex:performance-gate",
            owner_uid=1001,
        )
        candidate = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == submitted["run_id"]
        )
        lease = self.store.lease_target(
            candidate.target_id,
            lease_owner="performance-gate",
            lease_seconds=120,
            operation_id=str(uuid.uuid4()),
        )
        self.store.acknowledge_launch(
            lease.attempt_id,
            generation=lease.generation,
            launch_ack_id="launch-performance-gate",
            operation_id=str(uuid.uuid4()),
        )

        start_ingestion = threading.Event()
        ingestion_errors: list[BaseException] = []

        def ingest() -> None:
            try:
                start_ingestion.wait()
                for chunk_index in range(12):
                    cases = tuple(
                        CaseResult(
                            case_id=f"case-{chunk_index}-{case_index}",
                            display_name=f"case {chunk_index}/{case_index}",
                            status="passed",
                            duration_seconds=0.001,
                        )
                        for case_index in range(MAX_CASES_PER_CHUNK)
                    )
                    self.store.append_result_chunk(
                        lease.attempt_id,
                        generation=lease.generation,
                        chunk=AttemptResultChunk(
                            chunk_id=f"chunk-{chunk_index}",
                            chunk_index=chunk_index,
                            cases=cases,
                            reporter_complete=chunk_index == 11,
                        ),
                    )
            except BaseException as error:
                ingestion_errors.append(error)

        writer = threading.Thread(target=ingest, daemon=True)
        writer.start()
        start_ingestion.set()
        durations: list[float] = []
        for _index in range(_SAMPLE_COUNT):
            started = time.perf_counter()
            health = client.health()
            durations.append(time.perf_counter() - started)
            self.assertEqual(health["status"], "ok")
        writer.join(10)
        self.assertFalse(writer.is_alive(), "bounded maximum ingestion did not finish")
        self.assertEqual(ingestion_errors, [])
        p99 = self._p99(durations)
        self.assertLess(
            p99,
            _HEALTH_P99_SECONDS,
            f"test-plane health p99 under maximum chunks was {p99 * 1_000:.1f}ms",
        )


if __name__ == "__main__":
    unittest.main()
