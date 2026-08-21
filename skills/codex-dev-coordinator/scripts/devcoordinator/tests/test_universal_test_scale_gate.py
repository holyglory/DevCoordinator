from __future__ import annotations

import json
import math
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid

from devcoordinator.universal_test_service import (
    MAX_TEST_PLANE_RESPONSE_BYTES,
    StoreTestPlaneAdapter,
)
from devcoordinator.universal_test_store import UniversalTestStore
from devcoordinator.universal_test_transport import (
    TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
    TEST_REPOSITORY_STATS,
    TestPlaneDispatcher,
)


_NOW = 1_800_000_000.0
_REPOSITORY_COUNT = 20
_DAYS_PER_REPOSITORY = 365
_SAMPLE_COUNT = 20
_STATISTICS_P99_SECONDS = 0.250


class LiveStatisticsScaleGateTests(unittest.TestCase):
    """Keep direct terminal-row statistics responsive at realistic volume."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="test-live-statistics-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "tests.sqlite3"
        self.store = UniversalTestStore.create(self.path, clock=lambda: _NOW)
        self.dispatcher = TestPlaneDispatcher(StoreTestPlaneAdapter(self.store))
        self.repository_ids = tuple(
            f"repo-{index:02d}" for index in range(_REPOSITORY_COUNT)
        )
        self._seed_terminal_rows()

    def _seed_terminal_rows(self) -> None:
        connection = self.store._connect()  # focused scale fixture
        generation = str(self.store.health()["store_generation"])
        try:
            with connection:
                for repository_id in self.repository_ids:
                    connection.execute(
                        """
                        INSERT INTO test_snapshots(
                            snapshot_id, repository_id, source_mode,
                            content_fingerprint, manifest_fingerprint,
                            original_root, temporary_root, complete,
                            provenance_json, created_at
                        ) VALUES (?, ?, 'immutable', ?, ?, ?, NULL, 1, '{}', ?)
                        """,
                        (
                            f"snapshot-{repository_id}",
                            repository_id,
                            f"content-{repository_id}",
                            f"manifest-{repository_id}",
                            f"/srv/{repository_id}",
                            _NOW - _DAYS_PER_REPOSITORY * 86_400,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO test_plans(
                            plan_id, fingerprint, execution_fingerprint,
                            manifest_fingerprint, repository_id, intent,
                            snapshot_id, source_mode, source_fingerprint,
                            reusable, plan_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'manual', ?, 'immutable', ?, 0,
                                  '{}', ?)
                        """,
                        (
                            f"plan-{repository_id}",
                            f"plan-fingerprint-{repository_id}",
                            f"plan-execution-{repository_id}",
                            f"manifest-{repository_id}",
                            repository_id,
                            f"snapshot-{repository_id}",
                            f"source-{repository_id}",
                            _NOW - _DAYS_PER_REPOSITORY * 86_400,
                        ),
                    )
                runs: list[tuple[object, ...]] = []
                targets: list[tuple[object, ...]] = []
                sequence = 0
                first_day = _NOW - (_DAYS_PER_REPOSITORY - 1) * 86_400
                for repository_index, repository_id in enumerate(
                    self.repository_ids
                ):
                    for day in range(_DAYS_PER_REPOSITORY):
                        sequence += 1
                        finished_at = first_day + day * 86_400
                        started_at = finished_at - 10.0
                        queued_at = started_at - 2.0
                        failed = (repository_index + day) % 97 == 0
                        run_id = f"run-{sequence:08d}"
                        target_id = f"target-{sequence:08d}"
                        execution_id = f"execution-{sequence:08d}"
                        state = "failed" if failed else "succeeded"
                        classification = "test_failure" if failed else None
                        runs.append(
                            (
                                run_id,
                                f"plan-{repository_id}",
                                repository_id,
                                f"source-{repository_id}",
                                f"execution-{repository_id}-{day}",
                                state,
                                state,
                                classification,
                                queued_at,
                                started_at,
                                finished_at,
                                queued_at,
                                finished_at,
                            )
                        )
                        targets.append(
                            (
                                target_id,
                                run_id,
                                "unit",
                                "test_failed" if failed else "succeeded",
                                execution_id,
                                generation,
                                f"devcoordinator-test-{sequence:08d}.service",
                                f"launch-{sequence:08d}",
                                f"descriptor-{sequence:08d}",
                                finished_at + 30.0,
                                started_at,
                                10.0,
                                99 if failed else 100,
                                1 if failed else 0,
                                queued_at,
                                finished_at,
                                finished_at,
                                queued_at,
                                finished_at,
                            )
                        )
                connection.executemany(
                    """
                    INSERT INTO test_runs(
                        run_id, plan_id, repository_id, owner_uid, actor, intent,
                        source_mode, source_fingerprint, execution_fingerprint,
                        eligible_target_count, selected_target_count, state,
                        conclusion, failure_classification, priority, queued_at,
                        started_at, finished_at, cancel_reason, created_at,
                        updated_at
                    ) VALUES (
                        ?, ?, ?, 1001, 'codex:scale-gate', 'manual', 'immutable',
                        ?, ?, 4, 1, ?, ?, ?, 0, ?, ?, ?, NULL, ?, ?
                    )
                    """,
                    runs,
                )
                connection.executemany(
                    """
                    INSERT INTO test_run_targets(
                        target_id, run_id, target_name, wave_index,
                        exact_dependencies_json, shard_index, shard_count, state,
                        estimated_seconds, worktree_key,
                        exclusive_resources_json, ttl_seconds, execution_id,
                        generation, store_generation, repository_generation,
                        systemd_unit, launch_operation_id, descriptor_fingerprint,
                        launch_deadline_at, memory_commitment_mib, started_at,
                        duration_seconds, passed_count, failed_count,
                        reporter_complete, queued_at, finished_at, collected_at,
                        created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, 0, '[]', 0, 1, ?, 10.0, '/srv/scale', '[]',
                        120, ?, 1, ?, 1, ?, ?, ?, ?, 512, ?, ?, ?, ?, 1,
                        ?, ?, ?, ?, ?
                    )
                    """,
                    targets,
                )
        finally:
            connection.close()

    def _dispatch_statistics(
        self, *, repository_id: str, days: int, limit: int
    ) -> dict[str, object]:
        request = json.dumps(
            {
                "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
                "request_id": str(uuid.uuid4()),
                "operation": TEST_REPOSITORY_STATS,
                "arguments": {
                    "repository_id": repository_id,
                    "days": days,
                    "limit": limit,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        response = self.dispatcher.dispatch(request, peer_uid=os.geteuid())
        self.assertTrue(response["ok"], response)
        return dict(response["result"])

    @staticmethod
    def _p99(durations: list[float]) -> float:
        return sorted(durations)[max(0, math.ceil(0.99 * len(durations)) - 1)]

    def test_repository_statistics_transport_is_bounded_and_responsive(self) -> None:
        request = {"repository_id": "repo-00", "days": 3650, "limit": 25}
        warm = self._dispatch_statistics(**request)
        self.assertEqual(warm["totals"]["run_count"], _DAYS_PER_REPOSITORY)
        self.assertEqual(warm["totals"]["execution_count"], _DAYS_PER_REPOSITORY)
        self.assertEqual(len(warm["series"]), 25)
        self.assertEqual(warm["totals"]["avoided_target_count"], 3 * _DAYS_PER_REPOSITORY)
        encoded = json.dumps(
            warm, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), MAX_TEST_PLANE_RESPONSE_BYTES)
        self.assertNotIn(b"repo-01", encoded)

        durations: list[float] = []
        for _index in range(_SAMPLE_COUNT):
            started = time.perf_counter()
            result = self._dispatch_statistics(**request)
            durations.append(time.perf_counter() - started)
            self.assertEqual(result["repository_id"], "repo-00")
        p99 = self._p99(durations)
        self.assertLess(
            p99,
            _STATISTICS_P99_SECONDS,
            f"live statistics transport p99 was {p99 * 1_000:.1f}ms",
        )

    def test_statistics_burst_is_bounded_and_transport_recovers(self) -> None:
        callers = 12
        barrier = threading.Barrier(callers + 1)
        outcomes: list[tuple[str, float]] = []
        lock = threading.Lock()

        def request(index: int) -> None:
            barrier.wait()
            started = time.perf_counter()
            try:
                result = self._dispatch_statistics(
                    repository_id=self.repository_ids[index % len(self.repository_ids)],
                    days=3650,
                    limit=25,
                )
                outcome = "ok" if len(result["series"]) == 25 else "invalid"
            except Exception:
                outcome = "error"
            with lock:
                outcomes.append((outcome, time.perf_counter() - started))

        threads = [
            threading.Thread(target=request, args=(index,))
            for index in range(callers)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(outcomes), callers)
        self.assertTrue(any(outcome == "ok" for outcome, _elapsed in outcomes))
        self.assertTrue(
            all(outcome == "ok" for outcome, _elapsed in outcomes)
        )
        self.assertLess(max(elapsed for _outcome, elapsed in outcomes), 2.0)

        recovered = self._dispatch_statistics(
            repository_id="repo-00", days=3650, limit=25
        )
        self.assertEqual(recovered["totals"]["run_count"], _DAYS_PER_REPOSITORY)


if __name__ == "__main__":
    unittest.main()
