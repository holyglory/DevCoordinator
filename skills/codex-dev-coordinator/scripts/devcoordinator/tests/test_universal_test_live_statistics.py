from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_contract import SourceMode
from devcoordinator.universal_test_planner import (
    SourceIdentity,
    TargetSelection,
    TestPlan,
    TestPlanTimeouts,
)
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_store import (
    MAX_STATISTICS_SERIES_DAYS,
    ExecutionConclusion,
    CaseResult,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    TargetResources,
    TestStoreContractError,
    UniversalTestStore,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def immutable_plan(
    repository_id: str,
    label: str,
    *,
    eligible_target_count: int = 1,
) -> TestPlan:
    fingerprint = _digest(f"plan:{repository_id}:{label}")
    target = f"target-{label}"
    eligible = (target,) + tuple(
        f"omitted-{label}-{index}" for index in range(eligible_target_count - 1)
    )
    return TestPlan(
        plan_id="plan-" + fingerprint[:32],
        fingerprint=fingerprint,
        execution_fingerprint=_digest(f"execution:{repository_id}:{label}"),
        manifest_fingerprint=_digest(f"manifest:{repository_id}:{label}"),
        repository_id=repository_id,
        intent="manual",
        timeouts=TestPlanTimeouts(execution_seconds=120, launch_seconds=30),
        source=SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id=repository_id,
            content_fingerprint=_digest(f"source:{repository_id}:{label}"),
            original_root=f"/srv/{repository_id}",
            snapshot_id="snapshot-" + _digest(f"snapshot:{repository_id}:{label}")[:32],
        ),
        changes=(),
        eligible_targets=eligible,
        selected_targets=(target,),
        dependency_waves=((target,),),
        dependencies={target: ()},
        selection={
            target: TargetSelection(target=target, reasons=("manual",))
        },
        complete_intent_fallback=False,
        reusable=False,
        evidence_policies={},
    )


class LiveStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = Clock()
        self.path = Path(self.temporary.name) / "tests.sqlite3"
        self.store = UniversalTestStore.create(self.path, clock=self.clock)
        self.adapter = StoreTestPlaneAdapter(self.store)

    def submit(self, repository_id: str, label: str, *, eligible: int = 1):
        plan = immutable_plan(
            repository_id, label, eligible_target_count=eligible
        )
        return self.store.submit_plan(
            plan,
            operation_id=str(uuid.uuid4()),
            actor="codex:statistics-test",
            owner_uid=1001,
            target_resources={
                plan.selected_targets[0]: TargetResources(
                    estimated_seconds=10.0,
                    ttl_seconds=120,
                )
            },
        )

    def complete(
        self,
        repository_id: str,
        label: str,
        *,
        eligible: int = 1,
        queue_seconds: float = 0.0,
        duration_seconds: float = 2.0,
        conclusion: ExecutionConclusion = ExecutionConclusion.SUCCEEDED,
    ):
        submitted = self.submit(repository_id, label, eligible=eligible)
        self.clock.advance(queue_seconds)
        target = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == submitted.run_id
        )
        grant = self.store.begin_execution(
            target.target_id,
            repository_generation=1,
            systemd_unit=f"devcoordinator-test-{target.target_id}.service",
            launch_operation_id=str(uuid.uuid4()),
            descriptor_fingerprint=_digest(f"descriptor:{label}"),
            launch_deadline_at=self.clock.value + 30,
            operation_id=str(uuid.uuid4()),
        )
        self.store.record_started(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=grant.systemd_unit,
            launch_ack_id=f"launch-{grant.execution_id}",
            systemd_invocation_id=f"invocation-{grant.execution_id}",
            started_at=self.clock.value,
            operation_id=str(uuid.uuid4()),
        )
        self.clock.advance(duration_seconds)
        failed = conclusion is ExecutionConclusion.TEST_FAILED
        artifact = ExecutionResultPackage(
            package_id=f"package-{label}",
            cases=(
                CaseResult(f"{label}-pass", "passes", "passed", 0.25),
                CaseResult(
                    f"{label}-second",
                    "second",
                    "failed" if failed else "skipped",
                    0.5,
                ),
            ),
            failures=(
                FailureRecord(
                    f"failure-{label}",
                    FailureClassification.TEST_FAILURE,
                    "expected test failure",
                    case_id=f"{label}-second",
                ),
            )
            if failed
            else (),
            reporter_complete=True,
        )
        self.store.complete_from_package(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=grant.systemd_unit,
            package=artifact,
            conclusion=conclusion,
            duration_seconds=duration_seconds,
            operation_id=str(uuid.uuid4()),
            unit_inactive=True,
            cgroup_empty=True,
            peak_memory_bytes=32 * 1024 * 1024,
            cpu_seconds=1.0,
        )
        return submitted

    def test_statistics_derive_counts_timing_and_selection_from_terminal_rows(self) -> None:
        self.complete(
            "repo-visible",
            "failed",
            eligible=3,
            queue_seconds=5.0,
            duration_seconds=7.0,
            conclusion=ExecutionConclusion.TEST_FAILED,
        )
        self.submit("repo-visible", "still-queued", eligible=4)

        result = self.store.repository_statistics(
            repository_id="repo-visible", since=0
        )

        totals = result["totals"]
        self.assertEqual(totals["run_count"], 1)
        self.assertEqual(totals["execution_count"], 1)
        self.assertEqual(totals["eligible_target_count"], 3)
        self.assertEqual(totals["selected_target_count"], 1)
        self.assertEqual(totals["avoided_target_count"], 2)
        self.assertEqual(totals["case_count"], 2)
        self.assertEqual(totals["passed_count"], 1)
        self.assertEqual(totals["failed_count"], 1)
        self.assertEqual(totals["test_failed_execution_count"], 1)
        self.assertEqual(totals["run_queue_seconds"], 5.0)
        self.assertEqual(totals["execution_queue_seconds"], 5.0)
        self.assertEqual(totals["test_seconds"], 7.0)
        self.assertEqual(totals["run_wall_seconds"], 7.0)
        self.assertAlmostEqual(
            result["efficiency"]["selection_savings_ratio"], 2 / 3
        )
        self.assertEqual(result["efficiency"]["average_run_queue_seconds"], 5.0)
        self.assertEqual(result["efficiency"]["test_failure_rate"], 1.0)
        self.assertEqual(len(result["series"]), 1)

    def test_scope_since_and_limit_do_not_change_full_window_totals(self) -> None:
        first = self.complete("repo-visible", "day-one")
        first_finished = self.store.get_run(first.run_id)["finished_at"]
        self.clock.advance(86_400)
        self.complete("repo-private", "private")
        self.clock.advance(86_400)
        self.complete("repo-visible", "day-three")

        result = self.store.repository_statistics(
            repository_id="repo-visible",
            since=float(first_finished) - 1.0,
            limit=1,
        )

        self.assertEqual(result["totals"]["run_count"], 2)
        self.assertEqual(result["totals"]["execution_count"], 2)
        self.assertEqual(len(result["series"]), 1)
        self.assertEqual(
            result["series"][0]["bucket_start"],
            float(int(self.clock.value) // 86_400 * 86_400),
        )
        excluded = self.store.repository_statistics(
            repository_id="repo-visible",
            since=float(first_finished) + 1.0,
        )
        self.assertEqual(excluded["totals"]["run_count"], 1)
        self.assertNotIn("repo-private", repr(result))

    def test_service_enforces_days_and_series_bounds(self) -> None:
        self.complete("repo-visible", "bounded")
        result = self.adapter.statistics(
            repository_id="repo-visible", days=30, limit=25
        )
        self.assertEqual(result["repository_id"], "repo-visible")
        self.assertEqual(result["grain"], "daily")
        self.assertEqual(result["totals"]["execution_count"], 1)
        for days in (0, 3651, 1.5):
            with self.subTest(days=days), self.assertRaises(TestStoreContractError):
                self.adapter.statistics(
                    repository_id="repo-visible", days=days, limit=25
                )
        for limit in (0, MAX_STATISTICS_SERIES_DAYS + 1, 1.5):
            with self.subTest(limit=limit), self.assertRaises(TestStoreContractError):
                self.adapter.statistics(
                    repository_id="repo-visible", days=30, limit=limit
                )
        with self.assertRaises(TestStoreContractError):
            self.store.repository_statistics(
                repository_id="repo-visible", since=-1
            )

    def test_repository_setup_catalog_remains_separate_retained_control_data(self) -> None:
        self.store.retain_repository_setup_projection(
            {
                "repository_id": "repo-visible",
                "status": "ready",
                "manifest_fingerprint": "a" * 64,
            }
        )
        catalog = self.store.repository_setup_catalog(
            ("repo-visible", "repo-unobserved")
        )
        self.assertEqual(
            [(row["setup_status"], row["retained"]) for row in catalog],
            [("ready", True), ("missing", False)],
        )
        self.assertEqual(
            self.store.repository_statistics(
                repository_id="repo-visible", since=0
            )["totals"]["run_count"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
