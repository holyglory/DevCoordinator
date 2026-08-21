from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_contract import EvidencePolicy, SourceMode
from devcoordinator.universal_test_planner import (
    SourceIdentity,
    TargetSelection,
    TestPlan,
    TestPlanTimeouts,
)
from devcoordinator.universal_test_store import (
    ArtifactMetadata,
    ExecutionConclusion,
    CaseResult,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    TargetResources,
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)


def operation_id() -> str:
    return str(uuid.uuid4())


class Clock:
    def __init__(self, value: float = 1_900_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def immutable_plan(
    *,
    names: tuple[str, ...] = ("lint",),
    dependencies: dict[str, tuple[str, ...]] | None = None,
    evidence: bool = False,
    fingerprint: str = "a" * 64,
) -> TestPlan:
    dependency_map = dependencies or {name: () for name in names}
    unresolved = set(names)
    resolved: set[str] = set()
    waves: list[tuple[str, ...]] = []
    while unresolved:
        wave = tuple(
            sorted(
                name
                for name in unresolved
                if set(dependency_map[name]).issubset(resolved)
            )
        )
        if not wave:
            raise AssertionError("test dependency graph contains a cycle")
        waves.append(wave)
        unresolved.difference_update(wave)
        resolved.update(wave)
    policies = (
        {
            "release": EvidencePolicy(
                name="release",
                intent="release",
                required_targets=names,
                max_age_seconds=60,
                allow_reuse=True,
            )
        }
        if evidence
        else {}
    )
    return TestPlan(
        plan_id="plan-" + fingerprint[:32],
        fingerprint=fingerprint,
        execution_fingerprint="b" * 64,
        manifest_fingerprint="c" * 64,
        repository_id="repo-v8",
        intent="release",
        timeouts=TestPlanTimeouts(execution_seconds=20, launch_seconds=30),
        source=SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id="repo-v8",
            content_fingerprint="d" * 64,
            original_root="/srv/repo-v8",
            snapshot_id="snapshot-v8",
        ),
        changes=(),
        eligible_targets=names,
        selected_targets=names,
        dependency_waves=tuple(waves),
        dependencies=dependency_map,
        selection={
            name: TargetSelection(target=name, reasons=("release",))
            for name in names
        },
        complete_intent_fallback=False,
        reusable=False,
        evidence_policies=policies,
    )


class TestStoreV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = Clock()
        self.path = Path(self.temporary.name) / "tests.sqlite3"
        self.store = UniversalTestStore.create(self.path, clock=self.clock)

    def submit(
        self,
        plan: TestPlan | None = None,
        *,
        operation: str | None = None,
    ):
        selected = plan or immutable_plan()
        return self.store.submit_plan(
            selected,
            operation_id=operation or operation_id(),
            actor="codex:v8-test",
            owner_uid=1001,
            target_resources={
                name: TargetResources(
                    estimated_seconds=2,
                    ttl_seconds=20,
                    exclusive_resources=("resource-" + name,),
                )
                for name in selected.selected_targets
            },
        )

    def begin(self, *, target_name: str = "lint"):
        target = next(
            value
            for value in self.store.runnable_targets()
            if value.target_name == target_name
        )
        grant = self.store.begin_execution(
            target.target_id,
            repository_generation=7,
            systemd_unit=f"devcoordinator-test-{target.target_id}.service",
            launch_operation_id=operation_id(),
            descriptor_fingerprint="e" * 64,
            launch_deadline_at=self.clock.value + 30,
            operation_id=operation_id(),
        )
        return target, grant

    def start(self, grant) -> dict[str, object]:
        return self.store.record_started(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=grant.systemd_unit,
            launch_ack_id="launch-" + grant.execution_id,
            systemd_invocation_id="invocation-" + grant.execution_id,
            started_at=self.clock.value,
            operation_id=operation_id(),
        )

    def complete(
        self,
        grant,
        *,
        conclusion: ExecutionConclusion = ExecutionConclusion.SUCCEEDED,
        package: ExecutionResultPackage | None = None,
    ) -> dict[str, object]:
        return self.store.complete_from_package(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=grant.systemd_unit,
            package=package
            or ExecutionResultPackage(
                package_id="package-" + grant.execution_id,
                reporter_complete=True,
            ),
            conclusion=conclusion,
            duration_seconds=2,
            operation_id=operation_id(),
            unit_inactive=True,
            cgroup_empty=True,
            peak_memory_bytes=64 * 1024 * 1024,
            cpu_seconds=1.25,
        )

    def test_schema_v8_has_one_execution_slot_and_preserved_evidence_tables(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(test_run_targets)")
            }
            event_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(test_events)")
            }
        finally:
            connection.close()
        self.assertEqual(self.store.verify()["schema_version"], 8)
        self.assertNotIn("test_target_attempts", tables)
        self.assertNotIn("test_result_chunks", tables)
        self.assertNotIn("test_rollup_hourly", tables)
        self.assertNotIn("test_rollup_daily", tables)
        self.assertNotIn("lease_expires_at", columns)
        self.assertNotIn("max_attempts", columns)
        self.assertIn("execution_id", event_columns)
        self.assertNotIn("attempt_id", event_columns)
        self.assertTrue(
            {
                "execution_id",
                "systemd_unit",
                "launch_operation_id",
                "result_package_fingerprint",
            }.issubset(columns)
        )
        self.assertTrue(
            {
                "test_snapshots",
                "test_plans",
                "test_case_results",
                "test_failures",
                "test_artifacts",
                "test_evidence_attestations",
                "test_evidence_consumptions",
                "test_repository_setup_projections",
                "test_target_resource_profiles",
                "test_mutation_journal",
            }.issubset(tables)
        )

    def test_live_plan_is_rejected_before_registration(self) -> None:
        plan = immutable_plan()
        live = TestPlan(
            **{
                **plan.__dict__,
                "source": SourceIdentity(
                    mode=SourceMode.LIVE,
                    repository_id="repo-v8",
                    content_fingerprint="d" * 64,
                    original_root="/srv/repo-v8",
                ),
            }
        )
        with self.assertRaisesRegex(TestStoreContractError, "immutable snapshot"):
            self.submit(live)

    def test_begin_execution_persists_exact_identity_before_return_and_replays(self) -> None:
        submitted = self.submit()
        target = self.store.runnable_targets()[0]
        preview_execution_id = self.store.execution_identity(target.target_id)
        mutation = operation_id()
        launch = operation_id()
        arguments = {
            "repository_generation": 9,
            "systemd_unit": "devcoordinator-test-one.service",
            "launch_operation_id": launch,
            "descriptor_fingerprint": "e" * 64,
            "launch_deadline_at": self.clock.value + 30,
            "operation_id": mutation,
        }
        first = self.store.begin_execution(target.target_id, **arguments)
        self.assertEqual(first.execution_id, preview_execution_id)
        replay = self.store.begin_execution(target.target_id, **arguments)
        retained = self.store.restart_cleanup()
        self.assertEqual(first, replay)
        self.assertEqual(first.run_id, submitted.run_id)
        self.assertEqual(retained[0]["execution_id"], first.execution_id)
        self.assertEqual(retained[0]["systemd_unit"], arguments["systemd_unit"])
        self.assertEqual(
            retained[0]["launch_operation_id"], arguments["launch_operation_id"]
        )
        with self.assertRaises(TestStoreConflict):
            self.store.begin_execution(
                target.target_id,
                **{**arguments, "operation_id": operation_id()},
            )

    def test_started_progress_and_restart_cleanup_are_generation_fenced(self) -> None:
        self.submit()
        _target, grant = self.begin()
        started = self.start(grant)
        self.assertEqual(started["execution_deadline_at"], self.clock.value + 20)
        progress = self.store.record_progress(
            grant.execution_id,
            generation=1,
            stdout_bytes=5 * 1024 * 1024,
            stderr_bytes=10,
            stdout_retained_bytes=4 * 1024 * 1024,
            stderr_retained_bytes=10,
            stdout_truncated=True,
            stderr_truncated=False,
            current_memory_bytes=32 * 1024 * 1024,
            last_output_at=self.clock.value,
            observed_at=self.clock.value,
        )
        self.assertTrue(progress["stdout_truncated"])
        retained = self.store.restart_cleanup()[0]
        self.assertEqual(
            retained["execution_deadline_at"], self.clock.value + 20
        )
        run_target = self.store.get_run(grant.run_id)["targets"][0]
        execution = run_target["execution"]
        self.assertEqual(execution["execution_id"], grant.execution_id)
        self.assertEqual(execution["state"], "running")
        self.assertTrue(execution["launch_confirmed"])
        self.assertEqual(execution["last_observed_at"], self.clock.value)
        self.assertEqual(
            execution["launch_deadline_at"], self.clock.value + 30
        )
        self.assertEqual(
            execution["execution_deadline_at"], self.clock.value + 20
        )
        self.assertEqual(execution["output_progress"]["stdout_bytes"], 5 * 1024 * 1024)
        self.assertNotIn("current_attempt_id", run_target)
        self.assertNotIn("active_attempt", run_target)
        with self.assertRaisesRegex(TestStoreConflict, "regressed"):
            self.store.record_progress(
                grant.execution_id,
                generation=1,
                stdout_bytes=1,
                stderr_bytes=10,
                stdout_retained_bytes=1,
                stderr_retained_bytes=10,
                stdout_truncated=False,
                stderr_truncated=False,
                current_memory_bytes=None,
                last_output_at=self.clock.value,
                observed_at=self.clock.value,
            )
        with self.assertRaises(TestStoreConflict):
            self.store.record_progress(
                grant.execution_id,
                generation=2,
                stdout_bytes=5 * 1024 * 1024,
                stderr_bytes=10,
                stdout_retained_bytes=4 * 1024 * 1024,
                stderr_retained_bytes=10,
                stdout_truncated=True,
                stderr_truncated=False,
                current_memory_bytes=None,
                last_output_at=self.clock.value,
                observed_at=self.clock.value,
            )

    def test_complete_package_is_atomic_complete_and_idempotent(self) -> None:
        submitted = self.submit()
        _target, grant = self.begin()
        self.start(grant)
        artifact_id = "artifact-" + "1" * 32
        package = ExecutionResultPackage(
            package_id="package-result",
            cases=(
                CaseResult("case-pass", "pass", "passed", 0.1),
                CaseResult("case-fail", "fail", "failed", 0.2),
            ),
            failures=(
                FailureRecord(
                    "failure-case-fail",
                    FailureClassification.TEST_FAILURE,
                    "assertion failed",
                    case_id="case-fail",
                    artifact_id=artifact_id,
                ),
            ),
            artifacts=(
                ArtifactMetadata(
                    artifact_id,
                    "log",
                    f"test-artifact://{artifact_id}/{'f' * 64}",
                    "f" * 64,
                    128,
                ),
            ),
            reporter_complete=True,
        )
        mutation = operation_id()
        arguments = {
            "generation": 1,
            "systemd_unit": grant.systemd_unit,
            "package": package,
            "conclusion": ExecutionConclusion.TEST_FAILED,
            "duration_seconds": 2,
            "operation_id": mutation,
            "unit_inactive": True,
            "cgroup_empty": True,
            "peak_memory_bytes": 64 * 1024 * 1024,
            "cpu_seconds": 1.25,
        }
        with self.assertRaisesRegex(TestStoreConflict, "cgroup"):
            self.store.complete_from_package(
                grant.execution_id,
                **{**arguments, "unit_inactive": False},
            )
        with self.assertRaisesRegex(TestStoreConflict, "must win"):
            self.store.complete_from_package(
                grant.execution_id,
                **{
                    **arguments,
                    "conclusion": ExecutionConclusion.TIMED_OUT,
                    "operation_id": operation_id(),
                },
            )
        self.assertEqual(self.store.cases(run_id=submitted.run_id), ())
        first = self.store.complete_from_package(grant.execution_id, **arguments)
        replay = self.store.complete_from_package(grant.execution_id, **arguments)
        self.assertEqual(first, replay)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        self.assertEqual(len(self.store.cases(run_id=submitted.run_id)), 2)
        self.assertEqual(len(self.store.failures(run_id=submitted.run_id)), 1)
        self.assertEqual(len(self.store.artifacts(run_id=submitted.run_id)), 1)
        retained_execution = self.store.get_execution(grant.execution_id)
        self.assertEqual(retained_execution["execution_id"], grant.execution_id)
        self.assertNotIn("attempt_id", retained_execution)
        self.assertNotIn("attempt_number", retained_execution)
        self.assertNotIn("heartbeat_at", retained_execution)
        self.assertNotIn("lease_expires_at", retained_execution)
        self.assertEqual(
            self.store.cases(run_id=submitted.run_id)[0]["execution_id"],
            grant.execution_id,
        )

    def test_incomplete_failure_index_rolls_back_without_partial_cases(self) -> None:
        submitted = self.submit()
        _target, grant = self.begin()
        self.start(grant)
        invalid = ExecutionResultPackage(
            package_id="package-incomplete-failures",
            cases=(CaseResult("case-fail", "fail", "failed", 0.1),),
            reporter_complete=True,
        )
        with self.assertRaisesRegex(TestStoreContractError, "failure record"):
            self.complete(
                grant,
                conclusion=ExecutionConclusion.TEST_FAILED,
                package=invalid,
            )
        self.assertEqual(self.store.cases(run_id=submitted.run_id), ())
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "running")

    def test_dependency_failure_cancels_only_transitive_dependents(self) -> None:
        plan = immutable_plan(
            names=("lint", "unit", "docs"),
            dependencies={"lint": (), "unit": ("lint",), "docs": ()},
        )
        submitted = self.submit(plan)
        _target, lint = self.begin(target_name="lint")
        self.start(lint)
        failed = ExecutionResultPackage(
            package_id="package-lint-failed",
            failures=(
                FailureRecord(
                    "failure-lint",
                    FailureClassification.TEST_FAILURE,
                    "lint failed",
                ),
            ),
            reporter_complete=True,
        )
        self.complete(
            lint,
            conclusion=ExecutionConclusion.TEST_FAILED,
            package=failed,
        )
        interim = self.store.get_run(submitted.run_id)
        states = {item["target_name"]: item["state"] for item in interim["targets"]}
        self.assertEqual(states, {"docs": "queued", "lint": "test_failed", "unit": "cancelled"})
        self.assertEqual(
            [item.target_name for item in self.store.runnable_targets()], ["docs"]
        )
        _target, docs = self.begin(target_name="docs")
        self.start(docs)
        self.complete(docs)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")

    def test_cancel_moves_exact_execution_to_stopping_and_queued_to_cancelled(self) -> None:
        submitted = self.submit(
            immutable_plan(names=("lint", "docs"), fingerprint="9" * 64)
        )
        _target, grant = self.begin(target_name="lint")
        self.start(grant)
        cancelled = self.store.request_cancel(
            submitted.run_id,
            actor="user@example.com",
            reason="stop",
            operation_id=operation_id(),
        )
        self.assertEqual(cancelled["active_execution_ids"], [grant.execution_id])
        states = {
            item["target_name"]: item["state"]
            for item in self.store.get_run(submitted.run_id)["targets"]
        }
        self.assertEqual(states, {"docs": "cancelled", "lint": "stopping"})
        self.assertEqual(self.store.restart_cleanup()[0]["execution_id"], grant.execution_id)

    def test_retry_creates_a_new_run_and_preserves_original_execution(self) -> None:
        submitted = self.submit()
        _target, grant = self.begin()
        self.start(grant)
        package = ExecutionResultPackage(
            package_id="package-retry-source",
            failures=(
                FailureRecord(
                    "failure-retry-source",
                    FailureClassification.TEST_FAILURE,
                    "failed",
                ),
            ),
            reporter_complete=True,
        )
        self.complete(
            grant,
            conclusion=ExecutionConclusion.TEST_FAILED,
            package=package,
        )
        mutation = operation_id()
        retry = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry",
            failed_only=True,
            operation_id=mutation,
        )
        replay = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry",
            failed_only=True,
            operation_id=mutation,
        )
        self.assertEqual(retry, replay)
        self.assertNotEqual(retry.run_id, submitted.run_id)
        self.assertEqual(
            self.store.get_execution(grant.execution_id)["run_id"], submitted.run_id
        )
        retry_target = self.store.get_run(retry.run_id)["targets"][0]
        self.assertIsNone(retry_target["execution_id"])

    def test_setup_evidence_and_bounded_stats_survive_reduction(self) -> None:
        plan = immutable_plan(evidence=True, fingerprint="8" * 64)
        submitted = self.submit(plan)
        _target, grant = self.begin()
        self.start(grant)
        self.complete(grant)
        checked = self.store.check_evidence_policy(
            repository_id="repo-v8",
            snapshot_id="snapshot-v8",
            policy_name="release",
        )
        self.assertTrue(checked["satisfied"])
        retained = self.store.retain_repository_setup_projection(
            {
                "repository_id": "repo-v8",
                "status": "ready",
                "manifest_fingerprint": "c" * 64,
                "targets": ["lint"],
            }
        )
        self.assertTrue(retained["retained"])
        self.assertEqual(
            self.store.repository_setup_catalog(("repo-v8",))[0]["setup_status"],
            "ready",
        )
        statistics = self.store.repository_statistics(
            repository_id="repo-v8", since=0
        )
        self.assertEqual(statistics["totals"]["execution_count"], 1)
        self.assertEqual(
            statistics["totals"]["succeeded_execution_count"], 1
        )
        self.assertEqual(len(statistics["series"]), 1)


if __name__ == "__main__":
    unittest.main()
