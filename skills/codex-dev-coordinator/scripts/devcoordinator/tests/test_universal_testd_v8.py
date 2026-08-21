from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from devcoordinator.universal_test_scheduler import (
    HostMemorySnapshot,
    WeightedFairScheduler,
)
from devcoordinator.universal_test_contract import parse_test_manifest, SourceMode
from devcoordinator.universal_test_planner import SourceIdentity, create_test_plan
from devcoordinator.universal_test_store import (
    ArtifactMetadata,
    AttemptConclusion,
    CaseResult,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    TargetResources,
    UniversalTestStore,
)
from devcoordinator.universal_testd import (
    BrokerLaunchTicket,
    RunnerHandle,
    RunnerObservation,
    RunnerResultPackage,
    TestdEngine,
)
from devcoordinator.tests.test_universal_test_store_v8 import (
    Clock,
    operation_id,
)


def governed_plan(
    *,
    names: tuple[str, ...] = ("lint",),
    dependencies: dict[str, tuple[str, ...]] | None = None,
):
    dependency_map = dependencies or {name: () for name in names}
    manifest = parse_test_manifest(
        {
            "schema_version": 4,
            "defaults": {
                "timeout_seconds": 20,
                "network": "none",
                "environment": {},
            },
            "global_inputs": [".codex/tests.json"],
            "intents": {
                "release": {"source_mode": "immutable", "allow_reuse": False}
            },
            "fixtures": {},
            "targets": {
                name: {
                    "driver": "automation",
                    "reporter": "automation-events",
                    "argv": ["./scripts/test", name],
                    "cwd": ".",
                    "inputs": ["src/**"],
                    "depends_on": list(dependency_map[name]),
                    "intents": ["release"],
                }
                for name in names
            },
            "evidence_policies": {},
        }
    )
    return create_test_plan(
        manifest,
        intent="release",
        source=SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id="repo-v8",
            content_fingerprint="d" * 64,
            original_root="/srv/repo-v8",
            snapshot_id="snapshot-v8",
        ),
        changes=(),
        execution_timeout_seconds=20,
        launch_timeout_seconds=30,
    )


def result_pair(
    execution_id: str,
    *,
    failed: bool = False,
    reporter_complete: bool = True,
) -> tuple[RunnerResultPackage, ExecutionResultPackage]:
    package_id = "package-" + execution_id
    cases = (
        (CaseResult("case-fail", "failed case", "failed", 0.1),)
        if failed
        else (CaseResult("case-pass", "passed case", "passed", 0.1),)
    )
    failures = (
        (
            FailureRecord(
                "failure-" + execution_id,
                FailureClassification.TEST_FAILURE,
                "assertion failed",
                case_id="case-fail",
            ),
        )
        if failed
        else ()
    )
    package = ExecutionResultPackage(
        package_id=package_id,
        cases=cases,
        failures=failures,
        reporter_complete=reporter_complete,
    )
    metadata = RunnerResultPackage(
        package_id=package_id,
        sha256="a" * 64,
        size_bytes=1024,
        manifest={"reporter_complete": reporter_complete},
        outcome={"returncode": 1 if failed else 0, "infrastructure_error": None},
        counts={
            "passed": 0 if failed else 1,
            "failed": 1 if failed else 0,
            "skipped": 0,
            "error": 0,
            "failures": 1 if failed else 0,
            "artifacts": 0,
        },
    )
    return metadata, package


class FakeIssuer:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.calls = []

    def issue(self, *, candidate, execution, plan_document, launch_deadline):
        self.calls.append(
            (candidate.target_id, execution.execution_id, launch_deadline)
        )
        return BrokerLaunchTicket(
            ticket_id="ticket-" + candidate.target_id,
            target_id=candidate.target_id,
            run_id=candidate.run_id,
            repository_id=candidate.repository_id,
            repository_generation=11,
            owner_uid=candidate.owner_uid,
            root_repo="/srv/repo-v8",
            temporary_repo=None,
            execution_root="/srv/snapshots/v8",
            argv=("python3", "-m", "pytest"),
            cwd="tests",
            environment={},
            intent="release",
            driver="pytest",
            reporter="pytest-events",
            artifacts=(),
            fixtures=(),
            credentials=(),
            network="none",
            ttl_seconds=20,
            worktree_key="/srv/snapshots/v8",
            issued_at=self.clock.value,
            expires_at=launch_deadline,
        )


class FakeLauncher:
    def __init__(self, store: UniversalTestStore, clock: Clock) -> None:
        self.store = store
        self.clock = clock
        self.prepare_calls = []
        self.start_calls = []
        self.attach_calls = []
        self.stop_calls = []
        self.collect_calls = []
        self.resolve_calls = []
        self.observations: dict[str, list[RunnerObservation]] = {}
        self.packages: dict[str, ExecutionResultPackage] = {}
        self.confirm_start = True
        self.package_on_stop: dict[str, RunnerResultPackage] = {}

    def prepare(self, request):
        retained = self.store.get_attempt(request.execution.execution_id)
        if retained["state"] != "starting":
            raise AssertionError("store reservation was not committed before prepare")
        self.prepare_calls.append(request)
        return RunnerHandle(
            execution_id=request.execution.execution_id,
            generation=request.execution.generation,
            systemd_unit=request.execution.systemd_unit,
            launch_operation_id=request.execution.launch_operation_id,
        )

    def start(self, request, handle):
        self.start_calls.append((request, handle))
        if not self.confirm_start:
            return handle
        return replace(
            handle,
            launch_ack_id="launch-" + handle.execution_id,
            launch_confirmed=True,
        )

    def observe(self, handle):
        queued = self.observations.get(handle.execution_id)
        if queued:
            return queued.pop(0)
        return RunnerObservation(
            "running",
            unit_inactive=False,
            cgroup_empty=False,
            launch_confirmed=True,
            started_at=self.clock.value,
        )

    def attach(self, binding):
        self.attach_calls.append(dict(binding))
        return RunnerHandle(
            execution_id=str(binding["execution_id"]),
            generation=int(binding["generation"]),
            systemd_unit=str(binding["systemd_unit"]),
            launch_operation_id=str(binding["launch_operation_id"]),
            launch_ack_id="launch-" + str(binding["execution_id"]),
            launch_confirmed=binding.get("started_at") is not None,
        )

    def stop(self, handle, *, reason):
        self.stop_calls.append((handle.execution_id, reason))
        return RunnerObservation(
            "stopped",
            unit_inactive=True,
            cgroup_empty=True,
            launch_confirmed=True,
            started_at=self.clock.value,
            result_package=self.package_on_stop.pop(handle.execution_id, None),
            peak_memory_bytes=64 * 1024 * 1024,
            cpu_seconds=1.0,
            exit_status=0,
        )

    def resolve_package(self, handle, metadata):
        self.resolve_calls.append((handle.execution_id, metadata.package_id))
        return self.packages[metadata.package_id]

    def collect(self, handle):
        self.collect_calls.append(handle.execution_id)
        return True


class TestdV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = Clock()
        self.store = UniversalTestStore.create(
            Path(self.temporary.name) / "tests.sqlite3", clock=self.clock
        )
        self.scheduler = WeightedFairScheduler(
            memory_probe=lambda: HostMemorySnapshot(
                total_mib=8192,
                available_mib=7000,
                observed_at=self.clock.value,
            )
        )
        self.issuer = FakeIssuer(self.clock)
        self.launcher = FakeLauncher(self.store, self.clock)
        self.engine = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=self.launcher,
            clock=self.clock,
        )

    def submit(self, plan=None):
        selected = plan or governed_plan()
        return self.store.submit_plan(
            selected,
            operation_id=operation_id(),
            actor="codex:testd-v8",
            owner_uid=1001,
            target_resources={
                name: TargetResources(estimated_seconds=1, ttl_seconds=20)
                for name in selected.selected_targets
            },
        )

    def launch_one(self):
        submitted = self.submit()
        scheduled = self.engine.schedule(launch_batch=1)
        self.assertEqual(len(scheduled["launched_target_ids"]), 1)
        request = self.launcher.prepare_calls[-1]
        return submitted, request.execution

    def start_one(self):
        submitted, execution = self.launch_one()
        heartbeat = self.engine.heartbeat()
        self.assertEqual(heartbeat["running_execution_ids"], [execution.execution_id])
        return submitted, execution

    def publish(self, execution, *, failed=False):
        metadata, package = result_pair(execution.execution_id, failed=failed)
        self.launcher.packages[metadata.package_id] = package
        self.launcher.observations[execution.execution_id] = [
            RunnerObservation(
                "running",
                unit_inactive=False,
                cgroup_empty=False,
                launch_confirmed=True,
                started_at=self.clock.value,
                result_package=metadata,
            )
        ]
        return metadata, package

    def test_schedule_commits_execution_before_prepare_and_never_duplicates(self) -> None:
        submitted, execution = self.launch_one()
        retained = self.store.get_attempt(execution.execution_id)
        self.assertEqual(retained["state"], "starting")
        self.assertEqual(len(self.launcher.prepare_calls), 1)
        second = self.engine.schedule(launch_batch=1)
        self.assertEqual(second["launched_target_ids"], [])
        self.assertEqual(len(self.launcher.prepare_calls), 1)
        self.assertEqual(self.store.get_run(submitted.run_id)["usage"]["total_attempts"], 1)

    def test_lost_launch_reply_observes_same_execution_without_relaunch(self) -> None:
        self.launcher.confirm_start = False
        submitted, execution = self.launch_one()
        self.launcher.observations[execution.execution_id] = [
            RunnerObservation(
                "starting",
                unit_inactive=False,
                cgroup_empty=False,
                launch_confirmed=False,
            ),
            RunnerObservation(
                "running",
                unit_inactive=False,
                cgroup_empty=False,
                launch_confirmed=True,
                started_at=self.clock.value,
            ),
        ]
        first = self.engine.heartbeat()
        self.assertEqual(first["running_execution_ids"], [execution.execution_id])
        second = self.engine.heartbeat()
        self.assertEqual(second["running_execution_ids"], [execution.execution_id])
        self.assertEqual(len(self.launcher.start_calls), 1)
        self.assertEqual(self.store.get_run(submitted.run_id)["targets"][0]["state"], "running")

    def test_result_package_stops_then_atomically_completes_and_collects(self) -> None:
        submitted, execution = self.start_one()
        self.publish(execution)
        heartbeat = self.engine.heartbeat()
        self.assertEqual(heartbeat["completed_execution_ids"], [execution.execution_id])
        self.assertEqual(self.launcher.stop_calls[0][0], execution.execution_id)
        self.assertEqual(self.launcher.collect_calls, [execution.execution_id])
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "succeeded")
        self.assertEqual(len(self.store.cases(run_id=submitted.run_id)), 1)

    def test_restart_imports_complete_package_before_cancelling(self) -> None:
        submitted, execution = self.start_one()
        metadata, package = result_pair(execution.execution_id)
        self.launcher.packages[metadata.package_id] = package
        self.launcher.observations[execution.execution_id] = [
            RunnerObservation(
                "exited",
                unit_inactive=True,
                cgroup_empty=True,
                result_package=metadata,
                started_at=self.clock.value,
                exit_status=0,
            )
        ]
        replacement = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=self.launcher,
            clock=self.clock,
        )
        self.assertIsInstance(replacement, TestdEngine)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "succeeded")
        self.assertEqual(self.store.restart_cleanup(), ())
        self.assertEqual(self.launcher.stop_calls, [])

    def test_restart_without_package_stops_exact_execution_and_cancels(self) -> None:
        submitted, execution = self.start_one()
        self.launcher.observations[execution.execution_id] = [
            RunnerObservation(
                "running",
                unit_inactive=False,
                cgroup_empty=False,
                started_at=self.clock.value,
            )
        ]
        TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=self.launcher,
            clock=self.clock,
        )
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "cancelled")
        self.assertEqual(self.launcher.stop_calls[-1][0], execution.execution_id)
        self.assertEqual(self.store.restart_cleanup(), ())

    def test_complete_result_wins_cancellation_race(self) -> None:
        submitted, execution = self.start_one()
        self.publish(execution, failed=True)
        cancelled = self.engine.cancel_run(
            run_id=submitted.run_id,
            actor="user@example.com",
            reason="stop",
            operation_id=operation_id(),
        )
        self.assertEqual(cancelled["unresolved_execution_ids"], [])
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "cancelled")
        self.assertEqual(run["targets"][0]["state"], "test_failed")
        self.assertEqual(len(self.store.failures(run_id=submitted.run_id)), 1)

    def test_complete_result_wins_inclusive_timeout_race(self) -> None:
        submitted, execution = self.start_one()
        self.clock.advance(20)
        self.publish(execution)
        self.engine.heartbeat()
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "succeeded")

    def test_timeout_without_result_stops_and_terminalizes_timeout(self) -> None:
        submitted, execution = self.start_one()
        self.clock.advance(20)
        self.engine.heartbeat()
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "timed_out")
        self.assertEqual(run["targets"][0]["state"], "timed_out")
        self.assertEqual(self.launcher.stop_calls[-1][0], execution.execution_id)

    def test_exact_dependencies_launch_independent_branches_only(self) -> None:
        plan = governed_plan(
            names=("lint", "unit", "docs"),
            dependencies={"lint": (), "unit": ("lint",), "docs": ()},
        )
        self.submit(plan)
        result = self.engine.schedule(launch_batch=3)
        launched_names = {
            request.target_name for request in self.launcher.prepare_calls
        }
        self.assertEqual(launched_names, {"lint", "docs"})
        self.assertEqual(len(result["launched_target_ids"]), 2)


if __name__ == "__main__":
    unittest.main()
