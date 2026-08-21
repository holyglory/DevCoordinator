from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_contract import SourceMode, parse_test_manifest
from devcoordinator.universal_test_planner import SourceIdentity, create_test_plan
from devcoordinator.universal_test_store import (
    AttemptConclusion,
    CaseResult,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    TestStoreContractError,
    TestStoreNotFound,
    UniversalTestStore,
)


def operation_id() -> str:
    return str(uuid.uuid4())


def selected_plan(*, repository_id: str = "repo-tests"):
    manifest = parse_test_manifest({
        "schema_version": 4,
        "defaults": {
            "timeout_seconds": 60,
            "network": "none",
            "environment": {},
        },
        "global_inputs": [".codex/tests.json"],
        "intents": {"release": {"source_mode": "immutable", "allow_reuse": False}},
        "fixtures": {},
        "targets": {
            "unit": {
                "driver": "pytest",
                "reporter": "pytest-events",
                "argv": ["{python}", "-m", "pytest"],
                "cwd": ".",
                "inputs": ["**"],
                "depends_on": [],
                "intents": ["release"],
            },
        },
        "evidence_policies": {},
    })
    source = SourceIdentity(
        mode=SourceMode.IMMUTABLE,
        repository_id=repository_id,
        content_fingerprint=uuid.uuid4().hex * 2,
        original_root=f"/home/example/{repository_id}",
        temporary_root=None,
        snapshot_id=f"snapshot-{uuid.uuid4().hex}",
    )
    return create_test_plan(
        manifest,
        intent="release",
        source=source,
        changes=(),
    )


class MutableClock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float = 1.0) -> None:
        self.value += seconds


class UniversalTestStoreReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock()
        self.store = UniversalTestStore.create(
            Path(self.temporary.name) / "test-plane.sqlite3",
            clock=self.clock,
        )

    def submit(self, *, repository_id: str = "repo-tests"):
        result = self.store.submit_plan(
            selected_plan(repository_id=repository_id),
            operation_id=operation_id(),
            actor="codex:test",
            owner_uid=1001,
        )
        self.clock.advance()
        return result

    def test_repository_run_history_uses_exact_scoped_cursor(self) -> None:
        oldest = self.submit()
        middle = self.submit()
        newest = self.submit()
        other = self.submit(repository_id="other-repo")

        first = self.store.runs(repository_id="repo-tests", limit=2)
        self.assertEqual([row["run_id"] for row in first], [newest.run_id, middle.run_id])
        self.assertEqual(first[0]["target_count"], 1)
        second = self.store.runs(
            repository_id="repo-tests", after=str(first[-1]["run_id"]), limit=2
        )
        self.assertEqual([row["run_id"] for row in second], [oldest.run_id])
        with self.assertRaises(TestStoreNotFound):
            self.store.runs(repository_id="repo-tests", after=other.run_id)
        with self.assertRaises(TestStoreContractError):
            self.store.runs(repository_id="repo-tests", state="invented")

    def test_run_lookup_can_bind_opaque_id_to_repository_in_one_query(self) -> None:
        own = self.submit(repository_id="repo-tests")
        foreign = self.submit(repository_id="other-repo")

        resolved = self.store.get_run(
            own.run_id, repository_id="repo-tests"
        )
        self.assertEqual(resolved["run_id"], own.run_id)
        self.assertEqual(resolved["repository_id"], "repo-tests")
        with self.assertRaisesRegex(TestStoreNotFound, "test run does not exist"):
            self.store.get_run(
                foreign.run_id, repository_id="repo-tests"
            )
        with self.assertRaisesRegex(TestStoreNotFound, "test run does not exist"):
            self.store.get_run(
                "missing-run", repository_id="repo-tests"
            )

    def test_case_details_are_reduced_to_current_run_counts(self) -> None:
        submitted = self.submit()
        target = self.store.runnable_targets()[0]
        execution_id = self.store.execution_identity(target.target_id)
        systemd_unit = (
            "devcoordinator-test-"
            + hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:32]
            + ".service"
        )
        grant = self.store.begin_execution(
            target.target_id,
            repository_generation=1,
            systemd_unit=systemd_unit,
            launch_operation_id=operation_id(),
            descriptor_fingerprint="a" * 64,
            launch_deadline_at=self.clock() + 30,
            operation_id=operation_id(),
        )
        self.store.record_started(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=systemd_unit,
            launch_ack_id="launch-1",
            started_at=self.clock(),
            operation_id=operation_id(),
        )
        self.store.complete_from_package(
            grant.execution_id,
            generation=grant.generation,
            systemd_unit=systemd_unit,
            package=ExecutionResultPackage(
                package_id="package-1",
                cases=(
                    CaseResult("case-a", "case a", "passed", 0.1),
                    CaseResult("case-b", "case b", "failed", 0.2),
                ),
                failures=(
                    FailureRecord(
                        failure_id="failure-1",
                        classification=FailureClassification.TEST_FAILURE,
                        message="case b failed",
                        case_id="case-b",
                    ),
                ),
                reporter_complete=True,
            ),
            conclusion=AttemptConclusion.TEST_FAILED,
            duration_seconds=0.3,
            operation_id=operation_id(),
            unit_inactive=True,
            cgroup_empty=True,
        )

        metrics = self.store.run_metrics(submitted.run_id)
        self.assertEqual(metrics["passed_count"], 1)
        self.assertEqual(metrics["failed_count"], 1)
        cases = self.store.cases(run_id=submitted.run_id, limit=1)
        self.assertEqual(cases[0]["case_id"], "case-a")
        next_page = self.store.cases(
            run_id=submitted.run_id, after=int(cases[0]["cursor"]), limit=1
        )
        self.assertEqual(next_page[0]["case_id"], "case-b")


if __name__ == "__main__":
    unittest.main()
