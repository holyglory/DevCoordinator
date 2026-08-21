from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_contract import SourceMode, parse_test_manifest
from devcoordinator.universal_test_planner import SourceIdentity, create_test_plan
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_store import (
    AttemptConclusion,
    CaseResult,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    TargetResources,
    UniversalTestStore,
)


def operation_id() -> str:
    return str(uuid.uuid4())


class V8TestPlaneSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = UniversalTestStore.create(
            Path(self.temporary.name) / "tests.sqlite3"
        )
        self.adapter = StoreTestPlaneAdapter(self.store)

    def complete_run(self, *, evidence: bool = False, failed: bool = False):
        manifest = {
            "schema_version": 4,
            "defaults": {"timeout_seconds": 20, "network": "none", "environment": {}},
            "global_inputs": [".codex/tests.json"],
            "intents": {
                "release": {"source_mode": "immutable", "allow_reuse": False}
            },
            "fixtures": {},
            "targets": {
                "lint": {
                    "driver": "automation",
                    "reporter": "automation-events",
                    "argv": ["python3", "-m", "unittest"],
                    "cwd": ".",
                    "inputs": ["**"],
                    "depends_on": [],
                    "intents": ["release"],
                }
            },
            "evidence_policies": (
                {
                    "release": {
                        "intent": "release",
                        "required_targets": ["lint"],
                        "max_age_seconds": 60,
                        "allow_reuse": False,
                    }
                }
                if evidence
                else {}
            ),
        }
        plan = create_test_plan(
            parse_test_manifest(manifest),
            intent="release",
            source=SourceIdentity(
                mode=SourceMode.IMMUTABLE,
                repository_id="repo-v8",
                content_fingerprint="d" * 64,
                original_root="/srv/repo-v8",
                snapshot_id="snapshot-v8",
            ),
        )
        self.adapter.register_plan(
            plan.to_document(),
            target_resources={
                "lint": TargetResources(
                    estimated_seconds=1,
                    ttl_seconds=20,
                    worktree_key="/srv/snapshot-v8",
                )
            },
        )
        submitted = self.adapter.submit(
            plan_id=plan.plan_id,
            repository_id=plan.repository_id,
            operation_id=operation_id(),
            actor="codex:surface-v8",
            owner_uid=1001,
        )
        target = self.store.runnable_targets()[0]
        execution_id = self.store.execution_identity(target.target_id)
        unit = (
            "devcoordinator-test-"
            + hashlib.sha256(execution_id.encode()).hexdigest()[:32]
            + ".service"
        )
        execution = self.store.begin_execution(
            target.target_id,
            repository_generation=1,
            systemd_unit=unit,
            launch_operation_id=operation_id(),
            descriptor_fingerprint="a" * 64,
            launch_deadline_at=self.store.current_time() + 30,
            operation_id=operation_id(),
        )
        self.store.record_started(
            execution.execution_id,
            generation=1,
            systemd_unit=unit,
            launch_ack_id="launch-" + execution.execution_id,
            started_at=self.store.current_time(),
            operation_id=operation_id(),
        )
        case = CaseResult(
            case_id="case-v8",
            display_name="case v8",
            status="failed" if failed else "passed",
            duration_seconds=0.1,
        )
        failures = (
            FailureRecord(
                failure_id="failure-v8",
                classification=FailureClassification.TEST_FAILURE,
                message="failed",
                case_id=case.case_id,
            ),
        ) if failed else ()
        self.store.complete_from_package(
            execution.execution_id,
            generation=1,
            systemd_unit=unit,
            package=ExecutionResultPackage(
                package_id="package-v8",
                cases=(case,),
                failures=failures,
                reporter_complete=True,
            ),
            conclusion=(
                AttemptConclusion.TEST_FAILED
                if failed
                else AttemptConclusion.SUCCEEDED
            ),
            duration_seconds=0.1,
            operation_id=operation_id(),
            unit_inactive=True,
            cgroup_empty=True,
        )
        return plan, submitted

    def test_cases_and_failures_are_cursor_bounded(self) -> None:
        plan, submitted = self.complete_run(failed=True)
        cases = self.adapter.cases(
            run_id=submitted["run_id"], repository_id=plan.repository_id, limit=1
        )
        failures = self.adapter.failures(
            run_id=submitted["run_id"], repository_id=plan.repository_id, limit=1
        )
        self.assertEqual(cases["cases"][0]["case_id"], "case-v8")
        self.assertEqual(failures["failures"][0]["failure_id"], "failure-v8")
        status = self.adapter.status(
            run_id=submitted["run_id"], repository_id=plan.repository_id
        )
        self.assertNotIn("lease_expiry_evidence", status)
        self.assertNotIn("active_attempt", status["targets"][0])
        self.assertEqual(
            status["targets"][0]["execution"]["execution_id"],
            self.store.get_run(submitted["run_id"])["targets"][0]["execution_id"],
        )

    def test_retry_creates_a_new_immutable_run(self) -> None:
        plan, submitted = self.complete_run(failed=True)
        retry = self.adapter.retry(
            run_id=submitted["run_id"],
            repository_id=plan.repository_id,
            actor="codex:surface-v8",
            failed_only=True,
            operation_id=operation_id(),
        )
        self.assertNotEqual(retry["run_id"], submitted["run_id"])
        self.assertEqual(retry["source_run_id"], submitted["run_id"])

    def test_evidence_and_statistics_use_testd_store(self) -> None:
        plan, submitted = self.complete_run(evidence=True)
        evidence_check = self.adapter.evidence(
            repository_id=plan.repository_id,
            snapshot_id=plan.source.snapshot_id or "",
            policy_name="release",
        )
        evidence = self.adapter.evidence(
            repository_id=plan.repository_id,
            snapshot_id=plan.source.snapshot_id or "",
            policy_name="release",
            operation_id=operation_id(),
        )
        statistics = self.adapter.statistics(
            repository_id=plan.repository_id, days=30, limit=30
        )
        self.assertTrue(evidence_check["requires_consumption"])
        self.assertTrue(evidence_check["consumable"])
        self.assertTrue(evidence["satisfied"])
        self.assertEqual(statistics["repository_id"], plan.repository_id)
        self.assertGreaterEqual(statistics["totals"]["run_count"], 1)


if __name__ == "__main__":
    unittest.main()
