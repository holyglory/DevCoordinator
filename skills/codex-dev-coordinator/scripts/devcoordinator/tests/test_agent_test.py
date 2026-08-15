from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import _test_run_actor
from devcoordinator.agent_test import (
    MAX_TEST_RESULT_BYTES,
    child_operation_id,
    enqueue_test,
    project_queue_status,
    project_test_follow,
    submit_test_plan,
)


ROOT_OPERATION = "00000000-0000-4000-8000-000000000001"


def plan(*, intent: str = "change") -> SimpleNamespace:
    return SimpleNamespace(
        repository_id="repo-1",
        plan_id="plan-1",
        intent=intent,
        fingerprint="f" * 64,
        selection={"unit": SimpleNamespace(), "lint": SimpleNamespace()},
        source=SimpleNamespace(
            mode=SimpleNamespace(value="live"),
            original_root="/repo",
            temporary_root=None,
            snapshot_id=None,
        ),
        timeouts=SimpleNamespace(execution_seconds=None, launch_seconds=300),
    )


class Profile:
    def __init__(
        self, *, intent: str = "change", account_id: str = "account-tests"
    ) -> None:
        self.plan = plan(intent=intent)
        self.account_id = account_id
        self.preview_calls: list[dict] = []
        self.submit_calls: list[dict] = []
        self.resolved_actor: str | None = None

    def preview_test_plan(self, **arguments):
        self.preview_calls.append(arguments)
        return {
            "operation_id": arguments["operation_id"],
            "repository_id": "repo-1",
            "plan_id": "plan-1",
            "plan": {"producer": "fixture"},
            "registered": True,
        }

    def submit_test_plan(self, **arguments):
        self.submit_calls.append(arguments)
        self.resolved_actor = _test_run_actor(
            AcceptedBrokerRequest(
                peer=PeerCredentials(uid=1234, gid=1234, pid=99),
                request=BrokerRequest.create(
                    account_id=self.account_id,
                    project_id="repo-1",
                    resource_id="repo-1",
                    operation=BrokerOperation.TEST_RUN_SUBMIT,
                    arguments={
                        "plan_id": arguments["plan_id"],
                        "expected_repository_id": arguments["repository"],
                        "actor": arguments["actor"],
                    },
                    operation_id=arguments["operation_id"],
                ),
            )
        )
        return {
            "operation_id": arguments["operation_id"],
            "repository_id": "repo-1",
            "plan_id": "plan-1",
            "run_id": "run-1",
            "state": "queued",
        }


class AgentTestTests(unittest.TestCase):
    def test_queue_status_projection_is_bounded_without_run_identity(self) -> None:
        result = project_queue_status(
            {
                "repository_id": "repo-1",
                "sampled_at": 123.0,
                "phase": "scheduler",
                "global_targets": {"queued": 4, "leased": 1, "running": 2},
                "repository_targets": {"queued": 2, "leased": 0, "running": 0},
                "repository_runnable_targets": 1,
                "approximate_first_position": 3,
                "position_population_truncated": False,
                "blockers": [{"code": "host_memory", "target_count": 1}],
                "representative_targets": [
                    {
                        "run_id": "run-1",
                        "target_name": "server-tests",
                        "state": "queued",
                        "attempt_id": None,
                        "wait_code": "exact_dependency_pending",
                    }
                ],
                "worker_capacity": {
                    "model": "dynamic_memory_admission",
                    "limit": None,
                    "available": None,
                },
            },
            repository_id="repo-1",
        )

        self.assertEqual(result["classification"], "test_queue_status")
        self.assertEqual(result["approximate_first_position"], 3)
        self.assertNotIn("run_id", result)
        self.assertEqual(
            result["representative_targets"][0]["target_name"], "server-tests"
        )

    def test_enqueue_replays_completed_durable_preview_and_submits(self) -> None:
        profile = Profile()
        profile.preview_test_plan = mock.Mock(
            return_value={
                "schema_version": 1,
                "ok": True,
                "classification": "test_plan_preview_completed",
                "operation_id": ROOT_OPERATION,
                "repository_id": "repo-1",
                "intent": "change",
                "plan_id": "plan-1",
                "snapshot_id": "snapshot-1",
                "registered": True,
            }
        )
        result = enqueue_test(
            profile=profile,
            repository=SimpleNamespace(repo_id="repo-1", canonical_root="/repo"),
            temporary_repository=None,
            intent="change",
            requested_targets=(),
            execution_timeout_seconds=None,
            launch_timeout_seconds=300,
            actor="codex:thread-1",
            operation_id=ROOT_OPERATION,
        )
        self.assertEqual(result["plan"]["id"], "plan-1")
        self.assertTrue(result["plan"]["replayed"])
        self.assertEqual(len(profile.submit_calls), 1)

    def _enqueue(
        self, *, intent: str = "change", account_id: str = "account-tests"
    ):
        profile = Profile(intent=intent, account_id=account_id)
        repository = SimpleNamespace(repo_id="repo-1", canonical_root="/repo")
        with mock.patch(
            "devcoordinator.universal_test_service.decode_test_plan_document",
            return_value=profile.plan,
        ):
            result = enqueue_test(
                profile=profile,
                repository=repository,
                temporary_repository=None,
                intent=intent,
                requested_targets=(),
                execution_timeout_seconds=None,
                launch_timeout_seconds=300,
                actor="codex:thread-1",
                operation_id=ROOT_OPERATION,
            )
        return profile, result

    def test_child_operation_is_stable_and_stage_separated(self) -> None:
        first = child_operation_id(ROOT_OPERATION, "submit")
        self.assertEqual(first, child_operation_id(ROOT_OPERATION, "submit"))
        self.assertNotEqual(first, ROOT_OPERATION)

    def test_routine_enqueue_previews_then_submits_deterministic_child(self) -> None:
        profile, result = self._enqueue()
        self.assertEqual(len(profile.preview_calls), 1)
        self.assertEqual(len(profile.submit_calls), 1)
        self.assertEqual(
            profile.submit_calls[0]["operation_id"],
            child_operation_id(ROOT_OPERATION, "submit"),
        )
        self.assertEqual(profile.submit_calls[0]["actor"], "codex:thread-1")
        self.assertNotIn("requested_actor", profile.submit_calls[0])
        self.assertEqual(profile.resolved_actor, "codex:thread-1")
        self.assertEqual(result["continuation"], "dc1:run:run-1")
        self.assertTrue(result["submission_performed"])
        self.assertLessEqual(
            len(json.dumps(result, separators=(",", ":"), sort_keys=True).encode()),
            MAX_TEST_RESULT_BYTES,
        )

    def test_handoff_submits_without_a_permission_review(self) -> None:
        profile, result = self._enqueue(intent="handoff")
        self.assertEqual(len(profile.submit_calls), 1)
        self.assertTrue(result["submission_performed"])
        self.assertEqual(result["continuation"], "dc1:run:run-1")

    def test_routine_enqueue_codex_actor_survives_api_account_routing(self) -> None:
        profile, result = self._enqueue(account_id="devcoordinator-api")
        self.assertEqual(result["classification"], "test_enqueued")
        self.assertEqual(profile.resolved_actor, "codex:thread-1")

    def test_plan_submit_forwards_the_current_actor_contract(self) -> None:
        profile = Profile(intent="handoff")
        result = submit_test_plan(
            profile=profile,
            repository=SimpleNamespace(repo_id="repo-1"),
            plan_id="plan-1",
            actor="codex:thread-1",
            operation_id=ROOT_OPERATION,
        )
        self.assertEqual(result["continuation"], "dc1:run:run-1")
        self.assertEqual(profile.submit_calls[0]["actor"], "codex:thread-1")
        self.assertNotIn("requested_actor", profile.submit_calls[0])

    def test_follow_projects_terminal_failures_without_raw_summary(self) -> None:
        status = {"run_id": "run-1", "state": "failed"}
        summary = {
            "run_id": "run-1",
            "conclusion": "failed",
            "counts": {"passed": 4, "failed": 1},
            "timing": {"wall_seconds": 1.25},
            "failures": [
                {
                    "target": "unit",
                    "message": "assertion failed " + "x" * 10_000,
                    "location": "tests/test_example.py:10",
                }
            ],
            "raw": "must-not-cross",
        }
        result = project_test_follow(status, run_id="run-1", summary=summary)
        self.assertTrue(result["run"]["terminal"])
        self.assertNotIn("raw", result)
        self.assertLessEqual(
            len(json.dumps(result, separators=(",", ":"), sort_keys=True).encode()),
            MAX_TEST_RESULT_BYTES,
        )

    def test_follow_exposes_bounded_typed_scheduler_waits(self) -> None:
        status = {
            "run_id": "run-1",
            "state": "queued",
            "targets": [
                {
                    "target_name": f"target-{index}",
                    "wait": {
                        "code": "exact_worktree_busy",
                        "since": 100.0 + index,
                        "required_mib": None,
                    },
                }
                for index in range(5)
            ],
        }
        result = project_test_follow(status, run_id="run-1")
        self.assertEqual(result["scheduler_wait"]["target_count"], 5)
        self.assertEqual(len(result["scheduler_wait"]["targets"]), 3)
        self.assertTrue(result["scheduler_wait"]["truncated"])
        self.assertEqual(
            result["scheduler_wait"]["targets"][0]["code"],
            "exact_worktree_busy",
        )

    def test_follow_exposes_bounded_active_attempt_heartbeats(self) -> None:
        status = {
            "run_id": "run-1",
            "state": "running",
            "targets": [
                {
                    "target_name": f"target-{index}",
                    "active_attempt": {
                        "attempt_id": f"attempt-{index}",
                        "state": "running",
                        "started_at": 100.0,
                        "heartbeat_at": 200.0 + index,
                        "lease_expires_at": 230.0 + index,
                    },
                }
                for index in range(6)
            ],
        }

        result = project_test_follow(status, run_id="run-1")

        self.assertEqual(len(result["active_attempts"]), 4)
        self.assertTrue(result["active_attempts_truncated"])
        self.assertEqual(
            result["active_attempts"][0]["attempt_id"], "attempt-0"
        )
        self.assertEqual(result["active_attempts"][0]["heartbeat_at"], 200.0)
        self.assertLessEqual(
            len(json.dumps(result, separators=(",", ":"), sort_keys=True).encode()),
            MAX_TEST_RESULT_BYTES,
        )

    def test_follow_distinguishes_failed_cases_from_retained_records(self) -> None:
        status = {"run_id": "run-1", "state": "failed"}
        summary = {
            "run_id": "run-1",
            "conclusion": "failed",
            "counts": {"passed": 4, "failed": 487},
            "failure_count": 129,
            "failures": [
                {"target": f"target-{index}", "message": "failed"}
                for index in range(3)
            ],
        }

        result = project_test_follow(status, run_id="run-1", summary=summary)

        self.assertEqual(result["failure_count"], 487)
        self.assertEqual(result["failure_record_count"], 129)
        self.assertTrue(result["failures_truncated"])
        self.assertEqual(
            result["next_command"],
            "devcoordinator test failures dc1:run:run-1",
        )


if __name__ == "__main__":
    unittest.main()
