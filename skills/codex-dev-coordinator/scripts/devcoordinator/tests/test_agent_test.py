from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import _test_run_actor
from devcoordinator.agent_test import (
    MAX_TEST_RESULT_BYTES,
    child_operation_id,
    enqueue_test,
    project_test_follow,
    submit_reviewed_plan,
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
            AuthorizedBrokerRequest(
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

    def test_handoff_is_review_first_and_does_not_submit(self) -> None:
        profile, result = self._enqueue(intent="handoff")
        self.assertEqual(profile.submit_calls, [])
        self.assertTrue(result["review_required"])
        self.assertEqual(result["plan_handle"], "dc1:plan:plan-1")

    def test_routine_enqueue_codex_actor_survives_api_account_routing(self) -> None:
        profile, result = self._enqueue(account_id="devcoordinator-api")
        self.assertEqual(result["classification"], "test_enqueued")
        self.assertEqual(profile.resolved_actor, "codex:thread-1")

    def test_reviewed_submit_forwards_the_current_actor_contract(self) -> None:
        profile = Profile(intent="handoff")
        result = submit_reviewed_plan(
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


if __name__ == "__main__":
    unittest.main()
