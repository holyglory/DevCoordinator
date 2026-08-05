#!/usr/bin/env python3
"""Focused contract tests for the governed-run installation verifier."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import verify_codex_test_access as access  # noqa: E402


RUN_ID = "run-probe"
PLAN_ID = "plan-probe"
REPOSITORY_ID = "repo-probe"


def successful_responses() -> dict[str, dict[str, object]]:
    return {
        "plan": {
            "ok": True,
            "plan": {
                "plan_id": PLAN_ID,
                "repository_id": REPOSITORY_ID,
                "selected_target_count": 1,
                "selected_targets": [access.RUNNER_PROBE_TARGET],
            },
            "submission": {
                "available": True,
                "registration": {
                    "registered": True,
                    "plan_id": PLAN_ID,
                },
            },
        },
        "submit": {"ok": True, "run_id": RUN_ID},
        "wait": {"ok": True, "run_id": RUN_ID, "state": "succeeded"},
        "status": {
            "ok": True,
            "run_id": RUN_ID,
            "state": "succeeded",
            "conclusion": "succeeded",
            "source_mode": "immutable",
            "usage": {
                "available": True,
                "peak_memory_mib": 12.5,
                "cpu_seconds": 0.25,
                "measured_attempts": 1,
                "total_attempts": 1,
            },
            "targets": [
                {
                    "target_name": access.RUNNER_PROBE_TARGET,
                    "state": "succeeded",
                }
            ],
        },
        "summary": {
            "ok": True,
            "run_id": RUN_ID,
            "conclusion": "succeeded",
            "source": {"mode": "immutable"},
            "counts": {
                "attempts": 1,
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "errors": 0,
            },
            "artifact_count": 3,
        },
        "failures": {
            "ok": True,
            "run_id": RUN_ID,
            "failures": [],
            "next_cursor": None,
        },
    }


class FakeRunner:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self.responses = copy.deepcopy(responses)
        self.calls: list[list[str]] = []

    def __call__(
        self,
        argv,
        label,
        *,
        timeout_seconds=None,
    ) -> subprocess.CompletedProcess[str]:
        del label, timeout_seconds
        values = list(argv)
        self.calls.append(values)
        action = values[1]
        return subprocess.CompletedProcess(
            values,
            0,
            stdout=json.dumps(self.responses[action]),
            stderr="",
        )


class RunnerExerciseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-access-probe-")
        self.root = Path(self.temporary.name)
        self.owner_uid = self.root.stat().st_uid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def exercise(
        self,
        responses: dict[str, dict[str, object]] | None = None,
    ) -> tuple[dict[str, object], FakeRunner]:
        runner = FakeRunner(responses or successful_responses())
        result = access.exercise_governed_runner(
            self.root,
            execution_timeout_seconds=41,
            launch_timeout_seconds=43,
            wait_timeout_seconds=47,
            launcher=Path("/fixture/devcoordinator-test"),
            command_runner=runner,
            verification_uid=self.owner_uid + 1,
        )
        return result, runner

    def assert_run_calls_are_repository_bound(
        self, runner: FakeRunner, expected_actions: list[str]
    ) -> None:
        run_calls = [call for call in runner.calls if call[1] != "plan"]
        self.assertEqual([call[1] for call in run_calls], expected_actions)
        for call in run_calls:
            self.assertEqual(
                call[call.index("--repository-id") + 1], REPOSITORY_ID
            )

    def test_exact_cross_account_success_and_caller_timeouts_are_required(self) -> None:
        result, runner = self.exercise()
        self.assertEqual(
            [call[1] for call in runner.calls],
            ["plan", "submit", "wait", "status", "summary"],
        )
        plan = runner.calls[0]
        self.assertEqual(plan[plan.index("--execution-timeout-seconds") + 1], "41")
        self.assertEqual(plan[plan.index("--launch-timeout-seconds") + 1], "43")
        self.assert_run_calls_are_repository_bound(
            runner, ["submit", "wait", "status", "summary"]
        )
        wait = runner.calls[2]
        self.assertEqual(wait[wait.index("--timeout-seconds") + 1], "47")
        self.assertEqual(result["repository_owner_uid"], self.owner_uid)
        self.assertEqual(result["verification_uid"], self.owner_uid + 1)
        self.assertEqual(result["passed_cases"], 1)
        self.assertEqual(result["artifact_count"], 3)
        self.assertTrue(result["newly_registered"])
        self.assertTrue(result["usage"]["available"])

    def test_plan_without_repository_id_is_rejected_before_submission(self) -> None:
        responses = successful_responses()
        del responses["plan"]["plan"]["repository_id"]  # type: ignore[index]
        runner = FakeRunner(responses)

        with self.assertRaisesRegex(
            access.VerificationError, "omitted its repository ID"
        ):
            access.exercise_governed_runner(
                self.root,
                execution_timeout_seconds=41,
                launch_timeout_seconds=43,
                wait_timeout_seconds=47,
                launcher=Path("/fixture/devcoordinator-test"),
                command_runner=runner,
                verification_uid=self.owner_uid + 1,
            )

        self.assertEqual([call[1] for call in runner.calls], ["plan"])

    def test_repeated_immutable_probe_accepts_existing_plan_registration(self) -> None:
        responses = successful_responses()
        responses["plan"]["submission"]["registration"]["registered"] = False  # type: ignore[index]

        result, runner = self.exercise(responses)

        self.assertFalse(result["newly_registered"])
        self.assertEqual(result["plan_id"], PLAN_ID)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(
            [call[1] for call in runner.calls],
            ["plan", "submit", "wait", "status", "summary"],
        )

    def test_same_account_is_not_accepted_as_cross_account_evidence(self) -> None:
        runner = FakeRunner(successful_responses())
        with self.assertRaisesRegex(access.VerificationError, "not cross-account"):
            access.exercise_governed_runner(
                self.root,
                execution_timeout_seconds=41,
                launch_timeout_seconds=43,
                wait_timeout_seconds=47,
                launcher=Path("/fixture/devcoordinator-test"),
                command_runner=runner,
                verification_uid=self.owner_uid,
            )
        self.assertEqual(runner.calls, [])

    def test_timeout_usage_case_and_artifact_failures_are_rejected(self) -> None:
        fixtures: list[tuple[str, dict[str, dict[str, object]], str]] = []

        timed_out = successful_responses()
        timed_out["wait"]["wait_timed_out"] = True
        fixtures.append(("wait", timed_out, "wait deadline"))

        no_usage = successful_responses()
        no_usage["status"]["usage"] = {
            "available": False,
            "peak_memory_mib": None,
            "cpu_seconds": None,
            "measured_attempts": 0,
            "total_attempts": 1,
        }
        fixtures.append(("usage", no_usage, "measured CPU/memory usage"))

        no_case = successful_responses()
        no_case["summary"]["counts"]["passed"] = 0  # type: ignore[index]
        fixtures.append(("case", no_case, "passing case or artifact"))

        no_artifact = successful_responses()
        no_artifact["summary"]["artifact_count"] = 0
        fixtures.append(("artifact", no_artifact, "passing case or artifact"))

        for name, responses, message in fixtures:
            with self.subTest(name=name), self.assertRaisesRegex(
                access.VerificationError, message
            ):
                self.exercise(responses)

    def test_terminal_failure_retains_run_id_and_first_launch_diagnostic(self) -> None:
        responses = successful_responses()
        responses["wait"] = {
            "ok": True,
            "run_id": RUN_ID,
            "state": "failed",
            "failure_classification": "infrastructure_failure",
        }
        responses["failures"]["failures"] = [
            {
                "location": "launch",
                "message": "systemd refused the transient unit",
            }
        ]
        runner = FakeRunner(responses)
        with self.assertRaisesRegex(
            access.VerificationError,
            r"run_id=run-probe.*location=launch.*systemd refused",
        ):
            access.exercise_governed_runner(
                self.root,
                execution_timeout_seconds=41,
                launch_timeout_seconds=43,
                wait_timeout_seconds=47,
                launcher=Path("/fixture/devcoordinator-test"),
                command_runner=runner,
                verification_uid=self.owner_uid + 1,
            )
        self.assert_run_calls_are_repository_bound(
            runner, ["submit", "wait", "failures"]
        )

    def test_subprocess_deadline_is_reported_as_caller_defined(self) -> None:
        with mock.patch.object(
            access.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["fixture"], 17),
        ), self.assertRaisesRegex(
            access.VerificationError, "caller-defined 17s deadline"
        ):
            access.run(["fixture"], "fixture command", timeout_seconds=17)


class LivePlanExerciseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-live-plan-probe-")
        self.root = Path(self.temporary.name)
        self.owner_uid = self.root.stat().st_uid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cross_account_live_plan_is_registered_but_not_submitted(self) -> None:
        selected_targets = [f"target-{index}" for index in range(7)]
        response = {
            "plan": {
                "ok": True,
                "plan": {
                    "plan_id": "plan-live",
                    "source": {"mode": "live"},
                    "selected_targets": selected_targets,
                },
                "submission": {
                    "available": True,
                    "registration": {
                        "registered": True,
                        "plan_id": "plan-live",
                    },
                },
            }
        }
        runner = FakeRunner(response)
        result = access.exercise_cross_account_live_plan(
            self.root,
            execution_timeout_seconds=101,
            launch_timeout_seconds=103,
            launcher=Path("/fixture/devcoordinator-test"),
            command_runner=runner,
            verification_uid=self.owner_uid + 1,
        )
        self.assertEqual(len(runner.calls), 1)
        plan = runner.calls[0]
        self.assertIn("--full", plan)
        self.assertEqual(plan[plan.index("--intent") + 1], "change")
        self.assertEqual(
            plan[plan.index("--execution-timeout-seconds") + 1], "101"
        )
        self.assertEqual(plan[plan.index("--launch-timeout-seconds") + 1], "103")
        self.assertEqual(result["source_mode"], "live")
        self.assertEqual(result["selected_target_count"], 7)
        self.assertTrue(result["newly_registered"])
        self.assertFalse(result["submitted"])

    def test_cross_account_live_plan_accepts_compact_selection_count(self) -> None:
        runner = FakeRunner(
            {
                "plan": {
                    "ok": True,
                    "plan": {
                        "plan_id": "plan-live",
                        "source": {"mode": "live"},
                        "selected_target_count": 7,
                    },
                    "submission": {
                        "available": True,
                        "registration": {
                            "registered": True,
                            "plan_id": "plan-live",
                        },
                    },
                }
            }
        )

        result = access.exercise_cross_account_live_plan(
            self.root,
            execution_timeout_seconds=101,
            launch_timeout_seconds=103,
            launcher=Path("/fixture/devcoordinator-test"),
            command_runner=runner,
            verification_uid=self.owner_uid + 1,
        )

        self.assertEqual(result["selected_target_count"], 7)

    def test_repeated_live_plan_accepts_idempotent_existing_registration(self) -> None:
        runner = FakeRunner(
            {
                "plan": {
                    "ok": True,
                    "plan": {
                        "plan_id": "plan-live",
                        "source": {"mode": "live"},
                        "selected_targets": ["target-one"],
                    },
                    "submission": {
                        "available": True,
                        "registration": {
                            "registered": False,
                            "plan_id": "plan-live",
                        },
                    },
                }
            }
        )

        result = access.exercise_cross_account_live_plan(
            self.root,
            execution_timeout_seconds=101,
            launch_timeout_seconds=103,
            launcher=Path("/fixture/devcoordinator-test"),
            command_runner=runner,
            verification_uid=self.owner_uid + 1,
        )

        self.assertFalse(result["newly_registered"])
        self.assertEqual(result["selected_target_count"], 1)

    def test_live_plan_rejects_contradictory_and_empty_selection_shapes(self) -> None:
        fixtures = {
            "contradictory": {
                "selected_target_count": 2,
                "selected_targets": ["target-one"],
            },
            "empty-full": {"selected_targets": []},
            "empty-compact": {"selected_target_count": 0},
        }
        for name, selection in fixtures.items():
            response = {
                "plan": {
                    "ok": True,
                    "plan": {
                        "plan_id": "plan-live",
                        "source": {"mode": "live"},
                        **selection,
                    },
                    "submission": {
                        "available": True,
                        "registration": {
                            "registered": True,
                            "plan_id": "plan-live",
                        },
                    },
                }
            }
            with self.subTest(name=name), self.assertRaisesRegex(
                access.VerificationError,
                "selected target|selected no targets",
            ):
                access.exercise_cross_account_live_plan(
                    self.root,
                    execution_timeout_seconds=101,
                    launch_timeout_seconds=103,
                    launcher=Path("/fixture/devcoordinator-test"),
                    command_runner=FakeRunner(response),
                    verification_uid=self.owner_uid + 1,
                )

    def test_live_plan_rejects_same_account_and_non_live_response(self) -> None:
        runner = FakeRunner({"plan": {}})
        with self.assertRaisesRegex(access.VerificationError, "not cross-account"):
            access.exercise_cross_account_live_plan(
                self.root,
                execution_timeout_seconds=101,
                launch_timeout_seconds=103,
                launcher=Path("/fixture/devcoordinator-test"),
                command_runner=runner,
                verification_uid=self.owner_uid,
            )
        self.assertEqual(runner.calls, [])

        invalid = FakeRunner(
            {
                "plan": {
                    "ok": True,
                    "plan": {
                        "plan_id": "plan-wrong",
                        "source": {"mode": "immutable"},
                        "selected_target_count": 1,
                    },
                    "submission": {"available": True},
                }
            }
        )
        with self.assertRaisesRegex(access.VerificationError, "not selectable"):
            access.exercise_cross_account_live_plan(
                self.root,
                execution_timeout_seconds=101,
                launch_timeout_seconds=103,
                launcher=Path("/fixture/devcoordinator-test"),
                command_runner=invalid,
                verification_uid=self.owner_uid + 1,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
