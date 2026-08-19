#!/usr/bin/env python3
"""Focused tests for the software-owned delivery orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
from typing import Sequence
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import software_owned_delivery as delivery  # noqa: E402
import run_production_console_acceptance as console_acceptance  # noqa: E402


DIGEST = "a" * 64


def command(name: str, *, blocking: bool = True) -> dict[str, object]:
    return {"name": name, "argv": ["fixture", name], "blocking": blocking}


def plan() -> dict[str, object]:
    return delivery.validate_plan(
        {
            "schema_version": delivery.SCHEMA_VERSION,
            "kind": delivery.PLAN_KIND,
            "source_checks": [
                command("advisory-failure", blocking=False),
                command("source-pass"),
            ],
            "same_schema": {
                "prepare": [command("prepare-one"), command("prepare-two")],
                "apply": [command("apply-one"), command("apply-two")],
                "rollback": [command("rollback-one"), command("rollback-two")],
                "health": [command("health-one"), command("health-two")],
            },
            "acceptance_setup": [command("acceptance-session")],
            "acceptance": [
                command("acceptance-one", blocking=False),
                command("acceptance-two", blocking=False),
                command("acceptance-three", blocking=False),
            ],
        }
    )


def reset_plan() -> dict[str, object]:
    value = plan()
    actions = {
        "prepare": "prepare",
        "apply": "apply",
        "rollback": "rollback",
        "health": "verify",
    }
    for phase, action in actions.items():
        value["same_schema"][phase] = [
            {
                "name": f"switch-{action}",
                "argv": [
                    "{release}/bin/devcoordinator-same-schema-switch",
                    action,
                    "--release",
                    "{release}",
                    "--transaction-root",
                    "{transaction_root}",
                ],
                "blocking": True,
            }
        ]
    return value


class FakeExecutor:
    def __init__(self, outcomes: dict[str, int] | None = None) -> None:
        self.outcomes = dict(outcomes or {})
        self.calls: list[list[str]] = []
        self.lock = threading.Lock()

    @staticmethod
    def name(argv: list[str]) -> str:
        for index, value in enumerate(argv):
            if Path(value).name == "devcoordinator-same-schema-switch":
                return argv[index + 1]
        if "plan" in argv and any("install_availability_release.py" in value for value in argv):
            return "release-plan"
        if "stage" in argv and any("install_availability_release.py" in value for value in argv):
            return "release-stage"
        if "verify" in argv and any("install_availability_release.py" in value for value in argv):
            return "release-verify"
        if "diff" in argv and "--check" in argv:
            return "diff-check"
        if any("self_test_software_owned_delivery.py" in value for value in argv):
            return "delivery-self-test"
        if any("self_test_verify_codex_test_access.py" in value for value in argv):
            return "codex-test-access-self-test"
        if any("self_test_switch_same_schema_release.py" in value for value in argv):
            return "same-schema-switch-self-test"
        if any("run_fast_repository_validation.py" in value for value in argv):
            return "fast-repository-validation"
        if any("run_console_unit_tests.py" in value for value in argv):
            return "console-tests"
        if any("run_coordinator_test_partition.py" in value for value in argv):
            return argv[-1]
        return argv[-1]

    def run(self, argv, *, cwd, stdout, stderr) -> int:
        values = list(argv)
        name = self.name(values)
        with self.lock:
            self.calls.append(values)
        if name == "release-plan":
            stdout.write_text(
                json.dumps(
                    {
                        "release_digest": DIGEST,
                        "release_directory": f"/opt/devcoordinator/releases/{DIGEST}",
                        "source_identity": {
                            "owner_uid": 1000,
                            "owner_gid": 1003,
                            "mode": "0775",
                        },
                    }
                ),
                encoding="utf-8",
            )
        elif name in {"release-stage", "release-verify"}:
            stdout.write_text(json.dumps({"ok": True, "release_digest": DIGEST}), encoding="utf-8")
        else:
            stdout.write_text(json.dumps({"ok": self.outcomes.get(name, 0) == 0}), encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return self.outcomes.get(name, 0)


class DeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="software-delivery-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def subject(
        self,
        *,
        executor: FakeExecutor | None = None,
        selected_plan: dict[str, object] | None = None,
        acceptance_execution_timeout_seconds: int | None = None,
        acceptance_launch_timeout_seconds: int | None = None,
        acceptance_wait_timeout_seconds: int | None = None,
        root_prefix: Sequence[str] | None = None,
        canonical_repo: Path | None = None,
    ) -> delivery.Delivery:
        return delivery.Delivery(
            repo=ROOT,
            run_root=self.root / "run",
            release_root=Path("/opt/devcoordinator/releases"),
            transaction_root=self.root / "transaction",
            plan=selected_plan or plan(),
            executor=executor or FakeExecutor(),
            root_prefix=[] if root_prefix is None else root_prefix,
            max_parallel=4,
            acceptance_execution_timeout_seconds=acceptance_execution_timeout_seconds,
            acceptance_launch_timeout_seconds=acceptance_launch_timeout_seconds,
            acceptance_wait_timeout_seconds=acceptance_wait_timeout_seconds,
            canonical_repo=canonical_repo,
        )

    def test_source_batch_runs_every_check_and_aggregates_findings(self) -> None:
        executor = FakeExecutor({"diff-check": 1, "advisory-failure": 1})
        subject = self.subject(executor=executor)
        results = subject.source_check()
        self.assertEqual(len(results), 12)
        self.assertEqual(
            {FakeExecutor.name(call) for call in executor.calls},
            {
                "diff-check",
                "delivery-self-test",
                "codex-test-access-self-test",
                "same-schema-switch-self-test",
                "fast-repository-validation",
                "console-tests",
                "broker-authority",
                "resources-storage",
                "runtime-lifecycle",
                "universal-harness",
                "advisory-failure",
                "source-pass",
            },
        )
        self.assertTrue(subject._blocking_failed(results))
        report = subject.report()
        self.assertEqual(report["counts"]["failures"], 2)
        self.assertEqual(report["counts"]["blocking_failures"], 1)
        self.assertTrue(subject.events_path.read_text(encoding="utf-8").endswith("\n"))
        self.assertTrue(subject.text_log_path.read_text(encoding="utf-8").endswith("\n"))

    def test_production_plan_has_no_repository_specific_acceptance(self) -> None:
        production = delivery.load_plan(ROOT / "deploy/software-owned-delivery.json")
        self.assertEqual(
            [item["name"] for item in production["acceptance_setup"]],
            ["production-browser-session"],
        )
        setup_argv = production["acceptance_setup"][0]["argv"]
        self.assertIn("{caller_uid}", setup_argv)
        self.assertIn("{caller_gid}", setup_argv)
        encoded = json.dumps(production["acceptance"], sort_keys=True)
        self.assertNotIn("/home/holyglory/", encoded)
        self.assertNotIn("first-use-development-server", encoded)
        self.assertIn("{canonical_repo}", encoded)
        self.assertNotIn('"{repo}"', encoded)

    def test_same_schema_commands_use_one_release_scoped_transaction(self) -> None:
        executor = FakeExecutor()
        subject = self.subject(executor=executor, selected_plan=reset_plan())

        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        results = subject.deploy_same_schema()
        subject._rollback(reset_plan()["same_schema"]["rollback"])

        self.assertTrue(all(item.ok for item in results))
        switch_calls = [
            call
            for call in executor.calls
            if any(Path(value).name == "devcoordinator-same-schema-switch" for value in call)
        ]
        self.assertEqual(len(switch_calls), 4)
        expected = str(self.root / "transaction" / DIGEST)
        for call in switch_calls:
            self.assertEqual(call[call.index("--transaction-root") + 1], expected)

    def test_browser_storage_handoff_requires_exact_caller_owned_private_json(self) -> None:
        storage = self.root / "storage-state.json"
        storage.write_text('{"cookies":[],"origins":[]}\n', encoding="utf-8")
        storage.chmod(0o600)
        self.assertEqual(
            console_acceptance.validated_storage_state(storage), storage.absolute()
        )
        storage.chmod(0o644)
        with self.assertRaisesRegex(
            console_acceptance.AcceptanceError, "mode 0600"
        ):
            console_acceptance.validated_storage_state(storage)
        storage.chmod(0o600)
        link = self.root / "storage-link.json"
        link.symlink_to(storage)
        with self.assertRaisesRegex(
            console_acceptance.AcceptanceError, "non-symlink"
        ):
            console_acceptance.validated_storage_state(link)

    def test_browser_storage_handoff_is_consumed_after_preflight_failure(self) -> None:
        release = self.root / DIGEST
        release.mkdir()
        storage = self.root / "consumed-storage-state.json"
        storage.write_text('{"cookies":[],"origins":[]}\n', encoding="utf-8")
        storage.chmod(0o600)
        with self.assertRaises(console_acceptance.AcceptanceError):
            console_acceptance.run(
                [
                    "--release",
                    str(release),
                    "--runtime-lock",
                    str(self.root / "missing-runtime-lock.json"),
                    "--storage-state",
                    str(storage),
                    "--consume-storage-state",
                    "--output-dir",
                    str(self.root / "acceptance-output"),
                ]
            )
        self.assertFalse(storage.exists())

    def test_package_has_no_source_ownership_approval_arguments(self) -> None:
        executor = FakeExecutor()
        subject = self.subject(executor=executor)
        results = subject.package()
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(
            [FakeExecutor.name(call) for call in executor.calls],
            ["release-plan", "release-stage", "release-verify"],
        )
        stage = executor.calls[1]
        self.assertFalse(any(value.startswith("--approve-source-") for value in stage))
        self.assertEqual(subject.state["release"]["digest"], DIGEST)

    def test_apply_failure_runs_complete_rollback_and_skips_health(self) -> None:
        executor = FakeExecutor({"apply-two": 1, "rollback-one": 1})
        subject = self.subject(executor=executor)
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        results = subject.deploy_same_schema()
        names = [FakeExecutor.name(call) for call in executor.calls]
        self.assertEqual(
            names,
            [
                "prepare-one",
                "prepare-two",
                "apply-one",
                "apply-two",
                "rollback-one",
                "rollback-two",
            ],
        )
        self.assertEqual(subject.state["deployment"]["status"], "rollback-incomplete")
        self.assertEqual(sum(not result.ok for result in results), 2)

    def test_health_batch_finishes_then_rolls_back(self) -> None:
        executor = FakeExecutor({"health-one": 1, "health-two": 1})
        subject = self.subject(executor=executor)
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        subject.deploy_same_schema()
        names = [FakeExecutor.name(call) for call in executor.calls]
        self.assertIn("health-one", names)
        self.assertIn("health-two", names)
        self.assertLess(names.index("health-one"), names.index("rollback-one"))
        self.assertLess(names.index("health-two"), names.index("rollback-one"))
        self.assertEqual(subject.state["deployment"]["status"], "rolled-back-after-health-failure")

    def test_same_schema_default_never_requests_test_history_reset(self) -> None:
        executor = FakeExecutor()
        subject = self.subject(executor=executor, selected_plan=reset_plan())
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        results = subject.deploy_same_schema()
        self.assertTrue(all(result.ok for result in results))
        self.assertTrue(
            all("--reset-test-history" not in call for call in executor.calls)
        )
        self.assertFalse(subject.state["deployment"]["test_history_reset"])

    def test_opt_in_test_history_reset_reaches_every_switch_phase(self) -> None:
        executor = FakeExecutor()
        subject = self.subject(executor=executor, selected_plan=reset_plan())
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        results = subject.deploy_same_schema(reset_test_history=True)
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(
            [FakeExecutor.name(call) for call in executor.calls],
            ["prepare", "apply", "verify"],
        )
        self.assertTrue(
            all(call.count("--reset-test-history") == 1 for call in executor.calls)
        )
        self.assertTrue(subject.state["deployment"]["test_history_reset"])

    def test_test_history_reset_rollback_keeps_explicit_flag(self) -> None:
        executor = FakeExecutor({"apply": 1})
        subject = self.subject(executor=executor, selected_plan=reset_plan())
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        subject.deploy_same_schema(reset_test_history=True)
        self.assertEqual(
            [FakeExecutor.name(call) for call in executor.calls],
            ["prepare", "apply", "rollback"],
        )
        self.assertTrue(
            all(call.count("--reset-test-history") == 1 for call in executor.calls)
        )

    def test_reset_test_history_flag_is_scoped_to_deploy_and_run(self) -> None:
        deploy_args = delivery.parser().parse_args(
            ["deploy", "--run-root", str(self.root), "--reset-test-history"]
        )
        run_args = delivery.parser().parse_args(
            [
                "run",
                "--run-root",
                str(self.root),
                "--reset-test-history",
                "--acceptance-execution-timeout-seconds",
                "41",
                "--acceptance-launch-timeout-seconds",
                "43",
                "--acceptance-wait-timeout-seconds",
                "47",
            ]
        )
        self.assertTrue(deploy_args.reset_test_history)
        self.assertTrue(run_args.reset_test_history)
        source_args = delivery.parser().parse_args(
            ["source-check", "--run-root", str(self.root)]
        )
        self.assertFalse(hasattr(source_args, "reset_test_history"))

    def test_acceptance_threads_caller_defined_runner_timeouts(self) -> None:
        selected_plan = plan()
        selected_plan["acceptance_setup"] = []
        selected_plan["acceptance"] = [
            {
                "name": "runner-probe",
                "argv": [
                    "fixture",
                    "--execution-timeout-seconds",
                    "{acceptance_execution_timeout_seconds}",
                    "--launch-timeout-seconds",
                    "{acceptance_launch_timeout_seconds}",
                    "--wait-timeout-seconds",
                    "{acceptance_wait_timeout_seconds}",
                ],
                "blocking": True,
            }
        ]
        executor = FakeExecutor()
        subject = self.subject(
            executor=executor,
            selected_plan=selected_plan,
            acceptance_execution_timeout_seconds=41,
            acceptance_launch_timeout_seconds=43,
            acceptance_wait_timeout_seconds=47,
        )
        result = subject.acceptance()
        self.assertTrue(result[0].ok)
        self.assertEqual(
            executor.calls,
            [
                [
                    "fixture",
                    "--execution-timeout-seconds",
                    "41",
                    "--launch-timeout-seconds",
                    "43",
                    "--wait-timeout-seconds",
                    "47",
                ]
            ],
        )

    def test_acceptance_distinguishes_source_and_canonical_repository(self) -> None:
        selected_plan = plan()
        selected_plan["acceptance_setup"] = []
        selected_plan["acceptance"] = [
            {
                "name": "repository-scope",
                "argv": ["fixture", "{repo}", "{canonical_repo}"],
                "blocking": True,
            }
        ]
        canonical = self.root / "canonical-repository"
        executor = FakeExecutor()
        subject = self.subject(
            executor=executor,
            selected_plan=selected_plan,
            canonical_repo=canonical,
        )

        result = subject.acceptance()

        self.assertTrue(result[0].ok)
        self.assertEqual(
            executor.calls,
            [["fixture", str(ROOT.resolve()), str(canonical.resolve())]],
        )

    def test_acceptance_runs_as_actual_caller_not_privileged_prefix(self) -> None:
        executor = FakeExecutor()
        subject = self.subject(
            executor=executor,
            root_prefix=["sudo-fixture", "--"],
        )
        results = subject.acceptance()
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(executor.calls[0][:2], ["sudo-fixture", "--"])
        self.assertTrue(
            all(call[:2] != ["sudo-fixture", "--"] for call in executor.calls[1:]),
            "agent-facing acceptance was executed as the privileged installer",
        )

    def test_acceptance_requires_all_three_timeouts_from_the_caller(self) -> None:
        with self.assertRaises(SystemExit):
            delivery.parser().parse_args(
                ["acceptance", "--run-root", str(self.root)]
            )

    def test_acceptance_runs_all_checks_after_multiple_failures(self) -> None:
        executor = FakeExecutor({"acceptance-one": 1, "acceptance-three": 1})
        subject = self.subject(executor=executor)
        results = subject.acceptance()
        self.assertEqual(
            [FakeExecutor.name(call) for call in executor.calls],
            [
                "acceptance-session",
                "acceptance-one",
                "acceptance-two",
                "acceptance-three",
            ],
        )
        self.assertEqual(sum(not result.ok for result in results), 2)
        report = subject.report()
        self.assertEqual(report["conclusion"], "failed")
        self.assertEqual(report["counts"]["acceptance_failures"], 2)

    def test_reset_inherits_every_setting_and_changes_only_release_paths(self) -> None:
        subject = self.subject()
        subject.state["release"] = {
            "digest": DIGEST,
            "path": f"/opt/devcoordinator/releases/{DIGEST}",
        }
        template = {
            "schema_version": 1,
            "kind": "devcoordinator-clean-adoption",
            "release": f"/opt/devcoordinator/releases/{'b' * 64}",
            "rendered_units": "/old/rendered",
            "candidate_slot_source": "/old/slot.env",
            "console_state_files": [
                "routes.json",
                "upstream-auth.json",
                "access-control.json",
                "telegram-control.json",
            ],
            "settings_sentinel": {"gmail": ["developer@example.test"]},
        }
        source = self.root / "template.json"
        source.write_text(json.dumps(template), encoding="utf-8")
        output = subject._reset_manifest(source)
        patched = delivery.read_json(output)
        changed = {
            key for key in template if patched.get(key) != template.get(key)
        }
        self.assertEqual(
            changed, {"release", "rendered_units", "candidate_slot_source"}
        )
        self.assertEqual(patched["settings_sentinel"], template["settings_sentinel"])

    def test_plan_rejects_missing_rollback_or_health(self) -> None:
        value = plan()
        value["same_schema"]["rollback"] = []
        with self.assertRaises(delivery.DeliveryError):
            delivery.validate_plan(value)
        value = plan()
        value["same_schema"]["health"] = []
        with self.assertRaises(delivery.DeliveryError):
            delivery.validate_plan(value)

    def test_report_can_be_rebuilt_from_durable_state_after_interruption(self) -> None:
        subject = self.subject()
        subject.run_step(
            phase="fixture",
            name="completed-step",
            argv=["fixture", "completed-step"],
            blocking=True,
        )
        self.assertFalse(subject.report_path.exists())
        self.assertEqual(
            delivery.main(["report", "--run-root", str(subject.run_root)]),
            0,
        )
        rebuilt = delivery.read_json(subject.report_path)
        self.assertEqual(rebuilt["counts"]["steps"], 1)

    def test_run_root_lock_rejects_overlapping_delivery_controller(self) -> None:
        run_root = self.root / "single-flight-run"
        with delivery.exclusive_run_root(run_root):
            with self.assertRaisesRegex(
                delivery.DeliveryError,
                "another software-owned delivery is active",
            ):
                with delivery.exclusive_run_root(run_root):
                    self.fail("overlapping delivery acquired the same run root")
        with delivery.exclusive_run_root(run_root):
            self.assertEqual((run_root / "delivery.lock").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
