from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator import universal_test_cli
from devcoordinator.universal_test_cli import (
    UniversalTestCliError,
    add_universal_test_cli_parser,
    handle_universal_test_cli,
    initialize_manifest,
    manifest_health,
    test_catalog as read_test_catalog,
)


PLAN_OPERATION_ID = "00000000-0000-4000-8000-00000000000f"
MUTATION_OPERATION_ID = "00000000-0000-4000-8000-000000000003"
REPOSITORY_ID = "repo-00000000-0000-4000-8000-000000000001"
RUN_REPOSITORY_ARGS = ("--repository-id", REPOSITORY_ID)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="group", required=True)
    add_universal_test_cli_parser(subparsers)
    return root


def subparser_choices(value: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in value._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    raise AssertionError("parser has no subcommands")


class RecordingBroker:
    METHODS = frozenset(
        {
            "preview_test_plan",
            "submit_test_plan",
            "test_run_status",
            "test_run_summary",
            "test_run_failures",
            "test_run_cases",
            "test_artifact",
            "cancel_test_run",
            "retry_test_run",
            "wait_test_run",
            "check_test_evidence",
            "consume_test_evidence",
            "test_repository_catalog",
            "test_repository_setup",
            "test_statistics",
        }
    )

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.resolve_calls: list[str] = []
        self.replies: dict[str, dict[str, object]] = {}

    def repository(self, _root: str) -> SimpleNamespace:
        return SimpleNamespace(repo_id=REPOSITORY_ID)

    def resolve_repository(self, root: str) -> SimpleNamespace:
        self.resolve_calls.append(root)
        return SimpleNamespace(repo_id=REPOSITORY_ID, canonical_root=root)

    def __getattr__(self, name: str):
        if name not in self.METHODS:
            raise AttributeError(name)

        def call(**arguments: object) -> dict[str, object]:
            self.calls.append((name, dict(arguments)))
            return self.replies.get(
                name,
                {
                    "schema_version": 1,
                    "ok": True,
                    "method": name,
                    **arguments,
                },
            )

        return call


class UniversalTestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def handle(self, raw: list[str], profile: object) -> dict[str, object]:
        return handle_universal_test_cli(
            parser().parse_args(raw),
            canonical_project=lambda value: value,
            broker_profile_loader=lambda: profile,
        )

    def test_parser_preserves_complete_advanced_command_grammar(self) -> None:
        root_choices = subparser_choices(parser())
        test_choices = subparser_choices(root_choices["test"])
        self.assertEqual(
            set(test_choices),
            {
                "manifest",
                "plan",
                "submit",
                "status",
                "summary",
                "failures",
                "cases",
                "artifact",
                "cancel",
                "retry",
                "policy",
                "catalog",
                "stats",
                "wait",
            },
        )
        self.assertEqual(
            set(subparser_choices(test_choices["manifest"])),
            {"init", "validate", "doctor"},
        )
        planned = parser().parse_args(
            [
                "test",
                "plan",
                "--agent",
                "codex:test",
                "--root-repo",
                str(self.root),
                "--no-temporary-repo",
                "--operation-id",
                PLAN_OPERATION_ID,
                "--intent",
                "change",
                "--change",
                "modified:source.py",
                "--full",
            ]
        )
        self.assertEqual(planned.change, ["modified:source.py"])
        self.assertTrue(planned.full)

    def test_manifest_init_validate_and_doctor_remain_local(self) -> None:
        created = initialize_manifest(self.root, force=False)
        self.assertTrue(created["created"])
        self.assertTrue(created["ok"])
        self.assertEqual(manifest_health(self.root, doctor=False)["status"], "ready")
        with self.assertRaisesRegex(UniversalTestCliError, "already exists"):
            initialize_manifest(self.root, force=False)
        doctor = self.handle(
            ["test", "manifest", "doctor", "--root-repo", str(self.root)],
            profile=object(),
        )
        self.assertEqual(doctor["status"], "ready")
        self.assertIn("warning_count", doctor)

    def test_manifest_health_distinguishes_missing_and_invalid(self) -> None:
        missing = manifest_health(self.root, doctor=False)
        self.assertEqual(missing["status"], "missing")
        manifest = self.root / ".codex" / "tests.json"
        manifest.parent.mkdir()
        manifest.write_text("{}", encoding="utf-8")
        invalid = manifest_health(self.root, doctor=False)
        self.assertEqual(invalid["status"], "invalid")

    def test_plan_is_one_protected_preview_call(self) -> None:
        profile = RecordingBroker()
        expected = {
            "schema_version": 1,
            "ok": True,
            "plan_id": "plan-protected",
            "source": "protected",
        }
        profile.replies["preview_test_plan"] = expected
        with mock.patch.object(
            universal_test_cli,
            "load_test_manifest",
            side_effect=AssertionError("client must not load the manifest for planning"),
        ):
            result = self.handle(
                [
                    "test",
                    "plan",
                    "--agent",
                    "codex:test",
                    "--root-repo",
                    str(self.root),
                    "--no-temporary-repo",
                    "--operation-id",
                    PLAN_OPERATION_ID,
                    "--intent",
                    "release",
                    "--execution-timeout-seconds",
                    "120",
                    "--launch-timeout-seconds",
                    "45",
                ],
                profile,
            )
        self.assertEqual(result, expected)
        self.assertEqual(
            profile.calls,
            [
                (
                    "preview_test_plan",
                    {
                        "repository": REPOSITORY_ID,
                        "intent": "release",
                        "temporary_root": None,
                        "requested_targets": (),
                        "execution_timeout_seconds": 120,
                        "launch_timeout_seconds": 45,
                        "operation_id": PLAN_OPERATION_ID,
                    },
                )
            ],
        )

    def test_plan_rejects_change_before_loading_broker(self) -> None:
        parsed = parser().parse_args(
            [
                "test",
                "plan",
                "--agent",
                "codex:test",
                "--root-repo",
                str(self.root),
                "--no-temporary-repo",
                "--operation-id",
                PLAN_OPERATION_ID,
                "--intent",
                "change",
                "--change",
                "modified:source.py",
            ]
        )
        loader = mock.Mock(side_effect=AssertionError("broker must not be loaded"))
        with self.assertRaisesRegex(UniversalTestCliError, "omit --change"):
            handle_universal_test_cli(
                parsed,
                canonical_project=lambda value: value,
                broker_profile_loader=loader,
            )
        loader.assert_not_called()

    def test_plan_and_run_actions_have_no_broker_optional_fallback(self) -> None:
        planned = parser().parse_args(
            [
                "test",
                "plan",
                "--agent",
                "codex:test",
                "--root-repo",
                str(self.root),
                "--no-temporary-repo",
                "--operation-id",
                PLAN_OPERATION_ID,
                "--intent",
                "change",
            ]
        )
        for parsed in (
            planned,
            parser().parse_args(
                ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "run-1"]
            ),
        ):
            with self.subTest(action=parsed.action), self.assertRaisesRegex(
                UniversalTestCliError,
                "protected broker profile is unavailable or invalid",
            ):
                handle_universal_test_cli(
                    parsed,
                    canonical_project=lambda value: value,
                    broker_profile_loader=lambda: None,
                )

    def test_broker_loader_failure_does_not_expose_private_detail(self) -> None:
        parsed = parser().parse_args(
            ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "run-1"]
        )
        with self.assertRaises(UniversalTestCliError) as raised:
            handle_universal_test_cli(
                parsed,
                canonical_project=lambda value: value,
                broker_profile_loader=lambda: (_ for _ in ()).throw(
                    RuntimeError("credential=do-not-print")
                ),
            )
        self.assertNotIn("credential", str(raised.exception))

    def test_execution_and_read_commands_dispatch_exact_broker_arguments(self) -> None:
        cases = (
            (
                ["test", "submit", *RUN_REPOSITORY_ARGS, "--plan-id", "plan-1", "--operation-id", MUTATION_OPERATION_ID],
                "submit_test_plan",
                {"repository": REPOSITORY_ID, "plan_id": "plan-1", "operation_id": MUTATION_OPERATION_ID, "actor": "codex:test-cli-task"},
            ),
            (
                ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "run-1"],
                "test_run_status",
                {"repository": REPOSITORY_ID, "run_id": "run-1"},
            ),
            (
                ["test", "summary", *RUN_REPOSITORY_ARGS, "--run-id", "run-1"],
                "test_run_summary",
                {"repository": REPOSITORY_ID, "run_id": "run-1"},
            ),
            (
                ["test", "failures", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--after", "failure-2", "--limit", "3"],
                "test_run_failures",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "after": "failure-2", "limit": 3},
            ),
            (
                ["test", "cases", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--after", "7", "--limit", "3"],
                "test_run_cases",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "after": 7, "limit": 3},
            ),
            (
                ["test", "artifact", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--artifact-id", "artifact-1"],
                "test_artifact",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "artifact_id": "artifact-1"},
            ),
            (
                ["test", "cancel", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--reason", "obsolete", "--operation-id", MUTATION_OPERATION_ID],
                "cancel_test_run",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "reason": "obsolete", "operation_id": MUTATION_OPERATION_ID, "actor": "codex:test-cli-task"},
            ),
            (
                ["test", "retry", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--failed-only", "--operation-id", MUTATION_OPERATION_ID],
                "retry_test_run",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "failed_only": True, "operation_id": MUTATION_OPERATION_ID, "actor": "codex:test-cli-task"},
            ),
            (
                ["test", "wait", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--timeout-seconds", "15"],
                "wait_test_run",
                {"repository": REPOSITORY_ID, "run_id": "run-1", "timeout_seconds": 15},
            ),
        )
        for raw, expected_method, expected_arguments in cases:
            with self.subTest(action=raw[1]):
                profile = RecordingBroker()
                with mock.patch.dict(
                    os.environ, {"CODEX_THREAD_ID": "test-cli-task"}, clear=False
                ):
                    result = self.handle(raw, profile)
                self.assertTrue(result["ok"])
                self.assertEqual(profile.calls, [(expected_method, expected_arguments)])

    def test_failure_and_case_pages_are_not_independently_trimmed(self) -> None:
        for action, method, collection in (
            ("failures", "test_run_failures", "failures"),
            ("cases", "test_run_cases", "cases"),
        ):
            with self.subTest(action=action):
                profile = RecordingBroker()
                page = {
                    "schema_version": 1,
                    "ok": True,
                    collection: [
                        {"identity": index, "detail": "x" * 2048}
                        for index in range(25)
                    ],
                    "next_cursor": None,
                }
                profile.replies[method] = page
                raw = [
                    "test",
                    action,
                    *RUN_REPOSITORY_ARGS,
                    "--run-id",
                    "run-1",
                    "--limit",
                    "25",
                ]
                result = self.handle(raw, profile)
                self.assertEqual(result, page)
                self.assertEqual(len(result[collection]), 25)

    def test_catalog_uses_only_broker_owned_reads(self) -> None:
        profile = RecordingBroker()
        profile.replies["test_repository_catalog"] = {
            "schema_version": 1,
            "ok": True,
            "repositories": [],
        }
        self.assertEqual(
            read_test_catalog(None, profile),
            profile.replies["test_repository_catalog"],
        )
        self.assertEqual(profile.calls, [("test_repository_catalog", {})])

        profile = RecordingBroker()
        result = read_test_catalog(self.root, profile)
        self.assertTrue(result["ok"])
        self.assertEqual(
            profile.calls,
            [("test_repository_setup", {"repository": REPOSITORY_ID})],
        )

    def test_stats_is_one_repository_bound_broker_read(self) -> None:
        profile = RecordingBroker()
        result = self.handle(
            [
                "test",
                "stats",
                "--root-repo",
                str(self.root),
                "--days",
                "90",
                "--limit",
                "40",
            ],
            profile,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            profile.calls,
            [
                (
                    "test_statistics",
                    {"repository": REPOSITORY_ID, "days": 90, "limit": 40},
                )
            ],
        )

    def test_policy_check_and_consumption_are_broker_owned(self) -> None:
        for operation_id, method in (
            (None, "check_test_evidence"),
            (MUTATION_OPERATION_ID, "consume_test_evidence"),
        ):
            with self.subTest(method=method):
                profile = RecordingBroker()
                raw = [
                    "test",
                    "policy",
                    "check",
                    "--root-repo",
                    str(self.root),
                    "--policy",
                    "release",
                    "--snapshot",
                    "snapshot-1",
                ]
                if operation_id is not None:
                    raw.extend(("--operation-id", operation_id))
                with mock.patch.object(
                    universal_test_cli,
                    "load_test_manifest",
                    side_effect=AssertionError("policy must be resolved by testd"),
                ):
                    result = self.handle(raw, profile)
                self.assertTrue(result["ok"])
                expected = {
                    "repository": REPOSITORY_ID,
                    "policy": "release",
                    "snapshot": "snapshot-1",
                }
                if operation_id is not None:
                    expected["operation_id"] = operation_id
                self.assertEqual(profile.calls, [(method, expected)])

    def test_canonical_root_continuations_resolve_current_authority_identity(self) -> None:
        profile = RecordingBroker()
        result = self.handle(
            [
                "test",
                "status",
                "--root-repo",
                str(self.root),
                "--run-id",
                "run-1",
            ],
            profile,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(profile.resolve_calls, [str(self.root)])
        self.assertEqual(
            profile.calls,
            [("test_run_status", {"run_id": "run-1", "repository": REPOSITORY_ID})],
        )

    def test_removed_client_authorities_are_not_exported(self) -> None:
        for name in (
            "build_local_plan",
            "discover_changes",
            "_local_repository_id",
            "scheduler_pending",
            "_bounded_failure_page",
            "_bounded_case_page",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(universal_test_cli, name))
        encoded_exports = json.dumps(universal_test_cli.__all__)
        self.assertNotIn("local_plan", encoded_exports)
        self.assertNotIn("scheduler_pending", encoded_exports)


if __name__ == "__main__":
    unittest.main()
