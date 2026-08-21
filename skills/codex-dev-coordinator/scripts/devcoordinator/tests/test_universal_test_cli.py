from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from devcoordinator import broker_profile as broker_profile_module
from devcoordinator.broker import BrokerError
from devcoordinator.universal_test_cli import (
    UniversalTestCliError,
    add_universal_test_cli_parser,
    build_local_plan,
    handle_universal_test_cli,
    initialize_manifest,
    manifest_health,
    scheduler_pending,
    test_catalog as read_test_catalog,
)
from devcoordinator.broker_profile import BrokerClientProfile
from devcoordinator.universal_test_contract import (
    MANIFEST_SCHEMA_VERSION,
    SourceMode,
    load_test_manifest,
)
from devcoordinator.universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    SourceIdentity,
    create_test_plan,
)


PLAN_OPERATION_ID = "00000000-0000-4000-8000-00000000000f"
REPOSITORY_ID = "repo-00000000-0000-4000-8000-000000000001"
RUN_REPOSITORY_ARGS = ("--repository-id", REPOSITORY_ID)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="group", required=True)
    add_universal_test_cli_parser(sub)
    return root


class FakeSchedulerProfile:
    def __init__(self) -> None:
        self.registered_plan_id: str | None = None

    def repository(self, _root: str) -> SimpleNamespace:
        return SimpleNamespace(repo_id="repo-00000000-0000-4000-8000-000000000001")

    def register_test_plan(
        self,
        *,
        plan: object,
        manifest: object,
        actor: str,
        operation_id: str,
    ) -> dict[str, object]:
        del manifest
        self.registered_plan_id = str(getattr(plan, "plan_id"))
        return {
            "plan_id": self.registered_plan_id,
            "actor": actor,
            "operation_id": operation_id,
            "registered": True,
        }

    def submit_test_plan(
        self,
        *,
        repository: str,
        plan_id: str,
        operation_id: str,
        actor: str,
    ) -> dict[str, object]:
        if repository != REPOSITORY_ID or not actor.startswith("codex:"):
            raise AssertionError("submission repository or actor is invalid")
        return {
            "plan_id": plan_id,
            "operation_id": operation_id,
            "run_id": "run-00000000-0000-4000-8000-000000000001",
            "state": "queued",
            "console_path": "#/tests/runs/run-00000000-0000-4000-8000-000000000001",
        }


class OversizedSummaryProfile:
    def test_run_summary(self, *, repository: str, run_id: str) -> dict[str, object]:
        del repository
        return {"run_id": run_id, "detail": "x" * 9000}


class RecordingSchedulerProfile:
    METHODS = frozenset(
        {
            "submit_test_plan",
            "test_run_status",
            "test_run_summary",
            "test_run_failures",
            "test_run_artifacts",
            "test_artifact",
            "cancel_test_run",
            "wait_test_run",
            "check_test_evidence",
            "consume_test_evidence",
        }
    )

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def repository(self, _root: str) -> SimpleNamespace:
        return SimpleNamespace(repo_id=REPOSITORY_ID)

    def __getattr__(self, name: str):
        if name not in self.METHODS:
            raise AttributeError(name)

        def call(**arguments: object) -> dict[str, object]:
            self.calls.append((name, dict(arguments)))
            return {
                "method": name,
                **arguments,
            }

        return call


class SetupCatalogProfile:
    def __init__(self) -> None:
        self.repository_profile = SimpleNamespace(
            repo_id="repo-00000000-0000-4000-8000-000000000008",
            canonical_root="/home/example/project",
            enabled=True,
        )
        self.repositories = {self.repository_profile.repo_id: self.repository_profile}
        self.calls: list[str] = []

    def repository(self, root: str) -> SimpleNamespace:
        if root != self.repository_profile.canonical_root:
            raise KeyError(root)
        return self.repository_profile

    def test_repository_setup(self, *, repository: str) -> dict[str, object]:
        self.calls.append(repository)
        return {
            "repository_id": repository,
            "status": "missing",
            "manifest_schema": None,
            "manifest_fingerprint": None,
            "targets": [],
            "target_graph": {},
            "input_coverage": {
                "global_input_count": 0,
                "target_input_count": 0,
                "targets_with_inputs": 0,
            },
            "input_coverage_gaps": [],
            "intents": [],
            "evidence_policies": [],
            "fixtures": [],
            "network_requirements": [],
            "isolation": {
                "network": "none",
                "private_scratch": True,
                "kill_after_run": True,
            },
            "issues": [
                {
                    "code": "manifest_missing",
                    "message": "repository test manifest is missing",
                }
            ],
        }


class ReadySetupCatalogProfile(SetupCatalogProfile):
    def test_repository_setup(self, *, repository: str) -> dict[str, object]:
        self.calls.append(repository)
        target = {
            "name": "unit",
            "driver": "automation",
            "reporter": "jsonl",
            "network": "none",
            "fixtures": [],
            "credentials": [],
            "depends_on": [],
        }
        return {
            "repository_id": repository,
            "status": "ready",
            "manifest_schema": 2,
            "manifest_fingerprint": "a" * 64,
            "targets": [target],
            "target_graph": {"unit": []},
            "input_coverage": {
                "global_input_count": 1,
                "target_input_count": 1,
                "targets_with_inputs": 1,
            },
            "input_coverage_gaps": [],
            "intents": ["manual"],
            "evidence_policies": [],
            "fixtures": [],
            "network_requirements": [],
            "isolation": {
                "network": "none",
                "private_scratch": True,
                "kill_after_run": True,
            },
            "issues": [],
        }


class OversizedCatalogProfile:
    def __init__(self) -> None:
        self.repositories = {
            f"repo-{index:064d}": SimpleNamespace(
                repo_id=f"repo-{index:064d}",
                canonical_root=f"/srv/repositories/project-{index:03d}",
                enabled=True,
            )
            for index in range(80)
        }

    def test_repository_setup(self, *, repository: str) -> dict[str, object]:
        index = int(repository.removeprefix("repo-"))
        status = ("ready", "missing", "invalid")[index % 3]
        return {
            "repository_id": repository,
            "status": status,
            "manifest_schema": 1 if status == "ready" else None,
            "manifest_fingerprint": "a" * 64 if status == "ready" else None,
            "targets": [
                {
                    "name": f"target-{item:03d}",
                    "driver": "automation",
                    "reporter": "jsonl",
                    "network": "none",
                    "fixtures": [],
                    "credentials": [],
                    "depends_on": [],
                }
                for item in range(40)
            ],
            "target_graph": {},
            "input_coverage": {},
            "input_coverage_gaps": [],
            "intents": ["change", "handoff", "release"],
            "evidence_policies": ["handoff", "release"],
            "fixtures": [],
            "network_requirements": [],
            "isolation": {},
            "issues": [
                {
                    "severity": "error" if status != "ready" else "info",
                    "code": "manifest_state",
                    "message": "unsafe\x00\n" + ("detail " * 2_000),
                }
            ],
        }


class DynamicSetupCatalogProfile(SetupCatalogProfile):
    def __init__(self, root: Path) -> None:
        super().__init__()
        self.repository_profile = SimpleNamespace(
            repo_id="repo-00000000-0000-4000-8000-000000000008",
            canonical_root=str(root.resolve()),
            enabled=True,
        )
        self.repositories = {}
        self.resolve_calls: list[str] = []

    def repository(self, _root: str) -> SimpleNamespace:
        raise KeyError("static installed profile is intentionally stale")

    def resolve_repository(self, root: str) -> SimpleNamespace | None:
        self.resolve_calls.append(root)
        if root != self.repository_profile.canonical_root:
            return None
        return self.repository_profile


class ImmutablePreviewProfile:
    repository_id = "repo-00000000-0000-4000-8000-000000000009"

    def __init__(self, root: Path, *, contradictory_root: bool = False) -> None:
        self.root = root
        self.contradictory_root = contradictory_root

    def repository(self, _root: str) -> SimpleNamespace:
        return SimpleNamespace(repo_id=self.repository_id)

    def preview_test_plan(
        self,
        *,
        repository: str,
        intent: str,
        temporary_root: str | None = None,
        requested_targets=(),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = 300,
        operation_id: str,
    ) -> dict[str, object]:
        manifest = load_test_manifest(self.root)
        source = SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id=repository,
            content_fingerprint="a" * 64,
            original_root=("/wrong/root" if self.contradictory_root else str(self.root)),
            temporary_root=temporary_root,
            snapshot_id="snapshot-00000000-0000-4000-8000-000000000009",
        )
        selected = create_test_plan(
            manifest,
            intent=intent,
            source=source,
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
        )
        return {
            "plan": selected.to_document(),
            "registered": True,
            "operation_id": operation_id,
        }


class DynamicImmutablePreviewProfile(ImmutablePreviewProfile):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.resolve_calls: list[str] = []

    def repository(self, _root: str) -> SimpleNamespace:
        raise KeyError("static installed profile is intentionally stale")

    def resolve_repository(self, root: str) -> SimpleNamespace | None:
        self.resolve_calls.append(root)
        if root != str(self.root.resolve()):
            return None
        return SimpleNamespace(repo_id=self.repository_id)


class LivePreviewProfile:
    repository_id = "repo-00000000-0000-4000-8000-000000000011"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = load_test_manifest(root)
        self.calls: list[dict[str, object]] = []

    def repository(self, _root: str) -> SimpleNamespace:
        return SimpleNamespace(repo_id=self.repository_id)

    def preview_test_plan(
        self,
        *,
        repository: str,
        intent: str,
        temporary_root: str | None = None,
        requested_targets=(),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = 300,
        operation_id: str,
    ) -> dict[str, object]:
        arguments = {
            "repository": repository,
            "intent": intent,
            "temporary_root": temporary_root,
            "requested_targets": tuple(requested_targets),
            "execution_timeout_seconds": execution_timeout_seconds,
            "launch_timeout_seconds": launch_timeout_seconds,
            "operation_id": operation_id,
        }
        self.calls.append(arguments)
        source = SourceIdentity(
            mode=SourceMode.LIVE,
            repository_id=repository,
            content_fingerprint="b" * 64,
            original_root=str(self.root),
            temporary_root=temporary_root,
        )
        selected = create_test_plan(
            self.manifest,
            intent=intent,
            source=source,
            changes=(ChangedPath("source.py", ChangeStatus.MODIFIED),),
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
        )
        return {
            "plan": selected.to_document(),
            "registered": True,
            "operation_id": operation_id,
        }


class UnavailablePreviewProfile(FakeSchedulerProfile):
    def __init__(self) -> None:
        super().__init__()
        self.preview_calls = 0

    def preview_test_plan(self, **_arguments: object) -> dict[str, object]:
        self.preview_calls += 1
        raise NotImplementedError


class FailedWaitProfile:
    wait_test_run = BrokerClientProfile.wait_test_run

    def __init__(self) -> None:
        self.reads = 0

    def test_run_status(
        self,
        *,
        repository: str,
        run_id: str,
        transport_timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        del transport_timeout_seconds
        self.reads += 1
        return {"repository_id": repository, "run_id": run_id, "state": "failed"}


class UniversalTestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> None:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))

    def _committed_repository(self) -> None:
        initialize_manifest(self.root, force=False)
        scripts = self.root / "scripts"
        scripts.mkdir()
        executable = scripts / "test"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        source = self.root / "source.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        self._git("init", "--quiet")
        self._git("config", "user.email", "tests@example.invalid")
        self._git("config", "user.name", "Tests")
        self._git("add", ".")
        self._git("commit", "--quiet", "-m", "initial")

    def test_parser_exposes_complete_nonblocking_surface(self) -> None:
        expected = {
            "manifest",
            "plan",
            "submit",
            "status",
            "summary",
            "failures",
            "artifact",
            "cancel",
            "catalog",
            "wait",
        }
        choices = parser()._subparsers._group_actions[0].choices[  # type: ignore[union-attr]
            "test"
        ]._subparsers._group_actions[0].choices
        self.assertEqual(set(choices), expected)

        parsed = parser().parse_args(
            [
                "test",
                "plan",
                "--agent",
                "codex",
                "--root-repo",
                str(self.root),
                "--no-temporary-repo",
                "--intent",
                "change",
                "--operation-id",
                PLAN_OPERATION_ID,
            ]
        )
        self.assertTrue(parsed.no_temporary_repo)
        self.assertIsNone(parsed.execution_timeout_seconds)
        self.assertEqual(parsed.launch_timeout_seconds, 300)
        explicit_timeouts = parser().parse_args(
            [
                "test",
                "plan",
                "--agent",
                "codex",
                "--root-repo",
                str(self.root),
                "--no-temporary-repo",
                "--intent",
                "change",
                "--execution-timeout-seconds",
                "86400",
                "--launch-timeout-seconds",
                "3600",
                "--operation-id",
                PLAN_OPERATION_ID,
            ]
        )
        self.assertEqual(explicit_timeouts.execution_timeout_seconds, 86_400)
        self.assertEqual(explicit_timeouts.launch_timeout_seconds, 3_600)
        with self.assertRaises(SystemExit):
            parser().parse_args(
                [
                    "test",
                    "plan",
                    "--agent",
                    "codex",
                    "--root-repo",
                    str(self.root),
                    "--intent",
                    "change",
                    "--operation-id",
                    PLAN_OPERATION_ID,
                ]
            )
        artifact = parser().parse_args(
            [
                "test",
                "artifact",
                *RUN_REPOSITORY_ARGS,
                "--run-id",
                "run-1",
                "--artifact-id",
                "artifact-20",
            ]
        )
        self.assertEqual(artifact.artifact_id, "artifact-20")
        with self.assertRaises(SystemExit):
            parser().parse_args(
                ["test", "failures", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--limit", "51"]
            )
        with self.assertRaises(SystemExit):
            parser().parse_args(
                ["test", "wait", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--timeout-seconds", "86401"]
            )
        longest_wait = parser().parse_args(
            ["test", "wait", *RUN_REPOSITORY_ARGS, "--run-id", "run-1", "--timeout-seconds", "86400"]
        )
        self.assertEqual(longest_wait.timeout_seconds, 86_400)
        with self.assertRaises(SystemExit):
            parser().parse_args(["test", "run"])

    def test_parser_matches_broker_identity_reason_and_agent_bounds(self) -> None:
        parsed = parser().parse_args(
            [
                "test",
                "cancel",
                *RUN_REPOSITORY_ARGS,
                "--run-id",
                "run-abc_123",
                "--reason",
                "  no longer needed  ",
                "--operation-id",
                "00000000-0000-4000-8000-000000000001",
            ]
        )
        self.assertEqual(parsed.reason, "no longer needed")
        with self.assertRaises(SystemExit):
            parser().parse_args(
                ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "run/looks/like/a/path"]
            )
        with self.assertRaises(SystemExit):
            parser().parse_args(
                ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "r" * 129]
            )
        with self.assertRaises(SystemExit):
            parser().parse_args(
                [
                    "test",
                    "plan",
                    "--agent",
                    " agent-with-whitespace ",
                    "--root-repo",
                    str(self.root),
                    "--no-temporary-repo",
                    "--intent",
                    "change",
                    "--operation-id",
                    PLAN_OPERATION_ID,
                ]
            )

    def test_every_test_continuation_accepts_exact_id_or_canonical_root(self) -> None:
        test_commands = parser()._subparsers._group_actions[0].choices[  # type: ignore[union-attr]
            "test"
        ]._subparsers._group_actions[0].choices
        for name in (
            "submit",
            "status",
            "summary",
            "failures",
            "artifact",
            "cancel",
            "wait",
        ):
            with self.subTest(command=name):
                option_strings = {
                    option
                    for action in test_commands[name]._actions
                    if action.dest in {"repository", "root_repo"}
                    for option in action.option_strings
                }
                self.assertEqual(option_strings, {"--repository-id", "--root-repo"})

        submit = test_commands["submit"]
        with self.assertRaises(SystemExit):
            parser().parse_args(
                [
                    "test",
                    "submit",
                    "--plan-id",
                    "plan-one",
                    "--operation-id",
                    PLAN_OPERATION_ID,
                ]
            )
        parsed = parser().parse_args(
            [
                "test",
                "submit",
                "--root-repo",
                str(self.root),
                "--plan-id",
                "plan-one",
                "--operation-id",
                PLAN_OPERATION_ID,
            ]
        )
        self.assertEqual(parsed.root_repo, str(self.root))
        self.assertIsNone(parsed.repository)
        with self.assertRaises(SystemExit):
            parser().parse_args(
                [
                    "test",
                    "submit",
                    "--repository-id",
                    REPOSITORY_ID,
                    "--root-repo",
                    str(self.root),
                    "--plan-id",
                    "plan-one",
                    "--operation-id",
                    PLAN_OPERATION_ID,
                ]
            )
        self.assertIsNotNone(submit)

    def test_manifest_init_is_atomic_valid_and_non_destructive(self) -> None:
        initialized = initialize_manifest(self.root, force=False)
        self.assertTrue(initialized["ok"])
        self.assertTrue(initialized["created"])
        manifest = load_test_manifest(self.root)
        self.assertEqual(manifest.schema_version, MANIFEST_SCHEMA_VERSION)
        self.assertEqual(sorted(manifest.targets), ["tests"])
        manifest_document = json.loads(
            (self.root / ".codex" / "tests.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("resources", manifest_document["defaults"])
        self.assertNotIn("resources", manifest_document["targets"]["tests"])
        self.assertEqual(
            manifest_document["targets"]["tests"]["retry"],
            {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        )
        self.assertFalse(
            list((self.root / ".codex").glob(".tests.json.*.tmp"))
        )
        with self.assertRaisesRegex(UniversalTestCliError, "already exists"):
            initialize_manifest(self.root, force=False)

    def test_wait_treats_store_failed_state_as_terminal(self) -> None:
        profile = FailedWaitProfile()
        result = profile.wait_test_run(
            repository=REPOSITORY_ID, run_id="run-failed", timeout_seconds=86_400
        )
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("wait_timed_out", result)
        self.assertEqual(profile.reads, 1)

    def test_wait_uses_remaining_caller_deadline_for_status_transport(self) -> None:
        now = [100.0]

        class TimeoutProfile:
            wait_test_run = BrokerClientProfile.wait_test_run

            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def test_run_status(
                self,
                *,
                repository: str,
                run_id: str,
                transport_timeout_seconds: float | None = None,
            ) -> dict[str, object]:
                del repository, run_id
                assert transport_timeout_seconds is not None
                self.timeouts.append(transport_timeout_seconds)
                now[0] += transport_timeout_seconds
                raise BrokerError("request_timeout", "injected timeout")

        profile = TimeoutProfile()
        with mock.patch.object(
            broker_profile_module.time, "monotonic", side_effect=lambda: now[0]
        ):
            result = profile.wait_test_run(
                repository=REPOSITORY_ID, run_id="run-pending", timeout_seconds=3
            )

        self.assertEqual(profile.timeouts, [3.0])
        self.assertEqual(
            result,
            {
                "schema_version": 1,
                "repository_id": REPOSITORY_ID,
                "run_id": "run-pending",
                "wait_timed_out": True,
                "status_observed": False,
            },
        )

    def test_wait_retries_transient_scheduler_replacement_failures(self) -> None:
        now = [100.0]

        class RecoveringProfile:
            wait_test_run = BrokerClientProfile.wait_test_run

            def __init__(self) -> None:
                self.reads = 0

            def test_run_status(
                self,
                *,
                repository: str,
                run_id: str,
                transport_timeout_seconds: float | None = None,
            ) -> dict[str, object]:
                del repository, run_id, transport_timeout_seconds
                self.reads += 1
                if self.reads == 1:
                    raise BrokerError(
                        "test_scheduler_unavailable", "testd is restarting"
                    )
                if self.reads == 2:
                    raise ConnectionResetError("authority is restarting")
                return {"run_id": "run-preserved", "state": "succeeded"}

        profile = RecoveringProfile()
        with (
            mock.patch.object(
                broker_profile_module.time, "monotonic", side_effect=lambda: now[0]
            ),
            mock.patch.object(
                broker_profile_module.time,
                "sleep",
                side_effect=lambda delay: now.__setitem__(0, now[0] + delay),
            ),
        ):
            result = profile.wait_test_run(
                repository=REPOSITORY_ID,
                run_id="run-preserved",
                timeout_seconds=3,
            )

        self.assertEqual(profile.reads, 3)
        self.assertEqual(result["state"], "succeeded")
        self.assertNotIn("wait_timed_out", result)

    def test_zero_wait_deadline_performs_no_status_read(self) -> None:
        profile = FailedWaitProfile()

        result = profile.wait_test_run(
            repository=REPOSITORY_ID, run_id="run-pending", timeout_seconds=0
        )

        self.assertEqual(profile.reads, 0)
        self.assertTrue(result["wait_timed_out"])
        self.assertFalse(result["status_observed"])

    def test_manifest_health_distinguishes_missing_invalid_and_ready(self) -> None:
        missing = manifest_health(self.root, doctor=False)
        self.assertEqual(missing["status"], "missing")
        (self.root / ".codex").mkdir()
        (self.root / ".codex" / "tests.json").write_text("{}", encoding="utf-8")
        invalid = manifest_health(self.root, doctor=False)
        self.assertEqual(invalid["status"], "invalid")
        initialize_manifest(self.root, force=True)
        ready = manifest_health(self.root, doctor=True)
        self.assertEqual(ready["status"], "ready")
        self.assertIn("target_graph", ready)
        self.assertFalse(
            any(issue["code"] == "target_executable_unavailable" for issue in ready["issues"])
        )

    def test_manifest_doctor_does_not_treat_caller_executable_access_as_admission(self) -> None:
        self._committed_repository()
        manifest_path = self.root / ".codex" / "tests.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["targets"]["tests"]["argv"][0] = ".venv/bin/python"
        manifest_path.write_text(json.dumps(document), encoding="utf-8")

        result = manifest_health(self.root, doctor=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ready")
        self.assertNotIn(
            "target_executable_unavailable",
            {issue["code"] for issue in result["issues"]},
        )

    def test_broker_profile_exception_text_is_not_exposed(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")

        def broken_profile() -> object:
            raise RuntimeError("credential=do-not-print\x00\n" + ("z" * 20_000))

        result = handle_universal_test_cli(
            parser().parse_args(
                [
                    "test",
                    "plan",
                    "--agent",
                    "codex",
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
            ),
            canonical_project=lambda value: value,
            broker_profile_loader=broken_profile,
        )

        self.assertEqual(
            result["broker_profile_error"],
            "protected broker profile is unavailable or invalid",
        )
        self.assertNotIn("credential", json.dumps(result))
        self.assertLessEqual(
            len(
                json.dumps(result, separators=(",", ":"), sort_keys=True).encode(
                    "utf-8"
                )
            ),
            8192,
        )

    def test_live_plan_selects_changed_target_and_is_advisory(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="change",
            raw_changes=("modified:source.py",),
            requested_targets=(),
            broker_profile=None,
            operation_id=PLAN_OPERATION_ID,
        )
        self.assertTrue(planned["ok"])
        self.assertFalse(planned["attestable"])
        self.assertFalse(planned["submission"]["available"])
        self.assertEqual(planned["plan"]["selected_targets"], ["tests"])
        self.assertEqual(planned["plan"]["source"]["mode"], "live")
        self.assertEqual(
            planned["plan"]["timeouts"],
            {"execution_seconds": None, "launch_seconds": 300},
        )
        self.assertTrue(planned["plan"]["plan_id"].startswith("plan-"))

    def test_live_plan_prefers_broker_preview_without_local_source_inspection(
        self,
    ) -> None:
        self._committed_repository()
        profile = LivePreviewProfile(self.root)

        with mock.patch(
            "devcoordinator.universal_test_cli.load_test_manifest",
            side_effect=AssertionError("local manifest load must not run"),
        ), mock.patch(
            "devcoordinator.universal_test_cli.discover_changes",
            side_effect=AssertionError("local Git discovery must not run"),
        ):
            planned = build_local_plan(
                root=self.root,
                temporary=None,
                agent="codex",
                intent="change",
                raw_changes=(),
                requested_targets=(),
                broker_profile=profile,
                operation_id=PLAN_OPERATION_ID,
                compact=False,
            )

        self.assertEqual(len(profile.calls), 1)
        self.assertEqual(profile.calls[0]["repository"], profile.repository_id)
        self.assertEqual(profile.calls[0]["intent"], "change")
        self.assertEqual(planned["classification"], "broker_test_plan")
        self.assertTrue(planned["submission"]["available"])
        self.assertFalse(planned["attestable"])
        self.assertEqual(planned["plan"]["source"]["mode"], "live")

    def test_live_plan_falls_back_when_broker_preview_is_unavailable(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
        profile = UnavailablePreviewProfile()

        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="change",
            raw_changes=(),
            requested_targets=(),
            broker_profile=profile,
            operation_id=PLAN_OPERATION_ID,
        )

        self.assertEqual(profile.preview_calls, 1)
        self.assertEqual(planned["classification"], "broker_test_plan")
        self.assertTrue(planned["submission"]["available"])
        self.assertEqual(planned["plan"]["selected_targets"], ["tests"])
        self.assertEqual(profile.registered_plan_id, planned["plan"]["plan_id"])

    def test_caller_timeouts_are_persisted_in_live_plan(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="change",
            raw_changes=("modified:source.py",),
            requested_targets=(),
            execution_timeout_seconds=4_321,
            launch_timeout_seconds=987,
            broker_profile=None,
            operation_id=PLAN_OPERATION_ID,
            compact=False,
        )
        self.assertEqual(
            planned["plan"]["timeouts"],
            {"execution_seconds": 4_321, "launch_seconds": 987},
        )

    def test_broker_registration_makes_live_plan_submittable_not_attestable(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
        profile = FakeSchedulerProfile()
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="change",
            raw_changes=("modified:source.py",),
            requested_targets=(),
            broker_profile=profile,
            operation_id=PLAN_OPERATION_ID,
        )
        self.assertEqual(planned["classification"], "broker_test_plan")
        self.assertTrue(planned["submission"]["available"])
        self.assertFalse(planned["attestable"])
        self.assertEqual(profile.registered_plan_id, planned["plan"]["plan_id"])

    def test_explicit_live_changes_must_cover_current_dirty_source(self) -> None:
        self._committed_repository()
        (self.root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
        (self.root / "omitted.py").write_text("VALUE = 3\n", encoding="utf-8")

        with self.assertRaisesRegex(
            UniversalTestCliError,
            "must exactly match current Git changes",
        ):
            build_local_plan(
                root=self.root,
                temporary=None,
                agent="codex",
                intent="change",
                raw_changes=("modified:source.py",),
                requested_targets=(),
                broker_profile=FakeSchedulerProfile(),
                operation_id=PLAN_OPERATION_ID,
            )

    def test_submit_returns_real_queued_run_from_broker(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000002"
        parsed = parser().parse_args(
            [
                "test",
                "submit",
                *RUN_REPOSITORY_ARGS,
                "--plan-id",
                "plan-abc",
                "--operation-id",
                operation_id,
            ]
        )
        result = handle_universal_test_cli(
            parsed,
            canonical_project=lambda value: value,
            broker_profile_loader=FakeSchedulerProfile,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "queued")
        self.assertEqual(
            result["run_id"], "run-00000000-0000-4000-8000-000000000001"
        )
        self.assertEqual(result["operation_id"], operation_id)

    def test_submit_resolves_an_adopted_root_in_a_fresh_process(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000006"
        parsed = parser().parse_args(
            [
                "test",
                "submit",
                "--root-repo",
                str(self.root),
                "--plan-id",
                "plan-abc",
                "--operation-id",
                operation_id,
            ]
        )

        result = handle_universal_test_cli(
            parsed,
            canonical_project=lambda value: value,
            broker_profile_loader=FakeSchedulerProfile,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["run_id"], "run-00000000-0000-4000-8000-000000000001"
        )
        self.assertEqual(result["operation_id"], operation_id)

    def test_wait_resolves_an_adopted_root_in_a_fresh_process(self) -> None:
        parsed = parser().parse_args(
            [
                "test",
                "wait",
                "--root-repo",
                str(self.root),
                "--run-id",
                "run-abc",
                "--timeout-seconds",
                "15",
            ]
        )
        profile = RecordingSchedulerProfile()

        result = handle_universal_test_cli(
            parsed,
            canonical_project=lambda value: value,
            broker_profile_loader=lambda: profile,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(
            profile.calls,
            [
                (
                    "wait_test_run",
                    {
                        "repository": REPOSITORY_ID,
                        "run_id": "run-abc",
                        "timeout_seconds": 15,
                    },
                )
            ],
        )

    def test_read_and_control_commands_dispatch_exact_bounded_arguments(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000003"
        cases = (
            (
                ["test", "status", *RUN_REPOSITORY_ARGS, "--run-id", "run-abc"],
                "test_run_status",
                {"repository": REPOSITORY_ID, "run_id": "run-abc"},
            ),
            (
                ["test", "summary", *RUN_REPOSITORY_ARGS, "--run-id", "run-abc"],
                "test_run_summary",
                {"repository": REPOSITORY_ID, "run_id": "run-abc"},
            ),
            (
                [
                    "test",
                    "failures",
                    *RUN_REPOSITORY_ARGS,
                    "--run-id",
                    "run-abc",
                    "--after",
                    "failure-10",
                    "--limit",
                    "3",
                ],
                "test_run_failures",
                {
                    "repository": REPOSITORY_ID,
                    "run_id": "run-abc",
                    "after": "failure-10",
                    "limit": 3,
                },
            ),
            (
                [
                    "test",
                    "artifact",
                    *RUN_REPOSITORY_ARGS,
                    "--run-id",
                    "run-abc",
                    "--artifact-id",
                    "artifact-4",
                ],
                "test_artifact",
                {
                    "repository": REPOSITORY_ID,
                    "run_id": "run-abc",
                    "artifact_id": "artifact-4",
                },
            ),
            (
                [
                    "test",
                    "cancel",
                    *RUN_REPOSITORY_ARGS,
                    "--run-id",
                    "run-abc",
                    "--reason",
                    "obsolete",
                    "--operation-id",
                    operation_id,
                ],
                "cancel_test_run",
                {
                    "run_id": "run-abc",
                    "repository": REPOSITORY_ID,
                    "reason": "obsolete",
                    "operation_id": operation_id,
                    "actor": "codex:test-cli-task",
                },
            ),
            (
                [
                    "test",
                    "wait",
                    *RUN_REPOSITORY_ARGS,
                    "--run-id",
                    "run-abc",
                    "--timeout-seconds",
                    "15",
                ],
                "wait_test_run",
                {
                    "repository": REPOSITORY_ID,
                    "run_id": "run-abc",
                    "timeout_seconds": 15,
                },
            ),
        )
        for raw, expected_method, expected_arguments in cases:
            with self.subTest(command=raw[1]):
                profile = RecordingSchedulerProfile()
                with mock.patch.dict(
                    os.environ, {"CODEX_THREAD_ID": "test-cli-task"}, clear=False
                ):
                    result = handle_universal_test_cli(
                        parser().parse_args(raw),
                        canonical_project=lambda value: value,
                        broker_profile_loader=lambda: profile,
                    )
                self.assertTrue(result["ok"])
                self.assertEqual(profile.calls, [(expected_method, expected_arguments)])

    def test_broker_summary_must_fit_agent_envelope(self) -> None:
        parsed = parser().parse_args(
            ["test", "summary", *RUN_REPOSITORY_ARGS, "--run-id", "run-abc"]
        )
        with self.assertRaisesRegex(UniversalTestCliError, "8 KiB"):
            handle_universal_test_cli(
                parsed,
                canonical_project=lambda value: value,
                broker_profile_loader=OversizedSummaryProfile,
            )

    def test_default_plan_envelope_is_bounded_and_marks_truncation(self) -> None:
        self._committed_repository()
        generated = self.root / "generated"
        generated.mkdir()
        for index in range(200):
            (generated / f"path-{index:04d}.py").write_text(
                f"VALUE = {index}\n", encoding="utf-8"
            )
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="change",
            raw_changes=tuple(
                f"untracked:generated/path-{index:04d}.py" for index in range(200)
            ),
            requested_targets=(),
            broker_profile=None,
            operation_id=PLAN_OPERATION_ID,
        )
        encoded = json.dumps(
            planned, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), 8192)
        self.assertTrue(planned["plan"]["truncated"]["changes"])

    def test_immutable_plan_fails_closed_until_snapshot_broker_exists(self) -> None:
        self._committed_repository()
        pending = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="handoff",
            raw_changes=(),
            requested_targets=(),
            broker_profile=None,
            operation_id=PLAN_OPERATION_ID,
        )
        self.assertFalse(pending["ok"])
        self.assertEqual(pending["code"], "immutable_snapshot_broker_pending")
        self.assertNotIn("run_id", pending)

    def test_immutable_plan_uses_broker_snapshot_and_is_attestable(self) -> None:
        self._committed_repository()
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="release",
            raw_changes=(),
            requested_targets=(),
            broker_profile=ImmutablePreviewProfile(self.root),
            operation_id=PLAN_OPERATION_ID,
            compact=False,
        )
        self.assertTrue(planned["ok"])
        self.assertTrue(planned["attestable"])
        self.assertTrue(planned["submission"]["available"])
        self.assertEqual(planned["plan"]["source"]["mode"], "immutable")
        self.assertTrue(planned["plan"]["source"]["snapshot_id"].startswith("snapshot-"))

    def test_plan_dynamically_resolves_authority_adopted_repository(self) -> None:
        self._committed_repository()
        profile = DynamicImmutablePreviewProfile(self.root)
        planned = build_local_plan(
            root=self.root,
            temporary=None,
            agent="codex",
            intent="release",
            raw_changes=(),
            requested_targets=(),
            broker_profile=profile,
            operation_id=PLAN_OPERATION_ID,
            compact=False,
        )
        self.assertTrue(planned["ok"])
        self.assertEqual(profile.resolve_calls, [str(self.root.resolve())])

    def test_immutable_temporary_worktree_and_manual_target_reach_broker_preview(self) -> None:
        self._committed_repository()
        temporary_root = Path(self.temporary.name + "-worktree")
        self.addCleanup(lambda: shutil.rmtree(temporary_root, ignore_errors=True))
        self._git("worktree", "add", "--detach", str(temporary_root))
        release = build_local_plan(
            root=self.root,
            temporary=temporary_root,
            agent="codex",
            intent="release",
            raw_changes=(),
            requested_targets=(),
            broker_profile=ImmutablePreviewProfile(self.root),
            operation_id=PLAN_OPERATION_ID,
            compact=False,
        )
        self.assertTrue(release["attestable"])
        self.assertEqual(
            release["plan"]["source"]["temporary_root"], str(temporary_root)
        )

        manual = build_local_plan(
            root=self.root,
            temporary=temporary_root,
            agent="codex",
            intent="manual",
            raw_changes=(),
            requested_targets=("tests",),
            broker_profile=ImmutablePreviewProfile(self.root),
            operation_id=PLAN_OPERATION_ID,
            compact=False,
        )
        self.assertEqual(manual["plan"]["selected_targets"], ["tests"])
        self.assertIn(
            "requested", manual["plan"]["selection"]["tests"]
        )

    def test_immutable_plan_rejects_contradictory_broker_source(self) -> None:
        self._committed_repository()
        with self.assertRaisesRegex(UniversalTestCliError, "contradictory"):
            build_local_plan(
                root=self.root,
                temporary=None,
                agent="codex",
                intent="release",
                raw_changes=(),
                requested_targets=(),
                broker_profile=ImmutablePreviewProfile(
                    self.root, contradictory_root=True
                ),
                operation_id=PLAN_OPERATION_ID,
            )

    def test_plan_rejects_unrelated_temporary_repository(self) -> None:
        self._committed_repository()
        other = self.root / "unrelated"
        other.mkdir()
        subprocess.run(
            ["git", "-C", str(other), "init", "--quiet"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with self.assertRaisesRegex(UniversalTestCliError, "not a Git worktree"):
            build_local_plan(
                root=self.root,
                temporary=other,
                agent="codex",
                intent="change",
                raw_changes=("modified:source.py",),
                requested_targets=(),
                broker_profile=None,
                operation_id=PLAN_OPERATION_ID,
            )

    def test_plan_rejects_dynamic_source_symlink_escape(self) -> None:
        self._committed_repository()
        (self.root / "escape.py").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(UniversalTestCliError, "symlink escapes"):
            build_local_plan(
                root=self.root,
                temporary=None,
                agent="codex",
                intent="change",
                raw_changes=("untracked:escape.py",),
                requested_targets=(),
                broker_profile=None,
                operation_id=PLAN_OPERATION_ID,
            )

    def test_scheduler_commands_never_fabricate_identity(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        parsed = parser().parse_args(
            [
                "test",
                "submit",
                *RUN_REPOSITORY_ARGS,
                "--plan-id",
                "plan-abc",
                "--operation-id",
                operation_id,
            ]
        )
        result = handle_universal_test_cli(
            parsed,
            canonical_project=lambda value: value,
            broker_profile_loader=lambda: None,
        )
        self.assertEqual(result["classification"], "test_scheduler_pending")
        self.assertEqual(result["operation_id"], operation_id)
        self.assertNotIn("run_id", result)

        for action in ("status", "summary", "wait"):
            context = scheduler_pending(action, run_id="run-abc")
            self.assertFalse(context["ok"])
            self.assertFalse(context["retryable"])

    def test_catalog_reports_ready_missing_and_invalid(self) -> None:
        ready = self.root / "ready"
        ready.mkdir()
        initialize_manifest(ready, force=False)
        catalog = read_test_catalog(ready, None)
        self.assertEqual(catalog["counts"], {"ready": 1, "missing": 0, "invalid": 0})
        self.assertTrue(catalog["ok"])
        self.assertEqual(catalog["status"], "ready")

        missing = self.root / "missing"
        missing.mkdir()
        missing_catalog = read_test_catalog(missing, None)
        self.assertEqual(missing_catalog["counts"]["missing"], 1)
        self.assertFalse(missing_catalog["ok"])
        self.assertEqual(missing_catalog["status"], "not_ready")

        invalid = self.root / "invalid"
        (invalid / ".codex").mkdir(parents=True)
        (invalid / ".codex" / "tests.json").write_text("{}", encoding="utf-8")
        invalid_catalog = read_test_catalog(invalid, None)
        self.assertEqual(invalid_catalog["counts"]["invalid"], 1)
        self.assertFalse(invalid_catalog["ok"])
        self.assertEqual(invalid_catalog["status"], "not_ready")

    def test_catalog_uses_repository_uid_setup_surface_when_brokered(self) -> None:
        profile = SetupCatalogProfile()
        catalog = read_test_catalog(None, profile)
        self.assertEqual(
            profile.calls,
            ["repo-00000000-0000-4000-8000-000000000008"],
        )
        self.assertEqual(catalog["counts"], {"ready": 0, "missing": 1, "invalid": 0})
        self.assertFalse(catalog["ok"])
        self.assertEqual(catalog["status"], "not_ready")
        self.assertEqual(
            catalog["repositories"][0]["repository"],
            "/home/example/project",
        )
        self.assertEqual(catalog["repositories"][0]["targets"], [])

        ready = read_test_catalog(None, ReadySetupCatalogProfile())
        self.assertEqual(ready["repositories"][0]["targets"], ["unit"])

    def test_catalog_dynamically_resolves_authority_adopted_repository(self) -> None:
        profile = DynamicSetupCatalogProfile(self.root)
        catalog = read_test_catalog(self.root, profile)
        self.assertEqual(profile.resolve_calls, [str(self.root.resolve())])
        self.assertEqual(catalog["repository_count"], 1)
        self.assertEqual(catalog["repositories"][0]["status"], "missing")

    def test_catalog_checks_all_rows_but_returns_one_bounded_envelope(self) -> None:
        parsed = parser().parse_args(["test", "catalog"])
        self.assertTrue(parsed.compact_json)
        catalog = read_test_catalog(None, OversizedCatalogProfile())
        encoded = json.dumps(
            catalog, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

        self.assertLessEqual(len(encoded), 8192)
        self.assertEqual(
            catalog["counts"], {"ready": 27, "missing": 27, "invalid": 26}
        )
        self.assertFalse(catalog["ok"])
        self.assertEqual(catalog["status"], "not_ready")
        self.assertEqual(catalog["repository_count"], 80)
        self.assertTrue(catalog["truncated"]["repositories"])
        self.assertNotIn("\x00", encoded.decode("utf-8"))
        self.assertNotIn("\n", catalog["repositories"][0]["issues"][0]["message"])

    def test_stats_command_is_retired(self) -> None:
        with self.assertRaises(SystemExit):
            parser().parse_args(["test", "stats", "--root-repo", "/repo"])

    def test_policy_command_is_retired(self) -> None:
        with self.assertRaises(SystemExit):
            parser().parse_args(["test", "policy", "check"])


if __name__ == "__main__":
    unittest.main()
