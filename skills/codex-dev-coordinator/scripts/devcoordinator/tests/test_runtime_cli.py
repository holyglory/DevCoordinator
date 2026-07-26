"""Focused contracts for the language-neutral runtime flag adapter."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import dev_coordinator  # noqa: E402
import devcoordinator.runtime_api as runtime_api_module  # noqa: E402
import devcoordinator.runtime_cli as runtime_cli  # noqa: E402
from devcoordinator.runtime_api import RuntimeRequestError  # noqa: E402


class RuntimeCliTests(unittest.TestCase):
    def parse(self, *arguments: str):
        return dev_coordinator.build_parser().parse_args(["runtime", *arguments])

    def existing_service_flags(
        self, action: str = "status", *extra: str
    ) -> list[str]:
        return [
            action,
            "--agent",
            "agent with spaces",
            "--root-repo",
            "/repo with spaces/$literal;not-shell",
            "--no-temporary-repo",
            "--target-kind",
            "service",
            "--target-id",
            "service:immutable:id",
            "--target-name",
            "worker;$(not-a-shell)",
            "--purpose",
            "development",
            "--no-ttl",
            "--kill-after-run",
            "false",
            *extra,
        ]

    def test_runtime_and_inventory_help_explain_discovery_and_lifetime_rules(self) -> None:
        parser = dev_coordinator.build_parser()
        runtime_parser = next(
            action.choices["runtime"]
            for action in parser._actions
            if getattr(action, "choices", None) and "runtime" in action.choices
        )
        inventory_parser = next(
            action.choices["inventory"]
            for action in parser._actions
            if getattr(action, "choices", None) and "inventory" in action.choices
        )
        runtime_help = runtime_parser.format_help()
        inventory_help = inventory_parser.format_help()
        top_level_help = parser.format_help()
        runtime_words = " ".join(runtime_help.split())
        inventory_words = " ".join(inventory_help.split())
        top_level_words = " ".join(top_level_help.split())
        for expected in (
            "status/start/stop/restart/remove",
            "inventory --project ROOT_REPO --compact-json",
            "Only run may set KillAfterRun=true",
            "first start supplies Keep Alive explicitly",
            "10 crashes in 300 seconds",
            "references/runtime-api.md#structured-request-examples",
        ):
            self.assertIn(expected, runtime_words)
        self.assertIn("only action=run may set true", runtime_words)
        self.assertIn("default 10", runtime_words)
        self.assertIn("default 300", runtime_words)
        self.assertIn("repository_trees", inventory_words)
        self.assertIn("server_definition_id", inventory_words)
        self.assertIn("docker_resource_id", inventory_words)
        self.assertIn("database_binding_id", inventory_words)
        self.assertIn(
            "runtime run one attributed repository-scoped runtime",
            top_level_words,
        )
        self.assertIn(
            "inventory read repository trees and immutable runtime",
            top_level_words,
        )

    def test_flag_mode_builds_the_canonical_request_without_shell_parsing(self) -> None:
        request = runtime_cli.load_runtime_cli_request(
            self.parse(*self.existing_service_flags())
        )
        self.assertEqual(
            request,
            {
                "schema_version": 1,
                "action": "status",
                "agent": "agent with spaces",
                "root_repo": "/repo with spaces/$literal;not-shell",
                "temporary_repo": None,
                "target": {
                    "kind": "service",
                    "id": "service:immutable:id",
                    "name": "worker;$(not-a-shell)",
                },
                "purpose": "development",
                "ttl_seconds": None,
                "kill_after_run": False,
                "options": {},
            },
        )

    def test_simple_flag_actions_and_target_kinds_delegate_to_the_validator(self) -> None:
        for action in sorted(
            runtime_cli.RUNTIME_SIMPLE_ACTIONS & runtime_api_module.RUNTIME_ACTIONS
        ):
            with self.subTest(action=action):
                extra = ["--reason", "obsolete worker"] if action == "remove" else []
                request = runtime_cli.load_runtime_cli_request(
                    self.parse(*self.existing_service_flags(action), *extra)
                )
                self.assertEqual(request["action"], action)

        for kind in ("docker", "database_stack"):
            with self.subTest(kind=kind):
                arguments = self.existing_service_flags()
                name_index = arguments.index("--target-name")
                del arguments[name_index : name_index + 2]
                arguments[arguments.index("service")] = kind
                with mock.patch.object(
                    runtime_cli,
                    "validate_runtime_request",
                    wraps=runtime_api_module.validate_runtime_request,
                ) as canonical_validator:
                    request = runtime_cli.load_runtime_cli_request(
                        self.parse(*arguments)
                    )
                canonical_validator.assert_called_once()
                self.assertEqual(request["target"]["kind"], kind)

    def test_temporary_and_ttl_values_are_explicit_and_canonical(self) -> None:
        arguments = self.existing_service_flags("start")
        no_temp = arguments.index("--no-temporary-repo")
        arguments[no_temp : no_temp + 1] = [
            "--temporary-repo",
            "/repo/worktrees/test one",
        ]
        no_ttl = arguments.index("--no-ttl")
        arguments[no_ttl : no_ttl + 1] = ["--ttl-seconds", "600"]
        purpose = arguments.index("development")
        arguments[purpose] = "test"
        request = runtime_cli.load_runtime_cli_request(self.parse(*arguments))
        self.assertEqual(request["temporary_repo"], "/repo/worktrees/test one")
        self.assertEqual(request["ttl_seconds"], 600)

    def test_worker_policy_and_remove_plan_flags_use_canonical_options(self) -> None:
        keep_alive = runtime_cli.load_runtime_cli_request(
            self.parse(
                *self.existing_service_flags("start"),
                "--keep-alive",
                "true",
                "--restart-limit",
                "10",
                "--restart-window-seconds",
                "300",
                "--rearm-crash-loop",
                "true",
            )
        )
        self.assertEqual(
            {
                key: keep_alive["options"][key]
                for key in (
                    "keep_alive",
                    "restart_limit",
                    "restart_window_seconds",
                    "rearm_crash_loop",
                )
            },
            {
                "keep_alive": True,
                "restart_limit": 10,
                "restart_window_seconds": 300,
                "rearm_crash_loop": True,
            },
        )

        planned = runtime_cli.load_runtime_cli_request(
            self.parse(
                *self.existing_service_flags("remove"),
                "--remove-plan-id",
                "11111111-1111-4111-8111-111111111111",
                "--remove-plan-fingerprint",
                "sha256:" + "a" * 64,
                "--remove-confirmation-phrase",
                "PURGE SERVER worker;$(not-a-shell)",
            )
        )
        self.assertEqual(
            planned["options"]["remove_plan_id"],
            "11111111-1111-4111-8111-111111111111",
        )
        self.assertEqual(
            planned["options"]["remove_confirmation_phrase"],
            "PURGE SERVER worker;$(not-a-shell)",
        )
        archive = runtime_cli.load_runtime_cli_request(
            self.parse(
                *self.existing_service_flags("remove"),
                "--remove-plan-id",
                "11111111-1111-4111-8111-111111111111",
                "--remove-plan-fingerprint",
                "sha256:" + "a" * 64,
                "--remove-confirmation-phrase",
                "",
            )
        )
        self.assertEqual(archive["options"]["remove_confirmation_phrase"], "")

    def test_invalid_flag_and_json_envelopes_preserve_safe_request_context(self) -> None:
        missing_id = self.existing_service_flags()
        id_index = missing_id.index("--target-id")
        del missing_id[id_index : id_index + 2]
        flagged = dev_coordinator.handle_cli(self.parse(*missing_id))
        self.assertFalse(flagged["ok"])
        self.assertEqual(flagged["action"], "status")
        self.assertEqual(
            flagged["repository"],
            {
                "root_repo": "/repo with spaces/$literal;not-shell",
                "temporary_repo": None,
            },
        )
        self.assertEqual(
            flagged["target"],
            {"kind": "service", "name": "worker;$(not-a-shell)"},
        )

        raw = {
            "schema_version": 1,
            "action": "restart",
            "agent": "audit",
            "root_repo": "/repo/root",
            "temporary_repo": "/repo/temp",
            "target": {"kind": "docker", "name": "missing-id"},
            "purpose": "test",
            "ttl_seconds": 30,
            "kill_after_run": False,
        }
        encoded = dev_coordinator.handle_cli(
            self.parse("--request-json", json.dumps(raw))
        )
        self.assertFalse(encoded["ok"])
        self.assertEqual(encoded["action"], "restart")
        self.assertEqual(
            encoded["repository"],
            {"root_repo": "/repo/root", "temporary_repo": "/repo/temp"},
        )
        self.assertEqual(
            encoded["target"], {"kind": "docker", "name": "missing-id"}
        )

        oversized = self.parse(*self.existing_service_flags())
        oversized.target_id = "x" * 301
        context = runtime_cli.runtime_cli_error_context(oversized)
        self.assertEqual(
            context["target"],
            {"kind": "service", "name": "worker;$(not-a-shell)"},
        )

    def test_structured_documentation_examples_use_the_canonical_schema(self) -> None:
        reference = SCRIPTS_ROOT.parent / "references" / "runtime-api.md"
        document = reference.read_text(encoding="utf-8")
        actions: list[str] = []
        for encoded in re.findall(r"```json\n(.*?)\n```", document, re.DOTALL):
            value = json.loads(encoded)
            if not isinstance(value, dict) or not (
                runtime_api_module.RUNTIME_REQUIRED_KEYS <= set(value)
            ):
                continue
            actions.append(runtime_api_module.validate_runtime_request(value)["action"])
        self.assertEqual(actions, ["status", "start", "replace", "run"])

    def test_flag_and_legacy_json_modes_normalize_to_the_same_request(self) -> None:
        flagged = runtime_cli.load_runtime_cli_request(
            self.parse(*self.existing_service_flags("restart", "--reason", "recover"))
        )
        encoded = json.dumps(flagged, separators=(",", ":"))
        with mock.patch.object(
            runtime_api_module,
            "validate_runtime_request",
            wraps=runtime_api_module.validate_runtime_request,
        ) as canonical_validator:
            legacy = runtime_cli.load_runtime_cli_request(
                self.parse("--request-json", encoded)
            )
        canonical_validator.assert_called_once()
        self.assertEqual(legacy, flagged)

    def test_legacy_request_file_remains_supported(self) -> None:
        request = runtime_cli.load_runtime_cli_request(
            self.parse(*self.existing_service_flags())
        )
        # load_runtime_request requires an absolute regular non-symlink file.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "request.json"
            path.write_text(json.dumps(request), encoding="utf-8")
            loaded = runtime_cli.load_runtime_cli_request(
                self.parse("--request-file", str(path))
            )
        self.assertEqual(loaded, request)

    def test_explicit_null_and_boolean_markers_cannot_be_omitted_or_mixed(self) -> None:
        cases: list[tuple[list[str], str]] = []

        missing_temporary = self.existing_service_flags()
        missing_temporary.remove("--no-temporary-repo")
        cases.append((missing_temporary, "temporary-repo"))

        missing_ttl = self.existing_service_flags()
        missing_ttl.remove("--no-ttl")
        cases.append((missing_ttl, "ttl-seconds"))

        missing_kill = self.existing_service_flags()
        kill_index = missing_kill.index("--kill-after-run")
        del missing_kill[kill_index : kill_index + 2]
        cases.append((missing_kill, "kill-after-run"))

        invalid_kill = self.existing_service_flags()
        invalid_kill[invalid_kill.index("false")] = "0"
        cases.append((invalid_kill, "exactly true or false"))

        invalid_ttl = self.existing_service_flags("start")
        invalid_ttl[invalid_ttl.index("--no-ttl")] = "--ttl-seconds"
        invalid_ttl.insert(invalid_ttl.index("--ttl-seconds") + 1, "+30")
        cases.append((invalid_ttl, "positive integer"))

        for arguments, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                RuntimeRequestError, message
            ):
                runtime_cli.load_runtime_cli_request(self.parse(*arguments))

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.parse(
                    *self.existing_service_flags(),
                    "--temporary-repo",
                    "/other",
                )
            with self.assertRaises(SystemExit):
                self.parse(*self.existing_service_flags(), "--ttl-seconds", "30")

    def test_json_mode_refuses_flag_fields_instead_of_silently_ignoring_them(self) -> None:
        request = runtime_cli.load_runtime_cli_request(
            self.parse(*self.existing_service_flags())
        )
        with self.assertRaisesRegex(RuntimeRequestError, "cannot be combined"):
            runtime_cli.load_runtime_cli_request(
                self.parse(
                    "--request-json",
                    json.dumps(request),
                    "--agent",
                    "second-agent",
                )
            )

    def test_policy_flags_are_derived_from_canonical_field_locations(self) -> None:
        flags = runtime_cli.canonical_policy_flags(
            request_keys={"keep_alive", "restart_limit"},
            option_keys={"restart_window_seconds"},
        )
        self.assertEqual(
            [(item.field, item.location, item.value_kind) for item in flags],
            [
                ("keep_alive", "request", "boolean"),
                ("restart_limit", "request", "integer"),
                ("restart_window_seconds", "options", "integer"),
            ],
        )
        exposed = {item.field for item in runtime_cli.canonical_policy_flags()}
        canonical = (
            runtime_api_module.RUNTIME_REQUEST_KEYS
            | runtime_api_module.RUNTIME_OPTION_KEYS
        )
        self.assertEqual(
            exposed,
            {
                name
                for name in (
                    "keep_alive",
                    "restart_limit",
                    "restart_window_seconds",
                    "rearm_crash_loop",
                )
                if name in canonical
            },
        )

    def test_every_required_canonical_request_field_has_one_flag_source(self) -> None:
        represented = {
            "schema_version",  # owned by this versioned adapter
            "action",
            "agent",
            "root_repo",
            "temporary_repo",
            "target",
            "purpose",
            "ttl_seconds",
            "kill_after_run",
        }
        represented.update(
            policy.field
            for policy in runtime_cli.canonical_policy_flags()
            if policy.location == "request"
        )
        self.assertEqual(represented, runtime_api_module.RUNTIME_REQUIRED_KEYS)

    def test_flag_mode_cli_is_compact_and_identical_under_optimized_python(self) -> None:
        invocation = repr(self.existing_service_flags())
        source = (
            "from unittest import mock\n"
            "import dev_coordinator\n"
            "argv = " + invocation + "\n"
            "with mock.patch.object(dev_coordinator, 'authority_mode', return_value='account'), "
            "mock.patch.object(dev_coordinator, 'coordinated_runtime_request', "
            "side_effect=lambda request: {'ok': True, 'request': request}):\n"
            " raise SystemExit(dev_coordinator.main(['runtime', *argv]))\n"
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SCRIPTS_ROOT)
        outputs: list[str] = []
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", source])
            completed = subprocess.run(
                command,
                cwd=str(SCRIPTS_ROOT),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn("\n", completed.stdout.strip())
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_malformed_flag_cli_returns_typed_nonzero_json_in_normal_and_optimized_python(
        self,
    ) -> None:
        arguments = self.existing_service_flags()
        kill_index = arguments.index("--kill-after-run")
        del arguments[kill_index : kill_index + 2]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SCRIPTS_ROOT)
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [str(SCRIPTS_ROOT / "dev_coordinator.py"), "runtime", *arguments]
            )
            completed = subprocess.run(
                command,
                cwd=str(SCRIPTS_ROOT),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn("\n", completed.stdout.strip())
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["classification"], "invalid_request")
            self.assertEqual(payload["error_type"], "RuntimeRequestError")
            self.assertIn("kill-after-run", payload["error"])


if __name__ == "__main__":
    unittest.main()
