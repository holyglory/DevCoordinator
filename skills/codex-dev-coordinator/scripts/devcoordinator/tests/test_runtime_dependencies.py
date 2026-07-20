from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from devcoordinator import broker_host


SCRIPT = Path(__file__).resolve().parents[2] / "validate_runtime_dependencies.py"
SPEC = importlib.util.spec_from_file_location("runtime_dependencies", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load runtime dependency validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def _completed(
    command: list[str], output: str, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=command,
        returncode=returncode,
        stdout=output,
        stderr="",
    )


def _config_output(*, explicit: str, implicit: str) -> str:
    return json.dumps(
        {
            "services": {
                VALIDATOR._PROBE_SERVICE: {
                    "environment": {
                        VALIDATOR._PROBE_EXPLICIT_KEY: explicit,
                        VALIDATOR._PROBE_IMPLICIT_KEY: implicit,
                    }
                }
            }
        }
    )


class ComposeVersionContractTests(unittest.TestCase):
    def test_accepts_supported_stable_and_vendor_versions(self) -> None:
        accepted = (
            "2.17.0",
            "v2.17.0",
            "Docker Compose version v2.99.1",
            "2.17.0-desktop.1",
            "2.26.1-4",
            "2.44.3+vendor.7",
            "5.0.0",
        )
        for raw in accepted:
            with self.subTest(raw=raw):
                self.assertIs(
                    VALIDATOR.compose_version_status(raw).get("ok"),
                    True,
                )

    def test_rejects_unsupported_unknown_and_prerelease_versions(self) -> None:
        rejected = {
            "1.29.2": "compose_version_unsupported",
            "2.16.99": "compose_version_unsupported",
            "3.0.0": "compose_version_unsupported",
            "4.99.0": "compose_version_unsupported",
            "6.0.0": "compose_version_unsupported",
            "2.17": "compose_version_unrecognized",
            "2.17.0-desktop..1": "compose_version_unrecognized",
            "docker-compose version 1.29.2": "compose_version_unrecognized",
            "unknown": "compose_version_unrecognized",
            "2.17.0-rc.1": "compose_version_prerelease",
            "5.0.0-beta1": "compose_version_prerelease",
            "2.17.0-desktop.rc1": "compose_version_prerelease",
            "5.8.9-vendor.4": "compose_version_prerelease",
            "2.17.0-canary.1": "compose_version_prerelease",
            "2.17.0-milestone.1": "compose_version_prerelease",
            "2.17.0-experimental.1": "compose_version_prerelease",
            "2.26.1-0": "compose_version_prerelease",
            "2.26.1-04": "compose_version_prerelease",
            "2.26.1-4.1": "compose_version_prerelease",
            "2.26.1-4-debian": "compose_version_prerelease",
        }
        for raw, code in rejected.items():
            with self.subTest(raw=raw):
                status = VALIDATOR.compose_version_status(raw)
                self.assertIs(status.get("ok"), False)
                self.assertEqual(status.get("code"), code)


class ComposeCapabilityContractTests(unittest.TestCase):
    def test_isolated_service_argv_loads_its_sibling_package_and_proves_runtime(
        self,
    ) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        docker = directory / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json\n"
            "import sys\n"
            "arguments = sys.argv[1:]\n"
            "if arguments == ['compose', 'version', '--short']:\n"
            "    print('2.26.1-4')\n"
            "    raise SystemExit(0)\n"
            "if arguments[:1] == ['compose'] and arguments[-3:] == "
            "['config', '--format', 'json']:\n"
            "    print(json.dumps({'services': {'runtime-capability-probe': "
            "{'environment': {"
            "'DEVCOORDINATOR_EXPLICIT_ENV_PROBE': "
            "'second-explicit-env-file-wins', "
            "'DEVCOORDINATOR_IMPLICIT_ENV_PROBE': "
            "'implicit-dotenv-suppressed'}}}}))\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(9)\n",
            encoding="utf-8",
        )
        docker.chmod(0o700)

        completed = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                "CODEX_DOCKER_CLI": str(docker),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
            timeout=15,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        evidence = json.loads(completed.stdout)
        self.assertIs(evidence.get("ok"), True)
        self.assertEqual(evidence["docker_compose"]["version"], "2.26.1-4")

    def test_preflight_and_broker_share_the_exact_environment_builder(self) -> None:
        self.assertIs(
            VALIDATOR._bounded_compose_environment,
            broker_host._bounded_compose_environment,
        )

    def test_full_status_uses_one_exact_cli_and_proves_config_contract(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append((list(command), dict(kwargs)))
            if command[2:] == ["version", "--short"]:
                return _completed(command, "2.17.0-desktop.1\n")
            self.assertEqual(command[0], "/trusted/docker")
            self.assertEqual(command[1], "compose")
            self.assertEqual(command[-3:], ["config", "--format", "json"])
            env_file_indexes = [
                index for index, value in enumerate(command) if value == "--env-file"
            ]
            self.assertEqual(len(env_file_indexes), 2)
            first = Path(command[env_file_indexes[0] + 1])
            second = Path(command[env_file_indexes[1] + 1])
            self.assertEqual(first.read_text(encoding="utf-8"), "")
            self.assertIn(
                f"{VALIDATOR._PROBE_EXPLICIT_KEY}={VALIDATOR._PROBE_EXPLICIT_VALUE}",
                second.read_text(encoding="utf-8"),
            )
            dot_env = Path(str(kwargs["cwd"])) / ".env"
            self.assertIn(
                VALIDATOR._PROBE_IMPLICIT_VALUE,
                dot_env.read_text(encoding="utf-8"),
            )
            environment = dict(kwargs["environment"])
            self.assertEqual(environment["COMPOSE_DISABLE_ENV_FILE"], "1")
            self.assertEqual(environment["COMPOSE_REMOVE_ORPHANS"], "0")
            self.assertEqual(environment["COMPOSE_PARALLEL_LIMIT"], "4")
            return _completed(
                command,
                _config_output(
                    explicit=VALIDATOR._PROBE_EXPLICIT_VALUE,
                    implicit=VALIDATOR._PROBE_IMPLICIT_DEFAULT,
                ),
            )

        fake_yaml = types.SimpleNamespace(
            __version__="6.0.2",
            load=lambda value: value,
            SafeLoader=type("SafeLoader", (), {}),
        )
        with (
            mock.patch.dict(sys.modules, {"yaml": fake_yaml}),
            mock.patch.object(
                VALIDATOR,
                "_resolve_docker_executable",
                return_value="/trusted/docker",
            ),
            mock.patch.object(VALIDATOR, "_run_compose", side_effect=runner),
        ):
            status = VALIDATOR.runtime_dependency_status()
        self.assertIs(status.get("ok"), True)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call[0][0] == "/trusted/docker" for call in calls))
        self.assertEqual(
            status["docker_compose"],
            {
                "docker_cli": "/trusted/docker",
                "version": "2.17.0-desktop.1",
                "config_json": True,
                "multiple_explicit_env_files": True,
                "second_env_file_override": True,
                "implicit_dotenv_suppressed": True,
            },
        )

    def test_capability_probe_rejects_wrong_second_file_value(self) -> None:
        completed = _completed(
            ["/trusted/docker", "compose"],
            _config_output(
                explicit="first-file-value",
                implicit=VALIDATOR._PROBE_IMPLICIT_DEFAULT,
            ),
        )
        with mock.patch.object(VALIDATOR, "_run_compose", return_value=completed):
            status = VALIDATOR._compose_capability_status(
                "/trusted/docker", {"PATH": "/trusted"}
            )
        self.assertEqual(
            status.get("code"),
            "compose_second_env_file_override_unavailable",
        )

    def test_capability_probe_rejects_loaded_implicit_dotenv(self) -> None:
        completed = _completed(
            ["/trusted/docker", "compose"],
            _config_output(
                explicit=VALIDATOR._PROBE_EXPLICIT_VALUE,
                implicit=VALIDATOR._PROBE_IMPLICIT_VALUE,
            ),
        )
        with mock.patch.object(VALIDATOR, "_run_compose", return_value=completed):
            status = VALIDATOR._compose_capability_status(
                "/trusted/docker", {"PATH": "/trusted"}
            )
        self.assertEqual(
            status.get("code"),
            "compose_implicit_dotenv_not_suppressed",
        )

    def test_capability_probe_requires_valid_json_merged_model(self) -> None:
        completed = _completed(["/trusted/docker", "compose"], "not-json")
        with mock.patch.object(VALIDATOR, "_run_compose", return_value=completed):
            status = VALIDATOR._compose_capability_status(
                "/trusted/docker", {"PATH": "/trusted"}
            )
        self.assertEqual(status.get("code"), "compose_capability_output_invalid")


if __name__ == "__main__":
    unittest.main()
