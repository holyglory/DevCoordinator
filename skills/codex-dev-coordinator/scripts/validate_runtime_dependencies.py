#!/usr/bin/env python3
"""Fail closed unless the broker's exact runtime dependencies are ready."""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIRECTORY))
_bounded_compose_environment = importlib.import_module(
    "devcoordinator.compose_contract"
).bounded_compose_environment


DOCKER_LOCATIONS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/usr/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
)
COMPOSE_VERSION_REQUIREMENT = "stable >=2.17,<3 or >=5,<6"
RUNTIME_CONTRACT = "devcoordinator-broker-runtime-v1"
_COMPOSE_VERSION = re.compile(
    r"^(?:Docker Compose version )?v?"
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?P<suffix>(?:[-+][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)$"
)
_REVIEWED_VENDOR_SUFFIX = re.compile(r"^-desktop\.[0-9]+$")
# Debian appends one positive decimal package revision to the stable upstream
# version exposed by its root-owned docker-compose package (for example
# ``2.26.1-4``).  Keep this deliberately narrower than Debian's general version
# grammar so arbitrary vendor and prerelease text still fails closed.
_REVIEWED_DISTRIBUTION_SUFFIX = re.compile(r"^-[1-9][0-9]*$")
_BUILD_METADATA_SUFFIX = re.compile(r"^\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*$")
_PROBE_SERVICE = "runtime-capability-probe"
_PROBE_EXPLICIT_KEY = "DEVCOORDINATOR_EXPLICIT_ENV_PROBE"
_PROBE_EXPLICIT_VALUE = "second-explicit-env-file-wins"
_PROBE_IMPLICIT_KEY = "DEVCOORDINATOR_IMPLICIT_ENV_PROBE"
_PROBE_IMPLICIT_VALUE = "implicit-dotenv-was-loaded"
_PROBE_IMPLICIT_DEFAULT = "implicit-dotenv-suppressed"


def _failure(code: str, **evidence: object) -> dict[str, object]:
    return {
        "ok": False,
        "contract": RUNTIME_CONTRACT,
        "code": code,
        "requirements": {
            "pyyaml": "6.x",
            "docker_compose": COMPOSE_VERSION_REQUIREMENT,
        },
        **evidence,
    }


def _executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _resolve_docker_executable() -> str:
    """Resolve the same exact Docker entry point later used by the broker."""

    configured = str(os.environ.get("CODEX_DOCKER_CLI") or "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute() or not _executable_file(candidate):
            raise RuntimeError("CODEX_DOCKER_CLI must name an absolute executable file")
        return str(candidate)
    discovered = shutil.which("docker", path=str(os.environ.get("PATH") or ""))
    if discovered and _executable_file(Path(discovered)):
        return str(Path(discovered).absolute())
    for raw in DOCKER_LOCATIONS:
        candidate = Path(raw)
        if _executable_file(candidate):
            return str(candidate)
    raise RuntimeError("Docker CLI is unavailable to the broker service")


def compose_version_status(raw: str) -> dict[str, object]:
    """Classify one official Compose plugin version response."""

    value = raw.strip()
    match = _COMPOSE_VERSION.fullmatch(value)
    if match is None:
        return _failure("compose_version_unrecognized")
    suffix = str(match.group("suffix") or "")
    if suffix and not (
        _REVIEWED_VENDOR_SUFFIX.fullmatch(suffix)
        or _REVIEWED_DISTRIBUTION_SUFFIX.fullmatch(suffix)
        or _BUILD_METADATA_SUFFIX.fullmatch(suffix)
    ):
        return _failure("compose_version_prerelease")
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    if not ((major == 2 and minor >= 17) or major == 5):
        return _failure("compose_version_unsupported")
    normalized = f"{major}.{minor}.{int(match.group('patch'))}{suffix}"
    return {
        "ok": True,
        "contract": RUNTIME_CONTRACT,
        "version": normalized,
        "major": major,
        "minor": minor,
    }


def _run_compose(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=None if cwd is None else str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        timeout=15,
        check=False,
    )


def _compose_capability_status(
    docker_executable: str,
    environment: dict[str, str],
) -> dict[str, object]:
    """Prove the exact non-mutating Compose config behavior the broker needs."""

    try:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-compose-runtime-"
        ) as raw_directory:
            directory = Path(raw_directory)
            empty_environment = directory / "empty.env"
            declared_environment = directory / "declared.env"
            implicit_environment = directory / ".env"
            compose_file = directory / "compose.yaml"
            empty_environment.write_text("", encoding="utf-8")
            declared_environment.write_text(
                f"{_PROBE_EXPLICIT_KEY}={_PROBE_EXPLICIT_VALUE}\n",
                encoding="utf-8",
            )
            implicit_environment.write_text(
                f"{_PROBE_EXPLICIT_KEY}=implicit-dotenv-value\n"
                f"{_PROBE_IMPLICIT_KEY}={_PROBE_IMPLICIT_VALUE}\n",
                encoding="utf-8",
            )
            compose_file.write_text(
                "services:\n"
                f"  {_PROBE_SERVICE}:\n"
                "    image: devcoordinator/runtime-capability-probe:never-run\n"
                "    environment:\n"
                f"      {_PROBE_EXPLICIT_KEY}: "
                f'"${{{_PROBE_EXPLICIT_KEY}:?explicit env-file missing}}"\n'
                f"      {_PROBE_IMPLICIT_KEY}: "
                f'"${{{_PROBE_IMPLICIT_KEY}:-{_PROBE_IMPLICIT_DEFAULT}}}"\n',
                encoding="utf-8",
            )
            completed = _run_compose(
                [
                    docker_executable,
                    "compose",
                    "--project-directory",
                    str(directory),
                    "--env-file",
                    str(empty_environment),
                    "--env-file",
                    str(declared_environment),
                    "--file",
                    str(compose_file),
                    "--project-name",
                    "devcoordinator-runtime-capability-probe",
                    "config",
                    "--format",
                    "json",
                ],
                cwd=directory,
                environment=environment,
            )
    except subprocess.TimeoutExpired:
        return _failure("compose_capability_probe_timeout")
    except OSError:
        return _failure("compose_capability_probe_unavailable")
    if completed.returncode:
        return _failure(
            "compose_capability_probe_failed",
            compose_config_returncode=completed.returncode,
        )
    try:
        document = json.loads(completed.stdout)
        services = document["services"]
        service = services[_PROBE_SERVICE]
        service_environment = service["environment"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return _failure("compose_capability_output_invalid")
    if not isinstance(service_environment, dict):
        return _failure("compose_capability_output_invalid")
    if service_environment.get(_PROBE_EXPLICIT_KEY) != _PROBE_EXPLICIT_VALUE:
        return _failure("compose_second_env_file_override_unavailable")
    if service_environment.get(_PROBE_IMPLICIT_KEY) != _PROBE_IMPLICIT_DEFAULT:
        return _failure("compose_implicit_dotenv_not_suppressed")
    return {
        "ok": True,
        "contract": RUNTIME_CONTRACT,
        "capabilities": {
            "config_json": True,
            "multiple_explicit_env_files": True,
            "second_env_file_override": True,
            "implicit_dotenv_suppressed": True,
        },
    }


def runtime_dependency_status() -> dict[str, object]:
    """Return bounded, non-sensitive dependency evidence for service startup."""

    try:
        import yaml
    except ImportError:
        return _failure("pyyaml_missing")
    version = str(getattr(yaml, "__version__", ""))
    if not version.startswith("6."):
        return _failure(
            "pyyaml_version_unsupported",
            detected_pyyaml_major=version.partition(".")[0] or "unknown",
        )
    if not callable(getattr(yaml, "load", None)) or not isinstance(
        getattr(yaml, "SafeLoader", None), type
    ):
        return _failure("pyyaml_contract_unavailable")
    try:
        docker_executable = _resolve_docker_executable()
    except (OSError, RuntimeError):
        return _failure("docker_cli_unavailable", detected_pyyaml_major="6")
    environment = _bounded_compose_environment(docker_executable)
    try:
        completed = _run_compose(
            [docker_executable, "compose", "version", "--short"],
            environment=environment,
        )
    except subprocess.TimeoutExpired:
        return _failure(
            "compose_version_probe_timeout",
            detected_pyyaml_major="6",
            docker_cli=docker_executable,
        )
    except OSError:
        return _failure(
            "compose_version_probe_unavailable",
            detected_pyyaml_major="6",
            docker_cli=docker_executable,
        )
    if completed.returncode:
        return _failure(
            "compose_version_probe_failed",
            detected_pyyaml_major="6",
            docker_cli=docker_executable,
            compose_version_returncode=completed.returncode,
        )
    compose_version = compose_version_status(completed.stdout)
    if compose_version.get("ok") is not True:
        return _failure(
            str(compose_version.get("code") or "compose_version_unrecognized"),
            detected_pyyaml_major="6",
            docker_cli=docker_executable,
        )
    capability = _compose_capability_status(docker_executable, environment)
    if capability.get("ok") is not True:
        return _failure(
            str(capability.get("code") or "compose_capability_probe_failed"),
            detected_pyyaml_major="6",
            docker_cli=docker_executable,
            compose_version=str(compose_version["version"]),
            **{
                key: value
                for key, value in capability.items()
                if key not in {"ok", "contract", "code", "requirements"}
            },
        )
    return {
        "ok": True,
        "contract": RUNTIME_CONTRACT,
        "requirements": {
            "pyyaml": "6.x",
            "docker_compose": COMPOSE_VERSION_REQUIREMENT,
        },
        "pyyaml": {"detected_major": "6"},
        "docker_compose": {
            "docker_cli": docker_executable,
            "version": str(compose_version["version"]),
            **dict(capability["capabilities"]),
        },
    }


def main() -> int:
    status = runtime_dependency_status()
    print(json.dumps(status, sort_keys=True, separators=(",", ":")))
    return 0 if status["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
