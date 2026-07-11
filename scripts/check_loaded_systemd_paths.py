#!/usr/bin/env python3
"""Verify systemd's loaded production paths before either split unit starts."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from secure_cutover_io import SecureIOError, open_private_parent


PROPERTIES = (
    "FragmentPath",
    "DropInPaths",
    "User",
    "Group",
    "WorkingDirectory",
    "Environment",
    "EnvironmentFiles",
    "ExecStartPre",
    "ExecStart",
    "ReadWritePaths",
)
SERVICE_HOME = "/home/holyglory"
COORDINATOR_HOME = f"{SERVICE_HOME}/.codex/agent-coordinator"
CONSOLE_STATE = f"{SERVICE_HOME}/.local/state/devops-console"
CONSOLE_ENV = f"{SERVICE_HOME}/.config/devops-console/console.env"
COORDINATOR_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py "
    f"api serve --host 127.0.0.1 --port 29876 --token-file {COORDINATOR_HOME}/api-token"
)
CONSOLE_PREFLIGHT_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/scripts/check_production_layout.py "
    f"--repo-root /home/DevCoordinator --home {SERVICE_HOME} --env-file {CONSOLE_ENV} "
    f"--state-dir {CONSOLE_STATE} --acme-webroot {CONSOLE_STATE}/acme "
    f"--coordinator-home {COORDINATOR_HOME} --token-file {COORDINATOR_HOME}/api-token "
    "--require-token --wait-token-seconds 10"
)
CONSOLE_ARGV = (
    "/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator COORDINATOR_AUTOSTART=0 "
    "COORDINATOR_URL=http://127.0.0.1:29876 "
    "COORDINATOR_SCRIPT=/home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py "
    f"COORDINATOR_TOKEN_FILE={COORDINATOR_HOME}/api-token "
    f"CODEX_AGENT_COORDINATOR_HOME={COORDINATOR_HOME} STATE_DIR={CONSOLE_STATE} "
    f"ACME_WEBROOT={CONSOLE_STATE}/acme /usr/bin/node bin/devops-console.mjs --env-file {CONSOLE_ENV}"
)


class LoadedUnitPathError(RuntimeError):
    pass


def parse_properties(raw: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            parsed[key] = value
    return parsed


def require_exact(
    violations: list[str],
    unit: str,
    properties: dict[str, str],
    key: str,
    expected: str,
    *,
    allow_omitted_empty: bool = False,
) -> None:
    actual = properties.get(key)
    if actual is None:
        if not (allow_omitted_empty and expected == ""):
            violations.append(f"{unit} did not expose {key}")
    elif actual != expected:
        violations.append(f"{unit} {key} does not match the pinned production contract")


def command_argv(value: str) -> list[str]:
    marker = "argv[]="
    suffix = " ; ignore_errors="
    results: list[str] = []
    offset = 0
    while True:
        start = value.find(marker, offset)
        if start < 0:
            return results
        start += len(marker)
        end = value.find(suffix, start)
        if end < 0:
            return []
        results.append(value[start:end])
        offset = end + len(suffix)


def require_command(
    violations: list[str], unit: str, properties: dict[str, str], key: str, expected: str
) -> None:
    actual = properties.get(key)
    if actual is None:
        violations.append(f"{unit} did not expose {key}")
        return
    executable_paths = re.findall(r"\{ path=([^ ;]+) ; argv\[\]=", actual)
    expected_executable = expected.partition(" ")[0]
    if executable_paths != [expected_executable] or command_argv(actual) != [expected]:
        violations.append(f"{unit} {key} does not contain exactly the pinned production command")


def validate_loaded_unit_outputs(coordinator_raw: str, console_raw: str) -> dict[str, dict[str, str]]:
    units = {
        "dev-coordinator.service": parse_properties(coordinator_raw),
        "devops-console.service": parse_properties(console_raw),
    }
    violations: list[str] = []
    for unit, properties in units.items():
        combined = "\n".join(properties.values())
        if "%h" in combined:
            violations.append(f"{unit} retains an unresolved system-manager home specifier")
        if "/root/" in combined:
            violations.append(f"{unit} resolved a runtime path through the system manager home")

    coordinator = units["dev-coordinator.service"]
    for key, expected in {
        "FragmentPath": "/etc/systemd/system/dev-coordinator.service",
        "DropInPaths": "",
        "User": "holyglory",
        "Group": "holyglory",
        "WorkingDirectory": "/home/DevCoordinator",
        "Environment": f"CODEX_AGENT_COORDINATOR_HOME={COORDINATOR_HOME}",
        "EnvironmentFiles": "",
        "ExecStartPre": "",
        "ReadWritePaths": "",
    }.items():
        require_exact(
            violations,
            "dev-coordinator.service",
            coordinator,
            key,
            expected,
            allow_omitted_empty=key in {"EnvironmentFiles", "ExecStartPre"},
        )
    require_command(violations, "dev-coordinator.service", coordinator, "ExecStart", COORDINATOR_ARGV)

    console = units["devops-console.service"]
    for key, expected in {
        "FragmentPath": "/etc/systemd/system/devops-console.service",
        "DropInPaths": "",
        "User": "holyglory",
        "Group": "holyglory",
        "WorkingDirectory": "/home/DevCoordinator/apps/DevOpsConsole",
        "Environment": "",
        "EnvironmentFiles": f"{CONSOLE_ENV} (ignore_errors=no)",
        "ReadWritePaths": CONSOLE_STATE,
    }.items():
        require_exact(violations, "devops-console.service", console, key, expected)
    require_command(violations, "devops-console.service", console, "ExecStartPre", CONSOLE_PREFLIGHT_ARGV)
    require_command(violations, "devops-console.service", console, "ExecStart", CONSOLE_ARGV)

    if violations:
        raise LoadedUnitPathError("; ".join(violations))
    return units


def systemctl_show(systemctl: str, unit: str) -> str:
    command = [systemctl, "show", "--no-pager"]
    command.extend(f"--property={name}" for name in PROPERTIES)
    command.append(unit)
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise LoadedUnitPathError(f"systemctl show failed for {unit}: {completed.stderr.strip()}")
    return completed.stdout


def write_evidence(path: Path, units: dict[str, dict[str, str]]) -> None:
    parent, _absolute, name = open_private_parent(path)
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        payload = json.dumps({"ok": True, "schema_version": 1, "units": units}, indent=2, sort_keys=True).encode()
        payload += b"\n"
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systemctl", default="systemctl")
    parser.add_argument("--evidence", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        coordinator_raw = systemctl_show(args.systemctl, "dev-coordinator.service")
        console_raw = systemctl_show(args.systemctl, "devops-console.service")
        units = validate_loaded_unit_outputs(coordinator_raw, console_raw)
        if args.evidence:
            write_evidence(args.evidence, units)
    except (LoadedUnitPathError, OSError, SecureIOError) as error:
        raise SystemExit(f"loaded systemd path preflight failed: {error}") from error
    print("loaded systemd path preflight ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
