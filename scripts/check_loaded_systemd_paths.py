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
    "Type",
    "FragmentPath",
    "DropInPaths",
    "User",
    "Group",
    "WorkingDirectory",
    "Environment",
    "EnvironmentFiles",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "TimeoutStartUSec",
    "ReadWritePaths",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
)
SERVICE_HOME = "/home/holyglory"
COORDINATOR_HOME = f"{SERVICE_HOME}/.codex/agent-coordinator"
COORDINATOR_JOURNAL = "/var/lib/devcoordinator-clients/1000"
CONSOLE_STATE = f"{SERVICE_HOME}/.local/state/devops-console"
CONSOLE_ENV = f"{SERVICE_HOME}/.config/devops-console/console.env"
COORDINATOR_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py "
    f"api serve --host 127.0.0.1 --port 29876 --token-file {COORDINATOR_HOME}/api-token"
)
COORDINATOR_POSTSTART_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py "
    f"--token-file {COORDINATOR_HOME}/api-token --host 127.0.0.1 --port 29876 "
    "--wait-seconds 10 --poll-interval-seconds 0.1"
)
CONSOLE_PREFLIGHT_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/scripts/check_production_layout.py "
    f"--repo-root /home/DevCoordinator --home {SERVICE_HOME} --env-file {CONSOLE_ENV} "
    f"--state-dir {CONSOLE_STATE} --acme-webroot {CONSOLE_STATE}/acme "
    f"--coordinator-home {COORDINATOR_HOME} --token-file {COORDINATOR_HOME}/api-token "
    "--require-token --wait-token-seconds 10"
)
CONSOLE_ARGV = (
    "/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator DEVCOORDINATOR_AUTHORITY=system COORDINATOR_AUTOSTART=0 "
    "COORDINATOR_REGISTRATION_REQUIRED=1 "
    "COORDINATOR_URL=http://127.0.0.1:29876 "
    "COORDINATOR_SCRIPT=/home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py "
    f"COORDINATOR_TOKEN_FILE={COORDINATOR_HOME}/api-token "
    f"CODEX_AGENT_COORDINATOR_HOME={COORDINATOR_JOURNAL} STATE_DIR={CONSOLE_STATE} "
    f"ACME_WEBROOT={CONSOLE_STATE}/acme /usr/bin/node bin/devops-console.mjs --env-file {CONSOLE_ENV}"
)
CONSOLE_POSTSTART_ARGV = (
    "/usr/bin/python3 /home/DevCoordinator/scripts/check_console_registration_ready.py "
    "--unit devops-console.service --main-pid $MAINPID "
    f"--token-file {COORDINATOR_HOME}/api-token --project /home/DevCoordinator "
    "--name devops-console --port 443 --host 127.0.0.1 --coordinator-port 29876 "
    f"--expected-executable /usr/bin/node --expected-script bin/devops-console.mjs "
    f"--env-file {CONSOLE_ENV} --expected-working-directory /home/DevCoordinator/apps/DevOpsConsole "
    "--wait-seconds 80 --poll-interval-seconds 0.1"
)

LINUX_CAPABILITIES = (
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
)
CAPABILITY_BITS = {name: 1 << index for index, name in enumerate(LINUX_CAPABILITIES)}


class LoadedUnitPathError(RuntimeError):
    pass


def parse_properties(raw: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            if key in parsed:
                raise LoadedUnitPathError(f"loaded unit output repeated {key}")
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


def capability_property_mask(value: str) -> int:
    names = value.split()
    if len(names) != len(set(names)):
        raise LoadedUnitPathError("loaded capability set contains duplicate names")
    unknown = sorted(set(names) - set(CAPABILITY_BITS))
    if unknown:
        raise LoadedUnitPathError(
            "loaded capability set contains unsupported names: " + ", ".join(unknown)
        )
    return sum(CAPABILITY_BITS[name] for name in names)


def manager_capability_bounding_mask(path: Path = Path("/proc/1/status")) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LoadedUnitPathError(f"cannot read system manager capability ceiling: {error}") from error
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key == "CapBnd":
            try:
                mask = int(value.strip(), 16)
            except ValueError as error:
                raise LoadedUnitPathError("system manager CapBnd is not hexadecimal") from error
            known_mask = (1 << len(LINUX_CAPABILITIES)) - 1
            if mask & ~known_mask:
                raise LoadedUnitPathError("system manager exposes capability bits unknown to this verifier")
            return mask
    raise LoadedUnitPathError("system manager status omitted CapBnd")


def validate_loaded_unit_outputs(
    coordinator_raw: str,
    console_raw: str,
    *,
    manager_bounding_mask: int,
) -> dict[str, dict[str, str]]:
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
        "Type": "simple",
        "FragmentPath": "/etc/systemd/system/dev-coordinator.service",
        "DropInPaths": "",
        "User": "holyglory",
        "Group": "holyglory",
        "WorkingDirectory": "/home/DevCoordinator",
        "Environment": (
            "DEVCOORDINATOR_AUTHORITY=system "
            f"CODEX_AGENT_COORDINATOR_HOME={COORDINATOR_JOURNAL}"
        ),
        "EnvironmentFiles": "",
        "ExecStartPre": "",
        "TimeoutStartUSec": "20s",
        "ReadWritePaths": "",
        "AmbientCapabilities": "cap_net_bind_service",
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
    require_command(
        violations,
        "dev-coordinator.service",
        coordinator,
        "ExecStartPost",
        COORDINATOR_POSTSTART_ARGV,
    )
    coordinator_bounding = coordinator.get("CapabilityBoundingSet")
    if coordinator_bounding is None:
        violations.append("dev-coordinator.service did not expose CapabilityBoundingSet")
    else:
        try:
            loaded_mask = capability_property_mask(coordinator_bounding)
        except LoadedUnitPathError as error:
            violations.append(f"dev-coordinator.service {error}")
        else:
            if loaded_mask != manager_bounding_mask:
                violations.append(
                    "dev-coordinator.service narrows or changes the system manager capability ceiling"
                )

    console = units["devops-console.service"]
    for key, expected in {
        "Type": "simple",
        "FragmentPath": "/etc/systemd/system/devops-console.service",
        "DropInPaths": "",
        "User": "holyglory",
        "Group": "holyglory",
        "WorkingDirectory": "/home/DevCoordinator/apps/DevOpsConsole",
        "Environment": "",
        "EnvironmentFiles": f"{CONSOLE_ENV} (ignore_errors=no)",
        "TimeoutStartUSec": "1min 30s",
        "ReadWritePaths": CONSOLE_STATE,
        "AmbientCapabilities": "cap_net_bind_service",
        "CapabilityBoundingSet": "cap_net_bind_service",
    }.items():
        require_exact(violations, "devops-console.service", console, key, expected)
    require_command(violations, "devops-console.service", console, "ExecStartPre", CONSOLE_PREFLIGHT_ARGV)
    require_command(violations, "devops-console.service", console, "ExecStart", CONSOLE_ARGV)
    require_command(
        violations,
        "devops-console.service",
        console,
        "ExecStartPost",
        CONSOLE_POSTSTART_ARGV,
    )

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
        units = validate_loaded_unit_outputs(
            coordinator_raw,
            console_raw,
            manager_bounding_mask=manager_capability_bounding_mask(),
        )
        if args.evidence:
            write_evidence(args.evidence, units)
    except (LoadedUnitPathError, OSError, SecureIOError) as error:
        raise SystemExit(f"loaded systemd path preflight failed: {error}") from error
    print("loaded systemd path preflight ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
