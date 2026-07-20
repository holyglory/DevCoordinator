#!/usr/bin/env python3
"""Verify the installed broker's shutdown, filesystem, and capability boundary."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from devcoordinator.broker import (  # noqa: E402
    BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
)


BROKER_UNIT = "devcoordinator-broker.service"
BROKER_FRAGMENT = "/etc/systemd/system/devcoordinator-broker.service"
BROKER_HOME_DROPIN = (
    "/etc/systemd/system/devcoordinator-broker.service.d/"
    "80-enrolled-home-write-paths.conf"
)
BASE_READ_WRITE_PATHS = "/var/lib/devcoordinator /run/devcoordinator"
HOME_DROPIN_COMMENT = (
    "# Generated transactionally from the complete explicit --client-user set."
)
SYSTEMD_STOP_TIMEOUT_SECONDS = 65 * 60
SYSTEMD_STOP_TIMEOUT_SOURCE = "65min"
SYSTEMD_STOP_TIMEOUT_EFFECTIVE = "1h 5min"
REQUIRED_OUTER_MARGIN_SECONDS = 4 * 60
EXPECTED_ENVIRONMENT = (
    "DEVCOORDINATOR_AUTHORITY=service "
    "DOCKER_CONFIG=/var/lib/devcoordinator/docker"
)
# systemd 257 omits these two undefined command-list properties from `show`
# instead of serializing `Property=`. Keep this allowlist local to this unit;
# other absent security-relevant properties remain violations.
OMITTED_WHEN_EMPTY = frozenset({"ExecStop", "ExecStopPost"})
PROPERTIES = (
    "Type",
    "FragmentPath",
    "DropInPaths",
    "User",
    "Group",
    "Environment",
    "ExecStop",
    "ExecStopPost",
    "KillMode",
    "KillSignal",
    "RestartKillSignal",
    "FinalKillSignal",
    "SendSIGKILL",
    "SurviveFinalKillSignal",
    "TimeoutStopUSec",
    "TimeoutStopFailureMode",
    "UMask",
    "NoNewPrivileges",
    "PrivateTmp",
    "ProtectSystem",
    "ProtectHome",
    "ReadWritePaths",
    "ReadOnlyPaths",
    "BindPaths",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
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


class BrokerShutdownUnitError(RuntimeError):
    pass


def parse_properties(raw: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key:
            continue
        if key in properties:
            raise BrokerShutdownUnitError(
                f"effective broker unit repeated property {key}"
            )
        properties[key] = value
    return properties


def capability_property_mask(value: str) -> int:
    names = value.split()
    if len(names) != len(set(names)):
        raise BrokerShutdownUnitError(
            "effective broker capability ceiling contains duplicate names"
        )
    unknown = sorted(set(names) - set(CAPABILITY_BITS))
    if unknown:
        raise BrokerShutdownUnitError(
            "effective broker capability ceiling contains unsupported names: "
            + ", ".join(unknown)
        )
    return sum(CAPABILITY_BITS[name] for name in names)


def manager_capability_bounding_mask(path: Path = Path("/proc/1/status")) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise BrokerShutdownUnitError(
            f"cannot read system manager capability ceiling: {error}"
        ) from error
    for line in lines:
        key, separator, value = line.partition(":")
        if not separator or key != "CapBnd":
            continue
        try:
            mask = int(value.strip(), 16)
        except ValueError as error:
            raise BrokerShutdownUnitError(
                "system manager CapBnd is not hexadecimal"
            ) from error
        known_mask = (1 << len(LINUX_CAPABILITIES)) - 1
        if mask & ~known_mask:
            raise BrokerShutdownUnitError(
                "system manager exposes capability bits unknown to this verifier"
            )
        return mask
    raise BrokerShutdownUnitError("system manager status omitted CapBnd")


def source_directives(source: str, key: str) -> list[tuple[str, str]]:
    current_section = ""
    results: list[tuple[str, str]] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
        elif line.startswith(f"{key}="):
            results.append((current_section, line))
    return results


def validate_home_dropin_source(source: str) -> tuple[str, ...]:
    lines = source.splitlines()
    if len(lines) != 4 or lines[:3] != [
        "[Service]",
        HOME_DROPIN_COMMENT,
        "ReadWritePaths=",
    ]:
        raise BrokerShutdownUnitError(
            "enrolled-home drop-in must contain only its generated Service reset"
        )
    prefix = f"ReadWritePaths={BASE_READ_WRITE_PATHS} "
    if not lines[3].startswith(prefix):
        raise BrokerShutdownUnitError(
            "enrolled-home drop-in must retain the authority/run writable paths"
        )
    homes = tuple(lines[3][len(prefix) :].split())
    if not homes or tuple(sorted(set(homes))) != homes:
        raise BrokerShutdownUnitError(
            "enrolled-home writable paths must be nonempty, unique, and sorted"
        )
    for raw in homes:
        path = Path(raw)
        if path.parent != Path("/home") or not re.fullmatch(
            r"[A-Za-z0-9._+-]+", path.name
        ):
            raise BrokerShutdownUnitError(
                f"enrolled-home writable path is not one safe direct /home child: {raw}"
            )
    return homes


def read_home_dropin(path: Path) -> str:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise BrokerShutdownUnitError(
            f"cannot inspect enrolled-home drop-in {absolute}: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokerShutdownUnitError(
            f"enrolled-home drop-in is not a real regular file: {absolute}"
        )
    if absolute == Path(BROKER_HOME_DROPIN) and (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or absolute.resolve(strict=True) != absolute
    ):
        raise BrokerShutdownUnitError(
            "installed enrolled-home drop-in has unsafe ownership, mode, or path"
        )
    try:
        return absolute.read_text(encoding="utf-8")
    except OSError as error:
        raise BrokerShutdownUnitError(
            f"cannot read enrolled-home drop-in {absolute}: {error}"
        ) from error


def validate_timeout_relationship() -> None:
    if (
        SYSTEMD_STOP_TIMEOUT_SECONDS
        < BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS + REQUIRED_OUTER_MARGIN_SECONDS
    ):
        raise BrokerShutdownUnitError(
            "systemd stop timeout does not outlive the configured broker graceful-wait budget"
        )


def validate_source_unit(source: str) -> None:
    validate_timeout_relationship()
    for directive in (
        "Environment=DEVCOORDINATOR_AUTHORITY=service",
        "Environment=DOCKER_CONFIG=/var/lib/devcoordinator/docker",
        "KillMode=mixed",
        "KillSignal=SIGTERM",
        "RestartKillSignal=SIGTERM",
        "FinalKillSignal=SIGKILL",
        "SendSIGKILL=yes",
        "SurviveFinalKillSignal=no",
        f"TimeoutStopSec={SYSTEMD_STOP_TIMEOUT_SOURCE}",
        "TimeoutStopFailureMode=terminate",
    ):
        if source.splitlines().count(directive) != 1:
            raise BrokerShutdownUnitError(
                f"broker source unit must contain exactly one {directive}"
            )
    forbidden = ("KillMode=control-group", "KillMode=process", "TimeoutStopSec=15")
    if any(item in source.splitlines() for item in forbidden):
        raise BrokerShutdownUnitError(
            "broker source unit retains an unsafe shutdown directive"
        )
    environment_directives = [
        line for line in source.splitlines() if line.startswith("Environment=")
    ]
    if environment_directives != [
        "Environment=DEVCOORDINATOR_AUTHORITY=service",
        "Environment=DOCKER_CONFIG=/var/lib/devcoordinator/docker",
    ]:
        raise BrokerShutdownUnitError(
            "broker source unit must contain only the pinned service environment"
        )
    if any(
        line.startswith(("ExecStop=", "ExecStopPost="))
        for line in source.splitlines()
    ):
        raise BrokerShutdownUnitError(
            "broker source unit must not install shutdown hooks"
        )
    current_section = ""
    survive_sections: list[str] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
        elif line == "SurviveFinalKillSignal=no":
            survive_sections.append(current_section)
    if survive_sections != ["Unit"]:
        raise BrokerShutdownUnitError(
            "SurviveFinalKillSignal=no must be pinned in the Unit section"
        )

    service_security = {
        "UMask": "UMask=0077",
        "NoNewPrivileges": "NoNewPrivileges=true",
        "PrivateTmp": "PrivateTmp=true",
        "ProtectSystem": "ProtectSystem=strict",
        "ProtectHome": "ProtectHome=read-only",
        "ReadWritePaths": f"ReadWritePaths={BASE_READ_WRITE_PATHS}",
    }
    for key, directive in service_security.items():
        if source_directives(source, key) != [("Service", directive)]:
            raise BrokerShutdownUnitError(
                f"broker source unit must pin exactly one {directive} in Service"
            )
    for key in ("AmbientCapabilities", "CapabilityBoundingSet"):
        if source_directives(source, key):
            raise BrokerShutdownUnitError(
                "broker source unit must inherit the manager capability ceiling "
                "with no ambient capability set"
            )
    for key in ("ReadOnlyPaths", "BindPaths", "BindReadOnlyPaths"):
        if source_directives(source, key):
            raise BrokerShutdownUnitError(
                f"broker source unit must not add a {key} filesystem bypass"
            )


def validate_effective_unit(
    raw: str,
    *,
    manager_bounding_mask: int,
    expected_home_paths: tuple[str, ...],
) -> dict[str, str]:
    validate_timeout_relationship()
    validate_home_dropin_source(
        "\n".join(
            [
                "[Service]",
                HOME_DROPIN_COMMENT,
                "ReadWritePaths=",
                (
                    f"ReadWritePaths={BASE_READ_WRITE_PATHS} "
                    + " ".join(expected_home_paths)
                ),
            ]
        )
        + "\n"
    )
    properties = parse_properties(raw)
    expected = {
        "Type": "simple",
        "FragmentPath": BROKER_FRAGMENT,
        "DropInPaths": BROKER_HOME_DROPIN,
        "User": "root",
        "Group": "devcoordinator-clients",
        "Environment": EXPECTED_ENVIRONMENT,
        "ExecStop": "",
        "ExecStopPost": "",
        "KillMode": "mixed",
        "KillSignal": "15",
        "RestartKillSignal": "15",
        "FinalKillSignal": "9",
        "SendSIGKILL": "yes",
        "SurviveFinalKillSignal": "no",
        "TimeoutStopUSec": SYSTEMD_STOP_TIMEOUT_EFFECTIVE,
        "TimeoutStopFailureMode": "terminate",
        "UMask": "0077",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "ReadWritePaths": (
            BASE_READ_WRITE_PATHS + " " + " ".join(expected_home_paths)
        ),
        "ReadOnlyPaths": "",
        "BindPaths": "",
        "AmbientCapabilities": "",
    }
    violations = [
        key
        for key, value in expected.items()
        if (
            ""
            if key in OMITTED_WHEN_EMPTY and key not in properties
            else properties.get(key)
        )
        != value
    ]
    if violations:
        raise BrokerShutdownUnitError(
            "effective broker unit violates pinned service/stop/sandbox properties: "
            + ", ".join(violations)
        )
    bounding = properties.get("CapabilityBoundingSet")
    if bounding is None:
        raise BrokerShutdownUnitError(
            "effective broker unit did not expose CapabilityBoundingSet"
        )
    if capability_property_mask(bounding) != manager_bounding_mask:
        raise BrokerShutdownUnitError(
            "effective broker unit narrows or changes the system manager capability ceiling"
        )
    return properties


def systemctl_show(systemctl: str, unit: str) -> str:
    command = [systemctl, "show", "--no-pager"]
    command.extend(f"--property={name}" for name in PROPERTIES)
    command.append(unit)
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BrokerShutdownUnitError(
            f"systemctl show failed for {unit}: {completed.stderr.strip()}"
        )
    return completed.stdout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        default=str(ROOT / "deploy/devcoordinator-broker.service"),
    )
    parser.add_argument("--home-dropin", default=BROKER_HOME_DROPIN)
    parser.add_argument("--unit", default=BROKER_UNIT)
    parser.add_argument("--systemctl", default="systemctl")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        source = Path(args.source).read_text(encoding="utf-8")
        validate_source_unit(source)
        home_dropin = read_home_dropin(Path(args.home_dropin))
        home_paths = validate_home_dropin_source(home_dropin)
        effective = systemctl_show(str(args.systemctl), str(args.unit))
        validate_effective_unit(
            effective,
            manager_bounding_mask=manager_capability_bounding_mask(),
            expected_home_paths=home_paths,
        )
    except (OSError, BrokerShutdownUnitError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("broker production unit contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
