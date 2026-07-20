#!/usr/bin/env python3
"""Recall and false-positive controls for the production broker unit guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile


SCRIPT = Path(__file__).with_name("check_broker_shutdown_unit.py")
SPEC = importlib.util.spec_from_file_location("broker_shutdown_unit", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import broker shutdown unit guard")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# The timeout, failure mode, environment, kill, filesystem sandbox, and
# capability spellings below were captured from this Linux target's real
# systemd 257 `show` serialization for isolated transient units on 2026-07-18.
# ExecStop and ExecStopPost were requested from `show` but omitted because they
# were undefined; DropInPaths and AmbientCapabilities were emitted as explicit
# empty values. Production identity fields use their pinned installed values.
# The fixtures were then stopped and unloaded.
EFFECTIVE = """Type=simple
FragmentPath=/etc/systemd/system/devcoordinator-broker.service
DropInPaths=/etc/systemd/system/devcoordinator-broker.service.d/80-enrolled-home-write-paths.conf
User=root
Group=devcoordinator-clients
Environment=DEVCOORDINATOR_AUTHORITY=service DOCKER_CONFIG=/var/lib/devcoordinator/docker
KillMode=mixed
KillSignal=15
RestartKillSignal=15
FinalKillSignal=9
SendSIGKILL=yes
SurviveFinalKillSignal=no
TimeoutStopUSec=1h 5min
TimeoutStopFailureMode=terminate
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob
ReadOnlyPaths=
BindPaths=
AmbientCapabilities=
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend cap_audit_read cap_perfmon cap_bpf cap_checkpoint_restore
"""

MANAGER_BOUNDING = sum(MODULE.CAPABILITY_BITS.values())
EXPECTED_HOME_PATHS = ("/home/alice", "/home/bob")
HOME_DROPIN = """[Service]
# Generated transactionally from the complete explicit --client-user set.
ReadWritePaths=
ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob
"""


def must_reject_effective(raw: str, label: str) -> None:
    try:
        MODULE.validate_effective_unit(
            raw,
            manager_bounding_mask=MANAGER_BOUNDING,
            expected_home_paths=EXPECTED_HOME_PATHS,
        )
    except MODULE.BrokerShutdownUnitError:
        return
    raise AssertionError(f"missed unsafe effective broker unit: {label}")


def must_reject_source(raw: str, label: str) -> None:
    try:
        MODULE.validate_source_unit(raw)
    except MODULE.BrokerShutdownUnitError:
        return
    raise AssertionError(f"missed unsafe source broker unit: {label}")


def must_reject_dropin(raw: str, label: str) -> None:
    try:
        MODULE.validate_home_dropin_source(raw)
    except MODULE.BrokerShutdownUnitError:
        return
    raise AssertionError(f"missed unsafe enrolled-home drop-in: {label}")


def main() -> int:
    source = (MODULE.ROOT / "deploy/devcoordinator-broker.service").read_text(
        encoding="utf-8"
    )
    MODULE.validate_source_unit(source)
    if MODULE.validate_home_dropin_source(HOME_DROPIN) != EXPECTED_HOME_PATHS:
        raise AssertionError("canonical enrolled-home drop-in parsed incorrectly")
    with tempfile.TemporaryDirectory(prefix="broker-home-dropin-") as raw:
        root = Path(raw).resolve(strict=True)
        regular = root / "homes.conf"
        regular.write_text(HOME_DROPIN, encoding="utf-8")
        if MODULE.read_home_dropin(regular) != HOME_DROPIN:
            raise AssertionError("real enrolled-home drop-in was not read exactly")
        symlink = root / "homes-link.conf"
        symlink.symlink_to(regular)
        try:
            MODULE.read_home_dropin(symlink)
        except MODULE.BrokerShutdownUnitError:
            pass
        else:
            raise AssertionError("enrolled-home drop-in reader followed a symlink")
    for broken, label in (
        (
            HOME_DROPIN.replace(
                "/home/alice /home/bob", "/home /home/alice /home/bob"
            ),
            "broad home root",
        ),
        (
            HOME_DROPIN.replace(
                "/home/alice /home/bob", "/home/alice /home/bob /etc"
            ),
            "extra system path",
        ),
        (
            HOME_DROPIN.replace(
                "/home/alice /home/bob", "/home/bob /home/alice"
            ),
            "unsorted homes",
        ),
        (
            HOME_DROPIN.replace(
                "/home/alice /home/bob", "/home/alice /home/alice"
            ),
            "duplicate home",
        ),
        (HOME_DROPIN.replace("ReadWritePaths=\n", "", 1), "missing list reset"),
        (HOME_DROPIN + "BindPaths=/home\n", "extra directive"),
        (HOME_DROPIN.replace("[Service]", "[Unit]"), "wrong section"),
    ):
        must_reject_dropin(broken, label)
    MODULE.validate_effective_unit(
        EFFECTIVE,
        manager_bounding_mask=MANAGER_BOUNDING,
        expected_home_paths=EXPECTED_HOME_PATHS,
    )
    for original, replacement, label in (
        ("Type=simple", "Type=notify", "service type"),
        (
            "FragmentPath=/etc/systemd/system/devcoordinator-broker.service",
            "FragmentPath=/run/systemd/transient/foreign.service",
            "fragment identity",
        ),
        ("User=root", "User=operator", "service user"),
        (
            "Group=devcoordinator-clients",
            "Group=operator",
            "service group",
        ),
        (
            "Environment=DEVCOORDINATOR_AUTHORITY=service DOCKER_CONFIG=/var/lib/devcoordinator/docker",
            "Environment=DEVCOORDINATOR_AUTHORITY=service DOCKER_CONFIG=/tmp/docker",
            "Docker configuration environment",
        ),
        (
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob",
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob /etc",
            "extra writable system path",
        ),
        (
            "ProtectHome=read-only",
            "ProtectHome=no",
            "writable home baseline",
        ),
        (
            "ProtectSystem=strict",
            "ProtectSystem=full",
            "weakened system protection",
        ),
        (
            "NoNewPrivileges=yes",
            "NoNewPrivileges=no",
            "privilege escalation enabled",
        ),
        (
            "PrivateTmp=yes",
            "PrivateTmp=no",
            "shared temporary directory",
        ),
        (
            "AmbientCapabilities=",
            "AmbientCapabilities=cap_sys_admin",
            "ambient capability",
        ),
        ("FinalKillSignal=9", "FinalKillSignal=15", "final kill signal"),
        (
            "DropInPaths=/etc/systemd/system/devcoordinator-broker.service.d/80-enrolled-home-write-paths.conf",
            "DropInPaths=/etc/systemd/system/devcoordinator-broker.service.d/override.conf",
            "drop-in override",
        ),
    ):
        must_reject_effective(
            EFFECTIVE.replace(original, replacement),
            label,
        )
    must_reject_effective(
        EFFECTIVE.replace("KillMode=mixed", "KillMode=control-group"),
        "control-group SIGTERM",
    )
    must_reject_effective(
        EFFECTIVE.replace("TimeoutStopUSec=1h 5min", "TimeoutStopUSec=1h"),
        "timeout lacks the configured outer margin",
    )
    must_reject_effective(
        EFFECTIVE.replace("SendSIGKILL=yes", "SendSIGKILL=no"),
        "unbounded final cgroup",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "SurviveFinalKillSignal=no", "SurviveFinalKillSignal=yes"
        ),
        "processes survive the final kill boundary",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "TimeoutStopFailureMode=terminate",
            "TimeoutStopFailureMode=abort",
        ),
        "stop timeout failure mode",
    )
    must_reject_effective(
        EFFECTIVE.replace("KillSignal=15", "KillSignal=1", 1),
        "stop signal bypasses the broker drain handler",
    )
    must_reject_effective(
        EFFECTIVE.replace("RestartKillSignal=15", "RestartKillSignal=1"),
        "restart signal bypasses the broker drain handler",
    )
    must_reject_effective(EFFECTIVE + "KillMode=mixed\n", "duplicate property")
    must_reject_effective(
        EFFECTIVE + "ExecStop={ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
        "stop hook",
    )
    must_reject_effective(
        EFFECTIVE + "ExecStopPost={ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
        "post-stop hook",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "DropInPaths=/etc/systemd/system/devcoordinator-broker.service.d/80-enrolled-home-write-paths.conf\n",
            "",
        ),
        "missing canonical home drop-in",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "Environment=DEVCOORDINATOR_AUTHORITY=service DOCKER_CONFIG=/var/lib/devcoordinator/docker",
            "Environment=DEVCOORDINATOR_AUTHORITY=service DOCKER_CONFIG=/var/lib/devcoordinator/docker EXTRA=value",
        ),
        "extra environment",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob",
            "ReadWritePaths=/ /var/lib/devcoordinator /run/devcoordinator /home/alice /home/bob",
        ),
        "root filesystem write access",
    )
    must_reject_effective(
        EFFECTIVE.replace("BindPaths=", "BindPaths=/home:/run/devcoordinator/home"),
        "writable bind alias",
    )
    must_reject_effective(
        EFFECTIVE.replace("ReadOnlyPaths=", "ReadOnlyPaths=/etc"),
        "unexpected filesystem override",
    )
    must_reject_effective(
        EFFECTIVE.replace("CapabilityBoundingSet=cap_chown ", "CapabilityBoundingSet="),
        "narrowed capability ceiling",
    )
    must_reject_effective(
        EFFECTIVE.replace(
            "CapabilityBoundingSet=cap_chown ",
            "CapabilityBoundingSet=cap_unknown ",
        ),
        "unknown capability",
    )
    must_reject_source(
        source.replace("KillMode=mixed", "KillMode=control-group"),
        "source control-group SIGTERM",
    )
    must_reject_source(
        source.replace("TimeoutStopSec=65min", "TimeoutStopSec=60min"),
        "source timeout drift",
    )
    must_reject_source(
        source.replace(
            "Environment=DOCKER_CONFIG=/var/lib/devcoordinator/docker",
            "Environment=DOCKER_CONFIG=/tmp/docker",
        ),
        "source Docker configuration drift",
    )
    must_reject_source(
        source.replace(
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator /etc",
        ),
        "source extra writable system path",
    )
    must_reject_source(
        source.replace(
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
            "ReadWritePaths=/ /var/lib/devcoordinator /run/devcoordinator",
        ),
        "source root filesystem write access",
    )
    must_reject_source(
        source.replace(
            "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
            "ReadWritePaths=/home /var/lib/devcoordinator /run/devcoordinator",
        ),
        "source ineffective broad home exception",
    )
    must_reject_source(
        source.replace("ProtectHome=read-only", "ProtectHome=false"),
        "source writable home baseline",
    )
    must_reject_source(
        source.replace("ProtectSystem=strict", "ProtectSystem=full"),
        "source weakened system protection",
    )
    must_reject_source(
        source.replace("NoNewPrivileges=true", "NoNewPrivileges=false"),
        "source privilege escalation enabled",
    )
    must_reject_source(
        source + "\nAmbientCapabilities=CAP_SYS_ADMIN\n",
        "source ambient capability",
    )
    must_reject_source(
        source + "\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
        "source narrowed capability ceiling",
    )
    must_reject_source(
        source + "\nBindPaths=/home:/run/devcoordinator/home\n",
        "source writable bind alias",
    )
    must_reject_source(
        source + "\nReadWritePaths=/etc\n",
        "source second writable-path directive",
    )
    writable = "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator"
    must_reject_source(
        source.replace(f"{writable}\n", "", 1) + f"\n{writable}\n",
        "source writable-path directive outside Service",
    )
    must_reject_source(
        source + "\nEnvironment=EXTRA=value\n",
        "extra source environment",
    )
    must_reject_source(source + "\nExecStop=/usr/bin/false\n", "source stop hook")
    must_reject_source(
        source + "\nExecStopPost=/usr/bin/false\n",
        "source post-stop hook",
    )
    must_reject_source(
        source.replace("SurviveFinalKillSignal=no\n", "", 1).replace(
            "SendSIGKILL=yes\n",
            "SendSIGKILL=yes\nSurviveFinalKillSignal=no\n",
            1,
        ),
        "SurviveFinalKillSignal in the wrong section",
    )
    for directive in (
        "Environment=DEVCOORDINATOR_AUTHORITY=service",
        "Environment=DOCKER_CONFIG=/var/lib/devcoordinator/docker",
        "KillSignal=SIGTERM",
        "RestartKillSignal=SIGTERM",
        "FinalKillSignal=SIGKILL",
        "SendSIGKILL=yes",
        "SurviveFinalKillSignal=no",
        "TimeoutStopFailureMode=terminate",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=/var/lib/devcoordinator /run/devcoordinator",
    ):
        must_reject_source(
            source.replace(directive, "", 1),
            f"missing source {directive}",
        )
    must_reject_source(source + "\nKillMode=mixed\n", "duplicate source directive")
    print("broker shutdown unit self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
