#!/usr/bin/env python3
"""Recall and false-positive tests for loaded systemd path verification."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_loaded_systemd_paths.py")
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("loaded_systemd_paths", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import loaded systemd path checker")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

MANAGER_BOUNDING = (
    MODULE.CAPABILITY_BITS["cap_chown"]
    | MODULE.CAPABILITY_BITS["cap_net_bind_service"]
    | MODULE.CAPABILITY_BITS["cap_sys_admin"]
)

COORDINATOR = """Type=simple
FragmentPath=/etc/systemd/system/dev-coordinator.service
DropInPaths=
User=holyglory
Group=holyglory
WorkingDirectory=/home/DevCoordinator
Environment=DEVCOORDINATOR_AUTHORITY=system CODEX_AGENT_COORDINATOR_HOME=/var/lib/devcoordinator-clients/1000
AmbientCapabilities=cap_net_bind_service
CapabilityBoundingSet=cap_chown cap_net_bind_service cap_sys_admin
ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py api serve --host 127.0.0.1 --port 29876 --token-file /home/holyglory/.codex/agent-coordinator/api-token ; ignore_errors=no ; start_time=[n/a] ; }
ExecStartPost={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py --token-file /home/holyglory/.codex/agent-coordinator/api-token --host 127.0.0.1 --port 29876 --wait-seconds 10 --poll-interval-seconds 0.1 ; ignore_errors=no ; start_time=[n/a] ; }
TimeoutStartUSec=20s
ReadWritePaths=
"""
CONSOLE = """Type=simple
FragmentPath=/etc/systemd/system/devops-console.service
DropInPaths=
User=holyglory
Group=holyglory
WorkingDirectory=/home/DevCoordinator/apps/DevOpsConsole
Environment=
EnvironmentFiles=/home/holyglory/.config/devops-console/console.env (ignore_errors=no)
AmbientCapabilities=cap_net_bind_service
CapabilityBoundingSet=cap_net_bind_service
ExecStartPre={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /home/DevCoordinator/scripts/check_production_layout.py --repo-root /home/DevCoordinator --home /home/holyglory --env-file /home/holyglory/.config/devops-console/console.env --state-dir /home/holyglory/.local/state/devops-console --acme-webroot /home/holyglory/.local/state/devops-console/acme --coordinator-home /home/holyglory/.codex/agent-coordinator --token-file /home/holyglory/.codex/agent-coordinator/api-token --require-token --wait-token-seconds 10 ; ignore_errors=no ; start_time=[n/a] ; }
ExecStart={ path=/usr/bin/env ; argv[]=/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator DEVCOORDINATOR_AUTHORITY=system COORDINATOR_AUTOSTART=0 COORDINATOR_REGISTRATION_REQUIRED=1 COORDINATOR_URL=http://127.0.0.1:29876 COORDINATOR_SCRIPT=/home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py COORDINATOR_TOKEN_FILE=/home/holyglory/.codex/agent-coordinator/api-token CODEX_AGENT_COORDINATOR_HOME=/var/lib/devcoordinator-clients/1000 STATE_DIR=/home/holyglory/.local/state/devops-console ACME_WEBROOT=/home/holyglory/.local/state/devops-console/acme /usr/bin/node bin/devops-console.mjs --env-file /home/holyglory/.config/devops-console/console.env ; ignore_errors=no ; start_time=[n/a] ; }
ExecStartPost={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /home/DevCoordinator/scripts/check_console_registration_ready.py --unit devops-console.service --main-pid $MAINPID --token-file /home/holyglory/.codex/agent-coordinator/api-token --project /home/DevCoordinator --name devops-console --port 443 --host 127.0.0.1 --coordinator-port 29876 --expected-executable /usr/bin/node --expected-script bin/devops-console.mjs --env-file /home/holyglory/.config/devops-console/console.env --expected-working-directory /home/DevCoordinator/apps/DevOpsConsole --wait-seconds 80 --poll-interval-seconds 0.1 ; ignore_errors=no ; start_time=[n/a] ; }
TimeoutStartUSec=1min 30s
ReadWritePaths=/home/holyglory/.local/state/devops-console
"""


def must_fail(coordinator: str, console: str, label: str) -> None:
    try:
        MODULE.validate_loaded_unit_outputs(
            coordinator,
            console,
            manager_bounding_mask=MANAGER_BOUNDING,
        )
    except MODULE.LoadedUnitPathError:
        return
    raise AssertionError(f"missed loaded-unit failure: {label}")


def main() -> int:
    MODULE.validate_loaded_unit_outputs(
        COORDINATOR,
        CONSOLE,
        manager_bounding_mask=MANAGER_BOUNDING,
    )
    home = MODULE.SERVICE_HOME

    must_fail(COORDINATOR.replace("User=holyglory", "User=root", 1), CONSOLE, "wrong service user")
    must_fail(COORDINATOR.replace("Type=simple", "Type=notify", 1), CONSOLE, "wrong coordinator service type")
    must_fail(COORDINATOR, CONSOLE.replace("Type=simple", "Type=notify", 1), "wrong Console service type")
    must_fail(COORDINATOR.replace(f"{home}/.codex", "/root/.codex"), CONSOLE, "resolved manager home")
    must_fail(COORDINATOR.replace(f"{home}/.codex", "%h/.codex"), CONSOLE, "unresolved manager home")
    must_fail(COORDINATOR.replace("/etc/systemd/system", "/run/systemd/transient"), CONSOLE, "wrong coordinator fragment")
    must_fail(COORDINATOR.replace("DropInPaths=", "DropInPaths=/run/systemd/system/dev-coordinator.service.d/override.conf", 1), CONSOLE, "coordinator drop-in")
    must_fail(COORDINATOR + "EnvironmentFiles=/tmp/attacker.env (ignore_errors=no)\n", CONSOLE, "coordinator extra environment file")
    must_fail(COORDINATOR + "ExecStartPre={ path=/tmp/hook ; argv[]=/tmp/hook ; ignore_errors=no ; }\n", CONSOLE, "coordinator extra pre-start command")
    must_fail(COORDINATOR.replace("WorkingDirectory=/home/DevCoordinator", "WorkingDirectory=/tmp"), CONSOLE, "coordinator working directory")
    must_fail(COORDINATOR.replace("AmbientCapabilities=cap_net_bind_service", "AmbientCapabilities="), CONSOLE, "missing observer ambient capability")
    must_fail(COORDINATOR.replace("CapabilityBoundingSet=cap_chown cap_net_bind_service cap_sys_admin", "CapabilityBoundingSet=cap_net_bind_service"), CONSOLE, "narrowed coordinator capability ceiling")
    must_fail(COORDINATOR.replace("CapabilityBoundingSet=cap_chown cap_net_bind_service cap_sys_admin", "CapabilityBoundingSet=cap_chown cap_net_bind_service cap_sys_admin cap_sys_ptrace"), CONSOLE, "changed coordinator capability ceiling")
    must_fail(COORDINATOR.replace("/home/DevCoordinator/skills", f"{home}/holyskills/skills"), CONSOLE, "stale coordinator executable")
    must_fail(COORDINATOR.replace("path=/usr/bin/python3", "path=/tmp/python3"), CONSOLE, "coordinator executable path")
    must_fail(COORDINATOR.replace("ExecStart=", "MissingExecStart=", 1), CONSOLE, "missing coordinator command")
    must_fail(COORDINATOR.replace("ExecStartPost=", "MissingExecStartPost=", 1), CONSOLE, "missing coordinator readiness gate")
    must_fail(COORDINATOR.replace("--wait-seconds 10", "--wait-seconds 0", 1), CONSOLE, "disabled coordinator readiness wait")
    must_fail(COORDINATOR.replace("TimeoutStartUSec=20s", "TimeoutStartUSec=infinity", 1), CONSOLE, "unbounded coordinator startup")
    must_fail(COORDINATOR, CONSOLE.replace(f"{home}/.config", "/root/.config"), "environment file")
    must_fail(COORDINATOR, CONSOLE.replace(f"--home {home}", "--home /root"), "preflight home")
    must_fail(COORDINATOR, CONSOLE.replace(f"--state-dir {home}/.local", "--state-dir /root/.local"), "preflight state")
    must_fail(COORDINATOR, CONSOLE.replace(f"STATE_DIR={home}/.local", "STATE_DIR=/root/.local"), "runtime state")
    must_fail(COORDINATOR, CONSOLE.replace(f"ReadWritePaths={home}", "ReadWritePaths=/root"), "sandbox path")
    must_fail(COORDINATOR, CONSOLE.replace(" (ignore_errors=no)", " (ignore_errors=no) /tmp/attacker.env (ignore_errors=no)"), "extra environment file")
    must_fail(COORDINATOR, CONSOLE.replace(f"ReadWritePaths={home}/.local/state/devops-console", f"ReadWritePaths={home}/.local/state/devops-console /tmp"), "extra writable path")
    must_fail(COORDINATOR, CONSOLE.replace("DropInPaths=", "DropInPaths=/run/systemd/system/devops-console.service.d/override.conf", 1), "Console drop-in")
    must_fail(COORDINATOR, CONSOLE.replace("WorkingDirectory=/home/DevCoordinator/apps/DevOpsConsole", "WorkingDirectory=/tmp"), "Console working directory")
    must_fail(COORDINATOR, CONSOLE.replace("AmbientCapabilities=cap_net_bind_service", "AmbientCapabilities=", 1), "missing Console bind capability")
    must_fail(COORDINATOR, CONSOLE.replace("CapabilityBoundingSet=cap_net_bind_service", "CapabilityBoundingSet=cap_sys_admin", 1), "overbroad Console capability")
    must_fail(COORDINATOR, CONSOLE.replace("COORDINATOR_SCRIPT=/home/DevCoordinator/skills", f"COORDINATOR_SCRIPT={home}/holyskills/skills"), "stale Console coordinator helper")
    must_fail(COORDINATOR, CONSOLE.replace("COORDINATOR_REGISTRATION_REQUIRED=1", "COORDINATOR_REGISTRATION_REQUIRED=0"), "optional production registration")
    must_fail(COORDINATOR, CONSOLE.replace("path=/usr/bin/env", "path=/tmp/env"), "Console executable path")
    must_fail(COORDINATOR, CONSOLE.replace("ExecStart=", "MissingExecStart=", 1), "missing Console command")
    must_fail(COORDINATOR, CONSOLE.replace("ExecStartPost=", "MissingExecStartPost=", 1), "missing Console registration readiness gate")
    must_fail(COORDINATOR, CONSOLE.replace("--main-pid $MAINPID", "--main-pid 4242", 1), "Console readiness is not tied to systemd MainPID")
    must_fail(COORDINATOR, CONSOLE.replace("--wait-seconds 80", "--wait-seconds 60", 1), "Console readiness deadline drift")
    must_fail(COORDINATOR, CONSOLE.replace("/usr/bin/node --expected-script", "/tmp/node --expected-script", 1), "wrong Console runtime executable")
    must_fail(COORDINATOR, CONSOLE.replace("TimeoutStartUSec=1min 30s", "TimeoutStartUSec=infinity", 1), "unbounded Console startup")
    must_fail(COORDINATOR, CONSOLE + "ExecStartPost=" + CONSOLE.split("ExecStartPost=", 1)[1].split("\n", 1)[0] + "\n", "duplicate Console post-start command")
    must_fail(COORDINATOR, CONSOLE.replace("FragmentPath=/etc/systemd/system", "FragmentPath=/tmp"), "wrong Console fragment")

    with tempfile.TemporaryDirectory(prefix="loaded-systemd-capabilities-") as temp:
        status = Path(temp) / "status"
        status.write_text(f"Name:\tsystemd\nCapBnd:\t{MANAGER_BOUNDING:016x}\n", encoding="utf-8")
        if MODULE.manager_capability_bounding_mask(status) != MANAGER_BOUNDING:
            raise AssertionError("manager capability ceiling was parsed incorrectly")
        status.write_text("Name:\tsystemd\nCapBnd:\tnot-hex\n", encoding="utf-8")
        try:
            MODULE.manager_capability_bounding_mask(status)
        except MODULE.LoadedUnitPathError:
            pass
        else:
            raise AssertionError("malformed manager capability ceiling was accepted")
        status.write_text(
            f"Name:\tsystemd\nCapBnd:\t{1 << len(MODULE.LINUX_CAPABILITIES):016x}\n",
            encoding="utf-8",
        )
        try:
            MODULE.manager_capability_bounding_mask(status)
        except MODULE.LoadedUnitPathError:
            pass
        else:
            raise AssertionError("unknown manager capability bit was accepted")

    print("loaded systemd path self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
