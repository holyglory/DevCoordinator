#!/usr/bin/env python3
"""Recall and false-positive tests for retired-assignment cleanup."""

from __future__ import annotations

import copy
import fcntl
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_retired_assignment_cleanup.py"
COORDINATOR = ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("prepare_retired_assignment_cleanup", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import retired-assignment cleanup helper")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
DEAD_PIDS = [2_147_483_610, 2_147_483_611, 2_147_483_612]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def private_json(path: Path, value: Any) -> Path:
    private_directory(path.parent)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def free_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    ports: list[int] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
            ports.append(listener.getsockname()[1])
        require(len(set(ports)) == count, "fixture ports are not unique")
        return ports
    finally:
        for listener in sockets:
            listener.close()


def fixture(old: Path, target_pid: int, ports: list[int]) -> tuple[dict[str, Any], dict[str, Any]]:
    old_project = str(old.resolve())
    target = {
        "disposition": "relocate",
        "key": f"{old_project}::devops-console",
        "name": "devops-console",
        "port": ports[0],
        "source": "seed_existing_servers",
        "server_id": "server-console",
        "pid": target_pid,
        "cwd": old_project,
        "cmd": None,
        "lease_id": "lease-console",
    }
    cleanup: list[dict[str, Any]] = []
    for index, name in enumerate(("web-demo", "ws-echo-demo", "demo-web"), start=1):
        cleanup.append(
            {
                "disposition": "unassign",
                "key": f"{old_project}::{name}",
                "name": name,
                "port": ports[index],
                "source": "server_start" if name == "demo-web" else "seed_existing_servers",
                "server_id": f"server-{name}",
                "pid": DEAD_PIDS[index - 1],
                "cwd": str((old / "apps" / "DevOpsConsole").resolve()) if name == "ws-echo-demo" else old_project,
                "cmd": (
                    f"node {old_project}/apps/DevOpsConsole/test/helpers/ws-echo.mjs"
                    if name == "ws-echo-demo"
                    else f"python3 -m http.server {ports[index]} --bind 127.0.0.1"
                ),
                "lease_id": f"lease-{name}",
            }
        )
    allowlist = {
        "schema_version": 1,
        "old_project": old_project,
        "new_project": str(ROOT),
        "target": target,
        "cleanup": cleanup,
    }
    assignments = []
    servers = []
    leases = []
    for reviewed in [target, *cleanup]:
        stopped = reviewed["disposition"] == "unassign"
        assignments.append(
            {
                "key": reviewed["key"],
                "project": old_project,
                "name": reviewed["name"],
                "port": reviewed["port"],
                "source": reviewed["source"],
                "server_status": "stopped" if stopped else "running",
            }
        )
        servers.append(
            {
                "id": reviewed["server_id"],
                "key": reviewed["key"],
                "project": old_project,
                "name": reviewed["name"],
                "port": reviewed["port"],
                "pid": reviewed["pid"],
                "cwd": reviewed["cwd"],
                "cmd": reviewed["cmd"],
                "lease_id": reviewed["lease_id"],
                "status": "stopped" if stopped else "running",
                "health": {
                    "ok": not stopped,
                    "pid_alive": not stopped,
                    "classification": "stopped" if stopped else "healthy",
                },
            }
        )
        leases.append(
            {
                "id": reviewed["lease_id"],
                "project": old_project,
                "port": reviewed["port"],
                "status": "released" if stopped else "active",
                "purpose": f"server:{reviewed['name']}",
                "server_id": reviewed["server_id"],
                "assignment_key": reviewed["key"],
            }
        )
    assignments.append(
        {
            "key": "/srv/unrelated::api",
            "project": "/srv/unrelated",
            "name": "api",
            "port": ports[4],
            "source": "port_assign",
            "server_status": "running",
        }
    )
    inventory = {
        "project": None,
        "port_assignments": assignments,
        "servers": servers,
        "leases": leases,
    }
    return inventory, allowlist


def plan_from(inventory: dict[str, Any], allowlist: dict[str, Any], listeners: set[int] | None = None) -> dict[str, Any]:
    return MODULE.build_plan(
        inventory,
        allowlist,
        old_project=allowlist["old_project"],
        new_project=allowlist["new_project"],
        target_name="devops-console",
        target_port=allowlist["target"]["port"],
        listener_ports=listeners or set(),
        inventory_sha256="1" * 64,
        allowlist_sha256="2" * 64,
    )


def must_plan_fail(
    inventory: dict[str, Any],
    allowlist: dict[str, Any],
    change: Callable[[dict[str, Any], dict[str, Any]], None],
    contains: str,
    label: str,
    *,
    listeners: set[int] | None = None,
) -> None:
    changed_inventory = copy.deepcopy(inventory)
    changed_allowlist = copy.deepcopy(allowlist)
    change(changed_inventory, changed_allowlist)
    try:
        plan_from(changed_inventory, changed_allowlist, listeners)
    except MODULE.RetiredAssignmentError as error:
        require(contains.lower() in str(error).lower(), f"{label}: wrong failure: {error}")
        return
    raise AssertionError(f"planner missed realistic failure: {label}")


def raw_state(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 9,
        "revision": 41,
        "updated_at": "2026-07-11T00:00:00Z",
        "leases": {row["id"]: copy.deepcopy(row) for row in inventory["leases"]},
        "servers": {row["id"]: copy.deepcopy(row) for row in inventory["servers"]},
        "port_assignments": {row["key"]: {key: copy.deepcopy(value) for key, value in row.items() if key != "server_status"} for row in inventory["port_assignments"]},
        "operations": {},
        "history": [],
        "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
    }


def apply_command(plan_path: Path, home: Path, output: Path) -> list[str]:
    return [
        sys.executable,
        str(SCRIPT),
        "apply",
        "--plan",
        str(plan_path),
        "--coordinator-script",
        str(COORDINATOR),
        "--coordinator-home",
        str(home),
        "--agent",
        "cutover-test",
        "--output",
        str(output),
    ]


def legacy_fixture_environment() -> dict[str, str]:
    """Keep this historical state.json fixture outside the product backend."""

    environment = dict(os.environ)
    environment["DEVCOORDINATOR_STATE_BACKEND"] = "legacy-json-test-only"
    return environment


def run_apply(case: Path, state: dict[str, Any], plan: dict[str, Any]) -> tuple[subprocess.CompletedProcess[str], bytes, bytes]:
    private_directory(case)
    home = private_directory(case / "coordinator")
    state_path = private_json(home / "state.json", state)
    plan_path = private_json(case / "plan.json", plan)
    output = case / "result.json"
    before = state_path.read_bytes()
    completed = subprocess.run(
        apply_command(plan_path, home, output),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=legacy_fixture_environment(),
    )
    return completed, before, state_path.read_bytes()


def require_apply_failure(
    root: Path,
    name: str,
    state: dict[str, Any],
    plan: dict[str, Any],
    contains: str,
) -> None:
    completed, before, after = run_apply(root / name, state, plan)
    require(completed.returncode != 0, f"{name}: unsafe apply unexpectedly succeeded")
    require(contains.lower() in completed.stderr.lower(), f"{name}: wrong error: {completed.stderr}")
    require(before == after, f"{name}: failed apply changed state bytes")


def main() -> int:
    # macOS exposes /var as a symlink to /private/var. Production evidence
    # deliberately rejects any symlink in its parent chain. A checkout-local
    # fixture would also canonicalize to the repository root, so use HOME.
    with tempfile.TemporaryDirectory(prefix=".retired-assignment-self-test-", dir=Path.home()) as raw:
        root = private_directory(Path(raw))
        old = private_directory(root / "legacy")
        private_directory(old / "apps" / "DevOpsConsole")
        ports = free_ports(5)
        target_process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            inventory, allowlist = fixture(old, target_process.pid, ports)
            valid_plan = plan_from(inventory, allowlist)
            require(len(valid_plan["cleanup"]) == 3, "exact three-row cleanup plan should pass")
            require(
                any(row.get("project") == "/srv/unrelated" for row in inventory["port_assignments"]),
                "valid fixture must prove unrelated current assignments are accepted",
            )

            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv.update({"project": allowlist["old_project"]}),
                "global",
                "project-filtered inventory",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["port_assignments"].append(
                    {
                        "key": f"{allowlist['old_project']}::unknown",
                        "project": allowlist["old_project"],
                        "name": "unknown",
                        "port": ports[4] + 1,
                        "source": "server_start",
                        "server_status": "stopped",
                    }
                ),
                "assignment set",
                "extra stopped assignment",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["port_assignments"].pop(1),
                "assignment set",
                "missing reviewed assignment",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["port_assignments"][1].update({"port": ports[1] + 9}),
                "port drifted",
                "same name repinned to another port",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["port_assignments"][1].update({"server_status": "running"}),
                "not stopped",
                "cleanup server became current",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["leases"].append(
                    {
                        "id": "foreign-active",
                        "project": "/srv/foreign",
                        "port": ports[1],
                        "status": "active",
                    }
                ),
                "active lease",
                "foreign active lease on cleanup port",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["servers"][1].update({"cmd": "python3 changed.py"}),
                "cmd drifted",
                "cleanup command drift",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda inv, _allow: inv["servers"][1].update({"cwd": "/srv/elsewhere"}),
                "cwd drifted",
                "cleanup cwd drift",
            )

            def live_cleanup_pid(inv: dict[str, Any], reviewed: dict[str, Any]) -> None:
                reviewed["cleanup"][0]["pid"] = os.getpid()
                inv["servers"][1]["pid"] = os.getpid()

            must_plan_fail(
                inventory,
                allowlist,
                live_cleanup_pid,
                "alive or reused",
                "cleanup PID was reused",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda _inv, reviewed: reviewed["cleanup"][0].update({"disposition": "keep"}),
                "disposition",
                "unknown cleanup disposition",
            )
            wrong_target_port = next(value for value in range(65000, 65536) if value not in ports)
            must_plan_fail(
                inventory,
                allowlist,
                lambda _inv, reviewed: reviewed["target"].update({"port": wrong_target_port}),
                "port drifted",
                "wrong-port relocation target",
            )
            must_plan_fail(
                inventory,
                allowlist,
                lambda _inv, _reviewed: None,
                "TCP listener",
                "cleanup port has a listener",
                listeners={ports[2]},
            )

            tcp4 = root / "tcp"
            tcp6 = root / "tcp6"
            tcp4.write_text("  sl  local_address rem_address   st\n", encoding="utf-8")
            tcp6.write_text("  sl  local_address rem_address   st\n", encoding="utf-8")
            tcp4.chmod(0o600)
            tcp6.chmod(0o600)
            inventory_path = private_json(root / "inventory.json", inventory)
            allowlist_path = private_json(root / "allowlist.json", allowlist)
            plan_output = root / "planned.json"
            planned = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "plan",
                    "--inventory",
                    str(inventory_path),
                    "--allowlist",
                    str(allowlist_path),
                    "--output",
                    str(plan_output),
                    "--old-project",
                    allowlist["old_project"],
                    "--new-project",
                    str(ROOT),
                    "--target-name",
                    "devops-console",
                    "--target-port",
                    str(ports[0]),
                    "--proc-tcp-table",
                    str(tcp4),
                    "--proc-tcp-table",
                    str(tcp6),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            require(planned.returncode == 0, f"real plan CLI failed: {planned.stderr}")
            require(stat.S_IMODE(plan_output.stat().st_mode) == 0o600, "plan output is not private")
        finally:
            target_process.terminate()
            target_process.wait(timeout=10)

        state = raw_state(inventory)
        successful, _before, after = run_apply(root / "apply-success", state, valid_plan)
        require(successful.returncode == 0, f"valid atomic apply failed: {successful.stderr}")
        applied_state = json.loads(after)
        old_keys = {
            key
            for key, row in applied_state["port_assignments"].items()
            if row.get("project") == allowlist["old_project"]
        }
        require(old_keys == {allowlist["target"]["key"]}, "apply did not remove exactly three residues")
        require(
            applied_state["port_assignments"]["/srv/unrelated::api"]
            == state["port_assignments"]["/srv/unrelated::api"],
            "apply changed an unrelated assignment",
        )

        extra_state = copy.deepcopy(state)
        extra_state["port_assignments"][f"{allowlist['old_project']}::extra"] = {
            "key": f"{allowlist['old_project']}::extra",
            "project": allowlist["old_project"],
            "name": "extra",
            "port": ports[4] + 1,
            "source": "server_start",
        }
        require_apply_failure(root, "apply-extra", extra_state, valid_plan, "assignment set drifted")

        repinned = copy.deepcopy(state)
        repinned["port_assignments"][allowlist["cleanup"][0]["key"]]["port"] += 7
        require_apply_failure(root, "apply-repinned", repinned, valid_plan, "port drifted")

        active_second = copy.deepcopy(state)
        active_second["leases"]["foreign-second"] = {
            "id": "foreign-second",
            "project": "/srv/foreign",
            "port": allowlist["cleanup"][1]["port"],
            "status": "active",
        }
        require_apply_failure(root, "apply-active-second", active_second, valid_plan, "active lease")

        pending = copy.deepcopy(state)
        pending["operations"]["pending-second"] = {
            "id": "pending-second",
            "status": "pending",
            "project": allowlist["old_project"],
            "target": f"server:{allowlist['cleanup'][1]['key']}",
        }
        require_apply_failure(root, "apply-pending", pending, valid_plan, "pending coordinator operation")

        malformed = copy.deepcopy(valid_plan)
        malformed["unexpected"] = True
        require_apply_failure(root, "apply-malformed", state, malformed, "unknown fields")

        concurrent_case = private_directory(root / "apply-concurrent-drift")
        concurrent_home = private_directory(concurrent_case / "coordinator")
        concurrent_state_path = private_json(concurrent_home / "state.json", state)
        concurrent_plan_path = private_json(concurrent_case / "plan.json", valid_plan)
        concurrent_output = concurrent_case / "result.json"
        lock_fd = os.open(concurrent_home / "state.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        waiting = subprocess.Popen(
            apply_command(concurrent_plan_path, concurrent_home, concurrent_output),
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=legacy_fixture_environment(),
        )
        time.sleep(0.1)
        require(waiting.poll() is None, "cleanup apply did not wait for the coordinator state lock")
        concurrent_state = copy.deepcopy(state)
        concurrent_state["port_assignments"][allowlist["cleanup"][1]["key"]]["port"] += 17
        private_json(concurrent_state_path, concurrent_state)
        concurrent_bytes = concurrent_state_path.read_bytes()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        _stdout, concurrent_stderr = waiting.communicate(timeout=10)
        require(waiting.returncode != 0, "post-lock assignment drift unexpectedly succeeded")
        require("port drifted" in concurrent_stderr, f"post-lock drift failure was unclear: {concurrent_stderr}")
        require(
            concurrent_state_path.read_bytes() == concurrent_bytes,
            "failed post-lock revalidation overwrote the concurrent state",
        )

        live_pid_plan = copy.deepcopy(valid_plan)
        live_pid_state = copy.deepcopy(state)
        live_pid_plan["cleanup"][1]["pid"] = os.getpid()
        live_pid_state["servers"][allowlist["cleanup"][1]["server_id"]]["pid"] = os.getpid()
        require_apply_failure(root, "apply-live-pid", live_pid_state, live_pid_plan, "alive or reused")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", allowlist["cleanup"][2]["port"]))
        listener.listen(1)
        try:
            require_apply_failure(root, "apply-listener", state, valid_plan, "live listener")
        finally:
            listener.close()

        coordinator_module = MODULE.load_coordinator(COORDINATOR, expected_root=str(ROOT))

        class FailSecondMutation:
            def __init__(self) -> None:
                self.calls = 0

            pid_alive = staticmethod(coordinator_module.pid_alive)
            listener_evidence_for_port = staticmethod(coordinator_module.listener_evidence_for_port)

            def unassign_port(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError("injected second mutation failure")
                return coordinator_module.unassign_port(*args, **kwargs)

        original = copy.deepcopy(state)
        try:
            MODULE.build_atomic_cleanup_state(state, valid_plan, FailSecondMutation(), agent="test")
        except RuntimeError as error:
            require("injected second" in str(error), f"wrong injected failure: {error}")
        else:
            raise AssertionError("injected second mutation unexpectedly succeeded")
        require(state == original, "second-item mutation failure changed the original state")

    print("retired assignment cleanup self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
