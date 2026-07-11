#!/usr/bin/env python3
"""Recall, precision, and convergence tests for Console registration readiness."""

from __future__ import annotations

import copy
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


READY = load("check_console_registration_ready", ROOT / "check_console_registration_ready.py")
FIXTURES = load("post_cutover_fixture", ROOT / "self_test_post_cutover_registration.py")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def ready_fixture(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid: int = FIXTURES.MAIN_PID) -> dict:
    value = copy.deepcopy(FIXTURES.fixture())
    old_key = FIXTURES.ASSIGNMENT_KEY
    new_key = f"{project}::{FIXTURES.NAME}"
    assignment = value["port_assignments"][0]
    assignment.update({"key": new_key, "project": project, "port": port})
    server = value["servers"][0]
    server.update({"key": new_key, "project": project, "port": port, "pid": pid})
    server["registration_identity"].update(
        {"pid": pid, "cwd": f"{project}/apps/DevOpsConsole", "project": project, "port": port}
    )
    server["health"]["identity"].update(
        {"pid": pid, "cwd": f"{project}/apps/DevOpsConsole", "project": project, "port": port}
    )
    lease = value["leases"][0]
    lease.update({"project": project, "port": port, "owner_pid": pid, "assignment_key": new_key})
    for row in value["port_assignments"][1:]:
        require(row.get("key") != old_key, "unrelated fixture unexpectedly shares target key")
    return value


def stopped_server(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid=27001, lease_id=None) -> dict:
    server = copy.deepcopy(FIXTURES.fixture()["servers"][0])
    server.update(
        {
            "key": f"{project}::{FIXTURES.NAME}",
            "project": project,
            "port": port,
            "pid": pid,
            "status": "stopped",
            "lease_id": lease_id,
            "health": {"ok": False, "pid_alive": False, "classification": "stopped"},
        }
    )
    return server


def pending_assignment(*, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT) -> dict:
    return {
        "key": f"{project}::{FIXTURES.NAME}",
        "project": project,
        "name": FIXTURES.NAME,
        "port": port,
        "server_status": "stopped",
    }


def classify(value: dict, *, project: str = FIXTURES.PROJECT, port: int = FIXTURES.PORT, pid: int = FIXTURES.MAIN_PID):
    return READY.classify_registration_snapshot(
        value,
        project=project,
        name=FIXTURES.NAME,
        port=port,
        main_pid=pid,
    )


def must_fail(value: dict, contains: str, label: str) -> None:
    try:
        classify(value)
    except READY.ConsoleRegistrationError as error:
        require(contains.lower() in str(error).lower(), f"{label}: wrong error: {error}")
        return
    raise AssertionError(f"readiness guard missed unsafe state: {label}")


class FakeClock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def wait_with_snapshots(snapshots: list[object]) -> dict:
    clock = FakeClock()
    state = {"active_state": "activating", "main_pid": FIXTURES.MAIN_PID, "cgroup": "/system.slice/devops-console.service"}
    identity = {
        "start_ticks": "123456",
        "argv": ["/usr/bin/node", "bin/devops-console.mjs", "--env-file", "/private/console.env"],
        "cwd": "/home/DevCoordinator/apps/DevOpsConsole",
        "cgroups": {state["cgroup"]},
    }
    queue = list(snapshots)

    def observe(_remaining: float) -> dict:
        value = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)

    return READY.wait_for_console_registration(
        unit="devops-console.service",
        main_pid=FIXTURES.MAIN_PID,
        project=FIXTURES.PROJECT,
        name=FIXTURES.NAME,
        port=FIXTURES.PORT,
        token="x" * 64,
        host="127.0.0.1",
        coordinator_port=29876,
        expected_argv=identity["argv"],
        expected_working_directory=identity["cwd"],
        wait_seconds=5,
        poll_interval_seconds=0.1,
        unit_probe_fn=lambda: copy.deepcopy(state),
        process_probe_fn=lambda: copy.deepcopy(identity),
        inventory_probe_fn=observe,
        clock=clock,
        sleeper=clock.sleep,
    )


def real_listener_delayed_registration_test() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self").exists():
        return
    with tempfile.TemporaryDirectory(prefix="console-registration-listener-") as raw:
        project = Path(raw).resolve()
        listener = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import http.server,sys; http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),http.server.SimpleHTTPRequestHandler).serve_forever()",
                "0",
            ],
            cwd=project,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            port = None
            while time.monotonic() < deadline:
                # The port is deliberately discovered from the real listener's
                # socket inode through /proc, not invented as registration evidence.
                try:
                    links = [Path(entry).readlink() for entry in (Path("/proc") / str(listener.pid) / "fd").iterdir()]
                except OSError:
                    links = []
                inodes = {str(link)[8:-1] for link in links if str(link).startswith("socket:[")}
                if inodes:
                    tcp = Path("/proc/net/tcp").read_text(encoding="utf-8").splitlines()[1:]
                    for line in tcp:
                        fields = line.split()
                        if len(fields) > 9 and fields[9] in inodes and fields[3] == "0A":
                            port = int(fields[1].rsplit(":", 1)[1], 16)
                            break
                if port:
                    break
                time.sleep(0.02)
            require(port is not None, "real listener did not expose a bound port")
            identity = READY.process_identity_probe(listener.pid)
            cgroup = sorted(identity["cgroups"])[0]
            blank = {"port_assignments": [], "servers": [], "leases": []}
            final = ready_fixture(project=str(project), port=port, pid=listener.pid)
            sequence = [blank, blank, final]
            clock = FakeClock()

            def inventory(_remaining: float) -> dict:
                return copy.deepcopy(sequence.pop(0) if len(sequence) > 1 else sequence[0])

            report = READY.wait_for_console_registration(
                unit="fixture.service",
                main_pid=listener.pid,
                project=str(project),
                name=FIXTURES.NAME,
                port=port,
                token="x" * 64,
                host="127.0.0.1",
                coordinator_port=29876,
                expected_argv=identity["argv"],
                expected_working_directory=str(project),
                wait_seconds=5,
                poll_interval_seconds=0.1,
                unit_probe_fn=lambda: {"active_state": "activating", "main_pid": listener.pid, "cgroup": cgroup},
                process_probe_fn=lambda: READY.process_identity_probe(listener.pid),
                inventory_probe_fn=inventory,
                clock=clock,
                sleeper=clock.sleep,
            )
            require(report["attempts"] == 3, "real listener delayed registration did not retry exactly")
        finally:
            listener.terminate()
            listener.wait(timeout=5)


def actual_api_delayed_registration_test() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self").exists():
        return
    coordinator_script = ROOT.parent / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py"
    with tempfile.TemporaryDirectory(prefix="console-registration-api-") as raw:
        project = Path(raw).resolve()
        home = project / "coordinator-home"
        home.mkdir(mode=0o700)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            listener_port = int(reserved.getsockname()[1])
        listener = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import http.server,sys; http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),http.server.SimpleHTTPRequestHandler).serve_forever()",
                str(listener_port),
            ],
            cwd=project,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        original_home = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
        os.environ["CODEX_AGENT_COORDINATOR_HOME"] = str(home)
        api = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", listener_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.02)
            else:
                raise AssertionError("real registration listener did not start")
            dc = load("actual_registration_coordinator", coordinator_script)
            # Production-shaped raw ordinary-restart state: the previous
            # process died while its row still says running and its linked
            # lease is active. The authenticated no-Docker observation must
            # normalize the server to stopped and prune the stale lease before
            # readiness may classify the baseline as retryable.
            old_server_id = "restart-server-id"
            old_lease_id = "pruned-old-lease-id"
            with dc.locked_state() as state:
                state["servers"][old_server_id] = {
                    "id": old_server_id,
                    "key": f"{project}::{FIXTURES.NAME}",
                    "project": str(project),
                    "name": FIXTURES.NAME,
                    "cwd": str(project),
                    "pid": 2_147_483_647,
                    "port": listener_port,
                    "host": "127.0.0.1",
                    "status": "running",
                    "lease_id": old_lease_id,
                    "health": {"ok": True, "pid_alive": True, "classification": "healthy"},
                    "created_at": dc.iso_timestamp(),
                    "updated_at": dc.iso_timestamp(),
                }
                state["leases"][old_lease_id] = {
                    "id": old_lease_id,
                    "agent": "readiness-test",
                    "project": str(project),
                    "port": listener_port,
                    "status": "active",
                    "purpose": f"server:{FIXTURES.NAME}",
                    "server_id": old_server_id,
                    "owner_pid": 2_147_483_647,
                    "assignment_key": f"{project}::{FIXTURES.NAME}",
                    "created_at": dc.iso_timestamp(),
                    "expires_at": dc.now() + 600,
                }
                dc.record_port_assignment(
                    state,
                    agent="readiness-test",
                    project=str(project),
                    name=FIXTURES.NAME,
                    port=listener_port,
                    source="restart-fixture",
                )
            token = "a" * 64
            api = dc.BoundedThreadingHTTPServer(("127.0.0.1", 0), dc.ApiHandler, token=token)
            api_port = int(api.server_address[1])
            api_thread = threading.Thread(target=api.serve_forever, daemon=True)
            api_thread.start()
            restart_inventory = READY.inventory_probe(
                host="127.0.0.1", port=api_port, token=token, timeout=3
            )
            restart_state, _restart_report = READY.classify_registration_snapshot(
                restart_inventory,
                project=str(project),
                name=FIXTURES.NAME,
                port=listener_port,
                main_pid=listener.pid,
            )
            require(
                restart_state == "pending-stopped-baseline",
                "actual no-Docker restart baseline was not retryable",
            )
            normalized_restart = next(
                row for row in restart_inventory["servers"] if row.get("id") == old_server_id
            )
            require(
                normalized_restart.get("status") == "stopped"
                and normalized_restart.get("health", {}).get("pid_alive") is False
                and not any(row.get("id") == old_lease_id for row in restart_inventory["leases"]),
                "actual no-Docker endpoint did not normalize dead running state and prune its active lease",
            )
            require(
                normalized_restart.get("port_reused_by", {}).get("type") == "process"
                and normalized_restart.get("port_reused_by", {}).get("pid") == listener.pid,
                "actual restart observation did not bind the raw listener to the gate MainPID",
            )

            with dc.locked_state() as state:
                relocated = state["servers"][old_server_id]
                relocated.update(
                    {
                        "pid": None,
                        "lease_id": None,
                        "url": f"http://127.0.0.1:{listener_port}",
                        "health_url": f"http://127.0.0.1:{listener_port}/",
                        "metadata_source": "port_relocate",
                        "relocated_from": "/srv/legacy/holyskills",
                        "relocated_at": dc.iso_timestamp(),
                        "stopped_reason": "Checkout ownership relocated; awaiting exact listener registration",
                    }
                )
            relocated_inventory = READY.inventory_probe(
                host="127.0.0.1", port=api_port, token=token, timeout=3
            )
            relocated_row = next(
                row for row in relocated_inventory["servers"] if row.get("id") == old_server_id
            )
            require(
                relocated_row.get("health", {}).get("pid_alive") is None,
                "actual relocated observation did not reproduce pid_alive=None",
            )
            require(
                relocated_row.get("port_reused_by", {}).get("type") == "process"
                and relocated_row.get("port_reused_by", {}).get("pid") == listener.pid,
                "actual relocated observation did not bind the raw listener to the gate MainPID",
            )
            relocated_state, _relocated_report = READY.classify_registration_snapshot(
                relocated_inventory,
                project=str(project),
                name=FIXTURES.NAME,
                port=listener_port,
                main_pid=listener.pid,
            )
            require(
                relocated_state == "pending-stopped-baseline",
                "actual answering-listener relocation baseline was not retryable",
            )
            registration: dict[str, object] = {}

            def register_later() -> None:
                time.sleep(0.15)
                connection = http.client.HTTPConnection("127.0.0.1", api_port, timeout=5)
                try:
                    payload = {
                        "agent": "readiness-test",
                        "project": str(project),
                        "name": FIXTURES.NAME,
                        "cwd": str(project),
                        "pid": listener.pid,
                        "port": listener_port,
                        "url": f"http://127.0.0.1:{listener_port}",
                        "health_url": f"http://127.0.0.1:{listener_port}/",
                    }
                    connection.request(
                        "POST",
                        "/v1/servers/register",
                        body=json.dumps(payload),
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "Host": f"127.0.0.1:{api_port}",
                        },
                    )
                    response = connection.getresponse()
                    registration["status"] = response.status
                    registration["body"] = response.read().decode("utf-8", errors="replace")
                except BaseException as error:  # test thread evidence
                    registration["error"] = repr(error)
                finally:
                    connection.close()

            register_thread = threading.Thread(target=register_later, daemon=True)
            register_thread.start()
            identity = READY.process_identity_probe(listener.pid)
            cgroup = sorted(identity["cgroups"])[0]
            report = READY.wait_for_console_registration(
                unit="fixture.service",
                main_pid=listener.pid,
                project=str(project),
                name=FIXTURES.NAME,
                port=listener_port,
                token=token,
                host="127.0.0.1",
                coordinator_port=api_port,
                expected_argv=identity["argv"],
                expected_working_directory=str(project),
                wait_seconds=8,
                poll_interval_seconds=0.05,
                unit_probe_fn=lambda: {"active_state": "activating", "main_pid": listener.pid, "cgroup": cgroup},
                process_probe_fn=lambda: READY.process_identity_probe(listener.pid),
            )
            register_thread.join(timeout=5)
            require(not register_thread.is_alive(), "actual registration request did not finish")
            require(registration.get("status") == 200, f"actual registration failed: {registration}")
            require(report["server_pid"] == listener.pid and report["attempts"] >= 2, "actual API registration was not observed after delay")
        finally:
            if api is not None:
                api.shutdown()
                api.server_close()
            listener.terminate()
            listener.wait(timeout=5)
            if original_home is None:
                os.environ.pop("CODEX_AGENT_COORDINATOR_HOME", None)
            else:
                os.environ["CODEX_AGENT_COORDINATOR_HOME"] = original_home


def identity_and_deadline_tests() -> None:
    state = {"active_state": "activating", "main_pid": FIXTURES.MAIN_PID, "cgroup": "/fixture.service"}
    identity = {
        "start_ticks": "123",
        "argv": ["/usr/bin/node", "bin/devops-console.mjs", "--env-file", "/private/console.env"],
        "cwd": "/home/DevCoordinator/apps/DevOpsConsole",
        "cgroups": {state["cgroup"]},
    }
    base = dict(
        unit="devops-console.service",
        main_pid=FIXTURES.MAIN_PID,
        project=FIXTURES.PROJECT,
        name=FIXTURES.NAME,
        port=FIXTURES.PORT,
        token="x" * 64,
        host="127.0.0.1",
        coordinator_port=29876,
        expected_argv=identity["argv"],
        expected_working_directory=identity["cwd"],
        wait_seconds=5,
        poll_interval_seconds=0.1,
        process_probe_fn=lambda: copy.deepcopy(identity),
        inventory_probe_fn=lambda _remaining: ready_fixture(),
    )
    try:
        READY.wait_for_console_registration(
            **{**base, "expected_argv": ["/tmp/wrong-node"]},
            unit_probe_fn=lambda: copy.deepcopy(state),
        )
    except READY.ConsoleRegistrationError as error:
        require("argv" in str(error), f"wrong runtime argv had wrong error: {error}")
    else:
        raise AssertionError("wrong runtime argv was accepted")

    calls = 0

    def drifting_unit() -> dict:
        nonlocal calls
        calls += 1
        value = copy.deepcopy(state)
        if calls >= 2:
            value["main_pid"] += 1
        return value

    try:
        READY.wait_for_console_registration(**base, unit_probe_fn=drifting_unit)
    except READY.ConsoleRegistrationError as error:
        require("MainPID changed" in str(error), f"unit PID drift had wrong error: {error}")
    else:
        raise AssertionError("systemd MainPID drift was accepted")

    clock = FakeClock()

    def late_ready(_remaining: float) -> dict:
        clock.value += 6
        return ready_fixture()

    try:
        READY.wait_for_console_registration(
            **{
                **base,
                "unit_probe_fn": lambda: copy.deepcopy(state),
                "inventory_probe_fn": late_ready,
                "clock": clock,
                "sleeper": clock.sleep,
            }
        )
    except READY.ConsoleRegistrationTimeout as error:
        require("crossed" in str(error), f"deadline overrun had wrong error: {error}")
    else:
        raise AssertionError("ready observation crossing the global deadline was accepted")


def main() -> int:
    state, report = classify(ready_fixture())
    require(state == "ready" and report["server_pid"] == FIXTURES.MAIN_PID, "valid graph must pass")

    unrelated_history = {
        "port_assignments": [],
        "servers": [{"project": "/retired", "name": "old", "port": FIXTURES.PORT, "status": "stopped"}],
        "leases": [{"id": "old", "project": "/retired", "port": FIXTURES.PORT, "status": "stale_released"}],
    }
    require(classify(unrelated_history)[0] == "pending-clean-absence", "inactive history is not current ownership")

    relocated = copy.deepcopy(unrelated_history)
    relocated["port_assignments"] = [pending_assignment()]
    relocated_server = stopped_server(pid=None, lease_id=None)
    relocated_server.update(
        {
            "metadata_source": "port_relocate",
            "relocated_from": "/srv/legacy/holyskills",
            "relocated_at": "2026-07-11T00:00:00Z",
            "stopped_reason": "Checkout ownership relocated; awaiting exact listener registration",
            # The real no-Docker observation recomputes this from the already
            # answering new listener even though the relocated row stays stopped.
            "health": {"ok": True, "pid_alive": None, "classification": "healthy"},
        }
    )
    relocated["servers"].append(relocated_server)
    require(classify(relocated)[0] == "pending-stopped-baseline", "relocated null-lease baseline must retry")
    observed_listener = copy.deepcopy(relocated)
    observed_listener["servers"][-1].update(
        {
            "port_reused": True,
            "url_is_current": False,
            "port_reused_by": {
                "type": "process",
                "pid": FIXTURES.MAIN_PID,
                "cwd": f"{FIXTURES.PROJECT}/apps/DevOpsConsole",
                "project": FIXTURES.PROJECT,
            },
        }
    )
    require(classify(observed_listener)[0] == "pending-stopped-baseline", "exact MainPID raw listener must retry")
    foreign_listener = copy.deepcopy(observed_listener)
    foreign_listener["servers"][-1]["port_reused_by"]["pid"] = FIXTURES.MAIN_PID + 1
    must_fail(foreign_listener, "raw port listener", "foreign unregistered listener occupies Console port")

    assignment_only = {"port_assignments": [pending_assignment()], "servers": [], "leases": []}
    assignment_only["port_assignments"][0]["server_status"] = "unregistered"
    require(classify(assignment_only)[0] == "pending-stopped-baseline", "unregistered exact assignment must retry")
    contradictory_assignment = copy.deepcopy(assignment_only)
    contradictory_assignment["port_assignments"][0]["server_status"] = "stopped"
    must_fail(contradictory_assignment, "expected 'unregistered'", "assignment says stopped without server")
    contradictory_server = copy.deepcopy(relocated)
    contradictory_server["port_assignments"][0]["server_status"] = "unregistered"
    must_fail(contradictory_server, "expected 'stopped'", "assignment says unregistered with stopped server")

    restart_lease = {
        "id": "prior-restart-lease",
        "project": FIXTURES.PROJECT,
        "port": FIXTURES.PORT,
        "status": "stale_released",
        "purpose": f"server:{FIXTURES.NAME}",
        "server_id": FIXTURES.SERVER_ID,
        "owner_pid": 27001,
        "assignment_key": FIXTURES.ASSIGNMENT_KEY,
    }
    restart = {
        "port_assignments": [pending_assignment()],
        "servers": [stopped_server(lease_id=restart_lease["id"])],
        "leases": [],
    }
    require(classify(restart)[0] == "pending-stopped-baseline", "ordinary restart stale linkage must retry")

    foreign_live = copy.deepcopy(unrelated_history)
    foreign_live["servers"][0]["status"] = "running"
    must_fail(foreign_live, "non-stopped server", "foreign current port owner")
    active = copy.deepcopy(restart)
    active["leases"] = [{**restart_lease, "status": "active"}]
    must_fail(active, "active lease", "stale lease was not normalized before retry")
    wrong_pid = copy.deepcopy(restart)
    wrong_pid["servers"][0]["pid"] = FIXTURES.MAIN_PID
    must_fail(wrong_pid, "MainPID", "stopped row names current MainPID")
    live_health = copy.deepcopy(restart)
    live_health["servers"][0]["health"]["pid_alive"] = True
    must_fail(live_health, "process-dead", "stopped metadata retains a live process")
    detached = copy.deepcopy(restart)
    detached["leases"] = [{**restart_lease, "server_id": "other"}]
    must_fail(detached, "server_id", "referenced inactive lease belongs to another server")

    converged = wait_with_snapshots([
        {"port_assignments": [], "servers": [], "leases": []},
        restart,
        ready_fixture(),
    ])
    require(converged["attempts"] == 3, "clean absence and exact stopped baseline should retry")
    transported = wait_with_snapshots([
        READY.InventoryTransportPending("connection refused"),
        ready_fixture(),
    ])
    require(transported["attempts"] == 2, "explicit startup transport should retry")
    try:
        wait_with_snapshots([foreign_live])
    except READY.ConsoleRegistrationError:
        pass
    else:
        raise AssertionError("unsafe current ownership was retried")

    identity_and_deadline_tests()
    real_listener_delayed_registration_test()
    actual_api_delayed_registration_test()
    print("Console registration readiness self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
