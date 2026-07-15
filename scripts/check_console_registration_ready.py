#!/usr/bin/env python3
"""Wait for the systemd Console MainPID's exact coordinator registration graph."""

from __future__ import annotations

import argparse
import errno
import http.client
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, read_private_regular
from verify_post_cutover_registration import (
    RegistrationGraphError,
    current_registration_inventory_view,
    verify_current_registration_graph,
)


class ConsoleRegistrationError(RuntimeError):
    """The observed startup state is unsafe or unobservable."""


class ConsoleRegistrationTimeout(ConsoleRegistrationError):
    """Only explicitly retryable states were observed until the deadline."""


class InventoryTransportPending(ConsoleRegistrationError):
    """The loopback API transport is in one explicitly temporary state."""


def _rows(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = inventory.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ConsoleRegistrationError(f"inventory {key!r} must be a list of objects")
    return value


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def classify_registration_snapshot(
    inventory: dict[str, Any],
    *,
    project: str,
    name: str,
    port: int,
    main_pid: int,
) -> tuple[str, dict[str, Any]]:
    """Return ``ready`` or an exact retryable baseline; reject everything else."""

    try:
        inventory = current_registration_inventory_view(inventory)
    except RegistrationGraphError as error:
        raise ConsoleRegistrationError(str(error)) from error

    try:
        report = verify_current_registration_graph(
            inventory,
            project=project,
            name=name,
            port=port,
            main_pid=main_pid,
        )
    except RegistrationGraphError:
        pass
    else:
        return "ready", report

    assignments = _rows(inventory, "port_assignments")
    servers = _rows(inventory, "servers")
    leases = _rows(inventory, "leases")
    expected_key = f"{project}::{name}"
    relevant_assignments = [
        row
        for row in assignments
        if _integer(row.get("port")) == port
        or (row.get("project") == project and row.get("name") == name)
    ]
    target_servers = [
        row
        for row in servers
        if row.get("project") == project and row.get("name") == name
    ]
    current_port_servers = [
        row
        for row in servers
        if _integer(row.get("port")) == port and row.get("status") != "stopped"
    ]
    active_port_leases = [
        row for row in leases if _integer(row.get("port")) == port and row.get("status") == "active"
    ]
    active_target_leases = [
        row
        for row in leases
        if row.get("status") == "active"
        and row.get("project") == project
        and row.get("purpose") == f"server:{name}"
    ]

    if current_port_servers:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: a non-stopped server claims the Console port"
        )
    if active_port_leases or active_target_leases:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: an active lease still claims the Console port"
        )
    if not relevant_assignments and not target_servers:
        return "pending-clean-absence", {"reason": "registration graph is cleanly absent"}

    if len(relevant_assignments) != 1:
        raise ConsoleRegistrationError(
            f"unsafe registration baseline: expected one relevant assignment, found {len(relevant_assignments)}"
        )
    assignment = relevant_assignments[0]
    for key, expected in {
        "key": expected_key,
        "project": project,
        "name": name,
        "port": port,
    }.items():
        if assignment.get(key) != expected:
            raise ConsoleRegistrationError(
                f"unsafe registration baseline: assignment {key} is {assignment.get(key)!r}, expected {expected!r}"
            )
    expected_assignment_status = "stopped" if target_servers else "unregistered"
    if assignment.get("server_status") != expected_assignment_status:
        raise ConsoleRegistrationError(
            "unsafe registration baseline: assignment status is "
            f"{assignment.get('server_status')!r}, expected {expected_assignment_status!r}"
        )

    server: dict[str, Any] | None = None
    if target_servers:
        if len(target_servers) != 1:
            raise ConsoleRegistrationError(
                f"unsafe registration baseline: expected at most one target server, found {len(target_servers)}"
            )
        server = target_servers[0]
        for key, expected in {
            "key": expected_key,
            "project": project,
            "name": name,
            "port": port,
            "status": "stopped",
        }.items():
            if server.get(key) != expected:
                raise ConsoleRegistrationError(
                    f"unsafe registration baseline: stopped server {key} is {server.get(key)!r}, expected {expected!r}"
                )
        server_id = server.get("id")
        if not isinstance(server_id, str) or not server_id.strip():
            raise ConsoleRegistrationError("unsafe registration baseline: stopped server has no id")
        reused_by = server.get("port_reused_by")
        if server.get("port_reused") is True or reused_by is not None:
            if (
                server.get("port_reused") is not True
                or server.get("url_is_current") is not False
                or not isinstance(reused_by, dict)
                or reused_by.get("type") != "process"
                or _integer(reused_by.get("pid")) != main_pid
                or reused_by.get("project") != project
                or not isinstance(reused_by.get("cwd"), str)
                or not (
                    reused_by["cwd"] == project
                    or reused_by["cwd"].startswith(project.rstrip("/") + "/")
                )
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: raw port listener is not the systemd MainPID"
                )
        relocated = server.get("pid") is None and server.get("lease_id") is None
        if relocated:
            if (
                "pid" not in server
                or "lease_id" not in server
                or server.get("metadata_source") != "port_relocate"
                or not isinstance(server.get("relocated_from"), str)
                or not server.get("relocated_from")
                or server.get("relocated_from") == project
                or not isinstance(server.get("relocated_at"), str)
                or not server.get("relocated_at")
                or server.get("stopped_reason")
                != "Checkout ownership relocated; awaiting exact listener registration"
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: null PID/lease row is not exact relocation evidence"
                )
        else:
            health = server.get("health")
            if (
                not isinstance(health, dict)
                or health.get("pid_alive") is not False
                or health.get("classification")
                not in {"stopped", "unhealthy_process", "crashed_process", "stale_coordinator_metadata"}
            ):
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server is not proven process-dead"
                )
            recorded_pid = _integer(server.get("pid"))
            if recorded_pid is None or recorded_pid <= 1:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server PID history is invalid"
                )
            if recorded_pid == main_pid:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: systemd MainPID is still recorded as stopped"
                )
    else:
        server_id = None

    referenced: list[dict[str, Any]] = []
    if server is not None and server.get("lease_id") is not None:
        referenced = [row for row in leases if row.get("id") == server.get("lease_id")]
        if len(referenced) > 1:
            raise ConsoleRegistrationError(
                "unsafe registration baseline: stopped server lease reference is ambiguous"
            )
        # Stale-lease pruning removes the inactive row while intentionally
        # retaining server.lease_id as historical evidence. A missing row is
        # therefore the normal observed restart baseline, not an unproved
        # active claim. If retained history exists, it must link exactly.
        if referenced:
            lease = referenced[0]
            if lease.get("status") not in {"released", "stale_released"}:
                raise ConsoleRegistrationError(
                    "unsafe registration baseline: stopped server references a current lease"
                )
            for key, expected in {
                "project": project,
                "port": port,
                "purpose": f"server:{name}",
                "assignment_key": expected_key,
                "server_id": server_id,
            }.items():
                if lease.get(key) != expected:
                    raise ConsoleRegistrationError(
                        f"unsafe registration baseline: referenced lease {key} is {lease.get(key)!r}, expected {expected!r}"
                    )

    return "pending-stopped-baseline", {
        "reason": "exact relocated or stale stopped registration baseline",
        "server_id": server_id,
        "inactive_lease_count": len(referenced),
        "active_stale_lease_count": 0,
    }


def systemd_unit_probe(unit: str, *, systemctl: str, timeout: float) -> dict[str, Any]:
    completed = subprocess.run(
        [
            systemctl,
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
            unit,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=max(0.1, min(timeout, 3.0)),
    )
    if completed.returncode != 0:
        raise ConsoleRegistrationError(
            f"cannot observe Console systemd identity: {completed.stderr.strip() or completed.returncode}"
        )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    try:
        main_pid = int(values["MainPID"])
        active_state = values["ActiveState"]
        cgroup = values["ControlGroup"]
    except (KeyError, ValueError) as error:
        raise ConsoleRegistrationError("Console systemd identity output is incomplete") from error
    return {"main_pid": main_pid, "active_state": active_state, "cgroup": cgroup}


def _process_cgroups(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ConsoleRegistrationError(f"cannot observe Console process cgroup: {error}") from error
    result = {line.split(":", 2)[2] for line in lines if line.count(":") >= 2}
    if not result:
        raise ConsoleRegistrationError("Console process cgroup membership is empty")
    return result


def process_identity_probe(pid: int, *, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    try:
        start_ticks, argv = read_stable_process_identity(proc_root / str(pid))
    except (OSError, ProcIdentityError) as error:
        raise ConsoleRegistrationError(f"cannot observe Console process identity: {error}") from error
    if not argv:
        raise ConsoleRegistrationError("Console process argv is empty")
    try:
        cwd = os.readlink(proc_root / str(pid) / "cwd")
    except OSError as error:
        raise ConsoleRegistrationError(f"cannot observe Console process cwd: {error}") from error
    return {
        "start_ticks": start_ticks,
        "argv": argv,
        "cwd": cwd,
        "cgroups": _process_cgroups(proc_root / str(pid) / "cgroup"),
    }


def inventory_probe(
    *, host: str, port: int, token: str, timeout: float
) -> dict[str, Any]:
    connection = http.client.HTTPConnection(host, port, timeout=max(0.1, min(timeout, 3.0)))
    try:
        connection.request(
            "GET",
            "/v1/inventory/no-docker",
            headers={"Authorization": f"Bearer {token}", "Host": f"{host}:{port}"},
        )
        response = connection.getresponse()
        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        body = response.read(8 * 1024 * 1024 + 1)
    except http.client.RemoteDisconnected as error:
        raise InventoryTransportPending(
            "authenticated no-Docker inventory transport closed during startup"
        ) from error
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, TimeoutError) as error:
        raise InventoryTransportPending(
            f"authenticated no-Docker inventory transport is starting: {type(error).__name__}"
        ) from error
    except OSError as error:
        if error.errno in {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT}:
            raise InventoryTransportPending(
                f"authenticated no-Docker inventory transport is starting: {type(error).__name__}"
            ) from error
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory transport failed unsafely: {type(error).__name__}"
        ) from error
    except http.client.HTTPException as error:
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory protocol failed: {type(error).__name__}"
        ) from error
    finally:
        connection.close()
    if response.status != 200:
        raise ConsoleRegistrationError(
            f"authenticated no-Docker inventory returned HTTP {response.status}"
        )
    if content_type != "application/json" or len(body) > 8 * 1024 * 1024:
        raise ConsoleRegistrationError("authenticated no-Docker inventory response is invalid")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConsoleRegistrationError(f"authenticated no-Docker inventory JSON is invalid: {error}") from error
    if not isinstance(value, dict):
        raise ConsoleRegistrationError("authenticated no-Docker inventory root is not an object")
    try:
        projected = current_registration_inventory_view(value)
    except RegistrationGraphError as error:
        raise ConsoleRegistrationError(str(error)) from error
    docker = projected.get("docker")
    if docker != {"available": None, "containers": [], "postgres": []}:
        raise ConsoleRegistrationError("inventory endpoint did not prove the no-Docker contract")
    return projected


def _require_unit(state: dict[str, Any], *, main_pid: int, cgroup: str | None = None) -> str:
    if state.get("active_state") not in {"activating", "active"}:
        raise ConsoleRegistrationError(
            f"Console unit left startup state: {state.get('active_state')!r}"
        )
    if state.get("main_pid") != main_pid:
        raise ConsoleRegistrationError(
            f"Console systemd MainPID changed: {state.get('main_pid')!r} != {main_pid}"
        )
    observed = state.get("cgroup")
    if not isinstance(observed, str) or not observed.startswith("/"):
        raise ConsoleRegistrationError("Console systemd cgroup is invalid")
    if cgroup is not None and observed != cgroup:
        raise ConsoleRegistrationError("Console systemd cgroup changed during readiness")
    return observed


def _require_process(
    identity: dict[str, Any],
    *,
    baseline: dict[str, Any],
    cgroup: str,
    expected_argv: list[str],
    expected_working_directory: str,
) -> None:
    if identity.get("start_ticks") != baseline.get("start_ticks"):
        raise ConsoleRegistrationError("Console process start identity changed during readiness")
    if identity.get("argv") != baseline.get("argv"):
        raise ConsoleRegistrationError("Console process argv changed during readiness")
    if identity.get("argv") != expected_argv:
        raise ConsoleRegistrationError("Console MainPID argv does not match the production contract")
    if identity.get("cwd") != expected_working_directory:
        raise ConsoleRegistrationError("Console MainPID cwd does not match the production contract")
    if cgroup not in identity.get("cgroups", set()):
        raise ConsoleRegistrationError("Console MainPID is outside its systemd cgroup")


def wait_for_console_registration(
    *,
    unit: str,
    main_pid: int,
    project: str,
    name: str,
    port: int,
    token: str,
    host: str,
    coordinator_port: int,
    expected_argv: list[str],
    expected_working_directory: str,
    wait_seconds: float,
    poll_interval_seconds: float,
    systemctl: str = "/usr/bin/systemctl",
    proc_root: Path = Path("/proc"),
    unit_probe_fn: Callable[[], dict[str, Any]] | None = None,
    process_probe_fn: Callable[[], dict[str, Any]] | None = None,
    inventory_probe_fn: Callable[[float], dict[str, Any]] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if main_pid <= 1:
        raise ConsoleRegistrationError("--main-pid must be greater than one")
    if not (0 < wait_seconds <= 120) or not (0 < poll_interval_seconds <= 1):
        raise ConsoleRegistrationError("readiness wait/poll bounds are invalid")
    deadline = clock() + wait_seconds
    unit_probe_fn = unit_probe_fn or (
        lambda: systemd_unit_probe(
            unit, systemctl=systemctl, timeout=max(0.1, deadline - clock())
        )
    )
    process_probe_fn = process_probe_fn or (
        lambda: process_identity_probe(main_pid, proc_root=proc_root)
    )
    inventory_probe_fn = inventory_probe_fn or (
        lambda remaining: inventory_probe(
            host=host,
            port=coordinator_port,
            token=token,
            timeout=remaining,
        )
    )
    first_unit = unit_probe_fn()
    cgroup = _require_unit(first_unit, main_pid=main_pid)
    baseline = process_probe_fn()
    _require_process(
        baseline,
        baseline=baseline,
        cgroup=cgroup,
        expected_argv=expected_argv,
        expected_working_directory=expected_working_directory,
    )
    last_pending = "none"
    attempts = 0
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise ConsoleRegistrationTimeout(
                f"Console registration did not converge before deadline; last state={last_pending}"
            )
        attempts += 1
        _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
        _require_process(
            process_probe_fn(),
            baseline=baseline,
            cgroup=cgroup,
            expected_argv=expected_argv,
            expected_working_directory=expected_working_directory,
        )
        try:
            snapshot = inventory_probe_fn(remaining)
        except InventoryTransportPending:
            _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
            _require_process(
                process_probe_fn(),
                baseline=baseline,
                cgroup=cgroup,
                expected_argv=expected_argv,
                expected_working_directory=expected_working_directory,
            )
            last_pending = "pending-api-transport"
            remaining = deadline - clock()
            if remaining > 0:
                sleeper(min(poll_interval_seconds, remaining))
            continue
        _require_unit(unit_probe_fn(), main_pid=main_pid, cgroup=cgroup)
        _require_process(
            process_probe_fn(),
            baseline=baseline,
            cgroup=cgroup,
            expected_argv=expected_argv,
            expected_working_directory=expected_working_directory,
        )
        if clock() >= deadline:
            raise ConsoleRegistrationTimeout(
                "Console registration observation crossed the readiness deadline"
            )
        state, report = classify_registration_snapshot(
            snapshot,
            project=project,
            name=name,
            port=port,
            main_pid=main_pid,
        )
        if state == "ready":
            return {**report, "attempts": attempts, "unit": unit}
        last_pending = state
        remaining = deadline - clock()
        if remaining <= 0:
            continue
        sleeper(min(poll_interval_seconds, remaining))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--main-pid", required=True, type=int)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--coordinator-port", default=29876, type=int)
    parser.add_argument("--expected-executable", required=True)
    parser.add_argument("--expected-script", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--expected-working-directory", required=True)
    parser.add_argument("--wait-seconds", default=80.0, type=float)
    parser.add_argument("--poll-interval-seconds", default=0.1, type=float)
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.host != "127.0.0.1":
            raise ConsoleRegistrationError("coordinator host must be exact IPv4 loopback")
        token = read_private_regular(args.token_file, label="coordinator token").decode("utf-8").strip()
        if len(token) < 32 or any(character.isspace() for character in token):
            raise ConsoleRegistrationError("coordinator token is invalid")
        report = wait_for_console_registration(
            unit=args.unit,
            main_pid=args.main_pid,
            project=args.project,
            name=args.name,
            port=args.port,
            token=token,
            host=args.host,
            coordinator_port=args.coordinator_port,
            expected_argv=[
                args.expected_executable,
                args.expected_script,
                "--env-file",
                args.env_file,
            ],
            expected_working_directory=args.expected_working_directory,
            wait_seconds=args.wait_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            systemctl=args.systemctl,
        )
    except (ConsoleRegistrationError, SecureIOError, UnicodeDecodeError) as error:
        print(f"Console registration readiness failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
