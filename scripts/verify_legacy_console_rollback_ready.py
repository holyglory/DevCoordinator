#!/usr/bin/env python3
"""Wait for the exact restored legacy Console topology to become ready."""

from __future__ import annotations

import argparse
import http.client
import json
import math
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, read_private_regular
from verify_legacy_cutover_boundary import BoundaryError, LedgerWriter, verify_ledger_pair
from verify_post_cutover_registration import (
    RegistrationGraphError,
    verify_current_registration_graph,
)


class RollbackReadinessError(RuntimeError):
    """The restored service cannot be proved safe and ready."""


class RollbackReadinessTimeout(RollbackReadinessError):
    """The restored service stayed in a retryable startup state too long."""


class RollbackReadinessInterrupted(RollbackReadinessError):
    """A handled process signal interrupted rollback readiness observation."""


UnitProbe = Callable[[float], dict[str, object]]
ListenerProbe = Callable[[tuple[int, ...], float], str]
HealthProbe = Callable[[str, float], dict[str, object]]
InventoryProbe = Callable[[str, float], dict[str, Any]]

MAX_INVENTORY_BYTES = 8 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(
    command: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def systemd_unit_probe(
    *,
    unit: str,
    timeout: float = 5.0,
    systemctl: str = "/usr/bin/systemctl",
) -> dict[str, object]:
    completed = _run(
        [
            systemctl,
            "show",
            unit,
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
        ],
        timeout=max(0.1, min(timeout, 5.0)),
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise RollbackReadinessError(f"cannot observe restored systemd unit: {detail}")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    try:
        main_pid = int(values["MainPID"])
        active_state = values["ActiveState"]
        cgroup = values["ControlGroup"]
    except (KeyError, ValueError) as error:
        raise RollbackReadinessError("restored systemd identity output is incomplete") from error
    return {"active_state": active_state, "main_pid": main_pid, "cgroup": cgroup}


def privileged_listener_probe(
    ports: tuple[int, ...],
    *,
    timeout: float = 5.0,
    sudo: str = "/usr/bin/sudo",
    ss: str = "/usr/bin/ss",
) -> str:
    expression = "( " + " or ".join(f"sport = :{port}" for port in ports) + " )"
    completed = _run(
        [sudo, "-n", ss, "-H", "-ltnp", expression],
        timeout=max(0.1, min(timeout, 5.0)),
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise RollbackReadinessError(
            f"privileged listener ownership is unobservable: {detail}"
        )
    return completed.stdout


def curl_health_probe(
    url: str,
    timeout: float,
    *,
    curl: str = "/usr/bin/curl",
) -> dict[str, object]:
    request_timeout = max(0.1, min(timeout, 3.0))
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise RollbackReadinessError("public health URL has no hostname")
    completed = _run(
        [
            curl,
            "--disable",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--noproxy",
            "*",
            "--resolve",
            f"{host}:443:127.0.0.1",
            "--connect-timeout",
            f"{request_timeout:g}",
            "--max-time",
            f"{request_timeout:g}",
            "--write-out",
            "status=%{http_code} tls=%{ssl_verify_result} remote=%{remote_ip}\n",
            url,
        ],
        timeout=request_timeout + 1,
    )
    if completed.returncode != 0:
        retryable_codes = {7, 28, 35, 52, 55, 56}
        return {
            "transport": "unavailable",
            "retryable": completed.returncode in retryable_codes,
            "curl_code": completed.returncode,
            "error": completed.stderr.strip()[-500:],
        }
    match = re.fullmatch(
        r"status=(\d{3}) tls=(\d+) remote=([^\s]+)\n?",
        completed.stdout,
    )
    if match is None:
        raise RollbackReadinessError("public health output is unparseable")
    return {
        "transport": "ok",
        "retryable": False,
        "status": int(match.group(1)),
        "tls_verify_result": int(match.group(2)),
        "remote_ip": match.group(3),
    }


def validate_legacy_inventory_url(url: str) -> int:
    """Return the coupled coordinator port for one credential-free loopback URL."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise RollbackReadinessError("legacy inventory URL is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/inventory"
        or parsed.query
        or parsed.fragment
        or port is None
        or parsed.netloc != f"127.0.0.1:{port}"
    ):
        raise RollbackReadinessError(
            "legacy inventory URL must be credential-free IPv4 loopback HTTP "
            "with an explicit port and exact /v1/inventory path"
        )
    return port


def credential_free_inventory_probe(url: str, timeout: float) -> dict[str, Any]:
    """Fetch legacy inventory without sending authentication or persisting its body."""

    port = validate_legacy_inventory_url(url)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(
            "GET",
            "/v1/inventory",
            headers={"Accept": "application/json"},
        )
        response = connection.getresponse()
        content_type = (
            response.getheader("Content-Type") or ""
        ).split(";", 1)[0].strip().lower()
        body = response.read(MAX_INVENTORY_BYTES + 1)
    except http.client.HTTPException as error:
        raise RollbackReadinessError(
            f"legacy inventory HTTP protocol failed: {type(error).__name__}"
        ) from error
    except OSError as error:
        raise RollbackReadinessError(
            f"legacy inventory transport failed: {type(error).__name__}"
        ) from error
    finally:
        connection.close()
    if response.status != 200:
        raise RollbackReadinessError(
            f"legacy inventory returned HTTP {response.status}, expected 200"
        )
    if content_type != "application/json":
        raise RollbackReadinessError("legacy inventory Content-Type is not application/json")
    if len(body) > MAX_INVENTORY_BYTES:
        raise RollbackReadinessError("legacy inventory response exceeds the safe size limit")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackReadinessError("legacy inventory JSON is invalid") from error
    if not isinstance(value, dict):
        raise RollbackReadinessError("legacy inventory JSON root must be an object")
    return value


def read_expected_identities(path: Path) -> tuple[str, str]:
    try:
        raw = read_private_regular(path, label="pre-cutover expected identities")
        value = json.loads(raw.decode("utf-8"))
    except (SecureIOError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackReadinessError(
            "pre-cutover expected identities are unreadable or invalid"
        ) from error
    if not isinstance(value, dict):
        raise RollbackReadinessError(
            "pre-cutover expected identities JSON root must be an object"
        )
    server_id = value.get("server_id")
    if (
        not isinstance(server_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", server_id)
    ):
        raise RollbackReadinessError(
            "pre-cutover expected identities must contain one safe non-empty server_id"
        )
    lease_id = value.get("lease_id")
    if (
        not isinstance(lease_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", lease_id)
    ):
        raise RollbackReadinessError(
            "pre-cutover expected identities must contain one safe non-empty lease_id"
        )
    return server_id, lease_id


def _inventory_rows(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = inventory.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise RollbackReadinessError(
            "legacy registration inventory has a malformed required row collection"
        )
    return value


def _inventory_integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _inside_project(value: Any, project: str) -> bool:
    return isinstance(value, str) and (
        value == project or value.startswith(project.rstrip("/") + "/")
    )


def classify_legacy_registration_snapshot(
    inventory: dict[str, Any],
    *,
    project: str,
    name: str,
    port: int,
    main_pid: int,
    expected_server_id: str,
    expected_lease_id: str,
) -> tuple[str, dict[str, Any]]:
    """Accept the exact graph or the one exact stopped precursor."""

    try:
        report = verify_current_registration_graph(
            inventory,
            project=project,
            name=name,
            port=port,
            main_pid=main_pid,
            expected_server_id=expected_server_id,
            schema_contract="legacy",
        )
    except RegistrationGraphError:
        pass
    else:
        if report.get("lease_id") == expected_lease_id or any(
            row.get("id") == expected_lease_id
            for row in inventory.get("leases", [])
        ):
            raise RollbackReadinessError(
                "unsafe legacy registration graph: captured lease survived the ready graph"
            )
        return "ready", report

    assignments = _inventory_rows(inventory, "port_assignments")
    servers = _inventory_rows(inventory, "servers")
    leases = _inventory_rows(inventory, "leases")
    expected_key = f"{project}::{name}"
    relevant_assignments = [
        row
        for row in assignments
        if _inventory_integer(row.get("port")) == port
        or (row.get("project") == project and row.get("name") == name)
    ]
    target_servers = [
        row for row in servers if row.get("project") == project and row.get("name") == name
    ]
    captured_id_rows = [row for row in servers if row.get("id") == expected_server_id]
    current_port_servers = [
        row
        for row in servers
        if _inventory_integer(row.get("port")) == port and row.get("status") != "stopped"
    ]
    current_target_servers = [row for row in target_servers if row.get("status") != "stopped"]
    active_relevant_leases = [
        row
        for row in leases
        if row.get("status") == "active"
        and (
            _inventory_integer(row.get("port")) == port
            or row.get("server_id") == expected_server_id
            or (
                row.get("project") == project
                and row.get("purpose") == f"server:{name}"
            )
        )
    ]

    # Registration is persisted atomically. Any current claim that failed the
    # exact shared verifier is a conflict, never a partially complete write.
    if current_port_servers or current_target_servers:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: a current server failed exact identity validation"
        )
    if active_relevant_leases:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: a relevant active lease survived locked-state pruning"
        )
    if len(captured_id_rows) > 1:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: captured server identity is ambiguous"
        )

    if not relevant_assignments and not target_servers:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: captured server identity is absent"
        )

    if len(relevant_assignments) != 1:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: relevant durable assignment is ambiguous"
        )
    assignment = relevant_assignments[0]
    for key, expected in {
        "key": expected_key,
        "project": project,
        "name": name,
        "port": port,
    }.items():
        if assignment.get(key) != expected:
            raise RollbackReadinessError(
                "unsafe legacy registration graph: durable assignment identity conflicts"
            )

    if not target_servers:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: assignment has lost the captured server identity"
        )

    if len(target_servers) != 1:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: target stopped server is ambiguous"
        )
    server = target_servers[0]
    for key, expected in {
        "id": expected_server_id,
        "key": expected_key,
        "project": project,
        "name": name,
        "port": port,
        "status": "stopped",
    }.items():
        if server.get(key) != expected:
            raise RollbackReadinessError(
                "unsafe legacy registration graph: stopped server identity conflicts"
            )
    if captured_id_rows != [server]:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: captured server identity is detached"
        )
    if assignment.get("server_status") != "stopped":
        raise RollbackReadinessError(
            "unsafe legacy registration graph: stopped assignment status conflicts"
        )
    if not _inside_project(server.get("cwd"), project):
        raise RollbackReadinessError(
            "unsafe legacy registration graph: stopped server cwd is outside the project"
        )
    recorded_pid = _inventory_integer(server.get("pid"))
    if recorded_pid is None or recorded_pid <= 1 or recorded_pid == main_pid:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: stopped server PID conflicts"
        )
    health = server.get("health")
    expected_stopped_health = {
        "ok": False,
        "pid_alive": False,
        "classification": "stopped",
        "check": {"ok": False, "skipped": "recorded process is not alive"},
        "identity": {
            "ok": True,
            "skipped": "not checked because recorded process is not alive",
        },
    }
    if health != expected_stopped_health:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: stopped health is not the exact 40a dead-process proof"
        )

    lease_id = server.get("lease_id")
    if lease_id != expected_lease_id:
        raise RollbackReadinessError(
            "unsafe legacy registration graph: stopped server lost the captured lease identity"
        )
    if any(row.get("id") == expected_lease_id for row in leases):
        raise RollbackReadinessError(
            "unsafe legacy registration graph: captured lease reference is not dangling after pruning"
        )

    return "pending-stopped-baseline", {
        "reason": "exact captured legacy server is stopped with its pruned lease dangling",
        "server_id": expected_server_id,
        "captured_lease_id": expected_lease_id,
        "recorded_dead_pid": recorded_pid,
        "dangling_captured_lease": True,
    }


def _read_members(path: Path) -> list[int]:
    try:
        members = [int(raw) for raw in path.read_text(encoding="utf-8").splitlines() if raw.strip()]
    except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
        raise RollbackReadinessError(f"restored cgroup membership is unobservable: {error}") from error
    if any(pid <= 1 for pid in members) or len(set(members)) != len(members):
        raise RollbackReadinessError("restored cgroup contains an invalid or duplicate PID")
    return sorted(members)


def _read_identity(proc_root: Path, pid: int) -> dict[str, object]:
    try:
        start_ticks, command = read_stable_process_identity(proc_root / str(pid))
    except (FileNotFoundError, ProcessLookupError, PermissionError, ProcIdentityError, OSError) as error:
        return {
            "pid": pid,
            "status": "unavailable",
            "error": f"{type(error).__name__}: {error}",
        }
    return {
        "pid": pid,
        "status": "captured",
        "start_ticks": start_ticks,
        "command": command,
    }


def _captured_identity(record: dict[str, object], *, role: str) -> tuple[str, list[str]]:
    if record.get("status") != "captured":
        raise RollbackReadinessError(
            f"restored {role} process identity is unobservable: {record.get('error', 'unknown error')}"
        )
    start_ticks = record.get("start_ticks")
    command = record.get("command")
    if not isinstance(start_ticks, str) or not start_ticks.isdigit():
        raise RollbackReadinessError(f"restored {role} start identity is invalid")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        raise RollbackReadinessError(f"restored {role} argv identity is invalid")
    return start_ticks, command


def _is_legacy_coordinator(
    command: list[str], old_coordinator_script: str, coordinator_port: int
) -> bool:
    return (
        len(command) == 8
        and Path(command[0]).name == "python3"
        and command[1:] == [
            old_coordinator_script,
            "api",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(coordinator_port),
        ]
    )


def _is_legacy_console(command: list[str]) -> bool:
    return len(command) == 2 and Path(command[0]).name == "node" and command[1] == "bin/devops-console.mjs"


def _remaining_seconds(*, deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise RollbackReadinessTimeout(
            "restored legacy Console did not become ready before the readiness deadline"
        )
    return remaining


def _parse_listener_owners(
    snapshot: str,
    *,
    ports: tuple[int, ...],
) -> tuple[dict[int, list[int]], list[int]]:
    observed: dict[int, set[int]] = {port: set() for port in ports}
    present: set[int] = set()
    for line in snapshot.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        local = fields[3]
        if ":" not in local:
            continue
        raw_port = local.rsplit(":", 1)[1]
        if not raw_port.isdigit() or int(raw_port) not in observed:
            continue
        port = int(raw_port)
        present.add(port)
        owners = {int(raw) for raw in re.findall(r"pid=(\d+),", line)}
        if not owners:
            raise RollbackReadinessError(
                f"restored listener ownership on port {port} is unparseable"
            )
        observed[port].update(owners)
    missing = sorted(set(ports) - present)
    normalized = {port: sorted(owners) for port, owners in observed.items() if port in present}
    return normalized, missing


def _require_present_listener_owners(
    observed: dict[int, list[int]],
    *,
    expected: dict[int, int],
) -> None:
    for port, wanted in expected.items():
        if port not in observed:
            continue
        owners = observed[port]
        if owners != [wanted]:
            qualifier = "ambiguous" if len(owners) > 1 else "wrong"
            raise RollbackReadinessError(
                f"restored listener ownership on port {port} is {qualifier}: "
                f"observed {owners}, expected only PID {wanted}"
            )


def _require_fixed_unit(
    state: dict[str, object],
    *,
    expected_main_pid: int,
    expected_cgroup: str,
) -> None:
    if state.get("active_state") != "active":
        raise RollbackReadinessError(
            f"restored unit left active state: {state.get('active_state')}"
        )
    if state.get("main_pid") != expected_main_pid:
        raise RollbackReadinessError(
            f"restored unit MainPID changed: {state.get('main_pid')} != {expected_main_pid}"
        )
    if state.get("cgroup") != expected_cgroup:
        raise RollbackReadinessError(
            f"restored unit cgroup changed: {state.get('cgroup')} != {expected_cgroup}"
        )


def _confirm_fixed_topology(
    *,
    unit_probe: UnitProbe,
    members_path: Path,
    proc_root: Path,
    expected_main_pid: int,
    expected_cgroup: str,
    main_identity: dict[str, object],
    coordinator_identity: dict[str, object],
    deadline: float,
    clock: Callable[[], float],
    report: dict[str, object],
) -> bool:
    state = unit_probe(_remaining_seconds(deadline=deadline, clock=clock))
    report["unit"] = state
    _remaining_seconds(deadline=deadline, clock=clock)
    _require_fixed_unit(
        state,
        expected_main_pid=expected_main_pid,
        expected_cgroup=expected_cgroup,
    )
    coordinator_pid = int(coordinator_identity["pid"])
    expected_members = {expected_main_pid, coordinator_pid}
    members_before = _read_members(members_path)
    report["members_before"] = members_before
    if not expected_members.issubset(members_before):
        raise RollbackReadinessError("a fixed restored process left its cgroup during readiness confirmation")
    records = [_read_identity(proc_root, pid) for pid in members_before]
    report["processes"] = records
    by_pid = {int(record["pid"]): record for record in records}
    if _captured_identity(by_pid[expected_main_pid], role="Console main") != _captured_identity(
        main_identity, role="Console main baseline"
    ):
        raise RollbackReadinessError("restored Console MainPID start/argv identity changed")
    if _captured_identity(by_pid[coordinator_pid], role="coordinator") != _captured_identity(
        coordinator_identity, role="coordinator baseline"
    ):
        raise RollbackReadinessError("restored coordinator PID start/argv identity changed")
    members_after = _read_members(members_path)
    report["members_after"] = members_after
    if not expected_members.issubset(members_after):
        raise RollbackReadinessError("a fixed restored process left its cgroup during readiness confirmation")
    confirmed_main = _read_identity(proc_root, expected_main_pid)
    confirmed_coordinator = _read_identity(proc_root, coordinator_pid)
    report["confirmed_processes"] = [confirmed_main, confirmed_coordinator]
    if _captured_identity(confirmed_main, role="confirmed Console main") != _captured_identity(
        main_identity, role="Console main baseline"
    ):
        raise RollbackReadinessError("restored Console identity changed during readiness confirmation")
    if _captured_identity(
        confirmed_coordinator, role="confirmed coordinator"
    ) != _captured_identity(coordinator_identity, role="coordinator baseline"):
        raise RollbackReadinessError("restored coordinator identity changed during readiness confirmation")
    _remaining_seconds(deadline=deadline, clock=clock)
    exact = members_before == members_after and set(members_after) == expected_members
    return exact


def wait_for_legacy_console_rollback(
    *,
    unit: str,
    expected_main_pid: int,
    expected_cgroup: str,
    old_coordinator_script: str,
    health_url: str,
    inventory_url: str,
    expected_server_id: str,
    expected_lease_id: str,
    registration_project: str,
    registration_name: str,
    registration_port: int,
    evidence_path: Path,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.1,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    unit_probe: UnitProbe,
    listener_probe: ListenerProbe,
    health_probe: HealthProbe,
    inventory_probe: InventoryProbe,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    if not unit or expected_main_pid <= 1:
        raise RollbackReadinessError("restored unit and MainPID must be explicit")
    if not expected_cgroup.startswith("/") or ".." in Path(expected_cgroup).parts:
        raise RollbackReadinessError("restored cgroup must be an absolute cgroup path")
    if not old_coordinator_script.startswith("/"):
        raise RollbackReadinessError("legacy coordinator script must be an absolute path")
    coordinator_port = validate_legacy_inventory_url(inventory_url)
    if (
        not registration_project.startswith("/")
        or ".." in Path(registration_project).parts
    ):
        raise RollbackReadinessError("legacy registration project must be an absolute safe path")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", registration_name):
        raise RollbackReadinessError("legacy registration name is invalid")
    if registration_port != 443:
        raise RollbackReadinessError(
            "legacy Console registration port must match the proven public TLS listener on 443"
        )
    if (
        not isinstance(expected_server_id, str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", expected_server_id
        )
    ):
        raise RollbackReadinessError("captured legacy server id is invalid")
    if (
        not isinstance(expected_lease_id, str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", expected_lease_id
        )
    ):
        raise RollbackReadinessError("captured legacy lease id is invalid")
    try:
        parsed_health = urlsplit(health_url)
        health_hostname = parsed_health.hostname
        health_port = parsed_health.port
    except ValueError as error:
        raise RollbackReadinessError("rollback health URL is invalid") from error
    if (
        parsed_health.scheme != "https"
        or not health_hostname
        or parsed_health.username is not None
        or parsed_health.password is not None
        or parsed_health.fragment
        or parsed_health.query
        or parsed_health.path != "/healthz"
        or health_port not in {None, 443}
    ):
        raise RollbackReadinessError(
            "rollback health URL must be credential-free HTTPS without a fragment"
        )
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 120:
        raise RollbackReadinessError("rollback readiness timeout must be in (0, 120]")
    if (
        not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds < 0.01
        or poll_interval_seconds > 1
    ):
        raise RollbackReadinessError("rollback readiness poll interval must be in [0.01, 1]")

    writer = LedgerWriter(evidence_path)
    started = clock()
    deadline = started + timeout_seconds
    ledger: dict[str, object] = {
        "schema_version": 2,
        "status": "running",
        "started_at": utc_now(),
        "unit": unit,
        "expected_main_pid": expected_main_pid,
        "expected_cgroup": expected_cgroup,
        "old_coordinator_script": old_coordinator_script,
        "health_url": health_url,
        "inventory_url": inventory_url,
        "expected_server_id": expected_server_id,
        "expected_lease_id": expected_lease_id,
        "registration_project": registration_project,
        "registration_name": registration_name,
        "registration_port": registration_port,
        "coordinator_port": coordinator_port,
        "timeout_seconds": timeout_seconds,
        "poll_interval_seconds": poll_interval_seconds,
        "observations": [],
    }
    coordinator_identity: dict[str, object] | None = None
    main_identity: dict[str, object] | None = None

    def finish_failure(error: BaseException, *, status: str) -> None:
        ledger["status"] = status
        ledger["finished_at"] = utc_now()
        ledger["error"] = f"{type(error).__name__}: {error}"
        writer.write(ledger)

    try:
        # Publish ``running`` only after entering the same protected
        # failure-finalization region as every later write. A handled signal
        # may arrive as soon as readers see that checksum-valid pair; it must
        # still replace the pair with durable ``interrupted`` evidence before
        # the process exits.
        writer.write(ledger)
        main_identity = _read_identity(proc_root, expected_main_pid)
        ledger["main_identity"] = main_identity
        writer.write(ledger)
        _main_start, main_command = _captured_identity(main_identity, role="Console main")
        if not _is_legacy_console(main_command):
            raise RollbackReadinessError(
                "restored systemd MainPID is not the legacy Node DevOps Console"
            )
        members_path = cgroup_root / expected_cgroup.lstrip("/") / "cgroup.procs"
        while True:
            now = clock()
            if now >= deadline:
                raise RollbackReadinessTimeout(
                    f"restored legacy Console did not become ready within {timeout_seconds:g}s"
                )
            observation: dict[str, object] = {
                "elapsed_seconds": max(0.0, now - started),
                "observed_at": utc_now(),
            }
            observations = ledger["observations"]
            if not isinstance(observations, list):
                raise RollbackReadinessError("rollback evidence observation list is invalid")
            observations.append(observation)

            unit_state = unit_probe(_remaining_seconds(deadline=deadline, clock=clock))
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["unit"] = unit_state
            _require_fixed_unit(
                unit_state,
                expected_main_pid=expected_main_pid,
                expected_cgroup=expected_cgroup,
            )

            members_before = _read_members(members_path)
            records = [_read_identity(proc_root, pid) for pid in members_before]
            members_after = _read_members(members_path)
            observation["members_before"] = members_before
            observation["members_after"] = members_after
            observation["processes"] = records
            if expected_main_pid not in members_before or expected_main_pid not in members_after:
                raise RollbackReadinessError("restored Console MainPID left its systemd cgroup")

            current_main = next(item for item in records if item["pid"] == expected_main_pid)
            if _captured_identity(current_main, role="Console main") != _captured_identity(
                main_identity, role="Console main baseline"
            ):
                raise RollbackReadinessError("restored Console MainPID start/argv identity changed")

            coordinator_candidates: list[dict[str, object]] = []
            for record in records:
                if record.get("status") != "captured":
                    continue
                command = record.get("command")
                if isinstance(command, list) and all(isinstance(item, str) for item in command):
                    if _is_legacy_coordinator(
                        command, old_coordinator_script, coordinator_port
                    ):
                        coordinator_candidates.append(record)
            if len(coordinator_candidates) > 1:
                raise RollbackReadinessError("restored cgroup has ambiguous legacy coordinator processes")
            if coordinator_identity is None and len(coordinator_candidates) == 1:
                coordinator_identity = coordinator_candidates[0]
                _captured_identity(coordinator_identity, role="coordinator")
                ledger["coordinator_identity"] = coordinator_identity
                if coordinator_identity["pid"] not in members_after:
                    raise RollbackReadinessError(
                        "restored legacy coordinator process left its cgroup during capture"
                    )
            elif coordinator_identity is not None:
                expected_coordinator_pid = coordinator_identity["pid"]
                if expected_coordinator_pid not in members_before or expected_coordinator_pid not in members_after:
                    raise RollbackReadinessError("restored legacy coordinator process left its cgroup")
                matching = [item for item in records if item["pid"] == expected_coordinator_pid]
                if len(matching) != 1 or _captured_identity(
                    matching[0], role="coordinator"
                ) != _captured_identity(coordinator_identity, role="coordinator baseline"):
                    raise RollbackReadinessError("restored coordinator PID start/argv identity changed")
                if coordinator_candidates != matching:
                    raise RollbackReadinessError("restored coordinator argv identity changed")

            # Listener ownership is a safety boundary even while startup is
            # incomplete. Do not defer a wrong public/coordinator owner merely
            # because the exact child coordinator has not been captured yet.
            early_snapshot = listener_probe(
                (80, 443, coordinator_port),
                _remaining_seconds(deadline=deadline, clock=clock),
            )
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["early_listener_snapshot"] = early_snapshot.splitlines()
            early_owners, _early_missing = _parse_listener_owners(
                early_snapshot,
                ports=(80, 443, coordinator_port),
            )
            observation["early_listener_owners"] = {
                str(port): pids for port, pids in early_owners.items()
            }
            _require_present_listener_owners(
                early_owners,
                expected={80: expected_main_pid, 443: expected_main_pid},
            )
            if coordinator_identity is not None:
                _require_present_listener_owners(
                    early_owners,
                    expected={coordinator_port: int(coordinator_identity["pid"])},
                )
            elif coordinator_port in early_owners:
                coordinator_owners = early_owners[coordinator_port]
                if len(coordinator_owners) != 1:
                    raise RollbackReadinessError(
                        f"restored listener ownership on port {coordinator_port} is ambiguous: "
                        f"observed {coordinator_owners}"
                    )
                listener_pid = coordinator_owners[0]
                current_owner_records = [item for item in records if item["pid"] == listener_pid]
                if current_owner_records:
                    owner_record = current_owner_records[0]
                    _owner_start, owner_command = _captured_identity(
                        owner_record, role=f"port {coordinator_port} owner"
                    )
                    if not _is_legacy_coordinator(
                        owner_command, old_coordinator_script, coordinator_port
                    ):
                        raise RollbackReadinessError(
                            f"restored listener ownership on port {coordinator_port} belongs to a process "
                            "that is not the exact legacy coordinator"
                        )
                    raise RollbackReadinessError(
                        f"exact port {coordinator_port} owner was not captured as the restored coordinator"
                    )

                # The coordinator may have joined the cgroup between the
                # membership read and ss. Confirm that exact concurrent arrival
                # twice; an outside-cgroup owner is immediately unsafe.
                listener_members_before = _read_members(members_path)
                owner_record = _read_identity(proc_root, listener_pid)
                listener_members_after = _read_members(members_path)
                confirmation = {
                    "pid": listener_pid,
                    "members_before": listener_members_before,
                    "members_after": listener_members_after,
                    "process": owner_record,
                }
                observation["listener_owner_confirmation"] = confirmation
                if (
                    listener_pid not in listener_members_before
                    or listener_pid not in listener_members_after
                    or expected_main_pid not in listener_members_before
                    or expected_main_pid not in listener_members_after
                ):
                    raise RollbackReadinessError(
                        f"restored listener ownership on port {coordinator_port} is outside the stable legacy cgroup"
                    )
                _owner_start, owner_command = _captured_identity(
                    owner_record, role=f"concurrent port {coordinator_port} owner"
                )
                if not _is_legacy_coordinator(
                    owner_command, old_coordinator_script, coordinator_port
                ):
                    raise RollbackReadinessError(
                        f"restored listener ownership on port {coordinator_port} belongs to a process "
                        "that is not the exact legacy coordinator"
                    )
                confirmed_owner = _read_identity(proc_root, listener_pid)
                listener_members_final = _read_members(members_path)
                confirmation["members_final"] = listener_members_final
                if _captured_identity(
                    confirmed_owner, role="confirmed concurrent coordinator"
                ) != _captured_identity(owner_record, role="concurrent coordinator"):
                    raise RollbackReadinessError(
                        "restored coordinator identity changed during listener-owner confirmation"
                    )
                if (
                    listener_pid not in listener_members_final
                    or expected_main_pid not in listener_members_final
                ):
                    raise RollbackReadinessError(
                        "restored listener owner left the legacy cgroup during confirmation"
                    )
                coordinator_identity = owner_record
                ledger["coordinator_identity"] = coordinator_identity
                observation["classification"] = "coordinator_appeared_during_listener_probe"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            if members_before != members_after:
                observation["classification"] = "cgroup_membership_changing"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            confirmed_main = _read_identity(proc_root, expected_main_pid)
            if _captured_identity(confirmed_main, role="confirmed Console main") != _captured_identity(
                main_identity, role="Console main baseline"
            ):
                raise RollbackReadinessError("restored Console identity changed during observation")

            if coordinator_identity is None:
                observation["classification"] = "waiting_for_coordinator"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue
            coordinator_pid = int(coordinator_identity["pid"])
            confirmed_coordinator = _read_identity(proc_root, coordinator_pid)
            if _captured_identity(
                confirmed_coordinator, role="confirmed coordinator"
            ) != _captured_identity(coordinator_identity, role="coordinator baseline"):
                raise RollbackReadinessError("restored coordinator identity changed during observation")

            expected_members = {expected_main_pid, coordinator_pid}
            extras = sorted(set(members_after) - expected_members)
            if extras:
                observation["classification"] = "transient_extra_cgroup_members"
                observation["extra_pids"] = extras
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            snapshot = listener_probe(
                (80, 443, coordinator_port),
                _remaining_seconds(deadline=deadline, clock=clock),
            )
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["candidate_listener_snapshot"] = snapshot.splitlines()
            owners, missing = _parse_listener_owners(
                snapshot,
                ports=(80, 443, coordinator_port),
            )
            _require_present_listener_owners(
                owners,
                expected={
                    80: expected_main_pid,
                    443: expected_main_pid,
                    coordinator_port: coordinator_pid,
                },
            )
            observation["candidate_listener_owners"] = {
                str(port): pids for port, pids in owners.items()
            }
            if missing:
                observation["classification"] = "waiting_for_listeners"
                observation["missing_ports"] = missing
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            remaining = max(0.1, deadline - clock())
            health = health_probe(health_url, remaining)
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["health"] = health
            if health.get("transport") != "ok":
                if health.get("retryable") is not True:
                    raise RollbackReadinessError(
                        f"public TLS health transport failed unsafely: {health.get('error', 'unknown error')}"
                    )
                observation["classification"] = "waiting_for_tls_transport"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue
            if health.get("tls_verify_result") != 0:
                raise RollbackReadinessError(
                    f"public TLS certificate verification failed: {health.get('tls_verify_result')}"
                )
            if health.get("status") != 200:
                raise RollbackReadinessError(
                    f"public rollback health returned HTTP {health.get('status')}, expected 200"
                )
            if health.get("remote_ip") != "127.0.0.1":
                raise RollbackReadinessError(
                    f"rollback health reached {health.get('remote_ip')}, expected local 127.0.0.1"
                )

            post_health: dict[str, object] = {}
            observation["post_health_topology"] = post_health
            post_health_exact = _confirm_fixed_topology(
                unit_probe=unit_probe,
                members_path=members_path,
                proc_root=proc_root,
                expected_main_pid=expected_main_pid,
                expected_cgroup=expected_cgroup,
                main_identity=main_identity,
                coordinator_identity=coordinator_identity,
                deadline=deadline,
                clock=clock,
                report=post_health,
            )
            if not post_health_exact:
                observation["classification"] = "post_health_transient_cgroup_members"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            final_snapshot = listener_probe(
                (80, 443, coordinator_port),
                _remaining_seconds(deadline=deadline, clock=clock),
            )
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["final_listener_snapshot"] = final_snapshot.splitlines()
            final_owners, final_missing = _parse_listener_owners(
                final_snapshot,
                ports=(80, 443, coordinator_port),
            )
            _require_present_listener_owners(
                final_owners,
                expected={
                    80: expected_main_pid,
                    443: expected_main_pid,
                    coordinator_port: coordinator_pid,
                },
            )
            observation["listener_owners"] = {
                str(port): pids for port, pids in final_owners.items()
            }
            if final_missing:
                observation["classification"] = "waiting_for_final_listeners"
                observation["missing_ports"] = final_missing
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            post_listener: dict[str, object] = {}
            observation["post_listener_topology"] = post_listener
            post_listener_exact = _confirm_fixed_topology(
                unit_probe=unit_probe,
                members_path=members_path,
                proc_root=proc_root,
                expected_main_pid=expected_main_pid,
                expected_cgroup=expected_cgroup,
                main_identity=main_identity,
                coordinator_identity=coordinator_identity,
                deadline=deadline,
                clock=clock,
                report=post_listener,
            )
            if not post_listener_exact:
                observation["classification"] = "post_listener_transient_cgroup_members"
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            inventory = inventory_probe(
                inventory_url,
                _remaining_seconds(deadline=deadline, clock=clock),
            )
            _remaining_seconds(deadline=deadline, clock=clock)
            registration_state, registration_report = (
                classify_legacy_registration_snapshot(
                    inventory,
                    project=registration_project,
                    name=registration_name,
                    port=registration_port,
                    main_pid=expected_main_pid,
                    expected_server_id=expected_server_id,
                    expected_lease_id=expected_lease_id,
                )
            )
            # Persist only the verifier's small allowlisted report. The raw
            # inventory may contain commands, paths, or future sensitive data.
            observation["registration"] = {
                "state": registration_state,
                **registration_report,
            }
            if registration_state != "ready":
                observation["classification"] = (
                    f"waiting_for_registration_{registration_state.removeprefix('pending-')}"
                )
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            post_registration_snapshot = listener_probe(
                (80, 443, coordinator_port),
                _remaining_seconds(deadline=deadline, clock=clock),
            )
            _remaining_seconds(deadline=deadline, clock=clock)
            observation["post_registration_listener_snapshot"] = (
                post_registration_snapshot.splitlines()
            )
            post_registration_owners, post_registration_missing = (
                _parse_listener_owners(
                    post_registration_snapshot,
                    ports=(80, 443, coordinator_port),
                )
            )
            _require_present_listener_owners(
                post_registration_owners,
                expected={
                    80: expected_main_pid,
                    443: expected_main_pid,
                    coordinator_port: coordinator_pid,
                },
            )
            observation["post_registration_listener_owners"] = {
                str(port): pids
                for port, pids in post_registration_owners.items()
            }
            if post_registration_missing:
                observation["classification"] = (
                    "waiting_for_post_registration_listeners"
                )
                observation["missing_ports"] = post_registration_missing
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            post_registration: dict[str, object] = {}
            observation["post_registration_topology"] = post_registration
            post_registration_exact = _confirm_fixed_topology(
                unit_probe=unit_probe,
                members_path=members_path,
                proc_root=proc_root,
                expected_main_pid=expected_main_pid,
                expected_cgroup=expected_cgroup,
                main_identity=main_identity,
                coordinator_identity=coordinator_identity,
                deadline=deadline,
                clock=clock,
                report=post_registration,
            )
            if not post_registration_exact:
                observation["classification"] = (
                    "post_registration_transient_cgroup_members"
                )
                writer.write(ledger)
                sleep(min(poll_interval_seconds, max(0.0, deadline - clock())))
                continue

            _remaining_seconds(deadline=deadline, clock=clock)
            observation["classification"] = "ready"
            ledger["status"] = "success"
            ledger["finished_at"] = utc_now()
            ledger["result"] = {
                "main_pid": expected_main_pid,
                "coordinator_pid": coordinator_pid,
                "cgroup": expected_cgroup,
                "listener_owners": observation[
                    "post_registration_listener_owners"
                ],
                "health": health,
                "registration": registration_report,
            }
            writer.write(ledger)
            verify_ledger_pair(evidence_path)
            return ledger["result"]
    except RollbackReadinessInterrupted as error:
        finish_failure(error, status="interrupted")
        verify_ledger_pair(evidence_path)
        raise
    except RollbackReadinessTimeout as error:
        finish_failure(error, status="timeout")
        verify_ledger_pair(evidence_path)
        raise
    except BaseException as error:
        finish_failure(error, status="failed")
        verify_ledger_pair(evidence_path)
        raise
    finally:
        writer.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", default="devops-console.service")
    parser.add_argument("--main-pid", required=True, type=int)
    parser.add_argument("--cgroup", required=True)
    parser.add_argument("--old-coordinator-script", required=True)
    parser.add_argument("--health-url", default="https://console.vr.ae/healthz")
    parser.add_argument("--inventory-url", required=True)
    parser.add_argument("--expected-identities", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=0.1)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    parser.add_argument("--systemctl", default="/usr/bin/systemctl", help=argparse.SUPPRESS)
    parser.add_argument("--sudo", default="/usr/bin/sudo", help=argparse.SUPPRESS)
    parser.add_argument("--ss", default="/usr/bin/ss", help=argparse.SUPPRESS)
    parser.add_argument("--curl", default="/usr/bin/curl", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    unit_probe = lambda timeout: systemd_unit_probe(
        unit=args.unit,
        timeout=timeout,
        systemctl=args.systemctl,
    )
    listener_probe = lambda ports, timeout: privileged_listener_probe(
        ports,
        timeout=timeout,
        sudo=args.sudo,
        ss=args.ss,
    )
    health_probe = lambda url, timeout: curl_health_probe(url, timeout, curl=args.curl)
    inventory_probe = lambda url, timeout: credential_free_inventory_probe(url, timeout)
    handled_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        handled_signals.append(signal.SIGHUP)
    previous_handlers: dict[signal.Signals, object] = {}

    def interrupt(signum: int, _frame: object) -> None:
        raise RollbackReadinessInterrupted(
            f"rollback readiness interrupted by {signal.Signals(signum).name}"
        )

    try:
        for handled_signal in handled_signals:
            previous_handlers[handled_signal] = signal.signal(handled_signal, interrupt)
        expected_server_id, expected_lease_id = read_expected_identities(
            args.expected_identities
        )
        report = wait_for_legacy_console_rollback(
            unit=args.unit,
            expected_main_pid=args.main_pid,
            expected_cgroup=args.cgroup,
            old_coordinator_script=args.old_coordinator_script,
            health_url=args.health_url,
            inventory_url=args.inventory_url,
            expected_server_id=expected_server_id,
            expected_lease_id=expected_lease_id,
            registration_project=args.project,
            registration_name=args.name,
            registration_port=args.port,
            evidence_path=Path(args.evidence),
            timeout_seconds=args.timeout_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
            cgroup_root=Path(args.cgroup_root),
            proc_root=Path(args.proc_root),
            unit_probe=unit_probe,
            listener_probe=listener_probe,
            health_probe=health_probe,
            inventory_probe=inventory_probe,
        )
    except (
        BoundaryError,
        RollbackReadinessError,
        SecureIOError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"legacy rollback readiness failed: {error}", file=sys.stderr)
        return 1
    finally:
        for handled_signal, previous_handler in previous_handlers.items():
            signal.signal(handled_signal, previous_handler)
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
