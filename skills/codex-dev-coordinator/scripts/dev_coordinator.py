#!/usr/bin/env python3
"""Shared port, dev-server, and Docker coordinator for Codex agents."""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import glob
import http.server
import json
import os
import re
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


VERSION = 1
DEFAULT_RANGE = "3000-3999"
DEFAULT_TTL_SECONDS = 8 * 60 * 60
DEFAULT_API_PORT = 29876
GRACE_SECONDS = 5
# A server that fails its health check but was created within this window is
# reported as "starting" rather than "unhealthy" so slow-booting servers do not
# trigger needless restart churn.
STARTUP_GRACE_SECONDS = 20
# Live `server status` re-checks health a few times before concluding a server
# is unhealthy, so a transient blip or a still-warming server is not
# misclassified after a single miss.
HEALTH_RETRY_ATTEMPTS = 3
HEALTH_RETRY_BACKOFF_SECONDS = 0.3
# Stopped-server records are kept for evidence but pruned so the state file does
# not grow without bound across months of start/stop cycles.
STOPPED_SERVER_RETENTION_SECONDS = 7 * 24 * 60 * 60
STOPPED_SERVER_LIMIT = 100
DOCKER_STATS_HISTORY_LIMIT = 120
PROJECT_RUNTIME_FILES = (
    ".codex/dev-runtime.json",
    ".codex/codex-dev-runtime.json",
    "codex-dev-runtime.json",
)

SERVICE_ROLE_TOKENS = {
    "api",
    "app",
    "backend",
    "cache",
    "database",
    "db",
    "frontend",
    "mailhog",
    "metrics",
    "minio",
    "nginx",
    "pg",
    "postgis",
    "postgres",
    "queue",
    "redis",
    "scheduler",
    "server",
    "web",
    "worker",
}

DEPLOYMENT_QUALIFIER_TOKENS = {
    "copy",
    "dev",
    "development",
    "local",
    "prod",
    "production",
    "stage",
    "staging",
    "test",
}


def now() -> float:
    return time.time()


def iso_timestamp(value: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value or now()))


def coordinator_home() -> Path:
    configured = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home() / ".codex" / "agent-coordinator"


def state_path() -> Path:
    return coordinator_home() / "state.json"


def lock_path() -> Path:
    return coordinator_home() / "state.lock"


def logs_dir() -> Path:
    return coordinator_home() / "logs"


def default_state() -> dict[str, Any]:
    return {
        "version": VERSION,
        "created_at": iso_timestamp(),
        "updated_at": iso_timestamp(),
        "leases": {},
        "servers": {},
        "port_assignments": {},
        "history": [],
        "docker": {"last_commands": [], "stats_history": {}, "metadata": {}},
    }


def read_state() -> dict[str, Any]:
    path = state_path()
    if not path.exists():
        return default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        # A corrupt state file (e.g. a partial write after a crash) must not make
        # even read-only commands like `inventory` unusable. Preserve the corrupt
        # file for forensics and recover with a fresh default state.
        backup = path.with_name(f"{path.name}.corrupt-{int(now())}")
        with contextlib.suppress(OSError):
            path.replace(backup)
        print(
            f"warning: invalid coordinator state JSON at {path}: {exc}; "
            f"backed up to {backup} and reinitialized empty state",
            file=sys.stderr,
        )
        return default_state()
    data.setdefault("version", VERSION)
    data.setdefault("created_at", iso_timestamp())
    data.setdefault("updated_at", iso_timestamp())
    data.setdefault("leases", {})
    data.setdefault("servers", {})
    data.setdefault("history", [])
    data.setdefault("docker", {"last_commands": []})
    data["docker"].setdefault("last_commands", [])
    data["docker"].setdefault("stats_history", {})
    data["docker"].setdefault("metadata", {})
    if "port_assignments" not in data:
        # One-time migration: pin every pre-existing server record to the port
        # it already holds so the durable-port contract covers old state files.
        data["port_assignments"] = {}
        seed_port_assignments(data)
    return data


def write_state(state: dict[str, Any]) -> None:
    home = coordinator_home()
    home.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = iso_timestamp()
    tmp = state_path().with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(state_path())


@contextlib.contextmanager
def locked_state() -> Any:
    home = coordinator_home()
    home.mkdir(parents=True, exist_ok=True)
    with lock_path().open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = read_state()
        prune_expired_leases(state)
        prune_stopped_servers(state)
        yield state
        write_state(state)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def parse_range(raw: str) -> tuple[int, int]:
    if "-" not in raw:
        port = int(raw)
        return port, port
    start_raw, end_raw = raw.split("-", 1)
    start, end = int(start_raw), int(end_raw)
    if start < 1 or end > 65535 or start > end:
        raise ValueError(f"invalid port range {raw!r}")
    return start, end


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _listening_inodes_for_port(port: int) -> set[str]:
    """Socket inodes of TCP sockets in LISTEN state on `port`, read from /proc.

    Pure-stdlib, Linux-native, and privilege-free — the parsed files are the
    calling user's view of the network tables. Covers IPv4 and IPv6.
    """
    inodes: set[str] = set()
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        with contextlib.suppress(Exception):
            with open(proc_file, encoding="utf-8") as handle:
                next(handle, None)  # header
                for line in handle:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    local_port = int(fields[1].rsplit(":", 1)[1], 16)
                    state = fields[3]
                    if local_port == port and state == "0A":  # 0A = TCP_LISTEN
                        inodes.add(fields[9])
    return inodes


def _pid_owning_socket_inodes(inodes: set[str]) -> int | None:
    if not inodes:
        return None
    targets = {f"socket:[{inode}]" for inode in inodes}
    for fd_dir in glob.glob("/proc/[0-9]*/fd"):
        with contextlib.suppress(Exception):
            for fd_path in os.scandir(fd_dir):
                with contextlib.suppress(OSError):
                    if os.readlink(fd_path.path) in targets:
                        return int(fd_dir.rsplit("/", 2)[1])
    return None


def listening_pid_for_port(port: int) -> int | None:
    # Prefer /proc on Linux (no external dependency); fall back to lsof so
    # macOS and other platforms without /proc still resolve the owner.
    with contextlib.suppress(Exception):
        pid = _pid_owning_socket_inodes(_listening_inodes_for_port(port))
        if pid is not None:
            return pid
    with contextlib.suppress(Exception):
        completed = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        if completed.returncode == 0:
            for line in completed.stdout.splitlines():
                if line.startswith("p"):
                    return int(line[1:])
    return None


def process_cwd(pid: int | None) -> str | None:
    if not pid:
        return None
    proc_cwd = Path("/proc") / str(pid) / "cwd"
    with contextlib.suppress(Exception):
        if not proc_cwd.exists():
            raise FileNotFoundError(str(proc_cwd))
        return str(proc_cwd.resolve())
    with contextlib.suppress(Exception):
        completed = subprocess.run(
            ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        if completed.returncode == 0:
            for line in completed.stdout.splitlines():
                if line.startswith("n"):
                    return str(Path(line[1:]).expanduser().resolve())
    return None


def path_inside(child: str | None, parent: str | None) -> bool:
    if not child or not parent:
        return False
    child_path = Path(child).expanduser().resolve()
    parent_path = Path(parent).expanduser().resolve()
    return child_path == parent_path or parent_path in child_path.parents


def listener_owner_for_port(port: int) -> dict[str, Any]:
    pid = listening_pid_for_port(port)
    cwd = process_cwd(pid)
    owner_project = canonical_project(cwd) if cwd else None
    return {"pid": pid, "cwd": cwd, "project": owner_project}


def listener_belongs_to_project(port: int, project: str) -> tuple[bool, dict[str, Any]]:
    owner = listener_owner_for_port(port)
    resolved_project = canonical_project(project)
    owner_project = owner.get("project")
    if not owner.get("pid"):
        owner["reason"] = f"port {port} is open but no listener PID could be identified"
        return False, owner
    if not owner.get("cwd") or not owner_project:
        owner["reason"] = f"port {port} is owned by PID {owner['pid']}, but its working directory could not be identified"
        return False, owner
    if owner_project != resolved_project and not path_inside(str(owner.get("cwd")), resolved_project):
        owner["reason"] = (
            f"port {port} is owned by PID {owner['pid']} in {owner.get('cwd')}, "
            f"outside project {resolved_project}"
        )
        return False, owner
    return True, owner


def read_process_table() -> dict[int, dict[str, Any]]:
    with contextlib.suppress(Exception):
        completed = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,%cpu=,rss=,command="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
        )
        if completed.returncode != 0:
            return {}
        rows: dict[int, dict[str, Any]] = {}
        for line in completed.stdout.splitlines():
            parts = line.strip().split(None, 4)
            if len(parts) < 5:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                cpu_percent = float(parts[2])
                rss_kb = int(float(parts[3]))
            except ValueError:
                continue
            rows[pid] = {
                "pid": pid,
                "ppid": ppid,
                "cpu_percent": cpu_percent,
                "rss_kb": rss_kb,
                "rss_bytes": rss_kb * 1024,
                "command": parts[4],
            }
        return rows
    return {}


def children_by_parent(process_table: dict[int, dict[str, Any]]) -> dict[int, list[int]]:
    children: dict[int, list[int]] = {}
    for pid, row in process_table.items():
        children.setdefault(int(row.get("ppid") or 0), []).append(pid)
    return children


def process_tree_pids(root_pids: set[int], process_table: dict[int, dict[str, Any]], children: dict[int, list[int]]) -> set[int]:
    seen: set[int] = set()
    stack = [pid for pid in root_pids if pid in process_table]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
    return seen


def process_usage_entry(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "pid": row.get("pid"),
        "ppid": row.get("ppid"),
        "cpu_percent": round(float(row.get("cpu_percent") or 0), 2),
        "rss_bytes": int(row.get("rss_bytes") or 0),
        "command": row.get("command"),
    }


def summarize_process_usage(
    pids: set[int],
    process_table: dict[int, dict[str, Any]],
    *,
    root_pids: set[int] | None = None,
    source: str,
) -> dict[str, Any] | None:
    live_pids = sorted(pid for pid in pids if pid in process_table)
    if not live_pids:
        return None
    processes = [process_usage_entry(process_table[pid]) for pid in live_pids]
    hot_processes = sorted(
        processes,
        key=lambda item: (float(item.get("cpu_percent") or 0), int(item.get("rss_bytes") or 0)),
        reverse=True,
    )
    cpu_percent = sum(float(item.get("cpu_percent") or 0) for item in processes)
    rss_bytes = sum(int(item.get("rss_bytes") or 0) for item in processes)
    return {
        "source": source,
        "root_pids": sorted(pid for pid in (root_pids or set()) if pid in process_table),
        "pids": live_pids,
        "process_count": len(live_pids),
        "cpu_percent": round(cpu_percent, 2),
        "rss_bytes": rss_bytes,
        "memory_bytes": rss_bytes,
        "processes": processes,
        "hot_processes": hot_processes[:5],
    }


def server_process_identity(server: dict[str, Any]) -> dict[str, Any]:
    pid = int(server.get("pid") or 0)
    if not pid or not pid_alive(pid):
        return {"ok": True, "pid": pid, "cwd": None, "project": None}
    cwd = process_cwd(pid)
    server_project = server.get("project")
    owner_project = canonical_project(cwd) if cwd else None
    if cwd and server_project:
        resolved_project = canonical_project(str(server_project))
        if owner_project != resolved_project and not path_inside(cwd, resolved_project):
            return {
                "ok": False,
                "pid": pid,
                "cwd": cwd,
                "project": owner_project,
                "reason": (
                    f"PID {pid} cwd {cwd} is outside registered project {resolved_project}; "
                    f"stale coordinator metadata"
                ),
            }
    return {"ok": True, "pid": pid, "cwd": cwd, "project": owner_project}


def server_listener_identity(server: dict[str, Any]) -> dict[str, Any]:
    identity = server_process_identity(server)
    if identity.get("ok") is False:
        return identity
    pid = int(server.get("pid") or 0)
    if pid and pid_alive(pid):
        return identity
    project = server.get("project")
    port = server.get("port")
    if not project or not port:
        return identity
    host = str(server.get("host") or "127.0.0.1")
    if not port_open(host, int(port)):
        return identity
    belongs, owner = listener_belongs_to_project(int(port), str(project))
    return {"ok": belongs, **owner}


def port_available(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def prune_stopped_servers(state: dict[str, Any]) -> None:
    """Bound the growth of stopped-server records kept for evidence.

    Drops stopped servers older than the retention window, then caps the total
    number of stopped records (oldest first). Running/adopted servers and any
    server without a recorded stop time newer than the cap are preserved.
    """
    servers = state.get("servers")
    if not isinstance(servers, dict):
        return
    current = now()
    for server_id, server in list(servers.items()):
        if not isinstance(server, dict) or server.get("status") != "stopped":
            continue
        stopped_ts = server.get("stopped_ts")
        if stopped_ts is None:
            continue
        try:
            age = current - float(stopped_ts)
        except (TypeError, ValueError):
            continue
        if age > STOPPED_SERVER_RETENTION_SECONDS:
            servers.pop(server_id, None)
    stopped = [
        (server_id, server)
        for server_id, server in servers.items()
        if isinstance(server, dict) and server.get("status") == "stopped"
    ]
    if len(stopped) > STOPPED_SERVER_LIMIT:
        stopped.sort(key=lambda item: float(item[1].get("stopped_ts") or 0.0))
        for server_id, _ in stopped[: len(stopped) - STOPPED_SERVER_LIMIT]:
            servers.pop(server_id, None)


def prune_expired_leases(state: dict[str, Any]) -> None:
    current = now()
    for lease_id, lease in list(state["leases"].items()):
        expires_at = lease.get("expires_at")
        server_id = lease.get("server_id")
        if server_id:
            if lease_has_stale_server(state, lease):
                mark_lease_stale_released(state, lease_id, lease, "linked server is stopped, missing, or no longer alive")
                continue
            if state["servers"].get(server_id):
                continue
        if expires_at and current > float(expires_at):
            lease["status"] = "expired"
            record_event(state, "port.expired", lease)
            state["leases"].pop(lease_id, None)


def lease_has_stale_server(state: dict[str, Any], lease: dict[str, Any]) -> bool:
    server_id = lease.get("server_id")
    if not server_id:
        return False
    server = state["servers"].get(server_id)
    if not server:
        return True
    if server.get("status") == "stopped":
        return True
    pid = server.get("pid")
    identity = server_listener_identity(server)
    if identity.get("ok") is False:
        return True
    return bool(pid) and not pid_alive(int(pid))


def mark_lease_stale_released(state: dict[str, Any], lease_id: str, lease: dict[str, Any], reason: str) -> dict[str, Any]:
    state["leases"].pop(lease_id, None)
    lease["status"] = "stale_released"
    lease["released_at"] = iso_timestamp()
    lease["stale_reason"] = reason
    record_event(state, "port.stale_released", lease)
    return lease


def reclaim_stale_leases_for_port(
    state: dict[str, Any],
    *,
    project: str,
    port: int,
    reason: str,
    allow_occupied_unattached: bool = False,
) -> list[dict[str, Any]]:
    resolved_project = canonical_project(project)
    released = []
    for lease_id, lease in list(state["leases"].items()):
        if lease.get("status") != "active" or int(lease.get("port") or 0) != int(port):
            continue
        lease_project = lease.get("project")
        if not lease_project or canonical_project(str(lease_project)) != resolved_project:
            continue
        if lease_has_stale_server(state, lease):
            released.append(mark_lease_stale_released(state, lease_id, lease, reason))
            continue
        if lease.get("server_id"):
            continue
        purpose = str(lease.get("purpose") or "")
        can_reclaim_unattached = purpose.startswith("server:") and (port_available(port) or allow_occupied_unattached)
        if can_reclaim_unattached:
            released.append(mark_lease_stale_released(state, lease_id, lease, reason))
    return released


def record_event(state: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
    history = state.setdefault("history", [])
    history.append({"at": iso_timestamp(), "type": event_type, "payload": payload})
    del history[:-200]


def active_lease_ports(state: dict[str, Any]) -> set[int]:
    return {int(lease["port"]) for lease in state["leases"].values() if lease.get("status") == "active"}


def lease_port(
    state: dict[str, Any],
    *,
    agent: str,
    project: str,
    port_range: str = DEFAULT_RANGE,
    preferred: int | None = None,
    ttl: int = DEFAULT_TTL_SECONDS,
    purpose: str = "manual",
    server_id: str | None = None,
    assignment_key: str | None = None,
) -> dict[str, Any]:
    project = canonical_project(project)
    start, end = parse_range(port_range)
    candidates = []
    if preferred is not None:
        if preferred < start or preferred > end:
            raise ValueError(f"preferred port {preferred} is outside {port_range}")
        candidates.append(preferred)
    candidates.extend(port for port in range(start, end + 1) if port != preferred)

    used = active_lease_ports(state)
    # Ports durably assigned to another (project, server) are never handed out,
    # even while that server is stopped — that is the whole durability contract.
    assigned = foreign_assigned_ports(state, owner_key=assignment_key)
    if preferred is not None and preferred in assigned:
        raise RuntimeError(
            f"port {preferred} is durably assigned to {assignment_owner_text(assigned[preferred])}; "
            "choose another port or unassign it first"
        )
    for port in candidates:
        if port in used or port in assigned:
            continue
        if not port_available(port):
            continue
        lease_id = str(uuid.uuid4())
        lease = {
            "id": lease_id,
            "port": port,
            "agent": agent,
            "project": project,
            "agent_metadata": agent_metadata(agent=agent, project=project, source="port_lease"),
            "purpose": purpose,
            "server_id": server_id,
            "status": "active",
            "created_at": iso_timestamp(),
            "created_ts": now(),
            "expires_at": now() + ttl if ttl > 0 else None,
            "expires_at_iso": iso_timestamp(now() + ttl) if ttl > 0 else None,
            "range": port_range,
        }
        state["leases"][lease_id] = lease
        record_event(state, "port.leased", lease)
        return lease

    raise RuntimeError(f"no free port available in {port_range}")


def release_mismatched_leases_for_existing_listener(
    state: dict[str, Any],
    *,
    port: int,
    owner_pid: int | None,
    owner_project: str,
    reason: str,
) -> None:
    resolved_owner_project = canonical_project(owner_project)
    for lease_id, lease in list(state["leases"].items()):
        if lease.get("status") != "active" or int(lease.get("port") or 0) != int(port):
            continue
        server = state["servers"].get(lease.get("server_id")) if lease.get("server_id") else None
        lease_project = canonical_project(str(lease.get("project") or "")) if lease.get("project") else None
        if lease_has_stale_server(state, lease):
            mark_lease_stale_released(state, lease_id, lease, reason)
            continue
        if server and owner_pid and int(server.get("pid") or 0) == int(owner_pid) and lease_project != resolved_owner_project:
            mark_lease_stale_released(state, lease_id, lease, reason)


def lease_existing_server_port(
    state: dict[str, Any],
    *,
    agent: str,
    project: str,
    port: int,
    purpose: str,
    server_id: str,
    owner_pid: int | None,
    ttl: int = DEFAULT_TTL_SECONDS,
    assignment_key: str | None = None,
) -> dict[str, Any]:
    project = canonical_project(project)
    foreign = foreign_assigned_ports(state, owner_key=assignment_key)
    if int(port) in foreign:
        raise RuntimeError(
            f"port {port} is durably assigned to {assignment_owner_text(foreign[int(port)])}; "
            "register on another port or unassign it first"
        )
    release_mismatched_leases_for_existing_listener(
        state,
        port=port,
        owner_pid=owner_pid,
        owner_project=project,
        reason=f"port {port} lease pointed at stale or foreign server metadata",
    )
    for lease in state["leases"].values():
        if lease.get("status") != "active" or int(lease.get("port") or 0) != int(port):
            continue
        if lease.get("server_id") == server_id and canonical_project(str(lease.get("project") or "")) == project:
            return lease
        raise RuntimeError(
            f"port {port} already has an active lease for {lease.get('project') or 'unknown project'}"
        )
    lease_id = str(uuid.uuid4())
    lease = {
        "id": lease_id,
        "port": port,
        "agent": agent,
        "project": project,
        "agent_metadata": agent_metadata(agent=agent, project=project, source="port_lease_existing"),
        "purpose": purpose,
        "server_id": server_id,
        "status": "active",
        "created_at": iso_timestamp(),
        "created_ts": now(),
        "expires_at": now() + ttl if ttl > 0 else None,
        "expires_at_iso": iso_timestamp(now() + ttl) if ttl > 0 else None,
        "range": f"{port}-{port}",
        "occupied_existing": True,
        "owner_pid": owner_pid,
    }
    state["leases"][lease_id] = lease
    record_event(state, "port.leased", lease)
    return lease


def release_port(state: dict[str, Any], *, lease_id: str | None = None, port: int | None = None) -> dict[str, Any]:
    for existing_id, lease in list(state["leases"].items()):
        if (lease_id and existing_id == lease_id) or (port is not None and int(lease["port"]) == port):
            state["leases"].pop(existing_id, None)
            lease["status"] = "released"
            lease["released_at"] = iso_timestamp()
            record_event(state, "port.released", lease)
            return lease
    raise KeyError("matching lease not found")


def server_key(project: str, name: str) -> str:
    return f"{canonical_project(project)}::{name}"


def canonical_project(project: str) -> str:
    raw = Path(project or os.getcwd()).expanduser()
    git_cwd = raw if raw.is_dir() else raw.parent
    if git_cwd.exists():
        with contextlib.suppress(Exception):
            completed = subprocess.run(
                ["git", "-C", str(git_cwd), "rev-parse", "--show-toplevel"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                return str(Path(completed.stdout.strip()).expanduser().resolve())
    return str(raw.resolve())


# --- durable port assignments -------------------------------------------------
# A port assignment permanently maps (canonical project, server name) -> port so
# a repo's servers always come back on the same ports. Assignments live in
# state["port_assignments"] (a sibling of leases/servers), survive server stop,
# lease release/expiry/stale-reclaim, and stopped-record pruning, and are
# removed only by explicit unassignment (or `state reset`).


def find_port_assignment(state: dict[str, Any], *, project: str, name: str) -> tuple[str, dict[str, Any] | None]:
    key = server_key(project, name)
    return key, state.setdefault("port_assignments", {}).get(key)


def foreign_assigned_ports(state: dict[str, Any], *, owner_key: str | None = None) -> dict[int, dict[str, Any]]:
    """Map of durably assigned ports -> assignment, excluding owner_key's own."""
    out: dict[int, dict[str, Any]] = {}
    for key, assignment in state.setdefault("port_assignments", {}).items():
        if key == owner_key:
            continue
        with contextlib.suppress(TypeError, ValueError):
            out[int(assignment["port"])] = assignment
    return out


def assignment_owner_text(assignment: dict[str, Any]) -> str:
    return f"server '{assignment.get('name')}' of {assignment.get('project')}"


def record_port_assignment(
    state: dict[str, Any],
    *,
    agent: str,
    project: str,
    name: str,
    port: int,
    source: str,
) -> dict[str, Any]:
    """Create or move the durable assignment for (project, name). Idempotent
    per key; landing on a different port (an explicit caller choice) re-pins."""
    project = canonical_project(project)
    key = server_key(project, name)
    assignments = state.setdefault("port_assignments", {})
    existing = assignments.get(key)
    if existing and int(existing.get("port") or 0) == int(port):
        existing["updated_at"] = iso_timestamp()
        return existing
    assignment = {
        "key": key,
        "project": project,
        "name": name,
        "port": int(port),
        "agent": agent,
        "source": source,
        "created_at": existing.get("created_at") if existing else iso_timestamp(),
        "updated_at": iso_timestamp(),
    }
    assignments[key] = assignment
    record_event(state, "port.assigned", assignment)
    return assignment


def assign_port(
    state: dict[str, Any],
    *,
    agent: str,
    project: str,
    name: str,
    port: int,
    force: bool = False,
) -> dict[str, Any]:
    agent = str(agent or "").strip()
    if not agent:
        raise ValueError("port assign requires --agent so the coordinator can attribute the action")
    if not str(project or "").strip():
        raise ValueError("port assign requires --project with the canonical repo path")
    if not str(name or "").strip():
        raise ValueError("port assign requires --name of the server the port belongs to")
    port = int(port)
    if port < 1 or port > 65535:
        raise ValueError(f"port {port} is outside 1-65535")
    project = canonical_project(project)
    key = server_key(project, name)
    foreign = foreign_assigned_ports(state, owner_key=key)
    if port in foreign:
        raise RuntimeError(
            f"port {port} is durably assigned to {assignment_owner_text(foreign[port])}; unassign it first"
        )
    if not force:
        for lease in state["leases"].values():
            if lease.get("status") != "active" or int(lease.get("port") or 0) != port:
                continue
            lease_project = canonical_project(str(lease.get("project"))) if lease.get("project") else None
            if lease_project != project:
                raise RuntimeError(
                    f"port {port} already has an active lease for {lease.get('project') or 'unknown project'}"
                )
    return record_port_assignment(state, agent=agent, project=project, name=name, port=port, source="port_assign")


def unassign_port(
    state: dict[str, Any],
    *,
    agent: str,
    project: str | None = None,
    name: str | None = None,
    port: int | None = None,
    force: bool = False,
) -> dict[str, Any]:
    agent = str(agent or "").strip()
    if not agent:
        raise ValueError("port unassign requires --agent so the coordinator can attribute the action")
    if name is not None and not str(project or "").strip():
        raise ValueError("port unassign by --name requires --project naming the owning repo")
    if name is None and port is None:
        raise ValueError("port unassign requires --name or --port")
    resolved = canonical_project(project) if project else None
    assignments = state.setdefault("port_assignments", {})
    for key, assignment in list(assignments.items()):
        if name is not None:
            if assignment.get("name") != name or assignment.get("project") != resolved:
                continue
        else:
            if int(assignment.get("port") or 0) != int(port):
                continue
            if assignment.get("project") != resolved and not force:
                # A moved/renamed repo can orphan an assignment whose canonical
                # project no longer matches any caller; --force is the cleanup.
                raise RuntimeError(
                    f"port {port} is durably assigned to {assignment_owner_text(assignment)}; "
                    "pass --force to remove another project's assignment"
                )
        assignments.pop(key, None)
        removed = {**assignment, "status": "unassigned", "unassigned_at": iso_timestamp(), "unassigned_by": agent}
        record_event(state, "port.unassigned", removed)
        return removed
    raise KeyError("matching port assignment not found")


def list_port_assignments(state: dict[str, Any], *, project: str | None = None) -> list[dict[str, Any]]:
    resolved = canonical_project(project) if project else None
    out = [
        dict(assignment)
        for assignment in state.setdefault("port_assignments", {}).values()
        if not resolved or assignment.get("project") == resolved
    ]
    out.sort(key=lambda item: int(item.get("port") or 0))
    return out


def seed_port_assignments(state: dict[str, Any]) -> None:
    """Migration for pre-assignment state files: pin each server record to its
    recorded port. On a contested port, running servers win; among stopped
    records the most recently stopped wins. Losers stay unpinned and get a
    fresh pinned port on their next start."""
    servers = [
        server
        for server in state.get("servers", {}).values()
        if isinstance(server, dict) and server.get("port") and server.get("name") and server.get("key")
    ]

    def rank(server: dict[str, Any]) -> tuple[int, float]:
        stopped = 1 if server.get("status") == "stopped" else 0
        try:
            ts = float(server.get("stopped_ts") or server.get("created_ts") or 0)
        except (TypeError, ValueError):
            # A malformed timestamp in a legacy record must degrade its rank,
            # never brick read_state (which every command depends on).
            ts = 0.0
        return (stopped, -ts)

    servers.sort(key=rank)
    assignments = state.setdefault("port_assignments", {})
    claimed = {int(a.get("port") or 0) for a in assignments.values()}
    for server in servers:
        key = str(server["key"])
        try:
            port = int(server["port"])
        except (TypeError, ValueError):
            continue
        if key in assignments or port in claimed:
            continue
        assignments[key] = {
            "key": key,
            "project": str(server.get("project") or key.rsplit("::", 1)[0]),
            "name": str(server["name"]),
            "port": port,
            "agent": str(server.get("agent") or "coordinator"),
            "source": "seed_existing_servers",
            "created_at": iso_timestamp(),
            "updated_at": iso_timestamp(),
        }
        claimed.add(port)


def git_value(project: str, *args: str) -> str | None:
    with contextlib.suppress(Exception):
        completed = subprocess.run(
            ["git", "-C", project, *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        if completed.returncode == 0:
            value = completed.stdout.strip()
            return value or None
    return None


def agent_metadata(*, agent: str, project: str, source: str, cwd: str | None = None) -> dict[str, Any]:
    resolved_project = canonical_project(project)
    resolved_cwd = str(Path(cwd).expanduser().resolve()) if cwd else resolved_project
    return {
        "agent": agent,
        "project": resolved_project,
        "repo_name": Path(resolved_project).name,
        "cwd": resolved_cwd,
        "git_branch": git_value(resolved_project, "rev-parse", "--abbrev-ref", "HEAD"),
        "git_commit": git_value(resolved_project, "rev-parse", "--short", "HEAD"),
        "recorded_at": iso_timestamp(),
        "metadata_source": source,
    }


def require_identity(options: dict[str, Any], command: str) -> tuple[str, str]:
    agent = str(options.get("agent") or "").strip()
    project = str(options.get("project") or "").strip()
    if not agent:
        raise ValueError(f"{command} requires --agent so the coordinator can attribute the action")
    if not project:
        raise ValueError(f"{command} requires --project with the canonical repo path")
    resolved_project = canonical_project(project)
    options["agent"] = agent
    options["project"] = resolved_project
    return agent, resolved_project


def project_name_tokens(name: str | None) -> list[str]:
    if not name:
        return []
    normalized = name.strip().lower().replace("_", "-")
    return [token for token in normalized.split("-") if token and not token.isdigit()]


def trim_trailing_qualifiers(tokens: list[str]) -> list[str]:
    result = list(tokens)
    while result and result[-1] in DEPLOYMENT_QUALIFIER_TOKENS:
        result.pop()
    return result or tokens


def project_key_from_resource_name(name: str | None) -> str:
    tokens = project_name_tokens(name)
    if not tokens:
        return "local"
    for index, token in enumerate(tokens):
        if token in SERVICE_ROLE_TOKENS:
            project_tokens = trim_trailing_qualifiers(tokens[:index])
            if project_tokens:
                return "-".join(project_tokens)
    return "-".join(trim_trailing_qualifiers(tokens))


def project_key_from_path(project: str | None) -> str:
    if not project:
        return "local"
    return project_key_from_resource_name(Path(project).expanduser().resolve().name)


def find_server(state: dict[str, Any], *, project: str, name: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    key = server_key(project, name)
    resolved_project = canonical_project(project)
    matches: list[tuple[str, dict[str, Any]]] = []
    for server_id, server in state["servers"].items():
        server_project = server.get("project")
        same_project = False
        if server_project:
            with contextlib.suppress(Exception):
                same_project = canonical_project(str(server_project)) == resolved_project
        if server.get("key") == key or (server.get("name") == name and same_project):
            matches.append((server_id, server))
    for server_id, server in reversed(matches):
        if server.get("status") != "stopped":
            return server_id, server
    if matches:
        return matches[-1]
    return None, None


def server_record_key(server: dict[str, Any]) -> str:
    key = server.get("key")
    if key:
        return str(key)
    project = server.get("project")
    name = server.get("name")
    if project and name:
        return server_key(str(project), str(name))
    return f"id::{server.get('id') or id(server)}"


def server_record_rank(server: dict[str, Any]) -> tuple[int, str, str, str]:
    status = str(server.get("status") or "").lower()
    health = server.get("health") or {}
    if status == "running" or health.get("ok"):
        state_rank = 4
    elif status in {"starting", "unhealthy", "degraded"}:
        state_rank = 3
    elif health.get("pid_alive"):
        state_rank = 2
    elif status == "stopped":
        state_rank = 1
    else:
        state_rank = 0
    timestamp = str(server.get("updated_at") or server.get("stopped_at") or server.get("created_at") or "")
    created_at = str(server.get("created_at") or "")
    server_id = str(server.get("id") or "")
    return (state_rank, timestamp, created_at, server_id)


def preferred_server_record(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return right if server_record_rank(right) >= server_record_rank(left) else left


def deduplicate_server_records(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    preferred: dict[str, dict[str, Any]] = {}
    duplicate_ids: dict[str, list[str]] = {}
    for server in servers:
        key = server_record_key(server)
        duplicate_ids.setdefault(key, []).append(str(server.get("id") or ""))
        current = preferred.get(key)
        preferred[key] = server if current is None else preferred_server_record(current, server)

    result: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for server in servers:
        key = server_record_key(server)
        winner = preferred[key]
        winner_id = str(winner.get("id") or "")
        if str(server.get("id") or "") != winner_id or winner_id in emitted:
            continue
        emitted.add(winner_id)
        duplicate_count = len(duplicate_ids.get(key, []))
        if duplicate_count > 1:
            server["duplicate_count"] = duplicate_count
            server["duplicate_server_ids"] = [item for item in duplicate_ids[key] if item and item != winner_id]
        result.append(server)
    return result


def annotate_server_url_currency(servers: list[dict[str, Any]]) -> None:
    active_by_endpoint: dict[tuple[str, int], dict[str, Any]] = {}
    for server in servers:
        port = server.get("port")
        if not port:
            continue
        endpoint = (str(server.get("host") or "127.0.0.1"), int(port))
        health = server.get("health") or {}
        is_current = server.get("status") != "stopped" and health.get("ok") is True
        server["url_is_current"] = bool(is_current)
        if is_current:
            active_by_endpoint[endpoint] = {
                "type": "server",
                "id": server.get("id"),
                "name": server.get("name"),
                "project": server.get("project"),
                "pid": server.get("pid"),
                "url": server.get("url"),
            }

    for server in servers:
        port = server.get("port")
        if not port or server.get("url_is_current"):
            continue
        endpoint = (str(server.get("host") or "127.0.0.1"), int(port))
        active_owner = active_by_endpoint.get(endpoint)
        if active_owner and active_owner.get("id") != server.get("id"):
            server["port_reused"] = True
            server["url_is_current"] = False
            server["port_reused_by"] = active_owner
            continue
        if port_open(endpoint[0], endpoint[1]):
            owner = listener_owner_for_port(endpoint[1])
            server["port_reused"] = True
            server["url_is_current"] = False
            server["port_reused_by"] = {
                "type": "process",
                "pid": owner.get("pid"),
                "cwd": owner.get("cwd"),
                "project": owner.get("project"),
            }


def resource_project_identity(project: str | None, fallback_name: str | None = None) -> dict[str, str | None]:
    if project:
        resolved = canonical_project(str(project))
        return {
            "usage_key": f"path:{resolved}",
            "project": resolved,
            "project_key": project_key_from_path(resolved),
            "name": Path(resolved).name,
        }
    project_key = project_key_from_resource_name(fallback_name)
    return {
        "usage_key": f"name:{project_key}",
        "project": None,
        "project_key": project_key,
        "name": project_key,
    }


def known_project_paths(
    state: dict[str, Any] | None,
    containers: list[dict[str, Any]] | None = None,
    extra: list[str] | None = None,
) -> set[str]:
    """Repo paths eligible to claim unattributed resources by name.

    State-recorded projects (server records, durable port pins) and `extra`
    entries are trusted as already canonical; container projects can come from
    Compose labels pointing inside a repo, so they are canonicalized.
    """
    paths: set[str] = set()
    for value in extra or []:
        if value:
            paths.add(str(value))
    for server in (state or {}).get("servers", {}).values():
        if server.get("project"):
            paths.add(str(server["project"]))
    for assignment in (state or {}).get("port_assignments", {}).values():
        if assignment.get("project"):
            paths.add(str(assignment["project"]))
    for container in containers or []:
        if container.get("project"):
            paths.add(canonical_project(str(container["project"])))
    return paths


def container_project_attribution(container: dict[str, Any], known_projects: set[str]) -> dict[str, Any]:
    """Single authority for which project group a Docker container belongs to.

    Display grouping (`build_project_usage`) and whole-project actions
    (`build_project_runtime_spec` via `matching_project_containers`) both
    resolve container membership here, so the group a UI shows a container
    under is exactly the group whose project start/stop/restart acts on it.

    Explicit attribution (Compose labels or coordinator sidecar metadata)
    always wins. An unattributed container is claimed by name only when
    exactly one known project path matches its name key; with zero or several
    claimants it stays in its own name-keyed group and no project action
    touches it.
    """
    fallback_name = container.get("name") or container.get("image")
    if container.get("project"):
        identity = resource_project_identity(str(container["project"]), fallback_name)
        identity["attribution"] = "explicit"
        return identity
    name_key = project_key_from_resource_name(fallback_name)
    claimants = sorted(path for path in known_projects if project_key_from_path(path) == name_key)
    if len(claimants) == 1:
        identity = resource_project_identity(claimants[0], fallback_name)
        identity["attribution"] = "name_match"
        return identity
    identity = resource_project_identity(None, fallback_name)
    identity["attribution"] = "ambiguous_name" if claimants else "unclaimed"
    return identity


def process_owner_matches_project(pid: int, project: str | None) -> bool:
    if not project:
        return True
    cwd = process_cwd(pid)
    if not cwd:
        return False
    resolved_project = canonical_project(str(project))
    owner_project = canonical_project(cwd)
    return owner_project == resolved_project or path_inside(cwd, resolved_project)


def annotate_server_process_usage(servers: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    process_table = read_process_table()
    if not process_table:
        for server in servers:
            server.pop("process_usage", None)
        return {}

    children = children_by_parent(process_table)
    sampled_at = iso_timestamp()
    listener_cache: dict[int, dict[str, Any]] = {}
    cwd_match_cache: dict[tuple[int, str | None], bool] = {}

    for server in servers:
        roots: set[int] = set()
        project = server.get("project")
        pid = int(server.get("pid") or 0)
        if pid in process_table:
            identity = (server.get("health") or {}).get("identity") or {}
            if identity.get("ok") is not False:
                roots.add(pid)

        port = int(server.get("port") or 0)
        if port and (server.get("status") != "stopped" or server.get("url_is_current") or roots):
            owner = listener_cache.get(port)
            if owner is None:
                owner = listener_owner_for_port(port)
                listener_cache[port] = owner
            owner_pid = int(owner.get("pid") or 0)
            if owner_pid in process_table:
                cache_key = (owner_pid, str(project) if project else None)
                matches = cwd_match_cache.get(cache_key)
                if matches is None:
                    matches = process_owner_matches_project(owner_pid, str(project) if project else None)
                    cwd_match_cache[cache_key] = matches
                if matches:
                    roots.add(owner_pid)

        pids = process_tree_pids(roots, process_table, children)
        usage = summarize_process_usage(pids, process_table, root_pids=roots, source="process_tree")
        if usage:
            usage["sampled_at"] = sampled_at
            usage["project"] = project
            usage["server_id"] = server.get("id")
            usage["server_name"] = server.get("name")
            server["process_usage"] = usage
        else:
            server.pop("process_usage", None)

    return process_table


def build_project_usage(
    servers: list[dict[str, Any]],
    docker: dict[str, Any],
    process_table: dict[int, dict[str, Any]],
    state: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    projects: dict[str, dict[str, Any]] = {}
    pids_by_project: dict[str, set[int]] = {}
    containers = docker.get("containers") or []
    # Same claim set as matching_project_containers: membership shown here is
    # exactly the membership whole-project actions act on.
    claimant_paths = known_project_paths(
        state, containers, extra=[str(s["project"]) for s in servers if s.get("project")]
    )

    def ensure(identity: dict[str, str | None]) -> dict[str, Any]:
        usage_key = str(identity["usage_key"])
        row = projects.setdefault(
            usage_key,
            {
                "usage_key": usage_key,
                "project": identity.get("project"),
                "project_key": identity.get("project_key"),
                "name": identity.get("name"),
                "server_count": 0,
                "container_count": 0,
                "process_count": 0,
                "cpu_percent": 0.0,
                "memory_bytes": 0,
                "process_cpu_percent": 0.0,
                "process_memory_bytes": 0,
                "docker_cpu_percent": 0.0,
                "docker_memory_bytes": 0,
                # Authoritative membership so UIs can group inventory rows by
                # repo without re-implementing the identity heuristics above.
                "server_ids": [],
                "container_names": [],
                "processes": [],
                "hot_processes": [],
            },
        )
        return row

    for server in servers:
        identity = resource_project_identity(server.get("project"), server.get("name"))
        row = ensure(identity)
        row["server_count"] += 1
        if server.get("id"):
            row["server_ids"].append(str(server["id"]))
        usage = server.get("process_usage") or {}
        for pid in usage.get("pids") or []:
            with contextlib.suppress(TypeError, ValueError):
                pids_by_project.setdefault(str(identity["usage_key"]), set()).add(int(pid))

    for usage_key, pids in pids_by_project.items():
        row = projects.get(usage_key)
        if not row:
            continue
        summary = summarize_process_usage(pids, process_table, source="project_processes")
        if not summary:
            continue
        row["process_count"] = summary["process_count"]
        row["process_cpu_percent"] = summary["cpu_percent"]
        row["process_memory_bytes"] = summary["memory_bytes"]
        row["processes"] = summary["processes"]
        row["hot_processes"] = summary["hot_processes"]

    for container in containers:
        identity = container_project_attribution(container, claimant_paths)
        row = ensure(identity)
        row["container_count"] += 1
        if container.get("name"):
            row["container_names"].append(str(container["name"]))
        stats = container.get("stats") or {}
        if stats.get("live") is False:
            continue
        cpu = stats.get("cpu_percent")
        memory = stats.get("memory_usage_bytes")
        if isinstance(cpu, (int, float)):
            row["docker_cpu_percent"] += float(cpu)
        if isinstance(memory, (int, float)):
            row["docker_memory_bytes"] += int(memory)

    for row in projects.values():
        row["cpu_percent"] = round(float(row.get("process_cpu_percent") or 0) + float(row.get("docker_cpu_percent") or 0), 2)
        row["memory_bytes"] = int(row.get("process_memory_bytes") or 0) + int(row.get("docker_memory_bytes") or 0)
        row["docker_cpu_percent"] = round(float(row.get("docker_cpu_percent") or 0), 2)

    return sorted(
        projects.values(),
        key=lambda item: (float(item.get("cpu_percent") or 0), int(item.get("memory_bytes") or 0), str(item.get("name") or "")),
        reverse=True,
    )


def stop_reason_from_health(server: dict[str, Any], health: dict[str, Any]) -> str:
    pid = server.get("pid")
    check = health.get("check") or {}
    identity = health.get("identity") or {}
    if identity.get("ok") is False:
        return str(identity.get("reason") or "Process belongs to a different project")
    if not health.get("pid_alive"):
        detail = check.get("error") or check.get("reason")
        if detail:
            return f"Process {pid or 'unknown'} is not alive; health check: {detail}"
        return f"Process {pid or 'unknown'} is not alive"
    if not health.get("ok"):
        detail = check.get("error") or check.get("reason") or check.get("status")
        return f"Health check failed: {detail}" if detail else "Health check failed"
    return "Stopped by coordinator"


def mark_server_stopped(
    state: dict[str, Any],
    server: dict[str, Any],
    *,
    reason: str,
    stopped_at: str | None = None,
    record: bool = True,
) -> None:
    was_stopped = server.get("status") == "stopped"
    server["status"] = "stopped"
    server["stopped_at"] = stopped_at or server.get("stopped_at") or iso_timestamp()
    server["stopped_ts"] = now()
    server["stopped_reason"] = reason
    server["updated_at"] = iso_timestamp()
    if record and not was_stopped:
        record_event(state, "server.stopped", server)


def normalize_env(values: list[str] | None) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise ValueError(f"environment value must be KEY=VALUE: {item!r}")
        key, value = item.split("=", 1)
        env[key] = value
    return env


def format_command(command: str, *, port: int, host: str) -> str:
    return command.replace("{port}", str(port)).replace("{host}", host)


def start_process(
    *,
    command: str,
    cwd: str,
    env_extra: dict[str, str],
    server_id: str,
) -> tuple[int, str]:
    logs_dir().mkdir(parents=True, exist_ok=True)
    log_path = logs_dir() / f"{server_id}.log"
    log_file = log_path.open("ab", buffering=0)
    env = os.environ.copy()
    env.update(env_extra)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=True,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return process.pid, str(log_path)


def http_health(url: str, timeout: float = 2.0) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return {"ok": False, "error": f"unsupported health URL scheme: {parsed.scheme}"}
    if not parsed.hostname:
        return {"ok": False, "error": "health URL is missing a host"}
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    deadline = time.monotonic() + max(timeout, 0.1)
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
        raw.settimeout(max(deadline - time.monotonic(), 0.1))
        sock = raw
        if parsed.scheme == "https":
            # Health probes are liveness checks, not security boundaries. For
            # loopback targets, skip certificate verification: a TLS edge on
            # 127.0.0.1 typically serves a cert for a public hostname (e.g. a
            # *.example wildcard) that can never validate against the loopback
            # address, and the probe never leaves the machine.
            if parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()
            sock = context.wrap_socket(raw, server_hostname=parsed.hostname)
            sock.settimeout(max(deadline - time.monotonic(), 0.1))
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}\r\n"
            "Connection: close\r\n"
            "User-Agent: CodexDevCoordinator/1\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        response = b""
        while b"\r\n" not in response and len(response) < 8192:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out after {timeout:.1f}s")
            sock.settimeout(max(remaining, 0.1))
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk
        status_line = response.splitlines()[0].decode("iso-8859-1", errors="replace") if response else ""
        parts = status_line.split(None, 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return {"ok": False, "error": "invalid HTTP response", "response": status_line}
        status = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""
        return {"ok": 200 <= status < 400, "status": status, "reason": reason}
    except (socket.timeout, TimeoutError) as exc:
        return {"ok": False, "classification": "timeout", "error": str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()


def within_startup_grace(server: dict[str, Any]) -> bool:
    created_ts = server.get("created_ts")
    if created_ts is None:
        return False
    try:
        return (now() - float(created_ts)) <= STARTUP_GRACE_SECONDS
    except (TypeError, ValueError):
        return False


def server_health(
    server: dict[str, Any],
    *,
    attempts: int = 1,
    backoff: float = HEALTH_RETRY_BACKOFF_SECONDS,
) -> dict[str, Any]:
    pid = int(server.get("pid") or 0)
    alive: bool | None = pid_alive(pid) if pid else None
    if alive is False:
        return {
            "ok": False,
            "pid_alive": False,
            "check": {"ok": False, "skipped": "recorded process is not alive"},
            "identity": {"ok": True, "skipped": "not checked because recorded process is not alive"},
            "classification": "stopped",
        }
    identity = server_listener_identity(server)
    health_url = server.get("health_url")
    attempts = max(1, int(attempts))
    check: dict[str, Any] = {"ok": False}
    for attempt in range(attempts):
        if health_url:
            check = http_health(health_url)
        else:
            check = {"ok": port_open("127.0.0.1", int(server["port"]))}
        if check.get("ok"):
            break
        if attempt + 1 < attempts:
            time.sleep(max(0.0, backoff))
    ok = alive is not False and bool(check.get("ok")) and identity.get("ok") is not False
    if ok:
        classification = "healthy"
    elif identity.get("ok") is False:
        classification = "wrong-listener"
    elif within_startup_grace(server):
        classification = "starting"
    else:
        classification = "unhealthy"
    return {
        "ok": ok,
        "pid_alive": alive,
        "check": check,
        "identity": identity,
        "attempts": attempts,
        "classification": classification,
    }


def docker_available_command(args: list[str]) -> dict[str, Any]:
    command = ["docker", *args]
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    except FileNotFoundError:
        return {"ok": False, "command": command, "error": "Docker CLI was not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "command": command, "error": "Docker command timed out"}
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
    }


def normalize_container_name(name: str | None) -> str:
    return str(name or "").strip().lstrip("/")


def docker_metadata_store(state: dict[str, Any]) -> dict[str, Any]:
    docker_state = state.setdefault("docker", {})
    docker_state.setdefault("last_commands", [])
    docker_state.setdefault("stats_history", {})
    return docker_state.setdefault("metadata", {})


def inspect_docker_container(container: str) -> dict[str, Any] | None:
    result = docker_available_command(["inspect", "--format", "{{json .}}", container])
    if not result.get("ok"):
        return None
    for line in str(result.get("stdout") or "").splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            return json.loads(line)
    return None


def compose_project_from_inspection(inspected: dict[str, Any] | None) -> str | None:
    labels = ((inspected or {}).get("Config") or {}).get("Labels") or {}
    working_dir = labels.get("com.docker.compose.project.working_dir")
    return str(Path(working_dir).expanduser().resolve()) if working_dir else None


def sidecar_metadata_for_container(state: dict[str, Any], container: dict[str, Any]) -> dict[str, Any] | None:
    metadata = docker_metadata_store(state)
    keys = [
        normalize_container_name(container.get("name")),
        normalize_container_name(container.get("id")),
    ]
    for key in keys:
        if key and key in metadata:
            return dict(metadata[key])
    return None


def register_docker_metadata(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "docker register")
    container = normalize_container_name(options.get("container"))
    if not container:
        raise ValueError("docker register requires --container")
    force = bool(options.get("force"))
    dry_run = bool(options.get("dry_run"))
    inspected = None if dry_run else inspect_docker_container(container)
    compose_project = compose_project_from_inspection(inspected)
    if compose_project and not force:
        payload = {
            "container": container,
            "project": compose_project,
            "agent": agent,
            "role": options.get("role"),
            "metadata_source": "docker_labels",
            "adopted": False,
            "skipped": True,
            "message": "container already has Docker Compose project metadata",
            "agent_metadata": agent_metadata(agent=agent, project=project, cwd=options.get("cwd"), source="docker_register_skipped"),
            "updated_at": iso_timestamp(),
        }
        record_event(state, "docker.register.skipped", payload)
        return payload

    inspected_name = normalize_container_name((inspected or {}).get("Name"))
    inspected_id = str((inspected or {}).get("Id") or "")
    payload = {
        "container": inspected_name or container,
        "id": inspected_id[:12] or None,
        "project": project,
        "agent": agent,
        "role": options.get("role"),
        "metadata_source": "coordinator_sidecar",
        "adopted": True,
        "agent_metadata": agent_metadata(agent=agent, project=project, cwd=options.get("cwd"), source="docker_register"),
        "updated_at": iso_timestamp(),
    }
    metadata = docker_metadata_store(state)
    metadata[container] = payload
    if inspected_name:
        metadata[inspected_name] = payload
    if inspected_id:
        metadata[inspected_id[:12]] = payload
    record_event(state, "docker.registered", payload)
    return payload


def parse_percent(raw: Any) -> float | None:
    if raw is None:
        return None
    value = str(raw).strip().replace("%", "")
    if not value or value.upper() == "N/A":
        return None
    with contextlib.suppress(ValueError):
        return float(value)
    return None


SIZE_UNITS = {
    "b": 1.0,
    "kb": 1000.0,
    "mb": 1000.0**2,
    "gb": 1000.0**3,
    "tb": 1000.0**4,
    "pb": 1000.0**5,
    "kib": 1024.0,
    "mib": 1024.0**2,
    "gib": 1024.0**3,
    "tib": 1024.0**4,
    "pib": 1024.0**5,
}


def parse_size_bytes(raw: Any) -> float | None:
    if raw is None:
        return None
    value = str(raw).strip()
    if not value or value.upper() == "N/A":
        return None
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?$", value)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "B").lower()
    multiplier = SIZE_UNITS.get(unit)
    if multiplier is None:
        return None
    return number * multiplier


def parse_io_pair(raw: Any) -> tuple[float | None, float | None]:
    if raw is None:
        return None, None
    left, separator, right = str(raw).partition("/")
    if not separator:
        return parse_size_bytes(left), None
    return parse_size_bytes(left), parse_size_bytes(right)


def parse_int(raw: Any) -> int | None:
    if raw is None:
        return None
    with contextlib.suppress(ValueError):
        return int(str(raw).strip())
    return None


def positive_rate(current: float | None, previous: float | None, elapsed: float) -> float | None:
    if current is None or previous is None or elapsed <= 0:
        return None
    delta = current - previous
    if delta < 0:
        return None
    return delta / elapsed


def normalize_docker_stats(item: dict[str, Any], *, timestamp: float) -> dict[str, Any]:
    memory_usage, memory_limit = parse_io_pair(item.get("MemUsage"))
    network_rx, network_tx = parse_io_pair(item.get("NetIO"))
    block_read, block_write = parse_io_pair(item.get("BlockIO"))
    return {
        "id": item.get("ID"),
        "container_id": item.get("Container"),
        "name": item.get("Name"),
        "timestamp": iso_timestamp(timestamp),
        "timestamp_ts": timestamp,
        "live": True,
        "cpu_percent": parse_percent(item.get("CPUPerc")),
        "memory_percent": parse_percent(item.get("MemPerc")),
        "memory_usage_bytes": memory_usage,
        "memory_limit_bytes": memory_limit,
        "network_rx_bytes": network_rx,
        "network_tx_bytes": network_tx,
        "block_read_bytes": block_read,
        "block_write_bytes": block_write,
        "pids": parse_int(item.get("PIDs")),
    }


def attach_docker_rates(sample: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    if not previous:
        return sample
    elapsed = float(sample.get("timestamp_ts") or 0) - float(previous.get("timestamp_ts") or 0)
    sample["network_rx_rate_bytes_per_second"] = positive_rate(
        sample.get("network_rx_bytes"), previous.get("network_rx_bytes"), elapsed
    )
    sample["network_tx_rate_bytes_per_second"] = positive_rate(
        sample.get("network_tx_bytes"), previous.get("network_tx_bytes"), elapsed
    )
    sample["block_read_rate_bytes_per_second"] = positive_rate(
        sample.get("block_read_bytes"), previous.get("block_read_bytes"), elapsed
    )
    sample["block_write_rate_bytes_per_second"] = positive_rate(
        sample.get("block_write_bytes"), previous.get("block_write_bytes"), elapsed
    )
    return sample


def sample_docker_stats(state: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    command = ["docker", "stats", "--no-stream", "--format", "{{json .}}"]
    if dry_run:
        return {"dry_run": True, "command": command}

    result = docker_available_command(command[1:])
    if not result.get("ok"):
        return {"available": False, "error": result.get("error") or result.get("stderr"), "stats": []}

    timestamp = now()
    history_by_id = state.setdefault("docker", {}).setdefault("stats_history", {})
    samples: list[dict[str, Any]] = []
    for line in str(result.get("stdout") or "").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        sample = normalize_docker_stats(item, timestamp=timestamp)
        key = str(sample.get("id") or sample.get("name") or "")
        if not key:
            continue
        history = history_by_id.setdefault(key, [])
        previous = history[-1] if history else None
        sample = attach_docker_rates(sample, previous)
        history.append(sample)
        del history[:-DOCKER_STATS_HISTORY_LIMIT]
        samples.append(sample)

    return {"available": True, "stats": samples}


def docker_ps_inventory(*, all_containers: bool = True, state: dict[str, Any] | None = None) -> dict[str, Any]:
    args = ["ps"]
    if all_containers:
        args.append("--all")
    args.extend(["--format", "{{json .}}"])
    result = docker_available_command(args)
    if not result.get("ok"):
        return {"available": False, "error": result.get("error") or result.get("stderr"), "containers": [], "postgres": []}
    stats_by_id: dict[str, dict[str, Any]] = {}
    history_by_id: dict[str, list[dict[str, Any]]] = {}
    stats_error = None
    if state is not None:
        stats_result = sample_docker_stats(state)
        stats_error = stats_result.get("error")
        stats_by_id = {
            str(item.get("id")): item
            for item in stats_result.get("stats", [])
            if item.get("id")
        }
        history_by_id = state.setdefault("docker", {}).setdefault("stats_history", {})
    containers = []
    postgres = []
    for line in str(result.get("stdout") or "").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        container = {
            "id": item.get("ID"),
            "name": item.get("Names"),
            "image": item.get("Image"),
            "status": item.get("Status"),
            "ports": item.get("Ports"),
        }
        container_id = str(container.get("id") or "")
        if container_id:
            if container_id in stats_by_id:
                container["stats"] = stats_by_id[container_id]
            container["stats_history"] = history_by_id.get(container_id, [])[-DOCKER_STATS_HISTORY_LIMIT:]
        containers.append(container)
    inspect_by_id: dict[str, dict[str, Any]] = {}
    inspect_ids = [str(container.get("id")) for container in containers if container.get("id")]
    if inspect_ids:
        inspect_result = docker_available_command(["inspect", "--format", "{{json .}}", *inspect_ids])
        if inspect_result.get("ok"):
            for line in str(inspect_result.get("stdout") or "").splitlines():
                with contextlib.suppress(json.JSONDecodeError):
                    inspected = json.loads(line)
                    short_id = str(inspected.get("Id") or "")[:12]
                    inspect_by_id[short_id] = inspected
    for container in containers:
        inspected = inspect_by_id.get(str(container.get("id") or ""))
        labels = ((inspected or {}).get("Config") or {}).get("Labels") or {}
        if labels:
            container["labels"] = labels
            container["compose_project"] = labels.get("com.docker.compose.project")
            compose_working_dir = labels.get("com.docker.compose.project.working_dir")
            if compose_working_dir:
                container["project"] = str(Path(compose_working_dir).expanduser().resolve())
                container["metadata_source"] = "docker_labels"
        sidecar = sidecar_metadata_for_container(state, container) if state is not None else None
        if sidecar and not container.get("project"):
            container["project"] = sidecar.get("project")
            container["agent"] = sidecar.get("agent")
            container["role"] = sidecar.get("role")
            container["metadata_source"] = sidecar.get("metadata_source") or "coordinator_sidecar"
            container["adopted"] = sidecar.get("adopted", True)
            container["agent_metadata"] = sidecar.get("agent_metadata")
        elif not container.get("metadata_source"):
            container["metadata_source"] = "none"
        haystack = " ".join(str(container.get(key) or "").lower() for key in ("name", "image", "ports"))
        if "postgres" in haystack or "5432" in haystack:
            postgres.append(container)
    payload: dict[str, Any] = {"available": True, "containers": containers, "postgres": postgres}
    if stats_error:
        payload["stats_error"] = stats_error
    return payload


def backup_inventory(project: str | None, backup_dirs: list[str] | None = None) -> list[dict[str, Any]]:
    roots = []
    if backup_dirs:
        roots.extend(Path(item).expanduser() for item in backup_dirs)
    if project:
        roots.append(Path(project).expanduser().resolve() / ".codex-db-backups")
    backups = []
    seen: set[Path] = set()
    for root in roots:
        root = root.resolve()
        if root in seen or not root.exists():
            continue
        seen.add(root)
        for item in sorted(root.rglob("*")):
            if not item.is_file() or item.name.endswith(".manifest.json"):
                continue
            manifest_path = Path(f"{item}.manifest.json")
            manifest = None
            if manifest_path.exists():
                with contextlib.suppress(json.JSONDecodeError):
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            backups.append(
                {
                    "path": str(item),
                    "size": item.stat().st_size,
                    "modified_at": iso_timestamp(item.stat().st_mtime),
                    "manifest": str(manifest_path) if manifest_path.exists() else None,
                    "database": (manifest or {}).get("database"),
                    "container": (manifest or {}).get("container"),
                    "format": (manifest or {}).get("format"),
                    "sha256": (manifest or {}).get("sha256"),
                }
            )
    return backups


def runtime_config_candidates(project: str, explicit: str | None = None) -> list[Path]:
    resolved = Path(project).expanduser().resolve()
    if explicit:
        explicit_path = Path(explicit).expanduser()
        if not explicit_path.is_absolute():
            explicit_path = resolved / explicit_path
        return [explicit_path]
    return [resolved / item for item in PROJECT_RUNTIME_FILES]


def load_project_runtime_config(project: str, explicit: str | None = None) -> tuple[dict[str, Any], str | None]:
    for candidate in runtime_config_candidates(project, explicit):
        if not candidate.exists():
            continue
        try:
            return json.loads(candidate.read_text(encoding="utf-8")), str(candidate)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid project runtime JSON at {candidate}: {exc}") from exc
    return {}, None


def runtime_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def resolve_runtime_path(project: str, raw: str | None) -> str:
    if not raw:
        return project
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path(project) / path
    return str(path.resolve())


def discover_compose_files(project: str) -> list[str]:
    root = Path(project)
    candidates = [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    ]
    return [item for item in candidates if (root / item).exists()]


def package_dev_script(project: str) -> str | None:
    package_path = Path(project) / "package.json"
    if not package_path.exists():
        return None
    with contextlib.suppress(json.JSONDecodeError):
        package = json.loads(package_path.read_text(encoding="utf-8"))
        script = (package.get("scripts") or {}).get("dev")
        if isinstance(script, str):
            return script
    return None


def infer_fixed_port(command: str | None) -> int | None:
    if not command:
        return None
    patterns = [
        r"(?:--port|-p)\s+([0-9]{2,5})",
        r"(?:^|\s)PORT=([0-9]{2,5})(?:\s|$)",
        r":([0-9]{2,5})(?:/|$)",
    ]
    for pattern in patterns:
        match = re.search(pattern, command)
        if match:
            with contextlib.suppress(ValueError):
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return port
    return None


def normalize_server_definition(raw: dict[str, Any], project: str) -> dict[str, Any]:
    name = str(raw.get("name") or "web")
    port = raw.get("port")
    with contextlib.suppress(TypeError, ValueError):
        port = int(port) if port is not None else None
    cwd = resolve_runtime_path(project, raw.get("cwd"))
    return {
        "type": "server",
        "name": name,
        "role": raw.get("role") or name,
        "required": raw.get("required", True) is not False,
        "project": project,
        "cwd": cwd,
        "cmd": raw.get("cmd") or raw.get("command"),
        "port": port,
        "host": raw.get("host") or "127.0.0.1",
        "health_url": raw.get("health_url"),
        "readiness_url": raw.get("readiness_url") or raw.get("ready_url"),
        "health_timeout": float(raw.get("health_timeout") or 10),
        "env": runtime_list(raw.get("env")),
    }


def normalize_docker_dependency(raw: dict[str, Any]) -> dict[str, Any]:
    name = raw.get("name") or raw.get("container") or raw.get("service") or "docker"
    ports = []
    for item in runtime_list(raw.get("ports") or raw.get("port")):
        if isinstance(item, dict):
            port = item.get("port")
            host = item.get("host") or "127.0.0.1"
        else:
            port = item
            host = "127.0.0.1"
        with contextlib.suppress(TypeError, ValueError):
            port = int(port)
            if 1 <= port <= 65535:
                ports.append({"host": host, "port": port})
    return {
        "type": "docker",
        "name": str(name),
        "container": raw.get("container") or raw.get("name"),
        "image": raw.get("image"),
        "required": raw.get("required", True) is not False,
        "ports": ports,
        "health_url": raw.get("health_url"),
    }


def normalize_health_check(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": raw.get("name") or raw.get("url") or raw.get("port") or "health",
        "type": raw.get("type") or ("http" if raw.get("url") else "tcp"),
        "url": raw.get("url"),
        "host": raw.get("host") or "127.0.0.1",
        "port": raw.get("port"),
        "expect_status": raw.get("expect_status") or raw.get("status") or 200,
        "expect_text": raw.get("expect_text") or raw.get("contains"),
        "required": raw.get("required", True) is not False,
        "timeout": float(raw.get("timeout") or 3),
    }


def matching_project_containers(
    project: str,
    containers: list[dict[str, Any]],
    *,
    state: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Containers whose unified attribution resolves to this project.

    The target project joins the claim set so `project start` on a repo the
    coordinator has never tracked can still adopt its obviously-named
    containers; every other rule is container_project_attribution's.
    """
    resolved = canonical_project(project)
    claimant_paths = known_project_paths(state, containers, extra=[resolved])
    return [
        container
        for container in containers
        if container_project_attribution(container, claimant_paths).get("project") == resolved
    ]


def build_project_runtime_spec(
    state: dict[str, Any],
    *,
    project: str,
    runtime_file: str | None = None,
    include_docker: bool = True,
) -> dict[str, Any]:
    resolved_project = canonical_project(project)
    config, config_path = load_project_runtime_config(resolved_project, runtime_file)
    docker = docker_ps_inventory(state=state) if include_docker else {"available": None, "containers": [], "postgres": []}
    servers_by_name = {
        server.get("name"): dict(server)
        for server in state.get("servers", {}).values()
        if server.get("project") == resolved_project
    }

    server_defs = [
        normalize_server_definition(item, resolved_project)
        for item in runtime_list(config.get("servers") or config.get("server"))
        if isinstance(item, dict)
    ]
    known_names = {item["name"] for item in server_defs}
    if not config_path:
        for name, server in servers_by_name.items():
            if not name or name in known_names:
                continue
            server_defs.append(
                {
                    "type": "server",
                    "name": name,
                    "role": name,
                    "required": True,
                    "project": resolved_project,
                    "cwd": server.get("cwd") or resolved_project,
                    "cmd": server.get("cmd_template") or server.get("cmd"),
                    "port": server.get("port"),
                    "host": server.get("host") or "127.0.0.1",
                    "health_url": server.get("health_url_template") or server.get("health_url"),
                    "readiness_url": None,
                    "health_timeout": 10,
                    "env": [],
                }
            )

    dev_script = package_dev_script(resolved_project)
    if not server_defs and dev_script:
        inferred_port = infer_fixed_port(dev_script)
        server_defs.append(
            {
                "type": "server",
                "name": "web",
                "role": "web",
                "required": True,
                "project": resolved_project,
                "cwd": resolved_project,
                "cmd": "npm run dev -- --host 127.0.0.1 --port {port}",
                "port": inferred_port,
                "host": "127.0.0.1",
                "health_url": f"http://127.0.0.1:{inferred_port}/" if inferred_port else None,
                "readiness_url": None,
                "health_timeout": 10,
                "env": [],
                "missing_fixed_port": inferred_port is None,
            }
        )

    docker_config = config.get("docker") if isinstance(config.get("docker"), dict) else {}
    compose_files = runtime_list(docker_config.get("compose_files") or docker_config.get("files"))
    compose_declared = bool(compose_files)
    if not compose_files and docker_config.get("services"):
        compose_files = discover_compose_files(resolved_project)
        compose_declared = bool(compose_files)
    elif not compose_files and not config_path:
        compose_files = discover_compose_files(resolved_project)
        compose_declared = False
    compose_services = [str(item) for item in runtime_list(docker_config.get("services")) if item]
    compose = {
        "type": "compose",
        "name": "docker-compose",
        "required": compose_declared,
        "declared": compose_declared,
        "discovered": bool(compose_files) and not compose_declared,
        "autostart": compose_declared,
        "cwd": resolved_project,
        "files": [str(item) for item in compose_files],
        "services": compose_services,
    } if compose_files else None

    docker_dependencies: list[dict[str, Any]] = []
    for item in runtime_list(docker_config.get("containers")):
        if isinstance(item, dict):
            docker_dependencies.append(normalize_docker_dependency(item))
    for item in runtime_list(config.get("dependencies")):
        if isinstance(item, dict) and (item.get("type") or "docker") == "docker":
            docker_dependencies.append(normalize_docker_dependency(item))

    known_containers = {item.get("container") or item.get("name") for item in docker_dependencies}
    for container in matching_project_containers(resolved_project, docker.get("containers", []), state=state):
        name = container.get("name")
        if name and name not in known_containers:
            docker_dependencies.append(
                {
                    "type": "docker",
                    "name": name,
                    "container": name,
                    "image": container.get("image"),
                    "required": True,
                    "ports": [],
                    "health_url": None,
                    "discovered": True,
                }
            )

    health_checks = [
        normalize_health_check(item)
        for item in runtime_list(config.get("health_checks"))
        if isinstance(item, dict)
    ]
    return {
        "id": config.get("id") or resolved_project,
        "name": config.get("name") or Path(resolved_project).name,
        "project": resolved_project,
        "project_key": project_key_from_path(resolved_project),
        "config_path": config_path,
        "declared": bool(config_path),
        "servers": server_defs,
        "compose": compose,
        "docker_dependencies": docker_dependencies,
        "health_checks": health_checks,
        "docker": docker,
    }


def docker_container_by_name(containers: list[dict[str, Any]], name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    for container in containers:
        if container.get("name") == name or container.get("id") == name:
            return container
    return None


def docker_inspect_state(container: str | None) -> dict[str, Any] | None:
    if not container:
        return None
    result = docker_available_command(["inspect", "--format", "{{json .State}}", container])
    if not result.get("ok"):
        return None
    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(str(result.get("stdout") or "{}"))
    return None


def docker_log_tail(container: str | None, tail: int = 40) -> str:
    if not container:
        return ""
    result = docker_available_command(["logs", "--tail", str(tail), container])
    if not result.get("ok"):
        return str(result.get("stderr") or result.get("error") or "")
    return str(result.get("stdout") or result.get("stderr") or "")


def classify_docker_dependency(dep: dict[str, Any], container: dict[str, Any] | None) -> str | None:
    if not container:
        return "missing_dependency"
    status = str(container.get("status") or "").lower()
    if is_stopped_container_status(status):
        return "stopped_container"
    if "unhealthy" in status or "dead" in status or "restart" in status:
        return "unhealthy_process"
    for port in dep.get("ports") or []:
        if not port_open(str(port.get("host") or "127.0.0.1"), int(port["port"])):
            return "wrong_port"
    return None


def is_stopped_container_status(status: str) -> bool:
    value = status.lower()
    return "exited" in value or "created" in value or "dead" in value or "stopped" in value


def docker_dependency_status(dep: dict[str, Any], containers: list[dict[str, Any]]) -> dict[str, Any]:
    container = docker_container_by_name(containers, dep.get("container") or dep.get("name"))
    state = docker_inspect_state(container.get("name") if container else dep.get("container"))
    classification = classify_docker_dependency(dep, container)
    logs = docker_log_tail(container.get("name") if container else dep.get("container"), 30) if classification else ""
    exit_reason = None
    if state:
        exit_reason = state.get("Error") or (
            f"exit_code={state.get('ExitCode')} finished_at={state.get('FinishedAt')}"
            if state.get("ExitCode") not in (None, 0)
            else None
        )
    return {
        "type": "docker",
        "name": dep.get("name"),
        "container": dep.get("container"),
        "required": dep.get("required", True),
        "status": container.get("status") if container else "missing",
        "image": (container or {}).get("image") or dep.get("image"),
        "ports": (container or {}).get("ports"),
        "project": (container or {}).get("project"),
        "metadata_source": (container or {}).get("metadata_source"),
        "agent": (container or {}).get("agent"),
        "adopted": (container or {}).get("adopted"),
        "declared_ports": dep.get("ports") or [],
        "ok": classification is None,
        "classification": classification,
        "previous_exit_reason": exit_reason,
        "recent_logs": logs,
    }


def server_status_for_runtime(state: dict[str, Any], server_def: dict[str, Any]) -> dict[str, Any]:
    server_id, server = find_server(state, project=server_def["project"], name=server_def["name"])
    if not server:
        return {
            "type": "server",
            "name": server_def["name"],
            "role": server_def.get("role"),
            "required": server_def.get("required", True),
            "status": "missing",
            "ok": False,
            "classification": "missing_dependency",
            "url": None,
            "port": server_def.get("port"),
            "fixed_port": server_def.get("port"),
            "previous_exit_reason": None,
            "recent_logs": "",
        }
    status_server(state, {"server_id": server_id, "project": server["project"], "name": server["name"]})
    classification = None
    if server.get("status") == "stopped":
        classification = "crashed_process" if server.get("stopped_reason") else "unhealthy_process"
    elif server.get("status") == "unhealthy":
        classification = "unhealthy_process"
    elif not server.get("health", {}).get("pid_alive") and server.get("status") != "stopped":
        classification = "stale_coordinator_metadata"
    logs = tail_text(Path(server.get("log_path") or ""), 30) if classification and server.get("log_path") else ""
    return {
        "type": "server",
        "name": server.get("name"),
        "role": server_def.get("role"),
        "required": server_def.get("required", True),
        "status": server.get("status"),
        "ok": classification is None,
        "classification": classification,
        "url": server.get("url"),
        "health_url": server.get("health_url"),
        "port": server.get("port"),
        "fixed_port": server_def.get("port") or server.get("port"),
        "pid": server.get("pid"),
        "log_path": server.get("log_path"),
        "adopted": server.get("adopted", False),
        "missing_command": server.get("missing_command", False),
        "metadata_source": server.get("metadata_source"),
        "agent": server.get("agent"),
        "agent_metadata": server.get("agent_metadata"),
        "previous_exit_reason": server.get("stopped_reason"),
        "stopped_at": server.get("stopped_at"),
        "recent_logs": logs,
    }


def run_health_check(check: dict[str, Any]) -> dict[str, Any]:
    classification = None
    if check.get("type") == "tcp" or not check.get("url"):
        port = check.get("port")
        if not port:
            classification = "missing_dependency"
            ok = False
        else:
            ok = port_open(str(check.get("host") or "127.0.0.1"), int(port))
            classification = None if ok else "wrong_port"
        return {**check, "ok": ok, "classification": classification}

    parsed = urlparse(str(check["url"]))
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    try:
        conn = connection_class(parsed.hostname, parsed.port, timeout=float(check.get("timeout") or 3))
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read(4096).decode("utf-8", errors="replace")
        expected_status = int(check.get("expect_status") or 200)
        ok = response.status == expected_status
        expected_text = check.get("expect_text")
        if expected_text:
            ok = ok and str(expected_text) in body
        return {
            **check,
            "ok": ok,
            "status": response.status,
            "classification": None if ok else "unhealthy_process",
            "body_excerpt": body[:300],
        }
    except TimeoutError:
        classification = "timeout"
    except OSError as exc:
        classification = "timeout" if "timed out" in str(exc).lower() else "unhealthy_process"
        return {**check, "ok": False, "classification": classification, "error": str(exc)}
    finally:
        with contextlib.suppress(Exception):
            conn.close()  # type: ignore[name-defined]
    return {**check, "ok": False, "classification": classification}


def project_runtime_report(state: dict[str, Any], spec: dict[str, Any], *, action: str) -> dict[str, Any]:
    containers = spec.get("docker", {}).get("containers", [])
    services: list[dict[str, Any]] = []
    concrete_services: list[dict[str, Any]] = []
    if spec.get("compose"):
        compose = dict(spec["compose"])
        compose["status"] = "configured" if compose.get("declared") else "discovered_only"
        compose["ok"] = True
        services.append(compose)
        if compose.get("declared"):
            concrete_services.append(compose)
    docker_services = [docker_dependency_status(dep, containers) for dep in spec.get("docker_dependencies", [])]
    server_services = [server_status_for_runtime(state, server_def) for server_def in spec.get("servers", [])]
    services.extend(docker_services)
    services.extend(server_services)
    concrete_services.extend(docker_services)
    concrete_services.extend(server_services)
    checks = [run_health_check(check) for check in spec.get("health_checks", [])]
    if not concrete_services and not checks:
        services.append(
            {
                "type": "runtime",
                "name": "project-runtime",
                "required": True,
                "status": "missing",
                "ok": False,
                "classification": "missing_dependency",
                "message": "No declared project runtime, managed server, or matching Docker container was found for this project. Add .codex/dev-runtime.json before project start mutates Docker Compose.",
            }
        )
    required_failures = [
        item
        for item in [*services, *checks]
        if item.get("required", True) and not item.get("ok", True)
    ]
    classifications = sorted({item.get("classification") for item in required_failures if item.get("classification")})
    urls = [
        {"name": item.get("name"), "url": item.get("url"), "health_url": item.get("health_url")}
        for item in services
        if item.get("url")
    ]
    ports = [
        {"name": item.get("name"), "port": item.get("port"), "fixed_port": item.get("fixed_port"), "ports": item.get("ports")}
        for item in services
        if item.get("port") or item.get("ports")
    ]
    previous_exit_reasons = [
        {"name": item.get("name"), "reason": item.get("previous_exit_reason"), "stopped_at": item.get("stopped_at")}
        for item in services
        if item.get("previous_exit_reason")
    ]
    logs = [
        {"name": item.get("name"), "text": item.get("recent_logs")}
        for item in services
        if item.get("recent_logs")
    ]
    return {
        "action": action,
        "ok": not required_failures,
        "classification": classifications[0] if classifications else None,
        "classifications": classifications,
        "project": spec["project"],
        "runtime_id": spec["id"],
        "name": spec["name"],
        "config_path": spec.get("config_path"),
        "declared": spec.get("declared", False),
        "urls": urls,
        "ports": ports,
        "services": services,
        "health_checks": checks,
        "previous_exit_reasons": previous_exit_reasons,
        "logs": logs,
    }


def start_runtime_server(state: dict[str, Any], server_def: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    require_identity(options, "project start")
    if server_def.get("missing_fixed_port") and not options.get("allow_port_change"):
        raise RuntimeError(f"project server {server_def['name']} has no fixed port declaration")
    server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
    _, runtime_assignment = find_port_assignment(state, project=server_def["project"], name=server_def["name"])
    # Precedence must match restart_server: an explicit runtime declaration
    # wins, then the durable pin, and only then the (possibly stale) record —
    # otherwise `project start` silently reverts an explicit `port assign`.
    fixed_port = server_def.get("port") or (runtime_assignment or {}).get("port") or (existing or {}).get("port")
    if fixed_port is None and not options.get("allow_port_change"):
        raise RuntimeError(f"project server {server_def['name']} has no fixed port; add .codex/dev-runtime.json")
    if fixed_port is not None:
        existing_health = server_health(existing) if existing else {"ok": False}
        if not existing_health.get("ok"):
            adopted = adopt_runtime_server_if_running(state, {**server_def, "port": fixed_port}, options)
            if adopted:
                return adopted
        reclaim_stale_leases_for_port(
            state,
            project=server_def["project"],
            port=int(fixed_port),
            reason=f"project start reclaimed stale fixed-port lease for {server_def['name']}",
        )
    command = server_def.get("cmd") or (existing or {}).get("cmd_template")
    if not command:
        raise RuntimeError(f"project server {server_def['name']} has no command declaration")
    start_options = {
        "agent": options.get("agent") or os.environ.get("USER") or "codex-agent",
        "project": server_def["project"],
        "name": server_def["name"],
        "cwd": server_def.get("cwd") or (existing or {}).get("cwd") or server_def["project"],
        "cmd": command,
        "range": f"{fixed_port}-{fixed_port}" if fixed_port else options.get("range") or DEFAULT_RANGE,
        "preferred": int(fixed_port) if fixed_port else options.get("preferred"),
        "host": server_def.get("host") or (existing or {}).get("host") or "127.0.0.1",
        "health_url": server_def.get("health_url") or (existing or {}).get("health_url_template") or (existing or {}).get("health_url"),
        "health_timeout": server_def.get("health_timeout") or options.get("health_timeout") or 10,
        "env": server_def.get("env") or [],
    }
    if existing and options.get("force_restart"):
        stop_server(state, {"server_id": server_id, "project": existing["project"], "name": existing["name"], "release_port": True, "reason": "Restarted by project runtime"})
    return start_server(state, start_options)


def project_runtime_status(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    spec = build_project_runtime_spec(state, project=options["project"], runtime_file=options.get("runtime_file"))
    return project_runtime_report(state, spec, action="status")


def ensure_runtime_docker_metadata(state: dict[str, Any], spec: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
    if not options.get("agent"):
        return []
    actions = []
    containers = spec.get("docker", {}).get("containers", [])
    for dep in spec.get("docker_dependencies", []):
        container_name = dep.get("container") or dep.get("name")
        container = docker_container_by_name(containers, container_name)
        if not container or container.get("metadata_source") != "none":
            continue
        payload = {
            "container": container.get("name") or container_name,
            "agent": options.get("agent"),
            "project": spec["project"],
            "cwd": spec["project"],
            "role": dep.get("role") or dep.get("name") or "docker",
        }
        if options.get("dry_run"):
            actions.append({**payload, "dry_run": True, "metadata_source": "planned_coordinator_sidecar"})
        else:
            actions.append(register_docker_metadata(state, payload))
    return actions


def project_runtime_start(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, _project = require_identity(options, "project start")
    spec = build_project_runtime_spec(state, project=options["project"], runtime_file=options.get("runtime_file"))
    before = project_runtime_report(state, spec, action="pre-start")
    dry_run = bool(options.get("dry_run"))
    actions: list[dict[str, Any]] = []
    action_errors: list[dict[str, Any]] = []
    compose = spec.get("compose")
    if compose and compose.get("autostart"):
        command = ["docker", "compose"]
        for file_name in compose.get("files") or []:
            command.extend(["-f", file_name])
        command.extend(["up", "-d"])
        command.extend(compose.get("services") or [])
        try:
            actions.append(run_docker(state, command, cwd=compose["cwd"], dry_run=dry_run, project=spec["project"], agent=agent))
        except Exception as exc:
            action_errors.append({"name": compose.get("name"), "classification": "unhealthy_process", "error": str(exc)})
    elif compose and compose.get("discovered"):
        actions.append(
            {
                "skipped": True,
                "name": compose.get("name"),
                "classification": "missing_dependency",
                "reason": "Docker Compose file was discovered but not declared in .codex/dev-runtime.json; project start will not create a duplicate Compose stack.",
                "files": compose.get("files") or [],
            }
        )
    actions.extend(ensure_runtime_docker_metadata(state, spec, options))
    containers = spec.get("docker", {}).get("containers", [])
    for dep in spec.get("docker_dependencies", []):
        status = docker_dependency_status(dep, containers)
        if status.get("ok"):
            continue
        container_name = dep.get("container") or dep.get("name")
        action = "restart" if status.get("classification") == "unhealthy_process" else "start"
        try:
            actions.append(run_docker(state, ["docker", action, container_name], dry_run=dry_run, project=spec["project"], agent=agent, container=container_name))
        except Exception as exc:
            action_errors.append({"name": dep.get("name"), "classification": status.get("classification") or "unhealthy_process", "error": str(exc)})
    for server_def in [item for item in spec.get("servers", []) if str(item.get("role")).lower() not in {"web", "frontend"}]:
        try:
            actions.append(start_runtime_server(state, server_def, options))
        except Exception as exc:
            action_errors.append({"name": server_def.get("name"), "classification": "missing_dependency", "error": str(exc)})
    for server_def in [item for item in spec.get("servers", []) if str(item.get("role")).lower() in {"web", "frontend"}]:
        try:
            actions.append(start_runtime_server(state, server_def, options))
        except Exception as exc:
            action_errors.append({"name": server_def.get("name"), "classification": "missing_dependency", "error": str(exc)})
    refreshed = build_project_runtime_spec(state, project=spec["project"], runtime_file=options.get("runtime_file"))
    after = project_runtime_report(state, refreshed, action="start")
    after["before"] = before
    after["actions"] = actions
    after["action_errors"] = action_errors
    if action_errors:
        after["ok"] = False
        after["classifications"] = sorted(set(after.get("classifications", []) + [item["classification"] for item in action_errors]))
        after["classification"] = after["classifications"][0]
    return after


def project_runtime_restart(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, _project = require_identity(options, "project restart")
    options = dict(options)
    options["force_restart"] = True
    spec = build_project_runtime_spec(state, project=options["project"], runtime_file=options.get("runtime_file"))
    before = project_runtime_report(state, spec, action="pre-restart")
    dry_run = bool(options.get("dry_run"))
    actions: list[dict[str, Any]] = []
    for server_def in reversed(spec.get("servers", [])):
        server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
        if existing:
            actions.append(stop_server(state, {"server_id": server_id, "agent": agent, "project": existing["project"], "name": existing["name"], "release_port": True, "reason": "Restarted by project runtime"}))
    action_errors: list[str] = []
    for dep in spec.get("docker_dependencies", []):
        container_name = dep.get("container") or dep.get("name")
        current = docker_dependency_status(dep, spec.get("docker", {}).get("containers", []))
        if current.get("status") == "missing":
            # A declared-but-absent container must not abort the restart after
            # the servers were already stopped; project start reports it.
            continue
        try:
            actions.append(run_docker(state, ["docker", "restart", container_name], dry_run=dry_run, project=spec["project"], agent=agent, container=container_name))
        except RuntimeError as exc:
            action_errors.append(f"docker restart {container_name}: {exc}")
    started = project_runtime_start(state, options)
    if action_errors:
        started["action_errors"] = action_errors + list(started.get("action_errors") or [])
    started["action"] = "restart"
    started["before"] = before
    started["actions"] = actions + started.get("actions", [])
    return started


def project_runtime_stop(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, _project = require_identity(options, "project stop")
    spec = build_project_runtime_spec(state, project=options["project"], runtime_file=options.get("runtime_file"))
    before = project_runtime_report(state, spec, action="pre-stop")
    dry_run = bool(options.get("dry_run"))
    actions: list[dict[str, Any]] = []
    # Like start/restart, stop records sidecar attribution for the containers
    # it acts on, so display grouping converges to explicit membership after
    # any whole-project action.
    actions.extend(ensure_runtime_docker_metadata(state, spec, options))
    for server_def in reversed(spec.get("servers", [])):
        server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
        if existing and existing.get("status") != "stopped":
            actions.append(stop_server(state, {"server_id": server_id, "agent": agent, "project": existing["project"], "name": existing["name"], "reason": "Stopped by project runtime"}))
    for dep in spec.get("docker_dependencies", []):
        container_name = dep.get("container") or dep.get("name")
        current = docker_dependency_status(dep, spec.get("docker", {}).get("containers", []))
        if current.get("status") != "missing" and not is_stopped_container_status(str(current.get("status") or "")):
            actions.append(run_docker(state, ["docker", "stop", container_name], dry_run=dry_run, project=spec["project"], agent=agent, container=container_name))
    compose = spec.get("compose")
    if compose and compose.get("autostart"):
        command = ["docker", "compose"]
        for file_name in compose.get("files") or []:
            command.extend(["-f", file_name])
        command.append("stop")
        command.extend(compose.get("services") or [])
        actions.append(run_docker(state, command, cwd=compose["cwd"], dry_run=dry_run, project=spec["project"], agent=agent))
    refreshed = build_project_runtime_spec(state, project=spec["project"], runtime_file=options.get("runtime_file"))
    after = project_runtime_report(state, refreshed, action="stop")
    after["ok"] = True
    after["classification"] = None
    after["classifications"] = []
    after["before"] = before
    after["actions"] = actions
    return after


def build_inventory(state: dict[str, Any], *, project: str | None = None, include_docker: bool = True, backup_dirs: list[str] | None = None) -> dict[str, Any]:
    resolved_project = canonical_project(project) if project else None
    servers = []
    for server in state["servers"].values():
        server_project = server.get("project")
        if resolved_project and (not server_project or canonical_project(str(server_project)) != resolved_project):
            continue
        health = server_health(server)
        if server.get("status") == "stopped":
            server["health"] = health
        elif health.get("ok"):
            server["health"] = health
            server["status"] = "running"
        elif (health.get("identity") or {}).get("ok") is False:
            server["health"] = health
            mark_server_stopped(state, server, reason=stop_reason_from_health(server, health))
            lease_id = server.get("lease_id")
            if lease_id and lease_id in state["leases"]:
                mark_lease_stale_released(
                    state,
                    str(lease_id),
                    state["leases"][lease_id],
                    "linked server process belongs to a different project",
                )
        elif not health.get("pid_alive"):
            server["health"] = health
            mark_server_stopped(state, server, reason=stop_reason_from_health(server, health))
        else:
            server["health"] = health
            server["status"] = "unhealthy"
            server["updated_at"] = iso_timestamp()
        updated = dict(server)
        servers.append(updated)
    leases = [
        lease
        for lease in state["leases"].values()
        if not resolved_project or (lease.get("project") and canonical_project(str(lease.get("project"))) == resolved_project)
    ]
    # Durable port assignments, annotated with the owning server's live status
    # (via the record's identity key — no per-assignment subprocess calls).
    servers_by_key = {
        str(server.get("key")): server for server in state["servers"].values() if server.get("key")
    }
    port_assignments = []
    for assignment in state.setdefault("port_assignments", {}).values():
        if resolved_project and assignment.get("project") != resolved_project:
            continue
        entry = dict(assignment)
        record = servers_by_key.get(str(assignment.get("key")))
        entry["server_status"] = record.get("status") if record else "unregistered"
        port_assignments.append(entry)
    port_assignments.sort(key=lambda item: int(item.get("port") or 0))
    servers = deduplicate_server_records(servers)
    annotate_server_url_currency(servers)
    process_table = annotate_server_process_usage(servers)
    urls = [
        {
            "name": server.get("name"),
            "project": server.get("project"),
            "url": server.get("url"),
            "health_url": server.get("health_url"),
            "status": server.get("status"),
        }
        for server in servers
        if server.get("url") and server.get("url_is_current")
    ]
    recent_events = []
    for event in state.get("history", []):
        payload = event.get("payload") or {}
        if resolved_project and payload.get("project") != resolved_project:
            continue
        recent_events.append(event)
    docker = docker_ps_inventory(state=state) if include_docker else {"available": None, "containers": [], "postgres": []}
    project_usage = build_project_usage(servers, docker, process_table, state)
    return {
        "coordinator_home": str(coordinator_home()),
        "state_path": str(state_path()),
        "project": resolved_project,
        "urls": urls,
        "servers": servers,
        "leases": leases,
        "port_assignments": port_assignments,
        "recent_events": recent_events[-40:],
        "docker": docker,
        "postgres": docker.get("postgres", []),
        "backups": backup_inventory(resolved_project, backup_dirs),
        "project_usage": project_usage,
    }


def wait_for_health(server: dict[str, Any], timeout: float) -> dict[str, Any]:
    deadline = now() + timeout
    last = server_health(server)
    while now() < deadline:
        if last.get("ok"):
            return last
        time.sleep(0.25)
        last = server_health(server)
    return last


def parse_server_endpoint(options: dict[str, Any]) -> tuple[str, int, str]:
    raw_url = options.get("url")
    parsed = urlparse(str(raw_url)) if raw_url else None
    host = str(options.get("host") or (parsed.hostname if parsed else None) or "127.0.0.1")
    port = options.get("port") or (parsed.port if parsed else None)
    if port is None:
        raise ValueError("server register requires --port or --url with a port")
    port = int(port)
    url = str(raw_url or f"http://{host}:{port}")
    return host, port, url


def register_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "server register")
    name = str(options.get("name") or "").strip()
    if not name:
        raise ValueError("server register requires --name")
    host, port, url = parse_server_endpoint(options)
    cwd = str(Path(options.get("cwd") or project).expanduser().resolve())
    command_template = options.get("cmd") or options.get("command")
    command = format_command(command_template, port=port, host=host) if command_template else None
    health_url_template = options.get("health_url") or url
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    pid = options.get("pid")
    if pid is None:
        pid = listening_pid_for_port(port)
    identity = server_listener_identity({"pid": int(pid) if pid else None, "project": project, "port": port, "host": host})
    if identity.get("ok") is False:
        raise RuntimeError(str(identity.get("reason") or f"PID {pid or 'unknown'} is outside project {project}"))
    server_id, existing = find_server(state, project=project, name=name)
    server_id = server_id or str(uuid.uuid4())
    previous = existing or {}
    assignment_key_value, _ = find_port_assignment(state, project=project, name=name)
    foreign = foreign_assigned_ports(state, owner_key=assignment_key_value)
    if int(port) in foreign:
        raise RuntimeError(
            f"port {port} is durably assigned to {assignment_owner_text(foreign[int(port)])}; "
            "register on another port or unassign it first"
        )
    reclaim_stale_leases_for_port(
        state,
        project=project,
        port=port,
        reason=f"server register reclaimed stale lease for {name}",
        allow_occupied_unattached=True,
    )
    server = {
        "id": server_id,
        "key": server_key(project, name),
        "name": name,
        "agent": agent,
        "project": project,
        "cwd": cwd,
        "cmd_template": command_template or previous.get("cmd_template"),
        "cmd": command or previous.get("cmd"),
        "port": port,
        "host": host,
        "url": url,
        "health_url": health_url,
        "health_url_template": health_url_template,
        "lease_id": previous.get("lease_id"),
        "pid": int(pid) if pid else None,
        "log_path": previous.get("log_path"),
        "adopted": True,
        "missing_command": not bool(command_template or previous.get("cmd_template")),
        "metadata_source": options.get("metadata_source") or "server_register",
        "agent_metadata": agent_metadata(agent=agent, project=project, cwd=cwd, source=options.get("metadata_source") or "server_register"),
        "created_at": previous.get("created_at") or iso_timestamp(),
        "updated_at": iso_timestamp(),
    }
    health = wait_for_health(server, float(options.get("health_timeout") or 3))
    server["health"] = health
    server["status"] = "running" if health.get("ok") else "unhealthy"
    if server["status"] == "running" and server.get("pid"):
        lease = lease_existing_server_port(
            state,
            agent=agent,
            project=project,
            port=port,
            purpose=f"server:{name}",
            server_id=server_id,
            owner_pid=int(server["pid"]),
            ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
            assignment_key=assignment_key_value,
        )
        server["lease_id"] = lease["id"]
    # Registration pins the port even when the server is unhealthy or pid-less:
    # the record's port is the operator's declared home for this server.
    record_port_assignment(state, agent=agent, project=project, name=name, port=int(port), source="server_register")
    state["servers"][server_id] = server
    record_event(state, "server.registered", server)
    return server


def adopt_runtime_server_if_running(state: dict[str, Any], server_def: dict[str, Any], options: dict[str, Any]) -> dict[str, Any] | None:
    fixed_port = server_def.get("port")
    if fixed_port is None:
        return None
    port = int(fixed_port)
    host = server_def.get("host") or "127.0.0.1"
    if not port_open(host, port):
        return None
    belongs, owner = listener_belongs_to_project(port, server_def["project"])
    if not belongs:
        raise RuntimeError(
            f"refusing to adopt {server_def['name']} on port {port}: "
            f"{owner.get('reason') or 'listener does not belong to project'}"
        )
    health_url_template = server_def.get("health_url")
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    if health_url and not http_health(health_url, timeout=float(server_def.get("health_timeout") or 3)).get("ok"):
        return None
    return register_server(
        state,
        {
            "agent": options.get("agent"),
            "project": server_def["project"],
            "name": server_def["name"],
            "cwd": server_def.get("cwd") or server_def["project"],
            "cmd": server_def.get("cmd"),
            "port": port,
            "host": host,
            "url": f"http://{host}:{port}",
            "health_url": health_url_template or f"http://{host}:{port}",
            "metadata_source": "project_adoption",
            "health_timeout": server_def.get("health_timeout") or options.get("health_timeout") or 3,
        },
    )


def stop_pid(pid: int) -> None:
    if not pid_alive(pid):
        return
    signaled = False
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        with contextlib.suppress(ProcessLookupError, OSError):
            os.kill(pid, signal.SIGTERM)
            signaled = True
    else:
        signaled = True
    if not signaled and pid_alive(pid):
        with contextlib.suppress(ProcessLookupError, OSError):
            os.kill(pid, signal.SIGTERM)
    deadline = now() + GRACE_SECONDS
    while now() < deadline:
        if not pid_alive(pid):
            return
        time.sleep(0.1)
    with contextlib.suppress(ProcessLookupError, OSError):
        os.killpg(pid, signal.SIGKILL)
    if pid_alive(pid):
        with contextlib.suppress(ProcessLookupError, OSError):
            os.kill(pid, signal.SIGKILL)


def start_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "server start")
    name = options["name"]
    existing_id, existing = find_server(state, project=project, name=name)
    if existing and server_health(existing).get("ok"):
        existing["status"] = "running"
        existing["health"] = server_health(existing)
        if existing.get("port"):
            # Self-heal a MISSING pin only: an idempotent re-start must never
            # move an existing pin (an explicit re-pin would silently revert)
            # nor collide with a port pinned to another server.
            heal_key, heal_pin = find_port_assignment(state, project=project, name=name)
            heal_port = int(existing["port"])
            if heal_pin is None and heal_port not in foreign_assigned_ports(state, owner_key=heal_key):
                record_port_assignment(
                    state, agent=agent, project=project, name=name, port=heal_port, source="server_start"
                )
        return existing
    if existing:
        stop_server(state, {"agent": agent, "project": project, "name": name, "release_port": True})

    server_id = existing_id or str(uuid.uuid4())
    key, assignment = find_port_assignment(state, project=project, name=name)
    port_range = options.get("range")
    preferred = options.get("preferred")
    if assignment and preferred is None:
        assigned_port = int(assignment["port"])
        if port_range:
            # The caller chose a range explicitly: steer to the pinned port when
            # it fits, otherwise honor the range (a successful lease re-pins).
            range_start, range_end = parse_range(port_range)
            if range_start <= assigned_port <= range_end:
                preferred = assigned_port
        else:
            # Default flow: the pinned port is the only acceptable outcome, so a
            # squatter produces a loud error instead of a silent port change.
            port_range = f"{assigned_port}-{assigned_port}"
            preferred = assigned_port
    elif assignment and preferred is not None and int(preferred) == int(assignment["port"]) and not port_range:
        # The owner explicitly asked for its own pin without a range: the pin
        # is the range (it may lie outside DEFAULT_RANGE, which would otherwise
        # reject the request with a misleading "outside 3000-3999" error).
        port_range = f"{int(preferred)}-{int(preferred)}"
    try:
        lease = lease_port(
            state,
            agent=agent,
            project=project,
            port_range=port_range or DEFAULT_RANGE,
            preferred=preferred,
            ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
            purpose=f"server:{name}",
            server_id=server_id,
            assignment_key=key,
        )
    except RuntimeError as exc:
        # Whenever the attempt was pinned to exactly the assigned port —
        # default flow, restart, or project start all pass a single-port range
        # — surface the pin instead of the opaque "no free port available".
        pin_port = int(assignment["port"]) if assignment else None
        effective_range = port_range or DEFAULT_RANGE
        if (
            pin_port is not None
            and preferred == pin_port
            and effective_range in (f"{pin_port}-{pin_port}", str(pin_port))
            and "no free port available" in str(exc)
        ):
            raise RuntimeError(
                f"server '{name}' is pinned to port {pin_port} but it is unavailable ({exc}); "
                f"free the port, or unassign it to pin a fresh one"
            ) from exc
        raise
    port = int(lease["port"])
    record_port_assignment(state, agent=agent, project=project, name=name, port=port, source="server_start")
    host = options.get("host") or "127.0.0.1"
    command = format_command(options["cmd"], port=port, host=host)
    cwd = str(Path(options.get("cwd") or project).expanduser().resolve())
    health_url_template = options.get("health_url")
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    env_extra = normalize_env(options.get("env") or [])
    env_extra.setdefault("PORT", str(port))
    env_extra.setdefault("HOST", host)
    pid, log_path = start_process(command=command, cwd=cwd, env_extra=env_extra, server_id=server_id)
    server = {
        "id": server_id,
        "key": server_key(project, name),
        "name": name,
        "agent": agent,
        "project": str(Path(project).expanduser().resolve()),
        "cwd": cwd,
        "cmd_template": options["cmd"],
        "cmd": command,
        "port": port,
        "host": host,
        "url": f"http://{host}:{port}",
        "health_url": health_url,
        "health_url_template": health_url_template,
        "lease_id": lease["id"],
        "pid": pid,
        "log_path": log_path,
        "adopted": False,
        "missing_command": False,
        "metadata_source": "server_start",
        "agent_metadata": agent_metadata(agent=agent, project=project, cwd=cwd, source="server_start"),
        "status": "starting",
        "created_at": iso_timestamp(),
        "created_ts": now(),
        "updated_at": iso_timestamp(),
    }
    health = wait_for_health(server, float(options.get("health_timeout") or 10))
    server["health"] = health
    server["status"] = "running" if health.get("ok") else "unhealthy"
    state["servers"][server_id] = server
    state["leases"][lease["id"]]["server_id"] = server_id
    record_event(state, "server.started", server)
    return server


def stop_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent = str(options.get("agent") or "").strip()
    if not agent:
        raise ValueError("server stop requires --agent so the coordinator can attribute the action")
    server_id = options.get("server_id")
    server = state["servers"].get(server_id) if server_id else None
    if not server:
        if not options.get("project") or not options.get("name"):
            raise KeyError("server-id or project/name is required")
        server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server or not server_id:
        raise KeyError("matching server not found")
    project = canonical_project(str(options.get("project") or server.get("project") or ""))
    if canonical_project(str(server.get("project") or "")) != project:
        raise ValueError("server stop project does not match the registered server project")
    health = server_health(server)
    server["health"] = health
    if (health.get("identity") or {}).get("ok") is False:
        mark_server_stopped(state, server, reason=stop_reason_from_health(server, health))
        if server.get("lease_id") and server["lease_id"] in state["leases"]:
            mark_lease_stale_released(
                state,
                str(server["lease_id"]),
                state["leases"][server["lease_id"]],
                "linked server process belongs to a different project",
            )
        return server
    stop_pid(int(server.get("pid") or 0))
    server["health"] = server_health(server)
    server["agent"] = agent
    server["agent_metadata"] = agent_metadata(agent=agent, project=project, cwd=server.get("cwd"), source="server_stop")
    mark_server_stopped(state, server, reason=options.get("reason") or "Stopped by coordinator")
    if options.get("release_port", True) and server.get("lease_id"):
        with contextlib.suppress(KeyError):
            release_port(state, lease_id=server["lease_id"])
    return server


def restart_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "server restart")
    server_id, server = find_server(state, project=project, name=options["name"])
    if not server:
        raise KeyError("matching server not found")
    if not server.get("cmd_template"):
        raise RuntimeError(f"server {server.get('name')} is registered without a command; missing_command=true")
    _, assignment = find_port_assignment(state, project=project, name=str(options["name"]))
    fixed_port = int(assignment["port"]) if assignment else int(server["port"])
    restart_options = {
        "agent": agent,
        "project": server["project"],
        "name": server["name"],
        "cwd": server["cwd"],
        "cmd": server["cmd_template"],
        "range": options.get("range") or f"{fixed_port}-{fixed_port}",
        "preferred": fixed_port,
        "host": server.get("host") or "127.0.0.1",
        "health_url": server.get("health_url_template") or server.get("health_url"),
        "health_timeout": options.get("health_timeout") or 10,
    }
    stop_server(state, {"server_id": server_id, "agent": agent, "project": server["project"], "name": server["name"], "release_port": True})
    return start_server(state, restart_options)


def status_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    server_id = options.get("server_id")
    server = state["servers"].get(server_id) if server_id else None
    if not server:
        if not options.get("project") or not options.get("name"):
            raise KeyError("server-id or project/name is required")
        server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server:
        raise KeyError("matching server not found")
    health = server_health(server, attempts=HEALTH_RETRY_ATTEMPTS)
    server["health"] = health
    if server.get("status") == "stopped":
        pass
    elif health.get("ok"):
        server["status"] = "running"
        server["updated_at"] = iso_timestamp()
    elif (health.get("identity") or {}).get("ok") is False:
        mark_server_stopped(state, server, reason=stop_reason_from_health(server, health))
        if server.get("lease_id") and server["lease_id"] in state["leases"]:
            mark_lease_stale_released(
                state,
                str(server["lease_id"]),
                state["leases"][server["lease_id"]],
                "linked server process belongs to a different project",
            )
    elif not health.get("pid_alive"):
        mark_server_stopped(state, server, reason=stop_reason_from_health(server, health))
    else:
        # A live, correctly-owned server that fails its health check is only
        # "unhealthy" once it is past its startup grace window; before that it is
        # still "starting" so a slow boot does not read as a failure.
        server["status"] = "starting" if health.get("classification") == "starting" else "unhealthy"
        server["updated_at"] = iso_timestamp()
    return server


def tail_text(path: Path, lines: int) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace")
    if lines <= 0:
        return content
    return "\n".join(content.splitlines()[-lines:])


def server_logs(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    server_id = options.get("server_id")
    server = state["servers"].get(server_id) if server_id else None
    if not server:
        if not options.get("project") or not options.get("name"):
            raise KeyError("server-id or project/name is required")
        server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server:
        raise KeyError("matching server not found")
    log_path = Path(server.get("log_path") or "")
    text = tail_text(log_path, int(options.get("tail") or 200)) if server.get("log_path") else ""
    return {
        "server": {
            "id": server.get("id"),
            "name": server.get("name"),
            "project": server.get("project"),
            "status": server.get("status"),
            "url": server.get("url"),
            "port": server.get("port"),
            "stopped_at": server.get("stopped_at"),
            "stopped_reason": server.get("stopped_reason"),
            "log_path": server.get("log_path"),
        },
        "text": text,
        "tail": int(options.get("tail") or 200),
    }


def docker_command_is_mutating(command: list[str]) -> bool:
    if len(command) < 2 or command[0] != "docker":
        return False
    if command[1] in {"start", "stop", "restart"}:
        return True
    if len(command) >= 3 and command[1] == "compose" and command[2] in {"up", "down", "stop", "restart"}:
        return True
    return False


def record_docker_command(
    state: dict[str, Any],
    command: list[str],
    cwd: str | None,
    result: dict[str, Any],
    project: str | None = None,
    agent: str | None = None,
) -> None:
    history = state["docker"].setdefault("last_commands", [])
    history.append(
        {
            "at": iso_timestamp(),
            "cwd": cwd,
            "agent": agent,
            "project": project,
            "agent_metadata": agent_metadata(agent=agent, project=project, cwd=cwd, source="docker_command") if agent and project else None,
            "command": command,
            "result": result,
        }
    )
    del history[:-20]


def run_docker(
    state: dict[str, Any],
    command: list[str],
    *,
    cwd: str | None = None,
    dry_run: bool = False,
    project: str | None = None,
    agent: str | None = None,
    container: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    if docker_command_is_mutating(command):
        identity = {"agent": agent, "project": project}
        agent, project = require_identity(identity, "docker " + " ".join(command[1:3]))
    elif project:
        project = canonical_project(project)
    if dry_run:
        result = {"dry_run": True, "command": command, "cwd": cwd, "agent": agent, "project": project}
        if container and agent and project:
            result["metadata"] = register_docker_metadata(
                state,
                {"container": container, "agent": agent, "project": project, "cwd": cwd, "role": role, "dry_run": True},
            )
        record_docker_command(state, command, cwd, result, project, agent)
        return result
    completed = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
        "cwd": cwd,
        "agent": agent,
        "project": project,
    }
    if completed.returncode != 0:
        record_docker_command(state, command, cwd, result, project, agent)
        raise RuntimeError(f"docker command failed: {' '.join(command)}\n{completed.stderr}")
    if container and agent and project:
        result["metadata"] = register_docker_metadata(
            state,
            {"container": container, "agent": agent, "project": project, "cwd": cwd, "role": role},
        )
    record_docker_command(state, command, cwd, result, project, agent)
    return result


def print_result(value: Any, *, as_json: bool = True) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value)


def add_common_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", default=True, help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Coordinate Codex dev ports, servers, and Docker.")
    sub = parser.add_subparsers(dest="group", required=True)

    inventory = sub.add_parser("inventory")
    inventory.add_argument("--project")
    inventory.add_argument("--backup-dir", action="append")
    inventory.add_argument("--no-docker", action="store_true")

    state = sub.add_parser("state")
    state_sub = state.add_subparsers(dest="action", required=True)
    state_sub.add_parser("show")
    reset = state_sub.add_parser("reset")
    reset.add_argument("--force", action="store_true", required=True)

    port = sub.add_parser("port")
    port_sub = port.add_subparsers(dest="action", required=True)
    lease = port_sub.add_parser("lease")
    lease.add_argument("--agent", required=True)
    lease.add_argument("--project", required=True)
    lease.add_argument("--range", default=DEFAULT_RANGE)
    lease.add_argument("--preferred", type=int)
    lease.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    lease.add_argument("--purpose", default="manual")
    release = port_sub.add_parser("release")
    release.add_argument("--lease-id")
    release.add_argument("--port", type=int)
    port_sub.add_parser("list")
    assign = port_sub.add_parser("assign")
    assign.add_argument("--agent", required=True)
    assign.add_argument("--project", required=True)
    assign.add_argument("--name", required=True)
    assign.add_argument("--port", type=int, required=True)
    assign.add_argument("--force", action="store_true")
    unassign = port_sub.add_parser("unassign")
    unassign.add_argument("--agent", required=True)
    unassign.add_argument("--project", required=True)
    unassign.add_argument("--name")
    unassign.add_argument("--port", type=int)
    unassign.add_argument("--force", action="store_true")
    assignments = port_sub.add_parser("assignments")
    assignments.add_argument("--project")

    server = sub.add_parser("server")
    server_sub = server.add_subparsers(dest="action", required=True)
    start = server_sub.add_parser("start")
    start.add_argument("--agent", required=True)
    start.add_argument("--project", required=True)
    start.add_argument("--name", required=True)
    start.add_argument("--cwd")
    start.add_argument("--cmd", required=True)
    # No parser default: start_server must see whether --range was actually
    # given, because an omitted range pins hard to the durable port assignment.
    start.add_argument("--range")
    start.add_argument("--preferred", type=int)
    start.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--health-url")
    start.add_argument("--health-timeout", type=float, default=10)
    start.add_argument("--env", action="append")
    register = server_sub.add_parser("register")
    register.add_argument("--agent", required=True)
    register.add_argument("--project", required=True)
    register.add_argument("--name", required=True)
    register.add_argument("--cwd")
    register.add_argument("--cmd")
    register.add_argument("--url")
    register.add_argument("--port", type=int)
    register.add_argument("--pid", type=int)
    register.add_argument("--host", default="127.0.0.1")
    register.add_argument("--health-url")
    register.add_argument("--health-timeout", type=float, default=3)
    for action_name in ("stop", "restart", "status"):
        action = server_sub.add_parser(action_name)
        action.add_argument("--agent", required=action_name in {"stop", "restart"})
        action.add_argument("--project", required=True)
        action.add_argument("--name", required=True)
        action.add_argument("--health-timeout", type=float, default=10)
        if action_name == "stop":
            action.add_argument("--reason")
    server_logs_parser = server_sub.add_parser("logs")
    server_logs_parser.add_argument("--server-id")
    server_logs_parser.add_argument("--project")
    server_logs_parser.add_argument("--name")
    server_logs_parser.add_argument("--tail", default="200")
    server_sub.add_parser("list")

    project = sub.add_parser("project")
    project_sub = project.add_subparsers(dest="action", required=True)
    for action_name in ("status", "start", "restart", "stop"):
        project_action = project_sub.add_parser(action_name)
        project_action.add_argument("--project", required=True)
        project_action.add_argument("--runtime-file")
        project_action.add_argument("--agent", required=action_name in {"start", "restart", "stop"})
        project_action.add_argument("--allow-port-change", action="store_true")
        project_action.add_argument("--dry-run", action="store_true")

    docker = sub.add_parser("docker")
    docker_sub = docker.add_subparsers(dest="action", required=True)
    docker_ps = docker_sub.add_parser("ps")
    docker_ps.add_argument("--all", "-a", action="store_true")
    docker_ps.add_argument("--dry-run", action="store_true")
    docker_stats = docker_sub.add_parser("stats")
    docker_stats.add_argument("--dry-run", action="store_true")
    compose_up = docker_sub.add_parser("compose-up")
    compose_up.add_argument("--cwd", required=True)
    compose_up.add_argument("--agent", required=True)
    compose_up.add_argument("--project", required=True)
    compose_up.add_argument("--file", action="append", default=[])
    compose_up.add_argument("--detach", action="store_true")
    compose_up.add_argument("--dry-run", action="store_true")
    compose_down = docker_sub.add_parser("compose-down")
    compose_down.add_argument("--cwd", required=True)
    compose_down.add_argument("--agent", required=True)
    compose_down.add_argument("--project", required=True)
    compose_down.add_argument("--file", action="append", default=[])
    compose_down.add_argument("--dry-run", action="store_true")
    logs = docker_sub.add_parser("logs")
    logs.add_argument("--container", required=True)
    logs.add_argument("--tail", default="80")
    logs.add_argument("--dry-run", action="store_true")
    for action_name in ("start", "stop", "restart"):
        container_action = docker_sub.add_parser(action_name)
        container_action.add_argument("--container", required=True)
        container_action.add_argument("--agent", required=True)
        container_action.add_argument("--project", required=True)
        container_action.add_argument("--role")
        container_action.add_argument("--dry-run", action="store_true")
    docker_register = docker_sub.add_parser("register")
    docker_register.add_argument("--container", required=True)
    docker_register.add_argument("--agent", required=True)
    docker_register.add_argument("--project", required=True)
    docker_register.add_argument("--role")
    docker_register.add_argument("--force", action="store_true")
    docker_register.add_argument("--dry-run", action="store_true")

    api = sub.add_parser("api")
    api_sub = api.add_subparsers(dest="action", required=True)
    serve = api_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    return parser


def namespace_to_options(args: argparse.Namespace) -> dict[str, Any]:
    return {key: value for key, value in vars(args).items() if key not in {"group", "action", "json"} and value is not None}


def handle_cli(args: argparse.Namespace) -> Any:
    if args.group == "state" and args.action == "reset":
        if not args.force:
            raise SystemExit("--force is required")
        with locked_state() as state:
            state.clear()
            state.update(default_state())
            return state
    with locked_state() as state:
        if args.group == "inventory":
            return build_inventory(
                state,
                project=args.project,
                include_docker=not args.no_docker,
                backup_dirs=args.backup_dir,
            )
        if args.group == "state" and args.action == "show":
            return state
        if args.group == "port" and args.action == "lease":
            return lease_port(
                state,
                agent=args.agent,
                project=args.project,
                port_range=args.range,
                preferred=args.preferred,
                ttl=args.ttl,
                purpose=args.purpose,
            )
        if args.group == "port" and args.action == "release":
            return release_port(state, lease_id=args.lease_id, port=args.port)
        if args.group == "port" and args.action == "list":
            return list(state["leases"].values())
        if args.group == "port" and args.action == "assign":
            return assign_port(
                state,
                agent=args.agent,
                project=args.project,
                name=args.name,
                port=args.port,
                force=bool(args.force),
            )
        if args.group == "port" and args.action == "unassign":
            return unassign_port(
                state,
                agent=args.agent,
                project=args.project,
                name=args.name,
                port=args.port,
                force=bool(args.force),
            )
        if args.group == "port" and args.action == "assignments":
            return list_port_assignments(state, project=args.project)
        if args.group == "server" and args.action == "start":
            return start_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "register":
            return register_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "stop":
            return stop_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "restart":
            return restart_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "status":
            return status_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "logs":
            return server_logs(state, namespace_to_options(args))
        if args.group == "server" and args.action == "list":
            return list(state["servers"].values())
        if args.group == "project" and args.action == "status":
            return project_runtime_status(state, namespace_to_options(args))
        if args.group == "project" and args.action == "start":
            return project_runtime_start(state, namespace_to_options(args))
        if args.group == "project" and args.action == "restart":
            return project_runtime_restart(state, namespace_to_options(args))
        if args.group == "project" and args.action == "stop":
            return project_runtime_stop(state, namespace_to_options(args))
        if args.group == "docker":
            if args.action == "ps":
                command = ["docker", "ps"]
                if args.all:
                    command.append("--all")
                return run_docker(state, command, dry_run=args.dry_run)
            if args.action == "stats":
                return sample_docker_stats(state, dry_run=args.dry_run)
            if args.action in {"compose-up", "compose-down"}:
                command = ["docker", "compose"]
                for file_name in args.file:
                    command.extend(["-f", file_name])
                command.append("up" if args.action == "compose-up" else "down")
                if args.action == "compose-up" and args.detach:
                    command.append("-d")
                return run_docker(state, command, cwd=args.cwd, dry_run=args.dry_run, project=args.project, agent=args.agent)
            if args.action == "logs":
                return run_docker(
                    state,
                    ["docker", "logs", "--tail", str(args.tail), args.container],
                    dry_run=args.dry_run,
                )
            if args.action in {"start", "stop", "restart"}:
                result = run_docker(
                    state,
                    ["docker", args.action, args.container],
                    dry_run=args.dry_run,
                    project=args.project,
                    agent=args.agent,
                    container=args.container,
                    role=args.role,
                )
                return result
            if args.action == "register":
                return register_docker_metadata(state, namespace_to_options(args))
    raise SystemExit("unsupported command")


class ApiHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CodexDevCoordinator/1"

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}", file=sys.stderr)

    def do_GET(self) -> None:  # noqa: N802
        try:
            with locked_state() as state:
                if self.path == "/v1/state":
                    self._send(200, state)
                elif self.path == "/v1/inventory":
                    self._send(200, build_inventory(state))
                elif self.path == "/v1/ports":
                    self._send(200, list(state["leases"].values()))
                elif self.path == "/v1/ports/assignments":
                    self._send(200, list_port_assignments(state))
                elif self.path == "/v1/servers":
                    self._send(200, list(state["servers"].values()))
                else:
                    self._send(404, {"error": "not found"})
        except Exception as exc:  # pragma: no cover - defensive endpoint wrapper
            self._send(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_json()
            with locked_state() as state:
                if self.path == "/v1/ports/lease":
                    result = lease_port(
                        state,
                        agent=payload["agent"],
                        project=payload["project"],
                        port_range=payload.get("range") or DEFAULT_RANGE,
                        preferred=payload.get("preferred"),
                        ttl=int(payload.get("ttl") or DEFAULT_TTL_SECONDS),
                        purpose=payload.get("purpose") or "manual",
                    )
                elif self.path == "/v1/ports/release":
                    result = release_port(state, lease_id=payload.get("lease_id"), port=payload.get("port"))
                elif self.path == "/v1/ports/assign":
                    result = assign_port(
                        state,
                        agent=payload["agent"],
                        project=payload["project"],
                        name=payload["name"],
                        port=payload["port"],
                        force=bool(payload.get("force")),
                    )
                elif self.path == "/v1/ports/unassign":
                    result = unassign_port(
                        state,
                        agent=payload["agent"],
                        project=payload.get("project"),
                        name=payload.get("name"),
                        port=payload.get("port"),
                        force=bool(payload.get("force")),
                    )
                elif self.path == "/v1/servers/start":
                    result = start_server(state, payload)
                elif self.path == "/v1/servers/register":
                    result = register_server(state, payload)
                elif self.path == "/v1/servers/stop":
                    result = stop_server(state, payload)
                elif self.path == "/v1/servers/restart":
                    result = restart_server(state, payload)
                elif self.path == "/v1/servers/status":
                    result = status_server(state, payload)
                elif self.path == "/v1/servers/logs":
                    result = server_logs(state, payload)
                elif self.path == "/v1/projects/status":
                    result = project_runtime_status(state, payload)
                elif self.path == "/v1/projects/start":
                    result = project_runtime_start(state, payload)
                elif self.path == "/v1/projects/restart":
                    result = project_runtime_restart(state, payload)
                elif self.path == "/v1/projects/stop":
                    result = project_runtime_stop(state, payload)
                elif self.path == "/v1/docker/ps":
                    result = run_docker(state, ["docker", "ps"], dry_run=bool(payload.get("dry_run")))
                elif self.path == "/v1/docker/stats":
                    result = sample_docker_stats(state, dry_run=bool(payload.get("dry_run")))
                elif self.path in {"/v1/docker/compose-up", "/v1/docker/compose-down"}:
                    command = ["docker", "compose"]
                    for file_name in payload.get("file") or []:
                        command.extend(["-f", file_name])
                    command.append("up" if self.path.endswith("compose-up") else "down")
                    if self.path.endswith("compose-up") and payload.get("detach"):
                        command.append("-d")
                    result = run_docker(
                        state,
                        command,
                        cwd=payload.get("cwd"),
                        dry_run=bool(payload.get("dry_run")),
                        project=payload.get("project"),
                        agent=payload.get("agent"),
                    )
                elif self.path == "/v1/docker/logs":
                    result = run_docker(
                        state,
                        ["docker", "logs", "--tail", str(payload.get("tail") or "80"), payload["container"]],
                        dry_run=bool(payload.get("dry_run")),
                    )
                elif self.path in {"/v1/docker/start", "/v1/docker/stop", "/v1/docker/restart"}:
                    docker_action = self.path.rsplit("/", 1)[-1]
                    result = run_docker(
                        state,
                        ["docker", docker_action, payload["container"]],
                        dry_run=bool(payload.get("dry_run")),
                        project=payload.get("project"),
                        agent=payload.get("agent"),
                        container=payload.get("container"),
                        role=payload.get("role"),
                    )
                elif self.path == "/v1/docker/register":
                    result = register_docker_metadata(state, payload)
                else:
                    self._send(404, {"error": "not found"})
                    return
            self._send(200, result)
        except Exception as exc:
            self._send(400, {"error": str(exc)})


class FastBindThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse-DNS lookup in server_bind.

    HTTPServer.server_bind calls socket.getfqdn(), which macOS CI runners
    black-hole for ~30s (mDNSResponder drops reverse queries even for
    loopback), stalling the server between bind() and listen(). The FQDN
    only feeds CGI-style environment we never use — bind like a plain
    TCPServer and report the bound address instead.
    """

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def serve_api(host: str, port: int) -> None:
    server = FastBindThreadingHTTPServer((host, port), ApiHandler)
    # Report the actual bound port so `--port 0` (OS-assigned) is usable:
    # callers treat this stdout line as the readiness signal.
    port = server.server_address[1]
    print(json.dumps({"host": host, "port": port, "url": f"http://{host}:{port}"}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.group == "api" and args.action == "serve":
        serve_api(args.host, args.port)
        return 0
    try:
        print_result(handle_cli(args))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
