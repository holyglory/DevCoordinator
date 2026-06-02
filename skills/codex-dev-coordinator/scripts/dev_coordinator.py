#!/usr/bin/env python3
"""Shared port, dev-server, and Docker coordinator for Codex agents."""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import http.client
import http.server
import json
import os
import signal
import socket
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
        "history": [],
        "docker": {"last_commands": []},
    }


def read_state() -> dict[str, Any]:
    path = state_path()
    if not path.exists():
        return default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid coordinator state JSON at {path}: {exc}") from exc
    data.setdefault("version", VERSION)
    data.setdefault("created_at", iso_timestamp())
    data.setdefault("updated_at", iso_timestamp())
    data.setdefault("leases", {})
    data.setdefault("servers", {})
    data.setdefault("history", [])
    data.setdefault("docker", {"last_commands": []})
    data["docker"].setdefault("last_commands", [])
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


def port_available(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def prune_expired_leases(state: dict[str, Any]) -> None:
    current = now()
    for lease_id, lease in list(state["leases"].items()):
        expires_at = lease.get("expires_at")
        server_id = lease.get("server_id")
        if server_id and state["servers"].get(server_id):
            continue
        if expires_at and current > float(expires_at):
            lease["status"] = "expired"
            record_event(state, "port.expired", lease)
            state["leases"].pop(lease_id, None)


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
) -> dict[str, Any]:
    start, end = parse_range(port_range)
    candidates = []
    if preferred is not None:
        if preferred < start or preferred > end:
            raise ValueError(f"preferred port {preferred} is outside {port_range}")
        candidates.append(preferred)
    candidates.extend(port for port in range(start, end + 1) if port != preferred)

    used = active_lease_ports(state)
    for port in candidates:
        if port in used:
            continue
        if not port_available(port):
            continue
        lease_id = str(uuid.uuid4())
        lease = {
            "id": lease_id,
            "port": port,
            "agent": agent,
            "project": str(Path(project).expanduser().resolve()) if project else "",
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
    resolved = str(Path(project).expanduser().resolve())
    return f"{resolved}::{name}"


def find_server(state: dict[str, Any], *, project: str, name: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    key = server_key(project, name)
    for server_id, server in state["servers"].items():
        if server.get("key") == key:
            return server_id, server
    return None, None


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
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    try:
        conn = connection_class(parsed.hostname, parsed.port, timeout=timeout)
        conn.request("GET", path)
        response = conn.getresponse()
        response.read(200)
        return {"ok": 200 <= response.status < 500, "status": response.status, "reason": response.reason}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        with contextlib.suppress(Exception):
            conn.close()  # type: ignore[name-defined]


def server_health(server: dict[str, Any]) -> dict[str, Any]:
    pid = int(server.get("pid") or 0)
    alive = pid_alive(pid)
    health_url = server.get("health_url")
    if health_url:
        check = http_health(health_url)
    else:
        check = {"ok": port_open("127.0.0.1", int(server["port"]))}
    return {"ok": alive and bool(check.get("ok")), "pid_alive": alive, "check": check}


def wait_for_health(server: dict[str, Any], timeout: float) -> dict[str, Any]:
    deadline = now() + timeout
    last = server_health(server)
    while now() < deadline:
        if last.get("ok"):
            return last
        time.sleep(0.25)
        last = server_health(server)
    return last


def stop_pid(pid: int) -> None:
    if not pid_alive(pid):
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        os.kill(pid, signal.SIGTERM)
    deadline = now() + GRACE_SECONDS
    while now() < deadline:
        if not pid_alive(pid):
            return
        time.sleep(0.1)
    with contextlib.suppress(ProcessLookupError, OSError):
        os.killpg(pid, signal.SIGKILL)


def start_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    project = options["project"]
    name = options["name"]
    existing_id, existing = find_server(state, project=project, name=name)
    if existing and server_health(existing).get("ok"):
        existing["status"] = "running"
        existing["health"] = server_health(existing)
        return existing
    if existing:
        stop_server(state, {"project": project, "name": name, "release_port": True})

    server_id = str(uuid.uuid4())
    lease = lease_port(
        state,
        agent=options.get("agent") or os.environ.get("USER") or "codex-agent",
        project=project,
        port_range=options.get("range") or DEFAULT_RANGE,
        preferred=options.get("preferred"),
        ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
        purpose=f"server:{name}",
        server_id=server_id,
    )
    port = int(lease["port"])
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
        "agent": options.get("agent") or os.environ.get("USER") or "codex-agent",
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
        "status": "starting",
        "created_at": iso_timestamp(),
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
    server_id = options.get("server_id")
    server = state["servers"].get(server_id) if server_id else None
    if not server:
        server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server or not server_id:
        raise KeyError("matching server not found")
    stop_pid(int(server.get("pid") or 0))
    server["status"] = "stopped"
    server["stopped_at"] = iso_timestamp()
    server["health"] = server_health(server)
    state["servers"].pop(server_id, None)
    if options.get("release_port", True) and server.get("lease_id"):
        with contextlib.suppress(KeyError):
            release_port(state, lease_id=server["lease_id"])
    record_event(state, "server.stopped", server)
    return server


def restart_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server:
        raise KeyError("matching server not found")
    restart_options = {
        "agent": options.get("agent") or server.get("agent"),
        "project": server["project"],
        "name": server["name"],
        "cwd": server["cwd"],
        "cmd": server["cmd_template"],
        "range": options.get("range") or DEFAULT_RANGE,
        "preferred": int(server["port"]),
        "host": server.get("host") or "127.0.0.1",
        "health_url": server.get("health_url_template") or server.get("health_url"),
        "health_timeout": options.get("health_timeout") or 10,
    }
    stop_server(state, {"server_id": server_id, "project": server["project"], "name": server["name"], "release_port": True})
    return start_server(state, restart_options)


def status_server(state: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    server_id = options.get("server_id")
    server = state["servers"].get(server_id) if server_id else None
    if not server:
        server_id, server = find_server(state, project=options["project"], name=options["name"])
    if not server:
        raise KeyError("matching server not found")
    server["health"] = server_health(server)
    server["status"] = "running" if server["health"].get("ok") else "unhealthy"
    server["updated_at"] = iso_timestamp()
    return server


def record_docker_command(state: dict[str, Any], command: list[str], cwd: str | None, result: dict[str, Any]) -> None:
    history = state["docker"].setdefault("last_commands", [])
    history.append({"at": iso_timestamp(), "cwd": cwd, "command": command, "result": result})
    del history[:-20]


def run_docker(state: dict[str, Any], command: list[str], *, cwd: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        result = {"dry_run": True, "command": command, "cwd": cwd}
        record_docker_command(state, command, cwd, result)
        return result
    completed = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
        "cwd": cwd,
    }
    record_docker_command(state, command, cwd, result)
    if completed.returncode != 0:
        raise RuntimeError(f"docker command failed: {' '.join(command)}\n{completed.stderr}")
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

    server = sub.add_parser("server")
    server_sub = server.add_subparsers(dest="action", required=True)
    start = server_sub.add_parser("start")
    start.add_argument("--agent", required=True)
    start.add_argument("--project", required=True)
    start.add_argument("--name", required=True)
    start.add_argument("--cwd")
    start.add_argument("--cmd", required=True)
    start.add_argument("--range", default=DEFAULT_RANGE)
    start.add_argument("--preferred", type=int)
    start.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--health-url")
    start.add_argument("--health-timeout", type=float, default=10)
    start.add_argument("--env", action="append")
    for action_name in ("stop", "restart", "status"):
        action = server_sub.add_parser(action_name)
        action.add_argument("--agent")
        action.add_argument("--project", required=True)
        action.add_argument("--name", required=True)
        action.add_argument("--health-timeout", type=float, default=10)
    server_sub.add_parser("list")

    docker = sub.add_parser("docker")
    docker_sub = docker.add_subparsers(dest="action", required=True)
    docker_ps = docker_sub.add_parser("ps")
    docker_ps.add_argument("--dry-run", action="store_true")
    compose_up = docker_sub.add_parser("compose-up")
    compose_up.add_argument("--cwd", required=True)
    compose_up.add_argument("--file", action="append", default=[])
    compose_up.add_argument("--detach", action="store_true")
    compose_up.add_argument("--dry-run", action="store_true")
    compose_down = docker_sub.add_parser("compose-down")
    compose_down.add_argument("--cwd", required=True)
    compose_down.add_argument("--file", action="append", default=[])
    compose_down.add_argument("--dry-run", action="store_true")
    logs = docker_sub.add_parser("logs")
    logs.add_argument("--container", required=True)
    logs.add_argument("--tail", default="80")
    logs.add_argument("--dry-run", action="store_true")

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
        if args.group == "server" and args.action == "start":
            return start_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "stop":
            return stop_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "restart":
            return restart_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "status":
            return status_server(state, namespace_to_options(args))
        if args.group == "server" and args.action == "list":
            return list(state["servers"].values())
        if args.group == "docker":
            if args.action == "ps":
                return run_docker(state, ["docker", "ps"], dry_run=args.dry_run)
            if args.action in {"compose-up", "compose-down"}:
                command = ["docker", "compose"]
                for file_name in args.file:
                    command.extend(["-f", file_name])
                command.append("up" if args.action == "compose-up" else "down")
                if args.action == "compose-up" and args.detach:
                    command.append("-d")
                return run_docker(state, command, cwd=args.cwd, dry_run=args.dry_run)
            if args.action == "logs":
                return run_docker(
                    state,
                    ["docker", "logs", "--tail", str(args.tail), args.container],
                    dry_run=args.dry_run,
                )
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
                elif self.path == "/v1/ports":
                    self._send(200, list(state["leases"].values()))
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
                elif self.path == "/v1/servers/start":
                    result = start_server(state, payload)
                elif self.path == "/v1/servers/stop":
                    result = stop_server(state, payload)
                elif self.path == "/v1/servers/restart":
                    result = restart_server(state, payload)
                elif self.path == "/v1/servers/status":
                    result = status_server(state, payload)
                elif self.path == "/v1/docker/ps":
                    result = run_docker(state, ["docker", "ps"], dry_run=bool(payload.get("dry_run")))
                elif self.path in {"/v1/docker/compose-up", "/v1/docker/compose-down"}:
                    command = ["docker", "compose"]
                    for file_name in payload.get("file") or []:
                        command.extend(["-f", file_name])
                    command.append("up" if self.path.endswith("compose-up") else "down")
                    if self.path.endswith("compose-up") and payload.get("detach"):
                        command.append("-d")
                    result = run_docker(state, command, cwd=payload.get("cwd"), dry_run=bool(payload.get("dry_run")))
                elif self.path == "/v1/docker/logs":
                    result = run_docker(
                        state,
                        ["docker", "logs", "--tail", str(payload.get("tail") or "80"), payload["container"]],
                        dry_run=bool(payload.get("dry_run")),
                    )
                else:
                    self._send(404, {"error": "not found"})
                    return
            self._send(200, result)
        except Exception as exc:
            self._send(400, {"error": str(exc)})


def serve_api(host: str, port: int) -> None:
    server = http.server.ThreadingHTTPServer((host, port), ApiHandler)
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
