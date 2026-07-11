#!/usr/bin/env python3
"""Shared port, dev-server, and Docker coordinator for Codex agents."""

from __future__ import annotations

import argparse
import atexit
import copy
import contextlib
import ctypes
import errno
import fcntl
import glob
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


VERSION = 2
DEFAULT_RANGE = "3000-3999"
DEFAULT_TTL_SECONDS = 8 * 60 * 60
DEFAULT_API_PORT = 29876
API_BODY_LIMIT_BYTES = 64 * 1024
API_MAX_CONCURRENT_REQUESTS = 16
API_REQUEST_TIMEOUT_SECONDS = 10
API_TOKEN_MAX_BYTES = 4096
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
DOCKER_OBSERVATION_TIMEOUT_SECONDS = 8.0
DOCKER_LIFECYCLE_TIMEOUT_SECONDS = 45.0
DOCKER_STANDARD_LOCATIONS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
    "~/.orbstack/bin/docker",
    "~/.docker/bin/docker",
)
OPERATION_STALE_SECONDS = 60 * 60
_PROJECT_ROOT_CACHE: dict[str, str] = {}
_GIT_IDENTITY_CONTEXT = threading.local()
_STATE_LOCK_CONTEXT = threading.local()
_PROJECT_OPERATION_CONTEXT = threading.local()
_SERVER_RESTART_CONTEXT = threading.local()
_PROCESS_INSTANCE_ID = uuid.uuid4().hex
_PROCESS_INSTANCE_PID = os.getpid()
_PROCESS_OWNER_MARKERS: dict[str, tuple[Path, int]] = {}
PROJECT_RUNTIME_FILES = (
    ".codex/dev-runtime.json",
    ".codex/codex-dev-runtime.json",
    "codex-dev-runtime.json",
)


class ListenerIdentityUnobservable(RuntimeError):
    """The caller lacks evidence access; this is not proof of wrong ownership."""

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


class StructuredCoordinatorError(RuntimeError):
    """A user-actionable failure whose machine-readable evidence must survive."""

    def __init__(self, message: str, payload: dict[str, Any]):
        super().__init__(message)
        self.payload = {"error": message, **payload}


class DockerCapabilityError(StructuredCoordinatorError):
    """Docker cannot be executed in this process environment."""


class DockerCommandTimeoutError(StructuredCoordinatorError):
    """A bounded Docker invocation exceeded its deadline."""


class PrivateStateWriteCleanupError(RuntimeError):
    """A private-state write and its temporary-file cleanup both failed."""

    def __init__(
        self,
        *,
        path: Path,
        temporary_path: Path,
        primary_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        super().__init__(
            f"private-state write failed for {path}: {type(primary_error).__name__}: "
            f"{primary_error}; temporary-file cleanup also failed for {temporary_path}: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        self.temporary_path = temporary_path


def coordinator_exception_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, StructuredCoordinatorError):
        return copy.deepcopy(exc.payload)
    return {"error": str(exc), "code": "internal_error", "classification": "unhealthy_process"}


def executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def resolve_docker_executable(
    *,
    environment: dict[str, str] | None = None,
    standard_locations: list[str] | tuple[str, ...] | None = None,
) -> str:
    """Resolve Docker without assuming an interactive-shell PATH.

    macOS GUI processes commonly inherit launchd's minimal PATH.  Respect an
    explicit absolute override first, then the supplied PATH, then well-known
    Docker Desktop, OrbStack, Homebrew, and user installation locations.
    """

    env = os.environ if environment is None else environment
    configured = str(env.get("CODEX_DOCKER_CLI") or "").strip()
    searched: list[str] = []
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            message = "CODEX_DOCKER_CLI must be an absolute executable path"
            raise DockerCapabilityError(
                message,
                {
                    "code": "docker_cli_unavailable",
                    "classification": "missing_dependency",
                    "capability": {
                        "name": "docker_cli",
                        "code": "docker_cli_unavailable",
                        "configured_path": configured,
                        "searched": [configured],
                    },
                },
            )
        searched.append(str(configured_path))
        if executable_file(configured_path):
            # Preserve the executable entry-point path. Multicall CLIs such as
            # OrbStack select behavior from argv[0]; resolving `docker` to its
            # `docker-tools` symlink target breaks an otherwise valid command.
            return str(configured_path.absolute())
        message = f"Docker CLI is unavailable at configured path: {configured_path}"
        raise DockerCapabilityError(
            message,
            {
                "code": "docker_cli_unavailable",
                "classification": "missing_dependency",
                "capability": {
                    "name": "docker_cli",
                    "code": "docker_cli_unavailable",
                    "configured_path": str(configured_path),
                    "searched": searched,
                },
            },
        )

    path_value = str(env.get("PATH") or "")
    on_path = shutil.which("docker", path=path_value)
    if on_path:
        on_path_value = Path(on_path).expanduser()
        searched.append(str(on_path_value))
        if executable_file(on_path_value):
            return str(on_path_value.absolute())

    candidates = DOCKER_STANDARD_LOCATIONS if standard_locations is None else standard_locations
    for raw_candidate in candidates:
        candidate = Path(raw_candidate).expanduser()
        candidate_text = str(candidate)
        if candidate_text not in searched:
            searched.append(candidate_text)
        if executable_file(candidate):
            return str(candidate.absolute())

    message = "Docker CLI is unavailable in PATH or standard installation locations"
    raise DockerCapabilityError(
        message,
        {
            "code": "docker_cli_unavailable",
            "classification": "missing_dependency",
            "capability": {
                "name": "docker_cli",
                "code": "docker_cli_unavailable",
                "searched": searched,
            },
        },
    )


def configured_docker_timeout(*, lifecycle: bool) -> float:
    default = DOCKER_LIFECYCLE_TIMEOUT_SECONDS if lifecycle else DOCKER_OBSERVATION_TIMEOUT_SECONDS
    variable = "CODEX_DOCKER_LIFECYCLE_TIMEOUT_SECONDS" if lifecycle else "CODEX_DOCKER_OBSERVATION_TIMEOUT_SECONDS"
    raw = os.environ.get(variable)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(0.1, min(value, 600.0))


def execute_docker_subprocess(
    command: list[str],
    *,
    cwd: str | None = None,
    lifecycle: bool = False,
    executable: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, float]:
    if not command or command[0] != "docker":
        raise ValueError("Docker commands must begin with the semantic 'docker' executable")
    executable = executable or resolve_docker_executable()
    resolved_command = [executable, *command[1:]]
    timeout_seconds = configured_docker_timeout(lifecycle=lifecycle)
    try:
        completed = subprocess.run(
            resolved_command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        # The executable can disappear after resolution; keep the same
        # actionable capability classification rather than leaking ENOENT.
        raise DockerCapabilityError(
            f"Docker CLI disappeared before execution: {executable}",
            {
                "code": "docker_cli_unavailable",
                "classification": "missing_dependency",
                "capability": {
                    "name": "docker_cli",
                    "code": "docker_cli_unavailable",
                    "resolved_path": executable,
                },
            },
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerCommandTimeoutError(
            f"Docker command timed out after {timeout_seconds:g} seconds: {' '.join(command)}",
            {
                "code": "docker_command_timeout",
                "classification": "timeout",
                "command": command,
                "docker_executable": executable,
                "timeout_seconds": timeout_seconds,
            },
        ) from exc
    return completed, executable, timeout_seconds

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


def api_token_path() -> Path:
    configured = os.environ.get("CODEX_AGENT_COORDINATOR_TOKEN_FILE")
    if configured:
        return Path(configured).expanduser().absolute()
    return coordinator_home() / "api-token"


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        path.chmod(0o700)


def atomic_write_private(path: Path, content: str) -> None:
    ensure_private_directory(path.parent)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    primary_error: BaseException | None = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            # coordinator_exception_payload serializes only str(error), so
            # the top-level failure must contain both incidents.  Keep the
            # requested write failure as the explicit cause.
            raise PrivateStateWriteCleanupError(
                path=path,
                temporary_path=tmp,
                primary_error=primary_error,
                cleanup_error=cleanup_error,
            ) from primary_error


def read_private_api_token(token_file: Path) -> str:
    """Read one regular private token without following its final symlink."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("API token safety requires O_NOFOLLOW support")
    try:
        fd = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP or token_file.is_symlink():
            raise PermissionError(f"API token file must not be a symbolic link: {token_file}") from exc
        raise
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError(f"API token file must be a regular file: {token_file}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError(f"API token file must not be accessible by group or others: {token_file}")
        if metadata.st_size > API_TOKEN_MAX_BYTES:
            raise ValueError(f"API token file exceeds {API_TOKEN_MAX_BYTES} bytes: {token_file}")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            token = handle.read(API_TOKEN_MAX_BYTES + 1).strip()
    finally:
        if fd >= 0:
            os.close(fd)
    if len(token) < 32:
        raise ValueError(f"API token file is empty or too short: {token_file}")
    return token


def open_api_token_initialization_lock(token_file: Path) -> int:
    """Open the persistent token-specific creation lock without following it."""

    lock_file = token_file.with_name(f".{token_file.name}.initialization.lock")
    try:
        fd = os.open(
            lock_file,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP or lock_file.is_symlink():
            raise PermissionError(f"API token initialization lock must not be a symbolic link: {lock_file}") from exc
        raise
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(fd)
        raise PermissionError(f"API token initialization lock must be a regular file: {lock_file}")
    os.fchmod(fd, 0o600)
    return fd


def load_or_create_api_token(path: Path | None = None) -> str:
    """Load the shared credential or win its exclusive first creation.

    Multiple API processes can start at the same time. Exactly one caller may
    create the token; every loser reopens and returns that winner's credential.
    The final path is never pre-resolved or followed as a symbolic link.
    """

    token_file = (path or api_token_path()).expanduser().absolute()
    # Create a missing dedicated parent privately, but never chmod an existing
    # caller-supplied parent such as /tmp or a shared workspace directory.
    token_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("API token safety requires O_NOFOLLOW support")
    lock_fd = open_api_token_initialization_lock(token_file)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            try:
                return read_private_api_token(token_file)
            except FileNotFoundError:
                pass

            token = secrets.token_urlsafe(48)
            try:
                fd = os.open(
                    token_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
            except FileExistsError:
                # A creator outside this process may not use our lock. Reopen
                # the complete credential under the same no-follow checks.
                return read_private_api_token(token_file)
            except OSError as exc:
                if exc.errno == errno.ELOOP or token_file.is_symlink():
                    raise PermissionError(f"API token file must not be a symbolic link: {token_file}") from exc
                raise
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(token + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                directory_fd = os.open(token_file.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except BaseException:
                if fd >= 0:
                    os.close(fd)
                with contextlib.suppress(OSError):
                    token_file.unlink()
                raise
            return token
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def default_state() -> dict[str, Any]:
    return {
        "version": VERSION,
        "revision": 0,
        "created_at": iso_timestamp(),
        "updated_at": iso_timestamp(),
        "leases": {},
        "servers": {},
        "port_assignments": {},
        "history": [],
        "operations": {},
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
    data["version"] = VERSION
    data.setdefault("revision", 0)
    data.setdefault("created_at", iso_timestamp())
    data.setdefault("updated_at", iso_timestamp())
    data.setdefault("leases", {})
    data.setdefault("servers", {})
    data.setdefault("history", [])
    data.setdefault("operations", {})
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
    ensure_private_directory(home)
    state["version"] = VERSION
    state["revision"] = int(state.get("revision") or 0) + 1
    state["updated_at"] = iso_timestamp()
    atomic_write_private(state_path(), json.dumps(state, indent=2, sort_keys=True) + "\n")


@contextlib.contextmanager
def locked_state() -> Any:
    home = coordinator_home()
    ensure_private_directory(home)
    lock_fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(lock_fd, "a+") as lock:
        with contextlib.suppress(OSError):
            lock_path().chmod(0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        previous_depth = int(getattr(_STATE_LOCK_CONTEXT, "depth", 0))
        _STATE_LOCK_CONTEXT.depth = previous_depth + 1
        try:
            state = read_state()
            reconcile_operations(state)
            prune_expired_leases(state)
            prune_stopped_servers(state)
            yield state
            write_state(state)
        finally:
            _STATE_LOCK_CONTEXT.depth = previous_depth
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


def _decode_proc_tcp_address(raw: str, *, ipv6: bool) -> str:
    payload = bytes.fromhex(raw)
    if ipv6:
        payload = b"".join(payload[offset : offset + 4][::-1] for offset in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, payload)
    return socket.inet_ntop(socket.AF_INET, payload[::-1])


def _proc_listening_sockets(port: int) -> list[dict[str, str]]:
    listeners: list[dict[str, str]] = []
    for proc_file, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
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
                        raw_address = fields[1].rsplit(":", 1)[0]
                        listeners.append(
                            {
                                "address": _decode_proc_tcp_address(raw_address, ipv6=ipv6),
                                "inode": fields[9],
                            }
                        )
    return listeners


def _host_addresses(host: str) -> set[str]:
    candidate = str(host or "127.0.0.1").strip().strip("[]")
    if candidate.lower() == "localhost":
        return {"127.0.0.1", "::1"}
    with contextlib.suppress(ValueError):
        return {str(ipaddress.ip_address(candidate))}
    addresses: set[str] = set()
    with contextlib.suppress(OSError):
        for result in socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM):
            addresses.add(str(ipaddress.ip_address(result[4][0])))
    return addresses


def _listener_address_matches(host: str, listener_address: str) -> bool:
    requested = _host_addresses(host)
    if not requested:
        return False
    listener = ipaddress.ip_address(listener_address)
    if listener.is_unspecified:
        return any(ipaddress.ip_address(address).version == listener.version for address in requested)
    return str(listener) in requested


def _listening_inodes_for_port(port: int) -> set[str]:
    """Socket inodes of all TCP LISTEN sockets on ``port`` from Linux procfs."""
    return {item["inode"] for item in _proc_listening_sockets(int(port))}


def _listening_inodes_for_endpoint(host: str, port: int) -> set[str]:
    return {
        item["inode"]
        for item in _proc_listening_sockets(int(port))
        if _listener_address_matches(host, item["address"])
    }


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


def _lsof_listener_observation(
    host: str, port: int, *, expected_pid: int | None = None
) -> tuple[bool, int | None]:
    command = ["lsof", "-nP", "-a"]
    if expected_pid is not None:
        command.extend(["-p", str(expected_pid)])
    command.extend([f"-iTCP:{int(port)}", "-sTCP:LISTEN", "-Fpn"])
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        if completed.returncode not in {0, 1}:
            return False, None
        current_pid: int | None = None
        for line in completed.stdout.splitlines():
            if line.startswith("p"):
                current_pid = int(line[1:])
                continue
            if not line.startswith("n") or current_pid is None:
                continue
            endpoint = line[1:].split("->", 1)[0].split(" (LISTEN)", 1)[0]
            endpoint_host, separator, endpoint_port = endpoint.rpartition(":")
            if not separator or endpoint_port != str(int(port)):
                continue
            endpoint_host = endpoint_host.strip("[]")
            if endpoint_host == "*" or _listener_address_matches(host, endpoint_host):
                return True, current_pid
        return True, None
    except (OSError, subprocess.SubprocessError):
        return False, None


def _lsof_listener_pid_for_endpoint(host: str, port: int, *, expected_pid: int | None = None) -> int | None:
    _observable, pid = _lsof_listener_observation(host, port, expected_pid=expected_pid)
    return pid


def listening_pid_for_endpoint(host: str, port: int) -> int | None:
    if Path("/proc/net/tcp").exists():
        with contextlib.suppress(Exception):
            return _pid_owning_socket_inodes(_listening_inodes_for_endpoint(host, port))
    return _lsof_listener_pid_for_endpoint(host, port)


def registration_pid_identity(*, pid: int, host: str, port: int, project: str) -> dict[str, Any]:
    """Prove that an explicit registration PID owns this project's listener.

    A live PID is not sufficient evidence.  On Linux, bind the claim to the
    exact LISTEN socket inode in ``/proc/net/tcp{,6}`` and require that inode to
    appear in the PID's own fd table.  This deliberately fails closed when the
    caller cannot inspect a capability-bearing target; the production
    coordinator unit is capability-matched for that observation boundary.
    """

    pid = int(pid)
    port = int(port)
    resolved_project = canonical_project(project)
    if pid <= 1 or not pid_alive(pid):
        raise RuntimeError(f"registration PID {pid} is not alive")
    cwd = process_cwd(pid)
    if not cwd:
        if sys.platform.startswith("linux"):
            try:
                raw_cwd = os.readlink(Path("/proc") / str(pid) / "cwd")
                Path(raw_cwd).resolve(strict=True)
            except PermissionError as exc:
                raise ListenerIdentityUnobservable(
                    f"registration PID {pid} working directory is not observable by this process"
                ) from exc
            except OSError:
                pass
        raise RuntimeError(f"registration PID {pid} working directory could not be identified")
    owner_project = canonical_project(cwd)
    if owner_project != resolved_project and not path_inside(cwd, resolved_project):
        raise RuntimeError(
            f"registration PID {pid} cwd {cwd} is outside registered project {resolved_project}"
        )

    proc_fd = Path("/proc") / str(pid) / "fd"
    proc_tcp_available = Path("/proc/net/tcp").exists()
    if proc_tcp_available:
        listener_inodes = _listening_inodes_for_endpoint(host, port)
        if not listener_inodes:
            raise RuntimeError(f"endpoint {host}:{port} has no TCP LISTEN socket")
        try:
            entries = list(os.scandir(proc_fd))
        except PermissionError as exc:
            raise ListenerIdentityUnobservable(
                f"registration PID {pid} fd table is not observable by this process"
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"registration PID {pid} fd table could not be inspected: {exc.strerror or exc}"
            ) from exc
        owned_inodes: set[str] = set()
        denied = 0
        for entry in entries:
            try:
                target = os.readlink(entry.path)
            except PermissionError:
                denied += 1
                continue
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                owned_inodes.add(match.group(1))
        matching = sorted(listener_inodes & owned_inodes)
        if not matching:
            if denied:
                raise ListenerIdentityUnobservable(
                    f"registration PID {pid} listener ownership is not observable for {host}:{port}"
                )
            raise RuntimeError(f"registration PID {pid} does not own a LISTEN socket on port {port}")
        return {
            "ok": True,
            "pid": pid,
            "cwd": cwd,
            "project": owner_project,
            "port": port,
            "host": host,
            "listener_inodes": matching,
            "source": "proc_pid_fd",
        }

    observable, discovered = _lsof_listener_observation(host, port, expected_pid=pid)
    if discovered != pid:
        if not observable and port_open(host, port):
            raise ListenerIdentityUnobservable(
                f"registration PID {pid} listener ownership is not observable for {host}:{port}"
            )
        raise RuntimeError(
            f"registration PID {pid} does not own the listener on port {port}"
        )
    return {
        "ok": True,
        "pid": pid,
        "cwd": cwd,
        "project": owner_project,
        "port": port,
        "host": host,
        "listener_inodes": [],
        "source": "platform_listener_probe",
    }


def resolve_registration_pid(options: dict[str, Any], *, host: str, port: int, project: str) -> tuple[int | None, dict[str, Any] | None]:
    explicit = options.get("pid")
    if explicit is not None:
        identity = registration_pid_identity(pid=int(explicit), host=host, port=port, project=project)
        return int(explicit), identity
    discovered = listening_pid_for_endpoint(host, port)
    if discovered is not None:
        identity = registration_pid_identity(pid=int(discovered), host=host, port=port, project=project)
        return int(discovered), identity
    probe_host = "127.0.0.1" if host == "0.0.0.0" else host
    if port_open(probe_host, int(port)):
        raise RuntimeError(f"endpoint {host}:{port} is open but no listener PID could be identified")
    return None, None


def process_cwd_from_proc(pid: int) -> str | None:
    """Read one Linux cwd symlink without converting denial into a path.

    Some older pathlib versions return a best-effort pseudo-path containing a
    ``readlink: Permission denied`` suffix from ``Path.resolve()`` on procfs.
    That string is not ownership evidence. Read the kernel link directly and
    require the resulting directory to resolve strictly.
    """

    proc_cwd = Path("/proc") / str(int(pid)) / "cwd"
    try:
        raw = os.readlink(proc_cwd)
        if not os.path.isabs(raw):
            return None
        return str(Path(raw).resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return None


def process_cwd(pid: int | None) -> str | None:
    if not pid:
        return None
    if sys.platform.startswith("linux"):
        # Do not fall back to lsof after procfs denial. That is an unknown
        # observation boundary, not permission to synthesize a cwd.
        return process_cwd_from_proc(int(pid))
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


def listener_owner_for_port(port: int, *, host: str | None = None) -> dict[str, Any]:
    pid = listening_pid_for_endpoint(host, port) if host else listening_pid_for_port(port)
    cwd = process_cwd(pid)
    owner_project = canonical_project(cwd) if cwd else None
    return {"pid": pid, "cwd": cwd, "project": owner_project}


def listener_belongs_to_project(port: int, project: str, *, host: str | None = None) -> tuple[bool, dict[str, Any]]:
    owner = listener_owner_for_port(port, host=host)
    resolved_project = canonical_project(project)
    owner_project = owner.get("project")
    if not owner.get("pid"):
        owner["observable"] = False
        owner["reason"] = f"port {port} is open but no listener PID could be identified"
        return False, owner
    if not owner.get("cwd") or not owner_project:
        owner["observable"] = False
        owner["reason"] = f"port {port} is owned by PID {owner['pid']}, but its working directory could not be identified"
        return False, owner
    if owner_project != resolved_project and not path_inside(str(owner.get("cwd")), resolved_project):
        owner["observable"] = True
        owner["reason"] = (
            f"port {port} is owned by PID {owner['pid']} in {owner.get('cwd')}, "
            f"outside project {resolved_project}"
        )
        return False, owner
    owner["observable"] = True
    return True, owner


def listener_evidence_for_port(port: int) -> dict[str, Any]:
    """Return positive listener evidence without trying to bind the port.

    Bind probes are not an availability detector for privileged ports: an
    unprivileged process can receive EACCES for a free port such as 443.  A
    relocation is therefore blocked only by a kernel LISTEN socket, an
    identified listening PID, or a successful loopback connection.
    """

    port = int(port)
    inodes = _listening_inodes_for_port(port)
    pid = _pid_owning_socket_inodes(inodes) if inodes else None
    if pid is None:
        pid = listening_pid_for_port(port)
    reachable = port_open("127.0.0.1", port)
    return {
        "present": bool(inodes or pid is not None or reachable),
        "port": port,
        "pid": pid,
        "proc_listen_socket_count": len(inodes),
        "loopback_reachable": reachable,
    }


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
        if server.get("registration_identity"):
            try:
                return registration_pid_identity(
                    pid=pid,
                    host=str(server.get("host") or "127.0.0.1"),
                    port=int(server.get("port") or 0),
                    project=str(server.get("project") or ""),
                )
            except ListenerIdentityUnobservable as exc:
                return {
                    "ok": None,
                    "observable": False,
                    "pid": pid,
                    "cwd": identity.get("cwd"),
                    "project": identity.get("project"),
                    "reason": str(exc),
                }
            except (OSError, RuntimeError, ValueError) as exc:
                return {
                    "ok": False,
                    "pid": pid,
                    "cwd": identity.get("cwd"),
                    "project": identity.get("project"),
                    "reason": str(exc),
                }
        return identity
    project = server.get("project")
    port = server.get("port")
    if not project or not port:
        return identity
    host = str(server.get("host") or "127.0.0.1")
    if not port_open(host, int(port)):
        return identity
    belongs, owner = listener_belongs_to_project(int(port), str(project), host=host)
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
        if lease.get("pending_operation_id"):
            # Exact-lease server attachment owns this lease until it commits or
            # rolls back; another lock holder must not expire it mid-operation.
            continue
        if server_id:
            if str(lease.get("attachment_status") or "").startswith("failed_after_launch") or lease.get(
                "attachment_status"
            ) == "launch_outcome_unknown":
                # A manual lease that reached process launch is quarantined
                # until an attributed server stop or port release explicitly
                # clears it.  Stale-process pruning must not make a port look
                # reusable merely because cleanup observed that process exit.
                continue
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
        can_reclaim_unattached = purpose.startswith("server:") and (
            allow_occupied_unattached or port_available(port)
        )
        if can_reclaim_unattached:
            released.append(mark_lease_stale_released(state, lease_id, lease, reason))
    return released


def record_event(state: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
    history = state.setdefault("history", [])
    history.append({"at": iso_timestamp(), "type": event_type, "payload": payload})
    del history[:-200]


def pending_operation_for_target(state: dict[str, Any], target: str) -> dict[str, Any] | None:
    for operation in state.setdefault("operations", {}).values():
        if operation.get("target") == target and operation.get("status") == "pending":
            return operation
    return None


def process_owner_marker_path(pid: int, instance_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", instance_id):
        raise ValueError("invalid coordinator process instance identity")
    return coordinator_home() / "process-owners" / f"{pid}-{instance_id}.lock"


def ensure_process_owner_marker() -> str:
    """Hold a process-instance lock that distinguishes PID reuse after crashes."""

    if os.getpid() != _PROCESS_INSTANCE_PID:
        reset_process_owner_identity_after_fork()
    home_key = str(coordinator_home())
    existing = _PROCESS_OWNER_MARKERS.get(home_key)
    if existing:
        return _PROCESS_INSTANCE_ID
    marker = process_owner_marker_path(os.getpid(), _PROCESS_INSTANCE_ID)
    ensure_private_directory(marker.parent)
    fd = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, f"{os.getpid()} {_PROCESS_INSTANCE_ID}\n".encode("ascii"))
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            marker.unlink()
        raise
    _PROCESS_OWNER_MARKERS[home_key] = (marker, fd)
    return _PROCESS_INSTANCE_ID


def cleanup_process_owner_markers() -> None:
    for marker, fd in list(_PROCESS_OWNER_MARKERS.values()):
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            marker.unlink()
    _PROCESS_OWNER_MARKERS.clear()


def reset_process_owner_identity_after_fork() -> None:
    global _PROCESS_INSTANCE_ID, _PROCESS_INSTANCE_PID
    for _marker, fd in list(_PROCESS_OWNER_MARKERS.values()):
        with contextlib.suppress(OSError):
            os.close(fd)
    _PROCESS_OWNER_MARKERS.clear()
    _PROCESS_INSTANCE_ID = uuid.uuid4().hex
    _PROCESS_INSTANCE_PID = os.getpid()


atexit.register(cleanup_process_owner_markers)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=reset_process_owner_identity_after_fork)


def operation_owner_instance_alive(operation: dict[str, Any]) -> bool | None:
    """Return True/False for verified identity, or None for legacy evidence."""

    owner_pid = int(operation.get("owner_pid") or 0)
    instance_id = str(operation.get("owner_instance_id") or "")
    if not owner_pid or not instance_id:
        return None
    if owner_pid == os.getpid() and instance_id == _PROCESS_INSTANCE_ID:
        owner_thread = int(operation.get("owner_thread") or 0)
        if not owner_thread:
            return True
        return any(
            thread.ident == owner_thread and thread.is_alive()
            for thread in threading.enumerate()
        )
    if not pid_alive(owner_pid):
        return False
    try:
        marker = process_owner_marker_path(owner_pid, instance_id)
    except ValueError:
        return False
    try:
        fd = os.open(marker, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                marker.unlink()
            return False
    finally:
        os.close(fd)


def operation_target_kind(target: str) -> str:
    return target.split(":", 1)[0] if ":" in target else target


def delegated_project_operation_id() -> str | None:
    value = getattr(_SERVER_RESTART_CONTEXT, "operation_id", None) or getattr(
        _PROJECT_OPERATION_CONTEXT,
        "operation_id",
        None,
    )
    return str(value) if value else None


@contextlib.contextmanager
def delegated_project_operation(operation: dict[str, Any]) -> Any:
    """Authorize synchronous child mutations for one pending project operation."""

    previous_id = getattr(_PROJECT_OPERATION_CONTEXT, "operation_id", None)
    previous_project = getattr(_PROJECT_OPERATION_CONTEXT, "project", None)
    _PROJECT_OPERATION_CONTEXT.operation_id = str(operation["id"])
    _PROJECT_OPERATION_CONTEXT.project = str(operation["project"])
    try:
        yield
    finally:
        _PROJECT_OPERATION_CONTEXT.operation_id = previous_id
        _PROJECT_OPERATION_CONTEXT.project = previous_project


@contextlib.contextmanager
def delegated_server_restart_operation(operation: dict[str, Any]) -> Any:
    """Authorize exact stop/start children inside one direct server restart."""

    previous_id = getattr(_SERVER_RESTART_CONTEXT, "operation_id", None)
    previous_project = getattr(_SERVER_RESTART_CONTEXT, "project", None)
    _SERVER_RESTART_CONTEXT.operation_id = str(operation["id"])
    _SERVER_RESTART_CONTEXT.project = str(operation["project"])
    try:
        yield
    finally:
        _SERVER_RESTART_CONTEXT.operation_id = previous_id
        _SERVER_RESTART_CONTEXT.project = previous_project


def pending_conflicting_operation(
    state: dict[str, Any],
    *,
    target: str,
    project: str,
    action: str,
    delegated_parent_id: str | None,
) -> dict[str, Any] | None:
    candidate_kind = operation_target_kind(target)
    candidate_is_project = candidate_kind == "project"
    candidate_is_child = candidate_kind in {"server", "docker", "docker-metadata"}
    for operation in state.setdefault("operations", {}).values():
        if operation.get("status") != "pending":
            continue
        operation_id = str(operation.get("id") or "")
        if operation_id == delegated_parent_id:
            parent_target = str(operation.get("target") or "")
            parent_kind = operation_target_kind(parent_target)
            project_child_allowed = parent_kind == "project" and candidate_is_child
            restart_child_allowed = (
                parent_kind == "server"
                and operation.get("action") == "server.restart"
                and target == parent_target
                and action in {"server.stop", "server.start"}
            )
            if str(operation.get("project") or "") != project or not (
                project_child_allowed or restart_child_allowed
            ):
                raise RuntimeError("delegated child operation does not match its pending parent capability")
            continue
        existing_target = str(operation.get("target") or "")
        if existing_target == target:
            return operation
        if str(operation.get("project") or "") != project:
            continue
        existing_kind = operation_target_kind(existing_target)
        existing_is_project = existing_kind == "project"
        existing_is_child = existing_kind in {"server", "docker", "docker-metadata"}
        if (candidate_is_project and existing_is_child) or (candidate_is_child and existing_is_project):
            return operation
    return None


def require_operation_slot(
    state: dict[str, Any],
    *,
    target: str,
    project: str,
    action: str,
    delegated_parent_id: str | None,
) -> None:
    """Reject a conflicting reservation without mutating coordinator state."""

    existing = pending_conflicting_operation(
        state,
        target=target,
        project=project,
        action=action,
        delegated_parent_id=delegated_parent_id,
    )
    if existing:
        raise RuntimeError(
            f"operation already in progress for {target}: "
            f"{existing.get('action')} ({existing.get('id')})"
        )


def begin_operation(
    state: dict[str, Any],
    *,
    action: str,
    target: str,
    agent: str,
    project: str,
    generation: int,
    lease_id: str | None = None,
    server_id: str | None = None,
) -> dict[str, Any]:
    project = canonical_project(project)
    delegated_parent_id = delegated_project_operation_id()
    context_project = getattr(_SERVER_RESTART_CONTEXT, "project", None) or getattr(
        _PROJECT_OPERATION_CONTEXT,
        "project",
        None,
    )
    if delegated_parent_id and str(context_project or "") != project:
        raise RuntimeError("delegated child operation project does not match its parent capability")
    require_operation_slot(
        state,
        target=target,
        project=project,
        action=action,
        delegated_parent_id=delegated_parent_id,
    )
    owner_instance_id = ensure_process_owner_marker()
    operation = {
        "id": str(uuid.uuid4()),
        "action": action,
        "target": target,
        "agent": agent,
        "project": project,
        "generation": generation,
        "status": "pending",
        "phase": "reserved",
        "owner_pid": os.getpid(),
        "owner_thread": threading.get_ident(),
        "owner_instance_id": owner_instance_id,
        "lease_id": lease_id,
        "server_id": server_id,
        "created_at": iso_timestamp(),
        "created_ts": now(),
        "updated_at": iso_timestamp(),
    }
    if delegated_parent_id:
        operation["parent_operation_id"] = delegated_parent_id
    state.setdefault("operations", {})[operation["id"]] = operation
    record_event(state, "operation.started", {**operation})
    return operation


def finish_operation(
    state: dict[str, Any], operation_id: str, *, status: str, phase: str, error: str | None = None
) -> dict[str, Any] | None:
    operation = state.setdefault("operations", {}).get(operation_id)
    if not operation:
        return None
    operation["status"] = status
    operation["phase"] = phase
    operation["updated_at"] = iso_timestamp()
    operation["finished_at"] = iso_timestamp()
    if error:
        operation["error"] = error
    record_event(state, f"operation.{status}", {**operation})
    # Keep a bounded amount of completed operation evidence.
    completed = sorted(
        (item for item in state["operations"].values() if item.get("status") != "pending"),
        key=lambda item: str(item.get("finished_at") or item.get("updated_at") or ""),
    )
    for stale in completed[:-100]:
        state["operations"].pop(str(stale.get("id")), None)
    return operation


def reconcile_operations(state: dict[str, Any]) -> None:
    """Fail abandoned reservations and release their unused leases."""

    for operation in list(state.setdefault("operations", {}).values()):
        if operation.get("status") != "pending":
            continue
        owner_pid = int(operation.get("owner_pid") or 0)
        owner_thread = int(operation.get("owner_thread") or 0)
        try:
            age = max(0.0, now() - float(operation.get("created_ts") or 0))
        except (TypeError, ValueError):
            age = OPERATION_STALE_SECONDS + 1
        owner_identity_alive = operation_owner_instance_alive(operation)
        if owner_identity_alive is True:
            continue
        if owner_identity_alive is None:
            if owner_pid == os.getpid() and owner_thread:
                owner_alive = any(
                    thread.ident == owner_thread and thread.is_alive()
                    for thread in threading.enumerate()
                )
            else:
                owner_alive = bool(owner_pid and pid_alive(owner_pid))
            # Legacy operations have no process-instance marker. Preserve a
            # recently live owner, but age may retire this unverifiable state.
            if owner_alive and age <= OPERATION_STALE_SECONDS:
                continue
        server_id = operation.get("server_id")
        server = state.setdefault("servers", {}).get(server_id) if server_id else None
        live_reserved_process = bool(
            server
            and server.get("operation_id") == operation.get("id")
            and server.get("pid")
            and pid_alive(int(server.get("pid") or 0))
        )
        lease_id = operation.get("lease_id")
        lease = state.setdefault("leases", {}).get(lease_id) if lease_id else None
        manual_lease_attachment = operation.get("lease_source") == "manual"
        launch_outcome_uncertain = str(operation.get("phase") or "") in {
            "launching",
            "launched",
            "health-check",
        }
        if manual_lease_attachment and lease:
            lease.pop("pending_operation_id", None)
            lease.pop("pending_server_id", None)
            lease["last_attachment_failure"] = {
                "at": iso_timestamp(),
                "operation_id": operation.get("id"),
                "process_launched": bool(live_reserved_process or launch_outcome_uncertain),
                "reason": "coordinator operation owner exited before completion",
            }
            if live_reserved_process or launch_outcome_uncertain:
                lease["original_purpose"] = lease.get("original_purpose") or "manual"
                lease["purpose"] = f"server:{(server or {}).get('name') or 'unknown'}"
                lease["server_id"] = server_id
                lease["attachment_status"] = "launch_outcome_unknown"
                lease["reconciliation_required"] = True
            else:
                lease["purpose"] = lease.get("original_purpose") or "manual"
                lease["server_id"] = None
                lease["attachment_status"] = "rolled_back_before_launch"
                lease["reconciliation_required"] = False
        if live_reserved_process or (manual_lease_attachment and launch_outcome_uncertain):
            if not server:
                # The operation evidence is still sufficient to quarantine the
                # lease even if a corrupt state lost the reserved server row.
                server = None
            else:
                server["status"] = "orphaned"
                server["reconciliation_required"] = True
                server["stopped_reason"] = (
                    "Coordinator operation owner exited after launch may have begun"
                )
                server["updated_at"] = iso_timestamp()
        elif manual_lease_attachment:
            if server and server.get("operation_id") == operation.get("id"):
                server["failed_lease_id"] = lease_id
                server["lease_id"] = None
                mark_server_stopped(
                    state,
                    server,
                    reason="Coordinator operation owner exited before manual-lease launch began",
                )
        else:
            if lease_id and lease_id in state.setdefault("leases", {}):
                with contextlib.suppress(KeyError):
                    release_port(state, lease_id=str(lease_id))
            if server and server.get("operation_id") == operation.get("id"):
                mark_server_stopped(state, server, reason="Coordinator operation owner exited before launch completed")
        finish_operation(
            state,
            str(operation["id"]),
            status="failed",
            phase="reconciled",
            error="operation owner exited before completion",
        )


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
    for lease_id, lease in list(state["leases"].items()):
        if lease.get("status") != "active" or int(lease.get("port") or 0) != int(port):
            continue
        if lease.get("server_id") == server_id and canonical_project(str(lease.get("project") or "")) == project:
            same_owner = int(lease.get("owner_pid") or 0) == int(owner_pid or 0)
            same_purpose = str(lease.get("purpose") or "") == str(purpose)
            if not same_owner or not same_purpose:
                mark_lease_stale_released(
                    state,
                    lease_id,
                    lease,
                    f"server registration owner or purpose changed on port {port}",
                )
                break
            if assignment_key:
                lease["assignment_key"] = assignment_key
            lease["expires_at"] = now() + ttl if ttl > 0 else None
            lease["expires_at_iso"] = iso_timestamp(lease["expires_at"]) if lease["expires_at"] else None
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
        "assignment_key": assignment_key,
    }
    state["leases"][lease_id] = lease
    record_event(state, "port.leased", lease)
    return lease


def release_port(
    state: dict[str, Any],
    *,
    lease_id: str | None = None,
    port: int | None = None,
    acting_agent: str | None = None,
    acting_project: str | None = None,
) -> dict[str, Any]:
    for existing_id, lease in list(state["leases"].items()):
        if (lease_id and existing_id == lease_id) or (port is not None and int(lease["port"]) == port):
            state["leases"].pop(existing_id, None)
            lease["status"] = "released"
            lease["released_at"] = iso_timestamp()
            if acting_agent and acting_project:
                lease["released_by"] = agent_metadata(
                    agent=acting_agent,
                    project=acting_project,
                    source="port_release",
                )
            record_event(state, "port.released", lease)
            return lease
    raise KeyError("matching lease not found")


def release_port_for_identity(
    state: dict[str, Any],
    *,
    agent: str,
    project: str,
    lease_id: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    agent = str(agent or "").strip()
    project = str(project or "").strip()
    if not agent:
        raise ValueError("port release requires --agent so the coordinator can attribute the action")
    if not project:
        raise ValueError("port release requires --project with the canonical repo path")
    project = canonical_project(project)
    matching = None
    for candidate_id, lease in state.get("leases", {}).items():
        if (lease_id and candidate_id == lease_id) or (
            port is not None and int(lease.get("port") or 0) == int(port)
        ):
            matching = lease
            break
    if not matching:
        raise KeyError("matching lease not found")
    if matching.get("pending_operation_id"):
        raise RuntimeError(
            f"port lease has an attachment operation in progress: {matching['pending_operation_id']}"
        )
    lease_project = matching.get("project")
    if not lease_project or canonical_project(str(lease_project)) != project:
        raise PermissionError("port release project does not match the lease owner project")
    return release_port(
        state,
        lease_id=lease_id,
        port=port,
        acting_agent=agent,
        acting_project=project,
    )


def server_key(project: str, name: str) -> str:
    return f"{canonical_project(project)}::{name}"


def canonical_project(project: str) -> str:
    """Resolve a project root without invoking Git.

    This helper is used by state mutations, including mutations performed while
    ``state.lock`` is held. Walking parent directories for a ``.git`` marker is
    deterministic and keeps an arbitrarily slow Git executable out of the
    cross-agent critical section. Worktrees are covered because their ``.git``
    marker is a file rather than a directory.
    """

    raw = Path(project or os.getcwd()).expanduser().resolve()
    cache_key = str(raw)
    cached = _PROJECT_ROOT_CACHE.get(cache_key)
    if cached:
        return cached
    if int(getattr(_STATE_LOCK_CONTEXT, "depth", 0)):
        # Routed commands resolve project roots before acquiring state.lock. A
        # legacy in-process caller that did not do so gets the resolved path,
        # never a Git-marker walk from inside the critical section.
        return cache_key
    candidate = raw if raw.is_dir() else raw.parent
    for directory in (candidate, *candidate.parents):
        if (directory / ".git").exists():
            resolved = str(directory)
            _PROJECT_ROOT_CACHE[cache_key] = resolved
            _PROJECT_ROOT_CACHE[resolved] = resolved
            return resolved
    _PROJECT_ROOT_CACHE[cache_key] = cache_key
    return cache_key


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


def _relocated_path(value: Any, *, old_project: str, new_project: str) -> str | None:
    if not value:
        return None
    candidate = Path(str(value)).expanduser().resolve()
    old_root = Path(old_project).expanduser().resolve()
    try:
        relative = candidate.relative_to(old_root)
    except ValueError:
        return str(candidate)
    return str(Path(new_project).expanduser().resolve() / relative)


def _stale_release_evidence(
    state: dict[str, Any],
    *,
    lease_id: str,
    old_project: str,
    port: int,
) -> dict[str, Any] | None:
    for event in reversed(state.get("history") or []):
        if event.get("type") != "port.stale_released":
            continue
        payload = event.get("payload") or {}
        if str(payload.get("id") or "") != lease_id:
            continue
        if int(payload.get("port") or 0) != port:
            raise RuntimeError(f"lease {lease_id} stale-release evidence names the wrong port")
        lease_project = str(payload.get("project") or "")
        if not lease_project or canonical_project(lease_project) != old_project:
            raise RuntimeError(f"lease {lease_id} stale-release evidence names the wrong project")
        return payload
    return None


def relocate_port_assignment(
    state: dict[str, Any],
    *,
    agent: str,
    old_project: str,
    new_project: str,
    name: str,
    port: int,
    lease_id: str,
) -> dict[str, Any]:
    """Atomically transfer one stopped server identity to a new checkout.

    Callers must execute this function inside ``locked_state``.  Every
    precondition is checked before the first mutation, so an exception causes
    the context manager to leave the on-disk state byte-for-byte unchanged.
    """

    if not int(getattr(_STATE_LOCK_CONTEXT, "depth", 0)):
        raise RuntimeError("port relocation requires the coordinator state lock")
    agent = str(agent or "").strip()
    name = str(name or "").strip()
    lease_id = str(lease_id or "").strip()
    if not agent:
        raise ValueError("port relocate requires --agent so the action is attributable")
    if not name:
        raise ValueError("port relocate requires --name")
    if not lease_id:
        raise ValueError("port relocate requires --lease-id from the pre-cutover inventory")
    port = int(port)
    if port < 1 or port > 65535:
        raise ValueError(f"port {port} is outside 1-65535")
    old_project = canonical_project(old_project)
    new_project = canonical_project(new_project)
    if old_project == new_project:
        raise ValueError("port relocate requires different old and new projects")

    old_key = server_key(old_project, name)
    new_key = server_key(new_project, name)
    assignments = state.setdefault("port_assignments", {})
    assignment = assignments.get(old_key)
    if not assignment:
        raise KeyError(f"no durable assignment exists for {old_project}::{name}")
    assignment_project = str(assignment.get("project") or "")
    if (
        not assignment_project
        or canonical_project(assignment_project) != old_project
        or str(assignment.get("name") or "") != name
        or int(assignment.get("port") or 0) != port
    ):
        raise RuntimeError("old durable assignment does not match the exact project/name/port precondition")
    if new_key in assignments:
        raise RuntimeError(f"destination already has a durable assignment for {new_project}::{name}")
    for key, candidate in assignments.items():
        if key != old_key and int(candidate.get("port") or 0) == port:
            raise RuntimeError(
                f"port {port} has a foreign durable assignment for "
                f"{candidate.get('project')}::{candidate.get('name')}"
            )

    active_on_port = [
        (candidate_id, candidate)
        for candidate_id, candidate in state.setdefault("leases", {}).items()
        if candidate.get("status") == "active" and int(candidate.get("port") or 0) == port
    ]
    foreign_leases = [(candidate_id, candidate) for candidate_id, candidate in active_on_port if candidate_id != lease_id]
    if foreign_leases:
        candidate_id, candidate = foreign_leases[0]
        raise RuntimeError(
            f"port {port} has foreign active lease {candidate_id} for {candidate.get('project') or 'unknown project'}"
        )
    matching_lease = state["leases"].get(lease_id)
    stale_evidence = None
    if matching_lease:
        if matching_lease.get("status") != "active":
            raise RuntimeError(f"lease {lease_id} is not active")
        if matching_lease.get("pending_operation_id"):
            raise RuntimeError(
                f"lease {lease_id} has pending operation {matching_lease['pending_operation_id']}"
            )
        lease_project = str(matching_lease.get("project") or "")
        if not lease_project or canonical_project(lease_project) != old_project:
            raise RuntimeError(f"lease {lease_id} is owned by the wrong project")
        if int(matching_lease.get("port") or 0) != port:
            raise RuntimeError(f"lease {lease_id} is for the wrong port")
        if str(matching_lease.get("purpose") or "") != f"server:{name}":
            raise RuntimeError(f"lease {lease_id} is not the server:{name} lease")
    else:
        # locked_state may have pruned a stopped/dead linked server's lease in
        # this transaction, or an earlier inventory may already have done so.
        # Accept only exact retained stale-release evidence; an arbitrary
        # missing lease remains a hard failure.
        stale_evidence = _stale_release_evidence(
            state,
            lease_id=lease_id,
            old_project=old_project,
            port=port,
        )
        if stale_evidence is None:
            raise KeyError(f"expected old lease {lease_id} is missing without stale-release evidence")
        if str(stale_evidence.get("purpose") or "") != f"server:{name}":
            raise RuntimeError(f"lease {lease_id} stale-release evidence is not for server:{name}")

    old_servers: list[tuple[str, dict[str, Any]]] = []
    new_servers: list[tuple[str, dict[str, Any]]] = []
    for server_id, server in state.setdefault("servers", {}).items():
        server_project = str(server.get("project") or "")
        resolved = canonical_project(server_project) if server_project else None
        if str(server.get("name") or "") != name:
            continue
        if resolved == old_project:
            old_servers.append((server_id, server))
        elif resolved == new_project:
            new_servers.append((server_id, server))
    if len(old_servers) > 1:
        raise RuntimeError(f"ambiguous old server identity: found {len(old_servers)} {name!r} records")
    if new_servers:
        raise RuntimeError(f"destination already has {len(new_servers)} {name!r} server record(s)")
    matching_server = old_servers[0] if old_servers else None
    if matching_server and int(matching_server[1].get("port") or 0) != port:
        raise RuntimeError("old server record names the wrong port")
    if matching_lease and matching_lease.get("server_id"):
        if not matching_server or str(matching_server[0]) != str(matching_lease.get("server_id")):
            raise RuntimeError("old lease is linked to an ambiguous or different server record")
    if matching_server:
        recorded_pid = int(matching_server[1].get("pid") or 0)
        if recorded_pid and pid_alive(recorded_pid):
            raise RuntimeError(
                f"old server record PID {recorded_pid} is still alive; stop and verify the exact old process first"
            )

    pending_targets = {f"server:{old_key}", f"port:{port}", f"project:{old_project}"}
    for operation in state.setdefault("operations", {}).values():
        if operation.get("status") != "pending":
            continue
        targets_relocation = (
            str(operation.get("target") or "") in pending_targets
            or str(operation.get("lease_id") or "") == lease_id
            or bool(matching_server and str(operation.get("server_id") or "") == str(matching_server[0]))
        )
        if targets_relocation:
            raise RuntimeError(
                f"pending coordinator operation {operation.get('id') or 'unknown'} targets the old server or port"
            )

    listener = listener_evidence_for_port(port)
    if listener.get("present"):
        raise RuntimeError(
            f"port {port} still has a live listener; stop the exact old service before relocation "
            f"(pid={listener.get('pid') or 'unknown'})"
        )

    relocated_at = iso_timestamp()
    assignments.pop(old_key)
    relocated_assignment = {
        **assignment,
        "key": new_key,
        "project": new_project,
        "name": name,
        "port": port,
        "agent": agent,
        "source": "port_relocate",
        "updated_at": relocated_at,
        "relocated_from": old_project,
        "relocated_at": relocated_at,
    }
    assignments[new_key] = relocated_assignment

    relocated_lease: dict[str, Any] | None = None
    if matching_lease:
        matching_lease["project"] = new_project
        matching_lease["assignment_key"] = new_key
        matching_lease["relocated_from"] = old_project
        matching_lease["relocated_at"] = relocated_at
        relocated_lease = mark_lease_stale_released(
            state,
            lease_id,
            matching_lease,
            "port ownership relocated after the old listener stopped",
        )

    relocated_server: dict[str, Any] | None = None
    if matching_server:
        server_id, server = matching_server
        server["key"] = new_key
        server["project"] = new_project
        server["cwd"] = _relocated_path(server.get("cwd"), old_project=old_project, new_project=new_project) or new_project
        server["pid"] = None
        server["lease_id"] = None
        server["status"] = "stopped"
        server["stopped_at"] = relocated_at
        server["stopped_ts"] = now()
        server["stopped_reason"] = "Checkout ownership relocated; awaiting exact listener registration"
        server["health"] = {
            "ok": False,
            "pid_alive": False,
            "classification": "stopped",
            "reason": "awaiting registration after checkout relocation",
        }
        server["updated_at"] = relocated_at
        server["metadata_source"] = "port_relocate"
        server["agent_metadata"] = agent_metadata(
            agent=agent,
            project=new_project,
            source="port_relocate",
            cwd=str(server["cwd"]),
        )
        server["relocated_from"] = old_project
        server["relocated_at"] = relocated_at
        # A registered external service is rediscovered from its new listener.
        # Retaining a stale checkout launch command or PID would allow the new
        # record to point back at the source repository being retired.
        for field in (
            "argv",
            "argv_template",
            "cmd",
            "cmd_template",
            "log_path",
            "operation_id",
            "pending_operation_id",
        ):
            server[field] = None
        relocated_server = server

    event_payload = {
        "agent": agent,
        "agent_metadata": agent_metadata(agent=agent, project=new_project, source="port_relocate"),
        "old_project": old_project,
        "new_project": new_project,
        "name": name,
        "port": port,
        "old_key": old_key,
        "new_key": new_key,
        "lease_id": lease_id,
        "lease_status": "stale_released" if (relocated_lease or stale_evidence) else "missing",
        "server_id": matching_server[0] if matching_server else None,
        "listener_evidence": listener,
    }
    record_event(state, "port.relocated", event_payload)
    return {
        "ok": True,
        "assignment": relocated_assignment,
        "lease": relocated_lease or stale_evidence,
        "server": relocated_server,
        "relocation": event_payload,
    }


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


def git_directory(project: str) -> Path | None:
    marker = Path(project) / ".git"
    if marker.is_dir():
        return marker
    if marker.is_file():
        with contextlib.suppress(OSError):
            prefix, _, value = marker.read_text(encoding="utf-8", errors="replace").strip().partition(":")
            if prefix.strip().lower() == "gitdir" and value.strip():
                path = Path(value.strip()).expanduser()
                if not path.is_absolute():
                    path = marker.parent / path
                return path.resolve()
    return None


def read_git_head_identity(project: str) -> tuple[str | None, str | None]:
    """Read branch/commit identity from Git metadata without a subprocess."""

    directory = git_directory(project)
    if not directory:
        return None, None
    with contextlib.suppress(OSError):
        head = (directory / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        if head.startswith("ref:"):
            reference = head.split(":", 1)[1].strip()
            branch = reference.removeprefix("refs/heads/")
            commit = None
            reference_path = directory / reference
            with contextlib.suppress(OSError):
                commit = reference_path.read_text(encoding="utf-8", errors="replace").strip()
            if not commit:
                with contextlib.suppress(OSError):
                    for line in (directory / "packed-refs").read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines():
                        value, separator, name = line.partition(" ")
                        if separator and name == reference:
                            commit = value
                            break
            return branch or None, commit[:7] if commit else None
        return "HEAD", head[:7] if head else None
    return None, None


def prime_git_head_identity(project: str) -> tuple[str | None, str | None]:
    resolved_project = canonical_project(project)
    identity = read_git_head_identity(resolved_project)
    identities = getattr(_GIT_IDENTITY_CONTEXT, "identities", None)
    if identities is None:
        identities = {}
        _GIT_IDENTITY_CONTEXT.identities = identities
    identities[resolved_project] = identity
    return identity


def git_head_identity(project: str) -> tuple[str | None, str | None]:
    resolved_project = canonical_project(project)
    identities = getattr(_GIT_IDENTITY_CONTEXT, "identities", {})
    if resolved_project in identities:
        return identities[resolved_project]
    if int(getattr(_STATE_LOCK_CONTEXT, "depth", 0)):
        return None, None
    return read_git_head_identity(resolved_project)


def agent_metadata(*, agent: str, project: str, source: str, cwd: str | None = None) -> dict[str, Any]:
    resolved_project = canonical_project(project)
    resolved_cwd = str(Path(cwd).expanduser().resolve()) if cwd else resolved_project
    git_branch, git_commit = git_head_identity(resolved_project)
    return {
        "agent": agent,
        "project": resolved_project,
        "repo_name": Path(resolved_project).name,
        "cwd": resolved_cwd,
        "git_branch": git_branch,
        "git_commit": git_commit,
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
    prime_git_head_identity(resolved_project)
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
    always wins. A name resemblance is retained only as read-only discovery
    evidence: it never moves the container into a repo-owned group and never
    authorizes a whole-project mutation.
    """
    fallback_name = container.get("name") or container.get("image")
    if container.get("project"):
        identity = resource_project_identity(str(container["project"]), fallback_name)
        identity["attribution"] = "explicit"
        return identity
    name_key = project_key_from_resource_name(fallback_name)
    claimants = sorted(path for path in known_projects if project_key_from_path(path) == name_key)
    identity = resource_project_identity(None, fallback_name)
    identity["attribution"] = (
        "name_match_read_only"
        if len(claimants) == 1
        else "ambiguous_name"
        if claimants
        else "unclaimed"
    )
    identity["suggested_project"] = claimants[0] if len(claimants) == 1 else None
    identity["mutation_authorized"] = False
    identity["read_only_evidence"] = True
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


@dataclass(frozen=True)
class LaunchSpec:
    """A shell-free, attributable process launch contract."""

    argv: tuple[str, ...]
    cwd: str
    env_extra: dict[str, str]
    agent: str
    project: str
    source: str

    def as_state(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env": dict(self.env_extra),
            "agent": self.agent,
            "project": self.project,
            "source": self.source,
        }


def parse_legacy_command(command: str) -> list[str]:
    """Parse compatibility command text as argv, never as shell source.

    Shell control syntax is rejected rather than silently changing meaning. A
    caller that needs a literal punctuation argument can use structured argv.
    """

    if not isinstance(command, str) or not command.strip():
        raise ValueError("server command must not be empty")
    if "\x00" in command or "\n" in command or "\r" in command:
        raise ValueError("unsafe shell syntax in server command: control character")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        argv = list(lexer)
    except ValueError as exc:
        raise ValueError(f"invalid quoted server command: {exc}") from exc
    dangerous = {";", "&", "&&", "|", "||", "<", ">", ">>", "<<", "(", ")"}
    for token in argv:
        if token in dangerous or (token and all(char in ";&|<>()" for char in token)):
            raise ValueError(f"unsafe shell syntax in server command: {token!r}; use structured argv")
    if not argv:
        raise ValueError("server command must not be empty")
    return argv


def command_argv(options: dict[str, Any]) -> list[str]:
    structured = options.get("argv")
    if structured is not None:
        if not isinstance(structured, (list, tuple)) or not structured:
            raise ValueError("server argv must be a non-empty array of strings")
        if not all(isinstance(item, str) and "\x00" not in item for item in structured):
            raise ValueError("server argv entries must be NUL-free strings")
        return list(structured)
    command = options.get("cmd") or options.get("command")
    return parse_legacy_command(str(command or ""))


def format_argv(argv: list[str] | tuple[str, ...], *, port: int, host: str) -> list[str]:
    return [item.replace("{port}", str(port)).replace("{host}", host) for item in argv]


def format_command(command: str, *, port: int, host: str) -> str:
    return command.replace("{port}", str(port)).replace("{host}", host)


def start_process(
    *,
    launch: LaunchSpec,
    server_id: str,
) -> tuple[int, str]:
    ensure_private_directory(logs_dir())
    log_path = logs_dir() / f"{server_id}.log"
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    log_file = os.fdopen(log_fd, "ab", buffering=0)
    env = os.environ.copy()
    env.update(launch.env_extra)
    try:
        process = subprocess.Popen(
            list(launch.argv),
            cwd=launch.cwd,
            env=env,
            shell=False,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log_file.close()
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
    identity_unobservable = identity.get("observable") is False
    if alive is not False and identity_unobservable:
        ok: bool | None = None
        classification = "unverified-listener"
    else:
        ok = alive is not False and bool(check.get("ok")) and identity.get("ok") is not False
    if ok is True:
        classification = "healthy"
    elif identity.get("ok") is False:
        classification = "wrong-listener"
    elif ok is not None and within_startup_grace(server):
        classification = "starting"
    elif ok is not None:
        classification = "unhealthy"
    return {
        "ok": ok,
        "pid_alive": alive,
        "check": check,
        "identity": identity,
        "attempts": attempts,
        "classification": classification,
    }


def listener_identity_unobservable(health: dict[str, Any] | None) -> bool:
    """Return whether a health result cannot prove the current listener owner.

    ``False`` means the observer positively disproved identity. ``None`` means
    the observer lacks the capability to decide. Lifecycle code must never
    collapse that third state into "down" and replace or signal the process.
    """

    evidence = health or {}
    identity = evidence.get("identity") or {}
    return bool(
        evidence.get("classification") == "unverified-listener"
        or ("ok" in evidence and evidence.get("ok") is None)
        or identity.get("observable") is False
        or ("ok" in identity and identity.get("ok") is None)
    )


def require_listener_identity_observable(
    health: dict[str, Any], *, action: str, server: dict[str, Any] | None = None
) -> None:
    """Fail a mutation before it can act on an unverified process identity."""

    if not listener_identity_unobservable(health):
        return
    identity = health.get("identity") or {}
    name = str((server or {}).get("name") or "server")
    reason = str(identity.get("reason") or "listener ownership cannot be observed")
    raise ListenerIdentityUnobservable(
        f"refusing to {action} {name}: listener identity is unobservable; {reason}"
    )


def require_project_server_identities_observable(
    state: dict[str, Any], spec: dict[str, Any], *, action: str
) -> dict[str, tuple[Any, ...]]:
    """Preflight every registered project server before any project mutation."""

    project = str(spec["project"])
    fingerprints: dict[str, tuple[Any, ...]] = {}
    registered_by_key: dict[str, dict[str, Any]] = {}
    for server_id, server in state.get("servers", {}).items():
        if str(server.get("project") or "") != project:
            continue
        health = server_health(copy.deepcopy(server))
        require_listener_identity_observable(
            health,
            action=f"{action} project server",
            server=server,
        )
        fingerprints[str(server_id)] = server_lifecycle_fingerprint(server)
        registered_by_key[server_key(project, str(server.get("name") or ""))] = server

    for server_def in spec.get("servers", []):
        server = registered_by_key.get(
            server_key(str(server_def["project"]), str(server_def["name"]))
        )
        health = server_health(copy.deepcopy(server)) if server else {"ok": False}
        if action not in {"start", "restart"} or health.get("ok") is True:
            continue
        _assignment_key, assignment = find_port_assignment(
            state,
            project=str(server_def["project"]),
            name=str(server_def["name"]),
        )
        fixed_port = server_def.get("port") or (assignment or {}).get("port") or (server or {}).get("port")
        if fixed_port is None:
            continue
        host = str(server_def.get("host") or (server or {}).get("host") or "127.0.0.1")
        if not port_open(host, int(fixed_port)):
            continue
        belongs, owner = listener_belongs_to_project(
            int(fixed_port), str(server_def["project"]), host=host
        )
        if belongs:
            continue
        reason = str(owner.get("reason") or "listener does not belong to project")
        if owner.get("observable") is False:
            raise ListenerIdentityUnobservable(
                f"refusing to {action} project server {server_def['name']}: "
                f"listener identity is unobservable; {reason}"
            )
        # A positively identified foreign listener follows the established
        # per-server adoption error/report path. This preflight is specifically
        # the no-capability boundary where continuing could create duplicates.
    return fingerprints


def docker_available_command(args: list[str], *, cwd: str | None = None) -> dict[str, Any]:
    command = ["docker", *args]
    try:
        completed, executable, timeout_seconds = execute_docker_subprocess(command, cwd=cwd)
    except Exception as exc:
        return {"ok": False, "command": command, **coordinator_exception_payload(exc)}
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
        "cwd": cwd,
        "docker_executable": executable,
        "timeout_seconds": timeout_seconds,
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


def docker_container_operation_identity(
    container: str | None,
    inspected: dict[str, Any] | None = None,
) -> str | None:
    """Normalize a name/short-id alias to Docker's immutable full container id."""

    normalized = normalize_container_name(container)
    if not normalized:
        return None
    evidence = inspected if inspected is not None else inspect_docker_container(normalized)
    immutable_id = str((evidence or {}).get("Id") or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{12,64}", immutable_id):
        return f"container-id:{immutable_id}"
    return f"container-alias:{normalized}"


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
    if "_coordinator_inspected_container" in options:
        inspected = options.get("_coordinator_inspected_container")
    else:
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
        "argv": raw.get("argv"),
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
        "service": raw.get("service"),
        "container": raw.get("container") or raw.get("name"),
        "image": raw.get("image"),
        "required": raw.get("required", True) is not False,
        "ports": ports,
        "health_url": raw.get("health_url"),
        "declared": True,
        "mutation_authorized": True,
        "ownership_source": "runtime_declaration",
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
    """Explicitly owned containers plus name-similar read-only evidence.

    ``build_project_runtime_spec`` marks name-only matches as non-mutable; this
    helper keeps them visible without turning their names into authority.
    """
    resolved = canonical_project(project)
    project_key = project_key_from_path(resolved)
    matches: list[dict[str, Any]] = []
    for container in containers:
        container_project = container.get("project")
        if container_project and canonical_project(str(container_project)) == resolved:
            matches.append(container)
            continue
        if project_key_from_resource_name(container.get("name") or container.get("image")) == project_key:
            matches.append(container)
    return matches


def container_has_authorized_project_provenance(container: dict[str, Any], project: str) -> bool:
    """Return whether Docker/coordinator evidence—not a name—owns this container."""

    container_project = container.get("project")
    if not container_project or canonical_project(str(container_project)) != canonical_project(project):
        return False
    source = container.get("metadata_source")
    if source == "docker_labels":
        return True
    if source != "coordinator_sidecar" or not container.get("agent"):
        return False
    metadata = container.get("agent_metadata") or {}
    metadata_project = metadata.get("project")
    return bool(
        metadata_project
        and canonical_project(str(metadata_project)) == canonical_project(project)
    )


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
    docker_evidence: list[dict[str, Any]] = []
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
            authorized = container_has_authorized_project_provenance(container, resolved_project)
            discovered = {
                "type": "docker",
                "name": name,
                "container": name,
                "image": container.get("image"),
                "required": authorized,
                "ports": [],
                "health_url": None,
                "declared": False,
                "discovered": True,
                "mutation_authorized": authorized,
                "ownership_source": container.get("metadata_source") if authorized else "name_heuristic",
                "read_only_evidence": not authorized,
            }
            if authorized:
                docker_dependencies.append(discovered)
            else:
                docker_evidence.append(discovered)

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
        "docker_evidence": docker_evidence,
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
        "declared": dep.get("declared", False),
        "discovered": dep.get("discovered", False),
        "mutation_authorized": dep.get("mutation_authorized", False),
        "ownership_source": dep.get("ownership_source"),
        "read_only_evidence": dep.get("read_only_evidence", False),
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
    if listener_identity_unobservable(server.get("health")):
        classification = "unverified-listener"
    elif server.get("status") == "stopped":
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
        "health": copy.deepcopy(server.get("health")),
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
    docker_evidence = [docker_dependency_status(dep, containers) for dep in spec.get("docker_evidence", [])]
    server_services = [server_status_for_runtime(state, server_def) for server_def in spec.get("servers", [])]
    services.extend(docker_services)
    services.extend(docker_evidence)
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
        if existing:
            require_listener_identity_observable(
                existing_health,
                action="start",
                server=existing,
            )
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
    declared_command = server_def.get("cmd")
    declared_argv = server_def.get("argv")
    if declared_argv is not None:
        command = None
        argv_template = declared_argv
    elif declared_command:
        command = declared_command
        argv_template = None
    else:
        command = (existing or {}).get("cmd_template")
        argv_template = (existing or {}).get("argv_template")
    if not command and not argv_template:
        raise RuntimeError(f"project server {server_def['name']} has no command declaration")
    start_options = {
        "agent": options.get("agent") or os.environ.get("USER") or "codex-agent",
        "project": server_def["project"],
        "name": server_def["name"],
        "cwd": server_def.get("cwd") or (existing or {}).get("cwd") or server_def["project"],
        "cmd": command,
        "argv": argv_template,
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
    for dep in mutable_runtime_docker_dependencies(spec):
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
    dry_run = bool(options.get("dry_run"))
    if not dry_run:
        require_project_server_identities_observable(state, spec, action="start")
    before = project_runtime_report(state, spec, action="pre-start")
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
    for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
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
    dry_run = bool(options.get("dry_run"))
    if not dry_run:
        require_project_server_identities_observable(state, spec, action="restart")
    before = project_runtime_report(state, spec, action="pre-restart")
    actions: list[dict[str, Any]] = []
    for server_def in reversed(spec.get("servers", [])):
        server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
        if existing:
            actions.append(stop_server(state, {"server_id": server_id, "agent": agent, "project": existing["project"], "name": existing["name"], "release_port": True, "reason": "Restarted by project runtime"}))
    action_errors: list[str] = []
    for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
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
    dry_run = bool(options.get("dry_run"))
    if not dry_run:
        require_project_server_identities_observable(state, spec, action="stop")
    before = project_runtime_report(state, spec, action="pre-stop")
    actions: list[dict[str, Any]] = []
    # Like start/restart, stop records sidecar attribution for the containers
    # it acts on, so display grouping converges to explicit membership after
    # any whole-project action.
    actions.extend(ensure_runtime_docker_metadata(state, spec, options))
    for server_def in reversed(spec.get("servers", [])):
        server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
        if existing and existing.get("status") != "stopped":
            actions.append(stop_server(state, {"server_id": server_id, "agent": agent, "project": existing["project"], "name": existing["name"], "reason": "Stopped by project runtime"}))
    for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
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
        elif listener_identity_unobservable(health):
            # An incapable observer must not upgrade, downgrade, or detach the
            # recorded lifecycle. Preserve it until the capability-matched API
            # can perform strict current listener proof.
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
        if last.get("ok") is True or listener_identity_unobservable(last):
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
    argv_template = command_argv(options) if command_template or options.get("argv") else None
    argv = format_argv(argv_template, port=port, host=host) if argv_template else None
    command = shlex.join(argv) if argv else None
    health_url_template = options.get("health_url") or url
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    pid, registration_identity = resolve_registration_pid(options, host=host, port=port, project=project)
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
    server = {
        "id": server_id,
        "key": server_key(project, name),
        "name": name,
        "agent": agent,
        "project": project,
        "cwd": cwd,
        "cmd_template": command_template or previous.get("cmd_template"),
        "argv_template": argv_template or previous.get("argv_template"),
        "argv": argv or previous.get("argv"),
        "cmd": command or previous.get("cmd"),
        "port": port,
        "host": host,
        "url": url,
        "health_url": health_url,
        "health_url_template": health_url_template,
        "lease_id": previous.get("lease_id"),
        "pid": int(pid) if pid else None,
        "registration_identity": registration_identity,
        "log_path": previous.get("log_path"),
        "adopted": True,
        "missing_command": not bool(argv_template or previous.get("argv_template") or previous.get("cmd_template")),
        "metadata_source": options.get("metadata_source") or "server_register",
        "agent_metadata": agent_metadata(agent=agent, project=project, cwd=cwd, source=options.get("metadata_source") or "server_register"),
        "created_at": previous.get("created_at") or iso_timestamp(),
        "updated_at": iso_timestamp(),
    }
    health = wait_for_health(server, float(options.get("health_timeout") or 3))
    require_listener_identity_observable(health, action="register", server=server)
    server["health"] = health
    server["status"] = "running" if health.get("ok") else "unhealthy"
    if server.get("pid"):
        server["registration_identity"] = registration_pid_identity(
            pid=int(server["pid"]), host=host, port=port, project=project
        )
    reclaim_stale_leases_for_port(
        state,
        project=project,
        port=port,
        reason=f"server register reclaimed stale lease for {name}",
        allow_occupied_unattached=True,
    )
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
    belongs, owner = listener_belongs_to_project(port, server_def["project"], host=str(host))
    if not belongs:
        error_type = ListenerIdentityUnobservable if owner.get("observable") is False else RuntimeError
        raise error_type(
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
            "argv": server_def.get("argv"),
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
        try:
            reaped_pid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            reaped_pid = 0
        if reaped_pid == pid:
            return
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
    argv_template = command_argv(options)
    name = options["name"]
    existing_id, existing = find_server(state, project=project, name=name)
    existing_health = server_health(existing) if existing else None
    if existing and existing_health is not None:
        require_listener_identity_observable(existing_health, action="start", server=existing)
    if existing and existing_health and existing_health.get("ok"):
        existing["status"] = "running"
        existing["health"] = existing_health
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
    argv = format_argv(argv_template, port=port, host=host)
    command = shlex.join(argv)
    cwd = str(Path(options.get("cwd") or project).expanduser().resolve())
    health_url_template = options.get("health_url")
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    env_extra = normalize_env(options.get("env") or [])
    env_extra.setdefault("PORT", str(port))
    env_extra.setdefault("HOST", host)
    launch = LaunchSpec(tuple(argv), cwd, env_extra, agent, project, "server_start")
    pid, log_path = start_process(launch=launch, server_id=server_id)
    server = {
        "id": server_id,
        "key": server_key(project, name),
        "name": name,
        "agent": agent,
        "project": str(Path(project).expanduser().resolve()),
        "cwd": cwd,
        "cmd_template": options.get("cmd"),
        "argv_template": argv_template,
        "argv": argv,
        "launch_spec": launch.as_state(),
        "env": env_extra,
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
    require_listener_identity_observable(health, action="stop", server=server)
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
    if not server.get("argv_template") and not server.get("cmd_template"):
        raise RuntimeError(f"server {server.get('name')} is registered without a command; missing_command=true")
    require_listener_identity_observable(
        server_health(server),
        action="restart",
        server=server,
    )
    _, assignment = find_port_assignment(state, project=project, name=str(options["name"]))
    fixed_port = int(assignment["port"]) if assignment else int(server["port"])
    restart_options = {
        "agent": agent,
        "project": server["project"],
        "name": server["name"],
        "cwd": server["cwd"],
        "cmd": server.get("cmd_template"),
        "argv": server.get("argv_template"),
        "range": options.get("range") or f"{fixed_port}-{fixed_port}",
        "preferred": fixed_port,
        "host": server.get("host") or "127.0.0.1",
        "health_url": server.get("health_url_template") or server.get("health_url"),
        "health_timeout": options.get("health_timeout") or 10,
        "env": [f"{key}={value}" for key, value in (server.get("env") or {}).items() if key not in {"PORT", "HOST"}],
    }
    stop_server(state, {"server_id": server_id, "agent": agent, "project": server["project"], "name": server["name"], "release_port": True})
    return start_server(state, restart_options)


def recorded_expired_lease(state: dict[str, Any], lease_id: str) -> bool:
    return any(
        event.get("type") == "port.expired"
        and str((event.get("payload") or {}).get("id") or "") == lease_id
        for event in reversed(state.get("history", []))
    )


def finalize_manual_lease_start_failure(
    *,
    operation_id: str,
    server_id: str,
    lease_id: str,
    reason: str,
    process_launched: bool,
    process_active: bool = False,
    pid: int | None = None,
    log_path: str | None = None,
    health: dict[str, Any] | None = None,
) -> None:
    """Close one failed exact-lease reservation without inventing reuse safety."""

    with locked_state() as state:
        operation = state.get("operations", {}).get(operation_id)
        server = state.get("servers", {}).get(server_id)
        lease = state.get("leases", {}).get(lease_id)
        failure = {
            "at": iso_timestamp(),
            "operation_id": operation_id,
            "process_launched": process_launched,
            "process_active": process_active,
            "reason": reason,
        }
        lease_reservation_owner = str((lease or {}).get("pending_operation_id") or "")
        may_finalize_lease = bool(
            lease
            and lease_reservation_owner in {"", operation_id}
        )
        if may_finalize_lease and lease:
            lease.pop("pending_operation_id", None)
            lease.pop("pending_server_id", None)
            lease["last_attachment_failure"] = failure
            if process_launched:
                lease["original_purpose"] = lease.get("original_purpose") or "manual"
                lease["purpose"] = f"server:{(server or {}).get('name') or 'unknown'}"
                lease["server_id"] = server_id
                lease["attachment_status"] = (
                    "failed_after_launch_reconciliation_required"
                    if process_active
                    else "failed_after_launch_stopped"
                )
                lease["reconciliation_required"] = process_active
            else:
                lease["purpose"] = lease.get("original_purpose") or "manual"
                lease["server_id"] = None
                lease["attachment_status"] = "rolled_back_before_launch"
                lease["reconciliation_required"] = False
        if server and server.get("operation_id") == operation_id:
            if pid is not None:
                server["pid"] = pid
            if log_path:
                server["log_path"] = log_path
            if health is not None:
                server["health"] = health
            server["last_start_failure"] = failure
            if process_launched:
                server["status"] = "orphaned" if process_active else "stopped"
                server["reconciliation_required"] = process_active
                server["stopped_reason"] = reason
                server["stopped_at"] = iso_timestamp()
                server["stopped_ts"] = now()
                server["updated_at"] = iso_timestamp()
            else:
                server["failed_lease_id"] = lease_id
                server["lease_id"] = None
                mark_server_stopped(state, server, reason=reason)
        if operation and operation.get("status") == "pending":
            finish_operation(
                state,
                operation_id,
                status="failed",
                phase="failed-after-launch" if process_launched else "rolled-back-before-launch",
                error=reason,
            )
        record_event(
            state,
            "server.manual_lease_start_failed",
            {
                "server_id": server_id,
                "lease_id": lease_id,
                **failure,
            },
        )


def coordinated_start_server_with_lease(options: dict[str, Any]) -> dict[str, Any]:
    """Attach one exact active manual lease to a structured server launch."""

    prepared = dict(options)
    agent, project = require_identity(prepared, "server start --lease-id")
    name = str(prepared.get("name") or "").strip()
    if not name:
        raise ValueError("server start --lease-id requires --name")
    lease_id = str(prepared.get("lease_id") or "").strip()
    if not lease_id:
        raise ValueError("server start --lease-id requires a lease id")
    if prepared.get("argv") is None or prepared.get("cmd") or prepared.get("command"):
        raise ValueError("server start --lease-id requires structured --argv and does not accept --cmd")
    argv_template = command_argv(prepared)
    cwd = str(Path(prepared.get("cwd") or project).expanduser().resolve())
    if not Path(cwd).is_dir():
        raise FileNotFoundError(f"server cwd does not exist or is not a directory: {cwd}")
    target = f"server:{server_key(project, name)}"
    host = str(prepared.get("host") or "127.0.0.1")

    with locked_state() as state:
        lease = state.get("leases", {}).get(lease_id)
        if not lease:
            if recorded_expired_lease(state, lease_id):
                raise ValueError(f"manual lease {lease_id} expired")
            raise KeyError(f"manual lease not found: {lease_id}")
        if lease.get("status") != "active":
            raise ValueError(f"manual lease {lease_id} is not active")
        expires_at = lease.get("expires_at")
        if expires_at is not None and now() > float(expires_at):
            raise ValueError(f"manual lease {lease_id} expired")
        if str(lease.get("agent") or "") != agent:
            raise ValueError(f"manual lease {lease_id} agent does not match server start agent")
        lease_project = canonical_project(str(lease.get("project") or ""))
        if lease_project != project:
            raise ValueError(f"manual lease {lease_id} project does not match server start project")
        if lease.get("server_id") or lease.get("pending_operation_id"):
            raise ValueError(f"manual lease {lease_id} is already bound or being attached")
        if str(lease.get("purpose") or "") != "manual":
            raise ValueError(f"server start --lease-id requires a manual lease, got {lease.get('purpose')!r}")
        port = int(lease["port"])
        assignment_key, _assignment = find_port_assignment(state, project=project, name=name)
        foreign_assignments = foreign_assigned_ports(state, owner_key=assignment_key)
        if port in foreign_assignments:
            raise RuntimeError(
                f"manual lease {lease_id} port {port} is durably assigned to "
                f"{assignment_owner_text(foreign_assignments[port])}"
            )
        preferred = prepared.get("preferred")
        if preferred is not None and int(preferred) != port:
            raise ValueError(f"manual lease {lease_id} owns port {port}, not preferred port {preferred}")
        existing_id, existing = find_server(state, project=project, name=name)
        if existing and (
            existing.get("status") != "stopped"
            or pid_alive(int(existing.get("pid") or 0))
        ):
            raise RuntimeError(f"server {name} already exists and must be stopped before exact-lease start")
        server_id = existing_id or str(uuid.uuid4())
        generation = int((existing or {}).get("generation") or 0) + 1
        operation = begin_operation(
            state,
            action="server.start",
            target=target,
            agent=agent,
            project=project,
            generation=generation,
            lease_id=lease_id,
            server_id=server_id,
        )
        operation["lease_source"] = "manual"
        operation["lease_port"] = port
        operation["phase"] = "reserved"
        lease["pending_operation_id"] = operation["id"]
        lease["pending_server_id"] = server_id
        lease["attachment_status"] = "reserved"
        lease["original_purpose"] = "manual"
        lease["updated_at"] = iso_timestamp()

        argv = format_argv(argv_template, port=port, host=host)
        health_url_template = prepared.get("health_url")
        health_url = (
            format_command(health_url_template, port=port, host=host)
            if health_url_template
            else None
        )
        env_extra = normalize_env(prepared.get("env") or [])
        env_extra.setdefault("PORT", str(port))
        env_extra.setdefault("HOST", host)
        launch = LaunchSpec(tuple(argv), cwd, env_extra, agent, project, "manual_lease_start")
        previous = existing or {}
        server = {
            "id": server_id,
            "key": server_key(project, name),
            "name": name,
            "agent": agent,
            "project": project,
            "cwd": cwd,
            "cmd_template": None,
            "argv_template": argv_template,
            "cmd": shlex.join(argv),
            "argv": argv,
            "launch_spec": launch.as_state(),
            "env": env_extra,
            "port": port,
            "host": host,
            "url": f"http://{host}:{port}",
            "health_url": health_url,
            "health_url_template": health_url_template,
            "lease_id": lease_id,
            "lease_source": "manual",
            "pid": None,
            "log_path": previous.get("log_path"),
            "adopted": False,
            "missing_command": False,
            "metadata_source": "manual_lease_start",
            "agent_metadata": agent_metadata(
                agent=agent,
                project=project,
                cwd=cwd,
                source="manual_lease_start",
            ),
            "status": "starting",
            "operation_id": operation["id"],
            "generation": generation,
            "created_at": previous.get("created_at") or iso_timestamp(),
            "created_ts": now(),
            "updated_at": iso_timestamp(),
        }
        state["servers"][server_id] = server
        record_event(
            state,
            "server.manual_lease_reserved",
            {
                "server_id": server_id,
                "lease_id": lease_id,
                "port": port,
                "operation_id": operation["id"],
                "project": project,
                "agent": agent,
            },
        )

    if not port_available(port, host):
        reason = f"manual lease {lease_id} port is no longer available: {host}:{port}"
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=False,
        )
        raise RuntimeError(reason)

    with locked_state() as state:
        current_operation = state.get("operations", {}).get(operation["id"])
        current_lease = state.get("leases", {}).get(lease_id)
        reservation_changed = bool(
            not current_operation
            or current_operation.get("status") != "pending"
            or not current_lease
            or current_lease.get("pending_operation_id") != operation["id"]
        )
        if not reservation_changed:
            current_operation["phase"] = "launching"
            current_operation["updated_at"] = iso_timestamp()
            current_lease["attachment_status"] = "launching"
            current_lease["updated_at"] = iso_timestamp()
    if reservation_changed:
        reason = "manual lease start reservation changed before process launch"
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=False,
        )
        raise RuntimeError(reason)

    try:
        pid, log_path = start_process(launch=launch, server_id=server_id)
    except Exception as exc:
        reason = f"server launch failed using manual lease {lease_id}: {exc}"
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=False,
            log_path=str(logs_dir() / f"{server_id}.log"),
        )
        raise RuntimeError(reason) from exc

    with locked_state() as state:
        current = state.get("servers", {}).get(server_id)
        current_operation = state.get("operations", {}).get(operation["id"])
        current_lease = state.get("leases", {}).get(lease_id)
        commit_allowed = bool(
            current
            and current.get("generation") == generation
            and current.get("operation_id") == operation["id"]
            and current_operation
            and current_operation.get("status") == "pending"
            and current_lease
            and current_lease.get("pending_operation_id") == operation["id"]
        )
        if commit_allowed:
            current["pid"] = pid
            current["log_path"] = log_path
            current["updated_at"] = iso_timestamp()
            current_operation["phase"] = "health-check"
            current_operation["launched_pid"] = pid
            current_operation["updated_at"] = iso_timestamp()
            current_lease["attachment_status"] = "health-check"
            current_lease["process_launched"] = True
            current_lease["updated_at"] = iso_timestamp()
            server_for_health = copy.deepcopy(current)
    if not commit_allowed:
        stop_pid(pid)
        process_active = pid_alive(pid) or not port_available(port, host)
        reason = "manual lease start reservation was superseded after process launch"
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=True,
            process_active=process_active,
            pid=pid,
            log_path=log_path,
        )
        raise RuntimeError(reason)

    health = wait_for_health(server_for_health, float(prepared.get("health_timeout") or 10))
    if not health.get("ok"):
        stop_pid(pid)
        process_active = pid_alive(pid) or not port_available(port, host)
        reason = (
            f"server failed health check using manual lease {lease_id}: "
            f"{health.get('classification') or health.get('error') or 'unhealthy'}"
        )
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=True,
            process_active=process_active,
            pid=pid,
            log_path=log_path,
            health=health,
        )
        raise RuntimeError(reason)

    with locked_state() as state:
        current = state.get("servers", {}).get(server_id)
        current_operation = state.get("operations", {}).get(operation["id"])
        current_lease = state.get("leases", {}).get(lease_id)
        if (
            not current
            or current.get("generation") != generation
            or current.get("operation_id") != operation["id"]
            or not current_operation
            or current_operation.get("status") != "pending"
            or not current_lease
            or current_lease.get("pending_operation_id") != operation["id"]
        ):
            committed = None
        else:
            current["health"] = health
            current["status"] = "running"
            current["updated_at"] = iso_timestamp()
            current_lease.pop("pending_operation_id", None)
            current_lease.pop("pending_server_id", None)
            current_lease["original_purpose"] = "manual"
            current_lease["purpose"] = f"server:{name}"
            current_lease["server_id"] = server_id
            current_lease["attachment_status"] = "attached"
            current_lease["process_launched"] = True
            current_lease["reconciliation_required"] = False
            current_lease["attached_at"] = iso_timestamp()
            current_lease["updated_at"] = iso_timestamp()
            record_port_assignment(
                state,
                agent=agent,
                project=project,
                name=name,
                port=port,
                source="manual_lease_start",
            )
            record_event(state, "server.started", current)
            record_event(
                state,
                "server.manual_lease_attached",
                {
                    "server_id": server_id,
                    "lease_id": lease_id,
                    "port": port,
                    "operation_id": operation["id"],
                },
            )
            finish_operation(state, operation["id"], status="completed", phase="committed")
            committed = copy.deepcopy(current)
    if committed is None:
        stop_pid(pid)
        process_active = pid_alive(pid) or not port_available(port, host)
        reason = "manual lease start was superseded before final commit"
        finalize_manual_lease_start_failure(
            operation_id=operation["id"],
            server_id=server_id,
            lease_id=lease_id,
            reason=reason,
            process_launched=True,
            process_active=process_active,
            pid=pid,
            log_path=log_path,
            health=health,
        )
        raise RuntimeError(reason)
    return committed


def coordinated_start_server(options: dict[str, Any]) -> dict[str, Any]:
    """Start a process with only reservation/commit phases under the state lock."""

    if options.get("lease_id"):
        return coordinated_start_server_with_lease(options)
    agent, project = require_identity(options, "server start")
    name = str(options.get("name") or "").strip()
    if not name:
        raise ValueError("server start requires --name")
    argv_template = command_argv(options)  # Validate before reserving any state.
    cwd = str(Path(options.get("cwd") or project).expanduser().resolve())
    if not Path(cwd).is_dir():
        raise FileNotFoundError(f"server cwd does not exist or is not a directory: {cwd}")
    target = f"server:{server_key(project, name)}"

    with locked_state() as state:
        existing_id, existing = find_server(state, project=project, name=name)
        existing_snapshot = copy.deepcopy(existing) if existing else None
    if existing_snapshot:
        existing_health = server_health(existing_snapshot)
        require_listener_identity_observable(
            existing_health,
            action="start",
            server=existing_snapshot,
        )
        if existing_health.get("ok"):
            with locked_state() as state:
                current = state["servers"].get(existing_id)
                if not current or server_lifecycle_fingerprint(current) != server_lifecycle_fingerprint(
                    existing_snapshot
                ):
                    raise RuntimeError(
                        f"server {name} changed while its existing health was checked; retry start"
                    )
                current["health"] = existing_health
                current["status"] = "running"
                current["updated_at"] = iso_timestamp()
                _key, current_assignment = find_port_assignment(state, project=project, name=name)
                if current_assignment is None:
                    record_port_assignment(
                        state,
                        agent=agent,
                        project=project,
                        name=name,
                        port=int(current["port"]),
                        source="server_start_heal",
                    )
                return copy.deepcopy(current)
        if existing_snapshot.get("status") != "stopped" or pid_alive(int(existing_snapshot.get("pid") or 0)):
            coordinated_stop_server(
                {
                    "server_id": existing_id,
                    "agent": agent,
                    "project": project,
                    "name": name,
                    "release_port": True,
                    "reason": "Replaced by coordinator start",
                }
            )

    with locked_state() as state:
        existing_id, existing = find_server(state, project=project, name=name)
        server_id = existing_id or str(uuid.uuid4())
        generation = int((existing or {}).get("generation") or 0) + 1
        assignment_key, assignment = find_port_assignment(state, project=project, name=name)
        explicit_range = options.get("range") is not None
        preferred = options.get("preferred")
        port_range = options.get("range") or DEFAULT_RANGE
        if assignment and not explicit_range and preferred is None:
            assigned_port = int(assignment["port"])
            port_range = f"{assigned_port}-{assigned_port}"
            preferred = assigned_port
            if not port_available(assigned_port, str(options.get("host") or "127.0.0.1")):
                raise RuntimeError(
                    f"server {name} is pinned to port {assigned_port}, but that port is occupied"
                )
        lease = lease_port(
            state,
            agent=agent,
            project=project,
            port_range=port_range,
            preferred=preferred,
            ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
            purpose=f"server:{name}",
            server_id=server_id,
            assignment_key=assignment_key,
        )
        operation = begin_operation(
            state,
            action="server.start",
            target=target,
            agent=agent,
            project=project,
            generation=generation,
            lease_id=str(lease["id"]),
            server_id=server_id,
        )
        port = int(lease["port"])
        host = str(options.get("host") or "127.0.0.1")
        argv = format_argv(argv_template, port=port, host=host)
        health_url_template = options.get("health_url")
        health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
        env_extra = normalize_env(options.get("env") or [])
        env_extra.setdefault("PORT", str(port))
        env_extra.setdefault("HOST", host)
        launch = LaunchSpec(tuple(argv), cwd, env_extra, agent, project, "server_start")
        previous = existing or {}
        server = {
            "id": server_id,
            "key": server_key(project, name),
            "name": name,
            "agent": agent,
            "project": project,
            "cwd": cwd,
            "cmd_template": options.get("cmd"),
            "argv_template": argv_template,
            "cmd": shlex.join(argv),
            "argv": argv,
            "launch_spec": launch.as_state(),
            "env": env_extra,
            "port": port,
            "host": host,
            "url": f"http://{host}:{port}",
            "health_url": health_url,
            "health_url_template": health_url_template,
            "lease_id": lease["id"],
            "pid": None,
            "log_path": previous.get("log_path"),
            "adopted": False,
            "missing_command": False,
            "metadata_source": "server_start",
            "agent_metadata": agent_metadata(agent=agent, project=project, cwd=cwd, source="server_start"),
            "status": "starting",
            "operation_id": operation["id"],
            "generation": generation,
            "created_at": previous.get("created_at") or iso_timestamp(),
            "created_ts": now(),
            "updated_at": iso_timestamp(),
        }
        state["servers"][server_id] = server

    try:
        pid, log_path = start_process(launch=launch, server_id=server_id)
    except Exception as exc:
        with locked_state() as state:
            current = state["servers"].get(server_id)
            if current and current.get("operation_id") == operation["id"]:
                current["log_path"] = str(logs_dir() / f"{server_id}.log")
                mark_server_stopped(state, current, reason=f"Process launch failed: {exc}")
            if lease["id"] in state["leases"]:
                with contextlib.suppress(KeyError):
                    release_port(state, lease_id=str(lease["id"]))
            finish_operation(state, operation["id"], status="failed", phase="launch", error=str(exc))
        raise

    with locked_state() as state:
        current = state["servers"].get(server_id)
        current_operation = state["operations"].get(operation["id"])
        if not current or current.get("generation") != generation or not current_operation or current_operation.get("status") != "pending":
            commit_allowed = False
        else:
            commit_allowed = True
            current["pid"] = pid
            current["log_path"] = log_path
            current["updated_at"] = iso_timestamp()
            current_operation["phase"] = "launched"
            current_operation["launched_pid"] = pid
            current_operation["updated_at"] = iso_timestamp()
            server_for_health = copy.deepcopy(current)
    if not commit_allowed:
        stop_pid(pid)
        raise RuntimeError("server start reservation was superseded before launch commit")

    health = wait_for_health(server_for_health, float(options.get("health_timeout") or 10))
    with locked_state() as state:
        current = state["servers"].get(server_id)
        if not current or current.get("generation") != generation or current.get("operation_id") != operation["id"]:
            finish_operation(
                state,
                operation["id"],
                status="failed",
                phase="commit",
                error="server generation changed before commit",
            )
            committed = None
        else:
            current["health"] = health
            current["status"] = "running" if health.get("ok") else "unhealthy"
            current["updated_at"] = iso_timestamp()
            state["leases"][lease["id"]]["server_id"] = server_id
            record_port_assignment(
                state,
                agent=agent,
                project=project,
                name=name,
                port=port,
                source="server_start",
            )
            record_event(state, "server.started", current)
            finish_operation(state, operation["id"], status="completed", phase="committed")
            committed = copy.deepcopy(current)
    if committed is None:
        stop_pid(pid)
        raise RuntimeError("server start was superseded before state commit")
    return committed


def coordinated_stop_server(options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    agent = str(prepared.get("agent") or "").strip()
    if not agent:
        raise ValueError("server stop requires --agent so the coordinator can attribute the action")
    if prepared.get("project"):
        project_hint = canonical_project(str(prepared["project"]))
    elif prepared.get("server_id"):
        snapshot = snapshot_coordinator_state()
        hinted_server = snapshot.get("servers", {}).get(prepared["server_id"])
        if not hinted_server or not hinted_server.get("project"):
            raise KeyError("matching server not found")
        project_hint = canonical_project(str(hinted_server["project"]))
    else:
        raise KeyError("server-id or project/name is required")
    prepared["project"] = project_hint
    prime_git_head_identity(project_hint)
    with locked_state() as state:
        server_id = prepared.get("server_id")
        server = state["servers"].get(server_id) if server_id else None
        if not server:
            if not prepared.get("project") or not prepared.get("name"):
                raise KeyError("server-id or project/name is required")
            server_id, server = find_server(state, project=prepared["project"], name=prepared["name"])
        if not server or not server_id:
            raise KeyError("matching server not found")
        project = project_hint
        if str(server.get("project") or "") != project:
            raise ValueError("server stop project does not match the registered server project")
        observed_snapshot = copy.deepcopy(server)

    health = server_health(observed_snapshot)
    require_listener_identity_observable(
        health,
        action="stop",
        server=observed_snapshot,
    )

    # Reserve only after identity observation. An incapable observer therefore
    # cannot create an operation, change status/generation, signal, or release.
    with locked_state() as state:
        current = state["servers"].get(server_id)
        if not current or server_lifecycle_fingerprint(current) != server_lifecycle_fingerprint(
            observed_snapshot
        ):
            raise RuntimeError("server changed while listener identity was checked; retry stop")
        target = f"server:{server_key(project, str(current.get('name') or ''))}"
        generation = int(current.get("generation") or 0) + 1
        operation = begin_operation(
            state,
            action="server.stop",
            target=target,
            agent=agent,
            project=project,
            generation=generation,
            lease_id=current.get("lease_id"),
            server_id=server_id,
        )
        current["generation"] = generation
        current["operation_id"] = operation["id"]
        current["status"] = "stopping"
        current["updated_at"] = iso_timestamp()
        snapshot = copy.deepcopy(current)

    identity_wrong = (health.get("identity") or {}).get("ok") is False
    if not identity_wrong:
        stop_pid(int(snapshot.get("pid") or 0))
    final_health = server_health(snapshot)

    with locked_state() as state:
        current = state["servers"].get(server_id)
        if not current or current.get("generation") != generation or current.get("operation_id") != operation["id"]:
            finish_operation(
                state,
                operation["id"],
                status="failed",
                phase="commit",
                error="server generation changed before stop commit",
            )
            raise RuntimeError("server stop was superseded before state commit")
        current["health"] = final_health
        current["agent"] = agent
        current["agent_metadata"] = agent_metadata(agent=agent, project=project, cwd=current.get("cwd"), source="server_stop")
        reason = stop_reason_from_health(current, health) if identity_wrong else prepared.get("reason") or "Stopped by coordinator"
        mark_server_stopped(state, current, reason=reason)
        if prepared.get("release_port", True) and current.get("lease_id") and current["lease_id"] in state["leases"]:
            with contextlib.suppress(KeyError):
                release_port(state, lease_id=str(current["lease_id"]))
        finish_operation(state, operation["id"], status="completed", phase="committed")
        return copy.deepcopy(current)


def coordinated_restart_server(options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "server restart")
    with locked_state() as state:
        server_id, server = find_server(state, project=project, name=options["name"])
        if not server:
            raise KeyError("matching server not found")
        if not server.get("argv_template") and not server.get("cmd_template"):
            raise RuntimeError(f"server {server.get('name')} is registered without a command; missing_command=true")
        snapshot = copy.deepcopy(server)
        _assignment_key, assignment = find_port_assignment(state, project=project, name=options["name"])
    health = server_health(snapshot)
    require_listener_identity_observable(
        health,
        action="restart",
        server=snapshot,
    )
    with locked_state() as state:
        current = state["servers"].get(server_id)
        if not current or server_lifecycle_fingerprint(current) != server_lifecycle_fingerprint(snapshot):
            raise RuntimeError("server changed while listener identity was checked; retry restart")
        operation = begin_operation(
            state,
            action="server.restart",
            target=f"server:{server_key(project, str(current.get('name') or ''))}",
            agent=agent,
            project=project,
            generation=int(current.get("generation") or 0) + 1,
            server_id=server_id,
        )
    fixed_port = int((assignment or {}).get("port") or snapshot["port"])
    restart_options = {
        "agent": agent,
        "project": snapshot["project"],
        "name": snapshot["name"],
        "cwd": snapshot["cwd"],
        "cmd": snapshot.get("cmd_template"),
        "argv": snapshot.get("argv_template"),
        "range": options.get("range") or f"{fixed_port}-{fixed_port}",
        "preferred": fixed_port,
        "host": snapshot.get("host") or "127.0.0.1",
        "health_url": snapshot.get("health_url_template") or snapshot.get("health_url"),
        "health_timeout": options.get("health_timeout") or 10,
        "env": [f"{key}={value}" for key, value in (snapshot.get("env") or {}).items() if key not in {"PORT", "HOST"}],
    }
    try:
        with delegated_server_restart_operation(operation):
            coordinated_stop_server(
                {
                    "server_id": server_id,
                    "agent": agent,
                    "project": project,
                    "name": snapshot["name"],
                    "release_port": True,
                    "reason": "Restarted by coordinator",
                }
            )
            result = coordinated_start_server(restart_options)
    except Exception as exc:
        with locked_state() as state:
            finish_operation(
                state,
                operation["id"],
                status="failed",
                phase="child-failed",
                error=str(exc),
            )
        raise
    with locked_state() as state:
        current_operation = state.get("operations", {}).get(operation["id"])
        if not current_operation or current_operation.get("status") != "pending":
            raise RuntimeError("server restart reservation was superseded before commit")
        current_operation["result"] = {
            "server_id": result.get("id"),
            "status": result.get("status"),
            "generation": result.get("generation"),
        }
        finish_operation(state, operation["id"], status="completed", phase="committed")
    return result


def snapshot_coordinator_state() -> dict[str, Any]:
    """Take a consistent state snapshot and release the lock immediately."""

    with locked_state() as state:
        return copy.deepcopy(state)


def snapshot_runtime_observation(*, project: str | None = None) -> dict[str, Any]:
    """Reserve a monotonic per-server observation ticket and return its snapshot."""

    with locked_state() as state:
        for server in state.get("servers", {}).values():
            if project and str(server.get("project") or "") != project:
                continue
            server["observation_generation"] = int(server.get("observation_generation") or 0) + 1
        return copy.deepcopy(state)


def server_lifecycle_fingerprint(server: dict[str, Any] | None) -> tuple[Any, ...]:
    if not server:
        return ()
    return (
        server.get("generation"),
        server.get("operation_id"),
        server.get("pid"),
        server.get("lease_id"),
        server.get("created_at"),
    )


def server_observation_fingerprint(server: dict[str, Any] | None) -> tuple[Any, ...]:
    return (*server_lifecycle_fingerprint(server), (server or {}).get("observation_generation"))


SERVER_OBSERVATION_FIELDS = (
    "health",
    "status",
    "updated_at",
    "stopped_at",
    "stopped_ts",
    "stopped_reason",
    "reconciliation_required",
)


def merge_docker_stats_history(state: dict[str, Any], observed: dict[str, Any]) -> None:
    current_histories = state.setdefault("docker", {}).setdefault("stats_history", {})
    observed_histories = observed.get("docker", {}).get("stats_history", {})
    for key, samples in observed_histories.items():
        current = current_histories.setdefault(str(key), [])
        known = {
            (item.get("timestamp_ts"), item.get("id"), item.get("name"))
            for item in current
            if isinstance(item, dict)
        }
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            identity = (sample.get("timestamp_ts"), sample.get("id"), sample.get("name"))
            if identity in known:
                continue
            current.append(copy.deepcopy(sample))
            known.add(identity)
        del current[:-DOCKER_STATS_HISTORY_LIMIT]


def commit_runtime_observations(baseline: dict[str, Any], observed: dict[str, Any]) -> None:
    """Commit health/stat observations only when the observed server is current.

    Slow process, HTTP, Docker, and filesystem checks run against ``observed``
    after the state lock has been released. This optimistic commit intentionally
    skips a server whose lifecycle generation changed while the checks ran.
    """

    with locked_state() as state:
        baseline_servers = baseline.get("servers", {})
        for server_id, observed_server in observed.get("servers", {}).items():
            baseline_server = baseline_servers.get(server_id)
            current = state.get("servers", {}).get(server_id)
            if not baseline_server or not current:
                continue
            if server_observation_fingerprint(current) != server_observation_fingerprint(baseline_server):
                continue
            previous_status = current.get("status")
            for field in SERVER_OBSERVATION_FIELDS:
                if field in observed_server:
                    current[field] = copy.deepcopy(observed_server[field])
                elif field in current and field in baseline_server:
                    current.pop(field, None)
            if previous_status != "stopped" and current.get("status") == "stopped":
                record_event(state, "server.stopped", current)
        observed_leases = observed.get("leases", {})
        for lease_id, baseline_lease in baseline.get("leases", {}).items():
            if lease_id in observed_leases:
                continue
            current_lease = state.get("leases", {}).get(lease_id)
            if not current_lease or current_lease != baseline_lease:
                continue
            server = observed.get("servers", {}).get(baseline_lease.get("server_id"))
            reason = (server or {}).get("stopped_reason") or "health observation marked linked server stale"
            mark_lease_stale_released(state, str(lease_id), current_lease, str(reason))
        merge_docker_stats_history(state, observed)


def coordinated_status_server(options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    if prepared.get("project"):
        prepared["project"] = canonical_project(str(prepared["project"]))
    baseline = snapshot_runtime_observation(project=prepared.get("project"))
    observed = copy.deepcopy(baseline)
    result = copy.deepcopy(status_server(observed, prepared))
    commit_runtime_observations(baseline, observed)
    return result


def coordinated_server_logs(options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    if prepared.get("project"):
        prepared["project"] = canonical_project(str(prepared["project"]))
    return server_logs(snapshot_coordinator_state(), prepared)


def coordinated_register_server(options: dict[str, Any]) -> dict[str, Any]:
    """Inspect and health-check an adopted server outside ``state.lock``."""

    prepared = dict(options)
    agent, project = require_identity(prepared, "server register")
    name = str(prepared.get("name") or "").strip()
    if not name:
        raise ValueError("server register requires --name")
    host, port, url = parse_server_endpoint(prepared)
    cwd = str(Path(prepared.get("cwd") or project).expanduser().resolve())
    command_template = prepared.get("cmd") or prepared.get("command")
    argv_template = command_argv(prepared) if command_template or prepared.get("argv") else None
    argv = format_argv(argv_template, port=port, host=host) if argv_template else None
    command = shlex.join(argv) if argv else None
    health_url_template = prepared.get("health_url") or url
    health_url = format_command(health_url_template, port=port, host=host) if health_url_template else None
    pid, registration_identity = resolve_registration_pid(prepared, host=host, port=port, project=project)

    target = f"server:{server_key(project, name)}"
    with locked_state() as state:
        assignment_key, _assignment = find_port_assignment(state, project=project, name=name)
        foreign_assignments = foreign_assigned_ports(state, owner_key=assignment_key)
        if int(port) in foreign_assignments:
            raise RuntimeError(
                f"port {port} is durably assigned to {assignment_owner_text(foreign_assignments[int(port)])}"
            )
        server_id, existing = find_server(state, project=project, name=name)
        server_id = server_id or str(uuid.uuid4())
        generation = int((existing or {}).get("generation") or 0) + 1
        operation = begin_operation(
            state,
            action="server.register",
            target=target,
            agent=agent,
            project=project,
            generation=generation,
            server_id=server_id,
        )
        previous = copy.deepcopy(existing or {})

    candidate = {
        "id": server_id,
        "key": server_key(project, name),
        "name": name,
        "agent": agent,
        "project": project,
        "cwd": cwd,
        "cmd_template": command_template or previous.get("cmd_template"),
        "argv_template": argv_template or previous.get("argv_template"),
        "argv": argv or previous.get("argv"),
        "cmd": command or previous.get("cmd"),
        "port": port,
        "host": host,
        "url": url,
        "health_url": health_url,
        "health_url_template": health_url_template,
        "lease_id": previous.get("lease_id"),
        "pid": int(pid) if pid else None,
        "registration_identity": registration_identity,
        "log_path": previous.get("log_path"),
        "adopted": True,
        "missing_command": not bool(
            argv_template or previous.get("argv_template") or previous.get("cmd_template")
        ),
        "metadata_source": prepared.get("metadata_source") or "server_register",
        "agent_metadata": agent_metadata(
            agent=agent,
            project=project,
            cwd=cwd,
            source=prepared.get("metadata_source") or "server_register",
        ),
        "generation": generation,
        "operation_id": operation["id"],
        "created_at": previous.get("created_at") or iso_timestamp(),
        "updated_at": iso_timestamp(),
    }
    try:
        health = wait_for_health(candidate, float(prepared.get("health_timeout") or 3))
        require_listener_identity_observable(
            health,
            action="register",
            server=candidate,
        )
        candidate["health"] = health
        candidate["status"] = "running" if health.get("ok") else "unhealthy"
        if candidate.get("pid"):
            candidate["registration_identity"] = registration_pid_identity(
                pid=int(candidate["pid"]), host=host, port=port, project=project
            )
    except Exception as exc:
        with locked_state() as state:
            finish_operation(state, operation["id"], status="failed", phase="observe", error=str(exc))
        raise

    with locked_state() as state:
        current_operation = state.get("operations", {}).get(operation["id"])
        if not current_operation or current_operation.get("status") != "pending":
            raise RuntimeError("server registration reservation was superseded before commit")
        try:
            reclaim_stale_leases_for_port(
                state,
                project=project,
                port=port,
                reason=f"server register reclaimed stale lease for {name}",
                allow_occupied_unattached=True,
            )
            if candidate["status"] == "running" and candidate.get("pid"):
                lease = lease_existing_server_port(
                    state,
                    agent=agent,
                    project=project,
                    port=port,
                    purpose=f"server:{name}",
                    server_id=server_id,
                    owner_pid=int(candidate["pid"]),
                    ttl=int(prepared.get("ttl") or DEFAULT_TTL_SECONDS),
                    assignment_key=assignment_key,
                )
                candidate["lease_id"] = lease["id"]
                current_operation["lease_id"] = lease["id"]
            state["servers"][server_id] = copy.deepcopy(candidate)
            record_port_assignment(
                state,
                agent=agent,
                project=project,
                name=name,
                port=int(port),
                source="server_register",
            )
            record_event(state, "server.registered", candidate)
            finish_operation(state, operation["id"], status="completed", phase="committed")
        except Exception as exc:
            finish_operation(state, operation["id"], status="failed", phase="commit", error=str(exc))
            raise
    return candidate


def coordinated_register_docker_metadata(options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    agent, project = require_identity(prepared, "docker register")
    container = normalize_container_name(prepared.get("container"))
    if not container:
        raise ValueError("docker register requires --container")
    inspected = None if prepared.get("dry_run") else inspect_docker_container(container)
    if not prepared.get("dry_run") and not inspected:
        raise RuntimeError(
            f"cannot register Docker metadata for {container}: immutable container identity was not verified"
        )
    prepared["_coordinator_inspected_container"] = inspected
    target_identity = (
        f"container-alias:{container}"
        if prepared.get("dry_run")
        else docker_container_operation_identity(container, inspected)
    )
    with locked_state() as state:
        operation = begin_operation(
            state,
            action="docker.register",
            target=f"docker-metadata:{target_identity}",
            agent=agent,
            project=project,
            generation=int(state.get("revision") or 0) + 1,
        )
        observed = copy.deepcopy(state)
    try:
        result = register_docker_metadata(observed, prepared)
    except Exception as exc:
        with locked_state() as state:
            finish_operation(state, operation["id"], status="failed", phase="observe", error=str(exc))
        raise
    observed_metadata = observed.get("docker", {}).get("metadata", {})
    with locked_state() as state:
        current_operation = state.get("operations", {}).get(operation["id"])
        if not current_operation or current_operation.get("status") != "pending":
            raise RuntimeError("Docker metadata registration was superseded before commit")
        try:
            metadata = docker_metadata_store(state)
            for key, value in observed_metadata.items():
                if value == result:
                    metadata[key] = copy.deepcopy(value)
            record_event(
                state,
                "docker.register.skipped" if result.get("skipped") else "docker.registered",
                result,
            )
            finish_operation(state, operation["id"], status="completed", phase="committed")
        except Exception as exc:
            finish_operation(state, operation["id"], status="failed", phase="commit", error=str(exc))
            raise
    return result


def coordinated_sample_docker_stats(*, dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        return sample_docker_stats({}, dry_run=True)
    baseline = snapshot_coordinator_state()
    observed = copy.deepcopy(baseline)
    result = sample_docker_stats(observed)
    with locked_state() as state:
        merge_docker_stats_history(state, observed)
    return result


def coordinated_build_inventory(
    *, project: str | None = None, include_docker: bool = True, backup_dirs: list[str] | None = None
) -> dict[str, Any]:
    prepared_project = canonical_project(project) if project else None
    baseline = snapshot_runtime_observation(project=prepared_project)
    observed = copy.deepcopy(baseline)
    result = build_inventory(
        observed,
        project=prepared_project,
        include_docker=include_docker,
        backup_dirs=backup_dirs,
    )
    commit_runtime_observations(baseline, observed)
    return result


def observe_project_runtime(
    options: dict[str, Any], *, action: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = dict(options)
    prepared["project"] = canonical_project(str(prepared["project"]))
    baseline = snapshot_runtime_observation(project=prepared["project"])
    observed = copy.deepcopy(baseline)
    spec = build_project_runtime_spec(
        observed,
        project=prepared["project"],
        runtime_file=prepared.get("runtime_file"),
    )
    report = project_runtime_report(observed, spec, action=action)
    commit_runtime_observations(baseline, observed)
    return spec, report


def begin_project_operation(options: dict[str, Any], action: str) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = dict(options)
    agent, project = require_identity(prepared, f"project {action}")
    if not prepared.get("dry_run"):
        preflight_state = snapshot_coordinator_state()
        preflight_spec = build_project_runtime_spec(
            preflight_state,
            project=project,
            runtime_file=prepared.get("runtime_file"),
        )
        preflight_fingerprints = require_project_server_identities_observable(
            preflight_state,
            preflight_spec,
            action=action,
        )
    else:
        preflight_fingerprints = {}
    target = f"project:{project}"
    operation_action = f"project.{action}"
    with locked_state() as state:
        # Conflict identity has precedence over a preflight fingerprint race:
        # the pending project operation is the cause of its child server-set
        # change, and this check is read-only. Preserve the established short,
        # actionable conflict response before reporting generic retry advice.
        require_operation_slot(
            state,
            target=target,
            project=project,
            action=operation_action,
            delegated_parent_id=delegated_project_operation_id(),
        )
        if not prepared.get("dry_run"):
            current_fingerprints = {
                str(server_id): server_lifecycle_fingerprint(server)
                for server_id, server in state.get("servers", {}).items()
                if str(server.get("project") or "") == project
            }
            if current_fingerprints != preflight_fingerprints:
                raise RuntimeError(
                    f"project {action} server lifecycle changed during listener identity preflight; retry"
                )
        operation = begin_operation(
            state,
            action=operation_action,
            target=target,
            agent=agent,
            project=project,
            generation=int(state.get("revision") or 0) + 1,
        )
        operation["runtime_file"] = prepared.get("runtime_file")
        operation["dry_run"] = bool(prepared.get("dry_run"))
    return prepared, operation


def finish_project_operation(
    operation_id: str,
    *,
    result: dict[str, Any] | None = None,
    error: BaseException | None = None,
) -> None:
    with locked_state() as state:
        operation = state.get("operations", {}).get(operation_id)
        if not operation or operation.get("status") != "pending":
            return
        incomplete = bool(result is not None and result.get("ok") is False)
        if result is not None:
            operation["result"] = {
                "action": result.get("action"),
                "ok": result.get("ok"),
                "classification": result.get("classification"),
                "action_error_count": len(result.get("action_errors") or []),
                "service_count": len(result.get("services") or []),
                "partial": bool(result.get("partial")),
                "preflight_failed": bool(result.get("preflight_failed")),
            }
        if error is not None:
            operation["failure"] = coordinator_exception_payload(error)
        finish_operation(
            state,
            operation_id,
            status="failed" if error or incomplete else "completed",
            phase="failed" if error else ("committed-incomplete" if incomplete else "committed"),
            error=str(error) if error else None,
        )


def record_project_status_evidence(report: dict[str, Any]) -> None:
    with locked_state() as state:
        record_event(
            state,
            "project.status",
            {
                "project": report.get("project"),
                "runtime_id": report.get("runtime_id"),
                "ok": report.get("ok"),
                "classification": report.get("classification"),
                "service_count": len(report.get("services") or []),
                "at": iso_timestamp(),
            },
        )


def coordinated_project_runtime_status(options: dict[str, Any]) -> dict[str, Any]:
    _spec, report = observe_project_runtime(options, action="status")
    record_project_status_evidence(report)
    return report


def coordinated_reclaim_runtime_port(*, project: str, port: int, reason: str) -> list[dict[str, Any]]:
    """Release only same-project server leases proven stale outside the lock."""

    if not port_available(port):
        return []
    baseline = snapshot_coordinator_state()
    candidates: list[str] = []
    for lease_id, lease in baseline.get("leases", {}).items():
        if lease.get("status") != "active" or int(lease.get("port") or 0) != int(port):
            continue
        lease_project = lease.get("project")
        if not lease_project or canonical_project(str(lease_project)) != canonical_project(project):
            continue
        if not str(lease.get("purpose") or "").startswith("server:"):
            continue
        server = baseline.get("servers", {}).get(lease.get("server_id")) if lease.get("server_id") else None
        if not server or server.get("status") == "stopped" or not pid_alive(int(server.get("pid") or 0)):
            candidates.append(str(lease_id))
    released: list[dict[str, Any]] = []
    with locked_state() as state:
        for lease_id in candidates:
            current = state.get("leases", {}).get(lease_id)
            original = baseline.get("leases", {}).get(lease_id)
            if not current or current != original:
                continue
            released.append(mark_lease_stale_released(state, lease_id, current, reason))
    return released


def runtime_server_start_options(
    state: dict[str, Any], server_def: dict[str, Any], options: dict[str, Any]
) -> tuple[dict[str, Any], str | None, dict[str, Any] | None]:
    server_id, existing = find_server(state, project=server_def["project"], name=server_def["name"])
    _assignment_key, assignment = find_port_assignment(
        state, project=server_def["project"], name=server_def["name"]
    )
    fixed_port = server_def.get("port") or (assignment or {}).get("port") or (existing or {}).get("port")
    if server_def.get("missing_fixed_port") and fixed_port is None and not options.get("allow_port_change"):
        raise RuntimeError(f"project server {server_def['name']} has no fixed port declaration")
    if fixed_port is None and not options.get("allow_port_change"):
        raise RuntimeError(f"project server {server_def['name']} has no fixed port; add .codex/dev-runtime.json")
    declared_command = server_def.get("cmd")
    declared_argv = server_def.get("argv")
    if declared_argv is not None:
        command = None
        argv_template = declared_argv
    elif declared_command:
        command = declared_command
        argv_template = None
    else:
        command = (existing or {}).get("cmd_template")
        argv_template = (existing or {}).get("argv_template")
    if not command and not argv_template:
        raise RuntimeError(f"project server {server_def['name']} has no command declaration")
    start_options = {
        "agent": options.get("agent") or os.environ.get("USER") or "codex-agent",
        "project": server_def["project"],
        "name": server_def["name"],
        "cwd": server_def.get("cwd") or (existing or {}).get("cwd") or server_def["project"],
        "cmd": command,
        "argv": argv_template,
        "range": f"{fixed_port}-{fixed_port}" if fixed_port else options.get("range") or DEFAULT_RANGE,
        "preferred": int(fixed_port) if fixed_port else options.get("preferred"),
        "host": server_def.get("host") or (existing or {}).get("host") or "127.0.0.1",
        "health_url": server_def.get("health_url")
        or (existing or {}).get("health_url_template")
        or (existing or {}).get("health_url"),
        "health_timeout": server_def.get("health_timeout") or options.get("health_timeout") or 10,
        "env": server_def.get("env") or [],
    }
    return start_options, server_id, copy.deepcopy(existing) if existing else None


def coordinated_start_runtime_server(server_def: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    require_identity(prepared, "project start")
    snapshot = snapshot_coordinator_state()
    start_options, server_id, existing = runtime_server_start_options(snapshot, server_def, prepared)
    fixed_port = start_options.get("preferred")
    if existing:
        existing_health = server_health(existing)
        require_listener_identity_observable(
            existing_health,
            action="start project server",
            server=existing,
        )
        if existing_health.get("ok"):
            return coordinated_status_server(
                {"server_id": server_id, "project": server_def["project"], "name": server_def["name"]}
            )

    if fixed_port is not None and port_open(str(start_options["host"]), int(fixed_port)):
        belongs, owner = listener_belongs_to_project(
            int(fixed_port), server_def["project"], host=str(server_def.get("host") or "127.0.0.1")
        )
        if not belongs:
            error_type = ListenerIdentityUnobservable if owner.get("observable") is False else RuntimeError
            raise error_type(
                f"refusing to adopt {server_def['name']} on port {fixed_port}: "
                f"{owner.get('reason') or 'listener does not belong to project'}"
            )
        health_url_template = server_def.get("health_url")
        health_url = (
            format_command(health_url_template, port=int(fixed_port), host=str(start_options["host"]))
            if health_url_template
            else None
        )
        adoption_healthy = not health_url or http_health(
            health_url, timeout=float(server_def.get("health_timeout") or 3)
        ).get("ok")
        if adoption_healthy:
            return coordinated_register_server(
                {
                    "agent": prepared.get("agent"),
                    "project": server_def["project"],
                    "name": server_def["name"],
                    "cwd": server_def.get("cwd") or server_def["project"],
                    "cmd": server_def.get("cmd"),
                    "argv": server_def.get("argv"),
                    "port": int(fixed_port),
                    "pid": owner.get("pid"),
                    "host": start_options["host"],
                    "url": f"http://{start_options['host']}:{fixed_port}",
                    "health_url": health_url_template or f"http://{start_options['host']}:{fixed_port}",
                    "metadata_source": "project_adoption",
                    "health_timeout": server_def.get("health_timeout") or prepared.get("health_timeout") or 3,
                }
            )

    if existing and server_id:
        coordinated_stop_server(
            {
                "server_id": server_id,
                "agent": prepared["agent"],
                "project": server_def["project"],
                "name": server_def["name"],
                "release_port": True,
                "reason": "Replaced by project runtime",
            }
        )
    if fixed_port is not None:
        coordinated_reclaim_runtime_port(
            project=server_def["project"],
            port=int(fixed_port),
            reason=f"project start reclaimed stale fixed-port lease for {server_def['name']}",
        )
    return coordinated_start_server(start_options)


def planned_runtime_server_action(server_def: dict[str, Any], action: str) -> dict[str, Any]:
    return {
        "dry_run": True,
        "action": f"server.{action}",
        "name": server_def.get("name"),
        "role": server_def.get("role"),
        "project": server_def.get("project"),
        "port": server_def.get("port"),
    }


def ensure_runtime_docker_metadata_coordinated(
    spec: dict[str, Any], options: dict[str, Any]
) -> list[dict[str, Any]]:
    if not options.get("agent"):
        return []
    actions: list[dict[str, Any]] = []
    containers = spec.get("docker", {}).get("containers", [])
    for dep in mutable_runtime_docker_dependencies(spec):
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
            actions.append(coordinated_register_docker_metadata(payload))
    return actions


def dependency_owned_by_compose(spec: dict[str, Any], dependency: dict[str, Any]) -> bool:
    """Return whether declared Compose owns this dependency's lifecycle.

    The dependency remains in `docker_dependencies` for health, readiness, and
    identity evidence.  Only lifecycle execution is deduplicated.  `service`
    is the preferred unambiguous mapping; for compatibility, a dependency name
    that exactly matches a declared Compose service is also accepted.
    """

    compose = spec.get("compose") or {}
    if not compose.get("declared") or not compose.get("autostart"):
        return False
    declared_services = {str(item) for item in compose.get("services") or [] if item}
    service = str(dependency.get("service") or "").strip()
    if service:
        return not declared_services or service in declared_services
    name = str(dependency.get("name") or "").strip()
    return bool(name and name in declared_services)


def mutable_runtime_docker_dependencies(
    spec: dict[str, Any], *, exclude_compose_owned: bool = False
) -> list[dict[str, Any]]:
    """Return dependencies with mutation authority, optionally deduplicated."""

    dependencies = [
        dep
        for dep in spec.get("docker_dependencies", [])
        if dep.get("mutation_authorized") is True
    ]
    if exclude_compose_owned:
        dependencies = [dep for dep in dependencies if not dependency_owned_by_compose(spec, dep)]
    return dependencies


def project_docker_requirement_reasons(spec: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    compose = spec.get("compose") or {}
    if compose.get("declared") and compose.get("autostart"):
        reasons.append("declared_compose")
    if mutable_runtime_docker_dependencies(spec):
        reasons.append("declared_or_attributed_container")
    return reasons


def require_docker_capability_probe(
    args: list[str], *, capability_name: str, unavailable_code: str
) -> dict[str, Any]:
    result = docker_available_command(args)
    if result.get("ok"):
        return {
            "name": capability_name,
            "ok": True,
            "command": result.get("command"),
            "docker_executable": result.get("docker_executable"),
            "timeout_seconds": result.get("timeout_seconds"),
        }
    timed_out = result.get("code") == "docker_command_timeout"
    code = "docker_command_timeout" if timed_out else unavailable_code
    classification = "timeout" if timed_out else "missing_dependency"
    detail = str(result.get("error") or result.get("stderr") or "").strip()
    message = f"Required Docker capability is unavailable: {capability_name}"
    if detail:
        message = f"{message}: {detail}"
    raise StructuredCoordinatorError(
        message,
        {
            "code": code,
            "classification": classification,
            "capability": {
                "name": capability_name,
                "code": code,
                "command": result.get("command"),
                "returncode": result.get("returncode"),
                "stderr": str(result.get("stderr") or "").strip(),
                "timeout_seconds": result.get("timeout_seconds"),
            },
        },
    )


def compose_command_prefix(compose: dict[str, Any]) -> list[str]:
    command = ["compose"]
    for file_name in compose.get("files") or []:
        command.extend(["-f", str(file_name)])
    return command


def require_compose_service_query(
    spec: dict[str, Any], suffix: list[str], *, purpose: str
) -> list[str]:
    compose = spec.get("compose") or {}
    args = [*compose_command_prefix(compose), *suffix]
    result = docker_available_command(args, cwd=compose.get("cwd"))
    if not result.get("ok"):
        detail = str(result.get("error") or result.get("stderr") or "").strip()
        message = f"Docker Compose {purpose} query failed"
        if detail:
            message = f"{message}: {detail}"
        raise StructuredCoordinatorError(
            message,
            {
                "code": "docker_compose_status_unavailable",
                "classification": result.get("classification") or "missing_dependency",
                "capability": {
                    "name": "docker_compose_status",
                    "code": "docker_compose_status_unavailable",
                    "command": result.get("command"),
                    "returncode": result.get("returncode"),
                    "stderr": str(result.get("stderr") or "").strip(),
                },
            },
        )
    return [line.strip() for line in str(result.get("stdout") or "").splitlines() if line.strip()]


def compose_restart_service_plan(
    spec: dict[str, Any], *, allow_queries: bool = True
) -> dict[str, Any]:
    """Split Compose services into safe restart versus start/recovery groups."""

    compose = spec.get("compose") or {}
    declared_services = [str(item) for item in compose.get("services") or [] if item]
    if not declared_services:
        if allow_queries:
            declared_services = require_compose_service_query(
                spec,
                ["config", "--services"],
                purpose="configuration",
            )
        else:
            return {
                "restart_services": [],
                "start_services": [],
                "declared_services": [],
                "all_services_action": "restart",
                "observation": "dry_run_without_docker",
            }
    containers = spec.get("docker", {}).get("containers", [])
    mapped_dependencies: dict[str, dict[str, Any]] = {}
    for dependency in mutable_runtime_docker_dependencies(spec):
        if not dependency_owned_by_compose(spec, dependency):
            continue
        service = str(dependency.get("service") or dependency.get("name") or "").strip()
        if service:
            mapped_dependencies[service] = dependency

    restart_services: list[str] = []
    start_services: list[str] = []
    unresolved: list[str] = []
    for service in declared_services:
        dependency = mapped_dependencies.get(service)
        container = None
        if dependency:
            container = docker_container_by_name(
                containers,
                dependency.get("container") or dependency.get("name"),
            )
        if container is None:
            container = next(
                (
                    item
                    for item in containers
                    if str((item.get("labels") or {}).get("com.docker.compose.service") or "")
                    == service
                ),
                None,
            )
        if container is None and dependency is None:
            unresolved.append(service)
            continue
        status = str((container or {}).get("status") or "missing")
        if container is None or is_stopped_container_status(status):
            start_services.append(service)
        else:
            restart_services.append(service)

    if unresolved:
        if allow_queries:
            existing = set(
                require_compose_service_query(
                    spec,
                    ["ps", "--services", "--all"],
                    purpose="existing-service",
                )
            )
            running = set(
                require_compose_service_query(
                    spec,
                    ["ps", "--services", "--status", "running"],
                    purpose="running-service",
                )
            )
            for service in unresolved:
                if service in existing and service in running:
                    restart_services.append(service)
                else:
                    start_services.append(service)
        else:
            restart_services.extend(unresolved)

    return {
        "restart_services": restart_services,
        "start_services": start_services,
        "declared_services": declared_services,
    }


def preflight_project_docker(
    spec: dict[str, Any], *, action: str, dry_run: bool
) -> dict[str, Any]:
    reasons = project_docker_requirement_reasons(spec)
    if not reasons:
        return {"required": False, "capability": "docker_cli", "reasons": []}
    if dry_run:
        compose = spec.get("compose") or {}
        compose_restart_plan = None
        if action == "restart" and compose.get("declared") and compose.get("autostart"):
            compose_restart_plan = compose_restart_service_plan(spec, allow_queries=False)
        return {
            "required": True,
            "capability": "docker_cli",
            "reasons": reasons,
            "skipped": "dry_run",
            "compose_restart_plan": compose_restart_plan,
        }
    try:
        executable = resolve_docker_executable()
    except DockerCapabilityError as exc:
        payload = coordinator_exception_payload(exc)
        capability = payload.setdefault("capability", {})
        capability["project"] = spec.get("project")
        capability["project_action"] = action
        capability["reasons"] = reasons
        raise DockerCapabilityError(str(exc), payload) from exc
    probes = [
        require_docker_capability_probe(
            ["info", "--format", "{{json .ServerVersion}}"],
            capability_name="docker_daemon",
            unavailable_code="docker_daemon_unavailable",
        )
    ]
    compose = spec.get("compose") or {}
    if compose.get("declared") and compose.get("autostart"):
        probes.append(
            require_docker_capability_probe(
                ["compose", "version", "--short"],
                capability_name="docker_compose",
                unavailable_code="docker_compose_unavailable",
            )
        )
    compose_restart_plan = None
    if action == "restart" and compose.get("declared") and compose.get("autostart"):
        compose_restart_plan = compose_restart_service_plan(spec)
    return {
        "required": True,
        "capability": "docker_cli",
        "reasons": reasons,
        "docker_executable": executable,
        "probes": probes,
        "compose_restart_plan": compose_restart_plan,
    }


def project_action_error_from_exception(
    exc: BaseException, *, name: str = "docker", fallback_classification: str = "unhealthy_process"
) -> dict[str, Any]:
    payload = coordinator_exception_payload(exc)
    classification = str(payload.get("classification") or fallback_classification)
    result: dict[str, Any] = {
        "name": name,
        "classification": classification,
        "code": payload.get("code") or "action_failed",
        "error": payload.get("error") or str(exc),
    }
    if payload.get("capability"):
        result["capability"] = copy.deepcopy(payload["capability"])
    for key in ("command", "timeout_seconds", "docker_executable"):
        if payload.get(key) is not None:
            result[key] = copy.deepcopy(payload[key])
    return result


def project_preflight_failure_report(
    before: dict[str, Any], *, action: str, exc: BaseException
) -> dict[str, Any]:
    action_error = project_action_error_from_exception(exc)
    classification = str(action_error["classification"])
    result = copy.deepcopy(before)
    result["action"] = action
    result["ok"] = False
    result["classification"] = classification
    result["classifications"] = sorted(
        set([classification, *[str(item) for item in before.get("classifications") or [] if item]])
    )
    result["before"] = copy.deepcopy(before)
    result["actions"] = []
    result["action_errors"] = [action_error]
    result["partial"] = False
    result["preflight_failed"] = True
    return result


def execute_project_start(
    options: dict[str, Any],
    spec: dict[str, Any],
    before: dict[str, Any],
    *,
    skip_compose_lifecycle: bool = False,
) -> dict[str, Any]:
    agent = str(options["agent"])
    dry_run = bool(options.get("dry_run"))
    actions: list[dict[str, Any]] = []
    action_errors: list[dict[str, Any]] = []
    compose = spec.get("compose")
    if compose and compose.get("autostart") and not skip_compose_lifecycle:
        command = ["docker", "compose"]
        for file_name in compose.get("files") or []:
            command.extend(["-f", file_name])
        command.extend(["up", "-d"])
        command.extend(compose.get("services") or [])
        try:
            actions.append(
                coordinated_run_docker(
                    command,
                    cwd=compose["cwd"],
                    dry_run=dry_run,
                    project=spec["project"],
                    agent=agent,
                )
            )
        except Exception as exc:
            action_errors.append(
                project_action_error_from_exception(
                    exc,
                    name=str(compose.get("name") or "docker-compose"),
                    fallback_classification="unhealthy_process",
                )
            )
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
    try:
        actions.extend(ensure_runtime_docker_metadata_coordinated(spec, options))
    except Exception as exc:
        action_errors.append(
            project_action_error_from_exception(
                exc,
                name="docker-metadata",
                fallback_classification="unhealthy_process",
            )
        )
    containers = spec.get("docker", {}).get("containers", [])
    for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
        status = docker_dependency_status(dep, containers)
        if status.get("ok"):
            continue
        container_name = dep.get("container") or dep.get("name")
        action = "restart" if status.get("classification") == "unhealthy_process" else "start"
        try:
            actions.append(
                coordinated_run_docker(
                    ["docker", action, container_name],
                    dry_run=dry_run,
                    project=spec["project"],
                    agent=agent,
                    container=container_name,
                )
            )
        except Exception as exc:
            action_errors.append(
                project_action_error_from_exception(
                    exc,
                    name=str(dep.get("name") or container_name or "docker"),
                    fallback_classification=str(
                        status.get("classification") or "unhealthy_process"
                    ),
                )
            )
    ordered_servers = sorted(
        spec.get("servers", []),
        key=lambda item: str(item.get("role")).lower() in {"web", "frontend"},
    )
    for server_def in ordered_servers:
        try:
            if dry_run:
                actions.append(planned_runtime_server_action(server_def, "start"))
            else:
                actions.append(coordinated_start_runtime_server(server_def, options))
        except Exception as exc:
            action_errors.append(
                project_action_error_from_exception(
                    exc,
                    name=str(server_def.get("name") or "server"),
                    fallback_classification="missing_dependency",
                )
            )
    _refreshed, after = observe_project_runtime(options, action="start")
    after["before"] = before
    after["actions"] = actions
    after["action_errors"] = action_errors
    after["partial"] = bool(actions and action_errors)
    if action_errors:
        after["ok"] = False
        after["classifications"] = sorted(
            set(after.get("classifications", []) + [item["classification"] for item in action_errors])
        )
        after["classification"] = after["classifications"][0]
    return after


def coordinated_project_runtime_start(options: dict[str, Any]) -> dict[str, Any]:
    prepared, operation = begin_project_operation(options, "start")
    try:
        with delegated_project_operation(operation):
            spec, before = observe_project_runtime(prepared, action="pre-start")
            try:
                preflight = preflight_project_docker(
                    spec,
                    action="start",
                    dry_run=bool(prepared.get("dry_run")),
                )
            except StructuredCoordinatorError as exc:
                result = project_preflight_failure_report(before, action="start", exc=exc)
            else:
                result = execute_project_start(prepared, spec, before)
                result["preflight"] = preflight
    except Exception as exc:
        finish_project_operation(operation["id"], error=exc)
        raise
    finish_project_operation(operation["id"], result=result)
    return result


def coordinated_project_runtime_restart(options: dict[str, Any]) -> dict[str, Any]:
    prepared, operation = begin_project_operation(options, "restart")
    delegation = delegated_project_operation(operation)
    delegation.__enter__()
    try:
        spec, before = observe_project_runtime(prepared, action="pre-restart")
        dry_run = bool(prepared.get("dry_run"))
        try:
            preflight = preflight_project_docker(
                spec,
                action="restart",
                dry_run=dry_run,
            )
        except StructuredCoordinatorError as exc:
            result = project_preflight_failure_report(before, action="restart", exc=exc)
        else:
            actions: list[dict[str, Any]] = []
            action_errors: list[dict[str, Any]] = []
            snapshot = snapshot_coordinator_state()
            for server_def in reversed(spec.get("servers", [])):
                server_id, existing = find_server(
                    snapshot, project=server_def["project"], name=server_def["name"]
                )
                if not existing:
                    continue
                try:
                    if dry_run:
                        actions.append(planned_runtime_server_action(server_def, "stop"))
                    else:
                        actions.append(
                            coordinated_stop_server(
                                {
                                    "server_id": server_id,
                                    "agent": prepared["agent"],
                                    "project": existing["project"],
                                    "name": existing["name"],
                                    "release_port": True,
                                    "reason": "Restarted by project runtime",
                                }
                            )
                        )
                except Exception as exc:
                    action_errors.append(
                        project_action_error_from_exception(
                            exc,
                            name=str(server_def.get("name") or "server"),
                            fallback_classification="unhealthy_process",
                        )
                    )
            for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
                container_name = dep.get("container") or dep.get("name")
                try:
                    actions.append(
                        coordinated_run_docker(
                            ["docker", "restart", container_name],
                            dry_run=dry_run,
                            project=spec["project"],
                            agent=prepared["agent"],
                            container=container_name,
                        )
                    )
                except Exception as exc:
                    action_errors.append(
                        project_action_error_from_exception(
                            exc,
                            name=str(dep.get("name") or container_name or "docker"),
                        )
                    )
            compose = spec.get("compose")
            if compose and compose.get("autostart"):
                restart_plan = preflight.get("compose_restart_plan") or {}
                compose_prefix = ["docker", *compose_command_prefix(compose)]
                lifecycle_commands: list[list[str]] = []
                restart_services = list(restart_plan.get("restart_services") or [])
                start_services = list(restart_plan.get("start_services") or [])
                all_services_action = restart_plan.get("all_services_action")
                if start_services:
                    lifecycle_commands.append([*compose_prefix, "up", "-d", *start_services])
                if restart_services:
                    lifecycle_commands.append([*compose_prefix, "restart", *restart_services])
                if all_services_action == "restart" and not lifecycle_commands:
                    lifecycle_commands.append([*compose_prefix, "restart"])
                for command in lifecycle_commands:
                    try:
                        actions.append(
                            coordinated_run_docker(
                                command,
                                cwd=compose["cwd"],
                                dry_run=dry_run,
                                project=spec["project"],
                                agent=prepared["agent"],
                            )
                        )
                    except Exception as exc:
                        action_errors.append(
                            project_action_error_from_exception(
                                exc,
                                name=str(compose.get("name") or "docker-compose"),
                            )
                        )
            refreshed_spec, _unused = observe_project_runtime(prepared, action="restart-start")
            started = execute_project_start(
                prepared,
                refreshed_spec,
                before,
                skip_compose_lifecycle=bool(compose and compose.get("autostart")),
            )
            started["action"] = "restart"
            started["before"] = before
            started["actions"] = actions + started.get("actions", [])
            started["action_errors"] = action_errors + started.get("action_errors", [])
            started["partial"] = bool(started["actions"] and started["action_errors"])
            if started["action_errors"]:
                started["ok"] = False
                started["classifications"] = sorted(
                    set(
                        [str(item) for item in started.get("classifications") or [] if item]
                        + [str(item["classification"]) for item in started["action_errors"]]
                    )
                )
                started["classification"] = started["classifications"][0]
            started["preflight"] = preflight
            result = started
    except Exception as exc:
        finish_project_operation(operation["id"], error=exc)
        raise
    finally:
        delegation.__exit__(None, None, None)
    finish_project_operation(operation["id"], result=result)
    return result


def coordinated_project_runtime_stop(options: dict[str, Any]) -> dict[str, Any]:
    prepared, operation = begin_project_operation(options, "stop")
    delegation = delegated_project_operation(operation)
    delegation.__enter__()
    try:
        spec, before = observe_project_runtime(prepared, action="pre-stop")
        dry_run = bool(prepared.get("dry_run"))
        try:
            preflight = preflight_project_docker(
                spec,
                action="stop",
                dry_run=dry_run,
            )
        except StructuredCoordinatorError as exc:
            result = project_preflight_failure_report(before, action="stop", exc=exc)
        else:
            actions: list[dict[str, Any]] = []
            action_errors: list[dict[str, Any]] = []
            snapshot = snapshot_coordinator_state()
            for server_def in reversed(spec.get("servers", [])):
                server_id, existing = find_server(
                    snapshot, project=server_def["project"], name=server_def["name"]
                )
                if not existing or existing.get("status") == "stopped":
                    continue
                try:
                    if dry_run:
                        actions.append(planned_runtime_server_action(server_def, "stop"))
                    else:
                        actions.append(
                            coordinated_stop_server(
                                {
                                    "server_id": server_id,
                                    "agent": prepared["agent"],
                                    "project": existing["project"],
                                    "name": existing["name"],
                                    "reason": "Stopped by project runtime",
                                }
                            )
                        )
                except Exception as exc:
                    action_errors.append(
                        project_action_error_from_exception(
                            exc,
                            name=str(server_def.get("name") or "server"),
                            fallback_classification="unhealthy_process",
                        )
                    )
            for dep in mutable_runtime_docker_dependencies(spec, exclude_compose_owned=True):
                container_name = dep.get("container") or dep.get("name")
                current = docker_dependency_status(dep, spec.get("docker", {}).get("containers", []))
                if current.get("status") == "missing" or is_stopped_container_status(
                    str(current.get("status") or "")
                ):
                    continue
                try:
                    actions.append(
                        coordinated_run_docker(
                            ["docker", "stop", container_name],
                            dry_run=dry_run,
                            project=spec["project"],
                            agent=prepared["agent"],
                            container=container_name,
                        )
                    )
                except Exception as exc:
                    action_errors.append(
                        project_action_error_from_exception(
                            exc,
                            name=str(dep.get("name") or container_name or "docker"),
                        )
                    )
            compose = spec.get("compose")
            if compose and compose.get("autostart"):
                command = ["docker", "compose"]
                for file_name in compose.get("files") or []:
                    command.extend(["-f", file_name])
                command.append("stop")
                command.extend(compose.get("services") or [])
                try:
                    actions.append(
                        coordinated_run_docker(
                            command,
                            cwd=compose["cwd"],
                            dry_run=dry_run,
                            project=spec["project"],
                            agent=prepared["agent"],
                        )
                    )
                except Exception as exc:
                    action_errors.append(
                        project_action_error_from_exception(
                            exc,
                            name=str(compose.get("name") or "docker-compose"),
                        )
                    )
            _refreshed, after = observe_project_runtime(prepared, action="stop")
            after["ok"] = not action_errors
            after["before"] = before
            after["actions"] = actions
            after["action_errors"] = action_errors
            after["partial"] = bool(actions and action_errors)
            after["preflight"] = preflight
            if action_errors:
                after["classifications"] = sorted(
                    set(
                        [str(item) for item in after.get("classifications") or [] if item]
                        + [str(item["classification"]) for item in action_errors]
                    )
                )
                after["classification"] = after["classifications"][0]
            else:
                after["classification"] = None
                after["classifications"] = []
            result = after
    except Exception as exc:
        finish_project_operation(operation["id"], error=exc)
        raise
    finally:
        delegation.__exit__(None, None, None)
    finish_project_operation(operation["id"], result=result)
    return result


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
    elif listener_identity_unobservable(health):
        # Read-only observers report the capability gap but preserve the last
        # lifecycle decision and its linked lease exactly.
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


COMPOSE_OPTIONS_WITH_VALUES = {
    "-f",
    "--file",
    "-p",
    "--project-name",
    "--profile",
    "--env-file",
    "--parallel",
    "--ansi",
    "--progress",
    "--project-directory",
}
COMPOSE_MUTATING_COMMANDS = {
    "build",
    "create",
    "down",
    "kill",
    "pause",
    "pull",
    "push",
    "restart",
    "rm",
    "run",
    "start",
    "stop",
    "unpause",
    "up",
}


def docker_compose_subcommand(command: list[str]) -> str | None:
    if len(command) < 3 or command[:2] != ["docker", "compose"]:
        return None
    index = 2
    while index < len(command):
        token = command[index]
        if token == "--":
            index += 1
            return command[index] if index < len(command) else None
        if token in COMPOSE_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def docker_command_is_mutating(command: list[str]) -> bool:
    if len(command) < 2 or command[0] != "docker":
        return False
    if command[1] in {"start", "stop", "restart"}:
        return True
    return docker_compose_subcommand(command) in COMPOSE_MUTATING_COMMANDS


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


def docker_command_failed_error(result: dict[str, Any]) -> StructuredCoordinatorError:
    command = [str(item) for item in result.get("command") or []]
    stderr = str(result.get("stderr") or "").strip()
    message = f"docker command failed: {' '.join(command)}"
    if stderr:
        message = f"{message}\n{stderr}"
    return StructuredCoordinatorError(
        message,
        {
            "code": "docker_command_failed",
            "classification": "unhealthy_process",
            "command": command,
            "returncode": result.get("returncode"),
            "stderr": stderr,
            "docker_executable": result.get("docker_executable"),
        },
    )


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
    mutating = docker_command_is_mutating(command)
    try:
        completed, executable, timeout_seconds = execute_docker_subprocess(
            command,
            cwd=cwd,
            lifecycle=mutating,
        )
    except Exception as exc:
        result = {
            "returncode": None,
            "command": command,
            "cwd": cwd,
            "agent": agent,
            "project": project,
            **coordinator_exception_payload(exc),
        }
        record_docker_command(state, command, cwd, result, project, agent)
        raise
    result = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
        "cwd": cwd,
        "agent": agent,
        "project": project,
        "docker_executable": executable,
        "timeout_seconds": timeout_seconds,
    }
    if completed.returncode != 0:
        record_docker_command(state, command, cwd, result, project, agent)
        raise docker_command_failed_error(result)
    if container and agent and project:
        result["metadata"] = register_docker_metadata(
            state,
            {"container": container, "agent": agent, "project": project, "cwd": cwd, "role": role},
        )
    record_docker_command(state, command, cwd, result, project, agent)
    return result


def coordinated_run_docker(
    command: list[str],
    *,
    cwd: str | None = None,
    dry_run: bool = False,
    project: str | None = None,
    agent: str | None = None,
    container: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """Run Docker outside the state lock, then atomically record the result."""

    mutating = docker_command_is_mutating(command)
    if mutating:
        agent, project = require_identity(
            {"agent": agent, "project": project}, "docker " + " ".join(command[1:3])
        )
    elif project:
        project = canonical_project(project)
    if dry_run:
        result: dict[str, Any] = {
            "dry_run": True,
            "command": command,
            "cwd": cwd,
            "agent": agent,
            "project": project,
        }
        if container and agent and project:
            result["metadata"] = coordinated_register_docker_metadata(
                {
                    "container": container,
                    "agent": agent,
                    "project": project,
                    "cwd": cwd,
                    "role": role,
                    "dry_run": True,
                }
            )
        with locked_state() as state:
            record_docker_command(state, command, cwd, result, project, agent)
        return result

    try:
        docker_executable = resolve_docker_executable()
    except Exception as exc:
        failure_result = {
            "returncode": None,
            "command": command,
            "cwd": cwd,
            "agent": agent,
            "project": project,
            **coordinator_exception_payload(exc),
        }
        with locked_state() as state:
            record_docker_command(state, command, cwd, failure_result, project, agent)
        raise

    operation_id: str | None = None
    if mutating:
        if container:
            target_suffix = docker_container_operation_identity(container)
            if not target_suffix or not target_suffix.startswith("container-id:"):
                raise RuntimeError(
                    f"cannot mutate Docker container {container}: immutable container identity was not verified"
                )
        else:
            target_suffix = canonical_project(project or cwd or "")
        with locked_state() as state:
            compose_action = docker_compose_subcommand(command)
            operation_action = compose_action if command[1] == "compose" else command[1]
            operation = begin_operation(
                state,
                action=f"docker.{command[1]}.{operation_action}" if command[1] == "compose" else f"docker.{operation_action}",
                target=f"docker:{target_suffix}",
                agent=str(agent),
                project=str(project),
                generation=int(state.get("revision") or 0) + 1,
            )
            operation_id = str(operation["id"])

    try:
        completed, executable, timeout_seconds = execute_docker_subprocess(
            command,
            cwd=cwd,
            lifecycle=mutating,
            executable=docker_executable,
        )
        result = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": command,
            "cwd": cwd,
            "agent": agent,
            "project": project,
            "docker_executable": executable,
            "timeout_seconds": timeout_seconds,
        }
    except Exception as exc:
        failure_result = {
            "returncode": None,
            "command": command,
            "cwd": cwd,
            "agent": agent,
            "project": project,
            "docker_executable": docker_executable,
            **coordinator_exception_payload(exc),
        }
        with locked_state() as state:
            record_docker_command(state, command, cwd, failure_result, project, agent)
            if operation_id:
                finish_operation(state, operation_id, status="failed", phase="execute", error=str(exc))
        raise

    if completed.returncode == 0 and container and agent and project:
        try:
            result["metadata"] = coordinated_register_docker_metadata(
                {"container": container, "agent": agent, "project": project, "cwd": cwd, "role": role}
            )
        except Exception as exc:
            result["metadata_error"] = str(exc)
            with locked_state() as state:
                record_docker_command(state, command, cwd, result, project, agent)
                if operation_id:
                    finish_operation(state, operation_id, status="failed", phase="metadata", error=str(exc))
            raise
    with locked_state() as state:
        record_docker_command(state, command, cwd, result, project, agent)
        if operation_id:
            finish_operation(
                state,
                operation_id,
                status="completed" if completed.returncode == 0 else "failed",
                phase="committed",
                error=completed.stderr.strip() if completed.returncode != 0 else None,
            )
    if completed.returncode != 0:
        raise docker_command_failed_error(result)
    return result


def print_result(value: Any, *, as_json: bool = True) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value)


def add_common_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", default=True, help=argparse.SUPPRESS)


def parse_argv_json(raw: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"--argv must be a JSON array: {exc}") from exc
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise argparse.ArgumentTypeError("--argv must be a non-empty JSON array of strings")
    return value


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
    reset.add_argument("--agent", required=True)
    reset.add_argument("--project", required=True)

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
    release.add_argument("--agent", required=True)
    release.add_argument("--project", required=True)
    port_sub.add_parser("list")
    assign = port_sub.add_parser("assign")
    assign.add_argument("--agent", required=True)
    assign.add_argument("--project", required=True)
    assign.add_argument("--name", required=True)
    assign.add_argument("--port", type=int, required=True)
    assign.add_argument("--force", action="store_true")
    relocate = port_sub.add_parser("relocate")
    relocate.add_argument("--agent", required=True)
    relocate.add_argument("--old-project", required=True)
    relocate.add_argument("--new-project", required=True)
    relocate.add_argument("--name", required=True)
    relocate.add_argument("--port", type=int, required=True)
    relocate.add_argument(
        "--lease-id",
        required=True,
        help="exact active/stale-released lease identity captured before cutover",
    )
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
    start_command = start.add_mutually_exclusive_group(required=True)
    start_command.add_argument("--cmd")
    start_command.add_argument("--argv", type=parse_argv_json)
    start.add_argument(
        "--lease-id",
        help="attach an existing active manual lease; requires structured --argv",
    )
    # No parser default: start_server must see whether --range was explicitly
    # given, because an omitted range pins hard to the durable assignment.
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
    register_command = register.add_mutually_exclusive_group()
    register_command.add_argument("--cmd")
    register_command.add_argument("--argv", type=parse_argv_json)
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
    serve.add_argument("--token-file")
    return parser


def namespace_to_options(args: argparse.Namespace) -> dict[str, Any]:
    return {key: value for key, value in vars(args).items() if key not in {"group", "action", "json"} and value is not None}


def handle_cli(args: argparse.Namespace) -> Any:
    if args.group == "state" and args.action == "reset":
        if not args.force:
            raise SystemExit("--force is required")
        identity = namespace_to_options(args)
        agent, project = require_identity(identity, "state reset")
        with locked_state() as state:
            prior = {
                "revision": state.get("revision"),
                "lease_count": len(state.get("leases", {})),
                "server_count": len(state.get("servers", {})),
                "pending_operation_count": sum(
                    1
                    for operation in state.get("operations", {}).values()
                    if operation.get("status") == "pending"
                ),
            }
            state.clear()
            state.update(default_state())
            record_event(
                state,
                "state.reset",
                {
                    "agent": agent,
                    "project": project,
                    "agent_metadata": agent_metadata(
                        agent=agent,
                        project=project,
                        source="state_reset",
                    ),
                    "prior": prior,
                },
            )
            return state
    if args.group == "server" and args.action == "start":
        return coordinated_start_server(namespace_to_options(args))
    if args.group == "server" and args.action == "stop":
        return coordinated_stop_server(namespace_to_options(args))
    if args.group == "server" and args.action == "restart":
        return coordinated_restart_server(namespace_to_options(args))
    if args.group == "server" and args.action == "register":
        return coordinated_register_server(namespace_to_options(args))
    if args.group == "server" and args.action == "status":
        return coordinated_status_server(namespace_to_options(args))
    if args.group == "server" and args.action == "logs":
        return coordinated_server_logs(namespace_to_options(args))
    if args.group == "project" and args.action == "status":
        return coordinated_project_runtime_status(namespace_to_options(args))
    if args.group == "project" and args.action == "start":
        return coordinated_project_runtime_start(namespace_to_options(args))
    if args.group == "project" and args.action == "restart":
        return coordinated_project_runtime_restart(namespace_to_options(args))
    if args.group == "project" and args.action == "stop":
        return coordinated_project_runtime_stop(namespace_to_options(args))
    if args.group == "inventory":
        return coordinated_build_inventory(
            project=args.project,
            include_docker=not args.no_docker,
            backup_dirs=args.backup_dir,
        )
    if args.group == "docker" and args.action == "ps":
        command = ["docker", "ps"]
        if args.all:
            command.append("--all")
        return coordinated_run_docker(command, dry_run=args.dry_run)
    if args.group == "docker" and args.action in {"compose-up", "compose-down"}:
        command = ["docker", "compose"]
        for file_name in args.file:
            command.extend(["-f", file_name])
        command.append("up" if args.action == "compose-up" else "down")
        if args.action == "compose-up" and args.detach:
            command.append("-d")
        return coordinated_run_docker(
            command,
            cwd=args.cwd,
            dry_run=args.dry_run,
            project=args.project,
            agent=args.agent,
        )
    if args.group == "docker" and args.action == "logs":
        return coordinated_run_docker(
            ["docker", "logs", "--tail", str(args.tail), args.container], dry_run=args.dry_run
        )
    if args.group == "docker" and args.action in {"start", "stop", "restart"}:
        return coordinated_run_docker(
            ["docker", args.action, args.container],
            dry_run=args.dry_run,
            project=args.project,
            agent=args.agent,
            container=args.container,
            role=args.role,
        )
    if args.group == "docker" and args.action == "stats":
        return coordinated_sample_docker_stats(dry_run=args.dry_run)
    if args.group == "docker" and args.action == "register":
        return coordinated_register_docker_metadata(namespace_to_options(args))
    if args.group == "port" and args.action == "lease":
        args.project = canonical_project(args.project)
        prime_git_head_identity(args.project)
    if args.group == "port" and args.action == "release":
        args.project = canonical_project(args.project)
        prime_git_head_identity(args.project)
    if args.group == "port" and args.action == "relocate":
        args.old_project = canonical_project(args.old_project)
        args.new_project = canonical_project(args.new_project)
        prime_git_head_identity(args.old_project)
        prime_git_head_identity(args.new_project)
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
            return release_port_for_identity(
                state,
                agent=args.agent,
                project=args.project,
                lease_id=args.lease_id,
                port=args.port,
            )
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
        if args.group == "port" and args.action == "relocate":
            return relocate_port_assignment(
                state,
                agent=args.agent,
                old_project=args.old_project,
                new_project=args.new_project,
                name=args.name,
                port=args.port,
                lease_id=args.lease_id,
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
        if args.group == "server" and args.action == "list":
            return list(state["servers"].values())
    raise SystemExit("unsupported command")


def validate_api_bind_host(host: str) -> str:
    candidate = str(host or "").strip()
    if candidate.lower() == "localhost":
        return candidate
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError("coordinator API host must be an explicit loopback address or localhost") from exc
    if not address.is_loopback:
        raise ValueError("coordinator API refuses non-loopback bind addresses")
    if address.version != 4:
        raise ValueError(
            "coordinator API currently supports IPv4 loopback only; use 127.0.0.1 instead of an IPv6 address"
        )
    return candidate


def linux_process_capability_sets(pid: int | str = "self") -> dict[str, int]:
    if not sys.platform.startswith("linux"):
        return {}
    values: dict[str, int] = {}
    labels = {
        "CapInh": "inheritable",
        "CapPrm": "permitted",
        "CapEff": "effective",
        "CapBnd": "bounding",
        "CapAmb": "ambient",
    }
    try:
        with open(Path("/proc") / str(pid) / "status", encoding="utf-8") as handle:
            for line in handle:
                key, separator, raw = line.partition(":")
                if separator and key in labels:
                    values[labels[key]] = int(raw.strip(), 16)
    except OSError as exc:
        raise RuntimeError(f"cannot inspect Linux capability sets for PID {pid}: {exc}") from exc
    missing = sorted(set(labels.values()) - set(values))
    if missing:
        raise RuntimeError(f"Linux capability status omitted: {', '.join(missing)}")
    return values


def clear_exec_capability_inheritance() -> dict[str, Any]:
    """Keep observer capabilities local to this process, never to exec children.

    The production API needs the same permitted capability as the Console to
    inspect that capability-bearing process's fd/cwd links.  Ambient and
    inheritable sets would otherwise flow through ``exec`` into every managed
    server.  Clear exactly those sets while retaining this process's effective
    and permitted observer capability.
    """

    if not sys.platform.startswith("linux"):
        return {"supported": False, "cleared": True}
    before = linux_process_capability_sets()
    libc = ctypes.CDLL(None, use_errno=True)

    class CapabilityHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapabilityData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    if before["inheritable"]:
        header = CapabilityHeader(0x20080522, 0)
        data = (CapabilityData * 2)()
        if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), "capget")
        for word in data:
            word.inheritable = 0
        if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), "capset")

    if before["ambient"]:
        # prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        if libc.prctl(47, 4, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), "prctl(PR_CAP_AMBIENT_CLEAR_ALL)")

    after = linux_process_capability_sets()
    if after["inheritable"] or after["ambient"]:
        raise RuntimeError("coordinator failed to clear inheritable/ambient capabilities")
    if after["permitted"] != before["permitted"] or after["effective"] != before["effective"]:
        raise RuntimeError("coordinator capability boundary unexpectedly changed observer capabilities")
    return {
        "supported": True,
        "cleared": True,
        "had_inheritable": bool(before["inheritable"]),
        "had_ambient": bool(before["ambient"]),
    }


def request_hostname(raw: str) -> str | None:
    try:
        return urlparse(f"//{raw}").hostname
    except ValueError:
        return None


def loopback_hostname(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(host).is_loopback
    return False


class BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = API_MAX_CONCURRENT_REQUESTS * 2

    def __init__(self, server_address: tuple[str, int], handler: type[http.server.BaseHTTPRequestHandler], *, token: str):
        self.api_token = token
        self._request_slots = threading.BoundedSemaphore(API_MAX_CONCURRENT_REQUESTS)
        super().__init__(server_address, handler)

    def server_bind(self) -> None:
        """Bind without HTTPServer's reverse-DNS lookup.

        The inherited getfqdn call can stall macOS CI before listen(). The
        server never uses the derived FQDN, so bind like TCPServer and report
        the actual bound address (including OS-assigned port zero).
        """

        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        self._request_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


API_GET_ROUTES = frozenset(
    {
        "/v1/inventory",
        "/v1/state",
        "/v1/ports",
        "/v1/ports/assignments",
        "/v1/servers",
    }
)
API_POST_ROUTES = frozenset(
    {
        "/v1/servers/start",
        "/v1/servers/stop",
        "/v1/servers/restart",
        "/v1/servers/register",
        "/v1/servers/status",
        "/v1/servers/logs",
        "/v1/projects/status",
        "/v1/projects/start",
        "/v1/projects/restart",
        "/v1/projects/stop",
        "/v1/docker/stats",
        "/v1/docker/register",
        "/v1/docker/ps",
        "/v1/docker/compose-up",
        "/v1/docker/compose-down",
        "/v1/docker/logs",
        "/v1/docker/start",
        "/v1/docker/stop",
        "/v1/docker/restart",
        "/v1/ports/lease",
        "/v1/ports/release",
        "/v1/ports/assign",
        "/v1/ports/unassign",
    }
)


class ApiHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CodexDevCoordinator/2"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(API_REQUEST_TIMEOUT_SECONDS)

    def _send(self, status: int, payload: Any, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="codex-dev-coordinator"')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        # HEAD describes the same representation as the corresponding request
        # while never writing that representation to the connection.
        if self.command != "HEAD":
            self.wfile.write(body)

    def _method_not_allowed(self, allowed: tuple[str, ...]) -> None:
        self._send(405, {"error": "method not allowed"}, headers={"Allow": ", ".join(allowed)})

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("transfer encoding is not supported")
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise TypeError("POST requests require Content-Type: application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > API_BODY_LIMIT_BYTES:
            raise OverflowError(f"request body exceeds {API_BODY_LIMIT_BYTES} bytes")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSON request body: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON request body must be an object")
        return value

    def _request_boundary_ok(self) -> bool:
        host = request_hostname(self.headers.get("Host") or "")
        if not loopback_hostname(host):
            self._send(400, {"error": "invalid Host header"})
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlparse(origin)
            server_port = int(self.server.server_address[1])
            origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme not in {"http", "https"} or not loopback_hostname(parsed.hostname) or origin_port != server_port:
                self._send(403, {"error": "cross-origin requests are forbidden"})
                return False
        return True

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization") or ""
        scheme, _, supplied = header.partition(" ")
        expected = str(getattr(self.server, "api_token", ""))
        return scheme.lower() == "bearer" and bool(supplied) and hmac.compare_digest(supplied, expected)

    def _require_authorization(self) -> bool:
        if self._authorized():
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}", file=sys.stderr)

    def _handle_get(self, path: str) -> None:
        try:
            if path == "/v1/inventory":
                result: Any = coordinated_build_inventory()
            elif path in {"/v1/state", "/v1/ports", "/v1/ports/assignments", "/v1/servers"}:
                snapshot = snapshot_coordinator_state()
                if path == "/v1/state":
                    result = snapshot
                elif path == "/v1/ports":
                    result = list(snapshot["leases"].values())
                elif path == "/v1/ports/assignments":
                    result = list_port_assignments(snapshot)
                else:
                    result = list(snapshot["servers"].values())
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(200, result)
        except Exception as exc:  # pragma: no cover - defensive endpoint wrapper
            self._send(500, {"error": str(exc)})

    def _handle_post(self, path: str) -> None:
        try:
            payload = self._read_json()
            if path == "/v1/servers/start":
                self._send(200, coordinated_start_server(payload))
                return
            if path == "/v1/servers/stop":
                self._send(200, coordinated_stop_server(payload))
                return
            if path == "/v1/servers/restart":
                self._send(200, coordinated_restart_server(payload))
                return
            if path == "/v1/servers/register":
                self._send(200, coordinated_register_server(payload))
                return
            if path == "/v1/servers/status":
                self._send(200, coordinated_status_server(payload))
                return
            if path == "/v1/servers/logs":
                self._send(200, coordinated_server_logs(payload))
                return
            if path == "/v1/projects/status":
                self._send(200, coordinated_project_runtime_status(payload))
                return
            if path == "/v1/projects/start":
                self._send(200, coordinated_project_runtime_start(payload))
                return
            if path == "/v1/projects/restart":
                self._send(200, coordinated_project_runtime_restart(payload))
                return
            if path == "/v1/projects/stop":
                self._send(200, coordinated_project_runtime_stop(payload))
                return
            if path == "/v1/docker/stats":
                self._send(200, coordinated_sample_docker_stats(dry_run=bool(payload.get("dry_run"))))
                return
            if path == "/v1/docker/register":
                self._send(200, coordinated_register_docker_metadata(payload))
                return
            if path == "/v1/docker/ps":
                command = ["docker", "ps"]
                if payload.get("all"):
                    command.append("--all")
                self._send(200, coordinated_run_docker(command, dry_run=bool(payload.get("dry_run"))))
                return
            if path in {"/v1/docker/compose-up", "/v1/docker/compose-down"}:
                command = ["docker", "compose"]
                for file_name in payload.get("file") or []:
                    command.extend(["-f", file_name])
                command.append("up" if path.endswith("compose-up") else "down")
                if path.endswith("compose-up") and payload.get("detach"):
                    command.append("-d")
                self._send(
                    200,
                    coordinated_run_docker(
                        command,
                        cwd=payload.get("cwd"),
                        dry_run=bool(payload.get("dry_run")),
                        project=payload.get("project"),
                        agent=payload.get("agent"),
                    ),
                )
                return
            if path == "/v1/docker/logs":
                self._send(
                    200,
                    coordinated_run_docker(
                        ["docker", "logs", "--tail", str(payload.get("tail") or "80"), payload["container"]],
                        dry_run=bool(payload.get("dry_run")),
                    ),
                )
                return
            if path in {"/v1/docker/start", "/v1/docker/stop", "/v1/docker/restart"}:
                docker_action = path.rsplit("/", 1)[-1]
                self._send(
                    200,
                    coordinated_run_docker(
                        ["docker", docker_action, payload["container"]],
                        dry_run=bool(payload.get("dry_run")),
                        project=payload.get("project"),
                        agent=payload.get("agent"),
                        container=payload.get("container"),
                        role=payload.get("role"),
                    ),
                )
                return
            if path == "/v1/ports/lease":
                payload["project"] = canonical_project(payload["project"])
                prime_git_head_identity(payload["project"])
            elif path == "/v1/ports/release":
                release_agent, release_project = require_identity(payload, "port release")
                payload["agent"] = release_agent
                payload["project"] = release_project
            elif path in {"/v1/ports/assign", "/v1/ports/unassign"}:
                assignment_agent = str(payload.get("agent") or "").strip()
                if not assignment_agent:
                    raise ValueError("port assignment mutation requires agent attribution")
                payload["agent"] = assignment_agent
                if payload.get("project"):
                    payload["project"] = canonical_project(str(payload["project"]))
                    prime_git_head_identity(payload["project"])
            else:
                self._send(404, {"error": "not found"})
                return
            with locked_state() as state:
                if path == "/v1/ports/lease":
                    result = lease_port(
                        state,
                        agent=payload["agent"],
                        project=payload["project"],
                        port_range=payload.get("range") or DEFAULT_RANGE,
                        preferred=payload.get("preferred"),
                        ttl=int(payload.get("ttl") or DEFAULT_TTL_SECONDS),
                        purpose=payload.get("purpose") or "manual",
                    )
                elif path == "/v1/ports/release":
                    result = release_port_for_identity(
                        state,
                        agent=payload["agent"],
                        project=payload["project"],
                        lease_id=payload.get("lease_id"),
                        port=payload.get("port"),
                    )
                elif path == "/v1/ports/assign":
                    result = assign_port(
                        state,
                        agent=payload["agent"],
                        project=payload["project"],
                        name=payload["name"],
                        port=payload["port"],
                        force=bool(payload.get("force")),
                    )
                elif path == "/v1/ports/unassign":
                    result = unassign_port(
                        state,
                        agent=payload["agent"],
                        project=payload.get("project"),
                        name=payload.get("name"),
                        port=payload.get("port"),
                        force=bool(payload.get("force")),
                    )
            self._send(200, result)
        except OverflowError as exc:
            self._send(413, {"error": str(exc)})
        except TypeError as exc:
            self._send(415, {"error": str(exc)})
        except Exception as exc:
            self._send(400, {"error": str(exc)})

    def _handle_request(self) -> None:
        if not self._request_boundary_ok():
            return

        method = self.command.upper()
        path = urlparse(self.path).path
        if path == "/healthz":
            if method in {"GET", "HEAD"}:
                self._send(200, {"ok": True, "service": "codex-dev-coordinator", "version": VERSION})
            else:
                self._method_not_allowed(("GET", "HEAD"))
            return

        protected = path == "/v1" or path.startswith("/v1/")
        if not protected:
            self._send(404, {"error": "not found"})
            return

        # Authenticate the protected namespace before route or method
        # dispatch. Otherwise BaseHTTPRequestHandler's inherited unsupported
        # method path leaks a 501 before the bearer boundary is evaluated.
        if not self._require_authorization():
            return

        if path in API_GET_ROUTES:
            if method != "GET":
                self._method_not_allowed(("GET",))
                return
            self._handle_get(path)
            return
        if path in API_POST_ROUTES:
            if method != "POST":
                self._method_not_allowed(("POST",))
                return
            self._handle_post(path)
            return
        self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_request()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_request()

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle_request()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle_request()

    def __getattr__(self, name: str) -> Any:
        # BaseHTTPRequestHandler otherwise emits an unauthenticated HTML 501
        # for extension methods (for example WebDAV PROPFIND). Route every
        # syntactically accepted HTTP method through the same boundary.
        if name.startswith("do_") and len(name) > 3:
            return self._handle_request
        raise AttributeError(name)


def serve_api(host: str, port: int, *, token_file: str | None = None) -> None:
    clear_exec_capability_inheritance()
    host = validate_api_bind_host(host)
    token_path = Path(token_file).expanduser().absolute() if token_file else api_token_path()
    token = load_or_create_api_token(token_path)
    server = BoundedThreadingHTTPServer((host, port), ApiHandler, token=token)
    actual_port = int(server.server_address[1])
    print(
        json.dumps({"host": host, "port": actual_port, "url": f"http://{host}:{actual_port}", "token_file": str(token_path)}),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.group == "api" and args.action == "serve":
        try:
            serve_api(args.host, args.port, token_file=args.token_file)
            return 0
        except Exception as exc:
            print(json.dumps(coordinator_exception_payload(exc), indent=2, sort_keys=True), file=sys.stderr)
            return 1
    try:
        print_result(handle_cli(args))
        return 0
    except Exception as exc:
        print(json.dumps(coordinator_exception_payload(exc), indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
