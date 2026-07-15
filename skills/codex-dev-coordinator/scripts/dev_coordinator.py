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
import functools
import glob
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import platform
import pwd
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from devcoordinator.observer import ObservationOutcome, SingleFlightObserver
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.host_lifecycle import CoordinatorHostLifecycleAdapter
from devcoordinator.broker_cli import (
    add_broker_parser,
    handle_broker_cli,
    serve_broker,
)
from devcoordinator.broker import BrokerError, BrokerOperation
from devcoordinator.broker_enrollment import enroll_repository
from devcoordinator.broker_links import BrokerLink, BrokerLinkStore
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
    SYSTEM_PROFILE_PATH,
    call_broker,
    load_broker_profile,
)
from devcoordinator.lifecycle_cli import (
    add_lifecycle_parsers,
    handle_lifecycle_cli,
)
from devcoordinator.normalized_server_lifecycle import (
    NormalizedLifecycleConflict,
    NormalizedPortLifecycle,
    NormalizedServerLifecycle,
    PortLeaseRequest,
    ServerRegistrationRequest,
    ServerStartRequest,
)
from devcoordinator.repository_lifecycle import (
    ActionFencedError,
    ConcurrentLifecycleError,
    RepositoryAction,
    RepositoryLifecycle,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import (
    AccountStore,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)


VERSION = 2
NORMALIZED_SCHEMA_VERSION = 2
NORMALIZED_DATABASE_NAME = "coordinator.sqlite3"
STATE_BACKEND_ENV = "DEVCOORDINATOR_STATE_BACKEND"
LEGACY_JSON_BACKEND = "legacy-json-test-only"
OBSERVER_DOMAIN_FULL_DOCKER = "host-runtime-v2:full-docker"
OBSERVER_DOMAIN_NO_DOCKER = "host-runtime-v2:no-docker"
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
_NORMALIZED_ACTION_CONTEXT = threading.local()
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
    if isinstance(exc, ActionFencedError):
        return {
            "error": str(exc),
            "code": "repository_action_fenced",
            "classification": "lifecycle_fenced",
            "action_required": "Reinstall the removed repository through the Coordinator skill before starting it.",
        }
    if isinstance(exc, BrokerError):
        return {
            "error": exc.message,
            "code": exc.code,
            "classification": "broker_mutation_failed",
            "operation_id": exc.operation_id,
            "action_required": (
                "Keep the local resource stopped/reserved and retry through the Coordinator skill; "
                "do not bypass the configured host broker."
            ),
        }
    if isinstance(exc, BrokerProfileError):
        return {
            "error": str(exc),
            "code": "broker_profile_invalid",
            "classification": "broker_configuration_required",
            "action_required": "Rerun Coordinator skill installation as the host administrator.",
        }
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


def posix_account_home(
    *,
    effective_uid: int | None = None,
    account_lookup: Any | None = None,
) -> Path:
    """Resolve the stable POSIX account home for one effective user."""

    uid = os.geteuid() if effective_uid is None else int(effective_uid)
    lookup = pwd.getpwuid if account_lookup is None else account_lookup
    try:
        record = lookup(uid)
    except (KeyError, OSError) as error:
        raise RuntimeError(
            f"could not resolve POSIX account home for effective uid {uid}: {error}"
        ) from error
    raw_home = str(getattr(record, "pw_dir", "") or "")
    home = Path(raw_home)
    if not raw_home or not home.is_absolute():
        raise RuntimeError(
            f"POSIX account home for effective uid {uid} is not an absolute path"
        )
    return home.resolve()


def coordinator_home() -> Path:
    configured = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    if configured:
        return Path(configured).expanduser().resolve()
    return posix_account_home() / ".codex" / "agent-coordinator"


def state_backend() -> str:
    """Return the configured persistence backend.

    SQLite is the product backend.  The JSON implementation is retained only
    as an explicitly named, temporary test bridge for deterministic legacy
    fixtures while those fixtures are ported to normalized storage.
    """

    configured = str(os.environ.get(STATE_BACKEND_ENV) or "sqlite").strip().lower()
    if configured not in {"sqlite", LEGACY_JSON_BACKEND}:
        raise ValueError(
            f"{STATE_BACKEND_ENV} must be 'sqlite' or the explicit temporary "
            f"test bridge {LEGACY_JSON_BACKEND!r}"
        )
    return configured


def legacy_state_path() -> Path:
    return coordinator_home() / "state.json"


def state_path() -> Path:
    if state_backend() == LEGACY_JSON_BACKEND:
        return legacy_state_path()
    return coordinator_home() / NORMALIZED_DATABASE_NAME


def lock_path() -> Path:
    return coordinator_home() / "state.lock"


def logs_dir() -> Path:
    return coordinator_home() / "logs"


def api_token_path() -> Path:
    configured = os.environ.get("CODEX_AGENT_COORDINATOR_TOKEN_FILE")
    if configured:
        return Path(configured).expanduser().absolute()
    return coordinator_home() / "api-token"


def validate_private_directory(
    path: Path,
    *,
    effective_uid: int | None = None,
) -> None:
    """Require one effective OS user to own a private coordinator directory."""

    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError(f"private coordinator path is not a directory: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != 0o700:
        raise PermissionError(
            f"private coordinator directory must be mode 0700, got {mode:04o}: {path}"
        )
    expected_uid = os.geteuid() if effective_uid is None else int(effective_uid)
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"private coordinator directory is owned by uid {metadata.st_uid}, "
            f"not effective uid {expected_uid}: {path}"
        )


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError as error:
        raise PermissionError(
            f"could not make coordinator directory private: {path}: {error}"
        ) from error
    validate_private_directory(path)


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


def read_legacy_json_state() -> dict[str, Any]:
    path = legacy_state_path()
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


def read_state() -> dict[str, Any]:
    if state_backend() != LEGACY_JSON_BACKEND:
        raise RuntimeError(
            "read_state is disabled for the SQLite product backend; use a "
            "normalized domain query"
        )
    return read_legacy_json_state()


def write_legacy_json_state(state: dict[str, Any]) -> None:
    home = coordinator_home()
    ensure_private_directory(home)
    state["version"] = VERSION
    state["revision"] = int(state.get("revision") or 0) + 1
    state["updated_at"] = iso_timestamp()
    atomic_write_private(legacy_state_path(), json.dumps(state, indent=2, sort_keys=True) + "\n")


def write_state(state: dict[str, Any], *, expected_revision: int | None = None) -> None:
    if state_backend() != LEGACY_JSON_BACKEND:
        raise RuntimeError(
            "write_state is disabled for the SQLite product backend; use a "
            "normalized domain transaction"
        )
    write_legacy_json_state(state)


def restore_legacy_pending_operation_statuses(
    store: AccountStore, state: dict[str, Any]
) -> None:
    """Hydrate normalized compatibility operations back into the v1 state machine.

    SQLite stores both a v1 ``pending`` operation and a normalized lifecycle
    guard as ``running``. Only the former must become ``pending`` when handed
    back to the legacy callback code; translating ``guard:*`` would make the
    guarded action conflict with its own normalized permit. The reservation's
    process identity is retained in normalized ``result_json`` until the
    operation finishes so abandoned-owner reconciliation remains safe.
    """

    compatibility_prefixes = ("project.", "server.", "docker.", "port.")
    with store.read_transaction() as connection:
        encoded = {
            str(row["operation_id"]): row["result_json"]
            for row in connection.execute(
                """
                SELECT operation_id, result_json FROM operations
                WHERE status = 'running' AND (
                    kind LIKE 'project.%' OR kind LIKE 'server.%'
                    OR kind LIKE 'docker.%' OR kind LIKE 'port.%'
                )
                """
            )
        }
    for operation in (state.get("operations") or {}).values():
        kind = str(operation.get("kind") or "")
        if operation.get("status") == "running" and kind.startswith(
            compatibility_prefixes
        ):
            try:
                result = json.loads(str(encoded.get(str(operation.get("id"))) or "{}"))
            except json.JSONDecodeError:
                result = {}
            reservation = result.get("_legacy_reservation") if isinstance(result, dict) else None
            if not isinstance(reservation, dict):
                # Pre-cutover rows lack the process-instance evidence required
                # to decide whether the owner is alive. Keep them normalized
                # and conflicting instead of guessing that they are pending.
                continue
            operation.update(copy.deepcopy(reservation))
            operation["result"] = copy.deepcopy(result)
            operation["status"] = "pending"


@contextlib.contextmanager
def locked_state() -> Any:
    if state_backend() != LEGACY_JSON_BACKEND:
        raise RuntimeError(
            "locked_state is disabled for the SQLite product backend; "
            "route the operation through a direct normalized transaction"
        )

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


def _non_zombie_process_observation(pid: int) -> bool | None:
    """Return whether an existing PID is a non-zombie process when observable."""

    if sys.platform.startswith("linux"):
        try:
            stat_text = (Path("/proc") / str(int(pid)) / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            return False
        except OSError:
            return None
        _prefix, separator, suffix = stat_text.rpartition(") ")
        if not separator or not suffix:
            return None
        return suffix[0] not in {"Z", "X"}
    try:
        completed = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(int(pid))],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    states = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if states:
        return states[0][0].upper() not in {"Z", "X"}
    if completed.returncode in {0, 1} and not completed.stderr.strip():
        return False
    return None


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return False
    # kill(pid, 0) succeeds for an unreaped zombie. A zombie cannot own a
    # listener or be stopped again, and treating it as live turns retained PID
    # metadata into a false unobservable-ownership block during restart.
    non_zombie = _non_zombie_process_observation(int(pid))
    return non_zombie is not False


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
        lsof = resolve_lsof_executable()
        if lsof is None:
            return None
        completed = subprocess.run(
            [lsof, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"],
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


def resolve_lsof_executable() -> str | None:
    """Resolve lsof without trusting a caller-controlled PATH exclusively.

    Deterministic runtimes intentionally clear PATH, while macOS listener and
    cwd ownership checks still need the platform's standard system binary.
    Returning ``None`` preserves the ownership observer's unknown state when
    no trustworthy executable is available.
    """

    for candidate in (shutil.which("lsof"), "/usr/sbin/lsof", "/usr/bin/lsof"):
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if executable_file(path):
            return str(path.resolve())
    return None


def _lsof_listener_observation(
    host: str, port: int, *, expected_pid: int | None = None
) -> tuple[bool, int | None]:
    lsof = resolve_lsof_executable()
    if lsof is None:
        return False, None
    command = [lsof, "-nP", "-a"]
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
        if completed.stderr.strip():
            # lsof uses exit 1 for both a clean empty selection and errors.
            # Diagnostic output means the query was not a complete negative
            # observation (for example, proc/process permission denial).
            return False, None
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
    cwd_observation = process_cwd_observation(pid)
    if cwd_observation.get("observable") is False:
        raise ListenerIdentityUnobservable(
            str(
                cwd_observation.get("reason")
                or f"registration PID {pid} working directory is not observable by this process"
            )
        )
    cwd = cwd_observation.get("cwd")
    if not cwd:
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


def _proc_process_cwd_observation(pid: int) -> dict[str, Any]:
    proc_cwd = Path("/proc") / str(int(pid)) / "cwd"
    try:
        raw = os.readlink(proc_cwd)
    except PermissionError:
        return {
            "observable": False,
            "cwd": None,
            "reason": f"PID {pid} working directory is not observable by this process",
        }
    except (FileNotFoundError, ProcessLookupError):
        return {
            "observable": False,
            "cwd": None,
            "reason": f"PID {pid} working directory disappeared during observation",
        }
    except OSError:
        return {
            "observable": False,
            "cwd": None,
            "reason": f"PID {pid} working directory could not be observed through procfs",
        }
    if not os.path.isabs(raw):
        return {
            "observable": False,
            "cwd": None,
            "reason": f"PID {pid} procfs cwd target is not absolute",
        }
    try:
        cwd = str(Path(raw).resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return {
            "observable": False,
            "cwd": None,
            "reason": f"PID {pid} procfs cwd target could not be resolved strictly",
        }
    return {"observable": True, "cwd": cwd, "reason": None}


def process_cwd_from_proc(pid: int) -> str | None:
    """Read one Linux cwd symlink without converting denial into a path.

    Some older pathlib versions return a best-effort pseudo-path containing a
    ``readlink: Permission denied`` suffix from ``Path.resolve()`` on procfs.
    That string is not ownership evidence. Read the kernel link directly and
    require the resulting directory to resolve strictly.
    """

    return _proc_process_cwd_observation(pid).get("cwd")


def _lsof_process_cwd_observation(pid: int) -> tuple[bool, str | None]:
    lsof = resolve_lsof_executable()
    if lsof is None:
        return False, None
    try:
        completed = subprocess.run(
            [lsof, "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return False, None
    if completed.returncode not in {0, 1}:
        return False, None
    for line in completed.stdout.splitlines():
        if not line.startswith("n"):
            continue
        try:
            return True, str(Path(line[1:]).expanduser().resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            return False, None
    if completed.stderr.strip():
        return False, None
    return True, None


def process_cwd_observation(pid: int | None) -> dict[str, Any]:
    if not pid:
        return {"observable": True, "cwd": None, "reason": "process PID is absent"}
    if sys.platform.startswith("linux"):
        return _proc_process_cwd_observation(int(pid))
    observable, cwd = _lsof_process_cwd_observation(int(pid))
    return {
        "observable": observable,
        "cwd": cwd,
        "reason": None if observable else f"PID {pid} working directory is not observable by this process",
    }


def process_cwd(pid: int | None) -> str | None:
    return process_cwd_observation(pid).get("cwd")


def path_inside(child: str | None, parent: str | None) -> bool:
    if not child or not parent:
        return False
    child_path = Path(child).expanduser().resolve()
    parent_path = Path(parent).expanduser().resolve()
    return child_path == parent_path or parent_path in child_path.parents


def listener_owner_for_port(port: int, *, host: str | None = None) -> dict[str, Any]:
    pid = listening_pid_for_endpoint(host, port) if host else listening_pid_for_port(port)
    cwd_observation = process_cwd_observation(pid)
    cwd = cwd_observation.get("cwd")
    owner_project = canonical_project(cwd) if cwd else None
    return {
        "pid": pid,
        "cwd": cwd,
        "project": owner_project,
        "observable": cwd_observation.get("observable"),
        "reason": cwd_observation.get("reason"),
    }


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
        owner["reason"] = owner.get("reason") or (
            f"port {port} is owned by PID {owner['pid']}, but its working directory could not be identified"
        )
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
    cwd_observation = process_cwd_observation(pid)
    if cwd_observation.get("observable") is False:
        return {
            "ok": None,
            "observable": False,
            "pid": pid,
            "cwd": None,
            "project": None,
            "reason": cwd_observation.get("reason") or f"PID {pid} working directory is not observable",
        }
    cwd = cwd_observation.get("cwd")
    if not cwd:
        return {
            "ok": None,
            "observable": False,
            "pid": pid,
            "cwd": None,
            "project": None,
            "reason": (
                f"PID {pid} working directory was not present in a completed observation; "
                "project ownership cannot be proved"
            ),
        }
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
    if identity.get("ok") is False or identity.get("observable") is False:
        return identity
    pid = int(server.get("pid") or 0)
    if pid and pid_alive(pid):
        if server.get("registration_identity") or server.get(
            "_require_exact_listener_identity"
        ):
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
    operation["result"] = {
        "_legacy_reservation": {
            key: copy.deepcopy(operation.get(key))
            for key in (
                "action",
                "target",
                "agent",
                "project",
                "generation",
                "owner_pid",
                "owner_thread",
                "owner_instance_id",
                "lease_id",
                "server_id",
                "created_at",
                "created_ts",
                "updated_at",
                "parent_operation_id",
            )
            if operation.get(key) is not None
        }
    }
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


class RepositoryActionGuardReleaseError(RuntimeError):
    """A guarded mutation and its permit release both failed."""

    def __init__(self, primary_error: BaseException, release_error: BaseException) -> None:
        super().__init__(
            "repository action failed and its normalized permit could not be released: "
            f"{type(primary_error).__name__}: {primary_error}; release failure: "
            f"{type(release_error).__name__}: {release_error}"
        )
        self.primary_error = primary_error
        self.release_error = release_error


class _GuardOnlyLifecycleAdapter:
    """Sentinel adapter: action reservation must never perform host work."""

    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(f"repository action guard unexpectedly requested host adapter method {name}")


_GUARD_ONLY_LIFECYCLE_ADAPTER = _GuardOnlyLifecycleAdapter()


def _local_normalized_host_id() -> str:
    machine = f"{platform.system()}\x1f{platform.node()}\x1f{socket.gethostname()}"
    return deterministic_id("host", hashlib.sha256(machine.encode("utf-8")).hexdigest())


def _strict_git_repository_root(project: str) -> Path:
    root = Path(canonical_project(project))
    try:
        root_metadata = root.lstat()
        marker_metadata = (root / ".git").lstat()
    except FileNotFoundError as exc:
        raise ActionFencedError(
            f"repository action requires an existing canonical Git worktree: {root}"
        ) from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ActionFencedError(
            f"repository action requires a real canonical worktree directory: {root}"
        )
    if stat.S_ISLNK(marker_metadata.st_mode) or not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        raise ActionFencedError(
            f"repository action requires a real .git directory or worktree marker: {root}"
        )
    return root


def _require_normalized_bootstrap_before_mutation(store: AccountStore) -> None:
    """Import same-UID legacy truth before the first normalized mutation.

    A pure inventory never creates the SQLite store. Once a mutation opens a
    fresh store, legacy capture/import must run before repository installation
    or action reservation can establish normalized authority.
    """

    with store.read_transaction() as connection:
        metadata = connection.execute(
            """
            SELECT migration_state, first_sqlite_mutation_at, state_revision
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
    if metadata is None:
        raise ActionFencedError("normalized coordinator metadata is missing")
    first_mutation = metadata["first_sqlite_mutation_at"]
    migration_state = str(metadata["migration_state"] or "empty")
    if migration_state == "conflicted":
        raise ActionFencedError(
            "legacy coordinator migration has unresolved blocking conflicts; "
            "resolve them through explicit observe before mutation"
        )
    if first_mutation is not None and migration_state != "empty":
        late_writers = store.detect_late_legacy_writers()
        if late_writers:
            raise ActionFencedError(
                "a retired legacy coordinator source changed after capture; run explicit "
                "observe and reconcile that writer before mutation"
            )
        return
    report = bootstrap_legacy_import(store)
    if report.get("blocking_conflict_count"):
        raise ActionFencedError(
            "legacy coordinator state has blocking migration conflicts; run explicit observe "
            "and resolve its migration report before mutating this repository"
        )
    if report.get("attempted") and not report.get("committed"):
        raise ActionFencedError(
            "legacy coordinator state was not committed; run explicit observe before mutation"
        )
    if report.get("late_writer_sources"):
        raise ActionFencedError(
            "a legacy coordinator source changed after capture; run explicit observe and "
            "reconcile that writer before mutation"
        )


def _mark_first_normalized_action(store: AccountStore) -> None:
    with store.read_transaction() as connection:
        row = connection.execute(
            "SELECT first_sqlite_mutation_at FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
    if row is not None and row[0] is not None:
        return
    timestamp = utc_timestamp()
    with store.immediate_transaction() as connection:
        connection.execute(
            """
            UPDATE schema_metadata
            SET authority_mode = 'sqlite',
                migration_state = CASE
                    WHEN migration_state = 'empty' THEN 'ready'
                    ELSE migration_state
                END,
                first_sqlite_mutation_at = COALESCE(first_sqlite_mutation_at, ?),
                updated_at = ?
            WHERE singleton = 1
            """,
            (timestamp, timestamp),
        )


def resolve_or_install_repository_for_action(store: AccountStore, project: str) -> str:
    """Resolve one repository, installing only a never-before-seen Git root.

    Existing rows are returned unchanged. In particular, this helper never
    clears a ``disabling``/``disabled`` installation or revives a missing
    repository; only the explicit lifecycle reinstall journey may do that.
    """

    root = _strict_git_repository_root(project)
    host_id = _local_normalized_host_id()
    with store.read_transaction() as connection:
        existing = connection.execute(
            """
            SELECT repo_id FROM repositories
            WHERE host_id = ? AND canonical_root = ?
            """,
            (host_id, str(root)),
        ).fetchone()
    if existing is not None:
        return str(existing["repo_id"])

    ensured_host_id = ensure_observation_host(store)
    if ensured_host_id != host_id:
        raise RuntimeError("normalized local host identity changed during repository installation")
    timestamp = utc_timestamp()
    repo_id = deterministic_id("repository", host_id, str(root))
    with store.immediate_transaction() as connection:
        # Recheck under the writer boundary. A concurrently created row may
        # already carry a decommission fence and must never be overwritten.
        current = connection.execute(
            """
            SELECT repo_id FROM repositories
            WHERE host_id = ? AND canonical_root = ?
            """,
            (host_id, str(root)),
        ).fetchone()
        if current is not None:
            return str(current["repo_id"])
        connection.execute(
            """
            INSERT INTO repositories(
                repo_id, host_id, canonical_root, display_name, state,
                generation, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
            """,
            (repo_id, host_id, str(root), root.name or str(root), timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO repository_installations(
                repo_id, status, startup_fenced, generation, reason, actor,
                updated_at
            ) VALUES (?, 'installed', 0, 0, 'first coordinator use',
                      'coordinator-skill', ?)
            """,
            (repo_id, timestamp),
        )
        connection.execute(
            """
            UPDATE schema_metadata
            SET authority_mode = 'sqlite', migration_state = 'ready',
                first_sqlite_mutation_at = COALESCE(first_sqlite_mutation_at, ?),
                updated_at = ?
            WHERE singleton = 1
            """,
            (timestamp, timestamp),
        )
    return repo_id


def _normalized_guard_stack() -> list[dict[str, str]]:
    stack = getattr(_NORMALIZED_ACTION_CONTEXT, "stack", None)
    if stack is None:
        stack = []
        _NORMALIZED_ACTION_CONTEXT.stack = stack
    return stack


def _open_normalized_action_store() -> AccountStore:
    """Open the WAL store; its maintenance lock owns first-open serialization."""

    return AccountStore.open_default(coordinator_home())


def _reserve_normalized_repository_action(
    lifecycle: RepositoryLifecycle,
    store: AccountStore,
    *,
    repo_id: str,
    action: RepositoryAction,
    agent: str,
) -> Any:
    """Reserve once, queueing only independent same-repository lease guards."""

    request_id = str(uuid.uuid4())
    deadline = time.monotonic() + 5.0
    while True:
        try:
            return lifecycle.reserve_repository_action(
                repo_id, action, request_id=request_id, actor=agent
            )
        except ConcurrentLifecycleError:
            if action is not RepositoryAction.LEASE:
                raise
            with store.read_transaction() as connection:
                conflicts = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT kind FROM operations
                        WHERE repo_id = ?
                          AND status IN ('running','needs_attention','partial')
                        """,
                        (repo_id,),
                    )
                ]
            if not conflicts or any(kind != "guard:lease" for kind in conflicts):
                raise
            if time.monotonic() >= deadline:
                raise ConcurrentLifecycleError(
                    "timed out waiting for another independent repository lease reservation"
                )
            time.sleep(0.01)


@contextlib.contextmanager
def normalized_repository_action_guard(
    *, project: str, agent: str, action: RepositoryAction
) -> Any:
    """Reserve the normalized lifecycle boundary before legacy or host work."""

    canonical = canonical_project(project)
    if state_backend() == LEGACY_JSON_BACKEND:
        yield None
        return
    stack = _normalized_guard_stack()
    for active in reversed(stack):
        if active["project"] == canonical:
            # Only synchronous internal calls can inherit this thread-local
            # capability. CLI/API payloads cannot manufacture it.
            yield active["repo_id"]
            return
    with _open_normalized_action_store() as store:
        _require_normalized_bootstrap_before_mutation(store)
        repo_id = resolve_or_install_repository_for_action(store, canonical)
        lifecycle = RepositoryLifecycle(
            SQLiteLifecyclePersistence(store),
            (
                CoordinatorHostLifecycleAdapter()
                if action is RepositoryAction.START
                else _GUARD_ONLY_LIFECYCLE_ADAPTER
            ),
        )
        permit = _reserve_normalized_repository_action(
            lifecycle,
            store,
            repo_id=repo_id,
            action=action,
            agent=agent,
        )
        try:
            _mark_first_normalized_action(store)
            if action is RepositoryAction.START:
                # Reinstallation only clears the normalized fence. The first
                # explicit start restores the exact captured native policies
                # under this permit, before any compatibility or host start
                # path is entered. This preflight is deliberately not a
                # cross-host-work state lock; a later observation remains the
                # durable detector for the residual post-preflight race.
                lifecycle.restore_startup_policies_for_start(permit)
        except BaseException as primary_error:
            try:
                lifecycle.release_action_permit(permit, outcome="failed")
            except BaseException as release_error:
                raise RepositoryActionGuardReleaseError(
                    primary_error, release_error
                ) from primary_error
            raise
        active = {"project": canonical, "repo_id": repo_id, "permit_id": permit.permit_id}
        stack.append(active)
        try:
            yield repo_id
        except BaseException as primary_error:
            try:
                lifecycle.release_action_permit(permit, outcome="failed")
            except BaseException as release_error:
                raise RepositoryActionGuardReleaseError(
                    primary_error, release_error
                ) from primary_error
            raise
        else:
            lifecycle.release_action_permit(permit, outcome="succeeded")
        finally:
            if stack and stack[-1] is active:
                stack.pop()
            else:
                with contextlib.suppress(ValueError):
                    stack.remove(active)


def normalized_guarded_action(
    action: RepositoryAction, command: str
) -> Any:
    """Decorate one options-dict public mutation before its first side effect."""

    def decorate(function: Any) -> Any:
        @functools.wraps(function)
        def guarded(options: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            agent, project = require_identity(options, command)
            with normalized_repository_action_guard(
                project=project, agent=agent, action=action
            ):
                return function(options, *args, **kwargs)

        return guarded

    return decorate


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
    resolved_port = int(port) if port is not None else None
    assignments = state.setdefault("port_assignments", {})
    for key, assignment in list(assignments.items()):
        if name is not None:
            if assignment.get("name") != name or assignment.get("project") != resolved:
                continue
            if resolved_port is not None and int(assignment.get("port") or 0) != resolved_port:
                continue
        else:
            if int(assignment.get("port") or 0) != resolved_port:
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
            if identity.get("ok") is not False and identity.get("observable") is not False:
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


def docker_stats_sample_sort_key(sample: Any) -> tuple[float, str, str]:
    if not isinstance(sample, dict):
        return float("-inf"), "", ""
    try:
        timestamp = float(sample.get("timestamp_ts"))
    except (TypeError, ValueError):
        timestamp = float("-inf")
    return timestamp, str(sample.get("id") or ""), str(sample.get("name") or "")


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
        history.sort(key=docker_stats_sample_sort_key)
        previous = history[-1] if history else None
        sample = attach_docker_rates(sample, previous)
        history.append(sample)
        del history[:-DOCKER_STATS_HISTORY_LIMIT]
        samples.append(sample)

    return {"available": True, "stats": samples}


def docker_ps_inventory(
    *,
    all_containers: bool = True,
    state: dict[str, Any] | None = None,
    stats_history_limit: int = DOCKER_STATS_HISTORY_LIMIT,
) -> dict[str, Any]:
    if not isinstance(stats_history_limit, int) or isinstance(stats_history_limit, bool):
        raise ValueError("Docker stats history limit must be an integer")
    if not 0 <= stats_history_limit <= DOCKER_STATS_HISTORY_LIMIT:
        raise ValueError(
            f"Docker stats history limit must be between 0 and {DOCKER_STATS_HISTORY_LIMIT}"
        )
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
            history = sorted(
                history_by_id.get(container_id, []),
                key=docker_stats_sample_sort_key,
            )
            container["stats_history"] = history[-stats_history_limit:] if stats_history_limit else []
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
        if inspected:
            full_id = str(inspected.get("Id") or "").strip()
            if full_id:
                container["full_id"] = full_id
            state_payload = inspected.get("State") if isinstance(inspected.get("State"), dict) else {}
            health_payload = state_payload.get("Health") if isinstance(state_payload.get("Health"), dict) else {}
            container["container_health"] = health_payload.get("Status")
            host_config = inspected.get("HostConfig") if isinstance(inspected.get("HostConfig"), dict) else {}
            restart = host_config.get("RestartPolicy") if isinstance(host_config.get("RestartPolicy"), dict) else {}
            container["restart_policy"] = restart.get("Name") or "no"
            port_bindings: list[dict[str, Any]] = []
            network = inspected.get("NetworkSettings") if isinstance(inspected.get("NetworkSettings"), dict) else {}
            published = network.get("Ports") if isinstance(network.get("Ports"), dict) else {}
            for destination, bindings in sorted(published.items()):
                raw_port, _separator, protocol = str(destination).partition("/")
                with contextlib.suppress(ValueError):
                    container_port = int(raw_port)
                    if not bindings:
                        port_bindings.append(
                            {
                                "host_address": None,
                                "host_port": None,
                                "container_port": container_port,
                                "protocol": protocol or "tcp",
                            }
                        )
                    for binding in bindings or []:
                        host_port = binding.get("HostPort")
                        port_bindings.append(
                            {
                                "host_address": binding.get("HostIp"),
                                "host_port": int(host_port) if host_port else None,
                                "container_port": container_port,
                                "protocol": protocol or "tcp",
                            }
                        )
            container["port_bindings"] = port_bindings
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


def discover_postgres_databases(container: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    """Read a running container's real PostgreSQL catalog once per observation."""

    if not str(container.get("status") or "").lower().startswith("up"):
        return [], "container is not running"
    target = str(container.get("full_id") or container.get("id") or container.get("name") or "")
    if not target:
        return [], "container identity is unavailable"
    identity = docker_available_command(
        [
            "exec",
            target,
            "sh",
            "-c",
            "printf '%s\\n%s\\n' \"${POSTGRES_USER:-postgres}\" \"${POSTGRES_DB:-postgres}\"",
        ]
    )
    if not identity.get("ok"):
        return [], str(identity.get("stderr") or identity.get("error") or "PostgreSQL identity query failed").strip()
    lines = str(identity.get("stdout") or "").splitlines()
    user = lines[0].strip() if lines and lines[0].strip() else "postgres"
    database = lines[1].strip() if len(lines) > 1 and lines[1].strip() else "postgres"
    query = (
        "SELECT datname, pg_database_size(datname) FROM pg_database "
        "WHERE datallowconn AND NOT datistemplate ORDER BY datname"
    )
    catalog = docker_available_command(
        ["exec", target, "psql", "-U", user, "-d", database, "-At", "-F", "\t", "-c", query]
    )
    if not catalog.get("ok"):
        return [], str(catalog.get("stderr") or catalog.get("error") or "PostgreSQL catalog query failed").strip()
    databases: list[dict[str, Any]] = []
    for line in str(catalog.get("stdout") or "").splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0]:
            return [], f"unexpected PostgreSQL catalog row: {line}"
        try:
            size_bytes = int(fields[1])
        except ValueError:
            return [], f"unexpected PostgreSQL database size: {line}"
        databases.append({"name": fields[0], "size_bytes": size_bytes})
    return databases, None


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


def build_inventory(
    state: dict[str, Any],
    *,
    project: str | None = None,
    include_docker: bool = True,
    backup_dirs: list[str] | None = None,
    stats_history_limit: int = DOCKER_STATS_HISTORY_LIMIT,
    include_process_usage: bool = True,
    include_backups: bool = True,
) -> dict[str, Any]:
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
    process_table = annotate_server_process_usage(servers) if include_process_usage else {}
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
    docker = (
        docker_ps_inventory(state=state, stats_history_limit=stats_history_limit)
        if include_docker
        else {"available": None, "containers": [], "postgres": []}
    )
    project_usage = (
        build_project_usage(servers, docker, process_table, state)
        if include_process_usage
        else []
    )
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
        "backups": backup_inventory(resolved_project, backup_dirs) if include_backups else [],
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
        operation["result"]["_legacy_reservation"].update(
            {"lease_source": "manual", "lease_port": port}
        )
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


def _coordinated_start_server_local(options: dict[str, Any]) -> dict[str, Any]:
    """Start a process with only reservation/commit phases under the state lock."""

    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_start_server_normalized(options)
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


@normalized_guarded_action(RepositoryAction.START, "server start")
def coordinated_start_server(options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "server start")
    broker_context = configured_broker_context(project)
    if broker_context is None:
        return _coordinated_start_server_local(options)
    profile, repository = broker_context
    name = str(options.get("name") or "").strip()
    if not name:
        raise ValueError("server start requires --name")

    if options.get("lease_id"):
        link = broker_lease_link_for_local(str(options["lease_id"]))
        if link is None:
            raise BrokerProfileError(
                "a host broker is configured, but the supplied local lease has no exact broker linkage"
            )
        if link.repo_id != repository.repo_id or link.server_definition_id != repository.server_id(name):
            raise BrokerProfileError("the supplied broker lease belongs to another enrolled server")
        result = _coordinated_start_server_local(options)
        return {
            **result,
            "broker": {
                "lease_id": link.broker_resource_id,
                "link_id": link.link_id,
                "status": link.status,
            },
        }

    # Do not allocate a second global lease when this exact process is already
    # healthy. The local implementation repeats the identity check before it
    # returns, so a race remains fail-safe.
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            _existing_id, existing = find_server(state, project=project, name=name)
            existing_snapshot = copy.deepcopy(existing) if existing else None
            _assignment_key, assignment = find_port_assignment(
                state, project=project, name=name
            )
    else:
        with AccountStore.open_default(coordinator_home()) as store:
            servers = NormalizedServerLifecycle(store)
            try:
                existing_snapshot = servers.server(
                    canonical_project=project, name=name
                )
            except KeyError:
                existing_snapshot = None
            assignment = next(
                (
                    item
                    for item in NormalizedPortLifecycle(store).list_assignments(
                        canonical_project=project, active_only=True
                    )
                    if str(item["name"]) == name
                ),
                None,
            )
    if existing_snapshot:
        existing_health = server_health(existing_snapshot)
        require_listener_identity_observable(
            existing_health, action="start", server=existing_snapshot
        )
        if existing_health.get("ok"):
            return _coordinated_start_server_local(options)

    requested_port = options.get("preferred")
    if requested_port is None and assignment is not None:
        requested_port = int(assignment["port"])
    link, broker_result = acquire_broker_lease_link(
        profile=profile,
        repository=repository,
        server_name=name,
        requested_port=(None if requested_port is None else int(requested_port)),
        ttl_seconds=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
    )
    prepared = dict(options)
    prepared["range"] = f"{link.port}-{link.port}"
    prepared["preferred"] = link.port
    try:
        result = _coordinated_start_server_local(prepared)
        local_lease_id = str(result.get("lease_id") or "")
        if not local_lease_id:
            raise RuntimeError("broker-backed server start returned no local lease identity")
        bound = bind_broker_lease_link(link.link_id, local_lease_id)
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                local = state.get("leases", {}).get(local_lease_id)
                current = state.get("servers", {}).get(result.get("id"))
                if local is None or current is None:
                    raise RuntimeError(
                        "broker-backed server committed without its local lease/server record"
                    )
                local["broker_lease_id"] = bound.broker_resource_id
                local["broker_link_id"] = bound.link_id
                local["broker_operation_id"] = bound.broker_operation_id
                current["broker_lease_id"] = bound.broker_resource_id
                current["broker_link_id"] = bound.link_id
                result = copy.deepcopy(current)
        else:
            with AccountStore.open_default(coordinator_home()) as store:
                local = next(
                    (
                        item
                        for item in NormalizedPortLifecycle(store).list_leases(
                            canonical_project=project, active_only=True
                        )
                        if str(item["id"]) == local_lease_id
                    ),
                    None,
                )
                if local is None:
                    raise RuntimeError(
                        "broker-backed server committed without its local lease record"
                    )
                result = normalized_public_server(
                    NormalizedServerLifecycle(store).server(
                        server_definition_id=str(result["id"])
                    )
                )
    except BaseException as local_error:
        rollback_errors: list[str] = []
        if "result" in locals() and result.get("id"):
            try:
                coordinated_stop_server(
                    {
                        "server_id": result["id"],
                        "agent": agent,
                        "project": project,
                        "name": name,
                        "release_port": True,
                        "reason": "Rolled back after broker-link commit failure",
                    }
                )
            except BaseException as stop_error:
                rollback_errors.append(
                    f"exact local stop failed: {type(stop_error).__name__}: {stop_error}"
                )
                payload = coordinator_exception_payload(stop_error)
                with AccountStore.open_default(coordinator_home()) as store:
                    BrokerLinkStore(store).fail_lease_release(
                        link.link_id,
                        operation_id=str(uuid.uuid4()),
                        error_code=str(payload.get("code") or "local_stop_failed"),
                        error_message=str(payload.get("error") or stop_error),
                        rollback=True,
                    )
                raise StructuredCoordinatorError(
                    "broker-backed server started but local linkage and exact rollback stop failed",
                    {
                        "code": "broker_server_start_outcome_uncertain",
                        "classification": "reconciliation_required",
                        "broker_lease_id": link.broker_resource_id,
                        "local_error": f"{type(local_error).__name__}: {local_error}",
                        "rollback_errors": rollback_errors,
                        "action_required": "Do not release or reuse this port until the exact process and broker lease are reconciled.",
                    },
                ) from local_error
        try:
            release_broker_lease_link(link, rollback=True)
        except BaseException as rollback_error:
            rollback_errors.append(
                f"{type(rollback_error).__name__}: {rollback_error}"
            )
        if rollback_errors:
            raise StructuredCoordinatorError(
                "broker-backed server start failed and lease rollback requires reconciliation",
                {
                    "code": "broker_server_start_rollback_failed",
                    "classification": "reconciliation_required",
                    "broker_lease_id": link.broker_resource_id,
                    "local_error": f"{type(local_error).__name__}: {local_error}",
                    "rollback_errors": rollback_errors,
                },
            ) from local_error
        raise
    return {
        **result,
        "broker": {
            "lease_id": bound.broker_resource_id,
            "link_id": bound.link_id,
            "operation_id": bound.broker_operation_id,
            "status": bound.status,
            "expires_at": broker_result.get("expires_at"),
        },
    }


def coordinated_stop_server(options: dict[str, Any]) -> dict[str, Any]:
    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_stop_server_normalized(options)
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
    requested_release = bool(prepared.get("release_port", True))
    broker_link = (
        broker_lease_link_for_local(str(observed_snapshot.get("lease_id")))
        if requested_release and observed_snapshot.get("lease_id")
        else None
    )
    if broker_link is not None:
        # Exact process stop is corrective and happens first. The local lease
        # stays active until the host-global broker confirms release.
        prepared["release_port"] = False

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
        committed = copy.deepcopy(current)

    if broker_link is None:
        return committed
    try:
        broker_result = release_broker_lease_link(broker_link, rollback=False)
    except BaseException as release_error:
        with locked_state() as state:
            current = state.get("servers", {}).get(server_id)
            if current is not None:
                current["reconciliation_required"] = True
                current["broker_release_error"] = coordinator_exception_payload(
                    release_error
                )
                current["updated_at"] = iso_timestamp()
                committed = copy.deepcopy(current)
        raise StructuredCoordinatorError(
            "server stopped, but its host-global broker lease could not be released",
            {
                "code": "broker_lease_release_pending",
                "classification": "reconciliation_required",
                "broker_lease_id": broker_link.broker_resource_id,
                "server": committed,
                "release_error": coordinator_exception_payload(release_error),
                "action_required": "Keep the local lease reserved and retry the exact broker release through the Coordinator skill.",
            },
        ) from release_error
    try:
        with locked_state() as state:
            local_lease_id = str(observed_snapshot.get("lease_id") or "")
            if local_lease_id in state.get("leases", {}):
                release_port(state, lease_id=local_lease_id)
            current = state.get("servers", {}).get(server_id)
            if current is not None:
                current["broker_lease_id"] = broker_link.broker_resource_id
                current["broker_lease_status"] = "released"
                current["reconciliation_required"] = False
                current.pop("broker_release_error", None)
                current["updated_at"] = iso_timestamp()
                committed = copy.deepcopy(current)
    except BaseException as local_release_error:
        raise StructuredCoordinatorError(
            "broker lease was released, but the local stopped-server lease record needs reconciliation",
            {
                "code": "local_lease_release_reconciliation_required",
                "classification": "reconciliation_required",
                "broker_lease_id": broker_link.broker_resource_id,
                "broker_result": broker_result,
                "local_error": f"{type(local_release_error).__name__}: {local_release_error}",
            },
        ) from local_release_error
    return {
        **committed,
        "broker": {
            "lease_id": broker_link.broker_resource_id,
            "status": "released",
            "result": broker_result,
        },
    }


@normalized_guarded_action(RepositoryAction.START, "server restart")
def coordinated_restart_server(options: dict[str, Any]) -> dict[str, Any]:
    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_restart_server_normalized(options)
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

    if state_backend() != LEGACY_JSON_BACKEND:
        return normalized_control_snapshot()
    with locked_state() as state:
        return copy.deepcopy(state)


def normalized_control_snapshot_from_store(store: AccountStore) -> dict[str, Any]:
    """Build the v1-shaped read model solely from normalized SQL tables."""

    graph = store.inventory_v2()
    compatibility = graph["v1_compatibility"]
    operations = {}
    with store.read_transaction() as connection:
        for row in connection.execute(
            """
            SELECT o.*, r.canonical_root FROM operations o
            LEFT JOIN repositories r USING(repo_id)
            ORDER BY o.created_at, o.operation_id
            """
        ):
            operations[str(row["operation_id"])] = {
                "id": row["operation_id"],
                "project": row["canonical_root"],
                "kind": row["kind"],
                "status": row["status"],
                "phase": row["phase"],
                "agent": row["actor"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
    return {
        "version": VERSION,
        "revision": int(graph["store"]["state_revision"]),
        "created_at": None,
        "updated_at": graph["store"]["updated_at"],
        "servers": {
            str(item["id"]): copy.deepcopy(item)
            for item in compatibility["servers"]
        },
        "leases": {
            str(item["id"]): copy.deepcopy(item)
            for item in compatibility["leases"]
        },
        "port_assignments": {
            f"{item['project']}::{item['name']}": copy.deepcopy(item)
            for item in compatibility["port_assignments"]
        },
        "operations": operations,
        "history": copy.deepcopy(compatibility["recent_events"]),
        "docker": copy.deepcopy(compatibility["docker"]),
    }


def normalized_control_snapshot() -> dict[str, Any]:
    """Return the direct normalized control read model."""

    with AccountStore.open_default(coordinator_home()) as store:
        return normalized_control_snapshot_from_store(store)


def normalized_public_server(server: dict[str, Any]) -> dict[str, Any]:
    """Strip private CAS fields from one normalized lifecycle result."""

    return {
        key: copy.deepcopy(value)
        for key, value in server.items()
        if not str(key).startswith("_")
    }


def normalized_process_instance_evidence(
    *, pid: int, project: str, host: str, port: int
) -> tuple[str | None, str]:
    """Bind retained PID metadata to a stable host-observed process instance."""

    start_time: str | None = None
    if sys.platform.startswith("linux"):
        try:
            stat_text = (Path("/proc") / str(int(pid)) / "stat").read_text(
                encoding="utf-8"
            )
            _prefix, separator, suffix = stat_text.rpartition(") ")
            fields = suffix.split() if separator else []
            # /proc/PID/stat field 22; suffix begins at field 3.
            if len(fields) > 19:
                start_time = fields[19]
        except (OSError, RuntimeError, ValueError):
            start_time = None
    else:
        try:
            completed = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(int(pid))],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                start_time = completed.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            start_time = None
    cwd_observation = process_cwd_observation(int(pid))
    evidence = {
        "pid": int(pid),
        "process_start_time": start_time,
        "project": canonical_project(project),
        "cwd": cwd_observation.get("cwd"),
        "cwd_observable": cwd_observation.get("observable"),
        "host": host,
        "port": int(port),
    }
    return start_time, "sha256:" + fingerprint(evidence)


def _normalized_start_candidates(
    *,
    port_start: int,
    port_end: int,
    preferred: int | None,
) -> list[int]:
    candidates: list[int] = []
    if preferred is not None:
        candidates.append(int(preferred))
    candidates.extend(
        port
        for port in range(int(port_start), int(port_end) + 1)
        if port != preferred
    )
    return candidates


def _coordinated_start_server_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    prepared = dict(options)
    agent, project = require_identity(prepared, "server start")
    name = str(prepared.get("name") or "").strip()
    if not name:
        raise ValueError("server start requires --name")
    if prepared.get("lease_id") and (
        prepared.get("argv") is None
        or prepared.get("cmd")
        or prepared.get("command")
    ):
        raise ValueError(
            "server start --lease-id requires structured --argv and does not accept --cmd"
        )
    argv_template = command_argv(prepared)
    cwd = str(Path(prepared.get("cwd") or project).expanduser().resolve())
    if not Path(cwd).is_dir():
        raise FileNotFoundError(
            f"server cwd does not exist or is not a directory: {cwd}"
        )
    host = str(prepared.get("host") or "127.0.0.1")

    with AccountStore.open_default(coordinator_home()) as store:
        servers = NormalizedServerLifecycle(store)
        try:
            existing = servers.server(canonical_project=project, name=name)
        except KeyError:
            existing = None
    if existing is not None:
        existing_health = server_health(existing)
        require_listener_identity_observable(
            existing_health, action="start", server=existing
        )
        if existing_health.get("ok") is True:
            with AccountStore.open_default(coordinator_home()) as store:
                refreshed = NormalizedServerLifecycle(store).commit_status(
                    server_definition_id=str(existing["id"]),
                    expected_definition_generation=int(existing["generation"]),
                    expected_observation_fingerprint=existing.get(
                        "_observation_fingerprint"
                    ),
                    health=existing_health,
                    stopped_reason=None,
                )
            return normalized_public_server(refreshed)
        if existing.get("status") != "stopped" or pid_alive(
            int(existing.get("pid") or 0)
        ):
            coordinated_stop_server(
                {
                    "server_id": existing["id"],
                    "agent": agent,
                    "project": project,
                    "name": name,
                    "release_port": True,
                    "reason": "Replaced by coordinator start",
                }
            )

    explicit_range = prepared.get("range") is not None
    preferred = (
        None if prepared.get("preferred") is None else int(prepared["preferred"])
    )
    manual_lease_id = str(prepared.get("lease_id") or "") or None
    with AccountStore.open_default(coordinator_home()) as store:
        ports = NormalizedPortLifecycle(store)
        assignments = ports.list_assignments(
            canonical_project=project, active_only=True
        )
        assignment = next(
            (item for item in assignments if str(item["name"]) == name), None
        )
        if manual_lease_id:
            lease = next(
                (
                    item
                    for item in ports.list_leases(
                        canonical_project=project, active_only=True
                    )
                    if str(item["id"]) == manual_lease_id
                ),
                None,
            )
            if lease is None:
                raise KeyError(f"manual lease not found: {manual_lease_id}")
            port_start = port_end = int(lease["port"])
        elif assignment is not None and not explicit_range and preferred is None:
            port_start = port_end = int(assignment["port"])
            preferred = int(assignment["port"])
        else:
            port_start, port_end = parse_range(
                str(prepared.get("range") or DEFAULT_RANGE)
            )
    candidates = _normalized_start_candidates(
        port_start=port_start,
        port_end=port_end,
        preferred=preferred,
    )
    observed_available = [
        candidate for candidate in candidates if port_available(candidate, host)
    ]
    if assignment is not None and not explicit_range and prepared.get("preferred") is None:
        assigned_port = int(assignment["port"])
        if assigned_port not in observed_available:
            raise RuntimeError(
                f"server '{name}' is pinned to port {assigned_port}, but that port is occupied; "
                "free the port, or explicitly choose a range/preferred port to repin"
            )
    health_url_template = prepared.get("health_url")
    environment_template = normalize_env(prepared.get("env") or [])
    request = ServerStartRequest(
        agent=agent,
        canonical_project=project,
        name=name,
        cwd=cwd,
        argv=tuple(argv_template),
        environment=environment_template,
        host=host,
        health_url=(str(health_url_template) if health_url_template else None),
        role=prepared.get("role"),
        port_start=port_start,
        port_end=port_end,
        preferred=preferred,
        ttl_seconds=int(prepared.get("ttl") or DEFAULT_TTL_SECONDS),
        explicit_range=explicit_range,
        manual_lease_id=manual_lease_id,
    )
    with AccountStore.open_default(coordinator_home()) as store:
        reservation = NormalizedServerLifecycle(store).reserve_start(
            request,
            observed_available_ports=observed_available,
        )
    reserved_port = int(reservation["port"])
    argv = format_argv(argv_template, port=reserved_port, host=host)
    environment = dict(environment_template)
    environment.setdefault("PORT", str(reserved_port))
    environment.setdefault("HOST", host)
    health_url = (
        format_command(str(health_url_template), port=reserved_port, host=host)
        if health_url_template
        else None
    )
    try:
        with AccountStore.open_default(coordinator_home()) as store:
            reservation = NormalizedServerLifecycle(
                store
            ).finalize_reserved_start_definition(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                definition_generation=int(reservation["_definition_generation"]),
                argv=tuple(argv),
                environment=environment,
                health_url=health_url,
            )
            reservation["_manual_lease"] = bool(manual_lease_id)
    except BaseException as definition_error:
        with AccountStore.open_default(coordinator_home()) as store:
            NormalizedServerLifecycle(store).fail_start(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                error=f"reserved argv commit failed: {definition_error}",
                process_launched=False,
                process_active=False,
                manual_lease=bool(manual_lease_id),
            )
        raise
    launch = LaunchSpec(tuple(argv), cwd, environment, agent, project, "server_start")
    pid: int | None = None
    log_path: str | None = None
    try:
        pid, log_path = start_process(
            launch=launch, server_id=str(reservation["id"])
        )
    except BaseException as launch_error:
        with AccountStore.open_default(coordinator_home()) as store:
            NormalizedServerLifecycle(store).fail_start(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                error=f"Process launch failed: {launch_error}",
                process_launched=False,
                process_active=False,
                manual_lease=bool(reservation.get("_manual_lease")),
                log_path=str(logs_dir() / f"{reservation['id']}.log"),
            )
        raise

    process_start_time, process_fingerprint = normalized_process_instance_evidence(
        pid=int(pid), project=project, host=host, port=reserved_port
    )
    try:
        with AccountStore.open_default(coordinator_home()) as store:
            launched = NormalizedServerLifecycle(store).mark_start_launched(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                definition_generation=int(reservation["_definition_generation"]),
                pid=int(pid),
                log_path=str(log_path),
                process_start_time=process_start_time,
                process_fingerprint=process_fingerprint,
            )
    except BaseException as commit_error:
        cleanup_errors: list[str] = []
        try:
            stop_pid(int(pid))
        except BaseException as cleanup_error:
            cleanup_errors.append(
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        process_active = pid_alive(int(pid)) or not port_available(reserved_port, host)
        with AccountStore.open_default(coordinator_home()) as store:
            failed = NormalizedServerLifecycle(store).fail_start(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                error=f"server launch commit failed: {commit_error}",
                process_launched=True,
                process_active=process_active,
                manual_lease=bool(reservation.get("_manual_lease")),
                pid=int(pid),
                log_path=str(log_path),
                cleanup_errors=cleanup_errors,
            )
        if cleanup_errors or process_active:
            raise StructuredCoordinatorError(
                "server launch committed on the host but cleanup is uncertain",
                {
                    "code": "server_start_cleanup_uncertain",
                    "server": normalized_public_server(failed),
                    "primary_error": f"{type(commit_error).__name__}: {commit_error}",
                    "cleanup_errors": cleanup_errors,
                },
            ) from commit_error
        raise

    launched["created_ts"] = now()
    health = wait_for_health(
        launched, float(prepared.get("health_timeout") or 10)
    )
    health_unobservable = listener_identity_unobservable(health)
    manual_health_failure = bool(manual_lease_id and health.get("ok") is not True)
    if health_unobservable or manual_health_failure:
        cleanup_errors = []
        try:
            stop_pid(int(pid))
        except BaseException as cleanup_error:
            cleanup_errors.append(
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        process_active = pid_alive(int(pid)) or not port_available(reserved_port, host)
        reason = (
            "listener identity is unobservable after server launch"
            if health_unobservable
            else f"server failed health check using manual lease {manual_lease_id}"
        )
        with AccountStore.open_default(coordinator_home()) as store:
            failed = NormalizedServerLifecycle(store).fail_start(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(reservation["id"]),
                error=reason,
                process_launched=True,
                process_active=process_active,
                manual_lease=bool(manual_lease_id),
                pid=int(pid),
                log_path=str(log_path),
                health=health,
                cleanup_errors=cleanup_errors,
            )
        if health_unobservable:
            raise ListenerIdentityUnobservable(
                f"refusing to complete start for {name}: {reason}; "
                f"cleanup reconciliation_required={bool(process_active or cleanup_errors)}"
            )
        raise StructuredCoordinatorError(
            reason,
            {
                "code": "manual_lease_server_health_failed",
                "server": normalized_public_server(failed),
                "cleanup_errors": cleanup_errors,
            },
        )
    with AccountStore.open_default(coordinator_home()) as store:
        committed = NormalizedServerLifecycle(store).commit_start_health(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(reservation["id"]),
            definition_generation=int(reservation["_definition_generation"]),
            health=health,
        )
    return normalized_public_server(committed)


def _coordinated_register_server_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    prepared = dict(options)
    agent, project = require_identity(prepared, "server register")
    name = str(prepared.get("name") or "").strip()
    if not name:
        raise ValueError("server register requires --name")
    host, port, url = parse_server_endpoint(prepared)
    cwd = str(Path(prepared.get("cwd") or project).expanduser().resolve())
    if not Path(cwd).is_dir():
        raise FileNotFoundError(
            f"server cwd does not exist or is not a directory: {cwd}"
        )
    command_template = prepared.get("cmd") or prepared.get("command")
    argv_template = (
        command_argv(prepared)
        if command_template or prepared.get("argv") is not None
        else []
    )
    argv = tuple(format_argv(argv_template, port=port, host=host))
    environment = normalize_env(prepared.get("env") or [])
    health_url_template = prepared.get("health_url") or url
    health_url = (
        format_command(str(health_url_template), port=port, host=host)
        if health_url_template
        else None
    )
    # Registration host proof happens before the server-specific operation is
    # written. A caller-supplied live PID is never accepted without exact cwd
    # and LISTEN ownership evidence.
    pid, registration_identity = resolve_registration_pid(
        prepared, host=host, port=port, project=project
    )
    candidate = {
        "id": "registration-preflight",
        "name": name,
        "project": project,
        "cwd": cwd,
        "pid": int(pid) if pid else None,
        "host": host,
        "port": port,
        "url": url,
        "health_url": health_url,
        "registration_identity": registration_identity,
        "created_ts": now(),
    }
    health = wait_for_health(
        candidate, float(prepared.get("health_timeout") or 3)
    )
    require_listener_identity_observable(
        health, action="register", server=candidate
    )
    process_start_time = None
    process_fingerprint = None
    if pid:
        # Re-run the exact listener proof after health probing so the retained
        # PID cannot switch identity between preflight and durable commit.
        registration_identity = registration_pid_identity(
            pid=int(pid), host=host, port=port, project=project
        )
        process_start_time, process_fingerprint = normalized_process_instance_evidence(
            pid=int(pid), project=project, host=host, port=port
        )
    with AccountStore.open_default(coordinator_home()) as store:
        committed = NormalizedServerLifecycle(store).commit_registration(
            ServerRegistrationRequest(
                agent=agent,
                canonical_project=project,
                name=name,
                cwd=cwd,
                argv=argv,
                environment=environment,
                host=host,
                port=port,
                health_url=health_url,
                role=prepared.get("role"),
                pid=int(pid) if pid else None,
                process_start_time=process_start_time,
                process_fingerprint=process_fingerprint,
                health=health,
                ttl_seconds=int(prepared.get("ttl") or DEFAULT_TTL_SECONDS),
                log_path=None,
            )
        )
    result = normalized_public_server(committed)
    if registration_identity is not None:
        result["registration_identity"] = registration_identity
    return result


def _normalized_server_from_options(options: dict[str, Any]) -> dict[str, Any]:
    project = (
        canonical_project(str(options["project"]))
        if options.get("project")
        else None
    )
    with AccountStore.open_default(coordinator_home()) as store:
        return NormalizedServerLifecycle(store).server(
            canonical_project=project,
            name=(str(options["name"]) if options.get("name") else None),
            server_definition_id=(
                str(options["server_id"]) if options.get("server_id") else None
            ),
        )


def _coordinated_status_server_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    # A concurrent explicit host observation may commit the same server after
    # this status call samples it. Re-read and re-observe a bounded number of
    # times instead of surfacing that ordinary optimistic-CAS race to either
    # Codex app instance. Every retry uses a fresh exact identity snapshot.
    for attempt in range(3):
        snapshot = _normalized_server_from_options(options)
        health = server_health(snapshot, attempts=HEALTH_RETRY_ATTEMPTS)
        reason = stop_reason_from_health(snapshot, health)
        try:
            with AccountStore.open_default(coordinator_home()) as store:
                committed = NormalizedServerLifecycle(store).commit_status(
                    server_definition_id=str(snapshot["id"]),
                    expected_definition_generation=int(snapshot["generation"]),
                    expected_observation_fingerprint=snapshot.get(
                        "_observation_fingerprint"
                    ),
                    health=health,
                    stopped_reason=reason,
                )
            return normalized_public_server(committed)
        except NormalizedLifecycleConflict:
            if attempt == 2:
                raise
    raise AssertionError("bounded normalized status retry did not return or raise")


def _coordinated_server_logs_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    server = _normalized_server_from_options(options)
    tail = int(options.get("tail") or 200)
    log_path = Path(str(server.get("log_path") or ""))
    text = tail_text(log_path, tail) if server.get("log_path") else ""
    return {
        "server": {
            key: server.get(key)
            for key in (
                "id",
                "name",
                "project",
                "status",
                "url",
                "port",
                "stopped_at",
                "stopped_reason",
                "log_path",
            )
        },
        "text": text,
        "tail": tail,
    }


def _coordinated_stop_server_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    prepared = dict(options)
    agent = str(prepared.get("agent") or "").strip()
    if not agent:
        raise ValueError(
            "server stop requires --agent so the coordinator can attribute the action"
        )
    snapshot = _normalized_server_from_options(prepared)
    project = canonical_project(
        str(prepared.get("project") or snapshot.get("project") or "")
    )
    if canonical_project(str(snapshot.get("project") or "")) != project:
        raise ValueError(
            "server stop project does not match the registered server project"
        )
    prime_git_head_identity(project)
    health = server_health(snapshot)
    require_listener_identity_observable(
        health, action="stop", server=snapshot
    )
    requested_release = bool(prepared.get("release_port", True))
    broker_link = (
        broker_lease_link_for_local(str(snapshot.get("lease_id")))
        if requested_release and snapshot.get("lease_id")
        else None
    )
    with AccountStore.open_default(coordinator_home()) as store:
        reservation = NormalizedServerLifecycle(store).reserve_stop(
            agent=agent,
            server_definition_id=str(snapshot["id"]),
            expected_definition_generation=int(snapshot["generation"]),
            expected_observation_fingerprint=snapshot.get(
                "_observation_fingerprint"
            ),
        )
    identity_wrong = (health.get("identity") or {}).get("ok") is False
    try:
        if not identity_wrong and snapshot.get("pid"):
            stop_pid(int(snapshot["pid"]))
        final_health = server_health(snapshot)
        if snapshot.get("pid") and not identity_wrong and final_health.get(
            "pid_alive"
        ) is not False:
            raise RuntimeError(
                f"server process {snapshot['pid']} did not reach a proved stopped boundary"
            )
        if listener_identity_unobservable(final_health):
            raise ListenerIdentityUnobservable(
                "listener identity became unobservable while proving server stop"
            )
    except BaseException as stop_error:
        cleanup_errors: list[str] = []
        try:
            still_alive = bool(
                snapshot.get("pid") and pid_alive(int(snapshot["pid"]))
            )
        except BaseException as observation_error:
            still_alive = True
            cleanup_errors.append(
                f"{type(observation_error).__name__}: {observation_error}"
            )
        with AccountStore.open_default(coordinator_home()) as store:
            failed = NormalizedServerLifecycle(store).fail_stop(
                operation_id=str(reservation["operation_id"]),
                server_definition_id=str(snapshot["id"]),
                error=f"{type(stop_error).__name__}: {stop_error}",
                cleanup_errors=cleanup_errors,
            )
        raise StructuredCoordinatorError(
            "server stop outcome is uncertain",
            {
                "code": "server_stop_outcome_uncertain",
                "server": normalized_public_server(failed),
                "process_still_alive": still_alive,
                "primary_error": f"{type(stop_error).__name__}: {stop_error}",
                "cleanup_errors": cleanup_errors,
            },
        ) from stop_error
    reason = (
        stop_reason_from_health(snapshot, health)
        if identity_wrong
        else str(prepared.get("reason") or "Stopped by coordinator")
    )
    final_identity_wrong = (final_health.get("identity") or {}).get("ok") is False
    with AccountStore.open_default(coordinator_home()) as store:
        committed = NormalizedServerLifecycle(store).commit_stop(
            operation_id=str(reservation["operation_id"]),
            server_definition_id=str(snapshot["id"]),
            agent=agent,
            reason=reason,
            release_port=requested_release and broker_link is None,
            stale_lease=identity_wrong or final_identity_wrong,
            final_health=final_health,
        )
    if broker_link is None:
        return normalized_public_server(committed)
    try:
        broker_result = release_broker_lease_link(broker_link, rollback=False)
    except BaseException as release_error:
        raise StructuredCoordinatorError(
            "server stopped, but its host-global broker lease could not be released",
            {
                "code": "broker_lease_release_pending",
                "classification": "reconciliation_required",
                "broker_lease_id": broker_link.broker_resource_id,
                "server": normalized_public_server(committed),
                "release_error": coordinator_exception_payload(release_error),
                "action_required": (
                    "Keep the local lease reserved and retry the exact broker "
                    "release through the Coordinator skill."
                ),
            },
        ) from release_error
    try:
        if snapshot.get("lease_id"):
            with AccountStore.open_default(coordinator_home()) as store:
                NormalizedPortLifecycle(store).release(
                    agent=agent,
                    canonical_project=project,
                    lease_id=str(snapshot["lease_id"]),
                )
                committed = NormalizedServerLifecycle(store).server(
                    server_definition_id=str(snapshot["id"])
                )
    except BaseException as local_release_error:
        raise StructuredCoordinatorError(
            "broker lease was released, but the local stopped-server lease record needs reconciliation",
            {
                "code": "local_lease_release_reconciliation_required",
                "classification": "reconciliation_required",
                "broker_lease_id": broker_link.broker_resource_id,
                "broker_result": broker_result,
                "local_error": (
                    f"{type(local_release_error).__name__}: {local_release_error}"
                ),
            },
        ) from local_release_error
    result = normalized_public_server(committed)
    result["broker"] = {
        "lease_id": broker_link.broker_resource_id,
        "status": "released",
        "result": broker_result,
    }
    return result


def _coordinated_restart_server_normalized(
    options: dict[str, Any]
) -> dict[str, Any]:
    prepared = dict(options)
    agent, project = require_identity(prepared, "server restart")
    prepared["project"] = project
    snapshot = _normalized_server_from_options(prepared)
    if not snapshot.get("argv"):
        raise RuntimeError(
            f"server {snapshot.get('name')} is registered without a command; "
            "missing_command=true"
        )
    health = server_health(snapshot)
    require_listener_identity_observable(
        health, action="restart", server=snapshot
    )
    fixed_port = int(snapshot.get("assigned_port") or snapshot["port"])
    restart_options = {
        "agent": agent,
        "project": project,
        "name": snapshot["name"],
        "cwd": snapshot["cwd"],
        "argv": list(snapshot["argv"]),
        "range": prepared.get("range") or f"{fixed_port}-{fixed_port}",
        "preferred": fixed_port,
        "host": snapshot.get("host") or "127.0.0.1",
        "health_url": snapshot.get("health_url"),
        "health_timeout": prepared.get("health_timeout") or 10,
        "env": [
            f"{key}={value}"
            for key, value in (snapshot.get("env") or {}).items()
            if key not in {"PORT", "HOST"}
        ],
    }
    coordinated_stop_server(
        {
            "server_id": snapshot["id"],
            "agent": agent,
            "project": project,
            "name": snapshot["name"],
            "release_port": True,
            "reason": "Restarted by coordinator",
        }
    )
    return coordinated_start_server(restart_options)


def snapshot_runtime_observation(*, project: str | None = None) -> dict[str, Any]:
    """Reserve a monotonic per-server observation ticket and return its snapshot."""

    if state_backend() != LEGACY_JSON_BACKEND:
        with AccountStore.open_default(coordinator_home()) as store:
            snapshot = normalized_control_snapshot_from_store(store)
            servers = NormalizedServerLifecycle(store).list_servers(
                canonical_project=(
                    canonical_project(project) if project is not None else None
                )
            )
        snapshot["servers"] = {
            str(server["id"]): copy.deepcopy(server) for server in servers
        }
        return snapshot
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
        current.sort(key=docker_stats_sample_sort_key)
        del current[:-DOCKER_STATS_HISTORY_LIMIT]


def persist_normalized_docker_stats(
    store: AccountStore, samples: list[dict[str, Any]]
) -> int:
    """Persist measured Docker telemetry against exact normalized resources."""

    inserted = 0
    with store.immediate_transaction(revision_kind="observation") as connection:
        for sample in samples:
            native_id = str(
                sample.get("container_id") or sample.get("id") or ""
            ).strip()
            sampled_at = str(sample.get("timestamp") or "").strip()
            if not native_id or not sampled_at:
                continue
            matches = list(
                connection.execute(
                    """
                    SELECT docker_resource_id, full_container_id
                    FROM docker_resources
                    WHERE lower(full_container_id) = lower(?)
                       OR lower(full_container_id) LIKE lower(?) || '%'
                    ORDER BY CASE WHEN lower(full_container_id) = lower(?)
                                  THEN 0 ELSE 1 END,
                             docker_resource_id
                    LIMIT 2
                    """,
                    (native_id, native_id, native_id),
                )
            )
            if not matches:
                continue
            exact = [
                row
                for row in matches
                if str(row["full_container_id"]).lower() == native_id.lower()
            ]
            if not exact and len(matches) != 1:
                continue
            resource_id = str((exact or matches)[0]["docker_resource_id"])
            before = connection.total_changes
            connection.execute(
                """
                INSERT OR IGNORE INTO telemetry_samples(
                    sample_id, host_resource_kind, host_resource_id, sampled_at,
                    cpu_percent, memory_bytes, network_rx_bytes, network_tx_bytes,
                    block_read_bytes, block_write_bytes
                ) VALUES (?, 'docker', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    deterministic_id(
                        "telemetry", "docker", resource_id, sampled_at
                    ),
                    resource_id,
                    sampled_at,
                    sample.get("cpu_percent"),
                    sample.get("memory_usage_bytes"),
                    sample.get("network_rx_bytes"),
                    sample.get("network_tx_bytes"),
                    sample.get("block_read_bytes"),
                    sample.get("block_write_bytes"),
                ),
            )
            inserted += int(connection.total_changes > before)
    return inserted


def commit_runtime_observations(baseline: dict[str, Any], observed: dict[str, Any]) -> None:
    """Commit health/stat observations only when the observed server is current.

    Slow process, HTTP, Docker, and filesystem checks run against ``observed``
    after the state lock has been released. This optimistic commit intentionally
    skips a server whose lifecycle generation changed while the checks ran.
    """

    if state_backend() != LEGACY_JSON_BACKEND:
        with AccountStore.open_default(coordinator_home()) as store:
            lifecycle = NormalizedServerLifecycle(store)
            baseline_servers = baseline.get("servers", {})
            for server_id, observed_server in observed.get("servers", {}).items():
                baseline_server = baseline_servers.get(server_id)
                health = observed_server.get("health")
                if not baseline_server or not isinstance(health, dict):
                    continue
                try:
                    lifecycle.commit_status(
                        server_definition_id=str(server_id),
                        expected_definition_generation=int(
                            baseline_server.get("generation") or 0
                        ),
                        expected_observation_fingerprint=baseline_server.get(
                            "_observation_fingerprint"
                        ),
                        health=copy.deepcopy(health),
                        stopped_reason=observed_server.get("stopped_reason"),
                    )
                except NormalizedLifecycleConflict:
                    # The lifecycle changed while slow host observation ran.
                    # Preserve the newer decision and skip this stale sample.
                    continue
            latest_samples: list[dict[str, Any]] = []
            for history in (
                observed.get("docker", {}).get("stats_history", {}) or {}
            ).values():
                if isinstance(history, list) and history:
                    sample = history[-1]
                    if isinstance(sample, dict):
                        latest_samples.append(sample)
            if latest_samples:
                persist_normalized_docker_stats(store, latest_samples)
        return

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
    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_status_server_normalized(options)
    prepared = dict(options)
    if prepared.get("project"):
        prepared["project"] = canonical_project(str(prepared["project"]))
    baseline = snapshot_runtime_observation(project=prepared.get("project"))
    observed = copy.deepcopy(baseline)
    result = copy.deepcopy(status_server(observed, prepared))
    commit_runtime_observations(baseline, observed)
    return result


def coordinated_server_logs(options: dict[str, Any]) -> dict[str, Any]:
    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_server_logs_normalized(options)
    prepared = dict(options)
    if prepared.get("project"):
        prepared["project"] = canonical_project(str(prepared["project"]))
    return server_logs(snapshot_coordinator_state(), prepared)


def _coordinated_register_server_local(options: dict[str, Any]) -> dict[str, Any]:
    """Inspect and health-check an adopted server outside ``state.lock``."""

    if state_backend() != LEGACY_JSON_BACKEND:
        return _coordinated_register_server_normalized(options)
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


@normalized_guarded_action(RepositoryAction.REGISTER, "server register")
def coordinated_register_server(options: dict[str, Any]) -> dict[str, Any]:
    """Adopt a listener through the host broker when cross-UID mode is active."""

    prepared = dict(options)
    agent, project = require_identity(prepared, "server register")
    broker_context = configured_broker_context(project)
    if broker_context is None:
        return _coordinated_register_server_local(prepared)
    profile, repository = broker_context
    name = str(prepared.get("name") or "").strip()
    if not name:
        raise ValueError("server register requires --name")
    _host, port, _url = parse_server_endpoint(prepared)
    link, broker_result = acquire_broker_lease_link(
        profile=profile,
        repository=repository,
        server_name=name,
        requested_port=int(port),
        ttl_seconds=int(prepared.get("ttl") or DEFAULT_TTL_SECONDS),
        adopt_existing_listener=True,
    )
    try:
        result = _coordinated_register_server_local(prepared)
        local_lease_id = str(result.get("lease_id") or "")
        if not local_lease_id:
            raise RuntimeError(
                "broker-verified listener registration produced no local lease identity"
            )
        bound = bind_broker_lease_link(link.link_id, local_lease_id)
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                local = state.get("leases", {}).get(local_lease_id)
                current = state.get("servers", {}).get(result.get("id"))
                if local is None or current is None:
                    raise RuntimeError(
                        "broker-verified registration committed without its exact local records"
                    )
                local["broker_lease_id"] = bound.broker_resource_id
                local["broker_link_id"] = bound.link_id
                local["broker_operation_id"] = bound.broker_operation_id
                current["broker_lease_id"] = bound.broker_resource_id
                current["broker_link_id"] = bound.link_id
                result = copy.deepcopy(current)
        else:
            with AccountStore.open_default(coordinator_home()) as store:
                local = next(
                    (
                        item
                        for item in NormalizedPortLifecycle(store).list_leases(
                            canonical_project=project, active_only=True
                        )
                        if str(item["id"]) == local_lease_id
                    ),
                    None,
                )
                if local is None:
                    raise RuntimeError(
                        "broker-verified registration committed without its exact local lease"
                    )
                result = normalized_public_server(
                    NormalizedServerLifecycle(store).server(
                        server_definition_id=str(result["id"])
                    )
                )
    except BaseException as local_error:
        # The adopted process pre-existed the coordinator call and must never
        # be killed as rollback. If local registration did not commit, release
        # only the broker lease. A committed-but-unlinked registration remains
        # reserved for explicit reconciliation rather than guessing.
        if "result" not in locals() or not result.get("lease_id"):
            try:
                release_broker_lease_link(link, rollback=True)
            except BaseException as rollback_error:
                raise StructuredCoordinatorError(
                    "listener registration failed and broker lease rollback requires reconciliation",
                    {
                        "code": "broker_register_rollback_failed",
                        "classification": "reconciliation_required",
                        "broker_lease_id": link.broker_resource_id,
                        "local_error": f"{type(local_error).__name__}: {local_error}",
                        "rollback_error": f"{type(rollback_error).__name__}: {rollback_error}",
                    },
                ) from local_error
        raise
    return {
        **result,
        "broker": {
            "lease_id": bound.broker_resource_id,
            "link_id": bound.link_id,
            "operation_id": bound.broker_operation_id,
            "status": bound.status,
            "listener_identity": broker_result.get("listener_identity"),
        },
    }


@normalized_guarded_action(RepositoryAction.REGISTER, "docker register")
def coordinated_register_docker_metadata(options: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(options)
    agent, project = require_identity(prepared, "docker register")
    if configured_broker_context(project) is not None:
        raise BrokerProfileError(
            "Docker registration in broker mode is service-owned: run a full service "
            "observation and rerun Coordinator skill enrollment; client-side Docker "
            "inspection and local ownership fallback are disabled"
        )
    container = normalize_container_name(prepared.get("container"))
    if not container:
        raise ValueError("docker register requires --container")
    inspected = None if prepared.get("dry_run") else inspect_docker_container(container)
    if not prepared.get("dry_run") and not inspected:
        raise RuntimeError(
            f"cannot register Docker metadata for {container}: immutable container identity was not verified"
        )
    if state_backend() != LEGACY_JSON_BACKEND:
        if prepared.get("dry_run"):
            return {
                "container": container,
                "project": project,
                "agent": agent,
                "role": prepared.get("role"),
                "metadata_source": "planned_normalized_observation",
                "adopted": True,
                "dry_run": True,
            }
        immutable_id = str((inspected or {}).get("Id") or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}", immutable_id):
            raise RuntimeError(
                f"cannot register Docker metadata for {container}: Docker omitted "
                "the immutable full container id"
            )
        inspected_name = normalize_container_name((inspected or {}).get("Name"))
        compose_project = compose_project_from_inspection(inspected)
        with AccountStore.open_default(coordinator_home()) as store:
            snapshot = normalized_control_snapshot_from_store(store)
            docker = docker_ps_inventory(state=snapshot)
            if docker.get("available") is not True:
                raise RuntimeError(
                    "cannot register Docker metadata without a complete Docker inventory: "
                    f"{docker.get('error') or 'Docker is unavailable'}"
                )
            candidates = [
                item
                for item in docker.get("containers", [])
                if str(item.get("full_id") or "").lower()
                == immutable_id.lower()
            ]
            if len(candidates) != 1:
                raise RuntimeError(
                    "the complete Docker inventory did not contain exactly the "
                    f"inspected container {immutable_id}"
                )
            selected = candidates[0]
            skipped = bool(compose_project and not prepared.get("force"))
            if skipped:
                selected["project"] = compose_project
                selected["metadata_source"] = "docker_labels"
            else:
                selected["project"] = project
                selected["metadata_source"] = "coordinator_sidecar"
                selected["agent"] = agent
                selected["role"] = prepared.get("role")
                selected["adopted"] = True
                selected["agent_metadata"] = agent_metadata(
                    agent=agent,
                    project=project,
                    cwd=prepared.get("cwd"),
                    source="docker_register",
                )
            sample = {"sampled_at": iso_timestamp(), "inventory": {"docker": docker}}
            host_id = ensure_observation_host(store)
            outcome = SingleFlightObserver(store).observe(
                host_id=host_id,
                observer_domain=f"docker-register:{immutable_id.lower()}",
                sampler=lambda: sample,
                commit=lambda connection, snapshot_id, measured: (
                    commit_host_inventory_observation(
                        connection,
                        snapshot_id,
                        measured,
                        host_id=host_id,
                        coordinator_home=str(coordinator_home()),
                    )
                ),
            )
            with store.read_transaction() as connection:
                membership = connection.execute(
                    """
                    SELECT r.canonical_root
                    FROM docker_resources d
                    LEFT JOIN repository_memberships m
                      ON m.resource_kind = 'container'
                     AND m.host_resource_id = d.docker_resource_id
                    LEFT JOIN repositories r USING(repo_id)
                    WHERE lower(d.full_container_id) = lower(?)
                    """,
                    (immutable_id,),
                ).fetchone()
            if not skipped and (
                membership is None
                or canonical_project(str(membership[0] or "")) != project
            ):
                raise RuntimeError(
                    "Docker observation found conflicting repository ownership; "
                    "the container was not reassigned"
                )
        payload = {
            "container": inspected_name or container,
            "id": immutable_id[:12],
            "project": compose_project if skipped else project,
            "agent": agent,
            "role": prepared.get("role"),
            "metadata_source": (
                "docker_labels" if skipped else "coordinator_sidecar"
            ),
            "adopted": not skipped,
            "skipped": skipped,
            "message": (
                "container already has Docker Compose project metadata"
                if skipped
                else "container ownership recorded in normalized inventory"
            ),
            "snapshot_id": outcome.snapshot_id,
            "updated_at": outcome.completed_at,
        }
        return payload
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
    if state_backend() != LEGACY_JSON_BACKEND:
        with AccountStore.open_default(coordinator_home()) as store:
            state = normalized_control_snapshot_from_store(store)
            result = sample_docker_stats(state)
            samples = [
                item
                for item in result.get("stats", [])
                if isinstance(item, dict)
            ]
            if samples:
                result["persisted_samples"] = persist_normalized_docker_stats(
                    store, samples
                )
            else:
                result["persisted_samples"] = 0
            return result
    baseline = snapshot_coordinator_state()
    observed = copy.deepcopy(baseline)
    result = sample_docker_stats(observed)
    with locked_state() as state:
        merge_docker_stats_history(state, observed)
    return result


def coordinated_build_inventory(
    *,
    project: str | None = None,
    include_docker: bool = True,
    backup_dirs: list[str] | None = None,
    stats_history_limit: int = DOCKER_STATS_HISTORY_LIMIT,
) -> dict[str, Any]:
    if state_backend() != LEGACY_JSON_BACKEND:
        return pure_normalized_inventory(
            project=project,
            include_docker=include_docker,
            stats_history_limit=stats_history_limit,
        )
    prepared_project = canonical_project(project) if project else None
    baseline = snapshot_runtime_observation(project=prepared_project)
    observed = copy.deepcopy(baseline)
    result = build_inventory(
        observed,
        project=prepared_project,
        include_docker=include_docker,
        backup_dirs=backup_dirs,
        stats_history_limit=stats_history_limit,
    )
    commit_runtime_observations(baseline, observed)
    return result


def coordinated_build_registration_inventory(
    *, project: str, name: str, port: int
) -> dict[str, Any]:
    """Return one target-scoped no-Docker graph with fresh in-memory proof.

    The systemd readiness loop supplies the exact Console project, server name,
    and port. Only rows that can affect that registration graph are observed;
    unrelated services, process-usage sampling, backup discovery, and Docker
    are deliberately outside this bounded startup path. Derived lifecycle and
    lease changes remain confined to the copied compatibility projection.
    """

    resolved_project = canonical_project(project)
    target_name = str(name).strip()
    target_port = int(port)
    if not Path(project).is_absolute() or not target_name:
        raise ValueError("registration inventory requires an absolute project and server name")
    if not 1 <= target_port <= 65535:
        raise ValueError("registration inventory port must be between 1 and 65535")
    if state_backend() == LEGACY_JSON_BACKEND:
        return coordinated_build_inventory(
            project=resolved_project,
            include_docker=False,
        )

    result = pure_normalized_inventory(include_docker=False)
    source_compatibility = result["v1_compatibility"]
    target_key = f"{resolved_project}::{target_name}"
    relevant_servers = [
        copy.deepcopy(server)
        for server in source_compatibility["servers"]
        if (
            server.get("project") == resolved_project
            and server.get("name") == target_name
        )
        or server.get("port") == target_port
    ]
    relevant_server_ids = {str(server["id"]) for server in relevant_servers}
    relevant_leases = [
        copy.deepcopy(lease)
        for lease in source_compatibility["leases"]
        if lease.get("port") == target_port
        or lease.get("assignment_key") == target_key
        or str(lease.get("server_id")) in relevant_server_ids
    ]
    relevant_assignments = [
        copy.deepcopy(assignment)
        for assignment in source_compatibility["port_assignments"]
        if assignment.get("port") == target_port
        or assignment.get("key") == target_key
    ]
    compatibility = copy.deepcopy(source_compatibility)
    state = {
        "servers": {str(server["id"]): server for server in relevant_servers},
        "leases": {str(lease["id"]): lease for lease in relevant_leases},
        "port_assignments": {
            str(assignment["key"]): assignment for assignment in relevant_assignments
        },
        "history": [],
        "docker": {"available": None, "containers": [], "postgres": []},
    }
    for server in state["servers"].values():
        if server.get("pid") is not None and server.get("status") in {
            "running",
            "starting",
            "unhealthy",
        }:
            # A stale persisted observability bit is not proof that the current
            # capability-matched observer can or cannot inspect this listener.
            server["_require_exact_listener_identity"] = True
    observed = build_inventory(
        state,
        include_docker=False,
        stats_history_limit=0,
        include_process_usage=False,
        include_backups=False,
    )
    for server in observed["servers"]:
        strict_requested = server.pop("_require_exact_listener_identity", False) is True
        health = server.get("health") or {}
        identity = health.get("identity") or {}
        exact_identity = (
            strict_requested
            and server.get("status") != "stopped"
            and health.get("ok") is True
            and identity.get("ok") is True
            and identity.get("pid") == server.get("pid")
            and identity.get("port") == server.get("port")
            and identity.get("host") == str(server.get("host") or "127.0.0.1")
            and identity.get("source") in {"proc_pid_fd", "platform_listener_probe"}
            and isinstance(identity.get("listener_inodes"), list)
        )
        if exact_identity:
            # Publish only the complete identity returned by the strict
            # listener-owner probe. Generic cwd attribution is not registration
            # proof and must remain visibly unverified.
            server["registration_identity"] = copy.deepcopy(identity)

    dead_linked_leases = {
        str(server["lease_id"])
        for server in observed["servers"]
        if server.get("status") == "stopped"
        and (server.get("health") or {}).get("pid_alive") is False
        and server.get("lease_id") is not None
    }
    if dead_linked_leases:
        # A copied active lease linked to a proved-dead stopped server is not a
        # current ownership claim.  Hide it from this readiness observation;
        # the durable SQLite row remains untouched for the registering writer
        # to reconcile transactionally.
        observed["leases"] = [
            lease
            for lease in observed["leases"]
            if str(lease.get("id")) not in dead_linked_leases
        ]

    compatibility_keys = (
        "urls",
        "servers",
        "leases",
        "port_assignments",
        "docker",
        "postgres",
    )
    for key in compatibility_keys:
        compatibility[key] = copy.deepcopy(observed[key])
    result["v1_compatibility"] = compatibility
    # Preserve normalized leases and assignments at the top level.  The other
    # names are non-colliding transitional aliases and should expose the same
    # fresh compatibility view as the nested contract.
    for key in compatibility_keys:
        if key not in {"leases", "port_assignments"}:
            result[key] = copy.deepcopy(compatibility[key])
    return result


def empty_normalized_inventory(*, project: str | None = None) -> dict[str, Any]:
    resolved_project = canonical_project(project) if project else None
    compatibility = {
        "coordinator_home": str(coordinator_home()),
        "state_path": str(coordinator_home() / NORMALIZED_DATABASE_NAME),
        "project": resolved_project,
        "urls": [],
        "servers": [],
        "leases": [],
        "port_assignments": [],
        "recent_events": [],
        "docker": {"available": None, "containers": [], "postgres": []},
        "postgres": [],
        "backups": [],
        "project_usage": [],
    }
    result = {
        "schema_version": NORMALIZED_SCHEMA_VERSION,
        "store": {
            "schema_version": 1,
            "state_revision": 0,
            "observation_revision": 0,
            "authority_mode": "sqlite",
            "migration_state": "empty",
        },
        "repositories": [],
        "coordinator_sources": [],
        "docker_engines": [],
        "memberships": [],
        "resources": {
            "servers": [],
            "docker": [],
            "docker_ports": [],
            "databases": [],
        },
        "leases": [],
        "port_assignments": [],
        "backup_evidence": [],
        "database_backups": [],
        "database_restore_events": [],
        "events": [],
        "unassigned_resources": [],
        "lifecycle_violations": [],
        "observations": {
            "servers": [],
            "docker": [],
            "databases": [],
            "telemetry": [],
            "snapshots": [],
        },
        "control_bindings": [],
        "v1_compatibility": compatibility,
    }
    for key, value in compatibility.items():
        result.setdefault(key, value)
    return result


def filter_normalized_inventory_project(
    inventory: dict[str, Any], project: str | None
) -> dict[str, Any]:
    """Shape one pure normalized snapshot without sampling or persisting."""

    if not project:
        return inventory
    resolved = canonical_project(project)
    result = copy.deepcopy(inventory)
    repositories = [
        row for row in result.get("repositories", []) if row.get("canonical_root") == resolved
    ]
    repo_ids = {str(row.get("repo_id")) for row in repositories if row.get("repo_id")}
    root_matched_violations = [
        row
        for row in result.get("lifecycle_violations", [])
        if row.get("affected_canonical_root") == resolved
    ]
    repo_ids.update(
        str(row.get("affected_repo_id"))
        for row in root_matched_violations
        if row.get("affected_repo_id")
    )
    scoped_lifecycle_violations = [
        row
        for row in result.get("lifecycle_violations", [])
        if row.get("affected_canonical_root") == resolved
        or str(row.get("affected_repo_id")) in repo_ids
    ]
    server_violation_ids = {
        str(row.get("resource_id"))
        for row in scoped_lifecycle_violations
        if row.get("resource_kind") == "server" and row.get("resource_id")
    }
    docker_violation_ids = {
        str(row.get("resource_id"))
        for row in scoped_lifecycle_violations
        if row.get("resource_kind") == "container" and row.get("resource_id")
    }
    result["repositories"] = repositories
    result["memberships"] = [
        row for row in result.get("memberships", []) if str(row.get("repo_id")) in repo_ids
    ]
    result["control_bindings"] = [
        row for row in result.get("control_bindings", []) if str(row.get("repo_id")) in repo_ids
    ]
    result["leases"] = [
        row for row in result.get("leases", []) if str(row.get("repo_id")) in repo_ids
    ]
    result["port_assignments"] = [
        row
        for row in result.get("port_assignments", [])
        if str(row.get("repo_id")) in repo_ids
    ]
    resources = result.get("resources") if isinstance(result.get("resources"), dict) else {}
    resources["servers"] = [
        row
        for row in resources.get("servers", [])
        if str(row.get("repo_id")) in repo_ids
        or str(row.get("server_definition_id")) in server_violation_ids
    ]
    server_ids = {
        str(row.get("server_definition_id"))
        for row in resources["servers"]
        if row.get("server_definition_id")
    }
    repository_databases = [
        row
        for row in resources.get("databases", [])
        if str(row.get("repo_id")) in repo_ids
    ]
    docker_scope_ids = {
        str(row.get("host_resource_id"))
        for row in result.get("memberships", [])
        if row.get("resource_kind") in {"container", "docker"}
        and row.get("host_resource_id")
    }
    docker_scope_ids.update(
        str(row.get("docker_resource_id"))
        for row in repository_databases
        if row.get("docker_resource_id")
    )
    docker_scope_ids.update(
        str(row.get("resource_id"))
        for row in result.get("control_bindings", [])
        if row.get("resource_kind") in {"container", "docker"}
        and row.get("resource_id")
    )
    docker_scope_ids.update(docker_violation_ids)
    resources["docker"] = [
        row
        for row in resources.get("docker", [])
        if str(row.get("docker_resource_id")) in docker_scope_ids
    ]
    docker_ids = {
        str(row.get("docker_resource_id"))
        for row in resources["docker"]
        if row.get("docker_resource_id")
    }
    docker_engine_ids = {
        str(row.get("engine_id"))
        for row in resources["docker"]
        if row.get("engine_id")
    }
    result["docker_engines"] = [
        row
        for row in result.get("docker_engines", [])
        if str(row.get("engine_id")) in docker_engine_ids
    ]
    resources["docker_ports"] = [
        row
        for row in resources.get("docker_ports", [])
        if str(row.get("docker_resource_id")) in docker_ids
    ]
    resources["databases"] = [
        row
        for row in resources.get("databases", [])
        if str(row.get("repo_id")) in repo_ids
        or str(row.get("docker_resource_id")) in docker_ids
    ]
    database_ids = {
        str(row.get("database_binding_id"))
        for row in resources["databases"]
        if row.get("database_binding_id")
    }
    result["resources"] = resources
    result["unassigned_resources"] = []
    result["lifecycle_violations"] = [
        row
        for row in result.get("lifecycle_violations", [])
        if str(row.get("affected_repo_id")) in repo_ids
        or row.get("affected_canonical_root") == resolved
        or (
            row.get("resource_kind") == "server"
            and str(row.get("resource_id")) in server_ids
        )
        or (
            row.get("resource_kind") == "container"
            and str(row.get("resource_id")) in docker_ids
        )
    ]
    observations = (
        result.get("observations")
        if isinstance(result.get("observations"), dict)
        else {}
    )
    observations["servers"] = [
        row
        for row in observations.get("servers", [])
        if str(row.get("server_definition_id")) in server_ids
    ]
    observations["docker"] = [
        row
        for row in observations.get("docker", [])
        if str(row.get("docker_resource_id")) in docker_ids
    ]
    observations["databases"] = [
        row
        for row in observations.get("databases", [])
        if str(row.get("database_binding_id")) in database_ids
    ]
    observations["telemetry"] = [
        row
        for row in observations.get("telemetry", [])
        if (
            row.get("host_resource_kind") == "server"
            and str(row.get("host_resource_id")) in server_ids
        )
        or (
            row.get("host_resource_kind") in {"docker", "container"}
            and str(row.get("host_resource_id")) in docker_ids
        )
        or (
            row.get("host_resource_kind") == "database"
            and str(row.get("host_resource_id")) in database_ids
        )
    ]
    # Observation snapshots are host-global sampler runs and cannot be
    # truthfully attributed to one project.
    observations["snapshots"] = []
    result["observations"] = observations
    result["backup_evidence"] = [
        row
        for row in result.get("backup_evidence", [])
        if str(row.get("repo_id")) in repo_ids
    ]
    result["database_backups"] = [
        row
        for row in result.get("database_backups", [])
        if str(row.get("repo_id")) in repo_ids
        or str(row.get("database_binding_id")) in database_ids
        or str(row.get("docker_resource_id")) in docker_ids
    ]
    database_backup_ids = {
        str(row.get("database_backup_id"))
        for row in result["database_backups"]
        if row.get("database_backup_id")
    }
    result["database_restore_events"] = [
        row
        for row in result.get("database_restore_events", [])
        if str(row.get("database_backup_id")) in database_backup_ids
        or str(row.get("safety_database_backup_id")) in database_backup_ids
        or str(row.get("target_database_binding_id")) in database_ids
        or str(row.get("target_docker_resource_id")) in docker_ids
    ]
    result["events"] = [
        row for row in result.get("events", []) if str(row.get("repo_id")) in repo_ids
    ]
    source_ids = {
        str(row.get("source_id"))
        for rows in (
            result.get("control_bindings", []),
            result.get("leases", []),
            result.get("backup_evidence", []),
            result.get("database_backups", []),
            result.get("events", []),
        )
        for row in rows
        if row.get("source_id")
    }
    result["coordinator_sources"] = [
        row
        for row in result.get("coordinator_sources", [])
        if str(row.get("source_id")) in source_ids
    ]
    result["project"] = resolved
    compatibility = copy.deepcopy(result.get("v1_compatibility") or {})
    for key in (
        "leases",
        "port_assignments",
        "recent_events",
        "backups",
        "project_usage",
    ):
        compatibility[key] = [
            row for row in compatibility.get(key, []) if row.get("project") == resolved
        ]
    compatibility["servers"] = [
        row
        for row in compatibility.get("servers", [])
        if (
            str(row.get("id")) in server_ids
            if row.get("id")
            else row.get("project") == resolved
        )
    ]
    compatibility["project"] = resolved
    retained_server_url_keys = {
        (
            row.get("name"),
            row.get("url"),
            row.get("health_url"),
            row.get("status"),
        )
        for row in compatibility["servers"]
        if row.get("url") is not None and row.get("url_is_current")
    }
    compatibility["urls"] = [
        row
        for row in compatibility.get("urls", [])
        if row.get("project") == resolved
        or (
            row.get("name"),
            row.get("url"),
            row.get("health_url"),
            row.get("status"),
        )
        in retained_server_url_keys
    ]
    containers = [
        row
        for row in (compatibility.get("docker") or {}).get("containers", [])
        if (
            str(row.get("host_resource_id")) in docker_ids
            if row.get("host_resource_id")
            else row.get("project") == resolved
        )
    ]
    postgres = [
        row
        for row in compatibility.get("postgres", [])
        if (
            str(row.get("database_binding_id")) in database_ids
            if row.get("database_binding_id")
            else (
                str(row.get("host_resource_id")) in docker_ids
                if row.get("host_resource_id")
                else row.get("project") == resolved
            )
        )
    ]
    compatibility["docker"] = {
        **(compatibility.get("docker") or {}),
        "containers": containers,
        "postgres": postgres,
    }
    compatibility["postgres"] = postgres
    result["v1_compatibility"] = compatibility
    for key, value in compatibility.items():
        if key not in {"leases", "port_assignments"}:
            result[key] = copy.deepcopy(value)
    return result


def pure_normalized_inventory(
    *,
    project: str | None = None,
    include_docker: bool = True,
    stats_history_limit: int = DOCKER_STATS_HISTORY_LIMIT,
) -> dict[str, Any]:
    """Return one query-only account-store snapshot.

    A missing database is represented as an empty normalized graph rather than
    being created by a read. `observe` is the explicit bootstrap/write path.
    """

    database_path = coordinator_home() / NORMALIZED_DATABASE_NAME
    if not database_path.exists():
        return empty_normalized_inventory(project=project)
    with AccountStore.open_default_read_only(coordinator_home()) as store:
        result = store.inventory_v2()
    result = filter_normalized_inventory_project(result, project)
    if not include_docker:
        result["docker"] = {"available": None, "containers": [], "postgres": []}
        result["postgres"] = []
        result["v1_compatibility"]["docker"] = copy.deepcopy(result["docker"])
        result["v1_compatibility"]["postgres"] = []
    if stats_history_limit < DOCKER_STATS_HISTORY_LIMIT:
        for container in result.get("docker", {}).get("containers", []):
            history = list(container.get("stats_history") or [])
            container["stats_history"] = history[-stats_history_limit:] if stats_history_limit else []
    return result


def discover_same_uid_legacy_homes(
    *, explicit_homes: list[str] | None = None
) -> list[Path]:
    """Find migration-only JSON homes owned by this effective account."""

    uid = os.geteuid()
    candidates: set[Path] = set()
    if explicit_homes is not None:
        candidates.update(Path(item).expanduser().absolute() for item in explicit_homes)
    else:
        account_home = posix_account_home()
        candidates.add(account_home / ".codex" / "agent-coordinator")
        candidates.add(account_home / ".claude" / "agent-coordinator")
        parall_root = account_home / "Library" / "Application Support" / "Parall"
        if parall_root.is_dir() and not parall_root.is_symlink():
            # Bound discovery to known application state suffixes. rglob is
            # migration-only and candidates still pass the importer's strict
            # no-symlink/private-owner checks.
            for state_file in parall_root.rglob(".codex/agent-coordinator/state.json"):
                candidates.add(state_file.parent)
    safe: list[Path] = []
    for candidate in sorted(candidates, key=str):
        state_file = candidate / "state.json"
        try:
            home_metadata = candidate.lstat()
            state_metadata = state_file.lstat()
        except FileNotFoundError:
            continue
        if (
            stat.S_ISLNK(home_metadata.st_mode)
            or not stat.S_ISDIR(home_metadata.st_mode)
            or home_metadata.st_uid != uid
            or stat.S_IMODE(home_metadata.st_mode) != 0o700
            or stat.S_ISLNK(state_metadata.st_mode)
            or not stat.S_ISREG(state_metadata.st_mode)
            or state_metadata.st_uid != uid
            or stat.S_IMODE(state_metadata.st_mode) != 0o600
        ):
            continue
        safe.append(candidate)
    return safe


def bootstrap_legacy_import(
    store: AccountStore,
    *,
    explicit_homes: list[str] | None = None,
    backup_root: str | None = None,
) -> dict[str, Any]:
    candidates = discover_same_uid_legacy_homes(explicit_homes=explicit_homes)
    reconciliation = store.reconcile_imported_legacy_conflicts()
    with store.read_transaction() as connection:
        imported_homes = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT canonical_home FROM coordinator_sources
                WHERE captured_sha256 IS NOT NULL AND status IN ('imported', 'retired')
                """
            )
        }
    pending = [candidate for candidate in candidates if str(candidate) not in imported_homes]
    if not pending:
        return {
            "attempted": bool(reconciliation.attempted),
            "source_count": int(reconciliation.source_count),
            "committed": bool(reconciliation.committed),
            "conflict_count": int(reconciliation.conflict_count),
            "blocking_conflict_count": int(
                reconciliation.blocking_conflict_count
            ),
            "reclassified_conflict_count": int(
                reconciliation.reclassified_count
            ),
            "destination_generation": reconciliation.destination_generation,
            "late_writer_sources": list(store.detect_late_legacy_writers()),
        }
    root = Path(backup_root).expanduser().absolute() if backup_root else coordinator_home() / "legacy-import-backups"
    report = store.import_legacy_homes(pending, root)
    with store.read_transaction() as connection:
        aggregate_conflicts = [
            dict(row)
            for row in connection.execute(
                """
                SELECT conflict_kind, severity FROM migration_conflicts
                WHERE disposition='open'
                ORDER BY conflict_kind, conflict_id
                """
            )
        ]
    return {
        "attempted": True,
        "committed": bool(report.committed),
        "source_count": int(report.source_count) + int(reconciliation.source_count),
        "repository_count": int(report.repository_count),
        "missing_repository_count": int(report.missing_repository_count),
        "unassigned_count": int(report.unassigned_count),
        "exact_duplicate_count": int(report.exact_duplicate_count),
        "conflict_count": len(aggregate_conflicts),
        "blocking_conflict_count": sum(
            1 for item in aggregate_conflicts if item["severity"] == "blocking"
        ),
        "conflict_kinds": sorted(
            {str(item["conflict_kind"]) for item in aggregate_conflicts}
        ),
        "destination_generation": report.destination_generation,
        "reclassified_conflict_count": int(reconciliation.reclassified_count),
        "late_writer_sources": list(store.detect_late_legacy_writers()),
    }


def ensure_observation_host(store: AccountStore) -> str:
    """Create the local-host row only when it is actually absent."""

    machine = f"{platform.system()}\x1f{platform.node()}\x1f{socket.gethostname()}"
    machine_fingerprint = hashlib.sha256(machine.encode("utf-8")).hexdigest()
    host_id = deterministic_id("host", machine_fingerprint)
    with store.read_transaction() as connection:
        exists = connection.execute(
            "SELECT 1 FROM hosts WHERE host_id = ?", (host_id,)
        ).fetchone()
    if exists is None:
        return store.ensure_local_host()
    return host_id


def latest_fresh_observation(
    store: AccountStore,
    *,
    host_id: str,
    observer_domain: str,
    max_age_seconds: float,
) -> ObservationOutcome | None:
    if max_age_seconds <= 0:
        return None
    with store.read_transaction() as connection:
        row = connection.execute(
            """
            SELECT snapshot_id, material_fingerprint, completed_at
            FROM observation_snapshots
            WHERE host_id = ? AND observer_domain = ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
            """,
            (host_id, observer_domain),
        ).fetchone()
    if row is None or not row[2]:
        return None
    try:
        completed = datetime.fromisoformat(str(row[2]).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
    if (datetime.now(timezone.utc) - completed).total_seconds() > max_age_seconds:
        return None
    return ObservationOutcome(
        snapshot_id=str(row[0]),
        host_id=host_id,
        observer_domain=observer_domain,
        joined=True,
        material_fingerprint=str(row[1]),
        completed_at=str(row[2]),
    )


def observation_domain_for_scope(
    *, include_docker: bool, backup_dirs: list[str] | None
) -> str:
    """Return one deterministic single-flight/freshness domain per sample scope."""

    base = (
        OBSERVER_DOMAIN_FULL_DOCKER
        if include_docker
        else OBSERVER_DOMAIN_NO_DOCKER
    )
    canonical_backups = sorted(
        {
            str(Path(value).expanduser().resolve())
            for value in (backup_dirs or [])
        }
    )
    if not canonical_backups:
        return base
    digest = hashlib.sha256(
        json.dumps(canonical_backups, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:20]
    return f"{base}:backups-{digest}"


def sample_host_inventory_for_normalized_store(
    store: AccountStore,
    *,
    include_docker: bool,
    backup_dirs: list[str] | None,
) -> dict[str, Any]:
    state = normalized_control_snapshot_from_store(store)
    state["servers"] = {
        str(server["id"]): server
        for server in NormalizedServerLifecycle(store).list_servers()
    }
    inventory = build_inventory(
        state,
        project=None,
        include_docker=include_docker,
        backup_dirs=backup_dirs,
        stats_history_limit=DOCKER_STATS_HISTORY_LIMIT,
    )
    if include_docker:
        postgres_ids = {
            str(item.get("full_id") or item.get("id") or "")
            for item in inventory.get("docker", {}).get("postgres", [])
        }
        for container in inventory.get("docker", {}).get("containers", []):
            identity = str(container.get("full_id") or container.get("id") or "")
            if identity not in postgres_ids:
                continue
            databases, error = discover_postgres_databases(container)
            container["databases"] = databases
            if error:
                container["database_discovery_error"] = error
    return {"sampled_at": iso_timestamp(), "inventory": inventory}


def coordinated_observe_host(options: dict[str, Any]) -> dict[str, Any]:
    if state_backend() == LEGACY_JSON_BACKEND:
        raise RuntimeError("explicit host observation requires the normalized SQLite backend")
    agent, project = require_identity(options, "observe")
    max_age_seconds = float(options.get("max_age_seconds") or 0)
    if not 0 <= max_age_seconds <= 24 * 60 * 60:
        raise ValueError("--max-age-seconds must be between 0 and 86400")
    with AccountStore.open_default(coordinator_home()) as store:
        imported = bootstrap_legacy_import(
            store,
            explicit_homes=options.get("legacy_home"),
            backup_root=options.get("legacy_backup_root"),
        )
        host_id = ensure_observation_host(store)
        include_docker = not bool(options.get("no_docker"))
        observer_domain = observation_domain_for_scope(
            include_docker=include_docker,
            backup_dirs=options.get("backup_dir"),
        )
        fresh = latest_fresh_observation(
            store,
            host_id=host_id,
            observer_domain=observer_domain,
            max_age_seconds=max_age_seconds,
        )
        observed = fresh is None
        if fresh is None:
            observer = SingleFlightObserver(store)
            outcome = observer.observe(
                host_id=host_id,
                observer_domain=observer_domain,
                sampler=lambda: sample_host_inventory_for_normalized_store(
                    store,
                    include_docker=include_docker,
                    backup_dirs=options.get("backup_dir"),
                ),
                commit=lambda connection, snapshot_id, sample: commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    sample,
                    host_id=host_id,
                    coordinator_home=str(coordinator_home()),
                ),
            )
        else:
            outcome = fresh
        metadata = store.metadata
        return {
            "schema_version": NORMALIZED_SCHEMA_VERSION,
            "status": "completed" if observed else "fresh",
            "observed": observed,
            "joined": bool(outcome.joined),
            "snapshot_id": outcome.snapshot_id,
            "host_id": outcome.host_id,
            "observer_domain": outcome.observer_domain,
            "material_fingerprint": outcome.material_fingerprint,
            "completed_at": outcome.completed_at,
            "max_age_seconds": max_age_seconds,
            "request": {"agent": agent, "project": project},
            "imported": imported,
            "state_revision": metadata.state_revision,
            "observation_revision": metadata.observation_revision,
        }


def observe_broker_service_store_for_enrollment(
    store: AccountStore,
) -> dict[str, Any]:
    """Run one full service-owned observation before publishing client ACLs.

    Enrollment is an administrator transaction journey: the repository and
    runtime definitions exist first, then the service observes Docker once,
    then exact grants/profile mappings are derived.  A failed observation
    aborts before a client profile is installed.
    """

    host_id = ensure_observation_host(store)
    observer = SingleFlightObserver(store)
    outcome = observer.observe(
        host_id=host_id,
        observer_domain=OBSERVER_DOMAIN_FULL_DOCKER,
        sampler=lambda: sample_host_inventory_for_normalized_store(
            store,
            include_docker=True,
            backup_dirs=None,
        ),
        commit=lambda connection, snapshot_id, sample: commit_host_inventory_observation(
            connection,
            snapshot_id,
            sample,
            host_id=host_id,
            coordinator_home=str(store.database_path.parent),
        ),
    )
    with store.read_transaction() as connection:
        capability = connection.execute(
            """
            SELECT docker_available, capability_fingerprint, committed_at
            FROM observation_capabilities
            WHERE snapshot_id = ? AND observer_domain = ?
            """,
            (outcome.snapshot_id, OBSERVER_DOMAIN_FULL_DOCKER),
        ).fetchone()
    if capability is None:
        raise RuntimeError(
            "completed broker observation lacks exact committed Docker capability evidence"
        )
    return {
        "observer_domain": OBSERVER_DOMAIN_FULL_DOCKER,
        "snapshot_id": outcome.snapshot_id,
        "joined": bool(outcome.joined),
        "completed_at": outcome.completed_at,
        "material_fingerprint": outcome.material_fingerprint,
        "docker_available": bool(capability["docker_available"]),
        "capability_fingerprint": str(capability["capability_fingerprint"]),
        "capability_committed_at": str(capability["committed_at"]),
    }


def coordinated_broker_enroll(args: argparse.Namespace) -> dict[str, Any]:
    """Synchronize one repository into the service broker and publish trust."""

    project = canonical_project(str(args.project))
    start_port, end_port = parse_range(str(args.port_range))
    profile_output = (
        Path(str(args.profile_output)).expanduser()
        if args.profile_output
        else SYSTEM_PROFILE_PATH
    )
    specification = build_project_runtime_spec(
        {"servers": {}, "docker": {}, "leases": {}, "port_assignments": {}},
        project=project,
        runtime_file=args.runtime_file,
        include_docker=False,
    )
    servers = list(specification.get("servers") or [])
    compose = specification.get("compose")
    result = enroll_repository(
        database_path=Path(str(args.database)).expanduser().absolute(),
        socket_path=Path(str(args.socket)).expanduser().absolute(),
        socket_gid=int(args.access_gid),
        client_uid=int(args.client_uid),
        account_id=str(args.account_id),
        canonical_root=project,
        servers=servers,
        port_start=start_port,
        port_end=end_port,
        profile_path=profile_output.absolute(),
        compose=compose if isinstance(compose, dict) else None,
        observe_host=observe_broker_service_store_for_enrollment,
        explicit_reinstall=bool(args.explicit_reinstall),
        validity_seconds=int(args.profile_valid_days) * 24 * 60 * 60,
    )
    result["observation"] = {
        "scope": OBSERVER_DOMAIN_FULL_DOCKER,
        "completed_before_profile_publish": True,
    }
    result["runtime_file"] = specification.get("runtime_file")
    result["agent"] = str(args.agent)
    return result


def observe_project_runtime(
    options: dict[str, Any], *, action: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = dict(options)
    prepared["project"] = canonical_project(str(prepared["project"]))
    broker_configured = configured_broker_context(prepared["project"]) is not None
    baseline = snapshot_runtime_observation(project=prepared["project"])
    observed = copy.deepcopy(baseline)
    spec = build_project_runtime_spec(
        observed,
        project=prepared["project"],
        runtime_file=prepared.get("runtime_file"),
        include_docker=not broker_configured,
    )
    report = project_runtime_report(observed, spec, action=action)
    if broker_configured and project_docker_requirement_reasons(spec):
        report["docker_observation"] = {
            "authority": "host_broker",
            "client_docker_required": False,
            "status": "service_observation_required",
        }
    commit_runtime_observations(baseline, observed)
    return spec, report


def begin_project_operation(options: dict[str, Any], action: str) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = dict(options)
    agent, project = require_identity(prepared, f"project {action}")
    if not prepared.get("dry_run"):
        # The normalized compatibility projection deliberately omits private
        # definition generations, active lease IDs, and other CAS fields.
        # Compare direct lifecycle rows before and after the slow listener
        # identity preflight; mixing the compatibility shape with the direct
        # shape would reject every stable managed server as a false TOCTOU.
        preflight_state = (
            snapshot_runtime_observation(project=project)
            if state_backend() != LEGACY_JSON_BACKEND
            else snapshot_coordinator_state()
        )
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
    if state_backend() != LEGACY_JSON_BACKEND:
        stack = _normalized_guard_stack()
        active = next(
            (
                item
                for item in reversed(stack)
                if item.get("project") == project
            ),
            None,
        )
        if active is None:
            raise RuntimeError(
                f"project {action} requires a normalized repository action guard"
            )
        if not prepared.get("dry_run"):
            current = snapshot_runtime_observation(project=project)
            current_fingerprints = {
                str(server_id): server_lifecycle_fingerprint(server)
                for server_id, server in current.get("servers", {}).items()
                if str(server.get("project") or "") == project
            }
            if current_fingerprints != preflight_fingerprints:
                raise RuntimeError(
                    f"project {action} server lifecycle changed during listener "
                    "identity preflight; retry"
                )
        operation = {
            "id": str(uuid.uuid4()),
            "permit_id": str(active["permit_id"]),
            "project": project,
            "agent": agent,
            "action": f"project.{action}",
        }
        timestamp = utc_timestamp()
        request = {
            "permit_id": operation["permit_id"],
            "project": project,
            "agent": agent,
            "action": operation["action"],
            "runtime_file": prepared.get("runtime_file"),
            "dry_run": bool(prepared.get("dry_run")),
        }
        with AccountStore.open_default(coordinator_home()) as store:
            with store.immediate_transaction() as connection:
                permit = connection.execute(
                    "SELECT status FROM operations WHERE operation_id = ? "
                    "AND repo_id = ? AND status = 'running'",
                    (operation["permit_id"], str(active["repo_id"])),
                ).fetchone()
                if permit is None:
                    raise RuntimeError("normalized project action permit disappeared")
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, owner_uid, actor, result_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'running', 'executing', 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        operation["id"],
                        str(active["repo_id"]),
                        operation["action"],
                        fingerprint(request),
                        os.geteuid(),
                        agent,
                        json.dumps(request, separators=(",", ":"), sort_keys=True),
                        timestamp,
                        timestamp,
                    ),
                )
        return prepared, operation
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
    if state_backend() != LEGACY_JSON_BACKEND:
        with AccountStore.open_default(coordinator_home()) as store:
            with store.immediate_transaction() as connection:
                operation = connection.execute(
                    "SELECT result_json FROM operations WHERE operation_id = ? "
                    "AND status = 'running'",
                    (operation_id,),
                ).fetchone()
                if operation is None:
                    return
                payload = json.loads(str(operation[0] or "{}"))
                if result is not None:
                    payload["project_result"] = {
                        "action": result.get("action"),
                        "ok": result.get("ok"),
                        "classification": result.get("classification"),
                        "action_error_count": len(
                            result.get("action_errors") or []
                        ),
                        "service_count": len(result.get("services") or []),
                        "partial": bool(result.get("partial")),
                        "preflight_failed": bool(result.get("preflight_failed")),
                    }
                if error is not None:
                    payload["failure"] = coordinator_exception_payload(error)
                incomplete = bool(result is not None and result.get("ok") is False)
                status = "failed" if error is not None or incomplete else "succeeded"
                phase = (
                    "failed"
                    if error is not None
                    else ("committed-incomplete" if incomplete else "committed")
                )
                connection.execute(
                    "UPDATE operations SET status = ?, phase = ?, result_json = ?, "
                    "error_code = ?, error_message = ?, updated_at = ? "
                    "WHERE operation_id = ? AND status = 'running'",
                    (
                        status,
                        phase,
                        json.dumps(payload, separators=(",", ":"), sort_keys=True),
                        (
                            str(payload["failure"].get("code") or "project_action_failed")
                            if error is not None
                            else ("project_action_incomplete" if incomplete else None)
                        ),
                        (
                            str(payload["failure"].get("error") or error)
                            if error is not None
                            else ("project action reported an incomplete result" if incomplete else None)
                        ),
                        utc_timestamp(),
                        operation_id,
                    ),
                )
        return
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
    if state_backend() != LEGACY_JSON_BACKEND:
        project = canonical_project(str(report.get("project") or ""))
        with AccountStore.open_default(coordinator_home()) as store:
            with store.immediate_transaction() as connection:
                repository = connection.execute(
                    "SELECT repo_id FROM repositories WHERE canonical_root = ? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (project,),
                ).fetchone()
                diagnostic = {
                    "project": project,
                    "runtime_id": report.get("runtime_id"),
                    "ok": report.get("ok"),
                    "classification": report.get("classification"),
                    "service_count": len(report.get("services") or []),
                    "at": iso_timestamp(),
                }
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, source_id, operation_id, event_kind,
                        code, message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, NULL, NULL, 'project.status',
                              'project_status_observed', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        str(repository[0]) if repository is not None else None,
                        f"Project runtime status observed for {project}",
                        json.dumps(
                            diagnostic, separators=(",", ":"), sort_keys=True
                        ),
                        utc_timestamp(),
                    ),
                )
        return
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
    if state_backend() != LEGACY_JSON_BACKEND:
        canonical = canonical_project(project)
        released: list[dict[str, Any]] = []
        with AccountStore.open_default(coordinator_home()) as store:
            ports = NormalizedPortLifecycle(store)
            servers = {
                str(server["id"]): server
                for server in NormalizedServerLifecycle(store).list_servers(
                    canonical_project=canonical
                )
            }
            candidates = [
                lease
                for lease in ports.list_leases(
                    canonical_project=canonical, active_only=True
                )
                if int(lease.get("port") or 0) == int(port)
                and str(lease.get("purpose") or "").startswith("server:")
            ]
            for lease in candidates:
                server = servers.get(str(lease.get("server_id") or ""))
                if server is not None and server.get("status") != "stopped":
                    pid = int(server.get("pid") or 0)
                    if pid and pid_alive(pid):
                        continue
                released.append(
                    ports.release(
                        agent=str(lease.get("agent") or "coordinator"),
                        canonical_project=canonical,
                        lease_id=str(lease["id"]),
                    )
                )
        return released
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
    broker_context = configured_broker_context(str(spec["project"]))
    if broker_context is not None:
        profile, repository = broker_context
        compose = spec.get("compose") or {}
        compose_id = None
        if compose.get("declared") and compose.get("autostart"):
            compose_id = repository.compose_id()
        container_ids: list[str] = []
        for dependency in mutable_runtime_docker_dependencies(
            spec, exclude_compose_owned=True
        ):
            identity = str(
                dependency.get("container") or dependency.get("name") or ""
            )
            if not identity:
                raise BrokerProfileError(
                    "declared Docker dependency has no exact broker enrollment identity"
                )
            container_ids.append(repository.container_id(identity))
        declared_services = [str(item) for item in compose.get("services") or []]
        compose_restart_plan = None
        if action == "restart" and compose_id is not None:
            # The broker owns the complete Compose definition. The later typed
            # restart is one service-owned down/up sequence; the client does
            # not query Docker or select paths/services.
            compose_restart_plan = {
                "restart_services": declared_services,
                "start_services": [],
                "declared_services": declared_services,
                "all_services_action": "service_owned_down_up",
            }
        return {
            "required": True,
            "capability": "host_broker",
            "reasons": reasons,
            "dry_run": bool(dry_run),
            "service": str(profile.service.socket_path),
            "repository_id": repository.repo_id,
            "compose_definition_id": compose_id,
            "container_resource_ids": sorted(set(container_ids)),
            "compose_restart_plan": compose_restart_plan,
            "client_docker_required": False,
        }
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
    if configured_broker_context(str(spec["project"])) is None:
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


@normalized_guarded_action(RepositoryAction.START, "project start")
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


@normalized_guarded_action(RepositoryAction.START, "project restart")
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


@normalized_guarded_action(RepositoryAction.STOP, "project stop")
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


def coordinated_broker_compose_command(
    *,
    profile: BrokerClientProfile,
    repository: BrokerRepositoryProfile,
    command: list[str],
    cwd: str | None,
    project: str,
    agent: str,
) -> dict[str, Any]:
    subcommand = docker_compose_subcommand(command)
    if subcommand is None:
        raise BrokerProfileError("Docker Compose command has no typed lifecycle action")
    compose_id = repository.compose_id()
    try:
        up_operation = BrokerOperation("compose.up")
        down_operation = BrokerOperation("compose.down")
    except ValueError as error:
        raise BrokerProfileError(
            "the installed coordinator broker does not support typed Compose lifecycle"
        ) from error
    if subcommand in {"up", "create", "start", "unpause"}:
        sequence = [up_operation]
    elif subcommand in {"down", "stop", "kill", "pause", "rm"}:
        sequence = [down_operation]
    elif subcommand == "restart":
        # The service owns the complete definition. A full down/up cycle is
        # explicit and globally serialized; no client-selected services or
        # file paths cross the trust boundary.
        sequence = [down_operation, up_operation]
    else:
        raise BrokerProfileError(
            f"Compose mutation {subcommand!r} has no typed broker operation"
        )
    operations: list[dict[str, Any]] = []
    for operation in sequence:
        operation_id, broker_result = profile.call(
            repository=repository,
            resource_id=compose_id,
            operation=operation,
        )
        operations.append(
            {
                "operation_id": operation_id,
                "operation": operation.value,
                "result": broker_result,
            }
        )
    result = {
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "command": command,
        "cwd": cwd,
        "agent": agent,
        "project": project,
        "broker": {
            "resource_id": compose_id,
            "operations": operations,
        },
    }
    # The service database is the sole durable authority for brokered host
    # mutations.  Do not open or project into the client's local state here:
    # the broker reply already carries the service-owned post-action
    # observation and operation identities.
    return result


COMPOSE_START_LIKE_COMMANDS = {"create", "restart", "run", "start", "unpause", "up"}


def normalized_guarded_docker_action(function: Any) -> Any:
    """Guard Docker commands that can create or resume repository resources."""

    @functools.wraps(function)
    def guarded(
        command: list[str],
        *,
        cwd: str | None = None,
        dry_run: bool = False,
        project: str | None = None,
        agent: str | None = None,
        container: str | None = None,
        role: str | None = None,
    ) -> dict[str, Any]:
        action: RepositoryAction | None = None
        if len(command) >= 2 and command[0] == "docker":
            if command[1] in {"start", "restart"}:
                action = RepositoryAction.START
            elif command[1] == "stop":
                action = RepositoryAction.STOP
            elif docker_compose_subcommand(command) in COMPOSE_START_LIKE_COMMANDS:
                action = RepositoryAction.COMPOSE
            elif docker_command_is_mutating(command):
                action = RepositoryAction.STOP
        if action is None:
            return function(
                command,
                cwd=cwd,
                dry_run=dry_run,
                project=project,
                agent=agent,
                container=container,
                role=role,
            )
        guarded_agent, guarded_project = require_identity(
            {"agent": agent, "project": project},
            "docker " + " ".join(command[1:3]),
        )
        if configured_broker_context(guarded_project) is not None:
            # The service reserves and fences the authoritative repository
            # operation.  Opening the account-local action store here would
            # establish a competing lock/state authority and fails for a
            # different-UID broker client whose local store is unavailable.
            return function(
                command,
                cwd=cwd,
                dry_run=dry_run,
                project=guarded_project,
                agent=guarded_agent,
                container=container,
                role=role,
            )
        with normalized_repository_action_guard(
            project=guarded_project, agent=guarded_agent, action=action
        ):
            return function(
                command,
                cwd=cwd,
                dry_run=dry_run,
                project=guarded_project,
                agent=guarded_agent,
                container=container,
                role=role,
            )

    return guarded


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


def record_normalized_docker_result(
    command: list[str],
    cwd: str | None,
    result: dict[str, Any],
    project: str | None,
    agent: str | None,
    *,
    outcome: str,
) -> None:
    """Record a bounded Docker command diagnostic in normalized SQL."""

    canonical = canonical_project(project) if project else None
    diagnostic = {
        "command": [str(item) for item in command],
        "cwd": cwd,
        "agent": agent,
        "project": canonical,
        "outcome": outcome,
        "returncode": result.get("returncode"),
        "dry_run": bool(result.get("dry_run")),
        "docker_executable": result.get("docker_executable"),
        "timeout_seconds": result.get("timeout_seconds"),
        "stdout": str(result.get("stdout") or "")[-4096:],
        "stderr": str(result.get("stderr") or "")[-4096:],
        "code": result.get("code"),
        "error": result.get("error"),
        "broker": copy.deepcopy(result.get("broker")),
    }
    active = next(
        (
            item
            for item in reversed(_normalized_guard_stack())
            if canonical and item.get("project") == canonical
        ),
        None,
    )
    timestamp = utc_timestamp()
    with AccountStore.open_default(coordinator_home()) as store:
        with store.immediate_transaction() as connection:
            repository = None
            if canonical:
                repository = connection.execute(
                    "SELECT repo_id FROM repositories WHERE canonical_root = ? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (canonical,),
                ).fetchone()
            operation_id = str(active["permit_id"]) if active is not None else None
            if operation_id is not None:
                operation = connection.execute(
                    "SELECT result_json FROM operations WHERE operation_id = ? "
                    "AND status = 'running'",
                    (operation_id,),
                ).fetchone()
                if operation is not None:
                    operation_result = json.loads(str(operation[0] or "{}"))
                    commands = list(operation_result.get("docker_commands") or [])
                    commands.append(diagnostic)
                    operation_result["docker_commands"] = commands[-20:]
                    connection.execute(
                        "UPDATE operations SET result_json = ?, updated_at = ? "
                        "WHERE operation_id = ? AND status = 'running'",
                        (
                            json.dumps(
                                operation_result,
                                separators=(",", ":"),
                                sort_keys=True,
                            ),
                            timestamp,
                            operation_id,
                        ),
                    )
            connection.execute(
                """
                INSERT INTO events(
                    event_id, repo_id, source_id, operation_id, event_kind,
                    code, message, diagnostic_json, occurred_at
                ) VALUES (?, ?, NULL, ?, 'docker.command', ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    str(repository[0]) if repository is not None else None,
                    operation_id,
                    f"docker_command_{outcome}",
                    f"Docker command {outcome}: {' '.join(command)}",
                    json.dumps(diagnostic, separators=(",", ":"), sort_keys=True),
                    timestamp,
                ),
            )


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


@normalized_guarded_docker_action
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
    broker_context = configured_broker_context(project) if project else None
    if broker_context is not None and mutating:
        profile, repository = broker_context
        if dry_run:
            return {
                "dry_run": True,
                "broker": True,
                "command_class": (
                    "compose" if docker_compose_subcommand(command) else "docker"
                ),
                "project": project,
                "agent": agent,
            }
        if len(command) >= 3 and command[1] in {"start", "stop", "restart"}:
            container_identity = str(container or command[2])
            resource_id = repository.container_id(container_identity)
            operation = {
                "start": BrokerOperation.DOCKER_START,
                "stop": BrokerOperation.DOCKER_STOP,
                "restart": BrokerOperation.DOCKER_RESTART,
            }[command[1]]
            operation_id, broker_result = profile.call(
                repository=repository,
                resource_id=resource_id,
                operation=operation,
            )
            result = {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "command": command,
                "cwd": cwd,
                "agent": agent,
                "project": project,
                "broker": {
                    "operation_id": operation_id,
                    "operation": operation.value,
                    "resource_id": resource_id,
                    "result": broker_result,
                },
            }
            # Broker service persistence and its authoritative post-action
            # observation are the durable record.  A client-local diagnostic
            # write would create a second authority and breaks cross-UID
            # operation when that local store is unavailable.
            return result
        if docker_compose_subcommand(command) is None:
            raise BrokerProfileError(
                "configured broker mode refuses an untyped host-global Docker mutation"
            )
        return coordinated_broker_compose_command(
            profile=profile,
            repository=repository,
            command=command,
            cwd=cwd,
            project=str(project),
            agent=str(agent),
        )
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
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                record_docker_command(state, command, cwd, result, project, agent)
        else:
            record_normalized_docker_result(
                command, cwd, result, project, agent, outcome="dry_run"
            )
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
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                record_docker_command(
                    state, command, cwd, failure_result, project, agent
                )
        else:
            record_normalized_docker_result(
                command, cwd, failure_result, project, agent, outcome="failed"
            )
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
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                compose_action = docker_compose_subcommand(command)
                operation_action = (
                    compose_action if command[1] == "compose" else command[1]
                )
                operation = begin_operation(
                    state,
                    action=(
                        f"docker.{command[1]}.{operation_action}"
                        if command[1] == "compose"
                        else f"docker.{operation_action}"
                    ),
                    target=f"docker:{target_suffix}",
                    agent=str(agent),
                    project=str(project),
                    generation=int(state.get("revision") or 0) + 1,
                )
                operation_id = str(operation["id"])
        else:
            active = next(
                (
                    item
                    for item in reversed(_normalized_guard_stack())
                    if item.get("project") == project
                ),
                None,
            )
            if active is None:
                raise RuntimeError(
                    "mutating Docker command requires a normalized repository guard"
                )
            operation_id = str(active["permit_id"])

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
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                record_docker_command(
                    state, command, cwd, failure_result, project, agent
                )
                if operation_id:
                    finish_operation(
                        state,
                        operation_id,
                        status="failed",
                        phase="execute",
                        error=str(exc),
                    )
        else:
            record_normalized_docker_result(
                command, cwd, failure_result, project, agent, outcome="failed"
            )
        raise

    if completed.returncode == 0 and container and agent and project:
        try:
            result["metadata"] = coordinated_register_docker_metadata(
                {"container": container, "agent": agent, "project": project, "cwd": cwd, "role": role}
            )
        except Exception as exc:
            result["metadata_error"] = str(exc)
            if state_backend() == LEGACY_JSON_BACKEND:
                with locked_state() as state:
                    record_docker_command(
                        state, command, cwd, result, project, agent
                    )
                    if operation_id:
                        finish_operation(
                            state,
                            operation_id,
                            status="failed",
                            phase="metadata",
                            error=str(exc),
                        )
            else:
                record_normalized_docker_result(
                    command, cwd, result, project, agent, outcome="metadata_failed"
                )
            raise
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            record_docker_command(state, command, cwd, result, project, agent)
            if operation_id:
                finish_operation(
                    state,
                    operation_id,
                    status="completed" if completed.returncode == 0 else "failed",
                    phase="committed",
                    error=(
                        completed.stderr.strip()
                        if completed.returncode != 0
                        else None
                    ),
                )
    else:
        record_normalized_docker_result(
            command,
            cwd,
            result,
            project,
            agent,
            outcome="succeeded" if completed.returncode == 0 else "failed",
        )
    if completed.returncode != 0:
        raise docker_command_failed_error(result)
    return result


def configured_broker_context(
    project: str,
) -> tuple[BrokerClientProfile, BrokerRepositoryProfile] | None:
    """Resolve the root-provisioned broker for one canonical repository.

    Absence means this host has not installed multi-user broker mode.  Once a
    root-owned profile exists, missing/stale/spoofed repository data is an
    error; host-global mutations never fall back to the per-user authority.
    """

    profile = load_broker_profile()
    if profile is None:
        return None
    return profile, profile.repository(canonical_project(project))


def _validated_broker_lease_result(result: dict[str, Any]) -> tuple[str, int, str, str | None]:
    lease_id = str(result.get("lease_id") or "")
    if not lease_id:
        raise BrokerError("invalid_reply", "Broker lease result omitted lease_id.")
    try:
        port = int(result["port"])
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerError("invalid_reply", "Broker lease result omitted a valid port.") from error
    if not 1 <= port <= 65535 or result.get("status") != "active":
        raise BrokerError("invalid_reply", "Broker lease result is not an active valid port.")
    protocol = str(result.get("protocol") or "tcp")
    if protocol not in {"tcp", "udp"}:
        raise BrokerError("invalid_reply", "Broker lease result has an invalid protocol.")
    expires_at = None if result.get("expires_at") is None else str(result["expires_at"])
    return lease_id, port, protocol, expires_at


def acquire_broker_lease_link(
    *,
    profile: BrokerClientProfile,
    repository: BrokerRepositoryProfile,
    server_name: str,
    requested_port: int | None,
    ttl_seconds: int,
    adopt_existing_listener: bool = False,
) -> tuple[BrokerLink, dict[str, Any]]:
    server_definition_id = repository.server_id(server_name)
    arguments: dict[str, Any] = {"protocol": "tcp", "ttl_seconds": ttl_seconds}
    if requested_port is not None:
        arguments["requested_port"] = int(requested_port)
    if adopt_existing_listener:
        arguments["adopt_existing_listener"] = True
    operation_id, result = profile.call(
        repository=repository,
        resource_id=server_definition_id,
        operation=BrokerOperation.PORT_LEASE,
        arguments=arguments,
    )
    lease_id, port, protocol, expires_at = _validated_broker_lease_result(result)
    try:
        with AccountStore.open_default(coordinator_home()) as store:
            link = BrokerLinkStore(store).reserve_lease(
                profile=profile,
                repository=repository,
                server_name=server_name,
                server_definition_id=server_definition_id,
                broker_lease_id=lease_id,
                port=port,
                protocol=protocol,
                operation_id=operation_id,
                expires_at=expires_at,
            )
    except BaseException as local_error:
        rollback_id = str(uuid.uuid4())
        try:
            profile.call(
                repository=repository,
                resource_id=lease_id,
                operation=BrokerOperation.PORT_RELEASE,
                operation_id=rollback_id,
            )
        except BaseException as rollback_error:
            raise StructuredCoordinatorError(
                "broker lease succeeded but local linkage and broker rollback both failed",
                {
                    "code": "broker_lease_link_and_rollback_failed",
                    "classification": "reconciliation_required",
                    "broker_lease_id": lease_id,
                    "broker_operation_id": operation_id,
                    "rollback_operation_id": rollback_id,
                    "local_error": f"{type(local_error).__name__}: {local_error}",
                    "rollback_error": f"{type(rollback_error).__name__}: {rollback_error}",
                    "action_required": "Do not reuse this port; reconcile the exact broker lease through the Coordinator skill.",
                },
            ) from local_error
        raise
    return link, result


def bind_broker_lease_link(link_id: str, local_lease_id: str) -> BrokerLink:
    with AccountStore.open_default(coordinator_home()) as store:
        return BrokerLinkStore(store).bind_local_lease(link_id, local_lease_id)


def broker_lease_link_for_local(local_lease_id: str) -> BrokerLink | None:
    if not state_path().exists() or state_backend() == LEGACY_JSON_BACKEND:
        return None
    with AccountStore.open_default(coordinator_home()) as store:
        return BrokerLinkStore(store).lease_for_local(local_lease_id)


def broker_lease_link_for_server(
    repository: BrokerRepositoryProfile, server_name: str
) -> BrokerLink | None:
    if not state_path().exists() or state_backend() == LEGACY_JSON_BACKEND:
        return None
    server_definition_id = repository.server_id(server_name)
    with AccountStore.open_default(coordinator_home()) as store:
        return BrokerLinkStore(store).lease_for_server(
            repository.repo_id, server_definition_id
        )


def release_broker_lease_link(link: BrokerLink, *, rollback: bool) -> dict[str, Any]:
    release_operation_id = str(uuid.uuid4())
    with AccountStore.open_default(coordinator_home()) as store:
        links = BrokerLinkStore(store)
        pending = links.begin_lease_release(link.link_id, release_operation_id)
        release_operation_id = str(pending.release_operation_id or release_operation_id)
    service = BrokerServiceProfile(
        socket_path=Path(link.broker_socket),
        service_uid=link.broker_service_uid,
        socket_gid=link.broker_socket_gid,
        socket_mode=link.broker_socket_mode,
        database_generation=link.broker_database_generation,
    )
    try:
        _operation_id, result = call_broker(
            service=service,
            account_id=link.account_id,
            repo_id=link.repo_id,
            resource_id=link.broker_resource_id,
            operation=BrokerOperation.PORT_RELEASE,
            operation_id=release_operation_id,
        )
    except BaseException as error:
        payload = coordinator_exception_payload(error)
        with AccountStore.open_default(coordinator_home()) as store:
            BrokerLinkStore(store).fail_lease_release(
                link.link_id,
                operation_id=release_operation_id,
                error_code=str(payload.get("code") or "broker_release_failed"),
                error_message=str(payload.get("error") or error),
                rollback=rollback,
            )
        raise
    with AccountStore.open_default(coordinator_home()) as store:
        BrokerLinkStore(store).complete_lease_release(link.link_id)
    return result


def _validated_broker_assignment_result(
    result: dict[str, Any], *, expected_port: int
) -> tuple[str, int]:
    assignment_id = str(result.get("assignment_id") or "")
    try:
        port = int(result["port"])
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerError(
            "invalid_reply", "Broker assignment result omitted a valid port."
        ) from error
    if (
        not assignment_id
        or port != int(expected_port)
        or result.get("status") != "active"
    ):
        raise BrokerError(
            "invalid_reply", "Broker assignment result does not match the requested port."
        )
    return assignment_id, port


def acquire_broker_assignment_link(
    *,
    profile: BrokerClientProfile,
    repository: BrokerRepositoryProfile,
    server_name: str,
    port: int,
) -> tuple[BrokerLink, dict[str, Any]]:
    server_definition_id = repository.server_id(server_name)
    operation_id, result = profile.call(
        repository=repository,
        resource_id=server_definition_id,
        operation=BrokerOperation.PORT_ASSIGN,
        arguments={"port": int(port)},
    )
    assignment_id, assigned_port = _validated_broker_assignment_result(
        result, expected_port=port
    )
    try:
        with AccountStore.open_default(coordinator_home()) as store:
            link = BrokerLinkStore(store).reserve_assignment(
                profile=profile,
                repository=repository,
                server_name=server_name,
                server_definition_id=server_definition_id,
                broker_assignment_id=assignment_id,
                port=assigned_port,
                operation_id=operation_id,
            )
    except BaseException as local_error:
        rollback_id = str(uuid.uuid4())
        try:
            profile.call(
                repository=repository,
                resource_id=server_definition_id,
                operation=BrokerOperation.PORT_UNASSIGN,
                operation_id=rollback_id,
            )
        except BaseException as rollback_error:
            raise StructuredCoordinatorError(
                "broker assignment succeeded but local linkage and broker rollback both failed",
                {
                    "code": "broker_assignment_link_and_rollback_failed",
                    "classification": "reconciliation_required",
                    "broker_assignment_id": assignment_id,
                    "broker_operation_id": operation_id,
                    "rollback_operation_id": rollback_id,
                    "local_error": f"{type(local_error).__name__}: {local_error}",
                    "rollback_error": f"{type(rollback_error).__name__}: {rollback_error}",
                },
            ) from local_error
        raise
    return link, result


def release_broker_assignment_link(
    link: BrokerLink, *, rollback: bool
) -> dict[str, Any]:
    release_operation_id = str(uuid.uuid4())
    with AccountStore.open_default(coordinator_home()) as store:
        links = BrokerLinkStore(store)
        pending = links.begin_assignment_release(link.link_id, release_operation_id)
        release_operation_id = str(pending.release_operation_id or release_operation_id)
    service = BrokerServiceProfile(
        socket_path=Path(link.broker_socket),
        service_uid=link.broker_service_uid,
        socket_gid=link.broker_socket_gid,
        socket_mode=link.broker_socket_mode,
        database_generation=link.broker_database_generation,
    )
    try:
        _operation_id, result = call_broker(
            service=service,
            account_id=link.account_id,
            repo_id=link.repo_id,
            resource_id=link.server_definition_id,
            operation=BrokerOperation.PORT_UNASSIGN,
            operation_id=release_operation_id,
        )
    except BaseException as error:
        payload = coordinator_exception_payload(error)
        with AccountStore.open_default(coordinator_home()) as store:
            BrokerLinkStore(store).fail_assignment_release(
                link.link_id,
                operation_id=release_operation_id,
                error_code=str(payload.get("code") or "broker_unassign_failed"),
                error_message=str(payload.get("error") or error),
                rollback=rollback,
            )
        raise
    with AccountStore.open_default(coordinator_home()) as store:
        BrokerLinkStore(store).complete_assignment_release(link.link_id)
    return result


@normalized_guarded_action(RepositoryAction.LEASE, "port lease")
def coordinated_lease_port(options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "port lease")
    prime_git_head_identity(project)
    broker_context = configured_broker_context(project)
    if broker_context is not None:
        profile, repository = broker_context
        server_name = str(options.get("name") or "").strip()
        if not server_name:
            raise BrokerProfileError(
                "broker-backed port lease requires the enrolled server name (--name)"
            )
        link, broker_result = acquire_broker_lease_link(
            profile=profile,
            repository=repository,
            server_name=server_name,
            requested_port=(
                None if options.get("preferred") is None else int(options["preferred"])
            ),
            ttl_seconds=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
        )
        try:
            if state_backend() == LEGACY_JSON_BACKEND:
                with locked_state() as state:
                    local = lease_port(
                        state,
                        agent=agent,
                        project=project,
                        port_range=f"{link.port}-{link.port}",
                        preferred=link.port,
                        ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
                        purpose=str(options.get("purpose") or "manual"),
                    )
            else:
                with AccountStore.open_default(coordinator_home()) as store:
                    local = NormalizedPortLifecycle(store).lease(
                        PortLeaseRequest(
                            agent=agent,
                            canonical_project=project,
                            port_start=link.port,
                            port_end=link.port,
                            preferred=link.port,
                            ttl_seconds=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
                            purpose=str(options.get("purpose") or "manual"),
                        ),
                        port_available=lambda candidate: port_available(candidate),
                    )
            local["broker_lease_id"] = link.broker_resource_id
            local["broker_link_id"] = link.link_id
            local["broker_operation_id"] = link.broker_operation_id
            bound = bind_broker_lease_link(link.link_id, str(local["id"]))
        except BaseException as local_error:
            cleanup_errors: list[str] = []
            with contextlib.suppress(BaseException):
                if "local" in locals():
                    if state_backend() == LEGACY_JSON_BACKEND:
                        with locked_state() as state:
                            if str(local.get("id") or "") in state.get("leases", {}):
                                release_port(state, lease_id=str(local["id"]))
                    else:
                        with AccountStore.open_default(coordinator_home()) as store:
                            NormalizedPortLifecycle(store).release(
                                agent=agent,
                                canonical_project=project,
                                lease_id=str(local["id"]),
                            )
            try:
                release_broker_lease_link(link, rollback=True)
            except BaseException as rollback_error:
                cleanup_errors.append(
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
            if cleanup_errors:
                raise StructuredCoordinatorError(
                    "local broker-lease commit failed and rollback requires reconciliation",
                    {
                        "code": "broker_lease_local_commit_failed",
                        "classification": "reconciliation_required",
                        "broker_lease_id": link.broker_resource_id,
                        "local_error": f"{type(local_error).__name__}: {local_error}",
                        "cleanup_errors": cleanup_errors,
                    },
                ) from local_error
            raise
        return {
            **local,
            "broker": {
                "lease_id": bound.broker_resource_id,
                "link_id": bound.link_id,
                "operation_id": bound.broker_operation_id,
                "status": bound.status,
                "expires_at": broker_result.get("expires_at"),
            },
        }
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            return lease_port(
                state,
                agent=agent,
                project=project,
                port_range=str(options.get("range") or DEFAULT_RANGE),
                preferred=options.get("preferred"),
                ttl=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
                purpose=str(options.get("purpose") or "manual"),
            )
    port_start, port_end = parse_range(str(options.get("range") or DEFAULT_RANGE))
    with AccountStore.open_default(coordinator_home()) as store:
        return NormalizedPortLifecycle(store).lease(
            PortLeaseRequest(
                agent=agent,
                canonical_project=project,
                port_start=port_start,
                port_end=port_end,
                preferred=(
                    None
                    if options.get("preferred") is None
                    else int(options["preferred"])
                ),
                ttl_seconds=int(options.get("ttl") or DEFAULT_TTL_SECONDS),
                purpose=str(options.get("purpose") or "manual"),
            ),
            port_available=lambda candidate: port_available(candidate),
        )


def coordinated_release_port(options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "port release")
    prime_git_head_identity(project)
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            lease_id = options.get("lease_id")
            if not lease_id and options.get("port") is not None:
                port = int(options["port"])
                matches = [
                    item
                    for item in state.get("leases", {}).values()
                    if int(item.get("port") or 0) == port
                    and item.get("status") == "active"
                ]
                if len(matches) != 1:
                    raise KeyError(f"could not resolve one active lease for port {port}")
                lease_id = matches[0].get("id")
            lease = state.get("leases", {}).get(str(lease_id or ""))
            if lease is None:
                raise KeyError("matching lease not found")
            if canonical_project(str(lease.get("project") or "")) != project:
                raise PermissionError("lease belongs to another repository")
            resolved_lease_id = str(lease["id"])
    else:
        with AccountStore.open_default(coordinator_home()) as store:
            leases = NormalizedPortLifecycle(store).list_leases(active_only=True)
        if options.get("lease_id"):
            matches = [
                item
                for item in leases
                if str(item["id"]) == str(options["lease_id"])
            ]
        elif options.get("port") is not None:
            matches = [
                item for item in leases if int(item["port"]) == int(options["port"])
            ]
        else:
            raise ValueError("port release requires --lease-id or --port")
        if len(matches) != 1:
            raise KeyError("matching lease not found")
        lease = matches[0]
        if canonical_project(str(lease.get("project") or "")) != project:
            raise PermissionError("lease belongs to another repository")
        resolved_lease_id = str(lease["id"])
    link = broker_lease_link_for_local(resolved_lease_id)
    broker_result = None
    if link is not None:
        broker_result = release_broker_lease_link(link, rollback=False)
    try:
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                released = release_port_for_identity(
                    state,
                    agent=agent,
                    project=project,
                    lease_id=resolved_lease_id,
                    port=None,
                )
        else:
            with AccountStore.open_default(coordinator_home()) as store:
                released = NormalizedPortLifecycle(store).release(
                    agent=agent,
                    canonical_project=project,
                    lease_id=resolved_lease_id,
                )
    except BaseException as local_error:
        if link is not None:
            raise StructuredCoordinatorError(
                "host-global broker lease was released, but the local lease record needs reconciliation",
                {
                    "code": "local_lease_release_reconciliation_required",
                    "classification": "reconciliation_required",
                    "broker_lease_id": link.broker_resource_id,
                    "broker_result": broker_result,
                    "local_error": f"{type(local_error).__name__}: {local_error}",
                },
            ) from local_error
        raise
    if link is not None:
        released["broker"] = {
            "lease_id": link.broker_resource_id,
            "status": "released",
            "result": broker_result,
        }
    return released


@normalized_guarded_action(RepositoryAction.LEASE, "port assign")
def coordinated_assign_port(options: dict[str, Any]) -> dict[str, Any]:
    agent, project = require_identity(options, "port assign")
    prime_git_head_identity(project)
    broker_context = configured_broker_context(project)
    if broker_context is not None:
        profile, repository = broker_context
        name = str(options.get("name") or "").strip()
        port = int(options["port"])
        link, broker_result = acquire_broker_assignment_link(
            profile=profile,
            repository=repository,
            server_name=name,
            port=port,
        )
        try:
            if state_backend() == LEGACY_JSON_BACKEND:
                with locked_state() as state:
                    assignment = assign_port(
                        state,
                        agent=agent,
                        project=project,
                        name=name,
                        port=port,
                        force=bool(options.get("force")),
                    )
            else:
                with AccountStore.open_default(coordinator_home()) as store:
                    assignment = NormalizedPortLifecycle(store).assign(
                        agent=agent,
                        canonical_project=project,
                        name=name,
                        port=port,
                        force=bool(options.get("force")),
                    )
            assignment["broker_assignment_id"] = link.broker_resource_id
            assignment["broker_link_id"] = link.link_id
            local_assignment_id = deterministic_id(
                "port-assignment", repository.repo_id, name
            )
            with AccountStore.open_default(coordinator_home()) as store:
                bound = BrokerLinkStore(store).bind_local_assignment(
                    link.link_id, local_assignment_id
                )
        except BaseException as local_error:
            with contextlib.suppress(BaseException):
                if state_backend() == LEGACY_JSON_BACKEND:
                    with locked_state() as state:
                        unassign_port(
                            state,
                            agent=agent,
                            project=project,
                            name=name,
                            port=port,
                            force=True,
                        )
                else:
                    with AccountStore.open_default(coordinator_home()) as store:
                        NormalizedPortLifecycle(store).unassign(
                            agent=agent,
                            canonical_project=project,
                            name=name,
                            port=port,
                            force=True,
                        )
            try:
                release_broker_assignment_link(link, rollback=True)
            except BaseException as rollback_error:
                raise StructuredCoordinatorError(
                    "local assignment commit failed and broker rollback requires reconciliation",
                    {
                        "code": "broker_assignment_local_commit_failed",
                        "classification": "reconciliation_required",
                        "broker_assignment_id": link.broker_resource_id,
                        "local_error": f"{type(local_error).__name__}: {local_error}",
                        "rollback_error": f"{type(rollback_error).__name__}: {rollback_error}",
                    },
                ) from local_error
            raise
        return {
            **assignment,
            "broker": {
                "assignment_id": bound.broker_resource_id,
                "link_id": bound.link_id,
                "operation_id": bound.broker_operation_id,
                "status": bound.status,
                "result": broker_result,
            },
        }
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            return assign_port(
                state,
                agent=agent,
                project=project,
                name=str(options.get("name") or ""),
                port=int(options["port"]),
                force=bool(options.get("force")),
            )
    with AccountStore.open_default(coordinator_home()) as store:
        return NormalizedPortLifecycle(store).assign(
            agent=agent,
            canonical_project=project,
            name=str(options.get("name") or ""),
            port=int(options["port"]),
            force=bool(options.get("force")),
        )


def coordinated_unassign_port(options: dict[str, Any]) -> dict[str, Any]:
    agent, requested_project = require_identity(options, "port unassign")
    if state_backend() == LEGACY_JSON_BACKEND:
        with locked_state() as state:
            matching = None
            for candidate in state.setdefault("port_assignments", {}).values():
                if options.get("name") is not None and (
                    str(candidate.get("name") or "") != str(options["name"])
                    or canonical_project(str(candidate.get("project") or ""))
                    != requested_project
                ):
                    continue
                if options.get("port") is not None and int(
                    candidate.get("port") or 0
                ) != int(options["port"]):
                    continue
                matching = copy.deepcopy(candidate)
                break
    else:
        with AccountStore.open_default(coordinator_home()) as store:
            assignments = NormalizedPortLifecycle(store).list_assignments(
                canonical_project=(
                    requested_project if options.get("name") is not None else None
                ),
                active_only=True,
            )
        matching = next(
            (
                candidate
                for candidate in assignments
                if (
                    options.get("name") is None
                    or str(candidate["name"]) == str(options["name"])
                )
                and (
                    options.get("port") is None
                    or int(candidate["port"]) == int(options["port"])
                )
            ),
            None,
        )
    if matching is None:
        raise KeyError("matching port assignment not found")
    owner_project = canonical_project(str(matching["project"]))
    if owner_project != requested_project and not bool(options.get("force")):
        raise PermissionError(
            f"port {matching['port']} is durably assigned to server "
            f"'{matching['name']}' of {owner_project}; pass --force to remove "
            "another project's assignment"
        )
    name = str(matching["name"])
    selector_name = (
        str(options["name"]) if options.get("name") is not None else None
    )
    broker_context = configured_broker_context(owner_project)
    broker_result = None
    link = None
    if broker_context is not None:
        _profile, repository = broker_context
        server_definition_id = repository.server_id(name)
        with AccountStore.open_default(coordinator_home()) as store:
            link = BrokerLinkStore(store).assignment_for_server(
                repository.repo_id, server_definition_id
            )
        if link is None:
            raise BrokerProfileError(
                "configured broker assignment has no exact local linkage; reconcile it before unassigning"
            )
        broker_result = release_broker_assignment_link(link, rollback=False)
    try:
        if state_backend() == LEGACY_JSON_BACKEND:
            with locked_state() as state:
                removed = unassign_port(
                    state,
                    agent=agent,
                    project=requested_project,
                    name=selector_name,
                    port=int(matching["port"]),
                    force=bool(options.get("force")),
                )
        else:
            with AccountStore.open_default(coordinator_home()) as store:
                removed = NormalizedPortLifecycle(store).unassign(
                    agent=agent,
                    canonical_project=requested_project,
                    name=selector_name,
                    port=int(matching["port"]),
                    force=bool(options.get("force")),
                )
    except BaseException as local_error:
        if link is not None:
            raise StructuredCoordinatorError(
                "host-global assignment was released, but the local assignment record needs reconciliation",
                {
                    "code": "local_assignment_release_reconciliation_required",
                    "classification": "reconciliation_required",
                    "broker_assignment_id": link.broker_resource_id,
                    "broker_result": broker_result,
                    "local_error": f"{type(local_error).__name__}: {local_error}",
                },
            ) from local_error
        raise
    if link is not None:
        removed["broker"] = {
            "assignment_id": link.broker_resource_id,
            "status": "released",
            "result": broker_result,
        }
    return removed


def coordinated_relocate_port_assignment(options: dict[str, Any]) -> dict[str, Any]:
    agent = str(options.get("agent") or "").strip()
    if not agent:
        raise ValueError("port relocate requires --agent")
    old_project = canonical_project(str(options.get("old_project") or ""))
    new_project = canonical_project(str(options.get("new_project") or ""))
    with normalized_repository_action_guard(
        project=new_project, agent=agent, action=RepositoryAction.LEASE
    ):
        prime_git_head_identity(old_project)
        prime_git_head_identity(new_project)
        if state_backend() != LEGACY_JSON_BACKEND:
            name = str(options.get("name") or "")
            port = int(options["port"])
            lease_id = str(options.get("lease_id") or "")
            with AccountStore.open_default(coordinator_home()) as store:
                lifecycle = NormalizedServerLifecycle(store)
                snapshot = lifecycle.relocation_snapshot(
                    old_project=old_project,
                    name=name,
                    port=port,
                    lease_id=lease_id,
                )
            listener_evidence = listener_evidence_for_port(port)
            recorded_pid = int(snapshot.get("pid") or 0)
            process_is_alive = bool(recorded_pid and pid_alive(recorded_pid))
            with AccountStore.open_default(coordinator_home()) as store:
                relocated = NormalizedServerLifecycle(store).relocate(
                    agent=agent,
                    old_project=old_project,
                    new_project=new_project,
                    name=name,
                    port=port,
                    lease_id=lease_id,
                    listener_present=bool(listener_evidence.get("present")),
                    process_alive=process_is_alive,
                )
            result = normalized_public_server(relocated)
            result["listener_evidence"] = listener_evidence
            return result
        with locked_state() as state:
            return relocate_port_assignment(
                state,
                agent=agent,
                old_project=old_project,
                new_project=new_project,
                name=str(options.get("name") or ""),
                port=int(options["port"]),
                lease_id=str(options.get("lease_id") or ""),
            )


def print_result(value: Any, *, as_json: bool = True, compact_json: bool = False) -> None:
    if as_json:
        if compact_json:
            print(json.dumps(value, separators=(",", ":"), sort_keys=True))
        else:
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


def parse_stats_history_limit(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("stats history limit must be an integer") from exc
    if not 0 <= value <= DOCKER_STATS_HISTORY_LIMIT:
        raise argparse.ArgumentTypeError(
            f"stats history limit must be between 0 and {DOCKER_STATS_HISTORY_LIMIT}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Coordinate Codex dev ports, servers, and Docker.")
    sub = parser.add_subparsers(dest="group", required=True)

    inventory = sub.add_parser("inventory")
    inventory.add_argument("--project")
    inventory.add_argument("--backup-dir", action="append")
    inventory.add_argument("--no-docker", action="store_true")
    inventory.add_argument(
        "--compact-json",
        action="store_true",
        help="emit inventory as one compact JSON line",
    )
    inventory.add_argument(
        "--stats-history-limit",
        type=parse_stats_history_limit,
        default=DOCKER_STATS_HISTORY_LIMIT,
        metavar="N",
        help=f"return the newest N Docker stats samples per container (0-{DOCKER_STATS_HISTORY_LIMIT})",
    )

    observe = sub.add_parser(
        "observe",
        help="explicitly sample host runtime state once and persist normalized observations",
    )
    observe.add_argument("--agent", required=True)
    observe.add_argument("--project", required=True)
    observe.add_argument("--max-age-seconds", type=float, default=0.0)
    observe.add_argument("--backup-dir", action="append")
    observe.add_argument("--no-docker", action="store_true")
    observe.add_argument("--compact-json", action="store_true")
    observe.add_argument(
        "--legacy-home",
        action="append",
        help="explicit same-UID legacy coordinator home (migration/testing override)",
    )
    observe.add_argument(
        "--legacy-backup-root",
        help="private backup root outside Git for captured legacy state",
    )

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
    lease.add_argument(
        "--name",
        help="enrolled server identity (required when the host broker is configured)",
    )
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

    add_lifecycle_parsers(sub)
    add_broker_parser(sub)

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
    if args.group in {"repository", "resource"}:
        return handle_lifecycle_cli(
            args,
            coordinator_home=coordinator_home(),
            canonical_project=canonical_project,
            bootstrap_legacy_import=bootstrap_legacy_import,
            observe_before_plan=lambda project, agent: coordinated_observe_host(
                {
                    "project": project,
                    "agent": agent,
                    "max_age_seconds": 0,
                    "no_docker": False,
                    "backup_dir": None,
                    "legacy_home": [],
                    "legacy_backup_root": None,
                }
            ),
            observe_before_apply=lambda project, agent: coordinated_observe_host(
                {
                    "project": project,
                    "agent": agent,
                    "max_age_seconds": 0,
                    "no_docker": False,
                    "backup_dir": None,
                    "legacy_home": [],
                    "legacy_backup_root": None,
                }
            ),
        )
    if args.group == "broker" and args.action == "enroll":
        return coordinated_broker_enroll(args)
    if args.group == "broker":
        return handle_broker_cli(args)
    if args.group == "observe":
        return coordinated_observe_host(namespace_to_options(args))
    if args.group == "state" and args.action == "reset":
        if not args.force:
            raise SystemExit("--force is required")
        identity = namespace_to_options(args)
        agent, project = require_identity(identity, "state reset")
        if state_backend() != LEGACY_JSON_BACKEND:
            raise RuntimeError(
                "state reset is available only with "
                f"{STATE_BACKEND_ENV}={LEGACY_JSON_BACKEND}; the normalized "
                "product backend must be decommissioned through exact "
                "repository/resource lifecycle commands"
            )
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
            stats_history_limit=args.stats_history_limit,
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
        return coordinated_lease_port(namespace_to_options(args))
    if args.group == "port" and args.action == "assign":
        return coordinated_assign_port(namespace_to_options(args))
    if args.group == "port" and args.action == "relocate":
        return coordinated_relocate_port_assignment(namespace_to_options(args))
    if args.group == "port" and args.action == "release":
        return coordinated_release_port(namespace_to_options(args))
    if args.group == "port" and args.action == "unassign":
        return coordinated_unassign_port(namespace_to_options(args))
    if state_backend() != LEGACY_JSON_BACKEND:
        if args.group == "state" and args.action == "show":
            return normalized_control_snapshot()
        if args.group == "port" and args.action == "list":
            with AccountStore.open_default(coordinator_home()) as store:
                return NormalizedPortLifecycle(store).list_leases(active_only=True)
        if args.group == "port" and args.action == "assignments":
            requested_project = (
                canonical_project(args.project) if args.project is not None else None
            )
            with AccountStore.open_default(coordinator_home()) as store:
                return NormalizedPortLifecycle(store).list_assignments(
                    canonical_project=requested_project,
                    active_only=True,
                )
        if args.group == "server" and args.action == "list":
            return list(normalized_control_snapshot()["servers"].values())
    with locked_state() as state:
        if args.group == "state" and args.action == "show":
            return state
        if args.group == "port" and args.action == "list":
            return list(state["leases"].values())
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
        "/v1/inventory/no-docker",
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
        "/v1/ports/relocate",
    }
)


def parse_registration_inventory_query(raw_query: str) -> dict[str, Any] | None:
    """Parse the exact target for the bounded registration-readiness view."""

    if not raw_query:
        return None
    values = parse_qs(
        raw_query,
        keep_blank_values=True,
        strict_parsing=True,
        max_num_fields=3,
    )
    required = {"project", "name", "port"}
    if set(values) != required or any(len(values[key]) != 1 for key in required):
        raise ValueError(
            "registration inventory query requires exactly one project, name, and port"
        )
    project = values["project"][0]
    name = values["name"][0].strip()
    if not project or not Path(project).is_absolute() or not name or len(name) > 200:
        raise ValueError(
            "registration inventory query requires an absolute project and valid server name"
        )
    try:
        port = int(values["port"][0])
    except ValueError as exc:
        raise ValueError("registration inventory query port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("registration inventory query port must be between 1 and 65535")
    return {"project": project, "name": name, "port": port}


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

    def _handle_get(self, path: str, raw_query: str = "") -> None:
        try:
            if path == "/v1/inventory":
                result: Any = coordinated_build_inventory()
            elif path == "/v1/inventory/no-docker":
                target = parse_registration_inventory_query(raw_query)
                # An ordinary no-Docker inventory remains a pure committed
                # snapshot. The systemd readiness client supplies an exact
                # target when it needs bounded current listener proof.
                result = (
                    pure_normalized_inventory(include_docker=False)
                    if target is None and state_backend() != LEGACY_JSON_BACKEND
                    else coordinated_build_inventory(include_docker=False)
                    if target is None
                    else coordinated_build_registration_inventory(**target)
                )
            elif path in {"/v1/state", "/v1/ports", "/v1/ports/assignments", "/v1/servers"}:
                if state_backend() == LEGACY_JSON_BACKEND:
                    snapshot = snapshot_coordinator_state()
                    if path == "/v1/state":
                        result = snapshot
                    elif path == "/v1/ports":
                        result = list(snapshot["leases"].values())
                    elif path == "/v1/ports/assignments":
                        result = list_port_assignments(snapshot)
                    else:
                        result = list(snapshot["servers"].values())
                elif path in {"/v1/ports", "/v1/ports/assignments"}:
                    with AccountStore.open_default(coordinator_home()) as store:
                        ports = NormalizedPortLifecycle(store)
                        result = (
                            ports.list_leases(active_only=True)
                            if path == "/v1/ports"
                            else ports.list_assignments(active_only=True)
                        )
                else:
                    snapshot = normalized_control_snapshot()
                    result = (
                        snapshot
                        if path == "/v1/state"
                        else list(snapshot["servers"].values())
                    )
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(200, result)
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
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
                self._send(200, coordinated_lease_port(payload))
                return
            elif path == "/v1/ports/release":
                self._send(200, coordinated_release_port(payload))
                return
            elif path == "/v1/ports/relocate":
                self._send(200, coordinated_relocate_port_assignment(payload))
                return
            elif path in {"/v1/ports/assign", "/v1/ports/unassign"}:
                assignment_agent = str(payload.get("agent") or "").strip()
                if not assignment_agent:
                    raise ValueError("port assignment mutation requires agent attribution")
                payload["agent"] = assignment_agent
                if path == "/v1/ports/assign":
                    # The guarded public helper must be the first repository
                    # mutation boundary. In particular, do not invoke Git to
                    # prime identity before a disabled repository is rejected.
                    self._send(200, coordinated_assign_port(payload))
                    return
                self._send(200, coordinated_unassign_port(payload))
                return
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(404, {"error": "not found"})
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
        parsed_request = urlparse(self.path)
        path = parsed_request.path
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
            self._handle_get(path, parsed_request.query)
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
    if args.group == "broker" and args.action == "serve":
        try:
            clear_exec_capability_inheritance()
            serve_broker(
                args,
                observe_before_lifecycle_plan=observe_broker_service_store_for_enrollment,
            )
            return 0
        except Exception as exc:
            print(json.dumps(coordinator_exception_payload(exc), indent=2, sort_keys=True), file=sys.stderr)
            return 1
    try:
        print_result(handle_cli(args), compact_json=bool(getattr(args, "compact_json", False)))
        return 0
    except Exception as exc:
        print(json.dumps(coordinator_exception_payload(exc), indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
