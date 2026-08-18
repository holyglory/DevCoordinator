"""Fast trusted-host Unix transport for the isolated test plane.

Any process which can connect to the local Unix socket is trusted on this
single-developer server.  Kernel peer credentials are attribution only;
requests carry operation IDs for idempotency, never bearer tokens or message
signatures.
"""

from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import time
from typing import Callable, Mapping
import uuid

from .call_journal import (
    RollingCallJournal,
    diagnostic_for_exception,
    event_record,
    monotonic_started,
)
from .universal_test_service import (
    MAX_TEST_PLANE_RESPONSE_BYTES,
    StoreTestPlaneAdapter,
    TestPlaneClient,
    TestPlanPreviewUnavailable,
)
from .universal_test_store import (
    LiveRetryReplanRequired,
    TargetResources,
    TestStoreConflict,
    TestStoreContractError,
    TestStoreNotFound,
)


TEST_PLANE_TRANSPORT_SCHEMA_VERSION = 1
MAX_TEST_PLANE_FRAME_BYTES = 768 * 1024
DEFAULT_TEST_PLANE_TIMEOUT_SECONDS = 10.0
TEST_CATALOG_READ_TIMEOUT_SECONDS = 60.0
TEST_SETUP_READ_TIMEOUT_SECONDS = 60.0
DEFAULT_TEST_PLAN_PREVIEW_TIMEOUT_SECONDS = 180.0
DEFAULT_TEST_PLANE_CONCURRENCY = 8
LOGGER = logging.getLogger(__name__)

TEST_HEALTH = "test.health"
TEST_REPOSITORY_SETUP = "test.repository_setup"
TEST_REPOSITORY_CATALOG = "test.repository_catalog"
TEST_DASHBOARD_STATS = "test.dashboard_stats"
TEST_DASHBOARD_FLEET = "test.dashboard_fleet"
TEST_PLAN_PREVIEW = "test.plan_preview"
TEST_PLAN_REGISTER = "test.plan_register"
TEST_PLAN_REPOSITORY = "test.plan_repository"
TEST_RUN_SUBMIT = "test.run_submit"
TEST_RUN_LIST = "test.run_list"
TEST_QUEUE_STATUS = "test.queue_status"
TEST_RUN_STATUS = "test.run_status"
TEST_RUN_SUMMARY = "test.run_summary"
TEST_RUN_FAILURES = "test.run_failures"
TEST_RUN_ARTIFACTS = "test.run_artifacts"
TEST_ARTIFACT_RESOLVE = "test.artifact_resolve"
TEST_RUN_CASES = "test.run_cases"
TEST_RUN_CANCEL = "test.run_cancel"
TEST_RUN_RETRY = "test.run_retry"
TEST_EVENTS_READ = "test.events_read"
TEST_EVIDENCE_CHECK = "test.evidence_check"
TEST_EVIDENCE_CONSUME = "test.evidence_consume"
TEST_STATS_READ = "test.stats_read"
TEST_FLEET_OVERVIEW = "test.fleet_overview"
TEST_REPOSITORY_DETAIL = "test.repository_detail"

TEST_PLANE_OPERATIONS = frozenset(
    {
        TEST_HEALTH,
        TEST_REPOSITORY_SETUP,
        TEST_REPOSITORY_CATALOG,
        TEST_DASHBOARD_STATS,
        TEST_DASHBOARD_FLEET,
        TEST_PLAN_PREVIEW,
        TEST_PLAN_REGISTER,
        TEST_PLAN_REPOSITORY,
        TEST_RUN_SUBMIT,
        TEST_RUN_LIST,
        TEST_QUEUE_STATUS,
        TEST_RUN_STATUS,
        TEST_RUN_SUMMARY,
        TEST_RUN_FAILURES,
        TEST_RUN_ARTIFACTS,
        TEST_ARTIFACT_RESOLVE,
        TEST_RUN_CASES,
        TEST_RUN_CANCEL,
        TEST_RUN_RETRY,
        TEST_EVENTS_READ,
        TEST_EVIDENCE_CHECK,
        TEST_EVIDENCE_CONSUME,
        TEST_STATS_READ,
        TEST_FLEET_OVERVIEW,
        TEST_REPOSITORY_DETAIL,
    }
)

_OPERATION_ARGUMENTS = {
    TEST_HEALTH: (frozenset(), frozenset()),
    TEST_REPOSITORY_SETUP: (
        frozenset({"repository_id", "owner_uid"}),
        frozenset(),
    ),
    TEST_REPOSITORY_CATALOG: (
        frozenset({"repository_ids"}),
        frozenset(),
    ),
    TEST_DASHBOARD_STATS: (
        frozenset({"repository_id", "days"}),
        frozenset({"limit"}),
    ),
    TEST_DASHBOARD_FLEET: (
        frozenset({"repository_ids", "hours"}),
        frozenset(),
    ),
    TEST_PLAN_PREVIEW: (
        frozenset({"repository_id", "intent", "actor", "owner_uid"}),
        frozenset(
            {
                "temporary_root",
                "requested_targets",
                "access_uid",
                "execution_timeout_seconds",
                "launch_timeout_seconds",
                "launch_deadline_monotonic",
            }
        ),
    ),
    TEST_PLAN_REGISTER: (
        frozenset({"plan_document"}),
        frozenset({"target_resources"}),
    ),
    TEST_PLAN_REPOSITORY: (
        frozenset({"plan_id", "repository_id"}),
        frozenset(),
    ),
    TEST_RUN_SUBMIT: (
        frozenset(
            {"plan_id", "repository_id", "operation_id", "actor", "owner_uid"}
        ),
        frozenset({"priority", "target_resources"}),
    ),
    TEST_RUN_LIST: (
        frozenset({"repository_id"}),
        frozenset({"after", "limit", "state"}),
    ),
    TEST_QUEUE_STATUS: (frozenset({"repository_id"}), frozenset()),
    TEST_RUN_STATUS: (frozenset({"run_id", "repository_id"}), frozenset()),
    TEST_RUN_SUMMARY: (frozenset({"run_id", "repository_id"}), frozenset()),
    TEST_RUN_FAILURES: (
        frozenset({"run_id", "repository_id"}),
        frozenset({"after", "limit"}),
    ),
    TEST_RUN_ARTIFACTS: (
        frozenset({"run_id", "repository_id"}),
        frozenset({"after", "limit"}),
    ),
    TEST_ARTIFACT_RESOLVE: (
        frozenset({"run_id", "repository_id", "artifact_id"}),
        frozenset(),
    ),
    TEST_RUN_CASES: (
        frozenset({"run_id", "repository_id"}),
        frozenset({"after", "limit"}),
    ),
    TEST_RUN_CANCEL: (
        frozenset(
            {"run_id", "repository_id", "actor", "reason", "operation_id"}
        ),
        frozenset(),
    ),
    TEST_RUN_RETRY: (
        frozenset(
            {"run_id", "repository_id", "actor", "failed_only", "operation_id"}
        ),
        frozenset(),
    ),
    TEST_EVENTS_READ: (
        frozenset({"repository_id"}),
        frozenset({"after_event_id", "limit"}),
    ),
    TEST_EVIDENCE_CHECK: (
        frozenset({"repository_id", "snapshot_id", "policy_name"}),
        frozenset(),
    ),
    TEST_EVIDENCE_CONSUME: (
        frozenset(
            {"repository_id", "snapshot_id", "policy_name", "operation_id"}
        ),
        frozenset(),
    ),
    TEST_STATS_READ: (
        frozenset({"repository_id", "grain", "since"}),
        frozenset({"limit"}),
    ),
    TEST_FLEET_OVERVIEW: (
        frozenset({"grain", "since"}),
        frozenset({"repository_limit", "bucket_limit"}),
    ),
    TEST_REPOSITORY_DETAIL: (
        frozenset({"repository_id", "grain", "since"}),
        frozenset({"limit"}),
    ),
}


class TestPlaneTransportError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _encode(value: object, *, maximum: int = MAX_TEST_PLANE_FRAME_BYTES) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise TestPlaneTransportError("invalid_json", "test-plane JSON is invalid") from error
    if not payload or len(payload) > maximum:
        raise TestPlaneTransportError(
            "frame_too_large", "test-plane frame exceeds its byte bound"
        )
    return payload


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except socket.timeout as error:
            raise TestPlaneTransportError(
                "request_timeout", "test-plane request timed out"
            ) from error
        if not chunk:
            raise TestPlaneTransportError(
                "incomplete_frame", "test-plane connection closed mid-frame"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_frame(connection: socket.socket) -> bytes:
    size = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if not 1 <= size <= MAX_TEST_PLANE_FRAME_BYTES:
        raise TestPlaneTransportError(
            "frame_too_large", "test-plane frame size is invalid"
        )
    return _receive_exact(connection, size)


def _send_frame(connection: socket.socket, document: Mapping[str, object]) -> None:
    payload = _encode(document)
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _decode(payload: bytes) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TestPlaneTransportError(
            "invalid_json", "test-plane request is not valid JSON"
        ) from error
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TestPlaneTransportError(
            "invalid_request", "test-plane request must be an object"
        )
    return value


def _peer_identity(
    connection: socket.socket,
) -> tuple[int | None, int | None, int | None]:
    """Return best-effort PID/UID/GID attribution without authorizing the call."""

    if connection.family != socket.AF_UNIX:
        return None, None, None
    option = getattr(socket, "SO_PEERCRED", None)
    if option is not None:
        try:
            raw = connection.getsockopt(
                socket.SOL_SOCKET, option, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", raw[: struct.calcsize("3i")])
            return (
                int(pid) if int(pid) >= 0 else None,
                int(uid) if int(uid) >= 0 else None,
                int(gid) if int(gid) >= 0 else None,
            )
        except (OSError, struct.error, ValueError):
            return None, None, None
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, gid = getpeereid()
            return (
                None,
                int(uid) if int(uid) >= 0 else None,
                int(gid) if int(gid) >= 0 else None,
            )
        except (OSError, TypeError, ValueError):
            return None, None, None
    return None, None, None


def _peer_uid(connection: socket.socket) -> int | None:
    """Compatibility wrapper returning only the attributed UID."""

    return _peer_identity(connection)[1]


def _request_correlations(
    arguments: object,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract only bounded identity fields; never copy a request payload."""

    if not isinstance(arguments, Mapping):
        return None, None, None, None
    repository_id = arguments.get("repository_id")
    run_id = arguments.get("run_id")
    attempt_id = arguments.get("attempt_id")
    operation_id = arguments.get("operation_id")
    return (
        repository_id if isinstance(repository_id, str) else None,
        run_id if isinstance(run_id, str) else None,
        attempt_id if isinstance(attempt_id, str) else None,
        operation_id if isinstance(operation_id, str) else None,
    )


def _target_resources(value: object) -> Mapping[str, TargetResources] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TestStoreContractError("target_resources must be an object")
    result: dict[str, TargetResources] = {}
    fields = set(TargetResources.__dataclass_fields__)
    for name, raw in value.items():
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise TestStoreContractError("target resource fields are invalid")
        result[name] = TargetResources(
            cpu_millis=raw["cpu_millis"],
            memory_mib=raw["memory_mib"],
            pids=raw["pids"],
            estimated_seconds=raw["estimated_seconds"],
            shard_count=raw["shard_count"],
            max_attempts=raw["max_attempts"],
            worktree_key=raw["worktree_key"],
            exclusive_resources=tuple(raw["exclusive_resources"]),
        )
    return result


def _resource_documents(
    values: Mapping[str, TargetResources] | None,
) -> Mapping[str, object] | None:
    if values is None:
        return None
    return {
        name: {
            "cpu_millis": value.cpu_millis,
            "memory_mib": value.memory_mib,
            "pids": value.pids,
            "estimated_seconds": value.estimated_seconds,
            "shard_count": value.shard_count,
            "max_attempts": value.max_attempts,
            "worktree_key": value.worktree_key,
            "exclusive_resources": list(value.exclusive_resources),
        }
        for name, value in values.items()
    }


class TestPlaneDispatcher:
    """Fixed-operation request router around :class:`TestPlaneClient`."""

    def __init__(
        self,
        service: TestPlaneClient,
        *,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        if not isinstance(service, TestPlaneClient):
            raise TestStoreContractError("test-plane service is invalid")
        self.service = service
        self.call_journal = call_journal

    def _record(
        self,
        *,
        phase: str,
        call_id: str,
        operation: str | None,
        request_id: str | None,
        peer_uid: int | None,
        peer_gid: int | None,
        peer_pid: int | None,
        arguments: object,
        started_at: float,
        outcome: str,
        code: str | None = None,
        message: str | None = None,
        diagnostic: Mapping[str, object] | None = None,
        result: object = None,
    ) -> None:
        if self.call_journal is None:
            return
        repository_id, run_id, attempt_id, operation_id = _request_correlations(
            arguments
        )
        result_repository, result_run, result_attempt, _ = _request_correlations(
            result
        )
        self.call_journal.record(
            event_record(
                boundary="test_plane",
                phase=phase,
                call_id=call_id,
                operation=operation,
                operation_id=operation_id,
                request_id=request_id,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                duration_seconds=(
                    None
                    if phase == "received"
                    else time.monotonic() - started_at
                ),
                outcome=outcome,
                code=code,
                message=message,
                repository_id=repository_id or result_repository,
                run_id=run_id or result_run,
                attempt_id=attempt_id or result_attempt,
                diagnostic=diagnostic,
            )
        )

    def dispatch(
        self,
        payload: bytes,
        *,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
        call_id: str | None = None,
        started_at: float | None = None,
    ) -> Mapping[str, object]:
        call_id = call_id or str(uuid.uuid4())
        started_at = monotonic_started() if started_at is None else started_at
        request_id: str | None = None
        operation: str | None = None
        arguments: object = None
        received_recorded = False
        try:
            request = _decode(payload)
            if set(request) != {"schema_version", "request_id", "operation", "arguments"}:
                raise TestPlaneTransportError(
                    "invalid_request", "test-plane request fields are invalid"
                )
            if request["schema_version"] != TEST_PLANE_TRANSPORT_SCHEMA_VERSION:
                raise TestPlaneTransportError(
                    "unsupported_schema", "test-plane schema is unsupported"
                )
            try:
                request_id = str(uuid.UUID(str(request["request_id"])))
            except (TypeError, ValueError, AttributeError) as error:
                raise TestPlaneTransportError(
                    "invalid_request", "test-plane request_id is invalid"
                ) from error
            candidate_operation = request["operation"]
            operation = (
                candidate_operation
                if isinstance(candidate_operation, str)
                else None
            )
            if (
                not isinstance(candidate_operation, str)
                or candidate_operation not in TEST_PLANE_OPERATIONS
            ):
                raise TestPlaneTransportError(
                    "unsupported_operation", "test-plane operation is unsupported"
                )
            arguments = request["arguments"]
            if not isinstance(arguments, Mapping) or any(
                not isinstance(key, str) for key in arguments
            ):
                raise TestPlaneTransportError(
                    "invalid_request", "test-plane arguments must be an object"
                )
            required, optional = _OPERATION_ARGUMENTS[operation]
            missing = required - set(arguments)
            extra = set(arguments) - required - optional
            if missing or extra:
                raise TestPlaneTransportError(
                    "invalid_request", "test-plane operation arguments are invalid"
                )
            self._record(
                phase="received",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                arguments=arguments,
                started_at=started_at,
                outcome="received",
            )
            received_recorded = True
            result = self._invoke(operation, arguments)
            response = {
                "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
                "request_id": request_id,
                "ok": True,
                "result": result,
            }
            self._record(
                phase="completed",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                arguments=arguments,
                started_at=started_at,
                outcome="ok",
                result=result,
            )
            return response
        except Exception as error:
            if isinstance(error, TestPlaneTransportError):
                code, message = error.code, error.message
            elif isinstance(error, TestPlanPreviewUnavailable):
                code, message = error.code, str(error)
            elif (
                isinstance(getattr(error, "code", None), str)
                and str(getattr(error, "code")).startswith("snapshot_")
            ):
                code, message = str(getattr(error, "code")), str(error)
            elif isinstance(error, TestStoreNotFound):
                code, message = "not_found", str(error)
            elif isinstance(error, LiveRetryReplanRequired):
                code, message = error.code, str(error)
            elif isinstance(error, TestStoreConflict):
                code, message = "conflict", str(error)
            elif isinstance(error, TestStoreContractError):
                code, message = (
                    ("test_plan_source_invalid", str(error))
                    if operation == TEST_PLAN_PREVIEW
                    else ("invalid_request", str(error))
                )
            elif isinstance(error, TypeError):
                code, message = "invalid_request", "test-plane arguments are invalid"
            else:
                code, message = "internal_error", "test-plane operation failed"
            diagnostic = getattr(error, "diagnostic", None)
            if not isinstance(diagnostic, Mapping):
                diagnostic = diagnostic_for_exception(
                    error, stage=f"test_plane.{operation or 'decode'}"
                )
            if not received_recorded:
                self._record(
                    phase="received",
                    call_id=call_id,
                    operation=operation,
                    request_id=request_id,
                    peer_uid=peer_uid,
                    peer_gid=peer_gid,
                    peer_pid=peer_pid,
                    arguments=arguments,
                    started_at=started_at,
                    outcome="received",
                )
            LOGGER.warning(
                "test-plane request failed code=%s exception=%s operation=%s "
                "request_id=%s peer_uid=%s",
                code,
                type(error).__name__,
                operation or "-",
                request_id or "-",
                peer_uid if peer_uid is not None else "-",
            )
            response = {
                "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
                "request_id": request_id,
                "ok": False,
                "error": {"code": code, "message": message[:2048]},
            }
            self._record(
                phase="rejected",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                arguments=arguments,
                started_at=started_at,
                outcome=("timeout" if "timeout" in code else "rejected"),
                code=code,
                message=message,
                diagnostic=diagnostic,
            )
            return response

    def _invoke(
        self, operation: str, arguments: Mapping[str, object]
    ) -> Mapping[str, object]:
        if operation == TEST_HEALTH:
            return self.service.health()
        if operation == TEST_REPOSITORY_SETUP:
            return self.service.setup(**arguments)
        if operation == TEST_REPOSITORY_CATALOG:
            return self.service.repository_catalog(**arguments)
        if operation == TEST_DASHBOARD_STATS:
            return self.service.dashboard_stats(**arguments)
        if operation == TEST_DASHBOARD_FLEET:
            return self.service.dashboard_fleet(**arguments)
        if operation == TEST_PLAN_PREVIEW:
            return self.service.preview(**arguments)
        if operation == TEST_PLAN_REGISTER:
            return self.service.register_plan(
                arguments["plan_document"],
                target_resources=_target_resources(arguments.get("target_resources")),
            )
        if operation == TEST_PLAN_REPOSITORY:
            return {
                "schema_version": 1,
                "repository_id": self.service.plan_repository(**arguments),
            }
        if operation == TEST_RUN_SUBMIT:
            values = dict(arguments)
            values["target_resources"] = _target_resources(values.get("target_resources"))
            return self.service.submit(**values)
        if operation == TEST_RUN_LIST:
            return self.service.runs(**arguments)
        if operation == TEST_QUEUE_STATUS:
            return self.service.queue_status(**arguments)
        if operation == TEST_RUN_STATUS:
            return self.service.status(**arguments)
        if operation == TEST_RUN_SUMMARY:
            return self.service.summary(**arguments)
        if operation == TEST_RUN_FAILURES:
            return self.service.failures(**arguments)
        if operation == TEST_RUN_ARTIFACTS:
            return self.service.artifacts(**arguments)
        if operation == TEST_ARTIFACT_RESOLVE:
            return self.service.artifact(**arguments)
        if operation == TEST_RUN_CASES:
            return self.service.cases(**arguments)
        if operation == TEST_RUN_CANCEL:
            return self.service.cancel(**arguments)
        if operation == TEST_RUN_RETRY:
            return self.service.retry(**arguments)
        if operation == TEST_EVENTS_READ:
            return self.service.events(**arguments)
        if operation == TEST_EVIDENCE_CHECK:
            return self.service.policy_check(**arguments)
        if operation == TEST_EVIDENCE_CONSUME:
            return self.service.policy_consume(**arguments)
        if operation == TEST_STATS_READ:
            return self.service.stats(**arguments)
        if operation == TEST_FLEET_OVERVIEW:
            return self.service.fleet_overview(**arguments)
        if operation == TEST_REPOSITORY_DETAIL:
            return self.service.repository_detail(**arguments)
        raise AssertionError("fixed operation allowlist and dispatcher diverged")


class UnixTestPlaneServer:
    """Serve one framed request per connected local Unix peer."""

    def __init__(
        self,
        listener: socket.socket,
        service: TestPlaneClient,
        *,
        peer_resolver: Callable[[socket.socket], int | None] = _peer_uid,
        request_timeout_seconds: float = DEFAULT_TEST_PLANE_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_TEST_PLANE_CONCURRENCY,
        owned_socket_path: Path | None = None,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        if listener.family != socket.AF_UNIX or listener.type & socket.SOCK_STREAM == 0:
            raise TestStoreContractError("test-plane listener must be a Unix stream socket")
        if request_timeout_seconds <= 0:
            raise TestStoreContractError("request timeout must be positive")
        if (
            type(max_concurrent_requests) is not int
            or not 1 <= max_concurrent_requests <= 128
        ):
            raise TestStoreContractError(
                "test-plane concurrency must be from 1 through 128"
            )
        self.listener = listener
        self.call_journal = call_journal
        self.dispatcher = TestPlaneDispatcher(service, call_journal=call_journal)
        self.peer_resolver = peer_resolver
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.max_concurrent_requests = max_concurrent_requests
        self.owned_socket_path = owned_socket_path
        self._stop = threading.Event()
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._workers_lock = threading.Lock()
        self._workers: set[threading.Thread] = set()

    @classmethod
    def bind(
        cls,
        socket_path: Path,
        service: TestPlaneClient,
        *,
        socket_mode: int = 0o600,
        backlog: int = 64,
        max_concurrent_requests: int = DEFAULT_TEST_PLANE_CONCURRENCY,
        call_journal: RollingCallJournal | None = None,
    ) -> "UnixTestPlaneServer":
        path = Path(socket_path)
        if not path.is_absolute() or len(os.fsencode(path)) > 100:
            raise TestStoreContractError("test-plane socket path is invalid")
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise TestStoreContractError("test-plane socket parent is unsafe")
        if path.exists() or path.is_symlink():
            raise TestStoreConflict("test-plane socket path already exists")
        if type(socket_mode) is not int or not 0 <= socket_mode <= 0o777:
            raise TestStoreContractError("test-plane socket mode is invalid")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        try:
            listener.bind(str(path))
            os.chmod(path, socket_mode)
            listener.listen(backlog)
            return cls(
                listener,
                service,
                max_concurrent_requests=max_concurrent_requests,
                owned_socket_path=path,
                call_journal=call_journal,
            )
        except Exception:
            listener.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise

    def serve_connection(self, connection: socket.socket) -> None:
        started_at = monotonic_started()
        call_id = str(uuid.uuid4())
        request_id: str | None = None
        peer_pid: int | None = None
        peer_uid: int | None = None
        peer_gid: int | None = None
        try:
            connection.settimeout(self.request_timeout_seconds)
            if self.peer_resolver is _peer_uid:
                peer_pid, peer_uid, peer_gid = _peer_identity(connection)
            else:
                peer_uid = self.peer_resolver(connection)
            response = self.dispatcher.dispatch(
                _receive_frame(connection),
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                call_id=call_id,
                started_at=started_at,
            )
        except OSError as error:
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="received",
                        call_id=call_id,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        outcome="received",
                    )
                )
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="rejected",
                        call_id=call_id,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        duration_seconds=time.monotonic() - started_at,
                        outcome="unavailable",
                        code="transport_aborted",
                        message="test-plane request transport closed before dispatch",
                        diagnostic=diagnostic_for_exception(
                            error, stage="test_plane.receive"
                        ),
                    )
                )
            try:
                connection.close()
            except OSError:
                pass
            return
        except TestPlaneTransportError as error:
            if error.code == "incomplete_frame":
                if self.call_journal is not None:
                    self.call_journal.record(
                        event_record(
                            boundary="test_plane",
                            phase="received",
                            call_id=call_id,
                            peer_uid=peer_uid,
                            peer_gid=peer_gid,
                            peer_pid=peer_pid,
                            outcome="received",
                        )
                    )
                    self.call_journal.record(
                        event_record(
                            boundary="test_plane",
                            phase="rejected",
                            call_id=call_id,
                            peer_uid=peer_uid,
                            peer_gid=peer_gid,
                            peer_pid=peer_pid,
                            duration_seconds=time.monotonic() - started_at,
                            outcome="unavailable",
                            code="transport_aborted",
                            message="test-plane request transport closed before dispatch",
                            diagnostic=diagnostic_for_exception(
                                error, stage="test_plane.receive"
                            ),
                        )
                    )
                try:
                    connection.close()
                except OSError:
                    pass
                return
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="received",
                        call_id=call_id,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        outcome="received",
                    )
                )
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="rejected",
                        call_id=call_id,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        duration_seconds=time.monotonic() - started_at,
                        outcome=(
                            "timeout" if error.code == "request_timeout" else "rejected"
                        ),
                        code=error.code,
                        message=error.message,
                        diagnostic=diagnostic_for_exception(
                            error, stage="test_plane.receive"
                        ),
                    )
                )
            response = {
                "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
                "request_id": request_id,
                "ok": False,
                "error": {"code": error.code, "message": error.message},
            }
        try:
            _send_frame(connection, response)
        except (OSError, socket.timeout, TestPlaneTransportError) as error:
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="completed",
                        call_id=call_id,
                        request_id=(
                            response.get("request_id")
                            if isinstance(response.get("request_id"), str)
                            else None
                        ),
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        duration_seconds=time.monotonic() - started_at,
                        outcome=(
                            "timeout"
                            if isinstance(error, (socket.timeout, TimeoutError))
                            else "unavailable"
                        ),
                        code=(
                            "reply_delivery_timeout"
                            if isinstance(error, (socket.timeout, TimeoutError))
                            else "reply_delivery_failed"
                        ),
                        message="test-plane reply could not be delivered",
                        diagnostic=diagnostic_for_exception(
                            error, stage="test_plane.reply_delivery"
                        ),
                    )
                )
            return

    def _reject_at_capacity(self, connection: socket.socket) -> None:
        """Return bounded backpressure without queueing an unbounded request."""

        # Do not read from a saturated peer on the sole accept loop.  A silent
        # connection must not consume 250ms and starve later callers.  The
        # protocol permits request_id=null only for this pre-admission busy
        # response on the client's own one-request connection.
        connection.settimeout(min(self.request_timeout_seconds, 0.05))
        call_id = str(uuid.uuid4())
        peer_pid: int | None = None
        peer_uid: int | None = None
        peer_gid: int | None = None
        try:
            if self.peer_resolver is _peer_uid:
                peer_pid, peer_uid, peer_gid = _peer_identity(connection)
            else:
                peer_uid = self.peer_resolver(connection)
        except Exception:
            # Peer attribution is observational and must not block backpressure.
            pass
        if self.call_journal is not None:
            self.call_journal.record(
                event_record(
                    boundary="test_plane",
                    phase="received",
                    call_id=call_id,
                    peer_uid=peer_uid,
                    peer_gid=peer_gid,
                    peer_pid=peer_pid,
                    outcome="received",
                )
            )
            self.call_journal.record(
                event_record(
                    boundary="test_plane",
                    phase="rejected",
                    call_id=call_id,
                    peer_uid=peer_uid,
                    peer_gid=peer_gid,
                    peer_pid=peer_pid,
                    duration_seconds=0.0,
                    outcome="busy",
                    code="server_busy",
                    message="test plane reached bounded request capacity",
                )
            )
        try:
            _send_frame(
                connection,
                {
                    "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
                    "request_id": None,
                    "ok": False,
                    "error": {
                        "code": "server_busy",
                        "message": "The test plane is at bounded request capacity; retry shortly.",
                    },
                },
            )
        except (OSError, socket.timeout, TestPlaneTransportError) as error:
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        boundary="test_plane",
                        phase="completed",
                        call_id=call_id,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        duration_seconds=0.0,
                        outcome=(
                            "timeout"
                            if isinstance(error, (socket.timeout, TimeoutError))
                            else "unavailable"
                        ),
                        code=(
                            "reply_delivery_timeout"
                            if isinstance(error, (socket.timeout, TimeoutError))
                            else "reply_delivery_failed"
                        ),
                        message="test-plane capacity reply could not be delivered",
                        diagnostic=diagnostic_for_exception(
                            error, stage="test_plane.reply_delivery"
                        ),
                    )
                )
            return

    def _serve_owned_connection(self, connection: socket.socket) -> None:
        """Serve one admitted request and release its exact capacity slot."""

        current = threading.current_thread()
        try:
            with connection:
                self.serve_connection(connection)
        finally:
            with self._workers_lock:
                self._workers.discard(current)
            self._request_slots.release()

    def serve_forever(self) -> None:
        self.listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                connection, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            if not self._request_slots.acquire(blocking=False):
                with connection:
                    self._reject_at_capacity(connection)
                continue
            worker = threading.Thread(
                target=self._serve_owned_connection,
                args=(connection,),
                name="devcoordinator-test-plane-request",
                daemon=True,
            )
            with self._workers_lock:
                self._workers.add(worker)
            try:
                worker.start()
            except BaseException:
                with self._workers_lock:
                    self._workers.discard(worker)
                self._request_slots.release()
                connection.close()
                raise

    def close(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        finally:
            if self.owned_socket_path is not None:
                try:
                    metadata = self.owned_socket_path.lstat()
                    if stat.S_ISSOCK(metadata.st_mode):
                        self.owned_socket_path.unlink()
                except FileNotFoundError:
                    pass


class UnixTestPlaneClient:
    """One-request Unix client implementing :class:`TestPlaneClient`."""

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_server_uid: int | None = None,
        timeout_seconds: float = DEFAULT_TEST_PLANE_TIMEOUT_SECONDS,
        preview_timeout_seconds: float = DEFAULT_TEST_PLAN_PREVIEW_TIMEOUT_SECONDS,
        connection_factory: Callable[[], socket.socket] | None = None,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        # Compatibility-only input for installed same-release callers. A
        # connected local server is trusted; its UID is retained only as
        # diagnostic attribution.
        del expected_server_uid
        self.last_peer_uid: int | None = None
        self.timeout_seconds = float(timeout_seconds)
        self.preview_timeout_seconds = float(preview_timeout_seconds)
        if self.timeout_seconds <= 0 or self.preview_timeout_seconds <= 0:
            raise TestStoreContractError("test-plane client timeouts must be positive")
        if connection_factory is not None and not callable(connection_factory):
            raise TestStoreContractError("connection factory is invalid")
        self.connection_factory = connection_factory
        self.call_journal = call_journal

    def _record(
        self,
        *,
        phase: str,
        call_id: str,
        operation: str,
        request_id: str,
        arguments: object,
        started_at: float,
        outcome: str,
        code: str | None = None,
        message: str | None = None,
        diagnostic: Mapping[str, object] | None = None,
        result: object = None,
    ) -> None:
        if self.call_journal is None:
            return
        repository_id, run_id, attempt_id, operation_id = _request_correlations(
            arguments
        )
        result_repository, result_run, result_attempt, _ = _request_correlations(
            result
        )
        self.call_journal.record(
            event_record(
                boundary="test_plane_client",
                phase=phase,
                call_id=call_id,
                operation=operation,
                operation_id=operation_id,
                request_id=request_id,
                peer_uid=self.last_peer_uid,
                duration_seconds=(
                    None
                    if phase == "received"
                    else time.monotonic() - started_at
                ),
                outcome=outcome,
                code=code,
                message=message,
                repository_id=repository_id or result_repository,
                run_id=run_id or result_run,
                attempt_id=attempt_id or result_attempt,
                diagnostic=diagnostic,
            )
        )

    def _call(
        self,
        operation: str,
        arguments: Mapping[str, object],
        *,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        request_id = str(uuid.uuid4())
        call_id = str(uuid.uuid4())
        started_at = monotonic_started()
        self.last_peer_uid = None
        request = {
            "schema_version": TEST_PLANE_TRANSPORT_SCHEMA_VERSION,
            "request_id": request_id,
            "operation": operation,
            "arguments": dict(arguments),
        }
        self._record(
            phase="received",
            call_id=call_id,
            operation=operation,
            request_id=request_id,
            arguments=arguments,
            started_at=started_at,
            outcome="received",
        )
        stage = "connect"
        try:
            connection = (
                self.connection_factory()
                if self.connection_factory is not None
                else socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            )
            with connection:
                connection.settimeout(
                    self.timeout_seconds
                    if timeout_seconds is None
                    else float(timeout_seconds)
                )
                if self.connection_factory is None:
                    connection.connect(str(self.socket_path))
                self.last_peer_uid = _peer_uid(connection)
                stage = "send"
                try:
                    _send_frame(connection, request)
                except (BrokenPipeError, ConnectionResetError):
                    # A saturated server deliberately sends a pre-admission
                    # ``server_busy`` response without reading the request, then
                    # closes.  If that close races this write, the response may
                    # already be queued even though sendall reports EPIPE/ECONNRESET.
                    # Continue to the framed receive so callers still get the
                    # exact typed response.  A peer that closed without a frame is
                    # rejected below as an incomplete transport response.
                    pass
                stage = "receive"
                response = _decode(_receive_frame(connection))
            stage = "validate"
            if (
                response.get("schema_version") != TEST_PLANE_TRANSPORT_SCHEMA_VERSION
                or type(response.get("ok")) is not bool
            ):
                raise TestPlaneTransportError(
                    "invalid_response", "test-plane response identity is invalid"
                )
            if response.get("request_id") != request_id:
                error = response.get("error")
                pre_admission_busy = (
                    response.get("ok") is False
                    and response.get("request_id") is None
                    and isinstance(error, Mapping)
                    and error.get("code") == "server_busy"
                )
                if not pre_admission_busy:
                    raise TestPlaneTransportError(
                        "invalid_response", "test-plane response identity is invalid"
                    )
            if not response["ok"]:
                error = response.get("error")
                if not isinstance(error, Mapping):
                    raise TestPlaneTransportError(
                        "invalid_response", "test-plane error response is invalid"
                    )
                raise TestPlaneTransportError(
                    str(error.get("code")), str(error.get("message"))
                )
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise TestPlaneTransportError(
                    "invalid_response", "test-plane result is invalid"
                )
            if (
                len(_encode(result, maximum=MAX_TEST_PLANE_RESPONSE_BYTES))
                > MAX_TEST_PLANE_RESPONSE_BYTES
            ):
                raise TestPlaneTransportError(
                    "invalid_response", "test-plane result is too large"
                )
        except TestPlaneTransportError as error:
            if error.code in {"request_timeout"}:
                phase, outcome = "completed", "timeout"
            elif stage == "validate" and error.code not in {"invalid_response"}:
                phase = "rejected"
                outcome = "busy" if error.code == "server_busy" else "rejected"
            elif error.code == "incomplete_frame":
                phase, outcome = "completed", "unavailable"
            else:
                phase, outcome = "completed", "failed"
            self._record(
                phase=phase,
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                arguments=arguments,
                started_at=started_at,
                outcome=outcome,
                code=error.code,
                message=error.message,
                diagnostic=diagnostic_for_exception(
                    error, stage=f"test_plane_client.{stage}"
                ),
            )
            raise
        except OSError as error:
            timed_out = isinstance(error, (socket.timeout, TimeoutError))
            self._record(
                phase="completed",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                arguments=arguments,
                started_at=started_at,
                outcome="timeout" if timed_out else "unavailable",
                code=("request_timeout" if timed_out else "transport_unavailable"),
                message=(
                    f"test-plane {stage} timed out"
                    if timed_out
                    else f"test-plane {stage} is unavailable"
                ),
                diagnostic=diagnostic_for_exception(
                    error, stage=f"test_plane_client.{stage}"
                ),
            )
            raise TestPlaneTransportError(
                "transport_unavailable", "test-plane socket is unavailable"
            ) from error
        except Exception as error:
            self._record(
                phase="completed",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                arguments=arguments,
                started_at=started_at,
                outcome="failed",
                code="test_plane_client_failed",
                message="test-plane client call failed",
                diagnostic=diagnostic_for_exception(
                    error, stage=f"test_plane_client.{stage}"
                ),
            )
            raise
        self._record(
            phase="completed",
            call_id=call_id,
            operation=operation,
            request_id=request_id,
            arguments=arguments,
            started_at=started_at,
            outcome="ok",
            result=result,
        )
        return result

    def setup(self, *, timeout_seconds: float | None = None, **arguments):
        return self._call(
            TEST_REPOSITORY_SETUP,
            arguments,
            timeout_seconds=timeout_seconds,
        )

    def health(self):
        return self._call(TEST_HEALTH, {})

    def repository_catalog(
        self, *, timeout_seconds: float | None = None, **arguments
    ):
        return self._call(
            TEST_REPOSITORY_CATALOG,
            arguments,
            timeout_seconds=timeout_seconds,
        )

    def dashboard_stats(self, **arguments):
        return self._call(TEST_DASHBOARD_STATS, arguments)

    def dashboard_fleet(self, **arguments):
        return self._call(TEST_DASHBOARD_FLEET, arguments)

    def preview(self, **arguments):
        launch_timeout = arguments.get("launch_timeout_seconds")
        if launch_timeout is not None and (
            type(launch_timeout) is not int
            or not 1 <= launch_timeout <= 3_600
        ):
            raise TestStoreContractError(
                "test-plan launch timeout must be from 1 through 3600 seconds"
            )
        inherited_deadline = arguments.get("launch_deadline_monotonic")
        if inherited_deadline is not None and (
            isinstance(inherited_deadline, bool)
            or not isinstance(inherited_deadline, (int, float))
            or not math.isfinite(float(inherited_deadline))
            or float(inherited_deadline) <= 0
        ):
            raise TestStoreContractError(
                "test-plan launch deadline must be a positive finite number"
            )
        wire_arguments = dict(arguments)
        request_timeout = (
            self.preview_timeout_seconds
            if launch_timeout is None
            # Preserve the caller's semantic materialization deadline while
            # allowing the server enough transport margin to return its typed
            # timeout/result instead of racing the client socket deadline.
            else float(launch_timeout + 60)
        )
        if launch_timeout is not None:
            deadline = time.monotonic() + launch_timeout
            if inherited_deadline is not None:
                deadline = min(deadline, float(inherited_deadline))
            wire_arguments["launch_deadline_monotonic"] = deadline
        return self._call(
            TEST_PLAN_PREVIEW,
            wire_arguments,
            # Immutable snapshot materialization happens inside preview and is
            # part of the caller-selected launch budget.  The generic
            # test-plane timeout remains a short default for unrelated reads.
            timeout_seconds=request_timeout,
        )

    def register_plan(self, plan_document, *, target_resources=None):
        return self._call(
            TEST_PLAN_REGISTER,
            {
                "plan_document": plan_document,
                "target_resources": _resource_documents(target_resources),
            },
        )

    def plan_repository(self, *, plan_id: str, repository_id: str) -> str:
        return str(
            self._call(
                TEST_PLAN_REPOSITORY,
                {"plan_id": plan_id, "repository_id": repository_id},
            )["repository_id"]
        )

    def submit(self, **arguments):
        values = dict(arguments)
        values["target_resources"] = _resource_documents(values.get("target_resources"))
        return self._call(TEST_RUN_SUBMIT, values)

    def runs(self, **arguments):
        return self._call(TEST_RUN_LIST, arguments)

    def queue_status(self, *, repository_id: str):
        return self._call(
            TEST_QUEUE_STATUS,
            {"repository_id": repository_id},
        )

    def status(self, *, run_id: str, repository_id: str):
        return self._call(
            TEST_RUN_STATUS,
            {"run_id": run_id, "repository_id": repository_id},
        )

    def summary(self, *, run_id: str, repository_id: str):
        return self._call(
            TEST_RUN_SUMMARY,
            {"run_id": run_id, "repository_id": repository_id},
        )

    def failures(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ):
        arguments: dict[str, object] = {
            "run_id": run_id,
            "repository_id": repository_id,
            "limit": limit,
        }
        if after is not None:
            arguments["after"] = after
        return self._call(TEST_RUN_FAILURES, arguments)

    def artifacts(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ):
        arguments: dict[str, object] = {
            "run_id": run_id,
            "repository_id": repository_id,
            "limit": limit,
        }
        if after is not None:
            arguments["after"] = after
        return self._call(TEST_RUN_ARTIFACTS, arguments)

    def artifact(self, *, run_id: str, repository_id: str, artifact_id: str):
        return self._call(
            TEST_ARTIFACT_RESOLVE,
            {
                "run_id": run_id,
                "repository_id": repository_id,
                "artifact_id": artifact_id,
            },
        )

    def cases(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: int = 0,
        limit: int = 25,
    ):
        return self._call(
            TEST_RUN_CASES,
            {
                "run_id": run_id,
                "repository_id": repository_id,
                "after": after,
                "limit": limit,
            },
        )

    def cancel(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        reason: str,
        operation_id: str,
    ):
        return self._call(
            TEST_RUN_CANCEL,
            {
                "run_id": run_id,
                "repository_id": repository_id,
                "actor": actor,
                "reason": reason,
                "operation_id": operation_id,
            },
        )

    def retry(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        failed_only: bool,
        operation_id: str,
    ):
        return self._call(
            TEST_RUN_RETRY,
            {
                "run_id": run_id,
                "repository_id": repository_id,
                "actor": actor,
                "failed_only": failed_only,
                "operation_id": operation_id,
            },
        )

    def events(self, **arguments):
        return self._call(TEST_EVENTS_READ, arguments)

    def stats(self, **arguments):
        return self._call(TEST_STATS_READ, arguments)

    def policy_check(self, **arguments):
        return self._call(TEST_EVIDENCE_CHECK, arguments)

    def policy_consume(self, **arguments):
        return self._call(TEST_EVIDENCE_CONSUME, arguments)

    def fleet_overview(self, **arguments):
        return self._call(TEST_FLEET_OVERVIEW, arguments)

    def repository_detail(self, **arguments):
        return self._call(TEST_REPOSITORY_DETAIL, arguments)


__all__ = [
    "TEST_PLANE_OPERATIONS",
    "TEST_HEALTH",
    "TEST_ARTIFACT_RESOLVE",
    "TEST_EVIDENCE_CONSUME",
    "TEST_REPOSITORY_SETUP",
    "TEST_REPOSITORY_CATALOG",
    "TEST_DASHBOARD_STATS",
    "TEST_DASHBOARD_FLEET",
    "TestPlaneDispatcher",
    "TestPlaneTransportError",
    "UnixTestPlaneClient",
    "UnixTestPlaneServer",
]
