"""Typed Unix-socket broker for host-global coordinator operations.

The broker is deliberately a narrow capability boundary.  Clients identify an
account, repository, resource, and one operation from :class:`BrokerOperation`.
They cannot submit commands, paths, SQL, or a writable database handle.  The
broker records operating-system peer credentials when available, resolves the
exact account/project/resource/operation against the host's combined local
policy, and sends the resulting typed request through one serialized mutation
writer. Unix accounts identify activity by one developer; they are not
security tenants.

The mutation backend is responsible for revalidating the current repository /
resource binding and durably deduplicating ``operation_id`` in the coordinator
store before performing external work.  Keeping that contract behind
``MutationBackend`` lets this module remain independent of the store package;
in particular, an untrusted client can never acquire a SQLite connection.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import logging
import math
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, FrozenSet, Iterable, Mapping, Optional, Protocol

from .call_journal import RollingCallJournal, call_record, event_record
from .compose_run_once import MAX_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS
from .maintenance import (
    MAINTENANCE_ROOT,
    MaintenanceMarkerError,
    PUBLIC_MAINTENANCE_MESSAGE,
    load_maintenance_state,
)
from .universal_test_admission import TestSubmissionAdmissionGate

PROTOCOL_VERSION = 1
# Inventory is a bounded whole-host graph.  Keep the local protocol bounded,
# but size it for a real multi-repository machine rather than a mutation-sized
# reply.  Reads are not retained in the mutation replay cache.
DEFAULT_MAX_MESSAGE_BYTES = 32 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_SOCKET_MODE = 0o660
SYSTEM_BROKER_SOCKET_PATH = Path("/run/devcoordinator-authority.sock")
UNMAPPED_LOCAL_IDENTITY = 65534
DEFAULT_MAX_CLIENTS = 32
DEFAULT_COMPLETED_OPERATION_CACHE = 1024
# POSIX guarantees an atomic pipe write of at least 512 bytes.  Keeping this
# credential payload below that floor avoids a broker-thread write wait while
# preserving ample room for a high-entropy service password.
MAX_EPHEMERAL_SECRET_BYTES = 512
# These are broker-side client and graceful-wait budgets for the PostgreSQL
# helper calls: one dump and one strong-verification allowance, plus a minute
# for durable result commits and the reply. They do not prove that nested
# Docker/in-container work reached a terminal state when a helper times out.
# Repository lifecycle plans can also exceed this budget; their recovery
# contract is durable per-target phase checkpoints plus idempotent
# re-observation, rather than completion inside this timeout.
# Large production databases can legitimately need several hours for a
# complete dump or a single-threaded scratch restore.  This is a semantic
# database-operation bound, not the ordinary broker transport slice.
DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS = 6 * 60 * 60.0
DATABASE_BACKUP_CUMULATIVE_TIMEOUT_SECONDS = (
    2 * DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS
)
DATABASE_RESTORE_CUMULATIVE_TIMEOUT_SECONDS = (
    DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS
)
DATABASE_OPERATION_COMPLETION_GRACE_SECONDS = 60.0
DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS = (
    DATABASE_BACKUP_CUMULATIVE_TIMEOUT_SECONDS
    + DATABASE_OPERATION_COMPLETION_GRACE_SECONDS
)
DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS = (
    DATABASE_RESTORE_CUMULATIVE_TIMEOUT_SECONDS
    + DATABASE_OPERATION_COMPLETION_GRACE_SECONDS
)
BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS = DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS
_NON_TERMINAL_OPERATION_ERRORS = frozenset(
    {
        "host_observation_busy",
        "operation_in_progress",
        "operation_outcome_uncertain",
        "service_shutting_down",
        "test_admission_drained",
        "test_attempt_runtime_unavailable",
        "worker_operation_uncertain",
    }
)

_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)
_SHA256_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_COMPOSE_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_LOGGER = logging.getLogger(__name__)


class BrokerOperation(str, Enum):
    """The complete typed operation set accepted from broker clients."""

    CAPABILITIES_READ = "capabilities.read"
    PORT_LEASE = "port.lease"
    PORT_RELEASE = "port.release"
    PORT_ASSIGN = "port.assign"
    PORT_UNASSIGN = "port.unassign"
    OPERATION_FOLLOW = "operation.follow"
    INVENTORY_READ = "inventory.read"
    EVENTS_READ = "events.read"
    HOST_OBSERVE = "host.observe"
    TEST_RUN_START = "test.run_start"
    TEST_RUN_FINISH = "test.run_finish"
    TEST_STATS_READ = "test.stats_read"
    TEST_HEALTH = "test.health"
    TEST_FLEET_STATS_READ = "test.fleet_stats_read"
    TEST_PLAN_PREVIEW = "test.plan_preview"
    TEST_PLAN_REGISTER = "test.plan_register"
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
    TEST_REPOSITORY_SETUP = "test.repository_setup"
    TEST_REPOSITORY_CATALOG = "test.repository_catalog"
    TEST_EVIDENCE_CHECK = "test.evidence_check"
    TEST_EVIDENCE_CONSUME = "test.evidence_consume"
    TEST_ADMISSION_DRAIN_BEGIN = "test.admission_drain_begin"
    TEST_ADMISSION_DRAIN_STATUS = "test.admission_drain_status"
    TEST_ADMISSION_DRAIN_CLEAR = "test.admission_drain_clear"
    TEST_ATTEMPT_TICKET = "test.attempt_ticket"
    TEST_ATTEMPT_LAUNCH = "test.attempt_launch"
    TEST_ATTEMPT_STATUS = "test.attempt_status"
    TEST_ATTEMPT_CANCEL = "test.attempt_cancel"
    RUNTIME_ENSURE = "runtime.ensure"
    RUNTIME_REQUEST = "runtime.request"
    REPOSITORY_ENSURE = "repository.ensure"
    REPOSITORY_RESOLVE = "repository.resolve"
    WORKER_LAUNCH_TICKET = "worker.launch_ticket"
    WORKER_LAUNCHED = "worker.launched"
    WORKER_EXIT = "worker.exit"
    WORKER_POLICY_READ = "worker.policy_read"
    WORKER_ATTEMPT_READ = "worker.attempt_read"
    SERVER_PUBLISH = "server.publish"
    EPHEMERAL_START = "ephemeral.start"
    EPHEMERAL_STATUS = "ephemeral.status"
    EPHEMERAL_RENEW = "ephemeral.renew"
    EPHEMERAL_FINISH = "ephemeral.finish"
    EPHEMERAL_IMAGE_STATUS = "ephemeral.image_status"
    EPHEMERAL_IMAGE_PREFETCH = "ephemeral.image_prefetch"
    EPHEMERAL_SECRET_FD = "ephemeral.secret_fd"
    DOCKER_START = "docker.start"
    DOCKER_STOP = "docker.stop"
    DOCKER_RESTART = "docker.restart"
    DATABASE_BACKUP = "database.backup"
    DATABASE_BACKUP_RETIRE = "database.backup_retire"
    DATABASE_RESTORE = "database.restore"
    COMPOSE_UP = "compose.up"
    COMPOSE_STOP = "compose.stop"
    COMPOSE_RESTART = "compose.restart"
    COMPOSE_DOWN = "compose.down"
    COMPOSE_RUN_ONCE = "compose.run_once"
    REPOSITORY_PLAN_REMOVE = "repository.plan_remove"
    REPOSITORY_LIST_REMOVED = "repository.list_removed"
    REPOSITORY_REMOVE = "repository.remove"
    REPOSITORY_REINSTALL = "repository.reinstall"
    RESOURCE_ATTACH = "resource.attach"
    RESOURCE_PLAN_RETIRE = "resource.plan_retire"
    RESOURCE_RETIRE = "resource.retire"
    RESOURCE_PLAN_ARCHIVE = "resource.plan_archive"
    RESOURCE_ARCHIVE = "resource.archive"
    RESOURCE_RESTORE = "resource.restore"
    ARCHIVES_READ = "archives.read"
    CONTAINER_REMOVE = "container.remove"
    CLEANUP_PLAN = "cleanup.plan"
    CLEANUP_APPLY = "cleanup.apply"
    LIFECYCLE_RESTORE = "lifecycle.restore"


_WORKER_RUNNER_CALLBACK_OPERATIONS = frozenset(
    {
        BrokerOperation.WORKER_LAUNCH_TICKET,
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
    }
)

TESTD_INTERNAL_OPERATIONS = frozenset(
    {
        BrokerOperation.TEST_ATTEMPT_TICKET,
        BrokerOperation.TEST_ATTEMPT_LAUNCH,
        BrokerOperation.TEST_ATTEMPT_STATUS,
        BrokerOperation.TEST_ATTEMPT_CANCEL,
    }
)


class BrokerError(RuntimeError):
    """A safe structured failure which may be returned to a client."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        operation_id: Optional[str] = None,
        retry_after_seconds: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.operation_id = operation_id
        self.retry_after_seconds = retry_after_seconds


class BrokerBackendError(BrokerError):
    """A trusted backend rejection safe to expose as structured broker data."""


@dataclass(frozen=True)
class PeerCredentials:
    """Credentials obtained from the kernel for one connected Unix peer."""

    uid: int
    gid: int
    pid: Optional[int]

    def __post_init__(self) -> None:
        if not _is_exact_int(self.uid) or self.uid < 0:
            raise ValueError("peer uid must be a non-negative integer")
        if not _is_exact_int(self.gid) or self.gid < 0:
            raise ValueError("peer gid must be a non-negative integer")
        if self.pid is not None and (
            not _is_exact_int(self.pid) or self.pid <= 0
        ):
            raise ValueError("peer pid must be a positive integer when present")


@dataclass(frozen=True)
class BrokerRequest:
    """A strictly validated request received from an untrusted client."""

    operation_id: str
    authority_generation: str
    account_id: str
    project_id: str
    repository_generation: int
    resource_id: str
    operation: BrokerOperation
    arguments: Mapping[str, Any]

    @classmethod
    def from_wire(cls, value: Any) -> "BrokerRequest":
        operation_id = _valid_operation_id_or_none(value)
        if not isinstance(value, dict):
            raise BrokerError(
                "invalid_request",
                "Broker request must be a JSON object.",
                operation_id=operation_id,
            )

        required = {
            "version",
            "operation_id",
            "authority_generation",
            "account_id",
            "project_id",
            "repository_generation",
            "resource_id",
            "operation",
            "arguments",
        }
        supplied = set(value)
        missing = sorted(required - supplied)
        unexpected = sorted(supplied - required)
        if missing or unexpected:
            details = []
            if missing:
                details.append("missing: " + ", ".join(missing))
            if unexpected:
                details.append("unexpected: " + ", ".join(unexpected))
            raise BrokerError(
                "invalid_request",
                "Broker request fields are invalid (" + "; ".join(details) + ").",
                operation_id=operation_id,
            )

        if not _is_exact_int(value["version"]) or value["version"] != PROTOCOL_VERSION:
            raise BrokerError(
                "unsupported_version",
                "Broker protocol version is not supported.",
                operation_id=operation_id,
            )

        if operation_id is None or value["operation_id"] != operation_id:
            raise BrokerError(
                "invalid_operation_id",
                "operation_id must be a canonical UUID.",
            )

        authority_generation = _validate_identifier(
            value["authority_generation"],
            "authority_generation",
            operation_id=operation_id,
        )

        account_id = _validate_identifier(
            value["account_id"], "account_id", operation_id=operation_id
        )
        project_id = _validate_identifier(
            value["project_id"], "project_id", operation_id=operation_id
        )
        repository_generation = value["repository_generation"]
        if not _is_exact_int(repository_generation) or repository_generation < 0:
            raise BrokerError(
                "invalid_request",
                "repository_generation must be a non-negative integer.",
                operation_id=operation_id,
            )
        resource_id = _validate_identifier(
            value["resource_id"], "resource_id", operation_id=operation_id
        )

        try:
            operation = BrokerOperation(value["operation"])
        except (TypeError, ValueError):
            raise BrokerError(
                "unknown_operation",
                "Requested broker operation is not allowed.",
                operation_id=operation_id,
            )

        arguments = _validate_arguments(
            operation, value["arguments"], operation_id=operation_id
        )
        if (
            operation is BrokerOperation.EPHEMERAL_SECRET_FD
            and arguments["run_id"] != resource_id
        ):
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral credential run_id must match the exact broker resource_id.",
                operation_id=operation_id,
            )
        return cls(
            operation_id=operation_id,
            authority_generation=authority_generation,
            account_id=account_id,
            project_id=project_id,
            repository_generation=repository_generation,
            resource_id=resource_id,
            operation=operation,
            arguments=MappingProxyType(arguments),
        )

    @classmethod
    def create(
        cls,
        *,
        account_id: str,
        project_id: str,
        resource_id: str,
        operation: BrokerOperation,
        arguments: Optional[Mapping[str, Any]] = None,
        operation_id: Optional[str] = None,
        authority_generation: str = "unbound-static-test",
        repository_generation: int = 0,
    ) -> "BrokerRequest":
        return cls.from_wire(
            {
                "version": PROTOCOL_VERSION,
                "operation_id": operation_id or str(uuid.uuid4()),
                "authority_generation": authority_generation,
                "account_id": account_id,
                "project_id": project_id,
                "repository_generation": repository_generation,
                "resource_id": resource_id,
                "operation": operation.value,
                "arguments": dict(arguments or {}),
            }
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "operation_id": self.operation_id,
            "authority_generation": self.authority_generation,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "repository_generation": self.repository_generation,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "arguments": dict(self.arguments),
        }


@dataclass(frozen=True)
class AcceptedBrokerRequest:
    """A validated typed request plus best-effort kernel attribution.

    Trusted local callers have no policy identity or permission set.  The peer
    UID is retained only for execution selection, accounting, and evidence.
    """

    peer: PeerCredentials
    request: BrokerRequest

    @property
    def attribution_uid(self) -> int:
        return self.peer.uid


@dataclass(frozen=True)
class EphemeralSecretFD:
    """One read-only, close-on-exec descriptor carrying a run credential.

    The descriptor is intentionally the only secret-bearing field.  Its
    metadata is safe to return to an in-process caller and to record in a
    diagnostic assertion, but it must never be printed as a credential value.
    """

    fd: int
    operation_id: str
    request_id: str
    expires_at_epoch: int
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _is_exact_int(self.fd) or self.fd < 0:
            raise ValueError("secret descriptor must be a non-negative integer")
        if _canonical_uuid_value(self.operation_id) is None:
            raise ValueError("secret operation_id must be a canonical UUID")
        if _canonical_uuid_value(self.request_id) is None:
            raise ValueError("secret request_id must be a canonical UUID")
        if not _is_exact_int(self.expires_at_epoch) or self.expires_at_epoch <= 0:
            raise ValueError("secret expiry must be a positive epoch")

    def close(self) -> None:
        """Close the received descriptor after its in-memory bytes are consumed."""

        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        try:
            os.close(self.fd)
        except OSError:
            return

    def __enter__(self) -> "EphemeralSecretFD":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()


class EphemeralSecretMaterial(Protocol):
    """Narrow, secret-bearing result that never enters the JSON protocol."""

    value: bytes
    expires_at_epoch: int
    request_id: uuid.UUID


class EphemeralSecretFdDelivery(Protocol):
    """One secret payload plus the lock-held lifecycle release callback."""

    material: EphemeralSecretMaterial

    def close(self) -> None:
        """Release the delivery boundary after local descriptor closure."""


class EphemeralSecretFdRetriever(Protocol):
    """Broker-local descriptor delivery after exact typed request validation.

    The store-backed implementation re-proves the exact running run, consumes
    the manager's one-time request tombstone, and holds the run mutation lock
    until the Unix transport closes its local descriptor.
    """

    def acquire_ephemeral_secret_fd_delivery(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> EphemeralSecretFdDelivery:
        """Return one closeable transient delivery or raise a safe BrokerError."""


@dataclass(frozen=True)
class _BrokerTransportResponse:
    """A redacted JSON reply with an optional one-shot ancillary descriptor."""

    payload: bytes
    secret_fd: Optional[int] = None
    secret_delivery: Optional[EphemeralSecretFdDelivery] = field(
        default=None,
        repr=False,
        compare=False,
    )


class RequestAcceptor(Protocol):
    def accept(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        """Validate a typed trusted-local request."""


class TrustedLocalRequestAcceptor:
    """Accept every strictly parsed request from a trusted local caller."""

    def accept(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        return AcceptedBrokerRequest(peer=peer, request=request)


class MutationBackend(Protocol):
    """Trusted broker-process implementation of shared resource mutation.

    Implementations must use ``request.request.operation_id`` as the durable
    idempotency key, revalidate the exact current resource generation, and keep slow
    Docker/process work outside bounded database write transactions.
    """

    def execute(self, request: AcceptedBrokerRequest) -> Mapping[str, Any]:
        """Perform one typed mutation and return JSON-safe result data."""


@dataclass(frozen=True)
class _CachedOutcome:
    fingerprint: str
    result: Optional[dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class _KeyedLockPool:
    """Bounded-lifetime locks for one operation id and one exact resource."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: dict[str, tuple[threading.Lock, int]] = {}

    @contextmanager
    def hold(self, keys: Iterable[str]) -> Iterable[None]:
        normalized = sorted(set(keys))
        entries: list[tuple[str, threading.Lock]] = []
        with self._guard:
            for key in normalized:
                lock, users = self._entries.get(key, (threading.Lock(), 0))
                self._entries[key] = (lock, users + 1)
                entries.append((key, lock))
        acquired: list[threading.Lock] = []
        try:
            for _, lock in entries:
                lock.acquire()
                acquired.append(lock)
            yield
        finally:
            for lock in reversed(acquired):
                lock.release()
            with self._guard:
                for key, lock in entries:
                    current_lock, users = self._entries[key]
                    if current_lock is not lock:
                        raise RuntimeError("broker keyed-lock identity changed")
                    if users == 1:
                        del self._entries[key]
                    else:
                        self._entries[key] = (lock, users - 1)


class SerializedMutationWriter:
    """Serializes one operation/target while allowing unrelated work to progress.

    Durable idempotency belongs to the store-backed backend.  The bounded cache
    here is only a latency optimization; eviction must never be the correctness
    boundary for a production backend.
    """

    def __init__(
        self,
        backend: MutationBackend,
        *,
        completed_cache_size: int = DEFAULT_COMPLETED_OPERATION_CACHE,
        max_result_bytes: int = DEFAULT_MAX_MESSAGE_BYTES // 2,
        max_concurrent_host_observations: int = 4,
        test_submission_gate: TestSubmissionAdmissionGate | None = None,
        test_admission_drain_timeout_seconds: float = 30.0,
    ) -> None:
        if not _is_exact_int(completed_cache_size) or completed_cache_size <= 0:
            raise ValueError("completed_cache_size must be positive")
        if not _is_exact_int(max_result_bytes) or max_result_bytes <= 0:
            raise ValueError("max_result_bytes must be positive")
        if (
            not _is_exact_int(max_concurrent_host_observations)
            or max_concurrent_host_observations < 0
        ):
            raise ValueError(
                "max_concurrent_host_observations must be a non-negative integer"
            )
        if test_admission_drain_timeout_seconds < 0:
            raise ValueError("test admission drain timeout must be non-negative")
        self._backend = backend
        self._completed_cache_size = completed_cache_size
        self._max_result_bytes = max_result_bytes
        self._keyed_locks = _KeyedLockPool()
        self._cache_lock = threading.Lock()
        # CPython's default Condition lock is currently reentrant, but make
        # that shutdown-safety contract explicit: a Python signal handler may
        # run on the main thread while close() is inside begin_shutdown().
        self._metrics_condition = threading.Condition(threading.RLock())
        self._waiting_count = 0
        self._active_count = 0
        self._inflight_mutation_count = 0
        self._admitted_mutation_count = 0
        self._accepting_mutations = True
        self._test_submission_gate = (
            test_submission_gate or TestSubmissionAdmissionGate()
        )
        self._test_admission_drain_timeout_seconds = float(
            test_admission_drain_timeout_seconds
        )
        self._host_observation_slots = (
            threading.BoundedSemaphore(max_concurrent_host_observations)
            if max_concurrent_host_observations > 0
            else None
        )
        self._completed: "OrderedDict[str, _CachedOutcome]" = OrderedDict()

    @property
    def waiting_count(self) -> int:
        """Number of callers currently queued at the single-writer boundary."""

        with self._metrics_condition:
            return self._waiting_count

    @property
    def is_active(self) -> bool:
        with self._metrics_condition:
            return self._active_count > 0

    @property
    def accepting_mutations(self) -> bool:
        """Whether a new mutation may cross the admission boundary."""

        with self._metrics_condition:
            return self._accepting_mutations

    @property
    def admitted_mutation_count(self) -> int:
        """Mutations admitted before the shutdown fence and not yet returned."""

        with self._metrics_condition:
            return self._admitted_mutation_count

    def begin_shutdown(self) -> int:
        """Atomically fence every later reservation and return the active count.

        Final admission and this state transition use one condition lock. A
        racing request therefore either increments ``_admitted_mutation_count``
        immediately before backend execution and is allowed to finish, or sees
        the fence after any keyed-lock wait and cannot reach the backend's
        durable reservation boundary.
        """

        with self._metrics_condition:
            self._accepting_mutations = False
            admitted = self._admitted_mutation_count
            self._metrics_condition.notify_all()
            return admitted

    def wait_for_drain(self, timeout: float) -> bool:
        """Wait for admitted work to finish and pre-fence waiters to reject."""

        if timeout < 0:
            raise ValueError("timeout must be non-negative")
        with self._metrics_condition:
            return self._metrics_condition.wait_for(
                lambda: self._inflight_mutation_count == 0,
                timeout=timeout,
            )

    def wait_for_queued(self, minimum: int, timeout: float) -> bool:
        """Wait for observable writer contention (useful for health/tests)."""

        if minimum < 0 or timeout < 0:
            raise ValueError("minimum and timeout must be non-negative")
        with self._metrics_condition:
            return self._metrics_condition.wait_for(
                lambda: self._waiting_count >= minimum, timeout=timeout
            )

    def execute(self, request: AcceptedBrokerRequest) -> dict[str, Any]:
        read_only = request.request.operation in {
            BrokerOperation.CAPABILITIES_READ,
            BrokerOperation.REPOSITORY_RESOLVE,
            BrokerOperation.OPERATION_FOLLOW,
            BrokerOperation.INVENTORY_READ,
            BrokerOperation.EVENTS_READ,
            BrokerOperation.TEST_STATS_READ,
            BrokerOperation.TEST_HEALTH,
            BrokerOperation.TEST_FLEET_STATS_READ,
            BrokerOperation.TEST_RUN_LIST,
            BrokerOperation.TEST_QUEUE_STATUS,
            BrokerOperation.TEST_RUN_STATUS,
            BrokerOperation.TEST_RUN_SUMMARY,
            BrokerOperation.TEST_RUN_FAILURES,
            BrokerOperation.TEST_RUN_ARTIFACTS,
            BrokerOperation.TEST_ARTIFACT_RESOLVE,
            BrokerOperation.TEST_RUN_CASES,
            BrokerOperation.TEST_EVENTS_READ,
            BrokerOperation.TEST_REPOSITORY_SETUP,
            BrokerOperation.TEST_REPOSITORY_CATALOG,
            BrokerOperation.TEST_EVIDENCE_CHECK,
            BrokerOperation.TEST_ADMISSION_DRAIN_STATUS,
            BrokerOperation.TEST_ATTEMPT_STATUS,
            BrokerOperation.EPHEMERAL_STATUS,
            BrokerOperation.EPHEMERAL_IMAGE_STATUS,
            BrokerOperation.WORKER_POLICY_READ,
            BrokerOperation.WORKER_ATTEMPT_READ,
        } or (
            request.request.operation is BrokerOperation.RUNTIME_REQUEST
            and request.request.arguments.get("action") in {"status", "capture_logs"}
        )
        if read_only:
            # A query-only snapshot does not need the mutation lock, durable
            # idempotency journal, or completed-result cache.  Avoid retaining
            # up to one full host graph per caller in broker memory.
            return _normalize_backend_result(
                self._backend.execute(request), max_bytes=self._max_result_bytes
            )
        operation_id = request.request.operation_id
        operation = request.request.operation
        admitted_test_submission = False
        if operation is BrokerOperation.TEST_RUN_SUBMIT:
            admitted_test_submission = self._test_submission_gate.admit_submission()
            if not admitted_test_submission:
                raise BrokerError(
                    "test_admission_drained",
                    "New test submissions are temporarily paused for a verified history cutover; retry shortly.",
                    operation_id=operation_id,
                )
        try:
            if operation is BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN:
                try:
                    self._test_submission_gate.begin_drain(
                        timeout_seconds=self._test_admission_drain_timeout_seconds
                    )
                except TimeoutError as error:
                    raise BrokerError(
                        "test_admission_drain_timeout",
                        "Existing test submissions did not drain before the migration deadline.",
                        operation_id=operation_id,
                    ) from error
            with self._metrics_condition:
                if not self._accepting_mutations:
                    raise BrokerError(
                        "service_shutting_down",
                        "The broker is shutting down; retry with its replacement.",
                        operation_id=operation_id,
                    )
                self._inflight_mutation_count += 1
                self._metrics_condition.notify_all()
            try:
                if operation == BrokerOperation.HOST_OBSERVE:
                    slots = self._host_observation_slots
                    if slots is None or not slots.acquire(blocking=False):
                        raise BrokerError(
                            "host_observation_busy",
                            "The broker already has the maximum number of host observation callers; retry later.",
                            operation_id=operation_id,
                        )
                    try:
                        result = self._execute_mutation(request)
                    finally:
                        slots.release()
                else:
                    result = self._execute_mutation(request)
                if operation is BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR:
                    self._test_submission_gate.resume()
                return result
            finally:
                with self._metrics_condition:
                    self._inflight_mutation_count -= 1
                    if self._inflight_mutation_count < 0:
                        raise RuntimeError("broker mutation in-flight count underflow")
                    self._metrics_condition.notify_all()
        finally:
            if admitted_test_submission:
                self._test_submission_gate.finish_submission()

    def _execute_mutation(
        self, request: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        fingerprint = _request_fingerprint(request)
        with self._metrics_condition:
            self._waiting_count += 1
            self._metrics_condition.notify_all()
        operation_id = request.request.operation_id
        resource_key = "\x1f".join(
            (
                request.request.account_id,
                request.request.project_id,
                request.request.resource_id,
            )
        )
        lock_keys = ["operation:" + operation_id]
        if (
            request.request.operation != BrokerOperation.HOST_OBSERVE
            and request.request.operation not in _WORKER_RUNNER_CALLBACK_OPERATIONS
        ):
            lock_keys.append("resource:" + resource_key)
        # A runtime lifecycle request starts/stops a fixed runner while holding
        # the exact resource lock. Its launch and exit callbacks must re-enter
        # the broker for state-machine transitions; taking that same generic
        # lock would deadlock the lifecycle request. Callback operations retain
        # their operation-id lock, authenticated identity checks, and worker
        # generation/CAS fencing in BrokerWorkerOperations.
        # Host observation is a repeat-safe state measurement. Distinct
        # requests must reach the database-backed host-domain SingleFlight
        # boundary together so they can join one durable snapshot. Keep the
        # operation lock/cache so duplicate operation IDs still replay in
        # process and sampler exceptions still become redacted broker errors.
        with self._keyed_locks.hold(lock_keys):
            with self._metrics_condition:
                self._waiting_count -= 1
                if not self._accepting_mutations:
                    self._metrics_condition.notify_all()
                    raise BrokerError(
                        "service_shutting_down",
                        "The broker is shutting down; retry with its replacement.",
                        operation_id=operation_id,
                    )
                self._active_count += 1
                self._admitted_mutation_count += 1
                self._metrics_condition.notify_all()
            try:
                with self._cache_lock:
                    cached = self._completed.get(operation_id)
                    if cached is not None:
                        self._completed.move_to_end(operation_id)
                if cached is not None:
                    if cached.fingerprint != fingerprint:
                        raise BrokerError(
                            "operation_id_conflict",
                            "operation_id was already used for a different request.",
                            operation_id=operation_id,
                        )
                    if cached.error_code is not None:
                        raise BrokerError(
                            cached.error_code,
                            cached.error_message or "Broker mutation failed.",
                            operation_id=operation_id,
                        )
                    return dict(cached.result or {})

                try:
                    raw_result = self._backend.execute(request)
                    result = _normalize_backend_result(
                        raw_result, max_bytes=self._max_result_bytes
                    )
                except BrokerError as exc:
                    outcome = _CachedOutcome(
                        fingerprint=fingerprint,
                        error_code=exc.code,
                        error_message=exc.message,
                    )
                    if exc.code not in _NON_TERMINAL_OPERATION_ERRORS:
                        self._remember(operation_id, outcome)
                    raise BrokerError(
                        exc.code, exc.message, operation_id=operation_id
                    ) from None
                except Exception:
                    _LOGGER.exception(
                        "broker mutation backend failed for operation_id=%s",
                        operation_id,
                    )
                    outcome = _CachedOutcome(
                        fingerprint=fingerprint,
                        error_code="mutation_failed",
                        error_message=(
                            "The broker could not complete the mutation; inspect broker logs."
                        ),
                    )
                    self._remember(operation_id, outcome)
                    raise BrokerError(
                        outcome.error_code or "mutation_failed",
                        outcome.error_message or "Broker mutation failed.",
                        operation_id=operation_id,
                    ) from None

                self._remember(
                    operation_id,
                    _CachedOutcome(fingerprint=fingerprint, result=result),
                )
                return dict(result)
            finally:
                with self._metrics_condition:
                    self._active_count -= 1
                    self._admitted_mutation_count -= 1
                    self._metrics_condition.notify_all()

    def _remember(self, operation_id: str, outcome: _CachedOutcome) -> None:
        with self._cache_lock:
            self._completed[operation_id] = outcome
            self._completed.move_to_end(operation_id)
            while len(self._completed) > self._completed_cache_size:
                self._completed.popitem(last=False)


class BrokerService:
    """Strict request parsing, trusted-local acceptance, and mutation dispatch."""

    def __init__(
        self,
        acceptor: RequestAcceptor,
        writer: SerializedMutationWriter,
        *,
        secret_fd_retriever: Optional[EphemeralSecretFdRetriever] = None,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        self._acceptor = acceptor
        self._writer = writer
        self._secret_fd_retriever = secret_fd_retriever
        self._call_journal = call_journal

    def reply_for_document(
        self, peer: PeerCredentials, document: Any
    ) -> dict[str, Any]:
        call_id = str(uuid.uuid4())
        started_at = time.monotonic()
        self._record_received(peer, document, call_id=call_id)
        reply = self._reply_for_document_unlogged(peer, document)
        self._record_reply(
            peer,
            document,
            reply,
            call_id=call_id,
            started_at=started_at,
        )
        return reply

    def _reply_for_document_unlogged(
        self, peer: PeerCredentials, document: Any
    ) -> dict[str, Any]:
        operation_id = _valid_operation_id_or_none(document)
        try:
            request = BrokerRequest.from_wire(document)
            if request.operation is BrokerOperation.EPHEMERAL_SECRET_FD:
                raise BrokerError(
                    "secret_fd_transport_required",
                    "Ephemeral credentials are available only through the authenticated descriptor transport.",
                    operation_id=request.operation_id,
                )
            accepted = self._acceptor.accept(peer, request)
            result = self._writer.execute(accepted)
            return {
                "version": PROTOCOL_VERSION,
                "operation_id": request.operation_id,
                "ok": True,
                "result": result,
            }
        except BrokerError as exc:
            return _error_reply(
                exc.code,
                exc.message,
                operation_id=exc.operation_id or operation_id,
            )
        except Exception:
            _LOGGER.exception(
                "broker request failed unexpectedly operation_id=%s", operation_id
            )
            return _error_reply(
                "internal_error",
                "The Coordinator could not complete the request; retry shortly.",
                operation_id=operation_id,
            )

    def reply_for_payload(
        self, peer: PeerCredentials, payload: bytes
    ) -> bytes:
        call_id = str(uuid.uuid4())
        started_at = time.monotonic()
        try:
            document = _decode_json_document(payload)
        except BrokerError as exc:
            reply = _error_reply(
                exc.code, exc.message, operation_id=exc.operation_id
            )
            self._record_received(peer, None, call_id=call_id)
            self._record_reply(
                peer,
                None,
                reply,
                call_id=call_id,
                started_at=started_at,
            )
            return _encode_json_document(reply)
        self._record_received(peer, document, call_id=call_id)
        reply = self._reply_for_document_unlogged(peer, document)
        self._record_reply(
            peer,
            document,
            reply,
            call_id=call_id,
            started_at=started_at,
        )
        return _encode_json_document(reply)

    def transport_response_for_payload(
        self,
        peer: PeerCredentials,
        payload: bytes,
        *,
        call_id: str | None = None,
        started_at: float | None = None,
    ) -> _BrokerTransportResponse:
        """Return a redacted reply and, only when accepted, one secret FD.

        The ordinary JSON endpoint deliberately refuses the secret operation so
        neither the serialized writer nor its completed-result cache can ever
        retain credential material.  This method is called only by the Unix
        transport that can carry a descriptor with ``SCM_RIGHTS``.
        """

        effective_call_id = call_id or str(uuid.uuid4())
        effective_started_at = (
            time.monotonic() if started_at is None else float(started_at)
        )
        try:
            document = _decode_json_document(payload)
        except BrokerError as exc:
            reply = _error_reply(
                exc.code, exc.message, operation_id=exc.operation_id
            )
            self._record_received(peer, None, call_id=effective_call_id)
            self._record_reply(
                peer,
                None,
                reply,
                call_id=effective_call_id,
                started_at=effective_started_at,
            )
            return _BrokerTransportResponse(_encode_json_document(reply))

        self._record_received(peer, document, call_id=effective_call_id)
        if not (
            isinstance(document, Mapping)
            and document.get("operation") == BrokerOperation.EPHEMERAL_SECRET_FD.value
        ):
            reply = self._reply_for_document_unlogged(peer, document)
            self._record_reply(
                peer,
                document,
                reply,
                call_id=effective_call_id,
                started_at=effective_started_at,
            )
            return _BrokerTransportResponse(_encode_json_document(reply))

        operation_id = _valid_operation_id_or_none(document)
        secret_fd: Optional[int] = None
        secret_delivery: Optional[EphemeralSecretFdDelivery] = None
        response: _BrokerTransportResponse
        reply: dict[str, Any]
        try:
            request = BrokerRequest.from_wire(document)
            # Consume-once material must not be requested until this process
            # has proved it can deliver a descriptor.  Otherwise a platform
            # without SCM_RIGHTS support could burn the only credential before
            # the socket layer discovered it could not send the FD.
            if not _descriptor_transport_available():
                raise BrokerError(
                    "secret_fd_transport_unavailable",
                    "This platform does not provide authenticated descriptor transport.",
                    operation_id=request.operation_id,
                )
            retriever = self._secret_fd_retriever
            if retriever is None:
                raise BrokerError(
                    "secret_delivery_unavailable",
                    "The broker has no configured ephemeral credential delivery boundary.",
                    operation_id=request.operation_id,
                )
            accepted = self._acceptor.accept(peer, request)
            template_id = str(request.arguments["template_id"])
            run_id = uuid.UUID(str(request.arguments["run_id"]))
            request_id = uuid.UUID(str(request.arguments["request_id"]))
            secret_delivery = retriever.acquire_ephemeral_secret_fd_delivery(
                accepted,
                template_id=template_id,
                run_id=run_id,
                request_id=request_id,
            )
            secret_fd, expires_at_epoch = _ephemeral_secret_pipe(
                secret_delivery.material,
                request_id,
            )
            reply = {
                "version": PROTOCOL_VERSION,
                "operation_id": request.operation_id,
                "ok": True,
                "result": {
                    "transport": "scm_rights",
                    "request_id": str(request_id),
                    "expires_at_epoch": expires_at_epoch,
                },
            }
            response = _BrokerTransportResponse(
                _encode_json_document(reply),
                secret_fd=secret_fd,
                secret_delivery=secret_delivery,
            )
            secret_fd = None
            secret_delivery = None
        except BrokerError as exc:
            reply = _error_reply(
                exc.code,
                exc.message,
                operation_id=exc.operation_id or operation_id,
            )
            response = _BrokerTransportResponse(_encode_json_document(reply))
        except (AttributeError, TypeError, ValueError):
            # Material validation deliberately does not interpolate an object
            # or exception: either could contain the secret in an unsafe repr.
            reply = _error_reply(
                "secret_delivery_invalid",
                "The broker could not safely prepare the ephemeral credential.",
                operation_id=operation_id,
            )
            response = _BrokerTransportResponse(_encode_json_document(reply))
        finally:
            if secret_fd is not None:
                _close_descriptor_quietly(secret_fd)
            if secret_delivery is not None:
                secret_delivery.close()
        self._record_reply(
            peer,
            document,
            reply,
            call_id=effective_call_id,
            started_at=effective_started_at,
        )
        return response

    def record_transport_rejection(
        self,
        *,
        peer: PeerCredentials | None,
        call_id: str,
        started_at: float,
        code: str,
        message: str,
        include_received: bool = True,
    ) -> None:
        """Record a pre-dispatch rejection or post-dispatch delivery failure."""

        journal = self._call_journal
        if journal is None:
            return
        uid = None if peer is None else peer.uid
        gid = None if peer is None else peer.gid
        pid = None if peer is None else peer.pid
        if include_received:
            self._record(
                event_record(
                    boundary="authority.transport",
                    phase="received",
                    call_id=call_id,
                    peer_uid=uid,
                    peer_gid=gid,
                    peer_pid=pid,
                    outcome="received",
                )
            )
        self._record(
            event_record(
                boundary="authority.transport",
                phase="rejected",
                call_id=call_id,
                peer_uid=uid,
                peer_gid=gid,
                peer_pid=pid,
                duration_seconds=max(0.0, time.monotonic() - started_at),
                outcome=(
                    "busy"
                    if code == "server_busy"
                    else "timeout"
                    if code in {"request_timeout", "response_timeout"}
                    else "unavailable"
                    if code in {
                        "transport_aborted",
                        "response_transport_aborted",
                    }
                    else "rejected"
                ),
                code=code,
                message=message,
            )
        )

    def _record_received(
        self,
        peer: PeerCredentials,
        document: object,
        *,
        call_id: str,
    ) -> None:
        request = document if isinstance(document, Mapping) else {}
        arguments = (
            request.get("arguments")
            if isinstance(request.get("arguments"), Mapping)
            else {}
        )
        self._record(
            event_record(
                boundary="authority",
                phase="received",
                call_id=call_id,
                operation=request.get("operation"),
                operation_id=request.get("operation_id"),
                peer_uid=peer.uid,
                peer_gid=peer.gid,
                peer_pid=peer.pid,
                outcome="received",
                account_id=request.get("account_id"),
                project_id=request.get("project_id"),
                repository_generation=request.get("repository_generation"),
                resource_id=request.get("resource_id"),
                run_id=arguments.get("run_id"),
                attempt_id=arguments.get("attempt_id"),
            )
        )

    def _record_reply(
        self,
        peer: PeerCredentials,
        document: object,
        reply: object,
        *,
        call_id: str,
        started_at: float,
    ) -> None:
        ok = isinstance(reply, Mapping) and reply.get("ok") is True
        self._record(
            call_record(
                peer_uid=peer.uid,
                peer_gid=peer.gid,
                peer_pid=peer.pid,
                document=document,
                reply=reply,
                duration_seconds=max(0.0, time.monotonic() - started_at),
                call_id=call_id,
                phase="completed" if ok else "rejected",
                boundary="authority",
            )
        )

    def _record(self, record: Mapping[str, object]) -> None:
        journal = self._call_journal
        if journal is None:
            return
        try:
            journal.record(record)
        except Exception:
            # Recording is strictly observational.  An implementation defect
            # in the journal must never change the authority call outcome.
            _LOGGER.exception("Coordinator call journal rejected a bounded record")


def resolve_peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read best-effort attribution credentials for an ``AF_UNIX`` peer.

    Linux uses ``SO_PEERCRED``.  macOS and BSD use ``getpeereid`` through a
    native socket method when exposed, otherwise through libc.  Local transport
    remains usable when an OS or test double cannot expose credentials; that
    case receives the explicit unmapped attribution identity.
    """

    if connection.family != socket.AF_UNIX:
        raise BrokerError(
            "peer_credentials_unavailable",
            "Broker accepts only authenticated Unix-domain socket peers.",
        )

    if sys.platform.startswith("linux"):
        option = getattr(socket, "SO_PEERCRED", None)
        if option is None:
            return PeerCredentials(
                uid=UNMAPPED_LOCAL_IDENTITY,
                gid=UNMAPPED_LOCAL_IDENTITY,
                pid=None,
            )
        size = struct.calcsize("3i")
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, option, size)
            pid, uid, gid = struct.unpack("3i", raw[:size])
            return PeerCredentials(uid=uid, gid=gid, pid=pid)
        except (OSError, struct.error, ValueError):
            return PeerCredentials(
                uid=UNMAPPED_LOCAL_IDENTITY,
                gid=UNMAPPED_LOCAL_IDENTITY,
                pid=None,
            )

    native_getpeereid = getattr(connection, "getpeereid", None)
    if callable(native_getpeereid):
        try:
            uid, gid = native_getpeereid()
            return PeerCredentials(uid=int(uid), gid=int(gid), pid=None)
        except (OSError, TypeError, ValueError):
            return PeerCredentials(
                uid=UNMAPPED_LOCAL_IDENTITY,
                gid=UNMAPPED_LOCAL_IDENTITY,
                pid=None,
            )

    if sys.platform == "darwin" or "bsd" in sys.platform:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            getpeereid = libc.getpeereid
            getpeereid.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint),
                ctypes.POINTER(ctypes.c_uint),
            ]
            getpeereid.restype = ctypes.c_int
            uid_value = ctypes.c_uint()
            gid_value = ctypes.c_uint()
            result = getpeereid(
                connection.fileno(),
                ctypes.byref(uid_value),
                ctypes.byref(gid_value),
            )
            if result != 0:
                raise OSError(ctypes.get_errno(), "getpeereid failed")
            return PeerCredentials(
                uid=int(uid_value.value), gid=int(gid_value.value), pid=None
            )
        except (AttributeError, OSError, TypeError, ValueError):
            return PeerCredentials(
                uid=UNMAPPED_LOCAL_IDENTITY,
                gid=UNMAPPED_LOCAL_IDENTITY,
                pid=None,
            )

    return PeerCredentials(
        uid=UNMAPPED_LOCAL_IDENTITY,
        gid=UNMAPPED_LOCAL_IDENTITY,
        pid=None,
    )


def validate_runtime_directory(
    runtime_directory: Path,
) -> os.stat_result:
    """Validate the structural Unix-socket directory contract.

    A managed host is one trusted developer boundary.  Unix ownership, groups,
    and mode bits only determine whether the kernel lets a local account reach
    the transport; they are not Coordinator request validation evidence.  Peer UID
    remains available from ``SO_PEERCRED`` for attribution.
    """

    path = Path(runtime_directory)
    if not path.is_absolute():
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory must be an absolute path.",
        )
    if ".." in path.parts:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory must not contain parent traversal.",
        )
    _validate_trusted_path_components(path)
    try:
        info = os.lstat(str(path))
    except OSError:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory is unavailable.",
        ) from None
    if not stat.S_ISDIR(info.st_mode):
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime path is not a directory.",
        )
    return info



class UnixBrokerServer:
    """Concurrent Unix-socket transport around :class:`BrokerService`."""

    def __init__(
        self,
        socket_path: Path,
        service: BrokerService,
        *,
        peer_resolver: Callable[[socket.socket], PeerCredentials] = resolve_peer_credentials,
        socket_mode: int = DEFAULT_SOCKET_MODE,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        self.socket_path = Path(socket_path)
        self._service = service
        self._peer_resolver = peer_resolver
        if (
            not _is_exact_int(socket_mode)
            or socket_mode < 0
            or socket_mode > 0o7777
        ):
            raise ValueError("socket_mode must be a permission mode")
        if not _is_exact_int(max_message_bytes) or max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if shutdown_timeout_seconds <= 0:
            raise ValueError("shutdown_timeout_seconds must be positive")
        if not _is_exact_int(max_clients) or max_clients <= 0:
            raise ValueError("max_clients must be positive")
        self._socket_mode = socket_mode
        self._max_message_bytes = max_message_bytes
        self._request_timeout_seconds = request_timeout_seconds
        self._shutdown_timeout_seconds = float(shutdown_timeout_seconds)
        self._client_slots = threading.BoundedSemaphore(max_clients)
        self._listener: Optional[socket.socket] = None
        self._socket_identity: Optional[tuple[int, int]] = None
        self._owns_socket_path = False
        self._stop = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._clients_lock = threading.Lock()
        self._client_threads: set[threading.Thread] = set()
        self._client_connections: set[socket.socket] = set()

    def start(self, *, listener: Optional[socket.socket] = None) -> None:
        if self._listener is not None:
            raise RuntimeError("broker server is already started")
        _validate_socket_path(self.socket_path)
        runtime_info = validate_runtime_directory(self.socket_path.parent)
        inherited = listener is not None
        if not inherited:
            try:
                os.lstat(str(self.socket_path))
            except FileNotFoundError:
                pass
            except OSError:
                raise BrokerError(
                    "unsafe_socket_path", "Broker socket path could not be inspected."
                ) from None
            else:
                raise BrokerError(
                    "socket_path_exists",
                    "Broker socket path already exists; direct server startup never "
                    "replaces it.",
                )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        assert listener is not None
        listener.set_inheritable(False)
        try:
            if inherited:
                if listener.family != socket.AF_UNIX:
                    raise BrokerError(
                        "invalid_inherited_socket",
                        "Inherited broker listener is not AF_UNIX.",
                    )
                if listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                    raise BrokerError(
                        "invalid_inherited_socket",
                        "Inherited broker listener is not a stream socket.",
                    )
                if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
                    raise BrokerError(
                        "invalid_inherited_socket",
                        "Inherited broker stream socket is not listening.",
                    )
                if listener.getsockname() != str(self.socket_path):
                    raise BrokerError(
                        "invalid_inherited_socket",
                        "Inherited broker listener path does not match the configured authority socket.",
                    )
            else:
                listener.bind(str(self.socket_path))

            created = os.lstat(str(self.socket_path))
            if not stat.S_ISSOCK(created.st_mode):
                raise BrokerError(
                    "unsafe_socket_path",
                    "Broker socket path is not a Unix socket.",
                )
            # Direct startup owns the pathname it created.  A systemd-owned
            # pathname remains present across daemon replacement and must
            # never be unlinked by this process.
            self._socket_identity = (created.st_dev, created.st_ino)
            self._owns_socket_path = not inherited
            if not inherited:
                os.chmod(str(self.socket_path), self._socket_mode)
            runtime_after = validate_runtime_directory(self.socket_path.parent)
            info = os.lstat(str(self.socket_path))
            if (
                not stat.S_ISSOCK(info.st_mode)
                or (info.st_dev, info.st_ino) != self._socket_identity
                or (runtime_after.st_dev, runtime_after.st_ino)
                != (runtime_info.st_dev, runtime_info.st_ino)
            ):
                raise BrokerError(
                    "unsafe_socket_path",
                    "Broker socket identity changed during startup.",
                )
            if not inherited:
                listener.listen()
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            self._remove_created_socket_if_owned()
            self._socket_identity = None
            self._owns_socket_path = False
            raise

        self._listener = listener
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._serve,
            name="devcoordinator-broker-accept",
            daemon=True,
        )
        self._accept_thread.start()

    def close(self, *, timeout_seconds: Optional[float] = None) -> None:
        timeout = (
            self._shutdown_timeout_seconds
            if timeout_seconds is None
            else float(timeout_seconds)
        )
        if timeout < 0:
            raise ValueError("timeout_seconds must be non-negative")
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        accept_thread = self._accept_thread
        self._accept_thread = None
        deadline = time.monotonic() + timeout
        if accept_thread is not None:
            accept_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        drain_error: Optional[BrokerError] = None
        while True:
            with self._clients_lock:
                clients = list(self._client_threads)
                connections = list(self._client_connections)
            if not clients:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # The published graceful deadline has expired.  Only now may
                # transport cleanup interrupt an accepted client.  Backend
                # mutation threads remain visible to the writer drain proof.
                for connection in connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                for client in clients:
                    client.join(timeout=0.1)
                drain_error = BrokerError(
                    "shutdown_timeout",
                    "Broker could not drain all accepted clients before the shutdown deadline.",
                )
                break
            for client in clients:
                client.join(timeout=min(remaining, 0.1))
        if accept_thread is not None and accept_thread.is_alive():
            drain_error = BrokerError(
                "shutdown_timeout",
                "Broker accept loop did not stop before the shutdown deadline.",
            )
        self._remove_created_socket_if_owned()
        self._socket_identity = None
        self._owns_socket_path = False
        if drain_error is not None:
            raise drain_error

    def __enter__(self) -> "UnixBrokerServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set() or self._listener is None:
                    return
                _LOGGER.exception("broker accept failed")
                continue
            connection.settimeout(self._request_timeout_seconds)
            if self._stop.is_set():
                connection.close()
                return
            if not self._client_slots.acquire(blocking=False):
                # Never let a saturated client that refuses to read block the
                # accept loop for the normal request timeout.
                call_id = str(uuid.uuid4())
                started_at = time.monotonic()
                self._service.record_transport_rejection(
                    peer=None,
                    call_id=call_id,
                    started_at=started_at,
                    code="server_busy",
                    message="Broker has reached its bounded client capacity; retry later.",
                )
                connection.settimeout(min(self._request_timeout_seconds, 0.1))
                _safe_send_reply(
                    connection,
                    _error_reply(
                        "server_busy",
                        "Broker has reached its bounded client capacity; retry later.",
                        operation_id=None,
                    ),
                    max_message_bytes=self._max_message_bytes,
                )
                connection.close()
                continue
            thread = threading.Thread(
                target=self._handle_client_thread,
                args=(connection,),
                name="devcoordinator-broker-client",
                daemon=True,
            )
            with self._clients_lock:
                self._client_threads.add(thread)
                self._client_connections.add(connection)
            try:
                thread.start()
            except BaseException:
                with self._clients_lock:
                    self._client_threads.discard(thread)
                    self._client_connections.discard(connection)
                self._client_slots.release()
                connection.close()
                raise

    def _handle_client_thread(self, connection: socket.socket) -> None:
        try:
            self._handle_connection(connection)
        finally:
            connection.close()
            with self._clients_lock:
                self._client_threads.discard(threading.current_thread())
                self._client_connections.discard(connection)
            self._client_slots.release()

    def _handle_connection(self, connection: socket.socket) -> None:
        connection.settimeout(self._request_timeout_seconds)
        call_id = str(uuid.uuid4())
        started_at = time.monotonic()
        peer: PeerCredentials | None = None
        dispatched = False
        try:
            peer = self._peer_resolver(connection)
        except BrokerError as exc:
            self._service.record_transport_rejection(
                peer=None,
                call_id=call_id,
                started_at=started_at,
                code=exc.code,
                message=exc.message,
            )
            _safe_send_reply(
                connection,
                _error_reply(exc.code, exc.message, operation_id=None),
                max_message_bytes=self._max_message_bytes,
            )
            return
        try:
            payload = _receive_frame_rejecting_fds(
                connection, max_message_bytes=self._max_message_bytes
            )
            dispatched = True
            response = self._service.transport_response_for_payload(
                peer,
                payload,
                call_id=call_id,
                started_at=started_at,
            )
            try:
                if response.secret_fd is None:
                    _send_frame(
                        connection,
                        response.payload,
                        max_message_bytes=self._max_message_bytes,
                    )
                else:
                    _send_frame_with_fd(
                        connection,
                        response.payload,
                        response.secret_fd,
                        max_message_bytes=self._max_message_bytes,
                    )
            finally:
                if response.secret_fd is not None:
                    _close_descriptor_quietly(response.secret_fd)
                if response.secret_delivery is not None:
                    response.secret_delivery.close()
        except BrokerError as exc:
            self._service.record_transport_rejection(
                peer=peer,
                call_id=call_id,
                started_at=started_at,
                code=exc.code,
                message=exc.message,
                include_received=not dispatched,
            )
            _safe_send_reply(
                connection,
                _error_reply(exc.code, exc.message, operation_id=exc.operation_id),
                max_message_bytes=self._max_message_bytes,
            )
        except socket.timeout:
            self._service.record_transport_rejection(
                peer=peer,
                call_id=call_id,
                started_at=started_at,
                code="response_timeout" if dispatched else "request_timeout",
                message=(
                    "Broker reply transport timed out after dispatch."
                    if dispatched
                    else "Broker request transport timed out before dispatch."
                ),
                include_received=not dispatched,
            )
            return
        except OSError:
            self._service.record_transport_rejection(
                peer=peer,
                call_id=call_id,
                started_at=started_at,
                code=(
                    "response_transport_aborted"
                    if dispatched
                    else "transport_aborted"
                ),
                message=(
                    "Broker reply transport closed after dispatch."
                    if dispatched
                    else "Broker request transport closed before dispatch."
                ),
                include_received=not dispatched,
            )
            return

    def _remove_created_socket_if_owned(self) -> None:
        if not self._owns_socket_path:
            return
        identity = self._socket_identity
        if identity is None:
            return
        try:
            info = os.lstat(str(self.socket_path))
        except FileNotFoundError:
            return
        except OSError:
            _LOGGER.exception("could not inspect broker socket during cleanup")
            return
        if (
            (info.st_dev, info.st_ino) == identity
            and stat.S_ISSOCK(info.st_mode)
        ):
            try:
                os.unlink(str(self.socket_path))
            except OSError:
                _LOGGER.exception("could not remove broker socket during cleanup")


class BrokerClient:
    """One-request client using a stable local Unix-socket endpoint.

    ``SO_PEERCRED`` is captured for attribution. Successful connection plus a
    stable Unix-socket identity is the complete trusted-local transport model.
    """

    def __init__(
        self,
        socket_path: Path,
        *,
        timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        maintenance_root: Optional[Path] = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not _is_exact_int(max_message_bytes) or max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")
        self._timeout_seconds = timeout_seconds
        self._max_message_bytes = max_message_bytes
        self._maintenance_root = (
            MAINTENANCE_ROOT
            if maintenance_root is None
            and self.socket_path == SYSTEM_BROKER_SOCKET_PATH
            else (None if maintenance_root is None else Path(maintenance_root))
        )
        self.last_peer_credentials: PeerCredentials | None = None

    def _require_available(self, *, operation_id: str) -> None:
        if self._maintenance_root is None:
            return
        try:
            maintenance = load_maintenance_state(maintenance_root=self._maintenance_root)
        except MaintenanceMarkerError as error:
            raise BrokerError(
                "maintenance_state_invalid",
                "Coordinator maintenance state cannot be verified; wait for the administrator before retrying.",
                operation_id=operation_id,
                retry_after_seconds=60,
            ) from error
        bypass = str(
            os.environ.get("DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID") or ""
        ).strip()
        if maintenance is not None and bypass == maintenance.deployment_id:
            # The clean-adoption route producer runs one owner-attributed,
            # read-only inventory call while the exact root-owned maintenance
            # deployment remains active.  A stale or guessed value cannot
            # bypass another deployment because it must equal the currently
            # verified marker identity.
            return
        if maintenance is not None:
            raise BrokerError(
                "maintenance_in_progress",
                PUBLIC_MAINTENANCE_MESSAGE,
                operation_id=operation_id,
                retry_after_seconds=maintenance.retry_after_seconds,
            )

    def call(self, request: BrokerRequest) -> dict[str, Any]:
        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be BrokerRequest")
        if request.operation is BrokerOperation.EPHEMERAL_SECRET_FD:
            raise TypeError(
                "ephemeral.secret_fd requires retrieve_ephemeral_secret_fd(); "
                "ordinary JSON broker calls never receive credential material"
            )
        self._require_available(operation_id=request.operation_id)
        payload = _encode_json_document(request.to_wire())
        with self._authenticated_connection(request) as connection:
            try:
                _send_frame(
                    connection, payload, max_message_bytes=self._max_message_bytes
                )
            except (BrokenPipeError, ConnectionResetError) as send_error:
                # A saturated broker rejects a connection before reading the
                # request.  Unix stream sockets may surface the peer's close
                # on our send even though its authenticated ``server_busy``
                # frame is already queued for reading.  Consume and validate
                # that bounded transport reply; if no complete reply exists,
                # retain the original transport failure.
                try:
                    reply_payload = _receive_frame_rejecting_fds(
                        connection, max_message_bytes=self._max_message_bytes
                    )
                except (BrokerError, OSError, socket.timeout):
                    raise send_error
            else:
                reply_payload = _receive_frame_rejecting_fds(
                    connection, max_message_bytes=self._max_message_bytes
                )
        document = _decode_json_document(reply_payload)
        return _validate_reply(document, expected_operation_id=request.operation_id)

    def retrieve_ephemeral_secret_fd(
        self, request: BrokerRequest
    ) -> EphemeralSecretFD:
        """Retrieve exactly one run credential through ``SCM_RIGHTS``.

        This method cannot be used through the ordinary CLI JSON result path:
        callers receive an in-process, read-only descriptor and must consume
        then close it.  A broken connection after manager consumption is
        intentionally ambiguous and must be retried only as a fail-closed
        replay check, never as a request for a second credential.
        """

        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be BrokerRequest")
        if request.operation is not BrokerOperation.EPHEMERAL_SECRET_FD:
            raise TypeError("request must use ephemeral.secret_fd")
        self._require_available(operation_id=request.operation_id)
        if not _descriptor_transport_available():
            raise BrokerError(
                "secret_fd_transport_unavailable",
                "This platform does not provide authenticated descriptor transport.",
                operation_id=request.operation_id,
            )
        payload = _encode_json_document(request.to_wire())
        descriptor: Optional[int] = None
        try:
            with self._authenticated_connection(request) as connection:
                _send_frame(
                    connection, payload, max_message_bytes=self._max_message_bytes
                )
                reply_payload, descriptor = _receive_frame_with_one_fd(
                    connection, max_message_bytes=self._max_message_bytes
                )
            document = _decode_json_document(reply_payload)
            reply = _validate_reply(
                document, expected_operation_id=request.operation_id
            )
            if not bool(reply["ok"]):
                _raise_reply_error(reply, operation_id=request.operation_id)
            if descriptor is None:
                raise BrokerError(
                    "secret_fd_missing",
                    "Broker credential reply did not carry exactly one descriptor.",
                    operation_id=request.operation_id,
                )
            result = _validate_ephemeral_secret_fd_result(
                reply["result"],
                expected_request_id=str(request.arguments["request_id"]),
                operation_id=request.operation_id,
            )
            received = EphemeralSecretFD(
                fd=descriptor,
                operation_id=request.operation_id,
                request_id=result["request_id"],
                expires_at_epoch=result["expires_at_epoch"],
            )
            descriptor = None
            return received
        finally:
            if descriptor is not None:
                _close_descriptor_quietly(descriptor)

    @contextmanager
    def _authenticated_connection(
        self, request: BrokerRequest
    ) -> Iterable[socket.socket]:
        socket_before = _validate_client_socket(self.socket_path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self._timeout_seconds)
            try:
                connection.connect(str(self.socket_path))
            except PermissionError as error:
                if error.errno not in {errno.EACCES, errno.EPERM}:
                    raise
                raise BrokerError(
                    "broker_transport_forbidden",
                    "This execution environment blocks the Coordinator's local Unix-socket transport; retry through an approved host Coordinator invocation.",
                    operation_id=request.operation_id,
                ) from error
            # Capture the kernel-reported peer for attribution and
            # diagnostics.  Multiple local Unix accounts belong to the same
            # developer, so its UID is deliberately not an request validation gate.
            self.last_peer_credentials = resolve_peer_credentials(connection)
            socket_after = _validate_client_socket(self.socket_path)
            if (socket_before.st_dev, socket_before.st_ino) != (
                socket_after.st_dev,
                socket_after.st_ino,
            ):
                raise BrokerError(
                    "broker_identity_mismatch",
                    "Broker socket identity changed while connecting.",
                    operation_id=request.operation_id,
                )
            yield connection


def _validate_arguments(
    operation: BrokerOperation,
    value: Any,
    *,
    operation_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerError(
            "invalid_arguments",
            "Broker operation arguments must be a JSON object.",
            operation_id=operation_id,
        )

    if operation == BrokerOperation.PORT_LEASE:
        allowed = {
            "requested_port",
            "protocol",
            "ttl_seconds",
            "adopt_existing_listener",
        }
        unexpected = sorted(set(value) - allowed)
        if unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Port lease contains unsupported arguments: "
                + ", ".join(unexpected)
                + ".",
                operation_id=operation_id,
            )
        normalized: dict[str, Any] = {}
        if "requested_port" in value:
            port = value["requested_port"]
            if not _is_exact_int(port) or not 1 <= port <= 65535:
                raise BrokerError(
                    "invalid_arguments",
                    "requested_port must be an integer from 1 through 65535.",
                    operation_id=operation_id,
                )
            normalized["requested_port"] = port
        protocol = value.get("protocol", "tcp")
        if protocol not in {"tcp", "udp"}:
            raise BrokerError(
                "invalid_arguments",
                "protocol must be tcp or udp.",
                operation_id=operation_id,
            )
        normalized["protocol"] = protocol
        adopt_existing = value.get("adopt_existing_listener", False)
        if type(adopt_existing) is not bool:
            raise BrokerError(
                "invalid_arguments",
                "adopt_existing_listener must be a boolean.",
                operation_id=operation_id,
            )
        if adopt_existing:
            if "requested_port" not in normalized or protocol != "tcp":
                raise BrokerError(
                    "invalid_arguments",
                    "listener adoption requires one exact requested TCP port.",
                    operation_id=operation_id,
                )
            normalized["adopt_existing_listener"] = True
        if "ttl_seconds" in value:
            ttl = value["ttl_seconds"]
            if not _is_exact_int(ttl) or not 1 <= ttl <= 7 * 24 * 60 * 60:
                raise BrokerError(
                    "invalid_arguments",
                    "ttl_seconds must be a positive integer no greater than seven days.",
                    operation_id=operation_id,
                )
            normalized["ttl_seconds"] = ttl
        return normalized

    if operation == BrokerOperation.PORT_RELEASE:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Port release does not accept client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.PORT_ASSIGN:
        if set(value) != {"port"}:
            raise BrokerError(
                "invalid_arguments",
                "Port assignment accepts exactly one typed port argument.",
                operation_id=operation_id,
            )
        port = value["port"]
        if not _is_exact_int(port) or not 1 <= port <= 65535:
            raise BrokerError(
                "invalid_arguments",
                "port must be an integer from 1 through 65535.",
                operation_id=operation_id,
            )
        return {"port": port}

    if operation == BrokerOperation.PORT_UNASSIGN:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Port unassignment does not accept client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.CAPABILITIES_READ:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Capability reads accept no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.REPOSITORY_ENSURE:
        if set(value) != {
            "agent",
            "canonical_root",
            "project_kind",
        }:
            raise BrokerError(
                "invalid_arguments",
                "Repository ensure requires one canonical root, project kind, and agent attribution.",
                operation_id=operation_id,
            )
        canonical_root = value["canonical_root"]
        if (
            not isinstance(canonical_root, str)
            or not 1 <= len(os.fsencode(canonical_root)) <= 4096
            or "\x00" in canonical_root
            or not Path(canonical_root).is_absolute()
            or os.path.normpath(canonical_root) != canonical_root
        ):
            raise BrokerError(
                "invalid_arguments",
                "canonical_root must be one normalized absolute path.",
                operation_id=operation_id,
            )
        project_kind = value["project_kind"]
        if project_kind not in {"primary", "temporary"}:
            raise BrokerError(
                "invalid_arguments",
                "project_kind must be primary or temporary.",
                operation_id=operation_id,
            )
        return {
            "agent": _bounded_agent(value["agent"], operation_id),
            "canonical_root": canonical_root,
            "project_kind": project_kind,
        }

    if operation == BrokerOperation.REPOSITORY_RESOLVE:
        if set(value) != {"canonical_root"}:
            raise BrokerError(
                "invalid_arguments",
                "Repository resolution requires exactly one canonical root.",
                operation_id=operation_id,
            )
        canonical_root = value["canonical_root"]
        if (
            not isinstance(canonical_root, str)
            or not 1 <= len(os.fsencode(canonical_root)) <= 4096
            or "\x00" in canonical_root
            or not Path(canonical_root).is_absolute()
            or os.path.normpath(canonical_root) != canonical_root
        ):
            raise BrokerError(
                "invalid_arguments",
                "canonical_root must be one normalized absolute path.",
                operation_id=operation_id,
            )
        return {"canonical_root": canonical_root}

    if operation == BrokerOperation.OPERATION_FOLLOW:
        if set(value) != {"operation_id"}:
            raise BrokerError(
                "invalid_arguments",
                "Operation follow accepts exactly one operation_id.",
                operation_id=operation_id,
            )
        return {
            "operation_id": _canonical_uuid_argument(
                value["operation_id"], "operation_id", operation_id
            )
        }

    if operation == BrokerOperation.INVENTORY_READ:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Host inventory accepts no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.EVENTS_READ:
        unexpected = sorted(set(value) - {"after", "limit"})
        if unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Event reads contain unsupported arguments: "
                + ", ".join(unexpected)
                + ".",
                operation_id=operation_id,
            )
        normalized: dict[str, Any] = {}
        if "after" in value:
            after = value["after"]
            if not isinstance(after, str) or not 1 <= len(after) <= 1024:
                raise BrokerError(
                    "invalid_arguments",
                    "after must be a bounded non-empty event cursor.",
                    operation_id=operation_id,
                )
            normalized["after"] = after
        limit = value.get("limit", 100)
        if not _is_exact_int(limit) or not 1 <= limit <= 500:
            raise BrokerError(
                "invalid_arguments",
                "limit must be an integer from 1 through 500.",
                operation_id=operation_id,
            )
        normalized["limit"] = limit
        return normalized

    if operation == BrokerOperation.HOST_OBSERVE:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Host observation accepts no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.TEST_RUN_START:
        required = {
            "agent",
            "suite",
            "run_kind",
            "selection",
            "command_fingerprint",
            "started_at",
        }
        allowed = required | {"parent_run_id"}
        if not required <= set(value) or set(value) - allowed:
            raise BrokerError(
                "invalid_arguments",
                "Test run start requires agent, suite, run_kind, selection, command_fingerprint and started_at.",
                operation_id=operation_id,
            )
        suite = value["suite"]
        if (
            not isinstance(suite, str)
            or not 1 <= len(suite) <= 160
            or any(ord(character) < 32 for character in suite)
        ):
            raise BrokerError(
                "invalid_arguments",
                "suite must be bounded printable text.",
                operation_id=operation_id,
            )
        if value["run_kind"] not in {"session", "test", "automation"}:
            raise BrokerError(
                "invalid_arguments",
                "run_kind must be session, test or automation.",
                operation_id=operation_id,
            )
        selection = value["selection"]
        if (
            not isinstance(selection, list)
            or len(selection) > 2_000
            or any(
                not isinstance(item, str) or not 1 <= len(item) <= 2_048
                for item in selection
            )
        ):
            raise BrokerError(
                "invalid_arguments",
                "selection must contain at most 2000 bounded test selectors.",
                operation_id=operation_id,
            )
        command_fingerprint = value["command_fingerprint"]
        if not isinstance(command_fingerprint, str) or not _SHA256_FINGERPRINT.fullmatch(
            command_fingerprint
        ):
            raise BrokerError(
                "invalid_arguments",
                "command_fingerprint must be an exact sha256 digest.",
                operation_id=operation_id,
            )
        started_at = value["started_at"]
        if not isinstance(started_at, str) or not 1 <= len(started_at) <= 64:
            raise BrokerError(
                "invalid_arguments",
                "started_at must be a bounded ISO-8601 timestamp.",
                operation_id=operation_id,
            )
        parent_run_id = value.get("parent_run_id")
        if parent_run_id is not None and _canonical_uuid_value(parent_run_id) is None:
            raise BrokerError(
                "invalid_arguments",
                "parent_run_id must be a canonical UUID.",
                operation_id=operation_id,
            )
        return {
            "agent": _bounded_agent(value["agent"], operation_id),
            "suite": suite,
            "run_kind": value["run_kind"],
            "selection": selection,
            "command_fingerprint": command_fingerprint,
            "started_at": started_at,
            **({"parent_run_id": parent_run_id} if parent_run_id is not None else {}),
        }

    if operation == BrokerOperation.TEST_RUN_FINISH:
        required = {
            "run_id",
            "status",
            "finished_at",
            "duration_seconds",
            "exit_code",
            "cases",
        }
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Test run finish requires exactly run_id, status, finished_at, duration_seconds, exit_code and cases.",
                operation_id=operation_id,
            )
        run_id = value["run_id"]
        if _canonical_uuid_value(run_id) is None:
            raise BrokerError(
                "invalid_arguments", "run_id must be a canonical UUID.", operation_id=operation_id
            )
        status = value["status"]
        if status not in {"passed", "failed", "cancelled", "incomplete"}:
            raise BrokerError(
                "invalid_arguments",
                "status must be passed, failed, cancelled or incomplete.",
                operation_id=operation_id,
            )
        finished_at = value["finished_at"]
        duration = value["duration_seconds"]
        exit_code = value["exit_code"]
        if not isinstance(finished_at, str) or not 1 <= len(finished_at) <= 64:
            raise BrokerError(
                "invalid_arguments",
                "finished_at must be a bounded ISO-8601 timestamp.",
                operation_id=operation_id,
            )
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not 0 <= float(duration) <= 31 * 24 * 60 * 60
        ):
            raise BrokerError(
                "invalid_arguments",
                "duration_seconds must be a non-negative number no greater than 31 days.",
                operation_id=operation_id,
            )
        if not _is_exact_int(exit_code) or not -255 <= exit_code <= 255:
            raise BrokerError(
                "invalid_arguments",
                "exit_code must be an integer from -255 through 255.",
                operation_id=operation_id,
            )
        cases = value["cases"]
        if not isinstance(cases, list) or len(cases) > 100_000:
            raise BrokerError(
                "invalid_arguments",
                "cases must contain at most 100000 individual results.",
                operation_id=operation_id,
            )
        normalized_cases = []
        case_fields = {
            "test_id",
            "display_name",
            "status",
            "started_at",
            "finished_at",
            "duration_seconds",
        }
        for case in cases:
            if not isinstance(case, dict) or set(case) != case_fields:
                raise BrokerError(
                    "invalid_arguments",
                    "Each test case must use the exact structured timing result fields.",
                    operation_id=operation_id,
                )
            if case["status"] not in {"passed", "failed", "skipped", "error"}:
                raise BrokerError(
                    "invalid_arguments",
                    "Individual test status is invalid.",
                    operation_id=operation_id,
                )
            if any(
                not isinstance(case[field], str) or not 1 <= len(case[field]) <= maximum
                for field, maximum in (
                    ("test_id", 2_048),
                    ("display_name", 2_048),
                    ("started_at", 64),
                    ("finished_at", 64),
                )
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "Individual test identity and timestamps must be bounded strings.",
                    operation_id=operation_id,
                )
            case_duration = case["duration_seconds"]
            if (
                isinstance(case_duration, bool)
                or not isinstance(case_duration, (int, float))
                or not 0 <= float(case_duration) <= 31 * 24 * 60 * 60
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "Individual test duration is invalid.",
                    operation_id=operation_id,
                )
            normalized_cases.append(dict(case))
        return {
            "run_id": run_id,
            "status": status,
            "finished_at": finished_at,
            "duration_seconds": float(duration),
            "exit_code": exit_code,
            "cases": normalized_cases,
        }

    if operation == BrokerOperation.TEST_HEALTH:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Authenticated test health accepts no arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.TEST_STATS_READ:
        if set(value) - {"days", "limit"}:
            raise BrokerError(
                "invalid_arguments",
                "Test statistics accept only days and limit.",
                operation_id=operation_id,
            )
        days = value.get("days", 30)
        limit = value.get("limit", 25)
        if not _is_exact_int(days) or not 1 <= days <= 3_650:
            raise BrokerError(
                "invalid_arguments", "days must be from 1 through 3650.", operation_id=operation_id
            )
        if not _is_exact_int(limit) or not 1 <= limit <= 500:
            raise BrokerError(
                "invalid_arguments", "limit must be from 1 through 500.", operation_id=operation_id
            )
        return {"days": days, "limit": limit}

    if operation == BrokerOperation.TEST_FLEET_STATS_READ:
        if set(value) - {"hours"}:
            raise BrokerError(
                "invalid_arguments",
                "Fleet test statistics accept only hours.",
                operation_id=operation_id,
            )
        hours = value.get("hours", 24)
        if not _is_exact_int(hours) or not 1 <= hours <= 168:
            raise BrokerError(
                "invalid_arguments",
                "hours must be from 1 through 168.",
                operation_id=operation_id,
            )
        return {"hours": hours}

    if operation == BrokerOperation.TEST_PLAN_PREVIEW:
        expected = {
            "intent",
            "temporary_root",
            "requested_targets",
            "execution_timeout_seconds",
            "launch_timeout_seconds",
        }
        if set(value) != expected:
            raise BrokerError(
                "invalid_arguments",
                "Test plan preview requires intent, source, targets, and exact timeout policy.",
                operation_id=operation_id,
            )
        intent = value["intent"]
        if intent not in {"change", "checkpoint", "handoff", "release", "manual"}:
            raise BrokerError(
                "invalid_arguments",
                "Test plan preview intent is invalid.",
                operation_id=operation_id,
            )
        temporary_root = value.get("temporary_root")
        if temporary_root is not None:
            temporary_root = _bounded_single_line_argument(
                temporary_root,
                "temporary_root",
                operation_id,
                maximum_bytes=4096,
            )
            if not temporary_root.startswith("/"):
                raise BrokerError(
                    "invalid_arguments",
                    "temporary_root must be absolute.",
                    operation_id=operation_id,
                )
        requested_raw = value.get("requested_targets", [])
        if (
            not isinstance(requested_raw, list)
            or len(requested_raw) > 256
        ):
            raise BrokerError(
                "invalid_arguments",
                "requested_targets must be a bounded array.",
                operation_id=operation_id,
            )
        requested_targets = [
            _bounded_single_line_argument(
                item,
                "requested_targets[]",
                operation_id,
                maximum_bytes=128,
            )
            for item in requested_raw
        ]
        if len(set(requested_targets)) != len(requested_targets):
            raise BrokerError(
                "invalid_arguments",
                "requested_targets must be unique.",
                operation_id=operation_id,
            )
        if requested_targets and intent != "manual":
            raise BrokerError(
                "invalid_arguments",
                "requested_targets are supported only for manual intent.",
                operation_id=operation_id,
            )
        execution_timeout = value["execution_timeout_seconds"]
        if execution_timeout is not None and (
            not _is_exact_int(execution_timeout)
            or not 1 <= execution_timeout <= 86_400
        ):
            raise BrokerError(
                "invalid_arguments",
                "execution_timeout_seconds must be null or an integer from 1 through 86400.",
                operation_id=operation_id,
            )
        launch_timeout = value["launch_timeout_seconds"]
        if (
            not _is_exact_int(launch_timeout)
            or not 1 <= launch_timeout <= 3_600
        ):
            raise BrokerError(
                "invalid_arguments",
                "launch_timeout_seconds must be an integer from 1 through 3600.",
                operation_id=operation_id,
            )
        return {
            "intent": intent,
            "temporary_root": temporary_root,
            "requested_targets": requested_targets,
            "execution_timeout_seconds": execution_timeout,
            "launch_timeout_seconds": launch_timeout,
        }

    if operation == BrokerOperation.TEST_PLAN_REGISTER:
        if set(value) != {"plan", "manifest", "actor"}:
            raise BrokerError(
                "invalid_arguments",
                "Test plan registration requires exactly plan, manifest, and actor.",
                operation_id=operation_id,
            )
        return {
            "plan": _bounded_json_object(
                value["plan"], "plan", operation_id, maximum_bytes=8 * 1024 * 1024
            ),
            "manifest": _bounded_json_object(
                value["manifest"], "manifest", operation_id, maximum_bytes=1024 * 1024
            ),
            "actor": _bounded_single_line_argument(
                value["actor"], "actor", operation_id, maximum_bytes=256
            ),
        }

    if operation == BrokerOperation.TEST_RUN_SUBMIT:
        required = {"plan_id", "expected_repository_id", "actor"}
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Test submission requires exactly plan_id, expected_repository_id, and actor.",
                operation_id=operation_id,
            )
        return {
            "plan_id": _opaque_argument(value["plan_id"], "plan_id", operation_id),
            "expected_repository_id": _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            ),
            "actor": _bounded_single_line_argument(
                value["actor"],
                "actor",
                operation_id,
                maximum_bytes=256,
            ),
        }

    if operation == BrokerOperation.TEST_RUN_LIST:
        allowed = {"after", "limit", "state"}
        if set(value) - allowed:
            raise BrokerError(
                "invalid_arguments",
                "Test run history accepts only after, limit, and state.",
                operation_id=operation_id,
            )
        limit = value.get("limit", 50)
        if not _is_exact_int(limit) or not 1 <= limit <= 200:
            raise BrokerError(
                "invalid_arguments",
                "Test run history limit must be from 1 through 200.",
                operation_id=operation_id,
            )
        normalized = {"limit": limit}
        if "after" in value:
            normalized["after"] = _opaque_argument(
                value["after"], "after", operation_id
            )
        if "state" in value:
            state = value["state"]
            if state not in {
                "queued",
                "running",
                "cancelling",
                "superseding",
                "succeeded",
                "failed",
                "timed_out",
                "cancelled",
                "incomplete",
                "abandoned",
                "superseded",
            }:
                raise BrokerError(
                    "invalid_arguments",
                    "Test run history state is invalid.",
                    operation_id=operation_id,
                )
            normalized["state"] = state
        return normalized

    if operation == BrokerOperation.TEST_QUEUE_STATUS:
        if set(value) - {"expected_repository_id"}:
            raise BrokerError(
                "invalid_arguments",
                "Test queue status accepts no selectors.",
                operation_id=operation_id,
            )
        normalized = {}
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation in {BrokerOperation.TEST_RUN_STATUS, BrokerOperation.TEST_RUN_SUMMARY}:
        if "run_id" not in value or set(value) - {"run_id", "expected_repository_id"}:
            raise BrokerError(
                "invalid_arguments",
                "Test run read requires exactly run_id.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id)
        }
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation in {BrokerOperation.TEST_RUN_FAILURES, BrokerOperation.TEST_RUN_ARTIFACTS}:
        allowed = {"run_id", "after", "limit", "expected_repository_id"}
        if "run_id" not in value or set(value) - allowed:
            raise BrokerError(
                "invalid_arguments",
                "Test evidence reads require run_id and accept only after and limit.",
                operation_id=operation_id,
            )
        limit = value.get("limit", 25)
        if not _is_exact_int(limit) or not 1 <= limit <= 50:
            raise BrokerError(
                "invalid_arguments",
                "Test evidence limit must be from 1 through 50.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id),
            "limit": limit,
        }
        if "after" in value:
            normalized["after"] = _opaque_argument(value["after"], "after", operation_id)
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation == BrokerOperation.TEST_RUN_CASES:
        allowed = {"run_id", "after", "limit", "expected_repository_id"}
        if "run_id" not in value or set(value) - allowed:
            raise BrokerError(
                "invalid_arguments",
                "Test case reads require run_id and accept only after and limit.",
                operation_id=operation_id,
            )
        limit = value.get("limit", 25)
        after = value.get("after", 0)
        if not _is_exact_int(limit) or not 1 <= limit <= 50:
            raise BrokerError(
                "invalid_arguments",
                "Test case limit must be from 1 through 50.",
                operation_id=operation_id,
            )
        if not _is_exact_int(after) or after < 0:
            raise BrokerError(
                "invalid_arguments",
                "Test case cursor must be non-negative.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id),
            "after": after,
            "limit": limit,
        }
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation == BrokerOperation.TEST_EVENTS_READ:
        allowed = {"after_event_id", "limit"}
        if set(value) - allowed:
            raise BrokerError(
                "invalid_arguments",
                "Test event reads accept only after_event_id and limit.",
                operation_id=operation_id,
            )
        after_event_id = value.get("after_event_id", 0)
        limit = value.get("limit", 200)
        if not _is_exact_int(after_event_id) or after_event_id < 0:
            raise BrokerError(
                "invalid_arguments",
                "Test event cursor must be non-negative.",
                operation_id=operation_id,
            )
        if not _is_exact_int(limit) or not 1 <= limit <= 500:
            raise BrokerError(
                "invalid_arguments",
                "Test event limit must be from 1 through 500.",
                operation_id=operation_id,
            )
        return {"after_event_id": after_event_id, "limit": limit}

    if operation == BrokerOperation.TEST_REPOSITORY_SETUP:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Test repository setup read accepts no arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.TEST_REPOSITORY_CATALOG:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Test repository catalog read accepts no arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.TEST_RUN_CANCEL:
        if (
            not {"run_id", "reason", "actor"}.issubset(value)
            or set(value) - {"run_id", "reason", "actor", "expected_repository_id"}
        ):
            raise BrokerError(
                "invalid_arguments",
                "Test cancellation requires exactly run_id, reason, and actor.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id),
            "reason": _bounded_reason(value["reason"], operation_id),
            "actor": _bounded_single_line_argument(
                value["actor"],
                "actor",
                operation_id,
                maximum_bytes=256,
            ),
        }
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation == BrokerOperation.TEST_RUN_RETRY:
        if (
            not {"run_id", "failed_only", "actor"}.issubset(value)
            or set(value) - {"run_id", "failed_only", "actor", "expected_repository_id"}
            or type(value["failed_only"]) is not bool
        ):
            raise BrokerError(
                "invalid_arguments",
                "Test retry requires exactly run_id, boolean failed_only, and actor.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id),
            "failed_only": value["failed_only"],
            "actor": _bounded_single_line_argument(
                value["actor"],
                "actor",
                operation_id,
                maximum_bytes=256,
            ),
        }
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    if operation == BrokerOperation.TEST_EVIDENCE_CHECK:
        if set(value) != {"snapshot_id", "policy_name"}:
            raise BrokerError(
                "invalid_arguments",
                "Evidence checks require snapshot_id and policy_name.",
                operation_id=operation_id,
            )
        return {
            "snapshot_id": _opaque_argument(value["snapshot_id"], "snapshot_id", operation_id),
            "policy_name": _opaque_argument(value["policy_name"], "policy_name", operation_id),
        }

    if operation == BrokerOperation.TEST_EVIDENCE_CONSUME:
        if set(value) != {"snapshot_id", "policy_name"}:
            raise BrokerError(
                "invalid_arguments",
                "Evidence consumption requires snapshot_id and policy_name.",
                operation_id=operation_id,
            )
        return {
            "snapshot_id": _opaque_argument(
                value["snapshot_id"], "snapshot_id", operation_id
            ),
            "policy_name": _opaque_argument(
                value["policy_name"], "policy_name", operation_id
            ),
        }

    if operation == BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN:
        if set(value) != {"purpose"} or value["purpose"] != "legacy-test-history-cutover":
            raise BrokerError(
                "invalid_arguments",
                "Test admission drain requires the fixed legacy-history purpose.",
                operation_id=operation_id,
            )
        return {"purpose": "legacy-test-history-cutover"}

    if operation == BrokerOperation.TEST_ADMISSION_DRAIN_STATUS:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Test admission drain status accepts no arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR:
        if set(value) != {"drain_id", "proof_sha256"}:
            raise BrokerError(
                "invalid_arguments",
                "Test admission drain clear requires the exact drain ID and proof fingerprint.",
                operation_id=operation_id,
            )
        return {
            "drain_id": _canonical_uuid_argument(
                value["drain_id"], "drain_id", operation_id
            ),
            "proof_sha256": _bare_sha256_argument(
                value["proof_sha256"], "proof_sha256", operation_id
            ),
        }

    if operation == BrokerOperation.TEST_ATTEMPT_TICKET:
        if set(value) != {"descriptor", "launch_timeout_seconds"}:
            raise BrokerError(
                "invalid_arguments",
                "Internal test ticket requests require one descriptor and its launch deadline.",
                operation_id=operation_id,
            )
        launch_timeout = value["launch_timeout_seconds"]
        if (
            not _is_exact_int(launch_timeout)
            or not 1 <= launch_timeout <= 3_600
        ):
            raise BrokerError(
                "invalid_arguments",
                "launch_timeout_seconds must be an integer from 1 through 3600.",
                operation_id=operation_id,
            )
        return {
            "descriptor": _bounded_json_object(
                value["descriptor"],
                "descriptor",
                operation_id,
                maximum_bytes=128 * 1024,
            ),
            "launch_timeout_seconds": launch_timeout,
        }

    if operation == BrokerOperation.TEST_ATTEMPT_LAUNCH:
        if set(value) != {
            "ticket_id",
            "attempt_id",
            "generation",
        }:
            raise BrokerError(
                "invalid_arguments",
                "Internal test launch requires exact ticket identity.",
                operation_id=operation_id,
            )
        generation = value["generation"]
        if not _is_exact_int(generation) or not 1 <= generation <= 1_000_000:
            raise BrokerError(
                "invalid_arguments",
                "generation must be an integer from 1 through 1000000.",
                operation_id=operation_id,
            )
        return {
            "ticket_id": _opaque_argument(
                value["ticket_id"], "ticket_id", operation_id
            ),
            "attempt_id": _opaque_argument(
                value["attempt_id"], "attempt_id", operation_id
            ),
            "generation": generation,
        }

    if operation == BrokerOperation.TEST_ATTEMPT_STATUS:
        if set(value) != {"runtime_id", "result_chunk_index"}:
            raise BrokerError(
                "invalid_arguments",
                "Internal test status requires runtime_id and result_chunk_index.",
                operation_id=operation_id,
            )
        result_chunk_index = value["result_chunk_index"]
        if (
            not _is_exact_int(result_chunk_index)
            or not 0 <= result_chunk_index < 4_096
        ):
            raise BrokerError(
                "invalid_arguments",
                "result_chunk_index must be an integer from 0 through 4095.",
                operation_id=operation_id,
            )
        return {
            "runtime_id": _opaque_argument(
                value["runtime_id"], "runtime_id", operation_id
            ),
            "result_chunk_index": result_chunk_index,
        }

    if operation == BrokerOperation.TEST_ATTEMPT_CANCEL:
        if set(value) != {"runtime_id", "reason"}:
            raise BrokerError(
                "invalid_arguments",
                "Internal test cancellation requires runtime_id and reason.",
                operation_id=operation_id,
            )
        return {
            "runtime_id": _opaque_argument(
                value["runtime_id"], "runtime_id", operation_id
            ),
            "reason": _bounded_reason(value["reason"], operation_id),
        }

    if operation in {
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_RENEW,
    }:
        allowed = {"ttl_seconds", "agent"}
        if "agent" not in value or (
            operation is BrokerOperation.EPHEMERAL_RENEW
            and "ttl_seconds" not in value
        ):
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral mutations require bounded agent attribution; renewal also requires typed ttl_seconds.",
                operation_id=operation_id,
            )
        unexpected = sorted(set(value) - allowed)
        if unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral container requests contain unsupported arguments: "
                + ", ".join(unexpected)
                + ". Images, commands, environment, mounts, and Docker options are service-owned.",
                operation_id=operation_id,
            )
        normalized: dict[str, Any] = {}
        normalized["agent"] = _bounded_agent(value["agent"], operation_id)
        if "ttl_seconds" not in value:
            return normalized
        ttl = value["ttl_seconds"]
        if not _is_exact_int(ttl) or not 60 <= ttl <= 7 * 24 * 60 * 60:
            raise BrokerError(
                "invalid_arguments",
                "ttl_seconds must be an integer from one minute through seven days.",
                operation_id=operation_id,
            )
        normalized["ttl_seconds"] = ttl
        return normalized

    if operation == BrokerOperation.EPHEMERAL_IMAGE_PREFETCH:
        if set(value) != {"agent"}:
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral image prefetch requires bounded agent attribution and accepts no client-controlled image or Docker arguments.",
                operation_id=operation_id,
            )
        return {"agent": _bounded_agent(value["agent"], operation_id)}

    if operation in {
        BrokerOperation.EPHEMERAL_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_STATUS,
    }:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral image/status reads accept no client-controlled arguments.",
                operation_id=operation_id,
        )
        return {}

    if operation == BrokerOperation.EPHEMERAL_SECRET_FD:
        if set(value) != {"template_id", "run_id", "request_id"}:
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral credential retrieval requires exactly template_id, run_id, and request_id.",
                operation_id=operation_id,
            )
        template_id = _opaque_argument(value["template_id"], "template_id", operation_id)
        run_id = _canonical_uuid_argument(value["run_id"], "run_id", operation_id)
        request_id = _canonical_uuid_argument(
            value["request_id"], "request_id", operation_id
        )
        return {
            "template_id": template_id,
            "run_id": run_id,
            "request_id": request_id,
        }

    if operation == BrokerOperation.EPHEMERAL_FINISH:
        unexpected = sorted(set(value) - {"reason", "agent"})
        if "reason" not in value or "agent" not in value or unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Ephemeral finish requires a bounded reason and bounded agent attribution.",
                operation_id=operation_id,
            )
        normalized = {"reason": _bounded_reason(value["reason"], operation_id)}
        normalized["agent"] = _bounded_agent(value["agent"], operation_id)
        return normalized

    if operation == BrokerOperation.RUNTIME_ENSURE:
        required = {
            "agent",
            "root_repo_id",
            "temporary_repo_id",
            "target_kind",
            "desired_state",
        }
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Runtime ensure accepts exactly configured repository/resource IDs "
                "and a desired ready or stopped state; TTL, commands, and "
                "lifecycle options are forbidden.",
                operation_id=operation_id,
            )
        target_kind = value["target_kind"]
        if target_kind not in {"service", "docker", "database_stack"}:
            raise BrokerError(
                "invalid_arguments",
                "target_kind must be service, docker, or database_stack.",
                operation_id=operation_id,
            )
        desired_state = value["desired_state"]
        if desired_state not in {"ready", "stopped"}:
            raise BrokerError(
                "invalid_arguments",
                "desired_state must be ready or stopped.",
                operation_id=operation_id,
            )
        root_repo_id = _opaque_argument(
            value["root_repo_id"], "root_repo_id", operation_id
        )
        temporary_repo_id = value["temporary_repo_id"]
        if temporary_repo_id is not None:
            temporary_repo_id = _opaque_argument(
                temporary_repo_id, "temporary_repo_id", operation_id
            )
        return {
            "agent": _bounded_agent(value["agent"], operation_id),
            "root_repo_id": root_repo_id,
            "temporary_repo_id": temporary_repo_id,
            "target_kind": target_kind,
            "desired_state": desired_state,
        }

    if operation == BrokerOperation.RUNTIME_REQUEST:
        required = {
            "action",
            "agent",
            "root_repo_id",
            "temporary_repo_id",
            "target_kind",
            "purpose",
            "ttl_seconds",
            "kill_after_run",
        }
        supervision_fields = {
            "keep_alive",
            "rearm_crash_loop",
            "restart_limit",
            "restart_window_seconds",
        }
        replacement_fields = {
            "expected_definition_generation",
            "argv",
            "cwd",
            "environment",
        }
        temporary_service_fields = {
            "name",
            "argv",
            "cwd",
            "port",
            "launch_timeout_seconds",
        }
        if not required.issubset(value) or not set(value) <= (
            required
            | supervision_fields
            | replacement_fields
            | temporary_service_fields
        ):
            raise BrokerError(
                "invalid_arguments",
                "Runtime requests accept only configured repository/resource IDs and the typed lifecycle policy.",
                operation_id=operation_id,
            )
        action = value["action"]
        if action not in {
            "status",
            "capture_logs",
            "start",
            "stop",
            "restart",
            "replace",
            "temporary_start",
        }:
            raise BrokerError(
                "unsupported_runtime_action",
                "The broker runtime endpoint supports status, bounded log capture, existing-resource lifecycle, typed worker replacement, and bounded temporary services; shell commands are forbidden.",
                operation_id=operation_id,
            )
        target_kind = value["target_kind"]
        if target_kind not in {"service", "docker", "database_stack"}:
            raise BrokerError(
                "invalid_arguments",
                "target_kind must be service, docker, or database_stack.",
                operation_id=operation_id,
            )
        supplied_replacement = replacement_fields & set(value)
        supplied_temporary = temporary_service_fields & set(value)
        if action == "replace" and target_kind == "service":
            if supplied_replacement != replacement_fields:
                raise BrokerError(
                    "invalid_arguments",
                    "Worker replacement requires service target plus exact generation, argv, cwd, and environment.",
                    operation_id=operation_id,
                )
        elif action == "replace":
            if target_kind not in {"docker", "database_stack"} or supplied_replacement:
                raise BrokerError(
                    "invalid_arguments",
                    "Docker-backed replacement accepts only an configured immutable target; client definitions and paths are forbidden.",
                    operation_id=operation_id,
                )
        elif action == "temporary_start":
            if (
                target_kind != "service"
                or supplied_temporary != temporary_service_fields
                or supplied_replacement - {"argv", "cwd"}
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "A temporary service requires exact name, argv, repository-relative cwd, fixed port, and launch timeout fields.",
                    operation_id=operation_id,
                )
        elif supplied_replacement or supplied_temporary:
            raise BrokerError(
                "invalid_arguments",
                "Replacement definition fields are valid only for service replace.",
                operation_id=operation_id,
            )
        purpose = value["purpose"]
        if purpose not in {"development", "test", "temporary"}:
            raise BrokerError(
                "invalid_arguments",
                "purpose must be development, test, or temporary.",
                operation_id=operation_id,
            )
        agent = value["agent"]
        if (
            not isinstance(agent, str)
            or not agent.strip()
            or agent != agent.strip()
            or len(agent.encode("utf-8")) > 200
            or "\x00" in agent
        ):
            raise BrokerError(
                "invalid_arguments",
                "agent must be one bounded non-empty string.",
                operation_id=operation_id,
            )
        root_repo_id = _opaque_argument(
            value["root_repo_id"], "root_repo_id", operation_id
        )
        temporary_repo_id = value["temporary_repo_id"]
        if temporary_repo_id is not None:
            temporary_repo_id = _opaque_argument(
                temporary_repo_id, "temporary_repo_id", operation_id
            )
        ttl_seconds = value["ttl_seconds"]
        if ttl_seconds is not None and (
            not _is_exact_int(ttl_seconds)
            or not 1 <= ttl_seconds <= 7 * 24 * 60 * 60
        ):
            raise BrokerError(
                "invalid_arguments",
                "ttl_seconds must be null or a positive integer no greater than seven days.",
                operation_id=operation_id,
            )
        kill_after_run = value["kill_after_run"]
        if type(kill_after_run) is not bool:
            raise BrokerError(
                "invalid_arguments",
                "kill_after_run must be a JSON boolean.",
                operation_id=operation_id,
            )
        if kill_after_run and not (
            action == "temporary_start"
            or (
                action == "replace"
                and target_kind in {"docker", "database_stack"}
            )
        ):
            raise BrokerError(
                "unsupported_runtime_action",
                "kill_after_run=true is reserved for broker-created temporary or replacement resources; client-supplied run commands are forbidden.",
                operation_id=operation_id,
            )
        if action in {"status", "capture_logs"} and ttl_seconds is not None:
            raise BrokerError(
                "invalid_arguments",
                "Runtime read operations require ttl_seconds=null.",
                operation_id=operation_id,
            )
        if action == "stop" and ttl_seconds is not None:
            raise BrokerError(
                "invalid_arguments",
                "Explicit runtime stop requires ttl_seconds=null.",
                operation_id=operation_id,
            )
        keep_alive = value.get("keep_alive")
        if keep_alive is not None and type(keep_alive) is not bool:
            raise BrokerError(
                "invalid_arguments",
                "keep_alive must be null or a JSON boolean.",
                operation_id=operation_id,
            )
        rearm_crash_loop = value.get("rearm_crash_loop", False)
        if type(rearm_crash_loop) is not bool:
            raise BrokerError(
                "invalid_arguments",
                "rearm_crash_loop must be a JSON boolean.",
                operation_id=operation_id,
            )
        restart_limit = value.get("restart_limit")
        if restart_limit is not None and (
            not _is_exact_int(restart_limit) or not 1 <= restart_limit <= 1000
        ):
            raise BrokerError(
                "invalid_arguments",
                "restart_limit must be null or an integer from 1 through 1000.",
                operation_id=operation_id,
            )
        restart_window_seconds = value.get("restart_window_seconds")
        if restart_window_seconds is not None and (
            not _is_exact_int(restart_window_seconds)
            or not 1 <= restart_window_seconds <= 7 * 24 * 60 * 60
        ):
            raise BrokerError(
                "invalid_arguments",
                "restart_window_seconds must be null or an integer from 1 through 604800.",
                operation_id=operation_id,
            )
        supervision_supplied = any(
            item is not None
            for item in (keep_alive, restart_limit, restart_window_seconds)
        ) or rearm_crash_loop
        if supervision_supplied and (
            target_kind != "service"
            or action not in {"start", "restart", "replace"}
            or purpose != "development"
        ):
            raise BrokerError(
                "invalid_arguments",
                "Worker supervision options apply only to persistent service start, restart, or replace.",
                operation_id=operation_id,
            )
        if (
            restart_limit is not None or restart_window_seconds is not None
        ) and keep_alive is not True:
            raise BrokerError(
                "invalid_arguments",
                "Worker restart limits require keep_alive=true.",
                operation_id=operation_id,
            )
        if (
            purpose in {"test", "temporary"}
            and action in {"start", "restart", "replace", "temporary_start"}
            and ttl_seconds is None
        ):
            raise BrokerError(
                "invalid_arguments",
                "Test and temporary start-like runtime requests require a positive TTL.",
                operation_id=operation_id,
            )
        normalized_runtime = {
            "action": action,
            "agent": agent,
            "root_repo_id": root_repo_id,
            "temporary_repo_id": temporary_repo_id,
            "target_kind": target_kind,
            "purpose": purpose,
            "ttl_seconds": ttl_seconds,
            "kill_after_run": (
                kill_after_run
                if action == "temporary_start"
                or (
                    action == "replace"
                    and target_kind in {"docker", "database_stack"}
                )
                else False
            ),
        }
        for field, normalized_value in (
            ("keep_alive", keep_alive),
            ("rearm_crash_loop", rearm_crash_loop),
            ("restart_limit", restart_limit),
            ("restart_window_seconds", restart_window_seconds),
        ):
            if field in value:
                normalized_runtime[field] = normalized_value
        if action == "replace" and target_kind == "service":
            argv = value["argv"]
            if (
                not isinstance(argv, list)
                or not argv
                or len(argv) > 256
                or not all(
                    isinstance(argument, str)
                    and bool(argument)
                    and "\x00" not in argument
                    and len(argument.encode("utf-8")) <= 8192
                    for argument in argv
                )
                or sum(len(argument.encode("utf-8")) for argument in argv) > 32768
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "argv must be a bounded non-empty array of NUL-free strings.",
                    operation_id=operation_id,
                )
            environment = value["environment"]
            if (
                not isinstance(environment, dict)
                or len(environment) > 128
                or not all(
                    isinstance(key, str)
                    and bool(key)
                    and "=" not in key
                    and "\x00" not in key
                    and len(key.encode("utf-8")) <= 256
                    and isinstance(item, str)
                    and "\x00" not in item
                    and len(item.encode("utf-8")) <= 8192
                    for key, item in environment.items()
                )
                or sum(
                    len(key.encode("utf-8")) + len(item.encode("utf-8"))
                    for key, item in environment.items()
                )
                > 32768
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "environment must be a bounded NUL-free string map.",
                    operation_id=operation_id,
                )
            cwd = _bounded_single_line_argument(
                value["cwd"], "cwd", operation_id, maximum_bytes=4096
            )
            if not cwd.startswith("/"):
                raise BrokerError(
                    "invalid_arguments",
                    "cwd must be an absolute path.",
                    operation_id=operation_id,
                )
            normalized_runtime.update(
                {
                    "expected_definition_generation": _non_negative_generation_argument(
                        value["expected_definition_generation"],
                        "expected_definition_generation",
                        operation_id,
                    ),
                    "argv": list(argv),
                    "cwd": cwd,
                    "environment": dict(sorted(environment.items())),
                }
            )
        elif action == "temporary_start":
            if purpose != "temporary":
                raise BrokerError(
                    "invalid_arguments",
                    "A temporary service requires purpose=temporary.",
                    operation_id=operation_id,
                )
            argv = value["argv"]
            if (
                not isinstance(argv, list)
                or not argv
                or len(argv) > 256
                or not all(
                    isinstance(argument, str)
                    and bool(argument)
                    and "\x00" not in argument
                    and len(argument.encode("utf-8")) <= 8192
                    for argument in argv
                )
                or sum(len(argument.encode("utf-8")) for argument in argv) > 32768
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "argv must be a bounded non-empty array of NUL-free strings.",
                    operation_id=operation_id,
                )
            shell = str(argv[0]).rsplit("/", 1)[-1]
            if shell in {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}:
                raise BrokerError(
                    "invalid_arguments",
                    "Temporary services require structured argv, not a shell.",
                    operation_id=operation_id,
                )
            cwd = _bounded_single_line_argument(
                value["cwd"], "cwd", operation_id, maximum_bytes=4096
            )
            if cwd.startswith("/") or any(part in {"", ".."} for part in cwd.split("/")):
                raise BrokerError(
                    "invalid_arguments",
                    "Temporary-service cwd must be repository-relative and cannot traverse upward.",
                    operation_id=operation_id,
                )
            name = _bounded_single_line_argument(
                value["name"], "name", operation_id, maximum_bytes=64
            )
            if re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]{0,62}[a-z0-9])?", name) is None:
                raise BrokerError(
                    "invalid_arguments",
                    "Temporary-service name must be a bounded lowercase identifier.",
                    operation_id=operation_id,
                )
            port = value["port"]
            if not _is_exact_int(port) or not 1 <= port <= 65535:
                raise BrokerError(
                    "invalid_arguments",
                    "Temporary-service port must be one exact TCP port from 1 through 65535.",
                    operation_id=operation_id,
                )
            launch_timeout = value["launch_timeout_seconds"]
            if not _is_exact_int(launch_timeout) or not 1 <= launch_timeout <= 300:
                raise BrokerError(
                    "invalid_arguments",
                    "launch_timeout_seconds must be from 1 through 300.",
                    operation_id=operation_id,
                )
            normalized_runtime.update(
                {
                    "name": name,
                    "argv": list(argv),
                    "cwd": cwd,
                    "port": port,
                    "launch_timeout_seconds": launch_timeout,
                }
            )
        return normalized_runtime

    if operation == BrokerOperation.WORKER_LAUNCH_TICKET:
        required = {
            "supervisor_epoch",
            "expected_definition_generation",
            "expected_policy_generation",
            "expected_supervisor_generation",
        }
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Worker launch tickets accept only the exact supervisor epoch and generation tokens.",
                operation_id=operation_id,
            )
        return {
            "supervisor_epoch": _opaque_argument(
                value["supervisor_epoch"], "supervisor_epoch", operation_id
            ),
            "expected_definition_generation": _non_negative_generation_argument(
                value["expected_definition_generation"],
                "expected_definition_generation",
                operation_id,
            ),
            "expected_policy_generation": _non_negative_generation_argument(
                value["expected_policy_generation"],
                "expected_policy_generation",
                operation_id,
            ),
            "expected_supervisor_generation": _non_negative_generation_argument(
                value["expected_supervisor_generation"],
                "expected_supervisor_generation",
                operation_id,
            ),
        }

    if operation == BrokerOperation.WORKER_LAUNCHED:
        required = {
            "attempt_id",
            "supervisor_epoch",
            "supervisor_generation",
            "pid",
            "process_start_time",
            "process_fingerprint",
        }
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Worker launch reports accept only the exact attempt, runner token, and process identity.",
                operation_id=operation_id,
            )
        pid = value["pid"]
        if not _is_exact_int(pid) or not 2 <= pid <= 2**31 - 1:
            raise BrokerError(
                "invalid_arguments",
                "pid must be an integer from 2 through 2147483647.",
                operation_id=operation_id,
            )
        return {
            "attempt_id": _opaque_argument(
                value["attempt_id"], "attempt_id", operation_id
            ),
            "supervisor_epoch": _opaque_argument(
                value["supervisor_epoch"], "supervisor_epoch", operation_id
            ),
            "supervisor_generation": _non_negative_generation_argument(
                value["supervisor_generation"],
                "supervisor_generation",
                operation_id,
            ),
            "pid": pid,
            "process_start_time": _bounded_single_line_argument(
                value["process_start_time"],
                "process_start_time",
                operation_id,
                maximum_bytes=256,
            ),
            "process_fingerprint": _sha256_fingerprint_argument(
                value["process_fingerprint"], "process_fingerprint", operation_id
            ),
        }

    if operation == BrokerOperation.WORKER_EXIT:
        required = {
            "attempt_id",
            "supervisor_epoch",
            "supervisor_generation",
            "exit_kind",
            "exit_code",
            "exit_signal",
            "log_artifact",
            "occurred_at_epoch",
        }
        if set(value) != required:
            raise BrokerError(
                "invalid_arguments",
                "Worker exit reports require the exact attempt, runner token, typed exit, and nullable artifact evidence.",
                operation_id=operation_id,
            )
        exit_kind = value["exit_kind"]
        if exit_kind not in {
            "exit_code",
            "signal",
            "launch_failure",
            "supervisor_lost",
            "unknown",
        }:
            raise BrokerError(
                "invalid_arguments",
                "exit_kind is not a supported typed worker exit.",
                operation_id=operation_id,
            )
        exit_code = value["exit_code"]
        exit_signal = value["exit_signal"]
        if exit_kind == "exit_code":
            if (
                not _is_exact_int(exit_code)
                or not -(2**31) <= exit_code <= 2**31 - 1
                or exit_signal is not None
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "exit_code exits require only one bounded integer exit_code.",
                    operation_id=operation_id,
                )
        elif exit_kind == "signal":
            if (
                not _is_exact_int(exit_signal)
                or not 1 <= exit_signal <= 255
                or exit_code is not None
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "signal exits require only one signal integer from 1 through 255.",
                    operation_id=operation_id,
                )
        elif exit_code is not None or exit_signal is not None:
            raise BrokerError(
                "invalid_arguments",
                "This worker exit_kind requires null exit_code and exit_signal.",
                operation_id=operation_id,
            )
        artifact = value["log_artifact"]
        normalized_artifact: dict[str, str] | None = None
        if artifact is not None:
            if not isinstance(artifact, dict) or set(artifact) != {
                "artifact_id",
                "sha256",
            }:
                raise BrokerError(
                    "invalid_arguments",
                    "log_artifact accepts only a canonical artifact UUID and SHA-256; paths are forbidden.",
                    operation_id=operation_id,
                )
            normalized_artifact = {
                "artifact_id": _canonical_uuid_argument(
                    artifact["artifact_id"], "log_artifact.artifact_id", operation_id
                ),
                "sha256": _bare_sha256_argument(
                    artifact["sha256"], "log_artifact.sha256", operation_id
                ),
            }
        occurred_at = value["occurred_at_epoch"]
        if occurred_at is not None and (
            type(occurred_at) not in {int, float}
            or not math.isfinite(float(occurred_at))
            or not 0 <= float(occurred_at) <= 2**53
        ):
            raise BrokerError(
                "invalid_arguments",
                "occurred_at_epoch must be null or a finite non-negative bounded number.",
                operation_id=operation_id,
            )
        return {
            "attempt_id": _opaque_argument(
                value["attempt_id"], "attempt_id", operation_id
            ),
            "supervisor_epoch": _opaque_argument(
                value["supervisor_epoch"], "supervisor_epoch", operation_id
            ),
            "supervisor_generation": _non_negative_generation_argument(
                value["supervisor_generation"],
                "supervisor_generation",
                operation_id,
            ),
            "exit_kind": exit_kind,
            "exit_code": exit_code,
            "exit_signal": exit_signal,
            "log_artifact": normalized_artifact,
            "occurred_at_epoch": (
                None if occurred_at is None else float(occurred_at)
            ),
        }

    if operation == BrokerOperation.WORKER_POLICY_READ:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Worker policy reads accept no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.WORKER_ATTEMPT_READ:
        if set(value) != {"attempt_id"}:
            raise BrokerError(
                "invalid_arguments",
                "Worker attempt reads require exactly one opaque attempt_id.",
                operation_id=operation_id,
            )
        return {
            "attempt_id": _opaque_argument(
                value["attempt_id"], "attempt_id", operation_id
            )
        }
    if operation == BrokerOperation.SERVER_PUBLISH:
        allowed = {
            "lease_id",
            "lifecycle",
            "pid",
            "listener_port",
            "health_classification",
            "health_ok",
            "stopped_reason",
        }
        unexpected = sorted(set(value) - allowed)
        if unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Server publication contains unsupported arguments: "
                + ", ".join(unexpected)
                + ".",
                operation_id=operation_id,
            )
        required = {"lease_id", "lifecycle", "listener_port", "health_classification", "health_ok"}
        if not required.issubset(value):
            raise BrokerError(
                "invalid_arguments",
                "Server publication requires lease_id, lifecycle, listener_port, health_classification, and health_ok.",
                operation_id=operation_id,
            )
        lease_id = _opaque_argument(value["lease_id"], "lease_id", operation_id)
        lifecycle = value["lifecycle"]
        if lifecycle not in {"running", "unhealthy", "stopped"}:
            raise BrokerError(
                "invalid_arguments",
                "Server lifecycle must be running, unhealthy, or stopped.",
                operation_id=operation_id,
            )
        port = value["listener_port"]
        if not _is_exact_int(port) or not 1 <= port <= 65535:
            raise BrokerError(
                "invalid_arguments",
                "listener_port must be an integer from 1 through 65535.",
                operation_id=operation_id,
            )
        classification = value["health_classification"]
        if (
            not isinstance(classification, str)
            or not classification
            or classification != classification.strip()
            or len(classification.encode("utf-8")) > 128
            or "\x00" in classification
        ):
            raise BrokerError(
                "invalid_arguments",
                "health_classification must be one bounded non-empty string.",
                operation_id=operation_id,
            )
        health_ok = value["health_ok"]
        if health_ok is not None and type(health_ok) is not bool:
            raise BrokerError(
                "invalid_arguments",
                "health_ok must be a boolean or null.",
                operation_id=operation_id,
            )
        normalized = {
            "lease_id": lease_id,
            "lifecycle": lifecycle,
            "listener_port": port,
            "health_classification": classification,
            "health_ok": health_ok,
        }
        pid = value.get("pid")
        if lifecycle == "stopped":
            if pid is not None:
                raise BrokerError(
                    "invalid_arguments",
                    "Stopped server publication must not claim a live pid.",
                    operation_id=operation_id,
                )
            normalized["stopped_reason"] = _bounded_reason(
                value.get("stopped_reason") or "Stopped by coordinator",
                operation_id,
            )
        else:
            if not _is_exact_int(pid) or pid <= 1:
                raise BrokerError(
                    "invalid_arguments",
                    "Running server publication requires one positive non-system pid.",
                    operation_id=operation_id,
                )
            if "stopped_reason" in value:
                raise BrokerError(
                    "invalid_arguments",
                    "Running server publication cannot include stopped_reason.",
                    operation_id=operation_id,
                )
            normalized["pid"] = pid
        return normalized

    if operation in {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_STOP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_DOWN,
    }:
        if operation is BrokerOperation.COMPOSE_UP and value:
            if set(value) != {
                "service",
                "force_recreate",
                "wait_timeout_seconds",
            }:
                raise BrokerError(
                    "invalid_arguments",
                    "Exact Compose service recreation accepts service, force_recreate, and wait_timeout_seconds only.",
                    operation_id=operation_id,
                )
            service = value["service"]
            wait_timeout = value["wait_timeout_seconds"]
            if (
                not isinstance(service, str)
                or _COMPOSE_SERVICE_NAME.fullmatch(service) is None
                or value["force_recreate"] is not True
                or not _is_exact_int(wait_timeout)
                or not 10 <= wait_timeout <= 600
            ):
                raise BrokerError(
                    "invalid_arguments",
                    "Exact Compose service recreation requires one service, force_recreate=true, and a wait timeout from 10 through 600 seconds.",
                    operation_id=operation_id,
                )
            return {
                "service": service,
                "force_recreate": True,
                "wait_timeout_seconds": wait_timeout,
            }
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Compose mutations do not accept client-controlled paths, names, arguments, or options.",
                operation_id=operation_id,
            )
        return {}

    if operation is BrokerOperation.COMPOSE_RUN_ONCE:
        if set(value) != {"agent", "service", "timeout_seconds"}:
            raise BrokerError(
                "invalid_arguments",
                "Compose run-once accepts exactly agent, service, and timeout_seconds; "
                "commands, environment, mounts, paths, and options are forbidden.",
                operation_id=operation_id,
            )
        service = value["service"]
        if (
            not isinstance(service, str)
            or _COMPOSE_SERVICE_NAME.fullmatch(service) is None
        ):
            raise BrokerError(
                "invalid_arguments",
                "Compose run-once service must be one exact Docker Compose service name.",
                operation_id=operation_id,
            )
        timeout_seconds = value["timeout_seconds"]
        if (
            not _is_exact_int(timeout_seconds)
            or not 1
            <= timeout_seconds
            <= MAX_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS
        ):
            raise BrokerError(
                "invalid_arguments",
                "Compose run-once timeout_seconds must be from one through 3600.",
                operation_id=operation_id,
            )
        return {
            "agent": _bounded_agent(value["agent"], operation_id),
            "service": service,
            "timeout_seconds": timeout_seconds,
        }

    if operation in {
        BrokerOperation.DOCKER_START,
        BrokerOperation.DOCKER_STOP,
        BrokerOperation.DOCKER_RESTART,
    }:
        allowed = {"expected_observation_revision"}
        unexpected = sorted(set(value) - allowed)
        if unexpected:
            raise BrokerError(
                "invalid_arguments",
                "Docker mutation contains unsupported arguments: "
                + ", ".join(unexpected)
                + ".",
                operation_id=operation_id,
            )
        if "expected_observation_revision" not in value:
            return {}
        revision = value["expected_observation_revision"]
        if not _is_exact_int(revision) or revision < 0:
            raise BrokerError(
                "invalid_arguments",
                "expected_observation_revision must be a non-negative integer.",
                operation_id=operation_id,
            )
        return {"expected_observation_revision": revision}

    if operation == BrokerOperation.DATABASE_BACKUP:
        if set(value) != {"database_name"}:
            raise BrokerError(
                "invalid_arguments",
                "Database backup accepts exactly one database name; service paths and commands are forbidden.",
                operation_id=operation_id,
            )
        return {
            "database_name": _database_name_argument(
                value["database_name"], operation_id
            )
        }

    if operation == BrokerOperation.DATABASE_BACKUP_RETIRE:
        if set(value) != {
            "database_name",
            "database_backup_id",
            "confirm_backup_id",
        }:
            raise BrokerError(
                "invalid_arguments",
                "Database backup retirement requires one database name, one "
                "registered backup ID, and its exact confirmation ID; service "
                "paths and commands are forbidden.",
                operation_id=operation_id,
            )
        backup_id = _opaque_argument(
            value["database_backup_id"], "database_backup_id", operation_id
        )
        confirmation = _opaque_argument(
            value["confirm_backup_id"], "confirm_backup_id", operation_id
        )
        if confirmation != backup_id:
            raise BrokerError(
                "database_backup_confirmation_invalid",
                "Backup retirement confirmation must exactly match the selected "
                "database backup ID.",
                operation_id=operation_id,
            )
        return {
            "database_name": _database_name_argument(
                value["database_name"], operation_id
            ),
            "database_backup_id": backup_id,
            "confirm_backup_id": confirmation,
        }

    if operation == BrokerOperation.DATABASE_RESTORE:
        if set(value) != {"database_name", "database_backup_id", "explicit"} or value.get(
            "explicit"
        ) is not True:
            raise BrokerError(
                "invalid_arguments",
                "Database restore requires one registered backup ID, one database name, and explicit=true; service paths and commands are forbidden.",
                operation_id=operation_id,
            )
        return {
            "database_name": _database_name_argument(
                value["database_name"], operation_id
            ),
            "database_backup_id": _opaque_argument(
                value["database_backup_id"], "database_backup_id", operation_id
            ),
            "explicit": True,
        }

    if operation == BrokerOperation.REPOSITORY_PLAN_REMOVE:
        if set(value) != {"reason"}:
            raise BrokerError(
                "invalid_arguments",
                "Repository removal planning accepts exactly one bounded reason.",
                operation_id=operation_id,
            )
        return {"reason": _bounded_reason(value["reason"], operation_id)}

    if operation == BrokerOperation.REPOSITORY_LIST_REMOVED:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Removed-repository listing accepts no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.REPOSITORY_REMOVE:
        if set(value) != {"plan_id", "plan_fingerprint"}:
            raise BrokerError(
                "invalid_arguments",
                "Repository removal requires the exact durable plan identity and fingerprint.",
                operation_id=operation_id,
            )
        return {
            "plan_id": _canonical_uuid_argument(value["plan_id"], "plan_id", operation_id),
            "plan_fingerprint": _sha256_fingerprint_argument(
                value["plan_fingerprint"], "plan_fingerprint", operation_id
            ),
        }

    if operation == BrokerOperation.REPOSITORY_REINSTALL:
        if set(value) != {"reason", "explicit"} or value.get("explicit") is not True:
            raise BrokerError(
                "invalid_arguments",
                "Repository reinstall requires one bounded reason and explicit=true.",
                operation_id=operation_id,
            )
        return {
            "reason": _bounded_reason(value["reason"], operation_id),
            "explicit": True,
        }

    if operation == BrokerOperation.ARCHIVES_READ:
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Archive listing accepts no client-controlled arguments.",
                operation_id=operation_id,
            )
        return {}

    if operation == BrokerOperation.CONTAINER_REMOVE:
        if set(value) != {"target_id", "reason"}:
            raise BrokerError(
                "invalid_arguments",
                "Direct container removal requires one opaque target ID and bounded reason.",
                operation_id=operation_id,
            )
        return {
            "target_id": _opaque_argument(value["target_id"], "target_id", operation_id),
            "reason": _bounded_reason(value["reason"], operation_id),
        }

    if operation == BrokerOperation.CLEANUP_PLAN:
        if set(value) != {"action", "target_kind", "target_id", "reason"}:
            raise BrokerError(
                "invalid_arguments",
                "Lifecycle planning requires an archive or purge action, one opaque target kind, ID, and bounded reason.",
                operation_id=operation_id,
            )
        action = str(value["action"])
        if action not in {"archive", "purge"}:
            raise BrokerError(
                "invalid_arguments",
                "lifecycle action must be archive or purge.",
                operation_id=operation_id,
            )
        target_kind = str(value["target_kind"])
        if target_kind == "repository":
            target_kind = "project"
        if target_kind not in {"project", "server", "container", "volume", "worktree"}:
            raise BrokerError(
                "invalid_arguments",
                "cleanup target_kind must be project, server, container, volume, or worktree.",
                operation_id=operation_id,
            )
        return {
            "action": action,
            "target_kind": target_kind,
            "target_id": _opaque_argument(value["target_id"], "target_id", operation_id),
            "reason": _bounded_reason(value["reason"], operation_id),
        }

    if operation == BrokerOperation.CLEANUP_APPLY:
        if set(value) != {"plan_id", "plan_fingerprint", "confirmation_phrase"}:
            raise BrokerError(
                "invalid_arguments",
                "Cleanup apply requires the exact durable plan and confirmation phrase.",
                operation_id=operation_id,
            )
        return {
            "plan_id": _canonical_uuid_argument(value["plan_id"], "plan_id", operation_id),
            "plan_fingerprint": _sha256_fingerprint_argument(
                value["plan_fingerprint"], "plan_fingerprint", operation_id
            ),
            "confirmation_phrase": (
                ""
                if value["confirmation_phrase"] == ""
                else _confirmation_phrase_argument(
                    value["confirmation_phrase"], operation_id
                )
            ),
        }

    if operation == BrokerOperation.LIFECYCLE_RESTORE:
        if set(value) != {"target_kind", "target_id", "reason"}:
            raise BrokerError(
                "invalid_arguments",
                "Lifecycle restore requires one opaque target and bounded reason.",
                operation_id=operation_id,
            )
        target_kind = "project" if value["target_kind"] == "repository" else value["target_kind"]
        if target_kind not in {"project", "server", "container"}:
            raise BrokerError(
                "invalid_arguments",
                "restore target_kind must be project, server, or container.",
                operation_id=operation_id,
            )
        return {
            "target_kind": target_kind,
            "target_id": _opaque_argument(value["target_id"], "target_id", operation_id),
            "reason": _bounded_reason(value["reason"], operation_id),
        }

    resource_identity_fields = {
        "resource_kind",
        "immutable_fingerprint",
        "observation_fingerprint",
    }
    if operation in {
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
    }:
        expected = set(resource_identity_fields)
        if operation in {
            BrokerOperation.RESOURCE_ATTACH,
            BrokerOperation.RESOURCE_PLAN_RETIRE,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
        }:
            expected.add("reason")
        else:
            expected.update({"plan_id", "plan_fingerprint"})
        if set(value) != expected:
            raise BrokerError(
                "invalid_arguments",
                "Resource lifecycle arguments do not match the exact typed contract.",
                operation_id=operation_id,
            )
        resource_kind = value["resource_kind"]
        if resource_kind not in {"server", "container", "supervisor"}:
            raise BrokerError(
                "invalid_arguments",
                "resource_kind must be server, container, or supervisor.",
                operation_id=operation_id,
            )
        result = {
            "resource_kind": resource_kind,
            "immutable_fingerprint": _sha256_fingerprint_argument(
                value["immutable_fingerprint"], "immutable_fingerprint", operation_id
            ),
            "observation_fingerprint": _sha256_fingerprint_argument(
                value["observation_fingerprint"], "observation_fingerprint", operation_id
            ),
        }
        if "reason" in value:
            result["reason"] = _bounded_reason(value["reason"], operation_id)
        else:
            result["plan_id"] = _canonical_uuid_argument(
                value["plan_id"], "plan_id", operation_id
            )
            result["plan_fingerprint"] = _sha256_fingerprint_argument(
                value["plan_fingerprint"], "plan_fingerprint", operation_id
            )
        return result

    if operation == BrokerOperation.TEST_ARTIFACT_RESOLVE:
        if (
            not {"run_id", "artifact_id"}.issubset(value)
            or set(value) - {"run_id", "artifact_id", "expected_repository_id"}
        ):
            raise BrokerError(
                "invalid_arguments",
                "Exact test artifact resolution requires run_id and artifact_id.",
                operation_id=operation_id,
            )
        normalized = {
            "run_id": _opaque_argument(value["run_id"], "run_id", operation_id),
            "artifact_id": _opaque_argument(
                value["artifact_id"], "artifact_id", operation_id
            ),
        }
        if "expected_repository_id" in value:
            normalized["expected_repository_id"] = _opaque_argument(
                value["expected_repository_id"],
                "expected_repository_id",
                operation_id,
            )
        return normalized

    raise BrokerError(
        "unknown_operation",
        "Requested broker operation is not allowed.",
        operation_id=operation_id,
    )


def _bounded_reason(value: Any, operation_id: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 500:
        raise BrokerError(
            "invalid_arguments",
            "reason must be from 1 through 500 non-whitespace characters.",
            operation_id=operation_id,
        )
    return value.strip()


def _bounded_agent(value: Any, operation_id: str) -> str:
    """Validate diagnostic client-agent metadata without treating it as identity."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerError(
            "invalid_arguments",
            "agent must be one bounded non-empty printable identifier.",
            operation_id=operation_id,
        )
    return value


def _confirmation_phrase_argument(value: Any, operation_id: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 700
        or any(ord(character) < 32 for character in value)
    ):
        raise BrokerError(
            "invalid_arguments",
            "confirmation_phrase must be an exact bounded printable phrase.",
            operation_id=operation_id,
        )
    return value


def _database_name_argument(value: Any, operation_id: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 128
        or "\x00" in value
    ):
        raise BrokerError(
            "invalid_arguments",
            "database_name must be a non-empty UTF-8 value no larger than 128 bytes.",
            operation_id=operation_id,
        )
    return value


def _canonical_uuid_argument(value: Any, field: str, operation_id: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        parsed = None
    if parsed is None or str(parsed) != value:
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a canonical UUID.",
            operation_id=operation_id,
        )
    return str(parsed)


def _sha256_fingerprint_argument(value: Any, field: str, operation_id: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a lowercase sha256 fingerprint.",
            operation_id=operation_id,
        )
    return value


def _non_negative_generation_argument(
    value: Any, field: str, operation_id: str
) -> int:
    if not _is_exact_int(value) or not 0 <= value <= 2**63 - 1:
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a bounded non-negative integer.",
            operation_id=operation_id,
        )
    return value


def _bare_sha256_argument(value: Any, field: str, operation_id: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a lowercase 64-character SHA-256 digest.",
            operation_id=operation_id,
        )
    return value


def _bounded_single_line_argument(
    value: Any,
    field: str,
    operation_id: str,
    *,
    maximum_bytes: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum_bytes
        or any(character in value for character in "\x00\r\n")
    ):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be one bounded non-empty line.",
            operation_id=operation_id,
        )
    return value


def _bounded_json_object(
    value: Any,
    field: str,
    operation_id: str,
    *,
    maximum_bytes: int,
) -> dict[str, Any]:
    """Freeze one nested untrusted document and enforce its byte budget."""

    if not isinstance(value, Mapping):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a JSON object.",
            operation_id=operation_id,
        )
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > maximum_bytes:
            raise BrokerError(
                "invalid_arguments",
                f"{field} exceeds its bounded byte limit.",
                operation_id=operation_id,
            )
        decoded = json.loads(encoded.decode("utf-8"))
    except BrokerError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must contain only finite JSON values.",
            operation_id=operation_id,
        ) from None
    if not isinstance(decoded, dict):
        raise BrokerError(
            "invalid_arguments",
            f"{field} must be a JSON object.",
            operation_id=operation_id,
        )
    return decoded


def _opaque_argument(value: Any, field: str, operation_id: str) -> str:
    try:
        return _validate_identifier(value, field, operation_id=operation_id)
    except BrokerError:
        raise


def _validate_reply(value: Any, *, expected_operation_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerError("invalid_reply", "Broker reply is not a JSON object.")
    if value.get("version") != PROTOCOL_VERSION:
        raise BrokerError("invalid_reply", "Broker reply version is invalid.")
    if type(value.get("ok")) is not bool:
        raise BrokerError(
            "invalid_reply",
            "Broker reply status is invalid.",
            operation_id=expected_operation_id,
        )
    unbound_transport_error = (
        value.get("operation_id") is None
        and value["ok"] is False
        and isinstance(value.get("error"), dict)
        and value["error"].get("code")
        in {"server_busy", "peer_credentials_unavailable"}
    )
    if (
        value.get("operation_id") != expected_operation_id
        and not unbound_transport_error
    ):
        raise BrokerError(
            "reply_operation_mismatch",
            "Broker reply does not match the requested operation_id.",
            operation_id=expected_operation_id,
        )
    if value["ok"]:
        if set(value) != {"version", "operation_id", "ok", "result"}:
            raise BrokerError(
                "invalid_reply",
                "Successful broker reply fields are invalid.",
                operation_id=expected_operation_id,
            )
        if not isinstance(value["result"], dict):
            raise BrokerError(
                "invalid_reply",
                "Successful broker result is invalid.",
                operation_id=expected_operation_id,
            )
    else:
        if set(value) != {"version", "operation_id", "ok", "error"}:
            raise BrokerError(
                "invalid_reply",
                "Failed broker reply fields are invalid.",
                operation_id=expected_operation_id,
            )
        error = value["error"]
        if (
            not isinstance(error, dict)
            or set(error) != {"code", "message"}
            or not isinstance(error.get("code"), str)
            or not isinstance(error.get("message"), str)
        ):
            raise BrokerError(
                "invalid_reply",
                "Broker error reply is invalid.",
                operation_id=expected_operation_id,
            )
    return value


def _raise_reply_error(reply: Mapping[str, Any], *, operation_id: str) -> None:
    """Raise a validated redacted broker error reply."""

    error = reply.get("error")
    if not isinstance(error, Mapping):
        raise BrokerError(
            "invalid_reply",
            "Broker returned an invalid failure payload.",
            operation_id=operation_id,
        )
    raise BrokerError(
        str(error.get("code") or "invalid_reply"),
        str(error.get("message") or "Broker credential delivery failed."),
        operation_id=operation_id,
    )


def _validate_ephemeral_secret_fd_result(
    value: Any,
    *,
    expected_request_id: str,
    operation_id: str,
) -> dict[str, Any]:
    """Accept only the deliberately non-secret descriptor acknowledgement."""

    if not isinstance(value, Mapping) or set(value) != {
        "transport",
        "request_id",
        "expires_at_epoch",
    }:
        raise BrokerError(
            "invalid_reply",
            "Broker credential reply metadata is invalid.",
            operation_id=operation_id,
        )
    request_id = _canonical_uuid_value(value.get("request_id"))
    expires_at_epoch = value.get("expires_at_epoch")
    if (
        value.get("transport") != "scm_rights"
        or request_id != expected_request_id
        or not _is_exact_int(expires_at_epoch)
        or int(expires_at_epoch) <= int(time.time())
    ):
        raise BrokerError(
            "invalid_reply",
            "Broker credential reply metadata is invalid or expired.",
            operation_id=operation_id,
        )
    return {
        "request_id": request_id,
        "expires_at_epoch": int(expires_at_epoch),
    }


def _valid_operation_id_or_none(value: Any) -> Optional[str]:
    if not isinstance(value, dict):
        return None
    candidate = value.get("operation_id")
    if not isinstance(candidate, str):
        return None
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError):
        return None
    canonical = str(parsed)
    if candidate != canonical:
        return None
    return canonical


def _canonical_uuid_value(value: Any) -> Optional[str]:
    """Return one lower-case canonical UUID string without exposing bad input."""

    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    canonical = str(parsed)
    return canonical if value == canonical else None


def _validate_identifier(
    value: Any,
    field: str,
    *,
    operation_id: Optional[str],
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value[0] not in _IDENTIFIER_CHARS - frozenset("_.:@-")
        or any(character not in _IDENTIFIER_CHARS for character in value)
        or ".." in value
    ):
        raise BrokerError(
            "invalid_identifier",
            field + " must be an opaque identifier, not a path.",
            operation_id=operation_id,
        )
    return value


def _validate_policy_identifier(value: Any, field: str) -> str:
    try:
        return _validate_identifier(value, field, operation_id=None)
    except BrokerError as exc:
        raise ValueError(exc.message) from None


def _normalize_backend_result(value: Any, *, max_bytes: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Broker mutation backend returned an invalid result.",
        )
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Broker mutation backend returned an invalid result.",
        ) from None
    if len(encoded) > max_bytes:
        raise BrokerBackendError(
            "backend_result_too_large",
            "Broker mutation result exceeds the configured response limit.",
        )
    decoded = json.loads(encoded.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise BrokerBackendError(
            "invalid_backend_result",
            "Broker mutation backend returned an invalid result.",
        )
    return decoded


def _request_fingerprint(request: AcceptedBrokerRequest) -> str:
    document = request.request.to_wire()
    # Unix credentials are audit attribution, not a tenancy boundary.  The
    # typed request identity is therefore stable when the same developer
    # retries an operation from another local account or agent.
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def accepted_request_fingerprint(request: AcceptedBrokerRequest) -> str:
    """Stable durable idempotency fingerprint for the typed request."""

    return _request_fingerprint(request)


def _error_reply(
    code: str,
    message: str,
    *,
    operation_id: Optional[str],
) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "operation_id": operation_id,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def _decode_json_document(payload: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise BrokerError("invalid_json", "Broker JSON contains a non-finite number.")

    def reject_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise BrokerError(
                    "invalid_json", "Broker JSON contains a duplicate object key."
                )
            result[key] = item
        return result

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except BrokerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise BrokerError("invalid_json", "Broker request is not valid JSON.") from None


def _encode_json_document(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise BrokerError("invalid_json", "Broker response is not valid JSON.") from None


def _receive_frame(connection: socket.socket, *, max_message_bytes: int) -> bytes:
    header = _receive_exact(connection, 4)
    size = struct.unpack("!I", header)[0]
    if size == 0:
        raise BrokerError("empty_request", "Broker request frame is empty.")
    if size > max_message_bytes:
        raise BrokerError(
            "request_too_large", "Broker request exceeds the configured size limit."
        )
    return _receive_exact(connection, size)


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except socket.timeout:
            raise BrokerError("request_timeout", "Broker request timed out.") from None
        if not chunk:
            raise BrokerError(
                "incomplete_request", "Broker connection closed before the frame completed."
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _descriptor_transport_available(connection: Optional[socket.socket] = None) -> bool:
    """Whether this endpoint can safely use Unix ``SCM_RIGHTS`` transport.

    The credential path must require both directions: the broker needs to send
    one descriptor and the client needs to receive it with ancillary-data
    bounds.  Ordinary JSON calls may still run without these optional socket
    methods, but never receive credential material.
    """

    endpoint: object = socket.socket if connection is None else connection
    return (
        callable(getattr(endpoint, "recvmsg", None))
        and callable(getattr(endpoint, "sendmsg", None))
        and callable(getattr(socket, "CMSG_SPACE", None))
        and _is_exact_int(getattr(socket, "SOL_SOCKET", None))
        and _is_exact_int(getattr(socket, "SCM_RIGHTS", None))
    )


def _receive_frame_rejecting_fds(
    connection: socket.socket, *, max_message_bytes: int
) -> bytes:
    """Read one normal JSON frame while rejecting all incoming descriptors."""

    # Descriptor receipt is an optional hardening layer for ordinary JSON
    # requests.  Keep existing non-secret broker operations usable on a
    # platform without recvmsg; the FD-only credential operation separately
    # fails closed before its one-time material is consumed.
    if not _descriptor_transport_available(connection):
        return _receive_frame(connection, max_message_bytes=max_message_bytes)
    header = _receive_exact_rejecting_fds(connection, 4)
    size = struct.unpack("!I", header)[0]
    if size == 0:
        raise BrokerError("empty_request", "Broker request frame is empty.")
    if size > max_message_bytes:
        raise BrokerError(
            "request_too_large", "Broker request exceeds the configured size limit."
        )
    return _receive_exact_rejecting_fds(connection, size)


def _receive_frame_with_one_fd(
    connection: socket.socket, *, max_message_bytes: int
) -> tuple[bytes, Optional[int]]:
    """Read one redacted reply and require at most one ``SCM_RIGHTS`` FD."""

    descriptors: list[int] = []
    try:
        header, received = _receive_exact_with_fds(connection, 4)
        descriptors.extend(received)
        size = struct.unpack("!I", header)[0]
        if size == 0:
            raise BrokerError("empty_reply", "Broker credential reply is empty.")
        if size > max_message_bytes:
            raise BrokerError(
                "response_too_large",
                "Broker credential reply exceeds the configured size limit.",
            )
        payload, received = _receive_exact_with_fds(connection, size)
        descriptors.extend(received)
        if len(descriptors) > 1:
            raise BrokerError(
                "secret_fd_invalid",
                "Broker credential reply carried more than one descriptor.",
            )
        return payload, descriptors.pop() if descriptors else None
    except BaseException:
        _close_descriptors_quietly(descriptors)
        raise


def _receive_exact_rejecting_fds(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk, descriptors = _receive_socket_chunk(connection, remaining)
        if descriptors:
            _close_descriptors_quietly(descriptors)
            raise BrokerError(
                "unexpected_file_descriptor",
                "Broker JSON protocol does not accept incoming file descriptors.",
            )
        if not chunk:
            raise BrokerError(
                "incomplete_request", "Broker connection closed before the frame completed."
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_exact_with_fds(
    connection: socket.socket, size: int
) -> tuple[bytes, list[int]]:
    chunks: list[bytes] = []
    descriptors: list[int] = []
    remaining = size
    try:
        while remaining:
            chunk, received = _receive_socket_chunk(connection, remaining)
            descriptors.extend(received)
            if not chunk:
                raise BrokerError(
                    "incomplete_reply",
                    "Broker connection closed before the credential reply completed.",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), descriptors
    except BaseException:
        _close_descriptors_quietly(descriptors)
        raise


def _receive_socket_chunk(
    connection: socket.socket, size: int
) -> tuple[bytes, list[int]]:
    if not _descriptor_transport_available(connection):
        raise BrokerError(
            "secret_fd_transport_unavailable",
            "This platform does not provide authenticated descriptor transport.",
        )
    recvmsg = connection.recvmsg
    ancillary_size = socket.CMSG_SPACE(struct.calcsize("i") * 2)
    recv_flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    try:
        chunk, ancillary, flags, _address = recvmsg(size, ancillary_size, recv_flags)
    except socket.timeout:
        raise BrokerError("request_timeout", "Broker request timed out.") from None
    except OSError:
        raise
    descriptors = _descriptors_from_ancillary(ancillary, flags)
    return chunk, descriptors


def _descriptors_from_ancillary(
    ancillary: Iterable[tuple[int, int, bytes]], flags: int
) -> list[int]:
    descriptors: list[int] = []
    try:
        descriptor_size = struct.calcsize("i")
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise BrokerError(
                    "secret_fd_invalid",
                    "Broker descriptor ancillary data is invalid.",
                )
            if not data:
                raise BrokerError(
                    "secret_fd_invalid",
                    "Broker descriptor ancillary data is invalid.",
                )
            full_descriptor_bytes = len(data) - (len(data) % descriptor_size)
            for descriptor in struct.unpack(
                f"{full_descriptor_bytes // descriptor_size}i",
                data[:full_descriptor_bytes],
            ):
                if descriptor < 0:
                    raise BrokerError(
                        "secret_fd_invalid",
                        "Broker descriptor ancillary data is invalid.",
                    )
                try:
                    os.set_inheritable(descriptor, False)
                except OSError:
                    _close_descriptor_quietly(descriptor)
                    raise BrokerError(
                        "secret_fd_invalid",
                        "Broker descriptor could not be made close-on-exec.",
                    ) from None
                descriptors.append(descriptor)
            if len(data) % descriptor_size:
                raise BrokerError(
                    "secret_fd_invalid",
                    "Broker descriptor ancillary data is invalid.",
                )
        if flags & getattr(socket, "MSG_CTRUNC", 0):
            # Parse and close every descriptor that did arrive before rejecting
            # the truncated remainder; leaving one open would turn malformed
            # ancillary data into a broker-side descriptor leak.
            raise BrokerError(
                "secret_fd_invalid",
                "Broker descriptor ancillary data was truncated.",
            )
        return descriptors
    except BaseException:
        _close_descriptors_quietly(descriptors)
        raise


def _ephemeral_secret_pipe(
    material: EphemeralSecretMaterial, expected_request_id: uuid.UUID
) -> tuple[int, int]:
    """Copy bounded bytes into an anonymous read-only pipe for FD transfer."""

    value = material.value
    expires_at_epoch = material.expires_at_epoch
    material_request_id = material.request_id
    if (
        type(value) is not bytes
        or not value
        or len(value) > MAX_EPHEMERAL_SECRET_BYTES
        or not _is_exact_int(expires_at_epoch)
        or int(expires_at_epoch) <= int(time.time())
        or material_request_id != expected_request_id
    ):
        raise BrokerError(
            "secret_delivery_invalid",
            "The broker could not safely prepare the ephemeral credential.",
        )
    if hasattr(os, "pipe2"):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    else:
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(write_fd, value[offset:])
            if written <= 0:
                raise OSError("ephemeral credential pipe write made no progress")
            offset += written
    except BaseException:
        _close_descriptor_quietly(read_fd)
        raise
    finally:
        _close_descriptor_quietly(write_fd)
    return read_fd, int(expires_at_epoch)


def _send_frame_with_fd(
    connection: socket.socket,
    payload: bytes,
    descriptor: int,
    *,
    max_message_bytes: int,
) -> None:
    """Send one redacted frame and one credential descriptor atomically first."""

    if not payload or len(payload) > max_message_bytes:
        raise BrokerError(
            "response_too_large", "Broker response exceeds the configured size limit."
        )
    if not _is_exact_int(descriptor) or descriptor < 0:
        raise BrokerError("secret_fd_invalid", "Broker credential descriptor is invalid.")
    if not _descriptor_transport_available(connection):
        raise BrokerError(
            "secret_fd_transport_unavailable",
            "This platform does not provide authenticated descriptor transport.",
        )
    sendmsg = connection.sendmsg
    try:
        os.fstat(descriptor)
    except OSError:
        raise BrokerError("secret_fd_invalid", "Broker credential descriptor is invalid.") from None
    frame = struct.pack("!I", len(payload)) + payload
    sent = sendmsg(
        [frame],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", descriptor))],
    )
    if sent <= 0:
        raise OSError("broker descriptor send made no progress")
    while sent < len(frame):
        written = connection.send(frame[sent:])
        if written <= 0:
            raise OSError("broker frame send made no progress")
        sent += written


def _close_descriptor_quietly(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        return


def _close_descriptors_quietly(descriptors: Iterable[int]) -> None:
    for descriptor in descriptors:
        _close_descriptor_quietly(descriptor)


def _send_frame(
    connection: socket.socket,
    payload: bytes,
    *,
    max_message_bytes: int,
) -> None:
    if not payload or len(payload) > max_message_bytes:
        raise BrokerError(
            "response_too_large", "Broker response exceeds the configured size limit."
        )
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _safe_send_reply(
    connection: socket.socket,
    reply: Mapping[str, Any],
    *,
    max_message_bytes: int,
) -> None:
    try:
        _send_frame(
            connection,
            _encode_json_document(reply),
            max_message_bytes=max_message_bytes,
        )
    except (BrokerError, OSError, socket.timeout):
        return


def _validate_socket_path(socket_path: Path) -> None:
    path = Path(socket_path)
    if not path.is_absolute() or ".." in path.parts:
        raise BrokerError(
            "unsafe_socket_path",
            "Broker socket path must be absolute and must not contain traversal.",
        )
    if path.name in {"", ".", ".."} or path.parent == path:
        raise BrokerError("unsafe_socket_path", "Broker socket path is invalid.")
    if len(os.fsencode(str(path))) > 103:
        raise BrokerError(
            "unsafe_socket_path",
            "Broker socket path is too long for a portable Unix-domain socket.",
        )


def _validate_client_socket(
    socket_path: Path,
) -> os.stat_result:
    _validate_socket_path(socket_path)
    _validate_trusted_path_components(socket_path.parent)
    try:
        info = os.lstat(str(socket_path))
    except OSError:
        raise BrokerError(
            "broker_identity_mismatch", "Configured broker socket is unavailable."
        ) from None
    if not stat.S_ISSOCK(info.st_mode):
        raise BrokerError(
            "broker_identity_mismatch",
            "Configured broker path is not a Unix socket.",
        )
    return info


def _validate_trusted_path_components(
    path: Path,
) -> None:
    """Reject symlink and non-directory transport path components."""

    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current = current / part
        try:
            info = os.lstat(str(current))
        except OSError:
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime directory has a missing or unreadable component.",
            ) from None
        if stat.S_ISLNK(info.st_mode):
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime directory must not contain symbolic-link components.",
            )
        if not stat.S_ISDIR(info.st_mode):
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime path contains a non-directory component.",
            )


def _reject_symlink_components(path: Path) -> None:
    # Backward-compatible private helper retained for callers that need only a
    # symlink check.  Transport callers use the component/type validation
    # above; neither helper treats ownership or Unix mode as request validation.
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current = current / part
        try:
            info = os.lstat(str(current))
        except OSError:
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime directory has a missing or unreadable component.",
            ) from None
        if stat.S_ISLNK(info.st_mode):
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime directory must not contain symbolic-link components.",
            )


def _is_exact_int(value: Any) -> bool:
    return type(value) is int
