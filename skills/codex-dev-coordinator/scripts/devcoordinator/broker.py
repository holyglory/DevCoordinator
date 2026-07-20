"""Authenticated Unix-socket broker for host-global coordinator mutations.

The broker is deliberately a narrow capability boundary.  Clients identify an
account, repository, resource, and one operation from :class:`BrokerOperation`.
They cannot submit commands, paths, SQL, or a writable database handle.  The
trusted broker process authenticates the operating-system peer, applies an
explicit per-UID ACL, and sends the resulting typed request through one
serialized mutation writer.

The mutation backend is responsible for revalidating the current repository /
resource binding and durably deduplicating ``operation_id`` in the coordinator
store before performing external work.  Keeping that contract behind
``MutationBackend`` lets this module remain independent of the store package;
in particular, an untrusted client can never acquire a SQLite connection.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
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


PROTOCOL_VERSION = 1
# Inventory is a bounded whole-host graph.  Keep the local protocol bounded,
# but size it for a real multi-repository machine rather than a mutation-sized
# reply.  Reads are not retained in the mutation replay cache.
DEFAULT_MAX_MESSAGE_BYTES = 32 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_SOCKET_MODE = 0o660
DEFAULT_MAX_CLIENTS = 32
DEFAULT_COMPLETED_OPERATION_CACHE = 1024
# These are broker-side client and graceful-wait budgets for the PostgreSQL
# helper calls: one dump and one strong-verification allowance, plus a minute
# for durable result commits and the reply. They do not prove that nested
# Docker/in-container work reached a terminal state when a helper times out.
# Repository lifecycle plans can also exceed this budget; their recovery
# contract is durable per-target phase checkpoints plus idempotent
# re-observation, rather than completion inside this timeout.
DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS = 30 * 60.0
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
    }
)

_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)
_LOGGER = logging.getLogger(__name__)


class BrokerOperation(str, Enum):
    """The complete typed operation set accepted from broker clients."""

    PORT_LEASE = "port.lease"
    PORT_RELEASE = "port.release"
    PORT_ASSIGN = "port.assign"
    PORT_UNASSIGN = "port.unassign"
    INVENTORY_READ = "inventory.read"
    EVENTS_READ = "events.read"
    HOST_OBSERVE = "host.observe"
    SERVER_PUBLISH = "server.publish"
    DOCKER_START = "docker.start"
    DOCKER_STOP = "docker.stop"
    DOCKER_RESTART = "docker.restart"
    DATABASE_BACKUP = "database.backup"
    DATABASE_RESTORE = "database.restore"
    COMPOSE_UP = "compose.up"
    COMPOSE_STOP = "compose.stop"
    COMPOSE_RESTART = "compose.restart"
    COMPOSE_DOWN = "compose.down"
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
    CLEANUP_PLAN = "cleanup.plan"
    CLEANUP_APPLY = "cleanup.apply"
    LIFECYCLE_RESTORE = "lifecycle.restore"


class BrokerError(RuntimeError):
    """A safe structured failure which may be returned to a client."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        operation_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.operation_id = operation_id


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
        return cls(
            operation_id=operation_id,
            authority_generation=authority_generation,
            account_id=account_id,
            project_id=project_id,
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
    ) -> "BrokerRequest":
        return cls.from_wire(
            {
                "version": PROTOCOL_VERSION,
                "operation_id": operation_id or str(uuid.uuid4()),
                "authority_generation": authority_generation,
                "account_id": account_id,
                "project_id": project_id,
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
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "arguments": dict(self.arguments),
        }


@dataclass(frozen=True)
class AuthorizedBrokerRequest:
    """A typed request whose peer and ACL have already been verified."""

    peer: PeerCredentials
    request: BrokerRequest


@dataclass(frozen=True)
class PortLeasePolicy:
    """The exact host-port capability granted to one server resource."""

    start_port: int
    end_port: int
    protocol: str = "tcp"
    max_ttl_seconds: int = 3_600

    def __post_init__(self) -> None:
        if (
            not _is_exact_int(self.start_port)
            or not _is_exact_int(self.end_port)
            or not 1 <= self.start_port <= self.end_port <= 65_535
        ):
            raise ValueError("port policy range must be within 1 through 65535")
        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("port policy protocol must be tcp or udp")
        if (
            not _is_exact_int(self.max_ttl_seconds)
            or not 1 <= self.max_ttl_seconds <= 7 * 24 * 60 * 60
        ):
            raise ValueError("port policy max_ttl_seconds must be from one second to seven days")

    def permits(self, *, port: Optional[int], protocol: str, ttl_seconds: int) -> bool:
        if protocol != self.protocol or ttl_seconds > self.max_ttl_seconds:
            return False
        return port is None or self.start_port <= port <= self.end_port


@dataclass(frozen=True)
class AccountAccessPolicy:
    """Explicit resource-operation grants for one account and kernel UID.

    ``grants`` is ``project_id -> resource_id -> operations``.  Wildcards and
    name-derived ownership are intentionally unsupported.
    """

    account_id: str
    grants: Mapping[str, Mapping[str, FrozenSet[BrokerOperation]]]
    port_policies: Mapping[str, Mapping[str, tuple[PortLeasePolicy, ...]]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        account_id = _validate_policy_identifier(self.account_id, "account_id")
        frozen_projects: dict[
            str, Mapping[str, FrozenSet[BrokerOperation]]
        ] = {}
        if not isinstance(self.grants, Mapping):
            raise ValueError("grants must be a mapping")
        for project_id, resources in self.grants.items():
            project = _validate_policy_identifier(project_id, "project_id")
            if not isinstance(resources, Mapping) or not resources:
                raise ValueError("each project grant must contain resources")
            frozen_resources: dict[str, FrozenSet[BrokerOperation]] = {}
            for resource_id, operations in resources.items():
                resource = _validate_policy_identifier(resource_id, "resource_id")
                normalized: set[BrokerOperation] = set()
                try:
                    for operation in operations:
                        normalized.add(BrokerOperation(operation))
                except (TypeError, ValueError):
                    raise ValueError("resource grants contain an unknown operation")
                if not normalized:
                    raise ValueError("each resource grant must contain operations")
                frozen_resources[resource] = frozenset(normalized)
            frozen_projects[project] = MappingProxyType(frozen_resources)

        if not isinstance(self.port_policies, Mapping):
            raise ValueError("port_policies must be a mapping")
        frozen_port_projects: dict[
            str, Mapping[str, tuple[PortLeasePolicy, ...]]
        ] = {}
        for project_id, resources in self.port_policies.items():
            project = _validate_policy_identifier(project_id, "project_id")
            if project not in frozen_projects:
                raise ValueError("port policy project must have a resource grant")
            if not isinstance(resources, Mapping) or not resources:
                raise ValueError("each port policy project must contain resources")
            frozen_resources: dict[str, tuple[PortLeasePolicy, ...]] = {}
            for resource_id, policies in resources.items():
                resource = _validate_policy_identifier(resource_id, "resource_id")
                operations = frozen_projects[project].get(resource)
                if operations is None or not operations.intersection(
                    {BrokerOperation.PORT_LEASE, BrokerOperation.PORT_ASSIGN}
                ):
                    raise ValueError(
                        "port policy resource must have a port.lease or port.assign grant"
                    )
                normalized_policies = tuple(policies)
                if not normalized_policies or any(
                    not isinstance(policy, PortLeasePolicy)
                    for policy in normalized_policies
                ):
                    raise ValueError("port policy resource must contain PortLeasePolicy values")
                frozen_resources[resource] = normalized_policies
            frozen_port_projects[project] = MappingProxyType(frozen_resources)

        for project, resources in frozen_projects.items():
            for resource, operations in resources.items():
                if operations.intersection(
                    {BrokerOperation.PORT_LEASE, BrokerOperation.PORT_ASSIGN}
                ) and not (
                    project in frozen_port_projects
                    and resource in frozen_port_projects[project]
                ):
                    raise ValueError(
                        "every port.lease or port.assign grant requires an explicit port policy"
                    )
        object.__setattr__(self, "account_id", account_id)
        object.__setattr__(self, "grants", MappingProxyType(frozen_projects))
        object.__setattr__(
            self, "port_policies", MappingProxyType(frozen_port_projects)
        )


class Authorizer(Protocol):
    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        """Return an authorized request or raise :class:`BrokerError`."""


class StaticPeerAuthorizer:
    """Kernel-UID authorizer backed by immutable explicit ACLs."""

    def __init__(self, policies: Mapping[int, AccountAccessPolicy]) -> None:
        frozen: dict[int, AccountAccessPolicy] = {}
        for uid, policy in policies.items():
            if not _is_exact_int(uid) or uid < 0:
                raise ValueError("policy uid must be a non-negative integer")
            if uid in frozen:
                raise ValueError("duplicate uid policy")
            if not isinstance(policy, AccountAccessPolicy):
                raise TypeError("policy values must be AccountAccessPolicy")
            frozen[uid] = policy
        self._policies = MappingProxyType(frozen)

    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        policy = self._policies.get(peer.uid)
        if policy is None:
            raise BrokerError(
                "peer_not_authorized",
                "This operating-system account is not authorized to use the broker.",
                operation_id=request.operation_id,
            )
        if request.account_id != policy.account_id:
            raise BrokerError(
                "cross_account_access_denied",
                "The authenticated account cannot act for the requested account.",
                operation_id=request.operation_id,
            )
        resources = policy.grants.get(request.project_id)
        if resources is None:
            raise BrokerError(
                "project_access_denied",
                "The authenticated account is not authorized for this project.",
                operation_id=request.operation_id,
            )
        operations = resources.get(request.resource_id)
        if operations is None:
            raise BrokerError(
                "resource_access_denied",
                "The authenticated account is not authorized for this resource.",
                operation_id=request.operation_id,
            )
        if request.operation not in operations:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this resource operation.",
                operation_id=request.operation_id,
            )
        if request.operation in {
            BrokerOperation.PORT_LEASE,
            BrokerOperation.PORT_ASSIGN,
        }:
            policies = policy.port_policies[request.project_id][request.resource_id]
            if request.operation == BrokerOperation.PORT_ASSIGN:
                port = request.arguments["port"]
                protocol = "tcp"
                ttl_seconds = 1
            else:
                port = request.arguments.get("requested_port")
                protocol = str(request.arguments.get("protocol", "tcp"))
                ttl_seconds = int(request.arguments.get("ttl_seconds", 600))
            if not any(
                item.permits(
                    port=port,
                    protocol=protocol,
                    ttl_seconds=ttl_seconds,
                )
                for item in policies
            ):
                raise BrokerError(
                    "port_policy_denied",
                    "The requested port, protocol, or lease duration is outside the account policy.",
                    operation_id=request.operation_id,
                )
        return AuthorizedBrokerRequest(peer=peer, request=request)


class MutationBackend(Protocol):
    """Trusted broker-process implementation of shared resource mutation.

    Implementations must use ``request.request.operation_id`` as the durable
    idempotency key, revalidate the exact current control binding, and keep slow
    Docker/process work outside bounded database write transactions.
    """

    def execute(self, request: AuthorizedBrokerRequest) -> Mapping[str, Any]:
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

    def execute(self, request: AuthorizedBrokerRequest) -> dict[str, Any]:
        if request.request.operation in {
            BrokerOperation.INVENTORY_READ,
            BrokerOperation.EVENTS_READ,
        }:
            # A query-only snapshot does not need the mutation lock, durable
            # idempotency journal, or completed-result cache.  Avoid retaining
            # up to one full host graph per caller in broker memory.
            return _normalize_backend_result(
                self._backend.execute(request), max_bytes=self._max_result_bytes
            )
        operation_id = request.request.operation_id
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
            if request.request.operation == BrokerOperation.HOST_OBSERVE:
                slots = self._host_observation_slots
                if slots is None or not slots.acquire(blocking=False):
                    raise BrokerError(
                        "host_observation_busy",
                        "The broker already has the maximum number of host observation callers; retry later.",
                        operation_id=operation_id,
                    )
                try:
                    return self._execute_mutation(request)
                finally:
                    slots.release()
            return self._execute_mutation(request)
        finally:
            with self._metrics_condition:
                self._inflight_mutation_count -= 1
                if self._inflight_mutation_count < 0:
                    raise RuntimeError("broker mutation in-flight count underflow")
                self._metrics_condition.notify_all()

    def _execute_mutation(
        self, request: AuthorizedBrokerRequest
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
        if request.request.operation != BrokerOperation.HOST_OBSERVE:
            lock_keys.append("resource:" + resource_key)
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
    """Strict request parsing, authorization, and mutation dispatch."""

    def __init__(
        self,
        authorizer: Authorizer,
        writer: SerializedMutationWriter,
    ) -> None:
        self._authorizer = authorizer
        self._writer = writer

    def reply_for_document(
        self, peer: PeerCredentials, document: Any
    ) -> dict[str, Any]:
        operation_id = _valid_operation_id_or_none(document)
        try:
            request = BrokerRequest.from_wire(document)
            authorized = self._authorizer.authorize(peer, request)
            result = self._writer.execute(authorized)
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

    def reply_for_payload(
        self, peer: PeerCredentials, payload: bytes
    ) -> bytes:
        try:
            document = _decode_json_document(payload)
        except BrokerError as exc:
            return _encode_json_document(
                _error_reply(exc.code, exc.message, operation_id=exc.operation_id)
            )
        return _encode_json_document(self.reply_for_document(peer, document))


def resolve_peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read kernel-authenticated credentials for an ``AF_UNIX`` peer.

    Linux uses ``SO_PEERCRED``.  macOS and BSD use ``getpeereid`` through a
    native socket method when exposed, otherwise through libc.  Unsupported or
    unreadable credentials fail closed.
    """

    if connection.family != socket.AF_UNIX:
        raise BrokerError(
            "peer_credentials_unavailable",
            "Broker accepts only authenticated Unix-domain socket peers.",
        )

    if sys.platform.startswith("linux"):
        option = getattr(socket, "SO_PEERCRED", None)
        if option is None:
            raise BrokerError(
                "peer_credentials_unavailable",
                "Kernel peer credentials are unavailable on this host.",
            )
        size = struct.calcsize("3i")
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, option, size)
            pid, uid, gid = struct.unpack("3i", raw[:size])
            return PeerCredentials(uid=uid, gid=gid, pid=pid)
        except (OSError, struct.error, ValueError):
            raise BrokerError(
                "peer_credentials_unavailable",
                "Kernel peer credentials could not be verified.",
            ) from None

    native_getpeereid = getattr(connection, "getpeereid", None)
    if callable(native_getpeereid):
        try:
            uid, gid = native_getpeereid()
            return PeerCredentials(uid=int(uid), gid=int(gid), pid=None)
        except (OSError, TypeError, ValueError):
            raise BrokerError(
                "peer_credentials_unavailable",
                "Kernel peer credentials could not be verified.",
            ) from None

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
            raise BrokerError(
                "peer_credentials_unavailable",
                "Kernel peer credentials could not be verified.",
            ) from None

    raise BrokerError(
        "peer_credentials_unavailable",
        "This platform does not provide a supported Unix peer-credential API.",
    )


def validate_runtime_directory(
    runtime_directory: Path,
    *,
    expected_uid: Optional[int] = None,
    expected_gid: Optional[int] = None,
) -> os.stat_result:
    """Validate a coordinator-owned, non-symlink Unix-socket directory.

    Group read/execute is allowed so a deliberately provisioned broker access
    group can reach the socket.  Group write and all access by ``other`` are
    rejected; cross-UID authorization remains a kernel-credential ACL decision.
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
    owner_uid = os.geteuid() if expected_uid is None else expected_uid
    if not _is_exact_int(owner_uid) or owner_uid < 0:
        raise BrokerError(
            "unsafe_runtime_directory", "Broker runtime owner UID is invalid."
        )
    if expected_gid is not None and (
        not _is_exact_int(expected_gid) or expected_gid < 0
    ):
        raise BrokerError(
            "unsafe_runtime_directory", "Broker runtime access GID is invalid."
        )
    _validate_trusted_path_components(path, expected_uid=owner_uid)
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
    if info.st_uid != owner_uid:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory is not owned by the coordinator service.",
        )
    if expected_gid is not None and info.st_gid != expected_gid:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory does not use the configured access group.",
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode & stat.S_IWGRP or mode & stat.S_IRWXO:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory must not be group-writable or accessible by other users.",
        )
    required_owner = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
    if mode & required_owner != required_owner:
        raise BrokerError(
            "unsafe_runtime_directory",
            "Broker runtime directory owner requires read, write, and execute access.",
        )
    return info


class UnixBrokerServer:
    """Concurrent Unix-socket transport around :class:`BrokerService`."""

    def __init__(
        self,
        socket_path: Path,
        service: BrokerService,
        *,
        expected_uid: Optional[int] = None,
        expected_gid: Optional[int] = None,
        peer_resolver: Callable[[socket.socket], PeerCredentials] = resolve_peer_credentials,
        socket_mode: int = DEFAULT_SOCKET_MODE,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        shutdown_timeout_seconds: float = BROKER_SHUTDOWN_DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        self.socket_path = Path(socket_path)
        self._service = service
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._expected_gid = os.getegid() if expected_gid is None else expected_gid
        if not _is_exact_int(self._expected_uid) or self._expected_uid < 0:
            raise ValueError("expected_uid must be a non-negative integer")
        if not _is_exact_int(self._expected_gid) or self._expected_gid < 0:
            raise ValueError("expected_gid must be a non-negative integer")
        self._peer_resolver = peer_resolver
        if not _is_exact_int(socket_mode) or socket_mode < 0:
            raise ValueError("socket_mode must be a permission mode")
        if socket_mode & 0o117 or socket_mode & 0o7000:
            raise ValueError("socket_mode may grant only owner/group read-write")
        if socket_mode & 0o600 != 0o600:
            raise ValueError("socket_mode must grant owner read-write")
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
        self._stop = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._clients_lock = threading.Lock()
        self._client_threads: set[threading.Thread] = set()
        self._client_connections: set[socket.socket] = set()

    def start(self) -> None:
        if self._listener is not None:
            raise RuntimeError("broker server is already started")
        _validate_socket_path(self.socket_path)
        runtime_info = validate_runtime_directory(
            self.socket_path.parent,
            expected_uid=self._expected_uid,
            expected_gid=self._expected_gid,
        )
        if self._socket_mode & 0o060 and not (
            stat.S_IMODE(runtime_info.st_mode) & stat.S_IXGRP
        ):
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime directory must grant traversal to its configured access group.",
            )
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
                "Broker socket path already exists; it was not replaced.",
            )

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        try:
            listener.bind(str(self.socket_path))
            created = os.lstat(str(self.socket_path))
            if not stat.S_ISSOCK(created.st_mode) or created.st_uid != self._expected_uid:
                raise BrokerError(
                    "unsafe_socket_path",
                    "Created broker socket failed ownership validation.",
                )
            # Record the exact inode as soon as bind succeeds so every later
            # startup failure can remove only the socket this process created.
            self._socket_identity = (created.st_dev, created.st_ino)
            os.chown(
                str(self.socket_path), self._expected_uid, self._expected_gid
            )
            os.chmod(str(self.socket_path), self._socket_mode)
            runtime_after = validate_runtime_directory(
                self.socket_path.parent,
                expected_uid=self._expected_uid,
                expected_gid=self._expected_gid,
            )
            info = os.lstat(str(self.socket_path))
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != self._expected_uid
                or info.st_gid != self._expected_gid
                or (info.st_dev, info.st_ino) != self._socket_identity
                or (runtime_after.st_dev, runtime_after.st_ino)
                != (runtime_info.st_dev, runtime_info.st_ino)
            ):
                raise BrokerError(
                    "unsafe_socket_path",
                    "Created broker socket failed ownership validation.",
                )
            if stat.S_IMODE(info.st_mode) != self._socket_mode:
                raise BrokerError(
                    "unsafe_socket_path",
                    "Created broker socket failed permission validation.",
                )
            listener.listen()
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            self._remove_created_socket_if_owned()
            self._socket_identity = None
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
        try:
            peer = self._peer_resolver(connection)
        except BrokerError as exc:
            _safe_send_reply(
                connection,
                _error_reply(exc.code, exc.message, operation_id=None),
                max_message_bytes=self._max_message_bytes,
            )
            return
        try:
            payload = _receive_frame(
                connection, max_message_bytes=self._max_message_bytes
            )
            reply_payload = self._service.reply_for_payload(peer, payload)
            _send_frame(
                connection,
                reply_payload,
                max_message_bytes=self._max_message_bytes,
            )
        except BrokerError as exc:
            _safe_send_reply(
                connection,
                _error_reply(exc.code, exc.message, operation_id=exc.operation_id),
                max_message_bytes=self._max_message_bytes,
            )
        except (OSError, socket.timeout):
            return

    def _remove_created_socket_if_owned(self) -> None:
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
            and info.st_uid == self._expected_uid
            and stat.S_ISSOCK(info.st_mode)
        ):
            try:
                os.unlink(str(self.socket_path))
            except OSError:
                _LOGGER.exception("could not remove broker socket during cleanup")


class BrokerClient:
    """One-request client that authenticates the service and reply identity."""

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_broker_uid: int,
        expected_socket_gid: Optional[int] = None,
        expected_socket_mode: int = DEFAULT_SOCKET_MODE,
        timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        self.socket_path = Path(socket_path)
        if not _is_exact_int(expected_broker_uid) or expected_broker_uid < 0:
            raise ValueError("expected_broker_uid must be a non-negative integer")
        if expected_socket_gid is not None and (
            not _is_exact_int(expected_socket_gid) or expected_socket_gid < 0
        ):
            raise ValueError("expected_socket_gid must be a non-negative integer")
        if (
            not _is_exact_int(expected_socket_mode)
            or expected_socket_mode < 0
            or expected_socket_mode > 0o7777
        ):
            raise ValueError("expected_socket_mode must be a permission mode")
        self._expected_broker_uid = expected_broker_uid
        self._expected_socket_gid = expected_socket_gid
        self._expected_socket_mode = expected_socket_mode
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not _is_exact_int(max_message_bytes) or max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")
        self._timeout_seconds = timeout_seconds
        self._max_message_bytes = max_message_bytes

    def call(self, request: BrokerRequest) -> dict[str, Any]:
        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be BrokerRequest")
        payload = _encode_json_document(request.to_wire())
        socket_before = _validate_client_socket(
            self.socket_path,
            expected_uid=self._expected_broker_uid,
            expected_gid=self._expected_socket_gid,
            expected_mode=self._expected_socket_mode,
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self._timeout_seconds)
            connection.connect(str(self.socket_path))
            peer = resolve_peer_credentials(connection)
            if peer.uid != self._expected_broker_uid:
                raise BrokerError(
                    "broker_identity_mismatch",
                    "Connected Unix peer is not the configured coordinator broker.",
                    operation_id=request.operation_id,
                )
            socket_after = _validate_client_socket(
                self.socket_path,
                expected_uid=self._expected_broker_uid,
                expected_gid=self._expected_socket_gid,
                expected_mode=self._expected_socket_mode,
            )
            if (socket_before.st_dev, socket_before.st_ino) != (
                socket_after.st_dev,
                socket_after.st_ino,
            ):
                raise BrokerError(
                    "broker_identity_mismatch",
                    "Broker socket identity changed while connecting.",
                    operation_id=request.operation_id,
                )
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
                    reply_payload = _receive_frame(
                        connection, max_message_bytes=self._max_message_bytes
                    )
                except (BrokerError, OSError, socket.timeout):
                    raise send_error
            else:
                reply_payload = _receive_frame(
                    connection, max_message_bytes=self._max_message_bytes
                )
        document = _decode_json_document(reply_payload)
        return _validate_reply(document, expected_operation_id=request.operation_id)


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
        if value:
            raise BrokerError(
                "invalid_arguments",
                "Compose mutations do not accept client-controlled paths, names, arguments, or options.",
                operation_id=operation_id,
            )
        return {}

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
        if target_kind not in {"project", "server", "container", "worktree"}:
            raise BrokerError(
                "invalid_arguments",
                "cleanup target_kind must be project, server, container, or worktree.",
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
        "control_binding_id",
        "immutable_fingerprint",
        "ownership_fingerprint",
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
            "control_binding_id": _opaque_argument(
                value["control_binding_id"], "control_binding_id", operation_id
            ),
            "immutable_fingerprint": _sha256_fingerprint_argument(
                value["immutable_fingerprint"], "immutable_fingerprint", operation_id
            ),
            "ownership_fingerprint": _sha256_fingerprint_argument(
                value["ownership_fingerprint"], "ownership_fingerprint", operation_id
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


def _request_fingerprint(request: AuthorizedBrokerRequest) -> str:
    document = request.request.to_wire()
    # Authorization is deliberately per effective UID.  The peer's incidental
    # effective GID may differ between two sessions of the same account and is
    # not part of the authenticated principal unless an authorizer explicitly
    # models it as such.
    document["authenticated_uid"] = request.peer.uid
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def authenticated_request_fingerprint(request: AuthorizedBrokerRequest) -> str:
    """Stable durable idempotency fingerprint for the authenticated UID."""

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
    *,
    expected_uid: int,
    expected_gid: Optional[int],
    expected_mode: int,
) -> os.stat_result:
    _validate_socket_path(socket_path)
    _validate_trusted_path_components(
        socket_path.parent, expected_uid=expected_uid
    )
    try:
        info = os.lstat(str(socket_path))
    except OSError:
        raise BrokerError(
            "broker_identity_mismatch", "Configured broker socket is unavailable."
        ) from None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid:
        raise BrokerError(
            "broker_identity_mismatch",
            "Configured broker socket has the wrong type or owner.",
        )
    if expected_gid is not None and info.st_gid != expected_gid:
        raise BrokerError(
            "broker_identity_mismatch",
            "Configured broker socket has the wrong access group.",
        )
    if stat.S_IMODE(info.st_mode) != expected_mode:
        raise BrokerError(
            "broker_identity_mismatch",
            "Configured broker socket has unexpected permissions.",
        )
    return info


def _validate_trusted_path_components(path: Path, *, expected_uid: int) -> None:
    """Reject symlinks and replaceable ancestors of a security boundary."""

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
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in {0, expected_uid}:
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime path has an ancestor owned by an untrusted account.",
            )
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise BrokerError(
                "unsafe_runtime_directory",
                "Broker runtime path has a replaceable group/world-writable ancestor.",
            )


def _reject_symlink_components(path: Path) -> None:
    # Backward-compatible private helper retained for callers that need only a
    # symlink check.  Security-boundary callers use the stricter trusted-path
    # validation above.
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
