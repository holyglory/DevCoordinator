"""Unix-peer-attributed testd-to-broker adapters for transient attempts."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import time
from pathlib import Path
from typing import Callable, Mapping, Protocol, runtime_checkable
import uuid

from .broker import BrokerClient, BrokerError, BrokerOperation, BrokerRequest
from .call_journal import RollingCallJournal, event_record
from .universal_test_service import decode_test_plan_document
from .universal_test_spool import AttemptExitEnvelope
from .universal_test_store import (
    AttemptConclusion,
    LeaseGrant,
    RunnableTarget,
    TestStoreConflict,
    TestStoreContractError,
)
from .universal_testd import (
    BrokerLaunchTicket,
    BrokerLaunchTicketIssuer,
    RunnerRecoveryContext,
    RuntimeRequestSubmitter,
)


# One broker call is only a polling slice inside the caller-owned launch
# deadline.  Snapshot materialization and systemd activation can legitimately
# outlive this slice; the deterministic operation identity is replayed until
# the semantic deadline expires.  Keeping the transport slice software-owned
# prevents one slow launch from blocking the testd supervision loop for the
# caller's entire (potentially one-hour) launch allowance.
DEFAULT_LAUNCH_RPC_SLICE_SECONDS = 10.0


def _terminal_resource_usage(value: object) -> tuple[int | None, float | None]:
    if not isinstance(value, Mapping) or set(value) != {
        "peak_memory_bytes",
        "cpu_seconds",
    }:
        raise TestStoreContractError("broker runtime resource usage is invalid")
    peak_memory_bytes = value["peak_memory_bytes"]
    cpu_seconds = value["cpu_seconds"]
    if peak_memory_bytes is not None and (
        type(peak_memory_bytes) is not int
        or not 0 <= peak_memory_bytes <= (1 << 63) - 1
    ):
        raise TestStoreContractError("broker runtime peak memory is invalid")
    if cpu_seconds is not None and (
        isinstance(cpu_seconds, bool)
        or not isinstance(cpu_seconds, (int, float))
        or not math.isfinite(float(cpu_seconds))
        or float(cpu_seconds) < 0
        or float(cpu_seconds) > 31_536_000
    ):
        raise TestStoreContractError("broker runtime CPU measurement is invalid")
    return (
        peak_memory_bytes,
        None if cpu_seconds is None else float(cpu_seconds),
    )


def _current_memory_usage(value: object) -> int | None:
    if not isinstance(value, Mapping) or set(value) != {"current_memory_bytes"}:
        raise TestStoreContractError("running broker runtime resource usage is invalid")
    current_memory_bytes = value["current_memory_bytes"]
    if current_memory_bytes is not None and (
        type(current_memory_bytes) is not int
        or not 0 <= current_memory_bytes <= (1 << 63) - 1
    ):
        raise TestStoreContractError("broker runtime current memory is invalid")
    return current_memory_bytes


@runtime_checkable
class RepositoryLaunchDescriptorResolver(Protocol):
    """Resolve one selected manifest target through the repository-UID helper."""

    def resolve_as_owner(
        self,
        *,
        candidate: RunnableTarget,
        lease: LeaseGrant,
        plan_document: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...

    def observe_live_source_as_owner(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        plan_document: Mapping[str, object],
    ) -> str: ...


@dataclass(frozen=True)
class BrokerConnection:
    socket_path: Path
    authority_generation: str

    def __post_init__(self) -> None:
        path = Path(self.socket_path)
        if not path.is_absolute():
            raise TestStoreContractError("broker socket path must be absolute")
        object.__setattr__(self, "socket_path", path)
        if (
            not isinstance(self.authority_generation, str)
            or not self.authority_generation
            or len(self.authority_generation) > 256
        ):
            raise TestStoreContractError("broker authority generation is invalid")


class _InternalBrokerCalls:
    def __init__(
        self,
        connection: BrokerConnection,
        *,
        client_factory: Callable[..., BrokerClient] = BrokerClient,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        self.connection = connection
        self.client_factory = client_factory
        self.call_journal = call_journal

    def call(
        self,
        *,
        repository_id: str,
        repository_generation: int,
        resource_id: str,
        operation: BrokerOperation,
        arguments: Mapping[str, object],
        operation_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0
        ):
            raise TestStoreContractError("broker request timeout is invalid")
        request = BrokerRequest.create(
            account_id="devcoordinator-testd",
            project_id=repository_id,
            repository_generation=repository_generation,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
            authority_generation=self.connection.authority_generation,
        )
        client_arguments: dict[str, object] = {}
        # Omit the keyword when the caller accepts the BrokerClient default so
        # older injected factories remain source-compatible.
        if timeout_seconds is not None:
            client_arguments["timeout_seconds"] = float(timeout_seconds)
        call_id = str(uuid.uuid4())
        started = time.monotonic()
        record_fields = {
            "boundary": "testd_authority_client",
            "call_id": call_id,
            "operation": operation.value,
            "operation_id": request.operation_id,
            "repository_id": repository_id,
            "repository_generation": repository_generation,
            "resource_id": resource_id,
            "run_id": arguments.get("run_id"),
            "attempt_id": arguments.get("attempt_id"),
        }
        if self.call_journal is not None:
            self.call_journal.record(
                event_record(phase="received", outcome="received", **record_fields)
            )
        try:
            client = self.client_factory(
                self.connection.socket_path,
                **client_arguments,
            )
            reply = client.call(request)
        except Exception as error:
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        phase="completed",
                        duration_seconds=time.monotonic() - started,
                        outcome=(
                            "timeout"
                            if isinstance(error, TimeoutError)
                            or getattr(error, "code", None) == "request_timeout"
                            else "unavailable"
                        ),
                        code=getattr(error, "code", None) or "transport_unavailable",
                        message=str(error),
                        **record_fields,
                    )
                )
            raise
        if not isinstance(reply, Mapping) or reply.get("ok") is not True:
            error = reply.get("error") if isinstance(reply, Mapping) else None
            if isinstance(error, Mapping):
                code = error.get("code")
                message = error.get("message")
                if self.call_journal is not None:
                    self.call_journal.record(
                        event_record(
                            phase="completed",
                            duration_seconds=time.monotonic() - started,
                            outcome="rejected",
                            code=code if isinstance(code, str) else "broker_request_failed",
                            message=message if isinstance(message, str) else None,
                            **record_fields,
                        )
                    )
                raise BrokerError(
                    code if isinstance(code, str) and code else "broker_request_failed",
                    message
                    if isinstance(message, str) and message
                    else "Broker test attempt request failed.",
                    operation_id=request.operation_id,
                )
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        phase="completed",
                        duration_seconds=time.monotonic() - started,
                        outcome="failed",
                        code="invalid_response",
                        **record_fields,
                    )
                )
            raise TestStoreConflict("broker test attempt request failed")
        result = reply.get("result")
        if not isinstance(result, Mapping):
            if self.call_journal is not None:
                self.call_journal.record(
                    event_record(
                        phase="completed",
                        duration_seconds=time.monotonic() - started,
                        outcome="failed",
                        code="invalid_response",
                        **record_fields,
                    )
                )
            raise TestStoreContractError("broker test attempt result is invalid")
        if self.call_journal is not None:
            self.call_journal.record(
                event_record(
                    phase="completed",
                    duration_seconds=time.monotonic() - started,
                    outcome="ok",
                    **record_fields,
                )
            )
        return result


class CoordinatorBrokerTicketIssuer(BrokerLaunchTicketIssuer):
    """Obtain a generation-fenced descriptor after UID-helper resolution."""

    def __init__(
        self,
        connection: BrokerConnection,
        resolver: RepositoryLaunchDescriptorResolver,
        *,
        client_factory: Callable[..., BrokerClient] = BrokerClient,
        call_journal: RollingCallJournal | None = None,
        clock: Callable[[], float] = time.time,
        request_timeout_seconds: float = DEFAULT_LAUNCH_RPC_SLICE_SECONDS,
    ) -> None:
        if not isinstance(resolver, RepositoryLaunchDescriptorResolver):
            raise TestStoreContractError("repository launch descriptor resolver is invalid")
        self.calls = _InternalBrokerCalls(
            connection, client_factory=client_factory, call_journal=call_journal
        )
        self.resolver = resolver
        if (
            isinstance(request_timeout_seconds, bool)
            or not isinstance(request_timeout_seconds, (int, float))
            or not math.isfinite(float(request_timeout_seconds))
            or float(request_timeout_seconds) <= 0
        ):
            raise TestStoreContractError("broker ticket request timeout is invalid")
        self.clock = clock
        self.request_timeout_seconds = float(request_timeout_seconds)

    @staticmethod
    def _operation_id(candidate: RunnableTarget, lease: LeaseGrant) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-ticket:"
                + candidate.repository_id
                + ":"
                + lease.attempt_id
                + ":"
                + str(lease.generation),
            )
        )

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - float(self.clock())
        if remaining <= 0:
            raise BrokerError(
                "test_launch_deadline_exceeded",
                "The caller's test launch deadline expired before a launch ticket was confirmed.",
            )
        return remaining

    def issue(
        self,
        *,
        candidate: RunnableTarget,
        lease: LeaseGrant,
        plan_document: Mapping[str, object],
        launch_deadline: float,
    ) -> BrokerLaunchTicket:
        plan = decode_test_plan_document(plan_document)
        if (
            isinstance(launch_deadline, bool)
            or not isinstance(launch_deadline, (int, float))
            or not math.isfinite(float(launch_deadline))
        ):
            raise TestStoreContractError("test launch deadline is invalid")
        deadline = float(launch_deadline)
        descriptor = self.resolver.resolve_as_owner(
            candidate=candidate,
            lease=lease,
            plan_document=plan_document,
            timeout_seconds=self._remaining(deadline),
        )
        if not isinstance(descriptor, Mapping):
            raise TestStoreContractError("repository helper descriptor is invalid")
        operation_id = self._operation_id(candidate, lease)
        remaining = self._remaining(deadline)
        # The operation arguments are frozen before the first call because the
        # broker binds idempotency to the complete typed request.  Replays use
        # the exact same operation ID and fingerprint even as their transport
        # slice shrinks.
        ticket_launch_seconds = max(
            1, min(plan.timeouts.launch_seconds, math.ceil(remaining))
        )
        arguments = {
            "descriptor": dict(descriptor),
            "launch_timeout_seconds": ticket_launch_seconds,
        }
        while True:
            remaining = self._remaining(deadline)
            try:
                result = self.calls.call(
                    repository_id=candidate.repository_id,
                    repository_generation=0,
                    resource_id=lease.attempt_id,
                    operation=BrokerOperation.TEST_ATTEMPT_TICKET,
                    arguments=arguments,
                    operation_id=operation_id,
                    timeout_seconds=min(self.request_timeout_seconds, remaining),
                )
                break
            except BrokerError as error:
                if error.code not in {
                    "request_timeout",
                    "operation_in_progress",
                    "operation_outcome_uncertain",
                }:
                    raise
        expected = {
            "ticket_id",
            "attempt_id",
            "target_id",
            "run_id",
            "repository_id",
            "repository_generation",
            "owner_uid",
            "generation",
            "root_repo",
            "temporary_repo",
            "execution_root",
            "argv",
            "cwd",
            "environment",
            "intent",
            "driver",
            "reporter",
            "artifacts",
            "fixtures",
            "credentials",
            "network",
            "ttl_seconds",
            "kill_after_run",
            "resources",
            "worktree_key",
            "issued_at",
            "expires_at",
        }
        if set(result) != expected or result.get("kill_after_run") is not True:
            raise TestStoreContractError("broker launch ticket fields are invalid")
        resources = result["resources"]
        if not isinstance(resources, Mapping) or set(resources) != {
            "cpu_millis",
            "memory_mib",
            "pids",
        }:
            raise TestStoreContractError("broker launch ticket resources are invalid")
        return BrokerLaunchTicket(
            ticket_id=result["ticket_id"],
            attempt_id=result["attempt_id"],
            target_id=result["target_id"],
            run_id=result["run_id"],
            repository_id=result["repository_id"],
            repository_generation=result["repository_generation"],
            owner_uid=result["owner_uid"],
            generation=result["generation"],
            root_repo=result["root_repo"],
            temporary_repo=result["temporary_repo"],
            execution_root=result["execution_root"],
            argv=tuple(result["argv"]),
            cwd=result["cwd"],
            environment=dict(result["environment"]),
            intent=result["intent"],
            driver=result["driver"],
            reporter=result["reporter"],
            artifacts=tuple(dict(item) for item in result["artifacts"]),
            fixtures=tuple(result["fixtures"]),
            credentials=tuple(result["credentials"]),
            network=result["network"],
            ttl_seconds=result["ttl_seconds"],
            kill_after_run=True,
            cpu_millis=resources["cpu_millis"],
            memory_mib=resources["memory_mib"],
            pids=resources["pids"],
            worktree_key=result["worktree_key"],
            issued_at=result["issued_at"],
            expires_at=result["expires_at"],
        )

    def observe_live_source(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        plan_document: Mapping[str, object],
    ) -> str:
        plan = decode_test_plan_document(plan_document)
        if plan.repository_id != repository_id or plan.source.mode.value != "live":
            raise TestStoreConflict("live source observation identity is contradictory")
        observed = self.resolver.observe_live_source_as_owner(
            repository_id=repository_id,
            owner_uid=owner_uid,
            plan_document=plan_document,
        )
        if not isinstance(observed, str) or len(observed) != 64 or any(
            character not in "0123456789abcdef" for character in observed
        ):
            raise TestStoreContractError("live source observation is invalid")
        return observed


@dataclass
class _RuntimeContext:
    repository_id: str
    repository_generation: int
    attempt_id: str
    generation: int
    started_at: float
    launch_ticket_id: str | None = None
    launch_operation_id: str | None = None
    launch_timeout_seconds: int = 300
    launch_request_timeout_seconds: float = DEFAULT_LAUNCH_RPC_SLICE_SECONDS
    launch_confirmed: bool = True
    launch_failure_code: str | None = None
    launch_failure_message: str | None = None
    cancelled: bool = False
    next_chunk_index: int = 0
    result_chunk_ids: list[str] = field(default_factory=list)
    terminal_duration_seconds: float | None = None


class CoordinatorRuntimeRequestSubmitter(RuntimeRequestSubmitter):
    """Submit/observe/cancel attempts only through broker internal operations."""

    def __init__(
        self,
        connection: BrokerConnection,
        *,
        client_factory: Callable[..., BrokerClient] = BrokerClient,
        call_journal: RollingCallJournal | None = None,
        clock: Callable[[], float] = time.time,
        launch_request_timeout_seconds: float | None = (
            DEFAULT_LAUNCH_RPC_SLICE_SECONDS
        ),
    ) -> None:
        self.calls = _InternalBrokerCalls(
            connection, client_factory=client_factory, call_journal=call_journal
        )
        self.clock = clock
        if launch_request_timeout_seconds is not None and (
            isinstance(launch_request_timeout_seconds, bool)
            or not isinstance(launch_request_timeout_seconds, (int, float))
            or not math.isfinite(float(launch_request_timeout_seconds))
            or float(launch_request_timeout_seconds) <= 0
        ):
            raise TestStoreContractError("broker launch request timeout is invalid")
        # ``None`` was accepted by the first source-only implementation and
        # meant "wait for the whole semantic deadline".  Normalize it to the
        # bounded polling slice so old constructors cannot reintroduce that
        # supervision stall.
        self.launch_request_timeout_seconds = (
            DEFAULT_LAUNCH_RPC_SLICE_SECONDS
            if launch_request_timeout_seconds is None
            else float(launch_request_timeout_seconds)
        )
        self._runtimes: dict[str, _RuntimeContext] = {}

    @staticmethod
    def _launch_operation_id(ticket: Mapping[str, object]) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-launch:"
                + str(ticket["repository_id"])
                + ":"
                + str(ticket["repository_generation"])
                + ":"
                + str(ticket["attempt_id"])
                + ":"
                + str(ticket["generation"])
                + ":"
                + str(ticket["ticket_id"]),
            )
        )

    @staticmethod
    def _expected_launch_result(ticket: Mapping[str, object]) -> dict[str, str]:
        attempt_id = str(ticket["attempt_id"])
        ticket_id = str(ticket["ticket_id"])
        return {
            "runtime_id": "devcoordinator-test-"
            + hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:32],
            "launch_ack_id": "test-launch-"
            + ticket_id.removeprefix("test-ticket-"),
        }

    @staticmethod
    def _expected_context_launch_result(
        context: _RuntimeContext,
    ) -> dict[str, str]:
        if context.launch_ticket_id is None:
            raise TestStoreContractError("pending broker launch ticket is missing")
        return {
            "runtime_id": "devcoordinator-test-"
            + hashlib.sha256(context.attempt_id.encode("utf-8")).hexdigest()[:32],
            "launch_ack_id": "test-launch-"
            + context.launch_ticket_id.removeprefix("test-ticket-"),
        }

    @classmethod
    def _launch_handle(cls, context: _RuntimeContext) -> dict[str, object]:
        return {
            **cls._expected_context_launch_result(context),
            "launch_ticket_id": context.launch_ticket_id,
            "launch_operation_id": context.launch_operation_id,
            "launch_timeout_seconds": context.launch_timeout_seconds,
            "launch_confirmed": context.launch_confirmed,
        }

    @staticmethod
    def _deadline_cancel_operation_id(context: _RuntimeContext) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-launch-deadline-cancel:"
                + context.attempt_id
                + ":"
                + str(context.generation),
            )
        )

    @staticmethod
    def _cancel_operation_id(context: _RuntimeContext, *, reason: str) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-cancel:"
                + context.repository_id
                + ":"
                + str(context.repository_generation)
                + ":"
                + context.attempt_id
                + ":"
                + str(context.generation)
                + ":"
                + hashlib.sha256(reason.encode("utf-8")).hexdigest(),
            )
        )

    @staticmethod
    def _validated_cancel_result(
        result: Mapping[str, object], *, runtime_id: str
    ) -> dict[str, object]:
        if (
            not isinstance(result, Mapping)
            or set(result) != {"runtime_id", "cancelled", "absent"}
            or result.get("runtime_id") != runtime_id
            or type(result.get("cancelled")) is not bool
            or type(result.get("absent")) is not bool
            or (result.get("absent") is True and result.get("cancelled") is not True)
        ):
            raise TestStoreContractError(
                "broker runtime cancellation result is invalid"
            )
        return dict(result)

    def _request_cancel(
        self,
        *,
        runtime_id: str,
        context: _RuntimeContext,
        reason: str,
        operation_id: str,
    ) -> dict[str, object] | None:
        for _attempt in range(2):
            try:
                result = self.calls.call(
                    repository_id=context.repository_id,
                    repository_generation=context.repository_generation,
                    resource_id=context.attempt_id,
                    operation=BrokerOperation.TEST_ATTEMPT_CANCEL,
                    arguments={"runtime_id": runtime_id, "reason": reason},
                    operation_id=operation_id,
                    timeout_seconds=context.launch_request_timeout_seconds,
                )
                return self._validated_cancel_result(
                    result, runtime_id=runtime_id
                )
            except BrokerError as error:
                if error.code != "request_timeout":
                    raise
        # Both bounded replies were lost. The same deterministic operation is
        # retried on the next supervision pass; do not claim cancellation or
        # terminalize a potentially active runtime while its outcome is unknown.
        return None

    def _launch_rpc_timeout(
        self, context: _RuntimeContext, *, attempts_remaining: int
    ) -> float | None:
        remaining = (
            context.started_at
            + context.launch_timeout_seconds
            - float(self.clock())
        )
        if remaining <= 0:
            return None
        # Reserve an equal share of the caller's remaining launch deadline for
        # each exact replay. A separately configured transport cap may shorten
        # a single wait, but never extends the caller's semantic deadline.
        timeout = remaining / attempts_remaining
        timeout = min(timeout, context.launch_request_timeout_seconds)
        return max(0.001, timeout)

    def _request_launch(
        self,
        *,
        context: _RuntimeContext,
    ) -> Mapping[str, object] | None:
        if context.launch_ticket_id is None or context.launch_operation_id is None:
            raise TestStoreContractError("pending broker launch identity is incomplete")
        arguments = {
            "ticket_id": context.launch_ticket_id,
            "attempt_id": context.attempt_id,
            "generation": context.generation,
        }
        # A timeout means the broker may still have committed the launch. Replay
        # the exact idempotency identity once immediately; if that reply is also
        # lost, retain a pending runtime and reconcile it from observe().
        for attempt_index in range(2):
            timeout_seconds = self._launch_rpc_timeout(
                context, attempts_remaining=2 - attempt_index
            )
            if timeout_seconds is None:
                return None
            try:
                return self.calls.call(
                    repository_id=context.repository_id,
                    repository_generation=context.repository_generation,
                    resource_id=context.attempt_id,
                    operation=BrokerOperation.TEST_ATTEMPT_LAUNCH,
                    arguments=arguments,
                    operation_id=context.launch_operation_id,
                    timeout_seconds=timeout_seconds,
                )
            except BrokerError as error:
                if error.code not in {
                    "request_timeout",
                    "test_attempt_launch_uncertain",
                }:
                    raise
        return None

    def _deadline_cleanup_proven(
        self, *, runtime_id: str, context: _RuntimeContext
    ) -> bool:
        operation_id = self._deadline_cancel_operation_id(context)
        try:
            result = self._request_cancel(
                runtime_id=runtime_id,
                context=context,
                reason="test launch deadline exceeded",
                operation_id=operation_id,
            )
        except (BrokerError, TestStoreConflict, TestStoreContractError):
            # A generic broker/contract error cannot distinguish an absent
            # runtime from an active runtime whose launch evidence is damaged.
            # Keep the attempt pending until an exact typed cleanup result is
            # observed.
            return False
        if result is None:
            return False
        context.cancelled = bool(result["cancelled"])
        return context.cancelled

    def _launch_failure_observation(
        self, *, context: _RuntimeContext, code: str, message: str
    ) -> Mapping[str, object]:
        code = code if code else "launch_failed"
        message = message if message else "The test runtime could not be launched."
        chunk_id = "chunk-launch-failure-" + hashlib.sha256(
            (
                context.attempt_id
                + "\0"
                + str(context.generation)
                + "\0"
                + code
            ).encode("utf-8")
        ).hexdigest()[:32]
        if context.next_chunk_index == 0:
            context.launch_failure_code = code
            context.launch_failure_message = message
            context.result_chunk_ids.append(chunk_id)
            context.next_chunk_index = 1
            return {
                "state": "result",
                "exit_envelope": None,
                "result_chunk": {
                    "chunk_id": chunk_id,
                    "chunk_index": 0,
                    "cases": [],
                    "failures": [
                        {
                            "failure_id": "failure-launch-"
                            + hashlib.sha256(
                                (context.attempt_id + "\0" + code).encode("utf-8")
                            ).hexdigest()[:32],
                            "classification": "infrastructure_failure",
                            "message": f"Test launch failed ({code}): {message}"[:8192],
                            "case_id": None,
                            "location": "launch",
                            "artifact_id": None,
                        }
                    ],
                    "artifacts": [],
                    "reporter_complete": True,
                },
                "current_memory_bytes": None,
                "launch_confirmed": False,
            }
        if context.result_chunk_ids != [chunk_id] or context.next_chunk_index != 1:
            raise TestStoreConflict("launch failure result identity is contradictory")
        conclusion = AttemptConclusion.INFRASTRUCTURE_FAILED
        duration = max(0.0, float(self.clock()) - context.started_at)
        envelope = AttemptExitEnvelope(
            envelope_id="exit-" + hashlib.sha256(
                (
                    context.attempt_id
                    + "\0"
                    + str(context.generation)
                    + "\0launch-failure\0"
                    + code
                ).encode("utf-8")
            ).hexdigest()[:32],
            attempt_id=context.attempt_id,
            generation=context.generation,
            operation_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "devcoordinator-test-launch-failure-exit:"
                    + context.attempt_id
                    + ":"
                    + str(context.generation)
                    + ":"
                    + code,
                )
            ),
            conclusion=conclusion,
            duration_seconds=duration,
            result_chunk_ids=(chunk_id,),
        )
        return {
            "state": "exited",
            "exit_envelope": envelope.to_document(),
            "result_chunk": None,
            "current_memory_bytes": None,
            "launch_confirmed": False,
        }

    @staticmethod
    def _bounded_termination_text(value: object, *, maximum: int = 512) -> str:
        """Keep native-manager detail useful without admitting an unbounded row."""

        normalized = " ".join(str(value).split())
        return (normalized or "unknown")[:maximum]

    def _native_exit_without_result_observation(
        self,
        *,
        context: _RuntimeContext,
        exit_status: int,
        termination: Mapping[str, object],
        duration_seconds: float,
        peak_memory_bytes: int | None,
        cpu_seconds: float | None,
    ) -> Mapping[str, object]:
        """Stream one actionable failure before terminalizing a lost runner result."""

        reason = self._bounded_termination_text(termination["reason"])
        systemd_result = self._bounded_termination_text(
            termination["systemd_result"]
        )
        exec_main_code = int(termination["exec_main_code"])
        oom_killed = bool(termination["oom_killed"])
        identity = (
            context.attempt_id
            + "\0"
            + str(context.generation)
            + "\0native-exit-without-result\0"
            + str(exit_status)
            + "\0"
            + reason
            + "\0"
            + systemd_result
            + "\0"
            + str(exec_main_code)
            + "\0"
            + str(oom_killed).lower()
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        chunk_id = "chunk-native-exit-failure-" + digest
        failure_id = "failure-native-exit-" + digest
        message = (
            "Native test runner exited without publishing a result document "
            f"(exit_status={exit_status}; reason={reason}; "
            f"systemd_result={systemd_result}; exec_main_code={exec_main_code}; "
            f"oom_killed={str(oom_killed).lower()})."
        )[:8192]

        if context.next_chunk_index == 0:
            context.result_chunk_ids.append(chunk_id)
            context.next_chunk_index = 1
            context.terminal_duration_seconds = duration_seconds
            return {
                "state": "result",
                "exit_envelope": None,
                "result_chunk": {
                    "chunk_id": chunk_id,
                    "chunk_index": 0,
                    "cases": [],
                    "failures": [
                        {
                            "failure_id": failure_id,
                            "classification": "infrastructure_failure",
                            "message": message,
                            "case_id": None,
                            "location": "runner",
                            "artifact_id": None,
                        }
                    ],
                    "artifacts": [],
                    "reporter_complete": True,
                },
                "current_memory_bytes": None,
                "launch_confirmed": True,
            }
        if context.result_chunk_ids != [chunk_id] or context.next_chunk_index != 1:
            raise TestStoreConflict(
                "native exit failure result identity is contradictory"
            )

        duration = (
            duration_seconds
            if context.terminal_duration_seconds is None
            else context.terminal_duration_seconds
        )
        context.terminal_duration_seconds = duration
        conclusion = AttemptConclusion.INFRASTRUCTURE_FAILED
        envelope = AttemptExitEnvelope(
            envelope_id="exit-"
            + hashlib.sha256(
                (
                    identity
                    + "\0"
                    + conclusion.value
                    + "\0"
                    + chunk_id
                ).encode("utf-8")
            ).hexdigest()[:32],
            attempt_id=context.attempt_id,
            generation=context.generation,
            operation_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "devcoordinator-test-native-exit-without-result:"
                    + digest,
                )
            ),
            conclusion=conclusion,
            duration_seconds=duration,
            result_chunk_ids=(chunk_id,),
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=cpu_seconds,
        )
        return {
            "state": "exited",
            "exit_envelope": envelope.to_document(),
            "result_chunk": None,
            "current_memory_bytes": None,
            "launch_confirmed": True,
        }

    def prepare(self, document: Mapping[str, object]) -> Mapping[str, object]:
        """Retain one deterministic launch identity without making an RPC.

        Testd fsyncs the returned handle before calling ``launch_prepared``.
        Re-preparing the same attempt reuses the original semantic deadline;
        it never turns a restart or replay into a fresh launch allowance.
        """

        ticket = document.get("ticket")
        if not isinstance(ticket, Mapping):
            raise TestStoreContractError("runtime request ticket is invalid")
        required = {
            "ticket_id",
            "attempt_id",
            "repository_id",
            "repository_generation",
            "generation",
        }
        if not required <= set(ticket):
            raise TestStoreContractError("runtime request ticket identity is incomplete")
        lifecycle = document.get("lifecycle")
        launch_timeout_seconds = (
            300
            if not isinstance(lifecycle, Mapping)
            else lifecycle.get("launch_timeout_seconds", 300)
        )
        if (
            type(launch_timeout_seconds) is not int
            or not 1 <= launch_timeout_seconds <= 3_600
        ):
            raise TestStoreContractError("runtime launch timeout is invalid")
        expected = self._expected_launch_result(ticket)
        candidate = _RuntimeContext(
            repository_id=str(ticket["repository_id"]),
            repository_generation=int(ticket["repository_generation"]),
            attempt_id=str(ticket["attempt_id"]),
            generation=int(ticket["generation"]),
            started_at=float(self.clock()),
            launch_ticket_id=str(ticket["ticket_id"]),
            launch_operation_id=self._launch_operation_id(ticket),
            launch_timeout_seconds=launch_timeout_seconds,
            launch_request_timeout_seconds=self.launch_request_timeout_seconds,
            launch_confirmed=False,
        )
        existing = self._runtimes.get(expected["runtime_id"])
        if existing is not None:
            # Deliberately exclude started_at and mutable observation state.
            # A replay must bind the same static request while retaining the
            # first caller-owned deadline and any already-observed outcome.
            static_fields = (
                "repository_id",
                "repository_generation",
                "attempt_id",
                "generation",
                "launch_ticket_id",
                "launch_operation_id",
                "launch_timeout_seconds",
                "launch_request_timeout_seconds",
            )
            if any(
                getattr(existing, field_name) != getattr(candidate, field_name)
                for field_name in static_fields
            ):
                raise TestStoreConflict("prepared runtime launch identity conflicts")
            return self._launch_handle(existing)
        self._runtimes[expected["runtime_id"]] = candidate
        return self._launch_handle(candidate)

    def launch_prepared(self, runtime_id: str) -> Mapping[str, object]:
        """Launch or reconcile only a previously retained exact identity."""

        context = self._runtimes.get(runtime_id)
        if context is None:
            raise TestStoreConflict("runtime is not owned by this testd generation")
        expected = self._expected_context_launch_result(context)
        if expected["runtime_id"] != runtime_id:
            raise TestStoreConflict("prepared runtime identity is contradictory")
        if context.launch_confirmed or context.launch_failure_code is not None:
            return self._launch_handle(context)
        try:
            result = self._request_launch(context=context)
        except BrokerError as error:
            # Return the deterministic pending handle so Testd can durably
            # publish a structured launch-stage infrastructure diagnostic.
            context.launch_failure_code = error.code
            context.launch_failure_message = error.message
            return self._launch_handle(context)
        if result is None:
            # Both calls lost their replies. The Coordinator runtime and launch
            # acknowledgement are deterministic, so persisting this handle is
            # safer than falsely terminalizing a process which may be running.
            return self._launch_handle(context)
        if set(result) != {"runtime_id", "launch_ack_id"}:
            raise TestStoreContractError("broker runtime launch result is invalid")
        if dict(result) != expected:
            raise TestStoreConflict("broker runtime launch identity is contradictory")
        context.launch_confirmed = True
        return self._launch_handle(context)

    def submit(self, document: Mapping[str, object]) -> Mapping[str, object]:
        """Compatibility wrapper for callers that do not own a durable spool."""

        prepared = self.prepare(document)
        return self.launch_prepared(str(prepared["runtime_id"]))

    def observe(self, runtime_id: str) -> Mapping[str, object]:
        context = self._runtimes.get(runtime_id)
        if context is None:
            raise TestStoreConflict("runtime is not owned by this testd generation")
        if context.launch_failure_code is not None:
            return self._launch_failure_observation(
                context=context,
                code=context.launch_failure_code,
                message=context.launch_failure_message
                or "The test runtime could not be launched.",
            )
        if not context.launch_confirmed:
            try:
                launch = self._request_launch(context=context)
            except BrokerError as error:
                context.launch_failure_code = error.code
                context.launch_failure_message = error.message
                return self._launch_failure_observation(
                    context=context, code=error.code, message=error.message
                )
            if launch is None:
                deadline_exceeded = float(self.clock()) >= (
                    context.started_at + context.launch_timeout_seconds
                )
                if deadline_exceeded and self._deadline_cleanup_proven(
                    runtime_id=runtime_id, context=context
                ):
                    code = "launch_deadline_exceeded"
                    message = (
                        "The caller's "
                        f"{context.launch_timeout_seconds}s launch deadline expired; "
                        "the Coordinator confirmed no active runtime remained."
                    )
                    context.launch_failure_code = code
                    context.launch_failure_message = message
                    return self._launch_failure_observation(
                        context=context, code=code, message=message
                    )
                return {
                    "state": "running",
                    "exit_envelope": None,
                    "result_chunk": None,
                    "current_memory_bytes": None,
                    "launch_confirmed": False,
                }
            expected = self._expected_context_launch_result(context)
            if dict(launch) != expected:
                raise TestStoreConflict("replayed broker launch identity is contradictory")
            if float(self.clock()) >= (
                context.started_at + context.launch_timeout_seconds
            ):
                if not self._deadline_cleanup_proven(
                    runtime_id=runtime_id, context=context
                ):
                    return {
                        "state": "running",
                        "exit_envelope": None,
                        "result_chunk": None,
                        "current_memory_bytes": None,
                        "launch_confirmed": False,
                    }
                code = "launch_deadline_exceeded"
                message = (
                    "The caller's "
                    f"{context.launch_timeout_seconds}s launch deadline expired; "
                    "the Coordinator stopped the late runtime and confirmed cleanup."
                )
                context.launch_failure_code = code
                context.launch_failure_message = message
                return self._launch_failure_observation(
                    context=context, code=code, message=message
                )
            context.launch_confirmed = True
        result = self.calls.call(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            resource_id=context.attempt_id,
            operation=BrokerOperation.TEST_ATTEMPT_STATUS,
            arguments={
                "runtime_id": runtime_id,
                "result_chunk_index": context.next_chunk_index,
            },
        )
        if result.get("state") == "running":
            if (
                result.get("result") is not None
                or result.get("result_chunk") is not None
                or result.get("termination") is not None
            ):
                raise TestStoreContractError("running broker runtime returned result evidence")
            current_memory_bytes = _current_memory_usage(
                result.get("resource_usage")
            )
            return {
                "state": "running",
                "exit_envelope": None,
                "result_chunk": None,
                "current_memory_bytes": current_memory_bytes,
                "launch_confirmed": True,
            }
        if result.get("state") != "exited" or type(result.get("exit_status")) is not int:
            raise TestStoreContractError("broker runtime observation is incomplete")
        termination = result.get("termination")
        peak_memory_bytes, cpu_seconds = _terminal_resource_usage(
            result.get("resource_usage")
        )
        if (
            not isinstance(termination, Mapping)
            or set(termination) != {
                "reason", "systemd_result", "exec_main_code", "oom_killed",
            }
            or termination.get("reason") not in {
                "success", "exit_code", "signal", "timeout", "oom_kill",
                "resource_failure", "start_limit", "protocol_failure",
                "systemd_failure",
            }
            or not isinstance(termination.get("systemd_result"), str)
            or type(termination.get("exec_main_code")) is not int
            or type(termination.get("oom_killed")) is not bool
        ):
            raise TestStoreContractError("broker runtime termination evidence is invalid")
        runner_result = result.get("result")
        chunk = result.get("result_chunk")
        duration = max(0.0, float(self.clock()) - context.started_at)
        if runner_result is None:
            if chunk is not None:
                raise TestStoreContractError("broker returned an orphan result chunk")
            conclusion = (
                AttemptConclusion.CANCELLED
                if context.cancelled
                else AttemptConclusion.TIMED_OUT
                if termination["reason"] == "timeout"
                else AttemptConclusion.INFRASTRUCTURE_FAILED
            )
            if conclusion == AttemptConclusion.INFRASTRUCTURE_FAILED:
                return self._native_exit_without_result_observation(
                    context=context,
                    exit_status=int(result["exit_status"]),
                    termination=termination,
                    duration_seconds=duration,
                    peak_memory_bytes=peak_memory_bytes,
                    cpu_seconds=cpu_seconds,
                )
        else:
            expected = {
                "schema_version", "attempt_id", "generation", "returncode",
                "duration_seconds", "incomplete_reporting", "terminal_outcome",
                "captures", "chunk_count",
            }
            if not isinstance(runner_result, Mapping) or set(runner_result) != expected:
                raise TestStoreContractError("broker runner result fields are invalid")
            if (
                runner_result["schema_version"] != 3
                or runner_result["attempt_id"] != context.attempt_id
                or runner_result["generation"] != context.generation
                or type(runner_result["returncode"]) is not int
                or type(runner_result["incomplete_reporting"]) is not bool
                or runner_result["terminal_outcome"] not in {
                    "succeeded",
                    "test_failed",
                    "infrastructure_failed",
                    "timed_out",
                    "incomplete",
                }
                or type(runner_result["chunk_count"]) is not int
                or not 1 <= runner_result["chunk_count"] <= 4_096
            ):
                raise TestStoreConflict("broker runner result identity is stale or invalid")
            try:
                reported_duration = float(runner_result["duration_seconds"])
            except (TypeError, ValueError) as error:
                raise TestStoreContractError("broker runner duration is invalid") from error
            if reported_duration < 0:
                raise TestStoreContractError("broker runner duration is invalid")
            duration = reported_duration
            chunk_count = int(runner_result["chunk_count"])
            if context.next_chunk_index < chunk_count:
                if not isinstance(chunk, Mapping):
                    raise TestStoreContractError("broker omitted the requested result chunk")
                if chunk.get("chunk_index") != context.next_chunk_index:
                    raise TestStoreConflict("broker result chunk ordering is invalid")
                chunk_id = chunk.get("chunk_id")
                if not isinstance(chunk_id, str) or chunk_id in context.result_chunk_ids:
                    raise TestStoreConflict("broker result chunk identity is invalid")
                context.result_chunk_ids.append(chunk_id)
                context.next_chunk_index += 1
                return {
                    "state": "result",
                    "exit_envelope": None,
                    "result_chunk": dict(chunk),
                    "current_memory_bytes": None,
                    "launch_confirmed": True,
                }
            if chunk is not None or context.next_chunk_index != chunk_count:
                raise TestStoreConflict("broker result chunk stream is contradictory")
            if context.cancelled:
                conclusion = AttemptConclusion.CANCELLED
            else:
                conclusion = AttemptConclusion(
                    str(runner_result["terminal_outcome"])
                )
        envelope = AttemptExitEnvelope(
            envelope_id="exit-" + hashlib.sha256(
                (
                    context.attempt_id
                    + "\0"
                    + str(context.generation)
                    + "\0"
                    + conclusion.value
                    + "\0"
                    + ",".join(context.result_chunk_ids)
                ).encode("utf-8")
            ).hexdigest()[:32],
            attempt_id=context.attempt_id,
            generation=context.generation,
            operation_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "devcoordinator-test-exit:"
                    + context.attempt_id
                    + ":"
                    + str(context.generation)
                    + ":"
                    + conclusion.value
                    + ":"
                    + ",".join(context.result_chunk_ids),
                )
            ),
            conclusion=conclusion,
            duration_seconds=duration,
            result_chunk_ids=tuple(context.result_chunk_ids),
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=cpu_seconds,
        )
        return {
            "state": "exited",
            "exit_envelope": envelope.to_document(),
            "result_chunk": chunk,
            "current_memory_bytes": None,
            "launch_confirmed": True,
        }

    def recover(
        self, runtime_id: str, *, context: RunnerRecoveryContext
    ) -> None:
        if not isinstance(context, RunnerRecoveryContext):
            raise TestStoreContractError("runtime recovery context is invalid")
        if (
            context.repository_generation < 0
            or context.generation <= 0
            or context.next_chunk_index != len(context.result_chunk_ids)
            or len(set(context.result_chunk_ids)) != len(context.result_chunk_ids)
            or type(context.launch_timeout_seconds) is not int
            or not 1 <= context.launch_timeout_seconds <= 3_600
            or type(context.launch_confirmed) is not bool
            or (
                not context.launch_confirmed
                and (
                    context.launch_ticket_id is None
                    or context.launch_operation_id is None
                )
            )
        ):
            raise TestStoreContractError("runtime recovery context is invalid")
        expected_runtime_id = "devcoordinator-test-" + hashlib.sha256(
            context.attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        if runtime_id != expected_runtime_id:
            raise TestStoreConflict("runtime recovery identity is contradictory")
        if context.launch_ticket_id is not None:
            expected_operation_id = self._launch_operation_id(
                {
                    "repository_id": context.repository_id,
                    "repository_generation": context.repository_generation,
                    "attempt_id": context.attempt_id,
                    "generation": context.generation,
                    "ticket_id": context.launch_ticket_id,
                }
            )
            if context.launch_operation_id != expected_operation_id:
                raise TestStoreConflict(
                    "runtime recovery launch operation is contradictory"
                )
        recovered = _RuntimeContext(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            attempt_id=context.attempt_id,
            generation=context.generation,
            started_at=context.started_at,
            launch_ticket_id=context.launch_ticket_id,
            launch_operation_id=context.launch_operation_id,
            launch_timeout_seconds=context.launch_timeout_seconds,
            launch_request_timeout_seconds=self.launch_request_timeout_seconds,
            launch_confirmed=context.launch_confirmed,
            next_chunk_index=context.next_chunk_index,
            result_chunk_ids=list(context.result_chunk_ids),
        )
        existing = self._runtimes.get(runtime_id)
        if existing is not None and existing != recovered:
            raise TestStoreConflict("runtime recovery context conflicts")
        self._runtimes[runtime_id] = recovered

    def cancel(self, runtime_id: str, *, reason: str) -> Mapping[str, object]:
        context = self._runtimes.get(runtime_id)
        if context is None:
            raise TestStoreConflict("runtime is not owned by this testd generation")
        if (
            not isinstance(reason, str)
            or not reason
            or len(reason.encode("utf-8")) > 1_024
            or any(character in reason for character in "\x00\r\n")
        ):
            raise TestStoreContractError("runtime cancellation reason is invalid")
        result = self._request_cancel(
            runtime_id=runtime_id,
            context=context,
            reason=reason,
            operation_id=self._cancel_operation_id(context, reason=reason),
        )
        if result is None:
            return {"cancelled": False}
        context.cancelled = bool(result["cancelled"])
        return {"cancelled": context.cancelled}


__all__ = [
    "BrokerConnection",
    "CoordinatorBrokerTicketIssuer",
    "CoordinatorRuntimeRequestSubmitter",
    "RepositoryLaunchDescriptorResolver",
    "SYSTEM_AUTHORITY_SOCKET_GID",
    "SYSTEM_AUTHORITY_SOCKET_MODE",
    "SYSTEM_AUTHORITY_SOCKET_UID",
]
