"""Unix-peer-attributed testd-to-broker adapters for governed executions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import time
from pathlib import Path
from typing import Callable, Mapping, Protocol, runtime_checkable
import uuid

from .broker import BrokerClient, BrokerError, BrokerOperation, BrokerRequest
from .call_journal import RollingCallJournal, event_record
from .universal_test_service import decode_test_plan_document
from .universal_test_result_package import (
    ResultPackageError,
    iter_result_package_records,
    validate_result_package,
)
from .universal_test_store import (
    ExecutionGrant,
    RunnableTarget,
    TestStoreConflict,
    TestStoreContractError,
)
from .universal_testd import (
    BrokerLaunchTicket,
    BrokerLaunchTicketIssuer,
    RuntimeRequestSubmitter,
)


# One broker call is only a polling slice inside the caller-owned launch
# deadline.  Snapshot materialization and systemd activation can legitimately
# outlive this slice; the deterministic operation identity is replayed until
# the semantic deadline expires.  Keeping the transport slice software-owned
# prevents one slow launch from blocking the testd supervision loop for the
# caller's entire (potentially one-hour) launch allowance.
DEFAULT_LAUNCH_RPC_SLICE_SECONDS = 10.0


@runtime_checkable
class RepositoryLaunchDescriptorResolver(Protocol):
    """Resolve one selected manifest target through the repository-UID helper."""

    def resolve_as_owner(
        self,
        *,
        candidate: RunnableTarget,
        execution: ExecutionGrant,
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
            # The public v8 request carries execution_id.  The generic call
            # journal keeps its historical diagnostic storage column name.
            "attempt_id": arguments.get("execution_id"),
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
                    else "Broker test execution request failed.",
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
            raise TestStoreConflict("broker test execution request failed")
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
            raise TestStoreContractError("broker test execution result is invalid")
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
    def _operation_id(candidate: RunnableTarget, execution: ExecutionGrant) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-ticket:"
                + candidate.repository_id
                + ":"
                + execution.execution_id
                + ":"
                + str(execution.generation),
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
        execution: ExecutionGrant,
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
            execution=execution,
            plan_document=plan_document,
            timeout_seconds=self._remaining(deadline),
        )
        if not isinstance(descriptor, Mapping):
            raise TestStoreContractError("repository helper descriptor is invalid")
        operation_id = self._operation_id(candidate, execution)
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
                    resource_id=execution.execution_id,
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
            "execution_id",
            "systemd_unit",
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
            "worktree_key",
            "issued_at",
            "expires_at",
        }
        if (
            set(result) != expected
            or result.get("execution_id") != execution.execution_id
            or result.get("systemd_unit") != execution.systemd_unit
            or result.get("kill_after_run") is not True
        ):
            raise TestStoreContractError("broker launch ticket fields are invalid")
        return BrokerLaunchTicket(
            ticket_id=result["ticket_id"],
            execution_id=result["execution_id"],
            target_id=result["target_id"],
            run_id=result["run_id"],
            repository_id=result["repository_id"],
            repository_generation=result["repository_generation"],
            owner_uid=result["owner_uid"],
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
class _V8RuntimeContext:
    repository_id: str
    repository_generation: int
    execution_id: str
    generation: int
    systemd_unit: str
    launch_operation_id: str
    ticket_id: str | None
    launch_ack_id: str | None = None
    launch_confirmed: bool = False
    storage_handle: str | None = None


class CoordinatorRuntimeRequestSubmitter(RuntimeRequestSubmitter):
    """Submit, observe, and stop executions through broker operations."""

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
        result_package_root: Path = Path("/var/lib/devcoordinator-test-results"),
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
        self.result_package_root = Path(result_package_root).absolute()
        self._v8_runtimes: dict[str, _V8RuntimeContext] = {}

    # This adapter carries only exact routing and native facts. Testd remains
    # the sole execution lifecycle and conclusion authority.

    @staticmethod
    def _v8_handle(context: _V8RuntimeContext) -> dict[str, object]:
        return {
            "execution_id": context.execution_id,
            "generation": context.generation,
            "systemd_unit": context.systemd_unit,
            "launch_operation_id": context.launch_operation_id,
            "launch_ack_id": context.launch_ack_id,
            "launch_confirmed": context.launch_confirmed,
        }

    def _v8_context(self, systemd_unit: str) -> _V8RuntimeContext:
        context = self._v8_runtimes.get(systemd_unit)
        if context is None:
            raise TestStoreConflict("test execution routing context is unavailable")
        return context

    def prepare(self, document: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(document, Mapping) or document.get("schema_version") != 2:
            raise TestStoreContractError("runtime request schema is invalid")
        ticket = document.get("ticket")
        execution = document.get("execution")
        if not isinstance(ticket, Mapping) or not isinstance(execution, Mapping):
            raise TestStoreContractError("runtime request identity is incomplete")
        required_execution = {
            "execution_id",
            "generation",
            "systemd_unit",
            "launch_operation_id",
            "descriptor_fingerprint",
        }
        if set(execution) != required_execution:
            raise TestStoreContractError("runtime execution fields are invalid")
        execution_id = str(execution["execution_id"])
        systemd_unit = str(execution["systemd_unit"])
        expected_unit = (
            "devcoordinator-test-"
            + hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:32]
            + ".service"
        )
        if systemd_unit != expected_unit:
            raise TestStoreConflict("runtime systemd unit identity is contradictory")
        try:
            launch_operation_id = str(uuid.UUID(str(execution["launch_operation_id"])))
        except (TypeError, ValueError, AttributeError) as error:
            raise TestStoreContractError("runtime launch operation is invalid") from error
        context = _V8RuntimeContext(
            repository_id=str(ticket.get("repository_id")),
            repository_generation=int(ticket.get("repository_generation", -1)),
            execution_id=execution_id,
            generation=int(execution.get("generation", 0)),
            systemd_unit=systemd_unit,
            launch_operation_id=launch_operation_id,
            ticket_id=str(ticket.get("ticket_id")),
        )
        if context.repository_generation < 0 or context.generation != 1:
            raise TestStoreContractError("runtime generation is invalid")
        existing = self._v8_runtimes.get(systemd_unit)
        if existing is not None and existing != context:
            raise TestStoreConflict("prepared runtime identity conflicts")
        self._v8_runtimes[systemd_unit] = context
        return self._v8_handle(context)

    def start_prepared(self, systemd_unit: str) -> Mapping[str, object]:
        context = self._v8_context(systemd_unit)
        if context.launch_confirmed:
            return self._v8_handle(context)
        result = self.calls.call(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            resource_id=context.execution_id,
            operation=BrokerOperation.TEST_ATTEMPT_LAUNCH,
            arguments={
                "ticket_id": context.ticket_id,
                "execution_id": context.execution_id,
                "generation": context.generation,
                "systemd_unit": context.systemd_unit,
            },
            operation_id=context.launch_operation_id,
            timeout_seconds=self.launch_request_timeout_seconds,
        )
        if (
            set(result)
            != {"execution_id", "generation", "systemd_unit", "launch_ack_id"}
            or result.get("execution_id") != context.execution_id
            or result.get("generation") != context.generation
            or result.get("systemd_unit") != context.systemd_unit
            or not isinstance(result.get("launch_ack_id"), str)
        ):
            raise TestStoreConflict("broker launch result is contradictory")
        context.launch_ack_id = str(result["launch_ack_id"])
        context.launch_confirmed = True
        return self._v8_handle(context)

    @staticmethod
    def _v8_package_projection(raw: object) -> tuple[dict[str, object] | None, str | None]:
        if raw is None:
            return None, None
        if not isinstance(raw, Mapping):
            raise TestStoreContractError("broker result package metadata is invalid")
        required = {
            "schema_version",
            "package_id",
            "storage_handle",
            "sha256",
            "size_bytes",
            "manifest_sha256",
            "identity",
            "manifest",
            "outcome",
            "counts",
        }
        if set(raw) != required:
            raise TestStoreContractError("broker result package metadata is invalid")
        counts = raw["counts"]
        outcome = raw["outcome"]
        manifest = raw["manifest"]
        if not isinstance(counts, Mapping) or not isinstance(outcome, Mapping) or not isinstance(manifest, Mapping):
            raise TestStoreContractError("broker result package metadata is invalid")
        reporter_complete = outcome.get("reporter_complete")
        if type(reporter_complete) is not bool:
            raise TestStoreContractError("broker result package completeness is invalid")
        projected_manifest = dict(manifest)
        projected_manifest["reporter_complete"] = reporter_complete
        projected_counts = {
            "passed": counts.get("passed", 0),
            "failed": counts.get("failed", 0),
            "skipped": counts.get("skipped", 0),
            "error": counts.get("errors", counts.get("error", 0)),
            "failures": counts.get("failures", 0),
            "artifacts": counts.get("artifacts", 0),
        }
        if any(type(value) is not int or value < 0 for value in projected_counts.values()):
            raise TestStoreContractError("broker result package counts are invalid")
        return (
            {
                "package_id": raw["package_id"],
                "sha256": raw["sha256"],
                "size_bytes": raw["size_bytes"],
                "manifest": projected_manifest,
                "outcome": dict(outcome),
                "counts": projected_counts,
            },
            str(raw["storage_handle"]),
        )

    def observe(self, systemd_unit: str) -> Mapping[str, object]:
        context = self._v8_context(systemd_unit)
        result = self.calls.call(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            resource_id=context.execution_id,
            operation=BrokerOperation.TEST_ATTEMPT_STATUS,
            arguments={
                "execution_id": context.execution_id,
                "generation": context.generation,
                "systemd_unit": context.systemd_unit,
            },
        )
        expected = {
            "execution_id",
            "generation",
            "repository_id",
            "repository_generation",
            "systemd_unit",
            "systemd_invocation_id",
            "state",
            "unit_inactive",
            "cgroup_empty",
            "launch_confirmed",
            "started_at",
            "finished_at",
            "result_package",
            "exit",
            "resource_usage",
            "progress",
        }
        if (
            set(result) != expected
            or result.get("execution_id") != context.execution_id
            or result.get("generation") != context.generation
            or result.get("repository_id") != context.repository_id
            or result.get("repository_generation") != context.repository_generation
            or result.get("systemd_unit") != context.systemd_unit
        ):
            raise TestStoreConflict("broker runtime observation binding is contradictory")
        package, storage_handle = self._v8_package_projection(
            result.get("result_package")
        )
        if storage_handle is not None:
            context.storage_handle = storage_handle
        usage = result.get("resource_usage")
        if not isinstance(usage, Mapping):
            raise TestStoreContractError("broker runtime usage is invalid")
        active = result.get("state") in {"starting", "running"}
        exit_evidence = result.get("exit")
        exit_status = (
            None
            if not isinstance(exit_evidence, Mapping)
            else exit_evidence.get("status")
        )
        return {
            "state": result.get("state"),
            "unit_inactive": result.get("unit_inactive"),
            "cgroup_empty": result.get("cgroup_empty"),
            "launch_confirmed": result.get("launch_confirmed"),
            "started_at": result.get("started_at"),
            "systemd_invocation_id": result.get("systemd_invocation_id"),
            "result_package": package,
            "current_memory_bytes": usage.get("current_memory_bytes") if active else None,
            "output_progress": result.get("progress") if active else None,
            "peak_memory_bytes": None if active else usage.get("peak_memory_bytes"),
            "cpu_seconds": None if active else usage.get("cpu_seconds"),
            "exit_status": exit_status,
        }

    def attach(self, binding: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(binding, Mapping):
            raise TestStoreContractError("restart execution binding is invalid")
        context = _V8RuntimeContext(
            repository_id=str(binding["repository_id"]),
            repository_generation=int(binding["repository_generation"]),
            execution_id=str(binding["execution_id"]),
            generation=int(binding["generation"]),
            systemd_unit=str(binding["systemd_unit"]),
            launch_operation_id=str(binding["launch_operation_id"]),
            ticket_id=None,
            launch_ack_id=(
                None if binding.get("launch_ack_id") is None else str(binding["launch_ack_id"])
            ),
            launch_confirmed=binding.get("state") != "starting",
        )
        expected_unit = (
            "devcoordinator-test-"
            + hashlib.sha256(context.execution_id.encode("utf-8")).hexdigest()[:32]
            + ".service"
        )
        if context.systemd_unit != expected_unit or context.generation != 1:
            raise TestStoreConflict("restart execution binding is contradictory")
        self._v8_runtimes[context.systemd_unit] = context
        return self._v8_handle(context)

    def stop(self, systemd_unit: str, *, reason: str) -> Mapping[str, object]:
        context = self._v8_context(systemd_unit)
        if not isinstance(reason, str) or not reason or len(reason.encode("utf-8")) > 1024:
            raise TestStoreContractError("runtime stop reason is invalid")
        operation_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-stop:"
                + context.execution_id
                + ":"
                + hashlib.sha256(reason.encode("utf-8")).hexdigest(),
            )
        )
        result = self.calls.call(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            resource_id=context.execution_id,
            operation=BrokerOperation.TEST_ATTEMPT_CANCEL,
            arguments={
                "execution_id": context.execution_id,
                "generation": context.generation,
                "systemd_unit": context.systemd_unit,
                "reason": reason,
            },
            operation_id=operation_id,
            timeout_seconds=self.launch_request_timeout_seconds,
        )
        if (
            set(result)
            != {
                "execution_id",
                "generation",
                "systemd_unit",
                "cancelled",
                "absent",
            }
            or result.get("execution_id") != context.execution_id
            or result.get("generation") != context.generation
            or result.get("systemd_unit") != context.systemd_unit
            or type(result.get("cancelled")) is not bool
            or type(result.get("absent")) is not bool
        ):
            raise TestStoreConflict("broker stop result is contradictory")
        return self.observe(systemd_unit)

    def resolve_package(
        self, systemd_unit: str, metadata: Mapping[str, object]
    ) -> Mapping[str, object]:
        context = self._v8_context(systemd_unit)
        if not isinstance(metadata, Mapping):
            raise TestStoreContractError("result package metadata is invalid")
        package_id = str(metadata.get("package_id"))
        digest = str(metadata.get("sha256"))
        if context.storage_handle != f"test-result-package://{package_id}/{digest}":
            raise TestStoreConflict("result package storage binding changed")
        path = self.result_package_root / f"{package_id}-{digest}.tar"
        try:
            package = validate_result_package(path, expected_sha256=digest)
            cases = [dict(item) for item in iter_result_package_records(package, "cases")]
            failures = [
                dict(item) for item in iter_result_package_records(package, "failures")
            ]
        except ResultPackageError as error:
            raise TestStoreConflict("verified result package is unavailable") from error
        artifacts: list[dict[str, object]] = []
        for raw in package.manifest["artifacts"]:
            if not isinstance(raw, Mapping):
                raise TestStoreContractError("result package artifact metadata is invalid")
            artifacts.append(
                {
                    "artifact_id": raw["artifact_id"],
                    "kind": raw["kind"],
                    "storage_handle": raw["storage_handle"],
                    "sha256": raw["sha256"],
                    "size_bytes": raw["size_bytes"],
                    "verified": raw["verified"],
                }
            )
        return {
            "package_id": package.evidence.package_id,
            "cases": cases,
            "failures": failures,
            "artifacts": artifacts,
            "reporter_complete": bool(package.manifest["outcome"]["reporter_complete"]),
        }

    def collect(self, systemd_unit: str) -> Mapping[str, object]:
        context = self._v8_context(systemd_unit)
        operation_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-collect:"
                + context.execution_id
                + ":"
                + str(context.generation),
            )
        )
        result = self.calls.call(
            repository_id=context.repository_id,
            repository_generation=context.repository_generation,
            resource_id=context.execution_id,
            operation=BrokerOperation.TEST_ATTEMPT_COLLECT,
            arguments={
                "execution_id": context.execution_id,
                "generation": context.generation,
                "systemd_unit": context.systemd_unit,
            },
            operation_id=operation_id,
            timeout_seconds=self.launch_request_timeout_seconds,
        )
        if (
            set(result)
            != {"execution_id", "generation", "systemd_unit", "collected"}
            or result.get("execution_id") != context.execution_id
            or result.get("generation") != context.generation
            or result.get("systemd_unit") != context.systemd_unit
            or result.get("collected") is not True
        ):
            raise TestStoreContractError("broker runtime collection result is invalid")
        self._v8_runtimes.pop(systemd_unit, None)
        return {"collected": True}


__all__ = [
    "BrokerConnection",
    "CoordinatorBrokerTicketIssuer",
    "CoordinatorRuntimeRequestSubmitter",
    "RepositoryLaunchDescriptorResolver",
]
