"""Bounded execution loop for the isolated asynchronous test scheduler.

The scheduler never invokes systemd, Docker, or a process API directly.  It
leases exact target generations from :mod:`universal_test_store`, asks the
broker for a sealed launch ticket, and passes one normalized request to an
injected launcher.  The production launcher can translate that request into a
Coordinator transient-runtime operation; tests use an in-memory submitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import math
import logging
from pathlib import PurePosixPath
import re
import threading
import time
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable
import uuid

from .universal_test_contract import SourceMode
from .universal_test_scheduler import (
    ActiveAllocation,
    ScheduleDecision,
    WeightedFairScheduler,
)
from .universal_test_service import decode_test_plan_document
from .universal_test_spool import (
    ActiveAttemptEnvelope,
    AttemptExitEnvelope,
    AttemptResultChunkEnvelope,
    DurableAttemptSpool,
)
from .universal_test_store import (
    ArtifactMetadata,
    AttemptConclusion,
    AttemptResultChunk,
    CaseResult,
    FailureClassification,
    FailureRecord,
    LeaseGrant,
    RunnableTarget,
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)


TESTD_RUNNER_SCHEMA_VERSION = 1
MAX_RUNNER_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_LAUNCH_TIMEOUT_SECONDS = 3_600
PENDING_LAUNCH_LEASE_MARGIN_SECONDS = 30
MAX_PENDING_LAUNCH_LEASE_SECONDS = (
    MAX_LAUNCH_TIMEOUT_SECONDS + PENDING_LAUNCH_LEASE_MARGIN_SECONDS
)
MAX_RUNNER_ENVIRONMENT = 128
MAX_RUNNER_ARGV = 256
MAX_RUNNER_ARGV_BYTES = 32 * 1024
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL)(?:_|$)"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "env",
    }
)
_LOGGER = logging.getLogger(__name__)


class LiveSourceChanged(TestStoreConflict):
    """The exact live worktree fingerprint changed after plan creation."""

    def __init__(self, observed_source_fingerprint: str) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", observed_source_fingerprint) is None:
            raise TestStoreContractError("observed live source fingerprint is invalid")
        self.observed_source_fingerprint = observed_source_fingerprint
        super().__init__("live source changed after plan creation")


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _bounded_text(field: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _absolute_path(field: str, value: object) -> str:
    text = _bounded_text(field, value, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != (text.rstrip("/") or "/")
    ):
        raise TestStoreContractError(f"{field} must be one normalized absolute path")
    return str(path)


def _relative_path(field: str, value: object) -> str:
    text = _bounded_text(field, value, maximum=4096)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise TestStoreContractError(f"{field} must be repository-relative")
    normalized = str(path)
    if normalized != text or normalized in {"", "."}:
        if text == ".":
            return "."
        raise TestStoreContractError(f"{field} must be normalized")
    return normalized


def _argv(value: Sequence[object]) -> tuple[str, ...]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or not value
        or len(value) > MAX_RUNNER_ARGV
    ):
        raise TestStoreContractError("runner argv is invalid")
    result = tuple(
        _bounded_text("runner argv item", item, maximum=8192) for item in value
    )
    if sum(len(item.encode("utf-8")) for item in result) > MAX_RUNNER_ARGV_BYTES:
        raise TestStoreContractError("runner argv exceeds its byte bound")
    if PurePosixPath(result[0]).name.lower() in _FORBIDDEN_EXECUTABLES:
        raise TestStoreContractError("runner argv cannot invoke a shell or env trampoline")
    if any(item.startswith("{") and item.endswith("}") for item in result):
        raise TestStoreContractError("runner argv contains an unresolved placeholder")
    return result


def _environment(value: Mapping[object, object]) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > MAX_RUNNER_ENVIRONMENT:
        raise TestStoreContractError("runner environment is invalid")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        if (
            not isinstance(raw_name, str)
            or _ENVIRONMENT_NAME.fullmatch(raw_name) is None
            or _SECRET_ENVIRONMENT_NAME.search(raw_name)
        ):
            raise TestStoreContractError("runner environment name is unsafe")
        result[raw_name] = _bounded_text(
            f"runner environment {raw_name}", raw_value, maximum=4096
        )
    return dict(sorted(result.items()))


def _positive_int(field: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TestStoreContractError(f"{field} must be from 1 through {maximum}")
    return value


def _stable_operation_id(kind: str, *values: object) -> str:
    material = "\0".join((kind, *(str(value) for value in values)))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "devcoordinator-testd:" + material))


@dataclass(frozen=True)
class BrokerLaunchTicket:
    """OS-peer-authorized, generation-fenced launch material.

    This is a bounded descriptor, not a bearer capability.  The broker and
    testd communicate over a Unix socket authenticated by ``SO_PEERCRED``;
    attempt, repository, and generation IDs provide stale-work fencing.
    """

    ticket_id: str
    attempt_id: str = ""
    target_id: str = ""
    run_id: str = ""
    repository_id: str = ""
    repository_generation: int = 0
    owner_uid: int = 0
    generation: int = 0
    root_repo: str = ""
    temporary_repo: str | None = None
    execution_root: str = ""
    argv: tuple[str, ...] = ()
    cwd: str = "."
    environment: Mapping[str, str] = field(default_factory=dict)
    intent: str = "change"
    driver: str = "automation"
    reporter: str = "jsonl"
    artifacts: tuple[Mapping[str, object], ...] = ()
    fixtures: tuple[str, ...] = ()
    credentials: tuple[str, ...] = ()
    network: str = "none"
    ttl_seconds: int = 0
    kill_after_run: bool = True
    cpu_millis: int = 0
    memory_mib: int = 0
    pids: int = 0
    worktree_key: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0

    @classmethod
    def issue(
        cls,
        *,
        ticket_id: str,
        attempt_id: str,
        target_id: str,
        run_id: str,
        repository_id: str,
        owner_uid: int,
        generation: int,
        root_repo: str,
        temporary_repo: str | None,
        argv: Sequence[str],
        cwd: str,
        environment: Mapping[str, str],
        network: str,
        ttl_seconds: int,
        cpu_millis: int,
        memory_mib: int,
        pids: int,
        worktree_key: str,
        issued_at: float,
        expires_at: float,
        repository_generation: int = 0,
        execution_root: str = "",
        intent: str = "change",
        driver: str = "automation",
        reporter: str = "jsonl",
        artifacts: Sequence[Mapping[str, object]] = (),
        fixtures: Sequence[str] = (),
        credentials: Sequence[str] = (),
    ) -> "BrokerLaunchTicket":
        return cls(
            ticket_id=ticket_id,
            attempt_id=attempt_id,
            target_id=target_id,
            run_id=run_id,
            repository_id=repository_id,
            repository_generation=repository_generation,
            owner_uid=owner_uid,
            generation=generation,
            root_repo=root_repo,
            temporary_repo=temporary_repo,
            execution_root=execution_root or root_repo,
            argv=tuple(argv),
            cwd=cwd,
            environment=dict(environment),
            intent=intent,
            driver=driver,
            reporter=reporter,
            artifacts=tuple(dict(item) for item in artifacts),
            fixtures=tuple(fixtures),
            credentials=tuple(credentials),
            network=network,
            ttl_seconds=ttl_seconds,
            kill_after_run=True,
            cpu_millis=cpu_millis,
            memory_mib=memory_mib,
            pids=pids,
            worktree_key=worktree_key,
            issued_at=float(issued_at),
            expires_at=float(expires_at),
        )
    def public_document(self) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "attempt_id": self.attempt_id,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "repository_id": self.repository_id,
            "repository_generation": self.repository_generation,
            "owner_uid": self.owner_uid,
            "generation": self.generation,
            "root_repo": self.root_repo,
            "temporary_repo": self.temporary_repo,
            "execution_root": self.execution_root,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "environment": dict(self.environment),
            "intent": self.intent,
            "driver": self.driver,
            "reporter": self.reporter,
            "artifacts": [dict(item) for item in self.artifacts],
            "fixtures": list(self.fixtures),
            "credentials": list(self.credentials),
            "network": self.network,
            "ttl_seconds": self.ttl_seconds,
            "kill_after_run": self.kill_after_run,
            "resources": {
                "cpu_millis": self.cpu_millis,
                "memory_mib": self.memory_mib,
                "pids": self.pids,
            },
            "worktree_key": self.worktree_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class TransientRunnerRequest:
    ticket: BrokerLaunchTicket
    target_name: str
    shard_index: int
    shard_count: int
    launch_timeout_seconds: int = 300

    def to_document(self) -> dict[str, object]:
        ticket = self.ticket
        return {
            "schema_version": TESTD_RUNNER_SCHEMA_VERSION,
            "ticket": ticket.public_document(),
            "target": {
                "kind": "test_attempt",
                "id": ticket.target_id,
                "name": self.target_name,
                "shard_index": self.shard_index,
                "shard_count": self.shard_count,
            },
            "lifecycle": {
                "purpose": "test",
                "ttl_seconds": ticket.ttl_seconds,
                "launch_timeout_seconds": self.launch_timeout_seconds,
                "kill_after_run": True,
            },
            "isolation": {
                "owner_uid": ticket.owner_uid,
                "worktree_key": ticket.worktree_key,
                "cpu_millis": ticket.cpu_millis,
                "memory_mib": ticket.memory_mib,
                "pids": ticket.pids,
                "network": ticket.network,
                "clean_environment": True,
            },
            "command": {
                "argv": list(ticket.argv),
                "cwd": ticket.cwd,
                "execution_root": ticket.execution_root,
                "environment": dict(ticket.environment),
            },
            "reporting": {
                "driver": ticket.driver,
                "reporter": ticket.reporter,
                "artifacts": [dict(item) for item in ticket.artifacts],
                "fixtures": list(ticket.fixtures),
            },
        }

@dataclass(frozen=True)
class RunnerHandle:
    runtime_id: str
    launch_ack_id: str
    launch_ticket_id: str | None = None
    launch_operation_id: str | None = None
    launch_timeout_seconds: int = 300
    launch_confirmed: bool = True


@dataclass(frozen=True)
class RunnerObservation:
    state: str
    exit_envelope: AttemptExitEnvelope | None = None
    result_chunk: Mapping[str, object] | None = None
    current_memory_bytes: int | None = None
    launch_confirmed: bool = True


@dataclass(frozen=True)
class RunnerRecoveryContext:
    """Generation-fenced attachment context retained outside testd memory."""

    repository_id: str
    repository_generation: int
    attempt_id: str
    generation: int
    started_at: float = 0.0
    next_chunk_index: int = 0
    result_chunk_ids: tuple[str, ...] = ()
    launch_ticket_id: str | None = None
    launch_operation_id: str | None = None
    launch_timeout_seconds: int = 300
    launch_confirmed: bool = True


@runtime_checkable
class RuntimeRequestSubmitter(Protocol):
    def prepare(self, document: Mapping[str, object]) -> Mapping[str, object]: ...

    def launch_prepared(self, runtime_id: str) -> Mapping[str, object]: ...

    def submit(self, document: Mapping[str, object]) -> Mapping[str, object]: ...

    def observe(self, runtime_id: str) -> Mapping[str, object]: ...

    def recover(
        self, runtime_id: str, *, context: RunnerRecoveryContext
    ) -> None: ...

    def cancel(self, runtime_id: str, *, reason: str) -> Mapping[str, object]: ...


@runtime_checkable
class RunnerLauncher(Protocol):
    def launch(self, request: TransientRunnerRequest) -> RunnerHandle: ...

    def observe(self, handle: RunnerHandle) -> RunnerObservation: ...

    def recover(
        self, handle: RunnerHandle, *, context: RunnerRecoveryContext
    ) -> None: ...

    def cancel(self, handle: RunnerHandle, *, reason: str) -> bool: ...


@runtime_checkable
class BrokerLaunchTicketIssuer(Protocol):
    def issue(
        self,
        *,
        candidate: RunnableTarget,
        lease: LeaseGrant,
        plan_document: Mapping[str, object],
        launch_deadline: float,
    ) -> BrokerLaunchTicket: ...

    def observe_live_source(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        plan_document: Mapping[str, object],
    ) -> str: ...


class TestdLaunchAdapter:
    """Translate normalized requests into an injected runtime submitter."""

    def __init__(self, submitter: RuntimeRequestSubmitter) -> None:
        if not isinstance(submitter, RuntimeRequestSubmitter):
            raise TestStoreContractError("runtime submitter is invalid")
        self._submitter = submitter

    @staticmethod
    def _handle(
        reply: Mapping[str, object], *, request: TransientRunnerRequest
    ) -> RunnerHandle:
        base_fields = {"runtime_id", "launch_ack_id"}
        recovery_fields = {
            "launch_ticket_id",
            "launch_operation_id",
            "launch_timeout_seconds",
            "launch_confirmed",
        }
        if not isinstance(reply, Mapping) or set(reply) not in {
            frozenset(base_fields),
            frozenset(base_fields | recovery_fields),
        }:
            raise TestStoreContractError("runtime launch reply fields are invalid")
        launch_confirmed = reply.get("launch_confirmed", True)
        launch_timeout_seconds = reply.get(
            "launch_timeout_seconds", request.launch_timeout_seconds
        )
        if (
            type(launch_confirmed) is not bool
            or type(launch_timeout_seconds) is not int
            or not 1 <= launch_timeout_seconds <= 3_600
        ):
            raise TestStoreContractError("runtime launch recovery fields are invalid")
        launch_ticket_id = reply.get("launch_ticket_id")
        launch_operation_id = reply.get("launch_operation_id")
        if not launch_confirmed and (
            launch_ticket_id is None or launch_operation_id is None
        ):
            raise TestStoreContractError("pending runtime launch identity is incomplete")
        return RunnerHandle(
            runtime_id=_safe_id("runtime_id", reply["runtime_id"]),
            launch_ack_id=_safe_id("launch_ack_id", reply["launch_ack_id"]),
            launch_ticket_id=(
                None
                if launch_ticket_id is None
                else _safe_id("launch_ticket_id", launch_ticket_id)
            ),
            launch_operation_id=(
                None
                if launch_operation_id is None
                else _safe_id("launch_operation_id", launch_operation_id)
            ),
            launch_timeout_seconds=launch_timeout_seconds,
            launch_confirmed=launch_confirmed,
        )

    def prepare(self, request: TransientRunnerRequest) -> RunnerHandle:
        """Publish deterministic pending identity without starting the host job."""

        if not isinstance(request, TransientRunnerRequest):
            raise TestStoreContractError("runner request is invalid")
        reply = self._submitter.prepare(request.to_document())
        handle = self._handle(reply, request=request)
        if handle.launch_confirmed:
            raise TestStoreConflict("prepared runtime was already launch-confirmed")
        return handle

    def launch_prepared(
        self, request: TransientRunnerRequest, handle: RunnerHandle
    ) -> RunnerHandle:
        """Start/reconcile only the exact identity already retained by testd."""

        if not isinstance(request, TransientRunnerRequest) or not isinstance(
            handle, RunnerHandle
        ):
            raise TestStoreContractError("prepared runner request is invalid")
        launched = self._handle(
            self._submitter.launch_prepared(handle.runtime_id), request=request
        )
        if (
            launched.runtime_id != handle.runtime_id
            or launched.launch_ack_id != handle.launch_ack_id
            or launched.launch_ticket_id != handle.launch_ticket_id
            or launched.launch_operation_id != handle.launch_operation_id
            or launched.launch_timeout_seconds != handle.launch_timeout_seconds
        ):
            raise TestStoreConflict("prepared runtime launch identity changed")
        return launched

    def launch(self, request: TransientRunnerRequest) -> RunnerHandle:
        """Compatibility wrapper for direct adapter callers."""

        prepared = self.prepare(request)
        return self.launch_prepared(request, prepared)

    def observe(self, handle: RunnerHandle) -> RunnerObservation:
        reply = self._submitter.observe(handle.runtime_id)
        base_fields = {
            "state", "exit_envelope", "result_chunk", "current_memory_bytes"
        }
        if not isinstance(reply, Mapping) or set(reply) not in {
            frozenset(base_fields),
            frozenset(base_fields | {"launch_confirmed"}),
        }:
            raise TestStoreContractError("runtime observation fields are invalid")
        state = str(reply["state"])
        launch_confirmed = reply.get("launch_confirmed", True)
        if type(launch_confirmed) is not bool:
            raise TestStoreContractError("runtime launch confirmation is invalid")
        current_memory_bytes = reply["current_memory_bytes"]
        if current_memory_bytes is not None and (
            type(current_memory_bytes) is not int or current_memory_bytes < 0
        ):
            raise TestStoreContractError("runtime current memory is invalid")
        if (
            state == "running"
            and reply["exit_envelope"] is None
            and reply["result_chunk"] is None
        ):
            return RunnerObservation(
                state="running",
                current_memory_bytes=current_memory_bytes,
                launch_confirmed=launch_confirmed,
            )
        if (
            state == "result"
            and reply["exit_envelope"] is None
            and isinstance(reply["result_chunk"], Mapping)
        ):
            return RunnerObservation(
                state="result",
                result_chunk=dict(reply["result_chunk"]),
                launch_confirmed=launch_confirmed,
            )
        if (
            state != "exited"
            or not isinstance(reply["exit_envelope"], Mapping)
            or (
                reply["result_chunk"] is not None
                and not isinstance(reply["result_chunk"], Mapping)
            )
        ):
            raise TestStoreContractError("runtime observation state is invalid")
        return RunnerObservation(
            state="exited",
            exit_envelope=AttemptExitEnvelope.from_document(reply["exit_envelope"]),
            result_chunk=(
                None
                if reply["result_chunk"] is None
                else dict(reply["result_chunk"])
            ),
            launch_confirmed=launch_confirmed,
        )

    def recover(
        self, handle: RunnerHandle, *, context: RunnerRecoveryContext
    ) -> None:
        if not isinstance(handle, RunnerHandle) or not isinstance(
            context, RunnerRecoveryContext
        ):
            raise TestStoreContractError("runtime recovery binding is invalid")
        self._submitter.recover(handle.runtime_id, context=context)

    def cancel(self, handle: RunnerHandle, *, reason: str) -> bool:
        reason = _bounded_text("cancel reason", reason, maximum=1024)
        reply = self._submitter.cancel(handle.runtime_id, reason=reason)
        if not isinstance(reply, Mapping) or set(reply) != {"cancelled"}:
            raise TestStoreContractError("runtime cancellation reply fields are invalid")
        if type(reply["cancelled"]) is not bool:
            raise TestStoreContractError("runtime cancellation result is invalid")
        return bool(reply["cancelled"])


def _attempt_result_chunk(value: Mapping[str, object]) -> AttemptResultChunk:
    expected = {
        "chunk_id", "chunk_index", "cases", "failures", "artifacts",
        "reporter_complete",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TestStoreContractError("runner result chunk fields are invalid")
    for field_name in ("cases", "failures", "artifacts"):
        if not isinstance(value[field_name], Sequence) or isinstance(
            value[field_name], (str, bytes)
        ):
            raise TestStoreContractError("runner result chunk collection is invalid")
    cases: list[CaseResult] = []
    for raw in value["cases"]:
        if not isinstance(raw, Mapping) or set(raw) != {
            "case_id", "display_name", "status", "duration_seconds", "location"
        }:
            raise TestStoreContractError("runner case result fields are invalid")
        cases.append(
            CaseResult(
                case_id=raw["case_id"],
                display_name=raw["display_name"],
                status=raw["status"],
                duration_seconds=raw["duration_seconds"],
                location=raw["location"],
            )
        )
    failures: list[FailureRecord] = []
    for raw in value["failures"]:
        if not isinstance(raw, Mapping) or set(raw) != {
            "failure_id", "classification", "message", "case_id", "location",
            "artifact_id",
        }:
            raise TestStoreContractError("runner failure fields are invalid")
        try:
            classification = FailureClassification(raw["classification"])
        except (TypeError, ValueError) as error:
            raise TestStoreContractError("runner failure classification is invalid") from error
        failures.append(
            FailureRecord(
                failure_id=raw["failure_id"],
                classification=classification,
                message=raw["message"],
                case_id=raw["case_id"],
                location=raw["location"],
                artifact_id=raw["artifact_id"],
            )
        )
    artifacts: list[ArtifactMetadata] = []
    for raw in value["artifacts"]:
        if not isinstance(raw, Mapping) or set(raw) != {
            "artifact_id", "kind", "storage_handle", "sha256", "size_bytes",
            "verified",
        }:
            raise TestStoreContractError("runner artifact fields are invalid")
        artifacts.append(
            ArtifactMetadata(
                artifact_id=raw["artifact_id"],
                kind=raw["kind"],
                storage_handle=raw["storage_handle"],
                sha256=raw["sha256"],
                size_bytes=raw["size_bytes"],
                verified=raw["verified"],
            )
        )
    return AttemptResultChunk(
        chunk_id=value["chunk_id"],
        chunk_index=value["chunk_index"],
        cases=tuple(cases),
        failures=tuple(failures),
        artifacts=tuple(artifacts),
        reporter_complete=value["reporter_complete"],
    )


@dataclass
class _ActiveAttempt:
    candidate: RunnableTarget
    lease: LeaseGrant
    handle: RunnerHandle
    launched_at: float
    next_source_check_at: float
    repository_generation: int
    result_chunk_ids: list[str] = field(default_factory=list)
    current_memory_bytes: int | None = None
    runtime_active: bool = True


class TestdEngine:
    """One deterministic scheduler/reconciliation owner for test attempts."""

    def __init__(
        self,
        *,
        store: UniversalTestStore,
        scheduler: WeightedFairScheduler,
        ticket_issuer: BrokerLaunchTicketIssuer,
        launcher: RunnerLauncher,
        spool: DurableAttemptSpool,
        lease_owner: str = "devcoordinator-testd",
        lease_seconds: int = 30,
        live_source_check_seconds: float = 5.0,
        clock: Callable[[], float],
    ) -> None:
        if not isinstance(store, UniversalTestStore):
            raise TestStoreContractError("store is invalid")
        if not isinstance(scheduler, WeightedFairScheduler):
            raise TestStoreContractError("scheduler is invalid")
        if not isinstance(ticket_issuer, BrokerLaunchTicketIssuer):
            raise TestStoreContractError("ticket issuer is invalid")
        if not isinstance(launcher, RunnerLauncher):
            raise TestStoreContractError("launcher is invalid")
        if not isinstance(spool, DurableAttemptSpool):
            raise TestStoreContractError("spool is invalid")
        if not callable(clock):
            raise TestStoreContractError("clock is invalid")
        self.store = store
        self.scheduler = scheduler
        self.ticket_issuer = ticket_issuer
        self.launcher = launcher
        self.spool = spool
        self.lease_owner = _safe_id("lease_owner", lease_owner)
        self.lease_seconds = _positive_int(
            "lease_seconds", lease_seconds, maximum=300
        )
        if (
            isinstance(live_source_check_seconds, bool)
            or not isinstance(live_source_check_seconds, (int, float))
            or not math.isfinite(float(live_source_check_seconds))
            or not 1 <= float(live_source_check_seconds) <= 300
        ):
            raise TestStoreContractError(
                "live_source_check_seconds must be from 1 through 300"
            )
        self.live_source_check_seconds = float(live_source_check_seconds)
        self.clock = clock
        self._active: dict[str, _ActiveAttempt] = {}
        self._recover_active_attempts()
        self.store.reconcile_nonterminal_runs(now=float(self.clock()))

    def _active_envelope(self, active: _ActiveAttempt) -> ActiveAttemptEnvelope:
        return ActiveAttemptEnvelope(
            attempt_id=active.lease.attempt_id,
            generation=active.lease.generation,
            candidate=dict(active.candidate.__dict__),
            lease=dict(active.lease.__dict__),
            runtime_id=active.handle.runtime_id,
            launch_ack_id=active.handle.launch_ack_id,
            repository_generation=active.repository_generation,
            launched_at=active.launched_at,
            next_source_check_at=active.next_source_check_at,
            result_chunk_ids=tuple(active.result_chunk_ids),
            launch_ticket_id=active.handle.launch_ticket_id,
            launch_operation_id=active.handle.launch_operation_id,
            launch_timeout_seconds=active.handle.launch_timeout_seconds,
            launch_confirmed=active.handle.launch_confirmed,
        )

    def _retain_active(self, active: _ActiveAttempt) -> None:
        self.spool.retain_active(self._active_envelope(active))

    def _recover_active_attempts(self) -> None:
        pending_terminal = {
            envelope.attempt_id for envelope in self.spool.pending_envelopes()
        }
        candidate_fields = set(RunnableTarget.__dataclass_fields__)
        lease_fields = set(LeaseGrant.__dataclass_fields__)
        for envelope in self.spool.active_envelopes():
            if set(envelope.candidate) != candidate_fields or set(
                envelope.lease
            ) != lease_fields:
                raise TestStoreContractError(
                    "active attempt recovery binding fields are invalid"
                )
            candidate_values = dict(envelope.candidate)
            raw_exclusive = candidate_values.get("exclusive_resources")
            if not isinstance(raw_exclusive, (list, tuple)):
                raise TestStoreContractError(
                    "active attempt exclusive resources are invalid"
                )
            candidate_values["exclusive_resources"] = tuple(raw_exclusive)
            candidate = RunnableTarget(**candidate_values)
            lease = LeaseGrant(**dict(envelope.lease))
            if (
                envelope.attempt_id != lease.attempt_id
                or envelope.generation != lease.generation
                or candidate.target_id != lease.target_id
                or candidate.run_id != lease.run_id
                or candidate.target_name != lease.target_name
                or candidate.shard_index != lease.shard_index
                or candidate.shard_count != lease.shard_count
            ):
                raise TestStoreConflict(
                    "active attempt recovery binding is contradictory"
                )
            attempt = self.store.get_attempt(envelope.attempt_id)
            state = str(attempt["state"])
            if state not in {"leased", "running"}:
                self.spool.discard_active(envelope.attempt_id)
                continue
            if (
                int(attempt["generation"]) != envelope.generation
                or str(attempt["target_id"]) != candidate.target_id
                or str(attempt["run_id"]) != candidate.run_id
                or str(attempt["lease_owner"]) != lease.lease_owner
            ):
                raise TestStoreConflict(
                    "active attempt recovery evidence is stale"
                )
            # A durable terminal envelope is already sufficient to converge;
            # avoid requiring the runtime to remain observable while it replays.
            if envelope.attempt_id in pending_terminal:
                continue
            handle = RunnerHandle(
                runtime_id=envelope.runtime_id,
                launch_ack_id=envelope.launch_ack_id,
                launch_ticket_id=envelope.launch_ticket_id,
                launch_operation_id=envelope.launch_operation_id,
                launch_timeout_seconds=envelope.launch_timeout_seconds,
                launch_confirmed=envelope.launch_confirmed,
            )
            self.launcher.recover(
                handle,
                context=RunnerRecoveryContext(
                    repository_id=candidate.repository_id,
                    repository_generation=envelope.repository_generation,
                    attempt_id=envelope.attempt_id,
                    generation=envelope.generation,
                    started_at=envelope.launched_at,
                    next_chunk_index=len(envelope.result_chunk_ids),
                    result_chunk_ids=envelope.result_chunk_ids,
                    launch_ticket_id=envelope.launch_ticket_id,
                    launch_operation_id=envelope.launch_operation_id,
                    launch_timeout_seconds=envelope.launch_timeout_seconds,
                    launch_confirmed=envelope.launch_confirmed,
                ),
            )
            self._active[envelope.attempt_id] = _ActiveAttempt(
                candidate=candidate,
                lease=lease,
                handle=handle,
                launched_at=envelope.launched_at,
                next_source_check_at=envelope.next_source_check_at,
                repository_generation=envelope.repository_generation,
                result_chunk_ids=list(envelope.result_chunk_ids),
            )

    def _acknowledge_active(self, active: _ActiveAttempt) -> None:
        if not active.handle.launch_confirmed:
            self.store.heartbeat_attempt(
                active.lease.attempt_id,
                generation=active.lease.generation,
                lease_seconds=self._pending_launch_lease_seconds(active),
                operation_id=str(uuid.uuid4()),
            )
            return
        self.store.acknowledge_launch(
            active.lease.attempt_id,
            generation=active.lease.generation,
            launch_ack_id=active.handle.launch_ack_id,
            operation_id=_stable_operation_id(
                "launch-ack",
                active.lease.attempt_id,
                active.lease.generation,
                active.handle.launch_ack_id,
            ),
        )
        # A pending launch starts with a lease covering its full semantic
        # deadline.  Once the exact launch is confirmed, return immediately to
        # the short ordinary heartbeat lease so abandoned work is reaped
        # promptly after a testd crash.
        self.store.heartbeat_attempt(
            active.lease.attempt_id,
            generation=active.lease.generation,
            lease_seconds=self.lease_seconds,
            operation_id=str(uuid.uuid4()),
        )

    def _pending_launch_lease_seconds(self, active: _ActiveAttempt) -> int:
        deadline = (
            active.launched_at
            + active.handle.launch_timeout_seconds
            + PENDING_LAUNCH_LEASE_MARGIN_SECONDS
        )
        remaining = math.ceil(deadline - float(self.clock()))
        return min(
            MAX_PENDING_LAUNCH_LEASE_SECONDS,
            max(self.lease_seconds, remaining),
        )

    def _prune_terminal_recovery(self) -> None:
        for envelope in self.spool.active_envelopes():
            state = str(self.store.get_attempt(envelope.attempt_id)["state"])
            if state not in {"leased", "running"}:
                self.spool.discard_active(envelope.attempt_id)
                self._active.pop(envelope.attempt_id, None)

    def schedule(self, *, launch_batch: int = 64) -> dict[str, object]:
        launch_batch = _positive_int("launch_batch", launch_batch, maximum=1_000)
        replay = self.replay_spool()
        reconciled = self.store.reconcile_nonterminal_runs(now=float(self.clock()))
        candidates = self.store.runnable_targets(limit=10_000)
        active = tuple(self._allocation(value) for value in self.store.active_allocations())
        decision = self.scheduler.select(
            candidates, active=active, launch_batch=launch_batch
        )
        serialized_rejections = [value.__dict__ for value in decision.rejected]
        self.store.record_schedule_decision(
            selected_target_ids=[value.target_id for value in decision.selected],
            rejected=serialized_rejections,
        )
        launched: list[str] = []
        failed: list[dict[str, str]] = []
        for candidate in decision.selected:
            try:
                self._launch(candidate)
                launched.append(candidate.target_id)
            except Exception as error:
                raw_error_code = getattr(error, "code", None)
                error_code = (
                    raw_error_code
                    if isinstance(raw_error_code, str)
                    and _SAFE_ID.fullmatch(raw_error_code) is not None
                    else type(error).__name__
                )
                _LOGGER.exception(
                    "test attempt launch failed repository_id=%s run_id=%s "
                    "target_id=%s target_name=%s error_code=%s",
                    candidate.repository_id,
                    candidate.run_id,
                    candidate.target_id,
                    candidate.target_name,
                    error_code,
                )
                failed.append(
                    {
                        "target_id": candidate.target_id,
                        "error_type": type(error).__name__,
                        "error_code": error_code,
                        "stage": "launch",
                    }
                )
        return {
            "launched_target_ids": launched,
            "launch_failures": failed,
            "rejected": serialized_rejections,
            "memory": {
                "total_mib": decision.memory.total_mib,
                "available_mib": decision.memory.available_mib,
                "reserve_mib": decision.reserve_mib,
                "active_memory_reservation_mib": (
                    decision.active_memory_reservation_mib
                ),
                "observed_at": decision.memory.observed_at,
            },
            "spool": replay,
            "reconciled": reconciled,
        }

    def _allocation(self, value: Mapping[str, object]) -> ActiveAllocation:
        retained = self._active.get(str(value["attempt_id"]))
        return ActiveAllocation(
            attempt_id=str(value["attempt_id"]),
            target_id=str(value["target_id"]),
            repository_id=str(value["repository_id"]),
            owner_uid=int(value["owner_uid"]),
            worktree_key=str(value["worktree_key"]),
            exclusive_resources=tuple(value["exclusive_resources"]),
            source_mode=str(value["source_mode"]),
            memory_commitment_mib=int(value["memory_commitment_mib"]),
            current_memory_bytes=(
                None if retained is None else retained.current_memory_bytes
            ),
            runtime_active=True if retained is None else retained.runtime_active,
        )

    def _launch(self, candidate: RunnableTarget) -> None:
        run = self.store.get_run(candidate.run_id)
        plan_document = self.store.get_plan_document(str(run["plan_id"]))
        plan = decode_test_plan_document(plan_document)
        operation = str(uuid.uuid4())
        lease = self.store.lease_target(
            candidate.target_id,
            lease_owner=self.lease_owner,
            lease_seconds=(
                plan.timeouts.launch_seconds
                + PENDING_LAUNCH_LEASE_MARGIN_SECONDS
            ),
            memory_commitment_mib=candidate.memory_estimate_mib,
            operation_id=operation,
        )
        active: _ActiveAttempt | None = None
        stage = "ticket"
        try:
            launch_deadline = float(self.clock()) + plan.timeouts.launch_seconds
            ticket = self.ticket_issuer.issue(
                candidate=candidate,
                lease=lease,
                plan_document=plan_document,
                launch_deadline=launch_deadline,
            )
            launch_started_at = float(self.clock())
            remaining_launch_seconds = min(
                plan.timeouts.launch_seconds,
                math.ceil(launch_deadline - launch_started_at),
            )
            if remaining_launch_seconds <= 0:
                raise TestStoreConflict(
                    "caller launch deadline expired before runtime submission"
                )
            stage = "descriptor"
            request = self._request(
                candidate,
                lease,
                plan_document,
                ticket,
                launch_timeout_seconds=remaining_launch_seconds,
            )
            prepare = getattr(self.launcher, "prepare", None)
            launch_prepared = getattr(self.launcher, "launch_prepared", None)
            if callable(prepare) and callable(launch_prepared):
                # Persist the deterministic pending identity before the first
                # broker RPC.  A testd crash at any point after this fsync can
                # recover and replay the exact operation without orphaning or
                # duplicating a host runtime.
                stage = "prepare"
                handle = prepare(request)
                active = _ActiveAttempt(
                    candidate=candidate,
                    lease=lease,
                    handle=handle,
                    launched_at=launch_started_at,
                    next_source_check_at=(
                        launch_started_at + self.live_source_check_seconds
                    ),
                    repository_generation=ticket.repository_generation,
                )
                self._retain_active(active)
                self._active[lease.attempt_id] = active
                stage = "runtime"
                active.handle = launch_prepared(request, handle)
                self._retain_active(active)
            else:
                # Non-production injected launchers retain the narrow legacy
                # interface. They do not cross a process boundary and are used
                # only by isolated unit tests.
                stage = "launcher"
                handle = self.launcher.launch(request)
                active = _ActiveAttempt(
                    candidate=candidate,
                    lease=lease,
                    handle=handle,
                    launched_at=launch_started_at,
                    next_source_check_at=(
                        launch_started_at + self.live_source_check_seconds
                    ),
                    repository_generation=ticket.repository_generation,
                )
                self._retain_active(active)
                self._active[lease.attempt_id] = active
            self._acknowledge_active(active)
        except LiveSourceChanged as error:
            self.store.mark_superseded(
                candidate.run_id,
                observed_source_fingerprint=error.observed_source_fingerprint,
                operation_id=str(uuid.uuid4()),
            )
            try:
                self.store.terminalize_attempt(
                    lease.attempt_id,
                    generation=lease.generation,
                    conclusion=AttemptConclusion.SUPERSEDED,
                    duration_seconds=0,
                    operation_id=str(uuid.uuid4()),
                )
            except (TestStoreConflict, TestStoreContractError):
                pass
            raise
        except Exception as error:
            if active is not None:
                # Launch ownership is durable. The next reconciliation pass
                # must observe the exact runtime instead of terminalizing a
                # possibly still-running process or launching a duplicate.
                raise
            try:
                self._spool_prelaunch_failure(
                    lease=lease,
                    stage=stage,
                    error=error,
                )
            except Exception:
                # Never replace the original launch cause. Both envelopes are
                # written before replay, so a transient store failure remains
                # recoverable on the next testd pass rather than committing a
                # zero-evidence infrastructure terminal.
                _LOGGER.exception(
                    "test prelaunch failure evidence could not be retained "
                    "attempt_id=%s stage=%s",
                    lease.attempt_id,
                    stage,
                )
            raise

    def _spool_prelaunch_failure(
        self,
        *,
        lease: LeaseGrant,
        stage: str,
        error: Exception,
    ) -> None:
        """Persist one actionable failure before a definitive pre-handle exit."""

        stage = _safe_id("prelaunch failure stage", stage)
        raw_code = getattr(error, "code", None)
        error_code = (
            raw_code
            if isinstance(raw_code, str) and _SAFE_ID.fullmatch(raw_code) is not None
            else type(error).__name__
        )
        detail = (" ".join(str(error).split()) or type(error).__name__)[:4096]
        identity = hashlib.sha256(
            (
                lease.attempt_id
                + "\0"
                + str(lease.generation)
                + "\0"
                + stage
                + "\0"
                + error_code
                + "\0"
                + detail
            ).encode("utf-8")
        ).hexdigest()
        chunk_id = "chunk-prelaunch-" + identity[:32]
        failure_id = "failure-prelaunch-" + identity[32:]
        chunk = {
            "chunk_id": chunk_id,
            "chunk_index": 0,
            "cases": [],
            "failures": [
                {
                    "failure_id": failure_id,
                    "classification": FailureClassification.INFRASTRUCTURE_FAILURE.value,
                    "message": (
                        f"Test launch failed during {stage} ({error_code}): {detail}"
                    )[:8192],
                    "case_id": None,
                    "location": f"launch/{stage}",
                    "artifact_id": None,
                }
            ],
            "artifacts": [],
            "reporter_complete": True,
        }
        self.spool.append_result_chunk(
            AttemptResultChunkEnvelope(
                envelope_id="result-prelaunch-" + identity[:32],
                attempt_id=lease.attempt_id,
                generation=lease.generation,
                chunk=chunk,
            )
        )
        self.spool.append(
            AttemptExitEnvelope(
                envelope_id="exit-prelaunch-" + identity[:32],
                attempt_id=lease.attempt_id,
                generation=lease.generation,
                operation_id=_stable_operation_id(
                    "prelaunch-terminal",
                    lease.attempt_id,
                    lease.generation,
                    identity,
                ),
                conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED,
                duration_seconds=0,
                result_chunk_ids=(chunk_id,),
            )
        )
        self.replay_spool()

    def _request(
        self,
        candidate: RunnableTarget,
        lease: LeaseGrant,
        plan_document: Mapping[str, object],
        ticket: BrokerLaunchTicket,
        *,
        launch_timeout_seconds: int | None = None,
    ) -> TransientRunnerRequest:
        if not isinstance(ticket, BrokerLaunchTicket):
            raise TestStoreContractError("broker launch ticket is invalid")
        plan = decode_test_plan_document(plan_document)
        if launch_timeout_seconds is None:
            launch_timeout_seconds = plan.timeouts.launch_seconds
        _positive_int(
            "launch_timeout_seconds",
            launch_timeout_seconds,
            maximum=plan.timeouts.launch_seconds,
        )
        if ticket.intent != plan.intent:
            raise TestStoreConflict("launch ticket intent does not match the plan")
        expected = {
            "attempt_id": lease.attempt_id,
            "target_id": candidate.target_id,
            "run_id": candidate.run_id,
            "repository_id": candidate.repository_id,
            "owner_uid": candidate.owner_uid,
            "generation": lease.generation,
            "worktree_key": candidate.worktree_key,
        }
        for field_name, expected_value in expected.items():
            if getattr(ticket, field_name) != expected_value:
                raise TestStoreConflict(f"launch ticket {field_name} is stale or mismatched")
        _safe_id("ticket_id", ticket.ticket_id)
        now = float(self.clock())
        if (
            isinstance(ticket.issued_at, bool)
            or isinstance(ticket.expires_at, bool)
            or not math.isfinite(ticket.issued_at)
            or not math.isfinite(ticket.expires_at)
            or ticket.issued_at > now
            or ticket.expires_at <= now
        ):
            raise TestStoreConflict("launch ticket is expired or not yet valid")
        if ticket.kill_after_run is not True:
            raise TestStoreContractError("test runners require kill_after_run=true")
        _positive_int("ttl_seconds", ticket.ttl_seconds, maximum=MAX_RUNNER_TTL_SECONDS)
        # Legacy manifest resource declarations remain in the ticket only as
        # descriptive compatibility metadata. They never authorize, reject,
        # throttle, or limit an attempt; host MemAvailable plus learned peak
        # memory is the sole capacity input to scheduling.
        if ticket.network not in {
            "none",
            "loopback",
            "host-loopback",
            "external",
        }:
            raise TestStoreContractError("launch ticket network is invalid")
        if ticket.network == "host-loopback" and (
            plan.intent != "manual" or bool(ticket.fixtures)
        ):
            raise TestStoreContractError(
                "host-loopback launch tickets require manual intent without fixtures"
            )
        root = _absolute_path("root_repo", ticket.root_repo)
        temporary = (
            None
            if ticket.temporary_repo is None
            else _absolute_path("temporary_repo", ticket.temporary_repo)
        )
        if root != plan.source.original_root or temporary != plan.source.temporary_root:
            raise TestStoreConflict("launch ticket source does not match the plan")
        execution_root = _absolute_path("execution_root", ticket.execution_root)
        if plan.source.mode is SourceMode.LIVE and execution_root not in {root, temporary}:
            raise TestStoreConflict("live launch ticket execution root is not authoritative")
        if type(ticket.repository_generation) is not int or ticket.repository_generation < 0:
            raise TestStoreContractError("launch ticket repository generation is invalid")
        if plan.source.mode is SourceMode.LIVE and candidate.worktree_key not in {
            root,
            temporary,
        }:
            raise TestStoreConflict("live launch ticket does not own the exact worktree")
        normalized_argv = _argv(ticket.argv)
        normalized_environment = _environment(ticket.environment)
        normalized_cwd = _relative_path("runner cwd", ticket.cwd)
        normalized_ticket = BrokerLaunchTicket(
            **{
                **ticket.__dict__,
                "argv": normalized_argv,
                "cwd": normalized_cwd,
                "environment": normalized_environment,
            }
        )
        return TransientRunnerRequest(
            ticket=normalized_ticket,
            target_name=candidate.target_name,
            shard_index=candidate.shard_index,
            shard_count=candidate.shard_count,
            launch_timeout_seconds=launch_timeout_seconds,
        )

    def heartbeat(self) -> dict[str, object]:
        running: list[str] = []
        completed: list[str] = []
        failed: list[dict[str, str]] = []
        for attempt_id, active in tuple(self._active.items()):
            try:
                self._acknowledge_active(active)
                run = self.store.get_run(active.candidate.run_id)
                state = str(run["state"])
                plan_document = self.store.get_plan_document(str(run["plan_id"]))
                plan = decode_test_plan_document(plan_document)
                now = float(self.clock())
                if (
                    state in {"queued", "running"}
                    and plan.source.mode is SourceMode.LIVE
                    and now >= active.next_source_check_at
                ):
                    # A slow/unavailable source observer must not starve the
                    # attempt lease.  Record the project-local observation
                    # failure and continue supervising the already-running job.
                    active.next_source_check_at = (
                        now + self.live_source_check_seconds
                    )
                    self._retain_active(active)
                    try:
                        observed = self.ticket_issuer.observe_live_source(
                            repository_id=active.candidate.repository_id,
                            owner_uid=active.candidate.owner_uid,
                            plan_document=plan_document,
                        )
                        if re.fullmatch(r"[0-9a-f]{64}", observed) is None:
                            raise TestStoreContractError(
                                "live source observer fingerprint is invalid"
                            )
                        if observed != plan.source.content_fingerprint:
                            changed = self.store.mark_superseded(
                                active.candidate.run_id,
                                observed_source_fingerprint=observed,
                                operation_id=str(uuid.uuid4()),
                            )
                            state = str(changed["state"])
                    except Exception as source_error:
                        failed.append(
                            {
                                "attempt_id": attempt_id,
                                "error_type": type(source_error).__name__,
                                "stage": "source_observation",
                            }
                        )
                if state in {"cancelling", "superseding"}:
                    reason = "run cancellation requested" if state == "cancelling" else "run superseded"
                    if self.launcher.cancel(active.handle, reason=reason):
                        conclusion = (
                            AttemptConclusion.CANCELLED
                            if state == "cancelling"
                            else AttemptConclusion.SUPERSEDED
                        )
                        self._spool_terminal(active, conclusion)
                        completed.append(attempt_id)
                        continue
                observation = self.launcher.observe(active.handle)
                if observation.launch_confirmed and not active.handle.launch_confirmed:
                    active.handle = replace(active.handle, launch_confirmed=True)
                    self._retain_active(active)
                    self._acknowledge_active(active)
                elif not observation.launch_confirmed and active.handle.launch_confirmed:
                    raise TestStoreConflict(
                        "confirmed runtime regressed to an uncertain launch"
                    )
                if observation.state == "running":
                    active.current_memory_bytes = observation.current_memory_bytes
                    active.runtime_active = True
                    self.store.heartbeat_attempt(
                        attempt_id,
                        generation=active.lease.generation,
                        lease_seconds=self.lease_seconds,
                        operation_id=str(uuid.uuid4()),
                    )
                    running.append(attempt_id)
                elif observation.state == "result" and observation.result_chunk is not None:
                    active.current_memory_bytes = None
                    active.runtime_active = False
                    chunk = _attempt_result_chunk(observation.result_chunk)
                    if chunk.chunk_id in active.result_chunk_ids:
                        raise TestStoreConflict("runner result chunk is duplicated")
                    self.spool.append_result_chunk(
                        AttemptResultChunkEnvelope(
                            envelope_id=(
                                f"result-{chunk.chunk_index:06d}-"
                                + hashlib.sha256(
                                (
                                    attempt_id
                                    + "\0"
                                    + str(active.lease.generation)
                                    + "\0"
                                    + chunk.chunk_id
                                ).encode("utf-8")
                                ).hexdigest()[:32]
                            ),
                            attempt_id=attempt_id,
                            generation=active.lease.generation,
                            chunk=dict(observation.result_chunk),
                        )
                    )
                    active.result_chunk_ids.append(chunk.chunk_id)
                    self._retain_active(active)
                    self.replay_result_spool()
                    self.store.heartbeat_attempt(
                        attempt_id,
                        generation=active.lease.generation,
                        lease_seconds=self.lease_seconds,
                        operation_id=str(uuid.uuid4()),
                    )
                    running.append(attempt_id)
                elif observation.state == "exited" and observation.exit_envelope is not None:
                    if plan.source.mode is SourceMode.LIVE:
                        # A short-lived runner can exit before the periodic
                        # source check is due.  Never accept its terminal
                        # envelope until the exact live source is observed one
                        # final time; otherwise a mutation immediately after
                        # launch could be reported against stale provenance.
                        try:
                            observed = self.ticket_issuer.observe_live_source(
                                repository_id=active.candidate.repository_id,
                                owner_uid=active.candidate.owner_uid,
                                plan_document=plan_document,
                            )
                            if re.fullmatch(r"[0-9a-f]{64}", observed) is None:
                                raise TestStoreContractError(
                                    "live source observer fingerprint is invalid"
                                )
                        except Exception:
                            # The exited runner is retained until provenance can
                            # be verified.  Renewing the lease prevents the
                            # reaper from converting a temporary observer outage
                            # into an unrelated abandonment conclusion.
                            self.store.heartbeat_attempt(
                                attempt_id,
                                generation=active.lease.generation,
                                lease_seconds=self.lease_seconds,
                                operation_id=str(uuid.uuid4()),
                            )
                            raise
                        if observed != plan.source.content_fingerprint:
                            self.store.mark_superseded(
                                active.candidate.run_id,
                                observed_source_fingerprint=observed,
                                operation_id=str(uuid.uuid4()),
                            )
                            self._spool_terminal(
                                active,
                                AttemptConclusion.SUPERSEDED,
                                peak_memory_bytes=(
                                    observation.exit_envelope.peak_memory_bytes
                                ),
                                cpu_seconds=observation.exit_envelope.cpu_seconds,
                            )
                            completed.append(attempt_id)
                            continue
                    self._validate_exit(active, observation.exit_envelope)
                    if observation.result_chunk is not None:
                        raise TestStoreContractError(
                            "terminal runner observation contains an undrained result chunk"
                        )
                    if observation.exit_envelope.result_chunk_ids != tuple(
                        active.result_chunk_ids
                    ):
                        raise TestStoreConflict(
                            "runner exit references contradictory result chunks"
                        )
                    self.spool.append(observation.exit_envelope)
                    self.replay_spool()
                    completed.append(attempt_id)
                else:
                    raise TestStoreContractError("runner observation is incomplete")
            except Exception as error:
                failed.append({"attempt_id": attempt_id, "error_type": type(error).__name__})
        return {"running_attempt_ids": running, "completed_attempt_ids": completed, "failures": failed}

    def cancel_run(
        self, *, run_id: str, actor: str, reason: str, operation_id: str
    ) -> dict[str, object]:
        result = self.store.request_cancel(
            run_id, actor=actor, reason=reason, operation_id=operation_id
        )
        cancelled: list[str] = []
        unresolved: list[str] = []
        for attempt_id in result["active_attempt_ids"]:
            active = self._active.get(str(attempt_id))
            if active is None:
                unresolved.append(str(attempt_id))
                continue
            if self.launcher.cancel(active.handle, reason=reason):
                self._spool_terminal(active, AttemptConclusion.CANCELLED)
                cancelled.append(str(attempt_id))
            else:
                unresolved.append(str(attempt_id))
        return {**result, "cancelled_attempt_ids": cancelled, "unresolved_attempt_ids": unresolved}

    def _spool_terminal(
        self,
        active: _ActiveAttempt,
        conclusion: AttemptConclusion,
        *,
        peak_memory_bytes: int | None = None,
        cpu_seconds: float | None = None,
    ) -> None:
        duration = max(0.0, float(self.clock()) - active.launched_at)
        identity = hashlib.sha256(
            (
                active.lease.attempt_id
                + "\0"
                + str(active.lease.generation)
                + "\0"
                + conclusion.value
                + "\0"
                + ",".join(active.result_chunk_ids)
            ).encode("utf-8")
        ).hexdigest()
        envelope = AttemptExitEnvelope(
            envelope_id="exit-" + identity[:32],
            attempt_id=active.lease.attempt_id,
            generation=active.lease.generation,
            operation_id=_stable_operation_id(
                "terminal",
                active.lease.attempt_id,
                active.lease.generation,
                conclusion.value,
                identity,
            ),
            conclusion=conclusion,
            duration_seconds=duration,
            result_chunk_ids=tuple(active.result_chunk_ids),
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=cpu_seconds,
        )
        self.spool.append(envelope)
        self.replay_spool()

    @staticmethod
    def _validate_exit(active: _ActiveAttempt, envelope: AttemptExitEnvelope) -> None:
        if (
            envelope.attempt_id != active.lease.attempt_id
            or envelope.generation != active.lease.generation
        ):
            raise TestStoreConflict("runner exit envelope is stale or mismatched")

    def replay_spool(self, *, limit: int = 1_000) -> dict[str, object]:
        chunks = self.replay_result_spool(limit=limit)
        exits = self.spool.replay(
            lambda envelope: self.store.terminalize_attempt(
                envelope.attempt_id,
                generation=envelope.generation,
                conclusion=envelope.conclusion,
                duration_seconds=envelope.duration_seconds,
                operation_id=envelope.operation_id,
                expected_result_chunk_ids=envelope.result_chunk_ids,
                peak_memory_bytes=envelope.peak_memory_bytes,
                cpu_seconds=envelope.cpu_seconds,
            ),
            limit=limit,
        )
        self._prune_terminal_recovery()
        return {**exits, "result_chunks": chunks}

    def replay_result_spool(self, *, limit: int = 1_000) -> dict[str, object]:
        return self.spool.replay_result_chunks(
            lambda envelope: self.store.append_result_chunk(
                envelope.attempt_id,
                generation=envelope.generation,
                chunk=_attempt_result_chunk(envelope.chunk),
            ),
            limit=limit,
        )

    def reap(self) -> dict[str, object]:
        return self.store.reap_expired_attempts(now=float(self.clock()))


class TestdEngineLoop:
    """Supervise scheduling, heartbeats, spool replay, and lease reaping."""

    def __init__(
        self,
        engine: TestdEngine,
        *,
        interval_seconds: float = 1.0,
        launch_batch: int = 64,
    ) -> None:
        if not isinstance(engine, TestdEngine):
            raise TestStoreContractError("testd engine loop requires TestdEngine")
        if not 0.05 <= float(interval_seconds) <= 60:
            raise TestStoreContractError("testd engine interval is invalid")
        self.engine = engine
        self.interval_seconds = float(interval_seconds)
        self.launch_batch = _positive_int(
            "launch_batch", launch_batch, maximum=1_000
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> Mapping[str, object]:
        # Reconcile launched work before admitting more, then reap only after
        # current leases have had a chance to heartbeat.
        heartbeat = self.engine.heartbeat()
        schedule = self.engine.schedule(launch_batch=self.launch_batch)
        reaped = self.engine.reap()
        return {"heartbeat": heartbeat, "schedule": schedule, "reaped": reaped}

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise TestStoreConflict("testd engine loop is already running")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.serve_forever,
            name="devcoordinator-testd-engine",
            daemon=True,
        )
        self._thread.start()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                _LOGGER.exception("testd scheduler iteration failed")
            self._stop.wait(self.interval_seconds)

    def close(self, *, timeout: float = 10.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))
            if thread.is_alive():
                raise TestStoreConflict("testd engine loop did not stop")
        self._thread = None


__all__ = [
    "BrokerLaunchTicket",
    "BrokerLaunchTicketIssuer",
    "LiveSourceChanged",
    "RunnerHandle",
    "RunnerLauncher",
    "RunnerObservation",
    "RuntimeRequestSubmitter",
    "TestdEngine",
    "TestdEngineLoop",
    "TestdLaunchAdapter",
    "TransientRunnerRequest",
]
