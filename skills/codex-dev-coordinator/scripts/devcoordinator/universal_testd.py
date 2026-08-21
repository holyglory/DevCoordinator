"""Deterministic testd scheduling over the schema-v8 execution state machine.

Testd is the sole semantic authority. The privileged launcher performs only
prepare, start, observe, stop, package resolution, and collection against exact
persisted systemd identities. Testd never uses leases, a spool, result chunks,
live-source supersession, or an in-run retry chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import threading
import time
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable
import uuid

from .universal_test_contract import deterministic_fingerprint
from .universal_test_scheduler import (
    ActiveAllocation,
    WeightedFairScheduler,
)
from .universal_test_service import decode_test_plan_document
from .universal_test_store import (
    ArtifactMetadata,
    ExecutionConclusion,
    CaseResult,
    ExecutionGrant,
    ExecutionResultPackage,
    FailureClassification,
    FailureRecord,
    RunnableTarget,
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)


TESTD_RUNNER_SCHEMA_VERSION = 2
MAX_RESULT_PACKAGE_BYTES = 1024 * 1024 * 1024
MAX_PROGRESS_RETAINED_BYTES = 4 * 1024 * 1024
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SYSTEMD_UNIT = re.compile(
    r"^devcoordinator-test-[A-Za-z0-9][A-Za-z0-9_.@:-]{0,199}\.service$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _systemd_unit(value: object) -> str:
    if not isinstance(value, str) or _SYSTEMD_UNIT.fullmatch(value) is None:
        raise TestStoreContractError("systemd_unit is invalid")
    return value


def _operation_id(value: object) -> str:
    try:
        normalized = str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as error:
        raise TestStoreContractError("operation identity is invalid") from error
    return normalized


def _bounded_text(field: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _absolute_path(field: str, value: object) -> str:
    text = _bounded_text(field, value, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != text.rstrip("/")
    ):
        raise TestStoreContractError(f"{field} must be an absolute normalized path")
    return str(path)


def _relative_path(field: str, value: object) -> str:
    text = _bounded_text(field, value, maximum=4096)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TestStoreContractError(f"{field} must be a contained relative path")
    return str(path)


def _argv(value: Sequence[object]) -> tuple[str, ...]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or not 1 <= len(value) <= 256
    ):
        raise TestStoreContractError("runner argv is invalid")
    result = tuple(_bounded_text("runner argument", item, maximum=4096) for item in value)
    if sum(len(item.encode("utf-8")) for item in result) > 64 * 1024:
        raise TestStoreContractError("runner argv exceeds its byte bound")
    return result


def _environment(value: Mapping[object, object]) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or len(value) > 128:
        raise TestStoreContractError("runner environment is invalid")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = _bounded_text("environment name", raw_name, maximum=128)
        if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) is None:
            raise TestStoreContractError("runner environment name is invalid")
        result[name] = _bounded_text(
            "environment value", raw_value, maximum=4096
        )
    if sum(len(key) + len(item) for key, item in result.items()) > 64 * 1024:
        raise TestStoreContractError("runner environment exceeds its byte bound")
    return dict(sorted(result.items()))


def _finite_nonnegative(field: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TestStoreContractError(f"{field} is invalid")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise TestStoreContractError(f"{field} is invalid")
    return number


def _stable_operation_id(kind: str, *values: object) -> str:
    material = "\0".join((kind, *(str(value) for value in values)))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "devcoordinator-testd:" + material))


@dataclass(frozen=True)
class BrokerLaunchTicket:
    """Bounded immutable launch facts resolved before native reservation."""

    ticket_id: str
    execution_id: str
    target_id: str
    run_id: str
    repository_id: str
    repository_generation: int
    owner_uid: int
    root_repo: str
    temporary_repo: str | None
    execution_root: str
    argv: tuple[str, ...]
    cwd: str
    environment: Mapping[str, str]
    intent: str
    driver: str
    reporter: str
    artifacts: tuple[Mapping[str, object], ...]
    fixtures: tuple[str, ...]
    credentials: tuple[str, ...]
    network: str
    ttl_seconds: int
    worktree_key: str
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        for field_name in (
            "ticket_id",
            "execution_id",
            "target_id",
            "run_id",
            "repository_id",
        ):
            object.__setattr__(
                self, field_name, _safe_id(field_name, getattr(self, field_name))
            )
        if (
            type(self.repository_generation) is not int
            or self.repository_generation < 0
            or type(self.owner_uid) is not int
            or self.owner_uid < 0
            or type(self.ttl_seconds) is not int
            or not 1 <= self.ttl_seconds <= 31_536_000
        ):
            raise TestStoreContractError("launch ticket generation, UID, or TTL is invalid")
        object.__setattr__(self, "root_repo", _absolute_path("root_repo", self.root_repo))
        if self.temporary_repo is not None:
            object.__setattr__(
                self,
                "temporary_repo",
                _absolute_path("temporary_repo", self.temporary_repo),
            )
        object.__setattr__(
            self,
            "execution_root",
            _absolute_path("execution_root", self.execution_root),
        )
        object.__setattr__(
            self, "worktree_key", _absolute_path("worktree_key", self.worktree_key)
        )
        object.__setattr__(self, "argv", _argv(self.argv))
        object.__setattr__(self, "cwd", _relative_path("cwd", self.cwd))
        object.__setattr__(self, "environment", _environment(self.environment))
        if self.intent not in {"change", "checkpoint", "handoff", "release", "manual"}:
            raise TestStoreContractError("launch ticket intent is invalid")
        if self.network not in {"none", "loopback", "host-loopback", "external"}:
            raise TestStoreContractError("launch ticket network is invalid")
        object.__setattr__(
            self,
            "fixtures",
            tuple(_safe_id("fixture", value) for value in self.fixtures),
        )
        object.__setattr__(
            self,
            "credentials",
            tuple(
                _bounded_text("credential alias", value, maximum=128)
                for value in self.credentials
            ),
        )
        issued = _finite_nonnegative("issued_at", self.issued_at)
        expires = _finite_nonnegative("expires_at", self.expires_at)
        if expires < issued:
            raise TestStoreContractError("launch ticket expiry is invalid")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(
            self, "artifacts", tuple(dict(item) for item in self.artifacts)
        )

    @classmethod
    def issue(cls, **values: object) -> "BrokerLaunchTicket":
        return cls(**values)  # type: ignore[arg-type]

    def public_document(self) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "execution_id": self.execution_id,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "repository_id": self.repository_id,
            "repository_generation": self.repository_generation,
            "owner_uid": self.owner_uid,
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
            "kill_after_run": True,
            "worktree_key": self.worktree_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class TransientRunnerRequest:
    ticket: BrokerLaunchTicket
    execution: ExecutionGrant
    target_name: str
    descriptor_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.ticket, BrokerLaunchTicket):
            raise TestStoreContractError("runner ticket is invalid")
        if not isinstance(self.execution, ExecutionGrant):
            raise TestStoreContractError("runner execution grant is invalid")
        object.__setattr__(
            self,
            "target_name",
            _bounded_text("target_name", self.target_name, maximum=256),
        )
        if (
            not isinstance(self.descriptor_fingerprint, str)
            or _SHA256.fullmatch(self.descriptor_fingerprint) is None
        ):
            raise TestStoreContractError("descriptor_fingerprint is invalid")
        if (
            self.ticket.execution_id != self.execution.execution_id
            or self.ticket.target_id != self.execution.target_id
            or self.ticket.run_id != self.execution.run_id
        ):
            raise TestStoreConflict("runner request identity is contradictory")

    def to_document(self) -> dict[str, object]:
        ticket = self.ticket
        execution = self.execution
        return {
            "schema_version": TESTD_RUNNER_SCHEMA_VERSION,
            "ticket": ticket.public_document(),
            "execution": {
                "execution_id": execution.execution_id,
                "generation": execution.generation,
                "systemd_unit": execution.systemd_unit,
                "launch_operation_id": execution.launch_operation_id,
                "descriptor_fingerprint": self.descriptor_fingerprint,
            },
            "target": {
                "kind": "test_execution",
                "id": execution.target_id,
                "name": self.target_name,
                "shard_index": execution.shard_index,
                "shard_count": execution.shard_count,
            },
            "lifecycle": {
                "purpose": "test",
                "ttl_seconds": ticket.ttl_seconds,
                "kill_after_run": True,
            },
            "isolation": {
                "owner_uid": ticket.owner_uid,
                "worktree_key": ticket.worktree_key,
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
    execution_id: str
    generation: int
    systemd_unit: str
    launch_operation_id: str
    launch_ack_id: str | None = None
    launch_confirmed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "execution_id", _safe_id("execution_id", self.execution_id)
        )
        if type(self.generation) is not int or self.generation != 1:
            raise TestStoreContractError("execution generation is invalid")
        object.__setattr__(self, "systemd_unit", _systemd_unit(self.systemd_unit))
        object.__setattr__(
            self,
            "launch_operation_id",
            _operation_id(self.launch_operation_id),
        )
        if self.launch_ack_id is not None:
            object.__setattr__(
                self,
                "launch_ack_id",
                _safe_id("launch_ack_id", self.launch_ack_id),
            )
        if type(self.launch_confirmed) is not bool:
            raise TestStoreContractError("launch confirmation is invalid")

    @property
    def runtime_id(self) -> str:
        return self.systemd_unit.removesuffix(".service")

@dataclass(frozen=True)
class RunnerResultPackage:
    package_id: str
    sha256: str
    size_bytes: int
    manifest: Mapping[str, object]
    outcome: Mapping[str, object]
    counts: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "package_id", _safe_id("package_id", self.package_id))
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise TestStoreContractError("result package digest is invalid")
        if (
            type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= MAX_RESULT_PACKAGE_BYTES
            or not isinstance(self.manifest, Mapping)
            or not isinstance(self.outcome, Mapping)
            or not isinstance(self.counts, Mapping)
        ):
            raise TestStoreContractError("result package metadata is invalid")
        expected_counts = {
            "passed", "failed", "skipped", "error", "failures", "artifacts"
        }
        if set(self.counts) != expected_counts or any(
            type(value) is not int or value < 0 for value in self.counts.values()
        ):
            raise TestStoreContractError("result package counts are invalid")
        reporter_complete = self.manifest.get("reporter_complete")
        if type(reporter_complete) is not bool:
            raise TestStoreContractError("result package manifest is invalid")
        returncode = self.outcome.get("returncode")
        infrastructure_error = self.outcome.get("infrastructure_error")
        test_failed = self.outcome.get("test_failed", False)
        if (
            returncode is not None and type(returncode) is not int
        ) or (
            infrastructure_error is not None
            and (
                not isinstance(infrastructure_error, str)
                or len(infrastructure_error) > 1024
            )
        ) or type(test_failed) is not bool:
            raise TestStoreContractError("result package outcome is invalid")
        object.__setattr__(self, "manifest", dict(self.manifest))
        object.__setattr__(self, "outcome", dict(self.outcome))
        object.__setattr__(
            self,
            "counts",
            {str(key): int(value) for key, value in self.counts.items()},
        )

    def to_document(self) -> dict[str, object]:
        return {
            "package_id": self.package_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "manifest": dict(self.manifest),
            "outcome": dict(self.outcome),
            "counts": dict(self.counts),
        }


@dataclass(frozen=True)
class RunnerObservation:
    state: str
    unit_inactive: bool
    cgroup_empty: bool
    launch_confirmed: bool = True
    started_at: float | None = None
    systemd_invocation_id: str | None = None
    result_package: RunnerResultPackage | None = None
    current_memory_bytes: int | None = None
    output_progress: Mapping[str, object] | None = None
    peak_memory_bytes: int | None = None
    cpu_seconds: float | None = None
    exit_status: int | None = None

    def __post_init__(self) -> None:
        if self.state not in {"starting", "running", "exited", "stopped", "absent"}:
            raise TestStoreContractError("runner observation state is invalid")
        if (
            type(self.unit_inactive) is not bool
            or type(self.cgroup_empty) is not bool
            or type(self.launch_confirmed) is not bool
            or (
                self.cgroup_empty and not self.unit_inactive
            )
        ):
            raise TestStoreContractError("runner cleanup facts are invalid")
        if self.started_at is not None:
            object.__setattr__(
                self, "started_at", _finite_nonnegative("started_at", self.started_at)
            )
        if self.systemd_invocation_id is not None:
            object.__setattr__(
                self,
                "systemd_invocation_id",
                _safe_id("systemd_invocation_id", self.systemd_invocation_id),
            )
        if self.result_package is not None and not isinstance(
            self.result_package, RunnerResultPackage
        ):
            raise TestStoreContractError("runner result package is invalid")
        if self.current_memory_bytes is not None and (
            type(self.current_memory_bytes) is not int
            or self.current_memory_bytes < 0
        ):
            raise TestStoreContractError("runner current memory is invalid")
        if self.peak_memory_bytes is not None and (
            type(self.peak_memory_bytes) is not int
            or self.peak_memory_bytes < 0
        ):
            raise TestStoreContractError("runner peak memory is invalid")
        if self.cpu_seconds is not None:
            object.__setattr__(
                self, "cpu_seconds", _finite_nonnegative("cpu_seconds", self.cpu_seconds)
            )
        if self.exit_status is not None and type(self.exit_status) is not int:
            raise TestStoreContractError("runner exit status is invalid")
        if self.output_progress is not None:
            object.__setattr__(
                self,
                "output_progress",
                _validated_progress(self.output_progress),
            )


def _validated_progress(value: Mapping[str, object]) -> Mapping[str, object]:
    expected = {
        "stdout_bytes",
        "stderr_bytes",
        "stdout_retained_bytes",
        "stderr_retained_bytes",
        "stdout_truncated",
        "stderr_truncated",
        "last_output_at",
        "observed_at",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TestStoreContractError("runner output progress is invalid")
    numeric = (
        value["stdout_bytes"],
        value["stderr_bytes"],
        value["stdout_retained_bytes"],
        value["stderr_retained_bytes"],
    )
    if (
        any(type(item) is not int or item < 0 for item in numeric)
        or int(value["stdout_retained_bytes"]) > MAX_PROGRESS_RETAINED_BYTES
        or int(value["stderr_retained_bytes"]) > MAX_PROGRESS_RETAINED_BYTES
        or int(value["stdout_retained_bytes"]) > int(value["stdout_bytes"])
        or int(value["stderr_retained_bytes"]) > int(value["stderr_bytes"])
        or type(value["stdout_truncated"]) is not bool
        or type(value["stderr_truncated"]) is not bool
        or bool(value["stdout_truncated"])
        != (int(value["stdout_bytes"]) > int(value["stdout_retained_bytes"]))
        or bool(value["stderr_truncated"])
        != (int(value["stderr_bytes"]) > int(value["stderr_retained_bytes"]))
    ):
        raise TestStoreContractError("runner output progress is invalid")
    last_output = value["last_output_at"]
    observed = _finite_nonnegative("progress observed_at", value["observed_at"])
    if last_output is not None:
        last_output = _finite_nonnegative("last_output_at", last_output)
    return {
        **dict(value),
        "last_output_at": last_output,
        "observed_at": observed,
    }


@runtime_checkable
class RuntimeRequestSubmitter(Protocol):
    def prepare(self, document: Mapping[str, object]) -> Mapping[str, object]: ...

    def start_prepared(self, systemd_unit: str) -> Mapping[str, object]: ...

    def observe(self, systemd_unit: str) -> Mapping[str, object]: ...

    def attach(self, binding: Mapping[str, object]) -> Mapping[str, object]: ...

    def stop(self, systemd_unit: str, *, reason: str) -> Mapping[str, object]: ...

    def resolve_package(
        self, systemd_unit: str, metadata: Mapping[str, object]
    ) -> Mapping[str, object]: ...

    def collect(self, systemd_unit: str) -> Mapping[str, object]: ...


@runtime_checkable
class RunnerLauncher(Protocol):
    def prepare(self, request: TransientRunnerRequest) -> RunnerHandle: ...

    def start(
        self, request: TransientRunnerRequest, handle: RunnerHandle
    ) -> RunnerHandle: ...

    def observe(self, handle: RunnerHandle) -> RunnerObservation: ...

    def attach(self, binding: Mapping[str, object]) -> RunnerHandle: ...

    def stop(self, handle: RunnerHandle, *, reason: str) -> RunnerObservation: ...

    def resolve_package(
        self, handle: RunnerHandle, metadata: RunnerResultPackage
    ) -> ExecutionResultPackage: ...

    def collect(self, handle: RunnerHandle) -> bool: ...


@runtime_checkable
class BrokerLaunchTicketIssuer(Protocol):
    def issue(
        self,
        *,
        candidate: RunnableTarget,
        execution: ExecutionGrant,
        plan_document: Mapping[str, object],
        launch_deadline: float,
    ) -> BrokerLaunchTicket: ...


def _runner_handle(value: Mapping[str, object]) -> RunnerHandle:
    expected = {
        "execution_id",
        "generation",
        "systemd_unit",
        "launch_operation_id",
        "launch_ack_id",
        "launch_confirmed",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TestStoreContractError("runner handle fields are invalid")
    return RunnerHandle(**dict(value))  # type: ignore[arg-type]


def _result_metadata(value: object) -> RunnerResultPackage | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TestStoreContractError("runner result package metadata is invalid")
    return RunnerResultPackage(
        package_id=value.get("package_id"),  # type: ignore[arg-type]
        sha256=value.get("sha256"),  # type: ignore[arg-type]
        size_bytes=value.get("size_bytes"),  # type: ignore[arg-type]
        manifest=value.get("manifest"),  # type: ignore[arg-type]
        outcome=value.get("outcome"),  # type: ignore[arg-type]
        counts=value.get("counts"),  # type: ignore[arg-type]
    )


def _runner_observation(value: Mapping[str, object]) -> RunnerObservation:
    expected = {
        "state",
        "unit_inactive",
        "cgroup_empty",
        "launch_confirmed",
        "started_at",
        "systemd_invocation_id",
        "result_package",
        "current_memory_bytes",
        "output_progress",
        "peak_memory_bytes",
        "cpu_seconds",
        "exit_status",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TestStoreContractError("runner observation fields are invalid")
    return RunnerObservation(
        state=str(value["state"]),
        unit_inactive=value["unit_inactive"],  # type: ignore[arg-type]
        cgroup_empty=value["cgroup_empty"],  # type: ignore[arg-type]
        launch_confirmed=value["launch_confirmed"],  # type: ignore[arg-type]
        started_at=value["started_at"],  # type: ignore[arg-type]
        systemd_invocation_id=value["systemd_invocation_id"],  # type: ignore[arg-type]
        result_package=_result_metadata(value["result_package"]),
        current_memory_bytes=value["current_memory_bytes"],  # type: ignore[arg-type]
        output_progress=value["output_progress"],  # type: ignore[arg-type]
        peak_memory_bytes=value["peak_memory_bytes"],  # type: ignore[arg-type]
        cpu_seconds=value["cpu_seconds"],  # type: ignore[arg-type]
        exit_status=value["exit_status"],  # type: ignore[arg-type]
    )


def _case_result(value: Mapping[str, object]) -> CaseResult:
    expected = {"case_id", "display_name", "status", "duration_seconds", "location"}
    if set(value) != expected:
        raise TestStoreContractError("result package case fields are invalid")
    return CaseResult(
        case_id=value["case_id"],  # type: ignore[arg-type]
        display_name=value["display_name"],  # type: ignore[arg-type]
        status=value["status"],  # type: ignore[arg-type]
        duration_seconds=value["duration_seconds"],  # type: ignore[arg-type]
        location=value["location"],  # type: ignore[arg-type]
    )


def _failure_record(value: Mapping[str, object]) -> FailureRecord:
    expected = {
        "failure_id", "classification", "message", "case_id", "location", "artifact_id"
    }
    if set(value) != expected:
        raise TestStoreContractError("result package failure fields are invalid")
    try:
        classification = FailureClassification(str(value["classification"]))
    except ValueError as error:
        raise TestStoreContractError("result package failure classification is invalid") from error
    return FailureRecord(
        failure_id=value["failure_id"],  # type: ignore[arg-type]
        classification=classification,
        message=value["message"],  # type: ignore[arg-type]
        case_id=value["case_id"],  # type: ignore[arg-type]
        location=value["location"],  # type: ignore[arg-type]
        artifact_id=value["artifact_id"],  # type: ignore[arg-type]
    )


def _artifact_metadata(value: Mapping[str, object]) -> ArtifactMetadata:
    expected = {
        "artifact_id", "kind", "storage_handle", "sha256", "size_bytes", "verified"
    }
    if set(value) != expected:
        raise TestStoreContractError("result package artifact fields are invalid")
    return ArtifactMetadata(
        artifact_id=value["artifact_id"],  # type: ignore[arg-type]
        kind=value["kind"],  # type: ignore[arg-type]
        storage_handle=value["storage_handle"],  # type: ignore[arg-type]
        sha256=value["sha256"],  # type: ignore[arg-type]
        size_bytes=value["size_bytes"],  # type: ignore[arg-type]
        verified=value["verified"],  # type: ignore[arg-type]
    )


def _execution_result_package(value: Mapping[str, object]) -> ExecutionResultPackage:
    expected = {"package_id", "cases", "failures", "artifacts", "reporter_complete"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TestStoreContractError("resolved result package fields are invalid")
    for field_name in ("cases", "failures", "artifacts"):
        if not isinstance(value[field_name], list):
            raise TestStoreContractError("resolved result package collection is invalid")
    return ExecutionResultPackage(
        package_id=value["package_id"],  # type: ignore[arg-type]
        cases=tuple(_case_result(item) for item in value["cases"]),  # type: ignore[arg-type]
        failures=tuple(
            _failure_record(item) for item in value["failures"]  # type: ignore[arg-type]
        ),
        artifacts=tuple(
            _artifact_metadata(item) for item in value["artifacts"]  # type: ignore[arg-type]
        ),
        reporter_complete=value["reporter_complete"],  # type: ignore[arg-type]
    )


class TestdLaunchAdapter:
    """Validate the mapping transport without assigning lifecycle meaning."""

    def __init__(self, submitter: RuntimeRequestSubmitter) -> None:
        if not isinstance(submitter, RuntimeRequestSubmitter):
            raise TestStoreContractError("runtime submitter is invalid")
        self._submitter = submitter

    def prepare(self, request: TransientRunnerRequest) -> RunnerHandle:
        return _runner_handle(self._submitter.prepare(request.to_document()))

    def start(
        self, request: TransientRunnerRequest, handle: RunnerHandle
    ) -> RunnerHandle:
        started = _runner_handle(
            self._submitter.start_prepared(handle.systemd_unit)
        )
        _require_same_handle(handle, started)
        return started

    def observe(self, handle: RunnerHandle) -> RunnerObservation:
        return _runner_observation(self._submitter.observe(handle.systemd_unit))

    def attach(self, binding: Mapping[str, object]) -> RunnerHandle:
        return _runner_handle(self._submitter.attach(binding))

    def stop(self, handle: RunnerHandle, *, reason: str) -> RunnerObservation:
        reason = _bounded_text("stop reason", reason, maximum=1024)
        return _runner_observation(
            self._submitter.stop(handle.systemd_unit, reason=reason)
        )

    def resolve_package(
        self, handle: RunnerHandle, metadata: RunnerResultPackage
    ) -> ExecutionResultPackage:
        return _execution_result_package(
            self._submitter.resolve_package(
                handle.systemd_unit, metadata.to_document()
            )
        )

    def collect(self, handle: RunnerHandle) -> bool:
        reply = self._submitter.collect(handle.systemd_unit)
        if not isinstance(reply, Mapping) or set(reply) != {"collected"}:
            raise TestStoreContractError("runner collection result is invalid")
        if type(reply["collected"]) is not bool:
            raise TestStoreContractError("runner collection result is invalid")
        return bool(reply["collected"])


def _require_same_handle(expected: RunnerHandle, observed: RunnerHandle) -> None:
    if (
        expected.execution_id != observed.execution_id
        or expected.generation != observed.generation
        or expected.systemd_unit != observed.systemd_unit
        or expected.launch_operation_id != observed.launch_operation_id
    ):
        raise TestStoreConflict("runner handle identity changed")


@dataclass
class _ActiveExecution:
    execution: ExecutionGrant
    handle: RunnerHandle
    run_id: str
    target_id: str
    target_name: str
    terminal_committed: bool = False


class TestdEngine:
    """One deterministic scheduler and reconciler for schema-v8 executions."""

    def __init__(
        self,
        *,
        store: UniversalTestStore,
        scheduler: WeightedFairScheduler,
        ticket_issuer: BrokerLaunchTicketIssuer,
        launcher: RunnerLauncher,
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
        if not callable(clock):
            raise TestStoreContractError("clock is invalid")
        self.store = store
        self.scheduler = scheduler
        self.ticket_issuer = ticket_issuer
        self.launcher = launcher
        self.clock = clock
        self._active: dict[str, _ActiveExecution] = {}
        self._restart_cleanup()
        self.store.reconcile_nonterminal_runs(now=float(self.clock()))

    @staticmethod
    def _unit_for_execution(execution_id: str) -> str:
        execution_id = _safe_id("execution_id", execution_id)
        return (
            "devcoordinator-test-"
            + hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:32]
            + ".service"
        )

    @staticmethod
    def _launch_operation_for_target(target_id: str) -> str:
        return _stable_operation_id("launch", target_id)

    @staticmethod
    def _descriptor_fingerprint(
        candidate: RunnableTarget, ticket: BrokerLaunchTicket
    ) -> str:
        return deterministic_fingerprint(
            {
                "ticket": ticket.public_document(),
                "target_id": candidate.target_id,
                "run_id": candidate.run_id,
                "target_name": candidate.target_name,
                "shard_index": candidate.shard_index,
                "shard_count": candidate.shard_count,
            }
        )

    @staticmethod
    def _handle_for_grant(grant: ExecutionGrant) -> RunnerHandle:
        return RunnerHandle(
            execution_id=grant.execution_id,
            generation=grant.generation,
            systemd_unit=grant.systemd_unit,
            launch_operation_id=grant.launch_operation_id,
        )

    def _active_from_binding(
        self, binding: Mapping[str, object], handle: RunnerHandle
    ) -> _ActiveExecution:
        return _ActiveExecution(
            execution=ExecutionGrant(
                execution_id=str(binding["execution_id"]),
                target_id=str(binding["target_id"]),
                run_id=str(binding["run_id"]),
                target_name=str(binding.get("target_name") or binding["target_id"]),
                shard_index=int(binding.get("shard_index", 0)),
                shard_count=int(binding.get("shard_count", 1)),
                generation=int(binding["generation"]),
                systemd_unit=str(binding["systemd_unit"]),
                launch_operation_id=str(binding["launch_operation_id"]),
            ),
            handle=handle,
            run_id=str(binding["run_id"]),
            target_id=str(binding["target_id"]),
            target_name=str(binding.get("target_name") or binding["target_id"]),
        )

    def _restart_cleanup(self) -> None:
        """Converge every exact retained binding before new admission."""

        for binding in self.store.restart_cleanup():
            handle = self.launcher.attach(binding)
            if (
                handle.execution_id != binding["execution_id"]
                or handle.generation != binding["generation"]
                or handle.systemd_unit != binding["systemd_unit"]
                or handle.launch_operation_id != binding["launch_operation_id"]
            ):
                raise TestStoreConflict("restart cleanup attached a different execution")
            active = self._active_from_binding(binding, handle)
            self._active[handle.execution_id] = active
            observation = self.launcher.observe(handle)
            fallback = (
                ExecutionConclusion.TIMED_OUT
                if binding.get("execution_deadline_at") is not None
                and float(self.clock()) >= float(binding["execution_deadline_at"])
                else ExecutionConclusion.CANCELLED
            )
            self._settle(
                active,
                observation,
                fallback=fallback,
                stop_reason="testd restart cleanup",
            )
        if self.store.restart_cleanup():
            raise TestStoreConflict("restart cleanup left active executions")

    def schedule(self, *, launch_batch: int = 64) -> dict[str, object]:
        if type(launch_batch) is not int or not 1 <= launch_batch <= 1_000:
            raise TestStoreContractError("launch_batch is invalid")
        reconciled = self.store.reconcile_nonterminal_runs(now=float(self.clock()))
        candidates = self.store.runnable_targets(limit=10_000)
        allocations = tuple(
            ActiveAllocation(
                execution_id=str(value["execution_id"]),
                target_id=str(value["target_id"]),
                repository_id=str(value["repository_id"]),
                owner_uid=int(value["owner_uid"]),
                worktree_key=str(value["worktree_key"]),
                source_mode="immutable",
                exclusive_resources=tuple(value["exclusive_resources"]),
                memory_commitment_mib=int(value["memory_commitment_mib"]),
                current_memory_bytes=(
                    None
                    if value["current_memory_bytes"] is None
                    else int(value["current_memory_bytes"])
                ),
                runtime_active=bool(value["runtime_active"]),
            )
            for value in self.store.active_allocations()
        )
        decision = self.scheduler.select(
            candidates, active=allocations, launch_batch=launch_batch
        )
        rejected = [dict(value.__dict__) for value in decision.rejected]
        self.store.record_schedule_decision(
            selected_target_ids=[value.target_id for value in decision.selected],
            rejected=rejected,
        )
        launched: list[str] = []
        failures: list[dict[str, str]] = []
        for candidate in decision.selected:
            try:
                self._launch(candidate)
                launched.append(candidate.target_id)
            except Exception as error:
                failures.append(
                    {
                        "target_id": candidate.target_id,
                        "error_type": type(error).__name__,
                        "stage": "launch",
                    }
                )
        return {
            "launched_target_ids": launched,
            "launch_failures": failures,
            "rejected": rejected,
            "memory": {
                "total_mib": decision.memory.total_mib,
                "available_mib": decision.memory.available_mib,
                "reserve_mib": decision.reserve_mib,
                "active_memory_reservation_mib": (
                    decision.active_memory_reservation_mib
                ),
                "observed_at": decision.memory.observed_at,
            },
            "reconciled": reconciled,
        }

    def _launch(self, candidate: RunnableTarget) -> None:
        run = self.store.get_run(candidate.run_id)
        plan_document = self.store.get_plan_document(str(run["plan_id"]))
        plan = decode_test_plan_document(plan_document)
        launch_deadline = float(self.clock()) + plan.timeouts.launch_seconds
        execution_id = self.store.execution_identity(candidate.target_id)
        systemd_unit = self._unit_for_execution(execution_id)
        launch_operation_id = self._launch_operation_for_target(candidate.target_id)
        preview = ExecutionGrant(
            execution_id=execution_id,
            target_id=candidate.target_id,
            run_id=candidate.run_id,
            target_name=candidate.target_name,
            shard_index=candidate.shard_index,
            shard_count=candidate.shard_count,
            generation=1,
            systemd_unit=systemd_unit,
            launch_operation_id=launch_operation_id,
        )
        ticket = self.ticket_issuer.issue(
            candidate=candidate,
            execution=preview,
            plan_document=plan_document,
            launch_deadline=launch_deadline,
        )
        if (
            ticket.target_id != candidate.target_id
            or ticket.run_id != candidate.run_id
            or ticket.repository_id != candidate.repository_id
            or ticket.owner_uid != candidate.owner_uid
            or ticket.ttl_seconds <= 0
        ):
            raise TestStoreConflict("launch ticket contradicts the selected target")
        descriptor_fingerprint = self._descriptor_fingerprint(candidate, ticket)
        grant = self.store.begin_execution(
            candidate.target_id,
            repository_generation=ticket.repository_generation,
            systemd_unit=systemd_unit,
            launch_operation_id=launch_operation_id,
            descriptor_fingerprint=descriptor_fingerprint,
            launch_deadline_at=launch_deadline,
            memory_commitment_mib=candidate.memory_estimate_mib,
            operation_id=_stable_operation_id("begin", candidate.target_id),
        )
        if grant != preview:
            raise TestStoreConflict(
                "test execution identity changed after descriptor resolution"
            )
        active = _ActiveExecution(
            execution=grant,
            handle=self._handle_for_grant(grant),
            run_id=grant.run_id,
            target_id=grant.target_id,
            target_name=grant.target_name,
        )
        self._active[grant.execution_id] = active
        request = TransientRunnerRequest(
            ticket=ticket,
            execution=grant,
            target_name=candidate.target_name,
            descriptor_fingerprint=descriptor_fingerprint,
        )
        prepared = self.launcher.prepare(request)
        _require_same_handle(active.handle, prepared)
        active.handle = prepared
        started = self.launcher.start(request, prepared)
        _require_same_handle(prepared, started)
        active.handle = started

    def _record_start_if_observed(
        self, active: _ActiveExecution, observation: RunnerObservation
    ) -> None:
        if not observation.launch_confirmed:
            return
        retained = self.store.get_execution(active.execution.execution_id)
        if str(retained["state"]) != "starting":
            return
        if observation.started_at is None:
            raise TestStoreConflict(
                "confirmed running execution omitted durable start evidence"
            )
        launch_ack_id = active.handle.launch_ack_id
        if launch_ack_id is None:
            launch_ack_id = "launch-" + active.execution.execution_id
            active.handle = replace(
                active.handle,
                launch_ack_id=launch_ack_id,
                launch_confirmed=True,
            )
        self.store.record_started(
            active.execution.execution_id,
            generation=active.execution.generation,
            systemd_unit=active.execution.systemd_unit,
            launch_ack_id=launch_ack_id,
            started_at=observation.started_at,
            systemd_invocation_id=observation.systemd_invocation_id,
            operation_id=_stable_operation_id(
                "started",
                active.execution.execution_id,
                observation.started_at,
                launch_ack_id,
            ),
        )

    def _record_progress(
        self, active: _ActiveExecution, observation: RunnerObservation
    ) -> None:
        if observation.output_progress is None:
            return
        progress = observation.output_progress
        self.store.record_progress(
            active.execution.execution_id,
            generation=active.execution.generation,
            stdout_bytes=int(progress["stdout_bytes"]),
            stderr_bytes=int(progress["stderr_bytes"]),
            stdout_retained_bytes=int(progress["stdout_retained_bytes"]),
            stderr_retained_bytes=int(progress["stderr_retained_bytes"]),
            stdout_truncated=bool(progress["stdout_truncated"]),
            stderr_truncated=bool(progress["stderr_truncated"]),
            current_memory_bytes=observation.current_memory_bytes,
            last_output_at=progress["last_output_at"],  # type: ignore[arg-type]
            observed_at=float(progress["observed_at"]),
        )

    @staticmethod
    def _package_conclusion(
        metadata: RunnerResultPackage,
        *,
        fallback: ExecutionConclusion,
    ) -> ExecutionConclusion:
        complete = bool(metadata.manifest["reporter_complete"])
        terminal_outcome = metadata.outcome.get("terminal_outcome")
        if not complete:
            return (
                fallback
                if fallback in {
                    ExecutionConclusion.TIMED_OUT,
                    ExecutionConclusion.CANCELLED,
                }
                else ExecutionConclusion.INCOMPLETE
            )
        if terminal_outcome == "timed_out":
            return ExecutionConclusion.TIMED_OUT
        if terminal_outcome == "incomplete":
            return ExecutionConclusion.INCOMPLETE
        if terminal_outcome == "infrastructure_failed":
            return ExecutionConclusion.INFRASTRUCTURE_FAILED
        if int(metadata.counts["failed"]) or int(metadata.counts["error"]):
            return ExecutionConclusion.TEST_FAILED
        if metadata.outcome.get("test_failed") is True:
            return ExecutionConclusion.TEST_FAILED
        if metadata.outcome.get("infrastructure_error") is not None:
            return ExecutionConclusion.INFRASTRUCTURE_FAILED
        returncode = metadata.outcome.get("returncode")
        if returncode not in {None, 0}:
            return ExecutionConclusion.INFRASTRUCTURE_FAILED
        return ExecutionConclusion.SUCCEEDED

    @staticmethod
    def _synthetic_package(
        execution_id: str, conclusion: ExecutionConclusion, reason: str
    ) -> ExecutionResultPackage:
        classification = {
            ExecutionConclusion.TIMED_OUT: FailureClassification.TIMEOUT,
            ExecutionConclusion.CANCELLED: FailureClassification.CANCELLATION,
            ExecutionConclusion.INCOMPLETE: FailureClassification.INCOMPLETE_REPORTING,
            ExecutionConclusion.INFRASTRUCTURE_FAILED:
                FailureClassification.INFRASTRUCTURE_FAILURE,
        }.get(conclusion)
        failures: tuple[FailureRecord, ...] = ()
        if classification is not None:
            identity = hashlib.sha256(
                f"{execution_id}\0{conclusion.value}\0{reason}".encode("utf-8")
            ).hexdigest()[:32]
            failures = (
                FailureRecord(
                    failure_id="failure-" + identity,
                    classification=classification,
                    message=reason[:8192],
                    location="execution",
                ),
            )
        return ExecutionResultPackage(
            package_id=(
                "package-"
                + hashlib.sha256(
                    f"{execution_id}\0{conclusion.value}".encode("utf-8")
                ).hexdigest()[:32]
            ),
            failures=failures,
            reporter_complete=False,
        )

    def _resolved_package(
        self,
        active: _ActiveExecution,
        metadata: RunnerResultPackage,
    ) -> ExecutionResultPackage:
        package = self.launcher.resolve_package(active.handle, metadata)
        if package.package_id != metadata.package_id:
            raise TestStoreConflict("resolved result package identity changed")
        counts = {
            "passed": sum(case.status == "passed" for case in package.cases),
            "failed": sum(case.status == "failed" for case in package.cases),
            "skipped": sum(case.status == "skipped" for case in package.cases),
            "error": sum(case.status == "error" for case in package.cases),
            "failures": len(package.failures),
            "artifacts": len(package.artifacts),
        }
        if counts != dict(metadata.counts):
            raise TestStoreConflict("resolved result package counts changed")
        if bool(package.reporter_complete) != bool(
            metadata.manifest["reporter_complete"]
        ):
            raise TestStoreConflict("resolved result package manifest changed")
        return package

    def _settle(
        self,
        active: _ActiveExecution,
        observation: RunnerObservation,
        *,
        fallback: ExecutionConclusion,
        stop_reason: str,
    ) -> None:
        metadata = observation.result_package
        package = (
            None
            if metadata is None
            else self._resolved_package(active, metadata)
        )
        if not observation.unit_inactive or not observation.cgroup_empty:
            observation = self.launcher.stop(active.handle, reason=stop_reason)
            if metadata is None and observation.result_package is not None:
                metadata = observation.result_package
                package = self._resolved_package(active, metadata)
        if not observation.unit_inactive or not observation.cgroup_empty:
            raise TestStoreConflict(
                "exact execution did not reach inactive empty-cgroup proof"
            )
        if package is None:
            package = self._synthetic_package(
                active.execution.execution_id,
                fallback,
                stop_reason,
            )
            conclusion = fallback
        else:
            assert metadata is not None
            conclusion = self._package_conclusion(metadata, fallback=fallback)
        retained = self.store.get_execution(active.execution.execution_id)
        started_at = retained.get("started_at")
        duration = (
            0.0
            if started_at is None
            else max(0.0, float(self.clock()) - float(started_at))
        )
        self.store.complete_from_package(
            active.execution.execution_id,
            generation=active.execution.generation,
            systemd_unit=active.execution.systemd_unit,
            package=package,
            conclusion=conclusion,
            duration_seconds=duration,
            operation_id=_stable_operation_id(
                "complete",
                active.execution.execution_id,
                package.package_id,
                conclusion.value,
            ),
            unit_inactive=True,
            cgroup_empty=True,
            peak_memory_bytes=observation.peak_memory_bytes,
            cpu_seconds=observation.cpu_seconds,
        )
        active.terminal_committed = True
        if self.launcher.collect(active.handle):
            self._active.pop(active.execution.execution_id, None)

    def heartbeat(self) -> dict[str, object]:
        running: list[str] = []
        completed: list[str] = []
        failures: list[dict[str, str]] = []
        for execution_id, active in tuple(self._active.items()):
            try:
                if active.terminal_committed:
                    if self.launcher.collect(active.handle):
                        self._active.pop(execution_id, None)
                        completed.append(execution_id)
                    continue
                observation = self.launcher.observe(active.handle)
                self._record_start_if_observed(active, observation)
                self._record_progress(active, observation)
                retained = self.store.get_execution(execution_id)
                run = self.store.get_run(active.run_id)
                target_projection = next(
                    target
                    for target in run["targets"]
                    if target.get("execution_id") == execution_id
                )
                deadline_at = target_projection.get("deadline_at")
                timed_out = (
                    deadline_at is not None
                    and float(self.clock()) >= float(deadline_at)
                )
                cancelling = (
                    str(run["state"]) == "cancelling"
                    or str(retained["state"]) == "stopping"
                )
                if observation.result_package is not None:
                    self._settle(
                        active,
                        observation,
                        fallback=(
                            ExecutionConclusion.TIMED_OUT
                            if timed_out
                            else ExecutionConclusion.CANCELLED
                            if cancelling
                            else ExecutionConclusion.INCOMPLETE
                        ),
                        stop_reason=(
                            "execution deadline reached"
                            if timed_out
                            else "run cancellation requested"
                            if cancelling
                            else "result package published"
                        ),
                    )
                    if execution_id not in self._active:
                        completed.append(execution_id)
                elif cancelling or timed_out:
                    self._settle(
                        active,
                        observation,
                        fallback=(
                            ExecutionConclusion.TIMED_OUT
                            if timed_out
                            else ExecutionConclusion.CANCELLED
                        ),
                        stop_reason=(
                            "execution deadline reached"
                            if timed_out
                            else "run cancellation requested"
                        ),
                    )
                    if execution_id not in self._active:
                        completed.append(execution_id)
                elif observation.state in {"exited", "stopped", "absent"}:
                    self._settle(
                        active,
                        observation,
                        fallback=ExecutionConclusion.INFRASTRUCTURE_FAILED,
                        stop_reason="execution exited without a complete package",
                    )
                    if execution_id not in self._active:
                        completed.append(execution_id)
                else:
                    running.append(execution_id)
            except Exception as error:
                failures.append(
                    {
                        "execution_id": execution_id,
                        "error_type": type(error).__name__,
                    }
                )
        return {
            "running_execution_ids": running,
            "completed_execution_ids": completed,
            "failures": failures,
        }

    def cancel_run(
        self, *, run_id: str, actor: str, reason: str, operation_id: str
    ) -> dict[str, object]:
        result = self.store.request_cancel(
            run_id,
            actor=actor,
            reason=reason,
            operation_id=operation_id,
        )
        before = set(self._active)
        heartbeat = self.heartbeat()
        completed = [
            execution_id
            for execution_id in result.get("active_execution_ids", ())
            if execution_id in before and execution_id not in self._active
        ]
        unresolved = [
            execution_id
            for execution_id in result.get("active_execution_ids", ())
            if execution_id in self._active
        ]
        return {
            **result,
            "cancelled_execution_ids": completed,
            "unresolved_execution_ids": unresolved,
            "supervision_failures": heartbeat["failures"],
        }


class TestdEngineLoop:
    """Periodic schema-v8 supervision with no lease or replay turns."""

    def __init__(
        self,
        engine: TestdEngine,
        *,
        interval_seconds: float = 1.0,
        launch_batch: int = 64,
    ) -> None:
        if not isinstance(engine, TestdEngine):
            raise TestStoreContractError("engine is invalid")
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or not 0.05 <= float(interval_seconds) <= 60
        ):
            raise TestStoreContractError("interval_seconds is invalid")
        if type(launch_batch) is not int or not 1 <= launch_batch <= 1_000:
            raise TestStoreContractError("launch_batch is invalid")
        self.engine = engine
        self.interval_seconds = float(interval_seconds)
        self.launch_batch = launch_batch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_result: Mapping[str, object] | None = None
        self.last_error: Exception | None = None

    def run_once(self) -> Mapping[str, object]:
        heartbeat = self.engine.heartbeat()
        schedule = self.engine.schedule(launch_batch=self.launch_batch)
        result = {"heartbeat": heartbeat, "schedule": schedule}
        self.last_result = result
        self.last_error = None
        return result

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def run() -> None:
            while not self._stop.wait(self.interval_seconds):
                try:
                    self.run_once()
                except Exception as error:  # pragma: no cover - defensive daemon loop.
                    self.last_error = error

        self._thread = threading.Thread(
            target=run,
            name="devcoordinator-testd",
            daemon=True,
        )
        self._thread.start()

    def serve_forever(self) -> None:
        self.start()
        while not self._stop.wait(self.interval_seconds):
            pass

    def close(self, *, timeout: float = 10.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                raise TestStoreConflict("testd loop did not stop within its bound")
        self._thread = None


__all__ = [
    "BrokerLaunchTicket",
    "BrokerLaunchTicketIssuer",
    "RunnerHandle",
    "RunnerLauncher",
    "RunnerObservation",
    "RunnerResultPackage",
    "RuntimeRequestSubmitter",
    "TESTD_RUNNER_SCHEMA_VERSION",
    "TestdEngine",
    "TestdEngineLoop",
    "TestdLaunchAdapter",
    "TransientRunnerRequest",
]
