"""Separated durable state for the universal asynchronous test harness.

The authority store deliberately does not import this module.  Test plans,
current plans, runs, bounded results, and attempt journals live in their own
SQLite/WAL database so test ingestion cannot extend an authority transaction.

Schema creation is explicit through :meth:`UniversalTestStore.create`.  Normal
service startup uses :meth:`UniversalTestStore.open`, which validates the
existing schema without creating or migrating anything.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from types import MappingProxyType
from typing import Any, Callable, Generator, Iterable, Mapping, Sequence
import uuid

from .universal_test_contract import (
    SourceMode,
    deterministic_fingerprint,
)
from .universal_test_planner import TestPlan
from .store import refuse_symlink_components


TEST_STORE_SCHEMA_VERSION = 7
DEFAULT_BUSY_TIMEOUT_MS = 5_000
DEFAULT_LEASE_SECONDS = 30
# Pending launch reconciliation may use the caller's full one-hour launch
# deadline. The lease covers that deadline plus one ordinary heartbeat.
MAX_LEASE_SECONDS = 3_630
MAX_RESULT_CHUNK_BYTES = 256 * 1024
MAX_CASES_PER_CHUNK = 500
MAX_FAILURES_PER_CHUNK = 64
MAX_ARTIFACTS_PER_CHUNK = 64
MAX_EVENT_DETAIL_BYTES = 16 * 1024
MAX_RUN_LEASE_EXPIRY_EVIDENCE = 64
MAX_EXPIRED_ATTEMPTS_PER_REAP = 128
MAX_NONTERMINAL_RUNS_PER_RECONCILE = 10_000
DEFAULT_MEMORY_BOOTSTRAP_MIB = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_ACTIVE_RUN_STATES = ("queued", "running", "cancelling", "superseding")
_RUN_STATES = (
    *_ACTIVE_RUN_STATES,
    "succeeded",
    "failed",
    "timed_out",
    "cancelled",
    "incomplete",
    "abandoned",
    "superseded",
)
_ACTIVE_ATTEMPT_STATES = ("leased", "running")
_TERMINAL_TARGET_STATES = (
    "succeeded",
    "test_failed",
    "infrastructure_failed",
    "timed_out",
    "cancelled",
    "incomplete",
    "abandoned",
    "superseded",
)
_LEASE_EXPIRY_REASONS = {
    "leased": "lease_expired_before_launch",
    "running": "running_heartbeat_lost",
}


class TestStoreError(RuntimeError):
    """Base error for the isolated test store."""


class TestStoreContractError(TestStoreError):
    """Caller supplied malformed or unsafe test-plane data."""


class TestStoreConflict(TestStoreError):
    """A request conflicts with immutable or generation-fenced state."""


class TestStoreSecurityError(TestStoreConflict):
    """The test store path or filesystem object shape is unsafe."""


class TestStoreNotFound(TestStoreError):
    """An exact test-plane entity does not exist."""


class FailureClassification(str, Enum):
    TEST_FAILURE = "test_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    INCOMPLETE_REPORTING = "incomplete_reporting"
    ABANDONMENT = "abandonment"
    SUPERSEDED = "superseded"


class AttemptConclusion(str, Enum):
    SUCCEEDED = "succeeded"
    TEST_FAILED = "test_failed"
    INFRASTRUCTURE_FAILED = "infrastructure_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"
    ABANDONED = "abandoned"
    SUPERSEDED = "superseded"


_CONCLUSION_CLASSIFICATION: Mapping[AttemptConclusion, FailureClassification | None] = {
    AttemptConclusion.SUCCEEDED: None,
    AttemptConclusion.TEST_FAILED: FailureClassification.TEST_FAILURE,
    AttemptConclusion.INFRASTRUCTURE_FAILED: FailureClassification.INFRASTRUCTURE_FAILURE,
    AttemptConclusion.TIMED_OUT: FailureClassification.TIMEOUT,
    AttemptConclusion.CANCELLED: FailureClassification.CANCELLATION,
    AttemptConclusion.INCOMPLETE: FailureClassification.INCOMPLETE_REPORTING,
    AttemptConclusion.ABANDONED: FailureClassification.ABANDONMENT,
    AttemptConclusion.SUPERSEDED: FailureClassification.SUPERSEDED,
}


def _lease_expiry_reason(previous_state: object) -> str:
    reason = _LEASE_EXPIRY_REASONS.get(str(previous_state))
    if reason is None:
        raise TestStoreConflict("lease-expiry evidence has an invalid prior state")
    return reason


def _test_store_path(path: Path | str | os.PathLike[str]) -> Path:
    candidate = Path(os.path.abspath(os.fspath(path)))
    if not candidate.is_absolute():  # defensive: ``abspath`` must be absolute
        raise TestStoreSecurityError("test store path must be absolute")
    return candidate


def _local_execution_uid(_expected_uid: int | None) -> int:
    """Return attribution only; Unix ownership is not local authorization.

    ``expected_uid`` remains accepted for callers compiled against the former
    multi-account trust model.  All accounts on this server belong to one
    developer, so the compatibility value must never gate opening the shared
    test store.  The effective UID is retained only for execution attribution.
    """

    return os.geteuid()


def _refuse_test_store_symlinks(
    path: Path, *, allow_missing_leaf: bool = False
) -> None:
    try:
        refuse_symlink_components(path, allow_missing_leaf=allow_missing_leaf)
    except (FileNotFoundError, PermissionError) as error:
        raise TestStoreSecurityError(
            "test store path must not contain a symbolic link"
        ) from error


def _validate_test_store_parent(path: Path) -> None:
    _refuse_test_store_symlinks(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise TestStoreSecurityError(
            "test store parent directory does not exist"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TestStoreSecurityError("test store parent must be a real directory")


def _validate_test_store_file(path: Path) -> os.stat_result:
    _refuse_test_store_symlinks(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise TestStoreNotFound("test store does not exist") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TestStoreSecurityError("test store must be a real regular file")
    return metadata


def _validate_test_store_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        try:
            _refuse_test_store_symlinks(sidecar)
        except TestStoreSecurityError:
            # SQLite may remove an unneeded WAL/SHM file between the presence
            # check and component walk. Absence is safe; an extant or dangling
            # symlink still fails closed.
            if not sidecar.exists() and not sidecar.is_symlink():
                continue
            raise
        try:
            metadata = sidecar.lstat()
        except FileNotFoundError:
            # The same benign last-reader/last-writer sidecar race may occur
            # after the component walk. The protected parent and database file
            # are validated independently on every connection.
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TestStoreSecurityError(
                "test store SQLite sidecar is not a regular file"
            )


def _sidecar_presence(path: Path) -> dict[Path, bool]:
    return {
        Path(f"{path}{suffix}"): (
            Path(f"{path}{suffix}").exists()
            or Path(f"{path}{suffix}").is_symlink()
        )
        for suffix in ("-wal", "-shm")
    }


def _validate_new_test_store_sidecars(presence: Mapping[Path, bool]) -> None:
    """Validate SQLite-created sidecar shape without Unix metadata gates."""

    for sidecar, existed in presence.items():
        if existed or (not sidecar.exists() and not sidecar.is_symlink()):
            continue
        _refuse_test_store_symlinks(sidecar)
        metadata = sidecar.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TestStoreSecurityError(
                "new test store SQLite sidecar has an unsafe identity"
            )


@dataclass(frozen=True)
class TargetResources:
    estimated_seconds: float = 1.0
    shard_count: int = 1
    max_attempts: int = 2
    worktree_key: str | None = None
    exclusive_resources: tuple[str, ...] = ()


@dataclass(frozen=True)
class SubmissionResult:
    run_id: str
    state: str
    deduplicated: bool
    deduplicated_run_id: str | None
    console_path: str


@dataclass(frozen=True)
class LeaseGrant:
    attempt_id: str
    target_id: str
    run_id: str
    target_name: str
    shard_index: int
    shard_count: int
    generation: int
    lease_owner: str
    lease_expires_at: float


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    display_name: str
    status: str
    duration_seconds: float
    location: str | None = None


@dataclass(frozen=True)
class FailureRecord:
    failure_id: str
    classification: FailureClassification
    message: str
    case_id: str | None = None
    location: str | None = None
    artifact_id: str | None = None


@dataclass(frozen=True)
class ArtifactMetadata:
    artifact_id: str
    kind: str
    storage_handle: str
    sha256: str
    size_bytes: int
    verified: bool = True


@dataclass(frozen=True)
class AttemptResultChunk:
    chunk_id: str
    chunk_index: int
    cases: tuple[CaseResult, ...] = ()
    failures: tuple[FailureRecord, ...] = ()
    artifacts: tuple[ArtifactMetadata, ...] = ()
    reporter_complete: bool = False


@dataclass(frozen=True)
class RunnableTarget:
    target_id: str
    run_id: str
    repository_id: str
    owner_uid: int
    priority: int
    queued_at: float
    target_name: str
    wave_index: int
    shard_index: int
    shard_count: int
    estimated_seconds: float
    worktree_key: str
    source_mode: str
    exclusive_resources: tuple[str, ...]
    memory_estimate_mib: int = 512
    memory_estimate_source: str = "fixed_default"
    memory_sample_count: int = 0


_SCHEMA = r"""
CREATE TABLE test_store_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    store_generation TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;

CREATE TABLE test_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    source_mode TEXT NOT NULL CHECK(source_mode IN ('live', 'immutable')),
    content_fingerprint TEXT NOT NULL,
    manifest_fingerprint TEXT NOT NULL,
    original_root TEXT NOT NULL,
    temporary_root TEXT,
    complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
    provenance_json TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;

CREATE TABLE test_plans (
    plan_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    execution_fingerprint TEXT NOT NULL,
    manifest_fingerprint TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES test_snapshots(snapshot_id),
    source_mode TEXT NOT NULL CHECK(source_mode IN ('live', 'immutable')),
    source_fingerprint TEXT NOT NULL,
    reusable INTEGER NOT NULL CHECK(reusable IN (0, 1)),
    plan_json TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;

CREATE TABLE test_runs (
    run_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES test_plans(plan_id),
    repository_id TEXT NOT NULL,
    owner_uid INTEGER NOT NULL CHECK(owner_uid >= 0),
    actor TEXT NOT NULL,
    intent TEXT NOT NULL,
    source_mode TEXT NOT NULL CHECK(source_mode IN ('live', 'immutable')),
    source_fingerprint TEXT NOT NULL,
    execution_fingerprint TEXT NOT NULL,
    eligible_target_count INTEGER NOT NULL CHECK(eligible_target_count >= 0),
    selected_target_count INTEGER NOT NULL CHECK(selected_target_count >= 0),
    state TEXT NOT NULL CHECK(state IN (
      'queued', 'running', 'cancelling', 'superseding', 'succeeded', 'failed',
      'timed_out', 'cancelled', 'incomplete', 'abandoned', 'superseded'
    )),
    conclusion TEXT,
    failure_classification TEXT,
    priority INTEGER NOT NULL,
    queued_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    cancel_reason TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    CHECK(selected_target_count <= eligible_target_count)
) STRICT;

CREATE UNIQUE INDEX one_active_immutable_execution
ON test_runs(execution_fingerprint)
WHERE source_mode = 'immutable'
  AND state IN ('queued', 'running', 'cancelling', 'superseding');
CREATE INDEX test_runs_repository_time
ON test_runs(repository_id, queued_at DESC, run_id);

CREATE TABLE test_run_targets (
    target_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    target_name TEXT NOT NULL,
    wave_index INTEGER NOT NULL CHECK(wave_index >= 0),
    shard_index INTEGER NOT NULL CHECK(shard_index >= 0),
    shard_count INTEGER NOT NULL CHECK(shard_count > 0),
    state TEXT NOT NULL CHECK(state IN (
      'queued', 'leased', 'running', 'succeeded', 'test_failed',
      'infrastructure_failed', 'timed_out', 'cancelled', 'incomplete',
      'abandoned', 'superseded'
    )),
    estimated_seconds REAL NOT NULL CHECK(estimated_seconds > 0),
    max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
    worktree_key TEXT NOT NULL,
    exclusive_resources_json TEXT NOT NULL,
    current_attempt_id TEXT,
    wait_code TEXT,
    wait_since REAL,
    wait_required_mib INTEGER,
    wait_available_mib INTEGER,
    wait_reserve_mib INTEGER,
    wait_observed_at REAL,
    wait_source TEXT,
    queued_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    UNIQUE(run_id, target_name, shard_index)
) STRICT;
CREATE INDEX test_run_targets_schedule
ON test_run_targets(state, wave_index, queued_at, target_id);

CREATE TABLE test_target_attempts (
    attempt_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES test_run_targets(target_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    state TEXT NOT NULL CHECK(state IN (
      'leased', 'running', 'succeeded', 'test_failed',
      'infrastructure_failed', 'timed_out', 'cancelled', 'incomplete',
      'abandoned', 'superseded'
    )),
    generation INTEGER NOT NULL CHECK(generation > 0),
    memory_commitment_mib INTEGER NOT NULL CHECK(memory_commitment_mib > 0),
    lease_owner TEXT NOT NULL,
    lease_token_sha256 TEXT NOT NULL,
    lease_expires_at REAL NOT NULL,
    heartbeat_at REAL NOT NULL,
    queued_at REAL NOT NULL,
    launched_at REAL,
    launch_ack_id TEXT,
    terminal_operation_id TEXT,
    terminal_fingerprint TEXT,
    conclusion TEXT,
    failure_classification TEXT,
    duration_seconds REAL,
    peak_memory_bytes INTEGER CHECK(
      peak_memory_bytes IS NULL OR peak_memory_bytes >= 0
    ),
    cpu_seconds REAL CHECK(cpu_seconds IS NULL OR cpu_seconds >= 0),
    passed_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    reporter_complete INTEGER NOT NULL DEFAULT 0 CHECK(reporter_complete IN (0, 1)),
    started_at REAL,
    finished_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(target_id, attempt_number),
    UNIQUE(terminal_operation_id)
) STRICT;
CREATE INDEX test_target_attempts_lease
ON test_target_attempts(state, lease_expires_at, attempt_id);

CREATE TABLE test_result_chunks (
    attempt_id TEXT NOT NULL REFERENCES test_target_attempts(attempt_id) ON DELETE CASCADE,
    chunk_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
    fingerprint TEXT NOT NULL,
    encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes >= 0),
    case_count INTEGER NOT NULL CHECK(case_count >= 0),
    failure_count INTEGER NOT NULL CHECK(failure_count >= 0),
    artifact_count INTEGER NOT NULL CHECK(artifact_count >= 0),
    reporter_complete INTEGER NOT NULL CHECK(reporter_complete IN (0, 1)),
    created_at REAL NOT NULL,
    PRIMARY KEY(attempt_id, chunk_id),
    UNIQUE(attempt_id, chunk_index)
) STRICT;

CREATE TABLE test_failures (
    failure_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES test_target_attempts(attempt_id) ON DELETE CASCADE,
    chunk_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    case_id TEXT,
    message TEXT NOT NULL,
    location TEXT,
    artifact_id TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY(attempt_id, chunk_id)
      REFERENCES test_result_chunks(attempt_id, chunk_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX test_failures_attempt ON test_failures(attempt_id, created_at, failure_id);

CREATE TABLE test_artifacts (
    artifact_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES test_target_attempts(attempt_id) ON DELETE CASCADE,
    chunk_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    storage_handle TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    verified INTEGER NOT NULL CHECK(verified IN (0, 1)),
    created_at REAL NOT NULL,
    FOREIGN KEY(attempt_id, chunk_id)
      REFERENCES test_result_chunks(attempt_id, chunk_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX test_artifacts_attempt ON test_artifacts(attempt_id, created_at, artifact_id);

CREATE TABLE test_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT,
    attempt_id TEXT,
    detail_json TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;
CREATE INDEX test_events_cursor ON test_events(repository_id, event_id);

CREATE TABLE test_mutation_journal (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;

"""

def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


_STORED_PLAN_RESOURCES_FIELD = "_coordinator_target_resources"


def _attempt_progress_document(value: object) -> dict[str, object]:
    """Normalize retained progress across the initial and expanded schemas."""

    if not isinstance(value, Mapping):
        raise TestStoreContractError("retained attempt output progress is invalid")
    legacy_fields = {
        "stdout_bytes",
        "stderr_bytes",
        "current_memory_bytes",
        "last_output_at",
        "observed_at",
    }
    current_fields = legacy_fields | {
        "stdout_retained_bytes",
        "stderr_retained_bytes",
        "stdout_truncated",
        "stderr_truncated",
    }
    if set(value) == legacy_fields:
        stdout_bytes = value["stdout_bytes"]
        stderr_bytes = value["stderr_bytes"]
        if type(stdout_bytes) is not int or type(stderr_bytes) is not int:
            raise TestStoreContractError(
                "retained attempt output progress is invalid"
            )
        normalized = {
            **dict(value),
            "stdout_retained_bytes": min(stdout_bytes, 4 * 1024 * 1024),
            "stderr_retained_bytes": min(stderr_bytes, 4 * 1024 * 1024),
            # The initial schema measured retained files only, so reaching the
            # cap did not prove whether additional bytes were observed.
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
    elif set(value) == current_fields:
        normalized = dict(value)
    else:
        raise TestStoreContractError("retained attempt output progress is invalid")
    stdout_bytes = normalized["stdout_bytes"]
    stderr_bytes = normalized["stderr_bytes"]
    stdout_retained = normalized["stdout_retained_bytes"]
    stderr_retained = normalized["stderr_retained_bytes"]
    stdout_truncated = normalized["stdout_truncated"]
    stderr_truncated = normalized["stderr_truncated"]
    current_memory = normalized["current_memory_bytes"]
    last_output_at = normalized["last_output_at"]
    observed_at = normalized["observed_at"]
    if (
        type(stdout_bytes) is not int
        or type(stderr_bytes) is not int
        or not 0 <= stdout_bytes <= (1 << 63) - 1
        or not 0 <= stderr_bytes <= (1 << 63) - 1
        or type(stdout_retained) is not int
        or type(stderr_retained) is not int
        or not 0 <= stdout_retained <= 4 * 1024 * 1024
        or not 0 <= stderr_retained <= 4 * 1024 * 1024
        or stdout_retained > stdout_bytes
        or stderr_retained > stderr_bytes
        or type(stdout_truncated) is not bool
        or type(stderr_truncated) is not bool
        or stdout_truncated != (stdout_bytes > stdout_retained)
        or stderr_truncated != (stderr_bytes > stderr_retained)
        or (
            current_memory is not None
            and (
                type(current_memory) is not int
                or not 0 <= current_memory <= (1 << 63) - 1
            )
        )
        or isinstance(observed_at, bool)
        or not isinstance(observed_at, (int, float))
        or not math.isfinite(float(observed_at))
        or float(observed_at) < 0
        or (
            last_output_at is not None
            and (
                isinstance(last_output_at, bool)
                or not isinstance(last_output_at, (int, float))
                or not math.isfinite(float(last_output_at))
                or float(last_output_at) < 0
            )
        )
    ):
        raise TestStoreContractError("retained attempt output progress is invalid")
    return normalized


def _stored_plan_parts(
    plan_json: object,
) -> tuple[dict[str, object], Mapping[str, object] | None]:
    """Decode one retained plan plus its same-schema durable launch resources."""

    try:
        raw = json.loads(str(plan_json))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise TestStoreContractError("stored test plan JSON is invalid") from error
    if not isinstance(raw, dict):
        raise TestStoreContractError("stored test plan is invalid")
    resources = raw.pop(_STORED_PLAN_RESOURCES_FIELD, None)
    if resources is not None and not isinstance(resources, Mapping):
        raise TestStoreContractError("stored test plan resources are invalid")
    return raw, resources


def _stored_plan_dependencies(plan_json: object) -> dict[str, tuple[str, ...]]:
    """Read exact dependencies from a validated retained plan document."""

    raw, _resources = _stored_plan_parts(plan_json)
    selected_raw = raw.get("selected_targets")
    selection_raw = raw.get("selection")
    if (
        not isinstance(selected_raw, list)
        or not isinstance(selection_raw, Mapping)
        or any(not isinstance(name, str) for name in selected_raw)
    ):
        raise TestStoreContractError("stored test plan selection is invalid")
    selected = tuple(str(name) for name in selected_raw)
    dependencies_raw = raw.get("dependencies")
    if dependencies_raw is None:
        dependencies: dict[str, tuple[str, ...]] = {}
        for target in selected:
            reasons = selection_raw.get(target)
            if not isinstance(reasons, list):
                raise TestStoreContractError(
                    "stored legacy test plan selection is invalid"
                )
            dependencies[target] = tuple(
                sorted(
                    str(reason).split(":", 1)[1]
                    for reason in reasons
                    if isinstance(reason, str)
                    and reason.startswith("dependent-of:")
                )
            )
    else:
        if not isinstance(dependencies_raw, Mapping) or set(
            dependencies_raw
        ) != set(selected):
            raise TestStoreContractError("stored test plan dependencies are invalid")
        dependencies = {}
        for target in selected:
            values = dependencies_raw[target]
            if not isinstance(values, list) or any(
                not isinstance(value, str) for value in values
            ):
                raise TestStoreContractError(
                    "stored test plan dependency list is invalid"
                )
            dependencies[target] = tuple(str(value) for value in values)
    for target, values in dependencies.items():
        if (
            tuple(sorted(set(values))) != values
            or target in values
            or not set(values).issubset(selected)
        ):
            raise TestStoreContractError("stored test plan dependencies are invalid")
    return dependencies


def _target_dependencies_succeeded(
    *,
    target_name: str,
    dependencies: Mapping[str, tuple[str, ...]],
    states: Mapping[str, Sequence[str]],
) -> bool:
    return all(
        states.get(dependency)
        and all(state == "succeeded" for state in states[dependency])
        for dependency in dependencies.get(target_name, ())
    )


def _bounded_text(
    field: str,
    value: object,
    *,
    maximum: int = 1024,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise TestStoreContractError(f"{field} must be text")
    if (not value and not allow_empty) or len(value) > maximum or "\x00" in value:
        raise TestStoreContractError(f"{field} must be bounded text")
    return value


def _single_line(field: str, value: object, *, maximum: int = 1024) -> str:
    text = _bounded_text(field, value, maximum=maximum)
    if "\r" in text or "\n" in text:
        raise TestStoreContractError(f"{field} must be single-line text")
    return text


def _safe_id(field: str, value: object) -> str:
    text = _single_line(field, value, maximum=256)
    if _SAFE_ID.fullmatch(text) is None:
        raise TestStoreContractError(f"{field} contains unsupported characters")
    return text


def _operation_id(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError) as error:
        raise TestStoreContractError("operation_id must be a UUID") from error


def _sha256(field: str, value: object) -> str:
    text = _single_line(field, value, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise TestStoreContractError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _positive_int(field: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TestStoreContractError(f"{field} must be between 1 and {maximum}")
    return value


def _finite_nonnegative(field: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TestStoreContractError(f"{field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise TestStoreContractError(f"{field} must be finite and non-negative")
    return number


def _now(clock: Callable[[], float]) -> float:
    return _finite_nonnegative("clock", clock())


class UniversalTestStore:
    """Transactional test-plane persistence with exact attempt fencing."""

    def __init__(
        self,
        path: Path,
        *,
        expected_uid: int | None = None,
        clock: Callable[[], float] | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self.path = _test_store_path(path)
        self.expected_uid = _local_execution_uid(expected_uid)
        self._clock = time.time if clock is None else clock
        self.busy_timeout_ms = _positive_int(
            "busy_timeout_ms", busy_timeout_ms, maximum=60_000
        )

    def current_time(self) -> float:
        """Return the store's validated clock value for bounded live reads."""

        return _now(self._clock)

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        expected_uid: int | None = None,
        clock: Callable[[], float] | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> "UniversalTestStore":
        """Explicitly create the current schema; never migrate an old one."""

        store = cls(
            path,
            expected_uid=expected_uid,
            clock=clock,
            busy_timeout_ms=busy_timeout_ms,
        )
        _validate_test_store_parent(store.path.parent)
        _refuse_test_store_symlinks(store.path, allow_missing_leaf=True)
        if store.path.exists():
            raise TestStoreConflict("test store already exists; implicit migration denied")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(store.path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise TestStoreSecurityError("new test store has an unsafe identity")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        before = _validate_test_store_file(store.path)
        sidecars_before = _sidecar_presence(store.path)
        connection = sqlite3.connect(
            str(store.path), isolation_level=None, timeout=busy_timeout_ms / 1000
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
            _validate_new_test_store_sidecars(sidecars_before)
            # ``executescript`` commits any transaction opened before it.  Put
            # the explicit boundary inside the script so schema plus metadata
            # remain one all-or-nothing offline creation transaction.
            connection.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            created_at = _now(store._clock)
            generation = secrets.token_hex(32)
            connection.execute(
                "INSERT INTO test_store_metadata VALUES (1, ?, ?, ?, ?)",
                (
                    TEST_STORE_SCHEMA_VERSION,
                    hashlib.sha256(_SCHEMA.encode("utf-8")).hexdigest(),
                    generation,
                    created_at,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()
            for candidate in (
                store.path,
                Path(str(store.path) + "-wal"),
                Path(str(store.path) + "-shm"),
            ):
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass
            raise
        finally:
            if connection:
                connection.close()
        after = _validate_test_store_file(store.path)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise TestStoreSecurityError("test store identity changed during creation")
        _validate_test_store_sidecars(store.path)
        store.verify()
        return store

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_uid: int | None = None,
        clock: Callable[[], float] | None = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        verify_integrity: bool = True,
    ) -> "UniversalTestStore":
        if type(verify_integrity) is not bool:
            raise TestStoreContractError("verify_integrity must be boolean")
        store = cls(
            path,
            expected_uid=expected_uid,
            clock=clock,
            busy_timeout_ms=busy_timeout_ms,
        )
        if verify_integrity:
            store.verify()
        else:
            # Service startup must be bounded independently of retained test
            # history size. Health proves the exact schema/read boundary;
            # verify_writable separately proves the rolled-back write path.
            # Full PRAGMA quick_check remains the default for explicit opens,
            # migrations, backup/restore, and diagnostic verification.
            store.health()
        return store

    def _connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        _validate_test_store_parent(self.path.parent)
        before = _validate_test_store_file(self.path)
        _validate_test_store_sidecars(self.path)
        sidecars_before = _sidecar_presence(self.path)
        if readonly:
            connection = sqlite3.connect(
                f"file:{self.path}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=self.busy_timeout_ms / 1000,
            )
        else:
            connection = sqlite3.connect(
                str(self.path),
                isolation_level=None,
                timeout=self.busy_timeout_ms / 1000,
            )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                raise TestStoreSecurityError(
                    "test store foreign-key enforcement could not be enabled"
                )
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema = OFF")
            _validate_new_test_store_sidecars(sidecars_before)
            after = _validate_test_store_file(self.path)
            _validate_test_store_sidecars(self.path)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise TestStoreSecurityError(
                    "test store identity changed while opening"
                )
            return connection
        except BaseException:
            connection.close()
            raise

    def verify(self) -> dict[str, object]:
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                "SELECT * FROM test_store_metadata WHERE singleton = 1"
            ).fetchone()
            if row is None or int(row["schema_version"]) != TEST_STORE_SCHEMA_VERSION:
                raise TestStoreConflict(
                    "test store schema is unsupported; initialize a fresh current store"
                )
            expected_schema = hashlib.sha256(_SCHEMA.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(str(row["schema_fingerprint"]), expected_schema):
                raise TestStoreConflict("test store schema fingerprint is invalid")
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if integrity != "ok":
                raise TestStoreConflict(f"test store integrity check failed: {integrity}")
            return {
                "schema_version": int(row["schema_version"]),
                "schema_fingerprint": str(row["schema_fingerprint"]),
                "store_generation": str(row["store_generation"]),
                "created_at": float(row["created_at"]),
            }
        except sqlite3.DatabaseError as error:
            raise TestStoreConflict("test store is malformed or unavailable") from error
        finally:
            connection.close()

    def verify_writable(self) -> None:
        """Prove that a write transaction can start without persisting data."""

        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ROLLBACK")
        except sqlite3.DatabaseError as error:
            if connection is not None and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    pass
            raise TestStoreConflict("test store is not writable") from error
        finally:
            if connection is not None:
                connection.close()

    def health(self) -> dict[str, object]:
        """Return a bounded readiness read without running an integrity scan.

        Startup and fresh-store readiness use :meth:`verify`, including
        ``PRAGMA quick_check``.  The serving health path must remain cheap
        while result chunks are being committed, but still proves the exact
        protected database and expected schema generation can be read.
        """

        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                """
                SELECT schema_version, schema_fingerprint, store_generation
                FROM test_store_metadata WHERE singleton = 1
                """
            ).fetchone()
            expected_schema = hashlib.sha256(_SCHEMA.encode("utf-8")).hexdigest()
            if (
                row is None
                or int(row["schema_version"]) != TEST_STORE_SCHEMA_VERSION
                or not hmac.compare_digest(
                    str(row["schema_fingerprint"]), expected_schema
                )
            ):
                raise TestStoreConflict(
                    "test store schema is unsupported; initialize a fresh current store"
                )
            return {
                "schema_version": int(row["schema_version"]),
                "store_generation": str(row["store_generation"]),
            }
        except sqlite3.DatabaseError as error:
            raise TestStoreConflict("test store is malformed or unavailable") from error
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _generation(self, connection: sqlite3.Connection) -> str:
        row = connection.execute(
            "SELECT store_generation FROM test_store_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise TestStoreConflict("test store metadata is missing")
        return str(row[0])

    def _mutation_replay(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        operation_kind: str,
        request_fingerprint: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM test_mutation_journal WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return None
        if (
            str(row["operation_kind"]) != operation_kind
            or str(row["request_fingerprint"]) != request_fingerprint
        ):
            raise TestStoreConflict("operation_id is bound to a different mutation")
        return json.loads(str(row["result_json"]))

    def _record_mutation(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        operation_kind: str,
        request_fingerprint: str,
        result: Mapping[str, object],
        created_at: float,
    ) -> None:
        connection.execute(
            """
            INSERT INTO test_mutation_journal(
                operation_id, operation_kind, request_fingerprint,
                result_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                operation_kind,
                request_fingerprint,
                _canonical_json(result),
                created_at,
            ),
        )

    def _event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        repository_id: str,
        run_id: str | None,
        attempt_id: str | None,
        detail: Mapping[str, object],
        created_at: float,
    ) -> None:
        encoded = _canonical_json(detail)
        if len(encoded.encode("utf-8")) > MAX_EVENT_DETAIL_BYTES:
            raise TestStoreContractError("event detail exceeds its byte bound")
        connection.execute(
            """
            INSERT INTO test_events(
                event_type, repository_id, run_id, attempt_id,
                detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_type, repository_id, run_id, attempt_id, encoded, created_at),
        )

    def submit_plan(
        self,
        plan: TestPlan,
        *,
        operation_id: str,
        actor: str,
        owner_uid: int,
        priority: int = 0,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> SubmissionResult:
        """Submit asynchronously and deduplicate only an active immutable job."""

        if not isinstance(plan, TestPlan):
            raise TestStoreContractError("plan must be a validated TestPlan")
        operation_id = _operation_id(operation_id)
        actor = _single_line("actor", actor, maximum=256)
        if type(owner_uid) is not int or owner_uid < 0:
            raise TestStoreContractError("owner_uid must be a non-negative integer")
        if type(priority) is not int or not -100 <= priority <= 100:
            raise TestStoreContractError("priority must be between -100 and 100")
        resources = self._normalize_resources(plan, target_resources or {})
        request_document = {
            "plan_fingerprint": plan.fingerprint,
            "actor": actor,
            "owner_uid": owner_uid,
            "priority": priority,
            "resources": {
                name: self._resource_document(resource)
                for name, resource in sorted(resources.items())
            },
        }
        request_fingerprint = deterministic_fingerprint(request_document)
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="submit",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return SubmissionResult(**replay)
            self._upsert_snapshot_and_plan(
                connection,
                plan=plan,
                created_at=timestamp,
                target_resources=resources,
            )
            existing = None
            if plan.source.mode is SourceMode.IMMUTABLE:
                existing = connection.execute(
                    f"""
                    SELECT run_id, state FROM test_runs
                    WHERE execution_fingerprint = ? AND source_mode = 'immutable'
                      AND state IN ({','.join('?' for _ in _ACTIVE_RUN_STATES)})
                    ORDER BY created_at, run_id LIMIT 1
                    """,
                    (plan.execution_fingerprint, *_ACTIVE_RUN_STATES),
                ).fetchone()
            if existing is not None:
                result = SubmissionResult(
                    run_id=str(existing["run_id"]),
                    state=str(existing["state"]),
                    deduplicated=True,
                    deduplicated_run_id=str(existing["run_id"]),
                    console_path=f"/#/tests/runs/{existing['run_id']}",
                )
                document = result.__dict__
                self._record_mutation(
                    connection,
                    operation_id=operation_id,
                    operation_kind="submit",
                    request_fingerprint=request_fingerprint,
                    result=document,
                    created_at=timestamp,
                )
                return result
            run_id = "run-" + hashlib.sha256(
                f"{operation_id}\0{request_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
            initial_state = "queued" if plan.selected_targets else "succeeded"
            initial_conclusion = None if plan.selected_targets else "succeeded"
            initial_finished_at = None if plan.selected_targets else timestamp
            connection.execute(
                """
                INSERT INTO test_runs(
                    run_id, plan_id, repository_id, owner_uid, actor, intent,
                    source_mode, source_fingerprint, execution_fingerprint,
                    eligible_target_count, selected_target_count,
                    state, conclusion, priority, queued_at, finished_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    plan.plan_id,
                    plan.repository_id,
                    owner_uid,
                    actor,
                    plan.intent,
                    plan.source.mode.value,
                    plan.source.content_fingerprint,
                    plan.execution_fingerprint,
                    len(plan.eligible_targets),
                    len(plan.selected_targets),
                    initial_state,
                    initial_conclusion,
                    priority,
                    timestamp,
                    initial_finished_at,
                    timestamp,
                    timestamp,
                ),
            )
            wave_by_target = {
                name: wave_index
                for wave_index, wave in enumerate(plan.dependency_waves)
                for name in wave
            }
            for target_name in plan.selected_targets:
                resource = resources[target_name]
                for shard_index in range(resource.shard_count):
                    target_id = "target-" + hashlib.sha256(
                        f"{run_id}\0{target_name}\0{shard_index}".encode("utf-8")
                    ).hexdigest()[:32]
                    connection.execute(
                        """
                        INSERT INTO test_run_targets(
                            target_id, run_id, target_name, wave_index,
                            shard_index, shard_count, state,
                            estimated_seconds, max_attempts,
                            worktree_key, exclusive_resources_json, queued_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)
                        """,
                        (
                            target_id,
                            run_id,
                            target_name,
                            wave_by_target[target_name],
                            shard_index,
                            resource.shard_count,
                            resource.estimated_seconds,
                            resource.max_attempts,
                            resource.worktree_key or plan.source.temporary_root or plan.source.original_root,
                            _canonical_json(list(resource.exclusive_resources)),
                            timestamp,
                        ),
                    )
            result = SubmissionResult(
                run_id=run_id,
                state=initial_state,
                deduplicated=False,
                deduplicated_run_id=None,
                console_path=f"/#/tests/runs/{run_id}",
            )
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="submit",
                request_fingerprint=request_fingerprint,
                result=result.__dict__,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.run_submitted",
                repository_id=plan.repository_id,
                run_id=run_id,
                attempt_id=None,
                detail={
                    "intent": plan.intent,
                    "source_mode": plan.source.mode.value,
                    "target_count": len(plan.selected_targets),
                },
                created_at=timestamp,
            )
            return result

    def register_plan(
        self,
        plan: TestPlan,
        *,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> dict[str, object]:
        """Durably register a validated plan before asynchronous submission."""

        if not isinstance(plan, TestPlan):
            raise TestStoreContractError("plan must be a validated TestPlan")
        resources = (
            None
            if target_resources is None
            else self._normalize_resources(plan, target_resources)
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT fingerprint FROM test_plans WHERE plan_id = ?",
                (plan.plan_id,),
            ).fetchone()
            self._upsert_snapshot_and_plan(
                connection,
                plan=plan,
                created_at=timestamp,
                target_resources=resources,
            )
            return {
                "plan_id": plan.plan_id,
                "fingerprint": plan.fingerprint,
                "repository_id": plan.repository_id,
                "registered": existing is None,
            }

    def _normalize_resources(
        self,
        plan: TestPlan,
        supplied: Mapping[str, TargetResources],
    ) -> dict[str, TargetResources]:
        unknown = sorted(set(supplied) - set(plan.selected_targets))
        if unknown:
            raise TestStoreContractError(
                "target_resources names unselected targets: " + ", ".join(unknown)
            )
        result: dict[str, TargetResources] = {}
        for name in plan.selected_targets:
            resource = supplied.get(name, TargetResources())
            if not isinstance(resource, TargetResources):
                raise TestStoreContractError("target resources must be TargetResources")
            estimated = _finite_nonnegative(
                "estimated_seconds", resource.estimated_seconds
            )
            if estimated <= 0 or estimated > 31_536_000:
                raise TestStoreContractError("estimated_seconds is outside its bound")
            _positive_int("shard_count", resource.shard_count, maximum=256)
            _positive_int("max_attempts", resource.max_attempts, maximum=16)
            worktree = resource.worktree_key
            if worktree is not None:
                worktree = _single_line("worktree_key", worktree, maximum=4096)
            exclusive = tuple(
                sorted(
                    {
                        _safe_id("exclusive_resource", value)
                        for value in resource.exclusive_resources
                    }
                )
            )
            result[name] = TargetResources(
                estimated_seconds=estimated,
                shard_count=resource.shard_count,
                max_attempts=resource.max_attempts,
                worktree_key=worktree,
                exclusive_resources=exclusive,
            )
        return result

    @staticmethod
    def _resource_document(resource: TargetResources) -> dict[str, object]:
        return {
            "estimated_seconds": resource.estimated_seconds,
            "shard_count": resource.shard_count,
            "max_attempts": resource.max_attempts,
            "worktree_key": resource.worktree_key,
            "exclusive_resources": list(resource.exclusive_resources),
        }

    def _upsert_snapshot_and_plan(
        self,
        connection: sqlite3.Connection,
        *,
        plan: TestPlan,
        created_at: float,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> None:
        source = plan.source
        snapshot_id = source.snapshot_id or (
            "live-" + hashlib.sha256(
                f"{source.repository_id}\0{source.content_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
        )
        snapshot_document = {
            "source": source.to_document(),
            "manifest_fingerprint": plan.manifest_fingerprint,
        }
        existing = connection.execute(
            "SELECT * FROM test_snapshots WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        expected_snapshot = (
            source.repository_id,
            source.mode.value,
            source.content_fingerprint,
            plan.manifest_fingerprint,
            source.original_root,
            source.temporary_root,
        )
        if existing is None:
            connection.execute(
                """
                INSERT INTO test_snapshots(
                    snapshot_id, repository_id, source_mode,
                    content_fingerprint, manifest_fingerprint, original_root,
                    temporary_root, complete, provenance_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    snapshot_id,
                    *expected_snapshot,
                    _canonical_json(snapshot_document),
                    created_at,
                ),
            )
        else:
            actual = tuple(
                existing[field]
                for field in (
                    "repository_id",
                    "source_mode",
                    "content_fingerprint",
                    "manifest_fingerprint",
                    "original_root",
                    "temporary_root",
                )
            )
            if actual != expected_snapshot:
                raise TestStoreConflict("snapshot_id is bound to different provenance")
        plan_document = plan.to_document()
        stored_document = dict(plan_document)
        if target_resources is not None:
            stored_document[_STORED_PLAN_RESOURCES_FIELD] = {
                name: self._resource_document(resource)
                for name, resource in sorted(target_resources.items())
            }
        plan_json = _canonical_json(stored_document)
        existing_plan = connection.execute(
            "SELECT * FROM test_plans WHERE plan_id = ?", (plan.plan_id,)
        ).fetchone()
        if existing_plan is None:
            connection.execute(
                """
                INSERT INTO test_plans(
                    plan_id, fingerprint, execution_fingerprint,
                    manifest_fingerprint, repository_id, intent, snapshot_id,
                    source_mode, source_fingerprint, reusable, plan_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.fingerprint,
                    plan.execution_fingerprint,
                    plan.manifest_fingerprint,
                    plan.repository_id,
                    plan.intent,
                    snapshot_id,
                    source.mode.value,
                    source.content_fingerprint,
                    int(plan.reusable),
                    plan_json,
                    created_at,
                ),
            )
        else:
            existing_document, existing_resources = _stored_plan_parts(
                existing_plan["plan_json"]
            )
            if (
                str(existing_plan["fingerprint"]) != plan.fingerprint
                or existing_document != plan_document
            ):
                raise TestStoreConflict("plan_id is bound to a different plan")
            requested_resources = stored_document.get(_STORED_PLAN_RESOURCES_FIELD)
            if requested_resources is not None:
                if existing_resources is None:
                    connection.execute(
                        "UPDATE test_plans SET plan_json = ? WHERE plan_id = ?",
                        (plan_json, plan.plan_id),
                    )
                elif existing_resources != requested_resources:
                    raise TestStoreConflict(
                        "plan_id is bound to different target resources"
                    )

    def runnable_targets(self, *, limit: int = 1_000) -> tuple[RunnableTarget, ...]:
        limit = _positive_int("limit", limit, maximum=10_000)
        connection = self._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid, run.priority,
                       run.state AS run_state, run.source_mode,
                       plan.plan_json
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                JOIN test_plans AS plan ON plan.plan_id = run.plan_id
                WHERE target.state = 'queued'
                  AND run.state IN ('queued', 'running')
                ORDER BY run.priority DESC, target.queued_at, target.target_id
                LIMIT 10000
                """,
            ).fetchall()
            dependencies_by_run: dict[str, dict[str, tuple[str, ...]]] = {}
            states_by_run: dict[str, dict[str, list[str]]] = {}
            for row in rows:
                run_id = str(row["run_id"])
                if run_id in dependencies_by_run:
                    continue
                dependencies_by_run[run_id] = _stored_plan_dependencies(
                    row["plan_json"]
                )
                states: dict[str, list[str]] = {}
                for state_row in connection.execute(
                    """
                    SELECT target_name, state FROM test_run_targets
                    WHERE run_id = ? ORDER BY target_name, shard_index
                    """,
                    (run_id,),
                ):
                    states.setdefault(str(state_row["target_name"]), []).append(
                        str(state_row["state"])
                    )
                states_by_run[run_id] = states
            runnable = [
                self._runnable_target(row)
                for row in rows
                if _target_dependencies_succeeded(
                    target_name=str(row["target_name"]),
                    dependencies=dependencies_by_run[str(row["run_id"])],
                    states=states_by_run[str(row["run_id"])],
                )
            ]
            return tuple(runnable[:limit])
        finally:
            connection.close()

    @staticmethod
    def _runnable_target(row: sqlite3.Row) -> RunnableTarget:
        return RunnableTarget(
            target_id=str(row["target_id"]),
            run_id=str(row["run_id"]),
            repository_id=str(row["repository_id"]),
            owner_uid=int(row["owner_uid"]),
            priority=int(row["priority"]),
            queued_at=float(row["queued_at"]),
            target_name=str(row["target_name"]),
            wave_index=int(row["wave_index"]),
            shard_index=int(row["shard_index"]),
            shard_count=int(row["shard_count"]),
            estimated_seconds=float(row["estimated_seconds"]),
            worktree_key=str(row["worktree_key"]),
            exclusive_resources=tuple(json.loads(row["exclusive_resources_json"])),
            source_mode=str(row["source_mode"]),
            memory_estimate_mib=DEFAULT_MEMORY_BOOTSTRAP_MIB,
            memory_estimate_source="fixed_default",
            memory_sample_count=0,
        )

    def active_allocations(self) -> tuple[dict[str, object], ...]:
        connection = self._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid, run.source_mode,
                       attempt.attempt_id, attempt.state AS attempt_state,
                       attempt.memory_commitment_mib
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                JOIN test_target_attempts AS attempt
                  ON attempt.attempt_id = target.current_attempt_id
                WHERE attempt.state IN ('leased', 'running')
                ORDER BY attempt.created_at, attempt.attempt_id
                """
            ).fetchall()
            return tuple(
                {
                    "attempt_id": str(row["attempt_id"]),
                    "target_id": str(row["target_id"]),
                    "repository_id": str(row["repository_id"]),
                    "owner_uid": int(row["owner_uid"]),
                    "worktree_key": str(row["worktree_key"]),
                    "source_mode": str(row["source_mode"]),
                    "memory_commitment_mib": int(row["memory_commitment_mib"]),
                    "exclusive_resources": tuple(
                        json.loads(row["exclusive_resources_json"])
                    ),
                }
                for row in rows
            )
        finally:
            connection.close()

    def cancel_interrupted_runs(
        self, *, reason: str = "testd restarted", now: float | None = None
    ) -> dict[str, object]:
        """Cancel all unfinished disposable work after daemon replacement."""

        reason = _bounded_text("reason", reason, maximum=500)
        timestamp = _now(self._clock) if now is None else float(now)
        with self._transaction() as connection:
            runs = connection.execute(
                """
                SELECT run_id, repository_id
                FROM test_runs
                WHERE state IN ('queued', 'running', 'cancelling', 'superseding')
                ORDER BY queued_at, run_id
                """
            ).fetchall()
            run_ids = [str(row["run_id"]) for row in runs]
            if run_ids:
                placeholders = ",".join("?" for _ in run_ids)
                connection.execute(
                    f"""
                    DELETE FROM test_result_chunks
                    WHERE attempt_id IN (
                      SELECT attempt_id FROM test_target_attempts
                      WHERE run_id IN ({placeholders})
                        AND state IN ('leased', 'running')
                    )
                    """,
                    run_ids,
                )
                connection.execute(
                    f"""
                    UPDATE test_target_attempts
                    SET state = 'cancelled', conclusion = 'cancelled',
                        failure_classification = ?, reporter_complete = 0,
                        passed_count = 0, failed_count = 0,
                        skipped_count = 0, error_count = 0,
                        lease_expires_at = ?, heartbeat_at = ?,
                        finished_at = ?, updated_at = ?
                    WHERE run_id IN ({placeholders})
                      AND state IN ('leased', 'running')
                    """,
                    (
                        FailureClassification.CANCELLATION.value,
                        timestamp,
                        timestamp,
                        timestamp,
                        timestamp,
                        *run_ids,
                    ),
                )
                connection.execute(
                    f"""
                    UPDATE test_run_targets
                    SET state = 'cancelled', wait_code = NULL,
                        finished_at = ?
                    WHERE run_id IN ({placeholders})
                      AND state IN ('queued', 'leased', 'running')
                    """,
                    (timestamp, *run_ids),
                )
                connection.execute(
                    f"""
                    UPDATE test_runs
                    SET state = 'cancelled', conclusion = 'cancelled',
                        failure_classification = ?, cancel_reason = ?,
                        finished_at = ?, updated_at = ?
                    WHERE run_id IN ({placeholders})
                    """,
                    (
                        FailureClassification.CANCELLATION.value,
                        reason,
                        timestamp,
                        timestamp,
                        *run_ids,
                    ),
                )
                for row in runs:
                    self._event(
                        connection,
                        event_type="test.run_cancelled_on_restart",
                        repository_id=str(row["repository_id"]),
                        run_id=str(row["run_id"]),
                        attempt_id=None,
                        detail={"reason": reason},
                        created_at=timestamp,
                    )
        return {"cancelled_run_ids": run_ids, "cancelled_run_count": len(run_ids)}

    def record_schedule_decision(
        self,
        *,
        selected_target_ids: Sequence[str],
        rejected: Sequence[Mapping[str, object]],
    ) -> None:
        """Persist current structured wait evidence without creating events.

        Scheduler ticks are frequent. Updating the target projection in place
        keeps one truthful current reason instead of flooding the event log.
        """

        selected = tuple(
            _safe_id("selected target_id", value) for value in selected_target_ids
        )
        if len(set(selected)) != len(selected):
            raise TestStoreContractError("selected target IDs are duplicated")
        waits: dict[str, dict[str, object]] = {}
        for index, raw in enumerate(rejected):
            if not isinstance(raw, Mapping):
                raise TestStoreContractError("scheduler rejection must be an object")
            target_id = _safe_id(f"rejected[{index}].target_id", raw.get("target_id"))
            if target_id in waits or target_id in selected:
                raise TestStoreContractError("scheduler target decision is duplicated")
            reason = _safe_id(f"rejected[{index}].reason", raw.get("reason"))
            wait: dict[str, object] = {"reason": reason}
            for field in ("required_mib", "available_mib", "reserve_mib"):
                value = raw.get(field)
                if value is not None and (type(value) is not int or value < 0):
                    raise TestStoreContractError(f"scheduler {field} is invalid")
                wait[field] = value
            observed_at = raw.get("observed_at")
            if observed_at is not None:
                observed_at = _finite_nonnegative(
                    "scheduler observed_at", observed_at
                )
            wait["observed_at"] = observed_at
            source = raw.get("source")
            if source is not None:
                source = _safe_id("scheduler memory source", source)
            wait["source"] = source
            waits[target_id] = wait
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            for target_id in selected:
                connection.execute(
                    """
                    UPDATE test_run_targets
                    SET wait_code = NULL, wait_since = NULL,
                        wait_required_mib = NULL, wait_available_mib = NULL,
                        wait_reserve_mib = NULL, wait_observed_at = NULL,
                        wait_source = NULL
                    WHERE target_id = ? AND state = 'queued'
                    """,
                    (target_id,),
                )
            for target_id, wait in waits.items():
                connection.execute(
                    """
                    UPDATE test_run_targets
                    SET wait_since = CASE
                          WHEN wait_code = ? THEN COALESCE(wait_since, ?)
                          ELSE ? END,
                        wait_code = ?, wait_required_mib = ?,
                        wait_available_mib = ?, wait_reserve_mib = ?,
                        wait_observed_at = ?, wait_source = ?
                    WHERE target_id = ? AND state = 'queued'
                    """,
                    (
                        wait["reason"], timestamp, timestamp, wait["reason"],
                        wait["required_mib"], wait["available_mib"],
                        wait["reserve_mib"], wait["observed_at"], wait["source"],
                        target_id,
                    ),
                )

    def lease_target(
        self,
        target_id: str,
        *,
        lease_owner: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        memory_commitment_mib: int = DEFAULT_MEMORY_BOOTSTRAP_MIB,
        operation_id: str,
    ) -> LeaseGrant:
        target_id = _safe_id("target_id", target_id)
        lease_owner = _safe_id("lease_owner", lease_owner)
        lease_seconds = _positive_int(
            "lease_seconds", lease_seconds, maximum=MAX_LEASE_SECONDS
        )
        memory_commitment_mib = _positive_int(
            "memory_commitment_mib",
            memory_commitment_mib,
            maximum=1 << 40,
        )
        operation_id = _operation_id(operation_id)
        request_document = {
            "target_id": target_id,
            "lease_owner": lease_owner,
            "lease_seconds": lease_seconds,
            "memory_commitment_mib": memory_commitment_mib,
        }
        request_fingerprint = deterministic_fingerprint(request_document)
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="lease",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return LeaseGrant(**replay)
            target = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid,
                       run.state AS run_state, plan.plan_json
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                JOIN test_plans AS plan ON plan.plan_id = run.plan_id
                WHERE target.target_id = ?
                """,
                (target_id,),
            ).fetchone()
            if target is None:
                raise TestStoreNotFound("test target does not exist")
            if str(target["state"]) != "queued" or str(target["run_state"]) not in {
                "queued",
                "running",
            }:
                raise TestStoreConflict("test target is not runnable")
            dependencies = _stored_plan_dependencies(target["plan_json"])
            states: dict[str, list[str]] = {}
            for state_row in connection.execute(
                """
                SELECT target_name, state FROM test_run_targets
                WHERE run_id = ? ORDER BY target_name, shard_index
                """,
                (target["run_id"],),
            ):
                states.setdefault(str(state_row["target_name"]), []).append(
                    str(state_row["state"])
                )
            if not _target_dependencies_succeeded(
                target_name=str(target["target_name"]),
                dependencies=dependencies,
                states=states,
            ):
                raise TestStoreConflict("test target exact dependencies are incomplete")
            attempt_number = int(
                connection.execute(
                    "SELECT COUNT(*) FROM test_target_attempts WHERE target_id = ?",
                    (target_id,),
                ).fetchone()[0]
            ) + 1
            if attempt_number > int(target["max_attempts"]):
                raise TestStoreConflict("test target exhausted its attempt budget")
            generation = attempt_number
            attempt_id = "attempt-" + hashlib.sha256(
                f"{target_id}\0{attempt_number}\0{operation_id}".encode("utf-8")
            ).hexdigest()[:32]
            expires = timestamp + lease_seconds
            # ``lease_token_sha256`` is retained as an inert field; attempt ID
            # plus generation fence updates carry no bearer credential.
            connection.execute(
                """
                INSERT INTO test_target_attempts(
                    attempt_id, target_id, run_id, attempt_number, state,
                    generation, memory_commitment_mib,
                    lease_owner, lease_token_sha256,
                    lease_expires_at, heartbeat_at, queued_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'leased', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    target_id,
                    target["run_id"],
                    attempt_number,
                    generation,
                    memory_commitment_mib,
                    lease_owner,
                    "",
                    expires,
                    timestamp,
                    target["queued_at"],
                    timestamp,
                    timestamp,
                ),
            )
            changed = connection.execute(
                """
                UPDATE test_run_targets
                SET state = 'leased', current_attempt_id = ?,
                    started_at = COALESCE(started_at, ?),
                    wait_code = NULL, wait_since = NULL,
                    wait_required_mib = NULL, wait_available_mib = NULL,
                    wait_reserve_mib = NULL, wait_observed_at = NULL,
                    wait_source = NULL
                WHERE target_id = ? AND state = 'queued'
                """,
                (attempt_id, timestamp, target_id),
            ).rowcount
            if changed != 1:
                raise TestStoreConflict("test target changed during lease")
            connection.execute(
                """
                UPDATE test_runs
                SET state = 'running', started_at = COALESCE(started_at, ?),
                    updated_at = ?
                WHERE run_id = ? AND state IN ('queued', 'running')
                """,
                (timestamp, timestamp, target["run_id"]),
            )
            grant = LeaseGrant(
                attempt_id=attempt_id,
                target_id=target_id,
                run_id=str(target["run_id"]),
                target_name=str(target["target_name"]),
                shard_index=int(target["shard_index"]),
                shard_count=int(target["shard_count"]),
                generation=generation,
                lease_owner=lease_owner,
                lease_expires_at=expires,
            )
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="lease",
                request_fingerprint=request_fingerprint,
                result=grant.__dict__,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.attempt_leased",
                repository_id=str(target["repository_id"]),
                run_id=str(target["run_id"]),
                attempt_id=attempt_id,
                detail={"target_id": target_id, "generation": generation},
                created_at=timestamp,
            )
            return grant

    @staticmethod
    def _require_lease(
        attempt: sqlite3.Row,
        *,
        generation: int,
        active: bool = True,
    ) -> None:
        if type(generation) is not int or generation <= 0:
            raise TestStoreContractError("generation must be a positive integer")
        if int(attempt["generation"]) != generation:
            raise TestStoreConflict("attempt lease generation is stale")
        if active and str(attempt["state"]) not in _ACTIVE_ATTEMPT_STATES:
            raise TestStoreConflict("attempt lease is no longer active")

    def acknowledge_launch(
        self,
        attempt_id: str,
        *,
        generation: int,
        launch_ack_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        attempt_id = _safe_id("attempt_id", attempt_id)
        launch_ack_id = _safe_id("launch_ack_id", launch_ack_id)
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "attempt_id": attempt_id,
                "generation": generation,
                "launch_ack_id": launch_ack_id,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="launch_ack",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            attempt = self._attempt(connection, attempt_id)
            self._require_lease(attempt, generation=generation)
            if str(attempt["state"]) == "running":
                if str(attempt["launch_ack_id"]) != launch_ack_id:
                    raise TestStoreConflict("attempt has different launch evidence")
            else:
                changed = connection.execute(
                    """
                    UPDATE test_target_attempts
                    SET state = 'running', launched_at = ?, launch_ack_id = ?,
                        started_at = ?, updated_at = ?
                    WHERE attempt_id = ? AND state = 'leased'
                    """,
                    (timestamp, launch_ack_id, timestamp, timestamp, attempt_id),
                ).rowcount
                if changed != 1:
                    raise TestStoreConflict("attempt changed during launch acknowledgement")
                connection.execute(
                    "UPDATE test_run_targets SET state = 'running' WHERE target_id = ?",
                    (attempt["target_id"],),
                )
            result = {"attempt_id": attempt_id, "state": "running"}
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="launch_ack",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def heartbeat_attempt(
        self,
        attempt_id: str,
        *,
        generation: int,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        operation_id: str,
    ) -> dict[str, object]:
        attempt_id = _safe_id("attempt_id", attempt_id)
        lease_seconds = _positive_int(
            "lease_seconds", lease_seconds, maximum=MAX_LEASE_SECONDS
        )
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "attempt_id": attempt_id,
                "generation": generation,
                "lease_seconds": lease_seconds,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="heartbeat",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            attempt = self._attempt(connection, attempt_id)
            self._require_lease(attempt, generation=generation)
            if float(attempt["lease_expires_at"]) < timestamp:
                raise TestStoreConflict("attempt lease expired before heartbeat")
            expires = timestamp + lease_seconds
            connection.execute(
                """
                UPDATE test_target_attempts
                SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (timestamp, expires, timestamp, attempt_id),
            )
            result = {
                "attempt_id": attempt_id,
                "state": str(attempt["state"]),
                "lease_expires_at": expires,
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="heartbeat",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def record_attempt_progress(
        self,
        attempt_id: str,
        *,
        generation: int,
        stdout_bytes: int,
        stderr_bytes: int,
        stdout_retained_bytes: int,
        stderr_retained_bytes: int,
        stdout_truncated: bool,
        stderr_truncated: bool,
        current_memory_bytes: int | None,
        last_output_at: float | None,
        observed_at: float,
    ) -> dict[str, object]:
        """Retain bounded output growth without storing captured output content."""

        attempt_id = _safe_id("attempt_id", attempt_id)
        if (
            type(stdout_bytes) is not int
            or type(stderr_bytes) is not int
            or not 0 <= stdout_bytes <= (1 << 63) - 1
            or not 0 <= stderr_bytes <= (1 << 63) - 1
            or type(stdout_retained_bytes) is not int
            or type(stderr_retained_bytes) is not int
            or not 0 <= stdout_retained_bytes <= 4 * 1024 * 1024
            or not 0 <= stderr_retained_bytes <= 4 * 1024 * 1024
            or type(stdout_truncated) is not bool
            or type(stderr_truncated) is not bool
            or stdout_retained_bytes > stdout_bytes
            or stderr_retained_bytes > stderr_bytes
            or stdout_truncated != (stdout_bytes > stdout_retained_bytes)
            or stderr_truncated != (stderr_bytes > stderr_retained_bytes)
        ):
            raise TestStoreContractError("attempt output progress bytes are invalid")
        if current_memory_bytes is not None and (
            type(current_memory_bytes) is not int
            or not 0 <= current_memory_bytes <= (1 << 63) - 1
        ):
            raise TestStoreContractError("attempt current memory is invalid")
        observed = _finite_nonnegative("observed_at", observed_at)
        last_output = (
            None
            if last_output_at is None
            else _finite_nonnegative("last_output_at", last_output_at)
        )
        with self._transaction() as connection:
            attempt = self._attempt(connection, attempt_id)
            self._require_lease(attempt, generation=generation)
            latest = connection.execute(
                """
                SELECT detail_json FROM test_events
                WHERE attempt_id = ? AND event_type = 'test.attempt.progress'
                ORDER BY event_id DESC LIMIT 1
                """,
                (attempt_id,),
            ).fetchone()
            previous: Mapping[str, object] | None = None
            if latest is not None:
                try:
                    decoded = json.loads(str(latest["detail_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise TestStoreContractError(
                        "retained attempt output progress is invalid"
                    ) from error
                previous = _attempt_progress_document(decoded)
            if previous is not None:
                prior_stdout = previous.get("stdout_bytes")
                prior_stderr = previous.get("stderr_bytes")
                prior_memory = previous.get("current_memory_bytes")
                if (
                    type(prior_stdout) is not int
                    or type(prior_stderr) is not int
                    or stdout_bytes < prior_stdout
                    or stderr_bytes < prior_stderr
                    or (
                        prior_memory is not None
                        and type(prior_memory) is not int
                    )
                ):
                    raise TestStoreConflict("attempt output progress regressed")
                if (
                    stdout_bytes == prior_stdout
                    and stderr_bytes == prior_stderr
                    and current_memory_bytes == prior_memory
                    and stdout_retained_bytes
                    == previous.get("stdout_retained_bytes")
                    and stderr_retained_bytes
                    == previous.get("stderr_retained_bytes")
                    and stdout_truncated == previous.get("stdout_truncated")
                    and stderr_truncated == previous.get("stderr_truncated")
                ):
                    return dict(previous)
            detail = {
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
                "stdout_retained_bytes": stdout_retained_bytes,
                "stderr_retained_bytes": stderr_retained_bytes,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "current_memory_bytes": current_memory_bytes,
                "last_output_at": last_output,
                "observed_at": observed,
            }
            run = connection.execute(
                "SELECT repository_id FROM test_runs WHERE run_id = ?",
                (attempt["run_id"],),
            ).fetchone()
            if run is None:
                raise TestStoreContractError(
                    "attempt output progress lost its run identity"
                )
            self._event(
                connection,
                event_type="test.attempt.progress",
                repository_id=str(run["repository_id"]),
                run_id=str(attempt["run_id"]),
                attempt_id=attempt_id,
                detail=detail,
                created_at=_now(self._clock),
            )
            return detail

    def append_result_chunk(
        self,
        attempt_id: str,
        *,
        generation: int,
        chunk: AttemptResultChunk,
    ) -> dict[str, object]:
        attempt_id = _safe_id("attempt_id", attempt_id)
        document = self._chunk_document(chunk)
        encoded = _canonical_json(document).encode("utf-8")
        if len(encoded) > MAX_RESULT_CHUNK_BYTES:
            raise TestStoreContractError("result chunk exceeds its byte bound")
        fingerprint = hashlib.sha256(encoded).hexdigest()
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            attempt = self._attempt(connection, attempt_id)
            self._require_lease(attempt, generation=generation, active=False)
            existing = connection.execute(
                """
                SELECT * FROM test_result_chunks
                WHERE attempt_id = ? AND chunk_id = ?
                """,
                (attempt_id, chunk.chunk_id),
            ).fetchone()
            if existing is not None:
                if str(existing["fingerprint"]) != fingerprint:
                    raise TestStoreConflict("chunk_id is bound to different results")
                return {
                    "attempt_id": attempt_id,
                    "chunk_id": chunk.chunk_id,
                    "replayed": True,
                }
            self._require_lease(attempt, generation=generation)
            if bool(attempt["reporter_complete"]):
                raise TestStoreConflict("reporter already published its final chunk")
            expected_index = int(
                connection.execute(
                    "SELECT COUNT(*) FROM test_result_chunks WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()[0]
            )
            if chunk.chunk_index != expected_index:
                raise TestStoreConflict(
                    f"result chunk index must be contiguous; expected {expected_index}"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO test_result_chunks(
                        attempt_id, chunk_id, chunk_index, fingerprint,
                        encoded_bytes, case_count, failure_count,
                        artifact_count, reporter_complete, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        chunk.chunk_id,
                        chunk.chunk_index,
                        fingerprint,
                        len(encoded),
                        len(chunk.cases),
                        len(chunk.failures),
                        len(chunk.artifacts),
                        int(chunk.reporter_complete),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise TestStoreConflict("result chunk index or identity already exists") from error
            counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
            for case in chunk.cases:
                counts[case.status] += 1
            for failure in chunk.failures:
                connection.execute(
                    """
                    INSERT INTO test_failures(
                        failure_id, attempt_id, chunk_id, classification,
                        case_id, message, location, artifact_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        failure.failure_id,
                        attempt_id,
                        chunk.chunk_id,
                        failure.classification.value,
                        failure.case_id,
                        failure.message,
                        failure.location,
                        failure.artifact_id,
                        timestamp,
                    ),
                )
            for artifact in chunk.artifacts:
                connection.execute(
                    """
                    INSERT INTO test_artifacts(
                        artifact_id, attempt_id, chunk_id, kind,
                        storage_handle, sha256, size_bytes, verified, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact.artifact_id,
                        attempt_id,
                        chunk.chunk_id,
                        artifact.kind,
                        artifact.storage_handle,
                        artifact.sha256,
                        artifact.size_bytes,
                        int(artifact.verified),
                        timestamp,
                    ),
                )
            connection.execute(
                """
                UPDATE test_target_attempts
                SET passed_count = passed_count + ?,
                    failed_count = failed_count + ?,
                    skipped_count = skipped_count + ?,
                    error_count = error_count + ?,
                    reporter_complete = MAX(reporter_complete, ?),
                    updated_at = ?
                WHERE attempt_id = ?
                """,
                (
                    counts["passed"],
                    counts["failed"],
                    counts["skipped"],
                    counts["error"],
                    int(chunk.reporter_complete),
                    timestamp,
                    attempt_id,
                ),
            )
            return {
                "attempt_id": attempt_id,
                "chunk_id": chunk.chunk_id,
                "replayed": False,
            }

    def _chunk_document(self, chunk: AttemptResultChunk) -> dict[str, object]:
        if not isinstance(chunk, AttemptResultChunk):
            raise TestStoreContractError("chunk must be AttemptResultChunk")
        chunk_id = _safe_id("chunk_id", chunk.chunk_id)
        if type(chunk.chunk_index) is not int or chunk.chunk_index < 0:
            raise TestStoreContractError("chunk_index must be non-negative")
        if len(chunk.cases) > MAX_CASES_PER_CHUNK:
            raise TestStoreContractError("result chunk contains too many cases")
        if len(chunk.failures) > MAX_FAILURES_PER_CHUNK:
            raise TestStoreContractError("result chunk contains too many failures")
        if len(chunk.artifacts) > MAX_ARTIFACTS_PER_CHUNK:
            raise TestStoreContractError("result chunk contains too many artifacts")
        cases: list[dict[str, object]] = []
        seen_cases: set[str] = set()
        for case in chunk.cases:
            if not isinstance(case, CaseResult):
                raise TestStoreContractError("cases must contain CaseResult")
            case_id = _single_line("case_id", case.case_id, maximum=1024)
            if case_id in seen_cases:
                raise TestStoreContractError("case_id is duplicated inside a chunk")
            seen_cases.add(case_id)
            display_name = _bounded_text("display_name", case.display_name, maximum=4096)
            if case.status not in {"passed", "failed", "skipped", "error"}:
                raise TestStoreContractError("unsupported case status")
            duration = _finite_nonnegative("case duration", case.duration_seconds)
            location = (
                None
                if case.location is None
                else _bounded_text("case location", case.location, maximum=4096)
            )
            cases.append(
                {
                    "case_id": case_id,
                    "display_name": display_name,
                    "status": case.status,
                    "duration_seconds": duration,
                    "location": location,
                }
            )
        failures: list[dict[str, object]] = []
        seen_failures: set[str] = set()
        for failure in chunk.failures:
            if not isinstance(failure, FailureRecord):
                raise TestStoreContractError("failures must contain FailureRecord")
            failure_id = _safe_id("failure_id", failure.failure_id)
            if failure_id in seen_failures:
                raise TestStoreContractError("failure_id is duplicated inside a chunk")
            seen_failures.add(failure_id)
            if not isinstance(failure.classification, FailureClassification):
                raise TestStoreContractError("failure classification is invalid")
            failures.append(
                {
                    "failure_id": failure_id,
                    "classification": failure.classification.value,
                    "message": _bounded_text(
                        "failure message", failure.message, maximum=8192
                    ),
                    "case_id": (
                        None
                        if failure.case_id is None
                        else _single_line("failure case_id", failure.case_id, maximum=1024)
                    ),
                    "location": (
                        None
                        if failure.location is None
                        else _bounded_text(
                            "failure location", failure.location, maximum=4096
                        )
                    ),
                    "artifact_id": (
                        None
                        if failure.artifact_id is None
                        else _safe_id("failure artifact_id", failure.artifact_id)
                    ),
                }
            )
        artifacts: list[dict[str, object]] = []
        seen_artifacts: set[str] = set()
        for artifact in chunk.artifacts:
            if not isinstance(artifact, ArtifactMetadata):
                raise TestStoreContractError("artifacts must contain ArtifactMetadata")
            artifact_id = _safe_id("artifact_id", artifact.artifact_id)
            if artifact_id in seen_artifacts:
                raise TestStoreContractError("artifact_id is duplicated inside a chunk")
            seen_artifacts.add(artifact_id)
            if type(artifact.size_bytes) is not int or not 0 <= artifact.size_bytes <= (1 << 63) - 1:
                raise TestStoreContractError("artifact size is outside its bound")
            if type(artifact.verified) is not bool:
                raise TestStoreContractError("artifact verified must be boolean")
            artifacts.append(
                {
                    "artifact_id": artifact_id,
                    "kind": _safe_id("artifact kind", artifact.kind),
                    "storage_handle": _single_line(
                        "artifact storage_handle", artifact.storage_handle, maximum=4096
                    ),
                    "sha256": _sha256("artifact sha256", artifact.sha256),
                    "size_bytes": artifact.size_bytes,
                    "verified": artifact.verified,
                }
            )
        if type(chunk.reporter_complete) is not bool:
            raise TestStoreContractError("reporter_complete must be boolean")
        return {
            "chunk_id": chunk_id,
            "chunk_index": chunk.chunk_index,
            "cases": cases,
            "failures": failures,
            "artifacts": artifacts,
            "reporter_complete": chunk.reporter_complete,
        }

    def terminalize_attempt(
        self,
        attempt_id: str,
        *,
        generation: int,
        conclusion: AttemptConclusion,
        duration_seconds: float,
        operation_id: str,
        expected_result_chunk_ids: Sequence[str] | None = None,
        peak_memory_bytes: int | None = None,
        cpu_seconds: float | None = None,
    ) -> dict[str, object]:
        attempt_id = _safe_id("attempt_id", attempt_id)
        if not isinstance(conclusion, AttemptConclusion):
            try:
                conclusion = AttemptConclusion(conclusion)
            except ValueError as error:
                raise TestStoreContractError("unsupported attempt conclusion") from error
        duration = _finite_nonnegative("duration_seconds", duration_seconds)
        if duration > 31_536_000:
            raise TestStoreContractError("duration_seconds is outside its bound")
        if peak_memory_bytes is not None and (
            type(peak_memory_bytes) is not int
            or not 0 <= peak_memory_bytes <= (1 << 63) - 1
        ):
            raise TestStoreContractError("peak_memory_bytes is outside its bound")
        if cpu_seconds is not None:
            cpu_seconds = _finite_nonnegative("cpu_seconds", cpu_seconds)
            if cpu_seconds > 31_536_000:
                raise TestStoreContractError("cpu_seconds is outside its bound")
        operation_id = _operation_id(operation_id)
        expected_chunks = None
        if expected_result_chunk_ids is not None:
            if (
                not isinstance(expected_result_chunk_ids, Sequence)
                or isinstance(expected_result_chunk_ids, (str, bytes))
                or len(expected_result_chunk_ids) > 4_096
            ):
                raise TestStoreContractError("expected result chunk IDs are invalid")
            expected_chunks = tuple(
                _safe_id("result_chunk_id", item)
                for item in expected_result_chunk_ids
            )
            if len(set(expected_chunks)) != len(expected_chunks):
                raise TestStoreContractError("expected result chunk IDs are duplicated")
        classification = _CONCLUSION_CLASSIFICATION[conclusion]
        request_fingerprint = deterministic_fingerprint(
            {
                "attempt_id": attempt_id,
                "generation": generation,
                "conclusion": conclusion.value,
                "duration_seconds": duration,
                "expected_result_chunk_ids": (
                    None if expected_chunks is None else list(expected_chunks)
                ),
                "peak_memory_bytes": peak_memory_bytes,
                "cpu_seconds": cpu_seconds,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="terminalize",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            attempt = self._attempt(connection, attempt_id)
            self._require_lease(attempt, generation=generation)
            if expected_chunks is not None:
                actual_chunks = tuple(
                    str(row["chunk_id"])
                    for row in connection.execute(
                        """
                        SELECT chunk_id FROM test_result_chunks
                        WHERE attempt_id = ? ORDER BY chunk_index
                        """,
                        (attempt_id,),
                    )
                )
                if actual_chunks != expected_chunks:
                    raise TestStoreConflict(
                        "attempt result chunks are incomplete or contradictory"
                    )
            if conclusion is AttemptConclusion.SUCCEEDED and not bool(
                attempt["reporter_complete"]
            ):
                conclusion = AttemptConclusion.INCOMPLETE
                classification = FailureClassification.INCOMPLETE_REPORTING
            connection.execute(
                """
                UPDATE test_target_attempts
                SET state = ?, terminal_operation_id = ?,
                    terminal_fingerprint = ?, conclusion = ?,
                    failure_classification = ?, duration_seconds = ?,
                    peak_memory_bytes = ?, cpu_seconds = ?,
                    finished_at = ?, updated_at = ?
                WHERE attempt_id = ? AND state IN ('leased', 'running')
                """,
                (
                    conclusion.value,
                    operation_id,
                    request_fingerprint,
                    conclusion.value,
                    None if classification is None else classification.value,
                    duration,
                    peak_memory_bytes,
                    cpu_seconds,
                    timestamp,
                    timestamp,
                    attempt_id,
                ),
            )
            connection.execute(
                """
                UPDATE test_run_targets
                SET state = ?, finished_at = ?, current_attempt_id = NULL
                WHERE target_id = ? AND current_attempt_id = ?
                """,
                (conclusion.value, timestamp, attempt["target_id"], attempt_id),
            )
            run = connection.execute(
                "SELECT repository_id FROM test_runs WHERE run_id = ?",
                (attempt["run_id"],),
            ).fetchone()
            if run is None:
                raise TestStoreContractError("attempt run disappeared during terminalization")
            self._reconcile_run(connection, str(attempt["run_id"]), timestamp)
            result = {
                "attempt_id": attempt_id,
                "run_id": str(attempt["run_id"]),
                "state": conclusion.value,
                "classification": None if classification is None else classification.value,
                "usage": {
                    "available": peak_memory_bytes is not None or cpu_seconds is not None,
                    "peak_memory_bytes": peak_memory_bytes,
                    "cpu_seconds": cpu_seconds,
                },
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="terminalize",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.attempt_terminal",
                repository_id=str(run["repository_id"]),
                run_id=str(attempt["run_id"]),
                attempt_id=attempt_id,
                detail={
                    "conclusion": conclusion.value,
                    "classification": result["classification"],
                    "peak_memory_bytes": peak_memory_bytes,
                    "cpu_seconds": cpu_seconds,
                },
                created_at=timestamp,
            )
            return result

    def request_cancel(
        self,
        run_id: str,
        *,
        actor: str,
        reason: str,
        operation_id: str,
    ) -> dict[str, object]:
        return self._request_run_stop(
            run_id,
            actor=actor,
            reason=reason,
            operation_id=operation_id,
            state="cancelling",
            target_state="cancelled",
        )

    def mark_superseded(
        self,
        run_id: str,
        *,
        observed_source_fingerprint: str,
        operation_id: str,
    ) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        observed = _sha256(
            "observed_source_fingerprint", observed_source_fingerprint
        )
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                "SELECT source_mode, source_fingerprint FROM test_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise TestStoreNotFound("test run does not exist")
        if str(row["source_mode"]) != SourceMode.LIVE.value:
            raise TestStoreConflict("immutable runs cannot be superseded")
        if str(row["source_fingerprint"]) == observed:
            raise TestStoreConflict("live source identity has not changed")
        return self._request_run_stop(
            run_id,
            actor="source-observer",
            reason=f"source changed to {observed}",
            operation_id=operation_id,
            state="superseding",
            target_state="superseded",
        )

    def _request_run_stop(
        self,
        run_id: str,
        *,
        actor: str,
        reason: str,
        operation_id: str,
        state: str,
        target_state: str,
    ) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        actor = _single_line("actor", actor, maximum=256)
        reason = _single_line("reason", reason, maximum=1024)
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "run_id": run_id,
                "actor": actor,
                "reason": reason,
                "state": state,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind=state,
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            run = connection.execute(
                "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise TestStoreNotFound("test run does not exist")
            if str(run["state"]) not in _ACTIVE_RUN_STATES:
                result = {
                    "run_id": run_id,
                    "state": str(run["state"]),
                    "active_attempt_ids": [],
                }
            else:
                connection.execute(
                    """
                    UPDATE test_runs SET state = ?, cancel_reason = ?, updated_at = ?
                    WHERE run_id = ?
                    """,
                    (state, reason, timestamp, run_id),
                )
                connection.execute(
                    """
                    UPDATE test_run_targets
                    SET state = ?, finished_at = ?
                    WHERE run_id = ? AND state = 'queued'
                    """,
                    (target_state, timestamp, run_id),
                )
                active = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT attempt_id FROM test_target_attempts
                        WHERE run_id = ? AND state IN ('leased', 'running')
                        ORDER BY attempt_id
                        """,
                        (run_id,),
                    ).fetchall()
                ]
                if not active:
                    terminal_run = "cancelled" if state == "cancelling" else "superseded"
                    connection.execute(
                        """
                        UPDATE test_runs
                        SET state = ?, conclusion = ?, failure_classification = ?,
                            finished_at = ?, updated_at = ?
                        WHERE run_id = ?
                        """,
                        (
                            terminal_run,
                            terminal_run,
                            (
                                FailureClassification.CANCELLATION.value
                                if state == "cancelling"
                                else FailureClassification.SUPERSEDED.value
                            ),
                            timestamp,
                            timestamp,
                            run_id,
                        ),
                    )
                    state_value = terminal_run
                else:
                    state_value = state
                result = {
                    "run_id": run_id,
                    "state": state_value,
                    "active_attempt_ids": active,
                }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind=state,
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def reap_expired_attempts(self, *, now: float | None = None) -> dict[str, object]:
        timestamp = _now(self._clock) if now is None else _finite_nonnegative("now", now)
        requeued: list[str] = []
        abandoned: list[str] = []
        lease_expired_before_launch: list[str] = []
        running_heartbeat_lost: list[str] = []
        outcomes: list[dict[str, object]] = []
        affected_runs: set[str] = set()
        affected_repositories: set[str] = set()
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT attempt.*, target.max_attempts, run.repository_id
                FROM test_target_attempts AS attempt
                JOIN test_run_targets AS target ON target.target_id = attempt.target_id
                JOIN test_runs AS run ON run.run_id = attempt.run_id
                WHERE attempt.state IN ('leased', 'running')
                  AND attempt.lease_expires_at < ?
                ORDER BY attempt.lease_expires_at, attempt.attempt_id
                LIMIT ?
                """,
                (timestamp, MAX_EXPIRED_ATTEMPTS_PER_REAP + 1),
            ).fetchall()
            selected_rows = rows[:MAX_EXPIRED_ATTEMPTS_PER_REAP]
            for attempt in selected_rows:
                attempt_id = str(attempt["attempt_id"])
                previous_state = str(attempt["state"])
                reason = _lease_expiry_reason(previous_state)
                if reason == "lease_expired_before_launch":
                    lease_expired_before_launch.append(attempt_id)
                else:
                    running_heartbeat_lost.append(attempt_id)
                affected_runs.add(str(attempt["run_id"]))
                affected_repositories.add(str(attempt["repository_id"]))
                will_requeue = (
                    previous_state == "leased"
                    and int(attempt["attempt_number"]) < int(attempt["max_attempts"])
                )
                if will_requeue:
                    connection.execute(
                        """
                        UPDATE test_target_attempts
                        SET state = 'abandoned', conclusion = 'abandoned',
                            failure_classification = ?, finished_at = ?, updated_at = ?
                        WHERE attempt_id = ?
                        """,
                        (
                            FailureClassification.ABANDONMENT.value,
                            timestamp,
                            timestamp,
                            attempt["attempt_id"],
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE test_run_targets
                        SET state = 'queued', current_attempt_id = NULL, queued_at = ?
                        WHERE target_id = ? AND current_attempt_id = ?
                        """,
                        (timestamp, attempt["target_id"], attempt["attempt_id"]),
                    )
                    requeued.append(attempt_id)
                else:
                    connection.execute(
                        """
                        UPDATE test_target_attempts
                        SET state = 'abandoned', conclusion = 'abandoned',
                            failure_classification = ?, finished_at = ?, updated_at = ?
                        WHERE attempt_id = ?
                        """,
                        (
                            FailureClassification.ABANDONMENT.value,
                            timestamp,
                            timestamp,
                            attempt["attempt_id"],
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE test_run_targets
                        SET state = 'abandoned', current_attempt_id = NULL,
                            finished_at = ?
                        WHERE target_id = ? AND current_attempt_id = ?
                        """,
                        (timestamp, attempt["target_id"], attempt["attempt_id"]),
                    )
                    abandoned.append(attempt_id)
                detail = {
                    "schema_version": 1,
                    "reason": reason,
                    "previous_state": previous_state,
                    "requeued": will_requeue,
                    "lease_expires_at": float(attempt["lease_expires_at"]),
                    "last_heartbeat_at": (
                        float(attempt["heartbeat_at"])
                        if previous_state == "running"
                        else None
                    ),
                    "launched_at": (
                        None
                        if attempt["launched_at"] is None
                        else float(attempt["launched_at"])
                    ),
                    "observed_at": timestamp,
                }
                self._event(
                    connection,
                    event_type="test.attempt_lease_expired",
                    repository_id=str(attempt["repository_id"]),
                    run_id=str(attempt["run_id"]),
                    attempt_id=str(attempt["attempt_id"]),
                    detail=detail,
                    created_at=timestamp,
                )
                outcomes.append(
                    {
                        "attempt_id": attempt_id,
                        "run_id": str(attempt["run_id"]),
                        "reason": reason,
                        "requeued": will_requeue,
                    }
                )
            for run_id in sorted(affected_runs):
                self._reconcile_run(connection, run_id, timestamp)
        return {
            "processed_attempt_count": len(selected_rows),
            "batch_limit": MAX_EXPIRED_ATTEMPTS_PER_REAP,
            "more_expired": len(rows) > len(selected_rows),
            "convergence_cursor": (
                None
                if not selected_rows
                else {
                    "lease_expires_at": float(selected_rows[-1]["lease_expires_at"]),
                    "attempt_id": str(selected_rows[-1]["attempt_id"]),
                }
            ),
            "requeued_attempt_ids": requeued,
            "abandoned_attempt_ids": abandoned,
            "lease_expired_before_launch_attempt_ids": lease_expired_before_launch,
            "running_heartbeat_lost_attempt_ids": running_heartbeat_lost,
            "outcomes": outcomes,
        }

    def reconcile_nonterminal_runs(
        self, *, now: float | None = None
    ) -> dict[str, object]:
        """Repair nonterminal runs which no active attempt can advance.

        Attempt terminalization normally reconciles its run in the same SQLite
        transaction.  Retained state imported by an older release (or captured
        before that invariant existed) can nevertheless contain a terminal
        target, no active attempt, and a run still marked queued/running.  Such
        a run is invisible to both the runnable-target query and the lease
        reaper, so restarting testd alone cannot make progress.

        Only runs with terminal target evidence and no leased/running attempt
        are considered.  This leaves recoverable runtime ownership to the
        spool/heartbeat path and avoids scanning ordinary newly queued runs.
        """

        timestamp = (
            _now(self._clock)
            if now is None
            else _finite_nonnegative("now", now)
        )
        placeholders = ",".join("?" for _ in _TERMINAL_TARGET_STATES)
        active_placeholders = ",".join("?" for _ in _ACTIVE_RUN_STATES)
        processed: list[str] = []
        changed: list[dict[str, str]] = []
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT run.run_id, run.state
                FROM test_runs AS run
                WHERE run.state IN ({active_placeholders})
                  AND EXISTS (
                    SELECT 1 FROM test_run_targets AS target
                    WHERE target.run_id = run.run_id
                      AND target.state IN ({placeholders})
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM test_target_attempts AS attempt
                    WHERE attempt.run_id = run.run_id
                      AND attempt.state IN ('leased', 'running')
                  )
                ORDER BY run.updated_at, run.run_id
                LIMIT ?
                """,
                (
                    *_ACTIVE_RUN_STATES,
                    *_TERMINAL_TARGET_STATES,
                    MAX_NONTERMINAL_RUNS_PER_RECONCILE + 1,
                ),
            ).fetchall()
            selected = rows[:MAX_NONTERMINAL_RUNS_PER_RECONCILE]
            for row in selected:
                run_id = str(row["run_id"])
                before = str(row["state"])
                self._reconcile_run(connection, run_id, timestamp)
                after_row = connection.execute(
                    "SELECT state FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                if after_row is None:
                    raise TestStoreNotFound("test run disappeared during reconciliation")
                after = str(after_row["state"])
                processed.append(run_id)
                if after != before:
                    changed.append(
                        {"run_id": run_id, "previous_state": before, "state": after}
                    )
        return {
            "processed_run_ids": processed,
            "changed_runs": changed,
            "more_candidates": len(rows) > len(selected),
        }

    def _reconcile_run(
        self, connection: sqlite3.Connection, run_id: str, timestamp: float
    ) -> None:
        run = connection.execute(
            """
            SELECT run.*, plan.plan_json
            FROM test_runs AS run
            JOIN test_plans AS plan ON plan.plan_id = run.plan_id
            WHERE run.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if run is None:
            raise TestStoreNotFound("test run does not exist")
        targets = connection.execute(
            "SELECT * FROM test_run_targets WHERE run_id = ? ORDER BY wave_index, target_id",
            (run_id,),
        ).fetchall()
        active = [row for row in targets if str(row["state"]) in {"queued", "leased", "running"}]
        run_state = str(run["state"])
        if run_state in {"cancelling", "superseding"}:
            if any(str(row["state"]) in {"leased", "running"} for row in targets):
                return
            terminal = "cancelled" if run_state == "cancelling" else "superseded"
            classification = (
                FailureClassification.CANCELLATION.value
                if run_state == "cancelling"
                else FailureClassification.SUPERSEDED.value
            )
            connection.execute(
                """
                UPDATE test_runs SET state = ?, conclusion = ?,
                    failure_classification = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (terminal, terminal, classification, timestamp, timestamp, run_id),
            )
            return
        failed = [
            row
            for row in targets
            if str(row["state"]) in _TERMINAL_TARGET_STATES
            and str(row["state"]) != "succeeded"
        ]
        if failed:
            dependencies = _stored_plan_dependencies(run["plan_json"])
            unavailable_names = {
                str(row["target_name"]) for row in failed
            }
            cancelled_dependents: set[str] = set()
            changed = True
            while changed:
                changed = False
                for target_name, required in dependencies.items():
                    if target_name in unavailable_names | cancelled_dependents:
                        continue
                    if any(
                        dependency in unavailable_names | cancelled_dependents
                        for dependency in required
                    ):
                        cancelled_dependents.add(target_name)
                        changed = True
            cancelled_target_ids: set[str] = set()
            for row in targets:
                if (
                    str(row["state"]) == "queued"
                    and str(row["target_name"]) in cancelled_dependents
                ):
                    connection.execute(
                        """
                        UPDATE test_run_targets
                        SET state = 'cancelled', finished_at = ?
                        WHERE target_id = ? AND state = 'queued'
                        """,
                        (timestamp, str(row["target_id"])),
                    )
                    cancelled_target_ids.add(str(row["target_id"]))
            if any(
                str(row["state"]) in {"queued", "leased", "running"}
                and str(row["target_id"]) not in cancelled_target_ids
                for row in targets
            ):
                return
            states = {str(row["state"]) for row in failed}
            run_terminal, classification = self._dominant_failure(states)
            connection.execute(
                """
                UPDATE test_runs SET state = ?, conclusion = ?,
                    failure_classification = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (run_terminal, run_terminal, classification, timestamp, timestamp, run_id),
            )
            return
        if not active and targets and all(
            str(row["state"]) == "succeeded" for row in targets
        ):
            connection.execute(
                """
                UPDATE test_runs SET state = 'succeeded', conclusion = 'succeeded',
                    failure_classification = NULL, finished_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (timestamp, timestamp, run_id),
            )

    @staticmethod
    def _dominant_failure(states: set[str]) -> tuple[str, str]:
        precedence = (
            ("infrastructure_failed", "failed", FailureClassification.INFRASTRUCTURE_FAILURE),
            ("timed_out", "timed_out", FailureClassification.TIMEOUT),
            ("incomplete", "incomplete", FailureClassification.INCOMPLETE_REPORTING),
            ("abandoned", "abandoned", FailureClassification.ABANDONMENT),
            ("test_failed", "failed", FailureClassification.TEST_FAILURE),
            ("superseded", "superseded", FailureClassification.SUPERSEDED),
            ("cancelled", "cancelled", FailureClassification.CANCELLATION),
        )
        for state, run_state, classification in precedence:
            if state in states:
                return run_state, classification.value
        raise AssertionError("terminal failure state was not classified")

    def get_run(
        self, run_id: str, *, repository_id: str | None = None
    ) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        if repository_id is not None:
            repository_id = _safe_id("repository_id", repository_id)
        connection = self._connect(readonly=True)
        try:
            if repository_id is None:
                row = connection.execute(
                    "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT * FROM test_runs
                    WHERE run_id = ? AND repository_id = ?
                    """,
                    (run_id, repository_id),
                ).fetchone()
            if row is None:
                raise TestStoreNotFound("test run does not exist")
            result = dict(row)
            attempt_rows = connection.execute(
                """
                SELECT attempt_id, target_id, state, started_at, heartbeat_at,
                       lease_expires_at, peak_memory_bytes, cpu_seconds
                FROM test_target_attempts
                WHERE run_id = ?
                ORDER BY created_at, attempt_id
                """,
                (run_id,),
            ).fetchall()
            attempts_by_target: dict[str, list[sqlite3.Row]] = {}
            attempts_by_id: dict[str, sqlite3.Row] = {}
            for attempt in attempt_rows:
                attempts_by_target.setdefault(str(attempt["target_id"]), []).append(
                    attempt
                )
                attempts_by_id[str(attempt["attempt_id"])] = attempt
            progress_by_attempt: dict[str, dict[str, object]] = {}
            for progress_row in connection.execute(
                """
                SELECT attempt_id, detail_json FROM test_events
                WHERE run_id = ? AND event_type = 'test.attempt.progress'
                ORDER BY event_id
                """,
                (run_id,),
            ).fetchall():
                progress_attempt_id = str(progress_row["attempt_id"])
                try:
                    progress = json.loads(str(progress_row["detail_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise TestStoreContractError(
                        "retained attempt output progress is invalid"
                    ) from error
                progress_by_attempt[progress_attempt_id] = (
                    _attempt_progress_document(progress)
                )
            targets: list[dict[str, object]] = []
            for target_row in connection.execute(
                """
                SELECT * FROM test_run_targets
                WHERE run_id = ? ORDER BY wave_index, target_name, shard_index
                """,
                (run_id,),
            ).fetchall():
                target = dict(target_row)
                wait_code = target.pop("wait_code")
                wait_since = target.pop("wait_since")
                wait_required = target.pop("wait_required_mib")
                wait_available = target.pop("wait_available_mib")
                wait_reserve = target.pop("wait_reserve_mib")
                wait_observed = target.pop("wait_observed_at")
                wait_source = target.pop("wait_source")
                target["wait"] = (
                    None
                    if wait_code is None
                    else {
                        "code": str(wait_code),
                        "since": None if wait_since is None else float(wait_since),
                        "required_mib": (
                            None if wait_required is None else int(wait_required)
                        ),
                        "available_mib": (
                            None if wait_available is None else int(wait_available)
                        ),
                        "reserve_mib": (
                            None if wait_reserve is None else int(wait_reserve)
                        ),
                        "observed_at": (
                            None if wait_observed is None else float(wait_observed)
                        ),
                        "source": None if wait_source is None else str(wait_source),
                    }
                )
                attempts = attempts_by_target.get(str(target["target_id"]), [])
                current_attempt_id = target.get("current_attempt_id")
                active_attempt = (
                    None
                    if current_attempt_id is None
                    else attempts_by_id.get(str(current_attempt_id))
                )
                target["active_attempt"] = (
                    None
                    if active_attempt is None
                    or str(active_attempt["state"]) not in {"leased", "running"}
                    else {
                        "attempt_id": str(active_attempt["attempt_id"]),
                        "state": str(active_attempt["state"]),
                        "started_at": (
                            None
                            if active_attempt["started_at"] is None
                            else float(active_attempt["started_at"])
                        ),
                        "heartbeat_at": float(active_attempt["heartbeat_at"]),
                        "lease_expires_at": float(
                            active_attempt["lease_expires_at"]
                        ),
                        "output_progress": progress_by_attempt.get(
                            str(active_attempt["attempt_id"])
                        ),
                    }
                )
                measured_peaks = [
                    int(attempt["peak_memory_bytes"])
                    for attempt in attempts
                    if attempt["peak_memory_bytes"] is not None
                ]
                measured_cpu = [
                    float(attempt["cpu_seconds"])
                    for attempt in attempts
                    if attempt["cpu_seconds"] is not None
                ]
                measured_count = sum(
                    1
                    for attempt in attempts
                    if attempt["peak_memory_bytes"] is not None
                    or attempt["cpu_seconds"] is not None
                )
                target["usage"] = {
                    "available": measured_count > 0,
                    "peak_memory_mib": (
                        None
                        if not measured_peaks
                        else max(measured_peaks) / (1024 * 1024)
                    ),
                    "cpu_seconds": None if not measured_cpu else sum(measured_cpu),
                    "measured_attempts": measured_count,
                    "total_attempts": len(attempts),
                }
                targets.append(target)
            result["targets"] = targets
            run_peaks = [
                target["usage"]["peak_memory_mib"]  # type: ignore[index]
                for target in targets
                if target["usage"]["peak_memory_mib"] is not None  # type: ignore[index]
            ]
            run_cpu = [
                target["usage"]["cpu_seconds"]  # type: ignore[index]
                for target in targets
                if target["usage"]["cpu_seconds"] is not None  # type: ignore[index]
            ]
            result["usage"] = {
                "available": any(
                    bool(target["usage"]["available"])  # type: ignore[index]
                    for target in targets
                ),
                "peak_memory_mib": None if not run_peaks else max(run_peaks),
                "cpu_seconds": None if not run_cpu else sum(run_cpu),
                "measured_attempts": sum(
                    int(target["usage"]["measured_attempts"])  # type: ignore[index]
                    for target in targets
                ),
                "total_attempts": len(attempt_rows),
            }
            result["lease_expiry_evidence"] = self._run_lease_expiry_evidence(
                connection,
                repository_id=str(row["repository_id"]),
                run_id=run_id,
            )
            return result
        finally:
            connection.close()

    @staticmethod
    def _run_lease_expiry_evidence(
        connection: sqlite3.Connection,
        *,
        repository_id: str,
        run_id: str,
    ) -> dict[str, object]:
        rows = connection.execute(
            """
            SELECT event_id, attempt_id, detail_json, created_at
            FROM test_events
            WHERE repository_id = ? AND run_id = ?
              AND event_type = 'test.attempt_lease_expired'
            ORDER BY event_id DESC
            LIMIT ?
            """,
            (repository_id, run_id, MAX_RUN_LEASE_EXPIRY_EVIDENCE + 1),
        ).fetchall()
        visible_rows = rows[:MAX_RUN_LEASE_EXPIRY_EVIDENCE]
        events: list[dict[str, object]] = []
        for row in reversed(visible_rows):
            try:
                detail = json.loads(str(row["detail_json"]))
            except json.JSONDecodeError as error:
                raise TestStoreConflict(
                    "retained lease-expiry evidence is malformed"
                ) from error
            if not isinstance(detail, dict):
                raise TestStoreConflict(
                    "retained lease-expiry evidence is malformed"
                )
            detail_schema = detail.get("schema_version", 1)
            if type(detail_schema) is not int or detail_schema != 1:
                raise TestStoreConflict(
                    "retained lease-expiry evidence schema is unsupported"
                )
            reason = _lease_expiry_reason(detail.get("previous_state"))
            retained_reason = detail.get("reason", reason)
            if retained_reason != reason or type(detail.get("requeued")) is not bool:
                raise TestStoreConflict(
                    "retained lease-expiry evidence is contradictory"
                )
            attempt_id = row["attempt_id"]
            if attempt_id is None:
                raise TestStoreConflict(
                    "retained lease-expiry evidence omitted its attempt"
                )
            try:
                observed_at = _finite_nonnegative(
                    "lease-expiry observed_at",
                    detail.get("observed_at", row["created_at"]),
                )
            except TestStoreContractError as error:
                raise TestStoreConflict(
                    "retained lease-expiry evidence has an invalid timestamp"
                ) from error
            events.append(
                {
                    "event_id": int(row["event_id"]),
                    "attempt_id": str(attempt_id),
                    "reason": reason,
                    "requeued": bool(detail["requeued"]),
                    "observed_at": observed_at,
                }
            )
        return {
            "visible_count": len(events),
            "truncated": len(rows) > MAX_RUN_LEASE_EXPIRY_EVIDENCE,
            "events": events,
        }

    def runs(
        self,
        *,
        repository_id: str,
        after: str | None = None,
        limit: int = 50,
        state: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        """Return only deterministic, repository-scoped unfinished runs.

        ``after`` is an opaque run-id cursor from the previous page.  The
        cursor is resolved to the stored timestamp before selecting the next
        page so callers cannot forge a cross-repository offset.
        """

        repository_id = _safe_id("repository_id", repository_id)
        after_value = None if after is None else _safe_id("after", after)
        limit = _positive_int("limit", limit, maximum=200)
        if state is not None:
            state = _safe_id("state", state)
            if state not in _ACTIVE_RUN_STATES:
                raise TestStoreContractError("only active test run states are listable")
        connection = self._connect(readonly=True)
        try:
            cursor: sqlite3.Row | None = None
            if after_value is not None:
                cursor = connection.execute(
                    """
                    SELECT queued_at, run_id FROM test_runs
                    WHERE repository_id = ? AND run_id = ?
                    """,
                    (repository_id, after_value),
                ).fetchone()
                if cursor is None:
                    raise TestStoreNotFound(
                        "test run history cursor does not exist in this repository"
                    )
            clauses = [
                "run.repository_id = ?",
                "run.state IN ('queued', 'running', 'cancelling', 'superseding')",
            ]
            parameters: list[object] = [repository_id]
            if state is not None:
                clauses.append("run.state = ?")
                parameters.append(state)
            if cursor is not None:
                clauses.append(
                    "(run.queued_at < ? OR (run.queued_at = ? AND run.run_id < ?))"
                )
                parameters.extend(
                    [cursor["queued_at"], cursor["queued_at"], cursor["run_id"]]
                )
            parameters.append(limit)
            rows = connection.execute(
                f"""
                SELECT run.*,
                       COUNT(DISTINCT target.target_id) AS target_count,
                       COUNT(DISTINCT CASE WHEN target.state IN (
                         'succeeded', 'test_failed', 'infrastructure_failed',
                         'timed_out', 'cancelled', 'incomplete', 'abandoned',
                         'superseded'
                       ) THEN target.target_id END) AS completed_target_count,
                       MAX(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_since END) AS memory_wait_since,
                       MAX(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_required_mib END) AS memory_wait_required_mib,
                       MIN(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_available_mib END) AS memory_wait_available_mib,
                       MAX(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_reserve_mib END) AS memory_wait_reserve_mib,
                       MAX(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_observed_at END) AS memory_wait_observed_at,
                       MAX(CASE WHEN target.wait_code = 'host_memory'
                         THEN target.wait_source END) AS memory_wait_source,
                       MAX(attempt.peak_memory_bytes) AS peak_memory_bytes,
                       SUM(attempt.cpu_seconds) AS cpu_seconds,
                       COUNT(attempt.attempt_id) AS total_attempts,
                       COUNT(CASE WHEN attempt.peak_memory_bytes IS NOT NULL
                                      OR attempt.cpu_seconds IS NOT NULL
                                  THEN 1 END) AS measured_attempts
                FROM test_runs AS run
                LEFT JOIN test_run_targets AS target ON target.run_id = run.run_id
                LEFT JOIN test_target_attempts AS attempt
                  ON attempt.target_id = target.target_id
                WHERE {' AND '.join(clauses)}
                GROUP BY run.run_id
                ORDER BY run.queued_at DESC, run.run_id DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            result: list[dict[str, object]] = []
            for row in rows:
                item = dict(row)
                wait_required = item.pop("memory_wait_required_mib")
                wait_since = item.pop("memory_wait_since")
                wait_available = item.pop("memory_wait_available_mib")
                wait_reserve = item.pop("memory_wait_reserve_mib")
                wait_observed = item.pop("memory_wait_observed_at")
                wait_source = item.pop("memory_wait_source")
                item["wait"] = (
                    None
                    if wait_required is None
                    else {
                        "code": "host_memory",
                        "since": None if wait_since is None else float(wait_since),
                        "required_mib": int(wait_required),
                        "available_mib": (
                            None if wait_available is None else int(wait_available)
                        ),
                        "reserve_mib": (
                            None if wait_reserve is None else int(wait_reserve)
                        ),
                        "observed_at": (
                            None if wait_observed is None else float(wait_observed)
                        ),
                        "source": None if wait_source is None else str(wait_source),
                    }
                )
                peak = item.pop("peak_memory_bytes")
                cpu = item.pop("cpu_seconds")
                measured = int(item.pop("measured_attempts"))
                total = int(item.pop("total_attempts"))
                item["usage"] = {
                    "available": measured > 0,
                    "peak_memory_mib": (
                        None if peak is None else int(peak) / (1024 * 1024)
                    ),
                    "cpu_seconds": None if cpu is None else float(cpu),
                    "measured_attempts": measured,
                    "total_attempts": total,
                }
                result.append(item)
            return tuple(result)
        finally:
            connection.close()

    def get_plan_document(self, plan_id: str) -> dict[str, object]:
        plan_id = _safe_id("plan_id", plan_id)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                "SELECT plan_json FROM test_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise TestStoreNotFound("test plan does not exist")
            document, _resources = _stored_plan_parts(row["plan_json"])
            return document
        finally:
            connection.close()

    def get_plan_target_resources(
        self, plan_id: str
    ) -> Mapping[str, TargetResources] | None:
        """Restore the exact normalized registration resources after replacement."""

        plan_id = _safe_id("plan_id", plan_id)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                "SELECT plan_json FROM test_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise TestStoreNotFound("test plan does not exist")
            plan_document, raw_resources = _stored_plan_parts(row["plan_json"])
        finally:
            connection.close()
        if raw_resources is None:
            return None
        selected = plan_document.get("selected_targets")
        if not isinstance(selected, list) or any(
            not isinstance(name, str) for name in selected
        ):
            raise TestStoreContractError("stored test plan selection is invalid")
        expected = set(TargetResources.__dataclass_fields__)
        decoded: dict[str, TargetResources] = {}
        if set(raw_resources) != set(selected):
            raise TestStoreContractError(
                "stored test plan target resources are incomplete"
            )
        for name, value in raw_resources.items():
            if not isinstance(name, str) or not isinstance(value, Mapping):
                raise TestStoreContractError(
                    "stored test plan target resources are invalid"
                )
            if set(value) != expected:
                raise TestStoreContractError(
                    "stored test plan target resource fields are invalid"
                )
            estimated = _finite_nonnegative(
                "estimated_seconds", value["estimated_seconds"]
            )
            if estimated <= 0 or estimated > 31_536_000:
                raise TestStoreContractError(
                    "stored estimated_seconds is outside its bound"
                )
            shard_count = _positive_int(
                "shard_count", value["shard_count"], maximum=256
            )
            max_attempts = _positive_int(
                "max_attempts", value["max_attempts"], maximum=16
            )
            worktree = value["worktree_key"]
            if worktree is not None:
                worktree = _single_line("worktree_key", worktree, maximum=4096)
            exclusive_value = value["exclusive_resources"]
            if not isinstance(exclusive_value, list):
                raise TestStoreContractError(
                    "stored exclusive resources are invalid"
                )
            exclusive = tuple(
                _safe_id("exclusive_resource", item)
                for item in exclusive_value
            )
            if tuple(sorted(set(exclusive))) != exclusive:
                raise TestStoreContractError(
                    "stored exclusive resources are invalid"
                )
            decoded[name] = TargetResources(
                estimated_seconds=estimated,
                shard_count=shard_count,
                max_attempts=max_attempts,
                worktree_key=worktree,
                exclusive_resources=exclusive,
            )
        return MappingProxyType(decoded)

    def run_metrics(self, run_id: str) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        connection = self._connect(readonly=True)
        try:
            run = connection.execute(
                "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise TestStoreNotFound("test run does not exist")
            counts = connection.execute(
                """
                SELECT
                  COUNT(*) AS attempt_count,
                  COALESCE(SUM(passed_count), 0) AS passed_count,
                  COALESCE(SUM(failed_count), 0) AS failed_count,
                  COALESCE(SUM(skipped_count), 0) AS skipped_count,
                  COALESCE(SUM(error_count), 0) AS error_count,
                  COALESCE(SUM(duration_seconds), 0.0) AS aggregate_test_seconds
                FROM test_target_attempts WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            targets = connection.execute(
                """
                SELECT state, COUNT(*) AS count FROM test_run_targets
                WHERE run_id = ? GROUP BY state
                """,
                (run_id,),
            ).fetchall()
            target_states = {str(row["state"]): int(row["count"]) for row in targets}
            failure_record_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM test_failures AS failure
                    JOIN test_target_attempts AS attempt
                      ON attempt.attempt_id = failure.attempt_id
                    WHERE attempt.run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            artifact_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM test_artifacts AS artifact
                    JOIN test_target_attempts AS attempt
                      ON attempt.attempt_id = artifact.attempt_id
                    WHERE attempt.run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            return {
                "target_count": sum(target_states.values()),
                "completed_target_count": sum(
                    count
                    for state, count in target_states.items()
                    if state not in {"queued", "leased", "running"}
                ),
                "target_states": target_states,
                "attempt_count": int(counts["attempt_count"]),
                "passed_count": int(counts["passed_count"]),
                "failed_count": int(counts["failed_count"]),
                "skipped_count": int(counts["skipped_count"]),
                "error_count": int(counts["error_count"]),
                "aggregate_test_seconds": float(counts["aggregate_test_seconds"]),
                "failure_record_count": failure_record_count,
                "artifact_count": artifact_count,
                "queue_seconds": (
                    None
                    if run["started_at"] is None
                    else max(0.0, float(run["started_at"]) - float(run["queued_at"]))
                ),
                "wall_seconds": (
                    None
                    if run["started_at"] is None
                    else max(
                        0.0,
                        float(run["finished_at"] or _now(self._clock))
                        - float(run["started_at"]),
                    )
                ),
            }
        finally:
            connection.close()

    def get_attempt(self, attempt_id: str) -> dict[str, object]:
        attempt_id = _safe_id("attempt_id", attempt_id)
        connection = self._connect(readonly=True)
        try:
            return dict(self._attempt(connection, attempt_id))
        finally:
            connection.close()

    @staticmethod
    def _attempt(connection: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM test_target_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise TestStoreNotFound("test attempt does not exist")
        return row

    def failures(
        self, *, run_id: str, after: str | None = None, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        run_id = _safe_id("run_id", run_id)
        after_value = "" if after is None else _safe_id("after", after)
        limit = _positive_int("limit", limit, maximum=500)
        connection = self._connect(readonly=True)
        try:
            return tuple(
                dict(row)
                for row in connection.execute(
                    """
                    SELECT failure.*, target.target_name
                    FROM test_failures AS failure
                    JOIN test_target_attempts AS attempt
                      ON attempt.attempt_id = failure.attempt_id
                    JOIN test_run_targets AS target
                      ON target.target_id = attempt.target_id
                    WHERE attempt.run_id = ? AND failure.failure_id > ?
                    ORDER BY failure.failure_id LIMIT ?
                    """,
                    (run_id, after_value, limit),
                ).fetchall()
            )
        finally:
            connection.close()

    def artifacts(
        self, *, run_id: str, after: str | None = None, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        run_id = _safe_id("run_id", run_id)
        after_value = "" if after is None else _safe_id("after", after)
        limit = _positive_int("limit", limit, maximum=500)
        connection = self._connect(readonly=True)
        try:
            return tuple(
                dict(row)
                for row in connection.execute(
                    """
                    SELECT artifact.*, target.target_name
                    FROM test_artifacts AS artifact
                    JOIN test_target_attempts AS attempt
                      ON attempt.attempt_id = artifact.attempt_id
                    JOIN test_run_targets AS target
                      ON target.target_id = attempt.target_id
                    WHERE attempt.run_id = ? AND artifact.artifact_id > ?
                    ORDER BY artifact.artifact_id LIMIT ?
                    """,
                    (run_id, after_value, limit),
                ).fetchall()
            )
        finally:
            connection.close()

    def artifact(self, *, run_id: str, artifact_id: str) -> dict[str, object]:
        """Resolve one verified artifact through its exact owning run."""

        run_id = _safe_id("run_id", run_id)
        artifact_id = _safe_id("artifact_id", artifact_id)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                """
                SELECT artifact.*, target.target_name
                FROM test_artifacts AS artifact
                JOIN test_target_attempts AS attempt
                  ON attempt.attempt_id = artifact.attempt_id
                JOIN test_run_targets AS target
                  ON target.target_id = attempt.target_id
                WHERE attempt.run_id = ? AND artifact.artifact_id = ?
                """,
                (run_id, artifact_id),
            ).fetchone()
            if row is None:
                raise TestStoreNotFound("test artifact does not exist for this run")
            result = dict(row)
            if not bool(result["verified"]):
                raise TestStoreConflict("test artifact has not been verified")
            expected_handle = f"test-artifact://{artifact_id}/{result['sha256']}"
            if result["storage_handle"] != expected_handle:
                raise TestStoreConflict(
                    "test artifact storage identity is contradictory"
                )
            return result
        finally:
            connection.close()

def prepare_test_store_schema(
    path: Path,
    *,
    operation_id: str,
    expected_uid: int | None = None,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    checkpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Attest one exact fresh current-schema Test Store.

    Test history is disposable on this single-developer server.  Older stores
    are intentionally not migrated: the administrator workflow replaces the
    isolated Test Store, then calls this function.  Console settings, access,
    routes, project runtimes, and authority state live elsewhere.
    """

    operation_id = _operation_id(operation_id)
    store = UniversalTestStore(
        path,
        expected_uid=expected_uid,
        busy_timeout_ms=busy_timeout_ms,
    )
    expected_schema = hashlib.sha256(_SCHEMA.encode("utf-8")).hexdigest()
    connection = store._connect()
    try:
        metadata = connection.execute(
            "SELECT * FROM test_store_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise TestStoreConflict("test store metadata is missing")
        version = int(metadata["schema_version"])
        schema_fingerprint = str(metadata["schema_fingerprint"])
        if version != TEST_STORE_SCHEMA_VERSION or not hmac.compare_digest(
            schema_fingerprint, expected_schema
        ):
            raise TestStoreConflict(
                "test store schema is unsupported; initialize a fresh current store"
            )

        replay = connection.execute(
            """
            SELECT operation_kind, request_fingerprint, result_json
            FROM test_mutation_journal WHERE operation_id = ?
            """,
            (operation_id,),
        ).fetchone()
        if replay is not None:
            operation_kind = str(replay["operation_kind"])
            if operation_kind != "schema_readiness":
                raise TestStoreConflict(
                    "test-store schema operation identity is already used"
                )
            result = json.loads(str(replay["result_json"]))
            if not isinstance(result, dict):
                raise TestStoreConflict(
                    "test-store schema readiness replay is malformed"
                )
            verified = store.verify()
            if result.get("store_generation") != verified["store_generation"]:
                raise TestStoreConflict(
                    "test-store schema readiness generation changed"
                )
            return {
                "schema_version": 1,
                "operation_id": operation_id,
                "action": "attested-fresh",
                "journal_kind": operation_kind,
                "journal": result,
                "store": verified,
            }

        integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if integrity != "ok":
            raise TestStoreConflict(
                f"test store readiness integrity check failed: {integrity}"
            )
        store_generation = str(metadata["store_generation"])
        request_fingerprint = deterministic_fingerprint(
            {
                "operation_id": operation_id,
                "schema_version": TEST_STORE_SCHEMA_VERSION,
                "schema_fingerprint": expected_schema,
                "store_generation": store_generation,
            }
        )
        result = {
            "schema_version": 1,
            "operation_id": operation_id,
            "from_schema_version": TEST_STORE_SCHEMA_VERSION,
            "to_schema_version": TEST_STORE_SCHEMA_VERSION,
            "store_generation": store_generation,
            "schema_fingerprint": expected_schema,
            "quick_check": "ok",
            "status": "succeeded",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            if checkpoint is not None:
                checkpoint("after_begin")
            connection.execute(
                """
                INSERT INTO test_mutation_journal(
                    operation_id, operation_kind, request_fingerprint,
                    result_json, created_at
                ) VALUES (?, 'schema_readiness', ?, ?, ?)
                """,
                (
                    operation_id,
                    request_fingerprint,
                    _canonical_json(result),
                    _now(store._clock),
                ),
            )
            if checkpoint is not None:
                checkpoint("before_commit")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    finally:
        if connection is not None:
            connection.close()
    verified = UniversalTestStore.open(
        path,
        expected_uid=store.expected_uid,
        busy_timeout_ms=busy_timeout_ms,
    ).verify()
    if verified["store_generation"] != result["store_generation"]:
        raise TestStoreConflict("test store generation changed after readiness")
    return {
        "schema_version": 1,
        "operation_id": operation_id,
        "action": "attested-fresh",
        "journal_kind": "schema_readiness",
        "journal": result,
        "store": verified,
    }


__all__ = [
    "ArtifactMetadata",
    "AttemptConclusion",
    "AttemptResultChunk",
    "CaseResult",
    "FailureClassification",
    "FailureRecord",
    "LeaseGrant",
    "RunnableTarget",
    "SubmissionResult",
    "TargetResources",
    "TestStoreConflict",
    "TestStoreContractError",
    "TestStoreError",
    "TestStoreNotFound",
    "TestStoreSecurityError",
    "UniversalTestStore",
    "prepare_test_store_schema",
]
