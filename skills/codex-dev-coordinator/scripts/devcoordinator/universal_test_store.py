"""Disposable durable state for the universal asynchronous test harness.

The authority store deliberately does not import this module. Testd owns one
immutable run state machine. Each run-target has at most one execution slot;
there are no scheduler leases, attempt chains, or incrementally committed
result chunks.

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
    EvidencePolicy,
    SourceMode,
    deterministic_fingerprint,
    evidence_policy_fingerprint,
)
from .universal_test_planner import TestPlan
from .store import refuse_symlink_components


TEST_STORE_SCHEMA_VERSION = 8
DEFAULT_BUSY_TIMEOUT_MS = 5_000
MAX_CASE_RESULTS = 100_000
MAX_FAILURE_RESULTS = MAX_CASE_RESULTS
MAX_ARTIFACT_RESULTS = 64
MAX_RESULT_PACKAGE_BYTES = 1024 * 1024 * 1024
MAX_EVENT_DETAIL_BYTES = 16 * 1024
MAX_ROLLUP_REBUILD_BATCH = 1_000
MAX_NONTERMINAL_RUNS_PER_RECONCILE = 10_000
DEFAULT_MEMORY_BOOTSTRAP_MIB = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SYSTEMD_UNIT = re.compile(
    r"^devcoordinator-test-[A-Za-z0-9][A-Za-z0-9_.@:-]{0,199}\.service$"
)
_ACTIVE_RUN_STATES = ("queued", "running", "cancelling")
_RUN_STATES = (
    *_ACTIVE_RUN_STATES,
    "succeeded",
    "failed",
    "timed_out",
    "cancelled",
    "incomplete",
)
_ACTIVE_TARGET_STATES = ("starting", "running", "stopping")
_TERMINAL_TARGET_STATES = (
    "succeeded",
    "test_failed",
    "infrastructure_failed",
    "timed_out",
    "cancelled",
    "incomplete",
)


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


class AttemptConclusion(str, Enum):
    SUCCEEDED = "succeeded"
    TEST_FAILED = "test_failed"
    INFRASTRUCTURE_FAILED = "infrastructure_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"


_CONCLUSION_CLASSIFICATION: Mapping[AttemptConclusion, FailureClassification | None] = {
    AttemptConclusion.SUCCEEDED: None,
    AttemptConclusion.TEST_FAILED: FailureClassification.TEST_FAILURE,
    AttemptConclusion.INFRASTRUCTURE_FAILED: FailureClassification.INFRASTRUCTURE_FAILURE,
    AttemptConclusion.TIMED_OUT: FailureClassification.TIMEOUT,
    AttemptConclusion.CANCELLED: FailureClassification.CANCELLATION,
    AttemptConclusion.INCOMPLETE: FailureClassification.INCOMPLETE_REPORTING,
}


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
    worktree_key: str | None = None
    exclusive_resources: tuple[str, ...] = ()
    ttl_seconds: int | None = None


@dataclass(frozen=True)
class SubmissionResult:
    run_id: str
    state: str
    deduplicated: bool
    deduplicated_run_id: str | None
    console_path: str


@dataclass(frozen=True)
class ExecutionGrant:
    execution_id: str
    target_id: str
    run_id: str
    target_name: str
    shard_index: int
    shard_count: int
    generation: int
    systemd_unit: str
    launch_operation_id: str

    @property
    def attempt_id(self) -> str:
        """Stable read compatibility for clients that still label executions attempts."""

        return self.execution_id


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
class ExecutionResultPackage:
    package_id: str
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
    memory_estimate_source: str = "cold_start_default"
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
    source_mode TEXT NOT NULL CHECK(source_mode = 'immutable'),
    content_fingerprint TEXT NOT NULL,
    manifest_fingerprint TEXT NOT NULL,
    original_root TEXT NOT NULL,
    temporary_root TEXT,
    complete INTEGER NOT NULL CHECK(complete = 1),
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
    source_mode TEXT NOT NULL CHECK(source_mode = 'immutable'),
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
    source_mode TEXT NOT NULL CHECK(source_mode = 'immutable'),
    source_fingerprint TEXT NOT NULL,
    execution_fingerprint TEXT NOT NULL,
    eligible_target_count INTEGER NOT NULL CHECK(eligible_target_count >= 0),
    selected_target_count INTEGER NOT NULL CHECK(selected_target_count >= 0),
    state TEXT NOT NULL CHECK(state IN (
      'queued', 'running', 'cancelling', 'succeeded', 'failed',
      'timed_out', 'cancelled', 'incomplete'
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
WHERE state IN ('queued', 'running', 'cancelling');
CREATE INDEX test_runs_repository_time
ON test_runs(repository_id, queued_at DESC, run_id);

CREATE TABLE test_run_targets (
    target_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    target_name TEXT NOT NULL,
    wave_index INTEGER NOT NULL CHECK(wave_index >= 0),
    exact_dependencies_json TEXT NOT NULL,
    shard_index INTEGER NOT NULL CHECK(shard_index >= 0),
    shard_count INTEGER NOT NULL CHECK(shard_count > 0),
    state TEXT NOT NULL CHECK(state IN (
      'queued', 'starting', 'running', 'stopping', 'succeeded', 'test_failed',
      'infrastructure_failed', 'timed_out', 'cancelled', 'incomplete'
    )),
    estimated_seconds REAL NOT NULL CHECK(estimated_seconds > 0),
    worktree_key TEXT NOT NULL,
    exclusive_resources_json TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL CHECK(ttl_seconds > 0),
    wait_code TEXT,
    wait_since REAL,
    wait_required_mib INTEGER,
    wait_available_mib INTEGER,
    wait_reserve_mib INTEGER,
    wait_observed_at REAL,
    wait_source TEXT,
    execution_id TEXT UNIQUE,
    generation INTEGER CHECK(generation IS NULL OR generation = 1),
    store_generation TEXT,
    repository_generation INTEGER CHECK(
      repository_generation IS NULL OR repository_generation >= 0
    ),
    systemd_unit TEXT UNIQUE,
    systemd_invocation_id TEXT,
    launch_operation_id TEXT UNIQUE,
    launch_ack_id TEXT,
    descriptor_fingerprint TEXT,
    launch_deadline_at REAL,
    memory_commitment_mib INTEGER CHECK(
      memory_commitment_mib IS NULL OR memory_commitment_mib > 0
    ),
    started_at REAL,
    deadline_at REAL,
    last_observed_at REAL,
    stop_reason TEXT,
    stdout_bytes INTEGER NOT NULL DEFAULT 0 CHECK(stdout_bytes >= 0),
    stderr_bytes INTEGER NOT NULL DEFAULT 0 CHECK(stderr_bytes >= 0),
    stdout_retained_bytes INTEGER NOT NULL DEFAULT 0 CHECK(stdout_retained_bytes >= 0),
    stderr_retained_bytes INTEGER NOT NULL DEFAULT 0 CHECK(stderr_retained_bytes >= 0),
    stdout_truncated INTEGER NOT NULL DEFAULT 0 CHECK(stdout_truncated IN (0, 1)),
    stderr_truncated INTEGER NOT NULL DEFAULT 0 CHECK(stderr_truncated IN (0, 1)),
    current_memory_bytes INTEGER CHECK(
      current_memory_bytes IS NULL OR current_memory_bytes >= 0
    ),
    last_output_at REAL,
    progress_observed_at REAL,
    terminal_operation_id TEXT UNIQUE,
    terminal_fingerprint TEXT,
    result_package_fingerprint TEXT,
    conclusion TEXT,
    failure_classification TEXT,
    duration_seconds REAL,
    peak_memory_bytes INTEGER CHECK(
      peak_memory_bytes IS NULL OR peak_memory_bytes >= 0
    ),
    cpu_seconds REAL CHECK(cpu_seconds IS NULL OR cpu_seconds >= 0),
    passed_count INTEGER NOT NULL DEFAULT 0 CHECK(passed_count >= 0),
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count >= 0),
    skipped_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK(error_count >= 0),
    reporter_complete INTEGER NOT NULL DEFAULT 0 CHECK(reporter_complete IN (0, 1)),
    queued_at REAL NOT NULL,
    finished_at REAL,
    collected_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(run_id, target_name, shard_index),
    CHECK(
      (
        execution_id IS NULL AND generation IS NULL
        AND store_generation IS NULL AND repository_generation IS NULL
        AND systemd_unit IS NULL AND launch_operation_id IS NULL
        AND descriptor_fingerprint IS NULL AND launch_deadline_at IS NULL
        AND memory_commitment_mib IS NULL
      )
      OR
      (
        execution_id IS NOT NULL AND generation = 1
        AND store_generation IS NOT NULL AND repository_generation IS NOT NULL
        AND systemd_unit IS NOT NULL AND launch_operation_id IS NOT NULL
        AND descriptor_fingerprint IS NOT NULL AND launch_deadline_at IS NOT NULL
        AND memory_commitment_mib IS NOT NULL
      )
    ),
    CHECK(
      state NOT IN ('starting', 'running', 'stopping')
      OR execution_id IS NOT NULL
    )
) STRICT;
CREATE INDEX test_run_targets_schedule
ON test_run_targets(state, wave_index, queued_at, target_id);
CREATE INDEX test_run_targets_execution
ON test_run_targets(execution_id, generation);
CREATE INDEX test_run_targets_measurements
ON test_run_targets(target_name, finished_at DESC)
WHERE peak_memory_bytes IS NOT NULL;

CREATE TABLE test_target_resource_profiles (
    repository_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    sample_count INTEGER NOT NULL CHECK(sample_count > 0),
    recent_peak_memory_bytes INTEGER NOT NULL CHECK(recent_peak_memory_bytes >= 0),
    last_peak_memory_bytes INTEGER NOT NULL CHECK(last_peak_memory_bytes >= 0),
    last_cpu_seconds REAL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(repository_id, target_name),
    CHECK(last_cpu_seconds IS NULL OR last_cpu_seconds >= 0)
) STRICT;

CREATE TABLE test_case_results (
    target_id TEXT NOT NULL REFERENCES test_run_targets(target_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    case_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('passed', 'failed', 'skipped', 'error')),
    duration_seconds REAL NOT NULL CHECK(duration_seconds >= 0),
    location TEXT,
    PRIMARY KEY(target_id, ordinal),
    UNIQUE(target_id, case_id)
) STRICT;

CREATE TABLE test_failures (
    failure_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES test_run_targets(target_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    classification TEXT NOT NULL,
    case_id TEXT,
    message TEXT NOT NULL,
    location TEXT,
    artifact_id TEXT,
    created_at REAL NOT NULL,
    UNIQUE(target_id, ordinal)
) STRICT;
CREATE INDEX test_failures_target ON test_failures(target_id, ordinal, failure_id);

CREATE TABLE test_artifacts (
    artifact_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES test_run_targets(target_id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    kind TEXT NOT NULL,
    storage_handle TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    verified INTEGER NOT NULL CHECK(verified IN (0, 1)),
    created_at REAL NOT NULL,
    UNIQUE(target_id, ordinal)
) STRICT;
CREATE INDEX test_artifacts_target ON test_artifacts(target_id, ordinal, artifact_id);

CREATE TABLE test_evidence_attestations (
    attestation_id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES test_snapshots(snapshot_id),
    run_id TEXT NOT NULL REFERENCES test_runs(run_id),
    policy_fingerprint TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    UNIQUE(run_id, policy_name, policy_fingerprint)
) STRICT;
CREATE INDEX test_evidence_attestations_lookup
ON test_evidence_attestations(
  repository_id, snapshot_id, policy_name, issued_at DESC, attestation_id
);

CREATE TABLE test_evidence_consumptions (
    consumption_id TEXT PRIMARY KEY,
    attestation_id TEXT NOT NULL UNIQUE
      REFERENCES test_evidence_attestations(attestation_id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL UNIQUE,
    consumed_at REAL NOT NULL
) STRICT;
CREATE INDEX test_evidence_consumptions_attestation
ON test_evidence_consumptions(attestation_id, consumed_at);

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

CREATE TABLE test_repository_setup_projections (
    repository_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('ready', 'missing', 'invalid')),
    manifest_fingerprint TEXT,
    projection_fingerprint TEXT NOT NULL,
    projection_json TEXT NOT NULL,
    observed_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    CHECK(
      (status = 'ready' AND manifest_fingerprint IS NOT NULL)
      OR (status != 'ready' AND manifest_fingerprint IS NULL)
    )
) STRICT;

CREATE TABLE test_mutation_journal (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at REAL NOT NULL
) STRICT;

CREATE TABLE test_rollup_hourly (
    repository_id TEXT NOT NULL,
    bucket_start REAL NOT NULL,
    run_count INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL,
    selected_target_count INTEGER NOT NULL,
    eligible_target_count INTEGER NOT NULL,
    avoided_target_count INTEGER NOT NULL,
    case_count INTEGER NOT NULL,
    passed_count INTEGER NOT NULL,
    failed_count INTEGER NOT NULL,
    skipped_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    queue_seconds REAL NOT NULL,
    attempt_queue_seconds REAL NOT NULL,
    aggregate_test_seconds REAL NOT NULL,
    attempt_wall_seconds REAL NOT NULL,
    wall_seconds REAL NOT NULL,
    retry_attempt_count INTEGER NOT NULL,
    flake_count INTEGER NOT NULL,
    slow_count INTEGER NOT NULL,
    regression_count INTEGER NOT NULL,
    max_attempt_seconds REAL NOT NULL,
    success_count INTEGER NOT NULL,
    failure_count INTEGER NOT NULL,
    infrastructure_count INTEGER NOT NULL,
    PRIMARY KEY(repository_id, bucket_start)
) STRICT;

CREATE TABLE test_rollup_daily (
    repository_id TEXT NOT NULL,
    bucket_start REAL NOT NULL,
    run_count INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL,
    selected_target_count INTEGER NOT NULL,
    eligible_target_count INTEGER NOT NULL,
    avoided_target_count INTEGER NOT NULL,
    case_count INTEGER NOT NULL,
    passed_count INTEGER NOT NULL,
    failed_count INTEGER NOT NULL,
    skipped_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    queue_seconds REAL NOT NULL,
    attempt_queue_seconds REAL NOT NULL,
    aggregate_test_seconds REAL NOT NULL,
    attempt_wall_seconds REAL NOT NULL,
    wall_seconds REAL NOT NULL,
    retry_attempt_count INTEGER NOT NULL,
    flake_count INTEGER NOT NULL,
    slow_count INTEGER NOT NULL,
    regression_count INTEGER NOT NULL,
    max_attempt_seconds REAL NOT NULL,
    success_count INTEGER NOT NULL,
    failure_count INTEGER NOT NULL,
    infrastructure_count INTEGER NOT NULL,
    PRIMARY KEY(repository_id, bucket_start)
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


def _retry_plan_projection(
    plan_json: object,
    *,
    selected_targets: Sequence[str],
) -> tuple[str, str, str, str]:
    """Derive one dense exact-dependency plan for a retained-run retry."""

    try:
        source, resources = _stored_plan_parts(plan_json)
    except TestStoreContractError as error:
        raise TestStoreContractError("stored retry source plan is invalid") from error
    selected = tuple(sorted(set(selected_targets)))
    if not selected:
        raise TestStoreContractError("retry plan requires selected targets")
    dependencies = _stored_plan_dependencies(plan_json)
    if not set(selected).issubset(dependencies):
        raise TestStoreContractError("retry targets exceed the stored plan")
    selected_set = set(selected)
    projected_dependencies = {
        target: tuple(
            dependency
            for dependency in dependencies[target]
            if dependency in selected_set
        )
        for target in selected
    }
    unresolved = set(selected)
    resolved: set[str] = set()
    waves: list[list[str]] = []
    while unresolved:
        wave = sorted(
            target
            for target in unresolved
            if set(projected_dependencies[target]).issubset(resolved)
        )
        if not wave:
            raise TestStoreContractError("retry plan dependencies contain a cycle")
        waves.append(wave)
        unresolved.difference_update(wave)
        resolved.update(wave)
    selection = source.get("selection")
    if not isinstance(selection, dict) or not selected_set.issubset(selection):
        raise TestStoreContractError("stored retry plan selection is invalid")
    document = dict(source)
    document["selected_targets"] = list(selected)
    document["dependency_waves"] = waves
    document["dependencies"] = {
        target: list(projected_dependencies[target]) for target in selected
    }
    document["selection"] = {target: selection[target] for target in selected}
    try:
        fingerprint_document = {
            "schema_version": 3,
            "manifest_fingerprint": document["manifest_fingerprint"],
            "repository_id": document["repository_id"],
            "intent": document["intent"],
            "timeouts": document["timeouts"],
            "source": document["source"],
            "changes": document["changes"],
            "eligible_targets": document["eligible_targets"],
            "selected_targets": document["selected_targets"],
            "dependency_waves": document["dependency_waves"],
            "dependencies": document["dependencies"],
            "selection": document["selection"],
            "complete_intent_fallback": document["complete_intent_fallback"],
            "reusable": document["reusable"],
        }
        execution_document = {
            "schema_version": 3,
            "manifest_fingerprint": document["manifest_fingerprint"],
            "repository_id": document["repository_id"],
            "source_mode": document["source"]["mode"],
            "content_fingerprint": document["source"]["content_fingerprint"],
            "intent": document["intent"],
            "timeouts": document["timeouts"],
            "eligible_targets": document["eligible_targets"],
            "selected_targets": document["selected_targets"],
            "dependency_waves": document["dependency_waves"],
            "dependencies": document["dependencies"],
        }
    except (KeyError, TypeError) as error:
        raise TestStoreContractError("stored retry source plan is invalid") from error
    fingerprint = deterministic_fingerprint(fingerprint_document)
    execution_fingerprint = deterministic_fingerprint(execution_document)
    plan_id = "plan-" + fingerprint[:32]
    document["plan_id"] = plan_id
    document["fingerprint"] = fingerprint
    document["execution_fingerprint"] = execution_fingerprint
    if resources is not None:
        document[_STORED_PLAN_RESOURCES_FIELD] = {
            target: resources[target]
            for target in selected
            if target in resources
        }
    return plan_id, fingerprint, execution_fingerprint, _canonical_json(document)


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


def _bucket_start(timestamp: float, seconds: int) -> float:
    return float(int(timestamp) // seconds * seconds)


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
        """Submit one immutable plan and create one execution slot per target."""

        if not isinstance(plan, TestPlan):
            raise TestStoreContractError("plan must be a validated TestPlan")
        if plan.source.mode is not SourceMode.IMMUTABLE or plan.source.snapshot_id is None:
            raise TestStoreContractError("governed test plans must use an immutable snapshot")
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
            existing = connection.execute(
                f"""
                SELECT run_id, state FROM test_runs
                WHERE execution_fingerprint = ?
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
                self._record_mutation(
                    connection,
                    operation_id=operation_id,
                    operation_kind="submit",
                    request_fingerprint=request_fingerprint,
                    result=result.__dict__,
                    created_at=timestamp,
                )
                return result
            run_id = "run-" + hashlib.sha256(
                f"{operation_id}\0{request_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
            initial_state = "queued" if plan.selected_targets else "succeeded"
            initial_finished_at = None if plan.selected_targets else timestamp
            connection.execute(
                """
                INSERT INTO test_runs(
                    run_id, plan_id, repository_id, owner_uid, actor, intent,
                    source_mode, source_fingerprint, execution_fingerprint,
                    eligible_target_count, selected_target_count,
                    state, conclusion, priority, queued_at, finished_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'immutable', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    plan.plan_id,
                    plan.repository_id,
                    owner_uid,
                    actor,
                    plan.intent,
                    plan.source.content_fingerprint,
                    plan.execution_fingerprint,
                    len(plan.eligible_targets),
                    len(plan.selected_targets),
                    initial_state,
                    "succeeded" if not plan.selected_targets else None,
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
                ttl_seconds = (
                    resource.ttl_seconds
                    or plan.timeouts.execution_seconds
                    or 300
                )
                dependencies = tuple(sorted(set(plan.dependencies.get(target_name, ()))))
                for shard_index in range(resource.shard_count):
                    target_id = "target-" + hashlib.sha256(
                        f"{run_id}\0{target_name}\0{shard_index}".encode("utf-8")
                    ).hexdigest()[:32]
                    connection.execute(
                        """
                        INSERT INTO test_run_targets(
                            target_id, run_id, target_name, wave_index,
                            exact_dependencies_json, shard_index, shard_count,
                            state, estimated_seconds, worktree_key,
                            exclusive_resources_json, ttl_seconds,
                            queued_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            target_id,
                            run_id,
                            target_name,
                            wave_by_target[target_name],
                            _canonical_json(list(dependencies)),
                            shard_index,
                            resource.shard_count,
                            resource.estimated_seconds,
                            resource.worktree_key
                            or plan.source.temporary_root
                            or plan.source.original_root,
                            _canonical_json(list(resource.exclusive_resources)),
                            ttl_seconds,
                            timestamp,
                            timestamp,
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
                    "source_mode": "immutable",
                    "target_count": len(plan.selected_targets),
                },
                created_at=timestamp,
            )
            if initial_finished_at is not None:
                self._refresh_rollups(
                    connection,
                    repository_id=plan.repository_id,
                    finished_at=initial_finished_at,
                )
            return result

    def register_plan(
        self,
        plan: TestPlan,
        *,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> dict[str, object]:
        """Durably register one immutable normalized plan before submission."""

        if not isinstance(plan, TestPlan):
            raise TestStoreContractError("plan must be a validated TestPlan")
        if plan.source.mode is not SourceMode.IMMUTABLE or plan.source.snapshot_id is None:
            raise TestStoreContractError("governed test plans must use an immutable snapshot")
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
            if not 0 < estimated <= 31_536_000:
                raise TestStoreContractError("estimated_seconds is outside its bound")
            _positive_int("shard_count", resource.shard_count, maximum=256)
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
            ttl_seconds = resource.ttl_seconds
            if ttl_seconds is not None:
                ttl_seconds = _positive_int(
                    "ttl_seconds", ttl_seconds, maximum=31_536_000
                )
            result[name] = TargetResources(
                estimated_seconds=estimated,
                shard_count=resource.shard_count,
                worktree_key=worktree,
                exclusive_resources=exclusive,
                ttl_seconds=ttl_seconds,
            )
        return result

    @staticmethod
    def _resource_document(resource: TargetResources) -> dict[str, object]:
        return {
            "estimated_seconds": resource.estimated_seconds,
            "shard_count": resource.shard_count,
            "worktree_key": resource.worktree_key,
            "exclusive_resources": list(resource.exclusive_resources),
            "ttl_seconds": resource.ttl_seconds,
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
        if source.mode is not SourceMode.IMMUTABLE or source.snapshot_id is None:
            raise TestStoreContractError("governed test plans must use an immutable snapshot")
        snapshot_id = source.snapshot_id
        snapshot_document = {
            "source": source.to_document(),
            "manifest_fingerprint": plan.manifest_fingerprint,
        }
        existing = connection.execute(
            "SELECT * FROM test_snapshots WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        expected_snapshot = (
            source.repository_id,
            "immutable",
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'immutable', ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.fingerprint,
                    plan.execution_fingerprint,
                    plan.manifest_fingerprint,
                    plan.repository_id,
                    plan.intent,
                    snapshot_id,
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
                       profile.sample_count AS memory_sample_count,
                       profile.recent_peak_memory_bytes
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                LEFT JOIN test_target_resource_profiles AS profile
                  ON profile.repository_id = run.repository_id
                 AND profile.target_name = target.target_name
                WHERE target.state = 'queued'
                  AND run.state IN ('queued', 'running')
                ORDER BY run.priority DESC, target.queued_at, target.target_id
                LIMIT 10000
                """
            ).fetchall()
            states_by_run: dict[str, dict[str, list[str]]] = {}
            for row in rows:
                run_id = str(row["run_id"])
                if run_id in states_by_run:
                    continue
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
                    dependencies={
                        str(row["target_name"]): tuple(
                            json.loads(str(row["exact_dependencies_json"]))
                        )
                    },
                    states=states_by_run[str(row["run_id"])],
                )
            ]
            return tuple(runnable[:limit])
        finally:
            connection.close()

    @staticmethod
    def _runnable_target(row: sqlite3.Row) -> RunnableTarget:
        recent_peak = row["recent_peak_memory_bytes"]
        sample_count = row["memory_sample_count"]
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
            source_mode="immutable",
            memory_estimate_mib=(
                DEFAULT_MEMORY_BOOTSTRAP_MIB
                if recent_peak is None
                else max(1, (int(recent_peak) + (1024 * 1024) - 1) // (1024 * 1024))
            ),
            memory_estimate_source=(
                "cold_start_default" if recent_peak is None else "learned_peak"
            ),
            memory_sample_count=0 if sample_count is None else int(sample_count),
        )

    def active_allocations(self) -> tuple[dict[str, object], ...]:
        connection = self._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                WHERE target.state IN ('starting', 'running', 'stopping')
                ORDER BY target.created_at, target.target_id
                """
            ).fetchall()
            return tuple(
                {
                    "attempt_id": str(row["execution_id"]),
                    "execution_id": str(row["execution_id"]),
                    "target_id": str(row["target_id"]),
                    "repository_id": str(row["repository_id"]),
                    "owner_uid": int(row["owner_uid"]),
                    "worktree_key": str(row["worktree_key"]),
                    "source_mode": "immutable",
                    "memory_commitment_mib": int(row["memory_commitment_mib"]),
                    "current_memory_bytes": (
                        None
                        if row["current_memory_bytes"] is None
                        else int(row["current_memory_bytes"])
                    ),
                    "runtime_active": str(row["state"]) in _ACTIVE_TARGET_STATES,
                    "exclusive_resources": tuple(
                        json.loads(row["exclusive_resources_json"])
                    ),
                }
                for row in rows
            )
        finally:
            connection.close()

    def queue_status(self, *, repository_id: str) -> dict[str, object]:
        """Return bounded current queue evidence without requiring a run ID."""

        repository_id = _safe_id("repository_id", repository_id)
        connection = self._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT run.repository_id, target.state, COUNT(*) AS count
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                WHERE target.state IN ('queued', 'starting', 'running', 'stopping')
                  AND run.state IN ('queued', 'running', 'cancelling')
                GROUP BY run.repository_id, target.state
                """
            ).fetchall()
            names = ("queued", "starting", "running", "stopping")
            global_counts = {name: 0 for name in names}
            repository_counts = {name: 0 for name in names}
            for row in rows:
                state = str(row["state"])
                count = int(row["count"])
                global_counts[state] += count
                if str(row["repository_id"]) == repository_id:
                    repository_counts[state] += count
            blockers = [
                {"code": str(row["wait_code"]), "target_count": int(row["count"])}
                for row in connection.execute(
                    """
                    SELECT target.wait_code, COUNT(*) AS count
                    FROM test_run_targets AS target
                    JOIN test_runs AS run ON run.run_id = target.run_id
                    WHERE run.repository_id = ?
                      AND target.state = 'queued'
                      AND target.wait_code IS NOT NULL
                    GROUP BY target.wait_code
                    ORDER BY target.wait_code
                    LIMIT 16
                    """,
                    (repository_id,),
                ).fetchall()
            ]
            representative_targets = [
                {
                    "run_id": str(row["run_id"]),
                    "target_name": str(row["target_name"]),
                    "state": str(row["state"]),
                    "attempt_id": (
                        None if row["execution_id"] is None else str(row["execution_id"])
                    ),
                    "execution_id": (
                        None if row["execution_id"] is None else str(row["execution_id"])
                    ),
                    "wait_code": (
                        None if row["wait_code"] is None else str(row["wait_code"])
                    ),
                }
                for row in connection.execute(
                    """
                    SELECT target.run_id, target.target_name, target.state,
                           target.execution_id, target.wait_code
                    FROM test_run_targets AS target
                    JOIN test_runs AS run ON run.run_id = target.run_id
                    WHERE run.repository_id = ?
                      AND target.state IN ('queued', 'starting', 'running', 'stopping')
                      AND run.state IN ('queued', 'running', 'cancelling')
                    ORDER BY target.queued_at, target.target_id
                    LIMIT 16
                    """,
                    (repository_id,),
                ).fetchall()
            ]
        finally:
            connection.close()
        runnable = self.runnable_targets(limit=10_000)
        repository_positions = [
            index
            for index, candidate in enumerate(runnable, start=1)
            if candidate.repository_id == repository_id
        ]
        runnable_count = len(repository_positions)
        dependency_blocked = max(0, repository_counts["queued"] - runnable_count)
        if dependency_blocked:
            blockers.append(
                {"code": "dependency_wave", "target_count": dependency_blocked}
            )
        phase = (
            "execution"
            if repository_counts["running"] or repository_counts["stopping"]
            else "launch"
            if repository_counts["starting"]
            else "scheduler"
            if repository_counts["queued"]
            else "idle"
        )
        # Keep the old count names as a read-only compatibility projection.
        global_projection = {
            **global_counts,
            "leased": global_counts["starting"],
        }
        repository_projection = {
            **repository_counts,
            "leased": repository_counts["starting"],
        }
        return {
            "repository_id": repository_id,
            "sampled_at": _now(self._clock),
            "phase": phase,
            "global_targets": global_projection,
            "repository_targets": repository_projection,
            "repository_runnable_targets": runnable_count,
            "approximate_first_position": (
                min(repository_positions) if repository_positions else None
            ),
            "position_population_truncated": len(runnable) == 10_000,
            "blockers": blockers[:16],
            "representative_targets": representative_targets,
            "worker_capacity": {
                "model": "dynamic_memory_admission",
                "limit": None,
                "available": None,
            },
        }

    def record_schedule_decision(
        self,
        *,
        selected_target_ids: Sequence[str],
        rejected: Sequence[Mapping[str, object]],
    ) -> None:
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
            wait["observed_at"] = (
                None
                if observed_at is None
                else _finite_nonnegative("scheduler observed_at", observed_at)
            )
            source = raw.get("source")
            wait["source"] = (
                None if source is None else _safe_id("scheduler memory source", source)
            )
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

    def begin_execution(
        self,
        target_id: str,
        *,
        repository_generation: int,
        systemd_unit: str,
        launch_operation_id: str,
        descriptor_fingerprint: str,
        launch_deadline_at: float,
        memory_commitment_mib: int = DEFAULT_MEMORY_BOOTSTRAP_MIB,
        operation_id: str,
    ) -> ExecutionGrant:
        """Persist exact native identity before the first host launch RPC."""

        target_id = _safe_id("target_id", target_id)
        if type(repository_generation) is not int or repository_generation < 0:
            raise TestStoreContractError("repository_generation is invalid")
        systemd_unit = _single_line("systemd_unit", systemd_unit, maximum=256)
        if _SYSTEMD_UNIT.fullmatch(systemd_unit) is None:
            raise TestStoreContractError("systemd_unit is invalid")
        launch_operation_id = _operation_id(launch_operation_id)
        descriptor_fingerprint = _sha256(
            "descriptor_fingerprint", descriptor_fingerprint
        )
        launch_deadline = _finite_nonnegative(
            "launch_deadline_at", launch_deadline_at
        )
        memory_commitment_mib = _positive_int(
            "memory_commitment_mib", memory_commitment_mib, maximum=1 << 40
        )
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "target_id": target_id,
                "repository_generation": repository_generation,
                "systemd_unit": systemd_unit,
                "launch_operation_id": launch_operation_id,
                "descriptor_fingerprint": descriptor_fingerprint,
                "launch_deadline_at": launch_deadline,
                "memory_commitment_mib": memory_commitment_mib,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="execution_begin",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return ExecutionGrant(**replay)
            target = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid,
                       run.state AS run_state
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                WHERE target.target_id = ?
                """,
                (target_id,),
            ).fetchone()
            if target is None:
                raise TestStoreNotFound("test target does not exist")
            if str(target["state"]) != "queued" or str(target["run_state"]) not in {
                "queued", "running"
            }:
                raise TestStoreConflict("test target is not runnable")
            states: dict[str, list[str]] = {}
            for row in connection.execute(
                "SELECT target_name, state FROM test_run_targets WHERE run_id = ?",
                (target["run_id"],),
            ):
                states.setdefault(str(row["target_name"]), []).append(str(row["state"]))
            dependencies = tuple(json.loads(str(target["exact_dependencies_json"])))
            if not _target_dependencies_succeeded(
                target_name=str(target["target_name"]),
                dependencies={str(target["target_name"]): dependencies},
                states=states,
            ):
                raise TestStoreConflict("test target exact dependencies are incomplete")
            store_generation = self._generation(connection)
            execution_id = "execution-" + hashlib.sha256(
                f"{store_generation}\0{target_id}".encode("utf-8")
            ).hexdigest()[:32]
            changed = connection.execute(
                """
                UPDATE test_run_targets
                SET state = 'starting', execution_id = ?, generation = 1,
                    store_generation = ?, repository_generation = ?,
                    systemd_unit = ?, launch_operation_id = ?,
                    descriptor_fingerprint = ?, launch_deadline_at = ?,
                    memory_commitment_mib = ?,
                    wait_code = NULL, wait_since = NULL,
                    wait_required_mib = NULL, wait_available_mib = NULL,
                    wait_reserve_mib = NULL, wait_observed_at = NULL,
                    wait_source = NULL, updated_at = ?
                WHERE target_id = ? AND state = 'queued'
                """,
                (
                    execution_id,
                    store_generation,
                    repository_generation,
                    systemd_unit,
                    launch_operation_id,
                    descriptor_fingerprint,
                    launch_deadline,
                    memory_commitment_mib,
                    timestamp,
                    target_id,
                ),
            ).rowcount
            if changed != 1:
                raise TestStoreConflict("test target changed during execution reservation")
            connection.execute(
                """
                UPDATE test_runs
                SET state = 'running', started_at = COALESCE(started_at, ?),
                    updated_at = ?
                WHERE run_id = ? AND state IN ('queued', 'running')
                """,
                (timestamp, timestamp, target["run_id"]),
            )
            grant = ExecutionGrant(
                execution_id=execution_id,
                target_id=target_id,
                run_id=str(target["run_id"]),
                target_name=str(target["target_name"]),
                shard_index=int(target["shard_index"]),
                shard_count=int(target["shard_count"]),
                generation=1,
                systemd_unit=systemd_unit,
                launch_operation_id=launch_operation_id,
            )
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="execution_begin",
                request_fingerprint=request_fingerprint,
                result=grant.__dict__,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.execution_reserved",
                repository_id=str(target["repository_id"]),
                run_id=str(target["run_id"]),
                attempt_id=execution_id,
                detail={
                    "target_id": target_id,
                    "generation": 1,
                    "systemd_unit": systemd_unit,
                },
                created_at=timestamp,
            )
            return grant

    def execution_identity(self, target_id: str) -> str:
        """Return the exact execution ID that ``begin_execution`` will reserve.

        This read-only preview lets protected descriptor resolution bind the
        final attempt identity before any native start.  The subsequent
        mutation revalidates that the target is still queued and recomputes the
        same store-generation-bound value transactionally.
        """

        target_id = _safe_id("target_id", target_id)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                "SELECT state FROM test_run_targets WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                raise TestStoreNotFound("test target does not exist")
            if str(row["state"]) != "queued":
                raise TestStoreConflict("test target is not awaiting execution")
            store_generation = self._generation(connection)
            return "execution-" + hashlib.sha256(
                f"{store_generation}\0{target_id}".encode("utf-8")
            ).hexdigest()[:32]
        finally:
            connection.close()

    @staticmethod
    def _require_execution(
        target: sqlite3.Row,
        *,
        execution_id: str,
        generation: int,
        systemd_unit: str | None = None,
        active: bool = True,
    ) -> None:
        if type(generation) is not int or generation <= 0:
            raise TestStoreContractError("execution generation must be positive")
        if (
            str(target["execution_id"] or "") != execution_id
            or int(target["generation"] or 0) != generation
        ):
            raise TestStoreConflict("execution identity or generation is stale")
        if systemd_unit is not None and str(target["systemd_unit"]) != systemd_unit:
            raise TestStoreConflict("execution systemd unit identity changed")
        if active and str(target["state"]) not in _ACTIVE_TARGET_STATES:
            raise TestStoreConflict("execution is no longer active")

    @staticmethod
    def _execution(
        connection: sqlite3.Connection, execution_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM test_run_targets WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise TestStoreNotFound("test execution does not exist")
        return row

    def record_started(
        self,
        execution_id: str,
        *,
        generation: int,
        systemd_unit: str,
        launch_ack_id: str,
        started_at: float,
        systemd_invocation_id: str | None = None,
        operation_id: str,
    ) -> dict[str, object]:
        execution_id = _safe_id("execution_id", execution_id)
        systemd_unit = _single_line("systemd_unit", systemd_unit, maximum=256)
        launch_ack_id = _safe_id("launch_ack_id", launch_ack_id)
        started = _finite_nonnegative("started_at", started_at)
        if systemd_invocation_id is not None:
            systemd_invocation_id = _safe_id(
                "systemd_invocation_id", systemd_invocation_id
            )
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "execution_id": execution_id,
                "generation": generation,
                "systemd_unit": systemd_unit,
                "launch_ack_id": launch_ack_id,
                "started_at": started,
                "systemd_invocation_id": systemd_invocation_id,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="execution_started",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            target = self._execution(connection, execution_id)
            self._require_execution(
                target,
                execution_id=execution_id,
                generation=generation,
                systemd_unit=systemd_unit,
            )
            if str(target["state"]) == "running":
                if (
                    str(target["launch_ack_id"]) != launch_ack_id
                    or target["systemd_invocation_id"] != systemd_invocation_id
                    or float(target["started_at"]) != started
                ):
                    raise TestStoreConflict("execution has different launch evidence")
            else:
                deadline = started + int(target["ttl_seconds"])
                changed = connection.execute(
                    """
                    UPDATE test_run_targets
                    SET state = 'running', launch_ack_id = ?,
                        systemd_invocation_id = ?, started_at = ?,
                        deadline_at = ?, last_observed_at = ?, updated_at = ?
                    WHERE execution_id = ? AND generation = 1 AND state = 'starting'
                    """,
                    (
                        launch_ack_id,
                        systemd_invocation_id,
                        started,
                        deadline,
                        timestamp,
                        timestamp,
                        execution_id,
                    ),
                ).rowcount
                if changed != 1:
                    raise TestStoreConflict("execution changed during start acknowledgement")
            result = {
                "attempt_id": execution_id,
                "execution_id": execution_id,
                "state": "running",
                "started_at": started,
                "deadline_at": started + int(target["ttl_seconds"]),
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="execution_started",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def record_progress(
        self,
        execution_id: str,
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
        execution_id = _safe_id("execution_id", execution_id)
        numeric = (
            stdout_bytes,
            stderr_bytes,
            stdout_retained_bytes,
            stderr_retained_bytes,
        )
        if (
            any(type(value) is not int or not 0 <= value <= (1 << 63) - 1 for value in numeric)
            or stdout_retained_bytes > 4 * 1024 * 1024
            or stderr_retained_bytes > 4 * 1024 * 1024
            or type(stdout_truncated) is not bool
            or type(stderr_truncated) is not bool
            or stdout_retained_bytes > stdout_bytes
            or stderr_retained_bytes > stderr_bytes
            or stdout_truncated != (stdout_bytes > stdout_retained_bytes)
            or stderr_truncated != (stderr_bytes > stderr_retained_bytes)
        ):
            raise TestStoreContractError("execution output progress is invalid")
        if current_memory_bytes is not None and (
            type(current_memory_bytes) is not int
            or not 0 <= current_memory_bytes <= (1 << 63) - 1
        ):
            raise TestStoreContractError("execution current memory is invalid")
        observed = _finite_nonnegative("observed_at", observed_at)
        last_output = (
            None
            if last_output_at is None
            else _finite_nonnegative("last_output_at", last_output_at)
        )
        with self._transaction() as connection:
            target = self._execution(connection, execution_id)
            self._require_execution(
                target, execution_id=execution_id, generation=generation
            )
            if (
                stdout_bytes < int(target["stdout_bytes"])
                or stderr_bytes < int(target["stderr_bytes"])
                or stdout_retained_bytes < int(target["stdout_retained_bytes"])
                or stderr_retained_bytes < int(target["stderr_retained_bytes"])
                or (
                    target["progress_observed_at"] is not None
                    and observed < float(target["progress_observed_at"])
                )
            ):
                raise TestStoreConflict("execution output progress regressed")
            evidence_changed = (
                stdout_bytes != int(target["stdout_bytes"])
                or stderr_bytes != int(target["stderr_bytes"])
                or stdout_retained_bytes != int(target["stdout_retained_bytes"])
                or stderr_retained_bytes != int(target["stderr_retained_bytes"])
                or stdout_truncated != bool(target["stdout_truncated"])
                or stderr_truncated != bool(target["stderr_truncated"])
                or current_memory_bytes != target["current_memory_bytes"]
                or last_output != target["last_output_at"]
            )
            connection.execute(
                """
                UPDATE test_run_targets
                SET stdout_bytes = ?, stderr_bytes = ?,
                    stdout_retained_bytes = ?, stderr_retained_bytes = ?,
                    stdout_truncated = ?, stderr_truncated = ?,
                    current_memory_bytes = ?, last_output_at = ?,
                    progress_observed_at = ?, last_observed_at = ?, updated_at = ?
                WHERE execution_id = ? AND generation = 1
                  AND state IN ('starting', 'running', 'stopping')
                """,
                (
                    stdout_bytes,
                    stderr_bytes,
                    stdout_retained_bytes,
                    stderr_retained_bytes,
                    int(stdout_truncated),
                    int(stderr_truncated),
                    current_memory_bytes,
                    last_output,
                    observed,
                    observed,
                    _now(self._clock),
                    execution_id,
                ),
            )
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
                (target["run_id"],),
            ).fetchone()
            if evidence_changed:
                self._event(
                    connection,
                    event_type="test.execution.progress",
                    repository_id=str(run["repository_id"]),
                    run_id=str(target["run_id"]),
                    attempt_id=execution_id,
                    detail=detail,
                    created_at=_now(self._clock),
                )
            return detail

    @staticmethod
    def _package_document(package: ExecutionResultPackage) -> dict[str, object]:
        if not isinstance(package, ExecutionResultPackage):
            raise TestStoreContractError(
                "result package must be an ExecutionResultPackage"
            )
        package_id = _safe_id("package_id", package.package_id)
        if (
            len(package.cases) > MAX_CASE_RESULTS
            or len(package.failures) > MAX_FAILURE_RESULTS
            or len(package.artifacts) > MAX_ARTIFACT_RESULTS
            or type(package.reporter_complete) is not bool
        ):
            raise TestStoreContractError("result package exceeds its record bounds")
        cases: list[dict[str, object]] = []
        case_ids: set[str] = set()
        failed_case_ids: set[str] = set()
        for case in package.cases:
            if not isinstance(case, CaseResult):
                raise TestStoreContractError("result package case is invalid")
            case_id = _single_line("case_id", case.case_id, maximum=1024)
            if case_id in case_ids:
                raise TestStoreContractError("result package case_id is duplicated")
            case_ids.add(case_id)
            if case.status not in {"passed", "failed", "skipped", "error"}:
                raise TestStoreContractError("result package case status is invalid")
            if case.status in {"failed", "error"}:
                failed_case_ids.add(case_id)
            cases.append(
                {
                    "case_id": case_id,
                    "display_name": _bounded_text(
                        "display_name", case.display_name, maximum=4096
                    ),
                    "status": case.status,
                    "duration_seconds": _finite_nonnegative(
                        "case duration", case.duration_seconds
                    ),
                    "location": (
                        None
                        if case.location is None
                        else _bounded_text(
                            "case location", case.location, maximum=4096
                        )
                    ),
                }
            )
        failures: list[dict[str, object]] = []
        failure_ids: set[str] = set()
        covered_case_ids: list[str] = []
        for failure in package.failures:
            if not isinstance(failure, FailureRecord):
                raise TestStoreContractError("result package failure is invalid")
            failure_id = _safe_id("failure_id", failure.failure_id)
            if failure_id in failure_ids:
                raise TestStoreContractError("result package failure_id is duplicated")
            failure_ids.add(failure_id)
            if not isinstance(failure.classification, FailureClassification):
                raise TestStoreContractError("failure classification is invalid")
            case_id = (
                None
                if failure.case_id is None
                else _single_line(
                    "failure case_id", failure.case_id, maximum=1024
                )
            )
            if case_id is not None:
                if case_id not in failed_case_ids:
                    raise TestStoreContractError(
                        "failure does not bind a failed or errored case"
                    )
                covered_case_ids.append(case_id)
            failures.append(
                {
                    "failure_id": failure_id,
                    "classification": failure.classification.value,
                    "message": _bounded_text(
                        "failure message", failure.message, maximum=8192
                    ),
                    "case_id": case_id,
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
        if set(covered_case_ids) != failed_case_ids or len(covered_case_ids) != len(
            failed_case_ids
        ):
            raise TestStoreContractError(
                "every failed or errored case requires one exact failure record"
            )
        artifacts: list[dict[str, object]] = []
        artifact_ids: set[str] = set()
        for artifact in package.artifacts:
            if not isinstance(artifact, ArtifactMetadata):
                raise TestStoreContractError("result package artifact is invalid")
            artifact_id = _safe_id("artifact_id", artifact.artifact_id)
            if artifact_id in artifact_ids:
                raise TestStoreContractError("result package artifact_id is duplicated")
            artifact_ids.add(artifact_id)
            if (
                type(artifact.size_bytes) is not int
                or not 0 <= artifact.size_bytes <= (1 << 63) - 1
                or type(artifact.verified) is not bool
            ):
                raise TestStoreContractError("result package artifact is invalid")
            artifacts.append(
                {
                    "artifact_id": artifact_id,
                    "kind": _safe_id("artifact kind", artifact.kind),
                    "storage_handle": _single_line(
                        "artifact storage_handle",
                        artifact.storage_handle,
                        maximum=4096,
                    ),
                    "sha256": _sha256("artifact sha256", artifact.sha256),
                    "size_bytes": artifact.size_bytes,
                    "verified": artifact.verified,
                }
            )
        return {
            "package_id": package_id,
            "cases": cases,
            "failures": failures,
            "artifacts": artifacts,
            "reporter_complete": package.reporter_complete,
        }

    def complete_from_package(
        self,
        execution_id: str,
        *,
        generation: int,
        systemd_unit: str,
        package: ExecutionResultPackage,
        conclusion: AttemptConclusion,
        duration_seconds: float,
        operation_id: str,
        unit_inactive: bool,
        cgroup_empty: bool,
        peak_memory_bytes: int | None = None,
        cpu_seconds: float | None = None,
    ) -> dict[str, object]:
        """Atomically publish one complete package after exact cgroup cleanup."""

        execution_id = _safe_id("execution_id", execution_id)
        systemd_unit = _single_line("systemd_unit", systemd_unit, maximum=256)
        document = self._package_document(package)
        encoded = _canonical_json(document).encode("utf-8")
        if len(encoded) > MAX_RESULT_PACKAGE_BYTES:
            raise TestStoreContractError("result package exceeds its byte bound")
        if unit_inactive is not True or cgroup_empty is not True:
            raise TestStoreConflict(
                "execution cannot terminalize before its exact cgroup is empty"
            )
        if not isinstance(conclusion, AttemptConclusion):
            try:
                conclusion = AttemptConclusion(conclusion)
            except ValueError as error:
                raise TestStoreContractError("unsupported execution conclusion") from error
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
        counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
        for case in document["cases"]:
            counts[str(case["status"])] += 1
        reporter_complete = bool(document["reporter_complete"])
        complete_test_failure = reporter_complete and (
            counts["failed"]
            or counts["error"]
            or any(
                failure["classification"]
                == FailureClassification.TEST_FAILURE.value
                for failure in document["failures"]
            )
        )
        if complete_test_failure and conclusion is not AttemptConclusion.TEST_FAILED:
            raise TestStoreConflict(
                "a complete measured test failure must win a competing conclusion"
            )
        if conclusion is AttemptConclusion.SUCCEEDED and (
            not reporter_complete or counts["failed"] or counts["error"]
        ):
            conclusion = AttemptConclusion.INCOMPLETE
        if conclusion is AttemptConclusion.TEST_FAILED and not (
            counts["failed"]
            or counts["error"]
            or any(
                failure["classification"]
                == FailureClassification.TEST_FAILURE.value
                for failure in document["failures"]
            )
        ):
            raise TestStoreContractError(
                "test-failed conclusion has no test-failure evidence"
            )
        classification = _CONCLUSION_CLASSIFICATION[conclusion]
        operation_id = _operation_id(operation_id)
        package_fingerprint = hashlib.sha256(encoded).hexdigest()
        request_fingerprint = deterministic_fingerprint(
            {
                "execution_id": execution_id,
                "generation": generation,
                "systemd_unit": systemd_unit,
                "package_fingerprint": package_fingerprint,
                "conclusion": conclusion.value,
                "duration_seconds": duration,
                "peak_memory_bytes": peak_memory_bytes,
                "cpu_seconds": cpu_seconds,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="execution_complete",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            target = self._execution(connection, execution_id)
            self._require_execution(
                target,
                execution_id=execution_id,
                generation=generation,
                systemd_unit=systemd_unit,
            )
            for ordinal, case in enumerate(document["cases"]):
                connection.execute(
                    """
                    INSERT INTO test_case_results(
                        target_id, execution_id, ordinal, case_id,
                        display_name, status, duration_seconds, location
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        target["target_id"],
                        execution_id,
                        ordinal,
                        case["case_id"],
                        case["display_name"],
                        case["status"],
                        case["duration_seconds"],
                        case["location"],
                    ),
                )
            for ordinal, failure in enumerate(document["failures"]):
                connection.execute(
                    """
                    INSERT INTO test_failures(
                        failure_id, target_id, execution_id, ordinal,
                        classification, case_id, message, location,
                        artifact_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        failure["failure_id"],
                        target["target_id"],
                        execution_id,
                        ordinal,
                        failure["classification"],
                        failure["case_id"],
                        failure["message"],
                        failure["location"],
                        failure["artifact_id"],
                        timestamp,
                    ),
                )
            for ordinal, artifact in enumerate(document["artifacts"]):
                connection.execute(
                    """
                    INSERT INTO test_artifacts(
                        artifact_id, target_id, execution_id, ordinal, kind,
                        storage_handle, sha256, size_bytes, verified, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact["artifact_id"],
                        target["target_id"],
                        execution_id,
                        ordinal,
                        artifact["kind"],
                        artifact["storage_handle"],
                        artifact["sha256"],
                        artifact["size_bytes"],
                        int(artifact["verified"]),
                        timestamp,
                    ),
                )
            changed = connection.execute(
                """
                UPDATE test_run_targets
                SET state = ?, terminal_operation_id = ?,
                    terminal_fingerprint = ?, result_package_fingerprint = ?,
                    conclusion = ?, failure_classification = ?,
                    duration_seconds = ?, peak_memory_bytes = ?, cpu_seconds = ?,
                    passed_count = ?, failed_count = ?, skipped_count = ?,
                    error_count = ?, reporter_complete = ?, finished_at = ?,
                    updated_at = ?
                WHERE execution_id = ? AND generation = 1
                  AND state IN ('starting', 'running', 'stopping')
                """,
                (
                    conclusion.value,
                    operation_id,
                    request_fingerprint,
                    package_fingerprint,
                    conclusion.value,
                    None if classification is None else classification.value,
                    duration,
                    peak_memory_bytes,
                    cpu_seconds,
                    counts["passed"],
                    counts["failed"],
                    counts["skipped"],
                    counts["error"],
                    int(reporter_complete),
                    timestamp,
                    timestamp,
                    execution_id,
                ),
            ).rowcount
            if changed != 1:
                raise TestStoreConflict("execution changed during terminalization")
            run = connection.execute(
                """
                SELECT run.repository_id, target.target_name
                FROM test_runs AS run
                JOIN test_run_targets AS target ON target.run_id = run.run_id
                WHERE target.target_id = ?
                """,
                (target["target_id"],),
            ).fetchone()
            if peak_memory_bytes is not None:
                recent = connection.execute(
                    """
                    SELECT measured.peak_memory_bytes
                    FROM test_run_targets AS measured
                    JOIN test_runs AS measured_run
                      ON measured_run.run_id = measured.run_id
                    WHERE measured_run.repository_id = ?
                      AND measured.target_name = ?
                      AND measured.peak_memory_bytes IS NOT NULL
                    ORDER BY measured.finished_at DESC, measured.target_id DESC
                    LIMIT 20
                    """,
                    (run["repository_id"], run["target_name"]),
                ).fetchall()
                connection.execute(
                    """
                    INSERT INTO test_target_resource_profiles(
                        repository_id, target_name, sample_count,
                        recent_peak_memory_bytes, last_peak_memory_bytes,
                        last_cpu_seconds, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_id, target_name) DO UPDATE SET
                        sample_count = excluded.sample_count,
                        recent_peak_memory_bytes = excluded.recent_peak_memory_bytes,
                        last_peak_memory_bytes = excluded.last_peak_memory_bytes,
                        last_cpu_seconds = excluded.last_cpu_seconds,
                        updated_at = excluded.updated_at
                    """,
                    (
                        run["repository_id"],
                        run["target_name"],
                        len(recent),
                        max(int(row[0]) for row in recent),
                        peak_memory_bytes,
                        cpu_seconds,
                        timestamp,
                    ),
                )
            self._reconcile_run(connection, str(target["run_id"]), timestamp)
            issued = self._issue_plan_evidence_attestations(
                connection,
                run_id=str(target["run_id"]),
                issued_at=timestamp,
            )
            self._refresh_rollups(
                connection,
                repository_id=str(run["repository_id"]),
                finished_at=timestamp,
            )
            result = {
                "attempt_id": execution_id,
                "execution_id": execution_id,
                "run_id": str(target["run_id"]),
                "state": conclusion.value,
                "classification": (
                    None if classification is None else classification.value
                ),
                "evidence_attestation_ids": list(issued),
                "usage": {
                    "available": peak_memory_bytes is not None or cpu_seconds is not None,
                    "peak_memory_bytes": peak_memory_bytes,
                    "cpu_seconds": cpu_seconds,
                },
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="execution_complete",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.execution_terminal",
                repository_id=str(run["repository_id"]),
                run_id=str(target["run_id"]),
                attempt_id=execution_id,
                detail={
                    "conclusion": conclusion.value,
                    "classification": result["classification"],
                    "package_fingerprint": package_fingerprint,
                },
                created_at=timestamp,
            )
            return result

    def restart_cleanup(self, *, limit: int = 10_000) -> tuple[dict[str, object], ...]:
        """Return every exact nonterminal native binding before admission resumes."""

        limit = _positive_int("limit", limit, maximum=10_000)
        connection = self._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT target.*, run.repository_id, run.owner_uid
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                WHERE target.state IN ('starting', 'running', 'stopping')
                ORDER BY target.created_at, target.target_id
                LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise TestStoreConflict(
                    "restart cleanup inventory exceeds its bounded page"
                )
            result: list[dict[str, object]] = []
            store_generation = self._generation(connection)
            for row in rows:
                if str(row["store_generation"]) != store_generation:
                    raise TestStoreConflict(
                        "active execution belongs to another Test Store generation"
                    )
                result.append(
                    {
                        "attempt_id": str(row["execution_id"]),
                        "execution_id": str(row["execution_id"]),
                        "generation": int(row["generation"]),
                        "target_id": str(row["target_id"]),
                        "run_id": str(row["run_id"]),
                        "repository_id": str(row["repository_id"]),
                        "repository_generation": int(row["repository_generation"]),
                        "owner_uid": int(row["owner_uid"]),
                        "systemd_unit": str(row["systemd_unit"]),
                        "systemd_invocation_id": (
                            None
                            if row["systemd_invocation_id"] is None
                            else str(row["systemd_invocation_id"])
                        ),
                        "launch_operation_id": str(row["launch_operation_id"]),
                        "descriptor_fingerprint": str(row["descriptor_fingerprint"]),
                        "launch_deadline_at": float(row["launch_deadline_at"]),
                        "started_at": (
                            None if row["started_at"] is None else float(row["started_at"])
                        ),
                        "deadline_at": (
                            None if row["deadline_at"] is None else float(row["deadline_at"])
                        ),
                        "state": str(row["state"]),
                    }
                )
            return tuple(result)
        finally:
            connection.close()

    def request_cancel(
        self,
        run_id: str,
        *,
        actor: str,
        reason: str,
        operation_id: str,
    ) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        actor = _single_line("actor", actor, maximum=256)
        reason = _single_line("reason", reason, maximum=1024)
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {"run_id": run_id, "actor": actor, "reason": reason}
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="cancel",
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
                    "active_execution_ids": [],
                    "already_terminal": True,
                }
            else:
                connection.execute(
                    """
                    UPDATE test_run_targets
                    SET state = 'cancelled', conclusion = 'cancelled',
                        failure_classification = ?, finished_at = ?, updated_at = ?
                    WHERE run_id = ? AND state = 'queued'
                    """,
                    (
                        FailureClassification.CANCELLATION.value,
                        timestamp,
                        timestamp,
                        run_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE test_run_targets
                    SET state = 'stopping', stop_reason = ?, updated_at = ?
                    WHERE run_id = ? AND state IN ('starting', 'running')
                    """,
                    (reason, timestamp, run_id),
                )
                active = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT execution_id FROM test_run_targets
                        WHERE run_id = ? AND state = 'stopping'
                        ORDER BY target_id
                        """,
                        (run_id,),
                    )
                ]
                connection.execute(
                    """
                    UPDATE test_runs
                    SET state = 'cancelling', cancel_reason = ?, updated_at = ?
                    WHERE run_id = ?
                    """,
                    (reason, timestamp, run_id),
                )
                self._reconcile_run(connection, run_id, timestamp)
                current = connection.execute(
                    "SELECT state FROM test_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                result = {
                    "run_id": run_id,
                    "state": str(current["state"]),
                    "active_attempt_ids": active,
                    "active_execution_ids": active,
                    "already_terminal": False,
                }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="cancel",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def retry_run(
        self,
        run_id: str,
        *,
        actor: str,
        failed_only: bool,
        operation_id: str,
    ) -> SubmissionResult:
        """Create a new immutable run; an existing target is never executed twice."""

        run_id = _safe_id("run_id", run_id)
        actor = _single_line("actor", actor, maximum=256)
        if type(failed_only) is not bool:
            raise TestStoreContractError("failed_only must be boolean")
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {"run_id": run_id, "actor": actor, "failed_only": failed_only}
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="retry",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return SubmissionResult(**replay)
            source_run = connection.execute(
                "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if source_run is None:
                raise TestStoreNotFound("test run does not exist")
            if str(source_run["state"]) in _ACTIVE_RUN_STATES:
                raise TestStoreConflict("an active run cannot be retried")
            source_plan = connection.execute(
                "SELECT * FROM test_plans WHERE plan_id = ?",
                (source_run["plan_id"],),
            ).fetchone()
            if source_plan is None or str(source_plan["source_mode"]) != "immutable":
                raise TestStoreConflict("retry requires retained immutable provenance")
            source_targets = connection.execute(
                """
                SELECT * FROM test_run_targets
                WHERE run_id = ? ORDER BY wave_index, target_name, shard_index
                """,
                (run_id,),
            ).fetchall()
            selected = [
                row
                for row in source_targets
                if not failed_only or str(row["state"]) != "succeeded"
            ]
            if not selected:
                raise TestStoreConflict("the run has no failed targets to retry")
            (
                retry_plan_id,
                retry_plan_fingerprint,
                retry_execution_fingerprint,
                retry_plan_json,
            ) = _retry_plan_projection(
                source_plan["plan_json"],
                selected_targets=[str(row["target_name"]) for row in selected],
            )
            retry_plan_document, _retry_resources = _stored_plan_parts(
                retry_plan_json
            )
            retry_wave_by_target = {
                str(target): wave_index
                for wave_index, wave in enumerate(
                    retry_plan_document["dependency_waves"]
                )
                for target in wave
            }
            active = connection.execute(
                f"""
                SELECT run_id, state FROM test_runs
                WHERE execution_fingerprint = ?
                  AND state IN ({','.join('?' for _ in _ACTIVE_RUN_STATES)})
                ORDER BY created_at, run_id LIMIT 1
                """,
                (retry_execution_fingerprint, *_ACTIVE_RUN_STATES),
            ).fetchone()
            if active is not None:
                result = SubmissionResult(
                    run_id=str(active["run_id"]),
                    state=str(active["state"]),
                    deduplicated=True,
                    deduplicated_run_id=str(active["run_id"]),
                    console_path=f"/#/tests/runs/{active['run_id']}",
                )
                self._record_mutation(
                    connection,
                    operation_id=operation_id,
                    operation_kind="retry",
                    request_fingerprint=request_fingerprint,
                    result=result.__dict__,
                    created_at=timestamp,
                )
                return result
            existing_retry_plan = connection.execute(
                "SELECT fingerprint, plan_json FROM test_plans WHERE plan_id = ?",
                (retry_plan_id,),
            ).fetchone()
            if existing_retry_plan is None:
                connection.execute(
                    """
                    INSERT INTO test_plans(
                        plan_id, fingerprint, execution_fingerprint,
                        manifest_fingerprint, repository_id, intent, snapshot_id,
                        source_mode, source_fingerprint, reusable, plan_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'immutable', ?, ?, ?, ?)
                    """,
                    (
                        retry_plan_id,
                        retry_plan_fingerprint,
                        retry_execution_fingerprint,
                        source_plan["manifest_fingerprint"],
                        source_plan["repository_id"],
                        source_plan["intent"],
                        source_plan["snapshot_id"],
                        source_plan["source_fingerprint"],
                        source_plan["reusable"],
                        retry_plan_json,
                        timestamp,
                    ),
                )
            retry_id = "run-" + hashlib.sha256(
                f"retry\0{operation_id}\0{request_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
            connection.execute(
                """
                INSERT INTO test_runs(
                    run_id, plan_id, repository_id, owner_uid, actor, intent,
                    source_mode, source_fingerprint, execution_fingerprint,
                    eligible_target_count, selected_target_count,
                    state, priority, queued_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'immutable', ?, ?, ?, ?, 'queued', ?, ?, ?, ?)
                """,
                (
                    retry_id,
                    retry_plan_id,
                    source_run["repository_id"],
                    source_run["owner_uid"],
                    actor,
                    source_run["intent"],
                    source_run["source_fingerprint"],
                    retry_execution_fingerprint,
                    source_run["eligible_target_count"],
                    len({str(row["target_name"]) for row in selected}),
                    source_run["priority"],
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            dependencies = retry_plan_document["dependencies"]
            for row in selected:
                target_name = str(row["target_name"])
                target_id = "target-" + hashlib.sha256(
                    f"{retry_id}\0{target_name}\0{row['shard_index']}".encode("utf-8")
                ).hexdigest()[:32]
                connection.execute(
                    """
                    INSERT INTO test_run_targets(
                        target_id, run_id, target_name, wave_index,
                        exact_dependencies_json, shard_index, shard_count,
                        state, estimated_seconds, worktree_key,
                        exclusive_resources_json, ttl_seconds,
                        queued_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        target_id,
                        retry_id,
                        target_name,
                        retry_wave_by_target[target_name],
                        _canonical_json(list(dependencies[target_name])),
                        row["shard_index"],
                        row["shard_count"],
                        row["estimated_seconds"],
                        row["worktree_key"],
                        row["exclusive_resources_json"],
                        row["ttl_seconds"],
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
            result = SubmissionResult(
                run_id=retry_id,
                state="queued",
                deduplicated=False,
                deduplicated_run_id=None,
                console_path=f"/#/tests/runs/{retry_id}",
            )
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="retry",
                request_fingerprint=request_fingerprint,
                result=result.__dict__,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.run_retried",
                repository_id=str(source_run["repository_id"]),
                run_id=retry_id,
                attempt_id=None,
                detail={
                    "source_run_id": run_id,
                    "failed_only": failed_only,
                    "target_count": len(selected),
                },
                created_at=timestamp,
            )
            return result

    @staticmethod
    def _plan_evidence_policies(plan_json: str) -> dict[str, EvidencePolicy]:
        try:
            document = json.loads(plan_json)
            raw = document["evidence_policies"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreContractError(
                "retained plan evidence policies are invalid"
            ) from error
        if not isinstance(raw, dict) or len(raw) > 64:
            raise TestStoreContractError("retained plan evidence policies are invalid")
        policies: dict[str, EvidencePolicy] = {}
        expected = {
            "intent",
            "required_targets",
            "max_age_seconds",
            "allow_reuse",
            "fingerprint",
        }
        for name, value in sorted(raw.items()):
            if (
                not isinstance(name, str)
                or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", name) is None
                or not isinstance(value, dict)
                or set(value) != expected
                or not isinstance(value["required_targets"], list)
            ):
                raise TestStoreContractError(
                    "retained plan evidence policy is invalid"
                )
            required_targets = tuple(value["required_targets"])
            if (
                not required_targets
                or any(not isinstance(item, str) for item in required_targets)
                or tuple(sorted(set(required_targets))) != required_targets
                or not isinstance(value["intent"], str)
                or type(value["max_age_seconds"]) is not int
                or not 1 <= value["max_age_seconds"] <= 31_536_000
                or type(value["allow_reuse"]) is not bool
            ):
                raise TestStoreContractError(
                    "retained plan evidence policy is invalid"
                )
            policy = EvidencePolicy(
                name=name,
                intent=value["intent"],
                required_targets=required_targets,
                max_age_seconds=value["max_age_seconds"],
                allow_reuse=value["allow_reuse"],
            )
            if value["fingerprint"] != evidence_policy_fingerprint(policy):
                raise TestStoreContractError(
                    "retained plan evidence policy fingerprint is invalid"
                )
            policies[name] = policy
        return policies

    def _issue_plan_evidence_attestations(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        issued_at: float,
    ) -> tuple[str, ...]:
        run = connection.execute(
            """
            SELECT run.*, plan.snapshot_id, plan.plan_json
            FROM test_runs AS run
            JOIN test_plans AS plan ON plan.plan_id = run.plan_id
            WHERE run.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if (
            run is None
            or str(run["source_mode"]) != SourceMode.IMMUTABLE.value
            or str(run["state"]) != "succeeded"
            or run["finished_at"] is None
        ):
            return ()
        executed = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT DISTINCT target_name FROM test_run_targets
                WHERE run_id = ? AND state = 'succeeded'
                """,
                (run_id,),
            )
        }
        issued: list[str] = []
        for policy in self._plan_evidence_policies(str(run["plan_json"])).values():
            if not set(policy.required_targets) <= executed:
                continue
            policy_fingerprint = evidence_policy_fingerprint(policy)
            attestation_id = "attestation-" + hashlib.sha256(
                f"{run_id}\0{policy.name}\0{policy_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
            connection.execute(
                """
                INSERT INTO test_evidence_attestations(
                    attestation_id, repository_id, policy_name, snapshot_id,
                    run_id, policy_fingerprint, conclusion, issued_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'satisfied', ?, ?)
                ON CONFLICT(attestation_id) DO NOTHING
                """,
                (
                    attestation_id,
                    run["repository_id"],
                    policy.name,
                    run["snapshot_id"],
                    run_id,
                    policy_fingerprint,
                    issued_at,
                    float(run["finished_at"]) + policy.max_age_seconds,
                ),
            )
            retained = connection.execute(
                "SELECT run_id FROM test_evidence_attestations WHERE attestation_id = ?",
                (attestation_id,),
            ).fetchone()
            if retained is None or str(retained["run_id"]) != run_id:
                raise TestStoreConflict(
                    "automatic evidence attestation identity is contradictory"
                )
            issued.append(attestation_id)
        return tuple(issued)

    def issue_evidence_attestation(
        self,
        run_id: str,
        *,
        policy_name: str,
        policy_fingerprint: str,
        required_targets: Sequence[str],
        max_age_seconds: int,
        operation_id: str,
    ) -> dict[str, object]:
        """Bind an explicit named policy to one successful immutable run."""

        run_id = _safe_id("run_id", run_id)
        policy_name = _safe_id("policy_name", policy_name)
        policy_fingerprint = _sha256("policy_fingerprint", policy_fingerprint)
        targets = tuple(sorted({_safe_id("required_target", item) for item in required_targets}))
        if not targets:
            raise TestStoreContractError("required_targets must not be empty")
        max_age_seconds = _positive_int(
            "max_age_seconds", max_age_seconds, maximum=31_536_000
        )
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "run_id": run_id,
                "policy_name": policy_name,
                "policy_fingerprint": policy_fingerprint,
                "required_targets": list(targets),
                "max_age_seconds": max_age_seconds,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="evidence_attestation",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            run = connection.execute(
                """
                SELECT run.*, plan.snapshot_id, plan.plan_json FROM test_runs AS run
                JOIN test_plans AS plan ON plan.plan_id = run.plan_id
                WHERE run.run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                raise TestStoreNotFound("test run does not exist")
            if (
                str(run["source_mode"]) != SourceMode.IMMUTABLE.value
                or str(run["state"]) != "succeeded"
                or run["finished_at"] is None
            ):
                raise TestStoreConflict(
                    "evidence requires a successful immutable terminal run"
                )
            policy = self._plan_evidence_policies(str(run["plan_json"])).get(
                policy_name
            )
            if (
                policy is None
                or evidence_policy_fingerprint(policy) != policy_fingerprint
                or policy.required_targets != targets
                or policy.max_age_seconds != max_age_seconds
            ):
                raise TestStoreConflict(
                    "evidence policy does not match the retained exact plan"
                )
            expires_at = float(run["finished_at"]) + max_age_seconds
            if expires_at < timestamp:
                raise TestStoreConflict("test evidence is already stale")
            executed = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT DISTINCT target_name FROM test_run_targets
                    WHERE run_id = ? AND state = 'succeeded'
                    """,
                    (run_id,),
                ).fetchall()
            }
            missing = sorted(set(targets) - executed)
            if missing:
                raise TestStoreConflict(
                    "run does not satisfy required target(s): " + ", ".join(missing)
                )
            attestation_id = "attestation-" + hashlib.sha256(
                f"{run_id}\0{policy_name}\0{policy_fingerprint}".encode("utf-8")
            ).hexdigest()[:32]
            try:
                connection.execute(
                    """
                    INSERT INTO test_evidence_attestations(
                        attestation_id, repository_id, policy_name, snapshot_id,
                        run_id, policy_fingerprint, conclusion, issued_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'satisfied', ?, ?)
                    """,
                    (
                        attestation_id,
                        run["repository_id"],
                        policy_name,
                        run["snapshot_id"],
                        run_id,
                        policy_fingerprint,
                        timestamp,
                        expires_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                existing = connection.execute(
                    "SELECT * FROM test_evidence_attestations WHERE attestation_id = ?",
                    (attestation_id,),
                ).fetchone()
                if existing is None or str(existing["run_id"]) != run_id:
                    raise TestStoreConflict(
                        "run already has contradictory evidence identity"
                    ) from error
                expires_at = float(existing["expires_at"])
            result = {
                "satisfied": True,
                "attestation_id": attestation_id,
                "repository_id": str(run["repository_id"]),
                "snapshot_id": str(run["snapshot_id"]),
                "run_id": run_id,
                "policy_name": policy_name,
                "expires_at": expires_at,
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="evidence_attestation",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            return result

    def _retained_attestation_policy(
        self, row: Mapping[str, object]
    ) -> EvidencePolicy:
        policy_name = str(row["policy_name"])
        policy = self._plan_evidence_policies(str(row["plan_json"])).get(
            policy_name
        )
        if (
            policy is None
            or evidence_policy_fingerprint(policy)
            != str(row["policy_fingerprint"])
        ):
            raise TestStoreConflict(
                "retained evidence policy contradicts its exact plan"
            )
        return policy

    def check_evidence_policy(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
        now: float | None = None,
    ) -> dict[str, object]:
        repository_id = _safe_id("repository_id", repository_id)
        snapshot_id = _safe_id("snapshot_id", snapshot_id)
        policy_name = _safe_id("policy_name", policy_name)
        timestamp = _now(self._clock) if now is None else _finite_nonnegative("now", now)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                """
                SELECT attestation.*, plan.plan_json,
                       consumption.consumption_id
                FROM test_evidence_attestations AS attestation
                JOIN test_runs AS run ON run.run_id = attestation.run_id
                JOIN test_plans AS plan ON plan.plan_id = run.plan_id
                LEFT JOIN test_evidence_consumptions AS consumption
                  ON consumption.attestation_id = attestation.attestation_id
                WHERE attestation.repository_id = ?
                  AND attestation.snapshot_id = ?
                  AND attestation.policy_name = ?
                  AND attestation.conclusion = 'satisfied'
                ORDER BY (attestation.expires_at >= ?) DESC,
                         attestation.issued_at DESC,
                         attestation.attestation_id DESC
                LIMIT 1
                """,
                (
                    repository_id,
                    snapshot_id,
                    policy_name,
                    timestamp,
                ),
            ).fetchone()
            if row is None:
                return {
                    "satisfied": False,
                    "reusable": None,
                    "requires_consumption": False,
                    "consumable": False,
                    "repository_id": repository_id,
                    "snapshot_id": snapshot_id,
                    "policy_name": policy_name,
                }
            policy = self._retained_attestation_policy(row)
            unexpired = float(row["expires_at"]) >= timestamp
            if not policy.allow_reuse:
                consumable = connection.execute(
                    """
                    SELECT 1
                    FROM test_evidence_attestations AS attestation
                    LEFT JOIN test_evidence_consumptions AS consumption
                      ON consumption.attestation_id = attestation.attestation_id
                    WHERE attestation.repository_id = ?
                      AND attestation.snapshot_id = ?
                      AND attestation.policy_name = ?
                      AND attestation.policy_fingerprint = ?
                      AND attestation.conclusion = 'satisfied'
                      AND attestation.expires_at >= ?
                      AND consumption.attestation_id IS NULL
                    LIMIT 1
                    """,
                    (
                        repository_id,
                        snapshot_id,
                        policy_name,
                        evidence_policy_fingerprint(policy),
                        timestamp,
                    ),
                ).fetchone()
                return {
                    "satisfied": False,
                    "reusable": False,
                    "requires_consumption": True,
                    "consumable": consumable is not None,
                    "repository_id": repository_id,
                    "snapshot_id": snapshot_id,
                    "policy_name": policy_name,
                    "policy_fingerprint": str(row["policy_fingerprint"]),
                    "expires_at": float(row["expires_at"]),
                }
            if not unexpired:
                return {
                    "satisfied": False,
                    "reusable": True,
                    "requires_consumption": False,
                    "consumable": False,
                    "repository_id": repository_id,
                    "snapshot_id": snapshot_id,
                    "policy_name": policy_name,
                    "policy_fingerprint": str(row["policy_fingerprint"]),
                    "expires_at": float(row["expires_at"]),
                }
            return {
                "satisfied": True,
                "reusable": True,
                "requires_consumption": False,
                "consumable": False,
                "attestation_id": str(row["attestation_id"]),
                "repository_id": repository_id,
                "snapshot_id": snapshot_id,
                "run_id": str(row["run_id"]),
                "policy_name": policy_name,
                "policy_fingerprint": str(row["policy_fingerprint"]),
                "expires_at": float(row["expires_at"]),
            }
        finally:
            connection.close()

    def consume_evidence_policy(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
        operation_id: str,
    ) -> dict[str, object]:
        """Consume one exact non-reusable attestation idempotently."""

        repository_id = _safe_id("repository_id", repository_id)
        snapshot_id = _safe_id("snapshot_id", snapshot_id)
        policy_name = _safe_id("policy_name", policy_name)
        operation_id = _operation_id(operation_id)
        request_fingerprint = deterministic_fingerprint(
            {
                "repository_id": repository_id,
                "snapshot_id": snapshot_id,
                "policy_name": policy_name,
            }
        )
        timestamp = _now(self._clock)
        with self._transaction() as connection:
            replay = self._mutation_replay(
                connection,
                operation_id=operation_id,
                operation_kind="evidence_consume",
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay
            row = connection.execute(
                """
                SELECT attestation.*, plan.plan_json
                FROM test_evidence_attestations AS attestation
                JOIN test_runs AS run ON run.run_id = attestation.run_id
                JOIN test_plans AS plan ON plan.plan_id = run.plan_id
                LEFT JOIN test_evidence_consumptions AS consumption
                  ON consumption.attestation_id = attestation.attestation_id
                WHERE attestation.repository_id = ?
                  AND attestation.snapshot_id = ?
                  AND attestation.policy_name = ?
                  AND attestation.conclusion = 'satisfied'
                  AND attestation.expires_at >= ?
                  AND consumption.attestation_id IS NULL
                ORDER BY attestation.issued_at DESC,
                         attestation.attestation_id DESC
                LIMIT 1
                """,
                (repository_id, snapshot_id, policy_name, timestamp),
            ).fetchone()
            if row is None:
                raise TestStoreConflict(
                    "no unconsumed exact-snapshot evidence is available"
                )
            policy = self._retained_attestation_policy(row)
            if policy.allow_reuse:
                raise TestStoreConflict(
                    "reusable evidence must be checked rather than consumed"
                )
            attestation_id = str(row["attestation_id"])
            consumption_id = "evidence-use-" + hashlib.sha256(
                f"{attestation_id}\0{operation_id}".encode("utf-8")
            ).hexdigest()[:32]
            try:
                connection.execute(
                    """
                    INSERT INTO test_evidence_consumptions(
                        consumption_id, attestation_id, operation_id, consumed_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (consumption_id, attestation_id, operation_id, timestamp),
                )
            except sqlite3.IntegrityError as error:
                raise TestStoreConflict(
                    "evidence attestation was consumed concurrently"
                ) from error
            result = {
                "satisfied": True,
                "consumed": True,
                "reusable": False,
                "requires_consumption": True,
                "consumption_id": consumption_id,
                "attestation_id": attestation_id,
                "repository_id": repository_id,
                "snapshot_id": snapshot_id,
                "run_id": str(row["run_id"]),
                "policy_name": policy_name,
                "policy_fingerprint": str(row["policy_fingerprint"]),
                "operation_id": operation_id,
                "consumed_at": timestamp,
                "expires_at": float(row["expires_at"]),
            }
            self._record_mutation(
                connection,
                operation_id=operation_id,
                operation_kind="evidence_consume",
                request_fingerprint=request_fingerprint,
                result=result,
                created_at=timestamp,
            )
            self._event(
                connection,
                event_type="test.evidence_consumed",
                repository_id=repository_id,
                run_id=str(row["run_id"]),
                attempt_id=None,
                detail={
                    "schema_version": 1,
                    "consumption_id": consumption_id,
                    "attestation_id": attestation_id,
                    "policy_name": policy_name,
                    "snapshot_id": snapshot_id,
                },
                created_at=timestamp,
            )
            return result

    def reconcile_nonterminal_runs(
        self, *, now: float | None = None
    ) -> dict[str, object]:
        """Reconcile retained target evidence without a recovery state machine."""

        timestamp = (
            _now(self._clock)
            if now is None
            else _finite_nonnegative("now", now)
        )
        processed: list[str] = []
        changed: list[dict[str, str]] = []
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT run_id, state FROM test_runs
                WHERE state IN ({','.join('?' for _ in _ACTIVE_RUN_STATES)})
                ORDER BY updated_at, run_id
                LIMIT ?
                """,
                (*_ACTIVE_RUN_STATES, MAX_NONTERMINAL_RUNS_PER_RECONCILE + 1),
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
            "SELECT * FROM test_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise TestStoreNotFound("test run does not exist")
        targets = connection.execute(
            """
            SELECT * FROM test_run_targets
            WHERE run_id = ? ORDER BY wave_index, target_name, shard_index
            """,
            (run_id,),
        ).fetchall()
        active_states = {"queued", *_ACTIVE_TARGET_STATES}
        run_state = str(run["state"])
        if run_state == "cancelling":
            if any(str(row["state"]) in _ACTIVE_TARGET_STATES for row in targets):
                return
            connection.execute(
                """
                UPDATE test_runs SET state = 'cancelled', conclusion = 'cancelled',
                    failure_classification = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    FailureClassification.CANCELLATION.value,
                    timestamp,
                    timestamp,
                    run_id,
                ),
            )
            return
        failed = [
            row
            for row in targets
            if str(row["state"]) in _TERMINAL_TARGET_STATES
            and str(row["state"]) != "succeeded"
        ]
        if failed:
            unavailable_names = {str(row["target_name"]) for row in failed}
            dependencies = {
                str(row["target_name"]): tuple(
                    json.loads(str(row["exact_dependencies_json"]))
                )
                for row in targets
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
            for row in targets:
                if (
                    str(row["state"]) == "queued"
                    and str(row["target_name"]) in cancelled_dependents
                ):
                    connection.execute(
                        """
                        UPDATE test_run_targets
                        SET state = 'cancelled', conclusion = 'cancelled',
                            failure_classification = ?, finished_at = ?, updated_at = ?
                        WHERE target_id = ? AND state = 'queued'
                        """,
                        (
                            FailureClassification.CANCELLATION.value,
                            timestamp,
                            timestamp,
                            str(row["target_id"]),
                        ),
                    )
            targets = connection.execute(
                "SELECT * FROM test_run_targets WHERE run_id = ?",
                (run_id,),
            ).fetchall()
            if any(str(row["state"]) in active_states for row in targets):
                return
            states = {
                str(row["state"])
                for row in targets
                if str(row["state"]) != "succeeded"
            }
            run_terminal, classification = self._dominant_failure(states)
            connection.execute(
                """
                UPDATE test_runs SET state = ?, conclusion = ?,
                    failure_classification = ?, finished_at = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    run_terminal,
                    run_terminal,
                    classification,
                    timestamp,
                    timestamp,
                    run_id,
                ),
            )
            return
        if targets and all(str(row["state"]) == "succeeded" for row in targets):
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
            (
                "infrastructure_failed",
                "failed",
                FailureClassification.INFRASTRUCTURE_FAILURE,
            ),
            ("timed_out", "timed_out", FailureClassification.TIMEOUT),
            ("incomplete", "incomplete", FailureClassification.INCOMPLETE_REPORTING),
            ("test_failed", "failed", FailureClassification.TEST_FAILURE),
            ("cancelled", "cancelled", FailureClassification.CANCELLATION),
        )
        for state, run_state, classification in precedence:
            if state in states:
                return run_state, classification.value
        raise AssertionError("terminal failure state was not classified")

    def _refresh_rollups(
        self,
        connection: sqlite3.Connection,
        *,
        repository_id: str,
        finished_at: float,
    ) -> None:
        """Refresh compatible bounded statistics from one execution per target."""

        for table, seconds in (
            ("test_rollup_hourly", 3_600),
            ("test_rollup_daily", 86_400),
        ):
            bucket = _bucket_start(finished_at, seconds)
            end = bucket + seconds
            executions = connection.execute(
                """
                SELECT
                  COUNT(*) AS attempt_count,
                  COALESCE(SUM(passed_count + failed_count + skipped_count + error_count), 0) AS case_count,
                  COALESCE(SUM(passed_count), 0) AS passed_count,
                  COALESCE(SUM(failed_count), 0) AS failed_count,
                  COALESCE(SUM(skipped_count), 0) AS skipped_count,
                  COALESCE(SUM(error_count), 0) AS error_count,
                  COALESCE(SUM(CASE WHEN EXISTS (
                    SELECT 1 FROM test_case_results AS observed_case
                    WHERE observed_case.target_id = target.target_id
                  ) THEN (
                    SELECT COALESCE(SUM(result.duration_seconds), 0.0)
                    FROM test_case_results AS result
                    WHERE result.target_id = target.target_id
                  ) ELSE target.duration_seconds END), 0.0) AS aggregate_test_seconds,
                  COALESCE(SUM(target.duration_seconds), 0.0) AS attempt_wall_seconds,
                  COALESCE(SUM(CASE
                    WHEN target.started_at IS NOT NULL
                    THEN MAX(0.0, target.started_at - target.queued_at)
                    ELSE 0.0 END), 0.0) AS attempt_queue_seconds,
                  0 AS retry_attempt_count,
                  COALESCE(SUM(CASE
                    WHEN target.duration_seconds > target.estimated_seconds * 1.25
                    THEN 1 ELSE 0 END), 0) AS slow_count,
                  COALESCE(MAX(target.duration_seconds), 0.0) AS max_attempt_seconds,
                  COALESCE(SUM(CASE
                    WHEN target.state = 'succeeded' AND EXISTS (
                      SELECT 1
                      FROM test_run_targets AS prior_target
                      JOIN test_runs AS prior_run
                        ON prior_run.run_id = prior_target.run_id
                      WHERE prior_run.repository_id = run.repository_id
                        AND prior_run.source_fingerprint = run.source_fingerprint
                        AND prior_target.target_name = target.target_name
                        AND prior_target.state = 'test_failed'
                        AND prior_target.finished_at < target.finished_at
                    ) THEN 1 ELSE 0 END), 0) AS flake_count,
                  COALESCE(SUM(CASE
                    WHEN target.state = 'succeeded'
                     AND (
                       SELECT COUNT(*)
                       FROM test_run_targets AS prior_target
                       JOIN test_runs AS prior_run
                         ON prior_run.run_id = prior_target.run_id
                       WHERE prior_run.repository_id = run.repository_id
                         AND prior_target.target_name = target.target_name
                         AND prior_target.state = 'succeeded'
                         AND prior_target.finished_at < target.finished_at
                     ) >= 3
                     AND target.duration_seconds > 1.25 * (
                       SELECT AVG(prior_target.duration_seconds)
                       FROM test_run_targets AS prior_target
                       JOIN test_runs AS prior_run
                         ON prior_run.run_id = prior_target.run_id
                       WHERE prior_run.repository_id = run.repository_id
                         AND prior_target.target_name = target.target_name
                         AND prior_target.state = 'succeeded'
                         AND prior_target.finished_at < target.finished_at
                     )
                    THEN 1 ELSE 0 END), 0) AS regression_count,
                  COALESCE(SUM(CASE WHEN target.state = 'succeeded' THEN 1 ELSE 0 END), 0) AS success_count,
                  COALESCE(SUM(CASE WHEN target.state = 'test_failed' THEN 1 ELSE 0 END), 0) AS failure_count,
                  COALESCE(SUM(CASE WHEN target.state IN (
                    'infrastructure_failed', 'timed_out', 'incomplete'
                  ) THEN 1 ELSE 0 END), 0) AS infrastructure_count
                FROM test_run_targets AS target
                JOIN test_runs AS run ON run.run_id = target.run_id
                WHERE run.repository_id = ?
                  AND target.execution_id IS NOT NULL
                  AND target.finished_at >= ? AND target.finished_at < ?
                """,
                (repository_id, bucket, end),
            ).fetchone()
            runs = connection.execute(
                """
                SELECT
                  COUNT(*) AS run_count,
                  COALESCE(SUM(selected_target_count), 0) AS selected_target_count,
                  COALESCE(SUM(eligible_target_count), 0) AS eligible_target_count,
                  COALESCE(SUM(eligible_target_count - selected_target_count), 0) AS avoided_target_count,
                  COALESCE(SUM(CASE WHEN started_at IS NOT NULL
                    THEN MAX(0.0, started_at - queued_at) ELSE 0.0 END), 0.0) AS queue_seconds,
                  COALESCE(SUM(CASE WHEN started_at IS NOT NULL
                    THEN MAX(0.0, finished_at - started_at) ELSE 0.0 END), 0.0) AS wall_seconds
                FROM test_runs
                WHERE repository_id = ?
                  AND finished_at >= ? AND finished_at < ?
                """,
                (repository_id, bucket, end),
            ).fetchone()
            connection.execute(
                f"""
                INSERT INTO {table}(
                    repository_id, bucket_start, run_count, attempt_count,
                    selected_target_count, eligible_target_count,
                    avoided_target_count, case_count,
                    passed_count, failed_count, skipped_count, error_count,
                    queue_seconds, attempt_queue_seconds,
                    aggregate_test_seconds, attempt_wall_seconds, wall_seconds,
                    retry_attempt_count, flake_count, slow_count,
                    regression_count, max_attempt_seconds, success_count,
                    failure_count, infrastructure_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, bucket_start) DO UPDATE SET
                    run_count = excluded.run_count,
                    attempt_count = excluded.attempt_count,
                    selected_target_count = excluded.selected_target_count,
                    eligible_target_count = excluded.eligible_target_count,
                    avoided_target_count = excluded.avoided_target_count,
                    case_count = excluded.case_count,
                    passed_count = excluded.passed_count,
                    failed_count = excluded.failed_count,
                    skipped_count = excluded.skipped_count,
                    error_count = excluded.error_count,
                    queue_seconds = excluded.queue_seconds,
                    attempt_queue_seconds = excluded.attempt_queue_seconds,
                    aggregate_test_seconds = excluded.aggregate_test_seconds,
                    attempt_wall_seconds = excluded.attempt_wall_seconds,
                    wall_seconds = excluded.wall_seconds,
                    retry_attempt_count = excluded.retry_attempt_count,
                    flake_count = excluded.flake_count,
                    slow_count = excluded.slow_count,
                    regression_count = excluded.regression_count,
                    max_attempt_seconds = excluded.max_attempt_seconds,
                    success_count = excluded.success_count,
                    failure_count = excluded.failure_count,
                    infrastructure_count = excluded.infrastructure_count
                """,
                (
                    repository_id,
                    bucket,
                    int(runs["run_count"]),
                    int(executions["attempt_count"]),
                    int(runs["selected_target_count"]),
                    int(runs["eligible_target_count"]),
                    int(runs["avoided_target_count"]),
                    int(executions["case_count"]),
                    int(executions["passed_count"]),
                    int(executions["failed_count"]),
                    int(executions["skipped_count"]),
                    int(executions["error_count"]),
                    float(runs["queue_seconds"]),
                    float(executions["attempt_queue_seconds"]),
                    float(executions["aggregate_test_seconds"]),
                    float(executions["attempt_wall_seconds"]),
                    float(runs["wall_seconds"]),
                    int(executions["retry_attempt_count"]),
                    int(executions["flake_count"]),
                    int(executions["slow_count"]),
                    int(executions["regression_count"]),
                    float(executions["max_attempt_seconds"]),
                    int(executions["success_count"]),
                    int(executions["failure_count"]),
                    int(executions["infrastructure_count"]),
                ),
            )

    def begin_rollup_rebuild(self) -> dict[str, object]:
        connection = self._connect(readonly=True)
        try:
            connection.execute("BEGIN")
            generation = self._generation(connection)
            execution_upper = int(
                connection.execute(
                    "SELECT COALESCE(MAX(rowid), 0) FROM test_run_targets"
                ).fetchone()[0]
            )
            run_upper = int(
                connection.execute(
                    "SELECT COALESCE(MAX(rowid), 0) FROM test_runs"
                ).fetchone()[0]
            )
            connection.execute("COMMIT")
        finally:
            connection.close()
        return {
            "schema_version": 1,
            "store_generation": generation,
            # Retain the published cursor field name for bounded stats callers.
            "attempt_rowid_upper": execution_upper,
            "run_rowid_upper": run_upper,
            "after_repository_id": "",
            "after_bucket_start": -1,
        }

    @staticmethod
    def _rollup_rebuild_cursor(
        value: Mapping[str, object],
    ) -> dict[str, object]:
        expected = {
            "schema_version",
            "store_generation",
            "attempt_rowid_upper",
            "run_rowid_upper",
            "after_repository_id",
            "after_bucket_start",
        }
        if set(value) != expected or value.get("schema_version") != 1:
            raise TestStoreContractError("rollup rebuild cursor is invalid")
        generation = value.get("store_generation")
        repository_id = value.get("after_repository_id")
        if not isinstance(generation, str) or not generation:
            raise TestStoreContractError("rollup rebuild generation is invalid")
        if not isinstance(repository_id, str):
            raise TestStoreContractError("rollup rebuild repository cursor is invalid")
        if repository_id:
            _safe_id("after_repository_id", repository_id)
        integers: dict[str, int] = {}
        for field in (
            "attempt_rowid_upper",
            "run_rowid_upper",
            "after_bucket_start",
        ):
            raw = value.get(field)
            if type(raw) is not int:
                raise TestStoreContractError(f"{field} must be an integer")
            integers[field] = int(raw)
        if integers["attempt_rowid_upper"] < 0 or integers["run_rowid_upper"] < 0:
            raise TestStoreContractError("rollup rebuild rowid bound is invalid")
        if integers["after_bucket_start"] < -1:
            raise TestStoreContractError("rollup rebuild bucket cursor is invalid")
        return {
            "schema_version": 1,
            "store_generation": generation,
            "attempt_rowid_upper": integers["attempt_rowid_upper"],
            "run_rowid_upper": integers["run_rowid_upper"],
            "after_repository_id": repository_id,
            "after_bucket_start": integers["after_bucket_start"],
        }

    def rebuild_rollup_batch(
        self,
        cursor: Mapping[str, object],
        *,
        batch_size: int = 64,
    ) -> dict[str, object]:
        state = self._rollup_rebuild_cursor(cursor)
        batch_size = _positive_int(
            "batch_size", batch_size, maximum=MAX_ROLLUP_REBUILD_BATCH
        )
        with self._transaction() as connection:
            if not hmac.compare_digest(
                str(state["store_generation"]), self._generation(connection)
            ):
                raise TestStoreConflict("rollup rebuild store generation changed")
            rows = connection.execute(
                """
                WITH source_buckets(repository_id, bucket_start) AS (
                    SELECT run.repository_id,
                           CAST(target.finished_at / 3600 AS INTEGER) * 3600
                    FROM test_run_targets AS target
                    JOIN test_runs AS run ON run.run_id = target.run_id
                    WHERE target.rowid <= ? AND target.finished_at IS NOT NULL
                    UNION
                    SELECT repository_id,
                           CAST(finished_at / 3600 AS INTEGER) * 3600
                    FROM test_runs
                    WHERE rowid <= ? AND finished_at IS NOT NULL
                )
                SELECT repository_id, bucket_start
                FROM source_buckets
                WHERE repository_id > ?
                   OR (repository_id = ? AND bucket_start > ?)
                ORDER BY repository_id, bucket_start
                LIMIT ?
                """,
                (
                    state["attempt_rowid_upper"],
                    state["run_rowid_upper"],
                    state["after_repository_id"],
                    state["after_repository_id"],
                    state["after_bucket_start"],
                    batch_size + 1,
                ),
            ).fetchall()
            selected = rows[:batch_size]
            for row in selected:
                self._refresh_rollups(
                    connection,
                    repository_id=str(row["repository_id"]),
                    finished_at=float(row["bucket_start"]),
                )
            next_cursor = dict(state)
            if selected:
                next_cursor["after_repository_id"] = str(
                    selected[-1]["repository_id"]
                )
                next_cursor["after_bucket_start"] = int(
                    selected[-1]["bucket_start"]
                )
            return {
                "cursor": next_cursor,
                "processed": len(selected),
                "complete": len(rows) <= batch_size,
            }

    def rebuild_rollups(self, *, batch_size: int = 64) -> dict[str, int]:
        cursor = self.begin_rollup_rebuild()
        while True:
            result = self.rebuild_rollup_batch(cursor, batch_size=batch_size)
            cursor = result["cursor"]  # type: ignore[assignment]
            if bool(result["complete"]):
                break
        connection = self._connect(readonly=True)
        try:
            return {
                "hourly": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM test_rollup_hourly"
                    ).fetchone()[0]
                ),
                "daily": int(
                    connection.execute(
                        "SELECT COUNT(*) FROM test_rollup_daily"
                    ).fetchone()[0]
                ),
            }
        finally:
            connection.close()

    def rollups(
        self,
        *,
        repository_id: str,
        grain: str,
        since: float = 0,
        limit: int = 1_000,
    ) -> tuple[dict[str, object], ...]:
        repository_id = _safe_id("repository_id", repository_id)
        if grain not in {"hourly", "daily"}:
            raise TestStoreContractError("grain must be hourly or daily")
        since = _finite_nonnegative("since", since)
        limit = _positive_int("limit", limit, maximum=10_000)
        table = "test_rollup_hourly" if grain == "hourly" else "test_rollup_daily"
        connection = self._connect(readonly=True)
        try:
            return tuple(
                dict(row)
                for row in connection.execute(
                    f"""
                    SELECT * FROM {table}
                    WHERE repository_id = ? AND bucket_start >= ?
                    ORDER BY bucket_start LIMIT ?
                    """,
                    (repository_id, since, limit),
                ).fetchall()
            )
        finally:
            connection.close()

    def current_time(self) -> float:
        """Return the store's validated clock for deterministic projections."""

        return _now(self._clock)

    def rollup_totals(
        self,
        *,
        repository_id: str,
        grain: str,
        since: float,
        before: float,
    ) -> dict[str, int | float | None]:
        """Aggregate one materialized-rollup range without result-table scans."""

        repository_id = _safe_id("repository_id", repository_id)
        if grain not in {"hourly", "daily"}:
            raise TestStoreContractError("grain must be hourly or daily")
        since = _finite_nonnegative("since", since)
        before = _finite_nonnegative("before", before)
        if before <= since:
            raise TestStoreContractError("rollup range must be positive")
        table = "test_rollup_hourly" if grain == "hourly" else "test_rollup_daily"
        additive = (
            "run_count", "attempt_count", "selected_target_count",
            "eligible_target_count", "avoided_target_count", "case_count",
            "passed_count", "failed_count", "skipped_count", "error_count",
            "queue_seconds", "attempt_queue_seconds",
            "aggregate_test_seconds", "attempt_wall_seconds", "wall_seconds",
            "retry_attempt_count", "flake_count", "slow_count",
            "regression_count", "success_count", "failure_count",
            "infrastructure_count",
        )
        columns = ", ".join(f"COALESCE(SUM({field}), 0) AS {field}" for field in additive)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                f"""
                SELECT {columns},
                       COALESCE(MAX(max_attempt_seconds), 0.0) AS max_attempt_seconds,
                       MAX(bucket_start) AS latest_bucket
                FROM {table}
                WHERE repository_id = ? AND bucket_start >= ? AND bucket_start < ?
                """,
                (repository_id, since, before),
            ).fetchone()
            if row is None:
                raise AssertionError("aggregate rollup query returned no row")
            return dict(row)
        finally:
            connection.close()

    def retain_repository_setup_projection(
        self,
        projection: Mapping[str, object],
        *,
        observed_at: float | None = None,
    ) -> dict[str, object]:
        """Retain one already-sanitized snapshotd setup projection.

        The service boundary performs the structural revalidation.  The store
        persists only bounded JSON plus exact repository/status identity, so
        catalog reads never need to enter another UID's worktree.
        """

        if not isinstance(projection, Mapping):
            raise TestStoreContractError("repository setup projection must be a mapping")
        repository_id = _safe_id("repository_id", projection.get("repository_id"))
        status = projection.get("status")
        if status not in {"ready", "missing", "invalid"}:
            raise TestStoreContractError("repository setup projection status is invalid")
        manifest_fingerprint = projection.get("manifest_fingerprint")
        if status == "ready":
            manifest_fingerprint = _sha256(
                "manifest_fingerprint", manifest_fingerprint
            )
        elif manifest_fingerprint is not None:
            raise TestStoreContractError(
                "unready repository setup projection has a manifest fingerprint"
            )
        try:
            encoded = json.dumps(
                dict(projection),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as error:
            raise TestStoreContractError(
                "repository setup projection must be bounded JSON"
            ) from error
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise TestStoreContractError("repository setup projection is too large")
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        timestamp = _now(self._clock) if observed_at is None else _finite_nonnegative(
            "observed_at", observed_at
        )
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO test_repository_setup_projections(
                        repository_id, status, manifest_fingerprint,
                        projection_fingerprint, projection_json,
                        observed_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_id) DO UPDATE SET
                        status = excluded.status,
                        manifest_fingerprint = excluded.manifest_fingerprint,
                        projection_fingerprint = excluded.projection_fingerprint,
                        projection_json = excluded.projection_json,
                        observed_at = excluded.observed_at,
                        updated_at = excluded.updated_at
                    WHERE excluded.observed_at >= test_repository_setup_projections.observed_at
                    """,
                    (
                        repository_id,
                        status,
                        manifest_fingerprint,
                        fingerprint,
                        encoded,
                        timestamp,
                        timestamp,
                    ),
                )
        finally:
            connection.close()
        return {
            "repository_id": repository_id,
            "setup_status": status,
            "manifest_fingerprint": manifest_fingerprint,
            "projection_fingerprint": fingerprint,
            "setup_observed_at": timestamp,
            "retained": True,
        }

    def repository_setup_catalog(
        self, repository_ids: Sequence[str]
    ) -> tuple[dict[str, object], ...]:
        """Read retained setup state for an exact bounded repository set.

        A repository with no completed setup observation is conservatively
        reported as missing setup and explicitly marked ``retained=False``.
        This is not a worktree read and cannot leak paths or manifest content.
        """

        if (
            isinstance(repository_ids, (str, bytes))
            or not isinstance(repository_ids, Sequence)
            or len(repository_ids) > 500
        ):
            raise TestStoreContractError("repository setup catalog scope is invalid")
        normalized = tuple(
            _safe_id(f"repository_ids[{index}]", value)
            for index, value in enumerate(repository_ids)
        )
        if len(set(normalized)) != len(normalized):
            raise TestStoreContractError("repository setup catalog IDs must be unique")
        connection = self._connect(readonly=True)
        try:
            rows: dict[str, sqlite3.Row] = {}
            if normalized:
                placeholders = ",".join("?" for _ in normalized)
                rows = {
                    str(row["repository_id"]): row
                    for row in connection.execute(
                        f"""
                        SELECT repository_id, status, manifest_fingerprint,
                               projection_fingerprint, observed_at
                        FROM test_repository_setup_projections
                        WHERE repository_id IN ({placeholders})
                        """,
                        normalized,
                    ).fetchall()
                }
            result: list[dict[str, object]] = []
            for repository_id in normalized:
                row = rows.get(repository_id)
                result.append(
                    {
                        "repository_id": repository_id,
                        "setup_status": (
                            "missing" if row is None else str(row["status"])
                        ),
                        "manifest_fingerprint": (
                            None if row is None else row["manifest_fingerprint"]
                        ),
                        "projection_fingerprint": (
                            None if row is None else str(row["projection_fingerprint"])
                        ),
                        "setup_observed_at": (
                            None if row is None else float(row["observed_at"])
                        ),
                        "retained": row is not None,
                    }
                )
            return tuple(result)
        finally:
            connection.close()

    def fleet_rollup_projection(
        self,
        *,
        grain: str,
        since: float,
        repository_limit: int = 50,
        bucket_limit: int = 48,
        repository_ids: Sequence[str] | None = None,
    ) -> dict[str, object]:
        """Return a compact fleet matrix using only materialized rollups."""

        if grain not in {"hourly", "daily"}:
            raise TestStoreContractError("grain must be hourly or daily")
        since = _finite_nonnegative("since", since)
        repository_limit = _positive_int(
            "repository_limit", repository_limit, maximum=50
        )
        bucket_limit = _positive_int("bucket_limit", bucket_limit, maximum=168)
        scoped_ids: tuple[str, ...] | None = None
        if repository_ids is not None:
            if (
                isinstance(repository_ids, (str, bytes))
                or not isinstance(repository_ids, Sequence)
                or len(repository_ids) > 50
            ):
                raise TestStoreContractError("fleet repository scope is invalid")
            scoped_ids = tuple(
                _safe_id(f"repository_ids[{index}]", value)
                for index, value in enumerate(repository_ids)
            )
            if len(set(scoped_ids)) != len(scoped_ids):
                raise TestStoreContractError("fleet repository IDs must be unique")
        seconds = 3_600 if grain == "hourly" else 86_400
        observed_at = _now(self._clock)
        latest = _bucket_start(observed_at, seconds)
        requested_first = min(latest, _bucket_start(since, seconds))
        actual_bucket_count = min(
            bucket_limit, int((latest - requested_first) // seconds) + 1
        )
        first = latest - (actual_bucket_count - 1) * seconds
        buckets = tuple(
            first + index * seconds for index in range(actual_bucket_count)
        )
        table = "test_rollup_hourly" if grain == "hourly" else "test_rollup_daily"
        connection = self._connect(readonly=True)
        try:
            scope_clause = ""
            scope_arguments: tuple[object, ...] = ()
            if scoped_ids is not None:
                if scoped_ids:
                    placeholders = ",".join("?" for _ in scoped_ids)
                    scope_clause = f" AND repository_id IN ({placeholders})"
                    scope_arguments = tuple(scoped_ids)
                else:
                    scope_clause = " AND 0 = 1"
            summaries = connection.execute(
                f"""
                SELECT repository_id,
                       SUM(run_count) AS run_count,
                       SUM(attempt_count) AS attempt_count,
                       SUM(selected_target_count) AS selected_target_count,
                       SUM(eligible_target_count) AS eligible_target_count,
                       SUM(avoided_target_count) AS avoided_target_count,
                       SUM(case_count) AS case_count,
                       SUM(passed_count) AS passed_count,
                       SUM(failed_count) AS failed_count,
                       SUM(error_count) AS error_count,
                       SUM(queue_seconds) AS queue_seconds,
                       SUM(attempt_queue_seconds) AS attempt_queue_seconds,
                       SUM(aggregate_test_seconds) AS aggregate_test_seconds,
                       SUM(attempt_wall_seconds) AS attempt_wall_seconds,
                       SUM(wall_seconds) AS wall_seconds,
                       SUM(retry_attempt_count) AS retry_attempt_count,
                       SUM(flake_count) AS flake_count,
                       SUM(slow_count) AS slow_count,
                       SUM(regression_count) AS regression_count,
                       MAX(max_attempt_seconds) AS max_attempt_seconds,
                       SUM(success_count) AS success_count,
                       SUM(failure_count) AS failure_count,
                       SUM(infrastructure_count) AS infrastructure_count,
                       MAX(bucket_start) AS latest_bucket
                FROM {table}
                WHERE bucket_start >= ? AND bucket_start <= ?
                      {scope_clause}
                GROUP BY repository_id
                ORDER BY infrastructure_count DESC, failure_count DESC,
                         aggregate_test_seconds DESC, repository_id
                LIMIT ?
                """,
                (first, latest, *scope_arguments, repository_limit),
            ).fetchall()
            repository_ids = [str(row["repository_id"]) for row in summaries]
            active_by_repository: dict[str, dict[str, int]] = {}
            terminal_by_repository: dict[str, dict[str, object]] = {}
            if repository_ids:
                placeholders = ",".join("?" for _ in repository_ids)
                for row in connection.execute(
                    f"""
                    SELECT repository_id, state, COUNT(*) AS count
                    FROM test_runs
                    WHERE repository_id IN ({placeholders})
                      AND state IN ('queued', 'running', 'cancelling')
                    GROUP BY repository_id, state
                    """,
                    repository_ids,
                ).fetchall():
                    active_by_repository.setdefault(
                        str(row["repository_id"]), {}
                    )[str(row["state"])] = int(row["count"])
                terminal_rows = connection.execute(
                    f"""
                    WITH terminal_run_facts AS (
                        SELECT run.repository_id,
                               run.run_id,
                               run.state,
                               run.finished_at,
                               MAX(CASE
                                   WHEN run.failure_classification =
                                            'infrastructure_failure'
                                     OR run.state IN ('timed_out', 'incomplete')
                                     OR target.state IN (
                                            'infrastructure_failed', 'timed_out',
                                            'incomplete'
                                        )
                                   THEN 1 ELSE 0
                               END) AS has_infrastructure_failure,
                               MAX(CASE WHEN target.peak_memory_bytes IS NOT NULL
                                            OR target.cpu_seconds IS NOT NULL
                                   THEN 1 ELSE 0 END) AS has_measurement
                        FROM test_runs AS run
                        LEFT JOIN test_run_targets AS target
                               ON target.run_id = run.run_id
                        WHERE run.repository_id IN ({placeholders})
                          AND run.finished_at IS NOT NULL
                          AND run.finished_at >= ?
                          AND run.finished_at <= ?
                          AND run.state IN (
                              'succeeded', 'failed', 'timed_out', 'cancelled',
                              'incomplete'
                          )
                        GROUP BY run.repository_id, run.run_id,
                                 run.state, run.finished_at
                    )
                    SELECT repository_id,
                           MAX(CASE WHEN has_infrastructure_failure = 1
                               THEN finished_at END) AS latest_infrastructure_run_at,
                           MAX(CASE WHEN state = 'succeeded'
                                         AND has_measurement = 1
                                         AND has_infrastructure_failure = 0
                               THEN finished_at END) AS latest_clean_measured_run_at
                    FROM terminal_run_facts
                    GROUP BY repository_id
                    """,
                    (*repository_ids, first, observed_at),
                ).fetchall()
                terminal_by_repository = {
                    str(row["repository_id"]): dict(row) for row in terminal_rows
                }
                cells = connection.execute(
                    f"""
                    SELECT repository_id, bucket_start, aggregate_test_seconds,
                           attempt_count, case_count, failed_count, error_count,
                           failure_count, infrastructure_count,
                           wall_seconds, queue_seconds, avoided_target_count,
                           flake_count, slow_count, regression_count
                    FROM {table}
                    WHERE repository_id IN ({placeholders})
                      AND bucket_start >= ? AND bucket_start <= ?
                    ORDER BY repository_id, bucket_start
                    """,
                    (*repository_ids, first, latest),
                ).fetchall()
            else:
                cells = []
            return {
                "grain": grain,
                "bucket_seconds": seconds,
                "bucket_starts": list(buckets),
                "repositories": [
                    {
                        **dict(row),
                        "efficiency": self._rollup_efficiency(dict(row)),
                        "active": active_by_repository.get(
                            str(row["repository_id"]), {}
                        ),
                        **terminal_by_repository.get(
                            str(row["repository_id"]), {}
                        ),
                    }
                    for row in summaries
                ],
                "cell_fields": [
                    "repository_id", "bucket_start", "aggregate_test_seconds",
                    "attempt_count", "case_count", "failed_count", "error_count",
                    "failure_count", "infrastructure_count",
                    "wall_seconds", "queue_seconds", "avoided_target_count",
                    "flake_count", "slow_count", "regression_count",
                ],
                "cells": [
                    [
                        str(row["repository_id"]),
                        float(row["bucket_start"]),
                        float(row["aggregate_test_seconds"]),
                        int(row["attempt_count"]),
                        int(row["case_count"]),
                        int(row["failed_count"]),
                        int(row["error_count"]),
                        int(row["failure_count"]),
                        int(row["infrastructure_count"]),
                        float(row["wall_seconds"]),
                        float(row["queue_seconds"]),
                        int(row["avoided_target_count"]),
                        int(row["flake_count"]),
                        int(row["slow_count"]),
                        int(row["regression_count"]),
                    ]
                    for row in cells
                ],
            }
        finally:
            connection.close()

    def repository_rollup_detail(
        self,
        *,
        repository_id: str,
        grain: str,
        since: float,
        limit: int = 500,
    ) -> dict[str, object]:
        """Return one repository trend without touching case/result tables."""

        rows = self.rollups(
            repository_id=repository_id,
            grain=grain,
            since=since,
            limit=limit,
        )
        numeric = (
            "run_count",
            "attempt_count",
            "selected_target_count",
            "eligible_target_count",
            "avoided_target_count",
            "case_count",
            "passed_count",
            "failed_count",
            "skipped_count",
            "error_count",
            "queue_seconds",
            "attempt_queue_seconds",
            "aggregate_test_seconds",
            "attempt_wall_seconds",
            "wall_seconds",
            "retry_attempt_count",
            "flake_count",
            "slow_count",
            "regression_count",
            "success_count",
            "failure_count",
            "infrastructure_count",
        )
        totals: dict[str, int | float] = {
            field: (0.0 if field.endswith("seconds") else 0) for field in numeric
        }
        for row in rows:
            for field in numeric:
                totals[field] += row[field]  # type: ignore[operator]
        totals["max_attempt_seconds"] = max(
            (float(row["max_attempt_seconds"]) for row in rows), default=0.0
        )
        return {
            "repository_id": repository_id,
            "grain": grain,
            "totals": totals,
            "efficiency": self._rollup_efficiency(totals),
            "series": list(rows),
        }

    @staticmethod
    def _rollup_efficiency(values: Mapping[str, object]) -> dict[str, float | None]:
        def ratio(numerator: str, denominator: str) -> float | None:
            bottom = float(values.get(denominator, 0) or 0)
            return None if bottom <= 0 else float(values.get(numerator, 0) or 0) / bottom

        terminal_attempts = (
            float(values.get("success_count", 0) or 0)
            + float(values.get("failure_count", 0) or 0)
            + float(values.get("infrastructure_count", 0) or 0)
        )
        attempts = float(values.get("attempt_count", 0) or 0)
        runs = float(values.get("run_count", 0) or 0)
        eligible = float(values.get("eligible_target_count", 0) or 0)
        return {
            "parallelism_ratio": ratio("aggregate_test_seconds", "wall_seconds"),
            "average_run_queue_seconds": (
                None if runs <= 0 else float(values.get("queue_seconds", 0) or 0) / runs
            ),
            "selection_savings_ratio": (
                None
                if eligible <= 0
                else float(values.get("avoided_target_count", 0) or 0) / eligible
            ),
            "flake_rate": (
                None
                if terminal_attempts <= 0
                else float(values.get("flake_count", 0) or 0) / terminal_attempts
            ),
            "failure_rate": (
                None
                if terminal_attempts <= 0
                else float(values.get("failure_count", 0) or 0)
                / terminal_attempts
            ),
            "infrastructure_rate": (
                None
                if terminal_attempts <= 0
                else float(values.get("infrastructure_count", 0) or 0)
                / terminal_attempts
            ),
            "slow_rate": (
                None if attempts <= 0 else float(values.get("slow_count", 0) or 0) / attempts
            ),
            "regression_rate": (
                None
                if attempts <= 0
                else float(values.get("regression_count", 0) or 0) / attempts
            ),
        }

    def get_run(
        self, run_id: str, *, repository_id: str | None = None
    ) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        if repository_id is not None:
            repository_id = _safe_id("repository_id", repository_id)
        connection = self._connect(readonly=True)
        try:
            parameters: tuple[object, ...]
            if repository_id is None:
                query = "SELECT * FROM test_runs WHERE run_id = ?"
                parameters = (run_id,)
            else:
                query = (
                    "SELECT * FROM test_runs "
                    "WHERE run_id = ? AND repository_id = ?"
                )
                parameters = (run_id, repository_id)
            row = connection.execute(query, parameters).fetchone()
            if row is None:
                raise TestStoreNotFound("test run does not exist")
            result = dict(row)
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
                target["exact_dependencies"] = tuple(
                    json.loads(str(target.pop("exact_dependencies_json")))
                )
                execution_id = target.get("execution_id")
                progress = None
                if execution_id is not None:
                    progress = {
                        "stdout_bytes": int(target["stdout_bytes"]),
                        "stderr_bytes": int(target["stderr_bytes"]),
                        "stdout_retained_bytes": int(
                            target["stdout_retained_bytes"]
                        ),
                        "stderr_retained_bytes": int(
                            target["stderr_retained_bytes"]
                        ),
                        "stdout_truncated": bool(target["stdout_truncated"]),
                        "stderr_truncated": bool(target["stderr_truncated"]),
                        "current_memory_bytes": target["current_memory_bytes"],
                        "last_output_at": target["last_output_at"],
                        "observed_at": target["progress_observed_at"],
                    }
                target["current_attempt_id"] = execution_id
                target["active_attempt"] = (
                    None
                    if execution_id is None
                    or str(target["state"]) not in _ACTIVE_TARGET_STATES
                    else {
                        "attempt_id": str(execution_id),
                        "execution_id": str(execution_id),
                        "state": str(target["state"]),
                        "started_at": target["started_at"],
                        "heartbeat_at": target["last_observed_at"],
                        "lease_expires_at": None,
                        "deadline_at": target["deadline_at"],
                        "output_progress": progress,
                    }
                )
                measured = (
                    target["peak_memory_bytes"] is not None
                    or target["cpu_seconds"] is not None
                )
                target["usage"] = {
                    "available": measured,
                    "peak_memory_mib": (
                        None
                        if target["peak_memory_bytes"] is None
                        else int(target["peak_memory_bytes"]) / (1024 * 1024)
                    ),
                    "cpu_seconds": (
                        None
                        if target["cpu_seconds"] is None
                        else float(target["cpu_seconds"])
                    ),
                    "measured_attempts": int(measured),
                    "total_attempts": 1 if execution_id is not None else 0,
                }
                targets.append(target)
            result["targets"] = targets
            peaks = [
                float(target["usage"]["peak_memory_mib"])  # type: ignore[index]
                for target in targets
                if target["usage"]["peak_memory_mib"] is not None  # type: ignore[index]
            ]
            cpu = [
                float(target["usage"]["cpu_seconds"])  # type: ignore[index]
                for target in targets
                if target["usage"]["cpu_seconds"] is not None  # type: ignore[index]
            ]
            measured = sum(
                int(target["usage"]["measured_attempts"])  # type: ignore[index]
                for target in targets
            )
            total = sum(
                int(target["usage"]["total_attempts"])  # type: ignore[index]
                for target in targets
            )
            result["usage"] = {
                "available": measured > 0,
                "peak_memory_mib": None if not peaks else max(peaks),
                "cpu_seconds": None if not cpu else sum(cpu),
                "measured_attempts": measured,
                "total_attempts": total,
            }
            result["lease_expiry_evidence"] = {
                "visible_count": 0,
                "truncated": False,
                "events": [],
            }
            return result
        finally:
            connection.close()

    def runs(
        self,
        *,
        repository_id: str,
        after: str | None = None,
        limit: int = 50,
        state: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        repository_id = _safe_id("repository_id", repository_id)
        after_value = None if after is None else _safe_id("after", after)
        limit = _positive_int("limit", limit, maximum=200)
        if state is not None:
            state = _safe_id("state", state)
            if state not in _RUN_STATES:
                raise TestStoreContractError("test run state is invalid")
        connection = self._connect(readonly=True)
        try:
            cursor = None
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
            clauses = ["run.repository_id = ?"]
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
                       COUNT(target.target_id) AS target_count,
                       COUNT(CASE WHEN target.state IN (
                         'succeeded', 'test_failed', 'infrastructure_failed',
                         'timed_out', 'cancelled', 'incomplete'
                       ) THEN 1 END) AS completed_target_count,
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
                       MAX(target.peak_memory_bytes) AS peak_memory_bytes,
                       SUM(target.cpu_seconds) AS cpu_seconds,
                       COUNT(target.execution_id) AS total_attempts,
                       COUNT(CASE WHEN target.peak_memory_bytes IS NOT NULL
                                      OR target.cpu_seconds IS NOT NULL
                                  THEN 1 END) AS measured_attempts
                FROM test_runs AS run
                LEFT JOIN test_run_targets AS target ON target.run_id = run.run_id
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
        if set(raw_resources) != set(selected):
            raise TestStoreContractError(
                "stored test plan target resources are incomplete"
            )
        decoded: dict[str, TargetResources] = {}
        for name, value in raw_resources.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, Mapping)
                or set(value) != expected
            ):
                raise TestStoreContractError(
                    "stored test plan target resources are invalid"
                )
            exclusive_value = value["exclusive_resources"]
            if not isinstance(exclusive_value, list):
                raise TestStoreContractError("stored exclusive resources are invalid")
            exclusive = tuple(
                _safe_id("exclusive_resource", item) for item in exclusive_value
            )
            if tuple(sorted(set(exclusive))) != exclusive:
                raise TestStoreContractError("stored exclusive resources are invalid")
            worktree = value["worktree_key"]
            if worktree is not None:
                worktree = _single_line("worktree_key", worktree, maximum=4096)
            ttl_seconds = value["ttl_seconds"]
            if ttl_seconds is not None:
                ttl_seconds = _positive_int(
                    "ttl_seconds", ttl_seconds, maximum=31_536_000
                )
            decoded[name] = TargetResources(
                estimated_seconds=_finite_nonnegative(
                    "estimated_seconds", value["estimated_seconds"]
                ),
                shard_count=_positive_int(
                    "shard_count", value["shard_count"], maximum=256
                ),
                worktree_key=worktree,
                exclusive_resources=exclusive,
                ttl_seconds=ttl_seconds,
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
                  COUNT(execution_id) AS attempt_count,
                  COALESCE(SUM(passed_count), 0) AS passed_count,
                  COALESCE(SUM(failed_count), 0) AS failed_count,
                  COALESCE(SUM(skipped_count), 0) AS skipped_count,
                  COALESCE(SUM(error_count), 0) AS error_count,
                  COALESCE(SUM(duration_seconds), 0.0) AS aggregate_test_seconds
                FROM test_run_targets WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            target_rows = connection.execute(
                """
                SELECT state, COUNT(*) AS count FROM test_run_targets
                WHERE run_id = ? GROUP BY state
                """,
                (run_id,),
            ).fetchall()
            target_states = {
                str(row["state"]): int(row["count"]) for row in target_rows
            }
            failure_record_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM test_failures AS failure
                    JOIN test_run_targets AS target
                      ON target.target_id = failure.target_id
                    WHERE target.run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            artifact_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM test_artifacts AS artifact
                    JOIN test_run_targets AS target
                      ON target.target_id = artifact.target_id
                    WHERE target.run_id = ?
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            return {
                "target_count": sum(target_states.values()),
                "completed_target_count": sum(
                    count
                    for state, count in target_states.items()
                    if state not in {"queued", *_ACTIVE_TARGET_STATES}
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
        """Return the one execution slot through the stable attempt read name."""

        execution_id = _safe_id("attempt_id", attempt_id)
        connection = self._connect(readonly=True)
        try:
            row = self._execution(connection, execution_id)
            return {
                "attempt_id": execution_id,
                "execution_id": execution_id,
                "target_id": str(row["target_id"]),
                "run_id": str(row["run_id"]),
                "attempt_number": 1,
                "state": str(row["state"]),
                "generation": int(row["generation"]),
                "memory_commitment_mib": int(row["memory_commitment_mib"]),
                "heartbeat_at": row["last_observed_at"],
                "lease_expires_at": None,
                "launched_at": row["started_at"],
                "launch_ack_id": row["launch_ack_id"],
                "terminal_operation_id": row["terminal_operation_id"],
                "terminal_fingerprint": row["terminal_fingerprint"],
                "conclusion": row["conclusion"],
                "failure_classification": row["failure_classification"],
                "duration_seconds": row["duration_seconds"],
                "peak_memory_bytes": row["peak_memory_bytes"],
                "cpu_seconds": row["cpu_seconds"],
                "passed_count": int(row["passed_count"]),
                "failed_count": int(row["failed_count"]),
                "skipped_count": int(row["skipped_count"]),
                "error_count": int(row["error_count"]),
                "reporter_complete": int(row["reporter_complete"]),
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        finally:
            connection.close()

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
                    SELECT failure.*, target.target_name,
                           target.execution_id AS attempt_id
                    FROM test_failures AS failure
                    JOIN test_run_targets AS target
                      ON target.target_id = failure.target_id
                    WHERE target.run_id = ? AND failure.failure_id > ?
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
                    SELECT artifact.*, target.target_name,
                           target.execution_id AS attempt_id
                    FROM test_artifacts AS artifact
                    JOIN test_run_targets AS target
                      ON target.target_id = artifact.target_id
                    WHERE target.run_id = ? AND artifact.artifact_id > ?
                    ORDER BY artifact.artifact_id LIMIT ?
                    """,
                    (run_id, after_value, limit),
                ).fetchall()
            )
        finally:
            connection.close()

    def artifact(self, *, run_id: str, artifact_id: str) -> dict[str, object]:
        run_id = _safe_id("run_id", run_id)
        artifact_id = _safe_id("artifact_id", artifact_id)
        connection = self._connect(readonly=True)
        try:
            row = connection.execute(
                """
                SELECT artifact.*, target.target_name,
                       target.execution_id AS attempt_id
                FROM test_artifacts AS artifact
                JOIN test_run_targets AS target
                  ON target.target_id = artifact.target_id
                WHERE target.run_id = ? AND artifact.artifact_id = ?
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

    def cases(
        self, *, run_id: str, after: int = 0, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        run_id = _safe_id("run_id", run_id)
        if type(after) is not int or after < 0:
            raise TestStoreContractError("case cursor must be non-negative")
        limit = _positive_int("limit", limit, maximum=500)
        connection = self._connect(readonly=True)
        try:
            if connection.execute(
                "SELECT 1 FROM test_runs WHERE run_id = ?", (run_id,)
            ).fetchone() is None:
                raise TestStoreNotFound("test run does not exist")
            return tuple(
                dict(row)
                for row in connection.execute(
                    """
                    SELECT result.rowid AS cursor, result.*, target.target_name,
                           target.execution_id AS attempt_id, 1 AS attempt_number
                    FROM test_case_results AS result
                    JOIN test_run_targets AS target
                      ON target.target_id = result.target_id
                    WHERE target.run_id = ? AND result.rowid > ?
                    ORDER BY result.rowid LIMIT ?
                    """,
                    (run_id, after, limit),
                ).fetchall()
            )
        finally:
            connection.close()

    def events(
        self,
        *,
        repository_id: str,
        after_event_id: int = 0,
        limit: int = 200,
    ) -> tuple[dict[str, object], ...]:
        repository_id = _safe_id("repository_id", repository_id)
        if type(after_event_id) is not int or after_event_id < 0:
            raise TestStoreContractError("after_event_id must be non-negative")
        limit = _positive_int("limit", limit, maximum=1_000)
        connection = self._connect(readonly=True)
        try:
            result = []
            for row in connection.execute(
                """
                SELECT * FROM test_events
                WHERE repository_id = ? AND event_id > ?
                ORDER BY event_id LIMIT ?
                """,
                (repository_id, after_event_id, limit),
            ).fetchall():
                item = dict(row)
                item["detail"] = json.loads(str(item.pop("detail_json")))
                result.append(item)
            return tuple(result)
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
    "CaseResult",
    "ExecutionGrant",
    "ExecutionResultPackage",
    "FailureClassification",
    "FailureRecord",
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
