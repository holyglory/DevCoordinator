"""Offline migration of legacy authority test history into the test store.

The legacy broker stored test runs and case rows in the authority database.
This module copies only test/automation history into ``UniversalTestStore``;
session rows are orchestration wrappers rather than executable test evidence.

Migration is deliberately two-pass:

1. capture a consistent authority watermark and copy terminal rows;
2. after legacy test admission is drained, capture a final watermark, rescan
   the complete range, copy rows which finished in place, and classify any
   remaining legacy ``running`` row as ``abandoned``.

The rescan is required because legacy completion updates a row in place, so a
simple increasing-rowid tail would lose work that was running at the first
watermark.  Every import batch is idempotent and records a mutation-journal
entry in the destination.  Source and destination digests are compared before
the batch commits successfully.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence
import uuid

from .store import CoordinatorStore, refuse_symlink_components
from .universal_test_contract import SourceMode, deterministic_fingerprint
from .universal_test_planner import (
    SourceIdentity,
    TargetSelection,
    TestPlan,
    TestPlanTimeouts,
)
from .universal_test_store import (
    FailureClassification,
    MAX_RESULT_CHUNK_BYTES,
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)


LEGACY_TEST_MIGRATION_SCHEMA_VERSION = 1
DEFAULT_MIGRATION_BATCH_SIZE = 100
MAX_MIGRATION_BATCH_SIZE = 1_000
DEFAULT_CAPACITY_RESERVE_BYTES = 64 * 1024 * 1024
MAX_MIGRATION_RUN_BYTES = 8 * 1024 * 1024
MAX_MIGRATION_BATCH_BYTES = 16 * 1024 * 1024
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_TERMINAL = frozenset({"passed", "failed", "cancelled", "incomplete"})


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise TestStoreContractError(f"legacy {field} is invalid")
    return value


def _bounded_text(field: str, value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestStoreContractError(f"legacy {field} is invalid")
    return value


def _nonnegative_int(field: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise TestStoreContractError(f"legacy {field} must be non-negative")
    return value


def _finite_nonnegative(field: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TestStoreContractError(f"legacy {field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise TestStoreContractError(f"legacy {field} must be finite and non-negative")
    return number


def _epoch(field: str, value: object) -> float:
    text = _bounded_text(field, value, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise TestStoreContractError(f"legacy {field} is not ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TestStoreContractError(f"legacy {field} lacks an explicit offset")
    return parsed.timestamp()


@dataclass(frozen=True)
class LegacyTestWatermark:
    authority_generation: str
    maximum_rowid: int
    captured_at: str
    eligible_run_count: int
    terminal_run_count: int
    running_run_count: int
    excluded_session_count: int
    case_count: int
    estimated_import_bytes: int
    source_digest: str
    schema_version: int = LEGACY_TEST_MIGRATION_SCHEMA_VERSION

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_generation": self.authority_generation,
            "maximum_rowid": self.maximum_rowid,
            "captured_at": self.captured_at,
            "eligible_run_count": self.eligible_run_count,
            "terminal_run_count": self.terminal_run_count,
            "running_run_count": self.running_run_count,
            "excluded_session_count": self.excluded_session_count,
            "case_count": self.case_count,
            "estimated_import_bytes": self.estimated_import_bytes,
            "source_digest": self.source_digest,
        }

    @classmethod
    def from_document(cls, value: object) -> "LegacyTestWatermark":
        if not isinstance(value, Mapping):
            raise TestStoreContractError("legacy watermark must be an object")
        expected = {
            "schema_version",
            "authority_generation",
            "maximum_rowid",
            "captured_at",
            "eligible_run_count",
            "terminal_run_count",
            "running_run_count",
            "excluded_session_count",
            "case_count",
            "estimated_import_bytes",
            "source_digest",
        }
        if set(value) != expected:
            raise TestStoreContractError("legacy watermark fields are invalid")
        if value["schema_version"] != LEGACY_TEST_MIGRATION_SCHEMA_VERSION:
            raise TestStoreContractError("legacy watermark schema is unsupported")
        source_digest = str(value["source_digest"])
        if re.fullmatch(r"[0-9a-f]{64}", source_digest) is None:
            raise TestStoreContractError("legacy watermark digest is invalid")
        captured_at = _bounded_text("captured_at", value["captured_at"], maximum=64)
        _epoch("captured_at", captured_at)
        eligible = _nonnegative_int("eligible_run_count", value["eligible_run_count"])
        terminal = _nonnegative_int("terminal_run_count", value["terminal_run_count"])
        running = _nonnegative_int("running_run_count", value["running_run_count"])
        if terminal + running != eligible:
            raise TestStoreContractError("legacy watermark run counts are contradictory")
        return cls(
            authority_generation=_safe_id(
                "authority generation", value["authority_generation"]
            ),
            maximum_rowid=_nonnegative_int("maximum_rowid", value["maximum_rowid"]),
            captured_at=captured_at,
            eligible_run_count=eligible,
            terminal_run_count=terminal,
            running_run_count=running,
            excluded_session_count=_nonnegative_int(
                "excluded_session_count", value["excluded_session_count"]
            ),
            case_count=_nonnegative_int("case_count", value["case_count"]),
            estimated_import_bytes=_nonnegative_int(
                "estimated_import_bytes", value["estimated_import_bytes"]
            ),
            source_digest=source_digest,
        )


@dataclass(frozen=True)
class LegacyImportResult:
    maximum_rowid: int
    imported_run_count: int
    imported_case_count: int
    deferred_running_count: int
    abandoned_running_count: int
    source_digest: str
    destination_digest: str
    rollups: Mapping[str, int]

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": LEGACY_TEST_MIGRATION_SCHEMA_VERSION,
            "maximum_rowid": self.maximum_rowid,
            "imported_run_count": self.imported_run_count,
            "imported_case_count": self.imported_case_count,
            "deferred_running_count": self.deferred_running_count,
            "abandoned_running_count": self.abandoned_running_count,
            "source_digest": self.source_digest,
            "destination_digest": self.destination_digest,
            "rollups": dict(self.rollups),
        }


@dataclass(frozen=True)
class LegacyImportBatchResult:
    """One durable, idempotent migration batch.

    ``next_rowid`` is the resume cursor.  It advances over excluded session
    wrappers as well as eligible rows, so a crash never causes an unbounded
    prefix rescan.
    """

    next_rowid: int
    complete: bool
    imported_run_count: int
    imported_case_count: int
    deferred_running_count: int
    abandoned_running_count: int
    batch_digest: str

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": LEGACY_TEST_MIGRATION_SCHEMA_VERSION,
            "next_rowid": self.next_rowid,
            "complete": self.complete,
            "imported_run_count": self.imported_run_count,
            "imported_case_count": self.imported_case_count,
            "deferred_running_count": self.deferred_running_count,
            "abandoned_running_count": self.abandoned_running_count,
            "batch_digest": self.batch_digest,
        }


@dataclass(frozen=True)
class LegacyExportBatchResult:
    """One bounded authority-owned export batch for a separate testd UID."""

    next_rowid: int
    complete: bool
    records: tuple[Mapping[str, object], ...]
    projection_digest: str
    run_count: int
    case_count: int
    deferred_running_count: int
    abandoned_running_count: int

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": LEGACY_TEST_MIGRATION_SCHEMA_VERSION,
            "next_rowid": self.next_rowid,
            "complete": self.complete,
            "records": [dict(record) for record in self.records],
            "projection_digest": self.projection_digest,
            "run_count": self.run_count,
            "case_count": self.case_count,
            "deferred_running_count": self.deferred_running_count,
            "abandoned_running_count": self.abandoned_running_count,
        }


_MIGRATION_PHASES = frozenset(
    {"captured", "copying", "copied", "finalizing", "finalized", "verified", "sealed"}
)


@dataclass(frozen=True)
class LegacyMigrationState:
    """Crash-resumable offline cutover state stored outside both databases."""

    migration_id: str
    authority_database: str
    test_database: str
    test_store_generation: str
    batch_size: int
    phase: str
    initial_watermark: LegacyTestWatermark
    initial_cursor: int
    final_watermark: LegacyTestWatermark | None
    final_cursor: int
    drain_proof_fingerprint: str | None
    verification: Mapping[str, object] | None
    seal: Mapping[str, object] | None
    created_at: str
    updated_at: str
    state_generation: int
    schema_version: int = LEGACY_TEST_MIGRATION_SCHEMA_VERSION

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "migration_id": self.migration_id,
            "authority_database": self.authority_database,
            "test_database": self.test_database,
            "test_store_generation": self.test_store_generation,
            "batch_size": self.batch_size,
            "phase": self.phase,
            "initial_watermark": self.initial_watermark.to_document(),
            "initial_cursor": self.initial_cursor,
            "final_watermark": (
                None if self.final_watermark is None else self.final_watermark.to_document()
            ),
            "final_cursor": self.final_cursor,
            "drain_proof_fingerprint": self.drain_proof_fingerprint,
            "verification": None if self.verification is None else dict(self.verification),
            "seal": None if self.seal is None else dict(self.seal),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state_generation": self.state_generation,
        }

    @classmethod
    def from_document(cls, value: object) -> "LegacyMigrationState":
        if not isinstance(value, Mapping):
            raise TestStoreContractError("migration state must be an object")
        expected = {
            "schema_version", "migration_id", "authority_database", "test_database",
            "test_store_generation", "batch_size", "phase", "initial_watermark",
            "initial_cursor", "final_watermark", "final_cursor",
            "drain_proof_fingerprint", "verification", "seal", "created_at",
            "updated_at", "state_generation",
        }
        if set(value) != expected:
            raise TestStoreContractError("migration state fields are invalid")
        if value["schema_version"] != LEGACY_TEST_MIGRATION_SCHEMA_VERSION:
            raise TestStoreContractError("migration state schema is unsupported")
        authority = str(value["authority_database"])
        destination = str(value["test_database"])
        if not Path(authority).is_absolute() or not Path(destination).is_absolute():
            raise TestStoreContractError("migration database paths must be absolute")
        phase = str(value["phase"])
        if phase not in _MIGRATION_PHASES:
            raise TestStoreContractError("migration phase is invalid")
        batch_size = _nonnegative_int("batch_size", value["batch_size"])
        if not 1 <= batch_size <= MAX_MIGRATION_BATCH_SIZE:
            raise TestStoreContractError("migration batch size is invalid")
        final_raw = value["final_watermark"]
        final = None if final_raw is None else LegacyTestWatermark.from_document(final_raw)
        proof = value["drain_proof_fingerprint"]
        if proof is not None and re.fullmatch(r"[0-9a-f]{64}", str(proof)) is None:
            raise TestStoreContractError("migration drain proof fingerprint is invalid")
        verification = value["verification"]
        seal = value["seal"]
        if verification is not None and not isinstance(verification, Mapping):
            raise TestStoreContractError("migration verification is invalid")
        if seal is not None and not isinstance(seal, Mapping):
            raise TestStoreContractError("migration seal is invalid")
        initial = LegacyTestWatermark.from_document(value["initial_watermark"])
        initial_cursor = _nonnegative_int("initial_cursor", value["initial_cursor"])
        final_cursor = _nonnegative_int("final_cursor", value["final_cursor"])
        if initial_cursor > initial.maximum_rowid:
            raise TestStoreContractError("initial migration cursor exceeds its watermark")
        if phase in {"copied", "finalizing", "finalized", "verified", "sealed"} and (
            initial_cursor != initial.maximum_rowid
        ):
            raise TestStoreContractError("initial copy phase is inconsistent with its cursor")
        if final is None and final_cursor != 0:
            raise TestStoreContractError("final migration cursor exists without a watermark")
        if final is not None and final_cursor > final.maximum_rowid:
            raise TestStoreContractError("final migration cursor exceeds its watermark")
        if phase in {"captured", "copying"} and final is not None:
            raise TestStoreContractError("final watermark exists before initial copy completion")
        if phase in {"finalizing", "finalized", "verified", "sealed"}:
            if final is None or proof is None:
                raise TestStoreContractError("final migration phase lacks its drain evidence")
        if phase in {"finalized", "verified", "sealed"} and final is not None and (
            final_cursor != final.maximum_rowid
        ):
            raise TestStoreContractError("finalized migration phase is inconsistent with its cursor")
        if phase in {"verified", "sealed"} and verification is None:
            raise TestStoreContractError("verified migration phase lacks verification evidence")
        if phase == "sealed" and seal is None:
            raise TestStoreContractError("sealed migration phase lacks seal evidence")
        return cls(
            migration_id=_safe_id("migration ID", value["migration_id"]),
            authority_database=authority,
            test_database=destination,
            test_store_generation=_safe_id(
                "test store generation", value["test_store_generation"]
            ),
            batch_size=batch_size,
            phase=phase,
            initial_watermark=initial,
            initial_cursor=initial_cursor,
            final_watermark=final,
            final_cursor=final_cursor,
            drain_proof_fingerprint=None if proof is None else str(proof),
            verification=None if verification is None else MappingProxyType(dict(verification)),
            seal=None if seal is None else MappingProxyType(dict(seal)),
            created_at=_bounded_text("created_at", value["created_at"], maximum=64),
            updated_at=_bounded_text("updated_at", value["updated_at"], maximum=64),
            state_generation=_nonnegative_int(
                "state_generation", value["state_generation"]
            ),
        )


def _private_state_parent(path: Path, *, expected_uid: int) -> None:
    parent = path.parent
    try:
        refuse_symlink_components(parent)
    except (FileNotFoundError, PermissionError) as error:
        raise TestStoreContractError("migration state path contains an unsafe component") from error
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TestStoreContractError("migration state parent must be a real directory")
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise TestStoreContractError("migration state parent must be owned by the service UID and mode 0700")


def load_migration_state(path: Path, *, expected_uid: int) -> LegacyMigrationState:
    path = Path(os.path.abspath(path))
    _private_state_parent(path, expected_uid=expected_uid)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise TestStoreContractError("migration state file identity is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as handle:
            document = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TestStoreContractError("migration state file is malformed") from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise TestStoreConflict("migration state changed while it was read")
    return LegacyMigrationState.from_document(document)


def _save_migration_state_unlocked(
    path: Path,
    state: LegacyMigrationState,
    *,
    expected_uid: int,
    create: bool,
    expected_generation: int | None = None,
) -> None:
    """Atomically create/replace a private state file with a CAS generation."""

    if not isinstance(state, LegacyMigrationState):
        raise TestStoreContractError("migration state is invalid")
    path = Path(os.path.abspath(path))
    _private_state_parent(path, expected_uid=expected_uid)
    exists = path.exists() or path.is_symlink()
    if create:
        if exists:
            raise TestStoreConflict("migration state already exists")
    else:
        if not exists:
            raise TestStoreConflict("migration state does not exist")
        current = load_migration_state(path, expected_uid=expected_uid)
        if expected_generation is None or current.state_generation != expected_generation:
            raise TestStoreConflict("migration state generation changed")
        if state.state_generation != expected_generation + 1:
            raise TestStoreContractError("replacement state generation must advance by one")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = (_canonical_json(state.to_document()) + "\n").encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if create:
            # ``link`` supplies no-replace publication semantics.
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def save_migration_state(
    path: Path,
    state: LegacyMigrationState,
    *,
    expected_uid: int,
    create: bool,
    expected_generation: int | None = None,
) -> None:
    """Serialize state publishers and atomically apply one CAS transition."""

    path = Path(os.path.abspath(path))
    _private_state_parent(path, expected_uid=expected_uid)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TestStoreContractError("migration state lock identity is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _save_migration_state_unlocked(
            path,
            state,
            expected_uid=expected_uid,
            create=create,
            expected_generation=expected_generation,
        )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class _LegacyBatch:
    next_rowid: int
    complete: bool
    runs: tuple[dict[str, object], ...]
    excluded_session_count: int


def _case_id(case: Mapping[str, object]) -> str:
    ordinal = _nonnegative_int("case ordinal", case["ordinal"])
    test_id = _bounded_text("case test_id", case["test_id"], maximum=1024)
    return f"legacy-case-{ordinal:08d}-{hashlib.sha256(test_id.encode()).hexdigest()[:16]}"


def _target_name(run: Mapping[str, object]) -> str:
    suite = _bounded_text("suite", run["suite"], maximum=1024)
    return "legacy-" + hashlib.sha256(suite.encode("utf-8")).hexdigest()[:24]


def _mapped_state(status: str, *, finalize_running: bool) -> tuple[str, str | None]:
    if status == "passed":
        return "succeeded", None
    if status == "failed":
        return "test_failed", FailureClassification.TEST_FAILURE.value
    if status == "cancelled":
        return "cancelled", FailureClassification.CANCELLATION.value
    if status == "incomplete":
        return "incomplete", FailureClassification.INCOMPLETE_REPORTING.value
    if status == "running" and finalize_running:
        return "abandoned", FailureClassification.ABANDONMENT.value
    raise TestStoreContractError("legacy run is not importable in this migration phase")


def _run_state(target_state: str) -> str:
    return "failed" if target_state == "test_failed" else target_state


def _legacy_plan(run: Mapping[str, object]) -> TestPlan:
    repository_id = _safe_id("repository ID", run["repo_id"])
    original_root = _bounded_text("repository root", run["canonical_root"])
    identity = {
        "schema_version": 1,
        "legacy_run_id": _safe_id("run ID", run["run_id"]),
        "repository_id": repository_id,
        "command_fingerprint": _bounded_text(
            "command fingerprint", run["command_fingerprint"], maximum=1024
        ),
        "started_at": _bounded_text("client_started_at", run["client_started_at"], maximum=64),
    }
    source = SourceIdentity(
        mode=SourceMode.LIVE,
        repository_id=repository_id,
        content_fingerprint=_digest(identity),
        original_root=original_root,
    )
    target = _target_name(run)
    manifest_fingerprint = _digest(
        {
            "schema_version": 1,
            "kind": "legacy-test-journal",
            "suite": run["suite"],
            "run_kind": run["run_kind"],
        }
    )
    selection = MappingProxyType(
        {target: TargetSelection(target=target, reasons=("historical-legacy-journal",))}
    )
    timeouts = TestPlanTimeouts()
    document = {
        "schema_version": 2,
        "manifest_fingerprint": manifest_fingerprint,
        "repository_id": repository_id,
        "intent": "manual",
        "timeouts": timeouts.to_document(),
        "source": source.to_document(),
        "changes": [],
        "eligible_targets": [target],
        "selected_targets": [target],
        "dependency_waves": [[target]],
        "selection": {target: ["historical-legacy-journal"]},
        "complete_intent_fallback": False,
        "reusable": False,
    }
    fingerprint = deterministic_fingerprint(document)
    execution_fingerprint = deterministic_fingerprint(
        {
            "schema_version": 2,
            "manifest_fingerprint": manifest_fingerprint,
            "repository_id": repository_id,
            "source_mode": source.mode.value,
            "content_fingerprint": source.content_fingerprint,
            "intent": "manual",
            "timeouts": timeouts.to_document(),
            "eligible_targets": [target],
            "selected_targets": [target],
            "dependency_waves": [[target]],
        }
    )
    return TestPlan(
        plan_id="plan-" + fingerprint[:32],
        fingerprint=fingerprint,
        execution_fingerprint=execution_fingerprint,
        manifest_fingerprint=manifest_fingerprint,
        repository_id=repository_id,
        intent="manual",
        timeouts=timeouts,
        source=source,
        changes=(),
        eligible_targets=(target,),
        selected_targets=(target,),
        dependency_waves=((target,),),
        selection=selection,
        complete_intent_fallback=False,
        reusable=False,
        evidence_policies=MappingProxyType({}),
    )


def _normalized_case(case: Mapping[str, object]) -> dict[str, object]:
    status = str(case["status"])
    if status not in {"passed", "failed", "skipped", "error"}:
        raise TestStoreContractError("legacy case status is invalid")
    return {
        "case_id": _case_id(case),
        "display_name": _bounded_text("case display_name", case["display_name"]),
        "status": status,
        "duration_seconds": _finite_nonnegative(
            "case duration_seconds", case["duration_seconds"]
        ),
    }


def _import_projection(
    run: Mapping[str, object], *, finalize_running: bool
) -> dict[str, object]:
    status = str(run["status"])
    target_state, classification = _mapped_state(
        status, finalize_running=finalize_running
    )
    cases = [_normalized_case(item) for item in run["cases"]]  # type: ignore[index]
    counts = {
        name: sum(1 for case in cases if case["status"] == status_name)
        for name, status_name in (
            ("passed_count", "passed"),
            ("failed_count", "failed"),
            ("skipped_count", "skipped"),
            ("error_count", "error"),
        )
    }
    if len(cases) != _nonnegative_int("case_count", run["case_count"]):
        raise TestStoreConflict("legacy run case_count does not match its case rows")
    for field, count in counts.items():
        if count != _nonnegative_int(field, run[field]):
            raise TestStoreConflict(f"legacy run {field} does not match its case rows")
    started_at = _epoch("client_started_at", run["client_started_at"])
    if status == "running":
        finished_at = _epoch("watermark captured_at", run["watermark_captured_at"])
    else:
        finished_at = _epoch("recorded_finished_at", run["recorded_finished_at"])
    if finished_at < started_at:
        raise TestStoreConflict("legacy run finished before it started")
    aggregate_seconds = round(
        sum(float(case["duration_seconds"]) for case in cases), 9
    )
    if not cases:
        aggregate_seconds = _finite_nonnegative(
            "duration_seconds", run["duration_seconds"] or 0.0
        )
    return {
        "run_id": _safe_id("run ID", run["run_id"]),
        "repository_id": _safe_id("repository ID", run["repo_id"]),
        "owner_uid": _nonnegative_int("owner_uid", run["owner_uid"]),
        "actor": _bounded_text("actor", run["actor"], maximum=256),
        "target_name": _target_name(run),
        "state": _run_state(target_state),
        "target_state": target_state,
        "classification": classification,
        "started_at": started_at,
        "finished_at": finished_at,
        "aggregate_test_seconds": aggregate_seconds,
        **counts,
        "cases": cases,
    }


def _chunk_cases(cases: Sequence[Mapping[str, object]]) -> tuple[tuple[Mapping[str, object], ...], ...]:
    if not cases:
        return ((),)
    chunks: list[tuple[Mapping[str, object], ...]] = []
    current: list[Mapping[str, object]] = []
    for case in cases:
        candidate = [*current, case]
        if current and len(_canonical_json(candidate).encode("utf-8")) > MAX_RESULT_CHUNK_BYTES // 2:
            chunks.append(tuple(current))
            current = [case]
        else:
            current = candidate
        if len(_canonical_json(current).encode("utf-8")) > MAX_RESULT_CHUNK_BYTES // 2:
            raise TestStoreContractError("one legacy case exceeds the migration chunk bound")
    chunks.append(tuple(current))
    return tuple(chunks)


class LegacyTestHistoryMigrator:
    """Copy a consistent authority test-history snapshot into testd storage."""

    def __init__(
        self,
        authority_database: Path,
        destination: UniversalTestStore | None,
        *,
        expected_authority_uid: int,
        busy_timeout_ms: int = 5_000,
        capacity_probe: Callable[[Path], int] | None = None,
        capacity_reserve_bytes: int = DEFAULT_CAPACITY_RESERVE_BYTES,
    ) -> None:
        self.authority_database = Path(authority_database)
        self.destination = destination
        self.expected_authority_uid = expected_authority_uid
        self.busy_timeout_ms = busy_timeout_ms
        self.capacity_probe = (
            (lambda path: int(shutil.disk_usage(path).free))
            if capacity_probe is None
            else capacity_probe
        )
        self.capacity_reserve_bytes = _nonnegative_int(
            "capacity_reserve_bytes", capacity_reserve_bytes
        )
        if destination is not None and not isinstance(destination, UniversalTestStore):
            raise TestStoreContractError("destination must be UniversalTestStore or null")

    def _destination_store(self) -> UniversalTestStore:
        if self.destination is None:
            raise TestStoreContractError("this migration operation requires a test store")
        return self.destination

    def capture_watermark(self) -> LegacyTestWatermark:
        return self._capture_watermark()

    @staticmethod
    def _source_document(row: Mapping[str, object]) -> dict[str, object]:
        return {
            **{
                key: value
                for key, value in row.items()
                if key not in {"cases", "watermark_captured_at"}
            },
            "cases": list(row["cases"]),
        }

    @staticmethod
    def _digest_documents(documents: Iterable[Mapping[str, object]]) -> str:
        hasher = hashlib.sha256()
        hasher.update(b"[")
        first = True
        for document in documents:
            if not first:
                hasher.update(b",")
            first = False
            hasher.update(_canonical_json(document).encode("utf-8"))
        hasher.update(b"]")
        return hasher.hexdigest()

    @staticmethod
    def _load_cases(connection: Any, run_id: str) -> list[dict[str, object]]:
        cursor = connection.execute(
            """
            SELECT * FROM test_case_results
            WHERE run_id = ? ORDER BY ordinal
            """,
            (run_id,),
        )
        cases: list[dict[str, object]] = []
        encoded_bytes = 0
        while True:
            rows = cursor.fetchmany(500)
            if not rows:
                break
            for raw in rows:
                case = dict(raw)
                encoded_bytes += len(_canonical_json(case).encode("utf-8"))
                if encoded_bytes > MAX_MIGRATION_RUN_BYTES:
                    raise TestStoreContractError(
                        "one legacy run exceeds the bounded migration export size"
                    )
                cases.append(case)
        return cases

    def _normalize_source_row(
        self, connection: Any, raw: Mapping[str, object], *, captured_at: str
    ) -> dict[str, object]:
        row = dict(raw)
        status = str(row["status"])
        if status not in _TERMINAL | {"running"}:
            raise TestStoreContractError("legacy run status is unsupported")
        row["cases"] = self._load_cases(connection, str(row["run_id"]))
        row["watermark_captured_at"] = captured_at
        if (
            len(_canonical_json(self._source_document(row)).encode("utf-8"))
            > MAX_MIGRATION_RUN_BYTES
        ):
            raise TestStoreContractError(
                "one legacy run exceeds the bounded migration export size"
            )
        return row

    def _capture_watermark(
        self, *, maximum_rowid: int | None = None
    ) -> LegacyTestWatermark:
        with CoordinatorStore.open_read_only(
            self.authority_database,
            expected_uid=self.expected_authority_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
                if metadata is None:
                    raise TestStoreConflict("authority database generation is missing")
                actual_max = int(
                    connection.execute("SELECT COALESCE(MAX(rowid), 0) FROM test_runs").fetchone()[0]
                )
                selected_max = actual_max if maximum_rowid is None else maximum_rowid
                if type(selected_max) is not int or selected_max < 0 or selected_max > actual_max:
                    raise TestStoreContractError("legacy maximum_rowid is invalid")
                captured_at = datetime.now().astimezone().isoformat()
                cursor = connection.execute(
                    """
                    SELECT run.rowid AS legacy_rowid, run.*, repository.canonical_root
                    FROM test_runs AS run
                    JOIN repositories AS repository USING(repo_id)
                    WHERE run.rowid <= ?
                    ORDER BY run.rowid, run.run_id
                    """,
                    (selected_max,),
                )
                hasher = hashlib.sha256()
                hasher.update(b"[")
                first = True
                eligible_count = terminal_count = running_count = 0
                excluded_count = case_count = logical_bytes = 0
                while True:
                    rows = cursor.fetchmany(DEFAULT_MIGRATION_BATCH_SIZE)
                    if not rows:
                        break
                    for raw in rows:
                        if str(raw["run_kind"]) == "session":
                            excluded_count += 1
                            continue
                        row = self._normalize_source_row(
                            connection, raw, captured_at=captured_at
                        )
                        status = str(row["status"])
                        eligible_count += 1
                        terminal_count += int(status in _TERMINAL)
                        running_count += int(status == "running")
                        case_count += len(row["cases"])
                        encoded = _canonical_json(self._source_document(row)).encode("utf-8")
                        if not first:
                            hasher.update(b",")
                        first = False
                        hasher.update(encoded)
                        logical_bytes += len(encoded)
                hasher.update(b"]")
                estimated_import_bytes = (
                    logical_bytes * 3
                    + eligible_count * 4_096
                    + case_count * 256
                )
                return LegacyTestWatermark(
                    authority_generation=str(metadata["database_generation"]),
                    maximum_rowid=selected_max,
                    captured_at=captured_at,
                    eligible_run_count=eligible_count,
                    terminal_run_count=terminal_count,
                    running_run_count=running_count,
                    excluded_session_count=excluded_count,
                    case_count=case_count,
                    estimated_import_bytes=estimated_import_bytes,
                    source_digest=hasher.hexdigest(),
                )

    def validate_watermark(self, watermark: LegacyTestWatermark) -> None:
        if not isinstance(watermark, LegacyTestWatermark):
            raise TestStoreContractError("legacy watermark is invalid")
        actual = self._capture_watermark(maximum_rowid=watermark.maximum_rowid)
        self._assert_watermark_matches(actual, watermark)

    @staticmethod
    def _assert_watermark_matches(
        actual: LegacyTestWatermark,
        expected: LegacyTestWatermark,
    ) -> None:
        stable_fields = (
            "authority_generation",
            "maximum_rowid",
            "eligible_run_count",
            "terminal_run_count",
            "running_run_count",
            "excluded_session_count",
            "case_count",
            "estimated_import_bytes",
            "source_digest",
        )
        if any(getattr(actual, field) != getattr(expected, field) for field in stable_fields):
            raise TestStoreConflict("legacy authority snapshot changed after its watermark")

    def validate_final_watermark(self, watermark: LegacyTestWatermark) -> None:
        """Require the supplied watermark to remain the complete legacy tail.

        ``validate_watermark`` deliberately validates only the bounded prefix
        captured by a pass.  Cutover verification and sealing need the stronger
        invariant that no row was admitted above that prefix while the broker
        drain was expected to remain active.
        """

        if not isinstance(watermark, LegacyTestWatermark):
            raise TestStoreContractError("legacy watermark is invalid")
        actual = self._capture_watermark()
        if actual.maximum_rowid != watermark.maximum_rowid:
            raise TestStoreConflict("legacy authority gained rows after its final watermark")
        self._assert_watermark_matches(actual, watermark)

    def preflight_capacity(self, watermark: LegacyTestWatermark) -> dict[str, int]:
        destination = self._destination_store()
        required = watermark.estimated_import_bytes + self.capacity_reserve_bytes
        available = self.capacity_probe(destination.path.parent)
        if type(available) is not int or available < 0:
            raise TestStoreContractError("migration capacity probe returned invalid data")
        if available < required:
            raise TestStoreConflict(
                f"test history migration needs {required} free bytes but only {available} are available"
            )
        return {"required_bytes": required, "available_bytes": available}

    def _load_batch(
        self,
        watermark: LegacyTestWatermark,
        *,
        after_rowid: int,
        batch_size: int,
    ) -> _LegacyBatch:
        if type(after_rowid) is not int or not 0 <= after_rowid <= watermark.maximum_rowid:
            raise TestStoreContractError("legacy migration cursor is invalid")
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_MIGRATION_BATCH_SIZE:
            raise TestStoreContractError("legacy migration batch size is invalid")
        with CoordinatorStore.open_read_only(
            self.authority_database,
            expected_uid=self.expected_authority_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
                if (
                    metadata is None
                    or str(metadata["database_generation"]) != watermark.authority_generation
                ):
                    raise TestStoreConflict("authority generation changed during migration")
                raw_rows = connection.execute(
                    """
                    SELECT run.rowid AS legacy_rowid, run.*, repository.canonical_root
                    FROM test_runs AS run
                    JOIN repositories AS repository USING(repo_id)
                    WHERE run.rowid > ? AND run.rowid <= ?
                    ORDER BY run.rowid, run.run_id LIMIT ?
                    """,
                    (after_rowid, watermark.maximum_rowid, batch_size),
                ).fetchall()
                if not raw_rows:
                    return _LegacyBatch(
                        next_rowid=watermark.maximum_rowid,
                        complete=True,
                        runs=(),
                        excluded_session_count=0,
                    )
                next_rowid = after_rowid
                excluded = 0
                runs: list[dict[str, object]] = []
                encoded_bytes = 0
                for raw in raw_rows:
                    rowid = int(raw["legacy_rowid"])
                    if str(raw["run_kind"]) == "session":
                        excluded += 1
                        next_rowid = rowid
                        continue
                    normalized = self._normalize_source_row(
                        connection, raw, captured_at=watermark.captured_at
                    )
                    row_bytes = len(
                        _canonical_json(self._source_document(normalized)).encode("utf-8")
                    )
                    if runs and encoded_bytes + row_bytes > MAX_MIGRATION_BATCH_BYTES:
                        break
                    encoded_bytes += row_bytes
                    runs.append(normalized)
                    next_rowid = rowid
                if next_rowid <= after_rowid:
                    raise TestStoreConflict("legacy migration batch could not make bounded progress")
                return _LegacyBatch(
                    next_rowid=next_rowid,
                    complete=next_rowid >= watermark.maximum_rowid,
                    runs=tuple(runs),
                    excluded_session_count=excluded,
                )

    def export_next_batch(
        self,
        watermark: LegacyTestWatermark,
        *,
        finalize_running: bool,
        after_rowid: int,
        batch_size: int = DEFAULT_MIGRATION_BATCH_SIZE,
    ) -> LegacyExportBatchResult:
        """Read one bounded authority batch without opening a test store."""

        batch = self._load_batch(
            watermark,
            after_rowid=after_rowid,
            batch_size=batch_size,
        )
        records: list[Mapping[str, object]] = []
        projections: list[dict[str, object]] = []
        deferred = abandoned = case_count = 0
        for row in batch.runs:
            if row["status"] == "running" and not finalize_running:
                deferred += 1
                continue
            projection = _import_projection(row, finalize_running=finalize_running)
            abandoned += int(projection["target_state"] == "abandoned")
            case_count += len(projection["cases"])
            source = {
                field: row[field]
                for field in (
                    "repo_id",
                    "canonical_root",
                    "run_id",
                    "command_fingerprint",
                    "client_started_at",
                    "suite",
                    "run_kind",
                )
            }
            records.append(
                MappingProxyType({"source": source, "projection": projection})
            )
            projections.append(projection)
        return LegacyExportBatchResult(
            next_rowid=batch.next_rowid,
            complete=batch.complete,
            records=tuple(records),
            projection_digest=_digest(projections),
            run_count=len(records),
            case_count=case_count,
            deferred_running_count=deferred,
            abandoned_running_count=abandoned,
        )

    def import_next_batch(
        self,
        watermark: LegacyTestWatermark,
        *,
        finalize_running: bool,
        after_rowid: int,
        batch_size: int = DEFAULT_MIGRATION_BATCH_SIZE,
    ) -> LegacyImportBatchResult:
        batch = self._load_batch(
            watermark, after_rowid=after_rowid, batch_size=batch_size
        )
        pairs: list[tuple[dict[str, object], dict[str, object]]] = []
        deferred = 0
        abandoned = 0
        for row in batch.runs:
            if row["status"] == "running" and not finalize_running:
                deferred += 1
                continue
            projection = _import_projection(
                row, finalize_running=finalize_running
            )
            abandoned += int(projection["target_state"] == "abandoned")
            pairs.append((row, projection))
        pairs.sort(key=lambda pair: str(pair[1]["run_id"]))
        projections = [pair[1] for pair in pairs]
        batch_digest = _digest(projections)
        operation_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator:legacy-test-import-batch:"
                + watermark.authority_generation
                + f":{watermark.maximum_rowid}:{watermark.source_digest}:"
                + f"{int(finalize_running)}:{after_rowid}:{batch.next_rowid}",
            )
        )
        request_fingerprint = _digest(
            {
                "watermark": watermark.to_document(),
                "finalize_running": finalize_running,
                "after_rowid": after_rowid,
                "next_rowid": batch.next_rowid,
                "batch_size": batch_size,
                "batch_digest": batch_digest,
            }
        )
        destination = self._destination_store()
        with destination._transaction() as connection:
            replay = connection.execute(
                "SELECT request_fingerprint FROM test_mutation_journal WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if replay is not None:
                if str(replay["request_fingerprint"]) != request_fingerprint:
                    raise TestStoreConflict("legacy import batch identity conflicts")
            else:
                for row, projection in pairs:
                    self._insert_run(connection, row, projection)
                destination_digest = self._destination_digest(
                    connection, [str(item["run_id"]) for item in projections]
                )
                if destination_digest != batch_digest:
                    raise TestStoreConflict("legacy destination batch digest does not match source")
                connection.execute(
                    """
                    INSERT INTO test_mutation_journal(
                        operation_id, operation_kind, request_fingerprint,
                        result_json, created_at
                    ) VALUES (?, 'legacy_test_import_batch', ?, ?, ?)
                    """,
                    (
                        operation_id,
                        request_fingerprint,
                        _canonical_json(
                            {
                                "after_rowid": after_rowid,
                                "next_rowid": batch.next_rowid,
                                "run_count": len(projections),
                                "case_count": sum(len(item["cases"]) for item in projections),
                                "batch_digest": batch_digest,
                            }
                        ),
                        _epoch("watermark captured_at", watermark.captured_at),
                    ),
                )
        return LegacyImportBatchResult(
            next_rowid=batch.next_rowid,
            complete=batch.complete,
            imported_run_count=len(projections),
            imported_case_count=sum(len(item["cases"]) for item in projections),
            deferred_running_count=deferred,
            abandoned_running_count=abandoned,
            batch_digest=batch_digest,
        )

    def _iter_import_projections(
        self,
        watermark: LegacyTestWatermark,
        *,
        finalize_running: bool,
        batch_size: int = DEFAULT_MIGRATION_BATCH_SIZE,
    ) -> Iterator[dict[str, object]]:
        cursor = 0
        while cursor < watermark.maximum_rowid:
            batch = self._load_batch(
                watermark, after_rowid=cursor, batch_size=batch_size
            )
            for row in batch.runs:
                if row["status"] == "running" and not finalize_running:
                    continue
                yield _import_projection(row, finalize_running=finalize_running)
            if batch.next_rowid <= cursor:
                raise TestStoreConflict("legacy migration cursor did not advance")
            cursor = batch.next_rowid

    def verify_import(
        self,
        watermark: LegacyTestWatermark,
        *,
        finalize_running: bool,
    ) -> LegacyImportResult:
        self.validate_watermark(watermark)
        source_count = source_cases = 0
        source_hasher = hashlib.sha256()
        source_hasher.update(b"[")
        first = True
        for projection in self._iter_import_projections(
            watermark, finalize_running=finalize_running
        ):
            if not first:
                source_hasher.update(b",")
            first = False
            source_hasher.update(_canonical_json(projection).encode("utf-8"))
            source_count += 1
            source_cases += len(projection["cases"])
        source_hasher.update(b"]")
        source_digest = source_hasher.hexdigest()
        connection = self._destination_store()._connect(readonly=True)
        try:
            destination_digest = self._destination_digest(
                connection,
                (
                    str(projection["run_id"])
                    for projection in self._iter_import_projections(
                        watermark, finalize_running=finalize_running
                    )
                ),
            )
        finally:
            connection.close()
        if destination_digest != source_digest:
            raise TestStoreConflict("legacy destination digest does not match source")
        return LegacyImportResult(
            maximum_rowid=watermark.maximum_rowid,
            imported_run_count=source_count,
            imported_case_count=source_cases,
            deferred_running_count=0 if finalize_running else watermark.running_run_count,
            abandoned_running_count=watermark.running_run_count if finalize_running else 0,
            source_digest=source_digest,
            destination_digest=destination_digest,
            rollups={"hourly": 0, "daily": 0},
        )

    def import_watermark(
        self,
        watermark: LegacyTestWatermark,
        *,
        finalize_running: bool,
        rebuild_rollups: bool = True,
        batch_size: int = DEFAULT_MIGRATION_BATCH_SIZE,
    ) -> LegacyImportResult:
        self.preflight_capacity(watermark)
        self.validate_watermark(watermark)
        cursor = 0
        while cursor < watermark.maximum_rowid:
            result = self.import_next_batch(
                watermark,
                finalize_running=finalize_running,
                after_rowid=cursor,
                batch_size=batch_size,
            )
            if result.next_rowid <= cursor:
                raise TestStoreConflict("legacy migration cursor did not advance")
            cursor = result.next_rowid
        verified = self.verify_import(
            watermark, finalize_running=finalize_running
        )
        rollups = (
            self._destination_store().rebuild_rollups()
            if rebuild_rollups
            else {"hourly": 0, "daily": 0}
        )
        return LegacyImportResult(
            maximum_rowid=verified.maximum_rowid,
            imported_run_count=verified.imported_run_count,
            imported_case_count=verified.imported_case_count,
            deferred_running_count=verified.deferred_running_count,
            abandoned_running_count=verified.abandoned_running_count,
            source_digest=verified.source_digest,
            destination_digest=verified.destination_digest,
            rollups=rollups,
        )

    def _insert_run(
        self,
        connection: Any,
        source: Mapping[str, object],
        projection: Mapping[str, object],
    ) -> None:
        plan = _legacy_plan(source)
        self._destination_store()._upsert_snapshot_and_plan(
            connection,
            plan=plan,
            created_at=float(projection["started_at"]),
        )
        run_id = str(projection["run_id"])
        existing = connection.execute(
            "SELECT run_id FROM test_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if existing is not None:
            existing_digest = self._destination_digest(connection, [run_id])
            if existing_digest != _digest([projection]):
                raise TestStoreConflict("legacy run already exists with different evidence")
            return
        target_name = str(projection["target_name"])
        target_id = "target-" + hashlib.sha256(f"{run_id}\0{target_name}".encode()).hexdigest()[:32]
        attempt_id = "attempt-" + hashlib.sha256(target_id.encode()).hexdigest()[:32]
        started = float(projection["started_at"])
        finished = float(projection["finished_at"])
        state = str(projection["state"])
        target_state = str(projection["target_state"])
        classification = projection["classification"]
        connection.execute(
            """
            INSERT INTO test_runs(
                run_id, plan_id, repository_id, owner_uid, actor, intent,
                source_mode, source_fingerprint, execution_fingerprint,
                eligible_target_count, selected_target_count, state, conclusion,
                failure_classification, priority, queued_at, started_at,
                finished_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'manual', 'live', ?, ?, 1, 1, ?, ?, ?, 0, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                plan.plan_id,
                projection["repository_id"],
                projection["owner_uid"],
                projection["actor"],
                plan.source.content_fingerprint,
                plan.execution_fingerprint,
                state,
                state,
                classification,
                started,
                started,
                finished,
                started,
                finished,
            ),
        )
        connection.execute(
            """
            INSERT INTO test_run_targets(
                target_id, run_id, target_name, wave_index, shard_index,
                shard_count, state, cpu_millis, memory_mib, pids,
                estimated_seconds, max_attempts, worktree_key,
                exclusive_resources_json, current_attempt_id, queued_at,
                started_at, finished_at
            ) VALUES (?, ?, ?, 0, 0, 1, ?, 1000, 1024, 256, ?, 1, ?, '[]', ?, ?, ?, ?)
            """,
            (
                target_id,
                run_id,
                target_name,
                target_state,
                max(0.001, finished - started),
                plan.source.original_root,
                attempt_id,
                started,
                started,
                finished,
            ),
        )
        terminal_operation = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"devcoordinator:legacy-attempt:{run_id}")
        )
        connection.execute(
            """
            INSERT INTO test_target_attempts(
                attempt_id, target_id, run_id, attempt_number, state,
                generation, lease_owner, lease_token_sha256, lease_expires_at,
                heartbeat_at, queued_at, launched_at, launch_ack_id,
                terminal_operation_id, terminal_fingerprint, conclusion,
                failure_classification, duration_seconds, passed_count,
                failed_count, skipped_count, error_count, reporter_complete,
                started_at, finished_at, created_at, updated_at
            ) VALUES (?, ?, ?, 1, ?, 1, 'legacy-migration', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                target_id,
                run_id,
                target_state,
                _digest({"run_id": run_id, "lease": "historical"}),
                finished,
                finished,
                started,
                started,
                "legacy-launch-" + hashlib.sha256(run_id.encode()).hexdigest()[:24],
                terminal_operation,
                _digest(projection),
                target_state,
                classification,
                projection["aggregate_test_seconds"],
                projection["passed_count"],
                projection["failed_count"],
                projection["skipped_count"],
                projection["error_count"],
                started,
                finished,
                started,
                finished,
            ),
        )
        chunks = _chunk_cases(projection["cases"])  # type: ignore[arg-type]
        has_failure = classification is not None
        for index, chunk in enumerate(chunks):
            chunk_id = f"legacy-chunk-{index:06d}"
            failure_count = int(has_failure and index == 0)
            encoded = _canonical_json(list(chunk)).encode("utf-8")
            connection.execute(
                """
                INSERT INTO test_result_chunks(
                    attempt_id, chunk_id, chunk_index, fingerprint,
                    encoded_bytes, case_count, failure_count, artifact_count,
                    reporter_complete, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    attempt_id,
                    chunk_id,
                    index,
                    hashlib.sha256(encoded).hexdigest(),
                    len(encoded),
                    len(chunk),
                    failure_count,
                    int(index == len(chunks) - 1),
                    finished,
                ),
            )
            for ordinal, case in enumerate(chunk):
                connection.execute(
                    """
                    INSERT INTO test_case_results(
                        attempt_id, chunk_id, ordinal, case_id, display_name,
                        status, duration_seconds, location
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        attempt_id,
                        chunk_id,
                        ordinal,
                        case["case_id"],
                        case["display_name"],
                        case["status"],
                        case["duration_seconds"],
                    ),
                )
            if failure_count:
                connection.execute(
                    """
                    INSERT INTO test_failures(
                        failure_id, attempt_id, chunk_id, classification,
                        case_id, message, location, artifact_id, created_at
                    ) VALUES (?, ?, ?, ?, NULL, ?, NULL, NULL, ?)
                    """,
                    (
                        "legacy-failure-" + hashlib.sha256(run_id.encode()).hexdigest()[:32],
                        attempt_id,
                        chunk_id,
                        classification,
                        "Historical run did not retain structured failure output.",
                        finished,
                    ),
                )

    @staticmethod
    def _destination_digest(connection: Any, run_ids: Iterable[str]) -> str:
        hasher = hashlib.sha256()
        hasher.update(b"[")
        first = True
        for run_id in run_ids:
            run = connection.execute(
                """
                SELECT run.*, target.target_name, target.state AS target_state,
                       attempt.duration_seconds AS aggregate_test_seconds,
                       attempt.passed_count, attempt.failed_count,
                       attempt.skipped_count, attempt.error_count
                FROM test_runs AS run
                JOIN test_run_targets AS target USING(run_id)
                JOIN test_target_attempts AS attempt USING(run_id, target_id)
                WHERE run.run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                raise TestStoreConflict("imported legacy run is missing")
            cases = [
                {
                    "case_id": str(row["case_id"]),
                    "display_name": str(row["display_name"]),
                    "status": str(row["status"]),
                    "duration_seconds": float(row["duration_seconds"]),
                }
                for row in connection.execute(
                    """
                    SELECT case_row.* FROM test_case_results AS case_row
                    JOIN test_target_attempts AS attempt USING(attempt_id)
                    WHERE attempt.run_id = ? ORDER BY case_row.case_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            projection = {
                "run_id": str(run["run_id"]),
                "repository_id": str(run["repository_id"]),
                "owner_uid": int(run["owner_uid"]),
                "actor": str(run["actor"]),
                "target_name": str(run["target_name"]),
                "state": str(run["state"]),
                "target_state": str(run["target_state"]),
                "classification": run["failure_classification"],
                "started_at": float(run["started_at"]),
                "finished_at": float(run["finished_at"]),
                "aggregate_test_seconds": float(run["aggregate_test_seconds"]),
                "passed_count": int(run["passed_count"]),
                "failed_count": int(run["failed_count"]),
                "skipped_count": int(run["skipped_count"]),
                "error_count": int(run["error_count"]),
                "cases": cases,
            }
            if not first:
                hasher.update(b",")
            first = False
            hasher.update(_canonical_json(projection).encode("utf-8"))
        hasher.update(b"]")
        return hasher.hexdigest()


class LegacyTestExportImporter:
    """Import authority-sealed batches while opening only the test store."""

    def __init__(self, destination: UniversalTestStore) -> None:
        if not isinstance(destination, UniversalTestStore):
            raise TestStoreContractError("destination must be UniversalTestStore")
        self.destination = destination
        # This helper never calls an authority-reading method.  It exists only
        # to reuse the exact legacy row-to-store insertion implementation.
        self._inserter = LegacyTestHistoryMigrator(
            Path("/authority-not-opened-by-testd"),
            destination,
            expected_authority_uid=os.geteuid(),
        )

    def import_batch(
        self,
        records: Sequence[Mapping[str, object]],
        *,
        operation_id: str,
        expected_projection_digest: str,
    ) -> dict[str, object]:
        if not isinstance(records, Sequence) or len(records) > MAX_MIGRATION_BATCH_SIZE:
            raise TestStoreContractError("migration export batch record count is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", expected_projection_digest) is None:
            raise TestStoreContractError("migration export projection digest is invalid")
        normalized: list[tuple[Mapping[str, object], Mapping[str, object]]] = []
        projections: list[Mapping[str, object]] = []
        encoded_bytes = 0
        for record in records:
            if not isinstance(record, Mapping) or set(record) != {"source", "projection"}:
                raise TestStoreContractError("migration export record fields are invalid")
            source = record["source"]
            projection = record["projection"]
            if not isinstance(source, Mapping) or not isinstance(projection, Mapping):
                raise TestStoreContractError("migration export record is malformed")
            encoded_bytes += len(_canonical_json(record).encode("utf-8"))
            if encoded_bytes > MAX_MIGRATION_BATCH_BYTES * 2:
                raise TestStoreContractError("migration export batch exceeds its byte bound")
            normalized.append((source, projection))
            projections.append(projection)
        if _digest(projections) != expected_projection_digest:
            raise TestStoreConflict("migration export projection digest does not match")
        operation_id = str(uuid.UUID(operation_id))
        request_fingerprint = _digest(
            {
                "operation_id": operation_id,
                "projection_digest": expected_projection_digest,
                "run_ids": [projection.get("run_id") for projection in projections],
            }
        )
        with self.destination._transaction() as connection:
            replay = connection.execute(
                "SELECT request_fingerprint FROM test_mutation_journal WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if replay is not None:
                if str(replay["request_fingerprint"]) != request_fingerprint:
                    raise TestStoreConflict("migration export import identity conflicts")
            else:
                for source, projection in normalized:
                    self._inserter._insert_run(connection, source, projection)
                connection.execute(
                    """
                    INSERT INTO test_mutation_journal(
                        operation_id, operation_kind, request_fingerprint,
                        result_json, created_at
                    ) VALUES (?, 'legacy_test_export_import', ?, ?, ?)
                    """,
                    (
                        operation_id,
                        request_fingerprint,
                        _canonical_json(
                            {
                                "projection_digest": expected_projection_digest,
                                "run_count": len(projections),
                            }
                        ),
                        0.0,
                    ),
                )
            destination_digest = LegacyTestHistoryMigrator._destination_digest(
                connection,
                [str(projection["run_id"]) for projection in projections],
            )
            if destination_digest != expected_projection_digest:
                raise TestStoreConflict("imported migration batch digest does not match")
        return {
            "run_count": len(projections),
            "case_count": sum(
                len(projection.get("cases", ())) for projection in projections
            ),
            "projection_digest": expected_projection_digest,
        }


__all__ = [
    "LEGACY_TEST_MIGRATION_SCHEMA_VERSION",
    "DEFAULT_MIGRATION_BATCH_SIZE",
    "MAX_MIGRATION_BATCH_SIZE",
    "MAX_MIGRATION_BATCH_BYTES",
    "MAX_MIGRATION_RUN_BYTES",
    "LegacyExportBatchResult",
    "LegacyTestExportImporter",
    "LegacyImportBatchResult",
    "LegacyImportResult",
    "LegacyMigrationState",
    "LegacyTestHistoryMigrator",
    "LegacyTestWatermark",
    "load_migration_state",
    "save_migration_state",
]
