"""Durable spool for test-runner exit and result envelopes.

Runner processes write bounded, generation-fenced envelopes before exiting.
Testd replays them through idempotent store operations.  A failed import leaves
the envelope in place; a successful import atomically moves it to a private
processed directory before deletion so crashes converge without losing data.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping, Sequence

from .universal_test_store import AttemptConclusion, TestStoreContractError


SPOOL_SCHEMA_VERSION = 3
ACTIVE_ATTEMPT_SCHEMA_VERSION = 5
MAX_SPOOL_ENVELOPE_BYTES = 512 * 1024
MAX_SPOOL_ENTRIES_PER_REPLAY = 1_000
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")


@dataclass(frozen=True)
class AttemptExitEnvelope:
    envelope_id: str
    attempt_id: str
    generation: int
    operation_id: str
    conclusion: AttemptConclusion
    duration_seconds: float
    result_chunk_ids: tuple[str, ...] = ()
    peak_memory_bytes: int | None = None
    cpu_seconds: float | None = None

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": SPOOL_SCHEMA_VERSION,
            "envelope_id": self.envelope_id,
            "attempt_id": self.attempt_id,
            "generation": self.generation,
            "operation_id": self.operation_id,
            "conclusion": self.conclusion.value,
            "duration_seconds": self.duration_seconds,
            "result_chunk_ids": list(self.result_chunk_ids),
            "peak_memory_bytes": self.peak_memory_bytes,
            "cpu_seconds": self.cpu_seconds,
        }

    @classmethod
    def from_document(cls, value: Mapping[str, object]) -> "AttemptExitEnvelope":
        if not isinstance(value, Mapping):
            raise TestStoreContractError("spool envelope fields are invalid")
        expected = {
            "schema_version",
            "envelope_id",
            "attempt_id",
            "generation",
            "operation_id",
            "conclusion",
            "duration_seconds",
            "result_chunk_ids",
            "peak_memory_bytes",
            "cpu_seconds",
        }
        if set(value) != expected:
            raise TestStoreContractError("spool envelope fields are invalid")
        if value.get("schema_version") != SPOOL_SCHEMA_VERSION:
            raise TestStoreContractError("spool envelope schema is unsupported")
        envelope_id = _safe_id("envelope_id", value["envelope_id"])
        attempt_id = _safe_id("attempt_id", value["attempt_id"])
        operation_id = _safe_id("operation_id", value["operation_id"])
        generation = value["generation"]
        if type(generation) is not int or generation <= 0:
            raise TestStoreContractError("spool generation must be positive")
        try:
            conclusion = AttemptConclusion(str(value["conclusion"]))
        except ValueError as error:
            raise TestStoreContractError("spool conclusion is invalid") from error
        duration = value["duration_seconds"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not 0 <= float(duration) <= 31_536_000
        ):
            raise TestStoreContractError("spool duration is invalid")
        raw_chunks = value["result_chunk_ids"]
        if not isinstance(raw_chunks, list) or len(raw_chunks) > 4_096:
            raise TestStoreContractError("spool result chunk IDs are invalid")
        chunks = tuple(_safe_id("result_chunk_id", item) for item in raw_chunks)
        if len(set(chunks)) != len(chunks):
            raise TestStoreContractError("spool result chunk IDs are duplicated")
        peak_memory_bytes = value["peak_memory_bytes"]
        if peak_memory_bytes is not None and (
            type(peak_memory_bytes) is not int
            or not 0 <= peak_memory_bytes <= (1 << 63) - 1
        ):
            raise TestStoreContractError("spool peak memory measurement is invalid")
        cpu_seconds = value["cpu_seconds"]
        if cpu_seconds is not None and (
            isinstance(cpu_seconds, bool)
            or not isinstance(cpu_seconds, (int, float))
            or not math.isfinite(float(cpu_seconds))
            or float(cpu_seconds) < 0
            or float(cpu_seconds) > 31_536_000
        ):
            raise TestStoreContractError("spool CPU measurement is invalid")
        return cls(
            envelope_id=envelope_id,
            attempt_id=attempt_id,
            generation=generation,
            operation_id=operation_id,
            conclusion=conclusion,
            duration_seconds=float(duration),
            result_chunk_ids=chunks,
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=None if cpu_seconds is None else float(cpu_seconds),
        )


@dataclass(frozen=True)
class AttemptResultChunkEnvelope:
    """One generation-fenced result chunk persisted before store ingestion."""

    envelope_id: str
    attempt_id: str
    generation: int
    chunk: Mapping[str, object]

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": SPOOL_SCHEMA_VERSION,
            "envelope_id": self.envelope_id,
            "attempt_id": self.attempt_id,
            "generation": self.generation,
            "chunk": dict(self.chunk),
        }

    @classmethod
    def from_document(
        cls, value: Mapping[str, object]
    ) -> "AttemptResultChunkEnvelope":
        if not isinstance(value, Mapping):
            raise TestStoreContractError("spool result chunk fields are invalid")
        expected = {
            "schema_version",
            "envelope_id",
            "attempt_id",
            "generation",
            "chunk",
        }
        if set(value) != expected:
            raise TestStoreContractError("spool result chunk fields are invalid")
        if value.get("schema_version") != SPOOL_SCHEMA_VERSION:
            raise TestStoreContractError("spool result chunk schema is unsupported")
        generation = value["generation"]
        chunk = value["chunk"]
        if type(generation) is not int or generation <= 0:
            raise TestStoreContractError("spool result chunk generation must be positive")
        if not isinstance(chunk, Mapping):
            raise TestStoreContractError("spool result chunk document is invalid")
        return cls(
            envelope_id=_safe_id("envelope_id", value["envelope_id"]),
            attempt_id=_safe_id("attempt_id", value["attempt_id"]),
            generation=generation,
            chunk=dict(chunk),
        )


@dataclass(frozen=True)
class ActiveAttemptEnvelope:
    """Durable testd ownership needed to reattach after a process restart."""

    attempt_id: str
    generation: int
    candidate: Mapping[str, object]
    lease: Mapping[str, object]
    runtime_id: str
    launch_ack_id: str
    repository_generation: int
    launched_at: float
    next_source_check_at: float
    result_chunk_ids: tuple[str, ...] = ()
    launch_ticket_id: str | None = None
    launch_operation_id: str | None = None
    launch_timeout_seconds: int = 300
    launch_confirmed: bool = True
    terminal_envelope: Mapping[str, object] | None = None

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVE_ATTEMPT_SCHEMA_VERSION,
            "attempt_id": self.attempt_id,
            "generation": self.generation,
            "candidate": dict(self.candidate),
            "lease": dict(self.lease),
            "runtime_id": self.runtime_id,
            "launch_ack_id": self.launch_ack_id,
            "repository_generation": self.repository_generation,
            "launched_at": self.launched_at,
            "next_source_check_at": self.next_source_check_at,
            "result_chunk_ids": list(self.result_chunk_ids),
            "launch_ticket_id": self.launch_ticket_id,
            "launch_operation_id": self.launch_operation_id,
            "launch_timeout_seconds": self.launch_timeout_seconds,
            "launch_confirmed": self.launch_confirmed,
            "terminal_envelope": (
                None
                if self.terminal_envelope is None
                else dict(self.terminal_envelope)
            ),
        }

    @classmethod
    def from_document(cls, value: Mapping[str, object]) -> "ActiveAttemptEnvelope":
        if not isinstance(value, Mapping):
            raise TestStoreContractError("active attempt spool fields are invalid")
        legacy_expected = {
            "schema_version",
            "attempt_id",
            "generation",
            "candidate",
            "lease",
            "runtime_id",
            "launch_ack_id",
            "repository_generation",
            "launched_at",
            "next_source_check_at",
            "result_chunk_ids",
        }
        version_4_expected = legacy_expected | {
            "launch_ticket_id",
            "launch_operation_id",
            "launch_timeout_seconds",
            "launch_confirmed",
        }
        current_expected = version_4_expected | {"terminal_envelope"}
        legacy = set(value) == legacy_expected and value.get("schema_version") == 3
        version_4 = (
            set(value) == version_4_expected and value.get("schema_version") == 4
        )
        current = (
            set(value) == current_expected
            and value.get("schema_version") == ACTIVE_ATTEMPT_SCHEMA_VERSION
        )
        if not legacy and not version_4 and not current:
            raise TestStoreContractError("active attempt spool fields are invalid")
        generation = value["generation"]
        repository_generation = value["repository_generation"]
        if type(generation) is not int or generation <= 0:
            raise TestStoreContractError("active attempt generation must be positive")
        if type(repository_generation) is not int or repository_generation < 0:
            raise TestStoreContractError(
                "active attempt repository generation must be non-negative"
            )
        candidate = value["candidate"]
        lease = value["lease"]
        if not isinstance(candidate, Mapping) or not isinstance(lease, Mapping):
            raise TestStoreContractError("active attempt binding is invalid")
        times: list[float] = []
        for field_name in ("launched_at", "next_source_check_at"):
            raw = value[field_name]
            if (
                isinstance(raw, bool)
                or not isinstance(raw, (int, float))
                or not math.isfinite(float(raw))
                or float(raw) < 0
            ):
                raise TestStoreContractError(f"active attempt {field_name} is invalid")
            times.append(float(raw))
        raw_chunks = value["result_chunk_ids"]
        if not isinstance(raw_chunks, list) or len(raw_chunks) > 4_096:
            raise TestStoreContractError("active attempt result chunk IDs are invalid")
        chunks = tuple(_safe_id("result_chunk_id", item) for item in raw_chunks)
        if len(set(chunks)) != len(chunks):
            raise TestStoreContractError("active attempt result chunk IDs are duplicated")
        launch_ticket_id = None
        launch_operation_id = None
        launch_timeout_seconds = 300
        launch_confirmed = True
        if version_4 or current:
            raw_ticket_id = value["launch_ticket_id"]
            raw_operation_id = value["launch_operation_id"]
            if raw_ticket_id is not None:
                launch_ticket_id = _safe_id("launch_ticket_id", raw_ticket_id)
            if raw_operation_id is not None:
                launch_operation_id = _safe_id(
                    "launch_operation_id", raw_operation_id
                )
            raw_timeout = value["launch_timeout_seconds"]
            if type(raw_timeout) is not int or not 1 <= raw_timeout <= 3_600:
                raise TestStoreContractError(
                    "active attempt launch timeout is invalid"
                )
            launch_timeout_seconds = raw_timeout
            if type(value["launch_confirmed"]) is not bool:
                raise TestStoreContractError(
                    "active attempt launch confirmation is invalid"
                )
            launch_confirmed = value["launch_confirmed"]
            if not launch_confirmed and (
                launch_ticket_id is None or launch_operation_id is None
            ):
                raise TestStoreContractError(
                    "pending active attempt launch identity is incomplete"
                )
        terminal_envelope = None
        if current and value["terminal_envelope"] is not None:
            raw_terminal = value["terminal_envelope"]
            if not isinstance(raw_terminal, Mapping):
                raise TestStoreContractError(
                    "active attempt terminal envelope is invalid"
                )
            terminal = AttemptExitEnvelope.from_document(raw_terminal)
            if (
                terminal.attempt_id != value["attempt_id"]
                or terminal.generation != generation
            ):
                raise TestStoreContractError(
                    "active attempt terminal envelope identity is invalid"
                )
            terminal_envelope = terminal.to_document()
        return cls(
            attempt_id=_safe_id("attempt_id", value["attempt_id"]),
            generation=generation,
            candidate=dict(candidate),
            lease=dict(lease),
            runtime_id=_safe_id("runtime_id", value["runtime_id"]),
            launch_ack_id=_safe_id("launch_ack_id", value["launch_ack_id"]),
            repository_generation=repository_generation,
            launched_at=times[0],
            next_source_check_at=times[1],
            result_chunk_ids=chunks,
            launch_ticket_id=launch_ticket_id,
            launch_operation_id=launch_operation_id,
            launch_timeout_seconds=launch_timeout_seconds,
            launch_confirmed=launch_confirmed,
            terminal_envelope=terminal_envelope,
        )


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class DurableAttemptSpool:
    """No-follow bounded spool with at-least-once replay.

    Filesystem ownership and permission bits are not a local authorization
    boundary on the single-developer host.  Type, path, size and race checks
    still protect the durable protocol from malformed or replaced entries.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.pending = self.root / "pending"
        self.processed = self.root / "processed"
        self.terminal_conflicts = self.root / "terminal-conflicts"
        self.result_pending = self.root / "result-pending"
        self.result_processed = self.root / "result-processed"
        self.active = self.root / "active"

    @classmethod
    def create(cls, root: Path) -> "DurableAttemptSpool":
        root = Path(root)
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (root / "pending").mkdir(mode=0o700)
        (root / "processed").mkdir(mode=0o700)
        (root / "terminal-conflicts").mkdir(mode=0o700)
        (root / "result-pending").mkdir(mode=0o700)
        (root / "result-processed").mkdir(mode=0o700)
        (root / "active").mkdir(mode=0o700)
        spool = cls(root)
        spool.verify()
        return spool

    @classmethod
    def open(cls, root: Path) -> "DurableAttemptSpool":
        spool = cls(root)
        # Initialize every queue after proving the existing
        # root.  This supports a genuinely fresh test store while preserving
        # any legacy pending/processed entries exactly when those queues
        # already exist.
        spool._verify_directory(spool.root)
        for path in (
            spool.pending,
            spool.processed,
            spool.terminal_conflicts,
            spool.result_pending,
            spool.result_processed,
            spool.active,
        ):
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        spool.verify()
        return spool

    def verify(self) -> None:
        for path in (
            self.root,
            self.pending,
            self.processed,
            self.terminal_conflicts,
            self.result_pending,
            self.result_processed,
            self.active,
        ):
            self._verify_directory(path)

    @staticmethod
    def _verify_directory(path: Path) -> None:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise TestStoreContractError("test spool path must be a real directory")

    def append(self, envelope: AttemptExitEnvelope) -> Path:
        if not isinstance(envelope, AttemptExitEnvelope):
            raise TestStoreContractError("spool value must be AttemptExitEnvelope")
        # Round-trip validation keeps construction and disk-import paths exact.
        normalized = AttemptExitEnvelope.from_document(envelope.to_document())
        payload = _canonical_json(normalized.to_document())
        if len(payload) > MAX_SPOOL_ENVELOPE_BYTES:
            raise TestStoreContractError("spool envelope exceeds its byte bound")
        digest = hashlib.sha256(payload).hexdigest()
        name = f"{normalized.envelope_id}-{digest}.json"
        pending_fd = self._open_directory(self.pending)
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=pending_fd,
                )
            except FileExistsError:
                # The content digest is part of the filename.  Verify the
                # existing private entry before treating an uncertain write as
                # an idempotent replay.
                existing = self._read(name)
                if existing != normalized:
                    raise TestStoreContractError(
                        "spool envelope identity conflicts with existing evidence"
                    )
                return self.pending / name
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(payload)
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(pending_fd)
        finally:
            os.close(pending_fd)
        return self.pending / name

    def append_result_chunk(self, envelope: AttemptResultChunkEnvelope) -> Path:
        if not isinstance(envelope, AttemptResultChunkEnvelope):
            raise TestStoreContractError(
                "result spool value must be AttemptResultChunkEnvelope"
            )
        normalized = AttemptResultChunkEnvelope.from_document(envelope.to_document())
        return self._append_document(
            normalized.envelope_id,
            normalized.to_document(),
            pending=self.result_pending,
            reader=self._read_result_chunk,
            expected=normalized,
        )

    @staticmethod
    def _active_name(attempt_id: str) -> str:
        attempt_id = _safe_id("attempt_id", attempt_id)
        return hashlib.sha256(attempt_id.encode("utf-8")).hexdigest() + ".json"

    def retain_active(self, envelope: ActiveAttemptEnvelope) -> Path:
        """Atomically retain the latest exact runtime attachment evidence."""

        if not isinstance(envelope, ActiveAttemptEnvelope):
            raise TestStoreContractError(
                "active spool value must be ActiveAttemptEnvelope"
            )
        normalized = ActiveAttemptEnvelope.from_document(envelope.to_document())
        payload = _canonical_json(normalized.to_document())
        if len(payload) > MAX_SPOOL_ENVELOPE_BYTES:
            raise TestStoreContractError("active attempt envelope exceeds its byte bound")
        name = self._active_name(normalized.attempt_id)
        active_fd = self._open_directory(self.active)
        temporary_name = ".tmp-" + hashlib.sha256(
            payload + os.urandom(32)
        ).hexdigest()
        try:
            try:
                existing = os.stat(name, dir_fd=active_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (
                not stat.S_ISREG(existing.st_mode)
            ):
                raise TestStoreContractError("active attempt entry is unsafe")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=active_fd,
            )
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(payload)
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(
                temporary_name,
                name,
                src_dir_fd=active_fd,
                dst_dir_fd=active_fd,
            )
            os.fsync(active_fd)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=active_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(active_fd)
        return self.active / name

    def active_envelopes(
        self, *, limit: int = 1_000
    ) -> tuple[ActiveAttemptEnvelope, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_SPOOL_ENTRIES_PER_REPLAY:
            raise TestStoreContractError("active spool limit is invalid")
        names = sorted(
            entry.name
            for entry in os.scandir(self.active)
            if entry.name.endswith(".json")
            and not entry.name.startswith(".tmp-")
            and not entry.is_symlink()
        )[:limit]
        return tuple(self._read_active(name) for name in names)

    def discard_active(self, attempt_id: str) -> None:
        name = self._active_name(attempt_id)
        active_fd = self._open_directory(self.active)
        try:
            try:
                envelope = self._read_active(name)
            except FileNotFoundError:
                return
            if envelope.attempt_id != attempt_id:
                raise TestStoreContractError("active attempt entry identity conflicts")
            os.unlink(name, dir_fd=active_fd)
            os.fsync(active_fd)
        finally:
            os.close(active_fd)

    def discard_all(self) -> int:
        """Delete only isolated disposable spool entries after restart cleanup."""

        removed = 0
        for directory in (
            self.pending,
            self.processed,
            self.terminal_conflicts,
            self.result_pending,
            self.result_processed,
            self.active,
        ):
            directory_fd = self._open_directory(directory)
            try:
                for entry in os.scandir(directory):
                    if entry.name.startswith(".tmp-"):
                        allowed = True
                    else:
                        allowed = entry.name.endswith(".json")
                    metadata = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if not allowed or not stat.S_ISREG(metadata.st_mode):
                        raise TestStoreContractError(
                            "test spool contains an unsupported entry"
                        )
                    os.unlink(entry.name, dir_fd=directory_fd)
                    removed += 1
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return removed

    def _append_document(
        self,
        envelope_id: str,
        document: Mapping[str, object],
        *,
        pending: Path,
        reader: Callable[[str], object],
        expected: object,
    ) -> Path:
        payload = _canonical_json(document)
        if len(payload) > MAX_SPOOL_ENVELOPE_BYTES:
            raise TestStoreContractError("spool envelope exceeds its byte bound")
        digest = hashlib.sha256(payload).hexdigest()
        name = f"{envelope_id}-{digest}.json"
        pending_fd = self._open_directory(pending)
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=pending_fd,
                )
            except FileExistsError:
                if reader(name) != expected:
                    raise TestStoreContractError(
                        "spool envelope identity conflicts with existing evidence"
                    )
                return pending / name
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(payload)
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(pending_fd)
        finally:
            os.close(pending_fd)
        return pending / name

    def pending_envelopes(self, *, limit: int = 1_000) -> tuple[AttemptExitEnvelope, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_SPOOL_ENTRIES_PER_REPLAY:
            raise TestStoreContractError("spool limit is invalid")
        names = sorted(
            entry.name
            for entry in os.scandir(self.pending)
            if entry.name.endswith(".json") and not entry.is_symlink()
        )[:limit]
        return tuple(self._read(name) for name in names)

    def pending_result_chunks(
        self, *, limit: int = 1_000
    ) -> tuple[AttemptResultChunkEnvelope, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_SPOOL_ENTRIES_PER_REPLAY:
            raise TestStoreContractError("spool limit is invalid")
        names = sorted(
            entry.name
            for entry in os.scandir(self.result_pending)
            if entry.name.endswith(".json") and not entry.is_symlink()
        )[:limit]
        return tuple(self._read_result_chunk(name) for name in names)

    def replay(
        self,
        importer: Callable[[AttemptExitEnvelope], object],
        *,
        limit: int = 1_000,
        priority_names: tuple[str, ...] = (),
    ) -> dict[str, object]:
        if not callable(importer):
            raise TestStoreContractError("spool importer must be callable")
        if type(limit) is not int or not 1 <= limit <= MAX_SPOOL_ENTRIES_PER_REPLAY:
            raise TestStoreContractError("spool limit is invalid")
        if (
            not isinstance(priority_names, tuple)
            or len(priority_names) > 16
            or len(set(priority_names)) != len(priority_names)
            or any(
                not isinstance(name, str)
                or Path(name).name != name
                or not name.endswith(".json")
                for name in priority_names
            )
        ):
            raise TestStoreContractError("spool replay priorities are invalid")
        imported: list[str] = []
        failed: list[dict[str, str]] = []
        quarantined: list[str] = []
        available = sorted(
            entry.name
            for entry in os.scandir(self.pending)
            if entry.name.endswith(".json") and not entry.is_symlink()
        )
        available_names = set(available)
        prioritized = [name for name in priority_names if name in available_names]
        prioritized_names = set(prioritized)
        names = (
            prioritized
            + [name for name in available if name not in prioritized_names]
        )[:limit]
        replayable: list[tuple[str, AttemptExitEnvelope]] = []
        seen_identities: set[tuple[str, str, int, str]] = set()
        conflicting_names: list[str] = []
        for name in names:
            try:
                envelope = self._read(name)
                identity = (
                    envelope.envelope_id,
                    envelope.attempt_id,
                    envelope.generation,
                    envelope.operation_id,
                )
                if identity in seen_identities:
                    conflicting_names.append(name)
                    quarantined.append(envelope.envelope_id)
                    continue
                seen_identities.add(identity)
                replayable.append((name, envelope))
            except Exception as error:
                failed.append({"entry": name, "error_type": type(error).__name__})
        if conflicting_names:
            try:
                self._quarantine_terminal_conflicts(conflicting_names)
            except Exception as error:
                failed.extend(
                    {"entry": name, "error_type": type(error).__name__}
                    for name in conflicting_names
                )
                quarantined = []
        for name, envelope in replayable:
            try:
                importer(envelope)
                self._complete(name)
                imported.append(envelope.envelope_id)
            except Exception as error:  # retained for the next bounded replay
                failed.append({"entry": name, "error_type": type(error).__name__})
        return {
            "imported_envelope_ids": imported,
            "quarantined_conflicting_envelope_ids": quarantined,
            "failed": failed,
        }

    def replay_result_chunks(
        self,
        importer: Callable[[AttemptResultChunkEnvelope], object],
        *,
        limit: int = 1_000,
    ) -> dict[str, object]:
        if not callable(importer):
            raise TestStoreContractError("spool result importer must be callable")
        if type(limit) is not int or not 1 <= limit <= MAX_SPOOL_ENTRIES_PER_REPLAY:
            raise TestStoreContractError("spool limit is invalid")
        imported: list[str] = []
        failed: list[dict[str, str]] = []
        names = sorted(
            entry.name
            for entry in os.scandir(self.result_pending)
            if entry.name.endswith(".json") and not entry.is_symlink()
        )[:limit]
        for name in names:
            try:
                envelope = self._read_result_chunk(name)
                importer(envelope)
                self._complete_in(
                    name,
                    pending=self.result_pending,
                    processed=self.result_processed,
                )
                imported.append(envelope.envelope_id)
            except Exception as error:
                failed.append({"entry": name, "error_type": type(error).__name__})
        return {"imported_envelope_ids": imported, "failed": failed}

    def _read(self, name: str) -> AttemptExitEnvelope:
        return AttemptExitEnvelope.from_document(
            self._read_document(name, pending=self.pending)
        )

    def _read_result_chunk(self, name: str) -> AttemptResultChunkEnvelope:
        return AttemptResultChunkEnvelope.from_document(
            self._read_document(name, pending=self.result_pending)
        )

    def _read_active(self, name: str) -> ActiveAttemptEnvelope:
        if Path(name).name != name or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise TestStoreContractError("active attempt entry name is invalid")
        document = self._read_private_document(name, directory=self.active)
        envelope = ActiveAttemptEnvelope.from_document(document)
        if name != self._active_name(envelope.attempt_id):
            raise TestStoreContractError("active attempt entry identity is invalid")
        return envelope

    def _read_private_document(
        self, name: str, *, directory: Path
    ) -> Mapping[str, object]:
        directory_fd = self._open_directory(directory)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > MAX_SPOOL_ENVELOPE_BYTES
                ):
                    raise TestStoreContractError("spool entry is not regular and bounded")
                payload = os.read(descriptor, MAX_SPOOL_ENVELOPE_BYTES + 1)
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                ):
                    raise TestStoreContractError("spool entry changed during read")
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
        if len(payload) > MAX_SPOOL_ENVELOPE_BYTES:
            raise TestStoreContractError("spool entry exceeds its byte bound")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("spool entry JSON is invalid") from error
        if not isinstance(document, Mapping):
            raise TestStoreContractError("spool entry document is invalid")
        return document

    def _read_document(
        self, name: str, *, pending: Path
    ) -> Mapping[str, object]:
        if Path(name).name != name or not name.endswith(".json"):
            raise TestStoreContractError("spool entry name is invalid")
        pending_fd = self._open_directory(pending)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pending_fd)
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > MAX_SPOOL_ENVELOPE_BYTES
                ):
                    raise TestStoreContractError("spool entry is not regular and bounded")
                payload = os.read(descriptor, MAX_SPOOL_ENVELOPE_BYTES + 1)
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                ):
                    raise TestStoreContractError("spool entry changed during read")
            finally:
                os.close(descriptor)
        finally:
            os.close(pending_fd)
        if len(payload) > MAX_SPOOL_ENVELOPE_BYTES:
            raise TestStoreContractError("spool entry exceeds its byte bound")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("spool entry JSON is invalid") from error
        if not isinstance(document, Mapping):
            raise TestStoreContractError("spool entry document is invalid")
        expected_suffix = "-" + hashlib.sha256(payload).hexdigest() + ".json"
        if not name.endswith(expected_suffix):
            raise TestStoreContractError("spool entry digest does not match its name")
        return document

    def _complete(self, name: str) -> None:
        self._complete_in(name, pending=self.pending, processed=self.processed)

    def _quarantine_terminal_conflicts(self, names: Sequence[str]) -> None:
        """Preserve contradictory duplicate transport outside hot replay."""

        pending_fd = self._open_directory(self.pending)
        conflicts_fd = self._open_directory(self.terminal_conflicts)
        try:
            for name in names:
                if Path(name).name != name or not name.endswith(".json"):
                    raise TestStoreContractError(
                        "terminal conflict entry name is invalid"
                    )
                try:
                    os.stat(name, dir_fd=conflicts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise TestStoreContractError(
                        "terminal conflict evidence already exists"
                    )
                os.rename(
                    name,
                    name,
                    src_dir_fd=pending_fd,
                    dst_dir_fd=conflicts_fd,
                )
            os.fsync(pending_fd)
            os.fsync(conflicts_fd)
        finally:
            os.close(conflicts_fd)
            os.close(pending_fd)

    def _complete_in(self, name: str, *, pending: Path, processed: Path) -> None:
        pending_fd = self._open_directory(pending)
        processed_fd = self._open_directory(processed)
        try:
            os.rename(
                name,
                name,
                src_dir_fd=pending_fd,
                dst_dir_fd=processed_fd,
            )
            os.fsync(pending_fd)
            os.fsync(processed_fd)
            os.unlink(name, dir_fd=processed_fd)
            os.fsync(processed_fd)
        finally:
            os.close(processed_fd)
            os.close(pending_fd)

    @staticmethod
    def _open_directory(path: Path) -> int:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise TestStoreContractError("spool path is not a directory")
        return descriptor


__all__ = [
    "ActiveAttemptEnvelope",
    "AttemptExitEnvelope",
    "AttemptResultChunkEnvelope",
    "DurableAttemptSpool",
    "MAX_SPOOL_ENVELOPE_BYTES",
]
