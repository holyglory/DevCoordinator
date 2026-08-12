"""Fixed-argv worker runner with durable, fenced crash evidence.

The native service manager starts this runner with only an immutable worker
identity.  Command, environment, repository ownership, and generation tokens
come from the Coordinator authority; none can be supplied on the runner CLI.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

from .broker import BrokerError, BrokerOperation
from .broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    load_broker_profile,
)
from .runtime_redaction import redact_runtime_value
from .store import canonical_json, ensure_private_store_directory, fingerprint
from .worker_supervision import (
    WorkerCircuitOpen,
    WorkerLaunchFenced,
    WorkerNotConfigured,
    WorkerSupervision,
    WorkerSupervisionConflict,
)


WORKER_LOG_MAX_BYTES = 1024 * 1024
WORKER_LOG_MAX_LINES = 2_000
WORKER_RESTART_DELAY_SECONDS = 2.0
WORKER_PENDING_EXIT_MAX_BYTES = 32 * 1024
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TEXT_LIMIT = 4096
_ARTIFACT_MARKER = b"[DevCoordinator retained the final bounded worker output]\n"
_PROTECTED_IDENTITY_ENVIRONMENT = frozenset({"HOME", "USER", "LOGNAME", "SHELL"})
_TRANSIENT_BROKER_ERRORS = frozenset(
    {
        "host_observation_busy",
        "incomplete_request",
        "operation_in_progress",
        "operation_outcome_uncertain",
        "request_timeout",
        "server_busy",
        "service_shutting_down",
        "worker_operation_uncertain",
    }
)


class WorkerRunnerError(RuntimeError):
    """The fixed runner could not safely complete its responsibility."""


class WorkerCandidateError(WorkerRunnerError):
    """Authority returned an invalid or unclassified launch candidate."""


class WorkerAuthorityBlocked(WorkerRunnerError):
    """Durable authority says this worker must not be launched."""


class WorkerAuthorityUnavailable(WorkerRunnerError):
    """Durable authority is temporarily unavailable."""


class WorkerAuthority(Protocol):
    """Narrow authority surface shared by direct and broker-backed runners."""

    def active_attempt(self, *, worker_id: str) -> Mapping[str, Any] | None:
        ...

    def read_attempt(
        self, *, worker_id: str, attempt_id: str
    ) -> Mapping[str, Any]:
        ...

    def launch_candidate(self, *, worker_id: str) -> Mapping[str, Any]:
        ...

    def begin_attempt(
        self, *, candidate: Mapping[str, Any], begin_request_id: str
    ) -> Mapping[str, Any]:
        ...

    def mark_attempt_launched(
        self,
        *,
        candidate: Mapping[str, Any],
        attempt: Mapping[str, Any],
        launch_report_id: str,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
    ) -> Mapping[str, Any]:
        ...

    def record_attempt_exit(
        self,
        *,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        log_artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> Mapping[str, Any]:
        ...


class DirectWorkerAuthority:
    """Adapt :class:`WorkerSupervision` to the runner's broker-ready surface."""

    def __init__(self, supervision: WorkerSupervision) -> None:
        self.supervision = supervision

    @staticmethod
    def _blocked(error: BaseException) -> WorkerAuthorityBlocked:
        return WorkerAuthorityBlocked(str(error))

    def active_attempt(self, *, worker_id: str) -> Mapping[str, Any] | None:
        try:
            policy = self.supervision.policy(worker_id)
            attempt_id = policy.get("current_attempt_id")
            if attempt_id is None:
                return None
            attempt = dict(self.supervision.attempt(str(attempt_id)))
            attempt["execution_uid"] = policy["execution_uid"]
            return attempt
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error

    def read_attempt(self, *, worker_id: str, attempt_id: str) -> Mapping[str, Any]:
        try:
            attempt = self.supervision.attempt(attempt_id)
            if str(attempt.get("server_definition_id") or "") != worker_id:
                raise WorkerSupervisionConflict(
                    "worker attempt belongs to another worker"
                )
            return attempt
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error

    def launch_candidate(self, *, worker_id: str) -> Mapping[str, Any]:
        try:
            policy = self.supervision.policy(worker_id)
            epoch = policy.get("supervisor_epoch")
            if not isinstance(epoch, str) or not epoch.strip():
                raise WorkerAuthorityBlocked(
                    "worker supervisor epoch is not initialized by the Coordinator"
                )
            return self.supervision.launch_candidate(
                server_definition_id=worker_id,
                supervisor_epoch=epoch,
            )
        except WorkerAuthorityBlocked:
            raise
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error

    def begin_attempt(
        self, *, candidate: Mapping[str, Any], begin_request_id: str
    ) -> Mapping[str, Any]:
        try:
            return self.supervision.begin_attempt(
                server_definition_id=str(candidate["server_definition_id"]),
                begin_request_id=begin_request_id,
                supervisor_epoch=str(candidate["supervisor_epoch"]),
                expected_definition_generation=int(candidate["definition_generation"]),
                expected_policy_generation=int(candidate["policy_generation"]),
                expected_supervisor_generation=int(
                    candidate["supervisor_generation"]
                ),
            )
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error

    def mark_attempt_launched(
        self,
        *,
        candidate: Mapping[str, Any],
        attempt: Mapping[str, Any],
        launch_report_id: str,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
    ) -> Mapping[str, Any]:
        try:
            return self.supervision.mark_attempt_launched(
                attempt_id=str(attempt["attempt_id"]),
                launch_report_id=launch_report_id,
                supervisor_epoch=str(candidate["supervisor_epoch"]),
                supervisor_generation=int(candidate["supervisor_generation"]),
                pid=pid,
                process_start_time=process_start_time,
                process_fingerprint=process_fingerprint,
            )
        except WorkerLaunchFenced:
            raise
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error

    def record_attempt_exit(
        self,
        *,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        log_artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> Mapping[str, Any]:
        try:
            return self.supervision.record_attempt_exit(
                attempt_id=str(attempt["attempt_id"]),
                exit_report_id=exit_report_id,
                supervisor_epoch=str(attempt["supervisor_epoch"]),
                supervisor_generation=int(attempt["supervisor_generation"]),
                exit_kind=exit_kind,
                exit_code=exit_code,
                exit_signal=exit_signal,
                log_artifact=log_artifact,
                occurred_at_epoch=occurred_at_epoch,
            )
        except (WorkerCircuitOpen, WorkerNotConfigured, WorkerSupervisionConflict) as error:
            raise self._blocked(error) from error


@dataclass(frozen=True)
class LaunchCandidate:
    worker_id: str
    repo_id: str
    family_id: str
    root_repo_id: str
    project_kind: str
    root_repository: Path
    repository: Path
    cwd: Path
    name: str
    argv: tuple[str, ...]
    environment: dict[str, str]
    execution_uid: int
    definition_fingerprint: str
    definition_generation: int
    policy_generation: int
    supervisor_epoch: str
    supervisor_generation: int
    raw: Mapping[str, Any]

    @property
    def repository_context(self) -> dict[str, str | None]:
        return {
            "root_repo": str(self.root_repository),
            "temporary_repo": (
                str(self.repository) if self.project_kind == "temporary" else None
            ),
        }


def _canonical_uuid(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise WorkerCandidateError(f"{name} must be a canonical UUID")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError as error:
        raise WorkerCandidateError(f"{name} must be a canonical UUID") from error
    if canonical != value:
        raise WorkerCandidateError(f"{name} must be a canonical UUID")
    return canonical


def _bounded_text(name: str, value: object, *, maximum: int = _TEXT_LIMIT) -> str:
    if not isinstance(value, str):
        raise WorkerCandidateError(f"{name} must be text")
    if (
        not value
        or len(value) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise WorkerCandidateError(f"{name} must be bounded non-empty text")
    return value


def _generation(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise WorkerCandidateError(f"{name} must be a non-negative integer")
    return value


def _canonical_directory(name: str, value: object) -> Path:
    text = _bounded_text(name, value)
    raw = Path(text)
    if not raw.is_absolute():
        raise WorkerCandidateError(f"{name} must be absolute")
    try:
        resolved = raw.resolve(strict=True)
        metadata = raw.lstat()
    except OSError as error:
        raise WorkerCandidateError(f"{name} is unavailable: {error}") from error
    if raw != resolved or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
        metadata.st_mode
    ):
        raise WorkerCandidateError(f"{name} must be an existing canonical directory")
    return resolved


def validate_launch_candidate(
    raw: Mapping[str, Any], *, worker_id: str, effective_uid: int
) -> LaunchCandidate:
    """Validate authority output before any process or artifact is created."""

    worker_id = _canonical_uuid("worker_id", worker_id)
    if not isinstance(raw, Mapping):
        raise WorkerCandidateError("worker launch candidate must be an object")
    server_id = _canonical_uuid(
        "candidate.server_definition_id", raw.get("server_definition_id")
    )
    if server_id != worker_id:
        raise WorkerCandidateError("launch candidate belongs to another worker")
    repo_id = _canonical_uuid("candidate.repo_id", raw.get("repo_id"))
    family_id = _canonical_uuid("candidate.family_id", raw.get("family_id"))
    root_repo_id = _canonical_uuid(
        "candidate.root_repo_id", raw.get("root_repo_id")
    )
    project_kind = _bounded_text("candidate.project_kind", raw.get("project_kind"))
    if project_kind not in {"primary", "temporary"}:
        raise WorkerCandidateError("worker repository ownership is unclassified")
    root_repository = _canonical_directory(
        "candidate.root_repository", raw.get("root_repository")
    )
    repository = _canonical_directory("candidate.repository", raw.get("repository"))
    cwd = _canonical_directory("candidate.cwd", raw.get("cwd"))
    if cwd != repository and repository not in cwd.parents:
        raise WorkerCandidateError("worker cwd escapes its attributed repository")
    if project_kind == "primary":
        if repo_id != root_repo_id or repository != root_repository:
            raise WorkerCandidateError("primary worker repository identity is inconsistent")
    elif repo_id == root_repo_id or repository == root_repository:
        raise WorkerCandidateError("temporary worker repository identity is inconsistent")
    execution_uid = raw.get("execution_uid")
    if type(execution_uid) is not int or execution_uid < 0:
        raise WorkerCandidateError("candidate.execution_uid must be non-negative")
    if execution_uid != effective_uid:
        raise WorkerCandidateError(
            "worker launch candidate is attributed to another operating-system account"
        )
    raw_argv = raw.get("argv")
    if isinstance(raw_argv, (str, bytes)) or not isinstance(raw_argv, Sequence):
        raise WorkerCandidateError("candidate.argv must be a stored argument array")
    argv = tuple(raw_argv)
    if not argv or any(
        not isinstance(item, str) or len(item) > 32_768 or "\x00" in item
        for item in argv
    ) or not argv[0]:
        raise WorkerCandidateError("candidate.argv is not a safe stored argument array")
    raw_environment = raw.get("environment")
    if not isinstance(raw_environment, Mapping):
        raise WorkerCandidateError("candidate.environment must be a stored object")
    environment: dict[str, str] = {}
    for key, value in raw_environment.items():
        if (
            not isinstance(key, str)
            or _ENVIRONMENT_NAME.fullmatch(key) is None
            or not isinstance(value, str)
            or len(value) > 65_536
            or "\x00" in value
        ):
            raise WorkerCandidateError("candidate.environment contains an invalid entry")
        environment[key] = value
    _deterministic_environment(environment, execution_uid=execution_uid)
    return LaunchCandidate(
        worker_id=worker_id,
        repo_id=repo_id,
        family_id=family_id,
        root_repo_id=root_repo_id,
        project_kind=project_kind,
        root_repository=root_repository,
        repository=repository,
        cwd=cwd,
        name=_bounded_text("candidate.name", raw.get("name")),
        argv=argv,
        environment=environment,
        execution_uid=execution_uid,
        definition_fingerprint=_bounded_text(
            "candidate.definition_fingerprint", raw.get("definition_fingerprint")
        ),
        definition_generation=_generation(
            "candidate.definition_generation", raw.get("definition_generation")
        ),
        policy_generation=_generation(
            "candidate.policy_generation", raw.get("policy_generation")
        ),
        supervisor_epoch=_bounded_text(
            "candidate.supervisor_epoch", raw.get("supervisor_epoch")
        ),
        supervisor_generation=_generation(
            "candidate.supervisor_generation", raw.get("supervisor_generation")
        ),
        raw=raw,
    )


class WorkerLogCapture:
    """Drain combined child output into one private, bounded durable artifact."""

    def __init__(
        self,
        *,
        root: Path,
        worker_id: str,
        attempt_id: str,
        maximum_bytes: int = WORKER_LOG_MAX_BYTES,
        maximum_lines: int = WORKER_LOG_MAX_LINES,
        redaction_request: Mapping[str, Any] | None = None,
    ) -> None:
        if type(maximum_bytes) is not int or maximum_bytes < 4_096:
            raise ValueError("worker log maximum must be at least 4096 bytes")
        if type(maximum_lines) is not int or not 1 <= maximum_lines <= 100_000:
            raise ValueError("worker log maximum lines must be between 1 and 100000")
        self.root = Path(root)
        self.worker_id = _canonical_uuid("worker_id", worker_id)
        self.attempt_id = _canonical_uuid("attempt_id", attempt_id)
        self.maximum_bytes = maximum_bytes
        self.maximum_lines = maximum_lines
        self.redaction_request = redaction_request
        ensure_private_store_directory(self.root, expected_uid=os.geteuid())
        self.artifact_id = str(uuid.uuid4())
        self.path = self.root / f"worker-attempt-{self.artifact_id}.log"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._file_fd = os.open(self.path, flags, 0o600)
        os.fchmod(self._file_fd, 0o600)
        self._read_fd, self._write_fd = os.pipe()
        self._lock = threading.Lock()
        self._tail = bytearray()
        self._received = 0
        self._written = 0
        self._truncated = False
        self._finished = False
        self._stop = threading.Event()
        self._reader = threading.Thread(
            target=self._drain,
            name=f"worker-log-{self.worker_id}",
            daemon=True,
        )
        self._reader.start()

    @property
    def child_output_fd(self) -> int:
        if self._write_fd < 0:
            raise WorkerRunnerError("worker log child descriptor is already closed")
        return self._write_fd

    def child_spawned(self) -> None:
        if self._write_fd >= 0:
            os.close(self._write_fd)
            self._write_fd = -1

    def write_note(self, message: str) -> None:
        normalized = str(message).replace("\x00", "�")
        self._append((normalized.rstrip("\r\n") + "\n").encode("utf-8"))

    def _append(self, payload: bytes) -> None:
        if not payload:
            return
        with self._lock:
            self._received += len(payload)
            self._tail.extend(payload)
            if len(self._tail) > self.maximum_bytes:
                del self._tail[: len(self._tail) - self.maximum_bytes]
            if self._written < self.maximum_bytes:
                selected = payload[: self.maximum_bytes - self._written]
                offset = 0
                while offset < len(selected):
                    offset += os.write(self._file_fd, selected[offset:])
                self._written += len(selected)
            self._truncated = self._received > self.maximum_bytes

    def _drain(self) -> None:
        try:
            while True:
                ready, _, _ = select.select([self._read_fd], [], [], 0.1)
                if ready:
                    chunk = os.read(self._read_fd, 64 * 1024)
                    if not chunk:
                        return
                    self._append(chunk)
                    continue
                if self._stop.is_set():
                    return
        except OSError:
            return
        finally:
            try:
                os.close(self._read_fd)
            except OSError:
                pass

    def finish(self) -> dict[str, str]:
        if self._finished:
            raise WorkerRunnerError("worker log artifact was already finalized")
        self._finished = True
        self.child_spawned()
        self._stop.set()
        self._reader.join(timeout=2.0)
        if self._reader.is_alive():
            try:
                os.close(self._read_fd)
            except OSError:
                pass
            self._reader.join(timeout=1.0)
        if self._reader.is_alive():
            os.close(self._file_fd)
            raise WorkerRunnerError("worker log drain did not stop at process exit")
        with self._lock:
            raw_text = bytes(self._tail).decode("utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
            line_truncated = len(raw_lines) > self.maximum_lines
            retained_lines = raw_lines[-self.maximum_lines :]
            retained_text = "\n".join(retained_lines)
            if retained_lines and raw_text.endswith(("\n", "\r")):
                retained_text += "\n"
            redacted = redact_runtime_value(
                retained_text,
                request=self.redaction_request,
            )
            if not isinstance(redacted, str):
                os.close(self._file_fd)
                raise WorkerRunnerError("worker log redaction returned invalid text")
            payload = redacted.encode("utf-8")
            byte_truncated = len(payload) > self.maximum_bytes
            truncated = self._truncated or line_truncated or byte_truncated
            if truncated:
                retained_after_redaction = redacted.splitlines()
                body_line_limit = max(0, self.maximum_lines - 1)
                retained_after_redaction = (
                    retained_after_redaction[-body_line_limit:]
                    if body_line_limit
                    else []
                )
                retained_body = "\n".join(retained_after_redaction)
                if retained_after_redaction and redacted.endswith(("\n", "\r")):
                    retained_body += "\n"
                payload = retained_body.encode("utf-8")
                allowed = max(0, self.maximum_bytes - len(_ARTIFACT_MARKER))
                payload = _ARTIFACT_MARKER + payload[-allowed:]
                # Do not retain a partial leading UTF-8 sequence.
                payload = payload.decode("utf-8", errors="ignore").encode("utf-8")
                if len(payload) > self.maximum_bytes:
                    payload = payload[-self.maximum_bytes :]
            os.lseek(self._file_fd, 0, os.SEEK_SET)
            os.ftruncate(self._file_fd, 0)
            offset = 0
            while offset < len(payload):
                offset += os.write(self._file_fd, payload[offset:])
            os.fsync(self._file_fd)
            before = os.fstat(self._file_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > self.maximum_bytes
            ):
                os.close(self._file_fd)
                raise WorkerRunnerError("worker log artifact identity is unsafe")
            os.lseek(self._file_fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            line_count = 0
            final_byte = b""
            remaining = int(before.st_size)
            while remaining:
                chunk = os.read(self._file_fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                line_count += chunk.count(b"\n")
                final_byte = chunk[-1:]
                remaining -= len(chunk)
            if before.st_size and final_byte != b"\n":
                line_count += 1
            if remaining or line_count > self.maximum_lines:
                os.close(self._file_fd)
                raise WorkerRunnerError("worker log artifact exceeds its bound")
            after = os.fstat(self._file_fd)
            os.close(self._file_fd)
        current = self.path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        ):
            raise WorkerRunnerError("worker log artifact changed during finalization")
        return {
            "artifact_id": self.artifact_id,
            "path": str(self.path),
            "sha256": digest.hexdigest(),
        }


class WorkerExitJournal:
    """UID-private, atomic replay evidence for one unacknowledged exit."""

    _FIELDS = frozenset(
        {
            "schema_version",
            "worker_id",
            "attempt_id",
            "supervisor_epoch",
            "supervisor_generation",
            "exit_report_id",
            "exit_kind",
            "exit_code",
            "exit_signal",
            "occurred_at_epoch",
            "artifact_id",
            "artifact_sha256",
        }
    )

    def __init__(self, root: Path, *, effective_uid: int | None = None) -> None:
        self.effective_uid = (
            os.geteuid() if effective_uid is None else int(effective_uid)
        )
        if type(self.effective_uid) is not int or self.effective_uid < 0:
            raise ValueError("worker journal UID must be non-negative")
        candidate = Path(root).expanduser()
        ensure_private_store_directory(candidate, expected_uid=self.effective_uid)
        self.root = candidate.resolve(strict=True)

    @staticmethod
    def _name(worker_id: str) -> str:
        worker = _canonical_uuid("worker_id", worker_id)
        return f"worker-pending-exit-{worker}.json"

    def pending_path(self, *, worker_id: str) -> Path:
        return self.root / self._name(worker_id)

    def _open_directory(self) -> int:
        ensure_private_store_directory(self.root, expected_uid=self.effective_uid)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.root, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise WorkerRunnerError("worker reconciliation path is not a directory")
        return descriptor

    def _read_document(self, name: str, *, directory_fd: int) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise WorkerRunnerError(
                "worker reconciliation record is unavailable or unsafe"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or not 1 <= before.st_size <= WORKER_PENDING_EXIT_MAX_BYTES
            ):
                raise WorkerRunnerError(
                    "worker reconciliation record is not a bounded regular file"
                )
            chunks: list[bytes] = []
            remaining = int(before.st_size)
            while remaining:
                chunk = os.read(descriptor, min(remaining, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (
                remaining
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise WorkerRunnerError(
                    "worker reconciliation record changed while it was read"
                )
        finally:
            os.close(descriptor)
        try:
            document = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise WorkerRunnerError(
                "worker reconciliation record is not valid JSON"
            ) from error
        if not isinstance(document, dict) or set(document) != self._FIELDS:
            raise WorkerRunnerError("worker reconciliation record fields are invalid")
        return dict(document)

    def _validate_document(
        self,
        document: Mapping[str, Any],
        *,
        worker_id: str,
        expected_attempt_id: str | None = None,
    ) -> dict[str, Any]:
        if document.get("schema_version") != 1:
            raise WorkerRunnerError(
                "worker reconciliation record schema is unsupported"
            )
        worker = _canonical_uuid("journal.worker_id", document.get("worker_id"))
        if worker != worker_id:
            raise WorkerRunnerError(
                "worker reconciliation record belongs to another worker"
            )
        attempt_id = _canonical_uuid(
            "journal.attempt_id", document.get("attempt_id")
        )
        if expected_attempt_id is not None and attempt_id != expected_attempt_id:
            raise WorkerRunnerError(
                "worker reconciliation filename and attempt identity differ"
            )
        _canonical_uuid(
            "journal.exit_report_id", document.get("exit_report_id")
        )
        _bounded_text(
            "journal.supervisor_epoch", document.get("supervisor_epoch")
        )
        _generation(
            "journal.supervisor_generation",
            document.get("supervisor_generation"),
        )
        exit_kind = document.get("exit_kind")
        exit_code = document.get("exit_code")
        exit_signal = document.get("exit_signal")
        if exit_kind == "exit_code":
            if (
                type(exit_code) is not int
                or not -(2**31) <= exit_code <= 2**31 - 1
                or exit_signal is not None
            ):
                raise WorkerRunnerError(
                    "worker reconciliation exit-code evidence is invalid"
                )
        elif exit_kind == "signal":
            if (
                type(exit_signal) is not int
                or not 1 <= exit_signal <= 255
                or exit_code is not None
            ):
                raise WorkerRunnerError(
                    "worker reconciliation signal evidence is invalid"
                )
        elif exit_kind in {"launch_failure", "supervisor_lost", "unknown"}:
            if exit_code is not None or exit_signal is not None:
                raise WorkerRunnerError(
                    "worker reconciliation typed exit evidence is inconsistent"
                )
        else:
            raise WorkerRunnerError(
                "worker reconciliation exit kind is unsupported"
            )
        occurred = document.get("occurred_at_epoch")
        if (
            type(occurred) not in {int, float}
            or not math.isfinite(float(occurred))
            or not 0 <= float(occurred) <= 2**53
        ):
            raise WorkerRunnerError(
                "worker reconciliation event time is invalid"
            )
        _canonical_uuid("journal.artifact_id", document.get("artifact_id"))
        digest = document.get("artifact_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise WorkerRunnerError(
                "worker reconciliation artifact digest is invalid"
            )
        return dict(document)

    def _verify_artifact(
        self, *, artifact_id: str, artifact_sha256: str
    ) -> dict[str, str]:
        artifact_id = _canonical_uuid("artifact_id", artifact_id)
        name = f"worker-attempt-{artifact_id}.log"
        directory_fd = self._open_directory()
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as error:
                raise WorkerRunnerError(
                    "pending worker log artifact is unavailable or unsafe"
                ) from error
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > WORKER_LOG_MAX_BYTES
            ):
                raise WorkerRunnerError(
                    "pending worker log artifact is not a bounded regular file"
                )
            digest = hashlib.sha256()
            line_count = 0
            final_byte = b""
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                line_count += chunk.count(b"\n")
                final_byte = chunk[-1:]
            if before.st_size and final_byte != b"\n":
                line_count += 1
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or line_count > WORKER_LOG_MAX_LINES
                or digest.hexdigest() != artifact_sha256
            ):
                raise WorkerRunnerError(
                    "pending worker log artifact changed or failed verification"
                )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_fd)
        return {
            "artifact_id": artifact_id,
            "path": str(self.root / name),
            "sha256": artifact_sha256,
        }

    def stage(
        self,
        *,
        worker_id: str,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> dict[str, Any]:
        worker_id = _canonical_uuid("worker_id", worker_id)
        attempt_id = _canonical_uuid("attempt.attempt_id", attempt.get("attempt_id"))
        artifact_id = _canonical_uuid(
            "artifact.artifact_id", artifact.get("artifact_id")
        )
        expected_artifact_path = self.root / f"worker-attempt-{artifact_id}.log"
        if artifact.get("path") != str(expected_artifact_path):
            raise WorkerRunnerError(
                "worker log artifact is outside the private reconciliation root"
            )
        document = self._validate_document(
            {
                "schema_version": 1,
                "worker_id": worker_id,
                "attempt_id": attempt_id,
                "supervisor_epoch": attempt.get("supervisor_epoch"),
                "supervisor_generation": attempt.get("supervisor_generation"),
                "exit_report_id": exit_report_id,
                "exit_kind": exit_kind,
                "exit_code": exit_code,
                "exit_signal": exit_signal,
                "occurred_at_epoch": occurred_at_epoch,
                "artifact_id": artifact_id,
                "artifact_sha256": artifact.get("sha256"),
            },
            worker_id=worker_id,
            expected_attempt_id=attempt_id,
        )
        self._verify_artifact(
            artifact_id=artifact_id,
            artifact_sha256=str(document["artifact_sha256"]),
        )
        payload = canonical_json(document).encode("utf-8")
        if not 1 <= len(payload) <= WORKER_PENDING_EXIT_MAX_BYTES:
            raise WorkerRunnerError("worker reconciliation record exceeds its bound")
        name = self._name(worker_id)
        directory_fd = self._open_directory()
        temporary_name = f".worker-pending-exit-{uuid.uuid4()}.tmp"
        temporary_fd = -1
        try:
            try:
                existing = self._read_document(name, directory_fd=directory_fd)
            except WorkerRunnerError as error:
                if not isinstance(error.__cause__, FileNotFoundError):
                    raise
            else:
                existing = self._validate_document(
                    existing,
                    worker_id=worker_id,
                    expected_attempt_id=attempt_id,
                )
                if canonical_json(existing) != canonical_json(document):
                    raise WorkerRunnerError(
                        "pending worker exit already has different immutable evidence"
                    )
                return document
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            temporary_fd = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(temporary_fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(temporary_fd, payload[offset:])
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            # The native manager admits one runner for this immutable worker.
            # Replace is therefore an atomic publication, not a concurrency
            # arbitration mechanism; an earlier exact record was checked above.
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = ""
            os.fsync(directory_fd)
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            os.close(directory_fd)
        return document

    def pending(self, *, worker_id: str) -> dict[str, Any] | None:
        worker_id = _canonical_uuid("worker_id", worker_id)
        name = self._name(worker_id)
        directory_fd = self._open_directory()
        try:
            try:
                persisted = self._read_document(name, directory_fd=directory_fd)
            except WorkerRunnerError as error:
                if isinstance(error.__cause__, FileNotFoundError):
                    return None
                raise
            document = self._validate_document(
                persisted,
                worker_id=worker_id,
            )
        finally:
            os.close(directory_fd)
        document["log_artifact"] = self._verify_artifact(
            artifact_id=str(document["artifact_id"]),
            artifact_sha256=str(document["artifact_sha256"]),
        )
        return document

    def acknowledge(self, document: Mapping[str, Any]) -> None:
        worker_id = _canonical_uuid("journal.worker_id", document.get("worker_id"))
        attempt_id = _canonical_uuid(
            "journal.attempt_id", document.get("attempt_id")
        )
        name = self._name(worker_id)
        directory_fd = self._open_directory()
        try:
            try:
                persisted = self._read_document(name, directory_fd=directory_fd)
            except WorkerRunnerError as error:
                if isinstance(error.__cause__, FileNotFoundError):
                    return
                raise
            persisted = self._validate_document(
                persisted,
                worker_id=worker_id,
                expected_attempt_id=attempt_id,
            )
            comparable = {key: document[key] for key in self._FIELDS}
            if canonical_json(persisted) != canonical_json(comparable):
                raise WorkerRunnerError(
                    "worker reconciliation acknowledgement changed immutable evidence"
                )
            os.unlink(name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _process_start_time(pid: int) -> str | None:
    if type(pid) is not int or pid <= 1:
        return None
    if sys.platform.startswith("linux"):
        try:
            text = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
        except OSError:
            return None
        _prefix, separator, suffix = text.rpartition(") ")
        fields = suffix.split() if separator else []
        return fields[19] if len(fields) >= 20 else None
    try:
        completed = subprocess.run(
            ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3.0,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return lines[0] if completed.returncode == 0 and len(lines) == 1 else None


def _observe_process_identity(pid: int, expected_start: str) -> str:
    observed = _process_start_time(pid)
    if observed is not None:
        return "alive" if observed == expected_start else "mismatch"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "absent"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"
    return "unknown"


def observe_worker_process_identity(pid: int, expected_start: str) -> str:
    """Classify whether one immutable worker process identity still exists."""

    return _observe_process_identity(pid, expected_start)


def _deterministic_environment(
    stored: Mapping[str, str], *, execution_uid: int
) -> dict[str, str]:
    """Build a useful launch environment without inheriting runner secrets."""

    try:
        account = pwd.getpwuid(execution_uid)
    except KeyError as error:
        raise WorkerCandidateError(
            "candidate.execution_uid has no local account identity"
        ) from error
    username = str(account.pw_name or "")
    home = str(account.pw_dir or "")
    shell = str(account.pw_shell or "/bin/sh")
    if not username or not Path(home).is_absolute() or not Path(shell).is_absolute():
        raise WorkerCandidateError("worker account identity is incomplete")
    fixed_path = (
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        if sys.platform == "darwin"
        else "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
    )
    environment = {
        "HOME": home,
        "USER": username,
        "LOGNAME": username,
        "SHELL": shell,
        "PATH": fixed_path,
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": "/tmp",
    }
    for key in _PROTECTED_IDENTITY_ENVIRONMENT:
        supplied = stored.get(key)
        if supplied is not None and supplied != environment[key]:
            raise WorkerCandidateError(
                f"candidate.environment cannot change verified {key} identity"
            )
    environment.update(stored)
    return environment


def _artifact_with_link(artifact: Mapping[str, str]) -> dict[str, str]:
    result = dict(artifact)
    result["link"] = Path(str(artifact["path"])).as_uri()
    return result


class BrokerWorkerAuthority:
    """Use the host routing profile for worker state.

    The runner sends opaque identities and fencing evidence.  Commands, paths,
    environment, ownership, and restart decisions are returned by the broker;
    local discovery is deliberately absent from this adapter.
    """

    def __init__(
        self,
        *,
        profile: BrokerClientProfile,
        worker_id: str,
        effective_uid: int | None = None,
    ) -> None:
        uid = os.geteuid() if effective_uid is None else int(effective_uid)
        if type(uid) is not int or uid < 0:
            raise WorkerAuthorityBlocked("worker execution UID is invalid")
        self.worker_id = _canonical_uuid("worker_id", worker_id)
        try:
            repository = profile.repository_for_server_id(self.worker_id)
        except BrokerProfileError as error:
            raise WorkerAuthorityBlocked(str(error)) from error
        self.profile = profile
        self.repository: BrokerRepositoryProfile = repository
        self.execution_uid = uid

    @classmethod
    def load(
        cls,
        *,
        worker_id: str,
        effective_uid: int | None = None,
        profile_path: Path | None = None,
    ) -> "BrokerWorkerAuthority":
        """Load the required root-provisioned configuration for one fixed worker."""

        uid = os.geteuid() if effective_uid is None else int(effective_uid)
        try:
            profile = load_broker_profile(
                path=profile_path,
                effective_uid=uid,
                required=True,
            )
        except BrokerProfileError as error:
            raise WorkerAuthorityBlocked(str(error)) from error
        if profile is None:
            raise WorkerAuthorityBlocked(
                "required root-provisioned broker profile is unavailable"
            )
        return cls(profile=profile, worker_id=worker_id, effective_uid=uid)

    @staticmethod
    def _broker_failure(error: BrokerError) -> WorkerRunnerError:
        detail = f"{error.code}: {error.message}"
        if error.code in _TRANSIENT_BROKER_ERRORS:
            return WorkerAuthorityUnavailable(detail)
        return WorkerAuthorityBlocked(detail)

    def _call(
        self,
        operation: BrokerOperation,
        *,
        arguments: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        try:
            returned_id, result = self.profile.worker_call(
                repository=self.repository,
                server_id=self.worker_id,
                operation=operation,
                arguments=arguments,
                operation_id=operation_id,
            )
        except BrokerProfileError as error:
            raise WorkerAuthorityBlocked(str(error)) from error
        except BrokerError as error:
            if (
                operation_id is not None
                and error.operation_id is not None
                and error.operation_id != operation_id
            ):
                raise WorkerAuthorityBlocked(
                    "broker failure referenced another operation identity"
                ) from error
            raise self._broker_failure(error) from error
        except (OSError, TimeoutError) as error:
            raise WorkerAuthorityUnavailable(
                f"coordinator broker is unavailable: {type(error).__name__}"
            ) from error
        except (TypeError, ValueError) as error:
            raise WorkerAuthorityBlocked(
                f"broker worker request contract is invalid: {error}"
            ) from error
        if not isinstance(returned_id, str) or not returned_id:
            raise WorkerAuthorityBlocked("broker omitted the worker operation identity")
        if operation_id is not None and returned_id != operation_id:
            raise WorkerAuthorityBlocked(
                "broker returned another worker operation identity"
            )
        if not isinstance(result, dict):
            raise WorkerAuthorityBlocked("broker returned invalid worker evidence")
        return returned_id, result

    def _policy_snapshot(self) -> tuple[dict[str, Any], dict[str, Any]]:
        _operation_id, result = self._call(
            BrokerOperation.WORKER_POLICY_READ,
            arguments={},
        )
        if result.get("status") != "current" or not isinstance(
            result.get("policy"), Mapping
        ):
            raise WorkerAuthorityBlocked("broker returned invalid worker policy evidence")
        policy = dict(result["policy"])
        if (
            policy.get("server_definition_id") != self.worker_id
            or policy.get("repo_id") != self.repository.repo_id
            or type(policy.get("execution_uid")) is not int
            or policy.get("execution_uid") != self.execution_uid
        ):
            raise WorkerAuthorityBlocked(
                "broker worker policy changed exact repository or execution identity"
            )
        return result, policy

    def _attempt_from_result(
        self,
        result: Mapping[str, Any],
        *,
        states: frozenset[str],
    ) -> dict[str, Any]:
        if not isinstance(result.get("attempt"), Mapping):
            raise WorkerAuthorityBlocked("broker omitted exact worker attempt evidence")
        attempt = dict(result["attempt"])
        _canonical_uuid("attempt.attempt_id", attempt.get("attempt_id"))
        if (
            attempt.get("server_definition_id") != self.worker_id
            or attempt.get("repo_id") != self.repository.repo_id
            or attempt.get("state") not in states
        ):
            raise WorkerAuthorityBlocked(
                "broker worker attempt changed exact target identity or state"
            )
        _bounded_text("attempt.supervisor_epoch", attempt.get("supervisor_epoch"))
        _generation(
            "attempt.supervisor_generation", attempt.get("supervisor_generation")
        )
        return attempt

    def _read_attempt(
        self,
        *,
        attempt_id: str,
        states: frozenset[str],
    ) -> dict[str, Any]:
        attempt_id = _canonical_uuid("attempt_id", attempt_id)
        _operation_id, result = self._call(
            BrokerOperation.WORKER_ATTEMPT_READ,
            arguments={"attempt_id": attempt_id},
        )
        if result.get("status") != "current":
            raise WorkerAuthorityBlocked("broker returned stale worker attempt evidence")
        attempt = self._attempt_from_result(result, states=states)
        if attempt["attempt_id"] != attempt_id:
            raise WorkerAuthorityBlocked("broker returned another worker attempt")
        return attempt

    def _candidate_from_result(self, result: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(result.get("candidate"), Mapping):
            blocker = result.get("launch_blocker")
            if isinstance(blocker, Mapping):
                code = str(blocker.get("code") or "worker_not_launchable")
                message = str(
                    blocker.get("message") or "worker has no launch candidate"
                )
                raise WorkerAuthorityBlocked(f"{code}: {message}")
            raise WorkerAuthorityBlocked(
                "broker omitted both worker launch candidate and blocker"
            )
        candidate = dict(result["candidate"])
        if (
            candidate.get("server_definition_id") != self.worker_id
            or candidate.get("repo_id") != self.repository.repo_id
            or type(candidate.get("execution_uid")) is not int
            or candidate.get("execution_uid") != self.execution_uid
        ):
            raise WorkerAuthorityBlocked(
                "broker launch candidate changed exact repository or execution identity"
            )
        return candidate

    def active_attempt(self, *, worker_id: str) -> Mapping[str, Any] | None:
        if _canonical_uuid("worker_id", worker_id) != self.worker_id:
            raise WorkerAuthorityBlocked("broker authority belongs to another worker")
        _result, policy = self._policy_snapshot()
        attempt_id = policy.get("current_attempt_id")
        if attempt_id is None:
            return None
        attempt = self._read_attempt(
            attempt_id=str(attempt_id),
            states=frozenset({"reserved", "running"}),
        )
        attempt["execution_uid"] = self.execution_uid
        return attempt

    def read_attempt(self, *, worker_id: str, attempt_id: str) -> Mapping[str, Any]:
        if _canonical_uuid("worker_id", worker_id) != self.worker_id:
            raise WorkerAuthorityBlocked("broker authority belongs to another worker")
        return self._read_attempt(
            attempt_id=attempt_id,
            states=frozenset({"reserved", "running", "exited"}),
        )

    def launch_candidate(self, *, worker_id: str) -> Mapping[str, Any]:
        if _canonical_uuid("worker_id", worker_id) != self.worker_id:
            raise WorkerAuthorityBlocked("broker authority belongs to another worker")
        result, _policy = self._policy_snapshot()
        return self._candidate_from_result(result)

    def begin_attempt(
        self, *, candidate: Mapping[str, Any], begin_request_id: str
    ) -> Mapping[str, Any]:
        begin_request_id = _canonical_uuid("begin_request_id", begin_request_id)
        arguments = {
            "supervisor_epoch": candidate["supervisor_epoch"],
            "expected_definition_generation": candidate["definition_generation"],
            "expected_policy_generation": candidate["policy_generation"],
            "expected_supervisor_generation": candidate["supervisor_generation"],
        }
        _returned_id, result = self._call(
            BrokerOperation.WORKER_LAUNCH_TICKET,
            arguments=arguments,
            operation_id=begin_request_id,
        )
        if (
            result.get("status") != "reserved"
            or result.get("operation_id") != begin_request_id
        ):
            raise WorkerAuthorityBlocked(
                "broker returned invalid worker launch-ticket evidence"
            )
        ticket_candidate = self._candidate_from_result(result)
        if fingerprint(dict(candidate)) != fingerprint(ticket_candidate):
            raise WorkerAuthorityBlocked(
                "broker launch candidate changed while reserving the worker"
            )
        attempt = self._attempt_from_result(
            result, states=frozenset({"reserved"})
        )
        if (
            attempt.get("supervisor_epoch") != ticket_candidate.get("supervisor_epoch")
            or attempt.get("supervisor_generation")
            != ticket_candidate.get("supervisor_generation")
        ):
            raise WorkerAuthorityBlocked(
                "broker launch ticket and attempt use different runner fencing tokens"
            )
        return attempt

    def mark_attempt_launched(
        self,
        *,
        candidate: Mapping[str, Any],
        attempt: Mapping[str, Any],
        launch_report_id: str,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
    ) -> Mapping[str, Any]:
        launch_report_id = _canonical_uuid("launch_report_id", launch_report_id)
        arguments = {
            "attempt_id": attempt["attempt_id"],
            "supervisor_epoch": candidate["supervisor_epoch"],
            "supervisor_generation": candidate["supervisor_generation"],
            "pid": pid,
            "process_start_time": process_start_time,
            "process_fingerprint": process_fingerprint,
        }
        try:
            _returned_id, result = self._call(
                BrokerOperation.WORKER_LAUNCHED,
                arguments=arguments,
                operation_id=launch_report_id,
            )
        except WorkerAuthorityBlocked as error:
            cause = error.__cause__
            if isinstance(cause, BrokerError) and cause.code == "worker_launch_fenced":
                fenced = self._read_attempt(
                    attempt_id=str(attempt["attempt_id"]),
                    states=frozenset({"exited"}),
                )
                raise WorkerLaunchFenced(cause.message, fenced) from cause
            raise
        if result.get("operation_id") != launch_report_id:
            raise WorkerAuthorityBlocked(
                "broker returned invalid worker launch-report identity"
            )
        launched = self._attempt_from_result(
            result, states=frozenset({"running"})
        )
        if launched.get("attempt_id") != attempt.get("attempt_id"):
            raise WorkerAuthorityBlocked("broker launched another worker attempt")
        return launched

    def record_attempt_exit(
        self,
        *,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        log_artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> Mapping[str, Any]:
        exit_report_id = _canonical_uuid("exit_report_id", exit_report_id)
        artifact_id = _canonical_uuid(
            "log_artifact.artifact_id", log_artifact.get("artifact_id")
        )
        artifact_sha256 = log_artifact.get("sha256")
        if (
            not isinstance(artifact_sha256, str)
            or len(artifact_sha256) != 64
            or any(character not in "0123456789abcdef" for character in artifact_sha256)
        ):
            raise WorkerAuthorityBlocked("worker log artifact digest is invalid")
        arguments = {
            "attempt_id": attempt["attempt_id"],
            "supervisor_epoch": attempt["supervisor_epoch"],
            "supervisor_generation": attempt["supervisor_generation"],
            "exit_kind": exit_kind,
            "exit_code": exit_code,
            "exit_signal": exit_signal,
            # Paths never cross the untrusted broker client protocol.
            "log_artifact": {
                "artifact_id": artifact_id,
                "sha256": artifact_sha256,
            },
            "occurred_at_epoch": occurred_at_epoch,
        }
        _returned_id, result = self._call(
            BrokerOperation.WORKER_EXIT,
            arguments=arguments,
            operation_id=exit_report_id,
        )
        if (
            result.get("status") != "exited"
            or result.get("operation_id") != exit_report_id
        ):
            raise WorkerAuthorityBlocked("broker returned invalid worker exit evidence")
        exited = self._attempt_from_result(
            result, states=frozenset({"exited"})
        )
        if exited.get("attempt_id") != attempt.get("attempt_id"):
            raise WorkerAuthorityBlocked("broker exited another worker attempt")
        for field, expected_type in (
            ("restart_allowed", bool),
            ("breaker_tripped_now", bool),
            ("crash_count_in_window", int),
        ):
            value = result.get(field)
            if type(value) is not expected_type:
                raise WorkerAuthorityBlocked(
                    f"broker omitted exact {field} worker-exit decision"
                )
            existing = exited.get(field)
            if existing is not None and existing != value:
                raise WorkerAuthorityBlocked(
                    f"broker returned conflicting {field} worker-exit evidence"
                )
            exited[field] = value
        return exited


ProcessFactory = Callable[..., subprocess.Popen[bytes]]


class WorkerRunner:
    """Run one exact worker until authority disallows another attempt."""

    def __init__(
        self,
        *,
        authority: WorkerAuthority,
        artifact_root: Path,
        process_factory: ProcessFactory = subprocess.Popen,
        identity_reader: Callable[[int], str | None] = _process_start_time,
        process_observer: Callable[[int, str], str] = _observe_process_identity,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        restart_delay_seconds: float = WORKER_RESTART_DELAY_SECONDS,
    ) -> None:
        if restart_delay_seconds < 0:
            raise ValueError("worker restart delay must be non-negative")
        self.authority = authority
        self.artifact_root = Path(artifact_root)
        self.process_factory = process_factory
        self.identity_reader = identity_reader
        self.process_observer = process_observer
        self.sleeper = sleeper
        self.clock = clock
        self.restart_delay_seconds = float(restart_delay_seconds)
        self.exit_journal = WorkerExitJournal(self.artifact_root)
        self._signal_received: int | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._signal_lock = threading.Lock()

    def _forward_signal(self, signum: int, _frame: object = None) -> None:
        with self._signal_lock:
            self._signal_received = signum
            process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    def _blocked_result(
        self,
        *,
        worker_id: str,
        classification: str,
        error: str,
        attempts: int,
        artifacts: list[dict[str, str]],
        candidate: LaunchCandidate | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "ok": False,
            "worker_id": worker_id,
            "classification": classification,
            "error": error,
            "attempts": attempts,
            "repository": (
                candidate.repository_context
                if candidate is not None
                else {"root_repo": None, "temporary_repo": None}
            ),
            "log_artifacts": artifacts,
            "restart_allowed": False,
        }

    @staticmethod
    def _validate_attempt(
        attempt: Mapping[str, Any], *, worker_id: str, state: set[str]
    ) -> dict[str, Any]:
        if not isinstance(attempt, Mapping):
            raise WorkerCandidateError("worker attempt evidence must be an object")
        result = dict(attempt)
        _canonical_uuid("attempt.attempt_id", result.get("attempt_id"))
        if _canonical_uuid(
            "attempt.server_definition_id", result.get("server_definition_id")
        ) != worker_id:
            raise WorkerCandidateError("worker attempt belongs to another worker")
        if result.get("state") not in state:
            raise WorkerCandidateError("worker attempt is in an unexpected state")
        _bounded_text("attempt.supervisor_epoch", result.get("supervisor_epoch"))
        _generation(
            "attempt.supervisor_generation", result.get("supervisor_generation")
        )
        return result

    def _persist_exit(
        self,
        *,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> Mapping[str, Any]:
        while True:
            try:
                return self.authority.record_attempt_exit(
                    attempt=attempt,
                    exit_report_id=exit_report_id,
                    exit_kind=exit_kind,
                    exit_code=exit_code,
                    exit_signal=exit_signal,
                    log_artifact=artifact,
                    occurred_at_epoch=occurred_at_epoch,
                )
            except (WorkerAuthorityUnavailable, sqlite3.OperationalError, TimeoutError):
                self.sleeper(max(self.restart_delay_seconds, 0.1))

    @staticmethod
    def _validate_exit_acknowledgement(
        acknowledgement: Mapping[str, Any],
        *,
        worker_id: str,
        attempt_id: str,
        exit_report_id: str,
        allow_authoritative_fence: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(acknowledgement, Mapping):
            raise WorkerRunnerError(
                "authority returned invalid worker exit acknowledgement"
            )
        result = dict(acknowledgement)
        exact_report = result.get("exit_report_id") == exit_report_id
        authoritative_fence = (
            allow_authoritative_fence
            and result.get("exit_kind") == "supervisor_lost"
            and result.get("exit_classification") == "stale_generation"
            and result.get("exit_decision_known") is True
        )
        if (
            result.get("server_definition_id") != worker_id
            or result.get("attempt_id") != attempt_id
            or not (exact_report or authoritative_fence)
            or result.get("state") != "exited"
            or type(result.get("restart_allowed")) is not bool
        ):
            raise WorkerRunnerError(
                "authority did not acknowledge the exact worker exit and restart decision"
            )
        return result

    def _authoritative_fence_acknowledgement(
        self,
        *,
        worker_id: str,
        document: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        """Accept only a manager fence that closed this exact pending attempt.

        A broker restart can stop an old native runner and durably finalize the
        attempt before that runner can replay its private exit journal. The
        journal must not overwrite the manager's immutable fence evidence, but
        it can be acknowledged once the authority proves the exact stale
        attempt and its restart decision.
        """

        try:
            candidate = self.authority.read_attempt(
                worker_id=worker_id,
                attempt_id=str(document["attempt_id"]),
            )
            acknowledged = self._validate_attempt(
                candidate, worker_id=worker_id, state={"exited"}
            )
        except (WorkerAuthorityBlocked, WorkerCandidateError):
            return None
        if (
            acknowledged.get("supervisor_epoch") != document["supervisor_epoch"]
            or acknowledged.get("supervisor_generation")
            != document["supervisor_generation"]
            or acknowledged.get("exit_kind") != "supervisor_lost"
            or acknowledged.get("exit_classification") != "stale_generation"
            or acknowledged.get("exit_decision_known") is not True
            or type(acknowledged.get("restart_allowed")) is not bool
        ):
            return None
        return acknowledged

    def _record_exit_durably(
        self,
        *,
        worker_id: str,
        attempt: Mapping[str, Any],
        exit_report_id: str,
        exit_kind: str,
        exit_code: int | None,
        exit_signal: int | None,
        artifact: Mapping[str, str],
        occurred_at_epoch: float,
    ) -> Mapping[str, Any]:
        document = self.exit_journal.stage(
            worker_id=worker_id,
            attempt=attempt,
            exit_report_id=exit_report_id,
            exit_kind=exit_kind,
            exit_code=exit_code,
            exit_signal=exit_signal,
            artifact=artifact,
            occurred_at_epoch=occurred_at_epoch,
        )
        acknowledgement = self._persist_exit(
            attempt=attempt,
            exit_report_id=exit_report_id,
            exit_kind=exit_kind,
            exit_code=exit_code,
            exit_signal=exit_signal,
            artifact=artifact,
            occurred_at_epoch=occurred_at_epoch,
        )
        result = self._validate_exit_acknowledgement(
            acknowledgement,
            worker_id=worker_id,
            attempt_id=str(attempt["attempt_id"]),
            exit_report_id=exit_report_id,
        )
        self.exit_journal.acknowledge(document)
        return result

    def _replay_pending_exit(
        self,
        *,
        worker_id: str,
        artifacts: list[dict[str, str]],
    ) -> Mapping[str, Any] | None:
        document = self.exit_journal.pending(worker_id=worker_id)
        if document is None:
            return None
        artifact = document.get("log_artifact")
        if not isinstance(artifact, Mapping):
            raise WorkerRunnerError(
                "worker reconciliation record omitted its verified log artifact"
            )
        attempt = {
            "attempt_id": document["attempt_id"],
            "server_definition_id": worker_id,
            "supervisor_epoch": document["supervisor_epoch"],
            "supervisor_generation": document["supervisor_generation"],
        }
        try:
            acknowledgement = self._persist_exit(
                attempt=attempt,
                exit_report_id=str(document["exit_report_id"]),
                exit_kind=str(document["exit_kind"]),
                exit_code=document["exit_code"],
                exit_signal=document["exit_signal"],
                artifact=artifact,
                occurred_at_epoch=float(document["occurred_at_epoch"]),
            )
        except WorkerAuthorityBlocked:
            acknowledgement = self._authoritative_fence_acknowledgement(
                worker_id=worker_id,
                document=document,
            )
            if acknowledgement is None:
                raise
        result = self._validate_exit_acknowledgement(
            acknowledgement,
            worker_id=worker_id,
            attempt_id=str(document["attempt_id"]),
            exit_report_id=str(document["exit_report_id"]),
            allow_authoritative_fence=True,
        )
        self.exit_journal.acknowledge(document)
        artifacts.append(_artifact_with_link(artifact))
        return result

    def _persist_begin(
        self,
        *,
        candidate: Mapping[str, Any],
        begin_request_id: str,
    ) -> Mapping[str, Any]:
        """Retry one idempotent reservation; never abandon an uncertain commit."""

        while True:
            try:
                return self.authority.begin_attempt(
                    candidate=candidate,
                    begin_request_id=begin_request_id,
                )
            except (WorkerAuthorityUnavailable, sqlite3.OperationalError, TimeoutError):
                self.sleeper(max(self.restart_delay_seconds, 0.1))

    def _persist_launch(
        self,
        *,
        candidate: Mapping[str, Any],
        attempt: Mapping[str, Any],
        launch_report_id: str,
        pid: int,
        process_start_time: str,
        process_fingerprint: str,
    ) -> Mapping[str, Any]:
        """Retry one idempotent launch report before observing its exit."""

        while True:
            try:
                return self.authority.mark_attempt_launched(
                    candidate=candidate,
                    attempt=attempt,
                    launch_report_id=launch_report_id,
                    pid=pid,
                    process_start_time=process_start_time,
                    process_fingerprint=process_fingerprint,
                )
            except (WorkerAuthorityUnavailable, sqlite3.OperationalError, TimeoutError):
                self.sleeper(max(self.restart_delay_seconds, 0.1))

    def _recover_absent_attempt(
        self,
        *,
        worker_id: str,
        attempt: Mapping[str, Any],
        artifacts: list[dict[str, str]],
    ) -> Mapping[str, Any] | None:
        state = str(attempt.get("state") or "")
        if state == "reserved":
            return None
        pid = attempt.get("pid")
        started = attempt.get("process_start_time")
        if type(pid) is not int or pid <= 1 or not isinstance(started, str) or not started:
            return None
        observation = self.process_observer(pid, started)
        if observation != "absent":
            return None
        capture = WorkerLogCapture(
            root=self.artifact_root,
            worker_id=worker_id,
            attempt_id=str(attempt["attempt_id"]),
        )
        capture.write_note(
            "DevCoordinator runner recovered an exact prior attempt whose process is observably absent."
        )
        artifact = capture.finish()
        artifacts.append(_artifact_with_link(artifact))
        return self._record_exit_durably(
            worker_id=worker_id,
            attempt=attempt,
            exit_report_id=str(uuid.uuid4()),
            exit_kind="supervisor_lost",
            exit_code=None,
            exit_signal=None,
            artifact=artifact,
            occurred_at_epoch=float(self.clock()),
        )

    def run(self, *, worker_id: str) -> dict[str, Any]:
        worker_id = _canonical_uuid("worker_id", worker_id)
        attempts = 0
        artifacts: list[dict[str, str]] = []
        candidate: LaunchCandidate | None = None
        try:
            replayed = self._replay_pending_exit(
                worker_id=worker_id,
                artifacts=artifacts,
            )
        except (WorkerAuthorityBlocked, WorkerCandidateError, WorkerRunnerError) as error:
            return self._blocked_result(
                worker_id=worker_id,
                classification="worker_reconciliation_invalid",
                error=str(error),
                attempts=attempts,
                artifacts=artifacts,
            )
        if replayed is not None and replayed["restart_allowed"] is False:
            return {
                "schema_version": 1,
                "ok": True,
                "worker_id": worker_id,
                "classification": "worker_stopped",
                "attempts": attempts,
                "repository": {"root_repo": None, "temporary_repo": None},
                "log_artifacts": artifacts,
                "restart_allowed": False,
                "last_attempt": dict(replayed),
            }
        try:
            active_raw = self.authority.active_attempt(worker_id=worker_id)
        except WorkerAuthorityBlocked as error:
            return self._blocked_result(
                worker_id=worker_id,
                classification="worker_not_launchable",
                error=str(error),
                attempts=attempts,
                artifacts=artifacts,
            )
        if active_raw is not None:
            try:
                active = self._validate_attempt(
                    active_raw, worker_id=worker_id, state={"reserved", "running"}
                )
                execution_uid = active.get("execution_uid")
                if type(execution_uid) is not int or execution_uid != os.geteuid():
                    raise WorkerCandidateError(
                        "active worker attempt belongs to another operating-system account"
                    )
                recovered = self._recover_absent_attempt(
                    worker_id=worker_id,
                    attempt=active,
                    artifacts=artifacts,
                )
            except WorkerCandidateError as error:
                return self._blocked_result(
                    worker_id=worker_id,
                    classification="worker_identity_unverifiable",
                    error=str(error),
                    attempts=attempts,
                    artifacts=artifacts,
                )
            if recovered is None:
                return self._blocked_result(
                    worker_id=worker_id,
                    classification="worker_identity_unverifiable",
                    error=(
                        "a prior reserved/running worker attempt cannot be proved absent; "
                        "refusing a duplicate launch"
                    ),
                    attempts=attempts,
                    artifacts=artifacts,
                )
            restart = recovered.get("restart_allowed")
            if type(restart) is not bool or not restart:
                return {
                    "schema_version": 1,
                    "ok": True,
                    "worker_id": worker_id,
                    "classification": "worker_stopped",
                    "attempts": attempts,
                    "repository": {"root_repo": None, "temporary_repo": None},
                    "log_artifacts": artifacts,
                    "restart_allowed": False,
                    "last_attempt": dict(recovered),
                }
        previous_handlers: dict[int, Any] = {}
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self._forward_signal)
        try:
            while self._signal_received is None:
                try:
                    raw_candidate = self.authority.launch_candidate(worker_id=worker_id)
                    candidate = validate_launch_candidate(
                        raw_candidate,
                        worker_id=worker_id,
                        effective_uid=os.geteuid(),
                    )
                except (WorkerAuthorityBlocked, WorkerCandidateError) as error:
                    return self._blocked_result(
                        worker_id=worker_id,
                        classification=(
                            "worker_not_launchable"
                            if isinstance(error, WorkerAuthorityBlocked)
                            else "worker_candidate_invalid"
                        ),
                        error=str(error),
                        attempts=attempts,
                        artifacts=artifacts,
                        candidate=candidate,
                    )
                begin_request_id = str(uuid.uuid4())
                try:
                    raw_attempt = self._persist_begin(
                        candidate=candidate.raw,
                        begin_request_id=begin_request_id,
                    )
                    attempt = self._validate_attempt(
                        raw_attempt, worker_id=worker_id, state={"reserved"}
                    )
                except (WorkerAuthorityBlocked, WorkerCandidateError) as error:
                    return self._blocked_result(
                        worker_id=worker_id,
                        classification="worker_launch_fenced",
                        error=str(error),
                        attempts=attempts,
                        artifacts=artifacts,
                        candidate=candidate,
                    )
                attempts += 1
                capture = WorkerLogCapture(
                    root=self.artifact_root,
                    worker_id=worker_id,
                    attempt_id=str(attempt["attempt_id"]),
                    redaction_request={
                        "options": {
                            "argv": list(candidate.argv),
                            "environment": candidate.environment,
                        }
                    },
                )
                process: subprocess.Popen[bytes] | None = None
                try:
                    process = self.process_factory(
                        list(candidate.argv),
                        cwd=str(candidate.cwd),
                        env=_deterministic_environment(
                            candidate.environment,
                            execution_uid=candidate.execution_uid,
                        ),
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=capture.child_output_fd,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                        close_fds=True,
                    )
                    capture.child_spawned()
                    with self._signal_lock:
                        self._process = process
                        pending_signal = self._signal_received
                    if pending_signal is not None and process.poll() is None:
                        self._forward_signal(pending_signal)
                    started = self.identity_reader(process.pid)
                    if not isinstance(started, str) or not started:
                        raise WorkerRunnerError(
                            "launched worker process identity is unobservable"
                        )
                    process_fingerprint = "sha256:" + fingerprint(
                        {
                            "pid": process.pid,
                            "process_start_time": started,
                            "argv": candidate.argv,
                            "cwd": str(candidate.cwd),
                            "environment": candidate.environment,
                            "definition_fingerprint": candidate.definition_fingerprint,
                        }
                    )
                    try:
                        launched = self._persist_launch(
                            candidate=candidate.raw,
                            attempt=attempt,
                            launch_report_id=str(uuid.uuid4()),
                            pid=process.pid,
                            process_start_time=started,
                            process_fingerprint=process_fingerprint,
                        )
                    except WorkerLaunchFenced as error:
                        self._terminate_process(process)
                        capture.write_note(f"Worker launch fenced: {error.reason}")
                        artifact = capture.finish()
                        artifacts.append(_artifact_with_link(artifact))
                        return {
                            "schema_version": 1,
                            "ok": True,
                            "worker_id": worker_id,
                            "classification": "worker_launch_fenced",
                            "attempts": attempts,
                            "repository": candidate.repository_context,
                            "log_artifacts": artifacts,
                            "restart_allowed": False,
                            "last_attempt": error.attempt,
                        }
                    attempt = self._validate_attempt(
                        launched, worker_id=worker_id, state={"running"}
                    )
                    return_code = process.wait()
                    if self._terminate_process_group_remainder(process.pid):
                        capture.write_note(
                            "DevCoordinator stopped descendant processes left behind after the worker exited."
                        )
                except Exception as error:
                    if process is not None:
                        self._terminate_process(process)
                    capture.write_note(f"Worker launch failed: {type(error).__name__}: {error}")
                    artifact = capture.finish()
                    artifacts.append(_artifact_with_link(artifact))
                    exit_result = self._record_exit_durably(
                        worker_id=worker_id,
                        attempt=attempt,
                        exit_report_id=str(uuid.uuid4()),
                        exit_kind="launch_failure",
                        exit_code=None,
                        exit_signal=None,
                        artifact=artifact,
                        occurred_at_epoch=float(self.clock()),
                    )
                else:
                    artifact = capture.finish()
                    artifacts.append(_artifact_with_link(artifact))
                    exit_result = self._record_exit_durably(
                        worker_id=worker_id,
                        attempt=attempt,
                        exit_report_id=str(uuid.uuid4()),
                        exit_kind="exit_code" if return_code >= 0 else "signal",
                        exit_code=return_code if return_code >= 0 else None,
                        exit_signal=-return_code if return_code < 0 else None,
                        artifact=artifact,
                        occurred_at_epoch=float(self.clock()),
                    )
                finally:
                    with self._signal_lock:
                        self._process = None
                if not isinstance(exit_result, Mapping):
                    return self._blocked_result(
                        worker_id=worker_id,
                        classification="worker_exit_evidence_invalid",
                        error="authority returned invalid worker exit evidence",
                        attempts=attempts,
                        artifacts=artifacts,
                        candidate=candidate,
                    )
                restart_allowed = exit_result.get("restart_allowed")
                if type(restart_allowed) is not bool:
                    return self._blocked_result(
                        worker_id=worker_id,
                        classification="worker_exit_evidence_invalid",
                        error="authority omitted an exact restart decision",
                        attempts=attempts,
                        artifacts=artifacts,
                        candidate=candidate,
                    )
                if not restart_allowed or self._signal_received is not None:
                    return {
                        "schema_version": 1,
                        "ok": True,
                        "worker_id": worker_id,
                        "classification": (
                            "worker_runner_stopped"
                            if self._signal_received is not None
                            else "worker_stopped"
                        ),
                        "attempts": attempts,
                        "repository": candidate.repository_context,
                        "log_artifacts": artifacts,
                        "restart_allowed": False,
                        "last_attempt": dict(exit_result),
                    }
                self.sleeper(self.restart_delay_seconds)
            return {
                "schema_version": 1,
                "ok": True,
                "worker_id": worker_id,
                "classification": "worker_runner_stopped",
                "attempts": attempts,
                "repository": (
                    candidate.repository_context
                    if candidate is not None
                    else {"root_repo": None, "temporary_repo": None}
                ),
                "log_artifacts": artifacts,
                "restart_allowed": False,
            }
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            WorkerRunner._terminate_process_group_remainder(process.pid)
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired as error:
            raise WorkerRunnerError("launched worker process group could not be stopped") from error

    @staticmethod
    def _terminate_process_group_remainder(process_group_id: int) -> bool:
        """Remove descendants left in the runner-created private process group."""

        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return False
        os.killpg(process_group_id, signal.SIGTERM)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group_id, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.02)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return True
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group_id, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.02)
        raise WorkerRunnerError("worker descendant process group could not be stopped")


def worker_runner_cli_result(
    *,
    worker_id: str,
    authority: WorkerAuthority,
    artifact_root: Path,
) -> dict[str, Any]:
    """Execute the fixed ``worker runner --worker-id`` command."""

    return WorkerRunner(
        authority=authority,
        artifact_root=artifact_root,
    ).run(worker_id=worker_id)


def add_worker_cli_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the fixed, JSON-free native-runner command shape."""

    worker = subparsers.add_parser(
        "worker",
        help="internal fixed-identity managed-worker runner",
    )
    actions = worker.add_subparsers(dest="action", required=True)
    runner = actions.add_parser("runner")
    runner.set_defaults(compact_json=True)
    runner.add_argument(
        "--worker-id",
        required=True,
        type=lambda value: _canonical_uuid("worker_id", value),
    )


__all__ = [
    "BrokerWorkerAuthority",
    "DirectWorkerAuthority",
    "LaunchCandidate",
    "WorkerAuthority",
    "WorkerAuthorityBlocked",
    "WorkerAuthorityUnavailable",
    "WorkerCandidateError",
    "WorkerExitJournal",
    "WorkerLogCapture",
    "WorkerRunner",
    "WorkerRunnerError",
    "add_worker_cli_parser",
    "observe_worker_process_identity",
    "validate_launch_candidate",
    "worker_runner_cli_result",
]
