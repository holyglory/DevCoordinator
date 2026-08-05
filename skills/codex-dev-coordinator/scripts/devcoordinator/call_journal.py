"""Bounded structured call journal for the server-wide Coordinator authority.

The journal records request envelopes and outcomes, never raw request/result
documents.  One fixed lock file serializes append and rotation across authority
process replacement, so the retained JSONL set remains valid and bounded even
when old and new same-schema processes briefly overlap.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import errno as errno_module
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Iterable, Mapping
import uuid


CALL_JOURNAL_SCHEMA_VERSION = 1
DEFAULT_CALL_JOURNAL_PATH = Path("/var/log/devcoordinator/calls.jsonl")
DEFAULT_CALL_JOURNAL_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_CALL_JOURNAL_BACKUPS = 4
MAX_CALL_JOURNAL_RECORD_BYTES = 8 * 1024
MAX_CALL_JOURNAL_MESSAGE_CHARS = 1024
MAX_CALL_JOURNAL_PAGE_BYTES = 8 * 1024
DEFAULT_CALL_JOURNAL_PAGE_RECORDS = 5
MAX_CALL_JOURNAL_PAGE_RECORDS = 20
CALL_JOURNAL_PATH_ENV = "DEVCOORDINATOR_CALL_LOG"
CALL_JOURNAL_MAX_BYTES_ENV = "DEVCOORDINATOR_CALL_LOG_MAX_BYTES"
CALL_JOURNAL_BACKUPS_ENV = "DEVCOORDINATOR_CALL_LOG_BACKUPS"

_CORRELATION_ARGUMENTS = frozenset(
    {
        "action",
        "artifact_id",
        "attempt_id",
        "intent",
        "plan_id",
        "repo_id",
        "run_id",
        "snapshot_id",
        "target_name",
    }
)
_CORRELATION_RESULTS = frozenset(
    {
        "artifact_id",
        "attempt_id",
        "classification",
        "conclusion",
        "plan_id",
        "run_id",
        "snapshot_id",
        "state",
    }
)
_SAFE_CORRELATION_VALUE = re.compile(r"[A-Za-z0-9_.:@+\-]{1,256}")
_BEARER_SECRET = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_FIELD = (
    r"(?:(?:[A-Za-z0-9]+[_-])*(?:token|password|passwd|secret|authorization|"
    r"api[_-]?key|credential|private[_-]?key|cookie)"
    r"(?:[_-][A-Za-z0-9]+)*)"
)
_ASSIGNED_SECRET = re.compile(
    rf"(?i)(?P<key>[\"']?{_SECRET_FIELD}[\"']?)"
    r"(?P<spacing>\s*)(?P<separator>[:=])(?P<after>\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}}\]]+)"
)
_SCALAR_CREDENTIALS_SECRET = re.compile(
    r"(?i)(?P<key>[\"']?credentials[\"']?)"
    r"(?P<spacing>\s*)(?P<separator>[:=])(?P<after>\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|"
    r"(?![\[{])[^\s,;}}\]]+)"
)
_SECRET_OPTION = re.compile(
    rf"(?i)(?P<key>--{_SECRET_FIELD})(?P<spacing>\s+)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_URI_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[^\s,:;]+/)*[^\s,:;]*")
_RELATIVE_SOURCE_PATH = re.compile(
    r"(?ix)"
    r"(?<![A-Za-z0-9_:/.-])"
    r"(?:[\"'`])?"
    r"(?:"
    r"(?:\.{1,2}|~)/(?:[^\s,;:\"'`]+/)*[^\s,;:\"'`]+"
    r"|(?:[A-Za-z0-9_.-]+/)*(?:"
    r"\.venv(?:-[A-Za-z0-9_.-]+)?|node_modules|src|source|lib|tests?|fixtures?|"
    r"scripts?|skills?|deploy|configs?|migrations?|packages?|apps?|services?|ui"
    r")/(?:[^\s,;:\"'`]+/)*[^\s,;:\"'`]+"
    r"|(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\."
    r"(?:py|pyi|js|jsx|ts|tsx|mjs|cjs|json|ya?ml|toml|ini|cfg|conf|env|"
    r"cs|csproj|fs|fsproj|vb|sln|java|kt|kts|go|rs|rb|php|swift|c|cc|cpp|"
    r"h|hpp|sh|bash|zsh|sql|proto|graphql|html|css|scss|less|vue|svelte|"
    r"md|rst|txt|csv|xml|lock)"
    r"|(?:pyproject\.toml|uv\.lock|package-lock\.json|package\.json|"
    r"docker-compose(?:\.[A-Za-z0-9_.-]+)?\.ya?ml|Dockerfile|Makefile|"
    r"README(?:\.[A-Za-z0-9_.-]+)?)"
    r")"
    r"(?:[\"'`])?"
)
_BOUNDARY = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_PHASES = frozenset({"received", "completed", "rejected"})
_OUTCOMES = frozenset(
    {"received", "ok", "rejected", "failed", "timeout", "unavailable", "busy"}
)
_DIAGNOSTIC_SUBJECTS = (
    ("immutable Python dependency root", "python_dependency_root"),
    ("immutable Python dependency executable", "python_dependency_executable"),
    ("immutable Python toolchain link", "python_toolchain_link"),
    ("immutable Python toolchain target", "python_toolchain_target"),
    ("immutable Python toolchain root", "python_toolchain_root"),
    ("immutable Node dependency root", "node_dependency_root"),
    ("immutable .NET toolchain root", "dotnet_toolchain_root"),
    ("snapshot", "snapshot_materialization"),
)

_READER_FILTER_KEYS = frozenset(
    {
        "boundary",
        "call_id",
        "operation_id",
        "request_id",
        "operation",
        "project_id",
        "repository_id",
        "run_id",
        "attempt_id",
        "code",
        "peer_uid",
    }
)
_PROJECTED_IDENTIFIER_FIELDS = (
    "record_id",
    "call_id",
    "release_digest",
    "operation",
    "operation_id",
    "request_id",
    "account_id",
    "project_id",
    "repository_id",
    "resource_id",
    "run_id",
    "attempt_id",
    "code",
)
_PROJECTED_INTEGER_FIELDS = (
    "authority_pid",
    "peer_uid",
    "peer_gid",
    "peer_pid",
    "repository_generation",
)


class CallJournalPageError(ValueError):
    """One bounded journal page request cannot be represented safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _release_digest() -> str | None:
    configured = os.environ.get("DEVCOORDINATOR_RELEASE_DIGEST")
    if isinstance(configured, str) and re.fullmatch(r"[0-9a-f]{64}", configured):
        return configured
    try:
        resolved = Path(__file__).resolve(strict=True)
    except OSError:
        return None
    for parent in resolved.parents:
        if (
            parent.parent == Path("/opt/devcoordinator/releases")
            and re.fullmatch(r"[0-9a-f]{64}", parent.name)
        ):
            return parent.name
    return None


def _safe_text(value: object, *, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.replace("\x00", " ").split())
    text = _BEARER_SECRET.sub("Bearer [REDACTED]", text)
    text = _ASSIGNED_SECRET.sub(
        lambda match: (
            f"{match.group('key')}{match.group('spacing')}"
            f"{match.group('separator')}{match.group('after')}[REDACTED]"
        ),
        text,
    )
    text = _SCALAR_CREDENTIALS_SECRET.sub(
        lambda match: (
            f"{match.group('key')}{match.group('spacing')}"
            f"{match.group('separator')}{match.group('after')}[REDACTED]"
        ),
        text,
    )
    text = _SECRET_OPTION.sub(
        lambda match: f"{match.group('key')}{match.group('spacing')}[REDACTED]",
        text,
    )
    text = _URI_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _ABSOLUTE_PATH.sub("[PATH]", text)
    text = _RELATIVE_SOURCE_PATH.sub("[PATH]", text)
    return text[:limit]


def sanitized_bounded_text(value: object, *, limit: int = 512) -> str:
    """Return one public path/credential-redacted diagnostic line."""

    if type(limit) is not int or not 64 <= limit <= MAX_CALL_JOURNAL_MESSAGE_CHARS:
        raise ValueError("sanitized text limit is outside the supported bound")
    text = _safe_text(str(value), limit=limit)
    return text or "unavailable"


def _safe_identifier(value: object) -> str | None:
    if not isinstance(value, str) or _SAFE_CORRELATION_VALUE.fullmatch(value) is None:
        return None
    return value


def _safe_integer(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _correlation_fields(
    value: object, *, allowed: frozenset[str]
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key in sorted(allowed):
        candidate = _safe_identifier(value.get(key))
        if candidate is not None:
            result[key] = candidate
    return result


def call_record(
    *,
    peer_uid: int | None,
    peer_gid: int | None,
    peer_pid: int | None,
    document: object,
    reply: object,
    duration_seconds: float,
    call_id: str | None = None,
    phase: str = "completed",
    boundary: str = "authority",
    transport_code: str | None = None,
    transport_message: str | None = None,
) -> dict[str, Any]:
    """Build one non-secret, bounded record from a request envelope and reply."""

    request = document if isinstance(document, Mapping) else {}
    response = reply if isinstance(reply, Mapping) else {}
    operation_id = _safe_identifier(request.get("operation_id"))
    if operation_id is None:
        operation_id = _safe_identifier(response.get("operation_id"))
    operation = _safe_identifier(request.get("operation"))
    ok = response.get("ok") if type(response.get("ok")) is bool else False
    error = response.get("error") if isinstance(response.get("error"), Mapping) else {}
    result = response.get("result") if isinstance(response.get("result"), Mapping) else {}
    code = _safe_identifier(error.get("code")) or _safe_identifier(transport_code)
    message = _safe_text(error.get("message"), limit=MAX_CALL_JOURNAL_MESSAGE_CHARS)
    if message is None:
        message = _safe_text(transport_message, limit=MAX_CALL_JOURNAL_MESSAGE_CHARS)

    outcome = (
        "received"
        if phase == "received"
        else "ok" if ok else "rejected" if code else "failed"
    )
    record: dict[str, Any] = {
        "schema_version": CALL_JOURNAL_SCHEMA_VERSION,
        "record_id": str(uuid.uuid4()),
        "call_id": _safe_identifier(call_id) or str(uuid.uuid4()),
        "boundary": boundary if _BOUNDARY.fullmatch(boundary) else "unknown",
        "phase": phase if phase in _PHASES else "completed",
        "recorded_at": _utc_now(),
        "release_digest": _release_digest(),
        "duration_ms": round(max(0.0, float(duration_seconds)) * 1000.0, 3),
        "authority_pid": os.getpid(),
        "peer_uid": _safe_integer(peer_uid),
        "peer_gid": _safe_integer(peer_gid),
        "peer_pid": _safe_integer(peer_pid),
        "operation_id": operation_id,
        "operation": operation,
        "account_id": _safe_identifier(request.get("account_id")),
        "project_id": _safe_identifier(request.get("project_id")),
        "repository_generation": _safe_integer(request.get("repository_generation")),
        "resource_id": _safe_identifier(request.get("resource_id")),
        "ok": ok,
        "outcome": outcome,
        "code": code,
        "message": message,
        "request": _correlation_fields(
            request.get("arguments"), allowed=_CORRELATION_ARGUMENTS
        ),
        "result": _correlation_fields(result, allowed=_CORRELATION_RESULTS),
    }
    return record


def diagnostic_for_exception(
    error: BaseException, *, stage: str
) -> dict[str, object]:
    """Return a path-free diagnostic identity for one internal failure."""

    root = error
    seen: set[int] = set()
    while root.__cause__ is not None and id(root) not in seen:
        seen.add(id(root))
        root = root.__cause__
    subject = None
    text = str(error)
    for prefix, candidate in _DIAGNOSTIC_SUBJECTS:
        if prefix in text:
            subject = candidate
            break
    errno_name = None
    errno_value = getattr(root, "errno", None)
    if type(errno_value) is int:
        errno_name = errno_module.errorcode.get(errno_value, f"ERRNO_{errno_value}")
    return {
        "stage": stage if _SAFE_CORRELATION_VALUE.fullmatch(stage) else "unknown",
        "subject": subject,
        "exception_type": type(error).__name__[:128],
        "root_exception_type": type(root).__name__[:128],
        "errno": errno_name,
    }


def event_record(
    *,
    boundary: str,
    phase: str,
    call_id: str,
    operation: str | None = None,
    operation_id: str | None = None,
    request_id: str | None = None,
    peer_uid: int | None = None,
    peer_gid: int | None = None,
    peer_pid: int | None = None,
    duration_seconds: float | None = None,
    outcome: str = "received",
    code: str | None = None,
    message: str | None = None,
    account_id: str | None = None,
    project_id: str | None = None,
    repository_id: str | None = None,
    repository_generation: int | None = None,
    resource_id: str | None = None,
    run_id: str | None = None,
    attempt_id: str | None = None,
    diagnostic: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Build a generic call lifecycle record without accepting raw payloads."""

    safe_diagnostic: dict[str, object] = {}
    if isinstance(diagnostic, Mapping):
        for key in (
            "stage",
            "subject",
            "exception_type",
            "root_exception_type",
            "errno",
        ):
            value = _safe_identifier(diagnostic.get(key))
            if value is not None:
                safe_diagnostic[key] = value
    return {
        "schema_version": CALL_JOURNAL_SCHEMA_VERSION,
        "record_id": str(uuid.uuid4()),
        "call_id": _safe_identifier(call_id) or str(uuid.uuid4()),
        "boundary": boundary if _BOUNDARY.fullmatch(boundary) else "unknown",
        "phase": phase if phase in _PHASES else "completed",
        "recorded_at": _utc_now(),
        "release_digest": _release_digest(),
        "duration_ms": (
            None
            if duration_seconds is None
            else round(max(0.0, float(duration_seconds)) * 1000.0, 3)
        ),
        "authority_pid": os.getpid(),
        "peer_uid": _safe_integer(peer_uid),
        "peer_gid": _safe_integer(peer_gid),
        "peer_pid": _safe_integer(peer_pid),
        "operation": _safe_identifier(operation),
        "operation_id": _safe_identifier(operation_id),
        "request_id": _safe_identifier(request_id),
        "account_id": _safe_identifier(account_id),
        "project_id": _safe_identifier(project_id),
        "repository_id": _safe_identifier(repository_id),
        "repository_generation": _safe_integer(repository_generation),
        "resource_id": _safe_identifier(resource_id),
        "run_id": _safe_identifier(run_id),
        "attempt_id": _safe_identifier(attempt_id),
        "outcome": outcome if outcome in _OUTCOMES else "failed",
        "code": _safe_identifier(code),
        "message": _safe_text(message, limit=MAX_CALL_JOURNAL_MESSAGE_CHARS),
        "diagnostic": safe_diagnostic,
    }


class RollingCallJournal:
    """Append JSONL records while enforcing one fixed retained-size ceiling."""

    def __init__(
        self,
        path: Path = DEFAULT_CALL_JOURNAL_PATH,
        *,
        max_bytes: int = DEFAULT_CALL_JOURNAL_MAX_BYTES,
        backups: int = DEFAULT_CALL_JOURNAL_BACKUPS,
        file_mode: int = 0o666,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("call journal path must be absolute")
        if type(max_bytes) is not int or max_bytes < MAX_CALL_JOURNAL_RECORD_BYTES:
            raise ValueError("call journal max_bytes is too small")
        if type(backups) is not int or not 0 <= backups <= 32:
            raise ValueError("call journal backups must be from 0 through 32")
        if type(file_mode) is not int or not 0 <= file_mode <= 0o777:
            raise ValueError("call journal file_mode is invalid")
        self.max_bytes = max_bytes
        self.backups = backups
        self.file_mode = file_mode
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._omitted_records = 0
        self._lock_identity: tuple[int, int] | None = None

    @property
    def retained_byte_ceiling(self) -> int:
        return self.max_bytes * (self.backups + 1)

    def append(self, record: Mapping[str, object]) -> None:
        line = self._encoded_line(record)
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            lock_descriptor, lock_status = self._open_verified_regular(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
                self.file_mode,
            )
            try:
                lock_identity = self._identity(lock_status)
                if (
                    self._lock_identity is not None
                    and lock_identity != self._lock_identity
                ):
                    raise OSError(
                        errno_module.ESTALE,
                        "call journal lock identity changed",
                    )
                self._lock_identity = lock_identity
                os.fchmod(lock_descriptor, self.file_mode)
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
                self._verify_descriptor_identity(
                    lock_descriptor,
                    self.lock_path,
                    expected=lock_status,
                )
                self._rotate_if_needed(len(line))
                descriptor, descriptor_status = self._open_verified_regular(
                    self.path,
                    os.O_WRONLY
                    | os.O_APPEND
                    | os.O_CREAT
                    | getattr(os, "O_CLOEXEC", 0),
                    self.file_mode,
                )
                try:
                    self._verify_descriptor_identity(
                        descriptor,
                        self.path,
                        expected=descriptor_status,
                    )
                    os.fchmod(descriptor, self.file_mode)
                    view = memoryview(line)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("call journal write made no progress")
                        view = view[written:]
                finally:
                    os.close(descriptor)
            finally:
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(lock_descriptor)

    def record(self, record: Mapping[str, object]) -> bool:
        """Best-effort append; observability must never fail a Coordinator call."""

        with self._state_lock:
            gap = self._omitted_records
            self._omitted_records = 0
        gap_written = False
        try:
            if gap:
                self.append(
                    event_record(
                        boundary="call_journal",
                        phase="completed",
                        call_id=str(uuid.uuid4()),
                        operation="logging.recovered",
                        outcome="failed",
                        code="logging_gap",
                        message=f"{gap} bounded call records could not be written",
                    )
                )
                gap_written = True
            self.append(record)
            return True
        except (OSError, ValueError, TypeError):
            with self._state_lock:
                self._omitted_records += 1 if gap_written else gap + 1
            return False

    def _encoded_line(self, record: Mapping[str, object]) -> bytes:
        normalized = dict(record)
        normalized["message"] = _safe_text(
            normalized.get("message"),
            limit=MAX_CALL_JOURNAL_MESSAGE_CHARS,
        )
        encoded = (
            json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) <= MAX_CALL_JOURNAL_RECORD_BYTES:
            return encoded
        reduced = dict(normalized)
        reduced["message"] = "call record exceeded the bounded journal schema"
        reduced["request"] = {}
        reduced["result"] = {}
        encoded = (
            json.dumps(reduced, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_CALL_JOURNAL_RECORD_BYTES:
            raise ValueError("call journal record exceeds its fixed maximum")
        return encoded

    @staticmethod
    def _identity(status: os.stat_result) -> tuple[int, int]:
        return (status.st_dev, status.st_ino)

    @staticmethod
    def _validate_regular_status(
        status: os.stat_result,
        *,
        description: str,
    ) -> None:
        if not stat.S_ISREG(status.st_mode):
            raise OSError(
                errno_module.EINVAL,
                f"{description} is not a regular file",
            )
        if status.st_nlink != 1:
            raise OSError(
                errno_module.EMLINK,
                f"{description} has an unsafe link count",
            )

    def _regular_path_status(
        self,
        path: Path,
        *,
        missing_ok: bool = False,
    ) -> os.stat_result | None:
        try:
            status = path.lstat()
        except FileNotFoundError:
            if missing_ok:
                return None
            raise
        self._validate_regular_status(status, description="call journal target")
        return status

    def _verify_descriptor_identity(
        self,
        descriptor: int,
        path: Path,
        *,
        expected: os.stat_result | None = None,
    ) -> os.stat_result:
        descriptor_status = os.fstat(descriptor)
        self._validate_regular_status(
            descriptor_status,
            description="call journal descriptor",
        )
        if expected is not None and self._identity(descriptor_status) != self._identity(
            expected
        ):
            raise OSError(
                errno_module.ESTALE,
                "call journal target changed before descriptor verification",
            )
        path_status = self._regular_path_status(path)
        assert path_status is not None
        if self._identity(descriptor_status) != self._identity(path_status):
            raise OSError(
                errno_module.ESTALE,
                "call journal target changed during descriptor verification",
            )
        return descriptor_status

    def _open_verified_regular(
        self,
        path: Path,
        flags: int,
        mode: int,
    ) -> tuple[int, os.stat_result]:
        before = self._regular_path_status(path, missing_ok=True)
        secure_flags = (
            flags
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, secure_flags, mode)
        try:
            status = self._verify_descriptor_identity(
                descriptor,
                path,
                expected=before,
            )
            return descriptor, status
        except BaseException:
            os.close(descriptor)
            raise

    def _numbered_rotations(self) -> dict[int, tuple[Path, os.stat_result]]:
        pattern = re.compile(rf"{re.escape(self.path.name)}\.([0-9]+)\Z")
        result: dict[int, tuple[Path, os.stat_result]] = {}
        try:
            candidates = tuple(self.path.parent.iterdir())
        except FileNotFoundError:
            return result
        for candidate in candidates:
            match = pattern.fullmatch(candidate.name)
            if match is None:
                continue
            status = self._regular_path_status(candidate)
            assert status is not None
            raw_index = match.group(1)
            index = int(raw_index)
            if index < 1 or raw_index != str(index):
                self._unlink_verified(candidate, status)
                continue
            result[index] = (candidate, status)
        return result

    def _unlink_verified(self, path: Path, expected: os.stat_result) -> None:
        current = self._regular_path_status(path)
        assert current is not None
        if self._identity(current) != self._identity(expected):
            raise OSError(
                errno_module.ESTALE,
                "call journal target changed before removal",
            )
        path.unlink()

    def _replace_verified(
        self,
        source: Path,
        destination: Path,
        expected: os.stat_result,
    ) -> os.stat_result:
        current = self._regular_path_status(source)
        assert current is not None
        if self._identity(current) != self._identity(expected):
            raise OSError(
                errno_module.ESTALE,
                "call journal rotation changed before replacement",
            )
        destination_status = self._regular_path_status(destination, missing_ok=True)
        if destination_status is not None:
            self._unlink_verified(destination, destination_status)
        os.replace(source, destination)
        replaced = self._regular_path_status(destination)
        assert replaced is not None
        if self._identity(replaced) != self._identity(expected):
            raise OSError(
                errno_module.ESTALE,
                "call journal rotation identity changed during replacement",
            )
        return replaced

    def _prune_rotations(self) -> dict[int, tuple[Path, os.stat_result]]:
        rotations = self._numbered_rotations()
        for index in sorted(rotations, reverse=True):
            path, status = rotations[index]
            if index > self.backups or status.st_size > self.max_bytes:
                self._unlink_verified(path, status)
                rotations.pop(index)
        return rotations

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        rotations = self._prune_rotations()
        current_status = self._regular_path_status(self.path, missing_ok=True)
        current_bytes = 0 if current_status is None else current_status.st_size
        if current_bytes + incoming_bytes <= self.max_bytes:
            return
        if current_status is None:
            return
        if self.backups == 0 or current_bytes > self.max_bytes:
            self._unlink_verified(self.path, current_status)
            return
        oldest = rotations.pop(self.backups, None)
        if oldest is not None:
            self._unlink_verified(*oldest)
        for index in range(self.backups - 1, 0, -1):
            source = rotations.pop(index, None)
            if source is not None:
                source_path, source_status = source
                self._replace_verified(
                    source_path,
                    self._backup_path(index + 1),
                    source_status,
                )
        self._replace_verified(self.path, self._backup_path(1), current_status)

    def _backup_path(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def retained_paths(self) -> tuple[Path, ...]:
        result: list[Path] = []
        for path in (
            *(self._backup_path(index) for index in range(self.backups, 0, -1)),
            self.path,
        ):
            if self._regular_path_status(path, missing_ok=True) is not None:
                result.append(path)
        return tuple(result)


def read_call_snapshot(
    path: Path = DEFAULT_CALL_JOURNAL_PATH,
    *,
    backups: int = DEFAULT_CALL_JOURNAL_BACKUPS,
) -> tuple[list[dict[str, Any]], list[dict[str, object]]]:
    """Read one rotation-consistent record and retained-file snapshot."""

    journal = RollingCallJournal(path, backups=backups)
    if not journal.path.parent.is_dir():
        return [], []
    try:
        lock_descriptor, lock_status = journal._open_verified_regular(
            journal.lock_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            journal.file_mode,
        )
    except FileNotFoundError:
        # A reader never bootstraps journal state.  No lock means there is no
        # rotation-consistent retained set that can be read safely.
        return [], []
    records: list[dict[str, Any]] = []
    files: list[dict[str, object]] = []
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_SH)
        journal._verify_descriptor_identity(
            lock_descriptor,
            journal.lock_path,
            expected=lock_status,
        )
        retained_paths = journal.retained_paths()
        for retained in retained_paths:
            descriptor, retained_status = journal._open_verified_regular(
                retained,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                journal.file_mode,
            )
            files.append({"path": str(retained), "bytes": retained_status.st_size})
            try:
                handle = os.fdopen(
                    descriptor,
                    "r",
                    encoding="utf-8",
                    closefd=True,
                )
            except BaseException:
                os.close(descriptor)
                raise
            with handle:
                for line in handle:
                    try:
                        value = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    if (
                        isinstance(value, dict)
                        and value.get("schema_version")
                        == CALL_JOURNAL_SCHEMA_VERSION
                    ):
                        records.append(value)
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
    return records, files


def _reader_record_value(record: Mapping[str, object], key: str) -> object:
    direct = record.get(key)
    if direct is not None:
        return direct
    aliases = {"repository_id": ("repo_id",)}
    for section in ("request", "result"):
        nested = record.get(section)
        if not isinstance(nested, Mapping):
            continue
        for candidate in (key, *aliases.get(key, ())):
            if nested.get(candidate) is not None:
                return nested[candidate]
    return None


def _reader_failure(record: Mapping[str, object]) -> bool:
    outcome = record.get("outcome")
    if outcome in {"rejected", "failed", "timeout", "unavailable", "busy"}:
        return True
    if outcome in {"received", "ok"}:
        return False
    return record.get("ok") is False


def _reader_matches(
    record: Mapping[str, object],
    *,
    filters: Mapping[str, object],
    failures_only: bool,
) -> bool:
    if failures_only and not _reader_failure(record):
        return False
    return all(
        expected is None or _reader_record_value(record, key) == expected
        for key, expected in filters.items()
    )


def _project_reader_record(
    record: Mapping[str, object],
    *,
    message_limit: int,
    minimal: bool,
) -> dict[str, object]:
    """Return a path-free whitelist projection of one retained call record."""

    phase = record.get("phase")
    if phase not in _PHASES:
        phase = "completed"
    outcome = record.get("outcome")
    if outcome not in _OUTCOMES:
        outcome = (
            "ok"
            if record.get("ok") is True
            else "rejected"
            if record.get("code") is not None
            else "failed"
        )
    boundary = record.get("boundary")
    if not isinstance(boundary, str) or _BOUNDARY.fullmatch(boundary) is None:
        boundary = "unknown"
    projected: dict[str, object] = {
        "schema_version": CALL_JOURNAL_SCHEMA_VERSION,
        "boundary": boundary,
        "phase": phase,
        "outcome": outcome,
    }
    for field in _PROJECTED_IDENTIFIER_FIELDS:
        value = _safe_identifier(record.get(field))
        if value is not None:
            projected[field] = value
    recorded_at = _safe_text(record.get("recorded_at"), limit=64)
    if recorded_at is not None:
        projected["recorded_at"] = recorded_at
    duration = record.get("duration_ms")
    if (
        not isinstance(duration, bool)
        and isinstance(duration, (int, float))
        and math.isfinite(float(duration))
        and float(duration) >= 0
    ):
        projected["duration_ms"] = duration
    for field in _PROJECTED_INTEGER_FIELDS:
        value = _safe_integer(record.get(field))
        if value is not None:
            projected[field] = value
    if type(record.get("ok")) is bool:
        projected["ok"] = record["ok"]
    diagnostic = record.get("diagnostic")
    if isinstance(diagnostic, Mapping):
        safe_diagnostic = {
            key: value
            for key in (
                "stage",
                "subject",
                "exception_type",
                "root_exception_type",
                "errno",
            )
            if (value := _safe_identifier(diagnostic.get(key))) is not None
        }
        if safe_diagnostic:
            projected["diagnostic"] = safe_diagnostic
    if not minimal:
        message = _safe_text(record.get("message"), limit=message_limit)
        if message is not None:
            projected["message"] = message
        for section, allowed in (
            ("request", _CORRELATION_ARGUMENTS),
            ("result", _CORRELATION_RESULTS),
        ):
            correlation = _correlation_fields(record.get(section), allowed=allowed)
            if correlation:
                projected[section] = correlation
    return projected


def _reader_message_exceeds(record: Mapping[str, object], limit: int) -> bool:
    sanitized = _safe_text(record.get("message"), limit=limit + 1)
    return sanitized is not None and len(sanitized) > limit


def _correlated_reader_indexes(
    records: list[dict[str, Any]],
    *,
    direct_indexes: list[int],
    prefer_pairs: bool,
) -> list[int]:
    if not prefer_pairs:
        return direct_indexes
    call_ids = {
        value
        for index in direct_indexes
        if (value := _safe_identifier(records[index].get("call_id"))) is not None
    }
    expanded = set(direct_indexes)
    for index, record in enumerate(records):
        if (
            _safe_identifier(record.get("call_id")) in call_ids
            and record.get("phase") in _PHASES
        ):
            expanded.add(index)
    return sorted(expanded)


def _reader_page_document(
    *,
    projected: list[dict[str, object]],
    matched_count: int,
    correlated_record_count: int,
    eligible_count: int,
    retained_byte_count: int,
    retained_file_count: int,
    before: str | None,
    prefer_pairs: bool,
    fields_truncated: bool,
) -> dict[str, object]:
    returned_count = len(projected)
    omitted_count = max(0, eligible_count - returned_count)
    next_cursor = None
    if omitted_count and projected:
        candidate = projected[0].get("record_id")
        if isinstance(candidate, str):
            next_cursor = candidate
    return {
        "schema_version": 1,
        "ok": True,
        "classification": "coordinator_call_journal_page",
        "retained_byte_count": retained_byte_count,
        "retained_file_count": retained_file_count,
        "matched_count": matched_count,
        "correlated_record_count": correlated_record_count,
        "eligible_count": eligible_count,
        "returned_count": returned_count,
        "omitted_count": omitted_count,
        "cursor": before,
        "next_cursor": next_cursor,
        "pairing": "exact_call_lifecycle" if prefer_pairs else "newest_records",
        "fields_truncated": fields_truncated,
        "records": projected,
    }


def _encode_reader_page(
    document: Mapping[str, object], *, output_format: str
) -> bytes:
    if output_format == "json":
        return (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    if output_format != "jsonl":
        raise CallJournalPageError("call journal format must be json or jsonl")
    metadata = {key: value for key, value in document.items() if key != "records"}
    lines = [
        json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    ]
    lines.extend(
        json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        for record in document.get("records", ())
        if isinstance(record, Mapping)
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def bounded_call_record_page(
    records: Iterable[dict[str, Any]],
    *,
    filters: Mapping[str, object] | None = None,
    failures_only: bool = False,
    limit: int = DEFAULT_CALL_JOURNAL_PAGE_RECORDS,
    before: str | None = None,
    retained_byte_count: int = 0,
    retained_file_count: int = 0,
    output_format: str = "json",
    maximum_bytes: int = MAX_CALL_JOURNAL_PAGE_BYTES,
) -> bytes:
    """Render one deterministic, sanitized, aggregate-bounded reader page.

    The returned bytes include exactly one trailing newline. Default output is
    path-free and contains only whitelisted call-envelope evidence. When an
    operation or run filter is present, received/terminal records sharing the
    exact call ID are paged together when the caller's record budget permits.
    """

    if type(limit) is not int or not 1 <= limit <= MAX_CALL_JOURNAL_PAGE_RECORDS:
        raise CallJournalPageError(
            f"call journal limit must be from 1 through {MAX_CALL_JOURNAL_PAGE_RECORDS}"
        )
    if (
        type(maximum_bytes) is not int
        or not 512 <= maximum_bytes <= MAX_CALL_JOURNAL_PAGE_BYTES
    ):
        raise CallJournalPageError("call journal output byte bound is invalid")
    if type(retained_byte_count) is not int or retained_byte_count < 0:
        raise CallJournalPageError("retained byte count is invalid")
    if type(retained_file_count) is not int or retained_file_count < 0:
        raise CallJournalPageError("retained file count is invalid")
    query = dict(filters or {})
    unknown = sorted(set(query) - _READER_FILTER_KEYS)
    if unknown:
        raise CallJournalPageError(
            "unsupported call journal filter(s): " + ", ".join(unknown)
        )
    rows = [dict(record) for record in records if isinstance(record, Mapping)]
    direct_indexes = [
        index
        for index, record in enumerate(rows)
        if _reader_matches(
            record,
            filters=query,
            failures_only=bool(failures_only),
        )
    ]
    prefer_pairs = query.get("operation_id") is not None or query.get("run_id") is not None
    indexes = _correlated_reader_indexes(
        rows,
        direct_indexes=direct_indexes,
        prefer_pairs=prefer_pairs,
    )
    matched_count = len(direct_indexes)
    correlated_record_count = len(indexes)
    if before is not None:
        if _safe_identifier(before) is None:
            raise CallJournalPageError("call journal cursor is invalid")
        cursor_positions = [
            position
            for position, index in enumerate(indexes)
            if _safe_identifier(rows[index].get("record_id")) == before
        ]
        if len(cursor_positions) != 1:
            raise CallJournalPageError(
                "call journal cursor is absent, duplicated, or no longer retained"
            )
        indexes = indexes[: cursor_positions[0]]
    eligible_count = len(indexes)
    # Keep a contiguous suffix of the filtered/correlated sequence. Correlated
    # received records are therefore carried with their terminal records when
    # they fit, while the cursor can page every omitted record without gaps or
    # query-specific hidden state.
    selected_indexes = indexes[-limit:]

    strategies = (
        (384, False),
        (192, False),
        (96, False),
        (96, True),
        (0, True),
    )
    while selected_indexes:
        for strategy_index, (message_limit, minimal) in enumerate(strategies):
            projected = [
                _project_reader_record(
                    rows[index], message_limit=message_limit, minimal=minimal
                )
                for index in selected_indexes
            ]
            document = _reader_page_document(
                projected=projected,
                matched_count=matched_count,
                correlated_record_count=correlated_record_count,
                eligible_count=eligible_count,
                retained_byte_count=retained_byte_count,
                retained_file_count=retained_file_count,
                before=before,
                prefer_pairs=prefer_pairs,
                fields_truncated=(
                    strategy_index > 0
                    or any(
                        _reader_message_exceeds(rows[index], message_limit)
                        for index in selected_indexes
                    )
                ),
            )
            encoded = _encode_reader_page(document, output_format=output_format)
            if len(encoded) <= maximum_bytes:
                return encoded
        # Preserve the newest diagnostic evidence and disclose the exact
        # number of older matching records that the byte budget omitted.
        selected_indexes = selected_indexes[1:]

    document = _reader_page_document(
        projected=[],
        matched_count=matched_count,
        correlated_record_count=correlated_record_count,
        eligible_count=eligible_count,
        retained_byte_count=retained_byte_count,
        retained_file_count=retained_file_count,
        before=before,
        prefer_pairs=prefer_pairs,
        fields_truncated=False,
    )
    encoded = _encode_reader_page(document, output_format=output_format)
    if len(encoded) > maximum_bytes:
        raise CallJournalPageError(
            "call journal page metadata exceeds its fixed output byte bound"
        )
    return encoded


def read_call_records(
    path: Path = DEFAULT_CALL_JOURNAL_PATH,
    *,
    backups: int = DEFAULT_CALL_JOURNAL_BACKUPS,
) -> Iterable[dict[str, Any]]:
    """Yield one consistent retained snapshot from oldest to newest."""

    records, _files = read_call_snapshot(path, backups=backups)
    yield from records


def monotonic_started() -> float:
    return time.monotonic()


def configured_call_journal(
    environment: Mapping[str, str] | None = None,
) -> RollingCallJournal | None:
    """Build the shared journal only when an installed service configures it."""

    values = os.environ if environment is None else environment
    raw_path = values.get(CALL_JOURNAL_PATH_ENV)
    if not raw_path:
        return None
    try:
        max_bytes = int(
            values.get(
                CALL_JOURNAL_MAX_BYTES_ENV,
                str(DEFAULT_CALL_JOURNAL_MAX_BYTES),
            )
        )
        backups = int(
            values.get(CALL_JOURNAL_BACKUPS_ENV, str(DEFAULT_CALL_JOURNAL_BACKUPS))
        )
    except ValueError as error:
        raise ValueError("configured call journal bounds are invalid") from error
    return RollingCallJournal(
        Path(raw_path),
        max_bytes=max_bytes,
        backups=backups,
    )
