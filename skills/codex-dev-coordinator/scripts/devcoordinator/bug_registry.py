"""Out-of-band, open-only Coordinator bug registry.

The registry is deliberately independent of repository discovery, broker
profiles, authority/API sockets, and testd.  It stores one bounded JSON file
per open bug in a shared local directory.  Presence means open; closing a bug
physically removes the file, so blue/green processes on this single-developer
host share one synchronization truth without a database migration.

The local trust decision is recorded in project-root
``security-assumptions.md``: Unix accounts on this host belong to one trusted
developer, non-secret coordination metadata may be shared, and UID/GID/mode
metadata is not an authorization boundary.  Shape, size, atomicity, and secret
redaction remain correctness boundaries.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
import uuid


BUG_REGISTRY_SCHEMA_VERSION = 1
BUG_REGISTRY_DIR_ENV = "DEVCOORDINATOR_BUG_DIR"
DEFAULT_BUG_REGISTRY_DIR = Path("/var/lib/devcoordinator-bugs/open")
MAX_BUG_FILE_BYTES = 16 * 1024
MAX_RESULT_BYTES = 8 * 1024
MAX_OPEN_BUGS = 2048
MAX_LIST_LIMIT = 20
MAX_STEPS = 8
MAX_ARGV_ITEMS = 64

_BUG_ID = re.compile(r"bug-[0-9a-f]{32}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+/-]{0,255}")
_RELEASE_DIGEST = re.compile(r"[0-9a-f]{64}")
_POTENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?P<key>\"[A-Za-z_][A-Za-z0-9_.-]{0,127}\"|"
    r"'[A-Za-z_][A-Za-z0-9_.-]{0,127}'|"
    r"[A-Za-z_][A-Za-z0-9_.-]{0,127})"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_AUTHORIZATION = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*"
    r"(?:(?:basic|digest|token)\s+)?[^\s,;]+"
)
_URI_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@")


class BugRegistryError(ValueError):
    """One bug-registry request cannot be represented safely."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        classification: str = "invalid_request",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.classification = classification
        self.phase = "bug_registry"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_secret_name(value: str) -> bool:
    # Match credential *field names*, including common environment and JSON
    # forms, without treating operational counters such as ``token_count`` as
    # credentials. CamelCase is normalized for clientSecret/apiKey inputs.
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value).lower()
    parts = tuple(part for part in re.split(r"[._-]+", normalized) if part)
    if not parts:
        return False
    if parts[-1] in {
        "token",
        "password",
        "passwd",
        "authorization",
        "credential",
        "credentials",
        "cookie",
    }:
        return True
    if "secret" in parts:
        return True
    if parts[0] in {"password", "passwd", "credential", "credentials", "cookie"}:
        return True
    return any(
        pair in {("api", "key"), ("private", "key"), ("access", "key")}
        for pair in zip(parts, parts[1:])
    )


def _redact_text(value: str) -> str:
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _AUTHORIZATION.sub("authorization=[REDACTED]", value)

    def replace_assignment(match: re.Match[str]) -> str:
        raw_key = match.group("key")
        key = raw_key[1:-1] if raw_key[:1] in {"\"", "'"} else raw_key
        if not _is_secret_name(key):
            return match.group(0)
        return f"{raw_key}{match.group('separator')}[REDACTED]"

    value = _POTENTIAL_ASSIGNMENT.sub(replace_assignment, value)
    return _URI_USERINFO.sub(r"\1[REDACTED]@", value)


def _text(
    value: object,
    field: str,
    *,
    maximum_bytes: int,
    required: bool = False,
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise BugRegistryError("bug_contract_invalid", f"{field} must be text")
    normalized = " ".join(value.split())
    if not normalized and required:
        raise BugRegistryError(
            "bug_contract_invalid", f"{field} must not be empty"
        )
    if len(normalized.encode("utf-8")) > maximum_bytes:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"{field} exceeds its {maximum_bytes}-byte bound",
        )
    return _redact_text(normalized)


def _name(value: object, field: str, *, required: bool = False) -> str | None:
    text = _text(value, field, maximum_bytes=256, required=required)
    if text is None:
        return None
    if _SAFE_NAME.fullmatch(text) is None:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"{field} must be one bounded identifier",
        )
    return text


def _identifier(value: object, field: str) -> str | None:
    return _name(value, field)


def _structured_argv(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise BugRegistryError(
            "bug_contract_invalid", f"{field} must be a structured argument array"
        )
    if len(value) > MAX_ARGV_ITEMS:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"{field} exceeds {MAX_ARGV_ITEMS} arguments",
        )
    result: list[str] = []
    redact_next = False
    for index, raw in enumerate(value):
        argument = _text(
            raw,
            f"{field}[{index}]",
            maximum_bytes=256,
            required=True,
        )
        assert argument is not None
        if redact_next:
            argument = "[REDACTED]"
            redact_next = False
        else:
            option, separator, _assigned = argument.partition("=")
            option_name = option.lstrip("-")
            if _is_secret_name(option_name):
                if separator:
                    argument = option + "=[REDACTED]"
                else:
                    redact_next = True
        result.append(argument)
    return result


def _steps(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise BugRegistryError(
            "bug_contract_invalid", "reproduction_steps must be an array"
        )
    if not 1 <= len(value) <= MAX_STEPS:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"reproduction_steps must contain 1 through {MAX_STEPS} steps",
        )
    result: list[str] = []
    for index, item in enumerate(value):
        step = _text(
            item,
            f"reproduction_steps[{index}]",
            maximum_bytes=512,
            required=True,
        )
        assert step is not None
        result.append(step)
    return result


def _reporter(value: object) -> str:
    provided = _text(value, "reporter", maximum_bytes=256)
    if provided:
        return provided
    thread = os.environ.get("CODEX_THREAD_ID")
    if thread:
        derived = _text(
            f"codex:{thread}", "reporter", maximum_bytes=256, required=True
        )
        assert derived is not None
        return derived
    return f"local:uid:{os.geteuid()}"


def _release_digest(value: object) -> str | None:
    if value is None:
        value = os.environ.get("DEVCOORDINATOR_RELEASE_DIGEST")
    if value is None:
        return None
    if not isinstance(value, str) or _RELEASE_DIGEST.fullmatch(value) is None:
        raise BugRegistryError(
            "bug_contract_invalid", "release_digest must be 64 lowercase hex digits"
        )
    return value


def _correlations(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise BugRegistryError(
            "bug_contract_invalid", "correlations must be an object"
        )
    allowed = {"call_id", "operation_id", "run_id", "attempt_id"}
    if set(value) - allowed:
        raise BugRegistryError(
            "bug_contract_invalid", "correlations contain unsupported fields"
        )
    result: dict[str, str] = {}
    for key in sorted(allowed):
        identifier = _identifier(value.get(key), f"correlations.{key}")
        if identifier is not None:
            result[key] = identifier
    return result


def _local_fallback(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise BugRegistryError(
            "bug_contract_invalid", "local_fallback must be an object"
        )
    allowed = {
        "status",
        "command_argv",
        "summary",
        "advisory",
        "coordinator_evidence",
    }
    if set(value) - allowed:
        raise BugRegistryError(
            "bug_contract_invalid", "local_fallback contains unsupported fields"
        )
    status_value = value.get("status")
    if status_value not in {"not_run", "passed", "failed", "incomplete"}:
        raise BugRegistryError(
            "bug_contract_invalid",
            "local_fallback.status must be not_run, passed, failed, or incomplete",
        )
    if "advisory" in value and value.get("advisory") is not True:
        raise BugRegistryError(
            "bug_contract_invalid", "local_fallback.advisory must be true"
        )
    if (
        "coordinator_evidence" in value
        and value.get("coordinator_evidence") is not False
    ):
        raise BugRegistryError(
            "bug_contract_invalid",
            "local_fallback.coordinator_evidence must be false",
        )
    summary = _text(value.get("summary"), "local_fallback.summary", maximum_bytes=512)
    argv = _structured_argv(value.get("command_argv"), "local_fallback.command_argv")
    if status_value == "not_run" and argv:
        raise BugRegistryError(
            "bug_contract_invalid", "not_run local fallback cannot include command argv"
        )
    result: dict[str, Any] = {
        "status": status_value,
        "advisory": True,
        "coordinator_evidence": False,
    }
    if argv:
        result["command_argv"] = argv
    if summary is not None:
        result["summary"] = summary
    return result


def _origin(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "server_id",
        "bug_id",
        "fingerprint",
    }:
        raise ValueError("bug origin is invalid")
    if value.get("kind") != "remote":
        raise ValueError("stored bug origin must be remote")
    server_id = _text(
        value.get("server_id"), "origin.server_id", maximum_bytes=256, required=True
    )
    bug_id = value.get("bug_id")
    fingerprint = value.get("fingerprint")
    if not isinstance(bug_id, str) or _BUG_ID.fullmatch(bug_id) is None:
        raise ValueError("origin bug identity is invalid")
    if (
        not isinstance(fingerprint, str)
        or _RELEASE_DIGEST.fullmatch(fingerprint) is None
    ):
        raise ValueError("origin fingerprint is invalid")
    assert server_id is not None
    return {
        "kind": "remote",
        "server_id": server_id,
        "bug_id": bug_id,
        "fingerprint": fingerprint,
    }


def configured_bug_dir() -> Path:
    raw = os.environ.get(BUG_REGISTRY_DIR_ENV)
    candidate = Path(raw) if raw else DEFAULT_BUG_REGISTRY_DIR
    if not candidate.is_absolute():
        raise BugRegistryError(
            "bug_registry_unavailable",
            f"{BUG_REGISTRY_DIR_ENV} must be an absolute path",
            classification="infrastructure_failure",
        )
    return candidate


def _ensure_directory(path: Path) -> int:
    try:
        path.mkdir(parents=True, exist_ok=True)
        try:
            # A caller-created test/local leaf must remain usable by the other
            # trusted developer accounts regardless of the creating umask.
            # Existing production metadata is never treated as authorization;
            # tmpfiles owns its authoritative mode and a non-owner chmod denial
            # is therefore harmless here.
            os.chmod(path, 0o777)
        except PermissionError:
            pass
        return os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise BugRegistryError(
            "bug_registry_unavailable",
            f"open bug registry is unavailable: {error}",
            classification="infrastructure_failure",
        ) from error


def _read_entry(directory_fd: int, name: str) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BUG_FILE_BYTES:
            raise ValueError("bug entry is not one bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_BUG_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_BUG_FILE_BYTES:
            raise ValueError("bug entry exceeds its byte bound")
        document = json.loads(raw.decode("utf-8"))
    finally:
        os.close(descriptor)
    if not isinstance(document, dict):
        raise ValueError("bug entry is not an object")
    normalized = _validated_stored_record(document)
    if normalized.get("bug_id") + ".json" != name:
        raise ValueError("bug entry identity contradicts its filename")
    return normalized


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} is not a UTC timestamp") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{field} is not UTC")
    return value


def _validated_stored_record(document: Mapping[str, Any]) -> dict[str, Any]:
    """Reconstruct one canonical record before it can participate in dedupe."""

    required = {
        "schema_version",
        "bug_id",
        "fingerprint",
        "component",
        "summary",
        "expected",
        "actual",
        "reproduction_steps",
        "reporter",
        "peer_uid",
        "first_seen_at",
        "last_seen_at",
        "occurrence_count",
    }
    optional = {
        "surface",
        "operation",
        "classification",
        "code",
        "stage",
        "repository",
        "release_digest",
        "instance_id",
        "command_argv",
        "correlations",
        "local_fallback",
        "origin",
    }
    if set(document) - required - optional or not required <= set(document):
        raise ValueError("bug entry fields are invalid")
    if document.get("schema_version") != BUG_REGISTRY_SCHEMA_VERSION:
        raise ValueError("bug entry schema is unsupported")
    bug_id = document.get("bug_id")
    if not isinstance(bug_id, str) or _BUG_ID.fullmatch(bug_id) is None:
        raise ValueError("bug entry identity is invalid")
    fingerprint = document.get("fingerprint")
    if not isinstance(fingerprint, str) or _RELEASE_DIGEST.fullmatch(fingerprint) is None:
        raise ValueError("bug entry fingerprint is invalid")
    normalized: dict[str, Any] = {
        "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
        "bug_id": bug_id,
        "fingerprint": fingerprint,
        "component": _name(document.get("component"), "component", required=True),
        "summary": _text(
            document.get("summary"), "summary", maximum_bytes=512, required=True
        ),
        "expected": _text(
            document.get("expected"), "expected", maximum_bytes=512, required=True
        ),
        "actual": _text(
            document.get("actual"), "actual", maximum_bytes=1024, required=True
        ),
        "reproduction_steps": _steps(document.get("reproduction_steps")),
        "reporter": _text(
            document.get("reporter"), "reporter", maximum_bytes=256, required=True
        ),
        "peer_uid": document.get("peer_uid"),
        "first_seen_at": _timestamp(document.get("first_seen_at"), "first_seen_at"),
        "last_seen_at": _timestamp(document.get("last_seen_at"), "last_seen_at"),
        "occurrence_count": document.get("occurrence_count"),
    }
    if type(normalized["peer_uid"]) is not int or normalized["peer_uid"] < 0:
        raise ValueError("bug entry peer_uid is invalid")
    if (
        type(normalized["occurrence_count"]) is not int
        or normalized["occurrence_count"] < 1
    ):
        raise ValueError("bug entry occurrence_count is invalid")
    for field in ("surface", "operation", "classification", "code", "stage", "instance_id"):
        if field in document:
            normalized[field] = _name(document.get(field), field, required=True)
    if "repository" in document:
        normalized["repository"] = _text(
            document.get("repository"),
            "repository",
            maximum_bytes=512,
            required=True,
        )
    if "release_digest" in document:
        normalized["release_digest"] = _release_digest(
            document.get("release_digest")
        )
    if "command_argv" in document:
        command_argv = _structured_argv(document.get("command_argv"), "command_argv")
        if not command_argv:
            raise ValueError("stored command_argv must not be empty")
        normalized["command_argv"] = command_argv
    if "correlations" in document:
        correlations = _correlations(document.get("correlations"))
        if not correlations:
            raise ValueError("stored correlations must not be empty")
        normalized["correlations"] = correlations
    if "local_fallback" in document:
        fallback = _local_fallback(document.get("local_fallback"))
        if fallback is None:
            raise ValueError("stored local fallback is invalid")
        normalized["local_fallback"] = fallback
    if "origin" in document:
        origin = _origin(document.get("origin"))
        if origin is None:
            raise ValueError("stored bug origin is invalid")
        normalized["origin"] = origin
    if _fingerprint(normalized) != fingerprint:
        raise ValueError("bug entry fingerprint does not match its stable fields")
    # This equality catches hidden values which a sanitizer would otherwise
    # redact and then accidentally preserve by rewriting the record.
    if _canonical_bytes(normalized) != _canonical_bytes(document):
        raise ValueError("bug entry is not canonical or contains redacted material")
    return normalized


def _entries(directory_fd: int) -> tuple[list[dict[str, Any]], int, bool]:
    names = sorted(
        name
        for name in os.listdir(directory_fd)
        if isinstance(name, str) and name.endswith(".json")
    )
    overflow = len(names) > MAX_OPEN_BUGS
    documents: list[dict[str, Any]] = []
    malformed = 0
    for name in names[:MAX_OPEN_BUGS]:
        try:
            documents.append(_read_entry(directory_fd, name))
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            malformed += 1
    return documents, malformed, overflow


def _write_entry(directory_fd: int, document: Mapping[str, Any]) -> None:
    payload = _canonical_bytes(document)
    if len(payload) > MAX_BUG_FILE_BYTES:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"bug record exceeds its {MAX_BUG_FILE_BYTES}-byte bound",
        )
    filename = str(document["bug_id"]) + ".json"
    temporary = ".tmp-" + uuid.uuid4().hex
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o666, dir_fd=directory_fd)
        # Files contain only bounded non-secret coordination metadata.  The
        # confirmed same-developer trust model makes cross-account readability
        # intentional and independent of each caller's umask.
        os.fchmod(descriptor, 0o666)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short bug-registry write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        raise BugRegistryError(
            "bug_registry_unavailable",
            f"open bug registry could not persist the report: {error}",
            classification="infrastructure_failure",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _fingerprint(document: Mapping[str, Any]) -> str:
    fields = {
        key: document[key]
        for key in (
            "component",
            "surface",
            "operation",
            "classification",
            "code",
            "stage",
            "summary",
            "expected",
            "actual",
            "reproduction_steps",
            "command_argv",
            "repository",
            "origin",
        )
        if key in document
    }
    return hashlib.sha256(_canonical_bytes(fields)).hexdigest()


def _report_projection(record: Mapping[str, Any], *, deduplicated: bool) -> dict[str, Any]:
    return {
        "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
        "ok": True,
        "action": "bug_reported",
        "deduplicated": deduplicated,
        "bug": {
            key: record[key]
            for key in (
                "bug_id",
                "fingerprint",
                "component",
                "summary",
                "first_seen_at",
                "last_seen_at",
                "occurrence_count",
            )
        },
        "next_command": f"devcoordinator bug close {record['bug_id']}",
    }


def report_bug(
    *,
    component: object,
    summary: object,
    expected: object,
    actual: object,
    reproduction_steps: object,
    command_argv: object = None,
    reporter: object = None,
    peer_uid: int | None = None,
    surface: object = None,
    operation: object = None,
    classification: object = None,
    code: object = None,
    stage: object = None,
    repository: object = None,
    release_digest: object = None,
    instance_id: object = None,
    correlations: object = None,
    local_fallback: object = None,
    bug_dir: Path | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    record: dict[str, Any] = {
        "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
        "bug_id": "bug-" + uuid.uuid4().hex,
        "component": _name(component, "component", required=True),
        "summary": _text(summary, "summary", maximum_bytes=512, required=True),
        "expected": _text(expected, "expected", maximum_bytes=512, required=True),
        "actual": _text(actual, "actual", maximum_bytes=1024, required=True),
        "reproduction_steps": _steps(reproduction_steps),
        "reporter": _reporter(reporter),
        "peer_uid": os.geteuid() if peer_uid is None else peer_uid,
        "first_seen_at": now,
        "last_seen_at": now,
        "occurrence_count": 1,
    }
    if type(record["peer_uid"]) is not int or record["peer_uid"] < 0:
        raise BugRegistryError(
            "bug_contract_invalid", "peer_uid must be a non-negative integer"
        )
    optional_names = {
        "surface": surface,
        "operation": operation,
        "classification": classification,
        "code": code,
        "stage": stage,
        "instance_id": instance_id,
    }
    for field, raw in optional_names.items():
        value = _name(raw, field)
        if value is not None:
            record[field] = value
    repository_value = _text(repository, "repository", maximum_bytes=512)
    if repository_value is not None:
        record["repository"] = repository_value
    release_value = _release_digest(release_digest)
    if release_value is not None:
        record["release_digest"] = release_value
    argv_value = _structured_argv(command_argv, "command_argv")
    if argv_value:
        record["command_argv"] = argv_value
    correlation_value = _correlations(correlations)
    if correlation_value:
        record["correlations"] = correlation_value
    fallback_value = _local_fallback(local_fallback)
    if fallback_value is not None:
        record["local_fallback"] = fallback_value
    record["fingerprint"] = _fingerprint(record)

    directory_fd = _ensure_directory(bug_dir or configured_bug_dir())
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        entries, _malformed, overflow = _entries(directory_fd)
        matching = next(
            (
                existing
                for existing in entries
                if existing.get("fingerprint") == record["fingerprint"]
                and "origin" not in existing
            ),
            None,
        )
        if matching is not None:
            count = matching.get("occurrence_count")
            matching["occurrence_count"] = (
                count + 1 if type(count) is int and count >= 1 else 2
            )
            matching["last_seen_at"] = now
            matching["reporter"] = record["reporter"]
            matching["peer_uid"] = record["peer_uid"]
            if correlation_value:
                matching["correlations"] = correlation_value
            if fallback_value is not None:
                matching["local_fallback"] = fallback_value
            if release_value is not None:
                matching["release_digest"] = release_value
            instance_value = record.get("instance_id")
            if isinstance(instance_value, str):
                matching["instance_id"] = instance_value
            _write_entry(directory_fd, matching)
            return _bounded_result(
                _report_projection(matching, deduplicated=True)
            )
        if overflow or len(entries) >= MAX_OPEN_BUGS:
            raise BugRegistryError(
                "bug_registry_capacity_reached",
                "open bug registry reached its bounded capacity; close resolved bugs first",
                classification="infrastructure_failure",
            )
        _write_entry(directory_fd, record)
        return _bounded_result(_report_projection(record, deduplicated=False))
    finally:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
        os.close(directory_fd)


def _list_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: record[key]
        for key in (
            "bug_id",
            "fingerprint",
            "component",
            "surface",
            "operation",
            "classification",
            "code",
            "stage",
            "summary",
            "reporter",
            "repository",
            "first_seen_at",
            "last_seen_at",
            "occurrence_count",
            "correlations",
            "local_fallback",
            "origin",
        )
        if key in record
    }


def list_bugs(
    *,
    limit: int = 8,
    component: object = None,
    bug_dir: Path | None = None,
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= MAX_LIST_LIMIT:
        raise BugRegistryError(
            "bug_contract_invalid",
            f"limit must be from 1 through {MAX_LIST_LIMIT}",
        )
    component_value = _name(component, "component")
    directory_fd = _ensure_directory(bug_dir or configured_bug_dir())
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_SH)
        entries, malformed, overflow = _entries(directory_fd)
    finally:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
        os.close(directory_fd)
    matching = [
        item
        for item in entries
        if component_value is None or item.get("component") == component_value
    ]
    matching.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    projected: list[dict[str, Any]] = []
    for entry in matching[:limit]:
        candidate = _list_projection(entry)
        trial = {
            "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
            "ok": True,
            "action": "bugs_listed",
            "bugs": [*projected, candidate],
            "open_count": len(matching),
            "malformed_count": malformed,
            # ``false`` is one byte longer than ``true``; size against the
            # larger final envelope so either truthful value remains bounded.
            "truncated": False,
        }
        # The standalone and integrated launchers append one newline byte.
        # Size the complete wire envelope here so a result accepted by the
        # registry cannot later fail while it is emitted to an agent.
        if len(_canonical_bytes(trial)) + 1 > MAX_RESULT_BYTES:
            break
        projected.append(candidate)
    return _bounded_result(
        {
            "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
            "ok": True,
            "action": "bugs_listed",
            "bugs": projected,
            "open_count": len(matching),
            "malformed_count": malformed,
            "truncated": overflow or len(projected) < len(matching),
        }
    )


def close_bug(*, bug_id: object, bug_dir: Path | None = None) -> dict[str, Any]:
    if not isinstance(bug_id, str) or _BUG_ID.fullmatch(bug_id) is None:
        raise BugRegistryError(
            "bug_id_invalid", "bug ID must be one canonical bug-UUID identity"
        )
    directory_fd = _ensure_directory(bug_dir or configured_bug_dir())
    removed = False
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        try:
            os.unlink(bug_id + ".json", dir_fd=directory_fd)
            removed = True
            os.fsync(directory_fd)
        except FileNotFoundError:
            removed = False
    except OSError as error:
        raise BugRegistryError(
            "bug_registry_unavailable",
            f"open bug registry could not close the bug: {error}",
            classification="infrastructure_failure",
        ) from error
    finally:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
        os.close(directory_fd)
    return _bounded_result(
        {
            "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
            "ok": True,
            "action": "bug_closed",
            "bug_id": bug_id,
            "removed": removed,
        }
    )


def _bounded_result(document: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(document)
    if len(_canonical_bytes(result)) + 1 > MAX_RESULT_BYTES:
        raise BugRegistryError(
            "bug_result_too_large",
            "bug registry result exceeds its bounded contract",
            classification="client_contract_failure",
        )
    return result


def _add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--component", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--actual", required=True)
    parser.add_argument("--step", action="append", required=True)
    parser.add_argument("--command-arg", action="append", default=[])
    parser.add_argument("--reporter")
    parser.add_argument("--surface")
    parser.add_argument("--operation")
    parser.add_argument("--classification")
    parser.add_argument("--code")
    parser.add_argument("--stage")
    parser.add_argument("--repository")
    parser.add_argument("--release-digest")
    parser.add_argument("--instance-id")
    parser.add_argument("--call-id")
    parser.add_argument("--operation-id")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt-id")
    parser.add_argument(
        "--local-fallback-status",
        choices=("not_run", "passed", "failed", "incomplete"),
    )
    parser.add_argument("--local-test-command-arg", action="append", default=[])
    parser.add_argument("--local-fallback-summary")


def add_bug_parser(commands: Any) -> argparse.ArgumentParser:
    bug = commands.add_parser(
        "bug",
        help="report, list, or close an open Coordinator bug without contacting services",
    )
    _add_actions(bug)
    return bug


def _add_actions(parser: argparse.ArgumentParser) -> None:
    actions = parser.add_subparsers(dest="bug_action", required=True)
    report = actions.add_parser("report", help="atomically report one reproducible bug")
    _add_report_arguments(report)
    listing = actions.add_parser("list", help="list bounded open bug summaries")
    listing.add_argument("--limit", type=int, default=8)
    listing.add_argument("--component")
    close = actions.add_parser("close", help="remove one resolved open bug")
    close.add_argument("bug_id")


def execute_namespace(namespace: argparse.Namespace) -> dict[str, Any]:
    action = namespace.bug_action
    if action == "report":
        correlations = {
            key: value
            for key in ("call_id", "operation_id", "run_id", "attempt_id")
            if (value := getattr(namespace, key, None)) is not None
        }
        fallback = None
        if (
            namespace.local_fallback_status is not None
            or namespace.local_test_command_arg
            or namespace.local_fallback_summary is not None
        ):
            if namespace.local_fallback_status is None:
                raise BugRegistryError(
                    "bug_contract_invalid",
                    "local fallback metadata requires --local-fallback-status",
                )
            fallback = {
                "status": namespace.local_fallback_status,
                "command_argv": list(namespace.local_test_command_arg),
                "summary": namespace.local_fallback_summary,
            }
        return report_bug(
            component=namespace.component,
            summary=namespace.summary,
            expected=namespace.expected,
            actual=namespace.actual,
            reproduction_steps=namespace.step,
            command_argv=namespace.command_arg,
            reporter=namespace.reporter,
            surface=namespace.surface,
            operation=namespace.operation,
            classification=namespace.classification,
            code=namespace.code,
            stage=namespace.stage,
            repository=namespace.repository,
            release_digest=namespace.release_digest,
            instance_id=namespace.instance_id,
            correlations=correlations,
            local_fallback=fallback,
        )
    if action == "list":
        return list_bugs(limit=namespace.limit, component=namespace.component)
    if action == "close":
        return close_bug(bug_id=namespace.bug_id)
    raise BugRegistryError("bug_action_invalid", "bug action is unsupported")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devcoordinator-bug",
        description=(
            "Out-of-band open Coordinator bug registry; no broker, profile, "
            "repository, API, or testd connection is required."
        ),
    )
    _add_actions(parser)
    return parser


def _failure(error: BaseException) -> dict[str, Any]:
    code = getattr(error, "code", "bug_registry_failed")
    classification = getattr(error, "classification", "infrastructure_failure")
    message = _text(str(error), "message", maximum_bytes=1024) or "bug registry failed"
    return _bounded_result(
        {
            "schema_version": BUG_REGISTRY_SCHEMA_VERSION,
            "ok": False,
            "classification": classification,
            "code": code,
            "stage": "bug_registry",
            "message": message,
            "retryable": classification == "infrastructure_failure",
        }
    )


def _emit(document: Mapping[str, Any]) -> None:
    payload = _canonical_bytes(document)
    if len(payload) + 1 > MAX_RESULT_BYTES:
        raise BugRegistryError(
            "bug_result_too_large",
            "bug registry output exceeds its bounded contract",
            classification="client_contract_failure",
        )
    sys.stdout.buffer.write(payload + b"\n")
    sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    # This launcher exists specifically for failures in the normal Coordinator
    # path.  Do not initialize or write the ordinary call journal here: its
    # blocking lock may itself be the outage under report.  The open bug file
    # is the complete durable record for this operation.
    try:
        namespace = _parser().parse_args(list(argv) if argv is not None else None)
        result = execute_namespace(namespace)
    except SystemExit:
        raise
    except BaseException as error:
        _emit(_failure(error))
        return 1
    _emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BUG_REGISTRY_DIR_ENV",
    "BUG_REGISTRY_SCHEMA_VERSION",
    "BugRegistryError",
    "add_bug_parser",
    "close_bug",
    "configured_bug_dir",
    "execute_namespace",
    "list_bugs",
    "main",
    "report_bug",
]
