"""Atomic, bounded result packages for one governed test attempt.

The trusted non-root runner publishes one deterministic uncompressed USTAR
file after the repository process has exited.  The package is the only
semantic result transport: cases and failures are newline-delimited canonical
JSON, artifact bytes are digest-bound members, and the manifest binds the
exact repository/attempt generations and descriptor fingerprint.

This module deliberately has no dependency on the test store, testd, or the
root runtime so all three boundaries can validate the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
from types import MappingProxyType
from typing import BinaryIO, Callable, Iterator, Mapping, Sequence
import uuid


RESULT_PACKAGE_SCHEMA_VERSION = 1
RESULT_PACKAGE_FILE_NAME = "result-package.tar"
MAX_RESULT_PACKAGE_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RESULT_PACKAGE_RECORD_BYTES = 4_096 * 240 * 1024
MAX_RESULT_PACKAGE_CASES = 100_000
MAX_RESULT_PACKAGE_FAILURES = 100_256
MAX_RESULT_PACKAGE_ARTIFACTS = 64
MAX_RESULT_PACKAGE_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_RESULT_PACKAGE_BYTES = (
    MAX_RESULT_PACKAGE_RECORD_BYTES
    + MAX_RESULT_PACKAGE_ARTIFACTS * MAX_RESULT_PACKAGE_ARTIFACT_BYTES
    + MAX_RESULT_PACKAGE_MANIFEST_BYTES
    + 16 * 1024 * 1024
)
MAX_RESULT_RECORD_LINE_BYTES = 64 * 1024

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_HANDLE = re.compile(
    r"^test-artifact://(artifact-[0-9a-f]{32})/([0-9a-f]{64})$"
)
_ARTIFACT_KINDS = frozenset(
    {"log", "jsonl", "junit", "trx", "coverage", "trace", "directory"}
)
_CASE_STATES = frozenset({"passed", "failed", "skipped", "error"})
_FAILURE_CLASSIFICATIONS = frozenset(
    {
        "test_failure",
        "infrastructure_failure",
        "timeout",
        "cancellation",
        "incomplete_reporting",
    }
)
_TERMINAL_OUTCOMES = frozenset(
    {
        "succeeded",
        "test_failed",
        "infrastructure_failed",
        "timed_out",
        "incomplete",
    }
)
_SECRET_MATERIAL = re.compile(
    rb"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|\bAKIA[0-9A-Z]{16}\b"
    rb"|\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"
    rb"|\bsk-[A-Za-z0-9_-]{20,}\b"
    rb"|\bxox[baprs]-[A-Za-z0-9-]{20,}\b"
    rb"|\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b)"
)


class ResultPackageError(RuntimeError):
    """The result package is malformed, unsafe, excessive, or contradictory."""


@dataclass(frozen=True)
class ResultPackageArtifact:
    """One public artifact record plus its private runner source file."""

    artifact_id: str
    kind: str
    storage_handle: str
    sha256: str
    size_bytes: int
    source_path: Path
    verified: bool = True


@dataclass(frozen=True)
class ResultPackageEvidence:
    package_id: str
    sha256: str
    size_bytes: int
    manifest_sha256: str
    identity: Mapping[str, object]
    outcome: Mapping[str, object]
    counts: Mapping[str, int]


@dataclass(frozen=True)
class ValidatedResultPackage:
    path: Path
    evidence: ResultPackageEvidence
    manifest: Mapping[str, object]
    file_identity: tuple[int, int, int, int, int]


def _canonical_json(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError) as error:
        raise ResultPackageError("result package JSON is invalid") from error


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ResultPackageError(f"{field} is invalid")
    return value


def _sha256(field: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ResultPackageError(f"{field} is invalid")
    return value


def _bounded_text(
    field: str,
    value: object,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ResultPackageError(f"{field} is invalid")
    return value


def _nonnegative_float(field: str, value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ResultPackageError(f"{field} is invalid")
    return float(value)


def _optional_nonnegative_int(field: str, value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise ResultPackageError(f"{field} is invalid")
    return value


def _optional_nonnegative_float(field: str, value: object) -> float | None:
    if value is None:
        return None
    return _nonnegative_float(field, value)


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_IFMT(metadata.st_mode),
    )


def _normalize_sequences(
    field: str, values: Sequence[bytes], *, maximum_total: int = 8 * 1024 * 1024
) -> tuple[bytes, ...]:
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes, bytearray))
        or len(values) > 256
    ):
        raise ResultPackageError(f"{field} is invalid")
    result: set[bytes] = set()
    total = 0
    for value in values:
        if not isinstance(value, bytes) or not value or len(value) > 256 * 1024:
            raise ResultPackageError(f"{field} is invalid")
        total += len(value)
        if total > maximum_total:
            raise ResultPackageError(f"{field} is excessive")
        result.add(value)
    return tuple(sorted(result, key=lambda item: (-len(item), item)))


class _MaterialScanner:
    def __init__(
        self,
        *,
        exact: Sequence[bytes],
        metadata_only: Sequence[bytes] = (),
    ) -> None:
        self._exact = tuple(exact)
        self._metadata_only = tuple(metadata_only)
        self._tail = b""
        self._overlap = max(
            4096,
            max(
                (len(value) - 1 for value in (*self._exact, *self._metadata_only)),
                default=0,
            ),
        )

    def scan(self, payload: bytes, *, metadata: bool) -> None:
        sample = self._tail + payload
        sequences = self._exact + (self._metadata_only if metadata else ())
        if _SECRET_MATERIAL.search(sample) is not None or any(
            value in sample for value in sequences
        ):
            raise ResultPackageError("result package contains protected material")
        self._tail = sample[-self._overlap :]


class _BoundedHashWriter(io.RawIOBase):
    def __init__(self, destination: BinaryIO, *, maximum_bytes: int) -> None:
        self._destination = destination
        self._maximum = maximum_bytes
        self._size = 0
        self._digest = hashlib.sha256()

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._size

    def write(self, value: bytes | bytearray) -> int:
        payload = bytes(value)
        if self._size + len(payload) > self._maximum:
            raise ResultPackageError("result package exceeds its byte bound")
        written = self._destination.write(payload)
        if written is None:
            written = len(payload)
        if written != len(payload):
            raise ResultPackageError("result package write was partial")
        self._digest.update(payload)
        self._size += written
        return written

    @property
    def evidence(self) -> tuple[str, int]:
        return self._digest.hexdigest(), self._size


class _VerifiedArtifactReader:
    def __init__(
        self,
        source: BinaryIO,
        *,
        exact_secrets: Sequence[bytes],
    ) -> None:
        self._source = source
        self._scanner = _MaterialScanner(exact=exact_secrets)
        self._digest = hashlib.sha256()
        self._size = 0

    def read(self, size: int = -1) -> bytes:
        payload = self._source.read(size)
        if payload:
            self._scanner.scan(payload, metadata=False)
            self._digest.update(payload)
            self._size += len(payload)
        return payload

    @property
    def evidence(self) -> tuple[str, int]:
        return self._digest.hexdigest(), self._size


def _normalize_identity(value: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "attempt_id",
        "target_id",
        "run_id",
        "repository_id",
        "repository_generation",
        "generation",
        "descriptor_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResultPackageError("result package identity fields are invalid")
    repository_generation = value["repository_generation"]
    generation = value["generation"]
    if (
        type(repository_generation) is not int
        or repository_generation < 0
        or type(generation) is not int
        or generation <= 0
    ):
        raise ResultPackageError("result package generation is invalid")
    return {
        "attempt_id": _safe_id("attempt_id", value["attempt_id"]),
        "target_id": _safe_id("target_id", value["target_id"]),
        "run_id": _safe_id("run_id", value["run_id"]),
        "repository_id": _safe_id("repository_id", value["repository_id"]),
        "repository_generation": repository_generation,
        "generation": generation,
        "descriptor_sha256": _sha256(
            "descriptor_sha256", value["descriptor_sha256"]
        ),
    }


def _normalize_outcome(value: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "returncode",
        "duration_seconds",
        "incomplete_reporting",
        "reporter_complete",
        "terminal_outcome",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResultPackageError("result package outcome fields are invalid")
    if type(value["returncode"]) is not int:
        raise ResultPackageError("result package returncode is invalid")
    if type(value["incomplete_reporting"]) is not bool or type(
        value["reporter_complete"]
    ) is not bool:
        raise ResultPackageError("result package reporting state is invalid")
    terminal = value["terminal_outcome"]
    if terminal not in _TERMINAL_OUTCOMES:
        raise ResultPackageError("result package terminal outcome is invalid")
    if value["reporter_complete"] == value["incomplete_reporting"]:
        raise ResultPackageError("result package reporting state is contradictory")
    return {
        "returncode": value["returncode"],
        "duration_seconds": _nonnegative_float(
            "duration_seconds", value["duration_seconds"]
        ),
        "incomplete_reporting": value["incomplete_reporting"],
        "reporter_complete": value["reporter_complete"],
        "terminal_outcome": terminal,
    }


def _normalize_resource_usage(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "peak_memory_bytes",
        "cpu_seconds",
    }:
        raise ResultPackageError("result package resource usage fields are invalid")
    return {
        "peak_memory_bytes": _optional_nonnegative_int(
            "peak_memory_bytes", value["peak_memory_bytes"]
        ),
        "cpu_seconds": _optional_nonnegative_float(
            "cpu_seconds", value["cpu_seconds"]
        ),
    }


def _normalize_capture(name: str, value: object) -> dict[str, object]:
    expected = {
        "artifact_id",
        "sha256",
        "retained_sha256",
        "size_bytes",
        "observed_bytes",
        "truncated",
        "secret_redacted",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResultPackageError(f"result package {name} capture fields are invalid")
    size = value["size_bytes"]
    observed = value["observed_bytes"]
    secret_redacted = value["secret_redacted"]
    if (
        type(size) is not int
        or type(observed) is not int
        or not 0 <= size <= MAX_RESULT_PACKAGE_ARTIFACT_BYTES
        or not 0 <= observed <= (1 << 63) - 1
        or type(value["truncated"]) is not bool
        or type(secret_redacted) is not bool
        or (
            not secret_redacted
            and (
                size > observed
                or value["truncated"] != (observed > size)
            )
        )
    ):
        raise ResultPackageError(f"result package {name} capture is invalid")
    return {
        "artifact_id": _safe_id(f"{name} artifact_id", value["artifact_id"]),
        "sha256": _sha256(f"{name} sha256", value["sha256"]),
        "retained_sha256": _sha256(
            f"{name} retained_sha256", value["retained_sha256"]
        ),
        "size_bytes": size,
        "observed_bytes": observed,
        "truncated": value["truncated"],
        "secret_redacted": secret_redacted,
    }


def _normalize_captures(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"stdout", "stderr"}:
        raise ResultPackageError("result package capture fields are invalid")
    return {
        name: _normalize_capture(name, value[name])
        for name in ("stdout", "stderr")
    }


def _normalize_case(value: object) -> dict[str, object]:
    expected = {
        "case_id",
        "display_name",
        "status",
        "duration_seconds",
        "location",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResultPackageError("result package case fields are invalid")
    status = value["status"]
    if status not in _CASE_STATES:
        raise ResultPackageError("result package case status is invalid")
    location = value["location"]
    if location is not None:
        location = _bounded_text("case location", location, maximum=4096)
    return {
        "case_id": _bounded_text("case_id", value["case_id"], maximum=1024),
        "display_name": _bounded_text(
            "case display_name", value["display_name"], maximum=4096
        ),
        "status": status,
        "duration_seconds": _nonnegative_float(
            "case duration_seconds", value["duration_seconds"]
        ),
        "location": location,
    }


def _normalize_failure(value: object) -> dict[str, object]:
    expected = {
        "failure_id",
        "classification",
        "message",
        "case_id",
        "location",
        "artifact_id",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResultPackageError("result package failure fields are invalid")
    classification = value["classification"]
    if classification not in _FAILURE_CLASSIFICATIONS:
        raise ResultPackageError("result package failure classification is invalid")
    case_id = value["case_id"]
    artifact_id = value["artifact_id"]
    location = value["location"]
    if case_id is not None:
        case_id = _bounded_text("failure case_id", case_id, maximum=1024)
    if artifact_id is not None:
        artifact_id = _safe_id("failure artifact_id", artifact_id)
    if location is not None:
        location = _bounded_text("failure location", location, maximum=4096)
    return {
        "failure_id": _safe_id("failure_id", value["failure_id"]),
        "classification": classification,
        "message": _bounded_text("failure message", value["message"], maximum=8192),
        "case_id": case_id,
        "location": location,
        "artifact_id": artifact_id,
    }


def _normalize_artifact(value: ResultPackageArtifact) -> tuple[dict[str, object], Path]:
    if not isinstance(value, ResultPackageArtifact):
        raise ResultPackageError("result package artifacts are invalid")
    artifact_id = _safe_id("artifact_id", value.artifact_id)
    if (
        re.fullmatch(r"artifact-[0-9a-f]{32}", artifact_id) is None
        or value.kind not in _ARTIFACT_KINDS
    ):
        raise ResultPackageError("result package artifact identity is invalid")
    digest = _sha256("artifact sha256", value.sha256)
    matched = _ARTIFACT_HANDLE.fullmatch(value.storage_handle)
    if (
        matched is None
        or matched.group(1) != artifact_id
        or matched.group(2) != digest
        or type(value.size_bytes) is not int
        or not 0 <= value.size_bytes <= MAX_RESULT_PACKAGE_ARTIFACT_BYTES
        or value.verified is not True
    ):
        raise ResultPackageError("result package artifact metadata is invalid")
    member_name = f"artifacts/{artifact_id}.blob"
    return (
        {
            "artifact_id": artifact_id,
            "kind": value.kind,
            "storage_handle": value.storage_handle,
            "sha256": digest,
            "size_bytes": value.size_bytes,
            "verified": True,
            "member_name": member_name,
        },
        Path(value.source_path),
    )


def _write_record_file(
    values: Sequence[Mapping[str, object]],
    *,
    kind: str,
    exact_secrets: Sequence[bytes],
    metadata_sequences: Sequence[bytes],
) -> tuple[BinaryIO, dict[str, object]]:
    if kind not in {"cases", "failures"}:
        raise AssertionError("unsupported result record kind")
    maximum_count = (
        MAX_RESULT_PACKAGE_CASES if kind == "cases" else MAX_RESULT_PACKAGE_FAILURES
    )
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes, bytearray))
        or len(values) > maximum_count
    ):
        raise ResultPackageError(f"result package {kind} exceed their bound")
    temporary = tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    total = 0
    scanner = _MaterialScanner(
        exact=exact_secrets,
        metadata_only=metadata_sequences,
    )
    try:
        for value in values:
            normalized = (
                _normalize_case(value) if kind == "cases" else _normalize_failure(value)
            )
            payload = _canonical_json(normalized)
            if len(payload) > MAX_RESULT_RECORD_LINE_BYTES:
                raise ResultPackageError(f"result package {kind} record is excessive")
            total += len(payload)
            if total > MAX_RESULT_PACKAGE_RECORD_BYTES:
                raise ResultPackageError("result package records exceed their byte bound")
            scanner.scan(payload, metadata=True)
            temporary.write(payload)
            digest.update(payload)
        temporary.flush()
        temporary.seek(0)
        return temporary, {
            "name": f"{kind}.ndjson",
            "records": len(values),
            "size_bytes": total,
            "sha256": digest.hexdigest(),
        }
    except BaseException:
        temporary.close()
        raise


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = 0o400
    info.size = size
    info.type = tarfile.REGTYPE
    return info


def _write_package_bytes(
    destination: BinaryIO,
    *,
    manifest_payload: bytes,
    case_file: BinaryIO,
    failure_file: BinaryIO,
    records: Mapping[str, Mapping[str, object]],
    artifacts: Sequence[tuple[Mapping[str, object], Path]],
    exact_secrets: Sequence[bytes],
) -> tuple[str, int]:
    writer = _BoundedHashWriter(destination, maximum_bytes=MAX_RESULT_PACKAGE_BYTES)
    with tarfile.open(fileobj=writer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(
            _tar_info("manifest.json", len(manifest_payload)),
            io.BytesIO(manifest_payload),
        )
        for kind, source in (("cases", case_file), ("failures", failure_file)):
            source.seek(0)
            record = records[kind]
            archive.addfile(
                _tar_info(str(record["name"]), int(record["size_bytes"])),
                source,
            )
        for metadata, path in artifacts:
            try:
                before_path = path.lstat()
                descriptor = os.open(
                    path,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
            except OSError as error:
                raise ResultPackageError("result package artifact is unavailable") from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_ISLNK(before_path.st_mode)
                    or _stable_identity(before) != _stable_identity(before_path)
                    or before.st_size != metadata["size_bytes"]
                ):
                    raise ResultPackageError("result package artifact is unsafe")
                with os.fdopen(os.dup(descriptor), "rb", closefd=True) as raw:
                    source = _VerifiedArtifactReader(
                        raw,
                        exact_secrets=exact_secrets,
                    )
                    archive.addfile(
                        _tar_info(str(metadata["member_name"]), before.st_size),
                        source,
                    )
                    digest, size = source.evidence
                after = os.fstat(descriptor)
                path_after = path.lstat()
                if (
                    digest != metadata["sha256"]
                    or size != metadata["size_bytes"]
                    or _stable_identity(before) != _stable_identity(after)
                    or _stable_identity(after) != _stable_identity(path_after)
                ):
                    raise ResultPackageError("result package artifact changed during read")
            finally:
                os.close(descriptor)
    return writer.evidence


def publish_result_package(
    destination: Path,
    *,
    identity: Mapping[str, object],
    outcome: Mapping[str, object],
    resource_usage: Mapping[str, object],
    captures: Mapping[str, object],
    cases: Sequence[Mapping[str, object]],
    failures: Sequence[Mapping[str, object]],
    artifacts: Sequence[ResultPackageArtifact],
    prohibited_sequences: Sequence[bytes] = (),
    prohibited_metadata_sequences: Sequence[bytes] = (),
) -> ResultPackageEvidence:
    """Publish one complete package through a no-overwrite atomic link."""

    destination = Path(destination)
    if not destination.is_absolute() or destination.name != RESULT_PACKAGE_FILE_NAME:
        raise ResultPackageError("result package destination is invalid")
    try:
        parent_metadata = destination.parent.lstat()
        parent_resolved = destination.parent.resolve(strict=True)
    except OSError as error:
        raise ResultPackageError("result package parent is unavailable") from error
    if (
        parent_resolved != destination.parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
    ):
        raise ResultPackageError("result package parent is unsafe")

    normalized_identity = _normalize_identity(identity)
    normalized_outcome = _normalize_outcome(outcome)
    normalized_usage = _normalize_resource_usage(resource_usage)
    normalized_captures = _normalize_captures(captures)
    exact_secrets = _normalize_sequences("result package secret policy", prohibited_sequences)
    metadata_sequences = _normalize_sequences(
        "result package metadata policy", prohibited_metadata_sequences
    )

    normalized_artifacts = [_normalize_artifact(value) for value in artifacts]
    normalized_artifacts.sort(key=lambda item: str(item[0]["artifact_id"]))
    if (
        len(normalized_artifacts) > MAX_RESULT_PACKAGE_ARTIFACTS
        or len({item[0]["artifact_id"] for item in normalized_artifacts})
        != len(normalized_artifacts)
    ):
        raise ResultPackageError("result package artifact identities are invalid")

    case_file, case_record = _write_record_file(
        cases,
        kind="cases",
        exact_secrets=exact_secrets,
        metadata_sequences=metadata_sequences,
    )
    try:
        failure_file, failure_record = _write_record_file(
            failures,
            kind="failures",
            exact_secrets=exact_secrets,
            metadata_sequences=metadata_sequences,
        )
    except BaseException:
        case_file.close()
        raise
    records = {"cases": case_record, "failures": failure_record}
    if int(case_record["size_bytes"]) + int(
        failure_record["size_bytes"]
    ) > MAX_RESULT_PACKAGE_RECORD_BYTES:
        case_file.close()
        failure_file.close()
        raise ResultPackageError("result package records exceed their combined byte bound")

    counts = {
        "cases": len(cases),
        "passed": sum(item.get("status") == "passed" for item in cases),
        "failed": sum(item.get("status") == "failed" for item in cases),
        "skipped": sum(item.get("status") == "skipped" for item in cases),
        "errors": sum(item.get("status") == "error" for item in cases),
        "failures": len(failures),
        "artifacts": len(normalized_artifacts),
    }
    manifest = {
        "schema_version": RESULT_PACKAGE_SCHEMA_VERSION,
        "identity": normalized_identity,
        "outcome": normalized_outcome,
        "resource_usage": normalized_usage,
        "counts": counts,
        "captures": normalized_captures,
        "records": records,
        "artifacts": [dict(item[0]) for item in normalized_artifacts],
    }
    manifest_payload = _canonical_json(manifest)
    if len(manifest_payload) > MAX_RESULT_PACKAGE_MANIFEST_BYTES:
        case_file.close()
        failure_file.close()
        raise ResultPackageError("result package manifest exceeds its byte bound")
    metadata_scanner = _MaterialScanner(
        exact=exact_secrets,
        metadata_only=metadata_sequences,
    )
    metadata_scanner.scan(manifest_payload, metadata=True)

    parent_fd = os.open(
        destination.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_name = f".{RESULT_PACKAGE_FILE_NAME}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(os.dup(descriptor), "wb", closefd=True) as output:
            expected_digest, expected_size = _write_package_bytes(
                output,
                manifest_payload=manifest_payload,
                case_file=case_file,
                failure_file=failure_file,
                records=records,
                artifacts=normalized_artifacts,
                exact_secrets=exact_secrets,
            )
            output.flush()
        os.fsync(descriptor)
        temporary_path = destination.parent / temporary_name
        validated_temporary = validate_result_package(
            temporary_path,
            expected_identity=normalized_identity,
            expected_sha256=expected_digest,
            prohibited_sequences=exact_secrets,
            prohibited_metadata_sequences=metadata_sequences,
        )
        if validated_temporary.evidence.size_bytes != expected_size:
            raise ResultPackageError("result package publication size is contradictory")
        try:
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            os.fsync(parent_fd)
        except FileExistsError:
            existing = validate_result_package(
                destination,
                expected_identity=normalized_identity,
                expected_sha256=expected_digest,
                prohibited_sequences=exact_secrets,
                prohibited_metadata_sequences=metadata_sequences,
            )
            return existing.evidence
        published = validate_result_package(
            destination,
            expected_identity=normalized_identity,
            expected_sha256=expected_digest,
            prohibited_sequences=exact_secrets,
            prohibited_metadata_sequences=metadata_sequences,
        )
        return published.evidence
    except OSError as error:
        raise ResultPackageError("result package could not be published") from error
    finally:
        case_file.close()
        failure_file.close()
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)


def _read_all_bounded(source: BinaryIO, maximum: int, *, field: str) -> bytes:
    payload = source.read(maximum + 1)
    if len(payload) > maximum:
        raise ResultPackageError(f"{field} exceeds its byte bound")
    return payload


def _validate_header(member: tarfile.TarInfo, *, expected_name: str) -> None:
    path = PurePosixPath(member.name)
    if (
        member.name != expected_name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or not member.isreg()
        or member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != 0
        or member.mode != 0o400
        or member.pax_headers
    ):
        raise ResultPackageError("result package member header is unsafe")


def _decode_manifest(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResultPackageError("result package manifest JSON is invalid") from error
    expected = {
        "schema_version",
        "identity",
        "outcome",
        "resource_usage",
        "counts",
        "captures",
        "records",
        "artifacts",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or value.get("schema_version") != RESULT_PACKAGE_SCHEMA_VERSION
    ):
        raise ResultPackageError("result package manifest fields are invalid")
    identity = _normalize_identity(value["identity"])  # type: ignore[arg-type]
    outcome = _normalize_outcome(value["outcome"])  # type: ignore[arg-type]
    usage = _normalize_resource_usage(value["resource_usage"])  # type: ignore[arg-type]
    captures = _normalize_captures(value["captures"])  # type: ignore[arg-type]
    counts = value["counts"]
    count_fields = {
        "cases",
        "passed",
        "failed",
        "skipped",
        "errors",
        "failures",
        "artifacts",
    }
    if (
        not isinstance(counts, Mapping)
        or set(counts) != count_fields
        or any(type(counts[field]) is not int or counts[field] < 0 for field in count_fields)
        or counts["cases"] > MAX_RESULT_PACKAGE_CASES
        or counts["failures"] > MAX_RESULT_PACKAGE_FAILURES
        or counts["artifacts"] > MAX_RESULT_PACKAGE_ARTIFACTS
        or counts["passed"] + counts["failed"] + counts["skipped"] + counts["errors"]
        != counts["cases"]
    ):
        raise ResultPackageError("result package counts are invalid")
    records = value["records"]
    if not isinstance(records, Mapping) or set(records) != {"cases", "failures"}:
        raise ResultPackageError("result package record manifest is invalid")
    normalized_records: dict[str, object] = {}
    combined = 0
    for kind in ("cases", "failures"):
        raw = records[kind]
        expected_records = counts["cases" if kind == "cases" else "failures"]
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"name", "records", "size_bytes", "sha256"}
            or raw["name"] != f"{kind}.ndjson"
            or raw["records"] != expected_records
            or type(raw["size_bytes"]) is not int
            or not 0 <= raw["size_bytes"] <= MAX_RESULT_PACKAGE_RECORD_BYTES
        ):
            raise ResultPackageError("result package record manifest is invalid")
        combined += int(raw["size_bytes"])
        normalized_records[kind] = {
            "name": raw["name"],
            "records": raw["records"],
            "size_bytes": raw["size_bytes"],
            "sha256": _sha256(f"{kind} sha256", raw["sha256"]),
        }
    if combined > MAX_RESULT_PACKAGE_RECORD_BYTES:
        raise ResultPackageError("result package record manifest is excessive")
    raw_artifacts = value["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != counts["artifacts"]:
        raise ResultPackageError("result package artifact manifest is invalid")
    normalized_artifacts: list[dict[str, object]] = []
    for raw in raw_artifacts:
        if not isinstance(raw, Mapping) or set(raw) != {
            "artifact_id",
            "kind",
            "storage_handle",
            "sha256",
            "size_bytes",
            "verified",
            "member_name",
        }:
            raise ResultPackageError("result package artifact manifest is invalid")
        artifact_id = _safe_id("artifact_id", raw["artifact_id"])
        digest = _sha256("artifact sha256", raw["sha256"])
        matched = _ARTIFACT_HANDLE.fullmatch(str(raw["storage_handle"]))
        expected_member = f"artifacts/{artifact_id}.blob"
        if (
            re.fullmatch(r"artifact-[0-9a-f]{32}", artifact_id) is None
            or raw["kind"] not in _ARTIFACT_KINDS
            or matched is None
            or matched.group(1) != artifact_id
            or matched.group(2) != digest
            or raw["member_name"] != expected_member
            or type(raw["size_bytes"]) is not int
            or not 0 <= raw["size_bytes"] <= MAX_RESULT_PACKAGE_ARTIFACT_BYTES
            or raw["verified"] is not True
        ):
            raise ResultPackageError("result package artifact manifest is invalid")
        normalized_artifacts.append(dict(raw))
    if [item["artifact_id"] for item in normalized_artifacts] != sorted(
        item["artifact_id"] for item in normalized_artifacts
    ) or len({item["artifact_id"] for item in normalized_artifacts}) != len(
        normalized_artifacts
    ):
        raise ResultPackageError("result package artifact order is invalid")
    capture_ids = {captures[name]["artifact_id"] for name in captures}
    if not capture_ids.issubset({item["artifact_id"] for item in normalized_artifacts}):
        raise ResultPackageError("result package capture artifact is missing")
    return {
        "schema_version": RESULT_PACKAGE_SCHEMA_VERSION,
        "identity": identity,
        "outcome": outcome,
        "resource_usage": usage,
        "counts": dict(counts),
        "captures": captures,
        "records": normalized_records,
        "artifacts": normalized_artifacts,
    }


def _read_record_member(
    source: BinaryIO,
    *,
    kind: str,
    expected: Mapping[str, object],
    exact_secrets: Sequence[bytes],
    metadata_sequences: Sequence[bytes],
    retain: bool = True,
    consumer: Callable[[Mapping[str, object]], None] | None = None,
) -> tuple[list[dict[str, object]], str, int]:
    digest = hashlib.sha256()
    observed = 0
    observed_records = 0
    records: list[dict[str, object]] = []
    scanner = _MaterialScanner(
        exact=exact_secrets,
        metadata_only=metadata_sequences,
    )
    while True:
        payload = source.readline(MAX_RESULT_RECORD_LINE_BYTES + 1)
        if not payload:
            break
        if len(payload) > MAX_RESULT_RECORD_LINE_BYTES or not payload.endswith(b"\n"):
            raise ResultPackageError("result package record framing is invalid")
        observed += len(payload)
        if observed > int(expected["size_bytes"]):
            raise ResultPackageError("result package record member is excessive")
        scanner.scan(payload, metadata=True)
        digest.update(payload)
        try:
            raw = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResultPackageError("result package record JSON is invalid") from error
        normalized = _normalize_case(raw) if kind == "cases" else _normalize_failure(raw)
        if consumer is not None:
            consumer(normalized)
        if retain:
            records.append(normalized)
        record_count = len(records) if retain else observed_records + 1
        observed_records = record_count
        if observed_records > int(expected["records"]):
            raise ResultPackageError("result package record count is excessive")
    if observed != expected["size_bytes"] or observed_records != expected["records"]:
        raise ResultPackageError("result package record evidence is incomplete")
    return records, digest.hexdigest(), observed


def validate_result_package(
    path: Path,
    *,
    expected_identity: Mapping[str, object] | None = None,
    expected_sha256: str | None = None,
    prohibited_sequences: Sequence[bytes] = (),
    prohibited_metadata_sequences: Sequence[bytes] = (),
) -> ValidatedResultPackage:
    """Validate the exact immutable package and every contained record/blob."""

    path = Path(path)
    exact_secrets = _normalize_sequences("result package secret policy", prohibited_sequences)
    metadata_sequences = _normalize_sequences(
        "result package metadata policy", prohibited_metadata_sequences
    )
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ResultPackageError("result package is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 1 <= before.st_size <= MAX_RESULT_PACKAGE_BYTES
        ):
            raise ResultPackageError("result package file is unsafe")
        digest = hashlib.sha256()
        observed = 0
        while True:
            payload = os.read(descriptor, 1024 * 1024)
            if not payload:
                break
            observed += len(payload)
            if observed > MAX_RESULT_PACKAGE_BYTES:
                raise ResultPackageError("result package exceeds its byte bound")
            digest.update(payload)
        package_sha256 = digest.hexdigest()
        if expected_sha256 is not None and package_sha256 != _sha256(
            "expected package sha256", expected_sha256
        ):
            raise ResultPackageError("result package digest is contradictory")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source:
            try:
                archive = tarfile.open(fileobj=source, mode="r:")
            except tarfile.TarError as error:
                raise ResultPackageError("result package archive is invalid") from error
            with archive:
                iterator = iter(archive)
                try:
                    manifest_member = next(iterator)
                except StopIteration as error:
                    raise ResultPackageError("result package manifest is missing") from error
                _validate_header(manifest_member, expected_name="manifest.json")
                if not 1 <= manifest_member.size <= MAX_RESULT_PACKAGE_MANIFEST_BYTES:
                    raise ResultPackageError("result package manifest size is invalid")
                manifest_source = archive.extractfile(manifest_member)
                if manifest_source is None:
                    raise ResultPackageError("result package manifest is unavailable")
                manifest_payload = _read_all_bounded(
                    manifest_source,
                    MAX_RESULT_PACKAGE_MANIFEST_BYTES,
                    field="result package manifest",
                )
                metadata_scanner = _MaterialScanner(
                    exact=exact_secrets,
                    metadata_only=metadata_sequences,
                )
                metadata_scanner.scan(manifest_payload, metadata=True)
                manifest = _decode_manifest(manifest_payload)
                if expected_identity is not None and manifest["identity"] != _normalize_identity(
                    expected_identity
                ):
                    raise ResultPackageError("result package identity is contradictory")

                case_ids: set[str] = set()
                failed_case_ids: set[str] = set()
                failure_case_ids: set[str] = set()
                failure_ids: set[str] = set()
                artifact_ids = {item["artifact_id"] for item in manifest["artifacts"]}

                def consume_case(record: Mapping[str, object]) -> None:
                    case_id = str(record["case_id"])
                    if case_id in case_ids:
                        raise ResultPackageError(
                            "result package case identity is duplicated"
                        )
                    case_ids.add(case_id)
                    if record["status"] in {"failed", "error"}:
                        failed_case_ids.add(case_id)

                def consume_failure(record: Mapping[str, object]) -> None:
                    failure_id = str(record["failure_id"])
                    if failure_id in failure_ids:
                        raise ResultPackageError(
                            "result package failure identity is duplicated"
                        )
                    failure_ids.add(failure_id)
                    case_id = record["case_id"]
                    artifact_id = record["artifact_id"]
                    if case_id is not None:
                        if case_id not in case_ids:
                            raise ResultPackageError(
                                "result package failure case is missing"
                            )
                        failure_case_ids.add(str(case_id))
                    if artifact_id is not None and artifact_id not in artifact_ids:
                        raise ResultPackageError(
                            "result package failure artifact is missing"
                        )

                for kind in ("cases", "failures"):
                    try:
                        member = next(iterator)
                    except StopIteration as error:
                        raise ResultPackageError("result package records are missing") from error
                    record_manifest = manifest["records"][kind]
                    _validate_header(member, expected_name=str(record_manifest["name"]))
                    if member.size != record_manifest["size_bytes"]:
                        raise ResultPackageError("result package record size is contradictory")
                    record_source = archive.extractfile(member)
                    if record_source is None:
                        raise ResultPackageError("result package records are unavailable")
                    _records, member_digest, _member_size = _read_record_member(
                        record_source,
                        kind=kind,
                        expected=record_manifest,
                        exact_secrets=exact_secrets,
                        metadata_sequences=metadata_sequences,
                        retain=False,
                        consumer=(consume_case if kind == "cases" else consume_failure),
                    )
                    if member_digest != record_manifest["sha256"]:
                        raise ResultPackageError("result package record digest is contradictory")
                if not failed_case_ids.issubset(failure_case_ids):
                    raise ResultPackageError("result package failed case detail is incomplete")

                for artifact in manifest["artifacts"]:
                    try:
                        member = next(iterator)
                    except StopIteration as error:
                        raise ResultPackageError("result package artifact is missing") from error
                    _validate_header(member, expected_name=str(artifact["member_name"]))
                    if member.size != artifact["size_bytes"]:
                        raise ResultPackageError("result package artifact size is contradictory")
                    artifact_source = archive.extractfile(member)
                    if artifact_source is None:
                        raise ResultPackageError("result package artifact is unavailable")
                    member_digest = hashlib.sha256()
                    member_size = 0
                    scanner = _MaterialScanner(exact=exact_secrets)
                    while True:
                        payload = artifact_source.read(1024 * 1024)
                        if not payload:
                            break
                        member_size += len(payload)
                        if member_size > artifact["size_bytes"]:
                            raise ResultPackageError("result package artifact is excessive")
                        scanner.scan(payload, metadata=False)
                        member_digest.update(payload)
                    if (
                        member_size != artifact["size_bytes"]
                        or member_digest.hexdigest() != artifact["sha256"]
                    ):
                        raise ResultPackageError("result package artifact digest is contradictory")
                try:
                    next(iterator)
                except StopIteration:
                    pass
                else:
                    raise ResultPackageError("result package contains an undeclared member")
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ResultPackageError("result package path changed during validation") from error
        identity = _stable_identity(before)
        if (
            observed != before.st_size
            or identity != _stable_identity(after)
            or identity != _stable_identity(path_after)
        ):
            raise ResultPackageError("result package changed during validation")
    finally:
        os.close(descriptor)

    manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
    evidence = ResultPackageEvidence(
        package_id="result-package-" + package_sha256[:32],
        sha256=package_sha256,
        size_bytes=observed,
        manifest_sha256=manifest_sha256,
        identity=MappingProxyType(dict(manifest["identity"])),
        outcome=MappingProxyType(dict(manifest["outcome"])),
        counts=MappingProxyType(
            {name: int(value) for name, value in manifest["counts"].items()}
        ),
    )
    return ValidatedResultPackage(
        path=path,
        evidence=evidence,
        manifest=MappingProxyType(dict(manifest)),
        file_identity=identity,
    )


def iter_result_package_records(
    package: ValidatedResultPackage, kind: str
) -> Iterator[Mapping[str, object]]:
    """Stream one already-validated record member without exposing other bytes."""

    if not isinstance(package, ValidatedResultPackage) or kind not in {
        "cases",
        "failures",
    }:
        raise ResultPackageError("result package record request is invalid")
    try:
        descriptor = os.open(
            package.path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise ResultPackageError("result package is unavailable") from error
    before = os.fstat(descriptor)
    if _stable_identity(before) != package.file_identity:
        os.close(descriptor)
        raise ResultPackageError("result package identity changed")
    record_manifest = package.manifest["records"][kind]
    try:
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as raw:
            with tarfile.open(fileobj=raw, mode="r:") as archive:
                for member in archive:
                    if member.name != record_manifest["name"]:
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise ResultPackageError(
                            "result package records are unavailable"
                        )
                    digest = hashlib.sha256()
                    observed = 0
                    count = 0
                    while True:
                        payload = source.readline(MAX_RESULT_RECORD_LINE_BYTES + 1)
                        if not payload:
                            break
                        if (
                            len(payload) > MAX_RESULT_RECORD_LINE_BYTES
                            or not payload.endswith(b"\n")
                        ):
                            raise ResultPackageError(
                                "result package record framing changed"
                            )
                        observed += len(payload)
                        count += 1
                        digest.update(payload)
                        try:
                            value = json.loads(payload)
                        except (UnicodeDecodeError, json.JSONDecodeError) as error:
                            raise ResultPackageError(
                                "result package record JSON changed"
                            ) from error
                        yield (
                            _normalize_case(value)
                            if kind == "cases"
                            else _normalize_failure(value)
                        )
                    if (
                        observed != record_manifest["size_bytes"]
                        or count != record_manifest["records"]
                        or digest.hexdigest() != record_manifest["sha256"]
                    ):
                        raise ResultPackageError(
                            "result package record evidence changed"
                        )
                    break
                else:
                    raise ResultPackageError(
                        "result package record member is missing"
                    )
        if (
            _stable_identity(os.fstat(descriptor)) != package.file_identity
            or _stable_identity(package.path.lstat()) != package.file_identity
        ):
            raise ResultPackageError("result package identity changed")
    finally:
        os.close(descriptor)


def copy_result_package_artifact(
    package: ValidatedResultPackage,
    artifact_id: str,
    destination: BinaryIO,
) -> tuple[str, int]:
    """Copy one exact verified artifact member to a trusted caller-owned stream."""

    if not isinstance(package, ValidatedResultPackage) or not hasattr(destination, "write"):
        raise ResultPackageError("result package artifact copy request is invalid")
    artifact_id = _safe_id("artifact_id", artifact_id)
    matches = [
        value
        for value in package.manifest["artifacts"]
        if value["artifact_id"] == artifact_id
    ]
    if len(matches) != 1:
        raise ResultPackageError("result package artifact identity is unavailable")
    artifact = matches[0]
    if _stable_identity(package.path.lstat()) != package.file_identity:
        raise ResultPackageError("result package identity changed")
    with tarfile.open(package.path, mode="r:") as archive:
        for member in archive:
            if member.name != artifact["member_name"]:
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ResultPackageError("result package artifact is unavailable")
            digest = hashlib.sha256()
            observed = 0
            while True:
                payload = source.read(1024 * 1024)
                if not payload:
                    break
                written = destination.write(payload)
                if written is not None and written != len(payload):
                    raise ResultPackageError("result package artifact copy was partial")
                digest.update(payload)
                observed += len(payload)
            if observed != artifact["size_bytes"] or digest.hexdigest() != artifact["sha256"]:
                raise ResultPackageError("result package artifact changed during copy")
            if _stable_identity(package.path.lstat()) != package.file_identity:
                raise ResultPackageError("result package identity changed")
            return digest.hexdigest(), observed
    raise ResultPackageError("result package artifact member is missing")


__all__ = [
    "MAX_RESULT_PACKAGE_ARTIFACTS",
    "MAX_RESULT_PACKAGE_BYTES",
    "MAX_RESULT_PACKAGE_CASES",
    "MAX_RESULT_PACKAGE_FAILURES",
    "RESULT_PACKAGE_FILE_NAME",
    "RESULT_PACKAGE_SCHEMA_VERSION",
    "ResultPackageArtifact",
    "ResultPackageError",
    "ResultPackageEvidence",
    "ValidatedResultPackage",
    "copy_result_package_artifact",
    "iter_result_package_records",
    "publish_result_package",
    "validate_result_package",
]
