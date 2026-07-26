"""Private immutable runtime log artifacts bound to exact Docker identities."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping
import uuid

from .runtime_redaction import redact_runtime_value
from .store import canonical_json, utc_timestamp


RUNTIME_LOG_ARTIFACT_KINDS = frozenset({"docker", "database_stack"})
RUNTIME_LOG_MAX_BYTES = 1_048_576
RUNTIME_LOG_MAX_LINES = 2_000
RUNTIME_LOG_MANIFEST_MAX_BYTES = 32 * 1024


def _canonical_artifact_id(value: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError as error:
        raise ValueError("invalid runtime log artifact identity") from error


def _kind(value: str) -> str:
    if value not in RUNTIME_LOG_ARTIFACT_KINDS:
        raise ValueError("unsupported runtime log artifact kind")
    return value


def _basename(kind: str, artifact_id: str, suffix: str) -> str:
    return f"runtime-{_kind(kind)}-{_canonical_artifact_id(artifact_id)}.{suffix}"


def _latest_basename(kind: str, resource_id: str) -> str:
    digest = hashlib.sha256(
        f"{_kind(kind)}\0{resource_id}".encode("utf-8")
    ).hexdigest()
    return f"runtime-latest-{kind}-{digest}.json"


def _open_private_root(root: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("safe no-follow artifact access is unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(root, flags)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise OSError("runtime artifact root is not private")
    return descriptor


def _write_exclusive(root_fd: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_private_pointer(root_fd: int, name: str, payload: bytes) -> None:
    temporary = f".{name}.{uuid.uuid4()}.tmp"
    _write_exclusive(root_fd, temporary, payload)
    try:
        os.replace(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise


def _bounded_redacted_text(
    raw: bytes, *, request: Mapping[str, Any] | None
) -> tuple[bytes, dict[str, Any]]:
    decoded = raw.decode("utf-8", errors="replace")
    redacted = redact_runtime_value(decoded, request=request)
    if not isinstance(redacted, str):  # pragma: no cover - string input
        raise TypeError("runtime log redaction returned a non-string")
    lines = redacted.splitlines()
    line_truncated = len(lines) > RUNTIME_LOG_MAX_LINES
    selected = lines[-RUNTIME_LOG_MAX_LINES:]
    text = "\n".join(selected)
    if selected and (decoded.endswith("\n") or decoded.endswith("\r")):
        text += "\n"
    encoded = text.encode("utf-8")
    byte_truncated = len(encoded) > RUNTIME_LOG_MAX_BYTES
    if byte_truncated:
        encoded = encoded[-RUNTIME_LOG_MAX_BYTES:]
        # Do not publish a partial UTF-8 codepoint or partial first line.
        text = encoded.decode("utf-8", errors="ignore")
        newline = text.find("\n")
        if newline >= 0:
            text = text[newline + 1 :]
        encoded = text.encode("utf-8")
    final_lines = len(text.splitlines())
    return encoded, {
        "tail_lines": RUNTIME_LOG_MAX_LINES,
        "max_bytes": RUNTIME_LOG_MAX_BYTES,
        "line_count": final_lines,
        "size_bytes": len(encoded),
        "truncated": bool(line_truncated or byte_truncated),
        "line_truncated": line_truncated,
        "byte_truncated": byte_truncated,
    }


def persist_runtime_log_artifact(
    *,
    root: Path,
    artifact_kind: str,
    target_resource_id: str,
    docker_resource_id: str,
    full_container_id: str,
    raw: bytes,
    request: Mapping[str, Any] | None,
    source: str = "docker_logs_exact_container",
    input_discarded_bytes: int = 0,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Redact, bound, and atomically publish one exact-container log capture."""

    kind = _kind(artifact_kind)
    if not target_resource_id or not docker_resource_id or not full_container_id:
        raise ValueError("runtime log artifact requires exact resource identities")
    root = Path(root)
    artifact_id = str(uuid.uuid4())
    log_name = _basename(kind, artifact_id, "log")
    manifest_name = _basename(kind, artifact_id, "json")
    payload, bounds = _bounded_redacted_text(raw, request=request)
    captured = captured_at or utc_timestamp()
    manifest = {
        "schema_version": 1,
        "artifact_id": artifact_id,
        "artifact_kind": kind,
        "target_resource_id": target_resource_id,
        "docker_resource_id": docker_resource_id,
        "full_container_id": full_container_id,
        "source": source,
        "captured_at": captured,
        "filename": log_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "input_discarded_bytes": max(0, int(input_discarded_bytes)),
        **bounds,
    }
    encoded_manifest = (canonical_json(manifest) + "\n").encode("utf-8")
    root_fd = _open_private_root(root)
    try:
        _write_exclusive(root_fd, log_name, payload)
        try:
            _write_exclusive(root_fd, manifest_name, encoded_manifest)
            pointer = {
                "schema_version": 1,
                "artifact_id": artifact_id,
                "artifact_kind": kind,
                "target_resource_id": target_resource_id,
                "docker_resource_id": docker_resource_id,
                "full_container_id": full_container_id,
            }
            _replace_private_pointer(
                root_fd,
                _latest_basename(kind, target_resource_id),
                (canonical_json(pointer) + "\n").encode("utf-8"),
            )
        except BaseException:
            for name in (manifest_name, log_name):
                try:
                    os.unlink(name, dir_fd=root_fd)
                except OSError:
                    pass
            raise
    finally:
        os.close(root_fd)
    return {
        "availability": "available",
        "artifact_id": artifact_id,
        "resource_kind": kind,
        "target_resource_id": target_resource_id,
        "path": str(root / log_name),
        "source": source,
        "captured_at": captured,
        "bounds": {
            "tail_lines": bounds["tail_lines"],
            "max_bytes": bounds["max_bytes"],
        },
        "truncated": bool(bounds["truncated"] or input_discarded_bytes),
    }


def _read_private_file(root_fd: int, name: str, *, maximum: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > maximum
        ):
            raise OSError("runtime artifact file is not private or bounded")
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise OSError("runtime artifact changed while being read")
        return payload
    finally:
        os.close(descriptor)


def load_runtime_log_artifact(
    *, root: Path, artifact_kind: str, artifact_id: str
) -> tuple[dict[str, Any], Path]:
    """Load and verify one private typed artifact manifest and payload."""

    kind = _kind(artifact_kind)
    canonical_id = _canonical_artifact_id(artifact_id)
    root = Path(root)
    root_fd = _open_private_root(root)
    try:
        manifest_payload = _read_private_file(
            root_fd,
            _basename(kind, canonical_id, "json"),
            maximum=RUNTIME_LOG_MANIFEST_MAX_BYTES,
        )
        manifest = json.loads(manifest_payload.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("runtime artifact manifest is not an object")
        expected_name = _basename(kind, canonical_id, "log")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("artifact_id") != canonical_id
            or manifest.get("artifact_kind") != kind
            or manifest.get("filename") != expected_name
            or not isinstance(manifest.get("target_resource_id"), str)
            or not isinstance(manifest.get("docker_resource_id"), str)
            or not isinstance(manifest.get("full_container_id"), str)
            or not isinstance(manifest.get("sha256"), str)
        ):
            raise ValueError("runtime artifact manifest identity is invalid")
        payload = _read_private_file(
            root_fd, expected_name, maximum=RUNTIME_LOG_MAX_BYTES
        )
        if hashlib.sha256(payload).hexdigest() != manifest["sha256"]:
            raise ValueError("runtime artifact payload does not match its manifest")
    finally:
        os.close(root_fd)
    return manifest, root / expected_name


def load_latest_runtime_log_artifact(
    *,
    root: Path,
    artifact_kind: str,
    target_resource_id: str,
    docker_resource_id: str,
    full_container_id: str,
) -> dict[str, Any] | None:
    """Return the latest retained capture only for the same exact identity."""

    kind = _kind(artifact_kind)
    root = Path(root)
    try:
        root_fd = _open_private_root(root)
        try:
            payload = _read_private_file(
                root_fd,
                _latest_basename(kind, target_resource_id),
                maximum=RUNTIME_LOG_MANIFEST_MAX_BYTES,
            )
        finally:
            os.close(root_fd)
        pointer = json.loads(payload.decode("utf-8"))
        if (
            not isinstance(pointer, dict)
            or pointer.get("schema_version") != 1
            or pointer.get("artifact_kind") != kind
            or pointer.get("target_resource_id") != target_resource_id
            or pointer.get("docker_resource_id") != docker_resource_id
            or pointer.get("full_container_id") != full_container_id
        ):
            return None
        manifest, path = load_runtime_log_artifact(
            root=root,
            artifact_kind=kind,
            artifact_id=str(pointer.get("artifact_id") or ""),
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return {
        "availability": "available",
        "artifact_id": manifest["artifact_id"],
        "resource_kind": kind,
        "target_resource_id": target_resource_id,
        "path": str(path),
        "source": "retained_exact_container_log",
        "captured_at": manifest.get("captured_at"),
        "bounds": {
            "tail_lines": RUNTIME_LOG_MAX_LINES,
            "max_bytes": RUNTIME_LOG_MAX_BYTES,
        },
        "truncated": bool(
            manifest.get("truncated") or manifest.get("input_discarded_bytes")
        ),
        "retained": True,
    }
