"""Broker-derived private artifact paths for fixed per-UID worker runners."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import uuid

MAX_WORKER_LOG_BYTES = 1024 * 1024
MAX_WORKER_LOG_LINES = 2000
SYSTEM_CLIENT_JOURNAL_ROOT = Path(
    "/Library/Application Support/DevCoordinator/Clients"
    if sys.platform == "darwin"
    else "/var/lib/devcoordinator-clients"
)


class WorkerArtifactError(RuntimeError):
    """A worker log target is missing, unsafe, or does not match its digest."""


def worker_log_directory(execution_uid: int) -> Path:
    if type(execution_uid) is not int or execution_uid < 0:
        raise ValueError("execution_uid must be a non-negative integer")
    return SYSTEM_CLIENT_JOURNAL_ROOT / str(execution_uid) / "logs"


def provision_worker_log_directory(execution_uid: int) -> Path:
    """Create the system-mode peer journal/log roots as root-owned/user-owned 0700."""

    root = SYSTEM_CLIENT_JOURNAL_ROOT
    _require_absolute_safe_root(root)
    created_root = not root.exists()
    root.mkdir(mode=0o711, parents=True, exist_ok=True)
    if created_root:
        os.chmod(root, 0o711)
    _require_directory(root, owner_uid=0, private=False)
    client_root = root / str(execution_uid)
    if client_root.exists() or client_root.is_symlink():
        _require_directory(client_root, owner_uid=execution_uid, private=True)
    else:
        client_root.mkdir(mode=0o700)
        os.chown(client_root, execution_uid, -1)
        os.chmod(client_root, 0o700)
    logs = client_root / "logs"
    if logs.exists() or logs.is_symlink():
        _require_directory(logs, owner_uid=execution_uid, private=True)
    else:
        logs.mkdir(mode=0o700)
        os.chown(logs, execution_uid, -1)
        os.chmod(logs, 0o700)
    _require_directory(client_root, owner_uid=execution_uid, private=True)
    _require_directory(logs, owner_uid=execution_uid, private=True)
    return logs


def worker_log_artifact(execution_uid: int, artifact_id: str) -> dict[str, str]:
    """Derive a path from one canonical runner-produced artifact identity."""

    artifact_id = _canonical_uuid(artifact_id, "artifact_id")
    path = worker_log_directory(execution_uid) / f"worker-attempt-{artifact_id}.log"
    return {"artifact_id": artifact_id, "path": str(path)}


def verify_worker_log_artifact(
    *,
    execution_uid: int,
    artifact_id: str,
    sha256: str,
) -> dict[str, str]:
    """Anchor-open one private log and prove its canonical identity and digest."""

    expected = worker_log_artifact(execution_uid, artifact_id)
    canonical_artifact = _canonical_uuid(artifact_id, "artifact_id")
    if canonical_artifact != expected["artifact_id"]:
        raise WorkerArtifactError(
            "worker log artifact ID does not match the exact attempt"
        )
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise WorkerArtifactError("worker log artifact digest is invalid")

    directory = worker_log_directory(execution_uid)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, flags)
    except OSError as error:
        raise WorkerArtifactError(
            "worker log directory is unavailable or unsafe"
        ) from error
    descriptor = -1
    try:
        _require_private_directory_descriptor(directory_fd, execution_uid)
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                Path(expected["path"]).name,
                file_flags,
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise WorkerArtifactError(
                "worker log artifact is missing or unsafe"
            ) from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_WORKER_LOG_BYTES
        ):
            raise WorkerArtifactError(
                "worker log artifact is not a bounded regular file"
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
        if metadata.st_size and final_byte != b"\n":
            line_count += 1
        if line_count > MAX_WORKER_LOG_LINES:
            raise WorkerArtifactError("worker log artifact exceeds the line bound")
        actual = digest.hexdigest()
        if actual != sha256:
            raise WorkerArtifactError("worker log artifact digest does not match")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)
    return {**expected, "sha256": sha256}


def _canonical_uuid(value: object, field: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(f"{field} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{field} must be a canonical UUID")
    return str(parsed)


def _require_absolute_safe_root(root: Path) -> None:
    if not root.is_absolute() or ".." in root.parts or root == Path(root.anchor):
        raise PermissionError("worker client journal root is unsafe")


def _require_directory(path: Path, *, owner_uid: int, private: bool) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise PermissionError(f"unsafe worker log directory: {path}")


def _require_private_directory_descriptor(descriptor: int, owner_uid: int) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise WorkerArtifactError("worker log directory is not a directory")


__all__ = [
    "MAX_WORKER_LOG_BYTES",
    "MAX_WORKER_LOG_LINES",
    "SYSTEM_CLIENT_JOURNAL_ROOT",
    "WorkerArtifactError",
    "provision_worker_log_directory",
    "verify_worker_log_artifact",
    "worker_log_artifact",
    "worker_log_directory",
]
