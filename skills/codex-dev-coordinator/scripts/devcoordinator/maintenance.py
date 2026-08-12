"""Trusted server-wide maintenance marker shared by every broker client.

The marker lives beside the protected Unix socket so an administrator can
fence cooperative clients before the broker is stopped for an offline schema
transaction. It is independent of both the Coordinator database and wire
schema, which lets clients on either side of an upgrade return the same wait
response while the authority is unavailable.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Any
import uuid


MAINTENANCE_ROOT = Path("/run/devcoordinator-maintenance")
MAINTENANCE_FILENAME = "maintenance.json"
MAINTENANCE_LOCK_FILENAME = "maintenance.lock"
MAINTENANCE_VERSION = 1
MAINTENANCE_MARKER_MODE = 0o644
MAX_MARKER_BYTES = 16 * 1024
MAX_MESSAGE_CHARS = 256
MIN_RETRY_AFTER_SECONDS = 1
MAX_RETRY_AFTER_SECONDS = 3600
CONTROL_PLANE_MAINTENANCE_SCOPE = "server-wide-authority-upgrade"
PUBLIC_MAINTENANCE_MESSAGE = (
    "Coordinator control-plane maintenance is in progress; live controls "
    "will reconnect automatically."
)


class MaintenanceMarkerError(RuntimeError):
    """The maintenance marker exists but is not a trusted exact document."""


@dataclass(frozen=True)
class MaintenanceState:
    deployment_id: str
    message: str
    retry_after_seconds: int
    started_at: str


def marker_path(maintenance_root: Path = MAINTENANCE_ROOT) -> Path:
    root = Path(maintenance_root)
    if not root.is_absolute() or ".." in root.parts:
        raise MaintenanceMarkerError(
            "Coordinator maintenance root must be absolute"
        )
    return root / MAINTENANCE_FILENAME


def _validate_parent(
    path: Path,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance directory cannot be verified"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise MaintenanceMarkerError(
            "Coordinator maintenance path must be a non-symlink directory"
        )
    return metadata


def _decode_state(document: Any) -> MaintenanceState:
    if not isinstance(document, dict) or set(document) != {
        "version",
        "status",
        "deployment_id",
        "message",
        "retry_after_seconds",
        "started_at",
    }:
        raise MaintenanceMarkerError("Coordinator maintenance marker fields are invalid")
    if (
        document.get("version") != MAINTENANCE_VERSION
        or document.get("status") != "active"
    ):
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker version or status is invalid"
        )
    deployment_id = str(document.get("deployment_id") or "")
    try:
        if str(uuid.UUID(deployment_id)) != deployment_id:
            raise ValueError
    except ValueError as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance deployment identity is invalid"
        ) from error
    message = document.get("message")
    if (
        not isinstance(message, str)
        or not message.strip()
        or message != message.strip()
        or len(message) > MAX_MESSAGE_CHARS
        or any(ord(character) < 0x20 for character in message)
    ):
        raise MaintenanceMarkerError("Coordinator maintenance message is invalid")
    retry = document.get("retry_after_seconds")
    if (
        isinstance(retry, bool)
        or not isinstance(retry, int)
        or retry < MIN_RETRY_AFTER_SECONDS
        or retry > MAX_RETRY_AFTER_SECONDS
    ):
        raise MaintenanceMarkerError(
            "Coordinator maintenance retry interval is invalid"
        )
    started_at = document.get("started_at")
    if (
        not isinstance(started_at, str)
        or len(started_at) < 20
        or len(started_at) > 40
        or not started_at.endswith("Z")
        or any(ord(character) < 0x20 for character in started_at)
    ):
        raise MaintenanceMarkerError("Coordinator maintenance timestamp is invalid")
    return MaintenanceState(
        deployment_id=deployment_id,
        message=message,
        retry_after_seconds=retry,
        started_at=started_at,
    )


def load_maintenance_state(
    *,
    maintenance_root: Path = MAINTENANCE_ROOT,
) -> MaintenanceState | None:
    """Return an active marker, absence, or a malformed-marker error.

    The marker is a non-secret same-server availability signal.  Its file
    owner, group, and mode do not authorize a local developer account; only
    structural type, bounded content, and stable descriptor identity matter.
    """

    marker = marker_path(maintenance_root)
    _validate_parent(marker.parent)
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker cannot be inspected"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_MARKER_BYTES
    ):
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker has an invalid type or size"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise MaintenanceMarkerError(
                    "Coordinator maintenance marker changed before it was opened"
                )
            payload = os.read(descriptor, MAX_MARKER_BYTES + 1)
            if len(payload) > MAX_MARKER_BYTES:
                raise MaintenanceMarkerError(
                    "Coordinator maintenance marker exceeds its size bound"
                )
        finally:
            os.close(descriptor)
    except MaintenanceMarkerError:
        raise
    except OSError as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker cannot be read safely"
        ) from error
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker cannot be decoded"
        ) from error
    after = marker.lstat()
    if (after.st_dev, after.st_ino, after.st_size) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
    ):
        raise MaintenanceMarkerError(
            "Coordinator maintenance marker changed while it was read"
        )
    return _decode_state(document)


@contextmanager
def _exclusive_writer(
    maintenance_root: Path,
):
    marker = marker_path(maintenance_root)
    _validate_parent(marker.parent)
    lock = marker.parent / MAINTENANCE_LOCK_FILENAME
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(lock, flags, 0o640)
    except OSError as error:
        raise MaintenanceMarkerError(
            "Coordinator maintenance writer lock cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MaintenanceMarkerError(
                "Coordinator maintenance writer lock is not a regular file"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def maintenance_writer_lock(
    *,
    maintenance_root: Path = MAINTENANCE_ROOT,
    expected_uid: int,
    expected_gid: int,
):
    """Hold the canonical marker-writer exclusion across one fenced operation."""

    del expected_uid, expected_gid
    with _exclusive_writer(maintenance_root):
        yield


def activate_maintenance(
    *,
    expected_uid: int,
    expected_gid: int,
    deployment_id: str,
    scope: str,
    message: str,
    retry_after_seconds: int,
    started_at: str,
    maintenance_root: Path = MAINTENANCE_ROOT,
) -> MaintenanceState:
    """Atomically publish one exact control-plane maintenance marker.

    This fence is not a project progress channel. Requiring the explicit
    server-wide scope and one fixed public message prevents ordinary project
    work from impersonating a Coordinator outage or leaking operator task
    text to every client.
    """

    if scope != CONTROL_PLANE_MAINTENANCE_SCOPE:
        raise MaintenanceMarkerError(
            "maintenance activation is reserved for a server-wide authority upgrade"
        )
    if message != PUBLIC_MAINTENANCE_MESSAGE:
        raise MaintenanceMarkerError(
            "maintenance message must use the fixed public control-plane text"
        )

    state = _decode_state(
        {
            "version": MAINTENANCE_VERSION,
            "status": "active",
            "deployment_id": deployment_id,
            "message": message,
            "retry_after_seconds": retry_after_seconds,
            "started_at": started_at,
        }
    )
    marker = marker_path(maintenance_root)
    with maintenance_writer_lock(
        maintenance_root=maintenance_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    ):
        existing = load_maintenance_state(
            maintenance_root=maintenance_root,
        )
        if existing is not None:
            if existing != state:
                raise MaintenanceMarkerError(
                    "another Coordinator maintenance deployment already owns the marker"
                )
            return existing
        payload = (
            json.dumps(
                {
                    "version": MAINTENANCE_VERSION,
                    "status": "active",
                    "deployment_id": state.deployment_id,
                    "message": state.message,
                    "retry_after_seconds": state.retry_after_seconds,
                    "started_at": state.started_at,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        temporary = marker.parent / f".{MAINTENANCE_FILENAME}.{uuid.uuid4().hex}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchown(descriptor, expected_uid, expected_gid)
            # The marker is an intentionally public, non-secret availability
            # signal.  Every configured local account must be able to read it
            # even when the installation uses no shared Unix group.
            os.fchmod(descriptor, MAINTENANCE_MARKER_MODE)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, marker, follow_symlinks=False)
        except FileExistsError as error:
            raise MaintenanceMarkerError(
                "another Coordinator maintenance deployment published a marker concurrently"
            ) from error
        finally:
            temporary.unlink(missing_ok=True)
        directory = os.open(
            marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return load_maintenance_state(
        maintenance_root=maintenance_root,
    ) or state


def clear_maintenance(
    *,
    expected_uid: int,
    expected_gid: int,
    deployment_id: str,
    maintenance_root: Path = MAINTENANCE_ROOT,
) -> bool:
    """Remove only the marker owned by the exact deployment."""

    marker = marker_path(maintenance_root)
    with maintenance_writer_lock(
        maintenance_root=maintenance_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    ):
        current = load_maintenance_state(
            maintenance_root=maintenance_root,
        )
        if current is None:
            return False
        if current.deployment_id != deployment_id:
            raise MaintenanceMarkerError(
                "maintenance marker belongs to another deployment and was not removed"
            )
        marker.unlink()
        directory = os.open(
            marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return True
