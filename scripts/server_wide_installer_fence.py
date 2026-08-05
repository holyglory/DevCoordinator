#!/usr/bin/env python3
"""Fail-closed server-wide installer mutex and durable transaction fence.

``flock`` alone protects only one process lifetime.  Availability cutovers
span multiple administrator commands, so a separate root-private file stores
one atomically published transaction claim bound to the canonical lock inode.
Ordinary installers refuse that claim; only the exact transaction path and
operation UUID may resume it.  The claim lives on persistent storage rather
than ``/run`` and therefore survives a process crash or host reboot.

There is deliberately no environment-variable adoption path.  A caller must
provide the exact transaction identity as function arguments, and public CLIs
derive those arguments from their parsed, validated command line or sealed
journal.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Mapping
import uuid


DEFAULT_INSTALLER_LOCK = Path("/run/devcoordinator-installer.lock")
DEFAULT_INSTALLER_CLAIM = Path(
    "/var/lib/devcoordinator-installs/server-wide-installer-fence.json"
)
CLAIM_KIND = "devcoordinator-server-wide-installer-transaction-fence"
CLAIM_SCHEMA_VERSION = 1
MAX_CLAIM_BYTES = 16 * 1024
CONTENTION_PROBE_TIMEOUT_SECONDS = 5.0


class InstallerFenceError(RuntimeError):
    """The global installer boundary or its durable owner is unsafe."""


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _seal(values: Mapping[str, object]) -> dict[str, object]:
    document = {
        "schema_version": CLAIM_SCHEMA_VERSION,
        "kind": CLAIM_KIND,
        **dict(values),
    }
    document["document_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


def _absolute(path: Path | str, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise InstallerFenceError(f"{label} must be an absolute normalized path")
    normalized = Path(os.path.normpath(os.fspath(candidate)))
    if normalized != candidate:
        raise InstallerFenceError(f"{label} must be an absolute normalized path")
    return candidate


def _identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": int(stat.S_IMODE(info.st_mode)),
        "nlink": int(info.st_nlink),
    }


def _require_lock_identity(
    descriptor: int,
    lock_path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_identity: Mapping[str, int] | None = None,
) -> dict[str, int]:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise InstallerFenceError(
            "installer lock must be a single-link regular file owned by the authority with mode 0600"
        )
    try:
        path_info = lock_path.lstat()
    except FileNotFoundError as error:
        raise InstallerFenceError("installer lock path disappeared") from error
    if stat.S_ISLNK(path_info.st_mode) or (
        path_info.st_dev,
        path_info.st_ino,
        path_info.st_uid,
        path_info.st_gid,
        stat.S_IMODE(path_info.st_mode),
        path_info.st_nlink,
    ) != (
        info.st_dev,
        info.st_ino,
        expected_uid,
        expected_gid,
        0o600,
        1,
    ):
        raise InstallerFenceError("installer lock path identity changed")
    identity = _identity(info)
    if expected_identity is not None and dict(expected_identity) != identity:
        raise InstallerFenceError("installer lock inode changed while held")
    return identity


def _require_parent(path: Path, *, expected_uid: int, expected_gid: int) -> None:
    parent = path.parent
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise InstallerFenceError("installer lock parent is not a protected authority directory")


def _require_claim_parent(
    claim_path: Path, *, expected_uid: int, expected_gid: int
) -> None:
    info = claim_path.parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise InstallerFenceError(
            "installer transaction claim parent must be authority-owned mode 0700"
        )


def _ensure_claim_parent(
    claim_path: Path, *, expected_uid: int, expected_gid: int
) -> None:
    parent = claim_path.parent
    if parent.exists() or parent.is_symlink():
        _require_claim_parent(
            claim_path, expected_uid=expected_uid, expected_gid=expected_gid
        )
        return
    ancestor = parent.parent.lstat()
    if (
        stat.S_ISLNK(ancestor.st_mode)
        or not stat.S_ISDIR(ancestor.st_mode)
        or ancestor.st_uid != expected_uid
        or ancestor.st_gid != expected_gid
        or stat.S_IMODE(ancestor.st_mode) & 0o022
    ):
        raise InstallerFenceError("installer transaction claim ancestry is unsafe")
    try:
        parent.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _require_claim_parent(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    descriptor = os.open(
        parent.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _claim_file(
    claim_path: Path, *, expected_uid: int, expected_gid: int
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(claim_path, flags)
    info = os.fstat(descriptor)
    try:
        path_info = claim_path.lstat()
    except BaseException:
        os.close(descriptor)
        raise
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or stat.S_ISLNK(path_info.st_mode)
        or (path_info.st_dev, path_info.st_ino, path_info.st_nlink)
        != (info.st_dev, info.st_ino, 1)
    ):
        os.close(descriptor)
        raise InstallerFenceError("installer transaction claim identity is unsafe")
    return descriptor, info


def _read_claim(
    claim_path: Path, *, expected_uid: int, expected_gid: int
) -> dict[str, object] | None:
    if not claim_path.parent.exists() and not claim_path.parent.is_symlink():
        return None
    _require_claim_parent(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if not claim_path.exists() and not claim_path.is_symlink():
        return None
    descriptor, info = _claim_file(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    try:
        if info.st_size < 2 or info.st_size > MAX_CLAIM_BYTES:
            raise InstallerFenceError("installer transaction claim size is invalid")
        raw = os.read(descriptor, info.st_size)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != info.st_size
        or not raw.endswith(b"\n")
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    ):
        raise InstallerFenceError("installer transaction claim is incomplete")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallerFenceError("installer transaction claim is invalid JSON") from error
    if not isinstance(value, dict):
        raise InstallerFenceError("installer transaction claim must be an object")
    expected_fields = {
        "schema_version",
        "kind",
        "owner_kind",
        "operation_id",
        "transaction",
        "terminal",
        "lock_identity",
        "created_at_epoch",
        "document_sha256",
    }
    if set(value) != expected_fields:
        raise InstallerFenceError("installer transaction claim fields are invalid")
    supplied_digest = value.get("document_sha256")
    unsigned = dict(value)
    unsigned.pop("document_sha256", None)
    if (
        value.get("schema_version") != CLAIM_SCHEMA_VERSION
        or value.get("kind") != CLAIM_KIND
        or not isinstance(supplied_digest, str)
        or hashlib.sha256(_canonical(unsigned)).hexdigest() != supplied_digest
    ):
        raise InstallerFenceError("installer transaction claim seal is invalid")
    try:
        operation_id = str(uuid.UUID(str(value["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise InstallerFenceError("installer transaction claim operation is invalid") from error
    if operation_id != value["operation_id"]:
        raise InstallerFenceError("installer transaction claim operation is not canonical")
    for field in ("transaction", "terminal"):
        if str(_absolute(str(value[field]), f"installer claim {field}")) != value[field]:
            raise InstallerFenceError(f"installer transaction claim {field} is invalid")
    if (
        not isinstance(value["owner_kind"], str)
        or not value["owner_kind"]
        or len(value["owner_kind"]) > 128
        or not isinstance(value["created_at_epoch"], int)
        or value["created_at_epoch"] <= 0
        or not isinstance(value["lock_identity"], dict)
        or set(value["lock_identity"])
        != {"device", "inode", "uid", "gid", "mode", "nlink"}
        or any(type(item) is not int for item in value["lock_identity"].values())
    ):
        raise InstallerFenceError("installer transaction claim binding is invalid")
    return value


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise InstallerFenceError("installer transaction claim write made no progress")
        view = view[written:]


def _publish_claim(
    claim_path: Path,
    claim: Mapping[str, object],
    *,
    expected_uid: int,
    expected_gid: int,
    failpoint=lambda _stage: None,
) -> None:
    """Publish a complete claim with a no-replace link and directory fsync."""

    _ensure_claim_parent(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    payload = _canonical(claim) + b"\n"
    if len(payload) > MAX_CLAIM_BYTES:
        raise InstallerFenceError("installer transaction claim exceeds its byte bound")
    temporary = claim_path.with_name(f".{claim_path.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    linked = False
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        failpoint("after-temp-fsync")
        os.link(temporary, claim_path, follow_symlinks=False)
        linked = True
        failpoint("after-link")
    except FileExistsError as error:
        raise InstallerFenceError("installer transaction claim already exists") from error
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if linked:
            parent = os.open(
                claim_path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent)
            finally:
                os.close(parent)


def _replace_claim(
    claim_path: Path,
    *,
    previous: Mapping[str, object],
    replacement: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Atomically replace one exact durable owner without an ownership gap."""

    retained = _read_claim(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if retained != dict(previous):
        raise InstallerFenceError("installer transaction claim changed before recovery")
    payload = _canonical(replacement) + b"\n"
    temporary = claim_path.with_name(f".{claim_path.name}.{uuid.uuid4().hex}.rebind")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if _read_claim(
            claim_path, expected_uid=expected_uid, expected_gid=expected_gid
        ) != dict(previous):
            raise InstallerFenceError("installer transaction claim changed during recovery")
        os.replace(temporary, claim_path)
        parent = os.open(
            claim_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_claim(
    claim_path: Path,
    *,
    expected: Mapping[str, object],
    expected_uid: int,
    expected_gid: int,
) -> None:
    if _read_claim(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    ) != dict(expected):
        raise InstallerFenceError("installer transaction claim changed before removal")
    descriptor, info = _claim_file(
        claim_path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    os.close(descriptor)
    path_info = claim_path.lstat()
    if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
        raise InstallerFenceError("installer transaction claim inode changed before removal")
    claim_path.unlink()
    parent = os.open(
        claim_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _prove_independent_contention(
    descriptor: int,
    lock_path: Path,
    *,
    expected_identity: Mapping[str, int],
) -> None:
    """Fork a separate process and prove a separately opened FD is excluded."""

    read_fd, write_fd = os.pipe2(getattr(os, "O_CLOEXEC", 0))
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the parent asserts the one-byte result
        try:
            os.close(read_fd)
            os.close(descriptor)
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            candidate = os.open(lock_path, flags)
            try:
                info = os.fstat(candidate)
                if _identity(info) != dict(expected_identity):
                    os.write(write_fd, b"I")
                else:
                    try:
                        fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os.write(write_fd, b"B")
                    else:
                        os.write(write_fd, b"A")
                        fcntl.flock(candidate, fcntl.LOCK_UN)
            finally:
                os.close(candidate)
        except BaseException:
            try:
                os.write(write_fd, b"E")
            except OSError:
                pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass
            os._exit(0)
    os.close(write_fd)
    deadline = time.monotonic() + CONTENTION_PROBE_TIMEOUT_SECONDS
    status: int | None = None
    try:
        while time.monotonic() < deadline:
            completed, status = os.waitpid(pid, os.WNOHANG)
            if completed == pid:
                break
            time.sleep(0.01)
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            raise InstallerFenceError("installer lock contention proof timed out")
        result = os.read(read_fd, 2)
    finally:
        os.close(read_fd)
    if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise InstallerFenceError("installer lock contention probe failed")
    if result != b"B":
        raise InstallerFenceError("installer lock did not exclude an independent process")


def _fsync_terminal(
    terminal: Path, *, expected_uid: int, expected_gid: int
) -> None:
    """Require durable exact terminal evidence before releasing ownership."""

    _require_parent(terminal, expected_uid=expected_uid, expected_gid=expected_gid)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_before = terminal.parent.lstat()
    descriptor = os.open(terminal, flags)
    try:
        info = os.fstat(descriptor)
        path_info = terminal.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > 4 * 1024 * 1024
            or stat.S_ISLNK(path_info.st_mode)
            or (path_info.st_dev, path_info.st_ino, path_info.st_size)
            != (info.st_dev, info.st_ino, info.st_size)
        ):
            raise InstallerFenceError("installer transaction terminal evidence is unsafe")
        os.fsync(descriptor)
        parent_descriptor = os.open(
            terminal.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            parent_open = os.fstat(parent_descriptor)
            parent_after = terminal.parent.lstat()
            if (
                not stat.S_ISDIR(parent_open.st_mode)
                or (parent_open.st_dev, parent_open.st_ino)
                != (parent_before.st_dev, parent_before.st_ino)
                or (parent_after.st_dev, parent_after.st_ino)
                != (parent_before.st_dev, parent_before.st_ino)
            ):
                raise InstallerFenceError(
                    "installer transaction terminal parent changed before fsync"
                )
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)


def _fsync_transaction_evidence(
    transaction: Path,
    *,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Durably bind a successor claim to one exact private transaction file."""

    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise InstallerFenceError(
            "successor installer transaction digest is invalid"
        )
    _require_parent(
        transaction, expected_uid=expected_uid, expected_gid=expected_gid
    )
    parent_before = transaction.parent.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(transaction, flags)
    try:
        info = os.fstat(descriptor)
        path_info = transaction.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > 4 * 1024 * 1024
            or stat.S_ISLNK(path_info.st_mode)
            or (path_info.st_dev, path_info.st_ino, path_info.st_size)
            != (info.st_dev, info.st_ino, info.st_size)
        ):
            raise InstallerFenceError(
                "successor installer transaction evidence is unsafe"
            )
        remaining = int(info.st_size)
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise InstallerFenceError(
                    "successor installer transaction evidence is incomplete"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        path_after = transaction.lstat()
        if (
            digest.hexdigest() != expected_sha256
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            or (
                path_after.st_dev,
                path_after.st_ino,
                path_after.st_size,
                path_after.st_mtime_ns,
                path_after.st_ctime_ns,
            )
            != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        ):
            raise InstallerFenceError(
                "successor installer transaction evidence changed before handoff"
            )
        os.fsync(descriptor)
        parent_descriptor = os.open(
            transaction.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            parent_open = os.fstat(parent_descriptor)
            parent_after = transaction.parent.lstat()
            if (
                not stat.S_ISDIR(parent_open.st_mode)
                or (parent_open.st_dev, parent_open.st_ino)
                != (parent_before.st_dev, parent_before.st_ino)
                or (parent_after.st_dev, parent_after.st_ino)
                != (parent_before.st_dev, parent_before.st_ino)
            ):
                raise InstallerFenceError(
                    "successor installer transaction parent changed before fsync"
                )
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)


@dataclass
class InstallerFenceHandle:
    descriptor: int
    lock_path: Path
    claim_path: Path
    expected_uid: int
    expected_gid: int
    identity: dict[str, int]
    owner: dict[str, object] | None
    transaction_path: Path | None
    terminal_path: Path | None
    created_claim: bool
    depth: int = 1
    _complete: bool = False
    _closed: bool = False

    def mark_complete(self) -> None:
        if self.owner is None:
            raise InstallerFenceError("ordinary installer mutex cannot complete a transaction")
        self._complete = True

    def close(self, *, command_succeeded: bool) -> None:
        if self._closed:
            return
        if self.depth != 1:
            raise InstallerFenceError("installer fence closed while nested")
        try:
            current_identity = _require_lock_identity(
                self.descriptor,
                self.lock_path,
                expected_uid=self.expected_uid,
                expected_gid=self.expected_gid,
                expected_identity=self.identity,
            )
            if self.owner is not None:
                current = _read_claim(
                    self.claim_path,
                    expected_uid=self.expected_uid,
                    expected_gid=self.expected_gid,
                )
                if current != self.owner:
                    raise InstallerFenceError("installer transaction claim changed while held")
                if self._complete:
                    if not command_succeeded:
                        raise InstallerFenceError("failed installer transaction cannot clear its claim")
                    if self.terminal_path is None:
                        raise InstallerFenceError("completed installer transaction lacks terminal evidence")
                    _fsync_terminal(
                        self.terminal_path,
                        expected_uid=self.expected_uid,
                        expected_gid=self.expected_gid,
                    )
                    _remove_claim(
                        self.claim_path,
                        expected=self.owner,
                        expected_uid=self.expected_uid,
                        expected_gid=self.expected_gid,
                    )
                elif (
                    not command_succeeded
                    and self.created_claim
                    and self.transaction_path is not None
                    and not self.transaction_path.exists()
                    and not self.transaction_path.is_symlink()
                ):
                    # A validation/preflight error before the durable journal is
                    # published leaves no transaction to recover.  SIGKILL is
                    # intentionally fail-closed: its provisional claim remains.
                    _remove_claim(
                        self.claim_path,
                        expected=self.owner,
                        expected_uid=self.expected_uid,
                        expected_gid=self.expected_gid,
                    )
            if _require_lock_identity(
                self.descriptor,
                self.lock_path,
                expected_uid=self.expected_uid,
                expected_gid=self.expected_gid,
                expected_identity=current_identity,
            ) != self.identity:
                raise InstallerFenceError("installer lock identity changed during release")
        finally:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self._closed = True
                _ACTIVE.pop(os.getpid(), None)


_ACTIVE: dict[int, InstallerFenceHandle] = {}


def _nested(
    lock_path: Path,
    claim_path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> InstallerFenceHandle | None:
    held = _ACTIVE.get(os.getpid())
    if held is None:
        return None
    if (
        held.lock_path != lock_path
        or held.claim_path != claim_path
        or held.expected_uid != expected_uid
        or held.expected_gid != expected_gid
    ):
        raise InstallerFenceError("nested installer operation changed the global lock identity")
    _require_lock_identity(
        held.descriptor,
        held.lock_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_identity=held.identity,
    )
    held.depth += 1
    return held


def _acquire(
    *,
    expected_uid: int,
    expected_gid: int,
    lock_path: Path,
    claim_path: Path,
) -> tuple[InstallerFenceHandle, dict[str, object] | None]:
    if os.geteuid() != expected_uid:
        raise InstallerFenceError("installer fence requires the exact authority identity")
    lock_path = _absolute(lock_path, "installer lock")
    claim_path = _absolute(claim_path, "installer transaction claim")
    nested = _nested(
        lock_path,
        claim_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if nested is not None:
        return nested, nested.owner
    _require_parent(lock_path, expected_uid=expected_uid, expected_gid=expected_gid)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        identity = _require_lock_identity(
            descriptor,
            lock_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InstallerFenceError("another server-wide installer process is active") from error
        _require_lock_identity(
            descriptor,
            lock_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=identity,
        )
        _prove_independent_contention(
            descriptor, lock_path, expected_identity=identity
        )
        claim = _read_claim(
            claim_path, expected_uid=expected_uid, expected_gid=expected_gid
        )
        handle = InstallerFenceHandle(
            descriptor=descriptor,
            lock_path=lock_path,
            claim_path=claim_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            identity=identity,
            owner=None,
            transaction_path=None,
            terminal_path=None,
            created_claim=False,
        )
        _ACTIVE[os.getpid()] = handle
        return handle, claim
    except BaseException:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)
        raise


def acquire_installer_mutex(
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> InstallerFenceHandle:
    """Acquire the ordinary mutation mutex and refuse any durable owner."""

    handle, claim = _acquire(
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        lock_path=lock_path,
        claim_path=claim_path,
    )
    if handle.depth > 1:
        # Trusted nested helpers participate in their already-held outer
        # transaction.  A separate process cannot reach this branch.
        return handle
    if claim is not None:
        handle.close(command_succeeded=False)
        raise InstallerFenceError(
            "a server-wide cutover transaction owns the installer fence: "
            f"{claim['owner_kind']} {claim['operation_id']}"
        )
    return handle


def acquire_transaction_fence(
    *,
    owner_kind: str,
    operation_id: str,
    transaction: Path,
    terminal: Path,
    action: str,
    expected_uid: int = 0,
    expected_gid: int = 0,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> InstallerFenceHandle:
    """Acquire or resume one exact durable multi-command installer owner."""

    if action not in {"prepare", "finalize", "abort", "recover"}:
        raise InstallerFenceError("installer transaction fence action is invalid")
    if not owner_kind or len(owner_kind) > 128:
        raise InstallerFenceError("installer transaction owner kind is invalid")
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise InstallerFenceError("installer transaction operation is invalid") from error
    transaction = _absolute(transaction, "installer transaction journal")
    terminal = _absolute(terminal, "installer transaction terminal evidence")
    if transaction == terminal:
        raise InstallerFenceError("installer transaction and terminal paths must differ")
    handle, current = _acquire(
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        lock_path=lock_path,
        claim_path=claim_path,
    )
    if handle.depth > 1:
        if handle.owner is None:
            handle.depth -= 1
            raise InstallerFenceError("nested transaction lacks an outer durable owner")
        expected = {
            "owner_kind": owner_kind,
            "operation_id": operation_id,
            "transaction": str(transaction),
            "terminal": str(terminal),
        }
        if any(handle.owner.get(key) != value for key, value in expected.items()):
            handle.depth -= 1
            raise InstallerFenceError("nested installer transaction identity changed")
        return handle
    expected = {
        "owner_kind": owner_kind,
        "operation_id": operation_id,
        "transaction": str(transaction),
        "terminal": str(terminal),
    }
    if current is None:
        if action != "prepare" and not (terminal.exists() and not terminal.is_symlink()):
            handle.close(command_succeeded=False)
            raise InstallerFenceError("installer transaction durable owner is missing")
        claim = _seal(
            {
                **expected,
                "lock_identity": dict(handle.identity),
                "created_at_epoch": int(time.time()),
            }
        )
        _publish_claim(
            handle.claim_path,
            claim,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        handle.created_claim = True
        current = claim
    elif any(current.get(key) != value for key, value in expected.items()):
        handle.close(command_succeeded=False)
        raise InstallerFenceError(
            "another server-wide cutover transaction owns the installer fence"
        )
    if current.get("lock_identity") != handle.identity:
        if (
            not transaction.exists()
            or transaction.is_symlink()
            or transaction.lstat().st_uid != expected_uid
            or transaction.lstat().st_gid != expected_gid
            or not stat.S_ISREG(transaction.lstat().st_mode)
            or stat.S_IMODE(transaction.lstat().st_mode) != 0o600
            or transaction.lstat().st_nlink != 1
            or transaction.lstat().st_size <= 0
        ):
            handle.close(command_succeeded=False)
            raise InstallerFenceError(
                "installer transaction is bound to another lock inode and lacks safe recovery evidence"
            )
        rebound = _seal(
            {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256", "lock_identity"}
            }
            | {"lock_identity": dict(handle.identity)}
        )
        _replace_claim(
            handle.claim_path,
            previous=current,
            replacement=rebound,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        current = rebound
    handle.owner = dict(current)
    handle.transaction_path = transaction
    handle.terminal_path = terminal
    return handle


def transfer_transaction_fence(
    handle: InstallerFenceHandle,
    *,
    successor_owner_kind: str,
    successor_operation_id: str,
    successor_transaction: Path,
    successor_terminal: Path,
    successor_transaction_sha256: str,
) -> dict[str, object]:
    """Atomically transfer a held durable claim to one exact successor.

    The predecessor remains the durable owner until the successor transaction
    file has been identity-checked, content-bound, and fsynced.  ``os.replace``
    then publishes the complete successor claim in one namespace operation and
    the claim directory is fsynced before this function returns.  At no point
    is the claim pathname absent.
    """

    if (
        handle._closed
        or handle.depth != 1
        or handle.owner is None
        or handle._complete
    ):
        raise InstallerFenceError(
            "installer transaction handoff requires one active incomplete durable owner"
        )
    if not successor_owner_kind or len(successor_owner_kind) > 128:
        raise InstallerFenceError("successor installer owner kind is invalid")
    try:
        successor_operation_id = str(uuid.UUID(successor_operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise InstallerFenceError(
            "successor installer operation is invalid"
        ) from error
    successor_transaction = _absolute(
        successor_transaction, "successor installer transaction journal"
    )
    successor_terminal = _absolute(
        successor_terminal, "successor installer terminal evidence"
    )
    if successor_transaction == successor_terminal:
        raise InstallerFenceError(
            "successor installer transaction and terminal paths must differ"
        )
    if {
        successor_transaction,
        successor_terminal,
    } & {handle.lock_path, handle.claim_path}:
        raise InstallerFenceError(
            "successor installer evidence must not alias the global lock or claim"
        )
    _require_parent(
        successor_terminal,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
    )
    predecessor_identity = {
        "owner_kind": handle.owner.get("owner_kind"),
        "operation_id": handle.owner.get("operation_id"),
        "transaction": handle.owner.get("transaction"),
        "terminal": handle.owner.get("terminal"),
    }
    successor_identity = {
        "owner_kind": successor_owner_kind,
        "operation_id": successor_operation_id,
        "transaction": str(successor_transaction),
        "terminal": str(successor_terminal),
    }
    if predecessor_identity == successor_identity:
        raise InstallerFenceError(
            "successor installer transaction must have a distinct durable identity"
        )
    _require_lock_identity(
        handle.descriptor,
        handle.lock_path,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
        expected_identity=handle.identity,
    )
    current = _read_claim(
        handle.claim_path,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
    )
    if current != handle.owner:
        raise InstallerFenceError(
            "installer transaction claim changed before handoff"
        )
    _fsync_transaction_evidence(
        successor_transaction,
        expected_sha256=successor_transaction_sha256,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
    )
    successor = _seal(
        {
            **successor_identity,
            "lock_identity": dict(handle.identity),
            "created_at_epoch": int(time.time()),
        }
    )
    _replace_claim(
        handle.claim_path,
        previous=handle.owner,
        replacement=successor,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
    )
    if _read_claim(
        handle.claim_path,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
    ) != successor:
        raise InstallerFenceError(
            "successor installer transaction claim was not durably published"
        )
    _require_lock_identity(
        handle.descriptor,
        handle.lock_path,
        expected_uid=handle.expected_uid,
        expected_gid=handle.expected_gid,
        expected_identity=handle.identity,
    )
    handle.owner = dict(successor)
    handle.transaction_path = successor_transaction
    handle.terminal_path = successor_terminal
    handle.created_claim = False
    return dict(successor)


def release_nested_installer_fence(handle: InstallerFenceHandle) -> None:
    """Release one in-process nesting level without dropping the outer lock."""

    if handle.depth <= 1:
        raise InstallerFenceError("installer fence is not nested")
    handle.depth -= 1
