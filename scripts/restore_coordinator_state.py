#!/usr/bin/env python3
"""Restore one verified coordinator snapshot while holding its state lock."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path

from secure_cutover_io import SecureIOError, read_private_regular


class RestoreError(RuntimeError):
    pass


def digest_from_checksum(payload: bytes, *, snapshot: Path) -> str:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RestoreError("snapshot checksum is not UTF-8") from error
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RestoreError("snapshot checksum must contain exactly one entry")
    fields = lines[0].split(None, 1)
    if len(fields) != 2:
        raise RestoreError("snapshot checksum entry is malformed")
    digest, recorded_name = fields
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise RestoreError("snapshot checksum is not SHA-256")
    if Path(recorded_name.lstrip("* ")).name != snapshot.name:
        raise RestoreError("snapshot checksum names a different file")
    return digest


def private_home(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise RestoreError("coordinator home must be an absolute direct directory")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise RestoreError("coordinator home is not canonical")
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RestoreError("coordinator home must be a user-owned directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RestoreError("coordinator home must not be accessible by group or others")
    return resolved


def existing_state_digest(home: Path) -> str | None:
    try:
        descriptor = os.open(home / "state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RestoreError("current coordinator state is not a regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(descriptor)


def validate_snapshot_shape(document: dict[str, object]) -> None:
    for key in ("leases", "servers"):
        value = document.get(key)
        if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
            raise RestoreError(f"coordinator rollback snapshot {key} must be an object of objects")
    history = document.get("history")
    if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
        raise RestoreError("coordinator rollback snapshot history must be a list of objects")
    for key in ("port_assignments", "operations", "docker"):
        if key in document and not isinstance(document[key], dict):
            raise RestoreError(f"coordinator rollback snapshot optional {key} must be an object")
    for key in ("version", "revision"):
        value = document.get(key)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise RestoreError(f"coordinator rollback snapshot {key} must be a non-negative integer")
def restore(snapshot: Path, checksum: Path, coordinator_home: Path) -> dict[str, object]:
    payload = read_private_regular(snapshot, label="coordinator rollback snapshot")
    checksum_payload = read_private_regular(checksum, label="coordinator rollback checksum")
    expected = digest_from_checksum(checksum_payload, snapshot=snapshot)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise RestoreError("coordinator rollback snapshot checksum mismatch")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RestoreError("coordinator rollback snapshot is not valid JSON") from error
    if not isinstance(document, dict):
        raise RestoreError("coordinator rollback snapshot root must be an object")
    validate_snapshot_shape(document)
    home = private_home(coordinator_home)
    lock_fd = os.open(
        home / "state.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    lock_metadata = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_uid != os.getuid()
        or stat.S_IMODE(lock_metadata.st_mode) & 0o077
    ):
        os.close(lock_fd)
        raise RestoreError("coordinator state lock must be a private user-owned regular file")
    temporary = home / f".state.json.rollback-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        before = existing_state_digest(home)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, home / "state.json")
        directory_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        after = existing_state_digest(home)
        if after != actual:
            raise RestoreError("restored coordinator state hash is not the verified snapshot hash")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return {
        "ok": True,
        "before_sha256": before,
        "restored_sha256": actual,
        "state_path": str(home / "state.json"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--checksum", type=Path, required=True)
    parser.add_argument("--coordinator-home", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = restore(args.snapshot, args.checksum, args.coordinator_home)
    except (RestoreError, SecureIOError, OSError) as error:
        print(json.dumps({"error": str(error), "type": type(error).__name__}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
