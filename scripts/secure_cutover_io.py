"""No-follow file access for private cutover evidence."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SecureIOError(RuntimeError):
    pass


def absolute_path(path: Path) -> Path:
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else (Path.cwd() / expanded)
    if ".." in absolute.parts:
        raise SecureIOError(f"private evidence path must not contain parent traversal: {path}")
    return absolute


def open_directory_nofollow(path: Path) -> int:
    absolute = absolute_path(path)
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise SecureIOError("no-follow directory access is unavailable on this platform")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(
                part,
                flags | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def trusted_owner_uid(expected_uid: int | None) -> int:
    owner = os.getuid() if expected_uid is None else int(expected_uid)
    if owner < 0 or (owner != os.getuid() and os.geteuid() != 0):
        raise SecureIOError("private evidence owner override requires root")
    return owner


def open_private_parent(
    path: Path, *, expected_uid: int | None = None
) -> tuple[int, Path, str]:
    absolute = absolute_path(path)
    owner_uid = trusted_owner_uid(expected_uid)
    if not absolute.name:
        raise SecureIOError(f"private evidence path has no filename: {path}")
    try:
        descriptor = open_directory_nofollow(absolute.parent)
    except OSError as error:
        raise SecureIOError(f"private evidence parent is unavailable or contains a symlink: {absolute.parent}") from error
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != owner_uid or mode & 0o077:
        os.close(descriptor)
        raise SecureIOError(
            f"private evidence parent must be owned by this user without group/world access: "
            f"{absolute.parent} ({mode:04o})"
        )
    return descriptor, absolute, absolute.name


def read_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
    expected_uid: int | None = None,
) -> bytes:
    owner_uid = trusted_owner_uid(expected_uid)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise SecureIOError(f"{label} is unavailable or not a direct regular file: {name}") from error
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecureIOError(f"{label} must be a regular file: {name}")
        if metadata.st_uid != owner_uid or mode & 0o077:
            raise SecureIOError(
                f"{label} must be owned by this user without group/world access: {name} ({mode:04o})"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def read_private_regular(
    path: Path, *, label: str, expected_uid: int | None = None
) -> bytes:
    parent_descriptor, _absolute, name = open_private_parent(
        path, expected_uid=expected_uid
    )
    try:
        return read_at(
            parent_descriptor,
            name,
            label=label,
            expected_uid=expected_uid,
        )
    finally:
        os.close(parent_descriptor)
