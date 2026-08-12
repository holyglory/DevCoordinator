"""Broker-owned immutable repository snapshot materialization.

The broker/testd boundary invokes a :class:`SnapshotMaterializer`; it never
walks a repository or copies client-controlled paths itself.  The production
filesystem implementation is deliberately usable only while running as the
repository owner.  It publishes a content-addressed, read-only tree after two
identical source scans and an exact destination verification.
"""

from __future__ import annotations

import base64
import binascii
import contextvars
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable

from .universal_test_contract import (
    MAX_MANIFEST_BYTES,
    SourceMode,
    deterministic_fingerprint,
    is_sha256,
    parse_test_manifest,
    safe_history_shard_ceiling,
)
from .universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    SourceIdentity,
    create_test_plan,
    fingerprint_source_content,
)
from .universal_test_store import TestStoreContractError


MAX_SNAPSHOT_FILES = 100_000
MAX_SNAPSHOT_UNTRACKED_FILES = 10_000
MAX_SNAPSHOT_FILE_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SNAPSHOT_UNTRACKED_BYTES = 512 * 1024 * 1024
MAX_GIT_METADATA_BYTES = 256 * 1024 * 1024
MAX_PROVENANCE_BYTES = 64 * 1024 * 1024
MAX_NUGET_LOCK_BYTES = 64 * 1024 * 1024
MAX_NUGET_LOCKED_PACKAGES = 8_192
MAX_NUGET_PACKAGE_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_SNAPSHOT_GITLINKS = 1_024
MAX_SNAPSHOT_GITLINK_DEPTH = 8
_FICLONE = 0x40049409
_MATERIALIZATION_MODES = frozenset({"copy", "mixed", "reflink"})
_COPY_RESULTS = frozenset({"copy", "reflink", "symlink"})
_REFLINK_FALLBACK_ERRNOS = frozenset(
    value
    for value in {
        errno.EINVAL,
        errno.ENOSYS,
        errno.ENOTTY,
        errno.EOPNOTSUPP,
        errno.EXDEV,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
    }
    if isinstance(value, int)
)
_MANIFEST_PATH = ".codex/tests.json"
_LOCK_NAMES = frozenset(
    {
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "package-lock.json",
        "packages.lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)
_NUGET_PACKAGE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}$")


class SnapshotMaterializationError(TestStoreContractError):
    """One repository state cannot become complete immutable test input."""


def nuget_locked_package_requirements(
    documents: Sequence[bytes],
) -> tuple[
    tuple[PurePosixPath, PurePosixPath, PurePosixPath, str], ...
]:
    """Return the exact cache identity files required by NuGet lock documents.

    NuGet's global packages folder is content-addressed by lower-cased package
    ID and resolved version.  A usable offline source requires the exact
    archive as well as NuGet's raw-archive checksum and logical content hash.
    Parsing is deliberately bounded because lock files remain
    repository-controlled input.
    """

    if not documents or sum(len(document) for document in documents) > MAX_NUGET_LOCK_BYTES:
        raise TestStoreContractError("NuGet lock documents are missing or excessive")
    packages: dict[tuple[str, str], str] = {}
    for payload in documents:
        if not payload or len(payload) > MAX_NUGET_LOCK_BYTES:
            raise TestStoreContractError("NuGet lock document is missing or excessive")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("NuGet lock document is invalid") from error
        dependencies = document.get("dependencies") if isinstance(document, Mapping) else None
        if not isinstance(dependencies, Mapping):
            raise TestStoreContractError("NuGet lock dependencies are invalid")
        for framework_packages in dependencies.values():
            if not isinstance(framework_packages, Mapping):
                raise TestStoreContractError("NuGet lock framework is invalid")
            for package_id, package in framework_packages.items():
                if isinstance(package, Mapping) and package.get("type") == "Project":
                    project_dependencies = package.get("dependencies", {})
                    if not isinstance(project_dependencies, Mapping):
                        raise TestStoreContractError(
                            "NuGet project-reference dependencies are invalid"
                        )
                    continue
                resolved = package.get("resolved") if isinstance(package, Mapping) else None
                content_hash = (
                    package.get("contentHash") if isinstance(package, Mapping) else None
                )
                if (
                    not isinstance(package_id, str)
                    or _NUGET_PACKAGE_COMPONENT.fullmatch(package_id) is None
                    or not isinstance(resolved, str)
                    or _NUGET_PACKAGE_COMPONENT.fullmatch(resolved) is None
                    or not isinstance(content_hash, str)
                    or not 1 <= len(content_hash) <= 512
                    or any(character.isspace() for character in content_hash)
                ):
                    raise TestStoreContractError("NuGet locked package identity is invalid")
                identity = (package_id.lower(), resolved.lower())
                prior = packages.setdefault(identity, content_hash)
                if prior != content_hash:
                    raise TestStoreContractError(
                        "NuGet locked package content hash is contradictory"
                    )
                if len(packages) > MAX_NUGET_LOCKED_PACKAGES:
                    raise TestStoreContractError("NuGet locked package set is excessive")
    if not packages:
        raise TestStoreContractError("NuGet locked package set is empty")
    requirements: list[
        tuple[PurePosixPath, PurePosixPath, PurePosixPath, str]
    ] = []
    for (package_id, version), content_hash in sorted(packages.items()):
        package_root = PurePosixPath(package_id, version)
        requirements.append(
            (
                package_root / f"{package_id}.{version}.nupkg",
                package_root / f"{package_id}.{version}.nupkg.sha512",
                package_root / ".nupkg.metadata",
                content_hash,
            )
        )
    return tuple(requirements)


def nuget_locked_package_source_paths(
    documents: Sequence[bytes],
) -> tuple[PurePosixPath, ...]:
    return tuple(
        path
        for archive_path, sha_path, metadata_path, _content_hash in (
            nuget_locked_package_requirements(documents)
        )
        for path in (archive_path, sha_path, metadata_path)
    )


def nuget_package_archive_matches_sha512(
    archive_payload: bytes, sha_payload: bytes
) -> bool:
    """Verify NuGet's raw archive checksum identity without trusting filenames."""

    if not archive_payload:
        raise TestStoreContractError("NuGet package archive checksum is invalid")
    return hashlib.sha512(archive_payload).digest() == nuget_package_sha512_digest(
        sha_payload
    )


def nuget_package_sha512_digest(sha_payload: bytes) -> bytes:
    """Decode NuGet's bounded base64 raw-archive SHA-512 sidecar."""

    if not sha_payload or len(sha_payload) > 1024:
        raise TestStoreContractError("NuGet package archive checksum is invalid")
    try:
        expected = base64.b64decode(sha_payload.strip(), validate=True)
    except (ValueError, binascii.Error) as error:
        raise TestStoreContractError(
            "NuGet package archive checksum is invalid"
        ) from error
    if len(expected) != hashlib.sha512().digest_size:
        raise TestStoreContractError("NuGet package archive checksum is invalid")
    return expected


def nuget_package_archive_file_digests(
    root: Path, relative: PurePosixPath
) -> tuple[str, bytes, int]:
    """Stream one stable archive and return canonical SHA-256 and raw SHA-512."""

    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
        or relative.suffix != ".nupkg"
    ):
        raise TestStoreContractError("NuGet package archive path is invalid")
    candidate = root.joinpath(*relative.parts)
    try:
        root_metadata = root.lstat()
        resolved_root = root.resolve(strict=True)
        path_metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(
            candidate,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise TestStoreContractError("NuGet package archive is unavailable") from error
    canonical = hashlib.sha256()
    canonical.update(b"devcoordinator:test-snapshot:regular\0-\0")
    raw_sha512 = hashlib.sha512()
    observed = 0
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or resolved_root != root
            or not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or resolved != candidate
            or root not in resolved.parents
            or before.st_size <= 0
            or before.st_size > MAX_NUGET_PACKAGE_ARCHIVE_BYTES
            or (before.st_dev, before.st_ino, before.st_size)
            != (path_metadata.st_dev, path_metadata.st_ino, path_metadata.st_size)
        ):
            raise TestStoreContractError("NuGet package archive is unsafe")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_NUGET_PACKAGE_ARCHIVE_BYTES:
                raise TestStoreContractError("NuGet package archive is excessive")
            canonical.update(chunk)
            raw_sha512.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = candidate.lstat()
    except OSError as error:
        raise TestStoreContractError("NuGet package archive changed") from error
    stable = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        observed != before.st_size
        or stable(before) != stable(after)
        or stable(after) != stable(current)
    ):
        raise TestStoreContractError("NuGet package archive changed")
    return canonical.hexdigest(), raw_sha512.digest(), observed


def nuget_package_metadata_content_hash(payload: bytes) -> str:
    """Return NuGet's lock-compatible hash from ``.nupkg.metadata``.

    ``packages.lock.json`` records NuGet's logical package ``contentHash``
    and NuGet repeats that value in ``.nupkg.metadata``.  The neighbouring
    ``*.nupkg.sha512`` hashes the raw downloaded archive and is normally a
    different value.  Both files remain part of the cache identity; only the
    metadata value is comparable with the lock contract.
    """

    if not payload or len(payload) > 64 * 1024:
        raise TestStoreContractError("NuGet package metadata is missing or excessive")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TestStoreContractError("NuGet package metadata is invalid") from error
    content_hash = document.get("contentHash") if isinstance(document, Mapping) else None
    if (
        not isinstance(content_hash, str)
        or not 1 <= len(content_hash) <= 512
        or any(character.isspace() for character in content_hash)
    ):
        raise TestStoreContractError("NuGet package metadata content hash is invalid")
    return content_hash


_SNAPSHOT_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "devcoordinator_snapshot_deadline", default=None
)


def _snapshot_timeout(maximum_seconds: float) -> float:
    """Return one work slice bounded by the active caller launch deadline."""

    deadline = _SNAPSHOT_DEADLINE.get()
    if deadline is None:
        return float(maximum_seconds)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SnapshotMaterializationError(
            "snapshot materialization exceeded the caller launch deadline"
        )
    return max(0.001, min(float(maximum_seconds), remaining))


def _check_snapshot_deadline() -> None:
    _snapshot_timeout(86_400.0)


_GENERIC_SNAPSHOT_SOURCE_DIAGNOSTIC = (
    "The repository test source could not be inspected; verify its Git and "
    "manifest access, then retry."
)


def _diagnostic_repository_path(value: str) -> str | None:
    """Return one bounded repository-relative path suitable for a client."""

    try:
        path = _repository_path(value, "snapshot diagnostic path")
    except SnapshotMaterializationError:
        return None
    return path if len(path) <= 384 else None


def public_snapshot_source_diagnostic(value: object) -> str:
    """Map internal snapshot failures to bounded, allowlisted client detail."""

    message = " ".join(str(value).split())
    unreadable_prefixes = {
        "snapshot file could not be opened safely: ": "unreadable",
        "snapshot file is unavailable: ": "unavailable",
        "snapshot path has an unsafe or unavailable parent: ": "unavailable",
    }
    for prefix, status in unreadable_prefixes.items():
        if message.startswith(prefix):
            detail = message[len(prefix) :]
            path = detail.split(": [Errno ", 1)[0]
            relative = _diagnostic_repository_path(path)
            if relative is not None:
                return f"Snapshot source path is {status}: {relative}."
            return f"A snapshot source path is {status}."

    path_failures = (
        (
            "snapshot file exceeds its bound: ",
            "Snapshot source file exceeds the per-file size limit: {}.",
        ),
        (
            "snapshot file changed while read: ",
            "Snapshot source changed during capture: {}; retry after writes stop.",
        ),
        (
            "snapshot source changed before copy: ",
            "Snapshot source changed during capture: {}; retry after writes stop.",
        ),
        (
            "snapshot symlink target is excluded or incomplete: ",
            "Snapshot symlink targets excluded content: {}.",
        ),
        (
            "absolute symlink is not immutable inside a snapshot: ",
            "Snapshot contains an absolute symlink: {}.",
        ),
    )
    for prefix, template in path_failures:
        if message.startswith(prefix):
            relative = _diagnostic_repository_path(message[len(prefix) :])
            return (
                template.format(relative)
                if relative is not None
                else _GENERIC_SNAPSHOT_SOURCE_DIAGNOSTIC
            )

    exact_failures = {
        "snapshot has too many files": "Snapshot source exceeds the file-count limit.",
        "snapshot contains too many files": "Snapshot source exceeds the file-count limit.",
        "snapshot exceeds its total byte bound": "Snapshot source exceeds the aggregate size limit.",
        "snapshot contains too many untracked files": "Snapshot source exceeds the untracked-file limit.",
        "snapshot untracked content exceeds its byte bound": "Snapshot source exceeds the untracked-byte limit.",
        "snapshot source changed during materialization": (
            "Snapshot source changed during capture; retry after writes stop."
        ),
        "snapshot manifest changed after the plan request was validated": (
            "The test manifest changed during snapshot capture; retry after writes stop."
        ),
        "repository UID helper failed": "The repository-owner inspection helper failed.",
        "repository UID helper output is excessive": (
            "The repository-owner inspection helper exceeded its output limit."
        ),
        "repository UID helper response is invalid": (
            "The repository-owner inspection helper returned an invalid response."
        ),
    }
    if message in exact_failures:
        return exact_failures[message]
    if message.startswith("Git snapshot inspection failed:"):
        return "Git metadata inspection failed for the configured repository."
    if message.startswith("gitlink worktree") or message.startswith(
        "Git index contains an unmerged entry:"
    ):
        return "Git metadata contains an unsupported or incomplete worktree entry."
    return _GENERIC_SNAPSHOT_SOURCE_DIAGNOSTIC


def _linux_ficlone(source_descriptor: int, destination_descriptor: int) -> None:
    """Clone all source extents into an empty destination on Linux."""

    if not sys.platform.startswith("linux"):
        raise OSError(errno.EOPNOTSUPP, "Linux FICLONE is unavailable")
    fcntl.ioctl(destination_descriptor, _FICLONE, source_descriptor)


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise SnapshotMaterializationError(f"{field} must be one absolute path")
    if any(character in value for character in "\x00\r\n\\"):
        raise SnapshotMaterializationError(f"{field} must be a POSIX path")
    pure = PurePosixPath(value)
    if not pure.is_absolute() or any(part in {".", ".."} for part in pure.parts):
        raise SnapshotMaterializationError(f"{field} must be normalized and absolute")
    normalized = str(pure)
    if normalized != value.rstrip("/") and value != "/":
        raise SnapshotMaterializationError(f"{field} must be normalized")
    return Path(normalized)


def _repository_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise SnapshotMaterializationError(f"{field} must be a repository path")
    if any(character in value for character in "\x00\r\n\\"):
        raise SnapshotMaterializationError(f"{field} contains unsafe characters")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotMaterializationError(f"{field} escapes the repository")
    normalized = str(path)
    if normalized != value:
        raise SnapshotMaterializationError(f"{field} must be normalized")
    return normalized


def _identifier(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise SnapshotMaterializationError(f"{field} must be bounded printable ASCII")
    return value


def _snapshot_identifier(value: object) -> str:
    identifier = _identifier(value, "snapshot_id", maximum=41)
    if (
        not identifier.startswith("snapshot-")
        or len(identifier) != 41
        or any(character not in "0123456789abcdef" for character in identifier[9:])
    ):
        raise SnapshotMaterializationError("snapshot_id has an invalid format")
    return identifier


def _lock_file(path: str) -> bool:
    name = PurePosixPath(path).name.casefold()
    return name in _LOCK_NAMES or name.endswith(".lock") or name.endswith("-lock.json")


def snapshot_regular_file_digest(data: bytes, *, executable: bool) -> str:
    """Return the canonical immutable-snapshot identity of one regular file."""

    digest = hashlib.sha256()
    digest.update(b"devcoordinator:test-snapshot:regular\0")
    digest.update(b"x\0" if executable else b"-\0")
    digest.update(data)
    return digest.hexdigest()


def _regular_digest(data: bytes, *, executable: bool) -> str:
    # Internal compatibility alias for the capture paths below.
    return snapshot_regular_file_digest(data, executable=executable)


def _symlink_digest(target: str) -> str:
    return hashlib.sha256(
        b"devcoordinator:test-snapshot:symlink\0" + os.fsencode(target)
    ).hexdigest()


@dataclass(frozen=True)
class SnapshotMaterializationRequest:
    repository_id: str
    original_root: str
    temporary_root: str | None
    manifest_fingerprint: str
    intent: str
    owner_uid: int
    access_uid: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.repository_id, "repository_id")
        original = _absolute_path(self.original_root, "original_root")
        object.__setattr__(self, "original_root", str(original))
        if self.temporary_root is not None:
            temporary = _absolute_path(self.temporary_root, "temporary_root")
            if temporary == original:
                raise SnapshotMaterializationError(
                    "temporary_root must differ from original_root"
                )
            object.__setattr__(self, "temporary_root", str(temporary))
        if not isinstance(self.manifest_fingerprint, str) or not is_sha256(
            self.manifest_fingerprint
        ):
            raise SnapshotMaterializationError(
                "manifest_fingerprint must be a lowercase SHA-256 digest"
            )
        if self.intent not in {
            "change",
            "checkpoint",
            "handoff",
            "release",
            "manual",
        }:
            raise SnapshotMaterializationError(
                "test source intent is unsupported"
            )
        if isinstance(self.owner_uid, bool) or not isinstance(self.owner_uid, int):
            raise SnapshotMaterializationError("owner_uid must be an integer")
        if self.owner_uid < 0:
            raise SnapshotMaterializationError("owner_uid cannot be negative")
        if self.access_uid is not None and (
            isinstance(self.access_uid, bool)
            or not isinstance(self.access_uid, int)
            or self.access_uid <= 0
        ):
            raise SnapshotMaterializationError("access_uid must be a positive integer")

    @property
    def inspection_uid(self) -> int:
        return self.owner_uid if self.access_uid is None else self.access_uid

    @property
    def source_root(self) -> Path:
        return Path(self.temporary_root or self.original_root)


@dataclass(frozen=True)
class SnapshotFile:
    path: str
    digest: str
    size_bytes: int
    executable: bool
    kind: str
    symlink_target: str | None
    tracked: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _repository_path(self.path, "snapshot_file.path"))
        if not isinstance(self.digest, str) or not is_sha256(self.digest):
            raise SnapshotMaterializationError("snapshot file digest is invalid")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 <= self.size_bytes <= MAX_SNAPSHOT_FILE_BYTES
        ):
            raise SnapshotMaterializationError("snapshot file size is invalid")
        if type(self.executable) is not bool or type(self.tracked) is not bool:
            raise SnapshotMaterializationError("snapshot file flags must be booleans")
        if self.kind not in {"regular", "symlink"}:
            raise SnapshotMaterializationError("snapshot file kind is invalid")
        if self.kind == "regular" and self.symlink_target is not None:
            raise SnapshotMaterializationError("regular files cannot have symlink targets")
        if self.kind == "symlink":
            if (
                not isinstance(self.symlink_target, str)
                or not self.symlink_target
                or len(self.symlink_target) > 4096
                or "\x00" in self.symlink_target
            ):
                raise SnapshotMaterializationError("symlink target is invalid")
            if self.executable:
                raise SnapshotMaterializationError("symlink executable mode is undefined")


@dataclass(frozen=True)
class _GitIndexEntry:
    path: str
    mode: str
    object_id: str


class _GitMetadataBudget:
    def __init__(self) -> None:
        self.used_bytes = 0

    def charge(self, raw: bytes) -> None:
        self.used_bytes += len(raw)
        if self.used_bytes > MAX_GIT_METADATA_BYTES:
            raise SnapshotMaterializationError(
                "aggregate Git snapshot metadata exceeded its byte bound"
            )

    @property
    def remaining_bytes(self) -> int:
        return MAX_GIT_METADATA_BYTES - self.used_bytes


class _GitCapture:
    def __init__(self) -> None:
        self.files: list[SnapshotFile] = []
        self.paths: set[str] = set()
        self.total_bytes = 0
        self.untracked_count = 0
        self.untracked_bytes = 0
        self.gitlink_states: list[dict[str, str]] = []
        self.visited_worktrees: set[tuple[int, int]] = set()

    def add_file(self, item: SnapshotFile) -> None:
        if item.path in self.paths:
            raise SnapshotMaterializationError(
                f"snapshot contains a duplicate path: {item.path}"
            )
        if len(self.files) >= MAX_SNAPSHOT_FILES:
            raise SnapshotMaterializationError("snapshot has too many files")
        total_bytes = self.total_bytes + item.size_bytes
        if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES:
            raise SnapshotMaterializationError("snapshot exceeds its total byte bound")
        if not item.tracked:
            untracked_count = self.untracked_count + 1
            if untracked_count > MAX_SNAPSHOT_UNTRACKED_FILES:
                raise SnapshotMaterializationError(
                    "snapshot has too many non-ignored untracked files"
                )
            untracked_bytes = self.untracked_bytes + item.size_bytes
            if untracked_bytes > MAX_SNAPSHOT_UNTRACKED_BYTES:
                raise SnapshotMaterializationError(
                    "snapshot untracked content exceeds its byte bound"
                )
            self.untracked_count = untracked_count
            self.untracked_bytes = untracked_bytes
        self.paths.add(item.path)
        self.files.append(item)
        self.total_bytes = total_bytes


@dataclass(frozen=True)
class SnapshotScan:
    files: tuple[SnapshotFile, ...]
    manifest_fingerprint: str
    manifest_digest: str
    dependency_locks: Mapping[str, str]
    toolchain: Mapping[str, str]
    content_fingerprint: str
    tracked_count: int
    untracked_count: int
    total_bytes: int
    untracked_bytes: int

    def __post_init__(self) -> None:
        paths = tuple(item.path for item in self.files)
        if not self.files or tuple(sorted(set(paths))) != paths:
            raise SnapshotMaterializationError(
                "snapshot files must be non-empty, unique, and sorted"
            )
        if len(self.files) > MAX_SNAPSHOT_FILES:
            raise SnapshotMaterializationError("snapshot contains too many files")
        for field, value in (
            ("manifest_fingerprint", self.manifest_fingerprint),
            ("manifest_digest", self.manifest_digest),
            ("content_fingerprint", self.content_fingerprint),
        ):
            if not isinstance(value, str) or not is_sha256(value):
                raise SnapshotMaterializationError(f"{field} is invalid")
        for field, value, maximum in (
            ("tracked_count", self.tracked_count, MAX_SNAPSHOT_FILES),
            ("untracked_count", self.untracked_count, MAX_SNAPSHOT_UNTRACKED_FILES),
            ("total_bytes", self.total_bytes, MAX_SNAPSHOT_TOTAL_BYTES),
            ("untracked_bytes", self.untracked_bytes, MAX_SNAPSHOT_UNTRACKED_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise SnapshotMaterializationError(f"{field} is outside its bound")
        if self.tracked_count + self.untracked_count != len(self.files):
            raise SnapshotMaterializationError("snapshot file counts are contradictory")
        if sum(item.size_bytes for item in self.files) != self.total_bytes:
            raise SnapshotMaterializationError("snapshot byte count is contradictory")
        if sum(item.size_bytes for item in self.files if not item.tracked) != self.untracked_bytes:
            raise SnapshotMaterializationError("snapshot untracked bytes are contradictory")
        expected = fingerprint_source_content(
            files={item.path: item.digest for item in self.files},
            manifest_fingerprint=self.manifest_fingerprint,
            dependency_locks=self.dependency_locks,
            toolchain=self.toolchain,
        )
        if expected != self.content_fingerprint:
            raise SnapshotMaterializationError("snapshot content fingerprint is invalid")
        object.__setattr__(
            self, "dependency_locks", MappingProxyType(dict(sorted(self.dependency_locks.items())))
        )
        object.__setattr__(self, "toolchain", MappingProxyType(dict(sorted(self.toolchain.items()))))

    def to_document(self) -> dict[str, object]:
        return {
            "files": [
                {
                    "path": item.path,
                    "digest": item.digest,
                    "size_bytes": item.size_bytes,
                    "executable": item.executable,
                    "kind": item.kind,
                    "symlink_target": item.symlink_target,
                    "tracked": item.tracked,
                }
                for item in self.files
            ],
            "manifest_fingerprint": self.manifest_fingerprint,
            "manifest_digest": self.manifest_digest,
            "dependency_locks": dict(self.dependency_locks),
            "toolchain": dict(self.toolchain),
            "content_fingerprint": self.content_fingerprint,
            "tracked_count": self.tracked_count,
            "untracked_count": self.untracked_count,
            "total_bytes": self.total_bytes,
            "untracked_bytes": self.untracked_bytes,
        }

    @classmethod
    def from_document(cls, value: Mapping[str, object]) -> "SnapshotScan":
        fields = {
            "files", "manifest_fingerprint", "manifest_digest",
            "dependency_locks", "toolchain", "content_fingerprint",
            "tracked_count", "untracked_count", "total_bytes", "untracked_bytes",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise SnapshotMaterializationError("snapshot scan fields are invalid")
        raw_files = value["files"]
        if not isinstance(raw_files, Sequence) or isinstance(raw_files, (str, bytes)):
            raise SnapshotMaterializationError("snapshot scan files are invalid")
        file_fields = {
            "path", "digest", "size_bytes", "executable", "kind",
            "symlink_target", "tracked",
        }
        files: list[SnapshotFile] = []
        for raw in raw_files:
            if not isinstance(raw, Mapping) or set(raw) != file_fields:
                raise SnapshotMaterializationError("snapshot scan file fields are invalid")
            files.append(SnapshotFile(**raw))  # type: ignore[arg-type]
        if not isinstance(value["dependency_locks"], Mapping) or not isinstance(
            value["toolchain"], Mapping
        ):
            raise SnapshotMaterializationError("snapshot scan maps are invalid")
        return cls(
            files=tuple(files),
            manifest_fingerprint=value["manifest_fingerprint"],  # type: ignore[arg-type]
            manifest_digest=value["manifest_digest"],  # type: ignore[arg-type]
            dependency_locks=value["dependency_locks"],  # type: ignore[arg-type]
            toolchain=value["toolchain"],  # type: ignore[arg-type]
            content_fingerprint=value["content_fingerprint"],  # type: ignore[arg-type]
            tracked_count=value["tracked_count"],  # type: ignore[arg-type]
            untracked_count=value["untracked_count"],  # type: ignore[arg-type]
            total_bytes=value["total_bytes"],  # type: ignore[arg-type]
            untracked_bytes=value["untracked_bytes"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class SnapshotProvenance:
    snapshot_id: str
    repository_id: str
    original_root: str
    temporary_root: str | None
    materialized_root: str
    content_fingerprint: str
    manifest_fingerprint: str
    manifest_digest: str
    dependency_locks: Mapping[str, str]
    toolchain: Mapping[str, str]
    file_count: int
    tracked_count: int
    untracked_count: int
    total_bytes: int
    materialization_mode: str
    complete: bool = True

    def __post_init__(self) -> None:
        _snapshot_identifier(self.snapshot_id)
        _identifier(self.repository_id, "repository_id")
        _absolute_path(self.original_root, "original_root")
        if self.temporary_root is not None:
            _absolute_path(self.temporary_root, "temporary_root")
        _absolute_path(self.materialized_root, "materialized_root")
        for field, value in (
            ("content_fingerprint", self.content_fingerprint),
            ("manifest_fingerprint", self.manifest_fingerprint),
            ("manifest_digest", self.manifest_digest),
        ):
            if not isinstance(value, str) or not is_sha256(value):
                raise SnapshotMaterializationError(f"{field} is invalid")
        if self.complete is not True:
            raise SnapshotMaterializationError("incomplete snapshots cannot be published")
        for field, value, maximum in (
            ("file_count", self.file_count, MAX_SNAPSHOT_FILES),
            ("tracked_count", self.tracked_count, MAX_SNAPSHOT_FILES),
            ("untracked_count", self.untracked_count, MAX_SNAPSHOT_UNTRACKED_FILES),
            ("total_bytes", self.total_bytes, MAX_SNAPSHOT_TOTAL_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise SnapshotMaterializationError(f"{field} is outside its bound")
        if self.file_count != self.tracked_count + self.untracked_count:
            raise SnapshotMaterializationError("snapshot provenance counts are contradictory")
        if self.materialization_mode not in _MATERIALIZATION_MODES:
            raise SnapshotMaterializationError(
                "snapshot materialization mode is invalid"
            )
        if not isinstance(self.dependency_locks, Mapping) or any(
            not isinstance(path, str)
            or _repository_path(path, "dependency_locks") != path
            or not isinstance(digest, str)
            or not is_sha256(digest)
            for path, digest in self.dependency_locks.items()
        ):
            raise SnapshotMaterializationError("dependency lock provenance is invalid")
        if not isinstance(self.toolchain, Mapping) or any(
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or not isinstance(value, str)
            or len(value) > 4096
            or any(character in value for character in "\x00\r\n")
            for name, value in self.toolchain.items()
        ):
            raise SnapshotMaterializationError("toolchain provenance is invalid")
        object.__setattr__(
            self,
            "dependency_locks",
            MappingProxyType(dict(sorted(self.dependency_locks.items()))),
        )
        object.__setattr__(
            self,
            "toolchain",
            MappingProxyType(dict(sorted(self.toolchain.items()))),
        )

    def source_identity(self) -> SourceIdentity:
        return SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id=self.repository_id,
            content_fingerprint=self.content_fingerprint,
            original_root=self.original_root,
            temporary_root=self.temporary_root,
            snapshot_id=self.snapshot_id,
        )

    def to_document(self, *, include_materialized_root: bool = False) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": 2,
            "snapshot_id": self.snapshot_id,
            "repository_id": self.repository_id,
            "source": self.source_identity().to_document(),
            "manifest_fingerprint": self.manifest_fingerprint,
            "manifest_digest": self.manifest_digest,
            "dependency_locks": dict(self.dependency_locks),
            "toolchain": dict(self.toolchain),
            "file_count": self.file_count,
            "tracked_count": self.tracked_count,
            "untracked_count": self.untracked_count,
            "total_bytes": self.total_bytes,
            "materialization_mode": self.materialization_mode,
            "complete": True,
        }
        if include_materialized_root:
            document["materialized_root"] = self.materialized_root
        return document


@runtime_checkable
class SnapshotSource(Protocol):
    def scan(self, request: SnapshotMaterializationRequest) -> SnapshotScan: ...

    def copy_file(
        self,
        request: SnapshotMaterializationRequest,
        source: SnapshotFile,
        destination: Path,
    ) -> str: ...


@runtime_checkable
class SnapshotMaterializer(Protocol):
    def materialize(self, request: SnapshotMaterializationRequest) -> SnapshotProvenance: ...

    def provenance(self, snapshot_id: str) -> SnapshotProvenance: ...


@dataclass(frozen=True)
class SnapshotRepositoryBinding:
    repository_id: str
    canonical_root: str
    owner_uid: int

    def __post_init__(self) -> None:
        _identifier(self.repository_id, "repository_id")
        root = _absolute_path(self.canonical_root, "canonical_root")
        object.__setattr__(self, "canonical_root", str(root))
        if isinstance(self.owner_uid, bool) or not isinstance(self.owner_uid, int):
            raise SnapshotMaterializationError("owner_uid must be an integer")
        if self.owner_uid < 0:
            raise SnapshotMaterializationError("owner_uid cannot be negative")


@runtime_checkable
class SnapshotRepositoryResolver(Protocol):
    """Resolve only authority-configured identity inside the UID helper."""

    def resolve_as_owner(
        self, *, repository_id: str, owner_uid: int
    ) -> SnapshotRepositoryBinding: ...


class GitSnapshotSource:
    """Read one Git worktree while running as its exact repository owner."""

    def __init__(
        self,
        *,
        enforce_process_uid: bool = True,
        clone_regular_file: Callable[[int, int], None] | None = None,
    ) -> None:
        if clone_regular_file is not None and not callable(clone_regular_file):
            raise SnapshotMaterializationError(
                "clone_regular_file must be callable"
            )
        self._enforce_process_uid = enforce_process_uid
        self._clone_regular_file = clone_regular_file or _linux_ficlone

    @staticmethod
    def _git(root: Path, arguments: Sequence[str], *, maximum_bytes: int) -> bytes:
        try:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                completed = subprocess.run(
                    [
                        "git",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.untrackedCache=false",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        f"safe.directory={root}",
                        "-C",
                        str(root),
                        *arguments,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=errors,
                    check=False,
                    timeout=_snapshot_timeout(60),
                )
                output_size = output.seek(0, os.SEEK_END)
                if output_size > maximum_bytes:
                    raise SnapshotMaterializationError(
                        "Git snapshot metadata exceeded its byte bound"
                    )
                output.seek(0)
                raw = output.read(maximum_bytes + 1)
                if completed.returncode != 0:
                    errors.seek(0)
                    detail = errors.read(64 * 1024).decode(
                        "utf-8", errors="replace"
                    ).strip()
                    unsafe_gitlink = re.search(
                        r"expected submodule path ['\"]([^'\"]+)['\"] not to be a symbolic link",
                        detail,
                    )
                    if unsafe_gitlink is not None:
                        raise SnapshotMaterializationError(
                            "gitlink worktree must be one real directory: "
                            + unsafe_gitlink.group(1)
                        )
                    raise SnapshotMaterializationError(
                        f"Git snapshot inspection failed: {detail or completed.returncode}"
                    )
                return raw
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SnapshotMaterializationError(
                f"Git snapshot inspection failed: {error}"
            ) from error

    @staticmethod
    def _paths(raw: bytes, field: str) -> set[str]:
        paths: set[str] = set()
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                path = _repository_path(os.fsdecode(item), field)
            except UnicodeError as error:
                raise SnapshotMaterializationError(f"{field} is not decodable") from error
            if path in paths:
                raise SnapshotMaterializationError(f"{field} contains a duplicate path")
            paths.add(path)
        return paths

    @staticmethod
    def _object_id(raw: bytes, field: str) -> str:
        try:
            value = raw.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise SnapshotMaterializationError(f"{field} is invalid") from error
        if (
            len(value) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise SnapshotMaterializationError(f"{field} is invalid")
        return value

    @staticmethod
    def _index_entries(raw: bytes) -> dict[str, _GitIndexEntry]:
        entries: dict[str, _GitIndexEntry] = {}
        supported_modes = {"100644", "100755", "120000", "160000"}
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                raw_mode, raw_object_id, raw_stage = metadata.split(b" ")
                mode = raw_mode.decode("ascii", errors="strict")
                object_id = raw_object_id.decode("ascii", errors="strict")
                stage = raw_stage.decode("ascii", errors="strict")
                path = _repository_path(os.fsdecode(raw_path), "tracked path")
            except (UnicodeError, ValueError) as error:
                raise SnapshotMaterializationError(
                    "Git index entry is invalid"
                ) from error
            if stage != "0":
                raise SnapshotMaterializationError(
                    f"Git index contains an unmerged entry: {path}"
                )
            if mode not in supported_modes:
                raise SnapshotMaterializationError(
                    f"Git index entry has an unsupported mode: {path}"
                )
            if (
                len(object_id) not in {40, 64}
                or any(
                    character not in "0123456789abcdef"
                    for character in object_id
                )
            ):
                raise SnapshotMaterializationError(
                    f"Git index entry has an invalid object ID: {path}"
                )
            if path in entries:
                raise SnapshotMaterializationError(
                    f"Git index contains a duplicate path: {path}"
                )
            entries[path] = _GitIndexEntry(path, mode, object_id)
        return entries

    def _budgeted_git(
        self,
        root: Path,
        arguments: Sequence[str],
        *,
        budget: _GitMetadataBudget,
        maximum_bytes: int = MAX_GIT_METADATA_BYTES,
    ) -> bytes:
        if budget.remaining_bytes <= 0:
            raise SnapshotMaterializationError(
                "aggregate Git snapshot metadata exceeded its byte bound"
            )
        raw = self._git(
            root,
            arguments,
            maximum_bytes=min(maximum_bytes, budget.remaining_bytes),
        )
        budget.charge(raw)
        return raw

    @staticmethod
    def _prefixed_path(prefix: str, path: str) -> str:
        combined = f"{prefix}/{path}" if prefix else path
        return _repository_path(combined, "nested snapshot path")

    def _require_worktree(
        self,
        root: Path,
        *,
        owner_uid: int,
        description: str,
        budget: _GitMetadataBudget | None = None,
    ) -> tuple[int, int]:
        identity = self._require_physical_root(
            root,
            owner_uid=owner_uid,
            description=description,
        )
        if budget is None:
            top = self._git(
                root, ["rev-parse", "--show-toplevel"], maximum_bytes=4096
            )
        else:
            top = self._budgeted_git(
                root,
                ["rev-parse", "--show-toplevel"],
                budget=budget,
                maximum_bytes=4096,
            )
        try:
            top_path = Path(top.decode("utf-8", errors="strict").strip())
            exact_top = top_path.resolve(strict=True)
        except (OSError, UnicodeError) as error:
            raise SnapshotMaterializationError(
                f"{description} Git worktree root is invalid"
            ) from error
        if exact_top != root:
            raise SnapshotMaterializationError(
                f"{description} is not the exact Git worktree root"
            )
        return identity

    def _require_physical_root(
        self,
        root: Path,
        *,
        owner_uid: int,
        description: str,
    ) -> tuple[int, int]:
        """Validate an exact physical root without consulting repository content."""

        try:
            metadata = root.lstat()
        except OSError as error:
            raise SnapshotMaterializationError(
                f"{description} is unavailable: {error}"
            ) from error
        if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
            raise SnapshotMaterializationError(
                f"{description} must be one real directory"
            )
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise SnapshotMaterializationError(
                f"{description} is unavailable: {error}"
            ) from error
        if resolved != root:
            raise SnapshotMaterializationError(
                f"{description} path changed during resolution"
            )
        if self._enforce_process_uid and os.geteuid() != owner_uid:
            raise SnapshotMaterializationError(
                "snapshot filesystem capture must run as the repository owner UID"
            )
        return metadata.st_dev, metadata.st_ino

    def _require_owner(self, request: SnapshotMaterializationRequest) -> Path:
        root = request.source_root
        self._require_worktree(
            root,
            owner_uid=request.owner_uid,
            description="snapshot source",
        )
        return root

    def _require_physical_owner(
        self, request: SnapshotMaterializationRequest
    ) -> Path:
        root = request.source_root
        self._require_physical_root(
            root,
            owner_uid=request.owner_uid,
            description="snapshot source",
        )
        return root

    def _require_gitlink_worktree(
        self,
        parent_root: Path,
        relative: str,
        *,
        owner_uid: int,
        budget: _GitMetadataBudget,
    ) -> tuple[Path, tuple[int, int]]:
        parent_descriptor, leaf = self._open_parent(parent_root, relative)
        try:
            metadata = os.stat(
                leaf,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise SnapshotMaterializationError(
                f"gitlink worktree is unavailable: {relative}: {error}"
            ) from error
        finally:
            os.close(parent_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise SnapshotMaterializationError(
                f"gitlink worktree must be one real directory: {relative}"
            )
        nested_root = parent_root / relative
        identity = self._require_worktree(
            nested_root,
            owner_uid=owner_uid,
            description=f"gitlink worktree {relative}",
            budget=budget,
        )
        return nested_root, identity

    @staticmethod
    def _open_parent(root: Path, relative: str) -> tuple[int, str]:
        """Open a leaf parent without ever following an intermediate symlink."""

        parts = PurePosixPath(relative).parts
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(root, flags)
            for part in parts[:-1]:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise SnapshotMaterializationError(
                f"snapshot path has an unsafe or unavailable parent: {relative}: {error}"
            ) from error

    @staticmethod
    def _normalized_link_destination(relative: str, target: str) -> str:
        if PurePosixPath(target).is_absolute():
            raise SnapshotMaterializationError(
                f"absolute symlink is not immutable inside a snapshot: {relative}"
            )
        parts = list(PurePosixPath(relative).parent.parts)
        for part in PurePosixPath(target).parts:
            if part in {"", "."}:
                continue
            if part == "..":
                if not parts:
                    raise SnapshotMaterializationError(
                        f"snapshot symlink escapes repository: {relative}"
                    )
                parts.pop()
            else:
                parts.append(part)
        if not parts:
            raise SnapshotMaterializationError(
                f"snapshot symlink has no materialized destination: {relative}"
            )
        return str(PurePosixPath(*parts))

    @staticmethod
    def _read_file(root: Path, relative: str, *, tracked: bool) -> SnapshotFile:
        _check_snapshot_deadline()
        parent_descriptor, leaf = GitSnapshotSource._open_parent(root, relative)
        descriptor: int | None = None
        try:
            metadata = os.stat(
                leaf,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            os.close(parent_descriptor)
            raise SnapshotMaterializationError(
                f"snapshot file is unavailable: {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(leaf, dir_fd=parent_descriptor)
                GitSnapshotSource._normalized_link_destination(relative, target)
                return SnapshotFile(
                    relative,
                    _symlink_digest(target),
                    len(os.fsencode(target)),
                    False,
                    "symlink",
                    target,
                    tracked,
                )
            finally:
                os.close(parent_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(parent_descriptor)
            raise SnapshotMaterializationError(
                f"snapshot path is not a regular file or symlink: {relative}"
            )
        if metadata.st_size > MAX_SNAPSHOT_FILE_BYTES:
            os.close(parent_descriptor)
            raise SnapshotMaterializationError(f"snapshot file exceeds its bound: {relative}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise SnapshotMaterializationError(
                f"snapshot file could not be opened safely: {relative}: {error}"
            ) from error
        finally:
            os.close(parent_descriptor)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise SnapshotMaterializationError(
                    f"snapshot file changed type while opened: {relative}"
                )
            digest = hashlib.sha256()
            digest.update(b"devcoordinator:test-snapshot:regular\0")
            digest.update(b"x\0" if before.st_mode & 0o111 else b"-\0")
            size = 0
            while True:
                _check_snapshot_deadline()
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_SNAPSHOT_FILE_BYTES:
                    raise SnapshotMaterializationError(
                        f"snapshot file grew beyond its bound: {relative}"
                    )
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
        )
        if identity_before != identity_after or size != after.st_size:
            raise SnapshotMaterializationError(f"snapshot file changed while read: {relative}")
        executable = bool(after.st_mode & 0o111)
        return SnapshotFile(
            relative,
            digest.hexdigest(),
            size,
            executable,
            "regular",
            None,
            tracked,
        )

    @staticmethod
    def _read_exact_regular(
        root: Path,
        source: SnapshotFile,
        *,
        maximum_bytes: int,
    ) -> bytes:
        _check_snapshot_deadline()
        if source.kind != "regular" or source.size_bytes > maximum_bytes:
            raise SnapshotMaterializationError(
                f"snapshot file exceeds its read bound: {source.path}"
            )
        parent_descriptor, leaf = GitSnapshotSource._open_parent(root, source.path)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                leaf,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            raise SnapshotMaterializationError(
                f"snapshot file could not be opened safely: {source.path}: {error}"
            ) from error
        finally:
            os.close(parent_descriptor)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
                raise SnapshotMaterializationError(
                    f"snapshot file changed type or size: {source.path}"
                )
            chunks: list[bytes] = []
            size = 0
            while True:
                _check_snapshot_deadline()
                chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum_bytes:
                    raise SnapshotMaterializationError(
                        f"snapshot file exceeds its read bound: {source.path}"
                    )
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
        ):
            raise SnapshotMaterializationError(
                f"snapshot file changed while read: {source.path}"
            )
        data = b"".join(chunks)
        if (
            len(data) != source.size_bytes
            or _regular_digest(data, executable=source.executable) != source.digest
        ):
            raise SnapshotMaterializationError(
                f"snapshot file differs from its scan: {source.path}"
            )
        return data

    def _scan_repository(
        self,
        *,
        top_root: Path,
        repo_root: Path,
        prefix: str,
        owner_uid: int,
        parent_gitlink_oid: str | None,
        depth: int,
        worktree_identity: tuple[int, int],
        capture: _GitCapture,
        budget: _GitMetadataBudget,
    ) -> dict[str, str]:
        _check_snapshot_deadline()
        if depth > MAX_SNAPSHOT_GITLINK_DEPTH:
            raise SnapshotMaterializationError(
                "snapshot gitlink nesting exceeds its depth bound"
            )
        current_identity = self._require_worktree(
            repo_root,
            owner_uid=owner_uid,
            description=(
                "snapshot source"
                if not prefix
                else f"gitlink worktree {prefix}"
            ),
            budget=budget,
        )
        if current_identity != worktree_identity:
            raise SnapshotMaterializationError(
                f"snapshot Git worktree changed during validation: {prefix or '.'}"
            )
        if current_identity in capture.visited_worktrees:
            raise SnapshotMaterializationError(
                f"snapshot gitlink worktree cycle or duplicate: {prefix or '.'}"
            )
        capture.visited_worktrees.add(current_identity)

        head = self._object_id(
            self._budgeted_git(
                repo_root,
                ["rev-parse", "--verify", "HEAD"],
                budget=budget,
                maximum_bytes=1024,
            ),
            f"Git HEAD for {prefix or '.'}",
        )
        entries = self._index_entries(
            self._budgeted_git(
                repo_root,
                ["ls-files", "--stage", "-z"],
                budget=budget,
            )
        )
        if any(".git" in PurePosixPath(path).parts for path in entries):
            raise SnapshotMaterializationError(
                f"Git metadata cannot be captured from {prefix or '.'}"
            )
        gitlinks = tuple(
            entry for entry in entries.values() if entry.mode == "160000"
        )
        if len(capture.gitlink_states) + len(gitlinks) > MAX_SNAPSHOT_GITLINKS:
            raise SnapshotMaterializationError(
                "snapshot contains too many gitlink worktrees"
            )
        validated_gitlinks: list[
            tuple[_GitIndexEntry, Path, tuple[int, int]]
        ] = []
        for entry in sorted(gitlinks, key=lambda item: item.path):
            _check_snapshot_deadline()
            nested_root, nested_identity = self._require_gitlink_worktree(
                repo_root,
                entry.path,
                owner_uid=owner_uid,
                budget=budget,
            )
            validated_gitlinks.append(
                (entry, nested_root, nested_identity)
            )
        tracked = {
            path for path, entry in entries.items() if entry.mode != "160000"
        }
        untracked = self._paths(
            self._budgeted_git(
                repo_root,
                ["ls-files", "-z", "--others", "--exclude-standard"],
                budget=budget,
            ),
            "untracked path",
        )
        if any(".git" in PurePosixPath(path).parts for path in untracked):
            raise SnapshotMaterializationError(
                f"Git metadata cannot be captured from {prefix or '.'}"
            )
        if (
            capture.untracked_count + len(untracked)
            > MAX_SNAPSHOT_UNTRACKED_FILES
        ):
            raise SnapshotMaterializationError(
                "snapshot has too many non-ignored untracked files"
            )
        deleted = self._paths(
            self._budgeted_git(
                repo_root,
                [
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--name-only",
                    "-z",
                    "--diff-filter=D",
                    "HEAD",
                    "--",
                ],
                budget=budget,
            ),
            "deleted path",
        )
        candidates = (tracked - deleted) | untracked
        if len(capture.files) + len(candidates) > MAX_SNAPSHOT_FILES:
            raise SnapshotMaterializationError("snapshot has too many files")
        for path in sorted(candidates):
            _check_snapshot_deadline()
            snapshot_path = self._prefixed_path(prefix, path)
            capture.add_file(
                self._read_file(
                    top_root,
                    snapshot_path,
                    tracked=path in tracked and path not in untracked,
                )
            )

        index_delta = self._budgeted_git(
            repo_root,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--cached",
                "--binary",
                "--full-index",
                "HEAD",
                "--",
            ],
            budget=budget,
        )
        worktree_delta = self._budgeted_git(
            repo_root,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--full-index",
                "--",
            ],
            budget=budget,
        )
        state = {
            "head": head,
            "index_delta": hashlib.sha256(index_delta).hexdigest(),
            "worktree_delta": hashlib.sha256(worktree_delta).hexdigest(),
        }
        if parent_gitlink_oid is not None:
            if len(capture.gitlink_states) >= MAX_SNAPSHOT_GITLINKS:
                raise SnapshotMaterializationError(
                    "snapshot contains too many gitlink worktrees"
                )
            capture.gitlink_states.append(
                {
                    "path": prefix,
                    "parent_gitlink_oid": parent_gitlink_oid,
                    **state,
                }
            )

        for entry, nested_root, nested_identity in validated_gitlinks:
            _check_snapshot_deadline()
            nested_prefix = self._prefixed_path(prefix, entry.path)
            self._scan_repository(
                top_root=top_root,
                repo_root=nested_root,
                prefix=nested_prefix,
                owner_uid=owner_uid,
                parent_gitlink_oid=entry.object_id,
                depth=depth + 1,
                worktree_identity=nested_identity,
                capture=capture,
                budget=budget,
            )
        return state

    def scan(self, request: SnapshotMaterializationRequest) -> SnapshotScan:
        _check_snapshot_deadline()
        root = self._require_owner(request)
        root_metadata = root.lstat()
        budget = _GitMetadataBudget()
        capture = _GitCapture()
        root_state = self._scan_repository(
            top_root=root,
            repo_root=root,
            prefix="",
            owner_uid=request.owner_uid,
            parent_gitlink_oid=None,
            depth=0,
            worktree_identity=(root_metadata.st_dev, root_metadata.st_ino),
            capture=capture,
            budget=budget,
        )
        files = tuple(sorted(capture.files, key=lambda item: item.path))
        materialized_paths = {item.path for item in files}
        for item in files:
            _check_snapshot_deadline()
            if item.kind != "symlink":
                continue
            destination = self._normalized_link_destination(
                item.path,
                str(item.symlink_target),
            )
            if destination not in materialized_paths and not any(
                path.startswith(destination + "/") for path in materialized_paths
            ):
                raise SnapshotMaterializationError(
                    f"snapshot symlink target is excluded or incomplete: {item.path}"
                )
        manifest_entry = next((item for item in files if item.path == _MANIFEST_PATH), None)
        if manifest_entry is None or manifest_entry.kind != "regular":
            raise SnapshotMaterializationError("snapshot test manifest is missing or not regular")
        if manifest_entry.size_bytes > MAX_MANIFEST_BYTES:
            raise SnapshotMaterializationError("snapshot test manifest exceeds its byte bound")
        try:
            manifest_bytes = self._read_exact_regular(
                root,
                manifest_entry,
                maximum_bytes=MAX_MANIFEST_BYTES,
            )
            manifest_document = json.loads(manifest_bytes.decode("utf-8"))
            manifest = parse_test_manifest(manifest_document, repository_root=root)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise SnapshotMaterializationError("snapshot test manifest is invalid") from error
        if manifest.fingerprint != request.manifest_fingerprint:
            raise SnapshotMaterializationError(
                "snapshot manifest changed after the plan request was validated"
            )
        git_version = subprocess.run(
            ["git", "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=_snapshot_timeout(10),
        ).stdout.decode("utf-8", errors="replace").strip()
        toolchain = {
            "git_head": root_state["head"],
            "git_index_delta": root_state["index_delta"],
            "git_worktree_delta": root_state["worktree_delta"],
            "git_version": git_version,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        if capture.gitlink_states:
            serialized_gitlinks = json.dumps(
                sorted(capture.gitlink_states, key=lambda item: item["path"]),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            toolchain["gitlink_count"] = str(len(capture.gitlink_states))
            toolchain["gitlink_state"] = hashlib.sha256(
                b"devcoordinator:test-snapshot:gitlinks\0" + serialized_gitlinks
            ).hexdigest()
        locks = {item.path: item.digest for item in files if _lock_file(item.path)}
        content_fingerprint = fingerprint_source_content(
            files={item.path: item.digest for item in files},
            manifest_fingerprint=manifest.fingerprint,
            dependency_locks=locks,
            toolchain=toolchain,
        )
        return SnapshotScan(
            files=files,
            manifest_fingerprint=manifest.fingerprint,
            manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
            dependency_locks=locks,
            toolchain=toolchain,
            content_fingerprint=content_fingerprint,
            tracked_count=sum(item.tracked for item in files),
            untracked_count=sum(not item.tracked for item in files),
            total_bytes=capture.total_bytes,
            untracked_bytes=capture.untracked_bytes,
        )

    def _decode_live_changes(
        self,
        raw: bytes,
        *,
        prefix: str,
    ) -> list[ChangedPath]:
        fields = raw.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        changes: list[ChangedPath] = []
        index = 0
        while index < len(fields):
            try:
                status = fields[index].decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise SnapshotMaterializationError(
                    "live change status is invalid"
                ) from error
            index += 1
            if not status:
                raise SnapshotMaterializationError("live change status is empty")
            code = status[0]
            required_paths = 2 if code in {"R", "C"} else 1
            if index + required_paths > len(fields):
                raise SnapshotMaterializationError("live change record is incomplete")
            try:
                paths = [
                    self._prefixed_path(prefix, os.fsdecode(value))
                    for value in fields[index:index + required_paths]
                ]
            except (UnicodeError, ValueError) as error:
                raise SnapshotMaterializationError(
                    "live change path is invalid"
                ) from error
            index += required_paths
            if code == "R":
                changes.append(
                    ChangedPath(
                        path=paths[1],
                        status=ChangeStatus.RENAMED,
                        previous_path=paths[0],
                    )
                )
            elif code == "C":
                # A copied destination is an addition.  Unexpected path mapping
                # still selects the complete intent in the deterministic planner.
                changes.append(ChangedPath(paths[1], ChangeStatus.ADDED))
            elif code == "A":
                changes.append(ChangedPath(paths[0], ChangeStatus.ADDED))
            elif code == "D":
                changes.append(ChangedPath(paths[0], ChangeStatus.DELETED))
            else:
                # Type changes, conflicts and unknown future Git status codes
                # fail toward more testing through the modified-path contract.
                changes.append(ChangedPath(paths[0], ChangeStatus.MODIFIED))
        return changes

    def _discover_repository_changes(
        self,
        *,
        repo_root: Path,
        prefix: str,
        baseline: str,
        owner_uid: int,
        depth: int,
        worktree_identity: tuple[int, int],
        budget: _GitMetadataBudget,
        visited_worktrees: set[tuple[int, int]],
        changes: list[ChangedPath],
        counters: dict[str, int],
    ) -> None:
        if depth > MAX_SNAPSHOT_GITLINK_DEPTH:
            raise SnapshotMaterializationError(
                "live gitlink nesting exceeds its depth bound"
            )
        current_identity = self._require_worktree(
            repo_root,
            owner_uid=owner_uid,
            description=(
                "snapshot source"
                if not prefix
                else f"gitlink worktree {prefix}"
            ),
            budget=budget,
        )
        if current_identity != worktree_identity:
            raise SnapshotMaterializationError(
                f"live Git worktree changed during validation: {prefix or '.'}"
            )
        if current_identity in visited_worktrees:
            raise SnapshotMaterializationError(
                f"live gitlink worktree cycle or duplicate: {prefix or '.'}"
            )
        visited_worktrees.add(current_identity)
        entries = self._index_entries(
            self._budgeted_git(
                repo_root,
                ["ls-files", "--stage", "-z"],
                budget=budget,
            )
        )
        if any(".git" in PurePosixPath(path).parts for path in entries):
            raise SnapshotMaterializationError(
                f"Git metadata cannot be captured from {prefix or '.'}"
            )
        gitlinks = sorted(
            (
                entry
                for entry in entries.values()
                if entry.mode == "160000"
            ),
            key=lambda item: item.path,
        )
        counters["gitlinks"] += len(gitlinks)
        if counters["gitlinks"] > MAX_SNAPSHOT_GITLINKS:
            raise SnapshotMaterializationError(
                "live source contains too many gitlink worktrees"
            )
        validated_gitlinks: list[
            tuple[_GitIndexEntry, Path, tuple[int, int]]
        ] = []
        for entry in gitlinks:
            nested_root, nested_identity = self._require_gitlink_worktree(
                repo_root,
                entry.path,
                owner_uid=owner_uid,
                budget=budget,
            )
            validated_gitlinks.append(
                (entry, nested_root, nested_identity)
            )
        raw = self._budgeted_git(
            repo_root,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-status",
                "-z",
                "-M",
                baseline,
                "--",
            ],
            budget=budget,
        )
        changes.extend(self._decode_live_changes(raw, prefix=prefix))
        untracked = self._paths(
            self._budgeted_git(
                repo_root,
                ["ls-files", "-z", "--others", "--exclude-standard"],
                budget=budget,
            ),
            "untracked path",
        )
        if any(".git" in PurePosixPath(path).parts for path in untracked):
            raise SnapshotMaterializationError(
                f"Git metadata cannot be captured from {prefix or '.'}"
            )
        counters["untracked"] += len(untracked)
        if counters["untracked"] > MAX_SNAPSHOT_UNTRACKED_FILES:
            raise SnapshotMaterializationError(
                "live source has too many non-ignored untracked files"
            )
        changes.extend(
            ChangedPath(
                self._prefixed_path(prefix, path),
                ChangeStatus.UNTRACKED,
            )
            for path in sorted(untracked)
        )
        for entry, nested_root, nested_identity in validated_gitlinks:
            nested_prefix = self._prefixed_path(prefix, entry.path)
            self._discover_repository_changes(
                repo_root=nested_root,
                prefix=nested_prefix,
                baseline=entry.object_id,
                owner_uid=owner_uid,
                depth=depth + 1,
                worktree_identity=nested_identity,
                budget=budget,
                visited_worktrees=visited_worktrees,
                changes=changes,
                counters=counters,
            )

    def discover_live_changes(
        self, request: SnapshotMaterializationRequest
    ) -> tuple[ChangedPath, ...]:
        """Return bounded HEAD-relative changes, including nested gitlinks."""

        root = self._require_owner(request)
        root_metadata = root.lstat()
        changes: list[ChangedPath] = []
        self._discover_repository_changes(
            repo_root=root,
            prefix="",
            baseline="HEAD",
            owner_uid=request.owner_uid,
            depth=0,
            worktree_identity=(root_metadata.st_dev, root_metadata.st_ino),
            budget=_GitMetadataBudget(),
            visited_worktrees=set(),
            changes=changes,
            counters={"untracked": 0, "gitlinks": 0},
        )
        unique = set(changes)
        if len(unique) > MAX_SNAPSHOT_FILES:
            raise SnapshotMaterializationError(
                "live source has too many changed paths"
            )
        return tuple(
            sorted(
                unique,
                key=lambda item: (
                    item.path,
                    item.status.value,
                    item.previous_path or "",
                ),
            )
        )

    def copy_file(
        self,
        request: SnapshotMaterializationRequest,
        source: SnapshotFile,
        destination: Path,
    ) -> str:
        _check_snapshot_deadline()
        # The owner-UID helper already established the Git worktree and emitted
        # the immutable scan.  Root-side materialization must only revalidate
        # the exact physical root and each anchored file: invoking Git here
        # would make a trusted cross-UID copy depend on Git's safe.directory
        # policy once per file.
        root = self._require_physical_owner(request)
        current = self._read_file(root, source.path, tracked=source.tracked)
        if current != source:
            raise SnapshotMaterializationError(f"snapshot source changed before copy: {source.path}")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if source.kind == "symlink":
            os.symlink(str(source.symlink_target), destination)
            return "symlink"
        parent_descriptor, leaf = self._open_parent(root, source.path)
        try:
            source_descriptor = os.open(
                leaf,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            raise SnapshotMaterializationError(
                f"snapshot source could not be opened safely: {source.path}: {error}"
            ) from error
        finally:
            os.close(parent_descriptor)
        try:
            source_metadata = os.fstat(source_descriptor)
        except OSError as error:
            os.close(source_descriptor)
            raise SnapshotMaterializationError(
                f"snapshot source could not be verified safely: {source.path}"
            ) from error
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_size != source.size_bytes
            or bool(source_metadata.st_mode & 0o111) != source.executable
        ):
            os.close(source_descriptor)
            raise SnapshotMaterializationError(
                f"snapshot source changed type, size, or mode before copy: {source.path}"
            )
        try:
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o700 if source.executable else 0o600,
            )
        except OSError as error:
            os.close(source_descriptor)
            raise SnapshotMaterializationError(
                f"snapshot destination could not be opened safely: {source.path}"
            ) from error
        materialization_mode = "reflink"
        try:
            try:
                self._clone_regular_file(
                    source_descriptor, destination_descriptor
                )
            except OSError as error:
                if error.errno not in _REFLINK_FALLBACK_ERRNOS:
                    raise SnapshotMaterializationError(
                        f"snapshot reflink failed without a safe fallback: {source.path}"
                    ) from error
                materialization_mode = "copy"
                try:
                    os.ftruncate(destination_descriptor, 0)
                    os.lseek(source_descriptor, 0, os.SEEK_SET)
                    os.lseek(destination_descriptor, 0, os.SEEK_SET)
                except OSError as reset_error:
                    raise SnapshotMaterializationError(
                        f"snapshot fallback could not reset its descriptors: {source.path}"
                    ) from reset_error
                digest = hashlib.sha256()
                digest.update(b"devcoordinator:test-snapshot:regular\0")
                digest.update(b"x\0" if source.executable else b"-\0")
                size = 0
                while True:
                    _check_snapshot_deadline()
                    chunk = os.read(source_descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    remaining = memoryview(chunk)
                    while remaining:
                        _check_snapshot_deadline()
                        written = os.write(destination_descriptor, remaining)
                        if written <= 0:
                            raise SnapshotMaterializationError(
                                f"snapshot destination write failed: {source.path}"
                            )
                        remaining = remaining[written:]
                if size != source.size_bytes or digest.hexdigest() != source.digest:
                    raise SnapshotMaterializationError(
                        f"snapshot source changed during copy: {source.path}"
                    )
            os.fsync(destination_descriptor)
        finally:
            os.close(source_descriptor)
            os.close(destination_descriptor)
        return materialization_mode


class FilesystemSnapshotMaterializer:
    """Atomically publish verified content-addressed immutable source trees."""

    def __init__(
        self,
        root: Path,
        *,
        source: SnapshotSource | None = None,
        allow_unprotected_test_store: bool = False,
    ) -> None:
        self._root = Path(root).expanduser().absolute()
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._root.is_symlink() or not self._root.is_dir():
            raise SnapshotMaterializationError("snapshot store must be one real directory")
        self._root = self._root.resolve(strict=True)
        root_metadata = self._root.lstat()
        if type(allow_unprotected_test_store) is not bool:
            raise SnapshotMaterializationError(
                "allow_unprotected_test_store must be boolean"
            )
        self._store_owner_uid = root_metadata.st_uid
        self._allow_unprotected_test_store = allow_unprotected_test_store
        self._source = source or GitSnapshotSource()

    @staticmethod
    def _snapshot_id(request: SnapshotMaterializationRequest, scan: SnapshotScan) -> str:
        identity = deterministic_fingerprint(
            {
                "schema_version": 1,
                "repository_id": request.repository_id,
                "content_fingerprint": scan.content_fingerprint,
            }
        )
        return "snapshot-" + identity[:32]

    @staticmethod
    def _make_provenance(
        request: SnapshotMaterializationRequest,
        scan: SnapshotScan,
        snapshot_id: str,
        materialized_root: Path,
        materialization_mode: str,
    ) -> SnapshotProvenance:
        return SnapshotProvenance(
            snapshot_id=snapshot_id,
            repository_id=request.repository_id,
            original_root=request.original_root,
            temporary_root=request.temporary_root,
            materialized_root=str(materialized_root),
            content_fingerprint=scan.content_fingerprint,
            manifest_fingerprint=scan.manifest_fingerprint,
            manifest_digest=scan.manifest_digest,
            dependency_locks=scan.dependency_locks,
            toolchain=scan.toolchain,
            file_count=len(scan.files),
            tracked_count=scan.tracked_count,
            untracked_count=scan.untracked_count,
            total_bytes=scan.total_bytes,
            materialization_mode=materialization_mode,
        )

    @staticmethod
    def _materialization_mode(copy_results: Sequence[str]) -> str:
        if any(result not in _COPY_RESULTS for result in copy_results):
            raise SnapshotMaterializationError(
                "snapshot source returned an invalid copy result"
            )
        regular_modes = {
            result for result in copy_results if result != "symlink"
        }
        if not regular_modes:
            raise SnapshotMaterializationError(
                "snapshot materialization contains no regular file"
            )
        if regular_modes == {"reflink"}:
            return "reflink"
        if regular_modes == {"copy"}:
            return "copy"
        if regular_modes == {"copy", "reflink"}:
            return "mixed"
        raise SnapshotMaterializationError(
            "snapshot materialization modes are contradictory"
        )

    @staticmethod
    def _verify_tree(root: Path, files: Sequence[SnapshotFile]) -> None:
        _check_snapshot_deadline()
        expected = {item.path: item for item in files}
        observed: set[str] = set()

        def visit(directory: Path, prefix: PurePosixPath) -> None:
            for entry in os.scandir(directory):
                _check_snapshot_deadline()
                relative = str(prefix / entry.name)
                if entry.is_symlink():
                    observed.add(relative)
                    target = os.readlink(entry.path)
                    item = expected.get(relative)
                    if item is None or item.kind != "symlink" or item.symlink_target != target:
                        raise SnapshotMaterializationError("materialized symlink differs from source")
                elif entry.is_dir(follow_symlinks=False):
                    visit(Path(entry.path), prefix / entry.name)
                elif entry.is_file(follow_symlinks=False):
                    observed.add(relative)
                    item = expected.get(relative)
                    if item is None or item.kind != "regular":
                        raise SnapshotMaterializationError("materialized file is unexpected")
                    executable = bool(Path(entry.path).stat().st_mode & 0o111)
                    digest = hashlib.sha256()
                    digest.update(b"devcoordinator:test-snapshot:regular\0")
                    digest.update(b"x\0" if executable else b"-\0")
                    size = 0
                    with open(entry.path, "rb", buffering=0) as stream:
                        while True:
                            _check_snapshot_deadline()
                            chunk = stream.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > item.size_bytes:
                                raise SnapshotMaterializationError(
                                    "materialized file grew beyond its source size"
                                )
                            digest.update(chunk)
                    if size != item.size_bytes or digest.hexdigest() != item.digest:
                        raise SnapshotMaterializationError("materialized file digest differs")
                else:
                    raise SnapshotMaterializationError("materialized tree contains a special file")

        visit(root, PurePosixPath())
        if observed != set(expected):
            raise SnapshotMaterializationError("materialized snapshot is incomplete")

    @staticmethod
    def _seal(root: Path) -> None:
        _check_snapshot_deadline()
        directories: list[Path] = []
        for directory, child_directories, files in os.walk(root, topdown=True, followlinks=False):
            _check_snapshot_deadline()
            current = Path(directory)
            directories.append(current)
            for name in files:
                _check_snapshot_deadline()
                path = current / name
                if path.is_symlink():
                    continue
                executable = bool(path.stat().st_mode & 0o111)
                path.chmod(0o555 if executable else 0o444)
            child_directories[:] = [
                name for name in child_directories if not (current / name).is_symlink()
            ]
        for directory in reversed(directories):
            _check_snapshot_deadline()
            directory.chmod(0o555)

    def materialize_with_timeout(
        self,
        request: SnapshotMaterializationRequest,
        *,
        timeout_seconds: float,
    ) -> SnapshotProvenance:
        """Materialize within one aggregate caller-selected launch deadline."""

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0
        ):
            raise SnapshotMaterializationError(
                "snapshot materialization timeout must be a positive finite number"
            )
        token = _SNAPSHOT_DEADLINE.set(
            time.monotonic() + float(timeout_seconds)
        )
        try:
            return self.materialize(request)
        finally:
            _SNAPSHOT_DEADLINE.reset(token)

    def materialize(self, request: SnapshotMaterializationRequest) -> SnapshotProvenance:
        _check_snapshot_deadline()
        if not isinstance(request, SnapshotMaterializationRequest):
            raise SnapshotMaterializationError("snapshot request must be typed")
        if request.intent not in {"handoff", "release", "manual"}:
            raise SnapshotMaterializationError(
                "live test sources cannot be materialized as immutable snapshots"
            )
        before = self._source.scan(request)
        if before.manifest_fingerprint != request.manifest_fingerprint:
            raise SnapshotMaterializationError("snapshot manifest fingerprint is contradictory")
        snapshot_id = self._snapshot_id(request, before)
        final = self._root / snapshot_id
        if final.exists():
            _check_snapshot_deadline()
            existing = self.provenance(snapshot_id)
            expected = self._make_provenance(
                request,
                before,
                snapshot_id,
                final / "root",
                existing.materialization_mode,
            )
            if existing != expected:
                raise SnapshotMaterializationError("snapshot identity collides with different provenance")
            self._verify_tree(final / "root", before.files)
            return existing
        stage = Path(tempfile.mkdtemp(prefix=".snapshot-", dir=self._root))
        published = False
        try:
            materialized_root = stage / "root"
            materialized_root.mkdir(mode=0o700)
            copy_results: list[str] = []
            for item in before.files:
                _check_snapshot_deadline()
                result = self._source.copy_file(
                    request, item, materialized_root / item.path
                )
                if item.kind == "symlink" and result != "symlink":
                    raise SnapshotMaterializationError(
                        "snapshot symlink copy result is contradictory"
                    )
                if item.kind == "regular" and result not in {"copy", "reflink"}:
                    raise SnapshotMaterializationError(
                        "snapshot regular-file copy result is contradictory"
                    )
                copy_results.append(result)
            self._verify_tree(materialized_root, before.files)
            _check_snapshot_deadline()
            after = self._source.scan(request)
            if after != before:
                raise SnapshotMaterializationError(
                    "snapshot source changed during materialization; retry from a fresh plan"
                )
            provenance = self._make_provenance(
                request,
                before,
                snapshot_id,
                final / "root",
                self._materialization_mode(copy_results),
            )
            encoded = (
                json.dumps(
                    provenance.to_document(include_materialized_root=True),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            descriptor = os.open(
                stage / "provenance.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
            try:
                remaining = memoryview(encoded)
                while remaining:
                    _check_snapshot_deadline()
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise SnapshotMaterializationError(
                            "snapshot provenance write failed"
                        )
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._seal(materialized_root)
            _check_snapshot_deadline()
            # Repository owners and transient runners need read/execute access
            # to the sealed tree, while only root may replace the containing
            # snapshot-store entry.  The provenance file remains root-readable.
            stage.chmod(0o555)
            try:
                _check_snapshot_deadline()
                os.rename(stage, final)
                published = True
            except FileExistsError:
                existing = self.provenance(snapshot_id)
                expected = self._make_provenance(
                    request,
                    before,
                    snapshot_id,
                    final / "root",
                    existing.materialization_mode,
                )
                if existing != expected:
                    raise SnapshotMaterializationError(
                        "concurrent snapshot publication produced different provenance"
                    )
                return existing
            return provenance
        finally:
            if not published and stage.exists():
                stage.chmod(0o700)
                for directory, child_directories, files in os.walk(
                    stage, topdown=False, followlinks=False
                ):
                    current = Path(directory)
                    for name in files:
                        path = current / name
                        if not path.is_symlink():
                            path.chmod(0o600)
                    for name in child_directories:
                        path = current / name
                        if not path.is_symlink():
                            path.chmod(0o700)
                    current.chmod(0o700)
                shutil.rmtree(stage)

    def provenance(self, snapshot_id: str) -> SnapshotProvenance:
        _check_snapshot_deadline()
        identifier = _snapshot_identifier(snapshot_id)
        directory = self._root / identifier
        path = directory / "provenance.json"
        try:
            directory_metadata = directory.lstat()
            if not stat.S_ISDIR(directory_metadata.st_mode) or stat.S_ISLNK(
                directory_metadata.st_mode
            ):
                raise SnapshotMaterializationError(
                    "snapshot directory is missing or unsafe"
                )
            path_metadata = path.lstat()
            if (
                not stat.S_ISREG(path_metadata.st_mode)
                or stat.S_ISLNK(path_metadata.st_mode)
                or path_metadata.st_size > MAX_PROVENANCE_BYTES
            ):
                raise SnapshotMaterializationError(
                    "snapshot provenance file is missing or unsafe"
                )
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                raw_buffer = bytearray()
                while True:
                    _check_snapshot_deadline()
                    chunk = os.read(descriptor, 64 * 1024)
                    if not chunk:
                        break
                    raw_buffer.extend(chunk)
                    if len(raw_buffer) > MAX_PROVENANCE_BYTES:
                        raise SnapshotMaterializationError(
                            "snapshot provenance exceeds its byte bound"
                        )
            finally:
                os.close(descriptor)
            raw = json.loads(bytes(raw_buffer).decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SnapshotMaterializationError("snapshot provenance is unavailable") from error
        expected_fields = {
            "schema_version",
            "snapshot_id",
            "repository_id",
            "source",
            "manifest_fingerprint",
            "manifest_digest",
            "dependency_locks",
            "toolchain",
            "file_count",
            "tracked_count",
            "untracked_count",
            "total_bytes",
            "materialization_mode",
            "complete",
            "materialized_root",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields or raw.get("schema_version") != 2:
            raise SnapshotMaterializationError("snapshot provenance contract is invalid")
        source = raw.get("source")
        if (
            not isinstance(source, dict)
            or set(source)
            != {
                "mode",
                "repository_id",
                "content_fingerprint",
                "original_root",
                "temporary_root",
                "snapshot_id",
            }
            or source.get("mode") != "immutable"
            or source.get("repository_id") != raw.get("repository_id")
            or source.get("snapshot_id") != raw.get("snapshot_id")
        ):
            raise SnapshotMaterializationError("snapshot source provenance is invalid")
        provenance = SnapshotProvenance(
            snapshot_id=raw["snapshot_id"],
            repository_id=raw["repository_id"],
            original_root=source["original_root"],
            temporary_root=source["temporary_root"],
            materialized_root=raw["materialized_root"],
            content_fingerprint=source["content_fingerprint"],
            manifest_fingerprint=raw["manifest_fingerprint"],
            manifest_digest=raw["manifest_digest"],
            dependency_locks=raw["dependency_locks"],
            toolchain=raw["toolchain"],
            file_count=raw["file_count"],
            tracked_count=raw["tracked_count"],
            untracked_count=raw["untracked_count"],
            total_bytes=raw["total_bytes"],
            materialization_mode=raw["materialization_mode"],
            complete=raw["complete"],
        )
        if provenance.snapshot_id != identifier:
            raise SnapshotMaterializationError("snapshot provenance identity is contradictory")
        if Path(provenance.materialized_root) != directory / "root":
            raise SnapshotMaterializationError("snapshot materialized root is contradictory")
        try:
            materialized_metadata = Path(provenance.materialized_root).lstat()
        except OSError as error:
            raise SnapshotMaterializationError(
                "snapshot materialized tree is missing"
            ) from error
        if not stat.S_ISDIR(materialized_metadata.st_mode) or stat.S_ISLNK(
            materialized_metadata.st_mode
        ):
            raise SnapshotMaterializationError("snapshot materialized tree is missing")
        return provenance


class ImmutableSnapshotPlanPreviewer:
    """Repository-UID helper that plans only from a verified snapshot.

    The public preview seam contains only repository identity and intent.  An
    injected authority resolver supplies the canonical root inside the UID
    helper.  The helper must itself be launched as ``owner_uid``.
    """

    def __init__(
        self,
        materializer: SnapshotMaterializer,
        resolver: SnapshotRepositoryResolver,
    ) -> None:
        if not isinstance(materializer, SnapshotMaterializer):
            raise SnapshotMaterializationError("snapshot materializer is invalid")
        if not isinstance(resolver, SnapshotRepositoryResolver):
            raise SnapshotMaterializationError("snapshot repository resolver is invalid")
        self._materializer = materializer
        self._resolver = resolver

    @staticmethod
    def _manifest(root: Path, *, owner_uid: int):
        try:
            metadata = root.lstat()
        except OSError as error:
            raise SnapshotMaterializationError("snapshot repository is unavailable") from error
        if os.geteuid() != owner_uid:
            raise SnapshotMaterializationError(
                "immutable plan preview must run as the repository owner UID"
            )
        try:
            manifest_file = GitSnapshotSource._read_file(
                root,
                _MANIFEST_PATH,
                tracked=True,
            )
            raw = GitSnapshotSource._read_exact_regular(
                root,
                manifest_file,
                maximum_bytes=MAX_MANIFEST_BYTES,
            )
            return parse_test_manifest(
                json.loads(raw.decode("utf-8")), repository_root=root
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise SnapshotMaterializationError("snapshot test manifest is invalid") from error

    @staticmethod
    def _setup_status(repository_id: str, status: str) -> Mapping[str, object]:
        code = "manifest_missing" if status == "missing" else "manifest_invalid"
        return {
            "schema_version": 1,
            "repository_id": repository_id,
            "ok": False,
            "status": status,
            "manifest_schema": None,
            "manifest_fingerprint": None,
            "targets": [],
            "target_graph": {},
            "input_coverage": {
                "global_input_count": 0,
                "target_input_count": 0,
                "targets_with_inputs": 0,
            },
            "input_coverage_gaps": [],
            "intents": [],
            "evidence_policies": [],
            "fixtures": [],
            "network_requirements": [],
            "isolation": {
                "network": "none",
                "cpu_millis": 0,
                "memory_mib": 0,
                "pids": 0,
                "private_scratch": True,
                "kill_after_run": True,
            },
            "issues": [
                {
                    "code": code,
                    "message": f"repository test manifest is {status}",
                }
            ],
        }

    def setup_as_owner(
        self,
        *,
        repository_id: str,
        owner_uid: int,
    ) -> Mapping[str, object]:
        binding = self._resolver.resolve_as_owner(
            repository_id=repository_id, owner_uid=owner_uid
        )
        if (
            not isinstance(binding, SnapshotRepositoryBinding)
            or binding.repository_id != repository_id
            or binding.owner_uid != owner_uid
        ):
            raise SnapshotMaterializationError(
                "snapshot resolver returned contradictory repository authority"
            )
        root = Path(binding.canonical_root)
        metadata = root.lstat()
        if os.geteuid() != owner_uid:
            raise SnapshotMaterializationError(
                "repository setup inspection must run as the repository owner UID"
            )
        try:
            (root / ".codex" / "tests.json").lstat()
        except FileNotFoundError:
            return self._setup_status(repository_id, "missing")
        except OSError:
            return self._setup_status(repository_id, "invalid")
        try:
            manifest = self._manifest(root, owner_uid=owner_uid)
        except Exception:
            return self._setup_status(repository_id, "invalid")

        network_rank = {
            "none": 0,
            "loopback": 1,
            "host-loopback": 2,
            "external": 3,
        }
        networks = sorted(
            {
                *(target.network for target in manifest.targets.values()),
                *(fixture.network for fixture in manifest.fixtures.values()),
            },
            key=network_rank.__getitem__,
        )
        document: Mapping[str, object] = {
            "schema_version": 1,
            "repository_id": repository_id,
            "ok": True,
            "status": "ready",
            "manifest_schema": manifest.schema_version,
            "manifest_fingerprint": manifest.fingerprint,
            "targets": [
                {
                    "name": name,
                    "driver": target.driver,
                    "reporter": target.reporter,
                    "network": target.network,
                    "fixtures": sorted(target.fixtures),
                    "depends_on": sorted(target.depends_on),
                    "resources": {
                        "cpu_millis": target.resources.cpu_millis,
                        "memory_mib": target.resources.memory_mib,
                        "pids": target.resources.pids,
                    },
                }
                for name, target in sorted(manifest.targets.items())
            ],
            "target_graph": {
                name: sorted(target.depends_on)
                for name, target in sorted(manifest.targets.items())
            },
            "input_coverage": {
                "global_input_count": len(manifest.global_inputs),
                "target_input_count": sum(
                    len(target.inputs) for target in manifest.targets.values()
                ),
                "targets_with_inputs": sum(
                    bool(target.inputs) for target in manifest.targets.values()
                ),
            },
            "input_coverage_gaps": [],
            "intents": sorted(manifest.intents),
            "evidence_policies": sorted(manifest.evidence_policies),
            "fixtures": sorted(manifest.fixtures),
            "network_requirements": networks,
            "isolation": {
                "network": max(networks, key=network_rank.__getitem__),
                "cpu_millis": max(
                    target.resources.cpu_millis for target in manifest.targets.values()
                ),
                "memory_mib": max(
                    target.resources.memory_mib for target in manifest.targets.values()
                ),
                "pids": max(
                    target.resources.pids for target in manifest.targets.values()
                ),
                "private_scratch": True,
                "kill_after_run": True,
            },
            "issues": [],
        }
        if len(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ) > 192 * 1024:
            result = dict(self._setup_status(repository_id, "invalid"))
            result["issues"] = [
                {
                    "code": "manifest_setup_too_large",
                    "message": "repository test manifest is invalid",
                }
            ]
            return result
        return document

    def preview_as_owner(
        self,
        *,
        repository_id: str,
        intent: str,
        actor: str,
        owner_uid: int,
        access_uid: int | None = None,
        temporary_root: str | None = None,
        requested_targets: Sequence[str] = (),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = 300,
        launch_deadline_monotonic: float | None = None,
    ) -> Mapping[str, object]:
        del actor
        if launch_deadline_monotonic is not None and (
            isinstance(launch_deadline_monotonic, bool)
            or not isinstance(launch_deadline_monotonic, (int, float))
            or not math.isfinite(float(launch_deadline_monotonic))
            or float(launch_deadline_monotonic) <= 0
        ):
            raise SnapshotMaterializationError(
                "snapshot preview launch deadline is invalid"
            )
        if temporary_root is not None:
            raise SnapshotMaterializationError(
                "temporary immutable previews require repository-family authority"
            )
        binding = self._resolver.resolve_as_owner(
            repository_id=repository_id, owner_uid=owner_uid
        )
        if (
            not isinstance(binding, SnapshotRepositoryBinding)
            or binding.repository_id != repository_id
            or binding.owner_uid != owner_uid
        ):
            raise SnapshotMaterializationError(
                "snapshot resolver returned contradictory repository authority"
            )
        request_root = Path(binding.canonical_root)
        manifest = self._manifest(request_root, owner_uid=owner_uid)
        intent_contract = manifest.intents.get(intent)
        if intent_contract is None or intent_contract.source_mode is not SourceMode.IMMUTABLE:
            raise SnapshotMaterializationError(
                "immutable preview requires an immutable manifest intent"
            )
        request = SnapshotMaterializationRequest(
            repository_id=repository_id,
            original_root=binding.canonical_root,
            temporary_root=None,
            manifest_fingerprint=manifest.fingerprint,
            intent=intent,
            owner_uid=owner_uid,
            access_uid=access_uid,
        )
        deadline = time.monotonic() + launch_timeout_seconds
        if launch_deadline_monotonic is not None:
            deadline = min(deadline, float(launch_deadline_monotonic))
        token = _SNAPSHOT_DEADLINE.set(deadline)
        try:
            provenance = self._materializer.materialize(request)
        finally:
            _SNAPSHOT_DEADLINE.reset(token)
        if (
            provenance.repository_id != repository_id
            or provenance.original_root != binding.canonical_root
            or provenance.temporary_root is not None
            or provenance.manifest_fingerprint != manifest.fingerprint
            or not provenance.snapshot_id.startswith("snapshot-")
            or not provenance.complete
        ):
            raise SnapshotMaterializationError(
                "snapshot materializer returned contradictory provenance"
            )
        plan = create_test_plan(
            manifest,
            intent=intent,
            source=provenance.source_identity(),
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
        )
        return {
            "plan": plan.to_document(),
            "target_resources": {
                name: {
                    "cpu_millis": manifest.targets[name].resources.cpu_millis,
                    "memory_mib": manifest.targets[name].resources.memory_mib,
                    "pids": manifest.targets[name].resources.pids,
                    "estimated_seconds": float(
                        manifest.targets[name].timeout_seconds
                        if plan.timeouts.execution_seconds is None
                        else plan.timeouts.execution_seconds
                    ),
                    "shard_count": safe_history_shard_ceiling(
                        manifest.targets[name]
                    ),
                    "max_attempts": manifest.targets[name].retry.max_attempts,
                    "worktree_key": provenance.materialized_root,
                    "exclusive_resources": list(
                        manifest.targets[name].exclusive_resources
                    ),
                }
                for name in plan.selected_targets
            },
        }


__all__ = [
    "FilesystemSnapshotMaterializer",
    "GitSnapshotSource",
    "ImmutableSnapshotPlanPreviewer",
    "MAX_SNAPSHOT_FILES",
    "MAX_SNAPSHOT_TOTAL_BYTES",
    "MAX_SNAPSHOT_UNTRACKED_BYTES",
    "MAX_SNAPSHOT_UNTRACKED_FILES",
    "SnapshotFile",
    "SnapshotMaterializationError",
    "SnapshotMaterializationRequest",
    "SnapshotMaterializer",
    "SnapshotProvenance",
    "SnapshotRepositoryBinding",
    "SnapshotRepositoryResolver",
    "SnapshotScan",
    "SnapshotSource",
    "public_snapshot_source_diagnostic",
]
