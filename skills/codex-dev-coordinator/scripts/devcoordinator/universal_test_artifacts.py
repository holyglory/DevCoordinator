"""Deterministic, race-resistant packaging for universal-test directories."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import BinaryIO, Sequence

from .universal_test_store import TestStoreConflict, TestStoreContractError


MAX_DIRECTORY_FILES = 10_000
MAX_DIRECTORY_DEPTH = 32
MAX_DIRECTORY_PATH_BYTES = 512
_SECRET_MATERIAL = re.compile(
    rb"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|\bAKIA[0-9A-Z]{16}\b"
    rb"|\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"
    rb"|\bsk-[A-Za-z0-9_-]{20,}\b"
    rb"|\bxox[baprs]-[A-Za-z0-9-]{20,}\b"
    rb"|\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b)"
)


@dataclass(frozen=True)
class DirectoryArchiveEvidence:
    sha256: str
    size_bytes: int
    file_count: int


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _exact_secret_sequences(
    values: Sequence[bytes],
) -> tuple[bytes, ...]:
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes, bytearray))
        or len(values) > 128
    ):
        raise TestStoreContractError(
            "directory artifact secret policy is invalid"
        )
    normalized: set[bytes] = set()
    total = 0
    for raw in values:
        if not isinstance(raw, bytes) or not raw or len(raw) > 256 * 1024:
            raise TestStoreContractError(
                "directory artifact secret policy is invalid"
            )
        total += len(raw)
        if total > 8 * 1024 * 1024:
            raise TestStoreContractError(
                "directory artifact secret policy is excessive"
            )
        normalized.add(raw)
    return tuple(sorted(normalized, key=lambda value: (-len(value), value)))


def _contains_secret(payload: bytes, exact: Sequence[bytes]) -> bool:
    return _SECRET_MATERIAL.search(payload) is not None or any(
        value in payload for value in exact
    )


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
            raise TestStoreContractError("directory artifact archive exceeds its bound")
        written = self._destination.write(payload)
        if written is None:
            written = len(payload)
        if written != len(payload):
            raise TestStoreContractError("directory artifact archive write was partial")
        self._digest.update(payload)
        self._size += len(payload)
        return written

    @property
    def evidence(self) -> tuple[str, int]:
        return self._digest.hexdigest(), self._size


class _SecretScanningReader:
    """Scan the exact bytes tarfile consumes, including chunk boundaries."""

    def __init__(
        self,
        source: BinaryIO,
        *,
        exact_secrets: Sequence[bytes],
    ) -> None:
        self._source = source
        self._exact_secrets = exact_secrets
        self._overlap = max(
            4096,
            max((len(value) - 1 for value in exact_secrets), default=0),
        )
        self._tail = b""
        self._digest = hashlib.sha256()
        self._size = 0

    def read(self, size: int = -1) -> bytes:
        payload = self._source.read(size)
        if payload:
            sample = self._tail + payload
            if _contains_secret(sample, self._exact_secrets):
                raise TestStoreContractError(
                    "directory artifact contains secret material"
                )
            self._tail = sample[-self._overlap :]
            self._digest.update(payload)
            self._size += len(payload)
        return payload

    @property
    def evidence(self) -> tuple[str, int]:
        return self._digest.hexdigest(), self._size


def _entries(
    root: Path,
    *,
    expected_uid: int,
    exact_secrets: Sequence[bytes],
) -> tuple[tuple[PurePosixPath, Path, os.stat_result], ...]:
    try:
        root_before = root.lstat()
        root_resolved = root.resolve(strict=True)
    except OSError as error:
        raise TestStoreContractError("directory artifact is unavailable") from error
    if (
        root_resolved != root
        or not stat.S_ISDIR(root_before.st_mode)
        or stat.S_ISLNK(root_before.st_mode)
    ):
        raise TestStoreContractError("directory artifact root is unsafe")
    pending: list[tuple[PurePosixPath, Path]] = [(PurePosixPath("."), root)]
    observed: list[tuple[PurePosixPath, Path, os.stat_result]] = []
    file_count = 0
    while pending:
        relative, directory = pending.pop()
        try:
            values = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise TestStoreContractError("directory artifact cannot be enumerated") from error
        for entry in values:
            if entry.name in {".", ".."} or "/" in entry.name or "\x00" in entry.name:
                raise TestStoreContractError("directory artifact entry name is unsafe")
            child_relative = PurePosixPath(entry.name) if relative == PurePosixPath(".") else relative / entry.name
            if (
                len(child_relative.parts) > MAX_DIRECTORY_DEPTH
                or len(child_relative.as_posix().encode("utf-8")) > MAX_DIRECTORY_PATH_BYTES
            ):
                raise TestStoreContractError("directory artifact path exceeds its bound")
            if _contains_secret(os.fsencode(child_relative.as_posix()), exact_secrets):
                raise TestStoreContractError(
                    "directory artifact path contains secret material"
                )
            child = directory / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise TestStoreContractError("directory artifact entry is unavailable") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise TestStoreContractError("directory artifact entry is unsafe")
            if stat.S_ISDIR(metadata.st_mode):
                observed.append((child_relative, child, metadata))
                pending.append((child_relative, child))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise TestStoreContractError("directory artifact contains an unsafe file")
            file_count += 1
            if file_count > MAX_DIRECTORY_FILES:
                raise TestStoreContractError("directory artifact contains too many files")
            observed.append((child_relative, child, metadata))
    root_after = root.lstat()
    if _stable_file_identity(root_before) != _stable_file_identity(root_after):
        raise TestStoreConflict("directory artifact root changed during enumeration")
    return tuple(sorted(observed, key=lambda item: os.fsencode(item[0].as_posix())))


def package_directory(
    root: Path,
    destination: BinaryIO,
    *,
    expected_uid: int,
    maximum_bytes: int,
    prohibited_sequences: Sequence[bytes] = (),
) -> DirectoryArchiveEvidence:
    """Write one canonical USTAR stream without following repository links."""

    if type(expected_uid) is not int or expected_uid < 0 or type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise TestStoreContractError("directory artifact packaging policy is invalid")
    exact_secrets = _exact_secret_sequences(prohibited_sequences)
    entries = _entries(
        root,
        expected_uid=expected_uid,
        exact_secrets=exact_secrets,
    )
    writer = _BoundedHashWriter(destination, maximum_bytes=maximum_bytes)
    files = 0
    try:
        archive = tarfile.open(fileobj=writer, mode="w", format=tarfile.USTAR_FORMAT)
        with archive:
            for relative, path, before in entries:
                info = tarfile.TarInfo(relative.as_posix() + ("/" if stat.S_ISDIR(before.st_mode) else ""))
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                if stat.S_ISDIR(before.st_mode):
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    archive.addfile(info)
                    continue
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    opened = os.fstat(descriptor)
                    current = path.lstat()
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or _stable_file_identity(before)
                        != _stable_file_identity(opened)
                        or _stable_file_identity(opened)
                        != _stable_file_identity(current)
                    ):
                        raise TestStoreConflict("directory artifact entry changed before packaging")
                    info.type = tarfile.REGTYPE
                    info.mode = 0o644
                    info.size = opened.st_size
                    retained = b""
                    inspected_digest = hashlib.sha256()
                    overlap = max(
                        4096,
                        max((len(value) - 1 for value in exact_secrets), default=0),
                    )
                    inspected = 0
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        inspected += len(chunk)
                        if inspected > maximum_bytes:
                            raise TestStoreContractError(
                                "directory artifact file exceeds its archive bound"
                            )
                        sample = retained + chunk
                        if _contains_secret(sample, exact_secrets):
                            raise TestStoreContractError(
                                "directory artifact contains secret material"
                            )
                        retained = sample[-overlap:]
                        inspected_digest.update(chunk)
                    if inspected != opened.st_size:
                        raise TestStoreConflict(
                            "directory artifact entry changed during inspection"
                        )
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source:
                        scanned_source = _SecretScanningReader(
                            source,
                            exact_secrets=exact_secrets,
                        )
                        archive.addfile(info, scanned_source)
                    copied_digest, copied_size = scanned_source.evidence
                    if (
                        copied_size != inspected
                        or copied_digest != inspected_digest.hexdigest()
                    ):
                        raise TestStoreConflict(
                            "directory artifact entry changed during packaging"
                        )
                    after = os.fstat(descriptor)
                    current_after = path.lstat()
                    if (
                        _stable_file_identity(opened)
                        != _stable_file_identity(after)
                        or _stable_file_identity(after)
                        != _stable_file_identity(current_after)
                    ):
                        raise TestStoreConflict("directory artifact entry changed during packaging")
                finally:
                    os.close(descriptor)
                files += 1
    except (OSError, tarfile.TarError) as error:
        raise TestStoreContractError("directory artifact packaging failed") from error
    digest, size = writer.evidence
    return DirectoryArchiveEvidence(sha256=digest, size_bytes=size, file_count=files)


__all__ = ["DirectoryArchiveEvidence", "package_directory"]
