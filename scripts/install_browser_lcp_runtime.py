#!/usr/bin/env python3
"""Root-only, offline installer for immutable browser LCP runtimes.

The installer never invokes npm, Playwright installation, or a network
operation.  It consumes an already-populated, root-controlled package tree and
exact Node/browser executables, seals a content-addressed plan, stages the
runtime atomically, and verifies every byte before producing a runtime lock.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping
import uuid


SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import browser_lcp_acceptance as browser_lcp  # noqa: E402


SCHEMA_VERSION = 1
PLAN_KIND = "devcoordinator-browser-runtime-install-plan"
STAGE_KIND = "devcoordinator-browser-runtime-stage-attestation"
DEFAULT_RUNTIME_ROOT = Path("/opt/devcoordinator-browser-runtimes")
AUTHORITY_UID = 0
AUTHORITY_GID = 0
MAX_FILES = browser_lcp.MAX_RUNTIME_FILES + 2
MAX_BYTES = browser_lcp.MAX_RUNTIME_BYTES + browser_lcp.MAX_BINARY_BYTES
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
PARTIAL_RE = re.compile(r"^\.([a-f0-9]{64})\.([a-f0-9]{32})\.partial$")


class BrowserRuntimeInstallError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(path: Path, *, maximum: int = browser_lcp.MAX_BINARY_BYTES) -> str:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_size > maximum
    ):
        raise BrowserRuntimeInstallError(f"unsafe or oversized source file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ):
        raise BrowserRuntimeInstallError(f"source changed while hashing: {path}")
    return digest.hexdigest()


def _identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
    }


def _same_identity(info: os.stat_result, expected: Mapping[str, object]) -> bool:
    return _identity(info) == dict(expected)


def _hash_open_source(
    path: Path, *, uid: int, gid: int, executable: bool = False
) -> tuple[str, dict[str, int]]:
    path = _owned_path(path, uid=uid, gid=gid, directory=False, executable=executable)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not _same_identity(before, _identity(path.lstat())):
            raise BrowserRuntimeInstallError(f"source changed before open: {path}")
        if before.st_size > browser_lcp.MAX_BINARY_BYTES:
            raise BrowserRuntimeInstallError(f"source file is oversized: {path}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise BrowserRuntimeInstallError(f"source read ended early: {path}")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise BrowserRuntimeInstallError(f"source grew while hashing: {path}")
        after = os.fstat(descriptor)
        if (
            _identity(after) != _identity(before)
            or not _same_identity(path.lstat(), _identity(before))
        ):
            raise BrowserRuntimeInstallError(f"source changed while hashing: {path}")
        return digest.hexdigest(), _identity(before)
    finally:
        os.close(descriptor)


def _owned_path(
    path: Path, *, uid: int, gid: int, directory: bool, executable: bool = False
) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_absolute() or ".." in path.parts:
        raise BrowserRuntimeInstallError("runtime source path is invalid")
    try:
        if path.resolve(strict=True) != path:
            raise BrowserRuntimeInstallError("runtime source path is not canonical")
    except OSError as error:
        raise BrowserRuntimeInstallError("runtime source path is unavailable") from error
    info = path.lstat()
    expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        stat.S_ISLNK(info.st_mode)
        or not expected_type
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) & 0o022
        or (executable and stat.S_IMODE(info.st_mode) & 0o111 == 0)
    ):
        raise BrowserRuntimeInstallError("runtime source ownership or mode is unsafe")
    return path


def _directory_identity(path: Path, *, uid: int, gid: int) -> dict[str, object]:
    path = _owned_path(path, uid=uid, gid=gid, directory=True)
    return {"path": str(path), "identity": _identity(path.lstat())}


def _source_inventory(
    *,
    package_root: Path,
    node: Path,
    browser_root: Path,
    browser_executable_relative: Path,
    uid: int,
    gid: int,
) -> tuple[list[dict[str, object]], dict[str, object], list[dict[str, object]]]:
    package_root = _owned_path(package_root, uid=uid, gid=gid, directory=True)
    node = _owned_path(node, uid=uid, gid=gid, directory=False, executable=True)
    browser_root = _owned_path(browser_root, uid=uid, gid=gid, directory=True)
    if (
        browser_executable_relative.is_absolute()
        or ".." in browser_executable_relative.parts
        or not browser_executable_relative.parts
        or browser_executable_relative.as_posix() in {"", "."}
    ):
        raise BrowserRuntimeInstallError("browser executable relative path is invalid")
    browser_executable = _owned_path(
        browser_root / browser_executable_relative,
        uid=uid,
        gid=gid,
        directory=False,
        executable=True,
    )
    try:
        browser_executable.relative_to(browser_root)
    except ValueError as error:
        raise BrowserRuntimeInstallError("browser executable escapes its bundle") from error
    # This validates the exact package/lock version relationship before any
    # plan can be sealed.  It performs no package-manager operation.
    version, package_sha, lock_sha = browser_lcp._load_runtime_package_contract(
        package_root
    )
    selected: list[tuple[Path, str, str]] = [
        (package_root / "package.json", "playwright/package.json", "0444"),
        (package_root / "package-lock.json", "playwright/package-lock.json", "0444"),
    ]
    source_directories: list[dict[str, object]] = [
        _directory_identity(package_root, uid=uid, gid=gid),
        _directory_identity(browser_root, uid=uid, gid=gid),
    ]
    for name in ("playwright", "playwright-core"):
        root = _owned_path(
            package_root / "node_modules" / name,
            uid=uid,
            gid=gid,
            directory=True,
        )
        for item in sorted(root.rglob("*")):
            info = item.lstat()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) & 0o022:
                    raise BrowserRuntimeInstallError("runtime package contains a mutable directory")
                source_directories.append(
                    {"path": str(item), "identity": _identity(info)}
                )
                continue
            _owned_path(item, uid=uid, gid=gid, directory=False)
            relative = item.relative_to(package_root).as_posix()
            selected.append((item, f"playwright/{relative}", "0444"))
    browser_files = 0
    for item in sorted(browser_root.rglob("*")):
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) & 0o022:
                raise BrowserRuntimeInstallError("browser bundle contains a mutable directory")
            source_directories.append({"path": str(item), "identity": _identity(info)})
            continue
        _owned_path(item, uid=uid, gid=gid, directory=False)
        relative = item.relative_to(browser_root).as_posix()
        mode = "0555" if stat.S_IMODE(info.st_mode) & 0o111 else "0444"
        selected.append((item, f"browser/{relative}", mode))
        browser_files += 1
    if browser_files == 0 or browser_executable not in {
        source for source, _destination, _mode in selected
    }:
        raise BrowserRuntimeInstallError("browser bundle is empty or omits its executable")
    selected.append((node, "bin/node", "0555"))
    if len(selected) > MAX_FILES:
        raise BrowserRuntimeInstallError("browser runtime file count exceeds its bound")
    entries: list[dict[str, object]] = []
    total = 0
    for source, destination, mode in sorted(selected, key=lambda item: item[1]):
        digest, identity = _hash_open_source(
            source,
            uid=uid,
            gid=gid,
            executable=mode == "0555" and source in {node, browser_executable},
        )
        size = identity["size"]
        total += size
        if total > MAX_BYTES:
            raise BrowserRuntimeInstallError("browser runtime bytes exceed their bound")
        entries.append(
            {
                "path": destination,
                "mode": mode,
                "size": size,
                "sha256": digest,
                "source": str(source),
                "source_identity": identity,
            }
        )
    if len({str(item["path"]) for item in entries}) != len(entries):
        raise BrowserRuntimeInstallError("browser runtime destination inventory overlaps")
    portable_browser = [
        {key: item[key] for key in ("path", "mode", "size", "sha256")}
        for item in entries
        if str(item["path"]).startswith("browser/")
    ]
    contract: dict[str, object] = {
        "playwright_version": version,
        "package_json_sha256": package_sha,
        "package_lock_sha256": lock_sha,
        "browser_executable_relative": browser_executable_relative.as_posix(),
        "browser_file_count": len(portable_browser),
        "browser_total_bytes": sum(int(item["size"]) for item in portable_browser),
        "browser_tree_sha256": hashlib.sha256(_canonical(portable_browser)).hexdigest(),
    }
    directories = sorted(source_directories, key=lambda item: str(item["path"]))
    if len({str(item["path"]) for item in directories}) != len(directories):
        raise BrowserRuntimeInstallError("browser runtime source directory inventory overlaps")
    return entries, contract, directories


def _runtime_digest(entries: list[Mapping[str, object]]) -> str:
    portable = [
        {key: item[key] for key in ("path", "mode", "size", "sha256")}
        for item in entries
    ]
    return hashlib.sha256(
        _canonical({"schema_version": SCHEMA_VERSION, "files": portable})
    ).hexdigest()


def build_plan(
    *,
    package_root: Path,
    node: Path,
    browser_root: Path,
    browser_executable_relative: Path,
) -> dict[str, object]:
    entries, contract, directories = _source_inventory(
        package_root=package_root,
        node=node,
        browser_root=browser_root,
        browser_executable_relative=browser_executable_relative,
        uid=AUTHORITY_UID,
        gid=AUTHORITY_GID,
    )
    digest = _runtime_digest(entries)
    runtime_root = _runtime_root_path()
    total_bytes = sum(int(item["size"]) for item in entries)
    return browser_lcp._seal_digest(
        PLAN_KIND,
        {
            "runtime_digest": digest,
            "runtime_root": str(runtime_root),
            "runtime": str(runtime_root / digest),
            "total_bytes": total_bytes,
            "files": entries,
            "source_directories": directories,
            "package_contract": contract,
            "created_at": browser_lcp._format_time(browser_lcp._now()),
        },
    )


PLAN_FIELDS = frozenset(
    {
        "runtime_digest", "runtime_root", "runtime", "total_bytes", "files",
        "source_directories", "package_contract", "created_at",
    }
)


def _runtime_root_path() -> Path:
    root = Path(os.path.abspath(DEFAULT_RUNTIME_ROOT.expanduser()))
    if not root.is_absolute() or ".." in root.parts or not root.name:
        raise BrowserRuntimeInstallError("fixed browser runtime root is invalid")
    if root != DEFAULT_RUNTIME_ROOT:
        raise BrowserRuntimeInstallError("browser runtime root must be canonical and fixed")
    return root


def _runtime_parent() -> Path:
    root = _runtime_root_path()
    parent = root.parent
    try:
        if parent.resolve(strict=True) != parent:
            raise BrowserRuntimeInstallError("browser runtime parent is not canonical")
    except OSError as error:
        raise BrowserRuntimeInstallError("browser runtime parent is unavailable") from error
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != AUTHORITY_UID
        or info.st_gid != AUTHORITY_GID
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise BrowserRuntimeInstallError("browser runtime parent ancestry is unsafe")
    return parent


def _require_runtime_root(*, create: bool) -> Path:
    root = _runtime_root_path()
    parent = _runtime_parent()
    if not root.exists() and not root.is_symlink():
        if not create:
            raise BrowserRuntimeInstallError("browser runtime root is unavailable")
        os.mkdir(root, 0o755)
        os.chown(root, AUTHORITY_UID, AUTHORITY_GID)
        os.chmod(root, 0o755)
        descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    try:
        if root.resolve(strict=True) != root:
            raise BrowserRuntimeInstallError("browser runtime root is not canonical")
    except OSError as error:
        raise BrowserRuntimeInstallError("browser runtime root is unavailable") from error
    info = root.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != AUTHORITY_UID
        or info.st_gid != AUTHORITY_GID
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise BrowserRuntimeInstallError("browser runtime root must be root:root mode 0755")
    return root


def verify_plan(value: object) -> dict[str, Any]:
    plan = browser_lcp._verify_digest_seal(value, kind=PLAN_KIND, fields=PLAN_FIELDS)
    entries = plan.get("files")
    package_contract = plan.get("package_contract")
    if (
        not isinstance(entries, list)
        or not entries
        or len(entries) > MAX_FILES
        or not isinstance(plan.get("runtime_digest"), str)
        or SHA256_RE.fullmatch(plan["runtime_digest"]) is None
        or plan.get("runtime")
        != str(Path(str(plan.get("runtime_root"))) / str(plan["runtime_digest"]))
        or plan.get("runtime_root") != str(_runtime_root_path())
        or _runtime_digest(entries) != plan["runtime_digest"]
        or type(plan.get("total_bytes")) is not int
        or plan["total_bytes"] < 0
        or plan["total_bytes"] > MAX_BYTES
        or not isinstance(package_contract, Mapping)
        or set(package_contract)
        != {
            "playwright_version",
            "package_json_sha256",
            "package_lock_sha256",
            "browser_executable_relative",
            "browser_file_count",
            "browser_total_bytes",
            "browser_tree_sha256",
        }
        or re.fullmatch(
            r"\d+\.\d+\.\d+", str(package_contract.get("playwright_version"))
        )
        is None
        or any(
            SHA256_RE.fullmatch(str(package_contract.get(field))) is None
            for field in ("package_json_sha256", "package_lock_sha256")
        )
        or not isinstance(package_contract.get("browser_executable_relative"), str)
        or Path(str(package_contract.get("browser_executable_relative"))).is_absolute()
        or ".." in Path(str(package_contract.get("browser_executable_relative"))).parts
        or type(package_contract.get("browser_file_count")) is not int
        or package_contract["browser_file_count"] <= 0
        or type(package_contract.get("browser_total_bytes")) is not int
        or package_contract["browser_total_bytes"] < 0
        or SHA256_RE.fullmatch(str(package_contract.get("browser_tree_sha256"))) is None
    ):
        raise BrowserRuntimeInstallError("browser runtime plan contract is invalid")
    previous = ""
    for item in entries:
        if (
            not isinstance(item, Mapping)
            or set(item) != {
                "path", "mode", "size", "sha256", "source", "source_identity"
            }
            or not isinstance(item["path"], str)
            or item["path"] <= previous
            or Path(item["path"]).is_absolute()
            or ".." in Path(item["path"]).parts
            or item["mode"] not in {"0444", "0555"}
            or not isinstance(item["size"], int)
            or item["size"] < 0
            or not isinstance(item["sha256"], str)
            or SHA256_RE.fullmatch(item["sha256"]) is None
            or not isinstance(item["source"], str)
            or not isinstance(item["source_identity"], Mapping)
            or set(item["source_identity"])
            != {"device", "inode", "size", "mtime_ns", "ctime_ns", "uid", "gid", "mode"}
            or any(type(item["source_identity"].get(field)) is not int for field in item["source_identity"])
            or item["source_identity"]["size"] != item["size"]
            or item["source_identity"]["uid"] != AUTHORITY_UID
            or item["source_identity"]["gid"] != AUTHORITY_GID
        ):
            raise BrowserRuntimeInstallError("browser runtime plan file is invalid")
        previous = item["path"]
    if sum(int(item["size"]) for item in entries) != plan["total_bytes"]:
        raise BrowserRuntimeInstallError("browser runtime total planned bytes are invalid")
    browser_entries = [
        {key: item[key] for key in ("path", "mode", "size", "sha256")}
        for item in entries
        if str(item["path"]).startswith("browser/")
    ]
    if (
        len(browser_entries) != package_contract["browser_file_count"]
        or sum(int(item["size"]) for item in browser_entries)
        != package_contract["browser_total_bytes"]
        or hashlib.sha256(_canonical(browser_entries)).hexdigest()
        != package_contract["browser_tree_sha256"]
        or not any(
            item["path"]
            == "browser/" + str(package_contract["browser_executable_relative"])
            and item["mode"] == "0555"
            for item in browser_entries
        )
    ):
        raise BrowserRuntimeInstallError("browser directory bundle contract is invalid")
    directories = plan.get("source_directories")
    if not isinstance(directories, list) or not directories or len(directories) > MAX_FILES:
        raise BrowserRuntimeInstallError("browser runtime source directory plan is invalid")
    previous = ""
    for item in directories:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"path", "identity"}
            or not isinstance(item["path"], str)
            or item["path"] <= previous
            or not Path(item["path"]).is_absolute()
            or ".." in Path(item["path"]).parts
            or not isinstance(item["identity"], Mapping)
            or set(item["identity"])
            != {"device", "inode", "size", "mtime_ns", "ctime_ns", "uid", "gid", "mode"}
            or any(type(item["identity"].get(field)) is not int for field in item["identity"])
            or item["identity"]["uid"] != AUTHORITY_UID
            or item["identity"]["gid"] != AUTHORITY_GID
        ):
            raise BrowserRuntimeInstallError("browser runtime source directory binding is invalid")
        previous = item["path"]
    return plan


def _verify_source_directories(plan: Mapping[str, object]) -> None:
    for item in plan["source_directories"]:
        path = _owned_path(
            Path(str(item["path"])),
            uid=AUTHORITY_UID,
            gid=AUTHORITY_GID,
            directory=True,
        )
        if not _same_identity(path.lstat(), item["identity"]):
            raise BrowserRuntimeInstallError(
                "browser runtime source directory changed after planning"
            )


def _ensure_private_directory(path: Path, *, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise BrowserRuntimeInstallError("staged runtime directory escaped its root") from error
    missing: list[Path] = []
    current = path
    while current != root and not current.exists() and not current.is_symlink():
        missing.append(current)
        current = current.parent
    if current != root:
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != AUTHORITY_UID
            or info.st_gid != AUTHORITY_GID
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise BrowserRuntimeInstallError("staged runtime directory ancestry is unsafe")
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        os.chown(directory, AUTHORITY_UID, AUTHORITY_GID)


def _copy_planned_file(item: Mapping[str, object], *, temporary: Path) -> None:
    source = _owned_path(
        Path(str(item["source"])),
        uid=AUTHORITY_UID,
        gid=AUTHORITY_GID,
        directory=False,
        executable=item["mode"] == "0555",
    )
    source_fd = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    destination = temporary / str(item["path"])
    _ensure_private_directory(destination.parent, root=temporary)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if (
            not _same_identity(before, item["source_identity"])
            or not _same_identity(source.lstat(), item["source_identity"])
        ):
            raise BrowserRuntimeInstallError("browser runtime source changed after planning")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while copied < int(item["size"]):
            block = os.read(source_fd, min(1024 * 1024, int(item["size"]) - copied))
            if not block:
                raise BrowserRuntimeInstallError("browser runtime source ended during copy")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise BrowserRuntimeInstallError("browser runtime destination write stalled")
                view = view[written:]
            copied += len(block)
        if os.read(source_fd, 1):
            raise BrowserRuntimeInstallError("browser runtime source grew during copy")
        after = os.fstat(source_fd)
        if (
            not _same_identity(after, item["source_identity"])
            or not _same_identity(source.lstat(), item["source_identity"])
            or digest.hexdigest() != item["sha256"]
        ):
            raise BrowserRuntimeInstallError("browser runtime source changed during copy")
        os.fchown(destination_fd, AUTHORITY_UID, AUTHORITY_GID)
        os.fchmod(destination_fd, int(str(item["mode"]), 8))
        os.fsync(destination_fd)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _freeze_and_sync_directories(temporary: Path) -> None:
    directories = [temporary]
    for path in temporary.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            directories.append(path)
    for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        os.chown(directory, AUTHORITY_UID, AUTHORITY_GID)
        os.chmod(directory, 0o555)
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _remove_private_partial(path: Path, *, root: Path) -> None:
    match = PARTIAL_RE.fullmatch(path.name)
    if match is None or path.parent != root:
        raise BrowserRuntimeInstallError("browser runtime partial name is unsafe")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != AUTHORITY_UID
        or info.st_gid != AUTHORITY_GID
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o555}
    ):
        raise BrowserRuntimeInstallError("browser runtime partial identity is unsafe")
    directories: list[Path] = [path]
    files: list[Path] = []
    for item in path.rglob("*"):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != AUTHORITY_UID or metadata.st_gid != AUTHORITY_GID:
            raise BrowserRuntimeInstallError("browser runtime partial contains an unsafe entry")
        if stat.S_ISDIR(metadata.st_mode):
            directories.append(item)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            files.append(item)
        else:
            raise BrowserRuntimeInstallError("browser runtime partial contains a special or linked file")
    for directory in directories:
        directory.chmod(0o700)
    for file in files:
        file.unlink()
    for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        directory.rmdir()


def _repair_stale_partials(root: Path, *, digest: str) -> int:
    repaired = 0
    for candidate in sorted(root.iterdir(), key=lambda path: path.name):
        match = PARTIAL_RE.fullmatch(candidate.name)
        if match is None or match.group(1) != digest:
            continue
        _remove_private_partial(candidate, root=root)
        repaired += 1
    if repaired:
        descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return repaired


def _verify_tree_contents(plan: Mapping[str, object], runtime: Path) -> Path:
    info = runtime.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != AUTHORITY_UID
        or info.st_gid != AUTHORITY_GID
        or stat.S_IMODE(info.st_mode) != 0o555
    ):
        raise BrowserRuntimeInstallError("immutable browser runtime root is unsafe")
    expected = {str(item["path"]): item for item in plan["files"]}
    actual: set[str] = set()
    for target in runtime.rglob("*"):
        relative = target.relative_to(runtime).as_posix()
        target_info = target.lstat()
        if stat.S_ISLNK(target_info.st_mode):
            raise BrowserRuntimeInstallError("immutable browser runtime contains a symlink")
        if stat.S_ISDIR(target_info.st_mode):
            if (
                target_info.st_uid != AUTHORITY_UID
                or target_info.st_gid != AUTHORITY_GID
                or stat.S_IMODE(target_info.st_mode) != 0o555
            ):
                raise BrowserRuntimeInstallError("immutable browser runtime directory is mutable")
            continue
        actual.add(relative)
        item = expected.get(relative)
        if (
            item is None
            or not stat.S_ISREG(target_info.st_mode)
            or target_info.st_uid != AUTHORITY_UID
            or target_info.st_gid != AUTHORITY_GID
            or stat.S_IMODE(target_info.st_mode) != int(str(item["mode"]), 8)
            or target_info.st_size != item["size"]
            or _sha256(target) != item["sha256"]
        ):
            raise BrowserRuntimeInstallError("immutable browser runtime file changed")
    if actual != set(expected):
        raise BrowserRuntimeInstallError("immutable browser runtime inventory is incomplete")
    if sum(int(expected[path]["size"]) for path in actual) != plan["total_bytes"]:
        raise BrowserRuntimeInstallError("immutable browser runtime byte total changed")
    return runtime


def _verify_runtime_tree(plan: Mapping[str, object]) -> Path:
    runtime = Path(str(plan["runtime"]))
    root = _require_runtime_root(create=False)
    if runtime != root / str(plan["runtime_digest"]):
        raise BrowserRuntimeInstallError("immutable browser runtime escaped its fixed root")
    return _verify_tree_contents(plan, runtime)


def stage(
    *, plan: Mapping[str, object], runtime_lock: Path, attestation: Path
) -> dict[str, object]:
    plan = verify_plan(plan)
    root = _require_runtime_root(create=True)
    runtime = Path(str(plan["runtime"]))
    root_descriptor = os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    temporary: Path | None = None
    try:
        fcntl.flock(root_descriptor, fcntl.LOCK_EX)
        if runtime.exists() or runtime.is_symlink():
            try:
                _verify_tree_contents(plan, runtime)
            except (BrowserRuntimeInstallError, OSError) as error:
                raise BrowserRuntimeInstallError(
                    "published browser runtime digest is corrupt; refusing automatic repair"
                ) from error
        else:
            _repair_stale_partials(root, digest=str(plan["runtime_digest"]))
            temporary = root / f".{plan['runtime_digest']}.{uuid.uuid4().hex}.partial"
            os.mkdir(temporary, 0o700)
            os.chown(temporary, AUTHORITY_UID, AUTHORITY_GID)
            _verify_source_directories(plan)
            for item in plan["files"]:
                _copy_planned_file(item, temporary=temporary)
            _verify_source_directories(plan)
            _freeze_and_sync_directories(temporary)
            _verify_tree_contents(plan, temporary)
            if runtime.exists() or runtime.is_symlink():
                raise BrowserRuntimeInstallError(
                    "browser runtime destination appeared during publication"
                )
            os.rename(temporary, runtime)
            temporary = None
            os.fsync(root_descriptor)
        runtime = _verify_tree_contents(plan, runtime)
    finally:
        try:
            if temporary is not None and (temporary.exists() or temporary.is_symlink()):
                _remove_private_partial(temporary, root=root)
                os.fsync(root_descriptor)
        finally:
            try:
                fcntl.flock(root_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(root_descriptor)
    if runtime_lock.exists() or runtime_lock.is_symlink():
        recorded_lock, _payload = browser_lcp._read_private_json(
            runtime_lock,
            uid=AUTHORITY_UID,
            label="browser runtime lock",
        )
        lock_document = browser_lcp.verify_runtime_lock_document(
            recorded_lock,
            expected_uid=AUTHORITY_UID,
            expected_gid=AUTHORITY_GID,
        )
        if (
            lock_document["node"]["executable"] != str(runtime / "bin/node")
            or lock_document["playwright"]["runtime_root"]
            != str(runtime / "playwright")
            or lock_document["browser"]["executable"]
            != str(
                runtime / "browser"
                / str(plan["package_contract"]["browser_executable_relative"])
            )
        ):
            raise BrowserRuntimeInstallError("browser runtime lock changed")
    else:
        lock_document = browser_lcp.create_runtime_lock_document(
            node_executable=runtime / "bin/node",
            playwright_runtime_root=runtime / "playwright",
            browser_executable=(
                runtime / "browser"
                / str(plan["package_contract"]["browser_executable_relative"])
            ),
            expected_uid=AUTHORITY_UID,
            expected_gid=AUTHORITY_GID,
        )
        browser_lcp._publish_private(
            runtime_lock, lock_document, uid=AUTHORITY_UID
        )
    document = browser_lcp._seal_digest(
        STAGE_KIND,
        {
            "plan_sha256": plan["document_sha256"],
            "runtime_digest": plan["runtime_digest"],
            "runtime": str(runtime),
            "runtime_lock": str(runtime_lock),
            "runtime_lock_sha256": lock_document["document_sha256"],
            "staged_at": browser_lcp._format_time(browser_lcp._now()),
        },
    )
    if attestation.exists() or attestation.is_symlink():
        recorded, _payload = browser_lcp._read_private_json(
            attestation,
            uid=AUTHORITY_UID,
            label="browser runtime stage attestation",
        )
        recorded = browser_lcp._verify_digest_seal(
            recorded,
            kind=STAGE_KIND,
            fields={
                "plan_sha256", "runtime_digest", "runtime", "runtime_lock",
                "runtime_lock_sha256", "staged_at",
            },
        )
        for field in (
            "plan_sha256", "runtime_digest", "runtime", "runtime_lock",
            "runtime_lock_sha256",
        ):
            if recorded[field] != document[field]:
                raise BrowserRuntimeInstallError("browser runtime stage evidence changed")
        return recorded
    browser_lcp._publish_private(
        attestation, document, uid=AUTHORITY_UID
    )
    return document


def verify(
    *, plan: Mapping[str, object], runtime_lock: Path, attestation: Path
) -> dict[str, object]:
    plan = verify_plan(plan)
    runtime = _verify_runtime_tree(plan)
    lock, _payload = browser_lcp._read_private_json(
        runtime_lock,
        uid=AUTHORITY_UID,
        label="browser runtime lock",
    )
    lock = browser_lcp.verify_runtime_lock_document(
        lock,
        expected_uid=AUTHORITY_UID,
        expected_gid=AUTHORITY_GID,
    )
    stage_value, _payload = browser_lcp._read_private_json(
        attestation,
        uid=AUTHORITY_UID,
        label="browser runtime stage attestation",
    )
    stage_value = browser_lcp._verify_digest_seal(
        stage_value,
        kind=STAGE_KIND,
        fields={
            "plan_sha256", "runtime_digest", "runtime", "runtime_lock",
            "runtime_lock_sha256", "staged_at",
        },
    )
    if (
        lock["node"]["executable"] != str(runtime / "bin/node")
        or lock["playwright"]["runtime_root"] != str(runtime / "playwright")
        or lock["browser"]["executable"]
        != str(
            runtime / "browser"
            / str(plan["package_contract"]["browser_executable_relative"])
        )
        or
        stage_value["plan_sha256"] != plan["document_sha256"]
        or stage_value["runtime_digest"] != plan["runtime_digest"]
        or stage_value["runtime"] != str(runtime)
        or stage_value["runtime_lock"] != str(runtime_lock)
        or stage_value["runtime_lock_sha256"] != lock["document_sha256"]
    ):
        raise BrowserRuntimeInstallError("browser runtime verification binding is invalid")
    return {
        "ok": True,
        "runtime": str(runtime),
        "runtime_digest": plan["runtime_digest"],
        "runtime_lock_sha256": lock["document_sha256"],
        "attestation_sha256": stage_value["document_sha256"],
    }


def _load_private(path: Path, *, uid: int, label: str) -> dict[str, Any]:
    value, _payload = browser_lcp._read_private_json(path, uid=uid, label=label)
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    plan = actions.add_parser("plan")
    plan.add_argument("--package-root", required=True)
    plan.add_argument("--node", required=True)
    plan.add_argument("--browser-root", required=True)
    plan.add_argument("--browser-executable-relative", required=True)
    plan.add_argument("--output", required=True)
    for name in ("stage", "verify"):
        command = actions.add_parser(name)
        command.add_argument("--plan", required=True)
        command.add_argument("--runtime-lock", required=True)
        command.add_argument("--attestation", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise BrowserRuntimeInstallError("browser runtime installer must run as root")
        if args.action == "plan":
            document = build_plan(
                package_root=Path(args.package_root),
                node=Path(args.node),
                browser_root=Path(args.browser_root),
                browser_executable_relative=Path(args.browser_executable_relative),
            )
            browser_lcp._publish_private(Path(args.output), document, uid=0)
            result = {
                "ok": True,
                "plan": args.output,
                "runtime_digest": document["runtime_digest"],
                "document_sha256": document["document_sha256"],
            }
        else:
            plan = verify_plan(
                _load_private(Path(args.plan), uid=0, label="browser runtime plan")
            )
            if args.action == "stage":
                document = stage(
                    plan=plan,
                    runtime_lock=Path(args.runtime_lock),
                    attestation=Path(args.attestation),
                )
                result = {
                    "ok": True,
                    "runtime": plan["runtime"],
                    "runtime_digest": plan["runtime_digest"],
                    "attestation_sha256": document["document_sha256"],
                }
            else:
                result = verify(
                    plan=plan,
                    runtime_lock=Path(args.runtime_lock),
                    attestation=Path(args.attestation),
                )
    except (
        BrowserRuntimeInstallError,
        browser_lcp.BrowserLcpAcceptanceError,
        OSError,
        ValueError,
    ) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
