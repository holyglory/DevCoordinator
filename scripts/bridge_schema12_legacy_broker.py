#!/usr/bin/env python3
"""Stage and run a temporary immutable schema-12 broker for first adoption.

The availability cutover intentionally requires an active legacy writer before
it enters maintenance, stops that writer, and applies the sealed schema-13
owner migration.  If schema-13 source was installed too early, this bridge
reconstructs the last committed schema-12 broker from Git objects only.  It
never executes dirty working-tree bytes and it never mutates authority data.

The bridge is deliberately narrow: ``stage`` materializes one content-
addressed release, ``activate`` owns one exact systemd drop-in and proves
authenticated inventory, and ``restore`` removes only that transaction-owned
drop-in.  The normal first-adoption transaction remains the sole owner of the
database migration.
"""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import importlib
import importlib.util
import io
import json
import marshal
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import shlex
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import quote
import uuid

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from server_wide_installer_fence import (
    InstallerFenceError,
    acquire_installer_mutex,
    acquire_transaction_fence,
    release_nested_installer_fence,
)


ROOT = SCRIPT_ROOT.parent
DEFAULT_RELEASE_ROOT = Path("/opt/devcoordinator-legacy-broker/releases")
DEFAULT_CLEAN_RELEASE_ROOT = Path(
    "/opt/devcoordinator-legacy-broker-clean/releases"
)
DEFAULT_AVAILABILITY_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
DEFAULT_DROPIN = Path(
    "/etc/systemd/system/devcoordinator-broker.service.d/"
    "95-schema12-cutover-bridge.conf"
)
DEFAULT_ENROLLED_HOME_DROPIN = Path(
    "/etc/systemd/system/devcoordinator-broker.service.d/"
    "80-enrolled-home-write-paths.conf"
)
DEFAULT_RETIREMENT_GUARD = Path(
    "/etc/systemd/system/devcoordinator-broker.service.d/"
    "99-schema13-retired-legacy-broker.conf"
)
DEFAULT_DATABASE = Path("/var/lib/devcoordinator/coordinator.sqlite3")
DEFAULT_PROFILE = Path("/etc/devcoordinator/client-profiles.json")
DEFAULT_SOCKET = Path("/run/devcoordinator-authority.sock")
INSTALLER_LOCK = Path("/run/devcoordinator-installer.lock")
BROKER_UNIT = "devcoordinator-broker.service"
ACCESS_GROUP = "devcoordinator-clients"
INTERNAL_CUTOVER_INVENTORY_ACTION = (
    "internal-cutover-schema12-inventory-read-canary"
)
SOURCE_PREFIX = PurePosixPath("skills/codex-dev-coordinator/scripts")
ENTRY_RELATIVE = SOURCE_PREFIX / "dev_coordinator.py"
DEPENDENCY_RELATIVE = SOURCE_PREFIX / "validate_runtime_dependencies.py"
SCHEMA_RELATIVE = SOURCE_PREFIX / "devcoordinator/schema.py"
MANIFEST_NAME = "legacy-broker-release.json"
JOURNAL_NAME = "bridge-journal.json"
HANDOFF_JOURNAL_NAME = "writer-handoff-journal.json"
SUCCESSOR_JOURNAL_NAME = "clean-successor-journal.json"
SUCCESSOR_TERMINAL_NAME = "clean-successor-terminal.json"
SUCCESSOR_COMPLETION_NAME = "clean-successor-completion.json"
SUCCESSOR_PROFILE_BACKUP_NAME = "clean-successor-profile.before.json"
SUCCESSOR_CLIENT_HANDOFF_INTENT_NAME = (
    "clean-successor-client-handoff-intent.json"
)
SUCCESSOR_CLIENT_HANDOFF_BACKUP_NAME = (
    "clean-successor-client-handoff.before.json"
)
SUCCESSOR_EXECUTOR_RESCUE_INTENT_NAME = (
    "clean-successor-executor-rescue-intent.json"
)
SUCCESSOR_EXECUTOR_RESCUE_BACKUP_NAME = (
    "clean-successor-executor-rescue.before.json"
)
SUCCESSOR_EXECUTOR_HANDOFF_INTENT_NAME = (
    "clean-successor-rescue-executor-handoff-intent.json"
)
SUCCESSOR_EXECUTOR_HANDOFF_BACKUP_NAME = (
    "clean-successor-rescue-executor-handoff.before.json"
)
SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_NAME = (
    "clean-successor-post-export-executor-continuation-intent.json"
)
SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_BACKUP_NAME = (
    "clean-successor-post-export-executor-continuation.before.json"
)
SUCCESSOR_POST_EXPORT_FAILED_CANDIDATE_BACKUP_NAME = (
    "clean-successor-post-export-failed-candidate.before.json"
)
SUCCESSOR_CANDIDATE_DIRECTORY = "clean-successor-candidate"
SUCCESSOR_POST_EXPORT_CANDIDATE_DIRECTORY = (
    "clean-successor-candidate-post-export-continuation"
)
SUCCESSOR_RESTORE_DIRECTORY = "clean-successor-predecessor-restore"
SUCCESSOR_SNAPSHOT_DIRECTORY = "clean-successor-authority-snapshots"
POLICY_RECOVERY_JOURNAL_NAME = "policy-reconciled-recovery-journal.json"
POLICY_RECOVERY_TERMINAL_NAME = "policy-reconciled-recovery-terminal.json"
POLICY_RECOVERY_PROFILE_BACKUP_NAME = (
    "policy-reconciled-client-profiles.before.json"
)
POLICY_RECOVERY_CANDIDATE_DIRECTORY = "policy-reconciled-clean-candidate"
POLICY_RECOVERY_SNAPSHOT_DIRECTORY = "policy-reconciled-authority-snapshots"
LIFECYCLE_QUIESCE_JOURNAL_NAME = "lifecycle-crash-loop-quiesce-journal.json"
LIFECYCLE_QUIESCE_TERMINAL_NAME = "lifecycle-crash-loop-quiesce-terminal.json"
BROKER_FRAGMENT = Path("/etc/systemd/system/devcoordinator-broker.service")
LIFECYCLE_REARM_JOURNAL_NAME = "lifecycle-predecessor-rearm.json"
MANIFEST_KIND = "devcoordinator-schema12-legacy-broker-release"
JOURNAL_KIND = "devcoordinator-schema12-legacy-broker-bridge"
HANDOFF_JOURNAL_KIND = "devcoordinator-schema12-legacy-writer-handoff"
READY_PROOF_KIND = "devcoordinator-schema12-legacy-broker-live-readiness"
SUCCESSOR_JOURNAL_KIND = "devcoordinator-schema12-clean-bridge-successor"
SUCCESSOR_TERMINAL_KIND = (
    "devcoordinator-schema12-clean-bridge-successor-terminal"
)
SUCCESSOR_COMPLETION_KIND = (
    "devcoordinator-schema12-clean-bridge-successor-completion"
)
SUCCESSOR_RESTORED_PROOF_KIND = (
    "devcoordinator-schema12-clean-bridge-predecessor-restored"
)
SUCCESSOR_CLIENT_HANDOFF_INTENT_KIND = (
    "devcoordinator-schema12-clean-bridge-client-handoff-intent"
)
SUCCESSOR_EXECUTOR_RESCUE_INTENT_KIND = (
    "devcoordinator-schema12-clean-bridge-executor-rescue-intent"
)
SUCCESSOR_EXECUTOR_HANDOFF_INTENT_KIND = (
    "devcoordinator-schema12-clean-bridge-rescue-executor-handoff-intent"
)
SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_KIND = (
    "devcoordinator-schema12-clean-bridge-post-export-executor-"
    "continuation-intent"
)
SUCCESSOR_PREDECESSOR_PROOF_KIND = (
    "devcoordinator-schema12-clean-bridge-predecessor-live"
)
LIFECYCLE_REARM_JOURNAL_KIND = (
    "devcoordinator-schema12-restored-predecessor-rearm"
)
SUCCESSOR_READY_PROOF_KIND = "devcoordinator-schema12-clean-bridge-live-readiness"
POLICY_RECOVERY_PRECLEAR_PROOF_KIND = (
    "devcoordinator-schema12-policy-reconciled-bridge-preclear-readiness"
)
POLICY_RECOVERY_JOURNAL_KIND = (
    "devcoordinator-schema12-policy-reconciled-bridge-recovery"
)
POLICY_RECOVERY_TERMINAL_KIND = (
    "devcoordinator-schema12-policy-reconciled-bridge-recovery-terminal"
)
LIFECYCLE_QUIESCE_JOURNAL_KIND = (
    "devcoordinator-schema12-lifecycle-crash-loop-quiesce"
)
LIFECYCLE_QUIESCE_TERMINAL_KIND = (
    "devcoordinator-schema12-lifecycle-crash-loop-quiesce-terminal"
)
SUCCESSOR_FENCE_OWNER = "schema12-clean-bridge-successor"
CONTRACT_VERSION = 1
JOURNAL_CONTRACT_VERSION = 2
PREDECESSOR_JOURNAL_CONTRACT_VERSION = 3
EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION = 4
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
RELEASE_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
BYTECODE_CACHE_RE = re.compile(
    r"(?P<module>[A-Za-z_][A-Za-z0-9_]*)\.cpython-(?P<abi>[0-9]+)"
    r"(?:\.opt-(?P<opt>[12]))?\.pyc\Z"
)
MAX_PREDECESSOR_CACHE_FILES = 4096
MAX_PREDECESSOR_CACHE_FILE_BYTES = 8 * 1024 * 1024
MAX_PREDECESSOR_CACHE_TOTAL_BYTES = 128 * 1024 * 1024
SYSTEMD_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]*\Z")
SCHEMA12_STARTUP_ERROR = (
    "coordinator schema 12 requires the sealed offline repository-owner "
    "authority migration"
)
SYSTEM_ENVIRONMENT = {
    "HOME": "/root",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
SUCCESSOR_EXECUTOR_RESCUE_REASON = (
    "resume-retired-successor-with-retained-client"
)
SUCCESSOR_EXECUTOR_RESCUE_PATH = "successor-executor-rescue"
SUCCESSOR_EXECUTOR_HANDOFF_REASON = (
    "continue-published-rescue-with-corrected-executor"
)
SUCCESSOR_EXECUTOR_HANDOFF_PATH = "successor-rescue-executor-handoff"
SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON = (
    "continue-post-export-rescue-with-corrected-executor"
)
SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH = (
    "successor-rescue-post-export-executor-continuation"
)
PROCESS_ACTIVE_STATES = {"activating", "active", "reloading", "deactivating"}
BROKER_STATUS_STABILITY_SECONDS = 0.1
BROKER_FAILURE_JOURNAL_LINES = 80
BROKER_FAILURE_JOURNAL_BYTES = 64 * 1024
BROKER_FAILURE_COMMAND_TIMEOUT_SECONDS = 10
BROKER_FAILURE_PROPERTIES = ("Result", "ExecMainCode", "ExecMainStatus")
_DIAGNOSTIC_BEARER_RE = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"
)
_DIAGNOSTIC_SECRET_FIELD_RE = re.compile(
    r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"password|passwd|secret|token|api[_-]?key)\b[\"']?"
    r"(?:\s*[:=]\s*|\s+))[^\r\n]*"
)
_DIAGNOSTIC_URL_USERINFO_RE = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@"
)
_DIAGNOSTIC_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----"
)
RETIREMENT_GUARD_PAYLOAD = (
    "# Permanent schema-12 writer retirement fence.\n"
    "[Unit]\n"
    "ConditionPathExists=!/\n"
).encode("utf-8")


class BridgeError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise BridgeError("bridge evidence is not canonical JSON") from error


def _digest_document(value: Mapping[str, object]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _seal(
    kind: str,
    values: Mapping[str, object],
    *,
    schema_version: int = CONTRACT_VERSION,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": schema_version,
        "kind": kind,
        **dict(values),
    }
    if "document_sha256" in values:
        raise BridgeError("bridge evidence contains a reserved digest field")
    document["document_sha256"] = _digest_document(document)
    return document


def _verify_seal(
    value: object,
    *,
    kind: str,
    fields: set[str],
    schema_version: int = CONTRACT_VERSION,
) -> dict[str, object]:
    expected = {"schema_version", "kind", "document_sha256", *fields}
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema_version") != schema_version
        or value.get("kind") != kind
        or not isinstance(value.get("document_sha256"), str)
        or RELEASE_RE.fullmatch(str(value["document_sha256"])) is None
        or _digest_document(value) != value["document_sha256"]
    ):
        raise BridgeError(f"{kind} evidence is invalid")
    return dict(value)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute(path: Path, label: str) -> Path:
    candidate = path.expanduser().absolute()
    if not candidate.is_absolute() or Path(os.path.normpath(candidate)) != candidate:
        raise BridgeError(f"{label} must be an absolute canonical path")
    return candidate


def _private_regular(path: Path, *, uid: int, label: str) -> os.stat_result:
    candidate = _absolute(path, label)
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_nlink != 1
    ):
        raise BridgeError(f"{label} must be a private regular file owned by UID {uid}")
    return info


def _protected_profile(path: Path, *, uid: int) -> os.stat_result:
    """Prove the installed group-readable, root-owned profile boundary."""

    candidate = _absolute(path, "protected profile")
    parent_info = candidate.parent.lstat()
    info = candidate.lstat()
    try:
        access_gid = grp.getgrnam(ACCESS_GROUP).gr_gid
    except KeyError as error:
        raise BridgeError(f"required access group is missing: {ACCESS_GROUP}") from error
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != uid
        or parent_info.st_gid != access_gid
        or stat.S_IMODE(parent_info.st_mode) != 0o750
        or candidate.parent.resolve(strict=True) != candidate.parent
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != access_gid
        or stat.S_IMODE(info.st_mode) != 0o640
        or info.st_nlink != 1
        or candidate.resolve(strict=True) != candidate
    ):
        raise BridgeError("protected profile has unsafe ownership or permissions")
    return info


def _private_directory(path: Path, *, uid: int, create: bool = False) -> Path:
    candidate = _absolute(path, "bridge transaction directory")
    if create:
        candidate.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise BridgeError("bridge transaction directory must be private and owner-only")
    return candidate


def _read_private_json(path: Path, *, uid: int, label: str) -> dict[str, Any]:
    info = _private_regular(path, uid=uid, label=label)
    if info.st_size <= 0 or info.st_size > MAX_JSON_BYTES:
        raise BridgeError(f"{label} size is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        payload = bytearray()
        while len(payload) <= MAX_JSON_BYTES:
            block = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_JSON_BYTES:
        raise BridgeError(f"{label} exceeds its size limit")
    try:
        value = json.loads(bytes(payload))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BridgeError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise BridgeError(f"{label} must contain a JSON object")
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
    ):
        raise BridgeError(f"{label} changed while it was read")
    return value


def _atomic_private_json(path: Path, value: Mapping[str, object], *, uid: int) -> None:
    parent = _private_directory(path.parent, uid=uid, create=True)
    payload = json.dumps(
        value,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    temporary = parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BridgeError("bridge journal write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _run(
    argv: Iterable[str],
    *,
    timeout: float = 30.0,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    pass_fds: Iterable[int] = (),
) -> subprocess.CompletedProcess[str]:
    command = [str(item) for item in argv]
    descriptors = tuple(int(item) for item in pass_fds)
    if any(item < 0 for item in descriptors) or len(set(descriptors)) != len(
        descriptors
    ):
        raise BridgeError("command inherited descriptors are invalid")
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(env) if env is not None else None,
            timeout=timeout,
            check=False,
            pass_fds=descriptors,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BridgeError(f"command failed: {command[0]}: {error}") from error
    if len(completed.stdout) > 4 * 1024 * 1024 or len(completed.stderr) > 4 * 1024 * 1024:
        raise BridgeError(f"command output exceeded its bound: {command[0]}")
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise BridgeError(
            f"command failed ({completed.returncode}): {' '.join(command[:3])}: "
            f"{detail[:4096]}"
        )
    return completed


@contextmanager
def _installer_lock(expected_uid: int):
    handle = None
    nested = False
    try:
        handle = acquire_installer_mutex(
            expected_uid=expected_uid,
            expected_gid=0,
            lock_path=INSTALLER_LOCK,
        )
        nested = handle.depth > 1
        yield
    except InstallerFenceError as error:
        raise BridgeError(str(error)) from error
    finally:
        if handle is not None:
            if nested:
                release_nested_installer_fence(handle)
            else:
                handle.close(command_succeeded=True)


@contextmanager
def _broker_service_lock(database: Path, *, expected_uid: int):
    """Exclude the real broker while validating a retained WAL snapshot."""

    lock_path = database.parent / ".broker-service.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise BridgeError("broker service lifetime lock has unsafe identity")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BridgeError("legacy broker acquired its service lifetime lock") from error
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _git(repo: Path, *arguments: str, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={repo}",
            "-C",
            os.fspath(repo),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise BridgeError(
            "Git object read failed: "
            + completed.stderr.decode("utf-8", errors="replace")[:4096]
        )
    if len(completed.stdout) > MAX_ARCHIVE_BYTES:
        raise BridgeError("Git object output exceeds the bridge archive limit")
    if binary:
        return bytes(completed.stdout)
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise BridgeError("Git returned non-text object identity") from error


def _schema_version_from_source(payload: bytes) -> int:
    try:
        tree = ast.parse(payload.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as error:
        raise BridgeError("legacy schema module is not parseable Python") from error
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "SCHEMA_VERSION"
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is int
        ):
            return int(node.value.value)
    raise BridgeError("legacy schema module does not declare SCHEMA_VERSION")


def _archive_members(payload: bytes) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    entries: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            is_source_ancestor = (
                member.isdir()
                and len(path.parts) < len(SOURCE_PREFIX.parts)
                and SOURCE_PREFIX.parts[: len(path.parts)] == path.parts
            )
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or (
                    not is_source_ancestor
                    and path.parts[: len(SOURCE_PREFIX.parts)] != SOURCE_PREFIX.parts
                )
            ):
                raise BridgeError("Git archive contains an unsafe path")
            normalized = path.as_posix()
            if member.isdir():
                entries.append({"path": normalized, "kind": "directory", "mode": "0555"})
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise BridgeError("Git archive contains a non-regular source entry")
            source = archive.extractfile(member)
            if source is None:
                raise BridgeError("Git archive regular file has no payload")
            data = source.read(MAX_ARCHIVE_BYTES + 1)
            if len(data) > MAX_ARCHIVE_BYTES:
                raise BridgeError("legacy source file exceeds the bridge size limit")
            mode = "0555" if member.mode & 0o111 else "0444"
            entries.append(
                {
                    "path": normalized,
                    "kind": "file",
                    "mode": mode,
                    "size": len(data),
                    "sha256": _sha256_bytes(data),
                }
            )
            contents[normalized] = data
    entries.sort(key=lambda item: str(item["path"]))
    if str(ENTRY_RELATIVE) not in contents or str(DEPENDENCY_RELATIVE) not in contents:
        raise BridgeError("Git archive lacks the legacy broker entry points")
    schema = contents.get(str(SCHEMA_RELATIVE))
    if schema is None or _schema_version_from_source(schema) != 12:
        raise BridgeError("selected Git tree is not an exact schema-12 broker")
    return entries, contents


def _release_payload(
    *, commit: str, tree: str, entries: list[dict[str, object]]
) -> dict[str, object]:
    binding = {
        "git_commit": commit,
        "git_scripts_tree": tree,
        "authority_schema_version": 12,
        "files": entries,
    }
    release_digest = hashlib.sha256(_canonical(binding)).hexdigest()
    return _seal(MANIFEST_KIND, {**binding, "release_digest": release_digest})


def _release_summary(
    manifest: Mapping[str, object], *, release: Path, created: bool | None = None
) -> dict[str, object]:
    files = manifest.get("files")
    result: dict[str, object] = {
        "ok": True,
        "release": str(release),
        "release_digest": manifest["release_digest"],
        "manifest_sha256": manifest["document_sha256"],
        "git_commit": manifest["git_commit"],
        "git_scripts_tree": manifest["git_scripts_tree"],
        "authority_schema_version": manifest["authority_schema_version"],
        "sealed_entry_count": len(files) if isinstance(files, list) else 0,
    }
    if created is not None:
        result["created"] = created
    return result


def _require_release_root(path: Path, *, owner_uid: int, owner_gid: int) -> Path:
    candidate = _absolute(path, "legacy release root")
    if candidate in {DEFAULT_RELEASE_ROOT, DEFAULT_CLEAN_RELEASE_ROOT}:
        _default_release_ancestry(
            candidate,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            reconcile=True,
        )
        return candidate
    if candidate == Path("/opt") or Path("/opt") in candidate.parents:
        raise BridgeError(
            "legacy /opt release root is not one of the sealed dedicated roots"
        )
    candidate.mkdir(parents=True, mode=0o755, exist_ok=True)
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise BridgeError("legacy release root has unsafe ownership or permissions")
    return candidate


def _default_release_ancestry(
    release_root: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    reconcile: bool,
) -> None:
    """Verify, and during stage only repair, the dedicated public ancestry.

    The immutable broker bytes contain no credentials and must be traversable
    by enrolled canary UIDs.  This permission reconciliation is intentionally
    limited to the two dedicated directories beneath an already trusted
    parent; arbitrary custom release roots retain their prior semantics.
    """

    release_root = _absolute(release_root, "legacy release root")
    if release_root not in {DEFAULT_RELEASE_ROOT, DEFAULT_CLEAN_RELEASE_ROOT}:
        raise BridgeError("release ancestry helper received a custom path")
    dedicated_root = release_root.parent
    parent = dedicated_root.parent
    parent_info = parent.lstat()
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != owner_uid
        or parent_info.st_gid != owner_gid
        or stat.S_IMODE(parent_info.st_mode) & 0o022
        or stat.S_IMODE(parent_info.st_mode) & 0o111 != 0o111
        or parent.resolve(strict=True) != parent
    ):
        raise BridgeError("legacy dedicated release parent is unsafe")

    for directory in (dedicated_root, release_root):
        changed = False
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if not reconcile:
                raise BridgeError(
                    f"legacy dedicated release ancestry is missing: {directory}"
                ) from None
            os.mkdir(directory, 0o755)
            os.chmod(directory, 0o755, follow_symlinks=False)
            changed = True
            info = directory.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) & 0o022
            or directory.resolve(strict=True) != directory
        ):
            raise BridgeError(
                f"legacy dedicated release ancestry is unsafe: {directory}"
            )
        if reconcile and stat.S_IMODE(info.st_mode) != 0o755:
            os.chmod(directory, 0o755, follow_symlinks=False)
            changed = True
            info = directory.lstat()
        if stat.S_IMODE(info.st_mode) != 0o755:
            raise BridgeError(
                f"legacy dedicated release ancestry mode is not 0755: {directory}"
            )
        if changed:
            parent_descriptor = os.open(
                directory.parent,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)


def _trusted_activation_directory(path: Path, *, owner_uid: int) -> None:
    """Require an immutable owner-controlled chain from ``/`` through path."""

    candidate = _absolute(path, "legacy activation release directory")
    current = Path(candidate.anchor)
    chain = [current]
    for part in candidate.parts[1:]:
        current = current / part
        chain.append(current)
    for current in chain:
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise BridgeError(
                f"legacy activation release ancestor is missing: {current}"
            ) from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) & 0o022
            or current.resolve(strict=True) != current
        ):
            raise BridgeError(
                f"legacy activation release ancestor is unsafe: {current}"
            )


def _verify_activation_release(
    release: Path,
    *,
    release_root: Path,
    owner_uid: int,
    allow_verified_bytecode_cache: bool = False,
) -> dict[str, object]:
    """Verify bytes only after the whole privileged release chain is trusted."""

    release = _absolute(release, "legacy release")
    release_root = _absolute(release_root, "legacy release root")
    _trusted_activation_directory(release_root, owner_uid=owner_uid)
    _trusted_activation_directory(release, owner_uid=owner_uid)
    manifest = verify_release(
        release,
        release_root=release_root,
        _allow_verified_bytecode_cache=allow_verified_bytecode_cache,
    )
    # Recheck after hashing so an administrator-side replacement cannot be
    # silently accepted across the verification boundary.
    _trusted_activation_directory(release_root, owner_uid=owner_uid)
    _trusted_activation_directory(release, owner_uid=owner_uid)
    return manifest


def stage_release(
    *,
    repo: Path,
    commit: str,
    release_root: Path,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, object]:
    if os.geteuid() != owner_uid:
        raise BridgeError("legacy release staging must run as its declared owner")
    repo = _absolute(repo, "repository")
    resolved_commit = str(_git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}"))
    if GIT_OBJECT_RE.fullmatch(resolved_commit) is None:
        raise BridgeError("Git commit identity is invalid")
    tree = str(_git(repo, "rev-parse", f"{resolved_commit}:{SOURCE_PREFIX.as_posix()}"))
    if GIT_OBJECT_RE.fullmatch(tree) is None:
        raise BridgeError("Git scripts tree identity is invalid")
    archive = _git(
        repo,
        "archive",
        "--format=tar",
        resolved_commit,
        SOURCE_PREFIX.as_posix(),
        binary=True,
    )
    if not isinstance(archive, bytes):
        raise BridgeError("Git archive payload is invalid")
    entries, contents = _archive_members(archive)
    manifest = _release_payload(commit=resolved_commit, tree=tree, entries=entries)
    release_root = _require_release_root(
        release_root, owner_uid=owner_uid, owner_gid=owner_gid
    )
    destination = release_root / str(manifest["release_digest"])
    if destination.exists() or destination.is_symlink():
        verified = verify_release(destination, release_root=release_root)
        if verified != manifest:
            raise BridgeError("existing legacy release contradicts the requested Git tree")
        return _release_summary(verified, release=destination, created=False)

    temporary = release_root / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    temporary.mkdir(mode=0o700)
    try:
        for entry in entries:
            relative = Path(str(entry["path"]))
            target = temporary / relative
            if entry["kind"] == "directory":
                target.mkdir(parents=True, mode=0o700, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                view = memoryview(contents[str(entry["path"])])
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise BridgeError("legacy release file write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(target, int(str(entry["mode"]), 8), follow_symlinks=False)

        manifest_path = temporary / MANIFEST_NAME
        manifest_payload = json.dumps(
            manifest,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        descriptor = os.open(
            manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(manifest_payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise BridgeError("legacy release manifest write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(manifest_path, 0o444, follow_symlinks=False)
        directories = sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        )
        for directory in directories:
            os.chmod(directory, 0o555, follow_symlinks=False)
        os.chmod(temporary, 0o555, follow_symlinks=False)
        os.replace(temporary, destination)
        parent = os.open(release_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            os.chmod(temporary, 0o700, follow_symlinks=False)
            shutil.rmtree(temporary)
    verified = verify_release(destination, release_root=release_root)
    return _release_summary(verified, release=destination, created=True)


def _verified_predecessor_bytecode_cache(
    *,
    release: Path,
    expected_paths: set[str],
    actual_paths: set[str],
    owner_uid: int,
    owner_gid: int,
) -> list[dict[str, object]]:
    """Prove that every unsealed predecessor byte is compiler-identical cache.

    A historical bridge can become non-immutable when root runs its Python
    entrypoint without ``-B``.  The clean-successor transaction must still be
    able to stop that exact writer, but it must never trust arbitrary unsealed
    bytecode.  Accept only direct ``__pycache__`` children whose marshalled
    code is byte-for-byte what this interpreter compiles from an already
    sealed source file at the same absolute path.
    """

    missing = expected_paths - actual_paths
    extras = actual_paths - expected_paths
    if missing:
        raise BridgeError("legacy release lost sealed entries")
    if not extras:
        return []
    cache_tag = str(getattr(sys.implementation, "cache_tag", ""))
    if re.fullmatch(r"cpython-[0-9]+", cache_tag) is None:
        raise BridgeError("predecessor bytecode cache ABI is unavailable")
    evidence: list[dict[str, object]] = []
    total_bytes = 0
    cache_directories: set[str] = set()
    cache_files: list[tuple[str, re.Match[str]]] = []
    for text in sorted(extras):
        relative = PurePosixPath(text)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[: len(SOURCE_PREFIX.parts)] != SOURCE_PREFIX.parts
        ):
            raise BridgeError("legacy release contains unsafe unsealed entries")
        target = release / Path(text)
        info = target.lstat()
        if info.st_uid != owner_uid or info.st_gid != owner_gid:
            raise BridgeError("predecessor bytecode cache ownership changed")
        if relative.name == "__pycache__":
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) & 0o022
                or relative.parent.as_posix() not in expected_paths
            ):
                raise BridgeError("predecessor bytecode cache directory is unsafe")
            cache_directories.add(text)
            continue
        match = BYTECODE_CACHE_RE.fullmatch(relative.name)
        if (
            match is None
            or relative.parent.name != "__pycache__"
            or relative.parent.as_posix() not in extras
            or len(relative.parts) < len(SOURCE_PREFIX.parts) + 3
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_size <= 16
            or info.st_size > MAX_PREDECESSOR_CACHE_FILE_BYTES
        ):
            raise BridgeError("predecessor bytecode cache entry is unsafe")
        cache_files.append((text, match))
    if set(relative.rsplit("/", 1)[0] for relative, _match in cache_files) != cache_directories:
        raise BridgeError("predecessor bytecode cache directory is incomplete")
    if not cache_files or len(cache_files) > MAX_PREDECESSOR_CACHE_FILES:
        raise BridgeError("predecessor bytecode cache file count is invalid")
    for text, match in cache_files:
        relative = PurePosixPath(text)
        if f"cpython-{match.group('abi')}" != cache_tag:
            raise BridgeError("predecessor bytecode cache ABI changed")
        source_relative = relative.parent.parent / f"{match.group('module')}.py"
        if source_relative.as_posix() not in expected_paths:
            raise BridgeError("predecessor bytecode cache lacks sealed source")
        source = release / Path(source_relative.as_posix())
        bytecode = release / Path(text)
        payload = bytecode.read_bytes()
        if payload[:4] != importlib.util.MAGIC_NUMBER:
            raise BridgeError("predecessor bytecode cache magic changed")
        flags = int.from_bytes(payload[4:8], "little")
        if flags not in {0, 1, 3}:
            raise BridgeError("predecessor bytecode cache flags are unsupported")
        optimize = int(match.group("opt") or "0")
        try:
            compiled = compile(
                source.read_bytes(),
                str(source),
                "exec",
                dont_inherit=True,
                optimize=optimize,
            )
            stream = io.BytesIO(payload[16:])
            cached = marshal.load(stream)
            trailing = stream.read(1)
        except (EOFError, OSError, SyntaxError, ValueError, TypeError) as error:
            raise BridgeError(
                "sealed predecessor source could not be compiled"
            ) from error
        if (
            trailing
            or not isinstance(cached, type(compiled))
            or cached != compiled
        ):
            raise BridgeError(
                "predecessor bytecode cache does not match sealed source"
            )
        total_bytes += len(payload)
        if total_bytes > MAX_PREDECESSOR_CACHE_TOTAL_BYTES:
            raise BridgeError("predecessor bytecode cache exceeds its bound")
        evidence.append(
            {
                "path": text,
                "source": source_relative.as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": f"{stat.S_IMODE(bytecode.lstat().st_mode):04o}",
            }
        )
    return evidence


def verify_release(
    release: Path,
    *,
    release_root: Path = DEFAULT_RELEASE_ROOT,
    _allow_verified_bytecode_cache: bool = False,
) -> dict[str, object]:
    release = _absolute(release, "legacy release")
    root = _absolute(release_root, "legacy release root")
    if release.parent != root or RELEASE_RE.fullmatch(release.name) is None:
        raise BridgeError("legacy release path is outside the dedicated release root")
    root_info = root.lstat()
    if root in {DEFAULT_RELEASE_ROOT, DEFAULT_CLEAN_RELEASE_ROOT}:
        _default_release_ancestry(
            root,
            owner_uid=root_info.st_uid,
            owner_gid=root_info.st_gid,
            reconcile=False,
        )
    elif root == Path("/opt") or Path("/opt") in root.parents:
        raise BridgeError(
            "legacy /opt release root is not one of the sealed dedicated roots"
        )
    release_info = release.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or stat.S_IMODE(root_info.st_mode) & 0o022
        or stat.S_ISLNK(release_info.st_mode)
        or not stat.S_ISDIR(release_info.st_mode)
        or release_info.st_uid != root_info.st_uid
        or release_info.st_gid != root_info.st_gid
        or stat.S_IMODE(release_info.st_mode) != 0o555
    ):
        raise BridgeError("legacy release directory identity is unsafe")
    manifest_path = release / MANIFEST_NAME
    manifest_info = manifest_path.lstat()
    if (
        stat.S_ISLNK(manifest_info.st_mode)
        or not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_uid != root_info.st_uid
        or manifest_info.st_gid != root_info.st_gid
        or stat.S_IMODE(manifest_info.st_mode) != 0o444
        or manifest_info.st_size <= 0
        or manifest_info.st_size > MAX_JSON_BYTES
    ):
        raise BridgeError("legacy release manifest identity is unsafe")
    try:
        raw = json.loads(manifest_path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BridgeError("legacy release manifest is not valid JSON") from error
    fields = {
        "git_commit",
        "git_scripts_tree",
        "authority_schema_version",
        "files",
        "release_digest",
    }
    manifest = _verify_seal(raw, kind=MANIFEST_KIND, fields=fields)
    if (
        manifest["release_digest"] != release.name
        or GIT_OBJECT_RE.fullmatch(str(manifest["git_commit"])) is None
        or GIT_OBJECT_RE.fullmatch(str(manifest["git_scripts_tree"])) is None
        or manifest["authority_schema_version"] != 12
        or not isinstance(manifest["files"], list)
    ):
        raise BridgeError("legacy release manifest binding is invalid")

    expected_paths = {MANIFEST_NAME}
    schema_payload: bytes | None = None
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) not in (
            {"path", "kind", "mode"},
            {"path", "kind", "mode", "size", "sha256"},
        ):
            raise BridgeError("legacy release file evidence is invalid")
        relative = PurePosixPath(str(entry["path"]))
        is_source_ancestor = (
            entry.get("kind") == "directory"
            and len(relative.parts) < len(SOURCE_PREFIX.parts)
            and SOURCE_PREFIX.parts[: len(relative.parts)] == relative.parts
        )
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or (
                not is_source_ancestor
                and relative.parts[: len(SOURCE_PREFIX.parts)] != SOURCE_PREFIX.parts
            )
        ):
            raise BridgeError("legacy release manifest contains an unsafe path")
        text = relative.as_posix()
        if text in expected_paths:
            raise BridgeError("legacy release manifest contains a duplicate path")
        expected_paths.add(text)
        target = release / Path(text)
        info = target.lstat()
        if info.st_uid != root_info.st_uid or info.st_gid != root_info.st_gid:
            raise BridgeError("legacy release entry ownership changed")
        wanted_mode = int(str(entry["mode"]), 8)
        if entry["kind"] == "directory":
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != wanted_mode:
                raise BridgeError("legacy release directory changed")
        elif entry["kind"] == "file":
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != wanted_mode
                or info.st_size != entry.get("size")
                or _sha256_file(target) != entry.get("sha256")
            ):
                raise BridgeError("legacy release file changed")
            if text == str(SCHEMA_RELATIVE):
                schema_payload = target.read_bytes()
        else:
            raise BridgeError("legacy release entry kind is invalid")
    actual_paths = {
        path.relative_to(release).as_posix()
        for path in release.rglob("*")
    }
    cache_evidence: list[dict[str, object]] = []
    if actual_paths != expected_paths:
        if not _allow_verified_bytecode_cache:
            raise BridgeError("legacy release contains unsealed entries")
        cache_evidence = _verified_predecessor_bytecode_cache(
            release=release,
            expected_paths=expected_paths,
            actual_paths=actual_paths,
            owner_uid=int(root_info.st_uid),
            owner_gid=int(root_info.st_gid),
        )
    if schema_payload is None or _schema_version_from_source(schema_payload) != 12:
        raise BridgeError("legacy release schema contract changed")
    binding = {
        "git_commit": manifest["git_commit"],
        "git_scripts_tree": manifest["git_scripts_tree"],
        "authority_schema_version": 12,
        "files": manifest["files"],
    }
    if hashlib.sha256(_canonical(binding)).hexdigest() != manifest["release_digest"]:
        raise BridgeError("legacy release content digest is invalid")
    if not cache_evidence:
        return manifest
    verified = dict(manifest)
    verified["verified_unsealed_bytecode_cache"] = cache_evidence
    verified["verified_unsealed_bytecode_cache_sha256"] = _sha256_bytes(
        _canonical(cache_evidence)
    )
    return verified


def _failed_activation_proof(
    transaction: Path, *, operation_id: str, uid: int
) -> dict[str, object]:
    journal = _read_private_json(
        _absolute(transaction, "failed installer transaction") / "install-journal.json",
        uid=uid,
        label="failed installer journal",
    )
    activation = journal.get("activation")
    failure = activation.get("failure_evidence") if isinstance(activation, dict) else None
    service_journal = failure.get("journal") if isinstance(failure, dict) else None
    tail = service_journal.get("tail") if isinstance(service_journal, dict) else None
    if (
        journal.get("status") != "applied"
        or not isinstance(activation, dict)
        or activation.get("operation_id") != operation_id
        or activation.get("phase") != "failed"
        or activation.get("initial_active") is not False
        or not isinstance(activation.get("baseline_restored_at_epoch"), int)
        or not isinstance(tail, str)
        or SCHEMA12_STARTUP_ERROR not in tail
    ):
        raise BridgeError("installer journal does not prove the schema-12 activation deadlock")
    return {
        "path": str(_absolute(transaction, "failed installer transaction") / "install-journal.json"),
        "document_sha256": _sha256_file(
            _absolute(transaction, "failed installer transaction") / "install-journal.json"
        ),
        "operation_id": operation_id,
        "baseline_restored_at_epoch": activation["baseline_restored_at_epoch"],
    }


def _load_cutover_module():
    module_root = ROOT / "scripts"
    if str(module_root) not in sys.path:
        sys.path.insert(0, str(module_root))
    import orchestrate_availability_cutover as cutover  # type: ignore[import-not-found]

    return cutover


def _sqlite_regular_identity(
    path: Path, *, uid: int, label: str
) -> dict[str, int]:
    candidate = _absolute(path, label)
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_nlink != 1
        or candidate.resolve(strict=True) != candidate
    ):
        raise BridgeError(f"{label} has unsafe identity")
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": int(info.st_nlink),
    }


def _sqlite_sidecar_identities(
    database: Path, *, uid: int
) -> dict[str, dict[str, int] | None]:
    identities: dict[str, dict[str, int] | None] = {}
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database) + suffix)
        if not sidecar.exists() and not sidecar.is_symlink():
            identities[suffix] = None
            continue
        identity = _sqlite_regular_identity(
            sidecar,
            uid=uid,
            label=f"authority SQLite {suffix[1:]} sidecar",
        )
        if suffix == "-wal" and identity["size"] != 0:
            raise BridgeError(
                "authority SQLite WAL must be absent or exactly zero bytes"
            )
        identities[suffix] = identity
    return identities


def _readiness_proof(
    attestation: Path,
    *,
    database: Path,
    uid: int,
    descendant_of: Mapping[str, object] | None = None,
) -> dict[str, object]:
    raw = _read_private_json(attestation, uid=uid, label="authority readiness attestation")
    cutover = _load_cutover_module()
    database = _absolute(database, "authority database")
    database_before = _sqlite_regular_identity(
        database,
        uid=uid,
        label="authority database",
    )
    sidecars_before = _sqlite_sidecar_identities(database, uid=uid)
    connection: sqlite3.Connection | None = None
    document: Any = None
    snapshot: Any = None
    validation_error: Exception | None = None
    try:
        document = cutover._authority_readiness_result(raw)
        encoded = quote(os.fspath(database), safe="/")
        connection = sqlite3.connect(
            f"file:{encoded}?mode=ro&immutable=1",
            uri=True,
            timeout=5.0,
        )
        snapshot = cutover._read_authority_readiness_snapshot(
            database,
            connection=connection,
        )
    except Exception as error:
        validation_error = error
    finally:
        if connection is not None:
            connection.close()
    database_after = _sqlite_regular_identity(
        database,
        uid=uid,
        label="authority database",
    )
    sidecars_after = _sqlite_sidecar_identities(database, uid=uid)
    if database_after != database_before:
        raise BridgeError("authority database changed during immutable readiness proof")
    if sidecars_after != sidecars_before:
        raise BridgeError("authority SQLite sidecars changed during readiness proof")
    if validation_error is not None:
        raise BridgeError(
            f"authority readiness evidence is invalid: {validation_error}"
        ) from validation_error
    current_identity = {
        key: database_after[key]
        for key in ("device", "inode", "size")
    }
    mismatch = (
        document.get("database") != str(database)
        or document.get("database_identity_after") != current_identity
        or document.get("postcondition") != snapshot
        or snapshot.get("metadata", {}).get("schema_version") != 12
        or snapshot.get("metadata", {}).get("migration_state") != "ready"
    )
    if mismatch and descendant_of is None:
        raise BridgeError("live authority no longer matches its sealed schema-12 readiness")
    if mismatch:
        _validate_readiness_descendant(
            descendant_of,
            current_identity=current_identity,
            snapshot=snapshot,
        )
    return {
        "path": str(_absolute(attestation, "authority readiness attestation")),
        "document_sha256": document["document_sha256"],
        "database_identity": current_identity,
        "database_generation": snapshot["metadata"]["database_generation"],
        "state_revision": snapshot["metadata"]["state_revision"],
        "snapshot": snapshot,
    }


def _verify_retained_readiness_reference(
    attestation: Path, expected: object, *, uid: int
) -> dict[str, object]:
    """Revalidate the sealed readiness document without reading a live writer."""

    if not isinstance(expected, dict):
        raise BridgeError("bridge journal omitted authority readiness evidence")
    raw = _read_private_json(
        attestation, uid=uid, label="authority readiness attestation"
    )
    cutover = _load_cutover_module()
    try:
        document = cutover._authority_readiness_result(raw)
    except Exception as error:
        raise BridgeError(f"authority readiness evidence is invalid: {error}") from error
    if (
        expected.get("path")
        != str(_absolute(attestation, "authority readiness attestation"))
        or expected.get("document_sha256") != document.get("document_sha256")
    ):
        raise BridgeError("retained authority readiness attestation changed")
    return dict(expected)


def _readiness_origin_from_attestation(
    attestation: Path, expected: object, *, uid: int
) -> dict[str, object]:
    readiness_fields = {
        "path",
        "document_sha256",
        "database_identity",
        "database_generation",
        "state_revision",
        "snapshot",
    }
    if not isinstance(expected, dict) or set(expected) != readiness_fields:
        raise BridgeError("bridge journal omitted authority readiness evidence")
    raw = _read_private_json(
        attestation, uid=uid, label="authority readiness attestation"
    )
    cutover = _load_cutover_module()
    try:
        document = cutover._authority_readiness_result(raw)
    except Exception as error:
        raise BridgeError(f"authority readiness evidence is invalid: {error}") from error
    snapshot = document.get("postcondition")
    metadata = snapshot.get("metadata") if isinstance(snapshot, dict) else None
    if (
        expected.get("path") != str(_absolute(attestation, "authority readiness attestation"))
        or expected.get("document_sha256") != document.get("document_sha256")
        or expected.get("database_identity") != document.get("database_identity_after")
        or not isinstance(metadata, dict)
        or expected.get("database_generation") != metadata.get("database_generation")
        or expected.get("state_revision") != metadata.get("state_revision")
        or expected.get("snapshot") != snapshot
    ):
        raise BridgeError("legacy journal readiness does not match its sealed attestation")
    return dict(expected)


def _validate_readiness_descendant(
    origin: Mapping[str, object],
    *,
    current_identity: Mapping[str, object],
    snapshot: object,
) -> None:
    origin_identity = origin.get("database_identity")
    origin_snapshot = origin.get("snapshot")
    if not isinstance(origin_identity, dict) or not isinstance(origin_snapshot, dict):
        raise BridgeError("readiness descendant origin is incomplete")
    cutover = _load_cutover_module()
    try:
        descendant = cutover._authority_readiness_ready_descendant(
            origin_snapshot,
            snapshot,
            label="schema-12 bridge retry readiness",
        )
    except Exception as error:
        raise BridgeError(
            f"live authority is not a safe descendant of sealed readiness: {error}"
        ) from error
    if (
        current_identity.get("device") != origin_identity.get("device")
        or current_identity.get("inode") != origin_identity.get("inode")
        or descendant.get("invariants") != origin_snapshot.get("invariants")
    ):
        raise BridgeError("live authority is not a safe descendant of sealed readiness")


def _systemd_state() -> dict[str, object]:
    properties = (
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "MainPID",
        "InvocationID",
        "NRestarts",
    )
    completed = _run(
        [
            "/usr/bin/systemctl",
            "show",
            BROKER_UNIT,
            "--property=" + ",".join(properties),
        ],
        timeout=10,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in properties and key not in values:
            values[key] = value
    if set(values) != set(properties):
        raise BridgeError("systemd returned incomplete broker state")
    try:
        main_pid = int(values["MainPID"])
        restarts = int(values["NRestarts"])
    except ValueError as error:
        raise BridgeError("systemd returned invalid numeric broker state") from error
    return {**values, "MainPID": main_pid, "NRestarts": restarts}


def _systemd_execution_identity() -> dict[str, str]:
    properties = (
        "FragmentPath",
        "DropInPaths",
        "ExecStart",
        "TriggeredBy",
        "WantedBy",
        "RequiredBy",
        "ConsistsOf",
        "PartOf",
        "BindsTo",
        "BoundBy",
    )
    completed = _run(
        [
            "/usr/bin/systemctl",
            "show",
            BROKER_UNIT,
            "--property=" + ",".join(properties),
        ],
        timeout=10,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in properties and key not in values:
            values[key] = value
    if set(values) != set(properties):
        raise BridgeError("systemd returned incomplete broker execution identity")
    return values


def _related_unit_states() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for unit in ("dev-coordinator.service", "prtzn-vpn-gateway.service"):
        completed = _run(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=LoadState,ActiveState,SubState,MainPID,NRestarts,Wants,Requires,ExecStart",
            ],
            timeout=10,
        )
        fields: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                fields[key] = value
        result[unit] = fields
    return result


def _systemd_failure_properties() -> dict[str, object]:
    """Read the last broker exit contract from one exact systemd unit."""

    completed = _run(
        [
            "/usr/bin/systemctl",
            "show",
            BROKER_UNIT,
            "--property=" + ",".join(BROKER_FAILURE_PROPERTIES),
        ],
        timeout=BROKER_FAILURE_COMMAND_TIMEOUT_SECONDS,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in BROKER_FAILURE_PROPERTIES and key not in values:
            values[key] = value
    if set(values) != set(BROKER_FAILURE_PROPERTIES):
        raise BridgeError("systemd returned incomplete broker failure state")
    try:
        main_code = int(values["ExecMainCode"])
        main_status = int(values["ExecMainStatus"])
    except ValueError as error:
        raise BridgeError("systemd returned invalid broker failure status") from error
    result = values["Result"]
    if (
        len(result) > 128
        or re.fullmatch(r"[a-z0-9_.-]*", result) is None
        or not 0 <= main_code <= 255
        or not 0 <= main_status <= 255
    ):
        raise BridgeError("systemd returned invalid broker failure status")
    return {
        "Result": result,
        "ExecMainCode": main_code,
        "ExecMainStatus": main_status,
    }


def _redact_diagnostic_text(value: str) -> tuple[str, bool]:
    """Remove common credential forms before privileged logs leave the wrapper."""

    if _DIAGNOSTIC_PRIVATE_KEY_RE.search(value):
        return "[REDACTED: private key material]", True
    redacted = _DIAGNOSTIC_BEARER_RE.sub("Bearer [REDACTED]", value)
    redacted = _DIAGNOSTIC_URL_USERINFO_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _DIAGNOSTIC_SECRET_FIELD_RE.sub(r"\1[REDACTED]", redacted)
    return redacted, redacted != value


def _bounded_journal_text(value: str) -> dict[str, object]:
    """Return at most the newest 80 lines and 64 KiB of redacted text."""

    redacted, contained_redaction = _redact_diagnostic_text(value)
    all_lines = redacted.splitlines()
    line_truncated = len(all_lines) > BROKER_FAILURE_JOURNAL_LINES
    selected = all_lines[-BROKER_FAILURE_JOURNAL_LINES :]
    selected_text = "\n".join(selected)
    encoded = selected_text.encode("utf-8")
    byte_truncated = len(encoded) > BROKER_FAILURE_JOURNAL_BYTES
    if byte_truncated:
        encoded = encoded[-BROKER_FAILURE_JOURNAL_BYTES :]
        selected_text = encoded.decode("utf-8", errors="ignore")
        while len(selected_text.encode("utf-8")) > BROKER_FAILURE_JOURNAL_BYTES:
            selected_text = selected_text[1:]
    return {
        "tail": selected_text,
        "line_count": len(selected_text.splitlines()),
        "byte_count": len(selected_text.encode("utf-8")),
        "redacted": contained_redaction,
        "truncated": line_truncated or byte_truncated,
        "line_truncated": line_truncated,
        "byte_truncated": byte_truncated,
        "max_lines": BROKER_FAILURE_JOURNAL_LINES,
        "max_bytes": BROKER_FAILURE_JOURNAL_BYTES,
    }


def _broker_failure_journal() -> dict[str, object]:
    """Capture one bounded exact-unit journal tail without exposing the shell."""

    try:
        completed = _run(
            [
                "/usr/bin/journalctl",
                "--unit",
                BROKER_UNIT,
                "--boot=0",
                "--no-pager",
                "--lines",
                str(BROKER_FAILURE_JOURNAL_LINES),
                "--output",
                "short-iso-precise",
            ],
            timeout=BROKER_FAILURE_COMMAND_TIMEOUT_SECONDS,
            env={
                **SYSTEM_ENVIRONMENT,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "SYSTEMD_COLORS": "0",
            },
            check=False,
        )
    except (BridgeError, UnicodeError) as error:
        detail, redacted = _redact_diagnostic_text(str(error))
        bounded = _bounded_journal_text(detail[:2048])
        return {
            "available": False,
            "error": bounded["tail"],
            "redacted": redacted or bounded["redacted"],
            "max_lines": BROKER_FAILURE_JOURNAL_LINES,
            "max_bytes": BROKER_FAILURE_JOURNAL_BYTES,
        }
    output = completed.stdout
    if completed.returncode != 0 and completed.stderr:
        output = f"{output}\n[journalctl stderr]\n{completed.stderr}"
    return {
        "available": completed.returncode == 0,
        "returncode": completed.returncode,
        **_bounded_journal_text(output),
    }


def _broker_failure_diagnostic() -> dict[str, object]:
    if os.geteuid() != 0:
        raise BridgeError(
            "schema-12 bridge failure diagnostics require the authority identity"
        )
    try:
        properties: dict[str, object] = _systemd_failure_properties()
        property_error = None
    except (BridgeError, UnicodeError) as error:
        properties = {}
        property_error, _redacted = _redact_diagnostic_text(str(error)[:2048])
    return {
        "captured_at_epoch": int(time.time()),
        "unit": BROKER_UNIT,
        "properties": properties,
        "property_error": property_error,
        "journal": _broker_failure_journal(),
    }


def _broker_status(broker_socket: Path) -> dict[str, object]:
    """Observe broker state and add privileged evidence only on instability."""

    if os.geteuid() != 0:
        raise BridgeError("schema-12 bridge status requires the authority identity")
    broker_socket = _absolute(broker_socket, "broker socket")
    first = _systemd_state()
    stably_ready = False
    state = first
    if (
        first.get("ActiveState") == "active"
        and first.get("SubState") == "running"
        and isinstance(first.get("MainPID"), int)
        and int(first["MainPID"]) > 0
        and _socket_ready(broker_socket)
    ):
        time.sleep(BROKER_STATUS_STABILITY_SECONDS)
        second = _systemd_state()
        state = second
        stable_fields = (
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "NRestarts",
        )
        if (
            all(second.get(field) == first.get(field) for field in stable_fields)
            and second.get("ActiveState") == "active"
            and second.get("SubState") == "running"
            and isinstance(second.get("MainPID"), int)
            and int(second["MainPID"]) > 0
            and _socket_ready(broker_socket)
        ):
            stably_ready = True
    result: dict[str, object] = {
        "ok": True,
        "stably_ready": stably_ready,
        "systemd": state,
        "execution": _systemd_execution_identity(),
        "related_units": _related_unit_states(),
        "socket_present": broker_socket.exists() or broker_socket.is_symlink(),
    }
    if not stably_ready:
        result["failure_diagnostic"] = _broker_failure_diagnostic()
    return result


def _stable_inactive(broker_socket: Path) -> dict[str, object]:
    first = _systemd_state()
    if (
        first["LoadState"] != "loaded"
        or first["ActiveState"] != "inactive"
        or first["SubState"] != "dead"
        or first["MainPID"] != 0
        or first["UnitFileState"] not in {"enabled", "enabled-runtime", "disabled"}
    ):
        raise BridgeError("legacy broker baseline is not stably inactive")
    time.sleep(0.25)
    second = _systemd_state()
    for field in ("ActiveState", "SubState", "MainPID", "InvocationID", "NRestarts"):
        if second[field] != first[field]:
            raise BridgeError("legacy broker state changed while proving its inactive baseline")
    if broker_socket.exists() or broker_socket.is_symlink():
        raise BridgeError("legacy broker socket still exists at the inactive baseline")
    return first


def _write_dropin(path: Path, payload: bytes, *, uid: int) -> None:
    parent = _absolute(path.parent, "broker drop-in directory")
    parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise BridgeError("broker drop-in directory is unsafe")
    temporary = parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BridgeError("broker drop-in write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _dropin_identity(
    path: Path, *, uid: int, expected_sha256: str
) -> dict[str, object]:
    """Return the exact identity of one transaction-owned systemd drop-in."""

    candidate = _absolute(path, "broker bridge drop-in")
    parent = candidate.parent.lstat()
    before = candidate.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != uid
        or stat.S_IMODE(parent.st_mode) & 0o022
        or candidate.parent.resolve(strict=True) != candidate.parent
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != uid
        or before.st_gid != parent.st_gid
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_nlink != 1
        or candidate.resolve(strict=True) != candidate
    ):
        raise BridgeError("broker bridge drop-in identity is unsafe")
    digest = _sha256_file(candidate)
    after = candidate.lstat()
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_nlink",
    )
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
        raise BridgeError("broker bridge drop-in changed while it was read")
    if digest != expected_sha256:
        raise BridgeError("broker bridge drop-in content changed")
    return {
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "ctime_ns": int(before.st_ctime_ns),
        "uid": int(before.st_uid),
        "gid": int(before.st_gid),
        "mode": stat.S_IMODE(before.st_mode),
        "nlink": int(before.st_nlink),
        "sha256": digest,
    }


def _verify_dropin_identity(
    path: Path,
    expected: object,
    *,
    uid: int,
    expected_sha256: str,
) -> dict[str, object]:
    if not isinstance(expected, dict):
        raise BridgeError("bridge journal omitted the exact drop-in identity")
    current = _dropin_identity(path, uid=uid, expected_sha256=expected_sha256)
    if current != expected:
        raise BridgeError("bridge drop-in was replaced after publication")
    return current


def _unlink_owned_dropin(
    path: Path,
    expected: object,
    *,
    uid: int,
    expected_sha256: str,
) -> None:
    _verify_dropin_identity(
        path,
        expected,
        uid=uid,
        expected_sha256=expected_sha256,
    )
    path.unlink()
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _dropin_payload_with_python_flags(
    release: Path,
    database: Path,
    broker_socket: Path,
    *,
    python_flags: str,
) -> bytes:
    if python_flags not in {"-I", "-B -I"}:
        raise BridgeError("bridge systemd Python flags are invalid")
    for path in (release, database, broker_socket):
        if SYSTEMD_PATH_RE.fullmatch(str(path)) is None:
            raise BridgeError(
                "bridge systemd paths must use the strict absolute safe-path grammar"
            )
    entry = release / Path(str(ENTRY_RELATIVE))
    dependency = release / Path(str(DEPENDENCY_RELATIVE))
    return (
        "[Service]\n"
        f"WorkingDirectory={release}\n"
        "ExecStartPre=\n"
        f"ExecStartPre=/usr/bin/python3 {python_flags} {dependency}\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/python3 {python_flags} {entry} broker serve "
        f"--database {database} --socket {broker_socket} "
        f"--access-group {ACCESS_GROUP}\n"
    ).encode("utf-8")


def _dropin_payload(release: Path, database: Path, broker_socket: Path) -> bytes:
    """Return the current hardened bridge drop-in (no bytecode, isolated)."""

    return _dropin_payload_with_python_flags(
        release,
        database,
        broker_socket,
        python_flags="-B -I",
    )


def _historical_restored_dropin_payload(
    release: Path, database: Path, broker_socket: Path
) -> bytes:
    """Reproduce the exact pre-hardening payload sealed by restored journals."""

    return _dropin_payload_with_python_flags(
        release,
        database,
        broker_socket,
        python_flags="-I",
    )


def _profile_identity(path: Path, *, uid: int) -> dict[str, object]:
    info = _protected_profile(path, uid=uid)
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": int(info.st_nlink),
        "sha256": _sha256_file(path),
    }


def _verify_profile_identity(
    path: Path, expected: object, *, uid: int
) -> dict[str, object]:
    if not isinstance(expected, dict):
        raise BridgeError("legacy-writer handoff omitted the protected profile identity")
    current = _profile_identity(path, uid=uid)
    if current != expected:
        raise BridgeError("protected profile changed during legacy-writer handoff")
    return current


def _profile_repository_binding(
    path: Path,
    *,
    client_uid: int,
    owner_uid: int | None = None,
    repository_id: str,
    repository_generation: int,
    canonical_root: Path,
    database_generation: str,
    broker_socket: Path,
) -> dict[str, object]:
    expected_owner_uid = client_uid if owner_uid is None else owner_uid
    if (
        isinstance(expected_owner_uid, bool)
        or not isinstance(expected_owner_uid, int)
        or expected_owner_uid <= 0
    ):
        raise BridgeError("protected profile repository owner UID is invalid")
    before = _profile_identity(path, uid=0)
    try:
        document = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BridgeError("protected profile is not valid JSON") from error
    after = _profile_identity(path, uid=0)
    if after != before:
        raise BridgeError("protected profile changed while it was read")
    service = document.get("service") if isinstance(document, dict) else None
    clients = document.get("clients") if isinstance(document, dict) else None
    client = clients.get(str(client_uid)) if isinstance(clients, dict) else None
    repositories = client.get("repositories") if isinstance(client, dict) else None
    matching = (
        [
            item
            for item in repositories
            if isinstance(item, dict)
            and item.get("repo_id") == repository_id
            and item.get("canonical_root") == str(canonical_root)
            and item.get("generation") == repository_generation
            and item.get("owner_uid") == expected_owner_uid
        ]
        if isinstance(repositories, list)
        else []
    )
    if (
        not isinstance(service, dict)
        or service.get("socket") != str(broker_socket)
        or service.get("uid") != 0
        or service.get("database_generation") != database_generation
        or len(matching) != 1
    ):
        raise BridgeError("protected profile repository owner binding is invalid")
    return {
        "client_uid": client_uid,
        "repository_id": repository_id,
        "canonical_root": str(canonical_root),
        "generation": repository_generation,
        "owner_uid": expected_owner_uid,
    }


def _verify_loaded_bridge_execution(
    *, release: Path, database: Path, broker_socket: Path, dropin: Path
) -> dict[str, object]:
    identity = _systemd_execution_identity()
    expected_argv = [
        "/usr/bin/python3",
        "-B",
        "-I",
        str(release / Path(str(ENTRY_RELATIVE))),
        "broker",
        "serve",
        "--database",
        str(database),
        "--socket",
        str(broker_socket),
        "--access-group",
        ACCESS_GROUP,
    ]
    historical_argv = [item for item in expected_argv if item != "-B"]
    prefix, separator, remainder = identity["ExecStart"].partition("argv[]=")
    raw_argv, argv_separator, suffix = remainder.partition(" ;")
    try:
        loaded_argv = shlex.split(raw_argv)
    except ValueError as error:
        raise BridgeError("systemd returned an invalid schema-12 bridge argv") from error
    dropin_paths = identity["DropInPaths"].split()
    expected_dropin_paths = sorted(
        (str(DEFAULT_ENROLLED_HOME_DROPIN), str(dropin))
    )
    if (
        not separator
        or not argv_separator
        or prefix != "{ path=/usr/bin/python3 ; "
        or not suffix.endswith(" }")
        or "argv[]=" in suffix
        or "{ path=" in suffix
        or loaded_argv not in (expected_argv, historical_argv)
        or sorted(dropin_paths) != expected_dropin_paths
    ):
        raise BridgeError("systemd did not load the exact schema-12 bridge execution")
    dropins: list[dict[str, object]] = []
    for raw_path in sorted(dropin_paths):
        candidate = _absolute(Path(raw_path), "loaded broker drop-in")
        if candidate.parent != dropin.parent:
            raise BridgeError("systemd loaded a broker drop-in outside the exact set")
        dropins.append(
            _dropin_identity(
                candidate,
                uid=0,
                expected_sha256=_sha256_file(candidate),
            )
        )
    return {
        "systemd": identity,
        "argv": loaded_argv,
        "dropin_paths": expected_dropin_paths,
        "dropins": dropins,
    }


def _broker_process_identity(
    *, main_pid: int, expected_argv: list[str], expected_uid: int
) -> dict[str, object]:
    if isinstance(main_pid, bool) or not isinstance(main_pid, int) or main_pid <= 0:
        raise BridgeError("schema-12 bridge MainPID is invalid")
    proc = Path("/proc") / str(main_pid)
    before = proc.lstat()
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != expected_uid
        or proc.resolve(strict=True) != proc
    ):
        raise BridgeError("schema-12 bridge process identity is unsafe")
    try:
        cmdline_raw = (proc / "cmdline").read_bytes()
        cgroup_raw = (proc / "cgroup").read_text(encoding="utf-8")
        stat_raw = (proc / "stat").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise BridgeError("schema-12 bridge process identity is unreadable") from error
    try:
        command = [
            item.decode("utf-8")
            for item in cmdline_raw.rstrip(b"\0").split(b"\0")
            if item
        ]
    except UnicodeDecodeError as error:
        raise BridgeError("schema-12 bridge MainPID argv is invalid") from error
    if command != expected_argv:
        raise BridgeError("schema-12 bridge MainPID argv changed")
    cgroups = [line for line in cgroup_raw.splitlines() if line]
    expected_cgroup = f"0::/system.slice/{BROKER_UNIT}"
    if cgroups != [expected_cgroup]:
        raise BridgeError("schema-12 bridge MainPID cgroup changed")
    closing = stat_raw.rfind(")")
    fields = stat_raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise BridgeError("schema-12 bridge MainPID start identity is invalid")
    after = proc.lstat()
    if (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_ctime_ns,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_ctime_ns,
    ):
        raise BridgeError("schema-12 bridge MainPID changed during process proof")
    return {
        "pid": main_pid,
        "uid": int(before.st_uid),
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "ctime_ns": int(before.st_ctime_ns),
        "start_time_ticks": int(fields[19]),
        "argv": command,
        "cgroup": expected_cgroup,
    }


def _broker_socket_peer(path: Path) -> dict[str, int]:
    before = _socket_identity(path)
    credentials_size = struct.calcsize("3i")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1.0)
            client.connect(str(path))
            payload = client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, credentials_size
            )
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as error:
        raise BridgeError("schema-12 bridge socket peer is unavailable") from error
    if len(payload) != credentials_size:
        raise BridgeError("schema-12 bridge socket peer credentials are invalid")
    pid, uid, gid = struct.unpack("3i", payload)
    after = _socket_identity(path)
    if after != before:
        raise BridgeError("schema-12 bridge socket changed during peer proof")
    return {"pid": pid, "uid": uid, "gid": gid}


def _parse_canary(value: str) -> tuple[pwd.struct_passwd, Path]:
    user, separator, raw_path = value.partition("=")
    if not separator or not user or not raw_path:
        raise BridgeError("--canary must be USER=/absolute/project")
    try:
        account = pwd.getpwnam(user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {user}") from error
    project = _absolute(Path(raw_path), "canary project")
    return account, project


def _root_cutover_parent_identity() -> dict[str, object]:
    """Prove the setpriv child was launched directly by a live root cutover."""

    parent_pid = os.getppid()
    if parent_pid <= 1:
        raise BridgeError("cutover inventory canary has no attributed parent")
    parent = Path("/proc") / str(parent_pid)
    try:
        before = parent.lstat()
        status = (parent / "status").read_text(encoding="utf-8")
        command = (parent / "cmdline").read_bytes()
        stat_line = (parent / "stat").read_text(encoding="utf-8")
        after = parent.lstat()
    except (OSError, UnicodeError) as error:
        raise BridgeError("cutover inventory parent identity is unreadable") from error
    uid_line = next(
        (line for line in status.splitlines() if line.startswith("Uid:\t")),
        "",
    )
    uids = uid_line.split()[1:]
    closing = stat_line.rfind(")")
    stat_fields = stat_line[closing + 2 :].split() if closing >= 0 else []
    if (
        before.st_uid != 0
        or len(uids) != 4
        or any(value != "0" for value in uids)
        or not command
        or len(command) > 64 * 1024
        or len(stat_fields) < 20
        or not stat_fields[19].isdigit()
        or (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_ctime_ns,
        )
        != (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_ctime_ns,
        )
    ):
        raise BridgeError("cutover inventory parent is not one stable root process")
    return {
        "pid": parent_pid,
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "ctime_ns": int(before.st_ctime_ns),
        "start_time_ticks": int(stat_fields[19]),
        "command_sha256": _sha256_bytes(command),
    }


def _load_historical_canary_modules(
    release: Path, *, expected_release_digest: str
) -> tuple[object, object]:
    """Load only BrokerClient/profile modules from one verified cutover client."""

    release = _absolute(release, "cutover inventory client release")
    running = ROOT.resolve(strict=True)
    if release == running:
        manifest = _verify_availability_client_release(
            release,
            owner_uid=0,
        )
    elif release.parent == DEFAULT_AVAILABILITY_RELEASE_ROOT:
        manifest = _verify_historical_availability_release(
            release,
            owner_uid=0,
        )
    else:
        manifest = _verify_activation_release(
            release,
            release_root=release.parent,
            owner_uid=0,
        )
    if manifest.get("release_digest") != expected_release_digest:
        raise BridgeError("cutover inventory client release changed")
    scripts = release / Path(str(SOURCE_PREFIX))
    package = scripts / "devcoordinator"
    package_init = package / "__init__.py"
    alias = f"_devcoordinator_schema12_canary_{expected_release_digest}"
    if any(name == alias or name.startswith(alias + ".") for name in sys.modules):
        raise BridgeError("cutover inventory historical modules were already loaded")
    spec = importlib.util.spec_from_file_location(
        alias,
        package_init,
        submodule_search_locations=[str(package)],
    )
    if spec is None or spec.loader is None:
        raise BridgeError("cutover inventory historical package cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
        broker = importlib.import_module(f"{alias}.broker")
        broker_profile = importlib.import_module(f"{alias}.broker_profile")
    except Exception as error:
        for name in tuple(sys.modules):
            if name == alias or name.startswith(alias + "."):
                sys.modules.pop(name, None)
        raise BridgeError("cutover inventory historical modules failed to load") from error
    expected_modules = {
        broker: package / "broker.py",
        broker_profile: package / "broker_profile.py",
    }
    if any(
        not isinstance(getattr(loaded, "__file__", None), str)
        or Path(str(loaded.__file__)).resolve() != expected.resolve()
        for loaded, expected in expected_modules.items()
    ):
        raise BridgeError("cutover inventory loaded modules outside its release")
    return broker, broker_profile


def _internal_cutover_inventory_read_canary(
    *,
    historical_release: Path,
    historical_release_digest: str,
    profile: Path,
    project: Path,
    expected_repository_id: str,
    expected_repository_generation: int,
    expected_database_generation: str,
    expected_broker_socket: Path,
    expected_service_uid: int,
    expected_client_uid: int,
    expected_client_gid: int,
) -> dict[str, object]:
    """Issue exactly schema-12 INVENTORY_READ while maintenance stays active."""

    historical_release = _absolute(
        historical_release, "cutover inventory historical release"
    )
    profile = _absolute(profile, "cutover inventory profile")
    project = _absolute(project, "cutover inventory project")
    expected_broker_socket = _absolute(
        expected_broker_socket, "cutover inventory broker socket"
    )
    if (
        RELEASE_RE.fullmatch(historical_release_digest) is None
        or not isinstance(expected_repository_id, str)
        or not expected_repository_id
        or isinstance(expected_repository_generation, bool)
        or not isinstance(expected_repository_generation, int)
        or expected_repository_generation < 0
        or not isinstance(expected_database_generation, str)
        or not expected_database_generation
        or isinstance(expected_service_uid, bool)
        or expected_service_uid != 0
        or isinstance(expected_client_uid, bool)
        or expected_client_uid <= 0
        or isinstance(expected_client_gid, bool)
        or expected_client_gid < 0
        or os.getresuid()
        != (expected_client_uid, expected_client_uid, expected_client_uid)
        or os.getresgid()
        != (expected_client_gid, expected_client_gid, expected_client_gid)
    ):
        raise BridgeError("cutover inventory canary identity is invalid")
    _root_cutover_parent_identity()
    broker, broker_profile = _load_historical_canary_modules(
        historical_release,
        expected_release_digest=historical_release_digest,
    )
    try:
        client_profile = broker_profile.load_broker_profile(
            path=profile,
            effective_uid=expected_client_uid,
            required=True,
            trusted_owner_uid=0,
        )
        if client_profile is None:
            raise BridgeError("cutover inventory profile is absent")
        repository = client_profile.repository(str(project))
        service = client_profile.service
        if (
            client_profile.client_uid != expected_client_uid
            or repository.canonical_root != str(project)
            or repository.repo_id != expected_repository_id
            or repository.generation != expected_repository_generation
            or service.database_generation != expected_database_generation
            or service.socket_path != expected_broker_socket
            or service.service_uid != expected_service_uid
        ):
            raise BridgeError("cutover inventory historical profile binding changed")
        operation = broker.BrokerOperation.INVENTORY_READ
        if operation.value != "inventory.read":
            raise BridgeError("cutover inventory operation identity changed")
        request = broker.BrokerRequest.create(
            account_id=client_profile.account_id,
            project_id=repository.repo_id,
            repository_generation=repository.generation,
            resource_id=repository.repo_id,
            operation=operation,
            arguments={},
            authority_generation=service.database_generation,
        )
        if request.operation is not broker.BrokerOperation.INVENTORY_READ:
            raise BridgeError("cutover inventory request is not read-only")
        client = broker.BrokerClient(
            service.socket_path,
            expected_broker_uid=service.service_uid,
            expected_socket_gid=service.socket_gid,
            expected_socket_mode=service.socket_mode,
            timeout_seconds=(
                broker_profile.INVENTORY_READ_CLIENT_TIMEOUT_SECONDS
            ),
        )
        maintenance_root = getattr(client, "_maintenance_root", None)
        if (
            maintenance_root is None
            or Path(maintenance_root) != Path(broker.MAINTENANCE_ROOT)
        ):
            raise BridgeError("historical client maintenance precheck changed")
        client._maintenance_root = None
        reply = client.call(request)
    except BridgeError:
        raise
    except Exception as error:
        detail = str(error).strip()
        if not detail or len(detail) > 240 or any(
            character in detail for character in "\x00\r\n"
        ):
            detail = type(error).__name__
        raise BridgeError(f"cutover inventory broker call failed: {detail}") from error
    if (
        not isinstance(reply, dict)
        or reply.get("ok") is not True
        or not isinstance(reply.get("result"), dict)
    ):
        raise BridgeError("cutover inventory broker returned an invalid reply")
    inventory = dict(reply["result"])
    repositories = inventory.get("repositories")
    matching = (
        [
            item
            for item in repositories
            if isinstance(item, dict)
            and item.get("repo_id") == expected_repository_id
            and item.get("canonical_root") == str(project)
            and item.get("generation") == expected_repository_generation
        ]
        if isinstance(repositories, list)
        else []
    )
    if inventory.get("schema_version") != 2 or len(matching) != 1:
        raise BridgeError(
            "cutover inventory broker omitted the exact repository binding"
        )
    # Match the historical public CLI's small authority envelope without
    # invoking its client-side maintenance fence.  The full host graph is not
    # copied to the outer transaction: this canary proves one enrolled read.
    return {
        "schema_version": 2,
        "repositories": [dict(matching[0])],
        "authority": {
            "scope": "server-wide",
            "transport": "authenticated-unix-socket",
            "socket": str(service.socket_path),
            "service_uid": service.service_uid,
            "database_generation": service.database_generation,
        },
    }


def _open_immutable_bridge_source() -> tuple[int, int]:
    """Open the verified bridge and its imports without widening path access."""

    script_path = Path(__file__).resolve(strict=True)
    identity = _root_regular_identity(
        script_path,
        label="immutable cutover bridge script",
    )
    source_directory = script_path.parent
    directory_before = source_directory.lstat()
    if (
        stat.S_ISLNK(directory_before.st_mode)
        or not stat.S_ISDIR(directory_before.st_mode)
        or directory_before.st_uid != 0
        or stat.S_IMODE(directory_before.st_mode) & 0o022
        or source_directory.resolve(strict=True) != source_directory
    ):
        raise BridgeError("immutable cutover source directory is unsafe")
    script_descriptor: int | None = None
    source_directory_descriptor: int | None = None
    try:
        script_descriptor = os.open(
            script_path,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        source_directory_descriptor = os.open(
            source_directory,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(script_descriptor)
        opened_directory = os.fstat(source_directory_descriptor)
        if (
            (
                int(identity["device"]),
                int(identity["inode"]),
                int(identity["size"]),
                int(identity["uid"]),
            )
            != (
                int(opened.st_dev),
                int(opened.st_ino),
                int(opened.st_size),
                int(opened.st_uid),
            )
            or (
                int(directory_before.st_dev),
                int(directory_before.st_ino),
                int(directory_before.st_uid),
                stat.S_IMODE(directory_before.st_mode),
            )
            != (
                int(opened_directory.st_dev),
                int(opened_directory.st_ino),
                int(opened_directory.st_uid),
                stat.S_IMODE(opened_directory.st_mode),
            )
        ):
            raise BridgeError("immutable cutover source changed while opened")
        return source_directory_descriptor, script_descriptor
    except Exception:
        if source_directory_descriptor is not None:
            os.close(source_directory_descriptor)
        if script_descriptor is not None:
            os.close(script_descriptor)
        raise


def _inventory_canary(
    *,
    release: Path,
    account: pwd.struct_passwd,
    project: Path,
    profile: Path = DEFAULT_PROFILE,
    expected_database_generation: str | None = None,
    expected_repository_id: str | None = None,
    canary_repository_generation: int | None = None,
    expected_broker_socket: Path | None = None,
    expected_service_uid: int | None = None,
    _cutover_maintenance_inventory_read: bool = False,
    _historical_release_digest: str | None = None,
) -> dict[str, object]:
    entry = release / Path(str(ENTRY_RELATIVE))
    script_descriptor: int | None = None
    source_directory_descriptor: int | None = None
    if not isinstance(_cutover_maintenance_inventory_read, bool):
        raise BridgeError("cutover maintenance canary mode is invalid")
    if _cutover_maintenance_inventory_read:
        if (
            expected_database_generation is None
            or expected_repository_id is None
            or canary_repository_generation is None
            or expected_broker_socket is None
            or expected_service_uid is None
            or _historical_release_digest is None
        ):
            raise BridgeError("cutover inventory canary binding is incomplete")
        (
            source_directory_descriptor,
            script_descriptor,
        ) = _open_immutable_bridge_source()
        command = [
            "/usr/bin/setpriv",
            "--reuid",
            str(account.pw_uid),
            "--regid",
            str(account.pw_gid),
            "--init-groups",
            "--reset-env",
            "/usr/bin/python3",
            "-B",
            "-I",
            "-c",
            (
                "import runpy,sys;"
                "sys.path.insert(0,sys.argv[1]);"
                "sys.argv=sys.argv[2:];"
                "runpy.run_path(sys.argv[0],run_name='__main__')"
            ),
            f"/proc/self/fd/{source_directory_descriptor}",
            f"/proc/self/fd/{script_descriptor}",
            "--json",
            INTERNAL_CUTOVER_INVENTORY_ACTION,
            "--historical-release",
            str(release),
            "--historical-release-digest",
            _historical_release_digest,
            "--profile",
            str(profile),
            "--project",
            str(project),
            "--expected-repository-id",
            expected_repository_id,
            "--expected-repository-generation",
            str(canary_repository_generation),
            "--expected-database-generation",
            expected_database_generation,
            "--expected-socket",
            str(expected_broker_socket),
            "--expected-service-uid",
            str(expected_service_uid),
            "--expected-client-uid",
            str(account.pw_uid),
            "--expected-client-gid",
            str(account.pw_gid),
        ]
    else:
        command = [
            "/usr/bin/setpriv",
            "--reuid",
            str(account.pw_uid),
            "--regid",
            str(account.pw_gid),
            "--init-groups",
            "--reset-env",
            "/usr/bin/python3",
            "-B",
            "-I",
            str(entry),
            "inventory",
            "--project",
            str(project),
            "--no-docker",
            "--compact-json",
        ]
    try:
        completed = _run(
            command,
            timeout=30,
            env=SYSTEM_ENVIRONMENT,
            pass_fds=(
                (source_directory_descriptor, script_descriptor)
                if source_directory_descriptor is not None
                and script_descriptor is not None
                else ()
            ),
        )
    finally:
        if source_directory_descriptor is not None:
            os.close(source_directory_descriptor)
        if script_descriptor is not None:
            os.close(script_descriptor)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BridgeError("legacy broker canary returned non-JSON output") from error
    authority = result.get("authority") if isinstance(result, dict) else None
    if (
        not isinstance(result, dict)
        or result.get("schema_version") != 2
        or not isinstance(authority, dict)
        or authority.get("scope") != "server-wide"
        or authority.get("transport") != "authenticated-unix-socket"
    ):
        raise BridgeError("legacy broker canary returned an invalid inventory contract")
    if expected_database_generation is not None and (
        not isinstance(expected_database_generation, str)
        or not expected_database_generation
        or authority.get("database_generation") != expected_database_generation
    ):
        raise BridgeError("legacy broker canary returned the wrong authority generation")
    if expected_broker_socket is not None and authority.get("socket") != str(
        _absolute(expected_broker_socket, "expected broker socket")
    ):
        raise BridgeError("legacy broker canary returned the wrong authority socket")
    if expected_service_uid is not None and authority.get("service_uid") != int(
        expected_service_uid
    ):
        raise BridgeError("legacy broker canary returned the wrong service identity")
    repository_result: dict[str, object] | None = None
    if expected_repository_id is not None:
        repositories = result.get("repositories")
        matching = (
            [
                item
                for item in repositories
                if isinstance(item, dict)
                and item.get("repo_id") == expected_repository_id
                and item.get("canonical_root") == str(project)
                and (
                    canary_repository_generation is None
                    or item.get("generation") == canary_repository_generation
                )
            ]
            if isinstance(repositories, list)
            else []
        )
        if (
            not isinstance(repositories, list)
            or len(repositories) != 1
            or len(matching) != 1
        ):
            raise BridgeError(
                "legacy broker canary did not return the exact requested repository"
            )
        repository_result = {
            "repository_id": expected_repository_id,
            "canonical_root": str(project),
            "generation": canary_repository_generation,
        }
    return {
        "user": account.pw_name,
        "uid": account.pw_uid,
        "project": str(project),
        "inventory_sha256": _sha256_bytes(_canonical(result)),
        "authority": {
            key: authority.get(key)
            for key in (
                "scope",
                "transport",
                "socket",
                "service_uid",
                "database_generation",
            )
            if key in authority
        },
        "repository": repository_result,
    }


def _socket_identity(path: Path) -> dict[str, object]:
    candidate = _absolute(path, "broker socket")
    info = candidate.lstat()
    try:
        group_gid = grp.getgrnam(ACCESS_GROUP).gr_gid
    except KeyError as error:
        raise BridgeError(f"required access group is missing: {ACCESS_GROUP}") from error
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != group_gid
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise BridgeError("legacy broker socket identity is unsafe")
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
    }


def _socket_ready(path: Path) -> bool:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return False
    group_gid = grp.getgrnam(ACCESS_GROUP).gr_gid
    if (
        not stat.S_ISSOCK(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != group_gid
        or stat.S_IMODE(before.st_mode) != 0o660
    ):
        raise BridgeError("legacy broker socket identity is unsafe")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
        return False
    after = path.lstat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise BridgeError("legacy broker socket changed during readiness")
    return True


_READY_PROOF_FIELDS = {
    "operation_id",
    "bridge_journal",
    "bridge_journal_sha256",
    "bridge_document_sha256",
    "release",
    "release_digest",
    "database",
    "database_generation",
    "profile",
    "profile_identity",
    "profile_repository",
    "broker_socket",
    "socket_identity",
    "socket_peer",
    "dropin",
    "dropin_identity",
    "systemd",
    "execution",
    "process",
    "canary",
    "verified_at_epoch",
}


def verify_ready_bridge_proof(value: object) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=READY_PROOF_KIND,
        fields=_READY_PROOF_FIELDS,
    )
    try:
        if str(uuid.UUID(str(document["operation_id"]))) != document["operation_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 bridge live proof operation is invalid") from error
    for field in (
        "bridge_journal_sha256",
        "bridge_document_sha256",
        "release_digest",
    ):
        if RELEASE_RE.fullmatch(str(document[field])) is None:
            raise BridgeError("schema-12 bridge live proof digest is invalid")
    for field in (
        "bridge_journal",
        "release",
        "database",
        "profile",
        "broker_socket",
        "dropin",
    ):
        document[field] = str(
            _absolute(Path(str(document[field])), f"schema-12 bridge live proof {field}")
        )
    if (
        not isinstance(document["database_generation"], str)
        or not document["database_generation"]
        or isinstance(document["verified_at_epoch"], bool)
        or not isinstance(document["verified_at_epoch"], int)
        or int(document["verified_at_epoch"]) < 0
        or not isinstance(document["profile_identity"], dict)
        or not isinstance(document["profile_repository"], dict)
        or not isinstance(document["socket_identity"], dict)
        or not isinstance(document["socket_peer"], dict)
        or not isinstance(document["dropin_identity"], dict)
        or not isinstance(document["systemd"], dict)
        or not isinstance(document["execution"], dict)
        or not isinstance(document["process"], dict)
        or not isinstance(document["canary"], dict)
    ):
        raise BridgeError("schema-12 bridge live proof binding is invalid")
    profile_repository = document["profile_repository"]
    canary = document["canary"]
    authority = canary.get("authority") if isinstance(canary, dict) else None
    canary_repository = (
        canary.get("repository") if isinstance(canary, dict) else None
    )
    socket_peer = document["socket_peer"]
    systemd = document["systemd"]
    execution = document["execution"]
    process = document["process"]
    if (
        set(profile_repository)
        != {
            "client_uid",
            "repository_id",
            "canonical_root",
            "generation",
            "owner_uid",
        }
        or not isinstance(profile_repository.get("repository_id"), str)
        or not profile_repository["repository_id"]
        or isinstance(profile_repository.get("generation"), bool)
        or not isinstance(profile_repository.get("generation"), int)
        or profile_repository["generation"] < 0
        or isinstance(profile_repository.get("client_uid"), bool)
        or not isinstance(profile_repository.get("client_uid"), int)
        or profile_repository["client_uid"] <= 0
        or profile_repository.get("owner_uid") != profile_repository["client_uid"]
        or str(
            _absolute(
                Path(str(profile_repository.get("canonical_root"))),
                "schema-12 bridge live proof repository root",
            )
        )
        != profile_repository.get("canonical_root")
        or set(canary)
        != {
            "user",
            "uid",
            "project",
            "inventory_sha256",
            "authority",
            "repository",
        }
        or not isinstance(canary.get("user"), str)
        or not canary["user"]
        or canary.get("uid") != profile_repository["client_uid"]
        or canary.get("project") != profile_repository["canonical_root"]
        or RELEASE_RE.fullmatch(str(canary.get("inventory_sha256"))) is None
        or not isinstance(authority, dict)
        or set(authority)
        != {
            "scope",
            "transport",
            "socket",
            "service_uid",
            "database_generation",
        }
        or authority.get("scope") != "server-wide"
        or authority.get("transport") != "authenticated-unix-socket"
        or authority.get("socket") != document["broker_socket"]
        or authority.get("service_uid") != 0
        or authority.get("database_generation") != document["database_generation"]
        or not isinstance(canary_repository, dict)
        or set(canary_repository)
        != {"repository_id", "canonical_root", "generation"}
        or canary_repository.get("repository_id")
        != profile_repository["repository_id"]
        or canary_repository.get("canonical_root")
        != profile_repository["canonical_root"]
        or canary_repository.get("generation")
        != profile_repository["generation"]
        or isinstance(systemd.get("MainPID"), bool)
        or not isinstance(systemd.get("MainPID"), int)
        or systemd["MainPID"] <= 0
        or not isinstance(systemd.get("InvocationID"), str)
        or not systemd["InvocationID"]
        or not isinstance(socket_peer.get("pid"), int)
        or isinstance(socket_peer.get("pid"), bool)
        or socket_peer.get("pid") != systemd["MainPID"]
        or socket_peer.get("uid") != 0
        or not isinstance(execution.get("argv"), list)
        or not all(isinstance(item, str) for item in execution["argv"])
        or process.get("pid") != systemd["MainPID"]
        or process.get("uid") != 0
        or process.get("argv") != execution["argv"]
        or process.get("cgroup") != f"0::/system.slice/{BROKER_UNIT}"
    ):
        raise BridgeError("schema-12 bridge live proof binding is invalid")
    return document


def verify_ready_bridge(
    *,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    wait_seconds: int = 30,
    expected_uid: int = 0,
) -> dict[str, object]:
    """Prove a restarted schema-12 bridge without changing its ready journal."""

    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("bridge operation identity must be a canonical UUID") from error
    if (
        RELEASE_RE.fullmatch(expected_journal_sha256) is None
        or RELEASE_RE.fullmatch(expected_journal_document_sha256) is None
    ):
        raise BridgeError("schema-12 bridge journal digest is invalid")
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
        raise BridgeError("schema-12 bridge readiness authority UID is invalid")
    if (
        not isinstance(expected_database_generation, str)
        or not expected_database_generation
        or len(expected_database_generation) > 256
        or not isinstance(canary_repository_id, str)
        or not canary_repository_id
        or len(canary_repository_id) > 256
        or isinstance(canary_repository_generation, bool)
        or not isinstance(canary_repository_generation, int)
        or canary_repository_generation < 0
        or isinstance(expected_canary_uid, bool)
        or not isinstance(expected_canary_uid, int)
        or expected_canary_uid <= 0
        or not 1 <= wait_seconds <= 120
    ):
        raise BridgeError("schema-12 bridge readiness inputs are invalid")
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    database = _absolute(database, "legacy authority database")
    profile = _absolute(profile, "protected profile")
    broker_socket = _absolute(broker_socket, "broker socket")
    dropin = _absolute(dropin, "broker bridge drop-in")
    canary_project = _absolute(canary_project, "canary project")
    if (
        profile != DEFAULT_PROFILE
        or broker_socket != DEFAULT_SOCKET
        or dropin != DEFAULT_DROPIN
    ):
        raise BridgeError("schema-12 bridge readiness paths are not canonical")
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    if account.pw_uid != expected_canary_uid:
        raise BridgeError("schema-12 bridge canary owner UID changed")

    with _installer_lock(expected_uid):
        journal_info_before = _private_regular(
            journal_path, uid=expected_uid, label="schema-12 bridge journal"
        )
        if _sha256_file(journal_path) != expected_journal_sha256:
            raise BridgeError("schema-12 bridge journal raw digest changed")
        bridge = _load_bridge_journal_for_ready_verification(
            journal_path, uid=expected_uid
        )
        declared_canary = {
            "user": account.pw_name,
            "uid": account.pw_uid,
            "project": str(canary_project),
        }
        if (
            bridge is None
            or bridge.get("operation_id") != operation_id
            or bridge.get("document_sha256")
            != expected_journal_document_sha256
            or bridge.get("phase") != "ready"
            or bridge.get("broker_socket") != str(broker_socket)
            or bridge.get("dropin") != str(dropin)
            or declared_canary not in bridge.get("canaries", [])
        ):
            raise BridgeError("schema-12 bridge ready journal binding changed")
        release = _absolute(Path(str(bridge["release"])), "legacy release")
        executor_rescue = bridge.get("executor_rescue")
        canary_release = (
            _absolute(
                Path(str(executor_rescue["client_release"])),
                "schema-12 bridge retained canary client",
            )
            if isinstance(executor_rescue, Mapping)
            else release
        )
        manifest = _verify_activation_release(
            release,
            release_root=release.parent,
            owner_uid=expected_uid,
        )
        dropin_sha256 = _sha256_bytes(
            _dropin_payload(release, database, broker_socket)
        )
        if (
            manifest.get("release_digest") != bridge.get("release_digest")
            or bridge.get("dropin_sha256") != dropin_sha256
        ):
            raise BridgeError("schema-12 bridge release binding changed")
        dropin_identity = _verify_dropin_identity(
            dropin,
            bridge.get("dropin_identity"),
            uid=expected_uid,
            expected_sha256=dropin_sha256,
        )
        readiness_value = bridge.get("readiness")
        if not isinstance(readiness_value, dict):
            raise BridgeError("schema-12 bridge omitted readiness evidence")
        readiness_path = Path(str(readiness_value.get("path")))
        readiness_info_before = _private_regular(
            readiness_path,
            uid=expected_uid,
            label="authority readiness attestation",
        )
        readiness = _verify_retained_readiness_reference(
            readiness_path,
            readiness_value,
            uid=expected_uid,
        )
        if readiness.get("database_generation") != expected_database_generation:
            raise BridgeError("schema-12 bridge readiness generation changed")

        profile_before = _profile_identity(profile, uid=expected_uid)
        profile_repository_before = _profile_repository_binding(
            profile,
            client_uid=expected_canary_uid,
            repository_id=canary_repository_id,
            repository_generation=canary_repository_generation,
            canonical_root=canary_project,
            database_generation=expected_database_generation,
            broker_socket=broker_socket,
        )
        state_before = _wait_active(broker_socket, wait_seconds)
        socket_before = _socket_identity(broker_socket)
        execution_before = _verify_loaded_bridge_execution(
            release=release,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
        activation = bridge.get("activation")
        if (
            not isinstance(activation, dict)
            or activation.get("execution") != execution_before
        ):
            raise BridgeError(
                "schema-12 bridge ready journal execution binding changed"
            )
        process_before = _broker_process_identity(
            main_pid=int(state_before["MainPID"]),
            expected_argv=list(execution_before["argv"]),
            expected_uid=0,
        )
        peer_before = _broker_socket_peer(broker_socket)
        if (
            peer_before.get("pid") != state_before.get("MainPID")
            or peer_before.get("uid") != 0
        ):
            raise BridgeError("schema-12 bridge socket peer is not the MainPID")
        canary = _inventory_canary(
            release=canary_release,
            account=account,
            project=canary_project,
            expected_database_generation=expected_database_generation,
            expected_repository_id=canary_repository_id,
            canary_repository_generation=canary_repository_generation,
            expected_broker_socket=broker_socket,
            expected_service_uid=0,
        )
        state_after = _wait_active(broker_socket, wait_seconds)
        socket_after = _socket_identity(broker_socket)
        execution_after = _verify_loaded_bridge_execution(
            release=release,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
        process_after = _broker_process_identity(
            main_pid=int(state_after["MainPID"]),
            expected_argv=list(execution_after["argv"]),
            expected_uid=0,
        )
        peer_after = _broker_socket_peer(broker_socket)
        if (
            peer_after.get("pid") != state_after.get("MainPID")
            or peer_after.get("uid") != 0
        ):
            raise BridgeError("schema-12 bridge socket peer is not the MainPID")
        profile_after = _profile_identity(profile, uid=expected_uid)
        profile_repository_after = _profile_repository_binding(
            profile,
            client_uid=expected_canary_uid,
            repository_id=canary_repository_id,
            repository_generation=canary_repository_generation,
            canonical_root=canary_project,
            database_generation=expected_database_generation,
            broker_socket=broker_socket,
        )
        manifest_after = _verify_activation_release(
            release,
            release_root=release.parent,
            owner_uid=expected_uid,
        )
        journal_info_after = _private_regular(
            journal_path, uid=expected_uid, label="schema-12 bridge journal"
        )
        if _sha256_file(journal_path) != expected_journal_sha256:
            raise BridgeError("schema-12 bridge journal changed during live readiness")
        bridge_after = _load_bridge_journal_for_ready_verification(
            journal_path, uid=expected_uid
        )
        dropin_after = _verify_dropin_identity(
            dropin,
            bridge.get("dropin_identity"),
            uid=expected_uid,
            expected_sha256=dropin_sha256,
        )
        readiness_info_after = _private_regular(
            readiness_path,
            uid=expected_uid,
            label="authority readiness attestation",
        )
        readiness_after = _verify_retained_readiness_reference(
            readiness_path,
            readiness_value,
            uid=expected_uid,
        )
        if (
            state_after.get("InvocationID") != state_before.get("InvocationID")
            or state_after.get("MainPID") != state_before.get("MainPID")
            or socket_after != socket_before
            or execution_after != execution_before
            or process_after != process_before
            or peer_after != peer_before
            or profile_after != profile_before
            or profile_repository_after != profile_repository_before
            or manifest_after != manifest
            or bridge_after != bridge
            or dropin_after != dropin_identity
            or readiness_after != readiness
            or any(
                getattr(journal_info_after, field)
                != getattr(journal_info_before, field)
                for field in (
                    "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                    "st_uid", "st_gid", "st_mode", "st_nlink",
                )
            )
            or any(
                getattr(readiness_info_after, field)
                != getattr(readiness_info_before, field)
                for field in (
                    "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                    "st_uid", "st_gid", "st_mode", "st_nlink",
                )
            )
        ):
            raise BridgeError("schema-12 bridge changed during live readiness proof")
        return verify_ready_bridge_proof(
            _seal(
                READY_PROOF_KIND,
                {
                    "operation_id": operation_id,
                    "bridge_journal": str(journal_path),
                    "bridge_journal_sha256": expected_journal_sha256,
                    "bridge_document_sha256": bridge["document_sha256"],
                    "release": str(release),
                    "release_digest": bridge["release_digest"],
                    "database": str(database),
                    "database_generation": expected_database_generation,
                    "profile": str(profile),
                    "profile_identity": profile_before,
                    "profile_repository": profile_repository_after,
                    "broker_socket": str(broker_socket),
                    "socket_identity": socket_before,
                    "socket_peer": peer_after,
                    "dropin": str(dropin),
                    "dropin_identity": dropin_identity,
                    "systemd": state_after,
                    "execution": execution_after,
                    "process": process_after,
                    "canary": canary,
                    "verified_at_epoch": int(time.time()),
                },
            )
        )


def _wait_active(path: Path, wait_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        state = _systemd_state()
        if state["ActiveState"] == "active" and state["MainPID"] > 0 and _socket_ready(path):
            time.sleep(0.5)
            stable = _systemd_state()
            for field in ("ActiveState", "SubState", "MainPID", "InvocationID", "NRestarts"):
                if stable[field] != state[field]:
                    break
            else:
                return stable
        time.sleep(0.1)
    raise BridgeError("schema-12 broker bridge did not become stably ready")


def _service_process_alive(state: Mapping[str, object]) -> bool:
    try:
        main_pid = int(state.get("MainPID", 0))
    except (TypeError, ValueError):
        raise BridgeError("systemd process state contains an invalid MainPID")
    return main_pid > 0 or state.get("ActiveState") in PROCESS_ACTIVE_STATES


def _wait_inactive(path: Path, wait_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        state = _systemd_state()
        if (
            state.get("ActiveState") == "inactive"
            and state.get("SubState") == "dead"
            and state.get("MainPID") == 0
            and not path.exists()
            and not path.is_symlink()
        ):
            time.sleep(0.1)
            stable = _systemd_state()
            if all(
                stable.get(field) == state.get(field)
                for field in ("ActiveState", "SubState", "MainPID", "InvocationID")
            ):
                return stable
        time.sleep(0.1)
    raise BridgeError("schema-12 broker bridge did not become stably inactive")


def _stop_owned_invocation(
    *, expected_invocation: object, broker_socket: Path, wait_seconds: int
) -> dict[str, object]:
    """Stop only a currently live invocation proved by exact systemd identity."""

    state = _systemd_state()
    if not _service_process_alive(state):
        return state
    invocation = state.get("InvocationID")
    if (
        not isinstance(expected_invocation, str)
        or not expected_invocation
        or invocation != expected_invocation
    ):
        raise BridgeError("live broker invocation is not owned by this bridge transaction")
    _run(["/usr/bin/systemctl", "stop", BROKER_UNIT], timeout=30)
    return _wait_inactive(broker_socket, wait_seconds)


def _stop_verified_crash_loop_descendant(
    current: Mapping[str, object],
    *,
    observed_state: Mapping[str, object],
    broker_socket: Path,
    dropin: Path,
    wait_seconds: int,
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    """Stop a supervised descendant without trusting its changed invocation ID.

    A ready bridge can later crash and be restarted by systemd.  The new
    invocation is no longer the one sealed at activation, but the transaction
    still owns the unit only when the immutable release (apart from verified
    derived bytecode), exact drop-ins, loaded argv, and monotonically advanced
    restart counter all remain bound to that ready journal.
    """

    activation = current.get("activation")
    activated_systemd = (
        activation.get("systemd") if isinstance(activation, Mapping) else None
    )
    original_invocation = (
        activated_systemd.get("InvocationID")
        if isinstance(activated_systemd, Mapping)
        else None
    )
    original_restarts = (
        activated_systemd.get("NRestarts")
        if isinstance(activated_systemd, Mapping)
        else None
    )
    observed_invocation = observed_state.get("InvocationID")
    observed_restarts = observed_state.get("NRestarts")
    if (
        current.get("phase") != "ready"
        or broker_socket != DEFAULT_SOCKET
        or dropin != DEFAULT_DROPIN
        or not isinstance(original_invocation, str)
        or not original_invocation
        or type(original_restarts) is not int
        or original_restarts < 0
        or not isinstance(observed_invocation, str)
        or not observed_invocation
        or observed_invocation == original_invocation
        or type(observed_restarts) is not int
        or observed_restarts <= original_restarts
    ):
        raise BridgeError(
            "live broker invocation is not a verified crash-loop descendant"
        )
    release = _absolute(Path(str(current.get("release"))), "legacy release")
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    if manifest.get("release_digest") != current.get("release_digest"):
        raise BridgeError("crash-loop descendant release binding changed")
    execution_before = _verify_loaded_bridge_execution(
        release=release,
        database=DEFAULT_DATABASE,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    latest = _systemd_state()
    latest_invocation = latest.get("InvocationID")
    latest_restarts = latest.get("NRestarts")
    if (
        latest.get("LoadState") != "loaded"
        or not isinstance(latest_invocation, str)
        or not latest_invocation
        or latest_invocation == original_invocation
        or type(latest_restarts) is not int
        or latest_restarts < observed_restarts
    ):
        raise BridgeError("crash-loop descendant identity regressed before stop")
    execution_after = _verify_loaded_bridge_execution(
        release=release,
        database=DEFAULT_DATABASE,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    if execution_after != execution_before:
        raise BridgeError("crash-loop descendant execution changed before stop")
    _run(["/usr/bin/systemctl", "stop", BROKER_UNIT], timeout=30)
    inactive = _wait_inactive(broker_socket, wait_seconds)
    cache_sha256 = manifest.get("verified_unsealed_bytecode_cache_sha256")
    evidence = {
        "kind": "verified-supervised-crash-loop-descendant",
        "activation_invocation_id": original_invocation,
        "activation_restart_count": original_restarts,
        "observed_invocation_id": observed_invocation,
        "observed_restart_count": observed_restarts,
        "last_invocation_id": latest_invocation,
        "last_restart_count": latest_restarts,
        "release_digest": manifest["release_digest"],
        "verified_unsealed_bytecode_cache_sha256": (
            cache_sha256 if isinstance(cache_sha256, str) else None
        ),
        "execution_sha256": _sha256_bytes(_canonical(execution_after)),
        "inactive_state": inactive,
    }
    return inactive, evidence


def _journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    schema_version = (
        EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION
        if "executor_rescue" in payload
        else (
            PREDECESSOR_JOURNAL_CONTRACT_VERSION
            if "predecessor_readiness" in payload
            else JOURNAL_CONTRACT_VERSION
        )
    )
    document = _seal(
        JOURNAL_KIND,
        payload,
        schema_version=schema_version,
    )
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_bridge_journal_contract(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    """Load and structurally authenticate a bridge journal.

    Runtime/executor identity is deliberately verified by the caller.  Keeping
    that decision outside the contract decoder lets the read-only ready-bridge
    verifier authenticate a completed historical transaction without making
    mutation paths accept an executor other than the one running them.
    """

    if not path.exists() and not path.is_symlink():
        return None
    raw = _read_private_json(path, uid=uid, label="schema-12 bridge journal")
    common_fields = {
            "operation_id",
            "release",
            "release_digest",
            "dropin",
            "dropin_sha256",
            "dropin_identity",
            "broker_socket",
            "failed_activation",
            "readiness",
            "canaries",
            "baseline",
            "phase",
            "attempts",
            "activation",
            "error",
            "created_at_epoch",
            "updated_at_epoch",
    }
    version = raw.get("schema_version")
    if version == CONTRACT_VERSION:
        return _verify_seal(
            raw,
            kind=JOURNAL_KIND,
            fields=common_fields,
            schema_version=CONTRACT_VERSION,
        )
    if version == JOURNAL_CONTRACT_VERSION:
        return _verify_seal(
            raw,
            kind=JOURNAL_KIND,
            fields={*common_fields, "readiness_origin", "attempt_evidence"},
            schema_version=JOURNAL_CONTRACT_VERSION,
        )
    if version == PREDECESSOR_JOURNAL_CONTRACT_VERSION:
        return _verify_seal(
            raw,
            kind=JOURNAL_KIND,
            fields={
                *common_fields,
                "readiness_origin",
                "attempt_evidence",
                "predecessor_readiness",
            },
            schema_version=PREDECESSOR_JOURNAL_CONTRACT_VERSION,
        )
    if version == EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION:
        return _verify_seal(
            raw,
            kind=JOURNAL_KIND,
            fields={
                *common_fields,
                "readiness_origin",
                "attempt_evidence",
                "executor_rescue",
            },
            schema_version=EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION,
        )

    raise BridgeError("schema-12 bridge journal version is unsupported")


def _load_bridge_journal(path: Path, *, uid: int) -> dict[str, object] | None:
    """Load a journal for an active mutation using the running executor."""

    document = _load_bridge_journal_contract(path, uid=uid)
    if (
        document is not None
        and document.get("schema_version")
        == EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION
    ):
        client_release = _absolute(
            Path(str(document.get("executor_rescue", {}).get("client_release"))),
            "executor rescue journal retained client",
        )
        runtime, _manifest = (
            _verify_successor_executor_rescue_runtime_binding(
                document["executor_rescue"],
                client_release=client_release,
                expected_uid=uid,
            )
        )
        if runtime != document["executor_rescue"]:
            raise BridgeError("executor rescue journal binding changed")
    return document


def _load_bridge_journal_for_ready_verification(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    """Load a completed ready journal from an external immutable verifier.

    This is intentionally narrower than ``_load_bridge_journal``: it is used
    only by the read-only ``verify-ready`` operation.  Every immutable release
    named by executor-rescue lineage is still verified, but the running ROOT is
    not required to equal the historical effective executor.
    """

    document = _load_bridge_journal_contract(path, uid=uid)
    if (
        document is not None
        and document.get("schema_version")
        == EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION
    ):
        runtime = _verify_historical_ready_executor_rescue_runtime_binding(
            document["executor_rescue"], expected_uid=uid
        )
        if runtime != document["executor_rescue"]:
            raise BridgeError("executor rescue journal binding changed")
    return document


def _legacy_v1_retry_upgrade(
    current: Mapping[str, object],
    *,
    readiness_origin: Mapping[str, object],
    baseline: Mapping[str, object],
    dropin: Path,
) -> dict[str, object]:
    release = Path(str(current.get("release")))
    entry = release / Path(str(ENTRY_RELATIVE))
    expected_error = (
        "command failed (2): /usr/bin/setpriv --reuid 1000: /usr/bin/python3: "
        f"can't open file '{entry}': [Errno 13] Permission denied"
    )
    identity = current.get("dropin_identity")
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    if (
        current.get("schema_version") != CONTRACT_VERSION
        or current.get("phase") != "failed"
        or current.get("attempts") != 1
        or current.get("activation") is not None
        or current.get("error") != expected_error
        or not isinstance(identity, dict)
        or set(identity) != identity_fields
        or identity.get("uid") != 0
        or identity.get("mode") != 0o644
        or identity.get("nlink") != 1
        or identity.get("sha256") != current.get("dropin_sha256")
        or not isinstance(current.get("readiness"), dict)
        or dropin.exists()
        or dropin.is_symlink()
        or baseline.get("ActiveState") != "inactive"
        or baseline.get("SubState") != "dead"
        or baseline.get("MainPID") != 0
    ):
        raise BridgeError("legacy v1 bridge journal is not the exact canary incident")
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["readiness_origin"] = dict(readiness_origin)
    payload["attempt_evidence"] = {
        "attempt": 1,
        "stage": "failed",
        "last_completed_stage": "systemd-ready",
        "systemd_ready": {
            "inferred_from_exact_v1_canary_error": True,
            "dropin_identity": current["dropin_identity"],
            "readiness_state_revision": current["readiness"]["state_revision"],
        },
        "failure_stage": "canaries",
        "error_sha256": _sha256_bytes(expected_error.encode("utf-8")),
    }
    return payload


def _descendant_retry_allowed(current: Mapping[str, object]) -> bool:
    evidence = current.get("attempt_evidence")
    ready = evidence.get("systemd_ready") if isinstance(evidence, dict) else None
    error = current.get("error")
    readiness = current.get("readiness")
    return bool(
        current.get("schema_version")
        in {JOURNAL_CONTRACT_VERSION, PREDECESSOR_JOURNAL_CONTRACT_VERSION}
        and current.get("phase") == "failed"
        and isinstance(error, str)
        and isinstance(evidence, dict)
        and evidence.get("attempt") == current.get("attempts")
        and evidence.get("stage") == "failed"
        and evidence.get("last_completed_stage") == "systemd-ready"
        and evidence.get("failure_stage") == "canaries"
        and evidence.get("error_sha256")
        == _sha256_bytes(error.encode("utf-8"))
        and isinstance(ready, dict)
        and isinstance(readiness, dict)
        and ready.get("dropin_identity") == current.get("dropin_identity")
        and ready.get("readiness_state_revision")
        == readiness.get("state_revision")
    )


def _failed_predecessor_readiness(
    *,
    transaction: Path,
    raw_sha256: str,
    document_sha256: str,
    operation_id: str,
    release: Path,
    release_digest: object,
    broker_socket: Path,
    dropin: Path,
    dropin_sha256: str,
    readiness_attestation: Path,
    database: Path,
    baseline: Mapping[str, object],
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Authorize one fresh retry from an exact cleaned-up failed predecessor."""

    if RELEASE_RE.fullmatch(raw_sha256) is None or RELEASE_RE.fullmatch(
        document_sha256
    ) is None:
        raise BridgeError("predecessor journal digests must be lowercase SHA-256")
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    _private_regular(
        journal_path, uid=expected_uid, label="predecessor schema-12 bridge journal"
    )
    if _sha256_file(journal_path) != raw_sha256:
        raise BridgeError("predecessor bridge journal raw digest changed")
    predecessor = _load_bridge_journal(journal_path, uid=expected_uid)
    if (
        predecessor is None
        or predecessor.get("schema_version") != JOURNAL_CONTRACT_VERSION
        or predecessor.get("document_sha256") != document_sha256
        or predecessor.get("operation_id") != operation_id
        or predecessor.get("phase") != "failed"
        or predecessor.get("release") != str(release)
        or predecessor.get("release_digest") != release_digest
        or predecessor.get("broker_socket") != str(broker_socket)
        or predecessor.get("dropin") != str(dropin)
        or predecessor.get("dropin_sha256") != dropin_sha256
        or not _descendant_retry_allowed(predecessor)
    ):
        raise BridgeError(
            "predecessor bridge journal is not an exact durable canary-stage failure"
        )
    if dropin.exists() or dropin.is_symlink():
        raise BridgeError("predecessor bridge drop-in cleanup is incomplete")
    if (
        baseline.get("ActiveState") != "inactive"
        or baseline.get("SubState") != "dead"
        or baseline.get("MainPID") != 0
        or broker_socket.exists()
        or broker_socket.is_symlink()
    ):
        raise BridgeError("predecessor broker cleanup is not stably inactive")
    origin = _readiness_origin_from_attestation(
        readiness_attestation,
        predecessor.get("readiness_origin"),
        uid=expected_uid,
    )
    current = _readiness_proof(
        readiness_attestation,
        database=database,
        uid=expected_uid,
        descendant_of=origin,
    )
    evidence = {
        "transaction": str(transaction),
        "journal": str(journal_path),
        "journal_raw_sha256": raw_sha256,
        "journal_document_sha256": document_sha256,
        "operation_id": operation_id,
        "attempt": predecessor["attempts"],
        "failure_stage": "canaries",
        "systemd_ready_sha256": _sha256_bytes(
            _canonical(predecessor["attempt_evidence"]["systemd_ready"])
        ),
        "readiness_origin_sha256": _sha256_bytes(_canonical(origin)),
        "accepted_readiness_sha256": _sha256_bytes(_canonical(current)),
    }
    return evidence, current, origin


def _verify_stored_predecessor_reference(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BridgeError("bridge journal omitted its predecessor evidence")
    required = {
        "transaction",
        "journal",
        "journal_raw_sha256",
        "journal_document_sha256",
        "operation_id",
    }
    if not required.issubset(value):
        raise BridgeError("bridge predecessor evidence is incomplete")
    transaction = _private_directory(Path(str(value["transaction"])), uid=expected_uid)
    journal = transaction / JOURNAL_NAME
    if str(journal) != value["journal"]:
        raise BridgeError("bridge predecessor journal path changed")
    _private_regular(journal, uid=expected_uid, label="predecessor bridge journal")
    if _sha256_file(journal) != value["journal_raw_sha256"]:
        raise BridgeError("bridge predecessor journal raw digest changed")
    predecessor = _load_bridge_journal(journal, uid=expected_uid)
    if (
        predecessor is None
        or predecessor.get("document_sha256")
        != value["journal_document_sha256"]
        or predecessor.get("operation_id") != value["operation_id"]
    ):
        raise BridgeError("bridge predecessor sealed identity changed")
    return dict(value)


def activate_bridge(
    *,
    release: Path,
    release_root: Path,
    transaction: Path,
    operation_id: str,
    failed_installer_transaction: Path,
    failed_installer_operation_id: str,
    readiness_attestation: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    canaries: list[str],
    wait_seconds: int,
    expected_uid: int,
    predecessor_transaction: Path | None = None,
    predecessor_operation_id: str | None = None,
    predecessor_journal_sha256: str | None = None,
    predecessor_document_sha256: str | None = None,
    client_release: Path | None = None,
    _authorized_readiness_origin: Mapping[str, object] | None = None,
    _defer_canaries_behind_maintenance: bool = False,
    _expected_readiness_state_revision: int | None = None,
    _cutover_maintenance_inventory_read: bool = False,
    _cutover_canary_repository_id: str | None = None,
    _cutover_canary_repository_generation: int | None = None,
    _cutover_expected_owner_uid: int | None = None,
    _executor_rescue_client_binding: Mapping[str, object] | None = None,
) -> dict[str, object]:
    try:
        operation_id = str(uuid.UUID(operation_id))
        failed_installer_operation_id = str(uuid.UUID(failed_installer_operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("bridge operation identities must be canonical UUIDs") from error
    predecessor_values = (
        predecessor_transaction,
        predecessor_operation_id,
        predecessor_journal_sha256,
        predecessor_document_sha256,
    )
    if any(value is not None for value in predecessor_values) and not all(
        value is not None for value in predecessor_values
    ):
        raise BridgeError("fresh retry requires every predecessor binding")
    if predecessor_operation_id is not None:
        try:
            if str(uuid.UUID(predecessor_operation_id)) != predecessor_operation_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as error:
            raise BridgeError(
                "predecessor bridge operation identity must be a canonical UUID"
            ) from error
        if predecessor_operation_id == operation_id:
            raise BridgeError("predecessor and fresh bridge operations must differ")
    if (
        _authorized_readiness_origin is not None
        and predecessor_transaction is not None
    ):
        raise BridgeError(
            "bridge activation cannot combine successor and retry readiness authority"
        )
    if _defer_canaries_behind_maintenance and _authorized_readiness_origin is None:
        raise BridgeError(
            "deferred bridge canaries require internal successor readiness authority"
        )
    if _expected_readiness_state_revision is not None and (
        isinstance(_expected_readiness_state_revision, bool)
        or not isinstance(_expected_readiness_state_revision, int)
        or _expected_readiness_state_revision < 0
        or _authorized_readiness_origin is None
    ):
        raise BridgeError(
            "expected bridge readiness revision requires internal successor authority"
        )
    cutover_canary_values = (
        _cutover_canary_repository_id,
        _cutover_canary_repository_generation,
        _cutover_expected_owner_uid,
    )
    if not isinstance(_cutover_maintenance_inventory_read, bool):
        raise BridgeError("cutover maintenance canary mode is invalid")
    if _cutover_maintenance_inventory_read:
        if (
            _authorized_readiness_origin is None
            or client_release is None
            or _defer_canaries_behind_maintenance
            or not isinstance(_cutover_canary_repository_id, str)
            or not _cutover_canary_repository_id
            or isinstance(_cutover_canary_repository_generation, bool)
            or not isinstance(_cutover_canary_repository_generation, int)
            or _cutover_canary_repository_generation < 0
            or isinstance(_cutover_expected_owner_uid, bool)
            or not isinstance(_cutover_expected_owner_uid, int)
            or _cutover_expected_owner_uid <= 0
        ):
            raise BridgeError(
                "cutover maintenance canaries require exact internal successor authority"
            )
    elif any(value is not None for value in cutover_canary_values):
        raise BridgeError(
            "cutover maintenance canary bindings require the internal read path"
        )
    if _executor_rescue_client_binding is not None and (
        not _cutover_maintenance_inventory_read or client_release is None
    ):
        raise BridgeError(
            "executor rescue activation requires the internal retained-client path"
        )
    if not canaries:
        raise BridgeError("bridge activation requires at least one owner-scoped canary")
    parsed_canaries = [_parse_canary(item) for item in canaries]
    if len({account.pw_uid for account, _project in parsed_canaries}) != len(parsed_canaries):
        raise BridgeError("bridge canaries must use distinct account UIDs")
    if _cutover_maintenance_inventory_read and all(
        account.pw_uid != _cutover_expected_owner_uid
        for account, _project in parsed_canaries
    ):
        raise BridgeError(
            "cutover maintenance canaries omitted their exact repository owner"
        )
    if not 1 <= wait_seconds <= 120:
        raise BridgeError("--wait-seconds must be from 1 through 120")
    database = _absolute(database, "authority database")
    profile = _absolute(profile, "protected profile")
    broker_socket = _absolute(broker_socket, "broker socket")
    dropin = _absolute(dropin, "broker drop-in")
    transaction = _private_directory(transaction, uid=expected_uid, create=True)
    journal_path = transaction / JOURNAL_NAME
    with _installer_lock(expected_uid):
        manifest = _verify_activation_release(
            release,
            release_root=release_root,
            owner_uid=expected_uid,
        )
        canary_release = release
        canary_manifest = manifest
        executor_rescue_binding: dict[str, object] | None = None
        if client_release is not None:
            client_release = _absolute(client_release, "bridge canary client release")
            if _executor_rescue_client_binding is None:
                canary_manifest = _verify_availability_client_release(
                    client_release, owner_uid=expected_uid
                )
            else:
                (
                    executor_rescue_binding,
                    canary_manifest,
                ) = _verify_successor_executor_rescue_runtime_binding(
                    dict(_executor_rescue_client_binding),
                    client_release=client_release,
                    expected_uid=expected_uid,
                )
            canary_release = client_release
        failure = _failed_activation_proof(
            failed_installer_transaction,
            operation_id=failed_installer_operation_id,
            uid=expected_uid,
        )
        profile_info = _protected_profile(profile, uid=expected_uid)
        dropin_payload = _dropin_payload(release, database, broker_socket)
        base_binding = {
            "operation_id": operation_id,
            "release": str(_absolute(release, "legacy release")),
            "release_digest": manifest["release_digest"],
            "dropin": str(dropin),
            "dropin_sha256": _sha256_bytes(dropin_payload),
            "broker_socket": str(broker_socket),
            "failed_activation": failure,
            "canaries": [
                {"user": account.pw_name, "uid": account.pw_uid, "project": str(project)}
                for account, project in parsed_canaries
            ],
        }
        if _executor_rescue_client_binding is not None:
            base_binding["executor_rescue"] = executor_rescue_binding

        def inventory_canaries() -> list[dict[str, object]]:
            if not _cutover_maintenance_inventory_read:
                return [
                    _inventory_canary(
                        release=canary_release,
                        account=account,
                        project=project,
                    )
                    for account, project in parsed_canaries
                ]
            repository_id = str(_cutover_canary_repository_id)
            repository_generation = int(
                _cutover_canary_repository_generation
            )
            owner_uid = int(_cutover_expected_owner_uid)
            results: list[dict[str, object]] = []
            for account, project in parsed_canaries:
                _profile_repository_binding(
                    profile,
                    client_uid=account.pw_uid,
                    owner_uid=owner_uid,
                    repository_id=repository_id,
                    repository_generation=repository_generation,
                    canonical_root=project,
                    database_generation=str(readiness["database_generation"]),
                    broker_socket=broker_socket,
                )
                result = _inventory_canary(
                        release=canary_release,
                        account=account,
                        project=project,
                        profile=profile,
                        expected_database_generation=str(
                            readiness["database_generation"]
                        ),
                        expected_repository_id=repository_id,
                        canary_repository_generation=repository_generation,
                        expected_broker_socket=broker_socket,
                        expected_service_uid=0,
                        _cutover_maintenance_inventory_read=True,
                        _historical_release_digest=str(
                            canary_manifest["release_digest"]
                        ),
                    )
                if _executor_rescue_client_binding is not None:
                    result["executor_rescue_sha256"] = (
                        executor_rescue_binding[
                            "executor_rescue_sha256"
                        ]
                    )
                results.append(result)
            return results

        current = _load_bridge_journal(journal_path, uid=expected_uid)
        if current is not None and current.get("executor_rescue") != (
            executor_rescue_binding
            if _executor_rescue_client_binding is not None
            else None
        ):
            raise BridgeError(
                "bridge executor rescue binding was omitted or changed"
            )
        authorized_readiness_origin: dict[str, object] | None = None
        if _authorized_readiness_origin is not None:
            # This argument is deliberately private and has no CLI surface.  The
            # clean-successor transaction derives it from the exact predecessor
            # journal, while this activation independently revalidates the
            # retained attestation before accepting a monotonic descendant.
            authorized_readiness_origin = _readiness_origin_from_attestation(
                readiness_attestation,
                _authorized_readiness_origin,
                uid=expected_uid,
            )
            if (
                current is not None
                and current.get("readiness_origin")
                != authorized_readiness_origin
            ):
                raise BridgeError(
                    "bridge successor readiness origin changed during replay"
                )
        if current is not None:
            for key, value in base_binding.items():
                if current.get(key) != value:
                    raise BridgeError("bridge journal belongs to another operation")
            stored_predecessor = current.get("predecessor_readiness")
            if predecessor_transaction is None:
                if stored_predecessor is not None:
                    raise BridgeError("bridge retry omitted its predecessor binding")
            elif (
                not isinstance(stored_predecessor, dict)
                or stored_predecessor.get("transaction")
                != str(_absolute(predecessor_transaction, "predecessor transaction"))
                or stored_predecessor.get("operation_id")
                != predecessor_operation_id
                or stored_predecessor.get("journal_raw_sha256")
                != predecessor_journal_sha256
                or stored_predecessor.get("journal_document_sha256")
                != predecessor_document_sha256
            ):
                raise BridgeError("bridge retry predecessor binding changed")
            else:
                _verify_stored_predecessor_reference(
                    stored_predecessor, expected_uid=expected_uid
                )
        if current is not None and current.get("phase") == "ready":
            readiness = _verify_retained_readiness_reference(
                readiness_attestation,
                current.get("readiness"),
                uid=expected_uid,
            )
            if (
                _expected_readiness_state_revision is not None
                and readiness.get("state_revision")
                != _expected_readiness_state_revision
            ):
                raise BridgeError("bridge ready revision changed during replay")
            binding = {**base_binding, "readiness": readiness}
            for key, value in binding.items():
                if current.get(key) != value:
                    raise BridgeError("bridge journal belongs to another operation")
            _verify_dropin_identity(
                dropin,
                current.get("dropin_identity"),
                uid=expected_uid,
                expected_sha256=str(binding["dropin_sha256"]),
            )
            state = _wait_active(broker_socket, wait_seconds)
            execution = _verify_loaded_bridge_execution(
                release=release,
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            )
            canary_results = inventory_canaries()
            replay_payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            replay_payload["activation"] = {
                "systemd": state,
                "execution": execution,
                "canaries": canary_results,
            }
            replay_payload["updated_at_epoch"] = int(time.time())
            persisted = _journal(journal_path, replay_payload, uid=expected_uid)
            replay = dict(persisted)
            replay["replayed"] = True
            return replay
        if current is not None and current.get("phase") == "systemd-ready":
            continuation_finalizer = (
                not _defer_canaries_behind_maintenance
                and _cutover_maintenance_inventory_read
                and isinstance(executor_rescue_binding, Mapping)
                and isinstance(
                    executor_rescue_binding.get(
                        "executor_rescue_post_export_continuation_sha256"
                    ),
                    str,
                )
            )
            if not _defer_canaries_behind_maintenance and not continuation_finalizer:
                raise BridgeError(
                    "deferred bridge activation requires its exact finalizer"
                )
            readiness = _verify_retained_readiness_reference(
                readiness_attestation,
                current.get("readiness"),
                uid=expected_uid,
            )
            if (
                _expected_readiness_state_revision is not None
                and readiness.get("state_revision")
                != _expected_readiness_state_revision
            ):
                raise BridgeError("deferred bridge readiness revision changed")
            binding = {**base_binding, "readiness": readiness}
            for key, value in binding.items():
                if current.get(key) != value:
                    raise BridgeError("bridge journal belongs to another operation")
            _verify_dropin_identity(
                dropin,
                current.get("dropin_identity"),
                uid=expected_uid,
                expected_sha256=str(binding["dropin_sha256"]),
            )
            state = _wait_active(broker_socket, wait_seconds)
            execution = _verify_loaded_bridge_execution(
                release=release,
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            )
            activation = current.get("activation")
            activation_systemd = (
                activation.get("systemd")
                if isinstance(activation, dict)
                else None
            )
            if (
                not isinstance(activation, dict)
                or not isinstance(activation_systemd, dict)
                or activation_systemd.get("InvocationID")
                != state.get("InvocationID")
                or activation.get("execution") != execution
                or activation.get("canaries") != []
            ):
                raise BridgeError("deferred bridge execution changed during replay")
            if continuation_finalizer:
                canary_results = inventory_canaries()
                replay_payload = {
                    key: value
                    for key, value in current.items()
                    if key not in {"schema_version", "kind", "document_sha256"}
                }
                replay_payload["phase"] = "ready"
                replay_payload["activation"] = {
                    "systemd": state,
                    "execution": execution,
                    "canaries": canary_results,
                }
                attempt_evidence = current.get("attempt_evidence")
                if not isinstance(attempt_evidence, Mapping):
                    raise BridgeError(
                        "post-export continuation attempt evidence is incomplete"
                    )
                replay_payload["attempt_evidence"] = {
                    **dict(attempt_evidence),
                    "stage": "ready",
                    "last_completed_stage": "canaries",
                    "failure_stage": None,
                    "error_sha256": None,
                }
                replay_payload["updated_at_epoch"] = int(time.time())
                persisted = _journal(journal_path, replay_payload, uid=expected_uid)
                replay = dict(persisted)
                replay["replayed"] = True
                return replay
            replay = dict(current)
            replay["replayed"] = True
            return replay

        baseline = _stable_inactive(broker_socket)
        readiness_origin: dict[str, object] | None = None
        legacy_upgrade: dict[str, object] | None = None
        predecessor_readiness: dict[str, object] | None = None
        with _broker_service_lock(database, expected_uid=expected_uid):
            if current is not None and current.get("phase") == "failed":
                origin_source = (
                    current.get("readiness_origin")
                    if current.get("schema_version") == JOURNAL_CONTRACT_VERSION
                    else current.get("readiness")
                )
                readiness_origin = _readiness_origin_from_attestation(
                    readiness_attestation,
                    origin_source,
                    uid=expected_uid,
                )
                if current.get("schema_version") == CONTRACT_VERSION:
                    legacy_upgrade = _legacy_v1_retry_upgrade(
                        current,
                        readiness_origin=readiness_origin,
                        baseline=baseline,
                        dropin=dropin,
                    )
                    descendant_allowed = True
                else:
                    descendant_allowed = _descendant_retry_allowed(current)
                readiness = _readiness_proof(
                    readiness_attestation,
                    database=database,
                    uid=expected_uid,
                    descendant_of=readiness_origin if descendant_allowed else None,
                )
            elif predecessor_transaction is not None:
                (
                    predecessor_readiness,
                    readiness,
                    readiness_origin,
                ) = _failed_predecessor_readiness(
                    transaction=predecessor_transaction,
                    raw_sha256=str(predecessor_journal_sha256),
                    document_sha256=str(predecessor_document_sha256),
                    operation_id=str(predecessor_operation_id),
                    release=release,
                    release_digest=manifest["release_digest"],
                    broker_socket=broker_socket,
                    dropin=dropin,
                    dropin_sha256=str(base_binding["dropin_sha256"]),
                    readiness_attestation=readiness_attestation,
                    database=database,
                    baseline=baseline,
                    expected_uid=expected_uid,
                )
            elif authorized_readiness_origin is not None:
                readiness_origin = dict(authorized_readiness_origin)
                readiness = _readiness_proof(
                    readiness_attestation,
                    database=database,
                    uid=expected_uid,
                    descendant_of=readiness_origin,
                )
            else:
                readiness = _readiness_proof(
                    readiness_attestation, database=database, uid=expected_uid
                )
                readiness_origin = dict(readiness)
            if (
                _expected_readiness_state_revision is not None
                and readiness.get("state_revision")
                != _expected_readiness_state_revision
            ):
                raise BridgeError("bridge readiness revision does not match its seal")
        if legacy_upgrade is not None:
            legacy_upgrade["readiness"] = readiness
            legacy_upgrade["updated_at_epoch"] = int(time.time())
            current = _journal(journal_path, legacy_upgrade, uid=expected_uid)
        binding = {**base_binding, "readiness": readiness}
        if current is not None:
            if current.get("phase") not in {"failed", "baseline"}:
                raise BridgeError("bridge transaction requires explicit recovery")
        if dropin.exists() or dropin.is_symlink():
            raise BridgeError("schema-12 bridge drop-in already exists without ready ownership evidence")
        attempts = int(current.get("attempts", 0)) + 1 if current else 1
        payload = {
            **binding,
            "readiness_origin": readiness_origin,
            "baseline": baseline,
            "phase": "baseline",
            "dropin_identity": None,
            "attempts": attempts,
            "attempt_evidence": {
                "attempt": attempts,
                "stage": "baseline",
                "last_completed_stage": "baseline",
                "systemd_ready": None,
                "failure_stage": None,
                "error_sha256": None,
            },
            "activation": None,
            "error": None,
            "created_at_epoch": current.get("created_at_epoch", int(time.time())) if current else int(time.time()),
            "updated_at_epoch": int(time.time()),
        }
        if predecessor_readiness is not None:
            payload["predecessor_readiness"] = predecessor_readiness
        elif current is not None and isinstance(
            current.get("predecessor_readiness"), dict
        ):
            payload["predecessor_readiness"] = current["predecessor_readiness"]
        _journal(journal_path, payload, uid=expected_uid)
        dropin_written = False
        published_identity: dict[str, object] | None = None
        start_attempted = False
        canary_stage = False
        try:
            # Bind the exact protected profile identity before the service can
            # consume it.  The legacy client parser is then exercised again by
            # every authenticated canary.
            current_profile = profile.lstat()
            if (
                current_profile.st_dev,
                current_profile.st_ino,
                current_profile.st_size,
                current_profile.st_mtime_ns,
            ) != (
                profile_info.st_dev,
                profile_info.st_ino,
                profile_info.st_size,
                profile_info.st_mtime_ns,
            ):
                raise BridgeError("protected profile changed before bridge activation")
            _write_dropin(dropin, dropin_payload, uid=expected_uid)
            dropin_written = True
            published_identity = _dropin_identity(
                dropin,
                uid=expected_uid,
                expected_sha256=str(binding["dropin_sha256"]),
            )
            payload.update(
                {
                    "phase": "dropin-published",
                    "dropin_identity": published_identity,
                    "attempt_evidence": {
                        **payload["attempt_evidence"],
                        "stage": "dropin-published",
                        "last_completed_stage": "dropin-published",
                    },
                    "updated_at_epoch": int(time.time()),
                }
            )
            _journal(journal_path, payload, uid=expected_uid)
            _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
            start_attempted = True
            _run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=30)
            state = _wait_active(broker_socket, wait_seconds)
            execution = _verify_loaded_bridge_execution(
                release=release,
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            )
            payload.update(
                {
                    "phase": "systemd-ready",
                    "activation": {
                        "systemd": state,
                        "execution": execution,
                        "canaries": [],
                    },
                    "attempt_evidence": {
                        "attempt": attempts,
                        "stage": "systemd-ready",
                        "last_completed_stage": "systemd-ready",
                        "systemd_ready": {
                            "systemd": state,
                            "dropin_identity": published_identity,
                            "readiness_state_revision": readiness["state_revision"],
                        },
                        "failure_stage": None,
                        "error_sha256": None,
                    },
                    "updated_at_epoch": int(time.time()),
                }
            )
            _journal(journal_path, payload, uid=expected_uid)
            if _defer_canaries_behind_maintenance:
                return _load_bridge_journal(journal_path, uid=expected_uid) or payload
            canary_stage = True
            canary_results = inventory_canaries()
            canary_stage = False
            payload.update(
                {
                    "phase": "ready",
                    "activation": {
                        "systemd": state,
                        "execution": execution,
                        "canaries": canary_results,
                    },
                    "attempt_evidence": {
                        **payload["attempt_evidence"],
                        "stage": "ready",
                        "last_completed_stage": "canaries",
                    },
                    "updated_at_epoch": int(time.time()),
                }
            )
            return _journal(journal_path, payload, uid=expected_uid)
        except BaseException as error:
            failure_text = str(error)[:4096]
            cleanup_errors: list[str] = []
            if dropin_written:
                try:
                    state = _systemd_state()
                    if _service_process_alive(state):
                        baseline_invocation = baseline.get("InvocationID")
                        current_invocation = state.get("InvocationID")
                        if (
                            not start_attempted
                            or not isinstance(current_invocation, str)
                            or not current_invocation
                            or current_invocation == baseline_invocation
                        ):
                            raise BridgeError(
                                "live broker appeared without transaction-owned invocation evidence"
                            )
                        _stop_owned_invocation(
                            expected_invocation=current_invocation,
                            broker_socket=broker_socket,
                            wait_seconds=wait_seconds,
                        )
                    if published_identity is None:
                        raise BridgeError(
                            "published bridge drop-in lacks sealed identity evidence"
                        )
                    _unlink_owned_dropin(
                        dropin,
                        published_identity,
                        uid=expected_uid,
                        expected_sha256=str(binding["dropin_sha256"]),
                    )
                    _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
                except (BridgeError, OSError) as cleanup_error:
                    cleanup_errors.append(str(cleanup_error))
            payload.update(
                {
                    "phase": "recovery-required" if cleanup_errors else "failed",
                    "error": (
                        failure_text
                        + (
                            "; bridge cleanup incomplete: " + "; ".join(cleanup_errors)
                            if cleanup_errors
                            else ""
                        )
                    )[:4096],
                    "attempt_evidence": {
                        **payload["attempt_evidence"],
                        "attempt": attempts,
                        "stage": "failed",
                        "failure_stage": "canaries" if canary_stage else payload["attempt_evidence"]["stage"],
                        "error_sha256": _sha256_bytes(failure_text.encode("utf-8")),
                    },
                    "updated_at_epoch": int(time.time()),
                }
            )
            _journal(journal_path, payload, uid=expected_uid)
            if cleanup_errors:
                raise BridgeError(payload["error"]) from error
            raise


def finalize_deferred_bridge_canaries(
    *,
    release: Path,
    release_root: Path,
    client_release: Path,
    transaction: Path,
    operation_id: str,
    readiness_attestation: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    expected_state_revision: int,
    canary_accounts: Sequence[Mapping[str, object]],
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    expected_owner_uid: int,
    wait_seconds: int,
    expected_uid: int,
) -> dict[str, object]:
    """Finalize one internally deferred bridge after maintenance is cleared.

    ``activate_bridge`` deliberately exposes no public deferred mode.  The
    policy-reconciliation recovery transaction is the only caller: it starts
    the exact clean release while cooperative clients remain fenced, proves
    stable systemd/socket/process identity, then calls this finalizer only
    after clearing that same maintenance marker.  A failure leaves the journal
    at ``systemd-ready`` so the outer transaction can re-arm maintenance and
    restore only its sealed invocation.
    """

    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("deferred bridge operation identity is invalid") from error
    if os.geteuid() != expected_uid:
        raise BridgeError("deferred bridge finalizer requires exact authority")
    if (
        not expected_database_generation
        or isinstance(expected_state_revision, bool)
        or not isinstance(expected_state_revision, int)
        or expected_state_revision < 0
        or isinstance(canary_repository_generation, bool)
        or not isinstance(canary_repository_generation, int)
        or canary_repository_generation < 0
        or isinstance(expected_owner_uid, bool)
        or not isinstance(expected_owner_uid, int)
        or expected_owner_uid <= 0
        or not canary_repository_id
        or not 1 <= wait_seconds <= 120
    ):
        raise BridgeError("deferred bridge canary binding is invalid")
    release = _absolute(release, "deferred bridge release")
    release_root = _absolute(release_root, "deferred bridge release root")
    client_release = _absolute(client_release, "deferred bridge client release")
    transaction = _private_directory(transaction, uid=expected_uid)
    readiness_attestation = _absolute(
        readiness_attestation, "deferred bridge readiness attestation"
    )
    database = _absolute(database, "deferred bridge authority database")
    profile = _absolute(profile, "deferred bridge protected profile")
    broker_socket = _absolute(broker_socket, "deferred bridge socket")
    dropin = _absolute(dropin, "deferred bridge drop-in")
    canary_project = _absolute(canary_project, "deferred bridge canary project")
    owner_user = next(
        (
            str(item["user"])
            for item in canary_accounts
            if isinstance(item, Mapping)
            and item.get("uid") == expected_owner_uid
        ),
        "",
    )
    accounts = _validate_successor_canary_accounts(
        list(canary_accounts),
        owner_user=owner_user,
        owner_uid=expected_owner_uid,
    )
    journal_path = transaction / JOURNAL_NAME
    with _installer_lock(expected_uid):
        manifest = _verify_activation_release(
            release,
            release_root=release_root,
            owner_uid=expected_uid,
        )
        _verify_availability_client_release(client_release, owner_uid=expected_uid)
        current = _load_bridge_journal(journal_path, uid=expected_uid)
        if (
            current is None
            or current.get("operation_id") != operation_id
            or current.get("phase") not in {"systemd-ready", "ready"}
            or current.get("release") != str(release)
            or current.get("release_digest") != manifest["release_digest"]
            or current.get("broker_socket") != str(broker_socket)
            or current.get("dropin") != str(dropin)
        ):
            raise BridgeError("deferred bridge journal binding changed")
        readiness = _verify_retained_readiness_reference(
            readiness_attestation,
            current.get("readiness"),
            uid=expected_uid,
        )
        if (
            readiness.get("database_generation") != expected_database_generation
            or readiness.get("state_revision") != expected_state_revision
        ):
            raise BridgeError("deferred bridge readiness seal changed")
        _verify_dropin_identity(
            dropin,
            current.get("dropin_identity"),
            uid=expected_uid,
            expected_sha256=str(current["dropin_sha256"]),
        )
        profile_before = _profile_identity(profile, uid=expected_uid)
        repository_bindings = [
            _profile_repository_binding(
                profile,
                client_uid=int(item["uid"]),
                owner_uid=expected_owner_uid,
                repository_id=canary_repository_id,
                repository_generation=canary_repository_generation,
                canonical_root=canary_project,
                database_generation=expected_database_generation,
                broker_socket=broker_socket,
            )
            for item in accounts
        ]
        state_before = _wait_active(broker_socket, wait_seconds)
        execution_before = _verify_loaded_bridge_execution(
            release=release,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
        process_before = _broker_process_identity(
            main_pid=int(state_before["MainPID"]),
            expected_argv=list(execution_before["argv"]),
            expected_uid=0,
        )
        peer_before = _broker_socket_peer(broker_socket)
        if (
            peer_before.get("pid") != state_before.get("MainPID")
            or peer_before.get("uid") != 0
        ):
            raise BridgeError("deferred bridge socket peer is not its exact MainPID")
        canaries = [
            _inventory_canary(
                release=client_release,
                account=pwd.getpwnam(str(item["user"])),
                project=canary_project,
                expected_database_generation=expected_database_generation,
                expected_repository_id=canary_repository_id,
                canary_repository_generation=canary_repository_generation,
                expected_broker_socket=broker_socket,
                expected_service_uid=0,
            )
            for item in accounts
        ]
        state_after = _wait_active(broker_socket, wait_seconds)
        execution_after = _verify_loaded_bridge_execution(
            release=release,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
        process_after = _broker_process_identity(
            main_pid=int(state_after["MainPID"]),
            expected_argv=list(execution_after["argv"]),
            expected_uid=0,
        )
        peer_after = _broker_socket_peer(broker_socket)
        if (
            state_after.get("InvocationID") != state_before.get("InvocationID")
            or state_after.get("MainPID") != state_before.get("MainPID")
            or execution_after != execution_before
            or process_after != process_before
            or peer_after != peer_before
            or _profile_identity(profile, uid=expected_uid) != profile_before
            or [
                _profile_repository_binding(
                    profile,
                    client_uid=int(item["uid"]),
                    owner_uid=expected_owner_uid,
                    repository_id=canary_repository_id,
                    repository_generation=canary_repository_generation,
                    canonical_root=canary_project,
                    database_generation=expected_database_generation,
                    broker_socket=broker_socket,
                )
                for item in accounts
            ]
            != repository_bindings
        ):
            raise BridgeError("deferred bridge changed during authenticated canaries")
        if current.get("phase") == "ready":
            activation = current.get("activation")
            if (
                not isinstance(activation, Mapping)
                or activation.get("systemd") != state_before
                or activation.get("execution") != execution_before
                or not isinstance(activation.get("canaries"), list)
                or len(activation["canaries"]) != len(accounts)
                or {
                    item.get("uid")
                    for item in activation["canaries"]
                    if isinstance(item, Mapping)
                }
                != {item["uid"] for item in accounts}
            ):
                raise BridgeError("deferred bridge ready evidence changed")
            replay = dict(current)
            replay["replayed"] = True
            return replay
        payload = {
            key: value
            for key, value in current.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        attempt_evidence = payload.get("attempt_evidence")
        if not isinstance(attempt_evidence, Mapping):
            raise BridgeError("deferred bridge attempt evidence is absent")
        payload.update(
            {
                "phase": "ready",
                "activation": {
                    "systemd": state_after,
                    "execution": execution_after,
                    "canaries": canaries,
                },
                "attempt_evidence": {
                    **dict(attempt_evidence),
                    "stage": "ready",
                    "last_completed_stage": "canaries",
                    "failure_stage": None,
                    "error_sha256": None,
                },
                "updated_at_epoch": int(time.time()),
            }
        )
        return _journal(journal_path, payload, uid=expected_uid)


def verify_deferred_bridge_preclear(
    *,
    release: Path,
    release_root: Path,
    transaction: Path,
    operation_id: str,
    readiness_attestation: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    expected_state_revision: int,
    canary_accounts: Sequence[Mapping[str, object]],
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    expected_owner_uid: int,
    wait_seconds: int,
    expected_uid: int,
) -> dict[str, object]:
    """Prove exact clean-bridge process identity while maintenance is active."""

    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("deferred preclear operation identity is invalid") from error
    release = _absolute(release, "deferred preclear release")
    release_root = _absolute(release_root, "deferred preclear release root")
    transaction = _private_directory(transaction, uid=expected_uid)
    database = _absolute(database, "deferred preclear authority database")
    profile = _absolute(profile, "deferred preclear protected profile")
    broker_socket = _absolute(broker_socket, "deferred preclear socket")
    dropin = _absolute(dropin, "deferred preclear drop-in")
    canary_project = _absolute(canary_project, "deferred preclear canary project")
    owner_user = next(
        (
            str(item["user"])
            for item in canary_accounts
            if isinstance(item, Mapping)
            and item.get("uid") == expected_owner_uid
        ),
        "",
    )
    accounts = _validate_successor_canary_accounts(
        list(canary_accounts),
        owner_user=owner_user,
        owner_uid=expected_owner_uid,
    )
    journal_path = transaction / JOURNAL_NAME
    journal_before = _private_file_identity(
        journal_path, uid=expected_uid, label="deferred preclear bridge journal"
    )
    bridge = _load_bridge_journal(journal_path, uid=expected_uid)
    manifest = _verify_activation_release(
        release, release_root=release_root, owner_uid=expected_uid
    )
    if (
        bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("phase") != "systemd-ready"
        or bridge.get("release") != str(release)
        or bridge.get("release_digest") != manifest["release_digest"]
        or bridge.get("broker_socket") != str(broker_socket)
        or bridge.get("dropin") != str(dropin)
    ):
        raise BridgeError("deferred preclear journal binding changed")
    readiness = _verify_retained_readiness_reference(
        _absolute(
            readiness_attestation, "deferred preclear readiness attestation"
        ),
        bridge.get("readiness"),
        uid=expected_uid,
    )
    if (
        readiness.get("database_generation") != expected_database_generation
        or readiness.get("state_revision") != expected_state_revision
    ):
        raise BridgeError("deferred preclear readiness revision changed")
    dropin_identity = _verify_dropin_identity(
        dropin,
        bridge.get("dropin_identity"),
        uid=expected_uid,
        expected_sha256=str(bridge["dropin_sha256"]),
    )
    profile_before = _profile_identity(profile, uid=expected_uid)
    repositories_before = [
        _profile_repository_binding(
            profile,
            client_uid=int(item["uid"]),
            owner_uid=expected_owner_uid,
            repository_id=canary_repository_id,
            repository_generation=canary_repository_generation,
            canonical_root=canary_project,
            database_generation=expected_database_generation,
            broker_socket=broker_socket,
        )
        for item in accounts
    ]
    state_before = _wait_active(broker_socket, wait_seconds)
    socket_before = _socket_identity(broker_socket)
    execution_before = _verify_loaded_bridge_execution(
        release=release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_before = _broker_process_identity(
        main_pid=int(state_before["MainPID"]),
        expected_argv=list(execution_before["argv"]),
        expected_uid=0,
    )
    peer_before = _broker_socket_peer(broker_socket)
    time.sleep(0.1)
    state_after = _wait_active(broker_socket, wait_seconds)
    socket_after = _socket_identity(broker_socket)
    execution_after = _verify_loaded_bridge_execution(
        release=release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_after = _broker_process_identity(
        main_pid=int(state_after["MainPID"]),
        expected_argv=list(execution_after["argv"]),
        expected_uid=0,
    )
    peer_after = _broker_socket_peer(broker_socket)
    if (
        state_after.get("InvocationID") != state_before.get("InvocationID")
        or state_after.get("MainPID") != state_before.get("MainPID")
        or socket_after != socket_before
        or execution_after != execution_before
        or process_after != process_before
        or peer_after != peer_before
        or peer_after.get("pid") != state_after.get("MainPID")
        or peer_after.get("uid") != 0
        or _profile_identity(profile, uid=expected_uid) != profile_before
        or [
            _profile_repository_binding(
                profile,
                client_uid=int(item["uid"]),
                owner_uid=expected_owner_uid,
                repository_id=canary_repository_id,
                repository_generation=canary_repository_generation,
                canonical_root=canary_project,
                database_generation=expected_database_generation,
                broker_socket=broker_socket,
            )
            for item in accounts
        ]
        != repositories_before
        or _private_file_identity(
            journal_path, uid=expected_uid, label="deferred preclear bridge journal"
        )
        != journal_before
    ):
        raise BridgeError("deferred bridge changed during preclear proof")
    return _seal(
        POLICY_RECOVERY_PRECLEAR_PROOF_KIND,
        {
            "operation_id": operation_id,
            "bridge_journal": str(journal_path),
            "bridge_journal_sha256": journal_before["sha256"],
            "bridge_document_sha256": bridge["document_sha256"],
            "release": str(release),
            "release_digest": manifest["release_digest"],
            "database": str(database),
            "database_generation": expected_database_generation,
            "state_revision": expected_state_revision,
            "profile": str(profile),
            "profile_identity": profile_before,
            "profile_repositories": repositories_before,
            "broker_socket": str(broker_socket),
            "socket_identity": socket_after,
            "socket_peer": peer_after,
            "dropin": str(dropin),
            "dropin_identity": dropin_identity,
            "systemd": state_after,
            "execution": execution_after,
            "process": process_after,
            "verified_at_epoch": int(time.time()),
        },
    )


_HANDOFF_FIELDS = {
    "operation_id",
    "outer_transaction_id",
    "bridge_journal",
    "bridge_journal_sha256",
    "bridge_document_sha256",
    "release",
    "release_digest",
    "database",
    "profile",
    "profile_identity",
    "broker_socket",
    "dropin",
    "dropin_sha256",
    "bridge_dropin_identity",
    "retirement_guard",
    "retirement_guard_sha256",
    "retirement_guard_identity",
    "activation_invocation_id",
    "readiness",
    "phase",
    "predecessor_sha256",
    "rollback_origin_phase",
    "rollback_dropin_identity",
    "rollback_guard_pending",
    "systemd",
    "created_at_epoch",
    "updated_at_epoch",
}


def _handoff_journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(HANDOFF_JOURNAL_KIND, payload)
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_handoff_journal(path: Path, *, uid: int) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_seal(
        _read_private_json(path, uid=uid, label="legacy-writer handoff journal"),
        kind=HANDOFF_JOURNAL_KIND,
        fields=_HANDOFF_FIELDS,
    )


def _handoff_advance(
    current: Mapping[str, object],
    *,
    path: Path,
    phase: str,
    predecessor_sha256: str,
    uid: int,
    **updates: object,
) -> dict[str, object]:
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload.update(updates)
    payload.update(
        {
            "phase": phase,
            "predecessor_sha256": predecessor_sha256,
            "updated_at_epoch": int(time.time()),
        }
    )
    return _handoff_journal(path, payload, uid=uid)


def _handoff_return(
    document: Mapping[str, object], *, replayed: bool = False
) -> dict[str, object]:
    result = dict(document)
    result["ok"] = True
    if replayed:
        result["replayed"] = True
    return result


def _handoff_static_binding(
    current: Mapping[str, object],
    *,
    operation_id: str,
    outer_transaction_id: str,
    bridge_journal: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    retirement_guard: Path,
) -> None:
    expected = {
        "operation_id": operation_id,
        "outer_transaction_id": outer_transaction_id,
        "bridge_journal": str(bridge_journal),
        "database": str(database),
        "profile": str(profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "retirement_guard": str(retirement_guard),
    }
    if any(current.get(key) != value for key, value in expected.items()):
        raise BridgeError("legacy-writer handoff journal belongs to another request")
    _private_regular(
        bridge_journal, uid=0, label="schema-12 bridge predecessor journal"
    )
    if _sha256_file(bridge_journal) != current.get("bridge_journal_sha256"):
        raise BridgeError("schema-12 bridge journal changed during writer handoff")


def _handoff_predecessor(
    current: Mapping[str, object],
    *,
    expected_sha256: str,
    source_phases: set[str],
    target_phase: str,
) -> bool:
    if (
        current.get("phase") == target_phase
        and current.get("predecessor_sha256") == expected_sha256
    ):
        return True
    if (
        current.get("document_sha256") != expected_sha256
        or current.get("phase") not in source_phases
    ):
        raise BridgeError("legacy-writer handoff predecessor evidence is invalid")
    return False


def _verify_handoff_active(
    current: Mapping[str, object], *, wait_seconds: int = 30
) -> dict[str, object]:
    dropin = Path(str(current["dropin"]))
    _verify_dropin_identity(
        dropin,
        current.get("rollback_dropin_identity")
        or current.get("bridge_dropin_identity"),
        uid=0,
        expected_sha256=str(current["dropin_sha256"]),
    )
    state = _wait_active(Path(str(current["broker_socket"])), wait_seconds)
    expected_invocation = current.get("activation_invocation_id")
    if (
        isinstance(expected_invocation, str)
        and expected_invocation
        and state.get("InvocationID") != expected_invocation
    ):
        raise BridgeError("schema-12 bridge invocation changed during writer handoff")
    _verify_loaded_bridge_execution(
        release=Path(str(current["release"])),
        database=Path(str(current["database"])),
        broker_socket=Path(str(current["broker_socket"])),
        dropin=dropin,
    )
    return state


def _verify_handoff_retired(current: Mapping[str, object]) -> dict[str, object]:
    guard = Path(str(current["retirement_guard"]))
    _verify_dropin_identity(
        guard,
        current.get("retirement_guard_identity"),
        uid=0,
        expected_sha256=str(current["retirement_guard_sha256"]),
    )
    dropin = Path(str(current["dropin"]))
    if dropin.exists() or dropin.is_symlink():
        raise BridgeError("schema-12 bridge drop-in reappeared after retirement")
    state = _stable_inactive(Path(str(current["broker_socket"])))
    if state.get("UnitFileState") != "disabled":
        raise BridgeError("retired legacy broker unit is not disabled")
    return state


def handoff_bridge(
    *,
    action: str,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    outer_transaction_id: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    retirement_guard: Path,
    handoff_journal: Path,
    expected_uid: int,
) -> dict[str, object]:
    if action not in {
        "handoff-reference",
        "handoff-arm",
        "handoff-retire",
        "handoff-rollback-prepare",
        "handoff-rollback-unfence",
        "handoff-verify-rearmed",
        "handoff-complete",
    }:
        raise BridgeError("legacy-writer handoff action is invalid")
    try:
        operation_id = str(uuid.UUID(operation_id))
        outer_transaction_id = str(uuid.UUID(outer_transaction_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("legacy-writer handoff identities must be canonical UUIDs") from error
    if RELEASE_RE.fullmatch(expected_journal_sha256) is None:
        raise BridgeError("legacy-writer handoff predecessor digest is invalid")
    if expected_uid != 0:
        raise BridgeError("legacy-writer handoff requires the root authority identity")
    transaction = _private_directory(transaction, uid=expected_uid)
    bridge_journal = transaction / JOURNAL_NAME
    handoff_journal = _absolute(handoff_journal, "legacy-writer handoff journal")
    if handoff_journal != transaction / HANDOFF_JOURNAL_NAME:
        raise BridgeError("legacy-writer handoff journal must belong to its bridge transaction")
    database = _absolute(database, "legacy authority database")
    profile = _absolute(profile, "protected profile")
    broker_socket = _absolute(broker_socket, "broker socket")
    dropin = _absolute(dropin, "broker bridge drop-in")
    retirement_guard = _absolute(retirement_guard, "legacy broker retirement guard")
    if (
        broker_socket != DEFAULT_SOCKET
        or dropin != DEFAULT_DROPIN
        or retirement_guard != DEFAULT_RETIREMENT_GUARD
    ):
        raise BridgeError("legacy-writer handoff paths are not the canonical writer boundary")

    with _installer_lock(expected_uid):
        current = _load_handoff_journal(handoff_journal, uid=expected_uid)
        if action == "handoff-reference":
            if current is not None:
                _handoff_static_binding(
                    current,
                    operation_id=operation_id,
                    outer_transaction_id=outer_transaction_id,
                    bridge_journal=bridge_journal,
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    retirement_guard=retirement_guard,
                )
                if (
                    current.get("phase") == "referenced"
                    and current.get("predecessor_sha256")
                    == expected_journal_sha256
                ):
                    _verify_profile_identity(
                        profile, current.get("profile_identity"), uid=expected_uid
                    )
                    _verify_handoff_active(current)
                    return _handoff_return(current, replayed=True)
                raise BridgeError("legacy-writer handoff reference already advanced")
            _private_regular(
                bridge_journal, uid=expected_uid, label="schema-12 bridge journal"
            )
            if _sha256_file(bridge_journal) != expected_journal_sha256:
                raise BridgeError("schema-12 bridge journal raw digest changed")
            bridge = _load_bridge_journal(bridge_journal, uid=expected_uid)
            if (
                bridge is None
                or bridge.get("operation_id") != operation_id
                or bridge.get("phase") != "ready"
                or bridge.get("broker_socket") != str(broker_socket)
                or bridge.get("dropin") != str(dropin)
            ):
                raise BridgeError("schema-12 bridge is not ready for writer handoff")
            release = Path(str(bridge["release"]))
            manifest = verify_release(release, release_root=release.parent)
            payload_sha256 = _sha256_bytes(
                _dropin_payload(release, database, broker_socket)
            )
            if (
                manifest.get("release_digest") != bridge.get("release_digest")
                or bridge.get("dropin_sha256") != payload_sha256
            ):
                raise BridgeError("schema-12 bridge release binding changed")
            dropin_identity = _verify_dropin_identity(
                dropin,
                bridge.get("dropin_identity"),
                uid=expected_uid,
                expected_sha256=payload_sha256,
            )
            profile_identity = _profile_identity(profile, uid=expected_uid)
            readiness_value = bridge.get("readiness")
            if not isinstance(readiness_value, dict):
                raise BridgeError("schema-12 bridge omitted readiness evidence")
            readiness = _verify_retained_readiness_reference(
                Path(str(readiness_value.get("path"))),
                readiness_value,
                uid=expected_uid,
            )
            activation = bridge.get("activation")
            activation_systemd = (
                activation.get("systemd") if isinstance(activation, dict) else None
            )
            invocation = (
                activation_systemd.get("InvocationID")
                if isinstance(activation_systemd, dict)
                else None
            )
            if not isinstance(invocation, str) or not invocation:
                raise BridgeError("schema-12 bridge omitted its active invocation")
            if retirement_guard.exists() or retirement_guard.is_symlink():
                raise BridgeError("legacy broker retirement guard already exists")
            state = _wait_active(broker_socket, 30)
            if state.get("InvocationID") != invocation:
                raise BridgeError("schema-12 bridge invocation changed before handoff")
            _verify_loaded_bridge_execution(
                release=release,
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            )
            now = int(time.time())
            document = _handoff_journal(
                handoff_journal,
                {
                    "operation_id": operation_id,
                    "outer_transaction_id": outer_transaction_id,
                    "bridge_journal": str(bridge_journal),
                    "bridge_journal_sha256": expected_journal_sha256,
                    "bridge_document_sha256": bridge["document_sha256"],
                    "release": str(release),
                    "release_digest": bridge["release_digest"],
                    "database": str(database),
                    "profile": str(profile),
                    "profile_identity": profile_identity,
                    "broker_socket": str(broker_socket),
                    "dropin": str(dropin),
                    "dropin_sha256": payload_sha256,
                    "bridge_dropin_identity": dropin_identity,
                    "retirement_guard": str(retirement_guard),
                    "retirement_guard_sha256": _sha256_bytes(
                        RETIREMENT_GUARD_PAYLOAD
                    ),
                    "retirement_guard_identity": None,
                    "activation_invocation_id": invocation,
                    "readiness": readiness,
                    "phase": "referenced",
                    "predecessor_sha256": expected_journal_sha256,
                    "rollback_origin_phase": None,
                    "rollback_dropin_identity": None,
                    "rollback_guard_pending": False,
                    "systemd": state,
                    "created_at_epoch": now,
                    "updated_at_epoch": now,
                },
                uid=expected_uid,
            )
            return _handoff_return(document)

        if current is None:
            raise BridgeError("legacy-writer handoff lacks its sealed reference")
        _handoff_static_binding(
            current,
            operation_id=operation_id,
            outer_transaction_id=outer_transaction_id,
            bridge_journal=bridge_journal,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            retirement_guard=retirement_guard,
        )
        guard_sha256 = str(current["retirement_guard_sha256"])

        if action == "handoff-arm":
            replay = _handoff_predecessor(
                current,
                expected_sha256=expected_journal_sha256,
                source_phases={"referenced"},
                target_phase="armed",
            )
            if replay:
                _verify_dropin_identity(
                    retirement_guard,
                    current.get("retirement_guard_identity"),
                    uid=expected_uid,
                    expected_sha256=guard_sha256,
                )
                _verify_handoff_active(current)
                return _handoff_return(current, replayed=True)
            if retirement_guard.exists() or retirement_guard.is_symlink():
                guard_identity = _dropin_identity(
                    retirement_guard,
                    uid=expected_uid,
                    expected_sha256=guard_sha256,
                )
            else:
                _write_dropin(
                    retirement_guard, RETIREMENT_GUARD_PAYLOAD, uid=expected_uid
                )
                guard_identity = _dropin_identity(
                    retirement_guard,
                    uid=expected_uid,
                    expected_sha256=guard_sha256,
                )
                _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
            state = _verify_handoff_active(current)
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="armed",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    retirement_guard_identity=guard_identity,
                    systemd=state,
                )
            )

        if action == "handoff-retire":
            replay = _handoff_predecessor(
                current,
                expected_sha256=expected_journal_sha256,
                source_phases={"armed"},
                target_phase="retired",
            )
            if replay:
                _verify_handoff_retired(current)
                return _handoff_return(current, replayed=True)
            _verify_dropin_identity(
                retirement_guard,
                current.get("retirement_guard_identity"),
                uid=expected_uid,
                expected_sha256=guard_sha256,
            )
            _stable_inactive(broker_socket)
            _run(["/usr/bin/systemctl", "disable", BROKER_UNIT], timeout=30)
            if dropin.exists() or dropin.is_symlink():
                _unlink_owned_dropin(
                    dropin,
                    current.get("bridge_dropin_identity"),
                    uid=expected_uid,
                    expected_sha256=str(current["dropin_sha256"]),
                )
            _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
            _run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=30)
            state = _wait_inactive(broker_socket, 30)
            if state.get("UnitFileState") != "disabled":
                raise BridgeError("legacy broker retirement did not disable its unit")
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="retired",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    systemd=state,
                )
            )

        if action == "handoff-complete":
            replay = _handoff_predecessor(
                current,
                expected_sha256=expected_journal_sha256,
                source_phases={"retired"},
                target_phase="committed",
            )
            state = _verify_handoff_retired(current)
            if replay:
                return _handoff_return(current, replayed=True)
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="committed",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    systemd=state,
                )
            )

        if action == "handoff-rollback-prepare":
            if (
                current.get("phase") == "rollback-prepared"
                and current.get("predecessor_sha256")
                == expected_journal_sha256
            ):
                if current.get("rollback_guard_pending") is True:
                    _verify_dropin_identity(
                        retirement_guard,
                        current.get("retirement_guard_identity"),
                        uid=expected_uid,
                        expected_sha256=guard_sha256,
                    )
                    _verify_dropin_identity(
                        dropin,
                        current.get("rollback_dropin_identity"),
                        uid=expected_uid,
                        expected_sha256=str(current["dropin_sha256"]),
                    )
                    _stable_inactive(broker_socket)
                else:
                    if retirement_guard.exists() or retirement_guard.is_symlink():
                        raise BridgeError(
                            "legacy writer rollback replay unexpectedly regained its guard"
                        )
                    _verify_handoff_active(current)
                return _handoff_return(current, replayed=True)
            if current.get("phase") == "rollback-prepare-intent":
                if current.get("predecessor_sha256") != expected_journal_sha256:
                    raise BridgeError(
                        "legacy-writer rollback intent predecessor changed"
                    )
                origin_phase = str(current["rollback_origin_phase"])
            else:
                _handoff_predecessor(
                    current,
                    expected_sha256=expected_journal_sha256,
                    source_phases={
                        "referenced",
                        "armed",
                        "retired",
                        "committed",
                    },
                    target_phase="rollback-prepared",
                )
                origin_phase = str(current["phase"])
                initial_state = _systemd_state()
                guard_pending_intent = bool(
                    origin_phase in {"retired", "committed"}
                    or (
                        origin_phase == "armed"
                        and not _service_process_alive(initial_state)
                    )
                )
                current = _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="rollback-prepare-intent",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    rollback_origin_phase=origin_phase,
                    rollback_guard_pending=guard_pending_intent,
                    systemd=initial_state,
                )
            rollback_identity: object = current.get("bridge_dropin_identity")
            guard_pending = current.get("rollback_guard_pending") is True
            if origin_phase == "referenced":
                state = _verify_handoff_active(current)
                if retirement_guard.exists() or retirement_guard.is_symlink():
                    raise BridgeError("unexpected retirement guard before rollback")
            elif origin_phase == "armed":
                if guard_pending:
                    _verify_dropin_identity(
                        retirement_guard,
                        current.get("retirement_guard_identity"),
                        uid=expected_uid,
                        expected_sha256=guard_sha256,
                    )
                    state = _stable_inactive(broker_socket)
                else:
                    state = _verify_handoff_active(current)
                    if retirement_guard.exists() or retirement_guard.is_symlink():
                        _unlink_owned_dropin(
                            retirement_guard,
                            current.get("retirement_guard_identity"),
                            uid=expected_uid,
                            expected_sha256=guard_sha256,
                        )
                        _run(
                            ["/usr/bin/systemctl", "daemon-reload"], timeout=30
                        )
            else:
                _verify_dropin_identity(
                    retirement_guard,
                    current.get("retirement_guard_identity"),
                    uid=expected_uid,
                    expected_sha256=guard_sha256,
                )
                state = _stable_inactive(broker_socket)
                if state.get("UnitFileState") != "disabled":
                    raise BridgeError(
                        "legacy broker unit changed before rollback preparation"
                    )
                if not (dropin.exists() or dropin.is_symlink()):
                    _write_dropin(
                        dropin,
                        _dropin_payload(
                            Path(str(current["release"])), database, broker_socket
                        ),
                        uid=expected_uid,
                    )
                rollback_identity = _dropin_identity(
                    dropin,
                    uid=expected_uid,
                    expected_sha256=str(current["dropin_sha256"]),
                )
                _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
                guard_pending = True
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="rollback-prepared",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    rollback_origin_phase=origin_phase,
                    rollback_dropin_identity=rollback_identity,
                    rollback_guard_pending=guard_pending,
                    systemd=state,
                )
            )

        if action == "handoff-rollback-unfence":
            if (
                current.get("phase") == "rollback-unfenced"
                and current.get("predecessor_sha256")
                == expected_journal_sha256
            ):
                if retirement_guard.exists() or retirement_guard.is_symlink():
                    raise BridgeError(
                        "legacy writer unfence replay unexpectedly regained its guard"
                    )
                _verify_dropin_identity(
                    dropin,
                    current.get("rollback_dropin_identity")
                    or current.get("bridge_dropin_identity"),
                    uid=expected_uid,
                    expected_sha256=str(current["dropin_sha256"]),
                )
                return _handoff_return(current, replayed=True)
            if current.get("phase") == "rollback-unfence-intent":
                if current.get("predecessor_sha256") != expected_journal_sha256:
                    raise BridgeError(
                        "legacy-writer unfence intent predecessor changed"
                    )
            else:
                _handoff_predecessor(
                    current,
                    expected_sha256=expected_journal_sha256,
                    source_phases={"rollback-prepared"},
                    target_phase="rollback-unfenced",
                )
                current = _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="rollback-unfence-intent",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                )
            if current.get("rollback_guard_pending") is True:
                _stable_inactive(broker_socket)
                _verify_dropin_identity(
                    dropin,
                    current.get("rollback_dropin_identity"),
                    uid=expected_uid,
                    expected_sha256=str(current["dropin_sha256"]),
                )
                if retirement_guard.exists() or retirement_guard.is_symlink():
                    _unlink_owned_dropin(
                        retirement_guard,
                        current.get("retirement_guard_identity"),
                        uid=expected_uid,
                        expected_sha256=guard_sha256,
                    )
                    _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
            elif retirement_guard.exists() or retirement_guard.is_symlink():
                raise BridgeError("legacy writer rollback guard state is contradictory")
            state = _systemd_state()
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="rollback-unfenced",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    rollback_guard_pending=False,
                    systemd=state,
                )
            )

        if action == "handoff-verify-rearmed":
            replay = _handoff_predecessor(
                current,
                expected_sha256=expected_journal_sha256,
                source_phases={"rollback-unfenced"},
                target_phase="rollback-ready",
            )
            if retirement_guard.exists() or retirement_guard.is_symlink():
                raise BridgeError("legacy writer retirement guard remained after rollback")
            state = _wait_active(broker_socket, 30)
            _verify_dropin_identity(
                dropin,
                current.get("rollback_dropin_identity")
                or current.get("bridge_dropin_identity"),
                uid=expected_uid,
                expected_sha256=str(current["dropin_sha256"]),
            )
            _verify_loaded_bridge_execution(
                release=Path(str(current["release"])),
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            )
            if replay:
                return _handoff_return(current, replayed=True)
            return _handoff_return(
                _handoff_advance(
                    current,
                    path=handoff_journal,
                    phase="rollback-ready",
                    predecessor_sha256=expected_journal_sha256,
                    uid=expected_uid,
                    activation_invocation_id=state["InvocationID"],
                    systemd=state,
                )
            )

        raise BridgeError("legacy-writer handoff action is unreachable")


def restore_bridge(
    *, transaction: Path, operation_id: str, expected_uid: int
) -> dict[str, object]:
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("bridge operation identity must be a canonical UUID") from error
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    with _installer_lock(expected_uid):
        current = _load_bridge_journal(journal_path, uid=expected_uid)
        if current is None or current.get("operation_id") != operation_id:
            raise BridgeError("bridge restore does not match its transaction")
        if current.get("phase") == "restored":
            replay = dict(current)
            replay["replayed"] = True
            return replay
        handoff = _load_handoff_journal(
            transaction / HANDOFF_JOURNAL_NAME, uid=expected_uid
        )
        if handoff is not None and handoff.get("phase") not in {
            "referenced",
            "rollback-ready",
        }:
            raise BridgeError(
                "bridge restore is fenced by an active legacy-writer handoff"
            )
        dropin = _absolute(Path(str(current["dropin"])), "broker drop-in")
        broker_socket = _absolute(
            Path(str(current["broker_socket"])), "broker socket"
        )
        present = dropin.exists() or dropin.is_symlink()
        dropin_identity = current.get("dropin_identity")
        if handoff is not None and handoff.get("phase") == "rollback-ready":
            dropin_identity = handoff.get("rollback_dropin_identity")
        if present:
            _verify_dropin_identity(
                dropin,
                dropin_identity,
                uid=expected_uid,
                expected_sha256=str(current["dropin_sha256"]),
            )
        crash_loop_restore: dict[str, object] | None = None
        state = _systemd_state()
        if _service_process_alive(state):
            if not present:
                raise BridgeError(
                    "bridge drop-in is missing while its broker process remains alive"
                )
            activation = current.get("activation")
            expected_invocation = None
            if isinstance(activation, dict) and isinstance(
                activation.get("systemd"), dict
            ):
                expected_invocation = activation["systemd"].get("InvocationID")
            if handoff is not None and handoff.get("phase") == "rollback-ready":
                handoff_systemd = handoff.get("systemd")
                if isinstance(handoff_systemd, dict):
                    expected_invocation = handoff_systemd.get("InvocationID")
            if expected_invocation is None and current.get("phase") in {
                "dropin-published",
                "recovery-required",
            }:
                baseline = current.get("baseline")
                baseline_invocation = (
                    baseline.get("InvocationID") if isinstance(baseline, dict) else None
                )
                candidate = state.get("InvocationID")
                if (
                    isinstance(candidate, str)
                    and candidate
                    and candidate != baseline_invocation
                ):
                    expected_invocation = candidate
            if state.get("InvocationID") == expected_invocation:
                _stop_owned_invocation(
                    expected_invocation=expected_invocation,
                    broker_socket=broker_socket,
                    wait_seconds=30,
                )
            else:
                _inactive, crash_loop_restore = (
                    _stop_verified_crash_loop_descendant(
                        current,
                        observed_state=state,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        wait_seconds=30,
                        expected_uid=expected_uid,
                    )
                )
        elif (
            state.get("ActiveState") != "inactive"
            or state.get("SubState") != "dead"
            or state.get("MainPID") != 0
            or broker_socket.exists()
            or broker_socket.is_symlink()
        ):
            if not present:
                raise BridgeError(
                    "broker baseline is not inactive and the bridge drop-in is missing"
                )
            _run(["/usr/bin/systemctl", "stop", BROKER_UNIT], timeout=30)
            _wait_inactive(broker_socket, 30)
        if present:
            _unlink_owned_dropin(
                dropin,
                dropin_identity,
                uid=expected_uid,
                expected_sha256=str(current["dropin_sha256"]),
            )
            _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
        elif current.get("phase") not in {"baseline", "failed"}:
            raise BridgeError("bridge drop-in disappeared before exact restore")
        final_state = _systemd_state()
        if (
            _service_process_alive(final_state)
            or final_state.get("ActiveState") != "inactive"
            or final_state.get("SubState") != "dead"
            or broker_socket.exists()
            or broker_socket.is_symlink()
        ):
            raise BridgeError("bridge restore could not prove an inactive broker baseline")
        payload = {
            key: value
            for key, value in current.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["phase"] = "restored"
        payload["updated_at_epoch"] = int(time.time())
        payload["error"] = None
        if crash_loop_restore is not None:
            activation = dict(current["activation"])
            activation["restore_descendant"] = crash_loop_restore
            payload["activation"] = activation
        return _journal(journal_path, payload, uid=expected_uid)


def verify_policy_reconciled_restored_predecessor(
    *,
    transaction: Path,
    operation_id: str,
    journal_raw_sha256: str,
    journal_document_sha256: str,
    readiness_attestation: Path,
    readiness_raw_sha256: str,
    readiness_document_sha256: str,
    database: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    expected_state_revision: int,
    expected_uid: int,
) -> dict[str, object]:
    """Bind the exact restored crash-loop predecessor to one safe descendant.

    This is intentionally narrower than normal bridge retry/successor
    admission.  It accepts only the schema-v3 journal produced when
    ``restore`` proved and stopped a supervised crash-loop descendant, plus
    the original sealed readiness evidence and an exact post-policy
    generation/revision.  The caller must hold the stopped-writer lock while
    invoking it.
    """

    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("restored predecessor operation identity is invalid") from error
    digests = (
        journal_raw_sha256,
        journal_document_sha256,
        readiness_raw_sha256,
        readiness_document_sha256,
    )
    if any(RELEASE_RE.fullmatch(str(value)) is None for value in digests):
        raise BridgeError("restored predecessor evidence digest is invalid")
    if (
        not expected_database_generation
        or isinstance(expected_state_revision, bool)
        or not isinstance(expected_state_revision, int)
        or expected_state_revision < 0
    ):
        raise BridgeError("restored predecessor descendant binding is invalid")
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    journal_before = _private_file_identity(
        journal_path, uid=expected_uid, label="restored predecessor journal"
    )
    if journal_before["sha256"] != journal_raw_sha256:
        raise BridgeError("restored predecessor journal raw digest changed")
    current = _load_bridge_journal(journal_path, uid=expected_uid)
    readiness_attestation = _absolute(
        readiness_attestation, "restored predecessor readiness attestation"
    )
    readiness_before = _private_file_identity(
        readiness_attestation,
        uid=expected_uid,
        label="restored predecessor readiness attestation",
    )
    if readiness_before["sha256"] != readiness_raw_sha256:
        raise BridgeError("restored predecessor readiness raw digest changed")
    if (
        current is None
        or current.get("schema_version")
        != PREDECESSOR_JOURNAL_CONTRACT_VERSION
        or current.get("document_sha256") != journal_document_sha256
        or current.get("operation_id") != operation_id
        or current.get("phase") != "restored"
        or current.get("broker_socket")
        != str(_absolute(broker_socket, "restored predecessor broker socket"))
        or current.get("dropin")
        != str(_absolute(dropin, "restored predecessor drop-in"))
    ):
        raise BridgeError(
            "predecessor is not the exact restored crash-loop bridge"
        )
    activation = current.get("activation")
    descendant = (
        activation.get("restore_descendant")
        if isinstance(activation, Mapping)
        else None
    )
    inactive = descendant.get("inactive_state") if isinstance(descendant, Mapping) else None
    if (
        not isinstance(descendant, Mapping)
        or descendant.get("kind")
        != "verified-supervised-crash-loop-descendant"
        or descendant.get("release_digest") != current.get("release_digest")
        or RELEASE_RE.fullmatch(str(descendant.get("execution_sha256"))) is None
        or type(descendant.get("activation_restart_count")) is not int
        or type(descendant.get("observed_restart_count")) is not int
        or type(descendant.get("last_restart_count")) is not int
        or int(descendant["observed_restart_count"])
        < int(descendant["activation_restart_count"])
        or int(descendant["last_restart_count"])
        < int(descendant["observed_restart_count"])
        or not all(
            isinstance(descendant.get(field), str) and descendant.get(field)
            for field in (
                "activation_invocation_id",
                "observed_invocation_id",
                "last_invocation_id",
            )
        )
        or not isinstance(inactive, Mapping)
        or inactive.get("ActiveState") != "inactive"
        or inactive.get("SubState") != "dead"
        or inactive.get("MainPID") != 0
    ):
        raise BridgeError("restored predecessor crash-loop proof is invalid")
    broker_socket = _absolute(broker_socket, "restored predecessor broker socket")
    dropin = _absolute(dropin, "restored predecessor drop-in")
    if dropin.exists() or dropin.is_symlink():
        raise BridgeError("restored predecessor drop-in reappeared")
    baseline = _stable_inactive(broker_socket)
    if (
        baseline.get("ActiveState") != "inactive"
        or baseline.get("SubState") != "dead"
        or baseline.get("MainPID") != 0
    ):
        raise BridgeError("restored predecessor broker is not stably inactive")
    release = _absolute(
        Path(str(current.get("release"))), "restored predecessor release"
    )
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    if manifest.get("release_digest") != current.get("release_digest"):
        raise BridgeError("restored predecessor release binding changed")
    origin = _readiness_origin_from_attestation(
        readiness_attestation,
        current.get("readiness_origin"),
        uid=expected_uid,
    )
    if origin.get("document_sha256") != readiness_document_sha256:
        raise BridgeError("restored predecessor readiness document changed")
    descendant_readiness = _readiness_proof(
        readiness_attestation,
        database=_absolute(database, "restored predecessor authority database"),
        uid=expected_uid,
        descendant_of=origin,
    )
    if (
        descendant_readiness.get("database_generation")
        != expected_database_generation
        or descendant_readiness.get("state_revision") != expected_state_revision
    ):
        raise BridgeError("restored predecessor descendant revision changed")
    if (
        _private_file_identity(
            journal_path, uid=expected_uid, label="restored predecessor journal"
        )
        != journal_before
        or _private_file_identity(
            readiness_attestation,
            uid=expected_uid,
            label="restored predecessor readiness attestation",
        )
        != readiness_before
    ):
        raise BridgeError("restored predecessor evidence changed while verified")
    return {
        "transaction": str(transaction),
        "operation_id": operation_id,
        "journal": str(journal_path),
        "journal_raw_sha256": journal_raw_sha256,
        "journal_document_sha256": journal_document_sha256,
        "release": str(release),
        "release_digest": manifest["release_digest"],
        "verified_unsealed_bytecode_cache_sha256": manifest.get(
            "verified_unsealed_bytecode_cache_sha256"
        ),
        "readiness_attestation": str(readiness_attestation),
        "readiness_raw_sha256": readiness_raw_sha256,
        "readiness_document_sha256": readiness_document_sha256,
        "readiness_origin": origin,
        "descendant_readiness": descendant_readiness,
        "crash_loop_restore_sha256": _sha256_bytes(_canonical(descendant)),
        "inactive_state": baseline,
    }


_SUCCESSOR_JOURNAL_FIELDS = {
    "operation_id",
    "binding",
    "predecessor",
    "profile",
    "candidate",
    "restored_predecessor",
    "phase",
    "error",
    "created_at_epoch",
    "updated_at_epoch",
}
_SUCCESSOR_PREDECESSOR_SHA_REPAIR_PHASES = frozenset(
    {
        "predecessor-verified",
        "maintenance-active",
        "predecessor-stop-intent",
        "predecessor-stopped",
        "predecessor-dropin-remove-intent",
    }
)
_SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES = frozenset(
    {
        "predecessor-dropin-remove-intent",
        "predecessor-retired",
    }
)
_SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES = frozenset(
    {
        "predecessor-retired",
        "profile-repair-intent",
        "profile-repaired",
        "candidate-activation-intent",
        "candidate-active",
        "candidate-verified",
    }
)
_SUCCESSOR_CLIENT_HANDOFF_FIELDS = frozenset(
    {
        "operation_id",
        "phase",
        "journal_backup",
        "journal_raw_sha256",
        "journal_document_sha256",
        "journal_identity",
        "journal_backup_identity",
        "intent",
        "intent_raw_sha256",
        "intent_document_sha256",
        "intent_identity",
        "previous_binding_sha256",
        "successor_binding_sha256",
        "stable_binding_sha256",
        "previous_client_release",
        "previous_client_release_digest",
        "successor_client_release",
        "successor_client_release_digest",
        "profile_identity",
        "profile_backup",
        "readiness_attestation",
        "database_bundle",
        "database_readiness",
        "broker_state",
        "predecessor_dropin",
        "recorded_at_epoch",
    }
)
_SUCCESSOR_CLIENT_HANDOFF_INTENT_FIELDS = (
    _SUCCESSOR_CLIENT_HANDOFF_FIELDS
    - {
        "journal_backup_identity",
        "intent",
        "intent_raw_sha256",
        "intent_document_sha256",
        "intent_identity",
    }
)
_SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS = frozenset(
    {
        "reason",
        "rescue_path",
        "operation_id",
        "phase",
        "journal_backup",
        "journal_raw_sha256",
        "journal_document_sha256",
        "journal_identity",
        "source_binding_sha256",
        "client_release",
        "client_release_digest",
        "previous_executor_release",
        "previous_executor_release_digest",
        "rescue_executor_release",
        "rescue_executor_release_digest",
        "source_profile",
        "predecessor_lineage",
        "first_handoff",
        "owner_binding_refresh_sha256",
        "live_state",
        "recorded_at_epoch",
    }
)
_SUCCESSOR_EXECUTOR_RESCUE_REQUEST_FIELDS = frozenset(
    {
        "reason",
        "rescue_path",
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "previous_executor_release",
        "previous_executor_release_digest",
        "retained_client_release",
        "retained_client_release_digest",
        "rescue_executor_release",
        "rescue_executor_release_digest",
    }
)
_SUCCESSOR_EXECUTOR_RESCUE_RUNTIME_FIELDS = frozenset(
    {
        "reason",
        "rescue_path",
        "executor_rescue_sha256",
        "client_release",
        "client_release_digest",
        "executor_release",
        "executor_release_digest",
        "source_profile_sha256",
        "predecessor_lineage_sha256",
        "first_handoff_sha256",
        "owner_binding_refresh_sha256",
    }
)
_SUCCESSOR_EXECUTOR_HANDOFF_RUNTIME_FIELDS = frozenset(
    {
        *_SUCCESSOR_EXECUTOR_RESCUE_RUNTIME_FIELDS,
        "executor_rescue_handoff_sha256",
        "original_executor_release",
        "original_executor_release_digest",
    }
)
_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_RUNTIME_FIELDS = frozenset(
    {
        *_SUCCESSOR_EXECUTOR_HANDOFF_RUNTIME_FIELDS,
        "executor_rescue_post_export_continuation_sha256",
        "handoff_executor_release",
        "handoff_executor_release_digest",
    }
)
_SUCCESSOR_EXECUTOR_RESCUE_FIELDS = frozenset(
    {
        *_SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS,
        "journal_backup_identity",
        "intent",
        "intent_raw_sha256",
        "intent_document_sha256",
        "intent_identity",
    }
)
_SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS = frozenset(
    {
        "reason",
        "handoff_path",
        "operation_id",
        "phase",
        "journal_backup",
        "journal_raw_sha256",
        "journal_document_sha256",
        "journal_identity",
        "source_binding_sha256",
        "executor_rescue_sha256",
        "previous_executor_release",
        "previous_executor_release_digest",
        "successor_executor_release",
        "successor_executor_release_digest",
        "retained_client_release",
        "retained_client_release_digest",
        "candidate_release",
        "candidate_release_digest",
        "source_profile_sha256",
        "predecessor_lineage_sha256",
        "first_handoff_sha256",
        "owner_binding_refresh_sha256",
        "live_state",
        "recorded_at_epoch",
    }
)
_SUCCESSOR_EXECUTOR_HANDOFF_REQUEST_FIELDS = frozenset(
    {
        "reason",
        "handoff_path",
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "executor_rescue_sha256",
        "previous_executor_release",
        "previous_executor_release_digest",
        "retained_client_release",
        "retained_client_release_digest",
        "successor_executor_release",
        "successor_executor_release_digest",
    }
)
_SUCCESSOR_EXECUTOR_HANDOFF_FIELDS = frozenset(
    {
        *_SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS,
        "journal_backup_identity",
        "intent",
        "intent_raw_sha256",
        "intent_document_sha256",
        "intent_identity",
    }
)
_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS = frozenset(
    {
        "reason",
        "continuation_path",
        "operation_id",
        "phase",
        "journal_backup",
        "journal_raw_sha256",
        "journal_document_sha256",
        "journal_identity",
        "source_binding_sha256",
        "executor_rescue_sha256",
        "executor_rescue_handoff_sha256",
        "previous_executor_release",
        "previous_executor_release_digest",
        "successor_executor_release",
        "successor_executor_release_digest",
        "retained_client_release",
        "retained_client_release_digest",
        "candidate_release",
        "candidate_release_digest",
        "failed_candidate",
        "failed_candidate_backup",
        "successor_candidate_transaction",
        "successor_candidate_operation_id",
        "source_profile_state_sha256",
        "source_profile_export_sha256",
        "live_state",
        "recorded_at_epoch",
    }
)
_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REQUEST_FIELDS = frozenset(
    {
        "reason",
        "continuation_path",
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "executor_rescue_sha256",
        "executor_rescue_handoff_sha256",
        "previous_executor_release",
        "previous_executor_release_digest",
        "retained_client_release",
        "retained_client_release_digest",
        "successor_executor_release",
        "successor_executor_release_digest",
    }
)
_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_FIELDS = frozenset(
    {
        *_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS,
        "journal_backup_identity",
        "failed_candidate_backup_identity",
        "intent",
        "intent_raw_sha256",
        "intent_document_sha256",
        "intent_identity",
    }
)
_SUCCESSOR_TERMINAL_FIELDS = {
    "operation_id",
    "status",
    "transaction_journal",
    "transaction_journal_sha256",
    "transaction_document_sha256",
    "predecessor_release_digest",
    "candidate_release_digest",
    "profile_before_sha256",
    "profile_after_sha256",
    "profile_owner_binding_sha256",
    "candidate_readiness_sha256",
    "restored_predecessor_sha256",
    "maintenance_deployment_id",
    "maintenance_handoff_sha256",
    "executor_rescue",
    "executor_rescue_sha256",
    "maintenance_clear_pending",
    "completed_at",
}
_SUCCESSOR_COMPLETION_FIELDS = {
    "operation_id",
    "status",
    "terminal",
    "terminal_sha256",
    "terminal_document_sha256",
    "transaction_document_sha256",
    "postclear_readiness",
    "maintenance_deployment_id",
    "maintenance_handoff_sha256",
    "executor_rescue",
    "executor_rescue_sha256",
    "maintenance_cleared",
    "completed_at",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _load_maintenance_contract():
    module_root = ROOT / "skills/codex-dev-coordinator/scripts"
    if str(module_root) not in sys.path:
        sys.path.insert(0, str(module_root))
    from devcoordinator import maintenance  # type: ignore[import-not-found]

    return maintenance


def _load_profile_contract():
    module_root = ROOT / "skills/codex-dev-coordinator/scripts"
    if str(module_root) not in sys.path:
        sys.path.insert(0, str(module_root))
    from devcoordinator import broker_profile  # type: ignore[import-not-found]

    return broker_profile


def _load_owner_contract():
    module_root = ROOT / "skills/codex-dev-coordinator/scripts"
    if str(module_root) not in sys.path:
        sys.path.insert(0, str(module_root))
    from devcoordinator import repository_owner_authority  # type: ignore[import-not-found]

    return repository_owner_authority


def _load_lifecycle_recovery_contract():
    """Load the recovery attestation validator from this immutable release."""

    path = ROOT / "scripts/orchestrate_availability_cutover.py"
    if not path.is_file() or path.is_symlink():
        raise BridgeError("lifecycle recovery contract is unavailable")
    spec = importlib.util.spec_from_file_location(
        f"devcoordinator_lifecycle_recovery_{ROOT.name}", path
    )
    if spec is None or spec.loader is None:
        raise BridgeError("lifecycle recovery contract cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except Exception as error:
        raise BridgeError(
            f"lifecycle recovery contract is invalid: {error}"
        ) from error
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _successor_canary_accounts(
    *,
    owner_user: str,
    owner_uid: int,
    additional_canaries: Sequence[str],
) -> list[dict[str, object]]:
    if (
        not owner_user
        or isinstance(owner_uid, bool)
        or not isinstance(owner_uid, int)
        or owner_uid <= 0
        or isinstance(additional_canaries, (str, bytes))
        or not additional_canaries
        or len(additional_canaries) > 15
    ):
        raise BridgeError("schema-12 successor canary accounts are invalid")
    requested: list[tuple[str, int]] = [(owner_user, owner_uid)]
    for value in additional_canaries:
        user, separator, raw_uid = str(value).partition("=")
        try:
            uid = int(raw_uid)
        except (TypeError, ValueError) as error:
            raise BridgeError(
                "--additional-canary must be USER=UID"
            ) from error
        if not separator or not user or str(uid) != raw_uid or uid <= 0:
            raise BridgeError("--additional-canary must be USER=UID")
        requested.append((user, uid))
    if len({user for user, _uid in requested}) != len(requested) or len(
        {uid for _user, uid in requested}
    ) != len(requested):
        raise BridgeError("schema-12 successor canary accounts repeat an identity")
    accounts: list[dict[str, object]] = []
    for user, uid in requested:
        try:
            account = pwd.getpwnam(user)
        except KeyError as error:
            raise BridgeError(f"unknown canary account: {user}") from error
        if account.pw_uid != uid:
            raise BridgeError(f"canary account UID changed: {user}")
        accounts.append({"user": account.pw_name, "uid": account.pw_uid})
    return sorted(accounts, key=lambda item: (int(item["uid"]), str(item["user"])))


def _validate_successor_canary_accounts(
    value: object, *, owner_user: str, owner_uid: int
) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise BridgeError("schema-12 successor canary account binding is invalid")
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"user", "uid"}:
            raise BridgeError("schema-12 successor canary account binding is invalid")
        user = str(item["user"])
        uid = item["uid"]
        if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
            raise BridgeError("schema-12 successor canary account binding is invalid")
        try:
            account = pwd.getpwnam(user)
        except KeyError as error:
            raise BridgeError(f"unknown canary account: {user}") from error
        if account.pw_uid != uid:
            raise BridgeError(f"canary account UID changed: {user}")
        normalized.append({"user": account.pw_name, "uid": account.pw_uid})
    expected = sorted(
        normalized, key=lambda item: (int(item["uid"]), str(item["user"]))
    )
    if (
        normalized != expected
        or len({item["user"] for item in normalized}) != len(normalized)
        or len({item["uid"] for item in normalized}) != len(normalized)
        or {"user": owner_user, "uid": owner_uid} not in normalized
    ):
        raise BridgeError("schema-12 successor canary account binding is invalid")
    return normalized


def _verify_availability_client_release(
    release: Path, *, owner_uid: int
) -> dict[str, object]:
    """Bind strict parsing/canaries to this running immutable release.

    A schema-12 broker release intentionally carries the old profile parser.
    The successor therefore accepts a second release identity, but it must be
    the immutable availability release containing this exact command.  This
    prevents a caller from validating with mutable checkout bytes or silently
    selecting another client implementation.
    """

    release = _absolute(release, "successor client release")
    if release != ROOT.resolve(strict=True):
        raise BridgeError(
            "successor client release must be the immutable release running the command"
        )
    verifier_path = release / "scripts/install_availability_release.py"
    if not verifier_path.is_file() or verifier_path.is_symlink():
        raise BridgeError("successor client release verifier is unavailable")
    spec = importlib.util.spec_from_file_location(
        f"devcoordinator_availability_verify_{release.name}", verifier_path
    )
    if spec is None or spec.loader is None:
        raise BridgeError("successor client release verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        verified = module.verify_release(release, owner_uid=owner_uid, owner_gid=0)
    except Exception as error:
        raise BridgeError(f"successor client release is invalid: {error}") from error
    finally:
        sys.modules.pop(spec.name, None)
    if (
        not isinstance(verified, dict)
        or verified.get("release_digest") != release.name
        or RELEASE_RE.fullmatch(release.name) is None
    ):
        raise BridgeError("successor client release identity is invalid")
    return dict(verified)


def _verify_historical_availability_release(
    release: Path, *, owner_uid: int
) -> dict[str, object]:
    """Verify retained producer evidence with the running release verifier.

    The historical lifecycle producer cannot contain a recovery command added
    later.  It must therefore be distinct from ``ROOT`` while its manifest and
    files are verified by the already-bound current immutable executor.
    """

    running = ROOT.resolve(strict=True)
    release = _absolute(release, "historical availability release")
    if release == running or release.parent != running.parent:
        raise BridgeError(
            "historical availability release is not a distinct retained producer"
        )
    verifier_path = running / "scripts/install_availability_release.py"
    if not verifier_path.is_file() or verifier_path.is_symlink():
        raise BridgeError("running availability release verifier is unavailable")
    spec = importlib.util.spec_from_file_location(
        f"devcoordinator_historical_availability_verify_{release.name}",
        verifier_path,
    )
    if spec is None or spec.loader is None:
        raise BridgeError("historical availability verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        verified = module.verify_release(
            release, owner_uid=owner_uid, owner_gid=0
        )
    except Exception as error:
        raise BridgeError(
            f"historical availability release is invalid: {error}"
        ) from error
    finally:
        sys.modules.pop(spec.name, None)
    if (
        not isinstance(verified, dict)
        or verified.get("release_digest") != release.name
        or RELEASE_RE.fullmatch(release.name) is None
    ):
        raise BridgeError("historical availability release identity is invalid")
    return dict(verified)


def _verify_successor_release_pair(
    client_release: Path, *, owner_uid: int
) -> dict[str, object]:
    """Verify the running executor and its separately retained client.

    New successor transactions use the immutable release that is executing
    this command for both roles.  A retained client is verified separately by
    the running executor's sealed-release verifier; whether it may be used is
    decided only after the existing successor journal is loaded under its
    transaction fence.
    """

    executor_release = ROOT.resolve(strict=True)
    executor_manifest = _verify_availability_client_release(
        executor_release, owner_uid=owner_uid
    )
    client_release = _absolute(client_release, "strict successor client release")
    if client_release == executor_release:
        client_manifest = executor_manifest
    else:
        client_manifest = _verify_historical_availability_release(
            client_release, owner_uid=owner_uid
        )
    return {
        "executor_release": str(executor_release),
        "executor_release_digest": executor_manifest["release_digest"],
        "client_release": str(client_release),
        "client_release_digest": client_manifest["release_digest"],
        "historical_client": client_release != executor_release,
    }


def _routes_inherited_lifecycle_client_handoff(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
) -> bool:
    """Admit only a structural handoff candidate to the strict validator.

    This gate does not validate or publish a handoff.  It only prevents the
    older dual-release replay guard from rejecting the one exact client-only
    transition which ``_migrate_inherited_successor_client_release`` then
    verifies against the inherited journal, live state, and retained evidence.
    """

    binding_value = current.get("binding")
    predecessor_value = current.get("predecessor")
    if (
        release_pair.get("historical_client") is True
        or not isinstance(binding_value, Mapping)
        or not isinstance(predecessor_value, Mapping)
        or "client_release_handoffs" in requested_binding
    ):
        return False
    binding = dict(binding_value)
    maintenance_handoff = binding.get("maintenance_handoff")
    ready_proof = predecessor_value.get("ready_proof")
    handoff_proof = (
        maintenance_handoff.get("predecessor_proof")
        if isinstance(maintenance_handoff, Mapping)
        else None
    )
    outer_rearm = (
        ready_proof.get("outer_rearm")
        if isinstance(ready_proof, Mapping)
        else None
    )
    if (
        not isinstance(outer_rearm, Mapping)
        or not isinstance(handoff_proof, Mapping)
        or handoff_proof.get("outer_rearm") != outer_rearm
        or requested_binding.get("client_release")
        != release_pair.get("client_release")
        or requested_binding.get("client_release_digest")
        != release_pair.get("client_release_digest")
        or _successor_binding_without_client_handoff(binding)
        != _successor_binding_without_client_handoff(requested_binding)
    ):
        return False
    raw_present = inherited_journal_sha256 is not None
    document_present = inherited_document_sha256 is not None
    digest_pair_valid = (
        raw_present
        and document_present
        and RELEASE_RE.fullmatch(str(inherited_journal_sha256)) is not None
        and RELEASE_RE.fullmatch(str(inherited_document_sha256)) is not None
    )
    if "client_release_handoffs" not in binding:
        return (
            current.get("phase")
            in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
            and digest_pair_valid
            and binding.get("client_release")
            != requested_binding.get("client_release")
            and binding.get("client_release_digest")
            != requested_binding.get("client_release_digest")
        )
    handoffs = binding["client_release_handoffs"]
    if (
        not isinstance(handoffs, list)
        or len(handoffs) != 1
        or not isinstance(handoffs[0], Mapping)
        or set(handoffs[0]) != _SUCCESSOR_CLIENT_HANDOFF_FIELDS
    ):
        return False
    handoff = handoffs[0]
    return digest_pair_valid and (
        handoff.get("phase")
        in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
        and (
            current.get("phase")
            not in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
            or current.get("phase") == handoff.get("phase")
        )
        and handoff.get("operation_id") == current.get("operation_id")
        and handoff.get("successor_client_release")
        == requested_binding.get("client_release")
        and handoff.get("successor_client_release_digest")
        == requested_binding.get("client_release_digest")
        and binding.get("client_release")
        == requested_binding.get("client_release")
        and binding.get("client_release_digest")
        == requested_binding.get("client_release_digest")
    )


def _routes_successor_executor_rescue(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
) -> bool:
    """Admit one exact post-handoff executor rescue to its strict publisher."""

    binding_value = current.get("binding")
    profile = current.get("profile")
    if (
        release_pair.get("historical_client") is not True
        or current.get("phase")
        not in _SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES
        or not isinstance(binding_value, Mapping)
        or not isinstance(profile, Mapping)
        or inherited_journal_sha256 is None
        or inherited_document_sha256 is None
        or RELEASE_RE.fullmatch(str(inherited_journal_sha256)) is None
        or RELEASE_RE.fullmatch(str(inherited_document_sha256)) is None
    ):
        return False
    binding = dict(binding_value)
    handoffs = binding.get("client_release_handoffs")
    if (
        not isinstance(handoffs, list)
        or len(handoffs) != 1
        or not isinstance(handoffs[0], Mapping)
        or handoffs[0].get("phase") != "predecessor-retired"
        or requested_binding.get("client_release")
        != binding.get("client_release")
        or requested_binding.get("client_release_digest")
        != binding.get("client_release_digest")
        or release_pair.get("client_release") != binding.get("client_release")
        or release_pair.get("client_release_digest")
        != binding.get("client_release_digest")
        or _successor_binding_without_client_handoff(binding)
        != _successor_binding_without_client_handoff(requested_binding)
    ):
        return False
    previous_client = handoffs[0].get("successor_client_release")
    previous_client_digest = handoffs[0].get("successor_client_release_digest")
    if (
        binding.get("client_release") != previous_client
        or binding.get("client_release_digest") != previous_client_digest
    ):
        return False
    rescue = binding.get("executor_rescue")
    if rescue is None:
        return (
            current.get("phase") == "predecessor-retired"
            and current.get("candidate")
            == {"activation": None, "readiness": None}
            and inherited_document_sha256
            == current.get("document_sha256")
            and not isinstance(profile.get("repaired_payload_sha256"), str)
            and profile.get("after_identity") is None
            and profile.get("restored_identity") is None
            and "export_evidence" not in profile
            and isinstance(profile.get("owner_binding_refresh"), Mapping)
            and isinstance(profile.get("owner_binding"), Mapping)
            and binding.get("owner_map") == profile.get("owner_binding")
            and profile.get("owner_binding_sha256")
            == profile["owner_binding"].get("document_sha256")
        )
    return (
        isinstance(rescue, Mapping)
        and rescue.get("operation_id") == current.get("operation_id")
        and rescue.get("phase") == "predecessor-retired"
        and rescue.get("journal_raw_sha256")
        == inherited_journal_sha256
        and rescue.get("journal_document_sha256")
        == inherited_document_sha256
        and rescue.get("client_release") == binding.get("client_release")
        and rescue.get("client_release_digest")
        == binding.get("client_release_digest")
        and rescue.get("rescue_executor_release")
        == release_pair.get("executor_release")
        and rescue.get("rescue_executor_release_digest")
        == release_pair.get("executor_release_digest")
    )


def _validate_successor_executor_rescue_request(
    value: object,
    *,
    current: Mapping[str, object] | None,
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    expected_uid: int,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != (
        _SUCCESSOR_EXECUTOR_RESCUE_REQUEST_FIELDS
    ):
        raise BridgeError("schema-12 executor rescue request fields are invalid")
    request = dict(value)
    digest_fields = {
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "previous_executor_release_digest",
        "retained_client_release_digest",
        "rescue_executor_release_digest",
    }
    for field in (
        "previous_executor_release",
        "retained_client_release",
        "rescue_executor_release",
    ):
        request[field] = str(
            _absolute(
                Path(str(request[field])),
                f"schema-12 executor rescue request {field}",
            )
        )
    binding = current.get("binding") if isinstance(current, Mapping) else None
    handoffs = (
        binding.get("client_release_handoffs")
        if isinstance(binding, Mapping)
        else None
    )
    handoff = (
        _validated_successor_client_handoff(
            handoffs[0], expected_uid=expected_uid
        )
        if isinstance(handoffs, list) and len(handoffs) == 1
        else None
    )
    running = ROOT.resolve(strict=True)
    if (
        request["reason"] != SUCCESSOR_EXECUTOR_RESCUE_REASON
        or request["rescue_path"] != SUCCESSOR_EXECUTOR_RESCUE_PATH
        or any(
            RELEASE_RE.fullmatch(str(request[field])) is None
            for field in digest_fields
        )
        or current is None
        or not isinstance(binding, Mapping)
        or not isinstance(handoff, Mapping)
        or request["inherited_journal_raw_sha256"]
        != inherited_journal_sha256
        or request["inherited_journal_document_sha256"]
        != inherited_document_sha256
        or request["previous_executor_release"]
        != request["retained_client_release"]
        or request["previous_executor_release_digest"]
        != request["retained_client_release_digest"]
        or request["retained_client_release"]
        != binding.get("client_release")
        or request["retained_client_release_digest"]
        != binding.get("client_release_digest")
        or request["retained_client_release"]
        != handoff.get("successor_client_release")
        or request["retained_client_release_digest"]
        != handoff.get("successor_client_release_digest")
        or request["rescue_executor_release"] != str(running)
        or request["rescue_executor_release_digest"] != running.name
        or request["rescue_executor_release"]
        != release_pair.get("executor_release")
        or request["rescue_executor_release_digest"]
        != release_pair.get("executor_release_digest")
        or request["retained_client_release"]
        != release_pair.get("client_release")
        or request["retained_client_release_digest"]
        != release_pair.get("client_release_digest")
        or release_pair.get("historical_client") is not True
    ):
        raise BridgeError("schema-12 executor rescue request binding changed")
    return request


def _validate_successor_executor_handoff_request(
    value: object,
    *,
    current: Mapping[str, object] | None,
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    expected_uid: int,
) -> dict[str, object]:
    """Admit only the exact executor replacement for one published rescue."""

    if not isinstance(value, dict) or set(value) != (
        _SUCCESSOR_EXECUTOR_HANDOFF_REQUEST_FIELDS
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff request fields are invalid"
        )
    request = dict(value)
    for field in (
        "previous_executor_release",
        "retained_client_release",
        "successor_executor_release",
    ):
        request[field] = str(
            _absolute(
                Path(str(request[field])),
                f"schema-12 rescue executor handoff {field}",
            )
        )
    digest_fields = {
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "executor_rescue_sha256",
        "previous_executor_release_digest",
        "retained_client_release_digest",
        "successor_executor_release_digest",
    }
    binding = current.get("binding") if isinstance(current, Mapping) else None
    rescue = (
        _validated_successor_executor_rescue(
            binding.get("executor_rescue"), expected_uid=expected_uid
        )
        if isinstance(binding, Mapping)
        and binding.get("executor_rescue") is not None
        else None
    )
    existing_handoff = (
        _validated_successor_executor_handoff(
            binding.get("executor_rescue_handoff"),
            expected_uid=expected_uid,
        )
        if isinstance(binding, Mapping)
        and binding.get("executor_rescue_handoff") is not None
        else None
    )
    first_publication = (
        existing_handoff is None
        and isinstance(current, Mapping)
        and current.get("phase") == "predecessor-retired"
        and current.get("document_sha256")
        == inherited_document_sha256
    )
    retained_replay = (
        isinstance(existing_handoff, Mapping)
        and isinstance(current, Mapping)
        and current.get("phase")
        in _SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES
        and existing_handoff.get("journal_raw_sha256")
        == inherited_journal_sha256
        and existing_handoff.get("journal_document_sha256")
        == inherited_document_sha256
        and existing_handoff.get("executor_rescue_sha256")
        == request["executor_rescue_sha256"]
        and existing_handoff.get("previous_executor_release")
        == request["previous_executor_release"]
        and existing_handoff.get("previous_executor_release_digest")
        == request["previous_executor_release_digest"]
        and existing_handoff.get("retained_client_release")
        == request["retained_client_release"]
        and existing_handoff.get("retained_client_release_digest")
        == request["retained_client_release_digest"]
        and existing_handoff.get("successor_executor_release")
        == request["successor_executor_release"]
        and existing_handoff.get("successor_executor_release_digest")
        == request["successor_executor_release_digest"]
    )
    running = ROOT.resolve(strict=True)
    if (
        request["reason"] != SUCCESSOR_EXECUTOR_HANDOFF_REASON
        or request["handoff_path"] != SUCCESSOR_EXECUTOR_HANDOFF_PATH
        or any(
            RELEASE_RE.fullmatch(str(request[field])) is None
            for field in digest_fields
        )
        or current is None
        or not (first_publication or retained_replay)
        or inherited_journal_sha256
        != request["inherited_journal_raw_sha256"]
        or inherited_document_sha256
        != request["inherited_journal_document_sha256"]
        or not isinstance(binding, Mapping)
        or not isinstance(rescue, Mapping)
        or request["executor_rescue_sha256"]
        != _sha256_bytes(_canonical(rescue))
        or request["previous_executor_release"]
        != rescue["rescue_executor_release"]
        or request["previous_executor_release_digest"]
        != rescue["rescue_executor_release_digest"]
        or request["retained_client_release"] != rescue["client_release"]
        or request["retained_client_release_digest"]
        != rescue["client_release_digest"]
        or request["successor_executor_release"] != str(running)
        or request["successor_executor_release_digest"] != running.name
        or request["successor_executor_release"]
        == request["previous_executor_release"]
        or request["successor_executor_release_digest"]
        == request["previous_executor_release_digest"]
        or request["retained_client_release"]
        != release_pair.get("client_release")
        or request["retained_client_release_digest"]
        != release_pair.get("client_release_digest")
        or request["successor_executor_release"]
        != release_pair.get("executor_release")
        or request["successor_executor_release_digest"]
        != release_pair.get("executor_release_digest")
        or release_pair.get("historical_client") is not True
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff request binding changed"
        )
    return request


def _authorize_successor_release_pair(
    current: Mapping[str, object] | None,
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    executor_handoff_request: Mapping[str, object] | None = None,
    post_export_continuation_request: Mapping[str, object] | None = None,
) -> None:
    """Apply the fresh-vs-replay boundary for successor release identities."""

    historical_client = release_pair.get("historical_client") is True
    if historical_client:
        if (
            executor_handoff_request is not None
            or post_export_continuation_request is not None
        ):
            return
        if current is not None and _routes_successor_executor_rescue(
            current,
            requested_binding=requested_binding,
            release_pair=release_pair,
            inherited_journal_sha256=inherited_journal_sha256,
            inherited_document_sha256=inherited_document_sha256,
        ):
            return
        raise BridgeError(
            "schema-12 successor historical client requires its exact "
            "journaled executor rescue"
        )
    if current is None:
        return
    if _routes_inherited_lifecycle_client_handoff(
        current,
        requested_binding=requested_binding,
        release_pair=release_pair,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
    ):
        return

    retained_binding = current.get("binding")
    retained_predecessor = current.get("predecessor")
    retained_handoff = (
        retained_binding.get("maintenance_handoff")
        if isinstance(retained_binding, Mapping)
        else None
    )
    retained_proof = (
        retained_predecessor.get("ready_proof")
        if isinstance(retained_predecessor, Mapping)
        else None
    )
    retained_outer_rearm = (
        retained_proof.get("outer_rearm")
        if isinstance(retained_proof, Mapping)
        else None
    )
    retained_handoff_proof = (
        retained_handoff.get("predecessor_proof")
        if isinstance(retained_handoff, Mapping)
        else None
    )
    if (
        isinstance(retained_outer_rearm, Mapping)
        and isinstance(retained_handoff_proof, Mapping)
        and retained_handoff_proof.get("outer_rearm") == retained_outer_rearm
        and retained_binding != requested_binding
    ):
        raise BridgeError(
            "inherited lifecycle successor must retain its journal-bound "
            "client release"
        )


@contextmanager
def _successor_transaction_fence(
    *,
    operation_id: str,
    journal: Path,
    terminal: Path,
    action: str,
    expected_uid: int,
):
    handle = None
    succeeded = False
    try:
        handle = acquire_transaction_fence(
            owner_kind=SUCCESSOR_FENCE_OWNER,
            operation_id=operation_id,
            transaction=journal,
            terminal=terminal,
            action=action,
            expected_uid=expected_uid,
            expected_gid=0,
            lock_path=INSTALLER_LOCK,
        )
        yield handle
        succeeded = True
    except InstallerFenceError as error:
        raise BridgeError(str(error)) from error
    finally:
        if handle is not None:
            if handle.depth > 1:
                release_nested_installer_fence(handle)
            else:
                handle.close(command_succeeded=succeeded)


def _successor_journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(SUCCESSOR_JOURNAL_KIND, payload)
    _atomic_private_json(path, document, uid=uid)
    return document


def _verify_successor_journal(value: object) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_JOURNAL_KIND,
        fields=_SUCCESSOR_JOURNAL_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 successor journal operation is invalid") from error
    if (
        operation_id != document["operation_id"]
        or not isinstance(document["binding"], dict)
        or not isinstance(document["predecessor"], dict)
        or not isinstance(document["profile"], dict)
        or not isinstance(document["candidate"], dict)
        or document["restored_predecessor"] is not None
        and not isinstance(document["restored_predecessor"], dict)
        or not isinstance(document["phase"], str)
        or document["phase"] not in {
            "predecessor-verified",
            "maintenance-active",
            "predecessor-stop-intent",
            "predecessor-stopped",
            "predecessor-dropin-remove-intent",
            "predecessor-retired",
            "profile-repair-intent",
            "profile-repaired",
            "candidate-activation-intent",
            "candidate-active",
            "candidate-verified",
            "abort-intent",
            "predecessor-restored",
        }
        or document["error"] is not None
        and not isinstance(document["error"], str)
        or any(
            isinstance(document[field], bool)
            or not isinstance(document[field], int)
            or int(document[field]) <= 0
            for field in ("created_at_epoch", "updated_at_epoch")
        )
    ):
        raise BridgeError("schema-12 successor journal binding is invalid")
    return document


def _load_successor_journal(path: Path, *, uid: int) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_successor_journal(
        _read_private_json(path, uid=uid, label="schema-12 successor journal")
    )


def _successor_terminal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(SUCCESSOR_TERMINAL_KIND, payload)
    if path.exists() or path.is_symlink():
        retained = _verify_successor_terminal(
            _read_private_json(path, uid=uid, label="schema-12 successor terminal")
        )
        if retained != document:
            raise BridgeError("schema-12 successor terminal evidence changed")
        return retained
    _atomic_private_json(path, document, uid=uid)
    return document


def _verify_successor_terminal(value: object) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_TERMINAL_KIND,
        fields=_SUCCESSOR_TERMINAL_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
        maintenance_deployment_id = str(
            uuid.UUID(str(document["maintenance_deployment_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 successor terminal operation is invalid") from error
    digests = (
        "transaction_journal_sha256",
        "transaction_document_sha256",
        "predecessor_release_digest",
        "candidate_release_digest",
        "profile_before_sha256",
        "profile_after_sha256",
        "profile_owner_binding_sha256",
    )
    optional_digests = (
        "candidate_readiness_sha256",
        "restored_predecessor_sha256",
        "executor_rescue_sha256",
    )
    executor_rescue = document["executor_rescue"]
    if (
        operation_id != document["operation_id"]
        or document["status"] not in {"committed", "aborted"}
        or any(RELEASE_RE.fullmatch(str(document[field])) is None for field in digests)
        or any(
            document[field] is not None
            and RELEASE_RE.fullmatch(str(document[field])) is None
            for field in optional_digests
        )
        or RELEASE_RE.fullmatch(str(document["maintenance_handoff_sha256"]))
        is None
        or (executor_rescue is None)
        != (document["executor_rescue_sha256"] is None)
        or executor_rescue is not None
        and _validate_successor_executor_rescue_runtime_evidence(
            executor_rescue,
            expected_sha256=document["executor_rescue_sha256"],
        ).get("executor_rescue_sha256")
        != document["executor_rescue_sha256"]
        or maintenance_deployment_id != document["maintenance_deployment_id"]
        or maintenance_deployment_id == operation_id
        or document["maintenance_clear_pending"] is not True
        or not isinstance(document["completed_at"], str)
        or not str(document["completed_at"]).endswith("Z")
    ):
        raise BridgeError("schema-12 successor terminal binding is invalid")
    document["transaction_journal"] = str(
        _absolute(
            Path(str(document["transaction_journal"])),
            "schema-12 successor terminal journal",
        )
    )
    if (document["status"] == "committed") != (
        document["candidate_readiness_sha256"] is not None
        and document["restored_predecessor_sha256"] is None
    ):
        raise BridgeError("schema-12 successor terminal outcome is contradictory")
    if (document["status"] == "aborted") != (
        document["candidate_readiness_sha256"] is None
        and document["restored_predecessor_sha256"] is not None
    ):
        raise BridgeError("schema-12 successor terminal outcome is contradictory")
    return document


def _successor_completion(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(SUCCESSOR_COMPLETION_KIND, payload)
    if path.exists() or path.is_symlink():
        retained = _verify_successor_completion(
            _read_private_json(path, uid=uid, label="schema-12 successor completion")
        )
        if retained != document:
            raise BridgeError("schema-12 successor completion evidence changed")
        return retained
    _atomic_private_json(path, document, uid=uid)
    return document


def _verify_successor_completion(value: object) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_COMPLETION_KIND,
        fields=_SUCCESSOR_COMPLETION_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
        maintenance_deployment_id = str(
            uuid.UUID(str(document["maintenance_deployment_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 successor completion identity is invalid") from error
    executor_rescue = document["executor_rescue"]
    if (
        operation_id != document["operation_id"]
        or document["status"] != "committed"
        or maintenance_deployment_id != document["maintenance_deployment_id"]
        or maintenance_deployment_id == operation_id
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in (
                "terminal_sha256",
                "terminal_document_sha256",
                "transaction_document_sha256",
                "maintenance_handoff_sha256",
            )
        )
        or document["executor_rescue_sha256"] is not None
        and RELEASE_RE.fullmatch(
            str(document["executor_rescue_sha256"])
        )
        is None
        or (executor_rescue is None)
        != (document["executor_rescue_sha256"] is None)
        or executor_rescue is not None
        and _validate_successor_executor_rescue_runtime_evidence(
            executor_rescue,
            expected_sha256=document["executor_rescue_sha256"],
        ).get("executor_rescue_sha256")
        != document["executor_rescue_sha256"]
        or document["maintenance_cleared"] is not True
        or not isinstance(document["completed_at"], str)
        or not str(document["completed_at"]).endswith("Z")
    ):
        raise BridgeError("schema-12 successor completion binding is invalid")
    document["terminal"] = str(
        _absolute(
            Path(str(document["terminal"])),
            "schema-12 successor completion terminal",
        )
    )
    document["postclear_readiness"] = _verify_successor_ready_proof(
        document["postclear_readiness"]
    )
    if (
        document["postclear_readiness"].get("executor_rescue")
        != executor_rescue
        or document["postclear_readiness"].get(
            "executor_rescue_sha256"
        )
        != document["executor_rescue_sha256"]
    ):
        raise BridgeError(
            "schema-12 successor completion rescue binding changed"
        )
    return document


def _write_private_bytes_once(path: Path, payload: bytes, *, uid: int) -> None:
    _private_directory(path.parent, uid=uid)
    if path.exists() or path.is_symlink():
        _private_regular(path, uid=uid, label="schema-12 successor retained bytes")
        if _sha256_file(path) != _sha256_bytes(payload) or path.read_bytes() != payload:
            raise BridgeError("schema-12 successor retained bytes changed")
        return
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
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
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BridgeError("schema-12 successor backup write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as error:
        raise BridgeError("schema-12 successor backup appeared concurrently") from error
    finally:
        temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _stable_profile_bytes(path: Path, *, uid: int) -> tuple[bytes, dict[str, object]]:
    before = _profile_identity(path, uid=uid)
    payload = path.read_bytes()
    after = _profile_identity(path, uid=uid)
    if before != after or _sha256_bytes(payload) != before["sha256"]:
        raise BridgeError("protected profile changed while it was captured")
    return payload, before


def _private_file_identity(path: Path, *, uid: int, label: str) -> dict[str, object]:
    info = _private_regular(path, uid=uid, label=label)
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": int(info.st_nlink),
        "sha256": _sha256_file(path),
    }


def _lock_file_identity(
    path: Path, *, uid: int, gid: int, mode: int, label: str
) -> dict[str, object]:
    path = _absolute(path, label)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
        or info.st_nlink != 1
        or path.resolve(strict=True) != path
    ):
        raise BridgeError(f"{label} has unsafe identity")
    return {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": int(info.st_nlink),
    }


def _capture_successor_profile(
    profile: Path, *, backup: Path, uid: int
) -> dict[str, object]:
    payload, identity = _stable_profile_bytes(profile, uid=uid)
    _write_private_bytes_once(backup, payload, uid=uid)
    return {
        "before_identity": identity,
        "backup": str(backup),
        "backup_sha256": _sha256_bytes(payload),
        "owner_binding": None,
        "owner_binding_sha256": None,
        "repaired_payload_sha256": None,
        "after_identity": None,
        "restored_identity": None,
    }


def _legacy_profile_repository_reference(
    path: Path,
    *,
    client_uid: int,
    repository_id: str,
    repository_generation: int,
    canonical_root: Path,
    database_generation: str,
    broker_socket: Path,
    uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    identity_before = _profile_identity(path, uid=uid)
    try:
        document = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError("legacy protected profile is invalid JSON") from error
    identity_after = _profile_identity(path, uid=uid)
    if identity_after != identity_before:
        raise BridgeError("legacy protected profile changed while it was read")
    service = document.get("service") if isinstance(document, dict) else None
    clients = document.get("clients") if isinstance(document, dict) else None
    client = clients.get(str(client_uid)) if isinstance(clients, dict) else None
    repositories = client.get("repositories") if isinstance(client, dict) else None
    matching = (
        [
            item
            for item in repositories
            if isinstance(item, dict)
            and item.get("repo_id") == repository_id
            and item.get("canonical_root") == str(canonical_root)
            and item.get("generation") == repository_generation
        ]
        if isinstance(repositories, list)
        else []
    )
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "service", "clients"}
        or document.get("version") != 1
        or not isinstance(service, dict)
        or service.get("socket") != str(broker_socket)
        or service.get("uid") != 0
        or service.get("database_generation") != database_generation
        or not isinstance(client, dict)
        or len(matching) != 1
        or "owner_uid" in matching[0]
    ):
        raise BridgeError("legacy profile is not the exact schema-12 client contract")
    return identity_before, {
        "client_uid": client_uid,
        "account_id": str(client.get("account_id") or ""),
        "repository_id": repository_id,
        "canonical_root": str(canonical_root),
        "generation": repository_generation,
        "owner_uid_present": False,
    }


_LIFECYCLE_REARM_FIELDS = {
    "outer_operation_id",
    "outer_transaction_journal",
    "outer_transaction_document_sha256",
    "bridge_operation_id",
    "bridge_journal",
    "bridge_journal_sha256",
    "bridge_document_sha256",
    "release",
    "release_digest",
    "database",
    "profile",
    "broker_socket",
    "dropin",
    "dropin_sha256",
    "staged_dropin",
    "staged_identity",
    "phase",
    "dropin_identity",
    "activation_invocation_id",
    "created_at_epoch",
    "updated_at_epoch",
}


def _verify_lifecycle_rearm_journal(value: object) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=LIFECYCLE_REARM_JOURNAL_KIND,
        fields=_LIFECYCLE_REARM_FIELDS,
    )
    try:
        document["outer_operation_id"] = str(
            uuid.UUID(str(document["outer_operation_id"]))
        )
        document["bridge_operation_id"] = str(
            uuid.UUID(str(document["bridge_operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("lifecycle predecessor rearm identities are invalid") from error
    for field in (
        "outer_transaction_journal",
        "bridge_journal",
        "release",
        "database",
        "profile",
        "broker_socket",
        "dropin",
        "staged_dropin",
    ):
        document[field] = str(
            _absolute(Path(str(document[field])), f"lifecycle rearm {field}")
        )
    if (
        document["outer_operation_id"] == document["bridge_operation_id"]
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in (
                "outer_transaction_document_sha256",
                "bridge_journal_sha256",
                "bridge_document_sha256",
                "release_digest",
                "dropin_sha256",
            )
        )
        or document["phase"] not in {"planned", "prepared", "published", "ready"}
        or isinstance(document["created_at_epoch"], bool)
        or not isinstance(document["created_at_epoch"], int)
        or isinstance(document["updated_at_epoch"], bool)
        or not isinstance(document["updated_at_epoch"], int)
        or document["created_at_epoch"] < 0
        or document["updated_at_epoch"] < document["created_at_epoch"]
    ):
        raise BridgeError("lifecycle predecessor rearm journal is invalid")
    if document["phase"] == "planned":
        if (
            document["staged_identity"] is not None
            or document["dropin_identity"] is not None
            or document["activation_invocation_id"] is not None
        ):
            raise BridgeError("planned lifecycle rearm has publication evidence")
    elif document["phase"] == "prepared":
        if (
            not isinstance(document["staged_identity"], dict)
            or document["dropin_identity"] is not None
            or document["activation_invocation_id"] is not None
        ):
            raise BridgeError("prepared lifecycle rearm has terminal evidence")
    elif (
        not isinstance(document["staged_identity"], dict)
        or not isinstance(document["dropin_identity"], dict)
    ):
        raise BridgeError("published lifecycle rearm omitted drop-in identity")
    if document["phase"] == "ready":
        if (
            not isinstance(document["activation_invocation_id"], str)
            or not document["activation_invocation_id"]
        ):
            raise BridgeError("ready lifecycle rearm omitted its invocation")
    elif document["activation_invocation_id"] is not None:
        raise BridgeError("non-ready lifecycle rearm has an invocation")
    return document


def _write_lifecycle_rearm_journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _verify_lifecycle_rearm_journal(
        _seal(LIFECYCLE_REARM_JOURNAL_KIND, payload)
    )
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_lifecycle_rearm_journal(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_lifecycle_rearm_journal(
        _read_private_json(
            path, uid=uid, label="lifecycle predecessor rearm journal"
        )
    )


def _lifecycle_rearm_reference(value: object) -> dict[str, object]:
    fields = {
        "journal",
        "journal_document_sha256",
        "outer_transaction_journal",
        "outer_transaction_document_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise BridgeError("lifecycle predecessor rearm reference is invalid")
    document = dict(value)
    for field in ("journal", "outer_transaction_journal"):
        document[field] = str(
            _absolute(Path(str(document[field])), f"lifecycle rearm {field}")
        )
    if any(
        RELEASE_RE.fullmatch(str(document[field])) is None
        for field in (
            "journal_document_sha256",
            "outer_transaction_document_sha256",
        )
    ):
        raise BridgeError("lifecycle predecessor rearm reference digest is invalid")
    return document


def _verified_lifecycle_rearm_lineage(
    value: object, *, expected_uid: int
) -> tuple[
    dict[str, object], dict[str, object], dict[str, object]
]:
    reference = _lifecycle_rearm_reference(value)
    journal_path = Path(str(reference["journal"]))
    payload, identity, journal_value = _stable_private_json_bytes(
        journal_path,
        uid=expected_uid,
        label="lifecycle predecessor rearm journal",
    )
    journal = _verify_lifecycle_rearm_journal(journal_value)
    if (
        journal.get("phase") != "ready"
        or journal.get("document_sha256")
        != reference["journal_document_sha256"]
        or journal.get("outer_transaction_journal")
        != reference["outer_transaction_journal"]
        or journal.get("outer_transaction_document_sha256")
        != reference["outer_transaction_document_sha256"]
        or identity.get("uid") != expected_uid
        or identity.get("mode") != 0o600
        or identity.get("nlink") != 1
    ):
        raise BridgeError("lifecycle predecessor rearm reference changed")
    outer_path = Path(str(reference["outer_transaction_journal"]))
    outer_payload, outer_identity, outer_value = _stable_private_json_bytes(
        outer_path,
        uid=expected_uid,
        label="lifecycle predecessor outer transaction journal",
    )
    if (
        outer_value.get("document_sha256")
        != reference["outer_transaction_document_sha256"]
        or RELEASE_RE.fullmatch(
            str(outer_value.get("document_sha256"))
        )
        is None
        or _digest_document(outer_value)
        != outer_value.get("document_sha256")
        or not isinstance(outer_value.get("schema_version"), int)
        or not isinstance(outer_value.get("kind"), str)
        or outer_identity.get("uid") != expected_uid
        or outer_identity.get("mode") != 0o600
        or outer_identity.get("nlink") != 1
    ):
        raise BridgeError(
            "lifecycle predecessor outer transaction reference changed"
        )
    evidence = {
        "rearm_journal": {
            "path": str(journal_path),
            "raw_sha256": _sha256_bytes(payload),
            "document_sha256": journal["document_sha256"],
            "identity": identity,
        },
        "outer_transaction": {
            "path": str(outer_path),
            "raw_sha256": _sha256_bytes(outer_payload),
            "document_sha256": outer_value["document_sha256"],
            "identity": outer_identity,
        },
    }
    return reference, journal, evidence


def _verified_lifecycle_rearm_binding(
    value: object, *, expected_uid: int
) -> tuple[dict[str, object], dict[str, object]]:
    reference, journal, _lineage = _verified_lifecycle_rearm_lineage(
        value, expected_uid=expected_uid
    )
    _verify_dropin_identity(
        Path(str(journal["dropin"])),
        journal["dropin_identity"],
        uid=expected_uid,
        expected_sha256=str(journal["dropin_sha256"]),
    )
    return reference, journal


def _verify_retained_lifecycle_rearm_descriptor_lineage(
    value: object,
    retained: object,
    *,
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(retained, dict) or set(retained) != {
        "rearm_journal",
        "outer_transaction",
    }:
        raise BridgeError("retained lifecycle rearm descriptor lineage is invalid")
    reference, journal, evidence = _verified_lifecycle_rearm_lineage(
        value, expected_uid=expected_uid
    )
    if evidence != retained:
        raise BridgeError("retained lifecycle rearm descriptor lineage changed")
    return reference, journal


def _verify_lifecycle_rearm_reference(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    reference, _journal = _verified_lifecycle_rearm_binding(
        value, expected_uid=expected_uid
    )
    return reference


def _dropin_identity_core(value: Mapping[str, object]) -> dict[str, object]:
    return {
        field: value[field]
        for field in (
            "device",
            "inode",
            "size",
            "uid",
            "gid",
            "mode",
            "nlink",
            "sha256",
        )
    }


def _preflight_lifecycle_predecessor(
    *,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    historical_client_release: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    expected_uid: int,
    _allow_rearmed_dropin: bool = False,
) -> dict[str, object]:
    """Fail closed before repair unless the predecessor is ready or rearmable."""

    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    _private_regular(
        journal_path, uid=expected_uid, label="lifecycle predecessor journal"
    )
    if _sha256_file(journal_path) != expected_journal_sha256:
        raise BridgeError("lifecycle predecessor journal raw digest changed")
    bridge = _load_bridge_journal(journal_path, uid=expected_uid)
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    declared = {
        "user": account.pw_name,
        "uid": account.pw_uid,
        "project": str(canary_project),
    }
    if (
        account.pw_uid != expected_canary_uid
        or bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("document_sha256")
        != expected_journal_document_sha256
        or bridge.get("phase") not in {"ready", "restored"}
        or bridge.get("broker_socket") != str(broker_socket)
        or bridge.get("dropin") != str(dropin)
        or declared not in bridge.get("canaries", [])
    ):
        raise BridgeError("lifecycle predecessor state is not recoverable")
    release = _absolute(Path(str(bridge["release"])), "predecessor broker release")
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    historical_client_release = _absolute(
        historical_client_release, "clean historical client release"
    )
    historical_manifest = _verify_activation_release(
        historical_client_release,
        release_root=historical_client_release.parent,
        owner_uid=expected_uid,
    )
    hardened_payload_sha256 = _sha256_bytes(
        _dropin_payload(release, database, broker_socket)
    )
    bridge_payload_sha256 = (
        hardened_payload_sha256
        if bridge["phase"] == "ready"
        else _sha256_bytes(
            _historical_restored_dropin_payload(
                release, database, broker_socket
            )
        )
    )
    if (
        historical_client_release == release
        or manifest.get("release_digest") != bridge.get("release_digest")
        or historical_manifest.get("release_digest")
        != manifest.get("release_digest")
        or bridge.get("dropin_sha256") != bridge_payload_sha256
    ):
        raise BridgeError("lifecycle predecessor release binding changed")
    readiness_value = bridge.get("readiness")
    origin_value = bridge.get("readiness_origin")
    if not isinstance(readiness_value, dict) or not isinstance(origin_value, dict):
        raise BridgeError("lifecycle predecessor omitted readiness lineage")
    readiness = _verify_retained_readiness_reference(
        Path(str(readiness_value.get("path"))), readiness_value, uid=expected_uid
    )
    origin = _readiness_origin_from_attestation(
        Path(str(origin_value.get("path"))), origin_value, uid=expected_uid
    )
    if readiness.get("database_generation") != expected_database_generation:
        raise BridgeError("lifecycle predecessor readiness generation changed")
    _validate_readiness_descendant(
        origin,
        current_identity=readiness.get("database_identity", {}),
        snapshot=readiness.get("snapshot"),
    )
    _legacy_profile_repository_reference(
        profile,
        client_uid=expected_canary_uid,
        repository_id=canary_repository_id,
        repository_generation=canary_repository_generation,
        canonical_root=canary_project,
        database_generation=expected_database_generation,
        broker_socket=broker_socket,
        uid=expected_uid,
    )
    if bridge["phase"] == "ready":
        _verify_dropin_identity(
            dropin,
            bridge.get("dropin_identity"),
            uid=expected_uid,
            expected_sha256=bridge_payload_sha256,
        )
        mode = "ready"
    else:
        if (
            (dropin.exists() or dropin.is_symlink())
            and not _allow_rearmed_dropin
        ):
            raise BridgeError("restored lifecycle predecessor drop-in reappeared")
        mode = "restored"
    return {
        "mode": mode,
        "bridge_journal": str(journal_path),
        "bridge_release": str(release),
        "bridge_release_digest": str(manifest["release_digest"]),
        "bridge_dropin_sha256": bridge_payload_sha256,
        "dropin_sha256": hardened_payload_sha256,
    }


def _verify_successor_predecessor_proof(value: object) -> dict[str, object]:
    fields = {
        "operation_id",
        "bridge_journal",
        "bridge_journal_sha256",
        "bridge_document_sha256",
        "broker_release",
        "broker_release_digest",
        "historical_client_release",
        "historical_client_release_digest",
        "verified_unsealed_bytecode_cache",
        "verified_unsealed_bytecode_cache_sha256",
        "readiness_origin",
        "readiness_origin_sha256",
        "database",
        "database_generation",
        "profile",
        "profile_identity",
        "legacy_profile_repository",
        "broker_socket",
        "socket_identity",
        "socket_peer",
        "dropin",
        "dropin_identity",
        "systemd",
        "execution",
        "process",
        "canary",
        "verified_at_epoch",
    }
    if isinstance(value, dict) and "outer_rearm" in value:
        fields.add("outer_rearm")
    document = _verify_seal(
        value, kind=SUCCESSOR_PREDECESSOR_PROOF_KIND, fields=fields
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("successor predecessor proof operation is invalid") from error
    legacy = document["legacy_profile_repository"]
    readiness_origin = document["readiness_origin"]
    outer_rearm = document.get("outer_rearm")
    cache_evidence = document["verified_unsealed_bytecode_cache"]
    cache_valid = isinstance(cache_evidence, list) and len(cache_evidence) <= (
        MAX_PREDECESSOR_CACHE_FILES
    )
    cache_total = 0
    if cache_valid:
        seen_cache_paths: set[str] = set()
        for item in cache_evidence:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "source",
                "sha256",
                "size",
                "mode",
            }:
                cache_valid = False
                break
            path = PurePosixPath(str(item["path"]))
            source = PurePosixPath(str(item["source"]))
            size = item["size"]
            mode = str(item["mode"])
            if (
                path.is_absolute()
                or source.is_absolute()
                or ".." in path.parts
                or ".." in source.parts
                or path.parent.name != "__pycache__"
                or path.parts[: len(SOURCE_PREFIX.parts)] != SOURCE_PREFIX.parts
                or source.parts[: len(SOURCE_PREFIX.parts)] != SOURCE_PREFIX.parts
                or path.as_posix() in seen_cache_paths
                or RELEASE_RE.fullmatch(str(item["sha256"])) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 16
                or size > MAX_PREDECESSOR_CACHE_FILE_BYTES
                or re.fullmatch(r"0[0-7]{3}", mode) is None
                or int(mode, 8) & 0o022
            ):
                cache_valid = False
                break
            seen_cache_paths.add(path.as_posix())
            cache_total += size
            if cache_total > MAX_PREDECESSOR_CACHE_TOTAL_BYTES:
                cache_valid = False
                break
    if (
        operation_id != document["operation_id"]
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in (
                "bridge_journal_sha256",
                "bridge_document_sha256",
                "broker_release_digest",
                "historical_client_release_digest",
                "verified_unsealed_bytecode_cache_sha256",
                "readiness_origin_sha256",
            )
        )
        or document["historical_client_release_digest"]
        != document["broker_release_digest"]
        or not isinstance(document["verified_unsealed_bytecode_cache"], list)
        or not cache_valid
        or _sha256_bytes(
            _canonical(document["verified_unsealed_bytecode_cache"])
        )
        != document["verified_unsealed_bytecode_cache_sha256"]
        or not isinstance(readiness_origin, dict)
        or set(readiness_origin)
        != {
            "path",
            "document_sha256",
            "database_identity",
            "database_generation",
            "state_revision",
            "snapshot",
        }
        or _sha256_bytes(_canonical(readiness_origin))
        != document["readiness_origin_sha256"]
        or not isinstance(legacy, dict)
        or set(legacy)
        != {
            "client_uid",
            "account_id",
            "repository_id",
            "canonical_root",
            "generation",
            "owner_uid_present",
        }
        or legacy.get("owner_uid_present") is not False
        or not isinstance(document["systemd"], dict)
        or not isinstance(document["execution"], dict)
        or not isinstance(document["process"], dict)
        or not isinstance(document["canary"], dict)
        or (
            outer_rearm is not None
            and _lifecycle_rearm_reference(outer_rearm) != outer_rearm
        )
    ):
        raise BridgeError("successor predecessor proof binding is invalid")
    for field in (
        "bridge_journal",
        "broker_release",
        "historical_client_release",
        "database",
        "profile",
        "broker_socket",
        "dropin",
    ):
        document[field] = str(
            _absolute(Path(str(document[field])), f"successor predecessor {field}")
        )
    if document["historical_client_release"] == document["broker_release"]:
        raise BridgeError("successor predecessor clean client is not distinct")
    return document


def _verify_active_predecessor_for_successor(
    *,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    historical_client_release: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    wait_seconds: int,
    expected_uid: int,
    _allow_restored: bool = False,
    _expected_dropin_identity: object | None = None,
    _outer_rearm: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Prove the active historical bridge with its historical client parser."""

    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    journal_info_before = _private_regular(
        journal_path, uid=expected_uid, label="successor predecessor journal"
    )
    if _sha256_file(journal_path) != expected_journal_sha256:
        raise BridgeError("successor predecessor journal raw digest changed")
    bridge = _load_bridge_journal(journal_path, uid=expected_uid)
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    declared = {
        "user": account.pw_name,
        "uid": account.pw_uid,
        "project": str(canary_project),
    }
    if (
        account.pw_uid != expected_canary_uid
        or bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("document_sha256") != expected_journal_document_sha256
        or bridge.get("phase")
        != ("restored" if _allow_restored else "ready")
        or bridge.get("broker_socket") != str(broker_socket)
        or bridge.get("dropin") != str(dropin)
        or declared not in bridge.get("canaries", [])
    ):
        raise BridgeError("successor predecessor ready binding changed")
    release = _absolute(Path(str(bridge["release"])), "predecessor broker release")
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    historical_client_release = _absolute(
        historical_client_release, "clean historical client release"
    )
    historical_manifest = _verify_activation_release(
        historical_client_release,
        release_root=historical_client_release.parent,
        owner_uid=expected_uid,
    )
    if (
        historical_client_release == release
        or historical_manifest.get("release_digest")
        != manifest.get("release_digest")
    ):
        raise BridgeError(
            "clean historical client does not reproduce the predecessor release"
        )
    cache_evidence = manifest.get("verified_unsealed_bytecode_cache", [])
    cache_evidence_sha256 = manifest.get(
        "verified_unsealed_bytecode_cache_sha256",
        _sha256_bytes(_canonical([])),
    )
    if manifest.get("release_digest") != bridge.get("release_digest"):
        raise BridgeError("successor predecessor release binding changed")
    readiness_value = bridge.get("readiness")
    if not isinstance(readiness_value, dict):
        raise BridgeError("successor predecessor omitted readiness evidence")
    readiness_path = Path(str(readiness_value.get("path")))
    readiness = _verify_retained_readiness_reference(
        readiness_path, readiness_value, uid=expected_uid
    )
    if readiness.get("database_generation") != expected_database_generation:
        raise BridgeError("successor predecessor readiness generation changed")
    origin_value = bridge.get("readiness_origin")
    if not isinstance(origin_value, dict):
        raise BridgeError("successor predecessor omitted readiness lineage")
    readiness_origin = _readiness_origin_from_attestation(
        Path(str(origin_value.get("path"))),
        origin_value,
        uid=expected_uid,
    )
    _validate_readiness_descendant(
        readiness_origin,
        current_identity=readiness.get("database_identity", {}),
        snapshot=readiness.get("snapshot"),
    )
    if _allow_restored != (_outer_rearm is not None):
        raise BridgeError("restored predecessor proof lacks outer rearm authority")
    rearm_journal: dict[str, object] | None = None
    if _outer_rearm is not None:
        _rearm_reference, rearm_journal = _verified_lifecycle_rearm_binding(
            _outer_rearm, expected_uid=expected_uid
        )
        expected_rearm_binding = {
            "bridge_operation_id": operation_id,
            "bridge_journal": str(journal_path),
            "bridge_journal_sha256": expected_journal_sha256,
            "bridge_document_sha256": expected_journal_document_sha256,
            "release": str(release),
            "release_digest": str(manifest["release_digest"]),
            "database": str(database),
            "profile": str(profile),
            "broker_socket": str(broker_socket),
            "dropin": str(dropin),
            "dropin_sha256": _sha256_bytes(
                _dropin_payload(release, database, broker_socket)
            ),
        }
        if any(
            rearm_journal.get(field) != expected
            for field, expected in expected_rearm_binding.items()
        ):
            raise BridgeError("restored predecessor outer rearm binding changed")
        if (
            _expected_dropin_identity is not None
            and rearm_journal.get("dropin_identity")
            != _expected_dropin_identity
        ):
            raise BridgeError("restored predecessor drop-in identity changed")
    expected_dropin_identity = (
        rearm_journal["dropin_identity"]
        if rearm_journal is not None
        else bridge.get("dropin_identity")
    )
    expected_dropin_sha256 = (
        str(rearm_journal["dropin_sha256"])
        if rearm_journal is not None
        else str(bridge["dropin_sha256"])
    )
    dropin_identity = _verify_dropin_identity(
        dropin,
        expected_dropin_identity,
        uid=expected_uid,
        expected_sha256=expected_dropin_sha256,
    )
    profile_identity, legacy_repository = _legacy_profile_repository_reference(
        profile,
        client_uid=expected_canary_uid,
        repository_id=canary_repository_id,
        repository_generation=canary_repository_generation,
        canonical_root=canary_project,
        database_generation=expected_database_generation,
        broker_socket=broker_socket,
        uid=expected_uid,
    )
    state_before = _wait_active(broker_socket, wait_seconds)
    socket_before = _socket_identity(broker_socket)
    execution_before = _verify_loaded_bridge_execution(
        release=release, database=database, broker_socket=broker_socket, dropin=dropin
    )
    process_before = _broker_process_identity(
        main_pid=int(state_before["MainPID"]),
        expected_argv=list(execution_before["argv"]),
        expected_uid=0,
    )
    peer_before = _broker_socket_peer(broker_socket)
    canary = _inventory_canary(
        release=historical_client_release,
        account=account,
        project=canary_project,
        profile=profile,
        expected_database_generation=expected_database_generation,
        expected_repository_id=canary_repository_id,
        canary_repository_generation=canary_repository_generation,
        expected_broker_socket=broker_socket,
        expected_service_uid=0,
        _cutover_maintenance_inventory_read=True,
        _historical_release_digest=str(
            historical_manifest["release_digest"]
        ),
    )
    state_after = _wait_active(broker_socket, wait_seconds)
    socket_after = _socket_identity(broker_socket)
    execution_after = _verify_loaded_bridge_execution(
        release=release, database=database, broker_socket=broker_socket, dropin=dropin
    )
    process_after = _broker_process_identity(
        main_pid=int(state_after["MainPID"]),
        expected_argv=list(execution_after["argv"]),
        expected_uid=0,
    )
    peer_after = _broker_socket_peer(broker_socket)
    profile_after, legacy_after = _legacy_profile_repository_reference(
        profile,
        client_uid=expected_canary_uid,
        repository_id=canary_repository_id,
        repository_generation=canary_repository_generation,
        canonical_root=canary_project,
        database_generation=expected_database_generation,
        broker_socket=broker_socket,
        uid=expected_uid,
    )
    journal_info_after = _private_regular(
        journal_path, uid=expected_uid, label="successor predecessor journal"
    )
    if (
        state_after.get("InvocationID") != state_before.get("InvocationID")
        or state_after.get("MainPID") != state_before.get("MainPID")
        or socket_after != socket_before
        or execution_after != execution_before
        or process_after != process_before
        or peer_after != peer_before
        or peer_after.get("pid") != state_after.get("MainPID")
        or peer_after.get("uid") != 0
        or profile_after != profile_identity
        or legacy_after != legacy_repository
        or _sha256_file(journal_path) != expected_journal_sha256
        or any(
            getattr(journal_info_after, field) != getattr(journal_info_before, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
            )
        )
    ):
        raise BridgeError("successor predecessor changed during live proof")
    proof_payload = {
        "operation_id": operation_id,
        "bridge_journal": str(journal_path),
        "bridge_journal_sha256": expected_journal_sha256,
        "bridge_document_sha256": expected_journal_document_sha256,
        "broker_release": str(release),
        "broker_release_digest": manifest["release_digest"],
        "historical_client_release": str(historical_client_release),
        "historical_client_release_digest": historical_manifest[
            "release_digest"
        ],
        "verified_unsealed_bytecode_cache": cache_evidence,
        "verified_unsealed_bytecode_cache_sha256": cache_evidence_sha256,
        "readiness_origin": readiness_origin,
        "readiness_origin_sha256": _sha256_bytes(_canonical(readiness_origin)),
        "database": str(database),
        "database_generation": expected_database_generation,
        "profile": str(profile),
        "profile_identity": profile_identity,
        "legacy_profile_repository": legacy_repository,
        "broker_socket": str(broker_socket),
        "socket_identity": socket_after,
        "socket_peer": peer_after,
        "dropin": str(dropin),
        "dropin_identity": dropin_identity,
        "systemd": state_after,
        "execution": execution_after,
        "process": process_after,
        "canary": canary,
        "verified_at_epoch": int(time.time()),
    }
    if _outer_rearm is not None:
        proof_payload["outer_rearm"] = _lifecycle_rearm_reference(
            dict(_outer_rearm)
        )
    return _verify_successor_predecessor_proof(
        _seal(
            SUCCESSOR_PREDECESSOR_PROOF_KIND,
            proof_payload,
        )
    )


def _rearm_restored_predecessor_for_lifecycle(
    *,
    outer_operation_id: str,
    outer_transaction_journal: Path,
    outer_transaction_document_sha256: str,
    rearm_journal: Path,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    historical_client_release: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    wait_seconds: int,
    expected_uid: int,
    terminal_bound: bool = False,
) -> dict[str, object]:
    """Re-arm one exact restored predecessor without rewriting its journal."""

    try:
        outer_operation_id = str(uuid.UUID(outer_operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("lifecycle rearm outer operation is invalid") from error
    if not 1 <= wait_seconds <= 120:
        raise BridgeError("lifecycle rearm wait must be from 1 through 120 seconds")
    outer_transaction_journal = _absolute(
        outer_transaction_journal, "lifecycle service transaction journal"
    )
    outer_info_before = _private_regular(
        outer_transaction_journal,
        uid=expected_uid,
        label="lifecycle service transaction journal",
    )
    outer_document = _read_private_json(
        outer_transaction_journal,
        uid=expected_uid,
        label="lifecycle service transaction journal",
    )
    if (
        outer_document.get("operation_id") != outer_operation_id
        or outer_document.get("document_sha256")
        != outer_transaction_document_sha256
    ):
        raise BridgeError("lifecycle service transaction binding changed")
    rearm_journal = _absolute(
        rearm_journal, "lifecycle predecessor rearm journal"
    )
    if (
        rearm_journal.parent != outer_transaction_journal.parent
        or rearm_journal.name != LIFECYCLE_REARM_JOURNAL_NAME
    ):
        raise BridgeError("lifecycle predecessor rearm journal path is invalid")
    context = _preflight_lifecycle_predecessor(
        transaction=transaction,
        operation_id=operation_id,
        expected_journal_sha256=expected_journal_sha256,
        expected_journal_document_sha256=expected_journal_document_sha256,
        historical_client_release=historical_client_release,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_database_generation=expected_database_generation,
        canary_user=canary_user,
        expected_canary_uid=expected_canary_uid,
        canary_project=canary_project,
        canary_repository_id=canary_repository_id,
        canary_repository_generation=canary_repository_generation,
        expected_uid=expected_uid,
        _allow_rearmed_dropin=(rearm_journal.exists() or rearm_journal.is_symlink()),
    )
    if context.get("mode") != "restored":
        raise BridgeError("lifecycle predecessor is not in restored state")
    transaction = _private_directory(transaction, uid=expected_uid)
    bridge_journal = transaction / JOURNAL_NAME
    release = Path(str(context["bridge_release"]))
    payload = _dropin_payload(release, database, broker_socket)
    payload_sha256 = str(context["dropin_sha256"])
    staged_dropin = dropin.parent / (
        f".{dropin.name}.{outer_operation_id}.lifecycle-rearm"
    )
    static = {
        "outer_operation_id": outer_operation_id,
        "outer_transaction_journal": str(outer_transaction_journal),
        "outer_transaction_document_sha256": outer_transaction_document_sha256,
        "bridge_operation_id": operation_id,
        "bridge_journal": str(bridge_journal),
        "bridge_journal_sha256": expected_journal_sha256,
        "bridge_document_sha256": expected_journal_document_sha256,
        "release": str(release),
        "release_digest": str(context["bridge_release_digest"]),
        "database": str(database),
        "profile": str(profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "dropin_sha256": payload_sha256,
        "staged_dropin": str(staged_dropin),
    }
    with _installer_lock(expected_uid):
        current = _load_lifecycle_rearm_journal(
            rearm_journal, uid=expected_uid
        )
        if current is None:
            if (
                staged_dropin.exists()
                or staged_dropin.is_symlink()
                or dropin.exists()
                or dropin.is_symlink()
            ):
                raise BridgeError(
                    "lifecycle rearm files exist without transaction evidence"
                )
            now = int(time.time())
            current = _write_lifecycle_rearm_journal(
                rearm_journal,
                {
                    **static,
                    "staged_identity": None,
                    "phase": "planned",
                    "dropin_identity": None,
                    "activation_invocation_id": None,
                    "created_at_epoch": now,
                    "updated_at_epoch": now,
                },
                uid=expected_uid,
            )
        elif any(current.get(field) != value for field, value in static.items()):
            raise BridgeError("lifecycle predecessor rearm belongs to another operation")

        if current["phase"] == "planned":
            if dropin.exists() or dropin.is_symlink():
                raise BridgeError("lifecycle rearm drop-in appeared before staging")
            if staged_dropin.exists() or staged_dropin.is_symlink():
                staged_identity = _dropin_identity(
                    staged_dropin,
                    uid=expected_uid,
                    expected_sha256=payload_sha256,
                )
            else:
                _write_dropin(staged_dropin, payload, uid=expected_uid)
                staged_identity = _dropin_identity(
                    staged_dropin,
                    uid=expected_uid,
                    expected_sha256=payload_sha256,
                )
            current = _write_lifecycle_rearm_journal(
                rearm_journal,
                {
                    **{
                        key: value
                        for key, value in current.items()
                        if key not in {"schema_version", "kind", "document_sha256"}
                    },
                    "staged_identity": staged_identity,
                    "phase": "prepared",
                    "updated_at_epoch": int(time.time()),
                },
                uid=expected_uid,
            )

        if current["phase"] == "prepared":
            staged_identity = current["staged_identity"]
            if staged_dropin.exists() or staged_dropin.is_symlink():
                _verify_dropin_identity(
                    staged_dropin,
                    staged_identity,
                    uid=expected_uid,
                    expected_sha256=payload_sha256,
                )
                if dropin.exists() or dropin.is_symlink():
                    raise BridgeError("lifecycle rearm has two published drop-ins")
                os.replace(staged_dropin, dropin)
                directory = os.open(
                    dropin.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            elif not (dropin.exists() or dropin.is_symlink()):
                raise BridgeError("lifecycle staged drop-in disappeared")
            dropin_identity = _dropin_identity(
                dropin, uid=expected_uid, expected_sha256=payload_sha256
            )
            if _dropin_identity_core(dropin_identity) != _dropin_identity_core(
                staged_identity
            ):
                raise BridgeError("lifecycle staged drop-in identity changed")
            current = _write_lifecycle_rearm_journal(
                rearm_journal,
                {
                    **{
                        key: value
                        for key, value in current.items()
                        if key not in {"schema_version", "kind", "document_sha256"}
                    },
                    "phase": "published",
                    "dropin_identity": dropin_identity,
                    "updated_at_epoch": int(time.time()),
                },
                uid=expected_uid,
            )

        dropin_identity = _verify_dropin_identity(
            dropin,
            current["dropin_identity"],
            uid=expected_uid,
            expected_sha256=payload_sha256,
        )
        state = _systemd_state()
        if terminal_bound and (
            current["phase"] != "ready"
            or not _service_process_alive(state)
            or current.get("activation_invocation_id")
            != state.get("InvocationID")
        ):
            raise BridgeError(
                "terminal lifecycle rearm invocation changed"
            )
        if not _service_process_alive(state):
            _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
            _run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=30)
            state = _wait_active(broker_socket, wait_seconds)
        else:
            state = _wait_active(broker_socket, wait_seconds)
        if (
            current["phase"] != "ready"
            or current.get("activation_invocation_id") != state.get("InvocationID")
        ):
            current = _write_lifecycle_rearm_journal(
                rearm_journal,
                {
                    **{
                        key: value
                        for key, value in current.items()
                        if key not in {"schema_version", "kind", "document_sha256"}
                    },
                    "phase": "ready",
                    "dropin_identity": dropin_identity,
                    "activation_invocation_id": state["InvocationID"],
                    "updated_at_epoch": int(time.time()),
                },
                uid=expected_uid,
            )
        outer_rearm = _lifecycle_rearm_reference(
            {
                "journal": str(rearm_journal),
                "journal_document_sha256": current["document_sha256"],
                "outer_transaction_journal": str(outer_transaction_journal),
                "outer_transaction_document_sha256": (
                    outer_transaction_document_sha256
                ),
            }
        )
        proof = _verify_active_predecessor_for_successor(
            transaction=transaction,
            operation_id=operation_id,
            expected_journal_sha256=expected_journal_sha256,
            expected_journal_document_sha256=(
                expected_journal_document_sha256
            ),
            historical_client_release=historical_client_release,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_database_generation=expected_database_generation,
            canary_user=canary_user,
            expected_canary_uid=expected_canary_uid,
            canary_project=canary_project,
            canary_repository_id=canary_repository_id,
            canary_repository_generation=canary_repository_generation,
            wait_seconds=wait_seconds,
            expected_uid=expected_uid,
            _allow_restored=True,
            _expected_dropin_identity=dropin_identity,
            _outer_rearm=outer_rearm,
        )
        outer_info_after = _private_regular(
            outer_transaction_journal,
            uid=expected_uid,
            label="lifecycle service transaction journal",
        )
        if any(
            getattr(outer_info_after, field) != getattr(outer_info_before, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
            )
        ):
            raise BridgeError("lifecycle service transaction changed during rearm")
        return proof


def _successor_predecessor_reference(
    *,
    transaction: Path,
    operation_id: str,
    journal_sha256: str,
    document_sha256: str,
    ready_proof: Mapping[str, object],
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    retired_dropin_boundary: Mapping[str, object] | None = None,
    verify_retired_absence: bool = True,
) -> dict[str, object]:
    proof = _verify_successor_predecessor_proof(ready_proof)
    outer_rearm = proof.get("outer_rearm")
    rearm_journal: dict[str, object] | None = None
    if outer_rearm is not None:
        if retired_dropin_boundary is None:
            _rearm_reference, rearm_journal = (
                _verified_lifecycle_rearm_binding(
                    outer_rearm, expected_uid=expected_uid
                )
            )
        else:
            _rearm_reference, rearm_journal, _rearm_lineage = (
                _verified_lifecycle_rearm_lineage(
                    outer_rearm, expected_uid=expected_uid
                )
            )
    transaction = _private_directory(transaction, uid=expected_uid)
    journal = transaction / JOURNAL_NAME
    _private_regular(journal, uid=expected_uid, label="successor predecessor journal")
    if _sha256_file(journal) != journal_sha256:
        raise BridgeError("successor predecessor journal raw digest changed")
    bridge = _load_bridge_journal(journal, uid=expected_uid)
    if (
        bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("document_sha256") != document_sha256
        or bridge.get("phase")
        != ("restored" if outer_rearm is not None else "ready")
        or proof.get("bridge_journal") != str(journal)
        or proof.get("bridge_journal_sha256") != journal_sha256
        or proof.get("bridge_document_sha256") != document_sha256
        or proof.get("broker_socket") != str(broker_socket)
        or proof.get("dropin") != str(dropin)
    ):
        raise BridgeError("successor predecessor ready binding changed")
    release = _absolute(
        Path(str(proof["broker_release"])), "successor predecessor release"
    )
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    cache_evidence = manifest.get("verified_unsealed_bytecode_cache", [])
    cache_evidence_sha256 = manifest.get(
        "verified_unsealed_bytecode_cache_sha256",
        _sha256_bytes(_canonical([])),
    )
    if (
        manifest.get("release_digest") != proof.get("broker_release_digest")
        or bridge.get("release_digest") != proof.get("broker_release_digest")
        or cache_evidence
        != proof.get("verified_unsealed_bytecode_cache")
        or cache_evidence_sha256
        != proof.get("verified_unsealed_bytecode_cache_sha256")
    ):
        raise BridgeError("successor predecessor release changed")
    active_dropin_identity = proof.get("dropin_identity")
    active_dropin_sha256 = (
        active_dropin_identity.get("sha256")
        if isinstance(active_dropin_identity, dict)
        else None
    )
    expected_active_identity = (
        rearm_journal.get("dropin_identity")
        if rearm_journal is not None
        else bridge.get("dropin_identity")
    )
    expected_active_sha256 = (
        rearm_journal.get("dropin_sha256")
        if rearm_journal is not None
        else bridge.get("dropin_sha256")
    )
    if (
        RELEASE_RE.fullmatch(str(active_dropin_sha256)) is None
        or active_dropin_identity != expected_active_identity
        or active_dropin_sha256 != expected_active_sha256
    ):
        raise BridgeError("successor predecessor active drop-in binding changed")
    if retired_dropin_boundary is not None:
        boundary_path = str(
            _absolute(
                Path(str(retired_dropin_boundary.get("path"))),
                "successor predecessor retired drop-in",
            )
        )
        if (
            retired_dropin_boundary.get("state") != "absent"
            or boundary_path != str(dropin)
            or retired_dropin_boundary.get("bound_identity")
            != active_dropin_identity
            or retired_dropin_boundary.get("bound_sha256")
            != active_dropin_sha256
        ):
            raise BridgeError(
                "successor predecessor retired drop-in boundary changed"
            )
        if verify_retired_absence:
            if (
                _verify_successor_client_handoff_dropin_boundary(
                    retired_dropin_boundary,
                    dropin=dropin,
                    expected_uid=expected_uid,
                    allow_bound_removal=False,
                )
                != "absent"
            ):
                raise BridgeError(
                    "successor predecessor retired drop-in boundary changed"
                )
            _verify_managed_path_absent(dropin, expected_uid=expected_uid)
    origin_value = bridge.get("readiness_origin")
    if not isinstance(origin_value, dict):
        raise BridgeError("successor predecessor omitted readiness lineage")
    readiness_origin = _readiness_origin_from_attestation(
        Path(str(origin_value.get("path"))),
        origin_value,
        uid=expected_uid,
    )
    readiness_origin_sha256 = _sha256_bytes(_canonical(readiness_origin))
    if (
        proof.get("readiness_origin") != readiness_origin
        or proof.get("readiness_origin_sha256") != readiness_origin_sha256
    ):
        raise BridgeError("successor predecessor readiness lineage changed")
    return {
        "transaction": str(transaction),
        "operation_id": operation_id,
        "journal": str(journal),
        "journal_sha256": journal_sha256,
        "document_sha256": document_sha256,
        "release": str(release),
        "release_digest": proof["broker_release_digest"],
        "dropin_sha256": active_dropin_sha256,
        "dropin_identity": active_dropin_identity,
        "readiness_origin": readiness_origin,
        "readiness_origin_sha256": readiness_origin_sha256,
        "ready_proof": dict(proof),
    }


def _repair_inherited_successor_predecessor_sha_replay(
    current: Mapping[str, object],
    *,
    journal_path: Path,
    expected_uid: int,
) -> dict[str, object]:
    """Repair one historical successor-journal producer defect, fail closed.

    An inherited lifecycle handoff may have recorded the restored bridge
    journal's removed drop-in digest in ``predecessor.dropin_sha256`` while its
    exact proof and identity correctly described the rearmed active drop-in.
    Repair is safe only before that active drop-in is retired and only when a
    freshly regenerated predecessor differs in that one scalar field.
    """

    if current.get("phase") not in _SUCCESSOR_PREDECESSOR_SHA_REPAIR_PHASES:
        return dict(current)
    binding = current.get("binding")
    predecessor_value = current.get("predecessor")
    if not isinstance(binding, Mapping) or not isinstance(
        predecessor_value, Mapping
    ):
        return dict(current)
    maintenance_handoff = binding.get("maintenance_handoff")
    ready_proof_value = predecessor_value.get("ready_proof")
    if not isinstance(maintenance_handoff, Mapping) or not isinstance(
        ready_proof_value, Mapping
    ):
        return dict(current)
    handoff_proof_value = maintenance_handoff.get("predecessor_proof")
    if not isinstance(handoff_proof_value, Mapping):
        return dict(current)
    outer_rearm_value = ready_proof_value.get("outer_rearm")
    if (
        outer_rearm_value is None
        or handoff_proof_value.get("outer_rearm") != outer_rearm_value
    ):
        return dict(current)
    ready_proof = _verify_successor_predecessor_proof(ready_proof_value)
    handoff_proof = _verify_successor_predecessor_proof(handoff_proof_value)
    outer_rearm = ready_proof.get("outer_rearm")
    if (
        handoff_proof.get("outer_rearm") != outer_rearm
        or _proof_stable_binding(ready_proof)
        != _proof_stable_binding(handoff_proof)
    ):
        return dict(current)
    regenerated = _successor_predecessor_reference(
        transaction=Path(str(predecessor_value.get("transaction"))),
        operation_id=str(predecessor_value.get("operation_id")),
        journal_sha256=str(predecessor_value.get("journal_sha256")),
        document_sha256=str(predecessor_value.get("document_sha256")),
        ready_proof=ready_proof,
        broker_socket=Path(str(ready_proof["broker_socket"])),
        dropin=Path(str(ready_proof["dropin"])),
        expected_uid=expected_uid,
    )
    predecessor = dict(predecessor_value)
    if predecessor == regenerated:
        return dict(current)
    repaired_predecessor = dict(predecessor)
    repaired_predecessor["dropin_sha256"] = regenerated.get("dropin_sha256")
    if repaired_predecessor != regenerated:
        return dict(current)

    stale_sha256 = predecessor.get("dropin_sha256")
    active_sha256 = regenerated.get("dropin_sha256")
    active_identity = ready_proof.get("dropin_identity")
    if (
        RELEASE_RE.fullmatch(str(stale_sha256)) is None
        or RELEASE_RE.fullmatch(str(active_sha256)) is None
        or stale_sha256 == active_sha256
        or not isinstance(active_identity, dict)
        or active_identity.get("sha256") != active_sha256
        or regenerated.get("dropin_identity") != active_identity
    ):
        raise BridgeError(
            "schema-12 successor predecessor replay SHA identity changed"
        )

    bridge = _load_bridge_journal(
        Path(str(regenerated["journal"])), uid=expected_uid
    )
    if (
        bridge is None
        or bridge.get("phase") != "restored"
        or bridge.get("dropin_sha256") != stale_sha256
    ):
        raise BridgeError(
            "schema-12 successor predecessor replay SHA lineage changed"
        )
    _rearm_reference, rearm_journal = _verified_lifecycle_rearm_binding(
        outer_rearm, expected_uid=expected_uid
    )
    if (
        rearm_journal.get("dropin_sha256") != active_sha256
        or rearm_journal.get("dropin_identity") != active_identity
    ):
        raise BridgeError(
            "schema-12 successor predecessor replay rearm binding changed"
        )
    _verify_dropin_identity(
        Path(str(ready_proof["dropin"])),
        active_identity,
        uid=expected_uid,
        expected_sha256=str(active_sha256),
    )

    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["predecessor"] = regenerated
    payload["updated_at_epoch"] = int(time.time())
    return _successor_journal(journal_path, payload, uid=expected_uid)


def _successor_binding_without_client_handoff(
    value: Mapping[str, object],
) -> dict[str, object]:
    binding = dict(value)
    binding.pop("client_release", None)
    binding.pop("client_release_digest", None)
    binding.pop("client_release_handoffs", None)
    binding.pop("executor_rescue", None)
    binding.pop("executor_rescue_handoff", None)
    binding.pop("executor_rescue_post_export_continuation", None)
    return binding


def _stable_private_json_bytes(
    path: Path, *, uid: int, label: str
) -> tuple[bytes, dict[str, object], dict[str, object]]:
    path = _absolute(path, label)
    before = _private_regular(path, uid=uid, label=label)
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
        )
        if any(
            getattr(opened, field) != getattr(before, field)
            for field in identity_fields
        ):
            raise BridgeError(f"{label} changed before it was opened")
        payload = bytearray()
        while len(payload) <= MAX_JSON_BYTES:
            block = os.read(
                descriptor,
                min(65536, MAX_JSON_BYTES + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if any(
            getattr(after, field) != getattr(opened, field)
            for field in identity_fields
        ):
            raise BridgeError(f"{label} changed while it was captured")
    finally:
        os.close(descriptor)
    path_after = path.lstat()
    if (
        len(payload) <= 0
        or len(payload) > MAX_JSON_BYTES
        or len(payload) != opened.st_size
        or any(
            getattr(path_after, field) != getattr(opened, field)
            for field in identity_fields
        )
    ):
        raise BridgeError(f"{label} changed while it was captured")
    payload_bytes = bytes(payload)
    identity = {
        "device": int(opened.st_dev),
        "inode": int(opened.st_ino),
        "size": int(opened.st_size),
        "mtime_ns": int(opened.st_mtime_ns),
        "ctime_ns": int(opened.st_ctime_ns),
        "uid": int(opened.st_uid),
        "gid": int(opened.st_gid),
        "mode": stat.S_IMODE(opened.st_mode),
        "nlink": int(opened.st_nlink),
        "sha256": _sha256_bytes(payload_bytes),
    }
    try:
        document = json.loads(payload_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError(f"{label} is not valid JSON") from error
    if not isinstance(document, dict):
        raise BridgeError(f"{label} must contain a JSON object")
    return payload_bytes, identity, document


def _successor_profile_backup_reference(
    profile_state: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    path = _absolute(
        Path(str(profile_state.get("backup"))),
        "schema-12 successor profile backup",
    )
    expected_sha256 = str(profile_state.get("backup_sha256"))
    if RELEASE_RE.fullmatch(expected_sha256) is None:
        raise BridgeError(
            "schema-12 successor profile backup binding is invalid"
        )
    try:
        before = _private_file_identity(
            path,
            uid=expected_uid,
            label="schema-12 successor profile backup",
        )
        after = _private_file_identity(
            path,
            uid=expected_uid,
            label="schema-12 successor profile backup",
        )
    except (BridgeError, OSError) as error:
        raise BridgeError(
            f"schema-12 successor profile backup is unavailable: {error}"
        ) from error
    if (
        before != after
        or before.get("sha256") != expected_sha256
    ):
        raise BridgeError(
            "schema-12 successor profile backup identity or content changed"
        )
    return {
        "path": str(path),
        "sha256": expected_sha256,
        "identity": before,
    }


def _verify_successor_profile_backup_reference(
    value: object,
    *,
    profile_state: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    current = _successor_profile_backup_reference(
        profile_state, expected_uid=expected_uid
    )
    if not isinstance(value, Mapping) or dict(value) != current:
        raise BridgeError(
            "schema-12 successor profile backup evidence changed"
        )
    return current


def _successor_readiness_attestation_reference(
    path: Path, *, expected_uid: int
) -> dict[str, object]:
    path = _absolute(
        path, "schema-12 successor readiness attestation"
    )
    try:
        before_payload, before_identity, before_value = (
            _stable_private_json_bytes(
                path,
                uid=expected_uid,
                label="schema-12 successor readiness attestation",
            )
        )
        cutover = _load_cutover_module()
        document = cutover._authority_readiness_result(before_value)
        after_payload, after_identity, after_value = (
            _stable_private_json_bytes(
                path,
                uid=expected_uid,
                label="schema-12 successor readiness attestation",
            )
        )
    except (BridgeError, OSError, Exception) as error:
        raise BridgeError(
            f"schema-12 successor readiness attestation is invalid: {error}"
        ) from error
    document_sha256 = (
        document.get("document_sha256")
        if isinstance(document, Mapping)
        else None
    )
    if (
        before_payload != after_payload
        or before_identity != after_identity
        or before_value != after_value
        or RELEASE_RE.fullmatch(str(document_sha256)) is None
    ):
        raise BridgeError(
            "schema-12 successor readiness attestation changed while verified"
        )
    return {
        "path": str(path),
        "raw_sha256": before_identity["sha256"],
        "document_sha256": document_sha256,
        "identity": before_identity,
    }


def _verify_successor_readiness_attestation_reference(
    value: object,
    *,
    path: Path,
    expected_uid: int,
) -> dict[str, object]:
    current = _successor_readiness_attestation_reference(
        path, expected_uid=expected_uid
    )
    if not isinstance(value, Mapping) or dict(value) != current:
        raise BridgeError(
            "schema-12 successor readiness attestation evidence changed"
        )
    return current


def _validated_successor_client_handoff(
    value: object,
    *,
    expected_uid: int,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _SUCCESSOR_CLIENT_HANDOFF_FIELDS:
        raise BridgeError("schema-12 successor client handoff fields are invalid")
    try:
        operation_id = str(uuid.UUID(str(value["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 successor client handoff operation is invalid"
        ) from error
    digest_fields = (
        "journal_raw_sha256",
        "journal_document_sha256",
        "previous_binding_sha256",
        "successor_binding_sha256",
        "stable_binding_sha256",
        "previous_client_release_digest",
        "successor_client_release_digest",
        "intent_raw_sha256",
        "intent_document_sha256",
    )
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    profile_identity = value["profile_identity"]
    journal_identity = value["journal_identity"]
    backup_identity = value["journal_backup_identity"]
    intent_identity = value["intent_identity"]
    database_bundle = value["database_bundle"]
    database_readiness = value["database_readiness"]
    broker_state = value["broker_state"]
    predecessor_dropin = value["predecessor_dropin"]
    profile_backup = value["profile_backup"]
    readiness_attestation = value["readiness_attestation"]
    if (
        operation_id != value["operation_id"]
        or value["phase"]
        not in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
        or any(
            RELEASE_RE.fullmatch(str(value[field])) is None
            for field in digest_fields
        )
        or isinstance(value["recorded_at_epoch"], bool)
        or not isinstance(value["recorded_at_epoch"], int)
        or int(value["recorded_at_epoch"]) <= 0
        or not isinstance(journal_identity, dict)
        or set(journal_identity) != identity_fields
        or not isinstance(backup_identity, dict)
        or set(backup_identity) != identity_fields
        or not isinstance(intent_identity, dict)
        or set(intent_identity) != identity_fields
        or journal_identity.get("sha256") != value["journal_raw_sha256"]
        or backup_identity.get("sha256") != value["journal_raw_sha256"]
        or intent_identity.get("sha256") != value["intent_raw_sha256"]
        or journal_identity.get("uid") != expected_uid
        or backup_identity.get("uid") != expected_uid
        or intent_identity.get("uid") != expected_uid
        or journal_identity.get("mode") != 0o600
        or backup_identity.get("mode") != 0o600
        or intent_identity.get("mode") != 0o600
        or not isinstance(profile_identity, dict)
        or set(profile_identity) != identity_fields
        or RELEASE_RE.fullmatch(str(profile_identity.get("sha256"))) is None
        or not isinstance(profile_backup, dict)
        or set(profile_backup) != {"path", "sha256", "identity"}
        or RELEASE_RE.fullmatch(str(profile_backup.get("sha256"))) is None
        or not isinstance(profile_backup.get("identity"), dict)
        or set(profile_backup["identity"]) != identity_fields
        or profile_backup["identity"].get("sha256")
        != profile_backup["sha256"]
        or profile_backup["identity"].get("uid") != expected_uid
        or isinstance(profile_backup["identity"].get("mode"), bool)
        or not isinstance(profile_backup["identity"].get("mode"), int)
        or profile_backup["identity"]["mode"] & 0o077
        or profile_backup["identity"].get("nlink") != 1
        or not isinstance(readiness_attestation, dict)
        or set(readiness_attestation)
        != {"path", "raw_sha256", "document_sha256", "identity"}
        or RELEASE_RE.fullmatch(
            str(readiness_attestation.get("raw_sha256"))
        )
        is None
        or RELEASE_RE.fullmatch(
            str(readiness_attestation.get("document_sha256"))
        )
        is None
        or not isinstance(readiness_attestation.get("identity"), dict)
        or set(readiness_attestation["identity"]) != identity_fields
        or readiness_attestation["identity"].get("sha256")
        != readiness_attestation["raw_sha256"]
        or readiness_attestation["identity"].get("uid") != expected_uid
        or isinstance(
            readiness_attestation["identity"].get("mode"), bool
        )
        or not isinstance(
            readiness_attestation["identity"].get("mode"), int
        )
        or readiness_attestation["identity"]["mode"] & 0o077
        or readiness_attestation["identity"].get("nlink") != 1
        or not isinstance(database_bundle, dict)
        or set(database_bundle) != {"main", "sidecars"}
        or not isinstance(database_bundle.get("main"), dict)
        or not isinstance(database_bundle.get("sidecars"), dict)
        or set(database_bundle["sidecars"]) != {"-wal", "-shm"}
        or RELEASE_RE.fullmatch(
            str(database_bundle["main"].get("sha256"))
        )
        is None
        or not isinstance(database_readiness, dict)
        or set(database_readiness)
        != {
            "database_identity",
            "database_generation",
            "state_revision",
            "snapshot_sha256",
        }
        or not isinstance(database_readiness.get("database_identity"), dict)
        or not isinstance(database_readiness.get("database_generation"), str)
        or not database_readiness["database_generation"]
        or isinstance(database_readiness.get("state_revision"), bool)
        or not isinstance(database_readiness.get("state_revision"), int)
        or int(database_readiness["state_revision"]) < 0
        or RELEASE_RE.fullmatch(
            str(database_readiness.get("snapshot_sha256"))
        )
        is None
        or not isinstance(broker_state, dict)
        or broker_state.get("ActiveState") != "inactive"
        or broker_state.get("SubState") != "dead"
        or broker_state.get("MainPID") != 0
        or not isinstance(predecessor_dropin, dict)
        or set(predecessor_dropin)
        != {"state", "path", "bound_identity", "bound_sha256"}
        or predecessor_dropin.get("state") not in {"present", "absent"}
        or not isinstance(predecessor_dropin.get("bound_identity"), dict)
        or set(predecessor_dropin["bound_identity"]) != identity_fields
        or RELEASE_RE.fullmatch(
            str(predecessor_dropin.get("bound_sha256"))
        )
        is None
        or predecessor_dropin["bound_identity"].get("sha256")
        != predecessor_dropin["bound_sha256"]
        or value["phase"] == "predecessor-retired"
        and predecessor_dropin.get("state") != "absent"
    ):
        raise BridgeError("schema-12 successor client handoff binding is invalid")
    for field in (
        "journal_backup",
        "intent",
        "previous_client_release",
        "successor_client_release",
    ):
        value[field] = str(
            _absolute(
                Path(str(value[field])),
                f"schema-12 successor client handoff {field}",
            )
        )
    predecessor_dropin["path"] = str(
        _absolute(
            Path(str(predecessor_dropin["path"])),
            "schema-12 successor client handoff predecessor drop-in",
        )
    )
    profile_backup["path"] = str(
        _absolute(
            Path(str(profile_backup["path"])),
            "schema-12 successor client handoff profile backup",
        )
    )
    readiness_attestation["path"] = str(
        _absolute(
            Path(str(readiness_attestation["path"])),
            "schema-12 successor client handoff readiness attestation",
        )
    )
    return dict(value)


def _verify_successor_client_handoff_intent(
    value: object,
) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_CLIENT_HANDOFF_INTENT_KIND,
        fields=set(_SUCCESSOR_CLIENT_HANDOFF_INTENT_FIELDS),
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 successor client handoff intent operation is invalid"
        ) from error
    if (
        operation_id != document["operation_id"]
        or document["phase"]
        not in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
        or isinstance(document["recorded_at_epoch"], bool)
        or not isinstance(document["recorded_at_epoch"], int)
        or int(document["recorded_at_epoch"]) <= 0
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in (
                "journal_raw_sha256",
                "journal_document_sha256",
                "previous_binding_sha256",
                "successor_binding_sha256",
                "stable_binding_sha256",
                "previous_client_release_digest",
                "successor_client_release_digest",
            )
        )
        or not isinstance(document["journal_identity"], dict)
        or not isinstance(document["profile_identity"], dict)
        or not isinstance(document["profile_backup"], dict)
        or not isinstance(document["readiness_attestation"], dict)
        or not isinstance(document["database_bundle"], dict)
        or not isinstance(document["database_readiness"], dict)
        or not isinstance(document["broker_state"], dict)
        or not isinstance(document["predecessor_dropin"], dict)
        or document["phase"] == "predecessor-retired"
        and document["predecessor_dropin"].get("state") != "absent"
    ):
        raise BridgeError(
            "schema-12 successor client handoff intent binding is invalid"
        )
    for field in (
        "journal_backup",
        "previous_client_release",
        "successor_client_release",
    ):
        document[field] = str(
            _absolute(
                Path(str(document[field])),
                f"schema-12 successor client handoff intent {field}",
            )
        )
    document["profile_backup"]["path"] = str(
        _absolute(
            Path(str(document["profile_backup"].get("path"))),
            "schema-12 successor client handoff intent profile backup",
        )
    )
    document["readiness_attestation"]["path"] = str(
        _absolute(
            Path(str(document["readiness_attestation"].get("path"))),
            "schema-12 successor client handoff intent readiness attestation",
        )
    )
    return document


def _load_successor_client_handoff_intent(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_successor_client_handoff_intent(
        _read_private_json(
            path,
            uid=uid,
            label="schema-12 successor client handoff intent",
        )
    )


def _verify_successor_client_handoff_dropin_boundary(
    value: object,
    *,
    dropin: Path,
    expected_uid: int,
    allow_bound_removal: bool,
) -> str:
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {"state", "path", "bound_identity", "bound_sha256"}
        or value.get("state") not in {"present", "absent"}
        or not isinstance(value.get("bound_identity"), dict)
        or set(value["bound_identity"]) != identity_fields
        or RELEASE_RE.fullmatch(str(value.get("bound_sha256"))) is None
        or value["bound_identity"].get("sha256")
        != value["bound_sha256"]
        or str(_absolute(Path(str(value.get("path"))), "handoff drop-in"))
        != str(dropin)
    ):
        raise BridgeError(
            "schema-12 successor client handoff drop-in binding is invalid"
        )
    if dropin.exists() or dropin.is_symlink():
        if value["state"] == "absent":
            raise BridgeError(
                "schema-12 successor client handoff drop-in reappeared "
                "after absent boundary"
            )
        _verify_dropin_identity(
            dropin,
            value["bound_identity"],
            uid=expected_uid,
            expected_sha256=str(value["bound_sha256"]),
        )
        return "present"
    if value["state"] == "absent" or allow_bound_removal:
        return "absent"
    raise BridgeError(
        "schema-12 successor client handoff bound drop-in disappeared"
    )


def _verify_managed_path_absent(
    path: Path, *, expected_uid: int
) -> dict[str, object]:
    """Prove ENOENT through a stable, non-symlink parent directory descriptor."""

    path = _absolute(path, "retired predecessor drop-in")
    parent = path.parent
    descriptor = os.open(
        parent,
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != expected_uid
            or not stat.S_ISDIR(before.st_mode)
            or before.st_nlink < 1
        ):
            raise BridgeError(
                "retired predecessor drop-in parent identity is invalid"
            )
        try:
            os.stat(
                path.name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise BridgeError("retired predecessor drop-in reappeared")
        after = os.fstat(descriptor)
        if any(
            getattr(after, field) != getattr(before, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
            )
        ):
            raise BridgeError(
                "retired predecessor drop-in parent changed while verified"
            )
        return {
            "state": "absent",
            "path": str(path),
            "parent": str(parent),
            "parent_identity": {
                "device": int(after.st_dev),
                "inode": int(after.st_ino),
                "uid": int(after.st_uid),
                "gid": int(after.st_gid),
                "mode": stat.S_IMODE(after.st_mode),
                "nlink": int(after.st_nlink),
            },
        }
    finally:
        os.close(descriptor)


def _verify_successor_client_handoff_live_state(
    current: Mapping[str, object],
    *,
    terminal_path: Path,
    completion_path: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    _allow_retired_sidecar_timestamp_drift: bool = False,
) -> None:
    binding = current.get("binding")
    if not isinstance(binding, Mapping):
        raise BridgeError("schema-12 successor client handoff lacks its binding")
    handoffs = binding.get("client_release_handoffs")
    if not isinstance(handoffs, list) or len(handoffs) != 1:
        raise BridgeError("schema-12 successor client handoff lineage is invalid")
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    candidate_journal = (
        Path(str(binding.get("candidate_transaction"))) / JOURNAL_NAME
    )
    _ensure_successor_maintenance(
        binding.get("maintenance"), uid=expected_uid
    )
    _verify_successor_client_handoff_dropin_boundary(
        handoff["predecessor_dropin"],
        dropin=dropin,
        expected_uid=expected_uid,
        allow_bound_removal=True,
    )
    profile_state = current.get("profile")
    if not isinstance(profile_state, Mapping):
        raise BridgeError(
            "schema-12 successor client handoff profile binding is invalid"
        )
    _verify_successor_profile_backup_reference(
        handoff["profile_backup"],
        profile_state=profile_state,
        expected_uid=expected_uid,
    )
    _verify_successor_readiness_attestation_reference(
        handoff["readiness_attestation"],
        path=Path(str(binding.get("readiness_attestation"))),
        expected_uid=expected_uid,
    )
    live_database_bundle = _sqlite_bundle_evidence(
        database, expected_uid=expected_uid
    )
    if _allow_retired_sidecar_timestamp_drift:
        if (
            current.get("phase") != "predecessor-retired"
            or handoff["phase"] != "predecessor-retired"
        ):
            raise BridgeError(
                "schema-12 retired sidecar timestamp tolerance is outside "
                "the executor rescue boundary"
            )
        database_bundle_matches = (
            _retired_rescue_sqlite_bundle_view(live_database_bundle)
            == _retired_rescue_sqlite_bundle_view(
                handoff["database_bundle"]
            )
        )
    else:
        database_bundle_matches = (
            live_database_bundle == handoff["database_bundle"]
        )
    if (
        current.get("phase") != handoff["phase"]
        or current.get("candidate")
        != {"activation": None, "readiness": None}
        or terminal_path.exists()
        or terminal_path.is_symlink()
        or completion_path.exists()
        or completion_path.is_symlink()
        or candidate_journal.exists()
        or candidate_journal.is_symlink()
        or _profile_identity(profile, uid=expected_uid)
        != handoff["profile_identity"]
        or not database_bundle_matches
        or _systemd_state() != handoff["broker_state"]
        or broker_socket.exists()
        or broker_socket.is_symlink()
    ):
        raise BridgeError(
            "schema-12 successor client handoff live state changed"
        )


def _verify_retained_successor_client_handoff(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    _allow_retired_sidecar_timestamp_drift: bool = False,
) -> dict[str, object]:
    current_binding_value = current.get("binding")
    if not isinstance(current_binding_value, Mapping):
        raise BridgeError("schema-12 successor client handoff lacks its binding")
    current_binding = dict(current_binding_value)
    _ensure_successor_maintenance(
        current_binding.get("maintenance"), uid=expected_uid
    )
    handoffs = current_binding.get("client_release_handoffs")
    if not isinstance(handoffs, list) or len(handoffs) != 1:
        raise BridgeError("schema-12 successor client handoff lineage is invalid")
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    if (
        handoff["operation_id"] != current.get("operation_id")
        or handoff["intent"] != str(intent_path)
        or handoff["journal_backup"] != str(journal_backup_path)
    ):
        raise BridgeError("schema-12 successor client handoff lineage changed")
    _intent_payload, intent_identity, intent_value = (
        _stable_private_json_bytes(
            intent_path,
            uid=expected_uid,
            label="schema-12 successor client handoff intent",
        )
    )
    intent = _verify_successor_client_handoff_intent(intent_value)
    if (
        intent_identity != handoff["intent_identity"]
        or intent_identity["sha256"] != handoff["intent_raw_sha256"]
        or intent["document_sha256"] != handoff["intent_document_sha256"]
        or any(
            intent[field] != handoff[field]
            for field in _SUCCESSOR_CLIENT_HANDOFF_INTENT_FIELDS
        )
    ):
        raise BridgeError("schema-12 successor client handoff intent changed")
    _backup_payload, backup_identity, backup_value = (
        _stable_private_json_bytes(
            journal_backup_path,
            uid=expected_uid,
            label="schema-12 successor client handoff journal backup",
        )
    )
    backup = _verify_successor_journal(backup_value)
    if backup is None:
        raise BridgeError("schema-12 successor client handoff backup is absent")
    backup_binding_value = backup.get("binding")
    backup_profile_value = backup.get("profile")
    current_profile_value = current.get("profile")
    if (
        not isinstance(backup_binding_value, Mapping)
        or not isinstance(backup_profile_value, Mapping)
        or not isinstance(current_profile_value, Mapping)
    ):
        raise BridgeError("schema-12 successor client handoff backup is invalid")
    backup_binding = dict(backup_binding_value)
    immutable_profile_fields = {
        "before_identity",
        "backup",
        "backup_sha256",
        "owner_binding",
        "owner_binding_sha256",
    }
    if (
        backup_identity != handoff["journal_backup_identity"]
        or backup_identity["sha256"] != handoff["journal_raw_sha256"]
        or backup.get("document_sha256") != handoff["journal_document_sha256"]
        or backup.get("operation_id") != handoff["operation_id"]
        or backup.get("phase") != handoff["phase"]
        or any(
            current_profile_value.get(field)
            != backup_profile_value.get(field)
            for field in immutable_profile_fields
        )
        or current.get("restored_predecessor")
        != backup.get("restored_predecessor")
        or current.get("error") != backup.get("error")
        or current.get("created_at_epoch") != backup.get("created_at_epoch")
        or "client_release_handoffs" in backup_binding
        or _sha256_bytes(_canonical(backup_binding))
        != handoff["previous_binding_sha256"]
        or _sha256_bytes(
            _canonical(
                _successor_binding_without_client_handoff(backup_binding)
            )
        )
        != handoff["stable_binding_sha256"]
        or backup_binding.get("client_release")
        != handoff["previous_client_release"]
        or backup_binding.get("client_release_digest")
        != handoff["previous_client_release_digest"]
        or backup_profile_value.get("before_identity")
        != handoff["profile_identity"]
        or backup_profile_value.get("backup")
        != handoff["profile_backup"]["path"]
        or backup_profile_value.get("backup_sha256")
        != handoff["profile_backup"]["sha256"]
        or backup_binding.get("readiness_attestation")
        != handoff["readiness_attestation"]["path"]
        or current_binding.get("readiness_attestation")
        != handoff["readiness_attestation"]["path"]
    ):
        raise BridgeError("schema-12 successor client handoff backup changed")
    _verify_successor_profile_backup_reference(
        handoff["profile_backup"],
        profile_state=current_profile_value,
        expected_uid=expected_uid,
    )
    _verify_successor_readiness_attestation_reference(
        handoff["readiness_attestation"],
        path=Path(str(current_binding["readiness_attestation"])),
        expected_uid=expected_uid,
    )
    if (
        "client_release_handoffs" in requested_binding
        or _successor_binding_without_client_handoff(backup_binding)
        != _successor_binding_without_client_handoff(requested_binding)
    ):
        raise BridgeError("schema-12 successor static binding changed")
    successor_binding = dict(backup_binding)
    successor_binding["client_release"] = handoff["successor_client_release"]
    successor_binding["client_release_digest"] = handoff[
        "successor_client_release_digest"
    ]
    successor_binding["client_release_handoffs"] = [handoff]
    current_client_binding = dict(current_binding)
    current_client_binding.pop("executor_rescue", None)
    current_client_binding.pop("executor_rescue_handoff", None)
    current_client_binding.pop(
        "executor_rescue_post_export_continuation", None
    )
    if (
        current_client_binding != successor_binding
        or requested_binding.get("client_release")
        != handoff["successor_client_release"]
        or requested_binding.get("client_release_digest")
        != handoff["successor_client_release_digest"]
        or _sha256_bytes(_canonical(dict(requested_binding)))
        != handoff["successor_binding_sha256"]
    ):
        raise BridgeError("schema-12 successor client handoff target changed")
    historical_manifest = _verify_historical_availability_release(
        Path(str(handoff["previous_client_release"])),
        owner_uid=expected_uid,
    )
    if (
        historical_manifest.get("release_digest")
        != handoff["previous_client_release_digest"]
    ):
        raise BridgeError(
            "schema-12 successor client handoff producer changed"
        )
    if (inherited_journal_sha256 is None) != (
        inherited_document_sha256 is None
    ):
        raise BridgeError(
            "schema-12 successor client handoff requires both inherited digests"
        )
    if inherited_journal_sha256 is not None and (
        inherited_journal_sha256 != handoff["journal_raw_sha256"]
        or inherited_document_sha256 != handoff["journal_document_sha256"]
    ):
        raise BridgeError(
            "schema-12 successor client handoff inherited digest changed"
        )
    if current.get("phase") == handoff["phase"]:
        _verify_successor_client_handoff_live_state(
            current,
            terminal_path=terminal_path,
            completion_path=completion_path,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
            _allow_retired_sidecar_timestamp_drift=(
                _allow_retired_sidecar_timestamp_drift
            ),
        )
    return dict(current)


def _successor_client_handoff_precondition(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    terminal_path: Path,
    completion_path: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    _stable_retired_sidecar_timestamps: bool = False,
) -> dict[str, object]:
    binding_value = current.get("binding")
    predecessor_value = current.get("predecessor")
    profile_value = current.get("profile")
    if (
        current.get("phase")
        not in _SUCCESSOR_CLIENT_HANDOFF_PUBLICATION_PHASES
        or current.get("candidate") != {"activation": None, "readiness": None}
        or not isinstance(binding_value, Mapping)
        or not isinstance(predecessor_value, Mapping)
        or not isinstance(profile_value, Mapping)
        or profile_value.get("repaired_payload_sha256") is not None
        or profile_value.get("after_identity") is not None
        or profile_value.get("restored_identity") is not None
        or "export_evidence" in profile_value
        or terminal_path.exists()
        or terminal_path.is_symlink()
        or completion_path.exists()
        or completion_path.is_symlink()
    ):
        raise BridgeError(
            "schema-12 successor client handoff is not at its exact safe phase"
        )
    binding = dict(binding_value)
    maintenance = binding.get("maintenance")
    candidate_transaction = Path(str(binding.get("candidate_transaction")))
    candidate_journal = candidate_transaction / JOURNAL_NAME
    if (
        not isinstance(maintenance, Mapping)
        or candidate_journal.exists()
        or candidate_journal.is_symlink()
    ):
        raise BridgeError(
            "schema-12 successor client handoff candidate state changed"
        )
    _ensure_successor_maintenance(maintenance, uid=expected_uid)
    ready_proof_value = predecessor_value.get("ready_proof")
    if not isinstance(ready_proof_value, Mapping):
        raise BridgeError(
            "schema-12 successor client handoff predecessor proof is absent"
        )
    ready_proof = _verify_successor_predecessor_proof(ready_proof_value)
    bound_dropin_identity = ready_proof.get("dropin_identity")
    bound_dropin_sha256 = (
        bound_dropin_identity.get("sha256")
        if isinstance(bound_dropin_identity, dict)
        else None
    )
    if (
        ready_proof.get("database") != str(database)
        or ready_proof.get("database_generation")
        != requested_binding.get("expected_database_generation")
        or ready_proof.get("profile") != str(profile)
        or ready_proof.get("broker_socket") != str(broker_socket)
        or ready_proof.get("dropin") != str(dropin)
        or predecessor_value.get("dropin_identity")
        != bound_dropin_identity
        or RELEASE_RE.fullmatch(str(bound_dropin_sha256)) is None
    ):
        raise BridgeError(
            "schema-12 successor client handoff predecessor binding changed"
        )
    profile_identity = _profile_identity(profile, uid=expected_uid)
    profile_backup = _successor_profile_backup_reference(
        profile_value, expected_uid=expected_uid
    )
    if profile_identity != profile_value.get("before_identity"):
        raise BridgeError(
            "schema-12 successor client handoff profile changed"
        )
    broker_state = _systemd_state()
    if (
        current.get("phase") == "predecessor-retired"
        and (dropin.exists() or dropin.is_symlink())
    ):
        raise BridgeError(
            "schema-12 successor predecessor-retired client handoff "
            "requires an absent drop-in"
        )
    predecessor_dropin = {
        "state": (
            "present"
            if dropin.exists() or dropin.is_symlink()
            else "absent"
        ),
        "path": str(dropin),
        "bound_identity": bound_dropin_identity,
        "bound_sha256": bound_dropin_sha256,
    }
    _verify_successor_client_handoff_dropin_boundary(
        predecessor_dropin,
        dropin=dropin,
        expected_uid=expected_uid,
        allow_bound_removal=False,
    )
    if (
        broker_state.get("ActiveState") != "inactive"
        or broker_state.get("SubState") != "dead"
        or broker_state.get("MainPID") != 0
        or broker_socket.exists()
        or broker_socket.is_symlink()
    ):
        raise BridgeError(
            "schema-12 successor client handoff predecessor is not retired"
        )
    origin = ready_proof.get("readiness_origin")
    if not isinstance(origin, Mapping):
        raise BridgeError(
            "schema-12 successor client handoff readiness lineage is absent"
        )
    readiness_path = Path(
        str(requested_binding["readiness_attestation"])
    )
    readiness_attestation = (
        _successor_readiness_attestation_reference(
            readiness_path, expected_uid=expected_uid
        )
    )
    readiness = _readiness_proof(
        readiness_path,
        database=database,
        uid=expected_uid,
        descendant_of=origin,
    )
    if (
        _successor_readiness_attestation_reference(
            readiness_path, expected_uid=expected_uid
        )
        != readiness_attestation
        or readiness.get("document_sha256")
        != readiness_attestation["document_sha256"]
    ):
        raise BridgeError(
            "schema-12 successor readiness attestation changed during "
            "database proof"
        )
    if (
        readiness.get("database_generation")
        != requested_binding.get("expected_database_generation")
        or not isinstance(readiness.get("database_identity"), dict)
        or not isinstance(readiness.get("state_revision"), int)
        or not isinstance(readiness.get("snapshot"), dict)
    ):
        raise BridgeError(
            "schema-12 successor client handoff database changed"
        )
    database_bundle = _sqlite_bundle_evidence(
        database, expected_uid=expected_uid
    )
    if _stable_retired_sidecar_timestamps:
        if current.get("phase") != "predecessor-retired":
            raise BridgeError(
                "schema-12 stable sidecar evidence is outside the executor "
                "rescue boundary"
            )
        database_bundle = _retired_rescue_sqlite_bundle_view(
            database_bundle
        )
    return {
        "profile_identity": profile_identity,
        "profile_backup": profile_backup,
        "readiness_attestation": readiness_attestation,
        "database_bundle": database_bundle,
        "database_readiness": {
            "database_identity": readiness["database_identity"],
            "database_generation": readiness["database_generation"],
            "state_revision": readiness["state_revision"],
            "snapshot_sha256": _sha256_bytes(
                _canonical(readiness["snapshot"])
            ),
        },
        "broker_state": broker_state,
        "predecessor_dropin": predecessor_dropin,
    }


def _migrate_inherited_successor_client_release(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    journal_path: Path,
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    failpoint: Callable[[str], None],
    _allow_retired_sidecar_timestamp_drift: bool = False,
) -> dict[str, object]:
    """Hand one trapped forward-only journal to one fixed immutable client.

    This is deliberately not a general binding migration.  The old sealed
    journal is retained byte-for-byte, all non-client fields remain exact, and
    only the incident's exact drop-in-removal boundary or its immediate
    pre-export retired successor can publish one lineage entry.
    """

    current_binding_value = current.get("binding")
    if not isinstance(current_binding_value, Mapping):
        raise BridgeError("schema-12 successor journal lacks its static binding")
    current_binding = dict(current_binding_value)
    if "client_release_handoffs" in current_binding:
        return _verify_retained_successor_client_handoff(
            current,
            requested_binding=requested_binding,
            intent_path=intent_path,
            journal_backup_path=journal_backup_path,
            terminal_path=terminal_path,
            completion_path=completion_path,
            inherited_journal_sha256=inherited_journal_sha256,
            inherited_document_sha256=inherited_document_sha256,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
            _allow_retired_sidecar_timestamp_drift=(
                _allow_retired_sidecar_timestamp_drift
            ),
        )
    if current_binding == requested_binding:
        if (
            inherited_journal_sha256 is not None
            or inherited_document_sha256 is not None
        ):
            raise BridgeError(
                "schema-12 successor client handoff was requested without a "
                "client-release change"
            )
        return dict(current)
    if (
        _successor_binding_without_client_handoff(current_binding)
        != _successor_binding_without_client_handoff(requested_binding)
        or current_binding.get("client_release")
        == requested_binding.get("client_release")
        or current_binding.get("client_release_digest")
        == requested_binding.get("client_release_digest")
    ):
        raise BridgeError("schema-12 successor static binding changed")
    if (
        inherited_journal_sha256 is None
        or inherited_document_sha256 is None
        or RELEASE_RE.fullmatch(inherited_journal_sha256) is None
        or RELEASE_RE.fullmatch(inherited_document_sha256) is None
    ):
        raise BridgeError(
            "schema-12 successor client handoff requires the exact inherited "
            "journal digests"
        )
    if (
        current.get("document_sha256") != inherited_document_sha256
    ):
        raise BridgeError(
            "schema-12 successor client handoff inherited journal changed"
        )
    source_payload, source_identity, source_value = (
        _stable_private_json_bytes(
            journal_path,
            uid=expected_uid,
            label="schema-12 successor inherited journal",
        )
    )
    source_document = _verify_successor_journal(source_value)
    if (
        source_document != current
        or source_identity["sha256"] != inherited_journal_sha256
    ):
        raise BridgeError(
            "schema-12 successor client handoff inherited journal changed"
        )
    previous_release = _absolute(
        Path(str(current_binding.get("client_release"))),
        "inherited successor client release",
    )
    previous_digest = str(current_binding.get("client_release_digest"))
    successor_release = _absolute(
        Path(str(requested_binding.get("client_release"))),
        "replacement successor client release",
    )
    successor_digest = str(
        requested_binding.get("client_release_digest")
    )
    historical_manifest = _verify_historical_availability_release(
        previous_release, owner_uid=expected_uid
    )
    if (
        previous_release == successor_release
        or RELEASE_RE.fullmatch(previous_digest) is None
        or RELEASE_RE.fullmatch(successor_digest) is None
        or historical_manifest.get("release_digest") != previous_digest
    ):
        raise BridgeError(
            "schema-12 successor client handoff release lineage is invalid"
        )
    precondition = _successor_client_handoff_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    intent_binding = {
        "operation_id": current["operation_id"],
        "phase": current["phase"],
        "journal_backup": str(journal_backup_path),
        "journal_raw_sha256": inherited_journal_sha256,
        "journal_document_sha256": inherited_document_sha256,
        "journal_identity": source_identity,
        "previous_binding_sha256": _sha256_bytes(
            _canonical(current_binding)
        ),
        "successor_binding_sha256": _sha256_bytes(
            _canonical(dict(requested_binding))
        ),
        "stable_binding_sha256": _sha256_bytes(
            _canonical(
                _successor_binding_without_client_handoff(current_binding)
            )
        ),
        "previous_client_release": str(previous_release),
        "previous_client_release_digest": previous_digest,
        "successor_client_release": str(successor_release),
        "successor_client_release_digest": successor_digest,
        **precondition,
    }
    intent = _load_successor_client_handoff_intent(
        intent_path, uid=expected_uid
    )
    if intent is None:
        intent = _seal(
            SUCCESSOR_CLIENT_HANDOFF_INTENT_KIND,
            {
                **intent_binding,
                "recorded_at_epoch": int(time.time()),
            },
        )
        intent = _verify_successor_client_handoff_intent(intent)
        _atomic_private_json(intent_path, intent, uid=expected_uid)
    elif any(
        intent[field] != expected
        for field, expected in intent_binding.items()
    ):
        raise BridgeError(
            "schema-12 successor client handoff intent changed"
        )
    intent_payload, intent_identity, retained_intent_value = (
        _stable_private_json_bytes(
            intent_path,
            uid=expected_uid,
            label="schema-12 successor client handoff intent",
        )
    )
    retained_intent = _verify_successor_client_handoff_intent(
        retained_intent_value
    )
    if retained_intent != intent:
        raise BridgeError(
            "schema-12 successor client handoff intent changed"
        )
    failpoint("after-successor-client-release-handoff-intent")
    _write_private_bytes_once(
        journal_backup_path, source_payload, uid=expected_uid
    )
    backup_payload, backup_identity, backup_value = (
        _stable_private_json_bytes(
            journal_backup_path,
            uid=expected_uid,
            label="schema-12 successor client handoff journal backup",
        )
    )
    if (
        backup_payload != source_payload
        or _verify_successor_journal(backup_value) != current
    ):
        raise BridgeError(
            "schema-12 successor client handoff journal backup changed"
        )
    failpoint("after-successor-client-release-handoff-backup")
    (
        retained_source_payload,
        retained_source_identity,
        retained_source_value,
    ) = _stable_private_json_bytes(
        journal_path,
        uid=expected_uid,
        label="schema-12 successor inherited journal",
    )
    _verify_successor_client_handoff_dropin_boundary(
        precondition["predecessor_dropin"],
        dropin=dropin,
        expected_uid=expected_uid,
        allow_bound_removal=False,
    )
    _verify_successor_profile_backup_reference(
        precondition["profile_backup"],
        profile_state=current["profile"],
        expected_uid=expected_uid,
    )
    _verify_successor_readiness_attestation_reference(
        precondition["readiness_attestation"],
        path=Path(str(requested_binding["readiness_attestation"])),
        expected_uid=expected_uid,
    )
    if (
        retained_source_payload != source_payload
        or retained_source_identity != source_identity
        or _verify_successor_journal(retained_source_value) != current
        or _profile_identity(profile, uid=expected_uid)
        != precondition["profile_identity"]
        or _sqlite_bundle_evidence(database, expected_uid=expected_uid)
        != precondition["database_bundle"]
        or _systemd_state() != precondition["broker_state"]
        or broker_socket.exists()
        or broker_socket.is_symlink()
    ):
        raise BridgeError(
            "schema-12 successor client handoff state changed before publication"
        )
    _ensure_successor_maintenance(
        current_binding["maintenance"], uid=expected_uid
    )
    handoff = {
        **{
            field: intent[field]
            for field in _SUCCESSOR_CLIENT_HANDOFF_INTENT_FIELDS
        },
        "journal_backup_identity": backup_identity,
        "intent": str(intent_path),
        "intent_raw_sha256": _sha256_bytes(intent_payload),
        "intent_document_sha256": intent["document_sha256"],
        "intent_identity": intent_identity,
    }
    handoff = _validated_successor_client_handoff(
        handoff, expected_uid=expected_uid
    )
    successor_binding = dict(current_binding)
    successor_binding["client_release"] = str(successor_release)
    successor_binding["client_release_digest"] = successor_digest
    successor_binding["client_release_handoffs"] = [handoff]
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["binding"] = successor_binding
    payload["updated_at_epoch"] = int(time.time())
    migrated = _successor_journal(
        journal_path, payload, uid=expected_uid
    )
    failpoint("after-successor-client-release-handoff")
    return _verify_retained_successor_client_handoff(
        migrated,
        requested_binding=requested_binding,
        intent_path=intent_path,
        journal_backup_path=journal_backup_path,
        terminal_path=terminal_path,
        completion_path=completion_path,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
        _allow_retired_sidecar_timestamp_drift=(
            _allow_retired_sidecar_timestamp_drift
        ),
    )


def _successor_executor_rescue_first_handoff(
    current: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    binding = current.get("binding")
    if not isinstance(binding, Mapping):
        raise BridgeError("schema-12 executor rescue lacks its first handoff")
    handoffs = binding.get("client_release_handoffs")
    if not isinstance(handoffs, list) or len(handoffs) != 1:
        raise BridgeError("schema-12 executor rescue requires one first handoff")
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    return {
        "sha256": _sha256_bytes(_canonical(handoff)),
        "operation_id": handoff["operation_id"],
        "phase": handoff["phase"],
        "client_release": handoff["successor_client_release"],
        "client_release_digest": handoff[
            "successor_client_release_digest"
        ],
        "intent": handoff["intent"],
        "intent_raw_sha256": handoff["intent_raw_sha256"],
        "intent_document_sha256": handoff[
            "intent_document_sha256"
        ],
        "intent_identity": handoff["intent_identity"],
        "journal_backup": handoff["journal_backup"],
        "journal_backup_raw_sha256": handoff["journal_raw_sha256"],
        "journal_backup_document_sha256": handoff[
            "journal_document_sha256"
        ],
        "journal_backup_identity": handoff[
            "journal_backup_identity"
        ],
    }


def _successor_executor_rescue_source_profile(
    current: Mapping[str, object]
) -> dict[str, object]:
    binding = current.get("binding")
    profile = current.get("profile")
    if not isinstance(binding, Mapping) or not isinstance(profile, Mapping):
        raise BridgeError("schema-12 executor rescue source profile is absent")
    owner_binding = profile.get("owner_binding")
    refresh = profile.get("owner_binding_refresh")
    if (
        not isinstance(owner_binding, Mapping)
        or not isinstance(refresh, Mapping)
        or binding.get("owner_map") != owner_binding
        or profile.get("owner_binding_sha256")
        != owner_binding.get("document_sha256")
    ):
        raise BridgeError("schema-12 executor rescue source profile changed")
    return {
        "path": str(
            _absolute(
                Path(str(binding.get("profile"))),
                "schema-12 executor rescue source profile",
            )
        ),
        "before_identity": profile.get("before_identity"),
        "backup": str(
            _absolute(
                Path(str(profile.get("backup"))),
                "schema-12 executor rescue profile backup",
            )
        ),
        "backup_sha256": profile.get("backup_sha256"),
        "owner_binding": dict(owner_binding),
        "owner_binding_sha256": profile.get("owner_binding_sha256"),
        "owner_binding_refresh_sha256": _sha256_bytes(
            _canonical(refresh)
        ),
    }


def _successor_executor_rescue_predecessor_lineage(
    current: Mapping[str, object],
    *,
    expected_uid: int,
    require_absent: bool,
) -> dict[str, object]:
    binding = current.get("binding")
    predecessor = current.get("predecessor")
    if not isinstance(binding, Mapping) or not isinstance(
        predecessor, Mapping
    ):
        raise BridgeError("schema-12 executor rescue predecessor is absent")
    handoffs = binding.get("client_release_handoffs")
    maintenance_handoff = binding.get("maintenance_handoff")
    if (
        not isinstance(handoffs, list)
        or len(handoffs) != 1
        or not isinstance(maintenance_handoff, Mapping)
    ):
        raise BridgeError(
            "schema-12 executor rescue predecessor lineage is invalid"
        )
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    ready = _verify_successor_predecessor_proof(
        predecessor.get("ready_proof")
    )
    maintenance = _verify_successor_predecessor_proof(
        maintenance_handoff.get("predecessor_proof")
    )
    outer_rearm = ready.get("outer_rearm")
    if outer_rearm is None:
        raise BridgeError(
            "schema-12 executor rescue predecessor lacks rearm lineage"
        )
    rearm_reference, rearm, descriptor_lineage = (
        _verified_lifecycle_rearm_lineage(
            outer_rearm, expected_uid=expected_uid
        )
    )
    boundary = handoff.get("predecessor_dropin")
    ready_identity = ready.get("dropin_identity")
    ready_sha256 = (
        ready_identity.get("sha256")
        if isinstance(ready_identity, Mapping)
        else None
    )
    identities = (
        ready_identity,
        rearm.get("dropin_identity"),
        predecessor.get("dropin_identity"),
        boundary.get("bound_identity")
        if isinstance(boundary, Mapping)
        else None,
    )
    sha256_values = (
        ready_sha256,
        rearm.get("dropin_sha256"),
        predecessor.get("dropin_sha256"),
        boundary.get("bound_sha256")
        if isinstance(boundary, Mapping)
        else None,
    )
    if (
        handoff.get("phase") != "predecessor-retired"
        or maintenance.get("outer_rearm") != rearm_reference
        or any(identity != ready_identity for identity in identities)
        or any(value != ready_sha256 for value in sha256_values)
        or RELEASE_RE.fullmatch(str(ready_sha256)) is None
        or not isinstance(boundary, Mapping)
        or boundary.get("state") != "absent"
        or boundary.get("path") != ready.get("dropin")
    ):
        raise BridgeError(
            "schema-12 executor rescue four-way drop-in lineage changed"
        )
    absence = (
        _verify_managed_path_absent(
            Path(str(ready["dropin"])), expected_uid=expected_uid
        )
        if require_absent
        else None
    )
    return {
        "operation_id": predecessor.get("operation_id"),
        "journal": predecessor.get("journal"),
        "journal_raw_sha256": predecessor.get("journal_sha256"),
        "journal_document_sha256": predecessor.get("document_sha256"),
        "ready_proof_document_sha256": ready.get("document_sha256"),
        "outer_rearm": rearm_reference,
        **descriptor_lineage,
        "dropin": ready.get("dropin"),
        "dropin_identity": ready_identity,
        "dropin_sha256": ready_sha256,
        "first_handoff_dropin": dict(boundary),
        "absence": absence,
    }


def _successor_executor_rescue_runtime_binding(
    value: object,
    *,
    expected_uid: int,
    handoff_value: object | None = None,
    continuation_value: object | None = None,
) -> dict[str, object]:
    rescue = _validated_successor_executor_rescue(
        value, expected_uid=expected_uid
    )
    handoff = (
        _validated_successor_executor_handoff(
            handoff_value, expected_uid=expected_uid
        )
        if handoff_value is not None
        else None
    )
    continuation = (
        _validated_successor_post_export_executor_continuation(
            continuation_value, expected_uid=expected_uid
        )
        if continuation_value is not None
        else None
    )
    rescue_sha256 = _sha256_bytes(_canonical(rescue))
    if handoff is not None and (
        handoff["operation_id"] != rescue["operation_id"]
        or handoff["executor_rescue_sha256"] != rescue_sha256
        or handoff["previous_executor_release"]
        != rescue["rescue_executor_release"]
        or handoff["previous_executor_release_digest"]
        != rescue["rescue_executor_release_digest"]
        or handoff["retained_client_release"] != rescue["client_release"]
        or handoff["retained_client_release_digest"]
        != rescue["client_release_digest"]
        or handoff["source_profile_sha256"]
        != _sha256_bytes(_canonical(rescue["source_profile"]))
        or handoff["predecessor_lineage_sha256"]
        != _sha256_bytes(_canonical(rescue["predecessor_lineage"]))
        or handoff["first_handoff_sha256"]
        != rescue["first_handoff"]["sha256"]
        or handoff["owner_binding_refresh_sha256"]
        != rescue["owner_binding_refresh_sha256"]
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff changed its original rescue"
        )
    handoff_sha256 = (
        _sha256_bytes(_canonical(handoff)) if handoff is not None else None
    )
    if continuation is not None and (
        handoff is None
        or continuation["operation_id"] != rescue["operation_id"]
        or continuation["executor_rescue_sha256"] != rescue_sha256
        or continuation["executor_rescue_handoff_sha256"] != handoff_sha256
        or continuation["previous_executor_release"]
        != handoff["successor_executor_release"]
        or continuation["previous_executor_release_digest"]
        != handoff["successor_executor_release_digest"]
        or continuation["retained_client_release"] != rescue["client_release"]
        or continuation["retained_client_release_digest"]
        != rescue["client_release_digest"]
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation changed prior lineage"
        )
    executor_release = (
        continuation["successor_executor_release"]
        if continuation is not None
        else (
            handoff["successor_executor_release"]
            if handoff is not None
            else rescue["rescue_executor_release"]
        )
    )
    executor_digest = (
        continuation["successor_executor_release_digest"]
        if continuation is not None
        else (
            handoff["successor_executor_release_digest"]
            if handoff is not None
            else rescue["rescue_executor_release_digest"]
        )
    )
    binding = {
        "reason": rescue["reason"],
        "rescue_path": rescue["rescue_path"],
        "executor_rescue_sha256": rescue_sha256,
        "client_release": rescue["client_release"],
        "client_release_digest": rescue["client_release_digest"],
        "executor_release": executor_release,
        "executor_release_digest": executor_digest,
        "source_profile_sha256": _sha256_bytes(
            _canonical(rescue["source_profile"])
        ),
        "predecessor_lineage_sha256": _sha256_bytes(
            _canonical(rescue["predecessor_lineage"])
        ),
        "first_handoff_sha256": rescue["first_handoff"]["sha256"],
        "owner_binding_refresh_sha256": rescue[
            "owner_binding_refresh_sha256"
        ],
    }
    if handoff is not None:
        binding.update(
            {
                "executor_rescue_handoff_sha256": _sha256_bytes(
                    _canonical(handoff)
                ),
                "original_executor_release": rescue[
                    "rescue_executor_release"
                ],
                "original_executor_release_digest": rescue[
                    "rescue_executor_release_digest"
                ],
            }
        )
    if continuation is not None:
        binding.update(
            {
                "executor_rescue_post_export_continuation_sha256": (
                    _sha256_bytes(_canonical(continuation))
                ),
                "handoff_executor_release": handoff[
                    "successor_executor_release"
                ],
                "handoff_executor_release_digest": handoff[
                    "successor_executor_release_digest"
                ],
            }
        )
    return binding


def _validate_successor_executor_rescue_runtime_evidence(
    value: object, *, expected_sha256: object
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) not in {
        _SUCCESSOR_EXECUTOR_RESCUE_RUNTIME_FIELDS,
        _SUCCESSOR_EXECUTOR_HANDOFF_RUNTIME_FIELDS,
        _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_RUNTIME_FIELDS,
    }:
        raise BridgeError("schema-12 executor rescue runtime binding is invalid")
    runtime = dict(value)
    has_handoff = set(runtime) == _SUCCESSOR_EXECUTOR_HANDOFF_RUNTIME_FIELDS
    has_continuation = (
        set(runtime)
        == _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_RUNTIME_FIELDS
    )
    has_handoff = has_handoff or has_continuation
    digest_fields = set(runtime) - {
        "reason",
        "rescue_path",
        "client_release",
        "original_executor_release",
        "executor_release",
        "executor_rescue_handoff_sha256",
        "executor_rescue_post_export_continuation_sha256",
        "handoff_executor_release",
    }
    path_fields = ["client_release", "executor_release"]
    if has_handoff:
        path_fields.append("original_executor_release")
    if has_continuation:
        path_fields.append("handoff_executor_release")
    for field in path_fields:
        runtime[field] = str(
            _absolute(
                Path(str(runtime[field])),
                f"schema-12 executor rescue runtime {field}",
            )
        )
    if (
        runtime["reason"] != SUCCESSOR_EXECUTOR_RESCUE_REASON
        or runtime["rescue_path"] != SUCCESSOR_EXECUTOR_RESCUE_PATH
        or any(
            RELEASE_RE.fullmatch(str(runtime[field])) is None
            for field in digest_fields
        )
        or has_handoff
        and RELEASE_RE.fullmatch(
            str(runtime["executor_rescue_handoff_sha256"])
        )
        is None
        or has_continuation
        and RELEASE_RE.fullmatch(
            str(runtime[
                "executor_rescue_post_export_continuation_sha256"
            ])
        )
        is None
        or runtime["executor_rescue_sha256"] != expected_sha256
        or runtime["client_release"] == runtime["executor_release"]
        or has_handoff
        and runtime["client_release"]
        == runtime["original_executor_release"]
        or has_handoff
        and runtime["executor_release"]
        == runtime["original_executor_release"]
        or has_continuation
        and runtime["handoff_executor_release"]
        in {
            runtime["client_release"],
            runtime["original_executor_release"],
            runtime["executor_release"],
        }
    ):
        raise BridgeError("schema-12 executor rescue runtime binding changed")
    return runtime


def _verify_successor_executor_rescue_runtime_binding(
    value: object,
    *,
    client_release: Path,
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    expected_sha256 = (
        value.get("executor_rescue_sha256")
        if isinstance(value, Mapping)
        else None
    )
    runtime = _validate_successor_executor_rescue_runtime_evidence(
        value, expected_sha256=expected_sha256
    )
    running = ROOT.resolve(strict=True)
    retained = _absolute(client_release, "executor rescue retained client")
    if (
        runtime["executor_release"] != str(running)
        or runtime["executor_release_digest"] != running.name
        or runtime["client_release"] != str(retained)
        or retained == running
    ):
        raise BridgeError("schema-12 executor rescue runtime binding changed")
    manifest = _verify_historical_availability_release(
        retained, owner_uid=expected_uid
    )
    if manifest.get("release_digest") != runtime["client_release_digest"]:
        raise BridgeError("schema-12 executor rescue retained client changed")
    if "executor_rescue_handoff_sha256" in runtime:
        original = _absolute(
            Path(str(runtime["original_executor_release"])),
            "executor rescue original executor",
        )
        original_manifest = _verify_historical_availability_release(
            original, owner_uid=expected_uid
        )
        if (
            original_manifest.get("release_digest")
            != runtime["original_executor_release_digest"]
        ):
            raise BridgeError(
                "schema-12 executor rescue original executor changed"
            )
    if "executor_rescue_post_export_continuation_sha256" in runtime:
        handoff_executor = _absolute(
            Path(str(runtime["handoff_executor_release"])),
            "executor rescue handoff executor",
        )
        handoff_manifest = _verify_historical_availability_release(
            handoff_executor, owner_uid=expected_uid
        )
        if (
            handoff_manifest.get("release_digest")
            != runtime["handoff_executor_release_digest"]
        ):
            raise BridgeError(
                "schema-12 executor rescue handoff executor changed"
            )
    return runtime, manifest


def _verify_historical_ready_executor_rescue_runtime_binding(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    """Verify completed rescue lineage without adopting its executor identity.

    ``verify-ready`` may be executed by a later immutable availability release.
    The completed journal still binds the exact retained client and every
    executor that participated in rescue, handoff, and continuation.  Verify
    each named release with the current immutable verifier, while deliberately
    omitting only the active-mutation invariant that ROOT must equal the final
    historical executor.
    """

    expected_sha256 = (
        value.get("executor_rescue_sha256")
        if isinstance(value, Mapping)
        else None
    )
    runtime = _validate_successor_executor_rescue_runtime_evidence(
        value, expected_sha256=expected_sha256
    )
    releases = [
        (
            "retained client",
            "client_release",
            "client_release_digest",
        ),
        (
            "effective executor",
            "executor_release",
            "executor_release_digest",
        ),
    ]
    if "executor_rescue_handoff_sha256" in runtime:
        releases.append(
            (
                "original executor",
                "original_executor_release",
                "original_executor_release_digest",
            )
        )
    if "executor_rescue_post_export_continuation_sha256" in runtime:
        releases.append(
            (
                "handoff executor",
                "handoff_executor_release",
                "handoff_executor_release_digest",
            )
        )

    running = ROOT.resolve(strict=True)
    verified_paths: set[Path] = set()
    for label, path_field, digest_field in releases:
        release = _absolute(
            Path(str(runtime[path_field])),
            f"historical ready bridge {label}",
        )
        if release in verified_paths:
            raise BridgeError(
                "schema-12 historical ready executor lineage is not singular"
            )
        verified_paths.add(release)
        manifest = (
            _verify_availability_client_release(
                release, owner_uid=expected_uid
            )
            if release == running
            else _verify_historical_availability_release(
                release, owner_uid=expected_uid
            )
        )
        if manifest.get("release_digest") != runtime[digest_field]:
            raise BridgeError(
                f"schema-12 historical ready {label} release changed"
            )
    return runtime


def _verify_successor_executor_rescue_intent(
    value: object,
) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_EXECUTOR_RESCUE_INTENT_KIND,
        fields=set(_SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS),
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 successor executor rescue operation is invalid"
        ) from error
    digest_fields = (
        "journal_raw_sha256",
        "journal_document_sha256",
        "source_binding_sha256",
        "client_release_digest",
        "previous_executor_release_digest",
        "rescue_executor_release_digest",
        "owner_binding_refresh_sha256",
    )
    live_state = document["live_state"]
    if (
        document["reason"] != SUCCESSOR_EXECUTOR_RESCUE_REASON
        or document["rescue_path"] != SUCCESSOR_EXECUTOR_RESCUE_PATH
        or operation_id != document["operation_id"]
        or document["phase"] != "predecessor-retired"
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in digest_fields
        )
        or document["client_release"]
        != document["previous_executor_release"]
        or document["client_release_digest"]
        != document["previous_executor_release_digest"]
        or document["rescue_executor_release"]
        == document["previous_executor_release"]
        or document["rescue_executor_release_digest"]
        == document["previous_executor_release_digest"]
        or not isinstance(document["journal_identity"], dict)
        or document["journal_identity"].get("sha256")
        != document["journal_raw_sha256"]
        or not isinstance(live_state, dict)
        or not isinstance(document["source_profile"], dict)
        or not isinstance(document["predecessor_lineage"], dict)
        or not isinstance(document["first_handoff"], dict)
        or RELEASE_RE.fullmatch(
            str(document["first_handoff"].get("sha256"))
        )
        is None
        or set(live_state)
        != {
            "owner_binding_refresh",
            "predecessor_lineage",
            "profile_identity",
            "profile_backup",
            "readiness_attestation",
            "database_bundle",
            "database_readiness",
            "broker_state",
            "predecessor_dropin",
        }
        or not isinstance(live_state["broker_state"], dict)
        or not isinstance(live_state["owner_binding_refresh"], dict)
        or live_state["predecessor_lineage"]
        != document["predecessor_lineage"]
        or _sha256_bytes(
            _canonical(live_state["owner_binding_refresh"])
        )
        != document["owner_binding_refresh_sha256"]
        or live_state["broker_state"].get("ActiveState") != "inactive"
        or live_state["broker_state"].get("SubState") != "dead"
        or live_state["broker_state"].get("MainPID") != 0
        or not isinstance(live_state["predecessor_dropin"], dict)
        or live_state["predecessor_dropin"].get("state") != "absent"
        or isinstance(document["recorded_at_epoch"], bool)
        or not isinstance(document["recorded_at_epoch"], int)
        or int(document["recorded_at_epoch"]) <= 0
    ):
        raise BridgeError(
            "schema-12 successor executor rescue intent binding is invalid"
        )
    for field in (
        "journal_backup",
        "client_release",
        "previous_executor_release",
        "rescue_executor_release",
    ):
        document[field] = str(
            _absolute(
                Path(str(document[field])),
                f"schema-12 successor executor rescue {field}",
            )
        )
    return document


def _successor_executor_rescue_precondition(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    terminal_path: Path,
    completion_path: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
) -> dict[str, object]:
    """Capture the exact retired boundary, including owner-map refresh lineage."""

    binding_value = current.get("binding")
    profile_value = current.get("profile")
    if not isinstance(binding_value, Mapping) or not isinstance(
        profile_value, Mapping
    ):
        raise BridgeError(
            "schema-12 successor executor rescue owner refresh is absent"
        )
    binding = dict(binding_value)
    refresh = profile_value.get("owner_binding_refresh")
    maintenance_handoff = binding.get("maintenance_handoff")
    owner_map = binding.get("owner_map")
    if (
        not isinstance(refresh, Mapping)
        or set(refresh) != _OWNER_MAP_REFRESH_RECORD_FIELDS
        or not isinstance(refresh.get("previous"), Mapping)
        or not isinstance(refresh.get("refreshed"), Mapping)
        or not isinstance(maintenance_handoff, Mapping)
        or not isinstance(owner_map, Mapping)
        or refresh.get("refreshed") != owner_map
        or requested_binding.get("owner_map") != owner_map
        or profile_value.get("owner_binding") != owner_map
        or profile_value.get("owner_binding_sha256")
        != owner_map.get("document_sha256")
    ):
        raise BridgeError(
            "schema-12 successor executor rescue owner refresh is invalid"
        )
    verified_refresh = _verified_owner_map_refresh_relation(
        previous_reference=refresh["previous"],
        refreshed_reference=refresh["refreshed"],
        maintenance_handoff=maintenance_handoff,
        expected_uid=expected_uid,
    )
    if verified_refresh != dict(refresh):
        raise BridgeError(
            "schema-12 successor executor rescue owner refresh changed"
        )
    live_state = _successor_client_handoff_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
        _stable_retired_sidecar_timestamps=True,
    )
    predecessor_lineage = _successor_executor_rescue_predecessor_lineage(
        current, expected_uid=expected_uid, require_absent=True
    )
    return {
        "owner_binding_refresh": verified_refresh,
        "predecessor_lineage": predecessor_lineage,
        **live_state,
    }


def _load_successor_executor_rescue_intent(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_successor_executor_rescue_intent(
        _read_private_json(
            path,
            uid=uid,
            label="schema-12 successor executor rescue intent",
        )
    )


def _validated_successor_executor_rescue(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _SUCCESSOR_EXECUTOR_RESCUE_FIELDS:
        raise BridgeError("schema-12 successor executor rescue fields are invalid")
    document = dict(value)
    core = {
        field: document[field]
        for field in _SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS
    }
    verified_core = _verify_successor_executor_rescue_intent(
        _seal(SUCCESSOR_EXECUTOR_RESCUE_INTENT_KIND, core)
    )
    if any(verified_core[field] != value for field, value in core.items()):
        raise BridgeError("schema-12 successor executor rescue binding changed")
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    journal_identity = document["journal_identity"]
    if (
        not isinstance(journal_identity, dict)
        or set(journal_identity) != identity_fields
        or journal_identity.get("uid") != expected_uid
        or journal_identity.get("mode") != 0o600
        or journal_identity.get("nlink") != 1
        or journal_identity.get("sha256")
        != document["journal_raw_sha256"]
    ):
        raise BridgeError(
            "schema-12 successor executor rescue source identity is invalid"
        )
    for field, digest_field in (
        ("journal_backup_identity", "journal_raw_sha256"),
        ("intent_identity", "intent_raw_sha256"),
    ):
        identity = document[field]
        if (
            not isinstance(identity, dict)
            or set(identity) != identity_fields
            or identity.get("uid") != expected_uid
            or identity.get("mode") != 0o600
            or identity.get("nlink") != 1
            or identity.get("sha256") != document[digest_field]
        ):
            raise BridgeError(
                "schema-12 successor executor rescue private identity is invalid"
            )
    if (
        RELEASE_RE.fullmatch(str(document["intent_raw_sha256"])) is None
        or RELEASE_RE.fullmatch(str(document["intent_document_sha256"])) is None
    ):
        raise BridgeError("schema-12 successor executor rescue intent digest is invalid")
    document["intent"] = str(
        _absolute(
            Path(str(document["intent"])),
            "schema-12 successor executor rescue intent",
        )
    )
    return document


def _verify_successor_executor_handoff_intent(
    value: object,
) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_EXECUTOR_HANDOFF_INTENT_KIND,
        fields=set(_SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS),
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 rescue executor handoff operation is invalid"
        ) from error
    digest_fields = {
        "journal_raw_sha256",
        "journal_document_sha256",
        "source_binding_sha256",
        "executor_rescue_sha256",
        "previous_executor_release_digest",
        "successor_executor_release_digest",
        "retained_client_release_digest",
        "candidate_release_digest",
        "source_profile_sha256",
        "predecessor_lineage_sha256",
        "first_handoff_sha256",
        "owner_binding_refresh_sha256",
    }
    if (
        document["reason"] != SUCCESSOR_EXECUTOR_HANDOFF_REASON
        or document["handoff_path"] != SUCCESSOR_EXECUTOR_HANDOFF_PATH
        or operation_id != document["operation_id"]
        or document["phase"] != "predecessor-retired"
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in digest_fields
        )
        or document["previous_executor_release"]
        == document["successor_executor_release"]
        or document["previous_executor_release_digest"]
        == document["successor_executor_release_digest"]
        or document["retained_client_release"]
        == document["successor_executor_release"]
        or not isinstance(document["journal_identity"], dict)
        or document["journal_identity"].get("sha256")
        != document["journal_raw_sha256"]
        or not isinstance(document["live_state"], dict)
        or isinstance(document["recorded_at_epoch"], bool)
        or not isinstance(document["recorded_at_epoch"], int)
        or document["recorded_at_epoch"] <= 0
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff intent binding is invalid"
        )
    for field in (
        "journal_backup",
        "previous_executor_release",
        "successor_executor_release",
        "retained_client_release",
        "candidate_release",
    ):
        document[field] = str(
            _absolute(
                Path(str(document[field])),
                f"schema-12 rescue executor handoff {field}",
            )
        )
    return document


def _load_successor_executor_handoff_intent(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_successor_executor_handoff_intent(
        _read_private_json(
            path,
            uid=uid,
            label="schema-12 rescue executor handoff intent",
        )
    )


def _validated_successor_executor_handoff(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != (
        _SUCCESSOR_EXECUTOR_HANDOFF_FIELDS
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff fields are invalid"
        )
    document = dict(value)
    core = {
        field: document[field]
        for field in _SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS
    }
    verified_core = _verify_successor_executor_handoff_intent(
        _seal(SUCCESSOR_EXECUTOR_HANDOFF_INTENT_KIND, core)
    )
    if any(verified_core[field] != field_value for field, field_value in core.items()):
        raise BridgeError(
            "schema-12 rescue executor handoff binding changed"
        )
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    for field, digest_field in (
        ("journal_identity", "journal_raw_sha256"),
        ("journal_backup_identity", "journal_raw_sha256"),
        ("intent_identity", "intent_raw_sha256"),
    ):
        identity = document[field]
        if (
            not isinstance(identity, dict)
            or set(identity) != identity_fields
            or identity.get("uid") != expected_uid
            or identity.get("mode") != 0o600
            or identity.get("nlink") != 1
            or identity.get("sha256") != document[digest_field]
        ):
            raise BridgeError(
                "schema-12 rescue executor handoff private identity is invalid"
            )
    if (
        RELEASE_RE.fullmatch(str(document["intent_raw_sha256"])) is None
        or RELEASE_RE.fullmatch(str(document["intent_document_sha256"]))
        is None
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff intent digest is invalid"
        )
    document["intent"] = str(
        _absolute(
            Path(str(document["intent"])),
            "schema-12 rescue executor handoff intent",
        )
    )
    return document


def _successor_executor_handoff_sha256(
    binding: Mapping[str, object], *, expected_uid: int
) -> str | None:
    handoff = binding.get("executor_rescue_handoff")
    if handoff is None:
        return None
    verified = _validated_successor_executor_handoff(
        handoff, expected_uid=expected_uid
    )
    return _sha256_bytes(_canonical(verified))


def _verify_retained_successor_executor_handoff(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError(
            "schema-12 rescue executor handoff lacks its binding"
        )
    binding = dict(binding_value)
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    handoff = _validated_successor_executor_handoff(
        binding.get("executor_rescue_handoff"), expected_uid=expected_uid
    )
    rescue_sha256 = _sha256_bytes(_canonical(rescue))
    if (
        current.get("phase")
        not in _SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES
        or current.get("operation_id") != handoff["operation_id"]
        or inherited_journal_sha256 != handoff["journal_raw_sha256"]
        or inherited_document_sha256
        != handoff["journal_document_sha256"]
        or handoff["executor_rescue_sha256"] != rescue_sha256
        or handoff["previous_executor_release"]
        != rescue["rescue_executor_release"]
        or handoff["previous_executor_release_digest"]
        != rescue["rescue_executor_release_digest"]
        or handoff["retained_client_release"] != rescue["client_release"]
        or handoff["retained_client_release_digest"]
        != rescue["client_release_digest"]
        or handoff["successor_executor_release"]
        != release_pair.get("executor_release")
        or handoff["successor_executor_release_digest"]
        != release_pair.get("executor_release_digest")
        or handoff["retained_client_release"]
        != release_pair.get("client_release")
        or handoff["retained_client_release_digest"]
        != release_pair.get("client_release_digest")
        or release_pair.get("historical_client") is not True
        or requested_binding.get("client_release") != rescue["client_release"]
        or requested_binding.get("client_release_digest")
        != rescue["client_release_digest"]
        or handoff["candidate_release"]
        != requested_binding.get("candidate_release")
        or handoff["candidate_release_digest"]
        != requested_binding.get("candidate_release_digest")
        or handoff["intent"] != str(intent_path)
        or handoff["journal_backup"] != str(journal_backup_path)
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff lineage changed"
        )
    intent_payload, intent_identity, intent_value = (
        _stable_private_json_bytes(
            intent_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff intent",
        )
    )
    intent = _verify_successor_executor_handoff_intent(intent_value)
    if (
        any(
            intent[field] != handoff[field]
            for field in _SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS
        )
        or intent_identity != handoff["intent_identity"]
        or intent_identity["sha256"] != handoff["intent_raw_sha256"]
        or intent["document_sha256"]
        != handoff["intent_document_sha256"]
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff intent changed"
        )
    backup_payload, backup_identity, backup_value = (
        _stable_private_json_bytes(
            journal_backup_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff journal preimage",
        )
    )
    preimage = _verify_successor_journal(backup_value)
    if (
        preimage is None
        or backup_identity != handoff["journal_backup_identity"]
        or backup_identity["sha256"] != handoff["journal_raw_sha256"]
        or preimage.get("document_sha256")
        != handoff["journal_document_sha256"]
        or preimage.get("phase") != "predecessor-retired"
        or preimage.get("operation_id") != current.get("operation_id")
        or not isinstance(preimage.get("binding"), dict)
        or "executor_rescue_handoff" in preimage["binding"]
        or preimage["binding"].get("executor_rescue") != rescue
        or _sha256_bytes(_canonical(preimage["binding"]))
        != handoff["source_binding_sha256"]
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff preimage changed"
        )
    source_binding = dict(binding)
    source_binding.pop("executor_rescue_handoff", None)
    runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
    )
    _verify_successor_executor_rescue_runtime_binding(
        runtime,
        client_release=Path(str(rescue["client_release"])),
        expected_uid=expected_uid,
    )
    if (
        source_binding != preimage["binding"]
        or _successor_binding_without_client_handoff(source_binding)
        != _successor_binding_without_client_handoff(requested_binding)
        or handoff["source_profile_sha256"]
        != _sha256_bytes(_canonical(rescue["source_profile"]))
        or handoff["predecessor_lineage_sha256"]
        != _sha256_bytes(_canonical(rescue["predecessor_lineage"]))
        or handoff["first_handoff_sha256"]
        != rescue["first_handoff"]["sha256"]
        or handoff["owner_binding_refresh_sha256"]
        != rescue["owner_binding_refresh_sha256"]
        or not backup_payload
        or not intent_payload
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff state changed"
        )
    if current.get("phase") == "predecessor-retired":
        current_profile = current.get("profile")
        if (
            current_profile != preimage.get("profile")
            or current.get("candidate")
            != {"activation": None, "readiness": None}
            or terminal_path.exists()
            or terminal_path.is_symlink()
            or completion_path.exists()
            or completion_path.is_symlink()
            or not isinstance(current_profile, Mapping)
            or current_profile.get("repaired_payload_sha256") is not None
            or current_profile.get("after_identity") is not None
            or current_profile.get("restored_identity") is not None
            or "export_evidence" in current_profile
        ):
            raise BridgeError(
                "schema-12 rescue executor handoff left its pre-export phase"
            )
        live_state = _successor_executor_rescue_precondition(
            current,
            requested_binding=requested_binding,
            terminal_path=terminal_path,
            completion_path=completion_path,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
        )
        if live_state != handoff["live_state"]:
            raise BridgeError(
                "schema-12 rescue executor handoff live state changed"
            )
    return dict(current)


def _migrate_successor_rescue_executor_handoff(
    current: Mapping[str, object],
    *,
    request: Mapping[str, object],
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    journal_path: Path,
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str,
    inherited_document_sha256: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    failpoint: Callable[[str], None],
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError(
            "schema-12 rescue executor handoff lacks its binding"
        )
    binding = dict(binding_value)
    if "executor_rescue_handoff" in binding:
        return _verify_retained_successor_executor_handoff(
            current,
            requested_binding=requested_binding,
            release_pair=release_pair,
            intent_path=intent_path,
            journal_backup_path=journal_backup_path,
            terminal_path=terminal_path,
            completion_path=completion_path,
            inherited_journal_sha256=inherited_journal_sha256,
            inherited_document_sha256=inherited_document_sha256,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
        )
    validated_request = _validate_successor_executor_handoff_request(
        request,
        current=current,
        release_pair=release_pair,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        expected_uid=expected_uid,
    )
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    source_payload, source_identity, source_value = (
        _stable_private_json_bytes(
            journal_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff source journal",
        )
    )
    if (
        source_identity["sha256"] != inherited_journal_sha256
        or _verify_successor_journal(source_value) != current
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff digest changed"
        )
    live_state = _successor_executor_rescue_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    intent_binding = {
        "reason": SUCCESSOR_EXECUTOR_HANDOFF_REASON,
        "handoff_path": SUCCESSOR_EXECUTOR_HANDOFF_PATH,
        "operation_id": current["operation_id"],
        "phase": "predecessor-retired",
        "journal_backup": str(journal_backup_path),
        "journal_raw_sha256": inherited_journal_sha256,
        "journal_document_sha256": inherited_document_sha256,
        "journal_identity": source_identity,
        "source_binding_sha256": _sha256_bytes(_canonical(binding)),
        "executor_rescue_sha256": _sha256_bytes(_canonical(rescue)),
        "previous_executor_release": rescue["rescue_executor_release"],
        "previous_executor_release_digest": rescue[
            "rescue_executor_release_digest"
        ],
        "successor_executor_release": release_pair["executor_release"],
        "successor_executor_release_digest": release_pair[
            "executor_release_digest"
        ],
        "retained_client_release": rescue["client_release"],
        "retained_client_release_digest": rescue["client_release_digest"],
        "candidate_release": binding["candidate_release"],
        "candidate_release_digest": binding["candidate_release_digest"],
        "source_profile_sha256": _sha256_bytes(
            _canonical(rescue["source_profile"])
        ),
        "predecessor_lineage_sha256": _sha256_bytes(
            _canonical(rescue["predecessor_lineage"])
        ),
        "first_handoff_sha256": rescue["first_handoff"]["sha256"],
        "owner_binding_refresh_sha256": rescue[
            "owner_binding_refresh_sha256"
        ],
        "live_state": live_state,
    }
    intent = _load_successor_executor_handoff_intent(
        intent_path, uid=expected_uid
    )
    if intent is None:
        intent = _verify_successor_executor_handoff_intent(
            _seal(
                SUCCESSOR_EXECUTOR_HANDOFF_INTENT_KIND,
                {**intent_binding, "recorded_at_epoch": int(time.time())},
            )
        )
        _atomic_private_json(intent_path, intent, uid=expected_uid)
    elif any(
        intent[field] != expected
        for field, expected in intent_binding.items()
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff intent changed"
        )
    intent_payload, intent_identity, retained_intent_value = (
        _stable_private_json_bytes(
            intent_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff intent",
        )
    )
    if _verify_successor_executor_handoff_intent(
        retained_intent_value
    ) != intent:
        raise BridgeError(
            "schema-12 rescue executor handoff intent changed"
        )
    failpoint("after-successor-rescue-executor-handoff-intent")
    _write_private_bytes_once(
        journal_backup_path, source_payload, uid=expected_uid
    )
    backup_payload, backup_identity, backup_value = (
        _stable_private_json_bytes(
            journal_backup_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff journal preimage",
        )
    )
    if (
        backup_payload != source_payload
        or _verify_successor_journal(backup_value) != current
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff preimage changed"
        )
    failpoint("after-successor-rescue-executor-handoff-backup")
    retained_payload, retained_identity, retained_value = (
        _stable_private_json_bytes(
            journal_path,
            uid=expected_uid,
            label="schema-12 rescue executor handoff source journal",
        )
    )
    retained_live_state = _successor_executor_rescue_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    if (
        retained_payload != source_payload
        or retained_identity != source_identity
        or _verify_successor_journal(retained_value) != current
        or retained_live_state != live_state
    ):
        raise BridgeError(
            "schema-12 rescue executor handoff state changed before publication"
        )
    _ensure_successor_maintenance(binding["maintenance"], uid=expected_uid)
    handoff = _validated_successor_executor_handoff(
        {
            **{
                field: intent[field]
                for field in _SUCCESSOR_EXECUTOR_HANDOFF_INTENT_FIELDS
            },
            "journal_backup_identity": backup_identity,
            "intent": str(intent_path),
            "intent_raw_sha256": _sha256_bytes(intent_payload),
            "intent_document_sha256": intent["document_sha256"],
            "intent_identity": intent_identity,
        },
        expected_uid=expected_uid,
    )
    successor_binding = dict(binding)
    successor_binding["executor_rescue_handoff"] = handoff
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["binding"] = successor_binding
    payload["updated_at_epoch"] = int(time.time())
    migrated = _successor_journal(journal_path, payload, uid=expected_uid)
    failpoint("after-successor-rescue-executor-handoff")
    return _verify_retained_successor_executor_handoff(
        migrated,
        requested_binding=requested_binding,
        release_pair=release_pair,
        intent_path=intent_path,
        journal_backup_path=journal_backup_path,
        terminal_path=terminal_path,
        completion_path=completion_path,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )


def _verify_successor_post_export_executor_continuation_intent(
    value: object,
) -> dict[str, object]:
    document = _verify_seal(
        value,
        kind=SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_KIND,
        fields=set(_SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS),
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
        successor_operation_id = str(
            uuid.UUID(str(document["successor_candidate_operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 post-export executor continuation operation is invalid"
        ) from error
    digest_fields = {
        "journal_raw_sha256",
        "journal_document_sha256",
        "source_binding_sha256",
        "executor_rescue_sha256",
        "executor_rescue_handoff_sha256",
        "previous_executor_release_digest",
        "successor_executor_release_digest",
        "retained_client_release_digest",
        "candidate_release_digest",
        "source_profile_state_sha256",
        "source_profile_export_sha256",
    }
    if (
        operation_id != document["operation_id"]
        or successor_operation_id
        != document["successor_candidate_operation_id"]
        or successor_operation_id == operation_id
        or document["reason"]
        != SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON
        or document["continuation_path"]
        != SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH
        or document["phase"] != "candidate-activation-intent"
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in digest_fields
        )
        or not isinstance(document["failed_candidate"], dict)
        or not isinstance(document["live_state"], dict)
        or isinstance(document["recorded_at_epoch"], bool)
        or not isinstance(document["recorded_at_epoch"], int)
        or document["recorded_at_epoch"] <= 0
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation intent is invalid"
        )
    for field in (
        "journal_backup",
        "failed_candidate_backup",
        "previous_executor_release",
        "successor_executor_release",
        "retained_client_release",
        "candidate_release",
        "successor_candidate_transaction",
    ):
        document[field] = str(
            _absolute(
                Path(str(document[field])),
                f"schema-12 post-export executor continuation {field}",
            )
        )
    return document


def _load_successor_post_export_executor_continuation_intent(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_successor_post_export_executor_continuation_intent(
        _read_private_json(
            path,
            uid=uid,
            label="schema-12 post-export executor continuation intent",
        )
    )


def _validated_successor_post_export_executor_continuation(
    value: object, *, expected_uid: int
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != (
        _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_FIELDS
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation fields are invalid"
        )
    document = dict(value)
    core = {
        field: document[field]
        for field in _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS
    }
    verified = _verify_successor_post_export_executor_continuation_intent(
        _seal(SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_KIND, core)
    )
    if any(verified[field] != field_value for field, field_value in core.items()):
        raise BridgeError(
            "schema-12 post-export executor continuation binding changed"
        )
    identity_fields = {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "sha256",
    }
    for field, digest_field in (
        ("journal_identity", "journal_raw_sha256"),
        ("journal_backup_identity", "journal_raw_sha256"),
        ("intent_identity", "intent_raw_sha256"),
    ):
        identity = document[field]
        if (
            not isinstance(identity, dict)
            or set(identity) != identity_fields
            or identity.get("uid") != expected_uid
            or identity.get("mode") != 0o600
            or identity.get("nlink") != 1
            or identity.get("sha256") != document[digest_field]
        ):
            raise BridgeError(
                "schema-12 post-export executor continuation private identity "
                "is invalid"
            )
    failed_backup_identity = document["failed_candidate_backup_identity"]
    failed_candidate = document["failed_candidate"]
    if (
        not isinstance(failed_candidate, dict)
        or not isinstance(failed_backup_identity, dict)
        or set(failed_backup_identity) != identity_fields
        or failed_backup_identity.get("uid") != expected_uid
        or failed_backup_identity.get("mode") != 0o600
        or failed_backup_identity.get("nlink") != 1
        or failed_backup_identity.get("sha256")
        != failed_candidate.get("journal_raw_sha256")
    ):
        raise BridgeError(
            "schema-12 post-export failed candidate backup identity is invalid"
        )
    if (
        RELEASE_RE.fullmatch(str(document["intent_raw_sha256"])) is None
        or RELEASE_RE.fullmatch(str(document["intent_document_sha256"]))
        is None
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation intent digest is invalid"
        )
    document["intent"] = str(
        _absolute(
            Path(str(document["intent"])),
            "schema-12 post-export executor continuation intent",
        )
    )
    return document


def _verify_failed_post_export_candidate_document(
    value: object,
    *,
    binding: Mapping[str, object],
    expected_runtime: Mapping[str, object],
) -> dict[str, object]:
    common_fields = {
        "operation_id",
        "release",
        "release_digest",
        "dropin",
        "dropin_sha256",
        "dropin_identity",
        "broker_socket",
        "failed_activation",
        "readiness",
        "canaries",
        "baseline",
        "phase",
        "attempts",
        "activation",
        "error",
        "created_at_epoch",
        "updated_at_epoch",
        "readiness_origin",
        "attempt_evidence",
        "executor_rescue",
    }
    document = _verify_seal(
        value,
        kind=JOURNAL_KIND,
        fields=common_fields,
        schema_version=EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION,
    )
    error = document.get("error")
    activation = document.get("activation")
    readiness = document.get("readiness")
    expected_error = (
        "legacy /opt release root is not one of the sealed dedicated roots"
    )
    wrapped_error = (
        "command failed (1): /usr/bin/setpriv --reuid "
        + str(binding.get("expected_canary_uid"))
        + ": "
        + json.dumps(
            {"error": expected_error, "ok": False},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    attempt_evidence = document.get("attempt_evidence")
    if (
        document.get("operation_id")
        != binding.get("candidate_operation_id")
        or document.get("release") != binding.get("candidate_release")
        or document.get("release_digest")
        != binding.get("candidate_release_digest")
        or document.get("phase") != "failed"
        or document.get("attempts") != 1
        or not isinstance(activation, Mapping)
        or set(activation) != {"systemd", "execution", "canaries"}
        or not isinstance(activation.get("systemd"), Mapping)
        or not isinstance(activation.get("execution"), Mapping)
        or activation.get("canaries") != []
        or not isinstance(readiness, Mapping)
        or document.get("executor_rescue") != dict(expected_runtime)
        or error not in {expected_error, wrapped_error}
        or not isinstance(attempt_evidence, Mapping)
        or attempt_evidence.get("attempt") != 1
        or attempt_evidence.get("stage") != "failed"
        or attempt_evidence.get("last_completed_stage") != "systemd-ready"
        or attempt_evidence.get("failure_stage") != "canaries"
        or not isinstance(attempt_evidence.get("systemd_ready"), Mapping)
        or attempt_evidence["systemd_ready"].get("dropin_identity")
        != document.get("dropin_identity")
        or attempt_evidence["systemd_ready"].get(
            "readiness_state_revision"
        )
        != readiness.get("state_revision")
        or attempt_evidence["systemd_ready"].get("systemd")
        != activation.get("systemd")
        or attempt_evidence.get("error_sha256")
        != _sha256_bytes(str(error).encode("utf-8"))
    ):
        raise BridgeError(
            "schema-12 post-export failed candidate lineage changed"
        )
    return document


def _failed_post_export_candidate_reference(
    binding: Mapping[str, object],
    *,
    expected_runtime: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    transaction = _absolute(
        Path(str(binding.get("candidate_transaction"))),
        "schema-12 failed candidate transaction",
    )
    journal = transaction / JOURNAL_NAME
    payload, identity, raw = _stable_private_json_bytes(
        journal,
        uid=expected_uid,
        label="schema-12 failed candidate journal",
    )
    document = _verify_failed_post_export_candidate_document(
        raw,
        binding=binding,
        expected_runtime=expected_runtime,
    )
    error = document["error"]
    return {
        "transaction": str(transaction),
        "operation_id": document["operation_id"],
        "journal": str(journal),
        "journal_raw_sha256": _sha256_bytes(payload),
        "journal_document_sha256": document["document_sha256"],
        "journal_identity": identity,
        "release": document["release"],
        "release_digest": document["release_digest"],
        "executor_rescue_sha256": _sha256_bytes(
            _canonical(document["executor_rescue"])
        ),
        "activation_sha256": _sha256_bytes(
            _canonical(document["activation"])
        ),
        "readiness_sha256": _sha256_bytes(
            _canonical(document["readiness"])
        ),
        "error_sha256": _sha256_bytes(str(error).encode("utf-8")),
    }


def _existing_post_export_successor_candidate(
    *,
    transaction: Path,
    operation_id: str,
    binding: Mapping[str, object],
    rescue: Mapping[str, object],
    handoff: Mapping[str, object],
    continuation: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    current = _load_bridge_journal(journal_path, uid=expected_uid)
    runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
        continuation_value=continuation,
    )
    if current is None:
        raise BridgeError(
            "schema-12 post-export successor candidate is partial and requires "
            "explicit recovery"
        )
    phase = current.get("phase")
    if phase == "recovery-required":
        raise BridgeError(
            "schema-12 post-export successor candidate cleanup requires explicit "
            "recovery"
        )
    if (
        current.get("operation_id") != operation_id
        or current.get("release") != binding.get("candidate_release")
        or current.get("release_digest")
        != binding.get("candidate_release_digest")
        or current.get("executor_rescue") != runtime
        or phase not in {"failed", "systemd-ready", "ready"}
    ):
        raise BridgeError(
            "schema-12 post-export successor candidate lineage changed"
        )
    if phase == "failed" and not isinstance(current.get("error"), str):
        raise BridgeError(
            "schema-12 post-export successor candidate failure is incomplete"
        )
    if phase in {"systemd-ready", "ready"}:
        activation = current.get("activation")
        systemd = activation.get("systemd") if isinstance(activation, dict) else None
        if (
            not isinstance(activation, dict)
            or not isinstance(systemd, dict)
            or not isinstance(systemd.get("InvocationID"), str)
            or not systemd.get("InvocationID")
            or not isinstance(activation.get("execution"), dict)
            or not isinstance(activation.get("canaries"), list)
        ):
            raise BridgeError(
                "schema-12 post-export successor candidate activation is incomplete"
            )
    return current


def _successor_post_export_executor_continuation_precondition(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    terminal_path: Path,
    completion_path: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    continuation_value: Mapping[str, object] | None = None,
    allow_existing_successor_candidate: bool = False,
    source_broker_state: Mapping[str, object] | None = None,
) -> dict[str, object]:
    binding_value = current.get("binding")
    profile_value = current.get("profile")
    if (
        current.get("phase") != "candidate-activation-intent"
        or current.get("candidate") != {"activation": None, "readiness": None}
        or not isinstance(binding_value, Mapping)
        or not isinstance(profile_value, Mapping)
        or terminal_path.exists()
        or terminal_path.is_symlink()
        or completion_path.exists()
        or completion_path.is_symlink()
    ):
        raise BridgeError(
            "schema-12 post-export continuation is outside its exact boundary"
        )
    binding = dict(binding_value)
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    handoff = _validated_successor_executor_handoff(
        binding.get("executor_rescue_handoff"), expected_uid=expected_uid
    )
    if "executor_rescue_post_export_continuation" in binding:
        raise BridgeError(
            "schema-12 post-export executor continuation is already published"
        )
    runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
    )
    maintenance_handoff = binding.get("maintenance_handoff")
    predecessor_proof = (
        maintenance_handoff.get("predecessor_proof")
        if isinstance(maintenance_handoff, Mapping)
        else None
    )
    readiness_origin = (
        predecessor_proof.get("readiness_origin")
        if isinstance(predecessor_proof, Mapping)
        else None
    )
    owner_binding_refresh = profile_value.get("owner_binding_refresh")
    with _broker_service_lock(database, expected_uid=expected_uid):
        profile_identity = _profile_identity(profile, uid=expected_uid)
        export = profile_value.get("export_evidence")
        repaired_sha256 = profile_value.get("repaired_payload_sha256")
        database_bundle = _sqlite_bundle_evidence(
            database, expected_uid=expected_uid
        )
        database_readiness = (
            _readiness_proof(
                Path(str(binding.get("readiness_attestation"))),
                database=database,
                uid=expected_uid,
                descendant_of=readiness_origin,
            )
            if isinstance(readiness_origin, Mapping)
            else None
        )
        export_database_identity = (
            export.get("database_identity")
            if isinstance(export, Mapping)
            else None
        )
        stable_export_database_identity = (
            {
                field: export_database_identity[field]
                for field in ("device", "inode", "size")
            }
            if isinstance(export_database_identity, Mapping)
            and all(
                field in export_database_identity
                for field in ("device", "inode", "size")
            )
            else None
        )
        readiness_state_revision = (
            database_readiness.get("state_revision")
            if isinstance(database_readiness, Mapping)
            else None
        )
        refreshed_state_revision = (
            owner_binding_refresh.get("refreshed_source_state_revision")
            if isinstance(owner_binding_refresh, Mapping)
            else None
        )
        if (
            _successor_binding_without_client_handoff(binding)
            != _successor_binding_without_client_handoff(requested_binding)
            or profile_value.get("after_identity") != profile_identity
            or profile_value.get("restored_identity") is not None
            or repaired_sha256 != profile_identity.get("sha256")
            or not isinstance(export, Mapping)
            or export.get("profile_sha256") != repaired_sha256
            or export.get("database_generation")
            != requested_binding.get("expected_database_generation")
            or not isinstance(database_readiness, Mapping)
            or database_readiness.get("database_generation")
            != requested_binding.get("expected_database_generation")
            or database_readiness.get("database_identity")
            != stable_export_database_identity
            or not isinstance(owner_binding_refresh, Mapping)
            or _sha256_bytes(_canonical(owner_binding_refresh))
            != runtime.get("owner_binding_refresh_sha256")
            or isinstance(readiness_state_revision, bool)
            or not isinstance(readiness_state_revision, int)
            or isinstance(refreshed_state_revision, bool)
            or not isinstance(refreshed_state_revision, int)
            or readiness_state_revision < refreshed_state_revision
            or export.get("owner_map") != profile_value.get("owner_binding")
            or profile_value.get("owner_binding") != binding.get("owner_map")
            or owner_binding_refresh.get("refreshed")
            != profile_value.get("owner_binding")
            or profile_value.get("owner_binding_sha256")
            != binding.get("owner_map", {}).get("document_sha256")
        ):
            raise BridgeError(
                "schema-12 post-export repaired profile binding changed"
            )
        _successor_profile_backup_reference(
            profile_value, expected_uid=expected_uid
        )
    _ensure_successor_maintenance(binding.get("maintenance"), uid=expected_uid)
    failed_candidate = _failed_post_export_candidate_reference(
        binding,
        expected_runtime=runtime,
        expected_uid=expected_uid,
    )
    successor_transaction = (
        Path(str(binding["candidate_transaction"])).parent
        / SUCCESSOR_POST_EXPORT_CANDIDATE_DIRECTORY
    )
    successor_operation = str(
        uuid.uuid5(
            uuid.UUID(str(current["operation_id"])),
            "schema12-clean-successor-post-export-candidate",
        )
    )
    successor_candidate: dict[str, object] | None = None
    successor_exists = (
        successor_transaction.exists() or successor_transaction.is_symlink()
    )
    if successor_exists:
        if (
            not allow_existing_successor_candidate
            or continuation_value is None
        ):
            raise BridgeError(
                "schema-12 post-export successor candidate already exists"
            )
        successor_candidate = _existing_post_export_successor_candidate(
            transaction=successor_transaction,
            operation_id=successor_operation,
            binding=binding,
            rescue=rescue,
            handoff=handoff,
            continuation=continuation_value,
            expected_uid=expected_uid,
        )
    broker_state = _systemd_state()
    successor_phase = (
        successor_candidate.get("phase")
        if isinstance(successor_candidate, Mapping)
        else None
    )
    if successor_phase in {"systemd-ready", "ready"}:
        activation = successor_candidate["activation"]
        systemd = activation["systemd"]
        if (
            broker_state.get("ActiveState") != "active"
            or not isinstance(broker_state.get("MainPID"), int)
            or broker_state.get("MainPID", 0) <= 0
            or broker_state.get("InvocationID") != systemd.get("InvocationID")
            or not broker_socket.exists()
            or broker_socket.is_symlink()
            or not dropin.exists()
            or dropin.is_symlink()
        ):
            raise BridgeError(
                "schema-12 post-export active successor boundary changed"
            )
        _verify_dropin_identity(
            dropin,
            successor_candidate.get("dropin_identity"),
            uid=expected_uid,
            expected_sha256=str(successor_candidate["dropin_sha256"]),
        )
        execution = _verify_loaded_bridge_execution(
            release=Path(str(binding["candidate_release"])),
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
        if execution != activation.get("execution"):
            raise BridgeError(
                "schema-12 post-export active successor execution changed"
            )
    elif (
        broker_state.get("ActiveState") != "inactive"
        or broker_state.get("SubState") != "dead"
        or broker_state.get("MainPID") != 0
        or broker_socket.exists()
        or broker_socket.is_symlink()
        or dropin.exists()
        or dropin.is_symlink()
    ):
        raise BridgeError(
            "schema-12 post-export continuation broker boundary changed"
        )
    return {
        "profile_identity": profile_identity,
        "profile_state_sha256": _sha256_bytes(_canonical(profile_value)),
        "profile_export_sha256": _sha256_bytes(_canonical(export)),
        "database_bundle": database_bundle,
        "database_readiness": database_readiness,
        "broker_state": (
            dict(source_broker_state)
            if successor_exists and source_broker_state is not None
            else broker_state
        ),
        "failed_candidate": failed_candidate,
        "successor_candidate_transaction": str(successor_transaction),
        "successor_candidate_operation_id": successor_operation,
    }


def _validate_successor_post_export_executor_continuation_request(
    value: object,
    *,
    current: Mapping[str, object] | None,
    release_pair: Mapping[str, object],
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    expected_uid: int,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != (
        _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REQUEST_FIELDS
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation request fields are invalid"
        )
    request = dict(value)
    for field in (
        "previous_executor_release",
        "retained_client_release",
        "successor_executor_release",
    ):
        request[field] = str(
            _absolute(
                Path(str(request[field])),
                f"schema-12 post-export continuation {field}",
            )
        )
    digest_fields = {
        "inherited_journal_raw_sha256",
        "inherited_journal_document_sha256",
        "executor_rescue_sha256",
        "executor_rescue_handoff_sha256",
        "previous_executor_release_digest",
        "retained_client_release_digest",
        "successor_executor_release_digest",
    }
    binding = current.get("binding") if isinstance(current, Mapping) else None
    rescue = (
        _validated_successor_executor_rescue(
            binding.get("executor_rescue"), expected_uid=expected_uid
        )
        if isinstance(binding, Mapping)
        else None
    )
    handoff = (
        _validated_successor_executor_handoff(
            binding.get("executor_rescue_handoff"), expected_uid=expected_uid
        )
        if isinstance(binding, Mapping)
        else None
    )
    existing = (
        _validated_successor_post_export_executor_continuation(
            binding.get("executor_rescue_post_export_continuation"),
            expected_uid=expected_uid,
        )
        if isinstance(binding, Mapping)
        and binding.get("executor_rescue_post_export_continuation") is not None
        else None
    )
    first_publication = (
        existing is None
        and isinstance(current, Mapping)
        and current.get("phase") == "candidate-activation-intent"
        and current.get("document_sha256") == inherited_document_sha256
    )
    retained_replay = (
        isinstance(existing, Mapping)
        and existing.get("journal_raw_sha256") == inherited_journal_sha256
        and existing.get("journal_document_sha256")
        == inherited_document_sha256
        and all(
            existing.get(field) == request[field]
            for field in (
                "executor_rescue_sha256",
                "executor_rescue_handoff_sha256",
                "previous_executor_release",
                "previous_executor_release_digest",
                "retained_client_release",
                "retained_client_release_digest",
                "successor_executor_release",
                "successor_executor_release_digest",
            )
        )
    )
    running = ROOT.resolve(strict=True)
    prohibited_executor_paths = (
        {
            str(rescue["rescue_executor_release"]),
            str(rescue["client_release"]),
            str(handoff["successor_executor_release"]),
            str(binding.get("candidate_release")),
        }
        if isinstance(rescue, Mapping) and isinstance(handoff, Mapping)
        else set()
    )
    prohibited_executor_digests = (
        {
            str(rescue["rescue_executor_release_digest"]),
            str(rescue["client_release_digest"]),
            str(handoff["successor_executor_release_digest"]),
            str(binding.get("candidate_release_digest")),
        }
        if isinstance(rescue, Mapping) and isinstance(handoff, Mapping)
        else set()
    )
    if (
        request["reason"]
        != SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON
        or request["continuation_path"]
        != SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH
        or any(
            RELEASE_RE.fullmatch(str(request[field])) is None
            for field in digest_fields
        )
        or not (first_publication or retained_replay)
        or inherited_journal_sha256
        != request["inherited_journal_raw_sha256"]
        or inherited_document_sha256
        != request["inherited_journal_document_sha256"]
        or not isinstance(rescue, Mapping)
        or not isinstance(handoff, Mapping)
        or request["executor_rescue_sha256"]
        != _sha256_bytes(_canonical(rescue))
        or request["executor_rescue_handoff_sha256"]
        != _sha256_bytes(_canonical(handoff))
        or request["previous_executor_release"]
        != handoff["successor_executor_release"]
        or request["previous_executor_release_digest"]
        != handoff["successor_executor_release_digest"]
        or request["retained_client_release"] != rescue["client_release"]
        or request["retained_client_release_digest"]
        != rescue["client_release_digest"]
        or request["successor_executor_release"] != str(running)
        or request["successor_executor_release_digest"] != running.name
        or request["successor_executor_release"] in prohibited_executor_paths
        or request["successor_executor_release_digest"]
        in prohibited_executor_digests
        or request["retained_client_release"]
        != release_pair.get("client_release")
        or request["successor_executor_release"]
        != release_pair.get("executor_release")
        or release_pair.get("historical_client") is not True
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation request binding changed"
        )
    return request


def _verify_retained_successor_post_export_executor_continuation(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    intent_path: Path,
    journal_backup_path: Path,
    failed_candidate_backup_path: Path,
    inherited_journal_sha256: str,
    inherited_document_sha256: str,
    terminal_path: Path,
    completion_path: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    require_prelaunch_boundary: bool,
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError(
            "schema-12 post-export executor continuation lacks its binding"
        )
    binding = dict(binding_value)
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    handoff = _validated_successor_executor_handoff(
        binding.get("executor_rescue_handoff"), expected_uid=expected_uid
    )
    continuation = _validated_successor_post_export_executor_continuation(
        binding.get("executor_rescue_post_export_continuation"),
        expected_uid=expected_uid,
    )
    if (
        continuation["operation_id"] != current.get("operation_id")
        or continuation["journal_raw_sha256"] != inherited_journal_sha256
        or continuation["journal_document_sha256"]
        != inherited_document_sha256
        or continuation["executor_rescue_sha256"]
        != _sha256_bytes(_canonical(rescue))
        or continuation["executor_rescue_handoff_sha256"]
        != _sha256_bytes(_canonical(handoff))
        or continuation["successor_executor_release"]
        != release_pair.get("executor_release")
        or continuation["successor_executor_release_digest"]
        != release_pair.get("executor_release_digest")
        or continuation["retained_client_release"]
        != release_pair.get("client_release")
        or continuation["retained_client_release_digest"]
        != release_pair.get("client_release_digest")
        or continuation["intent"] != str(intent_path)
        or continuation["journal_backup"] != str(journal_backup_path)
        or continuation["failed_candidate_backup"]
        != str(failed_candidate_backup_path)
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation lineage changed"
        )
    intent_payload, intent_identity, intent_value = _stable_private_json_bytes(
        intent_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation intent",
    )
    intent = _verify_successor_post_export_executor_continuation_intent(
        intent_value
    )
    backup_payload, backup_identity, backup_value = _stable_private_json_bytes(
        journal_backup_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation preimage",
    )
    preimage = _verify_successor_journal(backup_value)
    source_binding = dict(binding)
    source_binding.pop("executor_rescue_post_export_continuation", None)
    source_runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
    )
    failed_candidate = _failed_post_export_candidate_reference(
        source_binding,
        expected_runtime=source_runtime,
        expected_uid=expected_uid,
    )
    failed_payload, failed_identity, failed_value = _stable_private_json_bytes(
        Path(str(failed_candidate["journal"])),
        uid=expected_uid,
        label="schema-12 retained failed candidate journal",
    )
    failed_document = _verify_failed_post_export_candidate_document(
        failed_value,
        binding=source_binding,
        expected_runtime=source_runtime,
    )
    (
        failed_backup_payload,
        failed_backup_identity,
        failed_backup_value,
    ) = _stable_private_json_bytes(
        failed_candidate_backup_path,
        uid=expected_uid,
        label="schema-12 retained failed candidate backup",
    )
    failed_backup_document = _verify_failed_post_export_candidate_document(
        failed_backup_value,
        binding=source_binding,
        expected_runtime=source_runtime,
    )
    if (
        any(
            intent[field] != continuation[field]
            for field in _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS
        )
        or intent_identity != continuation["intent_identity"]
        or intent_identity["sha256"] != continuation["intent_raw_sha256"]
        or backup_identity != continuation["journal_backup_identity"]
        or backup_identity["sha256"] != continuation["journal_raw_sha256"]
        or failed_candidate != continuation["failed_candidate"]
        or failed_identity != failed_candidate["journal_identity"]
        or failed_payload != failed_backup_payload
        or failed_document != failed_backup_document
        or failed_backup_identity
        != continuation["failed_candidate_backup_identity"]
        or failed_backup_identity["sha256"]
        != failed_candidate["journal_raw_sha256"]
        or preimage is None
        or preimage.get("phase") != "candidate-activation-intent"
        or preimage.get("document_sha256")
        != continuation["journal_document_sha256"]
        or preimage.get("binding") != source_binding
        or _sha256_bytes(_canonical(source_binding))
        != continuation["source_binding_sha256"]
        or preimage.get("profile") != current.get("profile")
        or _sha256_bytes(_canonical(current.get("profile")))
        != continuation["source_profile_state_sha256"]
        or not intent_payload
        or not backup_payload
        or _successor_binding_without_client_handoff(source_binding)
        != _successor_binding_without_client_handoff(requested_binding)
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation state changed"
        )
    runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
        continuation_value=continuation,
    )
    _verify_successor_executor_rescue_runtime_binding(
        runtime,
        client_release=Path(str(rescue["client_release"])),
        expected_uid=expected_uid,
    )
    if require_prelaunch_boundary:
        if preimage is None:
            raise BridgeError(
                "schema-12 post-export continuation prelaunch preimage is absent"
            )
        live_state = _successor_post_export_executor_continuation_precondition(
            preimage,
            requested_binding=requested_binding,
            terminal_path=terminal_path,
            completion_path=completion_path,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
            continuation_value=continuation,
            allow_existing_successor_candidate=True,
            source_broker_state=(
                continuation.get("live_state", {}).get("broker_state")
                if isinstance(continuation.get("live_state"), Mapping)
                and isinstance(
                    continuation.get("live_state", {}).get("broker_state"),
                    Mapping,
                )
                else None
            ),
        )
        if live_state != continuation["live_state"]:
            raise BridgeError(
                "schema-12 post-export continuation prelaunch boundary changed"
            )
    return dict(current)


def _migrate_successor_post_export_executor_continuation(
    current: Mapping[str, object],
    *,
    request: Mapping[str, object],
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    journal_path: Path,
    intent_path: Path,
    journal_backup_path: Path,
    failed_candidate_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str,
    inherited_document_sha256: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    failpoint: Callable[[str], None],
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError(
            "schema-12 post-export executor continuation lacks its binding"
        )
    binding = dict(binding_value)
    if "executor_rescue_post_export_continuation" in binding:
        return _verify_retained_successor_post_export_executor_continuation(
            current,
            requested_binding=requested_binding,
            release_pair=release_pair,
            intent_path=intent_path,
            journal_backup_path=journal_backup_path,
            failed_candidate_backup_path=failed_candidate_backup_path,
            inherited_journal_sha256=inherited_journal_sha256,
            inherited_document_sha256=inherited_document_sha256,
            terminal_path=terminal_path,
            completion_path=completion_path,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
            require_prelaunch_boundary=(
                current.get("phase") == "candidate-activation-intent"
            ),
        )
    _validate_successor_post_export_executor_continuation_request(
        request,
        current=current,
        release_pair=release_pair,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        expected_uid=expected_uid,
    )
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    handoff = _validated_successor_executor_handoff(
        binding.get("executor_rescue_handoff"), expected_uid=expected_uid
    )
    source_payload, source_identity, source_value = _stable_private_json_bytes(
        journal_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation source journal",
    )
    if (
        source_identity["sha256"] != inherited_journal_sha256
        or _verify_successor_journal(source_value) != current
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation digest changed"
        )
    live_state = _successor_post_export_executor_continuation_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    intent_binding = {
        "reason": SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON,
        "continuation_path": SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH,
        "operation_id": current["operation_id"],
        "phase": "candidate-activation-intent",
        "journal_backup": str(journal_backup_path),
        "journal_raw_sha256": inherited_journal_sha256,
        "journal_document_sha256": inherited_document_sha256,
        "journal_identity": source_identity,
        "source_binding_sha256": _sha256_bytes(_canonical(binding)),
        "executor_rescue_sha256": _sha256_bytes(_canonical(rescue)),
        "executor_rescue_handoff_sha256": _sha256_bytes(_canonical(handoff)),
        "previous_executor_release": handoff["successor_executor_release"],
        "previous_executor_release_digest": handoff[
            "successor_executor_release_digest"
        ],
        "successor_executor_release": release_pair["executor_release"],
        "successor_executor_release_digest": release_pair[
            "executor_release_digest"
        ],
        "retained_client_release": rescue["client_release"],
        "retained_client_release_digest": rescue["client_release_digest"],
        "candidate_release": binding["candidate_release"],
        "candidate_release_digest": binding["candidate_release_digest"],
        "failed_candidate": live_state["failed_candidate"],
        "failed_candidate_backup": str(failed_candidate_backup_path),
        "successor_candidate_transaction": live_state[
            "successor_candidate_transaction"
        ],
        "successor_candidate_operation_id": live_state[
            "successor_candidate_operation_id"
        ],
        "source_profile_state_sha256": live_state["profile_state_sha256"],
        "source_profile_export_sha256": live_state["profile_export_sha256"],
        "live_state": live_state,
    }
    intent = _load_successor_post_export_executor_continuation_intent(
        intent_path, uid=expected_uid
    )
    if intent is None:
        intent = _verify_successor_post_export_executor_continuation_intent(
            _seal(
                SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_KIND,
                {**intent_binding, "recorded_at_epoch": int(time.time())},
            )
        )
        _atomic_private_json(intent_path, intent, uid=expected_uid)
    elif any(intent[field] != expected for field, expected in intent_binding.items()):
        raise BridgeError(
            "schema-12 post-export executor continuation intent changed"
        )
    intent_payload, intent_identity, retained_intent = _stable_private_json_bytes(
        intent_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation intent",
    )
    if _verify_successor_post_export_executor_continuation_intent(
        retained_intent
    ) != intent:
        raise BridgeError(
            "schema-12 post-export executor continuation intent changed"
        )
    failpoint("after-successor-post-export-executor-continuation-intent")
    _write_private_bytes_once(
        journal_backup_path, source_payload, uid=expected_uid
    )
    backup_payload, backup_identity, backup_value = _stable_private_json_bytes(
        journal_backup_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation preimage",
    )
    if (
        backup_payload != source_payload
        or _verify_successor_journal(backup_value) != current
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation preimage changed"
        )
    failpoint("after-successor-post-export-executor-continuation-backup")
    failed_source_path = Path(
        str(live_state["failed_candidate"]["journal"])
    )
    (
        failed_source_payload,
        failed_source_identity,
        failed_source_value,
    ) = _stable_private_json_bytes(
        failed_source_path,
        uid=expected_uid,
        label="schema-12 post-export failed candidate source journal",
    )
    source_runtime = _successor_executor_rescue_runtime_binding(
        rescue,
        expected_uid=expected_uid,
        handoff_value=handoff,
    )
    _verify_failed_post_export_candidate_document(
        failed_source_value,
        binding=binding,
        expected_runtime=source_runtime,
    )
    if (
        failed_source_identity
        != live_state["failed_candidate"]["journal_identity"]
        or _sha256_bytes(failed_source_payload)
        != live_state["failed_candidate"]["journal_raw_sha256"]
    ):
        raise BridgeError(
            "schema-12 post-export failed candidate changed before backup"
        )
    _write_private_bytes_once(
        failed_candidate_backup_path,
        failed_source_payload,
        uid=expected_uid,
    )
    (
        failed_backup_payload,
        failed_backup_identity,
        failed_backup_value,
    ) = _stable_private_json_bytes(
        failed_candidate_backup_path,
        uid=expected_uid,
        label="schema-12 post-export failed candidate backup",
    )
    _verify_failed_post_export_candidate_document(
        failed_backup_value,
        binding=binding,
        expected_runtime=source_runtime,
    )
    if failed_backup_payload != failed_source_payload:
        raise BridgeError(
            "schema-12 post-export failed candidate backup changed"
        )
    failpoint(
        "after-successor-post-export-executor-continuation-failed-candidate-backup"
    )
    retained_payload, retained_identity, retained_value = _stable_private_json_bytes(
        journal_path,
        uid=expected_uid,
        label="schema-12 post-export executor continuation source journal",
    )
    retained_live_state = _successor_post_export_executor_continuation_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    if (
        retained_payload != source_payload
        or retained_identity != source_identity
        or _verify_successor_journal(retained_value) != current
        or retained_live_state != live_state
    ):
        raise BridgeError(
            "schema-12 post-export executor continuation state changed before publication"
        )
    _ensure_successor_maintenance(binding.get("maintenance"), uid=expected_uid)
    continuation = _validated_successor_post_export_executor_continuation(
        {
            **{
                field: intent[field]
                for field in _SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_FIELDS
            },
            "journal_backup_identity": backup_identity,
            "failed_candidate_backup_identity": failed_backup_identity,
            "intent": str(intent_path),
            "intent_raw_sha256": _sha256_bytes(intent_payload),
            "intent_document_sha256": intent["document_sha256"],
            "intent_identity": intent_identity,
        },
        expected_uid=expected_uid,
    )
    successor_binding = dict(binding)
    successor_binding["executor_rescue_post_export_continuation"] = continuation
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["binding"] = successor_binding
    payload["updated_at_epoch"] = int(time.time())
    migrated = _successor_journal(journal_path, payload, uid=expected_uid)
    failpoint("after-successor-post-export-executor-continuation")
    return _verify_retained_successor_post_export_executor_continuation(
        migrated,
        requested_binding=requested_binding,
        release_pair=release_pair,
        intent_path=intent_path,
        journal_backup_path=journal_backup_path,
        failed_candidate_backup_path=failed_candidate_backup_path,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
        require_prelaunch_boundary=True,
    )


def _successor_executor_rescue_sha256(
    binding: Mapping[str, object], *, expected_uid: int
) -> str | None:
    rescue = binding.get("executor_rescue")
    if rescue is None:
        return None
    verified = _validated_successor_executor_rescue(
        rescue, expected_uid=expected_uid
    )
    return _sha256_bytes(_canonical(verified))


def _successor_effective_candidate_target(
    binding: Mapping[str, object], *, expected_uid: int, create: bool
) -> tuple[Path, str]:
    transaction = _absolute(
        Path(str(binding.get("candidate_transaction"))),
        "schema-12 successor candidate transaction",
    )
    operation_id = str(binding.get("candidate_operation_id"))
    continuation_value = binding.get(
        "executor_rescue_post_export_continuation"
    )
    if continuation_value is not None:
        continuation = _validated_successor_post_export_executor_continuation(
            continuation_value, expected_uid=expected_uid
        )
        transaction = _absolute(
            Path(str(continuation["successor_candidate_transaction"])),
            "schema-12 post-export successor candidate transaction",
        )
        operation_id = str(continuation["successor_candidate_operation_id"])
        expected_transaction = (
            Path(str(binding["candidate_transaction"])).parent
            / SUCCESSOR_POST_EXPORT_CANDIDATE_DIRECTORY
        )
        expected_operation = str(
            uuid.uuid5(
                uuid.UUID(str(continuation["operation_id"])),
                "schema12-clean-successor-post-export-candidate",
            )
        )
        if transaction != expected_transaction or operation_id != expected_operation:
            raise BridgeError(
                "schema-12 post-export successor candidate lineage changed"
            )
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "schema-12 successor candidate operation is invalid"
        ) from error
    if create:
        transaction = _private_directory(
            transaction, uid=expected_uid, create=True
        )
    else:
        transaction = _private_directory(transaction, uid=expected_uid)
    return transaction, operation_id


def _verify_retained_successor_executor_rescue(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError("schema-12 successor executor rescue lacks its binding")
    binding = dict(binding_value)
    rescue = _validated_successor_executor_rescue(
        binding.get("executor_rescue"), expected_uid=expected_uid
    )
    executor_handoff = (
        _validated_successor_executor_handoff(
            binding.get("executor_rescue_handoff"),
            expected_uid=expected_uid,
        )
        if binding.get("executor_rescue_handoff") is not None
        else None
    )
    post_export_continuation = (
        _validated_successor_post_export_executor_continuation(
            binding.get("executor_rescue_post_export_continuation"),
            expected_uid=expected_uid,
        )
        if binding.get("executor_rescue_post_export_continuation") is not None
        else None
    )
    effective_executor_release = (
        post_export_continuation["successor_executor_release"]
        if post_export_continuation is not None
        else (
            executor_handoff["successor_executor_release"]
            if executor_handoff is not None
            else rescue["rescue_executor_release"]
        )
    )
    effective_executor_digest = (
        post_export_continuation["successor_executor_release_digest"]
        if post_export_continuation is not None
        else (
            executor_handoff["successor_executor_release_digest"]
            if executor_handoff is not None
            else rescue["rescue_executor_release_digest"]
        )
    )
    if (
        current.get("phase")
        not in _SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES
        or current.get("operation_id") != rescue["operation_id"]
        or inherited_journal_sha256 != rescue["journal_raw_sha256"]
        or inherited_document_sha256 != rescue["journal_document_sha256"]
        or release_pair.get("historical_client") is not True
        or release_pair.get("client_release") != rescue["client_release"]
        or release_pair.get("client_release_digest")
        != rescue["client_release_digest"]
        or release_pair.get("executor_release")
        != effective_executor_release
        or release_pair.get("executor_release_digest")
        != effective_executor_digest
        or requested_binding.get("client_release") != rescue["client_release"]
        or requested_binding.get("client_release_digest")
        != rescue["client_release_digest"]
        or binding.get("client_release") != rescue["client_release"]
        or binding.get("client_release_digest") != rescue["client_release_digest"]
        or rescue["intent"] != str(intent_path)
        or rescue["journal_backup"] != str(journal_backup_path)
    ):
        raise BridgeError("schema-12 successor executor rescue lineage changed")
    intent_payload, intent_identity, intent_value = _stable_private_json_bytes(
        intent_path,
        uid=expected_uid,
        label="schema-12 successor executor rescue intent",
    )
    intent = _verify_successor_executor_rescue_intent(intent_value)
    intent_mismatches = [
        field
        for field in _SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS
        if intent[field] != rescue[field]
    ]
    if intent_identity != rescue["intent_identity"]:
        intent_mismatches.append("intent_identity")
    if intent_identity["sha256"] != rescue["intent_raw_sha256"]:
        intent_mismatches.append("intent_raw_sha256")
    if intent["document_sha256"] != rescue["intent_document_sha256"]:
        intent_mismatches.append("intent_document_sha256")
    if intent_mismatches:
        raise BridgeError(
            "schema-12 successor executor rescue intent changed: "
            + ", ".join(sorted(set(intent_mismatches)))
        )
    backup_payload, backup_identity, backup_value = _stable_private_json_bytes(
        journal_backup_path,
        uid=expected_uid,
        label="schema-12 successor executor rescue journal preimage",
    )
    preimage = _verify_successor_journal(backup_value)
    if (
        preimage is None
        or backup_identity != rescue["journal_backup_identity"]
        or backup_identity["sha256"] != rescue["journal_raw_sha256"]
        or preimage.get("document_sha256")
        != rescue["journal_document_sha256"]
        or preimage.get("phase") != "predecessor-retired"
        or preimage.get("operation_id") != current.get("operation_id")
        or not isinstance(preimage.get("binding"), dict)
        or "executor_rescue" in preimage["binding"]
        or _sha256_bytes(_canonical(preimage["binding"]))
        != rescue["source_binding_sha256"]
    ):
        raise BridgeError("schema-12 successor executor rescue preimage changed")
    source_binding = dict(binding)
    source_binding.pop("executor_rescue", None)
    source_binding.pop("executor_rescue_handoff", None)
    source_binding.pop(
        "executor_rescue_post_export_continuation", None
    )
    current_profile = current.get("profile")
    retained_source_profile = _successor_executor_rescue_source_profile(
        current
    )
    retained_first_handoff = _successor_executor_rescue_first_handoff(
        current, expected_uid=expected_uid
    )
    sealed_lineage_value = rescue["predecessor_lineage"]
    if not isinstance(sealed_lineage_value, Mapping):
        raise BridgeError(
            "schema-12 successor executor rescue predecessor lineage changed"
        )
    _verify_retained_lifecycle_rearm_descriptor_lineage(
        sealed_lineage_value.get("outer_rearm"),
        {
            "rearm_journal": sealed_lineage_value.get(
                "rearm_journal"
            ),
            "outer_transaction": sealed_lineage_value.get(
                "outer_transaction"
            ),
        },
        expected_uid=expected_uid,
    )
    retained_predecessor_lineage = (
        _successor_executor_rescue_predecessor_lineage(
            current, expected_uid=expected_uid, require_absent=False
        )
    )
    sealed_predecessor_lineage = dict(rescue["predecessor_lineage"])
    sealed_absence = sealed_predecessor_lineage.pop("absence", None)
    retained_predecessor_lineage.pop("absence", None)
    refresh = (
        current_profile.get("owner_binding_refresh")
        if isinstance(current_profile, Mapping)
        else None
    )
    maintenance_handoff = binding.get("maintenance_handoff")
    if (
        not isinstance(refresh, Mapping)
        or not isinstance(maintenance_handoff, Mapping)
        or not isinstance(refresh.get("previous"), Mapping)
        or not isinstance(refresh.get("refreshed"), Mapping)
    ):
        raise BridgeError(
            "schema-12 successor executor rescue owner refresh changed"
        )
    verified_refresh = _verified_owner_map_refresh_relation(
        previous_reference=refresh["previous"],
        refreshed_reference=refresh["refreshed"],
        maintenance_handoff=maintenance_handoff,
        expected_uid=expected_uid,
    )
    if (
        source_binding != preimage["binding"]
        or _successor_binding_without_client_handoff(source_binding)
        != _successor_binding_without_client_handoff(requested_binding)
        or current.get("predecessor") != preimage.get("predecessor")
        or current.get("restored_predecessor")
        != preimage.get("restored_predecessor")
        or current.get("error") != preimage.get("error")
        or current.get("created_at_epoch") != preimage.get("created_at_epoch")
        or not isinstance(current_profile, Mapping)
        or retained_source_profile != rescue["source_profile"]
        or retained_first_handoff != rescue["first_handoff"]
        or retained_predecessor_lineage != sealed_predecessor_lineage
        or not isinstance(sealed_absence, Mapping)
        or verified_refresh != dict(refresh)
        or dict(refresh) != rescue["live_state"]["owner_binding_refresh"]
        or _sha256_bytes(_canonical(refresh))
        != rescue["owner_binding_refresh_sha256"]
        or not backup_payload
        or not intent_payload
    ):
        raise BridgeError("schema-12 successor executor rescue state changed")
    if current.get("phase") == "predecessor-retired":
        exact_predecessor_lineage = (
            _successor_executor_rescue_predecessor_lineage(
                current, expected_uid=expected_uid, require_absent=True
            )
        )
        if (
            exact_predecessor_lineage != rescue["predecessor_lineage"]
            or
            current_profile != preimage.get("profile")
            or current.get("candidate")
            != {"activation": None, "readiness": None}
            or terminal_path.exists()
            or terminal_path.is_symlink()
            or completion_path.exists()
            or completion_path.is_symlink()
            or current_profile.get("repaired_payload_sha256") is not None
            or current_profile.get("after_identity") is not None
            or current_profile.get("restored_identity") is not None
            or "export_evidence" in current_profile
        ):
            raise BridgeError(
                "schema-12 successor executor rescue left its pre-export phase"
            )
        live_state = _successor_executor_rescue_precondition(
            current,
            requested_binding=requested_binding,
            terminal_path=terminal_path,
            completion_path=completion_path,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
        )
        if live_state != rescue["live_state"]:
            raise BridgeError(
                "schema-12 successor executor rescue live state changed"
            )
    return dict(current)


def _migrate_inherited_successor_executor_rescue(
    current: Mapping[str, object],
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    journal_path: Path,
    intent_path: Path,
    journal_backup_path: Path,
    terminal_path: Path,
    completion_path: Path,
    inherited_journal_sha256: str | None,
    inherited_document_sha256: str | None,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
    failpoint: Callable[[str], None],
) -> dict[str, object]:
    binding_value = current.get("binding")
    if not isinstance(binding_value, Mapping):
        raise BridgeError("schema-12 successor executor rescue lacks its binding")
    binding = dict(binding_value)
    if "executor_rescue" in binding:
        return _verify_retained_successor_executor_rescue(
            current,
            requested_binding=requested_binding,
            release_pair=release_pair,
            intent_path=intent_path,
            journal_backup_path=journal_backup_path,
            terminal_path=terminal_path,
            completion_path=completion_path,
            inherited_journal_sha256=inherited_journal_sha256,
            inherited_document_sha256=inherited_document_sha256,
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=expected_uid,
        )
    if (
        release_pair.get("historical_client") is not True
        or current.get("phase") != "predecessor-retired"
        or inherited_journal_sha256 is None
        or inherited_document_sha256 is None
        or current.get("document_sha256") != inherited_document_sha256
    ):
        raise BridgeError(
            "schema-12 successor executor rescue requires exact inherited digests"
        )
    handoffs = binding.get("client_release_handoffs")
    if not isinstance(handoffs, list) or len(handoffs) != 1:
        raise BridgeError(
            "schema-12 successor executor rescue requires one client handoff"
        )
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    previous_executor = handoff["successor_client_release"]
    previous_executor_digest = handoff["successor_client_release_digest"]
    if (
        handoff["phase"] != "predecessor-retired"
        or binding.get("client_release") != previous_executor
        or binding.get("client_release_digest") != previous_executor_digest
        or requested_binding.get("client_release") != previous_executor
        or requested_binding.get("client_release_digest")
        != previous_executor_digest
        or release_pair.get("client_release") != previous_executor
        or release_pair.get("client_release_digest")
        != previous_executor_digest
        or release_pair.get("executor_release") == previous_executor
        or release_pair.get("executor_release_digest")
        == previous_executor_digest
    ):
        raise BridgeError("schema-12 successor executor rescue identity changed")
    source_payload, source_identity, source_value = _stable_private_json_bytes(
        journal_path,
        uid=expected_uid,
        label="schema-12 successor executor rescue source journal",
    )
    if (
        source_identity["sha256"] != inherited_journal_sha256
        or _verify_successor_journal(source_value) != current
    ):
        raise BridgeError("schema-12 successor executor rescue digest changed")
    live_state = _successor_executor_rescue_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    intent_binding = {
        "reason": SUCCESSOR_EXECUTOR_RESCUE_REASON,
        "rescue_path": SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "operation_id": current["operation_id"],
        "phase": "predecessor-retired",
        "journal_backup": str(journal_backup_path),
        "journal_raw_sha256": inherited_journal_sha256,
        "journal_document_sha256": inherited_document_sha256,
        "journal_identity": source_identity,
        "source_binding_sha256": _sha256_bytes(_canonical(binding)),
        "client_release": previous_executor,
        "client_release_digest": previous_executor_digest,
        "previous_executor_release": previous_executor,
        "previous_executor_release_digest": previous_executor_digest,
        "rescue_executor_release": release_pair["executor_release"],
        "rescue_executor_release_digest": release_pair[
            "executor_release_digest"
        ],
        "source_profile": _successor_executor_rescue_source_profile(
            current
        ),
        "predecessor_lineage": live_state["predecessor_lineage"],
        "first_handoff": _successor_executor_rescue_first_handoff(
            current, expected_uid=expected_uid
        ),
        "owner_binding_refresh_sha256": _sha256_bytes(
            _canonical(live_state["owner_binding_refresh"])
        ),
        "live_state": live_state,
    }
    intent = _load_successor_executor_rescue_intent(
        intent_path, uid=expected_uid
    )
    if intent is None:
        intent = _verify_successor_executor_rescue_intent(
            _seal(
                SUCCESSOR_EXECUTOR_RESCUE_INTENT_KIND,
                {**intent_binding, "recorded_at_epoch": int(time.time())},
            )
        )
        _atomic_private_json(intent_path, intent, uid=expected_uid)
    elif any(
        intent[field] != expected
        for field, expected in intent_binding.items()
    ):
        raise BridgeError("schema-12 successor executor rescue intent changed")
    intent_payload, intent_identity, retained_intent_value = (
        _stable_private_json_bytes(
            intent_path,
            uid=expected_uid,
            label="schema-12 successor executor rescue intent",
        )
    )
    if _verify_successor_executor_rescue_intent(retained_intent_value) != intent:
        raise BridgeError("schema-12 successor executor rescue intent changed")
    failpoint("after-successor-executor-rescue-intent")
    _write_private_bytes_once(
        journal_backup_path, source_payload, uid=expected_uid
    )
    backup_payload, backup_identity, backup_value = _stable_private_json_bytes(
        journal_backup_path,
        uid=expected_uid,
        label="schema-12 successor executor rescue journal preimage",
    )
    if (
        backup_payload != source_payload
        or _verify_successor_journal(backup_value) != current
    ):
        raise BridgeError("schema-12 successor executor rescue preimage changed")
    failpoint("after-successor-executor-rescue-backup")
    retained_payload, retained_identity, retained_value = (
        _stable_private_json_bytes(
            journal_path,
            uid=expected_uid,
            label="schema-12 successor executor rescue source journal",
        )
    )
    retained_live_state = _successor_executor_rescue_precondition(
        current,
        requested_binding=requested_binding,
        terminal_path=terminal_path,
        completion_path=completion_path,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )
    if (
        retained_payload != source_payload
        or retained_identity != source_identity
        or _verify_successor_journal(retained_value) != current
        or retained_live_state != live_state
    ):
        raise BridgeError(
            "schema-12 successor executor rescue state changed before publication"
        )
    _ensure_successor_maintenance(binding["maintenance"], uid=expected_uid)
    rescue = _validated_successor_executor_rescue(
        {
            **{field: intent[field] for field in _SUCCESSOR_EXECUTOR_RESCUE_INTENT_FIELDS},
            "journal_backup_identity": backup_identity,
            "intent": str(intent_path),
            "intent_raw_sha256": _sha256_bytes(intent_payload),
            "intent_document_sha256": intent["document_sha256"],
            "intent_identity": intent_identity,
        },
        expected_uid=expected_uid,
    )
    successor_binding = dict(binding)
    successor_binding["executor_rescue"] = rescue
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["binding"] = successor_binding
    payload["updated_at_epoch"] = int(time.time())
    migrated = _successor_journal(journal_path, payload, uid=expected_uid)
    failpoint("after-successor-executor-rescue")
    return _verify_retained_successor_executor_rescue(
        migrated,
        requested_binding=requested_binding,
        release_pair=release_pair,
        intent_path=intent_path,
        journal_backup_path=journal_backup_path,
        terminal_path=terminal_path,
        completion_path=completion_path,
        inherited_journal_sha256=inherited_journal_sha256,
        inherited_document_sha256=inherited_document_sha256,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_uid=expected_uid,
    )


def _retired_successor_predecessor_dropin_boundary(
    current: Mapping[str, object], *, expected_uid: int
) -> dict[str, object] | None:
    """Return the one sealed absent predecessor boundary at retirement only."""

    phase = current.get("phase")
    if phase not in _SUCCESSOR_EXECUTOR_RESCUE_REPLAY_PHASES:
        return None
    binding = current.get("binding")
    predecessor = current.get("predecessor")
    handoffs = (
        binding.get("client_release_handoffs")
        if isinstance(binding, Mapping)
        else None
    )
    maintenance_handoff = (
        binding.get("maintenance_handoff")
        if isinstance(binding, Mapping)
        else None
    )
    executor_rescue = (
        binding.get("executor_rescue")
        if isinstance(binding, Mapping)
        else None
    )
    if not isinstance(handoffs, list) or not handoffs:
        if executor_rescue is None:
            return None
        raise BridgeError(
            "retired schema-12 successor lacks its client handoff boundary"
        )
    if (
        len(handoffs) != 1
        or not isinstance(predecessor, Mapping)
        or not isinstance(maintenance_handoff, Mapping)
    ):
        raise BridgeError(
            "retired schema-12 successor lacks its client handoff boundary"
        )
    handoff = _validated_successor_client_handoff(
        handoffs[0], expected_uid=expected_uid
    )
    ready_proof = _verify_successor_predecessor_proof(
        predecessor.get("ready_proof")
    )
    maintenance_proof = _verify_successor_predecessor_proof(
        maintenance_handoff.get("predecessor_proof")
    )
    boundary = handoff.get("predecessor_dropin")
    bound_identity = ready_proof.get("dropin_identity")
    bound_sha256 = (
        bound_identity.get("sha256")
        if isinstance(bound_identity, Mapping)
        else None
    )
    if (
        (phase != "predecessor-retired" and "executor_rescue" not in binding)
        or
        handoff.get("phase") != "predecessor-retired"
        or not isinstance(boundary, dict)
        or ready_proof.get("outer_rearm") is None
        or maintenance_proof.get("outer_rearm")
        != ready_proof.get("outer_rearm")
        or predecessor.get("dropin_identity") != bound_identity
        or predecessor.get("dropin_sha256") != bound_sha256
        or boundary.get("bound_identity") != bound_identity
        or boundary.get("bound_sha256") != bound_sha256
    ):
        raise BridgeError(
            "retired schema-12 successor handoff boundary is invalid"
        )
    return dict(boundary)


def _verify_successor_predecessor(
    predecessor: Mapping[str, object],
    *,
    expected_uid: int,
    retired_dropin_boundary: Mapping[str, object] | None = None,
    verify_retired_absence: bool = True,
) -> dict[str, object]:
    required = {
        "transaction",
        "operation_id",
        "journal",
        "journal_sha256",
        "document_sha256",
        "release",
        "release_digest",
        "dropin_sha256",
        "dropin_identity",
        "readiness_origin",
        "readiness_origin_sha256",
        "ready_proof",
    }
    if set(predecessor) != required:
        raise BridgeError("schema-12 successor predecessor fields are invalid")
    verified = _successor_predecessor_reference(
        transaction=Path(str(predecessor["transaction"])),
        operation_id=str(predecessor["operation_id"]),
        journal_sha256=str(predecessor["journal_sha256"]),
        document_sha256=str(predecessor["document_sha256"]),
        ready_proof=predecessor["ready_proof"],
        broker_socket=Path(
            str(
                _verify_successor_predecessor_proof(
                    predecessor["ready_proof"]
                )["broker_socket"]
            )
        ),
        dropin=Path(
            str(
                _verify_successor_predecessor_proof(
                    predecessor["ready_proof"]
                )["dropin"]
            )
        ),
        expected_uid=expected_uid,
        retired_dropin_boundary=retired_dropin_boundary,
        verify_retired_absence=verify_retired_absence,
    )
    if dict(predecessor) != verified:
        raise BridgeError("schema-12 successor predecessor binding changed")
    return verified


def _proof_stable_binding(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: item
        for key, item in value.items()
        if key
        not in {"schema_version", "kind", "document_sha256", "verified_at_epoch"}
    }


def _successor_live_identity_binding(
    value: Mapping[str, object],
) -> dict[str, object]:
    """Compare live proofs across the maintenance-only inventory envelope."""

    binding = _proof_stable_binding(value)
    canaries = binding.get("canaries")
    if isinstance(canaries, list):
        binding["canaries"] = [
            {
                key: item
                for key, item in canary.items()
                if key != "inventory_sha256"
            }
            if isinstance(canary, Mapping)
            else canary
            for canary in canaries
        ]
    return binding


def _verify_lifecycle_successor_handoff(
    *,
    transaction_journal: Path,
    transaction_journal_sha256: str,
    transaction_document_sha256: str,
    attestation: Path,
    attestation_sha256: str,
    attestation_document_sha256: str,
    expected_canary_release_digest: str,
    predecessor_transaction: Path,
    predecessor_operation_id: str,
    predecessor_journal_sha256: str,
    predecessor_document_sha256: str,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    expected_uid: int,
) -> dict[str, object]:
    digests = (
        transaction_journal_sha256,
        transaction_document_sha256,
        attestation_sha256,
        attestation_document_sha256,
        expected_canary_release_digest,
    )
    if any(RELEASE_RE.fullmatch(str(value)) is None for value in digests):
        raise BridgeError("lifecycle successor handoff digest is invalid")
    transaction_journal = _absolute(
        transaction_journal, "lifecycle recovery transaction journal"
    )
    attestation = _absolute(attestation, "lifecycle recovery attestation")
    if transaction_journal == attestation:
        raise BridgeError("lifecycle successor handoff evidence paths overlap")
    transaction_before = _private_file_identity(
        transaction_journal,
        uid=expected_uid,
        label="lifecycle recovery transaction journal",
    )
    attestation_before = _private_file_identity(
        attestation,
        uid=expected_uid,
        label="lifecycle recovery attestation",
    )
    if (
        transaction_before["sha256"] != transaction_journal_sha256
        or attestation_before["sha256"] != attestation_sha256
    ):
        raise BridgeError("lifecycle successor handoff raw digest changed")
    contract = _load_lifecycle_recovery_contract()
    try:
        transaction = contract._authority_repository_lifecycle_recovery_transaction(
            _read_private_json(
                transaction_journal,
                uid=expected_uid,
                label="lifecycle recovery transaction journal",
            )
        )
        producer_release, producer_manifest = (
            _verified_lifecycle_producer_release(
                transaction,
                expected_uid=expected_uid,
            )
        )
        plan_path = Path(str(transaction["plan"]))
        plan_before = _private_file_identity(
            plan_path,
            uid=expected_uid,
            label="lifecycle recovery plan",
        )
        plan = contract._validate_authority_repository_lifecycle_recovery_plan(
            _read_private_json(
                plan_path,
                uid=expected_uid,
                label="lifecycle recovery plan",
            )
        )
        recovery_path = Path(str(transaction["recovery_attestation"]))
        recovery_before = _private_file_identity(
            recovery_path,
            uid=expected_uid,
            label="lifecycle repository recovery attestation",
        )
        recovery = contract._validate_authority_repository_lifecycle_recovery_result(
            _read_private_json(
                recovery_path,
                uid=expected_uid,
                label="lifecycle repository recovery attestation",
            )
        )
        owner_recovered = contract._authority_repository_owner_is_recovered(
            before=plan["owner_authority"],
            current=recovery["owner_authority_after"],
            plan=plan,
        )
        result = contract._authority_repository_lifecycle_recovery_transaction_result(
            _read_private_json(
                attestation,
                uid=expected_uid,
                label="lifecycle recovery attestation",
            ),
            transaction=transaction,
            plan=plan,
            predecessor_proof_validator=_verify_successor_predecessor_proof,
        )
    except Exception as error:
        raise BridgeError(f"lifecycle successor handoff is invalid: {error}") from error
    predecessor = transaction["predecessor"]
    readiness = transaction["readiness"]
    proof = _verify_successor_predecessor_proof(result["predecessor_proof"])
    preclear = result.get("preclear_readiness")
    preclear_invariants = (
        preclear.get("invariants") if isinstance(preclear, Mapping) else None
    )
    maintenance = dict(result["maintenance"])
    maintenance_contract = _load_maintenance_contract()
    maintenance["scope"] = maintenance_contract.CONTROL_PLANE_MAINTENANCE_SCOPE
    if (
        transaction.get("document_sha256") != transaction_document_sha256
        or result.get("document_sha256") != attestation_document_sha256
        or result.get("transaction_journal_sha256")
        != transaction_document_sha256
        or result.get("operation_id") != transaction.get("operation_id")
        or result.get("recovery_result_sha256")
        != recovery.get("document_sha256")
        or result.get("release_digest") != transaction.get("release_digest")
        or result.get("canary_release_digest")
        != transaction.get("canary_release_digest")
        or transaction.get("release") != str(producer_release)
        or transaction.get("release_digest")
        != producer_manifest.get("release_digest")
        or transaction.get("canary_release_digest")
        != expected_canary_release_digest
        or result.get("maintenance") != transaction.get("maintenance")
        or transaction.get("plan_document_sha256") != plan.get("document_sha256")
        or plan.get("operation_id") != transaction.get("operation_id")
        or recovery.get("plan_id") != plan.get("plan_id")
        or recovery.get("operation_id") != transaction.get("operation_id")
        or recovery.get("plan_document_sha256") != plan.get("document_sha256")
        or recovery.get("source_repair_plan_sha256")
        != plan.get("source_repair_plan_sha256")
        or recovery.get("source_repair_result_sha256")
        != plan.get("source_repair_result_sha256")
        or recovery.get("authority_database") != transaction.get("database")
        or recovery.get("authority_uid") != plan.get("authority_uid")
        or recovery.get("authority_generation") != plan.get("authority_generation")
        or recovery.get("authority_schema_version")
        != plan.get("authority_schema_version")
        or recovery.get("authority_migration_state")
        != plan.get("authority_migration_state")
        or recovery.get("database_identity_before")
        != plan.get("database_identity")
        or recovery.get("maintenance_deployment_id")
        != transaction.get("maintenance", {}).get("deployment_id")
        or recovery.get("repository_id")
        != plan.get("repository", {}).get("repository_id")
        or recovery.get("repository_generation_after")
        != plan.get("target", {}).get("repository_generation")
        or recovery.get("repository_generation_before")
        != plan.get("repository", {}).get("generation")
        or recovery.get("installation_generation_after")
        != plan.get("target", {}).get("installation_generation")
        or recovery.get("installation_generation_before")
        != plan.get("repository", {}).get("installation_generation")
        or recovery.get("state_revision_before")
        != plan.get("authority_state_revision")
        or recovery.get("state_revision_after")
        != plan.get("target", {}).get("state_revision")
        or recovery.get("protected_rows") != plan.get("protected_rows")
        or recovery.get("owner_authority_before")
        != plan.get("owner_authority")
        or owner_recovered is not True
        or recovery.get("repository_state") != "active"
        or recovery.get("installation_status") != "installed"
        or recovery.get("startup_fenced") is not False
        or recovery.get("enrollment_count")
        != plan.get("repository", {}).get("enrollment_count")
        or recovery.get("reason") != plan.get("reason")
        or recovery.get("actor")
        != contract.AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or recovery.get("applied_at") != plan.get("mutation_updated_at")
        or result.get("database") != str(database)
        or transaction.get("database") != str(database)
        or plan.get("authority_generation") != expected_database_generation
        or proof.get("database_generation") != expected_database_generation
        or proof.get("database") != str(database)
        or proof.get("profile") != str(profile)
        or proof.get("broker_socket") != str(broker_socket)
        or proof.get("dropin") != str(dropin)
        or readiness.get("broker_socket") != str(broker_socket)
        or not isinstance(preclear, Mapping)
        or preclear.get("phase") != "preclear"
        or preclear.get("broker_socket") != str(broker_socket)
        or preclear.get("authority_generation")
        != expected_database_generation
        or preclear.get("canary") is not None
        or preclear.get("socket_identity") != proof.get("socket_identity")
        or preclear.get("socket_peer") != proof.get("socket_peer")
        or not isinstance(preclear_invariants, Mapping)
        or preclear_invariants.get("schema_version") != 12
        or preclear_invariants.get("database_generation")
        != expected_database_generation
        or type(preclear_invariants.get("state_revision")) is not int
        or int(preclear_invariants.get("state_revision", -1))
        < int(recovery.get("state_revision_after", -1))
        or preclear_invariants.get("quick_check") != "ok"
        or preclear_invariants.get("semantic_violation_count") != 0
        or predecessor.get("transaction") != str(predecessor_transaction)
        or predecessor.get("operation_id") != predecessor_operation_id
        or predecessor.get("journal_sha256") != predecessor_journal_sha256
        or predecessor.get("journal_document_sha256")
        != predecessor_document_sha256
        or predecessor.get("profile") != str(profile)
        or predecessor.get("dropin") != str(dropin)
        or proof.get("operation_id") != predecessor_operation_id
        or proof.get("bridge_journal_sha256") != predecessor_journal_sha256
        or proof.get("bridge_document_sha256") != predecessor_document_sha256
        or proof.get("historical_client_release")
        != transaction.get("canary_release")
        or proof.get("historical_client_release_digest")
        != transaction.get("canary_release_digest")
        or proof.get("broker_release_digest")
        != transaction.get("canary_release_digest")
        or result.get("service_restored") is not True
        or result.get("maintenance_cleared") is not False
        or result.get("successor_handoff_required") is not True
    ):
        raise BridgeError("lifecycle successor handoff binding changed")
    transaction_after = _private_file_identity(
        transaction_journal,
        uid=expected_uid,
        label="lifecycle recovery transaction journal",
    )
    attestation_after = _private_file_identity(
        attestation,
        uid=expected_uid,
        label="lifecycle recovery attestation",
    )
    plan_after = _private_file_identity(
        plan_path,
        uid=expected_uid,
        label="lifecycle recovery plan",
    )
    recovery_after = _private_file_identity(
        recovery_path,
        uid=expected_uid,
        label="lifecycle repository recovery attestation",
    )
    if (
        transaction_after != transaction_before
        or attestation_after != attestation_before
        or plan_after != plan_before
        or recovery_after != recovery_before
    ):
        raise BridgeError("lifecycle successor handoff changed while verified")
    return {
        "transaction_journal": str(transaction_journal),
        "transaction_journal_sha256": transaction_journal_sha256,
        "transaction_document_sha256": transaction_document_sha256,
        "attestation": str(attestation),
        "attestation_sha256": attestation_sha256,
        "attestation_document_sha256": attestation_document_sha256,
        "release": str(producer_release),
        "release_digest": str(producer_manifest["release_digest"]),
        "canary_release": str(transaction["canary_release"]),
        "canary_release_digest": expected_canary_release_digest,
        "operation_id": str(result["operation_id"]),
        "database_generation": expected_database_generation,
        "maintenance": maintenance,
        "predecessor_proof": proof,
        "preclear_readiness": dict(preclear),
    }


def _verified_lifecycle_producer_release(
    transaction: Mapping[str, object], *, expected_uid: int
) -> tuple[Path, dict[str, object]]:
    """Resolve a lifecycle producer from its validated, identity-bound journal."""

    release_value = transaction.get("release")
    release_digest = transaction.get("release_digest")
    if (
        not isinstance(release_value, str)
        or not release_value
        or not isinstance(release_digest, str)
        or RELEASE_RE.fullmatch(release_digest) is None
    ):
        raise BridgeError("lifecycle producer release binding is invalid")
    release_path = Path(release_value)
    if (
        not release_path.is_absolute()
        or Path(os.path.normpath(release_path)) != release_path
    ):
        raise BridgeError("lifecycle producer release binding is invalid")
    release = _absolute(release_path, "lifecycle producer release")
    if release == ROOT.resolve(strict=True):
        manifest = _verify_availability_client_release(
            release, owner_uid=expected_uid
        )
    else:
        manifest = _verify_historical_availability_release(
            release, owner_uid=expected_uid
        )
    if manifest.get("release_digest") != release_digest:
        raise BridgeError("lifecycle producer release digest changed")
    return release, manifest


def _validated_successor_maintenance(
    binding: Mapping[str, object],
) -> dict[str, object]:
    maintenance = _load_maintenance_contract()
    fields = {
        "root",
        "gid",
        "deployment_id",
        "scope",
        "message",
        "retry_after_seconds",
        "started_at",
    }
    try:
        deployment_id = str(uuid.UUID(str(binding["deployment_id"])))
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise BridgeError("inherited successor maintenance binding is invalid") from error
    if (
        set(binding) != fields
        or binding["deployment_id"] != deployment_id
        or binding["scope"] != maintenance.CONTROL_PLANE_MAINTENANCE_SCOPE
        or binding["message"] != maintenance.PUBLIC_MAINTENANCE_MESSAGE
        or isinstance(binding["gid"], bool)
        or not isinstance(binding["gid"], int)
        or int(binding["gid"]) < 0
        or isinstance(binding["retry_after_seconds"], bool)
        or not isinstance(binding["retry_after_seconds"], int)
        or int(binding["retry_after_seconds"]) <= 0
        or not isinstance(binding["started_at"], str)
        or not str(binding["started_at"]).endswith("Z")
    ):
        raise BridgeError("inherited successor maintenance binding is invalid")
    document = dict(binding)
    document["root"] = str(
        _absolute(Path(str(binding["root"])), "successor maintenance root")
    )
    return document


def _ensure_successor_maintenance(binding: Mapping[str, object], *, uid: int) -> None:
    maintenance = _load_maintenance_contract()
    binding = _validated_successor_maintenance(binding)
    root = Path(str(binding["root"]))
    try:
        state = maintenance.load_maintenance_state(
            expected_uid=uid,
            expected_gid=int(binding["gid"]),
            maintenance_root=root,
        )
        if state is None:
            raise BridgeError("inherited successor maintenance marker is absent")
        if (
            state.deployment_id != binding["deployment_id"]
            or state.message != binding["message"]
            or state.retry_after_seconds != binding["retry_after_seconds"]
            or state.started_at != binding["started_at"]
        ):
            raise BridgeError("schema-12 successor maintenance marker changed")
    except BridgeError:
        raise
    except Exception as error:
        raise BridgeError(f"schema-12 successor maintenance failed: {error}") from error


def _clear_successor_maintenance(binding: Mapping[str, object], *, uid: int) -> None:
    maintenance = _load_maintenance_contract()
    binding = _validated_successor_maintenance(binding)
    root = Path(str(binding["root"]))
    try:
        state = maintenance.load_maintenance_state(
            expected_uid=uid,
            expected_gid=int(binding["gid"]),
            maintenance_root=root,
        )
        if state is not None:
            if state.deployment_id != binding["deployment_id"]:
                raise BridgeError("another maintenance deployment owns the marker")
            maintenance.clear_maintenance(
                expected_uid=uid,
                expected_gid=int(binding["gid"]),
                deployment_id=str(binding["deployment_id"]),
                maintenance_root=root,
            )
        if maintenance.load_maintenance_state(
            expected_uid=uid,
            expected_gid=int(binding["gid"]),
            maintenance_root=root,
        ) is not None:
            raise BridgeError("schema-12 successor maintenance marker did not clear")
    except BridgeError:
        raise
    except Exception as error:
        raise BridgeError(f"schema-12 successor maintenance clear failed: {error}") from error


def _reactivate_successor_maintenance(
    binding: Mapping[str, object], *, uid: int
) -> None:
    maintenance = _load_maintenance_contract()
    binding = _validated_successor_maintenance(binding)
    root = Path(str(binding["root"]))
    try:
        state = maintenance.load_maintenance_state(
            expected_uid=uid,
            expected_gid=int(binding["gid"]),
            maintenance_root=root,
        )
        if state is None:
            maintenance.activate_maintenance(
                expected_uid=uid,
                expected_gid=int(binding["gid"]),
                deployment_id=str(binding["deployment_id"]),
                scope=str(binding["scope"]),
                message=str(binding["message"]),
                retry_after_seconds=int(binding["retry_after_seconds"]),
                started_at=str(binding["started_at"]),
                maintenance_root=root,
            )
        _ensure_successor_maintenance(binding, uid=uid)
    except BridgeError:
        raise
    except Exception as error:
        raise BridgeError(
            f"schema-12 successor maintenance reactivation failed: {error}"
        ) from error


def _maintenance_is_clear(binding: Mapping[str, object], *, uid: int) -> bool:
    maintenance = _load_maintenance_contract()
    binding = _validated_successor_maintenance(binding)
    try:
        state = maintenance.load_maintenance_state(
            expected_uid=uid,
            expected_gid=int(binding["gid"]),
            maintenance_root=Path(str(binding["root"])),
        )
    except Exception as error:
        raise BridgeError(f"schema-12 successor maintenance read failed: {error}") from error
    return state is None


def _sealed_owner_map_reference(
    owner_map: Path, *, owner_map_sha256: str, expected_uid: int
) -> dict[str, object]:
    if RELEASE_RE.fullmatch(owner_map_sha256) is None:
        raise BridgeError("sealed owner-map raw digest is invalid")
    owner_contract = _load_owner_contract()
    try:
        document = owner_contract.load_sealed_owner_map(
            owner_map, expected_owner_uid=expected_uid
        )
    except Exception as error:
        raise BridgeError(f"sealed owner map cannot be loaded: {error}") from error
    if _sha256_file(owner_map) != owner_map_sha256:
        raise BridgeError("sealed owner-map raw digest changed")
    document_digest = str(document.get("document_sha256") or "")
    unsigned = dict(document)
    unsigned.pop("document_sha256", None)
    expected_document = "sha256:" + _sha256_bytes(_canonical(unsigned))
    if (
        document_digest != expected_document
        or RELEASE_RE.fullmatch(document_digest.removeprefix("sha256:")) is None
    ):
        raise BridgeError("sealed owner-map document digest is invalid")
    return {
        "path": str(owner_map),
        "raw_sha256": owner_map_sha256,
        "document_sha256": document_digest[7:],
        "identity": _private_file_identity(
            owner_map, uid=expected_uid, label="sealed owner map"
        ),
    }


_OWNER_MAP_REFRESH_FIELDS = {
    "schema_version",
    "kind",
    "operation_id",
    "actor",
    "created_at",
    "source_database_generation",
    "target_database_generation",
    "source_schema_version",
    "source_state_revision",
    "repository_execution_scope",
    "repositories",
    "document_sha256",
}
_OWNER_MAP_SCOPE_REFRESH_FIELDS = {
    "schema_version",
    "kind",
    "authority_schema_version",
    "database_generation",
    "state_revision",
    "migration_state",
    "repository_count",
    "executable_repository_count",
    "excluded_terminal_repository_count",
    "repository_universe_sha256",
    "executable_repositories_sha256",
    "excluded_terminal_repositories_sha256",
    "executable_repositories",
    "excluded_terminal_repositories",
    "document_sha256",
}
_OWNER_MAP_REFRESH_RECORD_FIELDS = {
    "previous",
    "refreshed",
    "previous_source_state_revision",
    "refreshed_source_state_revision",
    "lifecycle_attestation_document_sha256",
    "lifecycle_preclear_state_revision",
}


def _owner_map_document_for_refresh(
    reference: Mapping[str, object], *, expected_uid: int, label: str
) -> dict[str, object]:
    if set(reference) != {"path", "raw_sha256", "document_sha256", "identity"}:
        raise BridgeError(f"{label} owner-map reference is invalid")
    path = _absolute(Path(str(reference["path"])), f"{label} owner map")
    retained = _sealed_owner_map_reference(
        path,
        owner_map_sha256=str(reference["raw_sha256"]),
        expected_uid=expected_uid,
    )
    if retained != dict(reference):
        raise BridgeError(f"{label} owner-map reference changed")
    owner_contract = _load_owner_contract()
    try:
        document = owner_contract.load_sealed_owner_map(
            path, expected_owner_uid=expected_uid
        )
    except Exception as error:
        raise BridgeError(f"{label} owner map cannot be loaded: {error}") from error
    if (
        not isinstance(document, dict)
        or set(document) != _OWNER_MAP_REFRESH_FIELDS
        or document.get("document_sha256")
        != "sha256:" + str(reference["document_sha256"])
    ):
        raise BridgeError(f"{label} owner-map document is invalid")
    scope = document.get("repository_execution_scope")
    if not isinstance(scope, dict) or set(scope) != _OWNER_MAP_SCOPE_REFRESH_FIELDS:
        raise BridgeError(f"{label} owner-map execution scope is invalid")
    unsigned_scope = dict(scope)
    scope_digest = unsigned_scope.pop("document_sha256", None)
    if (
        scope_digest != "sha256:" + _sha256_bytes(_canonical(unsigned_scope))
        or RELEASE_RE.fullmatch(str(scope_digest).removeprefix("sha256:")) is None
    ):
        raise BridgeError(f"{label} owner-map execution scope digest is invalid")
    return dict(document)


def _verified_owner_map_refresh_relation(
    *,
    previous_reference: Mapping[str, object],
    refreshed_reference: Mapping[str, object],
    maintenance_handoff: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    previous = _owner_map_document_for_refresh(
        previous_reference, expected_uid=expected_uid, label="previous"
    )
    refreshed = _owner_map_document_for_refresh(
        refreshed_reference, expected_uid=expected_uid, label="refreshed"
    )
    if previous_reference.get("path") == refreshed_reference.get("path"):
        raise BridgeError("refreshed owner map must use a distinct evidence path")
    static_fields = _OWNER_MAP_REFRESH_FIELDS - {
        "created_at",
        "source_state_revision",
        "repository_execution_scope",
        "document_sha256",
    }
    previous_revision = previous.get("source_state_revision")
    refreshed_revision = refreshed.get("source_state_revision")
    previous_scope = previous["repository_execution_scope"]
    refreshed_scope = refreshed["repository_execution_scope"]
    scope_static_fields = _OWNER_MAP_SCOPE_REFRESH_FIELDS - {
        "state_revision",
        "document_sha256",
    }
    preclear = maintenance_handoff.get("preclear_readiness")
    invariants = preclear.get("invariants") if isinstance(preclear, Mapping) else None
    if (
        any(previous.get(field) != refreshed.get(field) for field in static_fields)
        or isinstance(previous_revision, bool)
        or not isinstance(previous_revision, int)
        or isinstance(refreshed_revision, bool)
        or not isinstance(refreshed_revision, int)
        or refreshed_revision <= previous_revision
        or any(
            previous_scope.get(field) != refreshed_scope.get(field)
            for field in scope_static_fields
        )
        or previous_scope.get("state_revision") != previous_revision
        or refreshed_scope.get("state_revision") != refreshed_revision
        or not isinstance(invariants, Mapping)
        or invariants.get("schema_version") != 12
        or invariants.get("migration_state", "ready") != "ready"
        or invariants.get("database_generation")
        != previous.get("source_database_generation")
        or invariants.get("state_revision") != previous_revision
        or maintenance_handoff.get("database_generation")
        != previous.get("source_database_generation")
        or RELEASE_RE.fullmatch(
            str(maintenance_handoff.get("attestation_document_sha256"))
        )
        is None
    ):
        raise BridgeError(
            "refreshed owner map changed more than its lifecycle-bound revision"
        )
    return {
        "previous": dict(previous_reference),
        "refreshed": dict(refreshed_reference),
        "previous_source_state_revision": previous_revision,
        "refreshed_source_state_revision": refreshed_revision,
        "lifecycle_attestation_document_sha256": maintenance_handoff[
            "attestation_document_sha256"
        ],
        "lifecycle_preclear_state_revision": previous_revision,
    }


def _refresh_inherited_lifecycle_owner_map(
    current: Mapping[str, object] | None,
    *,
    requested_binding: Mapping[str, object],
    release_pair: Mapping[str, object],
    journal_path: Path,
    expected_uid: int,
) -> dict[str, object] | None:
    """Refresh one stale owner-map revision before any profile export.

    The existing successor journal is replaced atomically.  Its complete
    binding and profile are unchanged except for the same refreshed owner-map
    reference plus an embedded proof of the old-to-new revision-only delta.
    """

    if current is None:
        return None
    binding_value = current.get("binding")
    profile_value = current.get("profile")
    if not isinstance(binding_value, Mapping) or not isinstance(profile_value, Mapping):
        return dict(current)
    binding = dict(binding_value)
    profile = dict(profile_value)
    previous_reference = binding.get("owner_map")
    refreshed_reference = requested_binding.get("owner_map")
    refresh_record = profile.get("owner_binding_refresh")
    if previous_reference == refreshed_reference:
        if refresh_record is None:
            return dict(current)
        maintenance_handoff = binding.get("maintenance_handoff")
        if (
            not isinstance(refresh_record, Mapping)
            or set(refresh_record) != _OWNER_MAP_REFRESH_RECORD_FIELDS
            or not isinstance(refresh_record.get("previous"), Mapping)
            or not isinstance(refresh_record.get("refreshed"), Mapping)
            or not isinstance(refreshed_reference, Mapping)
            or not isinstance(maintenance_handoff, Mapping)
            or refresh_record.get("refreshed") != refreshed_reference
            or profile.get("owner_binding") != refreshed_reference
            or profile.get("owner_binding_sha256")
            != refreshed_reference.get("document_sha256")
        ):
            raise BridgeError("retained owner-map refresh lineage is invalid")
        verified = _verified_owner_map_refresh_relation(
            previous_reference=refresh_record["previous"],
            refreshed_reference=refresh_record["refreshed"],
            maintenance_handoff=maintenance_handoff,
            expected_uid=expected_uid,
        )
        if verified != dict(refresh_record):
            raise BridgeError("retained owner-map refresh lineage changed")
        return dict(current)

    static_binding = dict(binding)
    requested_static = dict(requested_binding)
    static_binding.pop("owner_map", None)
    requested_static.pop("owner_map", None)
    maintenance_handoff = binding.get("maintenance_handoff")
    if (
        release_pair.get("historical_client") is not True
        or current.get("phase") != "predecessor-retired"
        or static_binding != requested_static
        or not isinstance(previous_reference, Mapping)
        or not isinstance(refreshed_reference, Mapping)
        or not isinstance(maintenance_handoff, Mapping)
        or refresh_record is not None
        or profile.get("owner_binding") != previous_reference
        or profile.get("owner_binding_sha256")
        != previous_reference.get("document_sha256")
        or profile.get("repaired_payload_sha256") is not None
        or profile.get("after_identity") is not None
        or profile.get("restored_identity") is not None
        or "export_evidence" in profile
        or current.get("candidate") != {"activation": None, "readiness": None}
        or current.get("restored_predecessor") is not None
    ):
        raise BridgeError(
            "inherited lifecycle successor permits only a pre-export owner-map refresh"
        )
    _ensure_successor_maintenance(binding.get("maintenance"), uid=expected_uid)
    refresh_record = _verified_owner_map_refresh_relation(
        previous_reference=previous_reference,
        refreshed_reference=refreshed_reference,
        maintenance_handoff=maintenance_handoff,
        expected_uid=expected_uid,
    )
    binding["owner_map"] = dict(refreshed_reference)
    profile["owner_binding"] = dict(refreshed_reference)
    profile["owner_binding_sha256"] = refreshed_reference["document_sha256"]
    profile["owner_binding_refresh"] = refresh_record
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload["binding"] = binding
    payload["profile"] = profile
    payload["updated_at_epoch"] = int(time.time())
    return _successor_journal(journal_path, payload, uid=expected_uid)


def _load_validated_owner_map(
    *,
    connection: sqlite3.Connection,
    owner_map: Path,
    owner_map_sha256: str,
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    if RELEASE_RE.fullmatch(owner_map_sha256) is None:
        raise BridgeError("sealed owner-map raw digest is invalid")
    owner_contract = _load_owner_contract()
    try:
        document = owner_contract.load_sealed_owner_map(
            owner_map, expected_owner_uid=expected_uid
        )
        if _sha256_file(owner_map) != owner_map_sha256:
            raise BridgeError("sealed owner-map raw digest changed")
        validated = owner_contract.validate_owner_map(connection, document)
    except BridgeError:
        raise
    except Exception as error:
        raise BridgeError(f"sealed owner map is invalid: {error}") from error
    document_digest = str(validated.get("document_sha256") or "")
    if not document_digest.startswith("sha256:") or RELEASE_RE.fullmatch(
        document_digest[7:]
    ) is None:
        raise BridgeError("sealed owner-map document digest is invalid")
    identity = _private_file_identity(
        owner_map, uid=expected_uid, label="sealed owner map"
    )
    return dict(validated), {
        "path": str(owner_map),
        "raw_sha256": owner_map_sha256,
        "document_sha256": document_digest[7:],
        "identity": identity,
    }


def _sqlite_bundle_evidence(
    database: Path, *, expected_uid: int
) -> dict[str, object]:
    def evidence(path: Path, *, label: str) -> dict[str, object]:
        identity = _sqlite_regular_identity(path, uid=expected_uid, label=label)
        return {**identity, "path": str(path), "sha256": _sha256_file(path)}

    sidecars: dict[str, object] = {}
    for suffix in ("-wal", "-shm"):
        path = Path(str(database) + suffix)
        sidecars[suffix] = (
            None
            if not path.exists() and not path.is_symlink()
            else evidence(path, label=f"successor SQLite {suffix[1:]} sidecar")
        )
    return {
        "main": evidence(database, label="successor authority database"),
        "sidecars": sidecars,
    }


_SQLITE_BUNDLE_EVIDENCE_FIELDS = frozenset(
    {
        "device",
        "inode",
        "size",
        "mtime_ns",
        "ctime_ns",
        "uid",
        "gid",
        "mode",
        "nlink",
        "path",
        "sha256",
    }
)
_SQLITE_VOLATILE_SIDECAR_FIELDS = frozenset({"mtime_ns", "ctime_ns"})


def _retired_rescue_sqlite_bundle_view(
    value: object,
) -> dict[str, object]:
    """Return the stable stopped-database evidence used only by rescue.

    Merely opening SQLite for a legitimate read can advance WAL/SHM metadata
    timestamps even while their bytes and filesystem identity remain exact.
    The retired executor-rescue boundary therefore ignores only those two
    sidecar timestamps.  The authority database stays byte-for-byte exact, and
    sidecar path, presence, content, inode, size, ownership, mode, and link
    identity all remain fail-closed.
    """

    if not isinstance(value, Mapping) or set(value) != {"main", "sidecars"}:
        raise BridgeError("schema-12 SQLite bundle evidence is invalid")
    main = value.get("main")
    sidecars = value.get("sidecars")
    if (
        not isinstance(main, Mapping)
        or set(main) != _SQLITE_BUNDLE_EVIDENCE_FIELDS
        or not isinstance(sidecars, Mapping)
        or set(sidecars) != {"-wal", "-shm"}
    ):
        raise BridgeError("schema-12 SQLite bundle evidence is invalid")
    stable_sidecars: dict[str, object] = {}
    for suffix in ("-wal", "-shm"):
        sidecar = sidecars[suffix]
        if sidecar is None:
            stable_sidecars[suffix] = None
            continue
        if (
            not isinstance(sidecar, Mapping)
            or set(sidecar) != _SQLITE_BUNDLE_EVIDENCE_FIELDS
        ):
            raise BridgeError(
                f"schema-12 SQLite {suffix[1:]} sidecar evidence is invalid"
            )
        stable_sidecars[suffix] = {
            field: sidecar[field]
            for field in _SQLITE_BUNDLE_EVIDENCE_FIELDS
            if field not in _SQLITE_VOLATILE_SIDECAR_FIELDS
        }
    return {"main": dict(main), "sidecars": stable_sidecars}


def _schema12_read_snapshot(
    database: Path, *, snapshot_root: Path, expected_uid: int
) -> tuple[Path, Path, dict[str, object]]:
    """Copy a stopped SQLite main/WAL bundle without opening the source."""

    snapshot_root = _private_directory(
        snapshot_root, uid=expected_uid, create=True
    )
    before = _sqlite_bundle_evidence(database, expected_uid=expected_uid)
    scratch = Path(
        tempfile.mkdtemp(prefix="schema12-profile-export.", dir=snapshot_root)
    )
    scratch.chmod(0o700)
    snapshot = scratch / "authority.sqlite3"
    try:
        sources = [(database, snapshot)]
        wal = before["sidecars"]["-wal"]
        if wal is not None:
            sources.append((Path(str(database) + "-wal"), Path(str(snapshot) + "-wal")))
        for source, destination in sources:
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
            source_evidence = (
                before["main"]
                if source == database
                else before["sidecars"]["-wal"]
            )
            if (
                not isinstance(source_evidence, dict)
                or _sha256_file(destination) != source_evidence["sha256"]
            ):
                raise BridgeError("schema-12 SQLite snapshot copy changed")
        if _sqlite_bundle_evidence(database, expected_uid=expected_uid) != before:
            raise BridgeError("schema-12 authority changed during snapshot copy")
        return snapshot, scratch, before
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def _schema12_owner_bound_profile_export(
    *,
    database: Path,
    profile_path: Path,
    broker_socket: Path,
    owner_map: Path,
    owner_map_sha256: str,
    snapshot_root: Path,
    expected_database_generation: str,
    canary_uid: int,
    canary_project: Path,
    repository_id: str,
    repository_generation: int,
    expected_uid: int,
) -> tuple[bytes, dict[str, object]]:
    """Export every active schema-12 enrollment using sealed owner authority.

    No field from the legacy profile is merged.  Repository owners come only
    from the complete, schema-12-generation-fenced owner map; grants and
    resources come only from the stopped schema-12 database.
    """

    database = _absolute(database, "successor authority database")
    snapshot, scratch, source_bundle = _schema12_read_snapshot(
        database,
        snapshot_root=snapshot_root,
        expected_uid=expected_uid,
    )
    encoded = quote(os.fspath(snapshot), safe="/")
    connection: sqlite3.Connection | None = None
    current_epoch = int(time.time())
    try:
        connection = sqlite3.connect(
            f"file:{encoded}?mode=ro", uri=True, timeout=5.0
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        metadata = connection.execute(
            "SELECT schema_version, database_generation, migration_state "
            "FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if (
            metadata is None
            or int(metadata[0]) != 12
            or str(metadata[1]) != expected_database_generation
            or str(metadata[2]) != "ready"
        ):
            raise BridgeError("profile export requires the exact ready schema-12 authority")
        owner_document, owner_evidence = _load_validated_owner_map(
            connection=connection,
            owner_map=owner_map,
            owner_map_sha256=owner_map_sha256,
            expected_uid=expected_uid,
        )
        owners = {
            str(item["repository_id"]): dict(item)
            for item in owner_document["repositories"]
        }
        rows = connection.execute(
            """
            SELECT enrollment.uid, enrollment.account_id, enrollment.repo_id,
                   enrollment.issued_at, enrollment.valid_until_epoch,
                   repository.canonical_root, repository.generation
            FROM broker_repository_enrollments enrollment
            JOIN broker_acl_principals principal
              ON principal.uid = enrollment.uid
             AND principal.account_id = enrollment.account_id
            JOIN repositories repository USING(repo_id)
            JOIN repository_installations installation USING(repo_id)
            WHERE enrollment.enabled = 1 AND principal.enabled = 1
              AND enrollment.valid_until_epoch > ?
              AND repository.state = 'active'
              AND installation.status = 'installed'
              AND installation.startup_fenced = 0
            ORDER BY enrollment.uid, repository.canonical_root,
                     enrollment.repo_id
            """,
            (current_epoch,),
        ).fetchall()
        if not rows or len(rows) > 10_000:
            raise BridgeError("schema-12 authority has no bounded active enrollments")
        clients: dict[str, dict[str, object]] = {}
        bindings: list[dict[str, object]] = []

        def add_mapping(
            mapping: dict[str, str], key: object, value: object, *, label: str
        ) -> None:
            name = str(key)
            resource_id = str(value)
            previous = mapping.get(name)
            if (
                not name
                or not resource_id
                or (previous is not None and previous != resource_id)
            ):
                raise BridgeError(f"schema-12 {label} profile mapping is ambiguous")
            mapping[name] = resource_id

        for row in rows:
            client_uid = int(row["uid"])
            account_id = str(row["account_id"])
            repo_id = str(row["repo_id"])
            canonical_root = str(row["canonical_root"])
            generation = int(row["generation"])
            issued_at = str(row["issued_at"])
            valid_until = int(row["valid_until_epoch"])
            owner = owners.get(repo_id)
            if (
                client_uid < 0
                or not account_id
                or not repo_id
                or not Path(canonical_root).is_absolute()
                or generation < 0
                or not issued_at
                or valid_until <= current_epoch
                or owner is None
                or owner.get("canonical_root") != canonical_root
                or owner.get("repository_generation") != generation
                or type(owner.get("owner_uid")) is not int
                or int(owner["owner_uid"]) <= 0
            ):
                raise BridgeError("schema-12 profile enrollment lacks exact owner authority")
            client = clients.setdefault(
                str(client_uid),
                {
                    "account_id": account_id,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until,
                    "repositories": [],
                },
            )
            if client["account_id"] != account_id:
                raise BridgeError("one schema-12 client UID has conflicting accounts")
            repositories = client["repositories"]
            if not isinstance(repositories, list) or any(
                isinstance(item, Mapping) and item.get("repo_id") == repo_id
                for item in repositories
            ):
                raise BridgeError("schema-12 profile repeats a repository enrollment")
            servers: dict[str, str] = {}
            for resource in connection.execute(
                """
                SELECT DISTINCT definition.name, acl.resource_id
                FROM broker_resource_acl acl
                JOIN server_definitions definition
                  ON definition.server_definition_id = acl.resource_id
                 AND definition.repo_id = acl.repo_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.resource_kind = 'server' AND acl.enabled = 1
                ORDER BY definition.name, acl.resource_id
                """,
                (client_uid, repo_id),
            ):
                add_mapping(servers, resource["name"], resource["resource_id"], label="server")
            containers: dict[str, str] = {}
            for resource in connection.execute(
                """
                SELECT DISTINCT docker.current_name, docker.full_container_id,
                                acl.resource_id
                FROM broker_resource_acl acl
                JOIN docker_resources docker
                  ON docker.docker_resource_id = acl.resource_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.resource_kind = 'container' AND acl.enabled = 1
                ORDER BY docker.current_name, docker.full_container_id,
                         acl.resource_id
                """,
                (client_uid, repo_id),
            ):
                add_mapping(
                    containers,
                    resource["current_name"],
                    resource["resource_id"],
                    label="container",
                )
                add_mapping(
                    containers,
                    resource["full_container_id"],
                    resource["resource_id"],
                    label="container",
                )
            compose_ids = [
                str(item[0])
                for item in connection.execute(
                    """
                    SELECT DISTINCT acl.compose_definition_id
                    FROM broker_compose_acl acl
                    JOIN broker_compose_definitions definition
                      ON definition.compose_definition_id = acl.compose_definition_id
                     AND definition.repo_id = acl.repo_id
                    WHERE acl.uid = ? AND acl.repo_id = ?
                      AND acl.enabled = 1 AND definition.enabled = 1
                    ORDER BY acl.compose_definition_id
                    """,
                    (client_uid, repo_id),
                )
            ]
            if len(compose_ids) > 1:
                raise BridgeError("schema-12 profile has ambiguous Compose grants")
            templates: dict[str, str] = {}
            policies: dict[str, dict[str, str]] = {}
            prefetch: list[str] = []
            template_rows = connection.execute(
                """
                SELECT template.name, template.template_id,
                       template.secret_policy_kind, template.secret_binding_id,
                       MAX(CASE WHEN acl.operation = 'ephemeral.image_prefetch'
                                AND acl.enabled = 1 THEN 1 ELSE 0 END) AS prefetch
                FROM broker_ephemeral_acl acl
                JOIN ephemeral_container_templates template
                  ON template.template_id = acl.template_id
                 AND template.repo_id = acl.repo_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.enabled = 1 AND template.enabled = 1
                GROUP BY template.name, template.template_id,
                         template.secret_policy_kind, template.secret_binding_id
                ORDER BY template.name, template.template_id
                """,
                (client_uid, repo_id),
            ).fetchall()
            for resource in template_rows:
                add_mapping(
                    templates,
                    resource["name"],
                    resource["template_id"],
                    label="ephemeral template",
                )
                if bool(resource["prefetch"]):
                    prefetch.append(str(resource["template_id"]))
                policy = resource["secret_policy_kind"]
                secret_binding = resource["secret_binding_id"]
                if (policy is None) != (secret_binding is None):
                    raise BridgeError("schema-12 ephemeral secret authority is incomplete")
                if policy is not None:
                    policies[str(resource["name"])] = {
                        "policy": str(policy),
                        "binding_id": str(secret_binding),
                    }
            repositories.append(
                {
                    "canonical_root": canonical_root,
                    "repo_id": repo_id,
                    "generation": generation,
                    "owner_uid": int(owner["owner_uid"]),
                    "servers": servers,
                    "containers": containers,
                    "compose_definition_id": compose_ids[0] if compose_ids else None,
                    "account_id": account_id,
                    "enabled": True,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until,
                    "ephemeral_templates": templates,
                    "ephemeral_image_prefetch_templates": sorted(prefetch),
                    "ephemeral_secret_policies": policies,
                }
            )
            client["issued_at"] = min(str(client["issued_at"]), issued_at)
            client["valid_until_epoch"] = max(
                int(client["valid_until_epoch"]), valid_until
            )
            bindings.append(
                {
                    "client_uid": client_uid,
                    "account_id": account_id,
                    "repository_id": repo_id,
                    "repository_generation": generation,
                    "owner_uid": int(owner["owner_uid"]),
                    "canonical_root": canonical_root,
                }
            )
        connection.execute("ROLLBACK")
    finally:
        if connection is not None:
            connection.close()
        try:
            if (
                _sqlite_bundle_evidence(database, expected_uid=expected_uid)
                != source_bundle
            ):
                raise BridgeError(
                    "authority changed during full protected-profile export"
                )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    try:
        access_gid = grp.getgrnam(ACCESS_GROUP).gr_gid
    except KeyError as error:
        raise BridgeError(f"required broker access group is missing: {ACCESS_GROUP}") from error
    document = {
        "version": 1,
        "service": {
            "socket": str(broker_socket),
            "uid": 0,
            "gid": access_gid,
            "mode": "0660",
            "database_generation": expected_database_generation,
        },
        "clients": clients,
    }
    profile_contract = _load_profile_contract()
    for client_uid in sorted(int(value) for value in clients):
        try:
            parsed = profile_contract.profile_from_document(
                document, effective_uid=client_uid
            )
        except Exception as error:
            raise BridgeError(
                f"owner-bound profile failed client {client_uid} strict parsing: {error}"
            ) from error
        expected_ids = {
            str(item["repository_id"])
            for item in bindings
            if int(item["client_uid"]) == client_uid
        }
        if (
            parsed.service.database_generation != expected_database_generation
            or parsed.service.socket_path != broker_socket
            or {item.repo_id for item in parsed.repositories.values()} != expected_ids
        ):
            raise BridgeError("owner-bound profile parser result is contradictory")
    gf = [
        item
        for item in bindings
        if item["client_uid"] == canary_uid
        and item["repository_id"] == repository_id
        and item["repository_generation"] == repository_generation
        and item["canonical_root"] == str(canary_project)
        and item["owner_uid"] == canary_uid
    ]
    if len(gf) != 1:
        raise BridgeError("owner map does not bind the exact GlobalFinance canary")
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_JSON_BYTES:
        raise BridgeError("owner-bound protected profile exceeds its bound")
    evidence = {
        "profile": str(profile_path),
        "profile_sha256": _sha256_bytes(payload),
        "database_generation": expected_database_generation,
        "database_identity": source_bundle["main"],
        "database_sidecars": source_bundle["sidecars"],
        "owner_map": owner_evidence,
        "client_uids": sorted(int(value) for value in clients),
        "repository_bindings": bindings,
        "all_clients_parser_verified": True,
        "existing_profile_contents_reused": False,
    }
    evidence["evidence_sha256"] = _sha256_bytes(_canonical(evidence))
    return payload, evidence


def _replace_profile_bytes(
    path: Path,
    payload: bytes,
    *,
    expected_current_sha256: str,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> dict[str, object]:
    current_payload, current = _stable_profile_bytes(path, uid=owner_uid)
    target_sha256 = _sha256_bytes(payload)
    if current["sha256"] == target_sha256 and current_payload == payload:
        return current
    if (
        current["sha256"] != expected_current_sha256
        or current["gid"] != owner_gid
        or current["mode"] != mode
        or mode & 0o022
    ):
        raise BridgeError("protected profile changed before atomic replacement")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BridgeError("protected profile write made no progress")
            view = view[written:]
        if os.geteuid() == 0:
            os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    after_payload, after = _stable_profile_bytes(path, uid=owner_uid)
    if after["sha256"] != target_sha256 or after_payload != payload:
        raise BridgeError("protected profile atomic replacement did not verify")
    return after


def _stop_successor_predecessor(
    predecessor: Mapping[str, object], *, broker_socket: Path, wait_seconds: int
) -> dict[str, object]:
    state = _systemd_state()
    if _service_process_alive(state):
        expected = predecessor["ready_proof"]["systemd"]["InvocationID"]
        if state.get("InvocationID") != expected:
            raise BridgeError("schema-12 successor predecessor invocation changed")
        return _stop_owned_invocation(
            expected_invocation=expected,
            broker_socket=broker_socket,
            wait_seconds=wait_seconds,
        )
    return _wait_inactive(broker_socket, wait_seconds)


def _remove_successor_predecessor_dropin(
    predecessor: Mapping[str, object], *, dropin: Path, uid: int
) -> None:
    if dropin.exists() or dropin.is_symlink():
        _unlink_owned_dropin(
            dropin,
            predecessor["dropin_identity"],
            uid=uid,
            expected_sha256=str(predecessor["dropin_sha256"]),
        )
    _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
    if dropin.exists() or dropin.is_symlink():
        raise BridgeError("schema-12 successor predecessor drop-in remained")


def _candidate_bridge_reference(
    *,
    transaction: Path,
    operation_id: str,
    activation: Mapping[str, object],
    uid: int,
    executor_rescue: Mapping[str, object] | None = None,
    executor_rescue_sha256: str | None = None,
) -> dict[str, object]:
    journal = transaction / JOURNAL_NAME
    _private_regular(journal, uid=uid, label="successor candidate bridge journal")
    bridge = _load_bridge_journal(journal, uid=uid)
    if (
        bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("phase") != "ready"
        or bridge != activation
        or bridge.get("executor_rescue")
        != (dict(executor_rescue) if executor_rescue is not None else None)
        or (executor_rescue is None) != (executor_rescue_sha256 is None)
        or executor_rescue is not None
        and executor_rescue.get("executor_rescue_sha256")
        != executor_rescue_sha256
    ):
        raise BridgeError("successor candidate bridge activation is not durable")
    return {
        "transaction": str(transaction),
        "operation_id": operation_id,
        "journal": str(journal),
        "journal_sha256": _sha256_file(journal),
        "document_sha256": bridge["document_sha256"],
        "activation": dict(bridge),
        "executor_rescue": (
            dict(executor_rescue) if executor_rescue is not None else None
        ),
        "executor_rescue_sha256": executor_rescue_sha256,
        "readiness": None,
    }


def _verify_successor_ready_proof(value: object) -> dict[str, object]:
    fields = {
        "operation_id",
        "bridge_journal",
        "bridge_journal_sha256",
        "bridge_document_sha256",
        "broker_release",
        "broker_release_digest",
        "client_release",
        "client_release_digest",
        "executor_rescue",
        "executor_rescue_sha256",
        "database",
        "database_generation",
        "profile",
        "profile_identity",
        "owner_uid",
        "profile_repositories",
        "broker_socket",
        "socket_identity",
        "socket_peer",
        "dropin",
        "dropin_identity",
        "systemd",
        "execution",
        "process",
        "canaries",
        "verified_at_epoch",
    }
    document = _verify_seal(value, kind=SUCCESSOR_READY_PROOF_KIND, fields=fields)
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("clean successor proof operation is invalid") from error
    if (
        operation_id != document["operation_id"]
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in (
                "bridge_journal_sha256",
                "bridge_document_sha256",
                "broker_release_digest",
                "client_release_digest",
            )
        )
        or document["executor_rescue_sha256"] is not None
        and RELEASE_RE.fullmatch(
            str(document["executor_rescue_sha256"])
        )
        is None
        or (document["executor_rescue"] is None)
        != (document["executor_rescue_sha256"] is None)
        or document["executor_rescue"] is not None
        and (
            _validate_successor_executor_rescue_runtime_evidence(
                document["executor_rescue"],
                expected_sha256=document["executor_rescue_sha256"],
            ).get("client_release")
            != document["client_release"]
            or document["executor_rescue"].get("client_release_digest")
            != document["client_release_digest"]
        )
        or isinstance(document["owner_uid"], bool)
        or not isinstance(document["owner_uid"], int)
        or int(document["owner_uid"]) <= 0
        or not isinstance(document["profile_repositories"], list)
        or not document["profile_repositories"]
        or len(document["profile_repositories"]) > 16
        or not isinstance(document["canaries"], list)
        or len(document["canaries"]) != len(document["profile_repositories"])
        or any(
            not isinstance(item, dict)
            or set(item)
            != {
                "client_uid",
                "repository_id",
                "canonical_root",
                "generation",
                "owner_uid",
            }
            or item.get("owner_uid") != document["owner_uid"]
            for item in document["profile_repositories"]
        )
        or all(
            item.get("client_uid") != document["owner_uid"]
            for item in document["profile_repositories"]
        )
        or any(
            not isinstance(item, dict)
            or set(item)
            != ({
                "user",
                "uid",
                "project",
                "inventory_sha256",
                "authority",
                "repository",
            } | (
                {"executor_rescue_sha256"}
                if document["executor_rescue"] is not None
                else set()
            ))
            or item.get("uid")
            != document["profile_repositories"][index].get("client_uid")
            or item.get("project")
            != document["profile_repositories"][index].get("canonical_root")
            or RELEASE_RE.fullmatch(str(item.get("inventory_sha256"))) is None
            or not isinstance(item.get("authority"), dict)
            or not isinstance(item.get("repository"), dict)
            or item["repository"].get("repository_id")
            != document["profile_repositories"][index].get("repository_id")
            or item["repository"].get("canonical_root")
            != document["profile_repositories"][index].get("canonical_root")
            or item["repository"].get("generation")
            != document["profile_repositories"][index].get("generation")
            or document["executor_rescue"] is not None
            and item.get("executor_rescue_sha256")
            != document["executor_rescue_sha256"]
            for index, item in enumerate(document["canaries"])
        )
        or not isinstance(document["systemd"], dict)
        or not isinstance(document["execution"], dict)
        or not isinstance(document["process"], dict)
    ):
        raise BridgeError("clean successor proof binding is invalid")
    repositories = document["profile_repositories"]
    canaries = document["canaries"]
    repository_scope = {
        (
            item["repository_id"],
            item["canonical_root"],
            item["generation"],
            item["owner_uid"],
        )
        for item in repositories
    }
    if (
        len(repository_scope) != 1
        or len({item["client_uid"] for item in repositories}) != len(repositories)
        or len({item.get("user") for item in canaries}) != len(canaries)
        or len({item.get("uid") for item in canaries}) != len(canaries)
    ):
        raise BridgeError("clean successor proof canary scope is invalid")
    for field in (
        "bridge_journal",
        "broker_release",
        "client_release",
        "database",
        "profile",
        "broker_socket",
        "dropin",
    ):
        document[field] = str(
            _absolute(Path(str(document[field])), f"clean successor proof {field}")
        )
    return document


def _verify_clean_successor_live(
    *,
    transaction: Path,
    operation_id: str,
    expected_journal_sha256: str,
    expected_journal_document_sha256: str,
    broker_release: Path,
    client_release: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_accounts: Sequence[Mapping[str, object]],
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    wait_seconds: int,
    expected_uid: int,
    executor_rescue_sha256: str | None = None,
    _executor_rescue_client_binding: Mapping[str, object] | None = None,
    _cutover_maintenance_inventory_read: bool = False,
) -> dict[str, object]:
    if not isinstance(_cutover_maintenance_inventory_read, bool):
        raise BridgeError("clean successor canary mode is invalid")
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / JOURNAL_NAME
    journal_info_before = _private_regular(
        journal_path, uid=expected_uid, label="clean successor bridge journal"
    )
    if _sha256_file(journal_path) != expected_journal_sha256:
        raise BridgeError("clean successor bridge journal raw digest changed")
    bridge = _load_bridge_journal(journal_path, uid=expected_uid)
    if (
        bridge is None
        or bridge.get("operation_id") != operation_id
        or bridge.get("document_sha256") != expected_journal_document_sha256
        or bridge.get("phase") != "ready"
        or bridge.get("release") != str(broker_release)
        or bridge.get("broker_socket") != str(broker_socket)
        or bridge.get("dropin") != str(dropin)
        or bridge.get("executor_rescue")
        != (
            dict(_executor_rescue_client_binding)
            if _executor_rescue_client_binding is not None
            else None
        )
    ):
        raise BridgeError("clean successor bridge journal binding changed")
    broker_manifest = _verify_activation_release(
        broker_release,
        release_root=broker_release.parent,
        owner_uid=expected_uid,
    )
    executor_rescue_binding: dict[str, object] | None = None
    if _executor_rescue_client_binding is None:
        client_manifest = _verify_availability_client_release(
            client_release, owner_uid=expected_uid
        )
    else:
        (
            executor_rescue_binding,
            client_manifest,
        ) = _verify_successor_executor_rescue_runtime_binding(
            dict(_executor_rescue_client_binding),
            client_release=client_release,
            expected_uid=expected_uid,
        )
        if (
            executor_rescue_sha256
            != executor_rescue_binding["executor_rescue_sha256"]
        ):
            raise BridgeError(
                "clean successor executor rescue digest changed"
            )
    if bridge.get("release_digest") != broker_manifest["release_digest"]:
        raise BridgeError("clean successor broker release changed")
    dropin_identity = _verify_dropin_identity(
        dropin,
        bridge.get("dropin_identity"),
        uid=expected_uid,
        expected_sha256=str(bridge["dropin_sha256"]),
    )
    accounts = _validate_successor_canary_accounts(
        list(canary_accounts),
        owner_user=canary_user,
        owner_uid=expected_canary_uid,
    )
    profile_before = _profile_identity(profile, uid=expected_uid)
    repositories_before = [
        _profile_repository_binding(
            profile,
            client_uid=int(item["uid"]),
            owner_uid=expected_canary_uid,
            repository_id=canary_repository_id,
            repository_generation=canary_repository_generation,
            canonical_root=canary_project,
            database_generation=expected_database_generation,
            broker_socket=broker_socket,
        )
        for item in accounts
    ]
    state_before = _wait_active(broker_socket, wait_seconds)
    socket_before = _socket_identity(broker_socket)
    execution_before = _verify_loaded_bridge_execution(
        release=broker_release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_before = _broker_process_identity(
        main_pid=int(state_before["MainPID"]),
        expected_argv=list(execution_before["argv"]),
        expected_uid=0,
    )
    peer_before = _broker_socket_peer(broker_socket)
    canaries = [
        _inventory_canary(
            release=client_release,
            account=pwd.getpwnam(str(item["user"])),
            project=canary_project,
            expected_database_generation=expected_database_generation,
            expected_repository_id=canary_repository_id,
            canary_repository_generation=canary_repository_generation,
            expected_broker_socket=broker_socket,
            expected_service_uid=0,
            **(
                {
                    "profile": profile,
                    "_cutover_maintenance_inventory_read": True,
                    "_historical_release_digest": str(
                        client_manifest["release_digest"]
                    ),
                }
                if _cutover_maintenance_inventory_read
                else {}
            ),
        )
        for item in accounts
    ]
    if executor_rescue_binding is not None:
        for canary in canaries:
            canary["executor_rescue_sha256"] = (
                executor_rescue_binding["executor_rescue_sha256"]
            )
    state_after = _wait_active(broker_socket, wait_seconds)
    socket_after = _socket_identity(broker_socket)
    execution_after = _verify_loaded_bridge_execution(
        release=broker_release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_after = _broker_process_identity(
        main_pid=int(state_after["MainPID"]),
        expected_argv=list(execution_after["argv"]),
        expected_uid=0,
    )
    peer_after = _broker_socket_peer(broker_socket)
    profile_after = _profile_identity(profile, uid=expected_uid)
    repositories_after = [
        _profile_repository_binding(
            profile,
            client_uid=int(item["uid"]),
            owner_uid=expected_canary_uid,
            repository_id=canary_repository_id,
            repository_generation=canary_repository_generation,
            canonical_root=canary_project,
            database_generation=expected_database_generation,
            broker_socket=broker_socket,
        )
        for item in accounts
    ]
    journal_info_after = _private_regular(
        journal_path, uid=expected_uid, label="clean successor bridge journal"
    )
    if (
        state_after.get("InvocationID") != state_before.get("InvocationID")
        or state_after.get("MainPID") != state_before.get("MainPID")
        or socket_after != socket_before
        or execution_after != execution_before
        or process_after != process_before
        or peer_after != peer_before
        or peer_after.get("pid") != state_after.get("MainPID")
        or peer_after.get("uid") != 0
        or profile_after != profile_before
        or repositories_after != repositories_before
        or _sha256_file(journal_path) != expected_journal_sha256
        or any(
            getattr(journal_info_after, field) != getattr(journal_info_before, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
            )
        )
    ):
        raise BridgeError("clean successor changed during strict live proof")
    return _verify_successor_ready_proof(
        _seal(
            SUCCESSOR_READY_PROOF_KIND,
            {
                "operation_id": operation_id,
                "bridge_journal": str(journal_path),
                "bridge_journal_sha256": expected_journal_sha256,
                "bridge_document_sha256": expected_journal_document_sha256,
                "broker_release": str(broker_release),
                "broker_release_digest": broker_manifest["release_digest"],
                "client_release": str(client_release),
                "client_release_digest": client_manifest["release_digest"],
                "executor_rescue": executor_rescue_binding,
                "executor_rescue_sha256": executor_rescue_sha256,
                "database": str(database),
                "database_generation": expected_database_generation,
                "profile": str(profile),
                "profile_identity": profile_before,
                "owner_uid": expected_canary_uid,
                "profile_repositories": repositories_before,
                "broker_socket": str(broker_socket),
                "socket_identity": socket_before,
                "socket_peer": peer_after,
                "dropin": str(dropin),
                "dropin_identity": dropin_identity,
                "systemd": state_after,
                "execution": execution_after,
                "process": process_after,
                "canaries": canaries,
                "verified_at_epoch": int(time.time()),
            },
        )
    )


def _verify_restored_predecessor_live(
    *,
    predecessor: Mapping[str, object],
    profile: Path,
    expected_profile_sha256: str,
    owner_binding: Mapping[str, object],
    database: Path,
    broker_socket: Path,
    dropin: Path,
    canary_user: str,
    canary_uid: int,
    canary_project: Path,
    repository_id: str,
    repository_generation: int,
    expected_database_generation: str,
    wait_seconds: int,
    expected_uid: int,
) -> dict[str, object]:
    _verify_successor_predecessor(predecessor, expected_uid=expected_uid)
    release = Path(str(predecessor["release"]))
    manifest = _verify_activation_release(
        release, release_root=release.parent, owner_uid=expected_uid
    )
    profile_identity = _profile_identity(profile, uid=expected_uid)
    if profile_identity["sha256"] != expected_profile_sha256:
        raise BridgeError("restored predecessor profile differs from its backup")
    dropin_identity = _dropin_identity(
        dropin,
        uid=expected_uid,
        expected_sha256=str(predecessor["dropin_sha256"]),
    )
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    if account.pw_uid != canary_uid:
        raise BridgeError("restored predecessor canary owner UID changed")
    state_before = _wait_active(broker_socket, wait_seconds)
    socket_before = _socket_identity(broker_socket)
    execution_before = _verify_loaded_bridge_execution(
        release=release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_before = _broker_process_identity(
        main_pid=int(state_before["MainPID"]),
        expected_argv=list(execution_before["argv"]),
        expected_uid=0,
    )
    peer_before = _broker_socket_peer(broker_socket)
    canary = _inventory_canary(
        release=release,
        account=account,
        project=canary_project,
        expected_database_generation=expected_database_generation,
        expected_repository_id=repository_id,
        canary_repository_generation=repository_generation,
        expected_broker_socket=broker_socket,
        expected_service_uid=0,
    )
    state_after = _wait_active(broker_socket, wait_seconds)
    socket_after = _socket_identity(broker_socket)
    execution_after = _verify_loaded_bridge_execution(
        release=release,
        database=database,
        broker_socket=broker_socket,
        dropin=dropin,
    )
    process_after = _broker_process_identity(
        main_pid=int(state_after["MainPID"]),
        expected_argv=list(execution_after["argv"]),
        expected_uid=0,
    )
    peer_after = _broker_socket_peer(broker_socket)
    if (
        state_after.get("InvocationID") != state_before.get("InvocationID")
        or state_after.get("MainPID") != state_before.get("MainPID")
        or socket_after != socket_before
        or execution_after != execution_before
        or process_after != process_before
        or peer_after != peer_before
        or peer_after.get("pid") != state_after.get("MainPID")
        or peer_after.get("uid") != 0
    ):
        raise BridgeError("restored schema-12 predecessor changed during proof")
    return _seal(
        SUCCESSOR_RESTORED_PROOF_KIND,
        {
            "predecessor_journal_sha256": predecessor["journal_sha256"],
            "predecessor_document_sha256": predecessor["document_sha256"],
            "release": str(release),
            "release_digest": manifest["release_digest"],
            "profile": str(profile),
            "profile_identity": profile_identity,
            "profile_owner_binding_sha256": owner_binding["document_sha256"],
            "broker_socket": str(broker_socket),
            "socket_identity": socket_after,
            "socket_peer": peer_after,
            "dropin": str(dropin),
            "dropin_identity": dropin_identity,
            "systemd": state_after,
            "execution": execution_after,
            "process": process_after,
            "canary": canary,
            "verified_at_epoch": int(time.time()),
        },
    )


def _successor_terminal_payload(
    *,
    current: Mapping[str, object],
    journal_path: Path,
    status: str,
) -> dict[str, object]:
    profile = current["profile"]
    candidate = current["candidate"]
    restored = current["restored_predecessor"]
    executor_rescue_record = current["binding"].get("executor_rescue")
    executor_rescue = (
        _successor_executor_rescue_runtime_binding(
            executor_rescue_record,
            expected_uid=os.geteuid(),
            handoff_value=current["binding"].get(
                "executor_rescue_handoff"
            ),
            continuation_value=current["binding"].get(
                "executor_rescue_post_export_continuation"
            ),
        )
        if executor_rescue_record is not None
        else None
    )
    executor_rescue_sha256 = (
        executor_rescue["executor_rescue_sha256"]
        if executor_rescue is not None
        else None
    )
    readiness = candidate.get("readiness") if isinstance(candidate, dict) else None
    restored_proof = restored.get("proof") if isinstance(restored, dict) else None
    if (
        not isinstance(candidate, Mapping)
        or candidate.get("executor_rescue_sha256")
        != executor_rescue_sha256
        or candidate.get("executor_rescue") != executor_rescue
        or status == "committed"
        and (
            not isinstance(readiness, Mapping)
            or readiness.get("executor_rescue_sha256")
            != executor_rescue_sha256
            or readiness.get("executor_rescue") != executor_rescue
        )
    ):
        raise BridgeError(
            "schema-12 successor terminal lost its executor rescue binding"
        )
    return {
        "operation_id": current["operation_id"],
        "status": status,
        "transaction_journal": str(journal_path),
        "transaction_journal_sha256": _sha256_file(journal_path),
        "transaction_document_sha256": current["document_sha256"],
        "predecessor_release_digest": current["predecessor"]["release_digest"],
        "candidate_release_digest": current["binding"]["candidate_release_digest"],
        "profile_before_sha256": profile["backup_sha256"],
        "profile_after_sha256": (
            profile["repaired_payload_sha256"] or profile["backup_sha256"]
        ),
        "profile_owner_binding_sha256": profile["owner_binding_sha256"],
        "candidate_readiness_sha256": (
            readiness["document_sha256"] if status == "committed" else None
        ),
        "restored_predecessor_sha256": (
            restored_proof["document_sha256"] if status == "aborted" else None
        ),
        "maintenance_deployment_id": current["binding"]["maintenance"][
            "deployment_id"
        ],
        "maintenance_handoff_sha256": current["binding"][
            "maintenance_handoff"
        ]["attestation_document_sha256"],
        "executor_rescue": executor_rescue,
        "executor_rescue_sha256": executor_rescue_sha256,
        "maintenance_clear_pending": True,
        "completed_at": _utc_now(),
    }


def _successor_completion_payload(
    *,
    current: Mapping[str, object],
    terminal_path: Path,
    terminal: Mapping[str, object],
    postclear_readiness: Mapping[str, object],
) -> dict[str, object]:
    executor_rescue_record = current["binding"].get("executor_rescue")
    executor_rescue = (
        _successor_executor_rescue_runtime_binding(
            executor_rescue_record,
            expected_uid=os.geteuid(),
            handoff_value=current["binding"].get(
                "executor_rescue_handoff"
            ),
            continuation_value=current["binding"].get(
                "executor_rescue_post_export_continuation"
            ),
        )
        if executor_rescue_record is not None
        else None
    )
    executor_rescue_sha256 = (
        executor_rescue["executor_rescue_sha256"]
        if executor_rescue is not None
        else None
    )
    if (
        terminal.get("executor_rescue") != executor_rescue
        or terminal.get("executor_rescue_sha256") != executor_rescue_sha256
        or postclear_readiness.get("executor_rescue") != executor_rescue
        or postclear_readiness.get("executor_rescue_sha256")
        != executor_rescue_sha256
    ):
        raise BridgeError(
            "schema-12 successor completion lost its executor rescue binding"
        )
    return {
        "operation_id": current["operation_id"],
        "status": "committed",
        "terminal": str(terminal_path),
        "terminal_sha256": _sha256_file(terminal_path),
        "terminal_document_sha256": terminal["document_sha256"],
        "transaction_document_sha256": current["document_sha256"],
        "postclear_readiness": dict(postclear_readiness),
        "maintenance_deployment_id": current["binding"]["maintenance"][
            "deployment_id"
        ],
        "maintenance_handoff_sha256": current["binding"][
            "maintenance_handoff"
        ]["attestation_document_sha256"],
        "executor_rescue": executor_rescue,
        "executor_rescue_sha256": executor_rescue_sha256,
        "maintenance_cleared": True,
        "completed_at": _utc_now(),
    }


def _verify_committed_successor_terminal_binding(
    terminal: Mapping[str, object],
    *,
    current: Mapping[str, object],
    journal_path: Path,
) -> dict[str, object]:
    """Bind a committed terminal to the exact durable successor journal.

    The timestamp is descriptive. Every other field is a deterministic
    consequence of the retained transaction and must match exactly before the
    inherited maintenance marker may be cleared.
    """

    verified = _verify_successor_terminal(terminal)
    expected = _successor_terminal_payload(
        current=current,
        journal_path=journal_path,
        status="committed",
    )
    expected["completed_at"] = verified["completed_at"]
    retained = {field: verified[field] for field in _SUCCESSOR_TERMINAL_FIELDS}
    if retained != expected:
        raise BridgeError("schema-12 successor terminal lost its exact binding")
    return verified


def _replace_ready_bridge_with_clean_successor_impl(
    *,
    candidate_release: Path,
    release_root: Path,
    client_release: Path,
    transaction: Path,
    operation_id: str,
    predecessor_transaction: Path,
    predecessor_operation_id: str,
    predecessor_journal_sha256: str,
    predecessor_document_sha256: str,
    failed_installer_transaction: Path,
    failed_installer_operation_id: str,
    readiness_attestation: Path,
    database: Path,
    profile: Path,
    owner_map: Path,
    owner_map_sha256: str,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    lifecycle_transaction_journal: Path,
    lifecycle_transaction_journal_sha256: str,
    lifecycle_transaction_document_sha256: str,
    lifecycle_attestation: Path,
    lifecycle_attestation_sha256: str,
    lifecycle_attestation_document_sha256: str,
    additional_canaries: Sequence[str] = (),
    inherited_successor_journal_sha256: str | None = None,
    inherited_successor_document_sha256: str | None = None,
    wait_seconds: int = 30,
    expected_uid: int = 0,
    failpoint: Callable[[str], None] = lambda _stage: None,
    _executor_rescue_request: Mapping[str, object] | None = None,
    _executor_rescue_handoff_request: Mapping[str, object] | None = None,
    _post_export_executor_continuation_request: Mapping[str, object] | None = None,
) -> dict[str, object]:
    try:
        operation_id = str(uuid.UUID(operation_id))
        predecessor_operation_id = str(uuid.UUID(predecessor_operation_id))
        failed_installer_operation_id = str(uuid.UUID(failed_installer_operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 successor operation identity is invalid") from error
    if len({operation_id, predecessor_operation_id, failed_installer_operation_id}) != 3:
        raise BridgeError("schema-12 successor operation identities must be distinct")
    if os.geteuid() != expected_uid:
        raise BridgeError("schema-12 successor requires the exact authority identity")
    if not 1 <= wait_seconds <= 120:
        raise BridgeError("schema-12 successor wait must be from 1 through 120 seconds")
    if (
        isinstance(expected_canary_uid, bool)
        or not isinstance(expected_canary_uid, int)
        or expected_canary_uid <= 0
        or not isinstance(canary_repository_generation, int)
        or isinstance(canary_repository_generation, bool)
        or canary_repository_generation < 0
        or not canary_repository_id
        or not expected_database_generation
    ):
        raise BridgeError("schema-12 successor GlobalFinance identity is invalid")
    transaction = _private_directory(transaction, uid=expected_uid, create=True)
    journal_path = transaction / SUCCESSOR_JOURNAL_NAME
    terminal_path = transaction / SUCCESSOR_TERMINAL_NAME
    completion_path = transaction / SUCCESSOR_COMPLETION_NAME
    backup_path = transaction / SUCCESSOR_PROFILE_BACKUP_NAME
    client_handoff_intent_path = (
        transaction / SUCCESSOR_CLIENT_HANDOFF_INTENT_NAME
    )
    client_handoff_backup_path = (
        transaction / SUCCESSOR_CLIENT_HANDOFF_BACKUP_NAME
    )
    executor_rescue_intent_path = (
        transaction / SUCCESSOR_EXECUTOR_RESCUE_INTENT_NAME
    )
    executor_rescue_backup_path = (
        transaction / SUCCESSOR_EXECUTOR_RESCUE_BACKUP_NAME
    )
    executor_handoff_intent_path = (
        transaction / SUCCESSOR_EXECUTOR_HANDOFF_INTENT_NAME
    )
    executor_handoff_backup_path = (
        transaction / SUCCESSOR_EXECUTOR_HANDOFF_BACKUP_NAME
    )
    post_export_continuation_intent_path = (
        transaction / SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_INTENT_NAME
    )
    post_export_continuation_backup_path = (
        transaction / SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_BACKUP_NAME
    )
    post_export_failed_candidate_backup_path = (
        transaction / SUCCESSOR_POST_EXPORT_FAILED_CANDIDATE_BACKUP_NAME
    )
    candidate_transaction = _private_directory(
        transaction / SUCCESSOR_CANDIDATE_DIRECTORY,
        uid=expected_uid,
        create=True,
    )
    restore_transaction = _private_directory(
        transaction / SUCCESSOR_RESTORE_DIRECTORY,
        uid=expected_uid,
        create=True,
    )
    snapshot_root = _private_directory(
        transaction / SUCCESSOR_SNAPSHOT_DIRECTORY,
        uid=expected_uid,
        create=True,
    )
    candidate_release = _absolute(candidate_release, "clean schema-12 release")
    release_root = _absolute(release_root, "clean schema-12 release root")
    client_release = _absolute(client_release, "strict successor client release")
    predecessor_transaction = _private_directory(
        predecessor_transaction, uid=expected_uid
    )
    failed_installer_transaction = _private_directory(
        failed_installer_transaction, uid=expected_uid
    )
    readiness_attestation = _absolute(
        readiness_attestation, "authority readiness attestation"
    )
    database = _absolute(database, "legacy authority database")
    profile = _absolute(profile, "protected profile")
    owner_map = _absolute(owner_map, "sealed repository owner map")
    broker_socket = _absolute(broker_socket, "broker socket")
    dropin = _absolute(dropin, "broker bridge drop-in")
    canary_project = _absolute(canary_project, "GlobalFinance repository")
    if canary_project.name != "GlobalFinance":
        raise BridgeError("schema-12 successor requires the exact GlobalFinance root")
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    if account.pw_uid != expected_canary_uid:
        raise BridgeError("schema-12 successor GlobalFinance owner UID changed")
    canary_accounts = _successor_canary_accounts(
        owner_user=canary_user,
        owner_uid=expected_canary_uid,
        additional_canaries=additional_canaries,
    )
    candidate_operation_id = str(
        uuid.uuid5(uuid.UUID(operation_id), "schema12-clean-successor-candidate")
    )
    restore_operation_id = str(
        uuid.uuid5(uuid.UUID(operation_id), "schema12-clean-successor-restore")
    )
    candidate_manifest = _verify_activation_release(
        candidate_release,
        release_root=release_root,
        owner_uid=expected_uid,
    )
    release_pair = _verify_successor_release_pair(
        client_release, owner_uid=expected_uid
    )
    client_manifest = {
        "release_digest": release_pair["client_release_digest"]
    }
    owner_map_reference = _sealed_owner_map_reference(
        owner_map,
        owner_map_sha256=owner_map_sha256,
        expected_uid=expected_uid,
    )
    maintenance_handoff = _verify_lifecycle_successor_handoff(
        transaction_journal=lifecycle_transaction_journal,
        transaction_journal_sha256=lifecycle_transaction_journal_sha256,
        transaction_document_sha256=lifecycle_transaction_document_sha256,
        attestation=lifecycle_attestation,
        attestation_sha256=lifecycle_attestation_sha256,
        attestation_document_sha256=lifecycle_attestation_document_sha256,
        expected_canary_release_digest=candidate_manifest["release_digest"],
        predecessor_transaction=predecessor_transaction,
        predecessor_operation_id=predecessor_operation_id,
        predecessor_journal_sha256=predecessor_journal_sha256,
        predecessor_document_sha256=predecessor_document_sha256,
        database=database,
        profile=profile,
        broker_socket=broker_socket,
        dropin=dropin,
        expected_database_generation=expected_database_generation,
        expected_uid=expected_uid,
    )
    if maintenance_handoff["operation_id"] in {
        operation_id,
        predecessor_operation_id,
        failed_installer_operation_id,
    }:
        raise BridgeError("schema-12 successor operation identities must be distinct")
    maintenance = _validated_successor_maintenance(
        maintenance_handoff["maintenance"]
    )
    binding = {
        "candidate_release": str(candidate_release),
        "candidate_release_digest": candidate_manifest["release_digest"],
        "candidate_release_root": str(release_root),
        "client_release": str(client_release),
        "client_release_digest": client_manifest["release_digest"],
        "candidate_transaction": str(candidate_transaction),
        "candidate_operation_id": candidate_operation_id,
        "restore_transaction": str(restore_transaction),
        "restore_operation_id": restore_operation_id,
        "snapshot_root": str(snapshot_root),
        "predecessor_transaction": str(predecessor_transaction),
        "predecessor_operation_id": predecessor_operation_id,
        "predecessor_journal_sha256": predecessor_journal_sha256,
        "predecessor_document_sha256": predecessor_document_sha256,
        "failed_installer_transaction": str(failed_installer_transaction),
        "failed_installer_operation_id": failed_installer_operation_id,
        "readiness_attestation": str(readiness_attestation),
        "database": str(database),
        "profile": str(profile),
        "owner_map": owner_map_reference,
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "expected_database_generation": expected_database_generation,
        "canary_user": canary_user,
        "expected_canary_uid": expected_canary_uid,
        "canary_project": str(canary_project),
        "canary_repository_id": canary_repository_id,
        "canary_repository_generation": canary_repository_generation,
        "canary_accounts": canary_accounts,
        "maintenance_handoff": maintenance_handoff,
        "maintenance": maintenance,
        "wait_seconds": wait_seconds,
    }
    requested_successor_binding = dict(binding)
    with _successor_transaction_fence(
        operation_id=operation_id,
        journal=journal_path,
        terminal=terminal_path,
        action="prepare",
        expected_uid=expected_uid,
    ) as fence, ExitStack() as continuation_locks:
        current = _load_successor_journal(journal_path, uid=expected_uid)
        if current is not None and current["operation_id"] != operation_id:
            raise BridgeError("schema-12 successor journal belongs to another request")
        if release_pair["historical_client"] is True:
            rescue_routes = sum(
                request is not None
                for request in (
                    _executor_rescue_request,
                    _executor_rescue_handoff_request,
                    _post_export_executor_continuation_request,
                )
            )
            if rescue_routes == 0:
                raise BridgeError(
                    "schema-12 successor-apply forbids a historical client; "
                    "use the dedicated executor rescue route"
                )
            if rescue_routes != 1:
                raise BridgeError(
                    "schema-12 successor rescue routes are mutually exclusive"
                )
            if _post_export_executor_continuation_request is not None:
                _validate_successor_post_export_executor_continuation_request(
                    dict(_post_export_executor_continuation_request),
                    current=current,
                    release_pair=release_pair,
                    inherited_journal_sha256=(
                        inherited_successor_journal_sha256
                    ),
                    inherited_document_sha256=(
                        inherited_successor_document_sha256
                    ),
                    expected_uid=expected_uid,
                )
            elif _executor_rescue_handoff_request is not None:
                _validate_successor_executor_handoff_request(
                    dict(_executor_rescue_handoff_request),
                    current=current,
                    release_pair=release_pair,
                    inherited_journal_sha256=(
                        inherited_successor_journal_sha256
                    ),
                    inherited_document_sha256=(
                        inherited_successor_document_sha256
                    ),
                    expected_uid=expected_uid,
                )
            else:
                _validate_successor_executor_rescue_request(
                    dict(_executor_rescue_request),
                    current=current,
                    release_pair=release_pair,
                    inherited_journal_sha256=(
                        inherited_successor_journal_sha256
                    ),
                    inherited_document_sha256=(
                        inherited_successor_document_sha256
                    ),
                    expected_uid=expected_uid,
                )
        elif (
            _executor_rescue_request is not None
            or _executor_rescue_handoff_request is not None
            or _post_export_executor_continuation_request is not None
        ):
            raise BridgeError(
                "schema-12 executor rescue requires a distinct retained client"
            )
        if (
            _executor_rescue_request is None
            and _executor_rescue_handoff_request is None
            and _post_export_executor_continuation_request is None
        ):
            current = _refresh_inherited_lifecycle_owner_map(
                current,
                requested_binding=binding,
                release_pair=release_pair,
                journal_path=journal_path,
                expected_uid=expected_uid,
            )
        _authorize_successor_release_pair(
            current,
            requested_binding=binding,
            release_pair=release_pair,
            inherited_journal_sha256=inherited_successor_journal_sha256,
            inherited_document_sha256=inherited_successor_document_sha256,
            executor_handoff_request=_executor_rescue_handoff_request,
            post_export_continuation_request=(
                _post_export_executor_continuation_request
            ),
        )
        if current is None:
            handoff_predecessor_proof = maintenance_handoff[
                "predecessor_proof"
            ]
            handoff_outer_rearm = handoff_predecessor_proof.get(
                "outer_rearm"
            )
            ready_proof = _verify_active_predecessor_for_successor(
                transaction=predecessor_transaction,
                operation_id=predecessor_operation_id,
                expected_journal_sha256=predecessor_journal_sha256,
                expected_journal_document_sha256=predecessor_document_sha256,
                historical_client_release=candidate_release,
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_database_generation=expected_database_generation,
                canary_user=canary_user,
                expected_canary_uid=expected_canary_uid,
                canary_project=canary_project,
                canary_repository_id=canary_repository_id,
                canary_repository_generation=canary_repository_generation,
                wait_seconds=wait_seconds,
                expected_uid=expected_uid,
                _allow_restored=handoff_outer_rearm is not None,
                _expected_dropin_identity=(
                    handoff_predecessor_proof.get("dropin_identity")
                    if handoff_outer_rearm is not None
                    else None
                ),
                _outer_rearm=handoff_outer_rearm,
            )
            if _proof_stable_binding(ready_proof) != _proof_stable_binding(
                maintenance_handoff["predecessor_proof"]
            ):
                raise BridgeError(
                    "active predecessor changed after lifecycle recovery handoff"
                )
            predecessor = _successor_predecessor_reference(
                transaction=predecessor_transaction,
                operation_id=predecessor_operation_id,
                journal_sha256=predecessor_journal_sha256,
                document_sha256=predecessor_document_sha256,
                ready_proof=ready_proof,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_uid=expected_uid,
            )
            predecessor_release = Path(str(predecessor["release"]))
            if (
                release_root == predecessor_release.parent
                or candidate_release == predecessor_release
            ):
                raise BridgeError(
                    "clean successor requires a fresh protected release root"
                )
            profile_state = _capture_successor_profile(
                profile, backup=backup_path, uid=expected_uid
            )
            profile_state["owner_binding"] = owner_map_reference
            profile_state["owner_binding_sha256"] = owner_map_reference[
                "document_sha256"
            ]
            now = int(time.time())
            current = _successor_journal(
                journal_path,
                {
                    "operation_id": operation_id,
                    "binding": binding,
                    "predecessor": predecessor,
                    "profile": profile_state,
                    "candidate": {"activation": None, "readiness": None},
                    "restored_predecessor": None,
                    "phase": "predecessor-verified",
                    "error": None,
                    "created_at_epoch": now,
                    "updated_at_epoch": now,
                },
                uid=expected_uid,
            )
            failpoint("after-initial-journal")
        if current["operation_id"] != operation_id:
            raise BridgeError("schema-12 successor journal belongs to another request")
        if _post_export_executor_continuation_request is not None:
            continuation_binding = current.get("binding")
            if not isinstance(continuation_binding, Mapping):
                raise BridgeError(
                    "schema-12 post-export executor continuation lacks maintenance"
                )
            continuation_maintenance = _validated_successor_maintenance(
                continuation_binding.get("maintenance")
            )
            continuation_contract = _load_maintenance_contract()
            continuation_locks.enter_context(
                continuation_contract.maintenance_writer_lock(
                    maintenance_root=Path(
                        str(continuation_maintenance["root"])
                    ),
                    expected_uid=expected_uid,
                    expected_gid=int(continuation_maintenance["gid"]),
                )
            )
            current = _migrate_successor_post_export_executor_continuation(
                current,
                request=dict(_post_export_executor_continuation_request),
                requested_binding=binding,
                release_pair=release_pair,
                journal_path=journal_path,
                intent_path=post_export_continuation_intent_path,
                journal_backup_path=post_export_continuation_backup_path,
                failed_candidate_backup_path=(
                    post_export_failed_candidate_backup_path
                ),
                terminal_path=terminal_path,
                completion_path=completion_path,
                inherited_journal_sha256=str(
                    inherited_successor_journal_sha256
                ),
                inherited_document_sha256=str(
                    inherited_successor_document_sha256
                ),
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_uid=expected_uid,
                failpoint=failpoint,
            )
            failpoint(
                "after-retained-post-export-executor-continuation-verify"
            )
        elif _executor_rescue_handoff_request is not None:
            handoff_binding = current.get("binding")
            if not isinstance(handoff_binding, Mapping):
                raise BridgeError(
                    "schema-12 rescue executor handoff lacks maintenance"
                )
            handoff_maintenance = _validated_successor_maintenance(
                handoff_binding.get("maintenance")
            )
            handoff_contract = _load_maintenance_contract()
            with handoff_contract.maintenance_writer_lock(
                maintenance_root=Path(str(handoff_maintenance["root"])),
                expected_uid=expected_uid,
                expected_gid=int(handoff_maintenance["gid"]),
            ):
                current = _migrate_successor_rescue_executor_handoff(
                    current,
                    request=dict(_executor_rescue_handoff_request),
                    requested_binding=binding,
                    release_pair=release_pair,
                    journal_path=journal_path,
                    intent_path=executor_handoff_intent_path,
                    journal_backup_path=executor_handoff_backup_path,
                    terminal_path=terminal_path,
                    completion_path=completion_path,
                    inherited_journal_sha256=str(
                        inherited_successor_journal_sha256
                    ),
                    inherited_document_sha256=str(
                        inherited_successor_document_sha256
                    ),
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_uid=expected_uid,
                    failpoint=failpoint,
                )
            failpoint("after-retained-rescue-executor-handoff-verify")
        migration_binding = current.get("binding")
        migration_required = (
            isinstance(migration_binding, Mapping)
            and migration_binding != binding
            and "client_release_handoffs" not in migration_binding
        )
        handoff_replay_guard_required = (
            isinstance(migration_binding, Mapping)
            and "client_release_handoffs" in migration_binding
        )
        executor_rescue_required = False
        client_validation_binding = dict(binding)
        if handoff_replay_guard_required:
            migration_handoffs = migration_binding.get(
                "client_release_handoffs"
            )
            if not isinstance(migration_handoffs, list) or len(
                migration_handoffs
            ) != 1:
                raise BridgeError(
                    "schema-12 successor client handoff lineage is invalid"
                )
            migration_handoff = _validated_successor_client_handoff(
                migration_handoffs[0], expected_uid=expected_uid
            )
            executor_rescue_required = (
                "executor_rescue" in migration_binding
                or release_pair["historical_client"] is True
            )
            if executor_rescue_required:
                client_validation_binding["client_release"] = (
                    migration_handoff["successor_client_release"]
                )
                client_validation_binding["client_release_digest"] = (
                    migration_handoff[
                        "successor_client_release_digest"
                    ]
                )

        def migrate_release_lineage() -> dict[str, object]:
            migrated = _migrate_inherited_successor_client_release(
                current,
                requested_binding=client_validation_binding,
                journal_path=journal_path,
                intent_path=client_handoff_intent_path,
                journal_backup_path=client_handoff_backup_path,
                terminal_path=terminal_path,
                completion_path=completion_path,
                inherited_journal_sha256=(
                    None
                    if executor_rescue_required
                    else inherited_successor_journal_sha256
                ),
                inherited_document_sha256=(
                    None
                    if executor_rescue_required
                    else inherited_successor_document_sha256
                ),
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_uid=expected_uid,
                failpoint=failpoint,
                _allow_retired_sidecar_timestamp_drift=(
                    executor_rescue_required
                ),
            )
            if not executor_rescue_required:
                return migrated
            migrated_binding = migrated.get("binding")
            migrated_rescue = (
                migrated_binding.get("executor_rescue")
                if isinstance(migrated_binding, Mapping)
                else None
            )
            rescue_journal_sha256 = (
                str(migrated_rescue["journal_raw_sha256"])
                if isinstance(migrated_rescue, Mapping)
                else inherited_successor_journal_sha256
            )
            rescue_document_sha256 = (
                str(migrated_rescue["journal_document_sha256"])
                if isinstance(migrated_rescue, Mapping)
                else inherited_successor_document_sha256
            )
            return _migrate_inherited_successor_executor_rescue(
                migrated,
                requested_binding=binding,
                release_pair=release_pair,
                journal_path=journal_path,
                intent_path=executor_rescue_intent_path,
                journal_backup_path=executor_rescue_backup_path,
                terminal_path=terminal_path,
                completion_path=completion_path,
                inherited_journal_sha256=(
                    rescue_journal_sha256
                ),
                inherited_document_sha256=(
                    rescue_document_sha256
                ),
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_uid=expected_uid,
                failpoint=failpoint,
            )

        if release_pair["historical_client"] is True and not executor_rescue_required:
            raise BridgeError(
                "schema-12 successor historical client is outside its rescue route"
            )
        if migration_required or handoff_replay_guard_required:
            if _post_export_executor_continuation_request is not None:
                current = migrate_release_lineage()
            else:
                migration_maintenance = _validated_successor_maintenance(
                    migration_binding.get("maintenance")
                )
                migration_contract = _load_maintenance_contract()
                with migration_contract.maintenance_writer_lock(
                    maintenance_root=Path(
                        str(migration_maintenance["root"])
                    ),
                    expected_uid=expected_uid,
                    expected_gid=int(migration_maintenance["gid"]),
                ):
                    current = migrate_release_lineage()
        else:
            current = migrate_release_lineage()
        if handoff_replay_guard_required:
            failpoint("after-retained-client-release-handoff-verify")
        binding = dict(current["binding"])
        if not isinstance(
            binding.get("maintenance"), dict
        ) or not isinstance(binding.get("maintenance_handoff"), dict):
            raise BridgeError("schema-12 successor static binding changed")
        maintenance = current["binding"]["maintenance"]
        current = _repair_inherited_successor_predecessor_sha_replay(
            current,
            journal_path=journal_path,
            expected_uid=expected_uid,
        )
        predecessor = _verify_successor_predecessor(
            current["predecessor"],
            expected_uid=expected_uid,
            retired_dropin_boundary=(
                _retired_successor_predecessor_dropin_boundary(
                    current, expected_uid=expected_uid
                )
            ),
            verify_retired_absence=(
                current.get("phase") == "predecessor-retired"
            ),
        )
        if (
            Path(str(binding["candidate_release_root"]))
            == Path(str(predecessor["release"])).parent
            or candidate_release == Path(str(predecessor["release"]))
        ):
            raise BridgeError("clean successor release root overlaps its predecessor")
        if candidate_manifest["release_digest"] != predecessor["release_digest"]:
            raise BridgeError(
                "clean successor must reproduce the exact predecessor release bytes"
            )
        if candidate_manifest["release_digest"] != binding["candidate_release_digest"]:
            raise BridgeError("clean successor release changed after planning")

        def persist(phase: str, **updates: object) -> dict[str, object]:
            nonlocal current
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload.update(updates)
            payload["phase"] = phase
            payload["updated_at_epoch"] = int(time.time())
            current = _successor_journal(journal_path, payload, uid=expected_uid)
            return current

        def verify_candidate_now(
            *, maintenance_active: bool
        ) -> dict[str, object]:
            candidate = current["candidate"]
            (
                effective_candidate_transaction,
                effective_candidate_operation_id,
            ) = _successor_effective_candidate_target(
                current["binding"], expected_uid=expected_uid, create=False
            )
            executor_rescue = current["binding"].get("executor_rescue")
            executor_rescue_binding = (
                _successor_executor_rescue_runtime_binding(
                    executor_rescue,
                    expected_uid=expected_uid,
                    handoff_value=current["binding"].get(
                        "executor_rescue_handoff"
                    ),
                    continuation_value=current["binding"].get(
                        "executor_rescue_post_export_continuation"
                    ),
                )
                if executor_rescue is not None
                else None
            )
            executor_rescue_sha256 = (
                executor_rescue_binding["executor_rescue_sha256"]
                if executor_rescue_binding is not None
                else None
            )
            if (
                not isinstance(candidate, Mapping)
                or not isinstance(candidate.get("journal_sha256"), str)
                or not isinstance(candidate.get("document_sha256"), str)
                or candidate.get("executor_rescue")
                != executor_rescue_binding
                or candidate.get("executor_rescue_sha256")
                != executor_rescue_sha256
            ):
                raise BridgeError("schema-12 successor candidate evidence is absent")
            readiness = _verify_clean_successor_live(
                transaction=effective_candidate_transaction,
                operation_id=effective_candidate_operation_id,
                expected_journal_sha256=str(candidate["journal_sha256"]),
                expected_journal_document_sha256=str(candidate["document_sha256"]),
                broker_release=candidate_release,
                client_release=client_release,
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                expected_database_generation=expected_database_generation,
                canary_user=canary_user,
                expected_canary_uid=expected_canary_uid,
                canary_accounts=canary_accounts,
                canary_project=canary_project,
                canary_repository_id=canary_repository_id,
                canary_repository_generation=canary_repository_generation,
                wait_seconds=wait_seconds,
                expected_uid=expected_uid,
                executor_rescue_sha256=executor_rescue_sha256,
                _executor_rescue_client_binding=executor_rescue_binding,
                _cutover_maintenance_inventory_read=maintenance_active,
            )
            retained = candidate.get("readiness")
            if retained is not None:
                if not isinstance(retained, Mapping):
                    raise BridgeError(
                        "schema-12 successor live readiness changed"
                    )
                retained_proof = _verify_successor_ready_proof(retained)
                if _successor_live_identity_binding(
                    readiness
                ) != _successor_live_identity_binding(retained_proof):
                    raise BridgeError(
                        "schema-12 successor live readiness changed"
                    )
            return readiness

        def complete_terminal(
            terminal: Mapping[str, object],
        ) -> dict[str, object]:
            maintenance_active = not _maintenance_is_clear(
                maintenance, uid=expected_uid
            )
            preclear = verify_candidate_now(
                maintenance_active=maintenance_active
            )
            if maintenance_active:
                _clear_successor_maintenance(maintenance, uid=expected_uid)
            if not _maintenance_is_clear(maintenance, uid=expected_uid):
                raise BridgeError("schema-12 successor maintenance remained active")
            failpoint("after-maintenance-clear")
            postclear = verify_candidate_now(maintenance_active=False)
            if _successor_live_identity_binding(
                preclear
            ) != _successor_live_identity_binding(postclear):
                raise BridgeError("schema-12 successor changed across maintenance clear")
            if completion_path.exists() or completion_path.is_symlink():
                completion = _verify_successor_completion(
                    _read_private_json(
                        completion_path,
                        uid=expected_uid,
                        label="schema-12 successor completion",
                    )
                )
                if (
                    completion["operation_id"] != operation_id
                    or completion["terminal"] != str(terminal_path)
                    or completion["terminal_sha256"] != _sha256_file(terminal_path)
                    or completion["terminal_document_sha256"]
                    != terminal["document_sha256"]
                    or completion["transaction_document_sha256"]
                    != current["document_sha256"]
                    or completion["maintenance_deployment_id"]
                    != maintenance["deployment_id"]
                    or completion["maintenance_handoff_sha256"]
                    != maintenance_handoff["attestation_document_sha256"]
                    or completion["executor_rescue"]
                    != terminal["executor_rescue"]
                    or completion["executor_rescue"]
                    != postclear.get("executor_rescue")
                    or completion["executor_rescue_sha256"]
                    != terminal["executor_rescue_sha256"]
                    or completion["executor_rescue_sha256"]
                    != postclear.get("executor_rescue_sha256")
                    or _proof_stable_binding(completion["postclear_readiness"])
                    != _proof_stable_binding(postclear)
                ):
                    raise BridgeError(
                        "schema-12 successor completion lost its live binding"
                    )
                return completion
            completion = _successor_completion(
                completion_path,
                _successor_completion_payload(
                    current=current,
                    terminal_path=terminal_path,
                    terminal=terminal,
                    postclear_readiness=postclear,
                ),
                uid=expected_uid,
            )
            failpoint("after-completion-publish")
            return completion

        if terminal_path.exists() or terminal_path.is_symlink():
            terminal = _verify_committed_successor_terminal_binding(
                _read_private_json(
                    terminal_path, uid=expected_uid, label="schema-12 successor terminal"
                ),
                current=current,
                journal_path=journal_path,
            )
            if _post_export_executor_continuation_request is not None:
                continuation_locks.close()
            completion = complete_terminal(terminal)
            fence.mark_complete()
            return {
                "ok": True,
                "replayed": True,
                "terminal": terminal,
                "completion": completion,
            }

        def publish_terminal_behind_maintenance() -> dict[str, object]:
            _ensure_successor_maintenance(maintenance, uid=expected_uid)
            if "client_release_handoffs" in binding:
                _verify_retained_successor_client_handoff(
                    current,
                    requested_binding=requested_successor_binding,
                    intent_path=client_handoff_intent_path,
                    journal_backup_path=client_handoff_backup_path,
                    terminal_path=terminal_path,
                    completion_path=completion_path,
                    inherited_journal_sha256=(
                        None
                        if "executor_rescue" in binding
                        else inherited_successor_journal_sha256
                    ),
                    inherited_document_sha256=(
                        None
                        if "executor_rescue" in binding
                        else inherited_successor_document_sha256
                    ),
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_uid=expected_uid,
                    _allow_retired_sidecar_timestamp_drift=(
                        "executor_rescue" in binding
                    ),
                )
            failpoint("after-maintenance-activate")
            if current["phase"] == "predecessor-verified":
                persist("maintenance-active")
                failpoint("after-maintenance-journal")
            if current["phase"] == "maintenance-active":
                persist("predecessor-stop-intent")
            if current["phase"] == "predecessor-stop-intent":
                _stop_successor_predecessor(
                    predecessor,
                    broker_socket=broker_socket,
                    wait_seconds=wait_seconds,
                )
                failpoint("after-predecessor-stop")
                persist("predecessor-stopped")
            if current["phase"] == "predecessor-stopped":
                persist("predecessor-dropin-remove-intent")
                failpoint("after-predecessor-dropin-remove-intent")
            if current["phase"] == "predecessor-dropin-remove-intent":
                _remove_successor_predecessor_dropin(
                    predecessor, dropin=dropin, uid=expected_uid
                )
                failpoint("after-predecessor-dropin-remove")
                persist("predecessor-retired")
            if current["phase"] == "predecessor-retired":
                with _broker_service_lock(database, expected_uid=expected_uid):
                    current_binding = current.get("binding")
                    if isinstance(
                        current_binding, Mapping
                    ) and "executor_rescue" in current_binding:
                        current_rescue = _validated_successor_executor_rescue(
                            current_binding["executor_rescue"],
                            expected_uid=expected_uid,
                        )
                        if "executor_rescue_handoff" in current_binding:
                            _verify_retained_successor_executor_handoff(
                                current,
                                requested_binding=requested_successor_binding,
                                release_pair=release_pair,
                                intent_path=executor_handoff_intent_path,
                                journal_backup_path=executor_handoff_backup_path,
                                terminal_path=terminal_path,
                                completion_path=completion_path,
                                inherited_journal_sha256=(
                                    inherited_successor_journal_sha256
                                ),
                                inherited_document_sha256=(
                                    inherited_successor_document_sha256
                                ),
                                database=database,
                                profile=profile,
                                broker_socket=broker_socket,
                                dropin=dropin,
                                expected_uid=expected_uid,
                            )
                        _verify_retained_successor_executor_rescue(
                            current,
                            requested_binding=requested_successor_binding,
                            release_pair=release_pair,
                            intent_path=executor_rescue_intent_path,
                            journal_backup_path=executor_rescue_backup_path,
                            terminal_path=terminal_path,
                            completion_path=completion_path,
                            inherited_journal_sha256=(
                                current_rescue["journal_raw_sha256"]
                            ),
                            inherited_document_sha256=(
                                current_rescue["journal_document_sha256"]
                            ),
                            database=database,
                            profile=profile,
                            broker_socket=broker_socket,
                            dropin=dropin,
                            expected_uid=expected_uid,
                        )
                    repaired_payload, export_evidence = (
                        _schema12_owner_bound_profile_export(
                            database=database,
                            profile_path=profile,
                            broker_socket=broker_socket,
                            owner_map=owner_map,
                            owner_map_sha256=owner_map_sha256,
                            snapshot_root=snapshot_root,
                            expected_database_generation=expected_database_generation,
                            canary_uid=expected_canary_uid,
                            canary_project=canary_project,
                            repository_id=canary_repository_id,
                            repository_generation=canary_repository_generation,
                            expected_uid=expected_uid,
                        )
                    )
                profile_state = dict(current["profile"])
                profile_state.update(
                    {
                        "owner_binding": export_evidence["owner_map"],
                        "owner_binding_sha256": export_evidence["owner_map"][
                            "document_sha256"
                        ],
                        "repaired_payload_sha256": export_evidence["profile_sha256"],
                        "export_evidence": export_evidence,
                    }
                )
                persist("profile-repair-intent", profile=profile_state)
            if current["phase"] == "profile-repair-intent":
                with _broker_service_lock(database, expected_uid=expected_uid):
                    repaired_payload, export_evidence = (
                        _schema12_owner_bound_profile_export(
                            database=database,
                            profile_path=profile,
                            broker_socket=broker_socket,
                            owner_map=owner_map,
                            owner_map_sha256=owner_map_sha256,
                            snapshot_root=snapshot_root,
                            expected_database_generation=expected_database_generation,
                            canary_uid=expected_canary_uid,
                            canary_project=canary_project,
                            repository_id=canary_repository_id,
                            repository_generation=canary_repository_generation,
                            expected_uid=expected_uid,
                        )
                    )
                if export_evidence != current["profile"].get("export_evidence"):
                    raise BridgeError(
                        "owner-bound profile export changed before publication"
                    )
                before_identity = current["profile"]["before_identity"]
                after_identity = _replace_profile_bytes(
                    profile,
                    repaired_payload,
                    expected_current_sha256=str(before_identity["sha256"]),
                    owner_uid=expected_uid,
                    owner_gid=int(before_identity["gid"]),
                    mode=int(before_identity["mode"]),
                )
                failpoint("after-profile-repair")
                profile_state = dict(current["profile"])
                profile_state["after_identity"] = after_identity
                persist("profile-repaired", profile=profile_state)
            if current["phase"] == "profile-repaired":
                persist("candidate-activation-intent")
            if current["phase"] == "candidate-activation-intent":
                continuation_value = current["binding"].get(
                    "executor_rescue_post_export_continuation"
                )
                if continuation_value is not None:
                    continuation = (
                        _validated_successor_post_export_executor_continuation(
                            continuation_value,
                            expected_uid=expected_uid,
                        )
                    )
                    _verify_retained_successor_post_export_executor_continuation(
                        current,
                        requested_binding=requested_successor_binding,
                        release_pair=release_pair,
                        intent_path=post_export_continuation_intent_path,
                        journal_backup_path=(
                            post_export_continuation_backup_path
                        ),
                        failed_candidate_backup_path=(
                            post_export_failed_candidate_backup_path
                        ),
                        inherited_journal_sha256=str(
                            continuation["journal_raw_sha256"]
                        ),
                        inherited_document_sha256=str(
                            continuation["journal_document_sha256"]
                        ),
                        terminal_path=terminal_path,
                        completion_path=completion_path,
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        expected_uid=expected_uid,
                        require_prelaunch_boundary=True,
                    )
                    failpoint(
                        "before-successor-post-export-continuation-candidate-activate"
                    )
                (
                    effective_candidate_transaction,
                    effective_candidate_operation_id,
                ) = _successor_effective_candidate_target(
                    current["binding"], expected_uid=expected_uid, create=True
                )
                executor_rescue = current["binding"].get(
                    "executor_rescue"
                )
                executor_rescue_binding = (
                    _successor_executor_rescue_runtime_binding(
                        executor_rescue,
                        expected_uid=expected_uid,
                        handoff_value=current["binding"].get(
                            "executor_rescue_handoff"
                        ),
                        continuation_value=current["binding"].get(
                            "executor_rescue_post_export_continuation"
                        ),
                    )
                    if executor_rescue is not None
                    else None
                )
                activation = activate_bridge(
                    release=candidate_release,
                    release_root=release_root,
                    transaction=effective_candidate_transaction,
                    operation_id=effective_candidate_operation_id,
                    failed_installer_transaction=failed_installer_transaction,
                    failed_installer_operation_id=failed_installer_operation_id,
                    readiness_attestation=readiness_attestation,
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    canaries=[
                        f"{item['user']}={canary_project}" for item in canary_accounts
                    ],
                    wait_seconds=wait_seconds,
                    expected_uid=expected_uid,
                    client_release=client_release,
                    _authorized_readiness_origin=predecessor["readiness_origin"],
                    _cutover_maintenance_inventory_read=True,
                    _cutover_canary_repository_id=canary_repository_id,
                    _cutover_canary_repository_generation=(
                        canary_repository_generation
                    ),
                    _cutover_expected_owner_uid=expected_canary_uid,
                    _executor_rescue_client_binding=(
                        executor_rescue_binding
                    ),
                )
                failpoint("after-candidate-activate")
                candidate = _candidate_bridge_reference(
                    transaction=effective_candidate_transaction,
                    operation_id=effective_candidate_operation_id,
                    activation=activation,
                    uid=expected_uid,
                    executor_rescue=executor_rescue_binding,
                    executor_rescue_sha256=(
                        executor_rescue_binding[
                            "executor_rescue_sha256"
                        ]
                        if executor_rescue_binding is not None
                        else None
                    ),
                )
                persist("candidate-active", candidate=candidate)
            if current["phase"] == "candidate-active":
                candidate = current["candidate"]
                readiness = verify_candidate_now(maintenance_active=True)
                failpoint("after-candidate-verify")
                candidate_state = dict(candidate)
                candidate_state["readiness"] = readiness
                persist("candidate-verified", candidate=candidate_state)
            if current["phase"] != "candidate-verified":
                raise BridgeError(
                    "schema-12 successor requires explicit abort recovery"
                )
            _ensure_successor_maintenance(maintenance, uid=expected_uid)
            terminal = _successor_terminal(
                terminal_path,
                _successor_terminal_payload(
                    current=current, journal_path=journal_path, status="committed"
                ),
                uid=expected_uid,
            )
            terminal = _verify_committed_successor_terminal_binding(
                terminal,
                current=current,
                journal_path=journal_path,
            )
            failpoint("after-terminal-publish")
            return terminal

        if _post_export_executor_continuation_request is not None:
            terminal = publish_terminal_behind_maintenance()
            continuation_locks.close()
        else:
            maintenance_contract = _load_maintenance_contract()
            with maintenance_contract.maintenance_writer_lock(
                maintenance_root=Path(str(maintenance["root"])),
                expected_uid=expected_uid,
                expected_gid=int(maintenance["gid"]),
            ):
                terminal = publish_terminal_behind_maintenance()
        # Clearing the marker reacquires the non-reentrant writer lock, so it
        # must happen only after the destructive handoff lock has been released.
        completion = complete_terminal(terminal)
        fence.mark_complete()
        return {
            "ok": True,
            "replayed": False,
            "terminal": terminal,
            "completion": completion,
        }


def replace_ready_bridge_with_clean_successor(
    *,
    candidate_release: Path,
    release_root: Path,
    client_release: Path,
    transaction: Path,
    operation_id: str,
    predecessor_transaction: Path,
    predecessor_operation_id: str,
    predecessor_journal_sha256: str,
    predecessor_document_sha256: str,
    failed_installer_transaction: Path,
    failed_installer_operation_id: str,
    readiness_attestation: Path,
    database: Path,
    profile: Path,
    owner_map: Path,
    owner_map_sha256: str,
    broker_socket: Path,
    dropin: Path,
    expected_database_generation: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    lifecycle_transaction_journal: Path,
    lifecycle_transaction_journal_sha256: str,
    lifecycle_transaction_document_sha256: str,
    lifecycle_attestation: Path,
    lifecycle_attestation_sha256: str,
    lifecycle_attestation_document_sha256: str,
    additional_canaries: Sequence[str] = (),
    inherited_successor_journal_sha256: str | None = None,
    inherited_successor_document_sha256: str | None = None,
    wait_seconds: int = 30,
    expected_uid: int = 0,
    failpoint: Callable[[str], None] = lambda _stage: None,
) -> dict[str, object]:
    """Apply the ordinary successor contract; historical clients are forbidden."""

    return _replace_ready_bridge_with_clean_successor_impl(
        **locals(), _executor_rescue_request=None
    )


def rescue_ready_bridge_with_clean_successor(
    *,
    previous_executor_release: Path,
    previous_executor_release_digest: str,
    retained_client_release: Path,
    retained_client_release_digest: str,
    rescue_executor_release: Path,
    rescue_executor_release_digest: str,
    inherited_successor_journal_sha256: str,
    inherited_successor_document_sha256: str,
    successor_arguments: Mapping[str, object],
) -> dict[str, object]:
    """Enter the one explicit historical-client executor rescue route."""

    arguments = dict(successor_arguments)
    if any(
        field in arguments
        for field in (
            "client_release",
            "inherited_successor_journal_sha256",
            "inherited_successor_document_sha256",
            "_executor_rescue_request",
        )
    ):
        raise BridgeError("executor rescue arguments overlap protected fields")
    running_release = ROOT.resolve(strict=True)
    requested_executor = _absolute(
        rescue_executor_release, "executor rescue running release"
    )
    if (
        requested_executor != running_release
        or rescue_executor_release_digest != running_release.name
    ):
        raise BridgeError(
            "executor rescue release must be the exact running release"
        )
    request = {
        "reason": SUCCESSOR_EXECUTOR_RESCUE_REASON,
        "rescue_path": SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "inherited_journal_raw_sha256": (
            inherited_successor_journal_sha256
        ),
        "inherited_journal_document_sha256": (
            inherited_successor_document_sha256
        ),
        "previous_executor_release": str(previous_executor_release),
        "previous_executor_release_digest": (
            previous_executor_release_digest
        ),
        "retained_client_release": str(retained_client_release),
        "retained_client_release_digest": retained_client_release_digest,
        "rescue_executor_release": str(requested_executor),
        "rescue_executor_release_digest": rescue_executor_release_digest,
    }
    return _replace_ready_bridge_with_clean_successor_impl(
        **arguments,
        client_release=retained_client_release,
        inherited_successor_journal_sha256=(
            inherited_successor_journal_sha256
        ),
        inherited_successor_document_sha256=(
            inherited_successor_document_sha256
        ),
        _executor_rescue_request=request,
    )


def handoff_rescued_executor_with_clean_successor(
    *,
    executor_rescue_sha256: str,
    previous_executor_release: Path,
    previous_executor_release_digest: str,
    retained_client_release: Path,
    retained_client_release_digest: str,
    successor_executor_release: Path,
    successor_executor_release_digest: str,
    inherited_successor_journal_sha256: str,
    inherited_successor_document_sha256: str,
    successor_arguments: Mapping[str, object],
) -> dict[str, object]:
    """Replace only the executor for one already-published rescue."""

    arguments = dict(successor_arguments)
    if any(
        field in arguments
        for field in (
            "client_release",
            "inherited_successor_journal_sha256",
            "inherited_successor_document_sha256",
            "_executor_rescue_request",
            "_executor_rescue_handoff_request",
        )
    ):
        raise BridgeError(
            "rescue executor handoff arguments overlap protected fields"
        )
    running_release = ROOT.resolve(strict=True)
    requested_executor = _absolute(
        successor_executor_release,
        "rescue executor handoff running release",
    )
    if (
        requested_executor != running_release
        or successor_executor_release_digest != running_release.name
    ):
        raise BridgeError(
            "rescue executor handoff release must be the exact running release"
        )
    request = {
        "reason": SUCCESSOR_EXECUTOR_HANDOFF_REASON,
        "handoff_path": SUCCESSOR_EXECUTOR_HANDOFF_PATH,
        "inherited_journal_raw_sha256": (
            inherited_successor_journal_sha256
        ),
        "inherited_journal_document_sha256": (
            inherited_successor_document_sha256
        ),
        "executor_rescue_sha256": executor_rescue_sha256,
        "previous_executor_release": str(previous_executor_release),
        "previous_executor_release_digest": (
            previous_executor_release_digest
        ),
        "retained_client_release": str(retained_client_release),
        "retained_client_release_digest": retained_client_release_digest,
        "successor_executor_release": str(requested_executor),
        "successor_executor_release_digest": (
            successor_executor_release_digest
        ),
    }
    return _replace_ready_bridge_with_clean_successor_impl(
        **arguments,
        client_release=retained_client_release,
        inherited_successor_journal_sha256=(
            inherited_successor_journal_sha256
        ),
        inherited_successor_document_sha256=(
            inherited_successor_document_sha256
        ),
        _executor_rescue_request=None,
        _executor_rescue_handoff_request=request,
    )


def continue_post_export_rescued_executor_with_clean_successor(
    *,
    executor_rescue_sha256: str,
    executor_rescue_handoff_sha256: str,
    previous_executor_release: Path,
    previous_executor_release_digest: str,
    retained_client_release: Path,
    retained_client_release_digest: str,
    successor_executor_release: Path,
    successor_executor_release_digest: str,
    inherited_successor_journal_sha256: str,
    inherited_successor_document_sha256: str,
    successor_arguments: Mapping[str, object],
) -> dict[str, object]:
    """Continue one exact post-export rescue without relabeling its failed attempt."""

    arguments = dict(successor_arguments)
    protected = {
        "client_release",
        "inherited_successor_journal_sha256",
        "inherited_successor_document_sha256",
        "_executor_rescue_request",
        "_executor_rescue_handoff_request",
        "_post_export_executor_continuation_request",
    }
    if any(field in arguments for field in protected):
        raise BridgeError(
            "post-export executor continuation arguments overlap protected fields"
        )
    running_release = ROOT.resolve(strict=True)
    requested_executor = _absolute(
        successor_executor_release,
        "post-export executor continuation running release",
    )
    if (
        requested_executor != running_release
        or successor_executor_release_digest != running_release.name
    ):
        raise BridgeError(
            "post-export executor continuation release must be the exact running release"
        )
    request = {
        "reason": SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON,
        "continuation_path": SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH,
        "inherited_journal_raw_sha256": (
            inherited_successor_journal_sha256
        ),
        "inherited_journal_document_sha256": (
            inherited_successor_document_sha256
        ),
        "executor_rescue_sha256": executor_rescue_sha256,
        "executor_rescue_handoff_sha256": executor_rescue_handoff_sha256,
        "previous_executor_release": str(previous_executor_release),
        "previous_executor_release_digest": previous_executor_release_digest,
        "retained_client_release": str(retained_client_release),
        "retained_client_release_digest": retained_client_release_digest,
        "successor_executor_release": str(requested_executor),
        "successor_executor_release_digest": (
            successor_executor_release_digest
        ),
    }
    return _replace_ready_bridge_with_clean_successor_impl(
        **arguments,
        client_release=retained_client_release,
        inherited_successor_journal_sha256=(
            inherited_successor_journal_sha256
        ),
        inherited_successor_document_sha256=(
            inherited_successor_document_sha256
        ),
        _executor_rescue_request=None,
        _executor_rescue_handoff_request=None,
        _post_export_executor_continuation_request=request,
    )


def abort_clean_bridge_successor(
    *,
    transaction: Path,
    operation_id: str,
    expected_uid: int = 0,
    failpoint: Callable[[str], None] = lambda _stage: None,
) -> dict[str, object]:
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("schema-12 successor abort operation is invalid") from error
    if os.geteuid() != expected_uid:
        raise BridgeError("schema-12 successor abort requires the authority identity")
    transaction = _private_directory(transaction, uid=expected_uid)
    journal_path = transaction / SUCCESSOR_JOURNAL_NAME
    terminal_path = transaction / SUCCESSOR_TERMINAL_NAME
    with _successor_transaction_fence(
        operation_id=operation_id,
        journal=journal_path,
        terminal=terminal_path,
        action="abort",
        expected_uid=expected_uid,
    ) as fence:
        current = _load_successor_journal(journal_path, uid=expected_uid)
        if current is None or current["operation_id"] != operation_id:
            raise BridgeError("schema-12 successor abort lacks its exact journal")
        binding = current["binding"]
        if isinstance(binding.get("maintenance_handoff"), Mapping):
            raise BridgeError(
                "inherited schema-12 successor is forward-only; replay successor-apply"
            )
        maintenance = binding.get("maintenance")
        if not isinstance(maintenance, dict):
            raise BridgeError("schema-12 successor abort lacks maintenance evidence")
        if terminal_path.exists() or terminal_path.is_symlink():
            terminal = _verify_successor_terminal(
                _read_private_json(
                    terminal_path, uid=expected_uid, label="schema-12 successor terminal"
                )
            )
            if terminal["status"] == "committed":
                raise BridgeError("committed schema-12 successor cannot be aborted")
            if not _maintenance_is_clear(maintenance, uid=expected_uid):
                _clear_successor_maintenance(maintenance, uid=expected_uid)
            fence.mark_complete()
            return {"ok": True, "replayed": True, "terminal": terminal}
        _ensure_successor_maintenance(maintenance, uid=expected_uid)

        def persist(phase: str, **updates: object) -> dict[str, object]:
            nonlocal current
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload.update(updates)
            payload["phase"] = phase
            payload["updated_at_epoch"] = int(time.time())
            current = _successor_journal(journal_path, payload, uid=expected_uid)
            return current

        if current["phase"] != "predecessor-restored":
            persist("abort-intent")
            candidate_transaction = Path(str(binding["candidate_transaction"]))
            candidate_journal = candidate_transaction / JOURNAL_NAME
            if candidate_journal.exists() or candidate_journal.is_symlink():
                restore_bridge(
                    transaction=candidate_transaction,
                    operation_id=str(binding["candidate_operation_id"]),
                    expected_uid=expected_uid,
                )
            failpoint("after-abort-candidate-remove")
            profile_state = dict(current["profile"])
            before_identity = profile_state["before_identity"]
            backup_payload = Path(str(profile_state["backup"])).read_bytes()
            profile_path = Path(str(binding["profile"]))
            current_profile = _profile_identity(profile_path, uid=expected_uid)
            if current_profile["sha256"] == profile_state["backup_sha256"]:
                profile_state["restored_identity"] = current_profile
            elif (
                profile_state.get("repaired_payload_sha256") is not None
                and current_profile["sha256"]
                == profile_state["repaired_payload_sha256"]
            ):
                restored_identity = _replace_profile_bytes(
                    profile_path,
                    backup_payload,
                    expected_current_sha256=str(current_profile["sha256"]),
                    owner_uid=expected_uid,
                    owner_gid=int(before_identity["gid"]),
                    mode=int(before_identity["mode"]),
                )
                profile_state["restored_identity"] = restored_identity
            else:
                raise BridgeError(
                    "protected profile is neither the captured predecessor nor the exported candidate"
                )
            failpoint("after-abort-profile-restore")
            predecessor = _verify_successor_predecessor(
                current["predecessor"], expected_uid=expected_uid
            )
            dropin = Path(str(binding["dropin"]))
            broker_socket = Path(str(binding["broker_socket"]))
            wait_seconds = int(binding["wait_seconds"])
            if not (dropin.exists() or dropin.is_symlink()):
                activate_bridge(
                    release=Path(str(predecessor["release"])),
                    release_root=Path(str(predecessor["release"])).parent,
                    transaction=Path(str(binding["restore_transaction"])),
                    operation_id=str(binding["restore_operation_id"]),
                    failed_installer_transaction=Path(
                        str(binding["failed_installer_transaction"])
                    ),
                    failed_installer_operation_id=str(
                        binding["failed_installer_operation_id"]
                    ),
                    readiness_attestation=Path(str(binding["readiness_attestation"])),
                    database=Path(str(binding["database"])),
                    profile=Path(str(binding["profile"])),
                    broker_socket=broker_socket,
                    dropin=dropin,
                    canaries=[
                        f"{binding['canary_user']}={binding['canary_project']}"
                    ],
                    wait_seconds=wait_seconds,
                    expected_uid=expected_uid,
                    _authorized_readiness_origin=predecessor["readiness_origin"],
                )
            else:
                _dropin_identity(
                    dropin,
                    uid=expected_uid,
                    expected_sha256=str(predecessor["dropin_sha256"]),
                )
                state = _systemd_state()
                if not _service_process_alive(state):
                    _run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
                    _run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=30)
            restored_proof = _verify_restored_predecessor_live(
                predecessor=predecessor,
                profile=Path(str(binding["profile"])),
                expected_profile_sha256=str(profile_state["backup_sha256"]),
                owner_binding=profile_state["owner_binding"],
                database=Path(str(binding["database"])),
                broker_socket=broker_socket,
                dropin=dropin,
                canary_user=str(binding["canary_user"]),
                canary_uid=int(binding["expected_canary_uid"]),
                canary_project=Path(str(binding["canary_project"])),
                repository_id=str(binding["canary_repository_id"]),
                repository_generation=int(binding["canary_repository_generation"]),
                expected_database_generation=str(
                    binding["expected_database_generation"]
                ),
                wait_seconds=wait_seconds,
                expected_uid=expected_uid,
            )
            failpoint("after-abort-predecessor-verify")
            persist(
                "predecessor-restored",
                profile=profile_state,
                restored_predecessor={"proof": restored_proof},
            )
        terminal = _successor_terminal(
            terminal_path,
            _successor_terminal_payload(
                current=current, journal_path=journal_path, status="aborted"
            ),
            uid=expected_uid,
        )
        failpoint("after-abort-terminal-publish")
        _clear_successor_maintenance(maintenance, uid=expected_uid)
        failpoint("after-abort-maintenance-clear")
        fence.mark_complete()
        return {"ok": True, "replayed": False, "terminal": terminal}


_POLICY_RECOVERY_JOURNAL_FIELDS = {
    "operation_id",
    "binding",
    "precondition",
    "profile",
    "candidate",
    "phase",
    "error",
    "created_at_epoch",
    "updated_at_epoch",
}
_POLICY_RECOVERY_TERMINAL_FIELDS = {
    "operation_id",
    "status",
    "transaction_journal",
    "transaction_journal_sha256",
    "transaction_document_sha256",
    "policy_result_document_sha256",
    "policy_state_revision",
    "predecessor_journal_sha256",
    "candidate_journal_sha256",
    "candidate_document_sha256",
    "candidate_readiness_sha256",
    "database_sha256",
    "maintenance_deployment_id",
    "maintenance_active",
    "profile_sha256",
    "error_sha256",
    "completed_at_epoch",
}
_LIFECYCLE_QUIESCE_JOURNAL_FIELDS = {
    "operation_id",
    "binding",
    "precondition",
    "phase",
    "stop",
    "created_at_epoch",
    "updated_at_epoch",
}
_LIFECYCLE_QUIESCE_TERMINAL_FIELDS = {
    "operation_id",
    "transaction_journal",
    "transaction_journal_sha256",
    "transaction_document_sha256",
    "lifecycle_result_document_sha256",
    "lifecycle_service_intent_document_sha256",
    "predecessor_journal_sha256",
    "database_sha256",
    "profile_sha256",
    "maintenance_deployment_id",
    "service_stopped",
    "socket_absent",
    "dropin_absent",
    "completed_at_epoch",
}


def _policy_recovery_journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(POLICY_RECOVERY_JOURNAL_KIND, payload)
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_policy_recovery_journal(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return _verify_seal(
        _read_private_json(
            path, uid=uid, label="policy-reconciled bridge recovery journal"
        ),
        kind=POLICY_RECOVERY_JOURNAL_KIND,
        fields=_POLICY_RECOVERY_JOURNAL_FIELDS,
    )


def _policy_recovery_terminal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(POLICY_RECOVERY_TERMINAL_KIND, payload)
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_policy_recovery_terminal(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    document = _verify_seal(
        _read_private_json(
            path, uid=uid, label="policy-reconciled bridge recovery terminal"
        ),
        kind=POLICY_RECOVERY_TERMINAL_KIND,
        fields=_POLICY_RECOVERY_TERMINAL_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
        maintenance_id = str(
            uuid.UUID(str(document["maintenance_deployment_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError(
            "policy-reconciled recovery terminal identity is invalid"
        ) from error
    status = document["status"]
    required_digests = (
        "transaction_journal_sha256",
        "transaction_document_sha256",
        "policy_result_document_sha256",
        "predecessor_journal_sha256",
        "database_sha256",
        "profile_sha256",
    )
    candidate_digests = (
        document["candidate_journal_sha256"],
        document["candidate_document_sha256"],
    )
    if (
        operation_id != document["operation_id"]
        or maintenance_id != document["maintenance_deployment_id"]
        or status not in {"committed", "aborted"}
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in required_digests
        )
        or any(
            value is not None
            and RELEASE_RE.fullmatch(str(value)) is None
            for value in candidate_digests
        )
        or isinstance(document["policy_state_revision"], bool)
        or not isinstance(document["policy_state_revision"], int)
        or document["policy_state_revision"] < 0
        or type(document["maintenance_active"]) is not bool
        or document["maintenance_active"] != (status == "aborted")
        or (
            status == "committed"
            and (
                any(value is None for value in candidate_digests)
                or RELEASE_RE.fullmatch(
                    str(document["candidate_readiness_sha256"])
                )
                is None
                or document["error_sha256"] is not None
            )
        )
        or (
            status == "aborted"
            and (
                document["candidate_readiness_sha256"] is not None
                or RELEASE_RE.fullmatch(str(document["error_sha256"])) is None
            )
        )
        or isinstance(document["completed_at_epoch"], bool)
        or not isinstance(document["completed_at_epoch"], int)
        or document["completed_at_epoch"] <= 0
    ):
        raise BridgeError(
            "policy-reconciled recovery terminal binding is invalid"
        )
    return document


def _cutover_evidence_reference(
    *,
    path: Path,
    raw_sha256: str,
    document_sha256: str,
    uid: int,
    label: str,
    validator: Callable[[object], Mapping[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    if (
        RELEASE_RE.fullmatch(raw_sha256) is None
        or RELEASE_RE.fullmatch(document_sha256) is None
    ):
        raise BridgeError(f"{label} digest is invalid")
    path = _absolute(path, label)
    before = _private_file_identity(path, uid=uid, label=label)
    if before["sha256"] != raw_sha256:
        raise BridgeError(f"{label} raw digest changed")
    try:
        document = dict(
            validator(_read_private_json(path, uid=uid, label=label))
        )
    except Exception as error:
        raise BridgeError(f"{label} is invalid: {error}") from error
    if document.get("document_sha256") != document_sha256:
        raise BridgeError(f"{label} sealed document changed")
    after = _private_file_identity(path, uid=uid, label=label)
    if after != before:
        raise BridgeError(f"{label} changed while verified")
    return document, {
        "path": str(path),
        "raw_sha256": raw_sha256,
        "document_sha256": document_sha256,
        "identity": before,
    }


def _policy_reconciliation_lineage(
    *,
    source_repair_plan: Path,
    source_repair_plan_raw_sha256: str,
    source_repair_plan_document_sha256: str,
    source_repair_result: Path,
    source_repair_result_raw_sha256: str,
    source_repair_result_document_sha256: str,
    policy_plan: Path,
    policy_plan_raw_sha256: str,
    policy_plan_document_sha256: str,
    policy_result: Path,
    policy_result_raw_sha256: str,
    policy_result_document_sha256: str,
    database: Path,
    maintenance_deployment_id: str,
    expected_uid: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    cutover = _load_cutover_module()
    source_plan, source_plan_reference = _cutover_evidence_reference(
        path=source_repair_plan,
        raw_sha256=source_repair_plan_raw_sha256,
        document_sha256=source_repair_plan_document_sha256,
        uid=expected_uid,
        label="source repository repair plan",
        validator=lambda value: cutover._validate_authority_repository_disable_plan(
            value, allow_legacy=True
        ),
    )
    source_result, source_result_reference = _cutover_evidence_reference(
        path=source_repair_result,
        raw_sha256=source_repair_result_raw_sha256,
        document_sha256=source_repair_result_document_sha256,
        uid=expected_uid,
        label="source repository repair result",
        validator=lambda value: cutover._validate_authority_repository_disable_result(
            value, allow_legacy=True
        ),
    )
    plan, plan_reference = _cutover_evidence_reference(
        path=policy_plan,
        raw_sha256=policy_plan_raw_sha256,
        document_sha256=policy_plan_document_sha256,
        uid=expected_uid,
        label="startup-policy reconciliation plan",
        validator=cutover._validate_authority_repository_policy_reconciliation_plan,
    )
    result, result_reference = _cutover_evidence_reference(
        path=policy_result,
        raw_sha256=policy_result_raw_sha256,
        document_sha256=policy_result_document_sha256,
        uid=expected_uid,
        label="startup-policy reconciliation result",
        validator=cutover._validate_authority_repository_policy_reconciliation_result,
    )
    database = _absolute(database, "policy-reconciled authority database")
    if (
        source_result.get("plan_id") != source_plan.get("plan_id")
        or source_result.get("plan_document_sha256")
        != source_plan.get("document_sha256")
        or plan.get("source_repair_plan_sha256")
        != source_plan.get("document_sha256")
        or plan.get("source_repair_result_sha256")
        != source_result.get("document_sha256")
        or plan.get("source_repair_plan_id") != source_plan.get("plan_id")
        or result.get("plan_id") != plan.get("plan_id")
        or result.get("plan_document_sha256") != plan.get("document_sha256")
        or result.get("source_repair_plan_sha256")
        != source_plan.get("document_sha256")
        or result.get("source_repair_result_sha256")
        != source_result.get("document_sha256")
        or result.get("source_repair_plan_id") != source_plan.get("plan_id")
        or result.get("authority_database") != str(database)
        or plan.get("authority_database") != str(database)
        or source_result.get("authority_database") != str(database)
        or result.get("authority_uid") != expected_uid
        or plan.get("authority_uid") != expected_uid
        or source_result.get("authority_uid") != expected_uid
        or result.get("authority_generation") != plan.get("authority_generation")
        or result.get("authority_generation")
        != source_result.get("authority_generation")
        or result.get("state_revision_before")
        != plan.get("authority_state_revision")
        or result.get("state_revision_after")
        != int(result.get("state_revision_before", -2)) + 1
        or result.get("maintenance_deployment_id")
        != maintenance_deployment_id
        or result.get("repository_id")
        != plan.get("repository", {}).get("repository_id")
        or result.get("repository_id") != source_result.get("repository_id")
        or result.get("repository_generation")
        != plan.get("repository", {}).get("generation")
        or result.get("installation_generation")
        != plan.get("repository", {}).get("installation_generation")
        or result.get("startup_policy_update_count", 0) <= 0
        or result.get("startup_policies") is None
    ):
        raise BridgeError("startup-policy recovery evidence lineage changed")
    references = {
        "source_repair_plan": source_plan_reference,
        "source_repair_result": source_result_reference,
        "policy_plan": plan_reference,
        "policy_result": result_reference,
    }
    return plan, result, references


def _policy_reconciled_database_proof(
    *,
    database: Path,
    plan: Mapping[str, object],
    result: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    cutover = _load_cutover_module()
    database = _absolute(database, "policy-reconciled authority database")
    bundle_before = _sqlite_bundle_evidence(database, expected_uid=expected_uid)
    encoded = quote(os.fspath(database), safe="/")
    connection = sqlite3.connect(
        f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=5.0
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        cutover._authority_repair_schema(connection)
        metadata, snapshot, policies = (
            cutover._authority_repository_repair_snapshot(
                connection, str(result["repository_id"])
            )
        )
        policy_results = cutover._authority_startup_policy_results(
            planned=plan["startup_policies"],
            current=policies,
            applied_at=str(result["applied_at"]),
        )
        quick = [str(item[0]) for item in connection.execute("PRAGMA quick_check")]
        violations = cutover.invariant_violations(
            connection,
            include_foreign_keys=True,
            include_owner_authority=False,
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    invariants = {
        "contract": "schema12-pre-owner-authority-complete-v1",
        "schema_version": 12,
        "database_generation": metadata["authority_generation"],
        "state_revision": metadata["state_revision"],
        "quick_check": quick[0] if len(quick) == 1 else None,
        "semantic_violation_count": len(violations),
        "database_identity": {
            key: bundle_before["main"][key]
            for key in ("device", "inode", "size")
        },
    }
    bundle_after = _sqlite_bundle_evidence(database, expected_uid=expected_uid)
    result_identity = result.get("database_identity_after")
    if (
        bundle_after != bundle_before
        or not isinstance(result_identity, Mapping)
        or {
            key: bundle_after["main"][key]
            for key in ("device", "inode", "size")
        }
        != dict(result_identity)
        or metadata.get("authority_generation") != result["authority_generation"]
        or metadata.get("state_revision") != result["state_revision_after"]
        or invariants.get("state_revision") != result["state_revision_after"]
        or quick != ["ok"]
        or violations
        or snapshot.get("repository_id") != result["repository_id"]
        or snapshot.get("generation") != result["repository_generation"]
        or snapshot.get("installation_generation")
        != result["installation_generation"]
        or snapshot.get("state") != "missing"
        or snapshot.get("installation_status") != "disabled"
        or snapshot.get("installation_startup_fenced") is not True
        or snapshot.get("enrollment_count") != 0
        or policy_results != result["startup_policies"]
    ):
        raise BridgeError("post-policy authority state does not match its exact CAS")
    return {
        "database": str(database),
        "database_bundle": bundle_after,
        "database_sha256": bundle_after["main"]["sha256"],
        "database_generation": result["authority_generation"],
        "state_revision": result["state_revision_after"],
        "repository_id": result["repository_id"],
        "repository_generation": result["repository_generation"],
        "installation_generation": result["installation_generation"],
        "startup_policies_sha256": _sha256_bytes(_canonical(policy_results)),
        "invariants": invariants,
    }


def _policy_reconciled_database_stable_binding(
    value: Mapping[str, object],
) -> dict[str, object]:
    bundle = value.get("database_bundle")
    main = bundle.get("main") if isinstance(bundle, Mapping) else None
    if not isinstance(main, Mapping):
        raise BridgeError("policy-reconciled database proof is incomplete")
    return {
        "database": value.get("database"),
        "database_main": dict(main),
        "database_sha256": value.get("database_sha256"),
        "database_generation": value.get("database_generation"),
        "state_revision": value.get("state_revision"),
        "repository_id": value.get("repository_id"),
        "repository_generation": value.get("repository_generation"),
        "installation_generation": value.get("installation_generation"),
        "startup_policies_sha256": value.get("startup_policies_sha256"),
        "invariants": value.get("invariants"),
    }


def _lifecycle_quiesce_journal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(LIFECYCLE_QUIESCE_JOURNAL_KIND, payload)
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_lifecycle_quiesce_journal(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    document = _verify_seal(
        _read_private_json(
            path, uid=uid, label="lifecycle crash-loop quiesce journal"
        ),
        kind=LIFECYCLE_QUIESCE_JOURNAL_KIND,
        fields=_LIFECYCLE_QUIESCE_JOURNAL_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("lifecycle quiesce operation identity is invalid") from error
    if (
        operation_id != document["operation_id"]
        or not isinstance(document["binding"], Mapping)
        or not isinstance(document["precondition"], Mapping)
        or document["phase"] not in {"stop-intent", "stopped"}
        or (
            document["stop"] is not None
            and not isinstance(document["stop"], Mapping)
        )
        or any(
            isinstance(document[field], bool)
            or not isinstance(document[field], int)
            or int(document[field]) <= 0
            for field in ("created_at_epoch", "updated_at_epoch")
        )
    ):
        raise BridgeError("lifecycle crash-loop quiesce journal is invalid")
    return document


def _lifecycle_quiesce_terminal(
    path: Path, payload: Mapping[str, object], *, uid: int
) -> dict[str, object]:
    document = _seal(LIFECYCLE_QUIESCE_TERMINAL_KIND, payload)
    if path.exists() or path.is_symlink():
        retained = _load_lifecycle_quiesce_terminal(path, uid=uid)
        if retained != document:
            raise BridgeError("lifecycle crash-loop quiesce terminal changed")
        return retained
    _atomic_private_json(path, document, uid=uid)
    return document


def _load_lifecycle_quiesce_terminal(
    path: Path, *, uid: int
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    document = _verify_seal(
        _read_private_json(
            path, uid=uid, label="lifecycle crash-loop quiesce terminal"
        ),
        kind=LIFECYCLE_QUIESCE_TERMINAL_KIND,
        fields=_LIFECYCLE_QUIESCE_TERMINAL_FIELDS,
    )
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
        maintenance_id = str(
            uuid.UUID(str(document["maintenance_deployment_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("lifecycle quiesce terminal identity is invalid") from error
    digest_fields = (
        "transaction_journal_sha256",
        "transaction_document_sha256",
        "lifecycle_result_document_sha256",
        "lifecycle_service_intent_document_sha256",
        "predecessor_journal_sha256",
        "database_sha256",
        "profile_sha256",
    )
    if (
        operation_id != document["operation_id"]
        or maintenance_id != document["maintenance_deployment_id"]
        or any(
            RELEASE_RE.fullmatch(str(document[field])) is None
            for field in digest_fields
        )
        or any(
            document[field] is not True
            for field in (
                "service_stopped",
                "socket_absent",
                "dropin_absent",
            )
        )
        or isinstance(document["completed_at_epoch"], bool)
        or not isinstance(document["completed_at_epoch"], int)
        or document["completed_at_epoch"] <= 0
    ):
        raise BridgeError("lifecycle quiesce terminal binding is invalid")
    return document


def _lifecycle_quiesce_lineage(
    *,
    lifecycle_plan: Path,
    lifecycle_plan_raw_sha256: str,
    lifecycle_plan_document_sha256: str,
    lifecycle_result: Path,
    lifecycle_result_raw_sha256: str,
    lifecycle_result_document_sha256: str,
    lifecycle_service_intent: Path,
    lifecycle_service_intent_raw_sha256: str,
    lifecycle_service_intent_document_sha256: str,
    lifecycle_service_result: Path,
    database: Path,
    maintenance_deployment_id: str,
    expected_uid: int,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    cutover = _load_cutover_module()
    plan, plan_reference = _cutover_evidence_reference(
        path=lifecycle_plan,
        raw_sha256=lifecycle_plan_raw_sha256,
        document_sha256=lifecycle_plan_document_sha256,
        uid=expected_uid,
        label="lifecycle recovery plan",
        validator=cutover._validate_authority_repository_lifecycle_recovery_plan,
    )
    result, result_reference = _cutover_evidence_reference(
        path=lifecycle_result,
        raw_sha256=lifecycle_result_raw_sha256,
        document_sha256=lifecycle_result_document_sha256,
        uid=expected_uid,
        label="lifecycle recovery result",
        validator=cutover._validate_authority_repository_lifecycle_recovery_result,
    )
    service_intent, service_reference = _cutover_evidence_reference(
        path=lifecycle_service_intent,
        raw_sha256=lifecycle_service_intent_raw_sha256,
        document_sha256=lifecycle_service_intent_document_sha256,
        uid=expected_uid,
        label="lifecycle recovery service intent",
        validator=cutover._authority_repository_lifecycle_recovery_transaction,
    )
    lifecycle_service_result = _absolute(
        lifecycle_service_result, "lifecycle recovery service result"
    )
    _private_directory(lifecycle_service_result.parent, uid=expected_uid)
    if lifecycle_service_result.exists() or lifecycle_service_result.is_symlink():
        raise BridgeError(
            "lifecycle recovery service transaction already has a terminal result"
        )
    database = _absolute(database, "lifecycle recovery authority database")
    if (
        result.get("plan_id") != plan.get("plan_id")
        or result.get("operation_id") != plan.get("operation_id")
        or service_intent.get("operation_id") != plan.get("operation_id")
        or result.get("plan_document_sha256")
        != plan.get("document_sha256")
        or service_intent.get("plan") != str(_absolute(lifecycle_plan, "plan"))
        or service_intent.get("plan_document_sha256")
        != plan.get("document_sha256")
        or service_intent.get("recovery_attestation")
        != str(_absolute(lifecycle_result, "result"))
        or result.get("authority_database") != str(database)
        or service_intent.get("database") != str(database)
        or result.get("authority_generation")
        != plan.get("authority_generation")
        or result.get("state_revision_before")
        != plan.get("authority_state_revision")
        or result.get("state_revision_after")
        != plan.get("target", {}).get("state_revision")
        or result.get("repository_generation_after")
        != plan.get("target", {}).get("repository_generation")
        or result.get("installation_generation_after")
        != plan.get("target", {}).get("installation_generation")
        or result.get("repository_state") != "active"
        or result.get("installation_status") != "installed"
        or result.get("startup_fenced") is not False
        or result.get("maintenance_deployment_id")
        != maintenance_deployment_id
        or service_intent.get("maintenance", {}).get("deployment_id")
        != maintenance_deployment_id
    ):
        raise BridgeError("lifecycle recovery quiesce lineage changed")
    return plan, result, service_intent, {
        "plan": plan_reference,
        "result": result_reference,
        "service_intent": service_reference,
        "service_result": {
            "path": str(lifecycle_service_result),
            "expected_absent": True,
        },
    }


def _lifecycle_quiesce_predecessor(
    service_intent: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    predecessor = service_intent.get("predecessor")
    readiness = service_intent.get("readiness")
    if not isinstance(predecessor, Mapping) or not isinstance(readiness, Mapping):
        raise BridgeError("lifecycle service intent omitted predecessor binding")
    transaction = _private_directory(
        Path(str(predecessor["transaction"])), uid=expected_uid
    )
    journal_path = transaction / JOURNAL_NAME
    before = _private_file_identity(
        journal_path, uid=expected_uid, label="restored lifecycle predecessor"
    )
    bridge = _load_bridge_journal(journal_path, uid=expected_uid)
    activation = bridge.get("activation") if isinstance(bridge, Mapping) else None
    descendant = (
        activation.get("restore_descendant")
        if isinstance(activation, Mapping)
        else None
    )
    inactive = (
        descendant.get("inactive_state")
        if isinstance(descendant, Mapping)
        else None
    )
    if (
        before["sha256"] != predecessor.get("journal_sha256")
        or bridge is None
        or bridge.get("schema_version")
        != PREDECESSOR_JOURNAL_CONTRACT_VERSION
        or bridge.get("document_sha256")
        != predecessor.get("journal_document_sha256")
        or bridge.get("operation_id") != predecessor.get("operation_id")
        or bridge.get("phase") != "restored"
        or bridge.get("dropin") != predecessor.get("dropin")
        or bridge.get("broker_socket") != readiness.get("broker_socket")
        or not isinstance(descendant, Mapping)
        or descendant.get("kind")
        != "verified-supervised-crash-loop-descendant"
        or descendant.get("release_digest") != bridge.get("release_digest")
        or not isinstance(inactive, Mapping)
        or inactive.get("ActiveState") != "inactive"
        or inactive.get("SubState") != "dead"
        or inactive.get("MainPID") != 0
    ):
        raise BridgeError(
            "lifecycle service intent predecessor is not the exact restored bridge"
        )
    release = _absolute(
        Path(str(bridge["release"])), "restored lifecycle predecessor release"
    )
    manifest = _verify_activation_release(
        release,
        release_root=release.parent,
        owner_uid=expected_uid,
        allow_verified_bytecode_cache=True,
    )
    if (
        manifest.get("release_digest") != bridge.get("release_digest")
        or _private_file_identity(
            journal_path,
            uid=expected_uid,
            label="restored lifecycle predecessor",
        )
        != before
    ):
        raise BridgeError("restored lifecycle predecessor changed while verified")
    return {
        "transaction": str(transaction),
        "journal": str(journal_path),
        "journal_sha256": before["sha256"],
        "journal_document_sha256": bridge["document_sha256"],
        "operation_id": bridge["operation_id"],
        "release": str(release),
        "release_digest": manifest["release_digest"],
        "crash_loop_restore_sha256": _sha256_bytes(_canonical(descendant)),
    }


def _lifecycle_quiesce_database_proof(
    *,
    database: Path,
    plan: Mapping[str, object],
    result: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    cutover = _load_cutover_module()
    database = _absolute(database, "lifecycle recovery authority database")
    before = _sqlite_bundle_evidence(database, expected_uid=expected_uid)
    expected_identity = result.get("database_identity_after")
    if (
        not isinstance(expected_identity, Mapping)
        or {
            key: before["main"][key] for key in ("device", "inode", "size")
        }
        != dict(expected_identity)
    ):
        raise BridgeError("lifecycle recovery database identity changed")
    encoded = quote(os.fspath(database), safe="/")
    connection = sqlite3.connect(
        f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=5.0
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        cutover._authority_repair_schema(connection)
        schema = connection.execute(
            """
            SELECT schema_version, migration_state
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        metadata, snapshot, policies = (
            cutover._authority_repository_repair_snapshot(
                connection, str(result["repository_id"])
            )
        )
        protected = cutover._authority_repository_protected_rows(
            connection, str(result["repository_id"])
        )
        owner = cutover._authority_repository_owner_snapshot(
            connection,
            repository_id=str(result["repository_id"]),
            repository_generation=int(snapshot["generation"]),
            schema_version=12,
        )
        quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        violations = cutover.invariant_violations(
            connection,
            include_foreign_keys=True,
            include_owner_authority=False,
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    after = _sqlite_bundle_evidence(database, expected_uid=expected_uid)
    if (
        after != before
        or schema is None
        or tuple(schema) != (12, "ready")
        or metadata.get("authority_generation")
        != result.get("authority_generation")
        or metadata.get("state_revision") != result.get("state_revision_after")
        or quick != ["ok"]
        or violations
        or protected != plan.get("protected_rows")
        or protected != result.get("protected_rows")
        or not cutover._authority_repository_lifecycle_recovery_terminal(
            plan=plan,
            metadata=metadata,
            snapshot=snapshot,
            protected=protected,
            owner=owner,
        )
    ):
        raise BridgeError(
            "live authority is not the exact lifecycle recovery terminal"
        )
    return {
        "database": str(database),
        "database_bundle": after,
        "database_sha256": after["main"]["sha256"],
        "database_generation": metadata["authority_generation"],
        "state_revision": metadata["state_revision"],
        "repository_id": snapshot["repository_id"],
        "repository_generation": snapshot["generation"],
        "installation_generation": snapshot["installation_generation"],
        "repository_state": snapshot["state"],
        "installation_status": snapshot["installation_status"],
        "startup_fenced": snapshot["installation_startup_fenced"],
        "policy_count": len(policies),
        "policies_sha256": _sha256_bytes(_canonical(policies)),
        "protected_rows_sha256": protected["document_sha256"],
        "owner_authority": owner,
        "quick_check": "ok",
        "semantic_violation_count": 0,
    }


def _root_regular_identity(path: Path, *, label: str) -> dict[str, object]:
    path = _absolute(path, label)
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_nlink != 1
        or path.resolve(strict=True) != path
    ):
        raise BridgeError(f"{label} has unsafe identity")
    digest = _sha256_file(path)
    after = path.lstat()
    fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_nlink",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise BridgeError(f"{label} changed while verified")
    return {
        "path": str(path),
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "ctime_ns": int(before.st_ctime_ns),
        "uid": int(before.st_uid),
        "gid": int(before.st_gid),
        "mode": stat.S_IMODE(before.st_mode),
        "nlink": int(before.st_nlink),
        "sha256": digest,
    }


def _lifecycle_crash_loop_execution(
    *,
    service_intent: Mapping[str, object],
    database: Path,
    broker_socket: Path,
    dropin: Path,
    expected_uid: int,
) -> dict[str, object]:
    release = _absolute(
        Path(str(service_intent["release"])),
        "lifecycle recovery immutable release",
    )
    executor_release = ROOT.resolve(strict=True)
    executor_manifest = _verify_availability_client_release(
        executor_release, owner_uid=expected_uid
    )
    manifest = _verify_historical_availability_release(
        release, owner_uid=expected_uid
    )
    executor_fragment = _root_regular_identity(
        executor_release / "deploy/devcoordinator-broker.service",
        label="executor lifecycle broker unit",
    )
    installed_fragment = _root_regular_identity(
        BROKER_FRAGMENT, label="installed lifecycle broker unit"
    )
    identity = _systemd_execution_identity()
    prefix, separator, remainder = identity["ExecStart"].partition("argv[]=")
    raw_argv, argv_separator, suffix = remainder.partition(" ;")
    try:
        loaded_argv = shlex.split(raw_argv)
    except ValueError as error:
        raise BridgeError("lifecycle crash-loop argv is invalid") from error
    expected_argv = [
        "/usr/bin/python3",
        "-I",
        "/home/DevCoordinator/skills/codex-dev-coordinator/scripts/"
        "dev_coordinator.py",
        "broker",
        "serve",
        "--database",
        str(database),
        "--socket",
        str(broker_socket),
        "--access-group",
        ACCESS_GROUP,
        "--test-plane-socket",
        "/run/devcoordinator-testd/testd.sock",
        "--test-plane-user",
        "devcoordinator-testd",
        "--internal-testd-user",
        "devcoordinator-testd",
    ]
    dropin_paths = [
        _absolute(Path(value), "loaded lifecycle broker drop-in")
        for value in identity["DropInPaths"].split()
        if value
    ]
    if (
        manifest.get("release_digest") != service_intent.get("release_digest")
        or not isinstance(executor_manifest.get("capabilities"), Mapping)
        or executor_manifest["capabilities"].get(
            "schema12_lifecycle_crash_loop_quiescence"
        )
        is not True
        or executor_fragment["sha256"] != installed_fragment["sha256"]
        or identity["FragmentPath"] != str(BROKER_FRAGMENT)
        or not separator
        or not argv_separator
        or prefix != "{ path=/usr/bin/python3 ; "
        or not suffix.endswith(" }")
        or "argv[]=" in suffix
        or "{ path=" in suffix
        or loaded_argv != expected_argv
        or dropin in dropin_paths
        or DEFAULT_RETIREMENT_GUARD in dropin_paths
    ):
        raise BridgeError(
            "loaded broker is not the exact lifecycle schema-13 crash-loop entry"
        )
    loaded_dropins = [
        {
            "path": str(path),
            **_dropin_identity(
                path, uid=expected_uid, expected_sha256=_sha256_file(path)
            ),
        }
        for path in sorted(dropin_paths)
    ]
    return {
        "historical_release": str(release),
        "historical_release_digest": manifest["release_digest"],
        "executor_release": str(executor_release),
        "executor_release_digest": executor_manifest["release_digest"],
        "executor_fragment": executor_fragment,
        "installed_fragment": installed_fragment,
        "systemd": identity,
        "argv": loaded_argv,
        "dropins": loaded_dropins,
    }


def _observe_lifecycle_schema_mismatch_crash_loop(
    *,
    initial_state: Mapping[str, object] | None,
    wait_seconds: int,
) -> dict[str, object]:
    """Bind a restart lineage without trusting one instantaneous Result value."""

    error_text = SCHEMA12_STARTUP_ERROR
    deadline = time.monotonic() + min(max(wait_seconds, 1), 5)
    state = (
        dict(initial_state)
        if isinstance(initial_state, Mapping)
        else _systemd_state()
    )
    samples: list[dict[str, object]] = []
    first_restarts: int | None = None
    previous_restarts: int | None = None
    while True:
        diagnostic = _broker_failure_diagnostic()
        properties = diagnostic.get("properties")
        journal = diagnostic.get("journal")
        tail = journal.get("tail") if isinstance(journal, Mapping) else None
        restart_count = state.get("NRestarts")
        if (
            state.get("LoadState") != "loaded"
            or state.get("UnitFileState") != "enabled"
            or type(restart_count) is not int
            or int(restart_count) <= 0
            or not isinstance(tail, str)
            or error_text not in tail
        ):
            raise BridgeError(
                "broker is not the exact lifecycle schema mismatch crash loop"
            )
        if first_restarts is None:
            first_restarts = int(restart_count)
        if (
            int(restart_count) < first_restarts
            or (
                previous_restarts is not None
                and int(restart_count) < previous_restarts
            )
        ):
            raise BridgeError(
                "lifecycle schema mismatch restart lineage regressed"
            )
        previous_restarts = int(restart_count)
        exact_failure = properties == {
            "Result": "exit-code",
            "ExecMainCode": 1,
            "ExecMainStatus": 1,
        }
        active_transient = (
            properties
            == {
                "Result": "success",
                "ExecMainCode": 0,
                "ExecMainStatus": 0,
            }
            and state.get("ActiveState") in {"active", "activating"}
            and state.get("SubState") in {"running", "start", "auto-restart"}
            and tail.count(error_text) >= 2
        )
        samples.append(
            {
                "systemd": dict(state),
                "properties": (
                    dict(properties)
                    if isinstance(properties, Mapping)
                    else properties
                ),
                "journal_sha256": _sha256_bytes(tail.encode("utf-8")),
                "matching_error_count": tail.count(error_text),
            }
        )
        if exact_failure or (active_transient and len(samples) >= 2):
            return {
                "kind": "verified-lifecycle-schema-mismatch-crash-loop",
                "first_restart_count": first_restarts,
                "last_restart_count": int(restart_count),
                "samples": samples,
                "diagnostic": diagnostic,
            }
        if time.monotonic() >= deadline:
            raise BridgeError(
                "lifecycle schema mismatch crash loop did not reach an exact stop point"
            )
        time.sleep(0.1)
        state = _systemd_state()


def _normalize_lifecycle_quiesce_failed_stop(
    *,
    state: Mapping[str, object],
    minimum_restart_count: int,
    broker_socket: Path,
    journal_phase: str,
) -> dict[str, object]:
    """Clear only failure bookkeeping caused by the sealed stop command."""

    restart_count = state.get("NRestarts")
    invocation_id = state.get("InvocationID")
    if (
        journal_phase != "stop-intent"
        or state.get("LoadState") != "loaded"
        or state.get("ActiveState") != "failed"
        or state.get("SubState") != "failed"
        or state.get("UnitFileState") != "enabled"
        or state.get("MainPID") != 0
        or type(restart_count) is not int
        or int(restart_count) < minimum_restart_count
        or not isinstance(invocation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
        or broker_socket.exists()
        or broker_socket.is_symlink()
    ):
        raise BridgeError(
            "lifecycle quiesce did not prove its exact stopped failure"
        )
    diagnostic = _broker_failure_diagnostic()
    journal = diagnostic.get("journal")
    tail = journal.get("tail") if isinstance(journal, Mapping) else None
    control_marker = (
        "devcoordinator-broker.service: Control process exited, "
        "code=killed, status=15/TERM"
    )
    result_marker = (
        "devcoordinator-broker.service: Failed with result 'signal'."
    )
    stopped_marker = (
        "Stopped devcoordinator-broker.service - DevCoordinator "
        "server-wide authority broker."
    )
    starting_marker = "Starting devcoordinator-broker.service"
    control_index = (
        tail.rfind(control_marker) if isinstance(tail, str) else -1
    )
    result_index = (
        tail.find(result_marker, control_index)
        if isinstance(tail, str) and control_index >= 0
        else -1
    )
    stopped_index = (
        tail.find(stopped_marker, result_index)
        if isinstance(tail, str) and result_index >= 0
        else -1
    )
    if (
        diagnostic.get("unit") != BROKER_UNIT
        or diagnostic.get("properties")
        != {
            "Result": "signal",
            "ExecMainCode": 0,
            "ExecMainStatus": 0,
        }
        or control_index < 0
        or result_index < control_index
        or stopped_index < result_index
        or tail.rfind(SCHEMA12_STARTUP_ERROR, 0, control_index) < 0
        or tail.find(starting_marker, stopped_index + len(stopped_marker))
        >= 0
    ):
        raise BridgeError(
            "lifecycle quiesce failed state is not caused by its stop"
        )
    _run(
        ["/usr/bin/systemctl", "reset-failed", BROKER_UNIT],
        timeout=10,
    )
    return {
        "kind": "reset-sealed-lifecycle-stop-failure",
        "systemd": dict(state),
        "failure": diagnostic,
        "restart_count": int(restart_count),
        "reset_at_epoch": int(time.time()),
    }


def quiesce_lifecycle_recovery_crash_loop(
    *,
    transaction: Path,
    operation_id: str,
    lifecycle_plan: Path,
    lifecycle_plan_raw_sha256: str,
    lifecycle_plan_document_sha256: str,
    lifecycle_result: Path,
    lifecycle_result_raw_sha256: str,
    lifecycle_result_document_sha256: str,
    lifecycle_service_intent: Path,
    lifecycle_service_intent_raw_sha256: str,
    lifecycle_service_intent_document_sha256: str,
    lifecycle_service_result: Path,
    database: Path,
    profile: Path,
    broker_socket: Path,
    dropin: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    wait_seconds: int = 30,
    expected_uid: int = 0,
    failpoint: Callable[[str], None] = lambda _stage: None,
) -> dict[str, object]:
    """Stop only the exact failed lifecycle-service crash loop.

    This transaction does not edit the authority, profile, unit, or drop-in.
    It inherits and retains the exact maintenance marker and is intentionally
    terminal only at a stably inactive, socket-absent broker.
    """

    try:
        operation_id = str(uuid.UUID(operation_id))
        maintenance_deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("lifecycle quiesce identity is invalid") from error
    if (
        operation_id == maintenance_deployment_id
        or os.geteuid() != expected_uid
        or isinstance(maintenance_gid, bool)
        or not isinstance(maintenance_gid, int)
        or maintenance_gid < 0
        or not 1 <= wait_seconds <= 120
    ):
        raise BridgeError("lifecycle quiesce authority binding is invalid")
    transaction = _private_directory(transaction, uid=expected_uid, create=True)
    journal_path = transaction / LIFECYCLE_QUIESCE_JOURNAL_NAME
    terminal_path = transaction / LIFECYCLE_QUIESCE_TERMINAL_NAME
    database = _absolute(database, "lifecycle quiesce authority database")
    profile = _absolute(profile, "lifecycle quiesce protected profile")
    broker_socket = _absolute(broker_socket, "lifecycle quiesce broker socket")
    dropin = _absolute(dropin, "lifecycle quiesce bridge drop-in")
    maintenance_root = _absolute(
        maintenance_root, "lifecycle quiesce maintenance root"
    )
    maintenance_contract = _load_maintenance_contract()

    def load_lineage() -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        return _lifecycle_quiesce_lineage(
            lifecycle_plan=lifecycle_plan,
            lifecycle_plan_raw_sha256=lifecycle_plan_raw_sha256,
            lifecycle_plan_document_sha256=(
                lifecycle_plan_document_sha256
            ),
            lifecycle_result=lifecycle_result,
            lifecycle_result_raw_sha256=lifecycle_result_raw_sha256,
            lifecycle_result_document_sha256=(
                lifecycle_result_document_sha256
            ),
            lifecycle_service_intent=lifecycle_service_intent,
            lifecycle_service_intent_raw_sha256=(
                lifecycle_service_intent_raw_sha256
            ),
            lifecycle_service_intent_document_sha256=(
                lifecycle_service_intent_document_sha256
            ),
            lifecycle_service_result=lifecycle_service_result,
            database=database,
            maintenance_deployment_id=maintenance_deployment_id,
            expected_uid=expected_uid,
        )

    plan, result, service_intent, references = load_lineage()
    service_maintenance = service_intent["maintenance"]
    maintenance = _validated_successor_maintenance(
        {
            **dict(service_maintenance),
            "scope": maintenance_contract.CONTROL_PLANE_MAINTENANCE_SCOPE,
        }
    )
    if (
        maintenance["root"] != str(maintenance_root)
        or maintenance["gid"] != maintenance_gid
        or maintenance["deployment_id"] != maintenance_deployment_id
    ):
        raise BridgeError("lifecycle quiesce maintenance binding changed")
    binding = {
        "evidence": references,
        "database": str(database),
        "profile": str(profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "maintenance": maintenance,
        "lifecycle_operation_id": service_intent["operation_id"],
        "lifecycle_result_document_sha256": result["document_sha256"],
        "lifecycle_service_intent_document_sha256": service_intent[
            "document_sha256"
        ],
        "database_generation": result["authority_generation"],
        "state_revision": result["state_revision_after"],
        "wait_seconds": wait_seconds,
    }

    def revalidate() -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        current_plan, current_result, current_intent, current_references = (
            load_lineage()
        )
        if current_references != binding["evidence"]:
            raise BridgeError("lifecycle quiesce evidence identity changed")
        return current_plan, current_result, current_intent

    def light_database_identity() -> dict[str, int]:
        identity = _sqlite_regular_identity(
            database, uid=expected_uid, label="lifecycle quiesce database"
        )
        value = {
            key: identity[key] for key in ("device", "inode", "size")
        }
        if value != result["database_identity_after"]:
            raise BridgeError("lifecycle quiesce database identity changed")
        return value

    with _successor_transaction_fence(
        operation_id=operation_id,
        journal=journal_path,
        terminal=terminal_path,
        action="prepare",
        expected_uid=expected_uid,
    ) as fence:
        current = _load_lifecycle_quiesce_journal(
            journal_path, uid=expected_uid
        )
        if current is None:
            with maintenance_contract.maintenance_writer_lock(
                maintenance_root=maintenance_root,
                expected_uid=expected_uid,
                expected_gid=maintenance_gid,
            ):
                _ensure_successor_maintenance(
                    maintenance, uid=expected_uid
                )
                current_plan, current_result, current_intent = revalidate()
                predecessor = _lifecycle_quiesce_predecessor(
                    current_intent, expected_uid=expected_uid
                )
                profile_identity = _profile_identity(
                    profile, uid=expected_uid
                )
                if dropin.exists() or dropin.is_symlink():
                    raise BridgeError(
                        "restored schema-12 bridge drop-in reappeared"
                    )
                execution_before = _lifecycle_crash_loop_execution(
                    service_intent=current_intent,
                    database=database,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_uid=expected_uid,
                )
                state = _systemd_state()
                crash_loop = (
                    _observe_lifecycle_schema_mismatch_crash_loop(
                        initial_state=state,
                        wait_seconds=wait_seconds,
                    )
                )
                execution = _lifecycle_crash_loop_execution(
                    service_intent=current_intent,
                    database=database,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_uid=expected_uid,
                )
                if execution != execution_before:
                    raise BridgeError(
                        "lifecycle crash-loop execution changed during observation"
                    )
                state = crash_loop["samples"][-1]["systemd"]
                database_identity = light_database_identity()
                now = int(time.time())
                current = _lifecycle_quiesce_journal(
                    journal_path,
                    {
                        "operation_id": operation_id,
                        "binding": binding,
                        "precondition": {
                            "predecessor": predecessor,
                            "database_identity": database_identity,
                            "profile_identity": profile_identity,
                            "dropin_absent": True,
                            "execution": execution,
                            "systemd": state,
                            "failure": crash_loop,
                            "plan_document_sha256": current_plan[
                                "document_sha256"
                            ],
                            "result_document_sha256": current_result[
                                "document_sha256"
                            ],
                        },
                        "phase": "stop-intent",
                        "stop": None,
                        "created_at_epoch": now,
                        "updated_at_epoch": now,
                    },
                    uid=expected_uid,
                )
            failpoint("after-stop-intent")
        if (
            current.get("operation_id") != operation_id
            or current.get("binding") != binding
        ):
            raise BridgeError(
                "lifecycle quiesce journal belongs to another request"
            )

        def persist(phase: str, *, stop: object) -> dict[str, object]:
            nonlocal current
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload["phase"] = phase
            payload["stop"] = stop
            payload["updated_at_epoch"] = int(time.time())
            current = _lifecycle_quiesce_journal(
                journal_path, payload, uid=expected_uid
            )
            return current

        terminal = _load_lifecycle_quiesce_terminal(
            terminal_path, uid=expected_uid
        )
        if terminal is not None:
            if (
                terminal["operation_id"] != operation_id
                or terminal["transaction_journal"] != str(journal_path)
                or terminal["transaction_journal_sha256"]
                != _sha256_file(journal_path)
                or terminal["transaction_document_sha256"]
                != current["document_sha256"]
                or terminal["lifecycle_result_document_sha256"]
                != binding["lifecycle_result_document_sha256"]
                or terminal["lifecycle_service_intent_document_sha256"]
                != binding["lifecycle_service_intent_document_sha256"]
                or terminal["predecessor_journal_sha256"]
                != current["precondition"]["predecessor"]["journal_sha256"]
                or terminal["profile_sha256"]
                != current["precondition"]["profile_identity"]["sha256"]
                or terminal["maintenance_deployment_id"]
                != maintenance_deployment_id
            ):
                raise BridgeError("lifecycle quiesce terminal changed")
            _ensure_successor_maintenance(maintenance, uid=expected_uid)
            revalidate()
            if (
                _profile_identity(profile, uid=expected_uid)
                != current["precondition"]["profile_identity"]
                or dropin.exists()
                or dropin.is_symlink()
            ):
                raise BridgeError(
                    "lifecycle quiesce protected inputs changed"
                )
            stopped = _stable_inactive(broker_socket)
            current_plan, current_result, _intent = revalidate()
            database_proof = _lifecycle_quiesce_database_proof(
                database=database,
                plan=current_plan,
                result=current_result,
                expected_uid=expected_uid,
            )
            if terminal["database_sha256"] != database_proof["database_sha256"]:
                raise BridgeError("lifecycle quiesce terminal database changed")
            if stopped != current["stop"]["inactive_state"]:
                raise BridgeError("lifecycle quiesce inactive proof changed")
            fence.mark_complete()
            return {"ok": True, "replayed": True, "terminal": terminal}

        with maintenance_contract.maintenance_writer_lock(
            maintenance_root=maintenance_root,
            expected_uid=expected_uid,
            expected_gid=maintenance_gid,
        ):
            _ensure_successor_maintenance(maintenance, uid=expected_uid)
            revalidate()
            if (
                _profile_identity(profile, uid=expected_uid)
                != current["precondition"]["profile_identity"]
                or light_database_identity()
                != current["precondition"]["database_identity"]
                or dropin.exists()
                or dropin.is_symlink()
            ):
                raise BridgeError(
                    "lifecycle quiesce protected inputs changed before stop"
                )
            state = _systemd_state()
            normalization: dict[str, object] | None = None
            if not (
                state.get("ActiveState") == "inactive"
                and state.get("SubState") == "dead"
                and state.get("MainPID") == 0
            ):
                if (
                    state.get("ActiveState") == "failed"
                    and state.get("SubState") == "failed"
                    and state.get("MainPID") == 0
                ):
                    normalization = (
                        _normalize_lifecycle_quiesce_failed_stop(
                            state=state,
                            minimum_restart_count=int(
                                current["precondition"]["failure"][
                                    "last_restart_count"
                                ]
                            ),
                            broker_socket=broker_socket,
                            journal_phase=str(current["phase"]),
                        )
                    )
                else:
                    execution_before = _lifecycle_crash_loop_execution(
                        service_intent=service_intent,
                        database=database,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        expected_uid=expected_uid,
                    )
                    if (
                        execution_before
                        != current["precondition"]["execution"]
                        or type(state.get("NRestarts")) is not int
                        or int(state["NRestarts"])
                        < int(
                            current["precondition"]["failure"][
                                "last_restart_count"
                            ]
                        )
                    ):
                        raise BridgeError(
                            "lifecycle crash-loop execution changed before stop"
                        )
                    crash_loop = (
                        _observe_lifecycle_schema_mismatch_crash_loop(
                            initial_state=state,
                            wait_seconds=wait_seconds,
                        )
                    )
                    execution = _lifecycle_crash_loop_execution(
                        service_intent=service_intent,
                        database=database,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        expected_uid=expected_uid,
                    )
                    if (
                        execution != execution_before
                        or execution
                        != current["precondition"]["execution"]
                        or int(crash_loop["first_restart_count"])
                        < int(
                            current["precondition"]["failure"][
                                "last_restart_count"
                            ]
                        )
                    ):
                        raise BridgeError(
                            "lifecycle crash-loop lineage changed before stop"
                        )
                    _run(
                        ["/usr/bin/systemctl", "stop", BROKER_UNIT],
                        timeout=30,
                    )
                    stopped_state = _systemd_state()
                    if (
                        stopped_state.get("ActiveState") == "failed"
                        and stopped_state.get("SubState") == "failed"
                        and stopped_state.get("MainPID") == 0
                    ):
                        normalization = (
                            _normalize_lifecycle_quiesce_failed_stop(
                                state=stopped_state,
                                minimum_restart_count=int(
                                    crash_loop["last_restart_count"]
                                ),
                                broker_socket=broker_socket,
                                journal_phase=str(current["phase"]),
                            )
                        )
            inactive = _wait_inactive(broker_socket, wait_seconds)
            persist(
                "stopped",
                stop={
                    "observed_before_stop": state,
                    "normalization": normalization,
                    "inactive_state": inactive,
                    "stopped_at_epoch": int(time.time()),
                },
            )
        failpoint("after-stop")

        with maintenance_contract.maintenance_writer_lock(
            maintenance_root=maintenance_root,
            expected_uid=expected_uid,
            expected_gid=maintenance_gid,
        ):
            _ensure_successor_maintenance(maintenance, uid=expected_uid)
            current_plan, current_result, current_intent = revalidate()
            if (
                _lifecycle_quiesce_predecessor(
                    current_intent, expected_uid=expected_uid
                )
                != current["precondition"]["predecessor"]
                or _profile_identity(profile, uid=expected_uid)
                != current["precondition"]["profile_identity"]
                or dropin.exists()
                or dropin.is_symlink()
            ):
                raise BridgeError(
                    "lifecycle quiesce evidence changed after stop"
                )
            with _broker_service_lock(database, expected_uid=expected_uid):
                inactive = _stable_inactive(broker_socket)
                database_proof = _lifecycle_quiesce_database_proof(
                    database=database,
                    plan=current_plan,
                    result=current_result,
                    expected_uid=expected_uid,
                )
            if inactive != current["stop"]["inactive_state"]:
                raise BridgeError(
                    "lifecycle broker inactive proof changed before terminal"
                )
            terminal = _lifecycle_quiesce_terminal(
                terminal_path,
                {
                    "operation_id": operation_id,
                    "transaction_journal": str(journal_path),
                    "transaction_journal_sha256": _sha256_file(journal_path),
                    "transaction_document_sha256": current[
                        "document_sha256"
                    ],
                    "lifecycle_result_document_sha256": binding[
                        "lifecycle_result_document_sha256"
                    ],
                    "lifecycle_service_intent_document_sha256": binding[
                        "lifecycle_service_intent_document_sha256"
                    ],
                    "predecessor_journal_sha256": current["precondition"][
                        "predecessor"
                    ]["journal_sha256"],
                    "database_sha256": database_proof["database_sha256"],
                    "profile_sha256": current["precondition"][
                        "profile_identity"
                    ]["sha256"],
                    "maintenance_deployment_id": (
                        maintenance_deployment_id
                    ),
                    "service_stopped": True,
                    "socket_absent": True,
                    "dropin_absent": True,
                    "completed_at_epoch": int(time.time()),
                },
                uid=expected_uid,
            )
        failpoint("after-terminal")
        fence.mark_complete()
        return {"ok": True, "replayed": False, "terminal": terminal}


def recover_policy_reconciled_restored_bridge(
    *,
    candidate_release: Path,
    release_root: Path,
    client_release: Path,
    transaction: Path,
    operation_id: str,
    predecessor_transaction: Path,
    predecessor_operation_id: str,
    predecessor_journal_raw_sha256: str,
    predecessor_journal_document_sha256: str,
    failed_installer_transaction: Path,
    failed_installer_operation_id: str,
    readiness_attestation: Path,
    readiness_raw_sha256: str,
    readiness_document_sha256: str,
    source_repair_plan: Path,
    source_repair_plan_raw_sha256: str,
    source_repair_plan_document_sha256: str,
    source_repair_result: Path,
    source_repair_result_raw_sha256: str,
    source_repair_result_document_sha256: str,
    policy_plan: Path,
    policy_plan_raw_sha256: str,
    policy_plan_document_sha256: str,
    policy_result: Path,
    policy_result_raw_sha256: str,
    policy_result_document_sha256: str,
    database: Path,
    profile: Path,
    owner_map: Path,
    owner_map_sha256: str,
    broker_socket: Path,
    dropin: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    canary_user: str,
    expected_canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    additional_canaries: Sequence[str],
    wait_seconds: int = 30,
    expected_uid: int = 0,
    failpoint: Callable[[str], None] = lambda _stage: None,
) -> dict[str, object]:
    """Recover only the exact post-policy restored/crash-loop incident.

    The transaction is forward-completing until authenticated readiness or a
    sealed, maintenance-fenced rollback.  It never makes the generic bridge
    activator accept a restored journal or a revised database.
    """

    try:
        operation_id = str(uuid.UUID(operation_id))
        predecessor_operation_id = str(uuid.UUID(predecessor_operation_id))
        failed_installer_operation_id = str(uuid.UUID(failed_installer_operation_id))
        maintenance_deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise BridgeError("policy-reconciled recovery identity is invalid") from error
    if (
        len(
            {
                operation_id,
                predecessor_operation_id,
                failed_installer_operation_id,
                maintenance_deployment_id,
            }
        )
        != 4
        or os.geteuid() != expected_uid
        or isinstance(maintenance_gid, bool)
        or not isinstance(maintenance_gid, int)
        or maintenance_gid < 0
        or not 1 <= wait_seconds <= 120
    ):
        raise BridgeError("policy-reconciled recovery authority binding is invalid")
    transaction = _private_directory(transaction, uid=expected_uid, create=True)
    journal_path = transaction / POLICY_RECOVERY_JOURNAL_NAME
    terminal_path = transaction / POLICY_RECOVERY_TERMINAL_NAME
    backup_path = transaction / POLICY_RECOVERY_PROFILE_BACKUP_NAME
    candidate_transaction = _private_directory(
        transaction / POLICY_RECOVERY_CANDIDATE_DIRECTORY,
        uid=expected_uid,
        create=True,
    )
    snapshot_root = _private_directory(
        transaction / POLICY_RECOVERY_SNAPSHOT_DIRECTORY,
        uid=expected_uid,
        create=True,
    )
    candidate_operation_id = str(
        uuid.uuid5(
            uuid.UUID(operation_id),
            "schema12-policy-reconciled-clean-candidate",
        )
    )
    candidate_release = _absolute(
        candidate_release, "policy-reconciled clean release"
    )
    release_root = _absolute(
        release_root, "policy-reconciled clean release root"
    )
    client_release = _absolute(
        client_release, "policy-reconciled strict client release"
    )
    predecessor_transaction = _private_directory(
        predecessor_transaction, uid=expected_uid
    )
    failed_installer_transaction = _private_directory(
        failed_installer_transaction, uid=expected_uid
    )
    readiness_attestation = _absolute(
        readiness_attestation, "policy-reconciled readiness attestation"
    )
    database = _absolute(database, "policy-reconciled authority database")
    profile = _absolute(profile, "policy-reconciled protected profile")
    owner_map = _absolute(owner_map, "policy-reconciled owner map")
    broker_socket = _absolute(broker_socket, "policy-reconciled broker socket")
    dropin = _absolute(dropin, "policy-reconciled bridge drop-in")
    maintenance_root = _absolute(
        maintenance_root, "policy-reconciled maintenance root"
    )
    canary_project = _absolute(
        canary_project, "policy-reconciled canary project"
    )
    if canary_project.name != "GlobalFinance":
        raise BridgeError(
            "policy-reconciled recovery requires the exact GlobalFinance root"
        )
    try:
        account = pwd.getpwnam(canary_user)
    except KeyError as error:
        raise BridgeError(f"unknown canary account: {canary_user}") from error
    if account.pw_uid != expected_canary_uid:
        raise BridgeError("policy-reconciled canary owner UID changed")
    canary_accounts = _successor_canary_accounts(
        owner_user=canary_user,
        owner_uid=expected_canary_uid,
        additional_canaries=additional_canaries,
    )
    candidate_manifest = _verify_activation_release(
        candidate_release,
        release_root=release_root,
        owner_uid=expected_uid,
    )
    client_manifest = _verify_availability_client_release(
        client_release, owner_uid=expected_uid
    )
    owner_map_reference = _sealed_owner_map_reference(
        owner_map,
        owner_map_sha256=owner_map_sha256,
        expected_uid=expected_uid,
    )
    maintenance_contract = _load_maintenance_contract()
    early_current = _load_policy_recovery_journal(
        journal_path, uid=expected_uid
    )
    stored_maintenance = (
        early_current.get("binding", {}).get("maintenance")
        if isinstance(early_current, Mapping)
        and isinstance(early_current.get("binding"), Mapping)
        else None
    )
    try:
        maintenance_state = maintenance_contract.load_maintenance_state(
            expected_uid=expected_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
    except Exception as error:
        raise BridgeError(
            f"policy-reconciled maintenance cannot be read: {error}"
        ) from error
    if maintenance_state is None:
        if not isinstance(stored_maintenance, Mapping):
            raise BridgeError(
                "policy-reconciled recovery requires the exact active maintenance"
            )
        maintenance = _validated_successor_maintenance(stored_maintenance)
        if (
            maintenance["deployment_id"] != maintenance_deployment_id
            or maintenance["root"] != str(maintenance_root)
            or maintenance["gid"] != maintenance_gid
        ):
            raise BridgeError(
                "policy-reconciled recovery maintenance identity changed"
            )
    else:
        if (
            maintenance_state.deployment_id != maintenance_deployment_id
            or maintenance_state.message
            != maintenance_contract.PUBLIC_MAINTENANCE_MESSAGE
        ):
            raise BridgeError(
                "policy-reconciled recovery requires the exact active maintenance"
            )
        maintenance = _validated_successor_maintenance(
            {
                "root": str(maintenance_root),
                "gid": maintenance_gid,
                "deployment_id": maintenance_deployment_id,
                "scope": maintenance_contract.CONTROL_PLANE_MAINTENANCE_SCOPE,
                "message": maintenance_state.message,
                "retry_after_seconds": maintenance_state.retry_after_seconds,
                "started_at": maintenance_state.started_at,
            }
        )
        if stored_maintenance is not None and dict(maintenance) != dict(
            stored_maintenance
        ):
            raise BridgeError(
                "policy-reconciled recovery maintenance binding changed"
            )
    policy_plan_document, policy_result_document, evidence_references = (
        _policy_reconciliation_lineage(
            source_repair_plan=source_repair_plan,
            source_repair_plan_raw_sha256=source_repair_plan_raw_sha256,
            source_repair_plan_document_sha256=(
                source_repair_plan_document_sha256
            ),
            source_repair_result=source_repair_result,
            source_repair_result_raw_sha256=source_repair_result_raw_sha256,
            source_repair_result_document_sha256=(
                source_repair_result_document_sha256
            ),
            policy_plan=policy_plan,
            policy_plan_raw_sha256=policy_plan_raw_sha256,
            policy_plan_document_sha256=policy_plan_document_sha256,
            policy_result=policy_result,
            policy_result_raw_sha256=policy_result_raw_sha256,
            policy_result_document_sha256=policy_result_document_sha256,
            database=database,
            maintenance_deployment_id=maintenance_deployment_id,
            expected_uid=expected_uid,
        )
    )
    expected_generation = str(policy_result_document["authority_generation"])
    expected_state_revision = int(policy_result_document["state_revision_after"])
    binding = {
        "candidate_release": str(candidate_release),
        "candidate_release_root": str(release_root),
        "candidate_release_digest": candidate_manifest["release_digest"],
        "client_release": str(client_release),
        "client_release_digest": client_manifest["release_digest"],
        "candidate_transaction": str(candidate_transaction),
        "candidate_operation_id": candidate_operation_id,
        "predecessor_transaction": str(predecessor_transaction),
        "predecessor_operation_id": predecessor_operation_id,
        "predecessor_journal_raw_sha256": predecessor_journal_raw_sha256,
        "predecessor_journal_document_sha256": (
            predecessor_journal_document_sha256
        ),
        "failed_installer_transaction": str(failed_installer_transaction),
        "failed_installer_operation_id": failed_installer_operation_id,
        "readiness_attestation": str(readiness_attestation),
        "readiness_raw_sha256": readiness_raw_sha256,
        "readiness_document_sha256": readiness_document_sha256,
        "evidence": evidence_references,
        "database": str(database),
        "profile": str(profile),
        "owner_map": owner_map_reference,
        "snapshot_root": str(snapshot_root),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "maintenance": maintenance,
        "expected_database_generation": expected_generation,
        "expected_state_revision": expected_state_revision,
        "canary_user": canary_user,
        "expected_canary_uid": expected_canary_uid,
        "canary_project": str(canary_project),
        "canary_repository_id": canary_repository_id,
        "canary_repository_generation": canary_repository_generation,
        "canary_accounts": canary_accounts,
        "wait_seconds": wait_seconds,
    }

    def revalidate_lineage() -> tuple[dict[str, object], dict[str, object]]:
        plan, result, references = _policy_reconciliation_lineage(
            source_repair_plan=Path(
                str(binding["evidence"]["source_repair_plan"]["path"])
            ),
            source_repair_plan_raw_sha256=str(
                binding["evidence"]["source_repair_plan"]["raw_sha256"]
            ),
            source_repair_plan_document_sha256=str(
                binding["evidence"]["source_repair_plan"]["document_sha256"]
            ),
            source_repair_result=Path(
                str(binding["evidence"]["source_repair_result"]["path"])
            ),
            source_repair_result_raw_sha256=str(
                binding["evidence"]["source_repair_result"]["raw_sha256"]
            ),
            source_repair_result_document_sha256=str(
                binding["evidence"]["source_repair_result"]["document_sha256"]
            ),
            policy_plan=Path(str(binding["evidence"]["policy_plan"]["path"])),
            policy_plan_raw_sha256=str(
                binding["evidence"]["policy_plan"]["raw_sha256"]
            ),
            policy_plan_document_sha256=str(
                binding["evidence"]["policy_plan"]["document_sha256"]
            ),
            policy_result=Path(str(binding["evidence"]["policy_result"]["path"])),
            policy_result_raw_sha256=str(
                binding["evidence"]["policy_result"]["raw_sha256"]
            ),
            policy_result_document_sha256=str(
                binding["evidence"]["policy_result"]["document_sha256"]
            ),
            database=database,
            maintenance_deployment_id=maintenance_deployment_id,
            expected_uid=expected_uid,
        )
        if references != binding["evidence"]:
            raise BridgeError("policy-reconciled evidence identity changed")
        return plan, result

    def verify_historical_evidence_bytes() -> None:
        predecessor_journal = predecessor_transaction / JOURNAL_NAME
        if (
            _private_file_identity(
                predecessor_journal,
                uid=expected_uid,
                label="historical restored predecessor journal",
            )["sha256"]
            != predecessor_journal_raw_sha256
            or _private_file_identity(
                readiness_attestation,
                uid=expected_uid,
                label="historical authority readiness attestation",
            )["sha256"]
            != readiness_raw_sha256
        ):
            raise BridgeError(
                "policy-reconciled historical evidence bytes changed"
            )

    def stopped_precondition() -> tuple[
        dict[str, object], dict[str, object], dict[str, object]
    ]:
        _ensure_successor_maintenance(maintenance, uid=expected_uid)
        plan, result = revalidate_lineage()
        database_proof = _policy_reconciled_database_proof(
            database=database,
            plan=plan,
            result=result,
            expected_uid=expected_uid,
        )
        predecessor = verify_policy_reconciled_restored_predecessor(
            transaction=predecessor_transaction,
            operation_id=predecessor_operation_id,
            journal_raw_sha256=predecessor_journal_raw_sha256,
            journal_document_sha256=predecessor_journal_document_sha256,
            readiness_attestation=readiness_attestation,
            readiness_raw_sha256=readiness_raw_sha256,
            readiness_document_sha256=readiness_document_sha256,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_database_generation=expected_generation,
            expected_state_revision=expected_state_revision,
            expected_uid=expected_uid,
        )
        if (
            candidate_release == Path(str(predecessor["release"]))
            or release_root == Path(str(predecessor["release"])).parent
            or candidate_manifest["release_digest"]
            != predecessor["release_digest"]
        ):
            raise BridgeError(
                "policy-reconciled candidate must be an equal-byte distinct clean root"
            )
        lock_path = database.parent / ".broker-service.lock"
        maintenance_lock_path = (
            maintenance_root / maintenance_contract.MAINTENANCE_LOCK_FILENAME
        )
        return predecessor, database_proof, {
            "stopped_writer": {
                "acquired": True,
                "identity": _lock_file_identity(
                    lock_path,
                    uid=expected_uid,
                    gid=0,
                    mode=0o600,
                    label="policy-reconciled stopped-writer lock",
                ),
            },
            "maintenance_writer": {
                "acquired": True,
                "identity": _lock_file_identity(
                    maintenance_lock_path,
                    uid=expected_uid,
                    gid=maintenance_gid,
                    mode=0o640,
                    label="policy-reconciled maintenance-writer lock",
                ),
            },
        }

    def candidate_reference(activation: Mapping[str, object]) -> dict[str, object]:
        candidate_journal = candidate_transaction / JOURNAL_NAME
        bridge = _load_bridge_journal(candidate_journal, uid=expected_uid)
        if (
            bridge is None
            or bridge != activation
            or bridge.get("operation_id") != candidate_operation_id
            or bridge.get("phase") != "systemd-ready"
        ):
            raise BridgeError(
                "policy-reconciled candidate activation is not durable"
            )
        return {
            "journal": str(candidate_journal),
            "journal_sha256": _sha256_file(candidate_journal),
            "document_sha256": bridge["document_sha256"],
            "activation": dict(bridge),
            "preclear": None,
            "readiness": None,
        }

    with _successor_transaction_fence(
        operation_id=operation_id,
        journal=journal_path,
        terminal=terminal_path,
        action="prepare",
        expected_uid=expected_uid,
    ) as fence:
        current = _load_policy_recovery_journal(journal_path, uid=expected_uid)
        if current is None:
            with maintenance_contract.maintenance_writer_lock(
                maintenance_root=maintenance_root,
                expected_uid=expected_uid,
                expected_gid=maintenance_gid,
            ):
                with _broker_service_lock(database, expected_uid=expected_uid):
                    predecessor, database_proof, locks = stopped_precondition()
                    profile_state = _capture_successor_profile(
                        profile, backup=backup_path, uid=expected_uid
                    )
            profile_state["owner_binding"] = owner_map_reference
            profile_state["owner_binding_sha256"] = owner_map_reference[
                "document_sha256"
            ]
            now = int(time.time())
            current = _policy_recovery_journal(
                journal_path,
                {
                    "operation_id": operation_id,
                    "binding": binding,
                    "precondition": {
                        "predecessor": predecessor,
                        "database": database_proof,
                        "locks": locks,
                    },
                    "profile": profile_state,
                    "candidate": {
                        "journal": None,
                        "journal_sha256": None,
                        "document_sha256": None,
                        "activation": None,
                        "preclear": None,
                        "readiness": None,
                    },
                    "phase": "sealed-precondition",
                    "error": None,
                    "created_at_epoch": now,
                    "updated_at_epoch": now,
                },
                uid=expected_uid,
            )
            failpoint("after-sealed-precondition")
        if (
            current.get("operation_id") != operation_id
            or current.get("binding") != binding
        ):
            raise BridgeError(
                "policy-reconciled recovery journal belongs to another request"
            )

        def persist(phase: str, **updates: object) -> dict[str, object]:
            nonlocal current
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload.update(updates)
            payload["phase"] = phase
            payload["updated_at_epoch"] = int(time.time())
            current = _policy_recovery_journal(
                journal_path, payload, uid=expected_uid
            )
            return current

        terminal = _load_policy_recovery_terminal(
            terminal_path, uid=expected_uid
        )
        if terminal is not None:
            if (
                terminal["operation_id"] != operation_id
                or terminal["transaction_document_sha256"]
                != current["document_sha256"]
                or terminal["transaction_journal_sha256"]
                != _sha256_file(journal_path)
            ):
                raise BridgeError(
                    "policy-reconciled recovery terminal binding changed"
                )
            plan, result = revalidate_lineage()
            verify_historical_evidence_bytes()
            current_database = _policy_reconciled_database_proof(
                database=database,
                plan=plan,
                result=result,
                expected_uid=expected_uid,
            )
            if _policy_reconciled_database_stable_binding(
                current_database
            ) != _policy_reconciled_database_stable_binding(
                current["precondition"]["database"]
            ):
                raise BridgeError(
                    "policy-reconciled recovery terminal database changed"
                )
            if terminal["status"] == "committed":
                if not _maintenance_is_clear(maintenance, uid=expected_uid):
                    raise BridgeError(
                        "committed policy-reconciled recovery retained maintenance"
                    )
                candidate = current["candidate"]
                readiness = _verify_clean_successor_live(
                    transaction=candidate_transaction,
                    operation_id=candidate_operation_id,
                    expected_journal_sha256=str(candidate["journal_sha256"]),
                    expected_journal_document_sha256=str(
                        candidate["document_sha256"]
                    ),
                    broker_release=candidate_release,
                    client_release=client_release,
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_database_generation=expected_generation,
                    canary_user=canary_user,
                    expected_canary_uid=expected_canary_uid,
                    canary_accounts=canary_accounts,
                    canary_project=canary_project,
                    canary_repository_id=canary_repository_id,
                    canary_repository_generation=canary_repository_generation,
                    wait_seconds=wait_seconds,
                    expected_uid=expected_uid,
                )
                if _proof_stable_binding(
                    readiness
                ) != _proof_stable_binding(candidate["readiness"]):
                    raise BridgeError(
                        "policy-reconciled committed readiness changed"
                    )
            else:
                _ensure_successor_maintenance(maintenance, uid=expected_uid)
                _stable_inactive(broker_socket)
                if _profile_identity(profile, uid=expected_uid)["sha256"] != (
                    current["profile"]["backup_sha256"]
                ):
                    raise BridgeError(
                        "aborted policy-reconciled profile was not restored"
                    )
                predecessor = verify_policy_reconciled_restored_predecessor(
                    transaction=predecessor_transaction,
                    operation_id=predecessor_operation_id,
                    journal_raw_sha256=predecessor_journal_raw_sha256,
                    journal_document_sha256=(
                        predecessor_journal_document_sha256
                    ),
                    readiness_attestation=readiness_attestation,
                    readiness_raw_sha256=readiness_raw_sha256,
                    readiness_document_sha256=readiness_document_sha256,
                    database=database,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_database_generation=expected_generation,
                    expected_state_revision=expected_state_revision,
                    expected_uid=expected_uid,
                )
                if predecessor != current["precondition"]["predecessor"]:
                    raise BridgeError(
                        "aborted restored predecessor evidence changed"
                    )
                candidate_journal = candidate_transaction / JOURNAL_NAME
                if terminal["candidate_journal_sha256"] is None:
                    if (
                        candidate_journal.exists()
                        or candidate_journal.is_symlink()
                        or terminal["candidate_document_sha256"] is not None
                    ):
                        raise BridgeError(
                            "aborted clean candidate appeared after terminal"
                        )
                else:
                    candidate = _load_bridge_journal(
                        candidate_journal, uid=expected_uid
                    )
                    if (
                        candidate is None
                        or candidate.get("phase") != "restored"
                        or _sha256_file(candidate_journal)
                        != terminal["candidate_journal_sha256"]
                        or candidate.get("document_sha256")
                        != terminal["candidate_document_sha256"]
                    ):
                        raise BridgeError(
                            "aborted clean candidate was not exactly restored"
                        )
            fence.mark_complete()
            return {
                "ok": terminal["status"] == "committed",
                "replayed": True,
                "terminal": terminal,
            }

        try:
            if current["phase"] == "sealed-precondition":
                with maintenance_contract.maintenance_writer_lock(
                    maintenance_root=maintenance_root,
                    expected_uid=expected_uid,
                    expected_gid=maintenance_gid,
                ):
                    with _broker_service_lock(
                        database, expected_uid=expected_uid
                    ):
                        predecessor, database_proof, _locks = (
                            stopped_precondition()
                        )
                        if (
                            predecessor
                            != current["precondition"]["predecessor"]
                            or _policy_reconciled_database_stable_binding(
                                database_proof
                            )
                            != _policy_reconciled_database_stable_binding(
                                current["precondition"]["database"]
                            )
                        ):
                            raise BridgeError(
                                "policy-reconciled stopped precondition changed"
                            )
                        repaired_payload, export_evidence = (
                            _schema12_owner_bound_profile_export(
                                database=database,
                                profile_path=profile,
                                broker_socket=broker_socket,
                                owner_map=owner_map,
                                owner_map_sha256=owner_map_sha256,
                                snapshot_root=snapshot_root,
                                expected_database_generation=expected_generation,
                                canary_uid=expected_canary_uid,
                                canary_project=canary_project,
                                repository_id=canary_repository_id,
                                repository_generation=(
                                    canary_repository_generation
                                ),
                                expected_uid=expected_uid,
                            )
                        )
                profile_state = dict(current["profile"])
                profile_state.update(
                    {
                        "repaired_payload_sha256": export_evidence[
                            "profile_sha256"
                        ],
                        "export_evidence": export_evidence,
                    }
                )
                persist("profile-repair-intent", profile=profile_state)
                failpoint("after-profile-repair-intent")
            if current["phase"] == "profile-repair-intent":
                with maintenance_contract.maintenance_writer_lock(
                    maintenance_root=maintenance_root,
                    expected_uid=expected_uid,
                    expected_gid=maintenance_gid,
                ):
                    _ensure_successor_maintenance(
                        maintenance, uid=expected_uid
                    )
                    with _broker_service_lock(
                        database, expected_uid=expected_uid
                    ):
                        repaired_payload, export_evidence = (
                            _schema12_owner_bound_profile_export(
                                database=database,
                                profile_path=profile,
                                broker_socket=broker_socket,
                                owner_map=owner_map,
                                owner_map_sha256=owner_map_sha256,
                                snapshot_root=snapshot_root,
                                expected_database_generation=expected_generation,
                                canary_uid=expected_canary_uid,
                                canary_project=canary_project,
                                repository_id=canary_repository_id,
                                repository_generation=(
                                    canary_repository_generation
                                ),
                                expected_uid=expected_uid,
                            )
                        )
                        if export_evidence != current["profile"].get(
                            "export_evidence"
                        ):
                            raise BridgeError(
                                "policy-reconciled profile export changed"
                            )
                        before = current["profile"]["before_identity"]
                        after = _replace_profile_bytes(
                            profile,
                            repaired_payload,
                            expected_current_sha256=str(before["sha256"]),
                            owner_uid=expected_uid,
                            owner_gid=int(before["gid"]),
                            mode=int(before["mode"]),
                        )
                profile_state = dict(current["profile"])
                profile_state["after_identity"] = after
                persist("profile-repaired", profile=profile_state)
                failpoint("after-profile-repaired")
            if current["phase"] == "profile-repaired":
                persist("candidate-activation-intent")
            if current["phase"] == "candidate-activation-intent":
                with maintenance_contract.maintenance_writer_lock(
                    maintenance_root=maintenance_root,
                    expected_uid=expected_uid,
                    expected_gid=maintenance_gid,
                ):
                    _ensure_successor_maintenance(
                        maintenance, uid=expected_uid
                    )
                    activation = activate_bridge(
                        release=candidate_release,
                        release_root=release_root,
                        transaction=candidate_transaction,
                        operation_id=candidate_operation_id,
                        failed_installer_transaction=(
                            failed_installer_transaction
                        ),
                        failed_installer_operation_id=(
                            failed_installer_operation_id
                        ),
                        readiness_attestation=readiness_attestation,
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        canaries=[
                            f"{item['user']}={canary_project}"
                            for item in canary_accounts
                        ],
                        wait_seconds=wait_seconds,
                        expected_uid=expected_uid,
                        client_release=client_release,
                        _authorized_readiness_origin=current["precondition"][
                            "predecessor"
                        ]["readiness_origin"],
                        _defer_canaries_behind_maintenance=True,
                        _expected_readiness_state_revision=(
                            expected_state_revision
                        ),
                    )
                    candidate = candidate_reference(activation)
                    preclear = verify_deferred_bridge_preclear(
                        release=candidate_release,
                        release_root=release_root,
                        transaction=candidate_transaction,
                        operation_id=candidate_operation_id,
                        readiness_attestation=readiness_attestation,
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        expected_database_generation=expected_generation,
                        expected_state_revision=expected_state_revision,
                        canary_accounts=canary_accounts,
                        canary_project=canary_project,
                        canary_repository_id=canary_repository_id,
                        canary_repository_generation=(
                            canary_repository_generation
                        ),
                        expected_owner_uid=expected_canary_uid,
                        wait_seconds=wait_seconds,
                        expected_uid=expected_uid,
                    )
                    plan, result = revalidate_lineage()
                    database_proof = _policy_reconciled_database_proof(
                        database=database,
                        plan=plan,
                        result=result,
                        expected_uid=expected_uid,
                    )
                    if _policy_reconciled_database_stable_binding(
                        database_proof
                    ) != _policy_reconciled_database_stable_binding(
                        current["precondition"]["database"]
                    ):
                        raise BridgeError(
                            "policy-reconciled database changed before clear"
                        )
                    candidate["preclear"] = preclear
                    persist("candidate-preclear-ready", candidate=candidate)
                    failpoint("after-candidate-preclear")
            if current["phase"] == "candidate-preclear-ready":
                if not _maintenance_is_clear(maintenance, uid=expected_uid):
                    _clear_successor_maintenance(
                        maintenance, uid=expected_uid
                    )
                failpoint("after-maintenance-clear")
                persist("maintenance-cleared")
            if current["phase"] == "maintenance-cleared":
                finalized = finalize_deferred_bridge_canaries(
                    release=candidate_release,
                    release_root=release_root,
                    client_release=client_release,
                    transaction=candidate_transaction,
                    operation_id=candidate_operation_id,
                    readiness_attestation=readiness_attestation,
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_database_generation=expected_generation,
                    expected_state_revision=expected_state_revision,
                    canary_accounts=canary_accounts,
                    canary_project=canary_project,
                    canary_repository_id=canary_repository_id,
                    canary_repository_generation=(
                        canary_repository_generation
                    ),
                    expected_owner_uid=expected_canary_uid,
                    wait_seconds=wait_seconds,
                    expected_uid=expected_uid,
                )
                candidate = dict(current["candidate"])
                candidate["journal_sha256"] = _sha256_file(
                    candidate_transaction / JOURNAL_NAME
                )
                candidate["document_sha256"] = finalized["document_sha256"]
                candidate["activation"] = finalized
                readiness = _verify_clean_successor_live(
                    transaction=candidate_transaction,
                    operation_id=candidate_operation_id,
                    expected_journal_sha256=str(candidate["journal_sha256"]),
                    expected_journal_document_sha256=str(
                        candidate["document_sha256"]
                    ),
                    broker_release=candidate_release,
                    client_release=client_release,
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    expected_database_generation=expected_generation,
                    canary_user=canary_user,
                    expected_canary_uid=expected_canary_uid,
                    canary_accounts=canary_accounts,
                    canary_project=canary_project,
                    canary_repository_id=canary_repository_id,
                    canary_repository_generation=(
                        canary_repository_generation
                    ),
                    wait_seconds=wait_seconds,
                    expected_uid=expected_uid,
                )
                preclear = candidate["preclear"]
                if (
                    readiness["systemd"].get("InvocationID")
                    != preclear["systemd"].get("InvocationID")
                    or readiness["systemd"].get("MainPID")
                    != preclear["systemd"].get("MainPID")
                    or readiness["socket_identity"]
                    != preclear["socket_identity"]
                    or readiness["socket_peer"] != preclear["socket_peer"]
                    or readiness["execution"] != preclear["execution"]
                    or readiness["process"] != preclear["process"]
                ):
                    raise BridgeError(
                        "clean bridge changed across maintenance clearance"
                    )
                plan, result = revalidate_lineage()
                database_proof = _policy_reconciled_database_proof(
                    database=database,
                    plan=plan,
                    result=result,
                    expected_uid=expected_uid,
                )
                if _policy_reconciled_database_stable_binding(
                    database_proof
                ) != _policy_reconciled_database_stable_binding(
                    current["precondition"]["database"]
                ):
                    raise BridgeError(
                        "policy-reconciled database changed during canary"
                    )
                candidate["readiness"] = readiness
                persist("authenticated-ready", candidate=candidate)
                failpoint("after-authenticated-readiness")
            if current["phase"] != "authenticated-ready":
                raise BridgeError(
                    "policy-reconciled recovery requires explicit rollback"
                )
            if not _maintenance_is_clear(maintenance, uid=expected_uid):
                raise BridgeError(
                    "policy-reconciled terminal unexpectedly retained maintenance"
                )
            verify_historical_evidence_bytes()
            profile_sha256 = _profile_identity(
                profile, uid=expected_uid
            )["sha256"]
            with maintenance_contract.maintenance_writer_lock(
                maintenance_root=maintenance_root,
                expected_uid=expected_uid,
                expected_gid=maintenance_gid,
            ):
                if not _maintenance_is_clear(
                    maintenance, uid=expected_uid
                ):
                    raise BridgeError(
                        "maintenance changed before committed terminal"
                    )
                terminal = _policy_recovery_terminal(
                    terminal_path,
                    {
                        "operation_id": operation_id,
                        "status": "committed",
                        "transaction_journal": str(journal_path),
                        "transaction_journal_sha256": _sha256_file(
                            journal_path
                        ),
                        "transaction_document_sha256": current[
                            "document_sha256"
                        ],
                        "policy_result_document_sha256": (
                            policy_result_document_sha256
                        ),
                        "policy_state_revision": expected_state_revision,
                        "predecessor_journal_sha256": (
                            predecessor_journal_raw_sha256
                        ),
                        "candidate_journal_sha256": current["candidate"][
                            "journal_sha256"
                        ],
                        "candidate_document_sha256": current["candidate"][
                            "document_sha256"
                        ],
                        "candidate_readiness_sha256": current["candidate"][
                            "readiness"
                        ]["document_sha256"],
                        "database_sha256": current["precondition"][
                            "database"
                        ]["database_sha256"],
                        "maintenance_deployment_id": (
                            maintenance_deployment_id
                        ),
                        "maintenance_active": False,
                        "profile_sha256": profile_sha256,
                        "error_sha256": None,
                        "completed_at_epoch": int(time.time()),
                    },
                    uid=expected_uid,
                )
            failpoint("after-committed-terminal")
            fence.mark_complete()
            return {"ok": True, "replayed": False, "terminal": terminal}
        except Exception as error:
            failure_text = str(error)[:4096]
            cleanup_errors: list[str] = []
            try:
                _reactivate_successor_maintenance(
                    maintenance, uid=expected_uid
                )
            except Exception as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
            try:
                persist(
                    "rollback-intent",
                    error=failure_text,
                )
            except Exception as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
            try:
                candidate_journal = candidate_transaction / JOURNAL_NAME
                if candidate_journal.exists() or candidate_journal.is_symlink():
                    restore_bridge(
                        transaction=candidate_transaction,
                        operation_id=candidate_operation_id,
                        expected_uid=expected_uid,
                    )
                with maintenance_contract.maintenance_writer_lock(
                    maintenance_root=maintenance_root,
                    expected_uid=expected_uid,
                    expected_gid=maintenance_gid,
                ):
                    _ensure_successor_maintenance(
                        maintenance, uid=expected_uid
                    )
                    with _broker_service_lock(
                        database, expected_uid=expected_uid
                    ):
                        _stable_inactive(broker_socket)
                        profile_state = dict(current["profile"])
                        before = profile_state["before_identity"]
                        backup_payload = Path(
                            str(profile_state["backup"])
                        ).read_bytes()
                        current_profile = _profile_identity(
                            profile, uid=expected_uid
                        )
                        if (
                            current_profile["sha256"]
                            != profile_state["backup_sha256"]
                        ):
                            if current_profile["sha256"] != profile_state.get(
                                "repaired_payload_sha256"
                            ):
                                raise BridgeError(
                                    "policy-reconciled profile rollback is ambiguous"
                                )
                            current_profile = _replace_profile_bytes(
                                profile,
                                backup_payload,
                                expected_current_sha256=str(
                                    current_profile["sha256"]
                                ),
                                owner_uid=expected_uid,
                                owner_gid=int(before["gid"]),
                                mode=int(before["mode"]),
                            )
                        profile_state["restored_identity"] = current_profile
                        plan, result = revalidate_lineage()
                        database_proof = _policy_reconciled_database_proof(
                            database=database,
                            plan=plan,
                            result=result,
                            expected_uid=expected_uid,
                        )
                        predecessor = (
                            verify_policy_reconciled_restored_predecessor(
                                transaction=predecessor_transaction,
                                operation_id=predecessor_operation_id,
                                journal_raw_sha256=(
                                    predecessor_journal_raw_sha256
                                ),
                                journal_document_sha256=(
                                    predecessor_journal_document_sha256
                                ),
                                readiness_attestation=readiness_attestation,
                                readiness_raw_sha256=readiness_raw_sha256,
                                readiness_document_sha256=(
                                    readiness_document_sha256
                                ),
                                database=database,
                                broker_socket=broker_socket,
                                dropin=dropin,
                                expected_database_generation=(
                                    expected_generation
                                ),
                                expected_state_revision=(
                                    expected_state_revision
                                ),
                                expected_uid=expected_uid,
                            )
                        )
                        if (
                            _policy_reconciled_database_stable_binding(
                                database_proof
                            )
                            != _policy_reconciled_database_stable_binding(
                                current["precondition"]["database"]
                            )
                            or predecessor
                            != current["precondition"]["predecessor"]
                        ):
                            raise BridgeError(
                                "policy-reconciled rollback evidence changed"
                            )
                persist(
                    "rolled-back",
                    profile=profile_state,
                    candidate={
                        **dict(current["candidate"]),
                        "restored": True,
                    },
                    error=failure_text,
                )
                if cleanup_errors:
                    raise BridgeError(
                        "policy-reconciled rollback evidence publication was incomplete: "
                        + "; ".join(cleanup_errors)
                    )
                with maintenance_contract.maintenance_writer_lock(
                    maintenance_root=maintenance_root,
                    expected_uid=expected_uid,
                    expected_gid=maintenance_gid,
                ):
                    _ensure_successor_maintenance(
                        maintenance, uid=expected_uid
                    )
                    terminal = _policy_recovery_terminal(
                        terminal_path,
                        {
                            "operation_id": operation_id,
                            "status": "aborted",
                            "transaction_journal": str(journal_path),
                            "transaction_journal_sha256": _sha256_file(
                                journal_path
                            ),
                            "transaction_document_sha256": current[
                                "document_sha256"
                            ],
                            "policy_result_document_sha256": (
                                policy_result_document_sha256
                            ),
                            "policy_state_revision": expected_state_revision,
                            "predecessor_journal_sha256": (
                                predecessor_journal_raw_sha256
                            ),
                            "candidate_journal_sha256": (
                                _sha256_file(candidate_journal)
                                if candidate_journal.exists()
                                else None
                            ),
                            "candidate_document_sha256": (
                                _load_bridge_journal(
                                    candidate_journal, uid=expected_uid
                                )["document_sha256"]
                                if candidate_journal.exists()
                                else None
                            ),
                            "candidate_readiness_sha256": None,
                            "database_sha256": current["precondition"][
                                "database"
                            ]["database_sha256"],
                            "maintenance_deployment_id": (
                                maintenance_deployment_id
                            ),
                            "maintenance_active": True,
                            "profile_sha256": profile_state[
                                "backup_sha256"
                            ],
                            "error_sha256": _sha256_bytes(
                                failure_text.encode("utf-8")
                            ),
                            "completed_at_epoch": int(time.time()),
                        },
                        uid=expected_uid,
                    )
                fence.mark_complete()
                return {
                    "ok": False,
                    "replayed": False,
                    "terminal": terminal,
                    "error": failure_text,
                }
            except BridgeError as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
            except Exception as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
            try:
                persist(
                    "recovery-required",
                    error=(
                        failure_text
                        + "; rollback incomplete: "
                        + "; ".join(cleanup_errors)
                    )[:4096],
                )
            except Exception:
                pass
            raise BridgeError(
                "policy-reconciled recovery requires manual replay; "
                + "; ".join(cleanup_errors)
            ) from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    actions = parser.add_subparsers(dest="action", required=True)

    stage = actions.add_parser("stage")
    stage.add_argument("--repo", type=Path, default=ROOT)
    stage.add_argument("--commit", required=True)
    stage.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)
    stage.add_argument("--owner-uid", type=int, default=0)
    stage.add_argument("--owner-gid", type=int, default=0)

    verify = actions.add_parser("verify")
    verify.add_argument("--release", type=Path, required=True)
    verify.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)

    status = actions.add_parser("status")
    status.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)

    activate = actions.add_parser("activate")
    activate.add_argument("--release", type=Path, required=True)
    activate.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)
    activate.add_argument("--transaction-dir", type=Path, required=True)
    activate.add_argument("--operation-id", required=True)
    activate.add_argument("--failed-installer-transaction", type=Path, required=True)
    activate.add_argument("--failed-installer-operation-id", required=True)
    activate.add_argument("--readiness-attestation", type=Path, required=True)
    activate.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    activate.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    activate.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    activate.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    activate.add_argument("--canary", action="append", default=[], required=True)
    activate.add_argument("--wait-seconds", type=int, default=30)
    activate.add_argument("--expected-uid", type=int, default=0)
    activate.add_argument("--predecessor-transaction", type=Path)
    activate.add_argument("--predecessor-operation-id")
    activate.add_argument("--predecessor-journal-sha256")
    activate.add_argument("--predecessor-document-sha256")

    verify_ready = actions.add_parser("verify-ready")
    verify_ready.add_argument("--transaction-dir", type=Path, required=True)
    verify_ready.add_argument("--operation-id", required=True)
    verify_ready.add_argument("--expected-journal-sha256", required=True)
    verify_ready.add_argument(
        "--expected-journal-document-sha256", required=True
    )
    verify_ready.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    verify_ready.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    verify_ready.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    verify_ready.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    verify_ready.add_argument("--expected-database-generation", required=True)
    verify_ready.add_argument("--canary-user", required=True)
    verify_ready.add_argument("--expected-canary-uid", type=int, required=True)
    verify_ready.add_argument("--canary-project", type=Path, required=True)
    verify_ready.add_argument("--canary-repository-id", required=True)
    verify_ready.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    verify_ready.add_argument("--wait-seconds", type=int, default=30)
    verify_ready.add_argument("--expected-uid", type=int, default=0)

    successor_preflight = actions.add_parser("successor-preflight")
    successor_preflight.add_argument(
        "--historical-client-release", type=Path, required=True
    )
    successor_preflight.add_argument(
        "--predecessor-transaction", type=Path, required=True
    )
    successor_preflight.add_argument("--predecessor-operation-id", required=True)
    successor_preflight.add_argument("--predecessor-journal-sha256", required=True)
    successor_preflight.add_argument(
        "--predecessor-document-sha256", required=True
    )
    successor_preflight.add_argument(
        "--database", type=Path, default=DEFAULT_DATABASE
    )
    successor_preflight.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    successor_preflight.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    successor_preflight.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    successor_preflight.add_argument(
        "--expected-database-generation", required=True
    )
    successor_preflight.add_argument("--canary-user", required=True)
    successor_preflight.add_argument(
        "--expected-canary-uid", type=int, required=True
    )
    successor_preflight.add_argument("--canary-project", type=Path, required=True)
    successor_preflight.add_argument("--canary-repository-id", required=True)
    successor_preflight.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    successor_preflight.add_argument("--wait-seconds", type=int, default=30)
    successor_preflight.add_argument("--expected-uid", type=int, default=0)

    successor = actions.add_parser("successor-apply")
    successor.add_argument("--candidate-release", type=Path, required=True)
    successor.add_argument("--release-root", type=Path, required=True)
    successor.add_argument("--client-release", type=Path, required=True)
    successor.add_argument("--transaction-dir", type=Path, required=True)
    successor.add_argument("--operation-id", required=True)
    successor.add_argument("--predecessor-transaction", type=Path, required=True)
    successor.add_argument("--predecessor-operation-id", required=True)
    successor.add_argument("--predecessor-journal-sha256", required=True)
    successor.add_argument("--predecessor-document-sha256", required=True)
    successor.add_argument(
        "--failed-installer-transaction", type=Path, required=True
    )
    successor.add_argument("--failed-installer-operation-id", required=True)
    successor.add_argument("--readiness-attestation", type=Path, required=True)
    successor.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    successor.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    successor.add_argument("--owner-map", type=Path, required=True)
    successor.add_argument("--owner-map-sha256", required=True)
    successor.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    successor.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    successor.add_argument("--expected-database-generation", required=True)
    successor.add_argument("--canary-user", required=True)
    successor.add_argument("--expected-canary-uid", type=int, required=True)
    successor.add_argument("--canary-project", type=Path, required=True)
    successor.add_argument("--canary-repository-id", required=True)
    successor.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    successor.add_argument(
        "--lifecycle-transaction-journal", type=Path, required=True
    )
    successor.add_argument(
        "--lifecycle-transaction-journal-sha256", required=True
    )
    successor.add_argument(
        "--lifecycle-transaction-document-sha256", required=True
    )
    successor.add_argument("--lifecycle-attestation", type=Path, required=True)
    successor.add_argument("--lifecycle-attestation-sha256", required=True)
    successor.add_argument(
        "--lifecycle-attestation-document-sha256", required=True
    )
    successor.add_argument(
        "--additional-canary",
        action="append",
        required=True,
        metavar="USER=UID",
    )
    successor.add_argument("--inherited-successor-journal-sha256")
    successor.add_argument("--inherited-successor-document-sha256")
    successor.add_argument("--wait-seconds", type=int, default=30)
    successor.add_argument("--expected-uid", type=int, default=0)

    executor_rescue = actions.add_parser(SUCCESSOR_EXECUTOR_RESCUE_PATH)
    executor_rescue.add_argument("--candidate-release", type=Path, required=True)
    executor_rescue.add_argument("--release-root", type=Path, required=True)
    executor_rescue.add_argument("--transaction-dir", type=Path, required=True)
    executor_rescue.add_argument("--operation-id", required=True)
    executor_rescue.add_argument(
        "--predecessor-transaction", type=Path, required=True
    )
    executor_rescue.add_argument("--predecessor-operation-id", required=True)
    executor_rescue.add_argument("--predecessor-journal-sha256", required=True)
    executor_rescue.add_argument("--predecessor-document-sha256", required=True)
    executor_rescue.add_argument(
        "--failed-installer-transaction", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--failed-installer-operation-id", required=True
    )
    executor_rescue.add_argument(
        "--readiness-attestation", type=Path, required=True
    )
    executor_rescue.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    executor_rescue.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    executor_rescue.add_argument("--owner-map", type=Path, required=True)
    executor_rescue.add_argument("--owner-map-sha256", required=True)
    executor_rescue.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    executor_rescue.add_argument("--dropin", type=Path, default=DEFAULT_DROPIN)
    executor_rescue.add_argument(
        "--expected-database-generation", required=True
    )
    executor_rescue.add_argument("--canary-user", required=True)
    executor_rescue.add_argument(
        "--expected-canary-uid", type=int, required=True
    )
    executor_rescue.add_argument("--canary-project", type=Path, required=True)
    executor_rescue.add_argument("--canary-repository-id", required=True)
    executor_rescue.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-transaction-journal", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-transaction-journal-sha256", required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-transaction-document-sha256", required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-attestation", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-attestation-sha256", required=True
    )
    executor_rescue.add_argument(
        "--lifecycle-attestation-document-sha256", required=True
    )
    executor_rescue.add_argument(
        "--additional-canary",
        action="append",
        required=True,
        metavar="USER=UID",
    )
    executor_rescue.add_argument(
        "--inherited-successor-journal-sha256", required=True
    )
    executor_rescue.add_argument(
        "--inherited-successor-document-sha256", required=True
    )
    executor_rescue.add_argument(
        "--previous-executor-release", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--previous-executor-release-digest", required=True
    )
    executor_rescue.add_argument(
        "--retained-client-release", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--retained-client-release-digest", required=True
    )
    executor_rescue.add_argument(
        "--rescue-executor-release", type=Path, required=True
    )
    executor_rescue.add_argument(
        "--rescue-executor-release-digest", required=True
    )
    executor_rescue.add_argument("--wait-seconds", type=int, default=30)
    executor_rescue.add_argument("--expected-uid", type=int, default=0)

    executor_handoff = actions.add_parser(
        SUCCESSOR_EXECUTOR_HANDOFF_PATH,
        parents=[executor_rescue],
        add_help=False,
    )
    executor_handoff.add_argument(
        "--executor-rescue-sha256", required=True
    )

    post_export_continuation = actions.add_parser(
        SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH,
        parents=[executor_handoff],
        add_help=False,
    )
    post_export_continuation.add_argument(
        "--executor-rescue-handoff-sha256", required=True
    )

    successor_abort = actions.add_parser("successor-abort")
    successor_abort.add_argument("--transaction-dir", type=Path, required=True)
    successor_abort.add_argument("--operation-id", required=True)
    successor_abort.add_argument("--expected-uid", type=int, default=0)

    lifecycle_quiesce = actions.add_parser(
        "quiesce-lifecycle-recovery-crash-loop"
    )
    lifecycle_quiesce.add_argument(
        "--transaction-dir", type=Path, required=True
    )
    lifecycle_quiesce.add_argument("--operation-id", required=True)
    for prefix in (
        "lifecycle-plan",
        "lifecycle-result",
        "lifecycle-service-intent",
    ):
        lifecycle_quiesce.add_argument(
            f"--{prefix}", type=Path, required=True
        )
        lifecycle_quiesce.add_argument(
            f"--{prefix}-raw-sha256", required=True
        )
        lifecycle_quiesce.add_argument(
            f"--{prefix}-document-sha256", required=True
        )
    lifecycle_quiesce.add_argument(
        "--lifecycle-service-result", type=Path, required=True
    )
    lifecycle_quiesce.add_argument(
        "--database", type=Path, default=DEFAULT_DATABASE
    )
    lifecycle_quiesce.add_argument(
        "--profile", type=Path, default=DEFAULT_PROFILE
    )
    lifecycle_quiesce.add_argument(
        "--socket", type=Path, default=DEFAULT_SOCKET
    )
    lifecycle_quiesce.add_argument(
        "--dropin", type=Path, default=DEFAULT_DROPIN
    )
    lifecycle_quiesce.add_argument(
        "--maintenance-root", type=Path, required=True
    )
    lifecycle_quiesce.add_argument(
        "--maintenance-gid", type=int, required=True
    )
    lifecycle_quiesce.add_argument(
        "--maintenance-deployment-id", required=True
    )
    lifecycle_quiesce.add_argument("--wait-seconds", type=int, default=30)
    lifecycle_quiesce.add_argument("--expected-uid", type=int, default=0)

    policy_recovery = actions.add_parser(
        "recover-policy-reconciled-restored"
    )
    policy_recovery.add_argument(
        "--candidate-release", type=Path, required=True
    )
    policy_recovery.add_argument("--release-root", type=Path, required=True)
    policy_recovery.add_argument("--client-release", type=Path, required=True)
    policy_recovery.add_argument(
        "--transaction-dir", type=Path, required=True
    )
    policy_recovery.add_argument("--operation-id", required=True)
    policy_recovery.add_argument(
        "--predecessor-transaction", type=Path, required=True
    )
    policy_recovery.add_argument(
        "--predecessor-operation-id", required=True
    )
    policy_recovery.add_argument(
        "--predecessor-journal-raw-sha256", required=True
    )
    policy_recovery.add_argument(
        "--predecessor-journal-document-sha256", required=True
    )
    policy_recovery.add_argument(
        "--failed-installer-transaction", type=Path, required=True
    )
    policy_recovery.add_argument(
        "--failed-installer-operation-id", required=True
    )
    policy_recovery.add_argument(
        "--readiness-attestation", type=Path, required=True
    )
    policy_recovery.add_argument("--readiness-raw-sha256", required=True)
    policy_recovery.add_argument(
        "--readiness-document-sha256", required=True
    )
    for prefix in (
        "source-repair-plan",
        "source-repair-result",
        "policy-plan",
        "policy-result",
    ):
        policy_recovery.add_argument(
            f"--{prefix}", type=Path, required=True
        )
        policy_recovery.add_argument(
            f"--{prefix}-raw-sha256", required=True
        )
        policy_recovery.add_argument(
            f"--{prefix}-document-sha256", required=True
        )
    policy_recovery.add_argument(
        "--database", type=Path, default=DEFAULT_DATABASE
    )
    policy_recovery.add_argument(
        "--profile", type=Path, default=DEFAULT_PROFILE
    )
    policy_recovery.add_argument("--owner-map", type=Path, required=True)
    policy_recovery.add_argument("--owner-map-sha256", required=True)
    policy_recovery.add_argument(
        "--socket", type=Path, default=DEFAULT_SOCKET
    )
    policy_recovery.add_argument(
        "--dropin", type=Path, default=DEFAULT_DROPIN
    )
    policy_recovery.add_argument(
        "--maintenance-root", type=Path, required=True
    )
    policy_recovery.add_argument("--maintenance-gid", type=int, required=True)
    policy_recovery.add_argument(
        "--maintenance-deployment-id", required=True
    )
    policy_recovery.add_argument("--canary-user", required=True)
    policy_recovery.add_argument(
        "--expected-canary-uid", type=int, required=True
    )
    policy_recovery.add_argument(
        "--canary-project", type=Path, required=True
    )
    policy_recovery.add_argument("--canary-repository-id", required=True)
    policy_recovery.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    policy_recovery.add_argument(
        "--additional-canary",
        action="append",
        required=True,
        metavar="USER=UID",
    )
    policy_recovery.add_argument("--wait-seconds", type=int, default=30)
    policy_recovery.add_argument("--expected-uid", type=int, default=0)

    internal_inventory = actions.add_parser(
        INTERNAL_CUTOVER_INVENTORY_ACTION,
        help=argparse.SUPPRESS,
    )
    internal_inventory.add_argument(
        "--historical-release", type=Path, required=True
    )
    internal_inventory.add_argument(
        "--historical-release-digest", required=True
    )
    internal_inventory.add_argument("--profile", type=Path, required=True)
    internal_inventory.add_argument("--project", type=Path, required=True)
    internal_inventory.add_argument("--expected-repository-id", required=True)
    internal_inventory.add_argument(
        "--expected-repository-generation", type=int, required=True
    )
    internal_inventory.add_argument(
        "--expected-database-generation", required=True
    )
    internal_inventory.add_argument(
        "--expected-socket", type=Path, required=True
    )
    internal_inventory.add_argument(
        "--expected-service-uid", type=int, required=True
    )
    internal_inventory.add_argument(
        "--expected-client-uid", type=int, required=True
    )
    internal_inventory.add_argument(
        "--expected-client-gid", type=int, required=True
    )

    restore = actions.add_parser("restore")
    restore.add_argument("--transaction-dir", type=Path, required=True)
    restore.add_argument("--operation-id", required=True)
    restore.add_argument("--expected-uid", type=int, default=0)
    for handoff_action in (
        "handoff-reference",
        "handoff-arm",
        "handoff-retire",
        "handoff-rollback-prepare",
        "handoff-rollback-unfence",
        "handoff-verify-rearmed",
        "handoff-complete",
    ):
        handoff = actions.add_parser(handoff_action)
        handoff.add_argument("--transaction-dir", type=Path, required=True)
        handoff.add_argument("--operation-id", required=True)
        handoff.add_argument("--expected-journal-sha256", required=True)
        handoff.add_argument("--outer-transaction-id", required=True)
        handoff.add_argument("--database", type=Path, required=True)
        handoff.add_argument("--profile", type=Path, required=True)
        handoff.add_argument("--socket", type=Path, required=True)
        handoff.add_argument("--dropin", type=Path, required=True)
        handoff.add_argument("--retirement-guard", type=Path, required=True)
        handoff.add_argument("--handoff-journal", type=Path, required=True)
        handoff.add_argument("--expected-uid", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.action == "stage":
            result = stage_release(
                repo=arguments.repo,
                commit=arguments.commit,
                release_root=arguments.release_root,
                owner_uid=arguments.owner_uid,
                owner_gid=arguments.owner_gid,
            )
        elif arguments.action == "verify":
            manifest = verify_release(
                arguments.release, release_root=arguments.release_root
            )
            result = _release_summary(manifest, release=arguments.release)
        elif arguments.action == "status":
            result = _broker_status(arguments.socket)
        elif arguments.action == "activate":
            result = activate_bridge(
                release=arguments.release,
                release_root=arguments.release_root,
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                failed_installer_transaction=arguments.failed_installer_transaction,
                failed_installer_operation_id=arguments.failed_installer_operation_id,
                readiness_attestation=arguments.readiness_attestation,
                database=arguments.database,
                profile=arguments.profile,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                canaries=arguments.canary,
                wait_seconds=arguments.wait_seconds,
                expected_uid=arguments.expected_uid,
                predecessor_transaction=arguments.predecessor_transaction,
                predecessor_operation_id=arguments.predecessor_operation_id,
                predecessor_journal_sha256=arguments.predecessor_journal_sha256,
                predecessor_document_sha256=arguments.predecessor_document_sha256,
            )
        elif arguments.action == "verify-ready":
            result = verify_ready_bridge(
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                expected_journal_sha256=arguments.expected_journal_sha256,
                expected_journal_document_sha256=(
                    arguments.expected_journal_document_sha256
                ),
                database=arguments.database,
                profile=arguments.profile,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                expected_database_generation=(
                    arguments.expected_database_generation
                ),
                canary_user=arguments.canary_user,
                expected_canary_uid=arguments.expected_canary_uid,
                canary_project=arguments.canary_project,
                canary_repository_id=arguments.canary_repository_id,
                canary_repository_generation=arguments.canary_repository_generation,
                wait_seconds=arguments.wait_seconds,
                expected_uid=arguments.expected_uid,
            )
        elif arguments.action == "successor-preflight":
            result = {
                "ok": True,
                "predecessor": _verify_active_predecessor_for_successor(
                    transaction=arguments.predecessor_transaction,
                    operation_id=arguments.predecessor_operation_id,
                    expected_journal_sha256=(
                        arguments.predecessor_journal_sha256
                    ),
                    expected_journal_document_sha256=(
                        arguments.predecessor_document_sha256
                    ),
                    historical_client_release=(
                        arguments.historical_client_release
                    ),
                    database=arguments.database,
                    profile=arguments.profile,
                    broker_socket=arguments.socket,
                    dropin=arguments.dropin,
                    expected_database_generation=(
                        arguments.expected_database_generation
                    ),
                    canary_user=arguments.canary_user,
                    expected_canary_uid=arguments.expected_canary_uid,
                    canary_project=arguments.canary_project,
                    canary_repository_id=arguments.canary_repository_id,
                    canary_repository_generation=(
                        arguments.canary_repository_generation
                    ),
                    wait_seconds=arguments.wait_seconds,
                    expected_uid=arguments.expected_uid,
                ),
            }
        elif arguments.action == "successor-apply":
            result = replace_ready_bridge_with_clean_successor(
                candidate_release=arguments.candidate_release,
                release_root=arguments.release_root,
                client_release=arguments.client_release,
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                predecessor_transaction=arguments.predecessor_transaction,
                predecessor_operation_id=arguments.predecessor_operation_id,
                predecessor_journal_sha256=(
                    arguments.predecessor_journal_sha256
                ),
                predecessor_document_sha256=(
                    arguments.predecessor_document_sha256
                ),
                failed_installer_transaction=(
                    arguments.failed_installer_transaction
                ),
                failed_installer_operation_id=(
                    arguments.failed_installer_operation_id
                ),
                readiness_attestation=arguments.readiness_attestation,
                database=arguments.database,
                profile=arguments.profile,
                owner_map=arguments.owner_map,
                owner_map_sha256=arguments.owner_map_sha256,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                expected_database_generation=(
                    arguments.expected_database_generation
                ),
                canary_user=arguments.canary_user,
                expected_canary_uid=arguments.expected_canary_uid,
                canary_project=arguments.canary_project,
                canary_repository_id=arguments.canary_repository_id,
                canary_repository_generation=(
                    arguments.canary_repository_generation
                ),
                lifecycle_transaction_journal=(
                    arguments.lifecycle_transaction_journal
                ),
                lifecycle_transaction_journal_sha256=(
                    arguments.lifecycle_transaction_journal_sha256
                ),
                lifecycle_transaction_document_sha256=(
                    arguments.lifecycle_transaction_document_sha256
                ),
                lifecycle_attestation=arguments.lifecycle_attestation,
                lifecycle_attestation_sha256=(
                    arguments.lifecycle_attestation_sha256
                ),
                lifecycle_attestation_document_sha256=(
                    arguments.lifecycle_attestation_document_sha256
                ),
                additional_canaries=arguments.additional_canary,
                inherited_successor_journal_sha256=(
                    arguments.inherited_successor_journal_sha256
                ),
                inherited_successor_document_sha256=(
                    arguments.inherited_successor_document_sha256
                ),
                wait_seconds=arguments.wait_seconds,
                expected_uid=arguments.expected_uid,
            )
        elif arguments.action == SUCCESSOR_EXECUTOR_RESCUE_PATH:
            result = rescue_ready_bridge_with_clean_successor(
                previous_executor_release=(
                    arguments.previous_executor_release
                ),
                previous_executor_release_digest=(
                    arguments.previous_executor_release_digest
                ),
                retained_client_release=arguments.retained_client_release,
                retained_client_release_digest=(
                    arguments.retained_client_release_digest
                ),
                rescue_executor_release=arguments.rescue_executor_release,
                rescue_executor_release_digest=(
                    arguments.rescue_executor_release_digest
                ),
                inherited_successor_journal_sha256=(
                    arguments.inherited_successor_journal_sha256
                ),
                inherited_successor_document_sha256=(
                    arguments.inherited_successor_document_sha256
                ),
                successor_arguments={
                    "candidate_release": arguments.candidate_release,
                    "release_root": arguments.release_root,
                    "transaction": arguments.transaction_dir,
                    "operation_id": arguments.operation_id,
                    "predecessor_transaction": (
                        arguments.predecessor_transaction
                    ),
                    "predecessor_operation_id": (
                        arguments.predecessor_operation_id
                    ),
                    "predecessor_journal_sha256": (
                        arguments.predecessor_journal_sha256
                    ),
                    "predecessor_document_sha256": (
                        arguments.predecessor_document_sha256
                    ),
                    "failed_installer_transaction": (
                        arguments.failed_installer_transaction
                    ),
                    "failed_installer_operation_id": (
                        arguments.failed_installer_operation_id
                    ),
                    "readiness_attestation": (
                        arguments.readiness_attestation
                    ),
                    "database": arguments.database,
                    "profile": arguments.profile,
                    "owner_map": arguments.owner_map,
                    "owner_map_sha256": arguments.owner_map_sha256,
                    "broker_socket": arguments.socket,
                    "dropin": arguments.dropin,
                    "expected_database_generation": (
                        arguments.expected_database_generation
                    ),
                    "canary_user": arguments.canary_user,
                    "expected_canary_uid": arguments.expected_canary_uid,
                    "canary_project": arguments.canary_project,
                    "canary_repository_id": (
                        arguments.canary_repository_id
                    ),
                    "canary_repository_generation": (
                        arguments.canary_repository_generation
                    ),
                    "lifecycle_transaction_journal": (
                        arguments.lifecycle_transaction_journal
                    ),
                    "lifecycle_transaction_journal_sha256": (
                        arguments.lifecycle_transaction_journal_sha256
                    ),
                    "lifecycle_transaction_document_sha256": (
                        arguments.lifecycle_transaction_document_sha256
                    ),
                    "lifecycle_attestation": (
                        arguments.lifecycle_attestation
                    ),
                    "lifecycle_attestation_sha256": (
                        arguments.lifecycle_attestation_sha256
                    ),
                    "lifecycle_attestation_document_sha256": (
                        arguments.lifecycle_attestation_document_sha256
                    ),
                    "additional_canaries": arguments.additional_canary,
                    "wait_seconds": arguments.wait_seconds,
                    "expected_uid": arguments.expected_uid,
                },
            )
        elif arguments.action == SUCCESSOR_EXECUTOR_HANDOFF_PATH:
            result = handoff_rescued_executor_with_clean_successor(
                executor_rescue_sha256=arguments.executor_rescue_sha256,
                previous_executor_release=arguments.previous_executor_release,
                previous_executor_release_digest=(
                    arguments.previous_executor_release_digest
                ),
                retained_client_release=arguments.retained_client_release,
                retained_client_release_digest=(
                    arguments.retained_client_release_digest
                ),
                successor_executor_release=arguments.rescue_executor_release,
                successor_executor_release_digest=(
                    arguments.rescue_executor_release_digest
                ),
                inherited_successor_journal_sha256=(
                    arguments.inherited_successor_journal_sha256
                ),
                inherited_successor_document_sha256=(
                    arguments.inherited_successor_document_sha256
                ),
                successor_arguments={
                    "candidate_release": arguments.candidate_release,
                    "release_root": arguments.release_root,
                    "transaction": arguments.transaction_dir,
                    "operation_id": arguments.operation_id,
                    "predecessor_transaction": (
                        arguments.predecessor_transaction
                    ),
                    "predecessor_operation_id": (
                        arguments.predecessor_operation_id
                    ),
                    "predecessor_journal_sha256": (
                        arguments.predecessor_journal_sha256
                    ),
                    "predecessor_document_sha256": (
                        arguments.predecessor_document_sha256
                    ),
                    "failed_installer_transaction": (
                        arguments.failed_installer_transaction
                    ),
                    "failed_installer_operation_id": (
                        arguments.failed_installer_operation_id
                    ),
                    "readiness_attestation": arguments.readiness_attestation,
                    "database": arguments.database,
                    "profile": arguments.profile,
                    "owner_map": arguments.owner_map,
                    "owner_map_sha256": arguments.owner_map_sha256,
                    "broker_socket": arguments.socket,
                    "dropin": arguments.dropin,
                    "expected_database_generation": (
                        arguments.expected_database_generation
                    ),
                    "canary_user": arguments.canary_user,
                    "expected_canary_uid": arguments.expected_canary_uid,
                    "canary_project": arguments.canary_project,
                    "canary_repository_id": (
                        arguments.canary_repository_id
                    ),
                    "canary_repository_generation": (
                        arguments.canary_repository_generation
                    ),
                    "lifecycle_transaction_journal": (
                        arguments.lifecycle_transaction_journal
                    ),
                    "lifecycle_transaction_journal_sha256": (
                        arguments.lifecycle_transaction_journal_sha256
                    ),
                    "lifecycle_transaction_document_sha256": (
                        arguments.lifecycle_transaction_document_sha256
                    ),
                    "lifecycle_attestation": arguments.lifecycle_attestation,
                    "lifecycle_attestation_sha256": (
                        arguments.lifecycle_attestation_sha256
                    ),
                    "lifecycle_attestation_document_sha256": (
                        arguments.lifecycle_attestation_document_sha256
                    ),
                    "additional_canaries": arguments.additional_canary,
                    "wait_seconds": arguments.wait_seconds,
                    "expected_uid": arguments.expected_uid,
                },
            )
        elif (
            arguments.action
            == SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH
        ):
            result = continue_post_export_rescued_executor_with_clean_successor(
                executor_rescue_sha256=arguments.executor_rescue_sha256,
                executor_rescue_handoff_sha256=(
                    arguments.executor_rescue_handoff_sha256
                ),
                previous_executor_release=arguments.previous_executor_release,
                previous_executor_release_digest=(
                    arguments.previous_executor_release_digest
                ),
                retained_client_release=arguments.retained_client_release,
                retained_client_release_digest=(
                    arguments.retained_client_release_digest
                ),
                successor_executor_release=arguments.rescue_executor_release,
                successor_executor_release_digest=(
                    arguments.rescue_executor_release_digest
                ),
                inherited_successor_journal_sha256=(
                    arguments.inherited_successor_journal_sha256
                ),
                inherited_successor_document_sha256=(
                    arguments.inherited_successor_document_sha256
                ),
                successor_arguments={
                    "candidate_release": arguments.candidate_release,
                    "release_root": arguments.release_root,
                    "transaction": arguments.transaction_dir,
                    "operation_id": arguments.operation_id,
                    "predecessor_transaction": (
                        arguments.predecessor_transaction
                    ),
                    "predecessor_operation_id": (
                        arguments.predecessor_operation_id
                    ),
                    "predecessor_journal_sha256": (
                        arguments.predecessor_journal_sha256
                    ),
                    "predecessor_document_sha256": (
                        arguments.predecessor_document_sha256
                    ),
                    "failed_installer_transaction": (
                        arguments.failed_installer_transaction
                    ),
                    "failed_installer_operation_id": (
                        arguments.failed_installer_operation_id
                    ),
                    "readiness_attestation": arguments.readiness_attestation,
                    "database": arguments.database,
                    "profile": arguments.profile,
                    "owner_map": arguments.owner_map,
                    "owner_map_sha256": arguments.owner_map_sha256,
                    "broker_socket": arguments.socket,
                    "dropin": arguments.dropin,
                    "expected_database_generation": (
                        arguments.expected_database_generation
                    ),
                    "canary_user": arguments.canary_user,
                    "expected_canary_uid": arguments.expected_canary_uid,
                    "canary_project": arguments.canary_project,
                    "canary_repository_id": (
                        arguments.canary_repository_id
                    ),
                    "canary_repository_generation": (
                        arguments.canary_repository_generation
                    ),
                    "lifecycle_transaction_journal": (
                        arguments.lifecycle_transaction_journal
                    ),
                    "lifecycle_transaction_journal_sha256": (
                        arguments.lifecycle_transaction_journal_sha256
                    ),
                    "lifecycle_transaction_document_sha256": (
                        arguments.lifecycle_transaction_document_sha256
                    ),
                    "lifecycle_attestation": arguments.lifecycle_attestation,
                    "lifecycle_attestation_sha256": (
                        arguments.lifecycle_attestation_sha256
                    ),
                    "lifecycle_attestation_document_sha256": (
                        arguments.lifecycle_attestation_document_sha256
                    ),
                    "additional_canaries": arguments.additional_canary,
                    "wait_seconds": arguments.wait_seconds,
                    "expected_uid": arguments.expected_uid,
                },
            )
        elif arguments.action == "successor-abort":
            result = abort_clean_bridge_successor(
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                expected_uid=arguments.expected_uid,
            )
        elif (
            arguments.action
            == "quiesce-lifecycle-recovery-crash-loop"
        ):
            result = quiesce_lifecycle_recovery_crash_loop(
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                lifecycle_plan=arguments.lifecycle_plan,
                lifecycle_plan_raw_sha256=(
                    arguments.lifecycle_plan_raw_sha256
                ),
                lifecycle_plan_document_sha256=(
                    arguments.lifecycle_plan_document_sha256
                ),
                lifecycle_result=arguments.lifecycle_result,
                lifecycle_result_raw_sha256=(
                    arguments.lifecycle_result_raw_sha256
                ),
                lifecycle_result_document_sha256=(
                    arguments.lifecycle_result_document_sha256
                ),
                lifecycle_service_intent=(
                    arguments.lifecycle_service_intent
                ),
                lifecycle_service_intent_raw_sha256=(
                    arguments.lifecycle_service_intent_raw_sha256
                ),
                lifecycle_service_intent_document_sha256=(
                    arguments.lifecycle_service_intent_document_sha256
                ),
                lifecycle_service_result=(
                    arguments.lifecycle_service_result
                ),
                database=arguments.database,
                profile=arguments.profile,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                maintenance_root=arguments.maintenance_root,
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                wait_seconds=arguments.wait_seconds,
                expected_uid=arguments.expected_uid,
            )
        elif arguments.action == "recover-policy-reconciled-restored":
            result = recover_policy_reconciled_restored_bridge(
                candidate_release=arguments.candidate_release,
                release_root=arguments.release_root,
                client_release=arguments.client_release,
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                predecessor_transaction=arguments.predecessor_transaction,
                predecessor_operation_id=(
                    arguments.predecessor_operation_id
                ),
                predecessor_journal_raw_sha256=(
                    arguments.predecessor_journal_raw_sha256
                ),
                predecessor_journal_document_sha256=(
                    arguments.predecessor_journal_document_sha256
                ),
                failed_installer_transaction=(
                    arguments.failed_installer_transaction
                ),
                failed_installer_operation_id=(
                    arguments.failed_installer_operation_id
                ),
                readiness_attestation=arguments.readiness_attestation,
                readiness_raw_sha256=arguments.readiness_raw_sha256,
                readiness_document_sha256=(
                    arguments.readiness_document_sha256
                ),
                source_repair_plan=arguments.source_repair_plan,
                source_repair_plan_raw_sha256=(
                    arguments.source_repair_plan_raw_sha256
                ),
                source_repair_plan_document_sha256=(
                    arguments.source_repair_plan_document_sha256
                ),
                source_repair_result=arguments.source_repair_result,
                source_repair_result_raw_sha256=(
                    arguments.source_repair_result_raw_sha256
                ),
                source_repair_result_document_sha256=(
                    arguments.source_repair_result_document_sha256
                ),
                policy_plan=arguments.policy_plan,
                policy_plan_raw_sha256=arguments.policy_plan_raw_sha256,
                policy_plan_document_sha256=(
                    arguments.policy_plan_document_sha256
                ),
                policy_result=arguments.policy_result,
                policy_result_raw_sha256=arguments.policy_result_raw_sha256,
                policy_result_document_sha256=(
                    arguments.policy_result_document_sha256
                ),
                database=arguments.database,
                profile=arguments.profile,
                owner_map=arguments.owner_map,
                owner_map_sha256=arguments.owner_map_sha256,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                maintenance_root=arguments.maintenance_root,
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                canary_user=arguments.canary_user,
                expected_canary_uid=arguments.expected_canary_uid,
                canary_project=arguments.canary_project,
                canary_repository_id=arguments.canary_repository_id,
                canary_repository_generation=(
                    arguments.canary_repository_generation
                ),
                additional_canaries=arguments.additional_canary,
                wait_seconds=arguments.wait_seconds,
                expected_uid=arguments.expected_uid,
            )
        elif arguments.action == INTERNAL_CUTOVER_INVENTORY_ACTION:
            result = _internal_cutover_inventory_read_canary(
                historical_release=arguments.historical_release,
                historical_release_digest=(
                    arguments.historical_release_digest
                ),
                profile=arguments.profile,
                project=arguments.project,
                expected_repository_id=arguments.expected_repository_id,
                expected_repository_generation=(
                    arguments.expected_repository_generation
                ),
                expected_database_generation=(
                    arguments.expected_database_generation
                ),
                expected_broker_socket=arguments.expected_socket,
                expected_service_uid=arguments.expected_service_uid,
                expected_client_uid=arguments.expected_client_uid,
                expected_client_gid=arguments.expected_client_gid,
            )
        elif arguments.action == "restore":
            result = restore_bridge(
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                expected_uid=arguments.expected_uid,
            )
        else:
            result = handoff_bridge(
                action=arguments.action,
                transaction=arguments.transaction_dir,
                operation_id=arguments.operation_id,
                expected_journal_sha256=arguments.expected_journal_sha256,
                outer_transaction_id=arguments.outer_transaction_id,
                database=arguments.database,
                profile=arguments.profile,
                broker_socket=arguments.socket,
                dropin=arguments.dropin,
                retirement_guard=arguments.retirement_guard,
                handoff_journal=arguments.handoff_journal,
                expected_uid=arguments.expected_uid,
            )
        print(
            json.dumps(
                result,
                sort_keys=True,
                indent=None if arguments.json else 2,
                separators=(",", ":") if arguments.json else None,
            )
        )
        if (
            arguments.action == "recover-policy-reconciled-restored"
            and isinstance(result, Mapping)
            and result.get("ok") is False
        ):
            return 1
        return 0
    except (BridgeError, OSError, sqlite3.Error, ValueError) as error:
        payload = {"ok": False, "error": str(error)}
        print(
            json.dumps(
                payload,
                sort_keys=True,
                indent=None if arguments.json else 2,
                separators=(",", ":") if arguments.json else None,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
