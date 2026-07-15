"""Transactional import and compatibility projection for legacy JSON stores.

Legacy JSON is preservation input and provenance evidence only. Every value
that controls inventory or lifecycle is written into a normalized column or
child row before SQLite can become authoritative.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile
import time
from typing import Any, Callable, Generator, Iterable, Mapping, Sequence
import uuid

from .schema import invariant_violations
from .store import (
    AccountStore,
    canonical_json,
    deterministic_id,
    ensure_private_store_directory,
    fingerprint,
    refuse_symlink_components,
    utc_timestamp,
)


MAX_LEGACY_STATE_BYTES = 128 * 1024 * 1024
LEGACY_CONFLICT_CLASSIFIER_VERSION = 2
RECLASSIFIABLE_CONFLICT_KINDS = frozenset(
    {
        "server_definition_conflict",
        "assignment_identity_conflict",
        "host_port_conflict",
    }
)


class LegacyImportError(RuntimeError):
    """Legacy source cannot be safely normalized."""


class LegacySourceChanged(LegacyImportError):
    """A source changed after its checksummed capture."""


@dataclass(frozen=True)
class ImportConflict:
    kind: str
    logical_key: str
    severity: str
    source_id: str | None
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class LegacySourceCapture:
    source_id: str
    home: Path
    state_path: Path
    lock_path: Path
    revision: int
    sha256: str
    byte_size: int
    uid: int
    mode: int
    state: Mapping[str, Any]
    backup_path: Path
    manifest_path: Path
    manifest_sha256: str
    backup_id: str


@dataclass(frozen=True)
class ImportReport:
    dry_run: bool
    committed: bool
    import_ids: tuple[str, ...]
    source_count: int
    repository_count: int
    missing_repository_count: int
    unassigned_count: int
    exact_duplicate_count: int
    conflicts: tuple[ImportConflict, ...]
    destination_generation: str


@dataclass(frozen=True)
class LegacyReconciliationReport:
    attempted: bool
    committed: bool
    source_count: int
    reclassified_count: int
    conflict_count: int
    blocking_conflict_count: int
    destination_generation: str


@dataclass
class _NormalizedPlan:
    host: dict[str, Any]
    normalized_source: dict[str, Any]
    sources: list[dict[str, Any]] = field(default_factory=list)
    repositories: dict[str, dict[str, Any]] = field(default_factory=dict)
    installations: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_resources: list[dict[str, Any]] = field(default_factory=list)
    server_definitions: dict[str, dict[str, Any]] = field(default_factory=dict)
    server_arguments: list[tuple[str, int, str]] = field(default_factory=list)
    server_environment: list[tuple[str, str, str]] = field(default_factory=list)
    server_source_records: list[dict[str, Any]] = field(default_factory=list)
    server_observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    control_bindings: list[dict[str, Any]] = field(default_factory=list)
    memberships: list[dict[str, Any]] = field(default_factory=list)
    startup_policies: list[dict[str, Any]] = field(default_factory=list)
    assignments: list[dict[str, Any]] = field(default_factory=list)
    leases: list[dict[str, Any]] = field(default_factory=list)
    operations: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    docker_engines: dict[str, dict[str, Any]] = field(default_factory=dict)
    docker_resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    docker_claims: list[dict[str, Any]] = field(default_factory=list)
    telemetry_samples: list[dict[str, Any]] = field(default_factory=list)
    unassigned: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[ImportConflict] = field(default_factory=list)
    exact_duplicate_count: int = 0


def _call_fault(fault_injector: Callable[[str], None] | None, phase: str) -> None:
    if fault_injector is not None:
        fault_injector(phase)


def _ensure_outside_git(path: Path) -> None:
    for candidate in (path, *path.parents):
        marker = candidate / ".git"
        if marker.exists() or marker.is_symlink():
            raise LegacyImportError(
                f"legacy backup root must be outside every Git worktree: {path}"
            )


def _private_regular_file(path: Path, expected_uid: int) -> os.stat_result:
    refuse_symlink_components(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PermissionError(f"legacy state must be a real regular file: {path}")
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"legacy state is owned by uid {metadata.st_uid}, not {expected_uid}: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError(f"legacy state is accessible by group or others: {path}")
    if metadata.st_size > MAX_LEGACY_STATE_BYTES:
        raise LegacyImportError(
            f"legacy state exceeds {MAX_LEGACY_STATE_BYTES} bytes: {path}"
        )
    return metadata


def _read_state_bytes(path: Path, expected_uid: int) -> tuple[bytes, os.stat_result]:
    before = _private_regular_file(path, expected_uid)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise LegacySourceChanged(f"legacy state identity changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = MAX_LEGACY_STATE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_LEGACY_STATE_BYTES:
            raise LegacyImportError(f"legacy state grew beyond size limit: {path}")
        after = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise LegacySourceChanged(f"legacy state changed while reading: {path}")
        return payload, after
    finally:
        os.close(descriptor)


def _write_private_bytes(path: Path, payload: bytes, expected_uid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError(f"backup file did not retain private ownership: {path}")
    finally:
        os.close(descriptor)


@contextmanager
def _source_locks(homes: Sequence[Path], expected_uid: int) -> Generator[None, None, None]:
    with ExitStack() as stack:
        handles = []
        for home in sorted(homes, key=lambda value: str(value)):
            refuse_symlink_components(home)
            metadata = home.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid:
                raise PermissionError(f"legacy coordinator home has unsafe ownership/type: {home}")
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise PermissionError(f"legacy coordinator home must be mode 0700: {home}")
            lock_path = home / "state.lock"
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(lock_path, flags, 0o600)
            handle = stack.enter_context(os.fdopen(descriptor, "a+"))
            lock_metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != expected_uid:
                raise PermissionError(f"legacy source lock is unsafe: {lock_path}")
            os.fchmod(handle.fileno(), 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handles.append(handle)
        try:
            yield
        finally:
            for handle in reversed(handles):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _capture_sources(
    paths: Iterable[str | os.PathLike[str]],
    backup_root: str | os.PathLike[str],
    *,
    expected_uid: int,
    fault_injector: Callable[[str], None] | None,
) -> list[LegacySourceCapture]:
    homes = sorted({Path(path).expanduser().absolute() for path in paths}, key=str)
    if not homes:
        raise LegacyImportError("at least one legacy coordinator home is required")
    root = Path(backup_root).expanduser().absolute()
    _ensure_outside_git(root)
    ensure_private_store_directory(root, expected_uid=expected_uid)
    transaction_root = root / f"legacy-import-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex}"
    transaction_root.mkdir(mode=0o700)
    captures: list[LegacySourceCapture] = []
    with _source_locks(homes, expected_uid):
        _call_fault(fault_injector, "capture.locks_acquired")
        for ordinal, home in enumerate(homes):
            state_path = home / "state.json"
            payload, metadata = _read_state_bytes(state_path, expected_uid)
            source_hash = hashlib.sha256(payload).hexdigest()
            try:
                state = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LegacyImportError(f"legacy state is not valid UTF-8 JSON: {state_path}: {error}") from error
            if not isinstance(state, dict):
                raise LegacyImportError(f"legacy state root must be an object: {state_path}")
            revision = int(state.get("revision") or 0)
            if revision < 0:
                raise LegacyImportError(f"legacy state revision must not be negative: {state_path}")
            source_id = deterministic_id("legacy-source", expected_uid, str(home))
            source_dir = transaction_root / f"source-{ordinal:03d}-{source_id[:8]}"
            source_dir.mkdir(mode=0o700)
            backup_path = source_dir / "state.json"
            _write_private_bytes(backup_path, payload, expected_uid)
            manifest_path = source_dir / "manifest.json"
            manifest = {
                "format": 1,
                "source_id": source_id,
                "source_home": str(home),
                "source_state": str(state_path),
                "source_revision": revision,
                "source_sha256": source_hash,
                "source_bytes": len(payload),
                "source_uid": metadata.st_uid,
                "source_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "backup_state": str(backup_path),
                "captured_at": utc_timestamp(),
            }
            manifest_payload = (canonical_json(manifest) + "\n").encode("utf-8")
            _write_private_bytes(manifest_path, manifest_payload, expected_uid)
            manifest_hash = hashlib.sha256(manifest_payload).hexdigest()
            captures.append(
                LegacySourceCapture(
                    source_id=source_id,
                    home=home,
                    state_path=state_path,
                    lock_path=home / "state.lock",
                    revision=revision,
                    sha256=source_hash,
                    byte_size=len(payload),
                    uid=metadata.st_uid,
                    mode=stat.S_IMODE(metadata.st_mode),
                    state=state,
                    backup_path=backup_path,
                    manifest_path=manifest_path,
                    manifest_sha256=manifest_hash,
                    backup_id=deterministic_id("legacy-backup", source_id, source_hash),
                )
            )
        for capture in captures:
            current, _metadata = _read_state_bytes(capture.state_path, expected_uid)
            if hashlib.sha256(current).hexdigest() != capture.sha256:
                raise LegacySourceChanged(
                    f"legacy source changed before locked capture completed: {capture.state_path}"
                )
        _call_fault(fault_injector, "capture.backups_verified")
    directory_fd = os.open(transaction_root, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return captures


def _local_host_record() -> dict[str, Any]:
    import platform
    import socket

    material = f"{platform.system()}\x1f{platform.node()}\x1f{socket.gethostname()}"
    machine_fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()
    timestamp = utc_timestamp()
    return {
        "host_id": deterministic_id("host", machine_fingerprint),
        "machine_fingerprint": machine_fingerprint,
        "platform": platform.system(),
        "hostname": socket.gethostname(),
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def _strict_repository(raw: Any, host_id: str) -> tuple[dict[str, Any] | None, str | None]:
    if raw is None or not str(raw).strip():
        return None, "ambiguous_control"
    candidate = Path(str(raw)).expanduser()
    if not candidate.is_absolute():
        return None, "not_git"
    if not candidate.exists():
        canonical = Path(os.path.realpath(str(candidate)))
        repo_id = deterministic_id("repository", host_id, str(canonical))
        timestamp = utc_timestamp()
        return {
            "repo_id": repo_id,
            "host_id": host_id,
            "canonical_root": str(canonical),
            "display_name": canonical.name or str(canonical),
            "state": "missing",
            "generation": 0,
            "created_at": timestamp,
            "updated_at": timestamp,
        }, "missing_repo"
    canonical = candidate.resolve(strict=True)
    root: Path | None = None
    for path in (canonical, *canonical.parents):
        marker = path / ".git"
        if marker.is_dir() or marker.is_file():
            root = path
            break
    if root is None:
        return None, "not_git"
    repo_id = deterministic_id("repository", host_id, str(root))
    timestamp = utc_timestamp()
    return {
        "repo_id": repo_id,
        "host_id": host_id,
        "canonical_root": str(root),
        "display_name": root.name or str(root),
        "state": "active",
        "generation": 0,
        "created_at": timestamp,
        "updated_at": timestamp,
    }, None


def _argv(record: Mapping[str, Any]) -> list[str]:
    value = record.get("argv")
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    command = record.get("cmd")
    if isinstance(command, str) and command.strip():
        try:
            return shlex.split(command)
        except ValueError:
            return [command]
    return []


def _definition_payload(record: Mapping[str, Any], repo_id: str, name: str) -> dict[str, Any]:
    environment = record.get("env") or record.get("environment") or {}
    if not isinstance(environment, dict):
        environment = {}
    return {
        "repo_id": repo_id,
        "name": name,
        "role": record.get("role"),
        "cwd": record.get("cwd") or record.get("project"),
        "argv": _argv(record),
        "environment": {str(key): str(value) for key, value in sorted(environment.items())},
        "health_url": record.get("health_url") or record.get("url"),
        "log_path": record.get("log_path"),
    }


def _status(record: Mapping[str, Any]) -> str:
    raw = str(record.get("status") or record.get("state") or "stopped").lower()
    return raw if raw in {"running", "starting", "unhealthy", "failed", "orphaned"} else "stopped"


def _server_record_claims_current(record: Mapping[str, Any]) -> bool:
    """Return whether a legacy row can still describe a current process claim.

    Legacy stores retain stopped run records indefinitely.  Those rows are
    useful provenance, but they are not competing controllers.  Every
    non-stopped lifecycle remains conservative current evidence.  A positive
    PID without a stop marker is also current evidence even when an older
    writer omitted the lifecycle field; import still does not trust that PID
    as an active normalized observation without a fresh listener proof.
    """

    if _status(record) != "stopped":
        return True
    try:
        pid = int(record.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    return pid > 0 and not record.get("stopped_at")


def _server_candidate_recency_key(item: Mapping[str, Any]) -> tuple[str, int, str, str]:
    record = item["record"]
    capture = item["capture"]
    source_resource = item["source_resource"]
    timestamp = str(
        record.get("updated_at")
        or record.get("stopped_at")
        or record.get("started_at")
        or capture.state.get("updated_at")
        or ""
    )
    return (
        timestamp,
        int(capture.revision),
        str(capture.source_id),
        str(source_resource["native_id"]),
    )


def _record_port(record: Mapping[str, Any]) -> int | None:
    try:
        value = int(record.get("port"))
    except (TypeError, ValueError):
        return None
    return value if 1 <= value <= 65535 else None


def _source_resource(
    capture: LegacySourceCapture,
    kind: str,
    native_id: str,
    repo_id: str | None,
    payload: Mapping[str, Any] | Sequence[Any] | Any,
) -> dict[str, Any]:
    payload_hash = fingerprint(payload)
    return {
        "source_resource_id": deterministic_id("source-resource", capture.source_id, kind, native_id),
        "source_id": capture.source_id,
        "resource_kind": kind,
        "native_id": native_id,
        "repo_id": repo_id,
        "payload_sha256": payload_hash,
        "provenance_json": canonical_json(
            {
                "legacy_revision": capture.revision,
                "legacy_source_sha256": capture.sha256,
                "native_id": native_id,
            }
        ),
        "created_at": utc_timestamp(),
    }


def _unassigned(
    plan: _NormalizedPlan,
    *,
    host_id: str,
    source_resource_id: str | None,
    kind: str,
    resource_id: str,
    display_name: str,
    reason: str,
    suggested_root: str | None,
) -> None:
    plan.unassigned.append(
        {
            "unassigned_id": deterministic_id("unassigned", host_id, kind, resource_id, reason),
            "host_id": host_id,
            "source_resource_id": source_resource_id,
            "resource_kind": kind,
            "resource_id": resource_id,
            "display_name": display_name,
            "reason_code": reason,
            "suggested_root": suggested_root,
            "status": "active",
            "created_at": utc_timestamp(),
            "updated_at": utc_timestamp(),
        }
    )


def _register_repository(
    plan: _NormalizedPlan,
    record: dict[str, Any] | None,
    reason: str | None,
    *,
    actor: str,
) -> str | None:
    if record is None:
        return None
    repo_id = str(record["repo_id"])
    existing = plan.repositories.get(repo_id)
    if existing is not None and existing["canonical_root"] != record["canonical_root"]:
        raise LegacyImportError(f"repository id collision for {repo_id}")
    plan.repositories[repo_id] = record
    if repo_id not in plan.installations:
        missing = record["state"] == "missing"
        plan.installations[repo_id] = {
            "repo_id": repo_id,
            "status": "disabled" if missing else "installed",
            "startup_fenced": 1 if missing else 0,
            "generation": 0,
            "operation_id": None,
            "disabled_at": utc_timestamp() if missing else None,
            "reinstalled_at": None,
            "reason": reason if missing else None,
            "actor": actor,
            "updated_at": utc_timestamp(),
        }
    return repo_id


def _normalize_sources(
    captures: Sequence[LegacySourceCapture],
    store: AccountStore,
    *,
    normalized_authority: Mapping[str, Any] | None = None,
) -> _NormalizedPlan:
    host = _local_host_record()
    host_id = str(host["host_id"])
    if normalized_authority is None:
        normalized_source_id = deterministic_id(
            "normalized-account-source", host_id, str(store.path.parent)
        )
        normalized_source = {
            "source_id": normalized_source_id,
            "host_id": host_id,
            # This source represents the normalized database authority, not the
            # legacy JSON home that happens to share its parent directory.
            "canonical_home": str(store.path),
            "state_path": str(store.path),
            "effective_uid": store.expected_uid,
            "status": "imported",
            "captured_revision": None,
            "captured_sha256": None,
            "imported_at": utc_timestamp(),
            "retired_at": None,
            "late_writer_detected_at": None,
            "created_at": utc_timestamp(),
            "updated_at": utc_timestamp(),
        }
    else:
        normalized_source = dict(normalized_authority)
        normalized_source_id = str(normalized_source["source_id"])
        if str(normalized_source["host_id"]) != host_id:
            raise LegacyImportError(
                "committed normalized authority belongs to another host"
            )
    plan = _NormalizedPlan(host=host, normalized_source=normalized_source)
    server_candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    assignment_candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for capture in captures:
        plan.sources.append(
            {
                "source_id": capture.source_id,
                "host_id": host_id,
                "canonical_home": str(capture.home),
                "state_path": str(capture.state_path),
                "effective_uid": capture.uid,
                "status": "imported",
                "captured_revision": capture.revision,
                "captured_sha256": capture.sha256,
                "imported_at": utc_timestamp(),
                "retired_at": None,
                "late_writer_detected_at": None,
                "created_at": utc_timestamp(),
                "updated_at": utc_timestamp(),
            }
        )
        state = capture.state
        servers = state.get("servers") or {}
        if not isinstance(servers, dict):
            plan.conflicts.append(
                ImportConflict("invalid_collection", "servers", "blocking", capture.source_id, {"type": type(servers).__name__})
            )
            servers = {}
        for native_id, value in sorted(servers.items(), key=lambda item: str(item[0])):
            if not isinstance(value, dict):
                plan.conflicts.append(
                    ImportConflict("invalid_server", str(native_id), "blocking", capture.source_id, {"type": type(value).__name__})
                )
                continue
            record: Mapping[str, Any] = value
            name = str(record.get("name") or native_id)
            repository, reason = _strict_repository(record.get("project") or record.get("cwd"), host_id)
            repo_id = _register_repository(plan, repository, reason, actor="legacy-import")
            source_resource = _source_resource(capture, "server", str(native_id), repo_id, record)
            plan.source_resources.append(source_resource)
            if repo_id is None or reason is not None:
                _unassigned(
                    plan,
                    host_id=host_id,
                    source_resource_id=source_resource["source_resource_id"],
                    kind="server",
                    resource_id=str(native_id),
                    display_name=name,
                    reason=reason or "ambiguous_control",
                    suggested_root=str(record.get("project") or record.get("cwd") or "") or None,
                )
                if repo_id is None:
                    continue
            definition = _definition_payload(record, repo_id, name)
            definition_fingerprint = fingerprint(definition)
            server_candidates.setdefault((repo_id, name), []).append(
                {
                    "capture": capture,
                    "record": record,
                    "source_resource": source_resource,
                    "definition": definition,
                    "definition_fingerprint": definition_fingerprint,
                }
            )

        assignments = state.get("port_assignments") or {}
        if not isinstance(assignments, dict):
            plan.conflicts.append(
                ImportConflict("invalid_collection", "port_assignments", "blocking", capture.source_id, {"type": type(assignments).__name__})
            )
            assignments = {}
        for native_id, value in sorted(assignments.items(), key=lambda item: str(item[0])):
            if not isinstance(value, dict):
                continue
            project = value.get("project")
            name = str(value.get("name") or str(native_id).rsplit("::", 1)[-1])
            repository, reason = _strict_repository(project, host_id)
            repo_id = _register_repository(plan, repository, reason, actor="legacy-import")
            source_resource = _source_resource(capture, "port_assignment", str(native_id), repo_id, value)
            plan.source_resources.append(source_resource)
            if repo_id is None:
                _unassigned(
                    plan,
                    host_id=host_id,
                    source_resource_id=source_resource["source_resource_id"],
                    kind="port_assignment",
                    resource_id=str(native_id),
                    display_name=name,
                    reason=reason or "ambiguous_control",
                    suggested_root=str(project or "") or None,
                )
                continue
            try:
                port = int(value.get("port"))
            except (TypeError, ValueError):
                plan.conflicts.append(
                    ImportConflict("invalid_port", f"{repo_id}:{name}", "blocking", capture.source_id, {"port": value.get("port")})
                )
                continue
            if not 1 <= port <= 65535:
                plan.conflicts.append(
                    ImportConflict("invalid_port", f"{repo_id}:{name}", "blocking", capture.source_id, {"port": port})
                )
                continue
            assignment_candidates.setdefault((repo_id, name), []).append(
                {
                    "capture": capture,
                    "native_id": str(native_id),
                    "source_resource": source_resource,
                    "repo_id": repo_id,
                    "name": name,
                    "port": port,
                    "missing": repository is not None and repository["state"] == "missing",
                    "value": value,
                }
            )

        _normalize_leases(plan, capture, host_id)
        _normalize_operations_and_events(plan, capture, host_id)
        _normalize_docker(plan, capture, host_id)

    _finalize_servers(plan, server_candidates, normalized_source_id)
    _finalize_assignments(plan, assignment_candidates, server_candidates)
    _finalize_docker_claims(plan, host_id)
    return plan


def _finalize_servers(
    plan: _NormalizedPlan,
    candidates_by_key: Mapping[tuple[str, str], Sequence[dict[str, Any]]],
    normalized_source_id: str,
) -> None:
    for (repo_id, name), candidates in sorted(candidates_by_key.items()):
        ordered = sorted(
            candidates,
            key=lambda item: (item["capture"].source_id, item["source_resource"]["native_id"]),
        )
        fingerprints = {str(item["definition_fingerprint"]) for item in ordered}
        current = [
            item for item in ordered if _server_record_claims_current(item["record"])
        ]
        current_fingerprints = {
            str(item["definition_fingerprint"]) for item in current
        }
        blocking = len(current_fingerprints) > 1
        exact = len(fingerprints) == 1
        if exact:
            plan.exact_duplicate_count += max(0, len(ordered) - 1)
        else:
            plan.conflicts.append(
                ImportConflict(
                    "server_definition_conflict",
                    f"{repo_id}:{name}",
                    "blocking" if blocking else "warning",
                    ordered[0]["capture"].source_id,
                    {
                        "definition_fingerprints": sorted(fingerprints),
                        "classifier_version": LEGACY_CONFLICT_CLASSIFIER_VERSION,
                        "source_ids": sorted(
                            {str(item["capture"].source_id) for item in ordered}
                        ),
                        "classification": (
                            "concurrent_current_definitions"
                            if blocking
                            else "historical_definition_variation"
                        ),
                        "current_claims": [
                            {
                                "source_id": str(item["capture"].source_id),
                                "native_id": str(item["source_resource"]["native_id"]),
                                "definition_fingerprint": str(
                                    item["definition_fingerprint"]
                                ),
                                "lifecycle": _status(item["record"]),
                                "port": _record_port(item["record"]),
                            }
                            for item in sorted(current, key=_server_candidate_recency_key)
                        ],
                        "historical_claim_count": len(ordered) - len(current),
                    },
                )
            )
        # A single current definition wins over stopped history.  With no
        # current claim, the newest stopped record is the restart candidate;
        # all older definitions remain source provenance.  A contradictory
        # current set is still represented deterministically but receives no
        # lifecycle authority.
        selected = max(current or ordered, key=_server_candidate_recency_key)
        definition = selected["definition"]
        definition_id = deterministic_id("server-definition", repo_id, name)
        now = utc_timestamp()
        plan.server_definitions[definition_id] = {
            "server_definition_id": definition_id,
            "repo_id": repo_id,
            "name": name,
            "role": definition.get("role"),
            "cwd": str(definition.get("cwd") or plan.repositories[repo_id]["canonical_root"]),
            "health_url_template": definition.get("health_url"),
            "log_path": definition.get("log_path"),
            "definition_fingerprint": selected["definition_fingerprint"],
            "generation": 0,
            "created_at": now,
            "updated_at": now,
        }
        for ordinal, argument in enumerate(definition.get("argv") or []):
            plan.server_arguments.append((definition_id, ordinal, str(argument)))
        for env_name, env_value in sorted((definition.get("environment") or {}).items()):
            plan.server_environment.append((definition_id, str(env_name), str(env_value)))
        for item in ordered:
            plan.server_source_records.append(
                {
                    "server_definition_id": definition_id,
                    "source_resource_id": item["source_resource"]["source_resource_id"],
                    "definition_fingerprint": item["definition_fingerprint"],
                    "is_exact_duplicate": 1 if exact else 0,
                }
            )

        observation_item = selected
        record = observation_item["record"]
        pid = record.get("pid")
        try:
            pid_value = int(pid) if pid else None
        except (TypeError, ValueError):
            pid_value = None
        port = record.get("port")
        try:
            port_value = int(port) if port else None
        except (TypeError, ValueError):
            port_value = None
        health = record.get("health") if isinstance(record.get("health"), dict) else {}
        observation_payload = {
            "lifecycle": _status(record),
            "pid": pid_value,
            "process_start_time": record.get("process_start_time") or record.get("pid_start_time"),
            "process_fingerprint": record.get("process_fingerprint") or record.get("process_instance_id"),
            "listener_host": record.get("host") or "127.0.0.1",
            "listener_port": port_value,
            "listener_observable": record.get("identity_observable"),
            "health_classification": health.get("classification") or record.get("health_classification"),
            "health_ok": health.get("ok") if "ok" in health else record.get("health_ok"),
            "stopped_at": record.get("stopped_at"),
            "stopped_reason": record.get("stopped_reason"),
            "sampled_at": record.get("updated_at") or utc_timestamp(),
        }
        if observation_payload["listener_observable"] not in {True, False, 0, 1, None}:
            observation_payload["listener_observable"] = None
        if observation_payload["health_ok"] not in {True, False, 0, 1, None}:
            observation_payload["health_ok"] = None
        plan.server_observations[definition_id] = {
            "server_definition_id": definition_id,
            "source_resource_id": observation_item["source_resource"]["source_resource_id"],
            **observation_payload,
            "observation_fingerprint": fingerprint(observation_payload),
        }
        authority = "conflicting" if blocking else "authoritative"
        binding_id = deterministic_id("control-binding", "server", definition_id)
        plan.control_bindings.append(
            {
                "binding_id": binding_id,
                "repo_id": repo_id,
                "source_resource_id": observation_item["source_resource"]["source_resource_id"],
                "resource_kind": "server",
                "resource_id": definition_id,
                "source_id": (
                    observation_item["capture"].source_id
                    if blocking
                    else normalized_source_id
                ),
                "capability": "lifecycle",
                "provenance": (
                    "legacy_current_conflict"
                    if blocking
                    else "normalized_exact_import"
                    if exact
                    else "normalized_current_import"
                    if current
                    else "normalized_historical_import"
                ),
                "authority_state": authority,
                "priority": 0 if blocking else 100,
                "generation": 0,
                "created_at": now,
                "updated_at": now,
            }
        )
        plan.memberships.append(
            {
                "membership_id": deterministic_id("membership", repo_id, "server", definition_id),
                "repo_id": repo_id,
                "resource_kind": "server",
                "host_resource_id": definition_id,
                "immutable_fingerprint": selected["definition_fingerprint"],
                "control_binding_id": binding_id,
                "created_at": now,
            }
        )
        plan.startup_policies.append(
            {
                "policy_id": deterministic_id("startup-policy", "server", definition_id, "coordinator"),
                "repo_id": repo_id,
                "resource_kind": "server",
                "resource_id": definition_id,
                "policy_kind": "coordinator",
                "current_value": (
                    "disabled"
                    if plan.installations[repo_id]["status"] == "disabled"
                    else "enabled"
                ),
                "desired_disabled_value": "disabled",
                "immutable_fingerprint": selected["definition_fingerprint"],
                "generation": 0,
                "updated_at": now,
            }
        )


def _finalize_assignments(
    plan: _NormalizedPlan,
    candidates_by_key: Mapping[tuple[str, str], Sequence[dict[str, Any]]],
    server_candidates_by_key: Mapping[tuple[str, str], Sequence[dict[str, Any]]],
) -> None:
    selected: list[dict[str, Any]] = []
    identity_blocking_keys: set[tuple[str, str]] = set()
    identity_historical_keys: set[tuple[str, str]] = set()

    def current_server_candidates(key: tuple[str, str]) -> list[dict[str, Any]]:
        return [
            item
            for item in server_candidates_by_key.get(key, ())
            if _server_record_claims_current(item["record"])
        ]

    def assignment_has_current_claim(item: Mapping[str, Any]) -> bool:
        key = (str(item["repo_id"]), str(item["name"]))
        port = int(item["port"])
        return any(
            _record_port(server["record"]) in {None, port}
            for server in current_server_candidates(key)
        )

    def assignment_recency_key(
        item: Mapping[str, Any], key: tuple[str, str]
    ) -> tuple[str, int, str, str]:
        port = int(item["port"])
        matching_servers = [
            server
            for server in server_candidates_by_key.get(key, ())
            if _record_port(server["record"]) == port
        ]
        if matching_servers:
            newest = max(matching_servers, key=_server_candidate_recency_key)
            server_key = _server_candidate_recency_key(newest)
            timestamp = server_key[0]
        else:
            timestamp = str(item["capture"].state.get("updated_at") or "")
        return (
            timestamp,
            int(item["capture"].revision),
            str(item["capture"].source_id),
            str(item["native_id"]),
        )

    for key, candidates in sorted(candidates_by_key.items()):
        ports = {int(item["port"]) for item in candidates}
        current_servers = current_server_candidates(key)
        current_ports = {
            port
            for port in (_record_port(item["record"]) for item in current_servers)
            if port is not None and port in ports
        }
        current_port_unknown = any(
            _record_port(item["record"]) is None for item in current_servers
        )
        if len(ports) != 1:
            blocking = len(current_ports) > 1 or (
                current_port_unknown and bool(current_servers)
            )
            if blocking:
                identity_blocking_keys.add(key)
            elif not current_ports:
                identity_historical_keys.add(key)
            plan.conflicts.append(
                ImportConflict(
                    "assignment_identity_conflict",
                    f"{key[0]}:{key[1]}",
                    "blocking" if blocking else "warning",
                    candidates[0]["capture"].source_id,
                    {
                        "ports": sorted(ports),
                        "classifier_version": LEGACY_CONFLICT_CLASSIFIER_VERSION,
                        "current_ports": sorted(current_ports),
                        "current_port_unknown": current_port_unknown,
                        "classification": (
                            "concurrent_current_assignments"
                            if blocking
                            else "historical_assignment_variation"
                        ),
                    },
                )
            )
        else:
            plan.exact_duplicate_count += max(0, len(candidates) - 1)

        if len(current_ports) == 1:
            selected_port = next(iter(current_ports))
            pool = [item for item in candidates if int(item["port"]) == selected_port]
        else:
            pool = list(candidates)
        selected.append(max(pool, key=lambda item: assignment_recency_key(item, key)))

    selected_by_port: dict[int, list[dict[str, Any]]] = {}
    for item in selected:
        selected_by_port.setdefault(int(item["port"]), []).append(item)
    host_blocking_ports: set[int] = set()
    host_historical_ports: set[int] = set()
    sole_current_key_by_port: dict[int, tuple[str, str]] = {}
    for port, items in sorted(selected_by_port.items()):
        keys = {(str(item["repo_id"]), str(item["name"])) for item in items}
        if len(keys) <= 1:
            continue
        current_keys = {
            (str(item["repo_id"]), str(item["name"]))
            for item in items
            if assignment_has_current_claim(item)
        }
        blocking = len(current_keys) > 1
        if blocking:
            host_blocking_ports.add(port)
        else:
            host_historical_ports.add(port)
            if len(current_keys) == 1:
                sole_current_key_by_port[port] = next(iter(current_keys))
        plan.conflicts.append(
            ImportConflict(
                "host_port_conflict",
                str(port),
                "blocking" if blocking else "warning",
                items[0]["capture"].source_id,
                {
                    "claims": sorted(f"{key[0]}:{key[1]}" for key in keys),
                    "classifier_version": LEGACY_CONFLICT_CLASSIFIER_VERSION,
                    "current_claims": sorted(
                        f"{key[0]}:{key[1]}" for key in current_keys
                    ),
                    "classification": (
                        "concurrent_current_port_claims"
                        if blocking
                        else "historical_port_reuse"
                    ),
                },
            )
        )

    for item in selected:
        key = (str(item["repo_id"]), str(item["name"]))
        port = int(item["port"])
        inactive = (
            bool(item["missing"])
            or key in identity_blocking_keys
            or key in identity_historical_keys
            or port in host_blocking_ports
            or (
                port in host_historical_ports
                and sole_current_key_by_port.get(port) != key
            )
        )
        status = "inactive" if inactive else "active"
        now = utc_timestamp()
        plan.assignments.append(
            {
                "assignment_id": deterministic_id("port-assignment", item["repo_id"], item["name"]),
                "host_id": plan.host["host_id"],
                "repo_id": item["repo_id"],
                "server_name": item["name"],
                "port": item["port"],
                "status": status,
                "generation": 0,
                "deactivated_at": now if status == "inactive" else None,
                "created_at": now,
                "updated_at": now,
            }
        )


def _normalize_leases(plan: _NormalizedPlan, capture: LegacySourceCapture, host_id: str) -> None:
    leases = capture.state.get("leases") or {}
    if not isinstance(leases, dict):
        plan.conflicts.append(
            ImportConflict("invalid_collection", "leases", "blocking", capture.source_id, {"type": type(leases).__name__})
        )
        return
    for native_id, value in sorted(leases.items(), key=lambda item: str(item[0])):
        if not isinstance(value, dict):
            continue
        repository, reason = _strict_repository(value.get("project"), host_id)
        repo_id = _register_repository(plan, repository, reason, actor="legacy-import")
        source_resource = _source_resource(capture, "lease", str(native_id), repo_id, value)
        plan.source_resources.append(source_resource)
        if repo_id is None:
            _unassigned(
                plan,
                host_id=host_id,
                source_resource_id=source_resource["source_resource_id"],
                kind="lease",
                resource_id=str(native_id),
                display_name=f"Port {value.get('port', '?')}",
                reason=reason or "ambiguous_control",
                suggested_root=str(value.get("project") or "") or None,
            )
            continue
        try:
            port = int(value.get("port"))
        except (TypeError, ValueError):
            plan.conflicts.append(
                ImportConflict("invalid_port", f"lease:{native_id}", "blocking", capture.source_id, {"port": value.get("port")})
            )
            continue
        if not 1 <= port <= 65535:
            continue
        legacy_active = not value.get("released_at") and str(value.get("status") or "active") == "active"
        # A legacy PID/lease is never imported as active without a fresh immutable
        # listener proof. Keep it as stale evidence and require reconciliation.
        status = "stale" if legacy_active else "released"
        if legacy_active:
            plan.conflicts.append(
                ImportConflict(
                    "unverified_active_lease",
                    f"{capture.source_id}:{native_id}",
                    "blocking",
                    capture.source_id,
                    {"port": port, "project": str(value.get("project") or "")},
                )
            )
        now = utc_timestamp()
        plan.leases.append(
            {
                "lease_id": deterministic_id("legacy-lease", capture.source_id, native_id),
                "host_id": host_id,
                "repo_id": repo_id,
                "server_definition_id": None,
                "source_id": capture.source_id,
                "port": port,
                "owner": value.get("owner"),
                "agent": value.get("agent"),
                "purpose": value.get("purpose"),
                "status": status,
                "expires_at": value.get("expires_at"),
                "process_fingerprint": value.get("process_fingerprint") or value.get("process_instance_id"),
                "generation": 0,
                "deactivated_at": now,
                "created_at": value.get("created_at") or now,
                "updated_at": now,
            }
        )


def _normalize_operations_and_events(
    plan: _NormalizedPlan,
    capture: LegacySourceCapture,
    host_id: str,
) -> None:
    operations = capture.state.get("operations") or {}
    if isinstance(operations, dict):
        for native_id, value in sorted(operations.items(), key=lambda item: str(item[0])):
            if not isinstance(value, dict):
                continue
            repository, reason = _strict_repository(value.get("project"), host_id)
            repo_id = _register_repository(plan, repository, reason, actor="legacy-import")
            source_resource = _source_resource(capture, "operation", str(native_id), repo_id, value)
            plan.source_resources.append(source_resource)
            raw_status = str(value.get("status") or "failed").lower()
            status_map = {
                "pending": "running",
                "completed": "succeeded",
                "success": "succeeded",
                "error": "failed",
            }
            status_value = status_map.get(raw_status, raw_status)
            if status_value not in {"planned", "running", "succeeded", "failed", "partial", "cancelled"}:
                status_value = "failed"
            operation_id = deterministic_id("legacy-operation", capture.source_id, native_id)
            now = utc_timestamp()
            plan.operations.append(
                {
                    "operation_id": operation_id,
                    "repo_id": repo_id,
                    "source_id": capture.source_id,
                    "kind": str(value.get("kind") or value.get("action") or "legacy"),
                    "status": status_value,
                    "phase": str(value.get("phase") or raw_status),
                    "generation": int(value.get("generation") or 0),
                    "request_fingerprint": fingerprint(value),
                    "owner_uid": capture.uid,
                    "actor": str(value.get("agent") or value.get("owner") or "legacy-import"),
                    "process_fingerprint": value.get("owner_process_instance"),
                    "error_code": value.get("error_code"),
                    "error_message": value.get("error") if isinstance(value.get("error"), str) else None,
                    "result_json": canonical_json({"legacy_payload_sha256": fingerprint(value)}),
                    "created_at": value.get("created_at") or now,
                    "updated_at": value.get("updated_at") or now,
                }
            )
            if raw_status == "pending":
                plan.conflicts.append(
                    ImportConflict(
                        "pending_operation",
                        f"{capture.source_id}:{native_id}",
                        "blocking",
                        capture.source_id,
                        {"operation_id": operation_id},
                    )
                )

    history = capture.state.get("history") or []
    if isinstance(history, list):
        for ordinal, value in enumerate(history):
            if not isinstance(value, dict):
                continue
            repository, _reason = _strict_repository(value.get("project"), host_id)
            repo_id = _register_repository(plan, repository, _reason, actor="legacy-import")
            plan.events.append(
                {
                    "event_id": deterministic_id("legacy-event", capture.source_id, ordinal, fingerprint(value)),
                    "repo_id": repo_id,
                    "source_id": capture.source_id,
                    "operation_id": None,
                    "event_kind": str(value.get("type") or value.get("kind") or "legacy"),
                    "code": value.get("code"),
                    "message": str(value.get("message") or value.get("action") or "Imported legacy event"),
                    "diagnostic_json": canonical_json({"legacy_payload_sha256": fingerprint(value)}),
                    "occurred_at": value.get("at") or value.get("created_at") or utc_timestamp(),
                }
            )


def _normalize_docker(plan: _NormalizedPlan, capture: LegacySourceCapture, host_id: str) -> None:
    docker = capture.state.get("docker") or {}
    if not isinstance(docker, dict):
        return
    metadata = docker.get("metadata") or {}
    if isinstance(metadata, dict):
        engine_id = deterministic_id("docker-engine", host_id, "legacy-default")
        plan.docker_engines.setdefault(
            engine_id,
            {
                "engine_id": engine_id,
                "host_id": host_id,
                "context_identity": "legacy-default",
                "daemon_identity": None,
                "socket_identity": None,
                "capability_state": "unobserved",
                "created_at": utc_timestamp(),
                "updated_at": utc_timestamp(),
            },
        )
        for native_id, value in sorted(metadata.items(), key=lambda item: str(item[0])):
            if not isinstance(value, dict):
                continue
            repository, reason = _strict_repository(value.get("project"), host_id)
            repo_id = _register_repository(plan, repository, reason, actor="legacy-import")
            source_resource = _source_resource(capture, "container", str(native_id), repo_id, value)
            plan.source_resources.append(source_resource)
            immutable_id = str(value.get("container_id") or value.get("id") or "")
            is_full_id = len(immutable_id) == 64 and all(character in "0123456789abcdefABCDEF" for character in immutable_id)
            if not is_full_id:
                _unassigned(
                    plan,
                    host_id=host_id,
                    source_resource_id=source_resource["source_resource_id"],
                    kind="container",
                    resource_id=str(native_id),
                    display_name=str(value.get("name") or native_id),
                    reason=reason or ("ambiguous_control" if repo_id is None else "stale_observation"),
                    suggested_root=str(value.get("project") or "") or None,
                )
                continue
            docker_resource_id = deterministic_id("docker-resource", engine_id, immutable_id.lower())
            now = utc_timestamp()
            plan.docker_resources.setdefault(
                docker_resource_id,
                {
                    "docker_resource_id": docker_resource_id,
                    "engine_id": engine_id,
                    "full_container_id": immutable_id.lower(),
                    "current_name": str(value.get("name") or native_id),
                    "image": value.get("image"),
                    "created_at": now,
                    "updated_at": now,
                },
            )
            claim_id = deterministic_id("docker-claim", capture.source_id, native_id, immutable_id)
            plan.docker_claims.append(
                {
                    "claim_id": claim_id,
                    "docker_resource_id": docker_resource_id,
                    "source_resource_id": source_resource["source_resource_id"],
                    "repo_id": repo_id,
                    "source_id": capture.source_id,
                    "provenance": "legacy",
                    "priority": 0,
                    "conflict_state": "clear" if repo_id is not None and reason is None else "conflicting",
                    "created_at": now,
                    "updated_at": now,
                }
            )
            if repo_id is not None and reason is None:
                binding_id = deterministic_id("control-binding", "container", docker_resource_id)
                if not any(item["binding_id"] == binding_id for item in plan.control_bindings):
                    plan.control_bindings.append(
                        {
                            "binding_id": binding_id,
                            "repo_id": repo_id,
                            "source_resource_id": source_resource["source_resource_id"],
                            "resource_kind": "container",
                            "resource_id": docker_resource_id,
                            "source_id": capture.source_id,
                            "capability": "lifecycle",
                            "provenance": "legacy_sidecar",
                            "authority_state": "authoritative",
                            "priority": 50,
                            "generation": 0,
                            "created_at": now,
                            "updated_at": now,
                        }
                    )
                    plan.memberships.append(
                        {
                            "membership_id": deterministic_id("membership", repo_id, "container", docker_resource_id),
                            "repo_id": repo_id,
                            "resource_kind": "container",
                            "host_resource_id": docker_resource_id,
                            "immutable_fingerprint": fingerprint({"engine": engine_id, "container": immutable_id.lower()}),
                            "control_binding_id": binding_id,
                            "created_at": now,
                        }
                    )
            restart_policy = value.get("restart_policy")
            if restart_policy is not None:
                plan.startup_policies.append(
                    {
                        "policy_id": deterministic_id("startup-policy", "container", docker_resource_id, "docker_restart"),
                        "repo_id": repo_id,
                        "resource_kind": "container",
                        "resource_id": docker_resource_id,
                        "policy_kind": "docker_restart",
                        "current_value": str(restart_policy),
                        "desired_disabled_value": "no",
                        "immutable_fingerprint": fingerprint({"container": immutable_id.lower(), "restart": restart_policy}),
                        "generation": 0,
                        "updated_at": now,
                    }
                )

    histories = docker.get("stats_history") or {}
    if isinstance(histories, dict):
        for resource_id, samples in histories.items():
            if not isinstance(samples, list):
                continue
            for ordinal, sample in enumerate(samples):
                if not isinstance(sample, dict):
                    continue
                sampled_at = str(sample.get("sampled_at") or sample.get("at") or ordinal)
                def nonnegative_int(*names: str) -> int | None:
                    for name in names:
                        if sample.get(name) is not None:
                            try:
                                return max(0, int(sample[name]))
                            except (TypeError, ValueError):
                                return None
                    return None
                try:
                    cpu = float(sample.get("cpu_percent")) if sample.get("cpu_percent") is not None else None
                except (TypeError, ValueError):
                    cpu = None
                plan.telemetry_samples.append(
                    {
                        "sample_id": deterministic_id("telemetry", "docker", resource_id, sampled_at),
                        "host_resource_kind": "docker",
                        "host_resource_id": str(resource_id),
                        "sampled_at": sampled_at,
                        "cpu_percent": cpu,
                        "memory_bytes": nonnegative_int("memory_bytes", "memory_usage"),
                        "network_rx_bytes": nonnegative_int("network_rx_bytes", "network_rx"),
                        "network_tx_bytes": nonnegative_int("network_tx_bytes", "network_tx"),
                        "block_read_bytes": nonnegative_int("block_read_bytes", "block_read"),
                        "block_write_bytes": nonnegative_int("block_write_bytes", "block_write"),
                    }
                )


def _finalize_docker_claims(plan: _NormalizedPlan, host_id: str) -> None:
    """Collapse immutable Docker identity conflicts without choosing an owner.

    A full daemon/container identity denotes one physical resource. When two
    exact Git worktrees claim it, source order must not decide which repository
    can stop or remove it. Retain every provenance claim, remove repository
    lifecycle authority, and project one non-actionable unassigned resource.
    """

    claims_by_resource: dict[str, list[dict[str, Any]]] = {}
    for claim in plan.docker_claims:
        claims_by_resource.setdefault(str(claim["docker_resource_id"]), []).append(claim)

    for resource_id, claims in sorted(claims_by_resource.items()):
        exact_repo_ids = {
            str(claim["repo_id"])
            for claim in claims
            if claim.get("repo_id") is not None and claim.get("conflict_state") == "clear"
        }
        if len(exact_repo_ids) <= 1:
            continue

        for claim in claims:
            claim["conflict_state"] = "conflicting"
        plan.control_bindings = [
            binding
            for binding in plan.control_bindings
            if not (
                binding.get("resource_kind") == "container"
                and binding.get("resource_id") == resource_id
            )
        ]
        plan.memberships = [
            membership
            for membership in plan.memberships
            if not (
                membership.get("resource_kind") == "container"
                and membership.get("host_resource_id") == resource_id
            )
        ]
        for policy in plan.startup_policies:
            if (
                policy.get("resource_kind") == "container"
                and policy.get("resource_id") == resource_id
            ):
                policy["repo_id"] = None

        resource = plan.docker_resources[resource_id]
        source_resource_id = min(
            str(claim["source_resource_id"]) for claim in claims
        )
        plan.unassigned = [
            item
            for item in plan.unassigned
            if not (
                item.get("resource_kind") == "container"
                and item.get("resource_id") == resource_id
            )
        ]
        _unassigned(
            plan,
            host_id=host_id,
            source_resource_id=source_resource_id,
            kind="container",
            resource_id=resource_id,
            display_name=str(resource["current_name"]),
            reason="conflicting_claims",
            suggested_root=None,
        )
        sorted_repos = sorted(exact_repo_ids)
        plan.conflicts.append(
            ImportConflict(
                "docker_repository_claim_conflict",
                resource_id,
                "blocking",
                None,
                {
                    "docker_resource_id": resource_id,
                    "full_container_id": resource["full_container_id"],
                    "repo_ids": sorted_repos,
                    "claim_ids": sorted(str(claim["claim_id"]) for claim in claims),
                },
            )
        )


def _insert_record(connection: Any, table: str, record: Mapping[str, Any], *, ignore: bool = True) -> None:
    columns = tuple(record.keys())
    verb = "INSERT OR IGNORE" if ignore else "INSERT"
    sql = (
        f"{verb} INTO {table} ({', '.join(columns)}) VALUES "
        f"({', '.join('?' for _ in columns)})"
    )
    if not ignore and len(columns) > 1:
        sql += " ON CONFLICT DO UPDATE SET " + ", ".join(
            f"{column} = excluded.{column}" for column in columns[1:]
        )
    connection.execute(sql, tuple(record[column] for column in columns))


def _write_plan(
    connection: Any,
    plan: _NormalizedPlan,
    captures: Sequence[LegacySourceCapture],
    *,
    record_imports: bool = True,
    upsert: bool = False,
) -> tuple[str, ...]:
    _insert_record(connection, "hosts", plan.host, ignore=not upsert)
    _insert_record(connection, "coordinator_sources", plan.normalized_source, ignore=not upsert)
    for source in plan.sources:
        _insert_record(connection, "coordinator_sources", source, ignore=not upsert)
    for repository in plan.repositories.values():
        _insert_record(connection, "repositories", repository, ignore=not upsert)
    for source_resource in plan.source_resources:
        _insert_record(connection, "source_resources", source_resource, ignore=not upsert)
    for definition in plan.server_definitions.values():
        _insert_record(connection, "server_definitions", definition, ignore=not upsert)
    for definition_id, ordinal, argument in plan.server_arguments:
        connection.execute(
            "INSERT OR IGNORE INTO server_command_arguments VALUES (?, ?, ?)",
            (definition_id, ordinal, argument),
        )
    for definition_id, name, value in plan.server_environment:
        connection.execute(
            "INSERT OR IGNORE INTO server_environment VALUES (?, ?, ?)",
            (definition_id, name, value),
        )
    for record in plan.server_source_records:
        _insert_record(connection, "server_source_records", record)
    for record in plan.server_observations.values():
        _insert_record(connection, "server_observations", record, ignore=not upsert)
    for record in plan.control_bindings:
        _insert_record(connection, "control_bindings", record)
    for record in plan.memberships:
        _insert_record(connection, "repository_memberships", record)
    for record in plan.startup_policies:
        _insert_record(connection, "startup_policies", record)
    for record in plan.assignments:
        _insert_record(connection, "port_assignments", record)
    for record in plan.leases:
        _insert_record(connection, "leases", record)
    for record in plan.operations:
        _insert_record(connection, "operations", record)
    for installation in plan.installations.values():
        # A compatibility projection may refresh installed repositories, but
        # must never clear an explicit disabling/disabled fence.
        if upsert:
            existing = connection.execute(
                "SELECT status FROM repository_installations WHERE repo_id = ?",
                (installation["repo_id"],),
            ).fetchone()
            if existing is not None and str(existing[0]) in {"disabling", "disabled"}:
                continue
        _insert_record(connection, "repository_installations", installation, ignore=not upsert)
    for record in plan.events:
        _insert_record(connection, "events", record)
    for record in plan.docker_engines.values():
        _insert_record(connection, "docker_engines", record)
    for record in plan.docker_resources.values():
        _insert_record(connection, "docker_resources", record)
    for record in plan.docker_claims:
        _insert_record(connection, "docker_ownership_claims", record)
    for record in plan.telemetry_samples:
        _insert_record(connection, "telemetry_samples", record)
    for record in plan.unassigned:
        _insert_record(connection, "unassigned_resources", record)

    if not record_imports:
        connection.execute(
            "UPDATE schema_metadata SET migration_state = 'ready', updated_at = ? WHERE singleton = 1",
            (utc_timestamp(),),
        )
        return ()

    generation = str(
        connection.execute(
            "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
        ).fetchone()[0]
    )
    import_ids: list[str] = []
    import_by_source: dict[str, str] = {}
    for capture in captures:
        backup_evidence = {
            "backup_id": capture.backup_id,
            "repo_id": None,
            "source_id": capture.source_id,
            "manifest_path": str(capture.manifest_path),
            "manifest_sha256": capture.manifest_sha256,
            "verification_status": "verified",
            "created_at": utc_timestamp(),
            "verified_at": utc_timestamp(),
        }
        _insert_record(connection, "backup_evidence", backup_evidence)
        import_id = deterministic_id("legacy-import", capture.source_id, capture.sha256)
        import_by_source[capture.source_id] = import_id
        import_ids.append(import_id)
        _insert_record(
            connection,
            "legacy_imports",
            {
                "import_id": import_id,
                "source_id": capture.source_id,
                "source_path_digest": hashlib.sha256(str(capture.state_path).encode("utf-8")).hexdigest(),
                "source_revision": capture.revision,
                "source_sha256": capture.sha256,
                "backup_id": capture.backup_id,
                "destination_generation": generation,
                "phase": "committed",
                "committed_at": utc_timestamp(),
                "created_at": utc_timestamp(),
            },
        )
    fallback_import = import_ids[0] if import_ids else None
    for conflict in plan.conflicts:
        import_id = import_by_source.get(str(conflict.source_id)) or fallback_import
        if import_id is None:
            continue
        _insert_record(
            connection,
            "migration_conflicts",
            {
                "conflict_id": deterministic_id("migration-conflict", import_id, conflict.kind, conflict.logical_key),
                "import_id": import_id,
                "source_id": conflict.source_id,
                "conflict_kind": conflict.kind,
                "logical_key": conflict.logical_key,
                "severity": conflict.severity,
                "disposition": "open",
                "evidence_json": canonical_json(dict(conflict.evidence)),
                "created_at": utc_timestamp(),
                "resolved_at": None,
            },
        )
    connection.execute(
        """
        UPDATE schema_metadata
        SET migration_state = ?, updated_at = ?
        WHERE singleton = 1
        """,
        (
            "conflicted"
            if connection.execute(
                """
                SELECT 1 FROM migration_conflicts
                WHERE disposition='open' AND severity='blocking' LIMIT 1
                """
            ).fetchone()
            is not None
            else "ready",
            utc_timestamp(),
        ),
    )
    return tuple(import_ids)


def _verify_captures(captures: Sequence[LegacySourceCapture], expected_uid: int) -> None:
    for capture in captures:
        payload, _metadata = _read_state_bytes(capture.state_path, expected_uid)
        current_hash = hashlib.sha256(payload).hexdigest()
        try:
            current_state = json.loads(payload.decode("utf-8"))
            current_revision = int(current_state.get("revision") or 0)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as error:
            raise LegacySourceChanged(f"legacy source is no longer valid: {capture.state_path}") from error
        if current_hash != capture.sha256 or current_revision != capture.revision:
            raise LegacySourceChanged(
                f"legacy source changed after capture: {capture.state_path}; "
                f"expected revision/hash {capture.revision}/{capture.sha256}, "
                f"got {current_revision}/{current_hash}"
            )


def import_legacy_homes(
    store: AccountStore,
    paths: Iterable[str | os.PathLike[str]],
    backup_root: str | os.PathLike[str],
    *,
    dry_run: bool = False,
    fault_injector: Callable[[str], None] | None = None,
) -> ImportReport:
    """Capture, normalize, verify and atomically import same-UID JSON homes."""

    captures = _capture_sources(
        paths,
        backup_root,
        expected_uid=store.expected_uid,
        fault_injector=fault_injector,
    )
    _call_fault(fault_injector, "import.capture_complete")
    plan = _normalize_sources(captures, store)
    _call_fault(fault_injector, "import.plan_complete")
    destination_generation = store.metadata.database_generation
    if dry_run:
        return ImportReport(
            dry_run=True,
            committed=False,
            import_ids=(),
            source_count=len(captures),
            repository_count=len(plan.repositories),
            missing_repository_count=sum(1 for item in plan.repositories.values() if item["state"] == "missing"),
            unassigned_count=len(plan.unassigned),
            exact_duplicate_count=plan.exact_duplicate_count,
            conflicts=tuple(plan.conflicts),
            destination_generation=destination_generation,
        )

    homes = [capture.home for capture in captures]
    with _source_locks(homes, store.expected_uid):
        _verify_captures(captures, store.expected_uid)
        _call_fault(fault_injector, "import.sources_reverified")
        with store.immediate_transaction(max_seconds=30.0) as connection:
            _call_fault(fault_injector, "import.transaction_started")
            import_ids = _write_plan(connection, plan, captures)
            _call_fault(fault_injector, "import.rows_written")
            violations = invariant_violations(connection)
            if violations:
                detail = "; ".join(f"{item.code}:{item.detail}" for item in violations)
                raise LegacyImportError(f"legacy import violates normalized invariants: {detail}")
            _call_fault(fault_injector, "import.invariants_passed")
            _call_fault(fault_injector, "import.before_commit")
    _call_fault(fault_injector, "import.after_commit")
    return ImportReport(
        dry_run=False,
        committed=True,
        import_ids=import_ids,
        source_count=len(captures),
        repository_count=len(plan.repositories),
        missing_repository_count=sum(1 for item in plan.repositories.values() if item["state"] == "missing"),
        unassigned_count=len(plan.unassigned),
        exact_duplicate_count=plan.exact_duplicate_count,
        conflicts=tuple(plan.conflicts),
        destination_generation=destination_generation,
    )


def _legacy_import_rows(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT li.import_id, li.source_id, li.source_revision,
                   li.source_sha256, li.backup_id, li.destination_generation,
                   li.phase, s.host_id, s.canonical_home, s.state_path,
                   s.effective_uid,
                   b.manifest_path, b.manifest_sha256, b.verification_status
            FROM legacy_imports li
            JOIN coordinator_sources s USING(source_id)
            JOIN backup_evidence b USING(backup_id)
            WHERE li.phase IN ('committed', 'late_writer')
            ORDER BY li.source_id, li.import_id
            """
        )
    ]


def _require_import_destination_generation(
    rows: Sequence[Mapping[str, Any]],
    expected_generation: str,
    *,
    changed_during_reconciliation: bool = False,
) -> None:
    mismatches = sorted(
        {
            str(row["destination_generation"])
            for row in rows
            if str(row["destination_generation"]) != expected_generation
        }
    )
    if not mismatches:
        return
    if changed_during_reconciliation:
        raise LegacySourceChanged(
            "legacy import destination generation changed during conflict "
            f"reconciliation: expected {expected_generation}, got {mismatches}"
        )
    raise LegacyImportError(
        "legacy import evidence belongs to another database generation: "
        f"expected {expected_generation}, got {mismatches}"
    )


def _committed_normalized_authority(
    connection: Any,
    import_rows: Sequence[Mapping[str, Any]],
    *,
    expected_uid: int,
) -> dict[str, Any]:
    host_ids = {str(row["host_id"]) for row in import_rows}
    if len(host_ids) != 1:
        raise LegacyImportError(
            "committed legacy imports do not identify exactly one host"
        )
    host_id = next(iter(host_ids))
    authorities = [
        dict(row)
        for row in connection.execute(
            """
            SELECT source_id, host_id, canonical_home, state_path,
                   effective_uid, status, captured_revision, captured_sha256,
                   imported_at, retired_at, late_writer_detected_at,
                   created_at, updated_at
            FROM coordinator_sources
            WHERE host_id = ? AND captured_sha256 IS NULL
            ORDER BY source_id
            """,
            (host_id,),
        )
    ]
    if len(authorities) != 1:
        raise LegacyImportError(
            "committed legacy imports do not have exactly one normalized authority"
        )
    authority = authorities[0]
    state_path = Path(str(authority["state_path"]))
    expected_source_id = deterministic_id(
        "normalized-account-source", host_id, str(state_path.parent)
    )
    if (
        int(authority["effective_uid"]) != int(expected_uid)
        or str(authority["status"]) != "imported"
        or authority["captured_revision"] is not None
        or str(authority["canonical_home"]) != str(state_path)
        or not state_path.is_absolute()
        or str(authority["source_id"]) != expected_source_id
    ):
        raise LegacyImportError(
            "committed normalized authority identity is invalid"
        )
    return authority


def _load_committed_import_captures(
    rows: Sequence[Mapping[str, Any]], expected_uid: int
) -> list[LegacySourceCapture]:
    """Reload the immutable, checksummed backups used by a committed import.

    Reclassification deliberately does not trust the mutable legacy source.
    The original manifest and copied state are the evidence that produced the
    normalized rows being repaired.
    """

    captures: list[LegacySourceCapture] = []
    for row in rows:
        if str(row["verification_status"]) != "verified":
            raise LegacyImportError(
                f"legacy import backup is not verified: {row['backup_id']}"
            )
        manifest_path = Path(str(row["manifest_path"]))
        if not manifest_path.is_absolute():
            raise LegacyImportError(
                f"legacy import manifest path is not absolute: {manifest_path}"
            )
        manifest_payload, _manifest_metadata = _read_state_bytes(
            manifest_path, expected_uid
        )
        manifest_digest = hashlib.sha256(manifest_payload).hexdigest()
        if manifest_digest != str(row["manifest_sha256"]):
            raise LegacyImportError(
                f"legacy import manifest checksum changed: {manifest_path}"
            )
        try:
            manifest = json.loads(manifest_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LegacyImportError(
                f"legacy import manifest is invalid: {manifest_path}"
            ) from error
        if not isinstance(manifest, dict):
            raise LegacyImportError(
                f"legacy import manifest root is not an object: {manifest_path}"
            )
        expected_manifest = {
            "source_id": str(row["source_id"]),
            "source_home": str(row["canonical_home"]),
            "source_state": str(row["state_path"]),
            "source_revision": int(row["source_revision"]),
            "source_sha256": str(row["source_sha256"]),
            "source_uid": int(row["effective_uid"]),
        }
        for name, expected in expected_manifest.items():
            if manifest.get(name) != expected:
                raise LegacyImportError(
                    f"legacy import manifest {name} does not match committed evidence: "
                    f"{manifest_path}"
                )
        backup_path = Path(str(manifest.get("backup_state") or ""))
        if not backup_path.is_absolute():
            raise LegacyImportError(
                f"legacy import backup path is not absolute: {backup_path}"
            )
        payload, source_metadata = _read_state_bytes(backup_path, expected_uid)
        if hashlib.sha256(payload).hexdigest() != str(row["source_sha256"]):
            raise LegacyImportError(
                f"legacy import backup checksum changed: {backup_path}"
            )
        try:
            state = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LegacyImportError(
                f"legacy import backup is invalid JSON: {backup_path}"
            ) from error
        if not isinstance(state, dict) or int(state.get("revision") or 0) != int(
            row["source_revision"]
        ):
            raise LegacyImportError(
                f"legacy import backup revision does not match committed evidence: {backup_path}"
            )
        source_home = Path(str(row["canonical_home"]))
        source_path = Path(str(row["state_path"]))
        captures.append(
            LegacySourceCapture(
                source_id=str(row["source_id"]),
                home=source_home,
                state_path=source_path,
                lock_path=source_home / "state.lock",
                revision=int(row["source_revision"]),
                sha256=str(row["source_sha256"]),
                byte_size=len(payload),
                uid=int(row["effective_uid"]),
                mode=stat.S_IMODE(source_metadata.st_mode),
                state=state,
                backup_path=backup_path,
                manifest_path=manifest_path,
                manifest_sha256=manifest_digest,
                backup_id=str(row["backup_id"]),
            )
        )
    return captures


def reconcile_imported_legacy_conflicts(
    store: AccountStore,
) -> LegacyReconciliationReport:
    """Reclassify old import conflicts from their immutable backup evidence.

    Version-one import treated every retained server row and durable assignment
    as a simultaneous claim.  A conflicted store fenced all later lifecycle
    mutations, so this migration may safely replace only classifier-owned
    generation-zero catalog rows.  It never deletes source provenance,
    operations, history, backups, observations outside the affected logical
    servers, or user-created normalized state.
    """

    destination_generation = store.metadata.database_generation
    normalized_authority: dict[str, Any] | None = None
    with store.read_transaction() as connection:
        metadata = connection.execute(
            """
            SELECT migration_state, state_revision, database_generation
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        open_conflicts = [
            dict(row)
            for row in connection.execute(
                """
                SELECT conflict_id, import_id, source_id, conflict_kind,
                       logical_key, severity, disposition, evidence_json
                FROM migration_conflicts
                WHERE disposition = 'open'
                  AND conflict_kind IN (
                      'server_definition_conflict',
                      'assignment_identity_conflict',
                      'host_port_conflict'
                  )
                ORDER BY conflict_kind, logical_key, conflict_id
                """
            )
        ]
        import_rows = _legacy_import_rows(connection)
        if (
            metadata is not None
            and str(metadata["migration_state"]) == "conflicted"
            and open_conflicts
            and import_rows
        ):
            normalized_authority = _committed_normalized_authority(
                connection,
                import_rows,
                expected_uid=store.expected_uid,
            )
    if metadata is None or str(metadata["migration_state"]) != "conflicted" or not open_conflicts:
        with store.read_transaction() as connection:
            blocking = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM migration_conflicts
                    WHERE disposition='open' AND severity='blocking'
                    """
                ).fetchone()[0]
            )
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM migration_conflicts WHERE disposition='open'"
                ).fetchone()[0]
            )
        return LegacyReconciliationReport(
            attempted=False,
            committed=False,
            source_count=len(import_rows),
            reclassified_count=0,
            conflict_count=total,
            blocking_conflict_count=blocking,
            destination_generation=destination_generation,
        )
    if not import_rows:
        raise LegacyImportError(
            "conflicted legacy migration has no committed backup evidence"
        )
    if any(int(row["effective_uid"]) != store.expected_uid for row in import_rows):
        raise LegacyImportError(
            "legacy import backup evidence belongs to another effective uid"
        )
    current_generation = str(metadata["database_generation"])
    if current_generation != destination_generation:
        raise LegacySourceChanged(
            "normalized database generation changed before conflict reconciliation"
        )
    _require_import_destination_generation(import_rows, current_generation)
    if normalized_authority is None:
        raise LegacyImportError(
            "conflicted legacy migration lacks a normalized authority"
        )

    import_signature = fingerprint(import_rows)
    conflict_signature = fingerprint(open_conflicts)
    authority_signature = fingerprint(normalized_authority)
    captured_state_revision = int(metadata["state_revision"])
    captures = _load_committed_import_captures(import_rows, store.expected_uid)
    plan = _normalize_sources(
        captures,
        store,
        normalized_authority=normalized_authority,
    )
    planned_conflicts = {
        (item.kind, item.logical_key): item
        for item in plan.conflicts
        if item.kind in RECLASSIFIABLE_CONFLICT_KINDS
    }
    plan_definitions_by_key = {
        f"{record['repo_id']}:{record['name']}": record
        for record in plan.server_definitions.values()
    }
    plan_bindings_by_resource = {
        str(record["resource_id"]): record
        for record in plan.control_bindings
        if record["resource_kind"] == "server"
    }
    plan_arguments_by_definition: dict[str, list[tuple[int, str]]] = {}
    for definition_id, ordinal, argument in plan.server_arguments:
        plan_arguments_by_definition.setdefault(definition_id, []).append(
            (ordinal, argument)
        )
    plan_environment_by_definition: dict[str, list[tuple[str, str]]] = {}
    for definition_id, name, value in plan.server_environment:
        plan_environment_by_definition.setdefault(definition_id, []).append(
            (name, value)
        )
    plan_source_records_by_definition: dict[str, list[dict[str, Any]]] = {}
    for record in plan.server_source_records:
        plan_source_records_by_definition.setdefault(
            str(record["server_definition_id"]), []
        ).append(record)
    plan_memberships_by_resource = {
        str(record["host_resource_id"]): record
        for record in plan.memberships
        if record["resource_kind"] == "server"
    }
    plan_policies_by_resource = {
        str(record["resource_id"]): record
        for record in plan.startup_policies
        if record["resource_kind"] == "server"
    }

    server_keys = {
        str(row["logical_key"])
        for row in open_conflicts
        if row["conflict_kind"] == "server_definition_conflict"
    }
    assignment_keys = {
        str(row["logical_key"])
        for row in open_conflicts
        if row["conflict_kind"] == "assignment_identity_conflict"
    }
    affected_ports = {
        int(row["logical_key"])
        for row in open_conflicts
        if row["conflict_kind"] == "host_port_conflict"
    }
    affected_assignment_ids = {
        str(record["assignment_id"])
        for record in plan.assignments
        if f"{record['repo_id']}:{record['server_name']}" in assignment_keys
        or int(record["port"]) in affected_ports
    }
    plan_assignments_by_id = {
        str(record["assignment_id"]): record
        for record in plan.assignments
        if str(record["assignment_id"]) in affected_assignment_ids
    }

    now = utc_timestamp()
    with store.immediate_transaction(max_seconds=30.0) as connection:
        current_metadata = connection.execute(
            """
            SELECT migration_state, state_revision, database_generation
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        current_conflicts = [
            dict(row)
            for row in connection.execute(
                """
                SELECT conflict_id, import_id, source_id, conflict_kind,
                       logical_key, severity, disposition, evidence_json
                FROM migration_conflicts
                WHERE disposition = 'open'
                  AND conflict_kind IN (
                      'server_definition_conflict',
                      'assignment_identity_conflict',
                      'host_port_conflict'
                  )
                ORDER BY conflict_kind, logical_key, conflict_id
                """
            )
        ]
        current_import_rows = _legacy_import_rows(connection)
        _require_import_destination_generation(
            current_import_rows,
            destination_generation,
            changed_during_reconciliation=True,
        )
        current_authority = _committed_normalized_authority(
            connection,
            current_import_rows,
            expected_uid=store.expected_uid,
        )
        if (
            current_metadata is None
            or str(current_metadata["migration_state"]) != "conflicted"
            or int(current_metadata["state_revision"]) != captured_state_revision
            or str(current_metadata["database_generation"]) != destination_generation
            or fingerprint(current_import_rows) != import_signature
            or fingerprint(current_conflicts) != conflict_signature
            or fingerprint(current_authority) != authority_signature
        ):
            raise LegacySourceChanged(
                "normalized migration evidence changed during conflict reconciliation"
            )

        for logical_key in sorted(server_keys):
            definition = plan_definitions_by_key.get(logical_key)
            if definition is None:
                raise LegacyImportError(
                    f"reclassified server definition is missing: {logical_key}"
                )
            definition_id = str(definition["server_definition_id"])
            existing = connection.execute(
                "SELECT generation FROM server_definitions WHERE server_definition_id = ?",
                (definition_id,),
            ).fetchone()
            if existing is None or int(existing["generation"]) != 0:
                raise LegacyImportError(
                    f"reclassified server definition was modified after import: {logical_key}"
                )
            connection.execute(
                """
                UPDATE server_definitions
                SET role = ?, cwd = ?, health_url_template = ?, log_path = ?,
                    definition_fingerprint = ?, updated_at = ?
                WHERE server_definition_id = ?
                """,
                (
                    definition["role"],
                    definition["cwd"],
                    definition["health_url_template"],
                    definition["log_path"],
                    definition["definition_fingerprint"],
                    now,
                    definition_id,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise LegacyImportError(
                    f"reclassified server definition disappeared: {logical_key}"
                )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (definition_id,),
            )
            connection.executemany(
                "INSERT INTO server_command_arguments VALUES (?, ?, ?)",
                [
                    (definition_id, ordinal, argument)
                    for ordinal, argument in sorted(
                        plan_arguments_by_definition.get(definition_id, [])
                    )
                ],
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (definition_id,),
            )
            connection.executemany(
                "INSERT INTO server_environment VALUES (?, ?, ?)",
                [
                    (definition_id, name, value)
                    for name, value in sorted(
                        plan_environment_by_definition.get(definition_id, [])
                    )
                ],
            )
            for source_record in plan_source_records_by_definition.get(
                definition_id, []
            ):
                connection.execute(
                    """
                    UPDATE server_source_records
                    SET definition_fingerprint = ?, is_exact_duplicate = ?
                    WHERE server_definition_id = ? AND source_resource_id = ?
                    """,
                    (
                        source_record["definition_fingerprint"],
                        source_record["is_exact_duplicate"],
                        definition_id,
                        source_record["source_resource_id"],
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LegacyImportError(
                        "reclassified server source provenance disappeared: "
                        f"{logical_key}:{source_record['source_resource_id']}"
                    )
            # Host observations are newer measured truth and deliberately stay
            # untouched. The explicit Observe that invokes this migration will
            # sample them again after the catalog transaction commits.
            binding = plan_bindings_by_resource[definition_id]
            connection.execute(
                """
                UPDATE control_bindings
                SET repo_id = ?, source_resource_id = ?, source_id = ?,
                    provenance = ?, authority_state = ?, priority = ?, updated_at = ?
                WHERE binding_id = ? AND generation = 0
                """,
                (
                    binding["repo_id"],
                    binding["source_resource_id"],
                    binding["source_id"],
                    binding["provenance"],
                    binding["authority_state"],
                    binding["priority"],
                    now,
                    binding["binding_id"],
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise LegacyImportError(
                    f"reclassified server control binding was modified after import: {logical_key}"
                )
            membership = plan_memberships_by_resource[definition_id]
            connection.execute(
                """
                UPDATE repository_memberships
                SET immutable_fingerprint = ?, control_binding_id = ?
                WHERE resource_kind='server' AND host_resource_id = ?
                """,
                (
                    membership["immutable_fingerprint"],
                    membership["control_binding_id"],
                    definition_id,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise LegacyImportError(
                    f"reclassified server membership disappeared: {logical_key}"
                )
            policy = plan_policies_by_resource[definition_id]
            connection.execute(
                """
                UPDATE startup_policies
                SET immutable_fingerprint = ?, updated_at = ?
                WHERE resource_kind='server' AND resource_id = ? AND generation = 0
                """,
                (policy["immutable_fingerprint"], now, definition_id),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise LegacyImportError(
                    f"reclassified server startup policy was modified after import: {logical_key}"
                )

        if affected_assignment_ids:
            placeholders = ",".join("?" for _ in affected_assignment_ids)
            rows = connection.execute(
                f"""
                SELECT assignment_id, generation FROM port_assignments
                WHERE assignment_id IN ({placeholders})
                """,
                tuple(sorted(affected_assignment_ids)),
            ).fetchall()
            if any(int(row["generation"]) != 0 for row in rows):
                raise LegacyImportError(
                    "a reclassified port assignment was modified after import"
                )
            connection.execute(
                f"""
                UPDATE port_assignments
                SET status='inactive', deactivated_at=?, updated_at=?
                WHERE assignment_id IN ({placeholders}) AND generation=0
                """,
                (now, now, *sorted(affected_assignment_ids)),
            )
        for assignment_id, assignment in sorted(plan_assignments_by_id.items()):
            existing = connection.execute(
                "SELECT created_at FROM port_assignments WHERE assignment_id = ?",
                (assignment_id,),
            ).fetchone()
            created_at = (
                str(existing["created_at"])
                if existing is not None
                else str(assignment["created_at"])
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port, status,
                    generation, deactivated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                ON CONFLICT(assignment_id) DO UPDATE SET
                    host_id=excluded.host_id,
                    repo_id=excluded.repo_id,
                    server_name=excluded.server_name,
                    port=excluded.port,
                    status=excluded.status,
                    deactivated_at=excluded.deactivated_at,
                    updated_at=excluded.updated_at
                """,
                (
                    assignment_id,
                    assignment["host_id"],
                    assignment["repo_id"],
                    assignment["server_name"],
                    assignment["port"],
                    assignment["status"],
                    now if assignment["status"] == "inactive" else None,
                    created_at,
                    now,
                ),
            )

        existing_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in current_conflicts:
            existing_by_key.setdefault(
                (str(row["conflict_kind"]), str(row["logical_key"])), []
            ).append(row)
        import_by_source = {
            str(row["source_id"]): str(row["import_id"]) for row in import_rows
        }
        fallback_import = str(import_rows[0]["import_id"])
        for key, rows in existing_by_key.items():
            planned = planned_conflicts.get(key)
            if planned is None:
                for row in rows:
                    evidence = {
                        "classifier_version": LEGACY_CONFLICT_CLASSIFIER_VERSION,
                        "classification": "no_longer_conflicting",
                        "prior_evidence": json.loads(str(row["evidence_json"])),
                    }
                    connection.execute(
                        """
                        UPDATE migration_conflicts
                        SET severity='warning', disposition='resolved',
                            evidence_json=?, resolved_at=?
                        WHERE conflict_id=?
                        """,
                        (canonical_json(evidence), now, row["conflict_id"]),
                    )
            else:
                for row in rows:
                    connection.execute(
                        """
                        UPDATE migration_conflicts
                        SET source_id=?, severity=?, disposition='open',
                            evidence_json=?, resolved_at=NULL
                        WHERE conflict_id=?
                        """,
                        (
                            planned.source_id,
                            planned.severity,
                            canonical_json(dict(planned.evidence)),
                            row["conflict_id"],
                        ),
                    )
        for key, planned in planned_conflicts.items():
            if key in existing_by_key:
                continue
            import_id = import_by_source.get(str(planned.source_id)) or fallback_import
            _insert_record(
                connection,
                "migration_conflicts",
                {
                    "conflict_id": deterministic_id(
                        "migration-conflict",
                        import_id,
                        planned.kind,
                        planned.logical_key,
                    ),
                    "import_id": import_id,
                    "source_id": planned.source_id,
                    "conflict_kind": planned.kind,
                    "logical_key": planned.logical_key,
                    "severity": planned.severity,
                    "disposition": "open",
                    "evidence_json": canonical_json(dict(planned.evidence)),
                    "created_at": now,
                    "resolved_at": None,
                },
            )
        blocking = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM migration_conflicts
                WHERE disposition='open' AND severity='blocking'
                """
            ).fetchone()[0]
        )
        total = int(
            connection.execute(
                "SELECT COUNT(*) FROM migration_conflicts WHERE disposition='open'"
            ).fetchone()[0]
        )
        connection.execute(
            """
            UPDATE schema_metadata SET migration_state = ?, updated_at = ?
            WHERE singleton = 1
            """,
            ("conflicted" if blocking else "ready", now),
        )
        violations = invariant_violations(connection)
        if violations:
            detail = "; ".join(
                f"{item.code}:{item.detail}" for item in violations
            )
            raise LegacyImportError(
                f"legacy conflict reconciliation violates normalized invariants: {detail}"
            )

    return LegacyReconciliationReport(
        attempted=True,
        committed=True,
        source_count=len(captures),
        reclassified_count=len(open_conflicts),
        conflict_count=total,
        blocking_conflict_count=blocking,
        destination_generation=destination_generation,
    )


def load_legacy_state_projection(store: AccountStore) -> dict[str, Any]:
    """Reconstruct the bounded v1 compatibility shape from normalized rows."""

    with store.read_transaction() as connection:
        metadata = connection.execute(
            "SELECT state_revision, created_at, updated_at FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        servers: dict[str, Any] = {}
        definitions = connection.execute(
            """
            SELECT d.*, r.canonical_root
            FROM server_definitions d JOIN repositories r USING(repo_id)
            ORDER BY d.repo_id, d.name
            """
        ).fetchall()
        for definition in definitions:
            source = connection.execute(
                """
                SELECT sr.native_id
                FROM server_source_records ss
                JOIN source_resources sr USING(source_resource_id)
                WHERE ss.server_definition_id = ?
                ORDER BY sr.source_id, sr.native_id LIMIT 1
                """,
                (definition["server_definition_id"],),
            ).fetchone()
            native_id = str(source[0]) if source is not None else str(definition["server_definition_id"])
            arguments = [
                str(row[0])
                for row in connection.execute(
                    "SELECT argument FROM server_command_arguments WHERE server_definition_id = ? ORDER BY ordinal",
                    (definition["server_definition_id"],),
                )
            ]
            environment = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    "SELECT name, value FROM server_environment WHERE server_definition_id = ? ORDER BY name",
                    (definition["server_definition_id"],),
                )
            }
            record: dict[str, Any] = {
                "id": native_id,
                "name": definition["name"],
                "project": definition["canonical_root"],
                "cwd": definition["cwd"],
                "role": definition["role"],
                "argv": arguments,
                "env": environment,
                "health_url": definition["health_url_template"],
                "log_path": definition["log_path"],
            }
            observation = connection.execute(
                "SELECT * FROM server_observations WHERE server_definition_id = ?",
                (definition["server_definition_id"],),
            ).fetchone()
            if observation is not None:
                record.update(
                    {
                        "status": observation["lifecycle"],
                        "pid": observation["pid"],
                        "process_start_time": observation["process_start_time"],
                        "process_fingerprint": observation["process_fingerprint"],
                        "port": observation["listener_port"],
                        "health_classification": observation["health_classification"],
                        "health_ok": None if observation["health_ok"] is None else bool(observation["health_ok"]),
                        "stopped_at": observation["stopped_at"],
                        "stopped_reason": observation["stopped_reason"],
                        "updated_at": observation["sampled_at"],
                    }
                )
            servers[native_id] = {key: value for key, value in record.items() if value is not None}

        assignments: dict[str, Any] = {}
        for row in connection.execute(
            """
            SELECT p.*, r.canonical_root FROM port_assignments p
            JOIN repositories r USING(repo_id) ORDER BY r.canonical_root, p.server_name
            """
        ):
            key = f"{row['canonical_root']}::{row['server_name']}"
            assignments[key] = {
                "project": row["canonical_root"],
                "name": row["server_name"],
                "port": row["port"],
                "status": row["status"],
                "updated_at": row["updated_at"],
            }

        leases: dict[str, Any] = {}
        for row in connection.execute(
            "SELECT l.*, r.canonical_root FROM leases l JOIN repositories r USING(repo_id)"
        ):
            leases[str(row["lease_id"])] = {
                "id": row["lease_id"],
                "project": row["canonical_root"],
                "port": row["port"],
                "owner": row["owner"],
                "agent": row["agent"],
                "purpose": row["purpose"],
                "status": row["status"],
                "expires_at": row["expires_at"],
                "released_at": row["deactivated_at"] if row["status"] != "active" else None,
            }

        operations = {
            str(row["operation_id"]): {
                "id": row["operation_id"],
                "project": row["canonical_root"],
                "kind": row["kind"],
                "status": row["status"],
                "phase": row["phase"],
                "agent": row["actor"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in connection.execute(
                """
                SELECT o.*, r.canonical_root FROM operations o
                LEFT JOIN repositories r USING(repo_id) ORDER BY o.created_at
                """
            )
        }
        history = [
            {
                "id": row["event_id"],
                "type": row["event_kind"],
                "code": row["code"],
                "message": row["message"],
                "at": row["occurred_at"],
            }
            for row in connection.execute("SELECT * FROM events ORDER BY occurred_at, event_id")
        ]
        docker_metadata: dict[str, Any] = {}
        for row in connection.execute(
            """
            SELECT sr.native_id, c.repo_id, r.canonical_root, d.full_container_id,
                   d.current_name, c.source_id
            FROM docker_ownership_claims c
            JOIN source_resources sr USING(source_resource_id)
            LEFT JOIN repositories r ON r.repo_id = c.repo_id
            LEFT JOIN docker_resources d USING(docker_resource_id)
            ORDER BY sr.native_id
            """
        ):
            docker_metadata[str(row["native_id"])] = {
                "project": row["canonical_root"],
                "container_id": row["full_container_id"],
                "name": row["current_name"] or row["native_id"],
                "source_id": row["source_id"],
            }
        stats_history: dict[str, list[dict[str, Any]]] = {}
        for row in connection.execute(
            "SELECT * FROM telemetry_samples WHERE host_resource_kind = 'docker' ORDER BY sampled_at"
        ):
            stats_history.setdefault(str(row["host_resource_id"]), []).append(
                {
                    "sampled_at": row["sampled_at"],
                    "cpu_percent": row["cpu_percent"],
                    "memory_bytes": row["memory_bytes"],
                    "network_rx_bytes": row["network_rx_bytes"],
                    "network_tx_bytes": row["network_tx_bytes"],
                    "block_read_bytes": row["block_read_bytes"],
                    "block_write_bytes": row["block_write_bytes"],
                }
            )
        return {
            "version": 2,
            "revision": int(metadata["state_revision"]),
            "created_at": metadata["created_at"],
            "updated_at": metadata["updated_at"],
            "servers": servers,
            "leases": leases,
            "port_assignments": assignments,
            "operations": operations,
            "history": history,
            "docker": {"metadata": docker_metadata, "stats_history": stats_history, "last_commands": []},
        }


def _nullable_boolean(value: Any) -> int | None:
    if value is True or value == 1:
        return 1
    if value is False or value == 0:
        return 0
    return None


def replace_legacy_state_projection(
    store: AccountStore,
    state: dict[str, Any],
    *,
    expected_revision: int | None,
) -> int:
    """Commit an authoritative v1 adapter snapshot without legacy downgrades.

    One-time JSON import is deliberately conservative: an old active lease is
    stale until independently proved. This adapter is different. Its input was
    read from this exact normalized generation and mutated under optimistic
    revision control, so active leases, native IDs, and lifecycle states must
    remain authoritative rather than being re-imported as untrusted history.
    """

    if not isinstance(state, dict):
        raise TypeError("legacy compatibility state must be an object")
    with store.immediate_transaction(max_seconds=30.0) as connection:
        current_revision = int(
            connection.execute(
                "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
            ).fetchone()[0]
        )
        if expected_revision is not None and current_revision != int(expected_revision):
            raise LegacySourceChanged(
                f"normalized state revision changed: expected {expected_revision}, got {current_revision}"
            )
        now = utc_timestamp()
        host = _local_host_record()
        host_id = str(host["host_id"])
        _insert_record(connection, "hosts", host, ignore=False)
        source_id = deterministic_id(
            "normalized-account-source", host_id, str(store.path.parent)
        )
        _insert_record(
            connection,
            "coordinator_sources",
            {
                "source_id": source_id,
                "host_id": host_id,
                "canonical_home": str(store.path),
                "state_path": str(store.path),
                "effective_uid": store.expected_uid,
                "status": "imported",
                "captured_revision": None,
                "captured_sha256": None,
                "imported_at": now,
                "retired_at": None,
                "late_writer_detected_at": None,
                "created_at": now,
                "updated_at": now,
            },
            ignore=False,
        )

        repository_cache: dict[str, str] = {}

        def repository_id(raw_path: Any) -> str:
            if not raw_path:
                raise LegacyImportError("normalized mutation requires an exact repository path")
            canonical = str(Path(str(raw_path)).expanduser().resolve())
            if canonical in repository_cache:
                return repository_cache[canonical]
            existing = connection.execute(
                "SELECT repo_id FROM repositories WHERE host_id = ? AND canonical_root = ?",
                (host_id, canonical),
            ).fetchone()
            if existing is not None:
                repo_id = str(existing[0])
                repository_cache[canonical] = repo_id
                return repo_id
            repository, reason = _strict_repository(canonical, host_id)
            if repository is None or repository.get("state") != "active":
                raise LegacyImportError(
                    f"normalized mutation project is not an existing Git repository: {canonical} "
                    f"({reason or 'missing_repo'})"
                )
            repo_id = str(repository["repo_id"])
            _insert_record(connection, "repositories", repository, ignore=False)
            connection.execute(
                """
                INSERT OR IGNORE INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'normalized-adapter', ?)
                """,
                (repo_id, now),
            )
            repository_cache[canonical] = repo_id
            return repo_id

        desired_definition_ids: set[str] = set()
        servers = state.get("servers") or {}
        if not isinstance(servers, dict):
            raise TypeError("normalized compatibility servers must be an object")
        for native_id, record in sorted(servers.items(), key=lambda item: str(item[0])):
            if not isinstance(record, dict):
                continue
            repo_id = repository_id(record.get("project"))
            name = str(record.get("name") or "").strip()
            if not name:
                raise LegacyImportError("normalized server mutation lacks a server name")
            definition_id = deterministic_id("server-definition", repo_id, name)
            desired_definition_ids.add(definition_id)
            argv = record.get("argv") or record.get("argv_template") or []
            if not isinstance(argv, list):
                argv = []
            environment = record.get("env") or record.get("environment") or {}
            if isinstance(environment, list):
                environment = {
                    str(value).split("=", 1)[0]: str(value).split("=", 1)[1]
                    for value in environment
                    if isinstance(value, str) and "=" in value
                }
            if not isinstance(environment, dict):
                environment = {}
            definition_payload = {
                "name": name,
                "role": record.get("role"),
                "cwd": str(record.get("cwd") or record.get("project")),
                "argv": [str(value) for value in argv],
                "environment": {str(key): str(value) for key, value in environment.items()},
                "health_url": record.get("health_url_template") or record.get("health_url"),
                "log_path": record.get("log_path"),
            }
            _insert_record(
                connection,
                "server_definitions",
                {
                    "server_definition_id": definition_id,
                    "repo_id": repo_id,
                    "name": name,
                    "role": record.get("role"),
                    "cwd": definition_payload["cwd"],
                    "health_url_template": definition_payload["health_url"],
                    "log_path": record.get("log_path"),
                    "definition_fingerprint": fingerprint(definition_payload),
                    "generation": int(record.get("generation") or 0),
                    "created_at": record.get("created_at") or now,
                    "updated_at": record.get("updated_at") or now,
                },
                ignore=False,
            )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (definition_id,),
            )
            for ordinal, argument in enumerate(argv):
                connection.execute(
                    "INSERT INTO server_command_arguments VALUES (?, ?, ?)",
                    (definition_id, ordinal, str(argument)),
                )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (definition_id,),
            )
            for key, value in sorted(environment.items()):
                connection.execute(
                    "INSERT INTO server_environment VALUES (?, ?, ?)",
                    (definition_id, str(key), str(value)),
                )
            source_resource_id = deterministic_id(
                "source-resource", source_id, "server", str(native_id)
            )
            _insert_record(
                connection,
                "source_resources",
                {
                    "source_resource_id": source_resource_id,
                    "source_id": source_id,
                    "resource_kind": "server",
                    "native_id": str(native_id),
                    "repo_id": repo_id,
                    "payload_sha256": fingerprint(record),
                    "provenance_json": canonical_json({"source": "normalized-adapter"}),
                    "created_at": record.get("created_at") or now,
                },
                ignore=False,
            )
            connection.execute(
                """
                INSERT INTO server_source_records(
                    server_definition_id, source_resource_id,
                    definition_fingerprint, is_exact_duplicate
                ) VALUES (?, ?, ?, 1)
                ON CONFLICT(server_definition_id, source_resource_id) DO UPDATE SET
                    definition_fingerprint = excluded.definition_fingerprint,
                    is_exact_duplicate = 1
                """,
                (definition_id, source_resource_id, fingerprint(definition_payload)),
            )
            health = record.get("health") if isinstance(record.get("health"), dict) else {}
            listener_identity = (
                health.get("identity") if isinstance(health.get("identity"), dict) else {}
            )
            observation = {
                "lifecycle": str(record.get("status") or "unobserved"),
                "pid": int(record["pid"]) if record.get("pid") else None,
                "process_start_time": record.get("process_start_time") or record.get("pid_start_time"),
                "process_fingerprint": record.get("process_fingerprint") or record.get("process_instance_id"),
                "listener_host": record.get("host") or "127.0.0.1",
                "listener_port": int(record["port"]) if record.get("port") else None,
                "listener_observable": listener_identity.get(
                    "observable", record.get("identity_observable")
                ),
                "health_classification": health.get("classification") or record.get("health_classification"),
                "health_ok": health.get("ok", record.get("health_ok")),
                "stopped_at": record.get("stopped_at"),
                "stopped_reason": record.get("stopped_reason"),
                "sampled_at": record.get("updated_at") or now,
            }
            connection.execute(
                """
                INSERT INTO server_observations(
                    server_definition_id, source_resource_id, lifecycle, pid,
                    process_start_time, process_fingerprint, listener_host,
                    listener_port, listener_observable, health_classification,
                    health_ok, stopped_at, stopped_reason, sampled_at,
                    observation_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_definition_id) DO UPDATE SET
                    source_resource_id = excluded.source_resource_id,
                    lifecycle = excluded.lifecycle, pid = excluded.pid,
                    process_start_time = excluded.process_start_time,
                    process_fingerprint = excluded.process_fingerprint,
                    listener_host = excluded.listener_host,
                    listener_port = excluded.listener_port,
                    listener_observable = excluded.listener_observable,
                    health_classification = excluded.health_classification,
                    health_ok = excluded.health_ok,
                    stopped_at = excluded.stopped_at,
                    stopped_reason = excluded.stopped_reason,
                    sampled_at = excluded.sampled_at,
                    observation_fingerprint = excluded.observation_fingerprint
                """,
                (
                    definition_id,
                    source_resource_id,
                    observation["lifecycle"],
                    observation["pid"],
                    observation["process_start_time"],
                    observation["process_fingerprint"],
                    observation["listener_host"],
                    observation["listener_port"],
                    _nullable_boolean(observation["listener_observable"]),
                    observation["health_classification"],
                    _nullable_boolean(observation["health_ok"]),
                    observation["stopped_at"],
                    observation["stopped_reason"],
                    observation["sampled_at"],
                    fingerprint(observation),
                ),
            )
            binding_id = deterministic_id("control-binding", "server", definition_id)
            _insert_record(
                connection,
                "control_bindings",
                {
                    "binding_id": binding_id,
                    "repo_id": repo_id,
                    "source_resource_id": source_resource_id,
                    "resource_kind": "server",
                    "resource_id": definition_id,
                    "source_id": source_id,
                    "capability": "lifecycle",
                    "provenance": "normalized-adapter",
                    "authority_state": "authoritative",
                    "priority": 100,
                    "generation": int(record.get("generation") or 0),
                    "created_at": record.get("created_at") or now,
                    "updated_at": record.get("updated_at") or now,
                },
                ignore=False,
            )
            _insert_record(
                connection,
                "repository_memberships",
                {
                    "membership_id": deterministic_id(
                        "membership", repo_id, "server", definition_id
                    ),
                    "repo_id": repo_id,
                    "resource_kind": "server",
                    "host_resource_id": definition_id,
                    "immutable_fingerprint": fingerprint(definition_payload),
                    "control_binding_id": binding_id,
                    "created_at": record.get("created_at") or now,
                },
                ignore=False,
            )
            _insert_record(
                connection,
                "startup_policies",
                {
                    "policy_id": deterministic_id(
                        "startup-policy", "server", definition_id, "coordinator"
                    ),
                    "repo_id": repo_id,
                    "resource_kind": "server",
                    "resource_id": definition_id,
                    "policy_kind": "coordinator",
                    "current_value": "enabled",
                    "desired_disabled_value": "disabled",
                    "immutable_fingerprint": fingerprint(definition_payload),
                    "generation": int(record.get("generation") or 0),
                    "updated_at": record.get("updated_at") or now,
                },
                ignore=False,
            )

        assignments = state.get("port_assignments") or {}
        if not isinstance(assignments, dict):
            raise TypeError("normalized compatibility port assignments must be an object")
        desired_assignment_ids: set[str] = set()
        for _native_id, record in sorted(assignments.items(), key=lambda item: str(item[0])):
            if not isinstance(record, dict):
                continue
            repo_id = repository_id(record.get("project"))
            name = str(record.get("name") or "").strip()
            assignment_id = deterministic_id("port-assignment", repo_id, name)
            desired_assignment_ids.add(assignment_id)
            status = "inactive" if str(record.get("status") or "active") == "inactive" else "active"
            _insert_record(
                connection,
                "port_assignments",
                {
                    "assignment_id": assignment_id,
                    "host_id": host_id,
                    "repo_id": repo_id,
                    "server_name": name,
                    "port": int(record["port"]),
                    "status": status,
                    "generation": int(record.get("generation") or 0),
                    "deactivated_at": record.get("deactivated_at") if status == "inactive" else None,
                    "created_at": record.get("created_at") or now,
                    "updated_at": record.get("updated_at") or now,
                },
                ignore=False,
            )
        for row in connection.execute("SELECT assignment_id FROM port_assignments").fetchall():
            if str(row[0]) not in desired_assignment_ids:
                connection.execute("DELETE FROM port_assignments WHERE assignment_id = ?", (row[0],))

        leases = state.get("leases") or {}
        if not isinstance(leases, dict):
            raise TypeError("normalized compatibility leases must be an object")
        desired_lease_ids: set[str] = set()
        for native_id, record in sorted(leases.items(), key=lambda item: str(item[0])):
            if not isinstance(record, dict):
                continue
            lease_id = str(record.get("id") or native_id)
            desired_lease_ids.add(lease_id)
            repo_id = repository_id(record.get("project"))
            server_definition_id = None
            if record.get("server_id"):
                server_record = servers.get(str(record.get("server_id")))
                if isinstance(server_record, dict) and server_record.get("name"):
                    server_definition_id = deterministic_id(
                        "server-definition", repo_id, str(server_record["name"])
                    )
            status = str(record.get("status") or "active")
            if status not in {"active", "released", "stale"}:
                status = "released"
            _insert_record(
                connection,
                "leases",
                {
                    "lease_id": lease_id,
                    "host_id": host_id,
                    "repo_id": repo_id,
                    "server_definition_id": server_definition_id,
                    "source_id": source_id,
                    "port": int(record["port"]),
                    "owner": record.get("owner"),
                    "agent": record.get("agent"),
                    "purpose": record.get("purpose"),
                    "status": status,
                    "expires_at": str(record.get("expires_at")) if record.get("expires_at") is not None else None,
                    "process_fingerprint": record.get("process_fingerprint") or record.get("process_instance_id"),
                    "generation": int(record.get("generation") or 0),
                    "deactivated_at": record.get("released_at") if status != "active" else None,
                    "created_at": record.get("created_at") or now,
                    "updated_at": record.get("updated_at") or now,
                },
                ignore=False,
            )
        for row in connection.execute("SELECT lease_id FROM leases").fetchall():
            if str(row[0]) not in desired_lease_ids:
                connection.execute("DELETE FROM leases WHERE lease_id = ?", (row[0],))

        operations = state.get("operations") or {}
        if isinstance(operations, dict):
            for native_id, record in sorted(operations.items(), key=lambda item: str(item[0])):
                if not isinstance(record, dict):
                    continue
                repo_id = repository_id(record.get("project")) if record.get("project") else None
                raw_status = str(record.get("status") or "failed").lower()
                status = {
                    "pending": "running",
                    "completed": "succeeded",
                    "success": "succeeded",
                    "error": "failed",
                }.get(raw_status, raw_status)
                if status not in {
                    "planned", "running", "succeeded", "failed", "partial",
                    "needs_attention", "cancelled",
                }:
                    status = "failed"
                _insert_record(
                    connection,
                    "operations",
                    {
                        "operation_id": str(record.get("id") or native_id),
                        "repo_id": repo_id,
                        "source_id": source_id,
                        "kind": str(record.get("kind") or record.get("action") or "coordinator"),
                        "status": status,
                        "phase": str(record.get("phase") or raw_status),
                        "generation": int(record.get("generation") or 0),
                        "request_fingerprint": fingerprint(record),
                        "owner_uid": store.expected_uid,
                        "actor": str(record.get("agent") or record.get("owner") or "coordinator"),
                        "process_fingerprint": record.get("owner_process_instance"),
                        "error_code": record.get("error_code"),
                        "error_message": record.get("error") if isinstance(record.get("error"), str) else None,
                        "result_json": canonical_json(record.get("result") or {}),
                        "created_at": record.get("created_at") or now,
                        "updated_at": record.get("updated_at") or now,
                    },
                    ignore=False,
                )

        history = state.get("history") or []
        if isinstance(history, list):
            for ordinal, record in enumerate(history):
                if not isinstance(record, dict):
                    continue
                repo_id = repository_id(record.get("project")) if record.get("project") else None
                event_id = str(
                    record.get("id")
                    or deterministic_id("normalized-event", ordinal, fingerprint(record))
                )
                _insert_record(
                    connection,
                    "events",
                    {
                        "event_id": event_id,
                        "repo_id": repo_id,
                        "source_id": source_id,
                        "operation_id": None,
                        "event_kind": str(record.get("type") or record.get("kind") or "coordinator"),
                        "code": record.get("code"),
                        "message": str(record.get("message") or record.get("action") or "Coordinator event"),
                        "diagnostic_json": canonical_json(record),
                        "occurred_at": record.get("at") or record.get("created_at") or now,
                    },
                    ignore=False,
                )

        docker = state.get("docker") or {}
        if isinstance(docker, dict):
            metadata = docker.get("metadata") or {}
            if isinstance(metadata, dict):
                engine_id = deterministic_id("docker-engine", host_id, "default")
                _insert_record(
                    connection,
                    "docker_engines",
                    {
                        "engine_id": engine_id,
                        "host_id": host_id,
                        "context_identity": "default",
                        "daemon_identity": None,
                        "socket_identity": None,
                        "capability_state": "unobserved",
                        "created_at": now,
                        "updated_at": now,
                    },
                    ignore=False,
                )
                for native_id, record in sorted(metadata.items(), key=lambda item: str(item[0])):
                    if not isinstance(record, dict):
                        continue
                    repo_id = repository_id(record.get("project"))
                    immutable = str(record.get("container_id") or record.get("id") or "")
                    source_resource_id = deterministic_id(
                        "source-resource", source_id, "container", str(native_id)
                    )
                    _insert_record(
                        connection,
                        "source_resources",
                        {
                            "source_resource_id": source_resource_id,
                            "source_id": source_id,
                            "resource_kind": "container",
                            "native_id": str(native_id),
                            "repo_id": repo_id,
                            "payload_sha256": fingerprint(record),
                            "provenance_json": canonical_json(record),
                            "created_at": record.get("created_at") or now,
                        },
                        ignore=False,
                    )
                    if len(immutable) != 64:
                        continue
                    resource_id = deterministic_id("docker-resource", engine_id, immutable.lower())
                    _insert_record(
                        connection,
                        "docker_resources",
                        {
                            "docker_resource_id": resource_id,
                            "engine_id": engine_id,
                            "full_container_id": immutable.lower(),
                            "current_name": str(record.get("name") or native_id),
                            "image": record.get("image"),
                            "created_at": record.get("created_at") or now,
                            "updated_at": record.get("updated_at") or now,
                        },
                        ignore=False,
                    )
                    claim_id = deterministic_id("docker-claim", source_id, str(native_id))
                    _insert_record(
                        connection,
                        "docker_ownership_claims",
                        {
                            "claim_id": claim_id,
                            "docker_resource_id": resource_id,
                            "source_resource_id": source_resource_id,
                            "repo_id": repo_id,
                            "source_id": source_id,
                            "provenance": "sidecar",
                            "priority": 100,
                            "conflict_state": "clear",
                            "created_at": record.get("created_at") or now,
                            "updated_at": record.get("updated_at") or now,
                        },
                        ignore=False,
                    )

        connection.execute(
            """
            UPDATE schema_metadata
            SET authority_mode = 'sqlite', migration_state = CASE
                    WHEN migration_state = 'empty' THEN 'ready' ELSE migration_state END,
                first_sqlite_mutation_at = COALESCE(first_sqlite_mutation_at, ?),
                updated_at = ?
            WHERE singleton = 1
            """,
            (now, now),
        )
    return current_revision + 1


def detect_late_legacy_writers(store: AccountStore) -> tuple[str, ...]:
    """Mark imported sources whose JSON hash/revision changed after commit."""

    changed: list[str] = []
    with store.read_transaction() as connection:
        sources = [
            dict(row)
            for row in connection.execute(
                """
                SELECT source_id, state_path, captured_revision, captured_sha256
                FROM coordinator_sources
                WHERE captured_sha256 IS NOT NULL AND status IN ('imported', 'retired')
                ORDER BY canonical_home
                """
            )
        ]
    for source in sources:
        path = Path(str(source["state_path"]))
        try:
            payload, _metadata = _read_state_bytes(path, store.expected_uid)
            value = json.loads(payload.decode("utf-8"))
            revision = int(value.get("revision") or 0)
            digest = hashlib.sha256(payload).hexdigest()
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            changed.append(str(source["source_id"]))
            continue
        if digest != source["captured_sha256"] or revision != int(source["captured_revision"]):
            changed.append(str(source["source_id"]))
    if changed:
        with store.immediate_transaction() as connection:
            for source_id in changed:
                connection.execute(
                    """
                    UPDATE coordinator_sources
                    SET status = 'conflict', late_writer_detected_at = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (utc_timestamp(), utc_timestamp(), source_id),
                )
                connection.execute(
                    """
                    UPDATE legacy_imports SET phase = 'late_writer'
                    WHERE source_id = ? AND phase = 'committed'
                    """,
                    (source_id,),
                )
    return tuple(changed)
