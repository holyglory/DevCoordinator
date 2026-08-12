"""Exact live project-runtime cgroup audit and resumable migration ledger.

This is an administrator boundary, not a lifecycle executor.  It observes
broker-authoritative immutable resource identities and records which existing
runtimes must be explicitly recreated/restarted.  It never changes a process,
container, cgroup, database row, or systemd unit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote
import uuid

from .schema import SCHEMA_VERSION
from .worker_native import project_repository_slice


AUDIT_KIND = "devcoordinator-project-runtime-isolation-audit"
LEDGER_KIND = "devcoordinator-project-runtime-isolation-migration-ledger"
CONTRACT_VERSION = 3
REPORT_MAX_BYTES = 8 * 1024 * 1024
MAX_RESOURCES = 100_000
MAX_CGROUP_BYTES = 4096
MAX_DOCKER_AUDIT_OUTPUT_BYTES = 512 * 1024
CLASSIFICATIONS = frozenset(
    {"compliant", "legacy_requires_recreation", "unobservable"}
)
RESOURCE_KINDS = frozenset({"docker", "service"})
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_DOCKER_ID_RE = re.compile(r"[0-9a-f]{64}")
_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}")
_CGROUP_PARENT_RE = re.compile(r"[A-Za-z0-9_.:@\\-]{1,255}\.slice")


class ProjectIsolationError(RuntimeError):
    """Fail-closed project isolation contract error."""


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ProjectIsolationError("isolation timestamp must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ProjectIsolationError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectIsolationError(f"{field} is invalid") from error
    if parsed.tzinfo is None:
        raise ProjectIsolationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _fingerprint(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _with_fingerprint(value: Mapping[str, Any]) -> dict[str, Any]:
    document = dict(value)
    document["evidence_sha256"] = _fingerprint(document)
    return document


def _verify_fingerprint(document: Mapping[str, Any]) -> None:
    supplied = document.get("evidence_sha256")
    if not isinstance(supplied, str) or _SHA256_RE.fullmatch(supplied) is None:
        raise ProjectIsolationError("isolation evidence fingerprint is invalid")
    payload = dict(document)
    del payload["evidence_sha256"]
    if _fingerprint(payload) != supplied:
        raise ProjectIsolationError("isolation evidence fingerprint does not match")


def _exact_keys(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProjectIsolationError(
            f"{field} fields are invalid (missing={missing}, extra={extra})"
        )


def _opaque(value: Any, field: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise ProjectIsolationError(f"{field} is invalid")
    return value


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ProjectIsolationError(f"{field} must be a canonical UUID")
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise ProjectIsolationError(f"{field} must be a canonical UUID") from error
    if parsed != value:
        raise ProjectIsolationError(f"{field} must be a canonical UUID")
    return value


def _database_file(path: Path) -> sqlite3.Connection:
    if not path.is_absolute():
        raise ProjectIsolationError("authority database path must be absolute")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
    ):
        raise ProjectIsolationError("authority database is not a regular file")
    uri = f"file:{quote(str(path), safe='/')}?mode=ro&immutable=0"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    return connection


def _metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               observation_revision
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    if row is None or int(row["schema_version"]) != SCHEMA_VERSION:
        raise ProjectIsolationError("authority database schema is unsupported")
    hosts = connection.execute(
        "SELECT host_id FROM hosts ORDER BY host_id"
    ).fetchall()
    if len(hosts) != 1:
        raise ProjectIsolationError("isolation audit requires exactly one authority host")
    return {
        "source_schema_version": int(row["schema_version"]),
        "database_generation": str(row["database_generation"]),
        "state_revision": int(row["state_revision"]),
        "observation_revision": int(row["observation_revision"]),
        "host_id": str(hosts[0]["host_id"]),
    }


def _repository_execution_uids(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    execution_uid = os.geteuid()
    if execution_uid <= 0:
        raise ProjectIsolationError(
            "runtime isolation capture requires the non-root developer service account"
        )
    rows = connection.execute(
        """
        SELECT repository.repo_id
        FROM repositories AS repository
        JOIN repository_installations AS installation USING(repo_id)
        WHERE repository.state = 'active' AND installation.status != 'disabled'
        ORDER BY repository.repo_id
        """
    ).fetchall()
    return {str(row["repo_id"]): execution_uid for row in rows}


def _repository_execution_context(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    return _repository_execution_uids(connection)


def _active_resources(
    connection: sqlite3.Connection, *, execution_uids: Mapping[str, int]
) -> list[dict[str, Any]]:
    docker = connection.execute(
        """
        SELECT resource.docker_resource_id AS resource_id,
               resource.repo_id,
               resource.full_container_id,
               observation.lifecycle
        FROM docker_resources AS resource
        JOIN repositories AS repository USING(repo_id)
        LEFT JOIN docker_observations AS observation
          ON observation.docker_resource_id = resource.docker_resource_id
        WHERE repository.state = 'active'
          AND (observation.lifecycle IS NULL OR observation.lifecycle != 'stopped')
        ORDER BY resource.repo_id, resource.docker_resource_id
        """
    ).fetchall()
    workers = connection.execute(
        """
        SELECT attempt.server_definition_id AS resource_id,
               attempt.repo_id,
               attempt.pid,
               attempt.process_start_time,
               attempt.process_fingerprint,
               attempt.attempt_id
        FROM worker_attempts AS attempt
        JOIN worker_supervisor_states AS supervisor
          ON supervisor.server_definition_id = attempt.server_definition_id
         AND supervisor.current_attempt_id = attempt.attempt_id
        JOIN repositories AS repository ON repository.repo_id = attempt.repo_id
        WHERE attempt.state = 'running'
          AND supervisor.state IN ('launching', 'running', 'stopping')
          AND repository.state = 'active'
        ORDER BY attempt.repo_id, attempt.server_definition_id
        """
    ).fetchall()
    resources: list[dict[str, Any]] = []
    for row in docker:
        repo_id = str(row["repo_id"])
        if repo_id not in execution_uids:
            raise ProjectIsolationError(
                "active Docker resource lacks repository execution context"
            )
        resources.append(
            {
                "resource_kind": "docker",
                "resource_id": str(row["resource_id"]),
                "repo_id": repo_id,
                "execution_uid": int(execution_uids[repo_id]),
                "runtime_identity": {
                    "full_container_id": str(row["full_container_id"]),
                },
                "identity_observable": row["lifecycle"] is not None,
            }
        )
    for row in workers:
        repo_id = str(row["repo_id"])
        if repo_id not in execution_uids:
            raise ProjectIsolationError(
                "active service resource lacks repository execution context"
            )
        resources.append(
            {
                "resource_kind": "service",
                "resource_id": str(row["resource_id"]),
                "repo_id": repo_id,
                "execution_uid": int(execution_uids[repo_id]),
                "runtime_identity": {
                    "attempt_id": str(row["attempt_id"]),
                    "pid": int(row["pid"]),
                    "process_start_time": str(row["process_start_time"]),
                    "process_fingerprint": str(row["process_fingerprint"]),
                },
                "identity_observable": True,
            }
        )
    if len(resources) > MAX_RESOURCES:
        raise ProjectIsolationError("project runtime inventory exceeds its bound")
    identities = [(row["resource_kind"], row["resource_id"]) for row in resources]
    if len(set(identities)) != len(identities):
        raise ProjectIsolationError("project runtime inventory contains duplicate identities")
    return sorted(resources, key=lambda row: (row["repo_id"], row["resource_kind"], row["resource_id"]))


def _safe_docker_executable(value: str | os.PathLike[str]) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ProjectIsolationError("Docker executable path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ProjectIsolationError("Docker executable is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(resolved, os.X_OK)
    ):
        raise ProjectIsolationError("Docker executable is not executable")
    return resolved


def inspect_docker_cgroups(
    container_ids: tuple[str, ...],
    *,
    docker_executable: str | os.PathLike[str] = "/usr/bin/docker",
    timeout_seconds: float = 30.0,
) -> dict[str, dict[str, Any]]:
    """Read only exact Docker identities with one fixed command contract."""

    if any(_DOCKER_ID_RE.fullmatch(value) is None for value in container_ids):
        raise ProjectIsolationError("Docker audit received an invalid container identity")
    if len(set(container_ids)) != len(container_ids) or len(container_ids) > MAX_RESOURCES:
        raise ProjectIsolationError("Docker audit identity set is invalid")
    executable = _safe_docker_executable(docker_executable)
    output: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(container_ids), 100):
        chunk = container_ids[offset : offset + 100]
        # Never ask Docker for the full inspect object: it can contain secret
        # environment, mount and label data.  Literal JSON framing around only
        # these three scalar template fields is both bounded and exact.
        command = (
            str(executable),
            "inspect",
            "--format",
            '{"Id":{{json .Id}},"CgroupParent":{{json .HostConfig.CgroupParent}},'
            '"Running":{{json .State.Running}}}',
            *chunk,
        )
        returncode, stdout = _bounded_command_stdout(
            command,
            timeout_seconds=timeout_seconds,
            maximum_bytes=MAX_DOCKER_AUDIT_OUTPUT_BYTES,
        )
        if returncode != 0 or stdout is None:
            # Preserve exact coverage by marking every omitted identity
            # unobservable; never infer identity from Docker's error string.
            continue
        for raw_line in stdout.splitlines():
            if len(raw_line) > MAX_CGROUP_BYTES + 256:
                continue
            try:
                value = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or set(value) != {
                "Id",
                "CgroupParent",
                "Running",
            }:
                continue
            container_id = str(value.get("Id") or "").lower()
            if container_id not in chunk or container_id in output:
                continue
            parent = value.get("CgroupParent")
            running = value.get("Running")
            if (
                not isinstance(parent, str)
                or len(parent.encode("utf-8")) > MAX_CGROUP_BYTES
                or type(running) is not bool
            ):
                continue
            output[container_id] = {
                "cgroup_parent": parent,
                "running": running,
            }
    return output


def _bounded_command_stdout(
    command: tuple[str, ...], *, timeout_seconds: float, maximum_bytes: int
) -> tuple[int, bytes | None]:
    """Run a fixed argv while retaining no more than the declared stdout cap."""

    if not command or timeout_seconds <= 0 or maximum_bytes <= 0:
        raise ProjectIsolationError("bounded command contract is invalid")
    process = subprocess.Popen(
            (
                *command,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={
                "HOME": "/root",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
    if process.stdout is None:  # pragma: no cover - subprocess contract guard
        process.kill()
        process.wait()
        raise ProjectIsolationError("bounded command stdout pipe is unavailable")
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    deadline = datetime.now(timezone.utc).timestamp() + timeout_seconds
    chunks: list[bytes] = []
    retained = 0
    exceeded = False
    timed_out = False
    try:
        while True:
            remaining = deadline - datetime.now(timezone.utc).timestamp()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.25))
            if not events:
                if process.poll() is not None:
                    # Drain the nonblocking pipe after process exit.
                    events = [(None, None)]
                else:
                    continue
            try:
                block = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - retained))
            except BlockingIOError:
                if process.poll() is not None:
                    break
                continue
            if not block:
                break
            retained += len(block)
            if retained > maximum_bytes:
                exceeded = True
                break
            chunks.append(block)
    finally:
        selector.close()
        if exceeded or timed_out or process.poll() is None:
            process.kill()
        returncode = process.wait()
        process.stdout.close()
    if exceeded or timed_out:
        return returncode, None
    return returncode, b"".join(chunks)


def _read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    try:
        return _uuid(path.read_text(encoding="ascii").strip(), "host boot ID")
    except OSError as error:
        raise ProjectIsolationError("host boot ID is unavailable") from error


def _read_process_cgroup(
    identity: Mapping[str, Any], *, proc_root: Path = Path("/proc")
) -> str | None:
    pid = identity.get("pid")
    expected_start = identity.get("process_start_time")
    if type(pid) is not int or pid <= 1 or not isinstance(expected_start, str):
        return None
    try:
        stat_text = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
        suffix = stat_text[stat_text.rfind(")") + 1 :].strip().split()
        observed_start = suffix[19]
        if observed_start != expected_start:
            return None
        cgroup_text = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8")
    except (OSError, IndexError):
        return None
    paths: list[str] = []
    for raw in cgroup_text.splitlines():
        parts = raw.split(":", 2)
        if len(parts) != 3:
            return None
        hierarchy, controllers, cgroup_path = parts
        if hierarchy == "0" and controllers == "":
            paths.append(cgroup_path)
        elif "name=systemd" in controllers.split(","):
            paths.append(cgroup_path)
    unique = sorted(set(paths))
    if len(unique) != 1:
        return None
    value = unique[0]
    if not value.startswith("/") or len(value.encode("utf-8")) > MAX_CGROUP_BYTES:
        return None
    return value


def _cgroup_classification(
    *, resource_kind: str, expected: str, observed: str | None
) -> tuple[str, str]:
    if observed is None:
        return "unobservable", "cgroup_observation_unavailable"
    if resource_kind == "docker":
        if observed == expected:
            return "compliant", "exact_cgroup_parent"
        return "legacy_requires_recreation", "container_cgroup_parent_mismatch"
    segments = tuple(part for part in observed.split("/") if part)
    if expected in segments:
        return "compliant", "exact_repository_slice_ancestor"
    return "legacy_requires_recreation", "process_cgroup_path_mismatch"


def capture_isolation_audit(
    *,
    database_path: Path,
    docker_cgroup_reader: Callable[[tuple[str, ...]], Mapping[str, Mapping[str, Any]]] = inspect_docker_cgroups,
    process_cgroup_reader: Callable[[Mapping[str, Any]], str | None] = _read_process_cgroup,
    boot_id_reader: Callable[[], str] = _read_boot_id,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Capture one non-mutating exact-ID project isolation report."""

    connection = _database_file(database_path)
    try:
        before = _metadata(connection)
        execution_uids = _repository_execution_context(connection)
        resources = _active_resources(connection, execution_uids=execution_uids)
    finally:
        connection.close()
    docker_ids = tuple(
        row["runtime_identity"]["full_container_id"]
        for row in resources
        if row["resource_kind"] == "docker"
        and _DOCKER_ID_RE.fullmatch(row["runtime_identity"]["full_container_id"])
    )
    try:
        docker_observations = dict(docker_cgroup_reader(docker_ids))
    except Exception:
        docker_observations = {}
    rows: list[dict[str, Any]] = []
    for source in resources:
        kind = source["resource_kind"]
        execution_uid = source["execution_uid"]
        expected = None
        if type(execution_uid) is int and execution_uid > 0:
            try:
                expected = project_repository_slice(
                    uid=execution_uid, repository_id=source["repo_id"]
                )
            except ValueError:
                expected = None
        observed: str | None = None
        reason_override = None
        if not source["identity_observable"] or expected is None:
            reason_override = "authority_identity_unobservable"
        elif kind == "docker":
            evidence = docker_observations.get(
                source["runtime_identity"]["full_container_id"]
            )
            if isinstance(evidence, Mapping):
                observed_value = evidence.get("cgroup_parent")
                if evidence.get("running") is not True:
                    reason_override = "runtime_not_running_during_audit"
                elif isinstance(observed_value, str):
                    observed = observed_value
        else:
            observed = process_cgroup_reader(source["runtime_identity"])
        if reason_override is not None:
            classification, reason = "unobservable", reason_override
        else:
            classification, reason = _cgroup_classification(
                resource_kind=kind, expected=str(expected), observed=observed
            )
        rows.append(
            {
                "resource_kind": kind,
                "resource_id": source["resource_id"],
                "repo_id": source["repo_id"],
                "execution_uid": execution_uid,
                "runtime_identity": source["runtime_identity"],
                "expected_cgroup_parent": expected,
                "observed_cgroup": observed,
                "classification": classification,
                "reason_code": reason,
            }
        )

    # Bind the host reads to an unchanged authority revision. A concurrent
    # replacement makes the entire capture stale rather than mixing identities.
    check = _database_file(database_path)
    try:
        after = _metadata(check)
        after_execution_uids = _repository_execution_context(check)
    finally:
        check.close()
    if (
        after != before
        or after_execution_uids != execution_uids
    ):
        raise ProjectIsolationError(
            "authority changed while project runtime isolation was observed"
        )
    counts = {classification: 0 for classification in sorted(CLASSIFICATIONS)}
    for row in rows:
        counts[row["classification"]] += 1
    captured_at = now()
    payload = {
        "schema_version": CONTRACT_VERSION,
        "kind": AUDIT_KIND,
        "audit_id": str(uuid.uuid4()),
        "captured_at": _timestamp(captured_at),
        "valid_until": _timestamp(captured_at + timedelta(minutes=5)),
        "host_boot_id": boot_id_reader(),
        **before,
        "resources": rows,
        "counts": counts,
        "project_isolation_complete": bool(
            not counts["legacy_requires_recreation"]
            and not counts["unobservable"]
        ),
    }
    return validate_isolation_audit(_with_fingerprint(payload))


def validate_isolation_audit(
    document: Mapping[str, Any], *, now: datetime | None = None, require_fresh: bool = False
) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ProjectIsolationError("isolation audit must be an object")
    expected_keys = {
        "schema_version", "kind", "audit_id", "captured_at", "valid_until",
        "host_boot_id", "source_schema_version",
        "database_generation", "state_revision",
        "observation_revision", "host_id", "resources", "counts",
        "project_isolation_complete", "evidence_sha256",
    }
    _exact_keys(document, expected_keys, "isolation audit")
    _verify_fingerprint(document)
    if document["schema_version"] != CONTRACT_VERSION or document["kind"] != AUDIT_KIND:
        raise ProjectIsolationError("isolation audit discriminator is unsupported")
    _uuid(document["audit_id"], "audit ID")
    _uuid(document["host_boot_id"], "host boot ID")
    if document["source_schema_version"] != SCHEMA_VERSION:
        raise ProjectIsolationError("isolation audit source schema is unsupported")
    captured = _parse_timestamp(document["captured_at"], "captured_at")
    valid_until = _parse_timestamp(document["valid_until"], "valid_until")
    if valid_until <= captured or valid_until - captured > timedelta(minutes=5):
        raise ProjectIsolationError("isolation audit validity window is invalid")
    if require_fresh and (now or datetime.now(timezone.utc)).astimezone(timezone.utc) > valid_until:
        raise ProjectIsolationError("isolation audit has expired")
    _opaque(document["database_generation"], "database generation")
    _opaque(document["host_id"], "host ID")
    for field in ("state_revision", "observation_revision"):
        if type(document[field]) is not int or document[field] < 0:
            raise ProjectIsolationError(f"{field} is invalid")
    resources = document["resources"]
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES:
        raise ProjectIsolationError("isolation resources are invalid")
    seen: set[tuple[str, str]] = set()
    normalized_rows: list[dict[str, Any]] = []
    counts = {classification: 0 for classification in sorted(CLASSIFICATIONS)}
    row_keys = {
        "resource_kind", "resource_id", "repo_id", "execution_uid",
        "runtime_identity", "expected_cgroup_parent", "observed_cgroup",
        "classification", "reason_code",
    }
    for value in resources:
        if not isinstance(value, Mapping):
            raise ProjectIsolationError("isolation resource must be an object")
        _exact_keys(value, row_keys, "isolation resource")
        kind = value["resource_kind"]
        if kind not in RESOURCE_KINDS:
            raise ProjectIsolationError("isolation resource kind is invalid")
        resource_id = _opaque(value["resource_id"], "resource ID")
        repo_id = _opaque(value["repo_id"], "repository ID")
        key = (kind, resource_id)
        if key in seen:
            raise ProjectIsolationError("isolation resource identity is duplicated")
        seen.add(key)
        execution_uid = value["execution_uid"]
        if type(execution_uid) is not int or execution_uid <= 0:
            if value["classification"] != "unobservable":
                raise ProjectIsolationError("unattributed owner must be unobservable")
            expected = None
        else:
            expected = project_repository_slice(uid=execution_uid, repository_id=repo_id)
        if value["expected_cgroup_parent"] != expected:
            raise ProjectIsolationError("expected cgroup parent is contradictory")
        identity = value["runtime_identity"]
        if not isinstance(identity, Mapping):
            raise ProjectIsolationError("runtime identity must be an object")
        if kind == "docker":
            _exact_keys(identity, {"full_container_id"}, "Docker runtime identity")
            if _DOCKER_ID_RE.fullmatch(str(identity["full_container_id"])) is None:
                raise ProjectIsolationError("Docker runtime identity is invalid")
        else:
            _exact_keys(
                identity,
                {"attempt_id", "pid", "process_start_time", "process_fingerprint"},
                "service runtime identity",
            )
            _opaque(identity["attempt_id"], "worker attempt ID")
            if type(identity["pid"]) is not int or identity["pid"] <= 1:
                raise ProjectIsolationError("worker PID is invalid")
            if not isinstance(identity["process_start_time"], str) or not identity["process_start_time"]:
                raise ProjectIsolationError("worker process start identity is invalid")
            if _SHA256_RE.fullmatch(str(identity["process_fingerprint"])) is None:
                raise ProjectIsolationError("worker process fingerprint is invalid")
        observed = value["observed_cgroup"]
        if observed is not None and (
            not isinstance(observed, str)
            or len(observed.encode("utf-8")) > MAX_CGROUP_BYTES
            or any(character in observed for character in "\0\r\n")
        ):
            raise ProjectIsolationError("observed cgroup is invalid")
        classification = value["classification"]
        if classification not in CLASSIFICATIONS:
            raise ProjectIsolationError("isolation classification is invalid")
        if expected is not None:
            computed, _reason = _cgroup_classification(
                resource_kind=kind, expected=expected, observed=observed
            )
            # An authority failure can downgrade an otherwise shaped row to
            # unobservable, but no row may be upgraded over live cgroup facts.
            if classification != computed and classification != "unobservable":
                raise ProjectIsolationError("isolation classification contradicts cgroup evidence")
        elif classification != "unobservable":
            raise ProjectIsolationError("missing expected cgroup must be unobservable")
        _opaque(value["reason_code"], "isolation reason code")
        counts[classification] += 1
        normalized_rows.append(dict(value))
    if document["counts"] != counts:
        raise ProjectIsolationError("isolation counts are contradictory")
    complete = counts["legacy_requires_recreation"] == 0 and counts["unobservable"] == 0
    if document["project_isolation_complete"] is not complete:
        raise ProjectIsolationError("project isolation completion is contradictory")
    if normalized_rows != sorted(
        normalized_rows,
        key=lambda row: (row["repo_id"], row["resource_kind"], row["resource_id"]),
    ):
        raise ProjectIsolationError("isolation resources are not canonically ordered")
    return json.loads(json.dumps(document))


def verify_live_authority_binding(
    document: Mapping[str, Any],
    *,
    database_path: Path,
) -> dict[str, Any]:
    """Recheck a retained audit against the exact current execution context."""

    checked = validate_isolation_audit(document)
    connection = _database_file(database_path)
    try:
        before = _metadata(connection)
        execution_uids = _repository_execution_context(connection)
        after = _metadata(connection)
    finally:
        connection.close()
    expected_metadata = {
        field: checked[field]
        for field in (
            "source_schema_version",
            "database_generation",
            "state_revision",
            "observation_revision",
            "host_id",
        )
    }
    if before != after or before != expected_metadata:
        raise ProjectIsolationError(
            "authority changed after project runtime isolation capture"
        )
    for resource in checked["resources"]:
        if execution_uids.get(str(resource["repo_id"])) != resource["execution_uid"]:
            raise ProjectIsolationError(
                "project isolation repository execution context changed after capture"
            )
    return checked


def create_migration_ledger(
    audit: Mapping[str, Any], *, deadline: datetime, now: datetime | None = None
) -> dict[str, Any]:
    checked = validate_isolation_audit(audit)
    if checked["counts"]["unobservable"]:
        raise ProjectIsolationError(
            "unobservable project runtimes block migration ledger creation"
        )
    created = now or datetime.now(timezone.utc)
    if deadline.tzinfo is None or deadline <= created or deadline - created > timedelta(days=30):
        raise ProjectIsolationError("migration deadline must be within the next 30 days")
    entries = []
    for row in checked["resources"]:
        if row["classification"] != "legacy_requires_recreation":
            continue
        entries.append(
            {
                "resource_kind": row["resource_kind"],
                "resource_id": row["resource_id"],
                "repo_id": row["repo_id"],
                "execution_uid": row["execution_uid"],
                "original_runtime_identity": row["runtime_identity"],
                "action": "recreate" if row["resource_kind"] == "docker" else "restart",
                "status": "pending",
                "operation_id": None,
                "replacement_runtime_identity": None,
                "completed_at": None,
            }
        )
    payload = {
        "schema_version": CONTRACT_VERSION,
        "kind": LEDGER_KIND,
        "ledger_id": str(uuid.uuid4()),
        "created_at": _timestamp(created),
        "updated_at": _timestamp(created),
        "deadline": _timestamp(deadline),
        "host_boot_id": checked["host_boot_id"],
        "database_generation": checked["database_generation"],
        "source_audit_sha256": checked["evidence_sha256"],
        "latest_audit_sha256": checked["evidence_sha256"],
        "entries": entries,
        "counts": {"pending": len(entries), "completed": 0, "retired": 0},
    }
    return validate_migration_ledger(_with_fingerprint(payload), audit=checked)


def validate_migration_ledger(
    document: Mapping[str, Any], *, audit: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ProjectIsolationError("migration ledger must be an object")
    expected = {
        "schema_version", "kind", "ledger_id", "created_at", "updated_at",
        "deadline", "host_boot_id", "database_generation",
        "source_audit_sha256", "latest_audit_sha256", "entries", "counts",
        "evidence_sha256",
    }
    _exact_keys(document, expected, "migration ledger")
    _verify_fingerprint(document)
    if document["schema_version"] != CONTRACT_VERSION or document["kind"] != LEDGER_KIND:
        raise ProjectIsolationError("migration ledger discriminator is unsupported")
    _uuid(document["ledger_id"], "ledger ID")
    _uuid(document["host_boot_id"], "host boot ID")
    _opaque(document["database_generation"], "database generation")
    created = _parse_timestamp(document["created_at"], "created_at")
    updated = _parse_timestamp(document["updated_at"], "updated_at")
    deadline = _parse_timestamp(document["deadline"], "deadline")
    if not created <= updated <= deadline or deadline - created > timedelta(days=30):
        raise ProjectIsolationError("migration ledger time range is invalid")
    for field in ("source_audit_sha256", "latest_audit_sha256"):
        if _SHA256_RE.fullmatch(str(document[field])) is None:
            raise ProjectIsolationError(f"{field} is invalid")
    entries = document["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_RESOURCES:
        raise ProjectIsolationError("migration ledger entries are invalid")
    entry_keys = {
        "resource_kind", "resource_id", "repo_id", "execution_uid",
        "original_runtime_identity", "action", "status", "operation_id",
        "replacement_runtime_identity", "completed_at",
    }
    seen: set[tuple[str, str]] = set()
    counts = {"pending": 0, "completed": 0, "retired": 0}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ProjectIsolationError("migration ledger entry must be an object")
        _exact_keys(entry, entry_keys, "migration ledger entry")
        kind = entry["resource_kind"]
        if kind not in RESOURCE_KINDS:
            raise ProjectIsolationError("migration ledger resource kind is invalid")
        resource_id = _opaque(entry["resource_id"], "resource ID")
        _opaque(entry["repo_id"], "repository ID")
        if type(entry["execution_uid"]) is not int or entry["execution_uid"] <= 0:
            raise ProjectIsolationError("migration ledger owner UID is invalid")
        key = (kind, resource_id)
        if key in seen:
            raise ProjectIsolationError("migration ledger resource is duplicated")
        seen.add(key)
        expected_action = "recreate" if kind == "docker" else "restart"
        if entry["action"] != expected_action:
            raise ProjectIsolationError("migration ledger action is contradictory")
        status_value = entry["status"]
        if status_value not in counts:
            raise ProjectIsolationError("migration ledger status is invalid")
        counts[status_value] += 1
        if status_value == "pending":
            if any(
                entry[field] is not None
                for field in ("operation_id", "replacement_runtime_identity", "completed_at")
            ):
                raise ProjectIsolationError("pending migration entry contains completion evidence")
        else:
            _uuid(entry["operation_id"], "migration operation ID")
            _parse_timestamp(entry["completed_at"], "completed_at")
            if status_value == "completed" and not isinstance(entry["replacement_runtime_identity"], Mapping):
                raise ProjectIsolationError("completed migration lacks replacement identity")
            if status_value == "retired" and entry["replacement_runtime_identity"] is not None:
                raise ProjectIsolationError("retired migration contains a replacement identity")
    if document["counts"] != counts:
        raise ProjectIsolationError("migration ledger counts are contradictory")
    if audit is not None:
        checked = validate_isolation_audit(audit)
        if (
            checked["host_boot_id"] != document["host_boot_id"]
            or checked["database_generation"] != document["database_generation"]
            or checked["evidence_sha256"] != document["latest_audit_sha256"]
        ):
            raise ProjectIsolationError("migration ledger is not bound to the supplied audit")
    return json.loads(json.dumps(document))


def record_migration(
    ledger: Mapping[str, Any],
    *,
    audit: Mapping[str, Any],
    resource_kind: str,
    resource_id: str,
    operation_id: str,
    outcome: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = validate_migration_ledger(ledger)
    checked = validate_isolation_audit(audit)
    if outcome not in {"completed", "retired"}:
        raise ProjectIsolationError("migration outcome must be completed or retired")
    _uuid(operation_id, "migration operation ID")
    if (
        checked["host_boot_id"] != current["host_boot_id"]
        or checked["database_generation"] != current["database_generation"]
    ):
        raise ProjectIsolationError("migration audit host/generation changed")
    key = (resource_kind, resource_id)
    entries = [dict(entry) for entry in current["entries"]]
    matching = [entry for entry in entries if (entry["resource_kind"], entry["resource_id"]) == key]
    if len(matching) != 1:
        raise ProjectIsolationError("migration resource is not a unique ledger entry")
    entry = matching[0]
    if entry["status"] != "pending":
        if entry["operation_id"] == operation_id and entry["status"] == outcome:
            return current
        raise ProjectIsolationError("migration resource is already finalized")
    rows = {
        (row["resource_kind"], row["resource_id"]): row
        for row in checked["resources"]
    }
    replacement = rows.get(key)
    if outcome == "completed":
        if replacement is None or replacement["classification"] != "compliant":
            raise ProjectIsolationError("replacement runtime is not proven compliant")
        if replacement["runtime_identity"] == entry["original_runtime_identity"]:
            raise ProjectIsolationError("runtime identity did not change during migration")
        if replacement["repo_id"] != entry["repo_id"] or replacement["execution_uid"] != entry["execution_uid"]:
            raise ProjectIsolationError(
                "replacement runtime changed repository execution context"
            )
        entry["replacement_runtime_identity"] = replacement["runtime_identity"]
    else:
        if replacement is not None:
            raise ProjectIsolationError("retired runtime remains active in the audit")
        entry["replacement_runtime_identity"] = None
    entry["status"] = outcome
    entry["operation_id"] = operation_id
    entry["completed_at"] = _timestamp(now)
    current["updated_at"] = entry["completed_at"]
    current["latest_audit_sha256"] = checked["evidence_sha256"]
    current["counts"] = {
        status_value: sum(item["status"] == status_value for item in entries)
        for status_value in ("pending", "completed", "retired")
    }
    current["entries"] = entries
    current.pop("evidence_sha256", None)
    return validate_migration_ledger(_with_fingerprint(current), audit=checked)


def read_private_document(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise ProjectIsolationError("isolation evidence path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > REPORT_MAX_BYTES
        ):
            raise ProjectIsolationError("isolation evidence file is unsafe")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise ProjectIsolationError("isolation evidence changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProjectIsolationError("isolation evidence JSON is invalid") from error
    if not isinstance(value, dict):
        raise ProjectIsolationError("isolation evidence must be an object")
    return value


def write_private_document(
    path: Path,
    document: Mapping[str, Any],
    *,
    replace: bool = False,
    expected_sha256: str | None = None,
) -> None:
    if not path.is_absolute():
        raise ProjectIsolationError("isolation output path must be absolute")
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProjectIsolationError("isolation output parent must be a real directory")
    if replace:
        existing = read_private_document(path)
        if expected_sha256 is None or existing.get("evidence_sha256") != expected_sha256:
            raise ProjectIsolationError("isolation output replacement fingerprint changed")
    elif path.exists() or path.is_symlink():
        raise ProjectIsolationError("isolation output already exists")
    encoded = json.dumps(document, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(encoded) > REPORT_MAX_BYTES:
        raise ProjectIsolationError("isolation output exceeds its bound")
    temporary = parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.partial"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if replace:
            os.replace(temporary, path)
        else:
            # link() is the portable no-clobber publication primitive; rename()
            # would silently replace a destination created after our check.
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
