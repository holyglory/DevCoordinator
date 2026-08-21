"""Create a fresh current authority from an allowlisted retained-control view.

This is deliberately not a schema migrator.  It reads one quiesced authority
database, copies only durable configuration into a newly initialized current
schema, advances every mutable control generation, rebuilds the non-secret
client profile, and emits canonical Console control files.  Operations,
observations, attempts, test results, request history, and secret material are
never eligible collections.

Security basis: ``security-assumptions.md`` confirms one trusted developer on
one owned host, local Unix identities as attribution rather than tenants,
root-owned service configuration, and credentials kept out of repository and
ordinary environment transport.  These assumptions permit host-wide retained
catalog publication; they do not permit copying secret-shaped environment
values into the new authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import Any, Callable, Mapping
import uuid

from .broker_persistence import (
    BROKER_SCHEMA,
    _LEGACY_LOCAL_AUTHORIZATION_TABLES,
    _compose_definition_fingerprint,
    _compose_run_once_policies_connection,
    _require_service_image_evidence,
)
from .broker import BrokerError
from .broker_profile import BrokerProfileError, profile_from_document
from .schema import SCHEMA_VERSION, initialize_schema, invariant_violations


KIND = "devcoordinator-retained-control-rebaseline"
VERSION = 1
REBASELINE_SOURCE_SCHEMA = 15
MAX_ROWS_PER_COLLECTION = 100_000
MAX_CONSOLE_BYTES = 2 * 1024 * 1024
AUTHORITY_SOCKET = "/run/devcoordinator-authority/authority.sock"
CONSOLE_FILES = ("routes.json", "access-control.json", "ui-prefs.json")
SECRET_TRANSPORT_FILES = ("upstream-auth.json", "telegram-control.json")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}")
_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_EMAIL = re.compile(r'[^\s@<>(),;:"\[\]]+@[^\s@<>(),;:"\[\]]+\.[^\s@<>(),;:"\[\]]+')
_SECRET_NAME = re.compile(
    r"(?:^|_)(?:secret|password|passwd|token|credential|private_key|api_key|access_key|authorization)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)",
    re.IGNORECASE,
)

# The rebaseline is intentionally a one-time schema-15 -> schema-16 boundary.
# These columns are the reviewed schema-15 control surface.  Do not derive this
# map from the current schema: doing so would silently turn a future column into
# retained data without another explicit review.
SCHEMA_15_RETAINED_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "schema_metadata": ("singleton", "schema_version", "database_generation", "state_revision", "observation_revision", "authority_mode", "migration_state", "first_sqlite_mutation_at", "created_at", "updated_at"),
    "hosts": ("host_id", "machine_fingerprint", "platform", "hostname", "created_at", "updated_at"),
    "repositories": ("repo_id", "host_id", "canonical_root", "display_name", "state", "generation", "created_at", "updated_at"),
    "repository_aliases": ("alias_id", "repo_id", "host_id", "canonical_alias", "reason", "created_at"),
    "repository_installations": ("repo_id", "status", "startup_fenced", "generation", "operation_id", "disabled_at", "reinstalled_at", "reason", "actor", "updated_at"),
    "server_definitions": ("server_definition_id", "repo_id", "name", "role", "cwd", "health_url_template", "log_path", "definition_fingerprint", "generation", "created_at", "updated_at"),
    "server_command_arguments": ("server_definition_id", "ordinal", "argument"),
    "server_environment": ("server_definition_id", "name", "value"),
    "worker_policies": ("server_definition_id", "repo_id", "execution_uid", "keep_alive", "desired_state", "breaker_state", "crash_limit", "crash_window_seconds", "generation", "requested_by", "request_operation_id", "last_rearmed_at", "last_rearmed_by", "last_rearm_operation_id", "last_tripped_at", "last_trip_reason", "last_trip_attempt_id", "last_trip_event_id", "created_at", "updated_at"),
    "startup_policies": ("policy_id", "repo_id", "resource_kind", "resource_id", "policy_kind", "current_value", "desired_disabled_value", "immutable_fingerprint", "generation", "updated_at"),
    "broker_compose_definitions": ("compose_definition_id", "repo_id", "cwd", "project_name", "definition_fingerprint", "enabled", "generation", "created_at", "updated_at"),
    "broker_compose_project_claims": ("compose_definition_id", "project_name", "claimed", "release_snapshot_id", "released_at", "updated_at"),
    "broker_compose_directory_identity": ("compose_definition_id", "root_device", "root_inode", "cwd_device", "cwd_inode", "updated_at"),
    "broker_compose_effective_model_evidence": ("compose_definition_id", "definition_fingerprint", "model_sha256", "services_json", "service_replicas_json", "model_services_json", "model_service_replicas_json", "service_images_json", "profiles_json", "host_access_risks_json", "host_access_approved", "approved_by_uid", "approved_at", "replica_budget", "validated_at"),
    "broker_compose_files": ("compose_definition_id", "ordinal", "file_path"),
    "broker_compose_file_evidence": ("compose_definition_id", "ordinal", "content_sha256", "byte_size"),
    "broker_compose_env_files": ("compose_definition_id", "ordinal", "file_path"),
    "broker_compose_env_file_evidence": ("compose_definition_id", "ordinal", "content_sha256", "byte_size"),
    "broker_compose_profiles": ("compose_definition_id", "ordinal", "profile_name"),
    "broker_compose_services": ("compose_definition_id", "ordinal", "service_name"),
    "broker_compose_run_once_services": ("compose_definition_id", "ordinal", "service_name", "max_timeout_seconds", "receipt_contract_json", "policy_fingerprint"),
    "broker_port_ranges": ("repo_id", "server_definition_id", "protocol", "start_port", "end_port", "max_ttl_seconds", "enabled", "updated_at"),
    "ephemeral_container_templates": ("template_id", "repo_id", "name", "image_ref", "secret_policy_kind", "secret_binding_id", "definition_fingerprint", "default_ttl_seconds", "max_ttl_seconds", "container_tcp_port", "host_port_start", "host_port_end", "memory_bytes", "cpu_millis", "max_concurrent_runs", "max_concurrent_runs_per_uid", "repo_max_active_runs", "repo_memory_budget_bytes", "repo_cpu_budget_millis", "enabled", "generation", "created_at", "updated_at"),
    "ephemeral_template_arguments": ("template_id", "ordinal", "argument"),
    "ephemeral_template_environment": ("template_id", "name", "value"),
    "database_backups": ("database_backup_id", "database_binding_id", "docker_resource_id", "repo_id", "source_id", "scope", "source_container_id", "source_database_name", "source_identity_fingerprint", "artifact_path", "artifact_size_bytes", "artifact_sha256", "manifest_path", "manifest_sha256", "backup_format", "verification_status", "verification_mode", "created_at", "verified_at", "status", "last_restored_at", "restore_count", "updated_at"),
    "backup_evidence": ("backup_id", "repo_id", "source_id", "manifest_path", "manifest_sha256", "verification_status", "created_at", "verified_at"),
    "repository_families": ("family_id", "host_id", "root_repo_id", "git_common_dir", "identity_fingerprint", "created_at", "updated_at"),
    "repository_scopes": ("repo_id", "family_id", "project_kind", "git_dir", "git_common_dir", "identity_fingerprint", "root_device", "root_inode", "created_at", "updated_at"),
}

# This obsolete authorization table can legitimately survive the schema-15
# trusted-local migration as an empty child table.  Match its historical shape
# exactly before discarding it so a changed table cannot hide new control data.
SCHEMA_15_RETIRED_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "broker_repository_enrollments": (
        "uid",
        "repo_id",
        "account_id",
        "enabled",
        "issued_at",
        "valid_until_epoch",
        "enrollment_snapshot_id",
        "grant_snapshot_id",
        "updated_at",
    ),
}


class RetainedControlError(RuntimeError):
    """The retained-control view cannot be constructed safely."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular(path: Path, *, maximum: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise RetainedControlError(f"retained input is unavailable: {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RetainedControlError(f"retained input is not a regular file: {path}")
    if maximum is not None and not 0 < info.st_size <= maximum:
        raise RetainedControlError(f"retained input exceeds its byte bound: {path}")
    return info


def _parent_identity(path: Path, *, expected_uid: int | None = None) -> dict[str, int | str]:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise RetainedControlError(f"retained path is not canonical: {path}")
    parent = path.parent
    try:
        info = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as error:
        raise RetainedControlError(f"retained parent is unavailable: {parent}: {error}") from error
    if (
        resolved != parent
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or (expected_uid is not None and info.st_uid != expected_uid)
    ):
        raise RetainedControlError(f"retained parent is unsafe: {parent}")
    return {
        "path": str(parent),
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def _file_identity(
    path: Path,
    *,
    maximum: int | None = None,
    require_parent_owner: bool = True,
) -> dict[str, Any]:
    parent = _parent_identity(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RetainedControlError(f"retained input is unavailable: {path}: {error}") from error
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RetainedControlError(f"retained input is not a regular file: {path}")
        if maximum is not None and not 0 < before.st_size <= maximum:
            raise RetainedControlError(f"retained input exceeds its byte bound: {path}")
        if require_parent_owner and (before.st_uid, before.st_gid) != (
            parent["uid"],
            parent["gid"],
        ):
            raise RetainedControlError(
                f"retained file is not owned by its parent identity: {path}"
            )
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or size != before.st_size
    ):
        raise RetainedControlError(f"retained input changed while hashing: {path}")
    return {
        "path": str(path),
        "present": True,
        "sha256": digest.hexdigest(),
        "bytes": size,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "parent": parent,
    }


def _verify_file_identity(path: Path, expected: Mapping[str, Any]) -> None:
    actual = _file_identity(path)
    if actual != dict(expected):
        raise RetainedControlError(f"retained source changed during export: {path}")


def _private_root(path: Path, *, expected_uid: int) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    _parent_identity(path, expected_uid=expected_uid)
    if path.exists():
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RetainedControlError("retained-control output root is not owned mode 0700")
    else:
        path.mkdir(mode=0o700)
    if path.resolve(strict=True) != path:
        raise RetainedControlError("retained-control output root is not canonical")
    return path


def _atomic_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    if not path.parent.exists():
        _parent_identity(path.parent, expected_uid=os.geteuid())
        path.parent.mkdir(mode=0o700)
    parent = _parent_identity(path, expected_uid=os.geteuid())
    if parent["mode"] != 0o700:
        raise RetainedControlError("retained-control output parent is not private")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _execute_script(connection: sqlite3.Connection, source: str) -> None:
    statement = ""
    for line in source.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            statement = ""
            if sql:
                connection.execute(sql)
    if statement.strip():
        raise RetainedControlError("broker schema contains an incomplete statement")


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")'))


def _rows(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    rows = [dict(row) for row in connection.execute(f'SELECT * FROM "{table}"')]
    if len(rows) > MAX_ROWS_PER_COLLECTION:
        raise RetainedControlError(f"retained collection is too large: {table}")
    return rows


def _advanced(value: object, field: str) -> int:
    if type(value) is not int or int(value) < 0:
        raise RetainedControlError(f"retained {field} generation is invalid")
    return int(value) + 1


def _reject_secret_environment(row: Mapping[str, Any], table: str) -> dict[str, Any]:
    name = str(row.get("name") or "")
    value = str(row.get("value") or "")
    if _SECRET_NAME.search(name) or _SECRET_VALUE.search(value):
        raise RetainedControlError(
            f"{table} contains secret-shaped environment transport: {name!r}"
        )
    return dict(row)


def _verify_registered_file(path_value: object, digest_value: object, *, size: object | None = None) -> None:
    path = Path(str(path_value or ""))
    if not path.is_absolute():
        raise RetainedControlError("verified backup registry contains a relative path")
    info = _regular(path)
    if size is not None and (type(size) is not int or int(size) != info.st_size):
        raise RetainedControlError(f"verified backup size changed: {path}")
    if not isinstance(digest_value, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
        raise RetainedControlError("verified backup registry contains an invalid digest")
    if _digest_file(path) != digest_value:
        raise RetainedControlError(f"verified backup digest changed: {path}")


def _database_backup(row: Mapping[str, Any], _table: str) -> dict[str, Any] | None:
    if row.get("status") != "available" or row.get("verification_status") not in {
        "lightweight",
        "strong",
    }:
        return None
    _verify_registered_file(
        row.get("artifact_path"),
        row.get("artifact_sha256"),
        size=row.get("artifact_size_bytes"),
    )
    _verify_registered_file(row.get("manifest_path"), row.get("manifest_sha256"))
    result = dict(row)
    for field in ("database_binding_id", "docker_resource_id", "source_id"):
        result[field] = None
    return result


def _backup_evidence(row: Mapping[str, Any], _table: str) -> dict[str, Any] | None:
    if row.get("verification_status") != "verified":
        return None
    _verify_registered_file(row.get("manifest_path"), row.get("manifest_sha256"))
    result = dict(row)
    result["source_id"] = None
    return result


Transform = Callable[[Mapping[str, Any], str], dict[str, Any] | None]


def _identity(row: Mapping[str, Any], _table: str) -> dict[str, Any]:
    return dict(row)


def _advance_generation(row: Mapping[str, Any], table: str) -> dict[str, Any]:
    result = dict(row)
    result["generation"] = _advanced(result.get("generation"), table)
    return result


def _installation(row: Mapping[str, Any], table: str) -> dict[str, Any]:
    if row.get("status") == "disabling":
        raise RetainedControlError(
            "retained-control rebaseline requires repository disable operations to finish"
        )
    result = _advance_generation(row, table)
    result["operation_id"] = None
    return result


def _worker_policy(row: Mapping[str, Any], table: str) -> dict[str, Any]:
    result = _advance_generation(row, table)
    result.update(
        {
            "request_operation_id": None,
            "last_rearmed_at": None,
            "last_rearmed_by": None,
            "last_rearm_operation_id": None,
        }
    )
    if result.get("breaker_state") == "tripped":
        # Preserve the fence, but not its operation/attempt/event history.  The
        # next explicit start owns both re-arming and stopped -> running.
        result["desired_state"] = "stopped"
    result.update(
        {
            "last_tripped_at": None,
            "last_trip_reason": None,
            "last_trip_attempt_id": None,
            "last_trip_event_id": None,
        }
    )
    return result


def _compose_effective_model(row: Mapping[str, Any], table: str) -> dict[str, Any]:
    result = dict(row)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(result.get("model_sha256") or "")) is None:
        raise RetainedControlError(f"{table} model digest is invalid")
    list_fields = (
        "services_json",
        "model_services_json",
        "profiles_json",
        "host_access_risks_json",
    )
    decoded_lists: dict[str, list[str]] = {}
    for field in list_fields:
        try:
            value = json.loads(str(result.get(field)))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RetainedControlError(f"{table} {field} is invalid") from error
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) or not item for item in value)
            or value != sorted(set(value))
        ):
            raise RetainedControlError(f"{table} {field} is invalid")
        decoded_lists[field] = value
    replica_fields = (
        ("service_replicas_json", decoded_lists["services_json"]),
        ("model_service_replicas_json", decoded_lists["model_services_json"]),
    )
    for field, services in replica_fields:
        try:
            value = json.loads(str(result.get(field)))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RetainedControlError(f"{table} {field} is invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != set(services)
            or any(type(count) is not int or not 1 <= count <= 16 for count in value.values())
            or sum(value.values()) > 64
        ):
            raise RetainedControlError(f"{table} {field} is invalid")
    try:
        images = json.loads(str(result.get("service_images_json")))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RetainedControlError(f"{table} service_images_json is invalid") from error
    if (
        not isinstance(images, dict)
        or not set(images) <= set(decoded_lists["model_services_json"])
        or any(
            not isinstance(name, str)
            or not isinstance(image, str)
            or not image
            or image != image.strip()
            or any(character.isspace() for character in image)
            or "\x00" in image
            or len(image.encode("utf-8")) > 512
            for name, image in images.items()
        )
    ):
        raise RetainedControlError(f"{table} service_images_json is invalid")
    return result


RETAINED_COLLECTIONS: tuple[tuple[str, Transform], ...] = (
    ("hosts", _identity),
    ("repositories", _advance_generation),
    ("repository_aliases", _identity),
    ("repository_installations", _installation),
    ("server_definitions", _advance_generation),
    ("server_command_arguments", _identity),
    ("server_environment", _reject_secret_environment),
    ("worker_policies", _worker_policy),
    ("startup_policies", _advance_generation),
    ("broker_compose_definitions", _advance_generation),
    ("broker_compose_project_claims", _identity),
    ("broker_compose_directory_identity", _identity),
    ("broker_compose_effective_model_evidence", _compose_effective_model),
    ("broker_compose_files", _identity),
    ("broker_compose_file_evidence", _identity),
    ("broker_compose_env_files", _identity),
    ("broker_compose_env_file_evidence", _identity),
    ("broker_compose_profiles", _identity),
    ("broker_compose_services", _identity),
    ("broker_compose_run_once_services", _identity),
    ("broker_port_ranges", _identity),
    ("ephemeral_container_templates", _advance_generation),
    ("ephemeral_template_arguments", _identity),
    ("ephemeral_template_environment", _reject_secret_environment),
    ("database_backups", _database_backup),
    ("backup_evidence", _backup_evidence),
)


SCHEMA_15_DISPOSABLE_TEST_COLLECTIONS = frozenset(
    {
        "test_runs",
        "test_case_results",
        "test_store_metadata",
        "test_snapshots",
        "test_plans",
        "test_run_targets",
        "test_target_attempts",
        "test_failures",
        "test_artifacts",
        "test_evidence_attestations",
        "test_events",
        "test_rollup_hourly",
        "test_rollup_daily",
        "test_repository_setup_projections",
        "test_result_chunks",
        "test_mutation_journal",
        "test_target_resource_profiles",
        "test_evidence_consumptions",
    }
)


RETIRED_SOURCE_COLLECTIONS = frozenset(
    {
        "legacy_imports",
        "migration_conflicts",
        *SCHEMA_15_DISPOSABLE_TEST_COLLECTIONS,
        "repository_memberships",
        "control_bindings",
        "repository_owners",
        "repository_owner_transfers",
        "broker_host_observation_owners",
        "broker_port_policies",
        "broker_operation_requests_legacy_auth",
        "broker_observed_compose_containers_legacy_owner",
        *_LEGACY_LOCAL_AUTHORIZATION_TABLES,
    }
)


def _copy_collection(
    source: sqlite3.Connection,
    target: sqlite3.Connection,
    table: str,
    transform: Transform,
) -> int:
    expected_columns = SCHEMA_15_RETAINED_COLUMNS.get(table)
    if expected_columns is None:
        raise RetainedControlError(f"retained collection lacks a frozen schema-15 contract: {table}")
    source_columns = _columns(source, table)
    target_columns = _columns(target, table)
    if source_columns != expected_columns:
        raise RetainedControlError(f"retained {table} columns differ from frozen schema 15")
    if target_columns != expected_columns:
        raise RetainedControlError(f"current schema changed retained collection {table} without review")
    copied = 0
    for raw in _rows(source, table):
        value = transform(raw, table)
        if value is None:
            continue
        columns = tuple(column for column in target_columns if column in value)
        unknown = set(value) - set(source_columns)
        if unknown:
            raise RetainedControlError(f"retained transform invented unknown fields for {table}")
        placeholders = ",".join("?" for _ in columns)
        names = ",".join(f'"{name}"' for name in columns)
        try:
            target.execute(
                f'INSERT INTO "{table}"({names}) VALUES ({placeholders})',
                tuple(value[name] for name in columns),
            )
        except sqlite3.Error as error:
            raise RetainedControlError(f"retained {table} row is incompatible: {error}") from error
        copied += 1
    return copied


def _copy_repository_topology(source: sqlite3.Connection, target: sqlite3.Connection) -> dict[str, int]:
    source_tables = _tables(source)
    if not {"repository_families", "repository_scopes"} <= source_tables:
        raise RetainedControlError("schema-15 repository topology collections are missing")
    families = _rows(source, "repository_families")
    scopes = _rows(source, "repository_scopes")
    if not families and not scopes:
        return {"repository_families": 0, "repository_scopes": 0}
    target.execute("DELETE FROM repository_scopes")
    target.execute("DELETE FROM repository_families")
    counts = {
        "repository_families": _copy_collection(source, target, "repository_families", _identity),
        "repository_scopes": _copy_collection(source, target, "repository_scopes", _identity),
    }
    repo_count = int(target.execute("SELECT COUNT(*) FROM repositories").fetchone()[0])
    if counts["repository_scopes"] != repo_count:
        raise RetainedControlError("retained repository topology does not cover every repository")
    return counts


def _validate_compose_controls(connection: sqlite3.Connection) -> None:
    duplicate_claim = connection.execute(
        "SELECT project_name FROM broker_compose_project_claims WHERE claimed=1 "
        "GROUP BY project_name HAVING COUNT(*) != 1 LIMIT 1"
    ).fetchone()
    if duplicate_claim is not None:
        raise RetainedControlError("retained Compose project-name claim is ambiguous")
    for row in connection.execute(
        """
        SELECT definition.compose_definition_id, definition.repo_id,
               repository.canonical_root, definition.cwd,
               definition.project_name, definition.definition_fingerprint,
               claim.compose_definition_id IS NOT NULL AS has_claim,
               claim.project_name, claim.claimed,
               directory.root_device, directory.root_inode,
               directory.cwd_device, directory.cwd_inode,
               effective.definition_fingerprint,
               effective.services_json,
               effective.model_services_json,
               effective.profiles_json,
               effective.model_service_replicas_json,
               effective.service_images_json,
               effective.replica_budget,
               definition.enabled
        FROM broker_compose_definitions definition
        JOIN repositories repository USING(repo_id)
        LEFT JOIN broker_compose_project_claims claim
          USING(compose_definition_id)
        LEFT JOIN broker_compose_directory_identity directory
          USING(compose_definition_id)
        LEFT JOIN broker_compose_effective_model_evidence effective
          USING(compose_definition_id)
        ORDER BY definition.compose_definition_id
        """
    ):
        compose_id = str(row[0])
        if not bool(row[6]) or row[7] != row[4]:
            raise RetainedControlError(
                f"Compose control {compose_id!r} lacks its matching project-name claim"
            )
        if row[20] != 1:
            continue
        if row[8] != 1 or any(row[index] is None for index in (9, 10, 11, 12, 13)):
            raise RetainedControlError(
                f"Compose control {compose_id!r} lacks its active claim, directory identity, or effective model"
            )
        if str(row[5]) != str(row[13]):
            raise RetainedControlError(
                f"Compose control {compose_id!r} has stale effective evidence"
            )
        files = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT file_path FROM broker_compose_files WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        file_evidence = tuple(
            {"content_sha256": str(item[0]), "byte_size": int(item[1])}
            for item in connection.execute(
                "SELECT content_sha256,byte_size FROM broker_compose_file_evidence "
                "WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        env_files = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT file_path FROM broker_compose_env_files WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        env_file_evidence = tuple(
            {"content_sha256": str(item[0]), "byte_size": int(item[1])}
            for item in connection.execute(
                "SELECT content_sha256,byte_size FROM broker_compose_env_file_evidence "
                "WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        if not files or len(files) != len(file_evidence) or len(env_files) != len(
            env_file_evidence
        ):
            raise RetainedControlError(
                f"Compose control {compose_id!r} has incomplete file evidence"
            )
        lifecycle_services = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT service_name FROM broker_compose_services "
                "WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        profiles = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT profile_name FROM broker_compose_profiles "
                "WHERE compose_definition_id=? ORDER BY ordinal",
                (compose_id,),
            )
        )
        try:
            run_once_policies = _compose_run_once_policies_connection(
                connection,
                compose_definition_id=compose_id,
                operation_id=None,
            )
            expected_fingerprint = _compose_definition_fingerprint(
                repo_id=str(row[1]),
                canonical_root=str(row[2]),
                root_identity={"device": int(row[9]), "inode": int(row[10])},
                cwd=str(row[3]),
                cwd_identity={"device": int(row[11]), "inode": int(row[12])},
                compose_files=files,
                compose_file_evidence=file_evidence,
                env_files=env_files,
                env_file_evidence=env_file_evidence,
                profiles=profiles,
                services=lifecycle_services,
                run_once_services=run_once_policies,
                project_name=str(row[4]),
            )
        except (BrokerError, TypeError, ValueError) as error:
            raise RetainedControlError(
                f"Compose control {compose_id!r} has invalid persisted policy"
            ) from error
        if expected_fingerprint != str(row[5]):
            raise RetainedControlError(
                f"Compose control {compose_id!r} fingerprint contradicts its retained fields"
            )
        try:
            recorded_lifecycle = json.loads(str(row[14]))
            recorded_model = json.loads(str(row[15]))
            recorded_profiles = json.loads(str(row[16]))
            model_replicas = json.loads(str(row[17]))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RetainedControlError("retained Compose control JSON is invalid") from error
        if (
            recorded_lifecycle != sorted(lifecycle_services)
            or recorded_model
            != sorted((*lifecycle_services, *(policy.name for policy in run_once_policies)))
            or recorded_profiles != sorted(profiles)
            or not isinstance(model_replicas, dict)
            or int(row[19]) != sum(model_replicas.values())
        ):
            raise RetainedControlError(
                f"Compose control {compose_id!r} contradicts its retained model"
            )
        try:
            images = dict(
                _require_service_image_evidence(
                    row[18],
                    services=tuple(recorded_model),
                    operation_id=None,
                    allow_empty=not run_once_policies,
                )
            )
        except BrokerError as error:
            raise RetainedControlError(
                f"Compose control {compose_id!r} has invalid image evidence"
            ) from error
        if any(policy.name not in images for policy in run_once_policies):
            raise RetainedControlError(
                f"Compose control {compose_id!r} has a run-once service without a sealed image"
            )


@functools.lru_cache(maxsize=1)
def _known_source_tables() -> frozenset[str]:
    connection = sqlite3.connect(":memory:")
    try:
        initialize_schema(connection, database_generation="known", timestamp=_now())
        _execute_script(connection, BROKER_SCHEMA)
        return frozenset(_tables(connection) | set(RETIRED_SOURCE_COLLECTIONS))
    finally:
        connection.close()


def _validate_console_routes(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"version", "routes"} or value.get("version") != 1:
        raise RetainedControlError("Console routes are not current format")
    routes = value.get("routes")
    if not isinstance(routes, dict) or len(routes) > 1000:
        raise RetainedControlError("Console route collection is invalid")
    allowed = {
        "slug", "kind", "auth", "instanceId", "createdAt", "updatedAt", "title",
        "port", "project", "serverName", "containerName", "containerPort",
    }
    retained: dict[str, Any] = {}
    for slug, raw in sorted(routes.items()):
        if not isinstance(slug, str) or _SLUG.fullmatch(slug) is None:
            raise RetainedControlError("Console route slug is invalid")
        if not isinstance(raw, dict) or not set(raw) <= allowed:
            raise RetainedControlError(f"Console route {slug!r} has unknown fields")
        route = dict(raw)
        if (
            route.get("slug") != slug
            or route.get("kind") not in {"port", "server", "docker"}
            or route.get("auth") not in {"google", "public"}
            or not isinstance(route.get("instanceId"), str)
        ):
            raise RetainedControlError(f"Console route {slug!r} is invalid")
        retained[slug] = route
    return {"version": 1, "routes": retained}


def _validate_console_access(value: object, routes: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("version") != 3
        or set(value) != {"version", "users", "requests"}
        or not isinstance(value.get("users"), dict)
        or not isinstance(value.get("requests"), dict)
    ):
        raise RetainedControlError("Console access policy is not current format")
    users: dict[str, Any] = {}
    for email, raw in sorted(value["users"].items()):
        if not isinstance(email, str) or _EMAIL.fullmatch(email) is None or email != email.lower():
            raise RetainedControlError("Console user identity is invalid")
        if not isinstance(raw, dict) or set(raw) != {"grants"} or not isinstance(raw.get("grants"), list):
            raise RetainedControlError(f"Console user {email!r} grants are invalid")
        grants: list[str] = []
        for grant in raw["grants"]:
            if grant == "console":
                grants.append(grant)
                continue
            match = re.fullmatch(r"route:([a-z0-9-]{1,63})", str(grant))
            if match is None or match.group(1) not in routes:
                raise RetainedControlError(f"Console user {email!r} has an unknown grant")
            grants.append(str(grant))
        users[email] = {"grants": sorted(set(grants))}
    # Access requests are workflow/history, not durable retained control.
    return {"version": 3, "users": users, "requests": {}}


def _validate_console_prefs(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("version") != 1 or set(value) != {"version", "hidden"}:
        raise RetainedControlError("Console settings are not current format")
    hidden = value.get("hidden")
    if not isinstance(hidden, dict) or set(hidden) != {"servers", "docker", "projects"}:
        raise RetainedControlError("Console hidden-item settings are invalid")
    result: dict[str, list[str]] = {}
    for name in ("servers", "docker", "projects"):
        values = hidden[name]
        if (
            not isinstance(values, list)
            or len(values) > 500
            or any(not isinstance(item, str) or not item.strip() or len(item) > 300 for item in values)
        ):
            raise RetainedControlError(f"Console {name} settings are invalid")
        result[name] = sorted(set(item.strip() for item in values))
    return {"version": 1, "hidden": result}


def _read_console(path: Path, default: object) -> tuple[object, dict[str, Any]]:
    parent = _parent_identity(path)
    if not path.exists() and not path.is_symlink():
        return default, {"path": str(path), "present": False, "parent": parent}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RetainedControlError(f"Console retained control is unsafe: {path}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_CONSOLE_BYTES
        ):
            raise RetainedControlError(f"Console retained control is unsafe: {path}")
        if (before.st_uid, before.st_gid) != (parent["uid"], parent["gid"]):
            raise RetainedControlError(f"Console retained control has another owner: {path}")
        payload = bytearray()
        while len(payload) <= MAX_CONSOLE_BYTES:
            block = os.read(descriptor, min(64 * 1024, MAX_CONSOLE_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise RetainedControlError(f"Console retained control changed while reading: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RetainedControlError(f"Console retained control is invalid: {path}: {error}") from error
    return value, {
        "path": str(path),
        "present": True,
        "sha256": _digest_bytes(bytes(payload)),
        "bytes": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "parent": parent,
    }


def _verify_optional_identity(path: Path, expected: Mapping[str, Any]) -> None:
    if expected.get("path") != str(path) or type(expected.get("present")) is not bool:
        raise RetainedControlError("retained Console source identity is invalid")
    if expected["present"] is False:
        if path.exists() or path.is_symlink() or _parent_identity(path) != expected.get("parent"):
            raise RetainedControlError(f"retained Console source changed during export: {path}")
        return
    _verify_file_identity(path, expected)


def _console_view(
    state_root: Path, output_root: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    raw_routes, routes_source = _read_console(
        state_root / "routes.json", {"version": 1, "routes": {}}
    )
    routes = _validate_console_routes(raw_routes)
    raw_access, access_source = _read_console(
            state_root / "access-control.json",
            {"version": 3, "users": {}, "requests": {}},
    )
    access = _validate_console_access(raw_access, routes["routes"])
    raw_prefs, prefs_source = _read_console(
            state_root / "ui-prefs.json",
            {"version": 1, "hidden": {"servers": [], "docker": [], "projects": []}},
    )
    prefs = _validate_console_prefs(raw_prefs)
    console = output_root / "console"
    documents = {"routes.json": routes, "access-control.json": access, "ui-prefs.json": prefs}
    evidence: dict[str, Any] = {}
    for name, document in documents.items():
        payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        destination = console / name
        _atomic_bytes(destination, payload)
        evidence[name] = {"sha256": _digest_bytes(payload), "bytes": len(payload)}
    return evidence, {
        "routes": len(routes["routes"]),
        "users": len(access["users"]),
        "grants": sum(len(item["grants"]) for item in access["users"].values()),
        "settings": sum(len(values) for values in prefs["hidden"].values()),
    }, {
        "routes.json": routes_source,
        "access-control.json": access_source,
        "ui-prefs.json": prefs_source,
    }


def _profile_document(connection: sqlite3.Connection) -> dict[str, Any]:
    metadata = connection.execute(
        "SELECT database_generation FROM schema_metadata WHERE singleton=1"
    ).fetchone()
    repositories: list[dict[str, Any]] = []
    for row in connection.execute(
        """
        SELECT r.repo_id, r.canonical_root, r.generation
        FROM repositories r JOIN repository_installations i USING(repo_id)
        WHERE r.state='active' AND i.status='installed' AND i.startup_fenced=0
        ORDER BY r.canonical_root, r.repo_id
        """
    ):
        repo_id = str(row[0])
        compose = connection.execute(
            "SELECT compose_definition_id FROM broker_compose_definitions "
            "WHERE repo_id=? AND enabled=1 ORDER BY compose_definition_id",
            (repo_id,),
        ).fetchall()
        if len(compose) > 1:
            raise RetainedControlError("repository has multiple enabled Compose controls")
        compose_id = None if not compose else str(compose[0][0])
        run_once = {}
        if compose_id is not None:
            run_once = {
                str(item[0]): int(item[1])
                for item in connection.execute(
                    "SELECT service_name,max_timeout_seconds FROM broker_compose_run_once_services "
                    "WHERE compose_definition_id=? ORDER BY ordinal",
                    (compose_id,),
                )
            }
        templates: dict[str, str] = {}
        policies: dict[str, dict[str, str]] = {}
        for template in connection.execute(
            "SELECT name,template_id,secret_policy_kind,secret_binding_id "
            "FROM ephemeral_container_templates WHERE repo_id=? AND enabled=1 ORDER BY name",
            (repo_id,),
        ):
            name = str(template[0])
            templates[name] = str(template[1])
            if template[2] is not None:
                policies[name] = {"policy": str(template[2]), "binding_id": str(template[3])}
        repositories.append(
            {
                "canonical_root": str(row[1]),
                "repo_id": repo_id,
                "generation": int(row[2]),
                "servers": {
                    str(item[0]): str(item[1])
                    for item in connection.execute(
                        "SELECT name,server_definition_id FROM server_definitions "
                        "WHERE repo_id=? ORDER BY name",
                        (repo_id,),
                    )
                },
                "containers": {},
                "compose_definition_id": compose_id,
                "compose_container_ids": [],
                "compose_run_once_services": run_once,
                "ephemeral_templates": templates,
                "ephemeral_secret_policies": policies,
            }
        )
    if metadata is None or not repositories:
        raise RetainedControlError("retained authority has no routable repository catalog")
    document = {
        "version": 2,
        "service": {"socket": AUTHORITY_SOCKET, "database_generation": str(metadata[0])},
        "repositories": repositories,
    }
    try:
        profile_from_document(document)
    except BrokerProfileError as error:
        raise RetainedControlError("rebuilt client profile is invalid") from error
    return document


def _load_prepared_transaction(
    manifest_path: Path,
    *,
    source_database: Mapping[str, Any],
    source_profile: Mapping[str, Any],
    console_state_root: Path,
) -> dict[str, Any]:
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RetainedControlError("existing retained-control manifest is invalid") from error
    if not isinstance(document, dict):
        raise RetainedControlError("existing retained-control manifest is not an object")
    claimed = document.pop("document_sha256", None)
    if (
        document.get("schema_version") != VERSION
        or document.get("kind") != KIND
        or not isinstance(claimed, str)
        or _digest_bytes(_canonical(document)) != claimed
    ):
        raise RetainedControlError("existing retained-control manifest digest is invalid")
    document["document_sha256"] = claimed
    source = document.get("source")
    target = document.get("target")
    if (
        not isinstance(source, dict)
        or source.get("database") != source_database
        or source.get("profile") != source_profile
        or not isinstance(target, dict)
    ):
        raise RetainedControlError("existing retained-control transaction belongs to other inputs")
    target_database_value = target.get("database")
    target_profile_value = target.get("profile")
    if not isinstance(target_database_value, Mapping) or not isinstance(
        target_profile_value, Mapping
    ):
        raise RetainedControlError("existing retained-control target identity is invalid")
    target_database = Path(str(target_database_value.get("path") or ""))
    target_profile = Path(str(target_profile_value.get("path") or ""))
    if (
        _file_identity(target_database) != dict(target_database_value)
        or _file_identity(target_profile) != dict(target_profile_value)
    ):
        raise RetainedControlError("existing retained-control staged target changed")
    console_files = document.get("console_files")
    if not isinstance(console_files, dict) or set(console_files) != set(CONSOLE_FILES):
        raise RetainedControlError("existing retained Console evidence is invalid")
    for name in CONSOLE_FILES:
        evidence = console_files[name]
        path = manifest_path.parent / "console" / name
        if (
            not isinstance(evidence, dict)
            or not path.is_file()
            or path.is_symlink()
            or _digest_file(path) != evidence.get("sha256")
        ):
            raise RetainedControlError("existing retained Console target changed")
    console_sources = document.get("console_sources")
    if not isinstance(console_sources, dict) or set(console_sources) != set(CONSOLE_FILES):
        raise RetainedControlError("existing retained Console source evidence is invalid")
    for name in CONSOLE_FILES:
        _verify_optional_identity(console_state_root / name, console_sources[name])
    return document


def _discard_incomplete_staging(output_root: Path) -> None:
    """Remove only known partial outputs inside one validated transaction root."""

    allowed_files = {
        "authority.sqlite3",
        "authority.sqlite3-journal",
        "authority.sqlite3-wal",
        "authority.sqlite3-shm",
        "client-profiles.json",
    }
    allowed_temporary = re.compile(
        r"\.(?:authority\.sqlite3|client-profiles\.json|routes\.json|access-control\.json|ui-prefs\.json)\.\d+\.[0-9a-f]{32}\.tmp"
    )
    entries = list(output_root.iterdir())
    for entry in entries:
        if entry.name == "console":
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RetainedControlError("partial retained Console root is unsafe")
            for child in list(entry.iterdir()):
                child_info = child.lstat()
                if (
                    stat.S_ISLNK(child_info.st_mode)
                    or not stat.S_ISREG(child_info.st_mode)
                    or (
                        child.name not in CONSOLE_FILES
                        and allowed_temporary.fullmatch(child.name) is None
                    )
                ):
                    raise RetainedControlError("partial retained Console output is unknown")
                child.unlink()
            entry.rmdir()
            continue
        info = entry.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or (entry.name not in allowed_files and allowed_temporary.fullmatch(entry.name) is None)
        ):
            raise RetainedControlError("partial retained-control output is unknown")
        entry.unlink()


def prepare_rebaseline(
    *,
    source_database: Path,
    source_profile: Path,
    console_state_root: Path,
    output_root: Path,
    expected_uid: int | None = None,
    database_generation: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build one root-private, digest-bound retained-control transaction."""

    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    output_root = _private_root(output_root, expected_uid=uid)
    manifest_path = output_root / "retained-control.json"
    source_database = source_database.expanduser().absolute()
    source_profile = source_profile.expanduser().absolute()
    console_state_root = console_state_root.expanduser().absolute()
    for path, label in (
        (source_database, "source authority"),
        (source_profile, "source profile"),
        (console_state_root, "Console state root"),
    ):
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise RetainedControlError(f"{label} is unavailable") from error
        if resolved != path:
            raise RetainedControlError(f"{label} path is not canonical")
    console_info = console_state_root.lstat()
    if stat.S_ISLNK(console_info.st_mode) or not stat.S_ISDIR(console_info.st_mode):
        raise RetainedControlError("Console state root is not a real directory")
    source_database_identity = _file_identity(source_database)
    source_profile_identity = _file_identity(source_profile, maximum=MAX_CONSOLE_BYTES)
    if manifest_path.exists() or manifest_path.is_symlink():
        _regular(manifest_path, maximum=MAX_CONSOLE_BYTES)
        return _load_prepared_transaction(
            manifest_path,
            source_database=source_database_identity,
            source_profile=source_profile_identity,
            console_state_root=console_state_root,
        )
    _discard_incomplete_staging(output_root)
    generation = database_generation or str(uuid.uuid4())
    if _IDENTIFIER.fullmatch(generation) is None:
        raise RetainedControlError("new database generation is invalid")
    recorded_at = timestamp or _now()

    source = sqlite3.connect(f"{source_database.as_uri()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    target_path = output_root / "authority.sqlite3"
    if target_path.exists():
        raise RetainedControlError("retained authority output already exists")
    target = sqlite3.connect(target_path)
    target.row_factory = sqlite3.Row
    try:
        source.execute("PRAGMA query_only=ON")
        if str(source.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
            raise RetainedControlError("source authority quick-check failed")
        metadata = source.execute(
            "SELECT schema_version,database_generation FROM schema_metadata WHERE singleton=1"
        ).fetchone()
        if metadata is None or type(metadata[0]) is not int:
            raise RetainedControlError("source authority metadata is invalid")
        source_schema = int(metadata[0])
        if source_schema != REBASELINE_SOURCE_SCHEMA:
            raise RetainedControlError(
                "retained-control rebaseline accepts exactly authority schema 15"
            )
        source_table_names = _tables(source)
        required_source_tables = set(SCHEMA_15_RETAINED_COLUMNS)
        if not required_source_tables <= source_table_names:
            raise RetainedControlError(
                "schema-15 authority omitted retained collections: "
                + ", ".join(sorted(required_source_tables - source_table_names))
            )
        for table, expected_columns in SCHEMA_15_RETAINED_COLUMNS.items():
            if _columns(source, table) != expected_columns:
                raise RetainedControlError(
                    f"retained {table} columns differ from frozen schema 15"
                )
        for table, expected_columns in SCHEMA_15_RETIRED_COLUMNS.items():
            if table in source_table_names and _columns(source, table) != expected_columns:
                raise RetainedControlError(
                    f"retired {table} columns differ from frozen schema 15"
                )
        unknown = sorted(source_table_names - _known_source_tables())
        if unknown:
            raise RetainedControlError("source authority has unknown collections: " + ", ".join(unknown))

        target.execute("PRAGMA foreign_keys=ON")
        target.execute("PRAGMA synchronous=FULL")
        target.execute("BEGIN IMMEDIATE")
        initialize_schema(target, database_generation=generation, timestamp=recorded_at)
        _execute_script(target, BROKER_SCHEMA)
        counts: dict[str, int] = {}
        # Hosts/repositories must precede the topology that their insert trigger creates.
        for table, transform in RETAINED_COLLECTIONS[:2]:
            counts[table] = _copy_collection(source, target, table, transform)
        counts.update(_copy_repository_topology(source, target))
        for table, transform in RETAINED_COLLECTIONS[2:]:
            counts[table] = _copy_collection(source, target, table, transform)
        target.execute(
            """
            INSERT INTO worker_supervisor_states(
                server_definition_id,repo_id,state,supervisor_epoch,
                supervisor_generation,current_attempt_id,last_attempt_id,
                next_restart_at,last_error_code,last_error_message,updated_at
            )
            SELECT server_definition_id,repo_id,
                   CASE
                     WHEN breaker_state='tripped' THEN 'tripped'
                     WHEN desired_state='stopped' THEN 'stopped'
                     ELSE 'idle'
                   END,
                   NULL,0,NULL,NULL,NULL,NULL,NULL,?
            FROM worker_policies
            ORDER BY server_definition_id
            """,
            (recorded_at,),
        )
        counts["worker_supervisor_states"] = int(
            target.execute("SELECT COUNT(*) FROM worker_supervisor_states").fetchone()[0]
        )
        _validate_compose_controls(target)
        target.execute(
            """
            UPDATE schema_metadata
            SET state_revision=0, observation_revision=0, authority_mode='sqlite',
                migration_state='ready', first_sqlite_mutation_at=?, updated_at=?
            WHERE singleton=1
            """,
            (recorded_at, recorded_at),
        )
        violations = invariant_violations(target)
        if violations:
            raise RetainedControlError(
                "retained authority violates current invariants: "
                + "; ".join(f"{item.code}: {item.detail}" for item in violations[:10])
            )
        if target.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RetainedControlError("retained authority has a foreign-key violation")
        profile = _profile_document(target)
        target.commit()
    except BaseException:
        target.rollback()
        raise
    finally:
        target.close()
        source.close()
    os.chmod(target_path, 0o600)
    _verify_file_identity(source_database, source_database_identity)
    _verify_file_identity(source_profile, source_profile_identity)

    profile_payload = json.dumps(profile, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    target_profile = output_root / "client-profiles.json"
    _atomic_bytes(target_profile, profile_payload, 0o600)
    console_files, console_counts, console_sources = _console_view(
        console_state_root, output_root
    )
    for name, evidence in console_sources.items():
        _verify_optional_identity(console_state_root / name, evidence)

    secret_refs: list[dict[str, str]] = []
    for repository in profile["repositories"]:
        for name, policy in sorted(repository["ephemeral_secret_policies"].items()):
            secret_refs.append(
                {
                    "repository_id": repository["repo_id"],
                    "template": name,
                    "policy": policy["policy"],
                    "binding_sha256": _digest_bytes(policy["binding_id"].encode("utf-8")),
                }
            )
    external_secret_transport: dict[str, dict[str, object]] = {}
    for name in SECRET_TRANSPORT_FILES:
        path = console_state_root / name
        if not path.exists() and not path.is_symlink():
            continue
        info = _regular(path, maximum=16 * 1024 * 1024)
        external_secret_transport[name] = {
            "present": True,
            "bytes": info.st_size,
            "sha256": _digest_file(path),
            "transport": "preserved-external",
        }

    retained_names = {name for name, _transform in RETAINED_COLLECTIONS} | {
        "repository_families",
        "repository_scopes",
    }
    rejected = sorted(source_table_names - retained_names - {"schema_metadata"})
    manifest: dict[str, Any] = {
        "schema_version": VERSION,
        "kind": KIND,
        "source": {
            "database": source_database_identity,
            "schema_version": source_schema,
            "database_generation": str(metadata[1]),
            "profile": source_profile_identity,
        },
        "target": {
            "database": _file_identity(target_path),
            "schema_version": SCHEMA_VERSION,
            "database_generation": generation,
            "profile": _file_identity(target_profile),
        },
        "retained_collections": counts,
        "rejected_collections": rejected,
        "console_files": console_files,
        "console_sources": console_sources,
        "console_counts": console_counts,
        "redacted_secret_references": secret_refs,
        "external_secret_transport": external_secret_transport,
        "created_at": recorded_at,
    }
    manifest["document_sha256"] = _digest_bytes(_canonical(manifest))
    _atomic_bytes(
        manifest_path,
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        0o600,
    )
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-database", type=Path, required=True)
    result.add_argument("--source-profile", type=Path, required=True)
    result.add_argument("--console-state-root", type=Path, required=True)
    result.add_argument("--output-root", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise RetainedControlError("retained-control rebaseline must run as root")
        result = prepare_rebaseline(
            source_database=arguments.source_database,
            source_profile=arguments.source_profile,
            console_state_root=arguments.console_state_root,
            output_root=arguments.output_root,
        )
    except (OSError, sqlite3.Error, RetainedControlError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
