"""Verified PostgreSQL artifact registry for normalized coordinator stores."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Mapping

from .store import (
    AccountStore,
    deterministic_id,
    fingerprint,
    refuse_symlink_components,
    utc_timestamp,
)


_FULL_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1024 * 1024


def _absolute_unresolved(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(candidate))


def _validate_private_path(path: Path, expected_uid: int) -> os.stat_result:
    refuse_symlink_components(path)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise PermissionError(
            "backup artifact directory must be an expected-UID mode-0700 directory"
        )
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PermissionError("backup evidence must be a real regular file")
    if metadata.st_uid != expected_uid:
        raise PermissionError(
            f"backup evidence is owned by uid {metadata.st_uid}, not {expected_uid}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("backup evidence must be private mode 0600")
    return metadata


def _read_private_bytes(
    path: Path,
    *,
    expected_uid: int,
    maximum_bytes: int | None,
) -> tuple[bytes | None, str, os.stat_result]:
    before = _validate_private_path(path, expected_uid)
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        raise ValueError("backup manifest exceeds the bounded size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if identity != (before.st_dev, before.st_ino):
            raise RuntimeError("backup evidence identity changed while opening")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PermissionError("opened backup evidence lost its private identity")
        chunks: list[bytes] | None = [] if maximum_bytes is not None else None
        digest = hashlib.sha256()
        remaining = None if maximum_bytes is None else maximum_bytes + 1
        while remaining is None or remaining > 0:
            request_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = os.read(descriptor, request_size)
            if not chunk:
                break
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        payload = None if chunks is None else b"".join(chunks)
        if maximum_bytes is not None and payload is not None and len(payload) > maximum_bytes:
            raise ValueError("backup manifest exceeds the bounded size limit")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        material_before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        material_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        path_identity_after = (path_after.st_dev, path_after.st_ino)
        if material_before != material_after or path_identity_after != identity:
            raise RuntimeError("backup evidence changed while it was being read")
        return payload, digest.hexdigest(), after
    finally:
        os.close(descriptor)


def inspect_database_backup(
    artifact_path: str | Path,
    manifest_path: str | Path | None = None,
    *,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    """Return bounded verified evidence for one published backup artifact."""

    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    if uid < 0:
        raise ValueError("expected_uid must be non-negative")
    artifact = _absolute_unresolved(artifact_path)
    manifest = (
        _absolute_unresolved(manifest_path)
        if manifest_path is not None
        else Path(f"{artifact}.manifest.json")
    )
    _artifact_bytes, artifact_digest, artifact_metadata = _read_private_bytes(
        artifact, expected_uid=uid, maximum_bytes=None
    )
    manifest_bytes, manifest_digest, manifest_metadata = _read_private_bytes(
        manifest, expected_uid=uid, maximum_bytes=_MAX_MANIFEST_BYTES
    )
    if manifest_bytes is None:
        raise RuntimeError("bounded manifest read returned no bytes")
    if (artifact_metadata.st_dev, artifact_metadata.st_ino) == (
        manifest_metadata.st_dev,
        manifest_metadata.st_ino,
    ):
        raise ValueError("backup artifact and manifest must be distinct files")
    try:
        payload = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("backup manifest is not valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("backup manifest root must be an object")
    if payload.get("type") != "postgres-docker-backup" or payload.get("schema_version") != 2:
        raise ValueError("backup manifest is not a postgres-docker-backup v2 manifest")
    scope = str(payload.get("scope") or "")
    backup_format = str(payload.get("format") or "")
    if scope not in {"database", "cluster"}:
        raise ValueError("backup manifest has an unsupported scope")
    if backup_format not in {"custom", "plain", "all"}:
        raise ValueError("backup manifest has an unsupported format")
    if (scope == "cluster") != (backup_format == "all"):
        raise ValueError("backup scope and format do not match")
    source = payload.get("source")
    source = source if isinstance(source, Mapping) else {}
    container = source.get("container")
    container = container if isinstance(container, Mapping) else {}
    postgres = source.get("postgres")
    postgres = postgres if isinstance(postgres, Mapping) else {}
    container_id = str(container.get("id") or "").lower()
    if not _FULL_CONTAINER_ID.fullmatch(container_id):
        raise ValueError("backup manifest lacks an exact immutable container ID")
    database_name = postgres.get("database")
    if scope == "database":
        if not isinstance(database_name, str) or not database_name.strip():
            raise ValueError("database backup manifest lacks its source database")
        database_name = database_name.strip()
    elif database_name is not None:
        raise ValueError("cluster backup manifest must not claim one database")
    expected_path = str(payload.get("path") or "")
    canonical_artifact = artifact.resolve(strict=True)
    canonical_manifest = manifest.resolve(strict=True)
    if expected_path and Path(expected_path).expanduser().resolve() != canonical_artifact:
        raise ValueError("backup manifest path does not match the selected artifact")
    expected_size = payload.get("size")
    if type(expected_size) is not int or expected_size <= 0:
        raise ValueError("backup manifest lacks a positive artifact size")
    if artifact_metadata.st_size != expected_size:
        raise ValueError("backup artifact size does not match its manifest")
    artifact_sha256 = str(payload.get("sha256") or "").lower()
    if not _SHA256.fullmatch(artifact_sha256):
        raise ValueError("backup manifest lacks a valid SHA-256 checksum")
    if artifact_digest != artifact_sha256:
        raise ValueError("backup artifact checksum does not match its manifest")
    verification = payload.get("verification")
    verification = verification if isinstance(verification, Mapping) else None
    verification_status = "unverified"
    verification_mode = None
    verified_at = None
    if verification is not None:
        if verification.get("ok") is not True:
            raise ValueError("backup manifest contains a failed verification record")
        if str(verification.get("sha256") or "").lower() != artifact_sha256:
            raise ValueError("backup verification checksum does not match the artifact")
        verification_mode = str(verification.get("mode") or "")
        if verification_mode not in {"lightweight", "test_restore"}:
            raise ValueError("backup manifest contains an unsupported verification mode")
        if verification_mode == "test_restore":
            verification_target = verification.get("verification_target")
            catalog = verification.get("catalog_signature") or verification.get("catalog")
            if scope == "database":
                if verification_target != "scratch_database" or not isinstance(catalog, Mapping):
                    raise ValueError("database strong-verification evidence is incomplete")
                preflight = verification.get("container_identity_preflight")
                if (
                    not isinstance(preflight, Mapping)
                    or str(preflight.get("actual_id") or "").lower() != container_id
                ):
                    raise ValueError("database strong verification lacks exact source identity")
            elif verification_target != "disposable_cluster" or not isinstance(catalog, Mapping):
                raise ValueError("cluster strong-verification evidence is incomplete")
            verification_status = "strong"
        else:
            verification_status = "lightweight"
        verified_at = str(verification.get("verified_at") or "") or None
        if verified_at is None:
            raise ValueError("backup verification record lacks its timestamp")
    created_at = str(payload.get("created_at") or "")
    if not created_at:
        raise ValueError("backup manifest lacks its creation timestamp")
    return {
        "scope": scope,
        "source_container_id": container_id,
        "source_database_name": database_name,
        "source_identity_fingerprint": "sha256:"
        + fingerprint(
            {
                "container_id": container_id,
                "database_name": database_name,
                "scope": scope,
            }
        ),
        "artifact_path": str(canonical_artifact),
        "artifact_size_bytes": expected_size,
        "artifact_sha256": artifact_sha256,
        "manifest_path": str(canonical_manifest),
        "manifest_sha256": manifest_digest,
        "backup_format": backup_format,
        "verification_status": verification_status,
        "verification_mode": verification_mode,
        "created_at": created_at,
        "verified_at": verified_at,
    }


def upsert_database_backup(
    connection: sqlite3.Connection,
    descriptor: Mapping[str, Any],
) -> str:
    """Bind a verified artifact descriptor to exact normalized identities."""

    container_id = str(descriptor["source_container_id"])
    database_name = descriptor.get("source_database_name")
    resources = connection.execute(
        """
        SELECT docker_resource_id FROM docker_resources
        WHERE lower(full_container_id) = lower(?)
        ORDER BY docker_resource_id
        """,
        (container_id,),
    ).fetchall()
    if len(resources) > 1:
        raise ValueError("immutable container ID maps to multiple normalized resources")
    docker_resource_id = str(resources[0][0]) if resources else None
    database_binding_id = None
    if docker_resource_id is not None and database_name is not None:
        binding = connection.execute(
            """
            SELECT database_binding_id FROM database_bindings
            WHERE docker_resource_id = ? AND database_name = ?
            """,
            (docker_resource_id, str(database_name)),
        ).fetchone()
        database_binding_id = str(binding[0]) if binding is not None else None
    repo_id = None
    source_id = None
    if docker_resource_id is not None:
        membership = connection.execute(
            """
            SELECT repo_id, control_binding_id FROM repository_memberships
            WHERE resource_kind = 'container' AND host_resource_id = ?
            """,
            (docker_resource_id,),
        ).fetchone()
        if membership is not None:
            repo_id = str(membership["repo_id"])
            if membership["control_binding_id"] is not None:
                source = connection.execute(
                    "SELECT source_id FROM control_bindings WHERE binding_id = ?",
                    (membership["control_binding_id"],),
                ).fetchone()
                source_id = str(source[0]) if source is not None else None
    backup_id = deterministic_id(
        "database-backup",
        descriptor["artifact_path"],
        descriptor["artifact_sha256"],
    )
    now = utc_timestamp()
    connection.execute(
        """
        INSERT INTO database_backups(
            database_backup_id, database_binding_id, docker_resource_id,
            repo_id, source_id, scope, source_container_id,
            source_database_name, source_identity_fingerprint,
            artifact_path, artifact_size_bytes, artifact_sha256,
            manifest_path, manifest_sha256, backup_format,
            verification_status, verification_mode, created_at, verified_at,
            status, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                  'available', ?)
        ON CONFLICT(database_backup_id) DO UPDATE SET
            database_binding_id = excluded.database_binding_id,
            docker_resource_id = excluded.docker_resource_id,
            repo_id = excluded.repo_id,
            source_id = excluded.source_id,
            manifest_sha256 = excluded.manifest_sha256,
            verification_status = excluded.verification_status,
            verification_mode = excluded.verification_mode,
            verified_at = excluded.verified_at,
            status = 'available',
            updated_at = excluded.updated_at
        """,
        (
            backup_id,
            database_binding_id,
            docker_resource_id,
            repo_id,
            source_id,
            descriptor["scope"],
            container_id,
            database_name,
            descriptor["source_identity_fingerprint"],
            descriptor["artifact_path"],
            descriptor["artifact_size_bytes"],
            descriptor["artifact_sha256"],
            descriptor["manifest_path"],
            descriptor["manifest_sha256"],
            descriptor["backup_format"],
            descriptor["verification_status"],
            descriptor.get("verification_mode"),
            descriptor["created_at"],
            descriptor.get("verified_at"),
            now,
        ),
    )
    return backup_id


def reconcile_inventory_backups(
    connection: sqlite3.Connection,
    inventory: Mapping[str, Any],
) -> list[str]:
    """Import only manifests whose artifact evidence verifies now."""

    imported: list[str] = []
    for item in inventory.get("backups") or []:
        if not isinstance(item, Mapping):
            continue
        artifact_path = item.get("path")
        manifest_path = item.get("manifest")
        if not artifact_path or not manifest_path:
            continue
        try:
            descriptor = inspect_database_backup(artifact_path, manifest_path)
        except (OSError, ValueError):
            continue
        imported.append(upsert_database_backup(connection, descriptor))
    return imported


def record_successful_restore(
    connection: sqlite3.Connection,
    *,
    database_backup_id: str,
    target_container_id: str,
    target_database_name: str,
    result: Mapping[str, Any],
    safety_database_backup_id: str | None = None,
) -> str:
    """Persist one completed transactional restore; failures never enter the ledger."""

    backup = connection.execute(
        """
        SELECT artifact_path, artifact_sha256, scope FROM database_backups
        WHERE database_backup_id = ? AND status = 'available'
        """,
        (database_backup_id,),
    ).fetchone()
    if backup is None:
        raise ValueError("restore source is not an available registered backup")
    target_id = str(target_container_id).lower()
    if not _FULL_CONTAINER_ID.fullmatch(target_id):
        raise ValueError("restore target requires an exact immutable container ID")
    if backup["scope"] != "database":
        raise ValueError("only a database-scoped backup can record an in-place restore")
    incoming = result.get("incoming_verification")
    preflights = result.get("container_identity_preflights")
    restored_signature = result.get("restored_catalog_signature")
    if (
        result.get("transactional") is not True
        or result.get("scope") != "database"
        or str(result.get("sha256") or "").lower() != backup["artifact_sha256"]
        or Path(str(result.get("restored") or "")).expanduser().resolve()
        != Path(str(backup["artifact_path"])).resolve()
        or str(result.get("database") or "") != target_database_name
        or not isinstance(incoming, Mapping)
        or incoming.get("test_restore") is not True
        or incoming.get("verification_target") != "scratch_database"
        or incoming.get("restore_returncode") != 0
        or incoming.get("scratch_created") is not True
        or not isinstance(incoming.get("catalog_signature"), Mapping)
        or not isinstance(restored_signature, Mapping)
        or dict(incoming["catalog_signature"]) != dict(restored_signature)
        or not isinstance(preflights, list)
        or len(preflights) < 3
        or any(
            not isinstance(item, Mapping)
            or str(item.get("actual_id") or "").lower() != target_id
            for item in preflights
        )
    ):
        raise ValueError(
            "restore result lacks exact transactional, strong-verification, identity, or catalog evidence"
        )
    if safety_database_backup_id is not None:
        safety = connection.execute(
            """
            SELECT verification_status, status, source_container_id,
                   source_database_name
            FROM database_backups WHERE database_backup_id = ?
            """,
            (safety_database_backup_id,),
        ).fetchone()
        if (
            safety is None
            or safety["status"] != "available"
            or safety["verification_status"] != "strong"
            or str(safety["source_container_id"]).lower() != target_id
            or str(safety["source_database_name"] or "") != target_database_name
        ):
            raise ValueError("restore safety backup lacks exact strong target evidence")
    resource = connection.execute(
        "SELECT docker_resource_id FROM docker_resources WHERE lower(full_container_id) = lower(?)",
        (target_id,),
    ).fetchone()
    docker_resource_id = str(resource[0]) if resource is not None else None
    binding = None
    if docker_resource_id is not None:
        binding = connection.execute(
            """
            SELECT database_binding_id FROM database_bindings
            WHERE docker_resource_id = ? AND database_name = ?
            """,
            (docker_resource_id, target_database_name),
        ).fetchone()
    database_binding_id = str(binding[0]) if binding is not None else None
    restored_at = utc_timestamp()
    result_fingerprint = "sha256:" + fingerprint(dict(result))
    restore_event_id = deterministic_id(
        "database-restore",
        database_backup_id,
        target_id,
        target_database_name,
        restored_at,
        result_fingerprint,
    )
    connection.execute(
        """
        INSERT INTO database_restore_events(
            restore_event_id, database_backup_id, target_database_binding_id,
            target_docker_resource_id, target_container_id,
            target_database_name, artifact_sha256,
            safety_database_backup_id, result_fingerprint, restored_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            restore_event_id,
            database_backup_id,
            database_binding_id,
            docker_resource_id,
            target_id,
            target_database_name,
            backup["artifact_sha256"],
            safety_database_backup_id,
            result_fingerprint,
            restored_at,
        ),
    )
    connection.execute(
        """
        UPDATE database_backups
        SET last_restored_at = ?, restore_count = restore_count + 1,
            updated_at = ? WHERE database_backup_id = ?
        """,
        (restored_at, restored_at, database_backup_id),
    )
    return restore_event_id


def existing_account_store_path(home: str | Path | None = None) -> Path | None:
    """Resolve an already-created account store without creating state."""

    configured = home
    if configured is None:
        configured = os.environ.get("CODEX_AGENT_COORDINATOR_HOME")
    root = (
        Path(configured).expanduser()
        if configured is not None
        else Path.home() / ".codex" / "agent-coordinator"
    )
    database = _absolute_unresolved(root / "coordinator.sqlite3")
    return database if database.exists() else None


def register_backup_in_existing_account_store(
    artifact_path: str | Path,
    manifest_path: str | Path | None = None,
    *,
    coordinator_home: str | Path | None = None,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    """Register a real artifact if the normalized account store already exists."""

    database = existing_account_store_path(coordinator_home)
    if database is None:
        return {"status": "not_configured"}
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    descriptor = inspect_database_backup(
        artifact_path, manifest_path, expected_uid=uid
    )
    with AccountStore.open(database, expected_uid=uid) as store:
        with store.immediate_transaction() as connection:
            backup_id = upsert_database_backup(connection, descriptor)
    return {
        "status": "registered",
        "database_backup_id": backup_id,
        "verification_status": descriptor["verification_status"],
    }


def register_restore_in_existing_account_store(
    *,
    artifact_path: str | Path,
    result: Mapping[str, Any],
    target_container_id: str,
    target_database_name: str,
    safety_artifact_path: str | Path | None = None,
    coordinator_home: str | Path | None = None,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    """Atomically register source/safety artifacts and one proved restore."""

    database = existing_account_store_path(coordinator_home)
    if database is None:
        return {"status": "not_configured"}
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    incoming = inspect_database_backup(artifact_path, expected_uid=uid)
    if incoming["verification_status"] != "strong":
        raise ValueError("restore registry requires a strongly verified source manifest")
    safety = (
        inspect_database_backup(safety_artifact_path, expected_uid=uid)
        if safety_artifact_path is not None
        else None
    )
    if safety is not None and safety["verification_status"] != "strong":
        raise ValueError("restore registry requires a strongly verified safety backup")
    with AccountStore.open(database, expected_uid=uid) as store:
        with store.immediate_transaction() as connection:
            backup_id = upsert_database_backup(connection, incoming)
            safety_id = (
                upsert_database_backup(connection, safety)
                if safety is not None
                else None
            )
            restore_event_id = record_successful_restore(
                connection,
                database_backup_id=backup_id,
                target_container_id=target_container_id,
                target_database_name=target_database_name,
                result=result,
                safety_database_backup_id=safety_id,
            )
    return {
        "status": "registered",
        "database_backup_id": backup_id,
        "safety_database_backup_id": safety_id,
        "restore_event_id": restore_event_id,
    }
