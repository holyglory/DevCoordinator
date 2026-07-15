"""Transactional binary backup, logical export, and restore for normalized stores."""

from __future__ import annotations

import base64
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any, Mapping
import uuid

from .database_backups import _read_private_bytes
from .schema import SCHEMA_VERSION, initialize_schema, invariant_violations
from .store import (
    AccountStore,
    canonical_json,
    ensure_private_store_directory,
    exclusive_maintenance_lock,
    refuse_symlink_components,
    utc_timestamp,
)


STORE_BACKUP_TYPE = "devcoordinator-sqlite-backup"
STORE_EXPORT_TYPE = "devcoordinator-sqlite-export"
STORE_FORENSIC_TYPE = "devcoordinator-corrupt-store-forensic"
STORE_ARTIFACT_SCHEMA = 1
STORE_EXPORT_FORMAT = "normalized-table-set-v1"
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_EXPORT_BYTES = 512 * 1024 * 1024


def _ensure_outside_git(path: Path) -> None:
    for candidate in (path, *path.parents):
        marker = candidate / ".git"
        if marker.exists() or marker.is_symlink():
            raise ValueError(f"coordinator store backup root must be outside Git: {path}")


def _private_output_root(path: str | os.PathLike[str], expected_uid: int) -> Path:
    root = Path(path).expanduser()
    if not root.is_absolute():
        raise ValueError("coordinator store backup root must be absolute")
    root = Path(os.path.abspath(root))
    _ensure_outside_git(root)
    ensure_private_store_directory(root, expected_uid=expected_uid)
    return root


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_staging_file(directory: Path, name: str) -> tuple[int, Path]:
    path = directory / f".{name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    return descriptor, path


def _publish_private_bytes(path: Path, payload: bytes) -> None:
    descriptor, staging = _private_staging_file(path.parent, path.name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(staging, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            staging.unlink()


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$base64": base64.b64encode(value).decode("ascii")}
    return value


def _decode_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if set(value) != {"$base64"} or not isinstance(value["$base64"], str):
            raise ValueError("logical export contains an unsupported encoded value")
        try:
            return base64.b64decode(value["$base64"], validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("logical export contains invalid base64 data") from error
    if value is None or isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return value
    raise ValueError("logical export contains a non-SQLite value")


def _schema_descriptor(connection: sqlite3.Connection) -> dict[str, Any]:
    """Return a deterministic structural contract for every normalized table."""

    tables: dict[str, Any] = {}
    names = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        )
    ]
    for name in names:
        columns = [
            {
                "cid": int(row[0]),
                "name": str(row[1]),
                "type": str(row[2]),
                "not_null": bool(row[3]),
                "default": row[4],
                "primary_key_ordinal": int(row[5]),
                "hidden": int(row[6]),
            }
            for row in connection.execute(f'PRAGMA table_xinfo("{name}")')
        ]
        foreign_keys = sorted(
            (
                {
                    "id": int(row[0]),
                    "sequence": int(row[1]),
                    "table": str(row[2]),
                    "from": str(row[3]),
                    "to": None if row[4] is None else str(row[4]),
                    "on_update": str(row[5]),
                    "on_delete": str(row[6]),
                    "match": str(row[7]),
                }
                for row in connection.execute(f'PRAGMA foreign_key_list("{name}")')
            ),
            key=lambda item: (item["id"], item["sequence"]),
        )
        indexes: list[dict[str, Any]] = []
        for index in connection.execute(f'PRAGMA index_list("{name}")'):
            index_name = str(index[1])
            index_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                (index_name,),
            ).fetchone()
            indexes.append(
                {
                    "name": index_name,
                    "unique": bool(index[2]),
                    "origin": str(index[3]),
                    "partial": bool(index[4]),
                    "sql": None if index_sql is None else index_sql[0],
                    "columns": [
                        {
                            "sequence": int(column[0]),
                            "cid": int(column[1]),
                            "name": None if column[2] is None else str(column[2]),
                            "descending": bool(column[3]),
                            "collation": None if column[4] is None else str(column[4]),
                            "key": bool(column[5]),
                        }
                        for column in connection.execute(
                            f'PRAGMA index_xinfo("{index_name}")'
                        )
                    ],
                }
            )
        tables[name] = {
            "columns": columns,
            "foreign_keys": foreign_keys,
            "indexes": sorted(indexes, key=lambda item: item["name"]),
        }
    return {"tables": tables}


def _table_rows(connection: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    tables: dict[str, list[dict[str, Any]]] = {}
    names = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        )
    ]
    for name in names:
        columns = [
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{name}")')
        ]
        quoted = ", ".join(f'"{column}"' for column in columns)
        order = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(
            f'SELECT {quoted} FROM "{name}" ORDER BY {order}'
        ).fetchall()
        tables[name] = [
            {column: _encode_value(row[index]) for index, column in enumerate(columns)}
            for row in rows
        ]
    return tables


def _control_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    metadata = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               observation_revision, authority_mode, migration_state
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    if metadata is None:
        raise ValueError("normalized store metadata is missing")
    tables = _table_rows(connection)
    schema = _schema_descriptor(connection)
    return {
        "metadata": dict(metadata),
        "table_counts": {name: len(rows) for name, rows in tables.items()},
        "schema": schema,
        "schema_fingerprint": hashlib.sha256(
            canonical_json(schema).encode("utf-8")
        ).hexdigest(),
        "control_fingerprint": hashlib.sha256(
            canonical_json(tables).encode("utf-8")
        ).hexdigest(),
    }


def _validate_sqlite(path: Path) -> dict[str, Any]:
    uri = f"file:{path}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if [str(row[0]) for row in integrity] != ["ok"]:
            raise ValueError("SQLite backup failed integrity_check")
        foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign:
            raise ValueError("SQLite backup contains foreign-key violations")
        violations = invariant_violations(connection)
        if violations:
            raise ValueError(
                "SQLite backup contains coordinator invariant violations: "
                + "; ".join(f"{item.code}: {item.detail}" for item in violations)
            )
        summary = _control_summary(connection)
        if int(summary["metadata"]["schema_version"]) != SCHEMA_VERSION:
            raise ValueError("SQLite backup schema version is unsupported")
        return summary
    finally:
        connection.close()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(
    *,
    artifact: Path,
    artifact_type: str,
    store_role: str,
    summary: Mapping[str, Any],
) -> Path:
    manifest_path = Path(f"{artifact}.manifest.json")
    manifest = {
        "artifact_schema": STORE_ARTIFACT_SCHEMA,
        "type": artifact_type,
        "store_role": store_role,
        "created_at": utc_timestamp(),
        "artifact_path": str(artifact),
        "artifact_size_bytes": artifact.stat().st_size,
        "artifact_sha256": _sha256_file(artifact),
        "schema_version": summary["metadata"]["schema_version"],
        "schema_fingerprint": summary["schema_fingerprint"],
        "database_generation": summary["metadata"]["database_generation"],
        "state_revision": summary["metadata"]["state_revision"],
        "observation_revision": summary["metadata"]["observation_revision"],
        "control_fingerprint": summary["control_fingerprint"],
        "table_counts": summary["table_counts"],
        "verification": {
            "status": "verified",
            "verified_at": utc_timestamp(),
            "integrity_check": "ok",
            "foreign_key_check": "ok",
            "coordinator_invariants": "ok",
        },
    }
    _publish_private_bytes(
        manifest_path, (canonical_json(manifest) + "\n").encode("utf-8")
    )
    return manifest_path


def create_store_backup(
    database_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    store_role: str,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    """Create one online WAL-consistent, strongly verified SQLite backup."""

    if store_role not in {"account", "service"}:
        raise ValueError("store_role must be account or service")
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    root = _private_output_root(output_root, uid)
    database = Path(database_path).expanduser()
    if not database.is_absolute():
        raise ValueError("coordinator database path must be absolute")
    with AccountStore.open(database, expected_uid=uid) as source:
        return _backup_from_connection(source.connection, root, store_role=store_role)


def _backup_from_connection(
    source_connection: sqlite3.Connection,
    root: Path,
    *,
    store_role: str,
) -> dict[str, Any]:
    name = f"{store_role}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex}.sqlite3"
    artifact = root / name
    descriptor, staging = _private_staging_file(root, name)
    os.close(descriptor)
    try:
        destination = sqlite3.connect(str(staging), isolation_level=None)
        try:
            source_connection.backup(destination)
            destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            destination.close()
        os.chmod(staging, 0o600)
        with staging.open("rb") as handle:
            os.fsync(handle.fileno())
        summary = _validate_sqlite(staging)
        os.link(staging, artifact)
        os.chmod(artifact, 0o600)
        _fsync_directory(root)
        manifest = _write_manifest(
            artifact=artifact,
            artifact_type=STORE_BACKUP_TYPE,
            store_role=store_role,
            summary=summary,
        )
        return {
            "status": "verified",
            "backup": str(artifact),
            "manifest": str(manifest),
            **summary,
        }
    finally:
        with suppress(FileNotFoundError):
            staging.unlink()


def create_store_export(
    database_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    store_role: str,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    """Create a deterministic private logical export that can be imported."""

    if store_role not in {"account", "service"}:
        raise ValueError("store_role must be account or service")
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    root = _private_output_root(output_root, uid)
    database = Path(database_path).expanduser()
    with AccountStore.open(database, expected_uid=uid) as store:
        with store.read_transaction() as connection:
            summary = _control_summary(connection)
            tables = _table_rows(connection)
    document = {
        "artifact_schema": STORE_ARTIFACT_SCHEMA,
        "type": STORE_EXPORT_TYPE,
        "logical_format": STORE_EXPORT_FORMAT,
        "store_role": store_role,
        "created_at": utc_timestamp(),
        "restorable": True,
        "schema_version": summary["metadata"]["schema_version"],
        "schema": summary["schema"],
        "schema_fingerprint": summary["schema_fingerprint"],
        "metadata": summary["metadata"],
        "table_counts": summary["table_counts"],
        "control_fingerprint": summary["control_fingerprint"],
        "tables": tables,
    }
    artifact = root / (
        f"{store_role}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
        f"{uuid.uuid4().hex}.json"
    )
    _publish_private_bytes(
        artifact, (canonical_json(document) + "\n").encode("utf-8")
    )
    manifest = _write_manifest(
        artifact=artifact,
        artifact_type=STORE_EXPORT_TYPE,
        store_role=store_role,
        summary=summary,
    )
    return {
        "status": "verified",
        "export": str(artifact),
        "manifest": str(manifest),
        **summary,
    }


def _read_store_manifest(
    manifest_path: str | os.PathLike[str],
    *,
    expected_uid: int,
) -> tuple[dict[str, Any], Path]:
    manifest = Path(manifest_path).expanduser()
    if not manifest.is_absolute():
        raise ValueError("store artifact manifest path must be absolute")
    manifest = Path(os.path.abspath(manifest))
    payload, _digest, _metadata = _read_private_bytes(
        manifest, expected_uid=expected_uid, maximum_bytes=_MAX_MANIFEST_BYTES
    )
    if payload is None:
        raise RuntimeError("bounded manifest read returned no bytes")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("store artifact manifest is invalid JSON") from error
    if not isinstance(document, dict):
        raise ValueError("store artifact manifest root must be an object")
    return document, manifest


def _artifact_from_manifest(
    document: Mapping[str, Any],
    *,
    expected_uid: int,
    maximum_bytes: int | None,
) -> tuple[Path, bytes | None]:
    artifact = Path(str(document.get("artifact_path") or "")).expanduser()
    if not artifact.is_absolute():
        raise ValueError("store artifact manifest lacks an absolute artifact path")
    artifact = Path(os.path.abspath(artifact))
    payload, artifact_digest, artifact_metadata = _read_private_bytes(
        artifact, expected_uid=expected_uid, maximum_bytes=maximum_bytes
    )
    if (
        not isinstance(document.get("artifact_sha256"), str)
        or artifact_digest != document["artifact_sha256"]
        or type(document.get("artifact_size_bytes")) is not int
        or artifact_metadata.st_size != document["artifact_size_bytes"]
    ):
        raise ValueError("store artifact does not match its manifest")
    return artifact, payload


def _require_role(
    document: Mapping[str, Any], expected_role: str | None
) -> str:
    role = str(document.get("store_role") or "")
    if role not in {"account", "service"} or (
        expected_role is not None and role != expected_role
    ):
        raise ValueError("store artifact role does not match the restore target")
    return role


def inspect_store_backup(
    manifest_path: str | os.PathLike[str],
    *,
    expected_uid: int | None = None,
    expected_role: str | None = None,
) -> dict[str, Any]:
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    document, manifest = _read_store_manifest(
        manifest_path, expected_uid=uid
    )
    if (
        document.get("type") != STORE_BACKUP_TYPE
        or document.get("artifact_schema") != STORE_ARTIFACT_SCHEMA
        or document.get("verification", {}).get("status") != "verified"
    ):
        raise ValueError("store restore requires a verified binary backup manifest")
    _require_role(document, expected_role)
    artifact, _payload = _artifact_from_manifest(
        document, expected_uid=uid, maximum_bytes=None
    )
    summary = _validate_sqlite(artifact)
    if (
        summary["control_fingerprint"] != document.get("control_fingerprint")
        or summary["schema_fingerprint"] != document.get("schema_fingerprint")
        or summary["metadata"]["database_generation"]
        != document.get("database_generation")
        or summary["table_counts"] != document.get("table_counts")
    ):
        raise ValueError("store backup normalized control evidence does not match")
    return {"manifest": dict(document), "artifact": artifact, "summary": summary}


def inspect_store_export(
    manifest_path: str | os.PathLike[str],
    *,
    expected_uid: int | None = None,
    expected_role: str | None = None,
) -> dict[str, Any]:
    """Read and strictly verify one restorable logical store export."""

    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    manifest, manifest_file = _read_store_manifest(
        manifest_path, expected_uid=uid
    )
    if (
        manifest.get("type") != STORE_EXPORT_TYPE
        or manifest.get("artifact_schema") != STORE_ARTIFACT_SCHEMA
        or manifest.get("verification", {}).get("status") != "verified"
    ):
        raise ValueError("store import requires a verified logical export manifest")
    role = _require_role(manifest, expected_role)
    artifact, payload = _artifact_from_manifest(
        manifest, expected_uid=uid, maximum_bytes=_MAX_EXPORT_BYTES
    )
    if payload is None:
        raise RuntimeError("bounded logical export read returned no bytes")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("logical export is invalid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ValueError("logical export root must be an object")
    if (
        document.get("type") != STORE_EXPORT_TYPE
        or document.get("artifact_schema") != STORE_ARTIFACT_SCHEMA
        or document.get("logical_format") != STORE_EXPORT_FORMAT
        or document.get("restorable") is not True
        or document.get("store_role") != role
        or document.get("schema_version") != SCHEMA_VERSION
    ):
        raise ValueError("logical export format, role, or schema is unsupported")
    schema = document.get("schema")
    metadata = document.get("metadata")
    tables = document.get("tables")
    table_counts = document.get("table_counts")
    if not all(isinstance(item, dict) for item in (schema, metadata, tables, table_counts)):
        raise ValueError("logical export structural sections must be objects")
    if set(metadata) != {
        "schema_version",
        "database_generation",
        "state_revision",
        "observation_revision",
        "authority_mode",
        "migration_state",
    }:
        raise ValueError("logical export metadata contract is incomplete")
    if metadata["schema_version"] != SCHEMA_VERSION:
        raise ValueError("logical export metadata schema is unsupported")
    schema_fingerprint = hashlib.sha256(
        canonical_json(schema).encode("utf-8")
    ).hexdigest()
    if (
        schema_fingerprint != document.get("schema_fingerprint")
        or schema_fingerprint != manifest.get("schema_fingerprint")
    ):
        raise ValueError("logical export schema fingerprint does not match")
    schema_tables = schema.get("tables")
    if not isinstance(schema_tables, dict) or set(schema_tables) != set(tables):
        raise ValueError("logical export table set does not match its schema")
    normalized_tables: dict[str, list[dict[str, Any]]] = {}
    for table_name in sorted(tables):
        rows = tables[table_name]
        table_schema = schema_tables[table_name]
        if not isinstance(rows, list) or not isinstance(table_schema, dict):
            raise ValueError("logical export table data or schema is malformed")
        columns = table_schema.get("columns")
        if not isinstance(columns, list) or not columns:
            raise ValueError("logical export table lacks a column contract")
        column_names = [
            column.get("name") if isinstance(column, dict) else None
            for column in columns
        ]
        if not all(isinstance(name, str) and name for name in column_names):
            raise ValueError("logical export column contract is malformed")
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(column_names):
                raise ValueError("logical export row does not match its column contract")
            normalized_rows.append(
                {str(name): _decode_value(row[str(name)]) for name in column_names}
            )
        normalized_tables[str(table_name)] = normalized_rows
        if table_counts.get(table_name) != len(rows):
            raise ValueError("logical export table count does not match its rows")
    if set(table_counts) != set(tables):
        raise ValueError("logical export table counts contain an unknown table")
    control_fingerprint = hashlib.sha256(
        canonical_json(tables).encode("utf-8")
    ).hexdigest()
    if (
        control_fingerprint != document.get("control_fingerprint")
        or control_fingerprint != manifest.get("control_fingerprint")
        or table_counts != manifest.get("table_counts")
        or metadata["database_generation"] != manifest.get("database_generation")
        or metadata["schema_version"] != manifest.get("schema_version")
    ):
        raise ValueError("logical export normalized control evidence does not match")
    return {
        "manifest": manifest,
        "manifest_path": manifest_file,
        "artifact": artifact,
        "document": document,
        "decoded_tables": normalized_tables,
        "summary": {
            "metadata": metadata,
            "schema": schema,
            "schema_fingerprint": schema_fingerprint,
            "table_counts": table_counts,
            "control_fingerprint": control_fingerprint,
        },
    }


def _copy_private_source(
    source: Path,
    destination: Path,
    *,
    expected_uid: int,
) -> None:
    refuse_symlink_components(source)
    before = source.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise PermissionError("store backup source is not an expected-UID private file")
    source_flags = os.O_RDONLY
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        destination_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    destination_fd = os.open(destination, destination_flags, 0o600)
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("store backup source changed while opening")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        path_after = source.lstat()
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (path_after.st_dev, path_after.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError("store backup source changed while copying")
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _build_export_staging(
    database: Path,
    incoming: Mapping[str, Any],
) -> Path:
    """Import one logical export transactionally into a private staged DB."""

    descriptor, staging = _private_staging_file(database.parent, database.name)
    os.close(descriptor)
    connection = sqlite3.connect(str(staging), isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            summary = incoming["summary"]
            metadata = summary["metadata"]
            initialize_schema(
                connection,
                database_generation=str(metadata["database_generation"]),
                timestamp=utc_timestamp(),
            )
            expected_schema = _schema_descriptor(connection)
            if expected_schema != summary["schema"]:
                raise ValueError(
                    "logical export schema does not exactly match this coordinator build"
                )
            table_names = sorted(expected_schema["tables"])
            for table_name in table_names:
                connection.execute(f"DELETE FROM {_quote_identifier(table_name)}")
            decoded_tables = incoming["decoded_tables"]
            for table_name in table_names:
                table_schema = expected_schema["tables"][table_name]
                columns = [column["name"] for column in table_schema["columns"]]
                placeholders = ",".join("?" for _ in columns)
                identifiers = ",".join(_quote_identifier(column) for column in columns)
                statement = (
                    f"INSERT INTO {_quote_identifier(table_name)} ({identifiers}) "
                    f"VALUES ({placeholders})"
                )
                for row in decoded_tables[table_name]:
                    connection.execute(statement, tuple(row[column] for column in columns))
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        connection.execute("PRAGMA foreign_keys = ON")
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise ValueError("logical import could not enable foreign-key enforcement")
    except BaseException:
        connection.close()
        with suppress(FileNotFoundError):
            staging.unlink()
        raise
    else:
        connection.close()
    os.chmod(staging, 0o600)
    descriptor = os.open(staging, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    staged = _validate_sqlite(staging)
    if (
        staged["control_fingerprint"] != incoming["summary"]["control_fingerprint"]
        or staged["schema_fingerprint"] != incoming["summary"]["schema_fingerprint"]
        or staged["metadata"] != incoming["summary"]["metadata"]
    ):
        with suppress(FileNotFoundError):
            staging.unlink()
        raise ValueError("transactional logical import changed normalized state")
    return staging


def _remove_sqlite_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{database}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            sidecar.unlink()


def _validate_restore_target(database: Path, *, expected_uid: int) -> os.stat_result:
    """Refuse path substitution before any raw SQLite restore connection."""

    refuse_symlink_components(database)
    metadata = database.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("coordinator restore target must be a regular file")
    if metadata.st_uid != expected_uid:
        raise PermissionError("coordinator restore target has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("coordinator restore target must have mode 0600")
    return metadata


def _replace_and_verify_with_rollback(
    *,
    database: Path,
    staging: Path,
    expected_summary: Mapping[str, Any],
    current_summary: Mapping[str, Any],
    safety: Mapping[str, Any],
    expected_uid: int,
) -> dict[str, Any]:
    try:
        _remove_sqlite_sidecars(database)
        os.replace(staging, database)
        os.chmod(database, 0o600)
        _fsync_directory(database.parent)
        restored = _validate_sqlite(database)
        if (
            restored["control_fingerprint"] != expected_summary["control_fingerprint"]
            or restored["schema_fingerprint"] != expected_summary["schema_fingerprint"]
            or restored["metadata"] != expected_summary["metadata"]
        ):
            raise ValueError("restored normalized control evidence does not match")
        return restored
    except BaseException as primary:
        rollback_failures: list[BaseException] = []
        rollback_staging = database.parent / (
            f".{database.name}.rollback-{uuid.uuid4().hex}.tmp"
        )
        try:
            _copy_private_source(
                Path(str(safety["backup"])),
                rollback_staging,
                expected_uid=expected_uid,
            )
            _remove_sqlite_sidecars(database)
            os.replace(rollback_staging, database)
            os.chmod(database, 0o600)
            _fsync_directory(database.parent)
            rolled_back = _validate_sqlite(database)
            if (
                rolled_back["control_fingerprint"]
                != current_summary["control_fingerprint"]
                or rolled_back["schema_fingerprint"]
                != current_summary["schema_fingerprint"]
                or rolled_back["metadata"] != current_summary["metadata"]
            ):
                raise ValueError("rollback normalized control evidence does not match")
        except BaseException as rollback:
            rollback_failures.append(rollback)
        finally:
            try:
                rollback_staging.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                rollback_failures.append(cleanup)
            try:
                staging.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                rollback_failures.append(cleanup)
        if rollback_failures:
            failures = "; ".join(str(error) for error in rollback_failures)
            raise RuntimeError(
                f"restore publication or verification failed: {primary}; "
                f"normalized rollback or cleanup also failed: {failures}"
            ) from primary
        raise RuntimeError(
            f"restore publication or verification failed and normalized SQLite rollback succeeded: {primary}"
        ) from primary


def _create_forensic_store_snapshot(
    database: Path,
    output_root: Path,
    *,
    expected_uid: int,
) -> dict[str, Any]:
    """Copy exact unreadable store bytes before explicit corruption recovery."""

    candidates = [database, Path(f"{database}-wal"), Path(f"{database}-shm")]
    initial_presence = {str(path): path.exists() or path.is_symlink() for path in candidates}
    sources = [path for path in candidates if initial_presence[str(path)]]
    metadata: dict[str, os.stat_result] = {}
    for source in sources:
        refuse_symlink_components(source)
        item = source.lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != expected_uid
            or stat.S_IMODE(item.st_mode) != 0o600
        ):
            raise PermissionError(
                "corrupt-store forensic source must be an expected-UID mode-0600 regular file"
            )
        metadata[str(source)] = item
    if database not in sources:
        raise FileNotFoundError("corrupt-store recovery target is missing")

    capture_id = uuid.uuid4().hex
    captured: list[dict[str, Any]] = []
    for index, source in enumerate(sources):
        suffix = "database" if source == database else source.name.rsplit("-", 1)[-1]
        destination = output_root / (
            f"forensic-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
            f"{capture_id}-{index}-{suffix}.raw"
        )
        _copy_private_source(source, destination, expected_uid=expected_uid)
        captured.append(
            {
                "source": str(source),
                "kind": suffix,
                "artifact": str(destination),
                "size_bytes": destination.stat().st_size,
                "sha256": _sha256_file(destination),
            }
        )

    # Prove the complete DB/WAL/SHM set did not change across the capture.
    for candidate in candidates:
        present = candidate.exists() or candidate.is_symlink()
        if present != initial_presence[str(candidate)]:
            raise RuntimeError("corrupt-store files changed during forensic capture")
        if not present:
            continue
        before = metadata[str(candidate)]
        after = candidate.lstat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RuntimeError("corrupt-store files changed during forensic capture")

    manifest = output_root / f"forensic-{capture_id}.manifest.json"
    document = {
        "artifact_schema": STORE_ARTIFACT_SCHEMA,
        "type": STORE_FORENSIC_TYPE,
        "created_at": utc_timestamp(),
        "target": str(database),
        "files": captured,
        "normalized_readable": False,
    }
    _publish_private_bytes(
        manifest, (canonical_json(document) + "\n").encode("utf-8")
    )
    return {"manifest": str(manifest), "files": captured}


def _restore_forensic_store_bytes(
    database: Path,
    forensic: Mapping[str, Any],
    *,
    expected_uid: int,
) -> None:
    files = forensic.get("files")
    if not isinstance(files, list):
        raise ValueError("corrupt-store forensic snapshot is malformed")
    by_kind = {
        str(item.get("kind")): item for item in files if isinstance(item, Mapping)
    }
    database_item = by_kind.get("database")
    if database_item is None:
        raise ValueError("corrupt-store forensic snapshot lacks database bytes")
    _remove_sqlite_sidecars(database)
    for kind, target in (
        ("database", database),
        ("wal", Path(f"{database}-wal")),
        ("shm", Path(f"{database}-shm")),
    ):
        item = by_kind.get(kind)
        if item is None:
            if kind != "database":
                with suppress(FileNotFoundError):
                    target.unlink()
            continue
        source = Path(str(item["artifact"]))
        staging = database.parent / f".{target.name}.forensic-{uuid.uuid4().hex}.tmp"
        try:
            _copy_private_source(source, staging, expected_uid=expected_uid)
            os.replace(staging, target)
            os.chmod(target, 0o600)
        finally:
            with suppress(FileNotFoundError):
                staging.unlink()
        if (
            target.stat().st_size != item.get("size_bytes")
            or _sha256_file(target) != item.get("sha256")
        ):
            raise RuntimeError("forensic rollback bytes do not match their capture")
    _fsync_directory(database.parent)


def _replace_corrupt_store_with_forensic_rollback(
    *,
    database: Path,
    staging: Path,
    expected_summary: Mapping[str, Any],
    forensic: Mapping[str, Any],
    expected_uid: int,
) -> dict[str, Any]:
    try:
        _remove_sqlite_sidecars(database)
        os.replace(staging, database)
        os.chmod(database, 0o600)
        _fsync_directory(database.parent)
        restored = _validate_sqlite(database)
        if (
            restored["control_fingerprint"]
            != expected_summary["control_fingerprint"]
            or restored["schema_fingerprint"]
            != expected_summary["schema_fingerprint"]
            or restored["metadata"] != expected_summary["metadata"]
        ):
            raise ValueError("recovered normalized control evidence does not match")
        return restored
    except BaseException as primary:
        rollback_failures: list[BaseException] = []
        try:
            _restore_forensic_store_bytes(
                database, forensic, expected_uid=expected_uid
            )
        except BaseException as rollback:
            rollback_failures.append(rollback)
        finally:
            try:
                staging.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup:
                rollback_failures.append(cleanup)
        if rollback_failures:
            raise RuntimeError(
                "corrupt-store recovery failed: "
                f"{primary}; forensic byte rollback also failed: "
                + "; ".join(str(item) for item in rollback_failures)
            ) from primary
        raise RuntimeError(
            "corrupt-store recovery failed and exact forensic byte rollback succeeded: "
            f"{primary}"
        ) from primary


def recover_corrupt_store_backup(
    database_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    forensic_root: str | os.PathLike[str],
    *,
    store_role: str,
    confirm: bool,
    expected_uid: int | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Explicitly recover an unreadable store after preserving exact bytes.

    This command cannot prove the corrupt store's generation. It therefore
    accepts only a strongly verified same-role binary backup and is separate
    from ordinary same-generation restore. The coordinator service must be
    stopped; the maintenance lock excludes other coordinator maintenance.
    """

    if not confirm:
        raise ValueError("corrupt-store recovery requires explicit confirmation")
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    database = Path(database_path).expanduser()
    if not database.is_absolute():
        raise ValueError("coordinator database path must be absolute")
    database = Path(os.path.abspath(database))
    _validate_restore_target(database, expected_uid=uid)
    incoming = inspect_store_backup(
        manifest_path, expected_uid=uid, expected_role=store_role
    )
    output = _private_output_root(forensic_root, uid)
    staging = database.parent / f".{database.name}.recovery-{uuid.uuid4().hex}.tmp"
    with exclusive_maintenance_lock(
        database, expected_uid=uid, timeout_seconds=timeout_seconds
    ):
        _validate_restore_target(database, expected_uid=uid)
        forensic = _create_forensic_store_snapshot(
            database, output, expected_uid=uid
        )
        _copy_private_source(incoming["artifact"], staging, expected_uid=uid)
        staged = _validate_sqlite(staging)
        if staged["control_fingerprint"] != incoming["summary"]["control_fingerprint"]:
            staging.unlink()
            raise ValueError("copied recovery database changed normalized state")
        restored = _replace_corrupt_store_with_forensic_rollback(
            database=database,
            staging=staging,
            expected_summary=incoming["summary"],
            forensic=forensic,
            expected_uid=uid,
        )
    return {
        "status": "recovered",
        "database": str(database),
        "manifest": str(Path(manifest_path)),
        "store_role": store_role,
        "control_fingerprint": restored["control_fingerprint"],
        "database_generation": restored["metadata"]["database_generation"],
        "forensic_snapshot": forensic,
    }


def restore_store_backup(
    database_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    safety_root: str | os.PathLike[str],
    *,
    store_role: str,
    confirm: bool,
    expected_uid: int | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Atomically restore one same-generation normalized SQLite backup."""

    if not confirm:
        raise ValueError("store restore requires explicit confirmation")
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    database = Path(database_path).expanduser()
    if not database.is_absolute():
        raise ValueError("coordinator database path must be absolute")
    database = Path(os.path.abspath(database))
    _validate_restore_target(database, expected_uid=uid)
    incoming = inspect_store_backup(
        manifest_path, expected_uid=uid, expected_role=store_role
    )
    safety_output = _private_output_root(safety_root, uid)
    staging = database.parent / f".{database.name}.restore-{uuid.uuid4().hex}.tmp"
    with exclusive_maintenance_lock(
        database, expected_uid=uid, timeout_seconds=timeout_seconds
    ):
        _validate_restore_target(database, expected_uid=uid)
        raw_current = sqlite3.connect(str(database), isolation_level=None)
        raw_current.row_factory = sqlite3.Row
        try:
            try:
                raw_current.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                current = _control_summary(raw_current)
                safety = _backup_from_connection(
                    raw_current, safety_output, store_role=store_role
                )
            except (sqlite3.DatabaseError, ValueError) as error:
                raise RuntimeError(
                    "normal store restore requires a readable current normalized store; "
                    "stop the coordinator service and use `broker store-recover` for "
                    "explicit forensic corruption recovery"
                ) from error
        finally:
            raw_current.close()
        if (
            current["metadata"]["database_generation"]
            != incoming["summary"]["metadata"]["database_generation"]
        ):
            raise ValueError(
                "store backup belongs to another database generation; reenroll/reinstall instead"
            )
        _copy_private_source(
            incoming["artifact"], staging, expected_uid=uid
        )
        staged = _validate_sqlite(staging)
        if staged["control_fingerprint"] != incoming["summary"]["control_fingerprint"]:
            staging.unlink()
            raise ValueError("copied restore staging database changed normalized state")
        restored = _replace_and_verify_with_rollback(
            database=database,
            staging=staging,
            expected_summary=incoming["summary"],
            current_summary=current,
            safety=safety,
            expected_uid=uid,
        )
    return {
        "status": "restored",
        "database": str(database),
        "manifest": str(Path(manifest_path)),
        "control_fingerprint": incoming["summary"]["control_fingerprint"],
        "database_generation": incoming["summary"]["metadata"]["database_generation"],
        "safety_backup": safety,
    }


def restore_store_export(
    database_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    safety_root: str | os.PathLike[str],
    *,
    store_role: str,
    confirm: bool,
    expected_uid: int | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Transactionally import and atomically restore a logical store export."""

    if not confirm:
        raise ValueError("store import requires explicit confirmation")
    if store_role not in {"account", "service"}:
        raise ValueError("store_role must be account or service")
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    database = Path(database_path).expanduser()
    if not database.is_absolute():
        raise ValueError("coordinator database path must be absolute")
    database = Path(os.path.abspath(database))
    _validate_restore_target(database, expected_uid=uid)
    incoming = inspect_store_export(
        manifest_path, expected_uid=uid, expected_role=store_role
    )
    safety_output = _private_output_root(safety_root, uid)
    staging: Path | None = None
    with exclusive_maintenance_lock(
        database, expected_uid=uid, timeout_seconds=timeout_seconds
    ):
        _validate_restore_target(database, expected_uid=uid)
        raw_current = sqlite3.connect(str(database), isolation_level=None)
        raw_current.row_factory = sqlite3.Row
        try:
            try:
                raw_current.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                current = _control_summary(raw_current)
                safety = _backup_from_connection(
                    raw_current, safety_output, store_role=store_role
                )
            except (sqlite3.DatabaseError, ValueError) as error:
                raise RuntimeError(
                    "normal store import requires a readable current normalized store; "
                    "logical import is not corruption recovery"
                ) from error
        finally:
            raw_current.close()
        if (
            current["metadata"]["database_generation"]
            != incoming["summary"]["metadata"]["database_generation"]
        ):
            raise ValueError(
                "store export belongs to another database generation; reenroll/reinstall instead"
            )
        try:
            staging = _build_export_staging(database, incoming)
            restored = _replace_and_verify_with_rollback(
                database=database,
                staging=staging,
                expected_summary=incoming["summary"],
                current_summary=current,
                safety=safety,
                expected_uid=uid,
            )
            staging = None
        finally:
            if staging is not None:
                with suppress(FileNotFoundError):
                    staging.unlink()
    return {
        "status": "imported",
        "database": str(database),
        "manifest": str(Path(manifest_path)),
        "control_fingerprint": restored["control_fingerprint"],
        "database_generation": restored["metadata"]["database_generation"],
        "safety_backup": safety,
    }
