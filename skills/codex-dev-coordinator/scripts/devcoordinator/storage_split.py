"""Exact first-adoption split for the legacy normalized SQLite authority.

The legacy database remains untouched and is the rollback artifact.  This
module creates a small logical authority projection and an observer-owned,
bounded retained inventory store.  High-volume test history is deliberately
not copied into authority; exact source counts and logical digests bind the
separate testd migration.

The caller must already have fenced the legacy writer.  This module performs
no service control and is therefore safe to exercise in source-local tests.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
from typing import Any, Callable, Iterable, Mapping
import uuid

from .authority_retention import (
    MAX_EVENT_ROWS,
    MAX_SNAPSHOTS_PER_STATUS,
    MAX_TELEMETRY_SAMPLES_PER_RESOURCE,
    MAX_TERMINAL_OBSERVATION_PROOFS,
    MAX_WORKER_ATTEMPTS_PER_SERVER,
    prune_bounded_authority_state,
)
from .inventory_projection import (
    envelope,
    initialize_inventory_store,
    read_sealed_inventory_store,
)
from .store import AccountStore


SPLIT_SCHEMA_VERSION = 1
MAX_AUTHORITY_FILE_BYTES = 512 * 1024 * 1024
MIN_CAPACITY_RESERVE_BYTES = 64 * 1024 * 1024
SPLIT_ATTESTATION_KIND = "devcoordinator-logical-storage-split"
SPLIT_JOURNAL_KIND = "devcoordinator-logical-storage-split-journal"


TEST_TABLES = frozenset(
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
    }
)

CURRENT_OBSERVATION_TABLES = frozenset(
    {
        "server_observations",
        "docker_observations",
        "docker_ports",
        "docker_labels",
        "database_observations",
        "unassigned_resources",
    }
)

SNAPSHOT_PAYLOAD_TABLES = frozenset(
    {
        "observation_capabilities",
        "observation_snapshot_resources",
        "broker_observation_compose_scope",
        "broker_observed_compose_assets",
        "broker_observed_compose_containers",
        "broker_host_observation_sessions",
    }
)

SPECIAL_AUTHORITY_TABLES = frozenset(
    {
        "observation_snapshots",
        "telemetry_samples",
        "events",
        "event_journal_sequences",
        "worker_attempts",
        "worker_exit_decisions",
        "broker_lifecycle_plan_observations",
        "broker_compose_operation_preflights",
        *SNAPSHOT_PAYLOAD_TABLES,
    }
)

# Fail closed on new producer tables.  A schema addition must make an explicit
# authority/current/history decision here before first adoption can continue.
AUTHORITY_TABLES = frozenset(
    {
        "schema_metadata",
        "hosts",
        "coordinator_sources",
        "repositories",
        "repository_aliases",
        "repository_families",
        "repository_scopes",
        "operations",
        "runtime_sessions",
        "runtime_session_resources",
        "repository_installations",
        "source_resources",
        "server_definitions",
        "server_command_arguments",
        "server_environment",
        "server_source_records",
        "worker_policies",
        "worker_supervisor_states",
        "port_assignments",
        "leases",
        "broker_lease_links",
        "broker_assignment_links",
        "broker_reconciliation_queue",
        "broker_lifecycle_links",
        "broker_server_materialization_revocations",
        "broker_repository_materialization_revocations",
        "operation_targets",
        "operation_target_parameters",
        "operation_target_dependencies",
        "startup_policies",
        "startup_policy_restore_states",
        "resource_retirements",
        "resource_lifecycle_history",
        "cleanup_plans",
        "cleanup_phase_evidence",
        "cleanup_tombstones",
        "worktree_cleanup_identities",
        "docker_engines",
        "docker_resources",
        "docker_repository_hints",
        "ephemeral_container_templates",
        "ephemeral_template_arguments",
        "ephemeral_template_environment",
        "ephemeral_container_runs",
        "ephemeral_run_arguments",
        "ephemeral_run_environment",
        "ephemeral_run_phases",
        "database_bindings",
        "database_backups",
        "database_restore_events",
        "backup_evidence",
        "legacy_imports",
        "migration_conflicts",
        "broker_server_revocations",
        "broker_repository_revocations",
        "broker_worker_operation_requests",
        "broker_compose_definitions",
        "broker_compose_directory_identity",
        "broker_compose_effective_model_evidence",
        "broker_compose_project_claims",
        "broker_compose_project_claim_history",
        "broker_compose_files",
        "broker_compose_file_evidence",
        "broker_compose_env_files",
        "broker_compose_env_file_evidence",
        "broker_compose_profiles",
        "broker_compose_services",
        "broker_compose_run_once_services",
        "broker_compose_run_once_attempts",
        "broker_database_host_results",
        "broker_runtime_replacements",
        "broker_port_ranges",
        "broker_operation_requests",
        "broker_test_admission_fences",
        *CURRENT_OBSERVATION_TABLES,
        *SPECIAL_AUTHORITY_TABLES,
    }
)


class StorageSplitError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise StorageSplitError("split evidence is not canonical JSON") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _absolute(path: Path, label: str) -> Path:
    expanded = path.expanduser().absolute()
    if not expanded.is_absolute() or "\x00" in str(expanded):
        raise StorageSplitError(f"{label} must be absolute")
    return expanded


def _source_identity(path: Path, *, expected_uid: int) -> dict[str, Any]:
    path = _absolute(path, "legacy source database")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise StorageSplitError("legacy source database identity is unsafe")
    return {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": int(info.st_uid),
    }


def _private_destination(
    path: Path, *, owner_uid: int, label: str, allow_existing: bool = False
) -> Path:
    path = _absolute(path, label)
    parent = path.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise StorageSplitError(f"{label} parent is unsafe")
    if not allow_existing and (path.exists() or path.is_symlink()):
        raise StorageSplitError(f"{label} already exists; explicit recovery is required")
    return path


def _write_split_journal(
    path: Path,
    payload: Mapping[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, Any]:
    unsigned = {
        "kind": SPLIT_JOURNAL_KIND,
        "schema_version": SPLIT_SCHEMA_VERSION,
        **dict(payload),
    }
    document = {
        **unsigned,
        "document_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest(),
    }
    _write_attestation(path, document, owner_uid=owner_uid, owner_gid=owner_gid)
    return document


def _read_split_journal(path: Path, *, expected_uid: int) -> dict[str, Any] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size <= 0
        or info.st_size > 4 * 1024 * 1024
    ):
        raise StorageSplitError("logical storage split journal identity is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StorageSplitError("logical storage split journal is invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("kind") != SPLIT_JOURNAL_KIND
        or value.get("schema_version") != SPLIT_SCHEMA_VERSION
    ):
        raise StorageSplitError("logical storage split journal contract is invalid")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if value.get("document_sha256") != hashlib.sha256(_canonical(unsigned)).hexdigest():
        raise StorageSplitError("logical storage split journal digest is invalid")
    return value


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise StorageSplitError("legacy schema contains an unsafe identifier")
    return '"' + value + '"'


def _logical_cell(value: object) -> bytes:
    if value is None:
        return b"n;"
    if isinstance(value, int):
        return f"i:{value};".encode("ascii")
    if isinstance(value, float):
        return f"f:{value.hex()};".encode("ascii")
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return f"s:{len(payload)}:".encode("ascii") + payload + b";"
    if isinstance(value, bytes):
        return (
            f"b:{len(value)}:".encode("ascii")
            + hashlib.sha256(value).hexdigest().encode("ascii")
            + b";"
        )
    raise StorageSplitError("legacy row contains an unsupported SQLite value")


def _table_columns(
    connection: sqlite3.Connection, *, schema: str, table: str
) -> list[str]:
    columns = [
        str(row[1])
        for row in connection.execute(
            f"PRAGMA {_identifier(schema)}.table_xinfo({_identifier(table)})"
        )
        if int(row[6]) == 0
    ]
    if not columns:
        raise StorageSplitError(f"table has no copyable columns: {table}")
    return columns


def _signature_for_query(
    connection: sqlite3.Connection,
    *,
    query: str,
    columns: Iterable[str],
    parameters: tuple[object, ...] = (),
) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    logical_bytes = 0
    for row in connection.execute(query, parameters):
        digest.update(b"[")
        for value in row:
            encoded = _logical_cell(value)
            digest.update(encoded)
            logical_bytes += len(encoded)
        digest.update(b"]")
        count += 1
    return {
        "row_count": count,
        "logical_sha256": digest.hexdigest(),
        "logical_bytes": logical_bytes,
        "columns": list(columns),
    }


def _table_signature(
    connection: sqlite3.Connection, *, schema: str, table: str
) -> dict[str, Any]:
    columns = _table_columns(connection, schema=schema, table=table)
    projection = ", ".join(_identifier(column) for column in columns)
    ordering = ", ".join(_identifier(column) for column in columns)
    return _signature_for_query(
        connection,
        query=(
            f"SELECT {projection} FROM {_identifier(schema)}.{_identifier(table)} "
            f"ORDER BY {ordering}"
        ),
        columns=columns,
    )


def _copy_query(
    connection: sqlite3.Connection,
    *,
    table: str,
    select_sql: str,
    parameters: tuple[object, ...] = (),
) -> dict[str, Any]:
    columns = _table_columns(connection, schema="legacy", table=table)
    projection = ", ".join(_identifier(column) for column in columns)
    connection.execute(
        f"INSERT INTO {_identifier(table)} ({projection}) {select_sql}",
        parameters,
    )
    return _table_signature(connection, schema="main", table=table)


def _selected_worker_attempts(connection: sqlite3.Connection) -> set[str]:
    if not _has_table(connection, "worker_attempts"):
        return set()
    retained = {
        str(row[0])
        for row in connection.execute(
            """
            SELECT attempt_id FROM (
                SELECT attempt_id, state,
                       ROW_NUMBER() OVER (
                           PARTITION BY server_definition_id
                           ORDER BY created_at DESC, attempt_id DESC
                       ) AS retained_ordinal
                FROM legacy.worker_attempts
            )
            WHERE state IN ('reserved', 'running') OR retained_ordinal <= ?
            """,
            (MAX_WORKER_ATTEMPTS_PER_SERVER,),
        )
    }
    for table, column in (
        ("worker_supervisor_states", "current_attempt_id"),
        ("worker_policies", "last_trip_attempt_id"),
    ):
        if _has_table(connection, table):
            retained.update(
                str(row[0])
                for row in connection.execute(
                    f"SELECT {column} FROM legacy.{table} WHERE {column} IS NOT NULL"
                )
            )
    return retained


def _selected_proof_operations(
    connection: sqlite3.Connection, *, table: str, operation_column: str
) -> set[str]:
    if not _has_table(connection, table):
        return set()
    return {
        str(row[0])
        for row in connection.execute(
            f"""
            SELECT {operation_column} FROM legacy.{table}
            WHERE {operation_column} IN (
                SELECT operation_id FROM legacy.operations
                WHERE status IN ('planned', 'running', 'partial', 'needs_attention')
            )
            UNION
            SELECT {operation_column} FROM (
                SELECT proof.{operation_column},
                       ROW_NUMBER() OVER (
                           ORDER BY operation.updated_at DESC,
                                    operation.operation_id DESC
                       ) AS retained_ordinal
                FROM legacy.{table} proof
                JOIN legacy.operations operation
                  ON operation.operation_id = proof.{operation_column}
                WHERE operation.status IN ('succeeded', 'failed', 'cancelled')
            )
            WHERE retained_ordinal <= ?
            """,
            (MAX_TERMINAL_OBSERVATION_PROOFS,),
        )
    }


def _selected_snapshots(
    connection: sqlite3.Connection,
    *,
    lifecycle_operations: set[str],
    compose_operations: set[str],
) -> set[str]:
    if not _has_table(connection, "observation_snapshots"):
        return set()
    retained = {
        str(row[0])
        for row in connection.execute(
            """
            SELECT snapshot_id FROM (
                SELECT snapshot_id, status,
                       ROW_NUMBER() OVER (
                           PARTITION BY host_id, observer_domain, status
                           ORDER BY started_at DESC, snapshot_id DESC
                       ) AS retained_ordinal
                FROM legacy.observation_snapshots
            )
            WHERE status = 'running' OR retained_ordinal <= ?
            """,
            (MAX_SNAPSHOTS_PER_STATUS,),
        )
    }
    if _has_table(connection, "broker_repository_configurations"):
        for column in ("configuration_snapshot_id", "grant_snapshot_id"):
            retained.update(
                str(row[0])
                for row in connection.execute(
                    f"SELECT {column} FROM legacy.broker_repository_configurations "
                    f"WHERE {column} IS NOT NULL"
                )
            )
    for table, column, selected in (
        ("broker_lifecycle_plan_observations", "plan_id", lifecycle_operations),
        ("broker_compose_operation_preflights", "operation_id", compose_operations),
    ):
        if selected and _has_table(connection, table):
            for chunk in _chunks(selected):
                placeholders = ",".join("?" for _ in chunk)
                retained.update(
                    str(row[0])
                    for row in connection.execute(
                        f"SELECT snapshot_id FROM legacy.{table} "
                        f"WHERE {column} IN ({placeholders})",
                        chunk,
                    )
                )
    return retained


def _selected_events(
    connection: sqlite3.Connection, *, attempts: set[str]
) -> set[str]:
    if not _has_table(connection, "events"):
        return set()
    retained: set[str] = set()
    if attempts and _has_table(connection, "worker_attempts"):
        for chunk in _chunks(attempts):
            placeholders = ",".join("?" for _ in chunk)
            retained.update(
                str(row[0])
                for row in connection.execute(
                    "SELECT crash_event_id FROM legacy.worker_attempts "
                    f"WHERE attempt_id IN ({placeholders}) AND crash_event_id IS NOT NULL",
                    chunk,
                )
            )
    if _has_table(connection, "worker_policies"):
        retained.update(
            str(row[0])
            for row in connection.execute(
                "SELECT last_trip_event_id FROM legacy.worker_policies "
                "WHERE last_trip_event_id IS NOT NULL"
            )
        )
    if _has_table(connection, "event_journal_sequences"):
        retained.update(
            str(row[0])
            for row in connection.execute(
                """
                SELECT event_id FROM legacy.event_journal_sequences
                ORDER BY sequence DESC LIMIT ?
                """,
                (MAX_EVENT_ROWS,),
            )
        )
    else:
        retained.update(
            str(row[0])
            for row in connection.execute(
                "SELECT event_id FROM legacy.events "
                "ORDER BY occurred_at DESC, event_id DESC LIMIT ?",
                (MAX_EVENT_ROWS,),
            )
        )
    return retained


def _chunks(values: Iterable[str], size: int = 400) -> Iterable[tuple[str, ...]]:
    current: list[str] = []
    for value in sorted({str(item) for item in values}):
        current.append(value)
        if len(current) == size:
            yield tuple(current)
            current.clear()
    if current:
        yield tuple(current)


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM legacy.sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone() is not None


def _copy_selected_ids(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
    values: set[str],
) -> dict[str, Any]:
    columns = _table_columns(connection, schema="legacy", table=table)
    projection = ", ".join(_identifier(item) for item in columns)
    if not values:
        return _table_signature(connection, schema="main", table=table)
    for chunk in _chunks(values):
        placeholders = ",".join("?" for _ in chunk)
        connection.execute(
            f"INSERT INTO {_identifier(table)} ({projection}) "
            f"SELECT {projection} FROM legacy.{_identifier(table)} "
            f"WHERE {_identifier(column)} IN ({placeholders})",
            chunk,
        )
    return _table_signature(connection, schema="main", table=table)


def _selected_ids_logical_bytes(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
    values: set[str],
) -> int:
    if not values:
        return 0
    columns = _table_columns(connection, schema="legacy", table=table)
    projection = ", ".join(_identifier(item) for item in columns)
    total = 0
    for chunk in _chunks(values):
        placeholders = ",".join("?" for _ in chunk)
        signature = _signature_for_query(
            connection,
            query=(
                f"SELECT {projection} FROM legacy.{_identifier(table)} "
                f"WHERE {_identifier(column)} IN ({placeholders}) "
                f"ORDER BY {projection}"
            ),
            columns=columns,
            parameters=chunk,
        )
        total += int(signature["logical_bytes"])
    return total


def _create_authority_projection(
    *,
    source: Path,
    destination: Path,
    expected_uid: int,
    owner_uid: int,
    owner_gid: int,
    capacity_probe: Callable[[Path], int],
    failpoint: Callable[[str], None] | None,
) -> dict[str, Any]:
    connection = sqlite3.connect(str(destination), timeout=30.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("ATTACH DATABASE ? AS legacy", (f"file:{source}?mode=ro",))
        connection.execute("BEGIN")
        metadata = connection.execute(
            "SELECT schema_version, database_generation, state_revision, "
            "observation_revision FROM legacy.schema_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise StorageSplitError("legacy schema metadata is missing")
        tables = connection.execute(
            "SELECT name, sql FROM legacy.sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid"
        ).fetchall()
        names = {str(row["name"]) for row in tables}
        unknown = names - AUTHORITY_TABLES - TEST_TABLES
        if unknown:
            raise StorageSplitError(
                "legacy database contains unclassified tables: "
                + ", ".join(sorted(unknown))
            )
        missing = {"schema_metadata", "hosts", "repositories"} - names
        if missing:
            raise StorageSplitError(
                "legacy authority schema is incomplete: " + ", ".join(sorted(missing))
            )
        source_signatures = {
            table: _table_signature(connection, schema="legacy", table=table)
            for table in sorted(names)
        }
        if failpoint is not None:
            failpoint("source-signatures")
        for row in tables:
            sql = row["sql"]
            if not isinstance(sql, str) or not sql.strip():
                raise StorageSplitError("legacy table schema is unavailable")
            connection.execute(sql)

        attempts = _selected_worker_attempts(connection)
        lifecycle_operations = _selected_proof_operations(
            connection,
            table="broker_lifecycle_plan_observations",
            operation_column="plan_id",
        )
        compose_operations = _selected_proof_operations(
            connection,
            table="broker_compose_operation_preflights",
            operation_column="operation_id",
        )
        snapshots = _selected_snapshots(
            connection,
            lifecycle_operations=lifecycle_operations,
            compose_operations=compose_operations,
        )
        events = _selected_events(connection, attempts=attempts)
        selected_logical_bytes = sum(
            int(source_signatures[table]["logical_bytes"])
            for table in names
            if table not in TEST_TABLES and table not in SPECIAL_AUTHORITY_TABLES
        )
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection, table="worker_attempts", column="attempt_id", values=attempts
        ) if "worker_attempts" in names else 0
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection, table="worker_exit_decisions", column="attempt_id", values=attempts
        ) if "worker_exit_decisions" in names else 0
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection,
            table="broker_lifecycle_plan_observations",
            column="plan_id",
            values=lifecycle_operations,
        ) if "broker_lifecycle_plan_observations" in names else 0
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection,
            table="broker_compose_operation_preflights",
            column="operation_id",
            values=compose_operations,
        ) if "broker_compose_operation_preflights" in names else 0
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection,
            table="observation_snapshots",
            column="snapshot_id",
            values=snapshots,
        ) if "observation_snapshots" in names else 0
        for table in names & SNAPSHOT_PAYLOAD_TABLES:
            selected_logical_bytes += _selected_ids_logical_bytes(
                connection,
                table=table,
                column="snapshot_id",
                values=snapshots,
            )
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection, table="events", column="event_id", values=events
        ) if "events" in names else 0
        selected_logical_bytes += _selected_ids_logical_bytes(
            connection,
            table="event_journal_sequences",
            column="event_id",
            values=events,
        ) if "event_journal_sequences" in names else 0
        if "telemetry_samples" in names:
            telemetry_columns = _table_columns(
                connection, schema="legacy", table="telemetry_samples"
            )
            telemetry_projection = ", ".join(
                _identifier(column) for column in telemetry_columns
            )
            selected_logical_bytes += int(
                _signature_for_query(
                    connection,
                    query=(
                        f"SELECT {telemetry_projection} FROM ("
                        f"SELECT {telemetry_projection}, ROW_NUMBER() OVER ("
                        "PARTITION BY host_resource_kind, host_resource_id "
                        "ORDER BY sampled_at DESC, sample_id DESC"
                        ") AS retained_ordinal FROM legacy.telemetry_samples"
                        ") WHERE retained_ordinal <= ? "
                        f"ORDER BY {telemetry_projection}"
                    ),
                    columns=telemetry_columns,
                    parameters=(MAX_TELEMETRY_SAMPLES_PER_RESOURCE,),
                )["logical_bytes"]
            )
        schema_bytes = sum(
            len(str(row["sql"]).encode("utf-8")) for row in tables
        )
        estimated_required_bytes = max(
            MIN_CAPACITY_RESERVE_BYTES,
            selected_logical_bytes * 2 + schema_bytes * 4 + 16 * 1024 * 1024,
        )
        if estimated_required_bytes > MAX_AUTHORITY_FILE_BYTES:
            raise StorageSplitError("selected logical authority exceeds its 512 MiB boundary")
        if int(capacity_probe(destination.parent)) < estimated_required_bytes:
            raise StorageSplitError("insufficient capacity for exact logical authority projection")
        destination_signatures: dict[str, Any] = {}
        for table in sorted(names):
            columns = _table_columns(connection, schema="legacy", table=table)
            projection = ", ".join(_identifier(column) for column in columns)
            if table in TEST_TABLES:
                destination_signatures[table] = _table_signature(
                    connection, schema="main", table=table
                )
            elif table == "worker_attempts":
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="attempt_id", values=attempts
                )
            elif table == "worker_exit_decisions":
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="attempt_id", values=attempts
                )
            elif table == "broker_lifecycle_plan_observations":
                destination_signatures[table] = _copy_selected_ids(
                    connection,
                    table=table,
                    column="plan_id",
                    values=lifecycle_operations,
                )
            elif table == "broker_compose_operation_preflights":
                destination_signatures[table] = _copy_selected_ids(
                    connection,
                    table=table,
                    column="operation_id",
                    values=compose_operations,
                )
            elif table == "observation_snapshots":
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="snapshot_id", values=snapshots
                )
            elif table in SNAPSHOT_PAYLOAD_TABLES:
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="snapshot_id", values=snapshots
                )
            elif table == "events":
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="event_id", values=events
                )
            elif table == "event_journal_sequences":
                destination_signatures[table] = _copy_selected_ids(
                    connection, table=table, column="event_id", values=events
                )
            elif table == "telemetry_samples":
                destination_signatures[table] = _copy_query(
                    connection,
                    table=table,
                    select_sql=(
                        f"SELECT {projection} FROM ("
                        f"SELECT {projection}, ROW_NUMBER() OVER ("
                        "PARTITION BY host_resource_kind, host_resource_id "
                        "ORDER BY sampled_at DESC, sample_id DESC"
                        ") AS retained_ordinal FROM legacy.telemetry_samples"
                        ") WHERE retained_ordinal <= ?"
                    ),
                    parameters=(MAX_TELEMETRY_SAMPLES_PER_RESOURCE,),
                )
            else:
                destination_signatures[table] = _copy_query(
                    connection,
                    table=table,
                    select_sql=(
                        f"SELECT {projection} FROM legacy.{_identifier(table)}"
                    ),
                )

        objects = connection.execute(
            "SELECT type, sql FROM legacy.sqlite_master "
            "WHERE type IN ('index', 'trigger', 'view') AND sql IS NOT NULL "
            "ORDER BY CASE type WHEN 'view' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, rowid"
        ).fetchall()
        for row in objects:
            sql = row["sql"]
            if not isinstance(sql, str) or len(sql.encode("utf-8")) > 1024 * 1024:
                raise StorageSplitError("legacy schema object is invalid")
            connection.execute(sql)
        prune_bounded_authority_state(connection)
        connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")
        check = connection.execute("PRAGMA quick_check").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if check is None or str(check[0]) != "ok" or foreign_keys:
            raise StorageSplitError("logical authority projection failed integrity checks")
        final_signatures = {
            table: _table_signature(connection, schema="main", table=table)
            for table in sorted(names)
        }
        for table in sorted(names):
            intended = destination_signatures[table]
            final = final_signatures[table]
            if intended != final:
                raise StorageSplitError(
                    f"authority retention changed the intended logical rows for {table}"
                )
            if table in TEST_TABLES and int(final["row_count"]) != 0:
                raise StorageSplitError("test history leaked into the authority projection")
        destination_signatures = final_signatures
        connection.execute("DETACH DATABASE legacy")
    except BaseException:
        connection.rollback()
        connection.close()
        destination.unlink(missing_ok=True)
        raise
    else:
        connection.close()
    os.chown(destination, owner_uid, owner_gid)
    os.chmod(destination, 0o600)
    size = destination.stat().st_size
    if size > MAX_AUTHORITY_FILE_BYTES:
        destination.unlink(missing_ok=True)
        raise StorageSplitError("logical authority exceeds its 512 MiB boundary")
    return {
        "schema_version": int(metadata["schema_version"]),
        "database_generation": str(metadata["database_generation"]),
        "state_revision": int(metadata["state_revision"]),
        "observation_revision": int(metadata["observation_revision"]),
        "source_tables": {
            table: {
                key: value
                for key, value in signature.items()
                if key != "columns"
            }
            for table, signature in source_signatures.items()
        },
        "authority_tables": {
            table: {
                key: value
                for key, value in signature.items()
                if key != "columns"
            }
            for table, signature in destination_signatures.items()
        },
        "test_source_tables": {
            table: {
                key: value
                for key, value in source_signatures[table].items()
                if key != "columns"
            }
            for table in sorted(names & TEST_TABLES)
        },
        "retention": {
            "telemetry_samples_per_resource": MAX_TELEMETRY_SAMPLES_PER_RESOURCE,
            "snapshots_per_status": MAX_SNAPSHOTS_PER_STATUS,
            "events": MAX_EVENT_ROWS,
            "worker_attempts_per_server": MAX_WORKER_ATTEMPTS_PER_SERVER,
            "terminal_observation_proofs": MAX_TERMINAL_OBSERVATION_PROOFS,
        },
        "selected_logical_bytes": selected_logical_bytes,
        "estimated_required_bytes": estimated_required_bytes,
        "file": {
            "size": size,
            "sha256": _sha256_file(destination),
            "owner_uid": owner_uid,
            "owner_gid": owner_gid,
            "mode": "0600",
        },
    }


def _inventory_seed(
    authority_database: Path,
    *,
    expected_uid: int,
) -> Mapping[str, Any]:
    descriptor = os.open(
        authority_database,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    connection = sqlite3.connect(
        f"file:{authority_database}?mode=ro",
        uri=True,
        timeout=5.0,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    base = AccountStore(
        authority_database,
        connection,
        expected_uid=expected_uid,
        busy_timeout_ms=5_000,
        maintenance_descriptor=descriptor,
        read_only=True,
    )
    try:
        return base.inventory_v2()
    finally:
        base.close()


def _checkpoint_inventory(path: Path, *, expected_uid: int) -> None:
    info = path.lstat()
    if info.st_uid != expected_uid:
        raise StorageSplitError("temporary inventory store owner is invalid")
    connection = sqlite3.connect(str(path), timeout=30.0, isolation_level=None)
    try:
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise StorageSplitError("inventory store WAL checkpoint failed")
        mode = str(connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]).lower()
        if mode != "delete":
            raise StorageSplitError("inventory store could not be sealed for publication")
    finally:
        connection.close()


def _write_attestation(
    path: Path,
    document: Mapping[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    """Make a same-directory rename or unlink durable before proceeding."""

    directory = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _verify_console_access(
    *,
    source: Path | None,
    destination: Path | None,
    source_uid: int,
    destination_uid: int,
) -> dict[str, Any]:
    if source is None and destination is None:
        return {"present": False}
    if source is None or destination is None:
        raise StorageSplitError("Console access migration paths are incomplete")
    source = _absolute(source, "legacy Console access source")
    destination = _absolute(destination, "Console access destination")
    source_info = source.lstat()
    destination_info = destination.lstat()
    for label, info, uid in (
        ("legacy Console access", source_info, source_uid),
        ("final Console access", destination_info, destination_uid),
    ):
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise StorageSplitError(f"{label} identity is unsafe")
    source_digest = _sha256_file(source)
    destination_digest = _sha256_file(destination)
    if source_info.st_size != destination_info.st_size or source_digest != destination_digest:
        raise StorageSplitError("Console access migration changed logical content")
    return {
        "present": True,
        "source_size": int(source_info.st_size),
        "source_sha256": source_digest,
        "destination_size": int(destination_info.st_size),
        "destination_sha256": destination_digest,
        "destination_owner_uid": destination_uid,
        "destination_mode": f"{stat.S_IMODE(destination_info.st_mode):04o}",
    }


def split_legacy_storage(
    *,
    source_database: Path,
    authority_database: Path,
    inventory_database: Path,
    attestation_path: Path,
    expected_uid: int,
    authority_owner_uid: int,
    authority_owner_gid: int,
    inventory_owner_uid: int,
    inventory_owner_gid: int,
    attestation_owner_gid: int | None = None,
    console_access_source: Path | None = None,
    console_access_destination: Path | None = None,
    console_access_source_uid: int | None = None,
    console_access_destination_uid: int | None = None,
    capacity_probe: Callable[[Path], int] | None = None,
    failpoint: Callable[[str], None] | None = None,
    journal_path: Path | None = None,
) -> dict[str, Any]:
    """Create the final split stores and one exact, self-digesting attestation."""

    if os.geteuid() != expected_uid:
        raise StorageSplitError("logical storage split must run as the authority UID")
    attestation_gid = os.getegid() if attestation_owner_gid is None else int(attestation_owner_gid)
    source_database = _absolute(source_database, "legacy source database")
    source_before = _source_identity(source_database, expected_uid=expected_uid)
    source_before["sha256"] = _sha256_file(source_database)
    journal = None
    if journal_path is not None:
        journal_path = _absolute(journal_path, "logical storage split journal")
        journal = _read_split_journal(journal_path, expected_uid=expected_uid)
    authority_database = _private_destination(
        authority_database,
        owner_uid=authority_owner_uid,
        label="authority database",
        allow_existing=journal is not None,
    )
    inventory_database = _private_destination(
        inventory_database,
        owner_uid=inventory_owner_uid,
        label="inventory database",
        allow_existing=journal is not None,
    )
    attestation_path = _private_destination(
        attestation_path,
        owner_uid=expected_uid,
        label="storage split attestation",
        allow_existing=journal is not None,
    )
    if len({source_database, authority_database, inventory_database, attestation_path}) != 4:
        raise StorageSplitError("storage split paths must be distinct")
    binding = {
        "source": source_before,
        "authority_database": str(authority_database),
        "inventory_database": str(inventory_database),
        "attestation_path": str(attestation_path),
        "authority_owner_uid": authority_owner_uid,
        "authority_owner_gid": authority_owner_gid,
        "inventory_owner_uid": inventory_owner_uid,
        "inventory_owner_gid": inventory_owner_gid,
        "attestation_owner_gid": attestation_gid,
        "console_access_source": (
            str(console_access_source) if console_access_source is not None else None
        ),
        "console_access_destination": (
            str(console_access_destination)
            if console_access_destination is not None
            else None
        ),
        "console_access_source_uid": console_access_source_uid,
        "console_access_destination_uid": console_access_destination_uid,
    }
    if journal is None:
        if journal_path is None:
            operation_id = str(uuid.uuid4())
        else:
            operation_id = str(uuid.uuid4())
            journal = _write_split_journal(
                journal_path,
                {
                    "operation_id": operation_id,
                    "binding": binding,
                    "phase": "planned",
                    "created_at": _now(),
                    "updated_at": _now(),
                },
                owner_uid=expected_uid,
                owner_gid=attestation_gid,
            )
    else:
        if journal.get("binding") != binding:
            raise StorageSplitError(
                "logical storage split journal belongs to another operation"
            )
        operation_id = str(journal.get("operation_id"))
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as error:
            raise StorageSplitError(
                "logical storage split operation identity is invalid"
            ) from error

    def persist(phase: str, **updates: Any) -> None:
        nonlocal journal
        if journal_path is None:
            return
        if journal is None:
            raise StorageSplitError("logical storage split journal disappeared")
        payload = {
            key: value
            for key, value in journal.items()
            if key not in {"kind", "schema_version", "document_sha256"}
        }
        payload.update(updates)
        payload["phase"] = phase
        payload["updated_at"] = _now()
        journal = _write_split_journal(
            journal_path,
            payload,
            owner_uid=expected_uid,
            owner_gid=attestation_gid,
        )

    authority_temporary = authority_database.with_name(
        f".{authority_database.name}.{operation_id}.partial"
    )
    inventory_temporary = inventory_database.with_name(
        f".{inventory_database.name}.{operation_id}.partial"
    )

    def exact_file(path: Path, evidence: Mapping[str, Any], owner_uid: int) -> bool:
        if not path.exists() or path.is_symlink():
            return False
        info = path.lstat()
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == owner_uid
            and stat.S_IMODE(info.st_mode) == 0o600
            and int(info.st_size) == int(evidence.get("size", -1))
            and _sha256_file(path) == evidence.get("sha256")
        )

    if journal is not None and journal.get("phase") == "complete":
        result = journal.get("result")
        if not isinstance(result, Mapping):
            raise StorageSplitError("complete storage split journal lacks its result")
        return verify_storage_split_attestation(
            result,
            source_database=source_database,
            authority_database=authority_database,
            inventory_database=inventory_database,
            expected_uid=expected_uid,
            authority_owner_uid=authority_owner_uid,
            inventory_owner_uid=inventory_owner_uid,
        )

    phase = str(journal.get("phase")) if journal is not None else "untracked"
    if phase not in {
        "untracked",
        "planned",
        "authority_prepared",
        "prepared",
        "authority_published",
        "inventory_published",
    }:
        raise StorageSplitError("logical storage split journal phase is invalid")
    for partial, owner, durable_phase in (
        (authority_temporary, authority_owner_uid, {"authority_prepared", "prepared"}),
        (inventory_temporary, inventory_owner_uid, {"prepared"}),
    ):
        if (partial.exists() or partial.is_symlink()) and phase not in durable_phase:
            info = partial.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise StorageSplitError(
                    "unjournaled storage split partial has an unsafe identity"
                )
            partial.unlink()
            Path(f"{partial}-wal").unlink(missing_ok=True)
            Path(f"{partial}-shm").unlink(missing_ok=True)
            _fsync_directory(partial.parent)
    created: list[Path] = []
    free = capacity_probe or (lambda path: int(shutil.disk_usage(path).free))
    if int(free(authority_database.parent)) < MIN_CAPACITY_RESERVE_BYTES:
        raise StorageSplitError("insufficient capacity for logical authority projection")
    if int(free(inventory_database.parent)) < MIN_CAPACITY_RESERVE_BYTES:
        raise StorageSplitError("insufficient capacity for retained inventory store")
    try:
        authority_value = journal.get("authority") if journal is not None else None
        if isinstance(authority_value, Mapping):
            authority = dict(authority_value)
            authority_file = authority.get("file")
            if not isinstance(authority_file, Mapping):
                raise StorageSplitError("journaled authority projection is invalid")
            authority_location = (
                authority_database
                if authority_database.exists()
                else authority_temporary
            )
            if not exact_file(
                authority_location, authority_file, authority_owner_uid
            ):
                raise StorageSplitError("journaled authority projection changed")
        else:
            authority = _create_authority_projection(
                source=source_database,
                destination=authority_temporary,
                expected_uid=expected_uid,
                owner_uid=authority_owner_uid,
                owner_gid=authority_owner_gid,
                capacity_probe=free,
                failpoint=failpoint,
            )
            created.append(authority_temporary)
            if failpoint is not None:
                failpoint("authority-prepared")
            persist("authority_prepared", authority=authority)
        inventory_value = journal.get("inventory") if journal is not None else None
        source_after_value = journal.get("source_after") if journal is not None else None
        console_access_value = journal.get("console_access") if journal is not None else None
        if (
            isinstance(inventory_value, Mapping)
            and isinstance(source_after_value, Mapping)
            and isinstance(console_access_value, Mapping)
        ):
            inventory = dict(inventory_value)
            inventory_file_value = inventory.get("database")
            if not isinstance(inventory_file_value, Mapping):
                raise StorageSplitError("journaled inventory projection is invalid")
            inventory_file = dict(inventory_file_value)
            inventory_location = (
                inventory_database
                if inventory_database.exists()
                else inventory_temporary
            )
            if not exact_file(
                inventory_location, inventory_file, inventory_owner_uid
            ):
                raise StorageSplitError("journaled inventory projection changed")
            source_after = dict(source_after_value)
            console_access = dict(console_access_value)
        else:
            authority_seed_path = (
                authority_database
                if authority_database.exists()
                else authority_temporary
            )
            seed = envelope(
                generation=1,
                inventory=_inventory_seed(
                    authority_seed_path,
                    expected_uid=authority_owner_uid,
                ),
                published_at=_now(),
            )
            inventory_result = initialize_inventory_store(
                inventory_temporary,
                seed,
                owner_uid=inventory_owner_uid,
                owner_gid=inventory_owner_gid,
            )
            created.append(inventory_temporary)
            _checkpoint_inventory(
                inventory_temporary, expected_uid=inventory_owner_uid
            )
            inventory_file = {
                "size": inventory_temporary.stat().st_size,
                "sha256": _sha256_file(inventory_temporary),
                "owner_uid": inventory_owner_uid,
                "owner_gid": inventory_owner_gid,
                "mode": f"{stat.S_IMODE(inventory_temporary.stat().st_mode):04o}",
            }
            inventory = {
                "database": inventory_file,
                "generation": inventory_result["generation"],
                "payload_sha256": inventory_result["payload_sha256"],
                "retained_generations": inventory_result["retained_generations"],
                "logical_bytes": inventory_result["logical_bytes"],
            }
            if failpoint is not None:
                failpoint("inventory-prepared")
            source_after = _source_identity(
                source_database, expected_uid=expected_uid
            )
            console_access = _verify_console_access(
                source=console_access_source,
                destination=console_access_destination,
                source_uid=(
                    expected_uid
                    if console_access_source_uid is None
                    else console_access_source_uid
                ),
                destination_uid=(
                    expected_uid
                    if console_access_destination_uid is None
                    else console_access_destination_uid
                ),
            )
            source_after["sha256"] = _sha256_file(source_database)
            persist(
                "prepared",
                authority=authority,
                inventory=inventory,
                source_after=source_after,
                console_access=console_access,
            )
        for field in ("device", "inode", "size", "mtime_ns", "mode", "owner_uid"):
            if source_before[field] != source_after[field]:
                raise StorageSplitError("legacy source changed during logical split")
        source_after_digest = _sha256_file(source_database)
        if source_after.get("sha256") != source_after_digest:
            raise StorageSplitError("legacy source content changed during logical split")
        if source_after["sha256"] != source_before["sha256"]:
            raise StorageSplitError("legacy source content changed during logical split")
        authority_file = authority.get("file")
        if not isinstance(authority_file, Mapping):
            raise StorageSplitError("authority file evidence is invalid")
        if not authority_database.exists():
            if not exact_file(
                authority_temporary, authority_file, authority_owner_uid
            ):
                raise StorageSplitError("prepared authority projection changed")
            os.replace(authority_temporary, authority_database)
            if authority_temporary in created:
                created.remove(authority_temporary)
            created.append(authority_database)
            if failpoint is not None:
                failpoint("authority-renamed")
            _fsync_directory(authority_database.parent)
        elif not exact_file(authority_database, authority_file, authority_owner_uid):
            raise StorageSplitError("published authority projection changed")
        persist("authority_published")
        if failpoint is not None:
            failpoint("authority-published")
        if not inventory_database.exists():
            if not exact_file(
                inventory_temporary, inventory_file, inventory_owner_uid
            ):
                raise StorageSplitError("prepared inventory projection changed")
            os.replace(inventory_temporary, inventory_database)
            if inventory_temporary in created:
                created.remove(inventory_temporary)
            created.append(inventory_database)
            if failpoint is not None:
                failpoint("inventory-renamed")
            _fsync_directory(inventory_database.parent)
        elif not exact_file(inventory_database, inventory_file, inventory_owner_uid):
            raise StorageSplitError("published inventory projection changed")
        persist("inventory_published")
        if failpoint is not None:
            failpoint("inventory-published")
        unsigned = {
            "kind": SPLIT_ATTESTATION_KIND,
            "schema_version": SPLIT_SCHEMA_VERSION,
            "operation_id": operation_id,
            "source": source_after,
            "authority": authority,
            "inventory": inventory,
            "console_access": console_access,
            "legacy_source_retained_for_rollback": True,
            "created_at": (
                journal["created_at"]
                if journal is not None
                else _now()
            ),
        }
        document = {
            **unsigned,
            "document_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest(),
        }
        if attestation_path.exists() or attestation_path.is_symlink():
            try:
                recorded_attestation = json.loads(
                    attestation_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StorageSplitError(
                    "existing storage split attestation is invalid"
                ) from error
            if recorded_attestation != document:
                raise StorageSplitError(
                    "existing storage split attestation is contradictory"
                )
        else:
            _write_attestation(
                attestation_path,
                document,
                owner_uid=expected_uid,
                owner_gid=attestation_gid,
            )
        created.append(attestation_path)
        if failpoint is not None:
            failpoint("attestation-published")
        persist("complete", result=document)
        return document
    except BaseException as error:
        if getattr(error, "simulated_power_loss", False):
            raise
        cleanup_parents: set[Path] = set()
        for path in reversed(created):
            path.unlink(missing_ok=True)
            Path(f"{path}-wal").unlink(missing_ok=True)
            Path(f"{path}-shm").unlink(missing_ok=True)
            cleanup_parents.add(path.parent)
        authority_temporary.unlink(missing_ok=True)
        cleanup_parents.add(authority_temporary.parent)
        inventory_temporary.unlink(missing_ok=True)
        cleanup_parents.add(inventory_temporary.parent)
        Path(f"{inventory_temporary}-wal").unlink(missing_ok=True)
        Path(f"{inventory_temporary}-shm").unlink(missing_ok=True)
        attestation_path.unlink(missing_ok=True)
        cleanup_parents.add(attestation_path.parent)
        for parent in cleanup_parents:
            _fsync_directory(parent)
        raise


def verify_storage_split_attestation(
    document: Mapping[str, Any],
    *,
    source_database: Path,
    authority_database: Path,
    inventory_database: Path,
    expected_uid: int,
    authority_owner_uid: int,
    inventory_owner_uid: int,
) -> dict[str, Any]:
    """Revalidate the sealed split inputs immediately before activation."""

    if not isinstance(document, Mapping):
        raise StorageSplitError("storage split attestation must be an object")
    if document.get("kind") != SPLIT_ATTESTATION_KIND:
        raise StorageSplitError("storage split attestation kind is invalid")
    if document.get("schema_version") != SPLIT_SCHEMA_VERSION:
        raise StorageSplitError("storage split attestation schema is unsupported")
    unsigned = {key: value for key, value in document.items() if key != "document_sha256"}
    if document.get("document_sha256") != hashlib.sha256(_canonical(unsigned)).hexdigest():
        raise StorageSplitError("storage split attestation digest is invalid")
    source = _source_identity(source_database, expected_uid=expected_uid)
    recorded_source = document.get("source")
    if not isinstance(recorded_source, Mapping):
        raise StorageSplitError("storage split source evidence is invalid")
    for field in ("device", "inode", "size", "mtime_ns", "mode", "owner_uid"):
        if source[field] != recorded_source.get(field):
            raise StorageSplitError("legacy rollback source identity changed")
    if _sha256_file(source_database) != recorded_source.get("sha256"):
        raise StorageSplitError("legacy rollback source digest changed")
    authority_info = authority_database.lstat()
    inventory_info = inventory_database.lstat()
    for label, path, info, uid, recorded in (
        (
            "authority",
            authority_database,
            authority_info,
            authority_owner_uid,
            document.get("authority", {}).get("file")
            if isinstance(document.get("authority"), Mapping)
            else None,
        ),
        (
            "inventory",
            inventory_database,
            inventory_info,
            inventory_owner_uid,
            document.get("inventory", {}).get("database")
            if isinstance(document.get("inventory"), Mapping)
            else None,
        ),
    ):
        if (
            not isinstance(recorded, Mapping)
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o077
            or int(info.st_size) != recorded.get("size")
            or _sha256_file(path) != recorded.get("sha256")
        ):
            raise StorageSplitError(f"{label} split store changed after attestation")
    authority_evidence = document.get("authority")
    if not isinstance(authority_evidence, Mapping) or not isinstance(
        authority_evidence.get("authority_tables"), Mapping
    ):
        raise StorageSplitError("authority logical signatures are missing")
    with closing(
        sqlite3.connect(
            f"file:{authority_database}?mode=ro",
            uri=True,
            timeout=30.0,
        )
    ) as connection:
        connection.row_factory = sqlite3.Row
        check = connection.execute("PRAGMA quick_check").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if check is None or str(check[0]) != "ok" or foreign_keys:
            raise StorageSplitError("authority split store integrity changed")
        names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        recorded_tables = authority_evidence["authority_tables"]
        if names != set(recorded_tables):
            raise StorageSplitError("authority split table set changed")
        for table in sorted(names):
            actual = _table_signature(connection, schema="main", table=table)
            actual = {key: value for key, value in actual.items() if key != "columns"}
            if actual != recorded_tables.get(table):
                raise StorageSplitError(
                    f"authority logical signature changed for table {table}"
                )
            if table in TEST_TABLES and int(actual["row_count"]) != 0:
                raise StorageSplitError("test history regrew inside authority")
    inventory_state = read_sealed_inventory_store(
        inventory_database,
        expected_owner_uid=inventory_owner_uid,
    )
    recorded_inventory = document.get("inventory")
    if (
        not isinstance(recorded_inventory, Mapping)
        or inventory_state["generation"] != recorded_inventory.get("generation")
        or inventory_state["payload_sha256"]
        != recorded_inventory.get("payload_sha256")
        or inventory_state["logical_bytes"] != recorded_inventory.get("logical_bytes")
    ):
        raise StorageSplitError("retained inventory logical state changed")
    return dict(document)


__all__ = [
    "AUTHORITY_TABLES",
    "CURRENT_OBSERVATION_TABLES",
    "SPLIT_ATTESTATION_KIND",
    "SPLIT_SCHEMA_VERSION",
    "StorageSplitError",
    "TEST_TABLES",
    "split_legacy_storage",
    "verify_storage_split_attestation",
]
