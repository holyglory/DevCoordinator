"""Bound high-volume compatibility state retained by the authority store.

The final topology gives tests and retained inventory their own stores.  A
small amount of observation evidence must remain in authority for admission,
single-flight ownership, and lifecycle fencing.  This module keeps that
compatibility state explicitly bounded; it is intentionally called inside the
store-owned transaction so a crash cannot publish a new sample without also
applying its retention policy.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable


MAX_TELEMETRY_SAMPLES_PER_RESOURCE = 120
MAX_SNAPSHOTS_PER_STATUS = 2
MAX_EVENT_ROWS = 10_000
MAX_WORKER_ATTEMPTS_PER_SERVER = 256
MAX_TERMINAL_OBSERVATION_PROOFS = 2_048
_CHUNK = 400


class AuthorityRetentionError(RuntimeError):
    """The authority retention contract could not be applied safely."""


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def _chunks(values: Iterable[str]) -> Iterable[tuple[str, ...]]:
    current: list[str] = []
    for value in values:
        current.append(str(value))
        if len(current) == _CHUNK:
            yield tuple(current)
            current.clear()
    if current:
        yield tuple(current)


def _delete_terminal_observation_proofs(
    connection: sqlite3.Connection, tables: set[str]
) -> None:
    """Retain active proofs and only a bounded tail of terminal audit proofs."""

    specifications = (
        ("broker_lifecycle_plan_observations", "plan_id"),
        ("broker_compose_operation_preflights", "operation_id"),
    )
    if "operations" not in tables:
        return
    for table, operation_column in specifications:
        if table not in tables:
            continue
        connection.execute(
            f"""
            DELETE FROM {table}
            WHERE {operation_column} IN (
                SELECT operation_id FROM (
                    SELECT operation_id,
                           ROW_NUMBER() OVER (
                               ORDER BY updated_at DESC, operation_id DESC
                           ) AS retained_ordinal
                    FROM operations
                    WHERE status IN ('succeeded', 'failed', 'cancelled')
                      AND operation_id IN (
                          SELECT {operation_column} FROM {table}
                      )
                )
                WHERE retained_ordinal > ?
            )
            """,
            (MAX_TERMINAL_OBSERVATION_PROOFS,),
        )


def _referenced_snapshot_ids(
    connection: sqlite3.Connection, tables: set[str]
) -> set[str]:
    """Discover every non-cascading reference instead of guessing table names."""

    referenced: set[str] = set()
    for table in sorted(tables):
        if table.startswith("sqlite_") or table == "observation_snapshots":
            continue
        for foreign_key in connection.execute(f'PRAGMA foreign_key_list("{table}")'):
            if str(foreign_key[2]) != "observation_snapshots":
                continue
            # CASCADE children are history payload belonging to the snapshot;
            # they must disappear with it rather than pin it forever.
            if str(foreign_key[6]).upper() == "CASCADE":
                continue
            column = str(foreign_key[3])
            for row in connection.execute(
                f'SELECT DISTINCT "{column}" FROM "{table}" '
                f'WHERE "{column}" IS NOT NULL'
            ):
                referenced.add(str(row[0]))
    return referenced


def _prune_snapshots(
    connection: sqlite3.Connection, tables: set[str]
) -> None:
    required = {
        "observation_snapshots",
        "observation_capabilities",
        "observation_snapshot_resources",
    }
    if not required.issubset(tables):
        return
    _delete_terminal_observation_proofs(connection, tables)
    retained = _referenced_snapshot_ids(connection, tables)
    # Snapshot timestamps are millisecond-resolution and IDs are opaque, so a
    # burst can legitimately share one timestamp.  Retain by SQLite insertion
    # order; otherwise lexicographic ID ties can delete the just-committed
    # ticket before its caller verifies the exact observation evidence.
    retained.update(
        str(row[0])
        for row in connection.execute(
            """
            SELECT snapshot_id FROM (
                SELECT snapshot_id, status,
                       ROW_NUMBER() OVER (
                           PARTITION BY host_id, observer_domain, status
                           ORDER BY rowid DESC
                       ) AS retained_ordinal
                FROM observation_snapshots
            )
            WHERE retained_ordinal <= ? OR status = 'running'
            """,
            (MAX_SNAPSHOTS_PER_STATUS,),
        )
    )
    candidates = [
        str(row[0])
        for row in connection.execute(
            "SELECT snapshot_id FROM observation_snapshots ORDER BY rowid"
        )
        if str(row[0]) not in retained
    ]
    for chunk in _chunks(candidates):
        placeholders = ",".join("?" for _ in chunk)
        connection.execute(
            f"DELETE FROM observation_snapshots WHERE snapshot_id IN ({placeholders})",
            chunk,
        )


def _prune_telemetry(connection: sqlite3.Connection, tables: set[str]) -> None:
    if "telemetry_samples" not in tables:
        return
    connection.execute(
        """
        DELETE FROM telemetry_samples
        WHERE sample_id IN (
            SELECT sample_id FROM (
                SELECT sample_id,
                       ROW_NUMBER() OVER (
                           PARTITION BY host_resource_kind, host_resource_id
                           ORDER BY sampled_at DESC, sample_id DESC
                       ) AS retained_ordinal
                FROM telemetry_samples
            )
            WHERE retained_ordinal > ?
        )
        """,
        (MAX_TELEMETRY_SAMPLES_PER_RESOURCE,),
    )


def _prune_worker_attempts(connection: sqlite3.Connection, tables: set[str]) -> None:
    if "worker_attempts" not in tables:
        return
    protected: set[str] = set()
    if "worker_supervisor_states" in tables:
        protected.update(
            str(row[0])
            for row in connection.execute(
                "SELECT current_attempt_id FROM worker_supervisor_states "
                "WHERE current_attempt_id IS NOT NULL"
            )
        )
    if "worker_policies" in tables:
        protected.update(
            str(row[0])
            for row in connection.execute(
                "SELECT last_trip_attempt_id FROM worker_policies "
                "WHERE last_trip_attempt_id IS NOT NULL"
            )
        )
    candidates = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT attempt_id FROM (
                SELECT attempt_id, state,
                       ROW_NUMBER() OVER (
                           PARTITION BY server_definition_id
                           ORDER BY created_at DESC, attempt_id DESC
                       ) AS retained_ordinal
                FROM worker_attempts
            )
            WHERE state = 'exited' AND retained_ordinal > ?
            ORDER BY attempt_id
            """,
            (MAX_WORKER_ATTEMPTS_PER_SERVER,),
        )
        if str(row[0]) not in protected
    ]
    for chunk in _chunks(candidates):
        placeholders = ",".join("?" for _ in chunk)
        if "worker_exit_decisions" in tables:
            connection.execute(
                f"DELETE FROM worker_exit_decisions WHERE attempt_id IN ({placeholders})",
                chunk,
            )
        connection.execute(
            f"DELETE FROM worker_attempts WHERE attempt_id IN ({placeholders})",
            chunk,
        )


def _event_reference_columns(
    connection: sqlite3.Connection, tables: set[str]
) -> tuple[tuple[str, str], ...]:
    result: set[tuple[str, str]] = set()
    for table in sorted(tables):
        if table.startswith("sqlite_") or table in {"events", "event_journal_sequences"}:
            continue
        for foreign_key in connection.execute(f'PRAGMA foreign_key_list("{table}")'):
            if str(foreign_key[2]) == "events":
                result.add((table, str(foreign_key[3])))
    # These fields intentionally predate their foreign-key constraints but
    # still constitute live breaker state.
    if "worker_policies" in tables:
        result.add(("worker_policies", "last_trip_event_id"))
    return tuple(sorted(result))


def _prune_events(connection: sqlite3.Connection, tables: set[str]) -> None:
    required = {"events", "event_journal_sequences"}
    if not required.issubset(tables):
        return
    count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
    overflow = count - MAX_EVENT_ROWS
    if overflow <= 0:
        return
    candidates = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT event.event_id
            FROM event_journal_sequences sequence
            JOIN events event USING(event_id)
            ORDER BY sequence.sequence, event.event_id
            LIMIT ?
            """,
            (overflow,),
        )
    ]
    referenced: set[str] = set()
    for table, column in _event_reference_columns(connection, tables):
        for chunk in _chunks(candidates):
            placeholders = ",".join("?" for _ in chunk)
            referenced.update(
                str(row[0])
                for row in connection.execute(
                    f'SELECT DISTINCT "{column}" FROM "{table}" '
                    f'WHERE "{column}" IN ({placeholders})',
                    chunk,
                )
            )
    removable = [event_id for event_id in candidates if event_id not in referenced]
    for chunk in _chunks(removable):
        placeholders = ",".join("?" for _ in chunk)
        connection.execute(
            f"DELETE FROM events WHERE event_id IN ({placeholders})",
            chunk,
        )


def prune_bounded_authority_state(connection: sqlite3.Connection) -> None:
    """Apply every high-volume authority retention invariant.

    The function is idempotent and relies only on schema discovery, so account
    fixtures with an older subset of tables remain supported.
    """

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("authority retention requires a SQLite connection")
    tables = _tables(connection)
    _prune_telemetry(connection, tables)
    _prune_snapshots(connection, tables)
    _prune_worker_attempts(connection, tables)
    _prune_events(connection, tables)


__all__ = [
    "AuthorityRetentionError",
    "MAX_EVENT_ROWS",
    "MAX_SNAPSHOTS_PER_STATUS",
    "MAX_TELEMETRY_SAMPLES_PER_RESOURCE",
    "MAX_TERMINAL_OBSERVATION_PROOFS",
    "MAX_WORKER_ATTEMPTS_PER_SERVER",
    "prune_bounded_authority_state",
]
