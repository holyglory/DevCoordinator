"""Durable, bounded coordinator event journal reads and writes."""

from __future__ import annotations

import base64
import json
import sqlite3
from typing import Any, Mapping

from .store import canonical_json, deterministic_id


MAX_EVENT_PAGE_SIZE = 500
DEFAULT_EVENT_PAGE_SIZE = 100
MAX_EVENT_CURSOR_LENGTH = 1024


def append_observation_transition(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    repo_id: str | None,
    operation_id: str | None,
    resource_kind: str,
    resource_id: str,
    event_kind: str,
    code: str,
    message: str,
    diagnostic: Mapping[str, Any],
    occurred_at: str,
) -> str:
    """Append one idempotent event owned by an observation snapshot.

    A single-flight observation commits once, but the deterministic identifier
    also makes a repeated callback for the same snapshot/resource transition
    harmless.  The event and observed state share the caller's transaction.
    """

    event_id = deterministic_id(
        "observation-transition",
        snapshot_id,
        resource_kind,
        resource_id,
        event_kind,
        code,
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO events(
            event_id, repo_id, source_id, operation_id, event_kind,
            code, message, diagnostic_json, occurred_at
        ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            repo_id,
            operation_id,
            event_kind,
            code,
            message,
            canonical_json(dict(diagnostic)),
            occurred_at,
        ),
    )
    return event_id


def encode_event_cursor(sequence: int, event_id: str) -> str:
    if type(sequence) is not int or sequence < 0:
        raise ValueError("event cursor sequence must be a non-negative integer")
    payload = canonical_json({"seq": sequence, "id": event_id}).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_event_cursor(cursor: str) -> tuple[int, str]:
    if (
        not isinstance(cursor, str)
        or not cursor
        or len(cursor) > MAX_EVENT_CURSOR_LENGTH
    ):
        raise ValueError("event cursor must be a bounded non-empty string")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(
            cursor + padding,
            altchars=b"-_",
            validate=True,
        )
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("event cursor is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"seq", "id"}:
        raise ValueError("event cursor is invalid")
    sequence = value["seq"]
    event_id = value["id"]
    if (
        type(sequence) is not int
        or sequence < 0
        or not isinstance(event_id, str)
        or not 1 <= len(event_id) <= 512
        or any(character in event_id for character in "\x00\r\n")
    ):
        raise ValueError("event cursor is invalid")
    return sequence, event_id


def list_event_page(
    connection: sqlite3.Connection,
    *,
    after: str | None = None,
    limit: int = DEFAULT_EVENT_PAGE_SIZE,
) -> dict[str, Any]:
    """Return an ascending, lossless page without diagnostic/private fields."""

    if type(limit) is not int or not 1 <= limit <= MAX_EVENT_PAGE_SIZE:
        raise ValueError(
            f"event page limit must be an integer from 1 through {MAX_EVENT_PAGE_SIZE}"
        )
    parameters: list[Any] = []
    where = ""
    if after is not None:
        sequence, _event_id = decode_event_cursor(after)
        where = "WHERE s.sequence > ?"
        parameters.append(sequence)
    parameters.append(limit + 1)
    rows = connection.execute(
        f"""
        SELECT e.event_id, e.repo_id, e.event_kind, e.code, e.message,
               e.occurred_at, s.sequence AS _journal_sequence
        FROM event_journal_sequences s
        JOIN events e USING(event_id)
        {where}
        ORDER BY s.sequence
        LIMIT ?
        """,
        tuple(parameters),
    ).fetchall()
    has_more = len(rows) > limit
    selected = rows[:limit]
    events = [
        {
            "event_id": row["event_id"],
            "repo_id": row["repo_id"],
            "event_kind": row["event_kind"],
            "code": row["code"],
            "message": row["message"],
            "occurred_at": row["occurred_at"],
        }
        for row in selected
    ]
    next_cursor = after
    if selected:
        last = selected[-1]
        next_cursor = encode_event_cursor(
            int(last["_journal_sequence"]), str(last["event_id"])
        )
    return {
        "schema_version": 1,
        "events": events,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }


__all__ = [
    "DEFAULT_EVENT_PAGE_SIZE",
    "MAX_EVENT_CURSOR_LENGTH",
    "MAX_EVENT_PAGE_SIZE",
    "append_observation_transition",
    "decode_event_cursor",
    "encode_event_cursor",
    "list_event_page",
]
