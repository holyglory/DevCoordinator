#!/usr/bin/env python3
"""Prove one quiesced Coordinator database is safe to start with current code.

The verifier is deliberately read-only.  It checks the protected filesystem
boundary, the exact current schema, SQLite integrity and foreign keys, semantic
invariants, representative legacy storage projections, and the public
remote-infrastructure read projection.  It emits only bounded counts and
digests; repository, operation, lease, and infrastructure identities are not
copied into deployment evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.infrastructure_observation import (  # noqa: E402
    InfrastructureObservationError,
    InfrastructureObservationAuthority,
)
from devcoordinator.schema import (  # noqa: E402
    SCHEMA_VERSION,
    invariant_violations,
)
from devcoordinator.store import CoordinatorStore, StoreError  # noqa: E402


MAX_DATABASE_BYTES = 64 * 1024 * 1024 * 1024
HASH_BLOCK_BYTES = 1024 * 1024
INFRASTRUCTURE_PROJECTION_SCHEMA = "spectre.infrastructure.projection.v1"


class ReadinessError(RuntimeError):
    """A stable, non-secret database-readiness failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        while True:
            chunk = os.read(descriptor, HASH_BLOCK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _private_database_identity(path: Path, *, expected_uid: int) -> dict[str, int]:
    if not path.is_absolute() or ".." in path.parts:
        raise ReadinessError(
            "unsafe_database_path", "database path must be absolute and normalized"
        )
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReadinessError(
            "database_missing", "database or its protected parent is missing"
        ) from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise ReadinessError(
            "unsafe_database_parent",
            "database parent must be a private directory owned by the verifier UID",
        )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_DATABASE_BYTES
    ):
        raise ReadinessError(
            "unsafe_database_file",
            "database must be one private, singly-linked regular file owned by the verifier UID",
        )
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "size_bytes": int(metadata.st_size),
    }


def _legacy_projection_counts(connection: sqlite3.Connection) -> dict[str, int]:
    """Exercise bounded legacy list/event/lease reads without disclosing IDs."""

    required_tables = (
        "repositories",
        "repository_installations",
        "server_definitions",
        "leases",
        "operations",
        "events",
        "event_journal_sequences",
    )
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = sorted(set(required_tables) - present)
    if missing:
        raise ReadinessError(
            "legacy_projection_missing",
            "current schema is missing a required legacy projection table",
        )

    # These are the same ordering and join shapes used by the bounded
    # repository/server/event views.  Fetching a bounded page catches migrated
    # column or index incompatibilities while evidence retains counts only.
    connection.execute(
        """
        SELECT repository.repo_id, repository.state, repository.generation,
               installation.status, installation.startup_fenced
        FROM repositories AS repository
        LEFT JOIN repository_installations AS installation USING(repo_id)
        ORDER BY repository.repo_id
        LIMIT 65
        """
    ).fetchall()
    connection.execute(
        """
        SELECT server_definition_id, repo_id, name, role, generation
        FROM server_definitions
        ORDER BY server_definition_id
        LIMIT 257
        """
    ).fetchall()
    connection.execute(
        """
        SELECT sequence.sequence, event.event_id, event.event_kind, event.occurred_at
        FROM event_journal_sequences AS sequence
        JOIN events AS event USING(event_id)
        ORDER BY sequence.sequence DESC
        LIMIT 257
        """
    ).fetchall()
    connection.execute(
        """
        SELECT lease_id, repo_id, server_definition_id, status, generation
        FROM leases
        ORDER BY lease_id
        LIMIT 257
        """
    ).fetchall()

    unsequenced_events = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM events AS event
            LEFT JOIN event_journal_sequences AS sequence USING(event_id)
            WHERE sequence.event_id IS NULL
            """
        ).fetchone()[0]
    )
    dangling_sequences = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM event_journal_sequences AS sequence
            LEFT JOIN events AS event USING(event_id)
            WHERE event.event_id IS NULL
            """
        ).fetchone()[0]
    )
    if unsequenced_events or dangling_sequences:
        raise ReadinessError(
            "legacy_event_projection_invalid",
            "legacy event pagination has missing or dangling sequence rows",
        )
    return {
        "repositories": int(
            connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
        ),
        "server_definitions": int(
            connection.execute("SELECT COUNT(*) FROM server_definitions").fetchone()[0]
        ),
        "leases": int(
            connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
        ),
        "operations": int(
            connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        ),
        "events": int(
            connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        ),
    }


def verify_database(
    database: Path,
    *,
    expected_uid: int,
    expected_schema: int,
) -> dict[str, Any]:
    if expected_uid != os.geteuid():
        raise ReadinessError(
            "verifier_uid_mismatch",
            "the verifier must run as the database owner UID",
        )
    if expected_schema != SCHEMA_VERSION:
        raise ReadinessError(
            "verifier_schema_mismatch",
            "requested schema does not match the verifier source contract",
        )

    before = _private_database_identity(database, expected_uid=expected_uid)
    before_sha256 = _sha256(database)
    with CoordinatorStore.open_read_only(
        database,
        expected_uid=expected_uid,
        busy_timeout_ms=30_000,
    ) as store:
        with store.read_transaction() as connection:
            metadata = connection.execute(
                """
                SELECT schema_version, database_generation, state_revision,
                       observation_revision, authority_mode, migration_state
                FROM schema_metadata
                WHERE singleton = 1
                """
            ).fetchone()
            if metadata is None or int(metadata["schema_version"]) != expected_schema:
                raise ReadinessError(
                    "schema_version_mismatch",
                    "database is not at the exact target schema",
                )
            integrity = [
                tuple(row)
                for row in connection.execute("PRAGMA integrity_check").fetchall()
            ]
            foreign_keys = [
                tuple(row)
                for row in connection.execute("PRAGMA foreign_key_check").fetchall()
            ]
            if integrity != [("ok",)]:
                raise ReadinessError(
                    "integrity_check_failed", "SQLite integrity_check did not return ok"
                )
            if foreign_keys:
                raise ReadinessError(
                    "foreign_key_check_failed",
                    "SQLite foreign_key_check found retained violations",
                )
            violations = invariant_violations(
                connection, include_foreign_keys=False
            )
            if violations:
                raise ReadinessError(
                    "semantic_invariant_failed",
                    "Coordinator semantic invariants are not satisfied",
                )
            running = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM operations
                    WHERE status IN ('planned', 'running')
                    """
                ).fetchone()[0]
            )
            if running:
                raise ReadinessError(
                    "nonterminal_operations",
                    "Coordinator has planned or running operations",
                )
            legacy_counts = _legacy_projection_counts(connection)
            metadata_result = {
                "schema_version": int(metadata["schema_version"]),
                "database_generation_sha256": hashlib.sha256(
                    str(metadata["database_generation"]).encode("utf-8")
                ).hexdigest(),
                "state_revision": int(metadata["state_revision"]),
                "observation_revision": int(metadata["observation_revision"]),
                "authority_mode": str(metadata["authority_mode"]),
                "migration_state": str(metadata["migration_state"]),
            }

    infrastructure = InfrastructureObservationAuthority(
        database,
        expected_uid=expected_uid,
        busy_timeout_ms=30_000,
    ).read_projection({})
    if (
        infrastructure.get("schema") != INFRASTRUCTURE_PROJECTION_SCHEMA
        or not isinstance(infrastructure.get("hosts"), list)
        or infrastructure.get("has_more") not in (True, False)
    ):
        raise ReadinessError(
            "infrastructure_projection_invalid",
            "remote-infrastructure projection did not satisfy its public read contract",
        )

    after = _private_database_identity(database, expected_uid=expected_uid)
    after_sha256 = _sha256(database)
    if before != after or before_sha256 != after_sha256:
        raise ReadinessError(
            "database_changed_during_verification",
            "database identity or content changed during quiesced verification",
        )
    return {
        "ok": True,
        "schema": metadata_result,
        "database": {
            "size_bytes": after["size_bytes"],
            "sha256": after_sha256,
        },
        "checks": {
            "integrity_check": "ok",
            "foreign_key_check": "ok",
            "semantic_invariants": "ok",
            "nonterminal_operations": 0,
        },
        "legacy_projection_counts": legacy_counts,
        "infrastructure_projection": {
            "schema": str(infrastructure["schema"]),
            "host_count": len(infrastructure["hosts"]),
            "has_more": bool(infrastructure["has_more"]),
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--expected-schema", type=int, default=SCHEMA_VERSION)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = verify_database(
            args.database,
            expected_uid=args.expected_uid,
            expected_schema=args.expected_schema,
        )
    except (
        ReadinessError,
        InfrastructureObservationError,
        StoreError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        code = error.code if isinstance(error, ReadinessError) else "verification_error"
        print(
            json.dumps(
                {"ok": False, "code": code, "message": str(error)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
