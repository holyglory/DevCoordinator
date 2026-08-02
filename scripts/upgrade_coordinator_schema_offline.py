#!/usr/bin/env python3
"""Upgrade one quiesced Coordinator database in one guarded transaction.

This command is intentionally narrower than normal Coordinator startup.  It
performs only the schema migration on an existing private database owned by the
effective UID.  The deployment transaction must already have stopped every
writer and captured the main file plus WAL/SHM sidecars for rollback.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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

from devcoordinator.schema import (  # noqa: E402
    SCHEMA_VERSION,
    initialize_schema,
    invariant_violations,
)
from devcoordinator.store import (  # noqa: E402
    StoreError,
    exclusive_maintenance_lock,
)


MAX_DATABASE_BYTES = 64 * 1024 * 1024 * 1024
CORE_COUNT_TABLES = (
    "repositories",
    "server_definitions",
    "leases",
    "operations",
    "events",
)


class OfflineUpgradeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _database_identity(path: Path, *, expected_uid: int) -> dict[str, Any]:
    if not path.is_absolute() or ".." in path.parts:
        raise OfflineUpgradeError(
            "unsafe_database_path", "database path must be absolute and normalized"
        )
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise OfflineUpgradeError(
            "database_missing", "database or its protected parent is missing"
        ) from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise OfflineUpgradeError(
            "unsafe_database_parent",
            "database parent must be private and owned by the effective UID",
        )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_DATABASE_BYTES
    ):
        raise OfflineUpgradeError(
            "unsafe_database_file",
            "database must be one private, singly-linked regular file",
        )
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "size_bytes": int(metadata.st_size),
    }


def _database_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               observation_revision, authority_mode, migration_state
        FROM schema_metadata
        WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        raise OfflineUpgradeError(
            "schema_metadata_missing", "database has no singleton schema metadata"
        )
    return {key: row[key] for key in row.keys()}


def _counts(connection: sqlite3.Connection) -> dict[str, int]:
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = sorted(set(CORE_COUNT_TABLES) - present)
    if missing:
        raise OfflineUpgradeError(
            "core_schema_missing",
            "database lacks a required pre-upgrade core table",
        )
    return {
        table: int(
            connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        )
        for table in CORE_COUNT_TABLES
    }


def _require_integrity(connection: sqlite3.Connection, *, phase: str) -> None:
    integrity = [
        tuple(row) for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    foreign_keys = [
        tuple(row)
        for row in connection.execute("PRAGMA foreign_key_check").fetchall()
    ]
    if integrity != [("ok",)]:
        raise OfflineUpgradeError(
            f"{phase}_integrity_failed",
            f"SQLite integrity_check failed during {phase}",
        )
    if foreign_keys:
        raise OfflineUpgradeError(
            f"{phase}_foreign_keys_failed",
            f"SQLite foreign_key_check failed during {phase}",
        )


def upgrade_database(
    database: Path,
    *,
    expected_uid: int,
    expected_before: int,
    expected_after: int,
    timestamp: str,
) -> dict[str, Any]:
    if expected_uid != os.geteuid():
        raise OfflineUpgradeError(
            "upgrade_uid_mismatch",
            "offline upgrade must run as the database owner UID",
        )
    if expected_after != SCHEMA_VERSION or not 1 <= expected_before < expected_after:
        raise OfflineUpgradeError(
            "upgrade_version_contract_mismatch",
            "requested versions do not match the target source migration contract",
        )
    try:
        parsed_timestamp = datetime.strptime(
            timestamp, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise OfflineUpgradeError(
            "upgrade_timestamp_invalid",
            "migration timestamp must be second-resolution RFC3339 UTC",
        ) from error
    if (
        parsed_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") != timestamp
        or not 2000 <= parsed_timestamp.year <= 9999
    ):
        raise OfflineUpgradeError(
            "upgrade_timestamp_invalid",
            "migration timestamp must be canonical second-resolution RFC3339 UTC",
        )
    before_identity = _database_identity(database, expected_uid=expected_uid)
    before_sha256 = _database_sha256(database)

    with exclusive_maintenance_lock(
        database,
        expected_uid=expected_uid,
        timeout_seconds=60,
    ):
        connection = sqlite3.connect(
            database,
            isolation_level=None,
            timeout=60,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 60000")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
            journal_mode = str(
                connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise OfflineUpgradeError(
                    "journal_mode_invalid", "Coordinator database is not in WAL mode"
                )
            _require_integrity(connection, phase="before")
            before = _metadata(connection)
            if int(before["schema_version"]) != expected_before:
                raise OfflineUpgradeError(
                    "source_schema_mismatch",
                    "database does not match the exact approved source schema",
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
                raise OfflineUpgradeError(
                    "nonterminal_operations",
                    "database has planned or running operations",
                )
            counts_before = _counts(connection)

            connection.execute("BEGIN IMMEDIATE")
            try:
                initialize_schema(
                    connection,
                    database_generation=str(before["database_generation"]),
                    timestamp=timestamp,
                )
                after = _metadata(connection)
                counts_after = _counts(connection)
                violations = invariant_violations(
                    connection, include_foreign_keys=True
                )
                if violations:
                    raise OfflineUpgradeError(
                        "semantic_invariant_failed",
                        "target schema semantic invariants are not satisfied",
                    )
                if (
                    int(after["schema_version"]) != expected_after
                    or str(after["database_generation"])
                    != str(before["database_generation"])
                    or int(after["state_revision"]) != int(before["state_revision"])
                    or int(after["observation_revision"])
                    != int(before["observation_revision"])
                    or counts_after != counts_before
                ):
                    raise OfflineUpgradeError(
                        "migration_preservation_failed",
                        "schema upgrade changed a preserved identity, revision, or core row count",
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

            checkpoint = tuple(
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            )
            if checkpoint[0] != 0:
                raise OfflineUpgradeError(
                    "checkpoint_busy",
                    "target schema committed but the quiesced WAL checkpoint was busy",
                )
            _require_integrity(connection, phase="after")
        finally:
            connection.close()

    after_identity = _database_identity(database, expected_uid=expected_uid)
    if (
        before_identity["device"],
        before_identity["inode"],
    ) != (
        after_identity["device"],
        after_identity["inode"],
    ):
        raise OfflineUpgradeError(
            "database_identity_changed",
            "database inode changed during the in-place offline upgrade",
        )
    return {
        "ok": True,
        "receipt_contract": "devcoordinator.offline-schema-upgrade.v1",
        "database": str(database),
        "database_owner_uid": expected_uid,
        "migration_timestamp": timestamp,
        "schema_before": expected_before,
        "schema_after": expected_after,
        "database_generation_sha256": hashlib.sha256(
            str(before["database_generation"]).encode("utf-8")
        ).hexdigest(),
        "state_revision": int(before["state_revision"]),
        "observation_revision": int(before["observation_revision"]),
        "core_counts": counts_before,
        "database_before": {
            "size_bytes": before_identity["size_bytes"],
            "sha256": before_sha256,
        },
        "database_after": {
            "size_bytes": after_identity["size_bytes"],
            "sha256": _database_sha256(database),
        },
        "checks": {
            "integrity_before": "ok",
            "foreign_keys_before": "ok",
            "semantic_invariants_after": "ok",
            "integrity_after": "ok",
            "foreign_keys_after": "ok",
            "nonterminal_operations": 0,
            "wal_checkpoint": "ok",
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--expected-before", type=int, required=True)
    parser.add_argument("--expected-after", type=int, default=SCHEMA_VERSION)
    parser.add_argument("--timestamp", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = upgrade_database(
            args.database,
            expected_uid=args.expected_uid,
            expected_before=args.expected_before,
            expected_after=args.expected_after,
            timestamp=args.timestamp,
        )
    except (
        OfflineUpgradeError,
        StoreError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        code = (
            error.code
            if isinstance(error, OfflineUpgradeError)
            else "offline_upgrade_error"
        )
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
