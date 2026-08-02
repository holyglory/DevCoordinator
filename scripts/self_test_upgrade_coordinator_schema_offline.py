#!/usr/bin/env python3
"""Focused transaction and safety tests for the offline schema upgrader."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile


SCRIPT = Path(__file__).with_name("upgrade_coordinator_schema_offline.py")
SPEC = importlib.util.spec_from_file_location(
    "upgrade_coordinator_schema_offline", SCRIPT
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import offline schema upgrader")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

READINESS_SCRIPT = Path(__file__).with_name(
    "verify_coordinator_schema_readiness.py"
)
READINESS_SPEC = importlib.util.spec_from_file_location(
    "verify_coordinator_schema_readiness_for_upgrade_test",
    READINESS_SCRIPT,
)
if READINESS_SPEC is None or READINESS_SPEC.loader is None:
    raise RuntimeError("cannot import schema-readiness verifier")
READINESS = importlib.util.module_from_spec(READINESS_SPEC)
READINESS_SPEC.loader.exec_module(READINESS)

from devcoordinator.store import CoordinatorStore


INFRASTRUCTURE_TABLE_DROP_ORDER = (
    "infrastructure_current_vms",
    "infrastructure_current_hosts",
    "infrastructure_ingest_audit",
    "infrastructure_ingest_operations",
    "infrastructure_observations",
    "infrastructure_agent_replay_state",
    "infrastructure_agent_boot_history",
    "infrastructure_agent_certificates",
    "infrastructure_admin_receipts",
    "infrastructure_observer_agents",
    "infrastructure_host_vm_scope",
    "infrastructure_hosts",
    "infrastructure_cells",
)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_code(callable_value: object, code: str) -> None:
    try:
        callable_value()
    except MODULE.OfflineUpgradeError as error:
        expect(error.code == code, f"expected {code}, received {error.code}")
    else:
        raise AssertionError(f"offline upgrader did not reject {code}")


def create_v4_fixture(database: Path, *, running: bool) -> None:
    with CoordinatorStore.open(database, expected_uid=os.geteuid()) as store:
        with store.immediate_transaction(
            revision_kind=None, check_invariants=False
        ) as connection:
            if running:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, source_id, kind, status, phase,
                        generation, request_fingerprint, owner_uid, actor,
                        created_at, updated_at
                    ) VALUES (
                        '00000000-0000-4000-8000-000000000001',
                        NULL, NULL, 'test', 'running', 'fixture', 0,
                        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                        NULL, 'self-test',
                        '2026-07-29T00:00:00Z', '2026-07-29T00:00:00Z'
                    )
                    """
                )
            connection.execute("DROP TABLE repository_scopes")
            connection.execute("DROP TABLE repository_families")
            for table in INFRASTRUCTURE_TABLE_DROP_ORDER:
                connection.execute(f"DROP TABLE {table}")
            connection.execute(
                "UPDATE schema_metadata SET schema_version = 4 WHERE singleton = 1"
            )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="offline-schema-upgrade-test-") as raw:
        root = Path(raw)
        database = root / "coordinator.sqlite3"
        create_v4_fixture(database, running=True)

        expect_code(
            lambda: MODULE.upgrade_database(
                database,
                expected_uid=os.geteuid(),
                expected_before=4,
                expected_after=MODULE.SCHEMA_VERSION,
                timestamp="2026-07-29T16:30:00Z",
            ),
            "nonterminal_operations",
        )
        connection = sqlite3.connect(database)
        try:
            schema = int(
                connection.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            )
            connection.execute("DELETE FROM operations")
            connection.commit()
        finally:
            connection.close()
        expect(schema == 4, "rejected upgrade changed the source schema")

        result = MODULE.upgrade_database(
            database,
            expected_uid=os.geteuid(),
            expected_before=4,
            expected_after=MODULE.SCHEMA_VERSION,
            timestamp="2026-07-29T16:30:00Z",
        )
        expect(result["ok"] is True, "valid v4-to-v14 upgrade did not pass")
        expect(
            result["schema_before"] == 4
            and result["schema_after"] == MODULE.SCHEMA_VERSION,
            "upgrade evidence lost its exact schema boundary",
        )
        expect(
            result["receipt_contract"]
            == "devcoordinator.offline-schema-upgrade.v1"
            and result["database"] == str(database)
            and result["database_owner_uid"] == os.geteuid()
            and result["migration_timestamp"] == "2026-07-29T16:30:00Z",
            "upgrade evidence is not bound to its database, owner, and timestamp",
        )
        expect(
            result["checks"]["wal_checkpoint"] == "ok",
            "upgrade did not prove a quiesced WAL checkpoint",
        )
        readiness = READINESS.verify_database(
            database,
            expected_uid=os.geteuid(),
            expected_schema=MODULE.SCHEMA_VERSION,
        )
        expect(
            readiness["checks"]["semantic_invariants"] == "ok",
            "upgraded database did not pass independent readiness",
        )
        expect_code(
            lambda: MODULE.upgrade_database(
                database,
                expected_uid=os.geteuid(),
                expected_before=4,
                expected_after=MODULE.SCHEMA_VERSION,
                timestamp="2026-07-29T16:30:00Z",
            ),
            "source_schema_mismatch",
        )
        expect_code(
            lambda: MODULE.upgrade_database(
                database,
                expected_uid=os.geteuid() + 1,
                expected_before=4,
                expected_after=MODULE.SCHEMA_VERSION,
                timestamp="2026-07-29T16:30:00Z",
            ),
            "upgrade_uid_mismatch",
        )
        expect_code(
            lambda: MODULE.upgrade_database(
                database,
                expected_uid=os.geteuid(),
                expected_before=4,
                expected_after=MODULE.SCHEMA_VERSION,
                timestamp="not-a-timestamp",
            ),
            "upgrade_timestamp_invalid",
        )

    print(
        "offline schema upgrader self-test ok "
        "(quiescence rejection, transactional v4-v14 preservation, independent readiness, UID/time fences)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
