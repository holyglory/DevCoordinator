#!/usr/bin/env python3
"""Focused recall and false-positive tests for the schema-readiness verifier."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile


SCRIPT = Path(__file__).with_name("verify_coordinator_schema_readiness.py")
SPEC = importlib.util.spec_from_file_location(
    "verify_coordinator_schema_readiness", SCRIPT
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import schema-readiness verifier")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_code(callable_value: object, code: str) -> None:
    try:
        callable_value()
    except MODULE.ReadinessError as error:
        expect(error.code == code, f"expected {code}, received {error.code}")
    else:
        raise AssertionError(f"verifier did not reject {code}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="schema-readiness-test-") as raw:
        root = Path(raw)
        database = root / "coordinator.sqlite3"
        with MODULE.CoordinatorStore.open(database, expected_uid=os.geteuid()):
            pass

        first = MODULE.verify_database(
            database,
            expected_uid=os.geteuid(),
            expected_schema=MODULE.SCHEMA_VERSION,
        )
        expect(first["ok"] is True, "current empty schema did not pass")
        expect(
            first["infrastructure_projection"]["host_count"] == 0,
            "empty infrastructure projection invented a host",
        )
        expect(
            first["database"]["sha256"]
            == MODULE.verify_database(
                database,
                expected_uid=os.geteuid(),
                expected_schema=MODULE.SCHEMA_VERSION,
            )["database"]["sha256"],
            "readiness verification changed database content",
        )

        connection = sqlite3.connect(database)
        try:
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    process_fingerprint, error_code, error_message, result_json,
                    created_at, updated_at
                ) VALUES (
                    '00000000-0000-4000-8000-000000000001',
                    NULL, NULL, 'test', 'running', 'fixture', 0,
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    NULL, 'self-test', NULL, NULL, NULL, NULL,
                    '2026-07-29T00:00:00Z', '2026-07-29T00:00:00Z'
                )
                """
            )
            connection.commit()
        finally:
            connection.close()
        expect_code(
            lambda: MODULE.verify_database(
                database,
                expected_uid=os.geteuid(),
                expected_schema=MODULE.SCHEMA_VERSION,
            ),
            "nonterminal_operations",
        )

        connection = sqlite3.connect(database)
        try:
            connection.execute("DELETE FROM operations")
            connection.commit()
        finally:
            connection.close()
        expect(
            MODULE.verify_database(
                database,
                expected_uid=os.geteuid(),
                expected_schema=MODULE.SCHEMA_VERSION,
            )["checks"]["semantic_invariants"]
            == "ok",
            "terminal fixture did not recover after removing the running operation",
        )
        expect_code(
            lambda: MODULE.verify_database(
                database,
                expected_uid=os.geteuid() + 1,
                expected_schema=MODULE.SCHEMA_VERSION,
            ),
            "verifier_uid_mismatch",
        )
        expect_code(
            lambda: MODULE.verify_database(
                database,
                expected_uid=os.geteuid(),
                expected_schema=MODULE.SCHEMA_VERSION - 1,
            ),
            "verifier_schema_mismatch",
        )

    print(
        "schema-readiness verifier self-test ok "
        "(current schema, read-only stability, running-operation recall, UID/schema fences)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
