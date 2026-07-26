#!/usr/bin/env python3
"""Focused guards for the offline deployment transaction."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile


SCRIPT = Path(__file__).with_name("deploy_server_wide_maintenance.py")
SPEC = importlib.util.spec_from_file_location("deploy_server_wide_maintenance", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import maintenance deployment driver")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def driver_for(root: Path) -> object:
    driver = object.__new__(MODULE.Driver)
    driver.raw_checkpoint = root / "writer-free-database"
    driver.database_captured = False
    driver.journal = lambda **_extra: None
    return driver


def initialize_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE schema_metadata(
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                database_generation TEXT NOT NULL
            );
            INSERT INTO schema_metadata VALUES (1, 9, 'generation-a');
            CREATE TABLE operations(
                operation_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


class InventoryResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.status = 200

    def __enter__(self) -> "InventoryResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.payload if limit < 0 else self.payload[:limit]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="maintenance-deploy-test-") as raw:
        root = Path(raw).resolve()
        database = root / "coordinator.sqlite3"
        initialize_database(database)
        previous = MODULE.DATABASE
        MODULE.DATABASE = database
        try:
            driver = driver_for(root)
            evidence = driver.schema_evidence(expected=9)
            expect(evidence["schema_version"] == 9, "schema preflight lost its version")

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO operations VALUES ('operation-a', 'test', 'planned')"
                )
                connection.commit()
            finally:
                connection.close()
            try:
                driver.schema_evidence(expected=9)
            except MODULE.DeploymentError as error:
                expect(
                    "non-terminal operations" in str(error),
                    "pending-operation guard returned the wrong failure",
                )
            else:
                raise AssertionError("planned operation was accepted as quiescent")

            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM operations")
                connection.commit()
            finally:
                connection.close()
            before = database.read_bytes()
            driver.capture_database()
            manifest = json.loads(
                (driver.raw_checkpoint / "manifest.json").read_text(encoding="utf-8")
            )
            expect(
                manifest[database.name]["sha256"]
                == MODULE.hashlib.sha256(before).hexdigest(),
                "writer-free checkpoint did not bind the source checksum",
            )
            database.write_bytes(b"not a sqlite database")
            database.chmod(0o600)
            Path(f"{database}-wal").write_bytes(b"unexpected wal")
            Path(f"{database}-wal").chmod(0o600)
            driver.restore_database()
            expect(database.read_bytes() == before, "rollback did not restore exact bytes")
            expect(
                not Path(f"{database}-wal").exists(),
                "rollback retained a sidecar that was absent at checkpoint",
            )
        finally:
            MODULE.DATABASE = previous

    with tempfile.TemporaryDirectory(prefix="maintenance-inventory-test-") as raw:
        root = Path(raw).resolve()
        token_file = root / "api-token"
        token_file.write_text("fixture-token\n", encoding="utf-8")
        token_file.chmod(0o600)
        driver = object.__new__(MODULE.Driver)
        driver.token_file = token_file
        driver.transaction = root
        padding = "x" * (8 * 1024 * 1024)
        response_payload = json.dumps({"padding": padding}).encode("utf-8")
        previous_urlopen = MODULE.urllib.request.urlopen
        MODULE.urllib.request.urlopen = lambda *_args, **_kwargs: InventoryResponse(
            response_payload
        )
        try:
            inventory = driver.inventory("large-inventory.json")
        finally:
            MODULE.urllib.request.urlopen = previous_urlopen
        expect(
            inventory == {"padding": padding},
            "authenticated inventory larger than the former 8 MiB ceiling was truncated",
        )

        previous_limit = MODULE.MAX_INVENTORY_RESPONSE_BYTES
        MODULE.MAX_INVENTORY_RESPONSE_BYTES = 1024
        MODULE.urllib.request.urlopen = lambda *_args, **_kwargs: InventoryResponse(
            json.dumps({"padding": "x" * 2048}).encode("utf-8")
        )
        try:
            try:
                driver.inventory("oversized-inventory.json")
            except MODULE.DeploymentError as error:
                expect(
                    "exceeds the bounded 1024-byte" in str(error),
                    "oversized authenticated inventory returned the wrong failure",
                )
            else:
                raise AssertionError("oversized authenticated inventory was accepted")
        finally:
            MODULE.urllib.request.urlopen = previous_urlopen
            MODULE.MAX_INVENTORY_RESPONSE_BYTES = previous_limit

    source = SCRIPT.read_text(encoding="utf-8")
    expect('self.checkout("main")' in source, "target checkout is not explicit")
    expect("--force" not in source, "deployment can discard a dirty checkout")
    expect("self.rollback(error)" in source, "foreground failure handler is missing")
    expect(
        "clear maintenance marker after rollback" in source,
        "rollback does not retain the wait fence through health verification",
    )
    expect(
        "devcoordinator-sqlite-backup" in source,
        "deployment does not verify the canonical backup artifact type",
    )
    print("maintenance deployment self-test ok (quiescence, exact checkpoint, rollback guard)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
