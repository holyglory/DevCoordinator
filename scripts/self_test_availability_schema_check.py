#!/usr/bin/env python3
"""Read-only regression tests for availability startup checks."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/availability_schema_check.py"
SPEC = importlib.util.spec_from_file_location("availability_schema_check", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import availability schema checker")
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (CHECK.CheckError, OSError, sqlite3.Error):
        return
    raise AssertionError(f"unsafe read-only startup condition was accepted: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="availability-schema-check-") as raw:
        root = Path(raw)
        database = root / "authority.sqlite3"
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE schema_metadata(singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO schema_metadata VALUES(1, 12)")
        connection.commit()
        connection.close()
        database.chmod(0o600)
        before = database.stat()
        result = CHECK.check_schema(database, 12)
        after = database.stat()
        expect(result["ok"] and result["read_only"], "schema check omitted read-only evidence")
        expect(
            (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
            "read-only schema check changed the database",
        )
        must_fail(lambda: CHECK.check_schema(database, 11), "unsupported schema")
        database.chmod(0o622)
        must_fail(lambda: CHECK.check_schema(database, 12), "group-writable database")
        database.chmod(0o600)

        profile = root / "client-profiles.json"
        profile_document = {
            "version": 2,
            "service": {
                "socket": "/run/devcoordinator-authority/broker.sock",
                "database_generation": "generation-alpha",
            },
            "repositories": [
                {
                    "canonical_root": "/home/example/project",
                    "repo_id": "repo-alpha",
                    "generation": 0,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                    "compose_container_ids": [],
                    "compose_run_once_services": {},
                    "ephemeral_templates": {},
                    "ephemeral_secret_policies": {},
                }
            ],
        }
        profile.write_text(
            json.dumps(profile_document),
            encoding="utf-8",
        )
        profile.chmod(0o600)
        expect(
            CHECK.check_profile(
                profile,
                2,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            )["ok"],
            "valid profile was rejected",
        )
        must_fail(
            lambda: CHECK.check_profile(
                profile,
                1,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            ),
            "unsupported profile schema",
        )
        profile.chmod(0o640)
        expect(
            CHECK.check_profile(
                profile,
                2,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            )["ok"],
            "root-owned group-readable profile was rejected",
        )
        profile.chmod(0o600)
        link = root / "profile-link.json"
        link.symlink_to(profile)
        must_fail(
            lambda: CHECK.check_profile(
                link,
                2,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            ),
            "profile symlink",
        )

        replaceable = root / "replaceable"
        replaceable.mkdir(mode=0o700)
        bad_profile = replaceable / "client-profiles.json"
        bad_profile.write_text(profile.read_text(encoding="utf-8"), encoding="utf-8")
        bad_profile.chmod(0o600)
        replaceable.chmod(0o770)
        must_fail(
            lambda: CHECK.check_profile(
                bad_profile,
                2,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            ),
            "replaceable profile ancestor",
        )

        legacy_profile = dict(profile_document)
        legacy_profile.pop("repositories")
        legacy_profile["clients"] = {"1000": {}}
        profile.write_text(json.dumps(legacy_profile), encoding="utf-8")
        must_fail(
            lambda: CHECK.check_profile(
                profile,
                2,
                trusted_owner_uid=os.geteuid(),
                trust_root=root,
            ),
            "obsolete client-scoped profile",
        )

    print("availability schema check self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
