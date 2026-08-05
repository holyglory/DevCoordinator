#!/usr/bin/env python3
"""Read-only startup compatibility checks for immutable availability units."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Any


class CheckError(RuntimeError):
    pass


def _private_regular(path: Path, *, maximum_bytes: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise CheckError(f"cannot inspect {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise CheckError(f"expected one regular file: {path}")
    if info.st_size < 1 or info.st_size > maximum_bytes:
        raise CheckError(f"file size is outside the supported boundary: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise CheckError(f"file must not be group/world writable: {path}")
    return info


def _trusted_profile_path(
    path: Path,
    *,
    trusted_owner_uid: int,
    trust_root: Path = Path("/"),
) -> os.stat_result:
    """Require an administrator-owned, non-replaceable profile publication."""

    if not path.is_absolute() or ".." in path.parts:
        raise CheckError("profile path must be absolute without traversal")
    trust_root = trust_root.resolve(strict=True)
    try:
        relative = path.relative_to(trust_root)
    except ValueError as error:
        raise CheckError("profile path is outside its trusted root") from error
    current = trust_root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise CheckError(f"cannot inspect profile path component {current}: {error}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CheckError("profile path contains a symlink or non-directory")
        if info.st_uid != trusted_owner_uid:
            raise CheckError("broker profile path has an untrusted owner")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise CheckError("broker profile path has a replaceable ancestor")
    result = _private_regular(path, maximum_bytes=4 * 1024 * 1024)
    if result.st_uid != trusted_owner_uid:
        raise CheckError("broker profile is not owned by the trusted administrator")
    return result


def check_schema(database: Path, expected_schema: int) -> dict[str, Any]:
    before = _private_regular(database, maximum_bytes=64 * 1024 * 1024 * 1024)
    uri = f"file:{database.as_posix()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25)
    except sqlite3.Error as error:
        raise CheckError(f"cannot open database read-only: {error}") from error
    try:
        connection.execute("PRAGMA query_only = ON")
        integrity = connection.execute("PRAGMA quick_check(1)").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise CheckError("database quick_check did not return ok")
        try:
            row = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as error:
            raise CheckError("database does not expose schema_metadata") from error
        if row is None or type(row[0]) is not int:
            raise CheckError("database schema discriminator is missing or invalid")
        actual_schema = int(row[0])
        if actual_schema != expected_schema:
            raise CheckError(
                f"unsupported database schema {actual_schema}; expected {expected_schema}"
            )
    finally:
        connection.close()
    after = database.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CheckError("database changed while the read-only check was running")
    return {
        "ok": True,
        "kind": "schema",
        "database": str(database),
        "schema_version": expected_schema,
        "read_only": True,
    }


def check_profile(
    profile: Path,
    expected_schema: int,
    *,
    trusted_owner_uid: int = 0,
    trust_root: Path = Path("/"),
) -> dict[str, Any]:
    before = _trusted_profile_path(
        profile,
        trusted_owner_uid=trusted_owner_uid,
        trust_root=trust_root,
    )
    descriptor = os.open(
        profile,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError(f"profile is not valid JSON: {error}") from error
    after = profile.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CheckError("profile changed while it was read")
    if not isinstance(value, dict) or set(value) != {"version", "service", "clients"}:
        raise CheckError("profile fields are invalid")
    if type(value.get("version")) is not int:
        raise CheckError("profile schema discriminator is missing or invalid")
    if int(value["version"]) != expected_schema:
        raise CheckError(
            f"unsupported profile schema {value['version']}; expected {expected_schema}"
        )
    if not isinstance(value.get("service"), dict) or not isinstance(value.get("clients"), dict):
        raise CheckError("profile service or client collection is invalid")
    return {
        "ok": True,
        "kind": "profile",
        "profile": str(profile),
        "schema_version": expected_schema,
        "read_only": True,
        "trusted_owner_uid": trusted_owner_uid,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="kind", required=True)
    schema = subcommands.add_parser("schema")
    schema.add_argument("--database", type=Path, required=True)
    schema.add_argument("--expected-schema", type=int, required=True)
    schema.add_argument("--read-only", action="store_true", required=True)
    profile = subcommands.add_parser("profile")
    profile.add_argument("--profile", type=Path, required=True)
    profile.add_argument("--expected-schema", type=int, required=True)
    profile.add_argument("--read-only", action="store_true", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.kind == "schema":
            result = check_schema(args.database.expanduser().absolute(), args.expected_schema)
        else:
            result = check_profile(args.profile.expanduser().absolute(), args.expected_schema)
    except (CheckError, OSError, sqlite3.Error) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
