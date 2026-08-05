#!/usr/bin/env python3
"""Prepare and apply the explicit offline repository-owner schema-13 map."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.repository_owner_authority import (  # noqa: E402
    RepositoryOwnerAuthorityError,
    load_sealed_owner_map,
    prepare_owner_map,
    repository_census,
)


def _database_identity(path: Path, expected_uid: int) -> tuple[int, int]:
    candidate = path.expanduser().absolute()
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RepositoryOwnerAuthorityError(
            "authority database must be a private regular file owned by the expected service UID"
        )
    return int(info.st_dev), int(info.st_ino)


def _open_database(path: Path, *, expected_uid: int, read_only: bool) -> sqlite3.Connection:
    identity = _database_identity(path, expected_uid)
    mode = "ro" if read_only else "rw"
    connection = sqlite3.connect(
        f"{path.expanduser().absolute().as_uri()}?mode={mode}",
        uri=True,
        isolation_level=None,
        timeout=30.0,
    )
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    if _database_identity(path, expected_uid) != identity:
        connection.close()
        raise RepositoryOwnerAuthorityError(
            "authority database identity changed while opening"
        )
    return connection


def _owner_assignments(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        repository_id, separator, raw_uid = value.partition("=")
        if not separator or not repository_id or repository_id in result:
            raise RepositoryOwnerAuthorityError(
                "--owner must be a unique REPOSITORY_ID=UID assignment"
            )
        try:
            uid = int(raw_uid)
        except ValueError as error:
            raise RepositoryOwnerAuthorityError("owner UID must be an integer") from error
        if uid <= 0:
            raise RepositoryOwnerAuthorityError("owner UID must be positive")
        result[repository_id] = uid
    return result


def _write_private_new(path: Path, payload: bytes) -> None:
    candidate = path.expanduser().absolute()
    parent = candidate.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise RepositoryOwnerAuthorityError(
            "owner-map output parent must be a private directory owned by the caller"
        )
    descriptor = os.open(
        candidate,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RepositoryOwnerAuthorityError("owner-map write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    census = subparsers.add_parser(
        "census",
        help="list the exact schema-12 repositories requiring explicit owner decisions",
    )
    census.add_argument("--database", type=Path, required=True)
    census.add_argument("--expected-database-owner-uid", type=int, required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--database", type=Path, required=True)
    prepare.add_argument("--expected-database-owner-uid", type=int, required=True)
    prepare.add_argument("--owner", action="append", default=[])
    prepare.add_argument("--operation-id", default=None)
    prepare.add_argument("--actor")
    prepare.add_argument("--target-database-generation")
    prepare.add_argument("--refresh-from", type=Path)
    prepare.add_argument("--expected-refresh-map-owner-uid", type=int)
    prepare.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--database", type=Path, required=True)
    validate.add_argument("--expected-database-owner-uid", type=int, required=True)
    validate.add_argument("--map", type=Path, required=True)
    validate.add_argument("--expected-map-owner-uid", type=int, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "census":
            connection = _open_database(
                args.database,
                expected_uid=args.expected_database_owner_uid,
                read_only=True,
            )
            try:
                document = repository_census(connection)
            finally:
                connection.close()
            result = {
                "status": "census",
                **document,
                "owner_decisions_required": len(document["repositories"]),
            }
        elif args.command == "prepare":
            refresh_document = None
            if args.refresh_from is not None:
                if (
                    args.expected_refresh_map_owner_uid is None
                    or args.owner
                    or args.operation_id is not None
                    or args.actor is not None
                    or args.target_database_generation is not None
                    or args.output.expanduser().absolute()
                    == args.refresh_from.expanduser().absolute()
                ):
                    raise RepositoryOwnerAuthorityError(
                        "owner-map refresh requires a distinct output and only its "
                        "sealed source map"
                    )
                refresh_document = load_sealed_owner_map(
                    args.refresh_from,
                    expected_owner_uid=args.expected_refresh_map_owner_uid,
                )
                unsigned = dict(refresh_document)
                retained_digest = unsigned.pop("document_sha256", None)
                expected_digest = "sha256:" + hashlib.sha256(
                    json.dumps(
                        unsigned,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                repositories = refresh_document.get("repositories")
                if (
                    retained_digest != expected_digest
                    or not isinstance(repositories, list)
                    or any(
                        not isinstance(item, dict)
                        or set(item)
                        != {
                            "repository_id",
                            "canonical_root",
                            "repository_generation",
                            "owner_uid",
                        }
                        for item in repositories
                    )
                ):
                    raise RepositoryOwnerAuthorityError(
                        "owner-map refresh source is invalid"
                    )
                owner_uids = {
                    str(item["repository_id"]): item["owner_uid"]
                    for item in repositories
                }
                if len(owner_uids) != len(repositories):
                    raise RepositoryOwnerAuthorityError(
                        "owner-map refresh source repeats a repository"
                    )
                operation_id = refresh_document.get("operation_id")
                actor = refresh_document.get("actor")
                target_database_generation = refresh_document.get(
                    "target_database_generation"
                )
            else:
                if (
                    args.expected_refresh_map_owner_uid is not None
                    or not args.owner
                    or args.actor is None
                ):
                    raise RepositoryOwnerAuthorityError(
                        "owner-map preparation requires --owner and --actor"
                    )
                owner_uids = _owner_assignments(args.owner)
                operation_id = args.operation_id or str(uuid.uuid4())
                actor = args.actor
                target_database_generation = args.target_database_generation
            connection = _open_database(
                args.database,
                expected_uid=args.expected_database_owner_uid,
                read_only=True,
            )
            try:
                document = prepare_owner_map(
                    connection,
                    owner_uids=owner_uids,
                    operation_id=operation_id,
                    actor=actor,
                    target_database_generation=target_database_generation,
                )
                if refresh_document is not None and (
                    document.get("operation_id")
                    != refresh_document.get("operation_id")
                    or document.get("actor") != refresh_document.get("actor")
                    or document.get("target_database_generation")
                    != refresh_document.get("target_database_generation")
                    or document.get("repositories")
                    != refresh_document.get("repositories")
                    or document.get("source_database_generation")
                    != refresh_document.get("source_database_generation")
                    or int(document.get("source_state_revision", -1))
                    <= int(refresh_document.get("source_state_revision", -1))
                ):
                    raise RepositoryOwnerAuthorityError(
                        "owner-map refresh changed more than its source revision"
                    )
            finally:
                connection.close()
            payload = json.dumps(
                document,
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8") + b"\n"
            _write_private_new(args.output, payload)
            result = {
                "status": "prepared",
                "output": str(args.output.expanduser().absolute()),
                "owner_map_sha256": document["document_sha256"],
                "repository_count": len(document["repositories"]),
                "operation_id": document["operation_id"],
                "source_database_generation": document[
                    "source_database_generation"
                ],
                "target_database_generation": document[
                    "target_database_generation"
                ],
            }
        else:
            document = load_sealed_owner_map(
                args.map, expected_owner_uid=args.expected_map_owner_uid
            )
            connection = _open_database(
                args.database,
                expected_uid=args.expected_database_owner_uid,
                read_only=True,
            )
            try:
                from devcoordinator.repository_owner_authority import validate_owner_map

                validated = validate_owner_map(connection, document)
                result = {
                    "status": "valid",
                    "owner_map_sha256": validated["document_sha256"],
                    "repository_count": len(validated["repositories"]),
                    "operation_id": validated["operation_id"],
                    "source_database_generation": validated[
                        "source_database_generation"
                    ],
                    "target_database_generation": validated[
                        "target_database_generation"
                    ],
                    "apply": "first-adoption-cutover-only",
                }
            finally:
                connection.close()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, sqlite3.Error, RepositoryOwnerAuthorityError, ValueError) as error:
        print(
            json.dumps(
                {"status": "error", "error": str(error)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
