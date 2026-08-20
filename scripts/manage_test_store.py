#!/usr/bin/env python3
"""Create, reset, and attest the disposable DevCoordinator Test Store.

This helper deliberately has no authority-history import surface. It runs as
the testd service identity, accepts only the isolated ``tests.sqlite3`` store,
and produces one operation-bound readiness attestation for deployment.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Mapping
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
if str(MODULES) not in sys.path:
    sys.path.insert(0, str(MODULES))

from devcoordinator.store import refuse_symlink_components  # noqa: E402
from devcoordinator.universal_test_store import (  # noqa: E402
    TEST_STORE_SCHEMA_VERSION,
    UniversalTestStore,
    prepare_test_store_schema,
)


class TestStoreCommandError(RuntimeError):
    pass


READINESS_KIND = "universal-test-store-schema-readiness-attestation"
READINESS_FIELDS = {
    "operation_id",
    "test_database",
    "action",
    "journal_kind",
    "journal",
    "store",
    "published_at",
}
DISCARD_CONFIRMATION = "discard-test-history"


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _seal(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {"schema_version": 1, "kind": kind, **dict(values)}
    if "document_sha256" in document:
        raise TestStoreCommandError("attestation payload contains a reserved field")
    document["document_sha256"] = _fingerprint(document)
    return document


def _verify_attestation(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TestStoreCommandError("schema readiness attestation is not an object")
    expected = {
        "schema_version",
        "kind",
        "document_sha256",
        *READINESS_FIELDS,
    }
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or value.get("kind") != READINESS_KIND
    ):
        raise TestStoreCommandError("schema readiness attestation fields are invalid")
    digest = value.get("document_sha256")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or _fingerprint(unsigned) != digest
    ):
        raise TestStoreCommandError("schema readiness attestation digest is invalid")
    return MappingProxyType(dict(value))


def _absolute(raw: str | Path, field: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise TestStoreCommandError(f"{field} must be an absolute path")
    return Path(os.path.abspath(path))


def _require_service_identity(expected_uid: int) -> None:
    if type(expected_uid) is not int or expected_uid <= 0 or os.geteuid() != expected_uid:
        raise TestStoreCommandError("Test Store command must run as the testd service UID")


def _require_private_directory(path: Path, *, expected_uid: int) -> None:
    refuse_symlink_components(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise TestStoreCommandError("Test Store parent must be testd-owned mode 0700")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_json(path: Path, *, expected_uid: int) -> Mapping[str, object]:
    refuse_symlink_components(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= metadata.st_size <= 1024 * 1024
    ):
        raise TestStoreCommandError("attestation is not a private testd-owned file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TestStoreCommandError("attestation is malformed") from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise TestStoreCommandError("attestation changed while it was read")
    if not isinstance(value, Mapping):
        raise TestStoreCommandError("attestation is not an object")
    return MappingProxyType(dict(value))


def _publish_private_json(
    path: Path, document: Mapping[str, object], *, expected_uid: int
) -> None:
    _require_private_directory(path.parent, expected_uid=expected_uid)
    if path.exists() or path.is_symlink():
        if dict(_read_private_json(path, expected_uid=expected_uid)) != dict(document):
            raise TestStoreCommandError("attestation path belongs to another operation")
        return
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        payload = (_canonical_json(document) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _operation_id(value: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise TestStoreCommandError("operation ID is invalid") from error
    if normalized != value:
        raise TestStoreCommandError("operation ID is not canonical")
    return normalized


def _store_path(value: str | Path) -> Path:
    path = _absolute(value, "test database")
    if path.name != "tests.sqlite3":
        raise TestStoreCommandError("only the tests.sqlite3 Test Store is supported")
    return path


def create_store(path: Path, *, expected_uid: int) -> dict[str, object]:
    _require_service_identity(expected_uid)
    path = _store_path(path)
    _require_private_directory(path.parent, expected_uid=expected_uid)
    store = UniversalTestStore.create(path, expected_uid=expected_uid)
    return {
        "ok": True,
        "action": "create",
        "test_database": str(path),
        **store.verify(),
    }


def prepare_store(
    *,
    test_database: Path,
    operation_id: str,
    attestation_output: Path,
    expected_test_uid: int,
) -> dict[str, object]:
    _require_service_identity(expected_test_uid)
    test_database = _store_path(test_database)
    operation_id = _operation_id(operation_id)
    attestation_output = _absolute(attestation_output, "schema readiness attestation")
    expected_output = test_database.parent / f"schema-readiness-{operation_id}.json"
    if attestation_output != expected_output:
        raise TestStoreCommandError("attestation path is not bound to the store operation")
    prepared = prepare_test_store_schema(
        test_database,
        operation_id=operation_id,
        expected_uid=expected_test_uid,
    )
    document = _seal(
        READINESS_KIND,
        {
            "operation_id": operation_id,
            "test_database": str(test_database),
            "action": prepared["action"],
            "journal_kind": prepared["journal_kind"],
            "journal": prepared["journal"],
            "store": prepared["store"],
            "published_at": _now(),
        },
    )
    replayed = False
    if attestation_output.exists() or attestation_output.is_symlink():
        recorded = _verify_attestation(
            _read_private_json(attestation_output, expected_uid=expected_test_uid)
        )
        for field in READINESS_FIELDS - {"published_at"}:
            if recorded[field] != document[field]:
                raise TestStoreCommandError("attestation belongs to another store operation")
        document = dict(recorded)
        replayed = True
    else:
        _publish_private_json(
            attestation_output, document, expected_uid=expected_test_uid
        )
    return {
        "ok": True,
        "action": "test-store-prepare",
        "branch": document["action"],
        "attestation": str(attestation_output),
        "attestation_fingerprint": document["document_sha256"],
        "store_generation": document["store"]["store_generation"],
        "schema_version": document["store"]["schema_version"],
        "replayed": replayed,
    }


def _discard_store_file(path: Path, *, expected_uid: int) -> bool:
    refuse_symlink_components(path, allow_missing_leaf=True)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise TestStoreCommandError("discard target is not a private Test Store file")
    path.unlink()
    return True


def initialize_fresh_store(
    *,
    test_database: Path,
    operation_id: str,
    attestation_output: Path,
    expected_test_uid: int,
    confirmation: str,
) -> dict[str, object]:
    _require_service_identity(expected_test_uid)
    if confirmation != DISCARD_CONFIRMATION:
        raise TestStoreCommandError("test-history discard confirmation is invalid")
    test_database = _store_path(test_database)
    operation_id = _operation_id(operation_id)
    attestation_output = _absolute(attestation_output, "schema readiness attestation")
    _require_private_directory(test_database.parent, expected_uid=expected_test_uid)
    if attestation_output.exists() or attestation_output.is_symlink():
        return {
            **prepare_store(
                test_database=test_database,
                operation_id=operation_id,
                attestation_output=attestation_output,
                expected_test_uid=expected_test_uid,
            ),
            "action": "test-store-initialize-fresh",
            "discarded_existing": True,
            "replayed": True,
        }

    lock_path = test_database.parent / f".{test_database.name}.initialize.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_test_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TestStoreCommandError("Test Store initialization lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        discarded = False
        for path in (
            Path(str(test_database) + "-shm"),
            Path(str(test_database) + "-wal"),
            test_database,
        ):
            discarded = (
                _discard_store_file(path, expected_uid=expected_test_uid)
                or discarded
            )
        _fsync_directory(test_database.parent)
        created = UniversalTestStore.create(
            test_database, expected_uid=expected_test_uid
        ).verify()
        prepared = prepare_store(
            test_database=test_database,
            operation_id=operation_id,
            attestation_output=attestation_output,
            expected_test_uid=expected_test_uid,
        )
        verified = UniversalTestStore.open(
            test_database, expected_uid=expected_test_uid
        ).verify()
        if (
            prepared["branch"] != "attested-fresh"
            or prepared["store_generation"] != created["store_generation"]
            or verified != created
        ):
            raise TestStoreCommandError("fresh Test Store verification changed")
        return {
            **prepared,
            "action": "test-store-initialize-fresh",
            "discarded_existing": discarded,
            "replayed": False,
        }
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create")
    create.add_argument("--test-database", required=True)
    create.add_argument("--expected-test-uid", type=int, required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument("--test-database", required=True)
    prepare.add_argument("--operation-id", required=True)
    prepare.add_argument("--attestation-output", required=True)
    prepare.add_argument("--expected-test-uid", type=int, required=True)
    fresh = actions.add_parser("initialize-fresh")
    fresh.add_argument("--test-database", required=True)
    fresh.add_argument("--operation-id", required=True)
    fresh.add_argument("--attestation-output", required=True)
    fresh.add_argument("--expected-test-uid", type=int, required=True)
    fresh.add_argument(
        "--confirm-discard-test-history",
        required=True,
        choices=(DISCARD_CONFIRMATION,),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.action == "create":
            result = create_store(
                _store_path(arguments.test_database),
                expected_uid=arguments.expected_test_uid,
            )
        elif arguments.action == "prepare":
            result = prepare_store(
                test_database=_store_path(arguments.test_database),
                operation_id=arguments.operation_id,
                attestation_output=_absolute(
                    arguments.attestation_output, "schema readiness attestation"
                ),
                expected_test_uid=arguments.expected_test_uid,
            )
        else:
            result = initialize_fresh_store(
                test_database=_store_path(arguments.test_database),
                operation_id=arguments.operation_id,
                attestation_output=_absolute(
                    arguments.attestation_output, "schema readiness attestation"
                ),
                expected_test_uid=arguments.expected_test_uid,
                confirmation=arguments.confirm_discard_test_history,
            )
    except Exception as error:
        if isinstance(error, TestStoreCommandError):
            raise SystemExit(str(error)) from error
        raise
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
