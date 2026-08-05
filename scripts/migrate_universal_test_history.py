#!/usr/bin/env python3
"""Offline, split-identity migration of legacy test history into testd.

Authority commands open only the root-owned authority database and publish
bounded, digest-chained exports into a testd-owned private package directory.
``testd-import`` opens only the test store and publishes its own exact import
attestation.  ``authority-seal`` consumes that attestation plus the live,
broker-issued admission-drain proof.  No command activates a pointer or
deletes legacy rows.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
from types import MappingProxyType
from typing import Any, Mapping
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
if str(MODULES) not in sys.path:
    sys.path.insert(0, str(MODULES))

from devcoordinator.universal_test_migration import (  # noqa: E402
    DEFAULT_MIGRATION_BATCH_SIZE,
    LEGACY_TEST_MIGRATION_SCHEMA_VERSION,
    MAX_MIGRATION_BATCH_BYTES,
    MAX_MIGRATION_BATCH_SIZE,
    DEFAULT_CAPACITY_RESERVE_BYTES,
    LegacyTestExportImporter,
    LegacyMigrationState,
    LegacyTestHistoryMigrator,
    LegacyTestWatermark,
    load_migration_state,
    save_migration_state,
)
from devcoordinator.store import StoreError, refuse_symlink_components  # noqa: E402
from devcoordinator.universal_test_store import (  # noqa: E402
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
    prepare_test_store_schema_v5,
)


class MigrationCommandError(RuntimeError):
    pass


SPLIT_MIGRATION_KIND = "universal-test-history-split-cutover"
EXPORT_MANIFEST_KIND = "legacy-test-history-export"
EXPORT_CHUNK_KIND = "legacy-test-history-export-chunk"
IMPORT_ATTESTATION_KIND = "legacy-test-history-import-attestation"
TEST_STORE_SCHEMA_READINESS_ATTESTATION_KIND = (
    "universal-test-store-schema-readiness-attestation"
)
TEST_STORE_SCHEMA_READINESS_FIELDS = {
    "operation_id",
    "test_database",
    "action",
    "journal_kind",
    "journal",
    "store",
    "published_at",
}
DISCARD_TEST_HISTORY_CONFIRMATION = "discard-test-history"
MAX_EXPORT_DOCUMENT_BYTES = MAX_MIGRATION_BATCH_BYTES * 2 + 1024 * 1024
PACKAGE_PREPARATION_KIND = "universal-test-history-package-directories"
PACKAGE_PREPARATION_FILE = "package-directories.json"


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def _canonical_json(value: object) -> str:
    def plain(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): plain(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [plain(child) for child in item]
        return item

    return json.dumps(
        plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _seal_document(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {"schema_version": 1, "kind": kind, **dict(values)}
    if "document_sha256" in document:
        raise MigrationCommandError("sealed document payload contains a reserved field")
    document["document_sha256"] = _fingerprint(document)
    return document


def _verify_sealed_document(
    value: object,
    *,
    kind: str,
    fields: set[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MigrationCommandError(f"{kind} must be an object")
    expected = {"schema_version", "kind", "document_sha256", *fields}
    if set(value) != expected or value.get("schema_version") != 1 or value.get("kind") != kind:
        raise MigrationCommandError(f"{kind} fields are invalid")
    fingerprint = value.get("document_sha256")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if (
        not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        or _fingerprint(unsigned) != fingerprint
    ):
        raise MigrationCommandError(f"{kind} fingerprint is invalid")
    return MappingProxyType(dict(value))


def _absolute(raw: str | Path, field: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise MigrationCommandError(f"{field} must be an absolute path")
    return Path(os.path.abspath(path))


def _read_private_json(
    path: Path,
    *,
    expected_uid: int,
    maximum_bytes: int = 1024 * 1024,
) -> Mapping[str, object]:
    refuse_symlink_components(path)
    parent = path.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise MigrationCommandError(
            "drain proof parent must be owned by the authority UID and mode 0700"
        )
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > maximum_bytes
    ):
        raise MigrationCommandError("drain proof must be a private regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MigrationCommandError("drain proof is malformed") from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise MigrationCommandError("drain proof changed while it was read")
    if not isinstance(value, Mapping):
        raise MigrationCommandError("drain proof must be an object")
    return MappingProxyType(dict(value))


def _publish_recipient_json(
    path: Path,
    document: Mapping[str, object],
    *,
    writer_uid: int,
    recipient_uid: int,
) -> None:
    """Publish one no-replace handoff owned by a separate service UID."""

    if os.geteuid() != writer_uid:
        raise MigrationCommandError("handoff publisher is not the authority UID")
    path = _absolute(path, "handoff path")
    refuse_symlink_components(path.parent)
    parent = path.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != recipient_uid
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise MigrationCommandError(
            "handoff parent must be owned by the recipient UID and mode 0700"
        )
    if path.exists() or path.is_symlink():
        existing = _read_private_json(path, expected_uid=recipient_uid)
        if dict(existing) != dict(document):
            raise MigrationCommandError("handoff output already exists with different evidence")
        return
    payload = (_canonical_json(document) + "\n").encode("utf-8")
    if len(payload) > MAX_EXPORT_DOCUMENT_BYTES:
        raise MigrationCommandError("handoff document exceeds its byte bound")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if recipient_uid != writer_uid:
            if writer_uid != 0:
                raise MigrationCommandError(
                    "only the root authority may hand evidence to another UID"
                )
            os.fchown(descriptor, recipient_uid, parent.st_gid)
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _replace_private_json(
    path: Path,
    document: Mapping[str, object],
    *,
    expected_uid: int,
    create: bool,
    expected_generation: int | None = None,
) -> None:
    """CAS-publish a private split-migration state document."""

    if os.geteuid() != expected_uid:
        raise MigrationCommandError("state publisher is not the authority UID")
    path = _absolute(path, "state")
    refuse_symlink_components(path.parent)
    parent = path.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise MigrationCommandError("state parent must be authority-owned mode 0700")
    lock_path = path.with_name(f".{path.name}.lock")
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise MigrationCommandError("state lock identity is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        exists = path.exists() or path.is_symlink()
        if create and exists:
            raise MigrationCommandError("split migration state already exists")
        if not create:
            if not exists:
                raise MigrationCommandError("split migration state does not exist")
            current = _read_private_json(path, expected_uid=expected_uid)
            if current.get("state_generation") != expected_generation:
                raise MigrationCommandError("split migration state generation changed")
            if document.get("state_generation") != int(expected_generation or 0) + 1:
                raise MigrationCommandError("split migration state generation did not advance")
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        payload = (_canonical_json(document) + "\n").encode("utf-8")
        temp_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(temp_descriptor, 0o600)
            written = 0
            while written < len(payload):
                written += os.write(temp_descriptor, payload[written:])
            os.fsync(temp_descriptor)
        finally:
            os.close(temp_descriptor)
        try:
            if create:
                os.link(temporary, path, follow_symlinks=False)
                temporary.unlink()
            else:
                os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_directory(path: Path, *, expected_uid: int, label: str) -> None:
    refuse_symlink_components(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise MigrationCommandError(f"{label} must be testd-owned mode 0700")


def testd_prepare_package_directories(
    *,
    package_root: Path,
    operation_id: str,
    expected_test_uid: int,
) -> dict[str, object]:
    """Create the split-migration handoff directories under the testd identity.

    The authority exporter is intentionally unable to create or chown these
    directories.  This resumable preparation command gives the immutable
    release a safe way to establish the two recipient-owned handoff lanes
    without ad-hoc privileged shell commands during cutover.
    """

    if os.geteuid() != expected_test_uid:
        raise MigrationCommandError(
            "package directory preparation must run as the testd UID"
        )
    try:
        canonical_operation_id = str(uuid.UUID(operation_id))
    except (ValueError, AttributeError) as error:
        raise MigrationCommandError("package preparation operation ID is invalid") from error
    if canonical_operation_id != operation_id:
        raise MigrationCommandError("package preparation operation ID is not canonical")

    root = _absolute(package_root, "package root")
    parent = root.parent
    _require_private_directory(
        parent,
        expected_uid=expected_test_uid,
        label="package root parent",
    )
    created_root = False
    if root.exists() or root.is_symlink():
        _require_private_directory(
            root,
            expected_uid=expected_test_uid,
            label="package root",
        )
    else:
        os.mkdir(root, 0o700)
        created_root = True
        _require_private_directory(
            root,
            expected_uid=expected_test_uid,
            label="package root",
        )
        _fsync_directory(parent)

    initial = root / "initial"
    final = root / "final"
    for path, label in ((initial, "initial package directory"), (final, "final package directory")):
        if path.exists() or path.is_symlink():
            _require_private_directory(path, expected_uid=expected_test_uid, label=label)
        else:
            os.mkdir(path, 0o700)
            _require_private_directory(path, expected_uid=expected_test_uid, label=label)
            _fsync_directory(root)

    preparation = _seal_document(
        PACKAGE_PREPARATION_KIND,
        {
            "operation_id": operation_id,
            "package_root": str(root),
            "initial_package_directory": str(initial),
            "final_package_directory": str(final),
            "expected_test_uid": expected_test_uid,
            "created_at": _now(),
        },
    )
    preparation_path = root / PACKAGE_PREPARATION_FILE
    if preparation_path.exists() or preparation_path.is_symlink():
        existing = _verify_sealed_document(
            _read_private_json(preparation_path, expected_uid=expected_test_uid),
            kind=PACKAGE_PREPARATION_KIND,
            fields={
                "operation_id",
                "package_root",
                "initial_package_directory",
                "final_package_directory",
                "expected_test_uid",
                "created_at",
            },
        )
        comparisons = {
            "operation_id": operation_id,
            "package_root": str(root),
            "initial_package_directory": str(initial),
            "final_package_directory": str(final),
            "expected_test_uid": expected_test_uid,
        }
        for field, expected in comparisons.items():
            if existing[field] != expected:
                raise MigrationCommandError(
                    "package preparation belongs to another migration"
                )
        preparation = dict(existing)
    else:
        _replace_private_json(
            preparation_path,
            preparation,
            expected_uid=expected_test_uid,
            create=True,
        )
        _fsync_directory(root)

    return {
        "ok": True,
        "action": "testd-prepare-package-directories",
        "operation_id": operation_id,
        "created_root": created_root,
        "package_root": str(root),
        "initial_package_directory": str(initial),
        "final_package_directory": str(final),
        "attestation": str(preparation_path),
        "attestation_sha256": preparation["document_sha256"],
    }


def _verify_drain_proof(
    authority_database: Path,
    proof_path: Path,
    *,
    expected_uid: int,
) -> tuple[Mapping[str, object], str]:
    proof = _read_private_json(proof_path, expected_uid=expected_uid)
    try:
        from devcoordinator.universal_test_admission import (
            verify_legacy_test_admission_drain_proof,
        )
    except ImportError as error:
        raise MigrationCommandError(
            "broker admission-drain verifier is not installed; finalization is denied"
        ) from error
    normalized = verify_legacy_test_admission_drain_proof(
        authority_database, proof, expected_uid=expected_uid
    )
    if not isinstance(normalized, Mapping):
        raise MigrationCommandError("broker drain verifier returned malformed evidence")
    document = dict(normalized)
    return MappingProxyType(document), _fingerprint(document)


def _require_bound_drain_proof(
    authority_database: Path,
    proof_path: Path,
    *,
    expected_uid: int,
    expected_fingerprint: str,
) -> Mapping[str, object]:
    normalized, fingerprint = _verify_drain_proof(
        authority_database,
        proof_path,
        expected_uid=expected_uid,
    )
    if fingerprint != expected_fingerprint:
        raise MigrationCommandError("drain proof differs from the proof bound to this migration")
    return normalized


def _open_from_state(
    state: LegacyMigrationState,
    *,
    expected_authority_uid: int,
    expected_test_uid: int,
) -> tuple[UniversalTestStore, LegacyTestHistoryMigrator]:
    if expected_authority_uid != os.geteuid() or expected_test_uid != os.geteuid():
        raise MigrationCommandError("migration must run as both database service owners")
    store = UniversalTestStore.open(
        Path(state.test_database), expected_uid=expected_test_uid
    )
    metadata = store.verify()
    if metadata["store_generation"] != state.test_store_generation:
        raise MigrationCommandError("test store generation differs from migration state")
    return store, LegacyTestHistoryMigrator(
        Path(state.authority_database),
        store,
        expected_authority_uid=expected_authority_uid,
    )


_SPLIT_STATE_FIELDS = {
    "schema_version",
    "kind",
    "migration_id",
    "authority_database",
    "test_database",
    "test_store_generation",
    "batch_size",
    "phase",
    "initial_export",
    "final_export",
    "drain_proof_fingerprint",
    "destination_attestation_fingerprint",
    "created_at",
    "updated_at",
    "state_generation",
}
_SPLIT_PHASES = {
    "captured",
    "initial_exporting",
    "initial_exported",
    "final_exporting",
    "final_exported",
    "destination_verified",
    "sealed",
}
_EXPORT_STATE_FIELDS = {
    "package_directory",
    "watermark",
    "finalize_running",
    "cursor",
    "chunk_count",
    "chain_sha256",
    "projection_chain_sha256",
    "run_count",
    "case_count",
    "deferred_running_count",
    "abandoned_running_count",
    "manifest_path",
    "manifest_fingerprint",
}


def _validate_export_state(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != _EXPORT_STATE_FIELDS:
        raise MigrationCommandError("split export state fields are invalid")
    watermark = LegacyTestWatermark.from_document(value["watermark"])
    package = _absolute(str(value["package_directory"]), "package directory")
    cursor = value["cursor"]
    chunk_count = value["chunk_count"]
    if type(cursor) is not int or not 0 <= cursor <= watermark.maximum_rowid:
        raise MigrationCommandError("split export cursor is invalid")
    if type(chunk_count) is not int or chunk_count < 0:
        raise MigrationCommandError("split export chunk count is invalid")
    for field in (
        "run_count",
        "case_count",
        "deferred_running_count",
        "abandoned_running_count",
    ):
        if type(value[field]) is not int or int(value[field]) < 0:
            raise MigrationCommandError(f"split export {field} is invalid")
    chain = value["chain_sha256"]
    if not isinstance(chain, str) or re.fullmatch(r"[0-9a-f]{64}", chain) is None:
        raise MigrationCommandError("split export chain digest is invalid")
    projection_chain = value["projection_chain_sha256"]
    if (
        not isinstance(projection_chain, str)
        or re.fullmatch(r"[0-9a-f]{64}", projection_chain) is None
    ):
        raise MigrationCommandError("split export projection chain digest is invalid")
    manifest_path = value["manifest_path"]
    manifest_fingerprint = value["manifest_fingerprint"]
    if (manifest_path is None) != (manifest_fingerprint is None):
        raise MigrationCommandError("split export manifest identity is contradictory")
    if manifest_path is not None:
        _absolute(str(manifest_path), "manifest path")
        if re.fullmatch(r"[0-9a-f]{64}", str(manifest_fingerprint)) is None:
            raise MigrationCommandError("split export manifest fingerprint is invalid")
    if type(value["finalize_running"]) is not bool:
        raise MigrationCommandError("split export finalize flag is invalid")
    return MappingProxyType(
        {
            **dict(value),
            "package_directory": str(package),
            "watermark": watermark.to_document(),
        }
    )


def _validate_split_state(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != _SPLIT_STATE_FIELDS:
        raise MigrationCommandError("split migration state fields are invalid")
    if value.get("schema_version") != 1 or value.get("kind") != SPLIT_MIGRATION_KIND:
        raise MigrationCommandError("split migration state contract is unsupported")
    try:
        migration_id = str(uuid.UUID(str(value["migration_id"])))
    except (TypeError, ValueError, AttributeError) as error:
        raise MigrationCommandError("split migration ID is invalid") from error
    phase = str(value["phase"])
    if phase not in _SPLIT_PHASES:
        raise MigrationCommandError("split migration phase is invalid")
    authority = _absolute(str(value["authority_database"]), "authority database")
    destination = _absolute(str(value["test_database"]), "test database")
    generation = value["test_store_generation"]
    if (
        not isinstance(generation, str)
        or not generation
        or len(generation) > 256
        or any(character in generation for character in "\x00\r\n")
    ):
        raise MigrationCommandError("split migration test-store generation is invalid")
    batch_size = value["batch_size"]
    if type(batch_size) is not int or not 1 <= batch_size <= MAX_MIGRATION_BATCH_SIZE:
        raise MigrationCommandError("split migration batch size is invalid")
    initial = _validate_export_state(value["initial_export"])
    final_raw = value["final_export"]
    final = None if final_raw is None else _validate_export_state(final_raw)
    if phase in {"final_exporting", "final_exported", "destination_verified", "sealed"} and final is None:
        raise MigrationCommandError("split migration final phase lacks final export state")
    initial_watermark = LegacyTestWatermark.from_document(initial["watermark"])
    if phase in {
        "initial_exported",
        "final_exporting",
        "final_exported",
        "destination_verified",
        "sealed",
    } and (
        initial["cursor"] != initial_watermark.maximum_rowid
        or initial["manifest_path"] is None
    ):
        raise MigrationCommandError("split migration initial export is incomplete")
    if phase in {"final_exported", "destination_verified", "sealed"}:
        assert final is not None
        final_watermark = LegacyTestWatermark.from_document(final["watermark"])
        if (
            final["cursor"] != final_watermark.maximum_rowid
            or final["manifest_path"] is None
        ):
            raise MigrationCommandError("split migration final export is incomplete")
    proof = value["drain_proof_fingerprint"]
    if proof is not None and re.fullmatch(r"[0-9a-f]{64}", str(proof)) is None:
        raise MigrationCommandError("split migration drain fingerprint is invalid")
    if final is not None and proof is None:
        raise MigrationCommandError("split migration final export lacks drain evidence")
    attestation = value["destination_attestation_fingerprint"]
    if attestation is not None and re.fullmatch(r"[0-9a-f]{64}", str(attestation)) is None:
        raise MigrationCommandError("split migration attestation fingerprint is invalid")
    if phase in {"destination_verified", "sealed"} and attestation is None:
        raise MigrationCommandError("split migration phase lacks destination attestation")
    state_generation = value["state_generation"]
    if type(state_generation) is not int or state_generation < 0:
        raise MigrationCommandError("split migration state generation is invalid")
    return MappingProxyType(
        {
            **dict(value),
            "migration_id": migration_id,
            "authority_database": str(authority),
            "test_database": str(destination),
            "initial_export": dict(initial),
            "final_export": None if final is None else dict(final),
        }
    )


def _load_split_state(path: Path, *, expected_uid: int) -> Mapping[str, object]:
    return _validate_split_state(_read_private_json(path, expected_uid=expected_uid))


def create_store(path: Path, *, expected_uid: int) -> dict[str, object]:
    store = UniversalTestStore.create(path, expected_uid=expected_uid)
    return {"ok": True, "action": "create", "test_database": str(path), **store.verify()}


def _discard_private_test_store_file(path: Path, *, expected_uid: int) -> bool:
    """Remove one explicitly named test-store file after exact identity checks.

    This helper deliberately knows nothing about authority, profile, Console,
    or inventory stores.  It accepts only a private regular file owned by the
    calling testd UID.  Missing files make the reset replayable; symlinks,
    foreign ownership, and relaxed permissions fail closed.
    """

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
        raise MigrationCommandError(
            "discarded test-store files must be private regular files owned by testd"
        )
    path.unlink()
    return True


def testd_initialize_fresh_store(
    *,
    test_database: Path,
    operation_id: str,
    attestation_output: Path,
    expected_test_uid: int,
    confirmation: str,
) -> dict[str, object]:
    """Discard the isolated test plane and initialize the current empty schema.

    The administrator must stop testd before invoking this command.  Historical
    capture, admission drain, export/import, and schema compatibility are
    intentionally bypassed.  The authority and protected-profile stores are
    neither accepted as inputs nor opened.
    """

    if os.geteuid() != expected_test_uid:
        raise MigrationCommandError(
            "fresh test-store initialization must run as the testd UID"
        )
    if confirmation != DISCARD_TEST_HISTORY_CONFIRMATION:
        raise MigrationCommandError("test-history discard confirmation is invalid")
    try:
        canonical_operation_id = str(uuid.UUID(operation_id))
    except (ValueError, AttributeError) as error:
        raise MigrationCommandError(
            "fresh test-store operation ID is invalid"
        ) from error
    if canonical_operation_id != operation_id:
        raise MigrationCommandError(
            "fresh test-store operation ID is not canonical"
        )

    test_database = _absolute(test_database, "test database")
    attestation_output = _absolute(
        attestation_output, "schema readiness attestation"
    )
    if test_database.name != "tests.sqlite3":
        raise MigrationCommandError(
            "fresh initialization accepts only the tests.sqlite3 store"
        )
    parent = test_database.parent
    _require_private_directory(
        parent,
        expected_uid=expected_test_uid,
        label="test-store parent",
    )
    expected_attestation = parent / f"schema-readiness-{operation_id}.json"
    if attestation_output != expected_attestation:
        raise MigrationCommandError(
            "schema readiness attestation must be the operation-bound file "
            "beside tests.sqlite3"
        )

    # A completed operation is replayed without erasing data recorded after
    # testd was started.  Use a unique attestation path for every new reset.
    if attestation_output.exists() or attestation_output.is_symlink():
        prepared = testd_prepare_store_schema(
            test_database=test_database,
            operation_id=operation_id,
            attestation_output=attestation_output,
            expected_test_uid=expected_test_uid,
        )
        return {
            **prepared,
            "action": "testd-initialize-fresh",
            "discarded_existing": True,
            "replayed": True,
        }

    lock_path = parent / f".{test_database.name}.fresh-initialize.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_metadata = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != expected_test_uid
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        ):
            raise MigrationCommandError("fresh test-store lock identity is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)

        discarded = False
        # testd must be offline: its WAL/SHM files and the main database form
        # one disposable unit.  Removing only these three exact private paths
        # cannot reach the authority, profile, inventory, or Console stores.
        for candidate in (
            Path(str(test_database) + "-shm"),
            Path(str(test_database) + "-wal"),
            test_database,
        ):
            discarded = (
                _discard_private_test_store_file(
                    candidate, expected_uid=expected_test_uid
                )
                or discarded
            )
        _fsync_directory(parent)

        created = UniversalTestStore.create(
            test_database, expected_uid=expected_test_uid
        ).verify()
        prepared = testd_prepare_store_schema(
            test_database=test_database,
            operation_id=operation_id,
            attestation_output=attestation_output,
            expected_test_uid=expected_test_uid,
        )
        verified = UniversalTestStore.open(
            test_database, expected_uid=expected_test_uid
        ).verify()
        if (
            prepared.get("branch") != "attested-fresh-v5"
            or prepared.get("store_generation") != created.get("store_generation")
            or verified != created
        ):
            raise MigrationCommandError(
                "fresh test store did not retain its initialized generation"
            )
        return {
            **prepared,
            "action": "testd-initialize-fresh",
            "discarded_existing": discarded,
            "replayed": False,
        }
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def testd_prepare_store_schema(
    *,
    test_database: Path,
    operation_id: str,
    attestation_output: Path,
    expected_test_uid: int,
    checkpoint=None,
) -> dict[str, object]:
    """Journal and attest one freshly initialized schema-5 Test Store."""

    if os.geteuid() != expected_test_uid:
        raise MigrationCommandError(
            "test-store schema preparation must run as the testd UID"
        )
    test_database = _absolute(test_database, "test database")
    attestation_output = _absolute(
        attestation_output, "schema readiness attestation"
    )
    prepared = prepare_test_store_schema_v5(
        test_database,
        operation_id=operation_id,
        expected_uid=expected_test_uid,
        checkpoint=checkpoint,
    )
    if (
        prepared.get("action") != "attested-fresh-v5"
        or prepared.get("journal_kind") != "schema_readiness_v5"
    ):
        raise MigrationCommandError("test-store schema preparation is invalid")
    document = _seal_document(
        TEST_STORE_SCHEMA_READINESS_ATTESTATION_KIND,
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
        recorded = _verify_sealed_document(
            _read_private_json(
                attestation_output,
                expected_uid=expected_test_uid,
            ),
            kind=TEST_STORE_SCHEMA_READINESS_ATTESTATION_KIND,
            fields=TEST_STORE_SCHEMA_READINESS_FIELDS,
        )
        for field in TEST_STORE_SCHEMA_READINESS_FIELDS - {"published_at"}:
            if recorded[field] != document[field]:
                raise MigrationCommandError(
                    "schema readiness attestation belongs to another store operation"
                )
        document = dict(recorded)
        replayed = True
    else:
        _publish_private_json(
            attestation_output,
            document,
            expected_uid=expected_test_uid,
        )
    return {
        "ok": True,
        "action": "testd-prepare-schema",
        "branch": document["action"],
        "attestation": str(attestation_output),
        "attestation_fingerprint": document["document_sha256"],
        "store_generation": document["store"]["store_generation"],
        "replayed": replayed,
    }


def capture(
    *,
    authority_database: Path,
    test_database: Path,
    state_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    batch_size: int,
) -> dict[str, object]:
    if type(batch_size) is not int or not 1 <= batch_size <= MAX_MIGRATION_BATCH_SIZE:
        raise MigrationCommandError(
            f"batch size must be between 1 and {MAX_MIGRATION_BATCH_SIZE}"
        )
    store = UniversalTestStore.open(test_database, expected_uid=expected_test_uid)
    migrator = LegacyTestHistoryMigrator(
        authority_database, store, expected_authority_uid=expected_authority_uid
    )
    watermark = migrator.capture_watermark()
    capacity = migrator.preflight_capacity(watermark)
    timestamp = _now()
    state = LegacyMigrationState(
        migration_id="migration-" + uuid.uuid4().hex,
        authority_database=str(authority_database),
        test_database=str(test_database),
        test_store_generation=str(store.verify()["store_generation"]),
        batch_size=batch_size,
        phase="captured",
        initial_watermark=watermark,
        initial_cursor=0,
        final_watermark=None,
        final_cursor=0,
        drain_proof_fingerprint=None,
        verification=None,
        seal=None,
        created_at=timestamp,
        updated_at=timestamp,
        state_generation=0,
    )
    save_migration_state(
        state_path, state, expected_uid=expected_test_uid, create=True
    )
    return {
        "ok": True,
        "action": "capture",
        "state": str(state_path),
        "phase": state.phase,
        "watermark": watermark.to_document(),
        "capacity": capacity,
    }


def copy_batches(
    *,
    state_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    max_batches: int | None,
) -> dict[str, object]:
    if max_batches is not None and max_batches < 0:
        raise MigrationCommandError("max batches must be non-negative")
    state = load_migration_state(state_path, expected_uid=expected_test_uid)
    if state.phase not in {"captured", "copying", "copied"}:
        raise MigrationCommandError(f"copy is not allowed in phase {state.phase}")
    store, migrator = _open_from_state(
        state,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
    )
    migrator.preflight_capacity(state.initial_watermark)
    migrator.validate_watermark(state.initial_watermark)
    completed_batches = 0
    while state.initial_cursor < state.initial_watermark.maximum_rowid:
        if max_batches is not None and completed_batches >= max_batches:
            break
        batch = migrator.import_next_batch(
            state.initial_watermark,
            finalize_running=False,
            after_rowid=state.initial_cursor,
            batch_size=state.batch_size,
        )
        old_generation = state.state_generation
        phase = "copied" if batch.complete else "copying"
        state = replace(
            state,
            phase=phase,
            initial_cursor=batch.next_rowid,
            updated_at=_now(),
            state_generation=old_generation + 1,
        )
        save_migration_state(
            state_path,
            state,
            expected_uid=expected_test_uid,
            create=False,
            expected_generation=old_generation,
        )
        completed_batches += 1
    if state.initial_cursor >= state.initial_watermark.maximum_rowid and state.phase != "copied":
        old_generation = state.state_generation
        state = replace(
            state, phase="copied", updated_at=_now(), state_generation=old_generation + 1
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
    if state.phase == "copied":
        migrator.verify_import(state.initial_watermark, finalize_running=False)
    return {
        "ok": True,
        "action": "copy",
        "phase": state.phase,
        "cursor": state.initial_cursor,
        "maximum_rowid": state.initial_watermark.maximum_rowid,
        "batches": completed_batches,
        "source_retained": True,
        "test_store_generation": store.verify()["store_generation"],
    }


def finalize(
    *,
    state_path: Path,
    proof_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    max_batches: int | None,
) -> dict[str, object]:
    if max_batches is not None and max_batches < 0:
        raise MigrationCommandError("max batches must be non-negative")
    state = load_migration_state(state_path, expected_uid=expected_test_uid)
    if state.phase not in {"copied", "finalizing", "finalized"}:
        raise MigrationCommandError(f"finalize is not allowed in phase {state.phase}")
    store, migrator = _open_from_state(
        state,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
    )
    _proof, proof_fingerprint = _verify_drain_proof(
        Path(state.authority_database), proof_path, expected_uid=expected_authority_uid
    )
    if state.drain_proof_fingerprint not in {None, proof_fingerprint}:
        raise MigrationCommandError("drain proof differs from the proof bound to this migration")
    if state.final_watermark is None:
        watermark = migrator.capture_watermark()
        # Close the check/capture race by requiring the same durable fence after
        # the read transaction.  Admission remains denied while the row is active.
        _require_bound_drain_proof(
            Path(state.authority_database),
            proof_path,
            expected_uid=expected_authority_uid,
            expected_fingerprint=proof_fingerprint,
        )
        migrator.preflight_capacity(watermark)
        old_generation = state.state_generation
        state = replace(
            state,
            phase="finalizing",
            final_watermark=watermark,
            final_cursor=0,
            drain_proof_fingerprint=proof_fingerprint,
            updated_at=_now(),
            state_generation=old_generation + 1,
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
    assert state.final_watermark is not None
    migrator.validate_watermark(state.final_watermark)
    completed_batches = 0
    while state.final_cursor < state.final_watermark.maximum_rowid:
        if max_batches is not None and completed_batches >= max_batches:
            break
        _require_bound_drain_proof(
            Path(state.authority_database),
            proof_path,
            expected_uid=expected_authority_uid,
            expected_fingerprint=str(state.drain_proof_fingerprint),
        )
        batch = migrator.import_next_batch(
            state.final_watermark,
            finalize_running=True,
            after_rowid=state.final_cursor,
            batch_size=state.batch_size,
        )
        old_generation = state.state_generation
        state = replace(
            state,
            phase="finalized" if batch.complete else "finalizing",
            final_cursor=batch.next_rowid,
            updated_at=_now(),
            state_generation=old_generation + 1,
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
        completed_batches += 1
    if state.final_cursor >= state.final_watermark.maximum_rowid and state.phase != "finalized":
        old_generation = state.state_generation
        state = replace(
            state, phase="finalized", updated_at=_now(), state_generation=old_generation + 1
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
    if state.phase == "finalized":
        _require_bound_drain_proof(
            Path(state.authority_database),
            proof_path,
            expected_uid=expected_authority_uid,
            expected_fingerprint=str(state.drain_proof_fingerprint),
        )
        migrator.validate_final_watermark(state.final_watermark)
        migrator.verify_import(state.final_watermark, finalize_running=True)
        migrator.validate_final_watermark(state.final_watermark)
        _require_bound_drain_proof(
            Path(state.authority_database),
            proof_path,
            expected_uid=expected_authority_uid,
            expected_fingerprint=str(state.drain_proof_fingerprint),
        )
    return {
        "ok": True,
        "action": "finalize",
        "phase": state.phase,
        "cursor": state.final_cursor,
        "maximum_rowid": state.final_watermark.maximum_rowid,
        "batches": completed_batches,
        "drain_proof_fingerprint": proof_fingerprint,
        "test_store_generation": store.verify()["store_generation"],
    }


def verify(
    *,
    state_path: Path,
    proof_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
) -> dict[str, object]:
    state = load_migration_state(state_path, expected_uid=expected_test_uid)
    if state.phase not in {"finalized", "verified"} or state.final_watermark is None:
        raise MigrationCommandError("verification requires a completed final rescan")
    store, migrator = _open_from_state(
        state,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
    )
    proof_fingerprint = str(state.drain_proof_fingerprint)
    _require_bound_drain_proof(
        Path(state.authority_database),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    migrator.validate_final_watermark(state.final_watermark)
    result = migrator.verify_import(state.final_watermark, finalize_running=True)
    rollups = store.rebuild_rollups()
    store_metadata = store.verify()
    migrator.validate_final_watermark(state.final_watermark)
    _require_bound_drain_proof(
        Path(state.authority_database),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    verification = {
        **result.to_document(),
        "rollups": rollups,
        "test_store_generation": store_metadata["store_generation"],
        "authority_generation": state.final_watermark.authority_generation,
        "final_watermark_fingerprint": _fingerprint(
            state.final_watermark.to_document()
        ),
        "drain_proof_fingerprint": proof_fingerprint,
        "legacy_source_retained": True,
    }
    if state.phase != "verified" or dict(state.verification or {}) != verification:
        old_generation = state.state_generation
        state = replace(
            state,
            phase="verified",
            verification=MappingProxyType(verification),
            updated_at=_now(),
            state_generation=old_generation + 1,
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
    return {"ok": True, "action": "verify", "phase": state.phase, **verification}


def _publish_private_json(path: Path, document: Mapping[str, object], *, expected_uid: int) -> None:
    refuse_symlink_components(path.parent)
    if path.exists() or path.is_symlink():
        existing = _read_private_json(path, expected_uid=expected_uid)
        if dict(existing) != dict(document):
            raise MigrationCommandError("seal output already exists with different evidence")
        return
    metadata = path.parent.lstat()
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise MigrationCommandError("seal parent must be owned by the service UID and mode 0700")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        payload = (_canonical_json(document) + "\n").encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def seal(
    *,
    state_path: Path,
    output: Path,
    proof_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
) -> dict[str, object]:
    state = load_migration_state(state_path, expected_uid=expected_test_uid)
    if state.phase not in {"verified", "sealed"} or state.verification is None:
        raise MigrationCommandError("seal requires exact verified migration evidence")
    if state.final_watermark is None or state.drain_proof_fingerprint is None:
        raise MigrationCommandError("seal requires a bound final watermark and drain proof")
    store, migrator = _open_from_state(
        state,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
    )
    proof_fingerprint = str(state.drain_proof_fingerprint)
    _require_bound_drain_proof(
        Path(state.authority_database),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    migrator.validate_final_watermark(state.final_watermark)
    result = migrator.verify_import(state.final_watermark, finalize_running=True)
    expected_verification = dict(state.verification)
    current_verification = result.to_document()
    for field in (
        "maximum_rowid",
        "imported_run_count",
        "imported_case_count",
        "deferred_running_count",
        "abandoned_running_count",
        "source_digest",
        "destination_digest",
    ):
        if expected_verification.get(field) != current_verification.get(field):
            raise MigrationCommandError("verified migration evidence changed before sealing")
    if expected_verification.get("test_store_generation") != store.verify().get(
        "store_generation"
    ):
        raise MigrationCommandError("test store generation changed before sealing")
    watermark_fingerprint = _fingerprint(state.final_watermark.to_document())
    if expected_verification.get("final_watermark_fingerprint") != watermark_fingerprint:
        raise MigrationCommandError("final watermark differs from verified migration evidence")
    migrator.validate_final_watermark(state.final_watermark)
    _require_bound_drain_proof(
        Path(state.authority_database),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    seal_document = {
        "schema_version": LEGACY_TEST_MIGRATION_SCHEMA_VERSION,
        "kind": "universal-test-history-cutover-seal",
        "migration_id": state.migration_id,
        "authority_database": state.authority_database,
        "authority_generation": state.final_watermark.authority_generation if state.final_watermark else None,
        "test_database": state.test_database,
        "test_store_generation": state.test_store_generation,
        "drain_proof_fingerprint": proof_fingerprint,
        "final_watermark_fingerprint": watermark_fingerprint,
        "final_watermark_maximum_rowid": state.final_watermark.maximum_rowid,
        "source_digest": result.source_digest,
        "destination_digest": result.destination_digest,
        "verification_fingerprint": _fingerprint(dict(state.verification)),
        "legacy_source_retained": True,
        "activation_ready": True,
        "rollback": {
            "safe": True,
            "instruction": (
                "restore the retained legacy read pointer, verify its authority generation, "
                "then clear the broker admission fence only after the legacy writer is ready"
            ),
        },
    }
    _publish_private_json(output, seal_document, expected_uid=expected_test_uid)
    seal_evidence = {
        "path": str(output),
        "sha256": _fingerprint(seal_document),
    }
    if state.phase != "sealed" or dict(state.seal or {}) != seal_evidence:
        old_generation = state.state_generation
        state = replace(
            state,
            phase="sealed",
            seal=MappingProxyType(seal_evidence),
            updated_at=_now(),
            state_generation=old_generation + 1,
        )
        save_migration_state(
            state_path, state, expected_uid=expected_test_uid, create=False,
            expected_generation=old_generation,
        )
    return {"ok": True, "action": "seal", "phase": state.phase, **seal_evidence}


_EXPORT_MANIFEST_FIELDS = {
    "migration_id",
    "pass_kind",
    "authority_generation",
    "test_store_generation",
    "watermark",
    "watermark_fingerprint",
    "finalize_running",
    "chunk_count",
    "final_chunk_sha256",
    "projection_chain_sha256",
    "run_count",
    "case_count",
    "deferred_running_count",
    "abandoned_running_count",
}
_EXPORT_CHUNK_FIELDS = {
    "migration_id",
    "pass_kind",
    "authority_generation",
    "watermark_fingerprint",
    "chunk_index",
    "after_rowid",
    "next_rowid",
    "complete",
    "finalize_running",
    "previous_chunk_sha256",
    "projection_digest",
    "run_count",
    "case_count",
    "deferred_running_count",
    "abandoned_running_count",
    "records",
}
_IMPORT_ATTESTATION_FIELDS = {
    "migration_id",
    "pass_kind",
    "authority_generation",
    "watermark_fingerprint",
    "export_fingerprint",
    "test_store_generation",
    "chunk_count",
    "final_chunk_sha256",
    "run_count",
    "case_count",
    "destination_projection_chain_sha256",
    "source_retained",
}
_EMPTY_CHAIN = hashlib.sha256(b"").hexdigest()


def _new_export_state(
    *,
    package_directory: Path,
    watermark: LegacyTestWatermark,
    finalize_running: bool,
) -> dict[str, object]:
    return {
        "package_directory": str(_absolute(package_directory, "package directory")),
        "watermark": watermark.to_document(),
        "finalize_running": finalize_running,
        "cursor": 0,
        "chunk_count": 0,
        "chain_sha256": _EMPTY_CHAIN,
        "projection_chain_sha256": _EMPTY_CHAIN,
        "run_count": 0,
        "case_count": 0,
        "deferred_running_count": 0,
        "abandoned_running_count": 0,
        "manifest_path": None,
        "manifest_fingerprint": None,
    }


def authority_capture_split(
    *,
    authority_database: Path,
    test_database: Path,
    test_store_generation: str,
    state_path: Path,
    initial_package_directory: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    batch_size: int,
) -> dict[str, object]:
    """Capture authority history without opening the testd-owned database."""

    if os.geteuid() != expected_authority_uid:
        raise MigrationCommandError("authority capture must run as the authority UID")
    if type(batch_size) is not int or not 1 <= batch_size <= MAX_MIGRATION_BATCH_SIZE:
        raise MigrationCommandError("split migration batch size is invalid")
    package = _absolute(initial_package_directory, "initial package directory")
    refuse_symlink_components(package)
    package_metadata = package.lstat()
    if (
        not stat.S_ISDIR(package_metadata.st_mode)
        or package_metadata.st_uid != expected_test_uid
        or stat.S_IMODE(package_metadata.st_mode) != 0o700
    ):
        raise MigrationCommandError(
            "initial package directory must be testd-owned mode 0700"
        )
    source = LegacyTestHistoryMigrator(
        authority_database,
        None,
        expected_authority_uid=expected_authority_uid,
    )
    watermark = source.capture_watermark()
    timestamp = _now()
    state = {
        "schema_version": 1,
        "kind": SPLIT_MIGRATION_KIND,
        "migration_id": str(uuid.uuid4()),
        "authority_database": str(_absolute(authority_database, "authority database")),
        "test_database": str(_absolute(test_database, "test database")),
        "test_store_generation": str(test_store_generation),
        "batch_size": batch_size,
        "phase": "captured",
        "initial_export": _new_export_state(
            package_directory=package,
            watermark=watermark,
            finalize_running=False,
        ),
        "final_export": None,
        "drain_proof_fingerprint": None,
        "destination_attestation_fingerprint": None,
        "created_at": timestamp,
        "updated_at": timestamp,
        "state_generation": 0,
    }
    normalized = _validate_split_state(state)
    _replace_private_json(
        state_path,
        normalized,
        expected_uid=expected_authority_uid,
        create=True,
    )
    return {
        "ok": True,
        "action": "authority-capture",
        "migration_id": normalized["migration_id"],
        "phase": normalized["phase"],
        "watermark": watermark.to_document(),
    }


def _save_split_progress(
    state_path: Path,
    state: Mapping[str, object],
    *,
    expected_authority_uid: int,
    export_key: str,
    export_state: Mapping[str, object],
    phase: str,
) -> Mapping[str, object]:
    old_generation = int(state["state_generation"])
    updated = {
        **dict(state),
        export_key: dict(export_state),
        "phase": phase,
        "updated_at": _now(),
        "state_generation": old_generation + 1,
    }
    normalized = _validate_split_state(updated)
    _replace_private_json(
        state_path,
        normalized,
        expected_uid=expected_authority_uid,
        create=False,
        expected_generation=old_generation,
    )
    return normalized


def _export_batches_split(
    *,
    state_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    export_key: str,
    pass_kind: str,
    max_batches: int | None,
    proof_path: Path | None,
) -> dict[str, object]:
    if max_batches is not None and (type(max_batches) is not int or max_batches < 0):
        raise MigrationCommandError("max batches must be non-negative")
    state = _load_split_state(state_path, expected_uid=expected_authority_uid)
    export_state = _validate_export_state(state[export_key])
    watermark = LegacyTestWatermark.from_document(export_state["watermark"])
    finalize_running = bool(export_state["finalize_running"])
    if finalize_running != (pass_kind == "final"):
        raise MigrationCommandError("split export pass identity is contradictory")
    source = LegacyTestHistoryMigrator(
        Path(str(state["authority_database"])),
        None,
        expected_authority_uid=expected_authority_uid,
    )
    available = int(
        shutil.disk_usage(Path(str(export_state["package_directory"]))).free
    )
    required = watermark.estimated_import_bytes + DEFAULT_CAPACITY_RESERVE_BYTES
    if available < required:
        raise TestStoreConflict(
            f"test history export needs {required} free bytes but only {available} are available"
        )
    bound_proof = state["drain_proof_fingerprint"]

    def validate_boundary() -> None:
        if pass_kind == "final":
            if proof_path is None or bound_proof is None:
                raise MigrationCommandError("final export requires bound drain evidence")
            _require_bound_drain_proof(
                Path(str(state["authority_database"])),
                proof_path,
                expected_uid=expected_authority_uid,
                expected_fingerprint=str(bound_proof),
            )
            source.validate_final_watermark(watermark)
        else:
            source.validate_watermark(watermark)

    validate_boundary()
    completed_batches = 0
    cursor = int(export_state["cursor"])
    while cursor < watermark.maximum_rowid:
        if max_batches is not None and completed_batches >= max_batches:
            break
        validate_boundary()
        batch = source.export_next_batch(
            watermark,
            finalize_running=finalize_running,
            after_rowid=cursor,
            batch_size=int(state["batch_size"]),
        )
        chunk_index = int(export_state["chunk_count"])
        chunk = _seal_document(
            EXPORT_CHUNK_KIND,
            {
                "migration_id": state["migration_id"],
                "pass_kind": pass_kind,
                "authority_generation": watermark.authority_generation,
                "watermark_fingerprint": _fingerprint(watermark.to_document()),
                "chunk_index": chunk_index,
                "after_rowid": cursor,
                "next_rowid": batch.next_rowid,
                "complete": batch.complete,
                "finalize_running": finalize_running,
                "previous_chunk_sha256": export_state["chain_sha256"],
                "projection_digest": batch.projection_digest,
                "run_count": batch.run_count,
                "case_count": batch.case_count,
                "deferred_running_count": batch.deferred_running_count,
                "abandoned_running_count": batch.abandoned_running_count,
                "records": [dict(record) for record in batch.records],
            },
        )
        chunk_path = Path(str(export_state["package_directory"])) / f"chunk-{chunk_index:08d}.json"
        _publish_recipient_json(
            chunk_path,
            chunk,
            writer_uid=expected_authority_uid,
            recipient_uid=expected_test_uid,
        )
        export_state = {
            **dict(export_state),
            "cursor": batch.next_rowid,
            "chunk_count": chunk_index + 1,
            "chain_sha256": chunk["document_sha256"],
            "projection_chain_sha256": hashlib.sha256(
                (
                    str(export_state["projection_chain_sha256"])
                    + batch.projection_digest
                ).encode("ascii")
            ).hexdigest(),
            "run_count": int(export_state["run_count"]) + batch.run_count,
            "case_count": int(export_state["case_count"]) + batch.case_count,
            "deferred_running_count": int(export_state["deferred_running_count"])
            + batch.deferred_running_count,
            "abandoned_running_count": int(export_state["abandoned_running_count"])
            + batch.abandoned_running_count,
        }
        phase = "final_exporting" if pass_kind == "final" else "initial_exporting"
        state = _save_split_progress(
            state_path,
            state,
            expected_authority_uid=expected_authority_uid,
            export_key=export_key,
            export_state=export_state,
            phase=phase,
        )
        cursor = batch.next_rowid
        completed_batches += 1
    if cursor >= watermark.maximum_rowid and export_state["manifest_path"] is None:
        validate_boundary()
        manifest = _seal_document(
            EXPORT_MANIFEST_KIND,
            {
                "migration_id": state["migration_id"],
                "pass_kind": pass_kind,
                "authority_generation": watermark.authority_generation,
                "test_store_generation": state["test_store_generation"],
                "watermark": watermark.to_document(),
                "watermark_fingerprint": _fingerprint(watermark.to_document()),
                "finalize_running": finalize_running,
                "chunk_count": export_state["chunk_count"],
                "final_chunk_sha256": export_state["chain_sha256"],
                "projection_chain_sha256": export_state[
                    "projection_chain_sha256"
                ],
                "run_count": export_state["run_count"],
                "case_count": export_state["case_count"],
                "deferred_running_count": export_state["deferred_running_count"],
                "abandoned_running_count": export_state["abandoned_running_count"],
            },
        )
        manifest_path = Path(str(export_state["package_directory"])) / "manifest.json"
        _publish_recipient_json(
            manifest_path,
            manifest,
            writer_uid=expected_authority_uid,
            recipient_uid=expected_test_uid,
        )
        export_state = {
            **dict(export_state),
            "manifest_path": str(manifest_path),
            "manifest_fingerprint": manifest["document_sha256"],
        }
        phase = "final_exported" if pass_kind == "final" else "initial_exported"
        state = _save_split_progress(
            state_path,
            state,
            expected_authority_uid=expected_authority_uid,
            export_key=export_key,
            export_state=export_state,
            phase=phase,
        )
    validate_boundary()
    return {
        "ok": True,
        "action": f"authority-export-{pass_kind}",
        "phase": state["phase"],
        "cursor": export_state["cursor"],
        "maximum_rowid": watermark.maximum_rowid,
        "batches": completed_batches,
        "manifest": export_state["manifest_path"],
        "manifest_fingerprint": export_state["manifest_fingerprint"],
        "source_retained": True,
    }


def authority_export_initial_split(
    *,
    state_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    max_batches: int | None,
) -> dict[str, object]:
    state = _load_split_state(state_path, expected_uid=expected_authority_uid)
    if state["phase"] not in {"captured", "initial_exporting", "initial_exported"}:
        raise MigrationCommandError("initial export is not allowed in this phase")
    return _export_batches_split(
        state_path=state_path,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
        export_key="initial_export",
        pass_kind="initial",
        max_batches=max_batches,
        proof_path=None,
    )


def authority_finalize_split(
    *,
    state_path: Path,
    final_package_directory: Path,
    proof_path: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
    max_batches: int | None,
) -> dict[str, object]:
    state = _load_split_state(state_path, expected_uid=expected_authority_uid)
    if state["phase"] not in {
        "initial_exported",
        "final_exporting",
        "final_exported",
    }:
        raise MigrationCommandError("final export requires a completed initial export")
    _proof, proof_fingerprint = _verify_drain_proof(
        Path(str(state["authority_database"])),
        proof_path,
        expected_uid=expected_authority_uid,
    )
    if state["drain_proof_fingerprint"] not in {None, proof_fingerprint}:
        raise MigrationCommandError("final export drain proof differs from its bound proof")
    if state["final_export"] is None:
        package = _absolute(final_package_directory, "final package directory")
        refuse_symlink_components(package)
        metadata = package.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_test_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise MigrationCommandError(
                "final package directory must be testd-owned mode 0700"
            )
        source = LegacyTestHistoryMigrator(
            Path(str(state["authority_database"])),
            None,
            expected_authority_uid=expected_authority_uid,
        )
        watermark = source.capture_watermark()
        _require_bound_drain_proof(
            Path(str(state["authority_database"])),
            proof_path,
            expected_uid=expected_authority_uid,
            expected_fingerprint=proof_fingerprint,
        )
        source.validate_final_watermark(watermark)
        old_generation = int(state["state_generation"])
        updated = {
            **dict(state),
            "phase": "final_exporting",
            "final_export": _new_export_state(
                package_directory=package,
                watermark=watermark,
                finalize_running=True,
            ),
            "drain_proof_fingerprint": proof_fingerprint,
            "updated_at": _now(),
            "state_generation": old_generation + 1,
        }
        state = _validate_split_state(updated)
        _replace_private_json(
            state_path,
            state,
            expected_uid=expected_authority_uid,
            create=False,
            expected_generation=old_generation,
        )
    else:
        expected_package = str(_absolute(final_package_directory, "final package directory"))
        if str(state["final_export"]["package_directory"]) != expected_package:  # type: ignore[index]
            raise MigrationCommandError("final package differs from migration state")
    return _export_batches_split(
        state_path=state_path,
        expected_authority_uid=expected_authority_uid,
        expected_test_uid=expected_test_uid,
        export_key="final_export",
        pass_kind="final",
        max_batches=max_batches,
        proof_path=proof_path,
    )


def _verified_export_manifest(
    path: Path,
    *,
    expected_uid: int,
    expected_fingerprint: str,
) -> Mapping[str, object]:
    manifest = _verify_sealed_document(
        _read_private_json(path, expected_uid=expected_uid),
        kind=EXPORT_MANIFEST_KIND,
        fields=_EXPORT_MANIFEST_FIELDS,
    )
    if manifest["document_sha256"] != expected_fingerprint:
        raise MigrationCommandError("export manifest differs from its expected fingerprint")
    watermark = LegacyTestWatermark.from_document(manifest["watermark"])
    try:
        uuid.UUID(str(manifest["migration_id"]))
    except (TypeError, ValueError, AttributeError) as error:
        raise MigrationCommandError("export migration ID is invalid") from error
    store_generation = manifest["test_store_generation"]
    if (
        not isinstance(store_generation, str)
        or not store_generation
        or len(store_generation) > 256
        or any(character in store_generation for character in "\x00\r\n")
    ):
        raise MigrationCommandError("export test-store generation is invalid")
    if manifest["authority_generation"] != watermark.authority_generation:
        raise MigrationCommandError("export authority generation is contradictory")
    if manifest["watermark_fingerprint"] != _fingerprint(watermark.to_document()):
        raise MigrationCommandError("export watermark fingerprint is invalid")
    for field in (
        "chunk_count",
        "run_count",
        "case_count",
        "deferred_running_count",
        "abandoned_running_count",
    ):
        if type(manifest[field]) is not int or int(manifest[field]) < 0:
            raise MigrationCommandError(f"export manifest {field} is invalid")
    for field in ("final_chunk_sha256", "projection_chain_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(manifest[field])) is None:
            raise MigrationCommandError(f"export manifest {field} is invalid")
    if manifest["pass_kind"] not in {"initial", "final"}:
        raise MigrationCommandError("export pass kind is invalid")
    if manifest["finalize_running"] != (manifest["pass_kind"] == "final"):
        raise MigrationCommandError("export finalize flag is contradictory")
    return manifest


def _verified_export_chunk(
    path: Path,
    *,
    expected_uid: int,
) -> Mapping[str, object]:
    chunk = _verify_sealed_document(
        _read_private_json(
            path,
            expected_uid=expected_uid,
            maximum_bytes=MAX_EXPORT_DOCUMENT_BYTES,
        ),
        kind=EXPORT_CHUNK_KIND,
        fields=_EXPORT_CHUNK_FIELDS,
    )
    records = chunk["records"]
    if not isinstance(records, list) or len(records) > MAX_MIGRATION_BATCH_SIZE:
        raise MigrationCommandError("export chunk records are invalid")
    if type(chunk["chunk_index"]) is not int or int(chunk["chunk_index"]) < 0:
        raise MigrationCommandError("export chunk index is invalid")
    for field in (
        "after_rowid",
        "next_rowid",
        "run_count",
        "case_count",
        "deferred_running_count",
        "abandoned_running_count",
    ):
        if type(chunk[field]) is not int or int(chunk[field]) < 0:
            raise MigrationCommandError(f"export chunk {field} is invalid")
    if int(chunk["next_rowid"]) <= int(chunk["after_rowid"]):
        raise MigrationCommandError("export chunk cursor did not advance")
    if int(chunk["run_count"]) != len(records):
        raise MigrationCommandError("export chunk run count is contradictory")
    projection_digest = _fingerprint(
        [record.get("projection") for record in records if isinstance(record, Mapping)]
    )
    if projection_digest != chunk["projection_digest"]:
        raise MigrationCommandError("export chunk projection digest is invalid")
    return chunk


def testd_import_split(
    *,
    manifest_path: Path,
    expected_export_fingerprint: str,
    test_database: Path,
    attestation_output: Path,
    expected_test_uid: int,
) -> dict[str, object]:
    """Import one authority export while opening only testd-owned state."""

    if os.geteuid() != expected_test_uid:
        raise MigrationCommandError("export import must run as the testd UID")
    manifest_path = _absolute(manifest_path, "manifest")
    manifest = _verified_export_manifest(
        manifest_path,
        expected_uid=expected_test_uid,
        expected_fingerprint=expected_export_fingerprint,
    )
    store = UniversalTestStore.open(test_database, expected_uid=expected_test_uid)
    store_generation = str(store.verify()["store_generation"])
    if store_generation != manifest["test_store_generation"]:
        raise MigrationCommandError("export targets a different test-store generation")
    watermark = LegacyTestWatermark.from_document(manifest["watermark"])
    available = int(shutil.disk_usage(store.path.parent).free)
    required = watermark.estimated_import_bytes + DEFAULT_CAPACITY_RESERVE_BYTES
    if available < required:
        raise TestStoreConflict(
            f"test history import needs {required} free bytes but only {available} are available"
        )
    importer = LegacyTestExportImporter(store)
    previous_chunk = _EMPTY_CHAIN
    projection_chain = _EMPTY_CHAIN
    run_count = case_count = deferred_count = abandoned_count = 0
    package = manifest_path.parent
    for index in range(int(manifest["chunk_count"])):
        chunk = _verified_export_chunk(
            package / f"chunk-{index:08d}.json",
            expected_uid=expected_test_uid,
        )
        for field in (
            "migration_id",
            "pass_kind",
            "authority_generation",
            "watermark_fingerprint",
            "finalize_running",
        ):
            expected = (
                manifest[field]
                if field != "finalize_running"
                else bool(manifest[field])
            )
            if chunk[field] != expected:
                raise MigrationCommandError(f"export chunk {field} is contradictory")
        if chunk["chunk_index"] != index or chunk["previous_chunk_sha256"] != previous_chunk:
            raise MigrationCommandError("export chunk chain is invalid")
        if index + 1 < int(manifest["chunk_count"]) and chunk["complete"]:
            raise MigrationCommandError("export chunk ended before the manifest tail")
        if index + 1 == int(manifest["chunk_count"]) and not chunk["complete"]:
            raise MigrationCommandError("export manifest tail is incomplete")
        operation_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"devcoordinator:test-history-export:{expected_export_fingerprint}:{index}",
            )
        )
        imported = importer.import_batch(
            chunk["records"],  # type: ignore[arg-type]
            operation_id=operation_id,
            expected_projection_digest=str(chunk["projection_digest"]),
        )
        run_count += int(imported["run_count"])
        case_count += int(imported["case_count"])
        deferred_count += int(chunk["deferred_running_count"])
        abandoned_count += int(chunk["abandoned_running_count"])
        previous_chunk = str(chunk["document_sha256"])
        projection_chain = hashlib.sha256(
            (projection_chain + str(chunk["projection_digest"])).encode("ascii")
        ).hexdigest()
    if int(manifest["chunk_count"]) == 0 and watermark.maximum_rowid != 0:
        raise MigrationCommandError("non-empty export watermark has no chunks")
    if (
        previous_chunk != manifest["final_chunk_sha256"]
        or projection_chain != manifest["projection_chain_sha256"]
        or run_count != manifest["run_count"]
        or case_count != manifest["case_count"]
        or deferred_count != manifest["deferred_running_count"]
        or abandoned_count != manifest["abandoned_running_count"]
    ):
        raise MigrationCommandError("destination import does not match the export manifest")
    rollups = store.rebuild_rollups()
    store.verify()
    attestation = _seal_document(
        IMPORT_ATTESTATION_KIND,
        {
            "migration_id": manifest["migration_id"],
            "pass_kind": manifest["pass_kind"],
            "authority_generation": manifest["authority_generation"],
            "watermark_fingerprint": manifest["watermark_fingerprint"],
            "export_fingerprint": manifest["document_sha256"],
            "test_store_generation": store_generation,
            "chunk_count": manifest["chunk_count"],
            "final_chunk_sha256": previous_chunk,
            "run_count": run_count,
            "case_count": case_count,
            "destination_projection_chain_sha256": projection_chain,
            "source_retained": True,
        },
    )
    _publish_private_json(
        attestation_output,
        attestation,
        expected_uid=expected_test_uid,
    )
    return {
        "ok": True,
        "action": "testd-import",
        "pass_kind": manifest["pass_kind"],
        "attestation": str(attestation_output),
        "attestation_fingerprint": attestation["document_sha256"],
        "run_count": run_count,
        "case_count": case_count,
        "rollups": rollups,
    }


def _verified_import_attestation(
    path: Path,
    *,
    expected_uid: int,
    expected_fingerprint: str,
) -> Mapping[str, object]:
    attestation = _verify_sealed_document(
        _read_private_json(path, expected_uid=expected_uid),
        kind=IMPORT_ATTESTATION_KIND,
        fields=_IMPORT_ATTESTATION_FIELDS,
    )
    if attestation["document_sha256"] != expected_fingerprint:
        raise MigrationCommandError(
            "destination attestation differs from its expected fingerprint"
        )
    for field in ("chunk_count", "run_count", "case_count"):
        if type(attestation[field]) is not int or int(attestation[field]) < 0:
            raise MigrationCommandError(f"destination attestation {field} is invalid")
    if attestation["source_retained"] is not True:
        raise MigrationCommandError("destination attestation lost rollback retention")
    for field in (
        "watermark_fingerprint",
        "export_fingerprint",
        "final_chunk_sha256",
        "destination_projection_chain_sha256",
    ):
        if re.fullmatch(r"[0-9a-f]{64}", str(attestation[field])) is None:
            raise MigrationCommandError(f"destination attestation {field} is invalid")
    return attestation


def authority_seal_split(
    *,
    state_path: Path,
    proof_path: Path,
    attestation_path: Path,
    expected_attestation_fingerprint: str,
    output: Path,
    expected_authority_uid: int,
    expected_test_uid: int,
) -> dict[str, object]:
    """Publish readiness without ever opening the testd-owned database."""

    state = _load_split_state(state_path, expected_uid=expected_authority_uid)
    if state["phase"] not in {"final_exported", "destination_verified", "sealed"}:
        raise MigrationCommandError("authority seal requires a complete final export")
    final_export = _validate_export_state(state["final_export"])
    if final_export["manifest_path"] is None or final_export["manifest_fingerprint"] is None:
        raise MigrationCommandError("authority seal lacks a final export manifest")
    proof_fingerprint = str(state["drain_proof_fingerprint"])
    _require_bound_drain_proof(
        Path(str(state["authority_database"])),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    manifest = _verified_export_manifest(
        Path(str(final_export["manifest_path"])),
        expected_uid=expected_test_uid,
        expected_fingerprint=str(final_export["manifest_fingerprint"]),
    )
    if (
        manifest["migration_id"] != state["migration_id"]
        or manifest["pass_kind"] != "final"
        or manifest["test_store_generation"] != state["test_store_generation"]
    ):
        raise MigrationCommandError("final export manifest differs from migration state")
    attestation = _verified_import_attestation(
        attestation_path,
        expected_uid=expected_test_uid,
        expected_fingerprint=expected_attestation_fingerprint,
    )
    comparisons = {
        "migration_id": manifest["migration_id"],
        "pass_kind": "final",
        "authority_generation": manifest["authority_generation"],
        "watermark_fingerprint": manifest["watermark_fingerprint"],
        "export_fingerprint": manifest["document_sha256"],
        "test_store_generation": state["test_store_generation"],
        "chunk_count": manifest["chunk_count"],
        "final_chunk_sha256": manifest["final_chunk_sha256"],
        "run_count": manifest["run_count"],
        "case_count": manifest["case_count"],
        "destination_projection_chain_sha256": manifest[
            "projection_chain_sha256"
        ],
        "source_retained": True,
    }
    for field, expected in comparisons.items():
        if attestation[field] != expected:
            raise MigrationCommandError(
                f"destination attestation {field} does not match final export"
            )
    bound_attestation = str(attestation["document_sha256"])
    if state["destination_attestation_fingerprint"] not in {
        None,
        bound_attestation,
    }:
        raise MigrationCommandError("destination attestation differs from migration state")
    watermark = LegacyTestWatermark.from_document(manifest["watermark"])
    source = LegacyTestHistoryMigrator(
        Path(str(state["authority_database"])),
        None,
        expected_authority_uid=expected_authority_uid,
    )
    source.validate_final_watermark(watermark)
    _require_bound_drain_proof(
        Path(str(state["authority_database"])),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    if state["phase"] == "final_exported":
        old_generation = int(state["state_generation"])
        state = _validate_split_state(
            {
                **dict(state),
                "phase": "destination_verified",
                "destination_attestation_fingerprint": bound_attestation,
                "updated_at": _now(),
                "state_generation": old_generation + 1,
            }
        )
        _replace_private_json(
            state_path,
            state,
            expected_uid=expected_authority_uid,
            create=False,
            expected_generation=old_generation,
        )
    source.validate_final_watermark(watermark)
    _require_bound_drain_proof(
        Path(str(state["authority_database"])),
        proof_path,
        expected_uid=expected_authority_uid,
        expected_fingerprint=proof_fingerprint,
    )
    seal_document = _seal_document(
        "universal-test-history-split-cutover-seal",
        {
            "migration_id": state["migration_id"],
            "authority_database": state["authority_database"],
            "authority_generation": watermark.authority_generation,
            "test_database": state["test_database"],
            "test_store_generation": state["test_store_generation"],
            "drain_proof_fingerprint": proof_fingerprint,
            "final_export_fingerprint": manifest["document_sha256"],
            "final_watermark_fingerprint": manifest["watermark_fingerprint"],
            "destination_attestation_fingerprint": bound_attestation,
            "legacy_source_retained": True,
            "activation_ready": True,
            "rollback": {
                "safe": True,
                "instruction": (
                    "retain the authority history and clear the exact broker drain only "
                    "after the new testd read/write pointer is verified"
                ),
            },
        },
    )
    _publish_private_json(output, seal_document, expected_uid=expected_authority_uid)
    if state["phase"] != "sealed":
        old_generation = int(state["state_generation"])
        state = _validate_split_state(
            {
                **dict(state),
                "phase": "sealed",
                "updated_at": _now(),
                "state_generation": old_generation + 1,
            }
        )
        _replace_private_json(
            state_path,
            state,
            expected_uid=expected_authority_uid,
            create=False,
            expected_generation=old_generation,
        )
    return {
        "ok": True,
        "action": "authority-seal",
        "phase": state["phase"],
        "seal": str(output),
        "seal_fingerprint": seal_document["document_sha256"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)

    prepare_packages = actions.add_parser("testd-prepare-package-directories")
    prepare_packages.add_argument("--package-root", required=True)
    prepare_packages.add_argument("--operation-id", required=True)
    prepare_packages.add_argument("--expected-test-uid", type=int, required=True)

    split_capture = actions.add_parser("authority-capture")
    split_capture.add_argument("--authority-database", required=True)
    split_capture.add_argument("--test-database", required=True)
    split_capture.add_argument("--test-store-generation", required=True)
    split_capture.add_argument("--state", required=True)
    split_capture.add_argument("--initial-package-directory", required=True)
    split_capture.add_argument("--expected-authority-uid", type=int, required=True)
    split_capture.add_argument("--expected-test-uid", type=int, required=True)
    split_capture.add_argument(
        "--batch-size", type=int, default=DEFAULT_MIGRATION_BATCH_SIZE
    )

    split_initial = actions.add_parser("authority-export-initial")
    split_initial.add_argument("--state", required=True)
    split_initial.add_argument("--expected-authority-uid", type=int, required=True)
    split_initial.add_argument("--expected-test-uid", type=int, required=True)
    split_initial.add_argument("--max-batches", type=int)

    split_finalize = actions.add_parser("authority-finalize")
    split_finalize.add_argument("--state", required=True)
    split_finalize.add_argument("--final-package-directory", required=True)
    split_finalize.add_argument("--drain-proof", required=True)
    split_finalize.add_argument("--expected-authority-uid", type=int, required=True)
    split_finalize.add_argument("--expected-test-uid", type=int, required=True)
    split_finalize.add_argument("--max-batches", type=int)

    split_import = actions.add_parser("testd-import")
    split_import.add_argument("--manifest", required=True)
    split_import.add_argument("--expected-export-fingerprint", required=True)
    split_import.add_argument("--test-database", required=True)
    split_import.add_argument("--attestation-output", required=True)
    split_import.add_argument("--expected-test-uid", type=int, required=True)

    split_prepare_schema = actions.add_parser("testd-prepare-schema")
    split_prepare_schema.add_argument("--test-database", required=True)
    split_prepare_schema.add_argument("--operation-id", required=True)
    split_prepare_schema.add_argument("--attestation-output", required=True)
    split_prepare_schema.add_argument("--expected-test-uid", type=int, required=True)

    fresh = actions.add_parser(
        "testd-initialize-fresh",
        help=(
            "discard only the isolated test store and initialize the current "
            "empty schema; testd must be offline"
        ),
    )
    fresh.add_argument("--test-database", required=True)
    fresh.add_argument("--operation-id", required=True)
    fresh.add_argument("--attestation-output", required=True)
    fresh.add_argument("--expected-test-uid", type=int, required=True)
    fresh.add_argument(
        "--confirm-discard-test-history",
        required=True,
        choices=(DISCARD_TEST_HISTORY_CONFIRMATION,),
    )

    split_seal = actions.add_parser("authority-seal")
    split_seal.add_argument("--state", required=True)
    split_seal.add_argument("--drain-proof", required=True)
    split_seal.add_argument("--attestation", required=True)
    split_seal.add_argument("--expected-attestation-fingerprint", required=True)
    split_seal.add_argument("--output", required=True)
    split_seal.add_argument("--expected-authority-uid", type=int, required=True)
    split_seal.add_argument("--expected-test-uid", type=int, required=True)

    create = actions.add_parser("create")
    create.add_argument("--test-database", required=True)
    create.add_argument("--expected-test-uid", type=int, required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.action == "testd-prepare-package-directories":
            result = testd_prepare_package_directories(
                package_root=_absolute(args.package_root, "package root"),
                operation_id=args.operation_id,
                expected_test_uid=args.expected_test_uid,
            )
        elif args.action == "authority-capture":
            result = authority_capture_split(
                authority_database=_absolute(args.authority_database, "authority database"),
                test_database=_absolute(args.test_database, "test database"),
                test_store_generation=args.test_store_generation,
                state_path=_absolute(args.state, "state"),
                initial_package_directory=_absolute(
                    args.initial_package_directory, "initial package directory"
                ),
                expected_authority_uid=args.expected_authority_uid,
                expected_test_uid=args.expected_test_uid,
                batch_size=args.batch_size,
            )
        elif args.action == "authority-export-initial":
            result = authority_export_initial_split(
                state_path=_absolute(args.state, "state"),
                expected_authority_uid=args.expected_authority_uid,
                expected_test_uid=args.expected_test_uid,
                max_batches=args.max_batches,
            )
        elif args.action == "authority-finalize":
            result = authority_finalize_split(
                state_path=_absolute(args.state, "state"),
                final_package_directory=_absolute(
                    args.final_package_directory, "final package directory"
                ),
                proof_path=_absolute(args.drain_proof, "drain proof"),
                expected_authority_uid=args.expected_authority_uid,
                expected_test_uid=args.expected_test_uid,
                max_batches=args.max_batches,
            )
        elif args.action == "testd-import":
            result = testd_import_split(
                manifest_path=_absolute(args.manifest, "manifest"),
                expected_export_fingerprint=args.expected_export_fingerprint,
                test_database=_absolute(args.test_database, "test database"),
                attestation_output=_absolute(
                    args.attestation_output, "attestation output"
                ),
                expected_test_uid=args.expected_test_uid,
            )
        elif args.action == "testd-prepare-schema":
            result = testd_prepare_store_schema(
                test_database=_absolute(args.test_database, "test database"),
                operation_id=args.operation_id,
                attestation_output=_absolute(
                    args.attestation_output, "attestation output"
                ),
                expected_test_uid=args.expected_test_uid,
            )
        elif args.action == "testd-initialize-fresh":
            result = testd_initialize_fresh_store(
                test_database=_absolute(args.test_database, "test database"),
                operation_id=args.operation_id,
                attestation_output=_absolute(
                    args.attestation_output, "schema readiness attestation"
                ),
                expected_test_uid=args.expected_test_uid,
                confirmation=args.confirm_discard_test_history,
            )
        elif args.action == "authority-seal":
            result = authority_seal_split(
                state_path=_absolute(args.state, "state"),
                proof_path=_absolute(args.drain_proof, "drain proof"),
                attestation_path=_absolute(args.attestation, "attestation"),
                expected_attestation_fingerprint=args.expected_attestation_fingerprint,
                output=_absolute(args.output, "output"),
                expected_authority_uid=args.expected_authority_uid,
                expected_test_uid=args.expected_test_uid,
            )
        elif args.action == "create":
            result = create_store(
                _absolute(args.test_database, "test database"),
                expected_uid=args.expected_test_uid,
            )
        else:
            raise MigrationCommandError("unsupported migration action")
    except (
        MigrationCommandError,
        TestStoreConflict,
        TestStoreContractError,
        StoreError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        print(
            _canonical_json(
                {"ok": False, "error": " ".join(str(error).split())[:2000]}
            ),
            file=sys.stderr,
        )
        return 1
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
