"""Offline repair of profile authority that predates repository enrollments.

The protected client profile is an existing administrator-owned authority
artifact.  This migration may copy only its exact, still-current repository
enrollments into an otherwise compatible broker database.  It deliberately
does not synthesize principals, ACLs, repositories, or installation state.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any
import uuid

from .broker_enrollment import _atomic_write_root_json, _locked_root_profile
from .broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    _validate_profile_file,
    profile_from_document,
)
from .store import CoordinatorStore, canonical_json, fingerprint, utc_timestamp


class ProfileEnrollmentMigrationError(RuntimeError):
    """The protected profile cannot be copied safely into this authority."""


class ProfileGenerationReconciliationError(RuntimeError):
    """One exact protected-profile generation cannot be reconciled safely."""


@dataclass(frozen=True)
class _EnrollmentCandidate:
    uid: int
    account_id: str
    repo_id: str
    canonical_root: str
    repository_generation: int
    issued_at: str
    valid_until_epoch: int


_ACL_EVIDENCE_TABLES = (
    "broker_resource_acl",
    "broker_assignment_acl",
    "broker_compose_acl",
    "broker_lifecycle_acl",
    "broker_lifecycle_resource_acl",
    "broker_repository_read_acl",
    "broker_host_observation_acl",
    "broker_cleanup_acl",
    "broker_cleanup_resource_acl",
    "broker_database_acl",
)

_ENROLLMENT_COLUMNS = (
    "uid",
    "repo_id",
    "account_id",
    "enabled",
    "issued_at",
    "valid_until_epoch",
    "enrollment_snapshot_id",
    "grant_snapshot_id",
    "updated_at",
)

_CREATE_ENROLLMENT_TABLE = """
CREATE TABLE broker_repository_enrollments (
    uid INTEGER NOT NULL,
    repo_id TEXT NOT NULL
        REFERENCES repositories(repo_id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    issued_at TEXT NOT NULL,
    valid_until_epoch INTEGER NOT NULL CHECK(valid_until_epoch > 0),
    enrollment_snapshot_id TEXT
        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
    grant_snapshot_id TEXT
        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id),
    FOREIGN KEY(uid, account_id)
        REFERENCES broker_acl_principals(uid, account_id) ON DELETE CASCADE,
    CHECK(
        (enrollment_snapshot_id IS NULL AND grant_snapshot_id IS NULL)
        OR
        (enrollment_snapshot_id IS NOT NULL AND grant_snapshot_id IS NOT NULL)
    )
)
"""


def reconcile_protected_profile_repository_generation(
    *,
    database_path: Path,
    profile_path: Path,
    client_uid: int,
    account_id: str,
    repo_id: str,
    canonical_root: str,
    from_generation: int,
    to_generation: int,
    rollback_root: Path,
    expected_service_uid: int | None = None,
    trusted_profile_owner_uid: int = 0,
    trusted_rollback_owner_gid: int = 0,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Reconcile one explicitly identified stale profile generation forward.

    The caller must hold the broker lifetime lock. This function additionally
    holds the canonical protected-profile publication lock for validation,
    backup publication, the scalar rewrite, and post-publication verification.
    It never provisions or rebuilds a principal, ACL, repository, or grant.
    """

    service_uid = os.geteuid() if expected_service_uid is None else int(
        expected_service_uid
    )
    if service_uid != os.geteuid():
        raise PermissionError(
            "profile generation reconciliation must run as the database service owner"
        )
    if type(client_uid) is not int or client_uid < 0:
        raise ValueError("client_uid must be a non-negative integer")
    if type(from_generation) is not int or from_generation < 0:
        raise ValueError("from_generation must be a non-negative integer")
    if type(to_generation) is not int or to_generation <= from_generation:
        raise ValueError("to_generation must be greater than from_generation")
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("account_id must be a non-empty identifier")
    if not isinstance(repo_id, str) or not repo_id:
        raise ValueError("repo_id must be a non-empty identifier")
    requested_root = Path(canonical_root).expanduser()
    if (
        not requested_root.is_absolute()
        or ".." in requested_root.parts
        or str(requested_root.resolve()) != canonical_root
    ):
        raise ValueError("canonical_root must be an exact canonical absolute path")
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    if now <= 0:
        raise ValueError("now_epoch must be a positive integer")
    rollback_directory = _validate_private_rollback_root(
        rollback_root.expanduser(),
        trusted_owner_uid=int(trusted_profile_owner_uid),
        trusted_owner_gid=int(trusted_rollback_owner_gid),
    )
    rollback_preflight = rollback_directory.lstat()
    database = database_path.expanduser().absolute()
    with CoordinatorStore.open_read_only(
        database, expected_uid=service_uid
    ) as database_preflight:
        preflight_database_generation = (
            database_preflight.metadata.database_generation
        )

    path = profile_path.expanduser()
    preflight = _strict_profile_metadata(
        path, trusted_owner_uid=int(trusted_profile_owner_uid)
    )
    access_gid = int(preflight.st_gid)
    with _locked_root_profile(path, access_gid=access_gid):
        rollback_locked = _validate_private_rollback_root(
            rollback_directory,
            trusted_owner_uid=int(trusted_profile_owner_uid),
            trusted_owner_gid=int(trusted_rollback_owner_gid),
        ).lstat()
        if (rollback_preflight.st_dev, rollback_preflight.st_ino) != (
            rollback_locked.st_dev,
            rollback_locked.st_ino,
        ):
            raise ProfileGenerationReconciliationError(
                "rollback root identity changed before the profile lock was acquired"
            )
        metadata, document = _read_protected_profile_document(
            path,
            trusted_owner_uid=int(trusted_profile_owner_uid),
            expected_gid=access_gid,
        )
        if (metadata.st_dev, metadata.st_ino) != (
            preflight.st_dev,
            preflight.st_ino,
        ):
            raise ProfileGenerationReconciliationError(
                "protected profile identity changed before its publication lock was acquired"
            )
        profile, repository_index = _target_profile_repository(
            document,
            client_uid=client_uid,
            account_id=account_id,
            repo_id=repo_id,
            canonical_root=canonical_root,
            now_epoch=now,
        )
        repository = profile.repository(canonical_root)
        if repository.repo_id != repo_id:
            raise ProfileGenerationReconciliationError(
                "protected profile repository identity conflicts with the request"
            )
        if repository.generation != from_generation:
            raise ProfileGenerationReconciliationError(
                "from_generation does not match the protected profile"
            )
        service = profile.service
        if service.service_uid != service_uid:
            raise ProfileGenerationReconciliationError(
                "protected profile service UID does not match the database service owner"
            )
        if service.socket_gid != access_gid:
            raise ProfileGenerationReconciliationError(
                "protected profile socket GID does not match the profile publication group"
            )

        updated_document = copy.deepcopy(document)
        updated_repository = updated_document["clients"][str(client_uid)][
            "repositories"
        ][repository_index]
        if type(updated_repository.get("generation")) is not int:
            raise ProfileGenerationReconciliationError(
                "protected repository generation is not an integer scalar"
            )
        updated_repository["generation"] = to_generation
        expected_path = (
            "clients",
            str(client_uid),
            "repositories",
            repository_index,
            "generation",
        )
        _require_only_scalar_change(
            document,
            updated_document,
            expected_path=expected_path,
            expected_before=from_generation,
            expected_after=to_generation,
        )

        if service.database_generation != preflight_database_generation:
            raise ProfileGenerationReconciliationError(
                "protected profile database generation does not match the broker database"
            )
        with CoordinatorStore.open(database, expected_uid=service_uid) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                database_changes_before = connection.total_changes
                database_generation = _database_generation(connection)
                if database_generation != service.database_generation:
                    raise ProfileGenerationReconciliationError(
                        "protected profile database generation does not match the broker database"
                    )
                candidate = _EnrollmentCandidate(
                    uid=client_uid,
                    account_id=account_id,
                    repo_id=repo_id,
                    canonical_root=canonical_root,
                    repository_generation=to_generation,
                    issued_at=repository.issued_at,
                    valid_until_epoch=repository.valid_until_epoch,
                )
                _validate_reconciliation_candidate_authority(
                    connection, candidate
                )
                _validate_optional_existing_enrollment(
                    connection, candidate, now_epoch=now
                )
                acl_digest, acl_rows = _enabled_acl_digest(
                    connection, uid=client_uid, repo_id=repo_id
                )

                rollback_path = rollback_directory / (
                    f"{path.name}.generation-reconcile."
                    f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}."
                    f"{uuid.uuid4().hex}.rollback.json"
                )
                if rollback_path.exists() or rollback_path.is_symlink():
                    raise ProfileGenerationReconciliationError(
                        "unique rollback evidence path already exists"
                    )
                _write_private_rollback_json(
                    rollback_path,
                    document,
                    owner_uid=int(trusted_profile_owner_uid),
                    owner_gid=int(trusted_rollback_owner_gid),
                )
                _require_private_rollback_document(
                    rollback_path,
                    expected=document,
                    owner_uid=int(trusted_profile_owner_uid),
                    owner_gid=int(trusted_rollback_owner_gid),
                )
                try:
                    _atomic_write_root_json(
                        path, updated_document, access_gid=access_gid
                    )
                    _metadata_after, published = _read_protected_profile_document(
                        path,
                        trusted_owner_uid=int(trusted_profile_owner_uid),
                        expected_gid=access_gid,
                    )
                    if published != updated_document:
                        raise ProfileGenerationReconciliationError(
                            "published profile contains changes outside the exact generation reconciliation"
                        )
                    _require_only_scalar_change(
                        document,
                        published,
                        expected_path=expected_path,
                        expected_before=from_generation,
                        expected_after=to_generation,
                    )
                    after_digest, after_rows = _enabled_acl_digest(
                        connection, uid=client_uid, repo_id=repo_id
                    )
                    if (after_digest, after_rows) != (acl_digest, acl_rows):
                        raise ProfileGenerationReconciliationError(
                            "enabled ACL evidence changed during profile publication"
                        )
                    _validate_reconciliation_candidate_authority(
                        connection, candidate
                    )
                    _validate_optional_existing_enrollment(
                        connection, candidate, now_epoch=now
                    )
                    if connection.total_changes != database_changes_before:
                        raise ProfileGenerationReconciliationError(
                            "profile reconciliation unexpectedly mutated the broker database"
                        )
                except BaseException as publication_error:
                    rollback_error: BaseException | None = None
                    try:
                        _atomic_write_root_json(path, document, access_gid=access_gid)
                        _metadata_restored, restored = (
                            _read_protected_profile_document(
                                path,
                                trusted_owner_uid=int(trusted_profile_owner_uid),
                                expected_gid=access_gid,
                            )
                        )
                        if restored != document:
                            raise ProfileGenerationReconciliationError(
                                "profile rollback did not restore the original document"
                            )
                    except BaseException as error:
                        rollback_error = error
                    if rollback_error is not None:
                        raise ProfileGenerationReconciliationError(
                            "profile publication and rollback both failed; "
                            f"rollback evidence remains at {rollback_path}: "
                            f"publication={publication_error}; rollback={rollback_error}"
                        ) from publication_error
                    raise ProfileGenerationReconciliationError(
                        "profile publication failed and the original document was restored; "
                        f"rollback evidence remains at {rollback_path}: {publication_error}"
                    ) from publication_error

    return {
        "status": "reconciled",
        "database": str(database),
        "profile": str(path),
        "client_uid": client_uid,
        "account_id": account_id,
        "repo_id": repo_id,
        "canonical_root": canonical_root,
        "from_generation": from_generation,
        "to_generation": to_generation,
        "database_generation": service.database_generation,
        "acl_evidence_digest": acl_digest,
        "acl_evidence_rows": acl_rows,
        "rollback_profile": str(rollback_path),
        "rollback_document_sha256": "sha256:" + fingerprint(document),
        "grants_rebuilt": False,
        "database_mutated": False,
        "profile_scalar_changes": 1,
    }


def _strict_profile_metadata(
    path: Path, *, trusted_owner_uid: int
) -> os.stat_result:
    try:
        metadata = _validate_profile_file(
            path, trusted_owner_uid=trusted_owner_uid
        )
    except (FileNotFoundError, OSError, BrokerProfileError) as error:
        raise ProfileGenerationReconciliationError(
            f"protected broker profile is missing or unsafe: {error}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != trusted_owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o640
    ):
        raise ProfileGenerationReconciliationError(
            "protected broker profile must be an administrator-owned 0640 regular file"
        )
    return metadata


def _read_protected_profile_document(
    path: Path,
    *,
    trusted_owner_uid: int,
    expected_gid: int,
) -> tuple[os.stat_result, dict[str, Any]]:
    metadata = _strict_profile_metadata(
        path, trusted_owner_uid=trusted_owner_uid
    )
    if metadata.st_gid != expected_gid:
        raise ProfileGenerationReconciliationError(
            "protected broker profile group changed during reconciliation"
        )
    try:
        payload = path.read_bytes()
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileGenerationReconciliationError(
            f"protected broker profile cannot be decoded: {error}"
        ) from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
        raise ProfileGenerationReconciliationError(
            "protected broker profile identity changed while it was read"
        )
    if not isinstance(document, dict):
        raise ProfileGenerationReconciliationError(
            "protected broker profile document must be an object"
        )
    return metadata, document


def _target_profile_repository(
    document: dict[str, Any],
    *,
    client_uid: int,
    account_id: str,
    repo_id: str,
    canonical_root: str,
    now_epoch: int,
) -> tuple[BrokerClientProfile, int]:
    clients = document.get("clients")
    raw_client = clients.get(str(client_uid)) if isinstance(clients, dict) else None
    if not isinstance(raw_client, dict):
        raise ProfileGenerationReconciliationError(
            "protected profile has no exact client UID row"
        )
    if str(raw_client.get("account_id") or "") != account_id:
        raise ProfileGenerationReconciliationError(
            "protected profile client account conflicts with the request"
        )
    repositories = raw_client.get("repositories")
    if not isinstance(repositories, list):
        raise ProfileGenerationReconciliationError(
            "protected profile repository collection is invalid"
        )
    exact: list[int] = []
    same_repo_id: list[int] = []
    same_root: list[int] = []
    for index, raw_repository in enumerate(repositories):
        if not isinstance(raw_repository, dict):
            raise ProfileGenerationReconciliationError(
                "protected profile contains a non-object repository row"
            )
        raw_repo_id = str(raw_repository.get("repo_id") or "")
        raw_root_value = raw_repository.get("canonical_root")
        raw_root = raw_root_value if isinstance(raw_root_value, str) else ""
        if raw_root and str(Path(raw_root).expanduser().resolve()) == canonical_root:
            if raw_root != canonical_root:
                raise ProfileGenerationReconciliationError(
                    "protected profile repository root is not stored canonically"
                )
        if raw_repo_id == repo_id:
            same_repo_id.append(index)
        if raw_root == canonical_root:
            same_root.append(index)
        if raw_repo_id == repo_id and raw_root == canonical_root:
            exact.append(index)
    if len(exact) != 1:
        raise ProfileGenerationReconciliationError(
            "protected profile must contain exactly one matching repository row"
        )
    if len(same_repo_id) != 1 or len(same_root) != 1:
        raise ProfileGenerationReconciliationError(
            "protected profile contains conflicting or duplicate repository rows"
        )
    try:
        profile = profile_from_document(document, effective_uid=client_uid)
        repository = profile.repository(canonical_root)
    except BrokerProfileError as error:
        raise ProfileGenerationReconciliationError(str(error)) from error
    if now_epoch >= profile.valid_until_epoch:
        raise ProfileGenerationReconciliationError(
            "protected broker client profile has expired"
        )
    if not repository.enabled or now_epoch >= repository.valid_until_epoch:
        raise ProfileGenerationReconciliationError(
            "protected repository profile is disabled or expired"
        )
    if repository.account_id != account_id or repository.repo_id != repo_id:
        raise ProfileGenerationReconciliationError(
            "protected repository profile conflicts with the exact request"
        )
    return profile, exact[0]


def _scalar_changes(
    before: Any, after: Any, *, path: tuple[Any, ...] = ()
) -> list[tuple[tuple[Any, ...], Any, Any]]:
    if type(before) is not type(after):
        return [(path, before, after)]
    if isinstance(before, dict):
        if set(before) != set(after):
            return [(path, before, after)]
        changes: list[tuple[tuple[Any, ...], Any, Any]] = []
        for key in sorted(before):
            changes.extend(
                _scalar_changes(before[key], after[key], path=(*path, key))
            )
        return changes
    if isinstance(before, list):
        if len(before) != len(after):
            return [(path, before, after)]
        changes = []
        for index, (left, right) in enumerate(zip(before, after)):
            changes.extend(
                _scalar_changes(left, right, path=(*path, index))
            )
        return changes
    return [] if before == after else [(path, before, after)]


def _require_only_scalar_change(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    expected_path: tuple[Any, ...],
    expected_before: int,
    expected_after: int,
) -> None:
    changes = _scalar_changes(before, after)
    if changes != [(expected_path, expected_before, expected_after)]:
        raise ProfileGenerationReconciliationError(
            "profile reconciliation may change only the exact generation integer scalar"
        )


def _database_generation(connection: sqlite3.Connection) -> str:
    metadata = connection.execute(
        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if metadata is None:
        raise ProfileGenerationReconciliationError(
            "broker database schema metadata is missing"
        )
    return str(metadata["database_generation"])


def _validate_optional_existing_enrollment(
    connection: sqlite3.Connection,
    candidate: _EnrollmentCandidate,
    *,
    now_epoch: int,
) -> None:
    table = connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'broker_repository_enrollments'
        """
    ).fetchone()
    if table is None:
        return
    existing = connection.execute(
        """
        SELECT account_id, enabled, issued_at, valid_until_epoch
        FROM broker_repository_enrollments
        WHERE uid = ? AND repo_id = ?
        """,
        (candidate.uid, candidate.repo_id),
    ).fetchone()
    if existing is None:
        return
    if not bool(existing["enabled"]):
        raise ProfileGenerationReconciliationError(
            "existing repository enrollment is disabled"
        )
    if int(existing["valid_until_epoch"]) <= now_epoch:
        raise ProfileGenerationReconciliationError(
            "existing repository enrollment is expired"
        )
    if (
        str(existing["account_id"]) != candidate.account_id
        or str(existing["issued_at"]) != candidate.issued_at
        or int(existing["valid_until_epoch"]) != candidate.valid_until_epoch
    ):
        raise ProfileGenerationReconciliationError(
            "existing repository enrollment conflicts with the protected profile"
        )


def _validate_reconciliation_candidate_authority(
    connection: sqlite3.Connection, candidate: _EnrollmentCandidate
) -> None:
    try:
        _validate_candidate_authority(connection, candidate)
    except ProfileEnrollmentMigrationError as error:
        raise ProfileGenerationReconciliationError(str(error)) from error


def _enabled_acl_digest(
    connection: sqlite3.Connection, *, uid: int, repo_id: str
) -> tuple[str, int]:
    available_tables = {
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    evidence: list[dict[str, Any]] = []
    row_count = 0
    for table in _ACL_EVIDENCE_TABLES:
        if table not in available_tables:
            continue
        columns = tuple(
            str(row["name"])
            for row in connection.execute(f"PRAGMA table_info({table})")
            if str(row["name"]) != "updated_at"
        )
        selected = [
            {column: row[column] for column in columns}
            for row in connection.execute(
                f"SELECT * FROM {table} WHERE uid = ? AND repo_id = ? AND enabled = 1",
                (uid, repo_id),
            )
        ]
        if not selected:
            continue
        selected.sort(key=canonical_json)
        evidence.append({"table": table, "rows": selected})
        row_count += len(selected)
    if not evidence:
        raise ProfileGenerationReconciliationError(
            "protected profile repository has no existing enabled ACL evidence"
        )
    return "sha256:" + hashlib.sha256(
        canonical_json(evidence).encode("utf-8")
    ).hexdigest(), row_count


def _validate_private_rollback_root(
    path: Path, *, trusted_owner_uid: int, trusted_owner_gid: int
) -> Path:
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path == Path(path.anchor)
        or path.resolve() != path
    ):
        raise ProfileGenerationReconciliationError(
            "rollback root must be an existing canonical absolute directory"
        )
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProfileGenerationReconciliationError(
                f"rollback root is missing or unsafe: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ProfileGenerationReconciliationError(
                "rollback root path contains a non-directory or symlink"
            )
        if metadata.st_uid not in {0, trusted_owner_uid}:
            raise ProfileGenerationReconciliationError(
                "rollback root path has an untrusted owner"
            )
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProfileGenerationReconciliationError(
                "rollback root path contains a replaceable ancestor"
            )
    metadata = path.lstat()
    if (
        metadata.st_uid != trusted_owner_uid
        or metadata.st_gid != trusted_owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProfileGenerationReconciliationError(
            "rollback root must be administrator-owned with mode 0700"
        )
    return path


def _write_private_rollback_json(
    path: Path,
    document: dict[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    payload = (canonical_json(document) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    completed = False
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchown(handle.fileno(), owner_uid, owner_gid)
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        completed = True
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not completed:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _require_private_rollback_document(
    path: Path,
    *,
    expected: dict[str, Any],
    owner_uid: int,
    owner_gid: int,
) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProfileGenerationReconciliationError(
            "rollback evidence is not a protected administrator-owned 0600 file"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileGenerationReconciliationError(
            f"rollback evidence cannot be decoded: {error}"
        ) from error
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
        raise ProfileGenerationReconciliationError(
            "rollback evidence identity changed while it was read"
        )
    if document != expected:
        raise ProfileGenerationReconciliationError(
            "rollback evidence does not contain the original protected profile"
        )


def migrate_protected_profile_enrollments(
    *,
    database_path: Path,
    profile_path: Path,
    expected_service_uid: int | None = None,
    trusted_profile_owner_uid: int = 0,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Backfill only absent repository-enrollment rows from one profile.

    The public CLI wraps this function in the broker lifetime lock.  Keeping
    the mutation itself separate makes its complete validation and atomicity
    directly testable without weakening the production lock boundary.
    """

    service_uid = os.geteuid() if expected_service_uid is None else int(
        expected_service_uid
    )
    if service_uid != os.geteuid():
        raise PermissionError(
            "broker enrollment migration must run as the database service owner"
        )
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    if now <= 0:
        raise ValueError("now_epoch must be a positive integer")

    profiles = _load_protected_profiles(
        profile_path,
        trusted_owner_uid=int(trusted_profile_owner_uid),
        now_epoch=now,
    )
    service_generations = {profile.service.database_generation for profile in profiles}
    service_uids = {profile.service.service_uid for profile in profiles}
    if service_uids != {service_uid}:
        raise ProfileEnrollmentMigrationError(
            "protected profile service UID does not match the database service owner"
        )
    if len(service_generations) != 1:
        raise ProfileEnrollmentMigrationError(
            "protected profile contains conflicting database generations"
        )
    profile_generation = next(iter(service_generations))
    candidates = _candidates(profiles, now_epoch=now)

    database = database_path.expanduser().absolute()
    with CoordinatorStore.open(database, expected_uid=service_uid) as store:
        with store.immediate_transaction(
            revision_kind=None, check_invariants=False
        ) as connection:
            created_table = _ensure_enrollment_schema(connection)
            metadata = connection.execute(
                "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            if metadata is None:
                raise ProfileEnrollmentMigrationError(
                    "broker database schema metadata is missing"
                )
            database_generation = str(metadata["database_generation"])
            if database_generation != profile_generation:
                raise ProfileEnrollmentMigrationError(
                    "protected profile database generation does not match the broker database"
                )

            missing: list[_EnrollmentCandidate] = []
            current = 0
            for candidate in candidates:
                _validate_candidate_authority(connection, candidate)
                existing = connection.execute(
                    """
                    SELECT account_id, enabled, issued_at, valid_until_epoch
                    FROM broker_repository_enrollments
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (candidate.uid, candidate.repo_id),
                ).fetchone()
                if existing is None:
                    missing.append(candidate)
                    continue
                if not bool(existing["enabled"]):
                    raise ProfileEnrollmentMigrationError(
                        "existing repository enrollment is disabled; migration refuses to re-enable it"
                    )
                if (
                    str(existing["account_id"]) != candidate.account_id
                    or str(existing["issued_at"]) != candidate.issued_at
                    or int(existing["valid_until_epoch"])
                    != candidate.valid_until_epoch
                ):
                    raise ProfileEnrollmentMigrationError(
                        "existing repository enrollment conflicts with the protected profile"
                    )
                current += 1

            updated_at = utc_timestamp(now)
            for candidate in missing:
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, enrollment_snapshot_id,
                        grant_snapshot_id, updated_at
                    ) VALUES (?, ?, ?, 1, ?, ?, NULL, NULL, ?)
                    """,
                    (
                        candidate.uid,
                        candidate.repo_id,
                        candidate.account_id,
                        candidate.issued_at,
                        candidate.valid_until_epoch,
                        updated_at,
                    ),
                )
            _require_enrollment_invariants(connection, candidates)

    return {
        "status": "migrated",
        "profile": str(profile_path),
        "database": str(database),
        "database_generation": profile_generation,
        "checked": len(candidates),
        "inserted": len(missing),
        "already_current": current,
        "created_enrollment_table": created_table,
        "mutated_tables": ["broker_repository_enrollments"] if missing else [],
        "inserted_enrollments": [
            {"uid": item.uid, "repo_id": item.repo_id} for item in missing
        ],
    }


def _load_protected_profiles(
    path: Path, *, trusted_owner_uid: int, now_epoch: int
) -> tuple[BrokerClientProfile, ...]:
    candidate = path.expanduser()
    try:
        metadata = _validate_profile_file(
            candidate, trusted_owner_uid=trusted_owner_uid
        )
    except (FileNotFoundError, OSError, BrokerProfileError) as error:
        raise ProfileEnrollmentMigrationError(
            f"protected broker profile is missing or unsafe: {error}"
        ) from error
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileEnrollmentMigrationError(
            f"protected broker profile cannot be decoded: {error}"
        ) from error
    after = candidate.lstat()
    if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
        raise ProfileEnrollmentMigrationError(
            "protected broker profile identity changed while it was read"
        )
    clients = document.get("clients") if isinstance(document, dict) else None
    if not isinstance(clients, dict) or not clients:
        raise ProfileEnrollmentMigrationError(
            "protected broker profile has no client enrollments"
        )

    profiles: list[BrokerClientProfile] = []
    for raw_uid in sorted(clients, key=str):
        try:
            uid = int(raw_uid)
        except (TypeError, ValueError) as error:
            raise ProfileEnrollmentMigrationError(
                "protected broker profile contains an invalid client UID"
            ) from error
        if uid < 0 or str(uid) != raw_uid:
            raise ProfileEnrollmentMigrationError(
                "protected broker profile contains a non-canonical client UID"
            )
        try:
            profile = profile_from_document(document, effective_uid=uid)
        except BrokerProfileError as error:
            raise ProfileEnrollmentMigrationError(str(error)) from error
        if now_epoch >= profile.valid_until_epoch:
            raise ProfileEnrollmentMigrationError(
                "protected broker client profile has expired"
            )
        profiles.append(profile)
    return tuple(profiles)


def _candidates(
    profiles: tuple[BrokerClientProfile, ...], *, now_epoch: int
) -> tuple[_EnrollmentCandidate, ...]:
    result: list[_EnrollmentCandidate] = []
    identities: set[tuple[int, str]] = set()
    for profile in profiles:
        for repository in profile.repositories.values():
            identity = (profile.client_uid, repository.repo_id)
            if identity in identities:
                raise ProfileEnrollmentMigrationError(
                    "protected profile duplicates a client/repository identity"
                )
            identities.add(identity)
            if not repository.enabled:
                raise ProfileEnrollmentMigrationError(
                    "protected profile contains a disabled repository enrollment"
                )
            if repository.account_id != profile.account_id:
                raise ProfileEnrollmentMigrationError(
                    "protected repository profile belongs to another account"
                )
            if now_epoch >= repository.valid_until_epoch:
                raise ProfileEnrollmentMigrationError(
                    "protected repository profile has expired"
                )
            if not repository.issued_at:
                raise ProfileEnrollmentMigrationError(
                    "protected repository profile has no issuance timestamp"
                )
            result.append(
                _EnrollmentCandidate(
                    uid=profile.client_uid,
                    account_id=profile.account_id,
                    repo_id=repository.repo_id,
                    canonical_root=repository.canonical_root,
                    repository_generation=repository.generation,
                    issued_at=repository.issued_at,
                    valid_until_epoch=repository.valid_until_epoch,
                )
            )
    if not result:
        raise ProfileEnrollmentMigrationError(
            "protected broker profile has no current repository enrollments"
        )
    return tuple(sorted(result, key=lambda item: (item.uid, item.repo_id)))


def _ensure_enrollment_schema(connection: sqlite3.Connection) -> bool:
    existing = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("broker_repository_enrollments",),
    ).fetchone()
    created = existing is None
    if created:
        connection.execute(_CREATE_ENROLLMENT_TABLE)
    column_rows = tuple(
        connection.execute("PRAGMA table_info(broker_repository_enrollments)")
    )
    columns = tuple(str(row["name"]) for row in column_rows)
    column_contract = tuple(
        (
            str(row["name"]),
            str(row["type"]).upper(),
            int(row["notnull"]),
            None if row["dflt_value"] is None else str(row["dflt_value"]),
            int(row["pk"]),
        )
        for row in column_rows
    )
    expected_columns = (
        ("uid", "INTEGER", 1, None, 1),
        ("repo_id", "TEXT", 1, None, 2),
        ("account_id", "TEXT", 1, None, 0),
        ("enabled", "INTEGER", 1, "1", 0),
        ("issued_at", "TEXT", 1, None, 0),
        ("valid_until_epoch", "INTEGER", 1, None, 0),
        ("enrollment_snapshot_id", "TEXT", 0, None, 0),
        ("grant_snapshot_id", "TEXT", 0, None, 0),
        ("updated_at", "TEXT", 1, None, 0),
    )
    if columns != _ENROLLMENT_COLUMNS or column_contract != expected_columns:
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment schema is incompatible"
        )
    primary_key = tuple(
        str(row["name"])
        for row in sorted(
            connection.execute(
                "PRAGMA table_info(broker_repository_enrollments)"
            ),
            key=lambda row: int(row["pk"] or 0),
        )
        if int(row["pk"] or 0) > 0
    )
    if primary_key != ("uid", "repo_id"):
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment primary key is incompatible"
        )
    table_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("broker_repository_enrollments",),
    ).fetchone()
    normalized_sql = "".join(str(table_row["sql"] or "").lower().split())
    required_checks = (
        "check(enabledin(0,1))",
        "check(valid_until_epoch>0)",
        "(enrollment_snapshot_idisnullandgrant_snapshot_idisnull)or(enrollment_snapshot_idisnotnullandgrant_snapshot_idisnotnull)",
    )
    if any(value not in normalized_sql for value in required_checks):
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment CHECK constraints are incompatible"
        )
    foreign_keys = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
        )
        for row in connection.execute(
            "PRAGMA foreign_key_list(broker_repository_enrollments)"
        )
    }
    expected_foreign_keys = {
        ("repositories", "repo_id", "repo_id", "NO ACTION", "CASCADE"),
        (
            "observation_snapshots",
            "enrollment_snapshot_id",
            "snapshot_id",
            "NO ACTION",
            "RESTRICT",
        ),
        (
            "observation_snapshots",
            "grant_snapshot_id",
            "snapshot_id",
            "NO ACTION",
            "RESTRICT",
        ),
        ("broker_acl_principals", "uid", "uid", "NO ACTION", "CASCADE"),
        (
            "broker_acl_principals",
            "account_id",
            "account_id",
            "NO ACTION",
            "CASCADE",
        ),
    }
    if foreign_keys != expected_foreign_keys:
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment foreign keys are incompatible"
        )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS broker_repository_enrollments_by_repo
        ON broker_repository_enrollments(repo_id, enabled, valid_until_epoch)
        """
    )
    index_columns = tuple(
        str(row["name"])
        for row in connection.execute(
            "PRAGMA index_info(broker_repository_enrollments_by_repo)"
        )
    )
    if index_columns != ("repo_id", "enabled", "valid_until_epoch"):
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment index is incompatible"
        )
    index_row = next(
        (
            row
            for row in connection.execute(
                "PRAGMA index_list(broker_repository_enrollments)"
            )
            if str(row["name"]) == "broker_repository_enrollments_by_repo"
        ),
        None,
    )
    if (
        index_row is None
        or int(index_row["unique"]) != 0
        or int(index_row["partial"]) != 0
        or str(index_row["origin"]) != "c"
    ):
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment index properties are incompatible"
        )
    return created


def _require_enrollment_invariants(
    connection: sqlite3.Connection,
    candidates: tuple[_EnrollmentCandidate, ...],
) -> None:
    foreign_key_failures = tuple(
        connection.execute(
            "PRAGMA foreign_key_check(broker_repository_enrollments)"
        )
    )
    if foreign_key_failures:
        raise ProfileEnrollmentMigrationError(
            "broker repository enrollment foreign-key validation failed"
        )
    for candidate in candidates:
        row = connection.execute(
            """
            SELECT e.account_id, e.enabled, e.issued_at, e.valid_until_epoch,
                   p.account_id AS principal_account, p.enabled AS principal_enabled,
                   r.canonical_root, r.generation AS repository_generation,
                   r.state, i.status, i.startup_fenced
            FROM broker_repository_enrollments e
            JOIN broker_acl_principals p
              ON p.uid = e.uid AND p.account_id = e.account_id
            JOIN repositories r ON r.repo_id = e.repo_id
            JOIN repository_installations i ON i.repo_id = e.repo_id
            WHERE e.uid = ? AND e.repo_id = ?
            """,
            (candidate.uid, candidate.repo_id),
        ).fetchone()
        if (
            row is None
            or str(row["account_id"]) != candidate.account_id
            or not bool(row["enabled"])
            or str(row["issued_at"]) != candidate.issued_at
            or int(row["valid_until_epoch"]) != candidate.valid_until_epoch
            or str(row["principal_account"]) != candidate.account_id
            or not bool(row["principal_enabled"])
            or str(row["canonical_root"]) != candidate.canonical_root
            or int(row["repository_generation"])
            != candidate.repository_generation
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
        ):
            raise ProfileEnrollmentMigrationError(
                "broker repository enrollment invariant validation failed"
            )


def _validate_candidate_authority(
    connection: sqlite3.Connection, candidate: _EnrollmentCandidate
) -> None:
    principal = connection.execute(
        "SELECT account_id, enabled FROM broker_acl_principals WHERE uid = ?",
        (candidate.uid,),
    ).fetchone()
    if principal is None:
        raise ProfileEnrollmentMigrationError(
            "protected profile client has no existing broker principal"
        )
    if not bool(principal["enabled"]):
        raise ProfileEnrollmentMigrationError(
            "protected profile client broker principal is disabled"
        )
    if str(principal["account_id"]) != candidate.account_id:
        raise ProfileEnrollmentMigrationError(
            "protected profile account conflicts with the existing broker principal"
        )

    repository = connection.execute(
        """
        SELECT canonical_root, state, generation
        FROM repositories WHERE repo_id = ?
        """,
        (candidate.repo_id,),
    ).fetchone()
    if repository is None:
        raise ProfileEnrollmentMigrationError(
            "protected profile targets an unknown repository identity"
        )
    if str(repository["canonical_root"]) != candidate.canonical_root:
        raise ProfileEnrollmentMigrationError(
            "protected profile repository root conflicts with the broker database"
        )
    if int(repository["generation"]) != candidate.repository_generation:
        raise ProfileEnrollmentMigrationError(
            "protected profile repository generation conflicts with the broker database"
        )
    if str(repository["state"]) != "active":
        raise ProfileEnrollmentMigrationError(
            "protected profile repository is disabled in the broker database"
        )

    installation = connection.execute(
        """
        SELECT status, startup_fenced
        FROM repository_installations WHERE repo_id = ?
        """,
        (candidate.repo_id,),
    ).fetchone()
    if (
        installation is None
        or str(installation["status"]) != "installed"
        or bool(installation["startup_fenced"])
    ):
        raise ProfileEnrollmentMigrationError(
            "protected profile repository is not enabled and installed"
        )

    available_tables = {
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    evidence = False
    for table in _ACL_EVIDENCE_TABLES:
        if table not in available_tables:
            continue
        row = connection.execute(
            f"SELECT 1 FROM {table} WHERE uid = ? AND repo_id = ? AND enabled = 1 LIMIT 1",
            (candidate.uid, candidate.repo_id),
        ).fetchone()
        if row is not None:
            evidence = True
            break
    if not evidence:
        raise ProfileEnrollmentMigrationError(
            "protected profile repository has no existing enabled ACL evidence"
        )
