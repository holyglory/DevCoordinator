"""Sealed offline repository execution-owner authority migration.

No function in this module infers an owner from a caller, filesystem inode,
profile enrollment, repository name, or path.  An administrator supplies the
complete repo-id -> UID decision; the generated map binds those decisions to
the current database generation, state revision, canonical roots, and
repository generations before schema v13 is activated atomically.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Mapping
import uuid

from .schema import (
    PRE_OWNER_AUTHORITY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    migrate_repository_owner_authority_v13,
)
from .repository_execution_scope import (
    RepositoryExecutionScopeError,
    repository_execution_scope,
    validate_repository_execution_scope,
)


OWNER_MAP_SCHEMA_VERSION = 3
OWNER_MAP_KIND = "devcoordinator-repository-owner-authority-map"
MAX_OWNER_MAP_BYTES = 1024 * 1024
OWNER_MIGRATION_FENCE_SCHEMA_VERSION = 1
OWNER_MIGRATION_FENCE_KIND = "devcoordinator-repository-owner-cutover-fence"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_MAX_IDENTITY_TEXT = 512
_MAX_PATH_TEXT = 4096


class RepositoryOwnerAuthorityError(RuntimeError):
    pass


def _canonical_absolute_path(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_TEXT
        or "\x00" in value
        or not value.startswith("/")
        or os.path.normpath(value) != value
    ):
        raise RepositoryOwnerAuthorityError(f"{label} path is invalid")
    return value


def _sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise RepositoryOwnerAuthorityError(f"{label} digest is invalid")
    return value


def _bounded_identity(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > _MAX_IDENTITY_TEXT
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RepositoryOwnerAuthorityError(f"{label} is invalid")
    return value


def _canonical_uuid(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise RepositoryOwnerAuthorityError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise RepositoryOwnerAuthorityError(
            f"{label} must be a canonical UUID"
        ) from error
    if str(parsed) != value:
        raise RepositoryOwnerAuthorityError(f"{label} must be a canonical UUID")
    return value


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise RepositoryOwnerAuthorityError(
            "repository owner map is not canonical JSON"
        ) from error


def _document_digest(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("document_sha256", None)
    return "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()


def _metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               migration_state
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        raise RepositoryOwnerAuthorityError("schema metadata singleton is missing")
    return {
        "schema_version": int(row[0]),
        "database_generation": str(row[1]),
        "state_revision": int(row[2]),
        "migration_state": str(row[3]),
    }


def repository_census(connection: sqlite3.Connection) -> dict[str, Any]:
    """Return the exact schema-12 repository set for an operator decision.

    This deliberately reports no inferred owner.  The administrator must still
    provide every ``repo-id -> UID`` decision to :func:`prepare_owner_map`.
    Exposing the generation-fenced repository set closes the operational gap
    where the map preparer otherwise had no supported way to discover which
    explicit decisions were required.
    """

    metadata = _metadata(connection)
    if metadata["schema_version"] != PRE_OWNER_AUTHORITY_SCHEMA_VERSION:
        raise RepositoryOwnerAuthorityError(
            "repository census requires exact schema "
            f"{PRE_OWNER_AUTHORITY_SCHEMA_VERSION}"
        )
    if metadata["migration_state"] != "ready":
        raise RepositoryOwnerAuthorityError(
            "repository census requires migration_state=ready; "
            f"actual={metadata['migration_state']!r}"
        )
    try:
        scope = repository_execution_scope(connection)
    except RepositoryExecutionScopeError as error:
        raise RepositoryOwnerAuthorityError(str(error)) from error
    repositories = list(scope["executable_repositories"])
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for repository in repositories:
        repository_id = _bounded_identity(
            repository["repository_id"], label="repository census repository_id"
        )
        if repository_id in seen:
            raise RepositoryOwnerAuthorityError(
                "repository census contains a duplicate repository_id"
            )
        seen.add(repository_id)
        canonical_root = _canonical_absolute_path(
            repository["canonical_root"], label="repository census canonical_root"
        )
        generation = repository["repository_generation"]
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 0
        ):
            raise RepositoryOwnerAuthorityError(
                "repository census repository_generation is invalid"
            )
        blockers = repository.get("terminal_exclusion_blockers")
        if (
            not isinstance(blockers, list)
            or not blockers
            or any(
                not isinstance(item, str) or not item or len(item) > _MAX_IDENTITY_TEXT
                for item in blockers
            )
        ):
            raise RepositoryOwnerAuthorityError(
                "repository census executable scope blockers are invalid"
            )
        normalized.append(
            {
                "repository_id": repository_id,
                "canonical_root": canonical_root,
                "repository_generation": generation,
                "display_name": _bounded_identity(
                    repository["display_name"],
                    label="repository census display_name",
                ),
                "state": repository["state"],
                "terminal_exclusion_blockers": list(blockers),
            }
        )
        if normalized[-1]["state"] not in {"active", "missing", "relocated"}:
            raise RepositoryOwnerAuthorityError(
                "repository census state is invalid"
            )
    return {
        "schema_version": metadata["schema_version"],
        "database_generation": _bounded_identity(
            metadata["database_generation"],
            label="repository census database_generation",
        ),
        "state_revision": metadata["state_revision"],
        "migration_state": metadata["migration_state"],
        "repository_count": scope["repository_count"],
        "executable_repository_count": scope["executable_repository_count"],
        "excluded_terminal_repository_count": scope[
            "excluded_terminal_repository_count"
        ],
        "repository_universe_sha256": scope["repository_universe_sha256"],
        "executable_repositories_sha256": scope[
            "executable_repositories_sha256"
        ],
        "excluded_terminal_repositories_sha256": scope[
            "excluded_terminal_repositories_sha256"
        ],
        "repository_execution_scope_sha256": scope["document_sha256"],
        "repositories": normalized,
        "excluded_terminal_repositories": scope[
            "excluded_terminal_repositories"
        ],
    }


def prepare_owner_map(
    connection: sqlite3.Connection,
    *,
    owner_uids: Mapping[str, int],
    operation_id: str,
    actor: str,
    created_at: str | None = None,
    target_database_generation: str | None = None,
) -> dict[str, Any]:
    """Return an exact sealed owner map without modifying the database."""

    try:
        parsed_operation_id = uuid.UUID(operation_id)
    except (ValueError, TypeError, AttributeError) as error:
        raise RepositoryOwnerAuthorityError(
            "repository owner map operation_id must be a UUID"
        ) from error
    if str(parsed_operation_id) != operation_id:
        raise RepositoryOwnerAuthorityError(
            "repository owner map operation_id must be canonical"
        )
    _bounded_identity(actor, label="repository owner map actor")
    metadata = _metadata(connection)
    if metadata["schema_version"] != PRE_OWNER_AUTHORITY_SCHEMA_VERSION:
        raise RepositoryOwnerAuthorityError(
            "repository owner map preparation requires exact schema "
            f"{PRE_OWNER_AUTHORITY_SCHEMA_VERSION}"
        )
    if metadata["migration_state"] != "ready":
        raise RepositoryOwnerAuthorityError(
            "repository owner map preparation requires migration_state=ready; "
            f"actual={metadata['migration_state']!r}"
        )
    source_database_generation = _bounded_identity(
        metadata["database_generation"],
        label="repository owner map source_database_generation",
    )
    target_generation = _canonical_uuid(
        target_database_generation or str(uuid.uuid4()),
        label="repository owner map target_database_generation",
    )
    if target_generation == source_database_generation:
        raise RepositoryOwnerAuthorityError(
            "repository owner map target database generation must rotate"
        )
    try:
        execution_scope = repository_execution_scope(connection)
    except RepositoryExecutionScopeError as error:
        raise RepositoryOwnerAuthorityError(str(error)) from error
    repositories = [
        {
            "repository_id": str(item["repository_id"]),
            "canonical_root": str(item["canonical_root"]),
            "repository_generation": int(item["repository_generation"]),
        }
        for item in execution_scope["executable_repositories"]
    ]
    expected = {str(item["repository_id"]) for item in repositories}
    if set(owner_uids) != expected:
        missing = sorted(expected - set(owner_uids))
        extra = sorted(set(owner_uids) - expected)
        raise RepositoryOwnerAuthorityError(
            "repository owner decisions must cover every repository exactly once; "
            f"missing={missing!r} extra={extra!r}"
        )
    assignments: list[dict[str, Any]] = []
    for repository in repositories:
        repository_id = str(repository["repository_id"])
        owner_uid = owner_uids[repository_id]
        if isinstance(owner_uid, bool) or not isinstance(owner_uid, int) or owner_uid <= 0:
            raise RepositoryOwnerAuthorityError(
                f"repository {repository_id} owner UID must be a positive integer"
            )
        assignments.append({**repository, "owner_uid": owner_uid})
    document: dict[str, Any] = {
        "schema_version": OWNER_MAP_SCHEMA_VERSION,
        "kind": OWNER_MAP_KIND,
        "operation_id": operation_id,
        "actor": actor,
        "created_at": created_at or utc_timestamp(),
        "source_database_generation": source_database_generation,
        "target_database_generation": target_generation,
        "source_schema_version": PRE_OWNER_AUTHORITY_SCHEMA_VERSION,
        "source_state_revision": metadata["state_revision"],
        "repository_execution_scope": execution_scope,
        "repositories": assignments,
    }
    document["document_sha256"] = _document_digest(document)
    return document


def validate_owner_map(
    connection: sqlite3.Connection, document: Mapping[str, Any]
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "kind",
        "operation_id",
        "actor",
        "created_at",
        "source_database_generation",
        "target_database_generation",
        "source_schema_version",
        "source_state_revision",
        "repository_execution_scope",
        "repositories",
        "document_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise RepositoryOwnerAuthorityError("repository owner map fields are invalid")
    if (
        document["schema_version"] != OWNER_MAP_SCHEMA_VERSION
        or document["kind"] != OWNER_MAP_KIND
        or document["source_schema_version"]
        != PRE_OWNER_AUTHORITY_SCHEMA_VERSION
    ):
        raise RepositoryOwnerAuthorityError("repository owner map contract is invalid")
    try:
        parsed_operation_id = uuid.UUID(str(document["operation_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise RepositoryOwnerAuthorityError(
            "repository owner map operation_id must be a UUID"
        ) from error
    if str(parsed_operation_id) != document["operation_id"]:
        raise RepositoryOwnerAuthorityError(
            "repository owner map operation_id must be canonical"
        )
    _bounded_identity(document["actor"], label="repository owner map actor")
    if not isinstance(document["created_at"], str):
        raise RepositoryOwnerAuthorityError("repository owner map created_at is invalid")
    try:
        parsed_created_at = datetime.fromisoformat(
            document["created_at"].replace("Z", "+00:00")
        )
    except ValueError as error:
        raise RepositoryOwnerAuthorityError(
            "repository owner map created_at is invalid"
        ) from error
    canonical_created_at = parsed_created_at.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    if (
        parsed_created_at.tzinfo is None
        or document["created_at"] != canonical_created_at
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner map created_at must be canonical UTC"
        )
    _sha256(document["document_sha256"], label="repository owner map")
    source_database_generation = _bounded_identity(
        document["source_database_generation"],
        label="repository owner map source_database_generation",
    )
    target_database_generation = _canonical_uuid(
        document["target_database_generation"],
        label="repository owner map target_database_generation",
    )
    if target_database_generation == source_database_generation:
        raise RepositoryOwnerAuthorityError(
            "repository owner map target database generation must rotate"
        )
    if (
        isinstance(document["source_state_revision"], bool)
        or not isinstance(document["source_state_revision"], int)
        or document["source_state_revision"] < 0
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner map source_state_revision is invalid"
        )
    if document["document_sha256"] != _document_digest(document):
        raise RepositoryOwnerAuthorityError("repository owner map digest is invalid")
    metadata = _metadata(connection)
    if metadata != {
        "schema_version": PRE_OWNER_AUTHORITY_SCHEMA_VERSION,
        "database_generation": source_database_generation,
        "state_revision": document["source_state_revision"],
        "migration_state": "ready",
    }:
        raise RepositoryOwnerAuthorityError(
            "repository owner map database generation or revision fence changed"
        )
    try:
        execution_scope = validate_repository_execution_scope(
            connection, document["repository_execution_scope"]
        )
    except RepositoryExecutionScopeError as error:
        raise RepositoryOwnerAuthorityError(str(error)) from error
    if (
        execution_scope["authority_schema_version"]
        != PRE_OWNER_AUTHORITY_SCHEMA_VERSION
        or execution_scope["database_generation"] != source_database_generation
        or execution_scope["state_revision"] != document["source_state_revision"]
        or execution_scope["migration_state"] != "ready"
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner map execution scope fence is invalid"
        )
    repositories = document["repositories"]
    if not isinstance(repositories, list):
        raise RepositoryOwnerAuthorityError("repository owner map entries are invalid")
    expected_rows = [
        {
            "repository_id": str(item["repository_id"]),
            "canonical_root": str(item["canonical_root"]),
            "repository_generation": int(item["repository_generation"]),
        }
        for item in execution_scope["executable_repositories"]
    ]
    normalized_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict) or set(item) != {
            "repository_id",
            "canonical_root",
            "repository_generation",
            "owner_uid",
        }:
            raise RepositoryOwnerAuthorityError(
                "repository owner map entry fields are invalid"
            )
        repository_id = item["repository_id"]
        generation = item["repository_generation"]
        owner_uid = item["owner_uid"]
        if (
            not isinstance(repository_id, str)
            or not repository_id
            or repository_id in seen
            or not isinstance(item["canonical_root"], str)
            or len(repository_id) > _MAX_IDENTITY_TEXT
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 0
            or isinstance(owner_uid, bool)
            or not isinstance(owner_uid, int)
            or owner_uid <= 0
        ):
            raise RepositoryOwnerAuthorityError(
                "repository owner map entry values are invalid"
            )
        seen.add(repository_id)
        _canonical_absolute_path(
            item["canonical_root"], label="repository owner map canonical_root"
        )
        normalized_rows.append(dict(item))
    normalized_rows.sort(key=lambda item: str(item["repository_id"]))
    public_rows = [
        {
            "repository_id": item["repository_id"],
            "canonical_root": item["canonical_root"],
            "repository_generation": item["repository_generation"],
        }
        for item in normalized_rows
    ]
    if public_rows != expected_rows:
        raise RepositoryOwnerAuthorityError(
            "repository owner map no longer covers the current repository authority"
        )
    return {
        **dict(document),
        "repository_execution_scope": execution_scope,
        "repositories": normalized_rows,
    }


def _validate_file_evidence(value: Any, *, label: str) -> dict[str, Any]:
    fields = {
        "path",
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "nlink",
        "size",
        "mtime_ns",
        "ctime_ns",
        "sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RepositoryOwnerAuthorityError(f"{label} file evidence is invalid")
    if (
        not isinstance(value["mode"], str)
        or _MODE_PATTERN.fullmatch(value["mode"]) is None
    ):
        raise RepositoryOwnerAuthorityError(f"{label} file evidence values are invalid")
    _canonical_absolute_path(value["path"], label=label)
    _sha256(value["sha256"], label=label)
    for field in (
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "nlink",
        "size",
        "mtime_ns",
        "ctime_ns",
    ):
        if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] < 0:
            raise RepositoryOwnerAuthorityError(
                f"{label} file evidence {field} is invalid"
            )
    if value["inode"] <= 0 or value["nlink"] != 1:
        raise RepositoryOwnerAuthorityError(f"{label} file identity is unsafe")
    return dict(value)


def validate_owner_migration_fence(
    connection: sqlite3.Connection,
    document: Mapping[str, Any],
    fence: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the already-verified first-adoption transaction binding."""

    fields = {
        "schema_version",
        "kind",
        "operation_id",
        "maintenance",
        "journal",
        "source_database",
        "candidate_database",
        "split_attestation",
        "broker",
        "fence_sha256",
    }
    if not isinstance(fence, dict) or set(fence) != fields:
        raise RepositoryOwnerAuthorityError("repository owner cutover fence fields are invalid")
    unsigned = dict(fence)
    unsigned.pop("fence_sha256")
    expected_fence_sha = "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()
    _sha256(fence.get("fence_sha256"), label="repository owner cutover fence")
    if (
        fence["schema_version"] != OWNER_MIGRATION_FENCE_SCHEMA_VERSION
        or fence["kind"] != OWNER_MIGRATION_FENCE_KIND
        or fence["fence_sha256"] != expected_fence_sha
        or fence["operation_id"] != document.get("operation_id")
    ):
        raise RepositoryOwnerAuthorityError("repository owner cutover fence is invalid")
    maintenance = fence["maintenance"]
    if not isinstance(maintenance, dict) or set(maintenance) != {
        "marker_path",
        "marker_sha256",
        "deployment_id",
        "active",
    } or maintenance.get("active") is not True or maintenance.get(
        "deployment_id"
    ) != document.get("operation_id"):
        raise RepositoryOwnerAuthorityError("repository owner maintenance fence is invalid")
    _canonical_absolute_path(
        maintenance["marker_path"], label="repository owner maintenance marker"
    )
    _sha256(
        maintenance["marker_sha256"], label="repository owner maintenance marker"
    )
    journal = fence["journal"]
    if not isinstance(journal, dict) or set(journal) != {
        "path",
        "sha256",
        "phase",
    } or journal.get("phase") != "storage_split_complete":
        raise RepositoryOwnerAuthorityError("repository owner adoption journal fence is invalid")
    _canonical_absolute_path(journal["path"], label="repository owner adoption journal")
    _sha256(journal["sha256"], label="repository owner adoption journal")
    split = fence["split_attestation"]
    if not isinstance(split, dict) or set(split) != {"path", "sha256"}:
        raise RepositoryOwnerAuthorityError("repository owner split attestation fence is invalid")
    _canonical_absolute_path(split["path"], label="repository owner split attestation")
    _sha256(split["sha256"], label="repository owner split attestation")
    broker = fence["broker"]
    if not isinstance(broker, dict) or set(broker) != {"active", "lock"} or broker.get(
        "active"
    ) is not False:
        raise RepositoryOwnerAuthorityError("repository owner broker-offline fence is invalid")
    lock = broker["lock"]
    if not isinstance(lock, dict) or set(lock) != {
        "path",
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "nlink",
        "held_exclusive",
    } or lock.get("held_exclusive") is not True or lock.get("nlink") != 1:
        raise RepositoryOwnerAuthorityError("repository owner broker lock fence is invalid")
    _canonical_absolute_path(lock["path"], label="repository owner broker lock")
    if not isinstance(lock["mode"], str) or _MODE_PATTERN.fullmatch(lock["mode"]) is None:
        raise RepositoryOwnerAuthorityError("repository owner broker lock mode is invalid")
    for field in ("device", "inode", "owner_uid", "owner_gid", "nlink"):
        if (
            isinstance(lock[field], bool)
            or not isinstance(lock[field], int)
            or lock[field] < 0
        ):
            raise RepositoryOwnerAuthorityError(
                f"repository owner broker lock {field} is invalid"
            )
    if lock["inode"] <= 0:
        raise RepositoryOwnerAuthorityError("repository owner broker lock identity is invalid")
    database_paths: set[str] = set()
    for label in ("source_database", "candidate_database"):
        bundle = fence[label]
        if not isinstance(bundle, dict) or set(bundle) != {"main", "sidecars"}:
            raise RepositoryOwnerAuthorityError(f"repository owner {label} fence is invalid")
        main_evidence = _validate_file_evidence(bundle["main"], label=f"{label} main")
        if main_evidence["path"] in database_paths:
            raise RepositoryOwnerAuthorityError(
                "repository owner source and candidate database paths must be distinct"
            )
        database_paths.add(str(main_evidence["path"]))
        if not isinstance(bundle["sidecars"], list):
            raise RepositoryOwnerAuthorityError(
                f"repository owner {label} sidecar fence is invalid"
            )
        paths: set[str] = {str(main_evidence["path"])}
        for index, sidecar in enumerate(bundle["sidecars"]):
            evidence = _validate_file_evidence(
                sidecar, label=f"{label} sidecar {index}"
            )
            if evidence["path"] in paths:
                raise RepositoryOwnerAuthorityError(
                    f"repository owner {label} duplicates sidecar evidence"
                )
            paths.add(str(evidence["path"]))
            if evidence["path"] in database_paths:
                raise RepositoryOwnerAuthorityError(
                    "repository owner database evidence paths overlap"
                )
            database_paths.add(str(evidence["path"]))
    candidate = _validate_file_evidence(
        fence["candidate_database"]["main"], label="candidate_database main"
    )
    database_rows = list(connection.execute("PRAGMA database_list"))
    main_rows = [row for row in database_rows if str(row[1]) == "main"]
    if len(main_rows) != 1 or str(Path(str(main_rows[0][2])).absolute()) != candidate["path"]:
        raise RepositoryOwnerAuthorityError(
            "repository owner cutover fence is bound to another candidate database"
        )
    info = Path(candidate["path"]).lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            f"{stat.S_IMODE(info.st_mode):04o}",
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        != (
            candidate["device"],
            candidate["inode"],
            candidate["owner_uid"],
            candidate["owner_gid"],
            candidate["mode"],
            candidate["nlink"],
            candidate["size"],
            candidate["mtime_ns"],
            candidate["ctime_ns"],
        )
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner candidate database identity changed before migration"
        )
    return dict(fence)


def apply_owner_map(
    connection: sqlite3.Connection,
    document: Mapping[str, Any],
    *,
    cutover_fence: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply a validated map inside the caller's exclusive transaction."""

    if not connection.in_transaction:
        raise RepositoryOwnerAuthorityError(
            "repository owner map apply requires an exclusive transaction"
        )
    validated = validate_owner_map(connection, document)
    validate_owner_migration_fence(connection, validated, cutover_fence)
    migrate_repository_owner_authority_v13(
        connection,
        assignments=validated["repositories"],
        execution_scope=validated["repository_execution_scope"],
        target_database_generation=str(validated["target_database_generation"]),
        operation_id=str(validated["operation_id"]),
        actor=str(validated["actor"]),
        evidence_sha256=str(validated["document_sha256"]),
        timestamp=str(validated["created_at"]),
    )
    metadata = _metadata(connection)
    owner_count = int(connection.execute("SELECT COUNT(*) FROM repository_owners").fetchone()[0])
    ledger_count = int(
        connection.execute("SELECT COUNT(*) FROM repository_owner_transfers").fetchone()[0]
    )
    repository_count = int(connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0])
    executable_repository_count = int(
        validated["repository_execution_scope"]["executable_repository_count"]
    )
    excluded_terminal_repository_count = int(
        validated["repository_execution_scope"][
            "excluded_terminal_repository_count"
        ]
    )
    foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
    if (
        metadata["schema_version"] != SCHEMA_VERSION
        or metadata["database_generation"]
        != validated["target_database_generation"]
        or owner_count != executable_repository_count
        or ledger_count != executable_repository_count
        or repository_count
        != executable_repository_count + excluded_terminal_repository_count
        or foreign_keys
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner authority verification failed before commit"
        )
    return {
        "status": "applied",
        "schema_version": SCHEMA_VERSION,
        "source_database_generation": validated["source_database_generation"],
        "target_database_generation": metadata["database_generation"],
        "state_revision": metadata["state_revision"],
        "repository_count": repository_count,
        "executable_repository_count": executable_repository_count,
        "excluded_terminal_repository_count": excluded_terminal_repository_count,
        "repository_execution_scope_sha256": validated[
            "repository_execution_scope"
        ]["document_sha256"],
        "owner_map_sha256": validated["document_sha256"],
        "operation_id": validated["operation_id"],
    }


def load_sealed_owner_map(path: Path, *, expected_owner_uid: int) -> dict[str, Any]:
    candidate = path.expanduser().absolute()
    if not candidate.is_absolute():
        raise RepositoryOwnerAuthorityError("repository owner map path must be absolute")
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_owner_uid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > MAX_OWNER_MAP_BYTES
    ):
        raise RepositoryOwnerAuthorityError(
            "repository owner map must be a private, regular file owned by the expected administrator"
        )
    descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        anchored = os.fstat(descriptor)
        if (anchored.st_dev, anchored.st_ino) != (info.st_dev, info.st_ino):
            raise RepositoryOwnerAuthorityError(
                "repository owner map identity changed while opening"
            )
        chunks: list[bytes] = []
        remaining = MAX_OWNER_MAP_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        before_identity = (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if after_identity != before_identity or len(payload) != info.st_size:
            raise RepositoryOwnerAuthorityError(
                "repository owner map changed while reading"
            )
    finally:
        os.close(descriptor)
    if len(payload) > MAX_OWNER_MAP_BYTES:
        raise RepositoryOwnerAuthorityError("repository owner map exceeds its bound")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepositoryOwnerAuthorityError("repository owner map JSON is invalid") from error
    if not isinstance(document, dict):
        raise RepositoryOwnerAuthorityError("repository owner map must be an object")
    return document


__all__ = [
    "OWNER_MAP_KIND",
    "OWNER_MAP_SCHEMA_VERSION",
    "OWNER_MIGRATION_FENCE_KIND",
    "OWNER_MIGRATION_FENCE_SCHEMA_VERSION",
    "RepositoryOwnerAuthorityError",
    "apply_owner_map",
    "load_sealed_owner_map",
    "prepare_owner_map",
    "repository_census",
    "utc_timestamp",
    "validate_owner_map",
    "validate_owner_migration_fence",
]
