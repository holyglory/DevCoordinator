"""Sealed schema-12 cleanup for a falsely enrolled shared temporary root.

This module is deliberately database-only.  Its caller must obtain the host
observation through the Coordinator, hold the authority/maintenance locks, and
open the write transaction.  The primitive never calls Docker, systemd, Git,
or the filesystem.  It accepts only the exact latest committed exhaustive
Docker snapshot and turns that positive absence into a retained, replayable
authority transition.

The contract is intentionally narrow: it repairs the known legacy ``/tmp``
repository whose 24 container projections partition into 23 absent resources
and one still-present resource.  Expanding those bounds is a different
operator-reviewed migration, not a runtime option.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

from .store import MAX_SQLITE_INTEGER, canonical_json, deterministic_id


SCHEMA_VERSION = 1
AUTHORITY_SCHEMA_VERSION = 12
PLAN_KIND = "devcoordinator-shared-root-positive-absence-plan"
RESULT_KIND = "devcoordinator-shared-root-positive-absence-result"
OBSERVER_DOMAIN = "host-runtime-v2:full-docker"
SHARED_ROOT = "/tmp"
ACTOR = "devcoordinator-shared-root-positive-absence"
REASON = "terminalize falsely enrolled shared root from positive Docker absence"

EXPECTED_MEMBERSHIP_COUNT = 24
EXPECTED_ABSENT_COUNT = 23
EXPECTED_PRESENT_COUNT = 1
EXPECTED_SOURCE_COUNT = 24
EXPECTED_CONTROL_BINDING_COUNT = 24
EXPECTED_STARTUP_POLICY_COUNT = 24
EXPECTED_PRESENT_DATABASE_BINDING_COUNT = 135
EXPECTED_ABSENT_DATABASE_BINDING_COUNT = 4
EXPECTED_DATABASE_BINDING_COUNT = (
    EXPECTED_PRESENT_DATABASE_BINDING_COUNT
    + EXPECTED_ABSENT_DATABASE_BINDING_COUNT
)

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_PREFIXED_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)

_PLAN_FIELDS = frozenset(
    {
        "plan_id",
        "operation_id",
        "actor",
        "reason",
        "authority",
        "repository",
        "observation",
        "absent_resources",
        "present_resources",
        "database_bindings",
        "ownership_claims",
        "acl_projection",
        "unassigned_projection",
        "target",
        "mutation_at",
    }
)

_RESULT_FIELDS = frozenset(
    {
        "plan_id",
        "operation_id",
        "plan_document_sha256",
        "authority_generation",
        "observation_snapshot_id",
        "repository_id",
        "repository_generation_before",
        "repository_generation_after",
        "installation_generation_before",
        "installation_generation_after",
        "state_revision_before",
        "state_revision_after",
        "absent_resource_count",
        "present_resource_count",
        "detached_database_binding_count",
        "repository_state",
        "installation_status",
        "startup_fenced",
        "actor",
        "reason",
        "applied_at",
    }
)

_REQUIRED_TABLE_COLUMNS: dict[str, frozenset[str]] = {
    "schema_metadata": frozenset(
        {
            "singleton",
            "schema_version",
            "database_generation",
            "state_revision",
            "migration_state",
            "updated_at",
        }
    ),
    "repositories": frozenset(
        {
            "repo_id",
            "host_id",
            "canonical_root",
            "display_name",
            "state",
            "generation",
            "updated_at",
        }
    ),
    "repository_installations": frozenset(
        {
            "repo_id",
            "status",
            "startup_fenced",
            "generation",
            "operation_id",
            "disabled_at",
            "reason",
            "actor",
            "updated_at",
        }
    ),
    "repository_memberships": frozenset(
        {
            "membership_id",
            "repo_id",
            "resource_kind",
            "host_resource_id",
            "immutable_fingerprint",
            "control_binding_id",
            "created_at",
        }
    ),
    "docker_resources": frozenset(
        {
            "docker_resource_id",
            "engine_id",
            "full_container_id",
            "current_name",
        }
    ),
    "docker_engines": frozenset({"engine_id", "host_id"}),
    "source_resources": frozenset(
        {
            "source_resource_id",
            "source_id",
            "resource_kind",
            "native_id",
            "repo_id",
            "payload_sha256",
        }
    ),
    "control_bindings": frozenset(
        {
            "binding_id",
            "repo_id",
            "source_resource_id",
            "resource_kind",
            "resource_id",
            "authority_state",
            "generation",
            "updated_at",
        }
    ),
    "startup_policies": frozenset(
        {
            "policy_id",
            "repo_id",
            "resource_kind",
            "resource_id",
            "current_value",
            "desired_disabled_value",
            "generation",
            "updated_at",
        }
    ),
    "startup_policy_restore_states": frozenset(
        {"policy_id", "repo_id", "resource_kind", "resource_id", "updated_at"}
    ),
    "database_bindings": frozenset(
        {
            "database_binding_id",
            "docker_resource_id",
            "repo_id",
            "updated_at",
        }
    ),
    "docker_ownership_claims": frozenset(
        {
            "claim_id",
            "docker_resource_id",
            "source_resource_id",
            "repo_id",
            "source_id",
            "provenance",
            "conflict_state",
            "updated_at",
        }
    ),
    "observation_snapshots": frozenset(
        {
            "snapshot_id",
            "host_id",
            "observer_domain",
            "status",
            "material_fingerprint",
            "started_at",
            "completed_at",
        }
    ),
    "observation_capabilities": frozenset(
        {
            "snapshot_id",
            "observer_domain",
            "docker_available",
            "capability_fingerprint",
            "committed_at",
        }
    ),
    "observation_snapshot_resources": frozenset(
        {
            "snapshot_id",
            "resource_kind",
            "resource_id",
            "observation_fingerprint",
        }
    ),
    "operations": frozenset(
        {
            "operation_id",
            "repo_id",
            "kind",
            "status",
            "phase",
            "generation",
            "request_fingerprint",
            "owner_uid",
            "actor",
            "result_json",
            "created_at",
            "updated_at",
        }
    ),
    "resource_retirements": frozenset(
        {
            "host_resource_id",
            "resource_kind",
            "immutable_fingerprint",
            "status",
            "operation_id",
            "reason",
            "actor",
            "started_at",
            "retired_at",
            "updated_at",
        }
    ),
    "resource_lifecycle_history": frozenset(
        {
            "history_id",
            "repo_id",
            "resource_kind",
            "resource_id",
            "immutable_fingerprint",
            "action",
            "operation_id",
            "actor",
            "reason",
            "evidence_json",
            "occurred_at",
        }
    ),
    "cleanup_tombstones": frozenset(
        {
            "target_kind",
            "target_id",
            "target_generation",
            "repo_id",
            "immutable_fingerprint",
            "operation_id",
            "actor",
            "reason",
            "evidence_json",
            "removed_at",
        }
    ),
    "broker_repository_materialization_revocations": frozenset(
        {
            "repo_id",
            "repository_generation",
            "broker_operation_id",
            "immutable_fingerprint",
            "broker_database_generation",
            "revoked_at",
        }
    ),
    "unassigned_resources": frozenset(
        {
            "unassigned_id",
            "host_id",
            "source_resource_id",
            "resource_kind",
            "resource_id",
            "display_name",
            "reason_code",
            "suggested_root",
            "status",
            "created_at",
            "updated_at",
        }
    ),
    "broker_repository_enrollments": frozenset({"repo_id", "enabled"}),
}

_ACL_TABLES = (
    "broker_resource_acl",
    "broker_ephemeral_acl",
    "broker_runtime_acl",
    "broker_worker_acl",
    "broker_assignment_acl",
    "broker_database_acl",
    "broker_lifecycle_resource_acl",
    "broker_cleanup_resource_acl",
    "broker_compose_acl",
    "broker_lifecycle_acl",
    "broker_cleanup_acl",
    "broker_repository_read_acl",
    "broker_host_observation_acl",
    "broker_port_policies",
)

_PENDING_LIFECYCLE = (
    ("operations", "status IN ('planned','running','partial','needs_attention')"),
    (
        "runtime_sessions",
        "status IN ('planned','running','cleanup_pending','cleaning')",
    ),
    (
        "broker_lease_links",
        "status IN ('reserved','release_pending','rollback_failed','reconciliation_required')",
    ),
    (
        "broker_assignment_links",
        "status IN ('reserved','release_pending','rollback_failed','reconciliation_required')",
    ),
    (
        "broker_reconciliation_queue",
        "status IN ('pending','operator_required')",
    ),
    (
        "broker_lifecycle_links",
        "status IN ('pending','reconciliation_required','operator_required')",
    ),
    ("cleanup_plans", "status IN ('planned','running','needs_attention')"),
    ("ephemeral_container_runs", "status NOT IN ('cleaned','failed')"),
)

_MUST_BE_EMPTY_REPO_TABLES = (
    "server_definitions",
    "worker_policies",
    "ephemeral_container_templates",
    "broker_compose_definitions",
    "leases",
    "port_assignments",
)


class SharedRootPositiveAbsenceError(RuntimeError):
    """The sealed cleanup contract is unavailable, stale, or contradictory."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SharedRootPositiveAbsenceError(
            "positive-absence evidence is not canonical JSON"
        ) from error


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _seal(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {"schema_version": SCHEMA_VERSION, "kind": kind, **dict(values)}
    if "document_sha256" in document:
        raise SharedRootPositiveAbsenceError("reserved evidence digest field")
    document["document_sha256"] = _digest(document)
    return document


def _verify_seal(
    value: object, *, kind: str, fields: frozenset[str]
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise SharedRootPositiveAbsenceError(f"{kind} evidence must be an object")
    expected = {"schema_version", "kind", "document_sha256", *fields}
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    digest = value.get("document_sha256")
    if (
        set(value) != expected
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("kind") != kind
        or not isinstance(digest, str)
        or _HEX_SHA256.fullmatch(digest) is None
        or _digest(unsigned) != digest
    ):
        raise SharedRootPositiveAbsenceError(f"{kind} evidence is invalid")
    return dict(value)


def _canonical_uuid(value: object, field: str) -> str:
    try:
        normalized = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as error:
        raise SharedRootPositiveAbsenceError(f"{field} is invalid") from error
    if normalized != value:
        raise SharedRootPositiveAbsenceError(f"{field} is not canonical")
    return normalized


def _safe_text(value: object, field: str, *, limit: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > limit
        or any(character in value for character in "\x00\r\n")
    ):
        raise SharedRootPositiveAbsenceError(f"{field} is invalid")
    return value


def _parsed_timestamp(value: object, field: str) -> tuple[str, datetime]:
    text = _safe_text(value, field, limit=128)
    if _UTC_TIMESTAMP.fullmatch(text) is None:
        raise SharedRootPositiveAbsenceError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise SharedRootPositiveAbsenceError(f"{field} is invalid") from error
    if parsed.tzinfo is None:
        raise SharedRootPositiveAbsenceError(f"{field} is invalid")
    return text, parsed.astimezone(timezone.utc)


def _later_authority_timestamp(current: object, planned: object) -> str:
    current_text, current_time = _parsed_timestamp(
        current, "positive-absence current authority timestamp"
    )
    planned_text, planned_time = _parsed_timestamp(
        planned, "positive-absence planned authority timestamp"
    )
    return current_text if current_time >= planned_time else planned_text


def _table_columns(connection: sqlite3.Connection, table: str) -> frozenset[str]:
    if re.fullmatch(r"[a-z][a-z0-9_]*", table) is None:
        raise SharedRootPositiveAbsenceError("schema table name is invalid")
    return frozenset(
        str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
    )


def _require_schema12(connection: sqlite3.Connection) -> dict[str, object]:
    if connection.row_factory is not sqlite3.Row:
        raise SharedRootPositiveAbsenceError(
            "positive-absence core requires sqlite3.Row row_factory"
        )
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    if foreign_keys is None or int(foreign_keys[0]) != 1:
        raise SharedRootPositiveAbsenceError(
            "positive-absence core requires foreign key enforcement"
        )
    for table, required in _REQUIRED_TABLE_COLUMNS.items():
        columns = _table_columns(connection, table)
        if not required.issubset(columns):
            raise SharedRootPositiveAbsenceError(
                f"schema-12 positive-absence contract for {table} is unavailable"
            )
    if _table_columns(connection, "repository_owners") or _table_columns(
        connection, "repository_owner_transfers"
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence core is schema-12 only"
        )
    row = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               migration_state, updated_at
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    if (
        row is None
        or int(row["schema_version"]) != AUTHORITY_SCHEMA_VERSION
        or str(row["migration_state"]) != "ready"
        or not str(row["database_generation"])
        or int(row["state_revision"]) < 0
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence core requires ready schema-12 authority"
        )
    return {
        "schema_version": int(row["schema_version"]),
        "database_generation": str(row["database_generation"]),
        "state_revision": int(row["state_revision"]),
        "migration_state": str(row["migration_state"]),
        "updated_at": str(row["updated_at"]),
    }


def _normalized_row(row: sqlite3.Row) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in row.keys():
        value = row[key]
        if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int))):
            raise SharedRootPositiveAbsenceError(
                "positive-absence row contains an unsafe SQLite value"
            )
        result[str(key)] = value
    return result


def _rows(
    connection: sqlite3.Connection,
    statement: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> list[dict[str, object]]:
    raw = connection.execute(statement, parameters).fetchall()
    if len(raw) > limit:
        raise SharedRootPositiveAbsenceError(
            "positive-absence row set exceeds its sealed bound"
        )
    return [_normalized_row(row) for row in raw]


def _normalize_observation_evidence(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise SharedRootPositiveAbsenceError("host observation evidence is invalid")
    required = {
        "snapshot_id",
        "host_id",
        "observer_domain",
        "docker_available",
        "material_fingerprint",
        "started_at",
        "completed_at",
        "capability_fingerprint",
        "capability_committed_at",
    }
    if not required.issubset(value):
        raise SharedRootPositiveAbsenceError("host observation evidence is incomplete")
    normalized = {field: value[field] for field in sorted(required)}
    if (
        normalized["observer_domain"] != OBSERVER_DOMAIN
        or normalized["docker_available"] is not True
        or _HEX_SHA256.fullmatch(str(normalized["material_fingerprint"])) is None
        or _PREFIXED_SHA256.fullmatch(str(normalized["capability_fingerprint"]))
        is None
    ):
        raise SharedRootPositiveAbsenceError(
            "host observation is not exhaustive full-Docker evidence"
        )
    for field in (
        "snapshot_id",
        "host_id",
        "started_at",
        "completed_at",
        "capability_committed_at",
    ):
        _safe_text(normalized[field], f"observation {field}")
    return normalized


def _latest_full_docker_observation(
    connection: sqlite3.Connection, *, host_id: str
) -> dict[str, object]:
    row = connection.execute(
        """
        WITH latest AS (
            SELECT snapshot.snapshot_id
            FROM observation_snapshots snapshot
            JOIN observation_capabilities capability USING(snapshot_id)
            WHERE snapshot.host_id = ?
              AND snapshot.status = 'completed'
              AND snapshot.completed_at IS NOT NULL
              AND snapshot.observer_domain = ?
              AND capability.observer_domain = snapshot.observer_domain
              AND capability.docker_available = 1
            ORDER BY snapshot.completed_at DESC, snapshot.snapshot_id DESC
            LIMIT 1
        )
        SELECT snapshot.snapshot_id, snapshot.host_id,
               snapshot.observer_domain, capability.docker_available,
               snapshot.material_fingerprint, snapshot.started_at,
               snapshot.completed_at, capability.capability_fingerprint,
               capability.committed_at AS capability_committed_at
        FROM latest
        JOIN observation_snapshots snapshot USING(snapshot_id)
        JOIN observation_capabilities capability USING(snapshot_id)
        """,
        (host_id, OBSERVER_DOMAIN),
    ).fetchone()
    if row is None:
        raise SharedRootPositiveAbsenceError(
            "latest completed full-Docker observation is unavailable"
        )
    evidence = _normalized_row(row)
    evidence["docker_available"] = bool(evidence["docker_available"])
    return _normalize_observation_evidence(evidence)


def latest_shared_root_full_docker_observation(
    connection: sqlite3.Connection, *, repository_id: str
) -> dict[str, object]:
    """Read the latest exhaustive Docker evidence for the exact shared root.

    The production cutover wrapper uses this read-only helper to obtain the
    evidence supplied to :func:`plan_shared_root_positive_absence`.  Planning
    revalidates the same evidence inside its own stable read transaction, so a
    newer observation published between these two reads fails closed.
    """

    _safe_text(repository_id, "repository ID", limit=256)
    if connection.in_transaction:
        raise SharedRootPositiveAbsenceError(
            "full-Docker evidence read requires no active transaction"
        )
    connection.execute("BEGIN")
    try:
        _require_schema12(connection)
        repository = _repository_snapshot(connection, repository_id)
        evidence = _latest_full_docker_observation(
            connection, host_id=str(repository["host_id"])
        )
        connection.execute("ROLLBACK")
    except BaseException:
        connection.rollback()
        raise
    return evidence


def _retained_full_docker_observation(
    connection: sqlite3.Connection, *, snapshot_id: str, host_id: str
) -> dict[str, object]:
    row = connection.execute(
        """
        SELECT snapshot.snapshot_id, snapshot.host_id,
               snapshot.observer_domain, capability.docker_available,
               snapshot.material_fingerprint, snapshot.started_at,
               snapshot.completed_at, capability.capability_fingerprint,
               capability.committed_at AS capability_committed_at
        FROM observation_snapshots snapshot
        JOIN observation_capabilities capability USING(snapshot_id)
        WHERE snapshot.snapshot_id = ? AND snapshot.host_id = ?
          AND snapshot.status = 'completed'
          AND snapshot.completed_at IS NOT NULL
          AND snapshot.observer_domain = ?
          AND capability.observer_domain = snapshot.observer_domain
          AND capability.docker_available = 1
        """,
        (snapshot_id, host_id, OBSERVER_DOMAIN),
    ).fetchone()
    if row is None:
        raise SharedRootPositiveAbsenceError(
            "retained full-Docker observation evidence is unavailable"
        )
    evidence = _normalized_row(row)
    evidence["docker_available"] = bool(evidence["docker_available"])
    return _normalize_observation_evidence(evidence)


def _require_exact_observation(
    connection: sqlite3.Connection,
    *,
    host_id: str,
    observation_evidence: object,
) -> dict[str, object]:
    supplied = _normalize_observation_evidence(observation_evidence)
    latest = _latest_full_docker_observation(connection, host_id=host_id)
    if supplied != latest:
        raise SharedRootPositiveAbsenceError(
            "host observation is not the exact latest committed full-Docker snapshot"
        )
    return latest


def _repository_snapshot(
    connection: sqlite3.Connection, repository_id: str
) -> dict[str, object]:
    row = connection.execute(
        """
        SELECT repository.repo_id AS repository_id, repository.host_id,
               repository.canonical_root, repository.display_name,
               repository.state, repository.generation,
               repository.updated_at AS repository_updated_at,
               installation.status AS installation_status,
               installation.startup_fenced,
               installation.generation AS installation_generation,
               installation.operation_id AS installation_operation_id,
               installation.disabled_at, installation.reason,
               installation.actor AS installation_actor,
               installation.updated_at AS installation_updated_at
        FROM repositories repository
        JOIN repository_installations installation USING(repo_id)
        WHERE repository.repo_id = ?
        """,
        (repository_id,),
    ).fetchone()
    if row is None:
        raise SharedRootPositiveAbsenceError("shared-root repository is unavailable")
    result = _normalized_row(row)
    if (
        result["canonical_root"] != SHARED_ROOT
        or result["state"] != "active"
        or result["installation_status"] != "installed"
        or int(result["startup_fenced"]) != 0
        or result["installation_operation_id"] is not None
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root repository is not the exact recovered active installation"
        )
    result["startup_fenced"] = False
    return result


def _reject_pending_lifecycle(
    connection: sqlite3.Connection, repository_id: str
) -> None:
    for table, predicate in _PENDING_LIFECYCLE:
        columns = _table_columns(connection, table)
        if not {"repo_id", "status"}.issubset(columns):
            raise SharedRootPositiveAbsenceError(
                f"pending lifecycle contract for {table} is unavailable"
            )
        count = connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ? AND ({predicate})",
            (repository_id,),
        ).fetchone()
        if count is None or int(count[0]) != 0:
            raise SharedRootPositiveAbsenceError(
                f"shared-root repository has pending lifecycle rows in {table}"
            )
    for table in _MUST_BE_EMPTY_REPO_TABLES:
        columns = _table_columns(connection, table)
        if "repo_id" not in columns:
            raise SharedRootPositiveAbsenceError(
                f"terminal repository contract for {table} is unavailable"
            )
        count = connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ?", (repository_id,)
        ).fetchone()
        if count is None or int(count[0]) != 0:
            raise SharedRootPositiveAbsenceError(
                f"shared-root repository retains executable rows in {table}"
            )


def _acl_projection(
    connection: sqlite3.Connection, repository_id: str
) -> dict[str, object]:
    projection: dict[str, object] = {}
    for table in _ACL_TABLES:
        columns = _table_columns(connection, table)
        if not {"repo_id", "enabled"}.issubset(columns):
            raise SharedRootPositiveAbsenceError(
                f"ACL projection contract for {table} is unavailable"
            )
        rows = _rows(
            connection,
            f"SELECT * FROM {table} WHERE repo_id = ? ORDER BY rowid",
            (repository_id,),
            limit=4096,
        )
        projection[table] = {"count": len(rows), "rows_sha256": _digest(rows)}
    return {"tables": projection, "document_sha256": _digest(projection)}


def _resource_snapshot(
    connection: sqlite3.Connection,
    *,
    repository: Mapping[str, object],
    observation: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    repository_id = str(repository["repository_id"])
    memberships = _rows(
        connection,
        """
        SELECT * FROM repository_memberships
        WHERE repo_id = ? ORDER BY resource_kind, host_resource_id
        """,
        (repository_id,),
        limit=EXPECTED_MEMBERSHIP_COUNT + 1,
    )
    if (
        len(memberships) != EXPECTED_MEMBERSHIP_COUNT
        or any(row["resource_kind"] != "container" for row in memberships)
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root membership census is not exactly 24 containers"
        )
    records: list[dict[str, object]] = []
    binding_ids: set[str] = set()
    source_ids: set[str] = set()
    policy_ids: set[str] = set()
    for membership in memberships:
        resource_id = str(membership["host_resource_id"])
        docker = connection.execute(
            """
            SELECT resource.*, engine.host_id AS engine_host_id
            FROM docker_resources resource
            JOIN docker_engines engine USING(engine_id)
            WHERE resource.docker_resource_id = ?
            """,
            (resource_id,),
        ).fetchone()
        binding = connection.execute(
            "SELECT * FROM control_bindings WHERE binding_id = ?",
            (membership["control_binding_id"],),
        ).fetchone()
        if docker is None or binding is None:
            raise SharedRootPositiveAbsenceError(
                "shared-root membership lost its exact Docker/control identity"
            )
        docker_document = _normalized_row(docker)
        binding_document = _normalized_row(binding)
        if (
            docker_document["engine_host_id"] != repository["host_id"]
            or binding_document["repo_id"] != repository_id
            or binding_document["resource_kind"] != "container"
            or binding_document["resource_id"] != resource_id
            or binding_document["authority_state"] != "authoritative"
            or binding_document["source_resource_id"] is None
        ):
            raise SharedRootPositiveAbsenceError(
                "shared-root Docker/control ownership is contradictory"
            )
        source = connection.execute(
            "SELECT * FROM source_resources WHERE source_resource_id = ?",
            (binding_document["source_resource_id"],),
        ).fetchone()
        policies = connection.execute(
            """
            SELECT * FROM startup_policies
            WHERE repo_id = ? AND resource_kind = 'container' AND resource_id = ?
            ORDER BY policy_id
            """,
            (repository_id, resource_id),
        ).fetchall()
        if source is None or len(policies) != 1:
            raise SharedRootPositiveAbsenceError(
                "shared-root resource projection is incomplete"
            )
        source_document = _normalized_row(source)
        policy_document = _normalized_row(policies[0])
        if (
            source_document["repo_id"] != repository_id
            or source_document["resource_kind"] != "container"
            or source_document["native_id"] != docker_document["full_container_id"]
        ):
            raise SharedRootPositiveAbsenceError(
                "shared-root source projection is contradictory"
            )
        restore = connection.execute(
            "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
            (policy_document["policy_id"],),
        ).fetchone()
        restore_document = None if restore is None else _normalized_row(restore)
        if restore_document is not None and restore_document["repo_id"] != repository_id:
            raise SharedRootPositiveAbsenceError(
                "shared-root startup restore projection is contradictory"
            )
        observation_row = connection.execute(
            """
            SELECT observation_fingerprint
            FROM observation_snapshot_resources
            WHERE snapshot_id = ? AND resource_kind = 'container'
              AND resource_id = ?
            """,
            (observation["snapshot_id"], resource_id),
        ).fetchone()
        record = {
            "membership": membership,
            "docker": docker_document,
            "control_binding": binding_document,
            "source_resource": source_document,
            "startup_policy": policy_document,
            "startup_restore_state": restore_document,
            "observation_fingerprint": (
                None if observation_row is None else str(observation_row[0])
            ),
        }
        records.append(record)
        binding_ids.add(str(binding_document["binding_id"]))
        source_ids.add(str(source_document["source_resource_id"]))
        policy_ids.add(str(policy_document["policy_id"]))
    direct_bindings = connection.execute(
        "SELECT COUNT(*) FROM control_bindings WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()
    direct_sources = connection.execute(
        "SELECT COUNT(*) FROM source_resources WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()
    direct_policies = connection.execute(
        "SELECT COUNT(*) FROM startup_policies WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()
    direct_restore_rows = connection.execute(
        "SELECT policy_id FROM startup_policy_restore_states WHERE repo_id = ?",
        (repository_id,),
    ).fetchall()
    restore_ids = {
        str(record["startup_restore_state"]["policy_id"])
        for record in records
        if record["startup_restore_state"] is not None
    }
    if (
        len(binding_ids) != EXPECTED_CONTROL_BINDING_COUNT
        or len(source_ids) != EXPECTED_SOURCE_COUNT
        or len(policy_ids) != EXPECTED_STARTUP_POLICY_COUNT
        or direct_bindings is None
        or int(direct_bindings[0]) != EXPECTED_CONTROL_BINDING_COUNT
        or direct_sources is None
        or int(direct_sources[0]) != EXPECTED_SOURCE_COUNT
        or direct_policies is None
        or int(direct_policies[0]) != EXPECTED_STARTUP_POLICY_COUNT
        or {str(row[0]) for row in direct_restore_rows} != restore_ids
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root projection census changed"
        )
    absent = sorted(
        (record for record in records if record["observation_fingerprint"] is None),
        key=lambda record: str(record["membership"]["host_resource_id"]),
    )
    present = sorted(
        (record for record in records if record["observation_fingerprint"] is not None),
        key=lambda record: str(record["membership"]["host_resource_id"]),
    )
    if len(absent) != EXPECTED_ABSENT_COUNT or len(present) != EXPECTED_PRESENT_COUNT:
        raise SharedRootPositiveAbsenceError(
            "full-Docker snapshot does not prove the exact 23 absent / 1 present partition"
        )
    return absent, present


def _database_binding_snapshot(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    absent_resource_ids: set[str],
    present_resource_ids: set[str],
) -> list[dict[str, object]]:
    rows = _rows(
        connection,
        """
        SELECT * FROM database_bindings
        WHERE repo_id = ? ORDER BY database_binding_id
        """,
        (repository_id,),
        limit=EXPECTED_DATABASE_BINDING_COUNT + 1,
    )
    resource_ids = absent_resource_ids | present_resource_ids
    absent_count = sum(
        str(row["docker_resource_id"]) in absent_resource_ids for row in rows
    )
    present_count = sum(
        str(row["docker_resource_id"]) in present_resource_ids for row in rows
    )
    if (
        absent_resource_ids & present_resource_ids
        or len(rows) != EXPECTED_DATABASE_BINDING_COUNT
        or absent_count != EXPECTED_ABSENT_DATABASE_BINDING_COUNT
        or present_count != EXPECTED_PRESENT_DATABASE_BINDING_COUNT
        or any(str(row["docker_resource_id"]) not in resource_ids for row in rows)
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root database binding census is not exactly 135 present and "
            "4 absent retained bindings"
        )
    return rows


def _ownership_claim_snapshot(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    resource_ids: set[str],
) -> list[dict[str, object]]:
    rows = _rows(
        connection,
        """
        SELECT * FROM docker_ownership_claims
        WHERE repo_id = ? ORDER BY claim_id
        """,
        (repository_id,),
        limit=512,
    )
    if any(
        row["docker_resource_id"] is None
        or str(row["docker_resource_id"]) not in resource_ids
        for row in rows
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root ownership claim references an unrelated Docker resource"
        )
    return rows


def _unassigned_projection(
    connection: sqlite3.Connection, resource_ids: set[str]
) -> dict[str, object]:
    if not resource_ids:
        raise SharedRootPositiveAbsenceError("resource partition is empty")
    placeholders = ",".join("?" for _ in resource_ids)
    rows = _rows(
        connection,
        f"""
        SELECT * FROM unassigned_resources
        WHERE resource_kind = 'container' AND resource_id IN ({placeholders})
        ORDER BY resource_id, reason_code, unassigned_id
        """,
        tuple(sorted(resource_ids)),
        limit=512,
    )
    return {"count": len(rows), "rows_sha256": _digest(rows)}


def _require_no_existing_terminal_evidence(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    repository_generation: int,
    resource_ids: set[str],
    operation_id: str,
) -> None:
    if connection.execute(
        "SELECT 1 FROM operations WHERE operation_id = ?", (operation_id,)
    ).fetchone() is not None:
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation identity already exists"
        )
    placeholders = ",".join("?" for _ in resource_ids)
    checks = (
        (
            "SELECT COUNT(*) FROM resource_retirements "
            "WHERE resource_kind = 'container' "
            f"AND host_resource_id IN ({placeholders})",
            tuple(sorted(resource_ids)),
        ),
        (
            "SELECT COUNT(*) FROM cleanup_tombstones "
            "WHERE target_kind = 'container' "
            f"AND target_id IN ({placeholders})",
            tuple(sorted(resource_ids)),
        ),
        (
            "SELECT COUNT(*) FROM cleanup_tombstones "
            "WHERE target_kind = 'project' AND target_id = ? "
            "AND target_generation = ?",
            (repository_id, repository_generation),
        ),
        (
            "SELECT COUNT(*) "
            "FROM broker_repository_materialization_revocations "
            "WHERE repo_id = ? AND repository_generation = ?",
            (repository_id, repository_generation),
        ),
    )
    if any(int(connection.execute(sql, params).fetchone()[0]) != 0 for sql, params in checks):
        raise SharedRootPositiveAbsenceError(
            "shared-root terminal evidence already exists under another operation"
        )


def _initial_snapshot(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    operation_id: str,
    observation_evidence: object,
) -> dict[str, object]:
    authority = _require_schema12(connection)
    repository = _repository_snapshot(connection, repository_id)
    observation = _require_exact_observation(
        connection,
        host_id=str(repository["host_id"]),
        observation_evidence=observation_evidence,
    )
    _reject_pending_lifecycle(connection, repository_id)
    enrollment_count = connection.execute(
        "SELECT COUNT(*) FROM broker_repository_enrollments WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()
    if enrollment_count is None or int(enrollment_count[0]) != 0:
        raise SharedRootPositiveAbsenceError(
            "shared-root repository still has broker enrollments"
        )
    absent, present = _resource_snapshot(
        connection, repository=repository, observation=observation
    )
    absent_resource_ids = {
        str(record["membership"]["host_resource_id"])
        for record in absent
    }
    present_resource_ids = {
        str(record["membership"]["host_resource_id"])
        for record in present
    }
    resource_ids = {
        str(record["membership"]["host_resource_id"])
        for record in [*absent, *present]
    }
    database_bindings = _database_binding_snapshot(
        connection,
        repository_id=repository_id,
        absent_resource_ids=absent_resource_ids,
        present_resource_ids=present_resource_ids,
    )
    ownership_claims = _ownership_claim_snapshot(
        connection, repository_id=repository_id, resource_ids=resource_ids
    )
    _require_no_existing_terminal_evidence(
        connection,
        repository_id=repository_id,
        repository_generation=int(repository["generation"]),
        resource_ids=resource_ids,
        operation_id=operation_id,
    )
    return {
        "authority": authority,
        "repository": repository,
        "observation": observation,
        "absent_resources": absent,
        "present_resources": present,
        "database_bindings": database_bindings,
        "ownership_claims": ownership_claims,
        "acl_projection": _acl_projection(connection, repository_id),
        "unassigned_projection": _unassigned_projection(connection, resource_ids),
    }


def _repository_fingerprint(repository: Mapping[str, object]) -> str:
    return "sha256:" + _digest(
        {
            "repository_id": repository["repository_id"],
            "host_id": repository["host_id"],
            "canonical_root": repository["canonical_root"],
            "generation": repository["generation"],
            "state": repository["state"],
        }
    )


def _validate_plan(value: object) -> dict[str, object]:
    plan = _verify_seal(value, kind=PLAN_KIND, fields=_PLAN_FIELDS)
    _canonical_uuid(plan["plan_id"], "positive-absence plan ID")
    _canonical_uuid(plan["operation_id"], "positive-absence operation ID")
    _safe_text(plan["actor"], "positive-absence actor", limit=256)
    _safe_text(plan["reason"], "positive-absence reason", limit=1024)
    _safe_text(plan["mutation_at"], "positive-absence mutation timestamp", limit=128)
    authority = plan["authority"]
    repository = plan["repository"]
    target = plan["target"]
    if (
        not isinstance(authority, Mapping)
        or set(authority)
        != {
            "schema_version",
            "database_generation",
            "state_revision",
            "migration_state",
            "updated_at",
        }
        or authority["schema_version"] != AUTHORITY_SCHEMA_VERSION
        or authority["migration_state"] != "ready"
        or not isinstance(repository, Mapping)
        or repository.get("canonical_root") != SHARED_ROOT
        or repository.get("state") != "active"
        or repository.get("installation_status") != "installed"
        or repository.get("startup_fenced") is not False
        or not isinstance(plan["absent_resources"], list)
        or len(plan["absent_resources"]) != EXPECTED_ABSENT_COUNT
        or not isinstance(plan["present_resources"], list)
        or len(plan["present_resources"]) != EXPECTED_PRESENT_COUNT
        or not isinstance(plan["database_bindings"], list)
        or len(plan["database_bindings"]) != EXPECTED_DATABASE_BINDING_COUNT
        or not isinstance(plan["ownership_claims"], list)
        or not isinstance(plan["acl_projection"], Mapping)
        or not isinstance(plan["unassigned_projection"], Mapping)
        or not isinstance(target, Mapping)
        or dict(target)
        != {
            "repository_state": "missing",
            "repository_generation": int(repository["generation"]) + 1,
            "installation_status": "disabled",
            "startup_fenced": True,
            "installation_generation": int(repository["installation_generation"])
            + 1,
            "state_revision": int(authority["state_revision"]) + 1,
            "repository_fingerprint": _repository_fingerprint(repository),
        }
    ):
        raise SharedRootPositiveAbsenceError("positive-absence plan contract is invalid")
    _normalize_observation_evidence(plan["observation"])
    absent_ids = [
        str(record["membership"]["host_resource_id"])
        for record in plan["absent_resources"]
        if isinstance(record, Mapping)
        and isinstance(record.get("membership"), Mapping)
    ]
    present_ids = [
        str(record["membership"]["host_resource_id"])
        for record in plan["present_resources"]
        if isinstance(record, Mapping)
        and isinstance(record.get("membership"), Mapping)
    ]
    resource_ids = [*absent_ids, *present_ids]
    if (
        len(resource_ids) != EXPECTED_MEMBERSHIP_COUNT
        or absent_ids != sorted(absent_ids)
        or present_ids != sorted(present_ids)
        or len(set(resource_ids)) != EXPECTED_MEMBERSHIP_COUNT
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence resource partition is invalid"
        )
    if any(
        record.get("observation_fingerprint") is not None
        for record in plan["absent_resources"]
    ) or any(
        record.get("observation_fingerprint") is None
        for record in plan["present_resources"]
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence resource presence proof is invalid"
        )
    claim_ids = [
        str(claim["claim_id"])
        for claim in plan["ownership_claims"]
        if isinstance(claim, Mapping) and "claim_id" in claim
    ]
    if (
        len(claim_ids) != len(plan["ownership_claims"])
        or claim_ids != sorted(claim_ids)
        or len(set(claim_ids)) != len(claim_ids)
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence ownership claim projection is invalid"
        )
    return plan


def plan_shared_root_positive_absence(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    operation_id: str,
    observation_evidence: Mapping[str, object],
    created_at: str,
    actor: str = ACTOR,
) -> dict[str, object]:
    """Return a sealed, no-write plan for the exact legacy shared-root census."""

    _safe_text(repository_id, "repository ID", limit=256)
    operation_id = _canonical_uuid(operation_id, "positive-absence operation ID")
    actor = _safe_text(actor, "positive-absence actor", limit=256)
    created_at = _safe_text(created_at, "positive-absence creation timestamp", limit=128)
    if connection.in_transaction:
        raise SharedRootPositiveAbsenceError(
            "positive-absence planning requires a caller-owned stable read "
            "boundary, not an active transaction"
        )
    connection.execute("BEGIN")
    try:
        snapshot = _initial_snapshot(
            connection,
            repository_id=repository_id,
            operation_id=operation_id,
            observation_evidence=observation_evidence,
        )
        connection.execute("ROLLBACK")
    except BaseException:
        connection.rollback()
        raise
    plan = _seal(
        PLAN_KIND,
        {
            "plan_id": str(uuid.uuid4()),
            "operation_id": operation_id,
            "actor": actor,
            "reason": REASON,
            **snapshot,
            "target": {
                "repository_state": "missing",
                "repository_generation": int(snapshot["repository"]["generation"])
                + 1,
                "installation_status": "disabled",
                "startup_fenced": True,
                "installation_generation": int(
                    snapshot["repository"]["installation_generation"]
                )
                + 1,
                "state_revision": int(snapshot["authority"]["state_revision"]) + 1,
                "repository_fingerprint": _repository_fingerprint(
                    snapshot["repository"]
                ),
            },
            "mutation_at": created_at,
        },
    )
    return _validate_plan(plan)


def _exact_initial_matches(
    connection: sqlite3.Connection, plan: Mapping[str, object]
) -> bool:
    try:
        current = _initial_snapshot(
            connection,
            repository_id=str(plan["repository"]["repository_id"]),
            operation_id=str(plan["operation_id"]),
            observation_evidence=plan["observation"],
        )
    except SharedRootPositiveAbsenceError:
        return False
    current_authority = dict(current["authority"])
    planned_authority = dict(plan["authority"])
    current_revision = current_authority.pop("state_revision", None)
    planned_revision = planned_authority.pop("state_revision", None)
    current_updated_at = current_authority.pop("updated_at", None)
    planned_updated_at = planned_authority.pop("updated_at", None)
    if (
        isinstance(current_revision, bool)
        or not isinstance(current_revision, int)
        or isinstance(planned_revision, bool)
        or not isinstance(planned_revision, int)
        or current_revision < planned_revision
        or current_revision > MAX_SQLITE_INTEGER - 1
        or current_authority != planned_authority
    ):
        return False
    try:
        current_updated_text, current_updated_time = _parsed_timestamp(
            current_updated_at, "positive-absence current authority timestamp"
        )
        planned_updated_text, planned_updated_time = _parsed_timestamp(
            planned_updated_at, "positive-absence planned authority timestamp"
        )
    except SharedRootPositiveAbsenceError:
        return False
    if (
        current_revision == planned_revision
        and current_updated_text != planned_updated_text
    ) or (
        current_revision > planned_revision
        and current_updated_time < planned_updated_time
    ):
        return False
    return all(
        current[field] == plan[field]
        for field in current
        if field != "authority"
    )


def _operation_result_payload(
    plan: Mapping[str, object],
    *,
    state_revision_before: int,
    authority_updated_at_before: str,
    authority_updated_at_after: str,
) -> dict[str, object]:
    return {
        "kind": RESULT_KIND,
        "plan_id": plan["plan_id"],
        "plan_document_sha256": plan["document_sha256"],
        "repository_id": plan["repository"]["repository_id"],
        "observation_snapshot_id": plan["observation"]["snapshot_id"],
        "state_revision_before": state_revision_before,
        "state_revision_after": state_revision_before + 1,
        "authority_updated_at_before": authority_updated_at_before,
        "authority_updated_at_after": authority_updated_at_after,
    }


def _validated_operation_result_payload(
    value: object, plan: Mapping[str, object]
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation revision evidence is invalid"
        )
    payload = dict(value)
    expected_fields = {
        "kind",
        "plan_id",
        "plan_document_sha256",
        "repository_id",
        "observation_snapshot_id",
        "state_revision_before",
        "state_revision_after",
        "authority_updated_at_before",
        "authority_updated_at_after",
    }
    if set(payload) != expected_fields:
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation revision evidence is invalid"
        )
    expected_static = {
        "kind": RESULT_KIND,
        "plan_id": plan["plan_id"],
        "plan_document_sha256": plan["document_sha256"],
        "repository_id": plan["repository"]["repository_id"],
        "observation_snapshot_id": plan["observation"]["snapshot_id"],
    }
    if any(payload[field] != expected for field, expected in expected_static.items()):
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation revision evidence is invalid"
        )
    revision_before = payload["state_revision_before"]
    revision_after = payload["state_revision_after"]
    if (
        isinstance(revision_before, bool)
        or not isinstance(revision_before, int)
        or isinstance(revision_after, bool)
        or not isinstance(revision_after, int)
        or revision_before < int(plan["authority"]["state_revision"])
        or revision_before > MAX_SQLITE_INTEGER - 1
        or revision_after != revision_before + 1
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation revision evidence is invalid"
        )
    _parsed_timestamp(
        payload["authority_updated_at_before"],
        "positive-absence authority timestamp before mutation",
    )
    _parsed_timestamp(
        payload["authority_updated_at_after"],
        "positive-absence authority timestamp after mutation",
    )
    if payload["authority_updated_at_after"] != _later_authority_timestamp(
        payload["authority_updated_at_before"], plan["mutation_at"]
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence operation revision evidence is invalid"
        )
    return payload


def _retained_operation_result_payload(
    operation: sqlite3.Row, plan: Mapping[str, object]
) -> dict[str, object] | None:
    raw = operation["result_json"]
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
        if canonical_json(parsed) != raw:
            return None
        return _validated_operation_result_payload(parsed, plan)
    except (json.JSONDecodeError, SharedRootPositiveAbsenceError):
        return None


def _retained_partition_matches(
    connection: sqlite3.Connection, plan: Mapping[str, object]
) -> bool:
    snapshot_id = str(plan["observation"]["snapshot_id"])
    for record in plan["absent_resources"]:
        resource_id = str(record["membership"]["host_resource_id"])
        if connection.execute(
            """
            SELECT 1 FROM observation_snapshot_resources
            WHERE snapshot_id = ? AND resource_kind = 'container'
              AND resource_id = ?
            """,
            (snapshot_id, resource_id),
        ).fetchone() is not None:
            return False
    for record in plan["present_resources"]:
        resource_id = str(record["membership"]["host_resource_id"])
        row = connection.execute(
            """
            SELECT observation_fingerprint
            FROM observation_snapshot_resources
            WHERE snapshot_id = ? AND resource_kind = 'container'
              AND resource_id = ?
            """,
            (snapshot_id, resource_id),
        ).fetchone()
        if row is None or str(row[0]) != record["observation_fingerprint"]:
            return False
    return True


def _terminal_matches(
    connection: sqlite3.Connection, plan: Mapping[str, object]
) -> bool:
    repository_id = str(plan["repository"]["repository_id"])
    target = plan["target"]
    metadata = _require_schema12(connection)
    if (
        metadata["database_generation"] != plan["authority"]["database_generation"]
        or _retained_full_docker_observation(
            connection,
            snapshot_id=str(plan["observation"]["snapshot_id"]),
            host_id=str(plan["repository"]["host_id"]),
        )
        != plan["observation"]
        or not _retained_partition_matches(connection, plan)
    ):
        return False
    repository = connection.execute(
        """
        SELECT repository.state, repository.generation,
               repository.updated_at AS repository_updated_at,
               installation.status, installation.startup_fenced,
               installation.generation AS installation_generation,
               installation.operation_id, installation.disabled_at,
               installation.reason, installation.actor,
               installation.updated_at AS installation_updated_at
        FROM repositories repository
        JOIN repository_installations installation USING(repo_id)
        WHERE repository.repo_id = ?
        """,
        (repository_id,),
    ).fetchone()
    if (
        repository is None
        or str(repository["state"]) != "missing"
        or int(repository["generation"]) != target["repository_generation"]
        or str(repository["repository_updated_at"]) != plan["mutation_at"]
        or str(repository["status"]) != "disabled"
        or int(repository["startup_fenced"]) != 1
        or int(repository["installation_generation"])
        != target["installation_generation"]
        or repository["operation_id"] is not None
        or str(repository["disabled_at"]) != plan["mutation_at"]
        or str(repository["reason"]) != plan["reason"]
        or str(repository["actor"]) != plan["actor"]
        or str(repository["installation_updated_at"]) != plan["mutation_at"]
    ):
        return False
    operation = connection.execute(
        "SELECT * FROM operations WHERE operation_id = ?",
        (plan["operation_id"],),
    ).fetchone()
    operation_payload = (
        None
        if operation is None
        else _retained_operation_result_payload(operation, plan)
    )
    try:
        metadata_updated_text, metadata_updated_time = _parsed_timestamp(
            metadata["updated_at"],
            "positive-absence current authority timestamp",
        )
        operation_updated_text, operation_updated_time = _parsed_timestamp(
            None
            if operation_payload is None
            else operation_payload["authority_updated_at_after"],
            "positive-absence terminal authority timestamp",
        )
    except SharedRootPositiveAbsenceError:
        return False
    if (
        operation is None
        or str(operation["repo_id"]) != repository_id
        or str(operation["kind"]) != "shared_root_positive_absence"
        or str(operation["status"]) != "succeeded"
        or str(operation["phase"]) != "terminal"
        or str(operation["request_fingerprint"]) != plan["document_sha256"]
        or str(operation["actor"]) != plan["actor"]
        or operation_payload is None
        or int(metadata["state_revision"])
        < int(operation_payload["state_revision_after"])
        or (
            int(metadata["state_revision"])
            == int(operation_payload["state_revision_after"])
            and metadata_updated_text != operation_updated_text
        )
        or (
            int(metadata["state_revision"])
            > int(operation_payload["state_revision_after"])
            and metadata_updated_time < operation_updated_time
        )
    ):
        return False
    all_resources = [*plan["absent_resources"], *plan["present_resources"]]
    resource_ids = [
        str(record["membership"]["host_resource_id"]) for record in all_resources
    ]
    placeholders = ",".join("?" for _ in resource_ids)
    if connection.execute(
        "SELECT COUNT(*) FROM repository_memberships WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()[0] != 0:
        return False
    if any(
        connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ?", (repository_id,)
        ).fetchone()[0]
        != 0
        for table in (
            "source_resources",
            "control_bindings",
            "startup_policies",
            "database_bindings",
            "docker_ownership_claims",
        )
    ):
        return False
    binding_placeholders = ",".join("?" for _ in plan["database_bindings"])
    if connection.execute(
        "SELECT COUNT(*) FROM database_bindings "
        f"WHERE database_binding_id IN ({binding_placeholders}) "
        "AND repo_id IS NULL",
        tuple(row["database_binding_id"] for row in plan["database_bindings"]),
    ).fetchone()[0] != EXPECTED_DATABASE_BINDING_COUNT:
        return False
    for record in plan["absent_resources"]:
        resource_id = str(record["membership"]["host_resource_id"])
        policy = record["startup_policy"]
        binding = record["control_binding"]
        retirement = connection.execute(
            "SELECT * FROM resource_retirements WHERE host_resource_id = ?",
            (resource_id,),
        ).fetchone()
        tombstone = connection.execute(
            "SELECT * FROM cleanup_tombstones "
            "WHERE target_kind = 'container' AND target_id = ? "
            "AND target_generation = 0",
            (resource_id,),
        ).fetchone()
        current_policy = connection.execute(
            "SELECT repo_id, current_value, generation FROM startup_policies WHERE policy_id = ?",
            (policy["policy_id"],),
        ).fetchone()
        current_binding = connection.execute(
            "SELECT repo_id, authority_state, generation "
            "FROM control_bindings WHERE binding_id = ?",
            (binding["binding_id"],),
        ).fetchone()
        if (
            retirement is None
            or str(retirement["status"]) != "retired"
            or str(retirement["operation_id"]) != plan["operation_id"]
            or tombstone is None
            or str(tombstone["operation_id"]) != plan["operation_id"]
            or current_policy is None
            or current_policy["repo_id"] is not None
            or str(current_policy["current_value"])
            != str(policy["desired_disabled_value"])
            or int(current_policy["generation"])
            != int(policy["generation"])
            + (policy["current_value"] != policy["desired_disabled_value"])
            or current_binding is None
            or current_binding["repo_id"] is not None
            or str(current_binding["authority_state"]) != "retired"
            or int(current_binding["generation"])
            != int(binding["generation"])
            + (binding["authority_state"] != "retired")
        ):
            return False
    present = plan["present_resources"][0]
    present_id = str(present["membership"]["host_resource_id"])
    present_binding = connection.execute(
        "SELECT repo_id, authority_state, generation FROM control_bindings WHERE binding_id = ?",
        (present["control_binding"]["binding_id"],),
    ).fetchone()
    present_policy = connection.execute(
        "SELECT repo_id, current_value, generation FROM startup_policies WHERE policy_id = ?",
        (present["startup_policy"]["policy_id"],),
    ).fetchone()
    active_unassigned = connection.execute(
        """
        SELECT COUNT(*) FROM unassigned_resources
        WHERE resource_kind = 'container' AND resource_id = ?
          AND status = 'active' AND reason_code = 'not_git'
        """,
        (present_id,),
    ).fetchone()
    if (
        present_binding is None
        or present_binding["repo_id"] is not None
        or present_binding["authority_state"]
        != present["control_binding"]["authority_state"]
        or int(present_binding["generation"])
        != int(present["control_binding"]["generation"]) + 1
        or present_policy is None
        or present_policy["repo_id"] is not None
        or present_policy["current_value"]
        != present["startup_policy"]["current_value"]
        or int(present_policy["generation"])
        != int(present["startup_policy"]["generation"]) + 1
        or active_unassigned is None
        or int(active_unassigned[0]) != 1
    ):
        return False
    if connection.execute(
        "SELECT COUNT(*) FROM unassigned_resources "
        "WHERE resource_kind = 'container' "
        f"AND resource_id IN ({placeholders}) "
        "AND status = 'active' AND resource_id != ?",
        (*resource_ids, present_id),
    ).fetchone()[0] != 0:
        return False
    for claim in plan["ownership_claims"]:
        current_claim = connection.execute(
            """
            SELECT repo_id, conflict_state, updated_at
            FROM docker_ownership_claims WHERE claim_id = ?
            """,
            (claim["claim_id"],),
        ).fetchone()
        if (
            current_claim is None
            or current_claim["repo_id"] is not None
            or str(current_claim["conflict_state"]) != "retired"
            or str(current_claim["updated_at"]) != plan["mutation_at"]
        ):
            return False
    project_tombstone = connection.execute(
        "SELECT * FROM cleanup_tombstones "
        "WHERE target_kind = 'project' AND target_id = ? "
        "AND target_generation = ?",
        (repository_id, plan["repository"]["generation"]),
    ).fetchone()
    revocation = connection.execute(
        "SELECT * FROM broker_repository_materialization_revocations "
        "WHERE repo_id = ? AND repository_generation = ?",
        (repository_id, plan["repository"]["generation"]),
    ).fetchone()
    if (
        project_tombstone is None
        or str(project_tombstone["operation_id"]) != plan["operation_id"]
        or revocation is None
        or str(revocation["broker_operation_id"]) != plan["operation_id"]
        or str(revocation["immutable_fingerprint"])
        != target["repository_fingerprint"]
    ):
        return False
    for table in _ACL_TABLES:
        if connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ? AND enabled != 0",
            (repository_id,),
        ).fetchone()[0] != 0:
            return False
    return True


def _insert_operation(connection: sqlite3.Connection, plan: Mapping[str, object]) -> None:
    connection.execute(
        """
        INSERT INTO operations(
            operation_id, repo_id, source_id, kind, status, phase,
            generation, request_fingerprint, owner_uid, actor,
            process_fingerprint, error_code, error_message, result_json,
            created_at, updated_at
        ) VALUES (?, ?, NULL, 'shared_root_positive_absence', 'running',
                  'authority_mutation', 0, ?, 0, ?, NULL, NULL, NULL, NULL, ?, ?)
        """,
        (
            plan["operation_id"],
            plan["repository"]["repository_id"],
            plan["document_sha256"],
            plan["actor"],
            plan["mutation_at"],
            plan["mutation_at"],
        ),
    )


def _apply_initial(
    connection: sqlite3.Connection,
    plan: Mapping[str, object],
    *,
    authority_before: Mapping[str, object],
) -> None:
    repository_id = str(plan["repository"]["repository_id"])
    timestamp = str(plan["mutation_at"])
    revision_before = int(authority_before["state_revision"])
    authority_updated_at_before = str(authority_before["updated_at"])
    authority_updated_at_after = _later_authority_timestamp(
        authority_updated_at_before, timestamp
    )
    _insert_operation(connection, plan)
    absent_ids: list[str] = []
    for record in plan["absent_resources"]:
        resource_id = str(record["membership"]["host_resource_id"])
        absent_ids.append(resource_id)
        policy = record["startup_policy"]
        binding = record["control_binding"]
        membership = record["membership"]
        docker = record["docker"]
        changed_policy = connection.execute(
            """
            UPDATE startup_policies
            SET repo_id = NULL, current_value = desired_disabled_value,
                generation = generation + CASE
                    WHEN current_value != desired_disabled_value THEN 1 ELSE 0 END,
                updated_at = ?
            WHERE policy_id = ? AND repo_id = ? AND generation = ?
              AND current_value = ? AND desired_disabled_value = ?
            """,
            (
                timestamp,
                policy["policy_id"],
                repository_id,
                policy["generation"],
                policy["current_value"],
                policy["desired_disabled_value"],
            ),
        ).rowcount
        changed_binding = connection.execute(
            """
            UPDATE control_bindings
            SET repo_id = NULL, authority_state = 'retired',
                generation = generation + CASE
                    WHEN authority_state != 'retired' THEN 1 ELSE 0 END,
                updated_at = ?
            WHERE binding_id = ? AND repo_id = ? AND generation = ?
              AND authority_state = ?
            """,
            (
                timestamp,
                binding["binding_id"],
                repository_id,
                binding["generation"],
                binding["authority_state"],
            ),
        ).rowcount
        if changed_policy != 1 or changed_binding != 1:
            raise SharedRootPositiveAbsenceError(
                "absent resource projection changed during mutation"
            )
        connection.execute(
            """
            INSERT INTO resource_retirements(
                host_resource_id, resource_kind, immutable_fingerprint,
                status, operation_id, reason, actor, started_at,
                retired_at, updated_at
            ) VALUES (?, 'container', ?, 'retired', ?, ?, ?, ?, ?, ?)
            """,
            (
                resource_id,
                membership["immutable_fingerprint"],
                plan["operation_id"],
                plan["reason"],
                plan["actor"],
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        tombstone_evidence = {
            "kind": "positive-docker-absence",
            "plan_id": plan["plan_id"],
            "plan_document_sha256": plan["document_sha256"],
            "snapshot_id": plan["observation"]["snapshot_id"],
            "docker_resource_id": resource_id,
            "full_container_id": docker["full_container_id"],
            "native_resource_deleted": False,
            "positive_absence": True,
        }
        connection.execute(
            """
            INSERT INTO cleanup_tombstones(
                target_kind, target_id, target_generation, repo_id,
                immutable_fingerprint, operation_id, actor, reason,
                evidence_json, removed_at
            ) VALUES ('container', ?, 0, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resource_id,
                repository_id,
                membership["immutable_fingerprint"],
                plan["operation_id"],
                plan["actor"],
                plan["reason"],
                canonical_json(tombstone_evidence),
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO resource_lifecycle_history(
                history_id, repo_id, resource_kind, resource_id,
                immutable_fingerprint, action, operation_id, actor,
                reason, evidence_json, occurred_at
            ) VALUES (?, ?, 'container', ?, ?, 'purged', ?, ?, ?, ?, ?)
            """,
            (
                deterministic_id(
                    "shared-root-positive-absence-history",
                    plan["operation_id"],
                    resource_id,
                ),
                repository_id,
                resource_id,
                membership["immutable_fingerprint"],
                plan["operation_id"],
                plan["actor"],
                plan["reason"],
                canonical_json(tombstone_evidence),
                timestamp,
            ),
        )
    present = plan["present_resources"][0]
    present_id = str(present["membership"]["host_resource_id"])
    present_binding = present["control_binding"]
    present_policy = present["startup_policy"]
    if connection.execute(
        """
        UPDATE control_bindings
        SET repo_id = NULL, generation = generation + 1, updated_at = ?
        WHERE binding_id = ? AND repo_id = ? AND generation = ?
          AND authority_state = ?
        """,
        (
            timestamp,
            present_binding["binding_id"],
            repository_id,
            present_binding["generation"],
            present_binding["authority_state"],
        ),
    ).rowcount != 1:
        raise SharedRootPositiveAbsenceError(
            "present resource control projection changed during mutation"
        )
    if connection.execute(
        """
        UPDATE startup_policies
        SET repo_id = NULL, generation = generation + 1, updated_at = ?
        WHERE policy_id = ? AND repo_id = ? AND generation = ?
          AND current_value = ?
        """,
        (
            timestamp,
            present_policy["policy_id"],
            repository_id,
            present_policy["generation"],
            present_policy["current_value"],
        ),
    ).rowcount != 1:
        raise SharedRootPositiveAbsenceError(
            "present resource startup projection changed during mutation"
        )
    all_ids = [*absent_ids, present_id]
    placeholders = ",".join("?" for _ in all_ids)
    changed_sources = connection.execute(
        "UPDATE source_resources SET repo_id = NULL "
        f"WHERE repo_id = ? AND source_resource_id IN ({placeholders})",
        (
            repository_id,
            *[
                record["source_resource"]["source_resource_id"]
                for record in [*plan["absent_resources"], present]
            ],
        ),
    ).rowcount
    database_placeholders = ",".join("?" for _ in plan["database_bindings"])
    changed_databases = connection.execute(
        "UPDATE database_bindings SET repo_id = NULL, updated_at = ? "
        f"WHERE repo_id = ? AND database_binding_id IN ({database_placeholders})",
        (
            timestamp,
            repository_id,
            *[row["database_binding_id"] for row in plan["database_bindings"]],
        ),
    ).rowcount
    changed_claims = 0
    for claim in plan["ownership_claims"]:
        changed_claims += connection.execute(
            """
            UPDATE docker_ownership_claims
            SET repo_id = NULL, conflict_state = 'retired', updated_at = ?
            WHERE claim_id = ? AND repo_id = ? AND conflict_state = ?
              AND updated_at = ?
            """,
            (
                timestamp,
                claim["claim_id"],
                repository_id,
                claim["conflict_state"],
                claim["updated_at"],
            ),
        ).rowcount
    changed_memberships = connection.execute(
        "DELETE FROM repository_memberships "
        "WHERE repo_id = ? AND resource_kind = 'container' "
        f"AND host_resource_id IN ({placeholders})",
        (repository_id, *all_ids),
    ).rowcount
    if (
        changed_sources != EXPECTED_SOURCE_COUNT
        or changed_databases != EXPECTED_DATABASE_BINDING_COUNT
        or changed_memberships != EXPECTED_MEMBERSHIP_COUNT
        or changed_claims != len(plan["ownership_claims"])
    ):
        raise SharedRootPositiveAbsenceError(
            "shared-root detach mutation was incomplete"
        )
    connection.execute(
        "UPDATE startup_policy_restore_states SET repo_id = NULL, updated_at = ? WHERE repo_id = ?",
        (timestamp, repository_id),
    )
    connection.execute(
        "UPDATE unassigned_resources SET status = 'retired', updated_at = ? "
        "WHERE resource_kind = 'container' "
        f"AND resource_id IN ({placeholders}) AND status = 'active'",
        (timestamp, *all_ids),
    )
    connection.execute(
        """
        INSERT INTO unassigned_resources(
            unassigned_id, host_id, source_resource_id, resource_kind,
            resource_id, display_name, reason_code, suggested_root,
            status, created_at, updated_at
        ) VALUES (?, ?, ?, 'container', ?, ?, 'not_git', ?, 'active', ?, ?)
        ON CONFLICT(host_id, resource_kind, resource_id, reason_code) DO UPDATE SET
            source_resource_id = excluded.source_resource_id,
            display_name = excluded.display_name,
            suggested_root = excluded.suggested_root,
            status = 'active', updated_at = excluded.updated_at
        """,
        (
            deterministic_id(
                "unassigned",
                plan["repository"]["host_id"],
                "container",
                present_id,
                "not_git",
            ),
            plan["repository"]["host_id"],
            present["source_resource"]["source_resource_id"],
            present_id,
            present["docker"]["current_name"],
            SHARED_ROOT,
            timestamp,
            timestamp,
        ),
    )
    for table in _ACL_TABLES:
        connection.execute(
            f"UPDATE {table} SET enabled = 0 WHERE repo_id = ? AND enabled != 0",
            (repository_id,),
        )
    repository_fingerprint = plan["target"]["repository_fingerprint"]
    project_evidence = {
        "kind": "shared-root-positive-absence",
        "plan_id": plan["plan_id"],
        "plan_document_sha256": plan["document_sha256"],
        "snapshot_id": plan["observation"]["snapshot_id"],
        "absent_resource_count": EXPECTED_ABSENT_COUNT,
        "present_resource_count": EXPECTED_PRESENT_COUNT,
        "native_resources_mutated": False,
    }
    connection.execute(
        """
        INSERT INTO cleanup_tombstones(
            target_kind, target_id, target_generation, repo_id,
            immutable_fingerprint, operation_id, actor, reason,
            evidence_json, removed_at
        ) VALUES ('project', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            repository_id,
            plan["repository"]["generation"],
            repository_id,
            repository_fingerprint,
            plan["operation_id"],
            plan["actor"],
            plan["reason"],
            canonical_json(project_evidence),
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO broker_repository_materialization_revocations(
            repo_id, repository_generation, broker_operation_id,
            immutable_fingerprint, broker_database_generation, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            repository_id,
            plan["repository"]["generation"],
            plan["operation_id"],
            repository_fingerprint,
            plan["authority"]["database_generation"],
            timestamp,
        ),
    )
    changed_repository = connection.execute(
        """
        UPDATE repositories
        SET state = 'missing', generation = generation + 1, updated_at = ?
        WHERE repo_id = ? AND state = 'active' AND generation = ?
          AND updated_at = ?
        """,
        (
            timestamp,
            repository_id,
            plan["repository"]["generation"],
            plan["repository"]["repository_updated_at"],
        ),
    ).rowcount
    changed_installation = connection.execute(
        """
        UPDATE repository_installations
        SET status = 'disabled', startup_fenced = 1,
            generation = generation + 1, operation_id = NULL,
            disabled_at = ?, reason = ?, actor = ?, updated_at = ?
        WHERE repo_id = ? AND status = 'installed' AND startup_fenced = 0
          AND generation = ? AND operation_id IS NULL AND updated_at = ?
        """,
        (
            timestamp,
            plan["reason"],
            plan["actor"],
            timestamp,
            repository_id,
            plan["repository"]["installation_generation"],
            plan["repository"]["installation_updated_at"],
        ),
    ).rowcount
    changed_metadata = connection.execute(
        """
        UPDATE schema_metadata
        SET state_revision = state_revision + 1, updated_at = ?
        WHERE singleton = 1 AND schema_version = 12
          AND database_generation = ? AND migration_state = 'ready'
          AND state_revision = ? AND updated_at = ?
        """,
        (
            authority_updated_at_after,
            plan["authority"]["database_generation"],
            revision_before,
            authority_updated_at_before,
        ),
    ).rowcount
    if (changed_repository, changed_installation, changed_metadata) != (1, 1, 1):
        raise SharedRootPositiveAbsenceError(
            "shared-root terminalization CAS was incomplete"
        )
    changed_operation = connection.execute(
        """
        UPDATE operations
        SET status = 'succeeded', phase = 'terminal', result_json = ?, updated_at = ?
        WHERE operation_id = ? AND status = 'running'
          AND phase = 'authority_mutation' AND request_fingerprint = ?
        """,
        (
            canonical_json(
                _operation_result_payload(
                    plan,
                    state_revision_before=revision_before,
                    authority_updated_at_before=authority_updated_at_before,
                    authority_updated_at_after=authority_updated_at_after,
                )
            ),
            timestamp,
            plan["operation_id"],
            plan["document_sha256"],
        ),
    ).rowcount
    if changed_operation != 1:
        raise SharedRootPositiveAbsenceError(
            "shared-root operation terminalization was incomplete"
        )


def _result(
    plan: Mapping[str, object],
    *,
    state_revision_before: int,
    state_revision_after: int,
) -> dict[str, object]:
    return _seal(
        RESULT_KIND,
        {
            "plan_id": plan["plan_id"],
            "operation_id": plan["operation_id"],
            "plan_document_sha256": plan["document_sha256"],
            "authority_generation": plan["authority"]["database_generation"],
            "observation_snapshot_id": plan["observation"]["snapshot_id"],
            "repository_id": plan["repository"]["repository_id"],
            "repository_generation_before": plan["repository"]["generation"],
            "repository_generation_after": plan["target"]["repository_generation"],
            "installation_generation_before": plan["repository"][
                "installation_generation"
            ],
            "installation_generation_after": plan["target"][
                "installation_generation"
            ],
            "state_revision_before": state_revision_before,
            "state_revision_after": state_revision_after,
            "absent_resource_count": EXPECTED_ABSENT_COUNT,
            "present_resource_count": EXPECTED_PRESENT_COUNT,
            "detached_database_binding_count": EXPECTED_DATABASE_BINDING_COUNT,
            "repository_state": "missing",
            "installation_status": "disabled",
            "startup_fenced": True,
            "actor": plan["actor"],
            "reason": plan["reason"],
            "applied_at": plan["mutation_at"],
        },
    )


def _terminal_result(
    connection: sqlite3.Connection, plan: Mapping[str, object]
) -> dict[str, object] | None:
    if not _terminal_matches(connection, plan):
        return None
    operation = connection.execute(
        "SELECT result_json FROM operations WHERE operation_id = ?",
        (plan["operation_id"],),
    ).fetchone()
    payload = (
        None
        if operation is None
        else _retained_operation_result_payload(operation, plan)
    )
    if payload is None:
        raise SharedRootPositiveAbsenceError(
            "positive-absence terminal revision evidence is unavailable"
        )
    return _verify_seal(
        _result(
            plan,
            state_revision_before=int(payload["state_revision_before"]),
            state_revision_after=int(payload["state_revision_after"]),
        ),
        kind=RESULT_KIND,
        fields=_RESULT_FIELDS,
    )


def apply_shared_root_positive_absence(
    connection: sqlite3.Connection,
    *,
    plan: Mapping[str, object],
    plan_document_sha256: str,
) -> dict[str, object]:
    """Apply or replay the sealed transition inside a caller-owned transaction."""

    verified = _validate_plan(plan)
    if (
        plan_document_sha256 != verified["document_sha256"]
        or _HEX_SHA256.fullmatch(plan_document_sha256) is None
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence plan digest changed"
        )
    if not connection.in_transaction:
        raise SharedRootPositiveAbsenceError(
            "positive-absence apply requires an active caller-owned write transaction"
        )
    _require_schema12(connection)
    terminal = _terminal_result(connection, verified)
    if terminal is not None:
        return terminal
    if not _exact_initial_matches(connection, verified):
        raise SharedRootPositiveAbsenceError(
            "positive-absence plan drifted before apply"
        )
    authority_before = _require_schema12(connection)
    _apply_initial(
        connection,
        verified,
        authority_before=authority_before,
    )
    terminal = _terminal_result(connection, verified)
    if terminal is None:
        raise SharedRootPositiveAbsenceError(
            "positive-absence terminal state is incomplete"
        )
    return terminal


def validate_shared_root_positive_absence_plan(
    value: object,
) -> dict[str, object]:
    """Validate and normalize one sealed positive-absence plan."""

    return _validate_plan(value)


def validate_shared_root_positive_absence_result(
    value: object, *, plan: Mapping[str, object]
) -> dict[str, object]:
    """Validate a retained result against its exact sealed plan."""

    verified_plan = _validate_plan(plan)
    verified = _verify_seal(value, kind=RESULT_KIND, fields=_RESULT_FIELDS)
    revision_before = verified["state_revision_before"]
    revision_after = verified["state_revision_after"]
    if (
        isinstance(revision_before, bool)
        or not isinstance(revision_before, int)
        or isinstance(revision_after, bool)
        or not isinstance(revision_after, int)
        or revision_before < int(verified_plan["authority"]["state_revision"])
        or revision_before > MAX_SQLITE_INTEGER - 1
        or revision_after != revision_before + 1
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence result revision evidence is invalid"
        )
    expected = _verify_seal(
        _result(
            verified_plan,
            state_revision_before=revision_before,
            state_revision_after=revision_after,
        ),
        kind=RESULT_KIND,
        fields=_RESULT_FIELDS,
    )
    if verified != expected:
        raise SharedRootPositiveAbsenceError(
            "positive-absence result does not match its sealed plan"
        )
    return verified


def verify_shared_root_positive_absence_terminal(
    connection: sqlite3.Connection,
    *,
    plan: Mapping[str, object],
    plan_document_sha256: str,
    result: Mapping[str, object],
) -> dict[str, object]:
    """Verify retained evidence against the exact read-only authority projection."""

    verified_plan = _validate_plan(plan)
    if (
        plan_document_sha256 != verified_plan["document_sha256"]
        or _HEX_SHA256.fullmatch(plan_document_sha256) is None
    ):
        raise SharedRootPositiveAbsenceError(
            "positive-absence plan digest changed"
        )
    if not connection.in_transaction:
        raise SharedRootPositiveAbsenceError(
            "positive-absence terminal verification requires a stable read transaction"
        )
    verified_result = validate_shared_root_positive_absence_result(
        result, plan=verified_plan
    )
    terminal = _terminal_result(connection, verified_plan)
    if terminal is None or terminal != verified_result:
        raise SharedRootPositiveAbsenceError(
            "positive-absence retained result does not match authority state"
        )
    return terminal


__all__ = [
    "ACTOR",
    "EXPECTED_ABSENT_COUNT",
    "EXPECTED_ABSENT_DATABASE_BINDING_COUNT",
    "EXPECTED_DATABASE_BINDING_COUNT",
    "EXPECTED_MEMBERSHIP_COUNT",
    "EXPECTED_PRESENT_COUNT",
    "EXPECTED_PRESENT_DATABASE_BINDING_COUNT",
    "SharedRootPositiveAbsenceError",
    "apply_shared_root_positive_absence",
    "latest_shared_root_full_docker_observation",
    "plan_shared_root_positive_absence",
    "validate_shared_root_positive_absence_plan",
    "validate_shared_root_positive_absence_result",
    "verify_shared_root_positive_absence_terminal",
]
