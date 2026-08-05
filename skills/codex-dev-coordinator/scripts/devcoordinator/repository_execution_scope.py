"""Generation-fenced repository execution-scope partition.

Repository rows are retained after permanent project cleanup so their audit
history cannot be rewritten.  Retention must not, however, make a terminally
removed project part of the executable repository fleet forever.  This module
is the single fail-closed partition used by the schema-13 owner-authority
cutover:

* a repository is executable by default and therefore needs an explicit
  execution owner;
* exclusion is allowed only for an exact, generation-current, successfully
  completed permanent-project-cleanup tombstone; and
* the complete partition is revision fenced and digest sealed.

Malformed, partial, stale, or contradictory cleanup evidence never excludes a
repository.  It remains executable and must receive an owner decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from typing import Any, Mapping
import uuid


REPOSITORY_EXECUTION_SCOPE_SCHEMA_VERSION = 1
REPOSITORY_EXECUTION_SCOPE_KIND = "devcoordinator-repository-execution-scope"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_IDENTITY_TEXT = 512
_MAX_PATH_TEXT = 4096


class RepositoryExecutionScopeError(RuntimeError):
    """The retained authority cannot produce one trustworthy partition."""


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
        raise RepositoryExecutionScopeError(
            "repository execution scope is not canonical JSON"
        ) from error


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_identity(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > _MAX_IDENTITY_TEXT
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RepositoryExecutionScopeError(f"{label} is invalid")
    return value


def _canonical_absolute_path(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_TEXT
        or "\x00" in value
        or not value.startswith("/")
        or os.path.normpath(value) != value
    ):
        raise RepositoryExecutionScopeError(f"{label} path is invalid")
    return value


def _nonnegative_integer(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RepositoryExecutionScopeError(f"{label} is invalid")
    return value


def _canonical_uuid(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise RepositoryExecutionScopeError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise RepositoryExecutionScopeError(
            f"{label} must be a canonical UUID"
        ) from error
    if str(parsed) != value:
        raise RepositoryExecutionScopeError(f"{label} must be a canonical UUID")
    return value


def _parse_json(value: Any) -> Any | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
        # Reject NaN/Infinity and values which cannot be resealed canonically.
        _canonical(parsed)
        return parsed
    except (json.JSONDecodeError, RepositoryExecutionScopeError):
        return None


def _available_tables(connection: sqlite3.Connection) -> set[str]:
    required = {"schema_metadata", "repositories"}
    available = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = sorted(required - available)
    if missing:
        raise RepositoryExecutionScopeError(
            "repository execution scope tables are missing: " + ", ".join(missing)
        )
    return available


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def _metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               migration_state
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        raise RepositoryExecutionScopeError(
            "repository execution scope metadata singleton is missing"
        )
    return {
        "authority_schema_version": _nonnegative_integer(
            int(row[0]), label="repository execution scope authority_schema_version"
        ),
        "database_generation": _bounded_identity(
            str(row[1]), label="repository execution scope database_generation"
        ),
        "state_revision": _nonnegative_integer(
            int(row[2]), label="repository execution scope state_revision"
        ),
        "migration_state": _bounded_identity(
            str(row[3]), label="repository execution scope migration_state"
        ),
    }


def _expected_plan_summary(
    *,
    plan_id: str,
    plan_fingerprint: str,
    confirmation_phrase: str,
    snapshot: Mapping[str, Any],
    repository_id: str,
) -> dict[str, Any]:
    target_value = snapshot.get("target")
    if not isinstance(target_value, Mapping):
        target_value = {}
    target = dict(target_value)
    target.update({"target_kind": "project", "target_id": repository_id})
    blocker_value = snapshot.get("blockers")
    blockers = (
        [dict(item) for item in blocker_value if isinstance(item, Mapping)]
        if isinstance(blocker_value, list)
        else []
    )
    retained_value = snapshot.get("retained")
    retained = (
        list(retained_value)
        if isinstance(retained_value, list) and retained_value
        else ["audit_history", "cleanup_tombstone", "operation_evidence"]
    )
    return {
        "plan_id": plan_id,
        "plan_fingerprint": plan_fingerprint,
        "fingerprint": plan_fingerprint,
        "confirmation_phrase": confirmation_phrase,
        "action": "forget",
        "target": target,
        "effects": list(snapshot.get("effects") or []),
        "retained": retained,
        "deleted": list(snapshot.get("deleted") or []),
        "blockers": blockers,
        "status": "blocked" if blockers else "planned",
    }


def _terminal_exclusion(
    connection: sqlite3.Connection,
    repository: Mapping[str, Any],
    *,
    terminal_evidence_available: bool,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Return exact terminal evidence or fail-closed exclusion blockers."""

    blockers: list[str] = []
    if repository["state"] != "missing":
        blockers.append("repository_not_missing")
    if repository["installation_status"] != "disabled":
        blockers.append("installation_not_disabled")
    if repository["startup_fenced"] is not True:
        blockers.append("installation_not_fenced")
    generation = int(repository["repository_generation"])
    if generation < 1:
        blockers.append("repository_generation_has_no_terminal_predecessor")
    if blockers:
        return None, sorted(set(blockers))
    if not terminal_evidence_available:
        return None, ["terminal_evidence_tables_unavailable"]

    rows = list(
        connection.execute(
            """
            SELECT tombstone.target_generation,
                   tombstone.repo_id,
                   tombstone.immutable_fingerprint,
                   tombstone.operation_id,
                   tombstone.actor,
                   tombstone.reason,
                   tombstone.evidence_json,
                   tombstone.removed_at,
                   operation.repo_id,
                   operation.kind,
                   operation.status,
                   operation.phase,
                   operation.request_fingerprint,
                   operation.actor,
                   operation.result_json,
                   plan.repo_id,
                   plan.target_kind,
                   plan.target_id,
                   plan.action,
                   plan.target_fingerprint,
                   plan.plan_fingerprint,
                   plan.confirmation_phrase,
                   plan.snapshot_json,
                   plan.status,
                   plan.phase,
                   plan.actor,
                   plan.reason,
                   finalize.status,
                   finalize.evidence_json
            FROM cleanup_tombstones tombstone
            LEFT JOIN operations operation
              ON operation.operation_id = tombstone.operation_id
            LEFT JOIN cleanup_plans plan
              ON plan.plan_id = tombstone.operation_id
            LEFT JOIN cleanup_phase_evidence finalize
              ON finalize.plan_id = tombstone.operation_id
             AND finalize.phase = 'finalize'
            WHERE tombstone.target_kind = 'project'
              AND tombstone.target_id = ?
              AND tombstone.target_generation = ?
            """,
            (repository["repository_id"], generation - 1),
        )
    )
    if len(rows) != 1:
        return None, ["generation_current_project_tombstone_missing"]
    row = rows[0]
    (
        target_generation,
        tombstone_repo_id,
        immutable_fingerprint,
        operation_id,
        tombstone_actor,
        tombstone_reason,
        tombstone_evidence_json,
        removed_at,
        operation_repo_id,
        operation_kind,
        operation_status,
        operation_phase,
        operation_fingerprint,
        operation_actor,
        operation_result_json,
        plan_repo_id,
        target_kind,
        target_id,
        action,
        target_fingerprint,
        plan_fingerprint,
        confirmation_phrase,
        snapshot_json,
        plan_status,
        plan_phase,
        plan_actor,
        plan_reason,
        finalize_status,
        finalize_evidence_json,
    ) = row
    repository_id = str(repository["repository_id"])
    if (
        tombstone_repo_id != repository_id
        or operation_repo_id != repository_id
        or plan_repo_id != repository_id
        or target_kind != "project"
        or target_id != repository_id
        or action != "forget"
    ):
        blockers.append("terminal_repository_binding_invalid")
    if (
        operation_kind != "cleanup:forget"
        or operation_status != "succeeded"
        or operation_phase != "complete"
        or plan_status != "succeeded"
        or plan_phase != "complete"
        or finalize_status != "succeeded"
    ):
        blockers.append("terminal_operation_not_successful")
    if (
        not isinstance(immutable_fingerprint, str)
        or _SHA256_PATTERN.fullmatch(immutable_fingerprint) is None
        or target_fingerprint != immutable_fingerprint
        or not isinstance(plan_fingerprint, str)
        or _SHA256_PATTERN.fullmatch(plan_fingerprint) is None
        or operation_fingerprint != plan_fingerprint
    ):
        blockers.append("terminal_fingerprint_binding_invalid")
    if (
        tombstone_actor != plan_actor
        or operation_actor != plan_actor
        or tombstone_reason != plan_reason
        or not isinstance(confirmation_phrase, str)
        or not confirmation_phrase
    ):
        blockers.append("terminal_identity_binding_invalid")
    try:
        _canonical_uuid(operation_id, label="terminal cleanup operation_id")
    except RepositoryExecutionScopeError:
        blockers.append("terminal_identity_binding_invalid")

    snapshot = _parse_json(snapshot_json)
    tombstone_evidence = _parse_json(tombstone_evidence_json)
    operation_result = _parse_json(operation_result_json)
    finalize_evidence = _parse_json(finalize_evidence_json)
    if not isinstance(snapshot, dict) or not isinstance(tombstone_evidence, dict):
        blockers.append("terminal_evidence_invalid")
    else:
        identity = snapshot.get("identity")
        expected_identity = {
            "repo_id": repository_id,
            "canonical_root": repository["canonical_root"],
            "state": "active",
            "generation": generation - 1,
            "installation_status": "disabled",
            "startup_fenced": True,
            "installation_generation": repository["installation_generation"],
        }
        if identity != expected_identity:
            blockers.append("terminal_snapshot_identity_invalid")
        else:
            expected_target_fingerprint = _digest(identity)
            if immutable_fingerprint != expected_target_fingerprint:
                blockers.append("terminal_target_fingerprint_invalid")
        plan_material = {
            "action": "forget",
            "target_kind": "project",
            "target_id": repository_id,
            "repo_id": snapshot.get("repo_id"),
            "target_fingerprint": immutable_fingerprint,
            "snapshot": snapshot,
            "actor": plan_actor,
            "reason": plan_reason,
        }
        if plan_fingerprint != _digest(plan_material):
            blockers.append("terminal_plan_fingerprint_invalid")
        expected_evidence = {
            "plan": _expected_plan_summary(
                plan_id=str(operation_id),
                plan_fingerprint=str(plan_fingerprint),
                confirmation_phrase=str(confirmation_phrase),
                snapshot=snapshot,
                repository_id=repository_id,
            ),
            "snapshot": snapshot,
            "applied_by": tombstone_evidence.get("applied_by"),
        }
        if (
            set(tombstone_evidence) != {"plan", "snapshot", "applied_by"}
            or not isinstance(tombstone_evidence.get("applied_by"), str)
            or not tombstone_evidence["applied_by"]
            or tombstone_evidence != expected_evidence
        ):
            blockers.append("terminal_tombstone_evidence_invalid")
        target = snapshot.get("target")
        expected_confirmation = (
            f"PURGE PROJECT {target.get('display_name')}"
            if isinstance(target, dict)
            and isinstance(target.get("display_name"), str)
            and target.get("display_name")
            else None
        )
        if confirmation_phrase != expected_confirmation:
            blockers.append("terminal_confirmation_binding_invalid")
    expected_result = {
        "status": "succeeded",
        "partial": False,
        "needs_attention": False,
        "ok": True,
        "errors": [],
        "target_kind": "project",
        "target_id": repository_id,
    }
    if operation_result != expected_result or finalize_evidence != expected_result:
        blockers.append("terminal_completion_evidence_invalid")
    if blockers:
        return None, sorted(set(blockers))

    evidence = {
        "target_generation": int(target_generation),
        "operation_id": str(operation_id),
        "immutable_fingerprint": str(immutable_fingerprint),
        "plan_fingerprint": str(plan_fingerprint),
        "tombstone_evidence_sha256": _digest(tombstone_evidence),
        "snapshot_sha256": _digest(snapshot),
        "completion_evidence_sha256": _digest(operation_result),
        "removed_at": _bounded_identity(
            str(removed_at), label="terminal repository removed_at"
        ),
    }
    return evidence, []


def repository_execution_scope(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Return the exact executable/terminal partition for the current revision."""

    available_tables = _available_tables(connection)
    metadata = _metadata(connection)
    repository_columns = _table_columns(connection, "repositories")
    required_repository_columns = {
        "repo_id",
        "canonical_root",
        "generation",
        "state",
    }
    if not required_repository_columns.issubset(repository_columns):
        raise RepositoryExecutionScopeError(
            "repository execution scope repository columns are incomplete"
        )
    terminal_column_contract = {
        "repository_installations": {
            "repo_id",
            "status",
            "startup_fenced",
            "generation",
        },
        "operations": {
            "operation_id",
            "repo_id",
            "kind",
            "status",
            "phase",
            "request_fingerprint",
            "actor",
            "result_json",
        },
        "cleanup_plans": {
            "plan_id",
            "repo_id",
            "target_kind",
            "target_id",
            "action",
            "target_fingerprint",
            "plan_fingerprint",
            "confirmation_phrase",
            "snapshot_json",
            "status",
            "phase",
            "actor",
            "reason",
        },
        "cleanup_phase_evidence": {
            "plan_id",
            "phase",
            "status",
            "evidence_json",
        },
        "cleanup_tombstones": {
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
        },
    }
    terminal_evidence_available = all(
        table in available_tables
        and columns.issubset(_table_columns(connection, table))
        for table, columns in terminal_column_contract.items()
    )
    installation_columns = (
        _table_columns(connection, "repository_installations")
        if "repository_installations" in available_tables
        else set()
    )
    has_installation_projection = {
        "repo_id",
        "status",
        "startup_fenced",
    }.issubset(installation_columns)
    display_expression = (
        "repository.display_name"
        if "display_name" in repository_columns
        else "repository.repo_id"
    )
    installation_generation_expression = (
        "installation.generation"
        if "generation" in installation_columns
        else "NULL"
    )
    if has_installation_projection:
        repository_rows = list(
            connection.execute(
                f"""
                SELECT repository.repo_id, repository.canonical_root,
                       repository.generation, {display_expression},
                       repository.state, installation.status,
                       installation.startup_fenced,
                       {installation_generation_expression}
                FROM repositories repository
                LEFT JOIN repository_installations installation USING(repo_id)
                ORDER BY repository.repo_id
                """
            )
        )
    else:
        repository_rows = list(
            connection.execute(
                f"""
                SELECT repository.repo_id, repository.canonical_root,
                       repository.generation, {display_expression},
                       repository.state, NULL, NULL, NULL
                FROM repositories repository ORDER BY repository.repo_id
                """
            )
        )
    executable: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    universe: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in repository_rows:
        repository_id = _bounded_identity(
            str(row[0]), label="repository execution scope repository_id"
        )
        if repository_id in seen:
            raise RepositoryExecutionScopeError(
                "repository execution scope contains a duplicate repository_id"
            )
        seen.add(repository_id)
        state = str(row[4])
        if state not in {"active", "missing", "relocated"}:
            raise RepositoryExecutionScopeError(
                "repository execution scope state is invalid"
            )
        installation_status = None if row[5] is None else str(row[5])
        if installation_status not in {None, "installed", "disabling", "disabled"}:
            raise RepositoryExecutionScopeError(
                "repository execution scope installation status is invalid"
            )
        if row[6] not in {None, 0, 1}:
            raise RepositoryExecutionScopeError(
                "repository execution scope startup_fenced value is invalid"
            )
        startup_fenced = None if row[6] is None else bool(row[6])
        installation_generation = None if row[7] is None else int(row[7])
        if installation_generation is not None:
            _nonnegative_integer(
                installation_generation,
                label="repository execution scope installation_generation",
            )
        base = {
            "repository_id": repository_id,
            "canonical_root": _canonical_absolute_path(
                str(row[1]), label="repository execution scope canonical_root"
            ),
            "repository_generation": _nonnegative_integer(
                int(row[2]),
                label="repository execution scope repository_generation",
            ),
            "display_name": _bounded_identity(
                str(row[3]), label="repository execution scope display_name"
            ),
            "state": state,
            "installation_status": installation_status,
            "startup_fenced": startup_fenced,
            "installation_generation": installation_generation,
        }
        universe.append(base)
        terminal_evidence, blockers = _terminal_exclusion(
            connection,
            base,
            terminal_evidence_available=terminal_evidence_available,
        )
        if terminal_evidence is None:
            executable.append({**base, "terminal_exclusion_blockers": blockers})
        else:
            excluded.append({**base, "terminal_evidence": terminal_evidence})

    unsigned: dict[str, Any] = {
        "schema_version": REPOSITORY_EXECUTION_SCOPE_SCHEMA_VERSION,
        "kind": REPOSITORY_EXECUTION_SCOPE_KIND,
        **metadata,
        "repository_count": len(universe),
        "executable_repository_count": len(executable),
        "excluded_terminal_repository_count": len(excluded),
        "repository_universe_sha256": _digest(universe),
        "executable_repositories_sha256": _digest(executable),
        "excluded_terminal_repositories_sha256": _digest(excluded),
        "executable_repositories": executable,
        "excluded_terminal_repositories": excluded,
    }
    return {**unsigned, "document_sha256": _digest(unsigned)}


def validate_repository_execution_scope(
    connection: sqlite3.Connection,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Require byte-equivalent scope evidence for the current DB revision."""

    if not isinstance(document, dict):
        raise RepositoryExecutionScopeError(
            "repository execution scope document is invalid"
        )
    current = repository_execution_scope(connection)
    if dict(document) != current:
        raise RepositoryExecutionScopeError(
            "repository execution scope database generation, revision, or evidence changed"
        )
    return current


def validate_repository_execution_scope_transition(
    connection: sqlite3.Connection,
    source_document: Mapping[str, Any],
    *,
    target_schema_version: int,
    target_database_generation: str,
    target_state_revision: int,
) -> dict[str, Any]:
    """Verify one committed schema transition retained the exact partition."""

    if not isinstance(source_document, dict):
        raise RepositoryExecutionScopeError(
            "source repository execution scope document is invalid"
        )
    expected_fields = {
        "schema_version",
        "kind",
        "authority_schema_version",
        "database_generation",
        "state_revision",
        "migration_state",
        "repository_count",
        "executable_repository_count",
        "excluded_terminal_repository_count",
        "repository_universe_sha256",
        "executable_repositories_sha256",
        "excluded_terminal_repositories_sha256",
        "executable_repositories",
        "excluded_terminal_repositories",
        "document_sha256",
    }
    if set(source_document) != expected_fields:
        raise RepositoryExecutionScopeError(
            "source repository execution scope fields are invalid"
        )
    unsigned = dict(source_document)
    supplied_digest = unsigned.pop("document_sha256")
    executable = source_document["executable_repositories"]
    excluded = source_document["excluded_terminal_repositories"]
    if (
        source_document["schema_version"]
        != REPOSITORY_EXECUTION_SCOPE_SCHEMA_VERSION
        or source_document["kind"] != REPOSITORY_EXECUTION_SCOPE_KIND
        or not isinstance(executable, list)
        or not isinstance(excluded, list)
        or source_document["repository_count"] != len(executable) + len(excluded)
        or source_document["executable_repository_count"] != len(executable)
        or source_document["excluded_terminal_repository_count"] != len(excluded)
        or source_document["executable_repositories_sha256"] != _digest(executable)
        or source_document["excluded_terminal_repositories_sha256"] != _digest(excluded)
        or supplied_digest != _digest(unsigned)
    ):
        raise RepositoryExecutionScopeError(
            "source repository execution scope contract is contradictory"
        )
    current = repository_execution_scope(connection)
    partition_fields = (
        "repository_count",
        "executable_repository_count",
        "excluded_terminal_repository_count",
        "repository_universe_sha256",
        "executable_repositories_sha256",
        "excluded_terminal_repositories_sha256",
        "executable_repositories",
        "excluded_terminal_repositories",
    )
    if (
        current["authority_schema_version"] != target_schema_version
        or current["database_generation"] != target_database_generation
        or current["state_revision"] != target_state_revision
        or current["migration_state"] != "ready"
        or any(
            current[field] != source_document[field]
            for field in partition_fields
        )
    ):
        raise RepositoryExecutionScopeError(
            "repository execution scope changed across the schema transition"
        )
    return current
