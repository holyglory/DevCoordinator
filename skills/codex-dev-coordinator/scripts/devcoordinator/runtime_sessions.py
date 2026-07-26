"""Durable runtime-session lifetime and idempotent cleanup bookkeeping."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from typing import Any, Callable

from .runtime_redaction import redact_runtime_request, redact_runtime_value
from .store import canonical_json, fingerprint, utc_timestamp


ACTIVE_SESSION_STATUSES = frozenset(
    {"planned", "running", "cleanup_pending", "cleaning"}
)
_RECLAIM_CLEANING_AFTER_SECONDS = 60
_TERMINAL_CLEANUP_STATES = frozenset(
    {"absent", "removed", "released", "retained", "stopped", "exited"}
)


class RuntimeCleanupVerificationError(RuntimeError):
    """Cleanup returned without proving that its exact target is terminal."""

    def __init__(self, message: str, *, result: Any = None) -> None:
        super().__init__(message)
        self.result = result


class RuntimeCatalogCleanupError(RuntimeError):
    """A stopped runtime could not be removed from the active catalog safely."""

    def __init__(self, message: str, *, result: Any = None) -> None:
        super().__init__(message)
        self.result = result


def _verified_cleanup_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise RuntimeCleanupVerificationError(
            "runtime cleanup returned a non-object result", result=result
        )
    if result.get("ok") is not True:
        raise RuntimeCleanupVerificationError(
            "runtime cleanup did not report ok=true", result=result
        )
    state = result.get("state")
    if state not in _TERMINAL_CLEANUP_STATES:
        raise RuntimeCleanupVerificationError(
            "runtime cleanup did not prove a terminal state", result=result
        )
    return result


def _cleanup_failure(
    store: Any,
    *,
    session_id: str,
    claim_id: str,
    error: BaseException,
) -> None:
    failure = {
        "type": type(error).__name__,
        "message": str(error),
    }
    cleanup_result = getattr(error, "result", None)
    if isinstance(cleanup_result, dict):
        failure["result"] = cleanup_result
    failed_at = utc_timestamp()
    with store.immediate_transaction() as connection:
        connection.execute(
            """
            UPDATE runtime_sessions
            SET status = 'cleanup_pending', cleanup_error_json = ?, updated_at = ?
            WHERE session_id = ? AND cleanup_claim_id = ?
            """,
            (canonical_json(failure), failed_at, session_id, claim_id),
        )
        connection.execute(
            """
            UPDATE runtime_session_resources
            SET cleanup_state = 'failed', cleanup_error_json = ?, updated_at = ?
            WHERE session_id = ? AND cleanup_state = 'cleaning'
            """,
            (canonical_json(failure), failed_at, session_id),
        )


def _one_value(connection: Any, statement: str, parameters: tuple[Any, ...]) -> Any:
    row = connection.execute(statement, parameters).fetchone()
    return None if row is None else row[0]


def _require_created_service_terminal_boundary(
    connection: Any,
    *,
    session: Any,
    request: dict[str, Any],
    resource: dict[str, Any],
    cleanup_result: dict[str, Any],
) -> tuple[Any | None, dict[str, Any]]:
    target = request.get("target") or {}
    resource_id = str(resource["resource_id"])
    if (
        target.get("kind") != "service"
        or str(target.get("id") or "") != resource_id
        or str(resource.get("resource_kind") or "") != "service"
        or str(resource.get("cleanup_disposition") or "") != "removed"
    ):
        raise RuntimeCatalogCleanupError(
            "runtime-created service catalog target changed before cleanup",
            result=cleanup_result,
        )
    definition = connection.execute(
        """
        SELECT d.*, o.lifecycle, o.pid, o.listener_observable
        FROM server_definitions d
        LEFT JOIN server_observations o USING(server_definition_id)
        WHERE d.server_definition_id = ?
        """,
        (resource_id,),
    ).fetchone()
    identity = (
        json.loads(str(resource["identity_json"]))
        if resource.get("identity_json")
        else {}
    )
    if definition is None:
        if not (
            identity.get("state") == "reserved"
            and identity.get("prior") is None
            and cleanup_result.get("reservation_outcome") == "not_created"
        ):
            raise RuntimeCatalogCleanupError(
                "runtime-created service disappeared without a proved unused reservation",
                result=cleanup_result,
            )
        return None, identity
    if (
        str(definition["repo_id"] or "") != str(session["repo_id"])
        or str(definition["name"] or "") != str(target.get("name") or "")
    ):
        raise RuntimeCatalogCleanupError(
            "runtime-created service repository or name changed before catalog cleanup",
            result=cleanup_result,
        )
    expected_generation = (
        identity.get("expected_generation")
        if identity.get("state") == "reserved"
        else identity.get("generation")
    )
    if type(expected_generation) is not int or int(definition["generation"]) != int(
        expected_generation
    ):
        raise RuntimeCatalogCleanupError(
            "runtime-created service generation changed before catalog cleanup",
            result=cleanup_result,
        )
    server_result = cleanup_result.get("server")
    if not (
        isinstance(server_result, dict)
        and str(server_result.get("id") or "") == resource_id
        and server_result.get("status") == "stopped"
        and server_result.get("identity_observable") is True
        and cleanup_result.get("state") == "removed"
    ):
        raise RuntimeCatalogCleanupError(
            "runtime cleanup did not return exact observable stopped-service proof",
            result=cleanup_result,
        )
    if not (
        definition["lifecycle"] == "stopped"
        and definition["pid"] is None
        and definition["listener_observable"] == 1
    ):
        raise RuntimeCatalogCleanupError(
            "runtime-created service has no exact stopped listener boundary in the catalog",
            result=cleanup_result,
        )
    return definition, identity


def _delete_created_service_catalog(
    connection: Any,
    *,
    session: Any,
    request: dict[str, Any],
    resource: dict[str, Any],
    cleanup_result: dict[str, Any],
) -> dict[str, Any]:
    definition, _identity = _require_created_service_terminal_boundary(
        connection,
        session=session,
        request=request,
        resource=resource,
        cleanup_result=cleanup_result,
    )
    resource_id = str(resource["resource_id"])
    repo_id = str(session["repo_id"])
    if definition is None:
        return {
            "resource_kind": "service",
            "resource_id": resource_id,
            "ownership": "created",
            "active_catalog_deleted": True,
            "reservation_outcome": "not_created",
            "deleted_rows": {},
        }

    blockers: list[str] = []
    if _one_value(
        connection,
        "SELECT 1 FROM leases WHERE server_definition_id = ? AND status = 'active' LIMIT 1",
        (resource_id,),
    ):
        blockers.append("active_lease")
    if _one_value(
        connection,
        """
        SELECT 1 FROM port_assignments
        WHERE repo_id = ? AND server_name = ? AND status = 'active' LIMIT 1
        """,
        (repo_id, str(definition["name"])),
    ):
        blockers.append("active_port_assignment")
    if _one_value(
        connection,
        """
        SELECT 1 FROM operations operation
        JOIN operation_targets target USING(operation_id)
        WHERE target.target_kind = 'server' AND target.target_id = ?
          AND operation.status IN ('planned','running','partial','needs_attention')
        LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("pending_operation")
    if _one_value(
        connection,
        """
        SELECT 1 FROM broker_lease_links
        WHERE server_definition_id = ? AND status != 'released' LIMIT 1
        """,
        (resource_id,),
    ) or _one_value(
        connection,
        """
        SELECT 1 FROM broker_assignment_links
        WHERE server_definition_id = ? AND status != 'released' LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("unreleased_broker_link")
    if _one_value(
        connection,
        """
        SELECT 1 FROM broker_reconciliation_queue
        WHERE resource_id = ? AND status IN ('pending','operator_required') LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("broker_reconciliation")
    if _one_value(
        connection,
        """
        SELECT 1 FROM broker_lifecycle_links
        WHERE resource_id = ? AND status IN (
            'pending','reconciliation_required','operator_required'
        ) LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("broker_lifecycle_reconciliation")
    if _one_value(
        connection,
        """
        SELECT 1 FROM startup_policy_restore_states
        WHERE resource_kind = 'server' AND resource_id = ?
          AND restore_required = 1 AND status = 'captured' LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("startup_policy_restore")
    if _one_value(
        connection,
        "SELECT 1 FROM resource_retirements WHERE host_resource_id = ? LIMIT 1",
        (resource_id,),
    ):
        blockers.append("resource_retirement")
    if _one_value(
        connection,
        """
        SELECT 1 FROM cleanup_plans
        WHERE target_kind = 'server' AND target_id = ?
          AND status IN ('planned','running','needs_attention') LIMIT 1
        """,
        (resource_id,),
    ):
        blockers.append("cleanup_plan")
    if blockers:
        raise RuntimeCatalogCleanupError(
            "runtime-created service catalog still has active or unresolved state: "
            + ", ".join(sorted(set(blockers))),
            result={**cleanup_result, "catalog_blockers": sorted(set(blockers))},
        )

    membership = connection.execute(
        """
        SELECT membership_id, repo_id, control_binding_id
        FROM repository_memberships
        WHERE resource_kind = 'server' AND host_resource_id = ?
        """,
        (resource_id,),
    ).fetchone()
    if membership is None or str(membership["repo_id"]) != repo_id:
        raise RuntimeCatalogCleanupError(
            "runtime-created service has no exact repository membership",
            result=cleanup_result,
        )
    foreign_control = _one_value(
        connection,
        """
        SELECT 1 FROM control_bindings
        WHERE resource_kind = 'server' AND resource_id = ?
          AND repo_id IS NOT NULL AND repo_id != ? LIMIT 1
        """,
        (resource_id, repo_id),
    )
    foreign_policy = _one_value(
        connection,
        """
        SELECT 1 FROM startup_policies
        WHERE resource_kind = 'server' AND resource_id = ?
          AND repo_id IS NOT NULL AND repo_id != ? LIMIT 1
        """,
        (resource_id, repo_id),
    )
    if foreign_control or foreign_policy:
        raise RuntimeCatalogCleanupError(
            "runtime-created service active catalog crosses repository authority",
            result=cleanup_result,
        )

    deleted: dict[str, int] = {}

    def delete(label: str, statement: str, parameters: tuple[Any, ...]) -> None:
        deleted[label] = connection.execute(statement, parameters).rowcount

    delete(
        "broker_lease_links",
        "DELETE FROM broker_lease_links WHERE server_definition_id = ? AND status = 'released'",
        (resource_id,),
    )
    delete(
        "broker_assignment_links",
        "DELETE FROM broker_assignment_links WHERE server_definition_id = ? AND status = 'released'",
        (resource_id,),
    )
    delete(
        "leases",
        """
        DELETE FROM leases WHERE server_definition_id = ?
          AND status IN ('released','stale')
        """,
        (resource_id,),
    )
    delete(
        "port_assignments",
        """
        DELETE FROM port_assignments
        WHERE repo_id = ? AND server_name = ? AND status = 'inactive'
        """,
        (repo_id, str(definition["name"])),
    )
    delete(
        "startup_policies",
        "DELETE FROM startup_policies WHERE resource_kind = 'server' AND resource_id = ?",
        (resource_id,),
    )
    delete(
        "repository_memberships",
        "DELETE FROM repository_memberships WHERE membership_id = ?",
        (str(membership["membership_id"]),),
    )
    delete(
        "control_bindings",
        "DELETE FROM control_bindings WHERE resource_kind = 'server' AND resource_id = ?",
        (resource_id,),
    )
    delete(
        "server_definitions",
        "DELETE FROM server_definitions WHERE server_definition_id = ? AND repo_id = ?",
        (resource_id, repo_id),
    )
    if deleted["server_definitions"] != 1:
        raise RuntimeCatalogCleanupError(
            "runtime-created service definition changed before deletion",
            result=cleanup_result,
        )
    return {
        "resource_kind": "service",
        "resource_id": resource_id,
        "ownership": "created",
        "active_catalog_deleted": True,
        "deleted_rows": deleted,
    }


def _empty_temporary_scope_blockers(
    connection: Any, *, session_id: str, repo_id: str
) -> list[str]:
    checks = (
        ("server_definitions", "SELECT 1 FROM server_definitions WHERE repo_id = ? LIMIT 1"),
        ("memberships", "SELECT 1 FROM repository_memberships WHERE repo_id = ? LIMIT 1"),
        ("database_bindings", "SELECT 1 FROM database_bindings WHERE repo_id = ? LIMIT 1"),
        ("docker_claims", "SELECT 1 FROM docker_ownership_claims WHERE repo_id = ? AND conflict_state != 'retired' LIMIT 1"),
        ("source_resources", "SELECT 1 FROM source_resources WHERE repo_id = ? LIMIT 1"),
        ("control_bindings", "SELECT 1 FROM control_bindings WHERE repo_id = ? AND authority_state != 'retired' LIMIT 1"),
        ("startup_policies", "SELECT 1 FROM startup_policies WHERE repo_id = ? LIMIT 1"),
        ("port_assignments", "SELECT 1 FROM port_assignments WHERE repo_id = ? LIMIT 1"),
        ("leases", "SELECT 1 FROM leases WHERE repo_id = ? LIMIT 1"),
    )
    blockers = [
        label
        for label, statement in checks
        if _one_value(connection, statement, (repo_id,))
    ]
    if _one_value(
        connection,
        """
        SELECT 1 FROM runtime_sessions
        WHERE repo_id = ? AND session_id != ?
          AND status IN ('planned','running','cleanup_pending','cleaning') LIMIT 1
        """,
        (repo_id, session_id),
    ):
        blockers.append("active_runtime_session")
    if _one_value(
        connection,
        """
        SELECT 1 FROM operations WHERE repo_id = ?
          AND status IN ('planned','running','partial','needs_attention') LIMIT 1
        """,
        (repo_id,),
    ):
        blockers.append("pending_operation")
    return blockers


def _remove_empty_temporary_scope(
    connection: Any,
    *,
    session: Any,
    request: dict[str, Any],
    timestamp: str,
) -> dict[str, Any]:
    repo_id = str(session["repo_id"])
    root_repo_id = str(session["root_repo_id"])
    if request.get("temporary_repo") is None or repo_id == root_repo_id:
        return {"removed": False, "reason": "root_repository_scope_retained"}
    scope = connection.execute(
        """
        SELECT family_id, project_kind FROM repository_scopes WHERE repo_id = ?
        """,
        (repo_id,),
    ).fetchone()
    if scope is None:
        return {"removed": False, "reason": "temporary_scope_already_absent"}
    if (
        str(scope["family_id"]) != str(session["family_id"])
        or str(scope["project_kind"]) != "temporary"
    ):
        raise RuntimeCatalogCleanupError(
            "runtime temporary repository scope changed before cleanup"
        )
    blockers = _empty_temporary_scope_blockers(
        connection, session_id=str(session["session_id"]), repo_id=repo_id
    )
    if blockers:
        return {
            "removed": False,
            "reason": "temporary_scope_not_empty",
            "blockers": sorted(set(blockers)),
        }
    changed = connection.execute(
        """
        UPDATE repository_installations
        SET status = 'disabled', startup_fenced = 1,
            generation = generation + 1, disabled_at = ?,
            reason = 'temporary runtime catalog emptied', actor = ?,
            updated_at = ?
        WHERE repo_id = ? AND status = 'installed' AND startup_fenced = 0
        """,
        (timestamp, str(request.get("agent") or "runtime-cleanup"), timestamp, repo_id),
    ).rowcount
    if changed != 1:
        raise RuntimeCatalogCleanupError(
            "empty temporary repository could not be startup-fenced before hiding"
        )
    return {
        "removed": True,
        "repo_id": repo_id,
        "repository_disabled": True,
        "reinstall_required": True,
        "scope_identity_retained": True,
    }


def _finalize_active_catalog_cleanup(
    connection: Any,
    *,
    session_id: str,
    request: dict[str, Any],
    resources: list[dict[str, Any]],
    cleanup_result: dict[str, Any],
    timestamp: str,
) -> dict[str, Any]:
    session = connection.execute(
        """
        SELECT session_id, family_id, root_repo_id, repo_id, result_json
        FROM runtime_sessions WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    if session is None:
        raise RuntimeCatalogCleanupError("runtime session disappeared during cleanup")
    removed = [
        resource
        for resource in resources
        if str(resource.get("cleanup_disposition") or "") == "removed"
    ]
    retained = [
        {
            "resource_kind": str(resource["resource_kind"]),
            "resource_id": str(resource["resource_id"]),
            "ownership": "borrowed",
            "active_catalog_deleted": False,
            "reason": "preexisting_resource_retained",
        }
        for resource in resources
        if str(resource.get("cleanup_disposition") or "") == "retained"
    ]
    if any(str(item.get("resource_kind")) != "service" for item in removed):
        raise RuntimeCatalogCleanupError(
            "current runtime API cannot classify Docker/database targets as created",
            result=cleanup_result,
        )
    removed_evidence = [
        _delete_created_service_catalog(
            connection,
            session=session,
            request=request,
            resource=resource,
            cleanup_result=cleanup_result,
        )
        for resource in removed
    ]
    temporary_scope = _remove_empty_temporary_scope(
        connection,
        session=session,
        request=request,
        timestamp=timestamp,
    )
    changed = bool(removed_evidence or temporary_scope.get("removed"))
    if changed:
        connection.execute(
            """
            UPDATE schema_metadata
            SET state_revision = state_revision + 1, updated_at = ?
            WHERE singleton = 1
            """,
            (timestamp,),
        )
    return {
        "status": "completed",
        "resources": removed_evidence + retained,
        "temporary_scope": temporary_scope,
    }


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _process_identity(pid: int) -> str | None:
    if pid <= 1:
        return None
    if sys.platform.startswith("linux"):
        try:
            stat_text = (Path("/proc") / str(pid) / "stat").read_text(
                encoding="utf-8"
            )
        except OSError:
            return None
        _prefix, separator, suffix = stat_text.rpartition(") ")
        fields = suffix.split() if separator else []
        if len(fields) <= 19 or fields[0] == "Z":
            return None
        return "linux-start:" + fields[19]
    try:
        completed = subprocess.run(
            ["/bin/ps", "-o", "state=,lstart=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        return None
    state, separator, started = value.partition(" ")
    if not separator or state.startswith("Z") or not started.strip():
        return None
    return "ps-start:" + started.strip()


def create_runtime_session(
    store: Any,
    *,
    family_id: str,
    root_repo_id: str,
    repo_id: str,
    request: dict[str, Any],
    timestamp: str | None = None,
) -> str:
    created_at = timestamp or utc_timestamp()
    ttl_seconds = request.get("ttl_seconds")
    expires_at = None
    if ttl_seconds is not None:
        expires_at = (
            _parse_timestamp(created_at) + timedelta(seconds=int(ttl_seconds))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = str(uuid.uuid4())
    with store.immediate_transaction() as connection:
        changed = connection.execute(
            """
            INSERT INTO runtime_sessions(
                session_id, family_id, root_repo_id, repo_id, action,
                purpose, ttl_seconds, expires_at, kill_after_run, status,
                actor, request_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?)
            """,
            (
                session_id,
                family_id,
                root_repo_id,
                repo_id,
                request["action"],
                request["purpose"],
                ttl_seconds,
                expires_at,
                int(request["kill_after_run"]),
                request["agent"],
                canonical_json(redact_runtime_request(request)),
                created_at,
                created_at,
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError(
                f"runtime session {session_id} changed before completion"
            )
    return session_id


def mark_runtime_session_started(
    store: Any, session_id: str, *, timestamp: str | None = None
) -> None:
    started_at = timestamp or utc_timestamp()
    owner_pid = os.getpid()
    owner_identity = _process_identity(owner_pid)
    if owner_identity is None:
        raise RuntimeError("runtime execution owner identity is unobservable")
    with store.immediate_transaction() as connection:
        changed = connection.execute(
            """
            UPDATE runtime_sessions
            SET started_at = COALESCE(started_at, ?), updated_at = ?,
                execution_owner_pid = ?, execution_owner_identity = ?
            WHERE session_id = ? AND status = 'planned'
            """,
            (started_at, started_at, owner_pid, owner_identity, session_id),
        ).rowcount
        if changed != 1:
            raise RuntimeError(f"runtime session {session_id} is not planned")


def link_runtime_resource(
    store: Any,
    *,
    session_id: str,
    resource_kind: str,
    resource_id: str,
    cleanup_disposition: str,
    identity: dict[str, Any] | None = None,
    immutable_fingerprint: str | None = None,
    timestamp: str | None = None,
) -> None:
    if cleanup_disposition not in {"removed", "retained"}:
        raise ValueError("runtime cleanup disposition must be removed or retained")
    if resource_kind not in {"service", "docker", "database_stack"}:
        raise ValueError("runtime resource kind is unsupported")
    if resource_kind != "service" and cleanup_disposition == "removed":
        raise ValueError(
            "current runtime API targets pre-existing Docker/database resources; "
            "their cleanup disposition must be retained"
        )
    linked_at = timestamp or utc_timestamp()
    identity_fingerprint = immutable_fingerprint or (
        "sha256:"
        + fingerprint(
            identity
            or {
                "session_id": session_id,
                "resource_kind": resource_kind,
                "resource_id": resource_id,
            }
        )
    )
    with store.immediate_transaction() as connection:
        changed = connection.execute(
            """
            INSERT INTO runtime_session_resources(
                session_id, resource_kind, resource_id, immutable_fingerprint,
                identity_json, cleanup_disposition, cleanup_state,
                linked_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
            ON CONFLICT(session_id, resource_kind, resource_id) DO UPDATE SET
                immutable_fingerprint = excluded.immutable_fingerprint,
                identity_json = excluded.identity_json,
                cleanup_disposition = excluded.cleanup_disposition,
                cleanup_state = 'active', cleanup_error_json = NULL,
                cleaned_at = NULL, updated_at = excluded.updated_at
            """,
            (
                session_id,
                resource_kind,
                resource_id,
                identity_fingerprint,
                None if identity is None else canonical_json(identity),
                cleanup_disposition,
                linked_at,
                linked_at,
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError(
                f"runtime session {session_id} changed before completion"
            )


def finish_runtime_session(
    store: Any,
    session_id: str,
    *,
    succeeded: bool,
    result: dict[str, Any] | None,
    keep_running_until_ttl: bool,
    redaction_source: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> None:
    finished_at = timestamp or utc_timestamp()
    status = "running" if succeeded and keep_running_until_ttl else (
        "succeeded" if succeeded else "failed"
    )
    with store.immediate_transaction() as connection:
        changed = connection.execute(
            """
            UPDATE runtime_sessions
            SET status = ?, result_json = ?, finished_at = ?, updated_at = ?
            WHERE session_id = ?
              AND status IN ('planned', 'running', 'succeeded', 'cleanup_pending')
            """,
            (
                status,
                (
                    None
                    if result is None
                    else canonical_json(
                        redact_runtime_value(result, request=redaction_source)
                    )
                ),
                finished_at,
                finished_at,
                session_id,
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError(
                f"runtime session {session_id} changed before completion"
            )


def _claim_cleanup(
    store: Any,
    session_id: str,
    *,
    timestamp: str,
    allow_unexpired: bool,
) -> tuple[str, dict[str, Any], list[dict[str, Any]]] | None:
    claim_id = str(uuid.uuid4())
    stale_before = (
        _parse_timestamp(timestamp)
        - timedelta(seconds=_RECLAIM_CLEANING_AFTER_SECONDS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    claim_owner_pid = os.getpid()
    claim_owner_identity = _process_identity(claim_owner_pid)
    if claim_owner_identity is None:
        raise RuntimeError("runtime cleanup owner identity is unobservable")
    with store.read_transaction() as connection:
        owner = connection.execute(
            """
            SELECT status, execution_owner_pid, execution_owner_identity,
                   cleanup_owner_pid, cleanup_owner_identity
            FROM runtime_sessions WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
    execution_abandoned = False
    cleanup_owner_alive = False
    observed_cleanup_pid: int | None = None
    observed_cleanup_identity: str | None = None
    owner_pid: int | None = None
    owner_identity: str | None = None
    if owner is not None and str(owner["status"]) == "planned":
        owner_pid = (
            None
            if owner["execution_owner_pid"] is None
            else int(owner["execution_owner_pid"])
        )
        owner_identity = (
            None
            if owner["execution_owner_identity"] is None
            else str(owner["execution_owner_identity"])
        )
        if owner_pid is None or owner_identity is None:
            return None
        execution_abandoned = _process_identity(owner_pid) != owner_identity
    if owner is not None and str(owner["status"]) == "cleaning":
        cleanup_pid = owner["cleanup_owner_pid"]
        cleanup_identity = owner["cleanup_owner_identity"]
        observed_cleanup_pid = None if cleanup_pid is None else int(cleanup_pid)
        observed_cleanup_identity = (
            None if cleanup_identity is None else str(cleanup_identity)
        )
        cleanup_owner_alive = bool(
            cleanup_pid is not None
            and cleanup_identity is not None
            and _process_identity(int(cleanup_pid)) == str(cleanup_identity)
        )
    with store.immediate_transaction() as connection:
        row = connection.execute(
            """
            SELECT request_json, status, expires_at, cleanup_started_at,
                   started_at, updated_at, execution_owner_pid,
                   execution_owner_identity, cleanup_claim_id,
                   cleanup_owner_pid, cleanup_owner_identity
            FROM runtime_sessions WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        status = str(row["status"])
        if status == "cleaning" and (
            row["cleanup_owner_pid"] != observed_cleanup_pid
            or row["cleanup_owner_identity"] != observed_cleanup_identity
        ):
            return None
        expired = row["expires_at"] is not None and str(row["expires_at"]) <= timestamp
        reclaim = (
            status == "cleaning"
            and not cleanup_owner_alive
            and row["cleanup_started_at"] is not None
            and str(row["cleanup_started_at"]) <= stale_before
        )
        abandoned_execution = bool(
            status == "planned"
            and execution_abandoned
            and row["execution_owner_pid"] == owner_pid
            and row["execution_owner_identity"] == owner_identity
        )
        eligible = (
            status in {"running", "failed", "cleanup_pending"}
            or reclaim
            or abandoned_execution
        )
        if not eligible or (not allow_unexpired and not expired):
            return None
        resources = [
            dict(resource)
            for resource in connection.execute(
                """
                SELECT rowid AS link_ordinal, resource_kind, resource_id,
                       immutable_fingerprint, identity_json,
                       cleanup_disposition,
                       cleanup_state, linked_at
                FROM runtime_session_resources
                WHERE session_id = ?
                  AND cleanup_state IN (
                      'active', 'cleanup_pending', 'failed', 'cleaning'
                  )
                ORDER BY resource_kind, resource_id
                """,
                (session_id,),
            )
        ]
        if not resources:
            return None
        superseded = any(
            connection.execute(
                """
                SELECT 1
                FROM runtime_session_resources newer
                JOIN runtime_sessions newer_session
                  ON newer_session.session_id = newer.session_id
                WHERE newer.resource_kind = ? AND newer.resource_id = ?
                  AND newer.rowid > ?
                  AND newer.cleanup_state IN (
                      'active', 'cleanup_pending', 'cleaning', 'failed'
                  )
                  AND newer_session.status NOT IN ('cleaned', 'expired')
                LIMIT 1
                """,
                (
                    resource["resource_kind"],
                    resource["resource_id"],
                    resource["link_ordinal"],
                ),
            ).fetchone()
            is not None
            for resource in resources
        )
        owned = [] if superseded else resources
        if superseded:
            connection.execute(
                """
                UPDATE runtime_session_resources
                SET cleanup_state = 'retained', updated_at = ?
                WHERE session_id = ? AND cleanup_state IN (
                    'active', 'cleanup_pending', 'failed', 'cleaning'
                )
                """,
                (timestamp, session_id),
            )
        changed = connection.execute(
            """
            UPDATE runtime_sessions
            SET status = 'cleaning', cleanup_claim_id = ?,
                cleanup_started_at = ?, cleanup_owner_pid = ?,
                cleanup_owner_identity = ?, updated_at = ?
            WHERE session_id = ? AND status = ?
              AND cleanup_claim_id IS ?
              AND cleanup_owner_pid IS ?
              AND cleanup_owner_identity IS ?
            """,
            (
                claim_id,
                timestamp,
                claim_owner_pid,
                claim_owner_identity,
                timestamp,
                session_id,
                status,
                row["cleanup_claim_id"],
                row["cleanup_owner_pid"],
                row["cleanup_owner_identity"],
            ),
        ).rowcount
        if changed != 1:
            return None
        connection.execute(
            """
            UPDATE runtime_session_resources
            SET cleanup_state = 'cleaning', updated_at = ?
            WHERE session_id = ? AND cleanup_state IN ('active', 'cleanup_pending', 'failed')
            """,
            (timestamp, session_id),
        )
        request = json.loads(str(row["request_json"]))
    return claim_id, request, owned


def cleanup_runtime_session(
    store: Any,
    session_id: str,
    *,
    cleanup: Callable[[dict[str, Any], list[dict[str, Any]]], dict[str, Any]],
    expired: bool,
    allow_unexpired: bool = False,
    timestamp: str | None = None,
) -> dict[str, Any] | None:
    cleanup_at = timestamp or utc_timestamp()
    claimed = _claim_cleanup(
        store, session_id, timestamp=cleanup_at, allow_unexpired=allow_unexpired
    )
    if claimed is None:
        return None
    claim_id, request, resources = claimed
    try:
        if resources:
            result = _verified_cleanup_result(cleanup(request, resources))
        else:
            result = {
                "ok": True,
                "state": "removed",
                "classification": "superseded_by_newer_runtime_session",
            }
    except BaseException as error:
        _cleanup_failure(
            store,
            session_id=session_id,
            claim_id=claim_id,
            error=error,
        )
        raise
    cleaned_at = utc_timestamp()
    final_status = "expired" if expired else "cleaned"
    try:
        with store.immediate_transaction() as connection:
            claim = connection.execute(
                """
                SELECT result_json FROM runtime_sessions
                WHERE session_id = ? AND cleanup_claim_id = ? AND status = 'cleaning'
                """,
                (session_id, claim_id),
            ).fetchone()
            if claim is None:
                raise RuntimeError(
                    f"runtime session {session_id} cleanup claim changed before commit"
                )
            connection.execute(
                """
                UPDATE runtime_session_resources
                SET cleanup_state = cleanup_disposition,
                    cleanup_error_json = NULL,
                    cleaned_at = ?, updated_at = ?
                WHERE session_id = ? AND cleanup_state = 'cleaning'
                """,
                (cleaned_at, cleaned_at, session_id),
            )
            catalog_cleanup = _finalize_active_catalog_cleanup(
                connection,
                session_id=session_id,
                request=request,
                resources=resources,
                cleanup_result=result,
                timestamp=cleaned_at,
            )
            persisted_result = (
                json.loads(str(claim["result_json"]))
                if claim["result_json"] is not None
                else {}
            )
            if not isinstance(persisted_result, dict):
                persisted_result = {"action_result": persisted_result}
            persisted_result["catalog_cleanup"] = catalog_cleanup
            changed = connection.execute(
                """
                UPDATE runtime_sessions
                SET status = ?, result_json = ?, cleanup_error_json = NULL,
                    cleaned_at = ?, updated_at = ?
                WHERE session_id = ? AND cleanup_claim_id = ? AND status = 'cleaning'
                """,
                (
                    final_status,
                    canonical_json(persisted_result),
                    cleaned_at,
                    cleaned_at,
                    session_id,
                    claim_id,
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError(
                    f"runtime session {session_id} cleanup claim changed before commit"
                )
    except BaseException as error:
        _cleanup_failure(
            store,
            session_id=session_id,
            claim_id=claim_id,
            error=error,
        )
        raise
    result = {**result, "catalog_cleanup": catalog_cleanup}
    return {"session_id": session_id, "status": final_status, "result": result}


def reap_expired_runtime_sessions(
    store: Any,
    *,
    cleanup: Callable[[dict[str, Any], list[dict[str, Any]]], dict[str, Any]],
    timestamp: str | None = None,
) -> list[dict[str, Any]]:
    observed_at = timestamp or utc_timestamp()
    with store.read_transaction() as connection:
        session_ids = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT session_id FROM runtime_sessions
                WHERE expires_at IS NOT NULL AND expires_at <= ?
                  AND (
                      status IN ('running', 'failed', 'cleanup_pending', 'cleaning')
                      OR (status = 'planned' AND started_at IS NOT NULL)
                  )
                  AND EXISTS (
                      SELECT 1 FROM runtime_session_resources resource
                      WHERE resource.session_id = runtime_sessions.session_id
                        AND resource.cleanup_state IN (
                            'active', 'cleanup_pending', 'failed', 'cleaning'
                        )
                  )
                ORDER BY expires_at, session_id
                """,
                (observed_at,),
            )
        ]
    results: list[dict[str, Any]] = []
    for session_id in session_ids:
        try:
            item = cleanup_runtime_session(
                store,
                session_id,
                cleanup=cleanup,
                expired=True,
                timestamp=observed_at,
            )
        except BaseException as error:
            results.append(
                {
                    "session_id": session_id,
                    "status": "cleanup_pending",
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }
            )
        else:
            if item is not None:
                results.append(item)
    return results


def next_runtime_cleanup_at(
    store: Any, *, timestamp: str | None = None
) -> str | None:
    """Return the next useful cleanup deadline without polling host state."""

    observed_at = timestamp or utc_timestamp()
    now_value = _parse_timestamp(observed_at)
    candidates: list[datetime] = []
    with store.read_transaction() as connection:
        rows = list(
            connection.execute(
                """
                SELECT status, expires_at, updated_at, cleanup_started_at,
                       execution_owner_pid, execution_owner_identity,
                       cleanup_owner_pid, cleanup_owner_identity
                FROM runtime_sessions session
                WHERE expires_at IS NOT NULL
                  AND status IN (
                      'planned', 'running', 'failed',
                      'cleanup_pending', 'cleaning'
                  )
                  AND EXISTS (
                      SELECT 1 FROM runtime_session_resources resource
                      WHERE resource.session_id = session.session_id
                        AND resource.cleanup_state IN (
                            'active', 'cleanup_pending', 'failed', 'cleaning'
                        )
                  )
                ORDER BY expires_at, session_id
                """
            )
        )
    for row in rows:
        status = str(row["status"])
        expiry = _parse_timestamp(str(row["expires_at"]))
        if status == "planned":
            pid = row["execution_owner_pid"]
            identity = row["execution_owner_identity"]
            if (
                pid is not None
                and identity is not None
                and _process_identity(int(pid)) == str(identity)
            ):
                continue
        if status == "cleaning":
            cleanup_pid = row["cleanup_owner_pid"]
            cleanup_identity = row["cleanup_owner_identity"]
            if (
                cleanup_pid is not None
                and cleanup_identity is not None
                and _process_identity(int(cleanup_pid))
                == str(cleanup_identity)
            ):
                continue
        if status in {"cleanup_pending", "cleaning"}:
            basis = row["cleanup_started_at"] or row["updated_at"]
            retry = _parse_timestamp(str(basis)) + timedelta(
                seconds=_RECLAIM_CLEANING_AFTER_SECONDS
            )
            expiry = max(expiry, retry)
        candidates.append(max(now_value, expiry))
    if not candidates:
        return None
    return min(candidates).strftime("%Y-%m-%dT%H:%M:%SZ")
