"""Durable client-side linkage for broker leases and assignments.

The service-owned broker remains the host-global authority.  Each user store
records how a broker reservation is attached to its local compatibility lease
or assignment so failures can be rolled back or reconciled without guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from .broker import BrokerClient, BrokerOperation, BrokerRequest
from .broker_profile import BrokerClientProfile, BrokerRepositoryProfile
from .repository_lifecycle import ResourceKind
from .sqlite_lifecycle import SQLiteLifecyclePersistence
from .store import (
    AccountStore,
    canonical_json,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)


@dataclass(frozen=True)
class BrokerLink:
    link_id: str
    repo_id: str
    server_definition_id: str
    broker_resource_id: str
    local_resource_id: Optional[str]
    port: int
    status: str
    broker_operation_id: str
    release_operation_id: Optional[str]
    account_id: str
    broker_socket: str
    broker_service_uid: int
    broker_socket_gid: int
    broker_socket_mode: int
    broker_database_generation: str


class BrokerLinkStore:
    def __init__(self, store: AccountStore) -> None:
        self._store = store

    def reserve_lease(
        self,
        *,
        profile: BrokerClientProfile,
        repository: BrokerRepositoryProfile,
        server_name: str,
        server_definition_id: str,
        broker_lease_id: str,
        port: int,
        protocol: str,
        operation_id: str,
        expires_at: str | None,
    ) -> BrokerLink:
        self._ensure_server(repository, server_name, server_definition_id)
        timestamp = utc_timestamp()
        link_id = deterministic_id("broker-lease-link", broker_lease_id)
        with self._store.immediate_transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM broker_lease_links WHERE broker_lease_id = ?",
                (broker_lease_id,),
            ).fetchone()
            if existing is not None:
                _require_same_lease(
                    existing,
                    repository=repository,
                    server_definition_id=server_definition_id,
                    port=port,
                    operation_id=operation_id,
                )
                return _lease_link(existing)
            connection.execute(
                """
                INSERT INTO broker_lease_links(
                    link_id, repo_id, server_definition_id, broker_lease_id,
                    account_id, broker_socket, broker_service_uid,
                    broker_socket_gid, broker_socket_mode,
                    broker_database_generation, port, protocol, status,
                    broker_operation_id, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?, ?)
                """,
                (
                    link_id,
                    repository.repo_id,
                    server_definition_id,
                    broker_lease_id,
                    profile.account_id,
                    str(profile.service.socket_path),
                    profile.service.service_uid,
                    profile.service.socket_gid,
                    profile.service.socket_mode,
                    profile.service.database_generation,
                    port,
                    protocol,
                    operation_id,
                    expires_at,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM broker_lease_links WHERE link_id = ?", (link_id,)
            ).fetchone()
        return _lease_link(row)

    def bind_local_lease(self, link_id: str, local_lease_id: str) -> BrokerLink:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            changed = connection.execute(
                """
                UPDATE broker_lease_links
                SET local_lease_id = ?, status = 'active', updated_at = ?,
                    last_error_code = NULL, last_error_message = NULL
                WHERE link_id = ? AND status IN ('reserved','active')
                  AND (local_lease_id IS NULL OR local_lease_id = ?)
                """,
                (local_lease_id, timestamp, link_id, local_lease_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("broker lease link is not bindable")
            row = connection.execute(
                "SELECT * FROM broker_lease_links WHERE link_id = ?", (link_id,)
            ).fetchone()
        return _lease_link(row)

    def lease_for_local(self, local_lease_id: str) -> BrokerLink | None:
        with self._store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM broker_lease_links
                WHERE local_lease_id = ?
                  AND status IN ('active','release_pending','rollback_failed','reconciliation_required')
                """,
                (local_lease_id,),
            ).fetchone()
        return None if row is None else _lease_link(row)

    def lease_for_server(
        self, repo_id: str, server_definition_id: str
    ) -> BrokerLink | None:
        with self._store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM broker_lease_links
                WHERE repo_id = ? AND server_definition_id = ?
                  AND status IN ('reserved','active','release_pending','rollback_failed','reconciliation_required')
                ORDER BY created_at DESC LIMIT 1
                """,
                (repo_id, server_definition_id),
            ).fetchone()
        return None if row is None else _lease_link(row)

    def begin_lease_release(self, link_id: str, operation_id: str) -> BrokerLink:
        return self._begin_release("broker_lease_links", link_id, operation_id, _lease_link)

    def complete_lease_release(self, link_id: str) -> BrokerLink:
        return self._complete_release("broker_lease_links", link_id, _lease_link)

    def fail_lease_release(
        self,
        link_id: str,
        *,
        operation_id: str,
        error_code: str,
        error_message: str,
        rollback: bool,
    ) -> BrokerLink:
        return self._fail_release(
            "broker_lease_links",
            "lease",
            link_id,
            operation_id=operation_id,
            error_code=error_code,
            error_message=error_message,
            rollback=rollback,
            converter=_lease_link,
        )

    def reserve_assignment(
        self,
        *,
        profile: BrokerClientProfile,
        repository: BrokerRepositoryProfile,
        server_name: str,
        server_definition_id: str,
        broker_assignment_id: str,
        port: int,
        operation_id: str,
    ) -> BrokerLink:
        self._ensure_server(repository, server_name, server_definition_id)
        timestamp = utc_timestamp()
        link_id = deterministic_id("broker-assignment-link", broker_assignment_id)
        with self._store.immediate_transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM broker_assignment_links WHERE broker_assignment_id = ?",
                (broker_assignment_id,),
            ).fetchone()
            if existing is not None:
                _require_same_assignment(
                    existing,
                    repository=repository,
                    server_definition_id=server_definition_id,
                    port=port,
                    operation_id=operation_id,
                )
                return _assignment_link(existing)
            connection.execute(
                """
                INSERT INTO broker_assignment_links(
                    link_id, repo_id, server_definition_id, broker_assignment_id,
                    account_id, broker_socket, broker_service_uid,
                    broker_socket_gid, broker_socket_mode,
                    broker_database_generation, port, status,
                    broker_operation_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?)
                """,
                (
                    link_id,
                    repository.repo_id,
                    server_definition_id,
                    broker_assignment_id,
                    profile.account_id,
                    str(profile.service.socket_path),
                    profile.service.service_uid,
                    profile.service.socket_gid,
                    profile.service.socket_mode,
                    profile.service.database_generation,
                    port,
                    operation_id,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM broker_assignment_links WHERE link_id = ?", (link_id,)
            ).fetchone()
        return _assignment_link(row)

    def bind_local_assignment(
        self, link_id: str, local_assignment_id: str
    ) -> BrokerLink:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            changed = connection.execute(
                """
                UPDATE broker_assignment_links
                SET local_assignment_id = ?, status = 'active', updated_at = ?,
                    last_error_code = NULL, last_error_message = NULL
                WHERE link_id = ? AND status IN ('reserved','active')
                  AND (local_assignment_id IS NULL OR local_assignment_id = ?)
                """,
                (local_assignment_id, timestamp, link_id, local_assignment_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("broker assignment link is not bindable")
            row = connection.execute(
                "SELECT * FROM broker_assignment_links WHERE link_id = ?", (link_id,)
            ).fetchone()
        return _assignment_link(row)

    def assignment_for_server(
        self, repo_id: str, server_definition_id: str
    ) -> BrokerLink | None:
        with self._store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM broker_assignment_links
                WHERE repo_id = ? AND server_definition_id = ?
                  AND status IN ('reserved','active','release_pending','rollback_failed','reconciliation_required')
                """,
                (repo_id, server_definition_id),
            ).fetchone()
        return None if row is None else _assignment_link(row)

    def begin_assignment_release(self, link_id: str, operation_id: str) -> BrokerLink:
        return self._begin_release(
            "broker_assignment_links", link_id, operation_id, _assignment_link
        )

    def complete_assignment_release(self, link_id: str) -> BrokerLink:
        return self._complete_release(
            "broker_assignment_links", link_id, _assignment_link
        )

    def fail_assignment_release(
        self,
        link_id: str,
        *,
        operation_id: str,
        error_code: str,
        error_message: str,
        rollback: bool,
    ) -> BrokerLink:
        return self._fail_release(
            "broker_assignment_links",
            "assignment",
            link_id,
            operation_id=operation_id,
            error_code=error_code,
            error_message=error_message,
            rollback=rollback,
            converter=_assignment_link,
        )

    def record_and_apply_lifecycle(
        self,
        *,
        profile: BrokerClientProfile,
        repository: BrokerRepositoryProfile,
        operation: BrokerOperation,
        resource_id: str,
        operation_id: str,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Durably mirror one completed service-owned lifecycle result locally."""

        mirrored = {
            BrokerOperation.REPOSITORY_REMOVE,
            BrokerOperation.REPOSITORY_REINSTALL,
            BrokerOperation.RESOURCE_ATTACH,
            BrokerOperation.RESOURCE_RETIRE,
        }
        if operation not in mirrored:
            raise ValueError("broker lifecycle operation does not require a local mirror")
        if repository.repo_id != str(result.get("repo_id") or repository.repo_id):
            raise RuntimeError("broker lifecycle result belongs to another repository")
        timestamp = utc_timestamp()
        link_id = deterministic_id("broker-lifecycle-link", operation_id)
        with self._store.immediate_transaction() as connection:
            local_repo = connection.execute(
                """
                SELECT repo_id, canonical_root FROM repositories
                WHERE repo_id = ? AND canonical_root = ?
                """,
                (repository.repo_id, repository.canonical_root),
            ).fetchone()
            if local_repo is None:
                raise RuntimeError(
                    "local normalized repository does not match broker enrollment"
                )
            existing = connection.execute(
                "SELECT * FROM broker_lifecycle_links WHERE link_id = ?",
                (link_id,),
            ).fetchone()
            arguments_json = canonical_json(dict(arguments))
            result_json = canonical_json(dict(result))
            if existing is not None:
                if (
                    str(existing["repo_id"]) != repository.repo_id
                    or str(existing["resource_id"]) != resource_id
                    or str(existing["operation"]) != operation.value
                    or str(existing["broker_operation_id"]) != operation_id
                    or str(existing["arguments_json"]) != arguments_json
                    or str(existing["result_json"]) != result_json
                ):
                    raise RuntimeError(
                        "broker lifecycle operation identity conflicts with its saved mirror"
                    )
                if str(existing["status"]) == "applied":
                    return self._lifecycle_link_payload(existing)
            else:
                connection.execute(
                    """
                    INSERT INTO broker_lifecycle_links(
                        link_id, repo_id, resource_id, operation,
                        broker_operation_id, broker_plan_id, account_id,
                        broker_socket, broker_service_uid, broker_socket_gid,
                        broker_socket_mode, broker_database_generation,
                        arguments_json, result_json, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'pending', ?, ?)
                    """,
                    (
                        link_id,
                        repository.repo_id,
                        resource_id,
                        operation.value,
                        operation_id,
                        result.get("plan_id"),
                        profile.account_id,
                        str(profile.service.socket_path),
                        profile.service.service_uid,
                        profile.service.socket_gid,
                        profile.service.socket_mode,
                        profile.service.database_generation,
                        arguments_json,
                        result_json,
                        timestamp,
                        timestamp,
                    ),
                )
        try:
            self._apply_lifecycle_link(link_id)
        except BaseException as error:
            message = f"{type(error).__name__}: {error}"
            with self._store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_lifecycle_links
                    SET status = 'reconciliation_required',
                        last_error_code = 'local_lifecycle_mirror_failed',
                        last_error_message = ?, attempts = attempts + 1,
                        updated_at = ?
                    WHERE link_id = ? AND status != 'applied'
                    """,
                    (message, utc_timestamp(), link_id),
                )
            raise RuntimeError(
                "service lifecycle completed, but its local normalized mirror requires reconciliation: "
                + message
            ) from error
        with self._store.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM broker_lifecycle_links WHERE link_id = ?", (link_id,)
            ).fetchone()
        return self._lifecycle_link_payload(row)

    def pending_lifecycle_reconciliations(
        self, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("reconciliation limit must be from 1 through 1000")
        with self._store.read_transaction() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM broker_lifecycle_links
                    WHERE status IN ('pending','reconciliation_required')
                    ORDER BY created_at, link_id LIMIT ?
                    """,
                    (limit,),
                )
            ]

    def pending_reconciliations(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("reconciliation limit must be from 1 through 1000")
        with self._store.read_transaction() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT reconciliation_id, link_kind, link_id, repo_id,
                           resource_id, requested_action, operation_id,
                           error_code, error_message, attempts, created_at,
                           updated_at
                    FROM broker_reconciliation_queue
                    WHERE status = 'pending'
                    ORDER BY created_at, reconciliation_id
                    LIMIT ?
                    """,
                    (limit,),
                )
            ]

    def reconcile_pending(
        self,
        *,
        limit: int = 100,
        caller: Callable[[BrokerLink, BrokerRequest], Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Replay exact idempotent broker releases and finish local linkage."""

        invoke = _call_saved_broker if caller is None else caller
        outcomes: list[dict[str, Any]] = []
        for queued in self.pending_reconciliations(limit=limit):
            link_kind = str(queued["link_kind"])
            link_id = str(queued["link_id"] or "")
            if link_kind not in {"lease", "assignment"} or not link_id:
                self._mark_operator_required(
                    str(queued["reconciliation_id"]),
                    "unsupported_reconciliation",
                    "Only exact saved lease and assignment releases can be replayed automatically.",
                )
                outcomes.append(
                    {
                        "reconciliation_id": queued["reconciliation_id"],
                        "status": "operator_required",
                        "code": "unsupported_reconciliation",
                    }
                )
                continue
            try:
                link = self._link_by_id(link_kind, link_id)
                if link_kind == "lease":
                    pending = self.begin_lease_release(
                        link_id, str(queued["operation_id"])
                    )
                    operation = BrokerOperation.PORT_RELEASE
                    resource_id = pending.broker_resource_id
                else:
                    pending = self.begin_assignment_release(
                        link_id, str(queued["operation_id"])
                    )
                    operation = BrokerOperation.PORT_UNASSIGN
                    resource_id = pending.server_definition_id
                operation_id = str(
                    pending.release_operation_id or queued["operation_id"]
                )
                request = BrokerRequest.create(
                    account_id=pending.account_id,
                    project_id=pending.repo_id,
                    resource_id=resource_id,
                    operation=operation,
                    operation_id=operation_id,
                    authority_generation=pending.broker_database_generation,
                )
                reply = invoke(pending, request)
                if not bool(reply.get("ok")):
                    error = reply.get("error")
                    error = error if isinstance(error, Mapping) else {}
                    raise RuntimeError(
                        f"{error.get('code') or 'broker_reconciliation_failed'}: "
                        f"{error.get('message') or 'Broker release failed.'}"
                    )
                result = reply.get("result")
                if not isinstance(result, Mapping) or result.get("status") != "released":
                    raise RuntimeError("invalid_reply: broker release lacked released status")
                self._complete_reconciled_release(link_kind, pending)
            except BaseException as error:
                message = f"{type(error).__name__}: {error}"
                if link_kind == "lease":
                    self.fail_lease_release(
                        link_id,
                        operation_id=str(queued["operation_id"]),
                        error_code="broker_reconciliation_failed",
                        error_message=message,
                        rollback=False,
                    )
                else:
                    self.fail_assignment_release(
                        link_id,
                        operation_id=str(queued["operation_id"]),
                        error_code="broker_reconciliation_failed",
                        error_message=message,
                        rollback=False,
                    )
                outcomes.append(
                    {
                        "reconciliation_id": queued["reconciliation_id"],
                        "status": "pending",
                        "error": message,
                    }
                )
            else:
                outcomes.append(
                    {
                        "reconciliation_id": queued["reconciliation_id"],
                        "status": "resolved",
                        "link_kind": link_kind,
                        "link_id": link_id,
                    }
                )
        remaining = max(0, limit - len(outcomes))
        lifecycle_rows = (
            self.pending_lifecycle_reconciliations(limit=remaining)
            if remaining
            else []
        )
        for queued in lifecycle_rows:
            link_id = str(queued["link_id"])
            try:
                self._apply_lifecycle_link(link_id)
            except BaseException as error:
                message = f"{type(error).__name__}: {error}"
                with self._store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE broker_lifecycle_links
                        SET status = CASE WHEN attempts >= 2
                                          THEN 'operator_required'
                                          ELSE 'reconciliation_required' END,
                            last_error_code = 'local_lifecycle_mirror_failed',
                            last_error_message = ?, attempts = attempts + 1,
                            updated_at = ?
                        WHERE link_id = ? AND status != 'applied'
                        """,
                        (message, utc_timestamp(), link_id),
                    )
                outcomes.append(
                    {
                        "reconciliation_id": link_id,
                        "status": (
                            "operator_required"
                            if int(queued["attempts"]) >= 2
                            else "pending"
                        ),
                        "error": message,
                    }
                )
            else:
                outcomes.append(
                    {
                        "reconciliation_id": link_id,
                        "status": "resolved",
                        "link_kind": "lifecycle",
                        "link_id": link_id,
                    }
                )
        return {
            "attempted": len(outcomes),
            "resolved": sum(item["status"] == "resolved" for item in outcomes),
            "pending": sum(item["status"] == "pending" for item in outcomes),
            "operator_required": sum(
                item["status"] == "operator_required" for item in outcomes
            ),
            "outcomes": outcomes,
        }

    def _apply_lifecycle_link(self, link_id: str) -> None:
        with self._store.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM broker_lifecycle_links WHERE link_id = ?",
                (link_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("saved broker lifecycle link no longer exists")
        if str(row["status"]) == "applied":
            return
        operation = BrokerOperation(str(row["operation"]))
        try:
            arguments = json.loads(str(row["arguments_json"]))
            result = json.loads(str(row["result_json"]))
        except json.JSONDecodeError as error:
            raise RuntimeError("saved broker lifecycle evidence is invalid JSON") from error
        if not isinstance(arguments, dict) or not isinstance(result, dict):
            raise RuntimeError("saved broker lifecycle evidence is not an object")
        if operation == BrokerOperation.REPOSITORY_REMOVE:
            self._mirror_repository_removal(row, arguments, result)
        elif operation == BrokerOperation.REPOSITORY_REINSTALL:
            self._mirror_repository_reinstall(row, arguments, result)
        elif operation == BrokerOperation.RESOURCE_ATTACH:
            self._mirror_resource_attach(row, arguments, result)
        elif operation == BrokerOperation.RESOURCE_RETIRE:
            self._mirror_resource_retirement(row, arguments, result)
        else:
            raise RuntimeError("saved broker lifecycle operation is unsupported")

    def _mirror_repository_removal(
        self, row: Any, arguments: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        status = str(result.get("status") or "")
        if status not in {"succeeded", "already_complete", "needs_attention"}:
            raise RuntimeError("broker repository removal did not reach a mirrorable state")
        repo_id = str(row["repo_id"])
        if result.get("repo_id") != repo_id:
            raise RuntimeError("broker repository removal result identity changed")
        timestamp = utc_timestamp()
        terminal = status in {"succeeded", "already_complete"}
        with self._store.immediate_transaction() as connection:
            installation = connection.execute(
                "SELECT status FROM repository_installations WHERE repo_id = ?",
                (repo_id,),
            ).fetchone()
            if installation is None:
                raise RuntimeError("local repository installation no longer exists")
            connection.execute(
                """
                UPDATE repository_installations
                SET status = ?, startup_fenced = 1,
                    generation = generation + CASE WHEN status != ? OR startup_fenced != 1 THEN 1 ELSE 0 END,
                    operation_id = NULL, disabled_at = CASE WHEN ? THEN ? ELSE disabled_at END,
                    reason = ?, actor = ?, updated_at = ?
                WHERE repo_id = ?
                """,
                (
                    "disabled" if terminal else "disabling",
                    "disabled" if terminal else "disabling",
                    int(terminal),
                    timestamp,
                    "broker service repository removal",
                    "broker:" + str(row["account_id"]),
                    timestamp,
                    repo_id,
                ),
            )
            if terminal:
                connection.execute(
                    """
                    UPDATE startup_policies
                    SET current_value = desired_disabled_value,
                        generation = generation + CASE WHEN current_value != desired_disabled_value THEN 1 ELSE 0 END,
                        updated_at = ? WHERE repo_id = ?
                    """,
                    (timestamp, repo_id),
                )
                connection.execute(
                    """
                    UPDATE leases SET status = 'released', deactivated_at = ?,
                        generation = generation + CASE WHEN status != 'released' THEN 1 ELSE 0 END,
                        updated_at = ? WHERE repo_id = ? AND status = 'active'
                    """,
                    (timestamp, timestamp, repo_id),
                )
                connection.execute(
                    """
                    UPDATE port_assignments SET status = 'inactive', deactivated_at = ?,
                        generation = generation + CASE WHEN status != 'inactive' THEN 1 ELSE 0 END,
                        updated_at = ? WHERE repo_id = ? AND status = 'active'
                    """,
                    (timestamp, timestamp, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_lease_links SET status = 'released', updated_at = ?
                    WHERE repo_id = ? AND status != 'released'
                    """,
                    (timestamp, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_assignment_links SET status = 'released', updated_at = ?
                    WHERE repo_id = ? AND status != 'released'
                    """,
                    (timestamp, repo_id),
                )
            self._record_lifecycle_mirror_operation(
                connection, row, arguments, result, timestamp=timestamp
            )
            self._mark_lifecycle_applied(connection, str(row["link_id"]), timestamp)

    def _mirror_repository_reinstall(
        self, row: Any, arguments: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        if (
            result.get("repo_id") != row["repo_id"]
            or result.get("status") != "installed"
            or result.get("started") is not False
        ):
            raise RuntimeError("broker repository reinstall result is invalid")
        persistence = SQLiteLifecyclePersistence(self._store)
        persistence.reinstall_repository(
            str(row["repo_id"]),
            actor="broker:" + str(row["account_id"]),
            reason=str(arguments["reason"]),
        )
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            self._record_lifecycle_mirror_operation(
                connection, row, arguments, result, timestamp=timestamp
            )
            self._mark_lifecycle_applied(connection, str(row["link_id"]), timestamp)

    def _mirror_resource_attach(
        self, row: Any, arguments: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        if (
            result.get("repo_id") != row["repo_id"]
            or result.get("resource_id") != row["resource_id"]
            or result.get("attached") is not True
            or result.get("started") is not False
        ):
            raise RuntimeError("broker resource attachment result is invalid")
        persistence = SQLiteLifecyclePersistence(self._store)
        exact = persistence.resolve_standalone_resource(
            ResourceKind(str(arguments["resource_kind"])),
            str(row["resource_id"]),
            str(arguments["control_binding_id"]),
        )
        _require_exact_arguments(exact, arguments)
        persistence.attach_resource(
            str(row["repo_id"]),
            exact,
            actor="broker:" + str(row["account_id"]),
            reason=str(arguments["reason"]),
        )
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            self._record_lifecycle_mirror_operation(
                connection, row, arguments, result, timestamp=timestamp
            )
            self._mark_lifecycle_applied(connection, str(row["link_id"]), timestamp)

    def _mirror_resource_retirement(
        self, row: Any, arguments: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        if (
            result.get("resource_id") != row["resource_id"]
            or result.get("status") not in {"succeeded", "already_complete"}
            or result.get("hidden") is not True
        ):
            raise RuntimeError("broker resource retirement result is invalid")
        resource_kind = str(arguments["resource_kind"])
        resource_id = str(row["resource_id"])
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            binding = connection.execute(
                """
                SELECT * FROM control_bindings
                WHERE binding_id = ? AND resource_kind = ? AND resource_id = ?
                """,
                (arguments["control_binding_id"], resource_kind, resource_id),
            ).fetchone()
            if binding is None:
                raise RuntimeError("local standalone control binding no longer exists")
            expected_ownership = "sha256:" + fingerprint(
                {
                    "binding_id": binding["binding_id"],
                    "resource_kind": binding["resource_kind"],
                    "resource_id": binding["resource_id"],
                    "source_id": binding["source_id"],
                    "capability": binding["capability"],
                    "provenance": binding["provenance"],
                    "authority_state": binding["authority_state"],
                    "generation": binding["generation"],
                }
            )
            if (
                str(arguments["ownership_fingerprint"]) != expected_ownership
                and str(binding["authority_state"]) != "retired"
            ):
                raise RuntimeError("local standalone controller identity changed")
            if connection.execute(
                """
                SELECT 1 FROM repository_memberships
                WHERE resource_kind = ? AND host_resource_id = ?
                """,
                (resource_kind, resource_id),
            ).fetchone() is not None:
                raise RuntimeError("local standalone resource became repository-owned")
            self._record_lifecycle_mirror_operation(
                connection, row, arguments, result, timestamp=timestamp
            )
            mirror_operation_id = deterministic_id(
                "broker-lifecycle-mirror-operation", row["broker_operation_id"]
            )
            connection.execute(
                """
                INSERT INTO resource_retirements(
                    host_resource_id, resource_kind, immutable_fingerprint,
                    status, operation_id, reason, actor, started_at,
                    retired_at, updated_at
                ) VALUES (?, ?, ?, 'retired', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_resource_id) DO UPDATE SET
                    status = 'retired', operation_id = excluded.operation_id,
                    retired_at = excluded.retired_at, updated_at = excluded.updated_at
                """,
                (
                    resource_id,
                    resource_kind,
                    arguments["immutable_fingerprint"],
                    mirror_operation_id,
                    "broker service standalone retirement",
                    "broker:" + str(row["account_id"]),
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                UPDATE startup_policies
                SET current_value = desired_disabled_value,
                    generation = generation + CASE WHEN current_value != desired_disabled_value THEN 1 ELSE 0 END,
                    updated_at = ?
                WHERE resource_kind = ? AND resource_id = ?
                """,
                (timestamp, resource_kind, resource_id),
            )
            connection.execute(
                """
                UPDATE control_bindings SET authority_state = 'retired',
                    generation = generation + CASE WHEN authority_state != 'retired' THEN 1 ELSE 0 END,
                    updated_at = ? WHERE binding_id = ?
                """,
                (timestamp, arguments["control_binding_id"]),
            )
            connection.execute(
                """
                UPDATE unassigned_resources SET status = 'retired', updated_at = ?
                WHERE resource_kind = ? AND resource_id = ? AND status = 'active'
                """,
                (timestamp, resource_kind, resource_id),
            )
            if resource_kind == "container":
                connection.execute(
                    """
                    UPDATE docker_observations SET lifecycle = 'stopped', sampled_at = ?,
                        observation_fingerprint = ? WHERE docker_resource_id = ?
                    """,
                    (
                        timestamp,
                        fingerprint({"broker_verified_retired": resource_id, "at": timestamp}),
                        resource_id,
                    ),
                )
            elif resource_kind == "server":
                connection.execute(
                    """
                    UPDATE server_observations SET lifecycle = 'stopped', pid = NULL,
                        stopped_at = ?, stopped_reason = 'broker service retirement',
                        sampled_at = ?, observation_fingerprint = ?
                    WHERE server_definition_id = ?
                    """,
                    (
                        timestamp,
                        timestamp,
                        fingerprint({"broker_verified_retired": resource_id, "at": timestamp}),
                        resource_id,
                    ),
                )
            self._mark_lifecycle_applied(connection, str(row["link_id"]), timestamp)

    @staticmethod
    def _record_lifecycle_mirror_operation(
        connection: Any,
        row: Any,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
        *,
        timestamp: str,
    ) -> None:
        operation_id = deterministic_id(
            "broker-lifecycle-mirror-operation", row["broker_operation_id"]
        )
        raw_status = str(result.get("status") or "")
        status = "needs_attention" if raw_status == "needs_attention" else "succeeded"
        connection.execute(
            """
            INSERT INTO operations(
                operation_id, repo_id, kind, status, phase, generation,
                request_fingerprint, owner_uid, actor, result_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'broker_mirrored', 0, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(operation_id) DO UPDATE SET
                status = excluded.status, result_json = excluded.result_json,
                updated_at = excluded.updated_at
            """,
            (
                operation_id,
                row["repo_id"],
                "broker.mirror." + str(row["operation"]),
                status,
                "sha256:" + fingerprint(dict(arguments)),
                os.geteuid(),
                "broker:" + str(row["account_id"]),
                canonical_json(dict(result)),
                timestamp,
                timestamp,
            ),
        )

    @staticmethod
    def _mark_lifecycle_applied(
        connection: Any, link_id: str, timestamp: str
    ) -> None:
        connection.execute(
            """
            UPDATE broker_lifecycle_links
            SET status = 'applied', last_error_code = NULL,
                last_error_message = NULL, applied_at = ?, updated_at = ?
            WHERE link_id = ?
            """,
            (timestamp, timestamp, link_id),
        )

    @staticmethod
    def _lifecycle_link_payload(row: Any) -> dict[str, Any]:
        return {
            "link_id": str(row["link_id"]),
            "operation": str(row["operation"]),
            "broker_operation_id": str(row["broker_operation_id"]),
            "status": str(row["status"]),
        }

    def _link_by_id(self, link_kind: str, link_id: str) -> BrokerLink:
        table = (
            "broker_lease_links"
            if link_kind == "lease"
            else "broker_assignment_links"
        )
        converter = _lease_link if link_kind == "lease" else _assignment_link
        with self._store.read_transaction() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE link_id = ?", (link_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("saved broker link no longer exists")
        return converter(row)

    def _complete_reconciled_release(
        self, link_kind: str, link: BrokerLink
    ) -> None:
        timestamp = utc_timestamp()
        link_table = (
            "broker_lease_links"
            if link_kind == "lease"
            else "broker_assignment_links"
        )
        local_table = "leases" if link_kind == "lease" else "port_assignments"
        local_id_column = "lease_id" if link_kind == "lease" else "assignment_id"
        local_status = "released" if link_kind == "lease" else "inactive"
        with self._store.immediate_transaction() as connection:
            if link.local_resource_id is not None:
                connection.execute(
                    f"""
                    UPDATE {local_table}
                    SET status = ?, deactivated_at = ?, updated_at = ?,
                        generation = generation + CASE WHEN status != ? THEN 1 ELSE 0 END
                    WHERE {local_id_column} = ?
                    """,
                    (
                        local_status,
                        timestamp,
                        timestamp,
                        local_status,
                        link.local_resource_id,
                    ),
                )
            changed = connection.execute(
                f"""
                UPDATE {link_table}
                SET status = 'released', updated_at = ?,
                    last_error_code = NULL, last_error_message = NULL
                WHERE link_id = ? AND status = 'release_pending'
                """,
                (timestamp, link.link_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("broker link release was not pending")
            connection.execute(
                """
                UPDATE broker_reconciliation_queue
                SET status = 'resolved', resolved_at = ?, updated_at = ?
                WHERE link_kind = ? AND link_id = ?
                  AND requested_action = 'release' AND status = 'pending'
                """,
                (timestamp, timestamp, link_kind, link.link_id),
            )

    def _mark_operator_required(
        self, reconciliation_id: str, code: str, message: str
    ) -> None:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE broker_reconciliation_queue
                SET status = 'operator_required', error_code = ?,
                    error_message = ?, attempts = attempts + 1,
                    updated_at = ?
                WHERE reconciliation_id = ? AND status = 'pending'
                """,
                (code, message, timestamp, reconciliation_id),
            )

    def _ensure_server(
        self,
        repository: BrokerRepositoryProfile,
        server_name: str,
        server_definition_id: str,
    ) -> None:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            repo = connection.execute(
                "SELECT repo_id FROM repositories WHERE repo_id = ? AND canonical_root = ?",
                (repository.repo_id, repository.canonical_root),
            ).fetchone()
            if repo is None:
                raise RuntimeError(
                    "local normalized repository does not match the root-provisioned broker enrollment"
                )
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, cwd,
                    definition_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(server_definition_id) DO UPDATE SET
                    updated_at = excluded.updated_at
                """,
                (
                    server_definition_id,
                    repository.repo_id,
                    server_name,
                    repository.canonical_root,
                    "sha256:" + fingerprint(
                        {
                            "repo_id": repository.repo_id,
                            "name": server_name,
                            "source": "root-provisioned-broker-profile",
                        }
                    ),
                    timestamp,
                    timestamp,
                ),
            )

    def _begin_release(
        self, table: str, link_id: str, operation_id: str, converter: Any
    ) -> BrokerLink:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            existing = connection.execute(
                f"SELECT status, release_operation_id FROM {table} WHERE link_id = ?",
                (link_id,),
            ).fetchone()
            if existing is None:
                raise RuntimeError("broker link does not exist")
            retained_operation_id = (
                str(existing["release_operation_id"])
                if existing["release_operation_id"] is not None
                else operation_id
            )
            changed = connection.execute(
                f"""
                UPDATE {table}
                SET status = 'release_pending', release_operation_id = ?, updated_at = ?
                WHERE link_id = ?
                  AND status IN ('reserved','active','release_pending','rollback_failed','reconciliation_required')
                """,
                (retained_operation_id, timestamp, link_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("broker link is not releasable")
            row = connection.execute(
                f"SELECT * FROM {table} WHERE link_id = ?", (link_id,)
            ).fetchone()
        return converter(row)

    def _complete_release(self, table: str, link_id: str, converter: Any) -> BrokerLink:
        timestamp = utc_timestamp()
        with self._store.immediate_transaction() as connection:
            changed = connection.execute(
                f"""
                UPDATE {table}
                SET status = 'released', updated_at = ?,
                    last_error_code = NULL, last_error_message = NULL
                WHERE link_id = ? AND status = 'release_pending'
                """,
                (timestamp, link_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("broker link release was not pending")
            connection.execute(
                """
                UPDATE broker_reconciliation_queue
                SET status = 'resolved', resolved_at = ?, updated_at = ?
                WHERE link_id = ? AND status = 'pending'
                """,
                (timestamp, timestamp, link_id),
            )
            row = connection.execute(
                f"SELECT * FROM {table} WHERE link_id = ?", (link_id,)
            ).fetchone()
        return converter(row)

    def _fail_release(
        self,
        table: str,
        link_kind: str,
        link_id: str,
        *,
        operation_id: str,
        error_code: str,
        error_message: str,
        rollback: bool,
        converter: Any,
    ) -> BrokerLink:
        timestamp = utc_timestamp()
        status = "rollback_failed" if rollback else "reconciliation_required"
        with self._store.immediate_transaction() as connection:
            row = connection.execute(
                f"SELECT repo_id, server_definition_id FROM {table} WHERE link_id = ?",
                (link_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("broker link does not exist")
            connection.execute(
                f"""
                UPDATE {table}
                SET status = ?, release_operation_id = COALESCE(release_operation_id, ?), last_error_code = ?,
                    last_error_message = ?, updated_at = ?
                WHERE link_id = ?
                """,
                (
                    status,
                    operation_id,
                    error_code,
                    error_message,
                    timestamp,
                    link_id,
                ),
            )
            reconciliation_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO broker_reconciliation_queue(
                    reconciliation_id, link_kind, link_id, repo_id, resource_id,
                    requested_action, operation_id, status, error_code,
                    error_message, attempts, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'release', ?, 'pending', ?, ?, 0, ?, ?)
                ON CONFLICT(link_kind, link_id, requested_action)
                WHERE status = 'pending'
                DO UPDATE SET error_code = excluded.error_code,
                              error_message = excluded.error_message,
                              attempts = broker_reconciliation_queue.attempts + 1,
                              updated_at = excluded.updated_at
                """,
                (
                    reconciliation_id,
                    link_kind,
                    link_id,
                    row["repo_id"],
                    row["server_definition_id"],
                    operation_id,
                    error_code,
                    error_message,
                    timestamp,
                    timestamp,
                ),
            )
            updated = connection.execute(
                f"SELECT * FROM {table} WHERE link_id = ?", (link_id,)
            ).fetchone()
        return converter(updated)


def _require_same_lease(
    row: Any,
    *,
    repository: BrokerRepositoryProfile,
    server_definition_id: str,
    port: int,
    operation_id: str,
) -> None:
    if (
        str(row["repo_id"]) != repository.repo_id
        or str(row["server_definition_id"]) != server_definition_id
        or int(row["port"]) != port
        or str(row["broker_operation_id"]) != operation_id
    ):
        raise RuntimeError("broker lease identity was reused with conflicting linkage")


def _call_saved_broker(
    link: BrokerLink, request: BrokerRequest
) -> Mapping[str, Any]:
    return BrokerClient(
        Path(link.broker_socket),
        expected_broker_uid=link.broker_service_uid,
        expected_socket_gid=link.broker_socket_gid,
        expected_socket_mode=link.broker_socket_mode,
    ).call(request)


def _require_same_assignment(
    row: Any,
    *,
    repository: BrokerRepositoryProfile,
    server_definition_id: str,
    port: int,
    operation_id: str,
) -> None:
    if (
        str(row["repo_id"]) != repository.repo_id
        or str(row["server_definition_id"]) != server_definition_id
        or int(row["port"]) != port
        or str(row["broker_operation_id"]) != operation_id
    ):
        raise RuntimeError(
            "broker assignment identity was reused with conflicting linkage"
        )


def _require_exact_arguments(exact: Any, arguments: Mapping[str, Any]) -> None:
    observed = (
        exact.kind.value,
        exact.control_binding_id,
        exact.immutable_fingerprint,
        exact.ownership_fingerprint,
    )
    expected = (
        str(arguments["resource_kind"]),
        str(arguments["control_binding_id"]),
        str(arguments["immutable_fingerprint"]),
        str(arguments["ownership_fingerprint"]),
    )
    if observed != expected:
        raise RuntimeError("local standalone resource identity changed")


def _lease_link(row: Any) -> BrokerLink:
    return BrokerLink(
        link_id=str(row["link_id"]),
        repo_id=str(row["repo_id"]),
        server_definition_id=str(row["server_definition_id"]),
        broker_resource_id=str(row["broker_lease_id"]),
        local_resource_id=(
            None if row["local_lease_id"] is None else str(row["local_lease_id"])
        ),
        port=int(row["port"]),
        status=str(row["status"]),
        broker_operation_id=str(row["broker_operation_id"]),
        release_operation_id=(
            None
            if row["release_operation_id"] is None
            else str(row["release_operation_id"])
        ),
        account_id=str(row["account_id"]),
        broker_socket=str(row["broker_socket"]),
        broker_service_uid=int(row["broker_service_uid"]),
        broker_socket_gid=int(row["broker_socket_gid"]),
        broker_socket_mode=int(row["broker_socket_mode"]),
        broker_database_generation=str(row["broker_database_generation"]),
    )


def _assignment_link(row: Any) -> BrokerLink:
    return BrokerLink(
        link_id=str(row["link_id"]),
        repo_id=str(row["repo_id"]),
        server_definition_id=str(row["server_definition_id"]),
        broker_resource_id=str(row["broker_assignment_id"]),
        local_resource_id=(
            None
            if row["local_assignment_id"] is None
            else str(row["local_assignment_id"])
        ),
        port=int(row["port"]),
        status=str(row["status"]),
        broker_operation_id=str(row["broker_operation_id"]),
        release_operation_id=(
            None
            if row["release_operation_id"] is None
            else str(row["release_operation_id"])
        ),
        account_id=str(row["account_id"]),
        broker_socket=str(row["broker_socket"]),
        broker_service_uid=int(row["broker_service_uid"]),
        broker_socket_gid=int(row["broker_socket_gid"]),
        broker_socket_mode=int(row["broker_socket_mode"]),
        broker_database_generation=str(row["broker_database_generation"]),
    )
