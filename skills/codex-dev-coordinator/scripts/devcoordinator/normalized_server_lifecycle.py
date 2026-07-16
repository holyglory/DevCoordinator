"""Typed normalized SQLite lifecycle services for ports and managed servers.

This module is deliberately independent of the legacy ``state.json`` shape.
Host observation (socket availability, process identity, health, and signals)
is performed by the caller outside SQLite write transactions; this module owns
only short, fingerprint-bound reservation and commit phases.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Callable
import uuid

from .store import (
    AccountStore,
    canonical_json,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)


class NormalizedLifecycleConflict(RuntimeError):
    """A normalized lifecycle reservation conflicts with current authority."""


@dataclass(frozen=True)
class PortLeaseRequest:
    agent: str
    canonical_project: str
    port_start: int
    port_end: int
    preferred: int | None
    ttl_seconds: int
    purpose: str


@dataclass(frozen=True)
class ServerStartRequest:
    agent: str
    canonical_project: str
    name: str
    cwd: str
    argv: tuple[str, ...]
    environment: dict[str, str]
    host: str
    health_url: str | None
    role: str | None
    port_start: int
    port_end: int
    preferred: int | None
    ttl_seconds: int
    explicit_range: bool = False
    manual_lease_id: str | None = None


@dataclass(frozen=True)
class ServerRegistrationRequest:
    agent: str
    canonical_project: str
    name: str
    cwd: str
    argv: tuple[str, ...]
    environment: dict[str, str]
    host: str
    port: int
    health_url: str | None
    role: str | None
    pid: int | None
    process_start_time: str | None
    process_fingerprint: str | None
    health: dict[str, Any]
    ttl_seconds: int
    log_path: str | None = None


class NormalizedPortLifecycle:
    """Direct normalized port assignment and lease transactions."""

    def __init__(self, store: AccountStore) -> None:
        self.store = store

    def list_leases(
        self, *, canonical_project: str | None = None, active_only: bool = True
    ) -> list[dict[str, Any]]:
        with self.store.read_transaction() as connection:
            parameters: list[Any] = []
            where: list[str] = []
            if canonical_project is not None:
                where.append("r.canonical_root = ?")
                parameters.append(canonical_project)
            if active_only:
                where.append("l.status = 'active'")
            clause = f"WHERE {' AND '.join(where)}" if where else ""
            rows = connection.execute(
                f"""
                SELECT l.*, r.canonical_root
                FROM leases l JOIN repositories r USING(repo_id)
                {clause}
                ORDER BY l.port, l.lease_id
                """,
                tuple(parameters),
            ).fetchall()
            return [self._lease_payload(row) for row in rows]

    def list_assignments(
        self, *, canonical_project: str | None = None, active_only: bool = True
    ) -> list[dict[str, Any]]:
        with self.store.read_transaction() as connection:
            parameters: list[Any] = []
            where: list[str] = []
            if canonical_project is not None:
                where.append("r.canonical_root = ?")
                parameters.append(canonical_project)
            if active_only:
                where.append("p.status = 'active'")
            clause = f"WHERE {' AND '.join(where)}" if where else ""
            rows = connection.execute(
                f"""
                SELECT p.*, r.canonical_root,
                       COALESCE(o.lifecycle, 'unregistered') AS server_status
                FROM port_assignments p JOIN repositories r USING(repo_id)
                LEFT JOIN server_definitions d
                  ON d.repo_id = p.repo_id AND d.name = p.server_name
                LEFT JOIN server_observations o USING(server_definition_id)
                {clause}
                ORDER BY p.port, r.canonical_root, p.server_name
                """,
                tuple(parameters),
            ).fetchall()
            return [self._assignment_payload(row) for row in rows]

    def lease(
        self,
        request: PortLeaseRequest,
        *,
        port_available: Callable[[int], bool],
    ) -> dict[str, Any]:
        self._validate_request(request)
        candidates = self._candidates(request)
        # Socket probing is host work and must remain outside BEGIN IMMEDIATE.
        observed_available = [port for port in candidates if port_available(port)]
        if not observed_available:
            raise RuntimeError(
                f"no free port available in {request.port_start}-{request.port_end}"
            )
        timestamp = utc_timestamp()
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(seconds=request.ttl_seconds))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
            if request.ttl_seconds > 0
            else None
        )
        with self.store.immediate_transaction() as connection:
            repository = self._repository(connection, request.canonical_project)
            self._require_installed(repository)
            self._expire_safe_leases(connection, timestamp)
            assignment_rows = connection.execute(
                """
                SELECT p.port, p.repo_id, p.server_name, r.canonical_root
                FROM port_assignments p JOIN repositories r USING(repo_id)
                WHERE p.status = 'active'
                """
            ).fetchall()
            assignments = {int(row["port"]): row for row in assignment_rows}
            active_ports = {
                int(row[0])
                for row in connection.execute(
                    "SELECT port FROM leases WHERE status = 'active'"
                )
            }
            if request.preferred is not None and request.preferred in assignments:
                assignment = assignments[request.preferred]
                raise NormalizedLifecycleConflict(
                    f"port {request.preferred} is durably assigned to server "
                    f"'{assignment['server_name']}' of {assignment['canonical_root']}; "
                    "choose another port or unassign it first"
                )
            selected = next(
                (
                    port
                    for port in observed_available
                    if port not in active_ports and port not in assignments
                ),
                None,
            )
            if selected is None:
                raise RuntimeError(
                    f"no free port available in {request.port_start}-{request.port_end}"
                )
            lease_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO leases(
                    lease_id, host_id, repo_id, server_definition_id, source_id,
                    port, owner, agent, purpose, status, expires_at,
                    process_fingerprint, generation, deactivated_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, NULL, NULL, ?, NULL, ?, ?, 'active', ?,
                          NULL, 0, NULL, ?, ?)
                """,
                (
                    lease_id,
                    repository["host_id"],
                    repository["repo_id"],
                    selected,
                    request.agent,
                    request.purpose,
                    expires_at,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                repo_id=str(repository["repo_id"]),
                kind="port.leased",
                code="port_leased",
                message=f"Port {selected} leased to {request.agent}",
                diagnostic={"lease_id": lease_id, "purpose": request.purpose},
                timestamp=timestamp,
            )
            row = connection.execute(
                """
                SELECT l.*, r.canonical_root FROM leases l
                JOIN repositories r USING(repo_id) WHERE l.lease_id = ?
                """,
                (lease_id,),
            ).fetchone()
            return self._lease_payload(row)

    def release(
        self,
        *,
        agent: str,
        canonical_project: str,
        lease_id: str | None = None,
        port: int | None = None,
    ) -> dict[str, Any]:
        if not agent.strip():
            raise ValueError("port release requires --agent so the action is attributable")
        if not lease_id and port is None:
            raise ValueError("port release requires --lease-id or --port")
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            repository = self._repository(connection, canonical_project)
            if lease_id:
                matches = connection.execute(
                    """
                    SELECT l.*, r.canonical_root FROM leases l
                    JOIN repositories r USING(repo_id)
                    WHERE l.lease_id = ? AND l.status = 'active'
                    """,
                    (lease_id,),
                ).fetchall()
            else:
                matches = connection.execute(
                    """
                    SELECT l.*, r.canonical_root FROM leases l
                    JOIN repositories r USING(repo_id)
                    WHERE l.port = ? AND l.status = 'active'
                    """,
                    (int(port),),
                ).fetchall()
            if len(matches) != 1:
                raise KeyError("matching lease not found")
            row = matches[0]
            if str(row["repo_id"]) != str(repository["repo_id"]):
                raise PermissionError("port release project does not match the lease owner project")
            pending = connection.execute(
                """
                SELECT o.operation_id FROM operations o
                JOIN operation_targets t USING(operation_id)
                WHERE o.status = 'running' AND t.target_kind = 'lease'
                  AND t.target_id = ?
                LIMIT 1
                """,
                (row["lease_id"],),
            ).fetchone()
            if pending is not None:
                raise NormalizedLifecycleConflict(
                    f"port lease has an attachment operation in progress: {pending[0]}"
                )
            connection.execute(
                """
                UPDATE leases SET status = 'released', deactivated_at = ?,
                       generation = generation + 1, updated_at = ?
                WHERE lease_id = ? AND status = 'active'
                """,
                (timestamp, timestamp, row["lease_id"]),
            )
            self._event(
                connection,
                repo_id=str(repository["repo_id"]),
                kind="port.released",
                code="port_released",
                message=f"Port {row['port']} released by {agent}",
                diagnostic={"lease_id": row["lease_id"]},
                timestamp=timestamp,
            )
            released = dict(row)
            released.update(
                {"status": "released", "deactivated_at": timestamp, "updated_at": timestamp}
            )
            return self._lease_payload(released)

    def assign(
        self,
        *,
        agent: str,
        canonical_project: str,
        name: str,
        port: int,
        force: bool = False,
    ) -> dict[str, Any]:
        if not agent.strip():
            raise ValueError("port assign requires --agent so the action is attributable")
        if not name.strip():
            raise ValueError("port assign requires --name")
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is outside 1-65535")
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            repository = self._repository(connection, canonical_project)
            self._require_installed(repository)
            owner = connection.execute(
                """
                SELECT p.*, r.canonical_root FROM port_assignments p
                JOIN repositories r USING(repo_id)
                WHERE p.port = ? AND p.status = 'active'
                  AND NOT (p.repo_id = ? AND p.server_name = ?)
                """,
                (port, repository["repo_id"], name),
            ).fetchone()
            if owner is not None:
                raise NormalizedLifecycleConflict(
                    f"port {port} is durably assigned to server '{owner['server_name']}' "
                    f"of {owner['canonical_root']}; unassign it first"
                )
            if not force:
                lease = connection.execute(
                    """
                    SELECT l.*, r.canonical_root FROM leases l
                    JOIN repositories r USING(repo_id)
                    WHERE l.port = ? AND l.status = 'active' AND l.repo_id != ?
                    LIMIT 1
                    """,
                    (port, repository["repo_id"]),
                ).fetchone()
                if lease is not None:
                    raise NormalizedLifecycleConflict(
                        f"port {port} already has an active lease for {lease['canonical_root']}"
                    )
            assignment_id = deterministic_id(
                "port-assignment", str(repository["repo_id"]), name
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port, status,
                    generation, deactivated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'active', 0, NULL, ?, ?)
                ON CONFLICT(repo_id, server_name) DO UPDATE SET
                    port = excluded.port, status = 'active',
                    generation = port_assignments.generation + 1,
                    deactivated_at = NULL, updated_at = excluded.updated_at
                """,
                (
                    assignment_id,
                    repository["host_id"],
                    repository["repo_id"],
                    name,
                    port,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                repo_id=str(repository["repo_id"]),
                kind="port.assigned",
                code="port_assigned",
                message=f"Port {port} assigned to {name} by {agent}",
                diagnostic={"assignment_id": assignment_id, "server_name": name},
                timestamp=timestamp,
            )
            row = connection.execute(
                """
                SELECT p.*, r.canonical_root FROM port_assignments p
                JOIN repositories r USING(repo_id)
                WHERE p.repo_id = ? AND p.server_name = ?
                """,
                (repository["repo_id"], name),
            ).fetchone()
            return self._assignment_payload(row)

    def unassign(
        self,
        *,
        agent: str,
        canonical_project: str,
        name: str | None = None,
        port: int | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if not agent.strip():
            raise ValueError("port unassign requires --agent so the action is attributable")
        if name is None and port is None:
            raise ValueError("port unassign requires --name or --port")
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            repository = self._repository(connection, canonical_project)
            if name is not None:
                row = connection.execute(
                    """
                    SELECT p.*, r.canonical_root FROM port_assignments p
                    JOIN repositories r USING(repo_id)
                    WHERE p.repo_id = ? AND p.server_name = ? AND p.status = 'active'
                    """,
                    (repository["repo_id"], name),
                ).fetchone()
                if row is not None and port is not None and int(row["port"]) != int(port):
                    row = None
            else:
                row = connection.execute(
                    """
                    SELECT p.*, r.canonical_root FROM port_assignments p
                    JOIN repositories r USING(repo_id)
                    WHERE p.port = ? AND p.status = 'active'
                    """,
                    (int(port),),
                ).fetchone()
                if row is not None and str(row["repo_id"]) != str(repository["repo_id"]) and not force:
                    raise PermissionError(
                        f"port {port} is durably assigned to server '{row['server_name']}' "
                        f"of {row['canonical_root']}; pass --force to remove it"
                    )
            if row is None:
                raise KeyError("matching port assignment not found")
            connection.execute(
                """
                UPDATE port_assignments
                SET status = 'inactive', generation = generation + 1,
                    deactivated_at = ?, updated_at = ?
                WHERE assignment_id = ? AND status = 'active'
                """,
                (timestamp, timestamp, row["assignment_id"]),
            )
            self._event(
                connection,
                repo_id=str(row["repo_id"]),
                kind="port.unassigned",
                code="port_unassigned",
                message=f"Port {row['port']} unassigned by {agent}",
                diagnostic={"assignment_id": row["assignment_id"]},
                timestamp=timestamp,
            )
            removed = dict(row)
            removed.update(
                {"status": "unassigned", "deactivated_at": timestamp, "updated_at": timestamp}
            )
            return self._assignment_payload(removed)

    @staticmethod
    def _validate_request(request: PortLeaseRequest) -> None:
        if not request.agent.strip():
            raise ValueError("port lease requires --agent so the action is attributable")
        if not 1 <= request.port_start <= request.port_end <= 65535:
            raise ValueError("invalid port range")
        if request.preferred is not None and not (
            request.port_start <= request.preferred <= request.port_end
        ):
            raise ValueError(
                f"preferred port {request.preferred} is outside "
                f"{request.port_start}-{request.port_end}"
            )
        if request.ttl_seconds < 0:
            raise ValueError("port lease ttl must not be negative")

    @staticmethod
    def _candidates(request: PortLeaseRequest) -> list[int]:
        candidates: list[int] = []
        if request.preferred is not None:
            candidates.append(request.preferred)
        candidates.extend(
            port
            for port in range(request.port_start, request.port_end + 1)
            if port != request.preferred
        )
        return candidates

    @staticmethod
    def _repository(connection: sqlite3.Connection, canonical_project: str) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT r.*, i.status AS installation_status, i.startup_fenced
            FROM repositories r JOIN repository_installations i USING(repo_id)
            WHERE r.canonical_root = ?
            """,
            (canonical_project,),
        ).fetchone()
        if row is None:
            raise KeyError(f"normalized repository not found: {canonical_project}")
        return row

    @staticmethod
    def _require_installed(repository: sqlite3.Row) -> None:
        if (
            str(repository["state"]) != "active"
            or str(repository["installation_status"]) != "installed"
            or bool(repository["startup_fenced"])
        ):
            raise NormalizedLifecycleConflict(
                "repository is removed or start-fenced; explicitly reinstall it through the Coordinator skill"
            )

    @staticmethod
    def _expire_safe_leases(connection: sqlite3.Connection, timestamp: str) -> None:
        rows = connection.execute(
            """
            SELECT l.lease_id, l.expires_at, l.server_definition_id,
                   o.lifecycle AS server_lifecycle
            FROM leases l
            LEFT JOIN server_observations o USING(server_definition_id)
            WHERE l.status = 'active' AND l.expires_at IS NOT NULL
            """
        ).fetchall()
        now_value = datetime.now(timezone.utc)
        for row in rows:
            try:
                raw = str(row["expires_at"])
                expires = (
                    datetime.fromtimestamp(float(raw), timezone.utc)
                    if raw.replace(".", "", 1).isdigit()
                    else datetime.fromisoformat(raw.replace("Z", "+00:00"))
                )
            except (TypeError, ValueError, OverflowError):
                continue
            safe = row["server_definition_id"] is None or str(
                row["server_lifecycle"] or ""
            ) == "stopped"
            if safe and expires <= now_value:
                connection.execute(
                    """
                    UPDATE leases SET status = 'stale', deactivated_at = ?,
                           generation = generation + 1, updated_at = ?
                    WHERE lease_id = ? AND status = 'active'
                    """,
                    (timestamp, timestamp, row["lease_id"]),
                )

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        repo_id: str,
        kind: str,
        code: str,
        message: str,
        diagnostic: dict[str, Any],
        timestamp: str,
    ) -> None:
        import json

        connection.execute(
            """
            INSERT INTO events(
                event_id, repo_id, source_id, operation_id, event_kind,
                code, message, diagnostic_json, occurred_at
            ) VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                repo_id,
                kind,
                code,
                message,
                json.dumps(diagnostic, separators=(",", ":"), sort_keys=True),
                timestamp,
            ),
        )

    @staticmethod
    def _lease_payload(row: Any) -> dict[str, Any]:
        return {
            "id": str(row["lease_id"]),
            "port": int(row["port"]),
            "project": str(row["canonical_root"]),
            "agent": row["agent"],
            "owner": row["owner"],
            "purpose": row["purpose"],
            "server_id": row["server_definition_id"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "released_at": row["deactivated_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "generation": int(row["generation"]),
        }

    @staticmethod
    def _assignment_payload(row: Any) -> dict[str, Any]:
        server_status = (
            row["server_status"]
            if "server_status" in row.keys()
            else "unregistered"
        )
        return {
            "id": str(row["assignment_id"]),
            "key": f"{row['canonical_root']}::{row['server_name']}",
            "project": str(row["canonical_root"]),
            "name": str(row["server_name"]),
            "port": int(row["port"]),
            "status": row["status"],
            "server_status": server_status,
            "deactivated_at": row["deactivated_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "generation": int(row["generation"]),
        }


class NormalizedServerLifecycle:
    """Direct normalized managed-server persistence and CAS transitions.

    The caller performs every process, listener, socket, and health operation
    before entering these methods. The service persists only short reservation
    and commit phases and never materializes the legacy JSON state projection.
    """

    def __init__(self, store: AccountStore) -> None:
        self.store = store

    def list_servers(
        self, *, canonical_project: str | None = None
    ) -> list[dict[str, Any]]:
        with self.store.read_transaction() as connection:
            parameters: tuple[Any, ...] = ()
            clause = ""
            if canonical_project is not None:
                clause = "WHERE r.canonical_root = ?"
                parameters = (canonical_project,)
            rows = connection.execute(
                self._server_select(clause) + " ORDER BY r.canonical_root, d.name",
                parameters,
            ).fetchall()
            return [self._server_payload(connection, row) for row in rows]

    def server(
        self,
        *,
        canonical_project: str | None = None,
        name: str | None = None,
        server_definition_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.read_transaction() as connection:
            row = self._resolve_server_row(
                connection,
                canonical_project=canonical_project,
                name=name,
                server_definition_id=server_definition_id,
            )
            return self._server_payload(connection, row)

    def reserve_start(
        self,
        request: ServerStartRequest,
        *,
        observed_available_ports: list[int],
    ) -> dict[str, Any]:
        self._validate_start_request(request)
        available = [int(port) for port in observed_available_ports]
        if not available:
            raise RuntimeError(
                f"no free port available in {request.port_start}-{request.port_end}"
            )
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            repository = NormalizedPortLifecycle._repository(
                connection, request.canonical_project
            )
            NormalizedPortLifecycle._require_installed(repository)
            NormalizedPortLifecycle._expire_safe_leases(connection, timestamp)
            existing = connection.execute(
                """
                SELECT d.*, o.lifecycle, o.pid, o.observation_fingerprint
                FROM server_definitions d
                LEFT JOIN server_observations o USING(server_definition_id)
                WHERE d.repo_id = ? AND d.name = ?
                """,
                (repository["repo_id"], request.name),
            ).fetchone()
            if existing is not None and (
                str(existing["lifecycle"] or "unobserved")
                not in {"stopped", "unobserved"}
                or existing["pid"] is not None
            ):
                raise NormalizedLifecycleConflict(
                    f"server {request.name} must reach a proved stopped boundary before start"
                )
            definition_id = (
                str(existing["server_definition_id"])
                if existing is not None
                else deterministic_id(
                    "server-definition", str(repository["repo_id"]), request.name
                )
            )
            self._require_no_pending_server_operation(connection, definition_id)

            assignment = connection.execute(
                """
                SELECT * FROM port_assignments
                WHERE repo_id = ? AND server_name = ? AND status = 'active'
                """,
                (repository["repo_id"], request.name),
            ).fetchone()
            if (
                assignment is not None
                and not request.explicit_range
                and request.preferred is None
            ):
                assigned_port = int(assignment["port"])
                if assigned_port not in available:
                    raise NormalizedLifecycleConflict(
                        f"server '{request.name}' is pinned to port {assigned_port} "
                        "but it is unavailable; free the port, or explicitly "
                        "choose a range/preferred port to repin"
                    )
                # An omitted range/preferred is a hard fixed-port contract.
                # The reservation must never silently choose another candidate.
                available = [assigned_port]
            manual_lease = None
            if request.manual_lease_id:
                manual_lease = connection.execute(
                    """
                    SELECT * FROM leases WHERE lease_id = ? AND status = 'active'
                    """,
                    (request.manual_lease_id,),
                ).fetchone()
                self._validate_manual_lease(
                    manual_lease,
                    request=request,
                    repo_id=str(repository["repo_id"]),
                    available=available,
                )
                selected = int(manual_lease["port"])
            else:
                active_lease_ports = {
                    int(row[0])
                    for row in connection.execute(
                        "SELECT port FROM leases WHERE status = 'active'"
                    )
                }
                selected = next(
                    (
                        port
                        for port in available
                        if port not in active_lease_ports
                        and not self._foreign_assignment_at_port(
                            connection,
                            host_id=str(repository["host_id"]),
                            repo_id=str(repository["repo_id"]),
                            server_name=request.name,
                            port=port,
                        )
                    ),
                    None,
                )
                if selected is None:
                    raise RuntimeError(
                        f"no free port available in {request.port_start}-{request.port_end}"
                    )
            if self._foreign_assignment_at_port(
                connection,
                host_id=str(repository["host_id"]),
                repo_id=str(repository["repo_id"]),
                server_name=request.name,
                port=selected,
            ):
                owner = connection.execute(
                    """
                    SELECT r.canonical_root, p.server_name
                    FROM port_assignments p JOIN repositories r USING(repo_id)
                    WHERE p.host_id = ? AND p.port = ? AND p.status = 'active'
                    """,
                    (repository["host_id"], selected),
                ).fetchone()
                raise NormalizedLifecycleConflict(
                    f"port {selected} is durably assigned to server "
                    f"'{owner['server_name']}' of {owner['canonical_root']}"
                )

            definition = self._definition_payload(request, selected)
            definition_fingerprint = fingerprint(definition)
            previous_generation = int(existing["generation"]) if existing else -1
            definition_generation = previous_generation + 1
            created_at = str(existing["created_at"]) if existing else timestamp
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, role, cwd,
                    health_url_template, log_path, definition_fingerprint,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_definition_id) DO UPDATE SET
                    repo_id = excluded.repo_id, name = excluded.name,
                    role = excluded.role, cwd = excluded.cwd,
                    health_url_template = excluded.health_url_template,
                    definition_fingerprint = excluded.definition_fingerprint,
                    generation = excluded.generation,
                    updated_at = excluded.updated_at
                """,
                (
                    definition_id,
                    repository["repo_id"],
                    request.name,
                    request.role,
                    request.cwd,
                    request.health_url,
                    existing["log_path"] if existing else None,
                    definition_fingerprint,
                    definition_generation,
                    created_at,
                    timestamp,
                ),
            )
            self._replace_definition_details(
                connection,
                definition_id=definition_id,
                argv=request.argv,
                environment=request.environment,
            )
            self._ensure_server_authority(
                connection,
                repository=repository,
                definition_id=definition_id,
                definition_fingerprint=definition_fingerprint,
                timestamp=timestamp,
            )

            assignment_id = deterministic_id(
                "port-assignment", str(repository["repo_id"]), request.name
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port, status,
                    generation, deactivated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'active', 0, NULL, ?, ?)
                ON CONFLICT(repo_id, server_name) DO UPDATE SET
                    port = excluded.port, status = 'active',
                    generation = port_assignments.generation + 1,
                    deactivated_at = NULL, updated_at = excluded.updated_at
                """,
                (
                    assignment_id,
                    repository["host_id"],
                    repository["repo_id"],
                    request.name,
                    selected,
                    timestamp,
                    timestamp,
                ),
            )

            if manual_lease is not None:
                lease_id = str(manual_lease["lease_id"])
                changed = connection.execute(
                    """
                    UPDATE leases SET server_definition_id = ?,
                        purpose = ?, generation = generation + 1,
                        updated_at = ?
                    WHERE lease_id = ? AND status = 'active'
                      AND server_definition_id IS NULL AND purpose = 'manual'
                    """,
                    (
                        definition_id,
                        f"server:{request.name}",
                        timestamp,
                        lease_id,
                    ),
                ).rowcount
                if changed != 1:
                    raise NormalizedLifecycleConflict(
                        "manual lease changed before server reservation"
                    )
            else:
                lease_id = str(uuid.uuid4())
                expires_at = self._expiry(request.ttl_seconds)
                connection.execute(
                    """
                    INSERT INTO leases(
                        lease_id, host_id, repo_id, server_definition_id,
                        source_id, port, owner, agent, purpose, status,
                        expires_at, process_fingerprint, generation,
                        deactivated_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, NULL, ?, NULL, ?, ?, 'active', ?,
                              NULL, 0, NULL, ?, ?)
                    """,
                    (
                        lease_id,
                        repository["host_id"],
                        repository["repo_id"],
                        definition_id,
                        selected,
                        request.agent,
                        f"server:{request.name}",
                        expires_at,
                        timestamp,
                        timestamp,
                    ),
                )

            operation_id = str(uuid.uuid4())
            request_fingerprint = fingerprint(
                {
                    "kind": "server.start",
                    "server_definition_id": definition_id,
                    "definition_generation": definition_generation,
                    "lease_id": lease_id,
                    "port": selected,
                    "manual_lease": manual_lease is not None,
                }
            )
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    process_fingerprint, error_code, error_message, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'server.start', 'running', 'reserved',
                          ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?)
                """,
                (
                    operation_id,
                    repository["repo_id"],
                    definition_generation,
                    request_fingerprint,
                    os.geteuid(),
                    request.agent,
                    canonical_json(
                        {
                            "lease_id": lease_id,
                            "port": selected,
                            "manual_lease": manual_lease is not None,
                        }
                    ),
                    timestamp,
                    timestamp,
                ),
            )
            self._insert_operation_targets(
                connection,
                operation_id=operation_id,
                server_definition_id=definition_id,
                definition_fingerprint=definition_fingerprint,
                lease_id=lease_id,
                action="start",
                phase="reserved",
            )
            observation = {
                "lifecycle": "starting",
                "pid": None,
                "process_start_time": None,
                "process_fingerprint": None,
                "listener_host": request.host,
                "listener_port": selected,
                "listener_observable": None,
                "health_classification": "starting",
                "health_ok": None,
                "stopped_at": None,
                "stopped_reason": None,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=definition_id,
                source_resource_id=None,
                observation=observation,
            )
            self._event(
                connection,
                repo_id=str(repository["repo_id"]),
                operation_id=operation_id,
                kind="server.start.reserved",
                code="server_start_reserved",
                message=f"Reserved {request.name} on port {selected}",
                diagnostic={
                    "server_definition_id": definition_id,
                    "lease_id": lease_id,
                    "manual_lease": manual_lease is not None,
                },
                timestamp=timestamp,
            )
            row = self._resolve_server_row(
                connection, server_definition_id=definition_id
            )
            result = self._server_payload(connection, row)
            result.update(
                {
                    "operation_id": operation_id,
                    "lease_id": lease_id,
                    "lease_source": "manual" if manual_lease is not None else "allocated",
                    "_definition_generation": definition_generation,
                    "_manual_lease": manual_lease is not None,
                }
            )
            return result

    def mark_start_launched(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        definition_generation: int,
        pid: int,
        log_path: str,
        process_start_time: str | None,
        process_fingerprint: str,
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            operation = self._running_operation(connection, operation_id, "server.start")
            definition = connection.execute(
                """
                SELECT generation FROM server_definitions
                WHERE server_definition_id = ?
                """,
                (server_definition_id,),
            ).fetchone()
            if definition is None or int(definition["generation"]) != int(
                definition_generation
            ):
                raise NormalizedLifecycleConflict(
                    "server start definition changed before process launch commit"
                )
            lease = connection.execute(
                """
                SELECT l.lease_id FROM leases l
                JOIN operation_targets t
                  ON t.operation_id = ? AND t.target_kind = 'lease'
                 AND t.target_id = l.lease_id
                WHERE l.status = 'active'
                  AND l.server_definition_id = ?
                """,
                (operation_id, server_definition_id),
            ).fetchone()
            if lease is None:
                raise NormalizedLifecycleConflict(
                    "server start lease changed before process launch commit"
                )
            observation = connection.execute(
                """
                SELECT * FROM server_observations
                WHERE server_definition_id = ?
                """,
                (server_definition_id,),
            ).fetchone()
            if observation is None or str(observation["lifecycle"]) != "starting":
                raise NormalizedLifecycleConflict(
                    "server start observation changed before process launch commit"
                )
            evidence = {
                "lifecycle": "starting",
                "pid": int(pid),
                "process_start_time": process_start_time,
                "process_fingerprint": process_fingerprint,
                "listener_host": observation["listener_host"],
                "listener_port": observation["listener_port"],
                "listener_observable": None,
                "health_classification": "starting",
                "health_ok": None,
                "stopped_at": None,
                "stopped_reason": None,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=observation["source_resource_id"],
                observation=evidence,
            )
            connection.execute(
                """
                UPDATE server_definitions SET log_path = ?, updated_at = ?
                WHERE server_definition_id = ?
                """,
                (log_path, timestamp, server_definition_id),
            )
            connection.execute(
                """
                UPDATE leases SET owner = ?, process_fingerprint = ?,
                    generation = generation + 1, updated_at = ?
                WHERE lease_id = ? AND status = 'active'
                """,
                (str(pid), process_fingerprint, timestamp, lease["lease_id"]),
            )
            connection.execute(
                """
                UPDATE operations SET phase = 'health_check',
                    process_fingerprint = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (process_fingerprint, timestamp, operation_id),
            )
            connection.execute(
                """
                UPDATE operation_targets SET phase = 'health_check'
                WHERE operation_id = ? AND status = 'running'
                """,
                (operation_id,),
            )
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, row)
            result.update(
                {
                    "operation_id": str(operation["operation_id"]),
                    "_definition_generation": definition_generation,
                }
            )
            return result

    def finalize_reserved_start_definition(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        definition_generation: int,
        argv: tuple[str, ...],
        environment: dict[str, str],
        health_url: str | None,
    ) -> dict[str, Any]:
        """Bind templates to the exact reserved port before host launch."""

        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            self._running_operation(connection, operation_id, "server.start")
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            if int(row["definition_generation"]) != int(definition_generation):
                raise NormalizedLifecycleConflict(
                    "server definition changed before reserved argv commit"
                )
            definition = {
                "name": row["name"],
                "role": row["role"],
                "cwd": row["cwd"],
                "argv": list(argv),
                "environment": dict(sorted(environment.items())),
                "health_url": health_url,
                "port": row["listener_port"],
                "host": row["listener_host"],
            }
            definition_fingerprint = fingerprint(definition)
            connection.execute(
                """
                UPDATE server_definitions SET health_url_template = ?,
                    definition_fingerprint = ?, updated_at = ?
                WHERE server_definition_id = ? AND generation = ?
                """,
                (
                    health_url,
                    definition_fingerprint,
                    timestamp,
                    server_definition_id,
                    definition_generation,
                ),
            )
            self._replace_definition_details(
                connection,
                definition_id=server_definition_id,
                argv=argv,
                environment=environment,
            )
            connection.execute(
                """
                UPDATE repository_memberships SET immutable_fingerprint = ?
                WHERE resource_kind = 'server' AND host_resource_id = ?
                """,
                (definition_fingerprint, server_definition_id),
            )
            connection.execute(
                """
                UPDATE startup_policies SET immutable_fingerprint = ?,
                    generation = generation + 1, updated_at = ?
                WHERE resource_kind = 'server' AND resource_id = ?
                """,
                (definition_fingerprint, timestamp, server_definition_id),
            )
            connection.execute(
                """
                UPDATE operation_targets SET immutable_fingerprint = ?,
                    phase = 'launch_ready'
                WHERE operation_id = ? AND target_kind = 'server'
                  AND status = 'running'
                """,
                (definition_fingerprint, operation_id),
            )
            connection.execute(
                """
                UPDATE operations SET phase = 'launch_ready', updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (timestamp, operation_id),
            )
            current = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, current)
            result.update(
                {
                    "operation_id": operation_id,
                    "_definition_generation": definition_generation,
                }
            )
            return result

    def commit_start_health(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        definition_generation: int,
        health: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        listener_observable = self._listener_observable(health)
        lifecycle = (
            "running"
            if health.get("ok") is True
            else "starting"
            if health.get("classification") == "starting"
            else "unhealthy"
        )
        with self.store.immediate_transaction() as connection:
            operation = self._running_operation(connection, operation_id, "server.start")
            definition = connection.execute(
                """
                SELECT d.generation, d.repo_id, o.*
                FROM server_definitions d JOIN server_observations o
                  USING(server_definition_id)
                WHERE d.server_definition_id = ?
                """,
                (server_definition_id,),
            ).fetchone()
            if definition is None or int(definition["generation"]) != int(
                definition_generation
            ):
                raise NormalizedLifecycleConflict(
                    "server start definition changed before health commit"
                )
            if str(definition["lifecycle"]) != "starting" or definition["pid"] is None:
                raise NormalizedLifecycleConflict(
                    "server start launch evidence changed before health commit"
                )
            evidence = {
                "lifecycle": lifecycle,
                "pid": definition["pid"],
                "process_start_time": definition["process_start_time"],
                "process_fingerprint": definition["process_fingerprint"],
                "listener_host": definition["listener_host"],
                "listener_port": definition["listener_port"],
                "listener_observable": listener_observable,
                "health_classification": health.get("classification")
                or ("healthy" if health.get("ok") else "unhealthy"),
                "health_ok": self._nullable_bool(health.get("ok")),
                "stopped_at": None,
                "stopped_reason": None,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=definition["source_resource_id"],
                observation=evidence,
            )
            result_json = canonical_json(
                {
                    "server_definition_id": server_definition_id,
                    "lifecycle": lifecycle,
                    "health_classification": evidence["health_classification"],
                }
            )
            connection.execute(
                """
                UPDATE operations SET status = 'succeeded', phase = 'committed',
                    result_json = ?, error_code = NULL, error_message = NULL,
                    updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (result_json, timestamp, operation_id),
            )
            connection.execute(
                """
                UPDATE operation_targets SET phase = 'committed',
                    status = 'succeeded', result_json = ?, finished_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (result_json, timestamp, operation_id),
            )
            self._event(
                connection,
                repo_id=str(definition["repo_id"]),
                operation_id=operation_id,
                kind="server.started",
                code="server_started",
                message=f"Server {server_definition_id} reached {lifecycle}",
                diagnostic={
                    "health_classification": evidence["health_classification"],
                    "listener_observable": listener_observable,
                },
                timestamp=timestamp,
            )
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, row)
            result["operation_id"] = str(operation["operation_id"])
            return result

    def fail_start(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        error: str,
        process_launched: bool,
        process_active: bool,
        manual_lease: bool,
        pid: int | None = None,
        log_path: str | None = None,
        health: dict[str, Any] | None = None,
        cleanup_errors: list[str] | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        cleanup_errors = list(cleanup_errors or [])
        with self.store.immediate_transaction() as connection:
            operation = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if operation is None:
                raise KeyError(f"server start operation not found: {operation_id}")
            definition = connection.execute(
                """
                SELECT d.repo_id, d.log_path, o.*
                FROM server_definitions d LEFT JOIN server_observations o
                  USING(server_definition_id)
                WHERE d.server_definition_id = ?
                """,
                (server_definition_id,),
            ).fetchone()
            if definition is None:
                raise KeyError("server definition disappeared during failed start")
            lease_target = connection.execute(
                """
                SELECT target_id FROM operation_targets
                WHERE operation_id = ? AND target_kind = 'lease'
                """,
                (operation_id,),
            ).fetchone()
            lease_id = str(lease_target["target_id"]) if lease_target else None
            reconciliation = bool(process_active or cleanup_errors)
            lifecycle = "unhealthy" if reconciliation else "stopped"
            evidence = {
                "lifecycle": lifecycle,
                "pid": int(pid) if reconciliation and pid else None,
                "process_start_time": (
                    definition["process_start_time"] if reconciliation else None
                ),
                "process_fingerprint": (
                    definition["process_fingerprint"] if reconciliation else None
                ),
                "listener_host": definition["listener_host"],
                "listener_port": definition["listener_port"],
                "listener_observable": self._listener_observable(health or {}),
                "health_classification": (
                    (health or {}).get("classification")
                    or ("reconciliation-required" if reconciliation else "stopped")
                ),
                "health_ok": self._nullable_bool((health or {}).get("ok")),
                "stopped_at": None if reconciliation else timestamp,
                "stopped_reason": error,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=definition["source_resource_id"],
                observation=evidence,
            )
            if log_path:
                connection.execute(
                    "UPDATE server_definitions SET log_path = ?, updated_at = ? WHERE server_definition_id = ?",
                    (log_path, timestamp, server_definition_id),
                )
            if lease_id:
                if manual_lease and not process_launched:
                    connection.execute(
                        """
                        UPDATE leases SET server_definition_id = NULL,
                            purpose = 'manual', process_fingerprint = NULL,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (timestamp, lease_id),
                    )
                elif not manual_lease and not reconciliation:
                    connection.execute(
                        """
                        UPDATE leases SET status = 'released', deactivated_at = ?,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (timestamp, timestamp, lease_id),
                    )
                # Any manual lease that reached launch, or any uncertain
                # process outcome, remains attached and active until an
                # explicit attributed cleanup proves it reusable.
            error_payload = {
                "message": error,
                "process_launched": process_launched,
                "process_active": process_active,
                "cleanup_errors": cleanup_errors,
            }
            operation_status = "needs_attention" if reconciliation else "failed"
            connection.execute(
                """
                UPDATE operations SET status = ?, phase = ?, error_code = ?,
                    error_message = ?, result_json = ?, updated_at = ?
                WHERE operation_id = ?
                """,
                (
                    operation_status,
                    "cleanup_uncertain" if reconciliation else "rolled_back",
                    "server_start_cleanup_uncertain" if reconciliation else "server_start_failed",
                    error,
                    canonical_json(error_payload),
                    timestamp,
                    operation_id,
                ),
            )
            connection.execute(
                """
                UPDATE operation_targets SET status = 'failed', phase = ?,
                    error_json = ?, finished_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (
                    "cleanup_uncertain" if reconciliation else "rolled_back",
                    canonical_json(error_payload),
                    timestamp,
                    operation_id,
                ),
            )
            self._event(
                connection,
                repo_id=str(definition["repo_id"]),
                operation_id=operation_id,
                kind="server.start.failed",
                code=(
                    "server_start_cleanup_uncertain"
                    if reconciliation
                    else "server_start_failed"
                ),
                message=error,
                diagnostic=error_payload,
                timestamp=timestamp,
            )
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, row)
            result.update(
                {
                    "operation_id": operation_id,
                    "reconciliation_required": reconciliation,
                    "cleanup_errors": cleanup_errors,
                }
            )
            return result

    def commit_registration(
        self, request: ServerRegistrationRequest
    ) -> dict[str, Any]:
        if not request.agent.strip():
            raise ValueError("server register requires --agent")
        if not request.name.strip():
            raise ValueError("server register requires --name")
        if not 1 <= int(request.port) <= 65535:
            raise ValueError("server register port is outside 1-65535")
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            repository = NormalizedPortLifecycle._repository(
                connection, request.canonical_project
            )
            NormalizedPortLifecycle._require_installed(repository)
            existing = connection.execute(
                "SELECT * FROM server_definitions WHERE repo_id = ? AND name = ?",
                (repository["repo_id"], request.name),
            ).fetchone()
            definition_id = (
                str(existing["server_definition_id"])
                if existing is not None
                else deterministic_id(
                    "server-definition", str(repository["repo_id"]), request.name
                )
            )
            self._require_no_pending_server_operation(connection, definition_id)
            if self._foreign_assignment_at_port(
                connection,
                host_id=str(repository["host_id"]),
                repo_id=str(repository["repo_id"]),
                server_name=request.name,
                port=int(request.port),
            ):
                raise NormalizedLifecycleConflict(
                    f"port {request.port} is durably assigned to another server"
                )
            conflicting_lease = connection.execute(
                """
                SELECT l.*, r.canonical_root, d.name AS server_name,
                       o.lifecycle AS server_lifecycle
                FROM leases l JOIN repositories r USING(repo_id)
                LEFT JOIN server_definitions d USING(server_definition_id)
                LEFT JOIN server_observations o USING(server_definition_id)
                WHERE l.host_id = ? AND l.port = ? AND l.status = 'active'
                  AND (l.repo_id != ? OR l.server_definition_id != ?)
                """,
                (
                    repository["host_id"],
                    int(request.port),
                    repository["repo_id"],
                    definition_id,
                ),
            ).fetchone()
            if conflicting_lease is not None:
                safe_stale = (
                    str(conflicting_lease["canonical_root"])
                    == request.canonical_project
                    and str(conflicting_lease["server_lifecycle"] or "") == "stopped"
                )
                if not safe_stale:
                    raise NormalizedLifecycleConflict(
                        f"port {request.port} has an active lease for "
                        f"{conflicting_lease['canonical_root']}"
                    )
                connection.execute(
                    """
                    UPDATE leases SET status = 'stale', deactivated_at = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE lease_id = ? AND status = 'active'
                    """,
                    (
                        timestamp,
                        timestamp,
                        conflicting_lease["lease_id"],
                    ),
                )

            definition = {
                "name": request.name,
                "role": request.role,
                "cwd": request.cwd,
                "argv": list(request.argv),
                "environment": dict(sorted(request.environment.items())),
                "health_url": request.health_url,
                "port": int(request.port),
                "host": request.host,
            }
            definition_fingerprint = fingerprint(definition)
            generation = (int(existing["generation"]) + 1) if existing else 0
            created_at = str(existing["created_at"]) if existing else timestamp
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, role, cwd,
                    health_url_template, log_path, definition_fingerprint,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_definition_id) DO UPDATE SET
                    repo_id = excluded.repo_id, name = excluded.name,
                    role = excluded.role, cwd = excluded.cwd,
                    health_url_template = excluded.health_url_template,
                    log_path = COALESCE(excluded.log_path, server_definitions.log_path),
                    definition_fingerprint = excluded.definition_fingerprint,
                    generation = excluded.generation,
                    updated_at = excluded.updated_at
                """,
                (
                    definition_id,
                    repository["repo_id"],
                    request.name,
                    request.role,
                    request.cwd,
                    request.health_url,
                    request.log_path,
                    definition_fingerprint,
                    generation,
                    created_at,
                    timestamp,
                ),
            )
            self._replace_definition_details(
                connection,
                definition_id=definition_id,
                argv=request.argv,
                environment=request.environment,
            )
            self._ensure_server_authority(
                connection,
                repository=repository,
                definition_id=definition_id,
                definition_fingerprint=definition_fingerprint,
                timestamp=timestamp,
            )
            assignment_id = deterministic_id(
                "port-assignment", str(repository["repo_id"]), request.name
            )
            connection.execute(
                """
                INSERT INTO port_assignments(
                    assignment_id, host_id, repo_id, server_name, port, status,
                    generation, deactivated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'active', 0, NULL, ?, ?)
                ON CONFLICT(repo_id, server_name) DO UPDATE SET
                    port = excluded.port, status = 'active',
                    generation = port_assignments.generation + 1,
                    deactivated_at = NULL, updated_at = excluded.updated_at
                """,
                (
                    assignment_id,
                    repository["host_id"],
                    repository["repo_id"],
                    request.name,
                    int(request.port),
                    timestamp,
                    timestamp,
                ),
            )
            health_ok = self._nullable_bool(request.health.get("ok"))
            lifecycle = "running" if health_ok == 1 else "unhealthy"
            source_resource_id = None
            if existing is not None:
                previous_observation = connection.execute(
                    "SELECT source_resource_id FROM server_observations WHERE server_definition_id = ?",
                    (definition_id,),
                ).fetchone()
                if previous_observation is not None:
                    source_resource_id = previous_observation["source_resource_id"]
            observation = {
                "lifecycle": lifecycle,
                "pid": int(request.pid) if request.pid else None,
                "process_start_time": request.process_start_time,
                "process_fingerprint": request.process_fingerprint,
                "listener_host": request.host,
                "listener_port": int(request.port),
                "listener_observable": self._listener_observable(request.health),
                "health_classification": request.health.get("classification")
                or ("healthy" if health_ok == 1 else "unhealthy"),
                "health_ok": health_ok,
                "stopped_at": None,
                "stopped_reason": None,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=definition_id,
                source_resource_id=source_resource_id,
                observation=observation,
            )
            lease_id = None
            if lifecycle == "running" and request.pid:
                existing_lease = connection.execute(
                    """
                    SELECT * FROM leases
                    WHERE server_definition_id = ? AND status = 'active'
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (definition_id,),
                ).fetchone()
                lease_id = (
                    str(existing_lease["lease_id"])
                    if existing_lease is not None
                    else str(uuid.uuid4())
                )
                expires_at = self._expiry(request.ttl_seconds)
                if existing_lease is None:
                    connection.execute(
                        """
                        INSERT INTO leases(
                            lease_id, host_id, repo_id, server_definition_id,
                            source_id, port, owner, agent, purpose, status,
                            expires_at, process_fingerprint, generation,
                            deactivated_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, 'active', ?, ?,
                                  0, NULL, ?, ?)
                        """,
                        (
                            lease_id,
                            repository["host_id"],
                            repository["repo_id"],
                            definition_id,
                            int(request.port),
                            str(request.pid),
                            request.agent,
                            f"server:{request.name}",
                            expires_at,
                            request.process_fingerprint,
                            timestamp,
                            timestamp,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE leases SET port = ?, owner = ?, agent = ?,
                            purpose = ?, expires_at = ?, process_fingerprint = ?,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (
                            int(request.port),
                            str(request.pid),
                            request.agent,
                            f"server:{request.name}",
                            expires_at,
                            request.process_fingerprint,
                            timestamp,
                            lease_id,
                        ),
                    )
            operation_id = str(uuid.uuid4())
            result_payload = {
                "server_definition_id": definition_id,
                "lease_id": lease_id,
                "lifecycle": lifecycle,
            }
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    process_fingerprint, error_code, error_message, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'server.register', 'succeeded', 'committed',
                          ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)
                """,
                (
                    operation_id,
                    repository["repo_id"],
                    generation,
                    fingerprint({"kind": "server.register", **result_payload}),
                    os.geteuid(),
                    request.agent,
                    request.process_fingerprint,
                    canonical_json(result_payload),
                    timestamp,
                    timestamp,
                ),
            )
            self._insert_operation_targets(
                connection,
                operation_id=operation_id,
                server_definition_id=definition_id,
                definition_fingerprint=definition_fingerprint,
                lease_id=lease_id,
                action="register",
                phase="committed",
                status="succeeded",
                finished_at=timestamp,
            )
            self._event(
                connection,
                repo_id=str(repository["repo_id"]),
                operation_id=operation_id,
                kind="server.registered",
                code="server_registered",
                message=f"Registered {request.name} on port {request.port}",
                diagnostic=result_payload,
                timestamp=timestamp,
            )
            row = self._resolve_server_row(
                connection, server_definition_id=definition_id
            )
            result = self._server_payload(connection, row)
            result["operation_id"] = operation_id
            return result

    def commit_status(
        self,
        *,
        server_definition_id: str,
        expected_definition_generation: int,
        expected_observation_fingerprint: str | None,
        health: dict[str, Any],
        stopped_reason: str | None,
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            if int(row["definition_generation"]) != int(
                expected_definition_generation
            ) or (row["observation_fingerprint"] or None) != (
                expected_observation_fingerprint or None
            ):
                raise NormalizedLifecycleConflict(
                    "server changed while host health was observed; retry status"
                )
            prior_lifecycle = str(row["lifecycle"] or "unobserved")
            identity = health.get("identity") or {}
            unobservable = self._listener_observable(health) == 0
            wrong_listener = identity.get("ok") is False
            dead = health.get("pid_alive") is False
            if prior_lifecycle == "stopped":
                lifecycle = "stopped"
            elif unobservable:
                lifecycle = prior_lifecycle
            elif health.get("ok") is True:
                lifecycle = "running"
            elif wrong_listener or dead:
                lifecycle = "stopped"
            elif health.get("classification") == "starting":
                lifecycle = "starting"
            else:
                lifecycle = "unhealthy"
            stopped = lifecycle == "stopped" and prior_lifecycle != "stopped"
            observation = {
                "lifecycle": lifecycle,
                "pid": None if stopped else row["pid"],
                "process_start_time": (
                    None if stopped else row["process_start_time"]
                ),
                "process_fingerprint": (
                    None if stopped else row["process_fingerprint"]
                ),
                "listener_host": row["listener_host"],
                "listener_port": row["listener_port"],
                "listener_observable": self._listener_observable(health),
                "health_classification": health.get("classification")
                or lifecycle,
                "health_ok": self._nullable_bool(health.get("ok")),
                "stopped_at": timestamp if stopped else row["stopped_at"],
                "stopped_reason": (
                    stopped_reason if stopped else row["stopped_reason"]
                ),
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=row["source_resource_id"],
                observation=observation,
            )
            if stopped and row["lease_id"]:
                connection.execute(
                    """
                    UPDATE leases SET status = 'stale', deactivated_at = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE lease_id = ? AND status = 'active'
                    """,
                    (timestamp, timestamp, row["lease_id"]),
                )
                self._event(
                    connection,
                    repo_id=str(row["repo_id"]),
                    operation_id=None,
                    kind="server.stopped",
                    code=("wrong_listener" if wrong_listener else "process_stopped"),
                    message=stopped_reason or "Server stopped",
                    diagnostic={"server_definition_id": server_definition_id},
                    timestamp=timestamp,
                )
            current = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            return self._server_payload(connection, current)

    def reserve_stop(
        self,
        *,
        agent: str,
        server_definition_id: str,
        expected_definition_generation: int,
        expected_observation_fingerprint: str | None,
    ) -> dict[str, Any]:
        if not agent.strip():
            raise ValueError("server stop requires --agent")
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            if int(row["definition_generation"]) != int(
                expected_definition_generation
            ) or (row["observation_fingerprint"] or None) != (
                expected_observation_fingerprint or None
            ):
                raise NormalizedLifecycleConflict(
                    "server changed while listener identity was observed; retry stop"
                )
            self._require_no_pending_server_operation(connection, server_definition_id)
            operation_id = str(uuid.uuid4())
            generation = int(row["definition_generation"]) + 1
            request_payload = {
                "server_definition_id": server_definition_id,
                "definition_generation": row["definition_generation"],
                "observation_fingerprint": row["observation_fingerprint"],
                "pid": row["pid"],
                "lease_id": row["lease_id"],
            }
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    process_fingerprint, error_code, error_message, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'server.stop', 'running', 'reserved',
                          ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)
                """,
                (
                    operation_id,
                    row["repo_id"],
                    generation,
                    fingerprint(request_payload),
                    os.geteuid(),
                    agent,
                    row["process_fingerprint"],
                    canonical_json(request_payload),
                    timestamp,
                    timestamp,
                ),
            )
            self._insert_operation_targets(
                connection,
                operation_id=operation_id,
                server_definition_id=server_definition_id,
                definition_fingerprint=str(row["definition_fingerprint"]),
                lease_id=row["lease_id"],
                action="stop",
                phase="reserved",
            )
            observation = {
                "lifecycle": "stopping",
                "pid": row["pid"],
                "process_start_time": row["process_start_time"],
                "process_fingerprint": row["process_fingerprint"],
                "listener_host": row["listener_host"],
                "listener_port": row["listener_port"],
                "listener_observable": row["listener_observable"],
                "health_classification": "stopping",
                "health_ok": row["health_ok"],
                "stopped_at": row["stopped_at"],
                "stopped_reason": row["stopped_reason"],
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=row["source_resource_id"],
                observation=observation,
            )
            connection.execute(
                """
                UPDATE operation_targets SET status = 'running',
                    phase = 'host_stop', started_at = ?
                WHERE operation_id = ?
                """,
                (timestamp, operation_id),
            )
            current = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, current)
            result["operation_id"] = operation_id
            return result

    def commit_stop(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        agent: str,
        reason: str,
        release_port: bool,
        stale_lease: bool,
        final_health: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            operation = self._running_operation(connection, operation_id, "server.stop")
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            if str(row["lifecycle"] or "") != "stopping":
                raise NormalizedLifecycleConflict(
                    "server stop reservation changed before commit"
                )
            observation = {
                "lifecycle": "stopped",
                "pid": None,
                "process_start_time": None,
                "process_fingerprint": None,
                "listener_host": row["listener_host"],
                "listener_port": row["listener_port"],
                "listener_observable": self._listener_observable(final_health),
                "health_classification": final_health.get("classification")
                or "stopped",
                "health_ok": self._nullable_bool(final_health.get("ok")),
                "stopped_at": timestamp,
                "stopped_reason": reason,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=row["source_resource_id"],
                observation=observation,
            )
            if row["lease_id"] and (release_port or stale_lease):
                lease_status = "stale" if stale_lease else "released"
                connection.execute(
                    """
                    UPDATE leases SET status = ?, deactivated_at = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE lease_id = ? AND status = 'active'
                    """,
                    (
                        lease_status,
                        timestamp,
                        timestamp,
                        row["lease_id"],
                    ),
                )
            result_payload = {
                "server_definition_id": server_definition_id,
                "lease_status": (
                    "stale"
                    if stale_lease
                    else "released"
                    if release_port
                    else "active"
                ),
                "reason": reason,
                "agent": agent,
            }
            connection.execute(
                """
                UPDATE operations SET status = 'succeeded', phase = 'committed',
                    result_json = ?, error_code = NULL, error_message = NULL,
                    updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (canonical_json(result_payload), timestamp, operation_id),
            )
            connection.execute(
                """
                UPDATE operation_targets SET status = 'succeeded',
                    phase = 'committed', result_json = ?, finished_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (
                    canonical_json(result_payload),
                    timestamp,
                    operation_id,
                ),
            )
            self._event(
                connection,
                repo_id=str(row["repo_id"]),
                operation_id=operation_id,
                kind="server.stopped",
                code="server_stopped",
                message=reason,
                diagnostic=result_payload,
                timestamp=timestamp,
            )
            current = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, current)
            result["operation_id"] = str(operation["operation_id"])
            return result

    def fail_stop(
        self,
        *,
        operation_id: str,
        server_definition_id: str,
        error: str,
        cleanup_errors: list[str] | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_timestamp()
        cleanup_errors = list(cleanup_errors or [])
        with self.store.immediate_transaction() as connection:
            operation = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if operation is None:
                raise KeyError(f"server stop operation not found: {operation_id}")
            row = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            error_payload = {"message": error, "cleanup_errors": cleanup_errors}
            connection.execute(
                """
                UPDATE operations SET status = 'needs_attention',
                    phase = 'host_stop_uncertain',
                    error_code = 'server_stop_outcome_uncertain',
                    error_message = ?, result_json = ?, updated_at = ?
                WHERE operation_id = ?
                """,
                (error, canonical_json(error_payload), timestamp, operation_id),
            )
            connection.execute(
                """
                UPDATE operation_targets SET status = 'failed',
                    phase = 'host_stop_uncertain', error_json = ?, finished_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (canonical_json(error_payload), timestamp, operation_id),
            )
            observation = {
                "lifecycle": "unhealthy",
                "pid": row["pid"],
                "process_start_time": row["process_start_time"],
                "process_fingerprint": row["process_fingerprint"],
                "listener_host": row["listener_host"],
                "listener_port": row["listener_port"],
                "listener_observable": row["listener_observable"],
                "health_classification": "stop-outcome-uncertain",
                "health_ok": None,
                "stopped_at": row["stopped_at"],
                "stopped_reason": error,
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=server_definition_id,
                source_resource_id=row["source_resource_id"],
                observation=observation,
            )
            self._event(
                connection,
                repo_id=str(row["repo_id"]),
                operation_id=operation_id,
                kind="server.stop.uncertain",
                code="server_stop_outcome_uncertain",
                message=error,
                diagnostic=error_payload,
                timestamp=timestamp,
            )
            current = self._resolve_server_row(
                connection, server_definition_id=server_definition_id
            )
            result = self._server_payload(connection, current)
            result.update(
                {
                    "operation_id": operation_id,
                    "reconciliation_required": True,
                    "cleanup_errors": cleanup_errors,
                }
            )
            return result

    def relocation_snapshot(
        self,
        *,
        old_project: str,
        name: str,
        port: int,
        lease_id: str,
    ) -> dict[str, Any]:
        with self.store.read_transaction() as connection:
            assignment = connection.execute(
                """
                SELECT p.*, r.canonical_root FROM port_assignments p
                JOIN repositories r USING(repo_id)
                WHERE r.canonical_root = ? AND p.server_name = ?
                  AND p.port = ? AND p.status = 'active'
                """,
                (old_project, name, int(port)),
            ).fetchone()
            if assignment is None:
                raise KeyError("matching active old-project assignment not found")
            lease = connection.execute(
                """
                SELECT l.*, r.canonical_root FROM leases l
                JOIN repositories r USING(repo_id)
                WHERE l.lease_id = ? AND r.canonical_root = ? AND l.port = ?
                """,
                (lease_id, old_project, int(port)),
            ).fetchone()
            if lease is None:
                raise KeyError("exact relocation lease not found")
            row = self._resolve_server_row(
                connection,
                canonical_project=old_project,
                name=name,
            )
            result = self._server_payload(connection, row)
            result["assignment"] = NormalizedPortLifecycle._assignment_payload(
                assignment
            )
            result["relocation_lease"] = NormalizedPortLifecycle._lease_payload(lease)
            return result

    def relocate(
        self,
        *,
        agent: str,
        old_project: str,
        new_project: str,
        name: str,
        port: int,
        lease_id: str,
        listener_present: bool,
        process_alive: bool,
    ) -> dict[str, Any]:
        if not agent.strip():
            raise ValueError("port relocate requires --agent")
        if old_project == new_project:
            raise ValueError("port relocate requires distinct old and new projects")
        if listener_present:
            raise NormalizedLifecycleConflict(
                f"port {port} still has a listener; stop it before relocation"
            )
        if process_alive:
            raise NormalizedLifecycleConflict(
                "recorded server process is still alive; stop it before relocation"
            )
        timestamp = utc_timestamp()
        with self.store.immediate_transaction() as connection:
            old_repository = NormalizedPortLifecycle._repository(
                connection, old_project
            )
            new_repository = NormalizedPortLifecycle._repository(
                connection, new_project
            )
            NormalizedPortLifecycle._require_installed(new_repository)
            assignment = connection.execute(
                """
                SELECT * FROM port_assignments
                WHERE repo_id = ? AND server_name = ? AND port = ?
                  AND status = 'active'
                """,
                (old_repository["repo_id"], name, int(port)),
            ).fetchone()
            if assignment is None:
                raise KeyError("matching active old-project assignment not found")
            lease = connection.execute(
                """
                SELECT * FROM leases
                WHERE lease_id = ? AND repo_id = ? AND port = ?
                  AND status IN ('active','stale','released')
                """,
                (lease_id, old_repository["repo_id"], int(port)),
            ).fetchone()
            if lease is None:
                raise KeyError("exact relocation lease not found")
            definition = connection.execute(
                """
                SELECT d.*, o.lifecycle, o.pid
                FROM server_definitions d
                LEFT JOIN server_observations o USING(server_definition_id)
                WHERE d.repo_id = ? AND d.name = ?
                """,
                (old_repository["repo_id"], name),
            ).fetchone()
            if definition is None:
                raise KeyError("matching old-project server definition not found")
            collision = connection.execute(
                "SELECT server_definition_id FROM server_definitions WHERE repo_id = ? AND name = ?",
                (new_repository["repo_id"], name),
            ).fetchone()
            if collision is not None:
                raise NormalizedLifecycleConflict(
                    "new project already has a server definition with this name"
                )
            pending = connection.execute(
                """
                SELECT o.operation_id FROM operations o
                JOIN operation_targets t USING(operation_id)
                WHERE o.status = 'running' AND (
                    (t.target_kind = 'server' AND t.target_id = ?)
                    OR (t.target_kind = 'lease' AND t.target_id = ?)
                    OR (t.target_kind = 'port_assignment' AND t.target_id = ?)
                ) LIMIT 1
                """,
                (
                    definition["server_definition_id"],
                    lease_id,
                    assignment["assignment_id"],
                ),
            ).fetchone()
            if pending is not None:
                raise NormalizedLifecycleConflict(
                    f"resource has a lifecycle operation in progress: {pending[0]}"
                )
            definition_payload = {
                "name": name,
                "role": definition["role"],
                "cwd": new_project,
                "argv": [],
                "environment": {},
                "health_url": None,
                "port": int(port),
                "host": "127.0.0.1",
                "relocated_from": old_project,
            }
            definition_fingerprint = fingerprint(definition_payload)
            connection.execute(
                """
                UPDATE server_definitions SET repo_id = ?, cwd = ?,
                    health_url_template = NULL, log_path = NULL,
                    definition_fingerprint = ?, generation = generation + 1,
                    updated_at = ?
                WHERE server_definition_id = ? AND repo_id = ?
                """,
                (
                    new_repository["repo_id"],
                    new_project,
                    definition_fingerprint,
                    timestamp,
                    definition["server_definition_id"],
                    old_repository["repo_id"],
                ),
            )
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (definition["server_definition_id"],),
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (definition["server_definition_id"],),
            )
            connection.execute(
                """
                UPDATE port_assignments SET repo_id = ?, host_id = ?,
                    generation = generation + 1, updated_at = ?
                WHERE assignment_id = ? AND status = 'active'
                """,
                (
                    new_repository["repo_id"],
                    new_repository["host_id"],
                    timestamp,
                    assignment["assignment_id"],
                ),
            )
            connection.execute(
                """
                UPDATE leases SET repo_id = ?, host_id = ?, status = 'stale',
                    deactivated_at = COALESCE(deactivated_at, ?),
                    generation = generation + 1, updated_at = ?
                WHERE lease_id = ?
                """,
                (
                    new_repository["repo_id"],
                    new_repository["host_id"],
                    timestamp,
                    timestamp,
                    lease_id,
                ),
            )
            connection.execute(
                """
                UPDATE repository_memberships SET repo_id = ?,
                    immutable_fingerprint = ?
                WHERE resource_kind = 'server' AND host_resource_id = ?
                """,
                (
                    new_repository["repo_id"],
                    definition_fingerprint,
                    definition["server_definition_id"],
                ),
            )
            connection.execute(
                """
                UPDATE control_bindings SET repo_id = ?,
                    generation = generation + 1, updated_at = ?
                WHERE resource_kind = 'server' AND resource_id = ?
                """,
                (
                    new_repository["repo_id"],
                    timestamp,
                    definition["server_definition_id"],
                ),
            )
            connection.execute(
                """
                UPDATE startup_policies SET repo_id = ?,
                    immutable_fingerprint = ?, generation = generation + 1,
                    updated_at = ?
                WHERE resource_kind = 'server' AND resource_id = ?
                """,
                (
                    new_repository["repo_id"],
                    definition_fingerprint,
                    timestamp,
                    definition["server_definition_id"],
                ),
            )
            previous_observation = connection.execute(
                "SELECT source_resource_id, listener_host FROM server_observations WHERE server_definition_id = ?",
                (definition["server_definition_id"],),
            ).fetchone()
            observation = {
                "lifecycle": "stopped",
                "pid": None,
                "process_start_time": None,
                "process_fingerprint": None,
                "listener_host": (
                    previous_observation["listener_host"]
                    if previous_observation is not None
                    else "127.0.0.1"
                ),
                "listener_port": int(port),
                "listener_observable": 1,
                "health_classification": "stopped",
                "health_ok": None,
                "stopped_at": timestamp,
                "stopped_reason": (
                    "Checkout ownership relocated; awaiting exact listener registration"
                ),
                "sampled_at": timestamp,
            }
            self._upsert_observation(
                connection,
                definition_id=str(definition["server_definition_id"]),
                source_resource_id=(
                    previous_observation["source_resource_id"]
                    if previous_observation is not None
                    else None
                ),
                observation=observation,
            )
            operation_id = str(uuid.uuid4())
            result_payload = {
                "server_definition_id": definition["server_definition_id"],
                "assignment_id": assignment["assignment_id"],
                "lease_id": lease_id,
                "old_project": old_project,
                "new_project": new_project,
                "port": int(port),
            }
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    process_fingerprint, error_code, error_message, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'port.relocate', 'succeeded', 'committed',
                          0, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?)
                """,
                (
                    operation_id,
                    new_repository["repo_id"],
                    fingerprint(result_payload),
                    os.geteuid(),
                    agent,
                    canonical_json(result_payload),
                    timestamp,
                    timestamp,
                ),
            )
            for ordinal, (kind, target_id) in enumerate(
                (
                    ("server", definition["server_definition_id"]),
                    ("lease", lease_id),
                    ("port_assignment", assignment["assignment_id"]),
                )
            ):
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id, action,
                        immutable_fingerprint, phase, status, result_json,
                        started_at, finished_at
                    ) VALUES (?, ?, ?, ?, 'relocate', ?, 'committed',
                              'succeeded', ?, ?, ?)
                    """,
                    (
                        operation_id,
                        ordinal,
                        kind,
                        target_id,
                        definition_fingerprint,
                        canonical_json(result_payload),
                        timestamp,
                        timestamp,
                    ),
                )
            self._event(
                connection,
                repo_id=str(new_repository["repo_id"]),
                operation_id=operation_id,
                kind="port.assignment.relocated",
                code="port_assignment_relocated",
                message=f"Relocated {name} port {port} to {new_project}",
                diagnostic=result_payload,
                timestamp=timestamp,
            )
            current = self._resolve_server_row(
                connection,
                server_definition_id=str(definition["server_definition_id"]),
            )
            result = self._server_payload(connection, current)
            result.update(result_payload)
            result["operation_id"] = operation_id
            return result

    @staticmethod
    def _server_select(where_clause: str) -> str:
        return f"""
            SELECT d.server_definition_id, d.repo_id, d.name, d.role, d.cwd,
                   d.health_url_template, d.log_path, d.definition_fingerprint,
                   d.generation AS definition_generation,
                   d.created_at AS definition_created_at,
                   d.updated_at AS definition_updated_at,
                   r.canonical_root, r.host_id,
                   o.source_resource_id, o.lifecycle, o.pid,
                   o.process_start_time, o.process_fingerprint,
                   o.listener_host, o.listener_port, o.listener_observable,
                   o.health_classification, o.health_ok, o.stopped_at,
                   o.stopped_reason, o.sampled_at,
                   o.observation_fingerprint,
                   l.lease_id, l.status AS lease_status,
                   l.agent AS lease_agent, l.purpose AS lease_purpose,
                   l.expires_at AS lease_expires_at,
                   p.assignment_id, p.port AS assigned_port,
                   p.status AS assignment_status
            FROM server_definitions d
            JOIN repositories r USING(repo_id)
            LEFT JOIN server_observations o USING(server_definition_id)
            LEFT JOIN leases l ON l.lease_id = (
                SELECT candidate.lease_id FROM leases candidate
                WHERE candidate.server_definition_id = d.server_definition_id
                ORDER BY CASE candidate.status WHEN 'active' THEN 0 ELSE 1 END,
                         candidate.updated_at DESC, candidate.lease_id DESC
                LIMIT 1
            )
            LEFT JOIN port_assignments p
              ON p.repo_id = d.repo_id AND p.server_name = d.name
             AND p.status = 'active'
            {where_clause}
        """

    def _resolve_server_row(
        self,
        connection: sqlite3.Connection,
        *,
        canonical_project: str | None = None,
        name: str | None = None,
        server_definition_id: str | None = None,
    ) -> sqlite3.Row:
        if server_definition_id:
            rows = connection.execute(
                self._server_select("WHERE d.server_definition_id = ?"),
                (server_definition_id,),
            ).fetchall()
        elif canonical_project and name:
            rows = connection.execute(
                self._server_select(
                    "WHERE r.canonical_root = ? AND d.name = ?"
                ),
                (canonical_project, name),
            ).fetchall()
        else:
            raise KeyError("server-id or project/name is required")
        if len(rows) != 1:
            raise KeyError("matching server not found")
        return rows[0]

    @staticmethod
    def _server_payload(
        connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        definition_id = str(row["server_definition_id"])
        argv = [
            str(item[0])
            for item in connection.execute(
                """
                SELECT argument FROM server_command_arguments
                WHERE server_definition_id = ? ORDER BY ordinal
                """,
                (definition_id,),
            )
        ]
        environment = {
            str(item[0]): str(item[1])
            for item in connection.execute(
                """
                SELECT name, value FROM server_environment
                WHERE server_definition_id = ? ORDER BY name
                """,
                (definition_id,),
            )
        }
        lifecycle = str(row["lifecycle"] or "unobserved")
        host = str(row["listener_host"] or "127.0.0.1")
        port = (
            int(row["listener_port"])
            if row["listener_port"] is not None
            else int(row["assigned_port"])
            if row["assigned_port"] is not None
            else None
        )
        health_ok = (
            None if row["health_ok"] is None else bool(row["health_ok"])
        )
        listener_observable = (
            None
            if row["listener_observable"] is None
            else bool(row["listener_observable"])
        )
        health = {
            "ok": health_ok,
            "classification": row["health_classification"] or "unobserved",
            "identity": {
                "ok": True if listener_observable is True else None,
                "observable": listener_observable,
            },
        }
        endpoint = f"http://{host}:{port}" if port is not None else None
        return {
            "id": definition_id,
            "key": f"{row['canonical_root']}::{row['name']}",
            "name": str(row["name"]),
            "role": row["role"],
            "agent": row["lease_agent"],
            "project": str(row["canonical_root"]),
            "cwd": str(row["cwd"]),
            "cmd_template": None,
            "argv_template": list(argv) if argv else None,
            "argv": argv,
            "cmd": " ".join(argv) if argv else None,
            "env": environment,
            "port": port,
            "host": host,
            "url": endpoint,
            "url_is_current": bool(
                endpoint
                and lifecycle in {"running", "starting", "unhealthy", "stopping"}
            ),
            "health_url": row["health_url_template"],
            "health_url_template": row["health_url_template"],
            "lease_id": row["lease_id"],
            "lease_status": row["lease_status"],
            "lease_source": (
                "manual"
                if str(row["lease_purpose"] or "") == "manual"
                else "managed"
            ),
            "pid": row["pid"],
            "process_start_time": row["process_start_time"],
            "process_fingerprint": row["process_fingerprint"],
            "registration_identity": (
                {"source": "normalized_exact_listener"}
                if row["pid"] is not None and port is not None
                else None
            ),
            "log_path": row["log_path"],
            "adopted": not bool(argv),
            "_managed_process_tree": bool(argv),
            "missing_command": not bool(argv),
            "metadata_source": "normalized-sqlite",
            "status": lifecycle,
            "health": health,
            "identity_observable": listener_observable,
            "stopped_at": row["stopped_at"],
            "stopped_reason": row["stopped_reason"],
            "generation": int(row["definition_generation"]),
            "created_at": row["definition_created_at"],
            "updated_at": row["sampled_at"] or row["definition_updated_at"],
            "assignment_id": row["assignment_id"],
            "assigned_port": row["assigned_port"],
            "_definition_fingerprint": row["definition_fingerprint"],
            "_observation_fingerprint": row["observation_fingerprint"],
            "_repo_id": row["repo_id"],
        }

    @staticmethod
    def _validate_start_request(request: ServerStartRequest) -> None:
        if not request.agent.strip():
            raise ValueError("server start requires --agent")
        if not request.name.strip():
            raise ValueError("server start requires --name")
        if not request.argv or any("\x00" in item for item in request.argv):
            raise ValueError("server start requires NUL-free structured argv")
        if not Path(request.cwd).is_dir():
            raise FileNotFoundError(
                f"server cwd does not exist or is not a directory: {request.cwd}"
            )
        if not 1 <= request.port_start <= request.port_end <= 65535:
            raise ValueError("invalid server port range")
        if request.preferred is not None and not (
            request.port_start <= request.preferred <= request.port_end
        ):
            raise ValueError("preferred server port is outside the requested range")
        if request.ttl_seconds < 0:
            raise ValueError("server lease ttl must not be negative")

    @staticmethod
    def _validate_manual_lease(
        lease: sqlite3.Row | None,
        *,
        request: ServerStartRequest,
        repo_id: str,
        available: list[int],
    ) -> None:
        lease_id = request.manual_lease_id
        if lease is None:
            raise KeyError(f"manual lease not found or inactive: {lease_id}")
        if str(lease["repo_id"]) != repo_id:
            raise PermissionError(
                f"manual lease {lease_id} project does not match server start project"
            )
        if str(lease["agent"] or "") != request.agent:
            raise PermissionError(
                f"manual lease {lease_id} agent does not match server start agent"
            )
        if str(lease["purpose"] or "") != "manual":
            raise ValueError(
                f"server start --lease-id requires a manual lease, got {lease['purpose']!r}"
            )
        if lease["server_definition_id"] is not None:
            raise ValueError(f"manual lease {lease_id} is already attached")
        if lease["expires_at"] is not None:
            try:
                expiry = datetime.fromisoformat(
                    str(lease["expires_at"]).replace("Z", "+00:00")
                )
            except ValueError:
                expiry = datetime.fromtimestamp(
                    float(lease["expires_at"]), timezone.utc
                )
            if expiry <= datetime.now(timezone.utc):
                raise ValueError(f"manual lease {lease_id} expired")
        port = int(lease["port"])
        if port not in available:
            raise RuntimeError(
                f"manual lease {lease_id} port is no longer available: "
                f"{request.host}:{port}"
            )
        if request.preferred is not None and int(request.preferred) != port:
            raise ValueError(
                f"manual lease {lease_id} owns port {port}, not preferred port "
                f"{request.preferred}"
            )

    @staticmethod
    def _foreign_assignment_at_port(
        connection: sqlite3.Connection,
        *,
        host_id: str,
        repo_id: str,
        server_name: str,
        port: int,
    ) -> bool:
        row = connection.execute(
            """
            SELECT assignment_id FROM port_assignments
            WHERE host_id = ? AND port = ? AND status = 'active'
              AND NOT (repo_id = ? AND server_name = ?)
            LIMIT 1
            """,
            (host_id, int(port), repo_id, server_name),
        ).fetchone()
        return row is not None

    @staticmethod
    def _definition_payload(
        request: ServerStartRequest, selected_port: int
    ) -> dict[str, Any]:
        return {
            "name": request.name,
            "role": request.role,
            "cwd": request.cwd,
            "argv": list(request.argv),
            "environment": dict(sorted(request.environment.items())),
            "health_url": request.health_url,
            "port": int(selected_port),
            "host": request.host,
        }

    @staticmethod
    def _replace_definition_details(
        connection: sqlite3.Connection,
        *,
        definition_id: str,
        argv: tuple[str, ...],
        environment: dict[str, str],
    ) -> None:
        connection.execute(
            "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
            (definition_id,),
        )
        for ordinal, argument in enumerate(argv):
            connection.execute(
                "INSERT INTO server_command_arguments VALUES (?, ?, ?)",
                (definition_id, ordinal, str(argument)),
            )
        connection.execute(
            "DELETE FROM server_environment WHERE server_definition_id = ?",
            (definition_id,),
        )
        for name, value in sorted(environment.items()):
            connection.execute(
                "INSERT INTO server_environment VALUES (?, ?, ?)",
                (definition_id, str(name), str(value)),
            )

    def _ensure_server_authority(
        self,
        connection: sqlite3.Connection,
        *,
        repository: sqlite3.Row,
        definition_id: str,
        definition_fingerprint: str,
        timestamp: str,
    ) -> None:
        source_id = deterministic_id(
            "normalized-account-source",
            str(repository["host_id"]),
            str(self.store.path.parent),
        )
        connection.execute(
            """
            INSERT INTO coordinator_sources(
                source_id, host_id, canonical_home, state_path, effective_uid,
                status, captured_revision, captured_sha256, imported_at,
                retired_at, late_writer_detected_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'imported', NULL, NULL, ?, NULL, NULL, ?, ?)
            ON CONFLICT(host_id, canonical_home) DO UPDATE SET
                state_path = excluded.state_path, status = 'imported',
                imported_at = COALESCE(coordinator_sources.imported_at,
                                       excluded.imported_at),
                updated_at = excluded.updated_at
            """,
            (
                source_id,
                repository["host_id"],
                str(self.store.path),
                str(self.store.path),
                self.store.expected_uid,
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        authoritative = connection.execute(
            """
            SELECT * FROM control_bindings
            WHERE resource_kind = 'server' AND resource_id = ?
              AND authority_state = 'authoritative'
            """,
            (definition_id,),
        ).fetchone()
        binding_id = (
            str(authoritative["binding_id"])
            if authoritative is not None
            else deterministic_id("control-binding", "server", definition_id)
        )
        source_resource_id = (
            authoritative["source_resource_id"]
            if authoritative is not None
            else None
        )
        connection.execute(
            """
            INSERT INTO control_bindings(
                binding_id, repo_id, source_resource_id, resource_kind,
                resource_id, source_id, capability, provenance,
                authority_state, priority, generation, created_at, updated_at
            ) VALUES (?, ?, ?, 'server', ?, ?, 'lifecycle',
                      'normalized_direct_control', 'authoritative', 100, 0, ?, ?)
            ON CONFLICT(binding_id) DO UPDATE SET
                repo_id = excluded.repo_id,
                source_id = excluded.source_id,
                capability = excluded.capability,
                provenance = excluded.provenance,
                authority_state = 'authoritative', priority = 100,
                generation = control_bindings.generation + 1,
                updated_at = excluded.updated_at
            """,
            (
                binding_id,
                repository["repo_id"],
                source_resource_id,
                definition_id,
                source_id,
                timestamp,
                timestamp,
            ),
        )
        membership_id = deterministic_id(
            "membership", str(repository["repo_id"]), "server", definition_id
        )
        connection.execute(
            """
            INSERT INTO repository_memberships(
                membership_id, repo_id, resource_kind, host_resource_id,
                immutable_fingerprint, control_binding_id, created_at
            ) VALUES (?, ?, 'server', ?, ?, ?, ?)
            ON CONFLICT(resource_kind, host_resource_id) DO UPDATE SET
                repo_id = excluded.repo_id,
                immutable_fingerprint = excluded.immutable_fingerprint,
                control_binding_id = excluded.control_binding_id
            """,
            (
                membership_id,
                repository["repo_id"],
                definition_id,
                definition_fingerprint,
                binding_id,
                timestamp,
            ),
        )
        policy_id = deterministic_id(
            "startup-policy", "server", definition_id, "coordinator"
        )
        connection.execute(
            """
            INSERT INTO startup_policies(
                policy_id, repo_id, resource_kind, resource_id, policy_kind,
                current_value, desired_disabled_value, immutable_fingerprint,
                generation, updated_at
            ) VALUES (?, ?, 'server', ?, 'coordinator', 'enabled', 'disabled',
                      ?, 0, ?)
            ON CONFLICT(resource_kind, resource_id, policy_kind) DO UPDATE SET
                repo_id = excluded.repo_id,
                current_value = 'enabled',
                immutable_fingerprint = excluded.immutable_fingerprint,
                generation = startup_policies.generation + 1,
                updated_at = excluded.updated_at
            """,
            (
                policy_id,
                repository["repo_id"],
                definition_id,
                definition_fingerprint,
                timestamp,
            ),
        )

    @staticmethod
    def _require_no_pending_server_operation(
        connection: sqlite3.Connection, definition_id: str
    ) -> None:
        row = connection.execute(
            """
            SELECT o.operation_id, o.kind FROM operations o
            JOIN operation_targets t USING(operation_id)
            WHERE o.status IN ('planned','running','partial','needs_attention')
              AND t.target_kind = 'server' AND t.target_id = ?
            LIMIT 1
            """,
            (definition_id,),
        ).fetchone()
        if row is not None:
            raise NormalizedLifecycleConflict(
                f"server has an operation in progress: {row['operation_id']} "
                f"({row['kind']})"
            )

    @staticmethod
    def _insert_operation_targets(
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        server_definition_id: str,
        definition_fingerprint: str,
        lease_id: str | None,
        action: str,
        phase: str,
        status: str = "running",
        finished_at: str | None = None,
    ) -> None:
        targets = [("server", server_definition_id, definition_fingerprint)]
        if lease_id:
            targets.append(("lease", lease_id, fingerprint({"lease_id": lease_id})))
        for ordinal, (kind, target_id, immutable_fingerprint) in enumerate(targets):
            connection.execute(
                """
                INSERT INTO operation_targets(
                    operation_id, ordinal, target_kind, target_id, action,
                    immutable_fingerprint, phase, status, result_json,
                    error_json, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    operation_id,
                    ordinal,
                    kind,
                    target_id,
                    action,
                    immutable_fingerprint,
                    phase,
                    status,
                    utc_timestamp(),
                    finished_at,
                ),
            )

    @staticmethod
    def _upsert_observation(
        connection: sqlite3.Connection,
        *,
        definition_id: str,
        source_resource_id: str | None,
        observation: dict[str, Any],
    ) -> None:
        observation_fingerprint = fingerprint(observation)
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id, source_resource_id, lifecycle, pid,
                process_start_time, process_fingerprint, listener_host,
                listener_port, listener_observable, health_classification,
                health_ok, stopped_at, stopped_reason, sampled_at,
                observation_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_definition_id) DO UPDATE SET
                source_resource_id = excluded.source_resource_id,
                lifecycle = excluded.lifecycle, pid = excluded.pid,
                process_start_time = excluded.process_start_time,
                process_fingerprint = excluded.process_fingerprint,
                listener_host = excluded.listener_host,
                listener_port = excluded.listener_port,
                listener_observable = excluded.listener_observable,
                health_classification = excluded.health_classification,
                health_ok = excluded.health_ok,
                stopped_at = excluded.stopped_at,
                stopped_reason = excluded.stopped_reason,
                sampled_at = excluded.sampled_at,
                observation_fingerprint = excluded.observation_fingerprint
            """,
            (
                definition_id,
                source_resource_id,
                observation["lifecycle"],
                observation["pid"],
                observation["process_start_time"],
                observation["process_fingerprint"],
                observation["listener_host"],
                observation["listener_port"],
                observation["listener_observable"],
                observation["health_classification"],
                observation["health_ok"],
                observation["stopped_at"],
                observation["stopped_reason"],
                observation["sampled_at"],
                observation_fingerprint,
            ),
        )

    @staticmethod
    def _running_operation(
        connection: sqlite3.Connection, operation_id: str, kind: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM operations
            WHERE operation_id = ? AND kind = ? AND status = 'running'
            """,
            (operation_id, kind),
        ).fetchone()
        if row is None:
            raise NormalizedLifecycleConflict(
                f"{kind} reservation is no longer running: {operation_id}"
            )
        return row

    @staticmethod
    def _listener_observable(health: dict[str, Any]) -> int | None:
        identity = health.get("identity") or {}
        if (
            health.get("classification") == "unverified-listener"
            or ("ok" in health and health.get("ok") is None)
            or identity.get("observable") is False
            or ("ok" in identity and identity.get("ok") is None)
        ):
            return 0
        if identity.get("ok") is not None or health.get("pid_alive") is False:
            return 1
        return None

    @staticmethod
    def _nullable_bool(value: Any) -> int | None:
        return None if value is None else int(bool(value))

    @staticmethod
    def _expiry(ttl_seconds: int) -> str | None:
        if int(ttl_seconds) <= 0:
            return None
        return (
            (datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds)))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        repo_id: str,
        operation_id: str | None,
        kind: str,
        code: str,
        message: str,
        diagnostic: dict[str, Any],
        timestamp: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO events(
                event_id, repo_id, source_id, operation_id, event_kind,
                code, message, diagnostic_json, occurred_at
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                repo_id,
                operation_id,
                kind,
                code,
                message,
                json.dumps(diagnostic, separators=(",", ":"), sort_keys=True),
                timestamp,
            ),
        )
