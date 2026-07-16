"""Service-owned broker ACL, lease, and durable idempotency persistence.

Clients never receive this database path or a SQLite handle.  Every method
opens the private coordinator store as the broker service UID and exposes a
typed operation only; wire documents cannot supply SQL, commands, or paths.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Generator, Iterable, Mapping, Optional
import uuid

from .broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
    authenticated_request_fingerprint,
)
from .store import AccountStore, CoordinatorStore, utc_timestamp
from .database_backups import (
    inspect_database_backup,
    record_successful_restore,
    upsert_database_backup,
)


DEFAULT_PORT_LEASE_TTL_SECONDS = 600
_REPOSITORY_LIFECYCLE_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
    }
)
_RESOURCE_LIFECYCLE_OPERATIONS = frozenset(
    {
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_RETIRE,
    }
)
_LIFECYCLE_OPERATIONS = _REPOSITORY_LIFECYCLE_OPERATIONS | _RESOURCE_LIFECYCLE_OPERATIONS
_LIFECYCLE_PLAN_OPERATIONS_FOR_PERSISTENCE = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
    }
)
_DATABASE_OPERATIONS = frozenset(
    {BrokerOperation.DATABASE_BACKUP, BrokerOperation.DATABASE_RESTORE}
)
_REPOSITORY_READ_OPERATIONS = frozenset({BrokerOperation.REPOSITORY_LIST_REMOVED})
_HOST_READ_OPERATIONS = frozenset({BrokerOperation.INVENTORY_READ})


class _BrokerInventoryStore(AccountStore):
    """Reuse one authorized read snapshot inside the inventory projection."""

    @contextmanager
    def read_transaction(self) -> Generator[sqlite3.Connection, None, None]:
        if self.connection.in_transaction:
            yield self.connection
            return
        with super().read_transaction() as connection:
            yield connection


BROKER_SCHEMA = """
CREATE TABLE IF NOT EXISTS broker_acl_principals (
    uid INTEGER PRIMARY KEY CHECK(uid >= 0),
    account_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_resource_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server', 'container')),
    resource_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'port.lease', 'port.release', 'docker.start', 'docker.stop', 'docker.restart'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, resource_kind, resource_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_assignment_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN ('port.assign', 'port.unassign')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, server_definition_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_assignment_owners (
    assignment_id TEXT PRIMARY KEY
        REFERENCES port_assignments(assignment_id) ON DELETE CASCADE,
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE RESTRICT,
    account_id TEXT NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_compose_definitions (
    compose_definition_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    cwd TEXT NOT NULL,
    project_name TEXT NOT NULL,
    definition_fingerprint TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, project_name)
);

CREATE TABLE IF NOT EXISTS broker_compose_files (
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    file_path TEXT NOT NULL,
    PRIMARY KEY(compose_definition_id, ordinal),
    UNIQUE(compose_definition_id, file_path)
);

CREATE TABLE IF NOT EXISTS broker_compose_file_evidence (
    compose_definition_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    content_sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
    PRIMARY KEY(compose_definition_id, ordinal),
    FOREIGN KEY(compose_definition_id, ordinal)
        REFERENCES broker_compose_files(compose_definition_id, ordinal)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS broker_compose_services (
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    service_name TEXT NOT NULL,
    PRIMARY KEY(compose_definition_id, ordinal),
    UNIQUE(compose_definition_id, service_name)
);

CREATE TABLE IF NOT EXISTS broker_compose_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN ('compose.up', 'compose.down')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, compose_definition_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_lifecycle_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'repository.plan_remove', 'repository.remove', 'repository.reinstall',
        'resource.attach', 'resource.plan_retire', 'resource.retire'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_lifecycle_resource_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server', 'container', 'supervisor')),
    resource_id TEXT NOT NULL,
    control_binding_id TEXT NOT NULL
        REFERENCES control_bindings(binding_id) ON DELETE CASCADE,
    immutable_fingerprint TEXT NOT NULL,
    ownership_fingerprint TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'resource.attach', 'resource.plan_retire', 'resource.retire'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, resource_kind, resource_id, control_binding_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_repository_read_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN ('repository.list_removed')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_lifecycle_plan_observations (
    plan_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL
        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
    observer_domain TEXT NOT NULL,
    docker_available INTEGER NOT NULL CHECK(docker_available = 1),
    capability_fingerprint TEXT NOT NULL,
    material_fingerprint TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    bound_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_database_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    database_binding_id TEXT NOT NULL
        REFERENCES database_bindings(database_binding_id) ON DELETE CASCADE,
    docker_resource_id TEXT NOT NULL
        REFERENCES docker_resources(docker_resource_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN ('database.backup', 'database.restore')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, database_binding_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_database_host_results (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    result_json TEXT NOT NULL,
    result_fingerprint TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_port_policies (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    start_port INTEGER NOT NULL CHECK(start_port BETWEEN 1 AND 65535),
    end_port INTEGER NOT NULL CHECK(end_port BETWEEN start_port AND 65535),
    max_ttl_seconds INTEGER NOT NULL CHECK(max_ttl_seconds BETWEEN 1 AND 604800),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, server_definition_id, protocol, start_port, end_port)
);

CREATE TABLE IF NOT EXISTS broker_operation_requests (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE RESTRICT,
    account_id TEXT NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_lease_owners (
    lease_id TEXT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE RESTRICT,
    account_id TEXT NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE RESTRICT,
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS broker_acl_by_resource
ON broker_resource_acl(repo_id, resource_kind, resource_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_port_policy_lookup
ON broker_port_policies(uid, repo_id, server_definition_id, protocol, enabled);

CREATE INDEX IF NOT EXISTS broker_assignment_acl_lookup
ON broker_assignment_acl(repo_id, server_definition_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_compose_acl_lookup
ON broker_compose_acl(repo_id, compose_definition_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_lifecycle_acl_lookup
ON broker_lifecycle_acl(repo_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_lifecycle_resource_acl_lookup
ON broker_lifecycle_resource_acl(
    repo_id, resource_kind, resource_id, control_binding_id, operation, enabled
);

CREATE INDEX IF NOT EXISTS broker_repository_read_acl_lookup
ON broker_repository_read_acl(repo_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_database_acl_lookup
ON broker_database_acl(repo_id, docker_resource_id, database_binding_id, operation, enabled);
"""


@dataclass(frozen=True)
class DurableOperationDisposition:
    state: str
    result: Optional[dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


@dataclass(frozen=True)
class DockerMutationTarget:
    docker_resource_id: str
    full_container_id: str
    observation_revision: int
    control_generation: int


@dataclass(frozen=True)
class DatabaseMutationTarget:
    database_binding_id: str
    docker_resource_id: str
    full_container_id: str
    database_name: str
    observation_revision: int
    control_generation: int


@dataclass(frozen=True)
class RegisteredDatabaseBackup:
    database_backup_id: str
    database_binding_id: str
    artifact_path: str
    manifest_path: str
    artifact_sha256: str


@dataclass(frozen=True)
class ComposeMutationTarget:
    compose_definition_id: str
    repo_id: str
    canonical_root: str
    cwd: str
    compose_files: tuple[str, ...]
    compose_file_sha256s: tuple[str, ...]
    compose_file_sizes: tuple[int, ...]
    services: tuple[str, ...]
    project_name: str
    definition_fingerprint: str
    definition_generation: int
    repository_generation: int


class StoreBackedAuthorizer:
    """Live ACL authorizer; every request reads the current durable policy."""

    def __init__(self, persistence: "BrokerPersistence") -> None:
        self._persistence = persistence

    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        return self._persistence.authorize(peer, request)


class BrokerPersistence:
    """Typed access to a private service-owned normalized coordinator store."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        expected_uid: Optional[int] = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.database_path = Path(database_path)
        self.expected_uid = os.geteuid() if expected_uid is None else int(expected_uid)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.initialize()

    @contextmanager
    def _store(self) -> Generator[CoordinatorStore, None, None]:
        with CoordinatorStore.open(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            yield store

    def initialize(self) -> None:
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                for statement in BROKER_SCHEMA.split(";"):
                    if statement.strip():
                        connection.execute(statement)

    def provision_principal(
        self, *, uid: int, account_id: str, enabled: bool = True
    ) -> None:
        if type(uid) is not int or uid < 0:
            raise ValueError("uid must be a non-negative integer")
        _require_identifier(account_id, "account_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO broker_acl_principals(uid, account_id, enabled, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(uid) DO UPDATE SET
                        account_id = excluded.account_id,
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (uid, account_id, int(enabled), utc_timestamp()),
                )

    def provision_compose_definition(
        self,
        *,
        compose_definition_id: str,
        repo_id: str,
        cwd: str | os.PathLike[str],
        files: Iterable[str | os.PathLike[str]],
        services: Iterable[str] = (),
        project_name: Optional[str] = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Persist one trusted Compose definition outside the client protocol.

        This is an administrator/service provisioning interface.  Its paths
        are canonicalized and confined to the repository before the database
        transaction; broker clients can reference only ``compose_definition_id``.
        """

        _require_identifier(compose_definition_id, "compose_definition_id")
        _require_identifier(repo_id, "project_id")
        if isinstance(files, (str, bytes, os.PathLike)):
            raise ValueError("files must be an iterable of Compose file paths")
        if isinstance(services, (str, bytes)):
            raise ValueError("services must be an iterable of Compose service names")
        supplied_files = tuple(files)
        normalized_services = tuple(
            _require_compose_service_name(item) for item in services
        )
        if len(normalized_services) > 128:
            raise ValueError("services must contain at most 128 names")
        if len(set(normalized_services)) != len(normalized_services):
            raise ValueError("services must not contain duplicates")
        if not 1 <= len(supplied_files) <= 16:
            raise ValueError("compose_files must contain from one through 16 paths")

        with self._store() as store:
            with store.read_transaction() as connection:
                repo = connection.execute(
                    "SELECT canonical_root FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
        if repo is None:
            raise BrokerError(
                "project_access_denied", "Compose repository is not provisioned."
            )
        canonical_root = _canonical_existing_path(
            repo["canonical_root"], field="repository root", directory=True
        )
        normalized_project_name = _require_compose_project_name(
            project_name
            if project_name is not None
            else _default_compose_project_name(Path(canonical_root).name)
        )
        canonical_cwd = _canonical_existing_path(cwd, field="compose cwd", directory=True)
        _require_path_within(canonical_cwd, canonical_root, field="compose cwd")
        canonical_files = tuple(
            _canonical_existing_path(item, field="compose file", directory=False)
            for item in supplied_files
        )
        if len(set(canonical_files)) != len(canonical_files):
            raise ValueError("compose_files must not contain duplicate canonical paths")
        for file_path in canonical_files:
            _require_path_within(file_path, canonical_root, field="compose file")
        file_evidence = tuple(_compose_file_evidence(item) for item in canonical_files)
        definition_fingerprint = _compose_definition_fingerprint(
            repo_id=repo_id,
            cwd=canonical_cwd,
            compose_files=canonical_files,
            compose_file_evidence=file_evidence,
            services=normalized_services,
            project_name=normalized_project_name,
        )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                current_repo = connection.execute(
                    "SELECT canonical_root FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                if current_repo is None or str(current_repo["canonical_root"]) != canonical_root:
                    raise BrokerError(
                        "stale_compose_definition",
                        "Repository identity changed while provisioning Compose.",
                    )
                existing = connection.execute(
                    """
                    SELECT repo_id, definition_fingerprint, generation, created_at
                    FROM broker_compose_definitions
                    WHERE compose_definition_id = ?
                    """,
                    (compose_definition_id,),
                ).fetchone()
                if existing is not None and existing["repo_id"] != repo_id:
                    raise BrokerError(
                        "compose_definition_conflict",
                        "Compose definition identifier already belongs to another repository.",
                    )
                generation = (
                    0
                    if existing is None
                    else int(existing["generation"])
                    + int(existing["definition_fingerprint"] != definition_fingerprint)
                )
                created_at = now if existing is None else str(existing["created_at"])
                try:
                    connection.execute(
                        """
                        INSERT INTO broker_compose_definitions(
                            compose_definition_id, repo_id, cwd, project_name,
                            definition_fingerprint, enabled, generation,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(compose_definition_id) DO UPDATE SET
                            cwd = excluded.cwd,
                            project_name = excluded.project_name,
                            definition_fingerprint = excluded.definition_fingerprint,
                            enabled = excluded.enabled,
                            generation = excluded.generation,
                            updated_at = excluded.updated_at
                        """,
                        (
                            compose_definition_id,
                            repo_id,
                            canonical_cwd,
                            normalized_project_name,
                            definition_fingerprint,
                            int(enabled),
                            generation,
                            created_at,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise BrokerError(
                        "compose_definition_conflict",
                        "Repository already has a conflicting Compose project identity.",
                    ) from exc
                connection.execute(
                    "DELETE FROM broker_compose_files WHERE compose_definition_id = ?",
                    (compose_definition_id,),
                )
                connection.execute(
                    "DELETE FROM broker_compose_services WHERE compose_definition_id = ?",
                    (compose_definition_id,),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_files(
                        compose_definition_id, ordinal, file_path
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (compose_definition_id, ordinal, file_path)
                        for ordinal, file_path in enumerate(canonical_files)
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_file_evidence(
                        compose_definition_id, ordinal, content_sha256, byte_size
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        (
                            compose_definition_id,
                            ordinal,
                            evidence["content_sha256"],
                            evidence["byte_size"],
                        )
                        for ordinal, evidence in enumerate(file_evidence)
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_services(
                        compose_definition_id, ordinal, service_name
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (compose_definition_id, ordinal, service_name)
                        for ordinal, service_name in enumerate(normalized_services)
                    ),
                )
        return {
            "compose_definition_id": compose_definition_id,
            "repo_id": repo_id,
            "definition_fingerprint": definition_fingerprint,
            "generation": generation,
            "enabled": bool(enabled),
        }

    def list_compose_definitions(
        self, *, repo_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Return trusted administrative Compose definitions and exact IDs."""

        if repo_id is not None:
            _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT compose_definition_id, repo_id, cwd, project_name,
                               definition_fingerprint, enabled, generation,
                               created_at, updated_at
                        FROM broker_compose_definitions
                        WHERE (? IS NULL OR repo_id = ?)
                        ORDER BY repo_id, compose_definition_id
                        """,
                        (repo_id, repo_id),
                    )
                )
                results: list[dict[str, Any]] = []
                for row in rows:
                    definition_id = str(row["compose_definition_id"])
                    files = [
                        str(item["file_path"])
                        for item in connection.execute(
                            """
                            SELECT file_path FROM broker_compose_files
                            WHERE compose_definition_id = ? ORDER BY ordinal
                            """,
                            (definition_id,),
                        )
                    ]
                    file_evidence = [
                        {
                            "content_sha256": str(item["content_sha256"]),
                            "byte_size": int(item["byte_size"]),
                        }
                        for item in connection.execute(
                            """
                            SELECT content_sha256, byte_size
                            FROM broker_compose_file_evidence
                            WHERE compose_definition_id = ? ORDER BY ordinal
                            """,
                            (definition_id,),
                        )
                    ]
                    services = [
                        str(item["service_name"])
                        for item in connection.execute(
                            """
                            SELECT service_name FROM broker_compose_services
                            WHERE compose_definition_id = ? ORDER BY ordinal
                            """,
                            (definition_id,),
                        )
                    ]
                    results.append(
                        {
                            "compose_definition_id": definition_id,
                            "repo_id": str(row["repo_id"]),
                            "cwd": str(row["cwd"]),
                            "files": files,
                            "file_evidence": file_evidence,
                            "services": services,
                            "project_name": str(row["project_name"]),
                            "definition_fingerprint": str(
                                row["definition_fingerprint"]
                            ),
                            "enabled": bool(row["enabled"]),
                            "generation": int(row["generation"]),
                            "created_at": str(row["created_at"]),
                            "updated_at": str(row["updated_at"]),
                        }
                    )
                return results

    def grant_resource(
        self,
        *,
        uid: int,
        repo_id: str,
        resource_kind: str,
        resource_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        _require_identifier(repo_id, "project_id")
        _require_identifier(resource_id, "resource_id")
        if resource_kind not in {"server", "container", "compose"}:
            raise ValueError("resource_kind must be server, container, or compose")
        if operation in {
            BrokerOperation.PORT_LEASE,
            BrokerOperation.PORT_RELEASE,
            BrokerOperation.PORT_ASSIGN,
            BrokerOperation.PORT_UNASSIGN,
        }:
            expected_kind = "server"
        elif operation in {BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN}:
            expected_kind = "compose"
        else:
            expected_kind = "container"
        if resource_kind != expected_kind:
            raise ValueError("resource kind does not match broker operation")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                _require_resource_membership(
                    connection,
                    repo_id=repo_id,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                )
                if operation in {
                    BrokerOperation.PORT_ASSIGN,
                    BrokerOperation.PORT_UNASSIGN,
                }:
                    connection.execute(
                        """
                        INSERT INTO broker_assignment_acl(
                            uid, repo_id, server_definition_id, operation, enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(uid, repo_id, server_definition_id, operation)
                        DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                        """,
                        (
                            uid,
                            repo_id,
                            resource_id,
                            operation.value,
                            int(enabled),
                            utc_timestamp(),
                        ),
                    )

                elif operation in {BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN}:
                    connection.execute(
                        """
                        INSERT INTO broker_compose_acl(
                            uid, repo_id, compose_definition_id, operation, enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(uid, repo_id, compose_definition_id, operation)
                        DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                        """,
                        (
                            uid,
                            repo_id,
                            resource_id,
                            operation.value,
                            int(enabled),
                            utc_timestamp(),
                        ),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO broker_resource_acl(
                            uid, repo_id, resource_kind, resource_id, operation, enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(uid, repo_id, resource_kind, resource_id, operation)
                        DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                        """,
                        (
                            uid,
                            repo_id,
                            resource_kind,
                            resource_id,
                            operation.value,
                            int(enabled),
                            utc_timestamp(),
                        ),
                    )

    def replace_server_access(
        self,
        *,
        uid: int,
        repo_id: str,
        server_definition_ids: Iterable[str],
        start_port: int,
        end_port: int,
        protocol: str = "tcp",
        max_ttl_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        """Atomically replace one principal's exact server mutation allowlist."""

        _require_identifier(repo_id, "project_id")
        requested = tuple(server_definition_ids)
        if any(type(item) is not str for item in requested):
            raise ValueError("server definition ids must be strings")
        for item in requested:
            _require_identifier(item, "server_definition_id")
        selected = tuple(sorted(set(requested)))
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("server port range is invalid")
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        if not 1 <= max_ttl_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("max_ttl_seconds is invalid")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                known = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT server_definition_id FROM server_definitions WHERE repo_id = ?",
                        (repo_id,),
                    )
                }
                if any(item not in known for item in selected):
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Server access replacement includes a definition outside the exact repository.",
                    )
                connection.execute(
                    """
                    UPDATE broker_resource_acl SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ? AND resource_kind = 'server'
                      AND operation IN ('port.lease', 'port.release')
                    """,
                    (now, uid, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_assignment_acl SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (now, uid, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_port_policies SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (now, uid, repo_id),
                )
                for server_id in selected:
                    for operation in (
                        BrokerOperation.PORT_LEASE,
                        BrokerOperation.PORT_RELEASE,
                    ):
                        connection.execute(
                            """
                            INSERT INTO broker_resource_acl(
                                uid, repo_id, resource_kind, resource_id,
                                operation, enabled, updated_at
                            ) VALUES (?, ?, 'server', ?, ?, 1, ?)
                            ON CONFLICT(uid, repo_id, resource_kind, resource_id, operation)
                            DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                            """,
                            (uid, repo_id, server_id, operation.value, now),
                        )
                    for operation in (
                        BrokerOperation.PORT_ASSIGN,
                        BrokerOperation.PORT_UNASSIGN,
                    ):
                        connection.execute(
                            """
                            INSERT INTO broker_assignment_acl(
                                uid, repo_id, server_definition_id,
                                operation, enabled, updated_at
                            ) VALUES (?, ?, ?, ?, 1, ?)
                            ON CONFLICT(uid, repo_id, server_definition_id, operation)
                            DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                            """,
                            (uid, repo_id, server_id, operation.value, now),
                        )
                    connection.execute(
                        """
                        INSERT INTO broker_port_policies(
                            uid, repo_id, server_definition_id, protocol,
                            start_port, end_port, max_ttl_seconds,
                            enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                        ON CONFLICT(
                            uid, repo_id, server_definition_id,
                            protocol, start_port, end_port
                        ) DO UPDATE SET
                            max_ttl_seconds = excluded.max_ttl_seconds,
                            enabled = 1,
                            updated_at = excluded.updated_at
                        """,
                        (
                            uid,
                            repo_id,
                            server_id,
                            protocol,
                            start_port,
                            end_port,
                            max_ttl_seconds,
                            now,
                        ),
                    )

    def grant_port_range(
        self,
        *,
        uid: int,
        repo_id: str,
        server_definition_id: str,
        start_port: int,
        end_port: int,
        protocol: str = "tcp",
        max_ttl_seconds: int = 3_600,
        enabled: bool = True,
    ) -> None:
        if (
            type(start_port) is not int
            or type(end_port) is not int
            or not 1 <= start_port <= end_port <= 65_535
        ):
            raise ValueError("port range must be within 1 through 65535")
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        if type(max_ttl_seconds) is not int or not 1 <= max_ttl_seconds <= 604_800:
            raise ValueError("max_ttl_seconds must be from one second to seven days")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                _require_resource_membership(
                    connection,
                    repo_id=repo_id,
                    resource_kind="server",
                    resource_id=server_definition_id,
                )
                conflict = connection.execute(
                    """
                    SELECT start_port, end_port FROM broker_port_policies
                    WHERE uid = ? AND repo_id = ? AND server_definition_id = ?
                      AND protocol = ? AND enabled = 1
                      AND NOT(end_port < ? OR start_port > ?)
                      AND NOT(start_port = ? AND end_port = ?)
                    LIMIT 1
                    """,
                    (
                        uid,
                        repo_id,
                        server_definition_id,
                        protocol,
                        start_port,
                        end_port,
                        start_port,
                        end_port,
                    ),
                ).fetchone()
                if conflict is not None:
                    raise BrokerError(
                        "overlapping_port_policy",
                        "Port policies for one resource must not overlap.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_port_policies(
                        uid, repo_id, server_definition_id, protocol,
                        start_port, end_port, max_ttl_seconds, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, server_definition_id, protocol, start_port, end_port)
                    DO UPDATE SET max_ttl_seconds = excluded.max_ttl_seconds,
                                  enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        server_definition_id,
                        protocol,
                        start_port,
                        end_port,
                        max_ttl_seconds,
                        int(enabled),
                        utc_timestamp(),
                    ),
                )

    def grant_lifecycle(
        self,
        *,
        uid: int,
        repo_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        if operation not in _LIFECYCLE_OPERATIONS:
            raise ValueError("operation is not a broker lifecycle operation")
        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone() is None:
                    raise BrokerError(
                        "project_access_denied", "Lifecycle repository is not provisioned."
                    )
                connection.execute(
                    """
                    INSERT INTO broker_lifecycle_acl(
                        uid, repo_id, operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, operation)
                    DO UPDATE SET enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (uid, repo_id, operation.value, int(enabled), utc_timestamp()),
                )

    def grant_database(
        self,
        *,
        uid: int,
        repo_id: str,
        database_binding_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        if operation not in {
            BrokerOperation.DATABASE_BACKUP,
            BrokerOperation.DATABASE_RESTORE,
        }:
            raise ValueError("operation is not a broker database operation")
        _require_identifier(repo_id, "project_id")
        _require_identifier(database_binding_id, "database_binding_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                binding = connection.execute(
                    """
                    SELECT b.docker_resource_id
                    FROM database_bindings b
                    JOIN repository_memberships m
                      ON m.resource_kind = 'container'
                     AND m.host_resource_id = b.docker_resource_id
                     AND m.repo_id = ?
                    JOIN control_bindings c ON c.binding_id = m.control_binding_id
                    WHERE b.database_binding_id = ?
                      AND b.repo_id = ? AND b.engine_kind = 'postgresql'
                      AND c.authority_state = 'authoritative'
                    """,
                    (repo_id, database_binding_id, repo_id),
                ).fetchone()
                if binding is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "PostgreSQL database is not an authoritative resource of this repository.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_database_acl(
                        uid, repo_id, database_binding_id, docker_resource_id,
                        operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, database_binding_id, operation)
                    DO UPDATE SET docker_resource_id = excluded.docker_resource_id,
                                  enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        database_binding_id,
                        str(binding["docker_resource_id"]),
                        operation.value,
                        int(enabled),
                        utc_timestamp(),
                    ),
                )

    def grant_lifecycle_resource(
        self,
        *,
        uid: int,
        repo_id: str,
        resource_kind: str,
        resource_id: str,
        control_binding_id: str,
        immutable_fingerprint: str,
        ownership_fingerprint: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        if operation not in _RESOURCE_LIFECYCLE_OPERATIONS:
            raise ValueError("operation is not a standalone-resource lifecycle operation")
        if resource_kind not in {"server", "container", "supervisor"}:
            raise ValueError("resource_kind is not a lifecycle resource kind")
        for value, field in (
            (repo_id, "project_id"),
            (resource_id, "resource_id"),
            (control_binding_id, "control_binding_id"),
        ):
            _require_identifier(value, field)
        for value, field in (
            (immutable_fingerprint, "immutable_fingerprint"),
            (ownership_fingerprint, "ownership_fingerprint"),
        ):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise ValueError(f"{field} must be a sha256 fingerprint")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if enabled:
                    exact = connection.execute(
                        """
                        SELECT 1
                        FROM unassigned_resources u
                        JOIN control_bindings b
                          ON b.resource_kind = u.resource_kind
                         AND b.resource_id = u.resource_id
                        JOIN coordinator_sources s ON s.source_id = b.source_id
                        WHERE u.resource_kind = ? AND u.resource_id = ?
                          AND u.status = 'active' AND b.binding_id = ?
                          AND b.authority_state = 'authoritative'
                          AND s.effective_uid = ?
                        """,
                        (resource_kind, resource_id, control_binding_id, uid),
                    ).fetchone()
                else:
                    # Revocation must remain possible after retirement hides
                    # the resource and retires its controller.  It may only
                    # update the exact grant that was provisioned earlier.
                    exact = connection.execute(
                        """
                        SELECT 1 FROM broker_lifecycle_resource_acl
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = ? AND resource_id = ?
                          AND control_binding_id = ?
                          AND immutable_fingerprint = ?
                          AND ownership_fingerprint = ? AND operation = ?
                        """,
                        (
                            uid,
                            repo_id,
                            resource_kind,
                            resource_id,
                            control_binding_id,
                            immutable_fingerprint,
                            ownership_fingerprint,
                            operation.value,
                        ),
                    ).fetchone()
                if exact is None:
                    raise BrokerError(
                        "resource_access_denied",
                        "Standalone lifecycle grant requires an exact active resource or an exact existing grant being revoked.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_lifecycle_resource_acl(
                        uid, repo_id, resource_kind, resource_id,
                        control_binding_id, immutable_fingerprint,
                        ownership_fingerprint, operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(
                        uid, repo_id, resource_kind, resource_id,
                        control_binding_id, operation
                    ) DO UPDATE SET
                        immutable_fingerprint = excluded.immutable_fingerprint,
                        ownership_fingerprint = excluded.ownership_fingerprint,
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        resource_kind,
                        resource_id,
                        control_binding_id,
                        immutable_fingerprint,
                        ownership_fingerprint,
                        operation.value,
                        int(enabled),
                        utc_timestamp(),
                    ),
                )

    def grant_repository_read(
        self,
        *,
        uid: int,
        repo_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        if operation not in _REPOSITORY_READ_OPERATIONS:
            raise ValueError("operation is not a repository broker read")
        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)
                ).fetchone() is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Repository read target is not provisioned.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_repository_read_acl(
                        uid, repo_id, operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, operation)
                    DO UPDATE SET enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (uid, repo_id, operation.value, int(enabled), utc_timestamp()),
                )

    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=peer, request=request)
        return AuthorizedBrokerRequest(peer=peer, request=request)

    @staticmethod
    def _existing_operation_disposition(
        connection: sqlite3.Connection,
        *,
        authorized: AuthorizedBrokerRequest,
        fingerprint: str,
    ) -> DurableOperationDisposition | None:
        request = authorized.request
        existing = connection.execute(
            """
            SELECT o.status, o.result_json, o.error_code, o.error_message,
                   b.uid, b.request_fingerprint
            FROM operations o
            LEFT JOIN broker_operation_requests b USING(operation_id)
            WHERE o.operation_id = ?
            """,
            (request.operation_id,),
        ).fetchone()
        if existing is None:
            return None
        if (
            existing["uid"] != authorized.peer.uid
            or existing["request_fingerprint"] != fingerprint
        ):
            raise BrokerError(
                "operation_id_conflict",
                "operation_id was already used for a different authenticated request.",
                operation_id=request.operation_id,
            )
        if existing["status"] == "succeeded":
            return DurableOperationDisposition(
                "completed", result=_decode_result(existing["result_json"])
            )
        if existing["status"] in {
            "failed",
            "partial",
            "needs_attention",
            "cancelled",
        }:
            return DurableOperationDisposition(
                "failed",
                error_code=existing["error_code"] or "mutation_failed",
                error_message=existing["error_message"] or "Broker mutation failed.",
            )
        return DurableOperationDisposition("pending")

    def existing_operation_disposition(
        self, authorized: AuthorizedBrokerRequest
    ) -> DurableOperationDisposition | None:
        """Read an idempotent replay result without reserving a new operation."""

        fingerprint = authenticated_request_fingerprint(authorized)
        with self._store() as store:
            with store.read_transaction() as connection:
                return self._existing_operation_disposition(
                    connection,
                    authorized=authorized,
                    fingerprint=fingerprint,
                )

    def reserve_operation(
        self, authorized: AuthorizedBrokerRequest
    ) -> DurableOperationDisposition:
        request = authorized.request
        fingerprint = authenticated_request_fingerprint(authorized)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                existing = self._existing_operation_disposition(
                    connection,
                    authorized=authorized,
                    fingerprint=fingerprint,
                )
                if existing is not None:
                    return existing

                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                target_fingerprint = _reserved_target_fingerprint(
                    connection, request=request, fallback=fingerprint
                )
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, owner_uid, actor, process_fingerprint,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'running', 'reserved', 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.operation_id,
                        (
                            None
                            if request.operation in _LIFECYCLE_OPERATIONS
                            else request.project_id
                        ),
                        "broker." + request.operation.value,
                        fingerprint,
                        authorized.peer.uid,
                        "broker:" + request.account_id,
                        f"pid:{os.getpid()}",
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO broker_operation_requests(
                        operation_id, uid, account_id, repo_id, resource_id,
                        operation, request_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.operation_id,
                        authorized.peer.uid,
                        request.account_id,
                        request.project_id,
                        request.resource_id,
                        request.operation.value,
                        fingerprint,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id, action,
                        immutable_fingerprint, phase, status
                    ) VALUES (?, 0, ?, ?, ?, ?, 'reserved', 'running')
                    """,
                    (
                        request.operation_id,
                        _target_kind(request.operation),
                        request.resource_id,
                        request.operation.value,
                        target_fingerprint,
                    ),
                )
        return DurableOperationDisposition("execute")

    def port_lease_candidates(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[int, ...]:
        request = authorized.request
        protocol = str(request.arguments.get("protocol", "tcp"))
        ttl_seconds = int(
            request.arguments.get("ttl_seconds", DEFAULT_PORT_LEASE_TTL_SECONDS)
        )
        requested_port = request.arguments.get("requested_port")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                policies = _port_policy_rows(
                    connection,
                    uid=authorized.peer.uid,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    protocol=protocol,
                    ttl_seconds=ttl_seconds,
                )
                pinned = connection.execute(
                    """
                    SELECT port FROM port_assignments
                    WHERE repo_id = ? AND server_name = (
                        SELECT name FROM server_definitions WHERE server_definition_id = ?
                    ) AND status = 'active'
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if pinned is not None:
                    pinned_port = int(pinned["port"])
                    if requested_port is not None and requested_port != pinned_port:
                        raise BrokerError(
                            "port_assignment_conflict",
                            "Requested port conflicts with the server's active durable assignment.",
                            operation_id=request.operation_id,
                        )
                    requested_port = pinned_port
                if requested_port is not None:
                    return (int(requested_port),)
                return tuple(
                    port
                    for policy in policies
                    for port in range(
                        int(policy["start_port"]), int(policy["end_port"]) + 1
                    )
                )

    def complete_port_lease(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        observed_available_port: int,
        listener_evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = authorized.request
        protocol = str(request.arguments.get("protocol", "tcp"))
        ttl_seconds = int(
            request.arguments.get("ttl_seconds", DEFAULT_PORT_LEASE_TTL_SECONDS)
        )
        if type(observed_available_port) is not int:
            raise BrokerError(
                "port_unavailable",
                "Broker did not receive a valid host-observed port candidate.",
                operation_id=request.operation_id,
            )
        requested_port = request.arguments.get("requested_port")
        now_seconds = time.time()
        now = utc_timestamp(now_seconds)
        expires_at = utc_timestamp(now_seconds + ttl_seconds)
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                repo = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                policies = _port_policy_rows(
                    connection,
                    uid=authorized.peer.uid,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    protocol=protocol,
                    ttl_seconds=ttl_seconds,
                )
                pinned = connection.execute(
                    """
                    SELECT port FROM port_assignments
                    WHERE repo_id = ? AND server_name = (
                        SELECT name FROM server_definitions WHERE server_definition_id = ?
                    ) AND status = 'active'
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if pinned is not None:
                    pinned_port = int(pinned["port"])
                    if requested_port is not None and requested_port != pinned_port:
                        raise BrokerError(
                            "port_assignment_conflict",
                            "Requested port conflicts with the server's active durable assignment.",
                            operation_id=request.operation_id,
                        )
                    requested_port = pinned_port
                if requested_port is not None and observed_available_port != requested_port:
                    raise BrokerError(
                        "port_observation_mismatch",
                        "Host-observed port does not match the exact requested or assigned port.",
                        operation_id=request.operation_id,
                    )
                existing = connection.execute(
                    """
                    SELECT l.*, o.uid AS lease_uid,
                           o.account_id AS lease_account_id,
                           o.repo_id AS lease_repo_id,
                           o.server_definition_id AS lease_server_definition_id,
                           o.protocol AS lease_protocol,
                           d.name AS lease_server_name
                    FROM leases l
                    LEFT JOIN broker_lease_owners o USING(lease_id)
                    LEFT JOIN server_definitions d USING(server_definition_id)
                    WHERE l.host_id = ? AND l.port = ? AND l.status = 'active'
                    """,
                    (repo["host_id"], observed_available_port),
                ).fetchone()
                if (
                    bool(request.arguments.get("adopt_existing_listener"))
                    and existing is not None
                    and existing["repo_id"] == request.project_id
                    and existing["server_definition_id"] == request.resource_id
                    and existing["agent"] == request.account_id
                    and (
                        (
                            existing["purpose"] == "broker"
                            and existing["owner"] == f"uid:{authorized.peer.uid}"
                        )
                        or (
                            existing["purpose"]
                            == f"server:{existing['lease_server_name']}"
                            and str(existing["owner"] or "").isdigit()
                        )
                    )
                    and existing["lease_uid"] == authorized.peer.uid
                    and existing["lease_account_id"] == request.account_id
                    and existing["lease_repo_id"] == request.project_id
                    and existing["lease_server_definition_id"] == request.resource_id
                    and existing["lease_protocol"] == protocol
                ):
                    if listener_evidence is None:
                        raise BrokerError(
                            "listener_identity_unavailable",
                            "Exact lease reuse requires fresh listener identity evidence.",
                            operation_id=request.operation_id,
                        )
                    process_fingerprint = "sha256:" + hashlib.sha256(
                        json.dumps(
                            dict(listener_evidence),
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    changed = connection.execute(
                        """
                        UPDATE leases
                        SET owner = ?, agent = ?, purpose = 'broker',
                            expires_at = ?, process_fingerprint = ?,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                          AND repo_id = ? AND server_definition_id = ?
                          AND port = ?
                        """,
                        (
                            f"uid:{authorized.peer.uid}",
                            request.account_id,
                            expires_at,
                            process_fingerprint,
                            now,
                            existing["lease_id"],
                            request.project_id,
                            request.resource_id,
                            observed_available_port,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise BrokerError(
                            "lease_state_conflict",
                            "Exact active broker lease changed before listener adoption.",
                            operation_id=request.operation_id,
                        )
                    result = {
                        "lease_id": str(existing["lease_id"]),
                        "port": observed_available_port,
                        "protocol": protocol,
                        "expires_at": expires_at,
                        "status": "active",
                        "reused": True,
                        "listener_identity": dict(listener_evidence),
                    }
                    _finish_operation(connection, request.operation_id, result=result)
                    return result
                port = _select_available_port(
                    connection,
                    host_id=str(repo["host_id"]),
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    requested_port=observed_available_port,
                    policies=policies,
                )
                lease_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO leases(
                        lease_id, host_id, repo_id, server_definition_id, port,
                        owner, agent, purpose, status, expires_at,
                        process_fingerprint, generation,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'broker', 'active', ?, ?, 0, ?, ?)
                    """,
                    (
                        lease_id,
                        repo["host_id"],
                        request.project_id,
                        request.resource_id,
                        port,
                        f"uid:{authorized.peer.uid}",
                        request.account_id,
                        expires_at,
                        (
                            None
                            if listener_evidence is None
                            else "sha256:"
                            + hashlib.sha256(
                                json.dumps(
                                    dict(listener_evidence),
                                    ensure_ascii=True,
                                    allow_nan=False,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ).encode("utf-8")
                            ).hexdigest()
                        ),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO broker_lease_owners(
                        lease_id, uid, account_id, repo_id,
                        server_definition_id, protocol, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lease_id,
                        authorized.peer.uid,
                        request.account_id,
                        request.project_id,
                        request.resource_id,
                        protocol,
                        now,
                    ),
                )
                result = {
                    "lease_id": lease_id,
                    "port": port,
                    "protocol": protocol,
                    "expires_at": expires_at,
                    "status": "active",
                }
                if listener_evidence is not None:
                    result["listener_identity"] = dict(listener_evidence)
                _finish_operation(connection, request.operation_id, result=result)
                return result

    def listener_adoption_preflight_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[int, str]:
        """Resolve an authorized adoption target before operation reservation."""

        request = authorized.request
        if not bool(request.arguments.get("adopt_existing_listener")):
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption was not requested.",
                operation_id=request.operation_id,
            )
        candidates = self.port_lease_candidates(authorized)
        if len(candidates) != 1:
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption requires one exact authorized port.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT r.canonical_root
                    FROM repositories r
                    JOIN server_definitions s USING(repo_id)
                    WHERE r.repo_id = ? AND s.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Server listener adoption target is no longer enrolled.",
                        operation_id=request.operation_id,
                    )
                return int(candidates[0]), str(row["canonical_root"])

    def listener_adoption_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[int, str]:
        """Resolve an exact existing-listener adoption target from service truth."""

        request = authorized.request
        if not bool(request.arguments.get("adopt_existing_listener")):
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption was not requested.",
                operation_id=request.operation_id,
            )
        candidates = self.port_lease_candidates(authorized)
        if len(candidates) != 1:
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption requires one exact authorized port.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=_server_definition_fingerprint(
                        connection,
                        repo_id=request.project_id,
                        server_definition_id=request.resource_id,
                        operation_id=request.operation_id,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT r.canonical_root
                    FROM repositories r
                    JOIN server_definitions s USING(repo_id)
                    WHERE r.repo_id = ? AND s.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Server listener adoption target is no longer enrolled.",
                        operation_id=request.operation_id,
                    )
                return int(candidates[0]), str(row["canonical_root"])

    def complete_port_release(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        request = authorized.request
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                lease = _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                if lease is None or lease["status"] != "active":
                    raise BrokerError(
                        "lease_not_active",
                        "The exact authorized lease is no longer active.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    UPDATE leases SET status = 'released', deactivated_at = ?,
                                      updated_at = ?, generation = generation + 1
                    WHERE lease_id = ? AND status = 'active'
                    """,
                    (now, now, request.resource_id),
                )
                result = {
                    "lease_id": request.resource_id,
                    "port": int(lease["port"]),
                    "protocol": str(lease["protocol"]),
                    "status": "released",
                }
                _finish_operation(connection, request.operation_id, result=result)
                return result

    def port_assignment_candidates(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[int, ...]:
        """Return the one host port that must be proved free, or no probe for a no-op."""

        request = authorized.request
        port = int(request.arguments["port"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=_server_definition_fingerprint(
                        connection,
                        repo_id=request.project_id,
                        server_definition_id=request.resource_id,
                        operation_id=request.operation_id,
                    ),
                )
                server = _server_identity(
                    connection,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                _require_assignment_port_policy(
                    connection,
                    uid=authorized.peer.uid,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    port=port,
                    operation_id=request.operation_id,
                )
                existing = connection.execute(
                    """
                    SELECT port, status FROM port_assignments
                    WHERE repo_id = ? AND server_name = ?
                    """,
                    (request.project_id, server["name"]),
                ).fetchone()
                if (
                    existing is not None
                    and existing["status"] == "active"
                    and int(existing["port"]) == port
                ):
                    return ()
                _require_assignment_port_available(
                    connection,
                    host_id=str(server["host_id"]),
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    server_name=str(server["name"]),
                    port=port,
                    operation_id=request.operation_id,
                )
                return (port,)

    def complete_port_assignment(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        observed_available_port: Optional[int],
    ) -> dict[str, Any]:
        request = authorized.request
        port = int(request.arguments["port"])
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=_server_definition_fingerprint(
                        connection,
                        repo_id=request.project_id,
                        server_definition_id=request.resource_id,
                        operation_id=request.operation_id,
                    ),
                )
                server = _server_identity(
                    connection,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                _require_assignment_port_policy(
                    connection,
                    uid=authorized.peer.uid,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    port=port,
                    operation_id=request.operation_id,
                )
                existing = connection.execute(
                    """
                    SELECT assignment_id, port, status, generation, created_at
                    FROM port_assignments
                    WHERE repo_id = ? AND server_name = ?
                    """,
                    (request.project_id, server["name"]),
                ).fetchone()
                unchanged = (
                    existing is not None
                    and existing["status"] == "active"
                    and int(existing["port"]) == port
                )
                if not unchanged:
                    if observed_available_port != port:
                        raise BrokerError(
                            "port_observation_mismatch",
                            "Host-observed port does not match the exact assignment request.",
                            operation_id=request.operation_id,
                        )
                    _require_assignment_port_available(
                        connection,
                        host_id=str(server["host_id"]),
                        repo_id=request.project_id,
                        server_definition_id=request.resource_id,
                        server_name=str(server["name"]),
                        port=port,
                        operation_id=request.operation_id,
                    )
                assignment_id = (
                    str(existing["assignment_id"])
                    if existing is not None
                    else str(uuid.uuid4())
                )
                generation = (
                    int(existing["generation"])
                    if unchanged
                    else (int(existing["generation"]) + 1 if existing is not None else 0)
                )
                created_at = now if existing is None else str(existing["created_at"])
                if not unchanged:
                    try:
                        connection.execute(
                            """
                            INSERT INTO port_assignments(
                                assignment_id, host_id, repo_id, server_name,
                                port, status, generation, deactivated_at,
                                created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, 'active', ?, NULL, ?, ?)
                            ON CONFLICT(repo_id, server_name) DO UPDATE SET
                                host_id = excluded.host_id,
                                port = excluded.port,
                                status = 'active',
                                generation = excluded.generation,
                                deactivated_at = NULL,
                                updated_at = excluded.updated_at
                            """,
                            (
                                assignment_id,
                                server["host_id"],
                                request.project_id,
                                server["name"],
                                port,
                                generation,
                                created_at,
                                now,
                            ),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise BrokerError(
                            "port_assignment_conflict",
                            "The host port became assigned to another server.",
                            operation_id=request.operation_id,
                        ) from exc
                connection.execute(
                    """
                    INSERT INTO broker_assignment_owners(
                        assignment_id, uid, account_id, repo_id,
                        server_definition_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(assignment_id) DO UPDATE SET
                        uid = excluded.uid,
                        account_id = excluded.account_id,
                        repo_id = excluded.repo_id,
                        server_definition_id = excluded.server_definition_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        assignment_id,
                        authorized.peer.uid,
                        request.account_id,
                        request.project_id,
                        request.resource_id,
                        created_at,
                        now,
                    ),
                )
                result = {
                    "assignment_id": assignment_id,
                    "repo_id": request.project_id,
                    "server_definition_id": request.resource_id,
                    "port": port,
                    "status": "active",
                    "generation": generation,
                    "changed": not unchanged,
                }
                _finish_operation(connection, request.operation_id, result=result)
                return result

    def complete_port_unassignment(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        request = authorized.request
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=_server_definition_fingerprint(
                        connection,
                        repo_id=request.project_id,
                        server_definition_id=request.resource_id,
                        operation_id=request.operation_id,
                    ),
                )
                server = _server_identity(
                    connection,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                existing = connection.execute(
                    """
                    SELECT assignment_id, port, status, generation
                    FROM port_assignments
                    WHERE repo_id = ? AND server_name = ?
                    """,
                    (request.project_id, server["name"]),
                ).fetchone()
                changed = existing is not None and existing["status"] == "active"
                generation = (
                    int(existing["generation"]) + int(changed)
                    if existing is not None
                    else 0
                )
                if changed:
                    connection.execute(
                        """
                        UPDATE port_assignments
                        SET status = 'inactive', generation = ?,
                            deactivated_at = ?, updated_at = ?
                        WHERE assignment_id = ? AND status = 'active'
                        """,
                        (generation, now, now, existing["assignment_id"]),
                    )
                result = {
                    "assignment_id": (
                        str(existing["assignment_id"]) if existing is not None else None
                    ),
                    "repo_id": request.project_id,
                    "server_definition_id": request.resource_id,
                    "port": int(existing["port"]) if existing is not None else None,
                    "status": "released",
                    "generation": generation,
                    "changed": changed,
                }
                _finish_operation(connection, request.operation_id, result=result)
                return result

    def docker_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> DockerMutationTarget:
        request = authorized.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT d.docker_resource_id, d.full_container_id,
                           b.generation AS control_generation,
                           m.observation_revision
                    FROM docker_resources d
                    JOIN repository_memberships r
                      ON r.resource_kind = 'container'
                     AND r.host_resource_id = d.docker_resource_id
                     AND r.repo_id = ?
                    JOIN control_bindings b ON b.binding_id = r.control_binding_id
                    CROSS JOIN schema_metadata m
                    WHERE d.docker_resource_id = ?
                      AND b.authority_state = 'authoritative'
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Docker resource no longer has one authoritative control binding.",
                        operation_id=request.operation_id,
                    )
                expected = request.arguments.get("expected_observation_revision")
                if expected is not None and int(row["observation_revision"]) != expected:
                    raise BrokerError(
                        "stale_observation",
                        "Docker observation changed before the requested mutation.",
                        operation_id=request.operation_id,
                    )
                return DockerMutationTarget(
                    docker_resource_id=str(row["docker_resource_id"]),
                    full_container_id=str(row["full_container_id"]),
                    observation_revision=int(row["observation_revision"]),
                    control_generation=int(row["control_generation"]),
                )

    def database_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> DatabaseMutationTarget:
        request = authorized.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT db.database_binding_id, db.docker_resource_id,
                           db.database_name, d.full_container_id,
                           c.generation AS control_generation,
                           m.observation_revision
                    FROM database_bindings db
                    JOIN docker_resources d USING(docker_resource_id)
                    JOIN repository_memberships r
                      ON r.repo_id = db.repo_id
                     AND r.resource_kind = 'container'
                     AND r.host_resource_id = db.docker_resource_id
                    JOIN control_bindings c ON c.binding_id = r.control_binding_id
                    CROSS JOIN schema_metadata m
                    WHERE db.repo_id = ? AND db.docker_resource_id = ?
                      AND db.database_name = ? AND db.engine_kind = 'postgresql'
                      AND c.authority_state = 'authoritative'
                    """,
                    (
                        request.project_id,
                        request.resource_id,
                        request.arguments["database_name"],
                    ),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "PostgreSQL database no longer has one authoritative enrolled container binding.",
                        operation_id=request.operation_id,
                    )
                current_fingerprint = _database_target_fingerprint(row)
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=current_fingerprint,
                )
                if request.operation == BrokerOperation.DATABASE_RESTORE:
                    backup = connection.execute(
                        """
                        SELECT source_container_id FROM database_backups
                        WHERE database_backup_id = ? AND database_binding_id = ?
                          AND status = 'available' AND verification_status = 'strong'
                        """,
                        (
                            request.arguments["database_backup_id"],
                            row["database_binding_id"],
                        ),
                    ).fetchone()
                    if (
                        backup is None
                        or str(backup["source_container_id"]).lower()
                        != str(row["full_container_id"]).lower()
                    ):
                        raise BrokerError(
                            "database_backup_unavailable",
                            "Restore backup no longer matches the exact enrolled container identity.",
                            operation_id=request.operation_id,
                        )
                return DatabaseMutationTarget(
                    database_binding_id=str(row["database_binding_id"]),
                    docker_resource_id=str(row["docker_resource_id"]),
                    full_container_id=str(row["full_container_id"]).lower(),
                    database_name=str(row["database_name"]),
                    observation_revision=int(row["observation_revision"]),
                    control_generation=int(row["control_generation"]),
                )

    def save_database_host_result(
        self,
        authorized: AuthorizedBrokerRequest,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Journal completed host evidence before normalized registry commit."""

        request = authorized.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        try:
            encoded = json.dumps(
                dict(result),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as error:
            raise BrokerError(
                "invalid_backend_result",
                "PostgreSQL host result is not bounded JSON evidence.",
                operation_id=request.operation_id,
            ) from error
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise BrokerError(
                "invalid_backend_result",
                "PostgreSQL host result exceeds the bounded evidence limit.",
                operation_id=request.operation_id,
            )
        result_fingerprint = "sha256:" + hashlib.sha256(
            encoded.encode("utf-8")
        ).hexdigest()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                operation = connection.execute(
                    "SELECT status FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if operation is None or operation["status"] != "running":
                    raise BrokerError(
                        "operation_state_conflict",
                        "PostgreSQL host evidence has no matching running operation.",
                        operation_id=request.operation_id,
                    )
                existing = connection.execute(
                    """
                    SELECT result_json, result_fingerprint
                    FROM broker_database_host_results WHERE operation_id = ?
                    """,
                    (request.operation_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["result_fingerprint"] != result_fingerprint
                        or existing["result_json"] != encoded
                    ):
                        raise BrokerError(
                            "operation_id_conflict",
                            "PostgreSQL operation already has different completed host evidence.",
                            operation_id=request.operation_id,
                        )
                else:
                    connection.execute(
                        """
                        INSERT INTO broker_database_host_results(
                            operation_id, result_json, result_fingerprint, recorded_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            request.operation_id,
                            encoded,
                            result_fingerprint,
                            utc_timestamp(),
                        ),
                    )
        return dict(result)

    def database_host_result(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any] | None:
        """Load replayable host evidence for one authenticated pending operation."""

        request = authorized.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT h.result_json, h.result_fingerprint
                    FROM broker_database_host_results h
                    JOIN operations o USING(operation_id)
                    WHERE h.operation_id = ? AND o.status = 'running'
                    """,
                    (request.operation_id,),
                ).fetchone()
        if row is None:
            return None
        encoded = str(row["result_json"])
        expected = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if expected != row["result_fingerprint"]:
            raise BrokerError(
                "operation_evidence_corrupt",
                "Saved PostgreSQL host evidence failed its durable fingerprint.",
                operation_id=request.operation_id,
            )
        decoded = json.loads(encoded)
        if not isinstance(decoded, dict):
            raise BrokerError(
                "operation_evidence_corrupt",
                "Saved PostgreSQL host evidence has an invalid shape.",
                operation_id=request.operation_id,
            )
        return decoded

    def docker_observation_result(
        self,
        authorized: AuthorizedBrokerRequest,
        target: DockerMutationTarget,
    ) -> dict[str, Any]:
        request = authorized.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT d.docker_resource_id, d.full_container_id,
                           d.current_name, o.lifecycle, o.health,
                           o.restart_policy, o.sampled_at,
                           o.observation_fingerprint,
                           m.observation_revision
                    FROM docker_resources d
                    JOIN repository_memberships r
                      ON r.repo_id = ? AND r.resource_kind = 'container'
                     AND r.host_resource_id = d.docker_resource_id
                    JOIN control_bindings b ON b.binding_id = r.control_binding_id
                    JOIN docker_observations o USING(docker_resource_id)
                    CROSS JOIN schema_metadata m
                    WHERE d.docker_resource_id = ?
                      AND lower(d.full_container_id) = lower(?)
                      AND b.authority_state = 'authoritative'
                    """,
                    (
                        request.project_id,
                        target.docker_resource_id,
                        target.full_container_id,
                    ),
                ).fetchone()
                expected = (
                    {"stopped"}
                    if request.operation == BrokerOperation.DOCKER_STOP
                    else {"running", "starting", "unhealthy"}
                )
                if row is None or row["lifecycle"] not in expected:
                    raise BrokerError(
                        "docker_observation_mismatch",
                        "Fresh service observation does not prove the requested Docker lifecycle result.",
                        operation_id=request.operation_id,
                    )
                return dict(row)

    def repository_container_observations(
        self, authorized: AuthorizedBrokerRequest
    ) -> list[dict[str, Any]]:
        request = authorized.request
        if request.operation not in {
            BrokerOperation.COMPOSE_UP,
            BrokerOperation.COMPOSE_DOWN,
        }:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                return [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT d.docker_resource_id, d.full_container_id,
                               d.current_name, o.lifecycle, o.health,
                               o.restart_policy, o.sampled_at,
                               o.observation_fingerprint
                        FROM repository_memberships r
                        JOIN docker_resources d
                          ON d.docker_resource_id = r.host_resource_id
                        JOIN control_bindings b ON b.binding_id = r.control_binding_id
                        JOIN docker_observations o USING(docker_resource_id)
                        WHERE r.repo_id = ? AND r.resource_kind = 'container'
                          AND b.authority_state = 'authoritative'
                        ORDER BY d.current_name, d.full_container_id
                        """,
                        (request.project_id,),
                    )
                ]

    def registered_database_backup(
        self,
        authorized: AuthorizedBrokerRequest,
        target: DatabaseMutationTarget,
    ) -> RegisteredDatabaseBackup:
        request = authorized.request
        if request.operation != BrokerOperation.DATABASE_RESTORE:
            raise ValueError("request is not a database restore")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT database_backup_id, database_binding_id,
                           artifact_path, manifest_path, artifact_sha256,
                           source_container_id, source_database_name,
                           status, verification_status, scope
                    FROM database_backups WHERE database_backup_id = ?
                    """,
                    (request.arguments["database_backup_id"],),
                ).fetchone()
                if (
                    row is None
                    or row["database_binding_id"] != target.database_binding_id
                    or str(row["source_container_id"]).lower()
                    != target.full_container_id
                    or row["source_database_name"] != target.database_name
                    or row["status"] != "available"
                    or row["verification_status"] != "strong"
                    or row["scope"] != "database"
                ):
                    raise BrokerError(
                        "database_backup_unavailable",
                        "Restore requires a strongly verified service-owned backup of this exact database.",
                        operation_id=request.operation_id,
                    )
                descriptor = inspect_database_backup(
                    str(row["artifact_path"]),
                    str(row["manifest_path"]),
                    expected_uid=self.expected_uid,
                )
                if (
                    descriptor["verification_status"] != "strong"
                    or descriptor["artifact_sha256"] != row["artifact_sha256"]
                    or descriptor["source_container_id"] != target.full_container_id
                    or descriptor["source_database_name"] != target.database_name
                ):
                    raise BrokerError(
                        "database_backup_unavailable",
                        "Registered backup evidence changed or no longer verifies strongly.",
                        operation_id=request.operation_id,
                    )
                return RegisteredDatabaseBackup(
                    database_backup_id=str(row["database_backup_id"]),
                    database_binding_id=str(row["database_binding_id"]),
                    artifact_path=str(descriptor["artifact_path"]),
                    manifest_path=str(descriptor["manifest_path"]),
                    artifact_sha256=str(descriptor["artifact_sha256"]),
                )

    def register_database_backup_result(
        self,
        authorized: AuthorizedBrokerRequest,
        target: DatabaseMutationTarget,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        artifact = result.get("backup")
        manifest = result.get("manifest")
        if not isinstance(artifact, str) or not isinstance(manifest, str):
            raise BrokerError(
                "invalid_backend_result",
                "PostgreSQL backup host action omitted its service-owned artifact evidence.",
                operation_id=authorized.request.operation_id,
            )
        descriptor = inspect_database_backup(
            artifact, manifest, expected_uid=self.expected_uid
        )
        if (
            descriptor["scope"] != "database"
            or descriptor["backup_format"] != "custom"
            or descriptor["verification_status"] != "strong"
            or descriptor["source_container_id"] != target.full_container_id
            or descriptor["source_database_name"] != target.database_name
        ):
            raise BrokerError(
                "invalid_backend_result",
                "PostgreSQL backup host action did not produce a strongly verified artifact for the exact target.",
                operation_id=authorized.request.operation_id,
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
                    request=authorized.request,
                )
                backup_id = upsert_database_backup(connection, descriptor)
                row = connection.execute(
                    """
                    SELECT database_binding_id, docker_resource_id
                    FROM database_backups WHERE database_backup_id = ?
                    """,
                    (backup_id,),
                ).fetchone()
                if (
                    row is None
                    or row["database_binding_id"] != target.database_binding_id
                    or row["docker_resource_id"] != target.docker_resource_id
                ):
                    raise BrokerError(
                        "invalid_backend_result",
                        "Verified backup could not be bound to the exact normalized database.",
                        operation_id=authorized.request.operation_id,
                    )
        return {
            "database_backup_id": backup_id,
            "database_binding_id": target.database_binding_id,
            "docker_resource_id": target.docker_resource_id,
            "database_name": target.database_name,
            "verification_status": "strong",
            "status": "available",
        }

    def register_database_restore_result(
        self,
        authorized: AuthorizedBrokerRequest,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        safety = result.get("safety_backup")
        if not isinstance(safety, Mapping):
            raise BrokerError(
                "invalid_backend_result",
                "Transactional PostgreSQL restore omitted its mandatory safety backup.",
                operation_id=authorized.request.operation_id,
            )
        safety_artifact = safety.get("backup")
        safety_manifest = safety.get("manifest")
        if not isinstance(safety_artifact, str) or not isinstance(safety_manifest, str):
            raise BrokerError(
                "invalid_backend_result",
                "Transactional PostgreSQL restore safety backup evidence is incomplete.",
                operation_id=authorized.request.operation_id,
            )
        safety_descriptor = inspect_database_backup(
            safety_artifact, safety_manifest, expected_uid=self.expected_uid
        )
        if (
            safety_descriptor["verification_status"] != "strong"
            or safety_descriptor["source_container_id"] != target.full_container_id
            or safety_descriptor["source_database_name"] != target.database_name
        ):
            raise BrokerError(
                "invalid_backend_result",
                "Transactional PostgreSQL restore safety backup does not match the exact target.",
                operation_id=authorized.request.operation_id,
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
                    request=authorized.request,
                )
                safety_id = upsert_database_backup(connection, safety_descriptor)
                restore_event_id = record_successful_restore(
                    connection,
                    database_backup_id=backup.database_backup_id,
                    target_container_id=target.full_container_id,
                    target_database_name=target.database_name,
                    result=result,
                    safety_database_backup_id=safety_id,
                )
        return {
            "restore_event_id": restore_event_id,
            "database_backup_id": backup.database_backup_id,
            "safety_database_backup_id": safety_id,
            "database_binding_id": target.database_binding_id,
            "docker_resource_id": target.docker_resource_id,
            "database_name": target.database_name,
            "transactional": True,
            "status": "restored",
        }

    def compose_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> ComposeMutationTarget:
        request = authorized.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                row = connection.execute(
                    """
                    SELECT d.compose_definition_id, d.repo_id, d.cwd,
                           d.project_name, d.definition_fingerprint,
                           d.generation AS definition_generation, d.enabled,
                           r.canonical_root, r.generation AS repository_generation
                    FROM broker_compose_definitions d
                    JOIN repositories r USING(repo_id)
                    WHERE d.compose_definition_id = ? AND d.repo_id = ?
                    """,
                    (request.resource_id, request.project_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Compose definition no longer belongs to the exact repository.",
                        operation_id=request.operation_id,
                    )
                if request.operation == BrokerOperation.COMPOSE_UP and not row["enabled"]:
                    raise BrokerError(
                        "compose_definition_disabled",
                        "Compose definition is disabled; start-like mutation is unavailable.",
                        operation_id=request.operation_id,
                    )
                files = tuple(
                    str(item["file_path"])
                    for item in connection.execute(
                        """
                        SELECT file_path FROM broker_compose_files
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (request.resource_id,),
                    )
                )
                services = tuple(
                    str(item["service_name"])
                    for item in connection.execute(
                        """
                        SELECT service_name FROM broker_compose_services
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (request.resource_id,),
                    )
                )
                file_evidence = tuple(
                    (str(item["content_sha256"]), int(item["byte_size"]))
                    for item in connection.execute(
                        """
                        SELECT content_sha256, byte_size
                        FROM broker_compose_file_evidence
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (request.resource_id,),
                    )
                )
                if not files or len(file_evidence) != len(files):
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Compose definition has incomplete persisted file evidence.",
                        operation_id=request.operation_id,
                    )
                expected_fingerprint = _compose_definition_fingerprint(
                    repo_id=str(row["repo_id"]),
                    cwd=str(row["cwd"]),
                    compose_files=files,
                    compose_file_evidence=tuple(
                        {
                            "content_sha256": digest,
                            "byte_size": byte_size,
                        }
                        for digest, byte_size in file_evidence
                    ),
                    services=services,
                    project_name=str(row["project_name"]),
                )
                if expected_fingerprint != row["definition_fingerprint"]:
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Compose definition fingerprint does not match persisted fields.",
                        operation_id=request.operation_id,
                    )
                _require_reserved_target_fingerprint(
                    connection,
                    request=request,
                    current_fingerprint=str(row["definition_fingerprint"]),
                )
                return ComposeMutationTarget(
                    compose_definition_id=str(row["compose_definition_id"]),
                    repo_id=str(row["repo_id"]),
                    canonical_root=str(row["canonical_root"]),
                    cwd=str(row["cwd"]),
                    compose_files=files,
                    compose_file_sha256s=tuple(item[0] for item in file_evidence),
                    compose_file_sizes=tuple(item[1] for item in file_evidence),
                    services=services,
                    project_name=str(row["project_name"]),
                    definition_fingerprint=str(row["definition_fingerprint"]),
                    definition_generation=int(row["definition_generation"]),
                    repository_generation=int(row["repository_generation"]),
                )

    def list_removed_repository(
        self, authorized: AuthorizedBrokerRequest
    ) -> list[dict[str, Any]]:
        request = authorized.request
        if request.operation != BrokerOperation.REPOSITORY_LIST_REMOVED:
            raise ValueError("request is not a removed-repository read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT r.repo_id, r.canonical_root, r.display_name,
                           i.status, i.disabled_at, i.reason, i.actor
                    FROM repositories r
                    JOIN repository_installations i USING(repo_id)
                    WHERE r.repo_id = ? AND i.status = 'disabled'
                    """,
                    (request.project_id,),
                ).fetchone()
                return [] if row is None else [dict(row)]

    def inventory(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        """Return the one service-owned host graph after live peer authorization."""

        request = authorized.request
        if request.operation != BrokerOperation.INVENTORY_READ:
            raise ValueError("request is not a host inventory read")
        with self._store() as store:
            # The normalized service and account stores share one schema.  The
            # broker adapter also keeps authorization and projection inside
            # the exact same SQLite read snapshot, so live revocation cannot
            # race a second inventory transaction.
            store.__class__ = _BrokerInventoryStore
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                return store.inventory_v2()

    def server_publication_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        """Resolve the exact active broker lease and enrolled repository root."""

        request = authorized.request
        if request.operation != BrokerOperation.SERVER_PUBLISH:
            raise ValueError("request is not a server publication")
        with self._store() as store:
            with store.read_transaction() as connection:
                lease = _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                if lease is None:
                    raise BrokerError(
                        "lease_not_active",
                        "Server publication requires the exact active broker lease.",
                        operation_id=request.operation_id,
                    )
                root = connection.execute(
                    "SELECT canonical_root FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                return {
                    "canonical_root": str(root["canonical_root"]),
                    "lease_id": str(request.arguments["lease_id"]),
                    "port": int(lease["port"]),
                    "server_definition_id": request.resource_id,
                }

    def complete_server_publication(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        listener_evidence: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Commit broker-observed lifecycle into the shared authority graph."""

        request = authorized.request
        arguments = request.arguments
        now = utc_timestamp()
        lifecycle = str(arguments["lifecycle"])
        with self._store() as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                lease = _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                if lease is None or lease["status"] != "active":
                    raise BrokerError(
                        "lease_not_active",
                        "Server publication requires the exact active broker lease.",
                        operation_id=request.operation_id,
                    )
                port = int(lease["port"])
                if port != int(arguments["listener_port"]):
                    raise BrokerError(
                        "port_observation_mismatch",
                        "Published listener port does not match the exact active broker lease.",
                        operation_id=request.operation_id,
                    )
                definition = connection.execute(
                    """
                    SELECT d.name, r.host_id
                    FROM server_definitions d JOIN repositories r USING(repo_id)
                    WHERE d.repo_id = ? AND d.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if definition is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Published server is no longer enrolled with this repository.",
                        operation_id=request.operation_id,
                    )

                pid = None if lifecycle == "stopped" else int(arguments["pid"])
                evidence = dict(listener_evidence or {})
                process_fingerprint = (
                    None if lifecycle == "stopped" else str(evidence["process_identity"])
                )
                stopped_at = now if lifecycle == "stopped" else None
                stopped_reason = (
                    str(arguments.get("stopped_reason") or "Stopped by coordinator")
                    if lifecycle == "stopped"
                    else None
                )
                if lifecycle != "stopped":
                    changed = connection.execute(
                        """
                        UPDATE leases
                        SET owner = ?, purpose = ?, process_fingerprint = ?,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                          AND repo_id = ? AND server_definition_id = ?
                          AND port = ?
                        """,
                        (
                            str(pid),
                            f"server:{definition['name']}",
                            process_fingerprint,
                            now,
                            arguments["lease_id"],
                            request.project_id,
                            request.resource_id,
                            port,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise BrokerError(
                            "lease_state_conflict",
                            "Exact broker lease changed before server publication.",
                            operation_id=request.operation_id,
                        )
                payload = {
                    "server_definition_id": request.resource_id,
                    "lifecycle": lifecycle,
                    "pid": pid,
                    "process_fingerprint": process_fingerprint,
                    "listener_host": "127.0.0.1",
                    "listener_port": port,
                    "listener_observable": True,
                    "health_classification": arguments["health_classification"],
                    "health_ok": arguments["health_ok"],
                    "stopped_at": stopped_at,
                    "stopped_reason": stopped_reason,
                    "sampled_at": now,
                    "peer_uid": authorized.peer.uid,
                }
                observation_fingerprint = hashlib.sha256(
                    json.dumps(
                        payload,
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                connection.execute(
                    """
                    INSERT INTO server_observations(
                        server_definition_id, lifecycle, pid,
                        process_fingerprint, listener_host, listener_port,
                        listener_observable, health_classification, health_ok,
                        stopped_at, stopped_reason, sampled_at,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, ?, '127.0.0.1', ?, 1, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(server_definition_id) DO UPDATE SET
                        source_resource_id = NULL,
                        lifecycle = excluded.lifecycle,
                        pid = excluded.pid,
                        process_start_time = NULL,
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
                        request.resource_id,
                        lifecycle,
                        pid,
                        process_fingerprint,
                        port,
                        arguments["health_classification"],
                        (
                            None
                            if arguments["health_ok"] is None
                            else int(bool(arguments["health_ok"]))
                        ),
                        stopped_at,
                        stopped_reason,
                        now,
                        observation_fingerprint,
                    ),
                )

                if lifecycle != "stopped":
                    assignment = connection.execute(
                        """
                        SELECT assignment_id, port, status FROM port_assignments
                        WHERE repo_id = ? AND server_name = ?
                        """,
                        (request.project_id, str(definition["name"])),
                    ).fetchone()
                    if assignment is None:
                        assignment_id = str(uuid.uuid4())
                        try:
                            connection.execute(
                                """
                                INSERT INTO port_assignments(
                                    assignment_id, host_id, repo_id, server_name,
                                    port, status, generation, created_at, updated_at
                                ) VALUES (?, ?, ?, ?, ?, 'active', 0, ?, ?)
                                """,
                                (
                                    assignment_id,
                                    str(definition["host_id"]),
                                    request.project_id,
                                    str(definition["name"]),
                                    port,
                                    now,
                                    now,
                                ),
                            )
                        except sqlite3.IntegrityError as exc:
                            raise BrokerError(
                                "port_assignment_conflict",
                                "Another active server assignment owns the published port.",
                                operation_id=request.operation_id,
                            ) from exc
                    elif int(assignment["port"]) != port or assignment["status"] != "active":
                        raise BrokerError(
                            "port_assignment_conflict",
                            "Published listener conflicts with the server's durable assignment.",
                            operation_id=request.operation_id,
                        )

                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, operation_id, event_kind, code,
                        message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, ?, ?, 'broker_server_publication', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        request.project_id,
                        request.operation_id,
                        "server.stopped" if lifecycle == "stopped" else "server.observed",
                        f"Broker published {lifecycle} lifecycle for {definition['name']}",
                        json.dumps(
                            {
                                "peer_uid": authorized.peer.uid,
                                "lease_id": arguments["lease_id"],
                                "listener_evidence": evidence,
                            },
                            sort_keys=True,
                        ),
                        now,
                    ),
                )
                result = {
                    "server_definition_id": request.resource_id,
                    "lease_id": str(arguments["lease_id"]),
                    "lifecycle": lifecycle,
                    "pid": pid,
                    "port": port,
                    "sampled_at": now,
                    "observation_fingerprint": observation_fingerprint,
                }
                _finish_operation(connection, request.operation_id, result=result)
                return result

    def bind_lifecycle_plan_observation(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        plan_id: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = authorized.request
        if request.operation not in _LIFECYCLE_PLAN_OPERATIONS_FOR_PERSISTENCE:
            raise ValueError("request is not a lifecycle planning operation")
        snapshot_id = str(evidence.get("snapshot_id") or "")
        capability_fingerprint = str(evidence.get("capability_fingerprint") or "")
        material_fingerprint = str(evidence.get("material_fingerprint") or "")
        completed_at = str(evidence.get("completed_at") or "")
        if not all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            for value in (capability_fingerprint,)
        ) or not re.fullmatch(r"[0-9a-f]{64}", material_fingerprint):
            raise BrokerError(
                "lifecycle_observation_incomplete",
                "Lifecycle observation fingerprints are malformed.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                observed = connection.execute(
                    """
                    SELECT 1
                    FROM observation_snapshots s
                    JOIN observation_capabilities c USING(snapshot_id)
                    WHERE s.snapshot_id = ? AND s.status = 'completed'
                      AND s.observer_domain = ?
                      AND s.material_fingerprint = ?
                      AND s.completed_at = ?
                      AND c.observer_domain = s.observer_domain
                      AND c.docker_available = 1
                      AND c.capability_fingerprint = ?
                    """,
                    (
                        snapshot_id,
                        evidence.get("observer_domain"),
                        material_fingerprint,
                        completed_at,
                        capability_fingerprint,
                    ),
                ).fetchone()
                plan = connection.execute(
                    "SELECT repo_id, status FROM operations WHERE operation_id = ?",
                    (plan_id,),
                ).fetchone()
                if observed is None or plan is None or plan["repo_id"] not in {
                    None,
                    request.project_id,
                }:
                    raise BrokerError(
                        "lifecycle_observation_incomplete",
                        "Lifecycle plan could not be bound to the exact committed Docker capability snapshot.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    INSERT INTO broker_lifecycle_plan_observations(
                        plan_id, repo_id, snapshot_id, observer_domain,
                        docker_available, capability_fingerprint,
                        material_fingerprint, completed_at, bound_at
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        plan_id,
                        request.project_id,
                        snapshot_id,
                        evidence["observer_domain"],
                        capability_fingerprint,
                        material_fingerprint,
                        completed_at,
                        utc_timestamp(),
                    ),
                )
        return {
            "snapshot_id": snapshot_id,
            "observer_domain": str(evidence["observer_domain"]),
            "docker_available": True,
            "capability_fingerprint": capability_fingerprint,
            "material_fingerprint": material_fingerprint,
            "completed_at": completed_at,
        }

    def require_lifecycle_plan_observation(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        request = authorized.request
        if request.operation not in {
            BrokerOperation.REPOSITORY_REMOVE,
            BrokerOperation.RESOURCE_RETIRE,
        }:
            raise ValueError("request is not a lifecycle plan application")
        plan_id = str(request.arguments["plan_id"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT b.snapshot_id, b.observer_domain,
                           b.capability_fingerprint, b.material_fingerprint,
                           b.completed_at
                    FROM broker_lifecycle_plan_observations b
                    JOIN observation_snapshots s USING(snapshot_id)
                    JOIN observation_capabilities c USING(snapshot_id)
                    WHERE b.plan_id = ? AND b.repo_id = ?
                      AND s.status = 'completed'
                      AND s.observer_domain = b.observer_domain
                      AND s.material_fingerprint = b.material_fingerprint
                      AND c.docker_available = 1
                      AND c.capability_fingerprint = b.capability_fingerprint
                    """,
                    (plan_id, request.project_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "lifecycle_observation_incomplete",
                        "Lifecycle plan is not bound to an available committed full-Docker snapshot; create a new plan.",
                        operation_id=request.operation_id,
                    )
                return {
                    "snapshot_id": str(row["snapshot_id"]),
                    "observer_domain": str(row["observer_domain"]),
                    "docker_available": True,
                    "capability_fingerprint": str(row["capability_fingerprint"]),
                    "material_fingerprint": str(row["material_fingerprint"]),
                    "completed_at": str(row["completed_at"]),
                }

    def finish_operation(
        self,
        operation_id: str,
        *,
        result: Optional[Mapping[str, Any]] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _finish_operation(
                    connection,
                    operation_id,
                    result=dict(result) if result is not None else None,
                    error_code=error_code,
                    error_message=error_message,
                )


def _authorize_connection(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> Optional[sqlite3.Row]:
    generation = connection.execute(
        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if generation is None or str(generation[0]) != request.authority_generation:
        raise BrokerError(
            "broker_generation_mismatch",
            "The client enrollment belongs to another broker database generation; rerun Coordinator skill installation.",
            operation_id=request.operation_id,
        )
    principal = connection.execute(
        "SELECT account_id, enabled FROM broker_acl_principals WHERE uid = ?",
        (peer.uid,),
    ).fetchone()
    if principal is None or not principal["enabled"]:
        raise BrokerError(
            "peer_not_authorized",
            "This operating-system account is not authorized to use the broker.",
            operation_id=request.operation_id,
        )
    if request.account_id != principal["account_id"]:
        raise BrokerError(
            "cross_account_access_denied",
            "The authenticated account cannot act for the requested account.",
            operation_id=request.operation_id,
        )
    installation = connection.execute(
        """
        SELECT r.state, i.status, i.startup_fenced
        FROM repositories r JOIN repository_installations i USING(repo_id)
        WHERE r.repo_id = ?
        """,
        (request.project_id,),
    ).fetchone()
    if installation is None:
        raise BrokerError(
            "project_access_denied",
            "The authenticated account is not authorized for this project.",
            operation_id=request.operation_id,
        )
    if (
        request.operation
        in (
            _REPOSITORY_LIFECYCLE_OPERATIONS
            | _REPOSITORY_READ_OPERATIONS
            | _HOST_READ_OPERATIONS
        )
        and request.resource_id != request.project_id
    ):
        raise BrokerError(
            "resource_access_denied",
            "Repository lifecycle must target the exact authorized project identity.",
            operation_id=request.operation_id,
        )
    start_like = request.operation in {
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.DOCKER_START,
        BrokerOperation.DOCKER_RESTART,
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.DATABASE_BACKUP,
        BrokerOperation.DATABASE_RESTORE,
        BrokerOperation.SERVER_PUBLISH,
    }
    if installation["state"] != "active" or (
        start_like
        and (
            installation["status"] != "installed"
            or bool(installation["startup_fenced"])
        )
    ):
        raise BrokerError(
            "repository_startup_fenced",
            "Repository is disabled or being decommissioned; start-like mutations are fenced.",
            operation_id=request.operation_id,
        )

    resource_id = request.resource_id
    resource_kind = "container"
    lease_row: Optional[sqlite3.Row] = None
    if request.operation in _HOST_READ_OPERATIONS:
        # Inventory visibility is host-wide for every enrolled principal.  The
        # repository identity proves current enrollment; mutation authority
        # remains constrained by exact per-resource grants below.
        return None
    if request.operation in _REPOSITORY_READ_OPERATIONS:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_repository_read_acl
            WHERE uid = ? AND repo_id = ? AND operation = ?
            """,
            (peer.uid, request.project_id, request.operation.value),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this repository read.",
                operation_id=request.operation_id,
            )
        return None
    if request.operation in _LIFECYCLE_OPERATIONS:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_lifecycle_acl
            WHERE uid = ? AND repo_id = ? AND operation = ?
            """,
            (peer.uid, request.project_id, request.operation.value),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this lifecycle operation.",
                operation_id=request.operation_id,
            )
        if request.operation in _RESOURCE_LIFECYCLE_OPERATIONS:
            exact = connection.execute(
                """
                SELECT a.enabled
                FROM broker_lifecycle_resource_acl a
                JOIN control_bindings b ON b.binding_id = a.control_binding_id
                JOIN coordinator_sources s ON s.source_id = b.source_id
                JOIN unassigned_resources u
                  ON u.resource_kind = a.resource_kind
                 AND u.resource_id = a.resource_id
                WHERE a.uid = ? AND a.repo_id = ?
                  AND a.resource_kind = ? AND a.resource_id = ?
                  AND a.control_binding_id = ?
                  AND a.immutable_fingerprint = ?
                  AND a.ownership_fingerprint = ?
                  AND a.operation = ?
                  AND b.resource_kind = a.resource_kind
                  AND b.resource_id = a.resource_id
                  AND b.authority_state = 'authoritative'
                  AND s.effective_uid = ? AND u.status = 'active'
                """,
                (
                    peer.uid,
                    request.project_id,
                    request.arguments["resource_kind"],
                    request.resource_id,
                    request.arguments["control_binding_id"],
                    request.arguments["immutable_fingerprint"],
                    request.arguments["ownership_fingerprint"],
                    request.operation.value,
                    peer.uid,
                ),
            ).fetchone()
            if (
                (exact is None or not exact["enabled"])
                and request.operation == BrokerOperation.RESOURCE_RETIRE
            ):
                exact = _authorized_completed_retirement_replay(
                    connection,
                    peer=peer,
                    request=request,
                )
            if exact is None or not exact["enabled"]:
                raise BrokerError(
                    "resource_access_denied",
                    "Standalone lifecycle request does not match an exact administrator-provisioned resource grant.",
                    operation_id=request.operation_id,
                )
        return None
    if request.operation in _DATABASE_OPERATIONS:
        database_name = str(request.arguments["database_name"])
        grant = connection.execute(
            """
            SELECT a.enabled, a.database_binding_id
            FROM broker_database_acl a
            JOIN database_bindings b USING(database_binding_id)
            JOIN repository_memberships m
              ON m.repo_id = a.repo_id
             AND m.resource_kind = 'container'
             AND m.host_resource_id = a.docker_resource_id
            JOIN control_bindings c ON c.binding_id = m.control_binding_id
            WHERE a.uid = ? AND a.repo_id = ?
              AND a.docker_resource_id = ? AND a.operation = ?
              AND b.docker_resource_id = a.docker_resource_id
              AND b.repo_id = a.repo_id AND b.database_name = ?
              AND b.engine_kind = 'postgresql'
              AND c.repo_id = a.repo_id
              AND c.resource_kind = 'container'
              AND c.resource_id = a.docker_resource_id
              AND c.authority_state = 'authoritative'
            """,
            (
                peer.uid,
                request.project_id,
                request.resource_id,
                request.operation.value,
                database_name,
            ),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this PostgreSQL database operation.",
                operation_id=request.operation_id,
            )
        if request.operation == BrokerOperation.DATABASE_RESTORE:
            backup = connection.execute(
                """
                SELECT database_binding_id, docker_resource_id, status,
                       verification_status, scope, source_container_id,
                       source_database_name
                FROM database_backups WHERE database_backup_id = ?
                """,
                (request.arguments["database_backup_id"],),
            ).fetchone()
            if (
                backup is None
                or backup["status"] != "available"
                or backup["verification_status"] != "strong"
                or backup["scope"] != "database"
                or backup["database_binding_id"] != grant["database_binding_id"]
                or backup["docker_resource_id"] != request.resource_id
                or backup["source_database_name"] != database_name
            ):
                raise BrokerError(
                    "database_backup_unavailable",
                    "Restore requires a strongly verified service-owned backup of this exact database.",
                    operation_id=request.operation_id,
                )
        return None
    if request.operation == BrokerOperation.SERVER_PUBLISH:
        lease_row = connection.execute(
            """
            SELECT l.status, l.port, b.protocol, b.server_definition_id,
                   b.uid, b.account_id, b.repo_id
            FROM leases l JOIN broker_lease_owners b USING(lease_id)
            WHERE l.lease_id = ?
            """,
            (request.arguments["lease_id"],),
        ).fetchone()
        if (
            lease_row is None
            or lease_row["status"] != "active"
            or lease_row["uid"] != peer.uid
            or lease_row["account_id"] != request.account_id
            or lease_row["repo_id"] != request.project_id
            or lease_row["server_definition_id"] != request.resource_id
            or int(lease_row["port"]) != int(request.arguments["listener_port"])
        ):
            raise BrokerError(
                "resource_access_denied",
                "Server publication does not match the authenticated principal's exact active lease.",
                operation_id=request.operation_id,
            )
        resource_id = request.resource_id
        resource_kind = "server"
    elif request.operation == BrokerOperation.PORT_RELEASE:
        lease_row = connection.execute(
            """
            SELECT l.status, l.port, b.protocol, b.server_definition_id,
                   b.uid, b.account_id, b.repo_id
            FROM leases l JOIN broker_lease_owners b USING(lease_id)
            WHERE l.lease_id = ?
            """,
            (request.resource_id,),
        ).fetchone()
        if (
            lease_row is None
            or lease_row["uid"] != peer.uid
            or lease_row["account_id"] != request.account_id
            or lease_row["repo_id"] != request.project_id
        ):
            raise BrokerError(
                "resource_access_denied",
                "The authenticated account is not authorized for this lease.",
                operation_id=request.operation_id,
            )
        resource_id = str(lease_row["server_definition_id"])
        resource_kind = "server"
    elif request.operation in {
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.PORT_UNASSIGN,
    }:
        resource_kind = "server"
    elif request.operation in {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_DOWN,
    }:
        resource_kind = "compose"

    if request.operation in {
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.PORT_UNASSIGN,
    }:
        assignment_owner = connection.execute(
            """
            SELECT p.status, o.uid, o.account_id, o.repo_id,
                   o.server_definition_id
            FROM server_definitions s
            JOIN port_assignments p
              ON p.repo_id = s.repo_id AND p.server_name = s.name
            LEFT JOIN broker_assignment_owners o USING(assignment_id)
            WHERE s.repo_id = ? AND s.server_definition_id = ?
            """,
            (request.project_id, resource_id),
        ).fetchone()
        if (
            assignment_owner is not None
            and assignment_owner["status"] == "active"
            and assignment_owner["uid"] is not None
            and (
                assignment_owner["uid"] != peer.uid
                or assignment_owner["account_id"] != request.account_id
                or assignment_owner["repo_id"] != request.project_id
                or assignment_owner["server_definition_id"] != resource_id
            )
        ):
            raise BrokerError(
                "resource_access_denied",
                "The active port assignment belongs to another authenticated principal.",
                operation_id=request.operation_id,
            )

    if request.operation in {
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.PORT_UNASSIGN,
    }:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_assignment_acl
            WHERE uid = ? AND repo_id = ? AND server_definition_id = ?
              AND operation = ?
            """,
            (peer.uid, request.project_id, resource_id, request.operation.value),
        ).fetchone()
    elif request.operation in {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_DOWN,
    }:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_compose_acl
            WHERE uid = ? AND repo_id = ? AND compose_definition_id = ?
              AND operation = ?
            """,
            (peer.uid, request.project_id, resource_id, request.operation.value),
        ).fetchone()
    elif request.operation == BrokerOperation.SERVER_PUBLISH:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_resource_acl
            WHERE uid = ? AND repo_id = ? AND resource_kind = 'server'
              AND resource_id = ? AND operation = 'port.lease'
            """,
            (peer.uid, request.project_id, resource_id),
        ).fetchone()
    else:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_resource_acl
            WHERE uid = ? AND repo_id = ? AND resource_kind = ?
              AND resource_id = ? AND operation = ?
            """,
            (
                peer.uid,
                request.project_id,
                resource_kind,
                resource_id,
                request.operation.value,
            ),
        ).fetchone()
    if grant is None or not grant["enabled"]:
        raise BrokerError(
            "operation_access_denied",
            "The authenticated account is not authorized for this resource operation.",
            operation_id=request.operation_id,
        )

    _require_resource_membership(
        connection,
        repo_id=request.project_id,
        resource_kind=resource_kind,
        resource_id=resource_id,
        operation_id=request.operation_id,
    )
    if request.operation == BrokerOperation.PORT_LEASE:
        ttl = int(
            request.arguments.get("ttl_seconds", DEFAULT_PORT_LEASE_TTL_SECONDS)
        )
        policies = _port_policy_rows(
            connection,
            uid=peer.uid,
            repo_id=request.project_id,
            server_definition_id=resource_id,
            protocol=str(request.arguments.get("protocol", "tcp")),
            ttl_seconds=ttl,
        )
        requested = request.arguments.get("requested_port")
        if requested is not None and not any(
            int(row["start_port"]) <= requested <= int(row["end_port"])
            for row in policies
        ):
            raise BrokerError(
                "port_policy_denied",
                "The requested port is outside the account's authorized ranges.",
                operation_id=request.operation_id,
            )
    elif request.operation == BrokerOperation.PORT_ASSIGN:
        _require_assignment_port_policy(
            connection,
            uid=peer.uid,
            repo_id=request.project_id,
            server_definition_id=resource_id,
            port=int(request.arguments["port"]),
            operation_id=request.operation_id,
        )
    elif request.operation == BrokerOperation.COMPOSE_UP:
        definition = connection.execute(
            """
            SELECT enabled FROM broker_compose_definitions
            WHERE compose_definition_id = ? AND repo_id = ?
            """,
            (resource_id, request.project_id),
        ).fetchone()
        if definition is None or not definition["enabled"]:
            raise BrokerError(
                "compose_definition_disabled",
                "Compose definition is disabled or unavailable.",
                operation_id=request.operation_id,
            )
    return lease_row


def _authorized_completed_retirement_replay(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> Optional[sqlite3.Row]:
    """Authorize only the exact confirmed plan after its resource is hidden.

    Normal standalone authorization deliberately requires an active unassigned
    resource and an authoritative controller.  Successful retirement removes
    both conditions, so a client whose response was lost would otherwise be
    unable to retrieve the durable idempotent result.  This fallback keeps the
    administrator grant live but binds it to the exact broker-observed plan,
    target identity, and fingerprint that were authorized before retirement.
    It cannot create or apply a new plan against an inactive resource.
    """

    return connection.execute(
        """
        SELECT a.enabled
        FROM broker_lifecycle_resource_acl a
        JOIN broker_lifecycle_plan_observations observed
          ON observed.plan_id = ? AND observed.repo_id = a.repo_id
        JOIN operations operation
          ON operation.operation_id = observed.plan_id
        JOIN operation_targets target
          ON target.operation_id = operation.operation_id
         AND target.ordinal = 0
        JOIN operation_target_parameters binding
          ON binding.operation_id = operation.operation_id
         AND binding.target_ordinal = target.ordinal
         AND binding.name = 'control_binding_id'
        WHERE a.uid = ? AND a.repo_id = ?
          AND a.resource_kind = ? AND a.resource_id = ?
          AND a.control_binding_id = ?
          AND a.immutable_fingerprint = ?
          AND a.ownership_fingerprint = ?
          AND a.operation = 'resource.retire' AND a.enabled = 1
          AND operation.kind = 'standalone_resource_retirement'
          AND operation.status IN ('cancelled', 'succeeded')
          AND operation.request_fingerprint = ?
          AND target.target_kind = a.resource_kind
          AND target.target_id = a.resource_id
          AND target.immutable_fingerprint = a.immutable_fingerprint
          AND binding.value = a.control_binding_id
        """,
        (
            str(request.arguments["plan_id"]),
            peer.uid,
            request.project_id,
            str(request.arguments["resource_kind"]),
            request.resource_id,
            str(request.arguments["control_binding_id"]),
            str(request.arguments["immutable_fingerprint"]),
            str(request.arguments["ownership_fingerprint"]),
            str(request.arguments["plan_fingerprint"]),
        ),
    ).fetchone()


def _require_principal(connection: sqlite3.Connection, uid: int) -> None:
    if connection.execute(
        "SELECT 1 FROM broker_acl_principals WHERE uid = ?", (uid,)
    ).fetchone() is None:
        raise BrokerError("peer_not_authorized", "Broker principal is not provisioned.")


def _require_resource_membership(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    resource_kind: str,
    resource_id: str,
    operation_id: Optional[str] = None,
) -> None:
    if resource_kind == "server":
        exists = connection.execute(
            """
            SELECT 1 FROM server_definitions
            WHERE server_definition_id = ? AND repo_id = ?
            """,
            (resource_id, repo_id),
        ).fetchone()
    elif resource_kind == "container":
        exists = connection.execute(
            """
            SELECT 1
            FROM repository_memberships m
            JOIN control_bindings b ON b.binding_id = m.control_binding_id
            WHERE m.repo_id = ? AND m.resource_kind = 'container'
              AND m.host_resource_id = ?
              AND b.repo_id = m.repo_id
              AND b.resource_kind = 'container'
              AND b.resource_id = m.host_resource_id
              AND b.authority_state = 'authoritative'
            """,
            (repo_id, resource_id),
        ).fetchone()
    elif resource_kind == "compose":
        exists = connection.execute(
            """
            SELECT 1 FROM broker_compose_definitions
            WHERE compose_definition_id = ? AND repo_id = ?
            """,
            (resource_id, repo_id),
        ).fetchone()
    else:
        raise ValueError("unsupported broker resource kind")
    if exists is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Resource no longer has exact repository membership and control authority.",
            operation_id=operation_id,
        )


def _port_policy_rows(
    connection: sqlite3.Connection,
    *,
    uid: int,
    repo_id: str,
    server_definition_id: str,
    protocol: str,
    ttl_seconds: int,
) -> list[sqlite3.Row]:
    rows = list(
        connection.execute(
            """
            SELECT start_port, end_port, max_ttl_seconds
            FROM broker_port_policies
            WHERE uid = ? AND repo_id = ? AND server_definition_id = ?
              AND protocol = ? AND enabled = 1 AND max_ttl_seconds >= ?
            ORDER BY start_port, end_port
            """,
            (uid, repo_id, server_definition_id, protocol, ttl_seconds),
        )
    )
    if not rows:
        raise BrokerError(
            "port_policy_denied",
            "The requested protocol or lease duration is outside the account policy.",
        )
    return rows


def _server_identity(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    server_definition_id: str,
    operation_id: Optional[str],
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT s.name, r.host_id
        FROM server_definitions s JOIN repositories r USING(repo_id)
        WHERE s.server_definition_id = ? AND s.repo_id = ?
        """,
        (server_definition_id, repo_id),
    ).fetchone()
    if row is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Server definition no longer belongs to the exact repository.",
            operation_id=operation_id,
        )
    return row


def _server_definition_fingerprint(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    server_definition_id: str,
    operation_id: Optional[str],
) -> str:
    row = connection.execute(
        """
        SELECT definition_fingerprint FROM server_definitions
        WHERE server_definition_id = ? AND repo_id = ?
        """,
        (server_definition_id, repo_id),
    ).fetchone()
    if row is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Server definition no longer belongs to the exact repository.",
            operation_id=operation_id,
        )
    return str(row["definition_fingerprint"])


def _reserved_target_fingerprint(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
    fallback: str,
) -> str:
    if request.operation in {
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.PORT_UNASSIGN,
        BrokerOperation.SERVER_PUBLISH,
    }:
        return _server_definition_fingerprint(
            connection,
            repo_id=request.project_id,
            server_definition_id=request.resource_id,
            operation_id=request.operation_id,
        )
    if request.operation in {BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN}:
        row = connection.execute(
            """
            SELECT definition_fingerprint FROM broker_compose_definitions
            WHERE compose_definition_id = ? AND repo_id = ?
            """,
            (request.resource_id, request.project_id),
        ).fetchone()
        if row is None:
            raise BrokerError(
                "control_binding_unavailable",
                "Compose definition no longer belongs to the exact repository.",
                operation_id=request.operation_id,
            )
        return str(row["definition_fingerprint"])
    if request.operation in _DATABASE_OPERATIONS:
        row = connection.execute(
            """
            SELECT db.database_binding_id, db.docker_resource_id,
                   db.database_name, d.full_container_id,
                   c.generation AS control_generation,
                   m.observation_revision
            FROM database_bindings db
            JOIN docker_resources d USING(docker_resource_id)
            JOIN repository_memberships r
              ON r.repo_id = db.repo_id
             AND r.resource_kind = 'container'
             AND r.host_resource_id = db.docker_resource_id
            JOIN control_bindings c ON c.binding_id = r.control_binding_id
            CROSS JOIN schema_metadata m
            WHERE db.repo_id = ? AND db.docker_resource_id = ?
              AND db.database_name = ? AND db.engine_kind = 'postgresql'
              AND c.authority_state = 'authoritative'
            """,
            (
                request.project_id,
                request.resource_id,
                request.arguments["database_name"],
            ),
        ).fetchone()
        if row is None:
            raise BrokerError(
                "control_binding_unavailable",
                "PostgreSQL database no longer has one authoritative enrolled container binding.",
                operation_id=request.operation_id,
            )
        return _database_target_fingerprint(row)
    return fallback


def _database_target_fingerprint(row: Mapping[str, Any]) -> str:
    material = {
        "database_binding_id": str(row["database_binding_id"]),
        "docker_resource_id": str(row["docker_resource_id"]),
        "full_container_id": str(row["full_container_id"]).lower(),
        "database_name": str(row["database_name"]),
        "control_generation": int(row["control_generation"]),
        "observation_revision": int(row["observation_revision"]),
    }
    return "sha256:" + hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_reserved_target_fingerprint(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
    current_fingerprint: str,
) -> None:
    row = connection.execute(
        """
        SELECT immutable_fingerprint FROM operation_targets
        WHERE operation_id = ? AND ordinal = 0
          AND target_id = ? AND action = ?
        """,
        (request.operation_id, request.resource_id, request.operation.value),
    ).fetchone()
    if row is None:
        raise BrokerError(
            "operation_state_conflict",
            "Durable broker operation lost its exact target reservation.",
            operation_id=request.operation_id,
        )
    if str(row["immutable_fingerprint"]) != current_fingerprint:
        raise BrokerError(
            "stale_resource_definition",
            "Resource definition changed after the broker operation was reserved.",
            operation_id=request.operation_id,
        )


def _require_assignment_port_policy(
    connection: sqlite3.Connection,
    *,
    uid: int,
    repo_id: str,
    server_definition_id: str,
    port: int,
    operation_id: Optional[str],
) -> None:
    permitted = connection.execute(
        """
        SELECT 1 FROM broker_port_policies
        WHERE uid = ? AND repo_id = ? AND server_definition_id = ?
          AND protocol = 'tcp' AND enabled = 1
          AND start_port <= ? AND end_port >= ?
        LIMIT 1
        """,
        (uid, repo_id, server_definition_id, port, port),
    ).fetchone()
    if permitted is None:
        raise BrokerError(
            "port_policy_denied",
            "The requested assignment port is outside the account's authorized TCP ranges.",
            operation_id=operation_id,
        )


def _require_assignment_port_available(
    connection: sqlite3.Connection,
    *,
    host_id: str,
    repo_id: str,
    server_definition_id: str,
    server_name: str,
    port: int,
    operation_id: Optional[str],
) -> None:
    assignment = connection.execute(
        """
        SELECT repo_id, server_name FROM port_assignments
        WHERE host_id = ? AND port = ? AND status = 'active'
          AND NOT(repo_id = ? AND server_name = ?)
        LIMIT 1
        """,
        (host_id, port, repo_id, server_name),
    ).fetchone()
    if assignment is not None:
        raise BrokerError(
            "port_assignment_conflict",
            "The host port is durably assigned to another server.",
            operation_id=operation_id,
        )
    active_lease = connection.execute(
        """
        SELECT repo_id, server_definition_id FROM leases
        WHERE host_id = ? AND port = ? AND status = 'active'
          AND (expires_at IS NULL OR expires_at > ?)
          AND NOT(repo_id = ? AND server_definition_id = ?)
        LIMIT 1
        """,
        (host_id, port, utc_timestamp(), repo_id, server_definition_id),
    ).fetchone()
    if active_lease is not None:
        raise BrokerError(
            "port_lease_conflict",
            "The host port has an active lease owned by another server.",
            operation_id=operation_id,
        )
    different_owner_lease = connection.execute(
        """
        SELECT port FROM leases
        WHERE host_id = ? AND repo_id = ? AND server_definition_id = ?
          AND status = 'active' AND (expires_at IS NULL OR expires_at > ?)
          AND port != ?
        LIMIT 1
        """,
        (host_id, repo_id, server_definition_id, utc_timestamp(), port),
    ).fetchone()
    if different_owner_lease is not None:
        raise BrokerError(
            "active_server_lease_conflict",
            "Server has an active lease on a different host port.",
            operation_id=operation_id,
        )


_COMPOSE_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_COMPOSE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _require_compose_project_name(value: str) -> str:
    if not isinstance(value, str) or _COMPOSE_PROJECT_NAME.fullmatch(value) is None:
        raise ValueError(
            "project_name must use lowercase letters, digits, underscores, or hyphens"
        )
    return value


def _default_compose_project_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_-]+", "-", value.lower()).strip("-_")
    if not normalized:
        raise ValueError(
            "repository name cannot form a Compose project name; provide project_name"
        )
    return normalized[:128]


def _require_compose_service_name(value: str) -> str:
    if not isinstance(value, str) or _COMPOSE_SERVICE_NAME.fullmatch(value) is None:
        raise ValueError(
            "Compose service names must be bounded identifiers and cannot be options"
        )
    return value


def _canonical_existing_path(
    value: str | os.PathLike[str], *, field: str, directory: bool
) -> str:
    raw = Path(os.fspath(value)).expanduser()
    if not raw.is_absolute():
        raise ValueError(f"{field} must be an absolute path")
    absolute = Path(os.path.abspath(os.fspath(raw)))
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{field} must exist and be readable") from exc
    if absolute != resolved:
        raise ValueError(f"{field} must not contain symbolic-link components")
    if directory and not resolved.is_dir():
        raise ValueError(f"{field} must be a directory")
    if not directory and not resolved.is_file():
        raise ValueError(f"{field} must be a regular file")
    return str(resolved)


def _require_path_within(path: str, root: str, *, field: str) -> None:
    try:
        common = os.path.commonpath((path, root))
    except ValueError as exc:
        raise ValueError(f"{field} is outside the repository") from exc
    if common != root:
        raise ValueError(f"{field} is outside the repository")


def _compose_definition_fingerprint(
    *,
    repo_id: str,
    cwd: str,
    compose_files: Iterable[str],
    compose_file_evidence: Iterable[Mapping[str, Any]],
    services: Iterable[str],
    project_name: str,
) -> str:
    encoded = json.dumps(
        {
            "repo_id": repo_id,
            "cwd": cwd,
            "files": list(compose_files),
            "file_evidence": [dict(item) for item in compose_file_evidence],
            "services": list(services),
            "project_name": project_name,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compose_file_evidence(path: str) -> dict[str, Any]:
    maximum_bytes = 8 * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum_bytes:
                    raise ValueError("Compose files must not exceed 8 MiB")
                digest.update(chunk)
    except OSError as exc:
        raise ValueError("Compose file could not be read") from exc
    return {"content_sha256": digest.hexdigest(), "byte_size": size}


def _select_available_port(
    connection: sqlite3.Connection,
    *,
    host_id: str,
    repo_id: str,
    server_definition_id: str,
    requested_port: Optional[int],
    policies: list[sqlite3.Row],
) -> int:
    if requested_port is not None:
        candidates = (requested_port,)
    else:
        candidates = (
            port
            for policy in policies
            for port in range(int(policy["start_port"]), int(policy["end_port"]) + 1)
        )
    for port in candidates:
        allowed = any(
            int(row["start_port"]) <= port <= int(row["end_port"])
            for row in policies
        )
        if not allowed:
            continue
        occupied = connection.execute(
            """
            SELECT 1 FROM port_assignments
            WHERE host_id = ? AND port = ? AND status = 'active'
              AND NOT(
                  repo_id = ? AND server_name = (
                      SELECT name FROM server_definitions
                      WHERE server_definition_id = ?
                  )
              )
            UNION ALL
            SELECT 1 FROM leases
            WHERE host_id = ? AND port = ? AND status = 'active'
            LIMIT 1
            """,
            (
                host_id,
                port,
                repo_id,
                server_definition_id,
                host_id,
                port,
            ),
        ).fetchone()
        if occupied is None:
            return port
    raise BrokerError(
        "port_unavailable",
        "No authorized port is currently available for this server.",
    )


def _finish_operation(
    connection: sqlite3.Connection,
    operation_id: str,
    *,
    result: Optional[Mapping[str, Any]] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    now = utc_timestamp()
    if result is not None:
        encoded = json.dumps(
            dict(result),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        status = "succeeded"
        target_status = "succeeded"
        phase = "completed"
    else:
        encoded = None
        status = "failed"
        target_status = "failed"
        phase = "failed"
    cursor = connection.execute(
        """
        UPDATE operations
        SET status = ?, phase = ?, result_json = ?, error_code = ?,
            error_message = ?, updated_at = ?, generation = generation + 1
        WHERE operation_id = ? AND status = 'running'
        """,
        (
            status,
            phase,
            encoded,
            error_code,
            error_message,
            now,
            operation_id,
        ),
    )
    if cursor.rowcount != 1:
        raise BrokerError(
            "operation_state_conflict",
            "Durable broker operation is no longer in its reserved state.",
            operation_id=operation_id,
        )
    connection.execute(
        """
        UPDATE operation_targets
        SET phase = ?, status = ?, result_json = ?,
            error_json = ?, finished_at = ?
        WHERE operation_id = ? AND ordinal = 0
        """,
        (
            phase,
            target_status,
            encoded,
            None
            if error_code is None
            else json.dumps(
                {"code": error_code, "message": error_message or ""},
                sort_keys=True,
                separators=(",", ":"),
            ),
            now,
            operation_id,
        ),
    )


def _decode_result(value: Optional[str]) -> dict[str, Any]:
    if not value:
        return {}
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise BrokerError(
            "invalid_durable_result", "Stored broker result is not a JSON object."
        )
    return decoded


def _target_kind(operation: BrokerOperation) -> str:
    if operation in _REPOSITORY_LIFECYCLE_OPERATIONS:
        return "broker_repository_request"
    if operation in _RESOURCE_LIFECYCLE_OPERATIONS:
        return "broker_standalone_request"
    if operation in {
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.PORT_UNASSIGN,
        BrokerOperation.SERVER_PUBLISH,
    }:
        return "server"
    if operation == BrokerOperation.PORT_RELEASE:
        return "lease"
    if operation in {BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_DOWN}:
        return "compose"
    if operation in _DATABASE_OPERATIONS:
        return "database"
    return "container"


def _require_identifier(value: str, field: str) -> None:
    allowed = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
    )
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value[0] not in allowed - frozenset("_.:@-")
        or any(character not in allowed for character in value)
        or ".." in value
    ):
        raise ValueError(f"{field} must be an opaque identifier")
