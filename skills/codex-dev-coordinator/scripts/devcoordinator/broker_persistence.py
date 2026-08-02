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
from typing import Any, Callable, Generator, Iterable, Mapping, Optional
import uuid

from .broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
    authenticated_request_fingerprint,
)
from .compose_contract import (
    EffectiveComposeEvidence,
    compose_directory_identity,
    compose_relative_parts,
    open_anchored_compose_root,
    open_compose_directory_beneath,
    read_anchored_compose_file,
    require_effective_compose_model,
    require_sealable_compose_payload,
    stable_compose_descriptor_path,
)
from .schema import SCHEMA_VERSION
from .store import (
    AccountStore,
    CoordinatorStore,
    canonical_json,
    fingerprint,
    utc_timestamp,
)
from .database_backups import (
    inspect_database_backup,
    record_successful_restore,
    upsert_database_backup,
)
from .events import list_event_page
from .infrastructure_observation import (
    INFRASTRUCTURE_BROKER_PROJECT_ID,
    INFRASTRUCTURE_INGEST_RESOURCE_ID,
    INFRASTRUCTURE_READ_RESOURCE_ID,
    INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID,
)
from .ephemeral_secrets import (
    EphemeralSecretPolicy,
    POSTGRES_INITDB_PASSWORD_FILE_V1,
    deterministic_secret_binding_id,
    normalize_ephemeral_secret_policy,
)


DEFAULT_PORT_LEASE_TTL_SECONDS = 600
# Broker startup applies trusted, idempotent schema compatibility work before
# any client can connect. Keep that one transaction bounded by the service's
# startup envelope rather than the short per-request mutation budget.
BROKER_INITIALIZATION_MAX_SECONDS = 60.0
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
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
    }
)
_LIFECYCLE_OPERATIONS = (
    _REPOSITORY_LIFECYCLE_OPERATIONS | _RESOURCE_LIFECYCLE_OPERATIONS
)
_LIFECYCLE_PLAN_OPERATIONS_FOR_PERSISTENCE = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.RESOURCE_PLAN_RETIRE,
        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
    }
)
_DATABASE_OPERATIONS = frozenset(
    {BrokerOperation.DATABASE_BACKUP, BrokerOperation.DATABASE_RESTORE}
)
_DOCKER_OPERATIONS = frozenset(
    {
        BrokerOperation.DOCKER_START,
        BrokerOperation.DOCKER_STOP,
        BrokerOperation.DOCKER_RESTART,
    }
)
_EPHEMERAL_BASE_OPERATIONS = (
    BrokerOperation.EPHEMERAL_START,
    BrokerOperation.EPHEMERAL_STATUS,
    BrokerOperation.EPHEMERAL_IMAGE_STATUS,
    BrokerOperation.EPHEMERAL_RENEW,
    BrokerOperation.EPHEMERAL_FINISH,
)
_EPHEMERAL_SECRET_FD_OPERATION = BrokerOperation.EPHEMERAL_SECRET_FD
_EPHEMERAL_IMAGE_PREFETCH_OPERATION = BrokerOperation.EPHEMERAL_IMAGE_PREFETCH
_EPHEMERAL_OPERATIONS = frozenset(
    _EPHEMERAL_BASE_OPERATIONS
    + (_EPHEMERAL_IMAGE_PREFETCH_OPERATION, _EPHEMERAL_SECRET_FD_OPERATION)
)
_EPHEMERAL_MUTATION_OPERATIONS = _EPHEMERAL_OPERATIONS - {
    BrokerOperation.EPHEMERAL_STATUS,
    BrokerOperation.EPHEMERAL_IMAGE_STATUS,
    BrokerOperation.EPHEMERAL_SECRET_FD,
}


def _ephemeral_acl_operations_for_policy(
    secret_policy_kind: str | None,
    *,
    allow_image_prefetch: bool = False,
) -> tuple[BrokerOperation, ...]:
    """Return only the operations justified by one sealed template policy.

    Descriptor delivery is deliberately not a general ephemeral-container
    capability. The sole reviewed password-file policy gets it; every other
    template receives the four ordinary lifecycle grants only.
    """

    if secret_policy_kind is None:
        operations = _EPHEMERAL_BASE_OPERATIONS
    elif secret_policy_kind == POSTGRES_INITDB_PASSWORD_FILE_V1:
        operations = _EPHEMERAL_BASE_OPERATIONS + (_EPHEMERAL_SECRET_FD_OPERATION,)
    else:
        raise BrokerError(
            "control_binding_unavailable",
            "Ephemeral template has an unsupported credential policy.",
        )
    if allow_image_prefetch:
        return operations + (_EPHEMERAL_IMAGE_PREFETCH_OPERATION,)
    return operations


_COMPOSE_OPERATIONS = frozenset(
    {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_STOP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_DOWN,
    }
)
_COMPOSE_START_OPERATIONS = frozenset(
    {BrokerOperation.COMPOSE_UP, BrokerOperation.COMPOSE_RESTART}
)
_LEGACY_COMPOSE_RECONCILIATION_CODES = frozenset(
    {
        "compose_definition_migrated",
        "compose_service_scope_required",
        "compose_directory_identity_required",
        "compose_effective_model_required",
    }
)
_REPOSITORY_READ_OPERATIONS = frozenset({BrokerOperation.REPOSITORY_LIST_REMOVED})
_ARCHIVE_READ_OPERATIONS = frozenset({BrokerOperation.ARCHIVES_READ})
_CLEANUP_OPERATIONS = frozenset(
    {
        BrokerOperation.CLEANUP_PLAN,
        BrokerOperation.CLEANUP_APPLY,
        BrokerOperation.LIFECYCLE_RESTORE,
    }
)
_HOST_READ_OPERATIONS = frozenset(
    {BrokerOperation.INVENTORY_READ, BrokerOperation.EVENTS_READ}
)
_HOST_OBSERVE_OPERATIONS = frozenset({BrokerOperation.HOST_OBSERVE})
_TEST_OPERATIONS = frozenset(
    {
        BrokerOperation.TEST_RUN_START,
        BrokerOperation.TEST_RUN_FINISH,
        BrokerOperation.TEST_STATS_READ,
    }
)
_INFRASTRUCTURE_OPERATIONS = frozenset(
    {
        BrokerOperation.INFRASTRUCTURE_INGEST,
        BrokerOperation.INFRASTRUCTURE_READ,
        BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
    }
)
_INFRASTRUCTURE_INGRESS_OPERATIONS = frozenset(
    {
        BrokerOperation.INFRASTRUCTURE_INGEST,
        BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
    }
)
INFRASTRUCTURE_INGRESS_ACCESS_REQUEST_SCHEMA = (
    "spectre.infrastructure.ingress-access.v1"
)
INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_SCHEMA = (
    "spectre.infrastructure.ingress-access-receipt.v1"
)
INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT = (
    "devcoord-infra-ingress"
)
INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID = "spectre-infrastructure-ingress"
INFRASTRUCTURE_INGRESS_ACCESS_MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60
INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA = (
    "spectre.infrastructure.reader-access.v1"
)
INFRASTRUCTURE_READER_ACCESS_RECEIPT_SCHEMA = (
    "spectre.infrastructure.reader-access-receipt.v1"
)
INFRASTRUCTURE_READER_ACCESS_MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60


def _operation_actor(authorized: AuthorizedBrokerRequest) -> str:
    """Build durable actor metadata while keeping kernel identity authoritative."""

    request = authorized.request
    actor = "broker:" + request.account_id
    if request.operation in _EPHEMERAL_MUTATION_OPERATIONS:
        client_agent = request.arguments.get("agent")
        if client_agent is not None:
            actor += ":client-agent:" + str(client_agent)
    return actor


_WORKER_OPERATIONS = frozenset(
    {
        BrokerOperation.WORKER_LAUNCH_TICKET,
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
        BrokerOperation.WORKER_POLICY_READ,
        BrokerOperation.WORKER_ATTEMPT_READ,
    }
)


def _service_administrator_uid() -> int:
    """Return the authenticated local administrator identity."""

    return os.geteuid()


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

CREATE UNIQUE INDEX IF NOT EXISTS broker_principal_uid_account_identity
ON broker_acl_principals(uid, account_id);

-- Dedicated local service principals are not repository enrollments. They
-- receive only the fixed-scope remote-infrastructure operations appropriate
-- to their role and cannot use this table to acquire local runtime, lifecycle,
-- port, or database authority.
CREATE TABLE IF NOT EXISTS broker_infrastructure_service_acl (
    uid INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'infrastructure.ingest', 'infrastructure.read',
        'infrastructure.verification_context'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    valid_until_epoch INTEGER NOT NULL CHECK(valid_until_epoch > 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, operation),
    FOREIGN KEY(uid, account_id)
        REFERENCES broker_acl_principals(uid, account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS broker_infrastructure_service_acl_active
ON broker_infrastructure_service_acl(operation, enabled, valid_until_epoch, uid);

CREATE TABLE IF NOT EXISTS broker_infrastructure_ingress_access_receipts (
    request_id TEXT PRIMARY KEY,
    request_schema TEXT NOT NULL CHECK(
        request_schema = 'spectre.infrastructure.ingress-access.v1'
    ),
    action TEXT NOT NULL CHECK(action IN (
        'ingress.replace', 'ingress.disable'
    )),
    request_json TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    operator_uid INTEGER NOT NULL CHECK(operator_uid = 0),
    authority_schema_version INTEGER NOT NULL CHECK(
        authority_schema_version = 14
    ),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_infrastructure_reader_access_receipts (
    request_id TEXT PRIMARY KEY,
    request_schema TEXT NOT NULL CHECK(
        request_schema = 'spectre.infrastructure.reader-access.v1'
    ),
    action TEXT NOT NULL CHECK(action IN (
        'reader.replace', 'reader.disable'
    )),
    request_json TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    operator_uid INTEGER NOT NULL CHECK(operator_uid = 0),
    authority_schema_version INTEGER NOT NULL CHECK(
        authority_schema_version = 14
    ),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_repository_enrollments (
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
);

CREATE INDEX IF NOT EXISTS broker_repository_enrollments_by_repo
ON broker_repository_enrollments(repo_id, enabled, valid_until_epoch);

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

CREATE TABLE IF NOT EXISTS broker_ephemeral_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    template_id TEXT NOT NULL
        REFERENCES ephemeral_container_templates(template_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'ephemeral.start', 'ephemeral.status', 'ephemeral.image_status',
        'ephemeral.image_prefetch', 'ephemeral.renew', 'ephemeral.finish',
        'ephemeral.secret_fd'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, template_id, operation)
);

CREATE INDEX IF NOT EXISTS broker_ephemeral_acl_lookup
ON broker_ephemeral_acl(repo_id, template_id, operation, enabled);

CREATE TABLE IF NOT EXISTS broker_runtime_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL
        CHECK(resource_kind IN ('service', 'docker', 'database_stack')),
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('status', 'start', 'stop', 'restart', 'replace')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, resource_kind, resource_id, action)
);

CREATE INDEX IF NOT EXISTS broker_runtime_acl_by_resource
ON broker_runtime_acl(repo_id, resource_kind, resource_id, action, enabled);

CREATE TABLE IF NOT EXISTS broker_worker_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'worker.launch_ticket', 'worker.launched', 'worker.exit',
        'worker.policy_read', 'worker.attempt_read'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, server_definition_id, operation)
);

CREATE INDEX IF NOT EXISTS broker_worker_acl_by_resource
ON broker_worker_acl(repo_id, server_definition_id, operation, enabled);

-- Permanent cleanup must fence an exact server incarnation before native or
-- catalog mutation begins.  This record deliberately has no server-definition
-- foreign key: deletion retains the no-resurrection boundary and an explicit
-- reinstall receives a different immutable ID.
CREATE TABLE IF NOT EXISTS broker_server_revocations (
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    cleanup_operation_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    actor TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY(repo_id, server_definition_id)
);

CREATE INDEX IF NOT EXISTS broker_server_revocations_by_name
ON broker_server_revocations(repo_id, server_name, revoked_at);

-- Repository IDs remain stable for one canonical worktree. Permanent project
-- cleanup revokes one exact generation. Explicit reinstall advances the
-- generation and publishes a new protected-profile incarnation.
CREATE TABLE IF NOT EXISTS broker_repository_revocations (
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    repository_generation INTEGER NOT NULL CHECK(repository_generation >= 0),
    cleanup_operation_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    canonical_root TEXT NOT NULL,
    actor TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY(repo_id, repository_generation)
);

CREATE TABLE IF NOT EXISTS broker_worker_operation_requests (
    operation_id TEXT PRIMARY KEY,
    uid INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    repo_id TEXT NOT NULL,
    server_definition_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'worker.launch_ticket', 'worker.launched', 'worker.exit'
    )),
    request_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'failed')),
    prepared_json TEXT,
    result_json TEXT,
    error_code TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(
        (status = 'running' AND result_json IS NULL
            AND error_code IS NULL AND error_message IS NULL)
        OR (status = 'succeeded' AND result_json IS NOT NULL
            AND error_code IS NULL AND error_message IS NULL)
        OR (status = 'failed' AND result_json IS NULL
            AND error_code IS NOT NULL AND error_message IS NOT NULL)
    )
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

CREATE TABLE IF NOT EXISTS broker_compose_directory_identity (
    compose_definition_id TEXT PRIMARY KEY
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    root_device INTEGER NOT NULL CHECK(root_device >= 0),
    root_inode INTEGER NOT NULL CHECK(root_inode > 0),
    cwd_device INTEGER NOT NULL CHECK(cwd_device >= 0),
    cwd_inode INTEGER NOT NULL CHECK(cwd_inode > 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_compose_effective_model_evidence (
    compose_definition_id TEXT PRIMARY KEY
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    definition_fingerprint TEXT NOT NULL,
    model_sha256 TEXT NOT NULL,
    services_json TEXT NOT NULL,
    service_replicas_json TEXT NOT NULL,
    profiles_json TEXT NOT NULL,
    host_access_risks_json TEXT NOT NULL,
    host_access_approved INTEGER NOT NULL CHECK(host_access_approved IN (0, 1)),
    approved_by_uid INTEGER,
    approved_at TEXT,
    replica_budget INTEGER NOT NULL CHECK(replica_budget >= 0 AND replica_budget <= 64),
    validated_at TEXT NOT NULL,
    CHECK(
        (host_access_approved = 0 AND approved_by_uid IS NULL AND approved_at IS NULL)
        OR
        (host_access_approved = 1 AND approved_by_uid IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS broker_compose_project_claims (
    compose_definition_id TEXT PRIMARY KEY
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    project_name TEXT NOT NULL,
    claimed INTEGER NOT NULL DEFAULT 1 CHECK(claimed IN (0, 1)),
    release_snapshot_id TEXT,
    released_at TEXT,
    updated_at TEXT NOT NULL,
    CHECK(
        (claimed = 1 AND release_snapshot_id IS NULL AND released_at IS NULL)
        OR
        (claimed = 0 AND release_snapshot_id IS NOT NULL AND released_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS broker_compose_project_claims_by_name
ON broker_compose_project_claims(project_name, claimed);

CREATE TABLE IF NOT EXISTS broker_compose_project_claim_history (
    release_id TEXT PRIMARY KEY,
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    project_name TEXT NOT NULL,
    release_reason TEXT NOT NULL CHECK(release_reason IN ('explicit', 'rename')),
    release_snapshot_id TEXT NOT NULL,
    actor_uid INTEGER NOT NULL CHECK(actor_uid >= 0),
    released_at TEXT NOT NULL,
    UNIQUE(compose_definition_id, project_name, release_snapshot_id, release_reason)
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

CREATE TABLE IF NOT EXISTS broker_compose_env_files (
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    file_path TEXT NOT NULL,
    PRIMARY KEY(compose_definition_id, ordinal),
    UNIQUE(compose_definition_id, file_path)
);

CREATE TABLE IF NOT EXISTS broker_compose_env_file_evidence (
    compose_definition_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    content_sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
    PRIMARY KEY(compose_definition_id, ordinal),
    FOREIGN KEY(compose_definition_id, ordinal)
        REFERENCES broker_compose_env_files(compose_definition_id, ordinal)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS broker_compose_profiles (
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    profile_name TEXT NOT NULL,
    PRIMARY KEY(compose_definition_id, ordinal),
    UNIQUE(compose_definition_id, profile_name)
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
    operation TEXT NOT NULL CHECK(operation IN (
        'compose.up', 'compose.stop', 'compose.restart', 'compose.down'
    )),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, compose_definition_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_observation_compose_scope (
    snapshot_id TEXT PRIMARY KEY
        REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    assets_complete INTEGER NOT NULL CHECK(assets_complete IN (0, 1)),
    observed_asset_count INTEGER NOT NULL CHECK(observed_asset_count >= 0),
    evidence_fingerprint TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_observed_compose_assets (
    snapshot_id TEXT NOT NULL
        REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    asset_kind TEXT NOT NULL CHECK(asset_kind IN ('network', 'volume')),
    asset_id TEXT NOT NULL,
    project_name TEXT NOT NULL,
    working_dir TEXT,
    observation_fingerprint TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, asset_kind, asset_id)
);

CREATE TABLE IF NOT EXISTS broker_observed_compose_containers (
    snapshot_id TEXT NOT NULL
        REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    docker_resource_id TEXT NOT NULL
        REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
    full_container_id TEXT NOT NULL,
    project_name TEXT NOT NULL,
    service_name TEXT,
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('running', 'stopped')),
    ownership_state TEXT NOT NULL
        CHECK(ownership_state IN ('exclusive', 'missing', 'conflicting')),
    authoritative_owner_repo_id TEXT
        REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    observation_fingerprint TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, docker_resource_id),
    CHECK(
        (ownership_state = 'exclusive' AND authoritative_owner_repo_id IS NOT NULL)
        OR
        (ownership_state != 'exclusive' AND authoritative_owner_repo_id IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS broker_observed_compose_containers_by_project
ON broker_observed_compose_containers(snapshot_id, project_name, service_name);

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

CREATE TABLE IF NOT EXISTS broker_host_observation_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id)
);

CREATE TABLE IF NOT EXISTS broker_cleanup_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'archives.read', 'cleanup.plan', 'cleanup.apply', 'lifecycle.restore',
        'repository.plan_remove', 'repository.remove', 'repository.reinstall',
        'resource.plan_retire', 'resource.retire',
        'resource.plan_archive', 'resource.archive', 'resource.restore'
    )),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_cleanup_resource_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server', 'container', 'supervisor')),
    resource_id TEXT NOT NULL,
    control_binding_id TEXT NOT NULL
        REFERENCES control_bindings(binding_id) ON DELETE CASCADE,
    immutable_fingerprint TEXT NOT NULL,
    ownership_fingerprint TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'resource.plan_archive', 'resource.archive', 'resource.restore',
        'cleanup.plan', 'cleanup.apply'
    )),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, resource_kind, resource_id, control_binding_id, operation)
);

CREATE TABLE IF NOT EXISTS broker_host_observation_owners (
    snapshot_id TEXT PRIMARY KEY
        REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    broker_instance_id TEXT NOT NULL,
    claimed_at TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS broker_compose_operation_preflights (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL
        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
    material_fingerprint TEXT NOT NULL,
    capability_fingerprint TEXT NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS broker_lifecycle_acl_lookup
ON broker_lifecycle_acl(repo_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_lifecycle_resource_acl_lookup
ON broker_lifecycle_resource_acl(
    repo_id, resource_kind, resource_id, control_binding_id, operation, enabled
);

CREATE INDEX IF NOT EXISTS broker_repository_read_acl_lookup
ON broker_repository_read_acl(repo_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_host_observation_acl_lookup
ON broker_host_observation_acl(repo_id, enabled);

CREATE INDEX IF NOT EXISTS broker_cleanup_acl_lookup
ON broker_cleanup_acl(repo_id, operation, enabled);

CREATE INDEX IF NOT EXISTS broker_cleanup_resource_acl_lookup
ON broker_cleanup_resource_acl(
    repo_id, resource_kind, resource_id, control_binding_id, operation, enabled
);

CREATE INDEX IF NOT EXISTS broker_host_observation_owner_lookup
ON broker_host_observation_owners(broker_instance_id, snapshot_id);

CREATE INDEX IF NOT EXISTS broker_database_acl_lookup
ON broker_database_acl(repo_id, docker_resource_id, database_binding_id, operation, enabled);
"""

_INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS
        broker_infrastructure_ingress_access_receipts_immutable_update
    BEFORE UPDATE ON broker_infrastructure_ingress_access_receipts
    BEGIN
        SELECT RAISE(
            ABORT,
            'infrastructure ingress access receipts are immutable'
        );
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS
        broker_infrastructure_ingress_access_receipts_immutable_delete
    BEFORE DELETE ON broker_infrastructure_ingress_access_receipts
    BEGIN
        SELECT RAISE(
            ABORT,
            'infrastructure ingress access receipts are immutable'
        );
    END
    """,
)

_INFRASTRUCTURE_READER_ACCESS_RECEIPT_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS
        broker_infrastructure_reader_access_receipts_immutable_update
    BEFORE UPDATE ON broker_infrastructure_reader_access_receipts
    BEGIN
        SELECT RAISE(
            ABORT,
            'infrastructure reader access receipts are immutable'
        );
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS
        broker_infrastructure_reader_access_receipts_immutable_delete
    BEFORE DELETE ON broker_infrastructure_reader_access_receipts
    BEGIN
        SELECT RAISE(
            ABORT,
            'infrastructure reader access receipts are immutable'
        );
    END
    """,
)


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
class EphemeralContainerTarget:
    run_id: str
    template_id: str
    repo_id: str
    owner_uid: int
    account_id: str
    creation_nonce: str
    container_name: str
    image_ref: str
    secret_policy: EphemeralSecretPolicy | None
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    memory_bytes: int | None
    cpu_millis: int | None
    container_tcp_port: int | None
    host_port_start: int | None
    host_port_end: int | None
    host_port: int | None
    lease_id: str | None
    full_container_id: str | None
    docker_resource_id: str | None
    template_fingerprint: str
    max_ttl_seconds: int
    expires_at_epoch: int
    credential_renewal_phase: str
    credential_renewal_old_expires_at_epoch: int | None
    credential_renewal_new_expires_at_epoch: int | None
    credential_renewal_operation_id: str | None
    next_reconcile_at_epoch: int
    recovery_failures: int
    cleanup_requested: bool
    cleanup_reason: str | None
    error_code: str | None
    error_message: str | None
    status: str
    phase: str


@dataclass(frozen=True)
class EphemeralImageTarget:
    """Current sealed image identity for one enabled ephemeral template."""

    template_id: str
    repo_id: str
    image_ref: str
    template_fingerprint: str


@dataclass(frozen=True)
class EphemeralSecretRunTarget:
    """Exact non-secret run snapshot authorized for one descriptor delivery."""

    run_id: str
    template_id: str
    repo_id: str
    owner_uid: int
    account_id: str
    policy: EphemeralSecretPolicy
    expires_at_epoch: int


@dataclass(frozen=True)
class DatabaseMutationTarget:
    database_binding_id: str
    docker_resource_id: str
    full_container_id: str
    database_name: str
    observation_revision: int
    control_generation: int


@dataclass(frozen=True)
class RuntimeDockerMutationTarget:
    resource_kind: str
    resource_id: str
    docker_resource_id: str
    full_container_id: str
    database_binding_id: Optional[str]
    database_name: Optional[str]
    observation_revision: int
    control_generation: int
    immutable_fingerprint: str


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
    root_device: int
    root_inode: int
    cwd: str
    cwd_device: int
    cwd_inode: int
    compose_files: tuple[str, ...]
    compose_file_sha256s: tuple[str, ...]
    compose_file_sizes: tuple[int, ...]
    env_files: tuple[str, ...]
    env_file_sha256s: tuple[str, ...]
    env_file_sizes: tuple[int, ...]
    profiles: tuple[str, ...]
    services: tuple[str, ...]
    service_replicas: tuple[tuple[str, int], ...]
    project_name: str
    effective_model_sha256: str
    effective_host_access_risks: tuple[str, ...]
    effective_host_access_approved: bool
    definition_fingerprint: str
    definition_generation: int
    repository_generation: int


def prepare_infrastructure_ingress_access_request(
    value: Any,
) -> dict[str, Any]:
    """Normalize one closed root-owned dedicated-ingress access request."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "request_id",
        "action",
        "payload",
    }:
        raise ValueError(
            "infrastructure ingress access request fields are invalid"
        )
    if value.get("schema") != INFRASTRUCTURE_INGRESS_ACCESS_REQUEST_SCHEMA:
        raise ValueError(
            "infrastructure ingress access request schema is unsupported"
        )
    request_id = value.get("request_id")
    try:
        canonical_request_id = str(uuid.UUID(str(request_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(
            "infrastructure ingress access request_id is invalid"
        ) from error
    if request_id != canonical_request_id:
        raise ValueError(
            "infrastructure ingress access request_id must be canonical"
        )
    action = value.get("action")
    if action not in {"ingress.replace", "ingress.disable"}:
        raise ValueError(
            "infrastructure ingress access action is unsupported"
        )
    payload = value.get("payload")
    common_fields = {
        "service_account",
        "uid",
        "account_id",
    }
    expected_fields = (
        common_fields | {"valid_until_epoch"}
        if action == "ingress.replace"
        else common_fields
    )
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise ValueError(
            "infrastructure ingress access payload fields are invalid"
        )
    if (
        payload.get("service_account")
        != INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT
    ):
        raise ValueError(
            "infrastructure ingress service account is not the fixed v1 account"
        )
    uid = payload.get("uid")
    if type(uid) is not int or not 1 <= uid <= (1 << 31) - 1:
        raise ValueError(
            "infrastructure ingress UID must be one non-root system UID"
        )
    if (
        payload.get("account_id")
        != INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID
    ):
        raise ValueError(
            "infrastructure ingress broker account is not the fixed v1 account"
        )
    if action == "ingress.replace":
        valid_until_epoch = payload.get("valid_until_epoch")
        if type(valid_until_epoch) is not int or valid_until_epoch <= 0:
            raise ValueError(
                "infrastructure ingress access expiry is invalid"
            )
    else:
        valid_until_epoch = None
    normalized_payload = {
        "service_account": INFRASTRUCTURE_INGRESS_SERVICE_ACCOUNT,
        "uid": uid,
        "account_id": INFRASTRUCTURE_INGRESS_BROKER_ACCOUNT_ID,
    }
    if valid_until_epoch is not None:
        normalized_payload["valid_until_epoch"] = valid_until_epoch
    return {
        "schema": INFRASTRUCTURE_INGRESS_ACCESS_REQUEST_SCHEMA,
        "request_id": canonical_request_id,
        "action": action,
        "payload": normalized_payload,
    }


def prepare_infrastructure_reader_access_request(
    value: Any,
) -> dict[str, Any]:
    """Normalize one closed root-owned Console/API read-access request."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "request_id",
        "action",
        "payload",
    }:
        raise ValueError(
            "infrastructure reader access request fields are invalid"
        )
    if value.get("schema") != INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA:
        raise ValueError(
            "infrastructure reader access request schema is unsupported"
        )
    request_id = value.get("request_id")
    try:
        canonical_request_id = str(uuid.UUID(str(request_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(
            "infrastructure reader access request_id is invalid"
        ) from error
    if request_id != canonical_request_id:
        raise ValueError(
            "infrastructure reader access request_id must be canonical"
        )
    action = value.get("action")
    if action not in {"reader.replace", "reader.disable"}:
        raise ValueError(
            "infrastructure reader access action is unsupported"
        )
    payload = value.get("payload")
    common_fields = {"service_account", "uid", "account_id"}
    expected_fields = (
        common_fields | {"valid_until_epoch"}
        if action == "reader.replace"
        else common_fields
    )
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise ValueError(
            "infrastructure reader access payload fields are invalid"
        )
    service_account = payload.get("service_account")
    account_id = payload.get("account_id")
    _require_identifier(service_account, "service_account")
    _require_identifier(account_id, "account_id")
    uid = payload.get("uid")
    if type(uid) is not int or not 1 <= uid <= (1 << 31) - 1:
        raise ValueError(
            "infrastructure reader UID must be one non-root operating-system UID"
        )
    if action == "reader.replace":
        valid_until_epoch = payload.get("valid_until_epoch")
        if type(valid_until_epoch) is not int or valid_until_epoch <= 0:
            raise ValueError(
                "infrastructure reader access expiry is invalid"
            )
    else:
        valid_until_epoch = None
    normalized_payload: dict[str, Any] = {
        "service_account": service_account,
        "uid": uid,
        "account_id": account_id,
    }
    if valid_until_epoch is not None:
        normalized_payload["valid_until_epoch"] = valid_until_epoch
    return {
        "schema": INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA,
        "request_id": canonical_request_id,
        "action": action,
        "payload": normalized_payload,
    }


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
        compose_model_renderer: Optional[Callable[..., bytes]] = None,
    ) -> None:
        self.database_path = Path(database_path)
        self.expected_uid = os.geteuid() if expected_uid is None else int(expected_uid)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.compose_model_renderer = compose_model_renderer
        self.initialize()

    @contextmanager
    def _store(self) -> Generator[CoordinatorStore, None, None]:
        with CoordinatorStore.open(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            yield store

    def repository_host_id(self, repo_id: str) -> str:
        """Resolve one persisted repository to its exact host identity."""

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "project_access_denied",
                "Repository is not provisioned in this broker authority.",
            )
        return str(row["host_id"])

    def database_generation(self) -> str:
        """Return the immutable generation published in protected profiles."""

        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT database_generation FROM schema_metadata "
                    "WHERE singleton = 1"
                ).fetchone()
        if row is None or not str(row["database_generation"] or ""):
            raise BrokerError(
                "broker_generation_unavailable",
                "Broker database generation is unavailable.",
            )
        return str(row["database_generation"])

    def initialize(self) -> None:
        with self._store() as store:
            with store.immediate_transaction(
                max_seconds=BROKER_INITIALIZATION_MAX_SECONDS,
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                for statement in BROKER_SCHEMA.split(";"):
                    if statement.strip():
                        connection.execute(statement)
                for statement in (
                    _INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_TRIGGERS
                    + _INFRASTRUCTURE_READER_ACCESS_RECEIPT_TRIGGERS
                ):
                    connection.execute(statement)
                infrastructure_acl_row = connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'table' "
                    "AND name = 'broker_infrastructure_service_acl'"
                ).fetchone()
                infrastructure_acl_sql = str(
                    infrastructure_acl_row[0]
                    if infrastructure_acl_row
                    else ""
                )
                if "infrastructure.verification_context" not in infrastructure_acl_sql:
                    connection.execute(
                        "ALTER TABLE broker_infrastructure_service_acl "
                        "RENAME TO broker_infrastructure_service_acl_pre_v14"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_infrastructure_service_acl (
                            uid INTEGER NOT NULL,
                            account_id TEXT NOT NULL,
                            operation TEXT NOT NULL CHECK(operation IN (
                                'infrastructure.ingest',
                                'infrastructure.read',
                                'infrastructure.verification_context'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 1
                                CHECK(enabled IN (0, 1)),
                            valid_until_epoch INTEGER NOT NULL
                                CHECK(valid_until_epoch > 0),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, operation),
                            FOREIGN KEY(uid, account_id)
                                REFERENCES broker_acl_principals(uid, account_id)
                                ON DELETE CASCADE
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_infrastructure_service_acl(
                            uid, account_id, operation, enabled,
                            valid_until_epoch, updated_at
                        )
                        SELECT uid, account_id, operation, enabled,
                               valid_until_epoch, updated_at
                        FROM broker_infrastructure_service_acl_pre_v14
                        """
                    )
                    connection.execute(
                        "DROP TABLE broker_infrastructure_service_acl_pre_v14"
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS
                        broker_infrastructure_service_acl_active
                        ON broker_infrastructure_service_acl(
                            operation, enabled, valid_until_epoch, uid
                        )
                        """
                    )
                ephemeral_acl_row = connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'broker_ephemeral_acl'"
                ).fetchone()
                ephemeral_acl_sql = str(
                    ephemeral_acl_row[0] if ephemeral_acl_row else ""
                )
                if (
                    "ephemeral.secret_fd" not in ephemeral_acl_sql
                    or "ephemeral.image_status" not in ephemeral_acl_sql
                    or "ephemeral.image_prefetch" not in ephemeral_acl_sql
                ):
                    connection.execute(
                        "ALTER TABLE broker_ephemeral_acl "
                        "RENAME TO broker_ephemeral_acl_pre_image_cache"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_ephemeral_acl (
                            uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                            repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                            template_id TEXT NOT NULL
                                REFERENCES ephemeral_container_templates(template_id) ON DELETE CASCADE,
                            operation TEXT NOT NULL CHECK(operation IN (
                                'ephemeral.start', 'ephemeral.status', 'ephemeral.image_status',
                                'ephemeral.image_prefetch', 'ephemeral.renew', 'ephemeral.finish',
                                'ephemeral.secret_fd'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, repo_id, template_id, operation)
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_ephemeral_acl(
                            uid, repo_id, template_id, operation, enabled, updated_at
                        )
                        SELECT uid, repo_id, template_id, operation, enabled, updated_at
                        FROM broker_ephemeral_acl_pre_image_cache
                        WHERE operation IN (
                            'ephemeral.start', 'ephemeral.status',
                            'ephemeral.renew', 'ephemeral.finish', 'ephemeral.secret_fd'
                        )
                        """
                    )
                    connection.execute("DROP TABLE broker_ephemeral_acl_pre_image_cache")
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS broker_ephemeral_acl_lookup "
                        "ON broker_ephemeral_acl(repo_id, template_id, operation, enabled)"
                    )

                runtime_acl_row = connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'broker_runtime_acl'"
                ).fetchone()
                runtime_acl_sql = str(runtime_acl_row[0] if runtime_acl_row else "")
                if "'replace'" not in runtime_acl_sql:
                    connection.execute(
                        "ALTER TABLE broker_runtime_acl RENAME TO broker_runtime_acl_v1"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_runtime_acl (
                            uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                            repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                            resource_kind TEXT NOT NULL
                                CHECK(resource_kind IN ('service', 'docker', 'database_stack')),
                            resource_id TEXT NOT NULL,
                            action TEXT NOT NULL CHECK(action IN (
                                'status', 'start', 'stop', 'restart', 'replace'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, repo_id, resource_kind, resource_id, action)
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_runtime_acl(
                            uid, repo_id, resource_kind, resource_id,
                            action, enabled, updated_at
                        )
                        SELECT uid, repo_id, resource_kind, resource_id,
                               action, enabled, updated_at
                        FROM broker_runtime_acl_v1
                        """
                    )
                    connection.execute("DROP TABLE broker_runtime_acl_v1")
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS broker_runtime_acl_by_resource
                        ON broker_runtime_acl(
                            repo_id, resource_kind, resource_id, action, enabled
                        )
                        """
                    )
                cleanup_acl_sql = str(
                    connection.execute(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'broker_cleanup_resource_acl'"
                    ).fetchone()[0]
                )
                if "cleanup.plan" not in cleanup_acl_sql:
                    connection.execute(
                        "ALTER TABLE broker_cleanup_resource_acl RENAME TO broker_cleanup_resource_acl_v1"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_cleanup_resource_acl (
                            uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                            repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                            resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server', 'container', 'supervisor')),
                            resource_id TEXT NOT NULL,
                            control_binding_id TEXT NOT NULL REFERENCES control_bindings(binding_id) ON DELETE CASCADE,
                            immutable_fingerprint TEXT NOT NULL,
                            ownership_fingerprint TEXT NOT NULL,
                            operation TEXT NOT NULL CHECK(operation IN (
                                'resource.plan_archive', 'resource.archive', 'resource.restore',
                                'cleanup.plan', 'cleanup.apply'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, repo_id, resource_kind, resource_id, control_binding_id, operation)
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_cleanup_resource_acl(
                            uid, repo_id, resource_kind, resource_id,
                            control_binding_id, immutable_fingerprint,
                            ownership_fingerprint, operation, enabled, updated_at
                        )
                        SELECT uid, repo_id, resource_kind, resource_id,
                               control_binding_id, immutable_fingerprint,
                               ownership_fingerprint, operation, enabled, updated_at
                        FROM broker_cleanup_resource_acl_v1
                        """
                    )
                    connection.execute("DROP TABLE broker_cleanup_resource_acl_v1")
                # Existing server-wide enrollments predate the explicit host
                # observation mutation grant. Preserve exact enabled grants;
                # INSERT OR IGNORE also preserves a later operator revocation.
                connection.execute(
                    """
                    INSERT OR IGNORE INTO broker_host_observation_acl(
                        uid, repo_id, enabled, updated_at
                    )
                    SELECT a.uid, a.repo_id, 1, a.updated_at
                    FROM broker_repository_read_acl a
                    WHERE a.operation = 'repository.list_removed'
                      AND a.enabled = 1
                    """
                )

                effective_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_compose_effective_model_evidence)"
                    )
                }
                if "service_replicas_json" not in effective_columns:
                    connection.execute(
                        "ALTER TABLE broker_compose_effective_model_evidence "
                        "ADD COLUMN service_replicas_json TEXT NOT NULL DEFAULT '{}'"
                    )
                worker_operation_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_worker_operation_requests)"
                    )
                }
                if "prepared_json" not in worker_operation_columns:
                    connection.execute(
                        "ALTER TABLE broker_worker_operation_requests "
                        "ADD COLUMN prepared_json TEXT"
                    )
                _backfill_exact_worker_acl(
                    connection,
                    now_epoch=int(time.time()),
                    updated_at=utc_timestamp(),
                )
                _backfill_worker_replace_acl(
                    connection,
                    now_epoch=int(time.time()),
                    updated_at=utc_timestamp(),
                )
                compose_acl_row = connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'broker_compose_acl'"
                ).fetchone()
                compose_acl_sql = str(compose_acl_row[0] if compose_acl_row else "")
                if (
                    "compose.stop" not in compose_acl_sql
                    or "compose.restart" not in compose_acl_sql
                ):
                    connection.execute(
                        "ALTER TABLE broker_compose_acl RENAME TO broker_compose_acl_v1"
                    )
                    connection.execute(
                        """
                        CREATE TABLE broker_compose_acl (
                            uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
                            repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                            compose_definition_id TEXT NOT NULL
                                REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
                            operation TEXT NOT NULL CHECK(operation IN (
                                'compose.up', 'compose.stop', 'compose.restart', 'compose.down'
                            )),
                            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(uid, repo_id, compose_definition_id, operation)
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_acl(
                            uid, repo_id, compose_definition_id,
                            operation, enabled, updated_at
                        )
                        SELECT uid, repo_id, compose_definition_id,
                               operation, enabled, updated_at
                        FROM broker_compose_acl_v1
                        WHERE operation IN (
                            'compose.up', 'compose.stop',
                            'compose.restart', 'compose.down'
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_acl(
                            uid, repo_id, compose_definition_id,
                            operation, enabled, updated_at
                        )
                        SELECT uid, repo_id, compose_definition_id,
                               'compose.stop', enabled, updated_at
                        FROM broker_compose_acl_v1
                        WHERE operation = 'compose.down'
                          AND NOT EXISTS (
                              SELECT 1 FROM broker_compose_acl_v1 stop
                              WHERE stop.uid = broker_compose_acl_v1.uid
                                AND stop.repo_id = broker_compose_acl_v1.repo_id
                                AND stop.compose_definition_id =
                                    broker_compose_acl_v1.compose_definition_id
                                AND stop.operation = 'compose.stop'
                          )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_acl(
                            uid, repo_id, compose_definition_id,
                            operation, enabled, updated_at
                        )
                        SELECT up.uid, up.repo_id, up.compose_definition_id,
                               'compose.restart',
                               CASE WHEN up.enabled = 1 AND down.enabled = 1
                                    THEN 1 ELSE 0 END,
                               CASE WHEN up.updated_at > down.updated_at
                                    THEN up.updated_at ELSE down.updated_at END
                        FROM broker_compose_acl_v1 up
                        JOIN broker_compose_acl_v1 down
                          ON down.uid = up.uid
                         AND down.repo_id = up.repo_id
                         AND down.compose_definition_id = up.compose_definition_id
                         AND down.operation = 'compose.down'
                        WHERE up.operation = 'compose.up'
                          AND NOT EXISTS (
                              SELECT 1 FROM broker_compose_acl_v1 restart
                              WHERE restart.uid = up.uid
                                AND restart.repo_id = up.repo_id
                                AND restart.compose_definition_id =
                                    up.compose_definition_id
                                AND restart.operation = 'compose.restart'
                          )
                        """
                    )
                    connection.execute("DROP TABLE broker_compose_acl_v1")
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS broker_compose_acl_lookup "
                        "ON broker_compose_acl(repo_id, compose_definition_id, operation, enabled)"
                    )
                _migrate_legacy_compose_definition_fingerprints(connection)
                _disable_legacy_unscoped_compose_definitions(connection)
                _disable_unpinned_compose_definitions(connection)
                _disable_unvalidated_effective_compose_definitions(connection)
                _backfill_compose_project_claims(connection)
                collisions = list(
                    connection.execute(
                        """
                        SELECT project_name
                        FROM broker_compose_definitions
                        WHERE enabled = 1
                        GROUP BY project_name
                        HAVING count(DISTINCT repo_id) > 1
                        ORDER BY project_name
                        """
                    )
                )
                if collisions:
                    raise RuntimeError(
                        "enabled Compose project names conflict across repositories; "
                        "disable or rename the conflicting definitions before broker startup"
                    )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS one_enabled_compose_project_name "
                    "ON broker_compose_definitions(project_name) WHERE enabled = 1"
                )

    def provision_principal(
        self, *, uid: int, account_id: str, enabled: bool = True
    ) -> None:
        if type(uid) is not int or uid < 0:
            raise ValueError("uid must be a non-negative integer")
        _require_identifier(account_id, "account_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                existing = connection.execute(
                    "SELECT account_id FROM broker_acl_principals WHERE uid = ?",
                    (uid,),
                ).fetchone()
                if existing is not None and str(existing["account_id"]) != account_id:
                    raise BrokerError(
                        "principal_account_conflict",
                        "This operating-system UID is already enrolled for a different account; transfer requires an explicit administrative decommission and reenrollment.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_acl_principals(uid, account_id, enabled, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(uid) DO UPDATE SET
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (uid, account_id, int(enabled), utc_timestamp()),
                )

    def replace_infrastructure_service_access(
        self,
        *,
        uid: int,
        account_id: str,
        operations: Iterable[BrokerOperation],
        valid_until_epoch: int,
    ) -> None:
        """Replace only the fixed-scope infrastructure grants for one UID.

        This administrator-side API is intentionally not a broker operation.
        Public ingress may receive only ingest plus verification-context and
        must have no broader authority. The non-mutating read grant may coexist
        with an authenticated Console/API UID's repository authority. Neither
        path creates a fake repository enrollment or grants new runtime,
        lifecycle, port, Docker, database, or host-observe authority.
        """

        if type(uid) is not int or uid < 0:
            raise ValueError("uid must be a non-negative integer")
        _require_identifier(account_id, "account_id")
        if (
            type(valid_until_epoch) is not int
            or valid_until_epoch <= int(time.time())
        ):
            raise ValueError("valid_until_epoch must be in the future")
        try:
            normalized = frozenset(BrokerOperation(item) for item in operations)
        except (TypeError, ValueError):
            raise ValueError(
                "operations contain an unsupported broker operation"
            ) from None
        if not normalized <= _INFRASTRUCTURE_OPERATIONS:
            raise ValueError(
                "infrastructure service access accepts only ingest, "
                "verification-context, or read operations"
            )
        now_epoch = int(time.time())
        updated_at = utc_timestamp(now_epoch)
        with self._store() as store:
            with store.immediate_transaction() as connection:
                self._replace_infrastructure_service_access_in_transaction(
                    connection,
                    uid=uid,
                    account_id=account_id,
                    operations=normalized,
                    valid_until_epoch=valid_until_epoch,
                    now_epoch=now_epoch,
                    updated_at=updated_at,
                )

    def administer_infrastructure_ingress_access(
        self,
        request: Mapping[str, Any],
        *,
        operator_uid: int,
        now_epoch: int | None = None,
    ) -> dict[str, Any]:
        """Atomically replace the fixed ingress ACL and retain its receipt."""

        if operator_uid != 0 or self.expected_uid != 0:
            raise PermissionError(
                "infrastructure ingress access requires the root service owner"
            )
        normalized = prepare_infrastructure_ingress_access_request(request)
        request_json = canonical_json(normalized)
        request_sha256 = hashlib.sha256(
            request_json.encode("utf-8")
        ).hexdigest()
        request_id = str(normalized["request_id"])
        action = str(normalized["action"])
        current_epoch = (
            int(time.time()) if now_epoch is None else int(now_epoch)
        )
        payload = normalized["payload"]
        valid_until_epoch = (
            int(payload["valid_until_epoch"])
            if action == "ingress.replace"
            else None
        )
        replayed = False
        result: dict[str, Any]
        result_sha256: str
        created_at: str
        with self._store() as store:
            with store.immediate_transaction() as connection:
                metadata = connection.execute(
                    """
                    SELECT schema_version, database_generation
                    FROM schema_metadata
                    WHERE singleton = 1
                    """
                ).fetchone()
                if (
                    metadata is None
                    or int(metadata["schema_version"]) != SCHEMA_VERSION
                    or SCHEMA_VERSION != 14
                ):
                    raise RuntimeError(
                        "infrastructure ingress access requires schema 14"
                    )
                authority_generation = str(metadata["database_generation"])
                _require_identifier(
                    authority_generation, "database_generation"
                )
                existing = connection.execute(
                    """
                    SELECT request_schema, action, request_json,
                           request_sha256, result_json, result_sha256,
                           operator_uid, authority_schema_version, created_at
                    FROM broker_infrastructure_ingress_access_receipts
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["request_schema"])
                        != INFRASTRUCTURE_INGRESS_ACCESS_REQUEST_SCHEMA
                        or str(existing["action"]) != action
                        or str(existing["request_json"]) != request_json
                        or str(existing["request_sha256"])
                        != request_sha256
                        or int(existing["operator_uid"]) != operator_uid
                        or int(existing["authority_schema_version"]) != 14
                    ):
                        raise BrokerError(
                            "infrastructure_ingress_access_request_conflict",
                            "The request_id already binds a different immutable "
                            "infrastructure ingress access request.",
                        )
                    result_json = str(existing["result_json"])
                    result_sha256 = str(existing["result_sha256"])
                    if (
                        hashlib.sha256(result_json.encode("utf-8")).hexdigest()
                        != result_sha256
                    ):
                        raise BrokerError(
                            "infrastructure_ingress_access_receipt_corrupt",
                            "The retained infrastructure ingress access receipt "
                            "does not match its digest.",
                        )
                    decoded = json.loads(result_json)
                    if not isinstance(decoded, dict):
                        raise BrokerError(
                            "infrastructure_ingress_access_receipt_corrupt",
                            "The retained infrastructure ingress access result "
                            "is invalid.",
                        )
                    result = decoded
                    created_at = str(existing["created_at"])
                    replayed = True
                else:
                    created_at = utc_timestamp(current_epoch)
                    if action == "ingress.replace":
                        assert valid_until_epoch is not None
                        if not (
                            current_epoch < valid_until_epoch
                            <= current_epoch
                            + INFRASTRUCTURE_INGRESS_ACCESS_MAX_VALIDITY_SECONDS
                        ):
                            raise ValueError(
                                "infrastructure ingress access expiry must be "
                                "in the future and no more than 30 days"
                            )
                        self._replace_infrastructure_service_access_in_transaction(
                            connection,
                            uid=int(payload["uid"]),
                            account_id=str(payload["account_id"]),
                            operations=_INFRASTRUCTURE_INGRESS_OPERATIONS,
                            valid_until_epoch=valid_until_epoch,
                            now_epoch=current_epoch,
                            updated_at=created_at,
                        )
                        operations = sorted(
                            operation.value
                            for operation in _INFRASTRUCTURE_INGRESS_OPERATIONS
                        )
                        status = "configured"
                    else:
                        self._disable_infrastructure_ingress_access_in_transaction(
                            connection,
                            uid=int(payload["uid"]),
                            account_id=str(payload["account_id"]),
                            updated_at=created_at,
                        )
                        operations = []
                        status = "disabled"
                    result = {
                        "status": status,
                        "role": "infrastructure-ingress",
                        "service_account": str(payload["service_account"]),
                        "uid": int(payload["uid"]),
                        "account_id": str(payload["account_id"]),
                        "operations": operations,
                        "valid_until_epoch": valid_until_epoch,
                        "authority_generation": authority_generation,
                    }
                    result_json = canonical_json(result)
                    result_sha256 = hashlib.sha256(
                        result_json.encode("utf-8")
                    ).hexdigest()
                    connection.execute(
                        """
                        INSERT INTO
                            broker_infrastructure_ingress_access_receipts(
                                request_id, request_schema, action,
                                request_json, request_sha256,
                                result_json, result_sha256,
                                operator_uid, authority_schema_version,
                                created_at
                            )
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 14, ?)
                        """,
                        (
                            request_id,
                            INFRASTRUCTURE_INGRESS_ACCESS_REQUEST_SCHEMA,
                            action,
                            request_json,
                            request_sha256,
                            result_json,
                            result_sha256,
                            created_at,
                        ),
                    )
        return {
            "schema": INFRASTRUCTURE_INGRESS_ACCESS_RECEIPT_SCHEMA,
            "request_id": request_id,
            "action": action,
            "request_sha256": request_sha256,
            "result": result,
            "result_sha256": result_sha256,
            "operator_uid": operator_uid,
            "authority_schema_version": 14,
            "created_at": created_at,
            "replayed": replayed,
        }

    def administer_infrastructure_reader_access(
        self,
        request: Mapping[str, Any],
        *,
        operator_uid: int,
        now_epoch: int | None = None,
    ) -> dict[str, Any]:
        """Atomically replace/disable one expiring read grant and receipt."""

        if operator_uid != 0 or self.expected_uid != 0:
            raise PermissionError(
                "infrastructure reader access requires the root service owner"
            )
        normalized = prepare_infrastructure_reader_access_request(request)
        request_json = canonical_json(normalized)
        request_sha256 = hashlib.sha256(
            request_json.encode("utf-8")
        ).hexdigest()
        request_id = str(normalized["request_id"])
        action = str(normalized["action"])
        current_epoch = int(time.time()) if now_epoch is None else int(now_epoch)
        payload = normalized["payload"]
        valid_until_epoch = (
            int(payload["valid_until_epoch"])
            if action == "reader.replace"
            else None
        )
        replayed = False
        result: dict[str, Any]
        result_sha256: str
        created_at: str
        with self._store() as store:
            with store.immediate_transaction() as connection:
                metadata = connection.execute(
                    """
                    SELECT schema_version, database_generation
                    FROM schema_metadata
                    WHERE singleton = 1
                    """
                ).fetchone()
                if (
                    metadata is None
                    or int(metadata["schema_version"]) != SCHEMA_VERSION
                    or SCHEMA_VERSION != 14
                ):
                    raise RuntimeError(
                        "infrastructure reader access requires schema 14"
                    )
                authority_generation = str(metadata["database_generation"])
                _require_identifier(
                    authority_generation,
                    "database_generation",
                )
                existing = connection.execute(
                    """
                    SELECT request_schema, action, request_json,
                           request_sha256, result_json, result_sha256,
                           operator_uid, authority_schema_version, created_at
                    FROM broker_infrastructure_reader_access_receipts
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["request_schema"])
                        != INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA
                        or str(existing["action"]) != action
                        or str(existing["request_json"]) != request_json
                        or str(existing["request_sha256"]) != request_sha256
                        or int(existing["operator_uid"]) != operator_uid
                        or int(existing["authority_schema_version"]) != 14
                    ):
                        raise BrokerError(
                            "infrastructure_reader_access_request_conflict",
                            "The request_id already binds a different immutable "
                            "infrastructure reader access request.",
                        )
                    result_json = str(existing["result_json"])
                    result_sha256 = str(existing["result_sha256"])
                    if (
                        hashlib.sha256(result_json.encode("utf-8")).hexdigest()
                        != result_sha256
                    ):
                        raise BrokerError(
                            "infrastructure_reader_access_receipt_corrupt",
                            "The retained infrastructure reader access receipt "
                            "does not match its digest.",
                        )
                    decoded = json.loads(result_json)
                    if not isinstance(decoded, dict):
                        raise BrokerError(
                            "infrastructure_reader_access_receipt_corrupt",
                            "The retained infrastructure reader result is invalid.",
                        )
                    result = decoded
                    created_at = str(existing["created_at"])
                    replayed = True
                else:
                    created_at = utc_timestamp(current_epoch)
                    uid = int(payload["uid"])
                    account_id = str(payload["account_id"])
                    if action == "reader.replace":
                        assert valid_until_epoch is not None
                        if not (
                            current_epoch < valid_until_epoch
                            <= current_epoch
                            + INFRASTRUCTURE_READER_ACCESS_MAX_VALIDITY_SECONDS
                        ):
                            raise ValueError(
                                "infrastructure reader access expiry must be in "
                                "the future and no more than 30 days"
                            )
                        _require_uid_has_no_enabled_infrastructure_service_access(
                            connection,
                            uid=uid,
                        )
                        self._replace_infrastructure_service_access_in_transaction(
                            connection,
                            uid=uid,
                            account_id=account_id,
                            operations=frozenset(
                                {BrokerOperation.INFRASTRUCTURE_READ}
                            ),
                            valid_until_epoch=valid_until_epoch,
                            now_epoch=current_epoch,
                            updated_at=created_at,
                        )
                        status = "configured"
                        operations = [
                            BrokerOperation.INFRASTRUCTURE_READ.value
                        ]
                    else:
                        self._disable_infrastructure_reader_access_in_transaction(
                            connection,
                            uid=uid,
                            account_id=account_id,
                            updated_at=created_at,
                        )
                        status = "disabled"
                        operations = []
                    result = {
                        "status": status,
                        "role": "infrastructure-reader",
                        "service_account": str(payload["service_account"]),
                        "uid": uid,
                        "account_id": account_id,
                        "operations": operations,
                        "valid_until_epoch": valid_until_epoch,
                        "authority_generation": authority_generation,
                    }
                    result_json = canonical_json(result)
                    result_sha256 = hashlib.sha256(
                        result_json.encode("utf-8")
                    ).hexdigest()
                    connection.execute(
                        """
                        INSERT INTO
                            broker_infrastructure_reader_access_receipts(
                                request_id, request_schema, action,
                                request_json, request_sha256,
                                result_json, result_sha256,
                                operator_uid, authority_schema_version,
                                created_at
                            )
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 14, ?)
                        """,
                        (
                            request_id,
                            INFRASTRUCTURE_READER_ACCESS_REQUEST_SCHEMA,
                            action,
                            request_json,
                            request_sha256,
                            result_json,
                            result_sha256,
                            created_at,
                        ),
                    )
        return {
            "schema": INFRASTRUCTURE_READER_ACCESS_RECEIPT_SCHEMA,
            "request_id": request_id,
            "action": action,
            "request_sha256": request_sha256,
            "result": result,
            "result_sha256": result_sha256,
            "operator_uid": operator_uid,
            "authority_schema_version": 14,
            "created_at": created_at,
            "replayed": replayed,
        }

    @staticmethod
    def _disable_infrastructure_reader_access_in_transaction(
        connection: sqlite3.Connection,
        *,
        uid: int,
        account_id: str,
        updated_at: str,
    ) -> None:
        if type(uid) is not int or uid <= 0:
            raise ValueError(
                "infrastructure reader UID must be a non-root UID"
            )
        _require_identifier(account_id, "account_id")
        principal = connection.execute(
            """
            SELECT account_id
            FROM broker_acl_principals
            WHERE uid = ?
            """,
            (uid,),
        ).fetchone()
        if (
            principal is not None
            and str(principal["account_id"]) != account_id
        ):
            raise BrokerError(
                "principal_account_conflict",
                "This operating-system UID is enrolled for a different account.",
            )
        connection.execute(
            """
            UPDATE broker_infrastructure_service_acl
            SET enabled = 0, updated_at = ?
            WHERE uid = ? AND account_id = ?
              AND operation = 'infrastructure.read'
            """,
            (updated_at, uid, account_id),
        )

    @staticmethod
    def _disable_infrastructure_ingress_access_in_transaction(
        connection: sqlite3.Connection,
        *,
        uid: int,
        account_id: str,
        updated_at: str,
    ) -> None:
        if type(uid) is not int or uid <= 0:
            raise ValueError(
                "infrastructure ingress UID must be a non-root UID"
            )
        _require_identifier(account_id, "account_id")
        principal = connection.execute(
            """
            SELECT account_id
            FROM broker_acl_principals
            WHERE uid = ?
            """,
            (uid,),
        ).fetchone()
        if (
            principal is not None
            and str(principal["account_id"]) != account_id
        ):
            raise BrokerError(
                "principal_account_conflict",
                "This operating-system UID is enrolled for a different account.",
            )
        connection.execute(
            """
            UPDATE broker_infrastructure_service_acl
            SET enabled = 0, updated_at = ?
            WHERE uid = ? AND account_id = ?
              AND operation IN (
                  'infrastructure.ingest',
                  'infrastructure.verification_context'
              )
            """,
            (updated_at, uid, account_id),
        )

    @staticmethod
    def _replace_infrastructure_service_access_in_transaction(
        connection: sqlite3.Connection,
        *,
        uid: int,
        account_id: str,
        operations: frozenset[BrokerOperation],
        valid_until_epoch: int,
        now_epoch: int,
        updated_at: str,
    ) -> None:
        if type(uid) is not int or uid < 0:
            raise ValueError("uid must be a non-negative integer")
        _require_identifier(account_id, "account_id")
        if (
            type(valid_until_epoch) is not int
            or valid_until_epoch <= now_epoch
        ):
            raise ValueError("valid_until_epoch must be in the future")
        if not operations <= _INFRASTRUCTURE_OPERATIONS:
            raise ValueError(
                "infrastructure service access contains an invalid operation"
            )
        if operations & _INFRASTRUCTURE_INGRESS_OPERATIONS:
            if operations != _INFRASTRUCTURE_INGRESS_OPERATIONS:
                raise BrokerError(
                    "infrastructure_ingress_scope_mixed",
                    "A dedicated infrastructure ingress UID may receive "
                    "exactly ingest plus verification-context; partial "
                    "or read-mixed ingress authority is invalid.",
                )
            _require_infrastructure_principal_isolated(
                connection, uid=uid
            )
        principal = connection.execute(
            """
            SELECT account_id, enabled
            FROM broker_acl_principals WHERE uid = ?
            """,
            (uid,),
        ).fetchone()
        if principal is None:
            connection.execute(
                """
                INSERT INTO broker_acl_principals(
                    uid, account_id, enabled, updated_at
                ) VALUES (?, ?, 1, ?)
                """,
                (uid, account_id, updated_at),
            )
        elif str(principal["account_id"]) != account_id:
            raise BrokerError(
                "principal_account_conflict",
                "This operating-system UID is already enrolled for a "
                "different account.",
            )
        elif not bool(principal["enabled"]):
            raise BrokerError(
                "peer_not_authorized",
                "The service principal is disabled and cannot receive "
                "infrastructure grants.",
            )
        connection.execute(
            """
            UPDATE broker_infrastructure_service_acl
            SET enabled = 0, updated_at = ?
            WHERE uid = ?
            """,
            (updated_at, uid),
        )
        for operation in sorted(operations, key=lambda item: item.value):
            connection.execute(
                """
                INSERT INTO broker_infrastructure_service_acl(
                    uid, account_id, operation, enabled,
                    valid_until_epoch, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(uid, operation) DO UPDATE SET
                    account_id = excluded.account_id,
                    enabled = 1,
                    valid_until_epoch = excluded.valid_until_epoch,
                    updated_at = excluded.updated_at
                """,
                (
                    uid,
                    account_id,
                    operation.value,
                    valid_until_epoch,
                    updated_at,
                ),
            )

    def provision_repository_enrollment(
        self,
        *,
        uid: int,
        repo_id: str,
        account_id: str,
        issued_at: str,
        valid_until_epoch: int,
        enrollment_snapshot_id: str | None = None,
        grant_snapshot_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        """Persist one UID/account's independently expiring repository authority."""

        if type(uid) is not int or uid < 0:
            raise ValueError("uid must be a non-negative integer")
        _require_identifier(repo_id, "project_id")
        _require_identifier(account_id, "account_id")
        if not isinstance(issued_at, str) or not issued_at:
            raise ValueError("issued_at must be a non-empty timestamp")
        if type(valid_until_epoch) is not int or valid_until_epoch <= 0:
            raise ValueError("valid_until_epoch must be a positive integer")
        if (enrollment_snapshot_id is None) != (grant_snapshot_id is None):
            raise ValueError(
                "repository enrollment snapshot identifiers must both be present or both be absent"
            )
        for value, field in (
            (enrollment_snapshot_id, "enrollment_snapshot_id"),
            (grant_snapshot_id, "grant_snapshot_id"),
        ):
            if value is not None:
                _require_identifier(value, field)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_uid_has_no_enabled_infrastructure_service_access(
                    connection, uid=uid
                )
                principal = connection.execute(
                    "SELECT account_id FROM broker_acl_principals WHERE uid = ?",
                    (uid,),
                ).fetchone()
                if principal is None:
                    raise BrokerError(
                        "peer_not_authorized",
                        "The operating-system account must be provisioned before repository enrollment.",
                    )
                if str(principal["account_id"]) != account_id:
                    raise BrokerError(
                        "principal_account_conflict",
                        "Repository enrollment cannot transfer a UID to a different account.",
                    )
                repository = connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                if repository is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Repository enrollment targets an unknown project identity.",
                    )
                existing = connection.execute(
                    """
                    SELECT account_id
                    FROM broker_repository_enrollments
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (uid, repo_id),
                ).fetchone()
                if existing is not None and str(existing["account_id"]) != account_id:
                    raise BrokerError(
                        "principal_account_conflict",
                        "Existing repository authority belongs to a different account and cannot be transferred implicitly.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, enrollment_snapshot_id,
                        grant_snapshot_id, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id) DO UPDATE SET
                        enabled = excluded.enabled,
                        issued_at = excluded.issued_at,
                        valid_until_epoch = excluded.valid_until_epoch,
                        enrollment_snapshot_id = excluded.enrollment_snapshot_id,
                        grant_snapshot_id = excluded.grant_snapshot_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        account_id,
                        int(enabled),
                        issued_at,
                        valid_until_epoch,
                        enrollment_snapshot_id,
                        grant_snapshot_id,
                        now,
                    ),
                )

    def revoke_observation_derived_access(
        self,
        *,
        uid: int,
        repo_id: str,
        containers: bool = False,
        databases: bool = False,
        lifecycle_resources: bool = False,
    ) -> None:
        """Disable stale observation-derived grants before exact reprovisioning."""

        _require_identifier(repo_id, "project_id")
        if not any((containers, databases, lifecycle_resources)):
            return
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if containers:
                    connection.execute(
                        """
                        UPDATE broker_resource_acl
                        SET enabled = 0, updated_at = ?
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'container'
                        """,
                        (now, uid, repo_id),
                    )
                    connection.execute(
                        """
                        UPDATE broker_runtime_acl
                        SET enabled = 0, updated_at = ?
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'docker'
                        """,
                        (now, uid, repo_id),
                    )
                if databases:
                    connection.execute(
                        """
                        UPDATE broker_database_acl
                        SET enabled = 0, updated_at = ?
                        WHERE uid = ? AND repo_id = ?
                        """,
                        (now, uid, repo_id),
                    )
                    connection.execute(
                        """
                        UPDATE broker_runtime_acl
                        SET enabled = 0, updated_at = ?
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'database_stack'
                        """,
                        (now, uid, repo_id),
                    )
                if lifecycle_resources:
                    connection.execute(
                        """
                        UPDATE broker_lifecycle_resource_acl
                        SET enabled = 0, updated_at = ?
                        WHERE uid = ? AND repo_id = ?
                        """,
                        (now, uid, repo_id),
                    )

    def provision_ephemeral_template(
        self,
        *,
        template_id: str,
        repo_id: str,
        name: str,
        image_ref: str,
        command: Iterable[str] = (),
        environment: Mapping[str, str] | None = None,
        secret_policy_kind: str | None = None,
        secret_binding_id: str | None = None,
        default_ttl_seconds: int = 3600,
        max_ttl_seconds: int = 14400,
        container_tcp_port: int | None = None,
        host_port_start: int | None = None,
        host_port_end: int | None = None,
        memory_bytes: int | None = None,
        cpu_millis: int | None = None,
        max_concurrent_runs: int = 4,
        max_concurrent_runs_per_uid: int = 2,
        repo_max_active_runs: int = 16,
        repo_memory_budget_bytes: int = 8 * 1024 * 1024 * 1024,
        repo_cpu_budget_millis: int = 16_000,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Seal one administrator-declared short-lived container template.

        The broker wire protocol never accepts these values.  Runs copy this
        definition into their write-ahead record before Docker is invoked, so
        later reenrollment cannot change an in-flight recovery target.
        """

        _require_identifier(template_id, "template_id")
        _require_identifier(repo_id, "project_id")
        normalized_name = _require_ephemeral_template_name(name)
        normalized_image = _require_pinned_ephemeral_image(image_ref)
        if isinstance(command, (str, bytes)):
            raise ValueError("ephemeral command must be an iterable of arguments")
        normalized_command = tuple(
            _require_ephemeral_argument(item) for item in command
        )
        if len(normalized_command) > 128:
            raise ValueError("ephemeral command may contain at most 128 arguments")
        normalized_environment = _normalize_ephemeral_environment(environment or {})
        normalized_secret_policy_kind = normalize_ephemeral_secret_policy(
            secret_policy_kind
        )
        _require_ephemeral_secret_policy_environment(
            policy_kind=normalized_secret_policy_kind,
            environment=normalized_environment,
        )
        if normalized_secret_policy_kind is None:
            if secret_binding_id is not None:
                raise ValueError(
                    "ephemeral secret binding requires a typed secret policy"
                )
            secret_policy = None
        else:
            binding_id = (
                deterministic_secret_binding_id(
                    repository_id=repo_id,
                    template_id=template_id,
                    policy=normalized_secret_policy_kind,
                )
                if secret_binding_id is None
                else secret_binding_id
            )
            secret_policy = EphemeralSecretPolicy(
                kind=normalized_secret_policy_kind,
                binding_id=binding_id,
            )
        current_secret_policy_kind = (
            None if secret_policy is None else secret_policy.kind
        )
        current_secret_binding_id = (
            None if secret_policy is None else secret_policy.binding_id
        )
        if (
            type(default_ttl_seconds) is not int
            or type(max_ttl_seconds) is not int
            or not 60 <= default_ttl_seconds <= max_ttl_seconds <= 7 * 24 * 60 * 60
        ):
            raise ValueError(
                "ephemeral TTLs must be ordered integers from one minute through seven days"
            )
        port_values = (container_tcp_port, host_port_start, host_port_end)
        if all(item is None for item in port_values):
            pass
        elif (
            any(type(item) is not int for item in port_values)
            or not 1 <= int(container_tcp_port) <= 65535
            or not 1 <= int(host_port_start) <= int(host_port_end) <= 65535
        ):
            raise ValueError(
                "ephemeral TCP publication requires one container port and an ordered host range"
            )
        if memory_bytes is not None and (
            type(memory_bytes) is not int or memory_bytes < 16 * 1024 * 1024
        ):
            raise ValueError("ephemeral memory_bytes must be at least 16 MiB")
        if cpu_millis is not None and (
            type(cpu_millis) is not int or not 10 <= cpu_millis <= 256_000
        ):
            raise ValueError("ephemeral cpu_millis must be from 10 through 256000")
        effective_memory = memory_bytes or 512 * 1024 * 1024
        effective_cpu = cpu_millis or 1000
        if (
            type(max_concurrent_runs) is not int
            or type(max_concurrent_runs_per_uid) is not int
            or type(repo_max_active_runs) is not int
            or not 1
            <= max_concurrent_runs_per_uid
            <= max_concurrent_runs
            <= 32
            or not max_concurrent_runs <= repo_max_active_runs <= 64
        ):
            raise ValueError(
                "ephemeral concurrency limits must be ordered positive integers within the fixed host bounds"
            )
        if (
            type(repo_memory_budget_bytes) is not int
            or repo_memory_budget_bytes < effective_memory
            or repo_memory_budget_bytes > 64 * (1 << 50)
            or type(repo_cpu_budget_millis) is not int
            or repo_cpu_budget_millis < effective_cpu
            or repo_cpu_budget_millis > 64 * 256_000
        ):
            raise ValueError(
                "ephemeral repository CPU and memory budgets must cover at least one sealed run and stay within the fixed repository bounds"
            )
        definition = {
            "repo_id": repo_id,
            "template_id": template_id,
            "name": normalized_name,
            "image_ref": normalized_image,
            "command": list(normalized_command),
            "environment": dict(normalized_environment),
            "secret_policy_kind": current_secret_policy_kind,
            "secret_binding_id": current_secret_binding_id,
            "default_ttl_seconds": default_ttl_seconds,
            "max_ttl_seconds": max_ttl_seconds,
            "container_tcp_port": container_tcp_port,
            "host_port_start": host_port_start,
            "host_port_end": host_port_end,
            "memory_bytes": memory_bytes,
            "cpu_millis": cpu_millis,
            "max_concurrent_runs": max_concurrent_runs,
            "max_concurrent_runs_per_uid": max_concurrent_runs_per_uid,
            "repo_max_active_runs": repo_max_active_runs,
            "repo_memory_budget_bytes": repo_memory_budget_bytes,
            "repo_cpu_budget_millis": repo_cpu_budget_millis,
        }
        definition_fingerprint = "sha256:" + fingerprint(definition)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                repository = connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)
                ).fetchone()
                if repository is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Ephemeral template repository is not provisioned.",
                    )
                previous_policy = connection.execute(
                    """
                    SELECT secret_policy_kind, secret_binding_id
                    FROM ephemeral_container_templates
                    WHERE template_id = ? AND repo_id = ?
                    """,
                    (template_id, repo_id),
                ).fetchone()
                connection.execute(
                    """
                    INSERT INTO ephemeral_container_templates(
                        template_id, repo_id, name, image_ref,
                        secret_policy_kind, secret_binding_id,
                        definition_fingerprint, default_ttl_seconds,
                        max_ttl_seconds, container_tcp_port, host_port_start,
                        host_port_end, memory_bytes, cpu_millis,
                        max_concurrent_runs, max_concurrent_runs_per_uid,
                        repo_max_active_runs, repo_memory_budget_bytes,
                        repo_cpu_budget_millis, enabled,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ON CONFLICT(template_id) DO UPDATE SET
                        name = excluded.name,
                        image_ref = excluded.image_ref,
                        secret_policy_kind = excluded.secret_policy_kind,
                        secret_binding_id = excluded.secret_binding_id,
                        definition_fingerprint = excluded.definition_fingerprint,
                        default_ttl_seconds = excluded.default_ttl_seconds,
                        max_ttl_seconds = excluded.max_ttl_seconds,
                        container_tcp_port = excluded.container_tcp_port,
                        host_port_start = excluded.host_port_start,
                        host_port_end = excluded.host_port_end,
                        memory_bytes = excluded.memory_bytes,
                        cpu_millis = excluded.cpu_millis,
                        max_concurrent_runs = excluded.max_concurrent_runs,
                        max_concurrent_runs_per_uid = excluded.max_concurrent_runs_per_uid,
                        repo_max_active_runs = excluded.repo_max_active_runs,
                        repo_memory_budget_bytes = excluded.repo_memory_budget_bytes,
                        repo_cpu_budget_millis = excluded.repo_cpu_budget_millis,
                        enabled = excluded.enabled,
                        generation = CASE
                            WHEN ephemeral_container_templates.definition_fingerprint
                                 != excluded.definition_fingerprint
                            THEN ephemeral_container_templates.generation + 1
                            ELSE ephemeral_container_templates.generation
                        END,
                        updated_at = excluded.updated_at
                    """,
                    (
                        template_id,
                        repo_id,
                        normalized_name,
                        normalized_image,
                        current_secret_policy_kind,
                        current_secret_binding_id,
                        definition_fingerprint,
                        default_ttl_seconds,
                        max_ttl_seconds,
                        container_tcp_port,
                        host_port_start,
                        host_port_end,
                        memory_bytes,
                        cpu_millis,
                        max_concurrent_runs,
                        max_concurrent_runs_per_uid,
                        repo_max_active_runs,
                        repo_memory_budget_bytes,
                        repo_cpu_budget_millis,
                        int(enabled),
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT repo_id FROM ephemeral_container_templates WHERE template_id = ?",
                    (template_id,),
                ).fetchone()
                if row is None or str(row["repo_id"]) != repo_id:
                    raise BrokerError(
                        "template_identity_conflict",
                        "Ephemeral template ID already belongs to another repository.",
                    )
                if previous_policy is not None and (
                    previous_policy["secret_policy_kind"]
                    != current_secret_policy_kind
                    or previous_policy["secret_binding_id"]
                    != current_secret_binding_id
                ):
                    transition_reason = (
                        "The administrator changed this template's credential policy; "
                        "runs using the previous credential are fenced for cleanup."
                    )
                    connection.execute(
                        """
                        UPDATE broker_ephemeral_acl
                        SET enabled = 0, updated_at = ?
                        WHERE repo_id = ? AND template_id = ?
                          AND operation = 'ephemeral.secret_fd' AND enabled = 1
                        """,
                        (now, repo_id, template_id),
                    )
                    connection.execute(
                        """
                        UPDATE ephemeral_container_runs
                        SET status = 'cleanup_pending', phase = 'secret_policy_revoked',
                            cleanup_requested = 1,
                            cleanup_reason = COALESCE(cleanup_reason, ?),
                            error_code = COALESCE(
                                error_code, 'ephemeral_secret_policy_revoked'
                            ),
                            error_message = COALESCE(error_message, ?),
                            next_reconcile_at_epoch = 0,
                            generation = generation + 1, updated_at = ?
                        WHERE repo_id = ? AND template_id = ?
                          AND status NOT IN ('cleaned', 'failed')
                          AND secret_policy_kind IS NOT NULL
                        """,
                        (
                            transition_reason,
                            transition_reason,
                            now,
                            repo_id,
                            template_id,
                        ),
                    )
                connection.execute(
                    "DELETE FROM ephemeral_template_arguments WHERE template_id = ?",
                    (template_id,),
                )
                connection.executemany(
                    "INSERT INTO ephemeral_template_arguments(template_id, ordinal, argument) VALUES (?, ?, ?)",
                    [
                        (template_id, ordinal, argument)
                        for ordinal, argument in enumerate(normalized_command)
                    ],
                )
                connection.execute(
                    "DELETE FROM ephemeral_template_environment WHERE template_id = ?",
                    (template_id,),
                )
                connection.executemany(
                    "INSERT INTO ephemeral_template_environment(template_id, name, value) VALUES (?, ?, ?)",
                    [
                        (template_id, key, value)
                        for key, value in normalized_environment
                    ],
                )
        return {
            "template_id": template_id,
            "name": normalized_name,
            "definition_fingerprint": definition_fingerprint,
        }

    def disable_ephemeral_templates_except(
        self, *, repo_id: str, template_ids: Iterable[str]
    ) -> None:
        _require_identifier(repo_id, "project_id")
        retained = tuple(dict.fromkeys(str(item) for item in template_ids))
        for template_id in retained:
            _require_identifier(template_id, "template_id")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                if retained:
                    placeholders = ",".join("?" for _ in retained)
                    connection.execute(
                        f"""
                        UPDATE ephemeral_container_templates
                        SET enabled = 0, updated_at = ?
                        WHERE repo_id = ? AND template_id NOT IN ({placeholders})
                        """,
                        (now, repo_id, *retained),
                    )
                else:
                    connection.execute(
                        "UPDATE ephemeral_container_templates SET enabled = 0, updated_at = ? WHERE repo_id = ?",
                        (now, repo_id),
                    )
                connection.execute(
                    """
                    UPDATE broker_ephemeral_acl
                    SET enabled = 0, updated_at = ?
                    WHERE repo_id = ? AND operation IN (
                        'ephemeral.start', 'ephemeral.image_status',
                        'ephemeral.image_prefetch', 'ephemeral.renew',
                        'ephemeral.secret_fd'
                    ) AND template_id IN (
                        SELECT template_id FROM ephemeral_container_templates
                        WHERE repo_id = ? AND enabled = 0
                    )
                    """,
                    (now, repo_id, repo_id),
                )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET next_reconcile_at_epoch = 0,
                        generation = generation + 1, updated_at = ?
                    WHERE repo_id = ? AND status NOT IN ('cleaned', 'failed')
                      AND template_id IN (
                          SELECT template_id FROM ephemeral_container_templates
                          WHERE repo_id = ? AND enabled = 0
                      )
                    """,
                    (now, repo_id, repo_id),
                )

    def replace_ephemeral_access(
        self,
        *,
        uid: int,
        repo_id: str,
        template_ids: Iterable[str],
        prefetch_template_ids: Iterable[str] = (),
    ) -> None:
        _require_identifier(repo_id, "project_id")
        normalized = tuple(dict.fromkeys(str(item) for item in template_ids))
        for template_id in normalized:
            _require_identifier(template_id, "template_id")
        prefetch = tuple(
            dict.fromkeys(str(item) for item in prefetch_template_ids)
        )
        for template_id in prefetch:
            _require_identifier(template_id, "template_id")
        if not set(prefetch) <= set(normalized):
            raise ValueError(
                "ephemeral image prefetch grants must be a subset of enrolled templates"
            )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                connection.execute(
                    "UPDATE broker_ephemeral_acl SET enabled = 0, updated_at = ? WHERE uid = ? AND repo_id = ?",
                    (now, uid, repo_id),
                )
                for template_id in normalized:
                    template = connection.execute(
                        """
                        SELECT enabled, secret_policy_kind
                        FROM ephemeral_container_templates
                        WHERE template_id = ? AND repo_id = ?
                        """,
                        (template_id, repo_id),
                    ).fetchone()
                    if template is None or not bool(template["enabled"]):
                        raise BrokerError(
                            "control_binding_unavailable",
                            "Ephemeral access targets a disabled or unknown template.",
                        )
                    policy_kind = template["secret_policy_kind"]
                    operations = _ephemeral_acl_operations_for_policy(
                        None if policy_kind is None else str(policy_kind),
                        allow_image_prefetch=template_id in prefetch,
                    )
                    for operation in operations:
                        connection.execute(
                            """
                            INSERT INTO broker_ephemeral_acl(
                                uid, repo_id, template_id, operation, enabled, updated_at
                            ) VALUES (?, ?, ?, ?, 1, ?)
                            ON CONFLICT(uid, repo_id, template_id, operation)
                            DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                            """,
                            (uid, repo_id, template_id, operation.value, now),
                        )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET next_reconcile_at_epoch = 0,
                        generation = generation + 1, updated_at = ?
                    WHERE repo_id = ? AND owner_uid = ?
                      AND status NOT IN ('cleaned', 'failed')
                      AND NOT EXISTS (
                          SELECT 1 FROM ephemeral_container_templates template
                          JOIN broker_ephemeral_acl acl
                            ON acl.template_id = template.template_id
                           AND acl.repo_id = template.repo_id
                          WHERE template.template_id = ephemeral_container_runs.template_id
                            AND template.repo_id = ephemeral_container_runs.repo_id
                            AND template.enabled = 1
                            AND acl.uid = ephemeral_container_runs.owner_uid
                            AND acl.operation = 'ephemeral.start'
                            AND acl.enabled = 1
                      )
                    """,
                    (now, repo_id, uid),
                )

    def ephemeral_image_target(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        require_reserved_operation: bool = False,
    ) -> EphemeralImageTarget:
        """Resolve only the current sealed image for one template-scoped request."""

        request = authorized.request
        if request.operation not in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_STATUS,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        }:
            raise ValueError("request does not target an ephemeral template image")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                return _ephemeral_image_target_for_request(
                    connection,
                    request=request,
                    require_reserved_operation=require_reserved_operation,
                )

    def complete_ephemeral_image_prefetch(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        target: EphemeralImageTarget,
        proof: Mapping[str, Any],
        cache_origin: str,
        changed: bool | None,
    ) -> dict[str, Any]:
        """Persist one exact, digest-proven image cache receipt."""

        request = authorized.request
        if request.operation is not BrokerOperation.EPHEMERAL_IMAGE_PREFETCH:
            raise ValueError("request is not an ephemeral image prefetch")
        if cache_origin not in {"already_present", "pulled", "reconciled"}:
            raise ValueError("ephemeral image cache origin is invalid")
        if changed is not None and type(changed) is not bool:
            raise ValueError("ephemeral image cache changed must be boolean or null")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                current = _ephemeral_image_target_for_request(
                    connection,
                    request=request,
                    require_reserved_operation=True,
                )
                if current != target:
                    raise BrokerError(
                        "operation_state_conflict",
                        "The sealed ephemeral image target changed before its cache receipt could be recorded.",
                        operation_id=request.operation_id,
                    )
                normalized_proof = _normalize_ephemeral_image_cache_proof(
                    proof, target=current
                )
                result = {
                    **normalized_proof,
                    "cache_origin": cache_origin,
                    "changed": changed,
                    "template_id": current.template_id,
                    "template_fingerprint": current.template_fingerprint,
                }
                _finish_operation(
                    connection, request.operation_id, result=result
                )
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, source_id, operation_id,
                        event_kind, code, message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, NULL, ?, 'ephemeral.image_prefetched',
                              'ephemeral_image_cached', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        current.repo_id,
                        request.operation_id,
                        "The sealed ephemeral image cache was verified.",
                        json.dumps(
                            result,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        utc_timestamp(),
                    ),
                )
                return result

    def ephemeral_secret_fd_target(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
    ) -> EphemeralSecretRunTarget:
        """Authorize one descriptor retrieval against the exact running run.

        This returns only policy and opaque binding metadata; the password is
        deliberately owned by the volatile runtime manager and never enters
        this database transaction or the wire result.
        """

        request = authorized.request
        if request.operation is not BrokerOperation.EPHEMERAL_SECRET_FD:
            raise ValueError("request is not an ephemeral credential delivery")
        canonical_run_id = str(run_id)
        if request.resource_id != canonical_run_id:
            raise BrokerError(
                "resource_access_denied",
                "Credential delivery must target the exact ephemeral run identity.",
                operation_id=request.operation_id,
            )
        _require_identifier(template_id, "template_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                if row is None:
                    raise BrokerError(
                        "resource_access_denied",
                        "Credential delivery requires an exact running ephemeral run.",
                        operation_id=request.operation_id,
                    )
                if str(row["template_id"]) != template_id:
                    raise BrokerError(
                        "resource_access_denied",
                        "Credential delivery template does not match the exact run.",
                        operation_id=request.operation_id,
                    )
                kind = row["secret_policy_kind"]
                binding_id = row["secret_binding_id"]
                if kind is None or binding_id is None:
                    raise BrokerError(
                        "secret_delivery_unavailable",
                        "This ephemeral template has no broker-managed credential policy.",
                        operation_id=request.operation_id,
                    )
                try:
                    policy = EphemeralSecretPolicy(
                        kind=str(kind), binding_id=str(binding_id)
                    )
                except (TypeError, ValueError) as exc:
                    raise BrokerError(
                        "secret_delivery_unavailable",
                        "This ephemeral run has an invalid credential policy snapshot.",
                        operation_id=request.operation_id,
                    ) from exc
                return EphemeralSecretRunTarget(
                    run_id=canonical_run_id,
                    template_id=str(row["template_id"]),
                    repo_id=request.project_id,
                    owner_uid=int(row["owner_uid"]),
                    account_id=str(row["account_id"]),
                    policy=policy,
                    expires_at_epoch=int(row["expires_at_epoch"]),
                )

    def provision_compose_definition(
        self,
        *,
        compose_definition_id: str,
        repo_id: str,
        cwd: str | os.PathLike[str],
        files: Iterable[str | os.PathLike[str]],
        env_files: Iterable[str | os.PathLike[str]] = (),
        profiles: Iterable[str] = (),
        services: Iterable[str] = (),
        project_name: Optional[str] = None,
        observation_snapshot_id: Optional[str] = None,
        host_access_approved: bool = False,
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
        if isinstance(env_files, (str, bytes, os.PathLike)):
            raise ValueError("env_files must be an iterable of environment file paths")
        if isinstance(profiles, (str, bytes)):
            raise ValueError("profiles must be an iterable of Compose profile names")
        if isinstance(services, (str, bytes)):
            raise ValueError("services must be an iterable of Compose service names")
        if type(host_access_approved) is not bool:
            raise TypeError("host_access_approved must be a boolean")
        if host_access_approved and _service_administrator_uid() != 0:
            raise PermissionError(
                "Compose host-access approval requires the root service administrator"
            )
        supplied_files = tuple(files)
        supplied_env_files = tuple(env_files)
        normalized_profiles = tuple(
            _require_compose_profile_name(item) for item in profiles
        )
        normalized_services = tuple(
            _require_compose_service_name(item) for item in services
        )
        if len(supplied_env_files) > 16:
            raise ValueError("env_files must contain at most 16 paths")
        if len(normalized_profiles) > 64:
            raise ValueError("profiles must contain at most 64 names")
        if len(set(normalized_profiles)) != len(normalized_profiles):
            raise ValueError("profiles must not contain duplicates")
        if not 1 <= len(normalized_services) <= 128:
            raise ValueError("services must contain from one through 128 names")
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
        canonical_cwd = _canonical_existing_path(
            cwd, field="compose cwd", directory=True
        )
        _require_path_within(canonical_cwd, canonical_root, field="compose cwd")
        canonical_files = tuple(
            _canonical_existing_path(item, field="compose file", directory=False)
            for item in supplied_files
        )
        if len(set(canonical_files)) != len(canonical_files):
            raise ValueError("compose_files must not contain duplicate canonical paths")
        for file_path in canonical_files:
            _require_path_within(file_path, canonical_root, field="compose file")
        canonical_env_files = tuple(
            _canonical_existing_path(
                item, field="Compose environment file", directory=False
            )
            for item in supplied_env_files
        )
        if len(set(canonical_env_files)) != len(canonical_env_files):
            raise ValueError("env_files must not contain duplicate canonical paths")
        for file_path in canonical_env_files:
            _require_path_within(
                file_path, canonical_root, field="Compose environment file"
            )
        root_descriptor = open_anchored_compose_root(canonical_root)
        cwd_descriptor = -1
        try:
            root_identity = compose_directory_identity(root_descriptor)
            cwd_descriptor = open_compose_directory_beneath(
                root_descriptor,
                compose_relative_parts(
                    canonical_cwd,
                    canonical_root=canonical_root,
                    field="Compose cwd",
                ),
            )
            cwd_identity = compose_directory_identity(cwd_descriptor)
            root_owner_uid = int(os.fstat(root_descriptor).st_uid)
            file_evidence_list: list[dict[str, int | str]] = []
            compose_payload_list: list[bytes] = []
            for item in canonical_files:
                evidence, payload = read_anchored_compose_file(
                    root_descriptor,
                    compose_relative_parts(
                        item,
                        canonical_root=canonical_root,
                        field="Compose file",
                    ),
                    maximum_bytes=8 * 1024 * 1024,
                )
                require_sealable_compose_payload(payload)
                file_evidence_list.append(evidence)
                compose_payload_list.append(payload)
            env_file_evidence_list: list[dict[str, int | str]] = []
            env_payload_list: list[bytes] = []
            for item in canonical_env_files:
                evidence, payload = read_anchored_compose_file(
                    root_descriptor,
                    compose_relative_parts(
                        item,
                        canonical_root=canonical_root,
                        field="Compose environment file",
                    ),
                    maximum_bytes=1024 * 1024,
                    require_private=True,
                    allowed_owner_uids=frozenset({0, root_owner_uid}),
                )
                env_file_evidence_list.append(evidence)
                env_payload_list.append(payload)
            file_evidence = tuple(file_evidence_list)
            env_file_evidence = tuple(env_file_evidence_list)
            effective_evidence: EffectiveComposeEvidence | None = None
            if enabled:
                if self.compose_model_renderer is None:
                    raise RuntimeError(
                        "enabling Compose requires a service-owned merged-model renderer"
                    )
                rendered = self.compose_model_renderer(
                    compose_payloads=tuple(compose_payload_list),
                    env_payloads=tuple(env_payload_list),
                    profiles=normalized_profiles,
                    declared_services=normalized_services,
                    project_name=normalized_project_name,
                    pinned_cwd=stable_compose_descriptor_path(cwd_descriptor),
                )
                effective_evidence = require_effective_compose_model(
                    rendered,
                    declared_services=normalized_services,
                    declared_profiles=normalized_profiles,
                    project_name=normalized_project_name,
                    host_access_approved=host_access_approved,
                )
        finally:
            if cwd_descriptor >= 0:
                os.close(cwd_descriptor)
            os.close(root_descriptor)
        definition_fingerprint = _compose_definition_fingerprint(
            repo_id=repo_id,
            canonical_root=canonical_root,
            root_identity={
                "device": root_identity.device,
                "inode": root_identity.inode,
            },
            cwd=canonical_cwd,
            cwd_identity={
                "device": cwd_identity.device,
                "inode": cwd_identity.inode,
            },
            compose_files=canonical_files,
            compose_file_evidence=file_evidence,
            env_files=canonical_env_files,
            env_file_evidence=env_file_evidence,
            profiles=normalized_profiles,
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
                if (
                    current_repo is None
                    or str(current_repo["canonical_root"]) != canonical_root
                ):
                    raise BrokerError(
                        "stale_compose_definition",
                        "Repository identity changed while provisioning Compose.",
                    )
                if enabled and observation_snapshot_id is not None:
                    _require_observed_compose_project_name_available(
                        connection,
                        snapshot_id=observation_snapshot_id,
                        repo_id=repo_id,
                        project_name=normalized_project_name,
                    )
                if enabled:
                    conflicting_project = connection.execute(
                        """
                        SELECT definition.repo_id
                        FROM broker_compose_project_claims claim
                        JOIN broker_compose_definitions definition
                          USING(compose_definition_id)
                        WHERE claim.project_name = ? AND claim.claimed = 1
                          AND claim.compose_definition_id != ?
                        LIMIT 1
                        """,
                        (normalized_project_name, compose_definition_id),
                    ).fetchone()
                    if conflicting_project is not None:
                        raise BrokerError(
                            "compose_project_name_conflict",
                            "Compose project name remains claimed by another definition.",
                        )
                existing = connection.execute(
                    """
                    SELECT repo_id, project_name, definition_fingerprint,
                           generation, created_at
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
                if existing is not None:
                    _require_no_unresolved_compose_definition_change(
                        connection,
                        compose_definition_ids=(compose_definition_id,),
                    )
                existing_claim = connection.execute(
                    """
                    SELECT project_name, claimed, release_snapshot_id, released_at
                    FROM broker_compose_project_claims
                    WHERE compose_definition_id = ?
                    """,
                    (compose_definition_id,),
                ).fetchone()
                if (
                    enabled
                    and existing_claim is not None
                    and str(existing_claim["project_name"]) == normalized_project_name
                    and not bool(existing_claim["claimed"])
                ):
                    if observation_snapshot_id is None:
                        raise BrokerError(
                            "compose_project_name_reacquire_unverified",
                            "Re-enabling a released Compose project name requires a fresh full-Docker collision observation.",
                        )
                    _require_observed_compose_project_name_available(
                        connection,
                        snapshot_id=observation_snapshot_id,
                        repo_id=repo_id,
                        project_name=normalized_project_name,
                    )
                if (
                    existing is not None
                    and str(existing["project_name"]) != normalized_project_name
                ):
                    if observation_snapshot_id is None:
                        raise BrokerError(
                            "compose_project_name_change_unverified",
                            "Changing a Compose project name requires a fresh full-Docker observation proving the old project has no retained resources.",
                        )
                    _require_observed_compose_project_name_absent(
                        connection,
                        snapshot_id=observation_snapshot_id,
                        project_name=str(existing["project_name"]),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_project_claim_history(
                            release_id, compose_definition_id, project_name,
                            release_reason, release_snapshot_id, actor_uid,
                            released_at
                        ) VALUES (?, ?, ?, 'rename', ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            compose_definition_id,
                            str(existing["project_name"]),
                            observation_snapshot_id,
                            _service_administrator_uid(),
                            now,
                        ),
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
                        "compose_project_name_conflict",
                        "Compose project name conflicts with another enabled definition.",
                    ) from exc
                preserve_release = bool(
                    existing_claim is not None
                    and str(existing_claim["project_name"]) == normalized_project_name
                    and not bool(existing_claim["claimed"])
                    and not enabled
                )
                connection.execute(
                    """
                    INSERT INTO broker_compose_project_claims(
                        compose_definition_id, project_name, claimed,
                        release_snapshot_id, released_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(compose_definition_id) DO UPDATE SET
                        project_name = excluded.project_name,
                        claimed = excluded.claimed,
                        release_snapshot_id = excluded.release_snapshot_id,
                        released_at = excluded.released_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        compose_definition_id,
                        normalized_project_name,
                        0 if preserve_release else 1,
                        (
                            str(existing_claim["release_snapshot_id"])
                            if preserve_release
                            else None
                        ),
                        (
                            str(existing_claim["released_at"])
                            if preserve_release
                            else None
                        ),
                        now,
                    ),
                )
                if effective_evidence is None:
                    connection.execute(
                        "DELETE FROM broker_compose_effective_model_evidence "
                        "WHERE compose_definition_id = ?",
                        (compose_definition_id,),
                    )
                else:
                    approved = bool(
                        effective_evidence.host_access_risks and host_access_approved
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_effective_model_evidence(
                            compose_definition_id, definition_fingerprint,
                            model_sha256, services_json, service_replicas_json,
                            profiles_json,
                            host_access_risks_json, host_access_approved,
                            approved_by_uid, approved_at, replica_budget,
                            validated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(compose_definition_id) DO UPDATE SET
                            definition_fingerprint = excluded.definition_fingerprint,
                            model_sha256 = excluded.model_sha256,
                            services_json = excluded.services_json,
                            service_replicas_json = excluded.service_replicas_json,
                            profiles_json = excluded.profiles_json,
                            host_access_risks_json = excluded.host_access_risks_json,
                            host_access_approved = excluded.host_access_approved,
                            approved_by_uid = excluded.approved_by_uid,
                            approved_at = excluded.approved_at,
                            replica_budget = excluded.replica_budget,
                            validated_at = excluded.validated_at
                        """,
                        (
                            compose_definition_id,
                            definition_fingerprint,
                            effective_evidence.model_sha256,
                            json.dumps(list(effective_evidence.services)),
                            json.dumps(dict(effective_evidence.service_replicas)),
                            json.dumps(list(effective_evidence.profiles)),
                            json.dumps(list(effective_evidence.host_access_risks)),
                            int(approved),
                            _service_administrator_uid() if approved else None,
                            now if approved else None,
                            effective_evidence.replica_budget,
                            now,
                        ),
                    )
                connection.execute(
                    "DELETE FROM broker_compose_files WHERE compose_definition_id = ?",
                    (compose_definition_id,),
                )
                connection.execute(
                    """
                    INSERT INTO broker_compose_directory_identity(
                        compose_definition_id, root_device, root_inode,
                        cwd_device, cwd_inode, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(compose_definition_id) DO UPDATE SET
                        root_device = excluded.root_device,
                        root_inode = excluded.root_inode,
                        cwd_device = excluded.cwd_device,
                        cwd_inode = excluded.cwd_inode,
                        updated_at = excluded.updated_at
                    """,
                    (
                        compose_definition_id,
                        root_identity.device,
                        root_identity.inode,
                        cwd_identity.device,
                        cwd_identity.inode,
                        now,
                    ),
                )
                connection.execute(
                    "DELETE FROM broker_compose_env_files WHERE compose_definition_id = ?",
                    (compose_definition_id,),
                )
                connection.execute(
                    "DELETE FROM broker_compose_profiles WHERE compose_definition_id = ?",
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
                    INSERT INTO broker_compose_env_files(
                        compose_definition_id, ordinal, file_path
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (compose_definition_id, ordinal, file_path)
                        for ordinal, file_path in enumerate(canonical_env_files)
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_env_file_evidence(
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
                        for ordinal, evidence in enumerate(env_file_evidence)
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_profiles(
                        compose_definition_id, ordinal, profile_name
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (compose_definition_id, ordinal, profile_name)
                        for ordinal, profile_name in enumerate(normalized_profiles)
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

    def enrolled_compose_definition_id(self, *, repo_id: str) -> str | None:
        """Return the sole definition managed by repository enrollment."""

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT compose_definition_id, enabled
                        FROM broker_compose_definitions
                        WHERE repo_id = ?
                        ORDER BY enabled DESC, updated_at DESC,
                                 compose_definition_id
                        """,
                        (repo_id,),
                    )
                )
        enabled = [row for row in rows if bool(row["enabled"])]
        if len(enabled) > 1 or (not enabled and len(rows) > 1):
            raise BrokerError(
                "compose_definition_conflict",
                "Repository enrollment found multiple Compose definitions; reconcile them explicitly before reenrollment.",
            )
        selected = enabled[0] if enabled else (rows[0] if rows else None)
        return None if selected is None else str(selected["compose_definition_id"])

    def replace_compose_access(
        self,
        *,
        uid: int,
        repo_id: str,
        compose_definition_id: str,
    ) -> None:
        """Atomically replace one client's Compose authority for a repository."""

        _require_identifier(repo_id, "project_id")
        _require_identifier(compose_definition_id, "compose_definition_id")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                definition = connection.execute(
                    """
                    SELECT enabled FROM broker_compose_definitions
                    WHERE compose_definition_id = ? AND repo_id = ?
                    """,
                    (compose_definition_id, repo_id),
                ).fetchone()
                if definition is None or not bool(definition["enabled"]):
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Replacement Compose definition is not enabled for this repository.",
                    )
                connection.execute(
                    """
                    UPDATE broker_compose_acl
                    SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ?
                      AND compose_definition_id != ?
                    """,
                    (now, uid, repo_id, compose_definition_id),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_compose_acl(
                        uid, repo_id, compose_definition_id, operation,
                        enabled, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(
                        uid, repo_id, compose_definition_id, operation
                    ) DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                    """,
                    (
                        (
                            uid,
                            repo_id,
                            compose_definition_id,
                            operation.value,
                            now,
                        )
                        for operation in (
                            BrokerOperation.COMPOSE_UP,
                            BrokerOperation.COMPOSE_STOP,
                            BrokerOperation.COMPOSE_RESTART,
                            BrokerOperation.COMPOSE_DOWN,
                        )
                    ),
                )

    def disable_repository_compose(self, *, repo_id: str) -> None:
        """Disable execution while deliberately retaining every name claim."""

        _require_identifier(repo_id, "project_id")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                definition_ids = tuple(
                    str(row["compose_definition_id"])
                    for row in connection.execute(
                        """
                        SELECT compose_definition_id
                        FROM broker_compose_definitions
                        WHERE repo_id = ?
                        ORDER BY compose_definition_id
                        """,
                        (repo_id,),
                    )
                )
                _require_no_unresolved_compose_definition_change(
                    connection,
                    compose_definition_ids=definition_ids,
                )
                connection.execute(
                    """
                    UPDATE broker_compose_definitions
                    SET enabled = 0, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (now, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_compose_acl
                    SET enabled = 0, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (now, repo_id),
                )

    def compose_project_name_release_candidate(
        self, *, compose_definition_id: str
    ) -> dict[str, Any]:
        """Return the exact disabled claim and host needed for fresh release."""

        _require_identifier(compose_definition_id, "compose_definition_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT definition.compose_definition_id,
                           definition.repo_id, definition.project_name,
                           definition.enabled, repository.host_id,
                           claim.claimed
                    FROM broker_compose_definitions definition
                    JOIN repositories repository USING(repo_id)
                    JOIN broker_compose_project_claims claim
                      USING(compose_definition_id)
                    WHERE definition.compose_definition_id = ?
                    """,
                    (compose_definition_id,),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "compose_definition_invalid",
                "Compose definition has no durable project-name claim.",
            )
        return {
            "compose_definition_id": str(row["compose_definition_id"]),
            "repo_id": str(row["repo_id"]),
            "host_id": str(row["host_id"]),
            "project_name": str(row["project_name"]),
            "enabled": bool(row["enabled"]),
            "claimed": bool(row["claimed"]),
        }

    def release_compose_project_name(
        self,
        *,
        compose_definition_id: str,
        observation_evidence: Mapping[str, Any],
        actor_uid: int,
    ) -> dict[str, Any]:
        """Release one disabled name only after exhaustive empty-host proof."""

        _require_identifier(compose_definition_id, "compose_definition_id")
        if (
            type(actor_uid) is not int
            or actor_uid != 0
            or _service_administrator_uid() != 0
        ):
            raise PermissionError(
                "Compose project-name release requires the root service administrator"
            )
        if not isinstance(observation_evidence, Mapping):
            raise TypeError(
                "Compose project-name release requires exact observation evidence"
            )
        observation_snapshot_id = observation_evidence.get("snapshot_id")
        if not isinstance(observation_snapshot_id, str):
            raise ValueError(
                "Compose project-name release evidence lacks a snapshot ID"
            )
        _require_identifier(observation_snapshot_id, "observation_snapshot_id")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                definition = connection.execute(
                    """
                    SELECT definition.repo_id, definition.project_name,
                           definition.enabled, repository.host_id,
                           claim.claimed
                    FROM broker_compose_definitions definition
                    JOIN repositories repository USING(repo_id)
                    JOIN broker_compose_project_claims claim
                      USING(compose_definition_id)
                    WHERE definition.compose_definition_id = ?
                    """,
                    (compose_definition_id,),
                ).fetchone()
                if definition is None:
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Compose definition has no durable project-name claim.",
                    )
                if bool(definition["enabled"]):
                    raise BrokerError(
                        "compose_project_name_release_active",
                        "Disable the Compose definition before releasing its project name.",
                    )
                if not bool(definition["claimed"]):
                    raise BrokerError(
                        "compose_project_name_already_released",
                        "Compose project name was already released.",
                    )
                same_name_definition_ids = tuple(
                    str(row["compose_definition_id"])
                    for row in connection.execute(
                        """
                        SELECT candidate.compose_definition_id
                        FROM broker_compose_definitions candidate
                        JOIN repositories repository USING(repo_id)
                        WHERE repository.host_id = ?
                          AND candidate.project_name = ?
                        ORDER BY candidate.compose_definition_id
                        """,
                        (definition["host_id"], definition["project_name"]),
                    )
                )
                _require_no_unresolved_compose_definition_change(
                    connection,
                    compose_definition_ids=same_name_definition_ids,
                )
                _require_exact_full_docker_snapshot(
                    connection,
                    snapshot_id=observation_snapshot_id,
                    host_id=str(definition["host_id"]),
                    expected_evidence=observation_evidence,
                    operation_id=None,
                )
                _require_observed_compose_project_name_absent(
                    connection,
                    snapshot_id=observation_snapshot_id,
                    project_name=str(definition["project_name"]),
                )
                updated = connection.execute(
                    """
                    UPDATE broker_compose_project_claims
                    SET claimed = 0, release_snapshot_id = ?, released_at = ?,
                        updated_at = ?
                    WHERE compose_definition_id = ? AND claimed = 1
                    """,
                    (
                        observation_snapshot_id,
                        now,
                        now,
                        compose_definition_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise BrokerError(
                        "compose_project_name_release_conflict",
                        "Compose project-name claim changed during release.",
                    )
                connection.execute(
                    """
                    UPDATE broker_compose_acl
                    SET enabled = 0, updated_at = ?
                    WHERE compose_definition_id = ? AND enabled = 1
                    """,
                    (now, compose_definition_id),
                )
                connection.execute(
                    """
                    INSERT INTO broker_compose_project_claim_history(
                        release_id, compose_definition_id, project_name,
                        release_reason, release_snapshot_id, actor_uid,
                        released_at
                    ) VALUES (?, ?, ?, 'explicit', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        compose_definition_id,
                        str(definition["project_name"]),
                        observation_snapshot_id,
                        actor_uid,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, source_id, operation_id,
                        event_kind, code, message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, NULL, NULL, 'compose.project_name_released',
                              'compose_project_name_released', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        str(definition["repo_id"]),
                        "Disabled Compose project name was released after exhaustive empty-host observation.",
                        json.dumps(
                            {
                                "compose_definition_id": compose_definition_id,
                                "project_name": str(definition["project_name"]),
                                "snapshot_id": observation_snapshot_id,
                                "actor_uid": actor_uid,
                            },
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )
        return {
            "compose_definition_id": compose_definition_id,
            "project_name": str(definition["project_name"]),
            "claimed": False,
            "release_snapshot_id": observation_snapshot_id,
            "released_at": now,
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
                        SELECT definition.compose_definition_id,
                               definition.repo_id, definition.cwd,
                               definition.project_name,
                               definition.definition_fingerprint,
                               definition.enabled, definition.generation,
                               definition.created_at, definition.updated_at,
                               identity.root_device, identity.root_inode,
                               identity.cwd_device, identity.cwd_inode,
                               claim.claimed, claim.release_snapshot_id,
                               claim.released_at
                        FROM broker_compose_definitions definition
                        LEFT JOIN broker_compose_directory_identity identity
                          USING(compose_definition_id)
                        LEFT JOIN broker_compose_project_claims claim
                          USING(compose_definition_id)
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
                    env_files = [
                        str(item["file_path"])
                        for item in connection.execute(
                            """
                            SELECT file_path FROM broker_compose_env_files
                            WHERE compose_definition_id = ? ORDER BY ordinal
                            """,
                            (definition_id,),
                        )
                    ]
                    env_file_evidence = [
                        {
                            "content_sha256": str(item["content_sha256"]),
                            "byte_size": int(item["byte_size"]),
                        }
                        for item in connection.execute(
                            """
                            SELECT content_sha256, byte_size
                            FROM broker_compose_env_file_evidence
                            WHERE compose_definition_id = ? ORDER BY ordinal
                            """,
                            (definition_id,),
                        )
                    ]
                    profiles = [
                        str(item["profile_name"])
                        for item in connection.execute(
                            """
                            SELECT profile_name FROM broker_compose_profiles
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
                            "env_files": env_files,
                            "env_file_evidence": env_file_evidence,
                            "profiles": profiles,
                            "services": services,
                            "project_name": str(row["project_name"]),
                            "definition_fingerprint": str(
                                row["definition_fingerprint"]
                            ),
                            "directory_identity": (
                                None
                                if row["root_device"] is None
                                else {
                                    "root_device": int(row["root_device"]),
                                    "root_inode": int(row["root_inode"]),
                                    "cwd_device": int(row["cwd_device"]),
                                    "cwd_inode": int(row["cwd_inode"]),
                                }
                            ),
                            "project_name_claimed": bool(row["claimed"]),
                            "project_name_release_snapshot_id": (
                                None
                                if row["release_snapshot_id"] is None
                                else str(row["release_snapshot_id"])
                            ),
                            "project_name_released_at": (
                                None
                                if row["released_at"] is None
                                else str(row["released_at"])
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
        elif operation in _COMPOSE_OPERATIONS:
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

                elif operation in _COMPOSE_OPERATIONS:
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

    def grant_runtime(
        self,
        *,
        uid: int,
        repo_id: str,
        resource_kind: str,
        resource_id: str,
        action: str,
        enabled: bool = True,
    ) -> None:
        """Grant one live-revalidated ID-only runtime action."""

        _require_identifier(repo_id, "project_id")
        _require_identifier(resource_id, "resource_id")
        if resource_kind not in {"service", "docker", "database_stack"}:
            raise ValueError(
                "runtime resource_kind must be service, docker, or database_stack"
            )
        if action not in {"status", "start", "stop", "restart", "replace"}:
            raise ValueError(
                "runtime action must be status, start, stop, restart, or replace"
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                _require_runtime_resource_membership(
                    connection,
                    repo_id=repo_id,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                )
                connection.execute(
                    """
                    INSERT INTO broker_runtime_acl(
                        uid, repo_id, resource_kind, resource_id,
                        action, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, resource_kind, resource_id, action)
                    DO UPDATE SET enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        resource_kind,
                        resource_id,
                        action,
                        int(enabled),
                        utc_timestamp(),
                    ),
                )

    def grant_worker(
        self,
        *,
        uid: int,
        repo_id: str,
        server_definition_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        """Grant one exact runner-to-broker worker protocol operation."""

        _require_identifier(repo_id, "project_id")
        _require_identifier(server_definition_id, "server_definition_id")
        if operation not in _WORKER_OPERATIONS:
            raise ValueError("operation is not a worker broker operation")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                _require_resource_membership(
                    connection,
                    repo_id=repo_id,
                    resource_kind="server",
                    resource_id=server_definition_id,
                )
                connection.execute(
                    """
                    INSERT INTO broker_worker_acl(
                        uid, repo_id, server_definition_id,
                        operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, server_definition_id, operation)
                    DO UPDATE SET enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (
                        uid,
                        repo_id,
                        server_definition_id,
                        operation.value,
                        int(enabled),
                        utc_timestamp(),
                    ),
                )

    def revoke_server_for_permanent_cleanup(
        self,
        *,
        repo_id: str,
        server_definition_id: str,
        cleanup_operation_id: str,
        immutable_fingerprint: str,
        actor: str,
    ) -> dict[str, Any]:
        """Fence one exact server incarnation before permanent cleanup.

        The cleanup plan remains independently confirmation- and
        observation-bound.  This method proves the supplied target against
        that durable plan, then disables every operational and runner grant
        before native unregister/host mutation can begin.  The retained fence
        prevents reenrollment code from reviving the old immutable ID.
        """

        for value, label in (
            (repo_id, "project_id"),
            (server_definition_id, "server_definition_id"),
            (cleanup_operation_id, "cleanup_operation_id"),
        ):
            _require_identifier(value, label)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", immutable_fingerprint):
            raise ValueError("immutable_fingerprint must be a sha256 fingerprint")
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 512:
            raise ValueError("actor must be a bounded non-empty string")
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                plan = connection.execute(
                    """
                    SELECT repo_id, target_kind, target_id, action,
                           target_fingerprint, status
                    FROM cleanup_plans WHERE plan_id = ?
                    """,
                    (cleanup_operation_id,),
                ).fetchone()
                if plan is None or (
                    str(plan["repo_id"] or "") != repo_id
                    or str(plan["target_kind"]) != "server"
                    or str(plan["target_id"]) != server_definition_id
                    or str(plan["action"]) != "purge"
                    or str(plan["target_fingerprint"]) != immutable_fingerprint
                    or str(plan["status"])
                    not in {"planned", "running", "needs_attention", "succeeded"}
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent worker revocation does not match the exact durable cleanup plan.",
                        operation_id=cleanup_operation_id,
                    )
                definition = connection.execute(
                    """
                    SELECT name FROM server_definitions
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (repo_id, server_definition_id),
                ).fetchone()
                existing = connection.execute(
                    """
                    SELECT * FROM broker_server_revocations
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (repo_id, server_definition_id),
                ).fetchone()
                if definition is None and existing is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Permanent worker revocation targets no current or already-revoked exact definition.",
                        operation_id=cleanup_operation_id,
                    )
                server_name = (
                    str(definition["name"])
                    if definition is not None
                    else str(existing["server_name"])
                )
                if existing is not None and (
                    str(existing["server_name"]) != server_name
                    or str(existing["cleanup_operation_id"])
                    != cleanup_operation_id
                    or str(existing["immutable_fingerprint"])
                    != immutable_fingerprint
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent worker revocation conflicts with retained exact-ID evidence.",
                        operation_id=cleanup_operation_id,
                    )
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO broker_server_revocations(
                            repo_id, server_definition_id, server_name,
                            cleanup_operation_id, immutable_fingerprint,
                            actor, revoked_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            repo_id,
                            server_definition_id,
                            server_name,
                            cleanup_operation_id,
                            immutable_fingerprint,
                            actor.strip(),
                            timestamp,
                        ),
                    )
                disabled: dict[str, int] = {}
                for table, predicate, parameters in (
                    (
                        "broker_resource_acl",
                        "repo_id = ? AND resource_kind = 'server' AND resource_id = ?",
                        (repo_id, server_definition_id),
                    ),
                    (
                        "broker_runtime_acl",
                        "repo_id = ? AND resource_kind = 'service' AND resource_id = ?",
                        (repo_id, server_definition_id),
                    ),
                    (
                        "broker_worker_acl",
                        "repo_id = ? AND server_definition_id = ? "
                        "AND operation IN ('worker.launch_ticket', 'worker.policy_read')",
                        (repo_id, server_definition_id),
                    ),
                    (
                        "broker_assignment_acl",
                        "repo_id = ? AND server_definition_id = ?",
                        (repo_id, server_definition_id),
                    ),
                    (
                        "broker_port_policies",
                        "repo_id = ? AND server_definition_id = ?",
                        (repo_id, server_definition_id),
                    ),
                ):
                    disabled[table] = connection.execute(
                        f"UPDATE {table} SET enabled = 0, updated_at = ? "
                        f"WHERE {predicate} AND enabled = 1",
                        (timestamp, *parameters),
                    ).rowcount
        return {
            "status": "revoked",
            "repo_id": repo_id,
            "server_definition_id": server_definition_id,
            "server_name": server_name,
            "cleanup_operation_id": cleanup_operation_id,
            "immutable_fingerprint": immutable_fingerprint,
            "already_revoked": existing is not None,
            "disabled_grants": disabled,
            "profile_update_required": True,
        }

    def revoke_repository_for_permanent_cleanup(
        self,
        *,
        repo_id: str,
        repository_generation: int,
        cleanup_operation_id: str,
        immutable_fingerprint: str,
        actor: str,
    ) -> dict[str, Any]:
        """Fence one exact repository generation before project removal."""

        for value, label in (
            (repo_id, "project_id"),
            (cleanup_operation_id, "cleanup_operation_id"),
        ):
            _require_identifier(value, label)
        if type(repository_generation) is not int or repository_generation < 0:
            raise ValueError("repository_generation must be a non-negative integer")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", immutable_fingerprint):
            raise ValueError("immutable_fingerprint must be a sha256 fingerprint")
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 512:
            raise ValueError("actor must be a bounded non-empty string")

        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                plan = connection.execute(
                    """
                    SELECT repo_id, target_kind, target_id, action,
                           target_fingerprint, snapshot_json, status
                    FROM cleanup_plans WHERE plan_id = ?
                    """,
                    (cleanup_operation_id,),
                ).fetchone()
                if plan is None:
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent project revocation has no durable cleanup plan.",
                        operation_id=cleanup_operation_id,
                    )
                try:
                    snapshot = json.loads(str(plan["snapshot_json"]))
                    identity = snapshot["identity"]
                    planned_generation = identity["generation"]
                    planned_root = identity["canonical_root"]
                except (json.JSONDecodeError, KeyError, TypeError) as error:
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent project revocation has invalid durable identity evidence.",
                        operation_id=cleanup_operation_id,
                    ) from error
                if (
                    not isinstance(snapshot, dict)
                    or not isinstance(identity, dict)
                    or type(planned_generation) is not int
                    or planned_generation != repository_generation
                    or not isinstance(planned_root, str)
                    or not planned_root
                    or str(plan["repo_id"] or "") != repo_id
                    or str(plan["target_kind"]) != "project"
                    or str(plan["target_id"]) != repo_id
                    or str(plan["action"]) != "forget"
                    or str(plan["target_fingerprint"]) != immutable_fingerprint
                    or str(plan["status"])
                    not in {"planned", "running", "needs_attention", "succeeded"}
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent project revocation does not match the exact durable cleanup plan.",
                        operation_id=cleanup_operation_id,
                    )

                repository = connection.execute(
                    """
                    SELECT canonical_root, state, generation
                    FROM repositories WHERE repo_id = ?
                    """,
                    (repo_id,),
                ).fetchone()
                existing = connection.execute(
                    """
                    SELECT * FROM broker_repository_revocations
                    WHERE repo_id = ? AND repository_generation = ?
                    """,
                    (repo_id, repository_generation),
                ).fetchone()
                if repository is None and existing is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Permanent project revocation targets no current or retained exact repository generation.",
                        operation_id=cleanup_operation_id,
                    )
                canonical_root = (
                    str(repository["canonical_root"])
                    if repository is not None
                    else str(existing["canonical_root"])
                )
                if (
                    canonical_root != planned_root
                    or (
                        repository is not None
                        and int(repository["generation"]) != repository_generation
                    )
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Repository generation changed before permanent revocation.",
                        operation_id=cleanup_operation_id,
                    )
                if existing is not None and (
                    str(existing["cleanup_operation_id"]) != cleanup_operation_id
                    or str(existing["immutable_fingerprint"])
                    != immutable_fingerprint
                    or str(existing["canonical_root"]) != canonical_root
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Permanent project revocation conflicts with retained generation evidence.",
                        operation_id=cleanup_operation_id,
                    )
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO broker_repository_revocations(
                            repo_id, repository_generation,
                            cleanup_operation_id, immutable_fingerprint,
                            canonical_root, actor, revoked_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            repo_id,
                            repository_generation,
                            cleanup_operation_id,
                            immutable_fingerprint,
                            canonical_root,
                            actor.strip(),
                            timestamp,
                        ),
                    )

                server_revocations: list[dict[str, Any]] = []
                for definition in connection.execute(
                    """
                    SELECT server_definition_id, name, definition_fingerprint
                    FROM server_definitions WHERE repo_id = ?
                    ORDER BY name, server_definition_id
                    """,
                    (repo_id,),
                ):
                    server_id = str(definition["server_definition_id"])
                    server_name = str(definition["name"])
                    server_fingerprint = str(definition["definition_fingerprint"])
                    retained = connection.execute(
                        """
                        SELECT server_name, cleanup_operation_id,
                               immutable_fingerprint
                        FROM broker_server_revocations
                        WHERE repo_id = ? AND server_definition_id = ?
                        """,
                        (repo_id, server_id),
                    ).fetchone()
                    if retained is not None and (
                        str(retained["server_name"]) != server_name
                        or str(retained["cleanup_operation_id"])
                        != cleanup_operation_id
                        or str(retained["immutable_fingerprint"])
                        != server_fingerprint
                    ):
                        raise BrokerError(
                            "cleanup_plan_drift",
                            "Project removal conflicts with retained exact server evidence.",
                            operation_id=cleanup_operation_id,
                        )
                    if retained is None:
                        connection.execute(
                            """
                            INSERT INTO broker_server_revocations(
                                repo_id, server_definition_id, server_name,
                                cleanup_operation_id, immutable_fingerprint,
                                actor, revoked_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                repo_id,
                                server_id,
                                server_name,
                                cleanup_operation_id,
                                server_fingerprint,
                                actor.strip(),
                                timestamp,
                            ),
                        )
                    server_revocations.append(
                        {
                            "server_definition_id": server_id,
                            "server_name": server_name,
                            "immutable_fingerprint": server_fingerprint,
                            "already_revoked": retained is not None,
                        }
                    )

                disabled: dict[str, int] = {}
                for table in (
                    "broker_resource_acl",
                    "broker_runtime_acl",
                    "broker_worker_acl",
                    "broker_assignment_acl",
                    "broker_port_policies",
                    "broker_compose_acl",
                    "broker_lifecycle_acl",
                    "broker_lifecycle_resource_acl",
                    "broker_repository_read_acl",
                    "broker_host_observation_acl",
                    "broker_cleanup_acl",
                    "broker_cleanup_resource_acl",
                    "broker_database_acl",
                ):
                    disabled[table] = connection.execute(
                        f"UPDATE {table} SET enabled = 0, updated_at = ? "
                        "WHERE repo_id = ? AND enabled = 1",
                        (timestamp, repo_id),
                    ).rowcount
                disabled["broker_repository_enrollments"] = connection.execute(
                    """
                    UPDATE broker_repository_enrollments
                    SET enabled = 0, updated_at = ?
                    WHERE repo_id = ? AND enabled = 1
                    """,
                    (timestamp, repo_id),
                ).rowcount
                disabled["broker_compose_definitions"] = connection.execute(
                    """
                    UPDATE broker_compose_definitions
                    SET enabled = 0, generation = generation + 1, updated_at = ?
                    WHERE repo_id = ? AND enabled = 1
                    """,
                    (timestamp, repo_id),
                ).rowcount
        return {
            "status": "revoked",
            "repo_id": repo_id,
            "repository_generation": repository_generation,
            "canonical_root": canonical_root,
            "cleanup_operation_id": cleanup_operation_id,
            "immutable_fingerprint": immutable_fingerprint,
            "already_revoked": existing is not None,
            "server_revocations": server_revocations,
            "disabled_grants": disabled,
            "profile_update_required": True,
        }

    def remove_revoked_repository_server_definitions(
        self,
        *,
        repo_id: str,
        repository_generation: int,
        cleanup_operation_id: str,
    ) -> dict[str, Any]:
        """Remove fenced server projections after native workers are gone."""

        for value, label in (
            (repo_id, "project_id"),
            (cleanup_operation_id, "cleanup_operation_id"),
        ):
            _require_identifier(value, label)
        if type(repository_generation) is not int or repository_generation < 0:
            raise ValueError("repository_generation must be a non-negative integer")
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                repository_revocation = connection.execute(
                    """
                    SELECT cleanup_operation_id
                    FROM broker_repository_revocations
                    WHERE repo_id = ? AND repository_generation = ?
                    """,
                    (repo_id, repository_generation),
                ).fetchone()
                if (
                    repository_revocation is None
                    or str(repository_revocation["cleanup_operation_id"])
                    != cleanup_operation_id
                ):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Server projection removal lacks the exact repository-generation fence.",
                        operation_id=cleanup_operation_id,
                    )
                definitions = tuple(
                    connection.execute(
                        """
                        SELECT definition.server_definition_id, definition.name
                        FROM server_definitions definition
                        JOIN broker_server_revocations revocation
                          ON revocation.repo_id = definition.repo_id
                         AND revocation.server_definition_id =
                             definition.server_definition_id
                         AND revocation.cleanup_operation_id = ?
                        WHERE definition.repo_id = ?
                        ORDER BY definition.name,
                                 definition.server_definition_id
                        """,
                        (cleanup_operation_id, repo_id),
                    )
                )
                server_ids = tuple(
                    str(row["server_definition_id"]) for row in definitions
                )
                if not server_ids:
                    return {
                        "status": "already_removed",
                        "repo_id": repo_id,
                        "repository_generation": repository_generation,
                        "cleanup_operation_id": cleanup_operation_id,
                        "removed_server_definition_ids": [],
                    }
                placeholders = ",".join("?" for _ in server_ids)
                unresolved = connection.execute(
                    f"""
                    SELECT 'lease' AS source, status
                    FROM broker_lease_links
                    WHERE repo_id = ?
                      AND server_definition_id IN ({placeholders})
                      AND status != 'released'
                    UNION ALL
                    SELECT 'assignment' AS source, status
                    FROM broker_assignment_links
                    WHERE repo_id = ?
                      AND server_definition_id IN ({placeholders})
                      AND status != 'released'
                    UNION ALL
                    SELECT 'lease' AS source, status FROM leases
                    WHERE repo_id = ?
                      AND server_definition_id IN ({placeholders})
                      AND status = 'active'
                    LIMIT 1
                    """,
                    (
                        repo_id,
                        *server_ids,
                        repo_id,
                        *server_ids,
                        repo_id,
                        *server_ids,
                    ),
                ).fetchone()
                if unresolved is not None:
                    raise BrokerError(
                        "cleanup_blocked",
                        "Revoked project still has unresolved exact server "
                        f"{unresolved['source']} evidence ({unresolved['status']}).",
                        operation_id=cleanup_operation_id,
                    )
                connection.execute(
                    f"DELETE FROM broker_lease_links WHERE repo_id = ? "
                    f"AND server_definition_id IN ({placeholders})",
                    (repo_id, *server_ids),
                )
                connection.execute(
                    f"DELETE FROM broker_assignment_links WHERE repo_id = ? "
                    f"AND server_definition_id IN ({placeholders})",
                    (repo_id, *server_ids),
                )
                connection.execute(
                    f"DELETE FROM leases WHERE repo_id = ? "
                    f"AND server_definition_id IN ({placeholders}) "
                    "AND status IN ('released', 'stale')",
                    (repo_id, *server_ids),
                )
                for name in (str(row["name"]) for row in definitions):
                    connection.execute(
                        """
                        DELETE FROM port_assignments
                        WHERE repo_id = ? AND server_name = ?
                          AND status = 'inactive'
                        """,
                        (repo_id, name),
                    )
                connection.execute(
                    f"DELETE FROM repository_memberships WHERE repo_id = ? "
                    f"AND resource_kind = 'server' "
                    f"AND host_resource_id IN ({placeholders})",
                    (repo_id, *server_ids),
                )
                connection.execute(
                    f"DELETE FROM unassigned_resources "
                    f"WHERE resource_kind = 'server' "
                    f"AND resource_id IN ({placeholders})",
                    server_ids,
                )
                connection.execute(
                    f"DELETE FROM startup_policies "
                    f"WHERE resource_kind = 'server' "
                    f"AND resource_id IN ({placeholders})",
                    server_ids,
                )
                connection.execute(
                    f"""
                    UPDATE control_bindings
                    SET authority_state = 'retired',
                        generation = generation + 1, updated_at = ?
                    WHERE resource_kind = 'server'
                      AND resource_id IN ({placeholders})
                    """,
                    (timestamp, *server_ids),
                )
                deleted = connection.execute(
                    f"DELETE FROM server_definitions WHERE repo_id = ? "
                    f"AND server_definition_id IN ({placeholders})",
                    (repo_id, *server_ids),
                ).rowcount
                if deleted != len(server_ids):
                    raise BrokerError(
                        "cleanup_plan_drift",
                        "Revoked project server projections changed before deletion.",
                        operation_id=cleanup_operation_id,
                    )
        return {
            "status": "removed",
            "repo_id": repo_id,
            "repository_generation": repository_generation,
            "cleanup_operation_id": cleanup_operation_id,
            "removed_server_definition_ids": list(server_ids),
        }

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
                revoked = {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT server_definition_id
                        FROM broker_server_revocations
                        WHERE repo_id = ?
                        """,
                        (repo_id,),
                    )
                }
                if revoked.intersection(selected):
                    raise BrokerError(
                        "resource_permanently_removed",
                        "Server access replacement cannot revive a permanently removed incarnation; explicitly reinstall it to obtain a new ID.",
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
                    UPDATE broker_runtime_acl SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ? AND resource_kind = 'service'
                    """,
                    (now, uid, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_worker_acl SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ?
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
                    for runtime_action in (
                        "status", "start", "stop", "restart", "replace"
                    ):
                        connection.execute(
                            """
                            INSERT INTO broker_runtime_acl(
                                uid, repo_id, resource_kind, resource_id,
                                action, enabled, updated_at
                            ) VALUES (?, ?, 'service', ?, ?, 1, ?)
                            ON CONFLICT(
                                uid, repo_id, resource_kind, resource_id, action
                            ) DO UPDATE SET enabled = 1,
                                            updated_at = excluded.updated_at
                            """,
                            (uid, repo_id, server_id, runtime_action, now),
                        )
                    for worker_operation in sorted(
                        _WORKER_OPERATIONS, key=lambda item: item.value
                    ):
                        connection.execute(
                            """
                            INSERT INTO broker_worker_acl(
                                uid, repo_id, server_definition_id,
                                operation, enabled, updated_at
                            ) VALUES (?, ?, ?, ?, 1, ?)
                            ON CONFLICT(
                                uid, repo_id, server_definition_id, operation
                            ) DO UPDATE SET enabled = 1,
                                            updated_at = excluded.updated_at
                            """,
                            (
                                uid,
                                repo_id,
                                server_id,
                                worker_operation.value,
                                now,
                            ),
                        )
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
                if (
                    connection.execute(
                        "SELECT 1 FROM repositories WHERE repo_id = ?",
                        (repo_id,),
                    ).fetchone()
                    is None
                ):
                    raise BrokerError(
                        "project_access_denied",
                        "Lifecycle repository is not provisioned.",
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
            raise ValueError(
                "operation is not a standalone-resource lifecycle operation"
            )
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
                if (
                    connection.execute(
                        "SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)
                    ).fetchone()
                    is None
                ):
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

    def grant_cleanup(
        self,
        *,
        uid: int,
        repo_id: str,
        operation: BrokerOperation,
        enabled: bool = True,
    ) -> None:
        allowed = {
            BrokerOperation.ARCHIVES_READ,
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.CLEANUP_APPLY,
            BrokerOperation.REPOSITORY_PLAN_REMOVE,
            BrokerOperation.REPOSITORY_REMOVE,
            BrokerOperation.REPOSITORY_REINSTALL,
            BrokerOperation.RESOURCE_PLAN_RETIRE,
            BrokerOperation.RESOURCE_RETIRE,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
            BrokerOperation.LIFECYCLE_RESTORE,
        }
        if operation not in allowed:
            raise ValueError("operation is not an explicit cleanup capability")
        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)
                ).fetchone() is None:
                    raise BrokerError(
                        "project_access_denied", "Cleanup repository is not provisioned."
                    )
                connection.execute(
                    """
                    INSERT INTO broker_cleanup_acl(
                        uid, repo_id, operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id, operation) DO UPDATE SET
                        enabled = excluded.enabled,
                        updated_at = excluded.updated_at
                    """,
                    (uid, repo_id, operation.value, int(enabled), utc_timestamp()),
                )

    def grant_cleanup_resource(
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
        if operation not in {
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.CLEANUP_APPLY,
        }:
            raise ValueError("operation is not an exact resource cleanup capability")
        if resource_kind not in {"server", "container", "supervisor"}:
            raise ValueError("resource_kind is not a cleanup resource kind")
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
                        SELECT 1 FROM control_bindings b
                        JOIN coordinator_sources s ON s.source_id = b.source_id
                        LEFT JOIN repository_memberships m
                          ON m.control_binding_id = b.binding_id
                         AND m.resource_kind = b.resource_kind
                         AND m.host_resource_id = b.resource_id
                        WHERE b.binding_id = ? AND b.resource_kind = ?
                          AND b.resource_id = ? AND b.authority_state = 'authoritative'
                          AND (
                            (m.repo_id = ? AND s.effective_uid IN (0, ?))
                            OR (m.repo_id IS NULL AND s.effective_uid = ?)
                          )
                        """,
                        (
                            control_binding_id,
                            resource_kind,
                            resource_id,
                            repo_id,
                            uid,
                            uid,
                        ),
                    ).fetchone()
                else:
                    exact = connection.execute(
                        """
                        SELECT 1 FROM broker_cleanup_resource_acl
                        WHERE uid = ? AND repo_id = ? AND resource_kind = ?
                          AND resource_id = ? AND control_binding_id = ?
                          AND operation = ?
                        """,
                        (
                            uid,
                            repo_id,
                            resource_kind,
                            resource_id,
                            control_binding_id,
                            operation.value,
                        ),
                    ).fetchone()
                if exact is None:
                    raise BrokerError(
                        "resource_access_denied",
                        "Cleanup grant requires an exact authoritative resource.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_cleanup_resource_acl(
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

    def authorize_cleanup_resource(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        repo_id: str,
        resource_kind: str,
        resource_id: str,
        control_binding_id: str,
        immutable_fingerprint: str,
        ownership_fingerprint: str,
        operation: BrokerOperation,
    ) -> None:
        """Recheck one service-resolved exact cleanup/restore grant atomically."""

        if operation not in {
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.CLEANUP_APPLY,
            BrokerOperation.RESOURCE_RESTORE,
        }:
            raise ValueError("operation is not an exact resource cleanup capability")
        request = authorized.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                grant = connection.execute(
                    """
                    SELECT a.enabled
                    FROM broker_cleanup_resource_acl a
                    JOIN control_bindings b ON b.binding_id = a.control_binding_id
                    JOIN coordinator_sources s ON s.source_id = b.source_id
                    JOIN repository_memberships m
                      ON m.control_binding_id = b.binding_id
                     AND m.resource_kind = b.resource_kind
                     AND m.host_resource_id = b.resource_id
                    WHERE a.uid = ? AND a.repo_id = ?
                      AND a.resource_kind = ? AND a.resource_id = ?
                      AND a.control_binding_id = ?
                      AND a.immutable_fingerprint = ?
                      AND a.ownership_fingerprint = ?
                      AND a.operation = ? AND a.enabled = 1
                      AND b.resource_kind = a.resource_kind
                      AND b.resource_id = a.resource_id
                      AND b.authority_state = 'authoritative'
                      AND s.effective_uid IN (0, ?)
                      AND m.repo_id = a.repo_id
                    LIMIT 1
                    """,
                    (
                        authorized.peer.uid,
                        repo_id,
                        resource_kind,
                        resource_id,
                        control_binding_id,
                        immutable_fingerprint,
                        ownership_fingerprint,
                        operation.value,
                        authorized.peer.uid,
                    ),
                ).fetchone()
                if grant is None:
                    raise BrokerError(
                        "resource_access_denied",
                        "Cleanup or restore requires an explicit current exact resource grant.",
                        operation_id=request.operation_id,
                    )

    def grant_host_observation(
        self,
        *,
        uid: int,
        repo_id: str,
        enabled: bool = True,
    ) -> None:
        """Grant one enrolled OS principal authority to refresh host evidence."""

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)
                if connection.execute(
                    "SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)
                ).fetchone() is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Host observation target is not provisioned.",
                    )
                connection.execute(
                    """
                    INSERT INTO broker_host_observation_acl(
                        uid, repo_id, enabled, updated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(uid, repo_id)
                    DO UPDATE SET enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (uid, repo_id, int(enabled), utc_timestamp()),
                )

    def fail_owned_host_observations(self, *, broker_instance_id: str) -> int:
        """Durably terminate only running tickets claimed by one broker process."""

        _require_identifier(broker_instance_id, "broker_instance_id")
        completed_at = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction(max_seconds=5.0) as connection:
                owned = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT s.snapshot_id
                        FROM observation_snapshots s
                        JOIN broker_host_observation_owners o USING(snapshot_id)
                        WHERE o.broker_instance_id = ? AND s.status = 'running'
                        ORDER BY s.snapshot_id
                        """,
                        (broker_instance_id,),
                    )
                ]
                if owned:
                    placeholders = ",".join("?" for _ in owned)
                    connection.execute(
                        f"""
                        UPDATE observation_snapshots
                        SET status = 'failed', completed_at = ?,
                            error_code = 'observer_broker_shutdown',
                            error_message =
                                'the owning broker process shut down before observation completed'
                        WHERE status = 'running'
                          AND snapshot_id IN ({placeholders})
                        """,
                        (completed_at, *owned),
                    )
        return len(owned)

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
            "cancelled",
        }:
            return DurableOperationDisposition(
                "failed",
                error_code=existing["error_code"] or "mutation_failed",
                error_message=existing["error_message"] or "Broker mutation failed.",
            )
        if (
            existing["status"] == "needs_attention"
            and authorized.request.operation is BrokerOperation.RUNTIME_REQUEST
        ):
            return DurableOperationDisposition(
                "reconcile",
                error_code=existing["error_code"],
                error_message=existing["error_message"],
            )
        if existing["status"] == "needs_attention":
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
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        compose_preflight: Mapping[str, Any] | None = None,
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

                _authorize_connection(connection, peer=authorized.peer, request=request)
                compose_snapshot: sqlite3.Row | None = None
                runtime_target: tuple[str, str, str, str] | None = None
                if (
                    request.operation is BrokerOperation.RUNTIME_REQUEST
                    and request.arguments["action"] in {
                        "start", "stop", "restart", "replace"
                    }
                ):
                    if request.arguments["target_kind"] == "service":
                        runtime_target = (
                            "server",
                            request.resource_id,
                            "runtime." + str(request.arguments["action"]),
                            _server_definition_fingerprint(
                                connection,
                                repo_id=request.project_id,
                                server_definition_id=request.resource_id,
                                operation_id=request.operation_id,
                            ),
                        )
                    else:
                        runtime_target = _runtime_operation_target(
                            connection, request=request
                        )
                        _require_no_unresolved_container_operation(
                            connection,
                            docker_resource_id=runtime_target[1],
                            operation_id=request.operation_id,
                        )
                if request.operation in _DOCKER_OPERATIONS:
                    _require_no_unresolved_docker_operation(
                        connection,
                        request=request,
                    )
                if request.operation in _COMPOSE_OPERATIONS:
                    _require_no_unresolved_compose_operation(
                        connection,
                        request=request,
                    )
                    if not isinstance(compose_preflight, Mapping):
                        raise BrokerError(
                            "compose_observation_incomplete",
                            "Compose reservation requires bound fresh host evidence.",
                            operation_id=request.operation_id,
                        )
                    compose_snapshot = _require_compose_mutation_safe_connection(
                        connection,
                        request=request,
                        snapshot_id=str(compose_preflight.get("snapshot_id") or ""),
                        expected_evidence=compose_preflight,
                    )
                target_kind, target_id, target_action, target_fingerprint = (
                    runtime_target
                    if runtime_target is not None
                    else (
                        _target_kind(request.operation),
                        request.resource_id,
                        request.operation.value,
                        _reserved_target_fingerprint(
                            connection, request=request, fallback=fingerprint
                        ),
                    )
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
                            if request.operation
                            in (_LIFECYCLE_OPERATIONS | _CLEANUP_OPERATIONS)
                            else request.project_id
                        ),
                        "broker." + request.operation.value,
                        fingerprint,
                        authorized.peer.uid,
                        _operation_actor(authorized),
                        f"pid:{os.getpid()}",
                        now,
                        now,
                    ),
                )
                if compose_snapshot is not None:
                    connection.execute(
                        """
                        INSERT INTO broker_compose_operation_preflights(
                            operation_id, snapshot_id, material_fingerprint,
                            capability_fingerprint, committed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            request.operation_id,
                            str(compose_snapshot["snapshot_id"]),
                            str(compose_snapshot["material_fingerprint"]),
                            str(compose_snapshot["capability_fingerprint"]),
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
                        target_kind,
                        target_id,
                        target_action,
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                if (
                    requested_port is not None
                    and observed_available_port != requested_port
                ):
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
                    process_fingerprint = (
                        "sha256:"
                        + hashlib.sha256(
                            json.dumps(
                                dict(listener_evidence),
                                ensure_ascii=True,
                                allow_nan=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                    )
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                if lease is None or lease["status"] not in {"active", "released"}:
                    raise BrokerError(
                        "lease_not_active",
                        "The exact authorized lease is no longer active.",
                        operation_id=request.operation_id,
                    )
                if lease["status"] == "active":
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
                    else (
                        int(existing["generation"]) + 1 if existing is not None else 0
                    )
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                if (
                    expected is not None
                    and int(row["observation_revision"]) != expected
                ):
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

    def runtime_docker_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> RuntimeDockerMutationTarget:
        """Reauthorize and resolve a reserved runtime request to one container."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] not in {"start", "stop", "restart"}
            or request.arguments["target_kind"] not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed runtime mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = _runtime_mutation_row(connection, request=request)
                immutable_fingerprint = _runtime_target_fingerprint(
                    row, requested_resource_id=request.resource_id
                )
                reserved = connection.execute(
                    """
                    SELECT immutable_fingerprint
                    FROM operation_targets
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND target_id = ? AND action = ?
                    """,
                    (
                        request.operation_id,
                        row["docker_resource_id"],
                        "runtime." + str(request.arguments["action"]),
                    ),
                ).fetchone()
                if reserved is None:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Durable runtime operation lost its exact Docker reservation.",
                        operation_id=request.operation_id,
                    )
                if str(reserved["immutable_fingerprint"]) != immutable_fingerprint:
                    raise BrokerError(
                        "stale_resource_definition",
                        "Runtime target identity changed after reservation.",
                        operation_id=request.operation_id,
                    )
                return RuntimeDockerMutationTarget(
                    resource_kind=str(row["resource_kind"]),
                    resource_id=request.resource_id,
                    docker_resource_id=str(row["docker_resource_id"]),
                    full_container_id=str(row["full_container_id"]).lower(),
                    database_binding_id=(
                        None
                        if row["database_binding_id"] is None
                        else str(row["database_binding_id"])
                    ),
                    database_name=(
                        None
                        if row["database_name"] is None
                        else str(row["database_name"])
                    ),
                    observation_revision=int(row["observation_revision"]),
                    control_generation=int(row["control_generation"]),
                    immutable_fingerprint=immutable_fingerprint,
                )

    def database_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> DatabaseMutationTarget:
        request = authorized.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
        result_fingerprint = (
            "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        snapshot_id: str,
    ) -> list[dict[str, Any]]:
        """Project containers present in one exact completed Docker snapshot."""

        request = authorized.request
        if request.operation not in {
            BrokerOperation.COMPOSE_UP,
            BrokerOperation.COMPOSE_STOP,
            BrokerOperation.COMPOSE_RESTART,
            BrokerOperation.COMPOSE_DOWN,
        }:
            raise ValueError("request is not a Compose operation")
        if not snapshot_id:
            raise ValueError("Compose observation projection requires a snapshot ID")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                snapshot = connection.execute(
                    """
                    SELECT s.host_id
                    FROM observation_snapshots s
                    JOIN observation_capabilities c USING(snapshot_id)
                    WHERE s.snapshot_id = ? AND s.status = 'completed'
                      AND s.completed_at IS NOT NULL
                      AND s.observer_domain = 'host-runtime-v2:full-docker'
                      AND c.observer_domain = s.observer_domain
                      AND c.docker_available = 1
                    """,
                    (snapshot_id,),
                ).fetchone()
                if snapshot is None:
                    raise BrokerError(
                        "docker_observation_mismatch",
                        "Compose result does not reference a completed Docker-available service snapshot.",
                        operation_id=request.operation_id,
                    )
                return [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT d.docker_resource_id, d.full_container_id,
                               d.current_name, present.snapshot_id,
                               present.observation_fingerprint,
                               o.lifecycle AS current_lifecycle,
                               o.health AS current_health,
                               o.restart_policy AS current_restart_policy,
                               o.sampled_at AS current_sampled_at,
                               o.observation_fingerprint
                                   AS current_observation_fingerprint
                        FROM repository_memberships r
                        JOIN docker_resources d
                          ON d.docker_resource_id = r.host_resource_id
                        JOIN docker_engines e USING(engine_id)
                        JOIN control_bindings b ON b.binding_id = r.control_binding_id
                        JOIN docker_observations o USING(docker_resource_id)
                        JOIN observation_snapshot_resources present
                          ON present.snapshot_id = ?
                         AND present.resource_kind = 'container'
                         AND present.resource_id = d.docker_resource_id
                        WHERE r.repo_id = ? AND r.resource_kind = 'container'
                          AND b.authority_state = 'authoritative'
                          AND e.host_id = ?
                        ORDER BY d.current_name, d.full_container_id
                        """,
                        (snapshot_id, request.project_id, snapshot["host_id"]),
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                           claim.claimed,
                           r.canonical_root, r.generation AS repository_generation,
                           identity.root_device, identity.root_inode,
                           identity.cwd_device, identity.cwd_inode,
                           effective.definition_fingerprint AS effective_fingerprint,
                           effective.model_sha256,
                           effective.service_replicas_json,
                           effective.host_access_risks_json,
                           effective.host_access_approved
                    FROM broker_compose_definitions d
                    JOIN repositories r USING(repo_id)
                    JOIN broker_compose_project_claims claim
                      USING(compose_definition_id)
                    LEFT JOIN broker_compose_directory_identity identity
                      USING(compose_definition_id)
                    LEFT JOIN broker_compose_effective_model_evidence effective
                      USING(compose_definition_id)
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
                if (
                    request.operation in _COMPOSE_START_OPERATIONS
                    and not row["enabled"]
                ):
                    raise BrokerError(
                        "compose_definition_disabled",
                        "Compose definition is disabled; start-like mutation is unavailable.",
                        operation_id=request.operation_id,
                    )
                if not bool(row["claimed"]):
                    raise BrokerError(
                        "compose_project_name_released",
                        "Compose project-name authority was released; reenroll before any lifecycle mutation.",
                        operation_id=request.operation_id,
                    )
                if any(
                    row[name] is None
                    for name in (
                        "root_device",
                        "root_inode",
                        "cwd_device",
                        "cwd_inode",
                    )
                ):
                    raise BrokerError(
                        "compose_directory_identity_required",
                        "Compose directory identity is missing; rerun Coordinator skill installation.",
                        operation_id=request.operation_id,
                    )
                if row["effective_fingerprint"] is None or str(
                    row["effective_fingerprint"]
                ) != str(row["definition_fingerprint"]):
                    raise BrokerError(
                        "compose_effective_model_required",
                        "Compose definition lacks an exact merged-model enrollment proof.",
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
                service_replicas = _require_service_replica_evidence(
                    row["service_replicas_json"],
                    services=services,
                    operation_id=request.operation_id,
                )
                effective_risks = _require_string_list_evidence(
                    row["host_access_risks_json"],
                    field="host-access risks",
                    operation_id=request.operation_id,
                )
                env_files = tuple(
                    str(item["file_path"])
                    for item in connection.execute(
                        """
                        SELECT file_path FROM broker_compose_env_files
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (request.resource_id,),
                    )
                )
                profiles = tuple(
                    str(item["profile_name"])
                    for item in connection.execute(
                        """
                        SELECT profile_name FROM broker_compose_profiles
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
                env_file_evidence = tuple(
                    (str(item["content_sha256"]), int(item["byte_size"]))
                    for item in connection.execute(
                        """
                        SELECT content_sha256, byte_size
                        FROM broker_compose_env_file_evidence
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
                if len(env_file_evidence) != len(env_files):
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Compose definition has incomplete environment-file evidence.",
                        operation_id=request.operation_id,
                    )
                expected_fingerprint = _compose_definition_fingerprint(
                    repo_id=str(row["repo_id"]),
                    canonical_root=str(row["canonical_root"]),
                    root_identity={
                        "device": int(row["root_device"]),
                        "inode": int(row["root_inode"]),
                    },
                    cwd=str(row["cwd"]),
                    cwd_identity={
                        "device": int(row["cwd_device"]),
                        "inode": int(row["cwd_inode"]),
                    },
                    compose_files=files,
                    compose_file_evidence=tuple(
                        {
                            "content_sha256": digest,
                            "byte_size": byte_size,
                        }
                        for digest, byte_size in file_evidence
                    ),
                    env_files=env_files,
                    env_file_evidence=tuple(
                        {
                            "content_sha256": digest,
                            "byte_size": byte_size,
                        }
                        for digest, byte_size in env_file_evidence
                    ),
                    profiles=profiles,
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
                    root_device=int(row["root_device"]),
                    root_inode=int(row["root_inode"]),
                    cwd=str(row["cwd"]),
                    cwd_device=int(row["cwd_device"]),
                    cwd_inode=int(row["cwd_inode"]),
                    compose_files=files,
                    compose_file_sha256s=tuple(item[0] for item in file_evidence),
                    compose_file_sizes=tuple(item[1] for item in file_evidence),
                    env_files=env_files,
                    env_file_sha256s=tuple(item[0] for item in env_file_evidence),
                    env_file_sizes=tuple(item[1] for item in env_file_evidence),
                    profiles=profiles,
                    services=services,
                    service_replicas=service_replicas,
                    project_name=str(row["project_name"]),
                    effective_model_sha256=str(row["model_sha256"]),
                    effective_host_access_risks=effective_risks,
                    effective_host_access_approved=bool(row["host_access_approved"]),
                    definition_fingerprint=str(row["definition_fingerprint"]),
                    definition_generation=int(row["definition_generation"]),
                    repository_generation=int(row["repository_generation"]),
                )

    def require_compose_mutation_safe(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        snapshot_id: str,
    ) -> None:
        """Fence every Compose action against exact fresh host and name ownership."""

        request = authorized.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
                    request=request,
                )
                _require_compose_mutation_safe_connection(
                    connection,
                    request=request,
                    snapshot_id=snapshot_id,
                )

    def require_no_active_compose_operation(
        self,
        authorized: AuthorizedBrokerRequest,
    ) -> None:
        request = authorized.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
                    request=request,
                )
                _require_no_unresolved_compose_operation(
                    connection,
                    request=request,
                )

    def reconcilable_prior_compose_operation_id(
        self,
        authorized: AuthorizedBrokerRequest,
    ) -> str | None:
        """Return an exact prior uncertain Compose operation for this request."""

        request = authorized.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
                    request=request,
                )
                row = connection.execute(
                    """
                    SELECT operation.operation_id
                    FROM operations operation
                    JOIN operation_targets target USING(operation_id)
                    JOIN broker_compose_definitions target_definition
                      ON target_definition.compose_definition_id = target.target_id
                    JOIN repositories target_repository
                      ON target_repository.repo_id = target_definition.repo_id
                    JOIN broker_compose_definitions requested_definition
                      ON requested_definition.compose_definition_id = ?
                    JOIN repositories requested_repository
                      ON requested_repository.repo_id = requested_definition.repo_id
                    WHERE target.target_kind = 'compose'
                      AND (
                          target.target_id = ?
                          OR (
                              target_definition.project_name =
                                  requested_definition.project_name
                              AND target_repository.host_id =
                                  requested_repository.host_id
                          )
                      )
                      AND operation.operation_id != ?
                      AND operation.status = 'needs_attention'
                      AND operation.phase = 'reconciliation_required'
                    ORDER BY operation.created_at, operation.operation_id
                    LIMIT 1
                    """,
                    (
                        request.resource_id,
                        request.resource_id,
                        request.operation_id,
                    ),
                ).fetchone()
                return None if row is None else str(row["operation_id"])

    def list_removed_repository(
        self, authorized: AuthorizedBrokerRequest
    ) -> list[dict[str, Any]]:
        request = authorized.request
        if request.operation != BrokerOperation.REPOSITORY_LIST_REMOVED:
            raise ValueError("request is not a removed-repository read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
                graph = store.inventory_v2()
        # Test statistics are repository-owned, bounded projections over the
        # same service database. Keep them beside (not inside) runtime
        # resources so the Board cannot confuse test activity with host state.
        from .test_records import CoordinatorTestRecords

        records = CoordinatorTestRecords(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        )
        graph["test_statistics"] = [
            records.stats_for_repository(
                repo_id=str(repository["repo_id"]), days=30, limit=25
            )
            for repository in graph["repositories"]
            if repository.get("installation_status") != "disabled"
        ]
        return graph

    def runtime_snapshot(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        """Return one authorized runtime family context and host snapshot.

        Classification is evaluated in the same read transaction as the
        inventory projection.  A shared-host status request must not report a
        normal target while another active resource in the same repository
        family has no proved owner.
        """

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
        ):
            raise ValueError("request is not a runtime request")
        with self._store() as store:
            store.__class__ = _BrokerInventoryStore
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                root_repo_id = str(request.arguments["root_repo_id"])
                rows = list(
                    connection.execute(
                        """
                        SELECT repository.repo_id, repository.canonical_root,
                               scope.family_id, scope.project_kind
                        FROM repositories repository
                        JOIN repository_scopes scope USING(repo_id)
                        WHERE repository.repo_id IN (?, ?)
                        ORDER BY repository.repo_id
                        """,
                        (root_repo_id, request.project_id),
                    )
                )
                by_repo = {str(row["repo_id"]): row for row in rows}
                root = by_repo[root_repo_id]
                effective = by_repo[request.project_id]
                context = {
                    "family_id": str(root["family_id"]),
                    "root_repo_id": root_repo_id,
                    "effective_repo_id": request.project_id,
                    "project_kind": str(effective["project_kind"]),
                    "root_repo": str(root["canonical_root"]),
                    "temporary_repo": (
                        str(effective["canonical_root"])
                        if request.arguments["temporary_repo_id"] is not None
                        else None
                    ),
                }
                inventory = store.inventory_v2()
                family_rows = list(
                    connection.execute(
                        """
                        SELECT scope.repo_id, repository.canonical_root,
                               repository.host_id
                        FROM repository_scopes scope
                        JOIN repositories repository USING(repo_id)
                        WHERE scope.family_id = ?
                        ORDER BY scope.project_kind, repository.canonical_root
                        """,
                        (context["family_id"],),
                    )
                )
                family_repo_ids = {str(row["repo_id"]) for row in family_rows}
                family_host_ids = {str(row["host_id"]) for row in family_rows}
                if len(family_host_ids) != 1:
                    raise RuntimeError(
                        "runtime repository family does not resolve to one host authority"
                    )
                roots = tuple(
                    Path(str(row["canonical_root"])) for row in family_rows
                )
                if any(not root_path.is_absolute() for root_path in roots):
                    raise RuntimeError(
                        "runtime repository family contains a non-absolute canonical root"
                    )
                unassigned = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT unassigned.resource_kind,
                               unassigned.resource_id,
                               unassigned.display_name,
                               unassigned.reason_code,
                               unassigned.suggested_root
                        FROM unassigned_resources unassigned
                        LEFT JOIN docker_observations observed_docker
                          ON unassigned.resource_kind = 'container'
                         AND observed_docker.docker_resource_id = unassigned.resource_id
                        WHERE unassigned.status = 'active'
                          AND unassigned.host_id = ?
                          AND (
                            unassigned.resource_kind <> 'container'
                            OR observed_docker.lifecycle IS NULL
                            OR observed_docker.lifecycle <> 'stopped'
                          )
                        ORDER BY unassigned.resource_kind,
                                 unassigned.resource_id
                        """,
                        (next(iter(family_host_ids)),),
                    )
                ]

                def plausibly_in_family(item: Mapping[str, Any]) -> bool:
                    if str(item.get("reason_code") or "") not in {
                        "not_git",
                        "missing_repo",
                        "stale_observation",
                    }:
                        return True
                    raw = item.get("suggested_root")
                    if not isinstance(raw, str) or not raw or "\x00" in raw:
                        return True
                    if not Path(raw).is_absolute():
                        return True
                    suggested = Path(os.path.realpath(os.path.normpath(raw)))
                    return any(
                        suggested == root_path or root_path in suggested.parents
                        for root_path in roots
                    )

                classification_evidence = [
                    {"classification": "unclassified_resource", **item}
                    for item in unassigned
                    if plausibly_in_family(item)
                ]
                classification_evidence.extend(
                    {"classification": "lifecycle_violation", **dict(item)}
                    for item in inventory.get("lifecycle_violations") or []
                    if isinstance(item, Mapping)
                    and str(item.get("repo_id") or "") in family_repo_ids
                )
                return context, inventory, classification_evidence

    def require_worker_runtime_operation_current(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        """Reauthorize and prove one reserved worker-control target unchanged."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["target_kind"] != "service"
            or request.arguments["action"] not in {
                "start", "stop", "restart", "replace"
            }
        ):
            raise ValueError("request is not a worker runtime mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT target_kind, target_id, action, immutable_fingerprint
                    FROM operation_targets
                    WHERE operation_id = ? AND ordinal = 0
                    """,
                    (request.operation_id,),
                ).fetchone()
                expected_action = "runtime." + str(request.arguments["action"])
                if (
                    row is None
                    or str(row["target_kind"]) != "server"
                    or str(row["target_id"]) != request.resource_id
                    or str(row["action"]) != expected_action
                ):
                    raise BrokerError(
                        "operation_state_conflict",
                        "Durable worker control lost its exact target reservation.",
                        operation_id=request.operation_id,
                    )
                current = _server_definition_fingerprint(
                    connection,
                    repo_id=request.project_id,
                    server_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                if str(row["immutable_fingerprint"]) != current:
                    raise BrokerError(
                        "stale_resource_definition",
                        "Worker definition changed after the control operation was reserved.",
                        operation_id=request.operation_id,
                    )
                if request.arguments["action"] == "replace":
                    definition = connection.execute(
                        """
                        SELECT definition.generation, policy.execution_uid
                        FROM server_definitions definition
                        LEFT JOIN worker_policies policy
                          USING(server_definition_id)
                        WHERE definition.repo_id = ?
                          AND definition.server_definition_id = ?
                        """,
                        (request.project_id, request.resource_id),
                    ).fetchone()
                    if (
                        definition is None
                        or definition["execution_uid"] is None
                        or int(definition["execution_uid"]) != authorized.peer.uid
                    ):
                        raise BrokerError(
                            "worker_execution_uid_mismatch",
                            "The exact worker policy belongs to another execution account.",
                            operation_id=request.operation_id,
                        )
                    if int(definition["generation"]) != int(
                        request.arguments["expected_definition_generation"]
                    ):
                        raise BrokerError(
                            "stale_resource_definition",
                            "Worker definition generation changed before replacement.",
                            operation_id=request.operation_id,
                        )

    def require_worker_runtime_replacement_committed(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        replacement: Mapping[str, Any],
    ) -> None:
        """Reauthorize and prove the replacement CAS committed exactly once."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["target_kind"] != "service"
            or request.arguments["action"] != "replace"
        ):
            raise ValueError("request is not a worker replacement")
        expected_generation = int(request.arguments["expected_definition_generation"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                reserved = connection.execute(
                    """
                    SELECT immutable_fingerprint FROM operation_targets
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'server' AND target_id = ?
                      AND action = 'runtime.replace'
                    """,
                    (request.operation_id, request.resource_id),
                ).fetchone()
                current = connection.execute(
                    """
                    SELECT definition.generation,
                           definition.definition_fingerprint,
                           policy.execution_uid
                    FROM server_definitions definition
                    LEFT JOIN worker_policies policy USING(server_definition_id)
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                declared = replacement.get("replacement")
                if (
                    reserved is None
                    or current is None
                    or current["execution_uid"] is None
                    or int(current["execution_uid"]) != authorized.peer.uid
                    or not isinstance(declared, Mapping)
                    or int(current["generation"]) != expected_generation + 1
                    or declared.get("generation") != int(current["generation"])
                    or declared.get("definition_fingerprint")
                    != str(current["definition_fingerprint"])
                ):
                    raise BrokerError(
                        "stale_resource_definition",
                        "Worker replacement did not commit the exact expected definition generation.",
                        operation_id=request.operation_id,
                    )

    def runtime_service_role(
        self, authorized: AuthorizedBrokerRequest
    ) -> str | None:
        """Return the exact live-authorized service role for runtime routing."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["target_kind"] != "service"
        ):
            raise ValueError("request is not a service runtime request")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT role FROM server_definitions
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "control_binding_unavailable",
                        "Runtime service no longer belongs to the exact repository.",
                        operation_id=request.operation_id,
                    )
                return None if row["role"] is None else str(row["role"])

    def events(self, authorized: AuthorizedBrokerRequest) -> dict[str, Any]:
        """Page the host event journal after live peer authorization."""

        request = authorized.request
        if request.operation != BrokerOperation.EVENTS_READ:
            raise ValueError("request is not a host event read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                return list_event_page(
                    connection,
                    after=request.arguments.get("after"),
                    limit=int(request.arguments.get("limit", 100)),
                )

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
                    None
                    if lifecycle == "stopped"
                    else str(evidence["process_identity"])
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
                    elif (
                        int(assignment["port"]) != port
                        or assignment["status"] != "active"
                    ):
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
                        "server.stopped"
                        if lifecycle == "stopped"
                        else "server.observed",
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
                _authorize_connection(connection, peer=authorized.peer, request=request)
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
                if (
                    observed is None
                    or plan is None
                    or plan["repo_id"]
                    not in {
                        None,
                        request.project_id,
                    }
                ):
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
            BrokerOperation.RESOURCE_ARCHIVE,
        }:
            raise ValueError("request is not a lifecycle plan application")
        plan_id = str(request.arguments["plan_id"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
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

    def mark_compose_operation_reconciliation_required(
        self,
        operation_id: str,
        *,
        action: str,
        failed_phase: str,
        completed_phases: Iterable[str],
        cleanup_failed: bool,
        observation: Mapping[str, Any] | None,
    ) -> None:
        """Fence an invoked Compose action whose host outcome is uncertain."""

        if action not in {"up", "stop", "restart", "down"}:
            raise ValueError("unsupported Compose reconciliation action")
        if failed_phase not in {
            "up",
            "stop",
            "down",
            "cleanup",
            "observation",
            "journal_commit",
            "up_path_precheck",
            "stop_path_precheck",
            "down_path_precheck",
            "up_path_recheck",
            "stop_path_recheck",
            "down_path_recheck",
        }:
            raise ValueError("unsupported Compose reconciliation phase")
        normalized_completed = tuple(str(item) for item in completed_phases)
        if any(item not in {"up", "stop", "down"} for item in normalized_completed):
            raise ValueError("invalid completed Compose reconciliation phase")
        evidence = {
            "action": action,
            "failed_phase": failed_phase,
            "completed_phases": list(normalized_completed),
            "cleanup_failed": bool(cleanup_failed),
            "reconciliation_observation": (
                {"status": "unavailable"}
                if observation is None
                else {"status": "completed", **dict(observation)}
            ),
        }
        encoded = json.dumps(
            evidence,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        error = json.dumps(
            {
                "code": "operation_outcome_uncertain",
                "message": "Docker Compose host outcome requires reconciliation.",
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                cursor = connection.execute(
                    """
                    UPDATE operations
                    SET status = 'needs_attention',
                        phase = 'reconciliation_required',
                        result_json = ?, error_code = 'operation_outcome_uncertain',
                        error_message =
                            'Docker Compose did not prove a complete host outcome; reconciliation is required before any retry.',
                        updated_at = ?, generation = generation + 1
                    WHERE operation_id = ? AND status = 'running'
                      AND kind = ?
                    """,
                    (encoded, now, operation_id, f"broker.compose.{action}"),
                )
                if cursor.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose operation is no longer in its reserved state.",
                        operation_id=operation_id,
                    )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET phase = 'reconciliation_required', status = 'failed',
                        result_json = ?, error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'compose' AND status = 'running'
                    """,
                    (encoded, error, now, operation_id),
                )
                if target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose target is no longer in its reserved state.",
                        operation_id=operation_id,
                    )

    def mark_runtime_operation_reconciliation_required(
        self,
        operation_id: str,
        *,
        action: str,
        failed_phase: str,
    ) -> None:
        """Durably fence an invoked Docker-backed runtime action."""

        if action not in {"start", "stop", "restart"}:
            raise ValueError("unsupported runtime reconciliation action")
        if failed_phase not in {"host_invocation", "observation", "journal_commit"}:
            raise ValueError("unsupported runtime reconciliation phase")
        evidence = json.dumps(
            {
                "action": action,
                "failed_phase": failed_phase,
                "completion_unknown": True,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        error = json.dumps(
            {
                "code": "operation_outcome_uncertain",
                "message": "Docker-backed runtime outcome requires fresh reconciliation.",
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET status = 'needs_attention',
                        phase = 'reconciliation_required', result_json = ?,
                        error_code = 'operation_outcome_uncertain',
                        error_message =
                            'Docker-backed runtime outcome is uncertain; fresh reconciliation is required before retry.',
                        updated_at = ?, generation = generation + 1
                    WHERE operation_id = ? AND status = 'running'
                      AND kind = 'broker.runtime.request'
                    """,
                    (evidence, now, operation_id),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed', phase = 'reconciliation_required',
                        result_json = ?, error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND action = ? AND status = 'running'
                    """,
                    (evidence, error, now, operation_id, "runtime." + action),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Runtime operation is no longer in its reserved state.",
                        operation_id=operation_id,
                    )

    def finish_runtime_reconciliation(
        self,
        operation_id: str,
        *,
        result: Mapping[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        """Settle one needs-attention runtime operation from fresh exact proof."""

        succeeded = result is not None
        if succeeded == (error_code is not None):
            raise ValueError("runtime reconciliation requires result xor error")
        encoded = (
            json.dumps(
                dict(result),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if result is not None
            else None
        )
        error = (
            None
            if succeeded
            else json.dumps(
                {"code": error_code, "message": error_message or ""},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET status = ?, phase = ?, result_json = ?, error_code = ?,
                        error_message = ?, updated_at = ?, generation = generation + 1
                    WHERE operation_id = ? AND status = 'needs_attention'
                      AND kind = 'broker.runtime.request'
                    """,
                    (
                        "succeeded" if succeeded else "failed",
                        "reconciled" if succeeded else "reconciliation_failed",
                        encoded,
                        None if succeeded else error_code,
                        None if succeeded else error_message,
                        now,
                        operation_id,
                    ),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = ?, phase = ?, result_json = ?, error_json = ?,
                        finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND phase = 'reconciliation_required'
                    """,
                    (
                        "succeeded" if succeeded else "failed",
                        "reconciled" if succeeded else "reconciliation_failed",
                        encoded,
                        error,
                        now,
                        operation_id,
                    ),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Runtime reconciliation changed before it could settle.",
                        operation_id=operation_id,
                    )

    def recover_interrupted_compose_operations(self) -> dict[str, Any]:
        """Fence crash-left Compose reservations before the broker accepts clients."""

        now = utc_timestamp()
        recovered: list[str] = []
        with self._store() as store:
            with store.immediate_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT operation.operation_id, target.action
                        FROM operations operation
                        JOIN operation_targets target
                          ON target.operation_id = operation.operation_id
                         AND target.ordinal = 0
                        WHERE operation.status = 'running'
                          AND operation.kind IN (
                              'broker.compose.up', 'broker.compose.stop',
                              'broker.compose.restart', 'broker.compose.down'
                          )
                          AND target.target_kind = 'compose'
                          AND target.status = 'running'
                          AND target.action IN (
                              'compose.up', 'compose.stop',
                              'compose.restart', 'compose.down'
                          )
                        ORDER BY operation.created_at, operation.operation_id
                        """
                    )
                )
                for row in rows:
                    operation_id = str(row["operation_id"])
                    action = str(row["action"]).removeprefix("compose.")
                    evidence = json.dumps(
                        {
                            "action": action,
                            "failed_phase": "broker_restart",
                            "completed_phases": None,
                            "completion_unknown": True,
                            "cleanup_failed": False,
                            "reconciliation_observation": {"status": "unavailable"},
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    error = json.dumps(
                        {
                            "code": "operation_outcome_uncertain",
                            "message": (
                                "Broker restarted before the Compose outcome "
                                "was durably settled."
                            ),
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        """
                        UPDATE operations
                        SET status = 'needs_attention',
                            phase = 'reconciliation_required',
                            result_json = ?,
                            error_code = 'operation_outcome_uncertain',
                            error_message =
                                'Broker restarted before the Compose outcome was durably settled; reconciliation is required.',
                            updated_at = ?, generation = generation + 1
                        WHERE operation_id = ? AND status = 'running'
                        """,
                        (evidence, now, operation_id),
                    )
                    connection.execute(
                        """
                        UPDATE operation_targets
                        SET status = 'failed',
                            phase = 'reconciliation_required',
                            result_json = ?, error_json = ?, finished_at = ?
                        WHERE operation_id = ? AND ordinal = 0
                          AND target_kind = 'compose' AND status = 'running'
                        """,
                        (evidence, error, now, operation_id),
                    )
                    recovered.append(operation_id)
        return {"recovered": len(recovered), "operation_ids": recovered}

    def recover_interrupted_docker_operations(self) -> dict[str, Any]:
        """Fence crash-left direct and runtime Docker reservations at startup."""

        now = utc_timestamp()
        recovered: list[str] = []
        with self._store() as store:
            with store.immediate_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT operation.operation_id, target.action
                        FROM operations operation
                        JOIN operation_targets target
                          ON target.operation_id = operation.operation_id
                         AND target.ordinal = 0
                        WHERE operation.status = 'running'
                          AND operation.kind IN (
                              'broker.docker.start', 'broker.docker.stop',
                              'broker.docker.restart', 'broker.runtime.request'
                          )
                          AND target.target_kind = 'container'
                          AND target.status = 'running'
                          AND target.action IN (
                              'docker.start', 'docker.stop', 'docker.restart',
                              'runtime.start', 'runtime.stop', 'runtime.restart'
                          )
                        ORDER BY operation.created_at, operation.operation_id
                        """
                    )
                )
                for row in rows:
                    operation_id = str(row["operation_id"])
                    action = str(row["action"])
                    evidence = json.dumps(
                        {
                            "action": action,
                            "failed_phase": "broker_restart",
                            "completion_unknown": True,
                            "reconciliation_observation": {"status": "unavailable"},
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    error = json.dumps(
                        {
                            "code": "operation_outcome_uncertain",
                            "message": (
                                "Broker restarted before the Docker-backed outcome "
                                "was durably settled."
                            ),
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    operation = connection.execute(
                        """
                        UPDATE operations
                        SET status = 'needs_attention',
                            phase = 'reconciliation_required',
                            result_json = ?,
                            error_code = 'operation_outcome_uncertain',
                            error_message =
                                'Broker restarted before the Docker-backed outcome was durably settled; reconciliation is required.',
                            updated_at = ?, generation = generation + 1
                        WHERE operation_id = ? AND status = 'running'
                        """,
                        (evidence, now, operation_id),
                    )
                    target = connection.execute(
                        """
                        UPDATE operation_targets
                        SET status = 'failed',
                            phase = 'reconciliation_required',
                            result_json = ?, error_json = ?, finished_at = ?
                        WHERE operation_id = ? AND ordinal = 0
                          AND target_kind = 'container' AND status = 'running'
                        """,
                        (evidence, error, now, operation_id),
                    )
                    if operation.rowcount != 1 or target.rowcount != 1:
                        raise BrokerError(
                            "operation_state_conflict",
                            "Docker-backed operation changed during restart recovery.",
                            operation_id=operation_id,
                        )
                    recovered.append(operation_id)
        return {"recovered": len(recovered), "operation_ids": recovered}

    def docker_reconciliation_candidate(self, operation_id: str) -> dict[str, Any]:
        """Return one exact administratively reconcilable Docker operation."""

        _require_identifier(operation_id, "operation_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                return _docker_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )

    @classmethod
    def inspect_docker_reconciliation_candidate(
        cls,
        database_path: str | os.PathLike[str],
        *,
        operation_id: str,
        expected_uid: int = 0,
    ) -> dict[str, Any]:
        """Read one direct-Docker reconciliation plan without mutating state."""

        _require_identifier(operation_id, "operation_id")
        with CoordinatorStore.open_read_only(
            database_path, expected_uid=expected_uid
        ) as store:
            with store.read_transaction() as connection:
                candidate = _docker_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )
        return {
            key: candidate[key]
            for key in (
                "operation_id",
                "repo_id",
                "host_id",
                "docker_resource_id",
                "action",
                "full_container_id",
                "identity_reservation_kind",
            )
        }

    def reconcile_docker_operation(
        self,
        operation_id: str,
        *,
        evidence: Mapping[str, Any],
        confirm_container_id: str,
    ) -> dict[str, Any]:
        """Resolve one uncertain Docker outcome as an evidenced terminal failure."""

        if os.geteuid() != 0 or self.expected_uid != 0:
            raise PermissionError(
                "Direct Docker reconciliation requires the root service administrator"
            )
        _require_identifier(operation_id, "operation_id")
        if not isinstance(evidence, Mapping):
            raise TypeError("Docker reconciliation evidence must be a mapping")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                candidate = _docker_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )
                full_container_id = str(candidate["full_container_id"])
                if confirm_container_id.lower() != full_container_id:
                    raise BrokerError(
                        "docker_reconciliation_confirmation_required",
                        "Reconciliation requires the exact persisted 64-character container ID.",
                        operation_id=operation_id,
                    )
                snapshot_id = str(evidence.get("snapshot_id") or "")
                snapshot = _require_exact_full_docker_snapshot(
                    connection,
                    snapshot_id=snapshot_id,
                    host_id=str(candidate["host_id"]),
                    expected_evidence=evidence,
                    operation_id=operation_id,
                    require_compose_asset_scope=False,
                    error_code="docker_reconciliation_observation_incomplete",
                    error_message=(
                        "Docker reconciliation requires the exact fresh full-Docker host snapshot."
                    ),
                )
                resource = connection.execute(
                    """
                    SELECT observation_fingerprint
                    FROM observation_snapshot_resources
                    WHERE snapshot_id = ? AND resource_kind = 'container'
                      AND resource_id = ?
                    """,
                    (snapshot_id, candidate["docker_resource_id"]),
                ).fetchone()
                present = resource is not None
                observation = {
                    "status": "completed",
                    "snapshot_id": snapshot_id,
                    "observer_domain": str(snapshot["observer_domain"]),
                    "material_fingerprint": str(snapshot["material_fingerprint"]),
                    "capability_fingerprint": str(
                        snapshot["capability_fingerprint"]
                    ),
                    "completed_at": str(snapshot["completed_at"]),
                    "container_present": present,
                    "resource_observation_fingerprint": (
                        str(resource["observation_fingerprint"])
                        if resource is not None
                        else None
                    ),
                }
                original = candidate["uncertain_outcome"]
                reconciliation = {
                    "mode": "observed_terminal_failure",
                    "administrator": {"uid": 0, "actor": "broker-admin:uid:0"},
                    "container_identity": {
                        "docker_resource_id": candidate["docker_resource_id"],
                        "full_container_id": full_container_id,
                    },
                    "snapshot": observation,
                    "proof": {
                        "historical_transition_proven": False,
                        "prior_invocation_claimed_successful": False,
                        "current_container_present": present,
                    },
                    "reconciled_at": now,
                }
                result = {
                    "uncertain_outcome": original,
                    "reconciliation": reconciliation,
                }
                encoded = json.dumps(
                    result,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                message = (
                    "Uncertain direct Docker invocation was reconciled as a terminal "
                    "failure; the prior invocation is not claimed successful."
                )
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET status = 'failed', phase = 'reconciled',
                        result_json = ?, error_code = 'docker_outcome_reconciled',
                        error_message = ?, updated_at = ?,
                        generation = generation + 1
                    WHERE operation_id = ? AND status = 'needs_attention'
                      AND phase = 'reconciliation_required'
                    """,
                    (encoded, message, now, operation_id),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed', phase = 'reconciled',
                        result_json = ?, error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND phase = 'reconciliation_required'
                    """,
                    (
                        encoded,
                        json.dumps(
                            {"code": "docker_outcome_reconciled", "message": message},
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                        operation_id,
                    ),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Direct Docker operation changed during reconciliation.",
                        operation_id=operation_id,
                    )
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, source_id, operation_id,
                        event_kind, code, message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, NULL, ?, 'docker.reconciled',
                              'docker_outcome_reconciled', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        candidate["repo_id"],
                        operation_id,
                        message,
                        json.dumps(
                            reconciliation,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )
                return {
                    "operation_id": operation_id,
                    "status": "failed",
                    "phase": "reconciled",
                    "current_container_present": present,
                    "reconciliation": reconciliation,
                }

    def compose_reconciliation_candidate(self, operation_id: str) -> dict[str, Any]:
        """Return one exact administratively reconcilable Compose operation."""

        _require_identifier(operation_id, "operation_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                return _compose_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )

    @classmethod
    def inspect_compose_reconciliation_candidate(
        cls,
        database_path: str | os.PathLike[str],
        *,
        operation_id: str,
        expected_uid: int = 0,
    ) -> dict[str, Any]:
        """Read one reconciliation plan without schema or observation mutation."""

        _require_identifier(operation_id, "operation_id")
        with CoordinatorStore.open_read_only(
            database_path, expected_uid=expected_uid
        ) as store:
            with store.read_transaction() as connection:
                candidate = _compose_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )
        return {
            key: candidate[key]
            for key in (
                "operation_id",
                "repo_id",
                "host_id",
                "compose_definition_id",
                "project_name",
                "action",
                "target_fingerprint",
                "current_fingerprint",
                "services",
                "service_replicas",
                "scope_recoverable",
                "scope_failure_reason",
            )
        }

    def compose_observation_result(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prove a zero-exit Compose mutation's exact requested end state."""

        request = authorized.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(connection, peer=authorized.peer, request=request)
                snapshot_id = str(evidence.get("snapshot_id") or "")
                _require_compose_mutation_safe_connection(
                    connection,
                    request=request,
                    snapshot_id=snapshot_id,
                    expected_evidence=evidence,
                )
                definition = _compose_definition_scope_connection(
                    connection,
                    repo_id=request.project_id,
                    compose_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                action = request.operation.value.removeprefix("compose.")
                proof = _compose_action_observation_proof(
                    connection,
                    snapshot_id=snapshot_id,
                    repo_id=request.project_id,
                    project_name=str(definition["project_name"]),
                    services=tuple(definition["services"]),
                    service_replicas=tuple(definition["service_replicas"]),
                    action=action,
                    uncertain_transition=False,
                )
                if proof["desired_state_observed"] is not True:
                    raise BrokerError(
                        "compose_observation_mismatch",
                        "Fresh service observation did not prove the requested Compose lifecycle result.",
                        operation_id=request.operation_id,
                    )
                return proof

    def reconcile_compose_operation(
        self,
        operation_id: str,
        *,
        evidence: Mapping[str, Any] | None,
        abandon_as_failed: bool = False,
        confirm_definition_fingerprint: str | None = None,
        authorized: AuthorizedBrokerRequest | None = None,
    ) -> dict[str, Any]:
        """Resolve one uncertain Compose outcome as an evidenced terminal failure."""

        if authorized is None and (os.geteuid() != 0 or self.expected_uid != 0):
            raise PermissionError(
                "Compose reconciliation requires the root service administrator"
            )
        if authorized is not None and authorized.request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("automatic reconciliation requires a Compose request")
        _require_identifier(operation_id, "operation_id")
        if not abandon_as_failed and not isinstance(evidence, Mapping):
            raise TypeError("Compose reconciliation evidence must be a mapping")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                if authorized is not None:
                    _authorize_connection(
                        connection,
                        peer=authorized.peer,
                        request=authorized.request,
                    )
                candidate = _compose_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )
                if authorized is not None and (
                    candidate["repo_id"] != authorized.request.project_id
                    or candidate["compose_definition_id"]
                    != authorized.request.resource_id
                ):
                    raise BrokerError(
                        "resource_access_denied",
                        "Prior Compose operation does not belong to the exact authorized definition.",
                        operation_id=authorized.request.operation_id,
                    )
                scope_recoverable = bool(candidate["scope_recoverable"])
                if abandon_as_failed:
                    if scope_recoverable:
                        raise BrokerError(
                            "compose_reconciliation_scope_available",
                            "Exact Compose scope is available; use evidence-based reconciliation instead of abandonment.",
                            operation_id=operation_id,
                        )
                    if (
                        confirm_definition_fingerprint
                        != candidate["target_fingerprint"]
                    ):
                        raise BrokerError(
                            "compose_reconciliation_confirmation_required",
                            "Abandonment requires the exact persisted target definition fingerprint.",
                            operation_id=operation_id,
                        )
                    proof: dict[str, Any] = {
                        "proof": "scope_unrecoverable",
                        "desired_state_observed": False,
                        "transition_proven": False,
                        "reason": str(candidate["scope_failure_reason"]),
                    }
                    mode = "abandoned_as_failed"
                    snapshot_evidence: dict[str, Any] = {
                        "status": "unavailable",
                        "reason": "offline_failure_only_abandonment",
                    }
                else:
                    if not scope_recoverable:
                        raise BrokerError(
                            "compose_reconciliation_scope_unrecoverable",
                            "The original Compose scope cannot be re-proven; use explicit fingerprint-confirmed abandonment.",
                            operation_id=operation_id,
                        )
                    assert isinstance(evidence, Mapping)
                    snapshot_id = str(evidence.get("snapshot_id") or "")
                    snapshot = _require_exact_full_docker_snapshot(
                        connection,
                        snapshot_id=snapshot_id,
                        host_id=str(candidate["host_id"]),
                        expected_evidence=evidence,
                        operation_id=operation_id,
                    )
                    _require_observed_compose_project_name_available(
                        connection,
                        snapshot_id=snapshot_id,
                        repo_id=str(candidate["repo_id"]),
                        project_name=str(candidate["project_name"]),
                    )
                    proof = _compose_action_observation_proof(
                        connection,
                        snapshot_id=snapshot_id,
                        repo_id=str(candidate["repo_id"]),
                        project_name=str(candidate["project_name"]),
                        services=tuple(candidate["services"]),
                        service_replicas=tuple(candidate["service_replicas"]),
                        action=str(candidate["action"]),
                        uncertain_transition=True,
                    )
                    mode = "observed_terminal_failure"
                    snapshot_evidence = {
                        "status": "completed",
                        "snapshot_id": snapshot_id,
                        "observer_domain": str(snapshot["observer_domain"]),
                        "material_fingerprint": str(snapshot["material_fingerprint"]),
                        "capability_fingerprint": str(
                            snapshot["capability_fingerprint"]
                        ),
                        "completed_at": str(snapshot["completed_at"]),
                    }

                original = candidate["uncertain_outcome"]
                reconciliation = {
                    "mode": mode,
                    "administrator": {
                        "uid": 0 if authorized is None else authorized.peer.uid,
                        "actor": (
                            "broker-admin:uid:0"
                            if authorized is None
                            else "broker:auto-reconcile:uid:"
                            + str(authorized.peer.uid)
                        ),
                    },
                    "snapshot": snapshot_evidence,
                    "proof": proof,
                    "reconciled_at": now,
                }
                result = {
                    "uncertain_outcome": original,
                    "reconciliation": reconciliation,
                }
                encoded = json.dumps(
                    result,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                message = (
                    "Uncertain Compose invocation was reconciled as a terminal failure; "
                    "the prior invocation is not claimed successful."
                )
                updated = connection.execute(
                    """
                    UPDATE operations
                    SET status = 'failed', phase = 'reconciled',
                        result_json = ?, error_code = 'compose_outcome_reconciled',
                        error_message = ?, updated_at = ?,
                        generation = generation + 1
                    WHERE operation_id = ? AND status = 'needs_attention'
                      AND phase = 'reconciliation_required'
                    """,
                    (encoded, message, now, operation_id),
                )
                if updated.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose operation changed during reconciliation.",
                        operation_id=operation_id,
                    )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed', phase = 'reconciled',
                        result_json = ?, error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'compose'
                    """,
                    (
                        encoded,
                        json.dumps(
                            {
                                "code": "compose_outcome_reconciled",
                                "message": message,
                            },
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                        operation_id,
                    ),
                )
                if target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose target changed during reconciliation.",
                        operation_id=operation_id,
                    )
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, source_id, operation_id,
                        event_kind, code, message, diagnostic_json, occurred_at
                    ) VALUES (?, ?, NULL, ?, 'compose.reconciled',
                              'compose_outcome_reconciled', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        candidate["repo_id"],
                        operation_id,
                        message,
                        json.dumps(
                            reconciliation,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )
                return {
                    "operation_id": operation_id,
                    "status": "failed",
                    "phase": "reconciled",
                    "desired_state_observed": proof["desired_state_observed"],
                    "reconciliation": reconciliation,
                }


def _backfill_exact_worker_acl(
    connection: sqlite3.Connection,
    *,
    now_epoch: int,
    updated_at: str,
) -> None:
    """Migrate only existing exact, fully managed worker authority.

    A worker protocol grant is an implementation detail of existing service
    lifecycle authority.  It is therefore backfilled only when the same
    UID/repository has all four enabled exact-service actions, a current active
    enrollment, and is the configured execution identity of a current
    worker-role definition. ``INSERT OR IGNORE`` preserves explicit worker-ACL
    revocations and makes repeated startup migration idempotent.
    """

    connection.execute(
        """
        WITH eligible(uid, repo_id, server_definition_id) AS (
            SELECT runtime.uid, runtime.repo_id, runtime.resource_id
            FROM broker_runtime_acl runtime
            JOIN server_definitions definition
              ON definition.server_definition_id = runtime.resource_id
             AND definition.repo_id = runtime.repo_id
             AND lower(definition.role) = 'worker'
            JOIN worker_policies policy
              ON policy.server_definition_id = definition.server_definition_id
             AND policy.repo_id = runtime.repo_id
             AND policy.execution_uid = runtime.uid
            JOIN repositories repository
              ON repository.repo_id = runtime.repo_id
             AND repository.state = 'active'
            JOIN repository_installations installation
              ON installation.repo_id = runtime.repo_id
             AND installation.status = 'installed'
             AND installation.startup_fenced = 0
            JOIN broker_repository_enrollments enrollment
              ON enrollment.uid = runtime.uid
             AND enrollment.repo_id = runtime.repo_id
             AND enrollment.enabled = 1
             AND enrollment.valid_until_epoch > ?
            JOIN broker_acl_principals principal
              ON principal.uid = runtime.uid
             AND principal.account_id = enrollment.account_id
             AND principal.enabled = 1
            WHERE runtime.resource_kind = 'service'
              AND runtime.enabled = 1
              AND runtime.action IN ('status', 'start', 'stop', 'restart')
              AND NOT EXISTS (
                  SELECT 1 FROM broker_worker_acl revoked
                  WHERE revoked.uid = runtime.uid
                    AND revoked.repo_id = runtime.repo_id
                    AND revoked.server_definition_id = runtime.resource_id
                    AND revoked.enabled = 0
              )
            GROUP BY runtime.uid, runtime.repo_id, runtime.resource_id
            HAVING COUNT(DISTINCT runtime.action) = 4
        ), operations(operation) AS (
            SELECT 'worker.launch_ticket'
            UNION ALL SELECT 'worker.launched'
            UNION ALL SELECT 'worker.exit'
            UNION ALL SELECT 'worker.policy_read'
            UNION ALL SELECT 'worker.attempt_read'
        )
        INSERT OR IGNORE INTO broker_worker_acl(
            uid, repo_id, server_definition_id, operation, enabled, updated_at
        )
        SELECT eligible.uid, eligible.repo_id, eligible.server_definition_id,
               operations.operation, 1, ?
        FROM eligible CROSS JOIN operations
        """,
        (now_epoch, updated_at),
    )


def _backfill_worker_replace_acl(
    connection: sqlite3.Connection,
    *,
    now_epoch: int,
    updated_at: str,
) -> None:
    """Grant replace only where prior exact worker lifecycle authority is complete.

    This upgrades existing enrollments without broadening Docker or non-worker
    authority. An explicit disabled replace row is a durable revocation and is
    therefore preserved by ``INSERT OR IGNORE``.
    """

    connection.execute(
        """
        WITH eligible(uid, repo_id, server_definition_id) AS (
            SELECT runtime.uid, runtime.repo_id, runtime.resource_id
            FROM broker_runtime_acl runtime
            JOIN server_definitions definition
              ON definition.server_definition_id = runtime.resource_id
             AND definition.repo_id = runtime.repo_id
             AND lower(definition.role) = 'worker'
            JOIN worker_policies policy
              ON policy.server_definition_id = definition.server_definition_id
             AND policy.repo_id = runtime.repo_id
             AND policy.execution_uid = runtime.uid
            JOIN repositories repository
              ON repository.repo_id = runtime.repo_id
             AND repository.state = 'active'
            JOIN repository_installations installation
              ON installation.repo_id = runtime.repo_id
             AND installation.status = 'installed'
             AND installation.startup_fenced = 0
            JOIN broker_repository_enrollments enrollment
              ON enrollment.uid = runtime.uid
             AND enrollment.repo_id = runtime.repo_id
             AND enrollment.enabled = 1
             AND enrollment.valid_until_epoch > ?
            JOIN broker_acl_principals principal
              ON principal.uid = runtime.uid
             AND principal.account_id = enrollment.account_id
             AND principal.enabled = 1
            WHERE runtime.resource_kind = 'service'
              AND runtime.enabled = 1
              AND runtime.action IN ('status', 'start', 'stop', 'restart')
            GROUP BY runtime.uid, runtime.repo_id, runtime.resource_id
            HAVING COUNT(DISTINCT runtime.action) = 4
        )
        INSERT OR IGNORE INTO broker_runtime_acl(
            uid, repo_id, resource_kind, resource_id,
            action, enabled, updated_at
        )
        SELECT uid, repo_id, 'service', server_definition_id,
               'replace', 1, ?
        FROM eligible
        """,
        (now_epoch, updated_at),
    )


def _require_infrastructure_principal_isolated(
    connection: sqlite3.Connection,
    *,
    uid: int,
) -> None:
    """Fail closed when an infrastructure service UID has any broader role.

    This checks all current and future ``broker_*`` tables that carry a UID,
    excluding only the principal identity and the fixed infrastructure ACL
    itself. Retained operation/lease ownership also blocks reuse: an explicit
    administrator decommission is required before a user/runtime UID can
    become a dedicated public-ingress identity. Non-mutating read authority is
    deliberately allowed to coexist with the authenticated Console/API UID.
    """

    broader_tables: list[str] = []
    for row in connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name GLOB 'broker_*'
        ORDER BY name
        """
    ):
        table = str(row["name"])
        if table in {
            "broker_acl_principals",
            "broker_infrastructure_service_acl",
        }:
            continue
        if re.fullmatch(r"broker_[a-z0-9_]+", table) is None:
            raise BrokerError(
                "infrastructure_principal_isolation_unverifiable",
                "A broker authority table name could not be inspected safely.",
            )
        columns = {
            str(column["name"])
            for column in connection.execute(
                f'PRAGMA table_info("{table}")'
            )
        }
        if "uid" not in columns:
            continue
        if connection.execute(
            f'SELECT 1 FROM "{table}" WHERE uid = ? LIMIT 1',
            (uid,),
        ).fetchone() is not None:
            broader_tables.append(table)
    if broader_tables:
        raise BrokerError(
            "infrastructure_principal_not_dedicated",
            "Infrastructure service UID already has broader repository, "
            "runtime, control, or retained ownership authority and cannot "
            "receive or exercise the fixed infrastructure grant.",
        )


def _require_uid_has_no_enabled_infrastructure_service_access(
    connection: sqlite3.Connection,
    *,
    uid: int,
) -> None:
    if connection.execute(
        """
        SELECT 1 FROM broker_infrastructure_service_acl
        WHERE uid = ? AND enabled = 1
          AND operation IN (
              'infrastructure.ingest',
              'infrastructure.verification_context'
          )
        LIMIT 1
        """,
        (uid,),
    ).fetchone() is not None:
        raise BrokerError(
            "infrastructure_principal_is_dedicated",
            "A UID with enabled fixed infrastructure service authority cannot "
            "receive repository enrollment; disable and decommission that "
            "service identity first.",
        )


def _authorize_connection(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> Optional[sqlite3.Row]:
    ephemeral_retained_access = request.operation in {
        BrokerOperation.EPHEMERAL_STATUS,
        BrokerOperation.EPHEMERAL_FINISH,
    }
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
    if principal is None or (
        not principal["enabled"] and not ephemeral_retained_access
    ):
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
    if request.operation in _INFRASTRUCTURE_OPERATIONS:
        if request.operation in _INFRASTRUCTURE_INGRESS_OPERATIONS:
            _require_infrastructure_principal_isolated(
                connection, uid=peer.uid
            )
        expected_resource_id = (
            INFRASTRUCTURE_INGEST_RESOURCE_ID
            if request.operation is BrokerOperation.INFRASTRUCTURE_INGEST
            else (
                INFRASTRUCTURE_READ_RESOURCE_ID
                if request.operation is BrokerOperation.INFRASTRUCTURE_READ
                else INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID
            )
        )
        if (
            request.project_id != INFRASTRUCTURE_BROKER_PROJECT_ID
            or request.resource_id != expected_resource_id
            or request.repository_generation != 0
        ):
            raise BrokerError(
                "resource_access_denied",
                "Infrastructure service requests must target their exact fixed broker scope.",
                operation_id=request.operation_id,
            )
        grant = connection.execute(
            """
            SELECT account_id, enabled, valid_until_epoch
            FROM broker_infrastructure_service_acl
            WHERE uid = ? AND operation = ?
            """,
            (peer.uid, request.operation.value),
        ).fetchone()
        if (
            grant is None
            or not bool(grant["enabled"])
            or str(grant["account_id"]) != request.account_id
        ):
            raise BrokerError(
                "operation_access_denied",
                "The authenticated service principal is not authorized for this infrastructure operation.",
                operation_id=request.operation_id,
            )
        if int(time.time()) >= int(grant["valid_until_epoch"]):
            raise BrokerError(
                "service_enrollment_expired",
                "The infrastructure service-principal grant has expired.",
                operation_id=request.operation_id,
            )
        return None
    repository_identity = connection.execute(
        """
        SELECT canonical_root, state, generation
        FROM repositories WHERE repo_id = ?
        """,
        (request.project_id,),
    ).fetchone()
    revoked_repository = connection.execute(
        """
        SELECT cleanup_operation_id
        FROM broker_repository_revocations
        WHERE repo_id = ? AND repository_generation = ?
        """,
        (request.project_id, request.repository_generation),
    ).fetchone()
    has_repository_revocation = connection.execute(
        """
        SELECT 1 FROM broker_repository_revocations
        WHERE repo_id = ? LIMIT 1
        """,
        (request.project_id,),
    ).fetchone() is not None
    revoked_cleanup_replay = bool(
        revoked_repository is not None
        and request.operation is BrokerOperation.CLEANUP_APPLY
        and str(request.arguments.get("plan_id") or "")
        == str(revoked_repository["cleanup_operation_id"])
    )
    if revoked_repository is not None and not revoked_cleanup_replay:
        raise BrokerError(
            "project_permanently_removed",
            "This exact repository generation is permanently removed; explicitly reinstall it through the Coordinator skill.",
            operation_id=request.operation_id,
        )
    terminal_old_generation = request.operation in {
        BrokerOperation.PORT_RELEASE,
        BrokerOperation.PORT_UNASSIGN,
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
        BrokerOperation.WORKER_ATTEMPT_READ,
    }
    if (
        repository_identity is not None
        and int(repository_identity["generation"])
        != request.repository_generation
        and has_repository_revocation
        and not revoked_cleanup_replay
        and not terminal_old_generation
    ):
        raise BrokerError(
            "project_generation_stale",
            "The broker request belongs to an obsolete repository generation; reload the protected Coordinator profile.",
            operation_id=request.operation_id,
        )
    enrollment = connection.execute(
        """
        SELECT account_id, enabled, valid_until_epoch
        FROM broker_repository_enrollments
        WHERE uid = ? AND repo_id = ?
        """,
        (peer.uid, request.project_id),
    ).fetchone()
    if (
        enrollment is None or not bool(enrollment["enabled"])
    ) and not ephemeral_retained_access and not revoked_cleanup_replay:
        raise BrokerError(
            "project_access_denied",
            "The authenticated account has no enabled enrollment for this project.",
            operation_id=request.operation_id,
        )
    if (
        enrollment is not None
        and str(enrollment["account_id"]) != request.account_id
    ):
        raise BrokerError(
            "cross_account_access_denied",
            "The repository enrollment belongs to another account.",
            operation_id=request.operation_id,
        )
    if (
        enrollment is not None
        and int(time.time()) >= int(enrollment["valid_until_epoch"])
        and not ephemeral_retained_access
        and not revoked_cleanup_replay
    ):
        raise BrokerError(
            "repository_enrollment_expired",
            "The authenticated repository enrollment has expired; rerun Coordinator skill installation.",
            operation_id=request.operation_id,
        )
    revoked_server = connection.execute(
        """
        SELECT cleanup_operation_id
        FROM broker_server_revocations
        WHERE repo_id = ? AND server_definition_id = ?
        """,
        (request.project_id, request.resource_id),
    ).fetchone()
    if revoked_server is not None and request.operation not in {
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
        BrokerOperation.WORKER_ATTEMPT_READ,
    }:
        raise BrokerError(
            "resource_permanently_removed",
            "This exact server incarnation is permanently removed; explicitly reinstall it through the Coordinator skill to obtain a new ID.",
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
    if (
        installation is None
        and request.operation is not BrokerOperation.CLEANUP_APPLY
        and not ephemeral_retained_access
    ):
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
            | _ARCHIVE_READ_OPERATIONS
            | _HOST_READ_OPERATIONS
            | _HOST_OBSERVE_OPERATIONS
            | _TEST_OPERATIONS
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
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        BrokerOperation.EPHEMERAL_RENEW,
        BrokerOperation.EPHEMERAL_SECRET_FD,
        BrokerOperation.DOCKER_START,
        BrokerOperation.DOCKER_RESTART,
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.DATABASE_BACKUP,
        BrokerOperation.DATABASE_RESTORE,
        BrokerOperation.SERVER_PUBLISH,
        BrokerOperation.HOST_OBSERVE,
        BrokerOperation.TEST_RUN_START,
        BrokerOperation.WORKER_LAUNCH_TICKET,
    } or (
        request.operation is BrokerOperation.RUNTIME_REQUEST
        and request.arguments["action"] in {"start", "restart", "replace"}
    )
    retained_cleanup_access = request.operation in {
        BrokerOperation.ARCHIVES_READ,
        BrokerOperation.CLEANUP_PLAN,
        BrokerOperation.CLEANUP_APPLY,
        BrokerOperation.LIFECYCLE_RESTORE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
        BrokerOperation.RESOURCE_RETIRE,
        BrokerOperation.RESOURCE_ARCHIVE,
        BrokerOperation.RESOURCE_RESTORE,
        BrokerOperation.EPHEMERAL_STATUS,
        BrokerOperation.EPHEMERAL_FINISH,
        BrokerOperation.TEST_RUN_FINISH,
        BrokerOperation.TEST_STATS_READ,
        BrokerOperation.WORKER_LAUNCHED,
        BrokerOperation.WORKER_EXIT,
        BrokerOperation.WORKER_POLICY_READ,
        BrokerOperation.WORKER_ATTEMPT_READ,
    }
    if installation is not None and (
        installation["state"] != "active"
        and not retained_cleanup_access
    ) or (
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
    if request.operation in _EPHEMERAL_OPERATIONS:
        if request.operation in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_STATUS,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        }:
            template_id = request.resource_id
            target = connection.execute(
                """
                SELECT template_id, enabled
                FROM ephemeral_container_templates
                WHERE template_id = ? AND repo_id = ?
                """,
                (template_id, request.project_id),
            ).fetchone()
            if target is None or not bool(target["enabled"]):
                raise BrokerError(
                    "control_binding_unavailable",
                    "Ephemeral template is disabled or no longer belongs to this repository.",
                    operation_id=request.operation_id,
                )
        else:
            target = connection.execute(
                """
                SELECT run.template_id, template.enabled,
                       run.owner_uid, run.account_id, run.status,
                       run.expires_at_epoch, run.secret_policy_kind,
                       run.secret_binding_id,
                       run.credential_renewal_phase
                FROM ephemeral_container_runs run
                JOIN ephemeral_container_templates template USING(template_id)
                WHERE run.run_id = ? AND run.repo_id = ?
                """,
                (request.resource_id, request.project_id),
            ).fetchone()
            if (
                target is None
                or int(target["owner_uid"]) != peer.uid
                or str(target["account_id"]) != request.account_id
            ):
                raise BrokerError(
                    "resource_access_denied",
                    "Ephemeral run does not belong to the authenticated principal and project.",
                    operation_id=request.operation_id,
                )
            template_id = str(target["template_id"])
            if (
                request.operation
                in {
                    BrokerOperation.EPHEMERAL_RENEW,
                    BrokerOperation.EPHEMERAL_SECRET_FD,
                }
                and not bool(target["enabled"])
            ):
                raise BrokerError(
                    "control_binding_unavailable",
                    "The ephemeral template was disabled; this run may only be inspected or finished.",
                    operation_id=request.operation_id,
                )
            if request.operation is BrokerOperation.EPHEMERAL_SECRET_FD:
                arguments = request.arguments
                if (
                    arguments.get("run_id") != request.resource_id
                    or arguments.get("template_id") != template_id
                    or str(target["status"]) != "running"
                    or int(target["expires_at_epoch"]) <= int(time.time())
                    or str(target["credential_renewal_phase"]) != "none"
                ):
                    raise BrokerError(
                        "resource_access_denied",
                        "Credential delivery requires the exact current running ephemeral run.",
                        operation_id=request.operation_id,
                    )
        if not ephemeral_retained_access:
            grant = connection.execute(
                """
                SELECT enabled FROM broker_ephemeral_acl
                WHERE uid = ? AND repo_id = ? AND template_id = ?
                  AND operation = ?
                """,
                (peer.uid, request.project_id, template_id, request.operation.value),
            ).fetchone()
            if grant is None or not bool(grant["enabled"]):
                raise BrokerError(
                    "operation_access_denied",
                    "The authenticated account is not authorized for this ephemeral-container operation.",
                    operation_id=request.operation_id,
                )
        return target

    if request.operation is BrokerOperation.RUNTIME_REQUEST:
        _require_runtime_repository_context(
            connection, peer=peer, request=request
        )
        runtime_kind = str(request.arguments["target_kind"])
        _require_runtime_resource_membership(
            connection,
            repo_id=request.project_id,
            resource_kind=runtime_kind,
            resource_id=request.resource_id,
            operation_id=request.operation_id,
        )
        grant = connection.execute(
            """
            SELECT enabled FROM broker_runtime_acl
            WHERE uid = ? AND repo_id = ? AND resource_kind = ?
              AND resource_id = ? AND action = ?
            """,
            (
                peer.uid,
                request.project_id,
                runtime_kind,
                request.resource_id,
                request.arguments["action"],
            ),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this exact runtime action.",
                operation_id=request.operation_id,
            )
        return None
    if request.operation in _WORKER_OPERATIONS:
        definition = connection.execute(
            """
            SELECT definition.repo_id, policy.execution_uid
            FROM server_definitions definition
            LEFT JOIN worker_policies policy USING(server_definition_id)
            WHERE definition.server_definition_id = ?
            """,
            (request.resource_id,),
        ).fetchone()
        if definition is None or str(definition["repo_id"]) != request.project_id:
            raise BrokerError(
                "resource_access_denied",
                "The worker request does not target an exact server in the enrolled project.",
                operation_id=request.operation_id,
            )
        grant = connection.execute(
            """
            SELECT enabled FROM broker_worker_acl
            WHERE uid = ? AND repo_id = ? AND server_definition_id = ?
              AND operation = ?
            """,
            (
                peer.uid,
                request.project_id,
                request.resource_id,
                request.operation.value,
            ),
        ).fetchone()
        if grant is None or not bool(grant["enabled"]):
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for this exact worker operation.",
                operation_id=request.operation_id,
            )
        if definition["execution_uid"] is None:
            raise BrokerError(
                "worker_not_configured",
                "The exact server has no durable worker supervision policy.",
                operation_id=request.operation_id,
            )
        if int(definition["execution_uid"]) != peer.uid:
            raise BrokerError(
                "worker_execution_identity_mismatch",
                "The authenticated operating-system peer is not the worker policy execution identity.",
                operation_id=request.operation_id,
            )
        if request.operation in {
            BrokerOperation.WORKER_LAUNCHED,
            BrokerOperation.WORKER_EXIT,
            BrokerOperation.WORKER_ATTEMPT_READ,
        }:
            attempt = connection.execute(
                """
                SELECT repo_id, server_definition_id
                FROM worker_attempts WHERE attempt_id = ?
                """,
                (request.arguments["attempt_id"],),
            ).fetchone()
            if (
                attempt is None
                or str(attempt["repo_id"]) != request.project_id
                or str(attempt["server_definition_id"]) != request.resource_id
            ):
                raise BrokerError(
                    "worker_attempt_access_denied",
                    "The worker attempt does not belong to the exact enrolled project and server.",
                    operation_id=request.operation_id,
                )
        return definition
    if request.operation in _HOST_READ_OPERATIONS:
        # Host inventory visibility is read-only and host-wide for every
        # enrolled principal. Observation is an authoritative mutation and
        # therefore follows the explicit exact-repository ACL below.
        return None
    if request.operation in _TEST_OPERATIONS:
        # Repository enrollment is the complete authority for the universal
        # test journal. Runs and statistics can target only that exact repo;
        # result ownership is rechecked against the run row by the service.
        return None
    if request.operation in _HOST_OBSERVE_OPERATIONS:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_host_observation_acl
            WHERE uid = ? AND repo_id = ?
            """,
            (peer.uid, request.project_id),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized to refresh host observations.",
                operation_id=request.operation_id,
            )
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
    if request.operation in _ARCHIVE_READ_OPERATIONS:
        grant = connection.execute(
            """
            SELECT enabled FROM broker_cleanup_acl
            WHERE uid = ? AND repo_id = ? AND operation = ?
            """,
            (peer.uid, request.project_id, request.operation.value),
        ).fetchone()
        if grant is None or not grant["enabled"]:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized to read archives.",
                operation_id=request.operation_id,
            )
        return None
    if request.operation in _CLEANUP_OPERATIONS:
        acl_repo_id = request.project_id
        plan_row = None
        if request.operation is BrokerOperation.CLEANUP_APPLY:
            plan_row = connection.execute(
                """
                SELECT o.repo_id, o.kind, c.target_kind, c.target_id
                FROM operations o
                LEFT JOIN cleanup_plans c ON c.plan_id = o.operation_id
                WHERE o.operation_id = ?
                  AND (
                    c.plan_id IS NOT NULL
                    OR o.kind IN (
                      'repository_decommission',
                      'standalone_resource_retirement'
                    )
                  )
                """,
                (request.arguments["plan_id"],),
            ).fetchone()
            if plan_row is None or plan_row["repo_id"] is None:
                raise BrokerError(
                    "resource_access_denied",
                    "Cleanup plan has no authorized project boundary.",
                    operation_id=request.operation_id,
                )
            acl_repo_id = str(plan_row["repo_id"])
        project_cleanup = (
            request.operation is BrokerOperation.CLEANUP_PLAN
            and str(request.arguments.get("target_kind") or "") == "project"
        ) or (
            request.operation is BrokerOperation.CLEANUP_APPLY
            and plan_row is not None
            and (
                str(plan_row["kind"]) == "repository_decommission"
                or str(plan_row["target_kind"] or "") == "project"
            )
        )
        if project_cleanup:
            active_ephemeral = connection.execute(
                """
                SELECT 1 FROM ephemeral_container_runs
                WHERE repo_id = ? AND status NOT IN ('cleaned', 'failed')
                LIMIT 1
                """,
                (acl_repo_id,),
            ).fetchone()
            if active_ephemeral is not None:
                raise BrokerError(
                    "ephemeral_runs_active",
                    "Finish active broker-owned ephemeral runs before archiving or purging this project.",
                    operation_id=request.operation_id,
                )
        grant = connection.execute(
            """
            SELECT enabled FROM broker_cleanup_acl
            WHERE uid = ? AND repo_id = ? AND operation = ?
            """,
            (peer.uid, acl_repo_id, request.operation.value),
        ).fetchone()
        if (
            grant is None or not grant["enabled"]
        ) and not revoked_cleanup_replay:
            raise BrokerError(
                "operation_access_denied",
                "The authenticated account is not authorized for permanent cleanup.",
                operation_id=request.operation_id,
            )
        if request.operation in {
            BrokerOperation.CLEANUP_PLAN,
            BrokerOperation.LIFECYCLE_RESTORE,
        }:
            target_kind = str(request.arguments["target_kind"])
            target_id = str(request.arguments["target_id"])
            if target_kind in {"project", "worktree"}:
                owned = target_id == request.project_id
            else:
                owned = connection.execute(
                    """
                    SELECT 1 FROM repository_memberships
                    WHERE repo_id = ? AND resource_kind = ? AND host_resource_id = ?
                    UNION ALL
                    SELECT 1 FROM operations o
                    JOIN operation_targets t USING(operation_id)
                    WHERE o.repo_id = ? AND t.target_kind = ? AND t.target_id = ?
                    LIMIT 1
                    """,
                    (
                        request.project_id,
                        target_kind,
                        target_id,
                        request.project_id,
                        target_kind,
                        target_id,
                    ),
                ).fetchone() is not None
            if not owned:
                raise BrokerError(
                    "resource_access_denied",
                    "Cleanup target does not belong to the authorized project.",
                    operation_id=request.operation_id,
                )
            if (
                request.operation is BrokerOperation.LIFECYCLE_RESTORE
                and target_kind in {"server", "container"}
            ):
                exact_restore = connection.execute(
                    """
                    SELECT a.enabled
                    FROM broker_cleanup_resource_acl a
                    JOIN control_bindings b ON b.binding_id = a.control_binding_id
                    WHERE a.uid = ? AND a.repo_id = ?
                      AND a.resource_kind = ? AND a.resource_id = ?
                      AND a.operation = 'resource.restore' AND a.enabled = 1
                      AND b.resource_kind = a.resource_kind
                      AND b.resource_id = a.resource_id
                      AND b.authority_state = 'authoritative'
                    LIMIT 1
                    """,
                    (peer.uid, request.project_id, target_kind, target_id),
                ).fetchone()
                if exact_restore is None:
                    raise BrokerError(
                        "resource_access_denied",
                        "Resource restore requires an explicit exact restore grant.",
                        operation_id=request.operation_id,
                    )
        else:
            if plan_row is None:
                raise BrokerError(
                    "resource_access_denied",
                    "Cleanup plan has no authorized project boundary.",
                    operation_id=request.operation_id,
                )
        return None
    if request.operation in _LIFECYCLE_OPERATIONS:
        if request.operation in {
            BrokerOperation.REPOSITORY_PLAN_REMOVE,
            BrokerOperation.REPOSITORY_REMOVE,
        }:
            active_ephemeral = connection.execute(
                """
                SELECT 1 FROM ephemeral_container_runs
                WHERE repo_id = ? AND status NOT IN ('cleaned', 'failed')
                LIMIT 1
                """,
                (request.project_id,),
            ).fetchone()
            if active_ephemeral is not None:
                raise BrokerError(
                    "ephemeral_runs_active",
                    "Finish active broker-owned ephemeral runs before removing this repository.",
                    operation_id=request.operation_id,
                )
        canonical_resource_archive = request.operation in {
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
        }
        if not canonical_resource_archive:
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
        destructive_or_restore = request.operation in {
            BrokerOperation.REPOSITORY_PLAN_REMOVE,
            BrokerOperation.REPOSITORY_REMOVE,
            BrokerOperation.REPOSITORY_REINSTALL,
            BrokerOperation.RESOURCE_PLAN_RETIRE,
            BrokerOperation.RESOURCE_RETIRE,
            BrokerOperation.RESOURCE_PLAN_ARCHIVE,
            BrokerOperation.RESOURCE_ARCHIVE,
            BrokerOperation.RESOURCE_RESTORE,
        }
        if destructive_or_restore:
            cleanup_grant = connection.execute(
                """
                SELECT enabled FROM broker_cleanup_acl
                WHERE uid = ? AND repo_id = ? AND operation = ?
                """,
                (peer.uid, request.project_id, request.operation.value),
            ).fetchone()
            if cleanup_grant is None or not cleanup_grant["enabled"]:
                raise BrokerError(
                    "operation_access_denied",
                    "This archive, restore, or removal capability is default-deny and has not been explicitly granted.",
                    operation_id=request.operation_id,
                )
        if request.operation in _RESOURCE_LIFECYCLE_OPERATIONS:
            cleanup_resource_operation = canonical_resource_archive
            acl_table = (
                "broker_cleanup_resource_acl"
                if cleanup_resource_operation
                else "broker_lifecycle_resource_acl"
            )
            unassigned_join = (
                ""
                if cleanup_resource_operation
                else "JOIN unassigned_resources u ON u.resource_kind = a.resource_kind AND u.resource_id = a.resource_id"
            )
            unassigned_clause = "" if cleanup_resource_operation else "AND u.status = 'active'"
            exact = connection.execute(
                f"""
                SELECT a.enabled
                FROM {acl_table} a
                JOIN control_bindings b ON b.binding_id = a.control_binding_id
                JOIN coordinator_sources s ON s.source_id = b.source_id
                {unassigned_join}
                WHERE a.uid = ? AND a.repo_id = ?
                  AND a.resource_kind = ? AND a.resource_id = ?
                  AND a.control_binding_id = ?
                  AND a.immutable_fingerprint = ?
                  AND a.ownership_fingerprint = ?
                  AND a.operation = ?
                  AND b.resource_kind = a.resource_kind
                  AND b.resource_id = a.resource_id
                  AND b.authority_state = 'authoritative'
                  AND b.provenance != 'coordinator_ephemeral'
                  AND s.effective_uid = ?
                  {unassigned_clause}
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
                and request.operation in {
                    BrokerOperation.RESOURCE_RETIRE,
                    BrokerOperation.RESOURCE_ARCHIVE,
                }
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
    elif request.operation in _COMPOSE_OPERATIONS:
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
    elif request.operation in _COMPOSE_OPERATIONS:
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
        ttl = int(request.arguments.get("ttl_seconds", DEFAULT_PORT_LEASE_TTL_SECONDS))
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
    elif request.operation in _COMPOSE_START_OPERATIONS:
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
    if (
        connection.execute(
            "SELECT 1 FROM broker_acl_principals WHERE uid = ?", (uid,)
        ).fetchone()
        is None
    ):
        raise BrokerError("peer_not_authorized", "Broker principal is not provisioned.")


def _require_runtime_repository_context(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> None:
    """Prove the wire IDs describe one enrolled root/worktree family."""

    root_repo_id = str(request.arguments["root_repo_id"])
    temporary_repo_id = request.arguments["temporary_repo_id"]
    effective_repo_id = request.project_id
    if temporary_repo_id is None:
        if effective_repo_id != root_repo_id:
            raise BrokerError(
                "runtime_repository_context_mismatch",
                "The effective repository is not the declared root repository.",
                operation_id=request.operation_id,
            )
    elif effective_repo_id != str(temporary_repo_id):
        raise BrokerError(
            "runtime_repository_context_mismatch",
            "The effective repository is not the declared temporary repository.",
            operation_id=request.operation_id,
        )
    rows = list(
        connection.execute(
            """
            SELECT scope.repo_id, scope.family_id, scope.project_kind,
                   family.root_repo_id, repository.host_id, repository.state
            FROM repository_scopes scope
            JOIN repository_families family USING(family_id)
            JOIN repositories repository USING(repo_id)
            WHERE scope.repo_id IN (?, ?)
            ORDER BY scope.repo_id
            """,
            (root_repo_id, effective_repo_id),
        )
    )
    by_repo = {str(row["repo_id"]): row for row in rows}
    root = by_repo.get(root_repo_id)
    effective = by_repo.get(effective_repo_id)
    if (
        root is None
        or effective is None
        or str(root["project_kind"]) != "primary"
        or str(root["root_repo_id"]) != root_repo_id
        or str(effective["root_repo_id"]) != root_repo_id
        or str(root["family_id"]) != str(effective["family_id"])
        or str(root["host_id"]) != str(effective["host_id"])
        or str(root["state"]) != "active"
        or str(effective["state"]) != "active"
        or (
            temporary_repo_id is not None
            and str(effective["project_kind"]) != "temporary"
        )
    ):
        raise BrokerError(
            "runtime_repository_context_mismatch",
            "The runtime root/temporary repository IDs do not resolve to one active proved family.",
            operation_id=request.operation_id,
        )
    enrollment = connection.execute(
        """
        SELECT account_id, enabled, valid_until_epoch
        FROM broker_repository_enrollments
        WHERE uid = ? AND repo_id = ?
        """,
        (peer.uid, root_repo_id),
    ).fetchone()
    if (
        enrollment is None
        or not bool(enrollment["enabled"])
        or str(enrollment["account_id"]) != request.account_id
        or int(time.time()) >= int(enrollment["valid_until_epoch"])
    ):
        raise BrokerError(
            "runtime_root_enrollment_required",
            "The authenticated account has no current enrollment for the exact root repository.",
            operation_id=request.operation_id,
        )


def _require_runtime_resource_membership(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    resource_kind: str,
    resource_id: str,
    operation_id: Optional[str] = None,
) -> None:
    if resource_kind == "service":
        exists = connection.execute(
            """
            SELECT 1 FROM server_definitions definition
            WHERE definition.repo_id = ?
              AND definition.server_definition_id = ?
              AND NOT EXISTS (
                SELECT 1 FROM broker_server_revocations revoked
                WHERE revoked.repo_id = definition.repo_id
                  AND revoked.server_definition_id = definition.server_definition_id
              )
            """,
            (repo_id, resource_id),
        ).fetchone()
    elif resource_kind == "docker":
        exists = connection.execute(
            """
            SELECT 1
            FROM repository_memberships membership
            JOIN control_bindings binding
              ON binding.binding_id = membership.control_binding_id
            WHERE membership.repo_id = ?
              AND membership.resource_kind = 'container'
              AND membership.host_resource_id = ?
              AND binding.repo_id = membership.repo_id
              AND binding.resource_kind = 'container'
              AND binding.resource_id = membership.host_resource_id
              AND binding.authority_state = 'authoritative'
            """,
            (repo_id, resource_id),
        ).fetchone()
    elif resource_kind == "database_stack":
        exists = connection.execute(
            """
            SELECT 1
            FROM database_bindings database
            JOIN repository_memberships membership
              ON membership.repo_id = database.repo_id
             AND membership.resource_kind = 'container'
             AND membership.host_resource_id = database.docker_resource_id
            JOIN control_bindings binding
              ON binding.binding_id = membership.control_binding_id
            WHERE database.repo_id = ?
              AND database.database_binding_id = ?
              AND binding.repo_id = database.repo_id
              AND binding.resource_kind = 'container'
              AND binding.resource_id = database.docker_resource_id
              AND binding.authority_state = 'authoritative'
            """,
            (repo_id, resource_id),
        ).fetchone()
    else:
        raise ValueError("unsupported runtime resource kind")
    if exists is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Runtime target no longer has exact repository membership and control authority.",
            operation_id=operation_id,
        )


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
            SELECT 1 FROM server_definitions definition
            WHERE definition.server_definition_id = ?
              AND definition.repo_id = ?
              AND NOT EXISTS (
                SELECT 1 FROM broker_server_revocations revoked
                WHERE revoked.repo_id = definition.repo_id
                  AND revoked.server_definition_id = definition.server_definition_id
              )
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
              AND b.provenance != 'coordinator_ephemeral'
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


def _runtime_mutation_row(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
) -> sqlite3.Row:
    """Resolve one runtime target to its exact controlled Docker identity."""

    resource_kind = str(request.arguments["target_kind"])
    if resource_kind == "docker":
        rows = list(
            connection.execute(
                """
                SELECT 'docker' AS resource_kind,
                       d.docker_resource_id, d.full_container_id,
                       NULL AS database_binding_id, NULL AS database_name,
                       binding.generation AS control_generation,
                       metadata.observation_revision
                FROM docker_resources d
                JOIN docker_engines engine USING(engine_id)
                JOIN repositories repository
                  ON repository.repo_id = ?
                 AND repository.host_id = engine.host_id
                JOIN repository_memberships membership
                  ON membership.repo_id = repository.repo_id
                 AND membership.resource_kind = 'container'
                 AND membership.host_resource_id = d.docker_resource_id
                JOIN control_bindings binding
                  ON binding.binding_id = membership.control_binding_id
                 AND binding.repo_id = membership.repo_id
                 AND binding.resource_kind = 'container'
                 AND binding.resource_id = membership.host_resource_id
                 AND binding.authority_state = 'authoritative'
                CROSS JOIN schema_metadata metadata
                WHERE d.docker_resource_id = ?
                """,
                (request.project_id, request.resource_id),
            )
        )
    elif resource_kind == "database_stack":
        rows = list(
            connection.execute(
                """
                SELECT 'database_stack' AS resource_kind,
                       d.docker_resource_id, d.full_container_id,
                       database.database_binding_id, database.database_name,
                       binding.generation AS control_generation,
                       metadata.observation_revision
                FROM database_bindings database
                JOIN docker_resources d USING(docker_resource_id)
                JOIN docker_engines engine USING(engine_id)
                JOIN repositories repository
                  ON repository.repo_id = database.repo_id
                 AND repository.host_id = engine.host_id
                JOIN repository_memberships membership
                  ON membership.repo_id = repository.repo_id
                 AND membership.resource_kind = 'container'
                 AND membership.host_resource_id = d.docker_resource_id
                JOIN control_bindings binding
                  ON binding.binding_id = membership.control_binding_id
                 AND binding.repo_id = membership.repo_id
                 AND binding.resource_kind = 'container'
                 AND binding.resource_id = membership.host_resource_id
                 AND binding.authority_state = 'authoritative'
                CROSS JOIN schema_metadata metadata
                WHERE repository.repo_id = ?
                  AND database.database_binding_id = ?
                  AND database.engine_kind = 'postgresql'
                """,
                (request.project_id, request.resource_id),
            )
        )
    else:
        raise ValueError("runtime Docker mutation requires docker or database_stack")
    if len(rows) != 1:
        raise BrokerError(
            "control_binding_unavailable",
            "Runtime target no longer resolves to one exact controlled Docker identity.",
            operation_id=request.operation_id,
        )
    row = rows[0]
    if re.fullmatch(r"[0-9a-fA-F]{64}", str(row["full_container_id"])) is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Runtime target has no immutable full Docker identity.",
            operation_id=request.operation_id,
        )
    return row


def _runtime_target_fingerprint(
    row: Mapping[str, Any], *, requested_resource_id: str
) -> str:
    material = {
        "resource_kind": str(row["resource_kind"]),
        "resource_id": requested_resource_id,
        "docker_resource_id": str(row["docker_resource_id"]),
        "full_container_id": str(row["full_container_id"]).lower(),
        "database_binding_id": row["database_binding_id"],
        "database_name": row["database_name"],
        "control_generation": int(row["control_generation"]),
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


def _runtime_operation_target(
    connection: sqlite3.Connection, *, request: BrokerRequest
) -> tuple[str, str, str, str]:
    row = _runtime_mutation_row(connection, request=request)
    return (
        "container",
        str(row["docker_resource_id"]),
        "runtime." + str(request.arguments["action"]),
        _runtime_target_fingerprint(row, requested_resource_id=request.resource_id),
    )


def _reserved_target_fingerprint(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
    fallback: str,
) -> str:
    if (
        request.operation is BrokerOperation.RUNTIME_REQUEST
        and request.arguments["action"] in {"start", "stop", "restart"}
        and request.arguments["target_kind"] in {"docker", "database_stack"}
    ):
        return _runtime_operation_target(connection, request=request)[3]
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
    if request.operation in _COMPOSE_OPERATIONS:
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
    if request.operation in _EPHEMERAL_OPERATIONS:
        if request.operation in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        }:
            row = connection.execute(
                """
                SELECT definition_fingerprint
                FROM ephemeral_container_templates
                WHERE template_id = ? AND repo_id = ? AND enabled = 1
                """,
                (request.resource_id, request.project_id),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT template_fingerprint AS definition_fingerprint
                FROM ephemeral_container_runs
                WHERE run_id = ? AND repo_id = ?
                """,
                (request.resource_id, request.project_id),
            ).fetchone()
        if row is None:
            raise BrokerError(
                "control_binding_unavailable",
                "Ephemeral target no longer belongs to the exact repository authority.",
                operation_id=request.operation_id,
            )
        return str(row["definition_fingerprint"])
    if request.operation in _DOCKER_OPERATIONS:
        row = connection.execute(
            """
            SELECT resource.full_container_id
            FROM docker_resources resource
            JOIN docker_engines engine USING(engine_id)
            JOIN repositories repository
              ON repository.host_id = engine.host_id
            WHERE resource.docker_resource_id = ?
              AND repository.repo_id = ?
            """,
            (request.resource_id, request.project_id),
        ).fetchone()
        if row is None or re.fullmatch(
            r"[0-9a-fA-F]{64}", str(row["full_container_id"])
        ) is None:
            raise BrokerError(
                "control_binding_unavailable",
                "Docker target no longer belongs to the exact repository host.",
                operation_id=request.operation_id,
            )
        return str(row["full_container_id"]).lower()
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
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                material,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )


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
_COMPOSE_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


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


def _require_compose_profile_name(value: str) -> str:
    if not isinstance(value, str) or _COMPOSE_PROFILE_NAME.fullmatch(value) is None:
        raise ValueError(
            "Compose profile names must be bounded identifiers and cannot be options"
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
    canonical_root: str,
    root_identity: Mapping[str, int],
    cwd: str,
    cwd_identity: Mapping[str, int],
    compose_files: Iterable[str],
    compose_file_evidence: Iterable[Mapping[str, Any]],
    env_files: Iterable[str],
    env_file_evidence: Iterable[Mapping[str, Any]],
    profiles: Iterable[str],
    services: Iterable[str],
    project_name: str,
) -> str:
    encoded = json.dumps(
        {
            "repo_id": repo_id,
            "canonical_root": canonical_root,
            "root_identity": dict(root_identity),
            "cwd": cwd,
            "cwd_identity": dict(cwd_identity),
            "files": list(compose_files),
            "file_evidence": [dict(item) for item in compose_file_evidence],
            "env_files": list(env_files),
            "env_file_evidence": [dict(item) for item in env_file_evidence],
            "profiles": list(profiles),
            "services": list(services),
            "project_name": project_name,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _legacy_compose_definition_fingerprint(
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


def _migrate_legacy_compose_definition_fingerprints(
    connection: sqlite3.Connection,
) -> None:
    """Upgrade only definitions that exactly match the former hash contract."""

    now = utc_timestamp()
    definitions = list(
        connection.execute(
            """
            SELECT definition.compose_definition_id, definition.repo_id,
                   definition.cwd, definition.project_name,
                   definition.definition_fingerprint,
                   repository.canonical_root,
                   identity.root_device, identity.root_inode,
                   identity.cwd_device, identity.cwd_inode
            FROM broker_compose_definitions definition
            JOIN repositories repository USING(repo_id)
            LEFT JOIN broker_compose_directory_identity identity
              USING(compose_definition_id)
            ORDER BY compose_definition_id
            """
        )
    )
    for definition in definitions:
        if any(
            definition[name] is None
            for name in (
                "root_device",
                "root_inode",
                "cwd_device",
                "cwd_inode",
            )
        ):
            continue
        definition_id = str(definition["compose_definition_id"])
        files = tuple(
            str(row["file_path"])
            for row in connection.execute(
                """
                SELECT file_path FROM broker_compose_files
                WHERE compose_definition_id = ? ORDER BY ordinal
                """,
                (definition_id,),
            )
        )
        file_evidence = tuple(
            {
                "content_sha256": str(row["content_sha256"]),
                "byte_size": int(row["byte_size"]),
            }
            for row in connection.execute(
                """
                SELECT content_sha256, byte_size
                FROM broker_compose_file_evidence
                WHERE compose_definition_id = ? ORDER BY ordinal
                """,
                (definition_id,),
            )
        )
        services = tuple(
            str(row["service_name"])
            for row in connection.execute(
                """
                SELECT service_name FROM broker_compose_services
                WHERE compose_definition_id = ? ORDER BY ordinal
                """,
                (definition_id,),
            )
        )
        env_count = int(
            connection.execute(
                """
                SELECT count(*) FROM broker_compose_env_files
                WHERE compose_definition_id = ?
                """,
                (definition_id,),
            ).fetchone()[0]
        )
        profile_count = int(
            connection.execute(
                """
                SELECT count(*) FROM broker_compose_profiles
                WHERE compose_definition_id = ?
                """,
                (definition_id,),
            ).fetchone()[0]
        )
        if not files or len(file_evidence) != len(files) or env_count or profile_count:
            continue
        legacy = _legacy_compose_definition_fingerprint(
            repo_id=str(definition["repo_id"]),
            cwd=str(definition["cwd"]),
            compose_files=files,
            compose_file_evidence=file_evidence,
            services=services,
            project_name=str(definition["project_name"]),
        )
        if str(definition["definition_fingerprint"]) != legacy:
            continue
        upgraded = _compose_definition_fingerprint(
            repo_id=str(definition["repo_id"]),
            canonical_root=str(definition["canonical_root"]),
            root_identity={
                "device": int(definition["root_device"]),
                "inode": int(definition["root_inode"]),
            },
            cwd=str(definition["cwd"]),
            cwd_identity={
                "device": int(definition["cwd_device"]),
                "inode": int(definition["cwd_inode"]),
            },
            compose_files=files,
            compose_file_evidence=file_evidence,
            env_files=(),
            env_file_evidence=(),
            profiles=(),
            services=services,
            project_name=str(definition["project_name"]),
        )
        if upgraded == legacy:
            continue
        affected_operations = tuple(
            str(row["operation_id"])
            for row in connection.execute(
                """
                SELECT operation.operation_id
                FROM operations operation
                JOIN operation_targets target USING(operation_id)
                WHERE target.target_kind = 'compose'
                  AND target.target_id = ?
                  AND operation.status IN ('planned', 'running')
                ORDER BY operation.operation_id
                """,
                (definition_id,),
            )
        )
        if affected_operations:
            placeholders = ",".join("?" for _item in affected_operations)
            connection.execute(
                f"""
                UPDATE operations
                SET status = 'needs_attention',
                    phase = 'reconciliation_required',
                    generation = generation + 1,
                    error_code = 'compose_definition_migrated',
                    error_message =
                        'Compose definition contract changed while this operation was pending; reconcile its host outcome before retrying.',
                    updated_at = ?
                WHERE operation_id IN ({placeholders})
                """,
                (now, *affected_operations),
            )
            connection.execute(
                f"""
                UPDATE operation_targets
                SET phase = 'reconciliation_required',
                    error_json = ?
                WHERE operation_id IN ({placeholders})
                  AND target_kind = 'compose'
                  AND target_id = ?
                """,
                (
                    json.dumps(
                        {
                            "code": "compose_definition_migrated",
                            "message": "Host outcome requires reconciliation after definition migration.",
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    *affected_operations,
                    definition_id,
                ),
            )
        connection.execute(
            """
            UPDATE broker_compose_definitions
            SET definition_fingerprint = ?, generation = generation + 1,
                updated_at = ?
            WHERE compose_definition_id = ? AND definition_fingerprint = ?
            """,
            (upgraded, now, definition_id, legacy),
        )


def _disable_legacy_unscoped_compose_definitions(
    connection: sqlite3.Connection,
) -> None:
    """Fence legacy definitions whose empty service set widens Compose scope."""

    now = utc_timestamp()
    definition_ids = tuple(
        str(row["compose_definition_id"])
        for row in connection.execute(
            """
            SELECT definition.compose_definition_id
            FROM broker_compose_definitions definition
            WHERE NOT EXISTS (
                SELECT 1 FROM broker_compose_services service
                WHERE service.compose_definition_id =
                      definition.compose_definition_id
            )
            ORDER BY definition.compose_definition_id
            """
        )
    )
    if not definition_ids:
        return
    placeholders = ",".join("?" for _item in definition_ids)
    connection.execute(
        f"""
        UPDATE broker_compose_definitions
        SET enabled = 0, generation = generation + 1, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    connection.execute(
        f"""
        UPDATE broker_compose_acl
        SET enabled = 0, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    affected_operations = tuple(
        str(row["operation_id"])
        for row in connection.execute(
            f"""
            SELECT operation.operation_id
            FROM operations operation
            JOIN operation_targets target USING(operation_id)
            WHERE target.target_kind = 'compose'
              AND target.target_id IN ({placeholders})
              AND operation.status IN ('planned', 'running')
            ORDER BY operation.operation_id
            """,
            definition_ids,
        )
    )
    if not affected_operations:
        return
    operation_placeholders = ",".join("?" for _item in affected_operations)
    connection.execute(
        f"""
        UPDATE operations
        SET status = 'needs_attention', phase = 'reconciliation_required',
            error_code = 'compose_service_scope_required',
            error_message =
                'Legacy Compose definition had no exact service scope; reenroll it before mutation.',
            updated_at = ?, generation = generation + 1
        WHERE operation_id IN ({operation_placeholders})
        """,
        (now, *affected_operations),
    )
    connection.execute(
        f"""
        UPDATE operation_targets
        SET phase = 'reconciliation_required', error_json = ?
        WHERE operation_id IN ({operation_placeholders})
          AND target_kind = 'compose'
        """,
        (
            json.dumps(
                {
                    "code": "compose_service_scope_required",
                    "message": "Exact Compose service scope requires reenrollment.",
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ),
            *affected_operations,
        ),
    )


def _disable_unpinned_compose_definitions(
    connection: sqlite3.Connection,
) -> None:
    """Fence definitions created before directory identities were persisted."""

    now = utc_timestamp()
    definition_ids = tuple(
        str(row["compose_definition_id"])
        for row in connection.execute(
            """
            SELECT definition.compose_definition_id
            FROM broker_compose_definitions definition
            LEFT JOIN broker_compose_directory_identity identity
              USING(compose_definition_id)
            WHERE identity.compose_definition_id IS NULL
            ORDER BY definition.compose_definition_id
            """
        )
    )
    if not definition_ids:
        return
    placeholders = ",".join("?" for _item in definition_ids)
    connection.execute(
        f"""
        UPDATE broker_compose_definitions
        SET enabled = 0, generation = generation + 1, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    connection.execute(
        f"""
        UPDATE broker_compose_acl
        SET enabled = 0, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    affected_operations = tuple(
        str(row["operation_id"])
        for row in connection.execute(
            f"""
            SELECT operation.operation_id
            FROM operations operation
            JOIN operation_targets target USING(operation_id)
            WHERE target.target_kind = 'compose'
              AND target.target_id IN ({placeholders})
              AND operation.status IN ('planned', 'running')
            ORDER BY operation.operation_id
            """,
            definition_ids,
        )
    )
    if not affected_operations:
        return
    operation_placeholders = ",".join("?" for _item in affected_operations)
    connection.execute(
        f"""
        UPDATE operations
        SET status = 'needs_attention', phase = 'reconciliation_required',
            error_code = 'compose_directory_identity_required',
            error_message =
                'Legacy Compose definition has no pinned directory identity; reenroll it before mutation.',
            updated_at = ?, generation = generation + 1
        WHERE operation_id IN ({operation_placeholders})
        """,
        (now, *affected_operations),
    )
    connection.execute(
        f"""
        UPDATE operation_targets
        SET phase = 'reconciliation_required', error_json = ?
        WHERE operation_id IN ({operation_placeholders})
          AND target_kind = 'compose'
        """,
        (
            json.dumps(
                {
                    "code": "compose_directory_identity_required",
                    "message": "Pinned Compose directory identity requires reenrollment.",
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ),
            *affected_operations,
        ),
    )


def _disable_unvalidated_effective_compose_definitions(
    connection: sqlite3.Connection,
) -> None:
    """Fence definitions lacking an exact merged-model enrollment proof."""

    now = utc_timestamp()
    definition_ids = tuple(
        str(row["compose_definition_id"])
        for row in connection.execute(
            """
            SELECT definition.compose_definition_id
            FROM broker_compose_definitions definition
            LEFT JOIN broker_compose_effective_model_evidence evidence
              USING(compose_definition_id)
            WHERE evidence.compose_definition_id IS NULL
               OR evidence.definition_fingerprint !=
                  definition.definition_fingerprint
               OR evidence.service_replicas_json = '{}'
            ORDER BY definition.compose_definition_id
            """
        )
    )
    if not definition_ids:
        return
    placeholders = ",".join("?" for _item in definition_ids)
    connection.execute(
        f"""
        UPDATE broker_compose_definitions
        SET enabled = 0, generation = generation + 1, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    connection.execute(
        f"""
        UPDATE broker_compose_acl
        SET enabled = 0, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    affected_operations = tuple(
        str(row["operation_id"])
        for row in connection.execute(
            f"""
            SELECT operation.operation_id
            FROM operations operation
            JOIN operation_targets target USING(operation_id)
            WHERE target.target_kind = 'compose'
              AND target.target_id IN ({placeholders})
              AND operation.status IN ('planned', 'running')
            ORDER BY operation.operation_id
            """,
            definition_ids,
        )
    )
    if not affected_operations:
        return
    operation_placeholders = ",".join("?" for _item in affected_operations)
    connection.execute(
        f"""
        UPDATE operations
        SET status = 'needs_attention', phase = 'reconciliation_required',
            error_code = 'compose_effective_model_required',
            error_message =
                'Compose definition lacks a bound merged-model proof; reenroll it before mutation.',
            updated_at = ?, generation = generation + 1
        WHERE operation_id IN ({operation_placeholders})
        """,
        (now, *affected_operations),
    )
    connection.execute(
        f"""
        UPDATE operation_targets
        SET phase = 'reconciliation_required', error_json = ?
        WHERE operation_id IN ({operation_placeholders})
          AND target_kind = 'compose'
        """,
        (
            json.dumps(
                {
                    "code": "compose_effective_model_required",
                    "message": "Merged effective Compose validation requires reenrollment.",
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ),
            *affected_operations,
        ),
    )


def _backfill_compose_project_claims(connection: sqlite3.Connection) -> None:
    """Retain every legacy name claim until an explicit empty-host proof."""

    now = utc_timestamp()
    connection.execute(
        """
        INSERT INTO broker_compose_project_claims(
            compose_definition_id, project_name, claimed,
            release_snapshot_id, released_at, updated_at
        )
        SELECT definition.compose_definition_id, definition.project_name,
               1, NULL, NULL, ?
        FROM broker_compose_definitions definition
        LEFT JOIN broker_compose_project_claims claim
          USING(compose_definition_id)
        WHERE claim.compose_definition_id IS NULL
        """,
        (now,),
    )


def _require_observed_compose_project_name_available(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    repo_id: str,
    project_name: str,
) -> None:
    _require_complete_compose_asset_scope(connection, snapshot_id=snapshot_id)
    rows = list(
        connection.execute(
            """
            SELECT docker_resource_id, ownership_state,
                   authoritative_owner_repo_id
            FROM broker_observed_compose_containers
            WHERE snapshot_id = ? AND project_name = ?
            ORDER BY docker_resource_id
            """,
            (snapshot_id, project_name),
        )
    )
    exact_owned_container_seen = bool(rows)
    for row in rows:
        if (
            str(row["ownership_state"]) != "exclusive"
            or str(row["authoritative_owner_repo_id"] or "") != repo_id
        ):
            raise BrokerError(
                "compose_project_name_conflict",
                "Observed Compose project name is not exclusively owned by this repository.",
            )
    retained_asset = connection.execute(
        """
        SELECT asset_kind, asset_id
        FROM broker_observed_compose_assets
        WHERE snapshot_id = ? AND project_name = ?
        ORDER BY asset_kind, asset_id
        LIMIT 1
        """,
        (snapshot_id, project_name),
    ).fetchone()
    prior_definition = connection.execute(
        """
        SELECT 1 FROM broker_compose_definitions
        WHERE repo_id = ? AND project_name = ? AND enabled = 1
        LIMIT 1
        """,
        (repo_id, project_name),
    ).fetchone()
    if (
        retained_asset is not None
        and prior_definition is None
        and not exact_owned_container_seen
    ):
        raise BrokerError(
            "compose_project_name_conflict",
            "Observed retained Compose network or volume has no prior broker definition or authoritative same-project container ownership.",
        )


def _require_observed_compose_project_name_absent(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    project_name: str,
) -> None:
    _require_complete_compose_asset_scope(connection, snapshot_id=snapshot_id)
    retained = connection.execute(
        """
        SELECT 1 FROM broker_observed_compose_containers
        WHERE snapshot_id = ? AND project_name = ?
        LIMIT 1
        """,
        (snapshot_id, project_name),
    ).fetchone()
    if retained is not None:
        raise BrokerError(
            "compose_project_name_change_blocked",
            "The old Compose project name still has observed host resources; retire them explicitly before changing project identity.",
        )
    retained_asset = connection.execute(
        """
        SELECT 1 FROM broker_observed_compose_assets
        WHERE snapshot_id = ? AND project_name = ?
        LIMIT 1
        """,
        (snapshot_id, project_name),
    ).fetchone()
    if retained_asset is not None:
        raise BrokerError(
            "compose_project_name_change_blocked",
            "The old Compose project name still has a retained network or volume; retire it explicitly before changing project identity.",
        )


def _require_complete_compose_asset_scope(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
) -> None:
    scope = connection.execute(
        """
        SELECT assets_complete
        FROM broker_observation_compose_scope
        WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if scope is None or not bool(scope["assets_complete"]):
        raise BrokerError(
            "compose_collision_observation_incomplete",
            "Full-Docker observation did not prove exhaustive Compose network and volume visibility.",
        )


def _require_no_unresolved_compose_operation(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
) -> None:
    unresolved = connection.execute(
        """
        SELECT operation.operation_id, operation.status
        FROM operations operation
        JOIN operation_targets target USING(operation_id)
        JOIN broker_compose_definitions target_definition
          ON target_definition.compose_definition_id = target.target_id
        JOIN repositories target_repository
          ON target_repository.repo_id = target_definition.repo_id
        JOIN broker_compose_definitions requested_definition
          ON requested_definition.compose_definition_id = ?
        JOIN repositories requested_repository
          ON requested_repository.repo_id = requested_definition.repo_id
        WHERE target.target_kind = 'compose'
          AND (
              target.target_id = ?
              OR (
                  target_definition.project_name =
                      requested_definition.project_name
                  AND target_repository.host_id = requested_repository.host_id
              )
          )
          AND operation.operation_id != ?
          AND operation.status IN (
              'planned', 'running', 'partial', 'needs_attention'
          )
        ORDER BY operation.created_at, operation.operation_id
        LIMIT 1
        """,
        (request.resource_id, request.resource_id, request.operation_id),
    ).fetchone()
    if unresolved is not None:
        unresolved_operation_id = str(unresolved["operation_id"])
        raise BrokerError(
            "compose_operation_pending",
            "A prior Compose operation for this exact definition requires "
            "completion or reconciliation: operation_id="
            + unresolved_operation_id
            + ".",
            operation_id=request.operation_id,
        )


def _require_no_unresolved_docker_operation(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
) -> None:
    _require_no_unresolved_container_operation(
        connection,
        docker_resource_id=request.resource_id,
        operation_id=request.operation_id,
    )


def _require_no_unresolved_container_operation(
    connection: sqlite3.Connection,
    *,
    docker_resource_id: str,
    operation_id: str,
) -> None:
    unresolved = connection.execute(
        """
        SELECT operation.operation_id
        FROM operations operation
        JOIN operation_targets target USING(operation_id)
        WHERE target.target_kind = 'container'
          AND target.target_id = ?
          AND target.action IN (
              'docker.start', 'docker.stop', 'docker.restart',
              'runtime.start', 'runtime.stop', 'runtime.restart'
          )
          AND operation.operation_id != ?
          AND operation.status IN (
              'planned', 'running', 'partial', 'needs_attention'
          )
        ORDER BY operation.created_at, operation.operation_id
        LIMIT 1
        """,
        (docker_resource_id, operation_id),
    ).fetchone()
    if unresolved is not None:
        raise BrokerError(
            "docker_operation_pending",
            "A prior Docker lifecycle operation for this exact container requires completion or reconciliation.",
            operation_id=operation_id,
        )


def _require_no_unresolved_compose_definition_change(
    connection: sqlite3.Connection,
    *,
    compose_definition_ids: Iterable[str],
) -> None:
    definition_ids = tuple(compose_definition_ids)
    if not definition_ids:
        return
    placeholders = ",".join("?" for _item in definition_ids)
    unresolved = connection.execute(
        f"""
        SELECT operation.operation_id
        FROM operations operation
        JOIN operation_targets target USING(operation_id)
        WHERE target.target_kind = 'compose'
          AND target.target_id IN ({placeholders})
          AND operation.status IN (
              'planned', 'running', 'partial', 'needs_attention'
          )
        ORDER BY operation.created_at, operation.operation_id
        LIMIT 1
        """,
        definition_ids,
    ).fetchone()
    if unresolved is not None:
        raise BrokerError(
            "compose_operation_pending",
            "Compose definition cannot change while an operation requires completion or reconciliation.",
        )


def _require_string_list_evidence(
    value: Any,
    *,
    field: str,
    operation_id: str | None,
) -> tuple[str, ...]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError) as exc:
        raise BrokerError(
            "compose_effective_model_required",
            f"Persisted Compose {field} evidence is invalid.",
            operation_id=operation_id,
        ) from exc
    if (
        not isinstance(decoded, list)
        or any(not isinstance(item, str) or not item for item in decoded)
        or decoded != sorted(set(decoded))
    ):
        raise BrokerError(
            "compose_effective_model_required",
            f"Persisted Compose {field} evidence is invalid.",
            operation_id=operation_id,
        )
    return tuple(decoded)


def _require_service_replica_evidence(
    value: Any,
    *,
    services: tuple[str, ...],
    operation_id: str | None,
) -> tuple[tuple[str, int], ...]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError) as exc:
        raise BrokerError(
            "compose_effective_model_required",
            "Persisted Compose replica evidence is invalid.",
            operation_id=operation_id,
        ) from exc
    if (
        not isinstance(decoded, dict)
        or tuple(sorted(decoded)) != tuple(sorted(services))
        or any(
            not isinstance(name, str) or type(count) is not int or not 1 <= count <= 16
            for name, count in decoded.items()
        )
        or sum(decoded.values()) > 64
    ):
        raise BrokerError(
            "compose_effective_model_required",
            "Persisted Compose replica evidence is invalid.",
            operation_id=operation_id,
        )
    return tuple(sorted((str(name), int(count)) for name, count in decoded.items()))


def _compose_definition_scope_connection(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    compose_definition_id: str,
    operation_id: str | None,
    require_effective_model_evidence: bool = True,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT definition.compose_definition_id, definition.repo_id,
               definition.project_name, definition.definition_fingerprint,
               definition.enabled, repository.host_id,
               evidence.compose_definition_id AS effective_model_evidence_id,
               evidence.service_replicas_json
        FROM broker_compose_definitions definition
        JOIN repositories repository USING(repo_id)
        LEFT JOIN broker_compose_effective_model_evidence evidence
          USING(compose_definition_id)
        WHERE definition.compose_definition_id = ?
          AND definition.repo_id = ?
        """,
        (compose_definition_id, repo_id),
    ).fetchone()
    if row is None:
        raise BrokerError(
            "compose_definition_invalid",
            "Compose definition no longer belongs to the exact repository.",
            operation_id=operation_id,
        )
    services = tuple(
        str(service["service_name"])
        for service in connection.execute(
            """
            SELECT service_name FROM broker_compose_services
            WHERE compose_definition_id = ? ORDER BY ordinal
            """,
            (compose_definition_id,),
        )
    )
    legacy_missing_evidence = (
        not bool(row["enabled"])
        and (
            row["effective_model_evidence_id"] is None
            or row["service_replicas_json"] in {None, "{}"}
        )
    )
    if not require_effective_model_evidence and legacy_missing_evidence:
        service_replicas = ()
        effective_model_evidence_valid = False
    else:
        service_replicas = _require_service_replica_evidence(
            row["service_replicas_json"],
            services=services,
            operation_id=operation_id,
        )
        effective_model_evidence_valid = True
    return {
        **dict(row),
        "services": services,
        "service_replicas": service_replicas,
        "effective_model_evidence_valid": effective_model_evidence_valid,
    }


def _compose_reconciliation_candidate_connection(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT operation.operation_id, operation.repo_id, operation.kind,
               operation.status, operation.phase, operation.error_code,
               operation.result_json, request.repo_id AS request_repo_id,
               request.resource_id AS request_resource_id,
               request.operation AS request_operation,
               target.target_kind, target.target_id, target.action,
               target.immutable_fingerprint AS target_fingerprint,
               target.phase AS target_phase, target.status AS target_status,
               definition.repo_id AS definition_repo_id,
               definition.project_name,
               definition.definition_fingerprint AS current_fingerprint,
               definition.enabled, repository.host_id
        FROM operations operation
        JOIN broker_operation_requests request USING(operation_id)
        JOIN operation_targets target
          ON target.operation_id = operation.operation_id
         AND target.ordinal = 0
        JOIN broker_compose_definitions definition
          ON definition.compose_definition_id = target.target_id
        JOIN repositories repository
          ON repository.repo_id = definition.repo_id
        WHERE operation.operation_id = ?
        """,
        (operation_id,),
    ).fetchone()
    allowed_codes = {"operation_outcome_uncertain"} | set(
        _LEGACY_COMPOSE_RECONCILIATION_CODES
    )
    if (
        row is None
        or str(row["status"]) != "needs_attention"
        or str(row["phase"]) != "reconciliation_required"
        or str(row["target_phase"]) != "reconciliation_required"
        or str(row["target_kind"]) != "compose"
        or str(row["error_code"] or "") not in allowed_codes
        or str(row["repo_id"] or "") != str(row["request_repo_id"] or "")
        or str(row["repo_id"] or "") != str(row["definition_repo_id"] or "")
        or str(row["request_resource_id"]) != str(row["target_id"])
        or str(row["request_operation"]) != str(row["action"])
        or str(row["kind"]) != "broker." + str(row["action"])
        or str(row["action"])
        not in {
            "compose.up",
            "compose.stop",
            "compose.restart",
            "compose.down",
        }
        or (
            str(row["error_code"] or "") == "operation_outcome_uncertain"
            and str(row["target_status"]) != "failed"
        )
        or (
            str(row["error_code"] or "")
            in _LEGACY_COMPOSE_RECONCILIATION_CODES
            and str(row["target_status"]) not in {"pending", "running", "failed"}
        )
    ):
        raise BrokerError(
            "compose_reconciliation_unavailable",
            "Operation is not one exact administratively reconcilable Compose outcome.",
            operation_id=operation_id,
        )
    definition = _compose_definition_scope_connection(
        connection,
        repo_id=str(row["repo_id"]),
        compose_definition_id=str(row["target_id"]),
        operation_id=operation_id,
        require_effective_model_evidence=False,
    )
    try:
        decoded = json.loads(str(row["result_json"] or "{}"))
    except json.JSONDecodeError as exc:
        raise BrokerError(
            "operation_evidence_corrupt",
            "Compose uncertainty evidence is not valid JSON.",
            operation_id=operation_id,
        ) from exc
    if not isinstance(decoded, dict):
        raise BrokerError(
            "operation_evidence_corrupt",
            "Compose uncertainty evidence has an invalid shape.",
            operation_id=operation_id,
        )
    action = str(row["action"]).removeprefix("compose.")
    if (
        row["error_code"] == "operation_outcome_uncertain"
        and decoded.get("action") != action
    ):
        raise BrokerError(
            "operation_evidence_corrupt",
            "Compose uncertainty evidence does not match its durable action.",
            operation_id=operation_id,
        )
    scope_failures: list[str] = []
    if not bool(definition["effective_model_evidence_valid"]):
        scope_failures.append("effective_model_evidence_invalid")
    if str(row["error_code"]) != "operation_outcome_uncertain":
        scope_failures.append("legacy_definition_migration")
    if str(row["current_fingerprint"]) != str(row["target_fingerprint"]):
        scope_failures.append("definition_fingerprint_changed")
    if not bool(row["enabled"]):
        scope_failures.append("definition_disabled")
    if not definition["services"]:
        scope_failures.append("service_scope_missing")
    return {
        "operation_id": operation_id,
        "repo_id": str(row["repo_id"]),
        "host_id": str(row["host_id"]),
        "compose_definition_id": str(row["target_id"]),
        "project_name": str(row["project_name"]),
        "action": action,
        "target_fingerprint": str(row["target_fingerprint"]),
        "current_fingerprint": str(row["current_fingerprint"]),
        "services": tuple(definition["services"]),
        "service_replicas": tuple(definition["service_replicas"]),
        "uncertain_outcome": decoded,
        "scope_recoverable": not scope_failures,
        "scope_failure_reason": ",".join(scope_failures) or None,
    }


def _docker_reconciliation_candidate_connection(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT operation.operation_id, operation.repo_id, operation.kind,
               operation.status, operation.phase, operation.error_code,
               operation.result_json, request.repo_id AS request_repo_id,
               request.resource_id AS request_resource_id,
               request.operation AS request_operation,
               target.target_kind, target.target_id, target.action,
               target.immutable_fingerprint AS target_fingerprint,
               target.phase AS target_phase, target.status AS target_status,
               resource.full_container_id, engine.host_id,
               repository.host_id AS repository_host_id
        FROM operations operation
        JOIN broker_operation_requests request USING(operation_id)
        JOIN operation_targets target
          ON target.operation_id = operation.operation_id
         AND target.ordinal = 0
        JOIN docker_resources resource
          ON resource.docker_resource_id = target.target_id
        JOIN docker_engines engine USING(engine_id)
        JOIN repositories repository
          ON repository.repo_id = operation.repo_id
        WHERE operation.operation_id = ?
        """,
        (operation_id,),
    ).fetchone()
    if (
        row is None
        or str(row["status"]) != "needs_attention"
        or str(row["phase"]) != "reconciliation_required"
        or str(row["error_code"] or "") != "operation_outcome_uncertain"
        or str(row["target_phase"]) != "reconciliation_required"
        or str(row["target_status"]) != "failed"
        or str(row["target_kind"]) != "container"
        or str(row["repo_id"] or "") != str(row["request_repo_id"] or "")
        or str(row["request_resource_id"]) != str(row["target_id"])
        or str(row["request_operation"]) != str(row["action"])
        or str(row["kind"]) != "broker." + str(row["action"])
        or str(row["action"])
        not in {"docker.start", "docker.stop", "docker.restart"}
        or str(row["host_id"]) != str(row["repository_host_id"])
    ):
        raise BrokerError(
            "docker_reconciliation_unavailable",
            "Operation is not one exact administratively reconcilable direct Docker outcome.",
            operation_id=operation_id,
        )
    full_container_id = str(row["full_container_id"]).lower()
    if re.fullmatch(r"[0-9a-f]{64}", full_container_id) is None:
        raise BrokerError(
            "docker_reconciliation_identity_invalid",
            "Persisted Docker target does not have one immutable 64-character container ID.",
            operation_id=operation_id,
        )
    try:
        decoded = json.loads(str(row["result_json"] or "{}"))
    except json.JSONDecodeError as exc:
        raise BrokerError(
            "operation_evidence_corrupt",
            "Direct Docker uncertainty evidence is not valid JSON.",
            operation_id=operation_id,
        ) from exc
    if (
        not isinstance(decoded, dict)
        or decoded.get("action") != str(row["action"])
        or decoded.get("completion_unknown") is not True
    ):
        raise BrokerError(
            "operation_evidence_corrupt",
            "Direct Docker uncertainty evidence does not match its durable action.",
            operation_id=operation_id,
        )
    return {
        "operation_id": operation_id,
        "repo_id": str(row["repo_id"]),
        "host_id": str(row["host_id"]),
        "docker_resource_id": str(row["target_id"]),
        "action": str(row["action"]).removeprefix("docker."),
        "full_container_id": full_container_id,
        "identity_reservation_kind": (
            "full_container_id"
            if str(row["target_fingerprint"]).lower() == full_container_id
            else "legacy_authenticated_request_fingerprint"
        ),
        "uncertain_outcome": decoded,
    }


def _compose_action_observation_proof(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    repo_id: str,
    project_name: str,
    services: tuple[str, ...],
    service_replicas: tuple[tuple[str, int], ...],
    action: str,
    uncertain_transition: bool,
) -> dict[str, Any]:
    if action not in {"up", "stop", "restart", "down"}:
        raise ValueError("unsupported Compose observation action")
    if not services:
        raise BrokerError(
            "compose_reconciliation_scope_unrecoverable",
            "Compose observation has no exact persisted service scope.",
        )
    expected_counts = dict(service_replicas)
    if tuple(sorted(expected_counts)) != tuple(sorted(services)):
        raise BrokerError(
            "compose_reconciliation_scope_unrecoverable",
            "Compose observation lacks exact persisted replica scope.",
        )
    rows = list(
        connection.execute(
            """
            SELECT docker_resource_id, full_container_id, service_name,
                   lifecycle, ownership_state,
                   authoritative_owner_repo_id, observation_fingerprint
            FROM broker_observed_compose_containers
            WHERE snapshot_id = ? AND project_name = ?
            ORDER BY service_name, full_container_id
            """,
            (snapshot_id, project_name),
        )
    )
    for row in rows:
        if (
            str(row["ownership_state"]) != "exclusive"
            or str(row["authoritative_owner_repo_id"] or "") != repo_id
        ):
            raise BrokerError(
                "compose_project_name_conflict",
                "Observed Compose project name is not exclusively owned by this repository.",
            )
    service_counts = {service: {"running": 0, "stopped": 0} for service in services}
    unexpected_services: set[str] = set()
    for row in rows:
        service_name = str(row["service_name"] or "")
        if service_name in service_counts:
            lifecycle = str(row["lifecycle"])
            service_counts[service_name][lifecycle] += 1
        elif service_name:
            unexpected_services.add(service_name)
    missing_services = [
        service
        for service, counts in service_counts.items()
        if counts["running"] + counts["stopped"] == 0
    ]
    stopped_services = [
        service for service, counts in service_counts.items() if counts["stopped"] > 0
    ]
    excess_services = [
        service
        for service, counts in service_counts.items()
        if counts["running"] + counts["stopped"] > expected_counts[service]
    ]
    count_mismatch_services = [
        service
        for service, counts in service_counts.items()
        if counts["running"] != expected_counts[service] or counts["stopped"] != 0
    ]
    unclassified_container_count = sum(
        not str(row["service_name"] or "") for row in rows
    )
    running_target_count = sum(counts["running"] for counts in service_counts.values())
    stopped_target_count = sum(counts["stopped"] for counts in service_counts.values())
    assets = list(
        connection.execute(
            """
            SELECT asset_kind, asset_id, observation_fingerprint
            FROM broker_observed_compose_assets
            WHERE snapshot_id = ? AND project_name = ?
            ORDER BY asset_kind, asset_id
            """,
            (snapshot_id, project_name),
        )
    )
    network_count = sum(str(row["asset_kind"]) == "network" for row in assets)
    volume_count = sum(str(row["asset_kind"]) == "volume" for row in assets)
    if action in {"up", "restart"}:
        desired = (
            not count_mismatch_services
            and not excess_services
        )
        proof_kind = "all_target_services_running"
    elif action == "stop":
        desired = (
            running_target_count == 0
            and unclassified_container_count == 0
            and not unexpected_services
            and not excess_services
        )
        proof_kind = "no_target_service_running"
    else:
        desired = not rows and network_count == 0
        proof_kind = "project_containers_and_networks_absent"
    material = {
        "containers": [
            {
                "full_container_id": str(row["full_container_id"]),
                "service_name": row["service_name"],
                "lifecycle": str(row["lifecycle"]),
                "observation_fingerprint": str(row["observation_fingerprint"]),
            }
            for row in rows
        ],
        "assets": [
            {
                "kind": str(row["asset_kind"]),
                "id": str(row["asset_id"]),
                "observation_fingerprint": str(row["observation_fingerprint"]),
            }
            for row in assets
        ],
    }
    return {
        "proof": proof_kind,
        "desired_state_observed": desired,
        "transition_proven": not uncertain_transition,
        "project_container_count": len(rows),
        "target_running_count": running_target_count,
        "target_stopped_count": stopped_target_count,
        "missing_services": missing_services,
        "stopped_services": stopped_services,
        "count_mismatch_services": count_mismatch_services,
        "excess_services": excess_services,
        "expected_service_replicas": expected_counts,
        "unclassified_container_count": unclassified_container_count,
        "unexpected_services": sorted(unexpected_services),
        "network_count": network_count,
        "retained_volume_count": volume_count,
        "evidence_fingerprint": "sha256:" + fingerprint(material),
    }


def _require_exact_full_docker_snapshot(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    host_id: str,
    expected_evidence: Mapping[str, Any] | None,
    operation_id: str | None,
    require_compose_asset_scope: bool = True,
    error_code: str = "compose_observation_incomplete",
    error_message: str = (
        "Compose action requires the exact fresh full-Docker host snapshot."
    ),
) -> sqlite3.Row:
    snapshot = connection.execute(
        """
        SELECT observation.snapshot_id, observation.host_id,
               observation.observer_domain, observation.status,
               observation.material_fingerprint, observation.started_at,
               observation.completed_at,
               capability.observer_domain AS capability_domain,
               capability.docker_available,
               capability.capability_fingerprint
        FROM observation_snapshots observation
        JOIN observation_capabilities capability USING(snapshot_id)
        WHERE observation.snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if (
        snapshot is None
        or str(snapshot["host_id"]) != host_id
        or str(snapshot["observer_domain"]) != "host-runtime-v2:full-docker"
        or str(snapshot["capability_domain"]) != "host-runtime-v2:full-docker"
        or str(snapshot["status"]) != "completed"
        or bool(snapshot["docker_available"]) is not True
        or (
            expected_evidence is not None
            and (
                expected_evidence.get("observer_domain")
                != "host-runtime-v2:full-docker"
                or expected_evidence.get("docker_available") is not True
                or expected_evidence.get("snapshot_id") != snapshot_id
                or expected_evidence.get("material_fingerprint")
                != snapshot["material_fingerprint"]
                or expected_evidence.get("started_at") != snapshot["started_at"]
                or expected_evidence.get("capability_fingerprint")
                != snapshot["capability_fingerprint"]
                or expected_evidence.get("completed_at") != snapshot["completed_at"]
            )
        )
    ):
        raise BrokerError(
            error_code,
            error_message,
            operation_id=operation_id,
        )
    if require_compose_asset_scope:
        _require_complete_compose_asset_scope(connection, snapshot_id=snapshot_id)
    return snapshot


def _require_compose_mutation_safe_connection(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
    snapshot_id: str,
    expected_evidence: Mapping[str, Any] | None = None,
) -> sqlite3.Row:
    definition = connection.execute(
        """
        SELECT definition.repo_id, definition.project_name,
               repository.host_id
        FROM broker_compose_definitions definition
        JOIN repositories repository USING(repo_id)
        WHERE definition.compose_definition_id = ?
          AND definition.repo_id = ?
        """,
        (request.resource_id, request.project_id),
    ).fetchone()
    if definition is None:
        raise BrokerError(
            "compose_definition_invalid",
            "Compose definition no longer belongs to the exact repository.",
            operation_id=request.operation_id,
        )
    snapshot = _require_exact_full_docker_snapshot(
        connection,
        snapshot_id=snapshot_id,
        host_id=str(definition["host_id"]),
        expected_evidence=expected_evidence,
        operation_id=request.operation_id,
    )
    duplicate = connection.execute(
        """
        SELECT claim.compose_definition_id
        FROM broker_compose_project_claims claim
        WHERE claim.project_name = ?
          AND claim.compose_definition_id != ?
          AND claim.claimed = 1
        LIMIT 1
        """,
        (definition["project_name"], request.resource_id),
    ).fetchone()
    if duplicate is not None:
        raise BrokerError(
            "compose_project_name_conflict",
            "Compose project name is persisted by another definition; mutation was refused.",
            operation_id=request.operation_id,
        )
    _require_observed_compose_project_name_available(
        connection,
        snapshot_id=snapshot_id,
        repo_id=request.project_id,
        project_name=str(definition["project_name"]),
    )
    return snapshot


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
            int(row["start_port"]) <= port <= int(row["end_port"]) for row in policies
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


def _ephemeral_image_target_for_request(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
    require_reserved_operation: bool,
) -> EphemeralImageTarget:
    """Read one enabled template after authorization, never caller image input."""

    row = connection.execute(
        """
        SELECT template_id, repo_id, image_ref, definition_fingerprint
        FROM ephemeral_container_templates
        WHERE template_id = ? AND repo_id = ? AND enabled = 1
        """,
        (request.resource_id, request.project_id),
    ).fetchone()
    if row is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Ephemeral template is disabled or unavailable.",
            operation_id=request.operation_id,
        )
    try:
        image_ref = _require_pinned_ephemeral_image(row["image_ref"])
    except ValueError as error:
        raise BrokerError(
            "control_binding_unavailable",
            "Ephemeral template does not retain an immutable image reference.",
            operation_id=request.operation_id,
        ) from error
    template_fingerprint = str(row["definition_fingerprint"])
    if re.fullmatch(r"sha256:[0-9a-f]{64}", template_fingerprint) is None:
        raise BrokerError(
            "control_binding_unavailable",
            "Ephemeral template does not retain a valid immutable definition fingerprint.",
            operation_id=request.operation_id,
        )
    target = EphemeralImageTarget(
        template_id=str(row["template_id"]),
        repo_id=str(row["repo_id"]),
        image_ref=image_ref,
        template_fingerprint=template_fingerprint,
    )
    if require_reserved_operation:
        reserved = connection.execute(
            """
            SELECT target.immutable_fingerprint
            FROM operations operation
            JOIN operation_targets target USING(operation_id)
            WHERE operation.operation_id = ?
              AND operation.status = 'running'
              AND target.ordinal = 0
              AND target.target_kind = 'ephemeral_template'
              AND target.target_id = ?
            """,
            (request.operation_id, target.template_id),
        ).fetchone()
        if (
            reserved is None
            or str(reserved["immutable_fingerprint"])
            != target.template_fingerprint
        ):
            raise BrokerError(
                "operation_state_conflict",
                "The sealed ephemeral template changed after the operation was reserved.",
                operation_id=request.operation_id,
            )
    return target


def _normalize_ephemeral_image_cache_proof(
    proof: Mapping[str, Any], *, target: EphemeralImageTarget
) -> dict[str, Any]:
    """Allow only bounded public evidence for one exact immutable image."""

    required = {
        "cached",
        "image_ref",
        "image_id",
        "repo_digest",
        "os",
        "architecture",
    }
    if not isinstance(proof, Mapping) or set(proof) != required:
        raise BrokerError(
            "ephemeral_image_inspect_unobservable",
            "The service did not provide complete exact image cache evidence.",
        )
    image_ref = proof.get("image_ref")
    image_id = proof.get("image_id")
    repo_digest = proof.get("repo_digest")
    if (
        proof.get("cached") is not True
        or image_ref != target.image_ref
        or repo_digest != target.image_ref
        or not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or proof.get("os") != "linux"
        or proof.get("architecture") != "amd64"
    ):
        raise BrokerError(
            "ephemeral_image_inspect_unobservable",
            "The service did not prove the exact sealed image cache identity.",
        )
    return {
        "cached": True,
        "image_ref": target.image_ref,
        "image_id": image_id,
        "repo_digest": target.image_ref,
        "os": "linux",
        "architecture": "amd64",
    }


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
    if operation in _COMPOSE_OPERATIONS:
        return "compose"
    if operation in _DATABASE_OPERATIONS:
        return "database"
    if operation in {
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_IMAGE_STATUS,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
    }:
        return "ephemeral_template"
    if operation in {
        BrokerOperation.EPHEMERAL_RENEW,
        BrokerOperation.EPHEMERAL_FINISH,
    }:
        return "ephemeral_run"
    return "container"


def _require_ephemeral_template_name(value: Any) -> str:
    name = str(value or "").strip()
    if (
        not 1 <= len(name) <= 96
        or name != str(value)
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?", name) is None
    ):
        raise ValueError(
            "ephemeral template name must be a lowercase Docker-safe identifier"
        )
    return name


def _require_pinned_ephemeral_image(value: Any) -> str:
    image = str(value or "")
    if (
        not 1 <= len(image) <= 512
        or image != image.strip()
        or any(character.isspace() or character == "\x00" for character in image)
        or re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", image) is None
    ):
        raise ValueError(
            "ephemeral image_ref must be an immutable lowercase sha256 digest reference"
        )
    return image


def _require_ephemeral_argument(value: Any) -> str:
    if (
        not isinstance(value, str)
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise ValueError("ephemeral command arguments must be bounded strings")
    return value


def _normalize_ephemeral_environment(
    value: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise ValueError("ephemeral environment must be an object with at most 64 values")
    normalized: list[tuple[str, str]] = []
    for raw_name, raw_value in value.items():
        if (
            not isinstance(raw_name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", raw_name) is None
        ):
            raise ValueError("ephemeral environment contains an invalid variable name")
        if re.search(
            r"(?:^|_)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS?)(?:$|_)",
            raw_name.upper(),
        ):
            raise ValueError(
                "ephemeral manifest environment must not contain credentials; "
                "use a purpose-built private credential integration"
            )
        if (
            not isinstance(raw_value, str)
            or "\x00" in raw_value
            or len(raw_value.encode("utf-8")) > 65536
        ):
            raise ValueError("ephemeral environment values must be bounded strings")
        normalized.append((raw_name, raw_value))
    return tuple(sorted(normalized))


def _require_ephemeral_secret_policy_environment(
    *,
    policy_kind: str | None,
    environment: tuple[tuple[str, str], ...],
) -> None:
    """Require an authenticated PostgreSQL host policy for password-file runs.

    The broker-delivered password is meaningful only when the generated
    PostgreSQL instance actually requires SCRAM authentication. A permissive
    ``POSTGRES_HOST_AUTH_METHOD`` overrides the image defaults, so it is
    forbidden rather than merely ignored. The exact initdb argument is kept
    narrow deliberately: administrator enrollment is the one trusted place
    that declares this image contract.
    """

    if policy_kind != POSTGRES_INITDB_PASSWORD_FILE_V1:
        return
    values = dict(environment)
    if "POSTGRES_HOST_AUTH_METHOD" in values:
        raise ValueError(
            "postgres_initdb_password_file_v1 forbids POSTGRES_HOST_AUTH_METHOD; "
            "SCRAM must be selected through POSTGRES_INITDB_ARGS"
        )
    if values.get("POSTGRES_INITDB_ARGS") != "--auth-host=scram-sha-256":
        raise ValueError(
            "postgres_initdb_password_file_v1 requires PostgreSQL SCRAM via "
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256"
        )

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
