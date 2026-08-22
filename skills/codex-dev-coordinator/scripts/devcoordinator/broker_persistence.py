"""Service-owned broker catalog, lease, and durable idempotency persistence.

Clients never receive this database path or a SQLite handle.  Every method
opens the private coordinator store as the broker service UID and exposes a
typed operation only; wire documents cannot supply SQL, commands, or paths.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import calendar
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Callable, Generator, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit
import uuid

from .broker import (
    AcceptedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
    TESTD_INTERNAL_OPERATIONS,
    accepted_request_fingerprint,
)
from .browser_lifecycle import (
    BrowserLifecycleError,
    DEFAULT_IDLE_SECONDS as DEFAULT_BROWSER_IDLE_SECONDS,
    browser_lifecycle_inventory_projection,
    read_browser_lifecycle_state,
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
from .compose_run_once import (
    ComposeRunOncePolicy,
    ComposeRunOnceReceiptContract,
    PublishedReceipt,
    compose_run_once_policies_document,
    normalize_compose_run_once_policies,
    validate_published_receipt,
)
from .store import (
    AccountStore,
    CoordinatorStore,
    DEFAULT_BUSY_TIMEOUT_MS,
    deterministic_id,
    fingerprint,
    utc_timestamp,
)
from .schema import SCHEMA_VERSION
from .runtime_ensure import (
    validate_runtime_ensure_result,
)
from .runtime_sessions import runtime_process_identity
from .temporary_dev_service import temporary_dev_service_id
from .database_backups import (
    inspect_database_backup,
    record_successful_restore,
    upsert_database_backup,
)
from .events import list_event_page
from .ephemeral_secrets import (
    EphemeralSecretPolicy,
    POSTGRES_INITDB_PASSWORD_FILE_V1,
    deterministic_secret_binding_id,
    normalize_ephemeral_secret_policy,
)


DEFAULT_PORT_LEASE_TTL_SECONDS = 600
OPERATION_FOLLOW_MAX_BYTES = 2_048
OPERATION_FOLLOW_TARGET_SCAN_LIMIT = 32
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
_REPOSITORY_BOOTSTRAP_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_ENSURE,
        BrokerOperation.REPOSITORY_APPROVE_COMPOSE_HOST_ACCESS,
    }
)
_REPOSITORY_DISCOVERY_OPERATIONS = frozenset(
    {BrokerOperation.REPOSITORY_RESOLVE}
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
    {
        BrokerOperation.DATABASE_BACKUP,
        BrokerOperation.DATABASE_BACKUP_RETIRE,
        BrokerOperation.DATABASE_RESTORE,
    }
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


_COMPOSE_OPERATIONS = frozenset(
    {
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_STOP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_DOWN,
    }
)
_COMPOSE_RUN_ONCE_OPERATIONS = frozenset({BrokerOperation.COMPOSE_RUN_ONCE})
_ALL_COMPOSE_OPERATIONS = _COMPOSE_OPERATIONS | _COMPOSE_RUN_ONCE_OPERATIONS
_COMPOSE_RUN_ONCE_PHASES = frozenset(
    {
        "reserved",
        "image_bind_intent",
        "image_bound",
        "create_intent",
        "container_bound",
        "start_intent",
        "started",
        "wait_intent",
        "stop_intent",
        "terminal",
        "evidence_intent",
        "evidence_captured",
        "cleanup_intent",
        "cleaned",
    }
)
_COMPOSE_RUN_ONCE_UPDATE_COLUMNS = frozenset(
    {
        "expected_image_id",
        "full_container_id",
        "terminal_exit_code",
        "timed_out",
        "terminal_error_code",
        "receipt_status",
        "receipt_error_code",
        "receipt_json",
        "receipt_sha256",
        "stdout_sha256",
        "stdout_byte_size",
        "stderr_sha256",
        "stderr_byte_size",
        "cleanup_status",
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
    {
        BrokerOperation.CAPABILITIES_READ,
        BrokerOperation.OPERATION_FOLLOW,
        BrokerOperation.INVENTORY_READ,
        BrokerOperation.EVENTS_READ,
        BrokerOperation.TEST_FLEET_STATS_READ,
        BrokerOperation.TEST_REPOSITORY_CATALOG,
    }
)
_HOST_OBSERVE_OPERATIONS = frozenset({BrokerOperation.HOST_OBSERVE})
_TEST_OPERATIONS = frozenset(
    {
        BrokerOperation.TEST_RUN_START,
        BrokerOperation.TEST_RUN_FINISH,
        BrokerOperation.TEST_HEALTH,
        BrokerOperation.TEST_STATS_READ,
        BrokerOperation.TEST_FLEET_STATS_READ,
        BrokerOperation.TEST_PLAN_PREVIEW,
        BrokerOperation.TEST_PLAN_REGISTER,
        BrokerOperation.TEST_RUN_SUBMIT,
        BrokerOperation.TEST_RUN_LIST,
        BrokerOperation.TEST_QUEUE_STATUS,
        BrokerOperation.TEST_RUN_STATUS,
        BrokerOperation.TEST_RUN_SUMMARY,
        BrokerOperation.TEST_RUN_FAILURES,
        BrokerOperation.TEST_RUN_ARTIFACTS,
        BrokerOperation.TEST_ARTIFACT_RESOLVE,
        BrokerOperation.TEST_RUN_CASES,
        BrokerOperation.TEST_RUN_CANCEL,
        BrokerOperation.TEST_RUN_RETRY,
        BrokerOperation.TEST_EVENTS_READ,
        BrokerOperation.TEST_REPOSITORY_SETUP,
        BrokerOperation.TEST_REPOSITORY_CATALOG,
        BrokerOperation.TEST_EVIDENCE_CHECK,
        BrokerOperation.TEST_EVIDENCE_CONSUME,
    }
)


def _operation_actor(accepted: AcceptedBrokerRequest) -> str:
    """Build durable actor metadata while keeping kernel identity authoritative."""

    request = accepted.request
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
    """Reuse one accepted read snapshot inside the inventory projection."""

    @contextmanager
    def read_transaction(self) -> Generator[sqlite3.Connection, None, None]:
        if self.connection.in_transaction:
            yield self.connection
            return
        with super().read_transaction() as connection:
            yield connection


BROKER_SCHEMA = """
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
    model_services_json TEXT NOT NULL,
    model_service_replicas_json TEXT NOT NULL,
    service_images_json TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS broker_compose_run_once_services (
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    service_name TEXT NOT NULL,
    max_timeout_seconds INTEGER NOT NULL
        CHECK(max_timeout_seconds >= 600 AND max_timeout_seconds <= 3600),
    receipt_contract_json TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    PRIMARY KEY(compose_definition_id, service_name),
    UNIQUE(compose_definition_id, ordinal)
);

CREATE TABLE IF NOT EXISTS broker_compose_run_once_attempts (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE RESTRICT,
    agent TEXT NOT NULL,
    service_name TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds >= 1 AND timeout_seconds <= 3600),
    deadline_epoch INTEGER NOT NULL CHECK(deadline_epoch > 0),
    container_name TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK(phase IN (
        'reserved', 'image_bind_intent', 'image_bound',
        'create_intent', 'container_bound', 'start_intent', 'started',
        'wait_intent', 'stop_intent', 'terminal', 'evidence_intent',
        'evidence_captured', 'cleanup_intent', 'cleaned'
    )),
    policy_fingerprint TEXT NOT NULL,
    receipt_contract_json TEXT NOT NULL,
    definition_fingerprint TEXT NOT NULL,
    definition_generation INTEGER NOT NULL CHECK(definition_generation >= 0),
    repository_generation INTEGER NOT NULL CHECK(repository_generation >= 0),
    service_image_ref TEXT NOT NULL,
    expected_image_id TEXT,
    full_container_id TEXT,
    terminal_exit_code INTEGER,
    timed_out INTEGER NOT NULL DEFAULT 0 CHECK(timed_out IN (0, 1)),
    terminal_error_code TEXT,
    receipt_status TEXT,
    receipt_error_code TEXT,
    receipt_json TEXT,
    receipt_sha256 TEXT,
    stdout_sha256 TEXT,
    stdout_byte_size INTEGER CHECK(stdout_byte_size IS NULL OR stdout_byte_size >= 0),
    stderr_sha256 TEXT,
    stderr_byte_size INTEGER CHECK(stderr_byte_size IS NULL OR stderr_byte_size >= 0),
    cleanup_status TEXT,
    updated_at TEXT NOT NULL
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
    association_state TEXT NOT NULL
        CHECK(association_state IN ('exclusive', 'missing', 'conflicting')),
    associated_repo_id TEXT
        REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    observation_fingerprint TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, docker_resource_id),
    CHECK(
        (association_state = 'exclusive' AND associated_repo_id IS NOT NULL)
        OR
        (association_state != 'exclusive' AND associated_repo_id IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS broker_observed_compose_containers_by_project
ON broker_observed_compose_containers(snapshot_id, project_name, service_name);

CREATE TABLE IF NOT EXISTS broker_host_observation_sessions (
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

CREATE TABLE IF NOT EXISTS broker_database_host_results (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    result_json TEXT NOT NULL,
    result_fingerprint TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_runtime_replacements (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL
        CHECK(resource_kind IN ('docker', 'database_stack')),
    requested_resource_id TEXT NOT NULL,
    old_docker_resource_id TEXT NOT NULL
        REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
    old_full_container_id TEXT NOT NULL,
    database_binding_id TEXT,
    database_name TEXT,
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE RESTRICT,
    compose_service TEXT NOT NULL,
    compose_operation_id TEXT NOT NULL UNIQUE,
    backup_operation_id TEXT UNIQUE,
    database_backup_id TEXT
        REFERENCES database_backups(database_backup_id) ON DELETE RESTRICT,
    new_docker_resource_id TEXT
        REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
    new_full_container_id TEXT,
    restore_result_json TEXT,
    phase TEXT NOT NULL CHECK(phase IN (
        'reserved', 'backup_complete', 'recreated', 'rebound',
        'restore_intent', 'restore_complete', 'terminal'
    )),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(
        (resource_kind = 'docker' AND database_binding_id IS NULL
            AND database_name IS NULL AND backup_operation_id IS NULL)
        OR
        (resource_kind = 'database_stack' AND database_binding_id IS NOT NULL
            AND database_name IS NOT NULL AND backup_operation_id IS NOT NULL)
    ),
    CHECK(
        (new_docker_resource_id IS NULL AND new_full_container_id IS NULL)
        OR
        (new_docker_resource_id IS NOT NULL AND new_full_container_id IS NOT NULL)
    )
);

-- Port ranges are host-allocation constraints, not caller permissions. They
-- are attached to the target server and apply identically to every local
-- caller.
CREATE TABLE IF NOT EXISTS broker_port_ranges (
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    server_definition_id TEXT NOT NULL
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    start_port INTEGER NOT NULL CHECK(start_port BETWEEN 1 AND 65535),
    end_port INTEGER NOT NULL CHECK(end_port BETWEEN start_port AND 65535),
    max_ttl_seconds INTEGER NOT NULL CHECK(max_ttl_seconds BETWEEN 1 AND 604800),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(repo_id, server_definition_id, protocol, start_port, end_port)
);

CREATE TABLE IF NOT EXISTS broker_operation_requests (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    uid INTEGER NOT NULL CHECK(uid >= 0),
    account_id TEXT NOT NULL,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS broker_compose_run_once_attempt_phase
    ON broker_compose_run_once_attempts(compose_definition_id, phase);

CREATE TABLE IF NOT EXISTS broker_compose_operation_preflights (
    operation_id TEXT PRIMARY KEY
        REFERENCES operations(operation_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL
        REFERENCES observation_snapshots(snapshot_id) ON DELETE RESTRICT,
    material_fingerprint TEXT NOT NULL,
    capability_fingerprint TEXT NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS broker_host_observation_session_lookup
ON broker_host_observation_sessions(broker_instance_id, snapshot_id);

CREATE INDEX IF NOT EXISTS broker_port_range_lookup
ON broker_port_ranges(repo_id, server_definition_id, protocol, enabled);

"""


_LEGACY_LOCAL_AUTHORIZATION_TABLES = (
    "broker_cleanup_resource_acl",
    "broker_lifecycle_resource_acl",
    "broker_database_acl",
    "broker_compose_run_once_acl",
    "broker_compose_acl",
    "broker_assignment_acl",
    "broker_worker_acl",
    "broker_runtime_acl",
    "broker_ephemeral_acl",
    "broker_resource_acl",
    "broker_repository_read_acl",
    "broker_host_observation_acl",
    "broker_cleanup_acl",
    "broker_lifecycle_acl",
    "broker_repository_configurations",
    "broker_assignment_owners",
    "broker_lease_owners",
    "broker_acl_principals",
)


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _migrate_trusted_local_broker_schema(connection: sqlite3.Connection) -> None:
    """Remove legacy caller/repository request validation state transactionally."""

    if _table_exists(connection, "broker_host_observation_owners") and not _table_exists(
        connection, "broker_host_observation_sessions"
    ):
        connection.execute(
            "ALTER TABLE broker_host_observation_owners "
            "RENAME TO broker_host_observation_sessions"
        )

    observed_columns = {
        str(row["name"])
        for row in connection.execute(
            "PRAGMA table_info(broker_observed_compose_containers)"
        )
    }
    if observed_columns and "ownership_state" in observed_columns:
        connection.execute(
            "ALTER TABLE broker_observed_compose_containers "
            "RENAME TO broker_observed_compose_containers_legacy_owner"
        )
        connection.execute(
            """
            CREATE TABLE broker_observed_compose_containers (
                snapshot_id TEXT NOT NULL
                    REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
                docker_resource_id TEXT NOT NULL
                    REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
                full_container_id TEXT NOT NULL,
                project_name TEXT NOT NULL,
                service_name TEXT,
                lifecycle TEXT NOT NULL CHECK(lifecycle IN ('running', 'stopped')),
                association_state TEXT NOT NULL
                    CHECK(association_state IN ('exclusive', 'missing', 'conflicting')),
                associated_repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
                observation_fingerprint TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, docker_resource_id),
                CHECK(
                    (association_state = 'exclusive' AND associated_repo_id IS NOT NULL)
                    OR (association_state != 'exclusive' AND associated_repo_id IS NULL)
                )
            )
            """
        )
        connection.execute(
            """
            INSERT INTO broker_observed_compose_containers(
                snapshot_id, docker_resource_id, full_container_id,
                project_name, service_name, lifecycle, association_state,
                associated_repo_id, observation_fingerprint
            )
            SELECT snapshot_id, docker_resource_id, full_container_id,
                   project_name, service_name, lifecycle, ownership_state,
                   authoritative_owner_repo_id, observation_fingerprint
            FROM broker_observed_compose_containers_legacy_owner
            """
        )
        connection.execute("DROP TABLE broker_observed_compose_containers_legacy_owner")

    if _table_exists(connection, "broker_port_policies"):
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS broker_port_ranges (
                repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
                server_definition_id TEXT NOT NULL
                    REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
                protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
                start_port INTEGER NOT NULL CHECK(start_port BETWEEN 1 AND 65535),
                end_port INTEGER NOT NULL CHECK(end_port BETWEEN start_port AND 65535),
                max_ttl_seconds INTEGER NOT NULL CHECK(max_ttl_seconds BETWEEN 1 AND 604800),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                updated_at TEXT NOT NULL,
                PRIMARY KEY(repo_id, server_definition_id, protocol, start_port, end_port)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO broker_port_ranges(
                repo_id, server_definition_id, protocol, start_port, end_port,
                max_ttl_seconds, enabled, updated_at
            )
            SELECT repo_id, server_definition_id, protocol, start_port, end_port,
                   max(max_ttl_seconds), max(enabled), max(updated_at)
            FROM broker_port_policies
            GROUP BY repo_id, server_definition_id, protocol, start_port, end_port
            ON CONFLICT(repo_id, server_definition_id, protocol, start_port, end_port)
            DO UPDATE SET
                max_ttl_seconds = excluded.max_ttl_seconds,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """
        )
        connection.execute("DROP TABLE broker_port_policies")

    operation_request_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'broker_operation_requests'"
    ).fetchone()
    if operation_request_sql is not None and "broker_acl_principals" in str(
        operation_request_sql[0]
    ):
        connection.execute(
            "ALTER TABLE broker_operation_requests RENAME TO broker_operation_requests_legacy_auth"
        )
        connection.execute(
            """
            CREATE TABLE broker_operation_requests (
                operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
                uid INTEGER NOT NULL CHECK(uid >= 0),
                account_id TEXT NOT NULL,
                repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
                resource_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO broker_operation_requests(
                operation_id, uid, account_id, repo_id, resource_id,
                operation, request_fingerprint, created_at
            )
            SELECT operation_id, uid, account_id, repo_id, resource_id,
                   operation, request_fingerprint, created_at
            FROM broker_operation_requests_legacy_auth
            """
        )
        connection.execute("DROP TABLE broker_operation_requests_legacy_auth")

    for table in _LEGACY_LOCAL_AUTHORIZATION_TABLES:
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


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
    repo_id: str | None = None
    owner_uid: int | None = None


@dataclass(frozen=True)
class DirectContainerRemovalTarget:
    docker_resource_id: str
    full_container_id: str


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
class SealedTestFixtureTemplate:
    template_id: str
    repo_id: str
    name: str
    image_ref: str
    definition_fingerprint: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    secret_policy: EphemeralSecretPolicy | None
    container_tcp_port: int | None
    memory_bytes: int
    cpu_millis: int
    max_ttl_seconds: int


@dataclass(frozen=True)
class EphemeralSecretRunTarget:
    """Exact non-secret run snapshot accepted for one descriptor delivery."""

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
class RuntimeSessionCleanupTarget:
    session_id: str
    operation_id: str
    repo_id: str
    cleanup_disposition: str
    target: RuntimeDockerMutationTarget


@dataclass(frozen=True)
class RuntimeReplacementRecord:
    operation_id: str
    repo_id: str
    resource_kind: str
    requested_resource_id: str
    old_docker_resource_id: str
    old_full_container_id: str
    database_binding_id: str | None
    database_name: str | None
    compose_definition_id: str
    compose_service: str
    compose_operation_id: str
    backup_operation_id: str | None
    database_backup_id: str | None
    new_docker_resource_id: str | None
    new_full_container_id: str | None
    restore_result: dict[str, Any] | None
    phase: str


@dataclass(frozen=True)
class RuntimeServiceLogTarget:
    server_definition_id: str
    repo_id: str
    role: Optional[str]
    log_path: str
    definition_fingerprint: str
    owner_uid: int


@dataclass(frozen=True)
class RuntimeServiceEndpointTarget:
    server_definition_id: str
    repo_id: str
    canonical_root: str
    cwd: str
    listener_port: int | None
    listener_required: bool


@dataclass(frozen=True)
class RegisteredDatabaseBackup:
    database_backup_id: str
    database_binding_id: str
    artifact_path: str
    manifest_path: str
    artifact_sha256: str
    manifest_sha256: str
    artifact_size_bytes: int
    status: str


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
    model_services: tuple[str, ...]
    model_service_replicas: tuple[tuple[str, int], ...]
    model_service_images: tuple[tuple[str, str], ...]
    run_once_policies: tuple[ComposeRunOncePolicy, ...]
    project_name: str
    effective_model_sha256: str
    effective_host_access_risks: tuple[str, ...]
    effective_host_access_approved: bool
    definition_fingerprint: str
    definition_generation: int
    repository_generation: int
    owner_uid: int | None = None
    recreate_service: str | None = None
    wait_timeout_seconds: int | None = None


@dataclass(frozen=True)
class ComposeConfigurationContainerScope:
    """Exact configuration projection for one observed Compose project.

    ``lifecycle_container_ids`` are controlled by the retained Compose
    definition. ``non_lifecycle_container_ids`` belong to the same Compose
    project but must never be published as standalone Docker resources.  The
    latter contains declared run-once containers and inactive undeclared
    leftovers; an active undeclared container is rejected before this value is
    returned.
    """

    lifecycle_container_ids: tuple[str, ...]
    non_lifecycle_container_ids: tuple[str, ...]


@dataclass(frozen=True)
class ComposeRunOnceMutationTarget:
    """Exact durable phase and sealed service identity for one one-shot run."""

    compose: ComposeMutationTarget
    operation_id: str
    agent: str
    service_name: str
    timeout_seconds: int
    deadline_epoch: int
    container_name: str
    phase: str
    policy_fingerprint: str
    receipt_contract: ComposeRunOnceReceiptContract
    service_image_ref: str
    expected_image_id: str | None
    full_container_id: str | None
    terminal_exit_code: int | None
    timed_out: bool
    terminal_error_code: str | None
    receipt_status: str | None
    receipt_error_code: str | None
    receipt: Mapping[str, Any] | None
    receipt_sha256: str | None
    cleanup_status: str | None


@dataclass(frozen=True)
class TestRepositoryExecutionContext:
    """Exact current repository and attributed execution UID for one attempt."""

    repo_id: str
    canonical_root: str
    generation: int
    execution_uid: int


@dataclass(frozen=True)
class TemporaryServiceExecutionContext:
    """Exact repository identity and original kernel caller for one launch."""

    repo_id: str
    canonical_root: str
    generation: int
    execution_uid: int


class StoreBackedRequestAcceptor:
    """Validate trusted-local requests against current typed state."""

    def __init__(
        self,
        persistence: "BrokerPersistence",
        *,
        internal_testd_uid: int | None = None,
    ) -> None:
        self._persistence = persistence
        # Compatibility-only input for older unit constructors. It is never an
        # access decision on this single-developer host.
        del internal_testd_uid

    def accept(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        if request.operation in TESTD_INTERNAL_OPERATIONS:
            return self._persistence.accept_internal_testd(peer, request)
        return self._persistence.accept(peer, request)


class BrokerPersistence:
    """Typed access to a private service-owned normalized coordinator store."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        expected_uid: Optional[int] = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
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
                "repository_target_unavailable",
                "Repository is not present in the Coordinator catalog.",
            )
        return str(row["host_id"])

    def ensure_repository_catalog_entry(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        context: Any,
        reconcile_repository: Callable[[str, str, int], Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Register one proven Git context without creating access state."""

        request = accepted.request
        if request.operation is not BrokerOperation.REPOSITORY_ENSURE:
            raise ValueError("request is not a repository ensure")
        if (
            request.arguments["canonical_root"] != context.effective.canonical_root
            or request.arguments["project_kind"] != context.project_kind
        ):
            raise BrokerError(
                "repository_context_changed",
                "The proven repository context changed before registration.",
                operation_id=request.operation_id,
            )
        execution_uid = int(accepted.attribution_uid)
        disposition = self.reserve_operation(accepted)
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerError(
                disposition.error_code or "repository_registration_failed",
                disposition.error_message or "Repository registration failed.",
                operation_id=request.operation_id,
            )

        from .repository_context import _revalidate_context

        timestamp = utc_timestamp()
        scopes = [context.root]
        if context.temporary is not None:
            scopes.append(context.temporary)
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                _revalidate_context(context)
                anchor = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if anchor is None:
                    raise BrokerError(
                        "repository_target_unavailable",
                        "Repository registration lost its host routing anchor.",
                        operation_id=request.operation_id,
                    )
                host_id = str(anchor["host_id"])
                repository_ids: dict[str, str] = {}
                changed = False
                for scope in scopes:
                    root = str(scope.canonical_root)
                    repo_id = deterministic_id("repository", host_id, root)
                    existing = connection.execute(
                        """
                        SELECT repository.repo_id, repository.state,
                               repository.generation, installation.status,
                               installation.startup_fenced
                        FROM repositories AS repository
                        LEFT JOIN repository_installations AS installation USING(repo_id)
                        WHERE repository.host_id = ? AND repository.canonical_root = ?
                        """,
                        (host_id, root),
                    ).fetchone()
                    if existing is None:
                        connection.execute(
                            """
                            INSERT INTO repositories(
                                repo_id, host_id, canonical_root, display_name,
                                state, generation, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                            """,
                            (repo_id, host_id, root, Path(root).name or root, timestamp, timestamp),
                        )
                        connection.execute(
                            """
                            INSERT INTO repository_installations(
                                repo_id, status, startup_fenced, generation,
                                reason, actor, updated_at
                            ) VALUES (?, 'installed', 0, 0,
                                      'first repository use', ?, ?)
                            """,
                            (repo_id, str(request.arguments["agent"]), timestamp),
                        )
                        changed = True
                    elif (
                        str(existing["repo_id"]) != repo_id
                        or str(existing["state"]) != "active"
                        or str(existing["status"] or "") != "installed"
                        or bool(existing["startup_fenced"])
                    ):
                        raise BrokerError(
                            "repository_startup_fenced",
                            "An unavailable repository identity cannot be revived implicitly.",
                            operation_id=request.operation_id,
                        )
                    repository_ids[root] = repo_id

                root_repo_id = repository_ids[context.root.canonical_root]
                family_id = root_repo_id
                connection.execute(
                    """
                    INSERT OR IGNORE INTO repository_families(
                        family_id, host_id, root_repo_id, git_common_dir,
                        identity_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        family_id,
                        host_id,
                        root_repo_id,
                        context.root.git_common_dir,
                        context.root.identity_fingerprint,
                        timestamp,
                        timestamp,
                    ),
                )
                for scope in scopes:
                    repo_id = repository_ids[scope.canonical_root]
                    project_kind = (
                        "temporary"
                        if context.temporary is not None and scope is context.temporary
                        else "primary"
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_scopes(
                            repo_id, family_id, project_kind, git_dir,
                            git_common_dir, identity_fingerprint, root_device,
                            root_inode, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(repo_id) DO UPDATE SET
                            family_id = excluded.family_id,
                            project_kind = excluded.project_kind,
                            git_dir = excluded.git_dir,
                            git_common_dir = excluded.git_common_dir,
                            identity_fingerprint = excluded.identity_fingerprint,
                            root_device = excluded.root_device,
                            root_inode = excluded.root_inode,
                            updated_at = excluded.updated_at
                        """,
                        (
                            repo_id,
                            family_id,
                            project_kind,
                            scope.git_dir,
                            scope.git_common_dir,
                            scope.identity_fingerprint,
                            scope.root_device,
                            scope.root_inode,
                            timestamp,
                            timestamp,
                        ),
                    )

                effective_repo_id = repository_ids[context.effective.canonical_root]
                effective = connection.execute(
                    "SELECT generation FROM repositories WHERE repo_id = ?",
                    (effective_repo_id,),
                ).fetchone()
                if effective is None:
                    raise BrokerError(
                        "repository_registration_failed",
                        "Repository registration did not produce a current catalog entry.",
                        operation_id=request.operation_id,
                    )
                repository_document = {
                    "canonical_root": context.effective.canonical_root,
                    "repo_id": effective_repo_id,
                    "generation": int(effective["generation"]),
                    "execution_uid": execution_uid,
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                    "compose_container_ids": [],
                    "compose_run_once_services": {},
                    "ephemeral_templates": {},
                    "ephemeral_secret_policies": {},
                }
                result = {
                    "schema_version": 2,
                    "ok": True,
                    "operation_id": request.operation_id,
                    "changed": changed,
                    "repository": repository_document,
                }
        if reconcile_repository is not None:
            reconciliation = reconcile_repository(
                effective_repo_id, context.effective.canonical_root, execution_uid
            )
            if not isinstance(reconciliation, Mapping):
                raise RuntimeError("repository reconciliation did not return a mapping")
            repository_document["compose_definition_id"] = reconciliation.get(
                "compose_definition_id"
            )
            servers = reconciliation.get("servers", {})
            if not isinstance(servers, Mapping):
                raise RuntimeError(
                    "repository reconciliation returned invalid persistent services"
                )
            repository_document["servers"] = dict(servers)
            run_once_services = reconciliation.get("compose_run_once_services", {})
            if not isinstance(run_once_services, Mapping):
                raise RuntimeError(
                    "repository reconciliation returned invalid run-once services"
                )
            repository_document["compose_run_once_services"] = dict(run_once_services)
            ephemeral_templates = reconciliation.get("ephemeral_templates", {})
            if not isinstance(ephemeral_templates, Mapping):
                raise RuntimeError(
                    "repository reconciliation returned invalid ephemeral templates"
                )
            repository_document["ephemeral_templates"] = dict(ephemeral_templates)
            ephemeral_secret_policies = reconciliation.get(
                "ephemeral_secret_policies", {}
            )
            if not isinstance(ephemeral_secret_policies, Mapping):
                raise RuntimeError(
                    "repository reconciliation returned invalid ephemeral secret policies"
                )
            repository_document["ephemeral_secret_policies"] = dict(
                ephemeral_secret_policies
            )
            reconcile_changed = reconciliation.get("changed", False)
            if type(reconcile_changed) is not bool:
                raise RuntimeError(
                    "repository reconciliation returned an invalid change outcome"
                )
            result["changed"] = bool(result["changed"] or reconcile_changed)
        self.finish_operation(request.operation_id, result=result)
        return result

    def resolve_repository_catalog_entry(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        """Resolve one prior repository registration through a host anchor."""

        request = accepted.request
        if request.operation is not BrokerOperation.REPOSITORY_RESOLVE:
            raise ValueError("request is not a repository resolve")
        canonical_root = str(request.arguments["canonical_root"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                anchor = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if anchor is None:
                    raise BrokerError(
                        "repository_target_unavailable",
                        "Repository resolution lost its host routing anchor.",
                        operation_id=request.operation_id,
                    )
                row = connection.execute(
                    """
                    SELECT repository.repo_id, repository.state,
                           repository.generation, installation.status,
                           installation.startup_fenced
                    FROM repositories AS repository
                    LEFT JOIN repository_installations AS installation USING(repo_id)
                    WHERE repository.host_id = ? AND repository.canonical_root = ?
                    """,
                    (str(anchor["host_id"]), canonical_root),
                ).fetchone()
                if row is None:
                    return {
                        "schema_version": 2,
                        "ok": True,
                        "state": "unregistered",
                        "repository": None,
                    }
                revoked = connection.execute(
                    """
                    SELECT 1 FROM broker_repository_revocations
                    WHERE repo_id = ? AND repository_generation = ?
                    """,
                    (str(row["repo_id"]), int(row["generation"])),
                ).fetchone()
                current = (
                    str(row["state"]) == "active"
                    and str(row["status"] or "") == "installed"
                    and not bool(row["startup_fenced"])
                    and revoked is None
                )
                if not current:
                    return {
                        "schema_version": 2,
                        "ok": True,
                        "state": "blocked",
                        "repository": None,
                    }
                server_rows = list(
                    connection.execute(
                        """
                        SELECT definition.name, definition.server_definition_id
                        FROM server_definitions AS definition
                        WHERE definition.repo_id = ?
                          AND NOT EXISTS (
                              SELECT 1 FROM broker_server_revocations AS revoked_server
                              WHERE revoked_server.repo_id = definition.repo_id
                                AND revoked_server.server_definition_id = definition.server_definition_id
                          )
                        ORDER BY definition.updated_at DESC,
                                 definition.server_definition_id DESC
                        LIMIT 128
                        """,
                        (str(row["repo_id"]),),
                    )
                )
                compose_definition_id, compose_run_once_services = (
                    _repository_compose_profile_connection(
                        connection, repo_id=str(row["repo_id"])
                    )
                )
                return {
                    "schema_version": 2,
                    "ok": True,
                    "state": "available",
                    "repository": {
                        "canonical_root": canonical_root,
                        "repo_id": str(row["repo_id"]),
                        "generation": int(row["generation"]),
                        "execution_uid": int(accepted.attribution_uid),
                        "servers": {
                            str(server["name"]): str(server["server_definition_id"])
                            for server in reversed(server_rows)
                        },
                        "containers": {},
                        "compose_definition_id": compose_definition_id,
                        "compose_container_ids": [],
                        "compose_run_once_services": compose_run_once_services,
                        "ephemeral_templates": {},
                        "ephemeral_secret_policies": {},
                    },
                }

    def retarget_test_repository(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        repo_id: str,
    ) -> AcceptedBrokerRequest:
        """Resolve an opaque test handle to its exact repository target.

        The original request project is only a host-test-namespace anchor for
        commands whose public contract contains a plan/run id but no path.
        This method preserves the caller attribution and binds the same exact
        operation and operation id to the resolved immutable repository before
        any read or mutation crosses into testd.
        """

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                repository = connection.execute(
                    "SELECT generation FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                generation = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
        if repository is None or generation is None:
            raise BrokerError(
                "repository_unavailable",
                "The resolved test repository is not present in the local catalog.",
                operation_id=accepted.request.operation_id,
            )
        request = accepted.request
        exact = BrokerRequest.create(
            operation_id=request.operation_id,
            authority_generation=str(generation[0]),
            account_id=request.account_id,
            project_id=repo_id,
            repository_generation=int(repository["generation"]),
            resource_id=repo_id,
            operation=request.operation,
            arguments=request.arguments,
        )
        return self.accept(accepted.peer, exact)

    def current_test_repositories(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[dict[str, object], ...]:
        """Return every active repository in the server-wide test catalog.

        This authority read supplies only immutable IDs and display metadata.
        Test setup state and telemetry remain owned by testd's separate store.
        """

        with self._store() as store:
            with store.read_transaction() as connection:
                rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT repository.repo_id, repository.canonical_root,
                               repository.display_name, repository.generation
                        FROM repositories AS repository
                        JOIN repository_installations AS installation USING(repo_id)
                        WHERE repository.state = 'active'
                          AND installation.status = 'installed'
                          AND installation.startup_fenced = 0
                        ORDER BY lower(repository.display_name),
                                 repository.repo_id
                        LIMIT 501
                        """,
                    )
                ]
        if len(rows) > 500:
            raise BrokerError(
                "test_repository_catalog_too_large",
                "The authenticated test repository catalog exceeds its safe bound.",
                operation_id=accepted.request.operation_id,
            )
        return tuple(rows)

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
        """Install the trusted-local broker schema and erase legacy ACL state."""

        with self._store() as store:
            with store.immediate_transaction(
                max_seconds=BROKER_INITIALIZATION_MAX_SECONDS,
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                _migrate_trusted_local_broker_schema(connection)
                for statement in BROKER_SCHEMA.split(";"):
                    if statement.strip():
                        connection.execute(statement)

                effective_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_compose_effective_model_evidence)"
                    )
                }
                compose_column_defaults = {
                    "service_replicas_json": "{}",
                    "model_services_json": "[]",
                    "model_service_replicas_json": "{}",
                    "service_images_json": "{}",
                }
                for column, default in compose_column_defaults.items():
                    if column not in effective_columns:
                        connection.execute(
                            f"ALTER TABLE broker_compose_effective_model_evidence "
                            f"ADD COLUMN {column} TEXT NOT NULL DEFAULT '{default}'"
                        )
                run_once_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_compose_run_once_attempts)"
                    )
                }
                if run_once_columns and "receipt_error_code" not in run_once_columns:
                    connection.execute(
                        "ALTER TABLE broker_compose_run_once_attempts "
                        "ADD COLUMN receipt_error_code TEXT"
                    )
                worker_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_worker_operation_requests)"
                    )
                }
                if "prepared_json" not in worker_columns:
                    connection.execute(
                        "ALTER TABLE broker_worker_operation_requests "
                        "ADD COLUMN prepared_json TEXT"
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
        later reconfiguration cannot change an in-flight recovery target.
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
                        "repository_unavailable",
                        "Ephemeral template repository is not present in the local catalog.",
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

    def ephemeral_image_target(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        require_reserved_operation: bool = False,
    ) -> EphemeralImageTarget:
        """Resolve only the current sealed image for one template-scoped request."""

        request = accepted.request
        if request.operation not in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_STATUS,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        }:
            raise ValueError("request does not target an ephemeral template image")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                return _ephemeral_image_target_for_request(
                    connection,
                    request=request,
                    require_reserved_operation=require_reserved_operation,
                )

    def complete_ephemeral_image_prefetch(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        target: EphemeralImageTarget,
        proof: Mapping[str, Any],
        cache_origin: str,
        changed: bool | None,
    ) -> dict[str, Any]:
        """Persist one exact, digest-proven image cache receipt."""

        request = accepted.request
        if request.operation is not BrokerOperation.EPHEMERAL_IMAGE_PREFETCH:
            raise ValueError("request is not an ephemeral image prefetch")
        if cache_origin not in {"already_present", "pulled", "reconciled"}:
            raise ValueError("ephemeral image cache origin is invalid")
        if changed is not None and type(changed) is not bool:
            raise ValueError("ephemeral image cache changed must be boolean or null")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
        accepted: AcceptedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
    ) -> EphemeralSecretRunTarget:
        """Accept one descriptor retrieval against the exact running run.

        This returns only policy and opaque binding metadata; the password is
        deliberately owned by the volatile runtime manager and never enters
        this database transaction or the wire result.
        """

        request = accepted.request
        if request.operation is not BrokerOperation.EPHEMERAL_SECRET_FD:
            raise ValueError("request is not an ephemeral credential delivery")
        canonical_run_id = str(run_id)
        if request.resource_id != canonical_run_id:
            raise BrokerError(
                "resource_unavailable",
                "Credential delivery must target the exact ephemeral run identity.",
                operation_id=request.operation_id,
            )
        _require_identifier(template_id, "template_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                if row is None:
                    raise BrokerError(
                        "resource_unavailable",
                        "Credential delivery requires an exact running ephemeral run.",
                        operation_id=request.operation_id,
                    )
                if str(row["template_id"]) != template_id:
                    raise BrokerError(
                        "resource_unavailable",
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
        run_once_services: Iterable[Mapping[str, Any]] = (),
        project_name: Optional[str] = None,
        observation_snapshot_id: Optional[str] = None,
        host_access_approved: bool | None = False,
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
        if isinstance(run_once_services, (str, bytes, Mapping)):
            raise ValueError(
                "run_once_services must be an iterable of sealed service policies"
            )
        if host_access_approved is not None and type(host_access_approved) is not bool:
            raise TypeError("host_access_approved must be boolean or null")
        if host_access_approved is True and _service_administrator_uid() != 0:
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
        normalized_run_once = normalize_compose_run_once_policies(
            tuple(run_once_services)
        )
        run_once_names = tuple(policy.name for policy in normalized_run_once)
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
        if set(normalized_services) & set(run_once_names):
            raise ValueError(
                "Compose lifecycle and run-once service scopes must be disjoint"
            )
        model_services = tuple((*normalized_services, *run_once_names))
        if not 1 <= len(supplied_files) <= 16:
            raise ValueError("compose_files must contain from one through 16 paths")

        previous_host_access_approved = False
        previous_host_access_risks: tuple[str, ...] = ()
        with self._store() as store:
            with store.read_transaction() as connection:
                repo = connection.execute(
                    "SELECT canonical_root FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                previous_evidence = connection.execute(
                    """
                    SELECT effective.host_access_approved,
                           effective.host_access_risks_json
                    FROM broker_compose_effective_model_evidence effective
                    JOIN broker_compose_definitions definition
                      USING(compose_definition_id)
                    WHERE effective.compose_definition_id = ?
                      AND definition.repo_id = ?
                    """,
                    (compose_definition_id, repo_id),
                ).fetchone()
        if previous_evidence is not None:
            previous_host_access_approved = bool(
                previous_evidence["host_access_approved"]
            )
            previous_risks_raw = json.loads(
                str(previous_evidence["host_access_risks_json"])
            )
            if not isinstance(previous_risks_raw, list) or any(
                not isinstance(item, str) for item in previous_risks_raw
            ):
                raise BrokerError(
                    "compose_definition_invalid",
                    "Retained Compose host-access evidence is invalid.",
                )
            previous_host_access_risks = tuple(previous_risks_raw)
        if repo is None:
            raise BrokerError(
                "repository_unavailable",
                "Compose repository is not present in the local catalog.",
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
                )
                env_file_evidence_list.append(evidence)
                env_payload_list.append(payload)
            file_evidence = tuple(file_evidence_list)
            env_file_evidence = tuple(env_file_evidence_list)
            effective_evidence: EffectiveComposeEvidence | None = None
            effective_host_access_approved = host_access_approved is True
            if enabled:
                if self.compose_model_renderer is None:
                    raise RuntimeError(
                        "enabling Compose requires a service-owned merged-model renderer"
                    )
                rendered = self.compose_model_renderer(
                    compose_payloads=tuple(compose_payload_list),
                    env_payloads=tuple(env_payload_list),
                    profiles=normalized_profiles,
                    declared_services=model_services,
                    project_name=normalized_project_name,
                    pinned_cwd=stable_compose_descriptor_path(cwd_descriptor),
                )
                effective_evidence = require_effective_compose_model(
                    rendered,
                    declared_services=model_services,
                    declared_profiles=normalized_profiles,
                    project_name=normalized_project_name,
                    host_access_approved=(
                        previous_host_access_approved
                        if host_access_approved is None
                        else host_access_approved
                    ),
                )
                if host_access_approved is None and previous_host_access_approved:
                    added_risks = sorted(
                        set(effective_evidence.host_access_risks)
                        - set(previous_host_access_risks)
                    )
                    if added_risks:
                        raise PermissionError(
                            "effective Compose model adds administrator-approved "
                            "host access: " + ", ".join(added_risks)
                        )
                    effective_host_access_approved = True
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
            run_once_services=normalized_run_once,
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
                        effective_evidence.host_access_risks
                        and effective_host_access_approved
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_compose_effective_model_evidence(
                            compose_definition_id, definition_fingerprint,
                            model_sha256, services_json, service_replicas_json,
                            model_services_json, model_service_replicas_json,
                            service_images_json,
                            profiles_json,
                            host_access_risks_json, host_access_approved,
                            approved_by_uid, approved_at, replica_budget,
                            validated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(compose_definition_id) DO UPDATE SET
                            definition_fingerprint = excluded.definition_fingerprint,
                            model_sha256 = excluded.model_sha256,
                            services_json = excluded.services_json,
                            service_replicas_json = excluded.service_replicas_json,
                            model_services_json = excluded.model_services_json,
                            model_service_replicas_json =
                                excluded.model_service_replicas_json,
                            service_images_json = excluded.service_images_json,
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
                            json.dumps(list(normalized_services)),
                            json.dumps(
                                {
                                    name: count
                                    for name, count
                                    in effective_evidence.service_replicas
                                    if name in set(normalized_services)
                                }
                            ),
                            json.dumps(list(effective_evidence.services)),
                            json.dumps(dict(effective_evidence.service_replicas)),
                            json.dumps(dict(effective_evidence.service_images)),
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
                connection.execute(
                    "DELETE FROM broker_compose_run_once_services "
                    "WHERE compose_definition_id = ?",
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
                connection.executemany(
                    """
                    INSERT INTO broker_compose_run_once_services(
                        compose_definition_id, ordinal, service_name,
                        max_timeout_seconds, receipt_contract_json,
                        policy_fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            compose_definition_id,
                            ordinal,
                            policy.name,
                            policy.max_timeout_seconds,
                            json.dumps(
                                policy.receipt.to_document(),
                                ensure_ascii=True,
                                allow_nan=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            policy.fingerprint,
                        )
                        for ordinal, policy in enumerate(normalized_run_once)
                    ),
                )
        return {
            "compose_definition_id": compose_definition_id,
            "repo_id": repo_id,
            "definition_fingerprint": definition_fingerprint,
            "generation": generation,
            "enabled": bool(enabled),
            "run_once_services": {
                policy.name: policy.max_timeout_seconds
                for policy in normalized_run_once
            },
        }

    def configured_compose_definition_id(self, *, repo_id: str) -> str | None:
        """Return the sole definition managed by repository configuration."""

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
                "Repository configuration found multiple Compose definitions; reconcile them explicitly before reconfiguration.",
            )
        selected = enabled[0] if enabled else (rows[0] if rows else None)
        return None if selected is None else str(selected["compose_definition_id"])

    def compose_host_access_status(self, *, repo_id: str) -> dict[str, Any]:
        """Return the exact effective approval bound to one active definition."""

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT definition.compose_definition_id,
                               definition.definition_fingerprint,
                               definition.generation,
                               effective.host_access_risks_json,
                               effective.host_access_approved,
                               effective.approved_by_uid,
                               effective.approved_at
                        FROM broker_compose_definitions definition
                        JOIN broker_compose_effective_model_evidence effective
                          USING(compose_definition_id)
                        WHERE definition.repo_id = ?
                          AND definition.enabled = 1
                        ORDER BY definition.compose_definition_id
                        """,
                        (repo_id,),
                    )
                )
        if len(rows) != 1:
            raise BrokerError(
                "compose_definition_conflict",
                "Repository host-access approval requires exactly one active Compose definition.",
            )
        row = rows[0]
        try:
            risks = json.loads(str(row["host_access_risks_json"]))
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise StoreInvariantError(
                "Retained Compose host-access risks are invalid."
            ) from error
        if (
            not isinstance(risks, list)
            or any(not isinstance(item, str) or not item for item in risks)
            or risks != sorted(set(risks))
        ):
            raise StoreInvariantError(
                "Retained Compose host-access risks are invalid."
            )
        return {
            "compose_definition_id": str(row["compose_definition_id"]),
            "definition_fingerprint": str(row["definition_fingerprint"]),
            "generation": int(row["generation"]),
            "host_access_risks": list(risks),
            "host_access_approved": bool(row["host_access_approved"]),
            "approved_by_uid": (
                None
                if row["approved_by_uid"] is None
                else int(row["approved_by_uid"])
            ),
            "approved_at": (
                None if row["approved_at"] is None else str(row["approved_at"])
            ),
        }

    def compose_configuration_container_scope(
        self,
        *,
        repo_id: str,
        snapshot_id: str,
        project_name: str,
        service_names: Sequence[str],
        run_once_service_names: Sequence[str] = (),
    ) -> ComposeConfigurationContainerScope:
        """Resolve and validate one repository's complete Compose project scope.

        The protected client profile needs this exact subset so a whole-project
        action can run the Compose definition once and then operate only on
        genuinely standalone containers.  Names and image references are not
        ownership authority: the fenced snapshot's Compose project/service
        labels, exclusive repository binding, and immutable Docker resource ID
        are all required.  An active, exclusively owned container in this same
        Compose project may not disappear merely because its service was omitted
        from the lifecycle declaration; that partial declaration is rejected
        with a typed configuration error.  Explicit run-once services remain
        outside both lifecycle and standalone resource scopes.
        """

        _require_identifier(repo_id, "project_id")
        _require_identifier(snapshot_id, "snapshot_id")
        normalized_project = _require_compose_project_name(project_name)
        if isinstance(service_names, (str, bytes, bytearray)):
            raise ValueError("Compose lifecycle services must be a sequence")
        normalized_services = tuple(
            _require_compose_service_name(str(item)) for item in service_names
        )
        if (
            not normalized_services
            or len(normalized_services) > 256
            or len(set(normalized_services)) != len(normalized_services)
        ):
            raise ValueError(
                "Compose-owned container projection requires unique declared services"
            )
        if isinstance(run_once_service_names, (str, bytes, bytearray)):
            raise ValueError("Compose run-once services must be a sequence")
        normalized_run_once = tuple(
            _require_compose_service_name(str(item))
            for item in run_once_service_names
        )
        if (
            len(normalized_run_once) > 256
            or len(set(normalized_run_once)) != len(normalized_run_once)
            or set(normalized_services) & set(normalized_run_once)
        ):
            raise ValueError(
                "Compose run-once services must be unique and disjoint from lifecycle services"
            )
        lifecycle_services = frozenset(normalized_services)
        run_once_services = frozenset(normalized_run_once)
        with self._store() as store:
            with store.read_transaction() as connection:
                snapshot = connection.execute(
                    """
                    SELECT snapshot.host_id
                    FROM repositories repository
                    JOIN observation_snapshots snapshot
                      ON snapshot.host_id = repository.host_id
                    JOIN observation_capabilities capability
                      ON capability.snapshot_id = snapshot.snapshot_id
                     AND capability.observer_domain = snapshot.observer_domain
                    JOIN broker_observation_compose_scope compose_scope
                      ON compose_scope.snapshot_id = snapshot.snapshot_id
                    WHERE repository.repo_id = ? AND snapshot.snapshot_id = ?
                      AND snapshot.status = 'completed'
                      AND snapshot.completed_at IS NOT NULL
                      AND snapshot.observer_domain = 'host-runtime-v2:full-docker'
                      AND capability.docker_available = 1
                      AND compose_scope.assets_complete = 1
                    """,
                    (repo_id, snapshot_id),
                ).fetchone()
                if snapshot is None:
                    raise BrokerError(
                        "docker_observation_mismatch",
                        "Compose-owned container projection requires the exact completed configuration snapshot.",
                    )
                rows = list(
                    connection.execute(
                        """
                        SELECT observed.docker_resource_id,
                               observed.full_container_id,
                               observed.service_name,
                               observed.lifecycle,
                               observed.association_state,
                               observed.associated_repo_id,
                               resource.full_container_id AS current_full_container_id,
                               resource.repo_id AS current_repo_id
                        FROM broker_observed_compose_containers observed
                        JOIN observation_snapshot_resources present
                          ON present.snapshot_id = observed.snapshot_id
                         AND present.resource_kind = 'container'
                         AND present.resource_id = observed.docker_resource_id
                        JOIN docker_resources resource
                          ON resource.docker_resource_id = observed.docker_resource_id
                        WHERE observed.snapshot_id = ?
                          AND observed.project_name = ?
                        ORDER BY observed.docker_resource_id
                        """,
                        (
                            snapshot_id,
                            normalized_project,
                        ),
                    )
                )
        lifecycle_result: list[str] = []
        non_lifecycle_result: list[str] = []
        unexpected_active_services: set[str] = set()
        for row in rows:
            resource_id = str(row["docker_resource_id"])
            service_name = (
                None
                if row["service_name"] is None
                else str(row["service_name"])
            )
            exclusively_owned = (
                str(row["association_state"]) == "exclusive"
                and str(row["associated_repo_id"] or "") == repo_id
            )
            if service_name not in lifecycle_services:
                if (
                    exclusively_owned
                    and str(row["lifecycle"]) == "running"
                    and service_name not in run_once_services
                ):
                    unexpected_active_services.add(
                        service_name or "<missing-service-label>"
                    )
                if exclusively_owned:
                    non_lifecycle_result.append(resource_id)
                continue
            if (
                not exclusively_owned
                or str(row["current_repo_id"] or "") != repo_id
                or str(row["full_container_id"]).lower()
                != str(row["current_full_container_id"]).lower()
            ):
                raise BrokerError(
                    "resource_identity_unavailable",
                    "Compose-owned container identity changed before profile publication.",
                )
            lifecycle_result.append(resource_id)
        if unexpected_active_services:
            raise BrokerError(
                "compose_scope_incomplete",
                "Compose configuration omits active exclusively owned services from "
                f"project {normalized_project!r}: "
                + ", ".join(sorted(unexpected_active_services))
                + ". Declare each service as lifecycle or explicit run-once before configuration.",
            )
        all_result_ids = (*lifecycle_result, *non_lifecycle_result)
        if len(set(all_result_ids)) != len(all_result_ids):
            raise BrokerError(
                "resource_identity_unavailable",
                "Compose-owned container identity is duplicated in configuration evidence.",
            )
        return ComposeConfigurationContainerScope(
            lifecycle_container_ids=tuple(sorted(lifecycle_result)),
            non_lifecycle_container_ids=tuple(sorted(non_lifecycle_result)),
        )

    def compose_owned_container_ids(
        self,
        *,
        repo_id: str,
        snapshot_id: str,
        project_name: str,
        service_names: Sequence[str],
        run_once_service_names: Sequence[str] = (),
    ) -> tuple[str, ...]:
        """Return the lifecycle-controlled subset of a validated Compose scope."""

        return self.compose_configuration_container_scope(
            repo_id=repo_id,
            snapshot_id=snapshot_id,
            project_name=project_name,
            service_names=service_names,
            run_once_service_names=run_once_service_names,
        ).lifecycle_container_ids

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
        prevents reconfiguration code from reviving the old immutable ID.
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
                        "resource_identity_unavailable",
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
                connection.execute(
                    """
                    UPDATE broker_port_ranges
                    SET enabled = 0, updated_at = ?
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (timestamp, repo_id, server_definition_id),
                )
        return {
            "status": "revoked",
            "repo_id": repo_id,
            "server_definition_id": server_definition_id,
            "server_name": server_name,
            "cleanup_operation_id": cleanup_operation_id,
            "immutable_fingerprint": immutable_fingerprint,
            "already_revoked": existing is not None,
            "routing_cache_update_required": True,
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
                        "repository_unavailable",
                        "Permanent repository removal targets no current or retained exact repository generation.",
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

                connection.execute(
                    "UPDATE broker_port_ranges SET enabled = 0, updated_at = ? WHERE repo_id = ?",
                    (timestamp, repo_id),
                )
                connection.execute(
                    """
                    UPDATE broker_compose_definitions
                    SET enabled = 0, generation = generation + 1, updated_at = ?
                    WHERE repo_id = ? AND enabled = 1
                    """,
                    (timestamp, repo_id),
                )
        return {
            "status": "revoked",
            "repo_id": repo_id,
            "repository_generation": repository_generation,
            "canonical_root": canonical_root,
            "cleanup_operation_id": cleanup_operation_id,
            "immutable_fingerprint": immutable_fingerprint,
            "already_revoked": existing is not None,
            "server_revocations": server_revocations,
            "routing_cache_update_required": True,
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

    def replace_server_port_ranges(
        self,
        *,
        repo_id: str,
        server_definition_ids: Iterable[str],
        start_port: int,
        end_port: int,
        protocol: str = "tcp",
        max_ttl_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        """Replace server-specific host allocation ranges for one repository."""

        _require_identifier(repo_id, "project_id")
        selected = tuple(sorted(set(server_definition_ids)))
        for item in selected:
            _require_identifier(item, "server_definition_id")
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("server port range is invalid")
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        if not 1 <= max_ttl_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("max_ttl_seconds is invalid")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                known = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT server_definition_id FROM server_definitions WHERE repo_id = ?",
                        (repo_id,),
                    )
                }
                if any(item not in known for item in selected):
                    raise BrokerError(
                        "resource_identity_mismatch",
                        "Port range replacement includes a server outside the target repository.",
                    )
                connection.execute(
                    "UPDATE broker_port_ranges SET enabled = 0, updated_at = ? WHERE repo_id = ?",
                    (now, repo_id),
                )
                for server_id in selected:
                    connection.execute(
                        """
                        INSERT INTO broker_port_ranges(
                            repo_id, server_definition_id, protocol,
                            start_port, end_port, max_ttl_seconds,
                            enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                        ON CONFLICT(
                            repo_id, server_definition_id, protocol, start_port, end_port
                        ) DO UPDATE SET
                            max_ttl_seconds = excluded.max_ttl_seconds,
                            enabled = 1,
                            updated_at = excluded.updated_at
                        """,
                        (
                            repo_id,
                            server_id,
                            protocol,
                            start_port,
                            end_port,
                            max_ttl_seconds,
                            now,
                        ),
                    )

    def set_server_port_range(
        self,
        *,
        repo_id: str,
        server_definition_id: str,
        start_port: int,
        end_port: int,
        protocol: str = "tcp",
        max_ttl_seconds: int = 3_600,
        enabled: bool = True,
        replace_existing: bool = False,
    ) -> None:
        """Set one target server's allocation range for every local caller."""

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
        if type(replace_existing) is not bool:
            raise TypeError("replace_existing must be boolean")
        with self._store() as store:
            with store.immediate_transaction() as connection:
                server = connection.execute(
                    """
                    SELECT 1 FROM server_definitions
                    WHERE repo_id = ? AND server_definition_id = ?
                    """,
                    (repo_id, server_definition_id),
                ).fetchone()
                if server is None:
                    raise BrokerError(
                        "resource_identity_mismatch",
                        "Port range target is not a current server definition.",
                    )
                conflict = None if replace_existing else connection.execute(
                    """
                    SELECT start_port, end_port FROM broker_port_ranges
                    WHERE repo_id = ? AND server_definition_id = ?
                      AND protocol = ? AND enabled = 1
                      AND NOT(end_port < ? OR start_port > ?)
                      AND NOT(start_port = ? AND end_port = ?)
                    LIMIT 1
                    """,
                    (
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
                        "overlapping_port_range",
                        "Port ranges for one server must not overlap.",
                    )
                if replace_existing:
                    connection.execute(
                        """
                        UPDATE broker_port_ranges
                        SET enabled = 0, updated_at = ?
                        WHERE repo_id = ? AND server_definition_id = ?
                          AND protocol = ?
                          AND NOT(start_port = ? AND end_port = ?)
                        """,
                        (
                            utc_timestamp(),
                            repo_id,
                            server_definition_id,
                            protocol,
                            start_port,
                            end_port,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO broker_port_ranges(
                        repo_id, server_definition_id, protocol,
                        start_port, end_port, max_ttl_seconds, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repo_id, server_definition_id, protocol, start_port, end_port)
                    DO UPDATE SET max_ttl_seconds = excluded.max_ttl_seconds,
                                  enabled = excluded.enabled,
                                  updated_at = excluded.updated_at
                    """,
                    (
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

    def fail_instance_host_observations(self, *, broker_instance_id: str) -> int:
        """Durably terminate running tickets started by one broker process."""

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
                        JOIN broker_host_observation_sessions o USING(snapshot_id)
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

    def accept(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=peer, request=request)
        return AcceptedBrokerRequest(peer=peer, request=request)

    def accept_internal_testd(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AcceptedBrokerRequest:
        """Validate the typed internal scheduler namespace.

        The dedicated testd account remains useful for process isolation and
        peer attribution. Neither its label nor physical UID grants authority;
        operation shape and current attempt state remain exact.
        """

        if request.operation not in TESTD_INTERNAL_OPERATIONS:
            raise BrokerError(
                "operation_unavailable",
                "The internal test scheduler accepts only attempt operations.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                generation = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
                repository = connection.execute(
                    """
                    SELECT repository.generation, repository.state,
                           installation.status, installation.startup_fenced
                    FROM repositories repository
                    JOIN repository_installations installation USING(repo_id)
                    WHERE repository.repo_id = ?
                    """,
                    (request.project_id,),
                ).fetchone()
        if generation is None or request.authority_generation not in {
            str(generation[0]),
            "broker-current-testd",
        }:
            raise BrokerError(
                "broker_generation_mismatch",
                "The test scheduler belongs to another broker authority generation.",
                operation_id=request.operation_id,
            )
        if (
            repository is None
            or str(repository["state"]) != "active"
            or str(repository["status"]) != "installed"
            or bool(repository["startup_fenced"])
        ):
            raise BrokerError(
                "repository_startup_fenced",
                "The exact test repository is unavailable or fenced.",
                operation_id=request.operation_id,
            )
        actual_generation = int(repository["generation"])
        if (
            request.operation is not BrokerOperation.TEST_ATTEMPT_TICKET
            and request.repository_generation != actual_generation
        ):
            raise BrokerError(
                "project_generation_stale",
                "The test attempt belongs to an obsolete repository generation.",
                operation_id=request.operation_id,
            )
        if (
            request.operation is BrokerOperation.TEST_ATTEMPT_TICKET
            and request.repository_generation not in {0, actual_generation}
        ):
            raise BrokerError(
                "project_generation_stale",
                "The test attempt ticket targets an obsolete repository generation.",
                operation_id=request.operation_id,
            )
        return AcceptedBrokerRequest(peer=peer, request=request)

    def test_attempt_repository_context(
        self,
        *,
        repo_id: str,
        execution_uid: int | None,
        operation_id: str,
    ) -> TestRepositoryExecutionContext:
        """Bind an attempt to a current repository and recorded execution UID."""

        _require_identifier(repo_id, "project_id")
        if type(execution_uid) is not int or execution_uid < 0:
            raise BrokerError(
                "test_execution_context_invalid",
                "The test attempt has no valid execution attribution.",
                operation_id=operation_id,
            )
        return self.test_repository_execution_context(
            repo_id=repo_id,
            execution_uid=execution_uid,
            operation_id=operation_id,
        )

    def test_repository_execution_context(
        self,
        *,
        repo_id: str,
        execution_uid: int,
        operation_id: str,
    ) -> TestRepositoryExecutionContext:
        """Resolve one current repository without any owner or ACL lookup."""

        _require_identifier(repo_id, "project_id")
        if type(execution_uid) is not int or execution_uid < 0:
            raise BrokerError(
                "test_execution_context_invalid",
                "Test execution requires a non-negative attributed UID.",
                operation_id=operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    """
                    SELECT schema_version, migration_state
                    FROM schema_metadata WHERE singleton = 1
                    """
                ).fetchone()
                row = connection.execute(
                    """
                    SELECT repository.canonical_root, repository.generation,
                           repository.state, installation.status,
                           installation.startup_fenced
                    FROM repositories repository
                    JOIN repository_installations installation USING(repo_id)
                    WHERE repository.repo_id = ?
                    """,
                    (repo_id,),
                ).fetchone()
        if (
            metadata is None
            or int(metadata["schema_version"]) != SCHEMA_VERSION
            or str(metadata["migration_state"]) != "ready"
            or row is None
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
        ):
            raise BrokerError(
                "test_repository_unavailable",
                "The exact test repository is unavailable or fenced.",
                operation_id=operation_id,
            )
        return TestRepositoryExecutionContext(
            repo_id=repo_id,
            canonical_root=str(row["canonical_root"]),
            generation=int(row["generation"]),
            execution_uid=execution_uid,
        )

    def sealed_test_fixture_template(
        self,
        *,
        repo_id: str,
        owner_uid: int,
        repository_generation: int,
        template: str,
        operation_id: str,
    ) -> SealedTestFixtureTemplate:
        """Resolve one administrator-sealed fixture after exact test authority."""

        repository_context = self.test_attempt_repository_context(
            repo_id=repo_id,
            execution_uid=owner_uid,
            operation_id=operation_id,
        )
        if repository_context.generation != repository_generation:
            raise BrokerError(
                "project_generation_stale",
                "The sealed fixture targets an obsolete repository generation.",
                operation_id=operation_id,
            )
        _require_identifier(template, "fixture template")
        with self._store() as store:
            with store.read_transaction() as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM ephemeral_container_templates
                    WHERE enabled = 1 AND template_id = ?
                    ORDER BY template_id
                    """,
                    (template,),
                ).fetchall()
                if not rows:
                    rows = connection.execute(
                        """
                        SELECT * FROM ephemeral_container_templates
                        WHERE enabled = 1 AND name = ?
                        ORDER BY template_id
                        """,
                        (template,),
                    ).fetchall()
                    if len(rows) > 1:
                        routed = [
                            row for row in rows if str(row["repo_id"]) == repo_id
                        ]
                        if len(routed) == 1:
                            rows = routed
                    if len(rows) > 1:
                        canonical_id = "ephemeral-template-" + template
                        canonical = [
                            row
                            for row in rows
                            if str(row["template_id"]) == canonical_id
                        ]
                        if len(canonical) == 1:
                            rows = canonical
                    if len(rows) > 1:
                        def routing_signature(candidate: sqlite3.Row) -> tuple[Any, ...]:
                            candidate_id = str(candidate["template_id"])
                            candidate_arguments = tuple(
                                str(item[0])
                                for item in connection.execute(
                                    """
                                    SELECT argument FROM ephemeral_template_arguments
                                    WHERE template_id = ? ORDER BY ordinal
                                    """,
                                    (candidate_id,),
                                )
                            )
                            candidate_environment = tuple(
                                (str(item[0]), str(item[1]))
                                for item in connection.execute(
                                    """
                                    SELECT name, value FROM ephemeral_template_environment
                                    WHERE template_id = ? ORDER BY name
                                    """,
                                    (candidate_id,),
                                )
                            )
                            return (
                                str(candidate["name"]),
                                str(candidate["image_ref"]),
                                candidate["secret_policy_kind"],
                                candidate["secret_binding_id"],
                                candidate["container_tcp_port"],
                                candidate_arguments,
                                candidate_environment,
                            )

                        signatures = {routing_signature(row) for row in rows}
                        if len(signatures) == 1:
                            rows = [rows[0]]
                if len(rows) != 1:
                    candidate_ids = [
                        str(row["template_id"])
                        for row in rows[:8]
                    ]
                    candidate_suffix = (
                        "; candidates=" + ",".join(candidate_ids)
                        if candidate_ids
                        else ""
                    )
                    raise BrokerError(
                        "test_fixture_template_unavailable",
                        "The administrator-sealed fixture template is unavailable "
                        "or ambiguous"
                        + candidate_suffix
                        + ".",
                        operation_id=operation_id,
                    )
                row = rows[0]
                arguments = tuple(
                    str(item[0])
                    for item in connection.execute(
                        """
                        SELECT argument FROM ephemeral_template_arguments
                        WHERE template_id = ? ORDER BY ordinal
                        """,
                        (row["template_id"],),
                    )
                )
                environment = tuple(
                    (str(item[0]), str(item[1]))
                    for item in connection.execute(
                        """
                        SELECT name, value FROM ephemeral_template_environment
                        WHERE template_id = ? ORDER BY name
                        """,
                        (row["template_id"],),
                    )
                )
        image_ref = _require_pinned_ephemeral_image(row["image_ref"])
        definition_fingerprint = str(row["definition_fingerprint"])
        if re.fullmatch(r"sha256:[0-9a-f]{64}", definition_fingerprint) is None:
            raise BrokerError(
                "test_fixture_template_unavailable",
                "The sealed fixture definition fingerprint is invalid.",
                operation_id=operation_id,
            )
        policy = (
            None
            if row["secret_policy_kind"] is None
            else EphemeralSecretPolicy(
                kind=str(row["secret_policy_kind"]),
                binding_id=str(row["secret_binding_id"]),
            )
        )
        return SealedTestFixtureTemplate(
            template_id=str(row["template_id"]),
            repo_id=repo_id,
            name=str(row["name"]),
            image_ref=image_ref,
            definition_fingerprint=definition_fingerprint,
            command=arguments,
            environment=environment,
            secret_policy=policy,
            container_tcp_port=(
                None if row["container_tcp_port"] is None else int(row["container_tcp_port"])
            ),
            memory_bytes=int(row["memory_bytes"] or 512 * 1024 * 1024),
            cpu_millis=int(row["cpu_millis"] or 1000),
            max_ttl_seconds=int(row["max_ttl_seconds"]),
        )

    def require_test_temporary_root(
        self,
        *,
        root_repo_id: str,
        temporary_root: str,
        operation_id: str,
    ) -> None:
        """Require one live temporary path to be an active member of the root family."""

        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT repository.state
                    FROM repository_families family
                    JOIN repository_scopes scope USING(family_id)
                    JOIN repositories repository USING(repo_id)
                    WHERE family.root_repo_id = ?
                      AND scope.project_kind = 'temporary'
                      AND repository.canonical_root = ?
                    """,
                    (root_repo_id, temporary_root),
                ).fetchone()
        if row is None or str(row["state"]) != "active":
            raise BrokerError(
                "test_source_invalid",
                "The live temporary test source is not an active member of the root repository.",
                operation_id=operation_id,
            )

    @staticmethod
    def _existing_operation_disposition(
        connection: sqlite3.Connection,
        *,
        accepted: AcceptedBrokerRequest,
        fingerprint: str,
    ) -> DurableOperationDisposition | None:
        request = accepted.request
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
        if existing["request_fingerprint"] != fingerprint:
            raise BrokerError(
                "operation_id_conflict",
                "operation_id was already used for a different typed request.",
                operation_id=request.operation_id,
            )
        if (
            existing["status"] == "succeeded"
            and request.operation is BrokerOperation.RUNTIME_ENSURE
        ):
            return DurableOperationDisposition(
                "completed",
                result=_decode_runtime_ensure_result(
                    existing["result_json"], operation_id=request.operation_id
                ),
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
            and accepted.request.operation is BrokerOperation.RUNTIME_REQUEST
        ):
            return DurableOperationDisposition(
                "reconcile",
                error_code=existing["error_code"],
                error_message=existing["error_message"],
            )
        if (
            existing["status"] == "needs_attention"
            and accepted.request.operation is BrokerOperation.RUNTIME_ENSURE
            and isinstance(existing["result_json"], str)
        ):
            retained = _decode_runtime_ensure_result(
                existing["result_json"], operation_id=request.operation_id
            )
            if (
                retained.get("operation_id") == request.operation_id
                and retained.get("ok") is False
                and retained.get("classification") == "attention_required"
            ):
                return DurableOperationDisposition(
                    "completed", result=retained
                )
        if existing["status"] == "needs_attention":
            return DurableOperationDisposition(
                "failed",
                error_code=existing["error_code"] or "mutation_failed",
                error_message=existing["error_message"] or "Broker mutation failed.",
            )
        return DurableOperationDisposition("pending")

    def existing_operation_disposition(
        self, accepted: AcceptedBrokerRequest
    ) -> DurableOperationDisposition | None:
        """Read an idempotent replay result without reserving a new operation."""

        request_fingerprint = accepted_request_fingerprint(accepted)
        with self._store() as store:
            with store.read_transaction() as connection:
                return self._existing_operation_disposition(
                    connection,
                    accepted=accepted,
                    fingerprint=request_fingerprint,
                )

    def reserve_operation(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        compose_preflight: Mapping[str, Any] | None = None,
    ) -> DurableOperationDisposition:
        request = accepted.request
        request_fingerprint = accepted_request_fingerprint(accepted)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                existing = self._existing_operation_disposition(
                    connection,
                    accepted=accepted,
                    fingerprint=request_fingerprint,
                )
                if existing is not None:
                    if (
                        existing.state == "pending"
                        and request.operation is BrokerOperation.CLEANUP_PLAN
                    ):
                        connection.execute(
                            """
                            UPDATE operation_targets
                            SET target_kind = ?, target_id = ?, action = ?,
                                immutable_fingerprint = ?
                            WHERE operation_id = ? AND ordinal = 0
                              AND status = 'running'
                            """,
                            (
                                str(request.arguments["target_kind"]),
                                str(request.arguments["target_id"]),
                                "cleanup." + str(request.arguments["action"]),
                                request_fingerprint,
                                request.operation_id,
                            ),
                        )
                    return existing

                _validate_connection_request(connection, peer=accepted.peer, request=request)
                compose_snapshot: sqlite3.Row | None = None
                runtime_target: tuple[str, str, str, str] | None = None
                if request.operation is BrokerOperation.CLEANUP_PLAN:
                    runtime_target = (
                        str(request.arguments["target_kind"]),
                        str(request.arguments["target_id"]),
                        "cleanup." + str(request.arguments["action"]),
                        request_fingerprint,
                    )
                elif request.operation is BrokerOperation.LIFECYCLE_RESTORE:
                    runtime_target = (
                        str(request.arguments["target_kind"]),
                        str(request.arguments["target_id"]),
                        "lifecycle.restore",
                        request_fingerprint,
                    )
                elif request.operation is BrokerOperation.CLEANUP_APPLY:
                    cleanup_plan = connection.execute(
                        """
                        SELECT target_kind, target_id, target_fingerprint
                        FROM cleanup_plans WHERE plan_id = ?
                        """,
                        (str(request.arguments["plan_id"]),),
                    ).fetchone()
                    if cleanup_plan is None:
                        lifecycle_plan = connection.execute(
                            """
                            SELECT kind, repo_id, request_fingerprint
                            FROM operations WHERE operation_id = ?
                            """,
                            (str(request.arguments["plan_id"]),),
                        ).fetchone()
                        if (
                            lifecycle_plan is not None
                            and lifecycle_plan["kind"] == "repository_decommission"
                            and lifecycle_plan["repo_id"] is not None
                        ):
                            runtime_target = (
                                "project",
                                str(lifecycle_plan["repo_id"]),
                                "cleanup.apply",
                                str(lifecycle_plan["request_fingerprint"]),
                            )
                        elif (
                            lifecycle_plan is not None
                            and lifecycle_plan["kind"]
                            == "standalone_resource_retirement"
                        ):
                            lifecycle_target = connection.execute(
                                """
                                SELECT target_kind, target_id,
                                       immutable_fingerprint
                                FROM operation_targets
                                WHERE operation_id = ?
                                ORDER BY ordinal LIMIT 1
                                """,
                                (str(request.arguments["plan_id"]),),
                            ).fetchone()
                            if lifecycle_target is not None:
                                runtime_target = (
                                    str(lifecycle_target["target_kind"]),
                                    str(lifecycle_target["target_id"]),
                                    "cleanup.apply",
                                    str(lifecycle_target["immutable_fingerprint"]),
                                )
                        if runtime_target is None:
                            raise BrokerError(
                                "cleanup_plan_unavailable",
                                "The exact cleanup plan does not exist.",
                                operation_id=request.operation_id,
                            )
                    else:
                        runtime_target = (
                            str(cleanup_plan["target_kind"]),
                            str(cleanup_plan["target_id"]),
                            "cleanup.apply",
                            str(cleanup_plan["target_fingerprint"]),
                        )
                if (
                    request.operation is BrokerOperation.RUNTIME_REQUEST
                    and request.arguments["action"] == "temporary_start"
                ):
                    service_id = temporary_dev_service_id(
                        request.project_id,
                        str(request.arguments["name"]),
                    )
                    runtime_target = (
                        "service",
                        service_id,
                        "runtime.temporary_start",
                        fingerprint(
                            {
                                "operation_id": request.operation_id,
                                "repo_id": request.project_id,
                                "generation": request.repository_generation,
                                "arguments": dict(request.arguments),
                            }
                        ),
                    )
                if (
                    request.operation is BrokerOperation.RUNTIME_REQUEST
                    and request.arguments["action"] in {
                        "start", "stop", "restart", "replace"
                    }
                ) or request.operation is BrokerOperation.RUNTIME_ENSURE:
                    runtime_action = _runtime_operation_action(request)
                    if request.arguments["target_kind"] == "service":
                        runtime_target = (
                            "server",
                            request.resource_id,
                            runtime_action,
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
                if request.operation in _ALL_COMPOSE_OPERATIONS:
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
                            connection,
                            request=request,
                            fallback=request_fingerprint,
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
                        request_fingerprint,
                        accepted.peer.uid,
                        _operation_actor(accepted),
                        runtime_process_identity(os.getpid())
                        or f"pid:{os.getpid()}",
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
                        accepted.attribution_uid,
                        request.account_id,
                        request.project_id,
                        request.resource_id,
                        request.operation.value,
                        request_fingerprint,
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
                if request.operation is BrokerOperation.COMPOSE_RUN_ONCE:
                    policy = _compose_run_once_policy_for_request(
                        connection,
                        request=request,
                    )
                    definition = connection.execute(
                        """
                        SELECT definition.definition_fingerprint,
                               definition.generation AS definition_generation,
                               repository.generation AS repository_generation,
                               effective.service_images_json
                        FROM broker_compose_definitions definition
                        JOIN repositories repository USING(repo_id)
                        JOIN broker_compose_effective_model_evidence effective
                          USING(compose_definition_id)
                        WHERE definition.compose_definition_id = ?
                          AND definition.repo_id = ?
                          AND definition.enabled = 1
                        """,
                        (request.resource_id, request.project_id),
                    ).fetchone()
                    if definition is None:
                        raise BrokerError(
                            "compose_effective_model_required",
                            "Compose run-once reservation lacks a current sealed model.",
                            operation_id=request.operation_id,
                        )
                    images = _require_service_image_evidence(
                        definition["service_images_json"],
                        services=tuple(
                            str(row["service_name"])
                            for row in connection.execute(
                                """
                                SELECT service_name
                                FROM broker_compose_services
                                WHERE compose_definition_id = ?
                                UNION
                                SELECT service_name
                                FROM broker_compose_run_once_services
                                WHERE compose_definition_id = ?
                                ORDER BY service_name
                                """,
                                (request.resource_id, request.resource_id),
                            )
                        ),
                        operation_id=request.operation_id,
                        allow_empty=False,
                    )
                    service_image_ref = dict(images).get(policy.name)
                    if service_image_ref is None:
                        raise BrokerError(
                            "compose_run_once_image_unbound",
                            "Compose run-once service has no sealed image reference.",
                            operation_id=request.operation_id,
                        )
                    operation_token = request.operation_id.replace("-", "")
                    container_name = "devcoordinator-once-" + operation_token
                    connection.execute(
                        """
                        INSERT INTO broker_compose_run_once_attempts(
                            operation_id, compose_definition_id, agent,
                            service_name, timeout_seconds, deadline_epoch,
                            container_name, phase, policy_fingerprint,
                            receipt_contract_json, definition_fingerprint,
                            definition_generation, repository_generation,
                            service_image_ref, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            request.operation_id,
                            request.resource_id,
                            str(request.arguments["agent"]),
                            policy.name,
                            int(request.arguments["timeout_seconds"]),
                            int(time.time())
                            + int(request.arguments["timeout_seconds"]),
                            container_name,
                            policy.fingerprint,
                            json.dumps(
                                policy.receipt.to_document(),
                                ensure_ascii=True,
                                allow_nan=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            str(definition["definition_fingerprint"]),
                            int(definition["definition_generation"]),
                            int(definition["repository_generation"]),
                            service_image_ref,
                            now,
                        ),
                    )
        return DurableOperationDisposition("execute")

    def port_lease_candidates(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[int, ...]:
        request = accepted.request
        protocol = str(request.arguments.get("protocol", "tcp"))
        ttl_seconds = int(
            request.arguments.get("ttl_seconds", DEFAULT_PORT_LEASE_TTL_SECONDS)
        )
        requested_port = request.arguments.get("requested_port")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                policies = _port_range_rows(
                    connection,
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
                    selected = int(requested_port)
                    if selected < 1024 or not any(
                        int(policy["start_port"])
                        <= selected
                        <= int(policy["end_port"])
                        for policy in policies
                    ):
                        raise BrokerError(
                            "port_policy_denied",
                            "Requested port is outside the configured server ranges.",
                            operation_id=request.operation_id,
                        )
                    return (selected,)
                return tuple(
                    port
                    for policy in policies
                    for port in range(
                        int(policy["start_port"]), int(policy["end_port"]) + 1
                    )
                )

    def complete_port_lease(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        observed_available_port: int,
        listener_evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = accepted.request
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
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                repo = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                policies = _port_range_rows(
                    connection,
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
                    SELECT l.*, d.name AS lease_server_name
                    FROM leases l
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
                    and (
                        existing["purpose"] == "broker"
                        or (
                            existing["purpose"]
                            == f"server:{existing['lease_server_name']}"
                            and str(existing["owner"] or "").isdigit()
                        )
                    )
                    and existing["protocol"] == protocol
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
                            protocol = ?, expires_at = ?, process_fingerprint = ?,
                            generation = generation + 1, updated_at = ?
                        WHERE lease_id = ? AND status = 'active'
                          AND repo_id = ? AND server_definition_id = ?
                          AND port = ?
                        """,
                        (
                            f"uid:{accepted.peer.uid}",
                            request.account_id,
                            protocol,
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
                        lease_id, host_id, repo_id, server_definition_id, port, protocol,
                        owner, agent, purpose, status, expires_at,
                        process_fingerprint, generation,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'broker', 'active', ?, ?, 0, ?, ?)
                    """,
                    (
                        lease_id,
                        repo["host_id"],
                        request.project_id,
                        request.resource_id,
                        port,
                        protocol,
                        f"uid:{accepted.peer.uid}",
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
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[int, str]:
        """Resolve an accepted adoption target before operation reservation."""

        request = accepted.request
        if not bool(request.arguments.get("adopt_existing_listener")):
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption was not requested.",
                operation_id=request.operation_id,
            )
        candidates = self.port_lease_candidates(accepted)
        if len(candidates) != 1:
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption requires one exact accepted port.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                        "resource_identity_unavailable",
                        "Server listener adoption target is no longer configured.",
                        operation_id=request.operation_id,
                    )
                return int(candidates[0]), str(row["canonical_root"])

    def listener_adoption_target(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[int, str]:
        """Resolve an exact existing-listener adoption target from service truth."""

        request = accepted.request
        if not bool(request.arguments.get("adopt_existing_listener")):
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption was not requested.",
                operation_id=request.operation_id,
            )
        candidates = self.port_lease_candidates(accepted)
        if len(candidates) != 1:
            raise BrokerError(
                "invalid_arguments",
                "Listener adoption requires one exact accepted port.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                        "resource_identity_unavailable",
                        "Server listener adoption target is no longer configured.",
                        operation_id=request.operation_id,
                    )
                return int(candidates[0]), str(row["canonical_root"])

    def complete_port_release(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        request = accepted.request
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                lease = _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                if lease is None or lease["status"] not in {"active", "released"}:
                    raise BrokerError(
                        "lease_not_active",
                        "The exact accepted lease is no longer active.",
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
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[int, ...]:
        """Return the one host port that must be proved free, or no probe for a no-op."""

        request = accepted.request
        port = int(request.arguments["port"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                _require_assignment_port_range(
                    connection,
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
        accepted: AcceptedBrokerRequest,
        *,
        observed_available_port: Optional[int],
    ) -> dict[str, Any]:
        request = accepted.request
        port = int(request.arguments["port"])
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                _require_assignment_port_range(
                    connection,
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
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        request = accepted.request
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
        self, accepted: AcceptedBrokerRequest
    ) -> DockerMutationTarget:
        request = accepted.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                row = connection.execute(
                    """
                    SELECT d.docker_resource_id, d.full_container_id,
                           d.repo_id, m.observation_revision
                    FROM docker_resources d
                    CROSS JOIN schema_metadata m
                    WHERE d.docker_resource_id = ?
                    """,
                    (request.resource_id,),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "resource_unavailable",
                        "Docker resource is no longer present in the current catalog.",
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
                    control_generation=int(row["observation_revision"]),
                    repo_id=str(row["repo_id"] or request.project_id),
                    owner_uid=accepted.attribution_uid,
                )

    def direct_container_removal_target(
        self, accepted: AcceptedBrokerRequest
    ) -> DirectContainerRemovalTarget:
        """Resolve one catalogued container without ownership or lifecycle policy."""

        request = accepted.request
        if request.operation is not BrokerOperation.CONTAINER_REMOVE:
            raise ValueError("request is not direct container removal")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT docker_resource_id, full_container_id
                    FROM docker_resources
                    WHERE docker_resource_id = ?
                    """,
                    (request.resource_id,),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "resource_unavailable",
                "Direct container removal requires one current Coordinator container target.",
                operation_id=request.operation_id,
            )
        full_container_id = str(row["full_container_id"]).lower()
        if re.fullmatch(r"[0-9a-f]{64}", full_container_id) is None:
            raise BrokerError(
                "resource_identity_invalid",
                "Coordinator container target has no full native Docker identity.",
                operation_id=request.operation_id,
            )
        return DirectContainerRemovalTarget(
            docker_resource_id=str(row["docker_resource_id"]),
            full_container_id=full_container_id,
        )

    def runtime_docker_target(
        self, accepted: AcceptedBrokerRequest
    ) -> RuntimeDockerMutationTarget:
        """Reauthorize and resolve a reserved runtime mutation to one container."""

        request = accepted.request
        runtime_request = (
            request.operation is BrokerOperation.RUNTIME_REQUEST
            and request.arguments["action"]
            in {"start", "stop", "restart", "replace"}
        )
        runtime_ensure = request.operation is BrokerOperation.RUNTIME_ENSURE
        if not (runtime_request or runtime_ensure) or request.arguments[
            "target_kind"
        ] not in {"docker", "database_stack"}:
            raise ValueError("request is not a Docker-backed runtime mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
                        _runtime_operation_action(request),
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

    def begin_broker_runtime_session(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        target: RuntimeDockerMutationTarget,
    ) -> str:
        """Persist exact borrowed-resource ownership before a host mutation."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"]
            not in {"start", "stop", "restart", "replace"}
            or request.arguments["target_kind"] not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a shared Docker-backed runtime mutation")
        session_id = "session-" + uuid.uuid5(
            uuid.NAMESPACE_URL,
            "devcoordinator:broker-runtime-session:" + request.operation_id,
        ).hex
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                current = _runtime_mutation_row(connection, request=request)
                current_fingerprint = _runtime_target_fingerprint(
                    current, requested_resource_id=request.resource_id
                )
                if (
                    current_fingerprint != target.immutable_fingerprint
                    or str(current["docker_resource_id"])
                    != target.docker_resource_id
                    or str(current["full_container_id"]).lower()
                    != target.full_container_id
                ):
                    raise BrokerError(
                        "stale_resource_definition",
                        "Runtime target changed before session ownership was committed.",
                        operation_id=request.operation_id,
                    )
                scope = connection.execute(
                    """
                    SELECT scope.family_id, family.root_repo_id
                    FROM repository_scopes scope
                    JOIN repository_families family USING(family_id)
                    WHERE scope.repo_id = ? AND family.root_repo_id = ?
                    """,
                    (
                        request.project_id,
                        str(request.arguments["root_repo_id"]),
                    ),
                ).fetchone()
                operation = connection.execute(
                    """
                    SELECT created_at, status FROM operations
                    WHERE operation_id = ? AND repo_id = ?
                      AND kind = 'broker.runtime.request'
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
                if scope is None or operation is None or operation["status"] != "running":
                    raise BrokerError(
                        "operation_state_conflict",
                        "Runtime session no longer has its exact reserved operation and repository scope.",
                        operation_id=request.operation_id,
                    )
                ttl_seconds = request.arguments["ttl_seconds"]
                expires_at = None
                if ttl_seconds is not None:
                    created_epoch = calendar.timegm(
                        time.strptime(
                            str(operation["created_at"]), "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    expires_at = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(created_epoch + int(ttl_seconds)),
                    )
                elif bool(request.arguments["kill_after_run"]):
                    # KillAfterRun cleanup is immediately due once the durable
                    # replacement result commits. The session remains planned
                    # until then, so the reaper cannot race the mutation.
                    expires_at = str(operation["created_at"])
                session_request = {
                    "schema_version": 1,
                    "action": str(request.arguments["action"]),
                    "agent": str(request.arguments["agent"]),
                    "purpose": str(request.arguments["purpose"]),
                    "ttl_seconds": ttl_seconds,
                    "kill_after_run": bool(request.arguments["kill_after_run"]),
                    "target": {
                        "kind": target.resource_kind,
                        "id": target.resource_id,
                    },
                    "authority": "broker",
                }
                encoded_request = json.dumps(
                    session_request,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                existing = connection.execute(
                    """
                    SELECT operation_id, repo_id, request_json
                    FROM runtime_sessions WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["operation_id"] or "") != request.operation_id
                        or str(existing["repo_id"]) != request.project_id
                        or str(existing["request_json"]) != encoded_request
                    ):
                        raise BrokerError(
                            "operation_state_conflict",
                            "Runtime session replay contradicted its durable identity.",
                            operation_id=request.operation_id,
                        )
                    return session_id
                identity = {
                    "state": "borrowed",
                    "session_id": session_id,
                    "operation_id": request.operation_id,
                    "repository_id": request.project_id,
                    "resource_kind": target.resource_kind,
                    "resource_id": target.resource_id,
                    "docker_resource_id": target.docker_resource_id,
                    "full_container_id": target.full_container_id,
                    "database_binding_id": target.database_binding_id,
                    "database_name": target.database_name,
                    "immutable_fingerprint": target.immutable_fingerprint,
                }
                execution_owner_pid = os.getpid()
                execution_owner_identity = runtime_process_identity(
                    execution_owner_pid
                )
                if execution_owner_identity is None:
                    raise BrokerError(
                        "runtime_cleanup_owner_unobservable",
                        "Broker runtime session cannot prove its execution owner identity.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    INSERT INTO runtime_sessions(
                        session_id, family_id, root_repo_id, repo_id,
                        operation_id, action, purpose, ttl_seconds, expires_at,
                        kill_after_run, status, actor, request_json,
                        execution_owner_pid, execution_owner_identity,
                        created_at, started_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        str(scope["family_id"]),
                        str(scope["root_repo_id"]),
                        request.project_id,
                        request.operation_id,
                        str(request.arguments["action"]),
                        str(request.arguments["purpose"]),
                        ttl_seconds,
                        expires_at,
                        int(bool(request.arguments["kill_after_run"])),
                        str(request.arguments["agent"]),
                        encoded_request,
                        execution_owner_pid,
                        execution_owner_identity,
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO runtime_session_resources(
                        session_id, resource_kind, resource_id,
                        immutable_fingerprint, identity_json,
                        cleanup_disposition, cleanup_state, linked_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'retained', 'active', ?, ?)
                    """,
                    (
                        session_id,
                        target.resource_kind,
                        target.resource_id,
                        target.immutable_fingerprint,
                        json.dumps(
                            identity,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        timestamp,
                        timestamp,
                    ),
                )
        return session_id

    def broker_runtime_session_id(self, operation_id: str) -> str | None:
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT session_id, ttl_seconds, kill_after_run
                    FROM runtime_sessions
                    WHERE operation_id = ? ORDER BY created_at, session_id LIMIT 1
                    """,
                    (operation_id,),
                ).fetchone()
        return None if row is None else str(row["session_id"])

    def runtime_replacement_record(
        self, accepted: AcceptedBrokerRequest
    ) -> RuntimeReplacementRecord | None:
        """Load one resumable Docker-backed replacement journal."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "replace"
            or request.arguments["target_kind"]
            not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed replacement")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT * FROM broker_runtime_replacements
                    WHERE operation_id = ? AND repo_id = ?
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
        return None if row is None else _runtime_replacement_record(row)

    def prepare_runtime_replacement(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        evidence: Mapping[str, Any],
    ) -> RuntimeReplacementRecord:
        """Bind replacement to one observed single-replica Compose service.

        This is the last preflight transaction before any backup or Compose
        host action. It proves the path-free runtime target, sealed Compose
        definition, exact service identity, and every additional authority the
        composed workflow needs.
        """

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "replace"
            or request.arguments["target_kind"]
            not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed replacement")
        snapshot_id = str(evidence.get("snapshot_id") or "")
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                existing = connection.execute(
                    """
                    SELECT * FROM broker_runtime_replacements
                    WHERE operation_id = ? AND repo_id = ?
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
                if existing is not None:
                    return _runtime_replacement_record(existing)

                target_row = _runtime_mutation_row(connection, request=request)
                target_fingerprint = _runtime_target_fingerprint(
                    target_row, requested_resource_id=request.resource_id
                )
                operation = connection.execute(
                    """
                    SELECT status, error_code FROM operations
                    WHERE operation_id = ? AND repo_id = ?
                      AND kind = 'broker.runtime.request'
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
                reserved = connection.execute(
                    """
                    SELECT status, phase, immutable_fingerprint
                    FROM operation_targets
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND target_id = ? AND action = 'runtime.replace'
                    """,
                    (request.operation_id, target_row["docker_resource_id"]),
                ).fetchone()
                if (
                    operation is None
                    or reserved is None
                    or str(reserved["immutable_fingerprint"])
                    != target_fingerprint
                ):
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement lost its exact reserved container identity.",
                        operation_id=request.operation_id,
                    )
                if str(operation["status"]) == "needs_attention":
                    # No replacement journal means the implementation contract
                    # made no external replacement call. A broker restart may
                    # therefore resume only after this transaction re-proves
                    # the original immutable target in a fresh observation.
                    if str(operation["error_code"] or "") != "operation_outcome_uncertain":
                        raise BrokerError(
                            "operation_state_conflict",
                            "Replacement cannot resume from a terminal non-retryable failure.",
                            operation_id=request.operation_id,
                        )
                    connection.execute(
                        """
                        UPDATE operations
                        SET status = 'running', phase = 'executing',
                            result_json = NULL, error_code = NULL,
                            error_message = NULL, updated_at = ?,
                            generation = generation + 1
                        WHERE operation_id = ? AND status = 'needs_attention'
                        """,
                        (timestamp, request.operation_id),
                    )
                    connection.execute(
                        """
                        UPDATE operation_targets
                        SET status = 'running', phase = 'executing',
                            result_json = NULL, error_json = NULL,
                            finished_at = NULL
                        WHERE operation_id = ? AND ordinal = 0
                          AND phase = 'reconciliation_required'
                        """,
                        (request.operation_id,),
                    )
                    connection.execute(
                        """
                        UPDATE runtime_sessions
                        SET status = 'planned', updated_at = ?
                        WHERE operation_id = ? AND status = 'cleanup_pending'
                        """,
                        (timestamp, request.operation_id),
                    )
                    connection.execute(
                        """
                        UPDATE runtime_session_resources
                        SET cleanup_state = 'active', cleanup_error_json = NULL,
                            updated_at = ?
                        WHERE session_id IN (
                            SELECT session_id FROM runtime_sessions
                            WHERE operation_id = ?
                        ) AND cleanup_disposition = 'retained'
                        """,
                        (timestamp, request.operation_id),
                    )
                elif str(operation["status"]) != "running":
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement no longer has a running durable operation.",
                        operation_id=request.operation_id,
                    )

                repository = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if repository is None:
                    raise BrokerError(
                        "repository_unavailable",
                        "Replacement repository is unavailable.",
                        operation_id=request.operation_id,
                    )
                _require_exact_full_docker_snapshot(
                    connection,
                    snapshot_id=snapshot_id,
                    host_id=str(repository["host_id"]),
                    expected_evidence=evidence,
                    operation_id=request.operation_id,
                    require_compose_asset_scope=True,
                    error_code="runtime_replace_observation_incomplete",
                    error_message=(
                        "Replacement requires one fresh complete Compose-aware Docker observation."
                    ),
                )
                rows = list(
                    connection.execute(
                        """
                        SELECT observed.full_container_id,
                               observed.project_name, observed.service_name,
                               observed.lifecycle, observed.association_state,
                               observed.associated_repo_id,
                               definition.compose_definition_id,
                               definition.enabled, claim.claimed,
                               effective.service_replicas_json
                        FROM broker_observed_compose_containers observed
                        JOIN broker_compose_definitions definition
                          ON definition.repo_id = ?
                         AND definition.project_name = observed.project_name
                        JOIN broker_compose_project_claims claim
                          USING(compose_definition_id)
                        JOIN broker_compose_services service
                          ON service.compose_definition_id =
                             definition.compose_definition_id
                         AND service.service_name = observed.service_name
                        JOIN broker_compose_effective_model_evidence effective
                          USING(compose_definition_id)
                        WHERE observed.snapshot_id = ?
                          AND observed.docker_resource_id = ?
                        ORDER BY definition.compose_definition_id,
                                 observed.service_name
                        """,
                        (
                            request.project_id,
                            snapshot_id,
                            str(target_row["docker_resource_id"]),
                        ),
                    )
                )
                if len(rows) != 1:
                    raise BrokerError(
                        "runtime_replace_compose_scope_required",
                        "Replacement target must resolve to one configured Compose service.",
                        operation_id=request.operation_id,
                    )
                compose = rows[0]
                lifecycle_services = tuple(
                    str(row["service_name"])
                    for row in connection.execute(
                        """
                        SELECT service_name FROM broker_compose_services
                        WHERE compose_definition_id = ? ORDER BY ordinal
                        """,
                        (str(compose["compose_definition_id"]),),
                    )
                )
                replicas = _require_service_replica_evidence(
                    compose["service_replicas_json"],
                    services=lifecycle_services,
                    operation_id=request.operation_id,
                )
                if (
                    str(compose["full_container_id"]).lower()
                    != str(target_row["full_container_id"]).lower()
                    or str(compose["association_state"]) != "exclusive"
                    or str(compose["associated_repo_id"] or "")
                    != request.project_id
                    or not bool(compose["enabled"])
                    or not bool(compose["claimed"])
                    or dict(replicas).get(str(compose["service_name"])) != 1
                ):
                    raise BrokerError(
                        "runtime_replace_compose_scope_required",
                        "Replacement requires one current, exclusive, single-replica Compose service.",
                        operation_id=request.operation_id,
                    )
                database_binding_id = target_row["database_binding_id"]
                database_name = target_row["database_name"]
                compose_operation_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "devcoordinator:runtime-replace:compose:"
                        + request.operation_id,
                    )
                )
                backup_operation_id = (
                    str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            "devcoordinator:runtime-replace:backup:"
                            + request.operation_id,
                        )
                    )
                    if request.arguments["target_kind"] == "database_stack"
                    else None
                )
                connection.execute(
                    """
                    INSERT INTO broker_runtime_replacements(
                        operation_id, repo_id, resource_kind,
                        requested_resource_id, old_docker_resource_id,
                        old_full_container_id, database_binding_id,
                        database_name, compose_definition_id,
                        compose_service, compose_operation_id,
                        backup_operation_id, phase, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'reserved', ?, ?)
                    """,
                    (
                        request.operation_id,
                        request.project_id,
                        request.arguments["target_kind"],
                        request.resource_id,
                        str(target_row["docker_resource_id"]),
                        str(target_row["full_container_id"]).lower(),
                        database_binding_id,
                        database_name,
                        str(compose["compose_definition_id"]),
                        str(compose["service_name"]),
                        compose_operation_id,
                        backup_operation_id,
                        timestamp,
                        timestamp,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                assert row is not None
                return _runtime_replacement_record(row)

    def record_runtime_replacement_backup(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        database_backup_id: str,
    ) -> RuntimeReplacementRecord:
        """Bind one nested strong backup to the original replacement identity."""

        request = accepted.request
        _require_identifier(database_backup_id, "database_backup_id")
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if row is None or str(row["resource_kind"]) != "database_stack":
                    raise BrokerError(
                        "operation_state_conflict",
                        "Database replacement has no matching durable journal.",
                        operation_id=request.operation_id,
                    )
                backup = connection.execute(
                    """
                    SELECT database_binding_id, docker_resource_id,
                           source_container_id, source_database_name,
                           status, verification_status, scope
                    FROM database_backups WHERE database_backup_id = ?
                    """,
                    (database_backup_id,),
                ).fetchone()
                if (
                    backup is None
                    or str(backup["database_binding_id"] or "")
                    != str(row["database_binding_id"])
                    or str(backup["docker_resource_id"] or "")
                    != str(row["old_docker_resource_id"])
                    or str(backup["source_container_id"]).lower()
                    != str(row["old_full_container_id"]).lower()
                    or str(backup["source_database_name"] or "")
                    != str(row["database_name"])
                    or str(backup["status"]) != "available"
                    or str(backup["verification_status"]) != "strong"
                    or str(backup["scope"]) != "database"
                ):
                    raise BrokerError(
                        "database_backup_unavailable",
                        "Replacement backup does not strongly verify the exact original database identity.",
                        operation_id=request.operation_id,
                    )
                existing_backup_id = row["database_backup_id"]
                if (
                    existing_backup_id is not None
                    and str(existing_backup_id) != database_backup_id
                ):
                    raise BrokerError(
                        "operation_id_conflict",
                        "Replacement already references another immutable backup.",
                        operation_id=request.operation_id,
                    )
                if str(row["phase"]) == "reserved":
                    connection.execute(
                        """
                        UPDATE broker_runtime_replacements
                        SET database_backup_id = ?, phase = 'backup_complete',
                            updated_at = ?
                        WHERE operation_id = ? AND phase = 'reserved'
                        """,
                        (database_backup_id, timestamp, request.operation_id),
                    )
                elif str(row["phase"]) not in {
                    "backup_complete",
                    "recreated",
                    "rebound",
                    "restore_intent",
                    "restore_complete",
                    "terminal",
                }:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement backup arrived in an invalid phase.",
                        operation_id=request.operation_id,
                    )
                final = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                assert final is not None
                return _runtime_replacement_record(final)

    def begin_runtime_replacement_restore(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[DatabaseMutationTarget, RegisteredDatabaseBackup, dict[str, Any] | None]:
        """Load exact cross-incarnation restore material and commit intent."""

        request = accepted.request
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                journal = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if (
                    journal is None
                    or str(journal["resource_kind"]) != "database_stack"
                    or str(journal["phase"])
                    not in {
                        "rebound",
                        "restore_intent",
                        "restore_complete",
                        "terminal",
                    }
                    or journal["new_docker_resource_id"] is None
                    or journal["database_backup_id"] is None
                ):
                    raise BrokerError(
                        "operation_state_conflict",
                        "Database replacement is not ready for its exact restore.",
                        operation_id=request.operation_id,
                    )
                target_row = connection.execute(
                    """
                    SELECT database.database_binding_id,
                           database.docker_resource_id,
                           database.database_name, docker.full_container_id,
                           metadata.observation_revision AS control_generation,
                           metadata.observation_revision
                    FROM database_bindings database
                    JOIN docker_resources docker USING(docker_resource_id)
                    CROSS JOIN schema_metadata metadata
                    WHERE database.database_binding_id = ?
                      AND database.repo_id = ?
                      AND database.docker_resource_id = ?
                      AND database.database_name = ?
                      AND database.engine_kind = 'postgresql'
                    """,
                    (
                        str(journal["database_binding_id"]),
                        request.project_id,
                        str(journal["new_docker_resource_id"]),
                        str(journal["database_name"]),
                    ),
                ).fetchone()
                backup_row = connection.execute(
                    """
                    SELECT database_backup_id, database_binding_id,
                           artifact_path, manifest_path, artifact_sha256,
                           source_container_id, source_database_name,
                           status, verification_status, scope
                    FROM database_backups WHERE database_backup_id = ?
                    """,
                    (str(journal["database_backup_id"]),),
                ).fetchone()
                if (
                    target_row is None
                    or backup_row is None
                    or str(backup_row["database_binding_id"] or "")
                    != str(journal["database_binding_id"])
                    or str(backup_row["source_container_id"]).lower()
                    != str(journal["old_full_container_id"]).lower()
                    or str(backup_row["source_database_name"] or "")
                    != str(journal["database_name"])
                    or str(backup_row["status"]) != "available"
                    or str(backup_row["verification_status"]) != "strong"
                    or str(backup_row["scope"]) != "database"
                ):
                    raise BrokerError(
                        "database_backup_unavailable",
                        "Replacement restore lost its strongly verified original backup or exact new target.",
                        operation_id=request.operation_id,
                    )
                descriptor = inspect_database_backup(
                    str(backup_row["artifact_path"]),
                    str(backup_row["manifest_path"]),
                    expected_uid=self.expected_uid,
                )
                if (
                    descriptor["verification_status"] != "strong"
                    or descriptor["artifact_sha256"]
                    != str(backup_row["artifact_sha256"])
                    or descriptor["source_container_id"]
                    != str(journal["old_full_container_id"]).lower()
                    or descriptor["source_database_name"]
                    != str(journal["database_name"])
                ):
                    raise BrokerError(
                        "database_backup_unavailable",
                        "Replacement backup evidence changed or no longer verifies strongly.",
                        operation_id=request.operation_id,
                    )
                if str(journal["phase"]) == "rebound":
                    connection.execute(
                        """
                        UPDATE broker_runtime_replacements
                        SET phase = 'restore_intent', updated_at = ?
                        WHERE operation_id = ? AND phase = 'rebound'
                        """,
                        (timestamp, request.operation_id),
                    )
                saved_result = None
                if journal["restore_result_json"] is not None:
                    decoded = json.loads(str(journal["restore_result_json"]))
                    if not isinstance(decoded, dict):
                        raise BrokerError(
                            "operation_evidence_corrupt",
                            "Replacement restore evidence has an invalid shape.",
                            operation_id=request.operation_id,
                        )
                    saved_result = decoded
                return (
                    DatabaseMutationTarget(
                        database_binding_id=str(
                            target_row["database_binding_id"]
                        ),
                        docker_resource_id=str(target_row["docker_resource_id"]),
                        full_container_id=str(
                            target_row["full_container_id"]
                        ).lower(),
                        database_name=str(target_row["database_name"]),
                        observation_revision=int(
                            target_row["observation_revision"]
                        ),
                        control_generation=int(target_row["control_generation"]),
                    ),
                    RegisteredDatabaseBackup(
                        database_backup_id=str(
                            backup_row["database_backup_id"]
                        ),
                        database_binding_id=str(
                            backup_row["database_binding_id"]
                        ),
                        artifact_path=str(descriptor["artifact_path"]),
                        manifest_path=str(descriptor["manifest_path"]),
                        artifact_sha256=str(descriptor["artifact_sha256"]),
                        manifest_sha256=str(descriptor["manifest_sha256"]),
                        artifact_size_bytes=int(descriptor["artifact_size_bytes"]),
                        status=str(backup_row["status"]),
                    ),
                    saved_result,
                )

    def save_runtime_replacement_restore_result(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Journal completed replacement restore evidence before registration."""

        request = accepted.request
        try:
            encoded = json.dumps(
                dict(result),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise BrokerError(
                "invalid_backend_result",
                "Replacement restore returned invalid JSON evidence.",
                operation_id=request.operation_id,
            ) from exc
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise BrokerError(
                "invalid_backend_result",
                "Replacement restore evidence exceeds its bounded journal.",
                operation_id=request.operation_id,
            )
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT phase, restore_result_json
                    FROM broker_runtime_replacements
                    WHERE operation_id = ? AND resource_kind = 'database_stack'
                    """,
                    (request.operation_id,),
                ).fetchone()
                if row is None or str(row["phase"]) not in {
                    "restore_intent",
                    "restore_complete",
                    "terminal",
                }:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement restore has no matching durable intent.",
                        operation_id=request.operation_id,
                    )
                if row["restore_result_json"] is not None:
                    if str(row["restore_result_json"]) != encoded:
                        raise BrokerError(
                            "operation_id_conflict",
                            "Replacement already has different restore evidence.",
                            operation_id=request.operation_id,
                        )
                    return dict(result)
                connection.execute(
                    """
                    UPDATE broker_runtime_replacements
                    SET restore_result_json = ?, updated_at = ?
                    WHERE operation_id = ? AND phase = 'restore_intent'
                    """,
                    (encoded, timestamp, request.operation_id),
                )
        return dict(result)

    def complete_runtime_replacement_restore(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Register a strongly evidenced cross-incarnation restore exactly once."""

        request = accepted.request
        safety = result.get("safety_backup")
        if not isinstance(safety, Mapping):
            raise BrokerError(
                "invalid_backend_result",
                "Replacement restore omitted its mandatory safety backup.",
                operation_id=request.operation_id,
            )
        safety_artifact = safety.get("backup")
        safety_manifest = safety.get("manifest")
        if not isinstance(safety_artifact, str) or not isinstance(
            safety_manifest, str
        ):
            raise BrokerError(
                "invalid_backend_result",
                "Replacement restore safety-backup evidence is incomplete.",
                operation_id=request.operation_id,
            )
        safety_descriptor = inspect_database_backup(
            safety_artifact,
            safety_manifest,
            expected_uid=self.expected_uid,
        )
        if (
            safety_descriptor["verification_status"] != "strong"
            or safety_descriptor["source_container_id"]
            != target.full_container_id
            or safety_descriptor["source_database_name"]
            != target.database_name
        ):
            raise BrokerError(
                "invalid_backend_result",
                "Replacement restore safety backup does not match the exact new target.",
                operation_id=request.operation_id,
            )
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                journal = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if (
                    journal is None
                    or str(journal["phase"])
                    not in {"restore_intent", "restore_complete", "terminal"}
                    or str(journal["new_docker_resource_id"] or "")
                    != target.docker_resource_id
                    or str(journal["new_full_container_id"] or "").lower()
                    != target.full_container_id
                    or str(journal["database_backup_id"] or "")
                    != backup.database_backup_id
                    or str(journal["restore_result_json"] or "")
                    != json.dumps(
                        dict(result),
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ):
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement restore evidence no longer matches its exact journal.",
                        operation_id=request.operation_id,
                    )
                if str(journal["phase"]) in {"restore_complete", "terminal"}:
                    existing = connection.execute(
                        """
                        SELECT restore_event_id,
                               safety_database_backup_id
                        FROM database_restore_events
                        WHERE restore_event_id = ?
                        """,
                        (
                            deterministic_id(
                                "database-restore-operation",
                                request.operation_id,
                            ),
                        ),
                    ).fetchone()
                    if existing is None:
                        raise BrokerError(
                            "operation_evidence_corrupt",
                            "Replacement restore journal lost its terminal event.",
                            operation_id=request.operation_id,
                        )
                    return {
                        "restore_event_id": str(existing["restore_event_id"]),
                        "database_backup_id": backup.database_backup_id,
                        "safety_database_backup_id": str(
                            existing["safety_database_backup_id"]
                        ),
                        "database_binding_id": target.database_binding_id,
                        "docker_resource_id": target.docker_resource_id,
                        "database_name": target.database_name,
                        "transactional": True,
                        "status": "restored",
                    }
                safety_id = upsert_database_backup(
                    connection, safety_descriptor
                )
                restore_event_id = record_successful_restore(
                    connection,
                    database_backup_id=backup.database_backup_id,
                    target_container_id=target.full_container_id,
                    target_database_name=target.database_name,
                    result=result,
                    safety_database_backup_id=safety_id,
                    operation_id=request.operation_id,
                )
                connection.execute(
                    """
                    UPDATE broker_runtime_replacements
                    SET phase = 'restore_complete', updated_at = ?
                    WHERE operation_id = ? AND phase = 'restore_intent'
                    """,
                    (timestamp, request.operation_id),
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

    def finish_runtime_replacement(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        result: Mapping[str, Any],
    ) -> None:
        """Commit the replacement report and terminal journal in one write."""

        request = accepted.request
        encoded = json.dumps(
            dict(result),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                journal = connection.execute(
                    "SELECT resource_kind, phase FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                expected_phase = (
                    "restore_complete"
                    if journal is not None
                    and str(journal["resource_kind"]) == "database_stack"
                    else "rebound"
                )
                if journal is None or str(journal["phase"]) not in {
                    expected_phase,
                    "terminal",
                }:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement cannot finish before identity and data preservation complete.",
                        operation_id=request.operation_id,
                    )
                if str(journal["phase"]) == "terminal":
                    return
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET status = 'succeeded', phase = 'completed',
                        result_json = ?, error_code = NULL,
                        error_message = NULL, updated_at = ?,
                        generation = generation + 1
                    WHERE operation_id = ? AND status IN (
                        'running', 'needs_attention'
                    ) AND kind = 'broker.runtime.request'
                    """,
                    (encoded, timestamp, request.operation_id),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'succeeded', phase = 'completed',
                        result_json = ?, error_json = NULL, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                    """,
                    (encoded, timestamp, request.operation_id),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement terminal journal changed before commit.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    UPDATE broker_runtime_replacements
                    SET phase = 'terminal', updated_at = ?
                    WHERE operation_id = ?
                    """,
                    (timestamp, request.operation_id),
                )
                _settle_broker_runtime_session(
                    connection,
                    operation_id=request.operation_id,
                    result=result,
                    succeeded=True,
                    timestamp=timestamp,
                )

    def rebind_runtime_replacement(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        evidence: Mapping[str, Any],
    ) -> RuntimeReplacementRecord:
        """Atomically publish the new identity and retire the absent old one."""

        request = accepted.request
        snapshot_id = str(evidence.get("snapshot_id") or "")
        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                journal = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if journal is None:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement has no durable preflight journal.",
                        operation_id=request.operation_id,
                    )
                if str(journal["phase"]) in {
                    "rebound",
                    "restore_intent",
                    "restore_complete",
                    "terminal",
                }:
                    return _runtime_replacement_record(journal)
                required_phase = (
                    "backup_complete"
                    if str(journal["resource_kind"]) == "database_stack"
                    else "reserved"
                )
                if str(journal["phase"]) not in {required_phase, "recreated"}:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement identity arrived in an invalid durable phase.",
                        operation_id=request.operation_id,
                    )
                repository = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if repository is None:
                    raise BrokerError(
                        "repository_unavailable",
                        "Replacement repository is unavailable.",
                        operation_id=request.operation_id,
                    )
                _require_exact_full_docker_snapshot(
                    connection,
                    snapshot_id=snapshot_id,
                    host_id=str(repository["host_id"]),
                    expected_evidence=evidence,
                    operation_id=request.operation_id,
                    require_compose_asset_scope=True,
                    error_code="runtime_replace_observation_incomplete",
                    error_message=(
                        "Replacement rebind requires one fresh complete Compose-aware Docker observation."
                    ),
                )
                old_present = connection.execute(
                    """
                    SELECT 1 FROM observation_snapshot_resources
                    WHERE snapshot_id = ? AND resource_kind = 'container'
                      AND resource_id = ?
                    """,
                    (snapshot_id, str(journal["old_docker_resource_id"])),
                ).fetchone()
                definition = connection.execute(
                    """
                    SELECT project_name FROM broker_compose_definitions
                    WHERE compose_definition_id = ? AND repo_id = ?
                    """,
                    (
                        str(journal["compose_definition_id"]),
                        request.project_id,
                    ),
                ).fetchone()
                if definition is None:
                    raise BrokerError(
                        "runtime_replace_compose_scope_required",
                        "Replacement Compose definition is no longer current.",
                        operation_id=request.operation_id,
                    )
                candidates = list(
                    connection.execute(
                        """
                        SELECT observed.docker_resource_id,
                               observed.full_container_id,
                               observed.lifecycle, observed.association_state,
                               observed.associated_repo_id,
                               docker.current_name, docker_observation.health,
                               metadata.observation_revision AS control_generation,
                               metadata.observation_revision
                        FROM broker_observed_compose_containers observed
                        JOIN docker_resources docker
                          USING(docker_resource_id)
                        JOIN docker_observations docker_observation
                          USING(docker_resource_id)
                        CROSS JOIN schema_metadata metadata
                        WHERE observed.snapshot_id = ?
                          AND observed.project_name = ?
                          AND observed.service_name = ?
                        ORDER BY observed.full_container_id
                        """,
                        (
                            snapshot_id,
                            str(definition["project_name"]),
                            str(journal["compose_service"]),
                        ),
                    )
                )
                if (
                    old_present is not None
                    or len(candidates) != 1
                    or str(candidates[0]["docker_resource_id"])
                    == str(journal["old_docker_resource_id"])
                    or str(candidates[0]["full_container_id"]).lower()
                    == str(journal["old_full_container_id"]).lower()
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(candidates[0]["full_container_id"]).lower(),
                    )
                    is None
                    or str(candidates[0]["lifecycle"]) != "running"
                    or str(candidates[0]["association_state"]) != "exclusive"
                    or str(
                        candidates[0]["associated_repo_id"] or ""
                    )
                    != request.project_id
                    or str(candidates[0]["health"] or "").lower()
                    in {"starting", "unhealthy"}
                ):
                    raise BrokerError(
                        "runtime_replace_identity_unproven",
                        "Fresh observation did not prove one new healthy service identity and exact old-container absence.",
                        operation_id=request.operation_id,
                    )
                current = candidates[0]
                new_resource_id = str(current["docker_resource_id"])
                new_full_id = str(current["full_container_id"]).lower()

                new_database = None
                new_database_observation = None
                if str(journal["resource_kind"]) == "database_stack":
                    new_database = connection.execute(
                        """
                        SELECT database_binding_id FROM database_bindings
                        WHERE docker_resource_id = ? AND repo_id = ?
                          AND database_name = ? AND engine_kind = 'postgresql'
                        """,
                        (
                            new_resource_id,
                            request.project_id,
                            str(journal["database_name"]),
                        ),
                    ).fetchone()
                    if new_database is not None:
                        new_database_observation = connection.execute(
                            """
                            SELECT available, size_bytes, error_code,
                                   error_message, sampled_at,
                                   observation_fingerprint
                            FROM database_observations
                            WHERE database_binding_id = ?
                              AND docker_resource_id = ?
                            """,
                            (
                                str(new_database["database_binding_id"]),
                                new_resource_id,
                            ),
                        ).fetchone()
                    if new_database is None or new_database_observation is None:
                        raise BrokerError(
                            "runtime_replace_database_unobservable",
                            "Fresh replacement observation did not publish the exact PostgreSQL database on the new container.",
                            operation_id=request.operation_id,
                        )

                if str(journal["resource_kind"]) == "database_stack":
                    assert new_database is not None
                    assert new_database_observation is not None
                    new_binding_id = str(new_database["database_binding_id"])
                    old_binding_id = str(journal["database_binding_id"])
                    connection.execute(
                        "DELETE FROM database_observations WHERE database_binding_id = ?",
                        (new_binding_id,),
                    )
                    connection.execute(
                        "DELETE FROM database_bindings WHERE database_binding_id = ?",
                        (new_binding_id,),
                    )
                    changed = connection.execute(
                        """
                        UPDATE database_bindings
                        SET docker_resource_id = ?, updated_at = ?
                        WHERE database_binding_id = ?
                          AND docker_resource_id = ? AND repo_id = ?
                        """,
                        (
                            new_resource_id,
                            timestamp,
                            old_binding_id,
                            str(journal["old_docker_resource_id"]),
                            request.project_id,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise BrokerError(
                            "runtime_replace_identity_changed",
                            "Logical database binding changed before replacement rebind.",
                            operation_id=request.operation_id,
                        )
                    connection.execute(
                        """
                        INSERT INTO database_observations(
                            database_binding_id, docker_resource_id, available,
                            size_bytes, error_code, error_message, sampled_at,
                            observation_fingerprint
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(database_binding_id) DO UPDATE SET
                            docker_resource_id = excluded.docker_resource_id,
                            available = excluded.available,
                            size_bytes = excluded.size_bytes,
                            error_code = excluded.error_code,
                            error_message = excluded.error_message,
                            sampled_at = excluded.sampled_at,
                            observation_fingerprint =
                                excluded.observation_fingerprint
                        """,
                        (
                            old_binding_id,
                            new_resource_id,
                            int(new_database_observation["available"]),
                            new_database_observation["size_bytes"],
                            new_database_observation["error_code"],
                            new_database_observation["error_message"],
                            str(new_database_observation["sampled_at"]),
                            str(
                                new_database_observation[
                                    "observation_fingerprint"
                                ]
                            ),
                        ),
                    )
                connection.execute(
                    """
                    UPDATE docker_resources
                    SET repo_id = CASE
                        WHEN docker_resource_id = ? THEN ?
                        WHEN docker_resource_id = ? AND repo_id = ? THEN NULL
                        ELSE repo_id END,
                        updated_at = ?
                    WHERE docker_resource_id IN (?, ?)
                    """,
                    (
                        new_resource_id,
                        request.project_id,
                        str(journal["old_docker_resource_id"]),
                        request.project_id,
                        timestamp,
                        new_resource_id,
                        str(journal["old_docker_resource_id"]),
                    ),
                )

                logical_resource_id = (
                    new_resource_id
                    if str(journal["resource_kind"]) == "docker"
                    else str(journal["database_binding_id"])
                )
                target_material = {
                    "resource_kind": str(journal["resource_kind"]),
                    "docker_resource_id": new_resource_id,
                    "full_container_id": new_full_id,
                    "database_binding_id": (
                        None
                        if str(journal["resource_kind"]) == "docker"
                        else str(journal["database_binding_id"])
                    ),
                    "database_name": (
                        None
                        if str(journal["resource_kind"]) == "docker"
                        else str(journal["database_name"])
                    ),
                }
                replacement_fingerprint = _runtime_target_fingerprint(
                    target_material,
                    requested_resource_id=logical_resource_id,
                )
                session = connection.execute(
                    """
                    SELECT session_id, ttl_seconds, kill_after_run
                    FROM runtime_sessions
                    WHERE operation_id = ? AND repo_id = ?
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
                if session is None:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Replacement lost its durable cleanup session.",
                        operation_id=request.operation_id,
                    )
                session_id = str(session["session_id"])
                cleanup_disposition = (
                    "removed"
                    if session["ttl_seconds"] is not None
                    or bool(session["kill_after_run"])
                    else "retained"
                )
                identity = {
                    "state": "created",
                    "disposition": "session_created",
                    "session_id": session_id,
                    "operation_id": request.operation_id,
                    "repository_id": request.project_id,
                    "resource_kind": str(journal["resource_kind"]),
                    "resource_id": logical_resource_id,
                    "docker_resource_id": new_resource_id,
                    "full_container_id": new_full_id,
                    "database_binding_id": target_material[
                        "database_binding_id"
                    ],
                    "database_name": target_material["database_name"],
                    "immutable_fingerprint": replacement_fingerprint,
                    "replaced": {
                        "docker_resource_id": str(
                            journal["old_docker_resource_id"]
                        ),
                        "full_container_id": str(
                            journal["old_full_container_id"]
                        ).lower(),
                    },
                }
                connection.execute(
                    """
                    DELETE FROM runtime_session_resources
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )
                connection.execute(
                    """
                    INSERT INTO runtime_session_resources(
                        session_id, resource_kind, resource_id,
                        immutable_fingerprint, identity_json,
                        cleanup_disposition, cleanup_state, linked_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (
                        session_id,
                        str(journal["resource_kind"]),
                        logical_resource_id,
                        replacement_fingerprint,
                        json.dumps(
                            identity,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        cleanup_disposition,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE broker_runtime_replacements
                    SET new_docker_resource_id = ?,
                        new_full_container_id = ?, phase = 'rebound',
                        updated_at = ?
                    WHERE operation_id = ?
                    """,
                    (
                        new_resource_id,
                        new_full_id,
                        timestamp,
                        request.operation_id,
                    ),
                )
                final = connection.execute(
                    "SELECT * FROM broker_runtime_replacements WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
                assert final is not None
                return _runtime_replacement_record(final)

    def runtime_session_cleanup_target(
        self, resource: Mapping[str, Any]
    ) -> RuntimeSessionCleanupTarget:
        """Resolve one claimed session resource back to its sealed native ID."""

        try:
            identity = json.loads(str(resource["identity_json"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BrokerError(
                "runtime_cleanup_identity_invalid",
                "Runtime cleanup resource has no valid sealed identity.",
            ) from exc
        if not isinstance(identity, Mapping):
            raise BrokerError(
                "runtime_cleanup_identity_invalid",
                "Runtime cleanup resource has no valid sealed identity.",
            )
        session_id = str(identity.get("session_id") or "")
        repo_id = str(identity.get("repository_id") or "")
        operation_id = str(identity.get("operation_id") or "")
        resource_kind = str(resource.get("resource_kind") or "")
        resource_id = str(resource.get("resource_id") or "")
        if (
            not session_id
            or not repo_id
            or not operation_id
            or resource_kind not in {"docker", "database_stack"}
            or identity.get("resource_kind") != resource_kind
            or identity.get("resource_id") != resource_id
            or identity.get("immutable_fingerprint")
            != resource.get("immutable_fingerprint")
        ):
            raise BrokerError(
                "runtime_cleanup_identity_invalid",
                "Runtime cleanup resource contradicted its sealed identity.",
                operation_id=operation_id or None,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                session = connection.execute(
                    """
                    SELECT status FROM runtime_sessions
                    WHERE session_id = ? AND operation_id = ? AND repo_id = ?
                    """,
                    (session_id, operation_id, repo_id),
                ).fetchone()
                link = connection.execute(
                    """
                    SELECT cleanup_disposition, cleanup_state,
                           immutable_fingerprint, identity_json
                    FROM runtime_session_resources
                    WHERE session_id = ? AND resource_kind = ? AND resource_id = ?
                    """,
                    (session_id, resource_kind, resource_id),
                ).fetchone()
                row = _runtime_cleanup_mutation_row(
                    connection,
                    repo_id=repo_id,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    operation_id=operation_id,
                )
                fingerprint_value = _runtime_target_fingerprint(
                    row, requested_resource_id=resource_id
                )
                if (
                    session is None
                    or session["status"] != "cleaning"
                    or link is None
                    or link["cleanup_disposition"]
                    not in {"retained", "removed"}
                    or link["cleanup_state"] != "cleaning"
                    or str(link["immutable_fingerprint"]) != fingerprint_value
                    or str(link["identity_json"]) != str(resource["identity_json"])
                    or fingerprint_value != str(resource["immutable_fingerprint"])
                ):
                    raise BrokerError(
                        "runtime_cleanup_identity_changed",
                        "Runtime cleanup target changed after its exact claim.",
                        operation_id=operation_id,
                    )
                target = RuntimeDockerMutationTarget(
                    resource_kind=str(row["resource_kind"]),
                    resource_id=resource_id,
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
                    immutable_fingerprint=fingerprint_value,
                )
        return RuntimeSessionCleanupTarget(
            session_id=session_id,
            operation_id=operation_id,
            repo_id=repo_id,
            cleanup_disposition=str(link["cleanup_disposition"]),
            target=target,
        )

    def verify_runtime_session_stopped(
        self, cleanup: RuntimeSessionCleanupTarget
    ) -> dict[str, Any]:
        """Prove the same immutable container is now observably stopped."""

        with self._store() as store:
            with store.read_transaction() as connection:
                row = _runtime_cleanup_mutation_row(
                    connection,
                    repo_id=cleanup.repo_id,
                    resource_kind=cleanup.target.resource_kind,
                    resource_id=cleanup.target.resource_id,
                    operation_id=cleanup.operation_id,
                )
                current_fingerprint = _runtime_target_fingerprint(
                    row, requested_resource_id=cleanup.target.resource_id
                )
                observation = connection.execute(
                    """
                    SELECT lifecycle, sampled_at FROM docker_observations
                    WHERE docker_resource_id = ?
                    """,
                    (cleanup.target.docker_resource_id,),
                ).fetchone()
        if (
            current_fingerprint != cleanup.target.immutable_fingerprint
            or str(row["full_container_id"]).lower()
            != cleanup.target.full_container_id
            or observation is None
            or str(observation["lifecycle"]).lower() != "stopped"
        ):
            raise BrokerError(
                "runtime_cleanup_not_terminal",
                "Runtime expiry cleanup did not prove the exact container stopped.",
                operation_id=cleanup.operation_id,
            )
        return {
            "resource_kind": cleanup.target.resource_kind,
            "resource_id": cleanup.target.resource_id,
            "docker_resource_id": cleanup.target.docker_resource_id,
            "full_container_id": cleanup.target.full_container_id,
            "lifecycle": "stopped",
            "sampled_at": str(observation["sampled_at"]),
        }

    def verify_runtime_session_removed(
        self,
        cleanup: RuntimeSessionCleanupTarget,
        *,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prove created identity absent before active-catalog retirement."""

        snapshot_id = str(evidence.get("snapshot_id") or "")
        with self._store() as store:
            with store.read_transaction() as connection:
                repository = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (cleanup.repo_id,),
                ).fetchone()
                if repository is None:
                    raise BrokerError(
                        "runtime_cleanup_identity_changed",
                        "Runtime cleanup repository disappeared.",
                        operation_id=cleanup.operation_id,
                    )
                _require_exact_full_docker_snapshot(
                    connection,
                    snapshot_id=snapshot_id,
                    host_id=str(repository["host_id"]),
                    expected_evidence=evidence,
                    operation_id=cleanup.operation_id,
                    require_compose_asset_scope=False,
                    error_code="runtime_cleanup_observation_incomplete",
                    error_message=(
                        "Created-resource cleanup requires one fresh complete Docker observation."
                    ),
                )
                present = connection.execute(
                    """
                    SELECT 1 FROM observation_snapshot_resources
                    WHERE snapshot_id = ? AND resource_kind = 'container'
                      AND resource_id = ?
                    """,
                    (snapshot_id, cleanup.target.docker_resource_id),
                ).fetchone()
        if present is not None:
            raise BrokerError(
                "runtime_cleanup_not_terminal",
                "Created replacement container remains present after removal.",
                operation_id=cleanup.operation_id,
            )
        return {
            "resource_kind": cleanup.target.resource_kind,
            "resource_id": cleanup.target.resource_id,
            "docker_resource_id": cleanup.target.docker_resource_id,
            "full_container_id": cleanup.target.full_container_id,
            "lifecycle": "absent",
            "snapshot_id": snapshot_id,
        }

    def runtime_docker_read_target(
        self, accepted: AcceptedBrokerRequest
    ) -> RuntimeDockerMutationTarget:
        """Reauthorize one read-only runtime request to an exact container."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "capture_logs"
            or request.arguments["target_kind"] not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed runtime log read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = _runtime_mutation_row(connection, request=request)
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
                    immutable_fingerprint=_runtime_target_fingerprint(
                        row, requested_resource_id=request.resource_id
                    ),
                )

    def database_target(
        self, accepted: AcceptedBrokerRequest
    ) -> DatabaseMutationTarget:
        request = accepted.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                row = connection.execute(
                    """
                    SELECT db.database_binding_id, db.docker_resource_id,
                           db.database_name, d.full_container_id,
                           m.observation_revision AS control_generation,
                           m.observation_revision
                    FROM database_bindings db
                    JOIN docker_resources d USING(docker_resource_id)
                    CROSS JOIN schema_metadata m
                    WHERE db.repo_id = ? AND db.database_binding_id = ?
                      AND db.database_name = ? AND db.engine_kind = 'postgresql'
                    """,
                    (
                        request.project_id,
                        request.resource_id,
                        request.arguments["database_name"],
                    ),
                ).fetchone()
                if row is None:
                    raise BrokerError(
                        "resource_unavailable",
                        "PostgreSQL database no longer resolves to the requested current container.",
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
                            "Restore backup no longer matches the exact configured container identity.",
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

    def mark_database_host_execution(
        self, accepted: AcceptedBrokerRequest
    ) -> str:
        """Publish that the exact protected database helper has started."""

        request = accepted.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        phase = (
            "host_backup"
            if request.operation is BrokerOperation.DATABASE_BACKUP
            else "host_restore"
        )
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET phase = ?, updated_at = ?, generation = generation + 1
                    WHERE operation_id = ? AND status = 'running'
                      AND phase = 'reserved'
                    """,
                    (phase, now, request.operation_id),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET phase = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'database' AND status = 'running'
                      AND phase = 'reserved'
                    """,
                    (phase, request.operation_id),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Database operation lost its reserved host-execution fence.",
                        operation_id=request.operation_id,
                    )
        return phase

    def save_database_host_result(
        self,
        accepted: AcceptedBrokerRequest,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Journal completed host evidence before normalized registry commit."""

        request = accepted.request
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
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any] | None:
        """Load replayable host evidence for one authenticated pending operation."""

        request = accepted.request
        if request.operation not in _DATABASE_OPERATIONS:
            raise ValueError("request is not a database operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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

    def database_backup_was_interrupted(
        self, accepted: AcceptedBrokerRequest
    ) -> bool:
        """Recognize a reservation whose owning broker no longer exists."""

        request = accepted.request
        if request.operation is not BrokerOperation.DATABASE_BACKUP:
            raise ValueError("request is not a database backup")
        request_fingerprint = accepted_request_fingerprint(accepted)
        current_owner = runtime_process_identity(os.getpid()) or f"pid:{os.getpid()}"
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                disposition = self._existing_operation_disposition(
                    connection,
                    accepted=accepted,
                    fingerprint=request_fingerprint,
                )
                if disposition is None or disposition.state != "pending":
                    return False
                row = connection.execute(
                    """
                    SELECT o.kind, o.process_fingerprint,
                           h.operation_id AS host_result_operation_id
                    FROM operations o
                    LEFT JOIN broker_database_host_results h USING(operation_id)
                    WHERE o.operation_id = ? AND o.status = 'running'
                    """,
                    (request.operation_id,),
                ).fetchone()
        return bool(
            row is not None
            and str(row["kind"]) == "broker.database.backup"
            and row["host_result_operation_id"] is None
            and str(row["process_fingerprint"] or "") != current_owner
        )

    def docker_observation_result(
        self,
        accepted: AcceptedBrokerRequest,
        target: DockerMutationTarget,
    ) -> dict[str, Any]:
        request = accepted.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                row = connection.execute(
                    """
                    SELECT d.docker_resource_id, d.full_container_id,
                           d.current_name, o.lifecycle, o.health,
                           o.restart_policy, o.sampled_at,
                           o.observation_fingerprint,
                           m.observation_revision
                    FROM docker_resources d
                    JOIN docker_observations o USING(docker_resource_id)
                    CROSS JOIN schema_metadata m
                    WHERE d.docker_resource_id = ?
                      AND lower(d.full_container_id) = lower(?)
                    """,
                    (
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
        accepted: AcceptedBrokerRequest,
        *,
        snapshot_id: str,
    ) -> list[dict[str, Any]]:
        """Project containers present in one exact completed Docker snapshot."""

        request = accepted.request
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
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
                        FROM docker_resources d
                        JOIN docker_engines e USING(engine_id)
                        JOIN docker_observations o USING(docker_resource_id)
                        JOIN observation_snapshot_resources present
                          ON present.snapshot_id = ?
                         AND present.resource_kind = 'container'
                         AND present.resource_id = d.docker_resource_id
                        WHERE d.repo_id = ?
                          AND e.host_id = ?
                        ORDER BY d.current_name, d.full_container_id
                        """,
                        (snapshot_id, request.project_id, snapshot["host_id"]),
                    )
                ]

    def compose_service_observation(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        snapshot_id: str,
        service: str,
    ) -> dict[str, Any]:
        """Return one snapshot-bound exact Compose service container identity."""

        request = accepted.request
        if request.operation is not BrokerOperation.COMPOSE_UP:
            raise ValueError("request is not a Compose up operation")
        service = _require_compose_service_name(service)
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                definition = connection.execute(
                    """
                    SELECT project_name FROM broker_compose_definitions
                    WHERE compose_definition_id = ? AND repo_id = ?
                      AND enabled = 1
                      AND EXISTS (
                        SELECT 1 FROM broker_compose_services scoped
                        WHERE scoped.compose_definition_id =
                              broker_compose_definitions.compose_definition_id
                          AND scoped.service_name = ?
                      )
                    """,
                    (request.resource_id, request.project_id, service),
                ).fetchone()
                if definition is None:
                    raise BrokerError(
                        "compose_service_scope_required",
                        "Exact Compose observation requires one configured lifecycle service.",
                        operation_id=request.operation_id,
                    )
                rows = list(
                    connection.execute(
                        """
                        SELECT observed.docker_resource_id,
                               observed.full_container_id,
                               resource.current_name,
                               observed.snapshot_id,
                               observed.lifecycle,
                               observation.health,
                               observation.sampled_at,
                               observed.observation_fingerprint
                        FROM broker_observed_compose_containers observed
                        LEFT JOIN docker_resources resource
                          USING(docker_resource_id)
                        LEFT JOIN docker_observations observation
                          USING(docker_resource_id)
                        WHERE observed.snapshot_id = ?
                          AND observed.service_name = ?
                          AND observed.project_name = ?
                          AND observed.association_state = 'exclusive'
                          AND observed.associated_repo_id = ?
                        ORDER BY observed.full_container_id
                        """,
                        (
                            snapshot_id,
                            service,
                            str(definition["project_name"]),
                            request.project_id,
                        ),
                    )
                )
                if len(rows) != 1:
                    raise BrokerError(
                        "compose_service_identity_unobservable",
                        "Fresh observation did not prove one exact Compose service container.",
                        operation_id=request.operation_id,
                    )
                return {"service": service, **dict(rows[0])}

    def registered_database_backup(
        self,
        accepted: AcceptedBrokerRequest,
        target: DatabaseMutationTarget,
    ) -> RegisteredDatabaseBackup:
        request = accepted.request
        if request.operation != BrokerOperation.DATABASE_RESTORE:
            raise ValueError("request is not a database restore")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                row = connection.execute(
                    """
                    SELECT database_backup_id, database_binding_id,
                           artifact_path, manifest_path, artifact_sha256,
                           manifest_sha256, source_container_id, source_database_name,
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
                    manifest_sha256=str(descriptor["manifest_sha256"]),
                    artifact_size_bytes=int(descriptor["artifact_size_bytes"]),
                    status=str(row["status"]),
                )

    def database_backup_for_retirement(
        self,
        accepted: AcceptedBrokerRequest,
        target: DatabaseMutationTarget,
    ) -> RegisteredDatabaseBackup:
        """Resolve one exact registered backup without accepting caller paths."""

        request = accepted.request
        if request.operation is not BrokerOperation.DATABASE_BACKUP_RETIRE:
            raise ValueError("request is not a database backup retirement")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT database_backup_id, database_binding_id,
                           artifact_path, manifest_path, artifact_sha256, manifest_sha256,
                           artifact_size_bytes, source_container_id,
                           source_database_name, status
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
            or row["status"] not in {"available", "missing", "retired"}
        ):
            raise BrokerError(
                "database_backup_unavailable",
                "The exact registered backup does not belong to the selected database.",
                operation_id=request.operation_id,
            )
        return RegisteredDatabaseBackup(
            database_backup_id=str(row["database_backup_id"]),
            database_binding_id=str(row["database_binding_id"]),
            artifact_path=str(row["artifact_path"]),
            manifest_path=str(row["manifest_path"]),
            artifact_sha256=str(row["artifact_sha256"]),
            manifest_sha256=str(row["manifest_sha256"]),
            artifact_size_bytes=int(row["artifact_size_bytes"]),
            status=str(row["status"]),
        )

    def retire_database_backup_result(
        self,
        accepted: AcceptedBrokerRequest,
        backup: RegisteredDatabaseBackup,
    ) -> dict[str, Any]:
        request = accepted.request
        if request.operation is not BrokerOperation.DATABASE_BACKUP_RETIRE:
            raise ValueError("request is not a database backup retirement")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    "SELECT status FROM database_backups WHERE database_backup_id = ?",
                    (backup.database_backup_id,),
                ).fetchone()
                if row is None or row["status"] not in {
                    "available",
                    "missing",
                    "retired",
                }:
                    raise BrokerError(
                        "database_backup_unavailable",
                        "The exact registered backup is unavailable for retirement.",
                        operation_id=request.operation_id,
                    )
                connection.execute(
                    """
                    UPDATE database_backups SET status = 'retired', updated_at = ?
                    WHERE database_backup_id = ?
                    """,
                    (now, backup.database_backup_id),
                )
        return {
            "ok": True,
            "status": "retired",
            "database_backup_id": backup.database_backup_id,
            "database_binding_id": backup.database_binding_id,
        }

    def register_database_backup_result(
        self,
        accepted: AcceptedBrokerRequest,
        target: DatabaseMutationTarget,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        artifact = result.get("backup")
        manifest = result.get("manifest")
        if not isinstance(artifact, str) or not isinstance(manifest, str):
            raise BrokerError(
                "invalid_backend_result",
                "PostgreSQL backup host action omitted its service-owned artifact evidence.",
                operation_id=accepted.request.operation_id,
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
                operation_id=accepted.request.operation_id,
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=accepted.request,
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
                        operation_id=accepted.request.operation_id,
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
        accepted: AcceptedBrokerRequest,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        safety = result.get("safety_backup")
        if not isinstance(safety, Mapping):
            raise BrokerError(
                "invalid_backend_result",
                "Transactional PostgreSQL restore omitted its mandatory safety backup.",
                operation_id=accepted.request.operation_id,
            )
        safety_artifact = safety.get("backup")
        safety_manifest = safety.get("manifest")
        if not isinstance(safety_artifact, str) or not isinstance(safety_manifest, str):
            raise BrokerError(
                "invalid_backend_result",
                "Transactional PostgreSQL restore safety backup evidence is incomplete.",
                operation_id=accepted.request.operation_id,
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
                operation_id=accepted.request.operation_id,
            )
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=accepted.request,
                )
                safety_id = upsert_database_backup(connection, safety_descriptor)
                restore_event_id = record_successful_restore(
                    connection,
                    database_backup_id=backup.database_backup_id,
                    target_container_id=target.full_container_id,
                    target_database_name=target.database_name,
                    result=result,
                    safety_database_backup_id=safety_id,
                    operation_id=accepted.request.operation_id,
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
        self, accepted: AcceptedBrokerRequest
    ) -> ComposeMutationTarget:
        request = accepted.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                           effective.model_services_json,
                           effective.service_replicas_json,
                           effective.model_service_replicas_json,
                           effective.service_images_json,
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
                        "resource_identity_unavailable",
                        "Compose definition no longer belongs to the exact repository.",
                        operation_id=request.operation_id,
                    )
                if (
                    request.operation
                    in (_COMPOSE_START_OPERATIONS | _COMPOSE_RUN_ONCE_OPERATIONS)
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
                        "Compose project-name binding was released; reconfigure before any lifecycle mutation.",
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
                        "Compose definition lacks an exact merged-model configuration proof.",
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
                run_once_policies = _compose_run_once_policies_connection(
                    connection,
                    compose_definition_id=request.resource_id,
                    operation_id=request.operation_id,
                )
                model_services = _require_string_list_evidence(
                    row["model_services_json"],
                    field="model services",
                    operation_id=request.operation_id,
                )
                if tuple(sorted((*services, *(p.name for p in run_once_policies)))) != (
                    model_services
                ):
                    raise BrokerError(
                        "compose_effective_model_required",
                        "Persisted Compose model service scope is invalid.",
                        operation_id=request.operation_id,
                    )
                service_replicas = _require_service_replica_evidence(
                    row["service_replicas_json"],
                    services=services,
                    operation_id=request.operation_id,
                )
                model_service_replicas = _require_service_replica_evidence(
                    row["model_service_replicas_json"],
                    services=model_services,
                    operation_id=request.operation_id,
                )
                model_service_images = _require_service_image_evidence(
                    row["service_images_json"],
                    services=model_services,
                    operation_id=request.operation_id,
                    allow_empty=not run_once_policies,
                )
                if any(
                    policy.name not in dict(model_service_images)
                    for policy in run_once_policies
                ):
                    raise BrokerError(
                        "compose_run_once_image_unbound",
                        "Every Compose run-once service requires one sealed image reference.",
                        operation_id=request.operation_id,
                    )
                recreate_service: str | None = None
                wait_timeout_seconds: int | None = None
                if request.arguments.get("force_recreate") is True:
                    recreate_service = str(request.arguments["service"])
                    if recreate_service not in services:
                        raise BrokerError(
                            "compose_service_scope_required",
                            "Exact Compose recreation requires one configured lifecycle service.",
                            operation_id=request.operation_id,
                        )
                    if dict(service_replicas).get(recreate_service) != 1:
                        raise BrokerError(
                            "compose_service_replica_ambiguous",
                            "Exact Compose recreation requires a single-replica service.",
                            operation_id=request.operation_id,
                        )
                    wait_timeout_seconds = int(
                        request.arguments["wait_timeout_seconds"]
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
                    run_once_services=run_once_policies,
                    project_name=str(row["project_name"]),
                )
                if expected_fingerprint != row["definition_fingerprint"]:
                    raise BrokerError(
                        "compose_definition_invalid",
                        "Compose definition fingerprint does not match persisted fields.",
                        operation_id=request.operation_id,
                    )
                try:
                    repository_root = Path(str(row["canonical_root"]))
                    repository_info = repository_root.lstat()
                    if (
                        stat.S_ISLNK(repository_info.st_mode)
                        or not stat.S_ISDIR(repository_info.st_mode)
                        or repository_root.resolve(strict=True) != repository_root
                        or repository_info.st_uid <= 0
                    ):
                        raise OSError("repository ownership is unsafe")
                except OSError as error:
                    raise BrokerError(
                        "project_isolation_identity_unavailable",
                        "Repository ownership cannot be attributed to a non-root project account.",
                        operation_id=request.operation_id,
                    ) from error
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
                    model_services=model_services,
                    model_service_replicas=model_service_replicas,
                    model_service_images=model_service_images,
                    run_once_policies=run_once_policies,
                    project_name=str(row["project_name"]),
                    effective_model_sha256=str(row["model_sha256"]),
                    effective_host_access_risks=effective_risks,
                    effective_host_access_approved=bool(row["host_access_approved"]),
                    definition_fingerprint=str(row["definition_fingerprint"]),
                    definition_generation=int(row["definition_generation"]),
                    repository_generation=int(row["repository_generation"]),
                    owner_uid=int(repository_info.st_uid),
                    recreate_service=recreate_service,
                    wait_timeout_seconds=wait_timeout_seconds,
                )

    def compose_run_once_target(
        self,
        accepted: AcceptedBrokerRequest,
    ) -> ComposeRunOnceMutationTarget:
        """Load one exact resumable one-shot phase without exposing raw output."""

        request = accepted.request
        if request.operation is not BrokerOperation.COMPOSE_RUN_ONCE:
            raise ValueError("request is not a Compose run-once operation")
        compose = self.compose_target(accepted)
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=request,
                )
                row = _compose_run_once_attempt_connection(
                    connection,
                    request=request,
                )
                try:
                    contract = ComposeRunOnceReceiptContract.from_document(
                        json.loads(str(row["receipt_contract_json"]))
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise BrokerError(
                        "compose_run_once_state_invalid",
                        "Compose run-once receipt snapshot is invalid.",
                        operation_id=request.operation_id,
                    ) from exc
                policy = next(
                    (
                        item
                        for item in compose.run_once_policies
                        if item.name == str(row["service_name"])
                    ),
                    None,
                )
                if (
                    policy is None
                    or policy.fingerprint != str(row["policy_fingerprint"])
                    or policy.receipt != contract
                    or str(row["definition_fingerprint"])
                    != compose.definition_fingerprint
                    or int(row["definition_generation"])
                    != compose.definition_generation
                    or int(row["repository_generation"])
                    != compose.repository_generation
                    or dict(compose.model_service_images).get(policy.name)
                    != str(row["service_image_ref"])
                ):
                    raise BrokerError(
                        "compose_run_once_snapshot_stale",
                        "Compose run-once authority changed after reservation.",
                        operation_id=request.operation_id,
                    )
                receipt: Mapping[str, Any] | None = None
                receipt_status = (
                    None
                    if row["receipt_status"] is None
                    else str(row["receipt_status"])
                )
                receipt_error_code = (
                    None
                    if row["receipt_error_code"] is None
                    else str(row["receipt_error_code"])
                )
                receipt_sha256 = (
                    None
                    if row["receipt_sha256"] is None
                    else str(row["receipt_sha256"])
                )
                if receipt_status is not None:
                    if receipt_status == "valid":
                        if row["receipt_json"] is None:
                            raise BrokerError(
                                "compose_run_once_state_invalid",
                                "Valid Compose run-once receipt is missing.",
                                operation_id=request.operation_id,
                            )
                        encoded_receipt = str(row["receipt_json"]).encode("utf-8")
                        published = validate_published_receipt(
                            encoded_receipt,
                            contract=contract,
                        )
                        if (
                            published.status != "valid"
                            or published.receipt_sha256 != receipt_sha256
                            or receipt_error_code is not None
                        ):
                            raise BrokerError(
                                "compose_run_once_state_invalid",
                                "Compose run-once receipt evidence is inconsistent.",
                                operation_id=request.operation_id,
                            )
                        receipt = published.receipt
                    else:
                        try:
                            PublishedReceipt(
                                receipt_status,
                                None,
                                None,
                                receipt_error_code,
                            )
                        except (TypeError, ValueError) as exc:
                            raise BrokerError(
                                "compose_run_once_state_invalid",
                                "Compose run-once receipt status is invalid.",
                                operation_id=request.operation_id,
                            ) from exc
                        if (
                            row["receipt_json"] is not None
                            or receipt_sha256 is not None
                        ):
                            raise BrokerError(
                                "compose_run_once_state_invalid",
                                "Rejected Compose run-once receipt leaked payload data.",
                                operation_id=request.operation_id,
                            )
                return ComposeRunOnceMutationTarget(
                    compose=compose,
                    operation_id=request.operation_id,
                    agent=str(row["agent"]),
                    service_name=str(row["service_name"]),
                    timeout_seconds=int(row["timeout_seconds"]),
                    deadline_epoch=int(row["deadline_epoch"]),
                    container_name=str(row["container_name"]),
                    phase=str(row["phase"]),
                    policy_fingerprint=str(row["policy_fingerprint"]),
                    receipt_contract=contract,
                    service_image_ref=str(row["service_image_ref"]),
                    expected_image_id=(
                        None
                        if row["expected_image_id"] is None
                        else str(row["expected_image_id"])
                    ),
                    full_container_id=(
                        None
                        if row["full_container_id"] is None
                        else str(row["full_container_id"])
                    ),
                    terminal_exit_code=(
                        None
                        if row["terminal_exit_code"] is None
                        else int(row["terminal_exit_code"])
                    ),
                    timed_out=bool(row["timed_out"]),
                    terminal_error_code=(
                        None
                        if row["terminal_error_code"] is None
                        else str(row["terminal_error_code"])
                    ),
                    receipt_status=receipt_status,
                    receipt_error_code=receipt_error_code,
                    receipt=receipt,
                    receipt_sha256=receipt_sha256,
                    cleanup_status=(
                        None
                        if row["cleanup_status"] is None
                        else str(row["cleanup_status"])
                    ),
                )

    def mark_compose_run_once_image_bind_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("reserved",),
            next_phase="image_bind_intent",
        )

    def bind_compose_run_once_image(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        image_id: str,
    ) -> None:
        if not isinstance(image_id, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_id
        ) is None:
            raise ValueError("Compose run-once image ID is invalid")
        self._advance_compose_run_once(
            accepted,
            expected_phases=("image_bind_intent",),
            next_phase="image_bound",
            updates={"expected_image_id": image_id},
        )

    def mark_compose_run_once_create_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("image_bound",),
            next_phase="create_intent",
        )

    def bind_compose_run_once_container(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        full_container_id: str,
        image_id: str,
    ) -> None:
        normalized_id = str(full_container_id).lower()
        if re.fullmatch(r"[0-9a-f]{64}", normalized_id) is None:
            raise ValueError("Compose run-once container ID is invalid")
        if not isinstance(image_id, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_id
        ) is None:
            raise ValueError("Compose run-once observed image ID is invalid")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = _compose_run_once_attempt_connection(
                    connection,
                    request=accepted.request,
                )
                if str(row["expected_image_id"] or "") != image_id:
                    raise BrokerError(
                        "compose_run_once_image_mismatch",
                        "Created one-shot container does not use the bound image.",
                        operation_id=accepted.request.operation_id,
                    )
        self._advance_compose_run_once(
            accepted,
            expected_phases=("create_intent",),
            next_phase="container_bound",
            updates={"full_container_id": normalized_id},
        )

    def mark_compose_run_once_start_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("container_bound",),
            next_phase="start_intent",
        )

    def mark_compose_run_once_started(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("start_intent",),
            next_phase="started",
        )

    def mark_compose_run_once_wait_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("started",),
            next_phase="wait_intent",
        )

    def mark_compose_run_once_stop_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("wait_intent",),
            next_phase="stop_intent",
        )

    def record_compose_run_once_terminal(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        exit_code: int | None,
        timed_out: bool,
        error_code: str | None = None,
    ) -> None:
        if (
            exit_code is not None
            and (
                type(exit_code) is not int
                or not -(2**31) <= exit_code < 2**31
            )
        ):
            raise ValueError("Compose run-once exit code is invalid")
        if type(timed_out) is not bool:
            raise TypeError("Compose run-once timed_out must be a boolean")
        if error_code is not None and (
            not isinstance(error_code, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", error_code) is None
        ):
            raise ValueError("Compose run-once terminal error code is invalid")
        self._advance_compose_run_once(
            accepted,
            expected_phases=(
                "create_intent",
                "start_intent",
                "started",
                "wait_intent",
                "stop_intent",
            ),
            next_phase="terminal",
            updates={
                "terminal_exit_code": exit_code,
                "timed_out": int(timed_out),
                "terminal_error_code": error_code,
            },
        )

    def mark_compose_run_once_evidence_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("terminal",),
            next_phase="evidence_intent",
        )

    def record_compose_run_once_evidence(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        published_receipt: PublishedReceipt,
        stdout_sha256: str,
        stdout_byte_size: int,
        stderr_sha256: str,
        stderr_byte_size: int,
    ) -> None:
        if not isinstance(published_receipt, PublishedReceipt):
            raise TypeError("Compose run-once published receipt is invalid")
        for label, digest in (
            ("stdout", stdout_sha256),
            ("stderr", stderr_sha256),
        ):
            if not isinstance(digest, str) or re.fullmatch(
                r"sha256:[0-9a-f]{64}", digest
            ) is None:
                raise ValueError(f"Compose run-once {label} digest is invalid")
        if (
            type(stdout_byte_size) is not int
            or stdout_byte_size < 0
            or type(stderr_byte_size) is not int
            or stderr_byte_size < 0
        ):
            raise ValueError("Compose run-once stream size is invalid")
        receipt_json = (
            None
            if published_receipt.receipt is None
            else json.dumps(
                dict(published_receipt.receipt),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        self._advance_compose_run_once(
            accepted,
            expected_phases=("evidence_intent",),
            next_phase="evidence_captured",
            updates={
                "receipt_status": published_receipt.status,
                "receipt_error_code": published_receipt.error_code,
                "receipt_json": receipt_json,
                "receipt_sha256": published_receipt.receipt_sha256,
                "stdout_sha256": stdout_sha256,
                "stdout_byte_size": stdout_byte_size,
                "stderr_sha256": stderr_sha256,
                "stderr_byte_size": stderr_byte_size,
            },
        )

    def mark_compose_run_once_cleanup_intent(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            accepted,
            expected_phases=("evidence_captured",),
            next_phase="cleanup_intent",
        )

    def mark_compose_run_once_cleaned(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        cleanup_status: str,
    ) -> None:
        if cleanup_status not in {"removed", "not_created"}:
            raise ValueError("Compose run-once cleanup status is invalid")
        self._advance_compose_run_once(
            accepted,
            expected_phases=("cleanup_intent",),
            next_phase="cleaned",
            updates={"cleanup_status": cleanup_status},
        )

    def compose_run_once_public_result(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        target = self.compose_run_once_target(accepted)
        if target.phase != "cleaned":
            raise BrokerError(
                "compose_run_once_incomplete",
                "Compose run-once operation has not completed cleanup.",
                operation_id=target.operation_id,
            )
        if target.timed_out:
            status = "timed_out"
        elif target.terminal_error_code is not None:
            status = "failed"
        elif target.receipt_status != "valid":
            status = "receipt_invalid"
        elif target.terminal_exit_code == 0:
            status = "succeeded"
        else:
            status = "failed"
        return {
            "operation_id": target.operation_id,
            "compose_definition_id": target.compose.compose_definition_id,
            "agent": target.agent,
            "service": target.service_name,
            "status": status,
            "exit_code": target.terminal_exit_code,
            "timed_out": target.timed_out,
            "error_code": (
                target.terminal_error_code or target.receipt_error_code
            ),
            "receipt_status": target.receipt_status,
            "receipt": (
                None if target.receipt is None else dict(target.receipt)
            ),
            "receipt_sha256": target.receipt_sha256,
            "image_ref": target.service_image_ref,
            "image_id": target.expected_image_id,
            "container_id": target.full_container_id,
            "definition_fingerprint": target.compose.definition_fingerprint,
            "definition_generation": target.compose.definition_generation,
            "repository_generation": target.compose.repository_generation,
            "cleanup_status": target.cleanup_status,
            "output_suppressed": True,
        }

    def _advance_compose_run_once(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        expected_phases: tuple[str, ...],
        next_phase: str,
        updates: Mapping[str, Any] | None = None,
    ) -> None:
        request = accepted.request
        if request.operation is not BrokerOperation.COMPOSE_RUN_ONCE:
            raise ValueError("request is not a Compose run-once operation")
        if not expected_phases or next_phase not in _COMPOSE_RUN_ONCE_PHASES:
            raise ValueError("Compose run-once transition is invalid")
        update_values = dict(updates or {})
        if not set(update_values) <= _COMPOSE_RUN_ONCE_UPDATE_COLUMNS:
            raise ValueError("Compose run-once transition fields are invalid")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=request,
                )
                row = _compose_run_once_attempt_connection(
                    connection,
                    request=request,
                )
                current_phase = str(row["phase"])
                if current_phase not in expected_phases:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose run-once phase changed before its durable transition.",
                        operation_id=request.operation_id,
                    )
                assignments = ["phase = ?", "updated_at = ?"]
                parameters: list[Any] = [next_phase, now]
                for column in sorted(update_values):
                    assignments.append(f"{column} = ?")
                    parameters.append(update_values[column])
                parameters.extend((request.operation_id, current_phase))
                attempt = connection.execute(
                    f"""
                    UPDATE broker_compose_run_once_attempts
                    SET {", ".join(assignments)}
                    WHERE operation_id = ? AND phase = ?
                    """,
                    tuple(parameters),
                )
                operation = connection.execute(
                    """
                    UPDATE operations
                    SET phase = ?, updated_at = ?, generation = generation + 1
                    WHERE operation_id = ? AND status = 'running' AND phase = ?
                    """,
                    (next_phase, now, request.operation_id, current_phase),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET phase = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'compose' AND status = 'running'
                      AND phase = ?
                    """,
                    (next_phase, request.operation_id, current_phase),
                )
                if (
                    attempt.rowcount != 1
                    or operation.rowcount != 1
                    or target.rowcount != 1
                ):
                    raise BrokerError(
                        "operation_state_conflict",
                        "Compose run-once transition lost its durable reservation.",
                        operation_id=request.operation_id,
                    )

    def require_compose_mutation_safe(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        snapshot_id: str,
    ) -> None:
        """Fence every Compose action against exact fresh host and name ownership."""

        request = accepted.request
        if request.operation not in _ALL_COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=request,
                )
                _require_compose_mutation_safe_connection(
                    connection,
                    request=request,
                    snapshot_id=snapshot_id,
                )

    def require_no_active_compose_operation(
        self,
        accepted: AcceptedBrokerRequest,
    ) -> None:
        request = accepted.request
        if request.operation not in _ALL_COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
                    request=request,
                )
                _require_no_unresolved_compose_operation(
                    connection,
                    request=request,
                )

    def reconcilable_prior_compose_operation_id(
        self,
        accepted: AcceptedBrokerRequest,
    ) -> str | None:
        """Return an exact prior uncertain Compose operation for this request."""

        request = accepted.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection,
                    peer=accepted.peer,
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

    def reconcilable_compose_operation_for_definition(
        self,
        *,
        repo_id: str,
        compose_definition_id: str,
    ) -> str | None:
        """Return one exact uncertain operation before configuration updates.

        Repository configuration may need to replace the persisted Compose
        definition after the manifest changes.  A prior uncertain operation
        must be reconciled against its still-sealed definition first or the
        definition-change fence and the normal Compose reconciliation path
        deadlock each other.
        """

        _require_identifier(repo_id, "project_id")
        _require_identifier(compose_definition_id, "compose_definition_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT operation.operation_id
                    FROM operations operation
                    JOIN operation_targets target USING(operation_id)
                    JOIN broker_compose_definitions definition
                      ON definition.compose_definition_id = target.target_id
                    WHERE target.target_kind = 'compose'
                      AND target.target_id = ?
                      AND definition.repo_id = ?
                      AND operation.status = 'needs_attention'
                      AND operation.phase = 'reconciliation_required'
                    ORDER BY operation.created_at, operation.operation_id
                    LIMIT 1
                    """,
                    (compose_definition_id, repo_id),
                ).fetchone()
        return None if row is None else str(row["operation_id"])

    def list_removed_repository(
        self, accepted: AcceptedBrokerRequest
    ) -> list[dict[str, Any]]:
        request = accepted.request
        if request.operation != BrokerOperation.REPOSITORY_LIST_REMOVED:
            raise ValueError("request is not a removed-repository read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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

    def inventory(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        """Return the one service-owned host graph after live peer request validation."""

        request = accepted.request
        if request.operation != BrokerOperation.INVENTORY_READ:
            raise ValueError("request is not a host inventory read")
        with self._store() as store:
            # The normalized service and account stores share one schema.  The
            # broker adapter also keeps request validation and projection inside
            # the exact same SQLite read snapshot, so live revocation cannot
            # race a second inventory transaction.
            store.__class__ = _BrokerInventoryStore
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                graph = store.inventory_v2()
                compose_project_owners: dict[str, list[str]] = {}
                for row in connection.execute(
                    """
                    SELECT DISTINCT definition.project_name, definition.repo_id
                    FROM broker_compose_definitions definition
                    JOIN repositories repository USING(repo_id)
                    LEFT JOIN broker_compose_project_claims claim
                      USING(compose_definition_id)
                    JOIN observation_snapshots snapshot
                      ON snapshot.host_id = repository.host_id
                    JOIN observation_capabilities capability USING(snapshot_id)
                    JOIN broker_observation_compose_scope scope USING(snapshot_id)
                    JOIN broker_observed_compose_assets asset
                      ON asset.snapshot_id = snapshot.snapshot_id
                     AND asset.project_name = definition.project_name
                    WHERE repository.state = 'active'
                      AND (definition.enabled = 1 OR claim.claimed = 1)
                      AND snapshot.observer_domain = 'host-runtime-v2:full-docker'
                      AND snapshot.status = 'completed'
                      AND capability.docker_available = 1
                      AND scope.assets_complete = 1
                      AND snapshot.snapshot_id = (
                          SELECT newer.snapshot_id
                          FROM observation_snapshots newer
                          WHERE newer.host_id = snapshot.host_id
                            AND newer.observer_domain = 'host-runtime-v2:full-docker'
                            AND newer.status = 'completed'
                          ORDER BY newer.completed_at DESC, newer.snapshot_id DESC
                          LIMIT 1
                      )
                    ORDER BY definition.project_name, definition.repo_id
                    """
                ):
                    compose_project_owners.setdefault(
                        str(row["project_name"]), []
                    ).append(str(row["repo_id"]))
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
        # Physical Docker accounting is deliberately a cached authority-owned
        # observer.  The first read schedules collection without delaying the
        # inventory response; later reads receive one disjoint, project-aware
        # storage snapshot and exact reclaim-plan candidates.
        from .docker_storage import cached_project_docker_storage_inventory

        graph["docker_storage"] = cached_project_docker_storage_inventory(
            graph,
            compose_project_owners=compose_project_owners,
        )
        browser_state = str(
            os.environ.get("DEVCOORDINATOR_BROWSER_LIFECYCLE_STATE") or ""
        ).strip()
        if browser_state:
            try:
                configured_idle = int(
                    str(
                        os.environ.get("DEVCOORDINATOR_BROWSER_IDLE_SECONDS")
                        or DEFAULT_BROWSER_IDLE_SECONDS
                    )
                )
                if configured_idle < 1:
                    raise ValueError("browser idle timeout must be positive")
                browser_document = read_browser_lifecycle_state(
                    Path(browser_state).expanduser().absolute()
                )
                if browser_document is not None:
                    graph["agent_browsers"] = (
                        browser_lifecycle_inventory_projection(
                            browser_document,
                            idle_seconds=configured_idle,
                        )
                    )
            except (BrowserLifecycleError, OSError, TypeError, ValueError):
                # Browser telemetry is an optional bounded sidecar. Keep the
                # authoritative repository graph readable and let Performance
                # reconcile the omitted bytes into System / unclassified when
                # the last browser sample is unavailable or malformed.
                pass
        return graph

    def operation_follow(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        """Return one path-free decision projection for an exact durable call."""

        request = accepted.request
        if request.operation is not BrokerOperation.OPERATION_FOLLOW:
            raise ValueError("request is not an operation follow read")
        followed_operation_id = str(request.arguments["operation_id"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                operation = connection.execute(
                    """
                    SELECT durable.operation_id, durable.repo_id, durable.kind,
                           durable.status, durable.phase, durable.error_code,
                           durable.result_json, original.account_id,
                           original.repo_id AS request_repo_id
                    FROM operations AS durable
                    JOIN broker_operation_requests AS original
                      USING(operation_id)
                    WHERE durable.operation_id = ?
                    """,
                    (followed_operation_id,),
                ).fetchone()
                if operation is None:
                    raise BrokerError(
                        "operation_follow_unavailable",
                        "The exact operation does not exist.",
                        operation_id=request.operation_id,
                    )

                status = _operation_follow_identifier(
                    operation["status"],
                    field="operation status",
                    operation_id=request.operation_id,
                )
                phase = _operation_follow_identifier(
                    operation["phase"],
                    field="operation phase",
                    operation_id=request.operation_id,
                )
                kind = _operation_follow_identifier(
                    operation["kind"],
                    field="operation kind",
                    operation_id=request.operation_id,
                )
                target_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM operation_targets
                        WHERE operation_id = ?
                        """,
                        (followed_operation_id,),
                    ).fetchone()[0]
                )
                target_rows = connection.execute(
                    """
                    SELECT target_kind, target_id
                    FROM operation_targets
                    WHERE operation_id = ?
                    ORDER BY ordinal
                    LIMIT ?
                    """,
                    (
                        followed_operation_id,
                        OPERATION_FOLLOW_TARGET_SCAN_LIMIT,
                    ),
                ).fetchall()

                projection: dict[str, Any] = {
                    "operation_id": followed_operation_id,
                    "status": status,
                    "phase": phase,
                    "kind": kind,
                    "target_ids": [],
                    "target_count": target_count,
                    "target_ids_truncated": target_count > 0,
                    "error_classification": _operation_follow_error_classification(
                        status=status,
                        error_code=operation["error_code"],
                    ),
                    "outcome_certainty": _operation_follow_outcome_certainty(
                        status
                    ),
                    "next_transition": _operation_follow_next_transition(
                        status=status,
                        phase=phase,
                    ),
                }
                projection.update(
                    _operation_follow_correlations(
                        status=status,
                        result_json=operation["result_json"],
                    )
                )
                for target in target_rows:
                    candidate = {
                        "kind": _operation_follow_identifier(
                            target["target_kind"],
                            field="target kind",
                            operation_id=request.operation_id,
                        ),
                        "id": _operation_follow_identifier(
                            target["target_id"],
                            field="target id",
                            operation_id=request.operation_id,
                        ),
                    }
                    targets = [*projection["target_ids"], candidate]
                    candidate_projection = {
                        **projection,
                        "target_ids": targets,
                        "target_ids_truncated": len(targets) < target_count,
                    }
                    if (
                        _operation_follow_projection_size(candidate_projection)
                        > OPERATION_FOLLOW_MAX_BYTES
                    ):
                        break
                    projection = candidate_projection

        if _operation_follow_projection_size(projection) > OPERATION_FOLLOW_MAX_BYTES:
            raise BrokerError(
                "operation_follow_projection_invalid",
                "The durable operation cannot be represented by the bounded follow contract.",
                operation_id=request.operation_id,
            )
        return projection

    def runtime_ensure_observation(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        require_reserved: bool = False,
    ) -> dict[str, Any]:
        """Read one exact desired-state target and optionally prove reservation.

        This projection deliberately contains no canonical paths. The backend
        may use authority-only repository context separately when invoking the
        fixed worker supervisor, while the durable public result remains small
        and path-free.
        """

        request = accepted.request
        if request.operation is not BrokerOperation.RUNTIME_ENSURE:
            raise ValueError("request is not a runtime ensure")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                kind = str(request.arguments["target_kind"])
                if kind == "service":
                    row = connection.execute(
                        """
                        SELECT definition.server_definition_id,
                               definition.name, definition.role,
                               definition.definition_fingerprint,
                               observation.lifecycle,
                               observation.health_classification,
                               observation.health_ok,
                               observation.sampled_at,
                               policy.breaker_state
                        FROM server_definitions definition
                        LEFT JOIN server_observations observation
                          USING(server_definition_id)
                        LEFT JOIN worker_policies policy
                          USING(server_definition_id)
                        WHERE definition.repo_id = ?
                          AND definition.server_definition_id = ?
                        """,
                        (request.project_id, request.resource_id),
                    ).fetchone()
                    if row is None:
                        raise BrokerError(
                            "resource_identity_unavailable",
                            "Runtime service no longer belongs to the exact "
                            "repository.",
                            operation_id=request.operation_id,
                        )
                    target_kind = "server"
                    target_id = request.resource_id
                    current_fingerprint = str(row["definition_fingerprint"])
                    observation = {
                        "exact": True,
                        "resource_kind": "service",
                        "resource_id": request.resource_id,
                        "name": str(row["name"]),
                        "role": None if row["role"] is None else str(row["role"]),
                        "lifecycle": row["lifecycle"],
                        "health_classification": row["health_classification"],
                        "health_ok": (
                            None
                            if row["health_ok"] is None
                            else bool(row["health_ok"])
                        ),
                        "breaker_state": row["breaker_state"],
                        "sampled_at": row["sampled_at"],
                    }
                else:
                    row = _runtime_mutation_row(connection, request=request)
                    docker = connection.execute(
                        """
                        SELECT lifecycle, health, sampled_at
                        FROM docker_observations
                        WHERE docker_resource_id = ?
                        """,
                        (row["docker_resource_id"],),
                    ).fetchone()
                    database = (
                        None
                        if kind != "database_stack"
                        else connection.execute(
                            """
                            SELECT available, sampled_at
                            FROM database_observations
                            WHERE database_binding_id = ?
                              AND docker_resource_id = ?
                            """,
                            (
                                row["database_binding_id"],
                                row["docker_resource_id"],
                            ),
                        ).fetchone()
                    )
                    target_kind = "container"
                    target_id = str(row["docker_resource_id"])
                    current_fingerprint = _runtime_target_fingerprint(
                        row, requested_resource_id=request.resource_id
                    )
                    observation = {
                        "exact": True,
                        "resource_kind": kind,
                        "resource_id": request.resource_id,
                        "docker_resource_id": str(row["docker_resource_id"]),
                        "lifecycle": (
                            None if docker is None else docker["lifecycle"]
                        ),
                        "health": None if docker is None else docker["health"],
                        "sampled_at": (
                            None if docker is None else docker["sampled_at"]
                        ),
                    }
                    if kind == "database_stack":
                        observation["docker_lifecycle"] = observation["lifecycle"]
                        observation["database_available"] = (
                            None
                            if database is None
                            else bool(database["available"])
                        )
                        observation["database_sampled_at"] = (
                            None if database is None else database["sampled_at"]
                        )

                if require_reserved:
                    reserved = connection.execute(
                        """
                        SELECT target_kind, target_id, action,
                               immutable_fingerprint
                        FROM operation_targets
                        WHERE operation_id = ? AND ordinal = 0
                        """,
                        (request.operation_id,),
                    ).fetchone()
                    if (
                        reserved is None
                        or str(reserved["target_kind"]) != target_kind
                        or str(reserved["target_id"]) != target_id
                        or str(reserved["action"])
                        != _runtime_operation_action(request)
                    ):
                        raise BrokerError(
                            "operation_state_conflict",
                            "Durable runtime ensure lost its exact target reservation.",
                            operation_id=request.operation_id,
                        )
                    if (
                        str(reserved["immutable_fingerprint"])
                        != current_fingerprint
                    ):
                        raise BrokerError(
                            "stale_resource_definition",
                            "Runtime ensure target identity changed after reservation.",
                            operation_id=request.operation_id,
                        )
                return observation

    def reconcilable_prior_runtime_operation(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, str] | None:
        """Find one exact uncertain runtime action blocking an ensure.

        The current resource resolution and immutable fingerprint must still
        match the prior reservation. This is association and stale-identity
        protection, not a caller permission decision.
        """

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_ENSURE
            or request.arguments["target_kind"] not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed runtime ensure")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                current = _runtime_mutation_row(connection, request=request)
                current_fingerprint = _runtime_target_fingerprint(
                    current, requested_resource_id=request.resource_id
                )
                row = connection.execute(
                    """
                    SELECT operation.operation_id, target.action,
                           resource.full_container_id
                    FROM operations operation
                    JOIN operation_targets target USING(operation_id)
                    JOIN docker_resources resource
                      ON resource.docker_resource_id = target.target_id
                    WHERE operation.repo_id = ?
                      AND target.target_kind = 'container'
                      AND target.target_id = ?
                      AND target.immutable_fingerprint = ?
                      AND operation.operation_id != ?
                      AND operation.kind = 'broker.runtime.request'
                      AND operation.status = 'needs_attention'
                      AND operation.phase = 'reconciliation_required'
                      AND target.status = 'failed'
                      AND target.phase = 'reconciliation_required'
                      AND target.action IN (
                          'runtime.start', 'runtime.stop', 'runtime.restart'
                      )
                    ORDER BY operation.created_at, operation.operation_id
                    LIMIT 1
                    """,
                    (
                        request.project_id,
                        str(current["docker_resource_id"]),
                        current_fingerprint,
                        request.operation_id,
                    ),
                ).fetchone()
                if row is None:
                    return None
                full_container_id = str(row["full_container_id"]).lower()
                if full_container_id != str(current["full_container_id"]).lower():
                    raise BrokerError(
                        "stale_resource_definition",
                        "The uncertain runtime action no longer matches the current immutable container.",
                        operation_id=request.operation_id,
                    )
                return {
                    "operation_id": str(row["operation_id"]),
                    "action": str(row["action"]),
                    "docker_resource_id": str(current["docker_resource_id"]),
                    "full_container_id": full_container_id,
                }

    def runtime_snapshot(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        """Return one accepted runtime family context and host snapshot.

        Classification is evaluated in the same read transaction as the
        inventory projection.  A shared-host status request must not report a
        normal target while another active resource in the same repository
        family has no proved owner.
        """

        request = accepted.request
        if request.operation not in {
            BrokerOperation.RUNTIME_REQUEST,
            BrokerOperation.RUNTIME_ENSURE,
        }:
            raise ValueError("request is not a runtime request")
        with self._store() as store:
            store.__class__ = _BrokerInventoryStore
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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

    def worker_execution_uid(
        self, accepted: AcceptedBrokerRequest
    ) -> int:
        """Resolve one supervised service execution UID.

        An existing policy remains authoritative across callers.  On the first
        exact-ID start, the already-accepted peer UID becomes the execution
        identity that the native supervisor persists before launch.
        """

        request = accepted.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT policy.execution_uid
                    FROM server_definitions definition
                    LEFT JOIN worker_policies policy USING(server_definition_id)
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "worker_execution_uid_unavailable",
                "The exact supervised service has no current repository execution identity.",
                operation_id=request.operation_id,
            )
        if row["execution_uid"] is None:
            return int(accepted.peer.uid)
        return int(row["execution_uid"])

    def runtime_service_has_supervision(
        self, accepted: AcceptedBrokerRequest
    ) -> bool:
        """Return whether one exact service has a persisted supervisor policy."""

        request = accepted.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS policy_count
                    FROM server_definitions definition
                    JOIN worker_policies policy USING(server_definition_id)
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
        return row is not None and int(row["policy_count"]) == 1

    def worker_execution_uid_for_resource(
        self,
        *,
        repo_id: str,
        server_definition_id: str,
        operation_id: str,
    ) -> int:
        """Resolve an exact worker policy's execution identity.

        Lifecycle cleanup calls this after it has fenced the repository or
        resource. It therefore validates the retained worker definition and
        policy directly instead of consulting an active test configuration. The
        local caller UID remains attribution only.
        """

        _require_identifier(repo_id, "project_id")
        _require_identifier(server_definition_id, "server_definition_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                rows = connection.execute(
                    """
                    SELECT policy.execution_uid
                    FROM server_definitions definition
                    JOIN worker_policies policy USING(server_definition_id)
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (repo_id, server_definition_id),
                ).fetchall()
        row = rows[0] if len(rows) == 1 else None
        if row is None or type(row["execution_uid"]) is not int or int(
            row["execution_uid"]
        ) < 0:
            raise BrokerError(
                "worker_execution_uid_unavailable",
                "The exact worker has no current repository execution identity.",
                operation_id=operation_id,
            )
        return int(row["execution_uid"])

    def require_worker_runtime_operation_current(
        self, accepted: AcceptedBrokerRequest
    ) -> None:
        """Reauthorize and prove one reserved worker-control target unchanged."""

        request = accepted.request
        runtime_request = (
            request.operation is BrokerOperation.RUNTIME_REQUEST
            and request.arguments["action"] in {
                "start", "stop", "restart", "replace"
            }
        )
        runtime_ensure = request.operation is BrokerOperation.RUNTIME_ENSURE
        if not (runtime_request or runtime_ensure) or request.arguments[
            "target_kind"
        ] != "service":
            raise ValueError("request is not a worker runtime mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT target_kind, target_id, action, immutable_fingerprint
                    FROM operation_targets
                    WHERE operation_id = ? AND ordinal = 0
                    """,
                    (request.operation_id,),
                ).fetchone()
                expected_action = _runtime_operation_action(request)
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
                if (
                    request.operation is BrokerOperation.RUNTIME_REQUEST
                    and request.arguments["action"] == "replace"
                ):
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
                    ):
                        raise BrokerError(
                            "worker_execution_uid_unavailable",
                            "The exact worker policy has no execution account.",
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
        accepted: AcceptedBrokerRequest,
        *,
        replacement: Mapping[str, Any],
    ) -> None:
        """Reauthorize and prove the replacement CAS committed exactly once."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["target_kind"] != "service"
            or request.arguments["action"] != "replace"
        ):
            raise ValueError("request is not a worker replacement")
        expected_generation = int(request.arguments["expected_definition_generation"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
        self, accepted: AcceptedBrokerRequest
    ) -> str | None:
        """Return the exact live-accepted service role for runtime routing."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["target_kind"] != "service"
        ):
            raise ValueError("request is not a service runtime request")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
                        "resource_identity_unavailable",
                        "Runtime service no longer belongs to the exact repository.",
                        operation_id=request.operation_id,
                    )
                return None if row["role"] is None else str(row["role"])

    def runtime_service_endpoint_target(
        self, accepted: AcceptedBrokerRequest
    ) -> RuntimeServiceEndpointTarget:
        """Resolve the sealed cwd and optional assigned TCP endpoint."""

        request = accepted.request
        if (
            request.operation not in {
                BrokerOperation.RUNTIME_REQUEST,
                BrokerOperation.RUNTIME_ENSURE,
            }
            or request.arguments["target_kind"] != "service"
        ):
            raise ValueError("request is not a service runtime operation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT definition.server_definition_id,
                           definition.repo_id, repository.canonical_root,
                           definition.cwd,
                           definition.health_url_template,
                           assignment.port AS assignment_port,
                           (
                               SELECT MIN(lease.port) FROM leases lease
                               WHERE lease.repo_id = definition.repo_id
                                 AND lease.server_definition_id = definition.server_definition_id
                                 AND lease.status = 'active'
                           ) AS lease_port,
                           (
                               SELECT COUNT(*) FROM leases lease
                               WHERE lease.repo_id = definition.repo_id
                                 AND lease.server_definition_id = definition.server_definition_id
                                 AND lease.status = 'active'
                           ) AS lease_count
                    FROM server_definitions definition
                    JOIN repositories repository USING(repo_id)
                    LEFT JOIN port_assignments assignment
                      ON assignment.repo_id = definition.repo_id
                     AND assignment.server_name = definition.name
                     AND assignment.status = 'active'
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "resource_identity_unavailable",
                "Runtime service no longer belongs to the exact repository.",
                operation_id=request.operation_id,
            )
        assignment_port = row["assignment_port"]
        lease_port = row["lease_port"]
        if int(row["lease_count"]) > 1:
            raise BrokerError(
                "service_endpoint_binding_conflict",
                "The exact service has more than one active port lease.",
                operation_id=request.operation_id,
            )
        if (
            assignment_port is not None
            and lease_port is not None
            and int(assignment_port) != int(lease_port)
        ):
            raise BrokerError(
                "service_endpoint_binding_conflict",
                "The exact service assignment and active lease disagree.",
                operation_id=request.operation_id,
            )
        port = assignment_port if assignment_port is not None else lease_port
        listener_required = port is not None or bool(row["health_url_template"])
        if listener_required and port is None:
            raise BrokerError(
                "service_endpoint_binding_unavailable",
                "A network service requires one exact active port assignment or lease.",
                operation_id=request.operation_id,
            )
        if port is not None and row["health_url_template"]:
            health_url = str(row["health_url_template"]).replace(
                "{host}", "127.0.0.1"
            ).replace("{port}", str(port))
            try:
                parsed_health = urlsplit(health_url)
                health_port = parsed_health.port
            except ValueError as error:
                raise BrokerError(
                    "service_endpoint_binding_conflict",
                    "The exact service health endpoint is malformed.",
                    operation_id=request.operation_id,
                ) from error
            if health_port is None:
                health_port = (
                    80
                    if parsed_health.scheme == "http"
                    else 443
                    if parsed_health.scheme == "https"
                    else None
                )
            if health_port != int(port):
                raise BrokerError(
                    "service_endpoint_binding_conflict",
                    "The exact service health endpoint disagrees with its assigned port.",
                    operation_id=request.operation_id,
                )
        return RuntimeServiceEndpointTarget(
            server_definition_id=str(row["server_definition_id"]),
            repo_id=str(row["repo_id"]),
            canonical_root=str(row["canonical_root"]),
            cwd=str(row["cwd"]),
            listener_port=None if port is None else int(port),
            listener_required=listener_required,
        )

    def runtime_service_log_target(
        self, accepted: AcceptedBrokerRequest
    ) -> RuntimeServiceLogTarget:
        """Reauthorize one service log read to its sealed definition path."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "capture_logs"
            or request.arguments["target_kind"] != "service"
        ):
            raise ValueError("request is not a service runtime log read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT definition.server_definition_id,
                           definition.repo_id, definition.role,
                           COALESCE(
                               definition.log_path,
                               attempt.log_artifact_path
                           ) AS authoritative_log_path,
                           definition.definition_fingerprint,
                           policy.execution_uid
                    FROM server_definitions definition
                    LEFT JOIN worker_policies policy
                      USING(server_definition_id)
                    LEFT JOIN worker_attempts attempt
                      ON attempt.attempt_id = (
                          SELECT candidate.attempt_id
                          FROM worker_attempts candidate
                          WHERE candidate.server_definition_id =
                                definition.server_definition_id
                            AND candidate.log_artifact_path IS NOT NULL
                          ORDER BY candidate.exited_at_epoch DESC,
                                   candidate.updated_at DESC,
                                   candidate.attempt_id DESC
                          LIMIT 1
                      )
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if (
                    row is None
                    or not isinstance(row["authoritative_log_path"], str)
                    or not str(row["authoritative_log_path"])
                ):
                    raise BrokerError(
                        "service_log_unavailable",
                        "The exact service has no authoritative log artifact.",
                        operation_id=request.operation_id,
                    )
                return RuntimeServiceLogTarget(
                    server_definition_id=str(row["server_definition_id"]),
                    repo_id=str(row["repo_id"]),
                    role=None if row["role"] is None else str(row["role"]),
                    log_path=str(row["authoritative_log_path"]),
                    definition_fingerprint=str(row["definition_fingerprint"]),
                    owner_uid=(
                        accepted.attribution_uid
                        if row["execution_uid"] is None
                        else int(row["execution_uid"])
                    ),
                )

    def events(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        """Page the host event journal after live peer request validation."""

        request = accepted.request
        if request.operation != BrokerOperation.EVENTS_READ:
            raise ValueError("request is not a host event read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                return list_event_page(
                    connection,
                    after=request.arguments.get("after"),
                    limit=int(request.arguments.get("limit", 100)),
                )

    def server_publication_target(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        """Resolve the exact active broker lease and configured repository root."""

        request = accepted.request
        if request.operation != BrokerOperation.SERVER_PUBLISH:
            raise ValueError("request is not a server publication")
        with self._store() as store:
            with store.read_transaction() as connection:
                lease = _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
        accepted: AcceptedBrokerRequest,
        *,
        listener_evidence: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Commit broker-observed lifecycle into the shared authority graph."""

        request = accepted.request
        arguments = request.arguments
        now = utc_timestamp()
        lifecycle = str(arguments["lifecycle"])
        with self._store() as store:
            with store.immediate_transaction(revision_kind="observation") as connection:
                lease = _validate_connection_request(
                    connection, peer=accepted.peer, request=request
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
                        "resource_identity_unavailable",
                        "Published server is no longer configured with this repository.",
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
                    "peer_uid": accepted.peer.uid,
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
                                "peer_uid": accepted.peer.uid,
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
        accepted: AcceptedBrokerRequest,
        *,
        plan_id: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = accepted.request
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
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any]:
        request = accepted.request
        if request.operation not in {
            BrokerOperation.REPOSITORY_REMOVE,
            BrokerOperation.RESOURCE_RETIRE,
            BrokerOperation.RESOURCE_ARCHIVE,
        }:
            raise ValueError("request is not a lifecycle plan application")
        plan_id = str(request.arguments["plan_id"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
                _settle_broker_runtime_session(
                    connection,
                    operation_id=operation_id,
                    result=result,
                    succeeded=error_code is None,
                    timestamp=utc_timestamp(),
                )

    def temporary_service_launch_deadline(
        self, accepted: AcceptedBrokerRequest
    ) -> tuple[str, int]:
        """Return the original operation-bound TTL deadline and seconds left."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    "SELECT created_at FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        if row is None:
            raise BrokerError(
                "operation_state_conflict",
                "Temporary service operation reservation disappeared.",
                operation_id=request.operation_id,
            )
        created_epoch = calendar.timegm(
            time.strptime(str(row["created_at"]), "%Y-%m-%dT%H:%M:%SZ")
        )
        deadline_epoch = created_epoch + int(request.arguments["ttl_seconds"])
        remaining = math.ceil(deadline_epoch - time.time())
        if remaining <= 0:
            raise BrokerError(
                "temporary_service_launch_expired",
                "The original temporary-service TTL elapsed before launch could converge.",
                operation_id=request.operation_id,
            )
        return time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline_epoch)
        ), remaining

    def temporary_service_execution_context(
        self, accepted: AcceptedBrokerRequest
    ) -> TemporaryServiceExecutionContext:
        """Resolve a launch from repository state and its reserved caller UID.

        Repository ownership is deliberately absent from this lookup. On this
        single-developer host it is attribution metadata, not an request validation
        or execution selector. ``operations.owner_uid`` is the physical peer
        that created the idempotent launch operation, so replay cannot silently
        change the execution identity.
        """

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT repository.repo_id, repository.canonical_root,
                           repository.generation, repository.state,
                           installation.status, installation.startup_fenced,
                           operation.repo_id AS operation_repo_id,
                           operation.kind, operation.owner_uid
                    FROM repositories AS repository
                    JOIN repository_installations AS installation USING(repo_id)
                    JOIN operations AS operation
                      ON operation.operation_id = ?
                    WHERE repository.repo_id = ?
                    """,
                    (request.operation_id, request.project_id),
                ).fetchone()
        if (
            row is None
            or str(row["repo_id"]) != request.project_id
            or str(row["operation_repo_id"] or "") != request.project_id
            or str(row["kind"]) != "broker.runtime.request"
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
            or int(row["generation"]) != request.repository_generation
            or type(row["owner_uid"]) is not int
            or int(row["owner_uid"]) <= 0
        ):
            raise BrokerError(
                "temporary_service_execution_identity_unavailable",
                "The temporary-service operation has no active repository and original non-root caller identity.",
                operation_id=request.operation_id,
            )
        return TemporaryServiceExecutionContext(
            repo_id=str(row["repo_id"]),
            canonical_root=str(row["canonical_root"]),
            generation=int(row["generation"]),
            execution_uid=int(row["owner_uid"]),
        )

    def temporary_service_predecessor(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any] | None:
        """Return the latest still-leased same-name session for live probing."""

        request = accepted.request
        service_id = temporary_dev_service_id(
            request.project_id, str(request.arguments["name"])
        )
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT session.operation_id, session.expires_at,
                           session.result_json
                    FROM runtime_session_resources AS resource
                    JOIN runtime_sessions AS session USING(session_id)
                    WHERE resource.resource_kind = 'service'
                      AND resource.resource_id = ?
                      AND session.repo_id = ?
                      AND session.purpose = 'temporary'
                      AND session.operation_id != ?
                      AND session.expires_at > ?
                    ORDER BY resource.linked_at DESC, session.session_id DESC
                    LIMIT 1
                    """,
                    (
                        service_id,
                        request.project_id,
                        request.operation_id,
                        utc_timestamp(),
                    ),
                ).fetchone()
        if row is None:
            return None
        result = json.loads(str(row["result_json"] or "{}"))
        if not isinstance(result, dict):
            raise BrokerError(
                "temporary_service_catalog_invalid",
                "Temporary service predecessor metadata is malformed.",
                operation_id=request.operation_id,
            )
        unit = str(result.get("unit") or "")
        port = result.get("port")
        if not unit or type(port) is not int:
            raise BrokerError(
                "temporary_service_catalog_invalid",
                "Temporary service predecessor identity is incomplete.",
                operation_id=request.operation_id,
            )
        return {
            "operation_id": str(row["operation_id"]),
            "expires_at": str(row["expires_at"]),
            "unit": unit,
            "port": port,
        }

    def temporary_service_status(
        self, accepted: AcceptedBrokerRequest
    ) -> dict[str, Any] | None:
        """Resolve retained typed status metadata for one temporary service."""

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("target_kind") != "service"
        ):
            return None
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT session.session_id, session.status,
                           session.expires_at, session.result_json,
                           resource.identity_json,
                           definition.definition_fingerprint
                    FROM runtime_session_resources AS resource
                    JOIN runtime_sessions AS session USING(session_id)
                    JOIN server_definitions AS definition
                      ON definition.server_definition_id = resource.resource_id
                     AND definition.repo_id = session.repo_id
                    WHERE resource.resource_kind = 'service'
                      AND resource.resource_id = ?
                      AND session.repo_id = ?
                      AND session.purpose = 'temporary'
                    ORDER BY resource.linked_at DESC, session.session_id DESC
                    LIMIT 1
                    """,
                    (request.resource_id, request.project_id),
                ).fetchone()
        if row is None:
            return None
        result = json.loads(str(row["result_json"] or "{}"))
        identity = json.loads(str(row["identity_json"] or "{}"))
        if not isinstance(result, dict) or not isinstance(identity, dict):
            raise BrokerError(
                "temporary_service_catalog_invalid",
                "Temporary service status metadata is malformed.",
                operation_id=request.operation_id,
            )
        expires_at = str(row["expires_at"] or "")
        expired = bool(expires_at and expires_at <= utc_timestamp())
        return {
            "session_id": str(row["session_id"]),
            "service_id": request.resource_id,
            "name": str(result.get("name") or identity.get("name") or ""),
            "unit": str(result.get("unit") or identity.get("unit") or ""),
            "port": int(result.get("port") or identity.get("port") or 0),
            "url": result.get("url"),
            "execution_uid": result.get("execution_uid"),
            "expires_at": expires_at,
            "cleanup": dict(result.get("cleanup") or {}),
            "expired": expired,
            "catalog_state": str(row["status"]),
            "definition_fingerprint": str(row["definition_fingerprint"]),
        }

    def finish_temporary_dev_service(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Publish one launched temporary service and its operation atomically.

        The transient systemd unit owns process lifetime.  This transaction
        owns the discoverable repository catalog: a fresh client can resolve
        the exact service immediately, while the inventory/status projections
        stop publishing it at its positive TTL even if no client returns.
        """

        request = accepted.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        execution = self.temporary_service_execution_context(accepted)
        document = dict(result)
        expected_session_id = "session-" + uuid.uuid5(
            uuid.NAMESPACE_URL,
            "devcoordinator:dev-session:" + request.operation_id,
        ).hex
        expected_service_id = temporary_dev_service_id(
            request.project_id, str(request.arguments["name"])
        )
        cleanup = document.get("cleanup")
        isolation = document.get("isolation")
        mandatory = {
            "ok": True,
            "operation_id": request.operation_id,
            "session_id": expected_session_id,
            "service_id": expected_service_id,
            "repository_id": request.project_id,
            "repository_generation": request.repository_generation,
            "execution_uid": execution.execution_uid,
            "agent": str(request.arguments["agent"]),
            "name": str(request.arguments["name"]),
            "port": int(request.arguments["port"]),
            "state": "running",
        }
        if any(document.get(key) != value for key, value in mandatory.items()):
            raise BrokerError(
                "temporary_service_result_invalid",
                "The launched temporary service contradicted its reserved identity.",
                operation_id=request.operation_id,
            )
        if (
            not isinstance(cleanup, Mapping)
            or cleanup.get("owner") != "systemd"
            or cleanup.get("kill_mode") != "control-group"
            or cleanup.get("ttl_seconds") != request.arguments["ttl_seconds"]
            or cleanup.get("kill_after_run")
            != request.arguments["kill_after_run"]
            or type(document.get("main_pid")) is not int
            or int(document["main_pid"]) <= 1
            or not isinstance(isolation, Mapping)
            or isolation.get("execution_uid") != execution.execution_uid
            or isolation.get("actual_caller_uid_proven") is not True
        ):
            raise BrokerError(
                "temporary_service_result_invalid",
                "The launched temporary service lacks exact process-lifetime evidence.",
                operation_id=request.operation_id,
            )
        expires_at = str(document.get("expires_at") or "")
        try:
            expires_epoch = calendar.timegm(
                time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ")
            )
        except (OverflowError, ValueError) as error:
            raise BrokerError(
                "temporary_service_result_invalid",
                "The launched temporary service returned an invalid TTL deadline.",
                operation_id=request.operation_id,
            ) from error
        if expires_epoch <= time.time():
            raise BrokerError(
                "temporary_service_result_invalid",
                "The launched temporary service returned an expired TTL deadline.",
                operation_id=request.operation_id,
            )

        timestamp = utc_timestamp()
        definition_fingerprint = "sha256:" + fingerprint(
            {
                "repository_id": request.project_id,
                "repository_generation": request.repository_generation,
                "service_id": expected_service_id,
                "operation_id": request.operation_id,
                "execution_uid": execution.execution_uid,
                "name": request.arguments["name"],
                "argv": request.arguments["argv"],
                "cwd": request.arguments["cwd"],
                "port": request.arguments["port"],
                "unit": document.get("unit"),
            }
        )
        observation_fingerprint = "sha256:" + fingerprint(
            {
                "service_id": expected_service_id,
                "unit": document.get("unit"),
                "pid": document["main_pid"],
                "execution_uid": execution.execution_uid,
                "port": document["port"],
                "state": "running",
                "sampled_at": timestamp,
            }
        )
        identity = {
            "state": "running",
            "operation_id": request.operation_id,
            "repository_id": request.project_id,
            "repository_generation": request.repository_generation,
            "service_id": expected_service_id,
            "session_id": expected_session_id,
            "name": document["name"],
            "unit": document.get("unit"),
            "pid": document["main_pid"],
            "execution_uid": execution.execution_uid,
            "port": document["port"],
            "expires_at": expires_at,
            "cleanup_owner": "systemd",
        }
        session_request = {
            "schema_version": 1,
            "action": "start",
            "agent": str(request.arguments["agent"]),
            "purpose": "temporary",
            "ttl_seconds": int(request.arguments["ttl_seconds"]),
            "kill_after_run": bool(request.arguments["kill_after_run"]),
            "target": {"kind": "service", "id": expected_service_id},
            "name": str(request.arguments["name"]),
            "cwd": str(request.arguments["cwd"]),
            "port": int(request.arguments["port"]),
            "unit": document.get("unit"),
            "execution_uid": execution.execution_uid,
        }
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                replay = self._existing_operation_disposition(
                    connection,
                    accepted=accepted,
                    fingerprint=accepted_request_fingerprint(accepted),
                )
                if replay is not None and replay.state == "completed":
                    retained = dict(replay.result or {})
                    if retained != document:
                        raise BrokerError(
                            "operation_result_conflict",
                            "Temporary service replay contradicted its durable completed result.",
                            operation_id=request.operation_id,
                        )
                    return retained
                if replay is None or replay.state not in {"pending", "reconcile"}:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Temporary service operation is no longer publishable.",
                        operation_id=request.operation_id,
                    )
                scope = connection.execute(
                    """
                    SELECT scope.family_id, family.root_repo_id,
                           repository.canonical_root
                    FROM repository_scopes AS scope
                    JOIN repository_families AS family USING(family_id)
                    JOIN repositories AS repository USING(repo_id)
                    WHERE scope.repo_id = ? AND family.root_repo_id = ?
                    """,
                    (request.project_id, request.arguments["root_repo_id"]),
                ).fetchone()
                if scope is None:
                    raise BrokerError(
                        "runtime_repository_context_mismatch",
                        "Temporary service repository scope changed before catalog publication.",
                        operation_id=request.operation_id,
                    )
                absolute_cwd = str(
                    (
                        Path(str(scope["canonical_root"]))
                        / str(request.arguments["cwd"])
                    ).resolve()
                )
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, role, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'temporary', ?, ?, 0, ?, ?)
                    ON CONFLICT(server_definition_id) DO UPDATE SET
                        role = 'temporary',
                        cwd = excluded.cwd,
                        definition_fingerprint = excluded.definition_fingerprint,
                        generation = server_definitions.generation + 1,
                        updated_at = excluded.updated_at
                    """,
                    (
                        expected_service_id,
                        request.project_id,
                        str(request.arguments["name"]),
                        absolute_cwd,
                        definition_fingerprint,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                    (expected_service_id,),
                )
                connection.executemany(
                    """
                    INSERT INTO server_command_arguments(
                        server_definition_id, ordinal, argument
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (expected_service_id, ordinal, str(argument))
                        for ordinal, argument in enumerate(
                            request.arguments["argv"]
                        )
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO server_observations(
                        server_definition_id, lifecycle, pid,
                        listener_host, listener_port, listener_observable,
                        health_classification, health_ok, sampled_at,
                        observation_fingerprint
                    ) VALUES (?, 'running', ?, '127.0.0.1', ?, 1,
                              'ready', 1, ?, ?)
                    ON CONFLICT(server_definition_id) DO UPDATE SET
                        source_resource_id = NULL,
                        lifecycle = 'running',
                        pid = excluded.pid,
                        process_start_time = NULL,
                        process_fingerprint = NULL,
                        listener_host = excluded.listener_host,
                        listener_port = excluded.listener_port,
                        listener_observable = 1,
                        health_classification = 'ready',
                        health_ok = 1,
                        stopped_at = NULL,
                        stopped_reason = NULL,
                        sampled_at = excluded.sampled_at,
                        observation_fingerprint = excluded.observation_fingerprint
                    """,
                    (
                        expected_service_id,
                        int(document["main_pid"]),
                        int(document["port"]),
                        timestamp,
                        observation_fingerprint,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO runtime_sessions(
                        session_id, family_id, root_repo_id, repo_id,
                        operation_id, action, purpose, ttl_seconds, expires_at,
                        kill_after_run, status, actor, request_json, result_json,
                        created_at, started_at, finished_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'start', 'temporary', ?, ?, ?,
                              'running', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        expected_session_id,
                        str(scope["family_id"]),
                        str(scope["root_repo_id"]),
                        request.project_id,
                        request.operation_id,
                        int(request.arguments["ttl_seconds"]),
                        expires_at,
                        int(bool(request.arguments["kill_after_run"])),
                        str(request.arguments["agent"]),
                        json.dumps(
                            session_request,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            document,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        timestamp,
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO runtime_session_resources(
                        session_id, resource_kind, resource_id,
                        immutable_fingerprint, identity_json,
                        cleanup_disposition, cleanup_state, linked_at, updated_at
                    ) VALUES (?, 'service', ?, ?, ?, 'removed', 'active', ?, ?)
                    """,
                    (
                        expected_session_id,
                        expected_service_id,
                        definition_fingerprint,
                        json.dumps(
                            identity,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        timestamp,
                        timestamp,
                    ),
                )
                _finish_operation(
                    connection, request.operation_id, result=document
                )
        return document

    def finish_runtime_ensure(
        self,
        operation_id: str,
        *,
        result: Mapping[str, Any],
    ) -> None:
        """Commit success or retain an attention result without lying status."""

        document = validate_runtime_ensure_result(
            result, expected_operation_id=operation_id
        )
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        proof = document["terminal_proof"]
        if document["ok"] is True:
            with self._store() as store:
                with store.immediate_transaction() as connection:
                    _finish_operation(
                        connection, operation_id, result=document
                    )
            return
        if document.get("classification") != "attention_required":
            raise ValueError("unsuccessful runtime ensure must require attention")

        uncertain = proof["certain"] is False
        error_code = (
            "operation_outcome_uncertain"
            if uncertain
            else "runtime_ensure_attention_required"
        )
        error_message = (
            "Runtime ensure invoked a lifecycle action without certain terminal proof."
            if uncertain
            else "Runtime ensure stopped without mutation because exact state requires attention."
        )
        error = json.dumps(
            {"code": error_code, "message": error_message},
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
                        error_code = ?, error_message = ?, updated_at = ?,
                        generation = generation + 1
                    WHERE operation_id = ? AND status = 'running'
                      AND kind = 'broker.runtime.ensure'
                    """,
                    (
                        encoded,
                        error_code,
                        error_message,
                        now,
                        operation_id,
                    ),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed',
                        phase = 'reconciliation_required', result_json = ?,
                        error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind IN ('container', 'server')
                      AND action IN (
                          'runtime.ensure.ready', 'runtime.ensure.stopped'
                      )
                      AND status = 'running'
                    """,
                    (encoded, error, now, operation_id),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Runtime ensure is no longer in its reserved state.",
                        operation_id=operation_id,
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
        failure_code: str | None = None,
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
        if failure_code is not None and re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", failure_code
        ) is None:
            raise ValueError("invalid Compose observation failure code")
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
        if failure_code is not None:
            evidence["observation_failure_code"] = failure_code
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
                "message": (
                    "Docker Compose host outcome requires reconciliation."
                    if failure_code is None
                    else "Docker Compose host outcome requires reconciliation after "
                    f"observation failure {failure_code}."
                ),
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
        failure_code: str | None = None,
    ) -> None:
        """Durably fence an invoked Docker-backed runtime action."""

        if action not in {"start", "stop", "restart"}:
            raise ValueError("unsupported runtime reconciliation action")
        if failed_phase not in {"host_invocation", "observation", "journal_commit"}:
            raise ValueError("unsupported runtime reconciliation phase")
        if failure_code is not None and re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", failure_code
        ) is None:
            raise ValueError("invalid runtime observation failure code")
        evidence = json.dumps(
            {
                "action": action,
                "failed_phase": failed_phase,
                "completion_unknown": True,
                **(
                    {}
                    if failure_code is None
                    else {"observation_failure_code": failure_code}
                ),
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
                      AND kind IN ('broker.runtime.request', ?)
                    """,
                    (evidence, now, operation_id, "broker.docker." + action),
                )
                target = connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed', phase = 'reconciliation_required',
                        result_json = ?, error_json = ?, finished_at = ?
                    WHERE operation_id = ? AND ordinal = 0
                      AND target_kind = 'container'
                      AND action IN (?, ?) AND status = 'running'
                    """,
                    (
                        evidence,
                        error,
                        now,
                        operation_id,
                        "runtime." + action,
                        "docker." + action,
                    ),
                )
                if operation.rowcount != 1 or target.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Runtime operation is no longer in its reserved state.",
                        operation_id=operation_id,
                    )
                connection.execute(
                    """
                    UPDATE runtime_sessions
                    SET status = 'cleanup_pending', updated_at = ?
                    WHERE operation_id = ? AND status = 'planned'
                    """,
                    (now, operation_id),
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
                _settle_broker_runtime_session(
                    connection,
                    operation_id=operation_id,
                    result=result,
                    succeeded=succeeded,
                    timestamp=now,
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
        """Fence crash-left direct and desired-state runtime reservations."""

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
                              'broker.docker.restart', 'broker.runtime.request',
                              'broker.runtime.ensure'
                          )
                          AND target.target_kind IN ('container', 'server')
                          AND target.status = 'running'
                          AND target.action IN (
                              'docker.start', 'docker.stop', 'docker.restart',
                              'runtime.start', 'runtime.stop', 'runtime.restart',
                              'runtime.replace',
                              'runtime.ensure.ready', 'runtime.ensure.stopped'
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
                                "Broker restarted before the runtime outcome "
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
                                'Broker restarted before the runtime outcome was durably settled; reconciliation is required.',
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
                          AND target_kind IN ('container', 'server')
                          AND status = 'running'
                        """,
                        (evidence, error, now, operation_id),
                    )
                    if operation.rowcount != 1 or target.rowcount != 1:
                        raise BrokerError(
                            "operation_state_conflict",
                            "Docker-backed operation changed during restart recovery.",
                            operation_id=operation_id,
                        )
                    connection.execute(
                        """
                        UPDATE runtime_sessions
                        SET status = 'cleanup_pending', updated_at = ?
                        WHERE operation_id = ? AND status = 'planned'
                        """,
                        (now, operation_id),
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
        accepted: AcceptedBrokerRequest,
        *,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prove a zero-exit Compose mutation's exact requested end state."""

        request = accepted.request
        if request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("request is not a Compose mutation")
        with self._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
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
        accepted: AcceptedBrokerRequest | None = None,
    ) -> dict[str, Any]:
        """Resolve one uncertain Compose outcome as an evidenced terminal failure."""

        if accepted is None and (os.geteuid() != 0 or self.expected_uid != 0):
            raise PermissionError(
                "Compose reconciliation requires the root service administrator"
            )
        if accepted is not None and accepted.request.operation not in _COMPOSE_OPERATIONS:
            raise ValueError("automatic reconciliation requires a Compose request")
        _require_identifier(operation_id, "operation_id")
        if not abandon_as_failed and not isinstance(evidence, Mapping):
            raise TypeError("Compose reconciliation evidence must be a mapping")
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                if accepted is not None:
                    _validate_connection_request(
                        connection,
                        peer=accepted.peer,
                        request=accepted.request,
                    )
                candidate = _compose_reconciliation_candidate_connection(
                    connection, operation_id=operation_id
                )
                if accepted is not None and (
                    candidate["repo_id"] != accepted.request.project_id
                    or candidate["compose_definition_id"]
                    != accepted.request.resource_id
                ):
                    raise BrokerError(
                        "resource_unavailable",
                        "Prior Compose operation does not belong to the exact accepted definition.",
                        operation_id=accepted.request.operation_id,
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
                        "uid": 0 if accepted is None else accepted.peer.uid,
                        "actor": (
                            "broker-admin:uid:0"
                            if accepted is None
                            else "broker:auto-reconcile:uid:"
                            + str(accepted.peer.uid)
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


def _validate_connection_request(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> Optional[sqlite3.Row]:
    """Validate freshness and resolve the few ingress targets callers consume.

    This is deliberately not an request validation layer. The Unix peer is retained
    only for attribution, while typed backends validate their own immutable
    targets, current lifecycle state, idempotency keys, and safety invariants.
    """

    del peer
    generation = connection.execute(
        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if generation is None or str(generation[0]) != request.authority_generation:
        raise BrokerError(
            "broker_generation_mismatch",
            "The request belongs to another broker database generation; reload current Coordinator state.",
            operation_id=request.operation_id,
        )

    if (
        request.operation in _REPOSITORY_LIFECYCLE_OPERATIONS
        and request.resource_id != request.project_id
    ):
        raise BrokerError(
            "lifecycle_rejected",
            "Repository lifecycle requires the exact repository target.",
            operation_id=request.operation_id,
        )

    if _requires_active_repository(request):
        repository = connection.execute(
            """
            SELECT repository.generation, repository.state,
                   installation.status, installation.startup_fenced
            FROM repositories AS repository
            JOIN repository_installations AS installation USING(repo_id)
            WHERE repository.repo_id = ?
            """,
            (request.project_id,),
        ).fetchone()
        if (
            repository is None
            or str(repository["state"]) != "active"
            or str(repository["status"]) != "installed"
            or bool(repository["startup_fenced"])
        ):
            raise BrokerError(
                "repository_startup_fenced",
                "The exact repository is unavailable or fenced for new work.",
                operation_id=request.operation_id,
            )
        if request.repository_generation != int(repository["generation"]):
            raise BrokerError(
                "project_generation_stale",
                "The request belongs to an obsolete repository generation.",
                operation_id=request.operation_id,
            )

    if request.operation is BrokerOperation.EPHEMERAL_SECRET_FD:
        target = connection.execute(
            """
            SELECT run.template_id, template.enabled,
                   run.owner_uid, run.account_id, run.status,
                   run.expires_at_epoch, run.secret_policy_kind,
                   run.secret_binding_id, run.credential_renewal_phase
            FROM ephemeral_container_runs run
            JOIN ephemeral_container_templates template USING(template_id)
            WHERE run.run_id = ? AND run.repo_id = ?
            """,
            (request.resource_id, request.project_id),
        ).fetchone()
        if (
            target is None
            or request.arguments.get("run_id") != request.resource_id
            or request.arguments.get("template_id") != str(target["template_id"])
            or str(target["status"]) != "running"
            or int(target["expires_at_epoch"]) <= int(time.time())
            or str(target["credential_renewal_phase"]) != "none"
            or not bool(target["enabled"])
        ):
            raise BrokerError(
                "resource_unavailable",
                "Credential delivery requires the exact current running ephemeral run.",
                operation_id=request.operation_id,
            )
        return target

    if request.operation is BrokerOperation.SERVER_PUBLISH:
        lease = connection.execute(
            """
            SELECT status, port, protocol, server_definition_id, repo_id
            FROM leases WHERE lease_id = ?
            """,
            (request.arguments["lease_id"],),
        ).fetchone()
        if (
            lease is None
            or str(lease["status"]) != "active"
            or str(lease["repo_id"]) != request.project_id
            or str(lease["server_definition_id"]) != request.resource_id
            or int(lease["port"]) != int(request.arguments["listener_port"])
        ):
            raise BrokerError(
                "resource_identity_mismatch",
                "Server publication does not match the exact active lease and server target.",
                operation_id=request.operation_id,
            )
        return lease

    if request.operation is BrokerOperation.PORT_RELEASE:
        lease = connection.execute(
            """
            SELECT status, port, protocol, server_definition_id, repo_id
            FROM leases WHERE lease_id = ?
            """,
            (request.resource_id,),
        ).fetchone()
        if lease is None or str(lease["repo_id"]) != request.project_id:
            raise BrokerError(
                "resource_identity_mismatch",
                "Port release does not match the exact lease and repository target.",
                operation_id=request.operation_id,
            )
        return lease

    return None


def _requires_active_repository(request: BrokerRequest) -> bool:
    """Return whether this request would create, start, or publish new work."""

    if request.operation in {
        BrokerOperation.HOST_OBSERVE,
        BrokerOperation.PORT_LEASE,
        BrokerOperation.PORT_ASSIGN,
        BrokerOperation.SERVER_PUBLISH,
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_RUN_ONCE,
        BrokerOperation.DOCKER_START,
        BrokerOperation.DOCKER_RESTART,
    }:
        return True
    if request.operation is BrokerOperation.RUNTIME_REQUEST:
        return request.arguments.get("action") in {"start", "restart", "replace"}
    if request.operation is BrokerOperation.RUNTIME_ENSURE:
        return request.arguments.get("desired_state") == "ready"
    return False


def _port_range_rows(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    server_definition_id: str,
    protocol: str,
    ttl_seconds: int,
) -> list[sqlite3.Row]:
    rows = list(
        connection.execute(
            """
            SELECT start_port, end_port, max_ttl_seconds
            FROM broker_port_ranges configured
            WHERE configured.repo_id = ? AND configured.server_definition_id = ?
              AND configured.protocol = ? AND configured.enabled = 1
              AND configured.max_ttl_seconds >= ?
            ORDER BY start_port, end_port
            """,
            (repo_id, server_definition_id, protocol, ttl_seconds),
        )
    )
    if not rows:
        raise BrokerError(
            "port_range_unavailable",
            "The requested protocol or lease duration has no configured host configured.",
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
            "resource_identity_unavailable",
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
            "resource_identity_unavailable",
            "Server definition no longer belongs to the exact repository.",
            operation_id=operation_id,
        )
    return str(row["definition_fingerprint"])


def _settle_broker_runtime_session(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    result: Mapping[str, Any] | None,
    succeeded: bool,
    timestamp: str,
) -> None:
    """Settle a broker runtime session in the operation's transaction."""

    session = connection.execute(
        """
        SELECT session_id, action, ttl_seconds, kill_after_run
        FROM runtime_sessions
        WHERE operation_id = ? ORDER BY created_at, session_id LIMIT 1
        """,
        (operation_id,),
    ).fetchone()
    if session is None:
        return
    cleanup_immediately = succeeded and bool(session["kill_after_run"])
    keep_until_ttl = (
        session["ttl_seconds"] is not None
        and str(session["action"]) in {"start", "restart", "replace"}
    )
    status = (
        "cleanup_pending"
        if cleanup_immediately
        else "running"
        if succeeded and keep_until_ttl
        else "succeeded"
        if succeeded
        else "failed"
    )
    encoded = (
        None
        if result is None
        else json.dumps(
            dict(result),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    changed = connection.execute(
        """
        UPDATE runtime_sessions
        SET status = ?, result_json = ?, finished_at = ?, updated_at = ?
        WHERE session_id = ?
          AND status IN ('planned', 'running', 'failed', 'cleanup_pending')
        """,
        (status, encoded, timestamp, timestamp, str(session["session_id"])),
    ).rowcount
    if changed != 1:
        raise BrokerError(
            "operation_state_conflict",
            "Runtime session changed before its operation could settle.",
            operation_id=operation_id,
        )
    if not keep_until_ttl and not cleanup_immediately:
        connection.execute(
            """
            UPDATE runtime_session_resources
            SET cleanup_state = cleanup_disposition,
                cleaned_at = ?, updated_at = ?
            WHERE session_id = ? AND cleanup_state = 'active'
            """,
            (timestamp, timestamp, str(session["session_id"])),
        )


def _runtime_cleanup_mutation_row(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    resource_kind: str,
    resource_id: str,
    operation_id: str,
) -> sqlite3.Row:
    """Resolve broker-owned cleanup without depending on a departed caller."""

    if resource_kind == "docker":
        rows = list(
            connection.execute(
                """
                SELECT 'docker' AS resource_kind,
                       d.docker_resource_id, d.full_container_id,
                       NULL AS database_binding_id, NULL AS database_name,
                           metadata.observation_revision AS control_generation,
                           metadata.observation_revision
                FROM docker_resources d
                JOIN docker_engines engine USING(engine_id)
                JOIN repositories repository
                  ON repository.repo_id = ?
                 AND repository.host_id = engine.host_id
                CROSS JOIN schema_metadata metadata
                WHERE d.docker_resource_id = ?
                  AND (d.repo_id = repository.repo_id OR d.repo_id IS NULL)
                """,
                (repo_id, resource_id),
            )
        )
    elif resource_kind == "database_stack":
        rows = list(
            connection.execute(
                """
                SELECT 'database_stack' AS resource_kind,
                       d.docker_resource_id, d.full_container_id,
                       database.database_binding_id, database.database_name,
                       metadata.observation_revision AS control_generation,
                       metadata.observation_revision
                FROM database_bindings database
                JOIN docker_resources d USING(docker_resource_id)
                JOIN docker_engines engine USING(engine_id)
                JOIN repositories repository
                  ON repository.repo_id = database.repo_id
                 AND repository.host_id = engine.host_id
                CROSS JOIN schema_metadata metadata
                WHERE repository.repo_id = ?
                  AND database.database_binding_id = ?
                  AND database.engine_kind = 'postgresql'
                """,
                (repo_id, resource_id),
            )
        )
    else:
        raise ValueError("runtime cleanup requires docker or database_stack")
    if len(rows) != 1 or re.fullmatch(
        r"[0-9a-fA-F]{64}", str(rows[0]["full_container_id"])
    ) is None:
        raise BrokerError(
            "runtime_cleanup_identity_changed",
            "Runtime cleanup target no longer resolves to one exact controlled Docker identity.",
            operation_id=operation_id,
        )
    return rows[0]


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
                       metadata.observation_revision AS control_generation,
                       metadata.observation_revision
                FROM docker_resources d
                CROSS JOIN schema_metadata metadata
                WHERE d.docker_resource_id = ?
                """,
                (request.resource_id,),
            )
        )
    elif resource_kind == "database_stack":
        rows = list(
            connection.execute(
                """
                SELECT 'database_stack' AS resource_kind,
                       d.docker_resource_id, d.full_container_id,
                       database.database_binding_id, database.database_name,
                       metadata.observation_revision AS control_generation,
                       metadata.observation_revision
                FROM database_bindings database
                JOIN docker_resources d USING(docker_resource_id)
                JOIN docker_engines engine USING(engine_id)
                JOIN repositories repository
                  ON repository.repo_id = database.repo_id
                 AND repository.host_id = engine.host_id
                CROSS JOIN schema_metadata metadata
                WHERE database.database_binding_id = ?
                  AND database.engine_kind = 'postgresql'
                """,
                (request.resource_id,),
            )
        )
    else:
        raise ValueError("runtime Docker mutation requires docker or database_stack")
    if len(rows) != 1:
        raise BrokerError(
            "resource_identity_unavailable",
            "Runtime target no longer resolves to one exact controlled Docker identity.",
            operation_id=request.operation_id,
        )
    row = rows[0]
    if re.fullmatch(r"[0-9a-fA-F]{64}", str(row["full_container_id"])) is None:
        raise BrokerError(
            "resource_identity_unavailable",
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


def _runtime_replacement_record(row: Mapping[str, Any]) -> RuntimeReplacementRecord:
    restore_result: dict[str, Any] | None = None
    if row["restore_result_json"] is not None:
        try:
            decoded = json.loads(str(row["restore_result_json"]))
        except json.JSONDecodeError as exc:
            raise BrokerError(
                "operation_evidence_corrupt",
                "Replacement restore evidence is not valid JSON.",
                operation_id=str(row["operation_id"]),
            ) from exc
        if not isinstance(decoded, dict):
            raise BrokerError(
                "operation_evidence_corrupt",
                "Replacement restore evidence has an invalid shape.",
                operation_id=str(row["operation_id"]),
            )
        restore_result = decoded
    return RuntimeReplacementRecord(
        operation_id=str(row["operation_id"]),
        repo_id=str(row["repo_id"]),
        resource_kind=str(row["resource_kind"]),
        requested_resource_id=str(row["requested_resource_id"]),
        old_docker_resource_id=str(row["old_docker_resource_id"]),
        old_full_container_id=str(row["old_full_container_id"]).lower(),
        database_binding_id=(
            None
            if row["database_binding_id"] is None
            else str(row["database_binding_id"])
        ),
        database_name=(
            None if row["database_name"] is None else str(row["database_name"])
        ),
        compose_definition_id=str(row["compose_definition_id"]),
        compose_service=str(row["compose_service"]),
        compose_operation_id=str(row["compose_operation_id"]),
        backup_operation_id=(
            None
            if row["backup_operation_id"] is None
            else str(row["backup_operation_id"])
        ),
        database_backup_id=(
            None
            if row["database_backup_id"] is None
            else str(row["database_backup_id"])
        ),
        new_docker_resource_id=(
            None
            if row["new_docker_resource_id"] is None
            else str(row["new_docker_resource_id"])
        ),
        new_full_container_id=(
            None
            if row["new_full_container_id"] is None
            else str(row["new_full_container_id"]).lower()
        ),
        restore_result=restore_result,
        phase=str(row["phase"]),
    )


def _runtime_operation_action(request: BrokerRequest) -> str:
    if request.operation is BrokerOperation.RUNTIME_ENSURE:
        return "runtime.ensure." + str(request.arguments["desired_state"])
    if request.operation is BrokerOperation.RUNTIME_REQUEST:
        return "runtime." + str(request.arguments["action"])
    raise ValueError("request is not a runtime mutation")


def _runtime_operation_target(
    connection: sqlite3.Connection, *, request: BrokerRequest
) -> tuple[str, str, str, str]:
    row = _runtime_mutation_row(connection, request=request)
    return (
        "container",
        str(row["docker_resource_id"]),
        _runtime_operation_action(request),
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
        and request.arguments["action"]
        in {"start", "stop", "restart", "replace"}
        and request.arguments["target_kind"] in {"docker", "database_stack"}
    ) or (
        request.operation is BrokerOperation.RUNTIME_ENSURE
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
    if request.operation in _ALL_COMPOSE_OPERATIONS:
        row = connection.execute(
            """
            SELECT definition_fingerprint FROM broker_compose_definitions
            WHERE compose_definition_id = ? AND repo_id = ?
            """,
            (request.resource_id, request.project_id),
        ).fetchone()
        if row is None:
            raise BrokerError(
                "resource_identity_unavailable",
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
                "resource_identity_unavailable",
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
                "resource_identity_unavailable",
                "Docker target no longer belongs to the exact repository host.",
                operation_id=request.operation_id,
            )
        return str(row["full_container_id"]).lower()
    if request.operation in _DATABASE_OPERATIONS:
        row = connection.execute(
            """
            SELECT db.database_binding_id, db.docker_resource_id,
                   db.database_name, d.full_container_id,
                   m.observation_revision AS control_generation,
                   m.observation_revision
            FROM database_bindings db
            JOIN docker_resources d USING(docker_resource_id)
            CROSS JOIN schema_metadata m
            WHERE db.repo_id = ? AND db.database_binding_id = ?
              AND db.database_name = ? AND db.engine_kind = 'postgresql'
            """,
            (
                request.project_id,
                request.resource_id,
                request.arguments["database_name"],
            ),
        ).fetchone()
        if row is None:
            raise BrokerError(
                "resource_unavailable",
                "PostgreSQL database no longer resolves to the requested current container.",
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


def _require_assignment_port_range(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
    server_definition_id: str,
    port: int,
    operation_id: Optional[str],
) -> None:
    permitted = connection.execute(
        """
        SELECT 1
        FROM broker_port_ranges configured
        WHERE configured.repo_id = ? AND configured.server_definition_id = ?
          AND configured.protocol = 'tcp' AND configured.enabled = 1
          AND configured.start_port <= ? AND configured.end_port >= ?
        LIMIT 1
        """,
        (repo_id, server_definition_id, port, port),
    ).fetchone()
    if permitted is None:
        raise BrokerError(
            "port_range_unavailable",
            "The requested assignment port is outside the configured TCP ranges.",
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
    return str(value)


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
    run_once_services: Iterable[ComposeRunOncePolicy] = (),
    project_name: str,
) -> str:
    document: dict[str, Any] = {
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
    }
    normalized_run_once = tuple(run_once_services)
    if normalized_run_once:
        document["run_once_services"] = compose_run_once_policies_document(
            normalized_run_once
        )
    encoded = json.dumps(
        document,
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
                'Legacy Compose definition had no exact service scope; reconfigure it before mutation.',
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
                    "message": "Exact Compose service scope requires reconfiguration.",
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
                'Legacy Compose definition has no pinned directory identity; reconfigure it before mutation.',
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
                    "message": "Pinned Compose directory identity requires reconfiguration.",
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
    """Fence definitions lacking an exact merged-model configuration proof."""

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
                'Compose definition lacks a bound merged-model proof; reconfigure it before mutation.',
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
                    "message": "Merged effective Compose validation requires reconfiguration.",
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
            SELECT docker_resource_id, association_state,
                   associated_repo_id
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
            str(row["association_state"]) != "exclusive"
            or str(row["associated_repo_id"] or "") != repo_id
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
              'runtime.start', 'runtime.stop', 'runtime.restart',
              'runtime.replace'
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
        SELECT operation.operation_id, operation.status
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
            "Compose definition cannot change while operation "
            + str(unresolved["operation_id"])
            + " is "
            + str(unresolved["status"])
            + " and requires completion or reconciliation.",
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


def _require_service_image_evidence(
    value: Any,
    *,
    services: tuple[str, ...],
    operation_id: str | None,
    allow_empty: bool,
) -> tuple[tuple[str, str], ...]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError) as exc:
        raise BrokerError(
            "compose_effective_model_required",
            "Persisted Compose image evidence is invalid.",
            operation_id=operation_id,
        ) from exc
    if allow_empty and decoded == {}:
        return ()
    if (
        not isinstance(decoded, dict)
        or (not allow_empty and not decoded)
        or not set(decoded) <= set(services)
        or any(
            not isinstance(name, str)
            or not isinstance(image, str)
            or not image
            or image != image.strip()
            or any(character.isspace() for character in image)
            or "\x00" in image
            or len(image.encode("utf-8")) > 512
            for name, image in decoded.items()
        )
    ):
        raise BrokerError(
            "compose_effective_model_required",
            "Persisted Compose image evidence is invalid.",
            operation_id=operation_id,
        )
    return tuple(sorted((str(name), str(image)) for name, image in decoded.items()))


def _compose_run_once_policies_connection(
    connection: sqlite3.Connection,
    *,
    compose_definition_id: str,
    operation_id: str | None,
) -> tuple[ComposeRunOncePolicy, ...]:
    rows = list(
        connection.execute(
            """
            SELECT ordinal, service_name, max_timeout_seconds,
                   receipt_contract_json, policy_fingerprint
            FROM broker_compose_run_once_services
            WHERE compose_definition_id = ?
            ORDER BY ordinal
            """,
            (compose_definition_id,),
        )
    )
    policies: list[ComposeRunOncePolicy] = []
    for expected_ordinal, row in enumerate(rows):
        try:
            contract_document = json.loads(str(row["receipt_contract_json"]))
            policy = ComposeRunOncePolicy(
                name=str(row["service_name"]),
                max_timeout_seconds=int(row["max_timeout_seconds"]),
                receipt=ComposeRunOnceReceiptContract.from_document(
                    contract_document
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BrokerError(
                "compose_run_once_policy_invalid",
                "Persisted Compose run-once policy is invalid; rerun Coordinator configuration.",
                operation_id=operation_id,
            ) from exc
        if (
            int(row["ordinal"]) != expected_ordinal
            or str(row["policy_fingerprint"]) != policy.fingerprint
        ):
            raise BrokerError(
                "compose_run_once_policy_invalid",
                "Persisted Compose run-once policy fingerprint is invalid; rerun Coordinator configuration.",
                operation_id=operation_id,
            )
        policies.append(policy)
    if len({policy.name for policy in policies}) != len(policies):
        raise BrokerError(
            "compose_run_once_policy_invalid",
            "Persisted Compose run-once service scope is ambiguous.",
            operation_id=operation_id,
        )
    return tuple(policies)


def _compose_run_once_policy_for_request(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
) -> ComposeRunOncePolicy:
    if request.operation is not BrokerOperation.COMPOSE_RUN_ONCE:
        raise ValueError("request is not a Compose run-once operation")
    service_name = str(request.arguments["service"])
    policies = _compose_run_once_policies_connection(
        connection,
        compose_definition_id=request.resource_id,
        operation_id=request.operation_id,
    )
    policy = next(
        (item for item in policies if item.name == service_name),
        None,
    )
    if (
        policy is None
        or int(request.arguments["timeout_seconds"])
        > policy.max_timeout_seconds
    ):
        raise BrokerError(
            "compose_run_once_policy_denied",
            "Compose run-once request is outside the sealed service policy.",
            operation_id=request.operation_id,
        )
    return policy


def _compose_run_once_attempt_connection(
    connection: sqlite3.Connection,
    *,
    request: BrokerRequest,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT attempt.*,
               operation.kind AS operation_kind,
               operation.status AS operation_status,
               operation.phase AS operation_phase,
               operation.repo_id AS operation_repo_id,
               operation_request.repo_id AS request_repo_id,
               operation_request.resource_id AS request_resource_id,
               operation_request.operation AS request_operation,
               target.target_kind, target.target_id, target.action,
               target.immutable_fingerprint, target.phase AS target_phase,
               target.status AS target_status
        FROM broker_compose_run_once_attempts attempt
        JOIN operations operation USING(operation_id)
        JOIN broker_operation_requests operation_request USING(operation_id)
        JOIN operation_targets target
          ON target.operation_id = attempt.operation_id
         AND target.ordinal = 0
        WHERE attempt.operation_id = ?
        """,
        (request.operation_id,),
    ).fetchone()
    if (
        row is None
        or str(row["operation_kind"]) != "broker.compose.run_once"
        or str(row["operation_status"]) != "running"
        or str(row["operation_repo_id"] or "") != request.project_id
        or str(row["request_repo_id"]) != request.project_id
        or str(row["request_resource_id"]) != request.resource_id
        or str(row["request_operation"]) != BrokerOperation.COMPOSE_RUN_ONCE.value
        or str(row["compose_definition_id"]) != request.resource_id
        or str(row["target_kind"]) != "compose"
        or str(row["target_id"]) != request.resource_id
        or str(row["action"]) != BrokerOperation.COMPOSE_RUN_ONCE.value
        or str(row["immutable_fingerprint"])
        != str(row["definition_fingerprint"])
        or str(row["operation_phase"]) != str(row["phase"])
        or str(row["target_phase"]) != str(row["phase"])
        or str(row["target_status"]) != "running"
        or str(row["agent"]) != str(request.arguments["agent"])
        or str(row["service_name"]) != str(request.arguments["service"])
        or int(row["timeout_seconds"])
        != int(request.arguments["timeout_seconds"])
        or str(row["phase"]) not in _COMPOSE_RUN_ONCE_PHASES
    ):
        raise BrokerError(
            "compose_run_once_state_invalid",
            "Compose run-once durable reservation is missing or inconsistent.",
            operation_id=request.operation_id,
        )
    return row


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
            else "legacy_accepted_request_fingerprint"
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
                   lifecycle, association_state,
                   associated_repo_id, observation_fingerprint
            FROM broker_observed_compose_containers
            WHERE snapshot_id = ? AND project_name = ?
            ORDER BY service_name, full_container_id
            """,
            (snapshot_id, project_name),
        )
    )
    for row in rows:
        if (
            str(row["association_state"]) != "exclusive"
            or str(row["associated_repo_id"] or "") != repo_id
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
        "No accepted port is currently available for this server.",
    )


def _repository_compose_profile_connection(
    connection: sqlite3.Connection,
    *,
    repo_id: str,
) -> tuple[str | None, dict[str, int]]:
    rows = list(
        connection.execute(
            """
            SELECT compose_definition_id
            FROM broker_compose_definitions
            WHERE repo_id = ? AND enabled = 1
            ORDER BY updated_at DESC, compose_definition_id
            """,
            (repo_id,),
        )
    )
    if len(rows) > 1:
        raise BrokerError(
            "compose_definition_conflict",
            "Repository has multiple enabled Compose definitions; reconcile them explicitly.",
        )
    if not rows:
        return None, {}
    compose_definition_id = str(rows[0]["compose_definition_id"])
    run_once = {
        str(row["service_name"]): int(row["max_timeout_seconds"])
        for row in connection.execute(
            """
            SELECT service_name, max_timeout_seconds
            FROM broker_compose_run_once_services
            WHERE compose_definition_id = ?
            ORDER BY ordinal
            """,
            (compose_definition_id,),
        )
    }
    return compose_definition_id, run_once


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
    """Read one enabled template after request validation, never caller image input."""

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
            "resource_identity_unavailable",
            "Ephemeral template is disabled or unavailable.",
            operation_id=request.operation_id,
        )
    try:
        image_ref = _require_pinned_ephemeral_image(row["image_ref"])
    except ValueError as error:
        raise BrokerError(
            "resource_identity_unavailable",
            "Ephemeral template does not retain an immutable image reference.",
            operation_id=request.operation_id,
        ) from error
    template_fingerprint = str(row["definition_fingerprint"])
    if re.fullmatch(r"sha256:[0-9a-f]{64}", template_fingerprint) is None:
        raise BrokerError(
            "resource_identity_unavailable",
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


def _decode_runtime_ensure_result(
    value: Optional[str], *, operation_id: str
) -> dict[str, Any]:
    try:
        return validate_runtime_ensure_result(
            _decode_result(value), expected_operation_id=operation_id
        )
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise BrokerError(
            "invalid_durable_result",
            "Stored runtime ensure result violates its bounded contract.",
            operation_id=operation_id,
        ) from error


def _operation_follow_identifier(
    value: Any, *, field: str, operation_id: str
) -> str:
    try:
        _require_identifier(value, field)
    except ValueError:
        raise BrokerError(
            "operation_follow_projection_invalid",
            "The durable operation contains a non-opaque follow identifier.",
            operation_id=operation_id,
        ) from None
    return value


def _operation_follow_error_classification(
    *, status: str, error_code: Any
) -> str | None:
    if status == "needs_attention" or error_code == "operation_outcome_uncertain":
        return "outcome_uncertain"
    if status == "partial":
        return "partial_failure"
    if status == "failed":
        return "operation_failed"
    if status == "cancelled":
        return "operation_cancelled"
    return None


def _operation_follow_outcome_certainty(status: str) -> str:
    if status in {"planned", "running"}:
        return "pending"
    if status == "needs_attention":
        return "uncertain"
    if status == "partial":
        return "partial"
    return "certain"


def _operation_follow_next_transition(*, status: str, phase: str) -> str | None:
    if status == "planned":
        return "execute"
    if status == "running":
        return "wait"
    if status == "needs_attention":
        return "reconcile" if phase == "reconciliation_required" else "inspect"
    if status == "partial":
        return "inspect"
    return None


def _operation_follow_correlations(
    *, status: str, result_json: Any
) -> dict[str, str]:
    if status not in {"succeeded", "failed", "partial", "cancelled"}:
        return {}
    if not isinstance(result_json, str) or not result_json:
        return {}
    try:
        decoded = json.loads(result_json)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return {}
    if not isinstance(decoded, dict):
        return {}
    correlations: dict[str, str] = {}
    patterns = {
        "plan_id": re.compile(r"^plan-[0-9a-f]{32}$"),
        "run_id": re.compile(r"^run-[0-9a-f]{32}$"),
    }
    for field, pattern in patterns.items():
        value = decoded.get(field)
        if not isinstance(value, str):
            continue
        if pattern.fullmatch(value) is not None:
            correlations[field] = value
            continue
        try:
            if str(uuid.UUID(value)) == value:
                correlations[field] = value
        except (ValueError, AttributeError):
            continue
    return correlations


def _operation_follow_projection_size(projection: Mapping[str, Any]) -> int:
    return len(
        json.dumps(
            dict(projection),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _target_kind(operation: BrokerOperation) -> str:
    if operation is BrokerOperation.TEST_PLAN_PREVIEW:
        return "test_plan"
    if operation in _REPOSITORY_BOOTSTRAP_OPERATIONS:
        return "repository"
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
    if operation in _ALL_COMPOSE_OPERATIONS:
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
    narrow deliberately: administrator configuration is the one trusted place
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
