"""Service-owned broker ACL, lease, and durable idempotency persistence.

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
import uuid

from .broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
    TESTD_INTERNAL_OPERATIONS,
    authenticated_request_fingerprint,
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
    deterministic_id,
    fingerprint,
    utc_timestamp,
)
from .schema import SCHEMA_VERSION, establish_repository_owner_authority
from .runtime_ensure import (
    validate_runtime_ensure_result,
)
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
from .universal_test_admission import (
    clear_legacy_test_admission_drain_proof,
    persist_legacy_test_admission_drain_proof,
    read_legacy_test_admission_drain_proof,
)


DEFAULT_PORT_LEASE_TTL_SECONDS = 600
OPERATION_FOLLOW_MAX_BYTES = 2_048
OPERATION_FOLLOW_TARGET_SCAN_LIMIT = 32
# Broker startup applies trusted, idempotent schema compatibility work before
# any client can connect. Keep that one transaction bounded by the service's
# startup envelope rather than the short per-request mutation budget.
BROKER_INITIALIZATION_MAX_SECONDS = 60.0
TEST_ADMISSION_ADMIN_OPERATIONS = frozenset(
    {
        BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN,
        BrokerOperation.TEST_ADMISSION_DRAIN_STATUS,
        BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR,
    }
)
_REPOSITORY_LIFECYCLE_OPERATIONS = frozenset(
    {
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
    }
)
_REPOSITORY_BOOTSTRAP_OPERATIONS = frozenset(
    {BrokerOperation.REPOSITORY_ENSURE}
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

CREATE TABLE IF NOT EXISTS broker_compose_run_once_acl (
    uid INTEGER NOT NULL REFERENCES broker_acl_principals(uid) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    compose_definition_id TEXT NOT NULL
        REFERENCES broker_compose_definitions(compose_definition_id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(uid, repo_id, compose_definition_id, service_name)
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

CREATE INDEX IF NOT EXISTS broker_compose_run_once_acl_lookup
    ON broker_compose_run_once_acl(
        repo_id, compose_definition_id, service_name, enabled
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
class RuntimeServiceLogTarget:
    server_definition_id: str
    repo_id: str
    role: Optional[str]
    log_path: str
    definition_fingerprint: str
    owner_uid: int


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


@dataclass(frozen=True)
class ComposeEnrollmentContainerScope:
    """Exact enrollment projection for one observed Compose project.

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
class TestAttemptRepositoryAuthority:
    """Exact current repository authority for one broker-owned attempt."""

    repo_id: str
    canonical_root: str
    generation: int
    owner_uid: int


@dataclass(frozen=True)
class TemporaryServiceExecutionContext:
    """Exact repository identity and original kernel caller for one launch."""

    repo_id: str
    canonical_root: str
    generation: int
    execution_uid: int


class StoreBackedAuthorizer:
    """Live single-developer authorizer over the durable policy union.

    Peer UID is retained on the returned request for attribution.  Typed
    account/project/resource/operation authority comes from the union of local
    configured policies, including the internal test namespaces.
    """

    def __init__(
        self,
        persistence: "BrokerPersistence",
        *,
        internal_testd_uid: int | None = None,
    ) -> None:
        self._persistence = persistence
        # Compatibility-only input for older units. Internal test operations
        # are authorized by their exact typed account/operation/repository
        # contract; the connecting local UID is attribution, not a tenant
        # boundary on this single-developer host.
        del internal_testd_uid

    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        if request.operation in TEST_ADMISSION_ADMIN_OPERATIONS:
            return self._persistence.authorize_test_admission_admin(peer, request)
        if request.operation in TESTD_INTERNAL_OPERATIONS:
            return self._persistence.authorize_internal_testd(peer, request)
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

    def ensure_repository_enrollment(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        context: Any,
    ) -> dict[str, Any]:
        """Atomically adopt one proven Git context through an enrolled anchor.

        The request project is transport authority only.  The broker resolves
        and revalidates the Git context before this method, then this single
        writer transaction installs any missing normalized repository rows,
        owner facts, family/scopes, and caller enrollment.  Existing disabled
        or missing repositories are never revived by first use.
        """

        request = authorized.request
        if request.operation is not BrokerOperation.REPOSITORY_ENSURE:
            raise ValueError("request is not a repository ensure")
        if (
            request.arguments["canonical_root"]
            != context.effective.canonical_root
            or request.arguments["project_kind"] != context.project_kind
            or int(request.arguments["owner_uid"])
            != int(context.effective.root_owner_uid)
        ):
            raise BrokerError(
                "repository_context_changed",
                "The proven repository context changed before adoption.",
                operation_id=request.operation_id,
            )

        execution_uid = int(authorized.peer.uid)
        if execution_uid <= 0:
            raise BrokerError(
                "repository_execution_peer_invalid",
                "First-use repository execution requires a non-root local peer.",
                operation_id=request.operation_id,
            )

        disposition = self.reserve_operation(authorized)
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerError(
                disposition.error_code or "repository_bootstrap_failed",
                disposition.error_message or "Repository bootstrap failed.",
                operation_id=request.operation_id,
            )

        from .repository_context import _revalidate_context

        timestamp = utc_timestamp()
        valid_until_epoch = int(time.time()) + 365 * 24 * 60 * 60
        scopes = [context.root]
        if context.temporary is not None:
            scopes.append(context.temporary)

        with self._store() as store:
            with store.immediate_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                _revalidate_context(context)
                anchor = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if anchor is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Repository bootstrap lost its enrolled transport anchor.",
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
                               installation.startup_fenced, owner.owner_uid,
                               owner.repository_generation
                        FROM repositories AS repository
                        LEFT JOIN repository_installations AS installation
                          USING(repo_id)
                        LEFT JOIN repository_owners AS owner USING(repo_id)
                        WHERE repository.host_id = ?
                          AND repository.canonical_root = ?
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
                            (
                                repo_id,
                                host_id,
                                root,
                                Path(root).name or root,
                                timestamp,
                                timestamp,
                            ),
                        )
                        establish_repository_owner_authority(
                            connection,
                            repository_id=repo_id,
                            owner_uid=execution_uid,
                            repository_generation=0,
                            operation_id=str(
                                uuid.uuid5(
                                    uuid.UUID(request.operation_id), repo_id
                                )
                            ),
                            actor=str(request.arguments["agent"]),
                            reason="first start-like repository use",
                            timestamp=timestamp,
                            evidence={
                                "kind": "broker-first-use-repository-adoption",
                                "repository_id": repo_id,
                                "canonical_root": root,
                                "repository_generation": 0,
                                "owner_uid": execution_uid,
                                "execution_uid": execution_uid,
                                "filesystem_owner_uid": int(
                                    scope.root_owner_uid
                                ),
                            },
                        )
                        connection.execute(
                            """
                            INSERT INTO repository_installations(
                                repo_id, status, startup_fenced, generation,
                                reason, actor, updated_at
                            ) VALUES (?, 'installed', 0, 0,
                                      'first start-like repository use', ?, ?)
                            """,
                            (repo_id, str(request.arguments["agent"]), timestamp),
                        )
                        changed = True
                    else:
                        if (
                            str(existing["repo_id"]) != repo_id
                            or str(existing["state"]) != "active"
                            or str(existing["status"] or "") != "installed"
                            or bool(existing["startup_fenced"])
                            or existing["owner_uid"] is None
                            or existing["repository_generation"] is None
                            or int(existing["repository_generation"])
                            != int(existing["generation"])
                        ):
                            raise BrokerError(
                                "repository_startup_fenced",
                                "An existing repository identity cannot be adopted implicitly.",
                                operation_id=request.operation_id,
                            )
                    repository_ids[root] = repo_id

                    execution_principal = connection.execute(
                        """
                        SELECT account_id, enabled
                        FROM broker_acl_principals
                        WHERE uid = ?
                        """,
                        (execution_uid,),
                    ).fetchone()
                    if execution_principal is None:
                        execution_account_id = request.account_id
                        connection.execute(
                            """
                            INSERT INTO broker_acl_principals(
                                uid, account_id, enabled, updated_at
                            ) VALUES (?, ?, 1, ?)
                            """,
                            (execution_uid, execution_account_id, timestamp),
                        )
                        changed = True
                    else:
                        execution_account_id = str(
                            execution_principal["account_id"]
                        )
                        if not bool(execution_principal["enabled"]):
                            raise BrokerError(
                                "repository_execution_owner_disabled",
                                "The repository execution account is explicitly disabled in Coordinator; re-enable that account before starting repository work.",
                                operation_id=request.operation_id,
                            )

                    execution_enrollment = connection.execute(
                        """
                        SELECT account_id, enabled
                        FROM broker_repository_enrollments
                        WHERE uid = ? AND repo_id = ?
                        """,
                        (execution_uid, repo_id),
                    ).fetchone()
                    if execution_enrollment is None:
                        connection.execute(
                            """
                            INSERT INTO broker_repository_enrollments(
                                uid, repo_id, account_id, enabled, issued_at,
                                valid_until_epoch, enrollment_snapshot_id,
                                grant_snapshot_id, updated_at
                            ) VALUES (?, ?, ?, 1, ?, ?, NULL, NULL, ?)
                            """,
                            (
                                execution_uid,
                                repo_id,
                                execution_account_id,
                                timestamp,
                                valid_until_epoch,
                                timestamp,
                            ),
                        )
                        changed = True
                    elif (
                        str(execution_enrollment["account_id"])
                        != execution_account_id
                    ):
                        raise BrokerError(
                            "principal_account_conflict",
                            "The repository execution enrollment conflicts with its current Coordinator account binding.",
                            operation_id=request.operation_id,
                        )
                    elif not bool(execution_enrollment["enabled"]):
                        raise BrokerError(
                            "repository_execution_owner_disabled",
                            "The repository execution enrollment is explicitly disabled in Coordinator; re-enable it before starting repository work.",
                            operation_id=request.operation_id,
                        )

                    enrollment = connection.execute(
                        """
                        SELECT account_id, enabled, issued_at,
                               valid_until_epoch
                        FROM broker_repository_enrollments
                        WHERE uid = ? AND repo_id = ?
                        """,
                        (authorized.authorization_uid, repo_id),
                    ).fetchone()
                    if enrollment is not None and str(
                        enrollment["account_id"]
                    ) != request.account_id:
                        raise BrokerError(
                            "principal_account_conflict",
                            "Repository bootstrap conflicts with an existing account binding.",
                            operation_id=request.operation_id,
                        )
                    if enrollment is None:
                        connection.execute(
                            """
                            INSERT INTO broker_repository_enrollments(
                                uid, repo_id, account_id, enabled, issued_at,
                                valid_until_epoch, enrollment_snapshot_id,
                                grant_snapshot_id, updated_at
                            ) VALUES (?, ?, ?, 1, ?, ?, NULL, NULL, ?)
                            """,
                            (
                                authorized.authorization_uid,
                                repo_id,
                                request.account_id,
                                timestamp,
                                valid_until_epoch,
                                timestamp,
                            ),
                        )
                        changed = True
                    else:
                        if not bool(enrollment["enabled"]):
                            raise BrokerError(
                                "project_access_denied",
                                "A disabled repository enrollment cannot be revived implicitly.",
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
                        if context.temporary is not None
                        and scope is context.temporary
                        else "primary"
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO repository_scopes(
                            repo_id, family_id, project_kind, git_dir,
                            git_common_dir, identity_fingerprint, root_device,
                            root_inode, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

                effective_repo_id = repository_ids[
                    context.effective.canonical_root
                ]
                effective = connection.execute(
                    """
                    SELECT repository.generation, owner.owner_uid,
                           enrollment.issued_at, enrollment.valid_until_epoch
                    FROM repositories AS repository
                    JOIN repository_owners AS owner USING(repo_id)
                    JOIN broker_repository_enrollments AS enrollment
                      ON enrollment.repo_id = repository.repo_id
                     AND enrollment.uid = ?
                    WHERE repository.repo_id = ?
                    """,
                    (authorized.authorization_uid, effective_repo_id),
                ).fetchone()
                if effective is None:
                    raise BrokerError(
                        "repository_bootstrap_failed",
                        "Repository bootstrap did not produce a current enrollment.",
                        operation_id=request.operation_id,
                    )
                repository_document = {
                    "canonical_root": context.effective.canonical_root,
                    "repo_id": effective_repo_id,
                    "generation": int(effective["generation"]),
                    "owner_uid": int(effective["owner_uid"]),
                    "execution_uid": int(effective["owner_uid"]),
                    "filesystem_owner_uid": int(
                        context.effective.root_owner_uid
                    ),
                    "servers": {},
                    "containers": {},
                    "compose_definition_id": None,
                    "compose_container_ids": [],
                    "compose_run_once_services": {},
                    "ephemeral_templates": {},
                    "ephemeral_image_prefetch_templates": [],
                    "ephemeral_secret_policies": {},
                    "account_id": request.account_id,
                    "enabled": True,
                    "issued_at": str(effective["issued_at"]),
                    "valid_until_epoch": int(effective["valid_until_epoch"]),
                }
                result = {
                    "schema_version": 1,
                    "ok": True,
                    "operation_id": request.operation_id,
                    "changed": changed,
                    "repository": repository_document,
                }
                _finish_operation(
                    connection, request.operation_id, result=result
                )
                return result

    def resolve_repository_enrollment(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        """Read one prior first-use enrollment through an existing anchor."""

        request = authorized.request
        if request.operation is not BrokerOperation.REPOSITORY_RESOLVE:
            raise ValueError("request is not a repository resolve")
        canonical_root = str(request.arguments["canonical_root"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                anchor = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (request.project_id,),
                ).fetchone()
                if anchor is None:
                    raise BrokerError(
                        "project_access_denied",
                        "Repository resolution lost its enrolled transport anchor.",
                        operation_id=request.operation_id,
                    )
                row = connection.execute(
                    """
                    SELECT repository.repo_id, repository.state,
                           repository.generation, installation.status,
                           installation.startup_fenced, owner.owner_uid,
                           owner.repository_generation
                    FROM repositories AS repository
                    LEFT JOIN repository_installations AS installation
                      USING(repo_id)
                    LEFT JOIN repository_owners AS owner USING(repo_id)
                    WHERE repository.host_id = ?
                      AND repository.canonical_root = ?
                    """,
                    (
                        str(anchor["host_id"]),
                        canonical_root,
                    ),
                ).fetchone()
                if row is None:
                    return {
                        "schema_version": 1,
                        "ok": True,
                        "state": "unenrolled",
                        "repository": None,
                    }
                generation_revoked = connection.execute(
                    """
                    SELECT 1 FROM broker_repository_revocations
                    WHERE repo_id = ? AND repository_generation = ?
                    """,
                    (str(row["repo_id"]), int(row["generation"])),
                ).fetchone()
                # Local accounts are routing/attribution identities on this
                # single-developer host, not mutually distrusting principals.
                # Prefer an exact-account route when one exists.  If the
                # protected reader has never been enrolled for this newer
                # repository, reuse another enabled local route without
                # changing the physical peer UID. If matching account rows
                # exist but none has an enabled principal and enrollment, that
                # account-level block cannot silently fall through to another
                # account. Enabled rows within one account are a policy union;
                # disabling one UID row is not an account-wide veto while
                # another matching row remains enabled. Enrollment expiry is
                # retained evidence, not a local authorization boundary.
                exact_enrollments = list(
                    connection.execute(
                        """
                        SELECT enrollment.account_id, enrollment.enabled,
                               enrollment.issued_at,
                               enrollment.valid_until_epoch,
                               principal.enabled AS principal_enabled
                        FROM broker_repository_enrollments AS enrollment
                        LEFT JOIN broker_acl_principals AS principal
                          ON principal.uid = enrollment.uid
                         AND principal.account_id = enrollment.account_id
                        WHERE enrollment.repo_id = ?
                          AND enrollment.account_id = ?
                        ORDER BY enrollment.enabled DESC,
                                 principal.enabled DESC,
                                 enrollment.valid_until_epoch DESC,
                                 enrollment.uid
                        """,
                        (str(row["repo_id"]), request.account_id),
                    )
                )
                routing_enrollment = next(
                    (
                        enrollment
                        for enrollment in exact_enrollments
                        if bool(enrollment["enabled"])
                        and bool(enrollment["principal_enabled"])
                    ),
                    None,
                )
                if not exact_enrollments:
                    routing_enrollment = connection.execute(
                        """
                        SELECT enrollment.account_id, enrollment.enabled,
                               enrollment.issued_at,
                               enrollment.valid_until_epoch,
                               principal.enabled AS principal_enabled
                        FROM broker_repository_enrollments AS enrollment
                        JOIN broker_acl_principals AS principal
                          ON principal.uid = enrollment.uid
                         AND principal.account_id = enrollment.account_id
                        WHERE enrollment.repo_id = ?
                          AND enrollment.enabled = 1
                          AND principal.enabled = 1
                        ORDER BY enrollment.valid_until_epoch DESC,
                                 enrollment.account_id,
                                 enrollment.uid
                        LIMIT 1
                        """,
                        (str(row["repo_id"]),),
                    ).fetchone()
                current = (
                    str(row["state"]) == "active"
                    and str(row["status"] or "") == "installed"
                    and not bool(row["startup_fenced"])
                    and row["owner_uid"] is not None
                    and row["repository_generation"] is not None
                    and int(row["repository_generation"])
                    == int(row["generation"])
                    and routing_enrollment is not None
                    and generation_revoked is None
                )
                if not current:
                    return {
                        "schema_version": 1,
                        "ok": True,
                        "state": "blocked",
                        "repository": None,
                    }
                assert routing_enrollment is not None
                server_rows = list(
                    connection.execute(
                        """
                        SELECT definition.name, definition.server_definition_id
                        FROM server_definitions AS definition
                        WHERE definition.repo_id = ?
                          AND NOT EXISTS (
                              SELECT 1 FROM broker_server_revocations AS revoked
                              WHERE revoked.repo_id = definition.repo_id
                                AND revoked.server_definition_id =
                                    definition.server_definition_id
                          )
                        ORDER BY definition.updated_at DESC,
                                 definition.server_definition_id DESC
                        LIMIT 128
                        """,
                        (str(row["repo_id"]),),
                    )
                )
                repository_document = {
                    "canonical_root": canonical_root,
                    "repo_id": str(row["repo_id"]),
                    "generation": int(row["generation"]),
                    "owner_uid": int(row["owner_uid"]),
                    "servers": {
                        str(server["name"]): str(
                            server["server_definition_id"]
                        )
                        for server in reversed(server_rows)
                    },
                    "containers": {},
                    "compose_definition_id": None,
                    "compose_container_ids": [],
                    "compose_run_once_services": {},
                    "ephemeral_templates": {},
                    "ephemeral_image_prefetch_templates": [],
                    "ephemeral_secret_policies": {},
                    "account_id": str(routing_enrollment["account_id"]),
                    "enabled": True,
                    "issued_at": str(routing_enrollment["issued_at"]),
                    "valid_until_epoch": int(
                        routing_enrollment["valid_until_epoch"]
                    ),
                }
                return {
                    "schema_version": 1,
                    "ok": True,
                    "state": "enrolled",
                    "repository": repository_document,
                }

    def authorize_test_admission_admin(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        """Authorize only the local authority identity for cutover fencing."""

        if request.operation not in TEST_ADMISSION_ADMIN_OPERATIONS:
            raise BrokerError(
                "operation_access_denied",
                "This request is not a test-admission administration operation.",
                operation_id=request.operation_id,
            )
        if (
            request.account_id != "devcoordinator-authority"
            or request.project_id != "authority"
            or request.resource_id != "test-admission"
            or request.repository_generation != 0
        ):
            raise BrokerError(
                "peer_not_authorized",
                "Test admission migration controls require the exact typed authority namespace.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                generation = connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()
        if generation is None or str(generation[0]) != request.authority_generation:
            raise BrokerError(
                "broker_generation_mismatch",
                "The migration request belongs to another authority database generation.",
                operation_id=request.operation_id,
            )
        return AuthorizedBrokerRequest(peer=peer, request=request)

    def active_test_admission_proof(self) -> Mapping[str, object] | None:
        with self._store() as store:
            with store.read_transaction() as connection:
                return read_legacy_test_admission_drain_proof(connection)

    def activate_test_admission_drain(
        self,
        *,
        activated_at_epoch: int,
        activated_by_uid: int,
        drained_at_epoch: int,
        broker_instance_id: str,
    ) -> Mapping[str, object]:
        with self._store() as store:
            with store.immediate_transaction(max_seconds=5.0) as connection:
                return persist_legacy_test_admission_drain_proof(
                    connection,
                    activated_at_epoch=activated_at_epoch,
                    activated_by_uid=activated_by_uid,
                    drained_at_epoch=drained_at_epoch,
                    broker_instance_id=broker_instance_id,
                )

    def clear_test_admission_drain(
        self, *, drain_id: str, proof_sha256: str
    ) -> Mapping[str, object]:
        with self._store() as store:
            with store.immediate_transaction(max_seconds=5.0) as connection:
                return clear_legacy_test_admission_drain_proof(
                    connection,
                    drain_id=drain_id,
                    proof_sha256=proof_sha256,
                )

    def reauthorize_test_repository(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        repo_id: str,
    ) -> AuthorizedBrokerRequest:
        """Resolve an opaque test handle to its repo, then reauthorize exactly.

        The original request project is only a host-test-namespace anchor for
        commands whose public contract contains a plan/run id but no path.
        This method preserves the caller attribution and binds the same exact
        account, operation and operation id to the resolved immutable
        repository before any read or mutation crosses into testd.
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
                "project_access_denied",
                "The resolved test repository is not provisioned in this authority.",
                operation_id=authorized.request.operation_id,
            )
        request = authorized.request
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
        return self.authorize(authorized.peer, exact)

    def current_test_repositories(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[dict[str, object], ...]:
        """Return active test enrollments for the request's configured account.

        This authority read supplies only immutable IDs and display metadata.
        Test setup state and telemetry remain owned by testd's separate store.
        """

        with self._store() as store:
            with store.read_transaction() as connection:
                rows = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT DISTINCT repository.repo_id, repository.canonical_root,
                               repository.display_name, repository.generation
                        FROM broker_repository_enrollments AS enrollment
                        JOIN broker_acl_principals AS principal
                          ON principal.uid = enrollment.uid
                         AND principal.account_id = enrollment.account_id
                        JOIN repositories AS repository
                          ON repository.repo_id = enrollment.repo_id
                        WHERE enrollment.account_id = ?
                          AND enrollment.enabled = 1
                          AND principal.enabled = 1
                          AND repository.state = 'active'
                        ORDER BY lower(repository.display_name),
                                 repository.repo_id
                        LIMIT 501
                        """,
                        (authorized.request.account_id,),
                    )
                ]
        if len(rows) > 500:
            raise BrokerError(
                "test_repository_catalog_too_large",
                "The authenticated test repository catalog exceeds its safe bound.",
                operation_id=authorized.request.operation_id,
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
        with self._store() as store:
            with store.immediate_transaction(
                max_seconds=BROKER_INITIALIZATION_MAX_SECONDS,
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                for statement in BROKER_SCHEMA.split(";"):
                    if statement.strip():
                        connection.execute(statement)
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
                if "model_services_json" not in effective_columns:
                    connection.execute(
                        "ALTER TABLE broker_compose_effective_model_evidence "
                        "ADD COLUMN model_services_json TEXT NOT NULL DEFAULT '[]'"
                    )
                    connection.execute(
                        "UPDATE broker_compose_effective_model_evidence "
                        "SET model_services_json = services_json"
                    )
                if "model_service_replicas_json" not in effective_columns:
                    connection.execute(
                        "ALTER TABLE broker_compose_effective_model_evidence "
                        "ADD COLUMN model_service_replicas_json TEXT NOT NULL DEFAULT '{}'"
                    )
                    connection.execute(
                        "UPDATE broker_compose_effective_model_evidence "
                        "SET model_service_replicas_json = service_replicas_json"
                    )
                if "service_images_json" not in effective_columns:
                    connection.execute(
                        "ALTER TABLE broker_compose_effective_model_evidence "
                        "ADD COLUMN service_images_json TEXT NOT NULL DEFAULT '{}'"
                    )
                run_once_attempt_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(broker_compose_run_once_attempts)"
                    )
                }
                if (
                    run_once_attempt_columns
                    and "receipt_error_code" not in run_once_attempt_columns
                ):
                    connection.execute(
                        "ALTER TABLE broker_compose_run_once_attempts "
                        "ADD COLUMN receipt_error_code TEXT"
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
        cleanup_resources: bool = False,
    ) -> None:
        """Disable stale observation-derived grants before exact reprovisioning."""

        _require_identifier(repo_id, "project_id")
        if not any(
            (containers, databases, lifecycle_resources, cleanup_resources)
        ):
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
                if cleanup_resources:
                    connection.execute(
                        """
                        UPDATE broker_cleanup_resource_acl
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
        run_once_services: Iterable[Mapping[str, Any]] = (),
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
        if isinstance(run_once_services, (str, bytes, Mapping)):
            raise ValueError(
                "run_once_services must be an iterable of sealed service policies"
            )
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
                        effective_evidence.host_access_risks and host_access_approved
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

    def compose_enrollment_container_scope(
        self,
        *,
        repo_id: str,
        snapshot_id: str,
        project_name: str,
        service_names: Sequence[str],
        run_once_service_names: Sequence[str] = (),
    ) -> ComposeEnrollmentContainerScope:
        """Resolve and validate one repository's complete Compose project scope.

        The protected client profile needs this exact subset so a whole-project
        action can run the Compose definition once and then operate only on
        genuinely standalone containers.  Names and image references are not
        ownership authority: the fenced snapshot's Compose project/service
        labels, exclusive repository binding, and immutable Docker resource ID
        are all required.  An active, exclusively owned container in this same
        Compose project may not disappear merely because its service was omitted
        from the lifecycle declaration; that partial declaration is rejected
        with a typed enrollment error.  Explicit run-once services remain
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
                        "Compose-owned container projection requires the exact completed enrollment snapshot.",
                    )
                rows = list(
                    connection.execute(
                        """
                        SELECT observed.docker_resource_id,
                               observed.full_container_id,
                               observed.service_name,
                               observed.lifecycle,
                               observed.ownership_state,
                               observed.authoritative_owner_repo_id,
                               resource.full_container_id AS current_full_container_id,
                               binding.authority_state
                        FROM broker_observed_compose_containers observed
                        JOIN observation_snapshot_resources present
                          ON present.snapshot_id = observed.snapshot_id
                         AND present.resource_kind = 'container'
                         AND present.resource_id = observed.docker_resource_id
                        JOIN docker_resources resource
                          ON resource.docker_resource_id = observed.docker_resource_id
                        LEFT JOIN repository_memberships membership
                          ON membership.repo_id = ?
                         AND membership.resource_kind = 'container'
                         AND membership.host_resource_id = observed.docker_resource_id
                        LEFT JOIN control_bindings binding
                          ON binding.binding_id = membership.control_binding_id
                        WHERE observed.snapshot_id = ?
                          AND observed.project_name = ?
                        ORDER BY observed.docker_resource_id
                        """,
                        (
                            repo_id,
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
                str(row["ownership_state"]) == "exclusive"
                and str(row["authoritative_owner_repo_id"] or "") == repo_id
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
                or str(row["authority_state"] or "") != "authoritative"
                or str(row["full_container_id"]).lower()
                != str(row["current_full_container_id"]).lower()
            ):
                raise BrokerError(
                    "control_binding_unavailable",
                    "Compose-owned container identity changed before profile publication.",
                )
            lifecycle_result.append(resource_id)
        if unexpected_active_services:
            raise BrokerError(
                "compose_scope_incomplete",
                "Compose enrollment omits active exclusively owned services from "
                f"project {normalized_project!r}: "
                + ", ".join(sorted(unexpected_active_services))
                + ". Declare each service as lifecycle or explicit run-once before enrollment.",
            )
        all_result_ids = (*lifecycle_result, *non_lifecycle_result)
        if len(set(all_result_ids)) != len(all_result_ids):
            raise BrokerError(
                "control_binding_unavailable",
                "Compose-owned container identity is duplicated in enrollment evidence.",
            )
        return ComposeEnrollmentContainerScope(
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

        return self.compose_enrollment_container_scope(
            repo_id=repo_id,
            snapshot_id=snapshot_id,
            project_name=project_name,
            service_names=service_names,
            run_once_service_names=run_once_service_names,
        ).lifecycle_container_ids

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

    def replace_compose_run_once_access(
        self,
        *,
        uid: int,
        repo_id: str,
        compose_definition_id: str,
        service_names: Iterable[str],
    ) -> dict[str, int]:
        """Replace one UID's exact per-service one-shot capability set."""

        _require_identifier(repo_id, "project_id")
        _require_identifier(compose_definition_id, "compose_definition_id")
        if isinstance(service_names, (str, bytes)):
            raise ValueError("service_names must be an exact service sequence")
        normalized = tuple(
            _require_compose_service_name(item) for item in service_names
        )
        if len(set(normalized)) != len(normalized):
            raise ValueError("Compose run-once grants must not contain duplicates")
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
                        "Compose run-once grants require one enabled definition.",
                    )
                declared = {
                    str(row["service_name"])
                    for row in connection.execute(
                        """
                        SELECT service_name
                        FROM broker_compose_run_once_services
                        WHERE compose_definition_id = ?
                        """,
                        (compose_definition_id,),
                    )
                }
                if not set(normalized) <= declared:
                    raise BrokerError(
                        "compose_run_once_policy_invalid",
                        "Compose run-once grant references an undeclared service policy.",
                    )
                disabled = connection.execute(
                    """
                    UPDATE broker_compose_run_once_acl
                    SET enabled = 0, updated_at = ?
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (now, uid, repo_id),
                ).rowcount
                connection.executemany(
                    """
                    INSERT INTO broker_compose_run_once_acl(
                        uid, repo_id, compose_definition_id, service_name,
                        enabled, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(
                        uid, repo_id, compose_definition_id, service_name
                    ) DO UPDATE SET enabled = 1,
                                    updated_at = excluded.updated_at
                    """,
                    (
                        (
                            uid,
                            repo_id,
                            compose_definition_id,
                            service_name,
                            now,
                        )
                        for service_name in normalized
                    ),
                )
        return {"enabled": len(normalized), "disabled": disabled}

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
                connection.execute(
                    """
                    UPDATE broker_compose_run_once_acl
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
                    UPDATE broker_compose_run_once_acl
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

    def grant_observation_derived_access_batch(
        self,
        *,
        uid: int,
        repo_id: str,
        container_identity_grants: Iterable[
            tuple[str, str, str, bool]
        ] = (),
        runtime_grants: Iterable[tuple[str, str, str]] = (),
        resource_grants: Iterable[
            tuple[str, str, BrokerOperation]
        ] = (),
        database_grants: Iterable[tuple[str, BrokerOperation]] = (),
        lifecycle_resource_grants: Iterable[
            tuple[str, str, str, str, str, BrokerOperation]
        ] = (),
        cleanup_resource_grants: Iterable[
            tuple[str, str, str, str, str, BrokerOperation]
        ] = (),
    ) -> None:
        """Atomically validate and publish one observation-derived ACL set.

        Enrollment commits stale-grant revocation before calling this method.
        Every desired current-state grant is then revalidated and inserted in
        one bounded writer transaction, so a late invalid row rolls back the
        complete replacement set instead of leaving partially enabled access.
        """

        _require_identifier(repo_id, "project_id")
        container_identity_rows = _deduplicate_observation_grants(
            container_identity_grants,
            arity=4,
            key_indexes=(1,),
            label="container identity grant",
        )
        runtime_rows = _deduplicate_observation_grants(
            runtime_grants,
            arity=3,
            key_indexes=(0, 1, 2),
            label="runtime grant",
        )
        resource_rows = _deduplicate_observation_grants(
            resource_grants,
            arity=3,
            key_indexes=(0, 1, 2),
            label="resource grant",
        )
        database_rows = _deduplicate_observation_grants(
            database_grants,
            arity=2,
            key_indexes=(0, 1),
            label="database grant",
        )
        lifecycle_rows = _deduplicate_observation_grants(
            lifecycle_resource_grants,
            arity=6,
            key_indexes=(0, 1, 2, 5),
            label="lifecycle resource grant",
        )
        cleanup_rows = _deduplicate_observation_grants(
            cleanup_resource_grants,
            arity=6,
            key_indexes=(0, 1, 2, 5),
            label="cleanup resource grant",
        )
        if not any(
            (
                runtime_rows,
                container_identity_rows,
                resource_rows,
                database_rows,
                lifecycle_rows,
                cleanup_rows,
            )
        ):
            return

        for snapshot_id, resource_id, full_container_id, compose_scoped in (
            container_identity_rows
        ):
            _require_identifier(snapshot_id, "snapshot_id")
            _require_identifier(resource_id, "resource_id")
            if not re.fullmatch(r"[0-9a-f]{64}", full_container_id):
                raise ValueError(
                    "container identity grant requires a lowercase full container ID"
                )
            if type(compose_scoped) is not bool:
                raise TypeError("container identity grant scope must be a boolean")

        for resource_kind, resource_id, action in runtime_rows:
            _require_identifier(resource_id, "resource_id")
            if resource_kind not in {"docker", "database_stack"}:
                raise ValueError(
                    "observation-derived runtime resource_kind must be docker or database_stack"
                )
            if action not in {"status", "start", "stop", "restart"}:
                raise ValueError(
                    "observation-derived runtime action must be status, start, stop, or restart"
                )
        for resource_kind, resource_id, operation in resource_rows:
            _require_identifier(resource_id, "resource_id")
            if resource_kind != "container":
                raise ValueError(
                    "observation-derived resource_kind must be container"
                )
            if operation not in _DOCKER_OPERATIONS:
                raise ValueError(
                    "observation-derived resource operation must be a Docker lifecycle operation"
                )
        for database_binding_id, operation in database_rows:
            _require_identifier(database_binding_id, "database_binding_id")
            if operation not in _DATABASE_OPERATIONS:
                raise ValueError("operation is not a broker database operation")
        for rows, allowed_operations, label in (
            (
                lifecycle_rows,
                frozenset(
                    {
                        BrokerOperation.RESOURCE_ATTACH,
                        BrokerOperation.RESOURCE_PLAN_RETIRE,
                        BrokerOperation.RESOURCE_RETIRE,
                    }
                ),
                "lifecycle resource",
            ),
            (
                cleanup_rows,
                frozenset(
                    {
                        BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                        BrokerOperation.RESOURCE_ARCHIVE,
                        BrokerOperation.RESOURCE_RESTORE,
                        BrokerOperation.CLEANUP_PLAN,
                        BrokerOperation.CLEANUP_APPLY,
                    }
                ),
                "cleanup resource",
            ),
        ):
            for (
                resource_kind,
                resource_id,
                control_binding_id,
                immutable_fingerprint,
                ownership_fingerprint,
                operation,
            ) in rows:
                if operation not in allowed_operations:
                    raise ValueError(
                        f"operation is not an exact {label} capability"
                    )
                if resource_kind not in {"server", "container", "supervisor"}:
                    raise ValueError(f"resource_kind is not a {label} kind")
                _require_identifier(resource_id, "resource_id")
                _require_identifier(control_binding_id, "control_binding_id")
                for value, field in (
                    (immutable_fingerprint, "immutable_fingerprint"),
                    (ownership_fingerprint, "ownership_fingerprint"),
                ):
                    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                        raise ValueError(f"{field} must be a sha256 fingerprint")

        timestamp = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                _require_principal(connection, uid)

                for (
                    snapshot_id,
                    resource_id,
                    full_container_id,
                    compose_scoped,
                ) in container_identity_rows:
                    current = connection.execute(
                        """
                        SELECT full_container_id FROM docker_resources
                        WHERE docker_resource_id = ?
                        """,
                        (resource_id,),
                    ).fetchone()
                    if (
                        current is None
                        or str(current["full_container_id"]) != full_container_id
                    ):
                        raise BrokerError(
                            "control_binding_unavailable",
                            "Observed container identity changed before access publication.",
                        )
                    owners = tuple(
                        str(row["repo_id"])
                        for row in connection.execute(
                            """
                            SELECT DISTINCT membership.repo_id
                            FROM repository_memberships membership
                            JOIN control_bindings binding
                              ON binding.binding_id = membership.control_binding_id
                            WHERE membership.resource_kind = 'container'
                              AND membership.host_resource_id = ?
                              AND binding.authority_state = 'authoritative'
                            ORDER BY membership.repo_id
                            """,
                            (resource_id,),
                        )
                    )
                    ephemeral = connection.execute(
                        """
                        SELECT 1
                        FROM repository_memberships membership
                        JOIN control_bindings binding
                          ON binding.binding_id = membership.control_binding_id
                        WHERE membership.repo_id = ?
                          AND membership.resource_kind = 'container'
                          AND membership.host_resource_id = ?
                          AND binding.authority_state = 'authoritative'
                          AND binding.provenance = 'coordinator_ephemeral'
                        """,
                        (repo_id, resource_id),
                    ).fetchone()
                    if owners != (repo_id,) or ephemeral is not None:
                        raise BrokerError(
                            "control_binding_unavailable",
                            "Observed container no longer has one exact non-ephemeral owner.",
                        )
                    scope = connection.execute(
                        """
                        SELECT 1 FROM broker_observation_compose_scope
                        WHERE snapshot_id = ?
                        """,
                        (snapshot_id,),
                    ).fetchone()
                    if compose_scoped:
                        observed = connection.execute(
                            """
                            SELECT full_container_id, ownership_state,
                                   authoritative_owner_repo_id
                            FROM broker_observed_compose_containers
                            WHERE snapshot_id = ? AND docker_resource_id = ?
                            """,
                            (snapshot_id, resource_id),
                        ).fetchone()
                        if (
                            scope is None
                            or observed is None
                            or str(observed["full_container_id"])
                            != full_container_id
                            or str(observed["ownership_state"]) != "exclusive"
                            or str(observed["authoritative_owner_repo_id"] or "")
                            != repo_id
                        ):
                            raise BrokerError(
                                "control_binding_unavailable",
                                "Compose-scoped container evidence changed before access publication.",
                            )
                    else:
                        standalone = connection.execute(
                            """
                            SELECT 1
                            FROM observation_snapshot_resources observed
                            WHERE observed.snapshot_id = ?
                              AND observed.resource_kind = 'container'
                              AND observed.resource_id = ?
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM broker_observed_compose_containers compose
                                  WHERE compose.snapshot_id = observed.snapshot_id
                                    AND compose.docker_resource_id =
                                        observed.resource_id
                              )
                            """,
                            (snapshot_id, resource_id),
                        ).fetchone()
                        if standalone is None:
                            raise BrokerError(
                                "control_binding_unavailable",
                                "Standalone container snapshot evidence changed before access publication.",
                            )
                        if scope is not None:
                            explicit_membership = connection.execute(
                                """
                                SELECT 1
                                FROM repository_memberships membership
                                JOIN control_bindings binding
                                  ON binding.binding_id =
                                     membership.control_binding_id
                                WHERE membership.repo_id = ?
                                  AND membership.resource_kind = 'container'
                                  AND membership.host_resource_id = ?
                                  AND binding.authority_state = 'authoritative'
                                  AND binding.provenance IN (
                                      'operator_attach', 'runtime_manifest'
                                  )
                                """,
                                (repo_id, resource_id),
                            ).fetchone()
                            if explicit_membership is None:
                                raise BrokerError(
                                    "control_binding_unavailable",
                                    "Standalone container lacks explicit current ownership evidence.",
                                )

                for resource_kind, resource_id in {
                    (str(row[0]), str(row[1])) for row in runtime_rows
                }:
                    _require_runtime_resource_membership(
                        connection,
                        repo_id=repo_id,
                        resource_kind=resource_kind,
                        resource_id=resource_id,
                    )
                for resource_kind, resource_id in {
                    (str(row[0]), str(row[1])) for row in resource_rows
                }:
                    _require_resource_membership(
                        connection,
                        repo_id=repo_id,
                        resource_kind=resource_kind,
                        resource_id=resource_id,
                    )

                database_resources: dict[str, str] = {}
                for database_binding_id in {
                    str(row[0]) for row in database_rows
                }:
                    binding = connection.execute(
                        """
                        SELECT b.docker_resource_id
                        FROM database_bindings b
                        JOIN repository_memberships m
                          ON m.resource_kind = 'container'
                         AND m.host_resource_id = b.docker_resource_id
                         AND m.repo_id = ?
                        JOIN control_bindings c
                          ON c.binding_id = m.control_binding_id
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
                    database_resources[str(database_binding_id)] = str(
                        binding["docker_resource_id"]
                    )

                for resource_kind, resource_id, control_binding_id in {
                    (str(row[0]), str(row[1]), str(row[2]))
                    for row in lifecycle_rows
                }:
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
                    if exact is None:
                        raise BrokerError(
                            "resource_access_denied",
                            "Standalone lifecycle grant requires an exact active resource or an exact existing grant being revoked.",
                        )

                for resource_kind, resource_id, control_binding_id in {
                    (str(row[0]), str(row[1]), str(row[2]))
                    for row in cleanup_rows
                }:
                    exact = connection.execute(
                        """
                        SELECT 1 FROM control_bindings b
                        JOIN coordinator_sources s ON s.source_id = b.source_id
                        LEFT JOIN repository_memberships m
                          ON m.control_binding_id = b.binding_id
                         AND m.resource_kind = b.resource_kind
                         AND m.host_resource_id = b.resource_id
                        WHERE b.binding_id = ? AND b.resource_kind = ?
                          AND b.resource_id = ?
                          AND b.authority_state = 'authoritative'
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
                    if exact is None:
                        raise BrokerError(
                            "resource_access_denied",
                            "Cleanup grant requires an exact authoritative resource.",
                        )

                connection.executemany(
                    """
                    INSERT INTO broker_runtime_acl(
                        uid, repo_id, resource_kind, resource_id,
                        action, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(uid, repo_id, resource_kind, resource_id, action)
                    DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                    """,
                    (
                        (uid, repo_id, kind, resource_id, action, timestamp)
                        for kind, resource_id, action in runtime_rows
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_resource_acl(
                        uid, repo_id, resource_kind, resource_id,
                        operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(
                        uid, repo_id, resource_kind, resource_id, operation
                    ) DO UPDATE SET enabled = 1,
                                    updated_at = excluded.updated_at
                    """,
                    (
                        (
                            uid,
                            repo_id,
                            kind,
                            resource_id,
                            operation.value,
                            timestamp,
                        )
                        for kind, resource_id, operation in resource_rows
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO broker_database_acl(
                        uid, repo_id, database_binding_id, docker_resource_id,
                        operation, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(uid, repo_id, database_binding_id, operation)
                    DO UPDATE SET
                        docker_resource_id = excluded.docker_resource_id,
                        enabled = 1,
                        updated_at = excluded.updated_at
                    """,
                    (
                        (
                            uid,
                            repo_id,
                            database_binding_id,
                            database_resources[str(database_binding_id)],
                            operation.value,
                            timestamp,
                        )
                        for database_binding_id, operation in database_rows
                    ),
                )
                for table, rows in (
                    ("broker_lifecycle_resource_acl", lifecycle_rows),
                    ("broker_cleanup_resource_acl", cleanup_rows),
                ):
                    connection.executemany(
                        f"""
                        INSERT INTO {table}(
                            uid, repo_id, resource_kind, resource_id,
                            control_binding_id, immutable_fingerprint,
                            ownership_fingerprint, operation, enabled, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                        ON CONFLICT(
                            uid, repo_id, resource_kind, resource_id,
                            control_binding_id, operation
                        ) DO UPDATE SET
                            immutable_fingerprint = excluded.immutable_fingerprint,
                            ownership_fingerprint = excluded.ownership_fingerprint,
                            enabled = 1,
                            updated_at = excluded.updated_at
                        """,
                        (
                            (
                                uid,
                                repo_id,
                                kind,
                                resource_id,
                                binding_id,
                                immutable_fingerprint,
                                ownership_fingerprint,
                                operation.value,
                                timestamp,
                            )
                            for (
                                kind,
                                resource_id,
                                binding_id,
                                immutable_fingerprint,
                                ownership_fingerprint,
                                operation,
                            ) in rows
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
                    "broker_compose_run_once_acl",
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
                        authorized.authorization_uid,
                        repo_id,
                        resource_kind,
                        resource_id,
                        control_binding_id,
                        immutable_fingerprint,
                        ownership_fingerprint,
                        operation.value,
                        authorized.authorization_uid,
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
        if request.operation in TESTD_INTERNAL_OPERATIONS:
            raise BrokerError(
                "operation_access_denied",
                "Internal test-attempt operations require the protected testd identity.",
                operation_id=request.operation_id,
            )
        with self._store() as store:
            with store.read_transaction() as connection:
                _result, policy_uid = _authorize_connection_with_policy_uid(
                    connection,
                    peer=peer,
                    request=request,
                )
        return AuthorizedBrokerRequest(
            peer=peer,
            request=request,
            policy_uid=policy_uid,
        )

    def authorize_internal_testd(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        """Authorize the typed internal scheduler namespace.

        The dedicated testd account remains useful for process isolation and
        peer attribution, but its physical UID is not an authorization input.
        Operation, account, repository state and generations remain exact.
        """

        if request.operation not in TESTD_INTERNAL_OPERATIONS:
            raise BrokerError(
                "operation_access_denied",
                "The protected test scheduler may use only internal attempt operations.",
                operation_id=request.operation_id,
            )
        if request.account_id != "devcoordinator-testd":
            raise BrokerError(
                "cross_account_access_denied",
                "The protected test scheduler account identity is invalid.",
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
        return AuthorizedBrokerRequest(peer=peer, request=request)

    def test_attempt_repository_authority(
        self,
        *,
        repo_id: str,
        owner_uid: int | None,
        operation_id: str,
    ) -> TestAttemptRepositoryAuthority:
        """Bind an attempt to the repository's explicit execution authority.

        ``owner_uid`` is retained only for compatibility/diagnostics.  The
        repository owner is selected exclusively from current repository
        authority; a stale caller-side UID cannot block the attempt.
        """

        _require_identifier(repo_id, "project_id")
        del owner_uid
        authority = self.test_repository_execution_authority(
            repo_id=repo_id,
            operation_id=operation_id,
        )
        return authority

    def test_repository_execution_authority(
        self,
        *,
        repo_id: str,
        operation_id: str,
    ) -> TestAttemptRepositoryAuthority:
        """Resolve exactly one active schema-v13 execution owner.

        The local peer remains the best-effort actor attribution. It cannot
        select the operating-system identity used for repository inspection or
        test execution; current repository authority selects that identity.
        The current repository owner must also have an enabled broker principal
        and repository enrollment. First-use adoption provisions that execution
        enrollment atomically when the authorized caller and owner are different.
        """

        _require_identifier(repo_id, "project_id")
        with self._store() as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    """
                    SELECT schema_version, migration_state
                    FROM schema_metadata WHERE singleton = 1
                    """
                ).fetchone()
                rows = connection.execute(
                    """
                    SELECT repository.canonical_root, repository.generation,
                           repository.state, installation.status,
                           installation.startup_fenced,
                           owner.owner_uid, owner.repository_generation,
                           owner.authority_generation, owner.evidence_sha256,
                           enrollment.enabled,
                           principal.enabled AS principal_enabled,
                           transfer.owner_uid AS ledger_owner_uid,
                           transfer.repository_generation AS ledger_repository_generation,
                           transfer.evidence_sha256 AS ledger_evidence_sha256
                    FROM repositories repository
                    JOIN repository_installations installation USING(repo_id)
                    JOIN repository_owners owner
                      ON owner.repo_id = repository.repo_id
                    JOIN broker_repository_enrollments enrollment
                      ON enrollment.repo_id = repository.repo_id
                     AND enrollment.uid = owner.owner_uid
                    JOIN broker_acl_principals principal
                      ON principal.uid = enrollment.uid
                     AND principal.account_id = enrollment.account_id
                    JOIN repository_owner_transfers transfer
                      ON transfer.repo_id = owner.repo_id
                     AND transfer.authority_generation = owner.authority_generation
                    WHERE repository.repo_id = ?
                    """,
                    (repo_id,),
                ).fetchall()
        row = rows[0] if len(rows) == 1 else None
        if (
            metadata is None
            or int(metadata["schema_version"]) != SCHEMA_VERSION
            or str(metadata["migration_state"]) != "ready"
            or len(rows) != 1
            or row is None
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
            or int(row["owner_uid"]) <= 0
            or int(row["repository_generation"]) != int(row["generation"])
            or int(row["ledger_owner_uid"]) != int(row["owner_uid"])
            or int(row["ledger_repository_generation"])
            != int(row["repository_generation"])
            or str(row["ledger_evidence_sha256"])
            != str(row["evidence_sha256"])
            or not bool(row["enabled"])
            or not bool(row["principal_enabled"])
        ):
            raise BrokerError(
                "test_execution_owner_unavailable",
                "The repository has no single current, enrolled execution owner.",
                operation_id=operation_id,
            )
        return TestAttemptRepositoryAuthority(
            repo_id=repo_id,
            canonical_root=str(row["canonical_root"]),
            generation=int(row["generation"]),
            owner_uid=int(row["owner_uid"]),
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

        authority = self.test_attempt_repository_authority(
            repo_id=repo_id,
            owner_uid=owner_uid,
            operation_id=operation_id,
        )
        if authority.generation != repository_generation:
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
                    WHERE repo_id = ? AND enabled = 1
                      AND (template_id = ? OR name = ?)
                    ORDER BY template_id
                    """,
                    (repo_id, template, template),
                ).fetchall()
                if len(rows) != 1:
                    raise BrokerError(
                        "test_fixture_template_unavailable",
                        "The administrator-sealed fixture template is unavailable or ambiguous.",
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
            and authorized.request.operation is BrokerOperation.RUNTIME_REQUEST
        ):
            return DurableOperationDisposition(
                "reconcile",
                error_code=existing["error_code"],
                error_message=existing["error_message"],
            )
        if (
            existing["status"] == "needs_attention"
            and authorized.request.operation is BrokerOperation.RUNTIME_ENSURE
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
        self, authorized: AuthorizedBrokerRequest
    ) -> DurableOperationDisposition | None:
        """Read an idempotent replay result without reserving a new operation."""

        request_fingerprint = authenticated_request_fingerprint(authorized)
        with self._store() as store:
            with store.read_transaction() as connection:
                return self._existing_operation_disposition(
                    connection,
                    authorized=authorized,
                    fingerprint=request_fingerprint,
                )

    def reserve_operation(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        compose_preflight: Mapping[str, Any] | None = None,
    ) -> DurableOperationDisposition:
        request = authorized.request
        request_fingerprint = authenticated_request_fingerprint(authorized)
        now = utc_timestamp()
        with self._store() as store:
            with store.immediate_transaction() as connection:
                existing = self._existing_operation_disposition(
                    connection,
                    authorized=authorized,
                    fingerprint=request_fingerprint,
                )
                if existing is not None:
                    return existing

                _authorize_connection(connection, peer=authorized.peer, request=request)
                compose_snapshot: sqlite3.Row | None = None
                runtime_target: tuple[str, str, str, str] | None = None
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
                        authorized.authorization_uid,
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
                    account_id=request.account_id,
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
                    account_id=request.account_id,
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
                        existing["purpose"] == "broker"
                        or (
                            existing["purpose"]
                            == f"server:{existing['lease_server_name']}"
                            and str(existing["owner"] or "").isdigit()
                        )
                    )
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
                        authorized.authorization_uid,
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
                    account_id=request.account_id,
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
                    account_id=request.account_id,
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
                        authorized.authorization_uid,
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
                           m.observation_revision,
                           controller.effective_uid AS owner_uid
                    FROM docker_resources d
                    JOIN repository_memberships membership
                      ON membership.resource_kind = 'container'
                     AND membership.host_resource_id = d.docker_resource_id
                     AND membership.repo_id = ?
                    JOIN control_bindings b
                      ON b.binding_id = membership.control_binding_id
                    JOIN coordinator_sources controller
                      ON controller.source_id = b.source_id
                    CROSS JOIN schema_metadata m
                    WHERE d.docker_resource_id = ?
                      AND b.authority_state = 'authoritative'
                      AND controller.status = 'imported'
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
                owner_uid = int(row["owner_uid"])
                if owner_uid <= 0:
                    raise BrokerError(
                        "project_isolation_identity_unavailable",
                        "The authoritative resource controller cannot be attributed to a non-root project account.",
                        operation_id=request.operation_id,
                    )
                return DockerMutationTarget(
                    docker_resource_id=str(row["docker_resource_id"]),
                    full_container_id=str(row["full_container_id"]),
                    observation_revision=int(row["observation_revision"]),
                    control_generation=int(row["control_generation"]),
                    repo_id=request.project_id,
                    owner_uid=owner_uid,
                )

    def runtime_docker_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> RuntimeDockerMutationTarget:
        """Reauthorize and resolve a reserved runtime mutation to one container."""

        request = authorized.request
        runtime_request = (
            request.operation is BrokerOperation.RUNTIME_REQUEST
            and request.arguments["action"] in {"start", "stop", "restart"}
        )
        runtime_ensure = request.operation is BrokerOperation.RUNTIME_ENSURE
        if not (runtime_request or runtime_ensure) or request.arguments[
            "target_kind"
        ] not in {"docker", "database_stack"}:
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

    def runtime_docker_read_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> RuntimeDockerMutationTarget:
        """Reauthorize one read-only runtime request to an exact container."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "capture_logs"
            or request.arguments["target_kind"] not in {"docker", "database_stack"}
        ):
            raise ValueError("request is not a Docker-backed runtime log read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
                        "control_binding_unavailable",
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
                )

    def compose_run_once_target(
        self,
        authorized: AuthorizedBrokerRequest,
    ) -> ComposeRunOnceMutationTarget:
        """Load one exact resumable one-shot phase without exposing raw output."""

        request = authorized.request
        if request.operation is not BrokerOperation.COMPOSE_RUN_ONCE:
            raise ValueError("request is not a Compose run-once operation")
        compose = self.compose_target(authorized)
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
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
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("reserved",),
            next_phase="image_bind_intent",
        )

    def bind_compose_run_once_image(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        image_id: str,
    ) -> None:
        if not isinstance(image_id, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_id
        ) is None:
            raise ValueError("Compose run-once image ID is invalid")
        self._advance_compose_run_once(
            authorized,
            expected_phases=("image_bind_intent",),
            next_phase="image_bound",
            updates={"expected_image_id": image_id},
        )

    def mark_compose_run_once_create_intent(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("image_bound",),
            next_phase="create_intent",
        )

    def bind_compose_run_once_container(
        self,
        authorized: AuthorizedBrokerRequest,
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
                    request=authorized.request,
                )
                if str(row["expected_image_id"] or "") != image_id:
                    raise BrokerError(
                        "compose_run_once_image_mismatch",
                        "Created one-shot container does not use the bound image.",
                        operation_id=authorized.request.operation_id,
                    )
        self._advance_compose_run_once(
            authorized,
            expected_phases=("create_intent",),
            next_phase="container_bound",
            updates={"full_container_id": normalized_id},
        )

    def mark_compose_run_once_start_intent(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("container_bound",),
            next_phase="start_intent",
        )

    def mark_compose_run_once_started(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("start_intent",),
            next_phase="started",
        )

    def mark_compose_run_once_wait_intent(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("started",),
            next_phase="wait_intent",
        )

    def mark_compose_run_once_stop_intent(
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("wait_intent",),
            next_phase="stop_intent",
        )

    def record_compose_run_once_terminal(
        self,
        authorized: AuthorizedBrokerRequest,
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
            authorized,
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
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("terminal",),
            next_phase="evidence_intent",
        )

    def record_compose_run_once_evidence(
        self,
        authorized: AuthorizedBrokerRequest,
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
            authorized,
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
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        self._advance_compose_run_once(
            authorized,
            expected_phases=("evidence_captured",),
            next_phase="cleanup_intent",
        )

    def mark_compose_run_once_cleaned(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        cleanup_status: str,
    ) -> None:
        if cleanup_status not in {"removed", "not_created"}:
            raise ValueError("Compose run-once cleanup status is invalid")
        self._advance_compose_run_once(
            authorized,
            expected_phases=("cleanup_intent",),
            next_phase="cleaned",
            updates={"cleanup_status": cleanup_status},
        )

    def compose_run_once_public_result(
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        target = self.compose_run_once_target(authorized)
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
        authorized: AuthorizedBrokerRequest,
        *,
        expected_phases: tuple[str, ...],
        next_phase: str,
        updates: Mapping[str, Any] | None = None,
    ) -> None:
        request = authorized.request
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
                _authorize_connection(
                    connection,
                    peer=authorized.peer,
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
        authorized: AuthorizedBrokerRequest,
        *,
        snapshot_id: str,
    ) -> None:
        """Fence every Compose action against exact fresh host and name ownership."""

        request = authorized.request
        if request.operation not in _ALL_COMPOSE_OPERATIONS:
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
        if request.operation not in _ALL_COMPOSE_OPERATIONS:
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
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any]:
        """Return one path-free decision projection for an exact durable call."""

        request = authorized.request
        if request.operation is not BrokerOperation.OPERATION_FOLLOW:
            raise ValueError("request is not an operation follow read")
        followed_operation_id = str(request.arguments["operation_id"])
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
                      AND original.account_id = ?
                      AND original.repo_id = ?
                      AND (
                        durable.repo_id IS NULL
                        OR durable.repo_id = original.repo_id
                      )
                    """,
                    (
                        followed_operation_id,
                        request.account_id,
                        request.project_id,
                    ),
                ).fetchone()
                if operation is None:
                    raise BrokerError(
                        "operation_follow_unavailable",
                        "The operation does not belong to the exact current "
                        "account and repository.",
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
        authorized: AuthorizedBrokerRequest,
        *,
        require_reserved: bool = False,
    ) -> dict[str, Any]:
        """Read one exact desired-state target and optionally prove reservation.

        This projection deliberately contains no canonical paths. The backend
        may use authority-only repository context separately when invoking the
        fixed worker supervisor, while the durable public result remains small
        and path-free.
        """

        request = authorized.request
        if request.operation is not BrokerOperation.RUNTIME_ENSURE:
            raise ValueError("request is not a runtime ensure")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
                            "control_binding_unavailable",
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
        if request.operation not in {
            BrokerOperation.RUNTIME_REQUEST,
            BrokerOperation.RUNTIME_ENSURE,
        }:
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

    def worker_execution_uid(
        self, authorized: AuthorizedBrokerRequest
    ) -> int:
        """Resolve the enrolled worker policy UID independently of caller UID."""

        request = authorized.request
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
        return self.worker_execution_uid_for_resource(
            repo_id=request.project_id,
            server_definition_id=request.resource_id,
            operation_id=request.operation_id,
        )

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
        policy directly instead of consulting an active test enrollment. The
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
                      AND lower(COALESCE(definition.role, '')) = 'worker'
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
        self, authorized: AuthorizedBrokerRequest
    ) -> None:
        """Reauthorize and prove one reserved worker-control target unchanged."""

        request = authorized.request
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

    def runtime_service_log_target(
        self, authorized: AuthorizedBrokerRequest
    ) -> RuntimeServiceLogTarget:
        """Reauthorize one service log read to its sealed definition path."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments["action"] != "capture_logs"
            or request.arguments["target_kind"] != "service"
        ):
            raise ValueError("request is not a service runtime log read")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                row = connection.execute(
                    """
                    SELECT definition.server_definition_id,
                           definition.repo_id, definition.role,
                           definition.log_path,
                           definition.definition_fingerprint,
                           owner.owner_uid
                    FROM server_definitions definition
                    JOIN repository_owners owner USING(repo_id)
                    WHERE definition.repo_id = ?
                      AND definition.server_definition_id = ?
                    """,
                    (request.project_id, request.resource_id),
                ).fetchone()
                if (
                    row is None
                    or not isinstance(row["log_path"], str)
                    or not str(row["log_path"])
                    or int(row["owner_uid"]) <= 0
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
                    log_path=str(row["log_path"]),
                    definition_fingerprint=str(row["definition_fingerprint"]),
                    owner_uid=int(row["owner_uid"]),
                )

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

    def temporary_service_launch_deadline(
        self, authorized: AuthorizedBrokerRequest
    ) -> tuple[str, int]:
        """Return the original operation-bound TTL deadline and seconds left."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
        self, authorized: AuthorizedBrokerRequest
    ) -> TemporaryServiceExecutionContext:
        """Resolve a launch from repository state and its reserved caller UID.

        Repository ownership is deliberately absent from this lookup. On this
        single-developer host it is attribution metadata, not an authorization
        or execution selector. ``operations.owner_uid`` is the physical peer
        that created the idempotent launch operation, so replay cannot silently
        change the execution identity.
        """

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any] | None:
        """Return the latest still-leased same-name session for live probing."""

        request = authorized.request
        service_id = temporary_dev_service_id(
            request.project_id, str(request.arguments["name"])
        )
        with self._store() as store:
            with store.read_transaction() as connection:
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
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
        self, authorized: AuthorizedBrokerRequest
    ) -> dict[str, Any] | None:
        """Resolve retained typed status metadata for one temporary service."""

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "status"
            or request.arguments.get("target_kind") != "service"
        ):
            return None
        with self._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT session.session_id, session.status,
                           session.expires_at, session.result_json,
                           resource.identity_json
                    FROM runtime_session_resources AS resource
                    JOIN runtime_sessions AS session USING(session_id)
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
        }

    def finish_temporary_dev_service(
        self,
        authorized: AuthorizedBrokerRequest,
        *,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Publish one launched temporary service and its operation atomically.

        The transient systemd unit owns process lifetime.  This transaction
        owns the discoverable repository catalog: a fresh client can resolve
        the exact service immediately, while the inventory/status projections
        stop publishing it at its positive TTL even if no client returns.
        """

        request = authorized.request
        if (
            request.operation is not BrokerOperation.RUNTIME_REQUEST
            or request.arguments.get("action") != "temporary_start"
        ):
            raise ValueError("request is not a temporary service launch")
        execution = self.temporary_service_execution_context(authorized)
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
                _authorize_connection(
                    connection, peer=authorized.peer, request=request
                )
                replay = self._existing_operation_disposition(
                    connection,
                    authorized=authorized,
                    fingerprint=authenticated_request_fingerprint(authorized),
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
                connection.execute(
                    """
                    INSERT INTO broker_runtime_acl(
                        uid, repo_id, resource_kind, resource_id,
                        action, enabled, updated_at
                    ) VALUES (?, ?, 'service', ?, 'status', 1, ?)
                    ON CONFLICT(uid, repo_id, resource_kind, resource_id, action)
                    DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                    """,
                    (
                        authorized.authorization_uid,
                        request.project_id,
                        expected_service_id,
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
    lifecycle authority. It is therefore backfilled only when the same
    UID/repository has all four enabled exact-service actions, an enabled active
    enrollment, and is the configured execution identity of a current
    worker-role definition. ``INSERT OR IGNORE`` preserves explicit worker-ACL
    revocations and makes repeated startup migration idempotent.
    """

    del now_epoch
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
        (updated_at,),
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

    del now_epoch
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
        (updated_at,),
    )


def _authorize_connection(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> Optional[sqlite3.Row]:
    result, _policy_uid = _authorize_connection_with_policy_uid(
        connection,
        peer=peer,
        request=request,
    )
    return result


def _authorize_connection_with_policy_uid(
    connection: sqlite3.Connection,
    *,
    peer: PeerCredentials,
    request: BrokerRequest,
) -> tuple[Optional[sqlite3.Row], int]:
    """Authorize against any matching host-local policy.

    The physical caller UID is attribution only.  Each configured principal
    for the exact request account is evaluated as a policy row; a grant from
    any one of them authorizes the request.  The returned public request still
    carries the original kernel peer credentials.
    """

    policy_uids = tuple(
        int(row["uid"])
        for row in connection.execute(
            """
            SELECT uid
            FROM broker_acl_principals
            WHERE account_id = ?
            ORDER BY enabled DESC, uid
            """,
            (request.account_id,),
        )
    )
    if not policy_uids:
        raise BrokerError(
            "cross_account_access_denied",
            "No configured local policy grants the requested account.",
            operation_id=request.operation_id,
        )

    errors: list[BrokerError] = []
    for policy_uid in policy_uids:
        policy_peer = PeerCredentials(uid=policy_uid, gid=peer.gid, pid=peer.pid)
        try:
            return (
                _authorize_connection_for_policy_uid(
                    connection,
                    peer=policy_peer,
                    request=request,
                ),
                policy_uid,
            )
        except BrokerError as error:
            errors.append(error)

    # Prefer the error nearest the exact operation grant so diagnostics remain
    # actionable when several local policy rows exist.
    rank = {
        "port_policy_denied": 90,
        "operation_access_denied": 80,
        "resource_access_denied": 70,
        "control_binding_unavailable": 65,
        "repository_startup_fenced": 60,
        "project_access_denied": 40,
        "peer_not_authorized": 10,
    }
    raise max(errors, key=lambda error: rank.get(error.code, 55))


def _authorize_connection_for_policy_uid(
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
    # security-assumptions.md requires exact immutable repository generation
    # as a mistake-prevention gate even though local accounts are attribution
    # identities, not mutually hostile tenants. Desired-state mutation must
    # therefore never inherit the legacy revocation-dependent stale check.
    if request.operation is BrokerOperation.RUNTIME_ENSURE and (
        repository_identity is None
        or int(repository_identity["generation"])
        != request.repository_generation
    ):
        raise BrokerError(
            "project_generation_stale",
            "Runtime ensure requires the exact current repository generation; "
            "reload the protected Coordinator profile.",
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
            | _REPOSITORY_BOOTSTRAP_OPERATIONS
            | _REPOSITORY_DISCOVERY_OPERATIONS
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
        BrokerOperation.COMPOSE_RUN_ONCE,
        BrokerOperation.DATABASE_BACKUP,
        BrokerOperation.DATABASE_RESTORE,
        BrokerOperation.SERVER_PUBLISH,
        BrokerOperation.HOST_OBSERVE,
        BrokerOperation.TEST_RUN_START,
        BrokerOperation.TEST_PLAN_PREVIEW,
        BrokerOperation.TEST_PLAN_REGISTER,
        BrokerOperation.TEST_RUN_SUBMIT,
        BrokerOperation.WORKER_LAUNCH_TICKET,
    } or (
        request.operation is BrokerOperation.RUNTIME_REQUEST
        and request.arguments["action"]
        in {"start", "restart", "replace", "temporary_start"}
    ) or (
        request.operation is BrokerOperation.RUNTIME_ENSURE
        and request.arguments["desired_state"] == "ready"
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
        BrokerOperation.TEST_HEALTH,
        BrokerOperation.TEST_STATS_READ,
        BrokerOperation.TEST_FLEET_STATS_READ,
        BrokerOperation.TEST_RUN_LIST,
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

    if request.operation in {
        BrokerOperation.RUNTIME_REQUEST,
        BrokerOperation.RUNTIME_ENSURE,
    }:
        _require_runtime_repository_context(
            connection, peer=peer, request=request
        )
        if (
            request.operation is BrokerOperation.RUNTIME_REQUEST
            and request.arguments["action"] == "temporary_start"
        ):
            # A first-use temporary service is repository-scoped; there is no
            # pre-existing resource ACL or mutable server definition to
            # authorize. The exact active repository context and typed local
            # policy authorize the operation. Its reserved physical peer UID
            # independently selects and records the non-root execution identity;
            # legacy repository ownership never does.
            if (
                request.resource_id != request.project_id
                or request.arguments["target_kind"] != "service"
            ):
                raise BrokerError(
                    "resource_access_denied",
                    "A temporary service must target the exact enrolled repository.",
                    operation_id=request.operation_id,
                )
            return None
        runtime_kind = str(request.arguments["target_kind"])
        _require_runtime_resource_membership(
            connection,
            repo_id=request.project_id,
            resource_kind=runtime_kind,
            resource_id=request.resource_id,
            operation_id=request.operation_id,
        )
        if request.operation is BrokerOperation.RUNTIME_ENSURE:
            # security-assumptions.md permits no broader inferred authority:
            # ensuring ready consumes the exact start grant and ensuring
            # stopped consumes the exact stop grant for this one resource.
            acl_action = (
                "start"
                if request.arguments["desired_state"] == "ready"
                else "stop"
            )
        else:
            acl_action = (
                "status"
                if request.arguments["action"] == "capture_logs"
                else request.arguments["action"]
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
                acl_action,
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
    if request.operation in _REPOSITORY_BOOTSTRAP_OPERATIONS:
        # One existing exact enrollment is only a transport anchor. The
        # service independently proves the requested Git root and performs the
        # bounded adoption transaction before returning its immutable ID.
        return None
    if request.operation in _REPOSITORY_DISCOVERY_OPERATIONS:
        # Canonical-root discovery is a pure authority read routed through an
        # existing enrollment; it cannot create, revive, or change a project.
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
    elif request.operation in _ALL_COMPOSE_OPERATIONS:
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
                assignment_owner["account_id"] != request.account_id
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
    elif request.operation is BrokerOperation.COMPOSE_RUN_ONCE:
        grant = connection.execute(
            """
            SELECT acl.enabled
            FROM broker_compose_run_once_acl acl
            JOIN broker_compose_run_once_services policy
              ON policy.compose_definition_id = acl.compose_definition_id
             AND policy.service_name = acl.service_name
            JOIN broker_compose_definitions definition
              ON definition.compose_definition_id = acl.compose_definition_id
             AND definition.repo_id = acl.repo_id
            WHERE acl.uid = ? AND acl.repo_id = ?
              AND acl.compose_definition_id = ?
              AND acl.service_name = ?
              AND policy.max_timeout_seconds >= ?
              AND definition.enabled = 1
            """,
            (
                peer.uid,
                request.project_id,
                resource_id,
                request.arguments["service"],
                request.arguments["timeout_seconds"],
            ),
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
            account_id=request.account_id,
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
            account_id=request.account_id,
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
    elif request.operation is BrokerOperation.COMPOSE_RUN_ONCE:
        policy = connection.execute(
            """
            SELECT definition.enabled, policy.max_timeout_seconds
            FROM broker_compose_definitions definition
            JOIN broker_compose_run_once_services policy
              USING(compose_definition_id)
            WHERE definition.compose_definition_id = ?
              AND definition.repo_id = ?
              AND policy.service_name = ?
            """,
            (
                resource_id,
                request.project_id,
                request.arguments["service"],
            ),
        ).fetchone()
        if (
            policy is None
            or not bool(policy["enabled"])
            or int(request.arguments["timeout_seconds"])
            > int(policy["max_timeout_seconds"])
        ):
            raise BrokerError(
                "compose_run_once_policy_denied",
                "Compose run-once request is outside the sealed service policy.",
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
        WHERE account_id = ? AND repo_id = ?
          AND enabled = 1
        ORDER BY valid_until_epoch DESC
        LIMIT 1
        """,
        (request.account_id, root_repo_id),
    ).fetchone()
    if (
        enrollment is None
        or not bool(enrollment["enabled"])
        or str(enrollment["account_id"]) != request.account_id
    ):
        raise BrokerError(
            "runtime_root_enrollment_required",
            "The configured account has no enabled enrollment for the exact root repository.",
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


def _deduplicate_observation_grants(
    grants: Iterable[tuple[Any, ...]],
    *,
    arity: int,
    key_indexes: tuple[int, ...],
    label: str,
) -> tuple[tuple[Any, ...], ...]:
    """Materialize a fixed-arity batch and reject ambiguous duplicate keys."""

    if isinstance(grants, (str, bytes, bytearray, Mapping)):
        raise TypeError(f"{label} batch must be an iterable of tuples")
    rows = tuple(grants)
    unique: dict[tuple[Any, ...], tuple[Any, ...]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, tuple) or len(row) != arity:
            raise TypeError(
                f"{label} batch item {index} must be a {arity}-item tuple"
            )
        key = tuple(row[position] for position in key_indexes)
        prior = unique.get(key)
        if prior is not None and prior != row:
            raise ValueError(f"{label} batch contains a conflicting duplicate key")
        unique.setdefault(key, row)
    return tuple(unique.values())


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
    account_id: str,
    repo_id: str,
    server_definition_id: str,
    protocol: str,
    ttl_seconds: int,
) -> list[sqlite3.Row]:
    rows = list(
        connection.execute(
            """
            SELECT start_port, end_port, max_ttl_seconds
            FROM broker_port_policies policy
            JOIN broker_acl_principals principal ON principal.uid = policy.uid
            WHERE principal.account_id = ? AND principal.enabled = 1
              AND policy.repo_id = ? AND policy.server_definition_id = ?
              AND policy.protocol = ? AND policy.enabled = 1
              AND policy.max_ttl_seconds >= ?
            ORDER BY start_port, end_port
            """,
            (account_id, repo_id, server_definition_id, protocol, ttl_seconds),
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
        and request.arguments["action"] in {"start", "stop", "restart"}
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
    account_id: str,
    repo_id: str,
    server_definition_id: str,
    port: int,
    operation_id: Optional[str],
) -> None:
    permitted = connection.execute(
        """
        SELECT 1
        FROM broker_port_policies policy
        JOIN broker_acl_principals principal ON principal.uid = policy.uid
        WHERE principal.account_id = ? AND principal.enabled = 1
          AND policy.repo_id = ? AND policy.server_definition_id = ?
          AND policy.protocol = 'tcp' AND policy.enabled = 1
          AND policy.start_port <= ? AND policy.end_port >= ?
        LIMIT 1
        """,
        (account_id, repo_id, server_definition_id, port, port),
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
    connection.execute(
        f"""
        UPDATE broker_compose_acl
        SET enabled = 0, updated_at = ?
        WHERE compose_definition_id IN ({placeholders}) AND enabled = 1
        """,
        (now, *definition_ids),
    )
    connection.execute(
        f"""
        UPDATE broker_compose_run_once_acl
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
    connection.execute(
        f"""
        UPDATE broker_compose_run_once_acl
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
    connection.execute(
        f"""
        UPDATE broker_compose_run_once_acl
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
                "Persisted Compose run-once policy is invalid; rerun Coordinator enrollment.",
                operation_id=operation_id,
            ) from exc
        if (
            int(row["ordinal"]) != expected_ordinal
            or str(row["policy_fingerprint"]) != policy.fingerprint
        ):
            raise BrokerError(
                "compose_run_once_policy_invalid",
                "Persisted Compose run-once policy fingerprint is invalid; rerun Coordinator enrollment.",
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
    for field in ("plan_id", "run_id"):
        value = decoded.get(field)
        if not isinstance(value, str):
            continue
        try:
            canonical = str(uuid.UUID(value))
        except (ValueError, AttributeError):
            continue
        if value == canonical:
            correlations[field] = canonical
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
