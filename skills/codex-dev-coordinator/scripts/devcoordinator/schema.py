"""SQLite schema and invariant contract for the normalized coordinator store."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3
from typing import Iterable


SCHEMA_VERSION = 14
MINIMUM_MIGRATABLE_SCHEMA_VERSION = 1
INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60
INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS = 72 * 60 * 60


_SHA256_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")


DDL = r"""
CREATE TABLE IF NOT EXISTS schema_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    database_generation TEXT NOT NULL UNIQUE,
    state_revision INTEGER NOT NULL DEFAULT 0 CHECK (state_revision >= 0),
    observation_revision INTEGER NOT NULL DEFAULT 0 CHECK (observation_revision >= 0),
    authority_mode TEXT NOT NULL DEFAULT 'shadow'
        CHECK (authority_mode IN ('shadow', 'legacy', 'sqlite')),
    migration_state TEXT NOT NULL DEFAULT 'empty'
        CHECK (migration_state IN ('empty', 'importing', 'ready', 'conflicted', 'retired')),
    first_sqlite_mutation_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    machine_fingerprint TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    hostname TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS coordinator_sources (
    source_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    canonical_home TEXT NOT NULL,
    state_path TEXT NOT NULL,
    effective_uid INTEGER NOT NULL CHECK (effective_uid >= 0),
    status TEXT NOT NULL CHECK (status IN ('discovered', 'imported', 'retired', 'conflict')),
    captured_revision INTEGER CHECK (captured_revision IS NULL OR captured_revision >= 0),
    captured_sha256 TEXT,
    imported_at TEXT,
    retired_at TEXT,
    late_writer_detected_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host_id, canonical_home)
);

CREATE TABLE IF NOT EXISTS repositories (
    repo_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    canonical_root TEXT NOT NULL,
    display_name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'missing', 'relocated')),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host_id, canonical_root)
);

CREATE TABLE IF NOT EXISTS repository_aliases (
    alias_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    canonical_alias TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('nested', 'symlink', 'relocated', 'legacy')),
    created_at TEXT NOT NULL,
    UNIQUE(host_id, canonical_alias)
);

-- A repository remains one canonical Git worktree/project. Families provide
-- the separate, durable relationship between the primary checkout and linked
-- temporary worktrees without collapsing either project identity.
CREATE TABLE IF NOT EXISTS repository_families (
    family_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    root_repo_id TEXT NOT NULL UNIQUE REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    git_common_dir TEXT,
    identity_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS repository_scopes (
    repo_id TEXT PRIMARY KEY REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    family_id TEXT NOT NULL REFERENCES repository_families(family_id) ON DELETE RESTRICT,
    project_kind TEXT NOT NULL CHECK (project_kind IN ('primary', 'temporary')),
    git_dir TEXT,
    git_common_dir TEXT,
    identity_fingerprint TEXT,
    root_device INTEGER CHECK (root_device IS NULL OR root_device >= 0),
    root_inode INTEGER CHECK (root_inode IS NULL OR root_inode > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS one_primary_scope_per_repository_family
ON repository_scopes(family_id)
WHERE project_kind = 'primary';

-- New repositories start as deterministic singleton families. A later API
-- request may move a proved linked worktree into its primary family.
CREATE TRIGGER IF NOT EXISTS repository_default_family
AFTER INSERT ON repositories
BEGIN
    INSERT OR IGNORE INTO repository_families(
        family_id, host_id, root_repo_id, git_common_dir,
        identity_fingerprint, created_at, updated_at
    ) VALUES (
        NEW.repo_id, NEW.host_id, NEW.repo_id, NULL, NULL,
        NEW.created_at, NEW.updated_at
    );
    INSERT OR IGNORE INTO repository_scopes(
        repo_id, family_id, project_kind, git_dir, git_common_dir,
        identity_fingerprint, created_at, updated_at
    ) VALUES (
        NEW.repo_id, NEW.repo_id, 'primary', NULL, NULL, NULL,
        NEW.created_at, NEW.updated_at
    );
END;

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('planned', 'running', 'succeeded', 'failed', 'partial', 'needs_attention', 'cancelled')),
    phase TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    request_fingerprint TEXT NOT NULL,
    owner_uid INTEGER CHECK (owner_uid IS NULL OR owner_uid >= 0),
    actor TEXT NOT NULL,
    process_fingerprint TEXT,
    error_code TEXT,
    error_message TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_sessions (
    session_id TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES repository_families(family_id) ON DELETE RESTRICT,
    root_repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (action IN ('status', 'start', 'stop', 'restart', 'replace', 'run')),
    purpose TEXT NOT NULL CHECK (purpose IN ('development', 'test', 'temporary')),
    ttl_seconds INTEGER CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
    expires_at TEXT,
    kill_after_run INTEGER NOT NULL CHECK (kill_after_run IN (0, 1)),
    status TEXT NOT NULL CHECK (
        status IN ('planned', 'running', 'succeeded', 'failed', 'cleanup_pending', 'cleaning', 'cleaned', 'expired')
    ),
    actor TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json TEXT,
    cleanup_error_json TEXT,
    cleanup_claim_id TEXT,
    cleanup_started_at TEXT,
    cleanup_owner_pid INTEGER CHECK (
        cleanup_owner_pid IS NULL OR cleanup_owner_pid > 1
    ),
    cleanup_owner_identity TEXT,
    execution_owner_pid INTEGER CHECK (
        execution_owner_pid IS NULL OR execution_owner_pid > 1
    ),
    execution_owner_identity TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    cleaned_at TEXT,
    updated_at TEXT NOT NULL,
    CHECK (
        (purpose IN ('test', 'temporary') AND ttl_seconds IS NOT NULL AND expires_at IS NOT NULL)
        OR (purpose = 'development')
    )
);

CREATE INDEX IF NOT EXISTS runtime_sessions_by_expiry
ON runtime_sessions(status, expires_at);

CREATE TABLE IF NOT EXISTS runtime_session_resources (
    session_id TEXT NOT NULL REFERENCES runtime_sessions(session_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('service', 'docker', 'database_stack')),
    resource_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    identity_json TEXT,
    cleanup_disposition TEXT NOT NULL DEFAULT 'retained'
        CHECK (cleanup_disposition IN ('removed', 'retained')),
    cleanup_state TEXT NOT NULL CHECK (
        cleanup_state IN ('active', 'cleanup_pending', 'cleaning', 'removed', 'retained', 'failed')
    ),
    cleanup_error_json TEXT,
    linked_at TEXT NOT NULL,
    cleaned_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(session_id, resource_kind, resource_id)
);

CREATE INDEX IF NOT EXISTS runtime_session_resources_by_resource
ON runtime_session_resources(resource_kind, resource_id, linked_at);

CREATE TABLE IF NOT EXISTS repository_installations (
    repo_id TEXT PRIMARY KEY REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('installed', 'disabling', 'disabled')),
    startup_fenced INTEGER NOT NULL DEFAULT 0 CHECK (startup_fenced IN (0, 1)),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    disabled_at TEXT,
    reinstalled_at TEXT,
    reason TEXT,
    actor TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (status != 'disabled' OR startup_fenced = 1)
);

CREATE TABLE IF NOT EXISTS source_resources (
    source_resource_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL,
    native_id TEXT NOT NULL,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE SET NULL,
    payload_sha256 TEXT NOT NULL,
    provenance_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(source_id, resource_kind, native_id)
);

CREATE TABLE IF NOT EXISTS control_bindings (
    binding_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    source_resource_id TEXT REFERENCES source_resources(source_resource_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    source_id TEXT NOT NULL REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    capability TEXT NOT NULL,
    provenance TEXT NOT NULL,
    authority_state TEXT NOT NULL
        CHECK (authority_state IN ('candidate', 'authoritative', 'conflicting', 'retired')),
    priority INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS one_authoritative_control_binding
ON control_bindings(resource_kind, resource_id)
WHERE authority_state = 'authoritative';

CREATE TABLE IF NOT EXISTS server_definitions (
    server_definition_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    role TEXT,
    cwd TEXT NOT NULL,
    health_url_template TEXT,
    log_path TEXT,
    definition_fingerprint TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, name)
);

CREATE TABLE IF NOT EXISTS server_command_arguments (
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    argument TEXT NOT NULL,
    PRIMARY KEY(server_definition_id, ordinal)
);

CREATE TABLE IF NOT EXISTS server_environment (
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(server_definition_id, name)
);

CREATE TABLE IF NOT EXISTS server_source_records (
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    source_resource_id TEXT NOT NULL REFERENCES source_resources(source_resource_id) ON DELETE RESTRICT,
    definition_fingerprint TEXT NOT NULL,
    is_exact_duplicate INTEGER NOT NULL CHECK (is_exact_duplicate IN (0, 1)),
    PRIMARY KEY(server_definition_id, source_resource_id)
);

CREATE TABLE IF NOT EXISTS server_observations (
    server_definition_id TEXT PRIMARY KEY REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    source_resource_id TEXT REFERENCES source_resources(source_resource_id) ON DELETE SET NULL,
    lifecycle TEXT NOT NULL,
    pid INTEGER CHECK (pid IS NULL OR pid > 0),
    process_start_time TEXT,
    process_fingerprint TEXT,
    listener_host TEXT,
    listener_port INTEGER CHECK (listener_port IS NULL OR listener_port BETWEEN 1 AND 65535),
    listener_observable INTEGER CHECK (listener_observable IN (0, 1) OR listener_observable IS NULL),
    health_classification TEXT,
    health_ok INTEGER CHECK (health_ok IN (0, 1) OR health_ok IS NULL),
    stopped_at TEXT,
    stopped_reason TEXT,
    sampled_at TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL
);

-- Broker-authoritative worker supervision.  Policy and live supervisor state
-- follow the current server definition, while finalized attempts deliberately
-- retain the immutable server identity as text so purge cannot erase crash
-- evidence.
CREATE TABLE IF NOT EXISTS worker_policies (
    server_definition_id TEXT PRIMARY KEY
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    execution_uid INTEGER NOT NULL CHECK (execution_uid >= 0),
    keep_alive INTEGER NOT NULL DEFAULT 0 CHECK (keep_alive IN (0, 1)),
    desired_state TEXT NOT NULL DEFAULT 'stopped'
        CHECK (desired_state IN ('running', 'stopped')),
    breaker_state TEXT NOT NULL DEFAULT 'armed'
        CHECK (breaker_state IN ('armed', 'tripped')),
    crash_limit INTEGER NOT NULL DEFAULT 10
        CHECK (crash_limit BETWEEN 1 AND 1000),
    crash_window_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (crash_window_seconds BETWEEN 1 AND 86400),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    requested_by TEXT NOT NULL,
    request_operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    last_rearmed_at TEXT,
    last_rearmed_by TEXT,
    last_rearm_operation_id TEXT
        REFERENCES operations(operation_id) ON DELETE SET NULL,
    last_tripped_at TEXT,
    last_trip_reason TEXT,
    last_trip_attempt_id TEXT,
    last_trip_event_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (last_rearmed_at IS NULL AND last_rearmed_by IS NULL
            AND last_rearm_operation_id IS NULL)
        OR (last_rearmed_at IS NOT NULL AND last_rearmed_by IS NOT NULL)
    ),
    CHECK (
        (last_tripped_at IS NULL AND last_trip_reason IS NULL
            AND last_trip_attempt_id IS NULL AND last_trip_event_id IS NULL)
        OR (last_tripped_at IS NOT NULL AND last_trip_reason IS NOT NULL
            AND last_trip_attempt_id IS NOT NULL AND last_trip_event_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS worker_attempts (
    attempt_id TEXT PRIMARY KEY,
    begin_request_id TEXT NOT NULL UNIQUE,
    server_definition_id TEXT NOT NULL,
    repo_id TEXT NOT NULL,
    definition_generation INTEGER NOT NULL CHECK (definition_generation >= 0),
    policy_generation INTEGER NOT NULL CHECK (policy_generation >= 0),
    supervisor_generation INTEGER NOT NULL CHECK (supervisor_generation >= 0),
    supervisor_epoch TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'running', 'exited')),
    launch_report_id TEXT UNIQUE,
    exit_report_id TEXT UNIQUE,
    pid INTEGER CHECK (pid IS NULL OR pid > 1),
    process_start_time TEXT,
    process_fingerprint TEXT,
    reserved_at TEXT NOT NULL,
    launched_at TEXT,
    exited_at TEXT,
    exited_at_epoch REAL CHECK (exited_at_epoch IS NULL OR exited_at_epoch >= 0),
    exit_kind TEXT CHECK (
        exit_kind IS NULL OR exit_kind IN (
            'exit_code', 'signal', 'launch_failure', 'supervisor_lost', 'unknown'
        )
    ),
    exit_code INTEGER,
    exit_signal INTEGER CHECK (exit_signal IS NULL OR exit_signal > 0),
    exit_classification TEXT CHECK (
        exit_classification IS NULL OR exit_classification IN (
            'intentional', 'crash', 'stale_generation', 'fenced'
        )
    ),
    expected_exit INTEGER CHECK (expected_exit IN (0, 1) OR expected_exit IS NULL),
    counts_toward_breaker INTEGER
        CHECK (counts_toward_breaker IN (0, 1) OR counts_toward_breaker IS NULL),
    crash_event_id TEXT REFERENCES events(event_id) ON DELETE RESTRICT,
    log_artifact_id TEXT,
    log_artifact_path TEXT,
    log_artifact_sha256 TEXT,
    exit_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (state = 'reserved'
            AND launch_report_id IS NULL AND pid IS NULL
            AND process_start_time IS NULL AND process_fingerprint IS NULL
            AND launched_at IS NULL AND exit_report_id IS NULL
            AND exited_at IS NULL AND exited_at_epoch IS NULL AND exit_kind IS NULL
            AND exit_code IS NULL AND exit_signal IS NULL
            AND exit_classification IS NULL AND expected_exit IS NULL
            AND counts_toward_breaker IS NULL AND crash_event_id IS NULL
            AND exit_fingerprint IS NULL)
        OR (state = 'running'
            AND launch_report_id IS NOT NULL AND pid IS NOT NULL
            AND process_start_time IS NOT NULL AND process_fingerprint IS NOT NULL
            AND launched_at IS NOT NULL AND exit_report_id IS NULL
            AND exited_at IS NULL AND exited_at_epoch IS NULL AND exit_kind IS NULL
            AND exit_code IS NULL AND exit_signal IS NULL
            AND exit_classification IS NULL AND expected_exit IS NULL
            AND counts_toward_breaker IS NULL AND crash_event_id IS NULL
            AND exit_fingerprint IS NULL)
        OR (state = 'exited'
            AND exit_report_id IS NOT NULL AND exited_at IS NOT NULL
            AND exited_at_epoch IS NOT NULL
            AND exit_kind IS NOT NULL AND exit_classification IS NOT NULL
            AND expected_exit IS NOT NULL AND counts_toward_breaker IS NOT NULL
            AND exit_fingerprint IS NOT NULL
            AND ((launch_report_id IS NOT NULL AND pid IS NOT NULL
                    AND process_start_time IS NOT NULL
                    AND process_fingerprint IS NOT NULL
                    AND launched_at IS NOT NULL)
                OR (exit_kind = 'launch_failure'
                    AND launch_report_id IS NULL AND pid IS NULL
                    AND process_start_time IS NULL
                    AND process_fingerprint IS NULL AND launched_at IS NULL)))
    ),
    CHECK (
        (exit_kind = 'exit_code' AND exit_code IS NOT NULL AND exit_signal IS NULL)
        OR (exit_kind = 'signal' AND exit_code IS NULL AND exit_signal IS NOT NULL)
        OR (exit_kind IS NULL AND exit_code IS NULL AND exit_signal IS NULL)
        OR (exit_kind IN ('launch_failure', 'supervisor_lost', 'unknown')
            AND exit_code IS NULL AND exit_signal IS NULL)
    ),
    CHECK (
        (log_artifact_id IS NULL AND log_artifact_path IS NULL
            AND log_artifact_sha256 IS NULL)
        OR (log_artifact_id IS NOT NULL AND log_artifact_path IS NOT NULL
            AND log_artifact_sha256 IS NOT NULL)
    ),
    CHECK (counts_toward_breaker != 1 OR crash_event_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_worker_attempt
ON worker_attempts(server_definition_id)
WHERE state IN ('reserved', 'running');

CREATE INDEX IF NOT EXISTS worker_attempts_crash_window
ON worker_attempts(
    server_definition_id, policy_generation, counts_toward_breaker, exited_at_epoch
);

CREATE UNIQUE INDEX IF NOT EXISTS one_worker_attempt_per_log_artifact
ON worker_attempts(log_artifact_id)
WHERE log_artifact_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS finalized_worker_attempt_is_immutable
BEFORE UPDATE ON worker_attempts
WHEN OLD.state = 'exited'
BEGIN
    SELECT RAISE(ABORT, 'finalized worker attempt is immutable');
END;

-- The acknowledgement returned to a runner must survive a lost response and
-- must not be recomputed from policy that may later be re-armed or changed.
-- Deliberately omit live-resource foreign keys so removal retains the exact
-- historical restart decision with the attempt evidence.
CREATE TABLE IF NOT EXISTS worker_exit_decisions (
    attempt_id TEXT PRIMARY KEY,
    server_definition_id TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK (policy_generation >= 0),
    crash_limit INTEGER CHECK (crash_limit IS NULL OR crash_limit > 0),
    crash_window_seconds INTEGER
        CHECK (crash_window_seconds IS NULL OR crash_window_seconds > 0),
    crash_count_in_window INTEGER NOT NULL
        CHECK (crash_count_in_window >= 0),
    breaker_tripped_now INTEGER NOT NULL
        CHECK (breaker_tripped_now IN (0, 1)),
    restart_allowed INTEGER NOT NULL CHECK (restart_allowed IN (0, 1)),
    decided_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS worker_exit_decisions_by_server
ON worker_exit_decisions(server_definition_id, policy_generation);

CREATE TRIGGER IF NOT EXISTS worker_exit_decision_is_immutable
BEFORE UPDATE ON worker_exit_decisions
BEGIN
    SELECT RAISE(ABORT, 'worker exit decision is immutable');
END;

CREATE TABLE IF NOT EXISTS worker_supervisor_states (
    server_definition_id TEXT PRIMARY KEY
        REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (
        state IN (
            'stopped', 'idle', 'launching', 'running', 'stopping',
            'backoff', 'tripped', 'fenced'
        )
    ),
    supervisor_epoch TEXT,
    supervisor_generation INTEGER NOT NULL DEFAULT 0
        CHECK (supervisor_generation >= 0),
    current_attempt_id TEXT
        REFERENCES worker_attempts(attempt_id) ON DELETE SET NULL,
    last_attempt_id TEXT,
    next_restart_at TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    updated_at TEXT NOT NULL,
    CHECK (
        (state IN ('launching', 'running', 'stopping')
            AND current_attempt_id IS NOT NULL)
        OR (state NOT IN ('launching', 'running', 'stopping') AND state != 'fenced'
            AND current_attempt_id IS NULL)
        OR (state = 'fenced')
    )
);

CREATE TABLE IF NOT EXISTS port_assignments (
    assignment_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_name TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    deactivated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, server_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS active_host_port_assignment
ON port_assignments(host_id, port)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT REFERENCES server_definitions(server_definition_id) ON DELETE SET NULL,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE SET NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    owner TEXT,
    agent TEXT,
    purpose TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'released', 'stale')),
    expires_at TEXT,
    process_fingerprint TEXT,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    deactivated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS active_host_port_lease
ON leases(host_id, port)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS broker_lease_links (
    link_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE RESTRICT,
    broker_lease_id TEXT NOT NULL UNIQUE,
    local_lease_id TEXT UNIQUE,
    account_id TEXT NOT NULL,
    broker_socket TEXT NOT NULL,
    broker_service_uid INTEGER NOT NULL CHECK (broker_service_uid >= 0),
    broker_socket_gid INTEGER NOT NULL CHECK (broker_socket_gid >= 0),
    broker_socket_mode INTEGER NOT NULL CHECK (broker_socket_mode = 432),
    broker_database_generation TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    status TEXT NOT NULL CHECK (status IN (
        'reserved', 'active', 'release_pending', 'released',
        'rollback_failed', 'reconciliation_required'
    )),
    broker_operation_id TEXT NOT NULL,
    release_operation_id TEXT,
    expires_at TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS active_broker_lease_by_server
ON broker_lease_links(repo_id, server_definition_id)
WHERE status IN ('reserved', 'active', 'release_pending', 'rollback_failed', 'reconciliation_required');

CREATE TABLE IF NOT EXISTS broker_assignment_links (
    link_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE RESTRICT,
    broker_assignment_id TEXT NOT NULL UNIQUE,
    local_assignment_id TEXT UNIQUE,
    account_id TEXT NOT NULL,
    broker_socket TEXT NOT NULL,
    broker_service_uid INTEGER NOT NULL CHECK (broker_service_uid >= 0),
    broker_socket_gid INTEGER NOT NULL CHECK (broker_socket_gid >= 0),
    broker_socket_mode INTEGER NOT NULL CHECK (broker_socket_mode = 432),
    broker_database_generation TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    status TEXT NOT NULL CHECK (status IN (
        'reserved', 'active', 'release_pending', 'released',
        'rollback_failed', 'reconciliation_required'
    )),
    broker_operation_id TEXT NOT NULL,
    release_operation_id TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, server_definition_id)
);

CREATE TABLE IF NOT EXISTS broker_reconciliation_queue (
    reconciliation_id TEXT PRIMARY KEY,
    link_kind TEXT NOT NULL CHECK (link_kind IN ('lease', 'assignment', 'docker', 'compose')),
    link_id TEXT,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'resolved', 'operator_required')),
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS pending_broker_reconciliation
ON broker_reconciliation_queue(link_kind, link_id, requested_action)
WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS broker_lifecycle_links (
    link_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'repository.remove', 'repository.reinstall',
        'resource.attach', 'resource.retire'
    )),
    broker_operation_id TEXT NOT NULL UNIQUE,
    broker_plan_id TEXT,
    account_id TEXT NOT NULL,
    broker_socket TEXT NOT NULL,
    broker_service_uid INTEGER NOT NULL CHECK (broker_service_uid >= 0),
    broker_socket_gid INTEGER NOT NULL CHECK (broker_socket_gid >= 0),
    broker_socket_mode INTEGER NOT NULL CHECK (broker_socket_mode = 432),
    broker_database_generation TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'pending', 'applied', 'reconciliation_required', 'operator_required'
    )),
    last_error_code TEXT,
    last_error_message TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applied_at TEXT
);

CREATE INDEX IF NOT EXISTS pending_broker_lifecycle_reconciliation
ON broker_lifecycle_links(status, created_at)
WHERE status IN ('pending', 'reconciliation_required');

-- An account journal may outlive the protected broker profile object that
-- produced one of its link records.  Permanent service removal mirrors an
-- exact-ID fence here before deleting the local active projection, so a stale
-- in-memory profile can never materialize that incarnation again.  A later
-- explicit reinstall has a different server_definition_id and is unaffected.
CREATE TABLE IF NOT EXISTS broker_server_materialization_revocations (
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    server_definition_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    broker_operation_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    broker_database_generation TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY(repo_id, server_definition_id)
);

CREATE INDEX IF NOT EXISTS broker_server_materialization_revocations_by_name
ON broker_server_materialization_revocations(repo_id, server_name, revoked_at);

-- A repository ID names one canonical worktree across lifecycle generations.
-- Permanent project cleanup fences the exact removed generation so a stale
-- protected profile cannot recreate its account-side project or children.
-- Explicit reinstall advances the repository generation and is unaffected.
CREATE TABLE IF NOT EXISTS broker_repository_materialization_revocations (
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    repository_generation INTEGER NOT NULL CHECK(repository_generation >= 0),
    broker_operation_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    broker_database_generation TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY(repo_id, repository_generation)
);

CREATE TABLE IF NOT EXISTS operation_targets (
    operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    action TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'skipped')),
    result_json TEXT,
    error_json TEXT,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY(operation_id, ordinal),
    UNIQUE(operation_id, target_kind, target_id)
);

CREATE TABLE IF NOT EXISTS operation_target_parameters (
    operation_id TEXT NOT NULL,
    target_ordinal INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    value_type TEXT NOT NULL CHECK (value_type IN ('text', 'integer', 'boolean', 'null')),
    PRIMARY KEY(operation_id, target_ordinal, name),
    FOREIGN KEY(operation_id, target_ordinal)
        REFERENCES operation_targets(operation_id, ordinal) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operation_target_dependencies (
    operation_id TEXT NOT NULL,
    target_ordinal INTEGER NOT NULL,
    depends_on_ordinal INTEGER NOT NULL,
    PRIMARY KEY(operation_id, target_ordinal, depends_on_ordinal),
    FOREIGN KEY(operation_id, target_ordinal)
        REFERENCES operation_targets(operation_id, ordinal) ON DELETE CASCADE,
    FOREIGN KEY(operation_id, depends_on_ordinal)
        REFERENCES operation_targets(operation_id, ordinal) ON DELETE CASCADE,
    CHECK (target_ordinal != depends_on_ordinal)
);

CREATE TABLE IF NOT EXISTS startup_policies (
    policy_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    policy_kind TEXT NOT NULL
        CHECK (policy_kind IN ('docker_restart', 'compose', 'supervisor', 'coordinator')),
    current_value TEXT NOT NULL,
    desired_disabled_value TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at TEXT NOT NULL,
    UNIQUE(resource_kind, resource_id, policy_kind)
);

CREATE TABLE IF NOT EXISTS startup_policy_restore_states (
    policy_id TEXT PRIMARY KEY REFERENCES startup_policies(policy_id) ON DELETE CASCADE,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    policy_kind TEXT NOT NULL
        CHECK (policy_kind IN ('docker_restart', 'compose', 'supervisor', 'coordinator')),
    policy_immutable_fingerprint TEXT NOT NULL,
    target_immutable_fingerprint TEXT NOT NULL,
    control_binding_id TEXT NOT NULL REFERENCES control_bindings(binding_id) ON DELETE RESTRICT,
    ownership_fingerprint TEXT NOT NULL,
    native_identity_fingerprint TEXT NOT NULL,
    captured_value TEXT NOT NULL,
    restore_required INTEGER NOT NULL CHECK (restore_required IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('captured', 'restored', 'not_required')),
    docker_restart_policy TEXT,
    supervisor_manager TEXT CHECK (
        supervisor_manager IS NULL OR supervisor_manager IN ('systemd', 'launchd')
    ),
    supervisor_unit_file_state TEXT,
    supervisor_loaded INTEGER CHECK (supervisor_loaded IN (0, 1) OR supervisor_loaded IS NULL),
    supervisor_enabled INTEGER CHECK (supervisor_enabled IN (0, 1) OR supervisor_enabled IS NULL),
    captured_operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE RESTRICT,
    last_restore_permit_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    capture_generation INTEGER NOT NULL DEFAULT 0 CHECK (capture_generation >= 0),
    captured_at TEXT NOT NULL,
    restored_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, resource_kind, resource_id, policy_kind),
    CHECK (
        (policy_kind = 'docker_restart' AND docker_restart_policy IS NOT NULL
            AND supervisor_manager IS NULL)
        OR (policy_kind = 'supervisor' AND docker_restart_policy IS NULL
            AND supervisor_manager IS NOT NULL
            AND supervisor_unit_file_state IS NOT NULL
            AND supervisor_loaded IS NOT NULL
            AND supervisor_enabled IS NOT NULL)
        OR (policy_kind IN ('compose', 'coordinator')
            AND docker_restart_policy IS NULL AND supervisor_manager IS NULL)
    ),
    CHECK (
        (restore_required = 1 AND status IN ('captured', 'restored'))
        OR (restore_required = 0 AND status = 'not_required')
    )
);

CREATE TABLE IF NOT EXISTS repository_memberships (
    membership_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('server', 'container', 'supervisor')),
    host_resource_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    control_binding_id TEXT REFERENCES control_bindings(binding_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    UNIQUE(repo_id, resource_kind, host_resource_id),
    UNIQUE(resource_kind, host_resource_id)
);

CREATE TABLE IF NOT EXISTS resource_retirements (
    host_resource_id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('disabling', 'retired')),
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    started_at TEXT NOT NULL,
    retired_at TEXT,
    updated_at TEXT NOT NULL
);

-- Schema v3 separates reversible archive state from permanent cleanup
-- evidence.  Existing resource_retirements rows are the active archive fence
-- for backwards compatibility; these tables retain every archive/restore and
-- purge decision without making old rows writable history.
CREATE TABLE IF NOT EXISTS resource_lifecycle_history (
    history_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server', 'container', 'supervisor')),
    resource_id TEXT NOT NULL,
    immutable_fingerprint TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('archived', 'restored', 'purged')),
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS resource_lifecycle_history_by_resource
ON resource_lifecycle_history(resource_kind, resource_id, occurred_at);

CREATE TABLE IF NOT EXISTS cleanup_plans (
    plan_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL CHECK(target_kind IN ('project', 'server', 'container', 'worktree')),
    target_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('purge', 'forget')),
    target_fingerprint TEXT NOT NULL,
    plan_fingerprint TEXT NOT NULL,
    confirmation_phrase TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planned', 'running', 'needs_attention', 'succeeded')),
    phase TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_kind, target_id, plan_fingerprint)
);

CREATE TABLE IF NOT EXISTS cleanup_phase_evidence (
    plan_id TEXT NOT NULL REFERENCES cleanup_plans(plan_id) ON DELETE CASCADE,
    phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'failed')),
    evidence_json TEXT,
    error_json TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY(plan_id, phase)
);

CREATE TABLE IF NOT EXISTS cleanup_tombstones (
    target_kind TEXT NOT NULL CHECK(target_kind IN ('project', 'server', 'container', 'worktree')),
    target_id TEXT NOT NULL,
    target_generation INTEGER NOT NULL DEFAULT 0 CHECK(target_generation >= 0),
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    immutable_fingerprint TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    removed_at TEXT NOT NULL,
    PRIMARY KEY(target_kind, target_id, target_generation)
);

CREATE TABLE IF NOT EXISTS worktree_cleanup_identities (
    repo_id TEXT PRIMARY KEY REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    canonical_root TEXT NOT NULL,
    git_dir TEXT NOT NULL,
    common_dir TEXT NOT NULL,
    primary_root TEXT NOT NULL,
    root_device INTEGER NOT NULL,
    root_inode INTEGER NOT NULL,
    marker_device INTEGER NOT NULL,
    marker_inode INTEGER NOT NULL,
    head_oid TEXT,
    identity_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planned', 'removed')),
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS docker_engines (
    engine_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    context_identity TEXT NOT NULL,
    daemon_identity TEXT,
    socket_identity TEXT,
    capability_state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host_id, context_identity)
);

CREATE TABLE IF NOT EXISTS docker_resources (
    docker_resource_id TEXT PRIMARY KEY,
    engine_id TEXT NOT NULL REFERENCES docker_engines(engine_id) ON DELETE RESTRICT,
    full_container_id TEXT NOT NULL,
    current_name TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(engine_id, full_container_id)
);

CREATE TABLE IF NOT EXISTS docker_observations (
    docker_resource_id TEXT PRIMARY KEY REFERENCES docker_resources(docker_resource_id) ON DELETE CASCADE,
    lifecycle TEXT NOT NULL,
    health TEXT,
    restart_policy TEXT,
    ports_fingerprint TEXT,
    labels_fingerprint TEXT,
    sampled_at TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS docker_ports (
    docker_resource_id TEXT NOT NULL REFERENCES docker_resources(docker_resource_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    host_address TEXT,
    host_port INTEGER CHECK (host_port IS NULL OR host_port BETWEEN 1 AND 65535),
    container_port INTEGER NOT NULL CHECK (container_port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL,
    PRIMARY KEY(docker_resource_id, ordinal)
);

CREATE TABLE IF NOT EXISTS docker_labels (
    docker_resource_id TEXT NOT NULL REFERENCES docker_resources(docker_resource_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(docker_resource_id, name)
);

CREATE TABLE IF NOT EXISTS docker_ownership_claims (
    claim_id TEXT PRIMARY KEY,
    docker_resource_id TEXT REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
    source_resource_id TEXT REFERENCES source_resources(source_resource_id) ON DELETE RESTRICT,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    source_id TEXT NOT NULL REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    provenance TEXT NOT NULL CHECK (provenance IN ('compose', 'sidecar', 'operator', 'legacy')),
    priority INTEGER NOT NULL DEFAULT 0,
    conflict_state TEXT NOT NULL CHECK (conflict_state IN ('clear', 'conflicting', 'retired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ephemeral_container_templates (
    template_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    image_ref TEXT NOT NULL,
    secret_policy_kind TEXT CHECK(secret_policy_kind IS NULL OR secret_policy_kind IN (
        'postgres_initdb_password_file_v1'
    )),
    secret_binding_id TEXT,
    definition_fingerprint TEXT NOT NULL,
    default_ttl_seconds INTEGER NOT NULL
        CHECK(default_ttl_seconds BETWEEN 60 AND 604800),
    max_ttl_seconds INTEGER NOT NULL
        CHECK(max_ttl_seconds BETWEEN default_ttl_seconds AND 604800),
    container_tcp_port INTEGER
        CHECK(container_tcp_port IS NULL OR container_tcp_port BETWEEN 1 AND 65535),
    host_port_start INTEGER
        CHECK(host_port_start IS NULL OR host_port_start BETWEEN 1 AND 65535),
    host_port_end INTEGER
        CHECK(host_port_end IS NULL OR host_port_end BETWEEN 1 AND 65535),
    memory_bytes INTEGER CHECK(memory_bytes IS NULL OR memory_bytes >= 16777216),
    cpu_millis INTEGER CHECK(cpu_millis IS NULL OR cpu_millis BETWEEN 10 AND 256000),
    max_concurrent_runs INTEGER NOT NULL
        CHECK(max_concurrent_runs BETWEEN 1 AND 32),
    max_concurrent_runs_per_uid INTEGER NOT NULL
        CHECK(max_concurrent_runs_per_uid BETWEEN 1 AND max_concurrent_runs),
    repo_max_active_runs INTEGER NOT NULL
        CHECK(repo_max_active_runs BETWEEN max_concurrent_runs AND 64),
    repo_memory_budget_bytes INTEGER NOT NULL
        CHECK(repo_memory_budget_bytes BETWEEN 16777216 AND 72057594037927936),
    repo_cpu_budget_millis INTEGER NOT NULL
        CHECK(repo_cpu_budget_millis BETWEEN 10 AND 16384000),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo_id, name),
    CHECK(
        (secret_policy_kind IS NULL AND secret_binding_id IS NULL)
        OR (secret_policy_kind IS NOT NULL AND secret_binding_id IS NOT NULL)
    ),
    CHECK(
        (container_tcp_port IS NULL AND host_port_start IS NULL AND host_port_end IS NULL)
        OR
        (container_tcp_port IS NOT NULL AND host_port_start IS NOT NULL
         AND host_port_end IS NOT NULL AND host_port_start <= host_port_end)
    )
);

CREATE TABLE IF NOT EXISTS ephemeral_template_arguments (
    template_id TEXT NOT NULL
        REFERENCES ephemeral_container_templates(template_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    argument TEXT NOT NULL,
    PRIMARY KEY(template_id, ordinal)
);

CREATE TABLE IF NOT EXISTS ephemeral_template_environment (
    template_id TEXT NOT NULL
        REFERENCES ephemeral_container_templates(template_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(template_id, name)
);

CREATE TABLE IF NOT EXISTS ephemeral_container_runs (
    run_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE RESTRICT,
    template_id TEXT NOT NULL
        REFERENCES ephemeral_container_templates(template_id) ON DELETE RESTRICT,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    owner_uid INTEGER NOT NULL CHECK(owner_uid >= 0),
    account_id TEXT NOT NULL,
    creation_nonce TEXT NOT NULL UNIQUE,
    container_name TEXT NOT NULL UNIQUE,
    full_container_id TEXT UNIQUE,
    docker_resource_id TEXT UNIQUE
        REFERENCES docker_resources(docker_resource_id) ON DELETE SET NULL,
    lease_id TEXT UNIQUE REFERENCES leases(lease_id) ON DELETE RESTRICT,
    host_port INTEGER CHECK(host_port IS NULL OR host_port BETWEEN 1 AND 65535),
    image_ref TEXT NOT NULL,
    secret_policy_kind TEXT CHECK(secret_policy_kind IS NULL OR secret_policy_kind IN (
        'postgres_initdb_password_file_v1'
    )),
    secret_binding_id TEXT,
    memory_bytes INTEGER CHECK(memory_bytes IS NULL OR memory_bytes >= 16777216),
    cpu_millis INTEGER CHECK(cpu_millis IS NULL OR cpu_millis BETWEEN 10 AND 256000),
    container_tcp_port INTEGER
        CHECK(container_tcp_port IS NULL OR container_tcp_port BETWEEN 1 AND 65535),
    host_port_start INTEGER
        CHECK(host_port_start IS NULL OR host_port_start BETWEEN 1 AND 65535),
    host_port_end INTEGER
        CHECK(host_port_end IS NULL OR host_port_end BETWEEN 1 AND 65535),
    template_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'reserved', 'creating', 'attributed', 'starting', 'running',
        'cleanup_pending', 'stopping', 'removing', 'cleaned',
        'failed', 'needs_attention'
    )),
    phase TEXT NOT NULL,
    max_ttl_seconds INTEGER NOT NULL
        CHECK(max_ttl_seconds BETWEEN 60 AND 604800),
    expires_at_epoch INTEGER NOT NULL CHECK(expires_at_epoch > 0),
    credential_renewal_phase TEXT NOT NULL DEFAULT 'none'
        CHECK(credential_renewal_phase IN ('none', 'prepared', 'committing')),
    credential_renewal_old_expires_at_epoch INTEGER,
    credential_renewal_new_expires_at_epoch INTEGER,
    credential_renewal_operation_id TEXT,
    next_reconcile_at_epoch INTEGER NOT NULL CHECK(next_reconcile_at_epoch >= 0),
    recovery_failures INTEGER NOT NULL DEFAULT 0 CHECK(recovery_failures >= 0),
    create_absence_since_epoch INTEGER
        CHECK(create_absence_since_epoch IS NULL OR create_absence_since_epoch >= 0),
    create_absence_observations INTEGER NOT NULL DEFAULT 0
        CHECK(create_absence_observations >= 0),
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    cleanup_requested INTEGER NOT NULL DEFAULT 0
        CHECK(cleanup_requested IN (0, 1)),
    cleanup_reason TEXT,
    error_code TEXT,
    error_message TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    CHECK(
        full_container_id IS NULL
        OR (length(full_container_id) = 64
            AND full_container_id NOT GLOB '*[^0-9a-f]*')
    ),
    CHECK(
        (secret_policy_kind IS NULL AND secret_binding_id IS NULL)
        OR (secret_policy_kind IS NOT NULL AND secret_binding_id IS NOT NULL)
    ),
    CHECK((lease_id IS NULL AND host_port IS NULL) OR (lease_id IS NOT NULL AND host_port IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS ephemeral_run_arguments (
    run_id TEXT NOT NULL
        REFERENCES ephemeral_container_runs(run_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    argument TEXT NOT NULL,
    PRIMARY KEY(run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS ephemeral_run_environment (
    run_id TEXT NOT NULL
        REFERENCES ephemeral_container_runs(run_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(run_id, name)
);

CREATE INDEX IF NOT EXISTS ephemeral_runs_for_recovery
ON ephemeral_container_runs(status, expires_at_epoch, updated_at);

CREATE INDEX IF NOT EXISTS ephemeral_runs_for_quota_admission
ON ephemeral_container_runs(repo_id, status, template_id, owner_uid);

CREATE TABLE IF NOT EXISTS ephemeral_run_phases (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL
        REFERENCES ephemeral_container_runs(run_id) ON DELETE CASCADE,
    phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'failed')),
    evidence_json TEXT,
    error_json TEXT,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ephemeral_run_phases_by_run
ON ephemeral_run_phases(run_id, sequence);

CREATE TABLE IF NOT EXISTS database_bindings (
    database_binding_id TEXT PRIMARY KEY,
    docker_resource_id TEXT NOT NULL REFERENCES docker_resources(docker_resource_id) ON DELETE RESTRICT,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    database_name TEXT NOT NULL,
    engine_kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(docker_resource_id, database_name)
);

CREATE TABLE IF NOT EXISTS database_observations (
    database_binding_id TEXT PRIMARY KEY
        REFERENCES database_bindings(database_binding_id) ON DELETE CASCADE,
    docker_resource_id TEXT NOT NULL
        REFERENCES docker_resources(docker_resource_id) ON DELETE CASCADE,
    available INTEGER NOT NULL CHECK (available IN (0, 1)),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    error_code TEXT,
    error_message TEXT,
    sampled_at TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL,
    CHECK (
        (available = 1 AND error_code IS NULL AND error_message IS NULL)
        OR available = 0
    )
);

CREATE TABLE IF NOT EXISTS database_backups (
    database_backup_id TEXT PRIMARY KEY,
    database_binding_id TEXT
        REFERENCES database_bindings(database_binding_id) ON DELETE SET NULL,
    docker_resource_id TEXT
        REFERENCES docker_resources(docker_resource_id) ON DELETE SET NULL,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE SET NULL,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE SET NULL,
    scope TEXT NOT NULL CHECK (scope IN ('database', 'cluster')),
    source_container_id TEXT NOT NULL,
    source_database_name TEXT,
    source_identity_fingerprint TEXT NOT NULL,
    artifact_path TEXT NOT NULL UNIQUE,
    artifact_size_bytes INTEGER NOT NULL CHECK (artifact_size_bytes > 0),
    artifact_sha256 TEXT NOT NULL,
    manifest_path TEXT NOT NULL UNIQUE,
    manifest_sha256 TEXT NOT NULL,
    backup_format TEXT NOT NULL CHECK (backup_format IN ('custom', 'plain', 'all')),
    verification_status TEXT NOT NULL
        CHECK (verification_status IN ('unverified', 'lightweight', 'strong')),
    verification_mode TEXT,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('available', 'missing', 'retired')),
    last_restored_at TEXT,
    restore_count INTEGER NOT NULL DEFAULT 0 CHECK (restore_count >= 0),
    updated_at TEXT NOT NULL,
    CHECK (
        (scope = 'database' AND source_database_name IS NOT NULL
            AND backup_format IN ('custom', 'plain'))
        OR (scope = 'cluster' AND source_database_name IS NULL
            AND backup_format = 'all')
    )
);

CREATE TABLE IF NOT EXISTS database_restore_events (
    restore_event_id TEXT PRIMARY KEY,
    database_backup_id TEXT NOT NULL
        REFERENCES database_backups(database_backup_id) ON DELETE RESTRICT,
    target_database_binding_id TEXT
        REFERENCES database_bindings(database_binding_id) ON DELETE SET NULL,
    target_docker_resource_id TEXT
        REFERENCES docker_resources(docker_resource_id) ON DELETE SET NULL,
    target_container_id TEXT NOT NULL,
    target_database_name TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    safety_database_backup_id TEXT
        REFERENCES database_backups(database_backup_id) ON DELETE SET NULL,
    result_fingerprint TEXT NOT NULL,
    restored_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observation_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    observer_domain TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    material_fingerprint TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS observation_capabilities (
    snapshot_id TEXT PRIMARY KEY
        REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    observer_domain TEXT NOT NULL,
    docker_available INTEGER NOT NULL CHECK(docker_available IN (0, 1)),
    capability_fingerprint TEXT NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observation_snapshot_resources (
    snapshot_id TEXT NOT NULL REFERENCES observation_snapshots(snapshot_id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    observation_fingerprint TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, resource_kind, resource_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS one_running_observer_per_domain
ON observation_snapshots(host_id, observer_domain)
WHERE status = 'running';

-- Remote infrastructure is a distinct, observation-only authority domain.
-- Its identities never overlap local process/container identities, and the
-- signed observer never receives a writable database handle.
CREATE TABLE IF NOT EXISTS infrastructure_cells (
    cell_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    region TEXT,
    classification_label TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS infrastructure_hosts (
    host_id TEXT PRIMARY KEY,
    cell_id TEXT NOT NULL
        REFERENCES infrastructure_cells(cell_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    failure_domain_label TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform = 'windows-hyperv'),
    scope_sha256 TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS infrastructure_hosts_by_cell
ON infrastructure_hosts(cell_id, host_id);

-- Every VM identity and role is centrally approved. The observer may report
-- only this immutable-ID scope and cannot gain authority by choosing a name or
-- role in its signed payload.
CREATE TABLE IF NOT EXISTS infrastructure_host_vm_scope (
    host_id TEXT NOT NULL
        REFERENCES infrastructure_hosts(host_id) ON DELETE CASCADE,
    vm_id TEXT NOT NULL,
    approved_role TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(host_id, vm_id)
);

CREATE TABLE IF NOT EXISTS infrastructure_observer_agents (
    agent_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL
        REFERENCES infrastructure_hosts(host_id) ON DELETE RESTRICT,
    assigned_scope_sha256 TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_contact_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS infrastructure_agents_by_host
ON infrastructure_observer_agents(host_id, agent_id);

CREATE TRIGGER IF NOT EXISTS infrastructure_agent_scope_insert_guard
BEFORE INSERT ON infrastructure_observer_agents
WHEN NOT EXISTS (
    SELECT 1 FROM infrastructure_hosts host
    WHERE host.host_id = NEW.host_id
      AND host.scope_sha256 = NEW.assigned_scope_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure agent scope does not match host');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_agent_scope_update_guard
BEFORE UPDATE ON infrastructure_observer_agents
WHEN NOT EXISTS (
    SELECT 1 FROM infrastructure_hosts host
    WHERE host.host_id = NEW.host_id
      AND host.scope_sha256 = NEW.assigned_scope_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure agent scope does not match host');
END;

CREATE TABLE IF NOT EXISTS infrastructure_agent_certificates (
    agent_id TEXT NOT NULL
        REFERENCES infrastructure_observer_agents(agent_id) ON DELETE CASCADE,
    certificate_generation INTEGER NOT NULL
        CHECK(certificate_generation >= 1),
    certificate_fingerprint_sha256 TEXT NOT NULL UNIQUE,
    jws_key_id TEXT NOT NULL,
    jws_algorithm TEXT NOT NULL CHECK(jws_algorithm = 'PS256'),
    jws_spki_der_base64 TEXT NOT NULL,
    jws_spki_sha256 TEXT NOT NULL UNIQUE,
    valid_from_epoch INTEGER NOT NULL CHECK(valid_from_epoch >= 0),
    valid_until_epoch INTEGER NOT NULL
        CHECK(
            valid_until_epoch > valid_from_epoch
            AND valid_until_epoch - valid_from_epoch <= 2592000
        ),
    revoked_at TEXT,
    revocation_reason TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, certificate_generation),
    CHECK(
        (revoked_at IS NULL AND revocation_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS infrastructure_certificates_by_expiry
ON infrastructure_agent_certificates(valid_until_epoch, agent_id);

-- Root-only offline administration commits the enrollment mutation and this
-- canonical receipt in one transaction. Receipts contain no private key or
-- secret material and cannot be rewritten after publication.
CREATE TABLE IF NOT EXISTS infrastructure_admin_receipts (
    request_id TEXT PRIMARY KEY,
    request_schema TEXT NOT NULL
        CHECK(request_schema = 'spectre.infrastructure.admin.v1'),
    action TEXT NOT NULL CHECK(action IN (
        'cell.provision',
        'host.provision',
        'agent.provision',
        'certificate.provision',
        'certificate.revoke'
    )),
    request_json TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    operator_uid INTEGER NOT NULL CHECK(operator_uid = 0),
    authority_schema_version INTEGER NOT NULL CHECK(authority_schema_version = 14),
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS infrastructure_admin_receipts_immutable_update
BEFORE UPDATE ON infrastructure_admin_receipts
BEGIN
    SELECT RAISE(ABORT, 'infrastructure admin receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_admin_receipts_immutable_delete
BEFORE DELETE ON infrastructure_admin_receipts
BEGIN
    SELECT RAISE(ABORT, 'infrastructure admin receipts are immutable');
END;

CREATE TABLE IF NOT EXISTS infrastructure_agent_replay_state (
    agent_id TEXT PRIMARY KEY
        REFERENCES infrastructure_observer_agents(agent_id) ON DELETE CASCADE,
    current_boot_id TEXT NOT NULL,
    last_sequence INTEGER NOT NULL CHECK(last_sequence >= 1),
    last_observation_id TEXT NOT NULL,
    last_captured_at TEXT NOT NULL,
    last_accepted_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS infrastructure_agent_boot_history (
    agent_id TEXT NOT NULL
        REFERENCES infrastructure_observer_agents(agent_id) ON DELETE CASCADE,
    agent_boot_id TEXT NOT NULL,
    first_sequence INTEGER NOT NULL CHECK(first_sequence >= 1),
    last_sequence INTEGER NOT NULL CHECK(last_sequence >= first_sequence),
    first_accepted_at TEXT NOT NULL,
    last_accepted_at TEXT NOT NULL,
    PRIMARY KEY(agent_id, agent_boot_id)
);

-- Accepted headers are immutable evidence. Current projections point at them
-- but rejected reports never update or replace them.
CREATE TABLE IF NOT EXISTS infrastructure_observations (
    observation_id TEXT PRIMARY KEY,
    cell_id TEXT NOT NULL
        REFERENCES infrastructure_cells(cell_id) ON DELETE RESTRICT,
    host_id TEXT NOT NULL
        REFERENCES infrastructure_hosts(host_id) ON DELETE RESTRICT,
    agent_id TEXT NOT NULL,
    certificate_generation INTEGER NOT NULL,
    agent_boot_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    captured_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    roster_complete INTEGER NOT NULL CHECK(roster_complete IN (0, 1)),
    roster_error_code TEXT,
    scope_sha256 TEXT NOT NULL,
    canonical_payload_sha256 TEXT NOT NULL,
    observer_version TEXT NOT NULL,
    vm_count INTEGER NOT NULL CHECK(vm_count >= 0),
    signature_verified INTEGER NOT NULL CHECK(signature_verified = 1),
    evidence_available INTEGER NOT NULL CHECK(evidence_available = 1),
    signed_envelope_sha256 TEXT NOT NULL
        CHECK(length(signed_envelope_sha256) = 64),
    signed_envelope_locator TEXT NOT NULL
        CHECK(signed_envelope_locator = 'sha256:' || signed_envelope_sha256),
    signed_envelope_size_bytes INTEGER NOT NULL
        CHECK(
            signed_envelope_size_bytes >= 1
            AND signed_envelope_size_bytes <= 786432
        ),
    FOREIGN KEY(agent_id, certificate_generation)
        REFERENCES infrastructure_agent_certificates(
            agent_id, certificate_generation
        ) ON DELETE RESTRICT,
    UNIQUE(agent_id, agent_boot_id, sequence),
    CHECK(
        (roster_complete = 1 AND roster_error_code IS NULL)
        OR
        (roster_complete = 0 AND roster_error_code IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS infrastructure_observations_by_host
ON infrastructure_observations(host_id, accepted_at DESC, observation_id);

CREATE TRIGGER IF NOT EXISTS infrastructure_observation_scope_insert_guard
BEFORE INSERT ON infrastructure_observations
WHEN NOT EXISTS (
    SELECT 1
    FROM infrastructure_hosts host
    JOIN infrastructure_observer_agents agent
      ON agent.host_id = host.host_id
    WHERE host.host_id = NEW.host_id
      AND host.cell_id = NEW.cell_id
      AND host.scope_sha256 = NEW.scope_sha256
      AND agent.agent_id = NEW.agent_id
      AND agent.assigned_scope_sha256 = NEW.scope_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure observation scope identity mismatch');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_observations_immutable_update
BEFORE UPDATE ON infrastructure_observations
BEGIN
    SELECT RAISE(ABORT, 'infrastructure accepted observations are immutable');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_observations_immutable_delete
BEFORE DELETE ON infrastructure_observations
BEGIN
    SELECT RAISE(ABORT, 'infrastructure accepted observations are immutable');
END;

CREATE TABLE IF NOT EXISTS infrastructure_current_hosts (
    host_id TEXT PRIMARY KEY
        REFERENCES infrastructure_hosts(host_id) ON DELETE CASCADE,
    observation_id TEXT NOT NULL
        REFERENCES infrastructure_observations(observation_id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform = 'windows-hyperv'),
    platform_version TEXT NOT NULL,
    management_addresses_json TEXT NOT NULL,
    logical_cpu INTEGER NOT NULL CHECK(logical_cpu >= 1),
    physical_memory_bytes INTEGER NOT NULL
        CHECK(physical_memory_bytes >= 1),
    uptime_seconds INTEGER NOT NULL CHECK(uptime_seconds >= 0),
    roster_complete INTEGER NOT NULL CHECK(roster_complete IN (0, 1)),
    roster_error_code TEXT,
    last_captured_at TEXT NOT NULL,
    last_accepted_at TEXT NOT NULL,
    CHECK(
        (roster_complete = 1 AND roster_error_code IS NULL)
        OR
        (roster_complete = 0 AND roster_error_code IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS infrastructure_current_vms (
    host_id TEXT NOT NULL
        REFERENCES infrastructure_hosts(host_id) ON DELETE CASCADE,
    vm_id TEXT NOT NULL,
    observation_id TEXT NOT NULL
        REFERENCES infrastructure_observations(observation_id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    role TEXT,
    state TEXT NOT NULL CHECK(state IN (
        'running', 'off', 'paused', 'saved', 'starting', 'stopping', 'unknown'
    )),
    generation INTEGER NOT NULL CHECK(generation IN (1, 2)),
    vcpu INTEGER NOT NULL CHECK(vcpu >= 1),
    startup_memory_bytes INTEGER NOT NULL CHECK(startup_memory_bytes >= 0),
    assigned_memory_bytes INTEGER NOT NULL CHECK(assigned_memory_bytes >= 0),
    ip_addresses_json TEXT NOT NULL,
    heartbeat TEXT NOT NULL CHECK(heartbeat IN (
        'ok', 'degraded', 'unknown', 'not-running'
    )),
    automatic_checkpoints INTEGER NOT NULL
        CHECK(automatic_checkpoints IN (0, 1)),
    replication TEXT NOT NULL CHECK(replication IN (
        'disabled', 'enabled', 'unknown'
    )),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY(host_id, vm_id),
    FOREIGN KEY(host_id, vm_id)
        REFERENCES infrastructure_host_vm_scope(host_id, vm_id)
        ON DELETE RESTRICT
);

CREATE TRIGGER IF NOT EXISTS infrastructure_current_host_observation_guard
BEFORE INSERT ON infrastructure_current_hosts
WHEN NOT EXISTS (
    SELECT 1 FROM infrastructure_observations observation
    WHERE observation.observation_id = NEW.observation_id
      AND observation.host_id = NEW.host_id
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure current host observation mismatch');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_current_host_update_guard
BEFORE UPDATE ON infrastructure_current_hosts
WHEN NOT EXISTS (
    SELECT 1 FROM infrastructure_observations observation
    WHERE observation.observation_id = NEW.observation_id
      AND observation.host_id = NEW.host_id
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure current host observation mismatch');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_current_vm_insert_guard
BEFORE INSERT ON infrastructure_current_vms
WHEN NOT EXISTS (
    SELECT 1
    FROM infrastructure_observations observation
    JOIN infrastructure_host_vm_scope scope
      ON scope.host_id = observation.host_id
    WHERE observation.observation_id = NEW.observation_id
      AND observation.host_id = NEW.host_id
      AND scope.vm_id = NEW.vm_id
      AND scope.approved_role IS NEW.role
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure current VM scope mismatch');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_current_vm_update_guard
BEFORE UPDATE ON infrastructure_current_vms
WHEN NOT EXISTS (
    SELECT 1
    FROM infrastructure_observations observation
    JOIN infrastructure_host_vm_scope scope
      ON scope.host_id = observation.host_id
    WHERE observation.observation_id = NEW.observation_id
      AND observation.host_id = NEW.host_id
      AND scope.vm_id = NEW.vm_id
      AND scope.approved_role IS NEW.role
)
BEGIN
    SELECT RAISE(ABORT, 'infrastructure current VM scope mismatch');
END;

CREATE INDEX IF NOT EXISTS infrastructure_current_vms_by_observation
ON infrastructure_current_vms(observation_id, host_id, vm_id);

-- Durable operation replay is separate from immutable audit so a conflicting
-- reuse of an operation UUID can itself be audited without changing the
-- original terminal outcome.
CREATE TABLE IF NOT EXISTS infrastructure_ingest_operations (
    broker_operation_id TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('accepted', 'rejected')),
    result_json TEXT,
    error_code TEXT,
    error_message TEXT,
    completed_at TEXT NOT NULL,
    CHECK(
        (outcome = 'accepted' AND result_json IS NOT NULL
         AND error_code IS NULL AND error_message IS NULL)
        OR
        (outcome = 'rejected' AND result_json IS NULL
         AND error_code IS NOT NULL AND error_message IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS infrastructure_ingest_audit (
    audit_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL UNIQUE,
    broker_operation_id TEXT NOT NULL,
    broker_peer_uid INTEGER NOT NULL CHECK(broker_peer_uid >= 0),
    broker_account_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('accepted', 'rejected')),
    rejection_code TEXT,
    rejection_message TEXT,
    certificate_fingerprint_sha256 TEXT,
    certificate_generation INTEGER
        CHECK(certificate_generation IS NULL OR certificate_generation >= 1),
    agent_id TEXT,
    cell_id TEXT,
    host_id TEXT,
    observation_id TEXT,
    agent_boot_id TEXT,
    sequence INTEGER CHECK(sequence IS NULL OR sequence >= 1),
    captured_at TEXT,
    claimed_agent_id TEXT,
    claimed_cell_id TEXT,
    claimed_host_id TEXT,
    claimed_observation_id TEXT,
    claimed_agent_boot_id TEXT,
    claimed_sequence INTEGER CHECK(
        claimed_sequence IS NULL OR claimed_sequence >= 1
    ),
    claimed_captured_at TEXT,
    request_sha256 TEXT NOT NULL,
    canonical_payload_sha256 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    signature_verified INTEGER NOT NULL CHECK(signature_verified IN (0, 1)),
    mtls_verified INTEGER NOT NULL CHECK(mtls_verified IN (0, 1)),
    signed_envelope_sha256 TEXT
        CHECK(
            signed_envelope_sha256 IS NULL
            OR length(signed_envelope_sha256) = 64
        ),
    signed_envelope_locator TEXT
        CHECK(
            signed_envelope_locator IS NULL
            OR signed_envelope_locator = 'sha256:' || signed_envelope_sha256
        ),
    signed_envelope_size_bytes INTEGER
        CHECK(
            signed_envelope_size_bytes IS NULL
            OR (
                signed_envelope_size_bytes >= 1
                AND signed_envelope_size_bytes <= 786432
            )
        ),
    evidence_available INTEGER NOT NULL CHECK(evidence_available IN (0, 1)),
    CHECK(
        (outcome = 'accepted' AND rejection_code IS NULL
         AND rejection_message IS NULL)
        OR
        (outcome = 'rejected' AND rejection_code IS NOT NULL
         AND rejection_message IS NOT NULL)
    ),
    CHECK(
        (
            evidence_available = 1
            AND signed_envelope_sha256 IS NOT NULL
            AND signed_envelope_locator IS NOT NULL
            AND signed_envelope_size_bytes IS NOT NULL
        )
        OR
        (
            evidence_available = 0
            AND outcome = 'rejected'
            AND signature_verified = 0
            AND signed_envelope_sha256 IS NULL
            AND signed_envelope_locator IS NULL
            AND signed_envelope_size_bytes IS NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS infrastructure_audit_by_host
ON infrastructure_ingest_audit(host_id, audit_sequence DESC);

CREATE INDEX IF NOT EXISTS infrastructure_audit_by_operation
ON infrastructure_ingest_audit(broker_operation_id, audit_sequence);

CREATE TRIGGER IF NOT EXISTS infrastructure_ingest_audit_immutable_update
BEFORE UPDATE ON infrastructure_ingest_audit
BEGIN
    SELECT RAISE(ABORT, 'infrastructure ingest audit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS infrastructure_ingest_audit_immutable_delete
BEFORE DELETE ON infrastructure_ingest_audit
BEGIN
    SELECT RAISE(ABORT, 'infrastructure ingest audit is immutable');
END;

CREATE TABLE IF NOT EXISTS telemetry_samples (
    sample_id TEXT PRIMARY KEY,
    host_resource_kind TEXT NOT NULL,
    host_resource_id TEXT NOT NULL,
    sampled_at TEXT NOT NULL,
    cpu_percent REAL,
    memory_bytes INTEGER CHECK (memory_bytes IS NULL OR memory_bytes >= 0),
    network_rx_bytes INTEGER CHECK (network_rx_bytes IS NULL OR network_rx_bytes >= 0),
    network_tx_bytes INTEGER CHECK (network_tx_bytes IS NULL OR network_tx_bytes >= 0),
    block_read_bytes INTEGER CHECK (block_read_bytes IS NULL OR block_read_bytes >= 0),
    block_write_bytes INTEGER CHECK (block_write_bytes IS NULL OR block_write_bytes >= 0),
    UNIQUE(host_resource_kind, host_resource_id, sampled_at)
);

CREATE TABLE IF NOT EXISTS backup_evidence (
    backup_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    manifest_path TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK (verification_status IN ('verified', 'failed')),
    created_at TEXT NOT NULL,
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS legacy_imports (
    import_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    source_path_digest TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    source_sha256 TEXT NOT NULL,
    backup_id TEXT NOT NULL REFERENCES backup_evidence(backup_id) ON DELETE RESTRICT,
    destination_generation TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('planned', 'committed', 'rolled_back', 'late_writer')),
    committed_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(source_id, source_sha256)
);

CREATE TABLE IF NOT EXISTS migration_conflicts (
    conflict_id TEXT PRIMARY KEY,
    import_id TEXT REFERENCES legacy_imports(import_id) ON DELETE CASCADE,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE RESTRICT,
    conflict_kind TEXT NOT NULL,
    logical_key TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'blocking')),
    disposition TEXT NOT NULL CHECK (disposition IN ('open', 'resolved', 'accepted')),
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(import_id, conflict_kind, logical_key)
);

CREATE TABLE IF NOT EXISTS unassigned_resources (
    unassigned_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    source_resource_id TEXT REFERENCES source_resources(source_resource_id) ON DELETE SET NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'name_only', 'not_git', 'missing_repo', 'conflicting_claims',
        'ambiguous_control', 'stale_observation'
    )),
    suggested_root TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'attached', 'retired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host_id, resource_kind, resource_id, reason_code)
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    source_id TEXT REFERENCES coordinator_sources(source_id) ON DELETE SET NULL,
    operation_id TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
    event_kind TEXT NOT NULL,
    code TEXT,
    message TEXT NOT NULL,
    diagnostic_json TEXT,
    occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_runs (
    run_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    parent_run_id TEXT REFERENCES test_runs(run_id) ON DELETE RESTRICT,
    owner_uid INTEGER NOT NULL CHECK(owner_uid >= 0),
    account_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    suite TEXT NOT NULL,
    run_kind TEXT NOT NULL CHECK(run_kind IN ('session', 'test', 'automation')),
    selection_json TEXT NOT NULL,
    command_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'running', 'passed', 'failed', 'cancelled', 'incomplete'
    )),
    client_started_at TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    client_finished_at TEXT,
    recorded_finished_at TEXT,
    duration_seconds REAL CHECK(duration_seconds IS NULL OR duration_seconds >= 0),
    exit_code INTEGER,
    case_count INTEGER NOT NULL DEFAULT 0 CHECK(case_count >= 0),
    passed_count INTEGER NOT NULL DEFAULT 0 CHECK(passed_count >= 0),
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count >= 0),
    skipped_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK(error_count >= 0),
    finished_operation_id TEXT UNIQUE,
    result_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(parent_run_id IS NULL OR parent_run_id != run_id),
    CHECK(
        (status = 'running' AND client_finished_at IS NULL
         AND recorded_finished_at IS NULL AND finished_operation_id IS NULL)
        OR
        (status != 'running' AND client_finished_at IS NOT NULL
         AND recorded_finished_at IS NOT NULL AND duration_seconds IS NOT NULL
         AND exit_code IS NOT NULL AND finished_operation_id IS NOT NULL
         AND result_fingerprint IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS test_case_results (
    run_id TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    test_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('passed', 'failed', 'skipped', 'error')),
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_seconds REAL NOT NULL CHECK(duration_seconds >= 0),
    PRIMARY KEY(run_id, ordinal)
);

CREATE INDEX IF NOT EXISTS test_runs_by_repo_time
ON test_runs(repo_id, client_started_at DESC, run_id);

CREATE INDEX IF NOT EXISTS test_cases_by_identity_time
ON test_case_results(test_id, finished_at DESC, run_id);

CREATE TABLE IF NOT EXISTS event_journal_sequences (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE
        REFERENCES events(event_id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS assign_event_journal_sequence
AFTER INSERT ON events
BEGIN
    INSERT OR IGNORE INTO event_journal_sequences(event_id) VALUES (NEW.event_id);
END;

CREATE INDEX IF NOT EXISTS repositories_by_state ON repositories(state, display_name);
CREATE INDEX IF NOT EXISTS sources_by_status ON coordinator_sources(status, canonical_home);
CREATE INDEX IF NOT EXISTS source_resources_by_repo ON source_resources(repo_id, resource_kind);
CREATE INDEX IF NOT EXISTS memberships_by_repo ON repository_memberships(repo_id, resource_kind);
CREATE INDEX IF NOT EXISTS operations_by_repo ON operations(repo_id, created_at);
CREATE INDEX IF NOT EXISTS telemetry_by_resource_time
    ON telemetry_samples(host_resource_kind, host_resource_id, sampled_at);
CREATE INDEX IF NOT EXISTS database_observations_by_container
    ON database_observations(docker_resource_id, sampled_at);
CREATE INDEX IF NOT EXISTS database_backups_by_target
    ON database_backups(source_container_id, source_database_name, created_at);
CREATE INDEX IF NOT EXISTS unassigned_by_status ON unassigned_resources(status, reason_code);
"""


@dataclass(frozen=True)
class InvariantViolation:
    code: str
    detail: str


def _upgrade_sha256_fingerprints_to_v4(connection: sqlite3.Connection) -> None:
    """Normalize the exact current resource identities used by lifecycle ACLs.

    Schema v3 observations accidentally persisted the canonical digest without
    its algorithm tag in repository memberships and startup policies.  Only an
    exact lowercase 64-hex legacy value is safe to reinterpret.  Anything else
    is ambiguous evidence and must abort the surrounding store-open
    transaction instead of being guessed into a lifecycle identity.
    """

    for table in ("repository_memberships", "startup_policies"):
        connection.execute(
            f"""
            UPDATE {table}
            SET immutable_fingerprint = 'sha256:' || immutable_fingerprint
            WHERE length(immutable_fingerprint) = 64
              AND immutable_fingerprint NOT GLOB '*[^0-9a-f]*'
            """
        )
        identifier = (
            "membership_id" if table == "repository_memberships" else "policy_id"
        )
        for row in connection.execute(
            f"SELECT {identifier}, immutable_fingerprint FROM {table}"
        ):
            if not _SHA256_FINGERPRINT.fullmatch(str(row[1])):
                raise RuntimeError(
                    "coordinator schema v4 migration rejected malformed "
                    f"{table}.immutable_fingerprint for {row[0]}"
                )


def _upgrade_ephemeral_runs_to_v6(connection: sqlite3.Connection) -> None:
    """Add crash-recovery policy snapshots to an already-created v5 run table."""

    template_columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(ephemeral_container_templates)")
    }
    template_additions = (
        ("max_concurrent_runs", "INTEGER NOT NULL DEFAULT 4 CHECK(max_concurrent_runs BETWEEN 1 AND 32)"),
        ("max_concurrent_runs_per_uid", "INTEGER NOT NULL DEFAULT 2 CHECK(max_concurrent_runs_per_uid BETWEEN 1 AND max_concurrent_runs)"),
        ("repo_max_active_runs", "INTEGER NOT NULL DEFAULT 16 CHECK(repo_max_active_runs BETWEEN max_concurrent_runs AND 64)"),
        ("repo_memory_budget_bytes", "INTEGER NOT NULL DEFAULT 8589934592 CHECK(repo_memory_budget_bytes BETWEEN 16777216 AND 72057594037927936)"),
        ("repo_cpu_budget_millis", "INTEGER NOT NULL DEFAULT 16000 CHECK(repo_cpu_budget_millis BETWEEN 10 AND 16384000)"),
    )
    for name, declaration in template_additions:
        if name not in template_columns:
            connection.execute(
                f"ALTER TABLE ephemeral_container_templates ADD COLUMN {name} {declaration}"
            )

    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(ephemeral_container_runs)")
    }
    additions = (
        (
            "max_ttl_seconds",
            "INTEGER NOT NULL DEFAULT 604800 CHECK(max_ttl_seconds BETWEEN 60 AND 604800)",
        ),
        (
            "next_reconcile_at_epoch",
            "INTEGER NOT NULL DEFAULT 0 CHECK(next_reconcile_at_epoch >= 0)",
        ),
        (
            "recovery_failures",
            "INTEGER NOT NULL DEFAULT 0 CHECK(recovery_failures >= 0)",
        ),
        (
            "create_absence_since_epoch",
            "INTEGER CHECK(create_absence_since_epoch IS NULL OR create_absence_since_epoch >= 0)",
        ),
        (
            "create_absence_observations",
            "INTEGER NOT NULL DEFAULT 0 CHECK(create_absence_observations >= 0)",
        ),
        (
            "cleanup_requested",
            "INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_requested IN (0, 1))",
        ),
    )
    for name, declaration in additions:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE ephemeral_container_runs ADD COLUMN {name} {declaration}"
            )
    missing_template = connection.execute(
        """
        SELECT run.run_id
        FROM ephemeral_container_runs run
        LEFT JOIN ephemeral_container_templates template
          ON template.template_id = run.template_id
         AND template.repo_id = run.repo_id
        WHERE template.template_id IS NULL
        LIMIT 1
        """
    ).fetchone()
    if missing_template is not None:
        raise RuntimeError(
            "coordinator schema v6 migration cannot seal TTL policy for "
            f"ephemeral run {missing_template[0]} without its exact template"
        )
    # Version 5 did not snapshot the template maximum on each run.  The
    # additive column's seven-day default exists only to satisfy SQLite's
    # ALTER TABLE rules; retaining it would silently widen a one-hour template
    # into seven days after upgrade.  Bind every retained run to the exact
    # currently sealed template maximum before the new broker can renew it.
    connection.execute(
        """
        UPDATE ephemeral_container_runs
        SET max_ttl_seconds = (
            SELECT template.max_ttl_seconds
            FROM ephemeral_container_templates template
            WHERE template.template_id = ephemeral_container_runs.template_id
              AND template.repo_id = ephemeral_container_runs.repo_id
        )
        """
    )


def _upgrade_ephemeral_secret_policy_to_v7(connection: sqlite3.Connection) -> None:
    """Add non-secret credential policy snapshots to ephemeral definitions/runs.

    The runtime password never enters SQLite.  These nullable fields retain
    only the reviewed policy name and an opaque binding ID so a running
    container can be recovered without allowing reenrollment to substitute a
    new credential contract for an already admitted run.
    """

    additions = {
        "ephemeral_container_templates": (
            ("secret_policy_kind", "TEXT"),
            ("secret_binding_id", "TEXT"),
        ),
        "ephemeral_container_runs": (
            ("secret_policy_kind", "TEXT"),
            ("secret_binding_id", "TEXT"),
        ),
    }
    for table, columns in additions.items():
        current = {
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
        }
        for name, declaration in columns:
            if name not in current:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    for table in additions:
        invalid = connection.execute(
            f"""
            SELECT 1 FROM {table}
            WHERE (secret_policy_kind IS NULL) != (secret_binding_id IS NULL)
               OR (secret_policy_kind IS NOT NULL
                   AND secret_policy_kind != 'postgres_initdb_password_file_v1')
            LIMIT 1
            """
        ).fetchone()
        if invalid is not None:
            raise RuntimeError(
                "coordinator schema v7 migration rejected an invalid ephemeral "
                "secret-policy pairing"
            )
    # Cleanup intent must survive an attention/error status written by an old
    # broker after a stop/remove outcome became uncertain.  Recover every
    # unambiguous legacy intent before the upgraded broker can reconcile rows.
    connection.execute(
        """
        UPDATE ephemeral_container_runs
        SET cleanup_requested = 1
        WHERE cleanup_requested = 0
          AND (
              cleanup_reason IS NOT NULL
              OR status IN ('cleanup_pending', 'stopping', 'removing')
          )
        """
    )


def _upgrade_ephemeral_renewal_journal_to_v8(connection: sqlite3.Connection) -> None:
    """Add durable non-secret state for an interrupted credential expiry renewal."""

    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(ephemeral_container_runs)")
    }
    additions = (
        (
            "credential_renewal_phase",
            "TEXT NOT NULL DEFAULT 'none' "
            "CHECK(credential_renewal_phase IN ('none', 'prepared', 'committing'))",
        ),
        ("credential_renewal_old_expires_at_epoch", "INTEGER"),
        ("credential_renewal_new_expires_at_epoch", "INTEGER"),
        ("credential_renewal_operation_id", "TEXT"),
    )
    for name, declaration in additions:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE ephemeral_container_runs ADD COLUMN {name} {declaration}"
            )

    invalid = connection.execute(
        """
        SELECT run_id
        FROM ephemeral_container_runs
        WHERE credential_renewal_phase NOT IN ('none', 'prepared', 'committing')
           OR (
               credential_renewal_phase = 'none'
               AND (
                   credential_renewal_old_expires_at_epoch IS NOT NULL
                   OR credential_renewal_new_expires_at_epoch IS NOT NULL
                   OR credential_renewal_operation_id IS NOT NULL
               )
           )
           OR (
               credential_renewal_phase IN ('prepared', 'committing')
               AND (
                   credential_renewal_old_expires_at_epoch IS NULL
                   OR credential_renewal_old_expires_at_epoch <= 0
                   OR credential_renewal_new_expires_at_epoch IS NULL
                   OR credential_renewal_new_expires_at_epoch <= 0
                   OR credential_renewal_operation_id IS NULL
               )
           )
        LIMIT 1
        """
    ).fetchone()
    if invalid is not None:
        raise RuntimeError(
            "coordinator schema v8 migration rejected an invalid ephemeral "
            f"credential-renewal journal for run {invalid[0]}"
        )


def _backfill_repository_families_to_v5(
    connection: sqlite3.Connection, *, timestamp: str
) -> None:
    """Give every pre-v5 worktree a deterministic, lossless singleton family.

    Schema migration deliberately does not run Git or inspect the filesystem.
    A later runtime request may merge a *proved* linked worktree into its
    primary family; until then each legacy project remains independently and
    truthfully addressable exactly as it was in v4.
    """

    connection.execute(
        """
        INSERT OR IGNORE INTO repository_families(
            family_id, host_id, root_repo_id, git_common_dir,
            identity_fingerprint, created_at, updated_at
        )
        SELECT repo_id, host_id, repo_id, NULL, NULL,
               COALESCE(created_at, ?), ?
        FROM repositories
        ORDER BY host_id, canonical_root, repo_id
        """,
        (timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO repository_scopes(
            repo_id, family_id, project_kind, git_dir, git_common_dir,
            identity_fingerprint, created_at, updated_at
        )
        SELECT repo_id, repo_id, 'primary', NULL, NULL, NULL,
               COALESCE(created_at, ?), ?
        FROM repositories
        ORDER BY host_id, canonical_root, repo_id
        """,
        (timestamp, timestamp),
    )


def _upgrade_runtime_session_columns_to_v6(
    connection: sqlite3.Connection,
) -> None:
    session_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(runtime_sessions)")
    }
    if "execution_owner_pid" not in session_columns:
        connection.execute(
            """
            ALTER TABLE runtime_sessions
            ADD COLUMN execution_owner_pid INTEGER CHECK (
                execution_owner_pid IS NULL OR execution_owner_pid > 1
            )
            """
        )
    if "execution_owner_identity" not in session_columns:
        connection.execute(
            "ALTER TABLE runtime_sessions ADD COLUMN execution_owner_identity TEXT"
        )
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(runtime_session_resources)")
    }
    if "cleanup_disposition" not in columns:
        connection.execute(
            """
            ALTER TABLE runtime_session_resources
            ADD COLUMN cleanup_disposition TEXT NOT NULL DEFAULT 'retained'
                CHECK (cleanup_disposition IN ('removed', 'retained'))
            """
        )
    if "identity_json" not in columns:
        connection.execute(
            "ALTER TABLE runtime_session_resources ADD COLUMN identity_json TEXT"
        )


def _upgrade_runtime_cleanup_owner_columns_to_v7(
    connection: sqlite3.Connection,
) -> None:
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(runtime_sessions)")
    }
    if "cleanup_owner_pid" not in columns:
        connection.execute(
            """
            ALTER TABLE runtime_sessions
            ADD COLUMN cleanup_owner_pid INTEGER CHECK (
                cleanup_owner_pid IS NULL OR cleanup_owner_pid > 1
            )
            """
        )
    if "cleanup_owner_identity" not in columns:
        connection.execute(
            "ALTER TABLE runtime_sessions ADD COLUMN cleanup_owner_identity TEXT"
        )


def _upgrade_repository_scope_filesystem_identity_to_v8(
    connection: sqlite3.Connection,
) -> None:
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(repository_scopes)")
    }
    if "root_device" not in columns:
        connection.execute(
            "ALTER TABLE repository_scopes ADD COLUMN root_device INTEGER"
        )
    if "root_inode" not in columns:
        connection.execute(
            "ALTER TABLE repository_scopes ADD COLUMN root_inode INTEGER"
        )


def _upgrade_cleanup_tombstones_to_v11(
    connection: sqlite3.Connection,
) -> None:
    """Make permanent project evidence repository-generation aware."""

    table_info = tuple(connection.execute("PRAGMA table_info(cleanup_tombstones)"))
    columns = {str(row[1]): row for row in table_info}
    expected_v11_primary_key = {
        "target_kind": 1,
        "target_id": 2,
        "target_generation": 3,
    }
    if "target_generation" in columns:
        actual_primary_key = {
            name: int(row[5]) for name, row in columns.items() if int(row[5]) > 0
        }
        generation_column = columns["target_generation"]
        if (
            actual_primary_key != expected_v11_primary_key
            or str(generation_column[2]).upper() != "INTEGER"
            or int(generation_column[3]) != 1
        ):
            raise RuntimeError(
                "coordinator schema v11 migration rejected a partial cleanup "
                "tombstone generation schema"
            )
        return
    legacy_primary_key = {
        name: int(row[5]) for name, row in columns.items() if int(row[5]) > 0
    }
    if legacy_primary_key != {"target_kind": 1, "target_id": 2}:
        raise RuntimeError(
            "coordinator schema v11 migration rejected an unsupported legacy "
            "cleanup tombstone primary key"
        )
    rows = tuple(connection.execute("SELECT * FROM cleanup_tombstones"))
    migrated: list[tuple[object, ...]] = []
    for row in rows:
        target_kind = str(row["target_kind"])
        target_generation = 0
        if target_kind == "project":
            target_id = str(row["target_id"])
            try:
                evidence = json.loads(str(row["evidence_json"]))
                snapshot = evidence["snapshot"]
                identity = snapshot["identity"]
                generation = identity["generation"]
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise RuntimeError(
                    "coordinator schema v11 migration rejected project cleanup "
                    f"evidence without an exact generation for {row['target_id']}"
                ) from error
            if type(generation) is not int or generation < 0:
                raise RuntimeError(
                    "coordinator schema v11 migration rejected an invalid project "
                    f"cleanup generation for {row['target_id']}"
                )
            if (
                row["repo_id"] is None
                or str(row["repo_id"]) != target_id
                or str(identity.get("repo_id") or "") != target_id
            ):
                raise RuntimeError(
                    "coordinator schema v11 migration rejected project cleanup "
                    f"evidence with inconsistent repository identity for {target_id}"
                )
            target_generation = generation
        migrated.append(
            (
                target_kind,
                str(row["target_id"]),
                target_generation,
                row["repo_id"],
                str(row["immutable_fingerprint"]),
                str(row["operation_id"]),
                str(row["actor"]),
                str(row["reason"]),
                str(row["evidence_json"]),
                str(row["removed_at"]),
            )
        )

    connection.execute(
        """
        CREATE TABLE cleanup_tombstones_v11 (
            target_kind TEXT NOT NULL CHECK(target_kind IN (
                'project', 'server', 'container', 'worktree'
            )),
            target_id TEXT NOT NULL,
            target_generation INTEGER NOT NULL DEFAULT 0
                CHECK(target_generation >= 0),
            repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
            immutable_fingerprint TEXT NOT NULL,
            operation_id TEXT NOT NULL
                REFERENCES operations(operation_id) ON DELETE RESTRICT,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            removed_at TEXT NOT NULL,
            PRIMARY KEY(target_kind, target_id, target_generation)
        )
        """
    )
    connection.executemany(
        """
        INSERT INTO cleanup_tombstones_v11(
            target_kind, target_id, target_generation, repo_id,
            immutable_fingerprint, operation_id, actor, reason,
            evidence_json, removed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        migrated,
    )
    connection.execute("DROP TABLE cleanup_tombstones")
    connection.execute(
        "ALTER TABLE cleanup_tombstones_v11 RENAME TO cleanup_tombstones"
    )


def _upgrade_infrastructure_certificates_to_v14(
    connection: sqlite3.Connection,
) -> None:
    """Add real PS256 verification material without inventing old key data.

    The v13 development contract retained only a caller-chosen JWS key ID.
    There is no sound derivation from that identifier to the public signing
    key. An empty v13 table can therefore be upgraded additively, while any
    existing certificate row is an explicit offline reenrollment blocker.
    """

    columns = {
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(infrastructure_agent_certificates)"
        )
    }
    required = {
        "jws_algorithm",
        "jws_spki_der_base64",
        "jws_spki_sha256",
    }
    missing = required - columns
    if missing:
        row_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM infrastructure_agent_certificates"
            ).fetchone()[0]
        )
        if row_count:
            raise RuntimeError(
                "schema v13 infrastructure certificate rows lack immutable "
                "PS256/SPKI verification material; reenroll them through an "
                "audited offline migration before upgrading to schema v14"
            )
        additions = {
            "jws_algorithm": (
                "TEXT NOT NULL CHECK(jws_algorithm = 'PS256')"
            ),
            "jws_spki_der_base64": "TEXT NOT NULL",
            "jws_spki_sha256": "TEXT NOT NULL",
        }
        for name in (
            "jws_algorithm",
            "jws_spki_der_base64",
            "jws_spki_sha256",
        ):
            if name in missing:
                connection.execute(
                    "ALTER TABLE infrastructure_agent_certificates "
                    f"ADD COLUMN {name} {additions[name]}"
                )

    invalid_validity = connection.execute(
        """
        SELECT agent_id, certificate_generation
        FROM infrastructure_agent_certificates
        WHERE valid_until_epoch - valid_from_epoch > ?
        LIMIT 1
        """,
        (INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS,),
    ).fetchone()
    if invalid_validity is not None:
        raise RuntimeError(
            "infrastructure certificate generation exceeds the schema-v14 "
            "30-day cryptoperiod and requires audited offline reenrollment"
        )
    invalid_overlap = connection.execute(
        """
        SELECT older.agent_id, older.certificate_generation,
               newer.certificate_generation
        FROM infrastructure_agent_certificates AS older
        JOIN infrastructure_agent_certificates AS newer
          ON newer.agent_id = older.agent_id
         AND newer.certificate_generation > older.certificate_generation
        WHERE older.revoked_at IS NULL
          AND newer.revoked_at IS NULL
          AND MIN(older.valid_until_epoch, newer.valid_until_epoch)
              - MAX(older.valid_from_epoch, newer.valid_from_epoch) > ?
        LIMIT 1
        """,
        (INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS,),
    ).fetchone()
    if invalid_overlap is not None:
        raise RuntimeError(
            "infrastructure certificate generations exceed the schema-v14 "
            "72-hour active overlap bound and require audited offline "
            "reenrollment or revocation"
        )

    signing_index = next(
        (
            row
            for row in connection.execute(
                "PRAGMA index_list(infrastructure_agent_certificates)"
            )
            if str(row[1])
            == "infrastructure_certificates_by_signing_material"
        ),
        None,
    )
    if signing_index is not None:
        indexed_columns = [
            str(row[2])
            for row in connection.execute(
                "PRAGMA index_info(infrastructure_certificates_by_signing_material)"
            )
        ]
        if not bool(signing_index[2]) or indexed_columns != [
            "jws_spki_sha256"
        ]:
            connection.execute(
                "DROP INDEX infrastructure_certificates_by_signing_material"
            )
    try:
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            infrastructure_certificates_by_signing_material
            ON infrastructure_agent_certificates(jws_spki_sha256)
            """
        )
    except sqlite3.IntegrityError as error:
        raise RuntimeError(
            "infrastructure certificate generations reuse a JWS SPKI digest; "
            "schema v14 requires a globally unique signing key per generation "
            "and cannot choose which duplicated identity is authoritative"
        ) from error
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS
        infrastructure_certificate_validity_insert_guard
        BEFORE INSERT ON infrastructure_agent_certificates
        WHEN NEW.valid_until_epoch - NEW.valid_from_epoch > 2592000
        BEGIN
            SELECT RAISE(
                ABORT,
                'infrastructure certificate validity exceeds 30 days'
            );
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS
        infrastructure_certificate_overlap_insert_guard
        BEFORE INSERT ON infrastructure_agent_certificates
        WHEN EXISTS (
            SELECT 1
            FROM infrastructure_agent_certificates AS existing
            WHERE existing.agent_id = NEW.agent_id
              AND existing.revoked_at IS NULL
              AND MIN(existing.valid_until_epoch, NEW.valid_until_epoch)
                  - MAX(existing.valid_from_epoch, NEW.valid_from_epoch) > 259200
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'infrastructure certificate overlap exceeds 72 hours'
            );
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS infrastructure_certificate_identity_immutable
        BEFORE UPDATE ON infrastructure_agent_certificates
        WHEN OLD.agent_id != NEW.agent_id
          OR OLD.certificate_generation != NEW.certificate_generation
          OR OLD.certificate_fingerprint_sha256 != NEW.certificate_fingerprint_sha256
          OR OLD.jws_key_id != NEW.jws_key_id
          OR OLD.jws_algorithm != NEW.jws_algorithm
          OR OLD.jws_spki_der_base64 != NEW.jws_spki_der_base64
          OR OLD.jws_spki_sha256 != NEW.jws_spki_sha256
          OR OLD.valid_from_epoch != NEW.valid_from_epoch
          OR OLD.valid_until_epoch != NEW.valid_until_epoch
          OR OLD.created_at != NEW.created_at
        BEGIN
            SELECT RAISE(ABORT, 'infrastructure certificate identity is immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS infrastructure_certificate_revocation_guard
        BEFORE UPDATE ON infrastructure_agent_certificates
        WHEN (OLD.revoked_at IS NOT NULL)
          OR NEW.revoked_at IS NULL
          OR NEW.revocation_reason IS NULL
        BEGIN
            SELECT RAISE(ABORT, 'infrastructure certificate revocation is append-only');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS infrastructure_certificate_delete_guard
        BEFORE DELETE ON infrastructure_agent_certificates
        BEGIN
            SELECT RAISE(ABORT, 'infrastructure certificate generations are immutable');
        END
        """
    )


def _upgrade_infrastructure_artifacts_to_v14(
    connection: sqlite3.Connection,
) -> None:
    """Add broker-owned envelope bindings without fabricating old evidence."""

    requirements = {
        "infrastructure_observations": {
            "signed_envelope_sha256": "TEXT",
            "signed_envelope_locator": "TEXT",
            "signed_envelope_size_bytes": "INTEGER",
        },
        "infrastructure_ingest_audit": {
            "signed_envelope_sha256": "TEXT",
            "signed_envelope_locator": "TEXT",
            "signed_envelope_size_bytes": "INTEGER",
            "evidence_available": "INTEGER",
        },
    }
    missing_by_table: dict[str, dict[str, str]] = {}
    for table, expected in requirements.items():
        columns = {
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
        missing = {
            name: declaration
            for name, declaration in expected.items()
            if name not in columns
        }
        if missing:
            missing_by_table[table] = missing
    if missing_by_table:
        retained = sum(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in requirements
        )
        if retained:
            raise RuntimeError(
                "schema-v14 infrastructure rows lack broker-owned signed-envelope "
                "evidence; the immutable records require audited offline "
                "reconciliation instead of fabricated artifact locators"
            )
        for table, missing in missing_by_table.items():
            for column, declaration in missing.items():
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
                )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS infrastructure_observation_artifact_guard
        BEFORE INSERT ON infrastructure_observations
        WHEN NEW.evidence_available != 1
          OR NEW.signed_envelope_sha256 IS NULL
          OR length(NEW.signed_envelope_sha256) != 64
          OR NEW.signed_envelope_locator
             != 'sha256:' || NEW.signed_envelope_sha256
          OR NEW.signed_envelope_size_bytes < 1
          OR NEW.signed_envelope_size_bytes > 786432
        BEGIN
            SELECT RAISE(
                ABORT,
                'infrastructure observation lacks verified envelope evidence'
            );
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS infrastructure_audit_artifact_guard
        BEFORE INSERT ON infrastructure_ingest_audit
        WHEN NOT (
            (
                NEW.evidence_available = 1
                AND NEW.signed_envelope_sha256 IS NOT NULL
                AND length(NEW.signed_envelope_sha256) = 64
                AND NEW.signed_envelope_locator
                    = 'sha256:' || NEW.signed_envelope_sha256
                AND NEW.signed_envelope_size_bytes >= 1
                AND NEW.signed_envelope_size_bytes <= 786432
            )
            OR
            (
                NEW.evidence_available = 0
                AND NEW.outcome = 'rejected'
                AND NEW.signature_verified = 0
                AND NEW.signed_envelope_sha256 IS NULL
                AND NEW.signed_envelope_locator IS NULL
                AND NEW.signed_envelope_size_bytes IS NULL
            )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'infrastructure ingest audit lacks verified envelope evidence'
            );
        END
        """
    )


def initialize_schema(
    connection: sqlite3.Connection,
    *,
    database_generation: str,
    timestamp: str,
) -> None:
    """Create or atomically upgrade the normalized coordinator schema."""

    statement = ""
    for line in DDL.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            statement = ""
            if sql:
                connection.execute(sql)
    if statement.strip():
        raise RuntimeError("coordinator schema contains an incomplete SQL statement")
    _upgrade_infrastructure_certificates_to_v14(connection)
    _upgrade_infrastructure_artifacts_to_v14(connection)
    # Existing stores predate the insertion-order journal. Backfill once in a
    # deterministic order; the trigger assigns every later event atomically in
    # its originating transaction. AUTOINCREMENT prevents cursor reuse after
    # deletions, logical import, or VACUUM.
    connection.execute(
        """
        INSERT OR IGNORE INTO event_journal_sequences(event_id)
        SELECT event_id FROM events ORDER BY occurred_at, event_id
        """
    )
    row = connection.execute(
        "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if row is None:
        connection.execute(
            """
            INSERT INTO schema_metadata(
                singleton, schema_version, database_generation, created_at, updated_at
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (SCHEMA_VERSION, database_generation, timestamp, timestamp),
        )
    elif MINIMUM_MIGRATABLE_SCHEMA_VERSION <= int(row[0]) < SCHEMA_VERSION:
        # Versions 2 and 3 add only additive ledgers. Version 4 additionally
        # tags exact legacy membership/policy digests. Versions 5 through 11
        # were developed on two compatible feature lines: broker-owned
        # ephemeral/test journals and repository-family/runtime/worker state.
        # Their migrations are deliberately idempotent and all run below so a
        # database from either line reaches the merged v14 contract without
        # guessing which same-numbered historical line produced it.
        # The caller owns one BEGIN IMMEDIATE transaction around this entire
        # function, so a malformed leftover rolls back both DDL and every
        # successfully converted fingerprint.
        previous = int(row[0])
        _upgrade_sha256_fingerprints_to_v4(connection)
        _upgrade_ephemeral_runs_to_v6(connection)
        _upgrade_ephemeral_secret_policy_to_v7(connection)
        _upgrade_ephemeral_renewal_journal_to_v8(connection)
        _backfill_repository_families_to_v5(connection, timestamp=timestamp)
        _upgrade_runtime_session_columns_to_v6(connection)
        _upgrade_runtime_cleanup_owner_columns_to_v7(connection)
        _upgrade_repository_scope_filesystem_identity_to_v8(connection)
        _upgrade_cleanup_tombstones_to_v11(connection)
        connection.execute(
            """
            UPDATE schema_metadata SET schema_version = ?, updated_at = ?
            WHERE singleton = 1 AND schema_version = ?
            """,
            (SCHEMA_VERSION, timestamp, previous),
        )
    elif int(row[0]) != SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported coordinator database schema {row[0]}; expected {SCHEMA_VERSION}"
        )


def invariant_violations(
    connection: sqlite3.Connection,
    *,
    include_foreign_keys: bool = True,
) -> list[InvariantViolation]:
    """Return human-readable violations not expressible as local constraints.

    Foreign-key enforcement is enabled on every coordinator connection. A full
    ``foreign_key_check`` is therefore a maintenance verifier for pre-existing
    corruption, not a per-mutation safety primitive; callers on short write
    paths can omit it while still evaluating the semantic consistency checks.
    """

    violations: list[InvariantViolation] = []
    if include_foreign_keys:
        for row in connection.execute("PRAGMA foreign_key_check"):
            violations.append(
                InvariantViolation(
                    "foreign_key",
                    f"table={row[0]} rowid={row[1]} parent={row[2]} constraint={row[3]}",
                )
            )

    checks: Iterable[tuple[str, str, str]] = (
        (
            "installed_missing_repository",
            """
            SELECT r.repo_id || ':' || r.canonical_root
            FROM repositories r
            JOIN repository_installations i USING(repo_id)
            WHERE r.state = 'missing' AND i.status != 'disabled'
            """,
            "missing repository is not disabled",
        ),
        (
            "disabled_repository_active_lease",
            """
            SELECT l.lease_id || ':' || r.canonical_root
            FROM leases l
            JOIN repositories r USING(repo_id)
            JOIN repository_installations i USING(repo_id)
            WHERE i.status = 'disabled' AND l.status = 'active'
            """,
            "disabled repository retains an active lease",
        ),
        (
            "disabled_repository_active_assignment",
            """
            SELECT p.assignment_id || ':' || r.canonical_root
            FROM port_assignments p
            JOIN repositories r USING(repo_id)
            JOIN repository_installations i USING(repo_id)
            WHERE i.status = 'disabled' AND p.status = 'active'
            """,
            "disabled repository retains an active port assignment",
        ),
        (
            "disabled_repository_active_broker_lease",
            """
            SELECT b.link_id || ':' || r.canonical_root
            FROM broker_lease_links b
            JOIN repositories r USING(repo_id)
            JOIN repository_installations i USING(repo_id)
            WHERE i.status = 'disabled'
              AND b.status IN ('reserved','active','release_pending','rollback_failed','reconciliation_required')
            """,
            "disabled repository retains an active broker lease link",
        ),
        (
            "disabled_repository_active_broker_assignment",
            """
            SELECT b.link_id || ':' || r.canonical_root
            FROM broker_assignment_links b
            JOIN repositories r USING(repo_id)
            JOIN repository_installations i USING(repo_id)
            WHERE i.status = 'disabled'
              AND b.status IN ('reserved','active','release_pending','rollback_failed','reconciliation_required')
            """,
            "disabled repository retains an active broker assignment link",
        ),
        (
            "disabled_repository_enabled_startup_policy",
            """
            SELECT s.policy_id || ':' || r.canonical_root
            FROM startup_policies s
            JOIN repositories r USING(repo_id)
            JOIN repository_installations i USING(repo_id)
            WHERE i.status = 'disabled'
              AND s.current_value != s.desired_disabled_value
            """,
            "disabled repository retains an enabled startup policy",
        ),
        (
            "membership_binding_repository_mismatch",
            """
            SELECT m.membership_id
            FROM repository_memberships m
            JOIN control_bindings b ON b.binding_id = m.control_binding_id
            WHERE b.repo_id IS NOT NULL AND b.repo_id != m.repo_id
            """,
            "membership points to a control binding for another repository",
        ),
        (
            "successful_operation_incomplete_target",
            """
            SELECT DISTINCT o.operation_id
            FROM operations o JOIN operation_targets t USING(operation_id)
            WHERE o.status = 'succeeded' AND t.status != 'succeeded'
            """,
            "successful operation contains a non-successful target",
        ),
        (
            "event_missing_journal_sequence",
            """
            SELECT e.event_id FROM events e
            LEFT JOIN event_journal_sequences s USING(event_id)
            WHERE s.event_id IS NULL
            """,
            "durable event lacks a monotonic journal sequence",
        ),
        (
            "test_run_case_count_mismatch",
            """
            SELECT r.run_id FROM test_runs r
            LEFT JOIN test_case_results c USING(run_id)
            GROUP BY r.run_id
            HAVING r.case_count != COUNT(c.ordinal)
                OR r.case_count != r.passed_count + r.failed_count
                    + r.skipped_count + r.error_count
            """,
            "test run aggregate counts do not match its case journal",
        ),
        (
            "passed_test_run_has_failure",
            """
            SELECT run_id FROM test_runs
            WHERE status = 'passed' AND (failed_count != 0 OR error_count != 0)
            """,
            "passed test run retains failed or errored cases",
        ),
        (
            "repository_missing_scope",
            """
            SELECT r.repo_id FROM repositories r
            LEFT JOIN repository_scopes s USING(repo_id)
            WHERE s.repo_id IS NULL
            """,
            "repository has no family scope",
        ),
        (
            "repository_family_root_mismatch",
            """
            SELECT f.family_id
            FROM repository_families f
            LEFT JOIN repository_scopes s ON s.repo_id = f.root_repo_id
            WHERE s.repo_id IS NULL OR s.family_id != f.family_id
               OR s.project_kind != 'primary'
            """,
            "repository family root is not its primary scope",
        ),
        (
            "repository_family_cross_host",
            """
            SELECT s.repo_id
            FROM repository_scopes s
            JOIN repositories r USING(repo_id)
            JOIN repository_families f USING(family_id)
            WHERE r.host_id != f.host_id
            """,
            "repository scope crosses host authority",
        ),
        (
            "repository_scope_partial_filesystem_identity",
            """
            SELECT repo_id FROM repository_scopes
            WHERE (root_device IS NULL) != (root_inode IS NULL)
               OR root_device < 0 OR root_inode <= 0
            """,
            "repository scope has an incomplete filesystem identity",
        ),
        (
            "repository_scope_duplicate_filesystem_identity",
            """
            SELECT MIN(scope.repo_id)
            FROM repository_scopes scope
            JOIN repositories repository USING(repo_id)
            WHERE scope.root_device IS NOT NULL
              AND scope.root_inode IS NOT NULL
            GROUP BY repository.host_id, scope.root_device, scope.root_inode
            HAVING COUNT(*) > 1
            """,
            "multiple repositories identify one host filesystem worktree",
        ),
        (
            "runtime_session_scope_mismatch",
            """
            SELECT session.session_id
            FROM runtime_sessions session
            JOIN repository_scopes scope ON scope.repo_id = session.repo_id
            JOIN repository_families family USING(family_id)
            WHERE scope.family_id != session.family_id
               OR family.root_repo_id != session.root_repo_id
            """,
            "runtime session repository context is inconsistent",
        ),
        (
            "runtime_service_resource_scope_mismatch",
            """
            SELECT resource.session_id || ':' || resource.resource_id
            FROM runtime_session_resources resource
            JOIN runtime_sessions session USING(session_id)
            LEFT JOIN server_definitions server
              ON server.server_definition_id = resource.resource_id
            WHERE resource.resource_kind = 'service'
              AND resource.cleanup_state IN ('active', 'retained')
              AND COALESCE(
                  CASE WHEN json_valid(resource.identity_json)
                       THEN json_extract(resource.identity_json, '$.state') END,
                  ''
              )
                  != 'reserved'
              AND (server.server_definition_id IS NULL
                   OR server.repo_id != session.repo_id)
            """,
            "runtime service resource does not belong to its session repository",
        ),
        (
            "runtime_docker_resource_scope_mismatch",
            """
            SELECT resource.session_id || ':' || resource.resource_id
            FROM runtime_session_resources resource
            JOIN runtime_sessions session USING(session_id)
            WHERE resource.resource_kind = 'docker'
              AND resource.cleanup_state IN ('active', 'retained')
              AND COALESCE(
                  CASE WHEN json_valid(resource.identity_json)
                       THEN json_extract(resource.identity_json, '$.state') END,
                  ''
              )
                  != 'reserved'
              AND NOT EXISTS (
                  SELECT 1 FROM repository_memberships membership
                  WHERE membership.resource_kind = 'container'
                    AND membership.host_resource_id = resource.resource_id
                    AND membership.repo_id = session.repo_id
              )
            """,
            "runtime Docker resource does not belong to its session repository",
        ),
        (
            "runtime_database_resource_scope_mismatch",
            """
            SELECT resource.session_id || ':' || resource.resource_id
            FROM runtime_session_resources resource
            JOIN runtime_sessions session USING(session_id)
            LEFT JOIN database_bindings binding
              ON binding.database_binding_id = resource.resource_id
            WHERE resource.resource_kind = 'database_stack'
              AND resource.cleanup_state IN ('active', 'retained')
              AND COALESCE(
                  CASE WHEN json_valid(resource.identity_json)
                       THEN json_extract(resource.identity_json, '$.state') END,
                  ''
              )
                  != 'reserved'
              AND (
                  binding.database_binding_id IS NULL
                  OR binding.repo_id != session.repo_id
                  OR NOT EXISTS (
                      SELECT 1 FROM repository_memberships membership
                      WHERE membership.resource_kind = 'container'
                        AND membership.host_resource_id = binding.docker_resource_id
                        AND membership.repo_id = session.repo_id
                  )
              )
            """,
            "runtime database resource does not belong to its session repository",
        ),
        (
            "worker_policy_repository_mismatch",
            """
            SELECT policy.server_definition_id
            FROM worker_policies policy
            JOIN server_definitions definition USING(server_definition_id)
            WHERE definition.repo_id IS NULL OR definition.repo_id != policy.repo_id
            """,
            "worker policy belongs to a different repository than its definition",
        ),
        (
            "worker_supervisor_repository_mismatch",
            """
            SELECT supervisor.server_definition_id
            FROM worker_supervisor_states supervisor
            JOIN server_definitions definition USING(server_definition_id)
            WHERE definition.repo_id IS NULL OR definition.repo_id != supervisor.repo_id
            """,
            "worker supervisor state belongs to a different repository than its definition",
        ),
        (
            "worker_current_attempt_mismatch",
            """
            SELECT supervisor.server_definition_id
            FROM worker_supervisor_states supervisor
            JOIN worker_attempts attempt
              ON attempt.attempt_id = supervisor.current_attempt_id
            WHERE attempt.server_definition_id != supervisor.server_definition_id
               OR attempt.repo_id != supervisor.repo_id
               OR attempt.state NOT IN ('reserved', 'running')
            """,
            "worker supervisor points to an unrelated or finalized attempt",
        ),
        (
            "worker_trip_link_missing",
            """
            SELECT policy.server_definition_id
            FROM worker_policies policy
            LEFT JOIN worker_attempts attempt
              ON attempt.attempt_id = policy.last_trip_attempt_id
            LEFT JOIN events event
              ON event.event_id = policy.last_trip_event_id
            WHERE policy.last_trip_attempt_id IS NOT NULL
              AND (attempt.attempt_id IS NULL
                   OR event.event_id IS NULL
                   OR attempt.server_definition_id != policy.server_definition_id
                   OR attempt.crash_event_id != policy.last_trip_event_id)
            """,
            "worker circuit-breaker trip does not link exact attempt and event evidence",
        ),
        (
            "worker_attempt_event_repository_mismatch",
            """
            SELECT attempt.attempt_id
            FROM worker_attempts attempt
            JOIN events event ON event.event_id = attempt.crash_event_id
            WHERE event.repo_id IS NULL OR event.repo_id != attempt.repo_id
            """,
            "worker crash event belongs to a different repository",
        ),
    )
    for code, sql, prefix in checks:
        for row in connection.execute(sql):
            violations.append(InvariantViolation(code, f"{prefix}: {row[0]}"))
    return violations
