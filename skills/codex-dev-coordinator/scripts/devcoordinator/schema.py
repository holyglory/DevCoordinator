"""SQLite schema and invariant contract for the normalized coordinator store."""

from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
from typing import Iterable, Mapping

SCHEMA_VERSION = 16


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

-- Secret material is never stored in SQLite.  This table binds one server
-- environment name to an opaque deterministic credential file identity.
CREATE TABLE IF NOT EXISTS server_environment_credentials (
    server_definition_id TEXT NOT NULL REFERENCES server_definitions(server_definition_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE CHECK (
        length(credential_id) = 36
        AND substr(credential_id, 9, 1) = '-'
        AND substr(credential_id, 14, 1) = '-'
        AND substr(credential_id, 19, 1) = '-'
        AND substr(credential_id, 24, 1) = '-'
        AND length(replace(credential_id, '-', '')) = 32
        AND credential_id NOT GLOB '*[^0-9a-f-]*'
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
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
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp', 'udp')),
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
    target_kind TEXT NOT NULL CHECK(target_kind IN ('project', 'server', 'container', 'volume', 'worktree')),
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
    target_kind TEXT NOT NULL CHECK(target_kind IN ('project', 'server', 'container', 'volume', 'worktree')),
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
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE SET NULL,
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

CREATE TABLE IF NOT EXISTS docker_repository_hints (
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


def _execute_ddl(connection: sqlite3.Connection, ddl: str) -> None:
    statement = ""
    for line in ddl.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            statement = ""
            if sql:
                connection.execute(sql)
    if statement.strip():
        raise RuntimeError("coordinator schema contains an incomplete SQL statement")


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
    # security-assumptions.md confirms one trusted local developer: repository
    # enrollment was an authorization gate, not retained repository control.
    "broker_repository_enrollments",
    "broker_repository_configurations",
    "broker_assignment_owners",
    "broker_lease_owners",
    "broker_acl_principals",
)


def _schema_table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    if not _schema_table_exists(connection, table):
        return set()
    return {str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')}


def initialize_schema(
    connection: sqlite3.Connection,
    *,
    database_generation: str,
    timestamp: str,
) -> None:
    """Create the current schema or refuse an incompatible database."""

    tables = {
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        )
    }
    if "schema_metadata" not in tables:
        if tables:
            raise RuntimeError(
                "coordinator database has tables but no schema metadata; "
                "explicit recovery is required"
            )
        _execute_ddl(connection, DDL)
        connection.execute(
            """
            INSERT INTO schema_metadata(
                singleton, schema_version, database_generation, created_at, updated_at
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (SCHEMA_VERSION, database_generation, timestamp, timestamp),
        )
        return

    row = connection.execute(
        "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if row is None:
        raise RuntimeError("coordinator schema metadata singleton is missing")
    version = int(row[0])
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported coordinator database schema {version}; expected "
            f"{SCHEMA_VERSION}; run the retained-control rebaseline"
        )

    _execute_ddl(connection, DDL)
    forbidden = {
        "repository_memberships",
        "control_bindings",
        "repository_owners",
        "repository_owner_transfers",
        *_LEGACY_LOCAL_AUTHORIZATION_TABLES,
    }
    present = sorted(
        table for table in forbidden if _schema_table_exists(connection, table)
    )
    if present:
        raise RuntimeError(
            "trusted-local schema still contains obsolete authorization tables: "
            + ", ".join(present)
        )
    required_columns = {
        "docker_resources": {"repo_id"},
        "leases": {"protocol"},
        "server_environment_credentials": {
            "server_definition_id",
            "name",
            "credential_id",
            "created_at",
            "updated_at",
        },
    }
    for table, expected in required_columns.items():
        missing = expected - _table_columns(connection, table)
        if missing:
            raise RuntimeError(
                f"trusted-local schema table {table} is missing: "
                + ", ".join(sorted(missing))
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
            "repository scope crosses hosts",
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
            LEFT JOIN docker_resources docker
              ON docker.docker_resource_id = resource.resource_id
            WHERE resource.resource_kind = 'docker'
              AND resource.cleanup_state IN ('active', 'retained')
              AND COALESCE(
                  CASE WHEN json_valid(resource.identity_json)
                       THEN json_extract(resource.identity_json, '$.state') END,
                  ''
              )
                  != 'reserved'
              AND (docker.docker_resource_id IS NULL
                   OR docker.repo_id != session.repo_id)
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
            LEFT JOIN docker_resources docker
              ON docker.docker_resource_id = binding.docker_resource_id
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
                  OR docker.repo_id != session.repo_id
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
            "server_environment_transport_conflict",
            """
            SELECT literal.server_definition_id || ':' || literal.name
            FROM server_environment literal
            JOIN server_environment_credentials credential
              USING(server_definition_id, name)
            """,
            "server environment name has both literal and credential transport",
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
    # Import lazily: server_credentials uses store.deterministic_id, while the
    # store imports this module for its transaction invariant boundary.
    from .server_credentials import (  # pylint: disable=import-outside-toplevel
        ServerCredentialError,
        validate_server_credential_binding,
    )

    for row in connection.execute(
        "SELECT server_definition_id,name,credential_id "
        "FROM server_environment_credentials ORDER BY server_definition_id,name"
    ):
        try:
            validate_server_credential_binding(
                str(row[0]),
                {"name": str(row[1]), "credential_id": str(row[2])},
            )
        except ServerCredentialError:
            violations.append(
                InvariantViolation(
                    "server_environment_credential_binding_invalid",
                    "server credential binding does not match its definition and name: "
                    f"{row[0]}:{row[1]}",
                )
            )
    return violations
