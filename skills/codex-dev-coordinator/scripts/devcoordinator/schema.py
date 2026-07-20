"""SQLite schema and invariant contract for the normalized coordinator store."""

from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
from typing import Iterable


SCHEMA_VERSION = 4
MINIMUM_MIGRATABLE_SCHEMA_VERSION = 1


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
    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
    immutable_fingerprint TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    removed_at TEXT NOT NULL,
    PRIMARY KEY(target_kind, target_id)
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
        # tags exact legacy membership/policy digests before the metadata flip.
        # The caller owns one BEGIN IMMEDIATE transaction around this entire
        # function, so a malformed leftover rolls back both DDL and every
        # successfully converted fingerprint.
        previous = int(row[0])
        _upgrade_sha256_fingerprints_to_v4(connection)
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


def invariant_violations(connection: sqlite3.Connection) -> list[InvariantViolation]:
    """Return human-readable violations not expressible as local constraints."""

    violations: list[InvariantViolation] = []
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
    )
    for code, sql, prefix in checks:
        for row in connection.execute(sql):
            violations.append(InvariantViolation(code, f"{prefix}: {row[0]}"))
    return violations
