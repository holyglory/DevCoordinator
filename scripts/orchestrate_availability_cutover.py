#!/usr/bin/env python3
"""Resumable, evidence-gated availability and test-history cutover.

This program owns the durable cutover ledger, split-UID SQLite backups, and
the small set of explicit maintenance-fenced broker transactions required for
authority readiness, exact listener-port reservation, and stale-repository
repair.  It validates artifacts produced by the existing history migrator and
broker drain, and refuses activation unless the exact migration seal, API
delegation, candidate topology, and socket-inode continuity are proved.
"""

from __future__ import annotations

import argparse
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import socket
import stat
import struct
import subprocess
import sys
import time
from typing import Any, Mapping
import uuid
from urllib.parse import urlparse

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from server_wide_installer_fence import (
    InstallerFenceError,
    InstallerFenceHandle,
    acquire_transaction_fence,
    transfer_transaction_fence,
)
import browser_lcp_acceptance as browser_lcp  # noqa: E402


ROOT = SCRIPT_ROOT.parent
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.universal_test_admission import (  # noqa: E402
    normalize_legacy_test_admission_drain_proof,
    verify_legacy_test_admission_drain_proof,
)
from devcoordinator.universal_test_capabilities import (  # noqa: E402
    SealedTestCapabilityRegistry,
)
from devcoordinator.universal_test_service import (  # noqa: E402
    decode_repository_setup_document,
)
from devcoordinator.universal_test_snapshot_service import (  # noqa: E402
    UnixSnapshotServiceClient,
)
from devcoordinator.universal_test_store import (  # noqa: E402
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)
from devcoordinator.broker_profile import (  # noqa: E402
    BrokerProfileError,
    profile_from_document,
)
from devcoordinator.broker import BrokerOperation, BrokerRequest  # noqa: E402
from devcoordinator.broker_cli import BrokerClient  # noqa: E402
from devcoordinator.broker_cli import (  # noqa: E402
    exclusive_broker_service_lock,
)
from devcoordinator.broker_host import LocalBrokerHostMutations  # noqa: E402
from devcoordinator.schema import invariant_violations  # noqa: E402
from devcoordinator.shared_root_positive_absence import (  # noqa: E402
    SharedRootPositiveAbsenceError,
    apply_shared_root_positive_absence,
    latest_shared_root_full_docker_observation,
    plan_shared_root_positive_absence,
    validate_shared_root_positive_absence_plan,
    validate_shared_root_positive_absence_result,
    verify_shared_root_positive_absence_terminal,
)
from devcoordinator.maintenance import (  # noqa: E402
    CONTROL_PLANE_MAINTENANCE_SCOPE,
    PUBLIC_MAINTENANCE_MESSAGE,
    MaintenanceMarkerError,
    activate_maintenance,
    clear_maintenance,
    load_maintenance_state,
    maintenance_writer_lock,
)


SCHEMA_VERSION = 1
STATE_KIND = "devcoordinator-availability-cutover"
BACKUP_KIND = "devcoordinator-cutover-database-backup"
INITIAL_IMPORT_KIND = "legacy-test-history-import-attestation"
SEAL_KIND = "universal-test-history-split-cutover-seal"
DELEGATION_KIND = "devcoordinator-api-actor-delegation-attestation"
CANDIDATE_KIND = "devcoordinator-cutover-candidate-attestation"
CANDIDATE_PREPARATION_KIND = "devcoordinator-candidate-preparation-attestation"
BACKGROUND_CONFIG_KIND = "devcoordinator-background-config-transaction"
CAPABILITY_POLICY_KIND = "devcoordinator-test-capability-policy-attestation"
AUTHORITY_REPOSITORY_EXPORT_KIND = "devcoordinator-authority-repository-export"
AUTHORITY_REPOSITORY_DISABLE_PLAN_KIND = (
    "devcoordinator-authority-repository-disable-plan"
)
AUTHORITY_REPOSITORY_DISABLE_RESULT_KIND = (
    "devcoordinator-authority-repository-disable-result"
)
AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_PLAN_KIND = (
    "devcoordinator-authority-repository-startup-policy-reconciliation-plan"
)
AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_RESULT_KIND = (
    "devcoordinator-authority-repository-startup-policy-reconciliation-result"
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_PLAN_KIND = (
    "devcoordinator-authority-repository-lifecycle-recovery-plan"
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_RESULT_KIND = (
    "devcoordinator-authority-repository-lifecycle-recovery-result"
)
PROFILE_REPAIR_KIND = "devcoordinator-api-profile-repair-attestation"
PROFILE_INVENTORY_READINESS_KIND = (
    "devcoordinator-post-v13-profile-inventory-readiness-attestation"
)
ACTIVATION_KIND = "devcoordinator-cutover-activation-attestation"
RETENTION_KIND = "devcoordinator-cutover-retention-attestation"
ROLLBACK_KIND = "devcoordinator-cutover-rollback-attestation"
ROLLBACK_REHEARSAL_KIND = "devcoordinator-cutover-rollback-rehearsal-attestation"
LIVE_ROLLBACK_REHEARSAL_KIND = (
    "devcoordinator-cutover-live-rollback-rehearsal-attestation"
)
FIRST_DEPLOYMENT_BOOTSTRAP_KIND = (
    "devcoordinator-first-deployment-bootstrap-attestation"
)
AUTHORITY_READINESS_INTENT_KIND = (
    "devcoordinator-authority-readiness-recovery-intent"
)
AUTHORITY_READINESS_RESULT_KIND = (
    "devcoordinator-authority-readiness-recovery-attestation"
)
AUTHORITY_READINESS_TRANSACTION_KIND = (
    "devcoordinator-authority-readiness-service-transaction"
)
AUTHORITY_READINESS_TRANSACTION_RESULT_KIND = (
    "devcoordinator-authority-readiness-service-transaction-attestation"
)
AUTHORITY_READINESS_REBIND_KIND = (
    "devcoordinator-authority-readiness-release-rebind-attestation"
)
AUTHORITY_READINESS_REBIND_TRANSACTION_KIND = (
    "devcoordinator-authority-readiness-release-rebind-service-transaction"
)
AUTHORITY_READINESS_REBIND_TRANSACTION_RESULT_KIND = (
    "devcoordinator-authority-readiness-release-rebind-service-attestation"
)
AUTHORITY_READINESS_REATTEST_INTENT_KIND = (
    "devcoordinator-authority-readiness-release-reattestation-intent"
)
AUTHORITY_READINESS_REATTEST_KIND = (
    "devcoordinator-authority-readiness-release-reattestation"
)
ATOMIC_FIRST_ADOPTION_BINDING_TRANSACTION_KIND = (
    "devcoordinator-atomic-first-adoption-binding-service-transaction"
)
ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND = (
    "devcoordinator-atomic-first-adoption-binding-service-attestation"
)
SCHEMA13_FIRST_ADOPTION_INSTALLER_OWNER_KIND = (
    "schema13-first-adoption-executor"
)
ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND = (
    "devcoordinator-atomic-first-adoption-binding-finalization-intent"
)
AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_KIND = (
    "devcoordinator-authority-repository-disable-service-transaction"
)
AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_KIND = (
    "devcoordinator-authority-repository-disable-service-transaction-attestation"
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_KIND = (
    "devcoordinator-authority-repository-lifecycle-recovery-service-transaction"
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_RESULT_KIND = (
    "devcoordinator-authority-repository-lifecycle-recovery-service-attestation"
)
FIRST_ADOPTION_PORT_RESERVATION_INTENT_KIND = (
    "devcoordinator-first-adoption-port-reservation-intent"
)
FIRST_ADOPTION_PORT_RESERVATIONS_KIND = (
    "devcoordinator-first-adoption-port-reservations"
)
ATOMIC_FIRST_ADOPTION_PREPARED_KIND = (
    "devcoordinator-atomic-first-adoption-bindings-prepared"
)
ATOMIC_FIRST_ADOPTION_POST_START_READY_KIND = (
    "devcoordinator-atomic-first-adoption-post-start-ready"
)
FIRST_ADOPTION_AUTHORITY_ADOPTION_KIND = (
    "devcoordinator-authority-first-adoption"
)
FIRST_ADOPTION_AUTHORITY_ADOPTION_FIELDS = frozenset(
    {
        "operation_id",
        "release_digest",
        "source",
        "authority",
        "inventory",
        "storage_split",
        "owner_authority",
        "pointer_path",
        "legacy_source_original_path",
        "source_rotated",
        "retained_source_is_rollback",
        "legacy_unit",
        "maintenance",
        "created_at",
    }
)
AUTHORITY_FIRST_ADOPTION_KIND = "devcoordinator-authority-first-adoption"
CONTINUITY_PROBE_KIND = "devcoordinator-continuity-probe-attestation"
DEFAULT_RESERVE_BYTES = 1024 * 1024 * 1024
MAX_DOCUMENT_BYTES = 1024 * 1024
PHASES = (
    "planned",
    "backups_verified",
    "initial_migrated",
    "admission_drained",
    "tail_migrated",
    "sealed",
    "candidate_verified",
    "activated",
    "retained",
    "rolled_back",
)
SOCKET_NAMES = frozenset(
    {
        "edge-http",
        "edge-https",
        "api",
        "authority",
        "testd",
        "snapshotd",
    }
)
REQUIRED_READY_UNITS = frozenset(
    {
        "devcoordinator-edge.service",
        "devcoordinator-api.service",
        "devcoordinator-authority.service",
        "devcoordinator-observer.service",
        "devcoordinator-testd.service",
        "devcoordinator-test-snapshotd.service",
    }
)
CONTROL_SLICE = "devcoordinator-control.slice"
BACKGROUND_SLICE = "devcoordinator-background.slice"
PROTECTED_PROFILE_PATH = "/etc/devcoordinator/client-profiles.json"
TEST_CAPABILITY_POLICY_PATH = "/etc/devcoordinator/test-execution-capabilities.json"
PROTECTED_PROFILE_GROUP = "devcoordinator-clients"
API_BROKER_ACCOUNT = "devcoordinator-api"
GOOGLE_ACTOR_POLICY = "normalized-lowercase-google-email-only"
AUTHORITY_SOCKET_PATH = "/run/devcoordinator-authority.sock"
IMMUTABLE_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
FINAL_AUTHORITY_DATABASE_PATH = "/var/lib/devcoordinator/authority.sqlite3"
MAX_REPOSITORY_DIAGNOSTIC_ENROLLMENTS = 1024
MAX_REPOSITORY_STARTUP_POLICIES = 4096
SHARED_TEMPORARY_REPOSITORY_ROOTS = frozenset({"/tmp"})
AUTHORITY_REPOSITORY_REPAIR_ACTOR = "devcoordinator-authority-repair"
AUTHORITY_REPOSITORY_REPAIR_REASON = (
    "shared temporary directory is not a canonical Git repository"
)
AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_REASON = (
    "disable startup policies left enabled by repository authority repair"
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_REASON = (
    "restore repository lifecycle authority after incomplete shared-root repair"
)
FIRST_ADOPTION_PORT_ROLES = (
    "console_outer",
    "console_inner",
    "handoff_http",
    "handoff_https",
    "handoff_api",
)
FIRST_ADOPTION_CONSOLE_PORT_ROLES = frozenset(
    {"console_outer", "console_inner"}
)
FIRST_ADOPTION_HANDOFF_PORT_ROLES = frozenset(
    {"handoff_http", "handoff_https", "handoff_api"}
)
FIRST_ADOPTION_PORT_RANGE = {"start": 30000, "end": 60999}
MIN_FIRST_ADOPTION_HANDOFF_TTL_SECONDS = 60
MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS = 86400
EVIDENCE_KEYS = frozenset(
    {
        "authority-backup",
        "testd-backup",
        "initial-import",
        "admission-drain",
        "final-import",
        "migration-seal",
        "test-history-discard",
        "api-delegation",
        "profile-inventory-readiness",
        "candidate",
        "activation",
        "retention",
        "rollback",
        "rollback-rehearsal",
        "live-rollback-rehearsal",
        "first-deployment-bootstrap",
        "authority-readiness",
        "first-adoption-port-reservations",
    }
)

AUTHORITY_READINESS_INTENT_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "database",
        "database_identity",
        "maintenance",
        "writer_lock",
        "backup",
        "precondition",
        "target",
        "created_at",
    }
)

AUTHORITY_READINESS_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "intent_sha256",
        "release",
        "release_digest",
        "database",
        "database_identity_before",
        "database_identity_after",
        "maintenance",
        "writer_lock",
        "backup",
        "precondition",
        "postcondition",
        "applied",
        "recovered",
        "completed_at",
    }
)

AUTHORITY_READINESS_TABLES = frozenset(
    {
        "schema_metadata",
        "hosts",
        "repositories",
        "repository_installations",
        "broker_acl_principals",
        "broker_repository_enrollments",
        "migration_conflicts",
    }
)
AUTHORITY_READINESS_PARTIAL_V13_TABLES = frozenset(
    {"repository_owners", "repository_owner_transfers"}
)
AUTHORITY_READINESS_TRANSACTION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "database",
        "service_unit",
        "service_baseline",
        "maintenance",
        "recovery",
        "created_at",
    }
)
AUTHORITY_READINESS_TRANSACTION_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "transaction_journal_sha256",
        "authority_readiness_sha256",
        "release_digest",
        "database",
        "service_unit",
        "service_restored",
        "maintenance_cleared",
        "completed_at",
    }
)
AUTHORITY_READINESS_REBIND_FIELDS = frozenset(
    {
        "operation_id",
        "prior_attestation",
        "prior_release_digest",
        "release",
        "release_digest",
        "database",
        "database_identity",
        "database_sha256",
        "writer_lock",
        "backup",
        "precondition",
        "postcondition",
        "mutation_applied",
        "created_at",
    }
)
AUTHORITY_READINESS_REBIND_TRANSACTION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "database",
        "prior_attestation",
        "attestation",
        "service_unit",
        "service_baseline",
        "maintenance",
        "created_at",
    }
)
AUTHORITY_READINESS_REBIND_TRANSACTION_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "transaction_journal_sha256",
        "readiness_rebind_sha256",
        "release_digest",
        "database",
        "service_unit",
        "service_restored",
        "maintenance_cleared",
        "completed_at",
    }
)
AUTHORITY_READINESS_REATTEST_INTENT_FIELDS = frozenset(
    {
        "operation_id",
        "prior_attestation",
        "prior_release_digest",
        "quiescence_attestation",
        "release",
        "release_digest",
        "database",
        "database_identity",
        "database_sha256",
        "service_unit",
        "service_stopped",
        "maintenance",
        "writer_lock",
        "backup",
        "precondition",
        "created_at",
    }
)
AUTHORITY_READINESS_REATTEST_FIELDS = frozenset(
    {
        "operation_id",
        "intent",
        "prior_attestation",
        "prior_release_digest",
        "quiescence_attestation",
        "release",
        "release_digest",
        "database",
        "database_identity_before",
        "database_identity_after",
        "database_sha256",
        "service_unit",
        "service_stopped",
        "maintenance",
        "writer_lock",
        "backup",
        "precondition",
        "postcondition",
        "mutation_applied",
        "completed_at",
    }
)

ATOMIC_FIRST_ADOPTION_BINDING_TRANSACTION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "database",
        "prior_attestation",
        "readiness_attestation",
        "port_journal",
        "port_pending_attestation",
        "port_attestation",
        "finalization_journal",
        "transaction_attestation",
        "repository_id",
        "repository_generation",
        "canonical_root",
        "handoff_ttl_seconds",
        "service_unit",
        "service_baseline",
        "maintenance",
        "post_start_readiness",
        "created_at",
    }
)
ATOMIC_FIRST_ADOPTION_POST_START_READINESS_FIELDS = frozenset(
    {
        "transaction",
        "operation_id",
        "journal_sha256",
        "journal_document_sha256",
        "profile",
        "socket",
        "dropin",
        "canary_user",
        "canary_owner_uid",
        "canary_project",
        "canary_repository_id",
        "canary_repository_generation",
        "proof_attestation",
    }
)
ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_FIELDS = frozenset(
    {
        "operation_id",
        "transaction_journal_sha256",
        "prepared_attestation_sha256",
        "readiness_rebind_sha256",
        "state_path",
        "state_document_sha256",
        "state_generation",
        "final_state_document_sha256",
        "final_state_generation",
        "state_updated_at",
        "authorized_snapshot",
        "final_port_reservations",
        "created_at",
    }
)
ATOMIC_FIRST_ADOPTION_BINDING_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "outcome",
        "transaction_journal_sha256",
        "readiness_rebind_sha256",
        "port_reservations_sha256",
        "release_digest",
        "database",
        "service_unit",
        "service_restored",
        "maintenance_cleared",
        "completed_at",
    }
)

AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "plan",
        "plan_document_sha256",
        "database",
        "service_unit",
        "service_baseline",
        "readiness",
        "maintenance",
        "repair_attestation",
        "created_at",
    }
)
AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "transaction_journal_sha256",
        "repair_result_sha256",
        "release_digest",
        "database",
        "service_unit",
        "readiness_proof",
        "service_restored",
        "maintenance_cleared",
        "completed_at",
    }
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "canary_release",
        "canary_release_digest",
        "plan",
        "plan_document_sha256",
        "database",
        "service_unit",
        "service_baseline",
        "readiness",
        "predecessor",
        "maintenance",
        "recovery_attestation",
        "created_at",
    }
)
AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "transaction_journal_sha256",
        "recovery_result_sha256",
        "release_digest",
        "canary_release_digest",
        "database",
        "service_unit",
        "maintenance",
        "predecessor_proof",
        "preclear_readiness",
        "service_restored",
        "maintenance_cleared",
        "successor_handoff_required",
        "completed_at",
    }
)

FIRST_ADOPTION_PORT_RESERVATION_INTENT_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "authority_database",
        "attestation",
        "authority_generation",
        "authority_state_revision_before",
        "repository_id",
        "repository_generation",
        "canonical_root",
        "port_range",
        "handoff_ttl_seconds",
        "handoff_expires_at",
        "row_ids",
        "agent",
        "purposes",
        "service_unit",
        "service_baseline",
        "maintenance",
        "created_at",
    }
)

FIRST_ADOPTION_PORT_RESERVATIONS_FIELDS = frozenset(
    {
        "operation_id",
        "release_digest",
        "authority_database",
        "authority_generation",
        "authority_state_revision_before",
        "authority_state_revision_after",
        "repository_id",
        "repository_generation",
        "canonical_root",
        "port_range",
        "handoff_ttl_seconds",
        "reservations",
        "transaction_journal_sha256",
        "service_unit",
        "service_restored",
        "maintenance_cleared",
        "created_at",
        "completed_at",
    }
)
ATOMIC_FIRST_ADOPTION_PREPARED_FIELDS = frozenset(
    {
        "operation_id",
        "release_digest",
        "authority_database",
        "authority_generation",
        "authority_state_revision_before",
        "authority_state_revision_after",
        "repository_id",
        "repository_generation",
        "canonical_root",
        "port_range",
        "handoff_ttl_seconds",
        "reservations",
        "port_journal_sha256",
        "atomic_transaction_journal_sha256",
        "service_unit",
        "service_stopped",
        "maintenance",
        "created_at",
        "completed_at",
    }
)

AUTHORITY_FIRST_ADOPTION_FIELDS = frozenset(
    {
        "operation_id",
        "release_digest",
        "source",
        "authority",
        "inventory",
        "storage_split",
        "owner_authority",
        "pointer_path",
        "legacy_source_original_path",
        "source_rotated",
        "retained_source_is_rollback",
        "legacy_unit",
        "maintenance",
        "created_at",
    }
)

FIRST_DEPLOYMENT_BOOTSTRAP_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "release_digest",
        "rendered_units",
        "sysusers_config_sha256",
        "tmpfiles_config_sha256",
        "service_identities",
        "private_directories",
        "authority_database",
        "inventory_database",
        "test_database",
        "test_store",
        "schema_readiness",
        "created_at",
    }
)

SCHEMA_READINESS_KIND = "universal-test-store-schema-readiness-attestation"
DISCARD_TEST_HISTORY_CONFIRMATION = "discard-test-history"
SCHEMA_READINESS_FIELDS = frozenset(
    {
        "operation_id",
        "test_database",
        "action",
        "journal_kind",
        "journal",
        "store",
        "published_at",
    }
)

PROFILE_REPAIR_FIELDS = frozenset(
    {
        "profile_path",
        "profile_owner_uid",
        "profile_group_gid",
        "profile_mode",
        "profile_sha256",
        "source_authority_generation",
        "authority_generation",
        "authority_source_sha256",
        "api_uid",
        "broker_account_id",
        "repository_ids",
        "client_uids",
        "repository_bindings",
        "parser_verified",
        "all_clients_parser_verified",
        "existing_profile_contents_reused",
        "atomic_publication_verified",
        "created_at",
    }
)

PROFILE_INVENTORY_READINESS_FIELDS = frozenset(
    {
        "profile_repair_sha256",
        "api_delegation_sha256",
        "release_digest",
        "executor_release",
        "inventory_client_sha256",
        "authority_database",
        "source_authority_generation",
        "authority_generation",
        "authority_schema_version",
        "authority_migration_state",
        "profile_path",
        "profile_sha256",
        "profile_owner_uid",
        "profile_group_gid",
        "profile_mode",
        "full_regeneration",
        "strict_profile_parse",
        "project",
        "owner_uid",
        "owner_account_id",
        "repository_id",
        "repository_generation",
        "owner_bound_grant",
        "inventory_command",
        "inventory_sha256",
        "inventory_schema_version",
        "inventory_scope",
        "inventory_transport",
        "inventory_service_uid",
        "inventory_database_generation",
        "verified_at",
    }
)

AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS = frozenset(
    {
        "plan_id",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "authority_state_revision",
        "database_identity",
        "repository",
        "startup_policies",
        "enrollment_count",
        "shared_temporary_root",
        "git_metadata_absent",
        "target",
        "reason",
        "created_at",
    }
)

LEGACY_AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS = frozenset(
    AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS - {"startup_policies"}
)

AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS = frozenset(
    {
        "plan_id",
        "plan_document_sha256",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "maintenance_deployment_id",
        "database_identity_before",
        "database_identity_after",
        "repository_id",
        "repository_generation_before",
        "repository_generation_after",
        "installation_generation_before",
        "installation_generation_after",
        "state_revision_before",
        "state_revision_after",
        "repository_state",
        "installation_status",
        "startup_fenced",
        "startup_policy_count",
        "startup_policy_update_count",
        "startup_policies",
        "enrollment_count",
        "reason",
        "actor",
        "applied_at",
    }
)

LEGACY_AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS = frozenset(
    AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS
    - {
        "startup_policy_count",
        "startup_policy_update_count",
        "startup_policies",
    }
)

AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_PLAN_FIELDS = frozenset(
    {
        "plan_id",
        "source_repair_plan_sha256",
        "source_repair_result_sha256",
        "source_repair_plan_id",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "authority_state_revision",
        "database_identity",
        "repository",
        "startup_policies",
        "enrollment_count",
        "shared_temporary_root",
        "git_metadata_absent",
        "mutation_updated_at",
        "reason",
        "created_at",
    }
)

AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_RESULT_FIELDS = frozenset(
    {
        "plan_id",
        "plan_document_sha256",
        "source_repair_plan_sha256",
        "source_repair_result_sha256",
        "source_repair_plan_id",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "maintenance_deployment_id",
        "database_identity_before",
        "database_identity_after",
        "repository_id",
        "repository_generation",
        "installation_generation",
        "state_revision_before",
        "state_revision_after",
        "startup_policy_count",
        "startup_policy_update_count",
        "startup_policies",
        "enrollment_count",
        "reason",
        "actor",
        "applied_at",
    }
)

AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_PLAN_FIELDS = frozenset(
    {
        "plan_id",
        "operation_id",
        "source_repair_plan_sha256",
        "source_repair_result_sha256",
        "source_repair_plan_id",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "authority_schema_version",
        "authority_migration_state",
        "authority_state_revision",
        "database_identity",
        "repository",
        "protected_rows",
        "owner_authority",
        "target",
        "mutation_updated_at",
        "reason",
        "created_at",
    }
)

AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_RESULT_FIELDS = frozenset(
    {
        "plan_id",
        "operation_id",
        "plan_document_sha256",
        "source_repair_plan_sha256",
        "source_repair_result_sha256",
        "authority_database",
        "authority_uid",
        "authority_generation",
        "authority_schema_version",
        "authority_migration_state",
        "maintenance_deployment_id",
        "database_identity_before",
        "database_identity_after",
        "repository_id",
        "repository_generation_before",
        "repository_generation_after",
        "installation_generation_before",
        "installation_generation_after",
        "state_revision_before",
        "state_revision_after",
        "protected_rows",
        "owner_authority_before",
        "owner_authority_after",
        "repository_state",
        "installation_status",
        "startup_fenced",
        "enrollment_count",
        "reason",
        "actor",
        "applied_at",
    }
)


class CutoverError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def seal(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {"schema_version": SCHEMA_VERSION, "kind": kind, **dict(values)}
    if "document_sha256" in document:
        raise CutoverError("sealed evidence contains a reserved digest field")
    document["document_sha256"] = _digest(document)
    return document


def verify_seal(
    value: object,
    *,
    kind: str,
    fields: frozenset[str] | set[str],
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CutoverError(f"{kind} evidence must be an object")
    expected = {"schema_version", "kind", "document_sha256", *fields}
    if set(value) != expected or value.get("schema_version") != 1 or value.get("kind") != kind:
        raise CutoverError(f"{kind} evidence fields are invalid")
    digest = value.get("document_sha256")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or _digest(unsigned) != digest
    ):
        raise CutoverError(f"{kind} evidence digest is invalid")
    return dict(value)


def _absolute(value: str | Path, field: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise CutoverError(f"{field} must be an absolute path")
    return Path(os.path.abspath(path))


def _private_parent(path: Path, *, uid: int) -> None:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or path.resolve(strict=True) != path
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise CutoverError(f"private directory is unsafe: {path}")


def _private_file(path: Path, *, uid: int, maximum: int = MAX_DOCUMENT_BYTES) -> bytes:
    _private_parent(path.parent, uid=uid)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or path.resolve(strict=True) != path
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > maximum
    ):
        raise CutoverError(f"private evidence is unsafe: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        payload = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(payload) > maximum:
        raise CutoverError("private evidence exceeds its byte bound")
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ):
        raise CutoverError("private evidence changed while it was read")
    return payload


def read_private_json(path: Path, *, uid: int) -> dict[str, object]:
    try:
        value = json.loads(_private_file(path, uid=uid))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CutoverError(f"private JSON evidence is invalid: {path}") from error
    if not isinstance(value, dict):
        raise CutoverError("private JSON evidence must be an object")
    return value


def _write_private_json(
    path: Path,
    document: Mapping[str, object],
    *,
    uid: int,
    create: bool,
    expected_generation: int | None = None,
) -> None:
    if os.geteuid() != uid:
        raise CutoverError("cutover ledger publisher is not the authority UID")
    path = _absolute(path, "cutover ledger")
    _private_parent(path.parent, uid=uid)
    lock = path.with_name(f".{path.name}.lock")
    descriptor = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != uid
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise CutoverError("cutover ledger lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        exists = path.exists() or path.is_symlink()
        if create and exists:
            current = load_state(path, authority_uid=uid)
            if dict(current) == dict(document):
                return
            raise CutoverError("cutover ledger already exists with another plan")
        if not create:
            if not exists:
                raise CutoverError("cutover ledger does not exist")
            current = load_state(path, authority_uid=uid)
            if current["state_generation"] != expected_generation:
                raise CutoverError("cutover ledger generation changed")
        payload = _canonical(document) + b"\n"
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
        temp = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(temp, payload)
            os.fsync(temp)
        finally:
            os.close(temp)
        try:
            if create:
                os.link(temporary, path, follow_symlinks=False)
                temporary.unlink()
            else:
                os.replace(temporary, path)
            parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


STATE_FIELDS = frozenset(
    {
        "cutover_id",
        "phase",
        "release",
        "release_digest",
        "rendered_units",
        "authority_uid",
        "testd_uid",
        "legacy_authority_database",
        "authority_database",
        "test_database",
        "inventory_canary_project",
        "authority_backup_directory",
        "test_backup_directory",
        "migration_state",
        "drain_proof",
        "cutover_seal",
        "reserve_bytes",
        "retain_until",
        "authority_backup_required",
        "evidence",
        "created_at",
        "updated_at",
        "state_generation",
    }
)
LEGACY_STATE_FIELDS = STATE_FIELDS - {"legacy_authority_database"}


def validate_state(value: object) -> dict[str, object]:
    try:
        state = verify_seal(value, kind=STATE_KIND, fields=STATE_FIELDS)
    except CutoverError:
        # Ledgers sealed before first-adoption split planning used one
        # authority path for both the live source and the future destination.
        # Normalize them in memory so a sealed first-adoption request can bind
        # the distinct final path without discarding completed migration
        # evidence.  The next durable write upgrades the ledger to STATE_FIELDS.
        legacy = verify_seal(value, kind=STATE_KIND, fields=LEGACY_STATE_FIELDS)
        unsigned = {
            key: item
            for key, item in legacy.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["legacy_authority_database"] = legacy["authority_database"]
        state = seal(STATE_KIND, unsigned)
    try:
        cutover_id = str(uuid.UUID(str(state["cutover_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("cutover ID is invalid") from error
    if state["phase"] not in PHASES:
        raise CutoverError("cutover phase is invalid")
    for field in (
        "release",
        "rendered_units",
        "legacy_authority_database",
        "authority_database",
        "test_database",
        "inventory_canary_project",
        "authority_backup_directory",
        "test_backup_directory",
        "migration_state",
        "drain_proof",
        "cutover_seal",
    ):
        _absolute(str(state[field]), field)
    if (
        type(state["authority_uid"]) is not int
        or int(state["authority_uid"]) != 0
        or type(state["testd_uid"]) is not int
        or int(state["testd_uid"]) <= 0
        or state["authority_uid"] == state["testd_uid"]
    ):
        raise CutoverError("authority and testd require distinct service UIDs")
    if (
        state["legacy_authority_database"] == state["test_database"]
        or state["authority_database"] == state["test_database"]
    ):
        raise CutoverError("authority and testd databases must be distinct")
    if re.fullmatch(r"[0-9a-f]{64}", str(state["release_digest"])) is None:
        raise CutoverError("cutover release digest is invalid")
    if type(state["reserve_bytes"]) is not int or int(state["reserve_bytes"]) < 0:
        raise CutoverError("cutover reserve is invalid")
    if type(state["authority_backup_required"]) is not bool:
        raise CutoverError("cutover authority backup requirement is invalid")
    if type(state["state_generation"]) is not int or int(state["state_generation"]) < 0:
        raise CutoverError("cutover ledger generation is invalid")
    try:
        retain_until = datetime.fromisoformat(
            str(state["retain_until"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise CutoverError("cutover retention timestamp is invalid") from error
    if retain_until.tzinfo is None:
        raise CutoverError("cutover retention timestamp must include a timezone")
    if not isinstance(state["evidence"], dict):
        raise CutoverError("cutover evidence index is invalid")
    if set(state["evidence"]) - EVIDENCE_KEYS or any(
        not isinstance(item, Mapping) for item in state["evidence"].values()
    ):
        raise CutoverError("cutover evidence index contains an invalid entry")
    bootstrap = state["evidence"].get("first-deployment-bootstrap")
    if bootstrap is not None:
        validated_bootstrap = _first_deployment_bootstrap(
            bootstrap,
            expected_release=str(state["release_digest"]),
            expected_test_database=str(state["test_database"]),
            expected_testd_uid=int(state["testd_uid"]),
        )
    else:
        validated_bootstrap = None
    readiness = state["evidence"].get("authority-readiness")
    if readiness is not None:
        validated_readiness = _authority_readiness_evidence(readiness)
        if (
            validated_readiness["release"] != state["release"]
            or validated_readiness["release_digest"] != state["release_digest"]
            or validated_readiness["database"]
            != state["legacy_authority_database"]
        ):
            raise CutoverError("authority readiness evidence changed its cutover binding")
    reservations = state["evidence"].get("first-adoption-port-reservations")
    if reservations is not None:
        if readiness is None:
            raise CutoverError(
                "first-adoption port evidence requires authority readiness"
            )
        validated_reservations = verify_first_adoption_port_evidence(
            reservations
        )
        _validate_first_adoption_port_readiness_binding(
            readiness=validated_readiness,
            reservations=validated_reservations,
            release_digest=str(state["release_digest"]),
            authority_database=str(state["legacy_authority_database"]),
            inventory_canary_project=str(state["inventory_canary_project"]),
        )
    discarded = state["evidence"].get("test-history-discard")
    migrated = state["evidence"].get("migration-seal")
    if discarded is not None and migrated is not None:
        raise CutoverError(
            "cutover cannot both migrate and discard legacy test history"
        )
    if discarded is not None:
        fresh = _fresh_test_store_attestation(
            discarded,
            expected_test_database=str(state["test_database"]),
        )
        legacy_history_keys = {
            "testd-backup",
            "initial-import",
            "admission-drain",
            "final-import",
            "migration-seal",
        }
        if (
            validated_bootstrap is None
            or fresh["store"] != validated_bootstrap["test_store"]
            or legacy_history_keys & set(state["evidence"])
            or state["phase"]
            in {
                "planned",
                "backups_verified",
                "initial_migrated",
                "admission_drained",
                "tail_migrated",
            }
        ):
            raise CutoverError(
                "discarded Test Store evidence contradicts the cutover ledger"
            )
    state["cutover_id"] = cutover_id
    return state


def load_state(path: Path, *, authority_uid: int) -> dict[str, object]:
    return validate_state(read_private_json(path, uid=authority_uid))


def bind_first_adoption_authority_paths(
    *,
    state_path: Path,
    legacy_authority_database: Path,
    authority_database: Path,
    authority_uid: int,
) -> dict[str, object]:
    """Durably bind an older sealed ledger to distinct source/final paths.

    This is intentionally the only compatibility write for pre-split ledgers.
    It is replay-safe, requires the completed migration seal, and occurs before
    the first-adoption transaction mutates services or databases.
    """

    state_path = _absolute(state_path, "cutover ledger")
    legacy_path = _absolute(
        legacy_authority_database, "legacy authority database"
    )
    final_path = _absolute(authority_database, "final authority database")
    if legacy_path == final_path:
        raise CutoverError("legacy and final authority databases must be distinct")
    current = load_state(state_path, authority_uid=authority_uid)
    if current["phase"] != "sealed":
        raise CutoverError(
            "first-adoption authority paths require the exact sealed legacy source"
        )
    _test_store_cutover_completion(current)
    if current["legacy_authority_database"] != str(legacy_path):
        raise CutoverError(
            "first-adoption authority paths require the exact sealed legacy source"
        )
    current_final = str(current["authority_database"])
    if current_final == str(final_path):
        return current
    if current_final != str(legacy_path):
        raise CutoverError(
            "cutover ledger is already bound to another final authority database"
        )
    unsigned = {
        key: item
        for key, item in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned.update(
        {
            "authority_database": str(final_path),
            "updated_at": _now(),
            "state_generation": int(current["state_generation"]) + 1,
        }
    )
    updated = seal(STATE_KIND, unsigned)
    validate_state(updated)
    _write_private_json(
        state_path,
        updated,
        uid=authority_uid,
        create=False,
        expected_generation=int(current["state_generation"]),
    )
    return updated


def _load_release_verifier():
    path = ROOT / "scripts/install_availability_release.py"
    spec = importlib.util.spec_from_file_location("cutover_release_installer", path)
    if spec is None or spec.loader is None:
        raise CutoverError("immutable release verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_topology_verifier():
    path = ROOT / "scripts/check_availability_topology.py"
    spec = importlib.util.spec_from_file_location("cutover_topology", path)
    if spec is None or spec.loader is None:
        raise CutoverError("topology verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_schema12_bridge_verifier():
    path = ROOT / "scripts/bridge_schema12_legacy_broker.py"
    spec = importlib.util.spec_from_file_location(
        "cutover_schema12_bridge_verifier", path
    )
    if spec is None or spec.loader is None:
        raise CutoverError("schema-12 bridge verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _database_identity(path: Path, *, uid: int) -> dict[str, int]:
    path = _absolute(path, "database")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or path.resolve(strict=True) != path
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise CutoverError(f"database identity is unsafe: {path}")
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
    }


def _bounded_command_status(argv: list[str]) -> int:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise CutoverError("bootstrap command arguments are invalid")
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CutoverError("bootstrap command could not execute") from error
    if len(completed.stdout) > 8192 or len(completed.stderr) > 8192:
        raise CutoverError("bootstrap command output exceeded its bound")
    return int(completed.returncode)


def _bootstrap_config(path: Path, *, authority_uid: int, name: str) -> str:
    path = _absolute(path, name)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or path.resolve(strict=True) != path
        or info.st_uid != authority_uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size > 128 * 1024
    ):
        raise CutoverError(f"{name} is unsafe")
    return _file_digest(path)


def _directory_identity(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> dict[str, object]:
    path = _absolute(path, "bootstrap private directory")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or path.resolve(strict=True) != path
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise CutoverError(f"bootstrap private directory is unsafe: {path}")
    return {
        "path": str(path),
        "uid": uid,
        "gid": gid,
        "mode": f"{mode:04o}",
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
    }


def _availability_identities() -> dict[str, object]:
    users: dict[str, dict[str, int]] = {
        "root": {"uid": 0, "gid": 0},
    }
    for name in (
        "devcoordinator-edge",
        "devcoordinator-console",
        "devcoordinator-api",
        "devcoordinator-observer",
        "devcoordinator-testd",
        "devcoordinator-notifications",
    ):
        try:
            entry = pwd.getpwnam(name)
        except KeyError as error:
            raise CutoverError(f"availability identity is missing: {name}") from error
        if entry.pw_uid <= 0 or entry.pw_gid <= 0:
            raise CutoverError(f"availability identity is invalid: {name}")
        users[name] = {"uid": int(entry.pw_uid), "gid": int(entry.pw_gid)}
    service_uids = [item["uid"] for key, item in users.items() if key != "root"]
    if len(service_uids) != len(set(service_uids)):
        raise CutoverError("availability service UIDs are not distinct")
    # Trusted-local transports and retained projections no longer use one
    # shared authorization group. Dedicated service identities remain for
    # cgroup/state ownership, while local API/socket access is mode-based.
    return {"users": users, "groups": {}}


def _first_deployment_bootstrap(
    value: object,
    *,
    expected_release: str | None = None,
    expected_test_database: str | None = None,
    expected_testd_uid: int | None = None,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=FIRST_DEPLOYMENT_BOOTSTRAP_KIND,
        fields=FIRST_DEPLOYMENT_BOOTSTRAP_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("first-deployment bootstrap operation ID is invalid") from error
    identities = document.get("service_identities")
    users = identities.get("users") if isinstance(identities, Mapping) else None
    groups = identities.get("groups") if isinstance(identities, Mapping) else None
    testd = users.get("devcoordinator-testd") if isinstance(users, Mapping) else None
    store = document.get("test_store")
    readiness = document.get("schema_readiness")
    if (
        not isinstance(identities, Mapping)
        or set(identities) != {"users", "groups"}
        or not isinstance(groups, Mapping)
        or bool(groups)
        or not isinstance(testd, Mapping)
        or type(testd.get("uid")) is not int
        or int(testd["uid"]) <= 0
        or not isinstance(store, Mapping)
        or store.get("schema_version") != 5
        or not isinstance(store.get("store_generation"), str)
        or not isinstance(readiness, Mapping)
        or set(readiness)
        != {"path", "document_sha256", "branch", "store_generation"}
        or readiness.get("branch") != "attested-fresh-v5"
        or readiness.get("store_generation") != store.get("store_generation")
        or re.fullmatch(r"[0-9a-f]{64}", str(readiness.get("document_sha256")))
        is None
    ):
        raise CutoverError("first-deployment bootstrap store evidence is invalid")
    if expected_release is not None and document["release_digest"] != expected_release:
        raise CutoverError("first-deployment bootstrap release changed")
    if (
        expected_test_database is not None
        and document["test_database"] != expected_test_database
    ):
        raise CutoverError("first-deployment bootstrap test database changed")
    if expected_testd_uid is not None and int(testd["uid"]) != expected_testd_uid:
        raise CutoverError("first-deployment bootstrap testd UID changed")
    return document


def _fresh_test_store_attestation(
    value: object,
    *,
    expected_test_database: str | None = None,
) -> dict[str, object]:
    """Validate the testd-owned proof consumed by destructive first adoption."""

    document = verify_seal(
        value,
        kind=SCHEMA_READINESS_KIND,
        fields=SCHEMA_READINESS_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("fresh Test Store operation ID is invalid") from error
    database = str(
        _absolute(str(document["test_database"]), "fresh Test Store database")
    )
    store = document.get("store")
    journal = document.get("journal")
    if (
        document.get("action") != "attested-fresh-v5"
        or document.get("journal_kind") != "schema_readiness_v5"
        or not isinstance(journal, Mapping)
        or not isinstance(store, Mapping)
        or store.get("schema_version") != 5
        or not isinstance(store.get("store_generation"), str)
        or not str(store["store_generation"])
        or not isinstance(document.get("published_at"), str)
        or not document["published_at"]
        or (
            expected_test_database is not None
            and database != expected_test_database
        )
    ):
        raise CutoverError("fresh Test Store readiness evidence is contradictory")
    document["test_database"] = database
    return document


def bootstrap_first_deployment(
    *,
    release: Path,
    rendered_units: Path,
    authority_database: Path,
    inventory_database: Path,
    test_database: Path,
    schema_attestation: Path,
    output: Path,
    operation_id: str,
    authority_uid: int = 0,
    command_status=None,
) -> dict[str, object]:
    """Install identities/tmpfiles, prepare the Test Store, and seal bootstrap.

    This command intentionally precedes the cutover ledger: it creates only
    idempotent system identities/directories and the isolated Test Store.  It
    never starts a service, splits authority data, or publishes a route.
    """

    if os.geteuid() != authority_uid or authority_uid != 0:
        raise CutoverError("first-deployment bootstrap must run as root")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("first-deployment bootstrap operation ID is invalid") from error
    release = _absolute(release, "bootstrap release")
    rendered_units = _absolute(rendered_units, "bootstrap rendered units")
    authority_database = _absolute(authority_database, "authority database")
    inventory_database = _absolute(inventory_database, "inventory database")
    test_database = _absolute(test_database, "test database")
    schema_attestation = _absolute(schema_attestation, "schema readiness attestation")
    output = _absolute(output, "first-deployment bootstrap attestation")
    release_result = _load_release_verifier().verify_release(release)
    release_digest = str(release_result["release_digest"])
    if release != Path("/opt/devcoordinator/releases") / release_digest:
        raise CutoverError("bootstrap release is not the exact immutable release")
    if not all(release_result["capabilities"].values()):
        raise CutoverError("bootstrap release lacks a required capability")
    findings = _load_topology_verifier().validate_topology(
        rendered_units, release_digest=release_digest
    )
    if findings:
        raise CutoverError("bootstrap rendered topology is invalid")
    sysusers = rendered_units / "devcoordinator-availability.sysusers.conf"
    tmpfiles = rendered_units / "devcoordinator-availability.tmpfiles.conf"
    sysusers_sha = _bootstrap_config(
        sysusers, authority_uid=authority_uid, name="sysusers configuration"
    )
    tmpfiles_sha = _bootstrap_config(
        tmpfiles, authority_uid=authority_uid, name="tmpfiles configuration"
    )
    run = command_status or _bounded_command_status
    if run(["/usr/bin/systemd-sysusers", str(sysusers)]) != 0:
        raise CutoverError("availability identities could not be installed")
    if run(["/usr/bin/systemd-tmpfiles", "--create", str(tmpfiles)]) != 0:
        raise CutoverError("availability private directories could not be installed")
    identities = _availability_identities()
    users = identities["users"]
    groups = identities["groups"]
    if not isinstance(users, Mapping) or not isinstance(groups, Mapping) or groups:
        raise CutoverError("availability identity result is invalid")
    testd = users["devcoordinator-testd"]
    observer = users["devcoordinator-observer"]
    if not isinstance(testd, Mapping) or not isinstance(observer, Mapping):
        raise CutoverError("availability store identities are invalid")
    directories = [
        _directory_identity(
            authority_database.parent, uid=0, gid=0, mode=0o700
        ),
        _directory_identity(
            inventory_database.parent,
            uid=int(observer["uid"]),
            gid=int(observer["gid"]),
            # The projection file is intentionally readable by every local
            # developer account in trusted-local mode.  The SQLite database
            # remains service-owned 0600 inside this traversable parent.
            mode=0o755,
        ),
        _directory_identity(
            test_database.parent,
            uid=int(testd["uid"]),
            gid=int(testd["gid"]),
            mode=0o700,
        ),
    ]
    if authority_database.exists() or inventory_database.exists():
        raise CutoverError(
            "first-deployment split authority/inventory outputs already exist"
        )
    helper = release / "bin/devcoordinator-test-history"
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise CutoverError("immutable release lacks the Test Store bootstrap helper")
    prefix = [
        "/usr/bin/setpriv",
        "--reuid",
        str(testd["uid"]),
        "--regid",
        str(testd["gid"]),
        "--clear-groups",
        str(helper),
    ]
    if not test_database.exists():
        if run(
            [
                *prefix,
                "create",
                "--test-database",
                str(test_database),
                "--expected-test-uid",
                str(testd["uid"]),
            ]
        ) != 0:
            raise CutoverError("fresh Test Store creation failed")
    if run(
        [
            *prefix,
            "testd-prepare-schema",
            "--test-database",
            str(test_database),
            "--operation-id",
            operation_id,
            "--attestation-output",
            str(schema_attestation),
            "--expected-test-uid",
            str(testd["uid"]),
        ]
    ) != 0:
        raise CutoverError("Test Store schema preparation failed")
    schema = verify_seal(
        read_private_json(schema_attestation, uid=int(testd["uid"])),
        kind=SCHEMA_READINESS_KIND,
        fields=SCHEMA_READINESS_FIELDS,
    )
    store = schema.get("store")
    if (
        schema.get("operation_id") != operation_id
        or schema.get("test_database") != str(test_database)
        or schema.get("action") != "attested-fresh-v5"
        or not isinstance(store, Mapping)
        or store.get("schema_version") != 5
    ):
        raise CutoverError("Test Store schema readiness evidence is contradictory")
    _database_identity(test_database, uid=int(testd["uid"]))
    created_at = _now()
    recorded: dict[str, object] | None = None
    if output.exists() or output.is_symlink():
        recorded = _first_deployment_bootstrap(
            read_private_json(output, uid=authority_uid),
            expected_release=release_digest,
            expected_test_database=str(test_database),
            expected_testd_uid=int(testd["uid"]),
        )
        created_at = str(recorded["created_at"])
    document = seal(
        FIRST_DEPLOYMENT_BOOTSTRAP_KIND,
        {
            "operation_id": operation_id,
            "release": str(release),
            "release_digest": release_digest,
            "rendered_units": str(rendered_units),
            "sysusers_config_sha256": sysusers_sha,
            "tmpfiles_config_sha256": tmpfiles_sha,
            "service_identities": identities,
            "private_directories": directories,
            "authority_database": str(authority_database),
            "inventory_database": str(inventory_database),
            "test_database": str(test_database),
            "test_store": dict(store),
            "schema_readiness": {
                "path": str(schema_attestation),
                "document_sha256": schema["document_sha256"],
                "branch": schema["action"],
                "store_generation": store["store_generation"],
            },
            "created_at": created_at,
        },
    )
    if recorded is not None:
        if recorded != document:
            raise CutoverError(
                "first-deployment bootstrap output belongs to another host state"
            )
        return {"ok": True, "replayed": True, "attestation": recorded}
    _publish_evidence(output, document, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": document}


def _authoritative_repository_root_proof(
    raw_root: object, *, prove_git_metadata_absent: bool = False
) -> dict[str, object]:
    """Anchor-open one canonical root and optionally prove ``.git`` absent.

    The proof never resolves a repository-controlled symlink.  The stale-root
    repair deliberately accepts a root-owned shared directory such as
    ``/tmp``; callers that need an enrolled project owner apply the stricter
    non-root owner check separately.
    """

    if not isinstance(raw_root, str) or not raw_root or "\x00" in raw_root:
        raise CutoverError("authority repository root is invalid")
    path = Path(raw_root)
    if (
        not path.is_absolute()
        or str(path) != os.path.abspath(str(path))
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise CutoverError("authority repository root is not canonical")
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise CutoverError("authority repository root is not a directory")
        descriptor = os.open(
            "/",
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            for component in path.parts[1:]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            anchored = os.fstat(descriptor)
            git_metadata_absent = None
            if prove_git_metadata_absent:
                try:
                    git_before = os.stat(
                        ".git", dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    git_metadata_absent = True
                except OSError as error:
                    raise CutoverError(
                        "authority repository Git metadata cannot be inspected"
                    ) from error
                else:
                    if not stat.S_ISDIR(git_before.st_mode):
                        raise CutoverError(
                            "authority repository root contains Git metadata"
                        )
                    try:
                        git_descriptor = os.open(
                            ".git",
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0),
                            dir_fd=descriptor,
                        )
                        try:
                            git_anchored = os.fstat(git_descriptor)
                            entries = os.listdir(git_descriptor)
                            git_after = os.stat(
                                ".git",
                                dir_fd=descriptor,
                                follow_symlinks=False,
                            )
                        finally:
                            os.close(git_descriptor)
                    except OSError as error:
                        raise CutoverError(
                            "authority repository Git metadata cannot be inspected"
                        ) from error
                    git_identity_fields = (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                    )
                    if (
                        not stat.S_ISDIR(git_anchored.st_mode)
                        or any(
                            getattr(git_before, field)
                            != getattr(git_anchored, field)
                            or getattr(git_after, field)
                            != getattr(git_anchored, field)
                            for field in git_identity_fields
                        )
                    ):
                        raise CutoverError(
                            "authority repository Git metadata cannot be inspected"
                        )
                    if entries:
                        raise CutoverError(
                            "authority repository root contains Git metadata"
                        )
                    # Sandboxed agents may expose an immutable, empty `.git`
                    # mountpoint at a shared temporary root.  It is not Git
                    # metadata and must not make the exact stale-root repair
                    # impossible; files, symlinks, non-empty directories, and
                    # identity changes continue to fail closed above.
                    git_metadata_absent = True
            after = path.lstat()
        finally:
            os.close(descriptor)
    except CutoverError:
        raise
    except (OSError, RuntimeError) as error:
        raise CutoverError("authority repository root cannot be anchor-opened") from error
    identity_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    if any(
        getattr(before, field) != getattr(anchored, field)
        or getattr(after, field) != getattr(anchored, field)
        for field in identity_fields
    ):
        raise CutoverError("authority repository root changed during owner capture")
    if not stat.S_ISDIR(anchored.st_mode) or int(anchored.st_uid) < 0:
        raise CutoverError("authority repository root owner is invalid")
    proof = {
        "device": int(anchored.st_dev),
        "inode": int(anchored.st_ino),
        "mode": f"{stat.S_IMODE(anchored.st_mode):04o}",
        "owner_uid": int(anchored.st_uid),
    }
    if prove_git_metadata_absent:
        proof["git_metadata_absent"] = git_metadata_absent is True
    return proof


def _authoritative_repository_identity(raw_root: object) -> dict[str, object]:
    """Anchor-open one canonical repository without following symlinks."""

    return _authoritative_repository_root_proof(raw_root)


def _authoritative_repository_owner_uid(raw_root: object) -> int:
    owner_uid = int(_authoritative_repository_identity(raw_root)["owner_uid"])
    if owner_uid <= 0:
        raise CutoverError(
            "authority repository root requires a non-root filesystem owner"
        )
    return owner_uid


def diagnose_authority_repository(
    *,
    authority_database: Path,
    repository_id: str,
    authority_uid: int = 0,
    now_epoch: int | None = None,
    database_identity_reader=_database_identity,
    repository_identity_reader=_authoritative_repository_identity,
) -> dict[str, object]:
    """Read one bounded authority row without consulting client profiles."""

    if os.geteuid() != 0 or authority_uid != 0:
        raise CutoverError("authority repository diagnostic requires the root authority")
    if (
        not isinstance(repository_id, str)
        or not repository_id
        or len(repository_id.encode("utf-8")) > 256
        or any(character in repository_id for character in "\x00\r\n")
    ):
        raise CutoverError("repository diagnostic ID is invalid")
    database = _absolute(authority_database, "authority database")
    before_identity = database_identity_reader(database, uid=authority_uid)
    before_metadata = database.lstat()
    current_epoch = int(time.time()) if now_epoch is None else int(now_epoch)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        generation = connection.execute(
            "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        repository = connection.execute(
            """
            SELECT r.repo_id, r.display_name, r.canonical_root, r.generation,
                   r.state, i.status AS installation_status,
                   i.startup_fenced AS installation_startup_fenced
            FROM repositories r
            LEFT JOIN repository_installations i ON i.repo_id = r.repo_id
            WHERE r.repo_id = ?
            """,
            (repository_id,),
        ).fetchone()
        if repository is None:
            raise CutoverError("authority repository does not exist")
        rows = connection.execute(
            """
            SELECT e.uid, e.account_id,
                   e.enabled AS enrollment_enabled,
                   e.valid_until_epoch,
                   p.enabled AS principal_enabled
            FROM broker_repository_enrollments e
            LEFT JOIN broker_acl_principals p
              ON p.uid = e.uid AND p.account_id = e.account_id
            WHERE e.repo_id = ?
            ORDER BY e.uid, e.account_id
            LIMIT ?
            """,
            (repository_id, MAX_REPOSITORY_DIAGNOSTIC_ENROLLMENTS + 1),
        ).fetchall()
        startup_policies = _authority_repository_startup_policy_snapshot(
            connection, repository_id
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    if generation is None or not isinstance(generation[0], str) or not generation[0]:
        raise CutoverError("authority database generation is unavailable")
    if len(rows) > MAX_REPOSITORY_DIAGNOSTIC_ENROLLMENTS:
        raise CutoverError("repository diagnostic enrollment set exceeds its bound")
    display_name = repository["display_name"]
    canonical_root = repository["canonical_root"]
    if (
        not isinstance(display_name, str)
        or not display_name
        or len(display_name.encode("utf-8")) > 512
        or not isinstance(canonical_root, str)
        or not canonical_root
        or len(canonical_root.encode("utf-8")) > 4096
    ):
        raise CutoverError("authority repository diagnostic fields are invalid")
    root_error = None
    try:
        root_identity = repository_identity_reader(canonical_root)
        if (
            not isinstance(root_identity, Mapping)
            or set(root_identity) != {"device", "inode", "mode", "owner_uid"}
            or type(root_identity["owner_uid"]) is not int
            or int(root_identity["owner_uid"]) < 0
        ):
            raise CutoverError("authority repository root identity is invalid")
    except CutoverError as error:
        root_identity = None
        root_error = str(error)
        owner_account = None
    else:
        try:
            owner_account = pwd.getpwuid(int(root_identity["owner_uid"])).pw_name
        except KeyError:
            owner_account = None
    enrollments = [
        {
            "uid": int(row["uid"]),
            "account_id": str(row["account_id"]),
            "principal_present": row["principal_enabled"] is not None,
            "principal_enabled": bool(row["principal_enabled"]),
            "enrollment_enabled": bool(row["enrollment_enabled"]),
            "valid_until_epoch": int(row["valid_until_epoch"]),
            "current": bool(
                row["principal_enabled"]
                and row["enrollment_enabled"]
                and int(row["valid_until_epoch"]) > current_epoch
            ),
        }
        for row in rows
    ]
    after_identity = database_identity_reader(database, uid=authority_uid)
    after_metadata = database.lstat()
    stable_metadata = (
        before_metadata.st_dev,
        before_metadata.st_ino,
        before_metadata.st_size,
        before_metadata.st_mtime_ns,
    ) == (
        after_metadata.st_dev,
        after_metadata.st_ino,
        after_metadata.st_size,
        after_metadata.st_mtime_ns,
    )
    if before_identity != after_identity or not stable_metadata:
        raise CutoverError("authority database changed during repository diagnostic")
    return {
        "ok": True,
        "kind": "devcoordinator-authority-repository-diagnostic",
        "authority_generation": str(generation[0]),
        "database_identity": before_identity,
        "repository": {
            "repository_id": repository_id,
            "display_name": display_name,
            "canonical_root": canonical_root,
            "generation": int(repository["generation"]),
            "state": str(repository["state"]),
            "installation_status": (
                None
                if repository["installation_status"] is None
                else str(repository["installation_status"])
            ),
            "installation_startup_fenced": (
                None
                if repository["installation_startup_fenced"] is None
                else bool(repository["installation_startup_fenced"])
            ),
            "root_observation": (
                "available" if root_identity is not None else "unavailable"
            ),
            "root_identity": (
                None if root_identity is None else dict(root_identity)
            ),
            "root_error": root_error,
            "owner_account": owner_account,
        },
        "enrollments": enrollments,
        "startup_policies": [
            {
                "policy_id": policy["policy_id"],
                "resource_kind": policy["resource_kind"],
                "resource_id": policy["resource_id"],
                "policy_kind": policy["policy_kind"],
                "current_value": policy["current_value"],
                "desired_disabled_value": policy["desired_disabled_value"],
                "enabled": policy["requires_update"],
                "generation": policy["generation"],
                "immutable_fingerprint": policy["immutable_fingerprint"],
                "updated_at": policy["updated_at"],
                "offline_reconciliation": (
                    "authority"
                    if policy["policy_kind"] in {"coordinator", "compose"}
                    else "native_absence_proof_required"
                ),
            }
            for policy in startup_policies
        ],
        "startup_policy_count": len(startup_policies),
        "observed_at": _now(),
    }


def _authority_repair_schema(connection: sqlite3.Connection) -> None:
    required = {
        "schema_metadata": {
            "singleton",
            "database_generation",
            "state_revision",
            "updated_at",
        },
        "repositories": {
            "repo_id",
            "display_name",
            "canonical_root",
            "generation",
            "state",
            "updated_at",
        },
        "repository_installations": {
            "repo_id",
            "status",
            "startup_fenced",
            "generation",
            "operation_id",
            "disabled_at",
            "reason",
            "actor",
            "updated_at",
        },
        "broker_repository_enrollments": {"repo_id"},
        "startup_policies": {
            "policy_id",
            "repo_id",
            "resource_kind",
            "resource_id",
            "policy_kind",
            "current_value",
            "desired_disabled_value",
            "immutable_fingerprint",
            "generation",
            "updated_at",
        },
        "startup_policy_restore_states": {
            "policy_id",
            "repo_id",
            "resource_kind",
            "resource_id",
            "policy_kind",
            "policy_immutable_fingerprint",
            "target_immutable_fingerprint",
            "control_binding_id",
            "ownership_fingerprint",
            "native_identity_fingerprint",
            "captured_value",
            "restore_required",
            "status",
            "docker_restart_policy",
            "supervisor_manager",
            "supervisor_unit_file_state",
            "supervisor_loaded",
            "supervisor_enabled",
            "captured_operation_id",
            "last_restore_permit_id",
            "capture_generation",
            "captured_at",
            "restored_at",
            "updated_at",
        },
    }
    for table, expected in required.items():
        if re.fullmatch(r"[a-z_]+", table) is None:
            raise CutoverError("authority repair schema contract is invalid")
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        columns = {str(row[1]) for row in rows}
        if not expected.issubset(columns):
            raise CutoverError(
                f"authority repair requires the current {table} contract"
            )


AUTHORITY_STARTUP_POLICY_FIELDS = frozenset(
    {
        "policy_id",
        "resource_kind",
        "resource_id",
        "policy_kind",
        "current_value",
        "desired_disabled_value",
        "immutable_fingerprint",
        "generation",
        "updated_at",
        "target_current_value",
        "target_generation",
        "requires_update",
        "restore_state",
    }
)

AUTHORITY_STARTUP_POLICY_RESULT_FIELDS = frozenset(
    {
        *AUTHORITY_STARTUP_POLICY_FIELDS,
        "current_value_after",
        "generation_after",
        "updated_at_after",
    }
)

AUTHORITY_STARTUP_POLICY_RESTORE_FIELDS = frozenset(
    {
        "policy_id",
        "repo_id",
        "resource_kind",
        "resource_id",
        "policy_kind",
        "policy_immutable_fingerprint",
        "target_immutable_fingerprint",
        "control_binding_id",
        "ownership_fingerprint",
        "native_identity_fingerprint",
        "captured_value",
        "restore_required",
        "status",
        "docker_restart_policy",
        "supervisor_manager",
        "supervisor_unit_file_state",
        "supervisor_loaded",
        "supervisor_enabled",
        "captured_operation_id",
        "last_restore_permit_id",
        "capture_generation",
        "captured_at",
        "restored_at",
        "updated_at",
    }
)


def _authority_startup_policy_restore_state(
    row: sqlite3.Row,
) -> dict[str, object] | None:
    if row["restore_policy_id"] is None:
        return None
    state = {
        "policy_id": row["restore_policy_id"],
        "repo_id": row["restore_repo_id"],
        "resource_kind": row["restore_resource_kind"],
        "resource_id": row["restore_resource_id"],
        "policy_kind": row["restore_policy_kind"],
        "policy_immutable_fingerprint": row["policy_immutable_fingerprint"],
        "target_immutable_fingerprint": row["target_immutable_fingerprint"],
        "control_binding_id": row["control_binding_id"],
        "ownership_fingerprint": row["ownership_fingerprint"],
        "native_identity_fingerprint": row["native_identity_fingerprint"],
        "captured_value": row["captured_value"],
        "restore_required": bool(row["restore_required"]),
        "status": row["restore_status"],
        "docker_restart_policy": row["docker_restart_policy"],
        "supervisor_manager": row["supervisor_manager"],
        "supervisor_unit_file_state": row["supervisor_unit_file_state"],
        "supervisor_loaded": (
            None
            if row["supervisor_loaded"] is None
            else bool(row["supervisor_loaded"])
        ),
        "supervisor_enabled": (
            None
            if row["supervisor_enabled"] is None
            else bool(row["supervisor_enabled"])
        ),
        "captured_operation_id": row["captured_operation_id"],
        "last_restore_permit_id": row["last_restore_permit_id"],
        "capture_generation": row["capture_generation"],
        "captured_at": row["captured_at"],
        "restored_at": row["restored_at"],
        "updated_at": row["restore_updated_at"],
    }
    return _validate_authority_startup_policy_restore_state(state)


def _validate_authority_startup_policy_restore_state(
    value: object,
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != AUTHORITY_STARTUP_POLICY_RESTORE_FIELDS
    ):
        raise CutoverError("authority repair startup policy restore state is invalid")
    state = dict(value)
    required_strings = (
        "policy_id",
        "repo_id",
        "resource_kind",
        "resource_id",
        "policy_kind",
        "policy_immutable_fingerprint",
        "target_immutable_fingerprint",
        "control_binding_id",
        "ownership_fingerprint",
        "native_identity_fingerprint",
        "captured_value",
        "status",
        "captured_operation_id",
        "captured_at",
        "updated_at",
    )
    optional_strings = (
        "docker_restart_policy",
        "supervisor_manager",
        "supervisor_unit_file_state",
        "last_restore_permit_id",
        "restored_at",
    )
    if (
        any(
            not isinstance(state[field], str)
            or not state[field]
            or len(str(state[field]).encode("utf-8")) > 4096
            or any(character in str(state[field]) for character in "\x00\r\n")
            for field in required_strings
        )
        or any(
            state[field] is not None
            and (
                not isinstance(state[field], str)
                or not state[field]
                or len(str(state[field]).encode("utf-8")) > 4096
                or any(character in str(state[field]) for character in "\x00\r\n")
            )
            for field in optional_strings
        )
        or state["policy_kind"]
        not in {"docker_restart", "compose", "supervisor", "coordinator"}
        or type(state["restore_required"]) is not bool
        or state["status"] not in {"captured", "restored", "not_required"}
        or (
            state["restore_required"]
            and state["status"] not in {"captured", "restored"}
        )
        or (not state["restore_required"] and state["status"] != "not_required")
        or type(state["capture_generation"]) is not int
        or int(state["capture_generation"]) < 0
        or (
            state["supervisor_loaded"] is not None
            and type(state["supervisor_loaded"]) is not bool
        )
        or (
            state["supervisor_enabled"] is not None
            and type(state["supervisor_enabled"]) is not bool
        )
    ):
        raise CutoverError(
            "authority repair startup policy restore state contract is invalid"
        )
    return state


def _authority_repository_startup_policy_snapshot(
    connection: sqlite3.Connection, repository_id: str
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT policy.policy_id, policy.resource_kind, policy.resource_id,
               policy.policy_kind, policy.current_value,
               policy.desired_disabled_value, policy.immutable_fingerprint,
               policy.generation, policy.updated_at,
               restore.policy_id AS restore_policy_id,
               restore.repo_id AS restore_repo_id,
               restore.resource_kind AS restore_resource_kind,
               restore.resource_id AS restore_resource_id,
               restore.policy_kind AS restore_policy_kind,
               restore.policy_immutable_fingerprint,
               restore.target_immutable_fingerprint,
               restore.control_binding_id,
               restore.ownership_fingerprint,
               restore.native_identity_fingerprint,
               restore.captured_value,
               restore.restore_required,
               restore.status AS restore_status,
               restore.docker_restart_policy,
               restore.supervisor_manager,
               restore.supervisor_unit_file_state,
               restore.supervisor_loaded,
               restore.supervisor_enabled,
               restore.captured_operation_id,
               restore.last_restore_permit_id,
               restore.capture_generation,
               restore.captured_at,
               restore.restored_at,
               restore.updated_at AS restore_updated_at
        FROM startup_policies policy
        LEFT JOIN startup_policy_restore_states restore
          ON restore.policy_id = policy.policy_id
        WHERE policy.repo_id = ?
        ORDER BY policy.policy_id
        LIMIT ?
        """,
        (repository_id, MAX_REPOSITORY_STARTUP_POLICIES + 1),
    ).fetchall()
    if len(rows) > MAX_REPOSITORY_STARTUP_POLICIES:
        raise CutoverError("authority repository startup policy set exceeds its bound")
    policies: list[dict[str, object]] = []
    for row in rows:
        current_value = row["current_value"]
        desired_disabled_value = row["desired_disabled_value"]
        generation = row["generation"]
        policy = {
            "policy_id": row["policy_id"],
            "resource_kind": row["resource_kind"],
            "resource_id": row["resource_id"],
            "policy_kind": row["policy_kind"],
            "current_value": current_value,
            "desired_disabled_value": desired_disabled_value,
            "immutable_fingerprint": row["immutable_fingerprint"],
            "generation": generation,
            "updated_at": row["updated_at"],
            "target_current_value": desired_disabled_value,
            "target_generation": (
                int(generation) + 1
                if current_value != desired_disabled_value
                else int(generation)
            ),
            "requires_update": current_value != desired_disabled_value,
            "restore_state": _authority_startup_policy_restore_state(row),
        }
        policies.append(policy)
    validated = _validate_authority_startup_policies(policies)
    if any(
        policy["restore_state"] is not None
        and policy["restore_state"]["repo_id"] != repository_id
        for policy in validated
    ):
        raise CutoverError(
            "authority repair startup policy restore repository binding is invalid"
        )
    return validated


def _validate_authority_startup_policies(
    value: object,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise CutoverError("authority repair startup policies are invalid")
    policies: list[dict[str, object]] = []
    previous_id: str | None = None
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != AUTHORITY_STARTUP_POLICY_FIELDS:
            raise CutoverError("authority repair startup policy fields are invalid")
        policy = dict(raw)
        string_fields = (
            "policy_id",
            "resource_kind",
            "resource_id",
            "policy_kind",
            "current_value",
            "desired_disabled_value",
            "immutable_fingerprint",
            "updated_at",
            "target_current_value",
        )
        if any(
            not isinstance(policy[field], str)
            or not policy[field]
            or len(str(policy[field]).encode("utf-8")) > 4096
            or any(character in str(policy[field]) for character in "\x00\r\n")
            for field in string_fields
        ):
            raise CutoverError("authority repair startup policy values are invalid")
        if (
            policy["policy_kind"]
            not in {"docker_restart", "compose", "supervisor", "coordinator"}
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(policy["immutable_fingerprint"])
            )
            is None
            or type(policy["generation"]) is not int
            or int(policy["generation"]) < 0
            or type(policy["target_generation"]) is not int
            or int(policy["target_generation"]) < 0
            or type(policy["requires_update"]) is not bool
            or policy["target_current_value"] != policy["desired_disabled_value"]
            or policy["requires_update"]
            is (policy["current_value"] == policy["desired_disabled_value"])
            or policy["target_generation"]
            != int(policy["generation"]) + int(bool(policy["requires_update"]))
            or (previous_id is not None and str(policy["policy_id"]) <= previous_id)
        ):
            raise CutoverError("authority repair startup policy contract is invalid")
        restore_state = policy["restore_state"]
        if restore_state is not None:
            restore = _validate_authority_startup_policy_restore_state(restore_state)
            if (
                restore["policy_id"] != policy["policy_id"]
                or restore["resource_kind"] != policy["resource_kind"]
                or restore["resource_id"] != policy["resource_id"]
                or restore["policy_kind"] != policy["policy_kind"]
                or restore["policy_immutable_fingerprint"]
                != policy["immutable_fingerprint"]
            ):
                raise CutoverError(
                    "authority repair startup policy restore binding is invalid"
                )
            policy["restore_state"] = restore
        previous_id = str(policy["policy_id"])
        policies.append(policy)
    return policies


def _authority_startup_policies_match_initial(
    planned: object, current: object
) -> bool:
    try:
        return _validate_authority_startup_policies(planned) == (
            _validate_authority_startup_policies(current)
        )
    except CutoverError:
        return False


def _authority_startup_policy_results(
    *,
    planned: object,
    current: object,
    applied_at: str,
) -> list[dict[str, object]]:
    expected = _validate_authority_startup_policies(planned)
    observed = _validate_authority_startup_policies(current)
    if len(expected) != len(observed):
        raise CutoverError("authority repair startup policy membership changed")
    results: list[dict[str, object]] = []
    for before, after in zip(expected, observed, strict=True):
        unchanged_fields = {
            "policy_id",
            "resource_kind",
            "resource_id",
            "policy_kind",
            "desired_disabled_value",
            "immutable_fingerprint",
            "restore_state",
        }
        expected_updated_at = applied_at if before["requires_update"] else before["updated_at"]
        if (
            any(after[field] != before[field] for field in unchanged_fields)
            or after["current_value"] != before["target_current_value"]
            or after["generation"] != before["target_generation"]
            or after["updated_at"] != expected_updated_at
            or after["target_current_value"] != before["target_current_value"]
            or after["target_generation"] != before["target_generation"]
            or after["requires_update"] is not False
        ):
            raise CutoverError("authority repair startup policy terminal state changed")
        results.append(
            {
                **before,
                "current_value_after": after["current_value"],
                "generation_after": after["generation"],
                "updated_at_after": after["updated_at"],
            }
        )
    return results


def _authority_startup_policies_match_terminal(
    planned: object, current: object, *, applied_at: object
) -> bool:
    if not isinstance(applied_at, str) or not applied_at:
        return False
    try:
        _authority_startup_policy_results(
            planned=planned,
            current=current,
            applied_at=applied_at,
        )
    except CutoverError:
        return False
    return True


def _validate_authority_startup_policy_results(
    value: object,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise CutoverError("authority repair startup policy results are invalid")
    planned: list[dict[str, object]] = []
    for raw in value:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != AUTHORITY_STARTUP_POLICY_RESULT_FIELDS
        ):
            raise CutoverError("authority repair startup policy result fields are invalid")
        planned.append(
            {field: raw[field] for field in AUTHORITY_STARTUP_POLICY_FIELDS}
        )
    normalized = _validate_authority_startup_policies(planned)
    results: list[dict[str, object]] = []
    for before, raw in zip(normalized, value, strict=True):
        result = dict(raw)
        expected_updated_at = (
            result["updated_at_after"]
            if before["requires_update"]
            else before["updated_at"]
        )
        if (
            result["current_value_after"] != before["target_current_value"]
            or result["generation_after"] != before["target_generation"]
            or not isinstance(result["updated_at_after"], str)
            or not result["updated_at_after"]
            or (not before["requires_update"] and result["updated_at_after"] != expected_updated_at)
        ):
            raise CutoverError("authority repair startup policy result is invalid")
        results.append(result)
    return results


def _authority_repository_repair_snapshot(
    connection: sqlite3.Connection, repository_id: str
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    metadata = connection.execute(
        """
        SELECT database_generation, state_revision
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchone()
    repository = connection.execute(
        """
        SELECT r.repo_id, r.display_name, r.canonical_root, r.generation,
               r.state, r.updated_at AS repository_updated_at,
               i.status AS installation_status,
               i.startup_fenced AS installation_startup_fenced,
               i.generation AS installation_generation,
               i.operation_id AS installation_operation_id,
               i.disabled_at AS installation_disabled_at,
               i.reason AS installation_reason,
               i.actor AS installation_actor,
               i.updated_at AS installation_updated_at
        FROM repositories r
        JOIN repository_installations i ON i.repo_id = r.repo_id
        WHERE r.repo_id = ?
        """,
        (repository_id,),
    ).fetchone()
    if metadata is None or repository is None:
        raise CutoverError("authority repair target or generation is unavailable")
    enrollment = connection.execute(
        "SELECT COUNT(*) FROM broker_repository_enrollments WHERE repo_id = ?",
        (repository_id,),
    ).fetchone()
    if enrollment is None:
        raise CutoverError("authority repair enrollment count is unavailable")
    authority_generation = metadata["database_generation"]
    state_revision = metadata["state_revision"]
    if (
        not isinstance(authority_generation, str)
        or not authority_generation
        or len(authority_generation.encode("utf-8")) > 256
        or type(state_revision) is not int
        or int(state_revision) < 0
    ):
        raise CutoverError("authority repair generation fields are invalid")
    snapshot = {
        "repository_id": str(repository["repo_id"]),
        "display_name": str(repository["display_name"]),
        "canonical_root": str(repository["canonical_root"]),
        "generation": int(repository["generation"]),
        "state": str(repository["state"]),
        "repository_updated_at": str(repository["repository_updated_at"]),
        "installation_status": str(repository["installation_status"]),
        "installation_startup_fenced": bool(
            repository["installation_startup_fenced"]
        ),
        "installation_generation": int(repository["installation_generation"]),
        "installation_operation_id": repository["installation_operation_id"],
        "installation_disabled_at": repository["installation_disabled_at"],
        "installation_reason": repository["installation_reason"],
        "installation_actor": str(repository["installation_actor"]),
        "installation_updated_at": str(repository["installation_updated_at"]),
        "enrollment_count": int(enrollment[0]),
    }
    if (
        snapshot["repository_id"] != repository_id
        or not snapshot["display_name"]
        or len(str(snapshot["display_name"]).encode("utf-8")) > 512
        or type(snapshot["generation"]) is not int
        or int(snapshot["generation"]) < 0
        or type(snapshot["installation_generation"]) is not int
        or int(snapshot["installation_generation"]) < 0
        or int(snapshot["enrollment_count"]) < 0
    ):
        raise CutoverError("authority repair repository fields are invalid")
    return (
        {
            "authority_generation": authority_generation,
            "state_revision": int(state_revision),
        },
        snapshot,
        _authority_repository_startup_policy_snapshot(connection, repository_id),
    )


def _validate_authority_repository_disable_plan(
    value: object, *, allow_legacy: bool = False
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CutoverError("authority repository disable plan must be an object")
    unsigned_fields = set(value) - {"schema_version", "kind", "document_sha256"}
    legacy = unsigned_fields == set(LEGACY_AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS)
    if legacy and not allow_legacy:
        raise CutoverError("legacy authority repository disable plan is not accepted")
    fields = (
        LEGACY_AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS
        if legacy
        else AUTHORITY_REPOSITORY_DISABLE_PLAN_FIELDS
    )
    plan = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_DISABLE_PLAN_KIND,
        fields=fields,
    )
    try:
        plan_id = str(uuid.UUID(str(plan["plan_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority repair plan ID is invalid") from error
    database_identity = plan["database_identity"]
    repository = plan["repository"]
    target = plan["target"]
    startup_policies = (
        []
        if legacy
        else _validate_authority_startup_policies(plan["startup_policies"])
    )
    if (
        plan_id != plan["plan_id"]
        or not isinstance(plan["authority_database"], str)
        or str(_absolute(str(plan["authority_database"]), "authority database"))
        != plan["authority_database"]
        or type(plan["authority_uid"]) is not int
        or int(plan["authority_uid"]) < 0
        or not isinstance(plan["authority_generation"], str)
        or not plan["authority_generation"]
        or type(plan["authority_state_revision"]) is not int
        or int(plan["authority_state_revision"]) < 0
        or not isinstance(database_identity, Mapping)
        or set(database_identity) != {"device", "inode", "size"}
        or any(type(database_identity[field]) is not int for field in database_identity)
        or int(database_identity["device"]) < 0
        or int(database_identity["inode"]) <= 0
        or int(database_identity["size"]) <= 0
        or type(plan["enrollment_count"]) is not int
        or plan["enrollment_count"] != 0
        or plan["shared_temporary_root"] is not True
        or plan["git_metadata_absent"] is not True
        or plan["reason"] != AUTHORITY_REPOSITORY_REPAIR_REASON
        or not isinstance(plan["created_at"], str)
        or not isinstance(repository, Mapping)
        or set(repository)
        != {
            "repository_id",
            "display_name",
            "canonical_root",
            "generation",
            "state",
            "repository_updated_at",
            "installation_status",
            "installation_startup_fenced",
            "installation_generation",
            "installation_operation_id",
            "installation_disabled_at",
            "installation_reason",
            "installation_actor",
            "installation_updated_at",
            "root_identity",
        }
        or not isinstance(repository["repository_id"], str)
        or not repository["repository_id"]
        or repository["canonical_root"] not in SHARED_TEMPORARY_REPOSITORY_ROOTS
        or type(repository["generation"]) is not int
        or int(repository["generation"]) < 0
        or repository["state"] != "active"
        or not isinstance(repository["repository_updated_at"], str)
        or not repository["repository_updated_at"]
        or repository["installation_status"] != "installed"
        or repository["installation_startup_fenced"] is not False
        or type(repository["installation_generation"]) is not int
        or int(repository["installation_generation"]) < 0
        or repository["installation_operation_id"] is not None
        or repository["installation_disabled_at"] is not None
        or (
            repository["installation_reason"] is not None
            and (
                not isinstance(repository["installation_reason"], str)
                or len(repository["installation_reason"].encode("utf-8")) > 4096
            )
        )
        or not isinstance(repository["installation_actor"], str)
        or not repository["installation_actor"]
        or not isinstance(repository["installation_updated_at"], str)
        or not repository["installation_updated_at"]
        or not isinstance(target, Mapping)
        or dict(target)
        != {
            "repository_state": "missing",
            "installation_status": "disabled",
            "startup_fenced": True,
        }
    ):
        raise CutoverError("authority repository disable plan is invalid")
    unsupported = [
        str(policy["policy_id"])
        for policy in startup_policies
        if policy["requires_update"]
        and policy["policy_kind"] not in {"coordinator", "compose"}
    ]
    if unsupported:
        raise CutoverError(
            "authority repository disable plan requires native lifecycle "
            f"decommission for startup policy {unsupported[0]}"
        )
    root_identity = repository["root_identity"]
    if (
        not isinstance(root_identity, Mapping)
        or set(root_identity) != {"device", "inode", "mode", "owner_uid"}
        or type(root_identity["device"]) is not int
        or int(root_identity["device"]) < 0
        or type(root_identity["inode"]) is not int
        or int(root_identity["inode"]) <= 0
        or root_identity["mode"] != "1777"
        or root_identity["owner_uid"] != 0
    ):
        raise CutoverError("authority repair shared-root identity is invalid")
    return plan


def plan_authority_shared_root_positive_absence(
    *,
    authority_database: Path,
    repository_id: str,
    operation_id: str,
    plan_path: Path,
    authority_uid: int = 0,
    effective_uid_reader=None,
    database_identity_reader=None,
    evidence_publisher=None,
) -> dict[str, object]:
    """Publish the core sealed plan for the exact schema-12 ``/tmp`` census."""

    uid_reader = effective_uid_reader or os.geteuid
    if authority_uid != 0 or uid_reader() != 0:
        raise CutoverError(
            "shared-root positive-absence planning requires the root authority owner"
        )
    database = _absolute(authority_database, "authority database")
    output = _absolute(plan_path, "shared-root positive-absence plan")
    identity_reader = database_identity_reader or _database_identity
    publisher = evidence_publisher or _publish_evidence
    identity_before = identity_reader(database, uid=authority_uid)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            observation = latest_shared_root_full_docker_observation(
                connection, repository_id=repository_id
            )
            plan = plan_shared_root_positive_absence(
                connection,
                repository_id=repository_id,
                operation_id=operation_id,
                observation_evidence=observation,
                created_at=_now(),
            )
        except SharedRootPositiveAbsenceError as error:
            raise CutoverError(
                f"shared-root positive-absence plan refused: {error}"
            ) from error
    finally:
        connection.close()
    identity_after = identity_reader(database, uid=authority_uid)
    if identity_before != identity_after:
        raise CutoverError(
            "authority database changed while the shared-root plan was read"
        )
    publisher(output, plan, uid=authority_uid)
    return {
        "ok": True,
        "plan": str(output),
        "plan_id": plan["plan_id"],
        "operation_id": plan["operation_id"],
        "document_sha256": plan["document_sha256"],
        "repository_id": plan["repository"]["repository_id"],
        "observation_snapshot_id": plan["observation"]["snapshot_id"],
        "absent_resource_count": len(plan["absent_resources"]),
        "present_resource_count": len(plan["present_resources"]),
        "database_binding_count": len(plan["database_bindings"]),
        "writes_performed": False,
    }


def apply_authority_shared_root_positive_absence(
    *,
    authority_database: Path,
    plan_path: Path,
    plan_document_sha256: str,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    authority_uid: int = 0,
    effective_uid_reader=None,
    database_identity_reader=None,
    evidence_reader=None,
    evidence_publisher=None,
    maintenance_state_reader=None,
    maintenance_lock_factory=None,
    broker_lock_factory=None,
    before_commit_hook=None,
    after_commit_hook=None,
) -> dict[str, object]:
    """Apply the sealed DB-only transition behind both production write locks."""

    uid_reader = effective_uid_reader or os.geteuid
    if authority_uid != 0 or uid_reader() != 0:
        raise CutoverError(
            "shared-root positive-absence apply requires the root authority owner"
        )
    database = _absolute(authority_database, "authority database")
    plan_location = _absolute(plan_path, "shared-root positive-absence plan")
    output = _absolute(attestation, "shared-root positive-absence attestation")
    reader = evidence_reader or read_private_json
    publisher = evidence_publisher or _publish_evidence
    plan = reader(plan_location, uid=authority_uid)
    if (
        re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan.get("document_sha256") != plan_document_sha256
    ):
        raise CutoverError(
            "shared-root positive-absence plan digest does not match"
        )
    try:
        deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "shared-root positive-absence maintenance identity is invalid"
        ) from error
    if deployment_id != maintenance_deployment_id:
        raise CutoverError(
            "shared-root positive-absence maintenance identity is invalid"
        )
    maintenance_reader = maintenance_state_reader or load_maintenance_state
    maintenance_locker = maintenance_lock_factory or maintenance_writer_lock
    maintenance_root = _absolute(maintenance_root, "maintenance root")

    def require_maintenance() -> object:
        try:
            current = maintenance_reader(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "shared-root positive-absence maintenance marker is invalid"
            ) from error
        if (
            current is None
            or current.deployment_id != deployment_id
            or current.message != PUBLIC_MAINTENANCE_MESSAGE
        ):
            raise CutoverError(
                "shared-root positive-absence requires the exact active maintenance fence"
            )
        return current

    require_maintenance()
    identity_reader = database_identity_reader or _database_identity
    lock_factory = broker_lock_factory or exclusive_broker_service_lock
    mutated = False
    result: dict[str, object] | None = None
    with lock_factory(database), maintenance_locker(
        maintenance_root=maintenance_root,
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
    ):
        require_maintenance()
        identity_before = identity_reader(database, uid=authority_uid)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            changes_before = connection.total_changes
            try:
                result = apply_shared_root_positive_absence(
                    connection,
                    plan=plan,
                    plan_document_sha256=plan_document_sha256,
                )
            except SharedRootPositiveAbsenceError as error:
                raise CutoverError(
                    f"shared-root positive-absence apply refused: {error}"
                ) from error
            mutated = connection.total_changes != changes_before
            if before_commit_hook is not None:
                before_commit_hook()
            require_maintenance()
            connection.commit()
            if after_commit_hook is not None:
                after_commit_hook()
            connection.execute("BEGIN")
            try:
                committed = apply_shared_root_positive_absence(
                    connection,
                    plan=plan,
                    plan_document_sha256=plan_document_sha256,
                )
            except SharedRootPositiveAbsenceError as error:
                raise CutoverError(
                    f"shared-root positive-absence committed state is invalid: {error}"
                ) from error
            finally:
                connection.rollback()
            if committed != result:
                raise CutoverError(
                    "shared-root positive-absence committed result changed"
                )
        except BaseException:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
        identity_after = identity_reader(database, uid=authority_uid)
        if not _authority_repair_same_database(
            planned=identity_before, current=identity_after
        ):
            raise CutoverError(
                "authority database identity changed during shared-root apply"
            )
    if result is None:
        raise CutoverError("shared-root positive-absence result is unavailable")
    publisher(output, result, uid=authority_uid)
    return {
        "ok": True,
        "attestation": str(output),
        "document_sha256": result["document_sha256"],
        "plan_id": result["plan_id"],
        "operation_id": result["operation_id"],
        "repository_id": result["repository_id"],
        "observation_snapshot_id": result["observation_snapshot_id"],
        "absent_resource_count": result["absent_resource_count"],
        "present_resource_count": result["present_resource_count"],
        "detached_database_binding_count": result[
            "detached_database_binding_count"
        ],
        "writes_performed": mutated,
    }


def execute_authority_shared_root_positive_absence(
    *,
    release: Path,
    authority_database: Path,
    plan_path: Path,
    plan_document_sha256: str,
    attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    broker_socket: Path,
    canary_user: str,
    canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    readiness_wait_seconds: int = 30,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    command_output=None,
    effective_uid_reader=None,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=None,
    now_reader=_now,
    applier=apply_authority_shared_root_positive_absence,
    applier_options: Mapping[str, object] | None = None,
    service_state_reader=None,
    service_readiness_verifier=None,
    phase_hook=None,
) -> dict[str, object]:
    """Own the broker lifecycle around the DB-only positive-absence repair.

    An uncertain failure deliberately retains the marker.  Re-running this
    exact command with the same deployment and sealed plan deterministically
    replays the core result, restores the broker, proves the sealed repository
    inventory canary, and clears the marker only after readiness.
    """

    uid_reader = effective_uid_reader or os.geteuid
    publisher = evidence_publisher or _publish_evidence
    if authority_uid != 0 or uid_reader() != 0:
        raise CutoverError(
            "shared-root positive-absence execution requires root"
        )
    try:
        deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "shared-root positive-absence maintenance identity is invalid"
        ) from error
    if deployment_id != maintenance_deployment_id:
        raise CutoverError(
            "shared-root positive-absence maintenance identity is invalid"
        )
    release = _absolute(release, "shared-root positive-absence release")
    database = _absolute(authority_database, "authority database")
    plan_location = _absolute(plan_path, "shared-root positive-absence plan")
    result_location = _absolute(
        attestation, "shared-root positive-absence attestation"
    )
    transaction_journal = _absolute(
        transaction_journal, "shared-root positive-absence transaction journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation,
        "shared-root positive-absence transaction attestation",
    )
    if len(
        {plan_location, result_location, transaction_journal, transaction_attestation}
    ) != 4:
        raise CutoverError(
            "shared-root positive-absence evidence paths must be distinct"
        )
    maintenance_root = _absolute(maintenance_root, "maintenance root")
    broker_socket = _absolute(broker_socket, "broker socket")
    canary_project = _absolute(canary_project, "inventory canary project")
    binding = _authority_repository_service_readiness_binding(
        {
            "broker_socket": str(broker_socket),
            "canary_user": canary_user,
            "canary_uid": canary_uid,
            "canary_project": str(canary_project),
            "canary_repository_id": canary_repository_id,
            "canary_repository_generation": canary_repository_generation,
            "wait_seconds": readiness_wait_seconds,
        }
    )
    try:
        plan = validate_shared_root_positive_absence_plan(
            evidence_reader(plan_location, uid=authority_uid)
        )
    except SharedRootPositiveAbsenceError as error:
        raise CutoverError(
            f"shared-root positive-absence plan is invalid: {error}"
        ) from error
    if (
        re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan["document_sha256"] != plan_document_sha256
    ):
        raise CutoverError(
            "shared-root positive-absence plan digest does not match"
        )
    authority_generation = str(plan["authority"]["database_generation"])
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
        or (
            release_verifier is None
            and release != IMMUTABLE_RELEASE_ROOT / release_digest
        )
    ):
        raise CutoverError(
            "shared-root positive-absence immutable release is invalid"
        )
    readiness_verifier = (
        _authority_repository_service_readiness_proof
        if service_readiness_verifier is None
        else service_readiness_verifier
    )
    output_reader = command_output or _bounded_command_output
    state_reader = service_state_reader or (
        lambda unit: _shared_root_broker_service_state(
            output_reader, unit, broker_socket
        )
    )
    unit = "devcoordinator-broker.service"

    def phase(name: str) -> None:
        if phase_hook is not None:
            phase_hook(name)

    def service_state() -> dict[str, object]:
        return _validate_shared_root_broker_service_state(state_reader(unit))

    def wait_for_service(predicate, description: str) -> dict[str, object]:
        deadline = time.monotonic() + readiness_wait_seconds
        while time.monotonic() < deadline:
            current = service_state()
            if predicate(current):
                return current
            time.sleep(0.05)
        raise CutoverError(
            f"shared-root broker did not become {description}"
        )

    def completed_result() -> dict[str, object] | None:
        if not (result_location.exists() or result_location.is_symlink()):
            return None
        try:
            retained = validate_shared_root_positive_absence_result(
                evidence_reader(result_location, uid=authority_uid), plan=plan
            )
            connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA query_only = ON")
                connection.execute("PRAGMA trusted_schema = OFF")
                connection.execute("PRAGMA busy_timeout = 5000")
                connection.execute("BEGIN")
                try:
                    verified = verify_shared_root_positive_absence_terminal(
                        connection,
                        plan=plan,
                        plan_document_sha256=plan_document_sha256,
                        result=retained,
                    )
                finally:
                    connection.rollback()
            finally:
                connection.close()
            return verified
        except (SharedRootPositiveAbsenceError, sqlite3.Error) as error:
            raise CutoverError(
                "shared-root positive-absence retained authority state is invalid: "
                f"{error}"
            ) from error

    def read_marker() -> object:
        try:
            return maintenance_state_reader(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "shared-root positive-absence maintenance marker is invalid"
            ) from error

    marker = read_marker()
    existing_maintenance: dict[str, object] | None = None
    if marker is not None:
        existing_maintenance = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=deployment_id,
        )
    started_at = (
        str(existing_maintenance["started_at"])
        if existing_maintenance is not None
        else now_reader()
    )
    planned_maintenance = {
        "root": str(maintenance_root),
        "gid": maintenance_gid,
        "deployment_id": deployment_id,
        "message": PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": 5,
        "started_at": started_at,
    }
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _authority_repository_disable_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        if (
            transaction["operation_id"] != plan["operation_id"]
            or transaction["release"] != str(release)
            or transaction["release_digest"] != release_digest
            or transaction["plan"] != str(plan_location)
            or transaction["plan_document_sha256"] != plan_document_sha256
            or transaction["database"] != str(database)
            or transaction["repair_attestation"] != str(result_location)
            or transaction["readiness"] != binding
            or transaction["maintenance"]["root"] != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"] != deployment_id
        ):
            raise CutoverError(
                "shared-root positive-absence transaction belongs to another operation"
            )
        planned_maintenance = dict(transaction["maintenance"])
        started_at = str(planned_maintenance["started_at"])
    else:
        baseline = service_state()
        if not _shared_root_broker_is_healthy(baseline):
            raise CutoverError(
                "shared-root positive-absence transaction requires the healthy broker baseline"
            )
        transaction = _authority_repository_disable_transaction(
            seal(
                AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_KIND,
                {
                    "operation_id": plan["operation_id"],
                    "release": str(release),
                    "release_digest": release_digest,
                    "plan": str(plan_location),
                    "plan_document_sha256": plan_document_sha256,
                    "database": str(database),
                    "service_unit": unit,
                    "service_baseline": {"active": True, "enabled": True},
                    "readiness": binding,
                    "maintenance": planned_maintenance,
                    "repair_attestation": str(result_location),
                    "created_at": started_at,
                },
            )
        )
        publisher(transaction_journal, transaction, uid=authority_uid)
    if existing_maintenance is not None and existing_maintenance != transaction[
        "maintenance"
    ]:
        raise CutoverError(
            "shared-root positive-absence retained maintenance changed"
        )
    phase("after-journal")
    repair = completed_result()
    current_service = service_state()

    def publish_terminal(
        readiness: Mapping[str, object], repair_result: Mapping[str, object]
    ) -> dict[str, object]:
        terminal = _authority_repository_disable_transaction_result(
            seal(
                AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_KIND,
                {
                    "operation_id": plan["operation_id"],
                    "transaction_journal_sha256": transaction[
                        "document_sha256"
                    ],
                    "repair_result_sha256": repair_result["document_sha256"],
                    "release_digest": release_digest,
                    "database": str(database),
                    "service_unit": unit,
                    "readiness_proof": dict(readiness),
                    "service_restored": True,
                    "maintenance_cleared": True,
                    "completed_at": now_reader(),
                },
            ),
            readiness=binding,
            authority_generation=authority_generation,
        )
        publisher(
            transaction_attestation, terminal, uid=authority_uid
        )
        phase("after-terminal")
        return terminal

    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        terminal = _authority_repository_disable_transaction_result(
            evidence_reader(transaction_attestation, uid=authority_uid),
            readiness=binding,
            authority_generation=authority_generation,
        )
        if (
            repair is None
            or terminal["operation_id"] != plan["operation_id"]
            or terminal["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or terminal["repair_result_sha256"] != repair["document_sha256"]
            or terminal["release_digest"] != release_digest
            or terminal["database"] != str(database)
            or marker is not None
            or not _shared_root_broker_is_healthy(current_service)
        ):
            raise CutoverError(
                "shared-root positive-absence terminal is contradictory"
            )
        readiness = _validate_authority_repository_service_readiness_proof(
            readiness_verifier(
                phase="authenticated",
                release=release,
                database=database,
                authority_uid=authority_uid,
                authority_generation=authority_generation,
                binding=binding,
                now_reader=now_reader,
            ),
            phase="authenticated",
            binding=binding,
            generation=authority_generation,
        )
        if (
            readiness["socket_peer"]["pid"] != current_service["main_pid"]
            or readiness["invariants"]["database_identity"]["device"]
            != terminal["readiness_proof"]["invariants"]["database_identity"][
                "device"
            ]
            or readiness["invariants"]["database_identity"]["inode"]
            != terminal["readiness_proof"]["invariants"]["database_identity"][
                "inode"
            ]
        ):
            raise CutoverError(
                "shared-root positive-absence terminal readiness changed"
            )
        return {
            "ok": True,
            "replayed": True,
            "attestation": str(result_location),
            "transaction_attestation": str(transaction_attestation),
            "document_sha256": repair["document_sha256"],
            "terminal_document_sha256": terminal["document_sha256"],
            "plan_id": repair["plan_id"],
            "operation_id": repair["operation_id"],
            "repository_id": repair["repository_id"],
            "observation_snapshot_id": repair["observation_snapshot_id"],
            "release_digest": release_digest,
            "readiness": readiness,
            "writes_performed": False,
            "maintenance_deployment_id": deployment_id,
            "maintenance_cleared": True,
        }
    if (
        marker is None
        and repair is not None
        and _shared_root_broker_is_healthy(current_service)
    ):
        try:
            readiness = _validate_authority_repository_service_readiness_proof(
                readiness_verifier(
                    phase="authenticated",
                    release=release,
                    database=database,
                    authority_uid=authority_uid,
                    authority_generation=authority_generation,
                    binding=binding,
                    now_reader=now_reader,
                ),
                phase="authenticated",
                binding=binding,
                generation=authority_generation,
            )
            if readiness["socket_peer"]["pid"] != current_service["main_pid"]:
                raise CutoverError(
                    "shared-root inventory canary reached an unexpected broker PID"
                )
        except BaseException:
            maintenance_activator(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                deployment_id=deployment_id,
                scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
                message=PUBLIC_MAINTENANCE_MESSAGE,
                retry_after_seconds=5,
                started_at=started_at,
                maintenance_root=maintenance_root,
            )
            raise
        terminal = publish_terminal(readiness, repair)
        return {
            "ok": True,
            "replayed": True,
            "attestation": str(result_location),
            "transaction_attestation": str(transaction_attestation),
            "document_sha256": repair["document_sha256"],
            "terminal_document_sha256": terminal["document_sha256"],
            "plan_id": repair["plan_id"],
            "operation_id": repair["operation_id"],
            "repository_id": repair["repository_id"],
            "observation_snapshot_id": repair["observation_snapshot_id"],
            "release_digest": release_digest,
            "readiness": readiness,
            "writes_performed": False,
            "maintenance_deployment_id": deployment_id,
            "maintenance_cleared": True,
        }
    if marker is None:
        try:
            maintenance_activator(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                deployment_id=deployment_id,
                scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
                message=PUBLIC_MAINTENANCE_MESSAGE,
                retry_after_seconds=5,
                started_at=started_at,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "shared-root positive-absence maintenance activation failed"
            ) from error
        marker = read_marker()
        planned_maintenance = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=deployment_id,
        )
    if planned_maintenance is None:
        raise CutoverError(
            "shared-root positive-absence maintenance belongs to another operation"
        )
    phase("after-maintenance")

    repair_error: BaseException | None = None
    writes_performed = False
    if repair is None:
        try:
            current_service = service_state()
            if _shared_root_broker_is_healthy(current_service):
                if command_status(["/usr/bin/systemctl", "stop", unit]) != 0:
                    raise CutoverError(
                        "shared-root broker did not stop behind maintenance"
                    )
            elif not _shared_root_broker_is_stopped(current_service):
                raise CutoverError(
                    "shared-root broker is neither healthy nor safely stopped"
                )
            stopped = wait_for_service(_shared_root_broker_is_stopped, "stopped")
            time.sleep(0.1)
            if service_state() != stopped:
                raise CutoverError(
                    "shared-root broker stop proof did not remain stable"
                )
            phase("after-stop")
            apply_summary = applier(
                authority_database=database,
                plan_path=plan_location,
                plan_document_sha256=plan_document_sha256,
                attestation=result_location,
                maintenance_root=maintenance_root,
                maintenance_gid=maintenance_gid,
                maintenance_deployment_id=deployment_id,
                authority_uid=authority_uid,
                **dict(applier_options or {}),
            )
            writes_performed = bool(
                isinstance(apply_summary, Mapping)
                and apply_summary.get("writes_performed") is True
            )
            repair = completed_result()
            if repair is None:
                raise CutoverError(
                    "shared-root positive-absence result was not published"
                )
            phase("after-apply")
        except BaseException as error:
            repair_error = error

    current_service = service_state()
    if not _shared_root_broker_is_healthy(current_service):
        if not _shared_root_broker_is_stopped(current_service):
            raise CutoverError(
                "shared-root broker cannot be safely restarted"
            ) from repair_error
        if command_status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise CutoverError(
                "shared-root broker did not restart after positive-absence repair"
            ) from repair_error
    healthy_service = wait_for_service(_shared_root_broker_is_healthy, "healthy")
    time.sleep(0.1)
    if service_state() != healthy_service:
        raise CutoverError(
            "shared-root broker readiness did not remain stable"
        ) from repair_error
    phase("after-restart")
    if repair_error is not None:
        raise repair_error
    if repair is None:
        raise CutoverError(
            "shared-root positive-absence result was not published"
        )
    marker = read_marker()
    if (
        _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=deployment_id,
        )
        != planned_maintenance
    ):
        raise CutoverError(
            "shared-root positive-absence maintenance marker changed"
        )
    preclear = _validate_authority_repository_service_readiness_proof(
        readiness_verifier(
            phase="preclear",
            release=release,
            database=database,
            authority_uid=authority_uid,
            authority_generation=authority_generation,
            binding=binding,
            now_reader=now_reader,
        ),
        phase="preclear",
        binding=binding,
        generation=authority_generation,
    )
    if preclear["socket_peer"]["pid"] != healthy_service["main_pid"]:
        raise CutoverError(
            "shared-root preclear readiness reached an unexpected broker PID"
        )
    phase("after-preclear")
    try:
        cleared = maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=deployment_id,
            maintenance_root=maintenance_root,
        )
    except MaintenanceMarkerError as error:
        raise CutoverError(
            "shared-root positive-absence maintenance clear failed"
        ) from error
    if cleared is not True or read_marker() is not None:
        raise CutoverError(
            "shared-root positive-absence maintenance was not cleared"
        )
    try:
        phase("after-clear")
        readiness = _validate_authority_repository_service_readiness_proof(
            readiness_verifier(
                phase="authenticated",
                release=release,
                database=database,
                authority_uid=authority_uid,
                authority_generation=authority_generation,
                binding=binding,
                now_reader=now_reader,
            ),
            phase="authenticated",
            binding=binding,
            generation=authority_generation,
        )
        if (
            readiness["socket_identity"] != preclear["socket_identity"]
            or readiness["socket_peer"] != preclear["socket_peer"]
            or readiness["socket_peer"]["pid"] != healthy_service["main_pid"]
            or readiness["invariants"]["database_identity"]
            != preclear["invariants"]["database_identity"]
        ):
            raise CutoverError(
                "shared-root broker changed across authenticated readiness"
            )
        phase("after-authenticated")
    except BaseException:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(planned_maintenance["started_at"]),
            maintenance_root=maintenance_root,
        )
        raise
    terminal = publish_terminal(readiness, repair)
    return {
        "ok": True,
        "replayed": not writes_performed,
        "attestation": str(result_location),
        "transaction_attestation": str(transaction_attestation),
        "document_sha256": repair["document_sha256"],
        "terminal_document_sha256": terminal["document_sha256"],
        "plan_id": repair["plan_id"],
        "operation_id": repair["operation_id"],
        "repository_id": repair["repository_id"],
        "observation_snapshot_id": repair["observation_snapshot_id"],
        "release_digest": release_digest,
        "readiness": readiness,
        "writes_performed": writes_performed,
        "maintenance_deployment_id": deployment_id,
        "maintenance_cleared": True,
    }


def plan_authority_repository_disable(
    *,
    authority_database: Path,
    repository_id: str,
    plan_path: Path,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
) -> dict[str, object]:
    """Seal a no-write plan for one provably bogus shared-root repository."""

    if os.geteuid() != authority_uid:
        raise CutoverError("authority repair planning requires the authority owner")
    if (
        not isinstance(repository_id, str)
        or not repository_id
        or len(repository_id.encode("utf-8")) > 256
        or any(character in repository_id for character in "\x00\r\n")
    ):
        raise CutoverError("authority repair repository ID is invalid")
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    database = _absolute(authority_database, "authority database")
    before_identity = identity_reader(database, uid=authority_uid)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        _authority_repair_schema(connection)
        schema_row = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if schema_row is None or int(schema_row[0]) != 12:
            raise CutoverError(
                "authority repository disable supports only schema-12 authority"
            )
        metadata, snapshot, startup_policies = _authority_repository_repair_snapshot(
            connection, repository_id
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    after_identity = identity_reader(database, uid=authority_uid)
    if before_identity != after_identity:
        raise CutoverError("authority database changed while the repair plan was read")
    if (
        snapshot["canonical_root"] not in SHARED_TEMPORARY_REPOSITORY_ROOTS
        or snapshot["state"] != "active"
        or snapshot["installation_status"] != "installed"
        or snapshot["installation_startup_fenced"] is not False
        or snapshot["installation_operation_id"] is not None
        or snapshot["enrollment_count"] != 0
    ):
        raise CutoverError(
            "authority repository is not the exact unfenced, unenrolled stale target"
        )
    unsupported = [
        str(policy["policy_id"])
        for policy in startup_policies
        if policy["requires_update"]
        and policy["policy_kind"] not in {"coordinator", "compose"}
    ]
    if unsupported:
        raise CutoverError(
            "authority repository contains an enabled native startup policy; "
            "restore repository lifecycle authority and decommission it through "
            f"the normal lifecycle: {unsupported[0]}"
        )
    root_proof = root_reader(snapshot["canonical_root"])
    if (
        not isinstance(root_proof, Mapping)
        or set(root_proof)
        != {"device", "inode", "mode", "owner_uid", "git_metadata_absent"}
        or root_proof["owner_uid"] != 0
        or root_proof["mode"] != "1777"
        or root_proof["git_metadata_absent"] is not True
    ):
        raise CutoverError("authority shared temporary root proof is invalid")
    document = seal(
        AUTHORITY_REPOSITORY_DISABLE_PLAN_KIND,
        {
            "plan_id": str(uuid.uuid4()),
            "authority_database": str(database),
            "authority_uid": authority_uid,
            "authority_generation": metadata["authority_generation"],
            "authority_state_revision": metadata["state_revision"],
            "database_identity": dict(before_identity),
            "repository": {
                "repository_id": repository_id,
                "display_name": snapshot["display_name"],
                "canonical_root": snapshot["canonical_root"],
                "generation": snapshot["generation"],
                "state": snapshot["state"],
                "repository_updated_at": snapshot["repository_updated_at"],
                "installation_status": snapshot["installation_status"],
                "installation_startup_fenced": snapshot[
                    "installation_startup_fenced"
                ],
                "installation_generation": snapshot[
                    "installation_generation"
                ],
                "installation_operation_id": snapshot[
                    "installation_operation_id"
                ],
                "installation_disabled_at": snapshot[
                    "installation_disabled_at"
                ],
                "installation_reason": snapshot["installation_reason"],
                "installation_actor": snapshot["installation_actor"],
                "installation_updated_at": snapshot[
                    "installation_updated_at"
                ],
                "root_identity": {
                    field: root_proof[field]
                    for field in ("device", "inode", "mode", "owner_uid")
                },
            },
            "startup_policies": startup_policies,
            "enrollment_count": 0,
            "shared_temporary_root": True,
            "git_metadata_absent": True,
            "target": {
                "repository_state": "missing",
                "installation_status": "disabled",
                "startup_fenced": True,
            },
            "reason": AUTHORITY_REPOSITORY_REPAIR_REASON,
            "created_at": _now(),
        },
    )
    verified = _validate_authority_repository_disable_plan(document)
    _publish_evidence(_absolute(plan_path, "authority repair plan"), verified, uid=authority_uid)
    return {
        "ok": True,
        "plan": str(plan_path),
        "plan_id": verified["plan_id"],
        "document_sha256": verified["document_sha256"],
        "repository_id": repository_id,
        "writes_performed": False,
    }


def _authority_repair_expected_snapshot(
    *,
    plan: Mapping[str, object],
    snapshot: Mapping[str, object],
    startup_policies: object,
) -> bool:
    repository = plan["repository"]
    return bool(
        isinstance(repository, Mapping)
        and snapshot["repository_id"] == repository["repository_id"]
        and snapshot["display_name"] == repository["display_name"]
        and snapshot["canonical_root"] == repository["canonical_root"]
        and snapshot["generation"] == repository["generation"]
        and snapshot["state"] == repository["state"]
        and snapshot["repository_updated_at"]
        == repository["repository_updated_at"]
        and snapshot["installation_status"] == repository["installation_status"]
        and snapshot["installation_startup_fenced"]
        is repository["installation_startup_fenced"]
        and snapshot["installation_generation"]
        == repository["installation_generation"]
        and snapshot["installation_operation_id"]
        == repository["installation_operation_id"]
        and snapshot["installation_disabled_at"]
        == repository["installation_disabled_at"]
        and snapshot["installation_reason"] == repository["installation_reason"]
        and snapshot["installation_actor"] == repository["installation_actor"]
        and snapshot["installation_updated_at"]
        == repository["installation_updated_at"]
        and snapshot["enrollment_count"] == 0
        and _authority_startup_policies_match_initial(
            plan["startup_policies"], startup_policies
        )
    )


def _authority_repair_same_database(
    *, planned: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Bind a descendant authority state to the same database inode.

    SQLite's main-file size is mutable authority state, not identity.  An
    unrelated committed write may therefore grow the file after planning.
    Device and inode remain the fail-closed identity boundary.
    """

    return bool(
        set(current) == {"device", "inode", "size"}
        and all(type(current[field]) is int for field in current)
        and int(current["device"]) == int(planned["device"])
        and int(current["inode"]) == int(planned["inode"])
        and int(current["size"]) > 0
    )


def _authority_repair_mutation_reason(
    *, plan_id: str, deployment_id: str, state_revision_before: int
) -> str:
    return (
        f"{AUTHORITY_REPOSITORY_REPAIR_REASON}; plan={plan_id}; "
        f"maintenance={deployment_id}; "
        f"state_revision_before={state_revision_before}"
    )


def _authority_repair_reason_revision(
    *, reason: object, plan_id: str, deployment_id: str
) -> int | None:
    prefix = (
        f"{AUTHORITY_REPOSITORY_REPAIR_REASON}; plan={plan_id}; "
        f"maintenance={deployment_id}; state_revision_before="
    )
    if not isinstance(reason, str) or not reason.startswith(prefix):
        return None
    raw_revision = reason[len(prefix) :]
    if re.fullmatch(r"0|[1-9][0-9]*", raw_revision) is None:
        return None
    revision = int(raw_revision)
    return revision if revision >= 0 else None


def _validate_authority_repository_disable_result(
    value: object, *, allow_legacy: bool = False
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CutoverError("authority repository repair result must be an object")
    unsigned_fields = set(value) - {"schema_version", "kind", "document_sha256"}
    legacy = unsigned_fields == set(LEGACY_AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS)
    if legacy and not allow_legacy:
        raise CutoverError("legacy authority repository repair result is not accepted")
    fields = (
        LEGACY_AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS
        if legacy
        else AUTHORITY_REPOSITORY_DISABLE_RESULT_FIELDS
    )
    result = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_DISABLE_RESULT_KIND,
        fields=fields,
    )
    try:
        plan_id = str(uuid.UUID(str(result["plan_id"])))
        deployment_id = str(uuid.UUID(str(result["maintenance_deployment_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority repository repair result identity is invalid") from error
    identities = (
        result["database_identity_before"],
        result["database_identity_after"],
    )
    reason_revision = _authority_repair_reason_revision(
        reason=result["reason"], plan_id=plan_id, deployment_id=deployment_id
    )
    if (
        plan_id != result["plan_id"]
        or deployment_id != result["maintenance_deployment_id"]
        or re.fullmatch(r"[0-9a-f]{64}", str(result["plan_document_sha256"]))
        is None
        or not isinstance(result["authority_database"], str)
        or str(_absolute(str(result["authority_database"]), "authority database"))
        != result["authority_database"]
        or type(result["authority_uid"]) is not int
        or int(result["authority_uid"]) < 0
        or not isinstance(result["authority_generation"], str)
        or not result["authority_generation"]
        or any(
            not isinstance(identity, Mapping)
            or set(identity) != {"device", "inode", "size"}
            or any(type(identity[field]) is not int for field in identity)
            or int(identity["device"]) < 0
            or int(identity["inode"]) <= 0
            or int(identity["size"]) <= 0
            for identity in identities
        )
        or identities[0]["device"] != identities[1]["device"]
        or identities[0]["inode"] != identities[1]["inode"]
        or not isinstance(result["repository_id"], str)
        or not result["repository_id"]
        or type(result["repository_generation_before"]) is not int
        or result["repository_generation_after"]
        != int(result["repository_generation_before"]) + 1
        or type(result["installation_generation_before"]) is not int
        or result["installation_generation_after"]
        != int(result["installation_generation_before"]) + 1
        or type(result["state_revision_before"]) is not int
        or result["state_revision_after"] != int(result["state_revision_before"]) + 1
        or reason_revision != result["state_revision_before"]
        or result["repository_state"] != "missing"
        or result["installation_status"] != "disabled"
        or result["startup_fenced"] is not True
        or result["enrollment_count"] != 0
        or result["actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or not isinstance(result["applied_at"], str)
        or not result["applied_at"]
    ):
        raise CutoverError("authority repository repair result is invalid")
    if not legacy:
        policies = _validate_authority_startup_policy_results(
            result["startup_policies"]
        )
        if (
            type(result["startup_policy_count"]) is not int
            or result["startup_policy_count"] != len(policies)
            or type(result["startup_policy_update_count"]) is not int
            or result["startup_policy_update_count"]
            != sum(int(bool(policy["requires_update"])) for policy in policies)
            or any(
                policy["requires_update"]
                and policy["updated_at_after"] != result["applied_at"]
                for policy in policies
            )
        ):
            raise CutoverError("authority repository repair policy result is invalid")
    return result


def apply_authority_repository_disable(
    *,
    plan_path: Path,
    plan_document_sha256: str,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
    maintenance_state_reader=None,
    maintenance_lock_factory=None,
    broker_lock_factory=None,
    before_commit_hook=None,
    after_commit_hook=None,
) -> dict[str, object]:
    """Apply one exact sealed repair behind maintenance and the writer lock."""

    if os.geteuid() != authority_uid:
        raise CutoverError("authority repair apply requires the authority owner")
    plan_document = read_private_json(
        _absolute(plan_path, "authority repair plan"), uid=authority_uid
    )
    plan = _validate_authority_repository_disable_plan(plan_document)
    if (
        re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan["document_sha256"] != plan_document_sha256
    ):
        raise CutoverError("authority repair plan digest does not match")
    try:
        deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority repair maintenance identity is invalid") from error
    if deployment_id != maintenance_deployment_id:
        raise CutoverError("authority repair maintenance identity is invalid")
    maintenance_reader = maintenance_state_reader or load_maintenance_state
    maintenance_locker = maintenance_lock_factory or maintenance_writer_lock
    maintenance_root = _absolute(maintenance_root, "maintenance root")

    def require_maintenance() -> object:
        try:
            current = maintenance_reader(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "authority repair maintenance marker is invalid"
            ) from error
        if (
            current is None
            or current.deployment_id != deployment_id
            or current.message != PUBLIC_MAINTENANCE_MESSAGE
        ):
            raise CutoverError(
                "authority repair requires the exact active maintenance fence"
            )
        return current

    require_maintenance()
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    lock_factory = broker_lock_factory or exclusive_broker_service_lock
    database = _absolute(str(plan["authority_database"]), "authority database")
    if authority_uid != plan["authority_uid"]:
        raise CutoverError("authority repair owner differs from the sealed plan")
    expected_repository = plan["repository"]
    if not isinstance(expected_repository, Mapping):
        raise CutoverError("authority repair repository plan is invalid")
    mutated = False
    state_revision_before: int | None = None
    state_revision_after: int | None = None
    mutation_reason: str | None = None
    with lock_factory(database), maintenance_locker(
        maintenance_root=maintenance_root,
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
    ):
        require_maintenance()
        identity_before = identity_reader(database, uid=authority_uid)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            _authority_repair_schema(connection)
            schema_row = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()
            if schema_row is None or int(schema_row[0]) != 12:
                raise CutoverError(
                    "authority repository disable supports only schema-12 authority"
                )
            metadata, snapshot, startup_policies = _authority_repository_repair_snapshot(
                connection, str(expected_repository["repository_id"])
            )
            root_proof = root_reader(snapshot["canonical_root"])
            if (
                not isinstance(root_proof, Mapping)
                or set(root_proof)
                != {"device", "inode", "mode", "owner_uid", "git_metadata_absent"}
                or root_proof["git_metadata_absent"] is not True
                or {
                    key: root_proof[key]
                    for key in ("device", "inode", "mode", "owner_uid")
                }
                != expected_repository["root_identity"]
            ):
                raise CutoverError("authority repair root proof changed after planning")
            same_database = _authority_repair_same_database(
                planned=plan["database_identity"], current=identity_before
            )
            initial = (
                metadata["authority_generation"] == plan["authority_generation"]
                and metadata["state_revision"] >= plan["authority_state_revision"]
                and same_database
                and _authority_repair_expected_snapshot(
                    plan=plan,
                    snapshot=snapshot,
                    startup_policies=startup_policies,
                )
            )
            recovered_state_revision = _authority_repair_reason_revision(
                reason=snapshot["installation_reason"],
                plan_id=str(plan["plan_id"]),
                deployment_id=deployment_id,
            )
            recovered_reason = (
                None
                if recovered_state_revision is None
                else _authority_repair_mutation_reason(
                    plan_id=str(plan["plan_id"]),
                    deployment_id=deployment_id,
                    state_revision_before=recovered_state_revision,
                )
            )
            recovered = bool(
                metadata["authority_generation"] == plan["authority_generation"]
                and same_database
                and recovered_state_revision is not None
                and recovered_state_revision >= int(plan["authority_state_revision"])
                and metadata["state_revision"] >= recovered_state_revision + 1
                and snapshot["repository_id"] == expected_repository["repository_id"]
                and snapshot["canonical_root"] == expected_repository["canonical_root"]
                and snapshot["generation"]
                == int(expected_repository["generation"]) + 1
                and snapshot["state"] == "missing"
                and snapshot["installation_status"] == "disabled"
                and snapshot["installation_startup_fenced"] is True
                and snapshot["installation_generation"]
                == int(expected_repository["installation_generation"]) + 1
                and snapshot["installation_operation_id"] is None
                and snapshot["installation_reason"] == recovered_reason
                and snapshot["installation_actor"]
                == AUTHORITY_REPOSITORY_REPAIR_ACTOR
                and snapshot["installation_disabled_at"]
                == snapshot["installation_updated_at"]
                and snapshot["repository_updated_at"]
                == snapshot["installation_updated_at"]
                and snapshot["enrollment_count"] == 0
            )
            if recovered:
                try:
                    _authority_startup_policy_results(
                        planned=plan["startup_policies"],
                        current=startup_policies,
                        applied_at=str(snapshot["installation_disabled_at"]),
                    )
                except CutoverError:
                    recovered = False
            if not initial and not recovered:
                raise CutoverError("authority repair plan drifted before apply")
            if initial:
                state_revision_before = int(metadata["state_revision"])
                state_revision_after = state_revision_before + 1
                mutation_reason = _authority_repair_mutation_reason(
                    plan_id=str(plan["plan_id"]),
                    deployment_id=deployment_id,
                    state_revision_before=state_revision_before,
                )
                applied_at = _now()
                changed_policy_count = 0
                for policy in _validate_authority_startup_policies(
                    plan["startup_policies"]
                ):
                    if not policy["requires_update"]:
                        continue
                    changed_policy_count += connection.execute(
                        """
                        UPDATE startup_policies
                        SET current_value = desired_disabled_value,
                            generation = generation + 1, updated_at = ?
                        WHERE policy_id = ? AND repo_id = ?
                          AND resource_kind = ? AND resource_id = ?
                          AND policy_kind = ? AND current_value = ?
                          AND desired_disabled_value = ?
                          AND immutable_fingerprint = ? AND generation = ?
                          AND updated_at = ?
                        """,
                        (
                            applied_at,
                            policy["policy_id"],
                            expected_repository["repository_id"],
                            policy["resource_kind"],
                            policy["resource_id"],
                            policy["policy_kind"],
                            policy["current_value"],
                            policy["desired_disabled_value"],
                            policy["immutable_fingerprint"],
                            policy["generation"],
                            policy["updated_at"],
                        ),
                    ).rowcount
                expected_policy_updates = sum(
                    int(bool(policy["requires_update"]))
                    for policy in _validate_authority_startup_policies(
                        plan["startup_policies"]
                    )
                )
                changed_installation = connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        generation = generation + 1, operation_id = NULL,
                        disabled_at = ?, reason = ?, actor = ?, updated_at = ?
                    WHERE repo_id = ? AND status = 'installed'
                      AND startup_fenced = 0 AND generation = ?
                      AND operation_id IS NULL
                    """,
                    (
                        applied_at,
                        mutation_reason,
                        AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                        applied_at,
                        expected_repository["repository_id"],
                        expected_repository["installation_generation"],
                    ),
                ).rowcount
                changed_repository = connection.execute(
                    """
                    UPDATE repositories
                    SET state = 'missing', generation = generation + 1,
                        updated_at = ?
                    WHERE repo_id = ? AND state = 'active' AND generation = ?
                    """,
                    (
                        applied_at,
                        expected_repository["repository_id"],
                        expected_repository["generation"],
                    ),
                ).rowcount
                changed_metadata = connection.execute(
                    """
                    UPDATE schema_metadata
                    SET state_revision = state_revision + 1, updated_at = ?
                    WHERE singleton = 1 AND database_generation = ?
                      AND state_revision = ?
                    """,
                    (
                        applied_at,
                        plan["authority_generation"],
                        state_revision_before,
                    ),
                ).rowcount
                if (changed_installation, changed_repository, changed_metadata) != (
                    1,
                    1,
                    1,
                ):
                    raise CutoverError("authority repair exact-ID mutation was incomplete")
                if changed_policy_count != expected_policy_updates:
                    raise CutoverError(
                        "authority repair exact startup-policy mutation was incomplete"
                    )
                terminal_metadata, terminal_snapshot, terminal_policies = (
                    _authority_repository_repair_snapshot(
                        connection,
                        str(expected_repository["repository_id"]),
                    )
                )
                if (
                    terminal_metadata["state_revision"] != state_revision_after
                    or terminal_snapshot["state"] != "missing"
                    or terminal_snapshot["installation_status"] != "disabled"
                    or terminal_snapshot["installation_startup_fenced"] is not True
                    or not _authority_startup_policies_match_terminal(
                        plan["startup_policies"],
                        terminal_policies,
                        applied_at=applied_at,
                    )
                ):
                    raise CutoverError(
                        "authority repair precommit terminal state is incomplete"
                    )
                if before_commit_hook is not None:
                    before_commit_hook()
                require_maintenance()
                connection.commit()
                mutated = True
                if after_commit_hook is not None:
                    after_commit_hook()
                connection.execute("BEGIN")
                metadata, snapshot, startup_policies = _authority_repository_repair_snapshot(
                    connection, str(expected_repository["repository_id"])
                )
                connection.execute("ROLLBACK")
            else:
                state_revision_before = recovered_state_revision
                if state_revision_before is None or recovered_reason is None:
                    raise CutoverError("authority repair recovery evidence is invalid")
                state_revision_after = state_revision_before + 1
                mutation_reason = recovered_reason
                connection.execute("ROLLBACK")
        except BaseException:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
        identity_after = identity_reader(database, uid=authority_uid)
    if (
        state_revision_before is None
        or state_revision_after is None
        or mutation_reason is None
        or metadata["authority_generation"] != plan["authority_generation"]
        or metadata["state_revision"] < state_revision_after
        or not _authority_repair_same_database(
            planned=plan["database_identity"], current=identity_after
        )
        or snapshot["state"] != "missing"
        or snapshot["installation_status"] != "disabled"
        or snapshot["installation_startup_fenced"] is not True
        or snapshot["installation_reason"] != mutation_reason
        or snapshot["installation_actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
    ):
        raise CutoverError("authority repair terminal state did not verify")
    policy_results = _authority_startup_policy_results(
        planned=plan["startup_policies"],
        current=startup_policies,
        applied_at=str(snapshot["installation_disabled_at"]),
    )
    result = seal(
        AUTHORITY_REPOSITORY_DISABLE_RESULT_KIND,
        {
            "plan_id": plan["plan_id"],
            "plan_document_sha256": plan["document_sha256"],
            "authority_database": str(database),
            "authority_uid": authority_uid,
            "authority_generation": plan["authority_generation"],
            "maintenance_deployment_id": deployment_id,
            "database_identity_before": dict(identity_before),
            "database_identity_after": dict(identity_after),
            "repository_id": expected_repository["repository_id"],
            "repository_generation_before": expected_repository["generation"],
            "repository_generation_after": snapshot["generation"],
            "installation_generation_before": expected_repository[
                "installation_generation"
            ],
            "installation_generation_after": snapshot["installation_generation"],
            "state_revision_before": state_revision_before,
            "state_revision_after": state_revision_after,
            "repository_state": snapshot["state"],
            "installation_status": snapshot["installation_status"],
            "startup_fenced": snapshot["installation_startup_fenced"],
            "startup_policy_count": len(policy_results),
            "startup_policy_update_count": sum(
                int(bool(policy["requires_update"])) for policy in policy_results
            ),
            "startup_policies": policy_results,
            "enrollment_count": snapshot["enrollment_count"],
            "reason": snapshot["installation_reason"],
            "actor": snapshot["installation_actor"],
            "applied_at": snapshot["installation_disabled_at"],
        },
    )
    verified_result = _validate_authority_repository_disable_result(result)
    _publish_evidence(
        _absolute(attestation, "authority repair attestation"),
        verified_result,
        uid=authority_uid,
    )
    return {
        "ok": True,
        "attestation": str(attestation),
        "document_sha256": verified_result["document_sha256"],
        "repository_id": verified_result["repository_id"],
        "replayed": not mutated,
    }


def _authority_repository_matches_repair_result(
    *, repair: Mapping[str, object], snapshot: Mapping[str, object]
) -> bool:
    return bool(
        snapshot["repository_id"] == repair["repository_id"]
        and snapshot["generation"] == repair["repository_generation_after"]
        and snapshot["state"] == "missing"
        and snapshot["installation_status"] == "disabled"
        and snapshot["installation_startup_fenced"] is True
        and snapshot["installation_generation"]
        == repair["installation_generation_after"]
        and snapshot["installation_operation_id"] is None
        and snapshot["installation_disabled_at"] == repair["applied_at"]
        and snapshot["installation_updated_at"] == repair["applied_at"]
        and snapshot["repository_updated_at"] == repair["applied_at"]
        and snapshot["installation_reason"] == repair["reason"]
        and snapshot["installation_actor"] == repair["actor"]
        and snapshot["enrollment_count"] == 0
    )


AUTHORITY_REPOSITORY_PROTECTED_TABLES = (
    "broker_repository_enrollments",
    "repository_aliases",
    "repository_families",
    "repository_scopes",
    "operations",
    "runtime_sessions",
    "source_resources",
    "server_definitions",
    "worker_policies",
    "worker_supervisor_states",
    "startup_policies",
    "startup_policy_restore_states",
    "repository_memberships",
    "control_bindings",
    "port_assignments",
    "leases",
    "broker_lease_links",
    "broker_assignment_links",
    "broker_reconciliation_queue",
    "broker_lifecycle_links",
    "broker_server_materialization_revocations",
    "broker_repository_materialization_revocations",
    "resource_lifecycle_history",
    "cleanup_plans",
    "cleanup_tombstones",
    "worktree_cleanup_identities",
    "docker_ownership_claims",
    "ephemeral_container_templates",
    "ephemeral_container_runs",
    "database_bindings",
)
AUTHORITY_REPOSITORY_INTENTIONALLY_SEPARATE_TABLES = frozenset(
    {
        "repositories",
        "repository_installations",
        "repository_owners",
        "repository_owner_transfers",
        # Historical/result planes do not govern repository lifecycle.
        "worker_attempts",
        "database_backups",
        "backup_evidence",
        "events",
        "test_runs",
    }
)
MAX_AUTHORITY_REPOSITORY_PROTECTED_ROWS = 16384

AUTHORITY_REPOSITORY_PENDING_LIFECYCLE = (
    (
        "operations",
        "status IN ('planned','running','partial','needs_attention')",
    ),
    (
        "runtime_sessions",
        "status IN ('planned','running','cleanup_pending','cleaning')",
    ),
    (
        "broker_lease_links",
        "status IN ('reserved','release_pending','rollback_failed','reconciliation_required')",
    ),
    (
        "broker_assignment_links",
        "status IN ('reserved','release_pending','rollback_failed','reconciliation_required')",
    ),
    (
        "broker_reconciliation_queue",
        "status IN ('pending','operator_required')",
    ),
    (
        "broker_lifecycle_links",
        "status IN ('pending','reconciliation_required','operator_required')",
    ),
    (
        "cleanup_plans",
        "status IN ('planned','running','needs_attention')",
    ),
    (
        "ephemeral_container_runs",
        "status NOT IN ('cleaned','failed')",
    ),
)


def _authority_repository_reject_pending_lifecycle(
    connection: sqlite3.Connection, repository_id: str
) -> None:
    for table, predicate in AUTHORITY_REPOSITORY_PENDING_LIFECYCLE:
        columns = {
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if "repo_id" not in columns or "status" not in columns:
            raise CutoverError(
                f"lifecycle recovery pending-state contract for {table} is unavailable"
            )
        row = connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE repo_id = ? AND ({predicate})",
            (repository_id,),
        ).fetchone()
        if row is None or type(row[0]) is not int:
            raise CutoverError(
                f"lifecycle recovery pending-state evidence for {table} is invalid"
            )
        if int(row[0]) != 0:
            raise CutoverError(
                f"lifecycle recovery rejects pending lifecycle rows in {table}"
            )


def _authority_repository_protected_rows(
    connection: sqlite3.Connection, repository_id: str
) -> dict[str, object]:
    """Fingerprint every lifecycle/native row the compensation must not alter."""

    _authority_repository_reject_pending_lifecycle(connection, repository_id)

    schema_tables = [
        str(table_row[0])
        for table_row in connection.execute(
        """
        SELECT name FROM sqlite_schema
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
        ).fetchall()
    ]
    if any(re.fullmatch(r"[a-z_]+", table) is None for table in schema_tables):
        raise CutoverError("lifecycle recovery schema table name is invalid")
    columns_by_table = {
        table: [
            str(row[1])
            for row in connection.execute(
                f"PRAGMA table_info({table})"
            ).fetchall()
        ]
        for table in schema_tables
    }
    if any(
        not columns
        or any(
            re.fullmatch(r"[a-z][a-z0-9_]*", column) is None
            for column in columns
        )
        for columns in columns_by_table.values()
    ):
        raise CutoverError("lifecycle recovery schema column name is invalid")
    discovered_repo_tables = {
        table for table, columns in columns_by_table.items() if "repo_id" in columns
    }
    missing_required_tables = set(AUTHORITY_REPOSITORY_PROTECTED_TABLES) - (
        discovered_repo_tables | {"repository_families"}
    )
    if missing_required_tables:
        raise CutoverError(
            "lifecycle recovery required table coverage is incomplete: "
            + ", ".join(sorted(missing_required_tables))
        )
    protected_table_set = (
        (discovered_repo_tables - AUTHORITY_REPOSITORY_INTENTIONALLY_SEPARATE_TABLES)
        | {"repository_families"}
    )
    foreign_keys: dict[str, list[tuple[str, tuple[str, ...], tuple[str, ...]]]] = {}
    for child in schema_tables:
        grouped: dict[int, list[tuple[int, str, str, str]]] = {}
        for row in connection.execute(f"PRAGMA foreign_key_list({child})").fetchall():
            grouped.setdefault(int(row[0]), []).append(
                (int(row[1]), str(row[2]), str(row[3]), str(row[4]))
            )
        relationships: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
        for parts in grouped.values():
            ordered = sorted(parts)
            parent = ordered[0][1]
            if (
                parent not in columns_by_table
                or any(
                    part[1] != parent
                    or part[2] not in columns_by_table[child]
                    or part[3] not in columns_by_table[parent]
                    for part in ordered
                )
            ):
                raise CutoverError(
                    f"lifecycle recovery foreign-key contract for {child} is invalid"
                )
            relationships.append(
                (
                    parent,
                    tuple(part[2] for part in ordered),
                    tuple(part[3] for part in ordered),
                )
            )
        foreign_keys[child] = relationships
    changed = True
    while changed:
        changed = False
        for child, relationships in foreign_keys.items():
            if child in AUTHORITY_REPOSITORY_INTENTIONALLY_SEPARATE_TABLES:
                continue
            if child in protected_table_set:
                continue
            if any(parent in protected_table_set for parent, _child, _parent in relationships):
                protected_table_set.add(child)
                changed = True
    protected_tables = sorted(protected_table_set)
    selected: dict[str, dict[bytes, dict[str, object]]] = {
        table: {} for table in protected_tables
    }

    def normalize_rows(table: str, rows: list[object]) -> list[dict[str, object]]:
        columns = columns_by_table[table]
        normalized: list[dict[str, object]] = []
        for row in rows:
            document = {
                column: row[column] if isinstance(row, sqlite3.Row) else row[index]
                for index, column in enumerate(columns)
            }
            if any(
                value is not None
                and (isinstance(value, bool) or not isinstance(value, (str, int)))
                for value in document.values()
            ):
                raise CutoverError(
                    f"lifecycle recovery protected table {table} has unsafe values"
                )
            normalized.append(document)
        return normalized

    for table in protected_tables:
        if re.fullmatch(r"[a-z_]+", table) is None or not columns_by_table[table]:
            raise CutoverError("lifecycle recovery protected table is invalid")
        if table == "repository_families":
            rows = connection.execute(
                """
                SELECT * FROM repository_families
                WHERE root_repo_id = ? OR family_id IN (
                    SELECT family_id FROM repository_scopes WHERE repo_id = ?
                )
                LIMIT ?
                """,
                (repository_id, repository_id, MAX_REPOSITORY_STARTUP_POLICIES + 1),
            ).fetchall()
        elif "repo_id" in columns_by_table[table]:
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE repo_id = ? LIMIT ?",
                (repository_id, MAX_REPOSITORY_STARTUP_POLICIES + 1),
            ).fetchall()
        else:
            rows = []
        if len(rows) > MAX_REPOSITORY_STARTUP_POLICIES:
            raise CutoverError(
                f"lifecycle recovery protected table {table} exceeds its bound"
            )
        for document in normalize_rows(table, rows):
            selected[table][_canonical(document)] = document

    changed = True
    while changed:
        changed = False
        for child in protected_tables:
            for parent, child_columns, parent_columns in foreign_keys[child]:
                if parent not in selected or not selected[parent]:
                    continue
                parent_keys = sorted(
                    {
                        tuple(document[column] for column in parent_columns)
                        for document in selected[parent].values()
                        if all(document[column] is not None for column in parent_columns)
                    },
                    key=_canonical,
                )
                for offset in range(0, len(parent_keys), 100):
                    chunk = parent_keys[offset : offset + 100]
                    clauses = " OR ".join(
                        "(" + " AND ".join(f"{column} = ?" for column in child_columns) + ")"
                        for _key in chunk
                    )
                    parameters = [value for key in chunk for value in key]
                    rows = connection.execute(
                        f"SELECT * FROM {child} WHERE {clauses} LIMIT ?",
                        (*parameters, MAX_REPOSITORY_STARTUP_POLICIES + 1),
                    ).fetchall()
                    if len(rows) > MAX_REPOSITORY_STARTUP_POLICIES:
                        raise CutoverError(
                            f"lifecycle recovery protected table {child} exceeds its bound"
                        )
                    for document in normalize_rows(child, rows):
                        key = _canonical(document)
                        if key not in selected[child]:
                            selected[child][key] = document
                            changed = True
                            if len(selected[child]) > MAX_REPOSITORY_STARTUP_POLICIES:
                                raise CutoverError(
                                    f"lifecycle recovery protected table {child} exceeds its bound"
                                )

    total_rows = sum(len(rows) for rows in selected.values())
    if total_rows > MAX_AUTHORITY_REPOSITORY_PROTECTED_ROWS:
        raise CutoverError(
            "lifecycle recovery protected-row closure exceeds its bound"
        )
    tables: dict[str, object] = {}
    for table in protected_tables:
        normalized = sorted(selected[table].values(), key=_canonical)
        tables[table] = {
            "count": len(normalized),
            "rows_sha256": _digest(normalized),
        }
    return {
        "tables": tables,
        "document_sha256": _digest(tables),
    }


def _validate_authority_repository_protected_rows(
    value: object,
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"tables", "document_sha256"}
        or not isinstance(value["tables"], Mapping)
        or not set(AUTHORITY_REPOSITORY_PROTECTED_TABLES).issubset(
            set(value["tables"])
        )
        or any(
            re.fullmatch(r"[a-z_]+", str(table)) is None
            for table in value["tables"]
        )
        or re.fullmatch(r"[0-9a-f]{64}", str(value["document_sha256"])) is None
        or value["document_sha256"] != _digest(value["tables"])
    ):
        raise CutoverError("lifecycle recovery protected-row evidence is invalid")
    total_rows = 0
    for table in value["tables"]:
        evidence = value["tables"][table]
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != {"count", "rows_sha256"}
            or type(evidence["count"]) is not int
            or not 0 <= int(evidence["count"]) <= MAX_REPOSITORY_STARTUP_POLICIES
            or re.fullmatch(r"[0-9a-f]{64}", str(evidence["rows_sha256"]))
            is None
        ):
            raise CutoverError(
                f"lifecycle recovery protected-row evidence for {table} is invalid"
            )
        total_rows += int(evidence["count"])
    if total_rows > MAX_AUTHORITY_REPOSITORY_PROTECTED_ROWS:
        raise CutoverError("lifecycle recovery protected-row evidence exceeds its bound")
    return {
        "tables": {
            table: dict(value["tables"][table])
            for table in sorted(value["tables"])
        },
        "document_sha256": str(value["document_sha256"]),
    }


def _authority_repository_owner_snapshot(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    repository_generation: int,
    schema_version: int,
) -> dict[str, object]:
    owner_columns = connection.execute("PRAGMA table_info(repository_owners)").fetchall()
    transfer_columns = connection.execute(
        "PRAGMA table_info(repository_owner_transfers)"
    ).fetchall()
    if not owner_columns and not transfer_columns:
        if schema_version >= 13:
            raise CutoverError(
                "schema-13 lifecycle recovery requires repository owner authority"
            )
        return {"mode": "schema12_absent"}
    if not owner_columns or not transfer_columns:
        raise CutoverError("repository owner authority schema is partial")
    connection.row_factory = sqlite3.Row
    owner = connection.execute(
        "SELECT * FROM repository_owners WHERE repo_id = ?", (repository_id,)
    ).fetchone()
    transfers = connection.execute(
        """
        SELECT * FROM repository_owner_transfers
        WHERE repo_id = ? ORDER BY authority_generation, transfer_id
        LIMIT ?
        """,
        (repository_id, MAX_REPOSITORY_STARTUP_POLICIES + 1),
    ).fetchall()
    if owner is None or not transfers or len(transfers) > MAX_REPOSITORY_STARTUP_POLICIES:
        raise CutoverError("repository owner authority is incomplete")
    owner_document = dict(owner)
    transfer_documents = [dict(row) for row in transfers]
    head = transfer_documents[-1]
    if (
        owner_document.get("repo_id") != repository_id
        or owner_document.get("repository_generation") != repository_generation
        or head.get("repo_id") != repository_id
        or head.get("owner_uid") != owner_document.get("owner_uid")
        or head.get("repository_generation") != repository_generation
        or head.get("authority_generation")
        != owner_document.get("authority_generation")
        or head.get("evidence_sha256") != owner_document.get("evidence_sha256")
    ):
        raise CutoverError("repository owner authority generation is stale")
    return {
        "mode": "explicit",
        "owner": owner_document,
        "transfer_count": len(transfer_documents),
        "transfers_sha256": _digest(transfer_documents),
        "head": head,
    }


def _validate_authority_repository_owner_snapshot(
    value: object,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or value.get("mode") not in {
        "schema12_absent",
        "explicit",
    }:
        raise CutoverError("lifecycle recovery owner evidence is invalid")
    if value["mode"] == "schema12_absent":
        if set(value) != {"mode"}:
            raise CutoverError("schema-12 owner absence evidence is invalid")
        return {"mode": "schema12_absent"}
    if (
        set(value) != {"mode", "owner", "transfer_count", "transfers_sha256", "head"}
        or not isinstance(value["owner"], Mapping)
        or not isinstance(value["head"], Mapping)
        or type(value["transfer_count"]) is not int
        or int(value["transfer_count"]) <= 0
        or re.fullmatch(r"[0-9a-f]{64}", str(value["transfers_sha256"])) is None
        or type(value["owner"].get("repository_generation")) is not int
        or type(value["owner"].get("authority_generation")) is not int
        or type(value["head"].get("repository_generation")) is not int
        or type(value["head"].get("authority_generation")) is not int
        or value["owner"].get("repo_id") != value["head"].get("repo_id")
        or value["owner"].get("owner_uid") != value["head"].get("owner_uid")
        or value["owner"].get("repository_generation")
        != value["head"].get("repository_generation")
        or value["owner"].get("authority_generation")
        != value["head"].get("authority_generation")
        or value["owner"].get("evidence_sha256")
        != value["head"].get("evidence_sha256")
    ):
        raise CutoverError("explicit owner authority evidence is invalid")
    return {
        "mode": "explicit",
        "owner": dict(value["owner"]),
        "transfer_count": int(value["transfer_count"]),
        "transfers_sha256": str(value["transfers_sha256"]),
        "head": dict(value["head"]),
    }


def _authority_repository_lifecycle_recovery_reason(
    *, plan_id: str, source_result_sha256: str, state_revision_before: int
) -> str:
    return (
        f"{AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_REASON}; plan={plan_id}; "
        f"source_repair={source_result_sha256}; "
        f"state_revision_before={state_revision_before}"
    )


def _authority_repository_lifecycle_root_matches(
    *, plan: Mapping[str, object], proof: object
) -> bool:
    return bool(
        isinstance(proof, Mapping)
        and set(proof)
        == {"device", "inode", "mode", "owner_uid", "git_metadata_absent"}
        and proof["git_metadata_absent"] is True
        and {
            key: proof[key]
            for key in ("device", "inode", "mode", "owner_uid")
        }
        == plan["repository"]["root_identity"]
    )


def _validate_authority_repository_lifecycle_recovery_plan(
    value: object,
) -> dict[str, object]:
    plan = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_PLAN_KIND,
        fields=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_PLAN_FIELDS,
    )
    try:
        plan_id = str(uuid.UUID(str(plan["plan_id"])))
        operation_id = str(uuid.UUID(str(plan["operation_id"])))
        source_plan_id = str(uuid.UUID(str(plan["source_repair_plan_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("lifecycle recovery plan identity is invalid") from error
    repository = plan["repository"]
    target = plan["target"]
    identity = plan["database_identity"]
    protected = _validate_authority_repository_protected_rows(
        plan["protected_rows"]
    )
    owner = _validate_authority_repository_owner_snapshot(plan["owner_authority"])
    if (
        plan_id != plan["plan_id"]
        or operation_id != plan["operation_id"]
        or source_plan_id != plan["source_repair_plan_id"]
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(plan[field])) is None
            for field in (
                "source_repair_plan_sha256",
                "source_repair_result_sha256",
            )
        )
        or not isinstance(plan["authority_database"], str)
        or str(_absolute(str(plan["authority_database"]), "authority database"))
        != plan["authority_database"]
        or plan["authority_uid"] != 0
        or not isinstance(plan["authority_generation"], str)
        or not plan["authority_generation"]
        or type(plan["authority_schema_version"]) is not int
        or int(plan["authority_schema_version"]) != 12
        or plan["authority_migration_state"] != "ready"
        or type(plan["authority_state_revision"]) is not int
        or int(plan["authority_state_revision"]) < 0
        or not isinstance(identity, Mapping)
        or set(identity) != {"device", "inode", "size"}
        or any(type(identity[field]) is not int for field in identity)
        or int(identity["inode"]) <= 0
        or int(identity["size"]) <= 0
        or not isinstance(repository, Mapping)
        or set(repository)
        != {
            "repository_id",
            "display_name",
            "canonical_root",
            "generation",
            "state",
            "repository_updated_at",
            "installation_status",
            "installation_startup_fenced",
            "installation_generation",
            "installation_operation_id",
            "installation_disabled_at",
            "installation_reason",
            "installation_actor",
            "installation_updated_at",
            "enrollment_count",
            "root_identity",
        }
        or repository["canonical_root"] not in SHARED_TEMPORARY_REPOSITORY_ROOTS
        or repository["state"] != "missing"
        or repository["installation_status"] != "disabled"
        or repository["installation_startup_fenced"] is not True
        or repository["installation_operation_id"] is not None
        or repository["enrollment_count"] != 0
        or repository["installation_actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or not isinstance(repository["installation_reason"], str)
        or not repository["installation_reason"]
        or not isinstance(target, Mapping)
        or dict(target)
        != {
            "repository_state": "active",
            "repository_generation": int(repository["generation"]) + 1,
            "installation_status": "installed",
            "installation_startup_fenced": False,
            "installation_generation": int(repository["installation_generation"])
            + 1,
            "state_revision": int(plan["authority_state_revision"]) + 1,
        }
        or not isinstance(plan["mutation_updated_at"], str)
        or not plan["mutation_updated_at"]
        or plan["reason"]
        != _authority_repository_lifecycle_recovery_reason(
            plan_id=plan_id,
            source_result_sha256=str(plan["source_repair_result_sha256"]),
            state_revision_before=int(plan["authority_state_revision"]),
        )
        or not isinstance(plan["created_at"], str)
        or not plan["created_at"]
        or owner["mode"] != "schema12_absent"
        or protected != plan["protected_rows"]
    ):
        raise CutoverError("lifecycle recovery plan is invalid")
    root_identity = repository["root_identity"]
    if (
        not isinstance(root_identity, Mapping)
        or set(root_identity) != {"device", "inode", "mode", "owner_uid"}
        or root_identity["mode"] != "1777"
        or root_identity["owner_uid"] != 0
    ):
        raise CutoverError("lifecycle recovery root identity is invalid")
    return plan


def plan_authority_repository_lifecycle_recovery(
    *,
    repair_plan: Path,
    repair_plan_document_sha256: str,
    repair_attestation: Path,
    repair_attestation_document_sha256: str,
    plan_path: Path,
    operation_id: str,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
    now_reader=_now,
    effective_uid_reader=os.geteuid,
    evidence_reader=None,
    evidence_publisher=None,
) -> dict[str, object]:
    """Seal a compensating re-enable without touching native lifecycle rows."""

    if effective_uid_reader() != authority_uid or authority_uid != 0:
        raise CutoverError("lifecycle recovery planning requires root authority")
    reader = read_private_json if evidence_reader is None else evidence_reader
    publisher = _publish_evidence if evidence_publisher is None else evidence_publisher
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("lifecycle recovery operation ID is invalid") from error
    source_plan = _validate_authority_repository_disable_plan(
        reader(_absolute(repair_plan, "source repair plan"), uid=0),
        allow_legacy=True,
    )
    repair = _validate_authority_repository_disable_result(
        reader(
            _absolute(repair_attestation, "source repair attestation"), uid=0
        ),
        allow_legacy=True,
    )
    if (
        source_plan["document_sha256"] != repair_plan_document_sha256
        or repair["document_sha256"] != repair_attestation_document_sha256
        or repair["plan_id"] != source_plan["plan_id"]
        or repair["plan_document_sha256"] != source_plan["document_sha256"]
        or repair["authority_database"] != source_plan["authority_database"]
        or repair["authority_generation"] != source_plan["authority_generation"]
        or repair["repository_id"] != source_plan["repository"]["repository_id"]
    ):
        raise CutoverError("lifecycle recovery source repair binding changed")
    database = _absolute(str(repair["authority_database"]), "authority database")
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    before_identity = identity_reader(database, uid=0)
    if not _authority_repair_same_database(
        planned=repair["database_identity_after"], current=before_identity
    ):
        raise CutoverError("lifecycle recovery database identity changed")
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        _authority_repair_schema(connection)
        schema_row = connection.execute(
            """
            SELECT schema_version, migration_state
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        metadata, snapshot, policies = _authority_repository_repair_snapshot(
            connection, str(repair["repository_id"])
        )
        if schema_row is None:
            raise CutoverError("lifecycle recovery schema version is unavailable")
        schema_version = int(schema_row[0])
        migration_state = str(schema_row[1])
        if schema_version != 12 or migration_state != "ready":
            raise CutoverError(
                "lifecycle recovery requires ready schema-12 authority"
            )
        protected = _authority_repository_protected_rows(
            connection, str(repair["repository_id"])
        )
        owner = _authority_repository_owner_snapshot(
            connection,
            repository_id=str(repair["repository_id"]),
            repository_generation=int(snapshot["generation"]),
            schema_version=schema_version,
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    if identity_reader(database, uid=0) != before_identity:
        raise CutoverError("authority changed during lifecycle recovery planning")
    if (
        schema_version != 12
        or migration_state != "ready"
        or metadata["authority_generation"] != repair["authority_generation"]
        or metadata["state_revision"] < repair["state_revision_after"]
        or not _authority_repository_matches_repair_result(
            repair=repair, snapshot=snapshot
        )
        or not any(
            policy["requires_update"]
            and policy["policy_kind"] in {"docker_restart", "supervisor"}
            for policy in policies
        )
    ):
        raise CutoverError(
            "lifecycle recovery requires the exact disabled repository with an "
            "enabled native startup policy"
        )
    root_proof = root_reader(snapshot["canonical_root"])
    if (
        not isinstance(root_proof, Mapping)
        or set(root_proof)
        != {"device", "inode", "mode", "owner_uid", "git_metadata_absent"}
        or root_proof["git_metadata_absent"] is not True
        or root_proof["mode"] != "1777"
        or root_proof["owner_uid"] != 0
        or {
            key: root_proof[key]
            for key in ("device", "inode", "mode", "owner_uid")
        }
        != source_plan["repository"]["root_identity"]
    ):
        raise CutoverError("lifecycle recovery shared-root proof changed")
    timestamp = now_reader()
    plan_id = str(uuid.uuid4())
    reason = _authority_repository_lifecycle_recovery_reason(
        plan_id=plan_id,
        source_result_sha256=str(repair["document_sha256"]),
        state_revision_before=int(metadata["state_revision"]),
    )
    document = _validate_authority_repository_lifecycle_recovery_plan(
        seal(
            AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_PLAN_KIND,
            {
                "plan_id": plan_id,
                "operation_id": operation_id,
                "source_repair_plan_sha256": source_plan["document_sha256"],
                "source_repair_result_sha256": repair["document_sha256"],
                "source_repair_plan_id": source_plan["plan_id"],
                "authority_database": str(database),
                "authority_uid": 0,
                "authority_generation": metadata["authority_generation"],
                "authority_schema_version": schema_version,
                "authority_migration_state": migration_state,
                "authority_state_revision": metadata["state_revision"],
                "database_identity": dict(before_identity),
                "repository": {
                    **snapshot,
                    "root_identity": {
                        key: root_proof[key]
                        for key in ("device", "inode", "mode", "owner_uid")
                    },
                },
                "protected_rows": protected,
                "owner_authority": owner,
                "target": {
                    "repository_state": "active",
                    "repository_generation": int(snapshot["generation"]) + 1,
                    "installation_status": "installed",
                    "installation_startup_fenced": False,
                    "installation_generation": int(
                        snapshot["installation_generation"]
                    )
                    + 1,
                    "state_revision": int(metadata["state_revision"]) + 1,
                },
                "mutation_updated_at": timestamp,
                "reason": reason,
                "created_at": timestamp,
            },
        )
    )
    publisher(
        _absolute(plan_path, "lifecycle recovery plan"), document, uid=0
    )
    return {
        "ok": True,
        "plan": str(plan_path),
        "plan_id": plan_id,
        "operation_id": operation_id,
        "document_sha256": document["document_sha256"],
        "repository_id": repair["repository_id"],
        "protected_rows_sha256": protected["document_sha256"],
        "writes_performed": False,
    }


def _authority_repository_owner_is_recovered(
    *,
    before: Mapping[str, object],
    current: Mapping[str, object],
    plan: Mapping[str, object],
) -> bool:
    if before["mode"] == "schema12_absent":
        return current == {"mode": "schema12_absent"}
    if current.get("mode") != "explicit":
        return False
    before_owner = before["owner"]
    owner = current["owner"]
    head = current["head"]
    return bool(
        owner.get("repo_id") == before_owner.get("repo_id")
        and owner.get("owner_uid") == before_owner.get("owner_uid")
        and owner.get("repository_generation")
        == plan["target"]["repository_generation"]
        and owner.get("authority_generation")
        == int(before_owner.get("authority_generation")) + 1
        and owner.get("operation_id") == plan["operation_id"]
        and owner.get("established_by") == AUTHORITY_REPOSITORY_REPAIR_ACTOR
        and owner.get("established_at") == plan["mutation_updated_at"]
        and current.get("transfer_count") == int(before["transfer_count"]) + 1
        and head.get("repository_generation")
        == plan["target"]["repository_generation"]
        and head.get("authority_generation") == owner.get("authority_generation")
        and head.get("operation_id") == plan["operation_id"]
        and head.get("actor") == AUTHORITY_REPOSITORY_REPAIR_ACTOR
        and head.get("reason") == plan["reason"]
        and head.get("transferred_at") == plan["mutation_updated_at"]
        and head.get("evidence_sha256") == owner.get("evidence_sha256")
    )


def _authority_repository_lifecycle_recovery_terminal(
    *,
    plan: Mapping[str, object],
    metadata: Mapping[str, object],
    snapshot: Mapping[str, object],
    protected: Mapping[str, object],
    owner: Mapping[str, object],
) -> bool:
    return bool(
        metadata["authority_generation"] == plan["authority_generation"]
        and metadata["state_revision"] >= plan["target"]["state_revision"]
        and snapshot["repository_id"] == plan["repository"]["repository_id"]
        and snapshot["canonical_root"] == plan["repository"]["canonical_root"]
        and snapshot["generation"] == plan["target"]["repository_generation"]
        and snapshot["state"] == "active"
        and snapshot["repository_updated_at"] == plan["mutation_updated_at"]
        and snapshot["installation_status"] == "installed"
        and snapshot["installation_startup_fenced"] is False
        and snapshot["installation_generation"]
        == plan["target"]["installation_generation"]
        and snapshot["installation_operation_id"] is None
        and snapshot["installation_disabled_at"] is None
        and snapshot["installation_reason"] == plan["reason"]
        and snapshot["installation_actor"] == AUTHORITY_REPOSITORY_REPAIR_ACTOR
        and snapshot["installation_updated_at"] == plan["mutation_updated_at"]
        and snapshot["enrollment_count"] == 0
        and protected == plan["protected_rows"]
        and _authority_repository_owner_is_recovered(
            before=plan["owner_authority"], current=owner, plan=plan
        )
    )


def _validate_authority_repository_lifecycle_recovery_result(
    value: object,
) -> dict[str, object]:
    result = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_RESULT_KIND,
        fields=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_RESULT_FIELDS,
    )
    try:
        plan_id = str(uuid.UUID(str(result["plan_id"])))
        operation_id = str(uuid.UUID(str(result["operation_id"])))
        deployment_id = str(uuid.UUID(str(result["maintenance_deployment_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("lifecycle recovery result identity is invalid") from error
    identities = (
        result["database_identity_before"],
        result["database_identity_after"],
    )
    if (
        plan_id != result["plan_id"]
        or operation_id != result["operation_id"]
        or deployment_id != result["maintenance_deployment_id"]
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(result[field])) is None
            for field in (
                "plan_document_sha256",
                "source_repair_plan_sha256",
                "source_repair_result_sha256",
            )
        )
        or not isinstance(result["authority_database"], str)
        or str(_absolute(str(result["authority_database"]), "authority database"))
        != result["authority_database"]
        or result["authority_uid"] != 0
        or not isinstance(result["authority_generation"], str)
        or not result["authority_generation"]
        or result["authority_schema_version"] != 12
        or result["authority_migration_state"] != "ready"
        or any(
            not isinstance(identity, Mapping)
            or set(identity) != {"device", "inode", "size"}
            or any(type(identity[field]) is not int for field in identity)
            or int(identity["inode"]) <= 0
            or int(identity["size"]) <= 0
            for identity in identities
        )
        or identities[0]["device"] != identities[1]["device"]
        or identities[0]["inode"] != identities[1]["inode"]
        or result["repository_generation_after"]
        != int(result["repository_generation_before"]) + 1
        or result["installation_generation_after"]
        != int(result["installation_generation_before"]) + 1
        or result["state_revision_after"] != int(result["state_revision_before"]) + 1
        or _validate_authority_repository_protected_rows(result["protected_rows"])
        != result["protected_rows"]
        or _validate_authority_repository_owner_snapshot(
            result["owner_authority_before"]
        )
        != result["owner_authority_before"]
        or _validate_authority_repository_owner_snapshot(
            result["owner_authority_after"]
        )
        != result["owner_authority_after"]
        or result["repository_state"] != "active"
        or result["installation_status"] != "installed"
        or result["startup_fenced"] is not False
        or result["enrollment_count"] != 0
        or result["actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or not isinstance(result["reason"], str)
        or not result["reason"]
        or not isinstance(result["applied_at"], str)
        or not result["applied_at"]
    ):
        raise CutoverError("lifecycle recovery result is invalid")
    return result


def apply_authority_repository_lifecycle_recovery(
    *,
    plan_path: Path,
    plan_document_sha256: str,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
    maintenance_state_reader=None,
    maintenance_lock_factory=None,
    broker_lock_factory=None,
    before_commit_hook=None,
    after_commit_hook=None,
    effective_uid_reader=os.geteuid,
    evidence_reader=None,
    evidence_publisher=None,
) -> dict[str, object]:
    """Atomically re-enable authority while preserving every native row."""

    if effective_uid_reader() != authority_uid or authority_uid != 0:
        raise CutoverError("lifecycle recovery apply requires root authority")
    reader = read_private_json if evidence_reader is None else evidence_reader
    publisher = _publish_evidence if evidence_publisher is None else evidence_publisher
    plan = _validate_authority_repository_lifecycle_recovery_plan(
        reader(_absolute(plan_path, "lifecycle recovery plan"), uid=0)
    )
    if plan["document_sha256"] != plan_document_sha256:
        raise CutoverError("lifecycle recovery plan digest changed")
    try:
        deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("lifecycle recovery maintenance ID is invalid") from error
    if deployment_id != maintenance_deployment_id:
        raise CutoverError("lifecycle recovery maintenance ID is invalid")
    maintenance_reader = maintenance_state_reader or load_maintenance_state
    maintenance_locker = maintenance_lock_factory or maintenance_writer_lock
    maintenance_root = _absolute(maintenance_root, "maintenance root")

    def require_maintenance() -> object:
        try:
            current = maintenance_reader(
                expected_uid=0,
                expected_gid=maintenance_gid,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "lifecycle recovery maintenance marker is invalid"
            ) from error
        if (
            current is None
            or current.deployment_id != deployment_id
            or current.message != PUBLIC_MAINTENANCE_MESSAGE
        ):
            raise CutoverError(
                "lifecycle recovery requires the exact maintenance fence"
            )
        return current

    require_maintenance()
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    lock_factory = broker_lock_factory or exclusive_broker_service_lock
    database = _absolute(str(plan["authority_database"]), "authority database")
    mutated = False
    with lock_factory(database), maintenance_locker(
        maintenance_root=maintenance_root,
        expected_uid=0,
        expected_gid=maintenance_gid,
    ):
        require_maintenance()
        identity_before = identity_reader(database, uid=0)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            _authority_repair_schema(connection)
            schema_row = connection.execute(
                """
                SELECT schema_version, migration_state
                FROM schema_metadata WHERE singleton = 1
                """
            ).fetchone()
            metadata, snapshot, _policies = _authority_repository_repair_snapshot(
                connection, str(plan["repository"]["repository_id"])
            )
            if (
                schema_row is None
                or int(schema_row[0]) != plan["authority_schema_version"]
                or str(schema_row[1]) != plan["authority_migration_state"]
                or str(schema_row[1]) != "ready"
            ):
                raise CutoverError("lifecycle recovery schema changed")
            protected = _authority_repository_protected_rows(
                connection, str(plan["repository"]["repository_id"])
            )
            owner = _authority_repository_owner_snapshot(
                connection,
                repository_id=str(plan["repository"]["repository_id"]),
                repository_generation=int(snapshot["generation"]),
                schema_version=int(schema_row[0]),
            )
            root_proof = root_reader(snapshot["canonical_root"])
            repository_initial = all(
                snapshot[key] == plan["repository"][key]
                for key in snapshot
            )
            same_database = _authority_repair_same_database(
                planned=plan["database_identity"], current=identity_before
            )
            root_matches = _authority_repository_lifecycle_root_matches(
                plan=plan, proof=root_proof
            )
            initial = bool(
                metadata["authority_generation"] == plan["authority_generation"]
                and metadata["state_revision"] == plan["authority_state_revision"]
                and same_database
                and repository_initial
                and protected == plan["protected_rows"]
                and owner == plan["owner_authority"]
                and root_matches
            )
            recovered = _authority_repository_lifecycle_recovery_terminal(
                plan=plan,
                metadata=metadata,
                snapshot=snapshot,
                protected=protected,
                owner=owner,
            ) and root_matches
            if not initial and not recovered:
                raise CutoverError("lifecycle recovery plan drifted before apply")
            if initial:
                changed_repository = connection.execute(
                    """
                    UPDATE repositories
                    SET state = 'active', generation = generation + 1,
                        updated_at = ?
                    WHERE repo_id = ? AND state = 'missing' AND generation = ?
                      AND updated_at = ?
                    """,
                    (
                        plan["mutation_updated_at"],
                        plan["repository"]["repository_id"],
                        plan["repository"]["generation"],
                        plan["repository"]["repository_updated_at"],
                    ),
                ).rowcount
                changed_installation = connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'installed', startup_fenced = 0,
                        generation = generation + 1, operation_id = NULL,
                        disabled_at = NULL, reason = ?, actor = ?, updated_at = ?
                    WHERE repo_id = ? AND status = 'disabled'
                      AND startup_fenced = 1 AND generation = ?
                      AND operation_id IS NULL AND disabled_at IS ?
                      AND reason = ? AND actor = ? AND updated_at = ?
                    """,
                    (
                        plan["reason"],
                        AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                        plan["mutation_updated_at"],
                        plan["repository"]["repository_id"],
                        plan["repository"]["installation_generation"],
                        plan["repository"]["installation_disabled_at"],
                        plan["repository"]["installation_reason"],
                        plan["repository"]["installation_actor"],
                        plan["repository"]["installation_updated_at"],
                    ),
                ).rowcount
                changed_revision = connection.execute(
                    """
                    UPDATE schema_metadata
                    SET state_revision = state_revision + 1, updated_at = ?
                    WHERE singleton = 1 AND database_generation = ?
                      AND state_revision = ? AND migration_state = 'ready'
                    """,
                    (
                        plan["mutation_updated_at"],
                        plan["authority_generation"],
                        plan["authority_state_revision"],
                    ),
                ).rowcount
                if (changed_repository, changed_installation, changed_revision) != (
                    1,
                    1,
                    1,
                ):
                    raise CutoverError("lifecycle recovery exact mutation was incomplete")
                terminal_metadata, terminal_snapshot, _ = (
                    _authority_repository_repair_snapshot(
                        connection, str(plan["repository"]["repository_id"])
                    )
                )
                terminal_protected = _authority_repository_protected_rows(
                    connection, str(plan["repository"]["repository_id"])
                )
                terminal_owner = _authority_repository_owner_snapshot(
                    connection,
                    repository_id=str(plan["repository"]["repository_id"]),
                    repository_generation=int(terminal_snapshot["generation"]),
                    schema_version=int(schema_row[0]),
                )
                if not _authority_repository_lifecycle_recovery_terminal(
                    plan=plan,
                    metadata=terminal_metadata,
                    snapshot=terminal_snapshot,
                    protected=terminal_protected,
                    owner=terminal_owner,
                ):
                    raise CutoverError("lifecycle recovery precommit state is incomplete")
                if not _authority_repository_lifecycle_root_matches(
                    plan=plan,
                    proof=root_reader(terminal_snapshot["canonical_root"]),
                ):
                    raise CutoverError(
                        "lifecycle recovery root proof changed before commit"
                    )
                if before_commit_hook is not None:
                    before_commit_hook()
                require_maintenance()
                connection.commit()
                mutated = True
                if after_commit_hook is not None:
                    after_commit_hook()
                connection.execute("BEGIN")
                metadata, snapshot, _ = _authority_repository_repair_snapshot(
                    connection, str(plan["repository"]["repository_id"])
                )
                terminal_schema_row = connection.execute(
                    """
                    SELECT schema_version, migration_state
                    FROM schema_metadata WHERE singleton = 1
                    """
                ).fetchone()
                if (
                    terminal_schema_row is None
                    or int(terminal_schema_row[0])
                    != plan["authority_schema_version"]
                    or str(terminal_schema_row[1])
                    != plan["authority_migration_state"]
                    or str(terminal_schema_row[1]) != "ready"
                ):
                    raise CutoverError(
                        "lifecycle recovery migration state changed after commit"
                    )
                protected = _authority_repository_protected_rows(
                    connection, str(plan["repository"]["repository_id"])
                )
                owner = _authority_repository_owner_snapshot(
                    connection,
                    repository_id=str(plan["repository"]["repository_id"]),
                    repository_generation=int(snapshot["generation"]),
                    schema_version=int(schema_row[0]),
                )
                connection.execute("ROLLBACK")
            else:
                connection.execute("ROLLBACK")
        except BaseException:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
        identity_after = identity_reader(database, uid=0)
    if not _authority_repository_lifecycle_recovery_terminal(
        plan=plan,
        metadata=metadata,
        snapshot=snapshot,
        protected=protected,
        owner=owner,
    ):
        raise CutoverError("lifecycle recovery terminal state did not verify")
    if not _authority_repository_lifecycle_root_matches(
        plan=plan, proof=root_reader(snapshot["canonical_root"])
    ):
        raise CutoverError(
            "lifecycle recovery root proof changed before attestation"
        )
    result = _validate_authority_repository_lifecycle_recovery_result(
        seal(
            AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_RESULT_KIND,
            {
                "plan_id": plan["plan_id"],
                "operation_id": plan["operation_id"],
                "plan_document_sha256": plan["document_sha256"],
                "source_repair_plan_sha256": plan[
                    "source_repair_plan_sha256"
                ],
                "source_repair_result_sha256": plan[
                    "source_repair_result_sha256"
                ],
                "authority_database": str(database),
                "authority_uid": 0,
                "authority_generation": plan["authority_generation"],
                "authority_schema_version": plan["authority_schema_version"],
                "authority_migration_state": plan["authority_migration_state"],
                "maintenance_deployment_id": deployment_id,
                "database_identity_before": plan["database_identity"],
                "database_identity_after": dict(identity_after),
                "repository_id": plan["repository"]["repository_id"],
                "repository_generation_before": plan["repository"]["generation"],
                "repository_generation_after": snapshot["generation"],
                "installation_generation_before": plan["repository"][
                    "installation_generation"
                ],
                "installation_generation_after": snapshot[
                    "installation_generation"
                ],
                "state_revision_before": plan["authority_state_revision"],
                "state_revision_after": plan["target"]["state_revision"],
                "protected_rows": protected,
                "owner_authority_before": plan["owner_authority"],
                "owner_authority_after": owner,
                "repository_state": snapshot["state"],
                "installation_status": snapshot["installation_status"],
                "startup_fenced": snapshot["installation_startup_fenced"],
                "enrollment_count": snapshot["enrollment_count"],
                "reason": snapshot["installation_reason"],
                "actor": snapshot["installation_actor"],
                "applied_at": snapshot["installation_updated_at"],
            },
        )
    )
    publisher(
        _absolute(attestation, "lifecycle recovery attestation"), result, uid=0
    )
    return {
        "ok": True,
        "attestation": str(attestation),
        "document_sha256": result["document_sha256"],
        "repository_id": result["repository_id"],
        "replayed": not mutated,
    }


def _validate_authority_repository_policy_reconciliation_plan(
    value: object,
) -> dict[str, object]:
    plan = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_PLAN_KIND,
        fields=AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_PLAN_FIELDS,
    )
    try:
        plan_id = str(uuid.UUID(str(plan["plan_id"])))
        source_plan_id = str(uuid.UUID(str(plan["source_repair_plan_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("startup-policy reconciliation plan identity is invalid") from error
    database_identity = plan["database_identity"]
    repository = plan["repository"]
    policies = _validate_authority_startup_policies(plan["startup_policies"])
    if (
        plan_id != plan["plan_id"]
        or source_plan_id != plan["source_repair_plan_id"]
        or re.fullmatch(r"[0-9a-f]{64}", str(plan["source_repair_plan_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(plan["source_repair_result_sha256"]))
        is None
        or not isinstance(plan["authority_database"], str)
        or str(_absolute(str(plan["authority_database"]), "authority database"))
        != plan["authority_database"]
        or type(plan["authority_uid"]) is not int
        or int(plan["authority_uid"]) < 0
        or not isinstance(plan["authority_generation"], str)
        or not plan["authority_generation"]
        or type(plan["authority_state_revision"]) is not int
        or int(plan["authority_state_revision"]) < 0
        or not isinstance(database_identity, Mapping)
        or set(database_identity) != {"device", "inode", "size"}
        or any(type(database_identity[field]) is not int for field in database_identity)
        or int(database_identity["device"]) < 0
        or int(database_identity["inode"]) <= 0
        or int(database_identity["size"]) <= 0
        or not isinstance(repository, Mapping)
        or set(repository)
        != {
            "repository_id",
            "display_name",
            "canonical_root",
            "generation",
            "state",
            "repository_updated_at",
            "installation_status",
            "installation_startup_fenced",
            "installation_generation",
            "installation_operation_id",
            "installation_disabled_at",
            "installation_reason",
            "installation_actor",
            "installation_updated_at",
            "root_identity",
        }
        or not isinstance(repository["repository_id"], str)
        or not repository["repository_id"]
        or repository["canonical_root"] not in SHARED_TEMPORARY_REPOSITORY_ROOTS
        or repository["state"] != "missing"
        or repository["installation_status"] != "disabled"
        or repository["installation_startup_fenced"] is not True
        or repository["installation_operation_id"] is not None
        or type(repository["generation"]) is not int
        or int(repository["generation"]) < 1
        or type(repository["installation_generation"]) is not int
        or int(repository["installation_generation"]) < 1
        or not isinstance(repository["installation_reason"], str)
        or not repository["installation_reason"]
        or repository["installation_actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or repository["installation_disabled_at"]
        != repository["installation_updated_at"]
        or repository["repository_updated_at"]
        != repository["installation_updated_at"]
        or plan["enrollment_count"] != 0
        or plan["shared_temporary_root"] is not True
        or plan["git_metadata_absent"] is not True
        or not isinstance(plan["mutation_updated_at"], str)
        or not plan["mutation_updated_at"]
        or plan["reason"] != AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_REASON
        or not isinstance(plan["created_at"], str)
        or not plan["created_at"]
        or not policies
        or not any(policy["requires_update"] for policy in policies)
    ):
        raise CutoverError("startup-policy reconciliation plan is invalid")
    root_identity = repository["root_identity"]
    if (
        not isinstance(root_identity, Mapping)
        or set(root_identity) != {"device", "inode", "mode", "owner_uid"}
        or root_identity["mode"] != "1777"
        or root_identity["owner_uid"] != 0
        or type(root_identity["device"]) is not int
        or int(root_identity["device"]) < 0
        or type(root_identity["inode"]) is not int
        or int(root_identity["inode"]) <= 0
    ):
        raise CutoverError("startup-policy reconciliation root identity is invalid")
    unsafe = [
        policy["policy_id"]
        for policy in policies
        if policy["requires_update"]
        and policy["policy_kind"] not in {"coordinator", "compose"}
    ]
    if unsafe:
        raise CutoverError(
            "startup-policy reconciliation requires native absence proof or "
            f"lifecycle recovery for policy {unsafe[0]}"
        )
    return plan


def plan_authority_repository_startup_policy_reconciliation(
    *,
    repair_plan: Path,
    repair_plan_document_sha256: str,
    repair_attestation: Path,
    repair_attestation_document_sha256: str,
    plan_path: Path,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
    now_reader=_now,
) -> dict[str, object]:
    """Seal the exact logical-policy correction for a prior terminal repair."""

    if os.geteuid() != authority_uid:
        raise CutoverError("startup-policy reconciliation planning requires authority")
    source_plan = _validate_authority_repository_disable_plan(
        read_private_json(
            _absolute(repair_plan, "authority repair source plan"),
            uid=authority_uid,
        ),
        allow_legacy=True,
    )
    repair = _validate_authority_repository_disable_result(
        read_private_json(
            _absolute(repair_attestation, "authority repair attestation"),
            uid=authority_uid,
        ),
        allow_legacy=True,
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", repair_plan_document_sha256 or "") is None
        or source_plan["document_sha256"] != repair_plan_document_sha256
        or re.fullmatch(
            r"[0-9a-f]{64}", repair_attestation_document_sha256 or ""
        )
        is None
        or repair["document_sha256"] != repair_attestation_document_sha256
        or repair["plan_id"] != source_plan["plan_id"]
        or repair["plan_document_sha256"] != source_plan["document_sha256"]
        or repair["authority_database"] != source_plan["authority_database"]
        or repair["authority_uid"] != source_plan["authority_uid"]
        or repair["authority_uid"] != authority_uid
        or repair["authority_generation"] != source_plan["authority_generation"]
        or repair["repository_id"]
        != source_plan["repository"]["repository_id"]
        or repair["repository_generation_before"]
        != source_plan["repository"]["generation"]
        or repair["installation_generation_before"]
        != source_plan["repository"]["installation_generation"]
        or repair["state_revision_before"]
        < int(source_plan["authority_state_revision"])
    ):
        raise CutoverError(
            "startup-policy reconciliation source repair lineage changed"
        )
    database = _absolute(str(repair["authority_database"]), "authority database")
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    before_identity = identity_reader(database, uid=authority_uid)
    if not _authority_repair_same_database(
        planned=repair["database_identity_after"], current=before_identity
    ):
        raise CutoverError("startup-policy reconciliation database identity changed")
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        _authority_repair_schema(connection)
        metadata, snapshot, policies = _authority_repository_repair_snapshot(
            connection, str(repair["repository_id"])
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    after_identity = identity_reader(database, uid=authority_uid)
    if before_identity != after_identity:
        raise CutoverError("authority database changed during reconciliation planning")
    if (
        metadata["authority_generation"] != repair["authority_generation"]
        or metadata["state_revision"] < repair["state_revision_after"]
        or not _authority_repository_matches_repair_result(
            repair=repair, snapshot=snapshot
        )
    ):
        raise CutoverError("startup-policy reconciliation repair state changed")
    root_proof = root_reader(snapshot["canonical_root"])
    if (
        not isinstance(root_proof, Mapping)
        or set(root_proof)
        != {"device", "inode", "mode", "owner_uid", "git_metadata_absent"}
        or root_proof["mode"] != "1777"
        or root_proof["owner_uid"] != 0
        or root_proof["git_metadata_absent"] is not True
    ):
        raise CutoverError("startup-policy reconciliation root proof is invalid")
    unsafe = [
        policy["policy_id"]
        for policy in policies
        if policy["requires_update"]
        and policy["policy_kind"] not in {"coordinator", "compose"}
    ]
    if unsafe:
        raise CutoverError(
            "startup-policy reconciliation cannot mutate native policy; use the "
            f"sealed lifecycle recovery path for {unsafe[0]}"
        )
    if not any(policy["requires_update"] for policy in policies):
        raise CutoverError("startup-policy reconciliation is not required")
    timestamp = now_reader()
    document = _validate_authority_repository_policy_reconciliation_plan(
        seal(
            AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_PLAN_KIND,
            {
                "plan_id": str(uuid.uuid4()),
                "source_repair_plan_sha256": source_plan["document_sha256"],
                "source_repair_result_sha256": repair["document_sha256"],
                "source_repair_plan_id": repair["plan_id"],
                "authority_database": str(database),
                "authority_uid": authority_uid,
                "authority_generation": metadata["authority_generation"],
                "authority_state_revision": metadata["state_revision"],
                "database_identity": dict(before_identity),
                "repository": {
                    key: snapshot[key]
                    for key in (
                        "repository_id",
                        "display_name",
                        "canonical_root",
                        "generation",
                        "state",
                        "repository_updated_at",
                        "installation_status",
                        "installation_startup_fenced",
                        "installation_generation",
                        "installation_operation_id",
                        "installation_disabled_at",
                        "installation_reason",
                        "installation_actor",
                        "installation_updated_at",
                    )
                }
                | {
                    "root_identity": {
                        key: root_proof[key]
                        for key in ("device", "inode", "mode", "owner_uid")
                    }
                },
                "startup_policies": policies,
                "enrollment_count": 0,
                "shared_temporary_root": True,
                "git_metadata_absent": True,
                "mutation_updated_at": timestamp,
                "reason": AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_REASON,
                "created_at": timestamp,
            },
        )
    )
    _publish_evidence(
        _absolute(plan_path, "startup-policy reconciliation plan"),
        document,
        uid=authority_uid,
    )
    return {
        "ok": True,
        "plan": str(plan_path),
        "plan_id": document["plan_id"],
        "document_sha256": document["document_sha256"],
        "repository_id": repair["repository_id"],
        "startup_policy_count": len(policies),
        "startup_policy_update_count": sum(
            int(bool(policy["requires_update"])) for policy in policies
        ),
        "writes_performed": False,
    }


def _validate_authority_repository_policy_reconciliation_result(
    value: object,
) -> dict[str, object]:
    result = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_RESULT_KIND,
        fields=AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_RESULT_FIELDS,
    )
    try:
        plan_id = str(uuid.UUID(str(result["plan_id"])))
        source_plan_id = str(uuid.UUID(str(result["source_repair_plan_id"])))
        deployment_id = str(uuid.UUID(str(result["maintenance_deployment_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("startup-policy reconciliation result identity is invalid") from error
    policies = _validate_authority_startup_policy_results(
        result["startup_policies"]
    )
    identities = (
        result["database_identity_before"],
        result["database_identity_after"],
    )
    if (
        plan_id != result["plan_id"]
        or source_plan_id != result["source_repair_plan_id"]
        or deployment_id != result["maintenance_deployment_id"]
        or re.fullmatch(r"[0-9a-f]{64}", str(result["plan_document_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(result["source_repair_result_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(result["source_repair_plan_sha256"]))
        is None
        or not isinstance(result["authority_database"], str)
        or str(_absolute(str(result["authority_database"]), "authority database"))
        != result["authority_database"]
        or type(result["authority_uid"]) is not int
        or int(result["authority_uid"]) < 0
        or not isinstance(result["authority_generation"], str)
        or not result["authority_generation"]
        or any(
            not isinstance(identity, Mapping)
            or set(identity) != {"device", "inode", "size"}
            or any(type(identity[field]) is not int for field in identity)
            for identity in identities
        )
        or identities[0]["device"] != identities[1]["device"]
        or identities[0]["inode"] != identities[1]["inode"]
        or type(result["repository_generation"]) is not int
        or type(result["installation_generation"]) is not int
        or type(result["state_revision_before"]) is not int
        or result["state_revision_after"] != int(result["state_revision_before"]) + 1
        or type(result["startup_policy_count"]) is not int
        or result["startup_policy_count"] != len(policies)
        or type(result["startup_policy_update_count"]) is not int
        or result["startup_policy_update_count"]
        != sum(int(bool(policy["requires_update"])) for policy in policies)
        or result["enrollment_count"] != 0
        or result["reason"] != AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_REASON
        or result["actor"] != AUTHORITY_REPOSITORY_REPAIR_ACTOR
        or not isinstance(result["applied_at"], str)
        or not result["applied_at"]
        or any(
            policy["requires_update"]
            and policy["updated_at_after"] != result["applied_at"]
            for policy in policies
        )
    ):
        raise CutoverError("startup-policy reconciliation result is invalid")
    return result


def apply_authority_repository_startup_policy_reconciliation(
    *,
    plan_path: Path,
    plan_document_sha256: str,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    authority_uid: int = 0,
    database_identity_reader=None,
    repository_root_proof_reader=None,
    maintenance_state_reader=None,
    maintenance_lock_factory=None,
    broker_lock_factory=None,
    before_commit_hook=None,
    after_commit_hook=None,
) -> dict[str, object]:
    """Apply the sealed logical-only policy correction in one revision."""

    if os.geteuid() != authority_uid:
        raise CutoverError("startup-policy reconciliation apply requires authority")
    plan = _validate_authority_repository_policy_reconciliation_plan(
        read_private_json(
            _absolute(plan_path, "startup-policy reconciliation plan"),
            uid=authority_uid,
        )
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan["document_sha256"] != plan_document_sha256
    ):
        raise CutoverError("startup-policy reconciliation plan digest changed")
    try:
        deployment_id = str(uuid.UUID(maintenance_deployment_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("startup-policy reconciliation maintenance ID is invalid") from error
    if deployment_id != maintenance_deployment_id:
        raise CutoverError("startup-policy reconciliation maintenance ID is invalid")
    maintenance_reader = maintenance_state_reader or load_maintenance_state
    maintenance_locker = maintenance_lock_factory or maintenance_writer_lock
    maintenance_root = _absolute(maintenance_root, "maintenance root")

    def require_maintenance() -> object:
        try:
            current = maintenance_reader(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                maintenance_root=maintenance_root,
            )
        except MaintenanceMarkerError as error:
            raise CutoverError(
                "startup-policy reconciliation maintenance is invalid"
            ) from error
        if (
            current is None
            or current.deployment_id != deployment_id
            or current.message != PUBLIC_MAINTENANCE_MESSAGE
        ):
            raise CutoverError(
                "startup-policy reconciliation requires exact active maintenance"
            )
        return current

    require_maintenance()
    identity_reader = database_identity_reader or _database_identity
    root_reader = repository_root_proof_reader or (
        lambda root: _authoritative_repository_root_proof(
            root, prove_git_metadata_absent=True
        )
    )
    database = _absolute(str(plan["authority_database"]), "authority database")
    if authority_uid != plan["authority_uid"]:
        raise CutoverError("startup-policy reconciliation owner changed")
    lock_factory = broker_lock_factory or exclusive_broker_service_lock
    mutated = False
    with lock_factory(database), maintenance_locker(
        maintenance_root=maintenance_root,
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
    ):
        require_maintenance()
        identity_before = identity_reader(database, uid=authority_uid)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            _authority_repair_schema(connection)
            metadata, snapshot, policies = _authority_repository_repair_snapshot(
                connection, str(plan["repository"]["repository_id"])
            )
            root_proof = root_reader(snapshot["canonical_root"])
            if (
                not isinstance(root_proof, Mapping)
                or root_proof.get("git_metadata_absent") is not True
                or {
                    key: root_proof[key]
                    for key in ("device", "inode", "mode", "owner_uid")
                }
                != plan["repository"]["root_identity"]
            ):
                raise CutoverError("startup-policy reconciliation root proof changed")
            repository_matches = all(
                snapshot[key] == plan["repository"][key]
                for key in plan["repository"]
                if key != "root_identity"
            ) and snapshot["enrollment_count"] == 0
            same_database = _authority_repair_same_database(
                planned=plan["database_identity"], current=identity_before
            )
            initial = bool(
                metadata["authority_generation"] == plan["authority_generation"]
                and metadata["state_revision"] == plan["authority_state_revision"]
                and same_database
                and repository_matches
                and _authority_startup_policies_match_initial(
                    plan["startup_policies"], policies
                )
            )
            recovered = False
            if (
                metadata["authority_generation"] == plan["authority_generation"]
                and metadata["state_revision"]
                == int(plan["authority_state_revision"]) + 1
                and same_database
                and repository_matches
            ):
                try:
                    _authority_startup_policy_results(
                        planned=plan["startup_policies"],
                        current=policies,
                        applied_at=str(plan["mutation_updated_at"]),
                    )
                except CutoverError:
                    pass
                else:
                    recovered = True
            if not initial and not recovered:
                raise CutoverError("startup-policy reconciliation plan drifted")
            if initial:
                changed = 0
                for policy in _validate_authority_startup_policies(
                    plan["startup_policies"]
                ):
                    if not policy["requires_update"]:
                        continue
                    changed += connection.execute(
                        """
                        UPDATE startup_policies
                        SET current_value = desired_disabled_value,
                            generation = generation + 1, updated_at = ?
                        WHERE policy_id = ? AND repo_id = ?
                          AND resource_kind = ? AND resource_id = ?
                          AND policy_kind = ? AND current_value = ?
                          AND desired_disabled_value = ?
                          AND immutable_fingerprint = ? AND generation = ?
                          AND updated_at = ?
                        """,
                        (
                            plan["mutation_updated_at"],
                            policy["policy_id"],
                            plan["repository"]["repository_id"],
                            policy["resource_kind"],
                            policy["resource_id"],
                            policy["policy_kind"],
                            policy["current_value"],
                            policy["desired_disabled_value"],
                            policy["immutable_fingerprint"],
                            policy["generation"],
                            policy["updated_at"],
                        ),
                    ).rowcount
                expected_updates = sum(
                    int(bool(policy["requires_update"]))
                    for policy in plan["startup_policies"]
                )
                changed_revision = connection.execute(
                    """
                    UPDATE schema_metadata
                    SET state_revision = state_revision + 1, updated_at = ?
                    WHERE singleton = 1 AND database_generation = ?
                      AND state_revision = ?
                    """,
                    (
                        plan["mutation_updated_at"],
                        plan["authority_generation"],
                        plan["authority_state_revision"],
                    ),
                ).rowcount
                if changed != expected_updates or changed_revision != 1:
                    raise CutoverError(
                        "startup-policy reconciliation exact mutation was incomplete"
                    )
                terminal_metadata, terminal_snapshot, terminal_policies = (
                    _authority_repository_repair_snapshot(
                        connection,
                        str(plan["repository"]["repository_id"]),
                    )
                )
                if (
                    terminal_metadata["state_revision"]
                    != int(plan["authority_state_revision"]) + 1
                    or terminal_snapshot["state"] != "missing"
                    or terminal_snapshot["installation_status"] != "disabled"
                    or terminal_snapshot["installation_startup_fenced"] is not True
                    or not _authority_startup_policies_match_terminal(
                        plan["startup_policies"],
                        terminal_policies,
                        applied_at=plan["mutation_updated_at"],
                    )
                ):
                    raise CutoverError(
                        "startup-policy reconciliation precommit state is incomplete"
                    )
                if before_commit_hook is not None:
                    before_commit_hook()
                require_maintenance()
                connection.commit()
                mutated = True
                if after_commit_hook is not None:
                    after_commit_hook()
                connection.execute("BEGIN")
                metadata, snapshot, policies = _authority_repository_repair_snapshot(
                    connection, str(plan["repository"]["repository_id"])
                )
                connection.execute("ROLLBACK")
            else:
                connection.execute("ROLLBACK")
        except BaseException:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
        identity_after = identity_reader(database, uid=authority_uid)
    policy_results = _authority_startup_policy_results(
        planned=plan["startup_policies"],
        current=policies,
        applied_at=str(plan["mutation_updated_at"]),
    )
    if (
        metadata["authority_generation"] != plan["authority_generation"]
        or metadata["state_revision"]
        != int(plan["authority_state_revision"]) + 1
        or not _authority_repair_same_database(
            planned=plan["database_identity"], current=identity_after
        )
        or snapshot["state"] != "missing"
        or snapshot["installation_status"] != "disabled"
        or snapshot["installation_startup_fenced"] is not True
        or snapshot["enrollment_count"] != 0
    ):
        raise CutoverError("startup-policy reconciliation terminal state failed")
    result = _validate_authority_repository_policy_reconciliation_result(
        seal(
            AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_RESULT_KIND,
            {
                "plan_id": plan["plan_id"],
                "plan_document_sha256": plan["document_sha256"],
                "source_repair_plan_sha256": plan[
                    "source_repair_plan_sha256"
                ],
                "source_repair_result_sha256": plan[
                    "source_repair_result_sha256"
                ],
                "source_repair_plan_id": plan["source_repair_plan_id"],
                "authority_database": str(database),
                "authority_uid": authority_uid,
                "authority_generation": plan["authority_generation"],
                "maintenance_deployment_id": deployment_id,
                "database_identity_before": dict(identity_before),
                "database_identity_after": dict(identity_after),
                "repository_id": plan["repository"]["repository_id"],
                "repository_generation": plan["repository"]["generation"],
                "installation_generation": plan["repository"][
                    "installation_generation"
                ],
                "state_revision_before": plan["authority_state_revision"],
                "state_revision_after": int(plan["authority_state_revision"]) + 1,
                "startup_policy_count": len(policy_results),
                "startup_policy_update_count": sum(
                    int(bool(policy["requires_update"]))
                    for policy in policy_results
                ),
                "startup_policies": policy_results,
                "enrollment_count": 0,
                "reason": AUTHORITY_REPOSITORY_POLICY_RECONCILIATION_REASON,
                "actor": AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                "applied_at": plan["mutation_updated_at"],
            },
        )
    )
    _publish_evidence(
        _absolute(attestation, "startup-policy reconciliation attestation"),
        result,
        uid=authority_uid,
    )
    return {
        "ok": True,
        "attestation": str(attestation),
        "document_sha256": result["document_sha256"],
        "repository_id": result["repository_id"],
        "replayed": not mutated,
    }


def export_authority_test_repositories(
    database: Path,
    *,
    authority_uid: int,
    now_epoch: int | None = None,
) -> dict[str, object]:
    """Export exact v13 execution owners without path or caller inference."""

    database = _absolute(database, "authority database")
    _database_identity(database, uid=authority_uid)
    current_epoch = int(time.time()) if now_epoch is None else int(now_epoch)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        generation = connection.execute(
            """
            SELECT schema_version, database_generation, migration_state
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        rows = connection.execute(
            """
            SELECT r.repo_id, r.canonical_root, r.generation,
                   owner.owner_uid, owner.repository_generation,
                   owner.evidence_sha256,
                   transfer.owner_uid AS ledger_owner_uid,
                   transfer.repository_generation AS ledger_repository_generation,
                   transfer.evidence_sha256 AS ledger_evidence_sha256,
                   enrollment.enabled AS enrollment_enabled,
                   enrollment.valid_until_epoch,
                   principal.enabled AS principal_enabled
            FROM repositories r
            JOIN repository_installations i ON i.repo_id = r.repo_id
            JOIN repository_owners owner ON owner.repo_id = r.repo_id
            JOIN repository_owner_transfers transfer
              ON transfer.repo_id = owner.repo_id
             AND transfer.authority_generation = owner.authority_generation
            LEFT JOIN broker_repository_enrollments enrollment
              ON enrollment.repo_id = r.repo_id
             AND enrollment.uid = owner.owner_uid
            LEFT JOIN broker_acl_principals principal
              ON principal.uid = enrollment.uid
             AND principal.account_id = enrollment.account_id
            WHERE r.state = 'active'
              AND i.status = 'installed'
              AND i.startup_fenced = 0
              AND owner.repository_generation = r.generation
            ORDER BY r.repo_id
            """,
        ).fetchall()
        if (
            generation is None
            or int(generation["schema_version"]) != 13
            or str(generation["migration_state"]) != "ready"
            or not isinstance(generation["database_generation"], str)
            or not generation["database_generation"]
        ):
            raise CutoverError("authority database generation is unavailable")
        repositories: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in rows:
            repository_id = str(row["repo_id"])
            repository_generation = int(row["generation"])
            owner_uid = int(row["owner_uid"])
            if (
                not repository_id
                or len(repository_id.encode("utf-8")) > 256
                or repository_generation < 0
                or owner_uid <= 0
                or repository_id in seen
                or int(row["repository_generation"]) != repository_generation
                or int(row["ledger_owner_uid"]) != owner_uid
                or int(row["ledger_repository_generation"])
                != repository_generation
                or str(row["ledger_evidence_sha256"])
                != str(row["evidence_sha256"])
                or row["enrollment_enabled"] is None
                or not bool(row["enrollment_enabled"])
                or row["principal_enabled"] is None
                or not bool(row["principal_enabled"])
                or int(row["valid_until_epoch"] or 0) <= current_epoch
            ):
                raise CutoverError("authority repository identity is invalid or ambiguous")
            seen.add(repository_id)
            repositories.append(
                {
                    "repository_id": repository_id,
                    "owner_uid": owner_uid,
                    "repository_generation": repository_generation,
                }
            )
    finally:
        connection.close()
    if not repositories:
        raise CutoverError("authority export contains no active repository enrollments")
    return seal(
        AUTHORITY_REPOSITORY_EXPORT_KIND,
        {
            "authority_generation": str(generation["database_generation"]),
            "repositories": repositories,
            "exported_at": _now(),
        },
    )


def publish_authority_repository_export(
    *,
    authority_database: Path,
    attestation: Path,
    authority_uid: int,
    now_epoch: int | None = None,
) -> dict[str, object]:
    """Publish the exact sealed authority enrollment catalog for adopters.

    The export contains immutable repository IDs, owner UIDs, repository
    generations, and the authority generation only.  It is intentionally
    root-private and no-clobber so fleet adoption cannot infer ownership from
    checkout paths or names and cannot silently consume a newer generation.
    """

    document = export_authority_test_repositories(
        authority_database,
        authority_uid=authority_uid,
        now_epoch=now_epoch,
    )
    verified = verify_seal(
        document,
        kind=AUTHORITY_REPOSITORY_EXPORT_KIND,
        fields=AUTHORITY_REPOSITORY_EXPORT_FIELDS,
    )
    _publish_evidence(attestation, verified, uid=authority_uid)
    return {
        "ok": True,
        "attestation": str(attestation),
        "authority_generation": verified["authority_generation"],
        "repository_count": len(verified["repositories"]),
        "document_sha256": verified["document_sha256"],
    }


def build_test_capability_policy(
    authority_export: Mapping[str, object],
    *,
    setup_reader,
    dogfood_repository_id: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Build least-privilege grants from UID-parsed setup projections."""

    exported = verify_seal(
        authority_export,
        kind=AUTHORITY_REPOSITORY_EXPORT_KIND,
        fields=AUTHORITY_REPOSITORY_EXPORT_FIELDS,
    )
    rows = exported["repositories"]
    if not isinstance(rows, list) or not rows or len(rows) > 10_000:
        raise CutoverError("authority repository export is invalid")
    if not isinstance(dogfood_repository_id, str) or not dogfood_repository_id:
        raise CutoverError("dogfood repository ID is required")
    policy_rows: list[dict[str, object]] = []
    grants: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in rows:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {"repository_id", "owner_uid", "repository_generation"}
            or not isinstance(item["repository_id"], str)
            or not item["repository_id"]
            or type(item["owner_uid"]) is not int
            or int(item["owner_uid"]) <= 0
            or type(item["repository_generation"]) is not int
            or int(item["repository_generation"]) < 0
            or item["repository_id"] in seen
        ):
            raise CutoverError("authority repository export entry is invalid")
        repository_id = str(item["repository_id"])
        seen.add(repository_id)
        raw_setup = setup_reader(repository_id, int(item["owner_uid"]))
        if not isinstance(raw_setup, Mapping):
            raise CutoverError("repository UID setup parser returned invalid evidence")
        setup = decode_repository_setup_document(
            raw_setup,
            expected_repository_id=repository_id,
        )
        requested = sorted(
            {
                *(f"network.{network}" for network in setup["network_requirements"] if network != "none"),
                *(f"fixture.{fixture}" for fixture in setup["fixtures"]),
                *(f"credential.{credential}" for credential in setup["credentials"]),
            }
        )
        generation = int(item["repository_generation"])
        policy_rows.append(
            {
                "repository_id": repository_id,
                "generation": generation,
                "capabilities": requested,
            }
        )
        grants.append(
            {
                "repository_id": repository_id,
                "generation": generation,
                "setup_status": setup["status"],
                "manifest_fingerprint": setup["manifest_fingerprint"],
                "requested": requested,
                "granted": requested,
            }
        )
    dogfood = next(
        (item for item in grants if item["repository_id"] == dogfood_repository_id),
        None,
    )
    if (
        dogfood is None
        or dogfood["setup_status"] != "ready"
        or "network.loopback" not in dogfood["requested"]
    ):
        raise CutoverError(
            "DevCoordinator dogfood repository is not ready with explicit loopback testing"
        )
    policy_rows.sort(key=lambda item: str(item["repository_id"]))
    grants.sort(key=lambda item: str(item["repository_id"]))
    return {"schema_version": 1, "repositories": policy_rows}, grants


def _publish_test_capability_document(
    destination: Path,
    document: Mapping[str, object],
    *,
    owner_uid: int,
    owner_gid: int,
) -> tuple[bytes, bool]:
    destination = _absolute(destination, "test capability policy")
    parent = destination.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or destination.parent.resolve(strict=True) != destination.parent
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
        or os.geteuid() != owner_uid
    ):
        raise CutoverError("test capability policy parent is unsafe")
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise CutoverError("test capability policy exceeds its byte bound")
    existed = destination.exists() or destination.is_symlink()
    if existed:
        info = destination.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise CutoverError("existing test capability policy is unsafe")
        if destination.read_bytes() == payload:
            return payload, False
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, destination)
        parent_descriptor = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return payload, True


def publish_test_capability_policy(
    *,
    authority_database: Path,
    snapshot_socket: Path,
    destination: Path,
    dogfood_repository_id: str,
    authority_uid: int,
    owner_gid: int,
    expected_snapshot_uid: int = 0,
    now_epoch: int | None = None,
    setup_reader=None,
) -> dict[str, object]:
    authority_export = export_authority_test_repositories(
        authority_database,
        authority_uid=authority_uid,
        now_epoch=now_epoch,
    )
    if setup_reader is None:
        client = UnixSnapshotServiceClient(
            _absolute(snapshot_socket, "snapshot service socket"),
            expected_server_uid=expected_snapshot_uid,
        )
        setup_reader = lambda repository_id, owner_uid: client.setup_as_owner(
            repository_id=repository_id,
            owner_uid=owner_uid,
        )
    try:
        policy, grants = build_test_capability_policy(
            authority_export,
            setup_reader=setup_reader,
            dogfood_repository_id=dogfood_repository_id,
        )
    except (TestStoreConflict, TestStoreContractError) as error:
        raise CutoverError(
            "repository capability policy cannot be derived from setup evidence"
        ) from error
    payload, created = _publish_test_capability_document(
        destination,
        policy,
        owner_uid=authority_uid,
        owner_gid=owner_gid,
    )
    registry = SealedTestCapabilityRegistry.load(
        _absolute(destination, "test capability policy"),
        expected_uid=authority_uid,
        allow_missing=False,
    )
    for grant in grants:
        networks = tuple(
            capability.split(".", 1)[1]
            for capability in grant["requested"]
            if str(capability).startswith("network.")
        )
        fixtures = tuple(
            capability.split(".", 1)[1]
            for capability in grant["requested"]
            if str(capability).startswith("fixture.")
        )
        credentials = tuple(
            capability.split(".", 1)[1]
            for capability in grant["requested"]
            if str(capability).startswith("credential.")
        )
        checked = registry.check_requests(
            repository_id=str(grant["repository_id"]),
            repository_generation=int(grant["generation"]),
            networks=networks,
            fixtures=fixtures,
            credentials=credentials,
        )
        if checked["ok"] is not True:
            raise CutoverError("published test capability policy failed broker validation")
    attestation = seal(
        CAPABILITY_POLICY_KIND,
        {
            "policy_path": str(_absolute(destination, "test capability policy")),
            "policy_owner_uid": authority_uid,
            "policy_mode": "0600",
            "policy_file_sha256": hashlib.sha256(payload).hexdigest(),
            "policy_fingerprint": registry.policy_fingerprint,
            "authority_generation": authority_export["authority_generation"],
            "authority_export_sha256": authority_export["document_sha256"],
            "dogfood_repository_id": dogfood_repository_id,
            "repository_grants": grants,
            "coverage_complete": True,
            "broker_contract_verified": True,
            "created_at": _now(),
        },
    )
    return {"ok": True, "created": created, "attestation": attestation}


def _publish_reconstructed_profile(
    destination: Path,
    document: Mapping[str, object],
    *,
    owner_uid: int,
    access_gid: int,
) -> tuple[bytes, bool]:
    """Replace even an incorrectly owned regular profile without trusting it."""

    destination = _absolute(destination, "protected API profile")
    parent = destination.parent.lstat()
    if (
        os.geteuid() != owner_uid
        or stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or destination.parent.resolve(strict=True) != destination.parent
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
        or access_gid <= 0
    ):
        raise CutoverError("protected API profile parent or publisher is unsafe")
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise CutoverError("reconstructed API profile exceeds its byte bound")
    changed = True
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CutoverError("existing API profile is not a replaceable regular file")
        if (
            info.st_uid == owner_uid
            and info.st_gid == access_gid
            and stat.S_IMODE(info.st_mode) == 0o640
            and info.st_size <= MAX_DOCUMENT_BYTES
            and destination.read_bytes() == payload
        ):
            changed = False
    if changed:
        temporary = destination.with_name(
            f".{destination.name}.{uuid.uuid4().hex}.partial"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o640,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.fchown(descriptor, owner_uid, access_gid)
            os.fchmod(descriptor, 0o640)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, destination)
            parent_descriptor = os.open(
                destination.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        finally:
            temporary.unlink(missing_ok=True)
    after = destination.lstat()
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or after.st_uid != owner_uid
        or after.st_gid != access_gid
        or stat.S_IMODE(after.st_mode) != 0o640
        or destination.read_bytes() != payload
    ):
        raise CutoverError("reconstructed API profile publication did not verify")
    return payload, changed


def reconstruct_api_profile_from_authority(
    *,
    authority_database: Path,
    destination: Path,
    api_uid: int,
    access_gid: int,
    authority_uid: int = 0,
    account_id: str = API_BROKER_ACCOUNT,
    source_authority_generation: str | None = None,
    target_authority_generation: str | None = None,
    now_epoch: int | None = None,
) -> dict[str, object]:
    """Rebuild every protected client profile exclusively from v13 authority.

    The pre-v13 file is deliberately neither parsed nor merged.  It may have
    any historical repository shape and is treated only as a replaceable
    regular-file destination.  This is the cutover bridge that makes the
    owner-authority migration and the stricter client parser one transaction.
    """

    if api_uid <= 0 or authority_uid != os.geteuid() or account_id != API_BROKER_ACCOUNT:
        raise CutoverError("API profile reconstruction identity is invalid")
    database = _absolute(authority_database, "authority database")
    before = _database_identity(database, uid=authority_uid)
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        metadata = connection.execute(
            """
            SELECT schema_version, database_generation, migration_state
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        rows = connection.execute(
            """
            SELECT enrollment.uid, enrollment.account_id,
                   enrollment.repo_id, enrollment.issued_at,
                   enrollment.valid_until_epoch, repository.canonical_root,
                   repository.generation, owner.owner_uid,
                   owner.repository_generation
            FROM broker_repository_enrollments enrollment
            JOIN broker_acl_principals principal
              ON principal.uid = enrollment.uid
             AND principal.account_id = enrollment.account_id
            JOIN repositories repository USING(repo_id)
            JOIN repository_installations installation USING(repo_id)
            LEFT JOIN repository_owners owner USING(repo_id)
            WHERE principal.enabled = 1
              AND enrollment.enabled = 1
              AND enrollment.valid_until_epoch > ?
              AND repository.state = 'active'
              AND installation.status = 'installed'
              AND installation.startup_fenced = 0
            ORDER BY enrollment.uid, repository.canonical_root,
                     enrollment.repo_id
            """,
            (now,),
        ).fetchall()
        if (
            metadata is None
            or int(metadata[0]) != 13
            or not isinstance(metadata[1], str)
            or not metadata[1]
            or str(metadata[2]) != "ready"
            or not rows
            or len(rows) > 10_000
        ):
            raise CutoverError(
                "v13 authority has no exact active protected-profile enrollment"
            )

        clients: dict[str, dict[str, object]] = {}
        repository_bindings: list[dict[str, object]] = []

        def add_mapping(
            mapping: dict[str, str], key: object, value: object, *, label: str
        ) -> None:
            name = str(key)
            resource_id = str(value)
            previous = mapping.get(name)
            if not name or not resource_id or (
                previous is not None and previous != resource_id
            ):
                raise CutoverError(
                    f"authority-derived {label} profile mapping is ambiguous"
                )
            mapping[name] = resource_id

        for row in rows:
            client_uid = int(row["uid"])
            client_account = str(row["account_id"])
            repository_id = str(row["repo_id"])
            canonical_root = str(row["canonical_root"])
            issued_at = str(row["issued_at"])
            valid_until = int(row["valid_until_epoch"])
            generation = int(row["generation"])
            owner_value = row["owner_uid"]
            owner_generation = row["repository_generation"]
            if (
                client_uid < 0
                or not client_account
                or not repository_id
                or not Path(canonical_root).is_absolute()
                or not issued_at
                or valid_until <= now
                or generation < 0
                or owner_value is None
                or int(owner_value) <= 0
                or owner_generation is None
                or int(owner_generation) != generation
            ):
                raise CutoverError(
                    "active protected-profile enrollment lacks exact owner authority"
                )
            owner_uid = int(owner_value)
            client = clients.setdefault(
                str(client_uid),
                {
                    "account_id": client_account,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until,
                    "repositories": [],
                },
            )
            if client["account_id"] != client_account:
                raise CutoverError(
                    "one protected client UID has conflicting authority accounts"
                )
            repositories = client["repositories"]
            if not isinstance(repositories, list) or any(
                isinstance(item, Mapping)
                and item.get("repo_id") == repository_id
                for item in repositories
            ):
                raise CutoverError(
                    "protected client authority repeats a repository enrollment"
                )

            servers: dict[str, str] = {}
            for resource in connection.execute(
                """
                SELECT DISTINCT definition.name, acl.resource_id
                FROM broker_resource_acl acl
                JOIN server_definitions definition
                  ON definition.server_definition_id = acl.resource_id
                 AND definition.repo_id = acl.repo_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.resource_kind = 'server' AND acl.enabled = 1
                ORDER BY definition.name, acl.resource_id
                """,
                (client_uid, repository_id),
            ):
                add_mapping(
                    servers, resource["name"], resource["resource_id"], label="server"
                )

            containers: dict[str, str] = {}
            for resource in connection.execute(
                """
                SELECT DISTINCT docker.current_name, docker.full_container_id,
                                acl.resource_id
                FROM broker_resource_acl acl
                JOIN docker_resources docker
                  ON docker.docker_resource_id = acl.resource_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.resource_kind = 'container' AND acl.enabled = 1
                ORDER BY docker.current_name, docker.full_container_id,
                         acl.resource_id
                """,
                (client_uid, repository_id),
            ):
                add_mapping(
                    containers,
                    resource["current_name"],
                    resource["resource_id"],
                    label="container",
                )
                add_mapping(
                    containers,
                    resource["full_container_id"],
                    resource["resource_id"],
                    label="container",
                )

            compose_ids = [
                str(resource[0])
                for resource in connection.execute(
                    """
                    SELECT DISTINCT acl.compose_definition_id
                    FROM broker_compose_acl acl
                    JOIN broker_compose_definitions definition
                      ON definition.compose_definition_id = acl.compose_definition_id
                     AND definition.repo_id = acl.repo_id
                    WHERE acl.uid = ? AND acl.repo_id = ?
                      AND acl.enabled = 1 AND definition.enabled = 1
                    ORDER BY acl.compose_definition_id
                    """,
                    (client_uid, repository_id),
                )
            ]
            if len(compose_ids) > 1:
                raise CutoverError(
                    "protected client has ambiguous enabled Compose grants"
                )

            templates: dict[str, str] = {}
            secret_policies: dict[str, dict[str, str]] = {}
            prefetch: list[str] = []
            template_rows = connection.execute(
                """
                SELECT template.name, template.template_id,
                       template.secret_policy_kind, template.secret_binding_id,
                       MAX(CASE WHEN acl.operation = 'ephemeral.image_prefetch'
                                AND acl.enabled = 1 THEN 1 ELSE 0 END) AS prefetch
                FROM broker_ephemeral_acl acl
                JOIN ephemeral_container_templates template
                  ON template.template_id = acl.template_id
                 AND template.repo_id = acl.repo_id
                WHERE acl.uid = ? AND acl.repo_id = ?
                  AND acl.enabled = 1 AND template.enabled = 1
                GROUP BY template.name, template.template_id,
                         template.secret_policy_kind, template.secret_binding_id
                ORDER BY template.name, template.template_id
                """,
                (client_uid, repository_id),
            ).fetchall()
            for resource in template_rows:
                add_mapping(
                    templates,
                    resource["name"],
                    resource["template_id"],
                    label="ephemeral template",
                )
                if bool(resource["prefetch"]):
                    prefetch.append(str(resource["template_id"]))
                policy = resource["secret_policy_kind"]
                binding = resource["secret_binding_id"]
                if (policy is None) != (binding is None):
                    raise CutoverError(
                        "ephemeral template credential authority is incomplete"
                    )
                if policy is not None:
                    secret_policies[str(resource["name"])] = {
                        "policy": str(policy),
                        "binding_id": str(binding),
                    }

            repositories.append(
                {
                    "canonical_root": canonical_root,
                    "repo_id": repository_id,
                    "generation": generation,
                    "owner_uid": owner_uid,
                    "servers": servers,
                    "containers": containers,
                    "compose_definition_id": compose_ids[0] if compose_ids else None,
                    "account_id": client_account,
                    "enabled": True,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until,
                    "ephemeral_templates": templates,
                    "ephemeral_image_prefetch_templates": sorted(prefetch),
                    "ephemeral_secret_policies": secret_policies,
                }
            )
            client["issued_at"] = min(str(client["issued_at"]), issued_at)
            client["valid_until_epoch"] = max(
                int(client["valid_until_epoch"]), valid_until
            )
            repository_bindings.append(
                {
                    "client_uid": client_uid,
                    "account_id": client_account,
                    "repository_id": repository_id,
                    "generation": generation,
                    "owner_uid": owner_uid,
                    "issued_at": issued_at,
                    "valid_until_epoch": valid_until,
                }
            )
    finally:
        connection.close()
    after = _database_identity(database, uid=authority_uid)
    if before != after:
        raise CutoverError("authority database identity changed during profile export")
    api_client = clients.get(str(api_uid))
    if (
        not isinstance(api_client, Mapping)
        or api_client.get("account_id") != account_id
    ):
        raise CutoverError("authority has no exact active API repository enrollment")
    source_generation = (
        str(source_authority_generation)
        if source_authority_generation is not None
        else ""
    )
    target_generation = (
        str(target_authority_generation)
        if target_authority_generation is not None
        else ""
    )
    if (
        not source_generation
        or not target_generation
        or source_generation == target_generation
        or str(metadata[1]) != target_generation
        or len(source_generation.encode("utf-8")) > 256
        or len(target_generation.encode("utf-8")) > 256
    ):
        raise CutoverError(
            "protected profile reconstruction requires the exact sealed target generation"
        )
    document = {
        "version": 1,
        "service": {
            "socket": AUTHORITY_SOCKET_PATH,
            "uid": authority_uid,
            "gid": access_gid,
            "mode": "0660",
            "database_generation": str(metadata[1]),
        },
        "clients": clients,
    }
    for client_uid in sorted(int(value) for value in clients):
        try:
            parsed = profile_from_document(document, effective_uid=client_uid)
        except BrokerProfileError as error:
            raise CutoverError(
                "authority-derived protected profile failed strict parsing"
            ) from error
        expected = {
            str(item["repository_id"])
            for item in repository_bindings
            if int(item["client_uid"]) == client_uid
        }
        if (
            parsed.account_id != clients[str(client_uid)]["account_id"]
            or parsed.service.database_generation != str(metadata[1])
            or {item.repo_id for item in parsed.repositories.values()} != expected
        ):
            raise CutoverError("authority-derived protected profile is contradictory")
    repository_ids = {
        str(item["repository_id"])
        for item in repository_bindings
        if int(item["client_uid"]) == api_uid
    }
    payload, changed = _publish_reconstructed_profile(
        destination,
        document,
        owner_uid=authority_uid,
        access_gid=access_gid,
    )
    source = {
        "authority_generation": str(metadata[1]),
        "source_authority_generation": source_generation,
        "api_uid": api_uid,
        "account_id": account_id,
        "repository_bindings": repository_bindings,
    }
    attestation = seal(
        PROFILE_REPAIR_KIND,
        {
            "profile_path": str(_absolute(destination, "protected API profile")),
            "profile_owner_uid": authority_uid,
            "profile_group_gid": access_gid,
            "profile_mode": "0640",
            "profile_sha256": hashlib.sha256(payload).hexdigest(),
            "source_authority_generation": source_generation,
            "authority_generation": str(metadata[1]),
            "authority_source_sha256": _digest(source),
            "api_uid": api_uid,
            "broker_account_id": account_id,
            "repository_ids": sorted(repository_ids),
            "client_uids": sorted(int(value) for value in clients),
            "repository_bindings": repository_bindings,
            "parser_verified": True,
            "all_clients_parser_verified": True,
            "existing_profile_contents_reused": False,
            "atomic_publication_verified": True,
            "created_at": _now(),
        },
    )
    return {"ok": True, "changed": changed, "attestation": attestation}


def _post_v13_authority_metadata(
    database: Path, *, authority_uid: int
) -> dict[str, object]:
    """Read the final authority generation without accepting an inode swap."""

    before = _database_identity(database, uid=authority_uid)
    with closing(
        sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5.0)
    ) as connection:
        connection.execute("PRAGMA query_only = ON")
        row = connection.execute(
            "SELECT schema_version, database_generation, migration_state "
            "FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
    after = _database_identity(database, uid=authority_uid)
    if before != after or row is None or len(row) != 3:
        raise CutoverError(
            "post-v13 authority identity changed during readiness verification"
        )
    return {
        "schema_version": int(row[0]),
        "database_generation": str(row[1]),
        "migration_state": str(row[2]),
        "database_identity": before,
    }


def _immutable_inventory_client(release: Path) -> tuple[Path, str]:
    release = _absolute(release, "post-v13 immutable release")
    client = (
        release
        / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    )
    if (
        not client.is_file()
        or client.is_symlink()
        or release.parent != IMMUTABLE_RELEASE_ROOT
        or re.fullmatch(r"[0-9a-f]{64}", release.name) is None
    ):
        raise CutoverError("immutable inventory client is unavailable")
    return client, _file_digest(client)


def _inventory_as_repository_owner(
    *, release: Path, project: str, owner_uid: int
) -> dict[str, object]:
    """Run the immutable inventory client as the repository owner."""

    try:
        account = pwd.getpwuid(owner_uid)
    except KeyError as error:
        raise CutoverError("repository owner account is unavailable") from error
    client, _client_sha256 = _immutable_inventory_client(release)
    command = [
        "/usr/bin/setpriv",
        "--reuid",
        str(owner_uid),
        "--regid",
        str(account.pw_gid),
        "--init-groups",
        "--reset-env",
        "/usr/bin/python3",
        str(client),
        "inventory",
        "--project",
        project,
        "--no-docker",
        "--compact-json",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15.0,
            check=False,
            env={
                "PATH": "/usr/sbin:/usr/bin",
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CutoverError("owner-scoped inventory proof could not run") from error
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > MAX_DOCUMENT_BYTES
        or len(completed.stderr) > 64 * 1024
    ):
        raise CutoverError("owner-scoped inventory proof failed")
    try:
        document = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CutoverError("owner-scoped inventory proof is invalid JSON") from error
    if not isinstance(document, dict):
        raise CutoverError("owner-scoped inventory proof is invalid")
    return document


def _validate_owner_inventory_document(
    inventory: Mapping[str, object],
    *,
    project: str,
    repository_id: str,
    repository_generation: int,
    authority_generation: str,
    authority_uid: int,
) -> None:
    authority = inventory.get("authority")
    repositories = inventory.get("repositories")
    matching = [
        item
        for item in repositories
        if isinstance(item, Mapping)
        and item.get("canonical_root") == project
        and item.get("repo_id") == repository_id
        and item.get("generation") == repository_generation
    ] if isinstance(repositories, list) else []
    if (
        inventory.get("schema_version") != 2
        or not isinstance(authority, Mapping)
        or authority.get("scope") != "server-wide"
        or authority.get("transport") != "authenticated-unix-socket"
        or authority.get("socket") != AUTHORITY_SOCKET_PATH
        or authority.get("service_uid") != authority_uid
        or authority.get("database_generation") != authority_generation
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or len(matching) != 1
    ):
        raise CutoverError(
            "owner-scoped inventory does not prove the exact post-v13 grant"
        )


def verify_post_v13_profile_inventory_readiness(
    *,
    state: Mapping[str, object],
    profile_repair: Mapping[str, object],
    authority_database: Path,
    authority_uid: int = 0,
    inventory_fetcher: Any = None,
    verified_at: str | None = None,
) -> dict[str, object]:
    """Prove the regenerated profile works for one exact owner-scoped read."""

    current = validate_state(state)
    delegation = _recorded(current, "api-delegation")
    if current["phase"] != "sealed" or delegation is None:
        raise CutoverError(
            "post-v13 profile readiness requires the recorded API delegation"
        )
    delegation = verify_seal(
        delegation, kind=DELEGATION_KIND, fields=DELEGATION_FIELDS
    )
    repair = verify_seal(
        profile_repair,
        kind=PROFILE_REPAIR_KIND,
        fields=PROFILE_REPAIR_FIELDS,
    )
    database = _absolute(authority_database, "post-v13 authority database")
    release = _absolute(current["release"], "post-v13 immutable release")
    _inventory_client, inventory_client_sha256 = _immutable_inventory_client(release)
    project_path = str(
        _absolute(current["inventory_canary_project"], "owner inventory project")
    )
    completion = _test_store_cutover_completion(current)
    metadata = _post_v13_authority_metadata(
        database, authority_uid=authority_uid
    )
    if (
        authority_uid != os.geteuid()
        or str(database) != current["authority_database"]
        or int(metadata["schema_version"]) != 13
        or metadata["migration_state"] != "ready"
        or metadata["database_generation"] != repair["authority_generation"]
        or repair["source_authority_generation"]
        != completion["authority_generation"]
        or repair["source_authority_generation"]
        == repair["authority_generation"]
        or delegation["source_authority_generation"]
        != repair["source_authority_generation"]
        or delegation["authority_generation"]
        != repair["authority_generation"]
        or delegation["profile_fingerprint"] != repair["profile_sha256"]
        or repair["profile_path"] != PROTECTED_PROFILE_PATH
        or repair["profile_owner_uid"] != authority_uid
        or repair["profile_mode"] != "0640"
        or repair["parser_verified"] is not True
        or repair["all_clients_parser_verified"] is not True
        or repair["atomic_publication_verified"] is not True
        or repair["existing_profile_contents_reused"] is not False
    ):
        raise CutoverError(
            "post-v13 profile does not match the rotated authority generation"
        )

    profile = _absolute(repair["profile_path"], "post-v13 protected profile")
    info = profile.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != authority_uid
        or info.st_gid != int(repair["profile_group_gid"])
        or stat.S_IMODE(info.st_mode) != 0o640
        or _file_digest(profile) != repair["profile_sha256"]
    ):
        raise CutoverError("installed post-v13 profile changed after regeneration")
    try:
        profile_document = json.loads(profile.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CutoverError("installed post-v13 profile is not strict JSON") from error

    owner_matches: list[tuple[object, Mapping[str, object]]] = []
    bindings = repair["repository_bindings"]
    client_uids = repair["client_uids"]
    if (
        not isinstance(bindings, list)
        or not isinstance(client_uids, list)
        or not client_uids
        or any(type(item) is not int or item < 0 for item in client_uids)
    ):
        raise CutoverError("post-v13 profile authority bindings are invalid")
    for client_uid in client_uids:
        try:
            parsed = profile_from_document(
                profile_document, effective_uid=int(client_uid)
            )
        except BrokerProfileError as error:
            raise CutoverError(
                "installed post-v13 profile failed strict parsing"
            ) from error
        repository = parsed.repositories.get(project_path)
        if repository is None or int(client_uid) != repository.owner_uid:
            continue
        exact = [
            item
            for item in bindings
            if isinstance(item, Mapping)
            and item.get("client_uid") == int(client_uid)
            and item.get("owner_uid") == int(client_uid)
            and item.get("account_id") == parsed.account_id
            and item.get("repository_id") == repository.repo_id
            and item.get("generation") == repository.generation
        ]
        if len(exact) == 1:
            owner_matches.append((parsed, exact[0]))
    if len(owner_matches) != 1:
        raise CutoverError(
            "post-v13 profile lacks one exact owner-bound project grant"
        )
    owner_profile, owner_binding = owner_matches[0]
    owner_uid = int(owner_binding["owner_uid"])
    repository_id = str(owner_binding["repository_id"])
    repository_generation = int(owner_binding["generation"])
    delegated_ids = {
        str(item["repository_id"])
        for item in delegation["repository_grants"]
        if isinstance(item, Mapping)
    }
    if repository_id not in delegated_ids:
        raise CutoverError(
            "owner-bound project grant is absent from API delegation"
        )

    fetch = inventory_fetcher or _inventory_as_repository_owner
    inventory = fetch(
        release=release,
        project=project_path,
        owner_uid=owner_uid,
    )
    if not isinstance(inventory, Mapping):
        raise CutoverError("owner-scoped inventory proof is invalid")
    _validate_owner_inventory_document(
        inventory,
        project=project_path,
        repository_id=repository_id,
        repository_generation=repository_generation,
        authority_generation=str(repair["authority_generation"]),
        authority_uid=authority_uid,
    )
    return seal(
        PROFILE_INVENTORY_READINESS_KIND,
        {
            "profile_repair_sha256": repair["document_sha256"],
            "api_delegation_sha256": delegation["document_sha256"],
            "release_digest": current["release_digest"],
            "executor_release": str(release),
            "inventory_client_sha256": inventory_client_sha256,
            "authority_database": str(database),
            "source_authority_generation": repair[
                "source_authority_generation"
            ],
            "authority_generation": repair["authority_generation"],
            "authority_schema_version": metadata["schema_version"],
            "authority_migration_state": metadata["migration_state"],
            "profile_path": str(profile),
            "profile_sha256": repair["profile_sha256"],
            "profile_owner_uid": authority_uid,
            "profile_group_gid": int(repair["profile_group_gid"]),
            "profile_mode": "0640",
            "full_regeneration": True,
            "strict_profile_parse": True,
            "project": project_path,
            "owner_uid": owner_uid,
            "owner_account_id": owner_profile.account_id,
            "repository_id": repository_id,
            "repository_generation": repository_generation,
            "owner_bound_grant": True,
            "inventory_command": [
                "inventory",
                "--project",
                project_path,
                "--no-docker",
                "--compact-json",
            ],
            "inventory_sha256": _digest(inventory),
            "inventory_schema_version": 2,
            "inventory_scope": "server-wide",
            "inventory_transport": "authenticated-unix-socket",
            "inventory_service_uid": authority_uid,
            "inventory_database_generation": repair[
                "authority_generation"
            ],
            "verified_at": _now() if verified_at is None else verified_at,
        },
    )


def reverify_post_v13_profile_inventory_readiness(
    *,
    state: Mapping[str, object],
    authority_uid: int = 0,
    inventory_fetcher: Any = None,
    verified_at: str | None = None,
) -> dict[str, object]:
    """Re-run the installed owner-scoped profile/inventory proof for retention."""

    current = validate_state(state)
    recorded = _recorded(current, "profile-inventory-readiness")
    delegation = _recorded(current, "api-delegation")
    if current["phase"] not in {"activated", "retained"} or recorded is None:
        raise CutoverError(
            "fresh profile inventory verification requires completed activation"
        )
    if delegation is None:
        raise CutoverError("fresh profile inventory verification lacks delegation")
    readiness = verify_seal(
        recorded,
        kind=PROFILE_INVENTORY_READINESS_KIND,
        fields=PROFILE_INVENTORY_READINESS_FIELDS,
    )
    database = _absolute(current["authority_database"], "post-v13 authority database")
    release = _absolute(current["release"], "post-v13 immutable release")
    _client, inventory_client_sha256 = _immutable_inventory_client(release)
    metadata = _post_v13_authority_metadata(database, authority_uid=authority_uid)
    if (
        authority_uid != os.geteuid()
        or readiness["authority_database"] != str(database)
        or readiness["release_digest"] != current["release_digest"]
        or readiness["executor_release"] != str(release)
        or readiness["inventory_client_sha256"] != inventory_client_sha256
        or readiness["project"] != current["inventory_canary_project"]
        or readiness["api_delegation_sha256"] != delegation["document_sha256"]
        or metadata["schema_version"] != 13
        or metadata["migration_state"] != "ready"
        or metadata["database_generation"] != readiness["authority_generation"]
    ):
        raise CutoverError("fresh profile inventory authority binding changed")

    profile = _absolute(readiness["profile_path"], "post-v13 protected profile")
    info = profile.lstat()
    if (
        str(profile) != PROTECTED_PROFILE_PATH
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != authority_uid
        or info.st_gid != int(readiness["profile_group_gid"])
        or stat.S_IMODE(info.st_mode) != 0o640
        or _file_digest(profile) != readiness["profile_sha256"]
    ):
        raise CutoverError("installed post-v13 profile changed before retention")
    try:
        profile_document = json.loads(profile.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CutoverError("installed post-v13 profile is not strict JSON") from error
    clients = profile_document.get("clients") if isinstance(profile_document, dict) else None
    if not isinstance(clients, Mapping) or not clients:
        raise CutoverError("installed post-v13 profile clients are invalid")
    parsed_owner = None
    for client_uid in clients:
        if not isinstance(client_uid, str) or re.fullmatch(r"[0-9]+", client_uid) is None:
            raise CutoverError("installed post-v13 profile client UID is invalid")
        try:
            parsed = profile_from_document(
                profile_document, effective_uid=int(client_uid)
            )
        except BrokerProfileError as error:
            raise CutoverError(
                "installed post-v13 profile failed strict parsing"
            ) from error
        if int(client_uid) == readiness["owner_uid"]:
            if parsed_owner is not None:
                raise CutoverError("installed profile duplicates repository owner")
            parsed_owner = parsed
    repository = (
        parsed_owner.repositories.get(str(readiness["project"]))
        if parsed_owner is not None
        else None
    )
    if (
        parsed_owner is None
        or parsed_owner.account_id != readiness["owner_account_id"]
        or repository is None
        or repository.owner_uid != readiness["owner_uid"]
        or repository.repo_id != readiness["repository_id"]
        or repository.generation != readiness["repository_generation"]
    ):
        raise CutoverError("installed post-v13 owner grant changed before retention")

    fetch = inventory_fetcher or _inventory_as_repository_owner
    inventory = fetch(
        release=release,
        project=str(readiness["project"]),
        owner_uid=int(readiness["owner_uid"]),
    )
    if not isinstance(inventory, Mapping):
        raise CutoverError("owner-scoped inventory proof is invalid")
    _validate_owner_inventory_document(
        inventory,
        project=str(readiness["project"]),
        repository_id=str(readiness["repository_id"]),
        repository_generation=int(readiness["repository_generation"]),
        authority_generation=str(readiness["authority_generation"]),
        authority_uid=authority_uid,
    )
    unsigned = {
        key: item
        for key, item in readiness.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned["inventory_sha256"] = _digest(inventory)
    unsigned["verified_at"] = _now() if verified_at is None else verified_at
    return seal(PROFILE_INVENTORY_READINESS_KIND, unsigned)


def _validate_first_adoption_port_readiness_binding(
    *,
    readiness: Mapping[str, object],
    reservations: Mapping[str, object],
    release_digest: str,
    authority_database: str,
    inventory_canary_project: str,
) -> None:
    """Bind readiness immediately before or immediately after the port commit."""

    postcondition = readiness.get("postcondition")
    metadata = (
        postcondition.get("metadata")
        if isinstance(postcondition, Mapping)
        else None
    )
    if not isinstance(metadata, Mapping):
        raise CutoverError(
            "first-adoption port reservations changed the readiness binding"
        )
    common_invalid = (
        reservations.get("release_digest") != release_digest
        or reservations.get("authority_database") != authority_database
        or reservations.get("canonical_root") != inventory_canary_project
        or reservations.get("authority_generation")
        != metadata.get("database_generation")
    )
    if readiness.get("kind") == AUTHORITY_READINESS_REATTEST_KIND:
        quiescence = readiness.get("quiescence_attestation")
        invalid_revision_binding = (
            reservations.get("kind")
            not in {
                ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
                FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            }
            or readiness.get("operation_id") != reservations.get("operation_id")
            or not isinstance(quiescence, Mapping)
            or quiescence.get("kind")
            != ATOMIC_FIRST_ADOPTION_PREPARED_KIND
            or (
                reservations.get("kind")
                == ATOMIC_FIRST_ADOPTION_PREPARED_KIND
                and quiescence.get("document_sha256")
                != reservations.get("document_sha256")
            )
            or reservations.get("authority_state_revision_after")
            != metadata.get("state_revision")
            or reservations.get("authority_state_revision_before")
            != int(metadata.get("state_revision", -2)) - 1
        )
    else:
        invalid_revision_binding = (
            reservations.get("authority_state_revision_before")
            != metadata.get("state_revision")
            or reservations.get("authority_state_revision_after")
            != int(metadata.get("state_revision", -2)) + 1
        )
    if common_invalid or invalid_revision_binding:
        raise CutoverError(
            "first-adoption port reservations changed the readiness binding"
        )


def _first_adoption_port_authorized_readiness_snapshot(
    *,
    readiness: Mapping[str, object],
    reservations: Mapping[str, object],
) -> dict[str, object]:
    """Derive the sole live snapshot authorized after reserving listener ports."""

    postcondition = readiness["postcondition"]
    if not isinstance(postcondition, Mapping):
        raise CutoverError("authority readiness postcondition is invalid")
    metadata = postcondition["metadata"]
    invariants = postcondition["invariants"]
    if not isinstance(metadata, Mapping) or not isinstance(invariants, Mapping):
        raise CutoverError("authority readiness postcondition is invalid")
    if readiness.get("kind") == AUTHORITY_READINESS_REATTEST_KIND:
        return _authority_readiness_snapshot(
            {
                "metadata": dict(metadata),
                "invariants": dict(invariants),
            },
            required_state="ready",
        )
    authorized_metadata = dict(metadata)
    authorized_metadata["state_revision"] = reservations[
        "authority_state_revision_after"
    ]
    authorized_metadata["updated_at"] = reservations["created_at"]
    return _authority_readiness_snapshot(
        {
            "metadata": authorized_metadata,
            "invariants": dict(invariants),
        },
        required_state="ready",
    )


def initialize(
    *,
    state_path: Path,
    release: Path,
    rendered_units: Path,
    legacy_authority_database: Path,
    authority_database: Path,
    test_database: Path,
    inventory_canary_project: Path,
    authority_backup_directory: Path,
    test_backup_directory: Path,
    migration_state: Path,
    drain_proof: Path,
    cutover_seal: Path,
    first_deployment_bootstrap: Path,
    authority_readiness: Path,
    first_adoption_port_reservations: Path,
    first_adoption_port_reservations_sha256: str,
    discard_test_history: str | None = None,
    fresh_test_store_attestation: Path | None = None,
    fresh_test_store_attestation_sha256: str | None = None,
    authority_uid: int,
    testd_uid: int,
    reserve_bytes: int,
    retain_until: str,
    authority_backup_required: bool = False,
    persist: bool = True,
) -> dict[str, object]:
    if authority_uid != 0 or testd_uid <= 0:
        raise CutoverError("authority must be root and testd must use a distinct service UID")
    if type(reserve_bytes) is not int or reserve_bytes < 0:
        raise CutoverError("capacity reserve must be non-negative")
    if type(authority_backup_required) is not bool:
        raise CutoverError("authority backup requirement must be boolean")
    discard_requested = discard_test_history is not None
    if discard_requested:
        if discard_test_history != DISCARD_TEST_HISTORY_CONFIRMATION:
            raise CutoverError("discard Test Store confirmation is invalid")
        if (
            fresh_test_store_attestation is None
            or fresh_test_store_attestation_sha256 is None
        ):
            raise CutoverError(
                "discarding test history requires the exact fresh Test Store attestation"
            )
    elif (
        fresh_test_store_attestation is not None
        or fresh_test_store_attestation_sha256 is not None
    ):
        raise CutoverError(
            "fresh Test Store evidence requires explicit discard confirmation"
        )
    state_path = _absolute(state_path, "cutover ledger")
    release = _absolute(release, "release")
    rendered_units = _absolute(rendered_units, "rendered units")
    migration_state = _absolute(migration_state, "migration state")
    drain_proof = _absolute(drain_proof, "drain proof")
    cutover_seal = _absolute(cutover_seal, "cutover seal")
    first_deployment_bootstrap = _absolute(
        first_deployment_bootstrap, "first-deployment bootstrap attestation"
    )
    authority_readiness = _absolute(
        authority_readiness, "authority readiness attestation"
    )
    first_adoption_port_reservations = _absolute(
        first_adoption_port_reservations,
        "first-adoption port reservations",
    )
    legacy_authority_database = _absolute(
        legacy_authority_database, "legacy authority database"
    )
    authority_database = _absolute(authority_database, "final authority database")
    test_database = _absolute(test_database, "test database")
    if fresh_test_store_attestation is not None:
        fresh_test_store_attestation = _absolute(
            fresh_test_store_attestation,
            "fresh Test Store attestation",
        )
    inventory_canary_project = _absolute(
        inventory_canary_project, "inventory canary project"
    )
    if (
        legacy_authority_database == authority_database
        or legacy_authority_database == test_database
        or authority_database == test_database
    ):
        raise CutoverError(
            "legacy authority, final authority, and testd databases must be distinct"
        )
    authority_identity = _database_identity(
        legacy_authority_database, uid=authority_uid
    )
    test_identity = _database_identity(test_database, uid=testd_uid)
    authority_backup_directory = _absolute(
        authority_backup_directory, "authority backup directory"
    )
    test_backup_directory = _absolute(test_backup_directory, "test backup directory")
    _private_parent(authority_backup_directory, uid=authority_uid)
    if not discard_requested:
        _private_parent(test_backup_directory, uid=testd_uid)
    authority_required = authority_identity["size"] + reserve_bytes
    test_required = test_identity["size"] + reserve_bytes
    authority_available = int(shutil.disk_usage(authority_backup_directory).free)
    test_available = (
        int(shutil.disk_usage(test_backup_directory).free)
        if not discard_requested
        else 0
    )
    if authority_backup_required and authority_available < authority_required:
        raise CutoverError("authority backup destination lacks required capacity")
    if not discard_requested and test_available < test_required:
        raise CutoverError("test backup destination lacks required capacity")
    release_result = _load_release_verifier().verify_release(release)
    if not all(release_result["capabilities"].values()):
        raise CutoverError("immutable release lacks a required activation capability")
    digest = str(release_result["release_digest"])
    bootstrap = _first_deployment_bootstrap(
        read_private_json(first_deployment_bootstrap, uid=authority_uid),
        expected_release=digest,
        expected_test_database=str(test_database),
        expected_testd_uid=testd_uid,
    )
    if bootstrap["authority_database"] != str(authority_database):
        raise CutoverError("first-deployment bootstrap authority target changed")
    readiness = _authority_readiness_evidence(
        read_private_json(authority_readiness, uid=authority_uid)
    )
    if (
        readiness["release"] != str(release)
        or readiness["release_digest"] != digest
        or readiness["database"] != str(legacy_authority_database)
    ):
        raise CutoverError("authority readiness evidence changed its cutover binding")
    if readiness.get("kind") == AUTHORITY_READINESS_REATTEST_KIND:
        _verify_authority_readiness_reattest_references(
            readiness,
            authority_uid=authority_uid,
        )
    reservations = verify_first_adoption_port_evidence(
        read_private_json(first_adoption_port_reservations, uid=authority_uid)
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(first_adoption_port_reservations_sha256)
        )
        is None
        or reservations["document_sha256"]
        != first_adoption_port_reservations_sha256
    ):
        raise CutoverError("first-adoption port reservation digest changed")
    if (
        readiness.get("kind") == AUTHORITY_READINESS_REATTEST_KIND
        and readiness["quiescence_attestation"]["path"]
        != str(first_adoption_port_reservations)
    ):
        raise CutoverError(
            "authority readiness re-attestation changed its quiescence path"
        )
    _validate_first_adoption_port_readiness_binding(
        readiness=readiness,
        reservations=reservations,
        release_digest=digest,
        authority_database=str(legacy_authority_database),
        inventory_canary_project=str(inventory_canary_project),
    )
    if reservations["kind"] == ATOMIC_FIRST_ADOPTION_PREPARED_KIND:
        _verify_atomic_first_adoption_fence(
            reservations,
            authority_uid=authority_uid,
        )
    live_readiness = _read_authority_readiness_snapshot(legacy_authority_database)
    live_identity = _database_identity(legacy_authority_database, uid=authority_uid)
    if (
        live_readiness
        != _first_adoption_port_authorized_readiness_snapshot(
            readiness=readiness,
            reservations=reservations,
        )
        or live_identity["device"]
        != readiness.get(
            "database_identity_after", readiness.get("database_identity")
        )["device"]
        or live_identity["inode"]
        != readiness.get(
            "database_identity_after", readiness.get("database_identity")
        )["inode"]
    ):
        raise CutoverError("authority readiness evidence no longer matches the source")
    verify_first_adoption_port_reservation_rows(
        legacy_authority_database,
        reservations,
        authority_uid=authority_uid,
        minimum_handoff_remaining_seconds=300,
    )
    retained_backup = _verify_authority_readiness_backup(
        database=legacy_authority_database,
        backup=Path(str(readiness["backup"]["path"])),
        backup_attestation=Path(str(readiness["backup"]["attestation"])),
        authority_uid=authority_uid,
        expected_precondition=readiness["precondition"],
        expected_identity=readiness.get(
            "database_identity_before", readiness.get("database_identity")
        ),
        evidence_reader=read_private_json,
    )
    if retained_backup != readiness["backup"]:
        raise CutoverError("authority readiness backup binding changed")
    schema_binding = bootstrap["schema_readiness"]
    if not isinstance(schema_binding, Mapping):
        raise CutoverError("first-deployment schema binding is invalid")
    schema_document = verify_seal(
        read_private_json(Path(str(schema_binding["path"])), uid=testd_uid),
        kind=SCHEMA_READINESS_KIND,
        fields=SCHEMA_READINESS_FIELDS,
    )
    if (
        schema_document["document_sha256"]
        != schema_binding["document_sha256"]
        or schema_document["store"] != bootstrap["test_store"]
    ):
        raise CutoverError("first-deployment schema readiness evidence changed")
    fresh_store: dict[str, object] | None = None
    if discard_requested:
        if fresh_test_store_attestation is None:
            raise CutoverError("fresh Test Store attestation is missing")
        fresh_store = _fresh_test_store_attestation(
            read_private_json(fresh_test_store_attestation, uid=testd_uid),
            expected_test_database=str(test_database),
        )
        expected_fresh_path = test_database.parent / (
            f"schema-readiness-{fresh_store['operation_id']}.json"
        )
        if (
            test_database.name != "tests.sqlite3"
            or fresh_test_store_attestation != expected_fresh_path
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(fresh_test_store_attestation_sha256),
            )
            is None
            or fresh_store["document_sha256"]
            != fresh_test_store_attestation_sha256
            or fresh_store["store"] != bootstrap["test_store"]
            or fresh_store["store"] != schema_document["store"]
        ):
            raise CutoverError(
                "fresh Test Store attestation changed or belongs to another store"
            )
    findings = _load_topology_verifier().validate_topology(
        rendered_units, release_digest=digest
    )
    if findings:
        raise CutoverError("rendered availability topology is invalid")
    expected_plan = {
        "release": str(release),
        "release_digest": digest,
        "rendered_units": str(rendered_units),
        "authority_uid": authority_uid,
        "testd_uid": testd_uid,
        "legacy_authority_database": str(legacy_authority_database),
        "authority_database": str(authority_database),
        "test_database": str(test_database),
        "inventory_canary_project": str(inventory_canary_project),
        "authority_backup_directory": str(authority_backup_directory),
        "test_backup_directory": str(test_backup_directory),
        "migration_state": str(migration_state),
        "drain_proof": str(drain_proof),
        "cutover_seal": str(cutover_seal),
        "reserve_bytes": reserve_bytes,
        "retain_until": retain_until,
        "authority_backup_required": authority_backup_required,
    }
    capacity = {
        "authority": {
            "required": authority_backup_required,
            "source_bytes": authority_identity["size"],
            "estimated_backup_bytes": authority_identity["size"],
            "reserve_bytes": reserve_bytes if authority_backup_required else 0,
            "required_free_bytes": authority_required if authority_backup_required else 0,
            "available_bytes": authority_available,
        },
        "testd": {
            "required": not discard_requested,
            "source_bytes": test_identity["size"],
            "estimated_backup_bytes": (
                test_identity["size"] if not discard_requested else 0
            ),
            "reserve_bytes": reserve_bytes if not discard_requested else 0,
            "required_free_bytes": test_required if not discard_requested else 0,
            "available_bytes": test_available,
        },
    }
    expected_initial_evidence = {
        "first-deployment-bootstrap": bootstrap,
        "authority-readiness": readiness,
        "first-adoption-port-reservations": reservations,
        **(
            {"test-history-discard": fresh_store}
            if fresh_store is not None
            else {}
        ),
    }
    if state_path.exists() or state_path.is_symlink():
        current = load_state(state_path, authority_uid=authority_uid)
        if (
            any(current[field] != expected for field, expected in expected_plan.items())
            or any(
                current["evidence"].get(key) != value
                for key, value in expected_initial_evidence.items()
            )
            or (
                "test-history-discard" in current["evidence"]
            )
            != discard_requested
        ):
            raise CutoverError("cutover ledger already exists with another plan")
        return {
            "ok": True,
            "phase": current["phase"],
            "cutover_id": current["cutover_id"],
            "state_generation": current["state_generation"],
            "resumed": True,
            "dry_run": not persist,
            "capacity": capacity,
        }
    lock = (
        exclusive_broker_service_lock(legacy_authority_database)
        if persist
        and reservations["kind"] == ATOMIC_FIRST_ADOPTION_PREPARED_KIND
        else nullcontext()
    )
    with lock:
        if persist and reservations["kind"] == ATOMIC_FIRST_ADOPTION_PREPARED_KIND:
            _verify_atomic_first_adoption_fence(
                reservations,
                authority_uid=authority_uid,
            )
            locked_readiness_evidence = _authority_readiness_evidence(
                read_private_json(
                    authority_readiness, uid=authority_uid
                )
            )
            if locked_readiness_evidence != readiness:
                raise CutoverError(
                    "authority readiness evidence changed before initialization"
                )
            if (
                locked_readiness_evidence.get("kind")
                == AUTHORITY_READINESS_REATTEST_KIND
            ):
                _verify_authority_readiness_reattest_references(
                    locked_readiness_evidence,
                    authority_uid=authority_uid,
                )
            locked_reservations = verify_first_adoption_port_evidence(
                read_private_json(
                    first_adoption_port_reservations, uid=authority_uid
                )
            )
            if locked_reservations != reservations:
                raise CutoverError(
                    "first-adoption port reservation evidence changed before initialization"
                )
            locked_identity = _database_identity(
                legacy_authority_database, uid=authority_uid
            )
            locked_readiness = _read_authority_readiness_snapshot(
                legacy_authority_database
            )
            if (
                locked_readiness
                != _first_adoption_port_authorized_readiness_snapshot(
                    readiness=readiness,
                    reservations=reservations,
                )
                or locked_identity["device"]
                != readiness.get(
                    "database_identity_after",
                    readiness.get("database_identity"),
                )["device"]
                or locked_identity["inode"]
                != readiness.get(
                    "database_identity_after",
                    readiness.get("database_identity"),
                )["inode"]
            ):
                raise CutoverError(
                    "authority readiness evidence no longer matches the source"
                )
            locked_backup = _verify_authority_readiness_backup(
                database=legacy_authority_database,
                backup=Path(str(readiness["backup"]["path"])),
                backup_attestation=Path(
                    str(readiness["backup"]["attestation"])
                ),
                authority_uid=authority_uid,
                expected_precondition=readiness["precondition"],
                expected_identity=readiness.get(
                    "database_identity_before",
                    readiness.get("database_identity"),
                ),
                evidence_reader=read_private_json,
            )
            if locked_backup != readiness["backup"]:
                raise CutoverError(
                    "authority readiness backup changed before initialization"
                )
            verify_first_adoption_port_reservation_rows(
                legacy_authority_database,
                reservations,
                authority_uid=authority_uid,
                minimum_handoff_remaining_seconds=300,
            )
            if state_path.exists() or state_path.is_symlink():
                current = load_state(state_path, authority_uid=authority_uid)
                if (
                    any(
                        current[field] != expected
                        for field, expected in expected_plan.items()
                    )
                    or any(
                        current["evidence"].get(key) != value
                        for key, value in expected_initial_evidence.items()
                    )
                    or (
                        "test-history-discard" in current["evidence"]
                    )
                    != discard_requested
                ):
                    raise CutoverError(
                        "cutover ledger already exists with another plan"
                    )
                return {
                    "ok": True,
                    "phase": current["phase"],
                    "cutover_id": current["cutover_id"],
                    "state_generation": current["state_generation"],
                    "resumed": True,
                    "dry_run": False,
                    "capacity": capacity,
                }
        timestamp = _now()
        unsigned = {
            "cutover_id": str(uuid.uuid4()),
            "phase": "sealed" if discard_requested else "planned",
            **expected_plan,
            "evidence": expected_initial_evidence,
            "created_at": timestamp,
            "updated_at": timestamp,
            "state_generation": 0,
        }
        document = seal(STATE_KIND, unsigned)
        validate_state(document)
        if persist:
            _write_private_json(
                state_path,
                document,
                uid=authority_uid,
                create=True,
            )
    return {
        "ok": True,
        "phase": "sealed" if discard_requested else "planned",
        "cutover_id": unsigned["cutover_id"],
        "state_generation": 0,
        "resumed": False,
        "dry_run": not persist,
        "capacity": capacity,
        **({"actions": next_actions(document)["actions"]} if not persist else {}),
    }


BACKUP_FIELDS = frozenset(
    {
        "database",
        "database_device",
        "database_inode",
        "database_sha256",
        "backup",
        "backup_sha256",
        "backup_bytes",
        "quick_check",
        "foreign_key_violations",
        "available_bytes",
        "required_bytes",
        "expected_uid",
        "created_at",
    }
)


def backup_database(
    *,
    database: Path,
    backup: Path,
    attestation: Path,
    expected_uid: int,
    reserve_bytes: int,
) -> dict[str, object]:
    if os.geteuid() != expected_uid:
        raise CutoverError("database backup must run as the database service UID")
    database = _absolute(database, "database")
    backup = _absolute(backup, "backup")
    attestation = _absolute(attestation, "backup attestation")
    identity = _database_identity(database, uid=expected_uid)
    _private_parent(backup.parent, uid=expected_uid)
    if attestation.parent != backup.parent:
        raise CutoverError("backup and attestation must share one private directory")
    if attestation.exists() or attestation.is_symlink():
        existing = verify_seal(
            read_private_json(attestation, uid=expected_uid),
            kind=BACKUP_KIND,
            fields=BACKUP_FIELDS,
        )
        if (
            existing["database"] == str(database)
            and existing["backup"] == str(backup)
            and backup.is_file()
            and _file_digest(backup) == existing["backup_sha256"]
        ):
            return {"ok": True, "created": False, **existing}
        raise CutoverError("existing backup attestation is contradictory")
    if backup.exists() or backup.is_symlink():
        raise CutoverError("backup output already exists without its attestation")
    available = int(shutil.disk_usage(backup.parent).free)
    # SQLite's online backup writes one destination image.  The source already
    # exists on its own volume and is not duplicated in the destination.  A
    # second full-source multiplier caused the misleading multi-GiB estimate
    # that operators saw for a much smaller authority database.
    required = identity["size"] + reserve_bytes
    if available < required:
        raise CutoverError("backup destination lacks required reserve")
    source_uri = f"file:{database}?mode=ro"
    temporary = backup.with_name(f".{backup.name}.{uuid.uuid4().hex}.partial")
    try:
        with closing(sqlite3.connect(source_uri, uri=True, timeout=5.0)) as source:
            with closing(sqlite3.connect(temporary)) as destination:
                source.row_factory = sqlite3.Row
                if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise CutoverError("source database quick_check failed")
                source.backup(destination)
                destination.commit()
                if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise CutoverError("backup database quick_check failed")
                foreign_keys = len(
                    destination.execute("PRAGMA foreign_key_check").fetchall()
                )
        after_identity = _database_identity(database, uid=expected_uid)
        if (
            after_identity["device"] != identity["device"]
            or after_identity["inode"] != identity["inode"]
        ):
            raise CutoverError("source database identity changed during backup")
        os.chmod(temporary, 0o600)
        os.replace(temporary, backup)
    finally:
        temporary.unlink(missing_ok=True)
    backup_sha = _file_digest(backup)
    document = seal(
        BACKUP_KIND,
        {
            "database": str(database),
            "database_device": identity["device"],
            "database_inode": identity["inode"],
            "database_sha256": _file_digest(database),
            "backup": str(backup),
            "backup_sha256": backup_sha,
            "backup_bytes": backup.stat().st_size,
            "quick_check": "ok",
            "foreign_key_violations": foreign_keys,
            "available_bytes": available,
            "required_bytes": required,
            "expected_uid": expected_uid,
            "created_at": _now(),
        },
    )
    _publish_evidence(attestation, document, uid=expected_uid)
    return {"ok": True, "created": True, **document}


def _publish_evidence(path: Path, document: Mapping[str, object], *, uid: int) -> None:
    if os.geteuid() != uid:
        raise CutoverError("evidence publisher UID is invalid")
    _private_parent(path.parent, uid=uid)
    if path.exists() or path.is_symlink():
        if read_private_json(path, uid=uid) == dict(document):
            return
        raise CutoverError("evidence output already exists with different content")
    payload = _canonical(document) + b"\n"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def _authority_readiness_identity(value: object, *, label: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != {"device", "inode", "size"}:
        raise CutoverError(f"{label} identity fields are invalid")
    result: dict[str, int] = {}
    for field in ("device", "inode", "size"):
        item = value[field]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise CutoverError(f"{label} identity is invalid")
        result[field] = item
    return result


def _authority_readiness_maintenance(value: object) -> dict[str, object]:
    fields = {
        "root",
        "gid",
        "deployment_id",
        "message",
        "retry_after_seconds",
        "started_at",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("authority readiness maintenance binding is invalid")
    try:
        deployment_id = str(uuid.UUID(str(value["deployment_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness maintenance deployment ID is invalid") from error
    if (
        value["message"] != PUBLIC_MAINTENANCE_MESSAGE
        or isinstance(value["gid"], bool)
        or not isinstance(value["gid"], int)
        or int(value["gid"]) < 0
        or isinstance(value["retry_after_seconds"], bool)
        or not isinstance(value["retry_after_seconds"], int)
        or int(value["retry_after_seconds"]) <= 0
        or not isinstance(value["started_at"], str)
        or not str(value["started_at"]).endswith("Z")
    ):
        raise CutoverError("authority readiness maintenance marker is invalid")
    root = _absolute(str(value["root"]), "authority readiness maintenance root")
    return {
        "root": str(root),
        "gid": int(value["gid"]),
        "deployment_id": deployment_id,
        "message": PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": int(value["retry_after_seconds"]),
        "started_at": str(value["started_at"]),
    }


def _authority_readiness_writer_lock(value: object) -> dict[str, object]:
    fields = {
        "path",
        "device",
        "inode",
        "uid",
        "mode",
        "acquired",
        "active_broker_excluded",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("authority readiness writer lock evidence is invalid")
    path = _absolute(str(value["path"]), "authority readiness writer lock")
    if (
        any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or int(value[field]) < 0
            for field in ("device", "inode", "uid")
        )
        or value["mode"] != "0600"
        or value["acquired"] is not True
        or value["active_broker_excluded"] is not True
    ):
        raise CutoverError("authority readiness writer lock evidence is unsafe")
    return {
        "path": str(path),
        "device": int(value["device"]),
        "inode": int(value["inode"]),
        "uid": int(value["uid"]),
        "mode": "0600",
        "acquired": True,
        "active_broker_excluded": True,
    }


def _authority_readiness_backup(value: object) -> dict[str, object]:
    fields = {
        "path",
        "attestation",
        "attestation_sha256",
        "backup_sha256",
        "backup_bytes",
        "database_device",
        "database_inode",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("authority readiness backup binding is invalid")
    path = _absolute(str(value["path"]), "authority readiness backup")
    attestation = _absolute(
        str(value["attestation"]), "authority readiness backup attestation"
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(value["attestation_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(value["backup_sha256"])) is None
        or any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or int(value[field]) < 0
            for field in ("backup_bytes", "database_device", "database_inode")
        )
    ):
        raise CutoverError("authority readiness backup binding is invalid")
    return {
        "path": str(path),
        "attestation": str(attestation),
        "attestation_sha256": str(value["attestation_sha256"]),
        "backup_sha256": str(value["backup_sha256"]),
        "backup_bytes": int(value["backup_bytes"]),
        "database_device": int(value["database_device"]),
        "database_inode": int(value["database_inode"]),
    }


def _authority_readiness_snapshot(
    value: object, *, required_state: str
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"metadata", "invariants"}:
        raise CutoverError("authority readiness snapshot fields are invalid")
    metadata = value["metadata"]
    metadata_fields = {
        "schema_version",
        "database_generation",
        "state_revision",
        "observation_revision",
        "authority_mode",
        "migration_state",
        "first_sqlite_mutation_at",
        "created_at",
        "updated_at",
    }
    if not isinstance(metadata, Mapping) or set(metadata) != metadata_fields:
        raise CutoverError("authority readiness metadata fields are invalid")
    generation = metadata["database_generation"]
    if (
        metadata["schema_version"] != 12
        or metadata["migration_state"] != required_state
        or metadata["authority_mode"] != "sqlite"
        or not isinstance(generation, str)
        or generation != generation.strip()
        or not generation
        or len(generation) > 256
        or any(ord(character) < 0x20 for character in generation)
        or any(
            isinstance(metadata[field], bool)
            or not isinstance(metadata[field], int)
            or int(metadata[field]) < 0
            for field in ("state_revision", "observation_revision")
        )
        or not isinstance(metadata["first_sqlite_mutation_at"], str)
        or not metadata["first_sqlite_mutation_at"]
        or not isinstance(metadata["created_at"], str)
        or not metadata["created_at"]
        or not isinstance(metadata["updated_at"], str)
        or not metadata["updated_at"]
    ):
        raise CutoverError("authority readiness metadata is invalid")
    invariants = value["invariants"]
    invariant_fields = {
        "quick_check",
        "foreign_key_violations",
        "repositories",
        "installations",
        "principals",
        "enrollments",
        "hosts",
        "open_blocking_conflicts",
        "missing_installations",
        "orphan_installations",
        "orphan_repository_enrollments",
        "orphan_principal_enrollments",
        "partial_v13_tables",
    }
    if not isinstance(invariants, Mapping) or set(invariants) != invariant_fields:
        raise CutoverError("authority readiness invariant fields are invalid")
    numeric_fields = invariant_fields - {"quick_check", "partial_v13_tables"}
    if (
        invariants["quick_check"] != "ok"
        or invariants["partial_v13_tables"] != []
        or any(
            isinstance(invariants[field], bool)
            or not isinstance(invariants[field], int)
            or int(invariants[field]) < 0
            for field in numeric_fields
        )
        or int(invariants["repositories"]) <= 0
        or int(invariants["installations"]) != int(invariants["repositories"])
        or int(invariants["principals"]) <= 0
        or int(invariants["enrollments"]) <= 0
        or int(invariants["hosts"]) <= 0
        or any(
            int(invariants[field]) != 0
            for field in (
                "foreign_key_violations",
                "open_blocking_conflicts",
                "missing_installations",
                "orphan_installations",
                "orphan_repository_enrollments",
                "orphan_principal_enrollments",
            )
        )
    ):
        raise CutoverError("authority readiness invariants are not satisfied")
    return {
        "metadata": dict(metadata),
        "invariants": {
            field: invariants[field]
            for field in sorted(invariant_fields)
        },
    }


def _read_authority_readiness_snapshot(
    database: Path, *, connection: sqlite3.Connection | None = None
) -> dict[str, object]:
    owns_connection = connection is None
    active = connection
    if active is None:
        active = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5.0)
    try:
        active.row_factory = sqlite3.Row
        tables = {
            str(row[0])
            for row in active.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = sorted(AUTHORITY_READINESS_TABLES - tables)
        if missing:
            raise CutoverError(
                "authority readiness database is missing required tables: "
                + ", ".join(missing)
            )
        partial_v13 = sorted(AUTHORITY_READINESS_PARTIAL_V13_TABLES & tables)
        quick_rows = [str(row[0]) for row in active.execute("PRAGMA quick_check")]
        metadata = active.execute(
            """
            SELECT schema_version, database_generation, state_revision,
                   observation_revision, authority_mode, migration_state,
                   first_sqlite_mutation_at, created_at, updated_at
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchall()
        if len(metadata) != 1:
            raise CutoverError("authority readiness metadata singleton is invalid")
        row = metadata[0]

        def count(query: str) -> int:
            item = active.execute(query).fetchone()
            if item is None:
                raise CutoverError("authority readiness invariant query returned no row")
            return int(item[0])

        snapshot = {
            "metadata": {
                "schema_version": int(row[0]),
                "database_generation": str(row[1]),
                "state_revision": int(row[2]),
                "observation_revision": int(row[3]),
                "authority_mode": str(row[4]),
                "migration_state": str(row[5]),
                "first_sqlite_mutation_at": row[6],
                "created_at": str(row[7]),
                "updated_at": str(row[8]),
            },
            "invariants": {
                "quick_check": "ok" if quick_rows == ["ok"] else "failed",
                "foreign_key_violations": len(
                    active.execute("PRAGMA foreign_key_check").fetchall()
                ),
                "repositories": count("SELECT COUNT(*) FROM repositories"),
                "installations": count(
                    "SELECT COUNT(*) FROM repository_installations"
                ),
                "principals": count("SELECT COUNT(*) FROM broker_acl_principals"),
                "enrollments": count(
                    "SELECT COUNT(*) FROM broker_repository_enrollments"
                ),
                "hosts": count("SELECT COUNT(*) FROM hosts"),
                "open_blocking_conflicts": count(
                    "SELECT COUNT(*) FROM migration_conflicts "
                    "WHERE severity='blocking' AND disposition='open'"
                ),
                "missing_installations": count(
                    "SELECT COUNT(*) FROM repositories r LEFT JOIN "
                    "repository_installations i USING(repo_id) WHERE i.repo_id IS NULL"
                ),
                "orphan_installations": count(
                    "SELECT COUNT(*) FROM repository_installations i LEFT JOIN "
                    "repositories r USING(repo_id) WHERE r.repo_id IS NULL"
                ),
                "orphan_repository_enrollments": count(
                    "SELECT COUNT(*) FROM broker_repository_enrollments e LEFT JOIN "
                    "repositories r USING(repo_id) WHERE r.repo_id IS NULL"
                ),
                "orphan_principal_enrollments": count(
                    "SELECT COUNT(*) FROM broker_repository_enrollments e LEFT JOIN "
                    "broker_acl_principals p ON p.uid=e.uid AND "
                    "p.account_id=e.account_id WHERE p.uid IS NULL"
                ),
                "partial_v13_tables": partial_v13,
            },
        }
        state = str(snapshot["metadata"]["migration_state"])
        return _authority_readiness_snapshot(snapshot, required_state=state)
    finally:
        if owns_connection and active is not None:
            active.close()


def _authority_readiness_target(
    value: object, *, precondition: Mapping[str, object]
) -> dict[str, object]:
    fields = {
        "schema_version",
        "migration_state",
        "database_generation",
        "state_revision",
        "updated_at",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("authority readiness target fields are invalid")
    metadata = precondition["metadata"]
    if (
        value["schema_version"] != 12
        or value["migration_state"] != "ready"
        or value["database_generation"] != metadata["database_generation"]
        or value["state_revision"] != int(metadata["state_revision"]) + 1
        or not isinstance(value["updated_at"], str)
        or not value["updated_at"]
    ):
        raise CutoverError("authority readiness target contradicts its precondition")
    return dict(value)


def _authority_readiness_intent(value: object) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_INTENT_KIND,
        fields=AUTHORITY_READINESS_INTENT_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness operation ID is invalid") from error
    release = _absolute(str(document["release"]), "authority readiness release")
    database = _absolute(str(document["database"]), "authority readiness database")
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError("authority readiness intent binding is invalid")
    document["release"] = str(release)
    document["database"] = str(database)
    document["database_identity"] = _authority_readiness_identity(
        document["database_identity"], label="authority readiness database"
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    document["writer_lock"] = _authority_readiness_writer_lock(
        document["writer_lock"]
    )
    document["backup"] = _authority_readiness_backup(document["backup"])
    document["precondition"] = _authority_readiness_snapshot(
        document["precondition"], required_state="empty"
    )
    document["target"] = _authority_readiness_target(
        document["target"], precondition=document["precondition"]
    )
    return document


def _authority_readiness_result(value: object) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_RESULT_KIND,
        fields=AUTHORITY_READINESS_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness result operation ID is invalid") from error
    document["release"] = str(
        _absolute(str(document["release"]), "authority readiness result release")
    )
    document["database"] = str(
        _absolute(str(document["database"]), "authority readiness result database")
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["intent_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or type(document["applied"]) is not bool
        or type(document["recovered"]) is not bool
        or document["applied"] == document["recovered"]
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError("authority readiness result binding is invalid")
    document["database_identity_before"] = _authority_readiness_identity(
        document["database_identity_before"], label="authority readiness database before"
    )
    document["database_identity_after"] = _authority_readiness_identity(
        document["database_identity_after"], label="authority readiness database after"
    )
    if (
        document["database_identity_before"]["device"]
        != document["database_identity_after"]["device"]
        or document["database_identity_before"]["inode"]
        != document["database_identity_after"]["inode"]
    ):
        raise CutoverError("authority readiness database identity changed")
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    document["writer_lock"] = _authority_readiness_writer_lock(
        document["writer_lock"]
    )
    document["backup"] = _authority_readiness_backup(document["backup"])
    pre = _authority_readiness_snapshot(document["precondition"], required_state="empty")
    post = _authority_readiness_snapshot(document["postcondition"], required_state="ready")
    expected_post_metadata = dict(pre["metadata"])
    expected_post_metadata.update(
        {
            "migration_state": "ready",
            "state_revision": int(pre["metadata"]["state_revision"]) + 1,
            "updated_at": post["metadata"]["updated_at"],
        }
    )
    if (
        post["metadata"] != expected_post_metadata
        or post["invariants"] != pre["invariants"]
    ):
        raise CutoverError("authority readiness result changed unrelated authority state")
    document["precondition"] = pre
    document["postcondition"] = post
    return document


def _authority_readiness_rebind_attestation(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_REBIND_KIND,
        fields=AUTHORITY_READINESS_REBIND_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness rebind operation ID is invalid"
        ) from error
    document["release"] = str(
        _absolute(
            str(document["release"]), "authority readiness rebind release"
        )
    )
    document["database"] = str(
        _absolute(
            str(document["database"]), "authority readiness rebind database"
        )
    )
    prior = document["prior_attestation"]
    if (
        not isinstance(prior, Mapping)
        or set(prior) != {"path", "document_sha256"}
        or re.fullmatch(
            r"[0-9a-f]{64}", str(prior.get("document_sha256"))
        )
        is None
    ):
        raise CutoverError(
            "authority readiness prior attestation binding is invalid"
        )
    document["prior_attestation"] = {
        "path": str(
            _absolute(
                str(prior["path"]),
                "authority readiness prior attestation",
            )
        ),
        "document_sha256": str(prior["document_sha256"]),
    }
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(document["prior_release_digest"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["release_digest"])
        )
        is None
        or document["prior_release_digest"] == document["release_digest"]
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["database_sha256"])
        )
        is None
        or document["mutation_applied"] is not False
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError("authority readiness rebind binding is invalid")
    document["database_identity"] = _authority_readiness_identity(
        document["database_identity"],
        label="authority readiness rebind database",
    )
    document["writer_lock"] = _authority_readiness_writer_lock(
        document["writer_lock"]
    )
    document["backup"] = _authority_readiness_backup(document["backup"])
    precondition = _authority_readiness_snapshot(
        document["precondition"], required_state="ready"
    )
    postcondition = _authority_readiness_snapshot(
        document["postcondition"], required_state="ready"
    )
    if precondition != postcondition:
        raise CutoverError("authority readiness rebind changed authority state")
    document["precondition"] = precondition
    document["postcondition"] = postcondition
    return document


def _authority_readiness_evidence_reference(
    value: object, *, label: str, expected_kind: str | None = None
) -> dict[str, str]:
    fields = {"path", "document_sha256"}
    if expected_kind is not None:
        fields.add("kind")
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError(f"{label} binding is invalid")
    path = str(_absolute(str(value["path"]), label))
    digest = str(value["document_sha256"])
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise CutoverError(f"{label} digest is invalid")
    result = {"path": path, "document_sha256": digest}
    if expected_kind is not None:
        if value["kind"] != expected_kind:
            raise CutoverError(f"{label} kind is invalid")
        result["kind"] = expected_kind
    return result


def _authority_readiness_reattest_intent(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_REATTEST_INTENT_KIND,
        fields=AUTHORITY_READINESS_REATTEST_INTENT_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness re-attestation operation ID is invalid"
        ) from error
    document["release"] = str(
        _absolute(
            str(document["release"]),
            "authority readiness re-attestation release",
        )
    )
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "authority readiness re-attestation database",
        )
    )
    document["prior_attestation"] = _authority_readiness_evidence_reference(
        document["prior_attestation"],
        label="authority readiness prior attestation",
    )
    document["quiescence_attestation"] = (
        _authority_readiness_evidence_reference(
            document["quiescence_attestation"],
            label="authority readiness quiescence attestation",
            expected_kind=ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
        )
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(document["prior_release_digest"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["release_digest"])
        )
        is None
        or document["prior_release_digest"] == document["release_digest"]
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["database_sha256"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_stopped"] is not True
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError(
            "authority readiness re-attestation intent binding is invalid"
        )
    document["database_identity"] = _authority_readiness_identity(
        document["database_identity"],
        label="authority readiness re-attestation database",
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    document["writer_lock"] = _authority_readiness_writer_lock(
        document["writer_lock"]
    )
    document["backup"] = _authority_readiness_backup(document["backup"])
    document["precondition"] = _authority_readiness_snapshot(
        document["precondition"], required_state="ready"
    )
    return document


def _authority_readiness_reattest_attestation(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_REATTEST_KIND,
        fields=AUTHORITY_READINESS_REATTEST_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness re-attestation operation ID is invalid"
        ) from error
    document["release"] = str(
        _absolute(
            str(document["release"]),
            "authority readiness re-attestation release",
        )
    )
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "authority readiness re-attestation database",
        )
    )
    document["prior_attestation"] = _authority_readiness_evidence_reference(
        document["prior_attestation"],
        label="authority readiness prior attestation",
    )
    document["quiescence_attestation"] = (
        _authority_readiness_evidence_reference(
            document["quiescence_attestation"],
            label="authority readiness quiescence attestation",
            expected_kind=ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
        )
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(document["prior_release_digest"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["release_digest"])
        )
        is None
        or document["prior_release_digest"] == document["release_digest"]
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["database_sha256"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_stopped"] is not True
        or document["mutation_applied"] is not False
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError(
            "authority readiness re-attestation binding is invalid"
        )
    document["intent"] = _authority_readiness_evidence_reference(
        document["intent"],
        label="authority readiness re-attestation intent",
    )
    before = _authority_readiness_identity(
        document["database_identity_before"],
        label="authority readiness re-attestation database before",
    )
    after = _authority_readiness_identity(
        document["database_identity_after"],
        label="authority readiness re-attestation database after",
    )
    if before != after:
        raise CutoverError(
            "authority readiness re-attestation database identity changed"
        )
    document["database_identity_before"] = before
    document["database_identity_after"] = after
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    document["writer_lock"] = _authority_readiness_writer_lock(
        document["writer_lock"]
    )
    document["backup"] = _authority_readiness_backup(document["backup"])
    precondition = _authority_readiness_snapshot(
        document["precondition"], required_state="ready"
    )
    postcondition = _authority_readiness_snapshot(
        document["postcondition"], required_state="ready"
    )
    if precondition != postcondition:
        raise CutoverError(
            "authority readiness re-attestation changed authority state"
        )
    document["precondition"] = precondition
    document["postcondition"] = postcondition
    return document


def _authority_readiness_same_database(
    ancestor: object,
    candidate: object,
    *,
    label: str,
) -> dict[str, int]:
    """Validate a database identity that may have grown without being replaced."""

    prior = _authority_readiness_identity(
        ancestor, label=f"{label} ancestor database"
    )
    current = _authority_readiness_identity(
        candidate, label=f"{label} candidate database"
    )
    if (
        current["device"] != prior["device"]
        or current["inode"] != prior["inode"]
    ):
        raise CutoverError(f"{label} database identity changed")
    return current


def _authority_readiness_ready_descendant(
    ancestor: object,
    candidate: object,
    *,
    label: str,
) -> dict[str, object]:
    """Return a validated ready descendant without requiring byte equality.

    A live schema-12 authority can legitimately advance after its first readiness
    repair.  Release rebinding therefore preserves the immutable authority
    lineage while allowing only monotonic state/observation revisions.  Both
    snapshots are independently revalidated so a revision bump cannot conceal a
    schema, generation, authority-mode, migration-state, or invariant failure.
    """

    prior = _authority_readiness_snapshot(ancestor, required_state="ready")
    current = _authority_readiness_snapshot(candidate, required_state="ready")
    stable_metadata = (
        "schema_version",
        "database_generation",
        "authority_mode",
        "migration_state",
        "created_at",
        "first_sqlite_mutation_at",
    )
    if any(
        current["metadata"][field] != prior["metadata"][field]
        for field in stable_metadata
    ):
        raise CutoverError(f"{label} stable authority metadata changed")
    for field in ("state_revision", "observation_revision"):
        if int(current["metadata"][field]) < int(prior["metadata"][field]):
            raise CutoverError(f"{label} {field.replace('_', ' ')} regressed")
    if _parse_utc_timestamp(
        current["metadata"]["updated_at"], label=f"{label} current updated_at"
    ) < _parse_utc_timestamp(
        prior["metadata"]["updated_at"], label=f"{label} prior updated_at"
    ):
        raise CutoverError(f"{label} updated_at regressed")
    return current


def _authority_readiness_sidecar_identities(
    database: Path, *, uid: int
) -> dict[str, dict[str, int] | None]:
    identities: dict[str, dict[str, int] | None] = {}
    for suffix in ("-wal", "-shm"):
        path = Path(str(database) + suffix)
        if not path.exists() and not path.is_symlink():
            identities[suffix] = None
            continue
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_nlink != 1
            or path.resolve(strict=True) != path
            or (suffix == "-wal" and info.st_size != 0)
        ):
            raise CutoverError(
                f"authority readiness SQLite {suffix[1:]} sidecar is unsafe"
            )
        identities[suffix] = {
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "size": int(info.st_size),
            "mtime_ns": int(info.st_mtime_ns),
            "ctime_ns": int(info.st_ctime_ns),
        }
    return identities


def _authority_readiness_descriptor_digest(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise CutoverError(
                "authority readiness database shortened while it was hashed"
            )
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _immutable_authority_readiness_observation(
    database: Path, *, uid: int
) -> dict[str, object]:
    """Read one exact SQLite image through a retained no-follow descriptor."""

    database = _absolute(database, "authority readiness database")
    before_path = database.lstat()
    if (
        stat.S_ISLNK(before_path.st_mode)
        or not stat.S_ISREG(before_path.st_mode)
        or before_path.st_uid != uid
        or stat.S_IMODE(before_path.st_mode) & 0o022
        or before_path.st_nlink != 1
        or database.resolve(strict=True) != database
    ):
        raise CutoverError(
            "authority readiness database has unsafe immutable identity"
        )
    sidecars_before = _authority_readiness_sidecar_identities(
        database, uid=uid
    )
    descriptor = os.open(
        database,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before_descriptor = os.fstat(descriptor)
        if (
            before_descriptor.st_dev != before_path.st_dev
            or before_descriptor.st_ino != before_path.st_ino
            or before_descriptor.st_size != before_path.st_size
        ):
            raise CutoverError(
                "authority readiness database changed before descriptor anchoring"
            )
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1",
                uri=True,
                timeout=5.0,
            )
            connection.execute("PRAGMA query_only = ON")
            snapshot = _read_authority_readiness_snapshot(
                database, connection=connection
            )
        finally:
            if connection is not None:
                connection.close()
        database_sha256 = _authority_readiness_descriptor_digest(
            descriptor, int(before_descriptor.st_size)
        )
        after_descriptor = os.fstat(descriptor)
        after_path = database.lstat()
        sidecars_after = _authority_readiness_sidecar_identities(
            database, uid=uid
        )
        descriptor_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            any(
                getattr(before_descriptor, field)
                != getattr(after_descriptor, field)
                for field in descriptor_fields
            )
            or any(
                getattr(after_descriptor, field) != getattr(after_path, field)
                for field in descriptor_fields
            )
            or sidecars_after != sidecars_before
        ):
            raise CutoverError(
                "authority readiness database changed during immutable observation"
            )
        return {
            "database_identity": {
                "device": int(after_descriptor.st_dev),
                "inode": int(after_descriptor.st_ino),
                "size": int(after_descriptor.st_size),
            },
            "database_sha256": database_sha256,
            "snapshot": snapshot,
        }
    finally:
        os.close(descriptor)


def _authority_readiness_evidence(value: object) -> dict[str, object]:
    if (
        isinstance(value, Mapping)
        and value.get("kind") == AUTHORITY_READINESS_REATTEST_KIND
    ):
        return _authority_readiness_reattest_attestation(value)
    if isinstance(value, Mapping) and value.get("kind") == AUTHORITY_READINESS_REBIND_KIND:
        return _authority_readiness_rebind_attestation(value)
    return _authority_readiness_result(value)


def _verify_authority_readiness_reattest_references(
    readiness: Mapping[str, object],
    *,
    authority_uid: int,
    evidence_reader=read_private_json,
) -> dict[str, object]:
    document = _authority_readiness_reattest_attestation(readiness)
    intent = _authority_readiness_reattest_intent(
        evidence_reader(
            Path(str(document["intent"]["path"])), uid=authority_uid
        )
    )
    prior = _authority_readiness_result(
        evidence_reader(
            Path(str(document["prior_attestation"]["path"])),
            uid=authority_uid,
        )
    )
    intent_expected = {
        "operation_id": document["operation_id"],
        "prior_attestation": document["prior_attestation"],
        "prior_release_digest": document["prior_release_digest"],
        "quiescence_attestation": document["quiescence_attestation"],
        "release": document["release"],
        "release_digest": document["release_digest"],
        "database": document["database"],
        "database_identity": document["database_identity_before"],
        "database_sha256": document["database_sha256"],
        "service_unit": document["service_unit"],
        "service_stopped": document["service_stopped"],
        "maintenance": document["maintenance"],
        "writer_lock": document["writer_lock"],
        "backup": document["backup"],
        "precondition": document["precondition"],
    }
    if (
        intent["document_sha256"]
        != document["intent"]["document_sha256"]
        or any(
            intent[field] != expected
            for field, expected in intent_expected.items()
        )
        or prior["document_sha256"]
        != document["prior_attestation"]["document_sha256"]
        or prior["release_digest"] != document["prior_release_digest"]
        or prior["database"] != document["database"]
        or prior["backup"] != document["backup"]
    ):
        raise CutoverError(
            "authority readiness re-attestation lineage is contradictory"
        )
    _authority_readiness_same_database(
        prior["database_identity_after"],
        document["database_identity_before"],
        label="authority readiness re-attestation lineage",
    )
    _authority_readiness_ready_descendant(
        prior["postcondition"],
        document["precondition"],
        label="authority readiness re-attestation lineage",
    )
    return {"intent": intent, "prior": prior}


def _authority_readiness_rebind_transaction(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_REBIND_TRANSACTION_KIND,
        fields=AUTHORITY_READINESS_REBIND_TRANSACTION_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness rebind transaction ID is invalid"
        ) from error
    for field in ("release", "database", "prior_attestation", "attestation"):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"authority readiness rebind transaction {field}",
            )
        )
    baseline = document["service_baseline"]
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"]))
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or not isinstance(baseline, Mapping)
        or set(baseline) != {"active", "enabled"}
        or baseline.get("active") is not True
        or type(baseline.get("enabled")) is not bool
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError(
            "authority readiness rebind transaction binding is invalid"
        )
    document["service_baseline"] = dict(baseline)
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    return document


def _authority_readiness_rebind_transaction_result(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_REBIND_TRANSACTION_RESULT_KIND,
        fields=AUTHORITY_READINESS_REBIND_TRANSACTION_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness rebind result ID is invalid"
        ) from error
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "authority readiness rebind result database",
        )
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}",
            str(document["transaction_journal_sha256"]),
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["readiness_rebind_sha256"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["release_digest"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError("authority readiness rebind result is invalid")
    return document


def _atomic_first_adoption_post_start_readiness(
    value: object,
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != ATOMIC_FIRST_ADOPTION_POST_START_READINESS_FIELDS
    ):
        raise CutoverError(
            "atomic first-adoption post-start readiness fields are invalid"
        )
    document = dict(value)
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "atomic first-adoption bridge operation ID is invalid"
        ) from error
    if operation_id != document["operation_id"]:
        raise CutoverError(
            "atomic first-adoption bridge operation ID is not canonical"
        )
    for field in ("journal_sha256", "journal_document_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(document[field])) is None:
            raise CutoverError(
                "atomic first-adoption bridge journal digest is invalid"
            )
    for field in (
        "transaction",
        "profile",
        "socket",
        "dropin",
        "canary_project",
        "proof_attestation",
    ):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"atomic first-adoption post-start {field}",
            )
        )
    if (
        not isinstance(document["canary_user"], str)
        or not document["canary_user"]
        or len(str(document["canary_user"])) > 256
        or isinstance(document["canary_owner_uid"], bool)
        or not isinstance(document["canary_owner_uid"], int)
        or int(document["canary_owner_uid"]) <= 0
        or not isinstance(document["canary_repository_id"], str)
        or not document["canary_repository_id"]
        or len(str(document["canary_repository_id"])) > 256
        or isinstance(document["canary_repository_generation"], bool)
        or not isinstance(document["canary_repository_generation"], int)
        or int(document["canary_repository_generation"]) < 0
    ):
        raise CutoverError(
            "atomic first-adoption bridge canary user is invalid"
        )
    return document


def _atomic_first_adoption_binding_transaction(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=ATOMIC_FIRST_ADOPTION_BINDING_TRANSACTION_KIND,
        fields=ATOMIC_FIRST_ADOPTION_BINDING_TRANSACTION_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "atomic first-adoption binding transaction ID is invalid"
        ) from error
    for field in (
        "release",
        "database",
        "prior_attestation",
        "readiness_attestation",
        "port_journal",
        "port_pending_attestation",
        "port_attestation",
        "finalization_journal",
        "transaction_attestation",
        "canonical_root",
    ):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"atomic first-adoption binding transaction {field}",
            )
        )
    baseline = document["service_baseline"]
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"]))
        is None
        or not isinstance(document["repository_id"], str)
        or not document["repository_id"]
        or isinstance(document["repository_generation"], bool)
        or not isinstance(document["repository_generation"], int)
        or int(document["repository_generation"]) < 0
        or isinstance(document["handoff_ttl_seconds"], bool)
        or not isinstance(document["handoff_ttl_seconds"], int)
        or not MIN_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
        <= int(document["handoff_ttl_seconds"])
        <= MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
        or document["service_unit"] != "devcoordinator-broker.service"
        or not isinstance(baseline, Mapping)
        or set(baseline) != {"active", "enabled"}
        or baseline.get("active") is not True
        or type(baseline.get("enabled")) is not bool
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError(
            "atomic first-adoption binding transaction is invalid"
        )
    if len(
        {
            document["prior_attestation"],
            document["readiness_attestation"],
            document["port_journal"],
            document["port_pending_attestation"],
            document["port_attestation"],
            document["finalization_journal"],
            document["transaction_attestation"],
        }
    ) != 7:
        raise CutoverError(
            "atomic first-adoption binding evidence paths must be distinct"
        )
    expected_pending = str(
        Path(str(document["port_attestation"])).with_name(
            "."
            + Path(str(document["port_attestation"])).name
            + "."
            + str(document["operation_id"])
            + ".pending"
        )
    )
    if document["port_pending_attestation"] != expected_pending:
        raise CutoverError(
            "atomic first-adoption pending port evidence path is invalid"
        )
    expected_finalizing = str(
        Path(str(document["transaction_attestation"])).with_name(
            "."
            + Path(str(document["transaction_attestation"])).name
            + "."
            + str(document["operation_id"])
            + ".finalizing"
        )
    )
    if document["finalization_journal"] != expected_finalizing:
        raise CutoverError(
            "atomic first-adoption finalization journal path is invalid"
        )
    document["service_baseline"] = dict(baseline)
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    document["post_start_readiness"] = (
        _atomic_first_adoption_post_start_readiness(
            document["post_start_readiness"]
        )
    )
    post_start = document["post_start_readiness"]
    if (
        post_start["proof_attestation"]
        in {
            document["prior_attestation"],
            document["readiness_attestation"],
            document["port_journal"],
            document["port_pending_attestation"],
            document["port_attestation"],
            document["finalization_journal"],
            document["transaction_attestation"],
        }
        or post_start["proof_attestation"]
        != str(
            Path(str(document["transaction_attestation"])).with_name(
                "."
                + Path(str(document["transaction_attestation"])).name
                + "."
                + str(document["operation_id"])
                + ".post-start-ready"
            )
        )
    ):
        raise CutoverError(
            "atomic first-adoption post-start proof path is invalid"
        )
    return document


def _atomic_first_adoption_binding_result(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
        fields=ATOMIC_FIRST_ADOPTION_BINDING_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "atomic first-adoption binding result ID is invalid"
        ) from error
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "atomic first-adoption binding result database",
        )
    )
    if (
        document["outcome"] not in {"completed", "aborted"}
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(document[field])) is None
            for field in (
                "transaction_journal_sha256",
                "release_digest",
            )
        )
        or (
            document["outcome"] == "completed"
            and re.fullmatch(
                r"[0-9a-f]{64}", str(document["readiness_rebind_sha256"])
            )
            is None
        )
        or (
            document["outcome"] == "aborted"
            and document["readiness_rebind_sha256"] is not None
            and re.fullmatch(
                r"[0-9a-f]{64}", str(document["readiness_rebind_sha256"])
            )
            is None
        )
        or (
            document["outcome"] == "completed"
            and re.fullmatch(
                r"[0-9a-f]{64}", str(document["port_reservations_sha256"])
            )
            is None
        )
        or (
            document["outcome"] == "aborted"
            and document["port_reservations_sha256"] is not None
        )
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError("atomic first-adoption binding result is invalid")
    return document


def _verify_atomic_first_adoption_terminal(
    result: object,
    *,
    transaction: Mapping[str, object],
    outcome: str,
    readiness_sha256: str | None,
    port_reservations_sha256: str | None,
) -> dict[str, object]:
    terminal = _atomic_first_adoption_binding_result(result)
    expected = {
        "operation_id": transaction["operation_id"],
        "outcome": outcome,
        "transaction_journal_sha256": transaction["document_sha256"],
        "readiness_rebind_sha256": readiness_sha256,
        "port_reservations_sha256": port_reservations_sha256,
        "release_digest": transaction["release_digest"],
        "database": transaction["database"],
        "service_unit": transaction["service_unit"],
        "service_restored": True,
        "maintenance_cleared": True,
    }
    if any(terminal[field] != value for field, value in expected.items()):
        raise CutoverError(
            "atomic first-adoption terminal result is contradictory"
        )
    return terminal


def _verify_atomic_post_start_proof_binding(
    proof: Mapping[str, object],
    *,
    transaction: Mapping[str, object],
    readiness: Mapping[str, object] | None,
) -> None:
    if readiness is None:
        raise CutoverError(
            "atomic first-adoption post-start proof requires readiness"
        )
    binding = transaction["post_start_readiness"]
    expected_generation = readiness["postcondition"]["metadata"][
        "database_generation"
    ]
    expected = {
        "operation_id": binding["operation_id"],
        "bridge_journal": str(
            Path(str(binding["transaction"])) / "bridge-journal.json"
        ),
        "bridge_journal_sha256": binding["journal_sha256"],
        "bridge_document_sha256": binding["journal_document_sha256"],
        "database": transaction["database"],
        "database_generation": expected_generation,
        "profile": binding["profile"],
        "broker_socket": binding["socket"],
        "dropin": binding["dropin"],
    }
    if any(proof.get(field) != value for field, value in expected.items()):
        raise CutoverError(
            "atomic first-adoption post-start proof binding changed"
        )
    canary = proof.get("canary")
    repository = canary.get("repository") if isinstance(canary, Mapping) else None
    authority = canary.get("authority") if isinstance(canary, Mapping) else None
    profile_repository = proof.get("profile_repository")
    if (
        not isinstance(canary, Mapping)
        or canary.get("user") != binding["canary_user"]
        or canary.get("uid") != binding["canary_owner_uid"]
        or canary.get("project") != binding["canary_project"]
        or not isinstance(repository, Mapping)
        or repository.get("repository_id")
        != binding["canary_repository_id"]
        or repository.get("canonical_root") != binding["canary_project"]
        or repository.get("generation")
        != binding["canary_repository_generation"]
        or not isinstance(authority, Mapping)
        or authority.get("database_generation") != expected_generation
        or authority.get("socket") != binding["socket"]
        or authority.get("service_uid") != 0
        or not isinstance(profile_repository, Mapping)
        or profile_repository.get("client_uid")
        != binding["canary_owner_uid"]
        or profile_repository.get("repository_id")
        != binding["canary_repository_id"]
        or profile_repository.get("canonical_root")
        != binding["canary_project"]
        or profile_repository.get("generation")
        != binding["canary_repository_generation"]
        or profile_repository.get("owner_uid")
        != binding["canary_owner_uid"]
    ):
        raise CutoverError(
            "atomic first-adoption post-start canary binding changed"
        )


def _verify_and_publish_atomic_post_start_readiness(
    *,
    transaction: Mapping[str, object],
    readiness: Mapping[str, object] | None,
    authority_uid: int,
    evidence_reader,
    evidence_publisher,
    require_existing_proof: bool,
    publish_if_missing: bool = True,
    verifier=None,
    proof_validator=None,
    evidence_replacer=None,
) -> dict[str, object]:
    """Live-probe the bridge every time; retained proof is lineage, not health."""

    binding = transaction["post_start_readiness"]
    proof_path = Path(str(binding["proof_attestation"]))
    module = None
    if verifier is None or proof_validator is None:
        module = _load_schema12_bridge_verifier()
    active_verifier = (
        module.verify_ready_bridge if verifier is None else verifier
    )
    active_validator = (
        module.verify_ready_bridge_proof
        if proof_validator is None
        else proof_validator
    )
    if readiness is None:
        raise CutoverError(
            "atomic first-adoption post-start readiness is unavailable"
        )
    try:
        live = active_validator(
            active_verifier(
                transaction=Path(str(binding["transaction"])),
                operation_id=str(binding["operation_id"]),
                expected_journal_sha256=str(binding["journal_sha256"]),
                expected_journal_document_sha256=str(
                    binding["journal_document_sha256"]
                ),
                database=Path(str(transaction["database"])),
                profile=Path(str(binding["profile"])),
                broker_socket=Path(str(binding["socket"])),
                dropin=Path(str(binding["dropin"])),
                expected_database_generation=str(
                    readiness["postcondition"]["metadata"][
                        "database_generation"
                    ]
                ),
                canary_user=str(binding["canary_user"]),
                expected_canary_uid=int(binding["canary_owner_uid"]),
                canary_project=Path(str(binding["canary_project"])),
                canary_repository_id=str(binding["canary_repository_id"]),
                canary_repository_generation=int(
                    binding["canary_repository_generation"]
                ),
                expected_uid=authority_uid,
            )
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise CutoverError(
            f"atomic first-adoption post-start readiness failed: {error}"
        ) from error
    if not isinstance(live, Mapping):
        raise CutoverError(
            "atomic first-adoption post-start verifier returned invalid evidence"
        )
    live = dict(live)
    _verify_atomic_post_start_proof_binding(
        live, transaction=transaction, readiness=readiness
    )
    if proof_path.exists() or proof_path.is_symlink():
        try:
            retained = active_validator(
                evidence_reader(proof_path, uid=authority_uid)
            )
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise CutoverError(
                f"atomic first-adoption retained post-start proof is invalid: {error}"
            ) from error
        if not isinstance(retained, Mapping):
            raise CutoverError(
                "atomic first-adoption retained post-start proof is invalid"
            )
        retained = dict(retained)
        _verify_atomic_post_start_proof_binding(
            retained, transaction=transaction, readiness=readiness
        )
        if retained != live:
            if evidence_replacer is None:
                _write_private_json(
                    proof_path,
                    live,
                    uid=authority_uid,
                    create=False,
                )
            else:
                evidence_replacer(
                    proof_path,
                    live,
                    uid=authority_uid,
                    create=False,
                )
    elif publish_if_missing:
        if require_existing_proof:
            raise CutoverError(
                "atomic first-adoption maintenance cleared without its readiness proof"
            )
        evidence_publisher(proof_path, live, uid=authority_uid)
    elif require_existing_proof:
        raise CutoverError(
            "atomic first-adoption post-start proof is required"
        )
    return live


def _atomic_first_adoption_finalization_intent(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND,
        fields=ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_FIELDS,
    )
    try:
        document["operation_id"] = str(
            uuid.UUID(str(document["operation_id"]))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "atomic first-adoption finalization intent ID is invalid"
        ) from error
    for field in (
        "transaction_journal_sha256",
        "prepared_attestation_sha256",
        "readiness_rebind_sha256",
        "state_document_sha256",
        "final_state_document_sha256",
    ):
        if re.fullmatch(r"[0-9a-f]{64}", str(document[field])) is None:
            raise CutoverError(
                "atomic first-adoption finalization intent digest is invalid"
            )
    document["state_path"] = str(
        _absolute(
            str(document["state_path"]),
            "atomic first-adoption finalization state",
        )
    )
    if (
        isinstance(document["state_generation"], bool)
        or not isinstance(document["state_generation"], int)
        or int(document["state_generation"]) < 0
        or isinstance(document["final_state_generation"], bool)
        or not isinstance(document["final_state_generation"], int)
        or document["final_state_generation"]
        != int(document["state_generation"]) + 1
        or not isinstance(document["state_updated_at"], str)
        or not document["state_updated_at"]
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError(
            "atomic first-adoption finalization intent is invalid"
        )
    document["authorized_snapshot"] = _authority_readiness_snapshot(
        document["authorized_snapshot"], required_state="ready"
    )
    document["final_port_reservations"] = (
        verify_first_adoption_port_reservations(
            document["final_port_reservations"]
        )
    )
    return document


def _prepare_authority_readiness_rebind(
    *,
    release: Path,
    database: Path,
    prior_attestation: Path,
    authority_uid: int,
    release_verifier,
    identity_reader,
    evidence_reader,
) -> dict[str, object]:
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
        or (
            release_verifier is None
            and release != IMMUTABLE_RELEASE_ROOT / release_digest
        )
    ):
        raise CutoverError("authority readiness rebind release is invalid")
    prior = _authority_readiness_result(
        evidence_reader(prior_attestation, uid=authority_uid)
    )
    current_identity = _authority_readiness_identity(
        identity_reader(database, uid=authority_uid),
        label="authority readiness rebind database",
    )
    current_snapshot = _read_authority_readiness_snapshot(database)
    if (
        prior["database"] != str(database)
        or prior["release_digest"] == release_digest
    ):
        raise CutoverError(
            "authority readiness rebind source binding is invalid"
        )
    current_identity = _authority_readiness_same_database(
        prior["database_identity_after"],
        current_identity,
        label="authority readiness rebind source",
    )
    current_snapshot = _authority_readiness_ready_descendant(
        prior["postcondition"],
        current_snapshot,
        label="authority readiness rebind source",
    )
    backup = _verify_authority_readiness_backup(
        database=database,
        backup=Path(str(prior["backup"]["path"])),
        backup_attestation=Path(str(prior["backup"]["attestation"])),
        authority_uid=authority_uid,
        expected_precondition=prior["precondition"],
        expected_identity=prior["database_identity_before"],
        evidence_reader=evidence_reader,
    )
    if backup != prior["backup"]:
        raise CutoverError("authority readiness retained backup changed")
    return {
        "release_digest": release_digest,
        "prior": prior,
        "database_identity": current_identity,
        "database_sha256": _file_digest(database),
        "snapshot": current_snapshot,
        "backup": backup,
    }


def _authority_readiness_lock_evidence(
    database: Path, yielded: object, *, authority_uid: int
) -> dict[str, object]:
    if isinstance(yielded, Mapping):
        evidence = _authority_readiness_writer_lock(yielded)
        if evidence["uid"] != authority_uid:
            raise CutoverError("authority readiness writer lock owner changed")
        return evidence
    path = database.parent / ".broker-service.lock"
    info = path.lstat()
    evidence = {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "acquired": True,
        "active_broker_excluded": True,
    }
    normalized = _authority_readiness_writer_lock(evidence)
    if normalized["uid"] != authority_uid:
        raise CutoverError("authority readiness writer lock owner changed")
    return normalized


def _normalize_maintenance_state(
    state: object, *, root: Path, gid: int, deployment_id: str
) -> dict[str, object]:
    if state is None:
        raise CutoverError("authority readiness requires active maintenance")
    if isinstance(state, Mapping):
        source = state
        get = source.get
    else:
        get = lambda field: getattr(state, field, None)
    document = _authority_readiness_maintenance(
        {
            "root": str(root),
            "gid": gid,
            "deployment_id": get("deployment_id"),
            "message": get("message"),
            "retry_after_seconds": get("retry_after_seconds"),
            "started_at": get("started_at"),
        }
    )
    if document["deployment_id"] != deployment_id:
        raise CutoverError("authority readiness maintenance deployment changed")
    return document


def _verify_authority_readiness_backup(
    *,
    database: Path,
    backup: Path,
    backup_attestation: Path,
    authority_uid: int,
    expected_precondition: Mapping[str, object],
    expected_identity: Mapping[str, int],
    evidence_reader,
) -> dict[str, object]:
    document = verify_seal(
        evidence_reader(backup_attestation, uid=authority_uid),
        kind=BACKUP_KIND,
        fields=BACKUP_FIELDS,
    )
    if (
        document["database"] != str(database)
        or document["backup"] != str(backup)
        or document["expected_uid"] != authority_uid
        or document["database_device"] != expected_identity["device"]
        or document["database_inode"] != expected_identity["inode"]
        or document["quick_check"] != "ok"
        or document["foreign_key_violations"] != 0
        or not backup.is_file()
        or backup.is_symlink()
        or backup.stat().st_size != document["backup_bytes"]
        or _file_digest(backup) != document["backup_sha256"]
    ):
        raise CutoverError("authority readiness backup evidence is contradictory")
    backup_snapshot = _read_authority_readiness_snapshot(backup)
    if backup_snapshot != dict(expected_precondition):
        raise CutoverError("authority readiness backup does not preserve exact pre-state")
    return _authority_readiness_backup(
        {
            "path": str(backup),
            "attestation": str(backup_attestation),
            "attestation_sha256": document["document_sha256"],
            "backup_sha256": document["backup_sha256"],
            "backup_bytes": document["backup_bytes"],
            "database_device": document["database_device"],
            "database_inode": document["database_inode"],
        }
    )


def finalize_authority_readiness(
    *,
    release: Path,
    database: Path,
    backup: Path,
    backup_attestation: Path,
    journal: Path,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    reserve_bytes: int = DEFAULT_RESERVE_BYTES,
    authority_uid: int = 0,
    release_verifier=None,
    maintenance_state_reader=load_maintenance_state,
    broker_lock_factory=exclusive_broker_service_lock,
    backup_producer=backup_database,
    identity_reader=_database_identity,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    failpoint=None,
) -> dict[str, object]:
    """Journal and perform the sole schema-12 ``empty`` to ``ready`` repair."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("authority readiness recovery must run as root")
    if isinstance(reserve_bytes, bool) or not isinstance(reserve_bytes, int) or reserve_bytes < 0:
        raise CutoverError("authority readiness backup reserve is invalid")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(uuid.UUID(str(maintenance_deployment_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness operation identity is invalid") from error
    release = _absolute(release, "authority readiness release")
    database = _absolute(database, "authority readiness database")
    backup = _absolute(backup, "authority readiness backup")
    backup_attestation = _absolute(
        backup_attestation, "authority readiness backup attestation"
    )
    journal = _absolute(journal, "authority readiness journal")
    attestation = _absolute(attestation, "authority readiness attestation")
    maintenance_root = _absolute(
        maintenance_root, "authority readiness maintenance root"
    )
    if len({backup, backup_attestation, journal, attestation}) != 4:
        raise CutoverError("authority readiness evidence paths must be distinct")
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
    ):
        raise CutoverError("authority readiness immutable release is invalid")
    if release_verifier is None and release != IMMUTABLE_RELEASE_ROOT / release_digest:
        raise CutoverError("authority readiness must execute from the exact immutable release")
    maintenance = _normalize_maintenance_state(
        maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        ),
        root=maintenance_root,
        gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
    )
    failpoint = (lambda _stage: None) if failpoint is None else failpoint

    with broker_lock_factory(database) as yielded_lock:
        writer_lock = _authority_readiness_lock_evidence(
            database, yielded_lock, authority_uid=authority_uid
        )
        identity_before = identity_reader(database, uid=authority_uid)
        identity_before = _authority_readiness_identity(
            identity_before, label="authority readiness database"
        )
        current = _read_authority_readiness_snapshot(database)
        intent: dict[str, object]
        if journal.exists() or journal.is_symlink():
            intent = _authority_readiness_intent(
                evidence_reader(journal, uid=authority_uid)
            )
            if (
                intent["operation_id"] != operation_id
                or intent["release"] != str(release)
                or intent["release_digest"] != release_digest
                or intent["database"] != str(database)
                or intent["maintenance"] != maintenance
                or intent["writer_lock"] != writer_lock
                or intent["database_identity"]["device"] != identity_before["device"]
                or intent["database_identity"]["inode"] != identity_before["inode"]
                or intent["backup"]["path"] != str(backup)
                or intent["backup"]["attestation"] != str(backup_attestation)
            ):
                raise CutoverError("authority readiness journal belongs to another operation")
            precondition = intent["precondition"]
            backup_binding = _verify_authority_readiness_backup(
                database=database,
                backup=backup,
                backup_attestation=backup_attestation,
                authority_uid=authority_uid,
                expected_precondition=precondition,
                expected_identity=intent["database_identity"],
                evidence_reader=evidence_reader,
            )
            if backup_binding != intent["backup"]:
                raise CutoverError("authority readiness backup changed after intent")
        else:
            precondition = _authority_readiness_snapshot(
                current, required_state="empty"
            )
            backup_producer(
                database=database,
                backup=backup,
                attestation=backup_attestation,
                expected_uid=authority_uid,
                reserve_bytes=reserve_bytes,
            )
            identity_after_backup = _authority_readiness_identity(
                identity_reader(database, uid=authority_uid),
                label="authority readiness database after backup",
            )
            if (
                identity_after_backup["device"] != identity_before["device"]
                or identity_after_backup["inode"] != identity_before["inode"]
                or _read_authority_readiness_snapshot(database) != precondition
            ):
                raise CutoverError("authority readiness source changed during backup")
            backup_binding = _verify_authority_readiness_backup(
                database=database,
                backup=backup,
                backup_attestation=backup_attestation,
                authority_uid=authority_uid,
                expected_precondition=precondition,
                expected_identity=identity_before,
                evidence_reader=evidence_reader,
            )
            timestamp = now_reader()
            target = {
                "schema_version": 12,
                "migration_state": "ready",
                "database_generation": precondition["metadata"]["database_generation"],
                "state_revision": int(precondition["metadata"]["state_revision"]) + 1,
                "updated_at": timestamp,
            }
            intent = seal(
                AUTHORITY_READINESS_INTENT_KIND,
                {
                    "operation_id": operation_id,
                    "release": str(release),
                    "release_digest": release_digest,
                    "database": str(database),
                    "database_identity": identity_before,
                    "maintenance": maintenance,
                    "writer_lock": writer_lock,
                    "backup": backup_binding,
                    "precondition": precondition,
                    "target": target,
                    "created_at": timestamp,
                },
            )
            _authority_readiness_intent(intent)
            evidence_publisher(journal, intent, uid=authority_uid)

        expected_post_metadata = dict(precondition["metadata"])
        expected_post_metadata.update(
            {
                "migration_state": "ready",
                "state_revision": intent["target"]["state_revision"],
                "updated_at": intent["target"]["updated_at"],
            }
        )
        expected_post = {
            "metadata": expected_post_metadata,
            "invariants": precondition["invariants"],
        }
        if attestation.exists() or attestation.is_symlink():
            result = _authority_readiness_result(
                evidence_reader(attestation, uid=authority_uid)
            )
            if (
                result["operation_id"] != operation_id
                or result["intent_sha256"] != intent["document_sha256"]
                or result["release"] != str(release)
                or result["release_digest"] != release_digest
                or result["database"] != str(database)
                or result["maintenance"] != maintenance
                or result["writer_lock"] != writer_lock
                or result["backup"] != intent["backup"]
                or result["precondition"] != precondition
                or result["postcondition"] != expected_post
                or current != expected_post
                or result["database_identity_after"]["device"]
                != identity_before["device"]
                or result["database_identity_after"]["inode"]
                != identity_before["inode"]
            ):
                raise CutoverError("authority readiness result is contradictory")
            return {
                "ok": True,
                "replayed": True,
                "attestation": result,
            }

        applied = False
        recovered = False
        if current == precondition:
            failpoint("after-intent")
            connection = sqlite3.connect(database, timeout=5.0, isolation_level=None)
            try:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                inside = _read_authority_readiness_snapshot(
                    database, connection=connection
                )
                if inside != precondition:
                    raise CutoverError("authority readiness precondition changed")
                changed = connection.execute(
                    """
                    UPDATE schema_metadata
                    SET migration_state='ready', state_revision=state_revision + 1,
                        updated_at=?
                    WHERE singleton=1 AND schema_version=12
                      AND migration_state='empty' AND database_generation=?
                      AND state_revision=?
                    """,
                    (
                        intent["target"]["updated_at"],
                        precondition["metadata"]["database_generation"],
                        precondition["metadata"]["state_revision"],
                    ),
                ).rowcount
                if changed != 1:
                    raise CutoverError("authority readiness exact mutation fence changed")
                connection.execute("COMMIT")
                applied = True
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            failpoint("after-commit")
        elif current == expected_post:
            recovered = True
        else:
            raise CutoverError("authority readiness database drifted from journal")

        postcondition = _read_authority_readiness_snapshot(database)
        if postcondition != expected_post:
            raise CutoverError("authority readiness post-state is invalid")
        identity_after = _authority_readiness_identity(
            identity_reader(database, uid=authority_uid),
            label="authority readiness database after mutation",
        )
        if (
            identity_after["device"] != identity_before["device"]
            or identity_after["inode"] != identity_before["inode"]
        ):
            raise CutoverError("authority readiness database identity changed")
        result = seal(
            AUTHORITY_READINESS_RESULT_KIND,
            {
                "operation_id": operation_id,
                "intent_sha256": intent["document_sha256"],
                "release": str(release),
                "release_digest": release_digest,
                "database": str(database),
                "database_identity_before": intent["database_identity"],
                "database_identity_after": identity_after,
                "maintenance": maintenance,
                "writer_lock": writer_lock,
                "backup": intent["backup"],
                "precondition": precondition,
                "postcondition": postcondition,
                "applied": applied,
                "recovered": recovered,
                "completed_at": now_reader(),
            },
        )
        result = _authority_readiness_result(result)
        evidence_publisher(attestation, result, uid=authority_uid)
        return {"ok": True, "replayed": False, "attestation": result}


def _authority_readiness_transaction(value: object) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_TRANSACTION_KIND,
        fields=AUTHORITY_READINESS_TRANSACTION_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness transaction operation ID is invalid") from error
    document["release"] = str(
        _absolute(str(document["release"]), "authority readiness transaction release")
    )
    document["database"] = str(
        _absolute(str(document["database"]), "authority readiness transaction database")
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError("authority readiness transaction binding is invalid")
    baseline = document["service_baseline"]
    if (
        not isinstance(baseline, Mapping)
        or set(baseline) != {"active", "enabled"}
        or baseline["active"] is not True
        or type(baseline["enabled"]) is not bool
    ):
        raise CutoverError("authority readiness requires the active legacy broker baseline")
    document["service_baseline"] = dict(baseline)
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    recovery = document["recovery"]
    recovery_fields = {
        "backup",
        "backup_attestation",
        "journal",
        "attestation",
        "reserve_bytes",
    }
    if not isinstance(recovery, Mapping) or set(recovery) != recovery_fields:
        raise CutoverError("authority readiness transaction recovery paths are invalid")
    normalized_recovery = {
        field: str(
            _absolute(
                str(recovery[field]), f"authority readiness transaction {field}"
            )
        )
        for field in ("backup", "backup_attestation", "journal", "attestation")
    }
    if (
        isinstance(recovery["reserve_bytes"], bool)
        or not isinstance(recovery["reserve_bytes"], int)
        or int(recovery["reserve_bytes"]) < 0
    ):
        raise CutoverError("authority readiness transaction reserve is invalid")
    normalized_recovery["reserve_bytes"] = int(recovery["reserve_bytes"])
    document["recovery"] = normalized_recovery
    return document


def _authority_readiness_transaction_result(value: object) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_READINESS_TRANSACTION_RESULT_KIND,
        fields=AUTHORITY_READINESS_TRANSACTION_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness transaction result operation ID is invalid") from error
    document["database"] = str(
        _absolute(str(document["database"]), "authority readiness transaction result database")
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["transaction_journal_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["authority_readiness_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError("authority readiness transaction result is invalid")
    return document


def _systemd_service_state(command_status, unit: str) -> dict[str, bool]:
    active_status = command_status(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit]
    )
    if active_status not in {0, 3}:
        raise CutoverError("legacy broker active state is not observable")
    enabled_status = command_status(
        ["/usr/bin/systemctl", "is-enabled", "--quiet", unit]
    )
    if enabled_status not in {0, 1}:
        raise CutoverError("legacy broker enabled state is not observable")
    return {"active": active_status == 0, "enabled": enabled_status == 0}


def _bounded_command_output(argv: list[str]) -> str:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise CutoverError("service observation command arguments are invalid")
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CutoverError("service observation command could not execute") from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > 8192
        or len(completed.stderr) > 8192
    ):
        raise CutoverError("service observation command failed")
    try:
        return completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise CutoverError("service observation output is invalid") from error


def _systemd_recovery_service_state(command_output, unit: str) -> dict[str, object]:
    output = command_output(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "--property=SubState",
            unit,
        ]
    )
    values: dict[str, str] = {}
    for raw_line in output.splitlines():
        if not raw_line or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        if key in values:
            raise CutoverError("broker service state contains duplicate fields")
        values[key] = value
    if (
        set(values) != {"LoadState", "UnitFileState", "ActiveState", "SubState"}
        or values["LoadState"] != "loaded"
        or values["UnitFileState"] != "enabled"
        or values["ActiveState"]
        not in {"active", "activating", "deactivating", "failed", "inactive"}
        or not values["SubState"]
        or len(values["SubState"].encode("utf-8")) > 128
    ):
        raise CutoverError("broker service state is not safely observable")
    return {
        "loaded": True,
        "enabled": True,
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
    }


def _validate_systemd_recovery_service_state(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"loaded", "enabled", "active_state", "sub_state"}
        or value["loaded"] is not True
        or value["enabled"] is not True
        or value["active_state"]
        not in {"active", "activating", "deactivating", "failed", "inactive"}
        or not isinstance(value["sub_state"], str)
        or not value["sub_state"]
        or len(value["sub_state"].encode("utf-8")) > 128
    ):
        raise CutoverError("broker recovery service state is invalid")
    return dict(value)


def _systemd_recovery_service_is_stopped(value: Mapping[str, object]) -> bool:
    return bool(value["active_state"] == "inactive" and value["sub_state"] == "dead")


def _systemd_recovery_service_is_healthy(value: Mapping[str, object]) -> bool:
    return bool(value["active_state"] == "active" and value["sub_state"] == "running")


def _shared_root_broker_service_state(
    command_output, unit: str, broker_socket: Path
) -> dict[str, object]:
    """Observe the exact broker process and socket boundary for this cutover."""

    output = command_output(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=InvocationID",
            unit,
        ]
    )
    values: dict[str, str] = {}
    for raw_line in output.splitlines():
        if not raw_line or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        if key in values:
            raise CutoverError(
                "shared-root broker service state contains duplicate fields"
            )
        values[key] = value
    if (
        set(values)
        != {
            "LoadState",
            "UnitFileState",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
        }
        or values["LoadState"] != "loaded"
        or values["UnitFileState"] != "enabled"
        or values["ActiveState"]
        not in {"active", "activating", "deactivating", "failed", "inactive"}
        or not values["SubState"]
        or re.fullmatch(r"0|[1-9][0-9]*", values["MainPID"]) is None
        or re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is None
    ):
        raise CutoverError("shared-root broker service state is not observable")
    socket_path = _absolute(broker_socket, "broker socket")
    try:
        socket_info = socket_path.lstat()
    except FileNotFoundError:
        socket_present = False
    else:
        if stat.S_ISLNK(socket_info.st_mode) or not stat.S_ISSOCK(socket_info.st_mode):
            raise CutoverError("shared-root broker socket has an unsafe identity")
        socket_present = True
    return {
        "loaded": True,
        "enabled": True,
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
        "main_pid": int(values["MainPID"]),
        "invocation_id": values["InvocationID"],
        "socket_present": socket_present,
    }


def _validate_shared_root_broker_service_state(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "loaded",
            "enabled",
            "active_state",
            "sub_state",
            "main_pid",
            "invocation_id",
            "socket_present",
        }
        or value["loaded"] is not True
        or value["enabled"] is not True
        or value["active_state"]
        not in {"active", "activating", "deactivating", "failed", "inactive"}
        or not isinstance(value["sub_state"], str)
        or not value["sub_state"]
        or type(value["main_pid"]) is not int
        or int(value["main_pid"]) < 0
        or not isinstance(value["invocation_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", value["invocation_id"]) is None
        or type(value["socket_present"]) is not bool
    ):
        raise CutoverError("shared-root broker service state is invalid")
    return dict(value)


def _shared_root_broker_is_stopped(value: Mapping[str, object]) -> bool:
    return bool(
        value["active_state"] == "inactive"
        and value["sub_state"] == "dead"
        and value["main_pid"] == 0
        and value["socket_present"] is False
    )


def _shared_root_broker_is_healthy(value: Mapping[str, object]) -> bool:
    return bool(
        value["active_state"] == "active"
        and value["sub_state"] == "running"
        and int(value["main_pid"]) > 0
        and value["socket_present"] is True
    )


def _verify_atomic_first_adoption_fence(
    prepared: object,
    *,
    authority_uid: int,
    command_status=_bounded_command_status,
    maintenance_state_reader=load_maintenance_state,
    effective_uid_reader=os.geteuid,
) -> dict[str, object]:
    evidence = verify_atomic_first_adoption_prepared(prepared)
    if authority_uid != 0 or effective_uid_reader() != authority_uid:
        raise CutoverError(
            "atomic first-adoption prepared evidence requires the authority UID"
        )
    maintenance = evidence["maintenance"]
    service = _systemd_service_state(command_status, str(evidence["service_unit"]))
    if service["active"]:
        raise CutoverError(
            "atomic first-adoption prepared evidence requires the stopped broker"
        )
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(maintenance["gid"]),
        maintenance_root=Path(str(maintenance["root"])),
    )
    normalized = _normalize_maintenance_state(
        marker,
        root=Path(str(maintenance["root"])),
        gid=int(maintenance["gid"]),
        deployment_id=str(maintenance["deployment_id"]),
    )
    if normalized != maintenance:
        raise CutoverError(
            "atomic first-adoption prepared maintenance fence changed"
        )
    return {"service": service, "maintenance": normalized}


def recover_authority_readiness(
    *,
    release: Path,
    database: Path,
    backup: Path,
    backup_attestation: Path,
    journal: Path,
    attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    reserve_bytes: int = DEFAULT_RESERVE_BYTES,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    finalizer=finalize_authority_readiness,
    finalizer_options: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Fence only the legacy broker around the readiness recovery primitive."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("authority readiness service transaction must run as root")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(uuid.UUID(str(maintenance_deployment_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("authority readiness transaction identity is invalid") from error
    release = _absolute(release, "authority readiness transaction release")
    database = _absolute(database, "authority readiness transaction database")
    backup = _absolute(backup, "authority readiness transaction backup")
    backup_attestation = _absolute(
        backup_attestation, "authority readiness transaction backup attestation"
    )
    journal = _absolute(journal, "authority readiness transaction mutation journal")
    attestation = _absolute(
        attestation, "authority readiness transaction mutation attestation"
    )
    transaction_journal = _absolute(
        transaction_journal, "authority readiness service journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation, "authority readiness service attestation"
    )
    maintenance_root = _absolute(
        maintenance_root, "authority readiness transaction maintenance root"
    )
    if len(
        {
            backup,
            backup_attestation,
            journal,
            attestation,
            transaction_journal,
            transaction_attestation,
        }
    ) != 6:
        raise CutoverError("authority readiness transaction paths must be distinct")
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
        or (release_verifier is None and release != IMMUTABLE_RELEASE_ROOT / release_digest)
    ):
        raise CutoverError("authority readiness service transaction release is invalid")
    unit = "devcoordinator-broker.service"
    started_at = now_reader()
    planned_maintenance = {
        "root": str(maintenance_root),
        "gid": maintenance_gid,
        "deployment_id": maintenance_deployment_id,
        "message": PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": 5,
        "started_at": started_at,
    }
    recovery = {
        "backup": str(backup),
        "backup_attestation": str(backup_attestation),
        "journal": str(journal),
        "attestation": str(attestation),
        "reserve_bytes": reserve_bytes,
    }
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _authority_readiness_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        if (
            transaction["operation_id"] != operation_id
            or transaction["release"] != str(release)
            or transaction["release_digest"] != release_digest
            or transaction["database"] != str(database)
            or transaction["maintenance"]["root"] != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"]
            != maintenance_deployment_id
            or transaction["recovery"] != recovery
        ):
            raise CutoverError("authority readiness service journal belongs to another operation")
    else:
        baseline = _systemd_service_state(command_status, unit)
        if baseline["active"] is not True:
            raise CutoverError("authority readiness requires the active legacy broker")
        transaction = seal(
            AUTHORITY_READINESS_TRANSACTION_KIND,
            {
                "operation_id": operation_id,
                "release": str(release),
                "release_digest": release_digest,
                "database": str(database),
                "service_unit": unit,
                "service_baseline": baseline,
                "maintenance": planned_maintenance,
                "recovery": recovery,
                "created_at": started_at,
            },
        )
        transaction = _authority_readiness_transaction(transaction)
        evidence_publisher(transaction_journal, transaction, uid=authority_uid)

    def completed_readiness() -> dict[str, object] | None:
        if not (attestation.exists() or attestation.is_symlink()):
            return None
        result = _authority_readiness_result(
            evidence_reader(attestation, uid=authority_uid)
        )
        if (
            result["operation_id"] != operation_id
            or result["release"] != str(release)
            or result["release_digest"] != release_digest
            or result["database"] != str(database)
            or result["postcondition"] != _read_authority_readiness_snapshot(database)
        ):
            raise CutoverError("authority readiness mutation result changed")
        return result

    readiness = completed_readiness()
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        result = _authority_readiness_transaction_result(
            evidence_reader(transaction_attestation, uid=authority_uid)
        )
        state = _systemd_service_state(command_status, unit)
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        if (
            readiness is None
            or result["operation_id"] != operation_id
            or result["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or result["authority_readiness_sha256"]
            != readiness["document_sha256"]
            or result["release_digest"] != release_digest
            or result["database"] != str(database)
            or state != transaction["service_baseline"]
            or marker is not None
        ):
            raise CutoverError("authority readiness service result is contradictory")
        return {"ok": True, "replayed": True, "attestation": result}

    if readiness is None:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(transaction["maintenance"]["started_at"]),
            maintenance_root=maintenance_root,
        )
        state = _systemd_service_state(command_status, unit)
        if state["enabled"] != transaction["service_baseline"]["enabled"]:
            raise CutoverError("legacy broker enabled state changed")
        if state["active"] and command_status(
            ["/usr/bin/systemctl", "stop", unit]
        ) != 0:
            raise CutoverError("legacy broker did not stop behind maintenance")
        if _systemd_service_state(command_status, unit)["active"]:
            raise CutoverError("legacy broker remains active behind maintenance")
        options = dict(finalizer_options or {})
        readiness_result = finalizer(
            release=release,
            database=database,
            backup=backup,
            backup_attestation=backup_attestation,
            journal=journal,
            attestation=attestation,
            maintenance_root=maintenance_root,
            maintenance_gid=maintenance_gid,
            maintenance_deployment_id=maintenance_deployment_id,
            operation_id=operation_id,
            reserve_bytes=reserve_bytes,
            authority_uid=authority_uid,
            release_verifier=release_verifier,
            maintenance_state_reader=maintenance_state_reader,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            effective_uid_reader=effective_uid_reader,
            now_reader=now_reader,
            **options,
        )
        readiness = _authority_readiness_result(readiness_result["attestation"])

    service_state = _systemd_service_state(command_status, unit)
    if service_state["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError("legacy broker enabled state changed during recovery")
    if not service_state["active"]:
        if command_status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise CutoverError("legacy broker did not restart after readiness recovery")
    if _systemd_service_state(command_status, unit) != transaction["service_baseline"]:
        raise CutoverError("legacy broker baseline was not restored")
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if marker is not None:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        if normalized != transaction["maintenance"]:
            raise CutoverError("authority readiness maintenance marker changed")
        maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            maintenance_root=maintenance_root,
        )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError("authority readiness maintenance marker did not clear")
    result = seal(
        AUTHORITY_READINESS_TRANSACTION_RESULT_KIND,
        {
            "operation_id": operation_id,
            "transaction_journal_sha256": transaction["document_sha256"],
            "authority_readiness_sha256": readiness["document_sha256"],
            "release_digest": release_digest,
            "database": str(database),
            "service_unit": unit,
            "service_restored": True,
            "maintenance_cleared": True,
            "completed_at": now_reader(),
        },
    )
    result = _authority_readiness_transaction_result(result)
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": result}


def rebind_authority_readiness(
    *,
    release: Path,
    database: Path,
    prior_attestation: Path,
    attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    broker_lock_factory=exclusive_broker_service_lock,
    identity_reader=_database_identity,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
) -> dict[str, object]:
    """Rebind an exact ready authority seal to a new immutable release."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("authority readiness rebind must run as root")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(
            uuid.UUID(str(maintenance_deployment_id))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness rebind identity is invalid"
        ) from error
    release = _absolute(release, "authority readiness rebind release")
    database = _absolute(database, "authority readiness rebind database")
    prior_attestation = _absolute(
        prior_attestation, "authority readiness prior attestation"
    )
    attestation = _absolute(
        attestation, "authority readiness rebind attestation"
    )
    transaction_journal = _absolute(
        transaction_journal, "authority readiness rebind service journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation,
        "authority readiness rebind service attestation",
    )
    maintenance_root = _absolute(
        maintenance_root, "authority readiness rebind maintenance root"
    )
    if len(
        {
            prior_attestation,
            attestation,
            transaction_journal,
            transaction_attestation,
        }
    ) != 4:
        raise CutoverError(
            "authority readiness rebind evidence paths must be distinct"
        )
    prepared = _prepare_authority_readiness_rebind(
        release=release,
        database=database,
        prior_attestation=prior_attestation,
        authority_uid=authority_uid,
        release_verifier=release_verifier,
        identity_reader=identity_reader,
        evidence_reader=evidence_reader,
    )
    release_digest = str(prepared["release_digest"])
    unit = "devcoordinator-broker.service"
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _authority_readiness_rebind_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        if (
            transaction["operation_id"] != operation_id
            or transaction["release"] != str(release)
            or transaction["release_digest"] != release_digest
            or transaction["database"] != str(database)
            or transaction["prior_attestation"] != str(prior_attestation)
            or transaction["attestation"] != str(attestation)
            or transaction["maintenance"]["root"]
            != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError(
                "authority readiness rebind journal belongs to another operation"
            )
    else:
        baseline = _systemd_service_state(command_status, unit)
        if baseline["active"] is not True:
            raise CutoverError(
                "authority readiness rebind requires the active legacy broker"
            )
        started_at = now_reader()
        transaction = seal(
            AUTHORITY_READINESS_REBIND_TRANSACTION_KIND,
            {
                "operation_id": operation_id,
                "release": str(release),
                "release_digest": release_digest,
                "database": str(database),
                "prior_attestation": str(prior_attestation),
                "attestation": str(attestation),
                "service_unit": unit,
                "service_baseline": baseline,
                "maintenance": {
                    "root": str(maintenance_root),
                    "gid": maintenance_gid,
                    "deployment_id": maintenance_deployment_id,
                    "message": PUBLIC_MAINTENANCE_MESSAGE,
                    "retry_after_seconds": 5,
                    "started_at": started_at,
                },
                "created_at": started_at,
            },
        )
        transaction = _authority_readiness_rebind_transaction(transaction)
        evidence_publisher(
            transaction_journal, transaction, uid=authority_uid
        )

    def completed_rebind() -> dict[str, object] | None:
        if not (attestation.exists() or attestation.is_symlink()):
            return None
        rebound = _authority_readiness_rebind_attestation(
            evidence_reader(attestation, uid=authority_uid)
        )
        if (
            rebound["operation_id"] != operation_id
            or rebound["prior_attestation"]
            != {
                "path": str(prior_attestation),
                "document_sha256": prepared["prior"]["document_sha256"],
            }
            or rebound["prior_release_digest"]
            != prepared["prior"]["release_digest"]
            or rebound["release"] != str(release)
            or rebound["release_digest"] != release_digest
            or rebound["database"] != str(database)
            or rebound["backup"] != prepared["backup"]
        ):
            raise CutoverError(
                "authority readiness rebind attestation is contradictory"
            )
        _authority_readiness_same_database(
            prepared["prior"]["database_identity_after"],
            rebound["database_identity"],
            label="authority readiness rebind attestation",
        )
        _authority_readiness_same_database(
            rebound["database_identity"],
            prepared["database_identity"],
            label="authority readiness rebind replay",
        )
        attested_snapshot = _authority_readiness_ready_descendant(
            prepared["prior"]["postcondition"],
            rebound["precondition"],
            label="authority readiness rebind attestation",
        )
        _authority_readiness_ready_descendant(
            attested_snapshot,
            prepared["snapshot"],
            label="authority readiness rebind replay",
        )
        return rebound

    rebound = completed_rebind()
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        result = _authority_readiness_rebind_transaction_result(
            evidence_reader(transaction_attestation, uid=authority_uid)
        )
        state = _systemd_service_state(command_status, unit)
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        if (
            rebound is None
            or result["operation_id"] != operation_id
            or result["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or result["readiness_rebind_sha256"]
            != rebound["document_sha256"]
            or result["release_digest"] != release_digest
            or result["database"] != str(database)
            or state != transaction["service_baseline"]
            or marker is not None
        ):
            raise CutoverError(
                "authority readiness rebind service result is contradictory"
            )
        return {"ok": True, "replayed": True, "attestation": result}

    if rebound is None:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(transaction["maintenance"]["started_at"]),
            maintenance_root=maintenance_root,
        )
        service_state = _systemd_service_state(command_status, unit)
        if service_state["enabled"] != transaction["service_baseline"]["enabled"]:
            raise CutoverError("legacy broker enabled state changed")
        if service_state["active"] and command_status(
            ["/usr/bin/systemctl", "stop", unit]
        ) != 0:
            raise CutoverError(
                "legacy broker did not stop for readiness rebind"
            )
        if _systemd_service_state(command_status, unit)["active"]:
            raise CutoverError(
                "legacy broker remains active during readiness rebind"
            )
        with broker_lock_factory(database) as yielded_lock:
            writer_lock = _authority_readiness_lock_evidence(
                database, yielded_lock, authority_uid=authority_uid
            )
            locked = _prepare_authority_readiness_rebind(
                release=release,
                database=database,
                prior_attestation=prior_attestation,
                authority_uid=authority_uid,
                release_verifier=release_verifier,
                identity_reader=identity_reader,
                evidence_reader=evidence_reader,
            )
            if (
                locked["release_digest"] != prepared["release_digest"]
                or locked["prior"] != prepared["prior"]
                or locked["backup"] != prepared["backup"]
            ):
                raise CutoverError(
                    "authority readiness rebind lineage changed while entering fence"
                )
            _authority_readiness_same_database(
                prepared["database_identity"],
                locked["database_identity"],
                label="authority readiness rebind fence",
            )
            _authority_readiness_ready_descendant(
                prepared["snapshot"],
                locked["snapshot"],
                label="authority readiness rebind fence",
            )
            rebound = seal(
                AUTHORITY_READINESS_REBIND_KIND,
                {
                    "operation_id": operation_id,
                    "prior_attestation": {
                        "path": str(prior_attestation),
                        "document_sha256": locked["prior"][
                            "document_sha256"
                        ],
                    },
                    "prior_release_digest": locked["prior"][
                        "release_digest"
                    ],
                    "release": str(release),
                    "release_digest": release_digest,
                    "database": str(database),
                    "database_identity": locked["database_identity"],
                    "database_sha256": locked["database_sha256"],
                    "writer_lock": writer_lock,
                    "backup": locked["backup"],
                    "precondition": locked["snapshot"],
                    "postcondition": locked["snapshot"],
                    "mutation_applied": False,
                    "created_at": now_reader(),
                },
            )
            rebound = _authority_readiness_rebind_attestation(rebound)
            evidence_publisher(attestation, rebound, uid=authority_uid)

    service_state = _systemd_service_state(command_status, unit)
    if service_state["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError(
            "legacy broker enabled state changed during readiness rebind"
        )
    if not service_state["active"] and command_status(
        ["/usr/bin/systemctl", "start", unit]
    ) != 0:
        raise CutoverError(
            "legacy broker did not restart after readiness rebind"
        )
    if _systemd_service_state(command_status, unit) != transaction["service_baseline"]:
        raise CutoverError("legacy broker baseline was not restored")
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if marker is not None:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        if normalized != transaction["maintenance"]:
            raise CutoverError(
                "authority readiness rebind maintenance marker changed"
            )
        maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            maintenance_root=maintenance_root,
        )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError(
            "authority readiness rebind maintenance marker did not clear"
        )
    if rebound is None:
        raise CutoverError("authority readiness rebind result is missing")
    result = seal(
        AUTHORITY_READINESS_REBIND_TRANSACTION_RESULT_KIND,
        {
            "operation_id": operation_id,
            "transaction_journal_sha256": transaction["document_sha256"],
            "readiness_rebind_sha256": rebound["document_sha256"],
            "release_digest": release_digest,
            "database": str(database),
            "service_unit": unit,
            "service_restored": True,
            "maintenance_cleared": True,
            "completed_at": now_reader(),
        },
    )
    result = _authority_readiness_rebind_transaction_result(result)
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": result}


def reattest_authority_readiness(
    *,
    release: Path,
    database: Path,
    prior_attestation: Path,
    quiescence_attestation: Path,
    quiescence_attestation_sha256: str,
    journal: Path,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_state_reader=load_maintenance_state,
    broker_lock_factory=exclusive_broker_service_lock,
    observation_reader=_immutable_authority_readiness_observation,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    failpoint=lambda _stage: None,
) -> dict[str, object]:
    """Re-attest a quiesced ready schema-12 authority without mutating it.

    The caller must first establish the atomic first-adoption prepared fence.
    This operation never activates maintenance, changes a service, or executes
    write SQL.  It only acquires the existing broker lifetime lock and writes
    its own root-private intent/result evidence.
    """

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError(
            "authority readiness re-attestation must run as root"
        )
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(
            uuid.UUID(str(maintenance_deployment_id))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority readiness re-attestation identity is invalid"
        ) from error
    if (
        re.fullmatch(r"[0-9a-f]{64}", quiescence_attestation_sha256)
        is None
    ):
        raise CutoverError(
            "authority readiness quiescence digest is invalid"
        )
    release = _absolute(
        release, "authority readiness re-attestation release"
    )
    database = _absolute(
        database, "authority readiness re-attestation database"
    )
    prior_attestation = _absolute(
        prior_attestation, "authority readiness prior attestation"
    )
    quiescence_attestation = _absolute(
        quiescence_attestation,
        "authority readiness quiescence attestation",
    )
    journal = _absolute(
        journal, "authority readiness re-attestation journal"
    )
    attestation = _absolute(
        attestation, "authority readiness re-attestation result"
    )
    maintenance_root = _absolute(
        maintenance_root,
        "authority readiness re-attestation maintenance root",
    )
    if len(
        {
            prior_attestation,
            quiescence_attestation,
            journal,
            attestation,
        }
    ) != 4:
        raise CutoverError(
            "authority readiness re-attestation evidence paths must be distinct"
        )
    verifier = (
        _load_release_verifier()
        if release_verifier is None
        else release_verifier
    )
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    capabilities = verified_release.get("capabilities")
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(capabilities, Mapping)
        or not capabilities
        or not all(value is True for value in capabilities.values())
        or (
            release_verifier is None
            and release != IMMUTABLE_RELEASE_ROOT / release_digest
        )
    ):
        raise CutoverError(
            "authority readiness re-attestation release is invalid"
        )
    prior = _authority_readiness_result(
        evidence_reader(prior_attestation, uid=authority_uid)
    )
    if (
        prior["database"] != str(database)
        or prior["release_digest"] == release_digest
    ):
        raise CutoverError(
            "authority readiness re-attestation source binding is invalid"
        )
    backup = _verify_authority_readiness_backup(
        database=database,
        backup=Path(str(prior["backup"]["path"])),
        backup_attestation=Path(str(prior["backup"]["attestation"])),
        authority_uid=authority_uid,
        expected_precondition=prior["precondition"],
        expected_identity=prior["database_identity_before"],
        evidence_reader=evidence_reader,
    )
    if backup != prior["backup"]:
        raise CutoverError(
            "authority readiness re-attestation backup changed"
        )

    def load_quiescence() -> dict[str, object]:
        prepared = verify_atomic_first_adoption_prepared(
            evidence_reader(quiescence_attestation, uid=authority_uid)
        )
        if (
            prepared["document_sha256"]
            != quiescence_attestation_sha256
            or prepared["operation_id"] != operation_id
            or prepared["release_digest"] != release_digest
            or prepared["authority_database"] != str(database)
            or prepared["maintenance"]["root"] != str(maintenance_root)
            or prepared["maintenance"]["gid"] != maintenance_gid
            or prepared["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError(
                "authority readiness quiescence evidence is contradictory"
            )
        expires_at = _parse_utc_timestamp(
            str(prepared["created_at"]),
            label="authority readiness quiescence creation time",
        ) + timedelta(seconds=int(prepared["handoff_ttl_seconds"]))
        current_time = _parse_utc_timestamp(
            now_reader(),
            label="authority readiness re-attestation time",
        )
        if (expires_at - current_time).total_seconds() < 300:
            raise CutoverError(
                "authority readiness quiescence evidence is stale"
            )
        _verify_atomic_first_adoption_fence(
            prepared,
            authority_uid=authority_uid,
            command_status=command_status,
            maintenance_state_reader=maintenance_state_reader,
            effective_uid_reader=effective_uid_reader,
        )
        return prepared

    prepared = load_quiescence()
    if (
        attestation.exists() or attestation.is_symlink()
    ) and not (journal.exists() or journal.is_symlink()):
        raise CutoverError(
            "authority readiness re-attestation result lacks its intent"
        )

    with broker_lock_factory(database) as yielded_lock:
        writer_lock = _authority_readiness_lock_evidence(
            database, yielded_lock, authority_uid=authority_uid
        )
        locked_prepared = load_quiescence()
        if locked_prepared != prepared:
            raise CutoverError(
                "authority readiness quiescence changed while entering lock"
            )
        observed = observation_reader(database, uid=authority_uid)
        identity = _authority_readiness_identity(
            observed.get("database_identity"),
            label="authority readiness re-attestation database",
        )
        database_sha256 = str(observed.get("database_sha256", ""))
        snapshot = _authority_readiness_snapshot(
            observed.get("snapshot"), required_state="ready"
        )
        if re.fullmatch(r"[0-9a-f]{64}", database_sha256) is None:
            raise CutoverError(
                "authority readiness re-attestation database digest is invalid"
            )
        _authority_readiness_same_database(
            prior["database_identity_after"],
            identity,
            label="authority readiness re-attestation source",
        )
        snapshot = _authority_readiness_ready_descendant(
            prior["postcondition"],
            snapshot,
            label="authority readiness re-attestation source",
        )
        if (
            snapshot["metadata"]["database_generation"]
            != prepared["authority_generation"]
            or snapshot["metadata"]["state_revision"]
            != prepared["authority_state_revision_after"]
        ):
            raise CutoverError(
                "authority readiness quiescence is stale"
            )
        reference = {
            "path": str(prior_attestation),
            "document_sha256": prior["document_sha256"],
        }
        quiescence_reference = {
            "path": str(quiescence_attestation),
            "document_sha256": prepared["document_sha256"],
            "kind": ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
        }
        intent_values = {
            "operation_id": operation_id,
            "prior_attestation": reference,
            "prior_release_digest": prior["release_digest"],
            "quiescence_attestation": quiescence_reference,
            "release": str(release),
            "release_digest": release_digest,
            "database": str(database),
            "database_identity": identity,
            "database_sha256": database_sha256,
            "service_unit": prepared["service_unit"],
            "service_stopped": True,
            "maintenance": prepared["maintenance"],
            "writer_lock": writer_lock,
            "backup": backup,
            "precondition": snapshot,
        }
        if journal.exists() or journal.is_symlink():
            intent = _authority_readiness_reattest_intent(
                evidence_reader(journal, uid=authority_uid)
            )
            expected = {
                **intent_values,
                "created_at": intent["created_at"],
            }
            if any(intent[field] != value for field, value in expected.items()):
                raise CutoverError(
                    "authority readiness re-attestation intent is stale or contradictory"
                )
        else:
            intent = _authority_readiness_reattest_intent(
                seal(
                    AUTHORITY_READINESS_REATTEST_INTENT_KIND,
                    {**intent_values, "created_at": now_reader()},
                )
            )
            evidence_publisher(journal, intent, uid=authority_uid)
        failpoint("after-intent")

        second_prepared = load_quiescence()
        second_observed = observation_reader(database, uid=authority_uid)
        second_identity = _authority_readiness_identity(
            second_observed.get("database_identity"),
            label="authority readiness re-attestation database after intent",
        )
        second_sha256 = str(second_observed.get("database_sha256", ""))
        second_snapshot = _authority_readiness_snapshot(
            second_observed.get("snapshot"), required_state="ready"
        )
        if (
            second_prepared != prepared
            or second_identity != intent["database_identity"]
            or second_sha256 != intent["database_sha256"]
            or second_snapshot != intent["precondition"]
        ):
            raise CutoverError(
                "authority readiness source changed after intent publication"
            )
        result_values = {
            "operation_id": operation_id,
            "intent": {
                "path": str(journal),
                "document_sha256": intent["document_sha256"],
            },
            "prior_attestation": reference,
            "prior_release_digest": prior["release_digest"],
            "quiescence_attestation": quiescence_reference,
            "release": str(release),
            "release_digest": release_digest,
            "database": str(database),
            "database_identity_before": identity,
            "database_identity_after": second_identity,
            "database_sha256": second_sha256,
            "service_unit": prepared["service_unit"],
            "service_stopped": True,
            "maintenance": prepared["maintenance"],
            "writer_lock": writer_lock,
            "backup": backup,
            "precondition": snapshot,
            "postcondition": second_snapshot,
            "mutation_applied": False,
        }
        if attestation.exists() or attestation.is_symlink():
            result = _authority_readiness_reattest_attestation(
                evidence_reader(attestation, uid=authority_uid)
            )
            expected = {
                **result_values,
                "completed_at": result["completed_at"],
            }
            if any(result[field] != value for field, value in expected.items()):
                raise CutoverError(
                    "authority readiness re-attestation replay is contradictory"
                )
            replayed = True
        else:
            failpoint("before-result")
            result = _authority_readiness_reattest_attestation(
                seal(
                    AUTHORITY_READINESS_REATTEST_KIND,
                    {**result_values, "completed_at": now_reader()},
                )
            )
            evidence_publisher(attestation, result, uid=authority_uid)
            replayed = False
        failpoint("after-result")
        final_prepared = load_quiescence()
        final_observed = observation_reader(database, uid=authority_uid)
        if (
            final_prepared != prepared
            or final_observed.get("database_identity")
            != result["database_identity_after"]
            or final_observed.get("database_sha256")
            != result["database_sha256"]
            or final_observed.get("snapshot") != result["postcondition"]
        ):
            raise CutoverError(
                "authority readiness source changed after re-attestation"
            )
    return {"ok": True, "replayed": replayed, "attestation": result}


def _parse_utc_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CutoverError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CutoverError(f"{label} must be a UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise CutoverError(f"{label} must be a UTC timestamp")
    return parsed


def _first_adoption_port_agent(operation_id: str) -> str:
    return f"cutover:first-adoption:{operation_id}"


def _first_adoption_port_purpose(release_digest: str, role: str) -> str:
    return f"first-adoption:{release_digest}:{role}"


def _validate_first_adoption_port_common(
    document: Mapping[str, object],
) -> tuple[datetime, datetime]:
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("first-adoption port operation ID is invalid") from error
    if operation_id != document["operation_id"]:
        raise CutoverError("first-adoption port operation ID is not canonical")
    release_digest = document["release_digest"]
    authority_generation = document["authority_generation"]
    repository_id = document["repository_id"]
    if (
        not isinstance(release_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(authority_generation, str)
        or not authority_generation
        or len(authority_generation) > 256
        or any(ord(character) < 0x20 for character in authority_generation)
        or not isinstance(repository_id, str)
        or not repository_id
        or len(repository_id.encode("utf-8")) > 256
        or any(ord(character) < 0x20 for character in repository_id)
    ):
        raise CutoverError("first-adoption port authority binding is invalid")
    for field in (
        "authority_state_revision_before",
        "repository_generation",
        "handoff_ttl_seconds",
    ):
        value = document[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CutoverError(f"first-adoption port {field} is invalid")
    ttl = int(document["handoff_ttl_seconds"])
    if not (
        MIN_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
        <= ttl
        <= MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("first-adoption handoff TTL is out of range")
    if document["port_range"] != FIRST_ADOPTION_PORT_RANGE:
        raise CutoverError("first-adoption port range is invalid")
    database = _absolute(
        str(document["authority_database"]),
        "first-adoption port authority database",
    )
    canonical_root = _absolute(
        str(document["canonical_root"]),
        "first-adoption port canonical root",
    )
    if str(database) != document["authority_database"]:
        raise CutoverError("first-adoption authority database is not canonical")
    if str(canonical_root) != document["canonical_root"]:
        raise CutoverError("first-adoption repository root is not canonical")
    created_at = _parse_utc_timestamp(
        document["created_at"], label="first-adoption port creation time"
    )
    expected_expiry = created_at + timedelta(seconds=ttl)
    return created_at, expected_expiry


def verify_first_adoption_port_reservations(
    value: object,
) -> dict[str, object]:
    """Verify the exact sealed bundle consumed by renderers and activation."""

    document = verify_seal(
        value,
        kind=FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
        fields=FIRST_ADOPTION_PORT_RESERVATIONS_FIELDS,
    )
    created_at, expected_expiry = _validate_first_adoption_port_common(document)
    before = document["authority_state_revision_before"]
    after = document["authority_state_revision_after"]
    if (
        isinstance(after, bool)
        or not isinstance(after, int)
        or after != int(before) + 1
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["transaction_journal_sha256"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
    ):
        raise CutoverError("first-adoption port reservation result is invalid")
    completed_at = _parse_utc_timestamp(
        document["completed_at"], label="first-adoption port completion time"
    )
    if completed_at < created_at:
        raise CutoverError("first-adoption port completion precedes creation")
    reservations = document["reservations"]
    if not isinstance(reservations, Mapping) or set(reservations) != set(
        FIRST_ADOPTION_PORT_ROLES
    ):
        raise CutoverError("first-adoption reservation roles are invalid")
    normalized: dict[str, dict[str, object]] = {}
    ports: set[int] = set()
    handoff_expiry: str | None = None
    expected_agent = _first_adoption_port_agent(str(document["operation_id"]))
    for role in FIRST_ADOPTION_PORT_ROLES:
        reservation = reservations[role]
        fields = {"lease_id", "port", "agent", "purpose", "status", "expires_at"}
        if not isinstance(reservation, Mapping) or set(reservation) != fields:
            raise CutoverError(f"first-adoption {role} reservation fields are invalid")
        try:
            lease_id = str(uuid.UUID(str(reservation["lease_id"])))
        except (ValueError, TypeError, AttributeError) as error:
            raise CutoverError(
                f"first-adoption {role} lease ID is invalid"
            ) from error
        port = reservation["port"]
        if (
            lease_id != reservation["lease_id"]
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not FIRST_ADOPTION_PORT_RANGE["start"]
            <= port
            <= FIRST_ADOPTION_PORT_RANGE["end"]
            or port in ports
            or reservation["agent"] != expected_agent
            or reservation["purpose"]
            != _first_adoption_port_purpose(str(document["release_digest"]), role)
            or reservation["status"] != "active"
        ):
            raise CutoverError(f"first-adoption {role} reservation is invalid")
        ports.add(port)
        expires_at = reservation["expires_at"]
        if role in FIRST_ADOPTION_CONSOLE_PORT_ROLES:
            if expires_at is not None:
                raise CutoverError("first-adoption Console reservations must not expire")
        else:
            parsed_expiry = _parse_utc_timestamp(
                expires_at, label=f"first-adoption {role} expiry"
            )
            if parsed_expiry != expected_expiry:
                raise CutoverError("first-adoption handoff expiry does not match its TTL")
            if handoff_expiry is None:
                handoff_expiry = str(expires_at)
            elif handoff_expiry != expires_at:
                raise CutoverError("first-adoption handoff expiries differ")
        normalized[role] = dict(reservation)
    document["reservations"] = normalized
    return document


def verify_atomic_first_adoption_prepared(
    value: object,
) -> dict[str, object]:
    """Verify truthful, still-fenced readiness/port preparation evidence."""

    document = verify_seal(
        value,
        kind=ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
        fields=ATOMIC_FIRST_ADOPTION_PREPARED_FIELDS,
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["port_journal_sha256"]))
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(document["atomic_transaction_journal_sha256"]),
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_stopped"] is not True
    ):
        raise CutoverError("atomic first-adoption prepared binding is invalid")
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    compatible = verify_first_adoption_port_reservations(
        seal(
            FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            {
                "operation_id": document["operation_id"],
                "release_digest": document["release_digest"],
                "authority_database": document["authority_database"],
                "authority_generation": document["authority_generation"],
                "authority_state_revision_before": document[
                    "authority_state_revision_before"
                ],
                "authority_state_revision_after": document[
                    "authority_state_revision_after"
                ],
                "repository_id": document["repository_id"],
                "repository_generation": document["repository_generation"],
                "canonical_root": document["canonical_root"],
                "port_range": document["port_range"],
                "handoff_ttl_seconds": document["handoff_ttl_seconds"],
                "reservations": document["reservations"],
                "transaction_journal_sha256": document[
                    "port_journal_sha256"
                ],
                "service_unit": document["service_unit"],
                "service_restored": True,
                "maintenance_cleared": True,
                "created_at": document["created_at"],
                "completed_at": document["completed_at"],
            },
        )
    )
    document["reservations"] = compatible["reservations"]
    return document


def verify_first_adoption_port_evidence(
    value: object,
) -> dict[str, object]:
    if (
        isinstance(value, Mapping)
        and value.get("kind") == ATOMIC_FIRST_ADOPTION_PREPARED_KIND
    ):
        return verify_atomic_first_adoption_prepared(value)
    return verify_first_adoption_port_reservations(value)


def _prepared_binding_as_final_port_values(
    prepared: Mapping[str, object],
) -> dict[str, object]:
    verified = verify_atomic_first_adoption_prepared(prepared)
    return {
        "operation_id": verified["operation_id"],
        "release_digest": verified["release_digest"],
        "authority_database": verified["authority_database"],
        "authority_generation": verified["authority_generation"],
        "authority_state_revision_before": verified[
            "authority_state_revision_before"
        ],
        "authority_state_revision_after": verified[
            "authority_state_revision_after"
        ],
        "repository_id": verified["repository_id"],
        "repository_generation": verified["repository_generation"],
        "canonical_root": verified["canonical_root"],
        "port_range": verified["port_range"],
        "handoff_ttl_seconds": verified["handoff_ttl_seconds"],
        "reservations": verified["reservations"],
        "transaction_journal_sha256": verified["port_journal_sha256"],
        "service_unit": verified["service_unit"],
        "service_restored": True,
        "maintenance_cleared": True,
        "created_at": verified["created_at"],
        "completed_at": verified["completed_at"],
    }


def _first_adoption_port_reservation_intent(value: object) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=FIRST_ADOPTION_PORT_RESERVATION_INTENT_KIND,
        fields=FIRST_ADOPTION_PORT_RESERVATION_INTENT_FIELDS,
    )
    created_at, expected_expiry = _validate_first_adoption_port_common(document)
    del created_at
    document["release"] = str(
        _absolute(str(document["release"]), "first-adoption port release")
    )
    document["attestation"] = str(
        _absolute(
            str(document["attestation"]),
            "first-adoption port reservation attestation",
        )
    )
    if document["service_unit"] != "devcoordinator-broker.service":
        raise CutoverError("first-adoption port service unit is invalid")
    baseline = document["service_baseline"]
    if (
        not isinstance(baseline, Mapping)
        or set(baseline) != {"active", "enabled"}
        or baseline["active"] is not True
        or type(baseline["enabled"]) is not bool
    ):
        raise CutoverError("first-adoption ports require an active broker baseline")
    document["service_baseline"] = dict(baseline)
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    row_ids = document["row_ids"]
    purposes = document["purposes"]
    if (
        not isinstance(row_ids, Mapping)
        or set(row_ids) != set(FIRST_ADOPTION_PORT_ROLES)
        or not isinstance(purposes, Mapping)
        or set(purposes) != set(FIRST_ADOPTION_PORT_ROLES)
        or document["agent"]
        != _first_adoption_port_agent(str(document["operation_id"]))
    ):
        raise CutoverError("first-adoption port intent roles are invalid")
    normalized_ids: dict[str, dict[str, str]] = {}
    all_ids: set[str] = set()
    for role in FIRST_ADOPTION_PORT_ROLES:
        ids = row_ids[role]
        if not isinstance(ids, Mapping) or set(ids) != {"lease_id", "event_id"}:
            raise CutoverError("first-adoption port row identities are invalid")
        normalized_ids[role] = {}
        for field in ("lease_id", "event_id"):
            try:
                identifier = str(uuid.UUID(str(ids[field])))
            except (ValueError, TypeError, AttributeError) as error:
                raise CutoverError(
                    "first-adoption port row identity is invalid"
                ) from error
            if identifier != ids[field] or identifier in all_ids:
                raise CutoverError("first-adoption port row identities are ambiguous")
            all_ids.add(identifier)
            normalized_ids[role][field] = identifier
        if purposes[role] != _first_adoption_port_purpose(
            str(document["release_digest"]), role
        ):
            raise CutoverError("first-adoption port purpose is invalid")
    expiry = _parse_utc_timestamp(
        document["handoff_expires_at"],
        label="first-adoption handoff expiry",
    )
    if expiry != expected_expiry:
        raise CutoverError("first-adoption handoff intent expiry is invalid")
    document["row_ids"] = normalized_ids
    document["purposes"] = {role: str(purposes[role]) for role in FIRST_ADOPTION_PORT_ROLES}
    return document


def _first_adoption_authority_snapshot(
    connection: sqlite3.Connection,
    *,
    repository_id: str,
    allowed_schema_versions: frozenset[int] = frozenset({12}),
) -> tuple[dict[str, object], dict[str, object]]:
    required_columns = {
        "schema_metadata": {
            "schema_version",
            "database_generation",
            "state_revision",
            "authority_mode",
            "migration_state",
            "first_sqlite_mutation_at",
        },
        "hosts": {"host_id"},
        "repositories": {
            "repo_id",
            "host_id",
            "canonical_root",
            "generation",
            "state",
        },
        "repository_installations": {
            "repo_id",
            "status",
            "startup_fenced",
            "operation_id",
        },
        "port_assignments": {"host_id", "port", "status"},
        "leases": {
            "lease_id",
            "host_id",
            "repo_id",
            "server_definition_id",
            "source_id",
            "port",
            "owner",
            "agent",
            "purpose",
            "status",
            "expires_at",
            "process_fingerprint",
            "generation",
            "deactivated_at",
            "created_at",
            "updated_at",
        },
        "events": {
            "event_id",
            "repo_id",
            "source_id",
            "operation_id",
            "event_kind",
            "code",
            "message",
            "diagnostic_json",
            "occurred_at",
        },
    }
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if not set(required_columns).issubset(tables):
        raise CutoverError("first-adoption authority schema is incomplete")
    for table, required in required_columns.items():
        columns = {
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if not required.issubset(columns):
            raise CutoverError("first-adoption authority schema is incompatible")
    quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
    if quick_check != ["ok"] or connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchone() is not None:
        raise CutoverError("first-adoption authority database integrity failed")
    metadata_rows = connection.execute(
        """
        SELECT schema_version, database_generation, state_revision,
               authority_mode, migration_state, first_sqlite_mutation_at
        FROM schema_metadata WHERE singleton = 1
        """
    ).fetchall()
    if len(metadata_rows) != 1:
        raise CutoverError("first-adoption authority metadata is ambiguous")
    metadata_row = metadata_rows[0]
    metadata = {
        "schema_version": int(metadata_row[0]),
        "database_generation": str(metadata_row[1]),
        "state_revision": int(metadata_row[2]),
        "authority_mode": str(metadata_row[3]),
        "migration_state": str(metadata_row[4]),
        "first_sqlite_mutation_at": metadata_row[5],
    }
    if (
        metadata["schema_version"] not in allowed_schema_versions
        or metadata["authority_mode"] != "sqlite"
        or metadata["migration_state"] != "ready"
        or not metadata["database_generation"]
        or len(str(metadata["database_generation"])) > 256
        or metadata["state_revision"] < 0
        or not isinstance(metadata["first_sqlite_mutation_at"], str)
        or not metadata["first_sqlite_mutation_at"]
    ):
        raise CutoverError("first-adoption authority schema is not ready")
    rows = connection.execute(
        """
        SELECT r.repo_id, r.host_id, r.canonical_root, r.generation, r.state,
               i.status, i.startup_fenced, i.operation_id
        FROM repositories r
        JOIN repository_installations i ON i.repo_id = r.repo_id
        JOIN hosts h ON h.host_id = r.host_id
        WHERE r.repo_id = ?
        """,
        (repository_id,),
    ).fetchall()
    if len(rows) != 1:
        raise CutoverError("first-adoption repository identity is unavailable")
    row = rows[0]
    repository = {
        "repository_id": str(row[0]),
        "host_id": str(row[1]),
        "canonical_root": str(row[2]),
        "repository_generation": int(row[3]),
        "state": str(row[4]),
        "installation_status": str(row[5]),
        "startup_fenced": bool(row[6]),
        "installation_operation_id": row[7],
    }
    if (
        repository["state"] != "active"
        or repository["installation_status"] != "installed"
        or repository["startup_fenced"] is not False
        or repository["installation_operation_id"] is not None
    ):
        raise CutoverError("first-adoption repository is not active and unfenced")
    return metadata, repository


def _first_adoption_event_diagnostic(
    *, operation_id: str, role: str, lease_id: str, port: int
) -> str:
    return _canonical(
        {
            "lease_id": lease_id,
            "operation_id": operation_id,
            "port": port,
            "role": role,
        }
    ).decode("utf-8")


def _verify_first_adoption_rows_in_connection(
    connection: sqlite3.Connection,
    bundle: Mapping[str, object],
    *,
    allowed_schema_versions: frozenset[int] = frozenset({12}),
    expected_authority_generation: str | None = None,
    minimum_state_revision: int | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    metadata, repository = _first_adoption_authority_snapshot(
        connection,
        repository_id=str(bundle["repository_id"]),
        allowed_schema_versions=allowed_schema_versions,
    )
    expected_generation = (
        str(bundle["authority_generation"])
        if expected_authority_generation is None
        else expected_authority_generation
    )
    required_revision = (
        int(bundle["authority_state_revision_after"])
        if minimum_state_revision is None
        else minimum_state_revision
    )
    if (
        metadata["database_generation"] != expected_generation
        or metadata["state_revision"] < required_revision
        or repository["repository_generation"] != bundle["repository_generation"]
        or repository["canonical_root"] != bundle["canonical_root"]
    ):
        raise CutoverError("first-adoption reservation authority binding changed")
    reservations = bundle["reservations"]
    if not isinstance(reservations, Mapping):
        raise CutoverError("first-adoption reservations are invalid")
    lease_ids = [str(reservations[role]["lease_id"]) for role in FIRST_ADOPTION_PORT_ROLES]
    placeholders = ",".join("?" for _ in lease_ids)
    rows = connection.execute(
        f"""
        SELECT lease_id, host_id, repo_id, server_definition_id, source_id,
               port, owner, agent, purpose, status, expires_at,
               process_fingerprint, generation, deactivated_at, created_at,
               updated_at
        FROM leases WHERE lease_id IN ({placeholders})
        """,
        lease_ids,
    ).fetchall()
    by_id = {str(row[0]): row for row in rows}
    if len(rows) != len(FIRST_ADOPTION_PORT_ROLES):
        raise CutoverError("first-adoption reservation rows are incomplete")
    ports: dict[str, int] = {}
    for role in FIRST_ADOPTION_PORT_ROLES:
        reservation = reservations[role]
        if not isinstance(reservation, Mapping):
            raise CutoverError("first-adoption reservation is invalid")
        row = by_id.get(str(reservation["lease_id"]))
        expected_expiry = reservation["expires_at"]
        if row is None or (
            str(row[1]) != repository["host_id"]
            or str(row[2]) != bundle["repository_id"]
            or row[3] is not None
            or row[4] is not None
            or int(row[5]) != reservation["port"]
            or row[6] is not None
            or row[7] != reservation["agent"]
            or row[8] != reservation["purpose"]
            or row[9] != "active"
            or row[10] != expected_expiry
            or row[11] is not None
            or int(row[12]) != 0
            or row[13] is not None
            or row[14] != bundle["created_at"]
            or row[15] != bundle["created_at"]
        ):
            raise CutoverError("first-adoption reservation row changed")
        ports[role] = int(row[5])
        expected_diagnostic = _first_adoption_event_diagnostic(
            operation_id=str(bundle["operation_id"]),
            role=role,
            lease_id=str(reservation["lease_id"]),
            port=int(reservation["port"]),
        )
        event_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE repo_id = ? AND source_id IS NULL AND operation_id IS NULL
                  AND event_kind = 'port.lease.created'
                  AND code = 'first_adoption_port_reserved'
                  AND message = ? AND diagnostic_json = ? AND occurred_at = ?
                """,
                (
                    bundle["repository_id"],
                    f"Reserved first-adoption port for {role}",
                    expected_diagnostic,
                    bundle["created_at"],
                ),
            ).fetchone()[0]
        )
        if event_count != 1:
            raise CutoverError("first-adoption reservation event is missing or ambiguous")
    assigned_collision = int(
        connection.execute(
            f"""
            SELECT COUNT(*) FROM port_assignments
            WHERE host_id = ? AND status = 'active'
              AND port IN ({','.join('?' for _ in ports)})
            """,
            (repository["host_id"], *ports.values()),
        ).fetchone()[0]
    )
    other_lease_collision = int(
        connection.execute(
            f"""
            SELECT COUNT(*) FROM leases
            WHERE host_id = ? AND status = 'active'
              AND port IN ({','.join('?' for _ in ports)})
              AND lease_id NOT IN ({placeholders})
            """,
            (repository["host_id"], *ports.values(), *lease_ids),
        ).fetchone()[0]
    )
    if assigned_collision or other_lease_collision:
        raise CutoverError("first-adoption reserved ports conflict with authority state")
    return metadata, {"repository": repository, "ports": ports}


def verify_first_adoption_port_reservation_rows(
    database: Path,
    bundle: object,
    *,
    authority_uid: int = 0,
    minimum_handoff_remaining_seconds: int = 0,
    now_epoch: float | None = None,
    effective_uid_reader=os.geteuid,
) -> dict[str, object]:
    """Verify that a sealed port bundle still has exact active authority rows."""

    if effective_uid_reader() != authority_uid:
        raise CutoverError("first-adoption port verification requires authority owner")
    if (
        isinstance(minimum_handoff_remaining_seconds, bool)
        or not isinstance(minimum_handoff_remaining_seconds, int)
        or minimum_handoff_remaining_seconds < 0
        or minimum_handoff_remaining_seconds
        > MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("minimum handoff remaining time is invalid")
    verified = verify_first_adoption_port_reservations(bundle)
    database = _absolute(database, "first-adoption authority database")
    if str(database) != verified["authority_database"]:
        raise CutoverError("first-adoption reservation database differs from bundle")
    _database_identity(database, uid=authority_uid)
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        metadata, evidence = _verify_first_adoption_rows_in_connection(
            connection, verified
        )
    if minimum_handoff_remaining_seconds:
        handoff = verified["reservations"]["handoff_api"]
        expiry = _parse_utc_timestamp(
            handoff["expires_at"], label="first-adoption handoff expiry"
        ).timestamp()
        current = time.time() if now_epoch is None else float(now_epoch)
        if expiry - current < minimum_handoff_remaining_seconds:
            raise CutoverError("first-adoption handoff reservations expire too soon")
    return {
        "ok": True,
        "authority_generation": metadata["database_generation"],
        "authority_state_revision": metadata["state_revision"],
        "repository_id": verified["repository_id"],
        "repository_generation": verified["repository_generation"],
        "ports": evidence["ports"],
        "minimum_handoff_remaining_seconds": minimum_handoff_remaining_seconds,
    }


def verify_first_adoption_port_reservation_rows_after_adoption(
    database: Path,
    bundle: object,
    adoption: object,
    *,
    authority_uid: int = 0,
    minimum_handoff_remaining_seconds: int = 0,
    now_epoch: float | None = None,
    effective_uid_reader=os.geteuid,
) -> dict[str, object]:
    """Verify copied reservation rows through the sealed storage-split proof."""

    if effective_uid_reader() != authority_uid:
        raise CutoverError(
            "post-adoption port verification requires authority owner"
        )
    if (
        isinstance(minimum_handoff_remaining_seconds, bool)
        or not isinstance(minimum_handoff_remaining_seconds, int)
        or minimum_handoff_remaining_seconds < 0
        or minimum_handoff_remaining_seconds
        > MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("minimum handoff remaining time is invalid")
    verified = verify_first_adoption_port_reservations(bundle)
    pointer = verify_seal(
        adoption,
        kind=FIRST_ADOPTION_AUTHORITY_ADOPTION_KIND,
        fields=FIRST_ADOPTION_AUTHORITY_ADOPTION_FIELDS,
    )
    database = _absolute(database, "post-adoption authority database")
    source = pointer.get("source")
    authority = pointer.get("authority")
    if (
        not isinstance(source, Mapping)
        or not isinstance(authority, Mapping)
        or pointer.get("release_digest") != verified["release_digest"]
        or pointer.get("legacy_source_original_path")
        != verified["authority_database"]
        or pointer.get("source_rotated") is not False
        or source.get("path") != verified["authority_database"]
        or authority.get("path") != str(database)
        or str(database) != FINAL_AUTHORITY_DATABASE_PATH
        or authority.get("schema_version") != 13
        or not isinstance(authority.get("database_generation"), str)
        or not authority.get("database_generation")
        or isinstance(authority.get("state_revision"), bool)
        or not isinstance(authority.get("state_revision"), int)
        or int(authority["state_revision"])
        < int(verified["authority_state_revision_after"])
    ):
        raise CutoverError(
            "post-adoption authority does not prove the reserved-row migration"
        )
    identity = _database_identity(database, uid=authority_uid)
    if (
        identity["device"] != authority.get("device")
        or identity["inode"] != authority.get("inode")
        or identity["size"] != authority.get("size")
        or _file_digest(database) != authority.get("sha256")
    ):
        raise CutoverError("post-adoption authority identity changed")
    with closing(
        sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        metadata, evidence = _verify_first_adoption_rows_in_connection(
            connection,
            verified,
            allowed_schema_versions=frozenset({13}),
            expected_authority_generation=str(
                authority["database_generation"]
            ),
            minimum_state_revision=int(authority["state_revision"]),
        )
    if minimum_handoff_remaining_seconds:
        handoff = verified["reservations"]["handoff_api"]
        expiry = _parse_utc_timestamp(
            handoff["expires_at"], label="first-adoption handoff expiry"
        ).timestamp()
        current = time.time() if now_epoch is None else float(now_epoch)
        if expiry - current < minimum_handoff_remaining_seconds:
            raise CutoverError(
                "first-adoption handoff reservations expire too soon"
            )
    return {
        "ok": True,
        "authority_generation": metadata["database_generation"],
        "authority_state_revision": metadata["state_revision"],
        "repository_id": verified["repository_id"],
        "repository_generation": verified["repository_generation"],
        "ports": evidence["ports"],
        "minimum_handoff_remaining_seconds": (
            minimum_handoff_remaining_seconds
        ),
        "source_authority_database": verified["authority_database"],
        "adoption_sha256": pointer["document_sha256"],
    }


def _build_first_adoption_port_bundle_values(
    *,
    intent: Mapping[str, object],
    ports: Mapping[str, int],
    completed_at: str,
) -> dict[str, object]:
    reservations: dict[str, dict[str, object]] = {}
    for role in FIRST_ADOPTION_PORT_ROLES:
        reservations[role] = {
            "lease_id": intent["row_ids"][role]["lease_id"],
            "port": int(ports[role]),
            "agent": intent["agent"],
            "purpose": intent["purposes"][role],
            "status": "active",
            "expires_at": (
                None
                if role in FIRST_ADOPTION_CONSOLE_PORT_ROLES
                else intent["handoff_expires_at"]
            ),
        }
    return {
        "operation_id": intent["operation_id"],
        "release_digest": intent["release_digest"],
        "authority_database": intent["authority_database"],
        "authority_generation": intent["authority_generation"],
        "authority_state_revision_before": intent[
            "authority_state_revision_before"
        ],
        "authority_state_revision_after": int(
            intent["authority_state_revision_before"]
        )
        + 1,
        "repository_id": intent["repository_id"],
        "repository_generation": intent["repository_generation"],
        "canonical_root": intent["canonical_root"],
        "port_range": dict(FIRST_ADOPTION_PORT_RANGE),
        "handoff_ttl_seconds": intent["handoff_ttl_seconds"],
        "reservations": reservations,
        "transaction_journal_sha256": intent["document_sha256"],
        "service_unit": intent["service_unit"],
        "service_restored": True,
        "maintenance_cleared": True,
        "created_at": intent["created_at"],
        "completed_at": completed_at,
    }


def _apply_first_adoption_port_reservations(
    *,
    intent: Mapping[str, object],
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    authority_uid: int,
    maintenance_state_reader,
    broker_lock_factory,
    port_selector,
    minimum_handoff_remaining_seconds: int = 0,
    now_epoch: float | None = None,
    before_commit_hook=None,
    after_commit_hook=None,
) -> tuple[dict[str, int], bool]:
    if (
        isinstance(minimum_handoff_remaining_seconds, bool)
        or not isinstance(minimum_handoff_remaining_seconds, int)
        or minimum_handoff_remaining_seconds < 0
        or minimum_handoff_remaining_seconds
        > MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("minimum handoff remaining time is invalid")
    if minimum_handoff_remaining_seconds:
        expiry = _parse_utc_timestamp(
            str(intent["handoff_expires_at"]),
            label="first-adoption handoff expiry",
        ).timestamp()
        current = time.time() if now_epoch is None else float(now_epoch)
        if expiry - current < minimum_handoff_remaining_seconds:
            raise CutoverError(
                "first-adoption handoff reservations expire too soon"
            )
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    normalized_marker = _normalize_maintenance_state(
        marker,
        root=maintenance_root,
        gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
    )
    if normalized_marker != intent["maintenance"]:
        raise CutoverError("first-adoption port maintenance binding changed")
    database = _absolute(
        str(intent["authority_database"]), "first-adoption authority database"
    )
    _database_identity(database, uid=authority_uid)
    lock_factory = broker_lock_factory or exclusive_broker_service_lock
    selector = port_selector
    if selector is None:
        selector = LocalBrokerHostMutations().select_available_port
    mutated = False
    ports: dict[str, int] = {}
    with lock_factory(database):
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            metadata, repository = _first_adoption_authority_snapshot(
                connection, repository_id=str(intent["repository_id"])
            )
            if (
                metadata["database_generation"] != intent["authority_generation"]
                or repository["repository_generation"]
                != intent["repository_generation"]
                or repository["canonical_root"] != intent["canonical_root"]
            ):
                raise CutoverError("first-adoption port intent authority binding changed")
            lease_ids = [
                str(intent["row_ids"][role]["lease_id"])
                for role in FIRST_ADOPTION_PORT_ROLES
            ]
            placeholders = ",".join("?" for _ in lease_ids)
            existing = connection.execute(
                f"SELECT lease_id, port FROM leases WHERE lease_id IN ({placeholders})",
                lease_ids,
            ).fetchall()
            if existing and len(existing) != len(FIRST_ADOPTION_PORT_ROLES):
                raise CutoverError("first-adoption port replay is partial")
            if not existing:
                if metadata["state_revision"] != intent[
                    "authority_state_revision_before"
                ]:
                    raise CutoverError("first-adoption port authority revision drifted")
                occupied = {
                    int(row[0])
                    for row in connection.execute(
                        """
                        SELECT port FROM port_assignments
                        WHERE host_id = ? AND status = 'active'
                        UNION
                        SELECT port FROM leases
                        WHERE host_id = ? AND status = 'active'
                        """,
                        (repository["host_id"], repository["host_id"]),
                    )
                }
                selected: set[int] = set()
                for role in FIRST_ADOPTION_PORT_ROLES:
                    candidates = tuple(
                        port
                        for port in range(
                            FIRST_ADOPTION_PORT_RANGE["start"],
                            FIRST_ADOPTION_PORT_RANGE["end"] + 1,
                        )
                        if port not in occupied and port not in selected
                    )
                    port = selector(candidates=candidates, protocol="tcp")
                    if (
                        isinstance(port, bool)
                        or not isinstance(port, int)
                        or port not in candidates
                    ):
                        raise CutoverError(
                            f"no Coordinator-verified port is available for {role}"
                        )
                    selected.add(port)
                    ports[role] = port
                created_at = str(intent["created_at"])
                for role in FIRST_ADOPTION_PORT_ROLES:
                    ids = intent["row_ids"][role]
                    expires_at = (
                        None
                        if role in FIRST_ADOPTION_CONSOLE_PORT_ROLES
                        else intent["handoff_expires_at"]
                    )
                    connection.execute(
                        """
                        INSERT INTO leases(
                            lease_id, host_id, repo_id, server_definition_id,
                            source_id, port, owner, agent, purpose, status,
                            expires_at, process_fingerprint, generation,
                            deactivated_at, created_at, updated_at
                        ) VALUES (?, ?, ?, NULL, NULL, ?, NULL, ?, ?, 'active',
                                  ?, NULL, 0, NULL, ?, ?)
                        """,
                        (
                            ids["lease_id"],
                            repository["host_id"],
                            intent["repository_id"],
                            ports[role],
                            intent["agent"],
                            intent["purposes"][role],
                            expires_at,
                            created_at,
                            created_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO events(
                            event_id, repo_id, source_id, operation_id,
                            event_kind, code, message, diagnostic_json,
                            occurred_at
                        ) VALUES (?, ?, NULL, NULL, 'port.lease.created',
                                  'first_adoption_port_reserved', ?, ?, ?)
                        """,
                        (
                            ids["event_id"],
                            intent["repository_id"],
                            f"Reserved first-adoption port for {role}",
                            _first_adoption_event_diagnostic(
                                operation_id=str(intent["operation_id"]),
                                role=role,
                                lease_id=str(ids["lease_id"]),
                                port=ports[role],
                            ),
                            created_at,
                        ),
                    )
                changed = connection.execute(
                    """
                    UPDATE schema_metadata
                    SET state_revision = state_revision + 1, updated_at = ?
                    WHERE singleton = 1 AND schema_version = 12
                      AND authority_mode = 'sqlite'
                      AND migration_state = 'ready'
                      AND database_generation = ? AND state_revision = ?
                    """,
                    (
                        created_at,
                        intent["authority_generation"],
                        intent["authority_state_revision_before"],
                    ),
                ).rowcount
                if changed != 1:
                    raise CutoverError(
                        "first-adoption port revision mutation was incomplete"
                    )
                provisional = seal(
                    FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    _build_first_adoption_port_bundle_values(
                        intent=intent,
                        ports=ports,
                        completed_at=created_at,
                    ),
                )
                _verify_first_adoption_rows_in_connection(connection, provisional)
                if before_commit_hook is not None:
                    before_commit_hook()
                connection.commit()
                mutated = True
                if after_commit_hook is not None:
                    after_commit_hook()
            else:
                if metadata["state_revision"] != int(
                    intent["authority_state_revision_before"]
                ) + 1:
                    raise CutoverError("first-adoption port replay revision is contradictory")
                by_id = {str(row[0]): int(row[1]) for row in existing}
                ports = {
                    role: by_id[str(intent["row_ids"][role]["lease_id"])]
                    for role in FIRST_ADOPTION_PORT_ROLES
                }
                provisional = seal(
                    FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    _build_first_adoption_port_bundle_values(
                        intent=intent,
                        ports=ports,
                        completed_at=str(intent["created_at"]),
                    ),
                )
                _verify_first_adoption_rows_in_connection(connection, provisional)
                connection.rollback()
        except BaseException:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
    return ports, mutated


def reserve_first_adoption_ports(
    *,
    release: Path,
    database: Path,
    project_root: Path,
    repository_id: str,
    repository_generation: int,
    handoff_ttl_seconds: int,
    journal: Path,
    attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    broker_lock_factory=None,
    port_selector=None,
    mutation_options: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Reserve all first-adoption listener ports in one fenced transaction."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("first-adoption port reservation must run as root")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(uuid.UUID(str(maintenance_deployment_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("first-adoption port transaction identity is invalid") from error
    if (
        isinstance(repository_generation, bool)
        or not isinstance(repository_generation, int)
        or repository_generation < 0
        or isinstance(handoff_ttl_seconds, bool)
        or not isinstance(handoff_ttl_seconds, int)
        or not MIN_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
        <= handoff_ttl_seconds
        <= MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("first-adoption port input is invalid")
    release = _absolute(release, "first-adoption port release")
    database = _absolute(database, "first-adoption authority database")
    project_root = _absolute(project_root, "first-adoption project root")
    journal = _absolute(journal, "first-adoption port intent journal")
    attestation = _absolute(attestation, "first-adoption port attestation")
    maintenance_root = _absolute(maintenance_root, "first-adoption maintenance root")
    if journal == attestation:
        raise CutoverError("first-adoption port journal and attestation must differ")
    _database_identity(database, uid=authority_uid)
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    capabilities = verified_release.get("capabilities")
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(capabilities, Mapping)
        or not capabilities
        or not all(value is True for value in capabilities.values())
        or (release_verifier is None and release != IMMUTABLE_RELEASE_ROOT / release_digest)
    ):
        raise CutoverError("first-adoption port release is invalid")
    unit = "devcoordinator-broker.service"
    planned_maintenance: dict[str, object]
    if journal.exists() or journal.is_symlink():
        intent = _first_adoption_port_reservation_intent(
            evidence_reader(journal, uid=authority_uid)
        )
        if (
            intent["operation_id"] != operation_id
            or intent["release"] != str(release)
            or intent["release_digest"] != release_digest
            or intent["authority_database"] != str(database)
            or intent["attestation"] != str(attestation)
            or intent["repository_id"] != repository_id
            or intent["repository_generation"] != repository_generation
            or intent["canonical_root"] != str(project_root)
            or intent["handoff_ttl_seconds"] != handoff_ttl_seconds
            or intent["maintenance"]["root"] != str(maintenance_root)
            or intent["maintenance"]["gid"] != maintenance_gid
            or intent["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError("first-adoption port journal belongs to another operation")
        planned_maintenance = dict(intent["maintenance"])
    else:
        with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            metadata, repository = _first_adoption_authority_snapshot(
                connection, repository_id=repository_id
            )
        if (
            repository["repository_generation"] != repository_generation
            or repository["canonical_root"] != str(project_root)
        ):
            raise CutoverError("first-adoption repository binding does not match")
        baseline = _systemd_service_state(command_status, unit)
        if baseline["active"] is not True:
            raise CutoverError("first-adoption ports require the active broker baseline")
        created_at = now_reader()
        created = _parse_utc_timestamp(
            created_at, label="first-adoption port creation time"
        )
        handoff_expires_at = (
            created + timedelta(seconds=handoff_ttl_seconds)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        planned_maintenance = {
            "root": str(maintenance_root),
            "gid": maintenance_gid,
            "deployment_id": maintenance_deployment_id,
            "message": PUBLIC_MAINTENANCE_MESSAGE,
            "retry_after_seconds": 5,
            "started_at": created_at,
        }
        intent = _first_adoption_port_reservation_intent(
            seal(
                FIRST_ADOPTION_PORT_RESERVATION_INTENT_KIND,
                {
                    "operation_id": operation_id,
                    "release": str(release),
                    "release_digest": release_digest,
                    "authority_database": str(database),
                    "attestation": str(attestation),
                    "authority_generation": metadata["database_generation"],
                    "authority_state_revision_before": metadata["state_revision"],
                    "repository_id": repository_id,
                    "repository_generation": repository_generation,
                    "canonical_root": str(project_root),
                    "port_range": dict(FIRST_ADOPTION_PORT_RANGE),
                    "handoff_ttl_seconds": handoff_ttl_seconds,
                    "handoff_expires_at": handoff_expires_at,
                    "row_ids": {
                        role: {
                            "lease_id": str(uuid.uuid4()),
                            "event_id": str(uuid.uuid4()),
                        }
                        for role in FIRST_ADOPTION_PORT_ROLES
                    },
                    "agent": _first_adoption_port_agent(operation_id),
                    "purposes": {
                        role: _first_adoption_port_purpose(release_digest, role)
                        for role in FIRST_ADOPTION_PORT_ROLES
                    },
                    "service_unit": unit,
                    "service_baseline": baseline,
                    "maintenance": planned_maintenance,
                    "created_at": created_at,
                },
            )
        )
        evidence_publisher(journal, intent, uid=authority_uid)

    if attestation.exists() or attestation.is_symlink():
        bundle = verify_first_adoption_port_reservations(
            evidence_reader(attestation, uid=authority_uid)
        )
        current_marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        if (
            bundle["operation_id"] != operation_id
            or bundle["transaction_journal_sha256"] != intent["document_sha256"]
            or bundle["release_digest"] != release_digest
            or bundle["authority_database"] != str(database)
            or bundle["repository_id"] != repository_id
            or _systemd_service_state(command_status, unit)
            != intent["service_baseline"]
            or current_marker is not None
        ):
            raise CutoverError("first-adoption port attestation is contradictory")
        verify_first_adoption_port_reservation_rows(
            database,
            bundle,
            authority_uid=authority_uid,
            effective_uid_reader=effective_uid_reader,
        )
        return {"ok": True, "replayed": True, "attestation": bundle}

    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if marker is None:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(planned_maintenance["started_at"]),
            maintenance_root=maintenance_root,
        )
    else:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        if normalized != planned_maintenance:
            raise CutoverError("first-adoption port maintenance marker changed")
    mutation_error: BaseException | None = None
    ports: dict[str, int] | None = None
    mutated = False
    try:
        state = _systemd_service_state(command_status, unit)
        if state["enabled"] != intent["service_baseline"]["enabled"]:
            raise CutoverError("first-adoption broker enabled state changed")
        if state["active"] and command_status(
            ["/usr/bin/systemctl", "stop", unit]
        ) != 0:
            raise CutoverError("first-adoption broker did not stop")
        if _systemd_service_state(command_status, unit)["active"]:
            raise CutoverError("first-adoption broker remains active")
        options = dict(mutation_options or {})
        ports, mutated = _apply_first_adoption_port_reservations(
            intent=intent,
            maintenance_root=maintenance_root,
            maintenance_gid=maintenance_gid,
            maintenance_deployment_id=maintenance_deployment_id,
            authority_uid=authority_uid,
            maintenance_state_reader=maintenance_state_reader,
            broker_lock_factory=broker_lock_factory,
            port_selector=port_selector,
            **options,
        )
    except BaseException as error:
        mutation_error = error
    service_state = _systemd_service_state(command_status, unit)
    if service_state["enabled"] != intent["service_baseline"]["enabled"]:
        raise CutoverError("first-adoption broker enabled state changed during restore")
    if not service_state["active"]:
        if command_status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise CutoverError("first-adoption broker did not restart")
    if _systemd_service_state(command_status, unit) != intent["service_baseline"]:
        raise CutoverError("first-adoption broker baseline was not restored")
    active_marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if active_marker is not None:
        normalized = _normalize_maintenance_state(
            active_marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        if normalized != planned_maintenance:
            raise CutoverError("first-adoption maintenance marker changed during restore")
        maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            maintenance_root=maintenance_root,
        )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError("first-adoption maintenance marker did not clear")
    if mutation_error is not None:
        raise mutation_error
    if ports is None:
        raise CutoverError("first-adoption port transaction produced no reservations")
    bundle = verify_first_adoption_port_reservations(
        seal(
            FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            _build_first_adoption_port_bundle_values(
                intent=intent,
                ports=ports,
                completed_at=now_reader(),
            ),
        )
    )
    verify_first_adoption_port_reservation_rows(
        database,
        bundle,
        authority_uid=authority_uid,
        effective_uid_reader=effective_uid_reader,
    )
    evidence_publisher(attestation, bundle, uid=authority_uid)
    return {"ok": True, "replayed": not mutated, "attestation": bundle}


def _atomic_binding_rebound(
    *,
    transaction: Mapping[str, object],
    prepared: Mapping[str, object],
    locked: Mapping[str, object],
    writer_lock: Mapping[str, object],
    readiness_attestation: Path,
    authority_uid: int,
    evidence_reader,
    evidence_publisher,
    now_reader,
) -> tuple[dict[str, object], bool]:
    if readiness_attestation.exists() or readiness_attestation.is_symlink():
        rebound = _authority_readiness_rebind_attestation(
            evidence_reader(readiness_attestation, uid=authority_uid)
        )
        if (
            rebound["operation_id"] != transaction["operation_id"]
            or rebound["prior_attestation"]
            != {
                "path": transaction["prior_attestation"],
                "document_sha256": prepared["prior"]["document_sha256"],
            }
            or rebound["prior_release_digest"]
            != prepared["prior"]["release_digest"]
            or rebound["release"] != transaction["release"]
            or rebound["release_digest"] != transaction["release_digest"]
            or rebound["database"] != transaction["database"]
            or rebound["backup"] != prepared["backup"]
        ):
            raise CutoverError(
                "atomic first-adoption readiness attestation is contradictory"
            )
        _authority_readiness_same_database(
            rebound["database_identity"],
            locked["database_identity"],
            label="atomic first-adoption readiness replay",
        )
        _authority_readiness_ready_descendant(
            rebound["postcondition"],
            locked["snapshot"],
            label="atomic first-adoption readiness replay",
        )
        return rebound, True
    if (
        locked["release_digest"] != prepared["release_digest"]
        or locked["prior"] != prepared["prior"]
        or locked["backup"] != prepared["backup"]
    ):
        raise CutoverError(
            "atomic first-adoption readiness lineage changed while entering fence"
        )
    _authority_readiness_same_database(
        prepared["database_identity"],
        locked["database_identity"],
        label="atomic first-adoption readiness fence",
    )
    _authority_readiness_ready_descendant(
        prepared["snapshot"],
        locked["snapshot"],
        label="atomic first-adoption readiness fence",
    )
    rebound = _authority_readiness_rebind_attestation(
        seal(
            AUTHORITY_READINESS_REBIND_KIND,
            {
                "operation_id": transaction["operation_id"],
                "prior_attestation": {
                    "path": transaction["prior_attestation"],
                    "document_sha256": locked["prior"]["document_sha256"],
                },
                "prior_release_digest": locked["prior"]["release_digest"],
                "release": transaction["release"],
                "release_digest": transaction["release_digest"],
                "database": transaction["database"],
                "database_identity": locked["database_identity"],
                "database_sha256": locked["database_sha256"],
                "writer_lock": writer_lock,
                "backup": locked["backup"],
                "precondition": locked["snapshot"],
                "postcondition": locked["snapshot"],
                "mutation_applied": False,
                "created_at": now_reader(),
            },
        )
    )
    evidence_publisher(readiness_attestation, rebound, uid=authority_uid)
    return rebound, False


def _atomic_binding_port_intent(
    *,
    transaction: Mapping[str, object],
    rebound: Mapping[str, object],
    port_journal: Path,
    authority_uid: int,
    evidence_reader,
    evidence_publisher,
) -> dict[str, object]:
    if port_journal.exists() or port_journal.is_symlink():
        intent = _first_adoption_port_reservation_intent(
            evidence_reader(port_journal, uid=authority_uid)
        )
        if (
            intent["operation_id"] != transaction["operation_id"]
            or intent["release"] != transaction["release"]
            or intent["release_digest"] != transaction["release_digest"]
            or intent["authority_database"] != transaction["database"]
            or intent["attestation"] != transaction["port_attestation"]
            or intent["repository_id"] != transaction["repository_id"]
            or intent["repository_generation"]
            != transaction["repository_generation"]
            or intent["canonical_root"] != transaction["canonical_root"]
            or intent["handoff_ttl_seconds"]
            != transaction["handoff_ttl_seconds"]
            or intent["authority_generation"]
            != rebound["postcondition"]["metadata"]["database_generation"]
            or intent["authority_state_revision_before"]
            != rebound["postcondition"]["metadata"]["state_revision"]
            or intent["service_baseline"] != transaction["service_baseline"]
            or intent["maintenance"] != transaction["maintenance"]
        ):
            raise CutoverError(
                "atomic first-adoption port journal is contradictory"
            )
        return intent
    database = Path(str(transaction["database"]))
    live = _read_authority_readiness_snapshot(database)
    if live != rebound["postcondition"]:
        raise CutoverError(
            "authority changed between atomic readiness and port intent"
        )
    with closing(
        sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        metadata, repository = _first_adoption_authority_snapshot(
            connection, repository_id=str(transaction["repository_id"])
        )
    if (
        metadata["database_generation"]
        != rebound["postcondition"]["metadata"]["database_generation"]
        or metadata["state_revision"]
        != rebound["postcondition"]["metadata"]["state_revision"]
        or repository["repository_generation"]
        != transaction["repository_generation"]
        or repository["canonical_root"] != transaction["canonical_root"]
    ):
        raise CutoverError(
            "atomic first-adoption repository binding changed inside fence"
        )
    created_at = str(transaction["created_at"])
    created = _parse_utc_timestamp(
        created_at, label="atomic first-adoption creation time"
    )
    expires = (
        created
        + timedelta(seconds=int(transaction["handoff_ttl_seconds"]))
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    intent = _first_adoption_port_reservation_intent(
        seal(
            FIRST_ADOPTION_PORT_RESERVATION_INTENT_KIND,
            {
                "operation_id": transaction["operation_id"],
                "release": transaction["release"],
                "release_digest": transaction["release_digest"],
                "authority_database": transaction["database"],
                "attestation": transaction["port_attestation"],
                "authority_generation": metadata["database_generation"],
                "authority_state_revision_before": metadata["state_revision"],
                "repository_id": transaction["repository_id"],
                "repository_generation": transaction["repository_generation"],
                "canonical_root": transaction["canonical_root"],
                "port_range": dict(FIRST_ADOPTION_PORT_RANGE),
                "handoff_ttl_seconds": transaction["handoff_ttl_seconds"],
                "handoff_expires_at": expires,
                "row_ids": {
                    role: {
                        "lease_id": str(uuid.uuid4()),
                        "event_id": str(uuid.uuid4()),
                    }
                    for role in FIRST_ADOPTION_PORT_ROLES
                },
                "agent": _first_adoption_port_agent(
                    str(transaction["operation_id"])
                ),
                "purposes": {
                    role: _first_adoption_port_purpose(
                        str(transaction["release_digest"]), role
                    )
                    for role in FIRST_ADOPTION_PORT_ROLES
                },
                "service_unit": transaction["service_unit"],
                "service_baseline": transaction["service_baseline"],
                "maintenance": transaction["maintenance"],
                "created_at": created_at,
            },
        )
    )
    evidence_publisher(port_journal, intent, uid=authority_uid)
    return intent


def _require_atomic_handoff_remaining(
    intent: Mapping[str, object],
    *,
    now: str,
    minimum_seconds: int = 300,
) -> None:
    expiry = _parse_utc_timestamp(
        str(intent["handoff_expires_at"]),
        label="atomic first-adoption handoff expiry",
    )
    current = _parse_utc_timestamp(
        str(now), label="atomic first-adoption current time"
    )
    if (expiry - current).total_seconds() < minimum_seconds:
        raise CutoverError(
            "atomic first-adoption handoff reservations expire too soon"
        )


def prepare_atomic_first_adoption_bindings(
    *,
    release: Path,
    database: Path,
    prior_attestation: Path,
    readiness_attestation: Path,
    project_root: Path,
    repository_id: str,
    repository_generation: int,
    handoff_ttl_seconds: int,
    port_journal: Path,
    prepared_attestation: Path,
    port_attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    bridge_transaction: Path,
    bridge_operation_id: str,
    bridge_journal_sha256: str,
    bridge_journal_document_sha256: str,
    bridge_profile: Path,
    bridge_socket: Path,
    bridge_dropin: Path,
    bridge_canary_user: str,
    bridge_canary_owner_uid: int,
    bridge_canary_project: Path,
    bridge_canary_repository_id: str,
    bridge_canary_repository_generation: int,
    post_start_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_activator=activate_maintenance,
    maintenance_state_reader=load_maintenance_state,
    broker_lock_factory=exclusive_broker_service_lock,
    identity_reader=_database_identity,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    post_start_verifier=None,
    post_start_proof_validator=None,
    post_start_evidence_replacer=None,
    now_reader=_now,
    port_selector=None,
    mutation_options: Mapping[str, object] | None = None,
    failpoint=lambda _stage: None,
) -> dict[str, object]:
    """Prepare release readiness and ports under one durable stopped-writer fence."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("atomic first-adoption preparation must run as root")
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(
            uuid.UUID(str(maintenance_deployment_id))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("atomic first-adoption identity is invalid") from error
    if (
        isinstance(repository_generation, bool)
        or not isinstance(repository_generation, int)
        or repository_generation < 0
        or isinstance(handoff_ttl_seconds, bool)
        or not isinstance(handoff_ttl_seconds, int)
        or not MIN_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
        <= handoff_ttl_seconds
        <= MAX_FIRST_ADOPTION_HANDOFF_TTL_SECONDS
    ):
        raise CutoverError("atomic first-adoption input is invalid")
    release = _absolute(release, "atomic first-adoption release")
    database = _absolute(database, "atomic first-adoption authority")
    prior_attestation = _absolute(
        prior_attestation, "atomic first-adoption prior readiness"
    )
    readiness_attestation = _absolute(
        readiness_attestation, "atomic first-adoption readiness"
    )
    project_root = _absolute(project_root, "atomic first-adoption project")
    port_journal = _absolute(port_journal, "atomic first-adoption port journal")
    prepared_attestation = _absolute(
        prepared_attestation, "atomic first-adoption prepared attestation"
    )
    port_attestation = _absolute(
        port_attestation, "atomic first-adoption final port attestation"
    )
    transaction_journal = _absolute(
        transaction_journal, "atomic first-adoption transaction journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation,
        "atomic first-adoption transaction attestation",
    )
    bridge_transaction = _absolute(
        bridge_transaction, "atomic first-adoption bridge transaction"
    )
    bridge_profile = _absolute(
        bridge_profile, "atomic first-adoption bridge profile"
    )
    bridge_socket = _absolute(
        bridge_socket, "atomic first-adoption bridge socket"
    )
    bridge_dropin = _absolute(
        bridge_dropin, "atomic first-adoption bridge drop-in"
    )
    bridge_canary_project = _absolute(
        bridge_canary_project, "atomic first-adoption bridge canary project"
    )
    post_start_attestation = _absolute(
        post_start_attestation,
        "atomic first-adoption post-start attestation",
    )
    maintenance_root = _absolute(
        maintenance_root, "atomic first-adoption maintenance root"
    )
    pending_expected = port_attestation.with_name(
        f".{port_attestation.name}.{operation_id}.pending"
    )
    if prepared_attestation != pending_expected:
        raise CutoverError(
            "prepared attestation must use the operation-bound pending path"
        )
    finalization_journal = transaction_attestation.with_name(
        f".{transaction_attestation.name}.{operation_id}.finalizing"
    )
    expected_post_start_attestation = transaction_attestation.with_name(
        f".{transaction_attestation.name}.{operation_id}.post-start-ready"
    )
    if post_start_attestation != expected_post_start_attestation:
        raise CutoverError(
            "atomic first-adoption post-start attestation path is invalid"
        )
    post_start_readiness = _atomic_first_adoption_post_start_readiness(
        {
            "transaction": str(bridge_transaction),
            "operation_id": bridge_operation_id,
            "journal_sha256": bridge_journal_sha256,
            "journal_document_sha256": bridge_journal_document_sha256,
            "profile": str(bridge_profile),
            "socket": str(bridge_socket),
            "dropin": str(bridge_dropin),
            "canary_user": bridge_canary_user,
            "canary_owner_uid": bridge_canary_owner_uid,
            "canary_project": str(bridge_canary_project),
            "canary_repository_id": bridge_canary_repository_id,
            "canary_repository_generation": (
                bridge_canary_repository_generation
            ),
            "proof_attestation": str(post_start_attestation),
        }
    )
    if len(
        {
            prior_attestation,
            readiness_attestation,
            port_journal,
            prepared_attestation,
            port_attestation,
            transaction_journal,
            transaction_attestation,
            finalization_journal,
            post_start_attestation,
        }
    ) != 9:
        raise CutoverError("atomic first-adoption evidence paths must be distinct")
    prepared_release = _prepare_authority_readiness_rebind(
        release=release,
        database=database,
        prior_attestation=prior_attestation,
        authority_uid=authority_uid,
        release_verifier=release_verifier,
        identity_reader=identity_reader,
        evidence_reader=evidence_reader,
    )
    release_digest = str(prepared_release["release_digest"])
    unit = "devcoordinator-broker.service"
    bridge_preflight_verified = False
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _atomic_first_adoption_binding_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        expected = {
            "operation_id": operation_id,
            "release": str(release),
            "release_digest": release_digest,
            "database": str(database),
            "prior_attestation": str(prior_attestation),
            "readiness_attestation": str(readiness_attestation),
            "port_journal": str(port_journal),
            "port_pending_attestation": str(prepared_attestation),
            "port_attestation": str(port_attestation),
            "finalization_journal": str(finalization_journal),
            "transaction_attestation": str(transaction_attestation),
            "repository_id": repository_id,
            "repository_generation": repository_generation,
            "canonical_root": str(project_root),
            "handoff_ttl_seconds": handoff_ttl_seconds,
            "post_start_readiness": post_start_readiness,
        }
        if any(transaction[key] != value for key, value in expected.items()):
            raise CutoverError(
                "atomic first-adoption journal belongs to another operation"
            )
        if (
            transaction["maintenance"]["root"] != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError(
                "atomic first-adoption maintenance binding changed"
            )
    else:
        with closing(
            sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
        ) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            _metadata, repository = _first_adoption_authority_snapshot(
                connection, repository_id=repository_id
            )
        if (
            repository["repository_generation"] != repository_generation
            or repository["canonical_root"] != str(project_root)
        ):
            raise CutoverError("atomic first-adoption repository binding differs")
        baseline = _systemd_service_state(command_status, unit)
        if not baseline["active"]:
            raise CutoverError(
                "atomic first-adoption preparation requires the active broker baseline"
            )
        _verify_and_publish_atomic_post_start_readiness(
            transaction={
                "database": str(database),
                "post_start_readiness": post_start_readiness,
            },
            readiness={"postcondition": prepared_release["snapshot"]},
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            require_existing_proof=False,
            publish_if_missing=False,
            verifier=post_start_verifier,
            proof_validator=post_start_proof_validator,
            evidence_replacer=post_start_evidence_replacer,
        )
        bridge_preflight_verified = True
        created_at = now_reader()
        transaction = _atomic_first_adoption_binding_transaction(
            seal(
                ATOMIC_FIRST_ADOPTION_BINDING_TRANSACTION_KIND,
                {
                    "operation_id": operation_id,
                    "release": str(release),
                    "release_digest": release_digest,
                    "database": str(database),
                    "prior_attestation": str(prior_attestation),
                    "readiness_attestation": str(readiness_attestation),
                    "port_journal": str(port_journal),
                    "port_pending_attestation": str(prepared_attestation),
                    "port_attestation": str(port_attestation),
                    "finalization_journal": str(finalization_journal),
                    "transaction_attestation": str(transaction_attestation),
                    "repository_id": repository_id,
                    "repository_generation": repository_generation,
                    "canonical_root": str(project_root),
                    "handoff_ttl_seconds": handoff_ttl_seconds,
                    "service_unit": unit,
                    "service_baseline": baseline,
                    "maintenance": {
                        "root": str(maintenance_root),
                        "gid": maintenance_gid,
                        "deployment_id": maintenance_deployment_id,
                        "message": PUBLIC_MAINTENANCE_MESSAGE,
                        "retry_after_seconds": 5,
                        "started_at": created_at,
                    },
                    "post_start_readiness": post_start_readiness,
                    "created_at": created_at,
                },
            )
        )
        evidence_publisher(transaction_journal, transaction, uid=authority_uid)
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        readiness = _authority_readiness_rebind_attestation(
            evidence_reader(readiness_attestation, uid=authority_uid)
        )
        final_ports = verify_first_adoption_port_reservations(
            evidence_reader(port_attestation, uid=authority_uid)
        )
        terminal = _verify_atomic_first_adoption_terminal(
            evidence_reader(transaction_attestation, uid=authority_uid),
            transaction=transaction,
            outcome="completed",
            readiness_sha256=str(readiness["document_sha256"]),
            port_reservations_sha256=str(final_ports["document_sha256"]),
        )
        service = _systemd_service_state(command_status, unit)
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        if (
            service != transaction["service_baseline"]
            or marker is not None
        ):
            raise CutoverError(
                "atomic first-adoption completed preparation is contradictory"
            )
        _verify_and_publish_atomic_post_start_readiness(
            transaction=transaction,
            readiness=readiness,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            require_existing_proof=True,
            verifier=post_start_verifier,
            proof_validator=post_start_proof_validator,
            evidence_replacer=post_start_evidence_replacer,
        )
        return {
            "ok": True,
            "replayed": True,
            "attestation": final_ports,
            "terminal_attestation": terminal,
        }
    if prepared_attestation.exists() or prepared_attestation.is_symlink():
        prepared_evidence = verify_atomic_first_adoption_prepared(
            evidence_reader(prepared_attestation, uid=authority_uid)
        )
        if (
            prepared_evidence["atomic_transaction_journal_sha256"]
            != transaction["document_sha256"]
        ):
            raise CutoverError("atomic first-adoption prepared evidence changed")
        _verify_atomic_first_adoption_fence(
            prepared_evidence,
            authority_uid=authority_uid,
            command_status=command_status,
            maintenance_state_reader=maintenance_state_reader,
            effective_uid_reader=effective_uid_reader,
        )
        verify_first_adoption_port_reservation_rows(
            database,
            seal(
                FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                _prepared_binding_as_final_port_values(prepared_evidence),
            ),
            authority_uid=authority_uid,
            minimum_handoff_remaining_seconds=300,
            now_epoch=_parse_utc_timestamp(
                now_reader(), label="atomic first-adoption replay time"
            ).timestamp(),
            effective_uid_reader=effective_uid_reader,
        )
        return {"ok": True, "replayed": True, "attestation": prepared_evidence}
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    service = _systemd_service_state(command_status, unit)
    if service["active"] and not bridge_preflight_verified:
        _verify_and_publish_atomic_post_start_readiness(
            transaction=transaction,
            readiness={"postcondition": prepared_release["snapshot"]},
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            require_existing_proof=False,
            publish_if_missing=False,
            verifier=post_start_verifier,
            proof_validator=post_start_proof_validator,
            evidence_replacer=post_start_evidence_replacer,
        )
    if marker is None:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(transaction["maintenance"]["started_at"]),
            maintenance_root=maintenance_root,
        )
    elif _normalize_maintenance_state(
        marker,
        root=maintenance_root,
        gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
    ) != transaction["maintenance"]:
        raise CutoverError("atomic first-adoption maintenance marker changed")
    failpoint("after-marker")
    service = _systemd_service_state(command_status, unit)
    if service["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError("atomic first-adoption broker enabled state changed")
    if service["active"] and command_status(["/usr/bin/systemctl", "stop", unit]) != 0:
        raise CutoverError("atomic first-adoption broker did not stop")
    if _systemd_service_state(command_status, unit)["active"]:
        raise CutoverError("atomic first-adoption broker remains active")
    failpoint("after-stop")
    with broker_lock_factory(database) as yielded_lock:
        writer_lock = _authority_readiness_lock_evidence(
            database, yielded_lock, authority_uid=authority_uid
        )
        locked = _prepare_authority_readiness_rebind(
            release=release,
            database=database,
            prior_attestation=prior_attestation,
            authority_uid=authority_uid,
            release_verifier=release_verifier,
            identity_reader=identity_reader,
            evidence_reader=evidence_reader,
        )
        rebound, _ = _atomic_binding_rebound(
            transaction=transaction,
            prepared=prepared_release,
            locked=locked,
            writer_lock=writer_lock,
            readiness_attestation=readiness_attestation,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            now_reader=now_reader,
        )
        failpoint("after-readiness")
        intent = _atomic_binding_port_intent(
            transaction=transaction,
            rebound=rebound,
            port_journal=port_journal,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
        )
        failpoint("after-intent")
        _require_atomic_handoff_remaining(intent, now=now_reader())

        @contextmanager
        def held_lock(_database: Path):
            yield writer_lock

        ports, _mutated = _apply_first_adoption_port_reservations(
            intent=intent,
            maintenance_root=maintenance_root,
            maintenance_gid=maintenance_gid,
            maintenance_deployment_id=maintenance_deployment_id,
            authority_uid=authority_uid,
            maintenance_state_reader=maintenance_state_reader,
            broker_lock_factory=held_lock,
            port_selector=port_selector,
            minimum_handoff_remaining_seconds=300,
            now_epoch=_parse_utc_timestamp(
                now_reader(), label="atomic first-adoption mutation time"
            ).timestamp(),
            **dict(mutation_options or {}),
        )
        failpoint("after-commit")
        _require_atomic_handoff_remaining(intent, now=now_reader())
        compatible_values = _build_first_adoption_port_bundle_values(
            intent=intent,
            ports=ports,
            completed_at=now_reader(),
        )
        prepared_evidence = verify_atomic_first_adoption_prepared(
            seal(
                ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
                {
                    **{
                        key: compatible_values[key]
                        for key in (
                            "operation_id",
                            "release_digest",
                            "authority_database",
                            "authority_generation",
                            "authority_state_revision_before",
                            "authority_state_revision_after",
                            "repository_id",
                            "repository_generation",
                            "canonical_root",
                            "port_range",
                            "handoff_ttl_seconds",
                            "reservations",
                            "service_unit",
                            "created_at",
                            "completed_at",
                        )
                    },
                    "port_journal_sha256": intent["document_sha256"],
                    "atomic_transaction_journal_sha256": transaction[
                        "document_sha256"
                    ],
                    "service_stopped": True,
                    "maintenance": transaction["maintenance"],
                },
            )
        )
        failpoint("before-prepared")
        evidence_publisher(
            prepared_attestation, prepared_evidence, uid=authority_uid
        )
    _verify_atomic_first_adoption_fence(
        prepared_evidence,
        authority_uid=authority_uid,
        command_status=command_status,
        maintenance_state_reader=maintenance_state_reader,
        effective_uid_reader=effective_uid_reader,
    )
    return {"ok": True, "replayed": False, "attestation": prepared_evidence}


def _first_adoption_binding_completion(
    state: Mapping[str, object],
) -> dict[str, object] | None:
    """Validate the only two ledger states accepted by binding finalization."""

    phase = state.get("phase")
    evidence = state.get("evidence")
    if not isinstance(evidence, Mapping):
        raise CutoverError(
            "atomic first-adoption finalization requires a valid cutover ledger"
        )
    migrated = evidence.get("migration-seal")
    discarded = evidence.get("test-history-discard")
    if phase == "planned" and migrated is None and discarded is None:
        return None
    if phase == "sealed" and migrated is None and discarded is not None:
        completion = _test_store_cutover_completion(state)
        if completion["mode"] == "history-discarded":
            return completion
    raise CutoverError(
        "atomic first-adoption finalization requires planned history or "
        "a sealed discarded Test Store"
    )


def _build_atomic_binding_final_state(
    *,
    current: Mapping[str, object],
    prepared: Mapping[str, object],
    final_ports: Mapping[str, object],
    updated_at: str,
) -> dict[str, object]:
    indexed = dict(current["evidence"])
    _first_adoption_binding_completion(current)
    if indexed.get("first-adoption-port-reservations") != prepared:
        raise CutoverError(
            "atomic first-adoption finalization requires the initialized prepared ledger"
        )
    indexed["first-adoption-port-reservations"] = dict(final_ports)
    unsigned = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned.update(
        {
            "evidence": indexed,
            "updated_at": updated_at,
            "state_generation": int(current["state_generation"]) + 1,
        }
    )
    updated = seal(STATE_KIND, unsigned)
    validate_state(updated)
    return updated


def _atomic_binding_state_with_final_ports(
    *,
    state_path: Path,
    prepared: Mapping[str, object],
    final_ports: Mapping[str, object],
    authority_uid: int,
    state_document_sha256: str,
    state_generation: int,
    final_state_document_sha256: str,
    state_updated_at: str,
) -> tuple[dict[str, object], bool]:
    current = load_state(state_path, authority_uid=authority_uid)
    existing = current["evidence"].get("first-adoption-port-reservations")
    if (
        existing == final_ports
        and current["document_sha256"] == final_state_document_sha256
        and current["state_generation"] == state_generation + 1
    ):
        return current, True
    if (
        current["document_sha256"] != state_document_sha256
        or current["state_generation"] != state_generation
        or existing != prepared
    ):
        raise CutoverError(
            "atomic first-adoption ledger changed after finalization was journaled"
        )
    updated = _build_atomic_binding_final_state(
        current=current,
        prepared=prepared,
        final_ports=final_ports,
        updated_at=state_updated_at,
    )
    if updated["document_sha256"] != final_state_document_sha256:
        raise CutoverError(
            "atomic first-adoption final ledger digest changed"
        )
    _write_private_json(
        state_path,
        updated,
        uid=authority_uid,
        create=False,
        expected_generation=state_generation,
    )
    return updated, False


def finalize_atomic_first_adoption_bindings(
    *,
    state_path: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    authority_uid: int = 0,
    command_status=_bounded_command_status,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    broker_lock_factory=exclusive_broker_service_lock,
    post_start_verifier=None,
    post_start_proof_validator=None,
    post_start_evidence_replacer=None,
    now_reader=_now,
    failpoint=lambda _stage: None,
) -> dict[str, object]:
    """Finish an initialized binding transaction, then restore the broker."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("atomic first-adoption finalization must run as root")
    state_path = _absolute(state_path, "atomic first-adoption cutover ledger")
    transaction_journal = _absolute(
        transaction_journal, "atomic first-adoption transaction journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation,
        "atomic first-adoption transaction attestation",
    )
    transaction = _atomic_first_adoption_binding_transaction(
        evidence_reader(transaction_journal, uid=authority_uid)
    )
    if transaction["transaction_attestation"] != str(transaction_attestation):
        raise CutoverError("atomic first-adoption result path changed")
    database = Path(str(transaction["database"]))
    transaction_readiness = _authority_readiness_rebind_attestation(
        evidence_reader(
            Path(str(transaction["readiness_attestation"])), uid=authority_uid
        )
    )
    prepared = verify_atomic_first_adoption_prepared(
        evidence_reader(
            Path(str(transaction["port_pending_attestation"])), uid=authority_uid
        )
    )
    if (
        transaction_readiness["operation_id"] != transaction["operation_id"]
        or prepared["operation_id"] != transaction["operation_id"]
        or prepared["atomic_transaction_journal_sha256"]
        != transaction["document_sha256"]
    ):
        raise CutoverError("atomic first-adoption evidence binding changed")
    initial_state = load_state(state_path, authority_uid=authority_uid)
    _first_adoption_binding_completion(initial_state)
    readiness = _authority_readiness_evidence(
        initial_state["evidence"].get("authority-readiness")
    )
    if readiness.get("kind") == AUTHORITY_READINESS_REATTEST_KIND:
        _verify_authority_readiness_reattest_references(
            readiness,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
        )
        if (
            readiness["operation_id"] != transaction["operation_id"]
            or readiness["release"] != transaction["release"]
            or readiness["release_digest"] != transaction["release_digest"]
            or readiness["database"] != transaction["database"]
            or readiness["prior_attestation"]["path"]
            != transaction["prior_attestation"]
            or readiness["quiescence_attestation"]["path"]
            != transaction["port_pending_attestation"]
            or readiness["quiescence_attestation"]["document_sha256"]
            != prepared["document_sha256"]
        ):
            raise CutoverError(
                "atomic first-adoption re-attested readiness binding changed"
            )
        _authority_readiness_same_database(
            transaction_readiness["database_identity"],
            readiness["database_identity_after"],
            label="atomic first-adoption re-attested readiness",
        )
        _authority_readiness_ready_descendant(
            transaction_readiness["postcondition"],
            readiness["postcondition"],
            label="atomic first-adoption re-attested readiness",
        )
    elif readiness != transaction_readiness:
        raise CutoverError(
            "atomic first-adoption ledger readiness changed"
        )
    _validate_first_adoption_port_readiness_binding(
        readiness=readiness,
        reservations=prepared,
        release_digest=str(transaction["release_digest"]),
        authority_database=str(transaction["database"]),
        inventory_canary_project=str(transaction["canonical_root"]),
    )
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        final_ports = verify_first_adoption_port_reservations(
            evidence_reader(
                Path(str(transaction["port_attestation"])), uid=authority_uid
            )
        )
        terminal = _verify_atomic_first_adoption_terminal(
            evidence_reader(transaction_attestation, uid=authority_uid),
            transaction=transaction,
            outcome="completed",
            readiness_sha256=str(
                transaction_readiness["document_sha256"]
            ),
            port_reservations_sha256=str(final_ports["document_sha256"]),
        )
        state = load_state(state_path, authority_uid=authority_uid)
        if (
            state["evidence"].get("first-adoption-port-reservations")
            != final_ports
            or _systemd_service_state(
                command_status, str(transaction["service_unit"])
            )
            != transaction["service_baseline"]
            or maintenance_state_reader(
                expected_uid=authority_uid,
                expected_gid=int(transaction["maintenance"]["gid"]),
                maintenance_root=Path(str(transaction["maintenance"]["root"])),
            )
            is not None
        ):
            raise CutoverError(
                "atomic first-adoption completed result is contradictory"
            )
        _verify_and_publish_atomic_post_start_readiness(
            transaction=transaction,
            readiness=readiness,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            require_existing_proof=True,
            verifier=post_start_verifier,
            proof_validator=post_start_proof_validator,
            evidence_replacer=post_start_evidence_replacer,
        )
        return {"ok": True, "replayed": True, "attestation": terminal}
    finalization_path = Path(str(transaction["finalization_journal"]))
    if finalization_path.exists() or finalization_path.is_symlink():
        finalization = _atomic_first_adoption_finalization_intent(
            evidence_reader(finalization_path, uid=authority_uid)
        )
        if (
            finalization["operation_id"] != transaction["operation_id"]
            or finalization["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or finalization["prepared_attestation_sha256"]
            != prepared["document_sha256"]
            or finalization["readiness_rebind_sha256"]
            != readiness["document_sha256"]
            or finalization["state_path"] != str(state_path)
        ):
            raise CutoverError(
                "atomic first-adoption finalization journal is contradictory"
            )
    else:
        _verify_atomic_first_adoption_fence(
            prepared,
            authority_uid=authority_uid,
            command_status=command_status,
            maintenance_state_reader=maintenance_state_reader,
            effective_uid_reader=effective_uid_reader,
        )
        state = load_state(state_path, authority_uid=authority_uid)
        _first_adoption_binding_completion(state)
        if (
            state["release"] != transaction["release"]
            or state["legacy_authority_database"] != transaction["database"]
            or state["evidence"].get("authority-readiness") != readiness
            or state["evidence"].get("first-adoption-port-reservations")
            != prepared
        ):
            raise CutoverError(
                "atomic first-adoption finalization ledger is not bound to preparation"
            )
        authorized = _first_adoption_port_authorized_readiness_snapshot(
            readiness=readiness, reservations=prepared
        )
        with broker_lock_factory(database):
            if _read_authority_readiness_snapshot(database) != authorized:
                raise CutoverError(
                    "atomic first-adoption authority changed before finalization"
                )
            compatible = verify_first_adoption_port_reservations(
                seal(
                    FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    _prepared_binding_as_final_port_values(prepared),
                )
            )
            verify_first_adoption_port_reservation_rows(
                database,
                compatible,
                authority_uid=authority_uid,
                effective_uid_reader=effective_uid_reader,
            )
            finalization_created_at = now_reader()
            final_state = _build_atomic_binding_final_state(
                current=state,
                prepared=prepared,
                final_ports=compatible,
                updated_at=finalization_created_at,
            )
            finalization = _atomic_first_adoption_finalization_intent(
                seal(
                    ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND,
                    {
                        "operation_id": transaction["operation_id"],
                        "transaction_journal_sha256": transaction[
                            "document_sha256"
                        ],
                        "prepared_attestation_sha256": prepared[
                            "document_sha256"
                        ],
                        "readiness_rebind_sha256": readiness[
                            "document_sha256"
                        ],
                        "state_path": str(state_path),
                        "state_document_sha256": state["document_sha256"],
                        "state_generation": state["state_generation"],
                        "final_state_document_sha256": final_state[
                            "document_sha256"
                        ],
                        "final_state_generation": final_state[
                            "state_generation"
                        ],
                        "state_updated_at": finalization_created_at,
                        "authorized_snapshot": authorized,
                        "final_port_reservations": compatible,
                        "created_at": finalization_created_at,
                    },
                )
            )
            evidence_publisher(
                finalization_path, finalization, uid=authority_uid
            )
    expected_authorized = _first_adoption_port_authorized_readiness_snapshot(
        readiness=readiness,
        reservations=prepared,
    )
    expected_final_ports = verify_first_adoption_port_reservations(
        seal(
            FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            _prepared_binding_as_final_port_values(prepared),
        )
    )
    if (
        finalization["authorized_snapshot"] != expected_authorized
        or finalization["final_port_reservations"] != expected_final_ports
    ):
        raise CutoverError(
            "atomic first-adoption finalization derived evidence changed"
        )
    final_ports = finalization["final_port_reservations"]
    state = load_state(state_path, authority_uid=authority_uid)
    state_is_pre_final = (
        state["document_sha256"] == finalization["state_document_sha256"]
        and state["state_generation"] == finalization["state_generation"]
        and state["evidence"].get("first-adoption-port-reservations")
        == prepared
    )
    state_is_final = (
        state["document_sha256"]
        == finalization["final_state_document_sha256"]
        and state["state_generation"]
        == finalization["final_state_generation"]
        and state["evidence"].get("first-adoption-port-reservations")
        == final_ports
    )
    if not state_is_pre_final and not state_is_final:
        raise CutoverError(
            "atomic first-adoption ledger changed after finalization was journaled"
        )
    unit = str(transaction["service_unit"])
    service = _systemd_service_state(command_status, unit)
    if service["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError("atomic first-adoption broker enabled state changed")
    maintenance_root = Path(str(transaction["maintenance"]["root"]))
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    )
    if marker is not None:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
        )
        if normalized != transaction["maintenance"]:
            raise CutoverError("atomic first-adoption maintenance marker changed")
    elif not service["active"]:
        raise CutoverError(
            "atomic first-adoption broker is stopped without maintenance"
        )
    if state_is_pre_final and (service["active"] or marker is None):
        raise CutoverError(
            "atomic first-adoption pre-final ledger escaped its stopped fence"
        )
    current_authority = _read_authority_readiness_snapshot(database)
    authorized = finalization["authorized_snapshot"]
    if marker is not None and not service["active"]:
        if current_authority != authorized:
            raise CutoverError(
                "atomic first-adoption authority changed inside finalization fence"
            )
    else:
        _authority_readiness_ready_descendant(
            authorized,
            current_authority,
            label="atomic first-adoption completed authority",
        )
    if not service["active"]:
        with broker_lock_factory(database):
            if _read_authority_readiness_snapshot(database) != authorized:
                raise CutoverError(
                    "atomic first-adoption authority changed before publication"
                )
            verify_first_adoption_port_reservation_rows(
                database,
                final_ports,
                authority_uid=authority_uid,
                effective_uid_reader=effective_uid_reader,
            )
    else:
        verify_first_adoption_port_reservation_rows(
            database,
            final_ports,
            authority_uid=authority_uid,
            effective_uid_reader=effective_uid_reader,
        )
    evidence_publisher(
        Path(str(transaction["port_attestation"])),
        final_ports,
        uid=authority_uid,
    )
    updated_state, state_replayed = _atomic_binding_state_with_final_ports(
        state_path=state_path,
        prepared=prepared,
        final_ports=final_ports,
        authority_uid=authority_uid,
        state_document_sha256=str(finalization["state_document_sha256"]),
        state_generation=int(finalization["state_generation"]),
        final_state_document_sha256=str(
            finalization["final_state_document_sha256"]
        ),
        state_updated_at=str(finalization["state_updated_at"]),
    )
    if updated_state["evidence"].get("first-adoption-port-reservations") != final_ports:
        raise CutoverError("atomic first-adoption final ports were not published")
    failpoint("after-state-swap")
    service = _systemd_service_state(command_status, unit)
    if not service["active"] and command_status(
        ["/usr/bin/systemctl", "start", unit]
    ) != 0:
        raise CutoverError("atomic first-adoption broker did not restart")
    if _systemd_service_state(command_status, unit) != transaction[
        "service_baseline"
    ]:
        raise CutoverError("atomic first-adoption broker baseline was not restored")
    failpoint("after-service-start")
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    )
    _verify_and_publish_atomic_post_start_readiness(
        transaction=transaction,
        readiness=readiness,
        authority_uid=authority_uid,
        evidence_reader=evidence_reader,
        evidence_publisher=evidence_publisher,
        require_existing_proof=marker is None,
        verifier=post_start_verifier,
        proof_validator=post_start_proof_validator,
        evidence_replacer=post_start_evidence_replacer,
    )
    failpoint("after-post-start-ready")
    if marker is not None:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
        )
        if normalized != transaction["maintenance"]:
            raise CutoverError("atomic first-adoption maintenance marker changed")
        maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
            maintenance_root=maintenance_root,
        )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError("atomic first-adoption maintenance marker did not clear")
    failpoint("after-maintenance-clear")
    result = _atomic_first_adoption_binding_result(
        seal(
            ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
            {
                "operation_id": transaction["operation_id"],
                "outcome": "completed",
                "transaction_journal_sha256": transaction["document_sha256"],
                "readiness_rebind_sha256": transaction_readiness[
                    "document_sha256"
                ],
                "port_reservations_sha256": final_ports["document_sha256"],
                "release_digest": transaction["release_digest"],
                "database": transaction["database"],
                "service_unit": unit,
                "service_restored": True,
                "maintenance_cleared": True,
                "completed_at": now_reader(),
            },
        )
    )
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {
        "ok": True,
        "replayed": bool(state_replayed),
        "attestation": result,
    }


def _atomic_first_adoption_optional_evidence(
    path: Path,
    *,
    authority_uid: int,
    evidence_reader,
    validator,
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return validator(evidence_reader(path, uid=authority_uid))


def _atomic_first_adoption_abort_readiness(
    *,
    transaction: Mapping[str, object],
    authority_uid: int,
    evidence_reader,
) -> tuple[dict[str, object] | None, dict[str, object], dict[str, int]]:
    """Load the strongest durable readiness ancestor available to abort."""

    prior = _authority_readiness_evidence(
        evidence_reader(
            Path(str(transaction["prior_attestation"])), uid=authority_uid
        )
    )
    if prior["database"] != transaction["database"]:
        raise CutoverError(
            "atomic first-adoption prior readiness database changed"
        )
    prior_identity = prior.get(
        "database_identity_after", prior.get("database_identity")
    )
    if not isinstance(prior_identity, Mapping):
        raise CutoverError(
            "atomic first-adoption prior readiness identity is invalid"
        )
    readiness_path = Path(str(transaction["readiness_attestation"]))
    readiness = _atomic_first_adoption_optional_evidence(
        readiness_path,
        authority_uid=authority_uid,
        evidence_reader=evidence_reader,
        validator=_authority_readiness_rebind_attestation,
    )
    if readiness is None:
        return None, dict(prior["postcondition"]), dict(prior_identity)
    if (
        readiness["operation_id"] != transaction["operation_id"]
        or readiness["prior_attestation"]["path"]
        != transaction["prior_attestation"]
        or readiness["release"] != transaction["release"]
        or readiness["release_digest"] != transaction["release_digest"]
        or readiness["database"] != transaction["database"]
    ):
        raise CutoverError(
            "atomic first-adoption readiness attestation is contradictory"
        )
    _authority_readiness_same_database(
        prior_identity,
        readiness["database_identity"],
        label="atomic first-adoption abort readiness",
    )
    _authority_readiness_ready_descendant(
        prior["postcondition"],
        readiness["postcondition"],
        label="atomic first-adoption abort readiness",
    )
    return (
        readiness,
        dict(readiness["postcondition"]),
        dict(readiness["database_identity"]),
    )


def _verify_atomic_first_adoption_abort_intent(
    *,
    transaction: Mapping[str, object],
    readiness: Mapping[str, object],
    intent: Mapping[str, object],
) -> None:
    expected = {
        "operation_id": transaction["operation_id"],
        "release": transaction["release"],
        "release_digest": transaction["release_digest"],
        "authority_database": transaction["database"],
        "attestation": transaction["port_attestation"],
        "repository_id": transaction["repository_id"],
        "repository_generation": transaction["repository_generation"],
        "canonical_root": transaction["canonical_root"],
        "handoff_ttl_seconds": transaction["handoff_ttl_seconds"],
        "authority_generation": readiness["postcondition"]["metadata"][
            "database_generation"
        ],
        "authority_state_revision_before": readiness["postcondition"][
            "metadata"
        ]["state_revision"],
        "service_unit": transaction["service_unit"],
        "service_baseline": transaction["service_baseline"],
        "maintenance": transaction["maintenance"],
    }
    if any(intent[field] != value for field, value in expected.items()):
        raise CutoverError(
            "atomic first-adoption port journal is contradictory"
        )


def _atomic_first_adoption_abort_row_phase(
    *,
    database: Path,
    intent: Mapping[str, object],
) -> dict[str, object] | None:
    """Return exact committed rows, or None; reject every partial phase."""

    lease_ids = [
        str(intent["row_ids"][role]["lease_id"])
        for role in FIRST_ADOPTION_PORT_ROLES
    ]
    event_ids = [
        str(intent["row_ids"][role]["event_id"])
        for role in FIRST_ADOPTION_PORT_ROLES
    ]
    placeholders = ",".join("?" for _ in FIRST_ADOPTION_PORT_ROLES)
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        leases = connection.execute(
            f"SELECT lease_id, port FROM leases WHERE lease_id IN ({placeholders})",
            lease_ids,
        ).fetchall()
        events = connection.execute(
            f"""
            SELECT event_id, repo_id, source_id, operation_id, event_kind, code,
                   message, diagnostic_json, occurred_at
            FROM events WHERE event_id IN ({placeholders})
            """,
            event_ids,
        ).fetchall()
        expected_count = len(FIRST_ADOPTION_PORT_ROLES)
        if len(leases) == 0 and len(events) == 0:
            return None
        if len(leases) != expected_count or len(events) != expected_count:
            raise CutoverError(
                "atomic first-adoption abort found a partial reservation row set"
            )
        lease_by_id = {str(row[0]): row for row in leases}
        event_by_id = {str(row[0]): row for row in events}
        ports = {
            role: int(lease_by_id[str(intent["row_ids"][role]["lease_id"])][1])
            for role in FIRST_ADOPTION_PORT_ROLES
        }
        bundle = verify_first_adoption_port_reservations(
            seal(
                FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                _build_first_adoption_port_bundle_values(
                    intent=intent,
                    ports=ports,
                    completed_at=str(intent["created_at"]),
                ),
            )
        )
        _verify_first_adoption_rows_in_connection(connection, bundle)
        for role in FIRST_ADOPTION_PORT_ROLES:
            reservation = bundle["reservations"][role]
            row = event_by_id[
                str(intent["row_ids"][role]["event_id"])
            ]
            expected = (
                str(intent["repository_id"]),
                None,
                None,
                "port.lease.created",
                "first_adoption_port_reserved",
                f"Reserved first-adoption port for {role}",
                _first_adoption_event_diagnostic(
                    operation_id=str(intent["operation_id"]),
                    role=role,
                    lease_id=str(reservation["lease_id"]),
                    port=int(reservation["port"]),
                ),
                str(intent["created_at"]),
            )
            if tuple(row[index] for index in range(1, 9)) != expected:
                raise CutoverError(
                    "atomic first-adoption abort event row changed"
                )
        return bundle


def _verify_atomic_first_adoption_abort_prepared(
    *,
    transaction: Mapping[str, object],
    intent: Mapping[str, object],
    prepared: Mapping[str, object],
    rows: Mapping[str, object],
) -> None:
    expected = verify_first_adoption_port_reservations(
        seal(
            FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            _build_first_adoption_port_bundle_values(
                intent=intent,
                ports={
                    role: int(rows["reservations"][role]["port"])
                    for role in FIRST_ADOPTION_PORT_ROLES
                },
                completed_at=str(prepared["completed_at"]),
            ),
        )
    )
    compatible = verify_first_adoption_port_reservations(
        seal(
            FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
            _prepared_binding_as_final_port_values(prepared),
        )
    )
    if (
        prepared["atomic_transaction_journal_sha256"]
        != transaction["document_sha256"]
        or compatible != expected
        or prepared["maintenance"] != transaction["maintenance"]
        or prepared["service_stopped"] is not True
    ):
        raise CutoverError(
            "atomic first-adoption prepared evidence is contradictory"
        )


def abort_atomic_first_adoption_bindings(
    *,
    state_path: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    authority_uid: int = 0,
    command_status=_bounded_command_status,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    broker_lock_factory=exclusive_broker_service_lock,
    post_start_verifier=None,
    post_start_proof_validator=None,
    post_start_evidence_replacer=None,
    now_reader=_now,
    failpoint=lambda _stage: None,
) -> dict[str, object]:
    """Rollback every durable preparation prefix and restore the baseline."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError("atomic first-adoption abort must run as root")
    state_path = _absolute(state_path, "atomic first-adoption cutover ledger")
    transaction_journal = _absolute(
        transaction_journal, "atomic first-adoption transaction journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation,
        "atomic first-adoption transaction attestation",
    )
    transaction = _atomic_first_adoption_binding_transaction(
        evidence_reader(transaction_journal, uid=authority_uid)
    )
    if transaction["transaction_attestation"] != str(transaction_attestation):
        raise CutoverError("atomic first-adoption result path changed")
    database = Path(str(transaction["database"]))
    readiness, restored, readiness_identity = (
        _atomic_first_adoption_abort_readiness(
            transaction=transaction,
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
        )
    )
    intent_path = Path(str(transaction["port_journal"]))
    intent = _atomic_first_adoption_optional_evidence(
        intent_path,
        authority_uid=authority_uid,
        evidence_reader=evidence_reader,
        validator=_first_adoption_port_reservation_intent,
    )
    if intent is not None:
        if readiness is None:
            raise CutoverError(
                "atomic first-adoption port journal exists without readiness"
            )
        _verify_atomic_first_adoption_abort_intent(
            transaction=transaction,
            readiness=readiness,
            intent=intent,
        )
    prepared_path = Path(str(transaction["port_pending_attestation"]))
    prepared = _atomic_first_adoption_optional_evidence(
        prepared_path,
        authority_uid=authority_uid,
        evidence_reader=evidence_reader,
        validator=verify_atomic_first_adoption_prepared,
    )
    if prepared is not None and intent is None:
        raise CutoverError(
            "atomic first-adoption prepared evidence exists without its journal"
        )
    rows = (
        _atomic_first_adoption_abort_row_phase(database=database, intent=intent)
        if intent is not None
        else None
    )
    if prepared is not None:
        prepared_rows = rows
        if prepared_rows is None:
            prepared_rows = verify_first_adoption_port_reservations(
                seal(
                    FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
                    _prepared_binding_as_final_port_values(prepared),
                )
            )
        _verify_atomic_first_adoption_abort_prepared(
            transaction=transaction,
            intent=intent,
            prepared=prepared,
            rows=prepared_rows,
        )
    current_identity = _database_identity(database, uid=authority_uid)
    _authority_readiness_same_database(
        readiness_identity,
        current_identity,
        label="atomic first-adoption abort",
    )
    unit = str(transaction["service_unit"])
    service = _systemd_service_state(command_status, unit)
    if service["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError("atomic first-adoption broker enabled state changed")
    maintenance_root = Path(str(transaction["maintenance"]["root"]))
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    )
    if marker is not None:
        normalized = _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
        )
        if normalized != transaction["maintenance"]:
            raise CutoverError("atomic first-adoption maintenance marker changed")
    elif not service["active"]:
        raise CutoverError(
            "atomic first-adoption broker is stopped without maintenance"
        )
    current = _read_authority_readiness_snapshot(database)
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        result = _verify_atomic_first_adoption_terminal(
            evidence_reader(transaction_attestation, uid=authority_uid),
            transaction=transaction,
            outcome="aborted",
            readiness_sha256=(
                None if readiness is None else str(readiness["document_sha256"])
            ),
            port_reservations_sha256=None,
        )
        if (
            service != transaction["service_baseline"]
            or marker is not None
            or rows is not None
        ):
            raise CutoverError(
                "atomic first-adoption aborted result is contradictory"
            )
        _authority_readiness_ready_descendant(
            restored,
            current,
            label="atomic first-adoption aborted authority",
        )
        _verify_and_publish_atomic_post_start_readiness(
            transaction=transaction,
            readiness=(
                readiness
                if readiness is not None
                else {"postcondition": restored}
            ),
            authority_uid=authority_uid,
            evidence_reader=evidence_reader,
            evidence_publisher=evidence_publisher,
            require_existing_proof=True,
            verifier=post_start_verifier,
            proof_validator=post_start_proof_validator,
            evidence_replacer=post_start_evidence_replacer,
        )
        return {"ok": True, "replayed": True, "attestation": result}
    if state_path.exists() or state_path.is_symlink():
        raise CutoverError(
            "atomic first-adoption abort is unavailable after cutover initialization"
        )
    if (
        Path(str(transaction["finalization_journal"])).exists()
        or Path(str(transaction["finalization_journal"])).is_symlink()
    ):
        raise CutoverError(
            "atomic first-adoption finalization already started"
        )
    if rows is not None:
        if readiness is None or intent is None:
            raise CutoverError(
                "atomic first-adoption reservation rows lack their durable lineage"
            )
        authorized = _first_adoption_port_authorized_readiness_snapshot(
            readiness=readiness,
            reservations=rows,
        )
        if service["active"] or marker is None or current != authorized:
            raise CutoverError(
                "atomic first-adoption committed rows escaped their stopped fence"
            )
        with broker_lock_factory(database):
            locked_service = _systemd_service_state(command_status, unit)
            locked_marker = maintenance_state_reader(
                expected_uid=authority_uid,
                expected_gid=int(transaction["maintenance"]["gid"]),
                maintenance_root=maintenance_root,
            )
            if (
                locked_service["active"]
                or locked_service["enabled"]
                != transaction["service_baseline"]["enabled"]
                or _normalize_maintenance_state(
                    locked_marker,
                    root=maintenance_root,
                    gid=int(transaction["maintenance"]["gid"]),
                    deployment_id=str(
                        transaction["maintenance"]["deployment_id"]
                    ),
                )
                != transaction["maintenance"]
                or _read_authority_readiness_snapshot(database) != authorized
            ):
                raise CutoverError(
                    "atomic first-adoption abort fence changed before rollback"
                )
            verify_first_adoption_port_reservation_rows(
                database,
                rows,
                authority_uid=authority_uid,
                effective_uid_reader=effective_uid_reader,
            )
        connection = sqlite3.connect(database, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            lease_ids = [
                str(intent["row_ids"][role]["lease_id"])
                for role in FIRST_ADOPTION_PORT_ROLES
            ]
            event_ids = [
                str(intent["row_ids"][role]["event_id"])
                for role in FIRST_ADOPTION_PORT_ROLES
            ]
            placeholders = ",".join("?" for _ in FIRST_ADOPTION_PORT_ROLES)
            if _read_authority_readiness_snapshot(
                database, connection=connection
            ) != authorized:
                raise CutoverError(
                    "atomic first-adoption authority changed while aborting"
                )
            if connection.execute(
                f"DELETE FROM events WHERE event_id IN ({placeholders})",
                event_ids,
            ).rowcount != len(FIRST_ADOPTION_PORT_ROLES):
                raise CutoverError("atomic first-adoption abort event set changed")
            if connection.execute(
                f"DELETE FROM leases WHERE lease_id IN ({placeholders})",
                lease_ids,
            ).rowcount != len(FIRST_ADOPTION_PORT_ROLES):
                raise CutoverError("atomic first-adoption abort lease set changed")
            metadata = restored["metadata"]
            changed = connection.execute(
                """
                UPDATE schema_metadata
                SET state_revision=?, updated_at=?
                WHERE singleton=1 AND schema_version=12
                  AND database_generation=? AND state_revision=?
                """,
                (
                    metadata["state_revision"],
                    metadata["updated_at"],
                    metadata["database_generation"],
                    rows["authority_state_revision_after"],
                ),
            ).rowcount
            if changed != 1:
                raise CutoverError(
                    "atomic first-adoption abort revision fence changed"
                )
            if _read_authority_readiness_snapshot(
                database, connection=connection
            ) != restored:
                raise CutoverError(
                    "atomic first-adoption abort did not restore readiness"
                )
            connection.execute("COMMIT")
            failpoint("after-commit")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
    else:
        if service["active"]:
            _authority_readiness_ready_descendant(
                restored,
                current,
                label="atomic first-adoption abort recovery",
            )
        elif readiness is not None and current != restored:
            raise CutoverError(
                "atomic first-adoption stopped preparation readiness changed"
            )
        else:
            _authority_readiness_ready_descendant(
                restored,
                current,
                label="atomic first-adoption stopped abort recovery",
            )
    service = _systemd_service_state(command_status, unit)
    if not service["active"] and command_status(
        ["/usr/bin/systemctl", "start", unit]
    ) != 0:
        raise CutoverError("atomic first-adoption broker did not restart after abort")
    if _systemd_service_state(command_status, unit) != transaction[
        "service_baseline"
    ]:
        raise CutoverError("atomic first-adoption abort did not restore broker")
    failpoint("after-service-start")
    after_start = _read_authority_readiness_snapshot(database)
    _authority_readiness_ready_descendant(
        restored,
        after_start,
        label="atomic first-adoption abort restored authority",
    )
    if intent is not None and _atomic_first_adoption_abort_row_phase(
        database=database, intent=intent
    ) is not None:
        raise CutoverError(
            "atomic first-adoption abort reservation rows remain"
        )
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    )
    safe_unfenced_prefix = (
        marker is None
        and readiness is None
        and intent is None
        and prepared is None
        and rows is None
    )
    _verify_and_publish_atomic_post_start_readiness(
        transaction=transaction,
        readiness=(
            readiness
            if readiness is not None
            else {"postcondition": restored}
        ),
        authority_uid=authority_uid,
        evidence_reader=evidence_reader,
        evidence_publisher=evidence_publisher,
        require_existing_proof=marker is None and not safe_unfenced_prefix,
        verifier=post_start_verifier,
        proof_validator=post_start_proof_validator,
        evidence_replacer=post_start_evidence_replacer,
    )
    failpoint("after-post-start-ready")
    if marker is not None:
        if _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
        ) != transaction["maintenance"]:
            raise CutoverError("atomic first-adoption maintenance marker changed")
        maintenance_clearer(
            expected_uid=authority_uid,
            expected_gid=int(transaction["maintenance"]["gid"]),
            deployment_id=str(transaction["maintenance"]["deployment_id"]),
            maintenance_root=maintenance_root,
        )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=int(transaction["maintenance"]["gid"]),
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError("atomic first-adoption abort did not clear maintenance")
    failpoint("after-maintenance-clear")
    result = _atomic_first_adoption_binding_result(
        seal(
            ATOMIC_FIRST_ADOPTION_BINDING_RESULT_KIND,
            {
                "operation_id": transaction["operation_id"],
                "outcome": "aborted",
                "transaction_journal_sha256": transaction["document_sha256"],
                "readiness_rebind_sha256": (
                    None
                    if readiness is None
                    else readiness["document_sha256"]
                ),
                "port_reservations_sha256": None,
                "release_digest": transaction["release_digest"],
                "database": transaction["database"],
                "service_unit": unit,
                "service_restored": True,
                "maintenance_cleared": True,
                "completed_at": now_reader(),
            },
        )
    )
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": result}


AUTHORITY_REPOSITORY_SERVICE_READINESS_FIELDS = frozenset(
    {
        "broker_socket",
        "canary_user",
        "canary_uid",
        "canary_project",
        "canary_repository_id",
        "canary_repository_generation",
        "wait_seconds",
    }
)
AUTHORITY_REPOSITORY_SERVICE_PROOF_FIELDS = frozenset(
    {
        "phase",
        "broker_socket",
        "socket_identity",
        "socket_peer",
        "authority_generation",
        "canary",
        "invariants",
        "verified_at",
    }
)


def _authority_repository_service_readiness_binding(
    value: object,
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != AUTHORITY_REPOSITORY_SERVICE_READINESS_FIELDS
    ):
        raise CutoverError("authority repository service readiness binding is invalid")
    try:
        account = pwd.getpwnam(str(value["canary_user"]))
    except KeyError as error:
        raise CutoverError("authority repository canary account is unavailable") from error
    broker_socket = _absolute(
        str(value["broker_socket"]), "authority repository broker socket"
    )
    canary_project = _absolute(
        str(value["canary_project"]), "authority repository canary project"
    )
    if (
        not isinstance(value["canary_user"], str)
        or not value["canary_user"]
        or account.pw_uid != value["canary_uid"]
        or isinstance(value["canary_uid"], bool)
        or not isinstance(value["canary_uid"], int)
        or int(value["canary_uid"]) <= 0
        or not isinstance(value["canary_repository_id"], str)
        or not value["canary_repository_id"]
        or len(str(value["canary_repository_id"]).encode("utf-8")) > 256
        or isinstance(value["canary_repository_generation"], bool)
        or not isinstance(value["canary_repository_generation"], int)
        or int(value["canary_repository_generation"]) < 0
        or isinstance(value["wait_seconds"], bool)
        or not isinstance(value["wait_seconds"], int)
        or not 1 <= int(value["wait_seconds"]) <= 120
    ):
        raise CutoverError("authority repository service readiness values are invalid")
    return {
        "broker_socket": str(broker_socket),
        "canary_user": account.pw_name,
        "canary_uid": account.pw_uid,
        "canary_project": str(canary_project),
        "canary_repository_id": str(value["canary_repository_id"]),
        "canary_repository_generation": int(
            value["canary_repository_generation"]
        ),
        "wait_seconds": int(value["wait_seconds"]),
    }


def _authority_repository_socket_observation(
    broker_socket: Path,
) -> tuple[dict[str, int], dict[str, int]]:
    path = _absolute(broker_socket, "authority repository broker socket")
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise CutoverError("authority repository broker socket is unavailable") from error
    if (
        not stat.S_ISSOCK(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or stat.S_IMODE(before.st_mode) != 0o666
    ):
        raise CutoverError("authority repository broker socket identity is unsafe")
    credentials_size = 12
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(path))
            credentials = client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, credentials_size
            )
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout, OSError) as error:
        raise CutoverError("authority repository broker socket is not ready") from error
    if len(credentials) != credentials_size:
        raise CutoverError("authority repository broker peer proof is invalid")
    pid, uid, gid = struct.unpack("3i", credentials)
    after = path.lstat()
    identity = {
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "uid": int(before.st_uid),
        "gid": int(before.st_gid),
        "mode": stat.S_IMODE(before.st_mode),
    }
    if (
        (after.st_dev, after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode))
        != (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        or pid <= 0
        or uid != 0
    ):
        raise CutoverError("authority repository broker socket changed during proof")
    return identity, {"pid": pid, "uid": uid, "gid": gid}


def _authority_repository_full_schema12_invariant_proof(
    *,
    database: Path,
    authority_uid: int,
    expected_generation: str,
    identity_reader=_database_identity,
) -> dict[str, object]:
    before = identity_reader(database, uid=authority_uid)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        row = connection.execute(
            """
            SELECT schema_version, database_generation, state_revision,
                   authority_mode, migration_state
            FROM schema_metadata WHERE singleton = 1
            """
        ).fetchone()
        quick = [str(item[0]) for item in connection.execute("PRAGMA quick_check")]
        violations = invariant_violations(
            connection,
            include_foreign_keys=True,
            include_owner_authority=False,
        )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    after = identity_reader(database, uid=authority_uid)
    if before != after:
        raise CutoverError("authority database changed during full invariant proof")
    if (
        row is None
        or int(row[0]) != 12
        or str(row[1]) != expected_generation
        or int(row[2]) < 0
        or str(row[3]) != "sqlite"
        or str(row[4]) != "ready"
        or quick != ["ok"]
    ):
        raise CutoverError("authority schema-12 readiness contract is not satisfied")
    if violations:
        first = violations[0]
        raise CutoverError(
            f"authority full invariant proof failed: {first.code}"
        )
    return {
        "contract": "schema12-pre-owner-authority-complete-v1",
        "schema_version": 12,
        "database_generation": str(row[1]),
        "state_revision": int(row[2]),
        "quick_check": "ok",
        "semantic_violation_count": 0,
        "database_identity": dict(after),
    }


def _authority_repository_inventory_canary(
    *,
    release: Path,
    binding: Mapping[str, object],
    expected_generation: str,
) -> dict[str, object]:
    account = pwd.getpwnam(str(binding["canary_user"]))
    entry = release / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    if not entry.is_file():
        raise CutoverError("authority repository canary client is unavailable")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/setpriv",
                "--reuid",
                str(account.pw_uid),
                "--regid",
                str(account.pw_gid),
                "--init-groups",
                "--reset-env",
                "/usr/bin/python3",
                "-B",
                "-I",
                str(entry),
                "inventory",
                "--project",
                str(binding["canary_project"]),
                "--no-docker",
                "--compact-json",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": account.pw_dir,
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            timeout=int(binding["wait_seconds"]),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CutoverError(
            "authority repository authenticated canary could not execute"
        ) from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > 1024 * 1024
        or len(completed.stderr) > 8192
    ):
        raise CutoverError("authority repository authenticated canary failed")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CutoverError(
            "authority repository authenticated canary returned invalid JSON"
        ) from error
    authority = result.get("authority") if isinstance(result, Mapping) else None
    repositories = result.get("repositories") if isinstance(result, Mapping) else None
    matching = (
        [
            repository
            for repository in repositories
            if isinstance(repository, Mapping)
            and repository.get("repo_id") == binding["canary_repository_id"]
            and repository.get("canonical_root") == binding["canary_project"]
            and repository.get("generation")
            == binding["canary_repository_generation"]
        ]
        if isinstance(repositories, list)
        else []
    )
    if (
        not isinstance(result, Mapping)
        or result.get("schema_version") != 2
        or not isinstance(authority, Mapping)
        or authority.get("scope") != "server-wide"
        or authority.get("transport") != "authenticated-unix-socket"
        or authority.get("socket") != binding["broker_socket"]
        or authority.get("service_uid") != 0
        or authority.get("database_generation") != expected_generation
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or len(matching) != 1
    ):
        raise CutoverError(
            "authority repository authenticated canary binding is invalid"
        )
    return {
        "user": account.pw_name,
        "uid": account.pw_uid,
        "project": binding["canary_project"],
        "repository_id": binding["canary_repository_id"],
        "repository_generation": binding["canary_repository_generation"],
        "inventory_sha256": _digest(result),
    }


def _authority_repository_service_readiness_proof(
    *,
    phase: str,
    release: Path,
    database: Path,
    authority_uid: int,
    authority_generation: str,
    binding: Mapping[str, object],
    now_reader=_now,
) -> dict[str, object]:
    normalized = _authority_repository_service_readiness_binding(binding)
    if phase not in {"preclear", "authenticated"}:
        raise CutoverError("authority repository readiness phase is invalid")
    deadline = time.monotonic() + int(normalized["wait_seconds"])
    last_error: CutoverError | None = None
    first_identity: dict[str, int] | None = None
    first_peer: dict[str, int] | None = None
    while time.monotonic() < deadline:
        try:
            first_identity, first_peer = _authority_repository_socket_observation(
                Path(str(normalized["broker_socket"]))
            )
            time.sleep(0.1)
            second_identity, second_peer = _authority_repository_socket_observation(
                Path(str(normalized["broker_socket"]))
            )
            if first_identity != second_identity or first_peer != second_peer:
                raise CutoverError(
                    "authority repository broker socket did not remain stable"
                )
            break
        except CutoverError as error:
            last_error = error
            time.sleep(0.05)
    else:
        raise CutoverError(
            "authority repository broker socket never became stably ready"
        ) from last_error
    invariants = _authority_repository_full_schema12_invariant_proof(
        database=database,
        authority_uid=authority_uid,
        expected_generation=authority_generation,
    )
    canary = (
        None
        if phase == "preclear"
        else _authority_repository_inventory_canary(
            release=release,
            binding=normalized,
            expected_generation=authority_generation,
        )
    )
    final_identity, final_peer = _authority_repository_socket_observation(
        Path(str(normalized["broker_socket"]))
    )
    if final_identity != first_identity or final_peer != first_peer:
        raise CutoverError(
            "authority repository broker changed during readiness proof"
        )
    return {
        "phase": phase,
        "broker_socket": normalized["broker_socket"],
        "socket_identity": final_identity,
        "socket_peer": final_peer,
        "authority_generation": authority_generation,
        "canary": canary,
        "invariants": invariants,
        "verified_at": now_reader(),
    }


def _validate_authority_repository_service_readiness_proof(
    value: object, *, phase: str, binding: Mapping[str, object], generation: str
) -> dict[str, object]:
    invariant_fields = {
        "contract",
        "schema_version",
        "database_generation",
        "state_revision",
        "quick_check",
        "semantic_violation_count",
        "database_identity",
    }
    database_identity = (
        value["invariants"].get("database_identity")
        if isinstance(value, Mapping)
        and isinstance(value.get("invariants"), Mapping)
        else None
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != AUTHORITY_REPOSITORY_SERVICE_PROOF_FIELDS
        or value["phase"] != phase
        or value["broker_socket"] != binding["broker_socket"]
        or value["authority_generation"] != generation
        or not isinstance(value["socket_identity"], Mapping)
        or set(value["socket_identity"])
        != {"device", "inode", "uid", "gid", "mode"}
        or any(
            type(value["socket_identity"][field]) is not int
            for field in ("device", "inode", "uid", "gid", "mode")
        )
        or value["socket_identity"]["device"] < 0
        or value["socket_identity"]["inode"] <= 0
        or value["socket_identity"]["uid"] != 0
        or value["socket_identity"]["gid"] < 0
        or value["socket_identity"]["mode"] != 0o660
        or not isinstance(value["socket_peer"], Mapping)
        or set(value["socket_peer"]) != {"pid", "uid", "gid"}
        or any(
            type(value["socket_peer"][field]) is not int
            for field in ("pid", "uid", "gid")
        )
        or value["socket_peer"]["uid"] != 0
        or int(value["socket_peer"]["pid"]) <= 0
        or value["socket_peer"]["gid"] < 0
        or not isinstance(value["invariants"], Mapping)
        or set(value["invariants"]) != invariant_fields
        or value["invariants"].get("contract")
        != "schema12-pre-owner-authority-complete-v1"
        or value["invariants"].get("schema_version") != 12
        or value["invariants"].get("database_generation") != generation
        or type(value["invariants"].get("state_revision")) is not int
        or int(value["invariants"].get("state_revision", -1)) < 0
        or value["invariants"].get("quick_check") != "ok"
        or value["invariants"].get("semantic_violation_count") != 0
        or not isinstance(database_identity, Mapping)
        or set(database_identity) != {"device", "inode", "size"}
        or any(type(database_identity[field]) is not int for field in database_identity)
        or database_identity["device"] < 0
        or database_identity["inode"] <= 0
        or database_identity["size"] <= 0
        or not isinstance(value["verified_at"], str)
        or not value["verified_at"]
    ):
        raise CutoverError("authority repository service readiness proof is invalid")
    if phase == "preclear":
        if value["canary"] is not None:
            raise CutoverError("preclear readiness proof unexpectedly contains a canary")
    else:
        canary = value["canary"]
        if (
            not isinstance(canary, Mapping)
            or canary.get("user") != binding["canary_user"]
            or canary.get("uid") != binding["canary_uid"]
            or canary.get("project") != binding["canary_project"]
            or canary.get("repository_id") != binding["canary_repository_id"]
            or canary.get("repository_generation")
            != binding["canary_repository_generation"]
            or re.fullmatch(r"[0-9a-f]{64}", str(canary.get("inventory_sha256")))
            is None
        ):
            raise CutoverError(
                "authority repository authenticated readiness proof is invalid"
            )
    return dict(value)


def _authority_repository_readiness_stable_binding(
    value: Mapping[str, object],
) -> dict[str, object]:
    """Discard only the descriptive verification timestamp from a proof."""

    return {
        key: item
        for key, item in value.items()
        if key != "verified_at"
    }


def _authority_repository_disable_transaction(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_KIND,
        fields=AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository repair transaction operation ID is invalid"
        ) from error
    for field in ("release", "plan", "database", "repair_attestation"):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"authority repository repair transaction {field}",
            )
        )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["plan_document_sha256"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError("authority repository repair transaction binding is invalid")
    baseline = document["service_baseline"]
    if (
        not isinstance(baseline, Mapping)
        or set(baseline) != {"active", "enabled"}
        or baseline["active"] is not True
        or type(baseline["enabled"]) is not bool
    ):
        raise CutoverError(
            "authority repository repair requires the active legacy broker baseline"
        )
    document["service_baseline"] = dict(baseline)
    document["readiness"] = _authority_repository_service_readiness_binding(
        document["readiness"]
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    return document


def _authority_repository_disable_transaction_result(
    value: object,
    *,
    readiness: Mapping[str, object] | None = None,
    authority_generation: str | None = None,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_KIND,
        fields=AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository repair transaction result operation ID is invalid"
        ) from error
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "authority repository repair transaction result database",
        )
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(document["transaction_journal_sha256"])
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["repair_result_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError(
            "authority repository repair transaction result is invalid"
        )
    if readiness is not None and authority_generation is not None:
        document["readiness_proof"] = (
            _validate_authority_repository_service_readiness_proof(
                document["readiness_proof"],
                phase="authenticated",
                binding=readiness,
                generation=authority_generation,
            )
        )
    elif not isinstance(document["readiness_proof"], Mapping):
        raise CutoverError(
            "authority repository repair readiness proof is unavailable"
        )
    return document


def recover_authority_repository_disable(
    *,
    release: Path,
    plan_path: Path,
    plan_document_sha256: str,
    repair_attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    broker_socket: Path,
    canary_user: str,
    canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    readiness_wait_seconds: int = 30,
    authority_uid: int = 0,
    release_verifier=None,
    command_status=_bounded_command_status,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    repairer=apply_authority_repository_disable,
    repairer_options: Mapping[str, object] | None = None,
    service_readiness_verifier=None,
) -> dict[str, object]:
    """Fence only the legacy broker around one sealed shared-root repair."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError(
            "authority repository repair service transaction must run as root"
        )
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(uuid.UUID(str(maintenance_deployment_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository repair transaction identity is invalid"
        ) from error
    release = _absolute(release, "authority repository repair transaction release")
    plan_path = _absolute(plan_path, "authority repository repair transaction plan")
    repair_attestation = _absolute(
        repair_attestation, "authority repository repair transaction result"
    )
    transaction_journal = _absolute(
        transaction_journal, "authority repository repair service journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation, "authority repository repair service attestation"
    )
    maintenance_root = _absolute(
        maintenance_root, "authority repository repair transaction maintenance root"
    )
    readiness_binding = _authority_repository_service_readiness_binding(
        {
            "broker_socket": str(broker_socket),
            "canary_user": canary_user,
            "canary_uid": canary_uid,
            "canary_project": str(canary_project),
            "canary_repository_id": canary_repository_id,
            "canary_repository_generation": canary_repository_generation,
            "wait_seconds": readiness_wait_seconds,
        }
    )
    if len(
        {plan_path, repair_attestation, transaction_journal, transaction_attestation}
    ) != 4:
        raise CutoverError(
            "authority repository repair transaction paths must be distinct"
        )
    plan = _validate_authority_repository_disable_plan(
        evidence_reader(plan_path, uid=authority_uid)
    )
    if (
        plan["authority_uid"] != authority_uid
        or re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan["document_sha256"] != plan_document_sha256
    ):
        raise CutoverError(
            "authority repository repair transaction plan digest does not match"
        )
    database = _absolute(
        str(plan["authority_database"]),
        "authority repository repair transaction database",
    )
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
        or (release_verifier is None and release != IMMUTABLE_RELEASE_ROOT / release_digest)
    ):
        raise CutoverError(
            "authority repository repair service transaction release is invalid"
        )
    unit = "devcoordinator-broker.service"
    started_at = now_reader()
    planned_maintenance = {
        "root": str(maintenance_root),
        "gid": maintenance_gid,
        "deployment_id": maintenance_deployment_id,
        "message": PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": 5,
        "started_at": started_at,
    }
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _authority_repository_disable_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        if (
            transaction["operation_id"] != operation_id
            or transaction["release"] != str(release)
            or transaction["release_digest"] != release_digest
            or transaction["plan"] != str(plan_path)
            or transaction["plan_document_sha256"] != plan_document_sha256
            or transaction["database"] != str(database)
            or transaction["repair_attestation"] != str(repair_attestation)
            or transaction["readiness"] != readiness_binding
            or transaction["maintenance"]["root"] != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError(
                "authority repository repair service journal belongs to another operation"
            )
    else:
        baseline = _systemd_service_state(command_status, unit)
        if baseline["active"] is not True:
            raise CutoverError(
                "authority repository repair requires the active legacy broker"
            )
        transaction = _authority_repository_disable_transaction(
            seal(
                AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_KIND,
                {
                    "operation_id": operation_id,
                    "release": str(release),
                    "release_digest": release_digest,
                    "plan": str(plan_path),
                    "plan_document_sha256": plan_document_sha256,
                    "database": str(database),
                    "service_unit": unit,
                    "service_baseline": baseline,
                    "readiness": readiness_binding,
                    "maintenance": planned_maintenance,
                    "repair_attestation": str(repair_attestation),
                    "created_at": started_at,
                },
            )
        )
        evidence_publisher(transaction_journal, transaction, uid=authority_uid)

    readiness_verifier = (
        _authority_repository_service_readiness_proof
        if service_readiness_verifier is None
        else service_readiness_verifier
    )

    def completed_repair() -> dict[str, object] | None:
        if not (repair_attestation.exists() or repair_attestation.is_symlink()):
            return None
        result = _validate_authority_repository_disable_result(
            evidence_reader(repair_attestation, uid=authority_uid)
        )
        if (
            result["plan_id"] != plan["plan_id"]
            or result["plan_document_sha256"] != plan_document_sha256
            or result["authority_database"] != str(database)
            or result["maintenance_deployment_id"] != maintenance_deployment_id
            or result["repository_id"] != plan["repository"]["repository_id"]
            or result["repository_state"] != "missing"
            or result["installation_status"] != "disabled"
            or result["startup_fenced"] is not True
            or result["enrollment_count"] != 0
        ):
            raise CutoverError("authority repository repair result changed")
        return result

    repair = completed_repair()
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        result = _authority_repository_disable_transaction_result(
            evidence_reader(transaction_attestation, uid=authority_uid),
            readiness=transaction["readiness"],
            authority_generation=str(plan["authority_generation"]),
        )
        state = _systemd_service_state(command_status, unit)
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        if (
            repair is None
            or result["operation_id"] != operation_id
            or result["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or result["repair_result_sha256"] != repair["document_sha256"]
            or result["release_digest"] != release_digest
            or result["database"] != str(database)
            or state != transaction["service_baseline"]
            or marker is not None
        ):
            raise CutoverError(
                "authority repository repair service result is contradictory"
            )
        current_readiness = _validate_authority_repository_service_readiness_proof(
            readiness_verifier(
                phase="authenticated",
                release=release,
                database=database,
                authority_uid=authority_uid,
                authority_generation=str(plan["authority_generation"]),
                binding=transaction["readiness"],
                now_reader=now_reader,
            ),
            phase="authenticated",
            binding=transaction["readiness"],
            generation=str(plan["authority_generation"]),
        )
        if (
            current_readiness["invariants"]["database_identity"]["device"]
            != result["readiness_proof"]["invariants"]["database_identity"]["device"]
            or current_readiness["invariants"]["database_identity"]["inode"]
            != result["readiness_proof"]["invariants"]["database_identity"]["inode"]
        ):
            raise CutoverError(
                "authority repository repair replay database identity changed"
            )
        return {"ok": True, "replayed": True, "attestation": result}

    repair_error: BaseException | None = None
    if repair is None:
        try:
            maintenance_activator(
                expected_uid=authority_uid,
                expected_gid=maintenance_gid,
                deployment_id=maintenance_deployment_id,
                scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
                message=PUBLIC_MAINTENANCE_MESSAGE,
                retry_after_seconds=5,
                started_at=str(transaction["maintenance"]["started_at"]),
                maintenance_root=maintenance_root,
            )
            state = _systemd_service_state(command_status, unit)
            if state["enabled"] != transaction["service_baseline"]["enabled"]:
                raise CutoverError("legacy broker enabled state changed")
            if state["active"] and command_status(
                ["/usr/bin/systemctl", "stop", unit]
            ) != 0:
                raise CutoverError("legacy broker did not stop behind maintenance")
            if _systemd_service_state(command_status, unit)["active"]:
                raise CutoverError("legacy broker remains active behind maintenance")
            options = dict(repairer_options or {})
            repairer(
                plan_path=plan_path,
                plan_document_sha256=plan_document_sha256,
                attestation=repair_attestation,
                maintenance_root=maintenance_root,
                maintenance_gid=maintenance_gid,
                maintenance_deployment_id=maintenance_deployment_id,
                authority_uid=authority_uid,
                maintenance_state_reader=maintenance_state_reader,
                **options,
            )
            repair = completed_repair()
            if repair is None:
                raise CutoverError(
                    "authority repository repair result was not published"
                )
        except BaseException as error:
            repair_error = error

    service_state = _systemd_service_state(command_status, unit)
    if service_state["enabled"] != transaction["service_baseline"]["enabled"]:
        raise CutoverError("legacy broker enabled state changed during repair")
    if not service_state["active"]:
        if command_status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise CutoverError(
                "legacy broker did not restart after authority repository repair"
            )
    if _systemd_service_state(command_status, unit) != transaction["service_baseline"]:
        raise CutoverError("legacy broker baseline was not restored")
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if marker is None:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(transaction["maintenance"]["started_at"]),
            maintenance_root=maintenance_root,
        )
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
    normalized = _normalize_maintenance_state(
        marker,
        root=maintenance_root,
        gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
    )
    if normalized != transaction["maintenance"]:
        raise CutoverError("authority repository repair maintenance marker changed")
    preclear = _validate_authority_repository_service_readiness_proof(
        readiness_verifier(
            phase="preclear",
            release=release,
            database=database,
            authority_uid=authority_uid,
            authority_generation=str(plan["authority_generation"]),
            binding=transaction["readiness"],
            now_reader=now_reader,
        ),
        phase="preclear",
        binding=transaction["readiness"],
        generation=str(plan["authority_generation"]),
    )
    maintenance_clearer(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
        maintenance_root=maintenance_root,
    )
    if maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    ) is not None:
        raise CutoverError(
            "authority repository repair maintenance marker did not clear"
        )
    try:
        readiness_proof = _validate_authority_repository_service_readiness_proof(
            readiness_verifier(
                phase="authenticated",
                release=release,
                database=database,
                authority_uid=authority_uid,
                authority_generation=str(plan["authority_generation"]),
                binding=transaction["readiness"],
                now_reader=now_reader,
            ),
            phase="authenticated",
            binding=transaction["readiness"],
            generation=str(plan["authority_generation"]),
        )
        if (
            readiness_proof["socket_identity"] != preclear["socket_identity"]
            or readiness_proof["socket_peer"] != preclear["socket_peer"]
            or readiness_proof["invariants"]["database_identity"]
            != preclear["invariants"]["database_identity"]
        ):
            raise CutoverError(
                "authority repository service changed across authenticated readiness"
            )
    except BaseException:
        maintenance_activator(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=str(transaction["maintenance"]["started_at"]),
            maintenance_root=maintenance_root,
        )
        raise
    if repair_error is not None:
        raise repair_error
    if repair is None:
        raise CutoverError("authority repository repair result was not published")
    result = _authority_repository_disable_transaction_result(
        seal(
            AUTHORITY_REPOSITORY_DISABLE_TRANSACTION_RESULT_KIND,
            {
                "operation_id": operation_id,
                "transaction_journal_sha256": transaction["document_sha256"],
                "repair_result_sha256": repair["document_sha256"],
                "release_digest": release_digest,
                "database": str(database),
                "service_unit": unit,
                "readiness_proof": readiness_proof,
                "service_restored": True,
                "maintenance_cleared": True,
                "completed_at": now_reader(),
            },
        ),
        readiness=transaction["readiness"],
        authority_generation=str(plan["authority_generation"]),
    )
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": result}


def _authority_repository_predecessor_binding(
    value: object,
) -> dict[str, object]:
    fields = {
        "transaction",
        "operation_id",
        "journal_sha256",
        "journal_document_sha256",
        "profile",
        "dropin",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError(
            "authority repository predecessor binding is invalid"
        )
    try:
        operation_id = str(uuid.UUID(str(value["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository predecessor operation is invalid"
        ) from error
    document = dict(value)
    document["operation_id"] = operation_id
    for field in ("transaction", "profile", "dropin"):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"authority repository predecessor {field}",
            )
        )
    if any(
        re.fullmatch(r"[0-9a-f]{64}", str(document[field])) is None
        for field in ("journal_sha256", "journal_document_sha256")
    ):
        raise CutoverError(
            "authority repository predecessor digest is invalid"
        )
    return document


def _authority_repository_lifecycle_recovery_transaction(
    value: object,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_KIND,
        fields=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository lifecycle transaction operation ID is invalid"
        ) from error
    for field in (
        "release",
        "canary_release",
        "plan",
        "database",
        "recovery_attestation",
    ):
        document[field] = str(
            _absolute(
                str(document[field]),
                f"authority repository lifecycle transaction {field}",
            )
        )
    if (
        re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["canary_release_digest"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["plan_document_sha256"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or not isinstance(document["created_at"], str)
        or not document["created_at"]
    ):
        raise CutoverError(
            "authority repository lifecycle transaction binding is invalid"
        )
    document["service_baseline"] = _validate_systemd_recovery_service_state(
        document["service_baseline"]
    )
    document["readiness"] = _authority_repository_service_readiness_binding(
        document["readiness"]
    )
    document["predecessor"] = _authority_repository_predecessor_binding(
        document["predecessor"]
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    return document


def _authority_repository_bound_predecessor_proof(
    value: object,
    *,
    transaction: Mapping[str, object],
    plan: Mapping[str, object],
    proof_validator=None,
) -> dict[str, object]:
    try:
        validator = proof_validator or (
            _load_schema12_bridge_verifier()._verify_successor_predecessor_proof
        )
        proof = validator(value)
    except Exception as error:
        raise CutoverError(
            "authority repository predecessor proof is invalid"
        ) from error
    if not isinstance(proof, Mapping):
        raise CutoverError("authority repository predecessor proof is invalid")
    predecessor = transaction["predecessor"]
    readiness = transaction["readiness"]
    legacy = proof.get("legacy_profile_repository")
    canary = proof.get("canary")
    authority = canary.get("authority") if isinstance(canary, Mapping) else None
    repository = canary.get("repository") if isinstance(canary, Mapping) else None
    bridge_journal = Path(str(proof.get("bridge_journal", "")))
    if (
        proof.get("operation_id") != predecessor["operation_id"]
        or bridge_journal.parent != Path(str(predecessor["transaction"]))
        or proof.get("bridge_journal_sha256") != predecessor["journal_sha256"]
        or proof.get("bridge_document_sha256")
        != predecessor["journal_document_sha256"]
        or proof.get("historical_client_release")
        != transaction["canary_release"]
        or proof.get("historical_client_release_digest")
        != transaction["canary_release_digest"]
        or proof.get("broker_release_digest")
        != transaction["canary_release_digest"]
        or proof.get("broker_release") == transaction["canary_release"]
        or proof.get("database") != transaction["database"]
        or proof.get("database_generation") != plan["authority_generation"]
        or proof.get("profile") != predecessor["profile"]
        or proof.get("broker_socket") != readiness["broker_socket"]
        or proof.get("dropin") != predecessor["dropin"]
        or not isinstance(legacy, Mapping)
        or legacy.get("client_uid") != readiness["canary_uid"]
        or legacy.get("repository_id") != readiness["canary_repository_id"]
        or legacy.get("canonical_root") != readiness["canary_project"]
        or legacy.get("generation")
        != readiness["canary_repository_generation"]
        or legacy.get("owner_uid_present") is not False
        or not isinstance(canary, Mapping)
        or canary.get("user") != readiness["canary_user"]
        or canary.get("uid") != readiness["canary_uid"]
        or canary.get("project") != readiness["canary_project"]
        or not isinstance(authority, Mapping)
        or authority.get("database_generation") != plan["authority_generation"]
        or authority.get("socket") != readiness["broker_socket"]
        or not isinstance(repository, Mapping)
        or repository.get("repository_id")
        != readiness["canary_repository_id"]
        or repository.get("canonical_root") != readiness["canary_project"]
        or repository.get("generation")
        != readiness["canary_repository_generation"]
    ):
        raise CutoverError(
            "authority repository predecessor proof binding changed"
        )
    return dict(proof)


def _authority_repository_lifecycle_recovery_transaction_result(
    value: object,
    *,
    transaction: Mapping[str, object] | None = None,
    plan: Mapping[str, object] | None = None,
    predecessor_proof_validator=None,
) -> dict[str, object]:
    document = verify_seal(
        value,
        kind=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_RESULT_KIND,
        fields=AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_RESULT_FIELDS,
    )
    try:
        document["operation_id"] = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository lifecycle result operation ID is invalid"
        ) from error
    document["database"] = str(
        _absolute(
            str(document["database"]),
            "authority repository lifecycle result database",
        )
    )
    document["maintenance"] = _authority_readiness_maintenance(
        document["maintenance"]
    )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(document["transaction_journal_sha256"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["recovery_result_sha256"])
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document["release_digest"])) is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(document["canary_release_digest"])
        )
        is None
        or document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not False
        or document["successor_handoff_required"] is not True
        or not isinstance(document["completed_at"], str)
        or not document["completed_at"]
    ):
        raise CutoverError("authority repository lifecycle result is invalid")
    if transaction is not None and plan is not None:
        document["preclear_readiness"] = (
            _validate_authority_repository_service_readiness_proof(
                document["preclear_readiness"],
                phase="preclear",
                binding=transaction["readiness"],
                generation=str(plan["authority_generation"]),
            )
        )
        if (
            document["preclear_readiness"]["invariants"]["state_revision"]
            < int(plan["target"]["state_revision"])
        ):
            raise CutoverError(
                "authority repository lifecycle preclear predates recovery"
            )
        document["predecessor_proof"] = (
            _authority_repository_bound_predecessor_proof(
                document["predecessor_proof"],
                transaction=transaction,
                plan=plan,
                proof_validator=predecessor_proof_validator,
            )
        )
    elif (
        not isinstance(document["predecessor_proof"], Mapping)
        or not isinstance(document["preclear_readiness"], Mapping)
    ):
        raise CutoverError(
            "authority repository lifecycle readiness evidence is unavailable"
        )
    return document


def recover_authority_repository_lifecycle(
    *,
    release: Path,
    canary_release: Path,
    predecessor_transaction: Path,
    predecessor_operation_id: str,
    predecessor_journal_sha256: str,
    predecessor_journal_document_sha256: str,
    predecessor_profile: Path,
    predecessor_dropin: Path,
    plan_path: Path,
    plan_document_sha256: str,
    recovery_attestation: Path,
    transaction_journal: Path,
    transaction_attestation: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    maintenance_deployment_id: str,
    operation_id: str,
    broker_socket: Path,
    canary_user: str,
    canary_uid: int,
    canary_project: Path,
    canary_repository_id: str,
    canary_repository_generation: int,
    readiness_wait_seconds: int = 30,
    authority_uid: int = 0,
    release_verifier=None,
    canary_release_verifier=None,
    command_status=_bounded_command_status,
    command_output=_bounded_command_output,
    service_state_reader=None,
    maintenance_activator=activate_maintenance,
    maintenance_clearer=clear_maintenance,
    maintenance_state_reader=load_maintenance_state,
    evidence_reader=read_private_json,
    evidence_publisher=_publish_evidence,
    effective_uid_reader=os.geteuid,
    now_reader=_now,
    recoverer=apply_authority_repository_lifecycle_recovery,
    recoverer_options: Mapping[str, object] | None = None,
    service_readiness_verifier=None,
    predecessor_verifier=None,
    predecessor_proof_validator=None,
    predecessor_preflight=None,
    predecessor_rearmer=None,
) -> dict[str, object]:
    """Recover partial authority state behind a stable maintenance fence."""

    if effective_uid_reader() != 0 or authority_uid != 0:
        raise CutoverError(
            "authority repository lifecycle service transaction must run as root"
        )
    try:
        operation_id = str(uuid.UUID(str(operation_id)))
        maintenance_deployment_id = str(uuid.UUID(str(maintenance_deployment_id)))
        predecessor_operation_id = str(
            uuid.UUID(str(predecessor_operation_id))
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError(
            "authority repository lifecycle transaction identity is invalid"
        ) from error
    release = _absolute(release, "authority repository lifecycle release")
    canary_release = _absolute(
        canary_release, "authority repository lifecycle canary release"
    )
    predecessor_transaction = _absolute(
        predecessor_transaction,
        "authority repository predecessor transaction",
    )
    predecessor_profile = _absolute(
        predecessor_profile, "authority repository predecessor profile"
    )
    predecessor_dropin = _absolute(
        predecessor_dropin, "authority repository predecessor drop-in"
    )
    plan_path = _absolute(plan_path, "authority repository lifecycle plan")
    recovery_attestation = _absolute(
        recovery_attestation, "authority repository lifecycle result"
    )
    transaction_journal = _absolute(
        transaction_journal, "authority repository lifecycle service journal"
    )
    transaction_attestation = _absolute(
        transaction_attestation, "authority repository lifecycle service result"
    )
    maintenance_root = _absolute(
        maintenance_root, "authority repository lifecycle maintenance root"
    )
    if len(
        {plan_path, recovery_attestation, transaction_journal, transaction_attestation}
    ) != 4:
        raise CutoverError(
            "authority repository lifecycle transaction paths must be distinct"
        )
    plan = _validate_authority_repository_lifecycle_recovery_plan(
        evidence_reader(plan_path, uid=authority_uid)
    )
    if (
        plan["authority_uid"] != authority_uid
        or re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None
        or plan["document_sha256"] != plan_document_sha256
        or plan["operation_id"] != operation_id
    ):
        mismatches = []
        if plan["authority_uid"] != authority_uid:
            mismatches.append("authority_uid")
        if re.fullmatch(r"[0-9a-f]{64}", plan_document_sha256 or "") is None:
            mismatches.append("plan_digest_format")
        elif plan["document_sha256"] != plan_document_sha256:
            mismatches.append("plan_digest")
        if plan["operation_id"] != operation_id:
            mismatches.append("operation_id")
        raise CutoverError(
            "authority repository lifecycle transaction plan binding changed: "
            + ",".join(mismatches)
        )
    database = _absolute(
        str(plan["authority_database"]),
        "authority repository lifecycle transaction database",
    )
    verifier = _load_release_verifier() if release_verifier is None else release_verifier
    verified_release = (
        verifier.verify_release(release)
        if hasattr(verifier, "verify_release")
        else verifier(release)
    )
    release_digest = str(verified_release.get("release_digest", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", release_digest) is None
        or not isinstance(verified_release.get("capabilities"), Mapping)
        or not all(verified_release["capabilities"].values())
        or (release_verifier is None and release != IMMUTABLE_RELEASE_ROOT / release_digest)
    ):
        raise CutoverError(
            "authority repository lifecycle transaction release is invalid"
        )
    if canary_release_verifier is None:
        try:
            verified_canary_release = _load_schema12_bridge_verifier().verify_release(
                canary_release, release_root=canary_release.parent
            )
        except Exception as error:
            raise CutoverError(
                "authority repository historical canary release is invalid"
            ) from error
    else:
        verified_canary_release = (
            canary_release_verifier.verify_release(canary_release)
            if hasattr(canary_release_verifier, "verify_release")
            else canary_release_verifier(canary_release)
        )
    canary_release_digest = str(
        verified_canary_release.get("release_digest", "")
        if isinstance(verified_canary_release, Mapping)
        else ""
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", canary_release_digest) is None
        or not isinstance(verified_canary_release, Mapping)
        or verified_canary_release.get("authority_schema_version") != 12
        or (
            canary_release_verifier is None
            and canary_release.name != canary_release_digest
        )
    ):
        raise CutoverError(
            "authority repository historical canary release is invalid"
        )
    readiness = _authority_repository_service_readiness_binding(
        {
            "broker_socket": str(broker_socket),
            "canary_user": canary_user,
            "canary_uid": canary_uid,
            "canary_project": str(canary_project),
            "canary_repository_id": canary_repository_id,
            "canary_repository_generation": canary_repository_generation,
            "wait_seconds": readiness_wait_seconds,
        }
    )
    predecessor = _authority_repository_predecessor_binding(
        {
            "transaction": str(predecessor_transaction),
            "operation_id": predecessor_operation_id,
            "journal_sha256": predecessor_journal_sha256,
            "journal_document_sha256": predecessor_journal_document_sha256,
            "profile": str(predecessor_profile),
            "dropin": str(predecessor_dropin),
        }
    )
    state_reader = service_state_reader or (
        lambda unit: _systemd_recovery_service_state(command_output, unit)
    )
    unit = "devcoordinator-broker.service"
    started_at = now_reader()
    planned_maintenance = {
        "root": str(maintenance_root),
        "gid": maintenance_gid,
        "deployment_id": maintenance_deployment_id,
        "message": PUBLIC_MAINTENANCE_MESSAGE,
        "retry_after_seconds": 5,
        "started_at": started_at,
    }
    if transaction_journal.exists() or transaction_journal.is_symlink():
        transaction = _authority_repository_lifecycle_recovery_transaction(
            evidence_reader(transaction_journal, uid=authority_uid)
        )
        if (
            transaction["operation_id"] != operation_id
            or transaction["release"] != str(release)
            or transaction["release_digest"] != release_digest
            or transaction["canary_release"] != str(canary_release)
            or transaction["canary_release_digest"] != canary_release_digest
            or transaction["plan"] != str(plan_path)
            or transaction["plan_document_sha256"] != plan_document_sha256
            or transaction["database"] != str(database)
            or transaction["recovery_attestation"] != str(recovery_attestation)
            or transaction["readiness"] != readiness
            or transaction["predecessor"] != predecessor
            or transaction["maintenance"]["root"] != str(maintenance_root)
            or transaction["maintenance"]["gid"] != maintenance_gid
            or transaction["maintenance"]["deployment_id"]
            != maintenance_deployment_id
        ):
            raise CutoverError(
                "authority repository lifecycle journal belongs to another operation"
            )
    else:
        baseline = _validate_systemd_recovery_service_state(state_reader(unit))
        transaction = _authority_repository_lifecycle_recovery_transaction(
            seal(
                AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_KIND,
                {
                    "operation_id": operation_id,
                    "release": str(release),
                    "release_digest": release_digest,
                    "canary_release": str(canary_release),
                    "canary_release_digest": canary_release_digest,
                    "plan": str(plan_path),
                    "plan_document_sha256": plan_document_sha256,
                    "database": str(database),
                    "service_unit": unit,
                    "service_baseline": baseline,
                    "readiness": readiness,
                    "predecessor": predecessor,
                    "maintenance": planned_maintenance,
                    "recovery_attestation": str(recovery_attestation),
                    "created_at": started_at,
                },
            )
        )
        evidence_publisher(transaction_journal, transaction, uid=authority_uid)

    readiness_verifier = (
        _authority_repository_service_readiness_proof
        if service_readiness_verifier is None
        else service_readiness_verifier
    )

    bridge_module = None
    if (
        predecessor_verifier is None
        or predecessor_proof_validator is None
        or predecessor_preflight is None
        or predecessor_rearmer is None
    ):
        bridge_module = _load_schema12_bridge_verifier()
    active_predecessor_verifier = (
        bridge_module._verify_active_predecessor_for_successor
        if predecessor_verifier is None
        else predecessor_verifier
    )
    active_predecessor_validator = (
        bridge_module._verify_successor_predecessor_proof
        if predecessor_proof_validator is None
        else predecessor_proof_validator
    )
    lifecycle_predecessor_preflight = (
        bridge_module._preflight_lifecycle_predecessor
        if predecessor_preflight is None
        else predecessor_preflight
    )
    lifecycle_predecessor_rearmer = (
        bridge_module._rearm_restored_predecessor_for_lifecycle
        if predecessor_rearmer is None
        else predecessor_rearmer
    )

    predecessor_call = {
        "transaction": predecessor_transaction,
        "operation_id": predecessor_operation_id,
        "expected_journal_sha256": predecessor_journal_sha256,
        "expected_journal_document_sha256": (
            predecessor_journal_document_sha256
        ),
        "historical_client_release": canary_release,
        "database": database,
        "profile": predecessor_profile,
        "broker_socket": Path(str(readiness["broker_socket"])),
        "dropin": predecessor_dropin,
        "expected_database_generation": str(plan["authority_generation"]),
        "canary_user": str(readiness["canary_user"]),
        "expected_canary_uid": int(readiness["canary_uid"]),
        "canary_project": Path(str(readiness["canary_project"])),
        "canary_repository_id": str(readiness["canary_repository_id"]),
        "canary_repository_generation": int(
            readiness["canary_repository_generation"]
        ),
        "expected_uid": authority_uid,
    }
    predecessor_rearm_journal = transaction_journal.with_name(
        "lifecycle-predecessor-rearm.json"
    )

    try:
        predecessor_state = lifecycle_predecessor_preflight(
            **predecessor_call,
            _allow_rearmed_dropin=(
                predecessor_rearm_journal.exists()
                or predecessor_rearm_journal.is_symlink()
            ),
        )
    except Exception as error:
        raw_detail = str(error)
        detail = " ".join(raw_detail.replace("\x00", "").split())[:480]
        if not detail:
            detail = type(error).__name__
        raise CutoverError(
            f"authority repository predecessor preflight failed: {detail}"
        ) from error
    predecessor_mode = (
        predecessor_state.get("mode")
        if isinstance(predecessor_state, Mapping)
        else None
    )
    if predecessor_mode not in {"ready", "restored"}:
        raise CutoverError(
            "authority repository predecessor state is unsupported"
        )

    def bind_predecessor_proof(proof: object) -> dict[str, object]:
        return _authority_repository_bound_predecessor_proof(
            proof,
            transaction=transaction,
            plan=plan,
            proof_validator=active_predecessor_validator,
        )

    def prove_predecessor() -> dict[str, object]:
        try:
            proof = active_predecessor_verifier(
                **predecessor_call,
                wait_seconds=int(readiness["wait_seconds"]),
            )
        except Exception as error:
            raise CutoverError(
                "authority repository exact predecessor proof failed"
            ) from error
        return bind_predecessor_proof(proof)

    def rearm_predecessor(*, terminal_bound: bool = False) -> dict[str, object]:
        try:
            proof = lifecycle_predecessor_rearmer(
                outer_operation_id=operation_id,
                outer_transaction_journal=transaction_journal,
                outer_transaction_document_sha256=transaction[
                    "document_sha256"
                ],
                rearm_journal=predecessor_rearm_journal,
                **predecessor_call,
                wait_seconds=int(readiness["wait_seconds"]),
                terminal_bound=terminal_bound,
            )
        except Exception as error:
            raw_detail = str(error)
            detail = " ".join(raw_detail.replace("\x00", "").split())[:480]
            if not detail:
                detail = type(error).__name__
            raise CutoverError(
                "authority repository restored predecessor rearm failed: "
                + detail
            ) from error
        return bind_predecessor_proof(proof)

    def completed_recovery() -> dict[str, object] | None:
        if not (recovery_attestation.exists() or recovery_attestation.is_symlink()):
            return None
        result = _validate_authority_repository_lifecycle_recovery_result(
            evidence_reader(recovery_attestation, uid=authority_uid)
        )
        if (
            result["plan_id"] != plan["plan_id"]
            or result["operation_id"] != operation_id
            or result["plan_document_sha256"] != plan_document_sha256
            or result["authority_database"] != str(database)
            or result["maintenance_deployment_id"] != maintenance_deployment_id
            or result["repository_id"] != plan["repository"]["repository_id"]
            or result["repository_state"] != "active"
            or result["installation_status"] != "installed"
            or result["startup_fenced"] is not False
        ):
            raise CutoverError("authority repository lifecycle result changed")
        return result

    recovery = completed_recovery()
    initial_predecessor_proof = (
        prove_predecessor() if predecessor_mode == "ready" else None
    )
    if transaction_attestation.exists() or transaction_attestation.is_symlink():
        result = _authority_repository_lifecycle_recovery_transaction_result(
            evidence_reader(transaction_attestation, uid=authority_uid),
            transaction=transaction,
            plan=plan,
            predecessor_proof_validator=active_predecessor_validator,
        )
        marker = maintenance_state_reader(
            expected_uid=authority_uid,
            expected_gid=maintenance_gid,
            maintenance_root=maintenance_root,
        )
        service = _validate_systemd_recovery_service_state(state_reader(unit))
        if (
            recovery is None
            or result["operation_id"] != operation_id
            or result["transaction_journal_sha256"]
            != transaction["document_sha256"]
            or result["recovery_result_sha256"] != recovery["document_sha256"]
            or result["release_digest"] != release_digest
            or result["canary_release_digest"] != canary_release_digest
            or result["database"] != str(database)
            or result["maintenance"] != transaction["maintenance"]
            or not _systemd_recovery_service_is_healthy(service)
            or _normalize_maintenance_state(
                marker,
                root=maintenance_root,
                gid=maintenance_gid,
                deployment_id=maintenance_deployment_id,
            )
            != transaction["maintenance"]
        ):
            raise CutoverError(
                "authority repository lifecycle service result is contradictory"
            )
        if predecessor_mode == "restored":
            replay_predecessor = rearm_predecessor(terminal_bound=True)
        else:
            replay_predecessor = prove_predecessor()
        replay_preclear = _validate_authority_repository_service_readiness_proof(
            readiness_verifier(
                phase="preclear",
                release=canary_release,
                database=database,
                authority_uid=authority_uid,
                authority_generation=str(plan["authority_generation"]),
                binding=transaction["readiness"],
                now_reader=now_reader,
            ),
            phase="preclear",
            binding=transaction["readiness"],
            generation=str(plan["authority_generation"]),
        )
        if (
            _authority_repository_readiness_stable_binding(replay_preclear)
            != _authority_repository_readiness_stable_binding(
                result["preclear_readiness"]
            )
            or replay_predecessor["socket_identity"]
            != replay_preclear["socket_identity"]
            or replay_predecessor["socket_peer"]
            != replay_preclear["socket_peer"]
        ):
            raise CutoverError(
                "authority repository lifecycle readiness changed after handoff"
            )
        return {"ok": True, "replayed": True, "attestation": result}

    maintenance_activator(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        deployment_id=maintenance_deployment_id,
        scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
        message=PUBLIC_MAINTENANCE_MESSAGE,
        retry_after_seconds=5,
        started_at=str(transaction["maintenance"]["started_at"]),
        maintenance_root=maintenance_root,
    )
    marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if (
        _normalize_maintenance_state(
            marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        != transaction["maintenance"]
    ):
        raise CutoverError("authority repository lifecycle maintenance marker changed")
    service_before_recovery = _validate_systemd_recovery_service_state(
        state_reader(unit)
    )
    predecessor_proof: dict[str, object] | None = None
    can_fast_forward = (
        recovery is not None
        and _systemd_recovery_service_is_healthy(service_before_recovery)
    )
    if can_fast_forward:
        # A crash after the repository commit and predecessor rearm must not
        # manufacture another stop/start cycle merely to publish the missing
        # outer handoff. Re-prove the exact live predecessor in place, then
        # seal its current revision below.
        predecessor_proof = (
            rearm_predecessor()
            if predecessor_mode == "restored"
            else initial_predecessor_proof
        )
    else:
        if command_status(["/usr/bin/systemctl", "stop", unit]) != 0:
            raise CutoverError("legacy broker did not stop behind maintenance")
        stopped = _validate_systemd_recovery_service_state(state_reader(unit))
        if not _systemd_recovery_service_is_stopped(stopped):
            raise CutoverError("legacy broker remains active behind maintenance")
        if recovery is None:
            options = dict(recoverer_options or {})
            recoverer(
                plan_path=plan_path,
                plan_document_sha256=plan_document_sha256,
                attestation=recovery_attestation,
                maintenance_root=maintenance_root,
                maintenance_gid=maintenance_gid,
                maintenance_deployment_id=maintenance_deployment_id,
                authority_uid=authority_uid,
                maintenance_state_reader=maintenance_state_reader,
                **options,
            )
            recovery = completed_recovery()
        if recovery is None:
            raise CutoverError(
                "authority repository lifecycle result was not published"
            )
        if predecessor_mode == "restored":
            predecessor_proof = rearm_predecessor()
        elif command_status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise CutoverError(
                "legacy broker did not restart after lifecycle recovery"
            )
    preclear = _validate_authority_repository_service_readiness_proof(
        readiness_verifier(
            phase="preclear",
            release=canary_release,
            database=database,
            authority_uid=authority_uid,
            authority_generation=str(plan["authority_generation"]),
            binding=transaction["readiness"],
            now_reader=now_reader,
        ),
        phase="preclear",
        binding=transaction["readiness"],
        generation=str(plan["authority_generation"]),
    )
    healthy = _validate_systemd_recovery_service_state(state_reader(unit))
    if not _systemd_recovery_service_is_healthy(healthy):
        raise CutoverError("legacy broker is not healthy after lifecycle recovery")
    predecessor_proof = (
        predecessor_proof
        if predecessor_proof is not None
        else prove_predecessor()
    )
    if (
        initial_predecessor_proof is not None
        and _authority_repository_bound_predecessor_proof(
            initial_predecessor_proof,
            transaction=transaction,
            plan=plan,
            proof_validator=active_predecessor_validator,
        )["bridge_journal_sha256"]
        != predecessor_proof["bridge_journal_sha256"]
    ):
        raise CutoverError("authority repository predecessor identity changed")
    final_service = _validate_systemd_recovery_service_state(state_reader(unit))
    final_marker = maintenance_state_reader(
        expected_uid=authority_uid,
        expected_gid=maintenance_gid,
        maintenance_root=maintenance_root,
    )
    if (
        not _systemd_recovery_service_is_healthy(final_service)
        or _normalize_maintenance_state(
            final_marker,
            root=maintenance_root,
            gid=maintenance_gid,
            deployment_id=maintenance_deployment_id,
        )
        != transaction["maintenance"]
        or predecessor_proof["socket_identity"] != preclear["socket_identity"]
        or predecessor_proof["socket_peer"] != preclear["socket_peer"]
    ):
        raise CutoverError(
            "authority repository predecessor readiness changed before handoff"
        )
    result = _authority_repository_lifecycle_recovery_transaction_result(
        seal(
            AUTHORITY_REPOSITORY_LIFECYCLE_RECOVERY_TRANSACTION_RESULT_KIND,
            {
                "operation_id": operation_id,
                "transaction_journal_sha256": transaction["document_sha256"],
                "recovery_result_sha256": recovery["document_sha256"],
                "release_digest": release_digest,
                "canary_release_digest": canary_release_digest,
                "database": str(database),
                "service_unit": unit,
                "maintenance": transaction["maintenance"],
                "predecessor_proof": predecessor_proof,
                "preclear_readiness": preclear,
                "service_restored": True,
                "maintenance_cleared": False,
                "successor_handoff_required": True,
                "completed_at": now_reader(),
            },
        ),
        transaction=transaction,
        plan=plan,
        predecessor_proof_validator=active_predecessor_validator,
    )
    evidence_publisher(transaction_attestation, result, uid=authority_uid)
    return {"ok": True, "replayed": False, "attestation": result}


IMPORT_FIELDS = frozenset(
    {
        "migration_id",
        "pass_kind",
        "authority_generation",
        "watermark_fingerprint",
        "export_fingerprint",
        "test_store_generation",
        "chunk_count",
        "final_chunk_sha256",
        "run_count",
        "case_count",
        "destination_projection_chain_sha256",
        "source_retained",
    }
)
SEAL_FIELDS = frozenset(
    {
        "migration_id",
        "authority_database",
        "authority_generation",
        "test_database",
        "test_store_generation",
        "drain_proof_fingerprint",
        "final_export_fingerprint",
        "final_watermark_fingerprint",
        "destination_attestation_fingerprint",
        "legacy_source_retained",
        "activation_ready",
        "rollback",
    }
)
DELEGATION_FIELDS = frozenset(
    {
        "api_uid",
        "broker_account_id",
        "source_authority_generation",
        "authority_generation",
        "profile_fingerprint",
        "profile_path",
        "profile_owner_uid",
        "profile_group_name",
        "profile_group_gid",
        "profile_mode",
        "profile_source_kind",
        "profile_source_sha256",
        "profile_authority_reconciled",
        "profile_generation_matches_authority",
        "atomic_publication_verified",
        "existing_profile_contents_reused",
        "google_actor_prefix",
        "google_actor_policy",
        "repository_grants",
        "broker_verified",
        "created_at",
    }
)
CANDIDATE_FIELDS = frozenset(
    {
        "release_digest",
        "ready_units",
        "service_uids",
        "service_slices",
        "socket_inodes",
        "authority_database",
        "test_database",
        "migration_seal_sha256",
        "checks_passed",
        "test_capability_policy",
        "preparation",
        "created_at",
    }
)
CANDIDATE_PREPARATION_FIELDS = frozenset(
    {
        "release_digest",
        "executor_release",
        "credential_preflight_sha256",
        "host_preflight_sha256",
        "background_config",
        "project_isolation",
        "console_slot_ports",
        "prior_units",
        "prior_files",
        "installed_files",
        "ready_units",
        "socket_inodes",
        "created_at",
    }
)
CAPABILITY_POLICY_FIELDS = frozenset(
    {
        "policy_path",
        "policy_owner_uid",
        "policy_mode",
        "policy_file_sha256",
        "policy_fingerprint",
        "authority_generation",
        "authority_export_sha256",
        "dogfood_repository_id",
        "repository_grants",
        "coverage_complete",
        "broker_contract_verified",
        "created_at",
    }
)
AUTHORITY_REPOSITORY_EXPORT_FIELDS = frozenset(
    {"authority_generation", "repositories", "exported_at"}
)
ACTIVATION_FIELDS = frozenset(
    {
        "release_digest",
        "migration_seal_sha256",
        "profile_inventory_readiness_sha256",
        "executor_release",
        "credential_preflight_sha256",
        "publication_switch",
        "continuity_probe",
        "socket_inodes_before",
        "socket_inodes_after",
        "connection_refused_count",
        "project_route_failures",
        "legacy_units_active",
        "authority_ready",
        "testd_ready",
        "console_ready",
        "browser_lcp_attestation_sha256",
        "browser_lcp_consumption_sha256",
        "created_at",
    }
)
RETENTION_FIELDS = frozenset(
    {
        "authority_backup_sha256",
        "test_backup_sha256",
        "legacy_source_retained",
        "retain_until",
        "rollback_rehearsal_sha256",
        "live_rollback_rehearsal_sha256",
        "profile_inventory_readiness_sha256",
        "profile_inventory_reverification",
        "browser_lcp_attestation_sha256",
        "browser_lcp_consumption_sha256",
        "created_at",
    }
)
CONTINUITY_PROBE_FIELDS = frozenset(
    {
        "operation_id",
        "release_digest",
        "started_at",
        "completed_at",
        "sample_interval_ms",
        "round_count",
        "sample_count",
        "http_sample_count",
        "websocket_sample_count",
        "connection_refused_count",
        "project_route_failures",
        "failed_sample_count",
        "ttfb_p99_ms",
        "control_plane_p99_ms",
        "targets",
        "samples_sha256",
        "slo",
        "passed",
    }
)
ROLLBACK_REHEARSAL_FIELDS = frozenset(
    {
        "operation_id",
        "activation_sha256",
        "executor_release",
        "authority_backup_sha256",
        "test_backup_sha256",
        "restores",
        "publication_inverse_plan",
        "continuity_probe_sha256",
        "legacy_source_retained",
        "private_scratch",
        "rehearsed_at",
    }
)
LIVE_ROLLBACK_REHEARSAL_FIELDS = frozenset(
    {
        "operation_id",
        "activation_sha256",
        "activation_state_generation",
        "release_digest",
        "executor_release",
        "journal_sha256",
        "publication_before",
        "rollback_slot",
        "rollback_switch",
        "publication_rollback",
        "rollback_continuity_probe",
        "reactivation_slot",
        "reactivation_switch",
        "publication_reactivated",
        "reactivation_continuity_probe",
        "supported_rollback_head",
        "socket_inodes_before",
        "socket_inodes_after",
        "continuity_probe",
        "profile_health",
        "data_health",
        "recovery_count",
        "browser_lcp_attestation_sha256",
        "browser_lcp_consumption_sha256",
        "completed_at",
    }
)
ROLLBACK_FIELDS = frozenset(
    {
        "activation_sha256",
        "executor_release",
        "credential_preflight_sha256",
        "publication_switch",
        "authority_backup_sha256",
        "test_backup_sha256",
        "socket_inodes_before",
        "socket_inodes_after",
        "connection_refused_count",
        "legacy_authority_ready",
        "created_at",
    }
)


def _socket_map(value: object) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) != SOCKET_NAMES
        or any(type(item) is not int or item <= 0 for item in value.values())
    ):
        raise CutoverError("socket inode evidence is invalid")
    normalized = {str(key): int(item) for key, item in value.items()}
    if len(set(normalized.values())) != len(normalized):
        raise CutoverError("socket inode evidence reuses one listener identity")
    return normalized


def _continuity_probe(
    value: object, *, expected_release: str | None = None
) -> dict[str, object]:
    """Verify one bounded HTTP/WebSocket continuity and SLO window."""

    evidence = verify_seal(
        value,
        kind=CONTINUITY_PROBE_KIND,
        fields=CONTINUITY_PROBE_FIELDS,
    )
    try:
        evidence["operation_id"] = str(uuid.UUID(str(evidence["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise CutoverError("continuity probe operation ID is invalid") from error
    targets = evidence["targets"]
    slo = evidence["slo"]
    if (
        (expected_release is not None and evidence["release_digest"] != expected_release)
        or re.fullmatch(r"[0-9a-f]{64}", str(evidence["release_digest"])) is None
        or not isinstance(targets, list)
        or not targets
        or len(targets) > 1024
        or not isinstance(slo, Mapping)
        or set(slo)
        != {
            "ttfb_p99_ms",
            "control_plane_p99_ms",
            "minimum_rounds",
        }
        or any(type(slo[key]) is not int or int(slo[key]) <= 0 for key in slo)
    ):
        raise CutoverError("continuity probe contract is invalid")
    identifiers: list[str] = []
    protocols: set[str] = set()
    target_samples = 0
    target_failures = 0
    protocol_samples = {"http": 0, "websocket": 0}
    for target in targets:
        parsed_target = (
            urlparse(str(target.get("url", "")))
            if isinstance(target, Mapping)
            else None
        )
        if (
            not isinstance(target, Mapping)
            or set(target)
            != {
                "target_id",
                "protocol",
                "category",
                "url",
                "baseline_status",
                "last_status",
                "sample_count",
                "failure_count",
                "max_latency_ms",
            }
            or not isinstance(target["target_id"], str)
            or not target["target_id"]
            or target["protocol"] not in {"http", "websocket"}
            or target["category"] not in {"console", "api", "project"}
            or not isinstance(target["url"], str)
            or target["target_id"]
            != f"{target['protocol']}:{target['url']}"
            or parsed_target is None
            or parsed_target.scheme
            != ("https" if target["protocol"] == "http" else "wss")
            or not parsed_target.hostname
            or parsed_target.username is not None
            or parsed_target.password is not None
            or type(target["sample_count"]) is not int
            or int(target["sample_count"]) < 2
            or type(target["failure_count"]) is not int
            or int(target["failure_count"]) < 0
            or int(target["failure_count"]) > int(target["sample_count"])
            or type(target["max_latency_ms"]) not in {int, float}
            or float(target["max_latency_ms"]) < 0
            or (
                target["baseline_status"] is not None
                and (
                    type(target["baseline_status"]) is not int
                    or not 100 <= int(target["baseline_status"]) <= 599
                )
            )
            or (
                target["last_status"] is not None
                and (
                    type(target["last_status"]) is not int
                    or not 100 <= int(target["last_status"]) <= 599
                )
            )
        ):
            raise CutoverError("continuity probe target summary is invalid")
        identifiers.append(str(target["target_id"]))
        protocols.add(str(target["protocol"]))
        target_samples += int(target["sample_count"])
        target_failures += int(target["failure_count"])
        protocol_samples[str(target["protocol"])] += int(target["sample_count"])
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise CutoverError("continuity probe targets are not canonical")
    integer_fields = (
        "sample_interval_ms",
        "round_count",
        "sample_count",
        "http_sample_count",
        "websocket_sample_count",
        "connection_refused_count",
        "project_route_failures",
        "failed_sample_count",
        "ttfb_p99_ms",
        "control_plane_p99_ms",
    )
    if (
        protocols != {"http", "websocket"}
        or any(type(evidence[key]) is not int or int(evidence[key]) < 0 for key in integer_fields)
        or int(evidence["sample_interval_ms"]) < 10
        or int(evidence["sample_interval_ms"]) > 10_000
        or int(evidence["round_count"]) < int(slo["minimum_rounds"])
        or any(
            int(target["sample_count"]) != int(evidence["round_count"])
            for target in targets
        )
        or int(evidence["sample_count"]) != target_samples
        or int(evidence["http_sample_count"]) != protocol_samples["http"]
        or int(evidence["websocket_sample_count"])
        != protocol_samples["websocket"]
        or int(evidence["failed_sample_count"]) != target_failures
        or int(evidence["connection_refused_count"])
        > int(evidence["failed_sample_count"])
        or int(evidence["project_route_failures"])
        > int(evidence["failed_sample_count"])
        or re.fullmatch(r"[0-9a-f]{64}", str(evidence["samples_sha256"])) is None
        or evidence["passed"] is not True
        or int(evidence["connection_refused_count"]) != 0
        or int(evidence["project_route_failures"]) != 0
        or int(evidence["failed_sample_count"]) != 0
        or int(evidence["ttfb_p99_ms"]) > int(slo["ttfb_p99_ms"])
        or int(evidence["control_plane_p99_ms"])
        > int(slo["control_plane_p99_ms"])
    ):
        raise CutoverError("continuity probe did not satisfy its sealed SLO")
    timestamps: dict[str, datetime] = {}
    for field in ("started_at", "completed_at"):
        try:
            parsed = datetime.fromisoformat(str(evidence[field]).replace("Z", "+00:00"))
        except ValueError as error:
            raise CutoverError("continuity probe timestamp is invalid") from error
        if parsed.tzinfo is None:
            raise CutoverError("continuity probe timestamp lacks a timezone")
        timestamps[field] = parsed
    if timestamps["completed_at"] < timestamps["started_at"]:
        raise CutoverError("continuity probe completion precedes its start")
    return evidence


def _publication_switch(
    value: object,
    *,
    expected_release: str,
) -> dict[str, object]:
    if isinstance(value, Mapping) and value.get("mode") == "first-adoption-bootstrap":
        fields = {
            "mode",
            "previous_generation",
            "generation",
            "previous_payload_sha256",
            "payload_sha256",
            "previous_release_digest",
            "release_digest",
            "previous_port",
            "port",
            "retained_routes_sha256",
            "handoff_journal_sha256",
        }
        result = dict(value)
        if (
            set(result) != fields
            or result["previous_generation"] != 0
            or result["generation"] != 1
            or result["previous_payload_sha256"] is not None
            or result["previous_release_digest"] is not None
            or result["previous_port"] is not None
            or re.fullmatch(r"[0-9a-f]{64}", str(result["payload_sha256"])) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(result["release_digest"])) is None
            or result["release_digest"] != expected_release
            or type(result["port"]) is not int
            or not 30000 <= int(result["port"]) <= 60999
            or re.fullmatch(r"[0-9a-f]{64}", str(result["retained_routes_sha256"]))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", str(result["handoff_journal_sha256"]))
            is None
        ):
            raise CutoverError("first-adoption publication continuity evidence is invalid")
        return result
    fields = {
        "previous_generation",
        "generation",
        "previous_payload_sha256",
        "payload_sha256",
        "previous_release_digest",
        "release_digest",
        "previous_port",
        "port",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("publication switch evidence is invalid")
    result = dict(value)
    for field in ("previous_payload_sha256", "payload_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(result[field])) is None:
            raise CutoverError("publication switch digest evidence is invalid")
    for field in ("previous_release_digest", "release_digest"):
        if re.fullmatch(r"[0-9a-f]{64}", str(result[field])) is None:
            raise CutoverError("publication switch release evidence is invalid")
    if (
        type(result["previous_generation"]) is not int
        or type(result["generation"]) is not int
        or int(result["previous_generation"]) < 1
        or int(result["generation"]) != int(result["previous_generation"]) + 1
        or type(result["previous_port"]) is not int
        or type(result["port"]) is not int
        or not 30000 <= int(result["previous_port"]) <= 60999
        or not 30000 <= int(result["port"]) <= 60999
        or result["previous_payload_sha256"] == result["payload_sha256"]
        or result["previous_release_digest"] == result["release_digest"]
        or result["release_digest"] != expected_release
    ):
        raise CutoverError("publication switch continuity evidence is invalid")
    return result


def _live_rehearsal_publication(value: object) -> dict[str, object]:
    fields = {
        "generation",
        "payload_sha256",
        "release_digest",
        "port",
        "routing_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("live rehearsal publication summary is invalid")
    result = dict(value)
    if (
        type(result["generation"]) is not int
        or int(result["generation"]) < 1
        or re.fullmatch(r"[0-9a-f]{64}", str(result["payload_sha256"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(result["release_digest"]))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(result["routing_sha256"]))
        is None
        or type(result["port"]) is not int
        or not 30000 <= int(result["port"]) <= 60999
    ):
        raise CutoverError("live rehearsal publication summary is invalid")
    return result


def _live_rehearsal_slot(value: object, *, target_release: str) -> dict[str, object]:
    fields = {
        "target_release_digest",
        "target_port",
        "target_mode",
        "old_release_digest",
        "old_port",
        "old_mode",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CutoverError("live rehearsal slot evidence is invalid")
    result = dict(value)
    if (
        result["target_release_digest"] != target_release
        or result["target_mode"] != "active"
        or result["old_mode"] != "standby"
        or re.fullmatch(r"[0-9a-f]{64}", str(result["old_release_digest"]))
        is None
        or result["old_release_digest"] == target_release
        or type(result["target_port"]) is not int
        or type(result["old_port"]) is not int
        or not 30000 <= int(result["target_port"]) <= 60999
        or not 30000 <= int(result["old_port"]) <= 60999
    ):
        raise CutoverError("live rehearsal slot evidence is invalid")
    return result


def _candidate_units(release_digest: str) -> frozenset[str]:
    if re.fullmatch(r"[0-9a-f]{64}", release_digest) is None:
        raise CutoverError("candidate release digest is invalid")
    return REQUIRED_READY_UNITS | {
        f"devcoordinator-console@{release_digest}.service"
    }


def _candidate_service_identity(
    value: Mapping[str, object],
    *,
    release_digest: str,
    authority_uid: int,
    testd_uid: int,
    api_uid: int,
) -> None:
    units = _candidate_units(release_digest)
    raw_uids = value.get("service_uids")
    raw_slices = value.get("service_slices")
    if (
        not isinstance(raw_uids, Mapping)
        or not isinstance(raw_slices, Mapping)
        or set(raw_uids) != units
        or set(raw_slices) != units
    ):
        raise CutoverError("candidate service identity evidence is incomplete")
    console = f"devcoordinator-console@{release_digest}.service"
    required_slices = {
        "devcoordinator-edge.service": CONTROL_SLICE,
        "devcoordinator-api.service": CONTROL_SLICE,
        "devcoordinator-authority.service": CONTROL_SLICE,
        console: CONTROL_SLICE,
        "devcoordinator-observer.service": BACKGROUND_SLICE,
        "devcoordinator-testd.service": BACKGROUND_SLICE,
        "devcoordinator-test-snapshotd.service": BACKGROUND_SLICE,
    }
    if dict(raw_slices) != required_slices:
        raise CutoverError("candidate service slices contradict the protected topology")
    if any(type(item) is not int or item < 0 for item in raw_uids.values()):
        raise CutoverError("candidate service UID evidence is invalid")
    if (
        raw_uids["devcoordinator-authority.service"] != authority_uid
        or raw_uids["devcoordinator-testd.service"] != testd_uid
        or raw_uids["devcoordinator-api.service"] != api_uid
        or raw_uids["devcoordinator-test-snapshotd.service"] != 0
        or any(
            int(raw_uids[unit]) <= 0
            for unit in (
                "devcoordinator-edge.service",
                "devcoordinator-api.service",
                console,
                "devcoordinator-observer.service",
                "devcoordinator-testd.service",
            )
        )
    ):
        raise CutoverError("candidate service UIDs contradict the cutover plan")
    dedicated = {
        int(raw_uids[unit])
        for unit in (
            "devcoordinator-edge.service",
            "devcoordinator-api.service",
            console,
            "devcoordinator-observer.service",
            "devcoordinator-testd.service",
        )
    }
    if len(dedicated) != 5:
        raise CutoverError("candidate dedicated services share an operating-system UID")


def _capability_policy_attestation(
    value: object,
    *,
    delegation: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CutoverError("candidate capability policy evidence is missing")
    policy = verify_seal(
        value,
        kind=CAPABILITY_POLICY_KIND,
        fields=CAPABILITY_POLICY_FIELDS,
    )
    if (
        policy["policy_path"] != TEST_CAPABILITY_POLICY_PATH
        or policy["policy_owner_uid"] != 0
        or policy["policy_mode"] != "0600"
        or re.fullmatch(r"[0-9a-f]{64}", str(policy["policy_file_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(policy["policy_fingerprint"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(policy["authority_export_sha256"])) is None
        or policy["authority_generation"] != delegation["authority_generation"]
        or policy["coverage_complete"] is not True
        or policy["broker_contract_verified"] is not True
        or not isinstance(policy["dogfood_repository_id"], str)
        or not policy["dogfood_repository_id"]
    ):
        raise CutoverError("candidate capability policy metadata is invalid")
    grants = policy["repository_grants"]
    if not isinstance(grants, list) or not grants or len(grants) > 10_000:
        raise CutoverError("candidate capability policy grants are invalid")
    repository_ids: list[str] = []
    dogfood = None
    capability_pattern = re.compile(
        r"^(?:network\.(?:loopback|host-loopback|external)|fixture\.[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}|credential\.[a-z][a-z0-9_.-]{0,127})$"
    )
    for grant in grants:
        if (
            not isinstance(grant, Mapping)
            or set(grant)
            != {
                "repository_id",
                "generation",
                "setup_status",
                "manifest_fingerprint",
                "requested",
                "granted",
            }
            or not isinstance(grant["repository_id"], str)
            or not grant["repository_id"]
            or type(grant["generation"]) is not int
            or int(grant["generation"]) < 0
            or grant["setup_status"] not in {"ready", "missing", "invalid"}
            or (
                grant["setup_status"] == "ready"
                and re.fullmatch(r"[0-9a-f]{64}", str(grant["manifest_fingerprint"])) is None
            )
            or (
                grant["setup_status"] != "ready"
                and grant["manifest_fingerprint"] is not None
            )
            or not isinstance(grant["requested"], list)
            or not isinstance(grant["granted"], list)
            or any(
                not isinstance(item, str) or capability_pattern.fullmatch(item) is None
                for item in grant["requested"]
            )
            or grant["requested"] != sorted(set(grant["requested"]))
            or grant["granted"] != grant["requested"]
        ):
            raise CutoverError("candidate capability policy grant is invalid")
        repository_id = str(grant["repository_id"])
        repository_ids.append(repository_id)
        if repository_id == policy["dogfood_repository_id"]:
            dogfood = grant
    if len(repository_ids) != len(set(repository_ids)):
        raise CutoverError("candidate capability policy repeats a repository")
    delegated_ids = {
        str(item["repository_id"])
        for item in delegation["repository_grants"]  # type: ignore[union-attr]
    }
    if set(repository_ids) != delegated_ids:
        raise CutoverError("candidate capability policy does not cover every delegated repository")
    if (
        dogfood is None
        or dogfood["setup_status"] != "ready"
        or "network.loopback" not in dogfood["granted"]
    ):
        raise CutoverError("candidate dogfood test capability is incomplete")
    return policy


def _normalize_replay(
    evidence_kind: str, evidence: Mapping[str, object]
) -> dict[str, object]:
    sealed = {
        "authority-backup": (BACKUP_KIND, BACKUP_FIELDS),
        "testd-backup": (BACKUP_KIND, BACKUP_FIELDS),
        "initial-import": (INITIAL_IMPORT_KIND, IMPORT_FIELDS),
        "final-import": (INITIAL_IMPORT_KIND, IMPORT_FIELDS),
        "migration-seal": (SEAL_KIND, SEAL_FIELDS),
        "test-history-discard": (SCHEMA_READINESS_KIND, SCHEMA_READINESS_FIELDS),
        "api-delegation": (DELEGATION_KIND, DELEGATION_FIELDS),
        "profile-inventory-readiness": (
            PROFILE_INVENTORY_READINESS_KIND,
            PROFILE_INVENTORY_READINESS_FIELDS,
        ),
        "candidate": (CANDIDATE_KIND, CANDIDATE_FIELDS),
        "activation": (ACTIVATION_KIND, ACTIVATION_FIELDS),
        "rollback-rehearsal": (
            ROLLBACK_REHEARSAL_KIND,
            ROLLBACK_REHEARSAL_FIELDS,
        ),
        "live-rollback-rehearsal": (
            LIVE_ROLLBACK_REHEARSAL_KIND,
            LIVE_ROLLBACK_REHEARSAL_FIELDS,
        ),
        "retention": (RETENTION_KIND, RETENTION_FIELDS),
        "rollback": (ROLLBACK_KIND, ROLLBACK_FIELDS),
    }
    if evidence_kind == "admission-drain":
        return dict(normalize_legacy_test_admission_drain_proof(evidence))
    contract = sealed.get(evidence_kind)
    if contract is None:
        raise CutoverError("unsupported cutover evidence kind")
    return verify_seal(evidence, kind=contract[0], fields=contract[1])


def _recorded(state: Mapping[str, object], key: str) -> dict[str, object] | None:
    value = state["evidence"].get(key)  # type: ignore[union-attr]
    return dict(value) if isinstance(value, Mapping) else None


def _test_store_cutover_completion(
    state: Mapping[str, object],
) -> dict[str, object]:
    """Return the one completion proof accepted by activation.

    The retained ``migration_seal_sha256`` fields in candidate/activation
    documents bind this digest for compatibility; on a destructive first
    adoption it is the exact fresh-store readiness digest instead.
    """

    migrated = _recorded(state, "migration-seal")
    discarded = _recorded(state, "test-history-discard")
    if (migrated is None) == (discarded is None):
        raise CutoverError(
            "cutover requires exactly one migrated or discarded Test Store proof"
        )
    if migrated is not None:
        document = verify_seal(
            migrated,
            kind=SEAL_KIND,
            fields=SEAL_FIELDS,
        )
        return {
            "mode": "history-migrated",
            "document_sha256": document["document_sha256"],
            "authority_generation": document["authority_generation"],
            "test_store_generation": document["test_store_generation"],
        }
    if discarded is None:
        raise CutoverError("discarded Test Store proof is missing")
    document = _fresh_test_store_attestation(
        discarded,
        expected_test_database=str(state["test_database"]),
    )
    readiness = _recorded(state, "authority-readiness")
    if readiness is None:
        raise CutoverError(
            "discarded Test Store proof requires authority readiness"
        )
    authority = _authority_readiness_evidence(readiness)
    postcondition = authority.get("postcondition")
    metadata = (
        postcondition.get("metadata")
        if isinstance(postcondition, Mapping)
        else None
    )
    generation = (
        metadata.get("database_generation")
        if isinstance(metadata, Mapping)
        else None
    )
    if not isinstance(generation, str) or not generation:
        raise CutoverError(
            "discarded Test Store proof lacks its authority generation"
        )
    return {
        "mode": "history-discarded",
        "document_sha256": document["document_sha256"],
        "authority_generation": generation,
        "test_store_generation": document["store"]["store_generation"],
    }


def transition(
    state: Mapping[str, object],
    *,
    evidence_kind: str,
    evidence: Mapping[str, object],
) -> dict[str, object]:
    """Pure deterministic transition used by the CLI and focused tests."""

    current = validate_state(state)
    phase = str(current["phase"])
    indexed = dict(current["evidence"])
    key = evidence_kind
    if key in indexed:
        replay = _normalize_replay(evidence_kind, evidence)
        if indexed[key] != replay:
            raise CutoverError("cutover evidence key is already bound to another document")
        return current
    normalized: dict[str, object]
    next_phase = phase
    if evidence_kind in {"authority-backup", "testd-backup"}:
        if phase != "planned":
            raise CutoverError("backup evidence is allowed only before migration")
        if (
            evidence_kind == "authority-backup"
            and current["authority_backup_required"] is not True
        ):
            raise CutoverError(
                "authority backup is forbidden when no authority transaction is planned"
            )
        normalized = verify_seal(evidence, kind=BACKUP_KIND, fields=BACKUP_FIELDS)
        expected_uid = (
            int(current["authority_uid"])
            if evidence_kind == "authority-backup"
            else int(current["testd_uid"])
        )
        expected_database = (
            current["legacy_authority_database"]
            if evidence_kind == "authority-backup"
            else current["test_database"]
        )
        if (
            normalized["expected_uid"] != expected_uid
            or normalized["database"] != expected_database
            or normalized["quick_check"] != "ok"
            or normalized["foreign_key_violations"] != 0
            or int(normalized["available_bytes"]) < int(normalized["required_bytes"])
        ):
            raise CutoverError("database backup evidence contradicts the cutover plan")
        required_backups = {"testd-backup"}
        if current["authority_backup_required"] is True:
            required_backups.add("authority-backup")
        if required_backups <= (set(indexed) | {key}):
            next_phase = "backups_verified"
    elif evidence_kind == "initial-import":
        if phase != "backups_verified":
            raise CutoverError("initial import requires all planned verified backups")
        normalized = verify_seal(
            evidence, kind=INITIAL_IMPORT_KIND, fields=IMPORT_FIELDS
        )
        if normalized["pass_kind"] != "initial" or normalized["source_retained"] is not True:
            raise CutoverError("initial import attestation is contradictory")
        next_phase = "initial_migrated"
    elif evidence_kind == "admission-drain":
        if phase != "initial_migrated":
            raise CutoverError("admission drain requires the initial import")
        normalized = dict(normalize_legacy_test_admission_drain_proof(evidence))
        key = "admission-drain"
        next_phase = "admission_drained"
    elif evidence_kind == "final-import":
        if phase != "admission_drained":
            raise CutoverError("final import requires an active admission drain")
        normalized = verify_seal(
            evidence, kind=INITIAL_IMPORT_KIND, fields=IMPORT_FIELDS
        )
        initial = _recorded(current, "initial-import")
        drain = _recorded(current, "admission-drain")
        if (
            normalized["pass_kind"] != "final"
            or normalized["source_retained"] is not True
            or initial is None
            or drain is None
            or normalized["migration_id"] != initial["migration_id"]
            or normalized["authority_generation"] != drain["authority_generation"]
        ):
            raise CutoverError("final import attestation is contradictory")
        next_phase = "tail_migrated"
    elif evidence_kind == "migration-seal":
        if phase != "tail_migrated":
            raise CutoverError("migration seal requires the imported tail")
        normalized = verify_seal(evidence, kind=SEAL_KIND, fields=SEAL_FIELDS)
        final = _recorded(current, "final-import")
        drain = _recorded(current, "admission-drain")
        if (
            normalized["activation_ready"] is not True
            or normalized["legacy_source_retained"] is not True
            or normalized["authority_database"]
            != current["legacy_authority_database"]
            or normalized["test_database"] != current["test_database"]
            or final is None
            or drain is None
            or normalized["migration_id"] != final["migration_id"]
            or normalized["drain_proof_fingerprint"] != _digest(drain)
            or normalized["destination_attestation_fingerprint"]
            != final["document_sha256"]
        ):
            raise CutoverError("migration seal contradicts the imported destination")
        next_phase = "sealed"
    elif evidence_kind == "api-delegation":
        if phase != "sealed":
            raise CutoverError("API delegation is bound only after Test Store cutover")
        normalized = verify_seal(evidence, kind=DELEGATION_KIND, fields=DELEGATION_FIELDS)
        grants = normalized["repository_grants"]
        completion = _test_store_cutover_completion(current)
        repository_ids = [
            str(item.get("repository_id") or "")
            for item in grants
            if isinstance(item, Mapping)
        ] if isinstance(grants, list) else []
        if (
            type(normalized["api_uid"]) is not int
            or normalized["api_uid"] <= 0
            or normalized["broker_account_id"] != API_BROKER_ACCOUNT
            or normalized["source_authority_generation"]
            != completion["authority_generation"]
            or normalized["authority_generation"]
            == normalized["source_authority_generation"]
            or normalized["profile_path"] != PROTECTED_PROFILE_PATH
            or normalized["profile_owner_uid"] != 0
            or normalized["profile_group_name"] != PROTECTED_PROFILE_GROUP
            or type(normalized["profile_group_gid"]) is not int
            or normalized["profile_group_gid"] <= 0
            or normalized["profile_mode"] != "0640"
            or normalized["profile_source_kind"]
            not in {"authority-reconstructed", "administrator-sealed"}
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["profile_source_sha256"]))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["profile_fingerprint"]))
            is None
            or normalized["profile_authority_reconciled"] is not True
            or normalized["profile_generation_matches_authority"] is not True
            or normalized["atomic_publication_verified"] is not True
            or normalized["existing_profile_contents_reused"] is not False
            or normalized["google_actor_prefix"] != "google:"
            or normalized["google_actor_policy"] != GOOGLE_ACTOR_POLICY
            or normalized["broker_verified"] is not True
            or not isinstance(grants, list)
            or not grants
            or len(repository_ids) != len(set(repository_ids))
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"repository_id", "permissions"}
                or not isinstance(item["repository_id"], str)
                or not item["repository_id"]
                or len(item["repository_id"].encode("utf-8")) > 256
                or not isinstance(item["permissions"], list)
                or len(item["permissions"]) != 3
                or set(item["permissions"])
                != {"tests:read", "tests:run", "tests:operate"}
                for item in grants
            )
        ):
            raise CutoverError("API actor delegation evidence is invalid")
    elif evidence_kind == "profile-inventory-readiness":
        if phase != "sealed":
            raise CutoverError(
                "post-v13 profile readiness requires the sealed migration"
            )
        normalized = verify_seal(
            evidence,
            kind=PROFILE_INVENTORY_READINESS_KIND,
            fields=PROFILE_INVENTORY_READINESS_FIELDS,
        )
        completion = _test_store_cutover_completion(current)
        delegation = _recorded(current, "api-delegation")
        grants = delegation.get("repository_grants") if delegation else None
        delegated_ids = {
            str(item.get("repository_id"))
            for item in grants
            if isinstance(item, Mapping)
        } if isinstance(grants, list) else set()
        if (
            delegation is None
            or normalized["api_delegation_sha256"]
            != delegation["document_sha256"]
            or normalized["release_digest"] != current["release_digest"]
            or normalized["executor_release"] != current["release"]
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["inventory_client_sha256"])
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["profile_repair_sha256"])
            )
            is None
            or normalized["authority_database"]
            != current["authority_database"]
            or normalized["source_authority_generation"]
            != completion["authority_generation"]
            or normalized["authority_generation"]
            != delegation["authority_generation"]
            or normalized["source_authority_generation"]
            == normalized["authority_generation"]
            or normalized["authority_schema_version"] != 13
            or normalized["authority_migration_state"] != "ready"
            or normalized["profile_path"] != PROTECTED_PROFILE_PATH
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["profile_sha256"])
            )
            is None
            or normalized["profile_owner_uid"] != current["authority_uid"]
            or type(normalized["profile_group_gid"]) is not int
            or int(normalized["profile_group_gid"]) <= 0
            or normalized["profile_mode"] != "0640"
            or normalized["full_regeneration"] is not True
            or normalized["strict_profile_parse"] is not True
            or normalized["project"] != current["inventory_canary_project"]
            or type(normalized["owner_uid"]) is not int
            or int(normalized["owner_uid"]) <= 0
            or not isinstance(normalized["owner_account_id"], str)
            or not normalized["owner_account_id"]
            or not isinstance(normalized["repository_id"], str)
            or not normalized["repository_id"]
            or normalized["repository_id"] not in delegated_ids
            or type(normalized["repository_generation"]) is not int
            or int(normalized["repository_generation"]) < 0
            or normalized["owner_bound_grant"] is not True
            or normalized["inventory_command"]
            != [
                "inventory",
                "--project",
                current["inventory_canary_project"],
                "--no-docker",
                "--compact-json",
            ]
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["inventory_sha256"])
            )
            is None
            or normalized["inventory_schema_version"] != 2
            or normalized["inventory_scope"] != "server-wide"
            or normalized["inventory_transport"]
            != "authenticated-unix-socket"
            or normalized["inventory_service_uid"]
            != current["authority_uid"]
            or normalized["inventory_database_generation"]
            != normalized["authority_generation"]
        ):
            raise CutoverError(
                "post-v13 profile inventory readiness evidence is invalid"
            )
    elif evidence_kind == "candidate":
        if (
            phase != "sealed"
            or "api-delegation" not in indexed
            or "profile-inventory-readiness" not in indexed
        ):
            raise CutoverError(
                "candidate activation requires API delegation and post-v13 inventory readiness"
            )
        normalized = verify_seal(evidence, kind=CANDIDATE_KIND, fields=CANDIDATE_FIELDS)
        completion = _test_store_cutover_completion(current)
        if (
            normalized["release_digest"] != current["release_digest"]
            or normalized["authority_database"] != current["authority_database"]
            or normalized["test_database"] != current["test_database"]
            or normalized["checks_passed"] is not True
            or not isinstance(normalized["ready_units"], Mapping)
            or set(normalized["ready_units"])
            != _candidate_units(str(current["release_digest"]))
            or any(type(value) is not bool for value in normalized["ready_units"].values())
            or not all(normalized["ready_units"].values())
            or normalized["migration_seal_sha256"]
            != completion["document_sha256"]
        ):
            raise CutoverError("candidate attestation contradicts the cutover plan")
        _socket_map(normalized["socket_inodes"])
        delegation = _recorded(current, "api-delegation")
        if delegation is None:
            raise CutoverError("candidate activation lacks API delegation evidence")
        _capability_policy_attestation(
            normalized["test_capability_policy"],
            delegation=delegation,
        )
        preparation = verify_seal(
            normalized["preparation"],
            kind=CANDIDATE_PREPARATION_KIND,
            fields=CANDIDATE_PREPARATION_FIELDS,
        )
        background = preparation["background_config"]
        background_valid = (
            isinstance(background, Mapping)
            and set(background)
            == {
                "ok",
                "kind",
                "directory",
                "project_root",
                "files",
                "administrator_count",
                "transaction_sha256",
            }
            and background.get("ok") is True
            and background.get("kind") == BACKGROUND_CONFIG_KIND
            and isinstance(background.get("directory"), str)
            and Path(str(background.get("directory"))).is_absolute()
            and isinstance(background.get("project_root"), str)
            and Path(str(background.get("project_root"))).is_absolute()
            and isinstance(background.get("files"), Mapping)
            and set(background.get("files", {}))
            == {"notifications.env", "observer.env"}
            and all(
                isinstance(value, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
                for value in background.get("files", {}).values()
            )
            and type(background.get("administrator_count")) is int
            and int(background.get("administrator_count", 0)) > 0
            and isinstance(background.get("transaction_sha256"), str)
            and re.fullmatch(
                r"[0-9a-f]{64}", str(background.get("transaction_sha256"))
            )
            is not None
        )
        isolation = preparation["project_isolation"]
        isolation_counts = (
            isolation.get("audit_counts") if isinstance(isolation, Mapping) else None
        )
        isolation_allowed = {
            "ok",
            "kind",
            "audit_sha256",
            "source_schema_version",
            "repository_owner_map_sha256",
            "audit_counts",
            "project_isolation_complete",
            "authority_database",
            "audit_path",
            "ledger_path",
            "ledger_sha256",
            "ledger_counts",
            "observation_only",
            "project_resources_mutated",
        }
        isolation_valid = (
            isinstance(isolation, Mapping)
            and set(isolation) <= isolation_allowed
            and {
                "ok",
                "kind",
                "audit_sha256",
                "source_schema_version",
                "repository_owner_map_sha256",
                "audit_counts",
                "project_isolation_complete",
                "authority_database",
                "audit_path",
                "ledger_path",
            }
            <= set(isolation)
            and isolation.get("ok") is True
            and isolation.get("kind") == "project-runtime-isolation-verification"
            and isolation.get("source_schema_version") == 13
            and isolation.get("repository_owner_map_sha256") is None
            and isinstance(isolation.get("authority_database"), str)
            and Path(str(isolation.get("authority_database"))).is_absolute()
            and isinstance(isolation.get("audit_sha256"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(isolation.get("audit_sha256")))
            is not None
            and isinstance(isolation_counts, Mapping)
            and set(isolation_counts)
            == {"compliant", "legacy_requires_recreation", "unobservable"}
            and all(type(value) is int and value >= 0 for value in isolation_counts.values())
            and isolation_counts["unobservable"] == 0
            and isolation_counts["legacy_requires_recreation"] == 0
            and isolation.get("project_isolation_complete") is True
            and isolation.get("observation_only") is False
            and isolation.get("project_resources_mutated") is False
            and isinstance(isolation.get("audit_path"), str)
            and Path(str(isolation.get("audit_path"))).is_absolute()
            and (
                (
                    isolation.get("ledger_path") is None
                    and "ledger_counts" not in isolation
                    and "ledger_sha256" not in isolation
                )
                or (
                    isinstance(isolation.get("ledger_path"), str)
                    and Path(str(isolation.get("ledger_path"))).is_absolute()
                    and isinstance(isolation.get("ledger_counts"), Mapping)
                    and set(isolation.get("ledger_counts", {}))
                    == {"pending", "completed", "retired"}
                    and all(
                        type(value) is int and value >= 0
                        for value in isolation.get("ledger_counts", {}).values()
                    )
                    and isolation.get("ledger_counts", {}).get("pending") == 0
                    and isinstance(isolation.get("ledger_sha256"), str)
                    and re.fullmatch(
                        r"sha256:[0-9a-f]{64}", str(isolation.get("ledger_sha256"))
                    )
                    is not None
                )
            )
        )
        console_slot_ports = preparation["console_slot_ports"]
        console_slot_ports_valid = (
            isinstance(console_slot_ports, Mapping)
            and set(console_slot_ports) == {"console_outer", "console_inner"}
            and all(
                type(port) is int
                and FIRST_ADOPTION_PORT_RANGE["start"]
                <= port
                <= FIRST_ADOPTION_PORT_RANGE["end"]
                for port in console_slot_ports.values()
            )
            and len(set(console_slot_ports.values())) == 2
        )
        if (
            preparation["release_digest"] != current["release_digest"]
            or preparation["executor_release"] != current["release"]
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(preparation["credential_preflight_sha256"]),
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", str(preparation["host_preflight_sha256"])
            )
            is None
            or preparation["ready_units"] != normalized["ready_units"]
            or _socket_map(preparation["socket_inodes"])
            != _socket_map(normalized["socket_inodes"])
            or not isinstance(preparation["prior_units"], Mapping)
            or not isinstance(preparation["prior_files"], Mapping)
            or not isinstance(preparation["installed_files"], Mapping)
            or not preparation["installed_files"]
            or not background_valid
            or not isolation_valid
            or not console_slot_ports_valid
        ):
            raise CutoverError("candidate preparation evidence is invalid")
        _candidate_service_identity(
            normalized,
            release_digest=str(current["release_digest"]),
            authority_uid=int(current["authority_uid"]),
            testd_uid=int(current["testd_uid"]),
            api_uid=int(delegation["api_uid"]),
        )
        next_phase = "candidate_verified"
    elif evidence_kind == "activation":
        if phase != "candidate_verified":
            raise CutoverError("activation requires a verified candidate")
        normalized = verify_seal(evidence, kind=ACTIVATION_KIND, fields=ACTIVATION_FIELDS)
        candidate = _recorded(current, "candidate")
        readiness = _recorded(current, "profile-inventory-readiness")
        before = _socket_map(normalized["socket_inodes_before"])
        after = _socket_map(normalized["socket_inodes_after"])
        publication_switch = _publication_switch(
            normalized["publication_switch"],
            expected_release=str(current["release_digest"]),
        )
        continuity = _continuity_probe(
            normalized["continuity_probe"],
            expected_release=str(current["release_digest"]),
        )
        if (
            candidate is None
            or readiness is None
            or normalized["release_digest"] != current["release_digest"]
            or normalized["executor_release"] != current["release"]
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["credential_preflight_sha256"])
            )
            is None
            or normalized["migration_seal_sha256"]
            != candidate["migration_seal_sha256"]
            or normalized["profile_inventory_readiness_sha256"]
            != readiness["document_sha256"]
            or before != _socket_map(candidate["socket_inodes"])
            or before != after
            or publication_switch["release_digest"] != current["release_digest"]
            or normalized["connection_refused_count"]
            != continuity["connection_refused_count"]
            or normalized["project_route_failures"]
            != continuity["project_route_failures"]
            or type(normalized["connection_refused_count"]) is not int
            or normalized["connection_refused_count"] != 0
            or type(normalized["project_route_failures"]) is not int
            or normalized["project_route_failures"] != 0
            or type(normalized["legacy_units_active"]) is not list
            or normalized["legacy_units_active"] != []
            or any(
                normalized[field] is not True
                for field in ("authority_ready", "testd_ready", "console_ready")
            )
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(normalized[field])) is None
                for field in (
                    "browser_lcp_attestation_sha256",
                    "browser_lcp_consumption_sha256",
                )
            )
            or normalized["browser_lcp_attestation_sha256"]
            == normalized["browser_lcp_consumption_sha256"]
        ):
            raise CutoverError("activation did not prove listener-continuous readiness")
        next_phase = "activated"
    elif evidence_kind == "rollback-rehearsal":
        if phase != "activated":
            raise CutoverError("rollback rehearsal requires completed activation")
        normalized = verify_seal(
            evidence,
            kind=ROLLBACK_REHEARSAL_KIND,
            fields=ROLLBACK_REHEARSAL_FIELDS,
        )
        activation = _recorded(current, "activation")
        authority_backup = _recorded(current, "authority-backup")
        test_backup = _recorded(current, "testd-backup")
        expected_authority_sha = (
            authority_backup["backup_sha256"]
            if authority_backup is not None
            else None
        )
        if (
            activation is None
            or test_backup is None
            or normalized["activation_sha256"] != activation["document_sha256"]
            or normalized["executor_release"] != current["release"]
            or normalized["authority_backup_sha256"] != expected_authority_sha
            or normalized["test_backup_sha256"] != test_backup["backup_sha256"]
            or normalized["continuity_probe_sha256"]
            != activation["continuity_probe"]["document_sha256"]
            or normalized["legacy_source_retained"] is not True
            or not isinstance(normalized["restores"], Mapping)
            or set(normalized["restores"])
            != ({"testd"} | ({"authority"} if authority_backup is not None else set()))
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "source",
                    "source_sha256",
                    "restored_sha256",
                    "quick_check",
                    "foreign_key_violations",
                }
                or item["quick_check"] != "ok"
                or item["foreign_key_violations"] != 0
                or re.fullmatch(r"[0-9a-f]{64}", str(item["restored_sha256"]))
                is None
                for item in normalized["restores"].values()
            )
            or not isinstance(normalized["publication_inverse_plan"], Mapping)
            or normalized["private_scratch"] is not True
        ):
            raise CutoverError("rollback rehearsal evidence is invalid")
        key = "rollback-rehearsal"
        next_phase = "activated"
    elif evidence_kind == "live-rollback-rehearsal":
        if phase != "activated":
            raise CutoverError(
                "live rollback rehearsal requires completed activation"
            )
        normalized = verify_seal(
            evidence,
            kind=LIVE_ROLLBACK_REHEARSAL_KIND,
            fields=LIVE_ROLLBACK_REHEARSAL_FIELDS,
        )
        activation = _recorded(current, "activation")
        continuity = _continuity_probe(
            normalized["continuity_probe"],
            expected_release=str(current["release_digest"]),
        )
        rollback_continuity = _continuity_probe(
            normalized["rollback_continuity_probe"],
            expected_release=str(
                activation["publication_switch"].get("previous_release_digest")
                if activation is not None
                else ""
            ),
        )
        reactivation_continuity = _continuity_probe(
            normalized["reactivation_continuity_probe"],
            expected_release=str(current["release_digest"]),
        )
        profile_health = normalized["profile_health"]
        data_health = normalized["data_health"]
        before_publication = _live_rehearsal_publication(
            normalized["publication_before"]
        )
        rollback_publication = _live_rehearsal_publication(
            normalized["publication_rollback"]
        )
        reactivated_publication = _live_rehearsal_publication(
            normalized["publication_reactivated"]
        )
        supported_head = _live_rehearsal_publication(
            normalized["supported_rollback_head"]
        )
        rollback_switch = _publication_switch(
            normalized["rollback_switch"],
            expected_release=str(rollback_publication["release_digest"]),
        )
        reactivation_switch = _publication_switch(
            normalized["reactivation_switch"],
            expected_release=str(current["release_digest"]),
        )
        rollback_slot = _live_rehearsal_slot(
            normalized["rollback_slot"],
            target_release=str(rollback_publication["release_digest"]),
        )
        reactivation_slot = _live_rehearsal_slot(
            normalized["reactivation_slot"],
            target_release=str(current["release_digest"]),
        )
        try:
            overall_started = datetime.fromisoformat(
                str(continuity["started_at"]).replace("Z", "+00:00")
            )
            overall_completed = datetime.fromisoformat(
                str(continuity["completed_at"]).replace("Z", "+00:00")
            )
            rollback_started = datetime.fromisoformat(
                str(rollback_continuity["started_at"]).replace("Z", "+00:00")
            )
            rollback_completed = datetime.fromisoformat(
                str(rollback_continuity["completed_at"]).replace("Z", "+00:00")
            )
            reactivation_started = datetime.fromisoformat(
                str(reactivation_continuity["started_at"]).replace("Z", "+00:00")
            )
            reactivation_completed = datetime.fromisoformat(
                str(reactivation_continuity["completed_at"]).replace("Z", "+00:00")
            )
        except ValueError as error:
            raise CutoverError("live rehearsal continuity timestamp is invalid") from error
        if (
            activation is None
            or normalized["activation_sha256"] != activation["document_sha256"]
            or normalized["activation_state_generation"]
            != current["state_generation"]
            or normalized["release_digest"] != current["release_digest"]
            or normalized["executor_release"] != current["release"]
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["journal_sha256"]))
            is None
            or _socket_map(normalized["socket_inodes_before"])
            != _socket_map(normalized["socket_inodes_after"])
            or not isinstance(profile_health, Mapping)
            or set(profile_health) != {"before", "rollback", "reactivated"}
            or any(
                not isinstance(item, Mapping) or item.get("ready") is not True
                for item in profile_health.values()
            )
            or len(
                {
                    _digest(
                        {
                            key: value
                            for key, value in item.items()
                            if key not in {"proof_sha256", "inventory_sha256"}
                        }
                    )
                    for item in profile_health.values()
                    if isinstance(item, Mapping)
                }
            )
            != 1
            or not isinstance(data_health, Mapping)
            or set(data_health) != {"before", "rollback", "reactivated"}
            or any(
                not isinstance(item, Mapping) or item.get("ready") is not True
                for item in data_health.values()
            )
            or before_publication["release_digest"] != current["release_digest"]
            or before_publication["port"]
            != activation["publication_switch"].get("port")
            or rollback_publication["release_digest"]
            != activation["publication_switch"].get("previous_release_digest")
            or rollback_publication["port"]
            != activation["publication_switch"].get("previous_port")
            or rollback_switch["previous_generation"]
            != before_publication["generation"]
            or rollback_switch["previous_payload_sha256"]
            != before_publication["payload_sha256"]
            or rollback_switch["previous_release_digest"]
            != before_publication["release_digest"]
            or rollback_switch["previous_port"] != before_publication["port"]
            or rollback_switch["generation"] != rollback_publication["generation"]
            or rollback_switch["payload_sha256"]
            != rollback_publication["payload_sha256"]
            or reactivation_switch["previous_generation"]
            != rollback_publication["generation"]
            or reactivation_switch["previous_payload_sha256"]
            != rollback_publication["payload_sha256"]
            or reactivation_switch["previous_release_digest"]
            != rollback_publication["release_digest"]
            or reactivation_switch["previous_port"] != rollback_publication["port"]
            or reactivation_switch["generation"]
            != reactivated_publication["generation"]
            or reactivation_switch["payload_sha256"]
            != reactivated_publication["payload_sha256"]
            or reactivated_publication["release_digest"] != current["release_digest"]
            or reactivated_publication["port"]
            != activation["publication_switch"].get("port")
            or supported_head != reactivated_publication
            or len(
                {
                    before_publication["routing_sha256"],
                    rollback_publication["routing_sha256"],
                    reactivated_publication["routing_sha256"],
                }
            )
            != 1
            or rollback_slot["target_port"] != rollback_publication["port"]
            or rollback_slot["old_port"] != before_publication["port"]
            or reactivation_slot["target_port"] != reactivated_publication["port"]
            or reactivation_slot["old_port"] != rollback_publication["port"]
            or not (
                overall_started
                <= rollback_started
                <= rollback_completed
                <= overall_completed
                and overall_started
                <= reactivation_started
                <= reactivation_completed
                <= overall_completed
                and rollback_started <= reactivation_completed
            )
            or type(normalized["recovery_count"]) is not int
            or int(normalized["recovery_count"]) < 0
            or continuity["passed"] is not True
            or normalized["browser_lcp_attestation_sha256"]
            != activation["browser_lcp_attestation_sha256"]
            or normalized["browser_lcp_consumption_sha256"]
            != activation["browser_lcp_consumption_sha256"]
        ):
            raise CutoverError("live rollback rehearsal evidence is invalid")
        key = "live-rollback-rehearsal"
        next_phase = "activated"
    elif evidence_kind == "retention":
        if phase != "activated":
            raise CutoverError("retention evidence requires completed activation")
        normalized = verify_seal(evidence, kind=RETENTION_KIND, fields=RETENTION_FIELDS)
        authority_backup = _recorded(current, "authority-backup")
        test_backup = _recorded(current, "testd-backup")
        expected_authority_sha = (
            authority_backup["backup_sha256"]
            if authority_backup is not None
            else None
        )
        rehearsal = _recorded(current, "rollback-rehearsal")
        live_rehearsal = _recorded(current, "live-rollback-rehearsal")
        activation = _recorded(current, "activation")
        readiness = _recorded(current, "profile-inventory-readiness")
        fresh_readiness = verify_seal(
            normalized["profile_inventory_reverification"],
            kind=PROFILE_INVENTORY_READINESS_KIND,
            fields=PROFILE_INVENTORY_READINESS_FIELDS,
        )
        readiness_binding_fields = PROFILE_INVENTORY_READINESS_FIELDS - {
            "inventory_sha256",
            "verified_at",
        }
        if (
            test_backup is None
            or (current["authority_backup_required"] is True) != (authority_backup is not None)
            or normalized["authority_backup_sha256"] != expected_authority_sha
            or normalized["test_backup_sha256"] != test_backup["backup_sha256"]
            or normalized["legacy_source_retained"] is not True
            or rehearsal is None
            or live_rehearsal is None
            or activation is None
            or readiness is None
            or normalized["rollback_rehearsal_sha256"]
            != rehearsal["document_sha256"]
            or normalized["live_rollback_rehearsal_sha256"]
            != live_rehearsal["document_sha256"]
            or normalized["profile_inventory_readiness_sha256"]
            != readiness["document_sha256"]
            or normalized["browser_lcp_attestation_sha256"]
            != activation["browser_lcp_attestation_sha256"]
            or normalized["browser_lcp_consumption_sha256"]
            != activation["browser_lcp_consumption_sha256"]
            or live_rehearsal["browser_lcp_attestation_sha256"]
            != activation["browser_lcp_attestation_sha256"]
            or live_rehearsal["browser_lcp_consumption_sha256"]
            != activation["browser_lcp_consumption_sha256"]
            or any(
                fresh_readiness[field] != readiness[field]
                for field in readiness_binding_fields
            )
            or fresh_readiness["verified_at"] == readiness["verified_at"]
            or normalized["retain_until"] != current["retain_until"]
        ):
            raise CutoverError("retention evidence is invalid")
        next_phase = "retained"
    elif evidence_kind == "rollback":
        if phase not in {"activated", "retained"}:
            raise CutoverError("rollback evidence requires a prior activation")
        normalized = verify_seal(evidence, kind=ROLLBACK_KIND, fields=ROLLBACK_FIELDS)
        activation = _recorded(current, "activation")
        authority_backup = _recorded(current, "authority-backup")
        test_backup = _recorded(current, "testd-backup")
        expected_authority_sha = (
            authority_backup["backup_sha256"]
            if authority_backup is not None
            else None
        )
        publication_switch = _publication_switch(
            normalized["publication_switch"],
            expected_release=str(
                normalized["publication_switch"].get("release_digest", "")
                if isinstance(normalized["publication_switch"], Mapping)
                else ""
            ),
        )
        if (
            activation is None
            or test_backup is None
            or normalized["executor_release"] != current["release"]
            or re.fullmatch(
                r"[0-9a-f]{64}", str(normalized["credential_preflight_sha256"])
            )
            is None
            or (current["authority_backup_required"] is True) != (authority_backup is not None)
            or normalized["activation_sha256"] != activation["document_sha256"]
            or normalized["authority_backup_sha256"] != expected_authority_sha
            or normalized["test_backup_sha256"] != test_backup["backup_sha256"]
            or _socket_map(normalized["socket_inodes_before"])
            != _socket_map(normalized["socket_inodes_after"])
            or normalized["connection_refused_count"] != 0
            or normalized["legacy_authority_ready"] is not True
            or publication_switch["previous_release_digest"]
            != current["release_digest"]
        ):
            raise CutoverError("rollback continuity evidence is invalid")
        next_phase = "rolled_back"
    else:
        raise CutoverError("unsupported cutover evidence kind")

    indexed[key] = normalized
    unsigned = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned.update(
        {
            "phase": next_phase,
            "evidence": indexed,
            "updated_at": _now(),
            "state_generation": int(current["state_generation"]) + 1,
        }
    )
    return seal(STATE_KIND, unsigned)


def record_evidence(
    *,
    state_path: Path,
    evidence_kind: str,
    evidence_path: Path,
    authority_uid: int,
    evidence_uid: int,
) -> dict[str, object]:
    state = load_state(state_path, authority_uid=authority_uid)
    evidence = read_private_json(evidence_path, uid=evidence_uid)
    if evidence_kind == "admission-drain":
        evidence = dict(
            verify_legacy_test_admission_drain_proof(
                Path(str(state["legacy_authority_database"])),
                evidence,
                expected_uid=authority_uid,
            )
        )
    updated = transition(state, evidence_kind=evidence_kind, evidence=evidence)
    if updated == state:
        return {
            "ok": True,
            "phase": state["phase"],
            "state_generation": state["state_generation"],
            "cutover_id": state["cutover_id"],
            "replayed": True,
        }
    _write_private_json(
        state_path,
        updated,
        uid=authority_uid,
        create=False,
        expected_generation=int(state["state_generation"]),
    )
    return {
        "ok": True,
        "phase": updated["phase"],
        "state_generation": updated["state_generation"],
        "cutover_id": updated["cutover_id"],
        "replayed": False,
    }


def _authority_generation(path: Path, *, uid: int) -> str:
    before = _database_identity(path, uid=uid)
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        row = connection.execute(
            "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    after = _database_identity(path, uid=uid)
    if before != after or row is None or not isinstance(row[0], str) or not row[0]:
        raise CutoverError("authority generation is unavailable or changed")
    return str(row[0])


def execute_admission_drain(
    *,
    state_path: Path,
    proof_output: Path,
    broker_socket: Path,
    authority_uid: int,
    expected_broker_uid: int,
    expected_socket_gid: int | None = None,
    expected_socket_mode: int = 0o660,
    broker_call=None,
) -> dict[str, object]:
    """Begin or replay the one generation-bound legacy admission drain."""

    if os.geteuid() != authority_uid or authority_uid != 0:
        raise CutoverError("admission drain executor must run as root")
    state_path = _absolute(state_path, "cutover ledger")
    proof_output = _absolute(proof_output, "admission drain proof")
    broker_socket = _absolute(broker_socket, "authority broker socket")
    state = load_state(state_path, authority_uid=authority_uid)
    if state["phase"] not in {"initial_migrated", "admission_drained"}:
        raise CutoverError("admission drain requires the initial import")
    if proof_output != Path(str(state["drain_proof"])):
        raise CutoverError("admission drain output disagrees with the ledger")
    recorded = state["evidence"].get("admission-drain")
    if isinstance(recorded, Mapping):
        proof = dict(
            verify_legacy_test_admission_drain_proof(
                Path(str(state["legacy_authority_database"])),
                recorded,
                expected_uid=authority_uid,
            )
        )
        if proof_output.exists() or proof_output.is_symlink():
            if read_private_json(proof_output, uid=authority_uid) != proof:
                raise CutoverError("recorded admission drain proof output changed")
        else:
            _publish_evidence(proof_output, proof, uid=authority_uid)
        return {
            "ok": True,
            "phase": state["phase"],
            "replayed": True,
            "operation_id": None,
            "proof": proof,
        }
    generation = _authority_generation(
        Path(str(state["legacy_authority_database"])), uid=authority_uid
    )
    operation_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"devcoordinator-admission-drain:{state['cutover_id']}:{generation}",
        )
    )
    request = BrokerRequest.create(
        account_id="devcoordinator-authority",
        project_id="authority",
        resource_id="test-admission",
        repository_generation=0,
        authority_generation=generation,
        operation=BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN,
        operation_id=operation_id,
        arguments={"purpose": "legacy-test-history-cutover"},
    )
    if broker_call is None:
        client = BrokerClient(
            broker_socket,
            expected_broker_uid=expected_broker_uid,
            expected_socket_gid=expected_socket_gid,
            expected_socket_mode=expected_socket_mode,
            timeout_seconds=60.0,
        )
        reply = client.call(request)
    else:
        reply = broker_call(request)
    if not isinstance(reply, Mapping) or reply.get("ok") is not True:
        raise CutoverError("authority broker did not activate test admission drain")
    result = reply.get("result")
    proof_value = result.get("proof") if isinstance(result, Mapping) else None
    proof = dict(
        verify_legacy_test_admission_drain_proof(
            Path(str(state["legacy_authority_database"])),
            proof_value if isinstance(proof_value, Mapping) else {},
            expected_uid=authority_uid,
        )
    )
    if proof["authority_generation"] != generation:
        raise CutoverError("admission drain proof generation changed")
    if proof_output.exists() or proof_output.is_symlink():
        if read_private_json(proof_output, uid=authority_uid) != proof:
            raise CutoverError("admission drain output belongs to another proof")
    else:
        _publish_evidence(proof_output, proof, uid=authority_uid)
    transition_result = record_evidence(
        state_path=state_path,
        evidence_kind="admission-drain",
        evidence_path=proof_output,
        authority_uid=authority_uid,
        evidence_uid=authority_uid,
    )
    return {
        "ok": True,
        "phase": transition_result["phase"],
        "replayed": bool(transition_result["replayed"]),
        "operation_id": operation_id,
        "proof": proof,
    }


def _restore_backup_for_rehearsal(
    *,
    role: str,
    backup_evidence: Mapping[str, object],
    source_uid: int,
    scratch_directory: Path,
    authority_uid: int,
) -> dict[str, object]:
    source = _absolute(Path(str(backup_evidence["backup"])), f"{role} backup")
    _database_identity(source, uid=source_uid)
    if _file_digest(source) != backup_evidence["backup_sha256"]:
        raise CutoverError(f"{role} rollback backup digest changed")
    destination = scratch_directory / f"{role}.restored.sqlite3"
    if destination.exists() or destination.is_symlink():
        _database_identity(destination, uid=authority_uid)
    else:
        temporary = scratch_directory / f".{role}.{uuid.uuid4().hex}.partial"
        try:
            with closing(
                sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=5.0)
            ) as source_connection:
                if source_connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise CutoverError(f"{role} rollback backup quick_check failed")
                with closing(sqlite3.connect(temporary)) as restored:
                    source_connection.backup(restored)
                    restored.commit()
                    if restored.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise CutoverError(f"{role} rehearsed restore quick_check failed")
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    _database_identity(destination, uid=authority_uid)
    with closing(
        sqlite3.connect(f"file:{destination}?mode=ro", uri=True, timeout=5.0)
    ) as restored:
        quick_check = str(restored.execute("PRAGMA quick_check").fetchone()[0])
        foreign_keys = len(restored.execute("PRAGMA foreign_key_check").fetchall())
    if quick_check != "ok" or foreign_keys != 0:
        raise CutoverError(f"{role} rehearsed restore is not internally consistent")
    return {
        "source": str(source),
        "source_sha256": backup_evidence["backup_sha256"],
        "restored_sha256": _file_digest(destination),
        "quick_check": quick_check,
        "foreign_key_violations": foreign_keys,
    }


def produce_rollback_rehearsal(
    *,
    state_path: Path,
    scratch_directory: Path,
    output: Path,
    authority_uid: int,
) -> dict[str, object]:
    """Rehearse exact backup restores and seal the recorded inverse plan.

    This is deliberately offline: it proves the retained database images can
    be restored under the authority UID and that the exact activation inverse
    is retained.  It never changes a listener or a live database.
    """

    if os.geteuid() != authority_uid or authority_uid != 0:
        raise CutoverError("rollback rehearsal must run as root")
    state_path = _absolute(state_path, "cutover ledger")
    scratch_directory = _absolute(scratch_directory, "rollback rehearsal scratch")
    output = _absolute(output, "rollback rehearsal attestation")
    _private_parent(scratch_directory, uid=authority_uid)
    _private_parent(output.parent, uid=authority_uid)
    state = load_state(state_path, authority_uid=authority_uid)
    if state["phase"] != "activated":
        raise CutoverError("rollback rehearsal requires completed activation")
    recorded = state["evidence"].get("rollback-rehearsal")
    if isinstance(recorded, Mapping):
        verified = verify_seal(
            recorded,
            kind=ROLLBACK_REHEARSAL_KIND,
            fields=ROLLBACK_REHEARSAL_FIELDS,
        )
        if output.exists() or output.is_symlink():
            if read_private_json(output, uid=authority_uid) != verified:
                raise CutoverError("rollback rehearsal output changed")
        else:
            _publish_evidence(output, verified, uid=authority_uid)
        return {"ok": True, "replayed": True, "attestation": verified}
    if output.exists() or output.is_symlink():
        pending = verify_seal(
            read_private_json(output, uid=authority_uid),
            kind=ROLLBACK_REHEARSAL_KIND,
            fields=ROLLBACK_REHEARSAL_FIELDS,
        )
        transition(state, evidence_kind="rollback-rehearsal", evidence=pending)
        recorded_result = record_evidence(
            state_path=state_path,
            evidence_kind="rollback-rehearsal",
            evidence_path=output,
            authority_uid=authority_uid,
            evidence_uid=authority_uid,
        )
        return {
            "ok": True,
            "replayed": True,
            "attestation": pending,
            "ledger_replayed": bool(recorded_result["replayed"]),
        }
    activation = _recorded(state, "activation")
    test_backup = _recorded(state, "testd-backup")
    authority_backup = _recorded(state, "authority-backup")
    if activation is None or test_backup is None:
        raise CutoverError("rollback rehearsal lacks activation or backup evidence")
    continuity = _continuity_probe(
        activation["continuity_probe"],
        expected_release=str(state["release_digest"]),
    )
    restores = {
        "testd": _restore_backup_for_rehearsal(
            role="testd",
            backup_evidence=test_backup,
            source_uid=int(state["testd_uid"]),
            scratch_directory=scratch_directory,
            authority_uid=authority_uid,
        )
    }
    if authority_backup is not None:
        restores["authority"] = _restore_backup_for_rehearsal(
            role="authority",
            backup_evidence=authority_backup,
            source_uid=authority_uid,
            scratch_directory=scratch_directory,
            authority_uid=authority_uid,
        )
    _database_identity(
        Path(str(state["legacy_authority_database"])), uid=authority_uid
    )
    switch = activation["publication_switch"]
    if not isinstance(switch, Mapping):
        raise CutoverError("rollback rehearsal activation switch is invalid")
    inverse_plan = {
        "mode": (
            "first-adoption-reverse-graph"
            if switch.get("previous_release_digest") is None
            else "blue-green-inverse-switch"
        ),
        "activation_payload_sha256": switch.get("payload_sha256"),
        "rollback_payload_sha256": switch.get("previous_payload_sha256"),
        "rollback_release_digest": switch.get("previous_release_digest"),
        "rollback_port": switch.get("previous_port"),
        "reactivation_release_digest": switch.get("release_digest"),
        "reactivation_port": switch.get("port"),
    }
    operation_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"devcoordinator-rollback-rehearsal:{state['cutover_id']}:{activation['document_sha256']}",
        )
    )
    document = seal(
        ROLLBACK_REHEARSAL_KIND,
        {
            "operation_id": operation_id,
            "activation_sha256": activation["document_sha256"],
            "executor_release": state["release"],
            "authority_backup_sha256": (
                None
                if authority_backup is None
                else authority_backup["backup_sha256"]
            ),
            "test_backup_sha256": test_backup["backup_sha256"],
            "restores": {key: restores[key] for key in sorted(restores)},
            "publication_inverse_plan": inverse_plan,
            "continuity_probe_sha256": continuity["document_sha256"],
            "legacy_source_retained": True,
            "private_scratch": True,
            "rehearsed_at": _now(),
        },
    )
    transition(state, evidence_kind="rollback-rehearsal", evidence=document)
    _publish_evidence(output, document, uid=authority_uid)
    recorded_result = record_evidence(
        state_path=state_path,
        evidence_kind="rollback-rehearsal",
        evidence_path=output,
        authority_uid=authority_uid,
        evidence_uid=authority_uid,
    )
    return {
        "ok": True,
        "replayed": bool(recorded_result["replayed"]),
        "attestation": document,
    }


def produce_retention_attestation(
    *,
    state_path: Path,
    output: Path,
    authority_uid: int,
    browser_attestation: Path,
    browser_consumption: Path,
    browser_runtime_lock: Path,
    browser_signing_key: Path,
    observed_at: datetime | None = None,
    browser_attestation_verifier=browser_lcp.verify_historical_attestation_file,
    browser_consumption_validator=browser_lcp.validate_consumption_document,
    browser_health_observer=browser_lcp.observe_live_health,
) -> dict[str, object]:
    """Re-verify retained sources/backups and bind the rollback rehearsal."""

    if os.geteuid() != authority_uid or authority_uid != 0:
        raise CutoverError("retention attestation must run as root")
    state_path = _absolute(state_path, "cutover ledger")
    output = _absolute(output, "retention attestation")
    _private_parent(output.parent, uid=authority_uid)
    state = load_state(state_path, authority_uid=authority_uid)
    if state["phase"] not in {"activated", "retained"}:
        raise CutoverError("retention attestation requires completed activation")
    recorded = state["evidence"].get("retention")
    if isinstance(recorded, Mapping):
        verified = verify_seal(recorded, kind=RETENTION_KIND, fields=RETENTION_FIELDS)
        if output.exists() or output.is_symlink():
            if read_private_json(output, uid=authority_uid) != verified:
                raise CutoverError("retention output changed")
        else:
            _publish_evidence(output, verified, uid=authority_uid)
        return {"ok": True, "replayed": True, "attestation": verified}
    if output.exists() or output.is_symlink():
        pending = verify_seal(
            read_private_json(output, uid=authority_uid),
            kind=RETENTION_KIND,
            fields=RETENTION_FIELDS,
        )
        transition(state, evidence_kind="retention", evidence=pending)
        recorded_result = record_evidence(
            state_path=state_path,
            evidence_kind="retention",
            evidence_path=output,
            authority_uid=authority_uid,
            evidence_uid=authority_uid,
        )
        return {
            "ok": True,
            "replayed": True,
            "attestation": pending,
            "ledger_replayed": bool(recorded_result["replayed"]),
        }
    rehearsal = _recorded(state, "rollback-rehearsal")
    live_rehearsal = _recorded(state, "live-rollback-rehearsal")
    activation = _recorded(state, "activation")
    readiness = _recorded(state, "profile-inventory-readiness")
    test_backup = _recorded(state, "testd-backup")
    authority_backup = _recorded(state, "authority-backup")
    if (
        rehearsal is None
        or live_rehearsal is None
        or activation is None
        or readiness is None
        or test_backup is None
    ):
        raise CutoverError(
            "retention requires rollback rehearsals and profile inventory readiness"
        )
    attestation_value = read_private_json(
        _absolute(browser_attestation, "browser LCP attestation"),
        uid=authority_uid,
    )
    attested_health = attestation_value.get("health")
    if not isinstance(attested_health, Mapping):
        raise CutoverError("browser LCP attestation health is invalid")
    try:
        consumption_value = read_private_json(
            _absolute(browser_consumption, "browser LCP consumption"),
            uid=authority_uid,
        )
        consumed_at = browser_lcp._parse_time(
            consumption_value.get("consumed_at"), "browser LCP consumption"
        )
        verified_browser = browser_attestation_verifier(
            browser_attestation,
            release=Path(str(state["release"])),
            immutable_root=Path(str(state["release"])).parent,
            runtime_lock_path=browser_runtime_lock,
            signing_key_path=browser_signing_key,
            expected_operation_id=str(state["cutover_id"]),
            expected_uid=authority_uid,
            expected_gid=authority_uid,
            verified_at=consumed_at,
        )
        verified_consumption = browser_consumption_validator(
            consumption_value,
            attestation=verified_browser,
            expected_consumer_operation_id=str(state["cutover_id"]),
            expected_release_digest=str(state["release_digest"]),
            now=consumed_at,
        )
        urls = verified_browser.get("urls")
        if not isinstance(urls, Mapping):
            raise CutoverError("browser LCP attestation URLs are invalid")
        live_health = browser_health_observer(
            str(urls["health"]),
            expected_release_digest=str(state["release_digest"]),
        )
    except (browser_lcp.BrowserLcpAcceptanceError, KeyError) as error:
        raise CutoverError("browser LCP retention evidence is invalid") from error
    live_publication = live_rehearsal.get("publication_reactivated")
    if (
        not isinstance(live_publication, Mapping)
        or live_health.get("generation") != live_publication.get("generation")
        or verified_browser.get("document_sha256")
        != activation.get("browser_lcp_attestation_sha256")
        or verified_consumption.get("document_sha256")
        != activation.get("browser_lcp_consumption_sha256")
    ):
        raise CutoverError("browser LCP retention binding changed")
    now = observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise CutoverError("retention observation timestamp lacks a timezone")
    retain_until = datetime.fromisoformat(
        str(state["retain_until"]).replace("Z", "+00:00")
    )
    if now > retain_until:
        raise CutoverError("rollback retention window already expired")
    fresh_readiness = reverify_post_v13_profile_inventory_readiness(
        state=state,
        authority_uid=authority_uid,
        verified_at=now.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
    )
    for role, evidence, uid in (
        ("testd", test_backup, int(state["testd_uid"])),
        ("authority", authority_backup, authority_uid),
    ):
        if evidence is None:
            continue
        path = Path(str(evidence["backup"]))
        _database_identity(path, uid=uid)
        if _file_digest(path) != evidence["backup_sha256"]:
            raise CutoverError(f"retained {role} backup digest changed")
    _database_identity(
        Path(str(state["legacy_authority_database"])), uid=authority_uid
    )
    document = seal(
        RETENTION_KIND,
        {
            "authority_backup_sha256": (
                None
                if authority_backup is None
                else authority_backup["backup_sha256"]
            ),
            "test_backup_sha256": test_backup["backup_sha256"],
            "legacy_source_retained": True,
            "retain_until": state["retain_until"],
            "rollback_rehearsal_sha256": rehearsal["document_sha256"],
            "live_rollback_rehearsal_sha256": live_rehearsal[
                "document_sha256"
            ],
            "profile_inventory_readiness_sha256": readiness[
                "document_sha256"
            ],
            "profile_inventory_reverification": fresh_readiness,
            "browser_lcp_attestation_sha256": activation[
                "browser_lcp_attestation_sha256"
            ],
            "browser_lcp_consumption_sha256": activation[
                "browser_lcp_consumption_sha256"
            ],
            "created_at": _now(),
        },
    )
    transition(state, evidence_kind="retention", evidence=document)
    _publish_evidence(output, document, uid=authority_uid)
    recorded_result = record_evidence(
        state_path=state_path,
        evidence_kind="retention",
        evidence_path=output,
        authority_uid=authority_uid,
        evidence_uid=authority_uid,
    )
    return {
        "ok": True,
        "replayed": bool(recorded_result["replayed"]),
        "attestation": document,
    }


def next_actions(state: Mapping[str, object]) -> dict[str, object]:
    state = validate_state(state)
    phase = str(state["phase"])
    release_bin = Path(str(state["release"])) / "bin"
    cutover = str(release_bin / "devcoordinator-cutover")
    migration = str(release_bin / "devcoordinator-test-history")
    actions: list[dict[str, object]] = []
    if phase == "planned":
        if not isinstance(state["evidence"].get("authority-readiness"), Mapping):
            raise CutoverError(
                "cutover ledger lacks authority readiness recovery evidence"
            )
        backups = [
            (
                "testd",
                state["testd_uid"],
                state["test_database"],
                state["test_backup_directory"],
            )
        ]
        if state["authority_backup_required"] is True:
            backups.insert(
                0,
                (
                    "authority",
                    state["authority_uid"],
                    state["legacy_authority_database"],
                    state["authority_backup_directory"],
                ),
            )
        for role, uid, database, directory in backups:
            actions.append(
                {
                    "run_as_uid": uid,
                    "purpose": f"verified {role} SQLite backup and capacity proof",
                    "argv": [
                        cutover,
                        "backup",
                        "--database",
                        database,
                        "--backup",
                        f"{directory}/{role}.sqlite3",
                        "--attestation",
                        f"{directory}/{role}.backup.json",
                        "--expected-uid",
                        str(uid),
                        "--reserve-bytes",
                        str(state["reserve_bytes"]),
                    ],
                }
            )
        if state["authority_backup_required"] is not True:
            actions.append(
                {
                    "purpose": "authority backup intentionally omitted: this cutover declares no authority schema or pointer transaction; migration remains a bounded test-history export with retained source rows",
                    "authority_backup_required": False,
                }
            )
    elif phase == "backups_verified":
        bootstrap = state["evidence"].get("first-deployment-bootstrap")
        if not isinstance(bootstrap, Mapping):
            raise CutoverError(
                "cutover ledger lacks first-deployment bootstrap evidence"
            )
        schema = bootstrap.get("schema_readiness")
        if not isinstance(schema, Mapping):
            raise CutoverError("bootstrap schema readiness binding is invalid")
        actions.extend(
            [
                {
                    "purpose": "validate administrator-supplied explicit manifests and seal the exact authority-independent template that first adoption will bind to the post-split authority export",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "build-first-adoption-manifest-template",
                        "--input",
                        "<root-private-explicit-manifest-input>",
                        "--output",
                        "<root-private-sealed-manifest-template>",
                    ],
                    "input_contract": "schema_version 1, one UUID operation_id, and sorted unique explicit repository_id/manifest rows",
                    "output_contract": "root-owned mode 0600 sealed devcoordinator-first-adoption-manifest-template",
                    "then": "bind the output path and document_sha256 in the first-adoption request",
                },
                {
                    "purpose": (
                        "consume the generation-bound Test Store readiness branch; "
                        "fresh v4 stores are attested and only exact v3 stores are migrated"
                    ),
                    "completed_evidence": schema["path"],
                    "branch": schema["branch"],
                    "document_sha256": schema["document_sha256"],
                },
                {
                    "run_as_uid": state["authority_uid"],
                    "purpose": "capture and export the live initial history watermark after the exact Test Store schema attestation is retained",
                    "argv_prefix": [migration, "authority-capture"],
                    "then": "authority-export-initial until phase initial_exported; import manifest as testd UID; record initial-import attestation",
                },
            ]
        )
    elif phase == "initial_migrated":
        actions.append(
            {
                "run_as_uid": state["authority_uid"],
                "purpose": "activate the DB-backed legacy submission drain and publish its exact proof",
                "argv_prefix": [
                    cutover,
                    "admission-drain",
                    "--state",
                    "<root-private-cutover-state>",
                    "--proof-output",
                    state["drain_proof"],
                    "--broker-socket",
                    AUTHORITY_SOCKET_PATH,
                    "--authority-uid",
                    str(state["authority_uid"]),
                    "--expected-broker-uid",
                    str(state["authority_uid"]),
                ],
                "proof_contract": "generation-bound, DB-verified, private, and ledger-recorded idempotently",
            }
        )
    elif phase == "admission_drained":
        actions.append(
            {
                "run_as_uid": state["authority_uid"],
                "purpose": "export the drained tail and abandon unrecoverable legacy running rows",
                "argv_prefix": [migration, "authority-finalize"],
                "then": "import final manifest as testd UID and record final-import attestation",
            }
        )
    elif phase == "tail_migrated":
        actions.append(
            {
                "run_as_uid": state["authority_uid"],
                "purpose": "bind drain, tail export, destination attestation, and rollback retention",
                "argv_prefix": [migration, "authority-seal"],
                "output": state["cutover_seal"],
            }
        )
    elif phase == "sealed":
        actions.extend(
            [
                {
                    "purpose": "migrate the legacy Console session and Google OIDC credentials under the sealed source-owner UID while retaining root as the only destination publisher",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "migrate-credentials",
                        "--legacy-env",
                        "<legacy-console-environment>",
                        "--legacy-source-uid",
                        "<legacy-console-source-uid>",
                        "--rollback-directory",
                        "<root-private-credential-rollback-directory>",
                        "--attestation",
                        "<root-private-credential-migration-attestation>",
                        "--expected-uid",
                        str(state["authority_uid"]),
                    ],
                    "output_contract": "root-owned mode 0600 sealed credential migration attestation with the exact source identity and no credential bytes",
                    "then": "retain this exact attestation and pass the migrated root-owned credential paths to the first-adoption request",
                },
                {
                    "purpose": "install the listener-free first-adoption graph only while holding the exact schema-13 successor installer claim transferred by binding finalization",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "prepare-first-adoption",
                        "--state",
                        "<root-private-cutover-state>",
                        "--binding-attestation",
                        "<root-private-first-adoption-bindings-result>",
                        "--operation-id",
                        "<same-first-adoption-operation-uuid>",
                        "--hard-gate-attestation",
                        "<root-private-first-adoption-installation-hard-gate>",
                        "--canonical-project",
                        "<canonical-global-finance-project-root>",
                        "--canonical-repository-id",
                        "<global-finance-repository-id>",
                        "--owner-user",
                        "<global-finance-owner-user>",
                        "--collaborator-user",
                        "<global-finance-collaborator-user>",
                    ],
                    "required_argument_groups": {
                        "candidate": "--candidate-slot-source, --rollback-directory, --graph-evidence, --graph-journal, --credential-evidence",
                        "legacy": "--legacy-console-env, --legacy-console-uid, --legacy-authority-database",
                        "background": "--background-project-root, --background-config-transaction",
                        "isolation": "--project-isolation-audit, --project-isolation-ledger, --repository-owner-map",
                        "ports": "--port-reservations, --port-reservations-sha256",
                    },
                    "claim_contract": "the completed binding result, operation UUID, and future hard-gate path must exactly match the durable schema13-first-adoption-executor claim; preparation retains that claim",
                    "then": "pass the graph and credential evidence to build-first-adoption-request",
                },
                {
                    "purpose": "compile every first-adoption source/final path, identity, listener, post-authority fleet request, and background handoff into one validated root-private sealed request; the transaction derives policy and API profiles only after the storage split",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "build-first-adoption-request",
                        "--state",
                        "<root-private-cutover-state>",
                        "--output",
                        "<root-private-first-adoption-request>",
                    ],
                    "optional_argument_groups": {
                        "historical_tmp_repair": "--repair-plan and --repair-result must be supplied together only when the live schema-12 authority still contains an unsafe /tmp repository row",
                    },
                    "required_argument_groups": {
                        "ports": "--port-reservations, --port-reservations-sha256",
                        "legacy_writer": "--legacy-bridge-transaction, --legacy-bridge-operation-id, --legacy-bridge-journal-sha256, --legacy-bridge-database, --legacy-bridge-profile, --legacy-bridge-socket, --legacy-bridge-dropin, --legacy-broker-retirement-guard, --legacy-writer-handoff-journal",
                        "candidate": "--candidate-slot-source, --test-capability-policy, --test-capability-policy-evidence, --test-capability-policy-journal, --dogfood-repository-id, --candidate-rollback-directory, --legacy-console-env, --background-project-root, --background-config-transaction, --project-isolation-audit, --project-isolation-ledger, --graph-evidence, --candidate-graph-journal, --credential-evidence, --candidate-evidence, --activation-evidence",
                        "console": "--legacy-console-state, --console-state, --edge-identity-state, --console-config, --route-resolution, --publication-input, --console-port, --console-uid, --console-gid, --edge-uid, --edge-gid, --legacy-console-uid, --console-rollback-directory, --console-migration-journal",
                        "authority": "--legacy-authority-database, --authority-database, --inventory-database, --inventory-publication, --storage-split-attestation, --authority-adoption-pointer, --authority-operation-journal, --repository-owner-map, --repository-owner-map-sha256, --maintenance-root, --maintenance-gid, --authority-service-uid, --authority-service-gid, --inventory-uid, --inventory-gid",
                        "handoffs": "--api-handoff-port, --api-handoff-journal, --api-bootstrap-profile-path, --api-bootstrap-profile-journal, --api-final-profile-journal, --protected-profile-path, --protected-profile-access-gid, --api-service-uid, --api-delegation-evidence, --profile-inventory-readiness-evidence, --edge-publication, --public-handoff-journal, --http-handoff-port, --https-handoff-port",
                        "fleet": "--fleet-authority-export, --fleet-evidence-root, --fleet-manifest-template, --fleet-manifest-template-sha256, --fleet-manifest-set, --fleet-adoption-request, --fleet-uid-helper",
                        "background": "--telegram-present or --no-telegram-present, --telegram-source, --telegram-destination, --telegram-rollback, --telegram-fence, --telegram-source-owner-uid, --telegram-destination-owner-uid, --telegram-destination-owner-gid",
                        "browser": "--browser-runtime-lock, --browser-storage-state, --browser-signing-key, --browser-journal, --browser-attestation, --browser-consumption",
                    },
                    "output_contract": "root-owned mode 0600 sealed devcoordinator-first-adoption-request",
                    "then": "pass this exact output to the following first-adoption action",
                },
                {
                    "purpose": "run the single resumable first-adoption transaction: install a listener-free graph, arm the exact legacy-writer retirement guard, split the legacy authority into distinct final authority/inventory stores, retire the bridge-owned drop-in and legacy unit before any schema-13 authority starts, start snapshotd, derive policy, start authority/testd, hand API traffic through a candidate-only profile, publish the final profile and API, journal the exact maintenance-fence release immediately before live delegation, apply fleet adoption through its own durable intent journal, and record candidate/activation only after the sealed HTTP/WebSocket continuity window passes",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "first-adoption",
                        "--request",
                        "<root-private-first-adoption-request>",
                        "--journal",
                        "<root-private-first-adoption-journal>",
                        "--canonical-project",
                        "<canonical-global-finance-project-root>",
                        "--canonical-repository-id",
                        "<global-finance-repository-id>",
                        "--owner-user",
                        "<global-finance-owner-user>",
                        "--collaborator-user",
                        "<global-finance-collaborator-user>",
                    ],
                    "required_arguments": [
                        "--attestation",
                        "--rollback-evidence",
                        "--binding-attestation",
                        "--operation-id",
                        "--hard-gate-attestation",
                    ],
                    "record_after_delegation": "project isolation, inventory readiness, fleet plan/apply subtransaction, Console/public handoff, candidate, then activation in one journal",
                    "rollback_order": "re-arm the exact authority maintenance fence before reversing notifications, fleet, public handoff, cutover evidence, profiles, API, policy, and graph; restore the exact bridge drop-in while its retirement guard still blocks starts, restore schema-12 authority/unit state, prove the bridge socket ready, then clear maintenance last",
                    "request_producer": "the immediately preceding build-first-adoption-request action",
                    "first_adoption_constraint": "the transaction refuses unless project isolation pending=0/unobservable=0 and all split, route, inventory, fleet, Test Store completion, and rollback seals verify",
                },
                {
                    "purpose": "release the server-wide installer claim only after the installed final units, protected all-client profile, canonical Codex/Claude skill links for the declared owner and collaborator, and an immutable-client inventory read for the declared canonical hard-gate repository all verify",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "finalize-first-adoption-installation",
                        "--binding-attestation",
                        "<root-private-first-adoption-bindings-result>",
                        "--operation-id",
                        "<same-first-adoption-operation-uuid>",
                        "--first-adoption-attestation",
                        "<root-private-first-adoption-attestation>",
                        "--release",
                        state["release"],
                        "--hard-gate-attestation",
                        "<root-private-first-adoption-installation-hard-gate>",
                        "--canonical-project",
                        "<canonical-global-finance-project-root>",
                        "--canonical-repository-id",
                        "<global-finance-repository-id>",
                        "--owner-user",
                        "<global-finance-owner-user>",
                        "--collaborator-user",
                        "<global-finance-collaborator-user>",
                    ],
                    "hard_gate": {
                        "scope": "server-wide",
                        "transport": "authenticated-unix-socket",
                        "canonical_project": "<canonical-global-finance-project-root>",
                        "repository_id": "<global-finance-repository-id>",
                        "users": [
                            "<global-finance-owner-user>",
                            "<global-finance-collaborator-user>",
                        ],
                    },
                },
            ]
        )
    elif phase == "candidate_verified":
        actions.append(
            {
                "purpose": "activate the sealed release, disable the legacy broker writer, and embed a sealed multi-round HTTP/WebSocket continuity window with stable socket inodes and zero refused/project-route failures",
                "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                "required_arguments": [
                    "activate",
                    "--state",
                    "--publication",
                    "--candidate-control",
                    "--previous-control",
                    "--activation-evidence",
                    "--continuity-evidence",
                    "--credential-evidence",
                    "--browser-runtime-lock",
                    "--browser-storage-state",
                    "--browser-signing-key",
                    "--browser-journal",
                    "--browser-attestation",
                    "--browser-consumption",
                ],
                "record": "activation",
            }
        )
    elif phase == "activated":
        if "live-rollback-rehearsal" not in state["evidence"]:
            actions.append(
                {
                    "purpose": "reverse the live blue/green Console publication and reactivate it under one uninterrupted HTTP/WebSocket probe plus sealed rollback/reactivation subwindows",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "required_arguments": [
                        "rehearse-live-rollback",
                        "--state",
                        "--publication",
                        "--candidate-control",
                        "--previous-control",
                        "--journal",
                        "--attestation",
                        "--continuity-evidence",
                    ],
                    "record": "live-rollback-rehearsal",
                }
            )
        elif "rollback-rehearsal" not in state["evidence"]:
            actions.append(
                {
                    "purpose": "restore each retained SQLite backup in private scratch and bind the exact inverse publication plan",
                    "argv_prefix": [
                        cutover,
                        "rehearse-rollback",
                        "--state",
                        "<root-private-cutover-state>",
                        "--scratch-directory",
                        "<root-private-rollback-rehearsal-directory>",
                        "--output",
                        "<root-private-rollback-rehearsal-attestation>",
                    ],
                    "record": "rollback-rehearsal",
                }
            )
        else:
            actions.append(
                {
                    "purpose": "re-verify retained backup digests and legacy source through the declared rollback window",
                    "argv_prefix": [
                        cutover,
                        "attest-retention",
                        "--state",
                        "<root-private-cutover-state>",
                        "--output",
                        "<root-private-retention-attestation>",
                        "--browser-attestation",
                        "<root-private-browser-lcp-attestation>",
                        "--browser-consumption",
                        "<root-private-browser-lcp-consumption>",
                        "--browser-runtime-lock",
                        "<root-private-browser-runtime-lock>",
                        "--browser-signing-key",
                        "<root-private-browser-signing-key>",
                    ],
                    "record": "retention",
                }
            )
    return {"ok": True, "phase": phase, "actions": actions}


def _octal_mode(raw: str) -> int:
    try:
        value = int(raw, 8)
    except ValueError as error:
        raise argparse.ArgumentTypeError("socket mode must be octal") from error
    if value < 0 or value > 0o7777:
        raise argparse.ArgumentTypeError("socket mode is out of range")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare_bindings = actions.add_parser("prepare-first-adoption-bindings")
    for name in (
        "release",
        "database",
        "prior-attestation",
        "readiness-attestation",
        "project-root",
        "repository-id",
        "port-journal",
        "prepared-attestation",
        "port-attestation",
        "transaction-journal",
        "transaction-attestation",
        "bridge-transaction",
        "bridge-operation-id",
        "bridge-journal-sha256",
        "bridge-journal-document-sha256",
        "bridge-profile",
        "bridge-socket",
        "bridge-dropin",
        "bridge-canary-user",
        "bridge-canary-project",
        "bridge-canary-repository-id",
        "post-start-attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        prepare_bindings.add_argument(f"--{name}", required=True)
    prepare_bindings.add_argument(
        "--repository-generation", type=int, required=True
    )
    prepare_bindings.add_argument(
        "--bridge-canary-repository-generation", type=int, required=True
    )
    prepare_bindings.add_argument(
        "--bridge-canary-owner-uid", type=int, required=True
    )
    prepare_bindings.add_argument(
        "--handoff-ttl-seconds", type=int, required=True
    )
    prepare_bindings.add_argument("--maintenance-gid", type=int, required=True)
    prepare_bindings.add_argument("--authority-uid", type=int, default=0)
    for action in ("finalize-first-adoption-bindings", "abort-first-adoption-bindings"):
        binding = actions.add_parser(action)
        binding.add_argument("--state", required=True)
        binding.add_argument("--transaction-journal", required=True)
        binding.add_argument("--transaction-attestation", required=True)
        binding.add_argument("--operation-id", required=True)
        binding.add_argument("--authority-uid", type=int, default=0)
        if action == "finalize-first-adoption-bindings":
            binding.add_argument(
                "--successor-terminal-attestation", required=True
            )
    reserve_ports = actions.add_parser("reserve-first-adoption-ports")
    for name in (
        "release",
        "database",
        "project-root",
        "repository-id",
        "journal",
        "attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        reserve_ports.add_argument(f"--{name}", required=True)
    reserve_ports.add_argument("--repository-generation", type=int, required=True)
    reserve_ports.add_argument("--handoff-ttl-seconds", type=int, required=True)
    reserve_ports.add_argument("--maintenance-gid", type=int, required=True)
    reserve_ports.add_argument("--authority-uid", type=int, default=0)
    bootstrap_parser = actions.add_parser("bootstrap-first-deployment")
    for name in (
        "release",
        "rendered-units",
        "authority-database",
        "inventory-database",
        "test-database",
        "schema-attestation",
        "output",
        "operation-id",
    ):
        bootstrap_parser.add_argument(f"--{name}", required=True)
    bootstrap_parser.add_argument("--authority-uid", type=int, default=0)

    initialize_parser = actions.add_parser("init")
    for name in (
        "state",
        "release",
        "rendered-units",
        "legacy-authority-database",
        "authority-database",
        "test-database",
        "inventory-canary-project",
        "authority-backup-directory",
        "test-backup-directory",
        "migration-state",
        "drain-proof",
        "cutover-seal",
        "first-deployment-bootstrap",
        "authority-readiness",
        "first-adoption-port-reservations",
        "first-adoption-port-reservations-sha256",
    ):
        initialize_parser.add_argument(f"--{name}", required=True)
    initialize_parser.add_argument("--authority-uid", type=int, required=True)
    initialize_parser.add_argument("--testd-uid", type=int, required=True)
    initialize_parser.add_argument("--reserve-bytes", type=int, default=DEFAULT_RESERVE_BYTES)
    initialize_parser.add_argument("--retain-until", required=True)
    initialize_parser.add_argument(
        "--authority-transaction-required",
        action="store_true",
        help="Require a full authority backup only when this cutover changes authority schema or its active pointer.",
    )
    initialize_parser.add_argument(
        "--discard-test-history",
        choices=(DISCARD_TEST_HISTORY_CONFIRMATION,),
        help=(
            "Explicitly authorize destructive first adoption and skip legacy "
            "test-history backup/export/drain/import/seal work."
        ),
    )
    initialize_parser.add_argument("--fresh-test-store-attestation")
    initialize_parser.add_argument("--fresh-test-store-attestation-sha256")
    initialize_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the complete plan and print its first actions without creating the resume journal",
    )

    backup = actions.add_parser("backup")
    backup.add_argument("--database", required=True)
    backup.add_argument("--backup", required=True)
    backup.add_argument("--attestation", required=True)
    backup.add_argument("--expected-uid", type=int, required=True)
    backup.add_argument("--reserve-bytes", type=int, default=DEFAULT_RESERVE_BYTES)

    readiness = actions.add_parser("finalize-authority-readiness")
    for name in (
        "release",
        "database",
        "backup",
        "backup-attestation",
        "journal",
        "attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        readiness.add_argument(f"--{name}", required=True)
    readiness.add_argument("--maintenance-gid", type=int, required=True)
    readiness.add_argument("--reserve-bytes", type=int, default=DEFAULT_RESERVE_BYTES)
    readiness.add_argument("--authority-uid", type=int, default=0)

    recovery = actions.add_parser("recover-authority-readiness")
    for name in (
        "release",
        "database",
        "backup",
        "backup-attestation",
        "journal",
        "attestation",
        "transaction-journal",
        "transaction-attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        recovery.add_argument(f"--{name}", required=True)
    recovery.add_argument("--maintenance-gid", type=int, required=True)
    recovery.add_argument("--reserve-bytes", type=int, default=DEFAULT_RESERVE_BYTES)
    recovery.add_argument("--authority-uid", type=int, default=0)

    rebind = actions.add_parser("rebind-authority-readiness")
    for name in (
        "release",
        "database",
        "prior-attestation",
        "attestation",
        "transaction-journal",
        "transaction-attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        rebind.add_argument(f"--{name}", required=True)
    rebind.add_argument("--maintenance-gid", type=int, required=True)
    rebind.add_argument("--authority-uid", type=int, default=0)

    reattest = actions.add_parser("reattest-authority-readiness")
    for name in (
        "release",
        "database",
        "prior-attestation",
        "quiescence-attestation",
        "quiescence-attestation-sha256",
        "journal",
        "attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
    ):
        reattest.add_argument(f"--{name}", required=True)
    reattest.add_argument("--maintenance-gid", type=int, required=True)
    reattest.add_argument("--authority-uid", type=int, default=0)

    drain = actions.add_parser("admission-drain")
    drain.add_argument("--state", required=True)
    drain.add_argument("--proof-output", required=True)
    drain.add_argument("--broker-socket", default=AUTHORITY_SOCKET_PATH)
    drain.add_argument("--authority-uid", type=int, default=0)
    drain.add_argument("--expected-broker-uid", type=int, default=0)
    drain.add_argument("--expected-socket-gid", type=int)
    drain.add_argument("--expected-socket-mode", type=_octal_mode, default=0o660)

    rehearsal = actions.add_parser("rehearse-rollback")
    rehearsal.add_argument("--state", required=True)
    rehearsal.add_argument("--scratch-directory", required=True)
    rehearsal.add_argument("--output", required=True)
    rehearsal.add_argument("--authority-uid", type=int, default=0)

    retention = actions.add_parser("attest-retention")
    retention.add_argument("--state", required=True)
    retention.add_argument("--output", required=True)
    retention.add_argument("--browser-attestation", required=True)
    retention.add_argument("--browser-consumption", required=True)
    retention.add_argument("--browser-runtime-lock", required=True)
    retention.add_argument("--browser-signing-key", required=True)
    retention.add_argument("--authority-uid", type=int, default=0)

    policy = actions.add_parser("publish-test-policy")
    policy.add_argument("--authority-database", required=True)
    policy.add_argument("--snapshot-socket", required=True)
    policy.add_argument(
        "--destination", default=TEST_CAPABILITY_POLICY_PATH
    )
    policy.add_argument("--dogfood-repository-id", required=True)
    policy.add_argument("--authority-uid", type=int, default=0)
    policy.add_argument("--owner-gid", type=int, default=0)
    policy.add_argument("--expected-snapshot-uid", type=int, default=0)

    authority_export = actions.add_parser("export-authority-repositories")
    authority_export.add_argument("--authority-database", required=True)
    authority_export.add_argument("--attestation", required=True)
    authority_export.add_argument("--authority-uid", type=int, default=0)

    repository_diagnostic = actions.add_parser("diagnose-authority-repository")
    repository_diagnostic.add_argument(
        "--authority-database", default=FINAL_AUTHORITY_DATABASE_PATH
    )
    repository_diagnostic.add_argument("--repository-id", required=True)

    shared_root_positive_absence_plan = actions.add_parser(
        "plan-authority-shared-root-positive-absence"
    )
    shared_root_positive_absence_plan.add_argument(
        "--authority-database", default=FINAL_AUTHORITY_DATABASE_PATH
    )
    shared_root_positive_absence_plan.add_argument(
        "--repository-id", required=True
    )
    shared_root_positive_absence_plan.add_argument(
        "--operation-id", required=True
    )
    shared_root_positive_absence_plan.add_argument("--plan", required=True)
    shared_root_positive_absence_plan.add_argument(
        "--authority-uid", type=int, default=0
    )

    shared_root_positive_absence_apply = actions.add_parser(
        "apply-authority-shared-root-positive-absence"
    )
    shared_root_positive_absence_apply.add_argument(
        "--authority-database", default=FINAL_AUTHORITY_DATABASE_PATH
    )
    shared_root_positive_absence_apply.add_argument("--plan", required=True)
    shared_root_positive_absence_apply.add_argument(
        "--plan-document-sha256", required=True
    )
    shared_root_positive_absence_apply.add_argument(
        "--attestation", required=True
    )
    shared_root_positive_absence_apply.add_argument(
        "--maintenance-root", required=True
    )
    shared_root_positive_absence_apply.add_argument(
        "--maintenance-gid", type=int, required=True
    )
    shared_root_positive_absence_apply.add_argument(
        "--maintenance-deployment-id", required=True
    )
    shared_root_positive_absence_apply.add_argument(
        "--authority-uid", type=int, default=0
    )

    shared_root_positive_absence_execute = actions.add_parser(
        "execute-authority-shared-root-positive-absence"
    )
    shared_root_positive_absence_execute.add_argument(
        "--authority-database", default=FINAL_AUTHORITY_DATABASE_PATH
    )
    for name in (
        "release",
        "plan",
        "transaction-journal",
        "transaction-attestation",
        "broker-socket",
        "canary-user",
        "canary-project",
        "canary-repository-id",
    ):
        shared_root_positive_absence_execute.add_argument(
            f"--{name}", required=True
        )
    shared_root_positive_absence_execute.add_argument(
        "--plan-document-sha256", required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--attestation", required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--maintenance-root", required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--maintenance-gid", type=int, required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--canary-uid", type=int, required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--readiness-wait-seconds", type=int, default=30
    )
    shared_root_positive_absence_execute.add_argument(
        "--maintenance-deployment-id", required=True
    )
    shared_root_positive_absence_execute.add_argument(
        "--authority-uid", type=int, default=0
    )

    repository_disable_plan = actions.add_parser(
        "plan-authority-repository-disable"
    )
    repository_disable_plan.add_argument(
        "--authority-database", default=FINAL_AUTHORITY_DATABASE_PATH
    )
    repository_disable_plan.add_argument("--repository-id", required=True)
    repository_disable_plan.add_argument("--plan", required=True)
    repository_disable_plan.add_argument("--authority-uid", type=int, default=0)

    repository_disable_apply = actions.add_parser(
        "apply-authority-repository-disable"
    )
    repository_disable_apply.add_argument("--plan", required=True)
    repository_disable_apply.add_argument(
        "--plan-document-sha256", required=True
    )
    repository_disable_apply.add_argument("--attestation", required=True)
    repository_disable_apply.add_argument("--maintenance-root", required=True)
    repository_disable_apply.add_argument("--maintenance-gid", type=int, required=True)
    repository_disable_apply.add_argument(
        "--maintenance-deployment-id", required=True
    )
    repository_disable_apply.add_argument("--authority-uid", type=int, default=0)

    repository_policy_plan = actions.add_parser(
        "plan-authority-repository-startup-policy-reconciliation"
    )
    repository_policy_plan.add_argument(
        "--source-repair-plan", dest="repair_plan", required=True
    )
    repository_policy_plan.add_argument(
        "--source-repair-plan-document-sha256",
        dest="repair_plan_document_sha256",
        required=True,
    )
    repository_policy_plan.add_argument(
        "--source-repair-attestation",
        dest="repair_attestation",
        required=True,
    )
    repository_policy_plan.add_argument(
        "--source-repair-attestation-document-sha256",
        dest="repair_attestation_document_sha256",
        required=True,
    )
    repository_policy_plan.add_argument("--plan", required=True)
    repository_policy_plan.add_argument(
        "--authority-uid", type=int, default=0
    )

    repository_policy_apply = actions.add_parser(
        "apply-authority-repository-startup-policy-reconciliation"
    )
    for name in (
        "plan",
        "plan-document-sha256",
        "attestation",
        "maintenance-root",
        "maintenance-deployment-id",
    ):
        repository_policy_apply.add_argument(f"--{name}", required=True)
    repository_policy_apply.add_argument(
        "--maintenance-gid", type=int, required=True
    )
    repository_policy_apply.add_argument(
        "--authority-uid", type=int, default=0
    )

    repository_lifecycle_plan = actions.add_parser(
        "plan-authority-repository-lifecycle-recovery"
    )
    for name in (
        "source-repair-plan",
        "source-repair-plan-document-sha256",
        "source-repair-attestation",
        "source-repair-attestation-document-sha256",
        "plan",
        "operation-id",
    ):
        repository_lifecycle_plan.add_argument(f"--{name}", required=True)
    repository_lifecycle_plan.add_argument(
        "--authority-uid", type=int, default=0
    )

    repository_disable_recovery = actions.add_parser(
        "recover-authority-repository-disable"
    )
    for name in (
        "release",
        "plan",
        "plan-document-sha256",
        "attestation",
        "transaction-journal",
        "transaction-attestation",
        "maintenance-root",
        "maintenance-deployment-id",
        "operation-id",
        "broker-socket",
        "canary-user",
        "canary-project",
        "canary-repository-id",
    ):
        repository_disable_recovery.add_argument(f"--{name}", required=True)
    repository_disable_recovery.add_argument(
        "--maintenance-gid", type=int, required=True
    )
    repository_disable_recovery.add_argument(
        "--authority-uid", type=int, default=0
    )
    repository_disable_recovery.add_argument("--canary-uid", type=int, required=True)
    repository_disable_recovery.add_argument(
        "--canary-repository-generation", type=int, required=True
    )
    repository_disable_recovery.add_argument(
        "--readiness-wait-seconds", type=int, default=30
    )
    repository_disable_recovery.add_argument(
        "--mode",
        choices=("disable", "lifecycle-recovery"),
        default="disable",
    )
    repository_disable_recovery.add_argument("--canary-release")
    for name in (
        "predecessor-transaction",
        "predecessor-operation-id",
        "predecessor-journal-sha256",
        "predecessor-journal-document-sha256",
        "predecessor-profile",
        "predecessor-dropin",
    ):
        repository_disable_recovery.add_argument(f"--{name}")

    profile = actions.add_parser("publish-api-profile")
    profile.add_argument("--authority-database", required=True)
    profile.add_argument("--destination", default=PROTECTED_PROFILE_PATH)
    profile.add_argument("--api-uid", type=int, required=True)
    profile.add_argument("--access-gid", type=int, required=True)
    profile.add_argument("--source-authority-generation", required=True)
    profile.add_argument("--target-authority-generation", required=True)
    profile.add_argument("--authority-uid", type=int, default=0)
    profile.add_argument("--attestation")

    record = actions.add_parser("record")
    record.add_argument("--state", required=True)
    record.add_argument(
        "--kind",
        required=True,
        choices=(
            "authority-backup",
            "testd-backup",
            "initial-import",
            "admission-drain",
            "final-import",
            "migration-seal",
            "api-delegation",
            "candidate",
            "activation",
            "rollback-rehearsal",
            "live-rollback-rehearsal",
            "retention",
            "rollback",
        ),
    )
    record.add_argument("--evidence", required=True)
    record.add_argument("--authority-uid", type=int, required=True)
    record.add_argument("--evidence-uid", type=int, required=True)

    for name in ("status", "next", "plan"):
        command = actions.add_parser(name)
        command.add_argument("--state", required=True)
        command.add_argument("--authority-uid", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    installer_fence: InstallerFenceHandle | None = None
    bindings_claim_transferred = False
    command_succeeded = False
    try:
        if arguments.action in {
            "prepare-first-adoption-bindings",
            "finalize-first-adoption-bindings",
            "abort-first-adoption-bindings",
        }:
            try:
                installer_fence = acquire_transaction_fence(
                    owner_kind="atomic-first-adoption-bindings",
                    operation_id=arguments.operation_id,
                    transaction=Path(arguments.transaction_journal),
                    terminal=Path(arguments.transaction_attestation),
                    action={
                        "prepare-first-adoption-bindings": "prepare",
                        "finalize-first-adoption-bindings": "finalize",
                        "abort-first-adoption-bindings": "abort",
                    }[arguments.action],
                    expected_uid=arguments.authority_uid,
                    expected_gid=0,
                )
            except InstallerFenceError as predecessor_error:
                if arguments.action != "finalize-first-adoption-bindings":
                    raise
                try:
                    installer_fence = acquire_transaction_fence(
                        owner_kind=SCHEMA13_FIRST_ADOPTION_INSTALLER_OWNER_KIND,
                        operation_id=arguments.operation_id,
                        transaction=Path(arguments.transaction_attestation),
                        terminal=Path(arguments.successor_terminal_attestation),
                        action="recover",
                        expected_uid=arguments.authority_uid,
                        expected_gid=0,
                    )
                except InstallerFenceError as successor_error:
                    raise InstallerFenceError(
                        "atomic first-adoption installer claim is neither the exact "
                        f"binding predecessor ({predecessor_error}) nor its exact "
                        f"schema-13 successor ({successor_error})"
                    ) from successor_error
                bindings_claim_transferred = True
        if arguments.action == "prepare-first-adoption-bindings":
            result = prepare_atomic_first_adoption_bindings(
                release=Path(arguments.release),
                database=Path(arguments.database),
                prior_attestation=Path(arguments.prior_attestation),
                readiness_attestation=Path(arguments.readiness_attestation),
                project_root=Path(arguments.project_root),
                repository_id=arguments.repository_id,
                repository_generation=arguments.repository_generation,
                handoff_ttl_seconds=arguments.handoff_ttl_seconds,
                port_journal=Path(arguments.port_journal),
                prepared_attestation=Path(arguments.prepared_attestation),
                port_attestation=Path(arguments.port_attestation),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                bridge_transaction=Path(arguments.bridge_transaction),
                bridge_operation_id=arguments.bridge_operation_id,
                bridge_journal_sha256=arguments.bridge_journal_sha256,
                bridge_journal_document_sha256=(
                    arguments.bridge_journal_document_sha256
                ),
                bridge_profile=Path(arguments.bridge_profile),
                bridge_socket=Path(arguments.bridge_socket),
                bridge_dropin=Path(arguments.bridge_dropin),
                bridge_canary_user=arguments.bridge_canary_user,
                bridge_canary_owner_uid=arguments.bridge_canary_owner_uid,
                bridge_canary_project=Path(arguments.bridge_canary_project),
                bridge_canary_repository_id=(
                    arguments.bridge_canary_repository_id
                ),
                bridge_canary_repository_generation=(
                    arguments.bridge_canary_repository_generation
                ),
                post_start_attestation=Path(
                    arguments.post_start_attestation
                ),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "finalize-first-adoption-bindings":
            result = finalize_atomic_first_adoption_bindings(
                state_path=Path(arguments.state),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                authority_uid=arguments.authority_uid,
            )
            if installer_fence is None:
                raise InstallerFenceError(
                    "atomic first-adoption finalization lacks its installer fence"
                )
            if not bindings_claim_transferred:
                result_path = Path(arguments.transaction_attestation)
                result_payload = _private_file(
                    result_path, uid=arguments.authority_uid
                )
                successor_claim = transfer_transaction_fence(
                    installer_fence,
                    successor_owner_kind=(
                        SCHEMA13_FIRST_ADOPTION_INSTALLER_OWNER_KIND
                    ),
                    successor_operation_id=arguments.operation_id,
                    successor_transaction=result_path,
                    successor_terminal=Path(
                        arguments.successor_terminal_attestation
                    ),
                    successor_transaction_sha256=hashlib.sha256(
                        result_payload
                    ).hexdigest(),
                )
                result = {
                    **dict(result),
                    "installer_claim_handoff": {
                        "owner_kind": successor_claim["owner_kind"],
                        "operation_id": successor_claim["operation_id"],
                        "transaction": successor_claim["transaction"],
                        "terminal": successor_claim["terminal"],
                        "document_sha256": successor_claim["document_sha256"],
                    },
                }
            else:
                result = {**dict(result), "installer_claim_handoff": "replayed"}
        elif arguments.action == "abort-first-adoption-bindings":
            result = abort_atomic_first_adoption_bindings(
                state_path=Path(arguments.state),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "reserve-first-adoption-ports":
            result = reserve_first_adoption_ports(
                release=Path(arguments.release),
                database=Path(arguments.database),
                project_root=Path(arguments.project_root),
                repository_id=arguments.repository_id,
                repository_generation=arguments.repository_generation,
                handoff_ttl_seconds=arguments.handoff_ttl_seconds,
                journal=Path(arguments.journal),
                attestation=Path(arguments.attestation),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=arguments.maintenance_deployment_id,
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "bootstrap-first-deployment":
            result = bootstrap_first_deployment(
                release=Path(arguments.release),
                rendered_units=Path(arguments.rendered_units),
                authority_database=Path(arguments.authority_database),
                inventory_database=Path(arguments.inventory_database),
                test_database=Path(arguments.test_database),
                schema_attestation=Path(arguments.schema_attestation),
                output=Path(arguments.output),
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "init":
            result = initialize(
                state_path=Path(arguments.state),
                release=Path(arguments.release),
                rendered_units=Path(arguments.rendered_units),
                legacy_authority_database=Path(
                    arguments.legacy_authority_database
                ),
                authority_database=Path(arguments.authority_database),
                test_database=Path(arguments.test_database),
                inventory_canary_project=Path(arguments.inventory_canary_project),
                authority_backup_directory=Path(arguments.authority_backup_directory),
                test_backup_directory=Path(arguments.test_backup_directory),
                migration_state=Path(arguments.migration_state),
                drain_proof=Path(arguments.drain_proof),
                cutover_seal=Path(arguments.cutover_seal),
                first_deployment_bootstrap=Path(
                    arguments.first_deployment_bootstrap
                ),
                authority_readiness=Path(arguments.authority_readiness),
                first_adoption_port_reservations=Path(
                    arguments.first_adoption_port_reservations
                ),
                first_adoption_port_reservations_sha256=(
                    arguments.first_adoption_port_reservations_sha256
                ),
                discard_test_history=arguments.discard_test_history,
                fresh_test_store_attestation=(
                    Path(arguments.fresh_test_store_attestation)
                    if arguments.fresh_test_store_attestation
                    else None
                ),
                fresh_test_store_attestation_sha256=(
                    arguments.fresh_test_store_attestation_sha256
                ),
                authority_uid=arguments.authority_uid,
                testd_uid=arguments.testd_uid,
                reserve_bytes=arguments.reserve_bytes,
                retain_until=arguments.retain_until,
                authority_backup_required=bool(
                    arguments.authority_transaction_required
                ),
                persist=not arguments.dry_run,
            )
        elif arguments.action == "backup":
            result = backup_database(
                database=Path(arguments.database),
                backup=Path(arguments.backup),
                attestation=Path(arguments.attestation),
                expected_uid=arguments.expected_uid,
                reserve_bytes=arguments.reserve_bytes,
            )
        elif arguments.action == "finalize-authority-readiness":
            result = finalize_authority_readiness(
                release=Path(arguments.release),
                database=Path(arguments.database),
                backup=Path(arguments.backup),
                backup_attestation=Path(arguments.backup_attestation),
                journal=Path(arguments.journal),
                attestation=Path(arguments.attestation),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=arguments.maintenance_deployment_id,
                operation_id=arguments.operation_id,
                reserve_bytes=arguments.reserve_bytes,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "recover-authority-readiness":
            result = recover_authority_readiness(
                release=Path(arguments.release),
                database=Path(arguments.database),
                backup=Path(arguments.backup),
                backup_attestation=Path(arguments.backup_attestation),
                journal=Path(arguments.journal),
                attestation=Path(arguments.attestation),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=arguments.maintenance_deployment_id,
                operation_id=arguments.operation_id,
                reserve_bytes=arguments.reserve_bytes,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "rebind-authority-readiness":
            result = rebind_authority_readiness(
                release=Path(arguments.release),
                database=Path(arguments.database),
                prior_attestation=Path(arguments.prior_attestation),
                attestation=Path(arguments.attestation),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "reattest-authority-readiness":
            result = reattest_authority_readiness(
                release=Path(arguments.release),
                database=Path(arguments.database),
                prior_attestation=Path(arguments.prior_attestation),
                quiescence_attestation=Path(
                    arguments.quiescence_attestation
                ),
                quiescence_attestation_sha256=(
                    arguments.quiescence_attestation_sha256
                ),
                journal=Path(arguments.journal),
                attestation=Path(arguments.attestation),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "admission-drain":
            result = execute_admission_drain(
                state_path=Path(arguments.state),
                proof_output=Path(arguments.proof_output),
                broker_socket=Path(arguments.broker_socket),
                authority_uid=arguments.authority_uid,
                expected_broker_uid=arguments.expected_broker_uid,
                expected_socket_gid=arguments.expected_socket_gid,
                expected_socket_mode=arguments.expected_socket_mode,
            )
        elif arguments.action == "rehearse-rollback":
            result = produce_rollback_rehearsal(
                state_path=Path(arguments.state),
                scratch_directory=Path(arguments.scratch_directory),
                output=Path(arguments.output),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "attest-retention":
            result = produce_retention_attestation(
                state_path=Path(arguments.state),
                output=Path(arguments.output),
                authority_uid=arguments.authority_uid,
                browser_attestation=Path(arguments.browser_attestation),
                browser_consumption=Path(arguments.browser_consumption),
                browser_runtime_lock=Path(arguments.browser_runtime_lock),
                browser_signing_key=Path(arguments.browser_signing_key),
            )
        elif arguments.action == "publish-test-policy":
            result = publish_test_capability_policy(
                authority_database=Path(arguments.authority_database),
                snapshot_socket=Path(arguments.snapshot_socket),
                destination=Path(arguments.destination),
                dogfood_repository_id=arguments.dogfood_repository_id,
                authority_uid=arguments.authority_uid,
                owner_gid=arguments.owner_gid,
                expected_snapshot_uid=arguments.expected_snapshot_uid,
            )
        elif arguments.action == "export-authority-repositories":
            result = publish_authority_repository_export(
                authority_database=Path(arguments.authority_database),
                attestation=Path(arguments.attestation),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "diagnose-authority-repository":
            result = diagnose_authority_repository(
                authority_database=Path(arguments.authority_database),
                repository_id=arguments.repository_id,
            )
        elif arguments.action == "plan-authority-shared-root-positive-absence":
            result = plan_authority_shared_root_positive_absence(
                authority_database=Path(arguments.authority_database),
                repository_id=arguments.repository_id,
                operation_id=arguments.operation_id,
                plan_path=Path(arguments.plan),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "apply-authority-shared-root-positive-absence":
            result = apply_authority_shared_root_positive_absence(
                authority_database=Path(arguments.authority_database),
                plan_path=Path(arguments.plan),
                plan_document_sha256=arguments.plan_document_sha256,
                attestation=Path(arguments.attestation),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "execute-authority-shared-root-positive-absence":
            result = execute_authority_shared_root_positive_absence(
                release=Path(arguments.release),
                authority_database=Path(arguments.authority_database),
                plan_path=Path(arguments.plan),
                plan_document_sha256=arguments.plan_document_sha256,
                attestation=Path(arguments.attestation),
                transaction_journal=Path(arguments.transaction_journal),
                transaction_attestation=Path(
                    arguments.transaction_attestation
                ),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                broker_socket=Path(arguments.broker_socket),
                canary_user=arguments.canary_user,
                canary_uid=arguments.canary_uid,
                canary_project=Path(arguments.canary_project),
                canary_repository_id=arguments.canary_repository_id,
                canary_repository_generation=(
                    arguments.canary_repository_generation
                ),
                readiness_wait_seconds=arguments.readiness_wait_seconds,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "plan-authority-repository-disable":
            result = plan_authority_repository_disable(
                authority_database=Path(arguments.authority_database),
                repository_id=arguments.repository_id,
                plan_path=Path(arguments.plan),
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "apply-authority-repository-disable":
            result = apply_authority_repository_disable(
                plan_path=Path(arguments.plan),
                plan_document_sha256=arguments.plan_document_sha256,
                attestation=Path(arguments.attestation),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=arguments.maintenance_deployment_id,
                authority_uid=arguments.authority_uid,
            )
        elif (
            arguments.action
            == "plan-authority-repository-startup-policy-reconciliation"
        ):
            result = plan_authority_repository_startup_policy_reconciliation(
                repair_plan=Path(arguments.repair_plan),
                repair_plan_document_sha256=(
                    arguments.repair_plan_document_sha256
                ),
                repair_attestation=Path(arguments.repair_attestation),
                repair_attestation_document_sha256=(
                    arguments.repair_attestation_document_sha256
                ),
                plan_path=Path(arguments.plan),
                authority_uid=arguments.authority_uid,
            )
        elif (
            arguments.action
            == "apply-authority-repository-startup-policy-reconciliation"
        ):
            result = apply_authority_repository_startup_policy_reconciliation(
                plan_path=Path(arguments.plan),
                plan_document_sha256=arguments.plan_document_sha256,
                attestation=Path(arguments.attestation),
                maintenance_root=Path(arguments.maintenance_root),
                maintenance_gid=arguments.maintenance_gid,
                maintenance_deployment_id=(
                    arguments.maintenance_deployment_id
                ),
                authority_uid=arguments.authority_uid,
            )
        elif (
            arguments.action
            == "plan-authority-repository-lifecycle-recovery"
        ):
            result = plan_authority_repository_lifecycle_recovery(
                repair_plan=Path(arguments.source_repair_plan),
                repair_plan_document_sha256=(
                    arguments.source_repair_plan_document_sha256
                ),
                repair_attestation=Path(arguments.source_repair_attestation),
                repair_attestation_document_sha256=(
                    arguments.source_repair_attestation_document_sha256
                ),
                plan_path=Path(arguments.plan),
                operation_id=arguments.operation_id,
                authority_uid=arguments.authority_uid,
            )
        elif arguments.action == "recover-authority-repository-disable":
            common = {
                "release": Path(arguments.release),
                "plan_path": Path(arguments.plan),
                "plan_document_sha256": arguments.plan_document_sha256,
                "transaction_journal": Path(arguments.transaction_journal),
                "transaction_attestation": Path(
                    arguments.transaction_attestation
                ),
                "maintenance_root": Path(arguments.maintenance_root),
                "maintenance_gid": arguments.maintenance_gid,
                "maintenance_deployment_id": (
                    arguments.maintenance_deployment_id
                ),
                "operation_id": arguments.operation_id,
                "broker_socket": Path(arguments.broker_socket),
                "canary_user": arguments.canary_user,
                "canary_uid": arguments.canary_uid,
                "canary_project": Path(arguments.canary_project),
                "canary_repository_id": arguments.canary_repository_id,
                "canary_repository_generation": (
                    arguments.canary_repository_generation
                ),
                "readiness_wait_seconds": arguments.readiness_wait_seconds,
                "authority_uid": arguments.authority_uid,
            }
            if arguments.mode == "lifecycle-recovery":
                predecessor_values = {
                    "predecessor_transaction": arguments.predecessor_transaction,
                    "predecessor_operation_id": arguments.predecessor_operation_id,
                    "predecessor_journal_sha256": (
                        arguments.predecessor_journal_sha256
                    ),
                    "predecessor_journal_document_sha256": (
                        arguments.predecessor_journal_document_sha256
                    ),
                    "predecessor_profile": arguments.predecessor_profile,
                    "predecessor_dropin": arguments.predecessor_dropin,
                }
                if not arguments.canary_release or any(
                    not value for value in predecessor_values.values()
                ):
                    raise CutoverError(
                        "lifecycle recovery requires the exact predecessor binding"
                    )
                result = recover_authority_repository_lifecycle(
                    **common,
                    canary_release=Path(arguments.canary_release),
                    predecessor_transaction=Path(
                        str(predecessor_values["predecessor_transaction"])
                    ),
                    predecessor_operation_id=str(
                        predecessor_values["predecessor_operation_id"]
                    ),
                    predecessor_journal_sha256=str(
                        predecessor_values["predecessor_journal_sha256"]
                    ),
                    predecessor_journal_document_sha256=str(
                        predecessor_values[
                            "predecessor_journal_document_sha256"
                        ]
                    ),
                    predecessor_profile=Path(
                        str(predecessor_values["predecessor_profile"])
                    ),
                    predecessor_dropin=Path(
                        str(predecessor_values["predecessor_dropin"])
                    ),
                    recovery_attestation=Path(arguments.attestation),
                )
            else:
                if arguments.canary_release or any(
                    getattr(arguments, name.replace("-", "_"))
                    for name in (
                        "predecessor-transaction",
                        "predecessor-operation-id",
                        "predecessor-journal-sha256",
                        "predecessor-journal-document-sha256",
                        "predecessor-profile",
                        "predecessor-dropin",
                    )
                ):
                    raise CutoverError(
                        "disable recovery does not accept predecessor inputs"
                    )
                result = recover_authority_repository_disable(
                    **common,
                    repair_attestation=Path(arguments.attestation),
                )
        elif arguments.action == "publish-api-profile":
            result = reconstruct_api_profile_from_authority(
                authority_database=Path(arguments.authority_database),
                destination=Path(arguments.destination),
                api_uid=arguments.api_uid,
                access_gid=arguments.access_gid,
                authority_uid=arguments.authority_uid,
                source_authority_generation=arguments.source_authority_generation,
                target_authority_generation=arguments.target_authority_generation,
            )
            if arguments.attestation:
                _publish_evidence(
                    Path(arguments.attestation),
                    result["attestation"],
                    uid=arguments.authority_uid,
                )
                result = {
                    **result,
                    "attestation_path": arguments.attestation,
                }
        elif arguments.action == "record":
            result = record_evidence(
                state_path=Path(arguments.state),
                evidence_kind=arguments.kind,
                evidence_path=Path(arguments.evidence),
                authority_uid=arguments.authority_uid,
                evidence_uid=arguments.evidence_uid,
            )
        else:
            state = load_state(Path(arguments.state), authority_uid=arguments.authority_uid)
            result = (
                next_actions(state)
                if arguments.action in {"next", "plan"}
                else {
                    "ok": True,
                    "phase": state["phase"],
                    "state_generation": state["state_generation"],
                    "cutover_id": state["cutover_id"],
                    "evidence": sorted(state["evidence"]),
                }
            )
        command_succeeded = True
        if installer_fence is not None and (
            arguments.action
            in {
                "abort-first-adoption-bindings",
            }
            or (
                arguments.action == "prepare-first-adoption-bindings"
                and isinstance(result, Mapping)
                and "terminal_attestation" in result
            )
        ):
            installer_fence.mark_complete()
    except (
        OSError,
        ValueError,
        sqlite3.Error,
        CutoverError,
        InstallerFenceError,
    ) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        if installer_fence is not None:
            installer_fence.close(command_succeeded=command_succeeded)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
