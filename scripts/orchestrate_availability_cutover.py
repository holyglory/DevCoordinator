#!/usr/bin/env python3
"""Resumable, evidence-gated availability and test-history cutover.

This program owns the durable cutover ledger, split-UID SQLite backups, and
the small set of explicit maintenance-fenced broker transactions required for
authority readiness, exact listener-port reservation, and stale-repository
repair. It validates artifacts produced by the existing history migrator and
broker drain, and refuses activation unless the exact migration seal,
candidate topology, and socket-inode continuity are proved.
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
from devcoordinator.universal_test_store import UniversalTestStore  # noqa: E402
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
from devcoordinator.schema import (  # noqa: E402
    SCHEMA_VERSION as COORDINATOR_SCHEMA_VERSION,
    invariant_violations,
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
CANDIDATE_KIND = "devcoordinator-cutover-candidate-attestation"
CANDIDATE_PREPARATION_KIND = "devcoordinator-candidate-preparation-attestation"
BACKGROUND_CONFIG_KIND = "devcoordinator-background-config-transaction"
PROFILE_REPAIR_KIND = "devcoordinator-api-profile-repair-attestation"
PROFILE_INVENTORY_READINESS_KIND = (
    "devcoordinator-local-routing-inventory-readiness-attestation"
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
FIRST_ADOPTION_INSTALLER_CLAIM_KIND = (
    "schema13-first-adoption-executor"
)
ATOMIC_FIRST_ADOPTION_FINALIZATION_INTENT_KIND = (
    "devcoordinator-atomic-first-adoption-binding-finalization-intent"
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
AUTHORITY_SOCKET_PATH = "/run/devcoordinator-authority.sock"
IMMUTABLE_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
FINAL_AUTHORITY_DATABASE_PATH = "/var/lib/devcoordinator/authority.sqlite3"
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
        "migration_conflicts",
    }
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
        "profile_mode",
        "profile_sha256",
        "authority_generation",
        "authority_source_sha256",
        "validation_uid",
        "repository_ids",
        "repository_bindings",
        "parser_verified",
        "atomic_publication_verified",
        "created_at",
    }
)

PROFILE_INVENTORY_READINESS_FIELDS = frozenset(
    {
        "profile_repair_sha256",
        "release_digest",
        "executor_release",
        "inventory_client_sha256",
        "authority_database",
        "authority_generation",
        "authority_schema_version",
        "authority_migration_state",
        "profile_path",
        "profile_sha256",
        "profile_owner_uid",
        "profile_mode",
        "full_regeneration",
        "strict_profile_parse",
        "project",
        "execution_uid",
        "repository_id",
        "repository_generation",
        "route_verified",
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

def _publish_reconstructed_profile(
    destination: Path,
    document: Mapping[str, object],
    *,
    owner_uid: int,
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
            and stat.S_IMODE(info.st_mode) == 0o644
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
            0o644,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.fchown(descriptor, owner_uid, -1)
            os.fchmod(descriptor, 0o644)
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
        or stat.S_IMODE(after.st_mode) != 0o644
        or destination.read_bytes() != payload
    ):
        raise CutoverError("reconstructed API profile publication did not verify")
    return payload, changed


def reconstruct_api_profile_from_authority(
    *,
    authority_database: Path,
    destination: Path,
    validation_uid: int,
    authority_uid: int = 0,
) -> dict[str, object]:
    """Rebuild the host routing profile from the current trusted-local catalog."""

    if validation_uid <= 0 or authority_uid != os.geteuid():
        raise CutoverError("routing profile validation identity is invalid")
    database = _absolute(authority_database, "coordinator database")
    before = _database_identity(database, uid=authority_uid)
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
        repository_rows = connection.execute(
            """
            SELECT repository.repo_id, repository.canonical_root,
                   repository.generation
            FROM repositories AS repository
            JOIN repository_installations AS installation USING(repo_id)
            WHERE repository.state = 'active'
              AND installation.status = 'installed'
              AND installation.startup_fenced = 0
            ORDER BY repository.canonical_root, repository.repo_id
            """
        ).fetchall()
        if (
            metadata is None
            or int(metadata["schema_version"]) != COORDINATOR_SCHEMA_VERSION
            or str(metadata["migration_state"]) != "ready"
            or not isinstance(metadata["database_generation"], str)
            or not metadata["database_generation"]
            or not repository_rows
            or len(repository_rows) > 10_000
        ):
            raise CutoverError(
                "current coordinator database has no routable repository catalog"
            )

        repositories: list[dict[str, object]] = []
        bindings: list[dict[str, object]] = []
        for row in repository_rows:
            repo_id = str(row["repo_id"])
            canonical_root = str(row["canonical_root"])
            generation = int(row["generation"])
            if not repo_id or not Path(canonical_root).is_absolute() or generation < 0:
                raise CutoverError("repository routing identity is invalid")

            servers = {
                str(server["name"]): str(server["server_definition_id"])
                for server in connection.execute(
                    """
                    SELECT name, server_definition_id
                    FROM server_definitions
                    WHERE repo_id = ?
                    ORDER BY name, server_definition_id
                    """,
                    (repo_id,),
                )
            }
            container_aliases: dict[str, set[str]] = {}
            container_resource_ids: set[str] = set()
            for resource in connection.execute(
                """
                SELECT docker_resource_id, current_name, full_container_id
                FROM docker_resources
                WHERE repo_id = ?
                ORDER BY docker_resource_id
                """,
                (repo_id,),
            ):
                resource_id = str(resource["docker_resource_id"])
                container_resource_ids.add(resource_id)
                for alias in (
                    str(resource["current_name"] or ""),
                    str(resource["full_container_id"] or ""),
                ):
                    if alias:
                        container_aliases.setdefault(alias, set()).add(resource_id)
            # Container names are reusable display aliases, not authority.  A
            # stale container and its replacement may therefore share a name.
            # Retain aliases only when they resolve uniquely, then guarantee
            # every resource remains addressable by its immutable Coordinator
            # identity.  The latter deliberately wins over any pathological
            # display/native alias collision.
            containers = {
                alias: next(iter(resource_ids))
                for alias, resource_ids in container_aliases.items()
                if len(resource_ids) == 1
            }
            containers.update(
                {resource_id: resource_id for resource_id in container_resource_ids}
            )

            compose_rows = connection.execute(
                """
                SELECT compose_definition_id
                FROM broker_compose_definitions
                WHERE repo_id = ? AND enabled = 1
                ORDER BY compose_definition_id
                """,
                (repo_id,),
            ).fetchall()
            if len(compose_rows) > 1:
                raise CutoverError(
                    "repository has multiple current Compose definitions"
                )
            compose_id = (
                None
                if not compose_rows
                else str(compose_rows[0]["compose_definition_id"])
            )
            run_once = (
                {}
                if compose_id is None
                else {
                    str(service["service_name"]): int(
                        service["max_timeout_seconds"]
                    )
                    for service in connection.execute(
                        """
                        SELECT service_name, max_timeout_seconds
                        FROM broker_compose_run_once_services
                        WHERE compose_definition_id = ?
                        ORDER BY ordinal
                        """,
                        (compose_id,),
                    )
                }
            )
            templates: dict[str, str] = {}
            secret_policies: dict[str, dict[str, str]] = {}
            for template in connection.execute(
                """
                SELECT name, template_id, secret_policy_kind, secret_binding_id
                FROM ephemeral_container_templates
                WHERE repo_id = ? AND enabled = 1
                ORDER BY name, template_id
                """,
                (repo_id,),
            ):
                name = str(template["name"])
                templates[name] = str(template["template_id"])
                if template["secret_policy_kind"] is not None:
                    secret_policies[name] = {
                        "policy": str(template["secret_policy_kind"]),
                        "binding_id": str(template["secret_binding_id"]),
                    }

            repositories.append(
                {
                    "canonical_root": canonical_root,
                    "repo_id": repo_id,
                    "generation": generation,
                    "servers": servers,
                    "containers": containers,
                    "compose_definition_id": compose_id,
                    "compose_container_ids": [],
                    "compose_run_once_services": run_once,
                    "ephemeral_templates": templates,
                    "ephemeral_secret_policies": secret_policies,
                }
            )
            bindings.append(
                {
                    "repository_id": repo_id,
                    "generation": generation,
                    "canonical_root": canonical_root,
                }
            )
    finally:
        connection.close()
    after = _database_identity(database, uid=authority_uid)
    if before != after:
        raise CutoverError("coordinator database changed during profile export")

    document = {
        "version": 2,
        "service": {
            "socket": AUTHORITY_SOCKET_PATH,
            "database_generation": str(metadata["database_generation"]),
        },
        "repositories": repositories,
    }
    try:
        parsed = profile_from_document(document, effective_uid=validation_uid)
    except BrokerProfileError as error:
        raise CutoverError(
            "coordinator-derived routing profile failed strict parsing"
        ) from error
    if (
        parsed.service.database_generation != str(metadata["database_generation"])
        or {item.repo_id for item in parsed.repositories.values()}
        != {str(item["repository_id"]) for item in bindings}
    ):
        raise CutoverError("coordinator-derived routing profile is contradictory")

    payload, changed = _publish_reconstructed_profile(
        destination,
        document,
        owner_uid=authority_uid,
    )
    source = {
        "database_generation": str(metadata["database_generation"]),
        "repository_bindings": bindings,
    }
    attestation = seal(
        PROFILE_REPAIR_KIND,
        {
            "profile_path": str(_absolute(destination, "protected API profile")),
            "profile_owner_uid": authority_uid,
            "profile_mode": "0644",
            "profile_sha256": hashlib.sha256(payload).hexdigest(),
            "authority_generation": str(metadata["database_generation"]),
            "authority_source_sha256": _digest(source),
            "validation_uid": validation_uid,
            "repository_ids": sorted(
                str(item["repository_id"]) for item in bindings
            ),
            "repository_bindings": bindings,
            "parser_verified": True,
            "atomic_publication_verified": True,
            "created_at": _now(),
        },
    )
    return {"ok": True, "changed": changed, "attestation": attestation}


def _authority_metadata(
    database: Path, *, authority_uid: int
) -> dict[str, object]:
    """Read the current catalog generation without accepting an inode swap."""

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
            "coordinator catalog changed during readiness verification"
        )
    return {
        "schema_version": int(row[0]),
        "database_generation": str(row[1]),
        "migration_state": str(row[2]),
        "database_identity": before,
    }


def _immutable_inventory_client(release: Path) -> tuple[Path, str]:
    release = _absolute(release, "immutable release")
    client = release / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
    if (
        not client.is_file()
        or client.is_symlink()
        or release.parent != IMMUTABLE_RELEASE_ROOT
        or re.fullmatch(r"[0-9a-f]{64}", release.name) is None
    ):
        raise CutoverError("immutable inventory client is unavailable")
    return client, _file_digest(client)


def _inventory_as_execution_uid(
    *, release: Path, project: str, execution_uid: int
) -> dict[str, object]:
    """Run one cross-repository inventory read as an explicit local account."""

    if type(execution_uid) is not int or execution_uid <= 0:
        raise CutoverError("inventory execution UID must be positive")
    try:
        account = pwd.getpwuid(execution_uid)
    except KeyError as error:
        raise CutoverError("inventory execution account is unavailable") from error
    client, _client_sha256 = _immutable_inventory_client(release)
    command = [
        "/usr/bin/setpriv",
        "--reuid",
        str(execution_uid),
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
        raise CutoverError("local routing inventory proof could not run") from error
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > MAX_DOCUMENT_BYTES
        or len(completed.stderr) > 64 * 1024
    ):
        raise CutoverError("local routing inventory proof failed")
    try:
        document = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CutoverError("local routing inventory proof is invalid JSON") from error
    if not isinstance(document, dict):
        raise CutoverError("local routing inventory proof is invalid")
    return document


def _validate_routing_inventory(
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
    matching = (
        [
            item
            for item in repositories
            if isinstance(item, Mapping)
            and item.get("canonical_root") == project
            and item.get("repo_id") == repository_id
            and item.get("generation") == repository_generation
        ]
        if isinstance(repositories, list)
        else []
    )
    if (
        inventory.get("schema_version") != 2
        or not isinstance(authority, Mapping)
        or authority.get("scope") != "server-wide"
        or authority.get("transport") != "trusted-local-unix-socket"
        or authority.get("socket") != AUTHORITY_SOCKET_PATH
        or authority.get("service_uid") != authority_uid
        or authority.get("database_generation") != authority_generation
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or len(matching) != 1
    ):
        raise CutoverError(
            "local routing inventory does not prove the selected repository"
        )


def verify_profile_inventory_readiness(
    *,
    state: Mapping[str, object],
    profile_repair: Mapping[str, object],
    authority_database: Path,
    authority_uid: int = 0,
    inventory_fetcher: Any = None,
    verified_at: str | None = None,
) -> dict[str, object]:
    """Prove one local account can route to any selected repository."""

    current = validate_state(state)
    if current["phase"] != "sealed":
        raise CutoverError("routing readiness requires the sealed migration")
    repair = verify_seal(
        profile_repair,
        kind=PROFILE_REPAIR_KIND,
        fields=PROFILE_REPAIR_FIELDS,
    )
    database = _absolute(authority_database, "authority database")
    release = _absolute(current["release"], "immutable release")
    _inventory_client, inventory_client_sha256 = _immutable_inventory_client(release)
    project_path = str(
        _absolute(current["inventory_canary_project"], "inventory project")
    )
    metadata = _authority_metadata(database, authority_uid=authority_uid)
    if (
        authority_uid != os.geteuid()
        or str(database) != current["authority_database"]
        or int(metadata["schema_version"]) != COORDINATOR_SCHEMA_VERSION
        or metadata["migration_state"] != "ready"
        or metadata["database_generation"] != repair["authority_generation"]
        or repair["profile_path"] != PROTECTED_PROFILE_PATH
        or repair["profile_owner_uid"] != authority_uid
        or repair["profile_mode"] != "0644"
        or repair["parser_verified"] is not True
        or repair["atomic_publication_verified"] is not True
        or type(repair["validation_uid"]) is not int
        or int(repair["validation_uid"]) <= 0
    ):
        raise CutoverError("routing profile does not match the current catalog")

    profile = _absolute(repair["profile_path"], "protected routing profile")
    info = profile.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != authority_uid
        or stat.S_IMODE(info.st_mode) != 0o644
        or _file_digest(profile) != repair["profile_sha256"]
    ):
        raise CutoverError("installed routing profile changed after publication")
    try:
        profile_document = json.loads(profile.read_bytes())
        parsed = profile_from_document(
            profile_document, effective_uid=int(repair["validation_uid"])
        )
    except (UnicodeDecodeError, json.JSONDecodeError, BrokerProfileError) as error:
        raise CutoverError("installed routing profile is invalid") from error

    bindings = repair["repository_bindings"]
    if not isinstance(bindings, list) or not bindings:
        raise CutoverError("routing profile has no repository catalog")
    by_root = {
        str(item.get("canonical_root")): item
        for item in bindings
        if isinstance(item, Mapping)
    }
    binding = by_root.get(project_path)
    repository = parsed.repositories.get(project_path)
    if (
        len(by_root) != len(bindings)
        or binding is None
        or repository is None
        or repository.repo_id != binding.get("repository_id")
        or repository.generation != binding.get("generation")
        or set(repair["repository_ids"])
        != {item.repo_id for item in parsed.repositories.values()}
    ):
        raise CutoverError("routing profile does not contain the selected repository")

    execution_uid = int(repair["validation_uid"])
    fetch = inventory_fetcher or _inventory_as_execution_uid
    inventory = fetch(
        release=release,
        project=project_path,
        execution_uid=execution_uid,
    )
    if not isinstance(inventory, Mapping):
        raise CutoverError("local routing inventory proof is invalid")
    _validate_routing_inventory(
        inventory,
        project=project_path,
        repository_id=repository.repo_id,
        repository_generation=repository.generation,
        authority_generation=str(repair["authority_generation"]),
        authority_uid=authority_uid,
    )
    return seal(
        PROFILE_INVENTORY_READINESS_KIND,
        {
            "profile_repair_sha256": repair["document_sha256"],
            "release_digest": current["release_digest"],
            "executor_release": str(release),
            "inventory_client_sha256": inventory_client_sha256,
            "authority_database": str(database),
            "authority_generation": repair["authority_generation"],
            "authority_schema_version": metadata["schema_version"],
            "authority_migration_state": metadata["migration_state"],
            "profile_path": str(profile),
            "profile_sha256": repair["profile_sha256"],
            "profile_owner_uid": authority_uid,
            "profile_mode": "0644",
            "full_regeneration": True,
            "strict_profile_parse": True,
            "project": project_path,
            "execution_uid": execution_uid,
            "repository_id": repository.repo_id,
            "repository_generation": repository.generation,
            "route_verified": True,
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
            "inventory_transport": "trusted-local-unix-socket",
            "inventory_service_uid": authority_uid,
            "inventory_database_generation": repair["authority_generation"],
            "verified_at": _now() if verified_at is None else verified_at,
        },
    )


def reverify_profile_inventory_readiness(
    *,
    state: Mapping[str, object],
    authority_uid: int = 0,
    inventory_fetcher: Any = None,
    verified_at: str | None = None,
) -> dict[str, object]:
    """Re-run the installed local-routing proof before retention."""

    current = validate_state(state)
    recorded = _recorded(current, "profile-inventory-readiness")
    if current["phase"] not in {"activated", "retained"} or recorded is None:
        raise CutoverError("fresh routing verification requires activation")
    readiness = verify_seal(
        recorded,
        kind=PROFILE_INVENTORY_READINESS_KIND,
        fields=PROFILE_INVENTORY_READINESS_FIELDS,
    )
    database = _absolute(current["authority_database"], "authority database")
    release = _absolute(current["release"], "immutable release")
    _client, inventory_client_sha256 = _immutable_inventory_client(release)
    metadata = _authority_metadata(database, authority_uid=authority_uid)
    if (
        authority_uid != os.geteuid()
        or readiness["authority_database"] != str(database)
        or readiness["release_digest"] != current["release_digest"]
        or readiness["executor_release"] != str(release)
        or readiness["inventory_client_sha256"] != inventory_client_sha256
        or readiness["project"] != current["inventory_canary_project"]
        or metadata["schema_version"] != COORDINATOR_SCHEMA_VERSION
        or metadata["migration_state"] != "ready"
        or metadata["database_generation"] != readiness["authority_generation"]
    ):
        raise CutoverError("fresh routing catalog binding changed")

    profile = _absolute(readiness["profile_path"], "protected routing profile")
    info = profile.lstat()
    if (
        str(profile) != PROTECTED_PROFILE_PATH
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != authority_uid
        or stat.S_IMODE(info.st_mode) != 0o644
        or _file_digest(profile) != readiness["profile_sha256"]
    ):
        raise CutoverError("installed routing profile changed before retention")
    try:
        parsed = profile_from_document(
            json.loads(profile.read_bytes()),
            effective_uid=int(readiness["execution_uid"]),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, BrokerProfileError) as error:
        raise CutoverError("installed routing profile is invalid") from error
    repository = parsed.repositories.get(str(readiness["project"]))
    if (
        repository is None
        or repository.repo_id != readiness["repository_id"]
        or repository.generation != readiness["repository_generation"]
    ):
        raise CutoverError("installed routing catalog changed before retention")
    fetch = inventory_fetcher or _inventory_as_execution_uid
    inventory = fetch(
        release=release,
        project=str(readiness["project"]),
        execution_uid=int(readiness["execution_uid"]),
    )
    if not isinstance(inventory, Mapping):
        raise CutoverError("local routing inventory proof is invalid")
    _validate_routing_inventory(
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
        "hosts",
        "open_blocking_conflicts",
        "missing_installations",
        "orphan_installations",
    }
    if not isinstance(invariants, Mapping) or set(invariants) != invariant_fields:
        raise CutoverError("authority readiness invariant fields are invalid")
    numeric_fields = invariant_fields - {"quick_check"}
    if (
        invariants["quick_check"] != "ok"
        or any(
            isinstance(invariants[field], bool)
            or not isinstance(invariants[field], int)
            or int(invariants[field]) < 0
            for field in numeric_fields
        )
        or int(invariants["repositories"]) <= 0
        or int(invariants["installations"]) != int(invariants["repositories"])
        or int(invariants["hosts"]) <= 0
        or any(
            int(invariants[field]) != 0
            for field in (
                "foreign_key_violations",
                "open_blocking_conflicts",
                "missing_installations",
                "orphan_installations",
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
    elif evidence_kind == "profile-inventory-readiness":
        if phase != "sealed":
            raise CutoverError("routing readiness requires the sealed migration")
        normalized = verify_seal(
            evidence,
            kind=PROFILE_INVENTORY_READINESS_KIND,
            fields=PROFILE_INVENTORY_READINESS_FIELDS,
        )
        if (
            normalized["release_digest"] != current["release_digest"]
            or normalized["executor_release"] != current["release"]
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["inventory_client_sha256"])) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["profile_repair_sha256"])) is None
            or normalized["authority_database"] != current["authority_database"]
            or normalized["authority_schema_version"] != COORDINATOR_SCHEMA_VERSION
            or normalized["authority_migration_state"] != "ready"
            or normalized["profile_path"] != PROTECTED_PROFILE_PATH
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["profile_sha256"])) is None
            or normalized["profile_owner_uid"] != current["authority_uid"]
            or normalized["profile_mode"] != "0644"
            or normalized["full_regeneration"] is not True
            or normalized["strict_profile_parse"] is not True
            or normalized["project"] != current["inventory_canary_project"]
            or type(normalized["execution_uid"]) is not int
            or int(normalized["execution_uid"]) <= 0
            or not isinstance(normalized["repository_id"], str)
            or not normalized["repository_id"]
            or type(normalized["repository_generation"]) is not int
            or int(normalized["repository_generation"]) < 0
            or normalized["route_verified"] is not True
            or normalized["inventory_command"] != ["inventory", "--project", current["inventory_canary_project"], "--no-docker", "--compact-json"]
            or re.fullmatch(r"[0-9a-f]{64}", str(normalized["inventory_sha256"])) is None
            or normalized["inventory_schema_version"] != 2
            or normalized["inventory_scope"] != "server-wide"
            or normalized["inventory_transport"] != "trusted-local-unix-socket"
            or normalized["inventory_service_uid"] != current["authority_uid"]
            or normalized["inventory_database_generation"] != normalized["authority_generation"]
        ):
            raise CutoverError("local routing inventory readiness evidence is invalid")
    elif evidence_kind == "candidate":
        if (
            phase != "sealed"
            or "profile-inventory-readiness" not in indexed
        ):
            raise CutoverError(
                "candidate activation requires local routing inventory readiness"
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
                "audit_counts",
                "project_isolation_complete",
                "authority_database",
                "audit_path",
                "ledger_path",
            }
            <= set(isolation)
            and isolation.get("ok") is True
            and isolation.get("kind") == "project-runtime-isolation-verification"
            and isolation.get("source_schema_version")
            == COORDINATOR_SCHEMA_VERSION
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
    fresh_readiness = reverify_profile_inventory_readiness(
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
                    "purpose": "install the listener-free first-adoption graph only while holding the exact schema-14 successor installer claim transferred by binding finalization",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "prepare-first-adoption",
                        "--state",
                        "<root-private-cutover-state>",
                        "--binding-attestation",
                        "<root-private-first-adoption-bindings-result>",
                        "--operation-id",
                        "<same-first-adoption-operation-uuid>",
                        "--first-adoption-attestation",
                        "<root-private-first-adoption-attestation>",
                    ],
                    "required_argument_groups": {
                        "candidate": "--candidate-slot-source, --rollback-directory, --graph-evidence, --graph-journal, --credential-evidence",
                        "legacy": "--legacy-console-env, --legacy-console-uid, --legacy-authority-database",
                        "background": "--background-project-root, --background-config-transaction",
                        "isolation": "--project-isolation-audit, --project-isolation-ledger",
                        "ports": "--port-reservations, --port-reservations-sha256",
                    },
                    "claim_contract": "the completed binding result, operation UUID, and first-adoption completion path must exactly match the durable installer claim; preparation retains that claim",
                    "then": "pass the graph and credential evidence to build-first-adoption-request",
                },
                {
                    "purpose": "compile every first-adoption source/final path, identity, listener, post-authority fleet request, and background handoff into one validated root-private sealed request; the transaction derives API routing profiles only after the storage split",
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
                        "candidate": "--candidate-slot-source, --candidate-rollback-directory, --legacy-console-env, --background-project-root, --background-config-transaction, --project-isolation-audit, --project-isolation-ledger, --graph-evidence, --candidate-graph-journal, --credential-evidence, --candidate-evidence, --activation-evidence",
                        "console": "--legacy-console-state, --console-state, --edge-identity-state, --console-config, --route-resolution, --publication-input, --console-port, --console-uid, --console-gid, --edge-uid, --edge-gid, --legacy-console-uid, --console-rollback-directory, --console-migration-journal",
                        "authority": "--legacy-authority-database, --authority-database, --inventory-database, --inventory-publication, --storage-split-attestation, --authority-adoption-pointer, --authority-operation-journal, --maintenance-root, --maintenance-gid, --authority-service-uid, --authority-service-gid, --inventory-uid, --inventory-gid",
                        "handoffs": "--api-handoff-port, --api-handoff-journal, --api-bootstrap-profile-path, --api-bootstrap-profile-journal, --api-final-profile-journal, --protected-profile-path, --protected-profile-access-gid, --api-service-uid, --profile-inventory-readiness-evidence, --edge-publication, --public-handoff-journal, --http-handoff-port, --https-handoff-port",
                        "fleet": "--fleet-authority-export, --fleet-evidence-root, --fleet-manifest-template, --fleet-manifest-template-sha256, --fleet-manifest-set, --fleet-adoption-request, --fleet-uid-helper",
                        "background": "--telegram-present or --no-telegram-present, --telegram-source, --telegram-destination, --telegram-rollback, --telegram-fence, --telegram-source-owner-uid, --telegram-destination-owner-uid, --telegram-destination-owner-gid",
                        "browser": "--browser-runtime-lock, --browser-storage-state, --browser-signing-key, --browser-journal, --browser-attestation, --browser-consumption",
                    },
                    "output_contract": "root-owned mode 0600 sealed devcoordinator-first-adoption-request",
                    "then": "pass this exact output to the following first-adoption action",
                },
                {
                    "purpose": "run the single resumable first-adoption transaction and release the installer claim when its completion attestation is durable",
                    "executable": f"{state['release']}/bin/devcoordinator-availability-activate",
                    "argv_prefix": [
                        "first-adoption",
                        "--request",
                        "<root-private-first-adoption-request>",
                        "--journal",
                        "<root-private-first-adoption-journal>",
                    ],
                    "required_arguments": [
                        "--attestation",
                        "--rollback-evidence",
                        "--binding-attestation",
                        "--operation-id",
                    ],
                    "record_after_routing": "project isolation, inventory readiness, fleet setup, Console/public handoff, candidate, then activation in one journal",
                    "rollback_order": "re-arm the exact authority maintenance fence before reversing notifications, fleet, public handoff, cutover evidence, profiles, API, policy, and graph; restore the exact bridge drop-in while its retirement guard still blocks starts, restore schema-12 authority/unit state, prove the bridge socket ready, then clear maintenance last",
                    "request_producer": "the immediately preceding build-first-adoption-request action",
                    "first_adoption_constraint": "the transaction refuses unless project isolation pending=0/unobservable=0 and all split, route, inventory, fleet, Test Store completion, and rollback seals verify",
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

    profile = actions.add_parser("publish-api-profile")
    profile.add_argument("--authority-database", required=True)
    profile.add_argument("--destination", default=PROTECTED_PROFILE_PATH)
    profile.add_argument("--validation-uid", type=int, required=True)
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
            "profile-inventory-readiness",
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
                        owner_kind=FIRST_ADOPTION_INSTALLER_CLAIM_KIND,
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
                        f"schema-14 successor ({successor_error})"
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
                        FIRST_ADOPTION_INSTALLER_CLAIM_KIND
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
        elif arguments.action == "publish-api-profile":
            result = reconstruct_api_profile_from_authority(
                authority_database=Path(arguments.authority_database),
                destination=Path(arguments.destination),
                validation_uid=arguments.validation_uid,
                authority_uid=arguments.authority_uid,
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
