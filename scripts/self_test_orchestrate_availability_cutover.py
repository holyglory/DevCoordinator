#!/usr/bin/env python3
"""Focused regression tests for the evidence-only availability cutover."""

from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from typing import Mapping
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
if str(ROOT / "skills/codex-dev-coordinator/scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "skills/codex-dev-coordinator/scripts"))

import orchestrate_availability_cutover as cutover  # noqa: E402
from devcoordinator.universal_test_admission import (  # noqa: E402
    build_legacy_test_admission_drain_proof,
)


RELEASE = "a" * 64
LEGACY_AUTHORITY_DATABASE = "/var/lib/devcoordinator/coordinator.sqlite3"
AUTHORITY_DATABASE = "/var/lib/devcoordinator/authority.sqlite3"
TEST_DATABASE = "/var/lib/devcoordinator-testd/tests.sqlite3"
AUTHORITY_GENERATION = "authority-generation"
TARGET_AUTHORITY_GENERATION = "00000000-0000-4000-8000-000000000013"
TEST_GENERATION = "test-generation"
TESTD_UID = 2305
API_UID = 2302
OWNER_UID = 2301
OWNER_ACCOUNT_ID = "holyglory"
INVENTORY_PROJECT = "/home/example/GlobalFinance"
SCHEMA_ATTESTATION = "/var/lib/devcoordinator-testd/schema-readiness.json"
FRESH_SCHEMA_ATTESTATION = (
    "/var/lib/devcoordinator-testd/"
    "schema-readiness-00000000-0000-4000-8000-000000000014.json"
)
BOOTSTRAP_ATTESTATION = "/var/lib/devcoordinator/bootstrap.json"
AUTHORITY_READINESS_ATTESTATION = "/var/lib/devcoordinator/authority-readiness.json"
PORT_RESERVATIONS_ATTESTATION = "/var/lib/devcoordinator/first-adoption-ports.json"


def first_adoption_port_reservations(
    *,
    authority_generation: str = AUTHORITY_GENERATION,
    state_revision_before: int = 8,
    created_at: str = "2026-07-28T00:02:00.000Z",
) -> dict[str, object]:
    operation_id = "00000000-0000-4000-8000-000000000019"
    reservations = {}
    for offset, role in enumerate(cutover.FIRST_ADOPTION_PORT_ROLES):
        reservations[role] = {
            "lease_id": f"00000000-0000-4000-8000-{20 + offset:012d}",
            "port": 30100 + offset,
            "agent": f"cutover:first-adoption:{operation_id}",
            "purpose": f"first-adoption:{RELEASE}:{role}",
            "status": "active",
            "expires_at": (
                None
                if role in cutover.FIRST_ADOPTION_CONSOLE_PORT_ROLES
                else "2026-07-28T01:02:00.000Z"
            ),
        }
    return cutover.seal(
        cutover.FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
        {
            "operation_id": operation_id,
            "release_digest": RELEASE,
            "authority_database": LEGACY_AUTHORITY_DATABASE,
            "authority_generation": authority_generation,
            "authority_state_revision_before": state_revision_before,
            "authority_state_revision_after": state_revision_before + 1,
            "repository_id": "repo-alpha",
            "repository_generation": 7,
            "canonical_root": INVENTORY_PROJECT,
            "port_range": dict(cutover.FIRST_ADOPTION_PORT_RANGE),
            "handoff_ttl_seconds": 3600,
            "reservations": reservations,
            "transaction_journal_sha256": "d" * 64,
            "service_unit": "devcoordinator-broker.service",
            "service_restored": True,
            "maintenance_cleared": True,
            "created_at": created_at,
            "completed_at": created_at,
        },
    )


def atomic_first_adoption_prepared() -> dict[str, object]:
    final = first_adoption_port_reservations()
    return cutover.seal(
        cutover.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
        {
            "operation_id": final["operation_id"],
            "release_digest": final["release_digest"],
            "authority_database": final["authority_database"],
            "authority_generation": final["authority_generation"],
            "authority_state_revision_before": final[
                "authority_state_revision_before"
            ],
            "authority_state_revision_after": final[
                "authority_state_revision_after"
            ],
            "repository_id": final["repository_id"],
            "repository_generation": final["repository_generation"],
            "canonical_root": final["canonical_root"],
            "port_range": final["port_range"],
            "handoff_ttl_seconds": final["handoff_ttl_seconds"],
            "reservations": final["reservations"],
            "port_journal_sha256": final["transaction_journal_sha256"],
            "atomic_transaction_journal_sha256": "e" * 64,
            "service_unit": final["service_unit"],
            "service_stopped": True,
            "maintenance": {
                "root": "/run/devcoordinator-maintenance",
                "gid": 2300,
                "deployment_id": "00000000-0000-4000-8000-000000000031",
                "message": cutover.PUBLIC_MAINTENANCE_MESSAGE,
                "retry_after_seconds": 5,
                "started_at": final["created_at"],
            },
            "created_at": final["created_at"],
            "completed_at": final["completed_at"],
        },
    )


def continuity(
    *,
    release_digest: str = RELEASE,
    started_at: str = "2026-07-28T00:06:59Z",
    completed_at: str = "2026-07-28T00:07:00Z",
) -> dict[str, object]:
    targets = [
        {
            "target_id": "http:https://console.vr.ae/healthz",
            "protocol": "http",
            "category": "console",
            "url": "https://console.vr.ae/healthz",
            "baseline_status": 200,
            "last_status": 200,
            "sample_count": 2,
            "failure_count": 0,
            "max_latency_ms": 2,
        },
        {
            "target_id": "websocket:wss://console.vr.ae/",
            "protocol": "websocket",
            "category": "console",
            "url": "wss://console.vr.ae/",
            "baseline_status": 404,
            "last_status": 404,
            "sample_count": 2,
            "failure_count": 0,
            "max_latency_ms": 2,
        },
    ]
    return cutover.seal(
        cutover.CONTINUITY_PROBE_KIND,
        {
            "operation_id": str(uuid.uuid4()),
            "release_digest": release_digest,
            "started_at": started_at,
            "completed_at": completed_at,
            "sample_interval_ms": 50,
            "round_count": 2,
            "sample_count": 4,
            "http_sample_count": 2,
            "websocket_sample_count": 2,
            "connection_refused_count": 0,
            "project_route_failures": 0,
            "failed_sample_count": 0,
            "ttfb_p99_ms": 2,
            "control_plane_p99_ms": 2,
            "targets": targets,
            "samples_sha256": "a" * 64,
            "slo": {
                "ttfb_p99_ms": 100,
                "control_plane_p99_ms": 100,
                "minimum_rounds": 2,
            },
            "passed": True,
        },
    )


def schema_readiness() -> dict[str, object]:
    return cutover.seal(
        cutover.SCHEMA_READINESS_KIND,
        {
            "operation_id": "00000000-0000-4000-8000-000000000014",
            "test_database": TEST_DATABASE,
            "action": "attested-fresh-v5",
            "journal_kind": "schema_readiness_v5",
            "journal": {"replayed": False},
            "store": {
                "schema_version": 5,
                "store_generation": TEST_GENERATION,
            },
            "published_at": "2026-07-28T00:00:00Z",
        },
    )


def bootstrap_attestation() -> dict[str, object]:
    schema = schema_readiness()
    return cutover.seal(
        cutover.FIRST_DEPLOYMENT_BOOTSTRAP_KIND,
        {
            "operation_id": "00000000-0000-4000-8000-000000000014",
            "release": f"/opt/devcoordinator/releases/{RELEASE}",
            "release_digest": RELEASE,
            "rendered_units": "/run/devcoordinator/cutover/units",
            "sysusers_config_sha256": "1" * 64,
            "tmpfiles_config_sha256": "2" * 64,
            "service_identities": {
                "users": {
                    "root": {"uid": 0, "gid": 0},
                    "devcoordinator-testd": {"uid": TESTD_UID, "gid": TESTD_UID},
                },
                "groups": {},
            },
            "private_directories": [],
            "authority_database": AUTHORITY_DATABASE,
            "inventory_database": "/var/lib/devcoordinator-inventory/inventory.sqlite3",
            "test_database": TEST_DATABASE,
            "test_store": schema["store"],
            "schema_readiness": {
                "path": SCHEMA_ATTESTATION,
                "document_sha256": schema["document_sha256"],
                "branch": "attested-fresh-v5",
                "store_generation": TEST_GENERATION,
            },
            "created_at": "2026-07-28T00:00:00Z",
        },
    )


def authority_readiness_attestation(
    *, release: Path | str | None = None
) -> dict[str, object]:
    release_path = (
        str(release)
        if release is not None
        else f"/opt/devcoordinator/releases/{RELEASE}"
    )
    invariants = {
        "quick_check": "ok",
        "foreign_key_violations": 0,
        "repositories": 1,
        "installations": 1,
        "principals": 1,
        "enrollments": 1,
        "hosts": 1,
        "open_blocking_conflicts": 0,
        "missing_installations": 0,
        "orphan_installations": 0,
        "orphan_repository_enrollments": 0,
        "orphan_principal_enrollments": 0,
        "partial_v13_tables": [],
    }
    metadata = {
        "schema_version": 12,
        "database_generation": AUTHORITY_GENERATION,
        "state_revision": 7,
        "observation_revision": 11,
        "authority_mode": "sqlite",
        "migration_state": "empty",
        "first_sqlite_mutation_at": "2026-07-16T12:26:48Z",
        "created_at": "2026-07-16T12:20:00Z",
        "updated_at": "2026-07-28T00:00:00Z",
    }
    post_metadata = dict(metadata)
    post_metadata.update(
        {
            "migration_state": "ready",
            "state_revision": 8,
            "updated_at": "2026-07-28T00:01:00Z",
        }
    )
    return cutover.seal(
        cutover.AUTHORITY_READINESS_RESULT_KIND,
        {
            "operation_id": "00000000-0000-4000-8000-000000000016",
            "intent_sha256": "a" * 64,
            "release": release_path,
            "release_digest": RELEASE,
            "database": LEGACY_AUTHORITY_DATABASE,
            "database_identity_before": {"device": 1, "inode": 2, "size": 10},
            "database_identity_after": {"device": 1, "inode": 2, "size": 10},
            "maintenance": {
                "root": "/run/devcoordinator-maintenance",
                "gid": 986,
                "deployment_id": "00000000-0000-4000-8000-000000000017",
                "message": cutover.PUBLIC_MAINTENANCE_MESSAGE,
                "retry_after_seconds": 10,
                "started_at": "2026-07-28T00:00:00Z",
            },
            "writer_lock": {
                "path": "/var/lib/devcoordinator/.broker-service.lock",
                "device": 1,
                "inode": 3,
                "uid": 0,
                "mode": "0600",
                "acquired": True,
                "active_broker_excluded": True,
            },
            "backup": {
                "path": "/var/lib/devcoordinator/authority-readiness.sqlite3",
                "attestation": "/var/lib/devcoordinator/authority-readiness-backup.json",
                "attestation_sha256": "b" * 64,
                "backup_sha256": "c" * 64,
                "backup_bytes": 10,
                "database_device": 1,
                "database_inode": 2,
            },
            "precondition": {"metadata": metadata, "invariants": invariants},
            "postcondition": {"metadata": post_metadata, "invariants": invariants},
            "applied": True,
            "recovered": False,
            "completed_at": "2026-07-28T00:01:01Z",
        },
    )


def sealed_state(
    *,
    authority_backup_required: bool = True,
    release: Path | str | None = None,
) -> dict[str, object]:
    release_path = (
        str(release)
        if release is not None
        else f"/opt/devcoordinator/releases/{RELEASE}"
    )
    return cutover.seal(
        cutover.STATE_KIND,
        {
            "cutover_id": str(uuid.uuid4()),
            "phase": "planned",
            "release": release_path,
            "release_digest": RELEASE,
            "rendered_units": "/run/devcoordinator/cutover/units",
            "authority_uid": 0,
            "testd_uid": TESTD_UID,
            "legacy_authority_database": LEGACY_AUTHORITY_DATABASE,
            "authority_database": AUTHORITY_DATABASE,
            "test_database": TEST_DATABASE,
            "inventory_canary_project": INVENTORY_PROJECT,
            "authority_backup_directory": "/var/backups/devcoordinator",
            "test_backup_directory": "/var/backups/devcoordinator-testd",
            "migration_state": "/var/lib/devcoordinator/cutover.json",
            "drain_proof": "/var/lib/devcoordinator/drain.json",
            "cutover_seal": "/var/lib/devcoordinator/seal.json",
            "reserve_bytes": 1_000_000,
            "retain_until": "2026-09-01T00:00:00Z",
            "authority_backup_required": authority_backup_required,
            "evidence": {
                "first-deployment-bootstrap": bootstrap_attestation(),
                "authority-readiness": authority_readiness_attestation(
                    release=release_path
                ),
            },
            "created_at": "2026-07-28T00:00:00Z",
            "updated_at": "2026-07-28T00:00:00Z",
            "state_generation": 0,
        },
    )


def backup(role: str) -> dict[str, object]:
    authority = role == "authority"
    return cutover.seal(
        cutover.BACKUP_KIND,
        {
            "database": (
                LEGACY_AUTHORITY_DATABASE if authority else TEST_DATABASE
            ),
            "database_device": 1 if authority else 2,
            "database_inode": 11 if authority else 22,
            "database_sha256": ("1" if authority else "2") * 64,
            "backup": f"/var/backups/{role}.sqlite3",
            "backup_sha256": ("3" if authority else "4") * 64,
            "backup_bytes": 4096,
            "quick_check": "ok",
            "foreign_key_violations": 0,
            "available_bytes": 10_000_000,
            "required_bytes": 1_000_000,
            "expected_uid": 0 if authority else TESTD_UID,
            "created_at": "2026-07-28T00:01:00Z",
        },
    )


def imported(pass_kind: str, *, migration_id: str) -> dict[str, object]:
    return cutover.seal(
        cutover.INITIAL_IMPORT_KIND,
        {
            "migration_id": migration_id,
            "pass_kind": pass_kind,
            "authority_generation": AUTHORITY_GENERATION,
            "watermark_fingerprint": ("5" if pass_kind == "initial" else "6") * 64,
            "export_fingerprint": ("7" if pass_kind == "initial" else "8") * 64,
            "test_store_generation": TEST_GENERATION,
            "chunk_count": 2,
            "final_chunk_sha256": "9" * 64,
            "run_count": 100,
            "case_count": 1000,
            "destination_projection_chain_sha256": "b" * 64,
            "source_retained": True,
        },
    )

def profile_inventory_readiness(
    *, release: Path | str | None = None
) -> dict[str, object]:
    release_path = (
        str(release)
        if release is not None
        else f"/opt/devcoordinator/releases/{RELEASE}"
    )
    return cutover.seal(
        cutover.PROFILE_INVENTORY_READINESS_KIND,
        {
            "profile_repair_sha256": "f" * 64,
            "release_digest": RELEASE,
            "executor_release": release_path,
            "inventory_client_sha256": "2" * 64,
            "authority_database": AUTHORITY_DATABASE,
            "authority_generation": TARGET_AUTHORITY_GENERATION,
            "authority_schema_version": 15,
            "authority_migration_state": "ready",
            "profile_path": cutover.PROTECTED_PROFILE_PATH,
            "profile_sha256": "c" * 64,
            "profile_owner_uid": 0,
            "profile_mode": "0644",
            "full_regeneration": True,
            "strict_profile_parse": True,
            "project": INVENTORY_PROJECT,
            "execution_uid": API_UID,
            "repository_id": "repo-alpha",
            "repository_generation": 7,
            "route_verified": True,
            "inventory_command": [
                "inventory",
                "--project",
                INVENTORY_PROJECT,
                "--no-docker",
                "--compact-json",
            ],
            "inventory_sha256": "e" * 64,
            "inventory_schema_version": 2,
            "inventory_scope": "server-wide",
            "inventory_transport": "authenticated-unix-socket",
            "inventory_service_uid": 0,
            "inventory_database_generation": TARGET_AUTHORITY_GENERATION,
            "verified_at": "2026-07-28T00:05:30Z",
        },
    )


def refreshed_profile_inventory_readiness(
    state: Mapping[str, object],
    *,
    verified_at: str = "2026-08-01T00:00:00.000Z",
) -> dict[str, object]:
    recorded = state["evidence"]["profile-inventory-readiness"]
    return cutover.seal(
        cutover.PROFILE_INVENTORY_READINESS_KIND,
        {
            key: value
            for key, value in recorded.items()
            if key not in {
                "schema_version",
                "kind",
                "document_sha256",
                "inventory_sha256",
                "verified_at",
            }
        }
        | {
            "inventory_sha256": "1" * 64,
            "verified_at": verified_at,
        },
    )

def candidate(*, release: Path | str | None = None) -> dict[str, object]:
    release_path = (
        str(release)
        if release is not None
        else f"/opt/devcoordinator/releases/{RELEASE}"
    )
    console = f"devcoordinator-console@{RELEASE}.service"
    units = cutover._candidate_units(RELEASE)
    ready = {unit: True for unit in sorted(units)}
    sockets = {
        name: index + 100 for index, name in enumerate(sorted(cutover.SOCKET_NAMES))
    }
    preparation = cutover.seal(
        cutover.CANDIDATE_PREPARATION_KIND,
        {
            "release_digest": RELEASE,
            "executor_release": release_path,
            "credential_preflight_sha256": "2" * 64,
            "host_preflight_sha256": "3" * 64,
            "background_config": {
                "ok": True,
                "kind": cutover.BACKGROUND_CONFIG_KIND,
                "directory": "/var/lib/devcoordinator/cutover/background-config",
                "project_root": "/home/DevCoordinator",
                "files": {
                    "notifications.env": "sha256:" + "5" * 64,
                    "observer.env": "sha256:" + "6" * 64,
                },
                "administrator_count": 1,
                "transaction_sha256": "7" * 64,
            },
            "project_isolation": {
                "ok": True,
                "kind": "project-runtime-isolation-verification",
                "audit_sha256": "sha256:" + "8" * 64,
                "source_schema_version": 15,
                "audit_counts": {
                    "compliant": 1,
                    "legacy_requires_recreation": 0,
                    "unobservable": 0,
                },
                "project_isolation_complete": True,
                "authority_database": AUTHORITY_DATABASE,
                "audit_path": "/var/lib/devcoordinator/cutover/project-isolation.json",
                "ledger_path": None,
                "observation_only": False,
                "project_resources_mutated": False,
            },
            "console_slot_ports": {
                "console_outer": 31443,
                "console_inner": 32443,
            },
            "prior_units": {unit: {"active": False, "enabled": False} for unit in ready},
            "prior_files": {"/etc/systemd/system/example": {"existed": False, "backup": None}},
            "installed_files": {"/etc/systemd/system/example": {"sha256": "4" * 64}},
            "ready_units": ready,
            "socket_inodes": sockets,
            "created_at": "2026-07-28T00:05:45Z",
        },
    )
    return cutover.seal(
        cutover.CANDIDATE_KIND,
        {
            "release_digest": RELEASE,
            "ready_units": ready,
            "service_uids": {
                "devcoordinator-edge.service": 2301,
                "devcoordinator-api.service": API_UID,
                "devcoordinator-authority.service": 0,
                console: 2303,
                "devcoordinator-observer.service": 2304,
                "devcoordinator-testd.service": TESTD_UID,
                "devcoordinator-test-snapshotd.service": 0,
            },
            "service_slices": {
                "devcoordinator-edge.service": cutover.CONTROL_SLICE,
                "devcoordinator-api.service": cutover.CONTROL_SLICE,
                "devcoordinator-authority.service": cutover.CONTROL_SLICE,
                console: cutover.CONTROL_SLICE,
                "devcoordinator-observer.service": cutover.BACKGROUND_SLICE,
                "devcoordinator-testd.service": cutover.BACKGROUND_SLICE,
                "devcoordinator-test-snapshotd.service": cutover.BACKGROUND_SLICE,
            },
            "socket_inodes": sockets,
            "authority_database": AUTHORITY_DATABASE,
            "test_database": TEST_DATABASE,
            "migration_seal_sha256": "",
            "checks_passed": True,
            "preparation": preparation,
            "created_at": "2026-07-28T00:06:00Z",
        },
    )


def through_seal(
    *, release: Path | str | None = None
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    state = sealed_state(release=release)
    authority_backup = backup("authority")
    test_backup = backup("testd")
    state = cutover.transition(
        state, evidence_kind="authority-backup", evidence=authority_backup
    )
    state = cutover.transition(
        state, evidence_kind="testd-backup", evidence=test_backup
    )
    migration_id = str(uuid.uuid4())
    initial = imported("initial", migration_id=migration_id)
    final = imported("final", migration_id=migration_id)
    state = cutover.transition(state, evidence_kind="initial-import", evidence=initial)
    drain = dict(
        build_legacy_test_admission_drain_proof(
            drain_id=str(uuid.uuid4()),
            authority_generation=AUTHORITY_GENERATION,
            activated_at_epoch=100,
            activated_by_uid=0,
            drained_at_epoch=101,
            broker_instance_id="broker-instance",
        )
    )
    state = cutover.transition(state, evidence_kind="admission-drain", evidence=drain)
    state = cutover.transition(state, evidence_kind="final-import", evidence=final)
    migration_seal = cutover.seal(
        cutover.SEAL_KIND,
        {
            "migration_id": migration_id,
            "authority_database": LEGACY_AUTHORITY_DATABASE,
            "authority_generation": AUTHORITY_GENERATION,
            "test_database": TEST_DATABASE,
            "test_store_generation": TEST_GENERATION,
            "drain_proof_fingerprint": cutover._digest(drain),
            "final_export_fingerprint": final["export_fingerprint"],
            "final_watermark_fingerprint": final["watermark_fingerprint"],
            "destination_attestation_fingerprint": final["document_sha256"],
            "legacy_source_retained": True,
            "activation_ready": True,
            "rollback": {"safe": True},
        },
    )
    state = cutover.transition(
        state, evidence_kind="migration-seal", evidence=migration_seal
    )
    return state, authority_backup, test_backup


def through_discarded_store(
    *, release: Path | str | None = None
) -> dict[str, object]:
    state = sealed_state(release=release)
    unsigned = {
        key: value
        for key, value in state.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned.update(
        {
            "phase": "sealed",
            "evidence": dict(state["evidence"])
            | {"test-history-discard": schema_readiness()},
        }
    )
    return cutover.seal(cutover.STATE_KIND, unsigned)


def through_activation() -> tuple[
    dict[str, object], dict[str, object], dict[str, object], dict[str, object]
]:
    state, authority_backup, test_backup = through_seal()
    state = cutover.transition(
        state,
        evidence_kind="profile-inventory-readiness",
        evidence=profile_inventory_readiness(),
    )
    candidate_evidence = candidate()
    candidate_evidence = cutover.seal(
        cutover.CANDIDATE_KIND,
        {
            key: value
            for key, value in candidate_evidence.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        | {
            "migration_seal_sha256": state["evidence"]["migration-seal"][
                "document_sha256"
            ]
        },
    )
    state = cutover.transition(
        state, evidence_kind="candidate", evidence=candidate_evidence
    )
    probe = continuity()
    activation = cutover.seal(
        cutover.ACTIVATION_KIND,
        {
            "release_digest": RELEASE,
            "migration_seal_sha256": candidate_evidence[
                "migration_seal_sha256"
            ],
            "profile_inventory_readiness_sha256": state["evidence"][
                "profile-inventory-readiness"
            ]["document_sha256"],
            "executor_release": f"/opt/devcoordinator/releases/{RELEASE}",
            "credential_preflight_sha256": "c" * 64,
            "publication_switch": {
                "previous_generation": 7,
                "generation": 8,
                "previous_payload_sha256": "d" * 64,
                "payload_sha256": "e" * 64,
                "previous_release_digest": "b" * 64,
                "release_digest": RELEASE,
                "previous_port": 30443,
                "port": 31443,
            },
            "continuity_probe": probe,
            "socket_inodes_before": candidate_evidence["socket_inodes"],
            "socket_inodes_after": candidate_evidence["socket_inodes"],
            "connection_refused_count": probe["connection_refused_count"],
            "project_route_failures": probe["project_route_failures"],
            "legacy_units_active": [],
            "authority_ready": True,
            "testd_ready": True,
            "console_ready": True,
            "browser_lcp_attestation_sha256": "7" * 64,
            "browser_lcp_consumption_sha256": "8" * 64,
            "created_at": "2026-07-28T00:07:00Z",
        },
    )
    state = cutover.transition(
        state, evidence_kind="activation", evidence=activation
    )
    return state, authority_backup, test_backup, activation


def live_rollback_rehearsal(
    state: Mapping[str, object], activation: Mapping[str, object]
) -> dict[str, object]:
    previous_release = str(
        activation["publication_switch"]["previous_release_digest"]
    )
    before = {
        "generation": 8,
        "payload_sha256": "e" * 64,
        "release_digest": RELEASE,
        "port": 31443,
        "routing_sha256": "9" * 64,
    }
    rollback = {
        "generation": 9,
        "payload_sha256": "f" * 64,
        "release_digest": previous_release,
        "port": 30443,
        "routing_sha256": "9" * 64,
    }
    reactivated = {
        "generation": 10,
        "payload_sha256": "0" * 64,
        "release_digest": RELEASE,
        "port": 31443,
        "routing_sha256": "9" * 64,
    }
    return cutover.seal(
        cutover.LIVE_ROLLBACK_REHEARSAL_KIND,
        {
            "operation_id": str(uuid.uuid4()),
            "activation_sha256": activation["document_sha256"],
            "activation_state_generation": state["state_generation"],
            "release_digest": RELEASE,
            "executor_release": f"/opt/devcoordinator/releases/{RELEASE}",
            "journal_sha256": "1" * 64,
            "publication_before": before,
            "rollback_slot": {
                "target_release_digest": previous_release,
                "target_port": 30443,
                "target_mode": "active",
                "old_release_digest": RELEASE,
                "old_port": 31443,
                "old_mode": "standby",
            },
            "rollback_switch": {
                "previous_generation": 8,
                "generation": 9,
                "previous_payload_sha256": "e" * 64,
                "payload_sha256": "f" * 64,
                "previous_release_digest": RELEASE,
                "release_digest": previous_release,
                "previous_port": 31443,
                "port": 30443,
            },
            "publication_rollback": rollback,
            "rollback_continuity_probe": continuity(
                release_digest=previous_release,
                started_at="2026-07-28T00:07:11Z",
                completed_at="2026-07-28T00:07:14Z",
            ),
            "reactivation_slot": {
                "target_release_digest": RELEASE,
                "target_port": 31443,
                "target_mode": "active",
                "old_release_digest": previous_release,
                "old_port": 30443,
                "old_mode": "standby",
            },
            "reactivation_switch": {
                "previous_generation": 9,
                "generation": 10,
                "previous_payload_sha256": "f" * 64,
                "payload_sha256": "0" * 64,
                "previous_release_digest": previous_release,
                "release_digest": RELEASE,
                "previous_port": 30443,
                "port": 31443,
            },
            "publication_reactivated": reactivated,
            "reactivation_continuity_probe": continuity(
                started_at="2026-07-28T00:07:15Z",
                completed_at="2026-07-28T00:07:18Z",
            ),
            "supported_rollback_head": reactivated,
            "socket_inodes_before": activation["socket_inodes_after"],
            "socket_inodes_after": activation["socket_inodes_after"],
            "continuity_probe": continuity(
                started_at="2026-07-28T00:07:10Z",
                completed_at="2026-07-28T00:07:20Z",
            ),
            "profile_health": {
                name: {"ready": True, "sha256": "2" * 64}
                for name in ("before", "rollback", "reactivated")
            },
            "data_health": {
                name: {"ready": True, "stores": {}}
                for name in ("before", "rollback", "reactivated")
            },
            "recovery_count": 0,
            "browser_lcp_attestation_sha256": activation[
                "browser_lcp_attestation_sha256"
            ],
            "browser_lcp_consumption_sha256": activation[
                "browser_lcp_consumption_sha256"
            ],
            "completed_at": "2026-07-28T00:07:21Z",
        },
    )


class CutoverTransitionTests(unittest.TestCase):
    def test_first_deployment_bootstrap_rejects_obsolete_shared_groups(self) -> None:
        value = bootstrap_attestation()
        unsigned = {
            key: json.loads(json.dumps(item))
            for key, item in value.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["service_identities"]["groups"] = {
            "devcoordinator-clients": {"gid": 2310}
        }
        with self.assertRaisesRegex(
            cutover.CutoverError, "bootstrap store evidence"
        ):
            cutover._first_deployment_bootstrap(
                cutover.seal(cutover.FIRST_DEPLOYMENT_BOOTSTRAP_KIND, unsigned)
            )

    def test_authority_repository_socket_uses_trusted_local_identity(self) -> None:
        class SocketPath:
            def __init__(self, info: os.stat_result) -> None:
                self.info = info

            def lstat(self) -> os.stat_result:
                return self.info

            def __str__(self) -> str:
                return cutover.AUTHORITY_SOCKET_PATH

        class Client:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def settimeout(self, _seconds: float) -> None:
                return None

            def connect(self, path: str) -> None:
                self.path = path

            def getsockopt(self, *_args) -> bytes:
                return cutover.struct.pack("3i", 4321, 0, 0)

        def observe(mode: int, gid: int):
            info = os.stat_result(
                (stat.S_IFSOCK | mode, 17, 23, 1, 0, gid, 0, 0, 0, 0)
            )
            with mock.patch.object(
                cutover, "_absolute", return_value=SocketPath(info)
            ), mock.patch.object(cutover.socket, "socket", return_value=Client()):
                return cutover._authority_repository_socket_observation(
                    Path(cutover.AUTHORITY_SOCKET_PATH)
                )

        identity, peer = observe(0o666, 0)
        self.assertEqual(identity["uid"], 0)
        self.assertEqual(identity["gid"], 0)
        self.assertEqual(identity["mode"], 0o666)
        self.assertEqual(peer, {"pid": 4321, "uid": 0, "gid": 0})
        with self.assertRaisesRegex(cutover.CutoverError, "identity is unsafe"):
            observe(0o660, 2310)

    def test_first_adoption_binding_finalization_accepts_only_unstarted_or_discarded_history(self) -> None:
        planned = cutover.validate_state(sealed_state())
        self.assertIsNone(cutover._first_adoption_binding_completion(planned))

        discarded = cutover.validate_state(through_discarded_store())
        completion = cutover._first_adoption_binding_completion(discarded)
        self.assertEqual(completion["mode"], "history-discarded")

        migrated = cutover.validate_state(through_seal()[0])
        with self.assertRaisesRegex(
            cutover.CutoverError, "sealed discarded Test Store"
        ):
            cutover._first_adoption_binding_completion(migrated)

        contradictory = dict(planned)
        contradictory["evidence"] = dict(planned["evidence"])
        contradictory["evidence"]["test-history-discard"] = schema_readiness()
        with self.assertRaisesRegex(
            cutover.CutoverError, "sealed discarded Test Store"
        ):
            cutover._first_adoption_binding_completion(contradictory)

    def test_destructive_fresh_store_is_a_complete_fail_closed_cutover_branch(self) -> None:
        state = through_discarded_store()
        normalized = cutover.validate_state(state)
        completion = cutover._test_store_cutover_completion(normalized)
        self.assertEqual(completion["mode"], "history-discarded")
        self.assertEqual(completion["authority_generation"], AUTHORITY_GENERATION)
        self.assertEqual(
            completion["document_sha256"],
            state["evidence"]["test-history-discard"]["document_sha256"],
        )
        state = cutover.transition(
            state,
            evidence_kind="profile-inventory-readiness",
            evidence=profile_inventory_readiness(),
        )
        candidate_evidence = candidate()
        candidate_evidence = cutover.seal(
            cutover.CANDIDATE_KIND,
            {
                key: value
                for key, value in candidate_evidence.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            | {"migration_seal_sha256": completion["document_sha256"]},
        )
        state = cutover.transition(
            state, evidence_kind="candidate", evidence=candidate_evidence
        )
        self.assertEqual(state["phase"], "candidate_verified")

        contradictory = through_discarded_store()
        unsigned = {
            key: value
            for key, value in contradictory.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["evidence"] = dict(contradictory["evidence"])
        unsigned["evidence"]["migration-seal"] = through_seal()[0]["evidence"][
            "migration-seal"
        ]
        with self.assertRaisesRegex(
            cutover.CutoverError, "cannot both migrate and discard"
        ):
            cutover.validate_state(cutover.seal(cutover.STATE_KIND, unsigned))

        stale = through_discarded_store()
        stale_unsigned = {
            key: value
            for key, value in stale.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        stale_evidence = dict(stale["evidence"])
        fresh = schema_readiness()
        fresh_values = {
            key: value
            for key, value in fresh.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        fresh_values["store"] = {
            "schema_version": 5,
            "store_generation": "another-generation",
        }
        stale_evidence["test-history-discard"] = cutover.seal(
            cutover.SCHEMA_READINESS_KIND, fresh_values
        )
        stale_unsigned["evidence"] = stale_evidence
        with self.assertRaisesRegex(
            cutover.CutoverError, "contradicts the cutover ledger"
        ):
            cutover.validate_state(cutover.seal(cutover.STATE_KIND, stale_unsigned))

    def test_authority_readiness_remains_bound_to_the_exact_cutover(self) -> None:
        release = Path(f"/tmp/devcoordinator-fixture-releases/{RELEASE}")
        fixture = sealed_state(release=release)
        unsigned = {
            key: value
            for key, value in fixture.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["evidence"] = {
            "authority-readiness": fixture["evidence"]["authority-readiness"]
        }
        valid = cutover.seal(cutover.STATE_KIND, unsigned)
        self.assertEqual(cutover.validate_state(valid)["release"], str(release))

        changes = {
            "release": Path("/tmp/another-release") / RELEASE,
            "release_digest": "b" * 64,
            "legacy_authority_database": (
                "/var/lib/devcoordinator/another-coordinator.sqlite3"
            ),
        }
        for field, changed in changes.items():
            with self.subTest(field=field):
                contradictory = {
                    key: value
                    for key, value in valid.items()
                    if key not in {"schema_version", "kind", "document_sha256"}
                }
                contradictory[field] = (
                    str(changed) if isinstance(changed, Path) else changed
                )
                resealed = cutover.seal(cutover.STATE_KIND, contradictory)
                with self.assertRaisesRegex(
                    cutover.CutoverError,
                    "authority readiness evidence changed its cutover binding",
                ):
                    cutover.validate_state(resealed)

    def test_continuity_probe_rejects_forged_and_failed_seals(self) -> None:
        valid = continuity()
        self.assertTrue(cutover._continuity_probe(valid)["passed"])
        forged = dict(valid)
        forged["ttfb_p99_ms"] = 99
        with self.assertRaisesRegex(cutover.CutoverError, "digest"):
            cutover._continuity_probe(forged)
        failed_values = {
            key: value
            for key, value in valid.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        failed_values["connection_refused_count"] = 1
        failed_values["passed"] = True
        failed = cutover.seal(cutover.CONTINUITY_PROBE_KIND, failed_values)
        with self.assertRaisesRegex(cutover.CutoverError, "SLO"):
            cutover._continuity_probe(failed)

    def test_supported_drain_executor_binds_generation_proof(self) -> None:
        state = sealed_state()
        state = cutover.seal(
            cutover.STATE_KIND,
            {
                key: value
                for key, value in state.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            | {"drain_proof": f"/tmp/drain-{uuid.uuid4()}.json"},
        )
        state = cutover.transition(
            state, evidence_kind="authority-backup", evidence=backup("authority")
        )
        state = cutover.transition(
            state, evidence_kind="testd-backup", evidence=backup("testd")
        )
        state = cutover.transition(
            state,
            evidence_kind="initial-import",
            evidence=imported("initial", migration_id=str(uuid.uuid4())),
        )
        proof = dict(
            build_legacy_test_admission_drain_proof(
                drain_id=str(uuid.uuid4()),
                authority_generation=AUTHORITY_GENERATION,
                activated_at_epoch=100,
                activated_by_uid=0,
                drained_at_epoch=101,
                broker_instance_id="broker-instance",
            )
        )
        observed = {}

        def broker_call(request):
            observed["operation"] = request.operation
            observed["generation"] = request.authority_generation
            return {"ok": True, "result": {"proof": proof}}

        with mock.patch.object(cutover.os, "geteuid", return_value=0), mock.patch.object(
            cutover, "load_state", return_value=state
        ), mock.patch.object(
            cutover, "_authority_generation", return_value=AUTHORITY_GENERATION
        ), mock.patch.object(
            cutover,
            "verify_legacy_test_admission_drain_proof",
            side_effect=lambda _path, value, expected_uid: value,
        ), mock.patch.object(
            cutover, "_publish_evidence"
        ), mock.patch.object(
            cutover,
            "record_evidence",
            return_value={"phase": "admission_drained", "replayed": False},
        ):
            result = cutover.execute_admission_drain(
                state_path=Path("/var/lib/devcoordinator/cutover-state.json"),
                proof_output=Path(state["drain_proof"]),
                broker_socket=Path(cutover.AUTHORITY_SOCKET_PATH),
                authority_uid=0,
                expected_broker_uid=0,
                broker_call=broker_call,
            )
        self.assertEqual(observed["generation"], AUTHORITY_GENERATION)
        self.assertEqual(result["proof"], proof)
        self.assertEqual(result["phase"], "admission_drained")

    def test_supported_rehearsal_and_retention_producers_converge(self) -> None:
        state, authority_backup, test_backup, activation = through_activation()
        activation_state = state
        restore_values = {
            "authority": {
                "source": authority_backup["backup"],
                "source_sha256": authority_backup["backup_sha256"],
                "restored_sha256": "5" * 64,
                "quick_check": "ok",
                "foreign_key_violations": 0,
            },
            "testd": {
                "source": test_backup["backup"],
                "source_sha256": test_backup["backup_sha256"],
                "restored_sha256": "6" * 64,
                "quick_check": "ok",
                "foreign_key_violations": 0,
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            rehearsal_output = root / "rehearsal.json"
            captured = {}

            def publish(_path, document, *, uid):
                del uid
                captured["rehearsal"] = dict(document)

            with mock.patch.object(cutover.os, "geteuid", return_value=0), mock.patch.object(
                cutover, "_private_parent"
            ), mock.patch.object(
                cutover, "load_state", return_value=state
            ), mock.patch.object(
                cutover, "_database_identity", return_value={"device": 1, "inode": 2, "size": 3}
            ), mock.patch.object(
                cutover,
                "_restore_backup_for_rehearsal",
                side_effect=lambda **values: restore_values[values["role"]],
            ), mock.patch.object(
                cutover, "_publish_evidence", side_effect=publish
            ), mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "activated", "replayed": False},
            ):
                result = cutover.produce_rollback_rehearsal(
                    state_path=root / "state.json",
                    scratch_directory=scratch,
                    output=rehearsal_output,
                    authority_uid=0,
                )
            rehearsal = result["attestation"]
            self.assertEqual(
                rehearsal["continuity_probe_sha256"],
                activation["continuity_probe"]["document_sha256"],
            )
            state = cutover.transition(
                state,
                evidence_kind="rollback-rehearsal",
                evidence=rehearsal,
            )
            live_rehearsal = live_rollback_rehearsal(state, activation)
            state = cutover.transition(
                state,
                evidence_kind="live-rollback-rehearsal",
                evidence=live_rehearsal,
            )
            self.assertEqual(
                cutover.transition(
                    state,
                    evidence_kind="rollback-rehearsal",
                    evidence=rehearsal,
                ),
                state,
            )
            pending_rehearsal = root / "pending-rehearsal.json"
            pending_rehearsal.write_text("{}\n", encoding="utf-8")
            pending_rehearsal.chmod(0o600)
            with mock.patch.object(cutover.os, "geteuid", return_value=0), mock.patch.object(
                cutover, "_private_parent"
            ), mock.patch.object(
                cutover, "load_state", return_value=activation_state
            ), mock.patch.object(
                cutover, "read_private_json", return_value=rehearsal
            ), mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "activated", "replayed": False},
            ), mock.patch.object(
                cutover, "_restore_backup_for_rehearsal"
            ) as restore:
                converged = cutover.produce_rollback_rehearsal(
                    state_path=root / "state.json",
                    scratch_directory=scratch,
                    output=pending_rehearsal,
                    authority_uid=0,
                )
            self.assertTrue(converged["replayed"])
            restore.assert_not_called()
            retention_output = root / "retention.json"
            browser_attestation = root / "browser-attestation.json"
            browser_consumption = root / "browser-consumption.json"
            browser_attestation.write_text(
                json.dumps(
                    {
                        "health": {"generation": 8},
                        "urls": {"health": "https://console.vr.ae/healthz"},
                    }
                ),
                encoding="utf-8",
            )
            browser_attestation.chmod(0o600)
            browser_consumption.write_text("{}\n", encoding="utf-8")
            browser_consumption.chmod(0o600)

            def verify_browser(*_args, **_kwargs):
                return {
                    "health": {"generation": 8},
                    "urls": {"health": "https://console.vr.ae/healthz"},
                    "document_sha256": activation[
                        "browser_lcp_attestation_sha256"
                    ],
                }

            def verify_consumption(*_args, **_kwargs):
                return {
                    "document_sha256": activation[
                        "browser_lcp_consumption_sha256"
                    ]
                }

            def digest(path):
                return (
                    authority_backup["backup_sha256"]
                    if "authority" in str(path)
                    else test_backup["backup_sha256"]
                )

            with mock.patch.object(cutover.os, "geteuid", return_value=0), mock.patch.object(
                cutover, "_private_parent"
            ), mock.patch.object(
                cutover, "load_state", return_value=state
            ), mock.patch.object(
                cutover,
                "read_private_json",
                side_effect=lambda path, **_kwargs: (
                    {
                        "health": {"generation": 8},
                        "urls": {"health": "https://console.vr.ae/healthz"},
                    }
                    if Path(path) == browser_attestation
                    else {
                        "consumed_at": "2026-07-28T12:00:00.000Z"
                    }
                ),
            ), mock.patch.object(
                cutover,
                "reverify_post_v13_profile_inventory_readiness",
                return_value=refreshed_profile_inventory_readiness(state),
            ), mock.patch.object(
                cutover, "_database_identity", return_value={"device": 1, "inode": 2, "size": 3}
            ), mock.patch.object(
                cutover, "_file_digest", side_effect=digest
            ), mock.patch.object(
                cutover, "_publish_evidence"
            ), mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "retained", "replayed": False},
            ):
                retained = cutover.produce_retention_attestation(
                    state_path=root / "state.json",
                    output=retention_output,
                    authority_uid=0,
                    browser_attestation=browser_attestation,
                    browser_consumption=browser_consumption,
                    browser_runtime_lock=root / "runtime-lock.json",
                    browser_signing_key=root / "signing-key",
                    observed_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
                    browser_attestation_verifier=verify_browser,
                    browser_consumption_validator=verify_consumption,
                    browser_health_observer=lambda *_args, **_kwargs: {
                        "generation": 10
                    },
                )
            final = cutover.transition(
                state,
                evidence_kind="retention",
                evidence=retained["attestation"],
            )
            self.assertEqual(final["phase"], "retained")
            self.assertEqual(
                cutover.transition(
                    final,
                    evidence_kind="retention",
                    evidence=retained["attestation"],
                ),
                final,
            )
            forged = dict(retained["attestation"])
            forged["test_backup_sha256"] = "f" * 64
            with self.assertRaisesRegex(cutover.CutoverError, "digest"):
                cutover.transition(
                    state,
                    evidence_kind="retention",
                    evidence=forged,
                )
            pending_retention = root / "pending-retention.json"
            pending_retention.write_text("{}\n", encoding="utf-8")
            pending_retention.chmod(0o600)
            with mock.patch.object(cutover.os, "geteuid", return_value=0), mock.patch.object(
                cutover, "_private_parent"
            ), mock.patch.object(
                cutover, "load_state", return_value=state
            ), mock.patch.object(
                cutover,
                "read_private_json",
                return_value=retained["attestation"],
            ), mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "retained", "replayed": False},
            ):
                converged_retention = cutover.produce_retention_attestation(
                    state_path=root / "state.json",
                    output=pending_retention,
                    authority_uid=0,
                    browser_attestation=browser_attestation,
                    browser_consumption=browser_consumption,
                    browser_runtime_lock=root / "runtime-lock.json",
                    browser_signing_key=root / "signing-key",
                )
            self.assertTrue(converged_retention["replayed"])

    def test_pre_split_ledger_binds_distinct_final_authority_once(self) -> None:
        state, _authority, _testd = through_seal()
        legacy_unsigned = {
            key: value
            for key, value in state.items()
            if key
            not in {
                "schema_version",
                "kind",
                "document_sha256",
                "legacy_authority_database",
            }
        }
        legacy_unsigned["authority_database"] = LEGACY_AUTHORITY_DATABASE
        legacy_state = cutover.seal(cutover.STATE_KIND, legacy_unsigned)
        normalized = cutover.validate_state(legacy_state)
        self.assertEqual(
            normalized["legacy_authority_database"],
            LEGACY_AUTHORITY_DATABASE,
        )
        self.assertEqual(
            normalized["authority_database"], LEGACY_AUTHORITY_DATABASE
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            state_path = root / "cutover.json"
            cutover._write_private_json(
                state_path,
                legacy_state,
                uid=os.geteuid(),
                create=True,
            )
            bound = cutover.bind_first_adoption_authority_paths(
                state_path=state_path,
                legacy_authority_database=Path(
                    LEGACY_AUTHORITY_DATABASE
                ),
                authority_database=Path(AUTHORITY_DATABASE),
                authority_uid=os.geteuid(),
            )
            replayed = cutover.bind_first_adoption_authority_paths(
                state_path=state_path,
                legacy_authority_database=Path(
                    LEGACY_AUTHORITY_DATABASE
                ),
                authority_database=Path(AUTHORITY_DATABASE),
                authority_uid=os.geteuid(),
            )
        self.assertEqual(bound, replayed)
        self.assertEqual(
            bound["legacy_authority_database"],
            LEGACY_AUTHORITY_DATABASE,
        )
        self.assertEqual(bound["authority_database"], AUTHORITY_DATABASE)
        self.assertGreater(
            int(bound["state_generation"]),
            int(legacy_state["state_generation"]),
        )

    def test_complete_evidence_chain_and_exact_replay(self) -> None:
        state, authority_backup, test_backup = through_seal()
        state = cutover.transition(
            state,
            evidence_kind="profile-inventory-readiness",
            evidence=profile_inventory_readiness(),
        )
        candidate_evidence = candidate()
        candidate_evidence = cutover.seal(
            cutover.CANDIDATE_KIND,
            {
                key: value
                for key, value in candidate_evidence.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            | {
                "migration_seal_sha256": state["evidence"]["migration-seal"][
                    "document_sha256"
                ]
            },
        )
        state = cutover.transition(
            state, evidence_kind="candidate", evidence=candidate_evidence
        )
        sockets = candidate_evidence["socket_inodes"]
        activation = cutover.seal(
            cutover.ACTIVATION_KIND,
            {
                "release_digest": RELEASE,
                "migration_seal_sha256": candidate_evidence[
                    "migration_seal_sha256"
                ],
                "profile_inventory_readiness_sha256": state["evidence"][
                    "profile-inventory-readiness"
                ]["document_sha256"],
                "executor_release": f"/opt/devcoordinator/releases/{RELEASE}",
                "credential_preflight_sha256": "c" * 64,
                "publication_switch": {
                    "previous_generation": 7,
                    "generation": 8,
                    "previous_payload_sha256": "d" * 64,
                    "payload_sha256": "e" * 64,
                    "previous_release_digest": "b" * 64,
                    "release_digest": RELEASE,
                    "previous_port": 30443,
                    "port": 31443,
                },
                "continuity_probe": continuity(),
                "socket_inodes_before": sockets,
                "socket_inodes_after": sockets,
                "connection_refused_count": 0,
                "project_route_failures": 0,
                "legacy_units_active": [],
                "authority_ready": True,
                "testd_ready": True,
                "console_ready": True,
                "browser_lcp_attestation_sha256": "7" * 64,
                "browser_lcp_consumption_sha256": "8" * 64,
                "created_at": "2026-07-28T00:07:00Z",
            },
        )
        activation_values = {
            key: value
            for key, value in activation.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        missing_readiness = dict(activation_values)
        missing_readiness.pop("profile_inventory_readiness_sha256")
        with self.assertRaisesRegex(cutover.CutoverError, "fields"):
            cutover.transition(
                state,
                evidence_kind="activation",
                evidence=cutover.seal(
                    cutover.ACTIVATION_KIND, missing_readiness
                ),
            )
        stale_readiness = dict(activation_values)
        stale_readiness["profile_inventory_readiness_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            cutover.CutoverError, "listener-continuous readiness"
        ):
            cutover.transition(
                state,
                evidence_kind="activation",
                evidence=cutover.seal(
                    cutover.ACTIVATION_KIND, stale_readiness
                ),
            )
        state = cutover.transition(
            state, evidence_kind="activation", evidence=activation
        )
        rehearsal = cutover.seal(
            cutover.ROLLBACK_REHEARSAL_KIND,
            {
                "operation_id": str(uuid.uuid4()),
                "activation_sha256": activation["document_sha256"],
                "executor_release": f"/opt/devcoordinator/releases/{RELEASE}",
                "authority_backup_sha256": authority_backup["backup_sha256"],
                "test_backup_sha256": test_backup["backup_sha256"],
                "restores": {
                    "authority": {
                        "source": authority_backup["backup"],
                        "source_sha256": authority_backup["backup_sha256"],
                        "restored_sha256": "5" * 64,
                        "quick_check": "ok",
                        "foreign_key_violations": 0,
                    },
                    "testd": {
                        "source": test_backup["backup"],
                        "source_sha256": test_backup["backup_sha256"],
                        "restored_sha256": "6" * 64,
                        "quick_check": "ok",
                        "foreign_key_violations": 0,
                    },
                },
                "publication_inverse_plan": {"mode": "verified-offline"},
                "continuity_probe_sha256": activation["continuity_probe"][
                    "document_sha256"
                ],
                "legacy_source_retained": True,
                "private_scratch": True,
                "rehearsed_at": "2026-07-28T00:07:30Z",
            },
        )
        state = cutover.transition(
            state,
            evidence_kind="rollback-rehearsal",
            evidence=rehearsal,
        )
        live_rehearsal_evidence = live_rollback_rehearsal(state, activation)
        state = cutover.transition(
            state,
            evidence_kind="live-rollback-rehearsal",
            evidence=live_rehearsal_evidence,
        )
        retention = cutover.seal(
            cutover.RETENTION_KIND,
            {
                "authority_backup_sha256": authority_backup["backup_sha256"],
                "test_backup_sha256": test_backup["backup_sha256"],
                "legacy_source_retained": True,
                "retain_until": state["retain_until"],
                "rollback_rehearsal_sha256": rehearsal["document_sha256"],
                "live_rollback_rehearsal_sha256": live_rehearsal_evidence[
                    "document_sha256"
                ],
                "profile_inventory_readiness_sha256": state["evidence"][
                    "profile-inventory-readiness"
                ]["document_sha256"],
                "profile_inventory_reverification": (
                    refreshed_profile_inventory_readiness(state)
                ),
                "browser_lcp_attestation_sha256": activation[
                    "browser_lcp_attestation_sha256"
                ],
                "browser_lcp_consumption_sha256": activation[
                    "browser_lcp_consumption_sha256"
                ],
                "created_at": "2026-07-28T00:08:00Z",
            },
        )
        state = cutover.transition(
            state, evidence_kind="retention", evidence=retention
        )
        self.assertEqual(state["phase"], "retained")
        self.assertEqual(
            cutover.transition(
                state,
                evidence_kind="authority-backup",
                evidence=authority_backup,
            ),
            state,
        )

    def test_migration_seal_requires_migrator_fingerprint_of_whole_proof(self) -> None:
        state = sealed_state()
        state = cutover.transition(
            state, evidence_kind="authority-backup", evidence=backup("authority")
        )
        state = cutover.transition(
            state, evidence_kind="testd-backup", evidence=backup("testd")
        )
        migration_id = str(uuid.uuid4())
        initial = imported("initial", migration_id=migration_id)
        final = imported("final", migration_id=migration_id)
        state = cutover.transition(
            state, evidence_kind="initial-import", evidence=initial
        )
        drain = dict(
            build_legacy_test_admission_drain_proof(
                drain_id=str(uuid.uuid4()),
                authority_generation=AUTHORITY_GENERATION,
                activated_at_epoch=100,
                activated_by_uid=0,
                drained_at_epoch=101,
                broker_instance_id="broker-instance",
            )
        )
        state = cutover.transition(
            state, evidence_kind="admission-drain", evidence=drain
        )
        state = cutover.transition(
            state, evidence_kind="final-import", evidence=final
        )
        wrong = cutover.seal(
            cutover.SEAL_KIND,
            {
                "migration_id": migration_id,
                "authority_database": LEGACY_AUTHORITY_DATABASE,
                "authority_generation": AUTHORITY_GENERATION,
                "test_database": TEST_DATABASE,
                "test_store_generation": TEST_GENERATION,
                "drain_proof_fingerprint": drain["proof_sha256"],
                "final_export_fingerprint": final["export_fingerprint"],
                "final_watermark_fingerprint": final["watermark_fingerprint"],
                "destination_attestation_fingerprint": final["document_sha256"],
                "legacy_source_retained": True,
                "activation_ready": True,
                "rollback": {"safe": True},
            },
        )
        with self.assertRaisesRegex(cutover.CutoverError, "migration seal"):
            cutover.transition(
                state, evidence_kind="migration-seal", evidence=wrong
            )

    def test_candidate_requires_distinct_service_identities_and_exact_slices(self) -> None:
        state, _, _ = through_seal()
        state = cutover.transition(
            state,
            evidence_kind="profile-inventory-readiness",
            evidence=profile_inventory_readiness(),
        )
        invalid = candidate()
        unsigned = {
            key: value
            for key, value in invalid.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["migration_seal_sha256"] = state["evidence"]["migration-seal"][
            "document_sha256"
        ]
        unsigned["service_uids"] = dict(unsigned["service_uids"])
        unsigned["service_uids"]["devcoordinator-api.service"] = unsigned[
            "service_uids"
        ]["devcoordinator-edge.service"]
        invalid = cutover.seal(cutover.CANDIDATE_KIND, unsigned)
        with self.assertRaisesRegex(cutover.CutoverError, "service UIDs"):
            cutover.transition(state, evidence_kind="candidate", evidence=invalid)

    def test_candidate_state_machine_rejects_pending_project_isolation(self) -> None:
        state, _, _ = through_seal()
        state = cutover.transition(
            state,
            evidence_kind="profile-inventory-readiness",
            evidence=profile_inventory_readiness(),
        )
        invalid = candidate()
        unsigned = {
            key: value
            for key, value in invalid.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["migration_seal_sha256"] = state["evidence"]["migration-seal"][
            "document_sha256"
        ]
        preparation = unsigned["preparation"]
        preparation_unsigned = {
            key: value
            for key, value in preparation.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        preparation_unsigned["project_isolation"] = {
            "ok": True,
            "kind": "project-runtime-isolation-verification",
            "audit_sha256": "sha256:" + "8" * 64,
            "source_schema_version": 15,
            "audit_counts": {
                "compliant": 1,
                "legacy_requires_recreation": 1,
                "unobservable": 0,
            },
            "project_isolation_complete": False,
            "authority_database": AUTHORITY_DATABASE,
            "audit_path": "/var/lib/devcoordinator/cutover/project-isolation.json",
            "ledger_path": "/var/lib/devcoordinator/cutover/project-isolation-ledger.json",
            "ledger_sha256": "sha256:" + "9" * 64,
            "ledger_counts": {"pending": 1, "completed": 0, "retired": 0},
            "observation_only": False,
            "project_resources_mutated": False,
        }
        unsigned["preparation"] = cutover.seal(
            cutover.CANDIDATE_PREPARATION_KIND, preparation_unsigned
        )
        invalid = cutover.seal(cutover.CANDIDATE_KIND, unsigned)
        with self.assertRaisesRegex(cutover.CutoverError, "preparation"):
            cutover.transition(state, evidence_kind="candidate", evidence=invalid)

    def test_candidate_rejects_observation_or_mutating_isolation_evidence(self) -> None:
        state, _, _ = through_seal()
        state = cutover.transition(
            state,
            evidence_kind="profile-inventory-readiness",
            evidence=profile_inventory_readiness(),
        )
        for field in ("observation_only", "project_resources_mutated"):
            for invalid_value in (None, True):
                with self.subTest(field=field, invalid_value=invalid_value):
                    unsigned = {
                        key: value
                        for key, value in candidate().items()
                        if key not in {"schema_version", "kind", "document_sha256"}
                    }
                    unsigned["migration_seal_sha256"] = state["evidence"][
                        "migration-seal"
                    ]["document_sha256"]
                    preparation_unsigned = {
                        key: value
                        for key, value in unsigned["preparation"].items()
                        if key not in {"schema_version", "kind", "document_sha256"}
                    }
                    isolation = dict(preparation_unsigned["project_isolation"])
                    if invalid_value is None:
                        isolation.pop(field)
                    else:
                        isolation[field] = invalid_value
                    preparation_unsigned["project_isolation"] = isolation
                    unsigned["preparation"] = cutover.seal(
                        cutover.CANDIDATE_PREPARATION_KIND,
                        preparation_unsigned,
                    )
                    invalid = cutover.seal(cutover.CANDIDATE_KIND, unsigned)
                    with self.assertRaisesRegex(cutover.CutoverError, "preparation"):
                        cutover.transition(
                            state, evidence_kind="candidate", evidence=invalid
                        )

    def test_duplicate_socket_inode_fails_closed(self) -> None:
        sockets = {name: 100 for name in cutover.SOCKET_NAMES}
        with self.assertRaisesRegex(cutover.CutoverError, "reuses"):
            cutover._socket_map(sockets)

    def test_first_adoption_publication_bootstrap_is_explicit_and_bound(self) -> None:
        value = {
            "mode": "first-adoption-bootstrap",
            "previous_generation": 0,
            "generation": 1,
            "previous_payload_sha256": None,
            "payload_sha256": "1" * 64,
            "previous_release_digest": None,
            "release_digest": RELEASE,
            "previous_port": None,
            "port": 31443,
            "retained_routes_sha256": "2" * 64,
            "handoff_journal_sha256": "3" * 64,
        }
        self.assertEqual(
            cutover._publication_switch(value, expected_release=RELEASE), value
        )
        with self.assertRaisesRegex(cutover.CutoverError, "first-adoption"):
            cutover._publication_switch(
                {**value, "previous_generation": 1}, expected_release=RELEASE
            )

    def test_no_authority_transaction_skips_full_authority_backup(self) -> None:
        state = sealed_state(authority_backup_required=False)
        with self.assertRaisesRegex(cutover.CutoverError, "backup is forbidden"):
            cutover.transition(
                state,
                evidence_kind="authority-backup",
                evidence=backup("authority"),
            )
        state = cutover.transition(
            state,
            evidence_kind="testd-backup",
            evidence=backup("testd"),
        )
        self.assertEqual(state["phase"], "backups_verified")

    def test_sealed_next_actions_compile_request_before_first_adoption(self) -> None:
        state, _authority, _testd = through_seal()
        actions = cutover.next_actions(state)["actions"]
        commands = [
            item.get("argv_prefix", [None])[0]
            for item in actions
            if isinstance(item, Mapping)
            and isinstance(item.get("argv_prefix"), list)
            and item.get("argv_prefix")
        ]
        self.assertIn("migrate-credentials", commands)
        self.assertIn("prepare-first-adoption", commands)
        self.assertIn("build-first-adoption-request", commands)
        self.assertIn("first-adoption", commands)
        self.assertLess(
            commands.index("migrate-credentials"),
            commands.index("prepare-first-adoption"),
        )
        self.assertLess(
            commands.index("prepare-first-adoption"),
            commands.index("build-first-adoption-request"),
        )
        self.assertLess(
            commands.index("build-first-adoption-request"),
            commands.index("first-adoption"),
        )
        credential_migration = next(
            item
            for item in actions
            if isinstance(item, Mapping)
            and item.get("argv_prefix", [None])[0] == "migrate-credentials"
        )
        self.assertIn(
            "--legacy-source-uid",
            credential_migration["argv_prefix"],
        )
        self.assertNotIn("--api-token-source", credential_migration["argv_prefix"])
        self.assertNotIn(
            "--api-token-source-uid", credential_migration["argv_prefix"]
        )
        preparation = next(
            item
            for item in actions
            if isinstance(item, Mapping)
            and item.get("argv_prefix", [None])[0]
            == "prepare-first-adoption"
        )
        self.assertIn("--binding-attestation", preparation["argv_prefix"])
        self.assertIn("--operation-id", preparation["argv_prefix"])
        self.assertIn("--hard-gate-attestation", preparation["argv_prefix"])
        self.assertIn("retains that claim", preparation["claim_contract"])
        producer = next(
            item
            for item in actions
            if isinstance(item, Mapping)
            and item.get("argv_prefix", [None])[0]
            == "build-first-adoption-request"
        )
        self.assertEqual(
            producer["output_contract"],
            "root-owned mode 0600 sealed devcoordinator-first-adoption-request",
        )
        self.assertEqual(
            producer["required_argument_groups"]["legacy_writer"],
            "--legacy-bridge-transaction, --legacy-bridge-operation-id, --legacy-bridge-journal-sha256, --legacy-bridge-database, --legacy-bridge-profile, --legacy-bridge-socket, --legacy-bridge-dropin, --legacy-broker-retirement-guard, --legacy-writer-handoff-journal",
        )
        adoption = next(
            item
            for item in actions
            if isinstance(item, Mapping)
            and item.get("argv_prefix", [None])[0] == "first-adoption"
        )
        self.assertIn(
            "retire the bridge-owned drop-in and legacy unit before any schema-13 authority starts",
            adoption["purpose"],
        )
        self.assertIn(
            "restore the exact bridge drop-in while its retirement guard still blocks starts",
            adoption["rollback_order"],
        )
        self.assertTrue(adoption["rollback_order"].endswith("clear maintenance last"))
        finalizer = next(
            item
            for item in actions
            if isinstance(item, Mapping)
            and item.get("argv_prefix", [None])[0]
            == "finalize-first-adoption-installation"
        )
        hard_gate_arguments = {
            "--canonical-project": "<canonical-global-finance-project-root>",
            "--canonical-repository-id": "<global-finance-repository-id>",
            "--owner-user": "<global-finance-owner-user>",
            "--collaborator-user": "<global-finance-collaborator-user>",
        }
        for action in (preparation, adoption, finalizer):
            argv = action["argv_prefix"]
            self.assertEqual(argv.count("--canonical-project"), 1)
            self.assertEqual(argv.count("--canonical-repository-id"), 1)
            self.assertEqual(argv.count("--owner-user"), 1)
            self.assertEqual(argv.count("--collaborator-user"), 1)
            for option, expected in hard_gate_arguments.items():
                self.assertEqual(argv[argv.index(option) + 1], expected)
        self.assertEqual(
            finalizer["hard_gate"],
            {
                "scope": "server-wide",
                "transport": "authenticated-unix-socket",
                "canonical_project": "<canonical-global-finance-project-root>",
                "repository_id": "<global-finance-repository-id>",
                "users": [
                    "<global-finance-owner-user>",
                    "<global-finance-collaborator-user>",
                ],
            },
        )
        self.assertTrue(
            all(
                isinstance(finalizer["hard_gate"][field], str)
                and finalizer["hard_gate"][field].startswith("<")
                and finalizer["hard_gate"][field].endswith(">")
                for field in ("canonical_project", "repository_id")
            )
        )

    def test_next_actions_only_execute_immutable_release_wrappers(self) -> None:
        def assert_release_commands(state: Mapping[str, object]) -> None:
            release_bin = f"{state['release']}/bin/"
            actions = cutover.next_actions(state)["actions"]
            for action in actions:
                executable = action.get("executable")
                if isinstance(executable, str):
                    self.assertTrue(
                        executable.startswith(release_bin),
                        f"next action bypasses an immutable release wrapper: {executable}",
                    )
                for field in ("argv", "argv_prefix"):
                    argv = action.get(field)
                    if (
                        executable is None
                        and isinstance(argv, list)
                        and argv
                        and isinstance(argv[0], str)
                        and argv[0].startswith("/")
                    ):
                        self.assertTrue(
                            argv[0].startswith(release_bin),
                            f"next action bypasses an immutable release wrapper: {argv[0]}",
                        )

        planned = sealed_state()
        assert_release_commands(planned)
        backed_up = cutover.transition(
            planned,
            evidence_kind="authority-backup",
            evidence=backup("authority"),
        )
        backed_up = cutover.transition(
            backed_up,
            evidence_kind="testd-backup",
            evidence=backup("testd"),
        )
        assert_release_commands(backed_up)
        migration_id = str(uuid.uuid4())
        initial_migrated = cutover.transition(
            backed_up,
            evidence_kind="initial-import",
            evidence=imported("initial", migration_id=migration_id),
        )
        assert_release_commands(initial_migrated)
        drain = dict(
            build_legacy_test_admission_drain_proof(
                drain_id=str(uuid.uuid4()),
                authority_generation=AUTHORITY_GENERATION,
                activated_at_epoch=100,
                activated_by_uid=0,
                drained_at_epoch=101,
                broker_instance_id="broker-instance",
            )
        )
        admission_drained = cutover.transition(
            initial_migrated,
            evidence_kind="admission-drain",
            evidence=drain,
        )
        assert_release_commands(admission_drained)
        tail_migrated = cutover.transition(
            admission_drained,
            evidence_kind="final-import",
            evidence=imported("final", migration_id=migration_id),
        )
        assert_release_commands(tail_migrated)
        sealed, _authority, _testd = through_seal()
        assert_release_commands(sealed)
        activated, _authority, _testd, activation = through_activation()
        assert_release_commands(activated)
        live_rehearsed = cutover.transition(
            activated,
            evidence_kind="live-rollback-rehearsal",
            evidence=live_rollback_rehearsal(activated, activation),
        )
        assert_release_commands(live_rehearsed)

class CutoverPersistenceTests(unittest.TestCase):
    def test_first_deployment_bootstrap_failure_then_exact_replay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            authority = root / "authority.sqlite3"
            inventory = root / "inventory.sqlite3"
            test_database = root / "tests.sqlite3"
            schema_path = root / "schema.json"
            output = root / "bootstrap.json"
            schema = schema_readiness()
            schema_unsigned = {
                key: value
                for key, value in schema.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            schema_unsigned["test_database"] = str(test_database)
            schema = cutover.seal(cutover.SCHEMA_READINESS_KIND, schema_unsigned)
            identities = {
                "users": {
                    "root": {"uid": 0, "gid": 0},
                    "devcoordinator-testd": {"uid": TESTD_UID, "gid": TESTD_UID},
                    "devcoordinator-observer": {"uid": 2304, "gid": 2304},
                },
                "groups": {},
            }
            release_verifier = mock.Mock()
            release_verifier.verify_release.return_value = {
                "release_digest": RELEASE,
                "capabilities": {"edge": True, "testd": True},
            }
            topology_verifier = mock.Mock()
            topology_verifier.validate_topology.return_value = []
            calls = 0

            def fail_schema(_argv):
                nonlocal calls
                calls += 1
                return 1 if calls == 4 else 0

            def private_document(path, *, uid):
                del uid
                if Path(path) == schema_path:
                    return schema
                return json.loads(Path(path).read_text(encoding="utf-8"))

            def publish(path, document, *, uid):
                del uid
                Path(path).write_text(
                    json.dumps(document, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                Path(path).chmod(0o600)
                test_database.touch(mode=0o600, exist_ok=True)

            patches = (
                mock.patch.object(cutover.os, "geteuid", return_value=0),
                mock.patch.object(cutover.Path, "is_file", return_value=True),
                mock.patch.object(cutover.os, "access", return_value=True),
                mock.patch.object(cutover, "_bootstrap_config", return_value="a" * 64),
                mock.patch.object(cutover, "_availability_identities", return_value=identities),
                mock.patch.object(
                    cutover,
                    "_directory_identity",
                    return_value={"path": "/private", "uid": 0, "gid": 0, "mode": "0700"},
                ),
                mock.patch.object(cutover, "_database_identity", return_value={"device": 1, "inode": 2, "size": 3}),
                mock.patch.object(cutover, "read_private_json", side_effect=private_document),
                mock.patch.object(cutover, "_publish_evidence", side_effect=publish),
                mock.patch.object(cutover, "_load_release_verifier", return_value=release_verifier),
                mock.patch.object(cutover, "_load_topology_verifier", return_value=topology_verifier),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10]:
                with self.assertRaisesRegex(cutover.CutoverError, "schema preparation"):
                    cutover.bootstrap_first_deployment(
                        release=Path(f"/opt/devcoordinator/releases/{RELEASE}"),
                        rendered_units=root,
                        authority_database=authority,
                        inventory_database=inventory,
                        test_database=test_database,
                        schema_attestation=schema_path,
                        output=output,
                        operation_id=str(schema["operation_id"]),
                        command_status=fail_schema,
                    )
                self.assertFalse(output.exists())
                first = cutover.bootstrap_first_deployment(
                    release=Path(f"/opt/devcoordinator/releases/{RELEASE}"),
                    rendered_units=root,
                    authority_database=authority,
                    inventory_database=inventory,
                    test_database=test_database,
                    schema_attestation=schema_path,
                    output=output,
                    operation_id=str(schema["operation_id"]),
                    command_status=lambda _argv: 0,
                )
                replay = cutover.bootstrap_first_deployment(
                    release=Path(f"/opt/devcoordinator/releases/{RELEASE}"),
                    rendered_units=root,
                    authority_database=authority,
                    inventory_database=inventory,
                    test_database=test_database,
                    schema_attestation=schema_path,
                    output=output,
                    operation_id=str(schema["operation_id"]),
                    command_status=lambda _argv: 0,
                )
            self.assertFalse(first["replayed"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(first["attestation"], replay["attestation"])

    @staticmethod
    def _ready_setup(repository_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "repository_id": repository_id,
            "ok": True,
            "status": "ready",
            "manifest_schema": 2,
            "manifest_fingerprint": "a" * 64,
            "targets": [
                {
                    "name": "tests",
                    "driver": "automation",
                    "reporter": "automation-events",
                    "network": "loopback",
                    "fixtures": [],
                    "credentials": ["skydive-health-sweep-admin-v1"],
                    "depends_on": [],
                    "resources": {
                        "cpu_millis": 100,
                        "memory_mib": 64,
                        "pids": 8,
                    },
                }
            ],
            "target_graph": {"tests": []},
            "input_coverage": {
                "global_input_count": 1,
                "target_input_count": 1,
                "targets_with_inputs": 1,
            },
            "input_coverage_gaps": [],
            "intents": ["manual"],
            "evidence_policies": [],
            "fixtures": [],
            "credentials": ["skydive-health-sweep-admin-v1"],
            "network_requirements": ["loopback"],
            "isolation": {
                "network": "loopback",
                "cpu_millis": 100,
                "memory_mib": 64,
                "pids": 8,
                "private_scratch": True,
                "kill_after_run": True,
            },
            "issues": [],
        }

    def test_root_authority_repository_diagnostic_is_bounded_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            repository_root = root / "repo-alpha"
            repository_root.mkdir()
            owner_uid = os.geteuid() if os.geteuid() > 0 else 12345
            if os.geteuid() == 0:
                os.chown(repository_root, owner_uid, os.getegid())
            database = root / "authority.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_metadata(singleton INTEGER PRIMARY KEY, database_generation TEXT NOT NULL);
                    CREATE TABLE repositories(repo_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, canonical_root TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL);
                    CREATE TABLE repository_installations(repo_id TEXT PRIMARY KEY, status TEXT NOT NULL, startup_fenced INTEGER NOT NULL);
                    CREATE TABLE broker_acl_principals(uid INTEGER, account_id TEXT, enabled INTEGER);
                    CREATE TABLE broker_repository_enrollments(repo_id TEXT, uid INTEGER, account_id TEXT, enabled INTEGER, valid_until_epoch INTEGER);
                    CREATE TABLE startup_policies(
                        policy_id TEXT PRIMARY KEY, repo_id TEXT,
                        resource_kind TEXT, resource_id TEXT, policy_kind TEXT,
                        current_value TEXT, desired_disabled_value TEXT,
                        immutable_fingerprint TEXT, generation INTEGER,
                        updated_at TEXT
                    );
                    CREATE TABLE startup_policy_restore_states(
                        policy_id TEXT PRIMARY KEY, repo_id TEXT,
                        resource_kind TEXT, resource_id TEXT, policy_kind TEXT,
                        policy_immutable_fingerprint TEXT,
                        target_immutable_fingerprint TEXT,
                        control_binding_id TEXT, observation_fingerprint TEXT,
                        native_identity_fingerprint TEXT, captured_value TEXT,
                        restore_required INTEGER, status TEXT,
                        docker_restart_policy TEXT, supervisor_manager TEXT,
                        supervisor_unit_file_state TEXT,
                        supervisor_loaded INTEGER, supervisor_enabled INTEGER,
                        captured_operation_id TEXT, last_restore_permit_id TEXT,
                        capture_generation INTEGER, captured_at TEXT,
                        restored_at TEXT, updated_at TEXT
                    );
                    """
                )
                connection.execute("INSERT INTO schema_metadata VALUES (1, ?)", (AUTHORITY_GENERATION,))
                connection.execute(
                    "INSERT INTO repositories VALUES ('repo-alpha', 'Alpha', ?, 7, 'active')",
                    (str(repository_root),),
                )
                connection.execute("INSERT INTO repository_installations VALUES ('repo-alpha', 'installed', 0)")
                connection.execute("INSERT INTO broker_acl_principals VALUES (?, 'owner', 1)", (owner_uid,))
                connection.execute("INSERT INTO broker_acl_principals VALUES (?, 'api', 0)", (owner_uid + 1,))
                connection.execute(
                    "INSERT INTO broker_repository_enrollments VALUES ('repo-alpha', ?, 'api', 1, 1800000000)",
                    (owner_uid + 1,),
                )
                connection.execute(
                    "INSERT INTO broker_repository_enrollments VALUES ('repo-alpha', ?, 'owner', 1, 2000000000)",
                    (owner_uid,),
                )
                connection.commit()
            os.chmod(database, 0o600)
            info = database.lstat()
            identity = {
                "device": int(info.st_dev),
                "inode": int(info.st_ino),
                "size": int(info.st_size),
            }
            with mock.patch.object(
                cutover.os,
                "geteuid",
                return_value=owner_uid,
            ):
                with self.assertRaisesRegex(
                    cutover.CutoverError,
                    "root authority",
                ):
                    cutover.diagnose_authority_repository(
                        authority_database=database,
                        repository_id="repo-alpha",
                        database_identity_reader=lambda _path, uid: identity,
                    )
            with mock.patch.object(cutover.os, "geteuid", return_value=0):
                diagnostic = cutover.diagnose_authority_repository(
                    authority_database=database,
                    repository_id="repo-alpha",
                    now_epoch=1_900_000_000,
                    database_identity_reader=lambda _path, uid: identity,
                )
            self.assertEqual(diagnostic["repository"]["display_name"], "Alpha")
            self.assertEqual(
                diagnostic["repository"]["canonical_root"], str(repository_root)
            )
            self.assertEqual(
                diagnostic["repository"]["root_identity"]["owner_uid"], owner_uid
            )
            self.assertEqual(
                [row["uid"] for row in diagnostic["enrollments"]],
                [owner_uid, owner_uid + 1],
            )
            self.assertTrue(diagnostic["enrollments"][0]["current"])
            self.assertFalse(diagnostic["enrollments"][1]["current"])
            with mock.patch.object(cutover.os, "geteuid", return_value=0):
                unavailable = cutover.diagnose_authority_repository(
                    authority_database=database,
                    repository_id="repo-alpha",
                    now_epoch=1_900_000_000,
                    database_identity_reader=lambda _path, uid: identity,
                    repository_identity_reader=mock.Mock(
                        side_effect=cutover.CutoverError(
                            "authority repository root cannot be anchor-opened"
                        )
                    ),
                )
            self.assertEqual(
                unavailable["repository"]["root_observation"], "unavailable"
            )
            self.assertIsNone(unavailable["repository"]["root_identity"])
            self.assertEqual(
                unavailable["repository"]["root_error"],
                "authority repository root cannot be anchor-opened",
            )
            changed = {**identity, "inode": identity["inode"] + 1}
            with mock.patch.object(cutover.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(cutover.CutoverError, "changed"):
                    cutover.diagnose_authority_repository(
                        authority_database=database,
                        repository_id="repo-alpha",
                        database_identity_reader=mock.Mock(
                            side_effect=[identity, changed]
                        ),
                    )

    def test_host_routing_profile_is_reconstructed_without_access_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            database = root / "authority.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_metadata(
                        singleton INTEGER PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        database_generation TEXT NOT NULL,
                        migration_state TEXT NOT NULL
                    );
                    CREATE TABLE repositories(
                        repo_id TEXT PRIMARY KEY,
                        canonical_root TEXT NOT NULL,
                        generation INTEGER NOT NULL,
                        state TEXT NOT NULL
                    );
                    CREATE TABLE repository_installations(
                        repo_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        startup_fenced INTEGER NOT NULL
                    );
                    CREATE TABLE server_definitions(
                        server_definition_id TEXT PRIMARY KEY,
                        repo_id TEXT NOT NULL,
                        name TEXT NOT NULL
                    );
                    CREATE TABLE docker_resources(
                        docker_resource_id TEXT PRIMARY KEY,
                        repo_id TEXT NOT NULL,
                        current_name TEXT,
                        full_container_id TEXT
                    );
                    CREATE TABLE broker_compose_definitions(
                        compose_definition_id TEXT PRIMARY KEY,
                        repo_id TEXT NOT NULL,
                        enabled INTEGER NOT NULL
                    );
                    CREATE TABLE broker_compose_run_once_services(
                        compose_definition_id TEXT NOT NULL,
                        service_name TEXT NOT NULL,
                        max_timeout_seconds INTEGER NOT NULL,
                        ordinal INTEGER NOT NULL
                    );
                    CREATE TABLE ephemeral_container_templates(
                        template_id TEXT PRIMARY KEY,
                        repo_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        secret_policy_kind TEXT,
                        secret_binding_id TEXT,
                        enabled INTEGER NOT NULL
                    );
                    """
                )
                connection.execute(
                    "INSERT INTO schema_metadata VALUES (1, 15, ?, 'ready')",
                    (TARGET_AUTHORITY_GENERATION,),
                )
                connection.execute(
                    "INSERT INTO repositories VALUES (?, ?, 7, 'active')",
                    ("repo-alpha", "/home/example/repo-alpha"),
                )
                connection.execute(
                    "INSERT INTO repository_installations VALUES (?, 'installed', 0)",
                    ("repo-alpha",),
                )
                connection.executemany(
                    "INSERT INTO docker_resources VALUES (?, ?, ?, ?)",
                    (
                        (
                            "container-old",
                            "repo-alpha",
                            "database",
                            "a" * 64,
                        ),
                        (
                            "container-current",
                            "repo-alpha",
                            "database",
                            "b" * 64,
                        ),
                    ),
                )
                connection.commit()
            os.chmod(database, 0o600)
            destination = root / "client-profiles.json"
            destination.write_text('{"obsolete": true}', encoding="utf-8")
            os.chmod(destination, 0o600)
            arguments = {
                "authority_database": database,
                "destination": destination,
                "validation_uid": max(os.geteuid(), 1),
                "authority_uid": os.geteuid(),
            }
            first = cutover.reconstruct_api_profile_from_authority(**arguments)
            self.assertTrue(first["changed"])
            rebuilt = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(rebuilt["version"], 2)
            self.assertEqual(
                set(rebuilt["service"]), {"socket", "database_generation"}
            )
            self.assertEqual(
                rebuilt["repositories"][0]["repo_id"], "repo-alpha"
            )
            containers = rebuilt["repositories"][0]["containers"]
            self.assertNotIn("database", containers)
            self.assertEqual(containers["a" * 64], "container-old")
            self.assertEqual(containers["b" * 64], "container-current")
            self.assertEqual(containers["container-old"], "container-old")
            self.assertEqual(containers["container-current"], "container-current")
            self.assertNotIn("clients", rebuilt)
            self.assertNotIn("permissions", destination.read_text(encoding="utf-8"))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)
            second = cutover.reconstruct_api_profile_from_authority(**arguments)
            self.assertFalse(second["changed"])

    def test_sqlite_backup_is_private_verified_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            database = root / "authority.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
                connection.execute("INSERT INTO item VALUES (1)")
                connection.commit()
            os.chmod(database, 0o600)
            backup_path = root / "authority.backup.sqlite3"
            attestation = root / "authority.backup.json"
            first = cutover.backup_database(
                database=database,
                backup=backup_path,
                attestation=attestation,
                expected_uid=os.geteuid(),
                reserve_bytes=0,
            )
            second = cutover.backup_database(
                database=database,
                backup=backup_path,
                attestation=attestation,
                expected_uid=os.geteuid(),
                reserve_bytes=0,
            )
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(first["backup_sha256"], second["backup_sha256"])
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(attestation.stat().st_mode & 0o777, 0o600)

    def test_initialize_dry_run_validates_without_writing(self) -> None:
        identity = {"device": 1, "inode": 2, "size": 10}
        release_verifier = mock.Mock()
        release_verifier.verify_release.return_value = {
            "release_digest": RELEASE,
            "capabilities": {"edge": True, "testd": True},
        }
        topology_verifier = mock.Mock()
        topology_verifier.validate_topology.return_value = []
        bootstrap = bootstrap_attestation()
        schema = schema_readiness()
        readiness = authority_readiness_attestation()
        port_reservations = first_adoption_port_reservations()
        live_readiness = json.loads(json.dumps(readiness["postcondition"]))
        live_readiness["metadata"]["state_revision"] = 9
        live_readiness["metadata"]["updated_at"] = port_reservations[
            "created_at"
        ]
        self.assertEqual(
            bootstrap["schema_readiness"]["document_sha256"],
            schema["document_sha256"],
        )

        def private_document(path, *, uid):
            del uid
            if str(path) == SCHEMA_ATTESTATION:
                return schema
            if str(path) == AUTHORITY_READINESS_ATTESTATION:
                return readiness
            if str(path) == PORT_RESERVATIONS_ATTESTATION:
                return port_reservations
            return bootstrap

        with mock.patch.object(cutover, "_database_identity", return_value=identity), mock.patch.object(
            cutover, "_private_parent"
        ), mock.patch.object(
            cutover, "read_private_json", side_effect=private_document
        ), mock.patch.object(
            cutover, "_load_release_verifier", return_value=release_verifier
        ), mock.patch.object(
            cutover, "_load_topology_verifier", return_value=topology_verifier
        ), mock.patch.object(
            cutover.shutil, "disk_usage", return_value=mock.Mock(free=10_000_000)
        ), mock.patch.object(
            cutover,
            "_read_authority_readiness_snapshot",
            return_value=live_readiness,
        ), mock.patch.object(
            cutover,
            "_verify_authority_readiness_backup",
            return_value=readiness["backup"],
        ), mock.patch.object(
            cutover,
            "verify_first_adoption_port_reservation_rows",
            return_value={"ok": True},
        ), mock.patch.object(cutover, "_write_private_json") as writer:
            result = cutover.initialize(
                state_path=Path(f"/tmp/cutover-state-{uuid.uuid4()}.json"),
                release=Path(f"/opt/devcoordinator/releases/{RELEASE}"),
                rendered_units=Path("/run/devcoordinator/cutover/units"),
                legacy_authority_database=Path(
                    LEGACY_AUTHORITY_DATABASE
                ),
                authority_database=Path(AUTHORITY_DATABASE),
                test_database=Path(TEST_DATABASE),
                inventory_canary_project=Path(INVENTORY_PROJECT),
                authority_backup_directory=Path("/var/backups/devcoordinator"),
                test_backup_directory=Path("/var/backups/devcoordinator-testd"),
                migration_state=Path("/var/lib/devcoordinator/cutover.json"),
                drain_proof=Path("/var/lib/devcoordinator/drain.json"),
                cutover_seal=Path("/var/lib/devcoordinator/seal.json"),
                first_deployment_bootstrap=Path(BOOTSTRAP_ATTESTATION),
                authority_readiness=Path(AUTHORITY_READINESS_ATTESTATION),
                first_adoption_port_reservations=Path(
                    PORT_RESERVATIONS_ATTESTATION
                ),
                first_adoption_port_reservations_sha256=port_reservations[
                    "document_sha256"
                ],
                authority_uid=0,
                testd_uid=TESTD_UID,
                reserve_bytes=0,
                retain_until="2026-09-01T00:00:00Z",
                persist=False,
            )
        writer.assert_not_called()
        self.assertTrue(result["dry_run"])
        self.assertTrue(result["actions"])
        self.assertFalse(result["capacity"]["authority"]["required"])
        self.assertEqual(result["capacity"]["authority"]["required_free_bytes"], 0)
        self.assertEqual(result["capacity"]["testd"]["estimated_backup_bytes"], 10)


class AuthorityReadinessRebindDescendantTests(unittest.TestCase):
    @staticmethod
    def _ready_snapshot() -> dict[str, object]:
        readiness = authority_readiness_attestation()
        return json.loads(json.dumps(readiness["postcondition"]))

    def test_ready_descendant_accepts_monotonic_revisions_and_valid_growth(self) -> None:
        ancestor = self._ready_snapshot()
        descendant = json.loads(json.dumps(ancestor))
        descendant["metadata"].update(
            {
                "state_revision": ancestor["metadata"]["state_revision"] + 2,
                "observation_revision": (
                    ancestor["metadata"]["observation_revision"] + 3
                ),
                "updated_at": "2026-07-29T00:00:00Z",
            }
        )
        descendant["invariants"]["repositories"] = 2
        descendant["invariants"]["installations"] = 2

        self.assertEqual(
            cutover._authority_readiness_ready_descendant(
                ancestor, descendant, label="test descendant"
            ),
            descendant,
        )
        self.assertEqual(
            cutover._authority_readiness_same_database(
                {"device": 1, "inode": 2, "size": 10},
                {"device": 1, "inode": 2, "size": 4096},
                label="test descendant",
            )["size"],
            4096,
        )

    def test_ready_descendant_rejects_regression_and_lineage_drift(self) -> None:
        ancestor = self._ready_snapshot()
        cases: list[tuple[str, object]] = []
        for field in ("state_revision", "observation_revision"):
            candidate = json.loads(json.dumps(ancestor))
            candidate["metadata"][field] -= 1
            cases.append((f"{field} regression", candidate))
        for field, value in (
            ("schema_version", 13),
            ("database_generation", "another-generation"),
            ("authority_mode", "legacy-json"),
            ("migration_state", "empty"),
            ("created_at", "2026-07-15T00:00:00Z"),
            ("first_sqlite_mutation_at", "2026-07-15T01:00:00Z"),
        ):
            candidate = json.loads(json.dumps(ancestor))
            candidate["metadata"][field] = value
            cases.append((f"{field} drift", candidate))
        timestamp_regression = json.loads(json.dumps(ancestor))
        timestamp_regression["metadata"]["updated_at"] = "2026-07-27T23:59:59Z"
        cases.append(("updated_at regression", timestamp_regression))
        invalid_invariants = json.loads(json.dumps(ancestor))
        invalid_invariants["invariants"]["missing_installations"] = 1
        cases.append(("readiness invariant failure", invalid_invariants))

        for label, candidate in cases:
            with self.subTest(label=label):
                with self.assertRaises(cutover.CutoverError):
                    cutover._authority_readiness_ready_descendant(
                        ancestor, candidate, label="test descendant"
                    )
        with self.assertRaisesRegex(cutover.CutoverError, "identity changed"):
            cutover._authority_readiness_same_database(
                {"device": 1, "inode": 2, "size": 10},
                {"device": 1, "inode": 3, "size": 10},
                label="test descendant",
            )

    def test_prepare_records_exact_current_descendant_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            database = root / "authority.sqlite3"
            database.write_bytes(b"current-ready-authority")
            identity = {"device": 7, "inode": 11, "size": database.stat().st_size}
            prior = authority_readiness_attestation()
            prior_values = {
                field: prior[field]
                for field in cutover.AUTHORITY_READINESS_RESULT_FIELDS
            }
            prior_values["database"] = str(database)
            prior_values["database_identity_before"] = dict(identity)
            prior_values["database_identity_after"] = {**identity, "size": 1}
            prior = cutover.seal(
                cutover.AUTHORITY_READINESS_RESULT_KIND, prior_values
            )
            descendant = self._ready_snapshot()
            descendant["metadata"].update(
                {
                    "state_revision": 9,
                    "observation_revision": 12,
                    "updated_at": "2026-07-29T00:00:00Z",
                }
            )
            descendant["invariants"]["repositories"] = 2
            descendant["invariants"]["installations"] = 2
            verifier = mock.Mock()
            verifier.verify_release.return_value = {
                "release_digest": "b" * 64,
                "capabilities": {"authority_readiness_rebind": True},
            }

            with mock.patch.object(
                cutover,
                "_read_authority_readiness_snapshot",
                return_value=descendant,
            ), mock.patch.object(
                cutover,
                "_verify_authority_readiness_backup",
                return_value=prior["backup"],
            ):
                prepared = cutover._prepare_authority_readiness_rebind(
                    release=root / "release",
                    database=database,
                    prior_attestation=root / "prior.json",
                    authority_uid=0,
                    release_verifier=verifier,
                    identity_reader=lambda _path, *, uid: dict(identity),
                    evidence_reader=lambda _path, *, uid: prior,
                )

            self.assertEqual(prepared["snapshot"], descendant)
            self.assertEqual(
                prepared["database_sha256"], cutover._file_digest(database)
            )
            self.assertEqual(prepared["backup"], prior["backup"])


class InitializationPortRevisionWindowTests(unittest.TestCase):
    @staticmethod
    def _post_reservation_reattestation(
        bundle: Mapping[str, object],
    ) -> dict[str, object]:
        prior = authority_readiness_attestation(
            release=f"/opt/devcoordinator/releases/{'b' * 64}"
        )
        snapshot = json.loads(json.dumps(prior["postcondition"]))
        snapshot["metadata"]["state_revision"] = bundle[
            "authority_state_revision_after"
        ]
        snapshot["metadata"]["updated_at"] = bundle["created_at"]
        return cutover.seal(
            cutover.AUTHORITY_READINESS_REATTEST_KIND,
            {
                "operation_id": bundle["operation_id"],
                "intent": {
                    "path": "/var/lib/devcoordinator/reattest-intent.json",
                    "document_sha256": "1" * 64,
                },
                "prior_attestation": {
                    "path": "/var/lib/devcoordinator/original-readiness.json",
                    "document_sha256": prior["document_sha256"],
                },
                "prior_release_digest": "b" * 64,
                "quiescence_attestation": {
                    "path": PORT_RESERVATIONS_ATTESTATION,
                    "document_sha256": bundle["document_sha256"],
                    "kind": cutover.ATOMIC_FIRST_ADOPTION_PREPARED_KIND,
                },
                "release": f"/opt/devcoordinator/releases/{RELEASE}",
                "release_digest": RELEASE,
                "database": LEGACY_AUTHORITY_DATABASE,
                "database_identity_before": {
                    "device": 1,
                    "inode": 2,
                    "size": 10,
                },
                "database_identity_after": {
                    "device": 1,
                    "inode": 2,
                    "size": 10,
                },
                "database_sha256": "2" * 64,
                "service_unit": "devcoordinator-broker.service",
                "service_stopped": True,
                "maintenance": bundle["maintenance"],
                "writer_lock": prior["writer_lock"],
                "backup": prior["backup"],
                "precondition": snapshot,
                "postcondition": snapshot,
                "mutation_applied": False,
                "completed_at": "2026-07-28T00:02:01.000Z",
            },
        )

    def _run_initialize(
        self,
        *,
        bundle: Mapping[str, object] | None = None,
        readiness_evidence: Mapping[str, object] | None = None,
        live_readiness: Mapping[str, object] | None = None,
        supplied_digest: str | None = None,
        persist: bool = False,
        state_path: Path | None = None,
        existing_state: Mapping[str, object] | None = None,
        atomic_fence_verifier: mock.Mock | None = None,
        broker_lock_factory=None,
        database_identity_reader=None,
        readiness_snapshot_reader=None,
        reservation_row_verifier: mock.Mock | None = None,
        state_loader: mock.Mock | None = None,
        state_write_observer: mock.Mock | None = None,
        reattest_reference_verifier: mock.Mock | None = None,
        discard_test_history: bool = False,
        fresh_store_evidence: Mapping[str, object] | None = None,
        fresh_store_digest: str | None = None,
    ):
        identity = {"device": 1, "inode": 2, "size": 10}
        release_verifier = mock.Mock()
        release_verifier.verify_release.return_value = {
            "release_digest": RELEASE,
            "capabilities": {"edge": True, "testd": True},
        }
        topology_verifier = mock.Mock()
        topology_verifier.validate_topology.return_value = []
        bootstrap = bootstrap_attestation()
        schema = schema_readiness()
        fresh_schema = dict(fresh_store_evidence or schema)
        readiness = dict(
            readiness_evidence or authority_readiness_attestation()
        )
        reservations = dict(bundle or first_adoption_port_reservations())
        live = json.loads(json.dumps(readiness["postcondition"]))
        live["metadata"]["state_revision"] = reservations[
            "authority_state_revision_after"
        ]
        live["metadata"]["updated_at"] = reservations["created_at"]
        if live_readiness is not None:
            live = json.loads(json.dumps(live_readiness))
        if state_path is None:
            state_path = Path(f"/tmp/cutover-state-{uuid.uuid4()}.json")
        if existing_state is not None:
            state_path.write_text("{}", encoding="utf-8")

        def private_document(path, *, uid):
            del uid
            if str(path) == SCHEMA_ATTESTATION:
                return schema
            if str(path) == FRESH_SCHEMA_ATTESTATION:
                return fresh_schema
            if str(path) == AUTHORITY_READINESS_ATTESTATION:
                return readiness
            if str(path) == PORT_RESERVATIONS_ATTESTATION:
                return reservations
            return bootstrap

        captured: dict[str, object] = {}

        def writer(path, document, **kwargs):
            if state_write_observer is not None:
                state_write_observer(path, document, **kwargs)
            captured.update(document)
            path.write_text(json.dumps(document), encoding="utf-8")

        @contextmanager
        def passthrough_broker_lock(_database):
            yield

        identity_reader = database_identity_reader or mock.Mock(
            return_value=identity
        )
        snapshot_reader = readiness_snapshot_reader or mock.Mock(
            return_value=live
        )
        row_verifier = reservation_row_verifier or mock.Mock(
            return_value={"ok": True}
        )
        fence_verifier = atomic_fence_verifier or mock.Mock()
        reference_verifier = reattest_reference_verifier or mock.Mock()
        broker_lock = broker_lock_factory or passthrough_broker_lock
        loader = state_loader or mock.Mock(
            return_value=(
                dict(existing_state) if existing_state is not None else None
            )
        )
        with mock.patch.object(
            cutover, "_database_identity", side_effect=identity_reader
        ), mock.patch.object(
            cutover, "_private_parent"
        ), mock.patch.object(
            cutover, "read_private_json", side_effect=private_document
        ), mock.patch.object(
            cutover, "_load_release_verifier", return_value=release_verifier
        ), mock.patch.object(
            cutover, "_load_topology_verifier", return_value=topology_verifier
        ), mock.patch.object(
            cutover.shutil,
            "disk_usage",
            return_value=mock.Mock(free=10_000_000),
        ), mock.patch.object(
            cutover,
            "_read_authority_readiness_snapshot",
            side_effect=snapshot_reader,
        ), mock.patch.object(
            cutover,
            "_verify_authority_readiness_backup",
            return_value=readiness["backup"],
        ), mock.patch.object(
            cutover,
            "verify_first_adoption_port_reservation_rows",
            row_verifier,
        ), mock.patch.object(
            cutover,
            "_verify_atomic_first_adoption_fence",
            fence_verifier,
        ), mock.patch.object(
            cutover,
            "_verify_authority_readiness_reattest_references",
            reference_verifier,
        ), mock.patch.object(
            cutover,
            "exclusive_broker_service_lock",
            broker_lock,
        ), mock.patch.object(
            cutover, "_write_private_json", side_effect=writer
        ) as state_writer, mock.patch.object(
            cutover,
            "load_state",
            side_effect=loader,
        ):
            result = cutover.initialize(
                state_path=state_path,
                release=Path(f"/opt/devcoordinator/releases/{RELEASE}"),
                rendered_units=Path("/run/devcoordinator/cutover/units"),
                legacy_authority_database=Path(LEGACY_AUTHORITY_DATABASE),
                authority_database=Path(AUTHORITY_DATABASE),
                test_database=Path(TEST_DATABASE),
                inventory_canary_project=Path(INVENTORY_PROJECT),
                authority_backup_directory=Path("/var/backups/devcoordinator"),
                test_backup_directory=Path(
                    "/var/backups/devcoordinator-testd"
                ),
                migration_state=Path("/var/lib/devcoordinator/cutover.json"),
                drain_proof=Path("/var/lib/devcoordinator/drain.json"),
                cutover_seal=Path("/var/lib/devcoordinator/seal.json"),
                first_deployment_bootstrap=Path(BOOTSTRAP_ATTESTATION),
                authority_readiness=Path(AUTHORITY_READINESS_ATTESTATION),
                first_adoption_port_reservations=Path(
                    PORT_RESERVATIONS_ATTESTATION
                ),
                first_adoption_port_reservations_sha256=(
                    supplied_digest or str(reservations["document_sha256"])
                ),
                discard_test_history=(
                    cutover.DISCARD_TEST_HISTORY_CONFIRMATION
                    if discard_test_history
                    else None
                ),
                fresh_test_store_attestation=(
                    Path(FRESH_SCHEMA_ATTESTATION)
                    if discard_test_history
                    else None
                ),
                fresh_test_store_attestation_sha256=(
                    fresh_store_digest
                    or (
                        str(fresh_schema["document_sha256"])
                        if discard_test_history
                        else None
                    )
                ),
                authority_uid=0,
                testd_uid=TESTD_UID,
                reserve_bytes=0,
                retain_until="2026-09-01T00:00:00Z",
                persist=persist,
            )
        if existing_state is not None:
            state_path.unlink(missing_ok=True)
        return result, captured, row_verifier, state_writer

    def test_initialize_accepts_exact_single_reservation_revision_and_replays(self) -> None:
        state_path = Path(f"/tmp/cutover-state-{uuid.uuid4()}.json")
        bundle = first_adoption_port_reservations()
        result, state, row_verifier, state_writer = self._run_initialize(
            bundle=bundle,
            persist=True,
            state_path=state_path,
        )
        self.assertFalse(result["resumed"])
        state_writer.assert_called_once()
        row_verifier.assert_called_once()
        call = row_verifier.call_args
        self.assertEqual(call.args[0], Path(LEGACY_AUTHORITY_DATABASE))
        self.assertEqual(call.args[1], bundle)
        self.assertEqual(call.kwargs["authority_uid"], 0)
        self.assertEqual(
            state["evidence"]["first-adoption-port-reservations"], bundle
        )
        cutover.validate_state(state)
        resumed, _captured, replay_verifier, replay_writer = self._run_initialize(
            bundle=bundle,
            persist=True,
            state_path=state_path,
            existing_state=state,
        )
        self.assertTrue(resumed["resumed"])
        replay_verifier.assert_called_once()
        replay_writer.assert_not_called()

    def test_initialize_can_explicitly_discard_history_and_start_sealed(self) -> None:
        state_path = Path(f"/tmp/cutover-state-{uuid.uuid4()}.json")
        result, state, row_verifier, state_writer = self._run_initialize(
            discard_test_history=True,
            persist=True,
            state_path=state_path,
        )
        self.assertEqual(result["phase"], "sealed")
        self.assertFalse(result["capacity"]["testd"]["required"])
        self.assertEqual(result["capacity"]["testd"]["required_free_bytes"], 0)
        self.assertEqual(state["phase"], "sealed")
        self.assertEqual(
            state["evidence"]["test-history-discard"], schema_readiness()
        )
        self.assertEqual(
            cutover._test_store_cutover_completion(state)["mode"],
            "history-discarded",
        )
        state_writer.assert_called_once()
        row_verifier.assert_called_once()

        resumed, _captured, replay_verifier, replay_writer = self._run_initialize(
            discard_test_history=True,
            persist=True,
            state_path=state_path,
            existing_state=state,
        )
        self.assertEqual(resumed["phase"], "sealed")
        self.assertTrue(resumed["resumed"])
        replay_verifier.assert_called_once()
        replay_writer.assert_not_called()

        with self.assertRaisesRegex(cutover.CutoverError, "changed or belongs"):
            self._run_initialize(
                discard_test_history=True,
                fresh_store_digest="f" * 64,
            )

        state_path.unlink(missing_ok=True)

    def test_initialize_accepts_prepared_bundle_only_through_live_fence(self) -> None:
        bundle = atomic_first_adoption_prepared()
        fence = mock.Mock()
        result, state, row_verifier, _state_writer = self._run_initialize(
            bundle=bundle,
            persist=True,
            atomic_fence_verifier=fence,
        )

        self.assertFalse(result["resumed"])
        self.assertEqual(fence.call_count, 2)
        fence.assert_has_calls(
            [
                mock.call(bundle, authority_uid=0),
                mock.call(bundle, authority_uid=0),
            ]
        )
        self.assertEqual(row_verifier.call_count, 2)
        self.assertEqual(
            state["evidence"]["first-adoption-port-reservations"], bundle
        )

    def test_initialize_consumes_exact_post_reservation_reattestation(self) -> None:
        bundle = atomic_first_adoption_prepared()
        readiness = self._post_reservation_reattestation(bundle)
        reference_verifier = mock.Mock(
            return_value={"intent": {}, "prior": {}}
        )
        result, state, row_verifier, _state_writer = self._run_initialize(
            bundle=bundle,
            readiness_evidence=readiness,
            live_readiness=readiness["postcondition"],
            persist=True,
            reattest_reference_verifier=reference_verifier,
        )

        self.assertFalse(result["resumed"])
        self.assertEqual(reference_verifier.call_count, 2)
        reference_verifier.assert_has_calls(
            [
                mock.call(readiness, authority_uid=0),
                mock.call(readiness, authority_uid=0),
            ]
        )
        self.assertEqual(row_verifier.call_count, 2)
        self.assertEqual(
            state["evidence"]["authority-readiness"], readiness
        )
        self.assertEqual(
            cutover._first_adoption_port_authorized_readiness_snapshot(
                readiness=readiness,
                reservations=bundle,
            ),
            readiness["postcondition"],
        )
        self.assertEqual(
            cutover.validate_state(state)["evidence"][
                "authority-readiness"
            ],
            readiness,
        )

        wrong_path_values = {
            key: value
            for key, value in readiness.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        wrong_path_values["quiescence_attestation"] = {
            **dict(readiness["quiescence_attestation"]),
            "path": "/var/lib/devcoordinator/another-prepared.json",
        }
        wrong_path = cutover.seal(
            cutover.AUTHORITY_READINESS_REATTEST_KIND,
            wrong_path_values,
        )
        with self.assertRaisesRegex(
            cutover.CutoverError, "changed its quiescence path"
        ):
            self._run_initialize(
                bundle=bundle,
                readiness_evidence=wrong_path,
                live_readiness=wrong_path["postcondition"],
                reattest_reference_verifier=mock.Mock(
                    return_value={"intent": {}, "prior": {}}
                ),
            )

    def test_prepared_initialize_rechecks_every_authority_guard_under_lock(self) -> None:
        bundle = atomic_first_adoption_prepared()
        readiness = authority_readiness_attestation()
        expected_live = json.loads(json.dumps(readiness["postcondition"]))
        expected_live["metadata"]["state_revision"] = bundle[
            "authority_state_revision_after"
        ]
        expected_live["metadata"]["updated_at"] = bundle["created_at"]
        identity = {"device": 1, "inode": 2, "size": 10}
        locked = False
        events: list[tuple[str, object]] = []

        @contextmanager
        def broker_lock(database):
            nonlocal locked
            self.assertEqual(database, Path(LEGACY_AUTHORITY_DATABASE))
            self.assertFalse(locked)
            events.append(("lock-enter", str(database)))
            locked = True
            try:
                yield
            finally:
                locked = False
                events.append(("lock-exit", str(database)))

        def verify_fence(_prepared, *, authority_uid):
            self.assertEqual(authority_uid, 0)
            events.append(("fence", locked))
            return {
                "service": {"active": False, "enabled": True},
                "maintenance": bundle["maintenance"],
            }

        def read_identity(path, *, uid):
            self.assertIn(uid, {0, TESTD_UID})
            events.append((f"identity:{path}", locked))
            return dict(identity)

        def read_snapshot(path):
            self.assertEqual(path, Path(LEGACY_AUTHORITY_DATABASE))
            events.append(("snapshot", locked))
            return json.loads(json.dumps(expected_live))

        def verify_rows(database, reservations, **kwargs):
            self.assertEqual(database, Path(LEGACY_AUTHORITY_DATABASE))
            self.assertEqual(reservations, bundle)
            self.assertEqual(kwargs["authority_uid"], 0)
            self.assertEqual(kwargs["minimum_handoff_remaining_seconds"], 300)
            events.append(("rows", locked))
            return {"ok": True}

        def observe_write(path, _document, **kwargs):
            self.assertTrue(locked)
            self.assertEqual(kwargs, {"uid": 0, "create": True})
            events.append(("write", locked))

        result, _state, _rows, _writer = self._run_initialize(
            bundle=bundle,
            persist=True,
            broker_lock_factory=broker_lock,
            database_identity_reader=read_identity,
            readiness_snapshot_reader=read_snapshot,
            reservation_row_verifier=mock.Mock(side_effect=verify_rows),
            atomic_fence_verifier=mock.Mock(side_effect=verify_fence),
            state_write_observer=mock.Mock(side_effect=observe_write),
        )

        self.assertFalse(result["resumed"])
        self.assertIn(("fence", True), events)
        self.assertIn(("snapshot", True), events)
        self.assertIn(
            (f"identity:{Path(LEGACY_AUTHORITY_DATABASE)}", True), events
        )
        self.assertIn(("rows", True), events)
        self.assertIn(("write", True), events)
        lock_enter = events.index(
            ("lock-enter", str(Path(LEGACY_AUTHORITY_DATABASE)))
        )
        lock_exit = events.index(
            ("lock-exit", str(Path(LEGACY_AUTHORITY_DATABASE)))
        )
        for required in (
            ("fence", True),
            ("snapshot", True),
            (f"identity:{Path(LEGACY_AUTHORITY_DATABASE)}", True),
            ("rows", True),
            ("write", True),
        ):
            self.assertLess(lock_enter, events.index(required))
            self.assertLess(events.index(required), lock_exit)

    def test_prepared_initialize_rejects_revision_change_in_lock_window(self) -> None:
        bundle = atomic_first_adoption_prepared()
        readiness = authority_readiness_attestation()
        authorized = json.loads(json.dumps(readiness["postcondition"]))
        authorized["metadata"]["state_revision"] = bundle[
            "authority_state_revision_after"
        ]
        authorized["metadata"]["updated_at"] = bundle["created_at"]
        drifted = json.loads(json.dumps(authorized))
        drifted["metadata"]["state_revision"] += 1
        drifted["metadata"]["updated_at"] = "2026-07-28T00:02:01.000Z"
        locked = False
        snapshot_windows: list[bool] = []
        write_observer = mock.Mock()

        @contextmanager
        def broker_lock(_database):
            nonlocal locked
            locked = True
            try:
                yield
            finally:
                locked = False

        def read_snapshot(_database):
            snapshot_windows.append(locked)
            source = drifted if locked else authorized
            return json.loads(json.dumps(source))

        with self.assertRaisesRegex(
            cutover.CutoverError,
            "authority readiness evidence no longer matches the source",
        ):
            self._run_initialize(
                bundle=bundle,
                persist=True,
                broker_lock_factory=broker_lock,
                readiness_snapshot_reader=read_snapshot,
                state_write_observer=write_observer,
            )

        self.assertIn(False, snapshot_windows)
        self.assertIn(True, snapshot_windows)
        write_observer.assert_not_called()

    def test_prepared_initialize_rechecks_ledger_absence_under_lock(self) -> None:
        bundle = atomic_first_adoption_prepared()
        state_path = Path(f"/tmp/cutover-state-{uuid.uuid4()}.json")
        locked = False
        load_windows: list[bool] = []
        write_observer = mock.Mock()

        @contextmanager
        def broker_lock(_database):
            nonlocal locked
            locked = True
            state_path.write_text("{}", encoding="utf-8")
            try:
                yield
            finally:
                locked = False

        def load_existing(_path, *, authority_uid):
            self.assertEqual(authority_uid, 0)
            load_windows.append(locked)
            return sealed_state()

        try:
            with self.assertRaisesRegex(
                cutover.CutoverError,
                "cutover ledger already exists with another plan",
            ):
                self._run_initialize(
                    bundle=bundle,
                    persist=True,
                    state_path=state_path,
                    broker_lock_factory=broker_lock,
                    state_loader=mock.Mock(side_effect=load_existing),
                    state_write_observer=write_observer,
                )
        finally:
            state_path.unlink(missing_ok=True)

        self.assertEqual(load_windows, [True])
        write_observer.assert_not_called()

    def test_initialize_rejects_any_revision_window_or_binding_drift(self) -> None:
        readiness = authority_readiness_attestation()
        base_bundle = first_adoption_port_reservations()
        base_live = json.loads(json.dumps(readiness["postcondition"]))
        base_live["metadata"]["state_revision"] = base_bundle[
            "authority_state_revision_after"
        ]
        base_live["metadata"]["updated_at"] = base_bundle["created_at"]

        before_mismatch = first_adoption_port_reservations(
            state_revision_before=7
        )
        wrong_generation = first_adoption_port_reservations(
            authority_generation="wrong-authority-generation"
        )
        extra_revision = json.loads(json.dumps(base_live))
        extra_revision["metadata"]["state_revision"] += 1
        invariant_drift = json.loads(json.dumps(base_live))
        invariant_drift["invariants"]["repositories"] += 1
        metadata_drift = json.loads(json.dumps(base_live))
        metadata_drift["metadata"]["observation_revision"] += 1
        timestamp_drift = json.loads(json.dumps(base_live))
        timestamp_drift["metadata"]["updated_at"] = "2026-07-28T00:02:01.000Z"

        cases = (
            {
                "bundle": base_bundle,
                "live_readiness": base_live,
                "supplied_digest": "e" * 64,
            },
            {"bundle": before_mismatch, "live_readiness": base_live},
            {"bundle": wrong_generation, "live_readiness": base_live},
            {"bundle": base_bundle, "live_readiness": extra_revision},
            {"bundle": base_bundle, "live_readiness": invariant_drift},
            {"bundle": base_bundle, "live_readiness": metadata_drift},
            {"bundle": base_bundle, "live_readiness": timestamp_drift},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(cutover.CutoverError):
                    self._run_initialize(**case)


class FirstAdoptionPortReservationTests(unittest.TestCase):
    def _authority(self, root: Path) -> tuple[Path, Path]:
        database = root / "authority.sqlite3"
        project = root / "repo-alpha"
        project.mkdir()
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE schema_metadata(
                    singleton INTEGER PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL,
                    state_revision INTEGER NOT NULL,
                    observation_revision INTEGER NOT NULL,
                    authority_mode TEXT NOT NULL,
                    migration_state TEXT NOT NULL,
                    first_sqlite_mutation_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE hosts(
                    host_id TEXT PRIMARY KEY,
                    machine_fingerprint TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repositories(
                    repo_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL REFERENCES hosts(host_id),
                    canonical_root TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repository_installations(
                    repo_id TEXT PRIMARY KEY REFERENCES repositories(repo_id),
                    status TEXT NOT NULL,
                    startup_fenced INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    operation_id TEXT,
                    actor TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE port_assignments(
                    assignment_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL REFERENCES hosts(host_id),
                    repo_id TEXT NOT NULL REFERENCES repositories(repo_id),
                    server_name TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    deactivated_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX active_host_port_assignment
                    ON port_assignments(host_id, port) WHERE status = 'active';
                CREATE TABLE leases(
                    lease_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL REFERENCES hosts(host_id),
                    repo_id TEXT NOT NULL REFERENCES repositories(repo_id),
                    server_definition_id TEXT,
                    source_id TEXT,
                    port INTEGER NOT NULL,
                    owner TEXT,
                    agent TEXT,
                    purpose TEXT,
                    status TEXT NOT NULL,
                    expires_at TEXT,
                    process_fingerprint TEXT,
                    generation INTEGER NOT NULL,
                    deactivated_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX active_host_port_lease
                    ON leases(host_id, port) WHERE status = 'active';
                CREATE TABLE events(
                    event_id TEXT PRIMARY KEY,
                    repo_id TEXT REFERENCES repositories(repo_id),
                    source_id TEXT,
                    operation_id TEXT,
                    event_kind TEXT NOT NULL,
                    code TEXT,
                    message TEXT NOT NULL,
                    diagnostic_json TEXT,
                    occurred_at TEXT NOT NULL
                );
                """
            )
            stamp = "2026-07-29T00:00:00.000Z"
            connection.execute(
                "INSERT INTO schema_metadata VALUES (1, 12, ?, 17, 2, 'sqlite', 'ready', ?, ?, ?)",
                (AUTHORITY_GENERATION, stamp, stamp, stamp),
            )
            connection.execute(
                "INSERT INTO hosts VALUES ('host-alpha', 'machine', 'linux', 'host', ?, ?)",
                (stamp, stamp),
            )
            connection.execute(
                "INSERT INTO repositories VALUES ('repo-alpha', 'host-alpha', ?, 'Alpha', 'active', 4, ?, ?)",
                (str(project), stamp, stamp),
            )
            connection.execute(
                "INSERT INTO repository_installations VALUES ('repo-alpha', 'installed', 0, 1, NULL, 'installer', ?)",
                (stamp,),
            )
            connection.execute(
                "INSERT INTO port_assignments VALUES ('existing', 'host-alpha', 'repo-alpha', 'existing', 30000, 'active', 0, NULL, ?, ?)",
                (stamp, stamp),
            )
            connection.commit()
        os.chmod(database, 0o600)
        return database, project

    def _harness(self, root: Path, database: Path, project: Path):
        service = {"active": True, "enabled": True}
        maintenance: dict[str, object] = {"state": None}
        lock_entries: list[str] = []

        def command_status(argv):
            if argv[1:3] == ["is-active", "--quiet"]:
                return 0 if service["active"] else 3
            if argv[1:3] == ["is-enabled", "--quiet"]:
                return 0 if service["enabled"] else 1
            if argv[1] == "stop":
                service["active"] = False
                return 0
            if argv[1] == "start":
                service["active"] = True
                return 0
            return 1

        def activate(**kwargs):
            maintenance["state"] = {
                "deployment_id": kwargs["deployment_id"],
                "message": kwargs["message"],
                "retry_after_seconds": kwargs["retry_after_seconds"],
                "started_at": kwargs["started_at"],
            }

        def clear(**kwargs):
            current = maintenance["state"]
            self.assertIsNotNone(current)
            self.assertEqual(current["deployment_id"], kwargs["deployment_id"])
            maintenance["state"] = None

        def state_reader(**_kwargs):
            return maintenance["state"]

        def publisher(path, document, *, uid):
            del uid
            path.write_text(json.dumps(document), encoding="utf-8")
            os.chmod(path, 0o600)

        def reader(path, *, uid):
            del uid
            return json.loads(path.read_text(encoding="utf-8"))

        @contextmanager
        def lock(_database):
            lock_entries.append("enter")
            try:
                yield {"acquired": True}
            finally:
                lock_entries.append("exit")

        verifier = mock.Mock()
        verifier.verify_release.return_value = {
            "release_digest": RELEASE,
            "capabilities": {"edge": True, "api": True, "broker": True},
        }
        kwargs = {
            "release": root / "release",
            "database": database,
            "project_root": project,
            "repository_id": "repo-alpha",
            "repository_generation": 4,
            "handoff_ttl_seconds": 3600,
            "journal": root / "ports.intent.json",
            "attestation": root / "ports.json",
            "maintenance_root": root / "maintenance",
            "maintenance_gid": os.getegid(),
            "maintenance_deployment_id": str(uuid.uuid4()),
            "operation_id": str(uuid.uuid4()),
            "authority_uid": 0,
            "release_verifier": verifier,
            "command_status": command_status,
            "maintenance_activator": activate,
            "maintenance_clearer": clear,
            "maintenance_state_reader": state_reader,
            "evidence_reader": reader,
            "evidence_publisher": publisher,
            "effective_uid_reader": lambda: 0,
            "now_reader": lambda: "2026-07-29T01:00:00.000Z",
            "broker_lock_factory": lock,
            "port_selector": lambda *, candidates, protocol: (
                candidates[0] if protocol == "tcp" and candidates else None
            ),
        }
        return kwargs, service, maintenance, lock_entries

    def test_reservation_transaction_is_atomic_exact_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            database, project = self._authority(root)
            kwargs, service, maintenance, lock_entries = self._harness(
                root, database, project
            )
            with mock.patch.object(
                cutover,
                "_database_identity",
                return_value={"device": 1, "inode": 2, "size": 3},
            ):
                first = cutover.reserve_first_adoption_ports(**kwargs)
                verified = cutover.verify_first_adoption_port_reservations(
                    first["attestation"]
                )
                persisted = cutover.verify_first_adoption_port_reservation_rows(
                    database,
                    verified,
                    authority_uid=os.geteuid(),
                    minimum_handoff_remaining_seconds=300,
                    now_epoch=datetime(
                        2026, 7, 29, 1, 30, tzinfo=timezone.utc
                    ).timestamp(),
                )
                second = cutover.reserve_first_adoption_ports(**kwargs)
            self.assertFalse(first["replayed"])
            self.assertTrue(second["replayed"])
            self.assertEqual(
                first["attestation"]["document_sha256"],
                second["attestation"]["document_sha256"],
            )
            self.assertEqual(
                persisted["ports"],
                {
                    "console_outer": 30001,
                    "console_inner": 30002,
                    "handoff_http": 30003,
                    "handoff_https": 30004,
                    "handoff_api": 30005,
                },
            )
            self.assertIsNone(
                verified["reservations"]["console_outer"]["expires_at"]
            )
            expiries = {
                verified["reservations"][role]["expires_at"]
                for role in cutover.FIRST_ADOPTION_HANDOFF_PORT_ROLES
            }
            self.assertEqual(expiries, {"2026-07-29T02:00:00.000Z"})
            self.assertEqual(verified["authority_state_revision_before"], 17)
            self.assertEqual(verified["authority_state_revision_after"], 18)
            self.assertEqual(lock_entries, ["enter", "exit"])
            self.assertEqual(service, {"active": True, "enabled": True})
            self.assertIsNone(maintenance["state"])
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0],
                    5,
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                    5,
                )

    def test_invalid_selector_rolls_back_and_partial_replay_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            database, project = self._authority(root)
            kwargs, service, maintenance, _lock_entries = self._harness(
                root, database, project
            )
            kwargs["port_selector"] = lambda **_kwargs: 30001
            identity = {"device": 1, "inode": 2, "size": 3}
            with mock.patch.object(cutover, "_database_identity", return_value=identity):
                with self.assertRaisesRegex(
                    cutover.CutoverError, "Coordinator-verified port"
                ):
                    cutover.reserve_first_adoption_ports(**kwargs)
            self.assertEqual(service, {"active": True, "enabled": True})
            self.assertIsNone(maintenance["state"])
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0],
                    0,
                )
            intent = json.loads(Path(kwargs["journal"]).read_text(encoding="utf-8"))
            role = "console_outer"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    INSERT INTO leases VALUES (
                        ?, 'host-alpha', 'repo-alpha', NULL, NULL, 30001, NULL,
                        ?, ?, 'active', NULL, NULL, 0, NULL, ?, ?
                    )
                    """,
                    (
                        intent["row_ids"][role]["lease_id"],
                        intent["agent"],
                        intent["purposes"][role],
                        intent["created_at"],
                        intent["created_at"],
                    ),
                )
                connection.commit()
            kwargs["port_selector"] = lambda *, candidates, protocol: candidates[0]
            with mock.patch.object(cutover, "_database_identity", return_value=identity):
                with self.assertRaisesRegex(cutover.CutoverError, "replay is partial"):
                    cutover.reserve_first_adoption_ports(**kwargs)
            self.assertEqual(service, {"active": True, "enabled": True})
            self.assertIsNone(maintenance["state"])

    def test_contract_rejects_ttl_and_expiry_drift(self) -> None:
        operation_id = str(uuid.uuid4())
        created_at = "2026-07-29T01:00:00.000Z"
        reservations = {}
        for offset, role in enumerate(cutover.FIRST_ADOPTION_PORT_ROLES):
            reservations[role] = {
                "lease_id": str(uuid.uuid4()),
                "port": 40000 + offset,
                "agent": f"cutover:first-adoption:{operation_id}",
                "purpose": f"first-adoption:{RELEASE}:{role}",
                "status": "active",
                "expires_at": (
                    None
                    if role in cutover.FIRST_ADOPTION_CONSOLE_PORT_ROLES
                    else "2026-07-29T02:00:00.000Z"
                ),
            }
        values = {
            "operation_id": operation_id,
            "release_digest": RELEASE,
            "authority_database": AUTHORITY_DATABASE,
            "authority_generation": AUTHORITY_GENERATION,
            "authority_state_revision_before": 1,
            "authority_state_revision_after": 2,
            "repository_id": "repo-alpha",
            "repository_generation": 4,
            "canonical_root": "/home/example/repo-alpha",
            "port_range": dict(cutover.FIRST_ADOPTION_PORT_RANGE),
            "handoff_ttl_seconds": 3600,
            "reservations": reservations,
            "transaction_journal_sha256": "b" * 64,
            "service_unit": "devcoordinator-broker.service",
            "service_restored": True,
            "maintenance_cleared": True,
            "created_at": created_at,
            "completed_at": created_at,
        }
        self.assertEqual(
            cutover.verify_first_adoption_port_reservations(
                cutover.seal(cutover.FIRST_ADOPTION_PORT_RESERVATIONS_KIND, values)
            )["repository_id"],
            "repo-alpha",
        )
        drifted = json.loads(json.dumps(values))
        drifted["reservations"]["handoff_api"]["expires_at"] = (
            "2026-07-29T02:00:01.000Z"
        )
        with self.assertRaisesRegex(cutover.CutoverError, "expiry"):
            cutover.verify_first_adoption_port_reservations(
                cutover.seal(
                    cutover.FIRST_ADOPTION_PORT_RESERVATIONS_KIND, drifted
                )
            )

    def test_cli_exposes_root_only_reservation_action(self) -> None:
        parsed = cutover._parser().parse_args(
            [
                "reserve-first-adoption-ports",
                "--release",
                f"/opt/devcoordinator/releases/{RELEASE}",
                "--database",
                AUTHORITY_DATABASE,
                "--project-root",
                "/home/example/repo-alpha",
                "--repository-id",
                "repo-alpha",
                "--repository-generation",
                "4",
                "--handoff-ttl-seconds",
                "3600",
                "--journal",
                "/var/lib/devcoordinator/ports.intent.json",
                "--attestation",
                "/var/lib/devcoordinator/ports.json",
                "--maintenance-root",
                "/run/devcoordinator-maintenance",
                "--maintenance-gid",
                "986",
                "--maintenance-deployment-id",
                str(uuid.uuid4()),
                "--operation-id",
                str(uuid.uuid4()),
            ]
        )
        self.assertEqual(parsed.action, "reserve-first-adoption-ports")
        self.assertEqual(parsed.authority_uid, 0)


if __name__ == "__main__":
    unittest.main()
