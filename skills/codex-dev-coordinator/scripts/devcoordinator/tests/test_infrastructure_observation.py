"""Remote-infrastructure authority, replay, roster, and broker ACL tests."""

from __future__ import annotations

import copy
import base64
import hashlib
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from devcoordinator.broker import (
    DEFAULT_MAX_MESSAGE_BYTES,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import (
    BrokerPersistence,
    StoreBackedAuthorizer,
)
from devcoordinator.infrastructure_observation import (
    INFRASTRUCTURE_BROKER_PROJECT_ID,
    INFRASTRUCTURE_INGEST_RESOURCE_ID,
    INFRASTRUCTURE_JWS_ALGORITHM,
    INFRASTRUCTURE_JWS_TYPE,
    INFRASTRUCTURE_READ_RESOURCE_ID,
    INFRASTRUCTURE_SCHEMA,
    INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID,
    MAX_OBSERVATION_BYTES,
    MAX_PROJECTION_BYTES,
    OBSERVATION_CADENCE_SECONDS,
    OBSERVATION_STALE_AFTER_SECONDS,
    InfrastructureIngestRejected,
    InfrastructureObservationError,
    InfrastructureObservationAuthority,
    InfrastructureValidationError,
    normalize_ps256_spki,
    observation_payload_sha256,
    parse_canonical_observation_payload,
)
from devcoordinator.infrastructure_artifacts import stage_signed_envelope
from devcoordinator.schema import (
    INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS,
    INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS,
    SCHEMA_VERSION,
    invariant_violations,
)
from devcoordinator.store import CoordinatorStore, canonical_json, utc_timestamp


def _uuid(index: int) -> str:
    return str(uuid.UUID(int=index))


def _new_test_ps256_key() -> tuple[rsa.RSAPrivateKey, str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=3072,
    )
    spki_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        private_key,
        base64.b64encode(spki_der).decode("ascii"),
        hashlib.sha256(spki_der).hexdigest(),
    )


SIGNING_KEY_A, SPKI_A, SPKI_A_SHA256 = _new_test_ps256_key()
SIGNING_KEY_B, SPKI_B, SPKI_B_SHA256 = _new_test_ps256_key()
SIGNING_KEY_C, SPKI_C, SPKI_C_SHA256 = _new_test_ps256_key()
_SIGNATURE_CACHE: dict[tuple[str, str, str], bytes] = {}
_SIGNATURE_CACHE_LOCK = threading.Lock()
SPKI_RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmkuXsK+3jT5ix9e8t4yW"
    "1Dam+RyNuYTthlMtQOXm9Pr/4Ve6Oav5BFhL7iWtnakNaTQ87zfCE/SOS7pJF10g"
    "GboZln2+bw1uIGx0BfQ6Qe/+RRVtOsxMRk31EmkOvgh/3ufhWHO00EofBb1Z5C9"
    "lAfrb6xwjdCxAi8l/sYlW7M75WPqUhQOPumOptZxTj7YiiJWoCMiUrpu7fP4lv2/"
    "oQeZzWjSqK3J2i1bIGWgL4Z2+PLA6tJcEGNdirA08kRN8wuz3XrEI+T4d+jyKmq"
    "tgY6J3m2kqv7ggGhlAhSD1zGhafJQG+oOHQAFwKlreOPuqsox2Pn/rXXuKC0vo1"
    "iowQQIDAQAB"
)
SPKI_RSA_2048_SHA256 = (
    "2c51a0d944724c64d7349d46a23f02059f612712095106e6795e070943d5989a"
)


class InfrastructureObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".infrastructure-authority-", dir="/tmp"
        )
        self.database = Path(self.temporary.name) / "store" / "coordinator.sqlite3"
        self.now = int(time.time())
        self.cell_id = _uuid(1)
        self.host_id = _uuid(2)
        self.agent_id = _uuid(3)
        self.boot_id = _uuid(4)
        self.vm_a = _uuid(101)
        self.vm_b = _uuid(102)
        self.vm_c = _uuid(103)
        self.scope = {
            self.vm_a: "ingress",
            self.vm_b: "hub",
            self.vm_c: None,
        }
        self.ingress_staging_root = Path(self.temporary.name) / "ingress-artifacts"
        self.broker_artifact_root = Path(self.temporary.name) / "broker-artifacts"
        self.ingress_staging_root.mkdir(mode=0o700)
        self.broker_artifact_root.mkdir(mode=0o700)
        self.authority = InfrastructureObservationAuthority(
            self.database,
            clock=lambda: self.now,
            ingress_staging_root=self.ingress_staging_root,
            broker_artifact_root=self.broker_artifact_root,
        )
        self.authority.provision_cell(
            cell_id=self.cell_id,
            name="SPECTRE laboratory",
            region="lab",
            classification_label="test-only",
        )
        host = self.authority.provision_host(
            host_id=self.host_id,
            cell_id=self.cell_id,
            display_name="Hyper-V laboratory",
            failure_domain_label="single host; loss stops the whole laboratory",
            approved_virtual_machines=self.scope,
        )
        self.scope_sha256 = str(host["scope_sha256"])
        self.authority.provision_agent(
            agent_id=self.agent_id, host_id=self.host_id
        )
        self.authority.provision_certificate(
            agent_id=self.agent_id,
            certificate_generation=1,
            certificate_fingerprint_sha256="a" * 64,
            jws_key_id="spectre-agent-generation-1",
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_A,
            jws_spki_sha256=SPKI_A_SHA256,
            valid_from_epoch=self.now - 60,
            valid_until_epoch=self.now + 7_200,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def vm(self, vm_id: str, *, state: str = "off") -> dict:
        role = self.scope[vm_id]
        return {
            "vm_id": vm_id,
            "name": "VM-" + vm_id[-4:],
            "role": role,
            "state": state,
            "generation": 2,
            "vcpu": 4,
            "startup_memory_bytes": 8 * 1024**3,
            "assigned_memory_bytes": 0 if state == "off" else 8 * 1024**3,
            "ip_addresses": [],
            "heartbeat": "not-running" if state == "off" else "ok",
            "automatic_checkpoints": False,
            "replication": "disabled",
        }

    def observation(
        self,
        sequence: int,
        *,
        virtual_machines: list[dict] | None = None,
        roster_complete: bool = True,
        roster_error_code: str | None = None,
        captured_offset: int = 0,
        observation_id: str | None = None,
        boot_id: str | None = None,
    ) -> dict:
        document = {
            "schema": INFRASTRUCTURE_SCHEMA,
            "observation_id": observation_id or str(uuid.uuid4()),
            "cell_id": self.cell_id,
            "host_id": self.host_id,
            "agent_id": self.agent_id,
            "agent_boot_id": boot_id or self.boot_id,
            "sequence": sequence,
            "captured_at": utc_timestamp(self.now + captured_offset),
            "roster_complete": roster_complete,
            "roster_error_code": (
                None
                if roster_complete
                else roster_error_code or "vm_discovery_incomplete"
            ),
            "host": {
                "hostname": "SERVER-WORKII",
                "platform": "windows-hyperv",
                "platform_version": "Windows Server 2022 build 20348",
                "management_addresses": ["10.0.10.211"],
                "logical_cpu": 40,
                "physical_memory_bytes": 137_372_676_096,
                "uptime_seconds": 3600 + sequence,
            },
            "virtual_machines": (
                virtual_machines
                if virtual_machines is not None
                else [self.vm(self.vm_a), self.vm(self.vm_b)]
            ),
            "evidence": {
                "observer_version": "1.0.0",
                "scope_sha256": self.scope_sha256,
            },
        }
        return document

    @staticmethod
    def seal(document: dict) -> dict:
        return document

    def arguments(
        self,
        observation: dict,
        *,
        generation: int = 1,
        fingerprint: str = "a" * 64,
        key_id: str = "spectre-agent-generation-1",
        spki_sha256: str = SPKI_A_SHA256,
        signing_key: rsa.RSAPrivateKey | None = None,
    ) -> dict:
        header = {
            "alg": INFRASTRUCTURE_JWS_ALGORITHM,
            "typ": INFRASTRUCTURE_JWS_TYPE,
            "kid": key_id,
            "x5t#S256": base64.urlsafe_b64encode(bytes.fromhex(fingerprint))
            .rstrip(b"=")
            .decode("ascii"),
            "cert_generation": generation,
            "spki_sha256": spki_sha256,
        }
        encoded_header = (
            base64.urlsafe_b64encode(canonical_json(header).encode("utf-8"))
            .rstrip(b"=")
            .decode("ascii")
        )
        encoded_payload = (
            base64.urlsafe_b64encode(canonical_json(observation).encode("utf-8"))
            .rstrip(b"=")
            .decode("ascii")
        )
        selected_signing_key = signing_key or {
            SPKI_A_SHA256: SIGNING_KEY_A,
            SPKI_B_SHA256: SIGNING_KEY_B,
            SPKI_C_SHA256: SIGNING_KEY_C,
        }.get(spki_sha256, SIGNING_KEY_A)
        signing_input = f"{encoded_header}.{encoded_payload}"
        cache_key = (
            spki_sha256
            if signing_key is None
            else f"override:{id(selected_signing_key)}",
            encoded_header,
            encoded_payload,
        )
        with _SIGNATURE_CACHE_LOCK:
            signature = _SIGNATURE_CACHE.get(cache_key)
            if signature is None:
                signature = selected_signing_key.sign(
                    signing_input.encode("ascii"),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hashes.SHA256(),
                )
                _SIGNATURE_CACHE[cache_key] = signature
        encoded_signature = (
            base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        )
        compact_jws = (
            f"{encoded_header}.{encoded_payload}.{encoded_signature}".encode(
                "ascii"
            )
        )
        artifact = stage_signed_envelope(
            self.ingress_staging_root, compact_jws
        )
        return {
            "transport": {
                "mtls_verified": True,
                "jws_verified": True,
                "certificate_fingerprint_sha256": fingerprint,
                "certificate_generation": generation,
                "jws_key_id": key_id,
                "jws_algorithm": INFRASTRUCTURE_JWS_ALGORITHM,
                "jws_spki_sha256": spki_sha256,
                "canonical_payload_sha256": observation_payload_sha256(
                    observation
                ),
            },
            "observation": observation,
            "artifact": artifact.to_dict(),
        }

    def ingest(
        self, observation: dict, *, operation_id: str | None = None, **transport: object
    ) -> dict:
        return self.authority.ingest(
            self.arguments(observation, **transport),
            broker_operation_id=operation_id or str(uuid.uuid4()),
            broker_peer_uid=os.geteuid(),
            broker_account_id="infrastructure-ingress",
        )

    def audit_codes(self) -> list[str | None]:
        with CoordinatorStore.open_read_only(self.database) as store:
            with store.read_transaction() as connection:
                return [
                    row["rejection_code"]
                    for row in connection.execute(
                        """
                        SELECT rejection_code
                        FROM infrastructure_ingest_audit
                        ORDER BY audit_sequence
                        """
                    )
                ]

    def test_schema_v14_and_immutable_evidence_tables(self) -> None:
        accepted = self.ingest(self.observation(1))
        with CoordinatorStore.open(self.database) as store:
            self.assertEqual(store.metadata.schema_version, SCHEMA_VERSION)
            self.assertEqual(SCHEMA_VERSION, 14)
            with self.assertRaisesRegex(
                Exception, "infrastructure accepted observations are immutable"
            ):
                with store.immediate_transaction(
                    revision_kind=None, check_invariants=False
                ) as connection:
                    connection.execute(
                        """
                        UPDATE infrastructure_observations
                        SET observer_version = '9.9.9'
                        WHERE observation_id = ?
                        """,
                        (accepted["observation_id"],),
                    )
            with self.assertRaisesRegex(
                Exception, "infrastructure ingest audit is immutable"
            ):
                with store.immediate_transaction(
                    revision_kind=None, check_invariants=False
                ) as connection:
                    connection.execute(
                        "DELETE FROM infrastructure_ingest_audit"
                    )
            with self.assertRaisesRegex(
                Exception, "infrastructure current VM scope mismatch"
            ):
                with store.immediate_transaction(
                    revision_kind=None, check_invariants=False
                ) as connection:
                    connection.execute(
                        """
                        UPDATE infrastructure_current_vms
                        SET role = 'hub'
                        WHERE host_id = ? AND vm_id = ?
                        """,
                        (self.host_id, self.vm_a),
                    )

    def test_schema_v12_store_upgrades_to_v14_with_core_tables(self) -> None:
        legacy_database = (
            Path(self.temporary.name) / "legacy" / "coordinator.sqlite3"
        )
        infrastructure_tables = (
            "infrastructure_current_vms",
            "infrastructure_current_hosts",
            "infrastructure_ingest_audit",
            "infrastructure_ingest_operations",
            "infrastructure_observations",
            "infrastructure_agent_replay_state",
            "infrastructure_agent_boot_history",
            "infrastructure_agent_certificates",
            "infrastructure_observer_agents",
            "infrastructure_host_vm_scope",
            "infrastructure_hosts",
            "infrastructure_cells",
        )
        with CoordinatorStore.open(legacy_database) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                for table in infrastructure_tables:
                    connection.execute(f"DROP TABLE {table}")
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET schema_version = 12
                    WHERE singleton = 1
                    """
                )
        with CoordinatorStore.open(legacy_database) as upgraded:
            self.assertEqual(upgraded.metadata.schema_version, 14)
            names = {
                str(row[0])
                for row in upgraded.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(set(infrastructure_tables) <= names)

    def test_schema_v4_store_upgrades_to_v14_preserving_legacy_rows(self) -> None:
        legacy_database = (
            Path(self.temporary.name) / "legacy-v4" / "coordinator.sqlite3"
        )
        infrastructure_tables = (
            "infrastructure_current_vms",
            "infrastructure_current_hosts",
            "infrastructure_ingest_audit",
            "infrastructure_ingest_operations",
            "infrastructure_observations",
            "infrastructure_agent_replay_state",
            "infrastructure_agent_boot_history",
            "infrastructure_agent_certificates",
            "infrastructure_observer_agents",
            "infrastructure_host_vm_scope",
            "infrastructure_hosts",
            "infrastructure_cells",
        )
        now = utc_timestamp(self.now)
        with CoordinatorStore.open(legacy_database) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES ('legacy-host', 'legacy-machine', 'linux',
                              'legacy.example', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, captured_revision,
                        captured_sha256, imported_at, created_at, updated_at
                    ) VALUES ('legacy-source', 'legacy-host', '/legacy/home',
                              '/legacy/home/state.json', 1000, 'imported', 7,
                              ?, ?, ?, ?)
                    """,
                    ("a" * 64, now, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('legacy-repo', 'legacy-host', '/srv/legacy',
                              'Legacy repository', 'active', 3, ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, source_id, kind, status, phase,
                        generation, request_fingerprint, owner_uid, actor,
                        result_json, created_at, updated_at
                    ) VALUES ('legacy-operation', 'legacy-repo',
                              'legacy-source', 'inventory', 'succeeded',
                              'complete', 2, ?, 1000, 'legacy-agent',
                              '{"retained":true}', ?, ?)
                    """,
                    ("sha256:" + "b" * 64, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO source_resources(
                        source_resource_id, source_id, resource_kind, native_id,
                        repo_id, payload_sha256, provenance_json, created_at
                    ) VALUES ('legacy-resource', 'legacy-source', 'server',
                              'server-legacy', 'legacy-repo', ?,
                              '{"source":"legacy"}', ?)
                    """,
                    ("c" * 64, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind, host_resource_id,
                        immutable_fingerprint, created_at
                    ) VALUES ('legacy-membership', 'legacy-repo', 'server',
                              'server-legacy', ?, ?)
                    """,
                    ("sha256:" + "d" * 64, now),
                )
                connection.execute(
                    """
                    INSERT INTO startup_policies(
                        policy_id, repo_id, resource_kind, resource_id,
                        policy_kind, current_value, desired_disabled_value,
                        immutable_fingerprint, generation, updated_at
                    ) VALUES ('legacy-policy', 'legacy-repo', 'server',
                              'server-legacy', 'supervisor', 'enabled',
                              'disabled', ?, 4, ?)
                    """,
                    ("sha256:" + "e" * 64, now),
                )
                connection.execute("DROP TABLE repository_scopes")
                connection.execute("DROP TABLE repository_families")
                for table in infrastructure_tables:
                    connection.execute(f"DROP TABLE {table}")
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET schema_version = 4
                    WHERE singleton = 1
                    """
                )

        with CoordinatorStore.open(legacy_database) as upgraded:
            self.assertEqual(upgraded.metadata.schema_version, 14)
            connection = upgraded.connection
            self.assertEqual(
                dict(
                    connection.execute(
                        """
                        SELECT host_id, machine_fingerprint, hostname
                        FROM hosts WHERE host_id = 'legacy-host'
                        """
                    ).fetchone()
                ),
                {
                    "host_id": "legacy-host",
                    "machine_fingerprint": "legacy-machine",
                    "hostname": "legacy.example",
                },
            )
            self.assertEqual(
                dict(
                    connection.execute(
                        """
                        SELECT repo_id, generation, display_name
                        FROM repositories WHERE repo_id = 'legacy-repo'
                        """
                    ).fetchone()
                ),
                {
                    "repo_id": "legacy-repo",
                    "generation": 3,
                    "display_name": "Legacy repository",
                },
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT payload_sha256 FROM source_resources
                    WHERE source_resource_id = 'legacy-resource'
                    """
                ).fetchone()[0],
                "c" * 64,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT immutable_fingerprint FROM repository_memberships
                    WHERE membership_id = 'legacy-membership'
                    """
                ).fetchone()[0],
                "sha256:" + "d" * 64,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT immutable_fingerprint FROM startup_policies
                    WHERE policy_id = 'legacy-policy'
                    """
                ).fetchone()[0],
                "sha256:" + "e" * 64,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT result_json FROM operations
                    WHERE operation_id = 'legacy-operation'
                    """
                ).fetchone()[0],
                '{"retained":true}',
            )
            self.assertEqual(
                dict(
                    connection.execute(
                        """
                        SELECT family_id, project_kind
                        FROM repository_scopes
                        WHERE repo_id = 'legacy-repo'
                        """
                    ).fetchone()
                ),
                {"family_id": "legacy-repo", "project_kind": "primary"},
            )
            names = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(set(infrastructure_tables) <= names)
            self.assertEqual(
                list(connection.execute("PRAGMA foreign_key_check")), []
            )
            self.assertEqual(invariant_violations(connection), [])

    def test_real_v13_certificate_table_upgrades_only_when_empty(self) -> None:
        legacy_database = (
            Path(self.temporary.name) / "legacy-v13" / "coordinator.sqlite3"
        )
        legacy_database.parent.mkdir()
        with closing(sqlite3.connect(legacy_database)) as connection:
            connection.executescript(
                """
                CREATE TABLE schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL UNIQUE,
                    state_revision INTEGER NOT NULL DEFAULT 0,
                    observation_revision INTEGER NOT NULL DEFAULT 0,
                    authority_mode TEXT NOT NULL DEFAULT 'shadow',
                    migration_state TEXT NOT NULL DEFAULT 'empty',
                    first_sqlite_mutation_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO schema_metadata(
                    singleton, schema_version, database_generation,
                    state_revision, observation_revision, authority_mode,
                    migration_state, first_sqlite_mutation_at,
                    created_at, updated_at
                ) VALUES (
                    1, 13, 'legacy-v13-empty', 0, 0, 'shadow', 'empty',
                    NULL, '2026-07-29T00:00:00Z', '2026-07-29T00:00:00Z'
                );
                CREATE TABLE infrastructure_agent_certificates (
                    agent_id TEXT NOT NULL,
                    certificate_generation INTEGER NOT NULL,
                    certificate_fingerprint_sha256 TEXT NOT NULL UNIQUE,
                    jws_key_id TEXT NOT NULL,
                    valid_from_epoch INTEGER NOT NULL,
                    valid_until_epoch INTEGER NOT NULL,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(agent_id, certificate_generation)
                );
                """
            )
            connection.commit()
        with CoordinatorStore.open(legacy_database) as upgraded:
            self.assertEqual(upgraded.metadata.schema_version, 14)
            certificate_columns = {
                str(row["name"])
                for row in upgraded.connection.execute(
                    "PRAGMA table_info(infrastructure_agent_certificates)"
                )
            }
            self.assertTrue(
                {
                    "jws_algorithm",
                    "jws_spki_der_base64",
                    "jws_spki_sha256",
                }
                <= certificate_columns
            )

    def test_v13_certificate_rows_without_spki_block_v14_migration(self) -> None:
        legacy_database = (
            Path(self.temporary.name)
            / "legacy-v13-populated"
            / "coordinator.sqlite3"
        )
        legacy_database.parent.mkdir()
        with closing(sqlite3.connect(legacy_database)) as connection:
            connection.executescript(
                """
                CREATE TABLE schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL UNIQUE,
                    state_revision INTEGER NOT NULL DEFAULT 0,
                    observation_revision INTEGER NOT NULL DEFAULT 0,
                    authority_mode TEXT NOT NULL DEFAULT 'shadow',
                    migration_state TEXT NOT NULL DEFAULT 'empty',
                    first_sqlite_mutation_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO schema_metadata(
                    singleton, schema_version, database_generation,
                    state_revision, observation_revision, authority_mode,
                    migration_state, first_sqlite_mutation_at,
                    created_at, updated_at
                ) VALUES (
                    1, 13, 'legacy-v13-populated', 0, 0, 'shadow', 'empty',
                    NULL, '2026-07-29T00:00:00Z', '2026-07-29T00:00:00Z'
                );
                CREATE TABLE infrastructure_agent_certificates (
                    agent_id TEXT NOT NULL,
                    certificate_generation INTEGER NOT NULL,
                    certificate_fingerprint_sha256 TEXT NOT NULL UNIQUE,
                    jws_key_id TEXT NOT NULL,
                    valid_from_epoch INTEGER NOT NULL,
                    valid_until_epoch INTEGER NOT NULL,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(agent_id, certificate_generation)
                );
                INSERT INTO infrastructure_agent_certificates(
                    agent_id, certificate_generation,
                    certificate_fingerprint_sha256, jws_key_id,
                    valid_from_epoch, valid_until_epoch,
                    revoked_at, revocation_reason, created_at
                ) VALUES (
                    'legacy-agent', 1,
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'unknown-material', 1, 2, NULL, NULL,
                    '2026-07-29T00:00:00Z'
                );
                """
            )
            connection.commit()
        with self.assertRaisesRegex(
            RuntimeError,
            "lack immutable PS256/SPKI verification material",
        ):
            CoordinatorStore.open(legacy_database)
        with closing(sqlite3.connect(legacy_database)) as connection:
            self.assertEqual(
                int(
                    connection.execute(
                        """
                        SELECT schema_version FROM schema_metadata
                        WHERE singleton = 1
                        """
                    ).fetchone()[0]
                ),
                13,
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(infrastructure_agent_certificates)"
                )
            }
            self.assertNotIn("jws_spki_sha256", columns)

    def test_v14_migration_rejects_duplicate_signing_key_identity(self) -> None:
        legacy_database = (
            Path(self.temporary.name)
            / "legacy-v14-duplicate-spki"
            / "coordinator.sqlite3"
        )
        legacy_database.parent.mkdir()
        with closing(sqlite3.connect(legacy_database)) as connection:
            connection.executescript(
                f"""
                CREATE TABLE schema_metadata (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL UNIQUE,
                    state_revision INTEGER NOT NULL DEFAULT 0,
                    observation_revision INTEGER NOT NULL DEFAULT 0,
                    authority_mode TEXT NOT NULL DEFAULT 'shadow',
                    migration_state TEXT NOT NULL DEFAULT 'empty',
                    first_sqlite_mutation_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO schema_metadata(
                    singleton, schema_version, database_generation,
                    state_revision, observation_revision, authority_mode,
                    migration_state, first_sqlite_mutation_at,
                    created_at, updated_at
                ) VALUES (
                    1, 13, 'legacy-v14-duplicate-spki', 0, 0, 'shadow',
                    'empty', NULL, '2026-07-29T00:00:00Z',
                    '2026-07-29T00:00:00Z'
                );
                CREATE TABLE infrastructure_agent_certificates (
                    agent_id TEXT NOT NULL,
                    certificate_generation INTEGER NOT NULL,
                    certificate_fingerprint_sha256 TEXT NOT NULL UNIQUE,
                    jws_key_id TEXT NOT NULL,
                    jws_algorithm TEXT NOT NULL,
                    jws_spki_der_base64 TEXT NOT NULL,
                    jws_spki_sha256 TEXT NOT NULL,
                    valid_from_epoch INTEGER NOT NULL,
                    valid_until_epoch INTEGER NOT NULL,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(agent_id, certificate_generation)
                );
                INSERT INTO infrastructure_agent_certificates(
                    agent_id, certificate_generation,
                    certificate_fingerprint_sha256, jws_key_id,
                    jws_algorithm, jws_spki_der_base64, jws_spki_sha256,
                    valid_from_epoch, valid_until_epoch,
                    revoked_at, revocation_reason, created_at
                ) VALUES
                    (
                        'legacy-agent-a', 1,
                        '{'a' * 64}', 'legacy-key-a', 'PS256',
                        '{SPKI_A}', '{SPKI_A_SHA256}',
                        1, 2, NULL, NULL, '2026-07-29T00:00:00Z'
                    ),
                    (
                        'legacy-agent-b', 1,
                        '{'b' * 64}', 'legacy-key-b', 'PS256',
                        '{SPKI_A}', '{SPKI_A_SHA256}',
                        1, 2, NULL, NULL, '2026-07-29T00:00:00Z'
                    );
                """
            )
            connection.commit()
        with self.assertRaisesRegex(
            RuntimeError,
            "globally unique signing key per generation",
        ):
            CoordinatorStore.open(legacy_database)
        with closing(sqlite3.connect(legacy_database)) as connection:
            self.assertEqual(
                int(
                    connection.execute(
                        """
                        SELECT schema_version FROM schema_metadata
                        WHERE singleton = 1
                        """
                    ).fetchone()[0]
                ),
                13,
            )
            self.assertFalse(
                any(
                    str(row[1])
                    == "infrastructure_certificates_by_signing_material"
                    for row in connection.execute(
                        "PRAGMA index_list(infrastructure_agent_certificates)"
                    )
                )
            )

    def test_canonical_payload_parser_rejects_ambiguous_signed_bytes(self) -> None:
        document = self.observation(1)
        canonical = canonical_json(document).encode("utf-8")
        parsed, digest = parse_canonical_observation_payload(canonical)
        self.assertEqual(parsed, document)
        self.assertEqual(digest, observation_payload_sha256(document))

        variants = {
            "whitespace": b" " + canonical,
            "key_order": (
                b'{"schema":"'
                + INFRASTRUCTURE_SCHEMA.encode("ascii")
                + b'","observation_id":"'
                + document["observation_id"].encode("ascii")
                + b'"}'
            ),
            "escaped_unicode": canonical.replace(
                b"SERVER-WORKII", b"SERVER\\u002dWORKII"
            ),
            "duplicate_key": b'{"schema":"a","schema":"b"}',
            "nfd_unicode": canonical.replace(
                b"SERVER-WORKII", "E\u0301".encode("utf-8")
            ),
            "float": b'{"value":1.5}',
        }
        expected_codes = {
            "whitespace": "noncanonical_json_payload",
            "key_order": "noncanonical_json_payload",
            "escaped_unicode": "noncanonical_json_payload",
            "duplicate_key": "duplicate_json_key",
            "nfd_unicode": "noncanonical_unicode",
            "float": "json_float_not_allowed",
        }
        for name, payload in variants.items():
            with self.subTest(name=name):
                with self.assertRaises(InfrastructureValidationError) as error:
                    parse_canonical_observation_payload(payload)
                self.assertEqual(error.exception.code, expected_codes[name])

    def test_complete_replaces_and_partial_preserves_current_roster(self) -> None:
        first = self.ingest(self.observation(1))
        self.assertEqual(first["current_vm_count"], 2)

        partial = self.ingest(
            self.observation(
                2,
                virtual_machines=[self.vm(self.vm_a, state="running")],
                roster_complete=False,
                captured_offset=1,
            )
        )
        self.assertFalse(partial["roster_complete"])
        self.assertEqual(partial["reported_vm_count"], 1)
        self.assertEqual(partial["current_vm_count"], 2)

        complete = self.ingest(
            self.observation(
                3,
                virtual_machines=[self.vm(self.vm_a, state="running")],
                captured_offset=2,
            )
        )
        self.assertTrue(complete["roster_complete"])
        self.assertEqual(complete["current_vm_count"], 1)
        projection = self.authority.read_projection({})
        host = projection["hosts"][0]
        self.assertEqual(
            [item["vm_id"] for item in host["virtual_machines"]],
            [self.vm_a],
        )
        self.assertEqual(
            host["failure_domain_label"],
            "single host; loss stops the whole laboratory",
        )
        self.assertEqual(host["approved_vm_count"], 3)
        self.assertEqual(
            host["missing_approved_virtual_machines"],
            [
                {"vm_id": self.vm_b, "approved_role": "hub"},
                {"vm_id": self.vm_c, "approved_role": None},
            ],
        )
        self.assertFalse(host["missing_approved_projection_truncated"])
        self.assertTrue(host["signature_verified"])
        self.assertTrue(host["evidence_available"])
        self.assertEqual(
            host["verification"]["signed_envelope_locator"],
            "sha256:" + host["verification"]["signed_envelope_sha256"],
        )
        self.assertGreater(
            host["verification"]["signed_envelope_size_bytes"], 0
        )

    def test_projection_is_bounded_and_sorted_by_immutable_ids(self) -> None:
        self.ingest(self.observation(1))
        second_host = _uuid(20)
        self.authority.provision_host(
            host_id=second_host,
            cell_id=self.cell_id,
            display_name="Second enrolled host",
            failure_domain_label="independent fixture host",
            approved_virtual_machines={},
        )
        first_page = self.authority.read_projection(
            {
                "host_limit": 1,
                "vm_limit_per_host": 1,
                "rejection_limit_per_host": 0,
            }
        )
        self.assertEqual(
            [item["host_id"] for item in first_page["hosts"]],
            [self.host_id],
        )
        self.assertTrue(first_page["has_more"])
        self.assertEqual(first_page["next_after_host_id"], self.host_id)
        self.assertEqual(
            [item["vm_id"] for item in first_page["hosts"][0]["virtual_machines"]],
            [self.vm_a],
        )
        self.assertTrue(first_page["hosts"][0]["vm_projection_truncated"])
        self.assertEqual(first_page["hosts"][0]["approved_vm_count"], 3)
        self.assertEqual(
            first_page["hosts"][0]["missing_approved_virtual_machines"],
            [{"vm_id": self.vm_c, "approved_role": None}],
        )
        self.assertFalse(
            first_page["hosts"][0]["missing_approved_projection_truncated"]
        )
        zero_vm_page = self.authority.read_projection(
            {
                "host_limit": 1,
                "vm_limit_per_host": 0,
                "rejection_limit_per_host": 0,
            }
        )
        self.assertEqual(
            zero_vm_page["hosts"][0]["missing_approved_virtual_machines"], []
        )
        self.assertTrue(
            zero_vm_page["hosts"][0]["missing_approved_projection_truncated"]
        )
        second_page = self.authority.read_projection(
            {"after_host_id": self.host_id, "host_limit": 1}
        )
        self.assertEqual(
            [item["host_id"] for item in second_page["hosts"]],
            [second_host],
        )
        self.assertFalse(second_page["has_more"])
        with self.assertRaises(InfrastructureValidationError):
            self.authority.read_projection({"host_limit": 101})

    def test_projection_byte_limit_paginates_before_broker_result_limit(
        self,
    ) -> None:
        self.assertLess(
            MAX_PROJECTION_BYTES,
            DEFAULT_MAX_MESSAGE_BYTES // 2,
        )
        self.ingest(self.observation(1))
        second_host = _uuid(20)
        self.authority.provision_host(
            host_id=second_host,
            cell_id=self.cell_id,
            display_name="Second enrolled host",
            failure_domain_label="independent fixture host",
            approved_virtual_machines={},
        )
        full = self.authority.read_projection(
            {
                "host_limit": 2,
                "vm_limit_per_host": 3,
                "rejection_limit_per_host": 0,
            }
        )
        first_only = copy.deepcopy(full)
        first_only["hosts"] = first_only["hosts"][:1]
        first_only["has_more"] = True
        first_only["next_after_host_id"] = self.host_id
        exact_first_page_bytes = len(
            canonical_json(first_only).encode("utf-8")
        )
        self.assertGreater(
            len(canonical_json(full).encode("utf-8")),
            exact_first_page_bytes,
        )
        with mock.patch(
            "devcoordinator.infrastructure_observation.MAX_PROJECTION_BYTES",
            exact_first_page_bytes,
        ):
            bounded = self.authority.read_projection(
                {
                    "host_limit": 2,
                    "vm_limit_per_host": 3,
                    "rejection_limit_per_host": 0,
                }
            )
            second_page = self.authority.read_projection(
                {
                    "after_host_id": self.host_id,
                    "host_limit": 2,
                    "vm_limit_per_host": 3,
                    "rejection_limit_per_host": 0,
                }
            )
        self.assertEqual(
            [host["host_id"] for host in bounded["hosts"]],
            [self.host_id],
        )
        self.assertTrue(bounded["has_more"])
        self.assertEqual(bounded["next_after_host_id"], self.host_id)
        self.assertLessEqual(
            len(canonical_json(bounded).encode("utf-8")),
            exact_first_page_bytes,
        )
        self.assertEqual(
            [host["host_id"] for host in second_page["hosts"]],
            [second_host],
        )
        self.assertFalse(second_page["has_more"])

    def test_projection_freshness_is_exact_at_three_missed_observations(self) -> None:
        self.ingest(self.observation(1))
        unobserved_host = _uuid(20)
        self.authority.provision_host(
            host_id=unobserved_host,
            cell_id=self.cell_id,
            display_name="Awaiting first observation",
            failure_domain_label="independent fixture host",
            approved_virtual_machines={},
        )

        projection = self.authority.read_projection({})
        self.assertEqual(projection["generated_at"], utc_timestamp(self.now))
        self.assertEqual(
            projection["observation_cadence_seconds"],
            OBSERVATION_CADENCE_SECONDS,
        )
        self.assertEqual(
            projection["stale_after_seconds"],
            OBSERVATION_STALE_AFTER_SECONDS,
        )
        observed = projection["hosts"][0]
        for field in (
            "contact_freshness",
            "capture_freshness",
            "acceptance_freshness",
        ):
            self.assertEqual(
                observed[field],
                {
                    "status": "fresh",
                    "age_seconds": 0,
                    "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
                },
            )
        awaiting = projection["hosts"][1]
        for field in (
            "contact_freshness",
            "capture_freshness",
            "acceptance_freshness",
        ):
            self.assertEqual(
                awaiting[field],
                {
                    "status": "never",
                    "age_seconds": None,
                    "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
                },
            )

        self.now += OBSERVATION_STALE_AFTER_SECONDS - 1
        before_boundary = self.authority.read_projection({})["hosts"][0]
        for field in (
            "contact_freshness",
            "capture_freshness",
            "acceptance_freshness",
        ):
            self.assertEqual(before_boundary[field]["status"], "fresh")
            self.assertEqual(
                before_boundary[field]["age_seconds"],
                OBSERVATION_STALE_AFTER_SECONDS - 1,
            )

        self.now += 1
        at_boundary = self.authority.read_projection({})["hosts"][0]
        for field in (
            "contact_freshness",
            "capture_freshness",
            "acceptance_freshness",
        ):
            self.assertEqual(at_boundary[field]["status"], "stale")
            self.assertEqual(
                at_boundary[field]["age_seconds"],
                OBSERVATION_STALE_AFTER_SECONDS,
            )

    def test_identity_and_scope_mismatches_fail_closed(self) -> None:
        wrong_host = self.observation(1)
        wrong_host["host_id"] = _uuid(200)
        self.seal(wrong_host)
        with self.assertRaisesRegex(
            InfrastructureIngestRejected, "host_id does not match"
        ):
            self.ingest(wrong_host)

        wrong_scope = self.observation(1)
        wrong_scope["evidence"]["scope_sha256"] = "f" * 64
        self.seal(wrong_scope)
        with self.assertRaisesRegex(
            InfrastructureIngestRejected, "scope digest"
        ):
            self.ingest(wrong_scope)

        wrong_role = self.observation(1)
        wrong_role["virtual_machines"][0]["role"] = "hub"
        self.seal(wrong_role)
        with self.assertRaisesRegex(
            InfrastructureIngestRejected, "centrally approved role"
        ):
            self.ingest(wrong_role)

        outside_scope = self.observation(1)
        outside_scope["virtual_machines"] = [
            {
                **self.vm(self.vm_a),
                "vm_id": _uuid(999),
            }
        ]
        self.seal(outside_scope)
        with self.assertRaisesRegex(
            InfrastructureIngestRejected, "outside the centrally approved scope"
        ):
            self.ingest(outside_scope)
        self.assertEqual(
            self.audit_codes(),
            [
                "host_identity_mismatch",
                "scope_mismatch",
                "vm_role_mismatch",
                "vm_scope_mismatch",
            ],
        )

    def test_verified_transport_binding_and_canonical_digest_fail_closed(self) -> None:
        cases: list[tuple[str, dict, str]] = []
        not_mtls = self.arguments(self.observation(1))
        not_mtls["transport"]["mtls_verified"] = False
        cases.append(("mtls", not_mtls, "transport_not_verified"))
        not_jws = self.arguments(self.observation(1))
        not_jws["transport"]["jws_verified"] = False
        cases.append(("jws", not_jws, "transport_not_verified"))
        wrong_key = self.arguments(self.observation(1))
        wrong_key["transport"]["jws_key_id"] = "another-key"
        cases.append(("key", wrong_key, "signing_key_mismatch"))
        wrong_digest = self.arguments(self.observation(1))
        wrong_digest["transport"]["canonical_payload_sha256"] = "e" * 64
        cases.append(
            ("digest", wrong_digest, "artifact_payload_binding_mismatch")
        )
        forged_signature = self.arguments(
            self.observation(1),
            signing_key=SIGNING_KEY_B,
        )
        cases.append(
            ("forged-signature", forged_signature, "artifact_signature_invalid")
        )
        for name, arguments, code in cases:
            with self.subTest(name=name):
                with self.assertRaises(InfrastructureIngestRejected) as error:
                    self.authority.ingest(
                        arguments,
                        broker_operation_id=str(uuid.uuid4()),
                        broker_peer_uid=os.geteuid(),
                        broker_account_id="infrastructure-ingress",
                    )
                self.assertEqual(error.exception.code, code)
        self.assertEqual(
            self.audit_codes(),
            [code for _name, _arguments, code in cases],
        )
        with CoordinatorStore.open_read_only(self.database) as store:
            with store.read_transaction() as connection:
                evidence = list(
                    connection.execute(
                        """
                        SELECT signature_verified, evidence_available,
                               signed_envelope_sha256
                        FROM infrastructure_ingest_audit
                        ORDER BY audit_sequence
                        """
                    )
                )
        self.assertTrue(evidence)
        self.assertTrue(
            all(
                int(row["signature_verified"]) == 0
                and int(row["evidence_available"]) == 0
                and row["signed_envelope_sha256"] is None
                for row in evidence
            )
        )

    def test_prepublication_rejection_replay_and_conflict_are_durable(self) -> None:
        operation_id = str(uuid.uuid4())
        forged = self.arguments(
            self.observation(1),
            signing_key=SIGNING_KEY_B,
        )
        for _attempt in range(2):
            with self.assertRaises(InfrastructureIngestRejected) as rejected:
                self.authority.ingest(
                    copy.deepcopy(forged),
                    broker_operation_id=operation_id,
                    broker_peer_uid=os.geteuid(),
                    broker_account_id="infrastructure-ingress",
                )
            self.assertEqual(
                rejected.exception.code,
                "artifact_signature_invalid",
            )
        conflicting = self.arguments(
            self.observation(2),
            signing_key=SIGNING_KEY_B,
        )
        with self.assertRaises(InfrastructureIngestRejected) as conflict:
            self.authority.ingest(
                conflicting,
                broker_operation_id=operation_id,
                broker_peer_uid=os.geteuid(),
                broker_account_id="infrastructure-ingress",
            )
        self.assertEqual(conflict.exception.code, "operation_id_conflict")
        self.assertEqual(
            self.audit_codes(),
            ["artifact_signature_invalid", "operation_id_conflict"],
        )

    def test_ps256_spki_round_trip_and_digest_are_mandatory(self) -> None:
        normalized = normalize_ps256_spki(
            SPKI_A,
            SPKI_A_SHA256,
            code="invalid_enrollment",
        )
        self.assertEqual(normalized["jws_algorithm"], "PS256")
        self.assertEqual(normalized["jws_spki_der_base64"], SPKI_A)
        self.assertEqual(normalized["jws_spki_sha256"], SPKI_A_SHA256)
        self.assertEqual(normalized["rsa_modulus_bits"], 3072)
        self.assertEqual(normalized["rsa_public_exponent"], 65537)

        with self.assertRaises(InfrastructureValidationError) as digest_error:
            normalize_ps256_spki(
                SPKI_A,
                SPKI_B_SHA256,
                code="invalid_enrollment",
            )
        self.assertEqual(digest_error.exception.code, "invalid_enrollment")
        self.assertIn("does not match", digest_error.exception.message)

        with self.assertRaises(InfrastructureValidationError) as der_error:
            normalize_ps256_spki(
                SPKI_A[:-2] + "AA",
                SPKI_A_SHA256,
                code="invalid_enrollment",
            )
        self.assertEqual(der_error.exception.code, "invalid_enrollment")
        self.assertIn("canonical PS256 RSA SPKI", der_error.exception.message)

        with self.assertRaises(InfrastructureValidationError) as weak_key:
            normalize_ps256_spki(
                SPKI_RSA_2048,
                SPKI_RSA_2048_SHA256,
                code="invalid_enrollment",
            )
        self.assertIn("3072 through 8192", weak_key.exception.message)

        wrong_exponent_der = base64.b64decode(SPKI_A)
        self.assertTrue(wrong_exponent_der.endswith(bytes.fromhex("0203010001")))
        wrong_exponent_der = wrong_exponent_der[:-1] + b"\x03"
        wrong_exponent_spki = base64.b64encode(wrong_exponent_der).decode(
            "ascii"
        )
        wrong_exponent_sha256 = hashlib.sha256(
            wrong_exponent_der
        ).hexdigest()
        with self.assertRaises(InfrastructureValidationError) as exponent:
            normalize_ps256_spki(
                wrong_exponent_spki,
                wrong_exponent_sha256,
                code="invalid_enrollment",
            )
        self.assertIn("exactly 65537", exponent.exception.message)

        even_modulus_der = bytearray(base64.b64decode(SPKI_A))
        self.assertTrue(even_modulus_der.endswith(bytes.fromhex("0203010001")))
        even_modulus_der[-6] &= 0xFE
        even_modulus_bytes = bytes(even_modulus_der)
        with self.assertRaises(InfrastructureValidationError) as even_modulus:
            normalize_ps256_spki(
                base64.b64encode(even_modulus_bytes).decode("ascii"),
                hashlib.sha256(even_modulus_bytes).hexdigest(),
                code="invalid_enrollment",
            )
        self.assertIn("modulus must be odd", even_modulus.exception.message)

    def test_artifact_write_failure_removes_private_temporary_file(self) -> None:
        payload = f"write-failure-{uuid.uuid4()}".encode("ascii")
        with mock.patch(
            "devcoordinator.infrastructure_artifacts.os.write",
            side_effect=OSError("injected write failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected write failure"):
                stage_signed_envelope(
                    self.ingress_staging_root,
                    payload,
                )
        self.assertEqual(
            list(self.ingress_staging_root.rglob("*.tmp")),
            [],
        )

    def test_wrong_key_same_kid_is_rejected_by_generation_material(self) -> None:
        shared_kid = "shared-human-readable-kid"
        # Generation one already exists with SPKI A; exact replay may not
        # replace its key ID. Use a fresh agent so two overlapping generations
        # can intentionally share one display key ID while remaining bound to
        # distinct immutable SPKI digests.
        second_agent = _uuid(30)
        self.authority.provision_agent(
            agent_id=second_agent,
            host_id=self.host_id,
        )
        self.authority.provision_certificate(
            agent_id=second_agent,
            certificate_generation=1,
            certificate_fingerprint_sha256="d" * 64,
            jws_key_id=shared_kid,
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_B,
            jws_spki_sha256=SPKI_B_SHA256,
            valid_from_epoch=self.now - 60,
            valid_until_epoch=self.now + 7200,
        )
        self.authority.provision_certificate(
            agent_id=second_agent,
            certificate_generation=2,
            certificate_fingerprint_sha256="e" * 64,
            jws_key_id=shared_kid,
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_C,
            jws_spki_sha256=SPKI_C_SHA256,
            valid_from_epoch=self.now - 30,
            valid_until_epoch=self.now + 10800,
        )
        context_one = self.authority.verification_context(
            {
                "certificate_fingerprint_sha256": "d" * 64,
                "certificate_generation": 1,
            }
        )
        context_two = self.authority.verification_context(
            {
                "certificate_fingerprint_sha256": "e" * 64,
                "certificate_generation": 2,
            }
        )
        self.assertEqual(context_one["jws_key_id"], shared_kid)
        self.assertEqual(context_two["jws_key_id"], shared_kid)
        self.assertEqual(context_one["jws_spki_sha256"], SPKI_B_SHA256)
        self.assertEqual(context_two["jws_spki_sha256"], SPKI_C_SHA256)
        self.assertNotEqual(
            context_one["jws_spki_sha256"],
            context_two["jws_spki_sha256"],
        )

        document = self.observation(1)
        document["agent_id"] = second_agent
        arguments = self.arguments(
            document,
            generation=1,
            fingerprint="d" * 64,
            key_id=shared_kid,
            spki_sha256=SPKI_C_SHA256,
        )
        with self.assertRaises(InfrastructureIngestRejected) as wrong_key:
            self.authority.ingest(
                arguments,
                broker_operation_id=str(uuid.uuid4()),
                broker_peer_uid=os.geteuid(),
                broker_account_id="infrastructure-ingress",
            )
        self.assertEqual(
            wrong_key.exception.code,
            "signing_key_material_mismatch",
        )

    def test_signing_key_cannot_be_reused_across_agents_or_generations(self) -> None:
        second_agent = _uuid(31)
        self.authority.provision_agent(
            agent_id=second_agent,
            host_id=self.host_id,
        )
        with self.assertRaisesRegex(
            InfrastructureObservationError,
            "signing keys cannot be reused",
        ):
            self.authority.provision_certificate(
                agent_id=second_agent,
                certificate_generation=1,
                certificate_fingerprint_sha256="d" * 64,
                jws_key_id="cross-agent-reuse",
                jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
                jws_spki_der_base64=SPKI_A,
                jws_spki_sha256=SPKI_A_SHA256,
                valid_from_epoch=self.now,
                valid_until_epoch=(
                    self.now
                    + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
                ),
            )
        with self.assertRaisesRegex(
            InfrastructureObservationError,
            "signing keys cannot be reused",
        ):
            self.authority.provision_certificate(
                agent_id=self.agent_id,
                certificate_generation=2,
                certificate_fingerprint_sha256="e" * 64,
                jws_key_id="cross-generation-reuse",
                jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
                jws_spki_der_base64=SPKI_A,
                jws_spki_sha256=SPKI_A_SHA256,
                valid_from_epoch=self.now,
                valid_until_epoch=(
                    self.now
                    + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
                ),
            )
        with CoordinatorStore.open_read_only(self.database) as store:
            self.assertEqual(
                int(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM infrastructure_agent_certificates"
                    ).fetchone()[0]
                ),
                1,
            )

    def test_certificate_validity_and_overlap_bounds_are_exact(self) -> None:
        second_agent = _uuid(32)
        self.authority.provision_agent(
            agent_id=second_agent,
            host_id=self.host_id,
        )
        valid_from = self.now
        with self.assertRaises(InfrastructureValidationError) as too_long:
            self.authority.provision_certificate(
                agent_id=second_agent,
                certificate_generation=1,
                certificate_fingerprint_sha256="d" * 64,
                jws_key_id="thirty-days-plus-one",
                jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
                jws_spki_der_base64=SPKI_B,
                jws_spki_sha256=SPKI_B_SHA256,
                valid_from_epoch=valid_from,
                valid_until_epoch=(
                    valid_from
                    + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
                    + 1
                ),
            )
        self.assertIn("must not exceed 30 days", too_long.exception.message)

        first_valid_until = (
            valid_from + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
        )
        self.authority.provision_certificate(
            agent_id=second_agent,
            certificate_generation=1,
            certificate_fingerprint_sha256="d" * 64,
            jws_key_id="thirty-days",
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_B,
            jws_spki_sha256=SPKI_B_SHA256,
            valid_from_epoch=valid_from,
            valid_until_epoch=first_valid_until,
        )

        overlap_too_long_from = (
            first_valid_until
            - INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS
            - 1
        )
        with self.assertRaisesRegex(
            InfrastructureObservationError,
            "more than 72 hours",
        ):
            self.authority.provision_certificate(
                agent_id=second_agent,
                certificate_generation=2,
                certificate_fingerprint_sha256="e" * 64,
                jws_key_id="overlap-seventy-two-hours-plus-one",
                jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
                jws_spki_der_base64=SPKI_C,
                jws_spki_sha256=SPKI_C_SHA256,
                valid_from_epoch=overlap_too_long_from,
                valid_until_epoch=(
                    overlap_too_long_from
                    + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
                ),
            )

        overlap_boundary_from = (
            first_valid_until
            - INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS
        )
        accepted = self.authority.provision_certificate(
            agent_id=second_agent,
            certificate_generation=2,
            certificate_fingerprint_sha256="e" * 64,
            jws_key_id="overlap-seventy-two-hours",
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_C,
            jws_spki_sha256=SPKI_C_SHA256,
            valid_from_epoch=overlap_boundary_from,
            valid_until_epoch=(
                overlap_boundary_from
                + INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
            ),
        )
        self.assertEqual(
            accepted["valid_until_epoch"] - accepted["valid_from_epoch"],
            INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS,
        )

    def test_unknown_future_and_oversized_reports_retain_last_snapshot(self) -> None:
        accepted = self.ingest(self.observation(1))

        unknown = self.observation(2, captured_offset=1)
        unknown["schema"] = "spectre.infrastructure.observation.v999"
        self.seal(unknown)
        with self.assertRaises(InfrastructureIngestRejected) as unknown_error:
            self.ingest(unknown)
        self.assertEqual(
            unknown_error.exception.code, "unsupported_observation_schema"
        )

        future = self.observation(2, captured_offset=301)
        with self.assertRaises(InfrastructureIngestRejected) as future_error:
            self.ingest(future)
        self.assertEqual(future_error.exception.code, "captured_at_in_future")

        oversized = self.observation(2, captured_offset=1)
        oversized["padding"] = "x" * MAX_OBSERVATION_BYTES
        with self.assertRaises(InfrastructureIngestRejected) as oversized_error:
            self.ingest(oversized)
        self.assertEqual(oversized_error.exception.code, "observation_oversized")

        fractional = self.observation(2, captured_offset=1)
        fractional["captured_at"] = "2026-07-29T10:00:01.000001Z"
        with self.assertRaises(InfrastructureIngestRejected) as fractional_error:
            self.ingest(fractional)
        self.assertEqual(fractional_error.exception.code, "invalid_observation")

        projection = self.authority.read_projection(
            {"rejection_limit_per_host": 10}
        )
        host = projection["hosts"][0]
        self.assertEqual(host["accepted_observation_id"], accepted["observation_id"])
        self.assertEqual(host["current_vm_count"], 2)
        self.assertEqual(
            [item["code"] for item in reversed(host["recent_rejections"])],
            [
                "unsupported_observation_schema",
                "captured_at_in_future",
                "observation_oversized",
                "invalid_observation",
            ],
        )

    def test_revoked_and_expired_certificate_generations_are_audited(self) -> None:
        self.authority.provision_certificate(
            agent_id=self.agent_id,
            certificate_generation=2,
            certificate_fingerprint_sha256="b" * 64,
            jws_key_id="spectre-agent-generation-2",
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_B,
            jws_spki_sha256=SPKI_B_SHA256,
            valid_from_epoch=self.now - 120,
            valid_until_epoch=self.now - 1,
        )
        with self.assertRaises(InfrastructureIngestRejected) as expired:
            self.ingest(
                self.observation(1),
                generation=2,
                fingerprint="b" * 64,
                key_id="spectre-agent-generation-2",
                spki_sha256=SPKI_B_SHA256,
            )
        self.assertEqual(expired.exception.code, "certificate_expired")

        self.authority.provision_certificate(
            agent_id=self.agent_id,
            certificate_generation=3,
            certificate_fingerprint_sha256="c" * 64,
            jws_key_id="spectre-agent-generation-3",
            jws_algorithm=INFRASTRUCTURE_JWS_ALGORITHM,
            jws_spki_der_base64=SPKI_C,
            jws_spki_sha256=SPKI_C_SHA256,
            valid_from_epoch=self.now - 120,
            valid_until_epoch=self.now + 7200,
        )
        self.authority.revoke_certificate(
            agent_id=self.agent_id,
            certificate_generation=3,
            reason="test revocation",
        )
        with self.assertRaises(InfrastructureIngestRejected) as revoked:
            self.ingest(
                self.observation(1),
                generation=3,
                fingerprint="c" * 64,
                key_id="spectre-agent-generation-3",
                spki_sha256=SPKI_C_SHA256,
            )
        self.assertEqual(revoked.exception.code, "certificate_revoked")
        self.assertEqual(
            self.audit_codes(), ["certificate_expired", "certificate_revoked"]
        )

    def test_terminal_operation_replay_reauthorizes_and_refreshes_contact(self) -> None:
        operation_id = str(uuid.uuid4())
        observation = self.observation(1)
        arguments = self.arguments(observation)
        accepted = self.authority.ingest(
            arguments,
            broker_operation_id=operation_id,
            broker_peer_uid=os.geteuid(),
            broker_account_id="infrastructure-ingress",
        )
        original_result = canonical_json(accepted)

        self.now += 5
        restarted = InfrastructureObservationAuthority(
            self.database,
            clock=lambda: self.now,
            ingress_staging_root=self.ingress_staging_root,
            broker_artifact_root=self.broker_artifact_root,
        )
        replayed = restarted.ingest(
            arguments,
            broker_operation_id=operation_id,
            broker_peer_uid=os.geteuid(),
            broker_account_id="infrastructure-ingress",
        )
        self.assertEqual(canonical_json(replayed), original_result)
        refreshed_contact = utc_timestamp(self.now)
        self.assertEqual(
            restarted.read_projection({})["hosts"][0]["last_contact_at"],
            refreshed_contact,
        )

        def set_enrollment_state(
            *,
            agent_enabled: int | None = None,
            host_scope_sha256: str | None = None,
        ) -> None:
            with CoordinatorStore.open(self.database) as store:
                with store.immediate_transaction(
                    revision_kind="state", check_invariants=False
                ) as connection:
                    if host_scope_sha256 is not None:
                        connection.execute(
                            """
                            UPDATE infrastructure_hosts
                            SET scope_sha256 = ?, updated_at = ?
                            WHERE host_id = ?
                            """,
                            (
                                host_scope_sha256,
                                utc_timestamp(self.now),
                                self.host_id,
                            ),
                        )
                    if agent_enabled is not None:
                        connection.execute(
                            """
                            UPDATE infrastructure_observer_agents
                            SET enabled = ?, updated_at = ?
                            WHERE agent_id = ?
                            """,
                            (
                                agent_enabled,
                                utc_timestamp(self.now),
                                self.agent_id,
                            ),
                        )

        for label, expected_code, state in (
            ("disabled", "enrollment_disabled", {"agent_enabled": 0}),
            (
                "scope-changed",
                "enrollment_scope_stale",
                {"host_scope_sha256": "f" * 64},
            ),
        ):
            with self.subTest(label=label):
                self.now += 1
                set_enrollment_state(**state)
                with self.assertRaises(InfrastructureIngestRejected) as rejected:
                    restarted.ingest(
                        arguments,
                        broker_operation_id=operation_id,
                        broker_peer_uid=os.geteuid(),
                        broker_account_id="infrastructure-ingress",
                    )
                self.assertEqual(rejected.exception.code, expected_code)
                if label == "disabled":
                    set_enrollment_state(agent_enabled=1)
                else:
                    set_enrollment_state(host_scope_sha256=self.scope_sha256)

        self.now += 1
        self.authority.revoke_certificate(
            agent_id=self.agent_id,
            certificate_generation=1,
            reason="replay authorization regression",
        )
        with self.assertRaises(InfrastructureIngestRejected) as revoked:
            restarted.ingest(
                arguments,
                broker_operation_id=operation_id,
                broker_peer_uid=os.geteuid(),
                broker_account_id="infrastructure-ingress",
            )
        self.assertEqual(revoked.exception.code, "certificate_revoked")

        with CoordinatorStore.open_read_only(self.database) as store:
            with store.read_transaction() as connection:
                operation = connection.execute(
                    """
                    SELECT outcome, result_json
                    FROM infrastructure_ingest_operations
                    WHERE broker_operation_id = ?
                    """,
                    (operation_id,),
                ).fetchone()
                contact = connection.execute(
                    """
                    SELECT last_contact_at
                    FROM infrastructure_observer_agents
                    WHERE agent_id = ?
                    """,
                    (self.agent_id,),
                ).fetchone()
                audit_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM infrastructure_ingest_audit
                        WHERE broker_operation_id = ?
                        """,
                        (operation_id,),
                    ).fetchone()[0]
                )
        self.assertEqual(operation["outcome"], "accepted")
        self.assertEqual(
            canonical_json(json.loads(str(operation["result_json"]))),
            original_result,
        )
        self.assertEqual(contact["last_contact_at"], refreshed_contact)
        self.assertEqual(audit_count, 1)

    def test_unknown_certificate_claim_is_audited_but_not_host_attributed(self) -> None:
        with self.assertRaises(InfrastructureIngestRejected) as rejected:
            self.ingest(
                self.observation(1),
                generation=99,
                fingerprint="d" * 64,
                key_id="unknown-key",
            )
        self.assertEqual(rejected.exception.code, "certificate_not_enrolled")
        with CoordinatorStore.open_read_only(self.database) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT host_id, agent_id, claimed_host_id, claimed_agent_id
                    FROM infrastructure_ingest_audit
                    """
                ).fetchone()
        self.assertIsNone(row["host_id"])
        self.assertIsNone(row["agent_id"])
        self.assertEqual(row["claimed_host_id"], self.host_id)
        self.assertEqual(row["claimed_agent_id"], self.agent_id)
        self.assertEqual(
            self.authority.read_projection(
                {"rejection_limit_per_host": 10}
            )["hosts"][0]["recent_rejections"],
            [],
        )

    def test_concurrent_duplicate_and_sequence_races_are_atomic(self) -> None:
        duplicate_operation = str(uuid.uuid4())
        duplicate_arguments = self.observation(1)
        barrier = threading.Barrier(8)
        lock = threading.Lock()
        duplicate_results: list[dict] = []
        duplicate_errors: list[BaseException] = []

        def replay_same_operation() -> None:
            try:
                barrier.wait(timeout=5)
                result = self.ingest(
                    copy.deepcopy(duplicate_arguments),
                    operation_id=duplicate_operation,
                )
                with lock:
                    duplicate_results.append(result)
            except BaseException as error:
                with lock:
                    duplicate_errors.append(error)

        threads = [threading.Thread(target=replay_same_operation) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(duplicate_errors, [])
        self.assertEqual(len(duplicate_results), 8)
        self.assertEqual(
            {item["observation_id"] for item in duplicate_results},
            {duplicate_arguments["observation_id"]},
        )
        self.assertEqual(self.audit_codes(), [None])

        duplicate_observation = self.observation(2, captured_offset=1)
        observation_barrier = threading.Barrier(2)
        observation_results: list[dict] = []
        observation_errors: list[InfrastructureIngestRejected] = []

        def race_duplicate_observation() -> None:
            try:
                observation_barrier.wait(timeout=5)
                result = self.ingest(copy.deepcopy(duplicate_observation))
                with lock:
                    observation_results.append(result)
            except InfrastructureIngestRejected as error:
                with lock:
                    observation_errors.append(error)

        duplicate_threads = [
            threading.Thread(target=race_duplicate_observation) for _ in range(2)
        ]
        for thread in duplicate_threads:
            thread.start()
        for thread in duplicate_threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in duplicate_threads))
        self.assertEqual(len(observation_results), 1)
        self.assertEqual(len(observation_errors), 1)
        self.assertEqual(observation_errors[0].code, "observation_replay")

        race_barrier = threading.Barrier(2)
        race_results: list[dict] = []
        race_errors: list[InfrastructureIngestRejected] = []

        def race_sequence(document: dict) -> None:
            try:
                race_barrier.wait(timeout=5)
                result = self.ingest(document)
                with lock:
                    race_results.append(result)
            except InfrastructureIngestRejected as error:
                with lock:
                    race_errors.append(error)

        racers = [
            threading.Thread(
                target=race_sequence,
                args=(self.observation(3, captured_offset=2),),
            )
            for _ in range(2)
        ]
        for thread in racers:
            thread.start()
        for thread in racers:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in racers))
        self.assertEqual(len(race_results), 1)
        self.assertEqual(len(race_errors), 1)
        self.assertEqual(race_errors[0].code, "sequence_out_of_order")
        self.assertEqual(
            self.audit_codes(),
            [
                None,
                None,
                "observation_replay",
                None,
                "sequence_out_of_order",
            ],
        )

    def test_operation_replay_is_durable_and_conflicting_reuse_is_audited(self) -> None:
        operation_id = str(uuid.uuid4())
        observation = self.observation(1)
        accepted = self.ingest(observation, operation_id=operation_id)
        replacement = InfrastructureObservationAuthority(
            self.database,
            clock=lambda: self.now,
            ingress_staging_root=self.ingress_staging_root,
            broker_artifact_root=self.broker_artifact_root,
        )
        replay = replacement.ingest(
            self.arguments(copy.deepcopy(observation)),
            broker_operation_id=operation_id,
            broker_peer_uid=os.geteuid(),
            broker_account_id="infrastructure-ingress",
        )
        self.assertEqual(replay, accepted)
        with self.assertRaises(InfrastructureIngestRejected) as conflict:
            self.ingest(
                self.observation(2, captured_offset=1),
                operation_id=operation_id,
            )
        self.assertEqual(conflict.exception.code, "operation_id_conflict")
        self.assertEqual(self.audit_codes(), [None, "operation_id_conflict"])
        projection = self.authority.read_projection(
            {"rejection_limit_per_host": 10}
        )
        self.assertEqual(
            projection["hosts"][0]["accepted_observation_id"],
            accepted["observation_id"],
        )

    def test_root_admin_requests_are_atomic_receipted_and_conflict_safe(self) -> None:
        admin_database = (
            Path(self.temporary.name) / "admin" / "coordinator.sqlite3"
        )
        with CoordinatorStore.open(admin_database):
            pass
        authority = InfrastructureObservationAuthority(
            admin_database,
            expected_uid=0,
            clock=lambda: self.now,
        )

        def request(action: str, payload: dict) -> dict:
            return {
                "schema": "spectre.infrastructure.admin.v1",
                "request_id": str(uuid.uuid4()),
                "action": action,
                "payload": payload,
            }

        cell_request = request(
            "cell.provision",
            {
                "cell_id": self.cell_id,
                "name": "SPECTRE laboratory",
                "region": "lab",
                "classification_label": "test-only",
            },
        )
        host_request = request(
            "host.provision",
            {
                "host_id": self.host_id,
                "cell_id": self.cell_id,
                "display_name": "Hyper-V laboratory",
                "failure_domain_label": (
                    "single host; loss stops the whole laboratory"
                ),
                "approved_virtual_machines": [
                    {"vm_id": self.vm_b, "role": "hub"},
                    {"vm_id": self.vm_a, "role": "ingress"},
                ],
            },
        )
        agent_request = request(
            "agent.provision",
            {"agent_id": self.agent_id, "host_id": self.host_id},
        )
        certificate_request = request(
            "certificate.provision",
            {
                "agent_id": self.agent_id,
                "certificate_generation": 1,
                "certificate_fingerprint_sha256": "f" * 64,
                "jws_key_id": "admin-enrolled-generation-1",
                "jws_algorithm": "PS256",
                "jws_spki_der_base64": SPKI_A,
                "jws_spki_sha256": SPKI_A_SHA256,
                "valid_from_epoch": self.now - 60,
                "valid_until_epoch": self.now + 7200,
            },
        )
        revoke_request = request(
            "certificate.revoke",
            {
                "agent_id": self.agent_id,
                "certificate_generation": 1,
                "reason": "fixture rotation complete",
            },
        )
        receipts = [
            authority.administer(item, operator_uid=0)
            for item in (
                cell_request,
                host_request,
                agent_request,
                certificate_request,
                revoke_request,
            )
        ]
        self.assertTrue(all(not item["replayed"] for item in receipts))
        self.assertTrue(
            all(item["authority_schema_version"] == 14 for item in receipts)
        )
        self.assertEqual(
            receipts[3]["result"]["jws_spki_sha256"],
            SPKI_A_SHA256,
        )

        with CoordinatorStore.open_read_only(admin_database) as store:
            with store.read_transaction() as connection:
                revision_before = int(
                    connection.execute(
                        """
                        SELECT state_revision FROM schema_metadata
                        WHERE singleton = 1
                        """
                    ).fetchone()[0]
                )
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM infrastructure_admin_receipts"
                        ).fetchone()[0]
                    ),
                    5,
                )
        duplicate_key_request = request(
            "certificate.provision",
            {
                "agent_id": self.agent_id,
                "certificate_generation": 2,
                "certificate_fingerprint_sha256": "e" * 64,
                "jws_key_id": "admin-reused-generation-2",
                "jws_algorithm": "PS256",
                "jws_spki_der_base64": SPKI_A,
                "jws_spki_sha256": SPKI_A_SHA256,
                "valid_from_epoch": self.now,
                "valid_until_epoch": self.now + 7200,
            },
        )
        with self.assertRaisesRegex(
            InfrastructureObservationError,
            "signing keys cannot be reused",
        ):
            authority.administer(duplicate_key_request, operator_uid=0)
        with CoordinatorStore.open_read_only(admin_database) as store:
            self.assertEqual(
                int(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM infrastructure_admin_receipts"
                    ).fetchone()[0]
                ),
                5,
            )
        replay = authority.administer(cell_request, operator_uid=0)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["result"], receipts[0]["result"])
        with CoordinatorStore.open_read_only(admin_database) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    int(
                        connection.execute(
                            """
                            SELECT state_revision FROM schema_metadata
                            WHERE singleton = 1
                            """
                        ).fetchone()[0]
                    ),
                    revision_before,
                )

        conflicting = copy.deepcopy(cell_request)
        conflicting["payload"]["name"] = "Different identity"
        with self.assertRaisesRegex(
            InfrastructureObservationError,
            "admin_request_conflict",
        ):
            authority.administer(conflicting, operator_uid=0)
        with self.assertRaises(PermissionError):
            authority.administer(
                {
                    **request(
                        "cell.provision",
                        {
                            "cell_id": _uuid(50),
                            "name": "forbidden",
                            "region": None,
                            "classification_label": None,
                        },
                    ),
                },
                operator_uid=1000,
            )
        leaking = copy.deepcopy(certificate_request)
        leaking["request_id"] = str(uuid.uuid4())
        leaking["payload"]["private_key"] = "never accepted"
        with self.assertRaises(InfrastructureValidationError):
            authority.administer(leaking, operator_uid=0)
        with CoordinatorStore.open(admin_database) as store:
            with self.assertRaisesRegex(
                Exception,
                "infrastructure admin receipts are immutable",
            ):
                with store.immediate_transaction(
                    revision_kind=None,
                    check_invariants=False,
                ) as connection:
                    connection.execute(
                        """
                        UPDATE infrastructure_admin_receipts
                        SET result_json = '{}'
                        WHERE request_id = ?
                        """,
                        (cell_request["request_id"],),
                    )

    def test_new_boot_must_start_at_one_and_retired_boot_cannot_return(self) -> None:
        self.ingest(self.observation(1))
        new_boot = _uuid(5)
        with self.assertRaises(InfrastructureIngestRejected) as invalid_start:
            self.ingest(
                self.observation(
                    2, boot_id=new_boot, captured_offset=1
                )
            )
        self.assertEqual(
            invalid_start.exception.code, "new_boot_sequence_invalid"
        )
        self.ingest(
            self.observation(1, boot_id=new_boot, captured_offset=1)
        )
        third_boot = _uuid(6)
        self.ingest(
            self.observation(1, boot_id=third_boot, captured_offset=2)
        )
        with self.assertRaises(InfrastructureIngestRejected) as retired:
            self.ingest(
                self.observation(2, boot_id=new_boot, captured_offset=3)
            )
        self.assertEqual(retired.exception.code, "agent_boot_replay")

    def test_broker_service_principal_acl_is_fixed_scope_and_operation_exact(self) -> None:
        persistence = BrokerPersistence(self.database)
        persistence.replace_infrastructure_service_access(
            uid=os.geteuid(),
            account_id="infrastructure-service",
            operations={
                BrokerOperation.INFRASTRUCTURE_INGEST,
                BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
            },
            valid_until_epoch=int(time.time()) + 3600,
        )
        backend = StoreBackedMutationBackend(
            persistence,
            object(),
            infrastructure_ingress_staging_root=self.ingress_staging_root,
            infrastructure_broker_artifact_root=self.broker_artifact_root,
        )
        service = BrokerService(
            StoreBackedAuthorizer(persistence),
            SerializedMutationWriter(backend),
        )
        peer = PeerCredentials(
            uid=os.geteuid(), gid=os.getegid(), pid=os.getpid()
        )
        generation = persistence.database_generation()
        ingest_request = BrokerRequest.create(
            account_id="infrastructure-service",
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            resource_id=INFRASTRUCTURE_INGEST_RESOURCE_ID,
            operation=BrokerOperation.INFRASTRUCTURE_INGEST,
            arguments=self.arguments(self.observation(1)),
            authority_generation=generation,
            repository_generation=0,
        )
        accepted = service.reply_for_document(peer, ingest_request.to_wire())
        self.assertTrue(accepted["ok"], accepted)
        self.authority.revoke_certificate(
            agent_id=self.agent_id,
            certificate_generation=1,
            reason="same-process broker replay regression",
        )
        revoked_replay = service.reply_for_document(
            peer, ingest_request.to_wire()
        )
        self.assertFalse(revoked_replay["ok"])
        self.assertEqual(
            revoked_replay["error"]["code"], "certificate_revoked"
        )

        denied_read = BrokerRequest.create(
            account_id="infrastructure-service",
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            resource_id=INFRASTRUCTURE_READ_RESOURCE_ID,
            operation=BrokerOperation.INFRASTRUCTURE_READ,
            arguments={},
            authority_generation=generation,
            repository_generation=0,
        )
        reply = service.reply_for_document(peer, denied_read.to_wire())
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "operation_access_denied")

        wrong_scope = {
            **denied_read.to_wire(),
            "resource_id": INFRASTRUCTURE_INGEST_RESOURCE_ID,
        }
        persistence.replace_infrastructure_service_access(
            uid=os.geteuid(),
            account_id="infrastructure-service",
            operations={BrokerOperation.INFRASTRUCTURE_READ},
            valid_until_epoch=int(time.time()) + 3600,
        )
        wrong_reply = service.reply_for_document(peer, wrong_scope)
        self.assertFalse(wrong_reply["ok"])
        self.assertEqual(wrong_reply["error"]["code"], "resource_access_denied")
        read_reply = service.reply_for_document(peer, denied_read.to_wire())
        self.assertTrue(read_reply["ok"], read_reply)
        self.assertEqual(
            read_reply["result"]["hosts"][0]["host_id"], self.host_id
        )

        replay_ingest = BrokerRequest.create(
            account_id="infrastructure-service",
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            resource_id=INFRASTRUCTURE_INGEST_RESOURCE_ID,
            operation=BrokerOperation.INFRASTRUCTURE_INGEST,
            arguments=self.arguments(self.observation(2, captured_offset=1)),
            authority_generation=generation,
            repository_generation=0,
        )
        denied = service.reply_for_document(peer, replay_ingest.to_wire())
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "operation_access_denied")

        persistence.replace_infrastructure_service_access(
            uid=os.geteuid(),
            account_id="infrastructure-service",
            operations={
                BrokerOperation.INFRASTRUCTURE_INGEST,
                BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT
            },
            valid_until_epoch=int(time.time()) + 3600,
        )
        verification_request = BrokerRequest.create(
            account_id="infrastructure-service",
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            resource_id=INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID,
            operation=BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
            arguments={
                "certificate_fingerprint_sha256": "a" * 64,
                "certificate_generation": 1,
            },
            authority_generation=generation,
            repository_generation=0,
        )
        verified = service.reply_for_document(
            peer, verification_request.to_wire()
        )
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(
            verified["result"]["jws_spki_sha256"],
            SPKI_A_SHA256,
        )
        self.assertEqual(
            set(verified["result"]),
            {
                "schema",
                "certificate_fingerprint_sha256",
                "certificate_generation",
                "jws_key_id",
                "jws_algorithm",
                "jws_spki_der_base64",
                "jws_spki_sha256",
                "agent_id",
                "host_id",
                "cell_id",
                "assigned_scope_sha256",
                "host_scope_sha256",
                "valid_from_epoch",
                "valid_until_epoch",
                "revoked",
                "revoked_at",
                "revocation_reason",
                "agent_enabled",
                "host_enabled",
                "cell_enabled",
                "scope_current",
                "valid_at_lookup",
                "eligible_at_lookup",
                "lookup_epoch",
            },
        )
        wrong_verification_scope = {
            **verification_request.to_wire(),
            "resource_id": INFRASTRUCTURE_READ_RESOURCE_ID,
        }
        wrong_verification_reply = service.reply_for_document(
            peer, wrong_verification_scope
        )
        self.assertFalse(wrong_verification_reply["ok"])
        self.assertEqual(
            wrong_verification_reply["error"]["code"],
            "resource_access_denied",
        )

    def test_reader_access_receipt_grant_expiry_disable_and_restart(self) -> None:
        reader_uid = 20_001
        reader_account = "console-infrastructure-reader"
        now_epoch = int(time.time())
        valid_until = now_epoch + 600
        persistence = BrokerPersistence(self.database)

        def access_request(
            action: str,
            *,
            request_id: str | None = None,
        ) -> dict[str, object]:
            payload: dict[str, object] = {
                "service_account": "console-reader-fixture",
                "uid": reader_uid,
                "account_id": reader_account,
            }
            if action == "reader.replace":
                payload["valid_until_epoch"] = valid_until
            return {
                "schema": "spectre.infrastructure.reader-access.v1",
                "request_id": request_id or str(uuid.uuid4()),
                "action": action,
                "payload": payload,
            }

        replace = access_request("reader.replace")
        receipt = persistence.administer_infrastructure_reader_access(
            replace,
            operator_uid=0,
            now_epoch=now_epoch,
        )
        self.assertEqual(
            receipt["result"]["operations"],
            ["infrastructure.read"],
        )
        replayed = persistence.administer_infrastructure_reader_access(
            replace,
            operator_uid=0,
            now_epoch=now_epoch + 1,
        )
        self.assertTrue(replayed["replayed"])
        self.assertEqual(replayed["result_sha256"], receipt["result_sha256"])

        backend = StoreBackedMutationBackend(
            persistence,
            object(),
            infrastructure_ingress_staging_root=self.ingress_staging_root,
            infrastructure_broker_artifact_root=self.broker_artifact_root,
        )

        def service_for(current: BrokerPersistence) -> BrokerService:
            return BrokerService(
                StoreBackedAuthorizer(current),
                SerializedMutationWriter(backend),
            )

        peer = PeerCredentials(uid=reader_uid, gid=reader_uid, pid=123)
        generation = persistence.database_generation()

        def wire(
            *,
            account_id: str = reader_account,
            project_id: str = INFRASTRUCTURE_BROKER_PROJECT_ID,
        ) -> dict[str, object]:
            return BrokerRequest.create(
                account_id=account_id,
                project_id=project_id,
                resource_id=INFRASTRUCTURE_READ_RESOURCE_ID,
                operation=BrokerOperation.INFRASTRUCTURE_READ,
                arguments={
                    "after_host_id": None,
                    "host_limit": 1,
                    "vm_limit_per_host": 1,
                    "rejection_limit_per_host": 0,
                },
                authority_generation=generation,
                repository_generation=0,
            ).to_wire()

        service = service_for(persistence)
        allowed = service.reply_for_document(peer, wire())
        self.assertTrue(allowed["ok"], allowed)
        self.assertEqual(allowed["result"]["hosts"][0]["host_id"], self.host_id)
        wrong_account = service.reply_for_document(
            peer,
            wire(account_id="another-account"),
        )
        self.assertFalse(wrong_account["ok"])
        self.assertEqual(
            wrong_account["error"]["code"],
            "cross_account_access_denied",
        )
        with self.assertRaises(BrokerError) as wrong_scope:
            wire(project_id="another-project")
        self.assertEqual(
            wrong_scope.exception.code,
            "resource_access_denied",
        )

        with mock.patch(
            "devcoordinator.broker_persistence.time.time",
            return_value=valid_until,
        ):
            expired = service.reply_for_document(peer, wire())
        self.assertFalse(expired["ok"])
        self.assertEqual(
            expired["error"]["code"],
            "service_enrollment_expired",
        )

        disabled = persistence.administer_infrastructure_reader_access(
            access_request("reader.disable"),
            operator_uid=0,
            now_epoch=now_epoch + 2,
        )
        self.assertEqual(disabled["result"]["status"], "disabled")
        restarted = BrokerPersistence(self.database)
        denied_after_restart = service_for(restarted).reply_for_document(
            peer,
            wire(),
        )
        self.assertFalse(denied_after_restart["ok"])
        self.assertEqual(
            denied_after_restart["error"]["code"],
            "operation_access_denied",
        )

        with CoordinatorStore.open(self.database) as store:
            with self.assertRaises(sqlite3.IntegrityError):
                with store.immediate_transaction(
                    revision_kind=None,
                    check_invariants=False,
                ) as connection:
                    connection.execute(
                        """
                        UPDATE broker_infrastructure_reader_access_receipts
                        SET created_at = created_at
                        WHERE request_id = ?
                        """,
                        (replace["request_id"],),
                    )

    def test_broker_acl_upgrade_preserves_old_grants_and_adds_context(self) -> None:
        persistence = BrokerPersistence(self.database)
        persistence.initialize()
        legacy_uid = os.geteuid() + 200_000
        persistence.provision_principal(
            uid=legacy_uid,
            account_id="legacy-infrastructure-reader",
        )
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction(
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                connection.execute(
                    "DROP INDEX broker_infrastructure_service_acl_active"
                )
                connection.execute(
                    "DROP TABLE broker_infrastructure_service_acl"
                )
                connection.execute(
                    """
                    CREATE TABLE broker_infrastructure_service_acl (
                        uid INTEGER NOT NULL,
                        account_id TEXT NOT NULL,
                        operation TEXT NOT NULL CHECK(operation IN (
                            'infrastructure.ingest',
                            'infrastructure.read'
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
                    CREATE INDEX broker_infrastructure_service_acl_active
                    ON broker_infrastructure_service_acl(
                        operation, enabled, valid_until_epoch, uid
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO broker_infrastructure_service_acl(
                        uid, account_id, operation, enabled,
                        valid_until_epoch, updated_at
                    ) VALUES (?, ?, 'infrastructure.read', 1, ?, ?)
                    """,
                    (
                        legacy_uid,
                        "legacy-infrastructure-reader",
                        self.now + 3600,
                        utc_timestamp(self.now),
                    ),
                )

        persistence.initialize()
        with CoordinatorStore.open_read_only(self.database) as store:
            sql = str(
                store.connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'broker_infrastructure_service_acl'
                    """
                ).fetchone()[0]
            )
            self.assertIn("infrastructure.verification_context", sql)
            self.assertEqual(
                dict(
                    store.connection.execute(
                        """
                        SELECT account_id, operation, enabled,
                               valid_until_epoch
                        FROM broker_infrastructure_service_acl
                        WHERE uid = ?
                        """,
                        (legacy_uid,),
                    ).fetchone()
                ),
                {
                    "account_id": "legacy-infrastructure-reader",
                    "operation": "infrastructure.read",
                    "enabled": 1,
                    "valid_until_epoch": self.now + 3600,
                },
            )

    def test_infrastructure_service_uid_rejects_broader_authority_both_ways(self) -> None:
        persistence = BrokerPersistence(self.database)
        now = utc_timestamp(self.now)
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction(
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES ('local-host', 'machine-fixture', 'linux',
                              'fixture.local', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name,
                        state, generation, created_at, updated_at
                    ) VALUES ('repo-fixture', 'local-host', '/srv/fixture',
                              'Fixture', 'active', 0, ?, ?)
                    """,
                    (now, now),
                )

        broad_uid = 42420
        persistence.provision_principal(
            uid=broad_uid,
            account_id="broad-account",
        )
        persistence.provision_repository_enrollment(
            uid=broad_uid,
            repo_id="repo-fixture",
            account_id="broad-account",
            issued_at=now,
            valid_until_epoch=self.now + 3600,
        )
        with self.assertRaises(BrokerError) as broad_error:
            persistence.replace_infrastructure_service_access(
                uid=broad_uid,
                account_id="broad-account",
                operations={
                    BrokerOperation.INFRASTRUCTURE_INGEST,
                    BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
                },
                valid_until_epoch=self.now + 3600,
            )
        self.assertEqual(
            broad_error.exception.code,
            "infrastructure_principal_not_dedicated",
        )

        dedicated_uid = 42421
        persistence.replace_infrastructure_service_access(
            uid=dedicated_uid,
            account_id="dedicated-infrastructure",
            operations={
                BrokerOperation.INFRASTRUCTURE_INGEST,
                BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
            },
            valid_until_epoch=self.now + 3600,
        )
        with self.assertRaises(BrokerError) as dedicated_error:
            persistence.provision_repository_enrollment(
                uid=dedicated_uid,
                repo_id="repo-fixture",
                account_id="dedicated-infrastructure",
                issued_at=now,
                valid_until_epoch=self.now + 3600,
            )
        self.assertEqual(
            dedicated_error.exception.code,
            "infrastructure_principal_is_dedicated",
        )

        # The authenticated Console/API reader is non-mutating and may retain
        # its existing repository authority in this lab. Its grant remains
        # exact, expiring, and read-only.
        persistence.replace_infrastructure_service_access(
            uid=broad_uid,
            account_id="broad-account",
            operations={BrokerOperation.INFRASTRUCTURE_READ},
            valid_until_epoch=self.now + 3600,
        )
        read_request = BrokerRequest.create(
            account_id="broad-account",
            project_id=INFRASTRUCTURE_BROKER_PROJECT_ID,
            resource_id=INFRASTRUCTURE_READ_RESOURCE_ID,
            operation=BrokerOperation.INFRASTRUCTURE_READ,
            arguments={},
            authority_generation=persistence.database_generation(),
            repository_generation=0,
        )
        authorized_read = persistence.authorize(
            PeerCredentials(uid=broad_uid, gid=42420, pid=42420),
            read_request,
        )
        self.assertEqual(
            authorized_read.request.operation,
            BrokerOperation.INFRASTRUCTURE_READ,
        )
        with self.assertRaises(BrokerError) as mixed_ingress:
            persistence.replace_infrastructure_service_access(
                uid=42422,
                account_id="mixed-infrastructure",
                operations={
                    BrokerOperation.INFRASTRUCTURE_INGEST,
                    BrokerOperation.INFRASTRUCTURE_READ,
                },
                valid_until_epoch=self.now + 3600,
            )
        self.assertEqual(
            mixed_ingress.exception.code,
            "infrastructure_ingress_scope_mixed",
        )
        with self.assertRaises(BrokerError) as partial_ingress:
            persistence.replace_infrastructure_service_access(
                uid=42423,
                account_id="partial-infrastructure",
                operations={
                    BrokerOperation.INFRASTRUCTURE_VERIFICATION_CONTEXT,
                },
                valid_until_epoch=self.now + 3600,
            )
        self.assertEqual(
            partial_ingress.exception.code,
            "infrastructure_ingress_scope_mixed",
        )


if __name__ == "__main__":
    unittest.main()
