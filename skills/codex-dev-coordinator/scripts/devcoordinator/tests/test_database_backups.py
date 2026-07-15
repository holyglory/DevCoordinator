"""Deterministic tests for the normalized PostgreSQL backup registry."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import devcoordinator.database_backups as backup_registry

from devcoordinator.database_backups import (
    inspect_database_backup,
    record_successful_restore,
    register_backup_in_existing_account_store,
    upsert_database_backup,
)
from devcoordinator.store import AccountStore, CoordinatorStore, utc_timestamp


class DatabaseBackupRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / "store" / "coordinator.sqlite3"
        self.artifact = self.root / "backups" / "app.dump"
        self.artifact.parent.mkdir(mode=0o700)
        self.artifact.write_bytes(b"verified pg_dump fixture\n")
        os.chmod(self.artifact, 0o600)
        self.container_id = "a" * 64
        self.manifest_path = Path(f"{self.artifact}.manifest.json")
        self._write_manifest(verification=None)
        self._seed_store()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self, *, verification: dict | None) -> None:
        checksum = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        manifest = {
            "schema_version": 2,
            "type": "postgres-docker-backup",
            "created_at": "2026-07-15T12:00:00Z",
            "scope": "database",
            "format": "custom",
            "path": str(self.artifact),
            "size": self.artifact.stat().st_size,
            "sha256": checksum,
            "source": {
                "container": {"id": self.container_id, "name": "postgres"},
                "postgres": {"database": "app", "scope": "database"},
            },
            "verification": verification,
        }
        self.manifest_path.write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        os.chmod(self.manifest_path, 0o600)

    def _seed_store(self) -> None:
        now = utc_timestamp()
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(host_id, machine_fingerprint, platform,
                                      hostname, created_at, updated_at)
                    VALUES ('host', 'machine', 'test', 'test', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, created_at, updated_at
                    ) VALUES ('source', 'host', '/source', '/source/store', ?,
                              'imported', ?, ?)
                    """,
                    (os.geteuid(), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo', 'host', '/repo', 'repo', 'active', 0, ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES ('repo', 'installed', 0, 0, 'test', ?)
                    """,
                    (now,),
                )
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES ('engine', 'host', 'default', 'available', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES ('container', 'engine', ?, 'postgres', ?, ?)
                    """,
                    (self.container_id, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO control_bindings(
                        binding_id, repo_id, resource_kind, resource_id,
                        source_id, capability, provenance, authority_state,
                        priority, generation, created_at, updated_at
                    ) VALUES ('control', 'repo', 'container', 'container',
                              'source', 'lifecycle', 'test', 'authoritative',
                              100, 0, ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind, host_resource_id,
                        immutable_fingerprint, control_binding_id, created_at
                    ) VALUES ('membership', 'repo', 'container', 'container',
                              'immutable', 'control', ?)
                    """,
                    (now,),
                )
                connection.execute(
                    """
                    INSERT INTO database_bindings(
                        database_binding_id, docker_resource_id, repo_id,
                        database_name, engine_kind, created_at, updated_at
                    ) VALUES ('database', 'container', 'repo', 'app',
                              'postgresql', ?, ?)
                    """,
                    (now, now),
                )

    def test_real_artifact_updates_verification_and_restore_history(self) -> None:
        descriptor = inspect_database_backup(self.artifact, self.manifest_path)
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            with store.immediate_transaction() as connection:
                backup_id = upsert_database_backup(connection, descriptor)
        checksum = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self._write_manifest(
            verification={
                "ok": True,
                "mode": "test_restore",
                "sha256": checksum,
                "verified_at": "2026-07-15T12:05:00Z",
                "verification_target": "scratch_database",
                "catalog_signature": {
                    "tables": 2,
                    "sequences": 1,
                    "views": 0,
                    "functions": 3,
                },
                "container_identity_preflight": {
                    "actual_id": self.container_id,
                    "match": "exact_full",
                },
            }
        )
        verified = inspect_database_backup(self.artifact, self.manifest_path)
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            with store.immediate_transaction() as connection:
                self.assertEqual(upsert_database_backup(connection, verified), backup_id)
                event_id = record_successful_restore(
                    connection,
                    database_backup_id=backup_id,
                    target_container_id=self.container_id,
                    target_database_name="app",
                    result={
                        "restored": str(self.artifact),
                        "database": "app",
                        "scope": "database",
                        "sha256": checksum,
                        "transactional": True,
                        "incoming_verification": {
                            "test_restore": True,
                            "verification_target": "scratch_database",
                            "restore_returncode": 0,
                            "scratch_created": True,
                            "catalog_signature": {
                                "tables": 2,
                                "sequences": 1,
                                "views": 0,
                                "functions": 3,
                            },
                        },
                        "restored_catalog_signature": {
                            "tables": 2,
                            "sequences": 1,
                            "views": 0,
                            "functions": 3,
                        },
                        "container_identity_preflights": [
                            {"actual_id": self.container_id, "phase": phase}
                            for phase in ("selection", "post-incoming", "final")
                        ],
                    },
                )
            graph = store.inventory_v2()

        backup = graph["database_backups"][0]
        self.assertEqual(backup["database_binding_id"], "database")
        self.assertEqual(backup["repo_id"], "repo")
        self.assertEqual(backup["source_id"], "source")
        self.assertEqual(backup["verification_status"], "strong")
        self.assertEqual(backup["restore_count"], 1)
        self.assertEqual(graph["database_restore_events"][0]["restore_event_id"], event_id)

    def test_successful_backup_action_registers_in_an_existing_account_store(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CODEX_AGENT_COORDINATOR_HOME": str(self.database.parent)},
        ):
            registered = register_backup_in_existing_account_store(
                self.artifact, self.manifest_path
            )
        self.assertEqual(registered["status"], "registered")
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            backups = store.inventory_v2()["database_backups"]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["artifact_sha256"], hashlib.sha256(self.artifact.read_bytes()).hexdigest())

    def test_tampered_artifact_is_never_registered(self) -> None:
        self.artifact.write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "size|checksum"):
            inspect_database_backup(self.artifact, self.manifest_path)
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            self.assertEqual(store.inventory_v2()["database_backups"], [])

    def test_symlink_and_foreign_readable_evidence_are_rejected(self) -> None:
        alias = self.root / "artifact-alias.dump"
        alias.symlink_to(self.artifact)
        with self.assertRaises(PermissionError):
            inspect_database_backup(alias, self.manifest_path)

        os.chmod(self.artifact, 0o644)
        with self.assertRaisesRegex(PermissionError, "0600"):
            inspect_database_backup(self.artifact, self.manifest_path)

    def test_claimed_strong_verification_requires_real_strong_evidence(self) -> None:
        checksum = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self._write_manifest(
            verification={
                "ok": True,
                "mode": "test_restore",
                "sha256": checksum,
                "verified_at": "2026-07-15T12:05:00Z",
            }
        )
        with self.assertRaisesRegex(ValueError, "strong-verification"):
            inspect_database_backup(self.artifact, self.manifest_path)

    def test_path_replacement_during_hashing_is_rejected(self) -> None:
        replacement = self.artifact.parent / "replacement.dump"
        replacement.write_bytes(self.artifact.read_bytes())
        os.chmod(replacement, 0o600)
        real_read = os.read
        replaced = False

        def replace_after_first_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            chunk = real_read(descriptor, size)
            if chunk and not replaced:
                replaced = True
                os.replace(replacement, self.artifact)
            return chunk

        with mock.patch.object(backup_registry.os, "read", replace_after_first_read):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                inspect_database_backup(self.artifact, self.manifest_path)
        self.assertTrue(replaced)

    @unittest.skipUnless(os.geteuid() == 0, "ownership mutation requires root")
    def test_wrong_owner_is_rejected_before_read(self) -> None:
        os.chown(self.artifact, 1, -1)
        with self.assertRaisesRegex(PermissionError, "owned by uid"):
            inspect_database_backup(
                self.artifact, self.manifest_path, expected_uid=0
            )

    def test_restore_ledger_rejects_an_unproved_success_mapping(self) -> None:
        descriptor = inspect_database_backup(self.artifact, self.manifest_path)
        with AccountStore.open(self.database, expected_uid=os.geteuid()) as store:
            with store.immediate_transaction() as connection:
                backup_id = upsert_database_backup(connection, descriptor)
                with self.assertRaisesRegex(ValueError, "restore result lacks"):
                    record_successful_restore(
                        connection,
                        database_backup_id=backup_id,
                        target_container_id=self.container_id,
                        target_database_name="app",
                        result={"transactional": True},
                    )
            self.assertEqual(store.inventory_v2()["database_restore_events"], [])


if __name__ == "__main__":
    unittest.main()
