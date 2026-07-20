from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from devcoordinator.broker import (
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_cli import add_broker_parser, handle_broker_cli
from devcoordinator.broker_persistence import BrokerPersistence
import devcoordinator.broker_profile_enrollment_migration as migration_module
from devcoordinator.broker_profile_enrollment_migration import (
    ProfileEnrollmentMigrationError,
    ProfileGenerationReconciliationError,
    migrate_protected_profile_enrollments,
    reconcile_protected_profile_repository_generation,
)
from devcoordinator.store import CoordinatorStore, utc_timestamp


ACCOUNT_ID = "account-a"
HOST_ID = "host-a"
REPO_ID = "repo-a"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    groups = parser.add_subparsers(dest="group", required=True)
    add_broker_parser(groups)
    return parser


class ProtectedProfileEnrollmentMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".profile-enrollment-migration-",
            dir=str(Path.home().resolve()),
        )
        self.root = Path(self._temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        self.database = self.root / "store" / "coordinator.sqlite3"
        self.profile = self.root / "client-profiles.json"
        self.rollback_root = self.root / "rollback"
        self.rollback_root.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.now = int(time.time())
        self.issued_at = utc_timestamp(self.now - 60)
        self.valid_until = self.now + 3600

        self.persistence = BrokerPersistence(
            self.database, expected_uid=self.uid
        )
        now_text = utc_timestamp(self.now)
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            self.database_generation = store.metadata.database_generation
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'machine-a', 'test', 'host-a', ?, ?)
                    """,
                    (HOST_ID, now_text, now_text),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Project', 'active', 0, ?, ?)
                    """,
                    (REPO_ID, HOST_ID, str(self.project), now_text, now_text),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation,
                        actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                    """,
                    (REPO_ID, now_text),
                )
        self.persistence.provision_principal(
            uid=self.uid, account_id=ACCOUNT_ID
        )
        self.persistence.grant_repository_read(
            uid=self.uid,
            repo_id=REPO_ID,
            operation=BrokerOperation.REPOSITORY_LIST_REMOVED,
        )
        self._write_profile()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _write_profile(
        self,
        *,
        database_generation: str | None = None,
        repository_enabled: bool = True,
    ) -> None:
        document = {
            "version": 1,
            "service": {
                "socket": "/run/devcoordinator/broker.sock",
                "uid": self.uid,
                "gid": os.getegid(),
                "mode": "0660",
                "database_generation": (
                    self.database_generation
                    if database_generation is None
                    else database_generation
                ),
            },
            "clients": {
                str(self.uid): {
                    "account_id": ACCOUNT_ID,
                    "issued_at": self.issued_at,
                    "valid_until_epoch": self.valid_until,
                    "repositories": [
                        {
                            "canonical_root": str(self.project),
                            "repo_id": REPO_ID,
                            "generation": 0,
                            "servers": {},
                            "containers": {},
                            "compose_definition_id": None,
                            "account_id": ACCOUNT_ID,
                            "enabled": repository_enabled,
                            "issued_at": self.issued_at,
                            "valid_until_epoch": self.valid_until,
                        }
                    ],
                }
            },
        }
        self.profile.write_text(json.dumps(document), encoding="utf-8")
        self.profile.chmod(0o640)

    def _profile_document(self) -> dict[str, object]:
        return json.loads(self.profile.read_text(encoding="utf-8"))

    def _write_profile_document(self, document: dict[str, object]) -> None:
        self.profile.write_text(json.dumps(document), encoding="utf-8")
        self.profile.chmod(0o640)

    def _set_repository_generation(self, generation: int) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repositories SET generation = ? WHERE repo_id = ?",
                    (generation, REPO_ID),
                )

    @staticmethod
    def _test_profile_writer(
        path: Path, document: dict[str, object], *, access_gid: int
    ) -> None:
        del access_gid
        path.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o640)

    def _reconcile(
        self,
        *,
        from_generation: int = 0,
        to_generation: int = 1,
        account_id: str = ACCOUNT_ID,
        writer: object | None = None,
        rollback_root: Path | None = None,
    ) -> tuple[dict[str, object], mock.Mock]:
        publication_lock = mock.MagicMock()
        selected_writer = self._test_profile_writer if writer is None else writer
        with (
            mock.patch.object(
                migration_module,
                "_locked_root_profile",
                return_value=publication_lock,
            ) as lock,
            mock.patch.object(
                migration_module,
                "_atomic_write_root_json",
                side_effect=selected_writer,
            ),
        ):
            result = reconcile_protected_profile_repository_generation(
                database_path=self.database,
                profile_path=self.profile,
                client_uid=self.uid,
                account_id=account_id,
                repo_id=REPO_ID,
                canonical_root=str(self.project),
                from_generation=from_generation,
                to_generation=to_generation,
                rollback_root=(
                    self.rollback_root if rollback_root is None else rollback_root
                ),
                expected_service_uid=self.uid,
                trusted_profile_owner_uid=self.uid,
                trusted_rollback_owner_gid=os.getegid(),
                now_epoch=self.now,
            )
        return result, lock

    def _inventory_request(self) -> BrokerRequest:
        return BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=REPO_ID,
            resource_id=REPO_ID,
            operation=BrokerOperation.INVENTORY_READ,
            authority_generation=self.database_generation,
        )

    def _authorize_inventory(self) -> None:
        self.persistence.authorize(
            PeerCredentials(uid=self.uid, gid=os.getegid(), pid=os.getpid()),
            self._inventory_request(),
        )

    def _migrate(self) -> dict[str, object]:
        return migrate_protected_profile_enrollments(
            database_path=self.database,
            profile_path=self.profile,
            expected_service_uid=self.uid,
            trusted_profile_owner_uid=self.uid,
            now_epoch=self.now,
        )

    def _protected_rows(self) -> dict[str, list[tuple[object, ...]]]:
        tables = (
            "repositories",
            "repository_installations",
            "broker_acl_principals",
            "broker_repository_read_acl",
        )
        with CoordinatorStore.open_read_only(
            self.database, expected_uid=self.uid
        ) as store:
            with store.read_transaction() as connection:
                return {
                    table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                    for table in tables
                }

    def _enrollment(self) -> object:
        with CoordinatorStore.open_read_only(
            self.database, expected_uid=self.uid
        ) as store:
            with store.read_transaction() as connection:
                return connection.execute(
                    """
                    SELECT account_id, enabled, issued_at, valid_until_epoch,
                           enrollment_snapshot_id, grant_snapshot_id
                    FROM broker_repository_enrollments
                    WHERE uid = ? AND repo_id = ?
                    """,
                    (self.uid, REPO_ID),
                ).fetchone()

    def test_legacy_profile_missing_row_fails_before_and_passes_after_migration(
        self,
    ) -> None:
        with self.assertRaises(BrokerError) as before:
            self._authorize_inventory()
        self.assertEqual(before.exception.code, "project_access_denied")

        protected_before = self._protected_rows()
        result = self._migrate()
        self.assertEqual(result["status"], "migrated")
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(result["already_current"], 0)
        self.assertEqual(
            result["mutated_tables"], ["broker_repository_enrollments"]
        )
        self.assertEqual(self._protected_rows(), protected_before)

        enrollment = self._enrollment()
        self.assertIsNotNone(enrollment)
        self.assertEqual(enrollment["account_id"], ACCOUNT_ID)
        self.assertEqual(enrollment["enabled"], 1)
        self.assertEqual(enrollment["issued_at"], self.issued_at)
        self.assertEqual(enrollment["valid_until_epoch"], self.valid_until)
        self.assertIsNone(enrollment["enrollment_snapshot_id"])
        self.assertIsNone(enrollment["grant_snapshot_id"])
        self._authorize_inventory()

        second = self._migrate()
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["already_current"], 1)
        self.assertEqual(second["mutated_tables"], [])

    def test_generation_drift_is_rejected_without_creating_authority(self) -> None:
        self._write_profile(database_generation="different-generation")
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "generation does not match"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_repository_generation_drift_is_rejected_without_authority(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repositories SET generation = 1 WHERE repo_id = ?",
                    (REPO_ID,),
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "repository generation conflicts"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_pre_broker_restart_database_gets_only_the_new_enrollment_schema(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute("DROP TABLE broker_repository_enrollments")
        result = self._migrate()
        self.assertTrue(result["created_enrollment_table"])
        self.assertEqual(result["inserted"], 1)
        self._authorize_inventory()

    def test_migration_rejects_enrollment_schema_without_checks_or_foreign_keys(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute("DROP TABLE broker_repository_enrollments")
                connection.execute(
                    """
                    CREATE TABLE broker_repository_enrollments (
                        uid INTEGER NOT NULL,
                        repo_id TEXT NOT NULL,
                        account_id TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        issued_at TEXT NOT NULL,
                        valid_until_epoch INTEGER NOT NULL,
                        enrollment_snapshot_id TEXT,
                        grant_snapshot_id TEXT,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(uid, repo_id)
                    )
                    """
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "CHECK constraints"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_migration_rejects_enrollment_schema_without_foreign_keys(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute("DROP TABLE broker_repository_enrollments")
                connection.execute(
                    """
                    CREATE TABLE broker_repository_enrollments (
                        uid INTEGER NOT NULL,
                        repo_id TEXT NOT NULL,
                        account_id TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                        issued_at TEXT NOT NULL,
                        valid_until_epoch INTEGER NOT NULL CHECK(valid_until_epoch > 0),
                        enrollment_snapshot_id TEXT,
                        grant_snapshot_id TEXT,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(uid, repo_id),
                        CHECK(
                            (enrollment_snapshot_id IS NULL AND grant_snapshot_id IS NULL)
                            OR
                            (enrollment_snapshot_id IS NOT NULL AND grant_snapshot_id IS NOT NULL)
                        )
                    )
                    """
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "foreign keys"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_migration_rejects_unique_lookup_index_drift(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                connection.execute(
                    "DROP INDEX broker_repository_enrollments_by_repo"
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX broker_repository_enrollments_by_repo
                    ON broker_repository_enrollments(
                        repo_id, enabled, valid_until_epoch
                    )
                    """
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "index properties"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_disabled_principal_is_rejected_without_creating_authority(self) -> None:
        self.persistence.provision_principal(
            uid=self.uid, account_id=ACCOUNT_ID, enabled=False
        )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "principal is disabled"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_missing_acl_evidence_is_rejected_without_creating_authority(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_repository_read_acl WHERE uid = ? AND repo_id = ?",
                    (self.uid, REPO_ID),
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "no existing enabled ACL evidence"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_migration_refuses_expired_client_and_repository_profiles(self) -> None:
        document = self._profile_document()
        client = document["clients"][str(self.uid)]
        client["valid_until_epoch"] = self.now - 1
        client["repositories"][0]["valid_until_epoch"] = self.now - 1
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "expired"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

        document = self._profile_document()
        client = document["clients"][str(self.uid)]
        client["valid_until_epoch"] = self.valid_until
        other = self.root / "current-profile-repository"
        other.mkdir()
        current = json.loads(json.dumps(client["repositories"][0]))
        current.update(
            {
                "canonical_root": str(other),
                "repo_id": "repo-current",
                "valid_until_epoch": self.valid_until,
            }
        )
        client["repositories"].append(current)
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "expired"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_migration_accepts_legacy_repository_expiry_fallback(self) -> None:
        document = self._profile_document()
        repository = document["clients"][str(self.uid)]["repositories"][0]
        for field in (
            "account_id",
            "enabled",
            "issued_at",
            "valid_until_epoch",
        ):
            repository.pop(field)
        self._write_profile_document(document)
        result = self._migrate()
        self.assertEqual(result["inserted"], 1)
        enrollment = self._enrollment()
        self.assertEqual(enrollment["issued_at"], self.issued_at)
        self.assertEqual(enrollment["valid_until_epoch"], self.valid_until)

    def test_migration_refuses_conflicting_enabled_row_without_overwrite(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, updated_at
                    ) VALUES (?, ?, ?, 1, 'different-issued-at', ?, ?)
                    """,
                    (
                        self.uid,
                        REPO_ID,
                        ACCOUNT_ID,
                        self.valid_until + 60,
                        utc_timestamp(self.now),
                    ),
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "conflicts with the protected profile"
        ):
            self._migrate()
        enrollment = self._enrollment()
        self.assertEqual(enrollment["issued_at"], "different-issued-at")
        self.assertEqual(enrollment["valid_until_epoch"], self.valid_until + 60)

    def test_migration_preflight_is_atomic_across_multiple_candidates(self) -> None:
        second_root = self.root / "second-project"
        second_root.mkdir()
        second_repo = "repo-z"
        now_text = utc_timestamp(self.now)
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Second', 'active', 0, ?, ?)
                    """,
                    (second_repo, HOST_ID, str(second_root), now_text, now_text),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation,
                        actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                    """,
                    (second_repo, now_text),
                )
        self.persistence.grant_repository_read(
            uid=self.uid,
            repo_id=second_repo,
            operation=BrokerOperation.REPOSITORY_LIST_REMOVED,
        )
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, updated_at
                    ) VALUES (?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        self.uid,
                        second_repo,
                        ACCOUNT_ID,
                        self.issued_at,
                        self.valid_until,
                        now_text,
                    ),
                )
        document = self._profile_document()
        second = json.loads(
            json.dumps(document["clients"][str(self.uid)]["repositories"][0])
        )
        second.update(
            {"canonical_root": str(second_root), "repo_id": second_repo}
        )
        document["clients"][str(self.uid)]["repositories"].append(second)
        self._write_profile_document(document)

        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "refuses to re-enable"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_migration_refuses_fenced_install_and_principal_account_conflict(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repository_installations SET startup_fenced = 1 WHERE repo_id = ?",
                    (REPO_ID,),
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "not enabled and installed"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repository_installations SET startup_fenced = 0 WHERE repo_id = ?",
                    (REPO_ID,),
                )
        document = self._profile_document()
        document["clients"][str(self.uid)]["account_id"] = "account-b"
        document["clients"][str(self.uid)]["repositories"][0][
            "account_id"
        ] = "account-b"
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "existing broker principal"
        ):
            self._migrate()
        self.assertIsNone(self._enrollment())

    def test_disabled_existing_enrollment_is_never_reenabled(self) -> None:
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, updated_at
                    ) VALUES (?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        self.uid,
                        REPO_ID,
                        ACCOUNT_ID,
                        self.issued_at,
                        self.valid_until,
                        utc_timestamp(self.now),
                    ),
                )
        with self.assertRaisesRegex(
            ProfileEnrollmentMigrationError, "refuses to re-enable"
        ):
            self._migrate()
        self.assertEqual(self._enrollment()["enabled"], 0)

    def test_exact_forward_generation_reconciliation_changes_one_scalar_then_migrates(
        self,
    ) -> None:
        before = self._profile_document()
        self._set_repository_generation(1)

        result, publication_lock = self._reconcile()

        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(result["from_generation"], 0)
        self.assertEqual(result["to_generation"], 1)
        self.assertEqual(result["profile_scalar_changes"], 1)
        self.assertFalse(result["grants_rebuilt"])
        self.assertFalse(result["database_mutated"])
        self.assertRegex(str(result["acl_evidence_digest"]), r"^sha256:[0-9a-f]{64}$")
        publication_lock.assert_called_once_with(
            self.profile, access_gid=os.getegid()
        )
        publication_lock.return_value.__enter__.assert_called_once_with()
        publication_lock.return_value.__exit__.assert_called_once()

        after = self._profile_document()
        expected = json.loads(json.dumps(before))
        expected["clients"][str(self.uid)]["repositories"][0]["generation"] = 1
        self.assertEqual(after, expected)
        rollback = Path(str(result["rollback_profile"]))
        self.assertTrue(rollback.is_file())
        self.assertEqual(
            json.loads(rollback.read_text(encoding="utf-8")), before
        )

        migrated = self._migrate()
        self.assertEqual(migrated["inserted"], 1)
        self._authorize_inventory()

    def test_generation_reconciliation_requires_exact_from_and_to(self) -> None:
        self._set_repository_generation(1)
        before = self.profile.read_bytes()
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "from_generation does not match",
        ):
            self._reconcile(from_generation=2, to_generation=3)
        self.assertEqual(self.profile.read_bytes(), before)

        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "repository generation conflicts",
        ):
            self._reconcile(from_generation=0, to_generation=2)
        self.assertEqual(self.profile.read_bytes(), before)

        with self.assertRaisesRegex(ValueError, "greater than"):
            self._reconcile(from_generation=1, to_generation=1)
        self.assertEqual(self.profile.read_bytes(), before)

    def test_generation_reconciliation_refuses_missing_acl_evidence(self) -> None:
        self._set_repository_generation(1)
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "DELETE FROM broker_repository_read_acl WHERE uid = ? AND repo_id = ?",
                    (self.uid, REPO_ID),
                )
        before = self.profile.read_bytes()
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "no existing enabled ACL evidence",
        ):
            self._reconcile()
        self.assertEqual(self.profile.read_bytes(), before)

    def test_generation_reconciliation_refuses_unsafe_rollback_roots(self) -> None:
        self._set_repository_generation(1)
        before = self.profile.read_bytes()
        self.rollback_root.chmod(0o750)
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "mode 0700"
        ):
            self._reconcile()
        self.assertEqual(self.profile.read_bytes(), before)

        self.rollback_root.chmod(0o700)
        alternate = self.root / "alternate-rollback"
        alternate.mkdir(mode=0o700)
        alias = self.root / "rollback-alias"
        alias.symlink_to(alternate, target_is_directory=True)
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "canonical absolute directory|symlink",
        ):
            self._reconcile(rollback_root=alias)
        self.assertEqual(self.profile.read_bytes(), before)

    def test_generation_reconciliation_preserves_legacy_repository_shape(self) -> None:
        document = self._profile_document()
        repository = document["clients"][str(self.uid)]["repositories"][0]
        for field in (
            "account_id",
            "enabled",
            "issued_at",
            "valid_until_epoch",
        ):
            repository.pop(field)
        self._write_profile_document(document)
        self._set_repository_generation(1)

        result, _lock = self._reconcile()

        self.assertEqual(result["status"], "reconciled")
        published = self._profile_document()
        published_repository = published["clients"][str(self.uid)][
            "repositories"
        ][0]
        self.assertEqual(published_repository["generation"], 1)
        for field in (
            "account_id",
            "enabled",
            "issued_at",
            "valid_until_epoch",
        ):
            self.assertNotIn(field, published_repository)

    def test_generation_publication_corruption_rolls_back_atomically(self) -> None:
        self._set_repository_generation(1)
        original = self._profile_document()
        calls = 0

        def corrupting_writer(
            path: Path, document: dict[str, object], *, access_gid: int
        ) -> None:
            nonlocal calls
            calls += 1
            written = json.loads(json.dumps(document))
            if calls == 1:
                written["clients"][str(self.uid)]["account_id"] = "corrupted"
            self._test_profile_writer(path, written, access_gid=access_gid)

        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "original document was restored",
        ):
            self._reconcile(writer=corrupting_writer)
        self.assertEqual(self._profile_document(), original)
        self.assertEqual(calls, 2)
        backups = tuple(
            self.rollback_root.glob(
                "client-profiles.json.generation-reconcile.*.rollback.json"
            )
        )
        self.assertEqual(len(backups), 1)
        self.assertEqual(
            json.loads(backups[0].read_text(encoding="utf-8")), original
        )

    def test_generation_reconciliation_refuses_duplicate_profile_candidates(self) -> None:
        document = self._profile_document()
        duplicate = json.loads(
            json.dumps(document["clients"][str(self.uid)]["repositories"][0])
        )
        document["clients"][str(self.uid)]["repositories"].append(duplicate)
        self._write_profile_document(document)
        self._set_repository_generation(1)
        before = self.profile.read_bytes()
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "exactly one matching"
        ):
            self._reconcile()
        self.assertEqual(self.profile.read_bytes(), before)

    def test_generation_reconciliation_refuses_expired_client_and_repository(self) -> None:
        self._set_repository_generation(1)
        document = self._profile_document()
        document["clients"][str(self.uid)]["valid_until_epoch"] = self.now - 1
        document["clients"][str(self.uid)]["repositories"][0][
            "valid_until_epoch"
        ] = self.now - 1
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "expired"
        ):
            self._reconcile()

        document = self._profile_document()
        document["clients"][str(self.uid)]["valid_until_epoch"] = self.valid_until
        other = self.root / "other"
        other.mkdir()
        current = json.loads(
            json.dumps(document["clients"][str(self.uid)]["repositories"][0])
        )
        current.update(
            {
                "canonical_root": str(other),
                "repo_id": "repo-current",
                "valid_until_epoch": self.valid_until,
            }
        )
        document["clients"][str(self.uid)]["repositories"].append(current)
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "expired"
        ):
            self._reconcile()

    def test_generation_reconciliation_refuses_fenced_install_and_principal_conflict(
        self,
    ) -> None:
        self._set_repository_generation(1)
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repository_installations SET startup_fenced = 1 WHERE repo_id = ?",
                    (REPO_ID,),
                )
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "not enabled and installed"
        ):
            self._reconcile()

        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repository_installations SET startup_fenced = 0 WHERE repo_id = ?",
                    (REPO_ID,),
                )
        document = self._profile_document()
        document["clients"][str(self.uid)]["account_id"] = "account-b"
        document["clients"][str(self.uid)]["repositories"][0][
            "account_id"
        ] = "account-b"
        self._write_profile_document(document)
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError, "existing broker principal"
        ):
            self._reconcile(account_id="account-b")

    def test_generation_reconciliation_refuses_conflicting_enabled_enrollment(
        self,
    ) -> None:
        self._set_repository_generation(1)
        with CoordinatorStore.open(
            self.database, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO broker_repository_enrollments(
                        uid, repo_id, account_id, enabled, issued_at,
                        valid_until_epoch, updated_at
                    ) VALUES (?, ?, ?, 1, 'different-issued-at', ?, ?)
                    """,
                    (
                        self.uid,
                        REPO_ID,
                        ACCOUNT_ID,
                        self.valid_until,
                        utc_timestamp(self.now),
                    ),
                )
        before = self.profile.read_bytes()
        with self.assertRaisesRegex(
            ProfileGenerationReconciliationError,
            "conflicts with the protected profile",
        ):
            self._reconcile()
        self.assertEqual(self.profile.read_bytes(), before)

    def test_cli_is_root_only_and_holds_lifetime_lock_for_the_migration(self) -> None:
        args = _parser().parse_args(
            [
                "broker",
                "migrate-profile-enrollments",
                "--database",
                "/var/lib/devcoordinator/coordinator.sqlite3",
                "--profile",
                "/etc/devcoordinator/client-profiles.json",
            ]
        )
        expected = {"status": "migrated", "inserted": 1}
        lock = mock.MagicMock()
        with (
            mock.patch(
                "devcoordinator.broker_cli.os.geteuid", return_value=0
            ),
            mock.patch(
                "devcoordinator.broker_cli.exclusive_broker_service_lock",
                return_value=lock,
            ) as service_lock,
            mock.patch(
                "devcoordinator.broker_cli.migrate_protected_profile_enrollments",
                return_value=expected,
            ) as migrate,
        ):
            result = handle_broker_cli(args)
        self.assertEqual(result, expected)
        database = Path("/var/lib/devcoordinator/coordinator.sqlite3")
        service_lock.assert_called_once_with(database)
        migrate.assert_called_once_with(
            database_path=database,
            profile_path=Path("/etc/devcoordinator/client-profiles.json"),
            expected_service_uid=0,
            trusted_profile_owner_uid=0,
        )
        lock.__enter__.assert_called_once_with()
        lock.__exit__.assert_called_once()

        with (
            mock.patch(
                "devcoordinator.broker_cli.os.geteuid", return_value=1000
            ),
            mock.patch(
                "devcoordinator.broker_cli.migrate_protected_profile_enrollments"
            ) as migrate_nonroot,
            self.assertRaisesRegex(PermissionError, "root service administrator"),
        ):
            handle_broker_cli(args)
        migrate_nonroot.assert_not_called()

    def test_reconciliation_cli_is_root_only_and_holds_lifetime_lock(self) -> None:
        args = _parser().parse_args(
            [
                "broker",
                "reconcile-profile-repository-generation",
                "--database",
                "/var/lib/devcoordinator/coordinator.sqlite3",
                "--profile",
                "/etc/devcoordinator/client-profiles.json",
                "--client-uid",
                "1000",
                "--account-id",
                "account-a",
                "--repo-id",
                "repo-a",
                "--canonical-root",
                "/home/DevCoordinator",
                "--from-generation",
                "0",
                "--to-generation",
                "1",
                "--rollback-root",
                "/var/lib/devcoordinator-install/transaction-a",
            ]
        )
        expected = {"status": "reconciled", "profile_scalar_changes": 1}
        lock = mock.MagicMock()
        with (
            mock.patch("devcoordinator.broker_cli.os.geteuid", return_value=0),
            mock.patch(
                "devcoordinator.broker_cli.exclusive_broker_service_lock",
                return_value=lock,
            ) as service_lock,
            mock.patch(
                "devcoordinator.broker_cli.reconcile_protected_profile_repository_generation",
                return_value=expected,
            ) as reconcile,
        ):
            result = handle_broker_cli(args)
        self.assertEqual(result, expected)
        database = Path("/var/lib/devcoordinator/coordinator.sqlite3")
        service_lock.assert_called_once_with(database)
        reconcile.assert_called_once_with(
            database_path=database,
            profile_path=Path("/etc/devcoordinator/client-profiles.json"),
            client_uid=1000,
            account_id="account-a",
            repo_id="repo-a",
            canonical_root="/home/DevCoordinator",
            from_generation=0,
            to_generation=1,
            rollback_root=Path(
                "/var/lib/devcoordinator-install/transaction-a"
            ),
            expected_service_uid=0,
            trusted_profile_owner_uid=0,
            trusted_rollback_owner_gid=0,
        )
        lock.__enter__.assert_called_once_with()
        lock.__exit__.assert_called_once()

        with (
            mock.patch(
                "devcoordinator.broker_cli.os.geteuid", return_value=1000
            ),
            mock.patch(
                "devcoordinator.broker_cli.reconcile_protected_profile_repository_generation"
            ) as nonroot,
            self.assertRaisesRegex(PermissionError, "root service administrator"),
        ):
            handle_broker_cli(args)
        nonroot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
