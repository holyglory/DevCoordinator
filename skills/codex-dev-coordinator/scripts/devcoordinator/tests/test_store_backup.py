"""Transactional backup/export/restore tests for normalized SQLite stores."""

from __future__ import annotations

from contextlib import closing
import json
import hashlib
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.store import AccountStore, StoreError, canonical_json, utc_timestamp
from devcoordinator.store_backup import (
    create_store_backup,
    create_store_export,
    inspect_store_backup,
    inspect_store_export,
    recover_corrupt_store_backup,
    restore_store_backup,
    restore_store_export,
)
import devcoordinator.store_backup as store_backup_module


def canonical_test_temp_base() -> Path:
    """Return a writable canonical base outside any host/user Git marker."""

    candidates = (
        os.environ.get("DEVCOORDINATOR_TEST_TMP_ROOT"),
        pwd.getpwuid(os.geteuid()).pw_dir,
        tempfile.gettempdir(),
    )
    for raw in dict.fromkeys(value for value in candidates if value):
        base = Path(str(raw)).resolve()
        if not base.is_dir() or not os.access(base, os.W_OK | os.X_OK):
            continue
        cursor = base
        while not ((cursor / ".git").exists() or (cursor / ".git").is_symlink()):
            if cursor.parent == cursor:
                return base
            cursor = cursor.parent
    raise RuntimeError("no writable test temp root exists outside every Git worktree")


class StoreBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir=canonical_test_temp_base()
        )
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "account-store"
        self.database = self.home / "coordinator.sqlite3"
        self.backups = self.root / "backups"
        self.safety = self.root / "safety"
        self._seed_store()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_store(self) -> None:
        now = utc_timestamp()
        with AccountStore.open_default(self.home) as store:
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
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo', 'host', '/repo', 'before', 'active', 0, ?, ?)
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

    def _display_name(self) -> str:
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                return str(
                    connection.execute(
                        "SELECT display_name FROM repositories WHERE repo_id='repo'"
                    ).fetchone()[0]
                )

    def _mutate_display_name(self, value: str) -> None:
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repositories SET display_name=?, updated_at=? WHERE repo_id='repo'",
                    (value, utc_timestamp()),
                )

    def _rewrite_export(self, exported, mutate) -> None:
        artifact = Path(exported["export"])
        document = json.loads(artifact.read_text(encoding="utf-8"))
        mutate(document)
        payload = (canonical_json(document) + "\n").encode("utf-8")
        artifact.write_bytes(payload)
        os.chmod(artifact, 0o600)
        manifest_path = Path(exported["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifact_size_bytes"] = len(payload)
        manifest["artifact_sha256"] = hashlib.sha256(payload).hexdigest()
        if "schema_fingerprint" in document:
            manifest["schema_fingerprint"] = document["schema_fingerprint"]
        manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)

    def test_output_root_inside_explicit_git_worktree_is_rejected(self) -> None:
        repository = self.root / "operator-repository"
        repository.mkdir()
        (repository / ".git").mkdir()

        with self.assertRaisesRegex(ValueError, "backup root must be outside Git"):
            create_store_backup(
                self.database,
                repository / "backups",
                store_role="account",
            )
        self.assertFalse(
            (repository / "backups").exists(),
            "the Git-contained output root must be rejected before it is created",
        )

    def test_verified_backup_restores_normalized_state_and_retains_safety_backup(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("after")

        restored = restore_store_backup(
            self.database,
            backup["manifest"],
            self.safety,
            store_role="account",
            confirm=True,
        )

        self.assertEqual(restored["status"], "restored")
        self.assertEqual(self._display_name(), "before")
        safety = inspect_store_backup(restored["safety_backup"]["manifest"])
        safety_connection = __import__("sqlite3").connect(
            str(safety["artifact"]), isolation_level=None
        )
        try:
            safety_name = safety_connection.execute(
                "SELECT display_name FROM repositories WHERE repo_id='repo'"
            ).fetchone()[0]
        finally:
            safety_connection.close()
        self.assertEqual(safety_name, "after")

    def test_corrupt_store_requires_explicit_forensic_recovery(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        corrupt_bytes = b"not a sqlite database\x00forensic fixture\n"
        self.database.write_bytes(corrupt_bytes)
        os.chmod(self.database, 0o600)

        with self.assertRaisesRegex(RuntimeError, "broker store-recover"):
            restore_store_backup(
                self.database,
                backup["manifest"],
                self.safety,
                store_role="account",
                confirm=True,
            )
        self.assertEqual(self.database.read_bytes(), corrupt_bytes)

        recovered = recover_corrupt_store_backup(
            self.database,
            backup["manifest"],
            self.root / "forensic",
            store_role="account",
            confirm=True,
        )

        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(self._display_name(), "before")
        forensic = recovered["forensic_snapshot"]
        database_capture = next(
            item for item in forensic["files"] if item["kind"] == "database"
        )
        captured = Path(database_capture["artifact"])
        self.assertEqual(captured.read_bytes(), corrupt_bytes)
        self.assertEqual(
            database_capture["sha256"], hashlib.sha256(corrupt_bytes).hexdigest()
        )
        self.assertEqual(captured.stat().st_mode & 0o777, 0o600)
        forensic_manifest = json.loads(
            Path(forensic["manifest"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            forensic_manifest["type"], "devcoordinator-corrupt-store-forensic"
        )

    def test_open_store_blocks_restore_before_target_change(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("busy-current")
        with AccountStore.open_default(self.home):
            with self.assertRaisesRegex(StoreError, "busy"):
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                    timeout_seconds=0.05,
                )
        self.assertEqual(self._display_name(), "busy-current")

    def test_post_replace_verification_failure_rolls_back_normalized_sqlite(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("rollback-current")
        real_validate = store_backup_module._validate_sqlite
        real_replace = os.replace
        replaced_target = False
        failed_once = False

        def replace(source, target):
            nonlocal replaced_target
            result = real_replace(source, target)
            if Path(target) == self.database:
                replaced_target = True
            return result

        def validate(path):
            nonlocal failed_once
            if Path(path) == self.database and replaced_target and not failed_once:
                failed_once = True
                raise ValueError("injected post-replace verification failure")
            return real_validate(path)

        with mock.patch.object(store_backup_module.os, "replace", replace), mock.patch.object(
            store_backup_module, "_validate_sqlite", validate
        ):
            with self.assertRaisesRegex(RuntimeError, "rollback succeeded"):
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )
        self.assertTrue(failed_once)
        self.assertEqual(self._display_name(), "rollback-current")

    def test_post_replace_chmod_failure_rolls_back_normalized_sqlite(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("chmod-current")
        real_replace = os.replace
        real_chmod = os.chmod
        publications = 0
        failed = False

        def replace(source, target):
            nonlocal publications
            result = real_replace(source, target)
            if Path(target) == self.database:
                publications += 1
            return result

        def chmod(path, mode):
            nonlocal failed
            if Path(path) == self.database and publications == 1 and not failed:
                failed = True
                raise OSError("injected chmod-after-replace failure")
            return real_chmod(path, mode)

        with mock.patch.object(store_backup_module.os, "replace", replace), mock.patch.object(
            store_backup_module.os, "chmod", chmod
        ):
            with self.assertRaisesRegex(RuntimeError, "rollback succeeded"):
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )
        self.assertTrue(failed)
        self.assertEqual(self._display_name(), "chmod-current")

    def test_post_replace_directory_fsync_failure_rolls_back_normalized_sqlite(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("fsync-current")
        real_replace = os.replace
        real_fsync_directory = store_backup_module._fsync_directory
        publications = 0
        failed = False

        def replace(source, target):
            nonlocal publications
            result = real_replace(source, target)
            if Path(target) == self.database:
                publications += 1
            return result

        def fsync_directory(path):
            nonlocal failed
            if Path(path) == self.database.parent and publications == 1 and not failed:
                failed = True
                raise OSError("injected fsync-after-replace failure")
            return real_fsync_directory(path)

        with mock.patch.object(store_backup_module.os, "replace", replace), mock.patch.object(
            store_backup_module, "_fsync_directory", fsync_directory
        ):
            with self.assertRaisesRegex(RuntimeError, "rollback succeeded"):
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )
        self.assertTrue(failed)
        self.assertEqual(self._display_name(), "fsync-current")

    def test_primary_and_rollback_failures_are_both_reported(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("combined-current")
        real_replace = os.replace
        real_chmod = os.chmod
        real_copy = store_backup_module._copy_private_source
        publications = 0

        def replace(source, target):
            nonlocal publications
            result = real_replace(source, target)
            if Path(target) == self.database:
                publications += 1
            return result

        def chmod(path, mode):
            if Path(path) == self.database and publications == 1:
                raise OSError("primary chmod failure")
            return real_chmod(path, mode)

        def copy(source, destination, *, expected_uid):
            if ".rollback-" in Path(destination).name:
                raise OSError("rollback copy failure")
            return real_copy(source, destination, expected_uid=expected_uid)

        with mock.patch.object(store_backup_module.os, "replace", replace), mock.patch.object(
            store_backup_module.os, "chmod", chmod
        ), mock.patch.object(store_backup_module, "_copy_private_source", copy):
            with self.assertRaises(RuntimeError) as raised:
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )
        self.assertIn("primary chmod failure", str(raised.exception))
        self.assertIn("rollback copy failure", str(raised.exception))

    def test_restore_refuses_symlink_target_before_raw_sqlite_open(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        real_database = self.home / "real.sqlite3"
        self.database.rename(real_database)
        self.database.symlink_to(real_database)
        with mock.patch.object(
            store_backup_module.sqlite3,
            "connect",
            side_effect=AssertionError("raw SQLite open must not occur"),
        ):
            with self.assertRaises((PermissionError, ValueError)):
                restore_store_backup(
                    self.database,
                    backup["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )

    def test_tampered_backup_is_rejected_without_target_mutation(self) -> None:
        backup = create_store_backup(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("untouched")
        artifact = Path(backup["backup"])
        artifact.write_bytes(artifact.read_bytes() + b"tamper")
        os.chmod(artifact, 0o600)
        with self.assertRaisesRegex(ValueError, "artifact"):
            restore_store_backup(
                self.database,
                backup["manifest"],
                self.safety,
                store_role="account",
                confirm=True,
            )
        self.assertEqual(self._display_name(), "untouched")

    def test_private_logical_export_contains_service_broker_control_tables(self) -> None:
        persistence = BrokerPersistence(self.database, expected_uid=os.geteuid())
        persistence.provision_principal(uid=os.geteuid(), account_id="account")
        exported = create_store_export(
            self.database, self.backups, store_role="service"
        )
        artifact = Path(exported["export"])
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        document = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertTrue(document["restorable"])
        self.assertIn("repositories", document["tables"])
        self.assertIn("broker_acl_principals", document["tables"])
        self.assertEqual(
            document["tables"]["broker_acl_principals"][0]["account_id"],
            "account",
        )
        inspected = inspect_store_export(
            exported["manifest"], expected_role="service"
        )
        self.assertEqual(
            inspected["decoded_tables"]["broker_acl_principals"][0]["account_id"],
            "account",
        )

    def test_logical_export_transactionally_imports_and_retains_safety_backup(self) -> None:
        exported = create_store_export(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("after-export")

        restored = restore_store_export(
            self.database,
            exported["manifest"],
            self.safety,
            store_role="account",
            confirm=True,
        )

        self.assertEqual(restored["status"], "imported")
        self.assertEqual(self._display_name(), "before")
        safety = inspect_store_backup(restored["safety_backup"]["manifest"])
        with closing(
            __import__("sqlite3").connect(str(safety["artifact"]))
        ) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT display_name FROM repositories WHERE repo_id='repo'"
                ).fetchone()[0],
                "after-export",
            )

    def test_logical_export_schema_mismatch_is_rejected_before_target_change(self) -> None:
        exported = create_store_export(
            self.database, self.backups, store_role="account"
        )

        def remove_schema_table(document) -> None:
            document["schema"]["tables"].pop("repositories")
            document["schema_fingerprint"] = hashlib.sha256(
                canonical_json(document["schema"]).encode("utf-8")
            ).hexdigest()

        self._rewrite_export(exported, remove_schema_table)
        self._mutate_display_name("unchanged")
        with self.assertRaisesRegex(ValueError, "table set"):
            restore_store_export(
                self.database,
                exported["manifest"],
                self.safety,
                store_role="account",
                confirm=True,
            )
        self.assertEqual(self._display_name(), "unchanged")

    def test_logical_export_post_replace_failure_rolls_back_current_state(self) -> None:
        exported = create_store_export(
            self.database, self.backups, store_role="account"
        )
        self._mutate_display_name("logical-rollback-current")
        real_validate = store_backup_module._validate_sqlite
        real_replace = os.replace
        replaced_target = False
        failed_once = False

        def replace(source, target):
            nonlocal replaced_target
            result = real_replace(source, target)
            if Path(target) == self.database:
                replaced_target = True
            return result

        def validate(path):
            nonlocal failed_once
            if Path(path) == self.database and replaced_target and not failed_once:
                failed_once = True
                raise ValueError("injected logical post-replace failure")
            return real_validate(path)

        with mock.patch.object(store_backup_module.os, "replace", replace), mock.patch.object(
            store_backup_module, "_validate_sqlite", validate
        ):
            with self.assertRaisesRegex(RuntimeError, "rollback succeeded"):
                restore_store_export(
                    self.database,
                    exported["manifest"],
                    self.safety,
                    store_role="account",
                    confirm=True,
                )
        self.assertTrue(failed_once)
        self.assertEqual(self._display_name(), "logical-rollback-current")

    def test_foreign_generation_export_is_rejected_after_safety_backup(self) -> None:
        other_home = self.root / "other-store"
        with AccountStore.open_default(other_home):
            pass
        exported = create_store_export(
            other_home / "coordinator.sqlite3",
            self.backups,
            store_role="account",
        )
        self._mutate_display_name("generation-current")

        with self.assertRaisesRegex(ValueError, "another database generation"):
            restore_store_export(
                self.database,
                exported["manifest"],
                self.safety,
                store_role="account",
                confirm=True,
            )

        self.assertEqual(self._display_name(), "generation-current")
        self.assertTrue(list(self.safety.glob("*.sqlite3")))
        self.assertTrue(list(self.safety.glob("*.manifest.json")))


if __name__ == "__main__":
    unittest.main()
