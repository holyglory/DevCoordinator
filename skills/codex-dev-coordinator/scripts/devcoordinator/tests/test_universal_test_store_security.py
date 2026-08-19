from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

from devcoordinator.universal_test_store import (
    TestStoreContractError,
    TestStoreConflict,
    TestStoreSecurityError,
    UniversalTestStore,
)


class UniversalTestStoreSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="test-store-security-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "tests.sqlite3"
        self.store = UniversalTestStore.create(self.database)

    def test_created_store_uses_private_creation_defaults(self) -> None:
        metadata = self.database.lstat()
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.database}{suffix}")
            if sidecar.exists():
                self.assertEqual(sidecar.lstat().st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(sidecar.lstat().st_mode), 0o600)

    def test_open_accepts_shared_parent_and_database_modes(self) -> None:
        self.root.chmod(0o775)
        self.database.chmod(0o664)

        reopened = UniversalTestStore.open(self.database)

        self.assertEqual(reopened.verify()["schema_version"], 6)

    def test_open_rejects_symlink_database(self) -> None:
        real = self.root / "real.sqlite3"
        self.database.rename(real)
        self.database.symlink_to(real)
        with self.assertRaisesRegex(TestStoreSecurityError, "symbolic link"):
            UniversalTestStore.open(self.database)

    def test_open_rejects_non_regular_existing_sidecar(self) -> None:
        database = self.root / "invalid-sidecar.sqlite3"
        database.write_bytes(b"")
        sidecar = Path(f"{database}-wal")
        sidecar.mkdir()
        with self.assertRaisesRegex(
            TestStoreSecurityError, "sidecar is not a regular file"
        ):
            UniversalTestStore.open(database)

    def test_open_accepts_shared_modes_on_live_sqlite_sidecars(self) -> None:
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE test_store_metadata SET created_at = created_at WHERE singleton = 1"
        )
        sidecars = [Path(f"{self.database}{suffix}") for suffix in ("-wal", "-shm")]
        self.assertTrue(all(sidecar.exists() for sidecar in sidecars))
        for sidecar in sidecars:
            sidecar.chmod(0o664)

        reopened = UniversalTestStore.open(self.database)

        self.assertEqual(reopened.verify()["schema_version"], 6)

    def test_expected_uid_is_compatibility_only(self) -> None:
        reopened = UniversalTestStore.open(
            self.database, expected_uid=os.geteuid() + 1
        )

        self.assertEqual(reopened.expected_uid, os.geteuid())

    def test_open_rejects_nonboolean_integrity_mode(self) -> None:
        with self.assertRaisesRegex(
            TestStoreContractError, "verify_integrity must be boolean"
        ):
            UniversalTestStore.open(
                self.database, verify_integrity=1  # type: ignore[arg-type]
            )

    def test_verify_writable_begins_and_rolls_back_without_committing(self) -> None:
        connection = mock.Mock()
        with mock.patch.object(self.store, "_connect", return_value=connection):
            self.store.verify_writable()

        self.assertEqual(
            [call.args for call in connection.execute.call_args_list],
            [("BEGIN IMMEDIATE",), ("ROLLBACK",)],
        )
        connection.close.assert_called_once_with()

    def test_verify_writable_classifies_a_read_only_store(self) -> None:
        connection = mock.Mock()
        connection.in_transaction = False
        connection.execute.side_effect = sqlite3.OperationalError(
            "attempt to write a readonly database"
        )
        with mock.patch.object(self.store, "_connect", return_value=connection):
            with self.assertRaisesRegex(TestStoreConflict, "not writable"):
                self.store.verify_writable()

        connection.close.assert_called_once_with()

    def test_verify_writable_classifies_a_database_open_failure(self) -> None:
        with mock.patch.object(
            self.store,
            "_connect",
            side_effect=sqlite3.OperationalError("unable to open database file"),
        ):
            with self.assertRaisesRegex(TestStoreConflict, "not writable"):
                self.store.verify_writable()


if __name__ == "__main__":
    unittest.main()
