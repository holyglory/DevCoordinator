from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_store import UniversalTestStore


def _load_repository_cli():
    test_file = Path(__file__).resolve()
    skill_root = test_file.parents[3]
    repository_root = skill_root.parent.parent
    configured_skill = repository_root / "skills" / skill_root.name
    cli_path = repository_root / "scripts" / "migrate_universal_test_history.py"
    try:
        source_tree_matches = configured_skill.samefile(skill_root)
    except OSError:
        source_tree_matches = False
    if not source_tree_matches or not cli_path.is_file():
        raise unittest.SkipTest(
            "fresh-store administrator CLI is unavailable in a standalone skill copy"
        )
    spec = importlib.util.spec_from_file_location(
        "migrate_universal_test_history_fresh_store", cli_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load fresh-store administrator CLI")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION_CLI = _load_repository_cli()


class FreshTestStoreInitializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="universal-test-fresh-initialize-"
        )
        self.root = Path(self.temporary.name)
        self.test_parent = self.root / "testd"
        self.test_parent.mkdir(mode=0o700)
        self.test_path = self.test_parent / "tests.sqlite3"
        self.operation_id = str(uuid.uuid4())
        self.attestation = (
            self.test_parent / f"schema-readiness-{self.operation_id}.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_disposable_history(self) -> str:
        store = UniversalTestStore.create(self.test_path)
        generation = str(store.verify()["store_generation"])
        connection = store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO test_mutation_journal(
                    operation_id, operation_kind, request_fingerprint,
                    result_json, created_at
                ) VALUES (?, 'legacy-history', ?, '{}', 1.0)
                """,
                (str(uuid.uuid4()), "legacy-history-fingerprint"),
            )
            connection.execute("COMMIT")
        finally:
            connection.close()
        return generation

    def test_fresh_initializer_discards_only_test_store_and_attests_schema(self) -> None:
        old_generation = self._seed_disposable_history()
        authority_sentinel = self.root / "authority.sqlite3"
        authority_sentinel.write_bytes(b"authority-must-not-be-opened-or-changed")
        authority_before = authority_sentinel.read_bytes()

        result = MIGRATION_CLI.testd_initialize_fresh_store(
            test_database=self.test_path,
            operation_id=self.operation_id,
            attestation_output=self.attestation,
            expected_test_uid=os.geteuid(),
            confirmation=MIGRATION_CLI.DISCARD_TEST_HISTORY_CONFIRMATION,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "testd-initialize-fresh")
        self.assertEqual(result["branch"], "attested-fresh-v5")
        self.assertTrue(result["discarded_existing"])
        self.assertFalse(result["replayed"])
        self.assertNotEqual(result["store_generation"], old_generation)
        self.assertEqual(authority_sentinel.read_bytes(), authority_before)

        store = UniversalTestStore.open(self.test_path)
        self.assertEqual(store.verify()["schema_version"], 5)
        connection = store._connect(readonly=True)
        try:
            rows = connection.execute(
                """
                SELECT operation_id, operation_kind
                FROM test_mutation_journal ORDER BY operation_id
                """
            ).fetchall()
            counts = tuple(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "test_runs",
                    "test_case_results",
                    "test_failures",
                    "test_artifacts",
                    "test_rollup_hourly",
                    "test_rollup_daily",
                )
            )
        finally:
            connection.close()
        self.assertEqual(
            [(str(row["operation_id"]), str(row["operation_kind"])) for row in rows],
            [(self.operation_id, "schema_readiness_v5")],
        )
        self.assertEqual(counts, (0, 0, 0, 0, 0, 0))

        replay = MIGRATION_CLI.testd_initialize_fresh_store(
            test_database=self.test_path,
            operation_id=self.operation_id,
            attestation_output=self.attestation,
            expected_test_uid=os.geteuid(),
            confirmation=MIGRATION_CLI.DISCARD_TEST_HISTORY_CONFIRMATION,
        )
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["store_generation"], result["store_generation"])

    def test_fresh_initializer_requires_confirmation_before_discard(self) -> None:
        generation = self._seed_disposable_history()
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError,
            "confirmation",
        ):
            MIGRATION_CLI.testd_initialize_fresh_store(
                test_database=self.test_path,
                operation_id=self.operation_id,
                attestation_output=self.attestation,
                expected_test_uid=os.geteuid(),
                confirmation="no",
            )
        self.assertEqual(
            UniversalTestStore.open(self.test_path).verify()["store_generation"],
            generation,
        )

    def test_fresh_initializer_refuses_relaxed_store_files(self) -> None:
        self.test_path.write_bytes(b"not-a-private-test-store")
        self.test_path.chmod(0o644)
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError,
            "private regular files",
        ):
            MIGRATION_CLI.testd_initialize_fresh_store(
                test_database=self.test_path,
                operation_id=self.operation_id,
                attestation_output=self.attestation,
                expected_test_uid=os.geteuid(),
                confirmation=MIGRATION_CLI.DISCARD_TEST_HISTORY_CONFIRMATION,
            )
        self.assertEqual(self.test_path.read_bytes(), b"not-a-private-test-store")

    def test_fresh_initializer_refuses_non_test_store_or_unbound_output(self) -> None:
        protected = self.test_parent / "authority.sqlite3"
        protected.write_bytes(b"authority")
        protected.chmod(0o600)
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError,
            "only the tests.sqlite3",
        ):
            MIGRATION_CLI.testd_initialize_fresh_store(
                test_database=protected,
                operation_id=self.operation_id,
                attestation_output=self.attestation,
                expected_test_uid=os.geteuid(),
                confirmation=MIGRATION_CLI.DISCARD_TEST_HISTORY_CONFIRMATION,
            )
        self.assertEqual(protected.read_bytes(), b"authority")

        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError,
            "operation-bound file",
        ):
            MIGRATION_CLI.testd_initialize_fresh_store(
                test_database=self.test_path,
                operation_id=self.operation_id,
                attestation_output=self.test_parent / "schema-readiness.json",
                expected_test_uid=os.geteuid(),
                confirmation=MIGRATION_CLI.DISCARD_TEST_HISTORY_CONFIRMATION,
            )


if __name__ == "__main__":
    unittest.main()
