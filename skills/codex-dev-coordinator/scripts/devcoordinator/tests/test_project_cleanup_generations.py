"""Generation-aware permanent project cleanup regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from devcoordinator.cleanup_lifecycle import (
    CleanupError,
    CleanupLifecycle,
    PlanDriftError,
)
from devcoordinator.store import AccountStore, utc_timestamp


UID = os.geteuid()


class ProjectCleanupGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-project-generations-", dir=Path.home()
        )
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / "coordinator.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_archived_project(self, store: AccountStore) -> str:
        repo_id = "repo-generation-test"
        host_id = store.ensure_local_host()
        now = utc_timestamp()
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'Generation Test', 'active', 0, ?, ?)
                """,
                (repo_id, host_id, str(self.root / "repository"), now, now),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor,
                    disabled_at, reason, updated_at
                ) VALUES (?, 'disabled', 1, 1, 'test', ?, 'archived', ?)
                """,
                (repo_id, now, now),
            )
        return repo_id

    def _downgrade_tombstones_to_v10(
        self, *, retain_generation_column: bool = False
    ) -> None:
        """Rebuild only the tombstone table as an exact v10-shaped fixture."""

        generation_definition = (
            """
                    target_generation INTEGER NOT NULL DEFAULT 0
                        CHECK(target_generation >= 0),
            """
            if retain_generation_column
            else ""
        )
        generation_column = ", target_generation" if retain_generation_column else ""
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "ALTER TABLE cleanup_tombstones RENAME TO cleanup_tombstones_current"
            )
            connection.execute(
                f"""
                CREATE TABLE cleanup_tombstones (
                    target_kind TEXT NOT NULL CHECK(target_kind IN (
                        'project', 'server', 'container', 'worktree'
                    )),
                    target_id TEXT NOT NULL,
                    {generation_definition}
                    repo_id TEXT REFERENCES repositories(repo_id) ON DELETE RESTRICT,
                    immutable_fingerprint TEXT NOT NULL,
                    operation_id TEXT NOT NULL
                        REFERENCES operations(operation_id) ON DELETE RESTRICT,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    removed_at TEXT NOT NULL,
                    PRIMARY KEY(target_kind, target_id)
                )
                """
            )
            connection.execute(
                f"""
                INSERT INTO cleanup_tombstones(
                    target_kind, target_id{generation_column}, repo_id,
                    immutable_fingerprint, operation_id, actor, reason,
                    evidence_json, removed_at
                )
                SELECT target_kind, target_id{generation_column}, repo_id,
                       immutable_fingerprint, operation_id, actor, reason,
                       evidence_json, removed_at
                FROM cleanup_tombstones_current
                """
            )
            connection.execute("DROP TABLE cleanup_tombstones_current")
            connection.execute(
                "UPDATE schema_metadata SET schema_version = 10 WHERE singleton = 1"
            )
            connection.commit()
        finally:
            connection.close()

    def test_purge_reinstall_purge_retains_each_generation_and_replays_exactly(
        self,
    ) -> None:
        with AccountStore.open(self.database, expected_uid=UID) as store:
            repo_id = self._seed_archived_project(store)
            lifecycle = CleanupLifecycle(store)
            first = lifecycle.plan(
                target_kind="project",
                target_id=repo_id,
                actor="test",
                reason="first removal",
            )
            first_result = lifecycle.apply(
                plan_id=first.plan_id,
                plan_fingerprint=first.plan_fingerprint,
                confirmation_phrase=first.confirmation_phrase,
                actor="test",
            )
            self.assertTrue(first_result["ok"])

            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repositories SET state = 'active', updated_at = ?
                    WHERE repo_id = ? AND state = 'missing' AND generation = 1
                    """,
                    (utc_timestamp(), repo_id),
                )
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'installed', startup_fenced = 0, updated_at = ?
                    WHERE repo_id = ?
                    """,
                    (utc_timestamp(), repo_id),
                )
            stale_inventory = store.inventory_v2()
            self.assertNotIn(
                repo_id,
                {
                    str(item["repo_id"])
                    for item in stale_inventory["repositories"]
                },
            )
            with self.assertRaisesRegex(CleanupError, "already removed"):
                lifecycle.plan(
                    target_kind="project",
                    target_id=repo_id,
                    actor="test",
                    reason="stale reactivation must fail",
                )

            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repositories
                    SET state = 'active', generation = 2, updated_at = ?
                    WHERE repo_id = ? AND generation = 1
                    """,
                    (now, repo_id),
                )
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'installed', startup_fenced = 0,
                        generation = generation + 1, reinstalled_at = ?,
                        updated_at = ? WHERE repo_id = ?
                    """,
                    (now, now, repo_id),
                )
            inventory = store.inventory_v2()
            self.assertIn(
                repo_id,
                {str(item["repo_id"]) for item in inventory["repositories"]},
            )

            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        generation = generation + 1, disabled_at = ?,
                        updated_at = ? WHERE repo_id = ?
                    """,
                    (now, now, repo_id),
                )
            second = lifecycle.plan(
                target_kind="project",
                target_id=repo_id,
                actor="test",
                reason="second removal",
            )
            second_result = lifecycle.apply(
                plan_id=second.plan_id,
                plan_fingerprint=second.plan_fingerprint,
                confirmation_phrase=second.confirmation_phrase,
                actor="test",
            )
            self.assertTrue(second_result["ok"])
            current_removed_projects = [
                item
                for item in lifecycle.list_archives(actor="test")["archives"]
                if item["target_kind"] == "project"
                and item["target_id"] == repo_id
            ]
            self.assertEqual(len(current_removed_projects), 1)
            self.assertEqual(current_removed_projects[0]["target_generation"], 2)

            replay = lifecycle.apply(
                plan_id=first.plan_id,
                plan_fingerprint=first.plan_fingerprint,
                confirmation_phrase=first.confirmation_phrase,
                actor="test",
            )
            self.assertTrue(replay["ok"])
            with store.read_transaction() as connection:
                generations = [
                    int(row[0])
                    for row in connection.execute(
                        """
                        SELECT target_generation FROM cleanup_tombstones
                        WHERE target_kind = 'project' AND target_id = ?
                        ORDER BY target_generation
                        """,
                        (repo_id,),
                    )
                ]
                repository = connection.execute(
                    "SELECT state, generation FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
            self.assertEqual(generations, [0, 2])
            self.assertEqual(
                dict(repository), {"state": "missing", "generation": 3}
            )

    def test_project_finalization_rejects_generation_change_after_revalidation(
        self,
    ) -> None:
        with AccountStore.open(self.database, expected_uid=UID) as store:
            repo_id = self._seed_archived_project(store)

            def advance_generation(_plan: object, _actor: str) -> dict[str, bool]:
                timestamp = utc_timestamp()
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE repositories SET generation = generation + 1,
                            updated_at = ? WHERE repo_id = ?
                        """,
                        (timestamp, repo_id),
                    )
                return {"generation_advanced": True}

            lifecycle = CleanupLifecycle(store, prepare_apply=advance_generation)
            plan = lifecycle.plan(
                target_kind="project",
                target_id=repo_id,
                actor="test",
                reason="generation race",
            )
            with self.assertRaisesRegex(
                PlanDriftError, "catalog identity changed before removal"
            ):
                lifecycle.apply(
                    plan_id=plan.plan_id,
                    plan_fingerprint=plan.plan_fingerprint,
                    confirmation_phrase=plan.confirmation_phrase,
                    actor="test",
                )
            with store.read_transaction() as connection:
                repository = connection.execute(
                    "SELECT state, generation FROM repositories WHERE repo_id = ?",
                    (repo_id,),
                ).fetchone()
                tombstone = connection.execute(
                    """
                    SELECT 1 FROM cleanup_tombstones
                    WHERE target_kind = 'project' AND target_id = ?
                    """,
                    (repo_id,),
                ).fetchone()
            self.assertEqual(
                dict(repository), {"state": "active", "generation": 1}
            )
            self.assertIsNone(tombstone)

    def test_v10_tombstones_require_offline_migration_without_startup_writes(self) -> None:
        repo_id = "repo-legacy-generation"
        project_operation = str(uuid.uuid4())
        server_operation = str(uuid.uuid4())
        now = utc_timestamp()
        project_evidence = json.dumps(
            {
                "snapshot": {
                    "identity": {
                        "repo_id": repo_id,
                        "canonical_root": str(self.root / "legacy"),
                        "generation": 4,
                    }
                }
            },
            sort_keys=True,
        )
        with AccountStore.open(self.database, expected_uid=UID) as store:
            host_id = store.ensure_local_host()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Legacy', 'missing', 5, ?, ?)
                    """,
                    (repo_id, host_id, str(self.root / "legacy"), now, now),
                )
                for operation_id in (project_operation, server_operation):
                    connection.execute(
                        """
                        INSERT INTO operations(
                            operation_id, repo_id, kind, status, phase,
                            request_fingerprint, owner_uid, actor,
                            created_at, updated_at
                        ) VALUES (?, ?, 'cleanup.apply', 'succeeded', 'complete',
                                  ?, ?, 'test', ?, ?)
                        """,
                        (operation_id, repo_id, operation_id, UID, now, now),
                    )
                connection.execute(
                    """
                    INSERT INTO cleanup_tombstones(
                        target_kind, target_id, target_generation, repo_id,
                        immutable_fingerprint, operation_id, actor, reason,
                        evidence_json, removed_at
                    ) VALUES ('project', ?, 4, ?, ?, ?, 'legacy-project-actor',
                              'legacy project reason', ?, ?)
                    """,
                    (
                        repo_id,
                        repo_id,
                        "sha256:" + "a" * 64,
                        project_operation,
                        project_evidence,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_tombstones(
                        target_kind, target_id, target_generation, repo_id,
                        immutable_fingerprint, operation_id, actor, reason,
                        evidence_json, removed_at
                    ) VALUES ('server', 'server-legacy', 0, ?, ?, ?,
                              'legacy-server-actor', 'legacy server reason',
                              '{"source":"legacy-server"}', ?)
                    """,
                    (
                        repo_id,
                        "sha256:" + "b" * 64,
                        server_operation,
                        now,
                    ),
                )

        self._downgrade_tombstones_to_v10()
        before = self.database.read_bytes()
        for _attempt in range(2):
            with self.assertRaisesRegex(
                RuntimeError, "unsupported coordinator database schema 10"
            ):
                with AccountStore.open(self.database, expected_uid=UID):
                    pass
            self.assertEqual(self.database.read_bytes(), before)
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0],
                10,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM cleanup_tombstones").fetchone()[0],
                2,
            )
        finally:
            connection.close()

    def test_v10_malformed_project_evidence_rolls_back_atomically(self) -> None:
        repo_id = "repo-malformed-generation"
        operation_id = str(uuid.uuid4())
        malformed_evidence = '{"snapshot":{"identity":{"repo_id":"repo-malformed-generation"}}}'
        now = utc_timestamp()
        with AccountStore.open(self.database, expected_uid=UID) as store:
            host_id = store.ensure_local_host()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Malformed Legacy', 'missing', 1, ?, ?)
                    """,
                    (repo_id, host_id, str(self.root / "malformed"), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase,
                        request_fingerprint, owner_uid, actor,
                        created_at, updated_at
                    ) VALUES (?, ?, 'cleanup.apply', 'succeeded', 'complete',
                              ?, ?, 'test', ?, ?)
                    """,
                    (operation_id, repo_id, operation_id, UID, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_tombstones(
                        target_kind, target_id, target_generation, repo_id,
                        immutable_fingerprint, operation_id, actor, reason,
                        evidence_json, removed_at
                    ) VALUES ('project', ?, 0, ?, ?, ?, 'legacy-actor',
                              'malformed legacy evidence', ?, ?)
                    """,
                    (
                        repo_id,
                        repo_id,
                        "sha256:" + "c" * 64,
                        operation_id,
                        malformed_evidence,
                        now,
                    ),
                )
        self._downgrade_tombstones_to_v10()

        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 10"
        ):
            with AccountStore.open(self.database, expected_uid=UID):
                pass

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()[0]
            columns = {
                str(row[1]) for row in connection.execute(
                    "PRAGMA table_info(cleanup_tombstones)"
                )
            }
            retained = connection.execute(
                """
                SELECT target_kind, target_id, repo_id, immutable_fingerprint,
                       operation_id, actor, reason, evidence_json, removed_at
                FROM cleanup_tombstones
                """
            ).fetchone()
            leftover = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'cleanup_tombstones_v11'
                """
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, 10)
        self.assertNotIn("target_generation", columns)
        self.assertEqual(
            retained,
            (
                "project",
                repo_id,
                repo_id,
                "sha256:" + "c" * 64,
                operation_id,
                "legacy-actor",
                "malformed legacy evidence",
                malformed_evidence,
                now,
            ),
        )
        self.assertIsNone(leftover)

    def test_v10_partial_generation_column_with_old_primary_key_is_rejected(
        self,
    ) -> None:
        with AccountStore.open(self.database, expected_uid=UID):
            pass
        self._downgrade_tombstones_to_v10(retain_generation_column=True)

        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 10"
        ):
            with AccountStore.open(self.database, expected_uid=UID):
                pass

        connection = sqlite3.connect(self.database)
        try:
            version = connection.execute(
                "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
            ).fetchone()[0]
            primary_key = {
                str(row[1]): int(row[5])
                for row in connection.execute(
                    "PRAGMA table_info(cleanup_tombstones)"
                )
            }
        finally:
            connection.close()
        self.assertEqual(version, 10)
        self.assertEqual(
            (
                primary_key["target_kind"],
                primary_key["target_id"],
                primary_key["target_generation"],
            ),
            (1, 2, 0),
        )


if __name__ == "__main__":
    unittest.main()
