from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
import uuid

from devcoordinator.repository_owner_authority import (
    RepositoryOwnerAuthorityError,
    apply_owner_map,
    OWNER_MIGRATION_FENCE_KIND,
    OWNER_MIGRATION_FENCE_SCHEMA_VERSION,
    prepare_owner_map,
    repository_census,
    validate_owner_map,
    validate_owner_migration_fence,
)
from devcoordinator.schema import (
    SCHEMA_VERSION,
    establish_repository_owner_authority,
    initialize_schema,
    invariant_violations,
)


class RepositoryOwnerAuthorityTests(unittest.TestCase):
    def _reseal_fence(self, fence: dict[str, object]) -> None:
        fence.pop("fence_sha256", None)
        fence["fence_sha256"] = "sha256:" + hashlib.sha256(
            json.dumps(
                fence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    def _file_evidence(self, path: Path) -> dict[str, object]:
        info = path.lstat()
        return {
            "path": str(path.absolute()),
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "owner_uid": int(info.st_uid),
            "owner_gid": int(info.st_gid),
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "nlink": int(info.st_nlink),
            "size": int(info.st_size),
            "mtime_ns": int(info.st_mtime_ns),
            "ctime_ns": int(info.st_ctime_ns),
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def _fence(self, path: Path, document: dict[str, object]) -> dict[str, object]:
        source = path.with_name("retained-v12.sqlite3")
        source.write_bytes(path.read_bytes())
        os.chmod(source, 0o600)
        info = path.with_name("broker-service.lock")
        info.write_bytes(b"")
        os.chmod(info, 0o600)
        lock = info.lstat()
        fence: dict[str, object] = {
            "schema_version": OWNER_MIGRATION_FENCE_SCHEMA_VERSION,
            "kind": OWNER_MIGRATION_FENCE_KIND,
            "operation_id": document["operation_id"],
            "maintenance": {
                "marker_path": str(path.with_name("maintenance.json")),
                "marker_sha256": "sha256:" + "1" * 64,
                "deployment_id": document["operation_id"],
                "active": True,
            },
            "journal": {
                "path": str(path.with_name("adoption-journal.json")),
                "sha256": "sha256:" + "2" * 64,
                "phase": "storage_split_complete",
            },
            "source_database": {"main": self._file_evidence(source), "sidecars": []},
            "candidate_database": {"main": self._file_evidence(path), "sidecars": []},
            "split_attestation": {
                "path": str(path.with_name("split-attestation.json")),
                "sha256": "sha256:" + "3" * 64,
            },
            "broker": {
                "active": False,
                "lock": {
                    "path": str(info),
                    "device": int(lock.st_dev),
                    "inode": int(lock.st_ino),
                    "owner_uid": int(lock.st_uid),
                    "owner_gid": int(lock.st_gid),
                    "mode": f"{stat.S_IMODE(lock.st_mode):04o}",
                    "nlink": int(lock.st_nlink),
                    "held_exclusive": True,
                },
            },
        }
        self._reseal_fence(fence)
        return fence

    def _v12(self, path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE schema_metadata(
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                database_generation TEXT NOT NULL,
                state_revision INTEGER NOT NULL,
                migration_state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO schema_metadata VALUES(1, 12, 'generation-a', 7, 'ready', 'before');
            CREATE TABLE repositories(
                repo_id TEXT PRIMARY KEY,
                canonical_root TEXT NOT NULL,
                generation INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                state TEXT NOT NULL
            );
            INSERT INTO repositories VALUES('repo-a', '/srv/a', 2, 'Alpha', 'active');
            INSERT INTO repositories VALUES('repo-b', '/srv/b', 0, 'Beta', 'missing');
            CREATE TABLE repository_installations(
                repo_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                startup_fenced INTEGER NOT NULL,
                generation INTEGER NOT NULL
            );
            INSERT INTO repository_installations VALUES('repo-a', 'installed', 0, 4);
            INSERT INTO repository_installations VALUES('repo-b', 'installed', 0, 1);
            CREATE TABLE operations(
                operation_id TEXT PRIMARY KEY,
                repo_id TEXT,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                actor TEXT NOT NULL,
                result_json TEXT
            );
            CREATE TABLE cleanup_plans(
                plan_id TEXT PRIMARY KEY,
                repo_id TEXT,
                target_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_fingerprint TEXT NOT NULL,
                plan_fingerprint TEXT NOT NULL,
                confirmation_phrase TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE TABLE cleanup_phase_evidence(
                plan_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_json TEXT,
                PRIMARY KEY(plan_id, phase)
            );
            CREATE TABLE cleanup_tombstones(
                target_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_generation INTEGER NOT NULL,
                repo_id TEXT,
                immutable_fingerprint TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                removed_at TEXT NOT NULL,
                PRIMARY KEY(target_kind, target_id, target_generation)
            );
            """
        )
        return connection

    @staticmethod
    def _sha(value: object) -> str:
        return "sha256:" + hashlib.sha256(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    def _terminalize_repo_b(self, connection: sqlite3.Connection) -> str:
        operation_id = "77777777-2222-4333-8444-555555555555"
        actor = "host-admin"
        reason = "fixture permanent cleanup"
        connection.execute(
            "UPDATE repositories SET state = 'missing', generation = 3 "
            "WHERE repo_id = 'repo-b'"
        )
        connection.execute(
            "UPDATE repository_installations SET status = 'disabled', "
            "startup_fenced = 1, generation = 7 WHERE repo_id = 'repo-b'"
        )
        snapshot = {
            "identity": {
                "repo_id": "repo-b",
                "canonical_root": "/srv/b",
                "state": "active",
                "generation": 2,
                "installation_status": "disabled",
                "startup_fenced": True,
                "installation_generation": 7,
            },
            "repo_id": "repo-b",
            "target": {"display_name": "Beta", "project_id": "repo-b"},
            "effects": ["remove_from_project_catalog"],
            "retained": [
                "repository_files",
                "audit_history",
                "cleanup_tombstone",
                "operation_evidence",
            ],
            "deleted": ["active_project_catalog_entry"],
            "blockers": [],
        }
        target_fingerprint = self._sha(snapshot["identity"])
        plan_material = {
            "action": "forget",
            "target_kind": "project",
            "target_id": "repo-b",
            "repo_id": "repo-b",
            "target_fingerprint": target_fingerprint,
            "snapshot": snapshot,
            "actor": actor,
            "reason": reason,
        }
        plan_fingerprint = self._sha(plan_material)
        confirmation = "PURGE PROJECT Beta"
        plan_summary = {
            "plan_id": operation_id,
            "plan_fingerprint": plan_fingerprint,
            "fingerprint": plan_fingerprint,
            "confirmation_phrase": confirmation,
            "action": "forget",
            "target": {
                "display_name": "Beta",
                "project_id": "repo-b",
                "target_kind": "project",
                "target_id": "repo-b",
            },
            "effects": ["remove_from_project_catalog"],
            "retained": snapshot["retained"],
            "deleted": ["active_project_catalog_entry"],
            "blockers": [],
            "status": "planned",
        }
        terminal_result = {
            "status": "succeeded",
            "partial": False,
            "needs_attention": False,
            "ok": True,
            "errors": [],
            "target_kind": "project",
            "target_id": "repo-b",
        }
        connection.execute(
            "INSERT INTO operations VALUES(?, 'repo-b', 'cleanup:forget', "
            "'succeeded', 'complete', ?, ?, ?)",
            (
                operation_id,
                plan_fingerprint,
                actor,
                json.dumps(terminal_result, sort_keys=True, separators=(",", ":")),
            ),
        )
        connection.execute(
            "INSERT INTO cleanup_plans VALUES(?, 'repo-b', 'project', 'repo-b', "
            "'forget', ?, ?, ?, ?, 'succeeded', 'complete', ?, ?)",
            (
                operation_id,
                target_fingerprint,
                plan_fingerprint,
                confirmation,
                json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                actor,
                reason,
            ),
        )
        connection.execute(
            "INSERT INTO cleanup_phase_evidence VALUES(?, 'finalize', "
            "'succeeded', ?)",
            (
                operation_id,
                json.dumps(terminal_result, sort_keys=True, separators=(",", ":")),
            ),
        )
        tombstone_evidence = {
            "plan": plan_summary,
            "snapshot": snapshot,
            "applied_by": actor,
        }
        connection.execute(
            "INSERT INTO cleanup_tombstones VALUES('project', 'repo-b', 2, "
            "'repo-b', ?, ?, ?, ?, ?, '2026-07-28T19:59:00Z')",
            (
                target_fingerprint,
                operation_id,
                actor,
                reason,
                json.dumps(
                    tombstone_evidence, sort_keys=True, separators=(",", ":")
                ),
            ),
        )
        return operation_id

    def _insert_full_schema_terminal_repository(
        self, connection: sqlite3.Connection
    ) -> str:
        repository_id = "repo-terminal"
        operation_id = "88888888-2222-4333-8444-555555555555"
        canonical_root = "/srv/terminal"
        display_name = "Terminal"
        actor = "host-admin"
        reason = "fixture permanent cleanup"
        now = "2026-07-28T20:00:00Z"
        connection.execute(
            """
            INSERT INTO repositories(
                repo_id, host_id, canonical_root, display_name, state,
                generation, created_at, updated_at
            ) VALUES (?, 'host', ?, ?, 'missing', 3, ?, ?)
            """,
            (repository_id, canonical_root, display_name, now, now),
        )
        connection.execute(
            """
            INSERT INTO repository_installations(
                repo_id, status, startup_fenced, generation, actor,
                disabled_at, reason, updated_at
            ) VALUES (?, 'disabled', 1, 7, ?, ?, ?, ?)
            """,
            (repository_id, actor, now, reason, now),
        )
        snapshot = {
            "identity": {
                "repo_id": repository_id,
                "canonical_root": canonical_root,
                "state": "active",
                "generation": 2,
                "installation_status": "disabled",
                "startup_fenced": True,
                "installation_generation": 7,
            },
            "repo_id": repository_id,
            "target": {
                "display_name": display_name,
                "project_id": repository_id,
            },
            "effects": ["remove_from_project_catalog"],
            "retained": [
                "repository_files",
                "audit_history",
                "cleanup_tombstone",
                "operation_evidence",
            ],
            "deleted": ["active_project_catalog_entry"],
            "blockers": [],
        }
        target_fingerprint = self._sha(snapshot["identity"])
        plan_material = {
            "action": "forget",
            "target_kind": "project",
            "target_id": repository_id,
            "repo_id": repository_id,
            "target_fingerprint": target_fingerprint,
            "snapshot": snapshot,
            "actor": actor,
            "reason": reason,
        }
        plan_fingerprint = self._sha(plan_material)
        confirmation = f"PURGE PROJECT {display_name}"
        plan_summary = {
            "plan_id": operation_id,
            "plan_fingerprint": plan_fingerprint,
            "fingerprint": plan_fingerprint,
            "confirmation_phrase": confirmation,
            "action": "forget",
            "target": {
                "display_name": display_name,
                "project_id": repository_id,
                "target_kind": "project",
                "target_id": repository_id,
            },
            "effects": ["remove_from_project_catalog"],
            "retained": snapshot["retained"],
            "deleted": ["active_project_catalog_entry"],
            "blockers": [],
            "status": "planned",
        }
        terminal_result = {
            "status": "succeeded",
            "partial": False,
            "needs_attention": False,
            "ok": True,
            "errors": [],
            "target_kind": "project",
            "target_id": repository_id,
        }
        canonical = lambda value: json.dumps(  # noqa: E731
            value, sort_keys=True, separators=(",", ":")
        )
        connection.execute(
            """
            INSERT INTO operations(
                operation_id, repo_id, kind, status, phase, generation,
                request_fingerprint, owner_uid, actor, result_json,
                created_at, updated_at
            ) VALUES (?, ?, 'cleanup:forget', 'succeeded', 'complete', 0,
                      ?, 1, ?, ?, ?, ?)
            """,
            (
                operation_id,
                repository_id,
                plan_fingerprint,
                actor,
                canonical(terminal_result),
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO cleanup_plans(
                plan_id, repo_id, target_kind, target_id, action,
                target_fingerprint, plan_fingerprint, confirmation_phrase,
                snapshot_json, status, phase, actor, reason, created_at,
                updated_at
            ) VALUES (?, ?, 'project', ?, 'forget', ?, ?, ?, ?,
                      'succeeded', 'complete', ?, ?, ?, ?)
            """,
            (
                operation_id,
                repository_id,
                repository_id,
                target_fingerprint,
                plan_fingerprint,
                confirmation,
                canonical(snapshot),
                actor,
                reason,
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO cleanup_phase_evidence(
                plan_id, phase, status, evidence_json, error_json,
                started_at, finished_at
            ) VALUES (?, 'finalize', 'succeeded', ?, NULL, ?, ?)
            """,
            (operation_id, canonical(terminal_result), now, now),
        )
        connection.execute(
            """
            INSERT INTO cleanup_tombstones(
                target_kind, target_id, target_generation, repo_id,
                immutable_fingerprint, operation_id, actor, reason,
                evidence_json, removed_at
            ) VALUES ('project', ?, 2, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository_id,
                repository_id,
                target_fingerprint,
                operation_id,
                actor,
                reason,
                canonical(
                    {
                        "plan": plan_summary,
                        "snapshot": snapshot,
                        "applied_by": actor,
                    }
                ),
                now,
            ),
        )
        return repository_id

    def _map(self, connection: sqlite3.Connection) -> dict[str, object]:
        return prepare_owner_map(
            connection,
            owner_uids={"repo-a": 1001, "repo-b": 1002},
            operation_id=str(uuid.UUID("11111111-2222-4333-8444-555555555555")),
            actor="host-admin",
            created_at="2026-07-28T20:00:00.000Z",
            target_database_generation="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        )

    def test_ordinary_schema_open_refuses_v12_without_writing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "authority.sqlite3"
            connection = self._v12(path)
            connection.close()
            before = path.read_bytes()
            before_sha = hashlib.sha256(before).hexdigest()
            connection = sqlite3.connect(path, isolation_level=None)
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(RuntimeError, "sealed offline repository-owner"):
                initialize_schema(
                    connection,
                    database_generation="ignored",
                    timestamp="2026-07-28T20:01:00Z",
                )
            connection.rollback()
            connection.close()
            after = path.read_bytes()
            self.assertEqual(hashlib.sha256(after).hexdigest(), before_sha)
            self.assertEqual(after, before)

    def test_map_requires_exact_repository_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            with self.assertRaisesRegex(RepositoryOwnerAuthorityError, "exactly once"):
                prepare_owner_map(
                    connection,
                    owner_uids={"repo-a": 1001},
                    operation_id=str(uuid.uuid4()),
                    actor="host-admin",
                )
            connection.close()

    def test_repository_census_exposes_exact_decision_set_without_inference(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            census = repository_census(connection)
            self.assertEqual(census["schema_version"], 12)
            self.assertEqual(census["database_generation"], "generation-a")
            self.assertEqual(census["state_revision"], 7)
            self.assertEqual(census["repository_count"], 2)
            self.assertEqual(census["executable_repository_count"], 2)
            self.assertEqual(census["excluded_terminal_repository_count"], 0)
            self.assertEqual(
                census["repositories"],
                [
                    {
                        "repository_id": "repo-a",
                        "canonical_root": "/srv/a",
                        "repository_generation": 2,
                        "display_name": "Alpha",
                        "state": "active",
                        "terminal_exclusion_blockers": [
                            "installation_not_disabled",
                            "installation_not_fenced",
                            "repository_not_missing",
                        ],
                    },
                    {
                        "repository_id": "repo-b",
                        "canonical_root": "/srv/b",
                        "repository_generation": 0,
                        "display_name": "Beta",
                        "state": "missing",
                        "terminal_exclusion_blockers": [
                            "installation_not_disabled",
                            "installation_not_fenced",
                            "repository_generation_has_no_terminal_predecessor",
                        ],
                    },
                ],
            )
            self.assertEqual(census["excluded_terminal_repositories"], [])
            for field in (
                "repository_universe_sha256",
                "executable_repositories_sha256",
                "excluded_terminal_repositories_sha256",
                "repository_execution_scope_sha256",
            ):
                self.assertRegex(census[field], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("owner_uid", json.dumps(census))
            connection.close()

    def test_terminal_project_is_excluded_only_with_exact_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "authority.sqlite3"
            connection = self._v12(path)
            operation_id = self._terminalize_repo_b(connection)
            census = repository_census(connection)
            self.assertEqual(census["repository_count"], 2)
            self.assertEqual(census["executable_repository_count"], 1)
            self.assertEqual(census["excluded_terminal_repository_count"], 1)
            self.assertEqual(
                [item["repository_id"] for item in census["repositories"]],
                ["repo-a"],
            )
            excluded = census["excluded_terminal_repositories"]
            self.assertEqual(len(excluded), 1)
            self.assertEqual(excluded[0]["repository_id"], "repo-b")
            self.assertEqual(
                excluded[0]["terminal_evidence"]["operation_id"], operation_id
            )
            document = prepare_owner_map(
                connection,
                owner_uids={"repo-a": 1001},
                operation_id="11111111-2222-4333-8444-555555555555",
                actor="host-admin",
                created_at="2026-07-28T20:00:00.000Z",
                target_database_generation="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            )
            self.assertEqual(
                [item["repository_id"] for item in document["repositories"]],
                ["repo-a"],
            )
            self.assertEqual(
                document["repository_execution_scope"]["document_sha256"],
                census["repository_execution_scope_sha256"],
            )
            self.assertEqual(validate_owner_map(connection, document), document)
            fence = self._fence(path, document)
            connection.execute("BEGIN EXCLUSIVE")
            result = apply_owner_map(connection, document, cutover_fence=fence)
            connection.commit()
            self.assertEqual(result["repository_count"], 2)
            self.assertEqual(result["executable_repository_count"], 1)
            self.assertEqual(result["excluded_terminal_repository_count"], 1)
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT repo_id, owner_uid FROM repository_owners "
                        "ORDER BY repo_id"
                    )
                ),
                [("repo-a", 1001)],
            )
            connection.close()

    def test_legacy_missing_cleanup_tables_fails_toward_executable_ownership(self) -> None:
        variants = (
            (
                "all lifecycle tables absent",
                (
                    "DROP TABLE cleanup_phase_evidence",
                    "DROP TABLE cleanup_plans",
                    "DROP TABLE cleanup_tombstones",
                    "DROP TABLE operations",
                    "DROP TABLE repository_installations",
                ),
            ),
            (
                "partial terminal evidence schema",
                ("DROP TABLE cleanup_phase_evidence",),
            ),
        )
        for label, statements in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                connection = self._v12(Path(raw) / "authority.sqlite3")
                if label == "partial terminal evidence schema":
                    connection.execute(
                        "UPDATE repositories SET state = 'missing', generation = 3 "
                        "WHERE repo_id = 'repo-b'"
                    )
                    connection.execute(
                        "UPDATE repository_installations SET status = 'disabled', "
                        "startup_fenced = 1, generation = 7 "
                        "WHERE repo_id = 'repo-b'"
                    )
                for statement in statements:
                    connection.execute(statement)
                census = repository_census(connection)
                self.assertEqual(census["repository_count"], 2)
                self.assertEqual(census["executable_repository_count"], 2)
                self.assertEqual(census["excluded_terminal_repository_count"], 0)
                document = prepare_owner_map(
                    connection,
                    owner_uids={"repo-a": 1001, "repo-b": 1002},
                    operation_id="11111111-2222-4333-8444-555555555555",
                    actor="host-admin",
                    created_at="2026-07-28T20:00:00.000Z",
                    target_database_generation=(
                        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                    ),
                )
                self.assertEqual(
                    [item["repository_id"] for item in document["repositories"]],
                    ["repo-a", "repo-b"],
                )
                connection.close()

    def test_partial_or_stale_terminal_evidence_fails_toward_owner_decision(self) -> None:
        mutations = (
            "UPDATE operations SET status = 'running' WHERE repo_id = 'repo-b'",
            "UPDATE cleanup_tombstones SET evidence_json = '{}' "
            "WHERE target_kind = 'project' AND target_id = 'repo-b'",
            "UPDATE cleanup_tombstones SET target_generation = 1 "
            "WHERE target_kind = 'project' AND target_id = 'repo-b'",
            "UPDATE repository_installations SET startup_fenced = 0 "
            "WHERE repo_id = 'repo-b'",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                connection = self._v12(Path(raw) / "authority.sqlite3")
                self._terminalize_repo_b(connection)
                connection.execute(mutation)
                census = repository_census(connection)
                self.assertEqual(census["executable_repository_count"], 2)
                self.assertEqual(census["excluded_terminal_repository_count"], 0)
                self.assertEqual(
                    {item["repository_id"] for item in census["repositories"]},
                    {"repo-a", "repo-b"},
                )
                with self.assertRaisesRegex(
                    RepositoryOwnerAuthorityError, "exactly once"
                ):
                    prepare_owner_map(
                        connection,
                        owner_uids={"repo-a": 1001},
                        operation_id=str(uuid.uuid4()),
                        actor="host-admin",
                    )
                connection.close()

    def test_owner_map_binds_partition_counts_digests_and_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            self._terminalize_repo_b(connection)
            document = prepare_owner_map(
                connection,
                owner_uids={"repo-a": 1001},
                operation_id="11111111-2222-4333-8444-555555555555",
                actor="host-admin",
                created_at="2026-07-28T20:00:00.000Z",
                target_database_generation="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            )
            for field, replacement in (
                ("executable_repository_count", 2),
                ("excluded_terminal_repository_count", 0),
                ("state_revision", 8),
                ("excluded_terminal_repositories_sha256", "sha256:" + "f" * 64),
            ):
                tampered = json.loads(json.dumps(document))
                tampered["repository_execution_scope"][field] = replacement
                tampered["document_sha256"] = self._sha(
                    {
                        key: value
                        for key, value in tampered.items()
                        if key != "document_sha256"
                    }
                )
                with self.assertRaisesRegex(
                    RepositoryOwnerAuthorityError, "execution scope"
                ):
                    validate_owner_map(connection, tampered)
            connection.close()

    def test_map_reports_nonready_source_state_without_modifying_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            connection.execute(
                "UPDATE schema_metadata SET migration_state = 'conflicted' "
                "WHERE singleton = 1"
            )
            with self.assertRaisesRegex(
                RepositoryOwnerAuthorityError,
                r"requires migration_state=ready; actual='conflicted'",
            ):
                prepare_owner_map(
                    connection,
                    owner_uids={"repo-a": 1001, "repo-b": 1002},
                    operation_id=str(uuid.uuid4()),
                    actor="host-admin",
                )
            self.assertEqual(
                connection.execute(
                    "SELECT migration_state FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0],
                "conflicted",
            )
            connection.close()

    def test_map_is_generation_fenced_and_digest_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            document = self._map(connection)
            self.assertEqual(validate_owner_map(connection, document), document)
            connection.execute(
                "UPDATE repositories SET generation = 3 WHERE repo_id = 'repo-a'"
            )
            with self.assertRaisesRegex(
                RepositoryOwnerAuthorityError, "execution scope.*changed"
            ):
                validate_owner_map(connection, document)
            connection.close()

    def test_map_and_cutover_fence_require_canonical_identity_material(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "authority.sqlite3"
            connection = self._v12(path)
            with self.assertRaisesRegex(
                RepositoryOwnerAuthorityError, "operation_id must be canonical"
            ):
                prepare_owner_map(
                    connection,
                    owner_uids={"repo-a": 1001, "repo-b": 1002},
                    operation_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".upper(),
                    actor="host-admin",
                )
            document = self._map(connection)
            fence = self._fence(path, document)
            fence["maintenance"]["marker_path"] = str(
                path.parent / "alias" / ".." / "maintenance.json"
            )
            self._reseal_fence(fence)
            with self.assertRaisesRegex(RepositoryOwnerAuthorityError, "path is invalid"):
                validate_owner_migration_fence(connection, document, fence)
            fence = self._fence(path, document)
            fence["journal"]["sha256"] = "sha256:" + "G" * 64
            self._reseal_fence(fence)
            with self.assertRaisesRegex(RepositoryOwnerAuthorityError, "digest is invalid"):
                validate_owner_migration_fence(connection, document, fence)
            connection.close()

    def test_apply_is_atomic_complete_and_ledger_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            document = self._map(connection)
            fence = self._fence(Path(raw) / "authority.sqlite3", document)
            connection.execute("BEGIN EXCLUSIVE")
            result = apply_owner_map(connection, document, cutover_fence=fence)
            connection.commit()
            self.assertEqual(result["schema_version"], SCHEMA_VERSION)
            self.assertEqual(result["source_database_generation"], "generation-a")
            self.assertEqual(
                result["target_database_generation"],
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0],
                result["target_database_generation"],
            )
            self.assertEqual(result["repository_count"], 2)
            owners = list(
                connection.execute(
                    """
                    SELECT repo_id, owner_uid, repository_generation,
                           authority_generation
                    FROM repository_owners ORDER BY repo_id
                    """
                )
            )
            self.assertEqual(owners, [("repo-a", 1001, 2, 1), ("repo-b", 1002, 0, 1)])
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM repository_owner_transfers"
                ).fetchone()[0],
                2,
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE repository_owner_transfers SET actor = 'rewritten'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute("DELETE FROM repository_owner_transfers")
            connection.close()

    def test_failed_apply_rolls_back_all_v13_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            connection = self._v12(Path(raw) / "authority.sqlite3")
            document = self._map(connection)
            fence = self._fence(Path(raw) / "authority.sqlite3", document)
            document["repositories"][0]["owner_uid"] = 0
            connection.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(RepositoryOwnerAuthorityError):
                apply_owner_map(connection, document, cutover_fence=fence)
            connection.rollback()
            self.assertEqual(
                connection.execute(
                    "SELECT schema_version FROM schema_metadata"
                ).fetchone()[0],
                12,
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'repository_owners'"
                ).fetchone()
            )
            connection.close()

    def test_ready_v13_requires_full_generation_bound_owner_coverage(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN")
        initialize_schema(connection, database_generation="generation-v13", timestamp="now")
        connection.execute(
            "INSERT INTO hosts VALUES('host', 'machine', 'linux', 'host', 'now', 'now')"
        )
        connection.execute(
            """
            INSERT INTO repositories(
                repo_id, host_id, canonical_root, display_name, state,
                generation, created_at, updated_at
            ) VALUES ('repo', 'host', '/srv/repo', 'Repo', 'active', 3, 'now', 'now')
            """
        )
        terminal_repository_id = self._insert_full_schema_terminal_repository(
            connection
        )
        connection.execute(
            "UPDATE schema_metadata SET migration_state = 'ready' WHERE singleton = 1"
        )
        violations = invariant_violations(connection, include_foreign_keys=False)
        self.assertIn(
            "ready_repository_missing_owner_authority",
            {violation.code for violation in violations},
        )
        establish_repository_owner_authority(
            connection,
            repository_id="repo",
            owner_uid=1001,
            repository_generation=3,
            operation_id="owner-authority-fixture",
            actor="fixture",
            reason="fixture owner",
            timestamp="now",
            evidence={"kind": "fixture"},
        )
        violations = invariant_violations(connection, include_foreign_keys=False)
        self.assertNotIn(
            "ready_repository_missing_owner_authority",
            {violation.code for violation in violations},
        )
        self.assertIsNone(
            connection.execute(
                "SELECT 1 FROM repository_owners WHERE repo_id = ?",
                (terminal_repository_id,),
            ).fetchone()
        )
        connection.execute(
            """
            UPDATE cleanup_tombstones SET evidence_json = '{}'
            WHERE target_kind = 'project' AND target_id = ?
            """,
            (terminal_repository_id,),
        )
        violations = invariant_violations(connection, include_foreign_keys=False)
        self.assertIn(
            "ready_repository_missing_owner_authority",
            {violation.code for violation in violations},
        )
        connection.rollback()
        connection.close()


if __name__ == "__main__":
    unittest.main()
