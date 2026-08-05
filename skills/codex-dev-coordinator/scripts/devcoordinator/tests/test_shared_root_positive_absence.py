from __future__ import annotations

import copy
import json
import sqlite3
import unittest
import uuid

from devcoordinator.broker_persistence import BROKER_SCHEMA
from devcoordinator.schema import initialize_schema, invariant_violations
from devcoordinator.shared_root_positive_absence import (
    EXPECTED_ABSENT_COUNT,
    EXPECTED_ABSENT_DATABASE_BINDING_COUNT,
    EXPECTED_DATABASE_BINDING_COUNT,
    EXPECTED_MEMBERSHIP_COUNT,
    EXPECTED_PRESENT_DATABASE_BINDING_COUNT,
    SharedRootPositiveAbsenceError,
    apply_shared_root_positive_absence,
    plan_shared_root_positive_absence,
)


NOW = "2026-07-29T12:00:00Z"
APPLY_AT = "2026-07-29T12:05:00Z"
REPOSITORY_ID = "repo-shared-tmp"
HOST_ID = "host-a"
SOURCE_ID = "source-a"
ENGINE_ID = "engine-a"
SNAPSHOT_ID = "snapshot-full-docker-a"
OPERATION_ID = "11111111-2222-4333-8444-555555555555"


def _execute_statements(connection: sqlite3.Connection, source: str) -> None:
    statement = ""
    for line in source.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            statement = ""
            if sql:
                connection.execute(sql)
    if statement.strip():
        raise AssertionError("test schema contains an incomplete statement")


class SharedRootPositiveAbsenceFixture:
    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        initialize_schema(
            self.connection,
            database_generation="schema12-generation-a",
            timestamp=NOW,
        )
        _execute_statements(self.connection, BROKER_SCHEMA)
        self.connection.execute(
            "DROP TRIGGER repository_owner_transfers_no_update"
        )
        self.connection.execute(
            "DROP TRIGGER repository_owner_transfers_no_delete"
        )
        self.connection.execute("DROP TABLE repository_owner_transfers")
        self.connection.execute("DROP TABLE repository_owners")
        self.connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 12, state_revision = 41,
                migration_state = 'ready', updated_at = ?
            WHERE singleton = 1
            """,
            (NOW,),
        )
        self.connection.execute(
            """
            INSERT INTO hosts(
                host_id, machine_fingerprint, platform, hostname,
                created_at, updated_at
            ) VALUES (?, 'machine-a', 'linux', 'test-host', ?, ?)
            """,
            (HOST_ID, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO coordinator_sources(
                source_id, host_id, canonical_home, state_path,
                effective_uid, status, created_at, updated_at
            ) VALUES (?, ?, '/authority/coordinator.sqlite3',
                      '/authority/coordinator.sqlite3', 1000,
                      'imported', ?, ?)
            """,
            (SOURCE_ID, HOST_ID, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO repositories(
                repo_id, host_id, canonical_root, display_name,
                state, generation, created_at, updated_at
            ) VALUES (?, ?, '/tmp', 'tmp', 'active', 2, ?, ?)
            """,
            (REPOSITORY_ID, HOST_ID, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO repository_installations(
                repo_id, status, startup_fenced, generation,
                operation_id, disabled_at, reinstalled_at,
                reason, actor, updated_at
            ) VALUES (?, 'installed', 0, 4, NULL, NULL, ?,
                      'compensating recovery', 'recovery', ?)
            """,
            (REPOSITORY_ID, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO docker_engines(
                engine_id, host_id, context_identity, daemon_identity,
                socket_identity, capability_state, created_at, updated_at
            ) VALUES (?, ?, 'default', 'daemon-a', 'socket-a',
                      'available', ?, ?)
            """,
            (ENGINE_ID, HOST_ID, NOW, NOW),
        )
        self.resource_ids = [f"container-{index:02d}" for index in range(24)]
        self.present_id = self.resource_ids[-1]
        for index, resource_id in enumerate(self.resource_ids):
            full_id = f"{index + 1:064x}"
            source_resource_id = f"source-resource-{index:02d}"
            binding_id = f"binding-{index:02d}"
            policy_id = f"policy-{index:02d}"
            self.connection.execute(
                """
                INSERT INTO docker_resources(
                    docker_resource_id, engine_id, full_container_id,
                    current_name, image, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'postgres:17', ?, ?)
                """,
                (resource_id, ENGINE_ID, full_id, f"container-{index}", NOW, NOW),
            )
            self.connection.execute(
                """
                INSERT INTO docker_observations(
                    docker_resource_id, lifecycle, health, restart_policy,
                    ports_fingerprint, labels_fingerprint, sampled_at,
                    observation_fingerprint
                ) VALUES (?, 'running', 'healthy', ?, 'ports', 'labels', ?, ?)
                """,
                (
                    resource_id,
                    "no" if resource_id == self.present_id else "unless-stopped",
                    NOW,
                    f"docker-observation-{index}",
                ),
            )
            self.connection.execute(
                """
                INSERT INTO source_resources(
                    source_resource_id, source_id, resource_kind, native_id,
                    repo_id, payload_sha256, provenance_json, created_at
                ) VALUES (?, ?, 'container', ?, ?, ?, '{}', ?)
                """,
                (
                    source_resource_id,
                    SOURCE_ID,
                    full_id,
                    REPOSITORY_ID,
                    f"payload-{index}",
                    NOW,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO control_bindings(
                    binding_id, repo_id, source_resource_id, resource_kind,
                    resource_id, source_id, capability, provenance,
                    authority_state, priority, generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'container', ?, ?, 'lifecycle',
                          'docker_labels', 'authoritative', 100, 3, ?, ?)
                """,
                (
                    binding_id,
                    REPOSITORY_ID,
                    source_resource_id,
                    resource_id,
                    SOURCE_ID,
                    NOW,
                    NOW,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind,
                    host_resource_id, immutable_fingerprint,
                    control_binding_id, created_at
                ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                """,
                (
                    f"membership-{index:02d}",
                    REPOSITORY_ID,
                    resource_id,
                    "sha256:" + f"{index + 50:064x}",
                    binding_id,
                    NOW,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO startup_policies(
                    policy_id, repo_id, resource_kind, resource_id,
                    policy_kind, current_value, desired_disabled_value,
                    immutable_fingerprint, generation, updated_at
                ) VALUES (?, ?, 'container', ?, 'docker_restart', ?,
                          'no', ?, 5, ?)
                """,
                (
                    policy_id,
                    REPOSITORY_ID,
                    resource_id,
                    "no" if resource_id == self.present_id else "unless-stopped",
                    "sha256:" + f"{index + 80:064x}",
                    NOW,
                ),
            )
        for index in range(EXPECTED_DATABASE_BINDING_COUNT):
            resource_id = (
                self.present_id
                if index < EXPECTED_PRESENT_DATABASE_BINDING_COUNT
                else self.resource_ids[
                    index - EXPECTED_PRESENT_DATABASE_BINDING_COUNT
                ]
            )
            binding_id = f"database-binding-{index:03d}"
            self.connection.execute(
                """
                INSERT INTO database_bindings(
                    database_binding_id, docker_resource_id, repo_id,
                    database_name, engine_kind, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'postgresql', ?, ?)
                """,
                (
                    binding_id,
                    resource_id,
                    REPOSITORY_ID,
                    f"database_{index:03d}",
                    NOW,
                    NOW,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO database_observations(
                    database_binding_id, docker_resource_id, available,
                    size_bytes, error_code, error_message, sampled_at,
                    observation_fingerprint
                ) VALUES (?, ?, 1, 4096, NULL, NULL, ?, ?)
                """,
                (binding_id, resource_id, NOW, f"database-observation-{index}"),
            )
        self.connection.execute(
            """
            INSERT INTO docker_ownership_claims(
                claim_id, docker_resource_id, source_resource_id, repo_id,
                source_id, provenance, priority, conflict_state,
                created_at, updated_at
            ) VALUES ('legacy-claim', ?, 'source-resource-23', ?, ?,
                      'legacy', 10, 'clear', ?, ?)
            """,
            (self.present_id, REPOSITORY_ID, SOURCE_ID, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO broker_acl_principals(uid, account_id, enabled, updated_at)
            VALUES (1000, 'owner', 1, ?)
            """,
            (NOW,),
        )
        self.connection.execute(
            """
            INSERT INTO broker_resource_acl(
                uid, repo_id, resource_kind, resource_id,
                operation, enabled, updated_at
            ) VALUES (1000, ?, 'container', ?, 'docker.stop', 1, ?)
            """,
            (REPOSITORY_ID, self.present_id, NOW),
        )
        self.publish_snapshot(snapshot_id=SNAPSHOT_ID, completed_at=NOW)

    def close(self) -> None:
        self.connection.close()

    def publish_snapshot(
        self,
        *,
        snapshot_id: str,
        completed_at: str,
        present_ids: tuple[str, ...] | None = None,
    ) -> None:
        observed = (self.present_id,) if present_ids is None else present_ids
        self.connection.execute(
            """
            INSERT INTO observation_snapshots(
                snapshot_id, host_id, observer_domain, status,
                material_fingerprint, started_at, completed_at,
                error_code, error_message
            ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                      ?, ?, ?, NULL, NULL)
            """,
            (snapshot_id, HOST_ID, "a" * 64, completed_at, completed_at),
        )
        self.connection.execute(
            """
            INSERT INTO observation_capabilities(
                snapshot_id, observer_domain, docker_available,
                capability_fingerprint, committed_at
            ) VALUES (?, 'host-runtime-v2:full-docker', 1, ?, ?)
            """,
            (snapshot_id, "sha256:" + "b" * 64, completed_at),
        )
        for resource_id in observed:
            self.connection.execute(
                """
                INSERT INTO observation_snapshot_resources(
                    snapshot_id, resource_kind, resource_id,
                    observation_fingerprint
                ) VALUES (?, 'container', ?, ?)
                """,
                (snapshot_id, resource_id, f"observed:{resource_id}"),
            )

    def evidence(self, snapshot_id: str = SNAPSHOT_ID) -> dict[str, object]:
        row = self.connection.execute(
            """
            SELECT snapshot.snapshot_id, snapshot.host_id,
                   snapshot.observer_domain, capability.docker_available,
                   snapshot.material_fingerprint, snapshot.started_at,
                   snapshot.completed_at, capability.capability_fingerprint,
                   capability.committed_at AS capability_committed_at
            FROM observation_snapshots snapshot
            JOIN observation_capabilities capability USING(snapshot_id)
            WHERE snapshot.snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()
        assert row is not None
        result = dict(row)
        result["docker_available"] = bool(result["docker_available"])
        return result

    def plan(self) -> dict[str, object]:
        return plan_shared_root_positive_absence(
            self.connection,
            repository_id=REPOSITORY_ID,
            operation_id=OPERATION_ID,
            observation_evidence=self.evidence(),
            created_at=APPLY_AT,
        )

    def apply(self, plan: dict[str, object]) -> dict[str, object]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            result = apply_shared_root_positive_absence(
                self.connection,
                plan=plan,
                plan_document_sha256=str(plan["document_sha256"]),
            )
            self.connection.commit()
            return result
        except BaseException:
            self.connection.rollback()
            raise


class SharedRootPositiveAbsenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SharedRootPositiveAbsenceFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_plan_and_apply_preserve_native_and_database_history(self) -> None:
        connection = self.fixture.connection
        docker_before = connection.execute(
            "SELECT COUNT(*) FROM docker_resources"
        ).fetchone()[0]
        docker_observations_before = connection.execute(
            "SELECT COUNT(*) FROM docker_observations"
        ).fetchone()[0]
        database_observations_before = connection.execute(
            "SELECT COUNT(*) FROM database_observations"
        ).fetchone()[0]
        changes_before_plan = connection.total_changes
        plan = self.fixture.plan()
        self.assertEqual(connection.total_changes, changes_before_plan)
        self.assertEqual(len(plan["absent_resources"]), EXPECTED_ABSENT_COUNT)
        self.assertEqual(len(plan["present_resources"]), 1)

        result = self.fixture.apply(plan)

        self.assertEqual(result["kind"], "devcoordinator-shared-root-positive-absence-result")
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM docker_resources").fetchone()[0],
            docker_before,
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM docker_observations").fetchone()[0],
            docker_observations_before,
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM database_observations").fetchone()[0],
            database_observations_before,
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM database_bindings").fetchone()[0],
            EXPECTED_DATABASE_BINDING_COUNT,
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM database_bindings WHERE repo_id IS NULL"
            ).fetchone()[0],
            EXPECTED_DATABASE_BINDING_COUNT,
        )
        present_policy = connection.execute(
            "SELECT repo_id, current_value, generation FROM startup_policies "
            "WHERE resource_id = ?",
            (self.fixture.present_id,),
        ).fetchone()
        self.assertEqual(
            (
                present_policy["repo_id"],
                present_policy["current_value"],
                present_policy["generation"],
            ),
            (None, "no", 6),
        )
        self.assertEqual(
            connection.execute(
                "SELECT restart_policy FROM docker_observations "
                "WHERE docker_resource_id = ?",
                (self.fixture.present_id,),
            ).fetchone()[0],
            "no",
        )
        repository = connection.execute(
            "SELECT state, generation FROM repositories WHERE repo_id = ?",
            (REPOSITORY_ID,),
        ).fetchone()
        self.assertEqual((repository["state"], repository["generation"]), ("missing", 3))
        installation = connection.execute(
            "SELECT status, startup_fenced, generation "
            "FROM repository_installations WHERE repo_id = ?",
            (REPOSITORY_ID,),
        ).fetchone()
        self.assertEqual(
            (installation["status"], installation["startup_fenced"], installation["generation"]),
            ("disabled", 1, 5),
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM resource_retirements WHERE status = 'retired'"
            ).fetchone()[0],
            EXPECTED_ABSENT_COUNT,
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM cleanup_tombstones WHERE target_kind = 'container'"
            ).fetchone()[0],
            EXPECTED_ABSENT_COUNT,
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM cleanup_tombstones WHERE target_kind = 'project'"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM repository_memberships WHERE repo_id = ?",
                (REPOSITORY_ID,),
            ).fetchone()[0],
            0,
        )
        claim = connection.execute(
            "SELECT repo_id, conflict_state FROM docker_ownership_claims "
            "WHERE claim_id = 'legacy-claim'"
        ).fetchone()
        self.assertEqual((claim["repo_id"], claim["conflict_state"]), (None, "retired"))
        self.assertEqual(
            connection.execute(
                "SELECT enabled FROM broker_resource_acl WHERE repo_id = ?",
                (REPOSITORY_ID,),
            ).fetchone()[0],
            0,
        )
        unassigned = connection.execute(
            """
            SELECT resource_id, reason_code, status FROM unassigned_resources
            WHERE status = 'active'
            """
        ).fetchall()
        self.assertEqual(
            [(row["resource_id"], row["reason_code"], row["status"]) for row in unassigned],
            [(self.fixture.present_id, "not_git", "active")],
        )
        self.assertEqual(
            invariant_violations(
                connection,
                include_foreign_keys=True,
                include_owner_authority=False,
            ),
            [],
        )

    def test_apply_replay_returns_identical_sealed_result(self) -> None:
        plan = self.fixture.plan()
        first = self.fixture.apply(plan)
        self.fixture.publish_snapshot(
            snapshot_id="snapshot-after-terminal",
            completed_at="2026-07-29T12:06:00Z",
        )
        replay = self.fixture.apply(plan)
        self.assertEqual(replay, first)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                (OPERATION_ID,),
            ).fetchone()[0],
            1,
        )

    def test_authority_revision_churn_does_not_invalidate_or_change_replay(self) -> None:
        plan = self.fixture.plan()
        self.fixture.connection.execute(
            """
            UPDATE schema_metadata
            SET state_revision = state_revision + 5,
                updated_at = '2026-07-29T12:06:00Z'
            WHERE singleton = 1
            """
        )

        first = self.fixture.apply(plan)

        self.assertEqual(first["state_revision_before"], 46)
        self.assertEqual(first["state_revision_after"], 47)
        metadata = self.fixture.connection.execute(
            "SELECT state_revision, updated_at FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        self.assertEqual(
            (metadata["state_revision"], metadata["updated_at"]),
            (47, "2026-07-29T12:06:00Z"),
        )
        operation_payload = self.fixture.connection.execute(
            "SELECT result_json FROM operations WHERE operation_id = ?",
            (OPERATION_ID,),
        ).fetchone()[0]
        self.assertIn('"state_revision_before":46', operation_payload)
        self.assertIn(
            '"authority_updated_at_before":"2026-07-29T12:06:00Z"',
            operation_payload,
        )
        self.assertIn(
            '"authority_updated_at_after":"2026-07-29T12:06:00Z"',
            operation_payload,
        )

        self.fixture.connection.execute(
            """
            UPDATE schema_metadata
            SET state_revision = state_revision + 3,
                updated_at = '2026-07-29T12:07:00Z'
            WHERE singleton = 1
            """
        )
        replay = self.fixture.apply(plan)
        self.assertEqual(replay, first)

    def test_apply_rejects_static_authority_generation_drift(self) -> None:
        plan = self.fixture.plan()
        self.fixture.connection.execute(
            """
            UPDATE schema_metadata
            SET database_generation = 'schema12-generation-b',
                state_revision = state_revision + 1,
                updated_at = '2026-07-29T12:06:00Z'
            WHERE singleton = 1
            """
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                (OPERATION_ID,),
            ).fetchone()[0],
            0,
        )

    def test_apply_rejects_updated_at_only_authority_drift(self) -> None:
        plan = self.fixture.plan()
        self.fixture.connection.execute(
            "UPDATE schema_metadata SET updated_at = '2026-07-29T12:06:00Z' "
            "WHERE singleton = 1"
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                (OPERATION_ID,),
            ).fetchone()[0],
            0,
        )

    def test_apply_rejects_schema_and_migration_drift(self) -> None:
        for field, value in (("schema_version", 13), ("migration_state", "conflicted")):
            with self.subTest(field=field):
                fixture = SharedRootPositiveAbsenceFixture()
                try:
                    plan = fixture.plan()
                    fixture.connection.execute(
                        f"UPDATE schema_metadata SET {field} = ? WHERE singleton = 1",
                        (value,),
                    )
                    with self.assertRaises(SharedRootPositiveAbsenceError):
                        fixture.apply(plan)
                    self.assertEqual(
                        fixture.connection.execute(
                            "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                            (OPERATION_ID,),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    fixture.close()

    def test_apply_rolls_back_when_authority_revision_changes_during_mutation(self) -> None:
        plan = self.fixture.plan()
        self.fixture.connection.execute(
            """
            CREATE TRIGGER test_positive_absence_revision_race
            AFTER UPDATE ON repositories
            BEGIN
                UPDATE schema_metadata
                SET state_revision = state_revision + 1,
                    updated_at = '2026-07-29T12:06:00Z'
                WHERE singleton = 1;
            END
            """
        )

        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "terminalization CAS"
        ):
            self.fixture.apply(plan)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT state_revision FROM schema_metadata WHERE singleton = 1"
            ).fetchone()[0],
            41,
        )
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT state FROM repositories WHERE repo_id = ?", (REPOSITORY_ID,)
            ).fetchone()[0],
            "active",
        )
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                (OPERATION_ID,),
            ).fetchone()[0],
            0,
        )

    def test_replay_rejects_tampered_operation_revision_evidence(self) -> None:
        plan = self.fixture.plan()
        self.fixture.apply(plan)
        raw = self.fixture.connection.execute(
            "SELECT result_json FROM operations WHERE operation_id = ?",
            (OPERATION_ID,),
        ).fetchone()[0]
        payload = json.loads(raw)
        payload["state_revision_after"] += 1
        self.fixture.connection.execute(
            "UPDATE operations SET result_json = ? WHERE operation_id = ?",
            (
                json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                OPERATION_ID,
            ),
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)

    def test_replay_rejects_tampered_operation_static_evidence(self) -> None:
        plan = self.fixture.plan()
        self.fixture.apply(plan)
        raw = self.fixture.connection.execute(
            "SELECT result_json FROM operations WHERE operation_id = ?",
            (OPERATION_ID,),
        ).fetchone()[0]
        payload = json.loads(raw)
        payload["repository_id"] = "another-repository"
        self.fixture.connection.execute(
            "UPDATE operations SET result_json = ? WHERE operation_id = ?",
            (
                json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                OPERATION_ID,
            ),
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)

    def test_replay_rejects_noncanonical_operation_evidence(self) -> None:
        plan = self.fixture.plan()
        self.fixture.apply(plan)
        raw = self.fixture.connection.execute(
            "SELECT result_json FROM operations WHERE operation_id = ?",
            (OPERATION_ID,),
        ).fetchone()[0]
        self.fixture.connection.execute(
            "UPDATE operations SET result_json = ? WHERE operation_id = ?",
            (raw + " ", OPERATION_ID),
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)

    def test_replay_rejects_authority_revision_below_retained_result(self) -> None:
        plan = self.fixture.plan()
        self.fixture.apply(plan)
        self.fixture.connection.execute(
            """
            UPDATE schema_metadata
            SET state_revision = 41, updated_at = ?
            WHERE singleton = 1
            """,
            (NOW,),
        )

        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)

    def test_plan_requires_exact_latest_snapshot(self) -> None:
        self.fixture.publish_snapshot(
            snapshot_id="snapshot-newer",
            completed_at="2026-07-29T12:01:00Z",
        )
        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "exact latest committed"
        ):
            self.fixture.plan()

    def test_plan_rejects_partition_other_than_23_absent_one_present(self) -> None:
        self.fixture.publish_snapshot(
            snapshot_id="snapshot-two-present",
            completed_at="2026-07-29T12:01:00Z",
            present_ids=(self.fixture.present_id, self.fixture.resource_ids[-2]),
        )
        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "23 absent / 1 present"
        ):
            plan_shared_root_positive_absence(
                self.fixture.connection,
                repository_id=REPOSITORY_ID,
                operation_id=OPERATION_ID,
                observation_evidence=self.fixture.evidence("snapshot-two-present"),
                created_at=APPLY_AT,
            )

    def test_plan_rejects_database_binding_partition_drift(self) -> None:
        self.assertEqual(EXPECTED_ABSENT_DATABASE_BINDING_COUNT, 4)
        self.fixture.connection.execute(
            "UPDATE database_bindings SET docker_resource_id = ? "
            "WHERE database_binding_id = 'database-binding-000'",
            (self.fixture.resource_ids[0],),
        )
        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "135 present and 4 absent"
        ):
            self.fixture.plan()

    def test_apply_rejects_newer_snapshot_after_plan_without_writes(self) -> None:
        plan = self.fixture.plan()
        self.fixture.publish_snapshot(
            snapshot_id="snapshot-drift",
            completed_at="2026-07-29T12:02:00Z",
        )
        before = self.fixture.connection.total_changes
        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)
        self.assertEqual(self.fixture.connection.total_changes, before)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT state FROM repositories WHERE repo_id = ?", (REPOSITORY_ID,)
            ).fetchone()[0],
            "active",
        )

    def test_apply_rejects_projection_drift_atomically(self) -> None:
        plan = self.fixture.plan()
        self.fixture.connection.execute(
            "UPDATE startup_policies SET generation = generation + 1 WHERE policy_id = 'policy-00'"
        )
        with self.assertRaisesRegex(SharedRootPositiveAbsenceError, "drifted"):
            self.fixture.apply(plan)
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM operations WHERE operation_id = ?",
                (OPERATION_ID,),
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.fixture.connection.execute(
                "SELECT COUNT(*) FROM repository_memberships WHERE repo_id = ?",
                (REPOSITORY_ID,),
            ).fetchone()[0],
            EXPECTED_MEMBERSHIP_COUNT,
        )

    def test_plan_rejects_pending_lifecycle(self) -> None:
        self.fixture.connection.execute(
            """
            INSERT INTO operations(
                operation_id, repo_id, source_id, kind, status, phase,
                generation, request_fingerprint, owner_uid, actor,
                process_fingerprint, error_code, error_message, result_json,
                created_at, updated_at
            ) VALUES (?, ?, NULL, 'test', 'running', 'host', 0,
                      'request', 1000, 'test', NULL, NULL, NULL, NULL, ?, ?)
            """,
            (str(uuid.uuid4()), REPOSITORY_ID, NOW, NOW),
        )
        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "pending lifecycle rows"
        ):
            self.fixture.plan()

    def test_schema13_is_rejected(self) -> None:
        self.fixture.connection.execute(
            "UPDATE schema_metadata SET schema_version = 13 WHERE singleton = 1"
        )
        with self.assertRaisesRegex(
            SharedRootPositiveAbsenceError, "schema-12 only|ready schema-12"
        ):
            self.fixture.plan()

    def test_tampered_seal_is_rejected(self) -> None:
        plan = self.fixture.plan()
        tampered = copy.deepcopy(plan)
        tampered["reason"] = "different"
        self.fixture.connection.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(
                SharedRootPositiveAbsenceError, "evidence is invalid"
            ):
                apply_shared_root_positive_absence(
                    self.fixture.connection,
                    plan=tampered,
                    plan_document_sha256=str(plan["document_sha256"]),
                )
        finally:
            self.fixture.connection.rollback()


if __name__ == "__main__":
    unittest.main()
