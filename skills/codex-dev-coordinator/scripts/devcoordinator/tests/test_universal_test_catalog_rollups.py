from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import tempfile
import unittest

from devcoordinator.broker import (
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.store import CoordinatorStore
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_store import (
    TestStoreContractError,
    UniversalTestStore,
)


FIXED_NOW = 1_800_000_000.0


def _rollup_values(
    repository_id: str,
    bucket_start: float,
    *,
    test_seconds: float,
    cases: int,
    failures: int = 0,
    infrastructure_failures: int = 0,
) -> tuple[object, ...]:
    return (
        repository_id,
        bucket_start,
        2,  # run_count
        4,  # attempt_count
        4,  # selected_target_count
        8,  # eligible_target_count
        4,  # avoided_target_count
        cases,
        cases - failures,
        failures,
        0,
        0,
        12.0,  # queue_seconds
        8.0,  # attempt_queue_seconds
        test_seconds,
        120.0,  # attempt_wall_seconds
        60.0,  # wall_seconds
        1,  # retry_attempt_count
        1,  # flake_count
        1,  # slow_count
        1,  # regression_count
        45.0,
        3,
        failures,
        infrastructure_failures,
    )


def _insert_rollup(
    store: UniversalTestStore,
    table: str,
    values: tuple[object, ...],
) -> None:
    connection = store._connect()  # focused persistence-contract fixture
    try:
        with connection:
            connection.execute(
                f"""
                INSERT INTO {table}(
                    repository_id, bucket_start, run_count, attempt_count,
                    selected_target_count, eligible_target_count,
                    avoided_target_count, case_count, passed_count,
                    failed_count, skipped_count, error_count, queue_seconds,
                    attempt_queue_seconds, aggregate_test_seconds,
                    attempt_wall_seconds, wall_seconds, retry_attempt_count,
                    flake_count, slow_count, regression_count,
                    max_attempt_seconds, success_count, failure_count,
                    infrastructure_count
                ) VALUES ({','.join('?' for _ in values)})
                """,
                values,
            )
    finally:
        connection.close()


class RetainedCatalogAndRollupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.test_store = UniversalTestStore.create(
            self.root / "tests.sqlite3", clock=lambda: FIXED_NOW
        )
        self.adapter = StoreTestPlaneAdapter(self.test_store)
        self.day = float(int(FIXED_NOW) // 86_400 * 86_400)
        self.hour = float(int(FIXED_NOW) // 3_600 * 3_600)
        self.run_sequence = 0

    def retain_setup(self, repository_id: str, status: str) -> None:
        self.test_store.retain_repository_setup_projection(
            {
                "repository_id": repository_id,
                "status": status,
                "manifest_fingerprint": "a" * 64 if status == "ready" else None,
            }
        )

    def seed_rollups(self, repository_id: str, *, failures: int = 0) -> None:
        _insert_rollup(
            self.test_store,
            "test_rollup_daily",
            _rollup_values(
                repository_id,
                self.day,
                test_seconds=7_200.0,
                cases=1_000,
                failures=failures,
            ),
        )
        _insert_rollup(
            self.test_store,
            "test_rollup_hourly",
            _rollup_values(
                repository_id,
                self.hour,
                test_seconds=7_200.0,
                cases=1_000,
                failures=failures,
            ),
        )

    def seed_infrastructure_rollups(self, repository_id: str) -> None:
        for table, bucket in (
            ("test_rollup_daily", self.day),
            ("test_rollup_hourly", self.hour),
        ):
            _insert_rollup(
                self.test_store,
                table,
                _rollup_values(
                    repository_id,
                    bucket,
                    test_seconds=0.0,
                    cases=0,
                    infrastructure_failures=1,
                ),
            )

    def seed_terminal_run(
        self,
        repository_id: str,
        *,
        state: str,
        finished_at: float,
        attempts: tuple[tuple[str, bool], ...],
    ) -> None:
        self.run_sequence += 1
        suffix = f"{self.run_sequence:04d}"
        snapshot_id = f"snapshot-{suffix}"
        plan_id = f"plan-{suffix}"
        run_id = f"run-{suffix}"
        connection = self.test_store._connect()  # focused terminal-history fixture
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO test_snapshots(
                        snapshot_id, repository_id, source_mode,
                        content_fingerprint, manifest_fingerprint, original_root,
                        temporary_root, complete, provenance_json, created_at
                    ) VALUES (?, ?, 'immutable', ?, ?, ?, NULL, 1, '{}', ?)
                    """,
                    (
                        snapshot_id,
                        repository_id,
                        f"content-{suffix}",
                        f"manifest-{suffix}",
                        str(self.root / repository_id),
                        finished_at - 3.0,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO test_plans(
                        plan_id, fingerprint, execution_fingerprint,
                        manifest_fingerprint, repository_id, intent, snapshot_id,
                        source_mode, source_fingerprint, reusable, plan_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, 'manual', ?, 'immutable', ?, 0, '{}', ?)
                    """,
                    (
                        plan_id,
                        f"plan-fingerprint-{suffix}",
                        f"execution-{suffix}",
                        f"manifest-{suffix}",
                        repository_id,
                        snapshot_id,
                        f"source-{suffix}",
                        finished_at - 2.0,
                    ),
                )
                failure_classification = (
                    None if state == "succeeded" else "infrastructure_failure"
                )
                connection.execute(
                    """
                    INSERT INTO test_runs(
                        run_id, plan_id, repository_id, owner_uid, actor, intent,
                        source_mode, source_fingerprint, execution_fingerprint,
                        eligible_target_count, selected_target_count, state,
                        conclusion, failure_classification, priority, queued_at,
                        started_at, finished_at, cancel_reason, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, 1000, 'fixture', 'manual', 'immutable', ?, ?,
                        ?, ?, ?, ?, ?, 0, ?, ?, ?, NULL, ?, ?
                    )
                    """,
                    (
                        run_id,
                        plan_id,
                        repository_id,
                        f"source-{suffix}",
                        f"execution-{suffix}",
                        len(attempts),
                        len(attempts),
                        state,
                        state,
                        failure_classification,
                        finished_at - 2.0,
                        finished_at - 1.0,
                        finished_at,
                        finished_at - 2.0,
                        finished_at,
                    ),
                )
                for index, (attempt_state, measured) in enumerate(attempts):
                    target_id = f"target-{suffix}-{index}"
                    attempt_id = f"attempt-{suffix}-{index}"
                    connection.execute(
                        """
                        INSERT INTO test_run_targets(
                            target_id, run_id, target_name, wave_index,
                            shard_index, shard_count, state,
                            estimated_seconds, max_attempts,
                            worktree_key, exclusive_resources_json,
                            current_attempt_id, queued_at, started_at, finished_at
                        ) VALUES (
                            ?, ?, ?, 0, 0, 1, ?, 1.0, 1,
                            ?, '[]', ?, ?, ?, ?
                        )
                        """,
                        (
                            target_id,
                            run_id,
                            f"target-{index}",
                            attempt_state,
                            repository_id,
                            attempt_id,
                            finished_at - 2.0,
                            finished_at - 1.0,
                            finished_at,
                        ),
                    )
                    attempt_failure = (
                        None
                        if attempt_state == "succeeded"
                        else "infrastructure_failure"
                    )
                    connection.execute(
                        """
                        INSERT INTO test_target_attempts(
                            attempt_id, target_id, run_id, attempt_number, state,
                            generation, memory_commitment_mib, lease_owner,
                            lease_token_sha256, lease_expires_at, heartbeat_at,
                            queued_at, launched_at, launch_ack_id,
                            terminal_operation_id, terminal_fingerprint,
                            conclusion, failure_classification, duration_seconds,
                            peak_memory_bytes, cpu_seconds, reporter_complete,
                            started_at, finished_at, created_at, updated_at
                        ) VALUES (
                            ?, ?, ?, 1, ?, 1, 1024, 'fixture', ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, 1.0, ?, ?, 1, ?, ?, ?, ?
                        )
                        """,
                        (
                            attempt_id,
                            target_id,
                            run_id,
                            attempt_state,
                            "a" * 64,
                            finished_at + 60.0,
                            finished_at - 0.5,
                            finished_at - 2.0,
                            finished_at - 1.0,
                            f"launch-{suffix}-{index}",
                            f"terminal-{suffix}-{index}",
                            f"fingerprint-{suffix}-{index}",
                            attempt_state,
                            attempt_failure,
                            50 * 1024 * 1024 if measured else None,
                            0.5 if measured else None,
                            finished_at - 1.0,
                            finished_at,
                            finished_at - 2.0,
                            finished_at,
                        ),
                    )
        finally:
            connection.close()

    def test_catalog_is_exact_retained_and_never_invokes_a_uid_previewer(self) -> None:
        for repository_id, status in (
            ("repo-ready", "ready"),
            ("repo-missing", "missing"),
            ("repo-invalid", "invalid"),
        ):
            self.retain_setup(repository_id, status)

        result = self.adapter.repository_catalog(
            repository_ids=("repo-ready", "repo-missing", "repo-invalid", "repo-new")
        )
        self.assertEqual(
            [row["setup_status"] for row in result["repositories"]],
            ["ready", "missing", "invalid", "missing"],
        )
        self.assertEqual(
            [row["retained"] for row in result["repositories"]],
            [True, True, True, False],
        )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn("projection_json", encoded)
        with self.assertRaises(TestStoreContractError):
            self.adapter.repository_catalog(repository_ids=("repo-ready", "repo-ready"))

    def test_dashboard_statistics_are_served_from_materialized_testdb_rollups(self) -> None:
        self.retain_setup("repo-visible", "ready")
        self.seed_rollups("repo-visible")
        stats = self.adapter.dashboard_stats(
            repository_id="repo-visible", days=30, limit=25
        )
        self.assertEqual(stats["summary"]["test_count"], 1_000)
        self.assertEqual(stats["summary"]["test_seconds"], 7_200.0)
        self.assertEqual(stats["summary"]["avoided_target_count"], 4)
        self.assertEqual(stats["snapshot"]["source"], "devcoordinator-testdb-rollups")
        self.assertEqual(stats["hourly"][0]["test_count"], 1_000)
        self.assertNotIn(str(self.root), json.dumps(stats, sort_keys=True))

    def test_fleet_rollup_scope_cannot_enumerate_another_repository(self) -> None:
        self.retain_setup("repo-visible", "ready")
        self.retain_setup("repo-private", "invalid")
        self.seed_rollups("repo-visible")
        self.seed_rollups("repo-private", failures=1)
        fleet = self.adapter.dashboard_fleet(
            repository_ids=("repo-visible",), hours=24
        )
        self.assertEqual(
            [row["repo_id"] for row in fleet["repositories"]], ["repo-visible"]
        )
        self.assertEqual(fleet["repositories"][0]["summary"]["test_count"], 1_000)
        encoded = json.dumps(fleet, sort_keys=True)
        self.assertNotIn("repo-private", encoded)
        self.assertNotIn(str(self.root), encoded)

    def test_fleet_distinguishes_test_and_infrastructure_failures(self) -> None:
        self.retain_setup("repo-tests-failed", "ready")
        self.retain_setup("repo-infrastructure", "ready")
        self.seed_rollups("repo-tests-failed", failures=1)
        self.seed_infrastructure_rollups("repo-infrastructure")

        fleet = self.adapter.dashboard_fleet(
            repository_ids=("repo-tests-failed", "repo-infrastructure"),
            hours=24,
        )
        by_id = {row["repo_id"]: row for row in fleet["repositories"]}

        test_failure = by_id["repo-tests-failed"]
        self.assertEqual(test_failure["state"], "failing")
        self.assertEqual(test_failure["state_scope"], "selected_window")
        self.assertEqual(
            test_failure["state_detail"]["code"], "recent_test_failures"
        )
        self.assertEqual(test_failure["summary"]["failed_run_count"], 1)
        self.assertEqual(test_failure["summary"]["test_failure_count"], 1)
        self.assertEqual(test_failure["summary"]["infrastructure_count"], 0)
        self.assertEqual(
            test_failure["summary"]["infrastructure_failure_count"], 0
        )
        self.assertEqual(test_failure["efficiency"]["failure_rate"], 0.25)
        self.assertEqual(test_failure["efficiency"]["infrastructure_rate"], 0.0)

        infrastructure = by_id["repo-infrastructure"]
        self.assertEqual(infrastructure["state"], "infrastructure")
        self.assertEqual(infrastructure["state_scope"], "selected_window")
        self.assertEqual(
            infrastructure["state_detail"]["code"],
            "recent_infrastructure_failures",
        )
        self.assertEqual(infrastructure["summary"]["failure_count"], 0)
        self.assertEqual(infrastructure["summary"]["failed_run_count"], 0)
        self.assertEqual(infrastructure["summary"]["test_failure_count"], 0)
        self.assertEqual(infrastructure["summary"]["infrastructure_count"], 1)
        self.assertEqual(
            infrastructure["summary"]["infrastructure_failure_count"], 1
        )
        self.assertEqual(infrastructure["efficiency"]["failure_rate"], 0.0)
        self.assertEqual(infrastructure["efficiency"]["infrastructure_rate"], 0.25)
        self.assertEqual(infrastructure["hourly"][0]["failure_count"], 0)
        self.assertEqual(infrastructure["hourly"][0]["infrastructure_count"], 1)

        self.assertEqual(fleet["summary"]["failure_count"], 1)
        self.assertEqual(fleet["summary"]["test_failure_count"], 1)
        self.assertEqual(fleet["summary"]["infrastructure_count"], 1)
        self.assertEqual(fleet["summary"]["infrastructure_failure_count"], 1)
        populated_capacity = next(
            cell for cell in fleet["capacity"] if cell["infrastructure_count"]
        )
        self.assertEqual(populated_capacity["failure_count"], 1)
        self.assertEqual(populated_capacity["infrastructure_count"], 1)
        attention = {item["repo_id"]: item for item in fleet["attention"]}
        self.assertEqual(
            attention["repo-tests-failed"]["code"], "recent_test_failures"
        )
        self.assertEqual(
            attention["repo-infrastructure"]["code"],
            "recent_infrastructure_failures",
        )
        self.assertEqual(attention["repo-infrastructure"]["severity"], "warning")

    def test_fleet_attention_clears_only_after_a_later_clean_measured_run(self) -> None:
        repositories = (
            "repo-recovered",
            "repo-prelaunch-recovered",
            "repo-unmeasured",
            "repo-partial",
            "repo-later-incident",
        )
        for repository_id in repositories:
            self.retain_setup(repository_id, "ready")
            self.seed_infrastructure_rollups(repository_id)

        self.seed_terminal_run(
            "repo-recovered",
            state="failed",
            finished_at=self.hour - 200.0,
            attempts=(("infrastructure_failed", False),),
        )
        self.seed_terminal_run(
            "repo-recovered",
            state="succeeded",
            finished_at=self.hour - 100.0,
            attempts=(("succeeded", True),),
        )

        self.seed_terminal_run(
            "repo-prelaunch-recovered",
            state="failed",
            finished_at=self.hour - 200.0,
            attempts=(),
        )
        self.seed_terminal_run(
            "repo-prelaunch-recovered",
            state="succeeded",
            finished_at=self.hour - 100.0,
            attempts=(("succeeded", True),),
        )

        self.seed_terminal_run(
            "repo-unmeasured",
            state="failed",
            finished_at=self.hour - 200.0,
            attempts=(("infrastructure_failed", False),),
        )
        self.seed_terminal_run(
            "repo-unmeasured",
            state="succeeded",
            finished_at=self.hour - 100.0,
            attempts=(("succeeded", False),),
        )

        self.seed_terminal_run(
            "repo-partial",
            state="failed",
            finished_at=self.hour - 200.0,
            attempts=(("infrastructure_failed", False),),
        )
        self.seed_terminal_run(
            "repo-partial",
            state="failed",
            finished_at=self.hour - 100.0,
            attempts=(("succeeded", True), ("infrastructure_failed", False)),
        )

        self.seed_terminal_run(
            "repo-later-incident",
            state="succeeded",
            finished_at=self.hour - 200.0,
            attempts=(("succeeded", True),),
        )
        self.seed_terminal_run(
            "repo-later-incident",
            state="failed",
            finished_at=self.hour - 100.0,
            attempts=(("infrastructure_failed", False),),
        )

        fleet = self.adapter.dashboard_fleet(
            repository_ids=repositories,
            hours=24,
        )
        by_id = {row["repo_id"]: row for row in fleet["repositories"]}
        attention = {item["repo_id"]: item for item in fleet["attention"]}
        for repository_id in repositories[:2]:
            recovered = by_id[repository_id]
            self.assertEqual(recovered["state"], "healthy")
            self.assertEqual(
                recovered["state_detail"]["code"],
                "recent_infrastructure_recovered",
            )
            self.assertEqual(recovered["summary"]["infrastructure_count"], 1)
            self.assertEqual(recovered["hourly"][0]["infrastructure_count"], 1)
            self.assertNotIn(repository_id, attention)
        for repository_id in repositories[2:]:
            self.assertEqual(by_id[repository_id]["state"], "infrastructure")
            self.assertEqual(
                by_id[repository_id]["state_detail"]["code"],
                "recent_infrastructure_failures",
            )
            self.assertIn(repository_id, attention)


class BrokerTestDbProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.authority = self.root / "authority.sqlite3"
        self.repo_id = "repo-visible"
        now = datetime.now(UTC).isoformat()
        with CoordinatorStore.open(self.authority) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts(host_id, machine_fingerprint, platform, hostname, created_at, updated_at) VALUES ('host-test', 'machine-test', 'linux', 'test', ?, ?)",
                    (now, now),
                )
                connection.execute(
                    "INSERT INTO repositories(repo_id, host_id, canonical_root, display_name, state, created_at, updated_at) VALUES (?, 'host-test', ?, 'Visible', 'active', ?, ?)",
                    (self.repo_id, str(self.root / "private-repo"), now, now),
                )
                connection.execute(
                    "INSERT INTO repository_installations(repo_id, status, startup_fenced, actor, updated_at) VALUES (?, 'installed', 0, 'test', ?)",
                    (self.repo_id, now),
                )
                self.generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
        self.persistence = BrokerPersistence(self.authority)
        self.test_store = UniversalTestStore.create(
            self.root / "tests.sqlite3", clock=lambda: FIXED_NOW
        )
        self.test_store.retain_repository_setup_projection(
            {
                "repository_id": self.repo_id,
                "status": "ready",
                "manifest_fingerprint": "b" * 64,
            }
        )
        day = float(int(FIXED_NOW) // 86_400 * 86_400)
        hour = float(int(FIXED_NOW) // 3_600 * 3_600)
        _insert_rollup(
            self.test_store,
            "test_rollup_daily",
            _rollup_values(self.repo_id, day, test_seconds=3_600.0, cases=400),
        )
        _insert_rollup(
            self.test_store,
            "test_rollup_hourly",
            _rollup_values(self.repo_id, hour, test_seconds=3_600.0, cases=400),
        )
        _insert_rollup(
            self.test_store,
            "test_rollup_daily",
            _rollup_values("repo-private", day, test_seconds=99_999.0, cases=9_999),
        )
        _insert_rollup(
            self.test_store,
            "test_rollup_hourly",
            _rollup_values("repo-private", hour, test_seconds=99_999.0, cases=9_999),
        )
        self.backend = StoreBackedMutationBackend(
            self.persistence,
            object(),  # type: ignore[arg-type]
            test_plane=StoreTestPlaneAdapter(self.test_store),
        )
        self.peer = PeerCredentials(
            uid=os.geteuid(), gid=os.getegid(), pid=os.getpid()
        )

    def call(self, operation: BrokerOperation, arguments: dict[str, object]):
        request = BrokerRequest.create(
            account_id="account-tests",
            project_id=self.repo_id,
            resource_id=self.repo_id,
            operation=operation,
            arguments=arguments,
            authority_generation=self.generation,
        )
        return self.backend.execute(self.persistence.accept(self.peer, request))

    def test_broker_routes_catalog_stats_and_fleet_to_testdb(self) -> None:
        catalog = self.call(BrokerOperation.TEST_REPOSITORY_CATALOG, {})
        self.assertEqual(catalog["repositories"][0]["setup_status"], "ready")
        self.assertNotIn(str(self.root), json.dumps(catalog, sort_keys=True))
        stats = self.call(
            BrokerOperation.TEST_STATS_READ, {"days": 30, "limit": 25}
        )
        fleet = self.call(BrokerOperation.TEST_FLEET_STATS_READ, {"hours": 24})
        self.assertEqual(stats["summary"]["test_count"], 400)
        self.assertEqual(fleet["summary"]["test_count"], 400.0)
        self.assertEqual(
            fleet["snapshot"]["source"], "devcoordinator-testdb-rollups"
        )
        self.assertEqual(fleet["repositories"][0]["display_name"], "Visible")
        self.assertNotIn("repo-private", json.dumps(fleet, sort_keys=True))
        browser_safe = {
            "schema_version": catalog["schema_version"],
            "repositories": [
                {
                    "repo_id": row["repo_id"],
                    "display_name": row["display_name"],
                    "setup_status": row["setup_status"],
                }
                for row in catalog["repositories"]
            ],
        }
        self.assertNotIn(str(self.root), json.dumps(browser_safe, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
