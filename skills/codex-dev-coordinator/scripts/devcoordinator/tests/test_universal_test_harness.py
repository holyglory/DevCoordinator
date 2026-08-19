from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.store import CoordinatorStore
from devcoordinator.test_records import CoordinatorTestRecords
from devcoordinator.test_runner import TestHarnessError, load_manifest
from devcoordinator.universal_test_contract import SourceMode, parse_test_manifest
from devcoordinator.universal_test_planner import SourceIdentity, create_test_plan
from devcoordinator.universal_test_snapshot_service import SnapshotAuthority
from devcoordinator.universal_test_store import TestStoreContractError
from devcoordinator.universal_test_transport import TestPlaneTransportError
from devcoordinator.tests.test_universal_test_plane import (
    manifest_document as universal_manifest_document,
)

UTC = timezone.utc


class PreviewTestPlane:
    def __init__(self, selected_plan) -> None:
        self.selected_plan = selected_plan
        self.registered: list[dict[str, object]] = []
        self.preview_calls: list[dict[str, object]] = []
        self.preview_error: Exception | None = None

    def health(self):
        return {
            "schema_version": 1,
            "status": "ok",
            "test_store_schema_version": 6,
            "store_generation": "generation-tests",
        }

    def preview(self, **values):
        self.preview_calls.append(dict(values))
        if self.preview_error is not None:
            raise self.preview_error
        resources = {
            target: {
                "cpu_millis": 1000,
                "memory_mib": 512,
                "pids": 128,
                "estimated_seconds": 60.0,
                "shard_count": 1,
                "max_attempts": 2,
                "worktree_key": f"/var/lib/devcoordinator-test-snapshots/{self.selected_plan.source.snapshot_id}/root",
                "exclusive_resources": [],
            }
            for target in self.selected_plan.selected_targets
        }
        return {
            "schema_version": 1,
            "repository_id": self.selected_plan.repository_id,
            "intent": self.selected_plan.intent,
            "plan": self.selected_plan.to_document(),
            "registered": False,
            "target_resources": resources,
            "capability_requests": {
                "networks": ["none"],
                "fixtures": [],
                "credentials": [],
            },
        }

    def register_plan(self, plan_document, *, target_resources=None):
        document = dict(plan_document)
        self.registered.append(document)
        self.target_resources = target_resources
        return {
            "schema_version": 1,
            "repository_id": self.selected_plan.repository_id,
            "plan_id": self.selected_plan.plan_id,
            "registered": True,
        }

    def dashboard_fleet(self, *, repository_ids, hours):
        return {
            "schema_version": 2,
            "window": {"hours": hours},
            "snapshot": {"source": "testdb-rollups"},
            "summary": {},
            "hours": [],
            "repositories": [
                {
                    "repo_id": repository_id,
                    "repository_id": repository_id,
                    "state": "idle",
                    "summary": {},
                    "hourly": [],
                }
                for repository_id in repository_ids
            ],
            "capacity": [],
            "attention": [],
        }


class UniversalTestHarnessTests(unittest.TestCase):
    @staticmethod
    def preview_arguments(intent: str) -> dict[str, object]:
        return {
            "intent": intent,
            "temporary_root": None,
            "requested_targets": [],
            "execution_timeout_seconds": None,
            "launch_timeout_seconds": 300,
        }

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "coordinator.sqlite3"
        self.repo_id = "repo-tests"
        with CoordinatorStore.open(self.database) as store:
            now = datetime.now(UTC).isoformat()
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts(host_id, machine_fingerprint, platform, hostname, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    ("host-tests", "machine-tests", "linux", "test", now, now),
                )
                connection.execute(
                    "INSERT INTO repositories(repo_id, host_id, canonical_root, display_name, state, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
                    (self.repo_id, "host-tests", str(self.root), "Tests", now, now),
                )
                connection.execute(
                    "INSERT INTO repository_installations(repo_id, status, startup_fenced, actor, updated_at) VALUES (?, 'installed', 0, 'test', ?)",
                    (self.repo_id, now),
                )
                connection.execute(
                    "UPDATE schema_metadata SET migration_state = 'ready' WHERE singleton = 1"
                )
        self.persistence = BrokerPersistence(self.database)
        with CoordinatorStore.open(self.database) as store:
            now = datetime.now(UTC).isoformat()
            with store.immediate_transaction() as connection:
                self.generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
        self.records = CoordinatorTestRecords(
            self.database, expected_uid=os.geteuid(), busy_timeout_ms=5_000
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        operation: BrokerOperation,
        arguments: dict[str, object],
        *,
        operation_id: str | None = None,
    ) -> AcceptedBrokerRequest:
        return AcceptedBrokerRequest(
            peer=PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid()),
            request=BrokerRequest.create(
                account_id="account-tests",
                project_id=self.repo_id,
                resource_id=self.repo_id,
                operation=operation,
                arguments=arguments,
                operation_id=operation_id,
                authority_generation=self.generation,
            ),
        )


    def test_records_exact_case_timings_and_repository_statistics(self) -> None:
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC)
        start = self.records.start(
            self.request(
                BrokerOperation.TEST_RUN_START,
                {
                    "agent": "unit-test",
                    "suite": "unit",
                    "run_kind": "test",
                    "selection": ["tests/unit/test_example.py::test_case"],
                    "command_fingerprint": "a" * 64,
                    "started_at": started.isoformat(),
                },
                operation_id=run_id,
            )
        )
        self.assertEqual(start["status"], "running")

        finished = started + timedelta(seconds=0.25)
        completed = self.records.finish(
            self.request(
                BrokerOperation.TEST_RUN_FINISH,
                {
                    "run_id": run_id,
                    "status": "passed",
                    "finished_at": finished.isoformat(),
                    "duration_seconds": 0.25,
                    "exit_code": 0,
                    "cases": [
                        {
                            "test_id": "tests/unit/test_example.py::test_case",
                            "display_name": "test_case",
                            "status": "passed",
                            "started_at": started.isoformat(),
                            "finished_at": finished.isoformat(),
                            "duration_seconds": 0.25,
                        }
                    ],
                },
            )
        )
        self.assertEqual(completed["case_count"], 1)
        stats = self.records.stats_for_repository(repo_id=self.repo_id)
        self.assertEqual(stats["summary"]["run_count"], 1)
        self.assertEqual(stats["summary"]["test_count"], 1)
        self.assertEqual(
            stats["slow_tests"][0]["test_id"], "tests/unit/test_example.py::test_case"
        )
        self.assertEqual(stats["slow_tests"][0]["percent_of_test_time"], 100.0)
        self.assertEqual(stats["efficiency"]["parallel_efficiency_ratio"], 1.0)
        self.assertEqual(stats["health"]["pass_rate"], 1.0)
        self.assertEqual(stats["series"]["daily"], stats["daily"])
        self.assertEqual(stats["snapshot"]["source"], "coordinator-test-store")
        self.assertFalse(stats["avoided_work"]["available"])

    def test_hourly_statistics_add_parallel_case_intervals(self) -> None:
        run_id = str(uuid.uuid4())
        started = (datetime.now(UTC) - timedelta(days=1)).replace(
            hour=10, minute=30, second=0, microsecond=0
        )
        finished = started + timedelta(hours=1)
        self.records.start(
            self.request(
                BrokerOperation.TEST_RUN_START,
                {
                    "agent": "parallel-test",
                    "suite": "parallel-suite",
                    "run_kind": "test",
                    "selection": [],
                    "command_fingerprint": "c" * 64,
                    "started_at": started.isoformat(),
                },
                operation_id=run_id,
            )
        )
        cases = []
        for ordinal in range(3):
            cases.append(
                {
                    "test_id": f"tests/test_parallel.py::test_{ordinal}",
                    "display_name": f"test_{ordinal}",
                    "status": "failed" if ordinal == 0 else "passed",
                    "started_at": started.isoformat(),
                    "finished_at": finished.isoformat(),
                    "duration_seconds": 3_600,
                }
            )
        self.records.finish(
            self.request(
                BrokerOperation.TEST_RUN_FINISH,
                {
                    "run_id": run_id,
                    "status": "failed",
                    "finished_at": finished.isoformat(),
                    "duration_seconds": 3_600,
                    "exit_code": 1,
                    "cases": cases,
                },
            )
        )

        stats = self.records.stats_for_repository(repo_id=self.repo_id)
        cells = {
            (row["day"], row["hour"]): row
            for row in stats["hourly"]
        }
        day = started.date().isoformat()
        self.assertAlmostEqual(cells[(day, 10)]["test_seconds"], 5_400, places=2)
        self.assertAlmostEqual(cells[(day, 11)]["test_seconds"], 5_400, places=2)
        self.assertEqual(cells[(day, 10)]["failure_count"], 1)
        self.assertEqual(stats["summary"]["failed_run_count"], 1)
        self.assertEqual(stats["dynamics"][0]["suite"], "parallel-suite")
        self.assertEqual(stats["dynamics"][0]["current_seconds"], 10_800)
        self.assertEqual(stats["top_actionable_regression"]["kind"], "test_failure")
        self.assertEqual(stats["series"]["daily"][0]["failure_count"], 1)

    def test_hourly_statistics_never_reintroduce_case_by_bucket_cross_join(self) -> None:
        source = inspect.getsource(CoordinatorTestRecords.stats_for_repository)
        self.assertIn("_hourly_case_statistics", source)
        self.assertNotIn("WITH RECURSIVE hours", source)
        self.assertNotIn("LEFT JOIN recent_cases", source)

    def test_fleet_statistics_are_bounded_exact_and_parallel_aware(self) -> None:
        hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        started = hour + timedelta(minutes=5)
        finished = hour + timedelta(minutes=35)
        run_id = str(uuid.uuid4())
        self.records.start(
            self.request(
                BrokerOperation.TEST_RUN_START,
                {
                    "agent": "fleet-test",
                    "suite": "fleet-suite",
                    "run_kind": "test",
                    "selection": [],
                    "command_fingerprint": "d" * 64,
                    "started_at": started.isoformat(),
                },
                operation_id=run_id,
            )
        )
        self.records.finish(
            self.request(
                BrokerOperation.TEST_RUN_FINISH,
                {
                    "run_id": run_id,
                    "status": "failed",
                    "finished_at": finished.isoformat(),
                    "duration_seconds": 1_800,
                    "exit_code": 1,
                    "cases": [
                        {
                            "test_id": "tests/test_flake.py::test_unstable",
                            "display_name": "test_unstable",
                            "status": status,
                            "started_at": started.isoformat(),
                            "finished_at": finished.isoformat(),
                            "duration_seconds": 1_800,
                        }
                        for status in ("failed", "passed")
                    ]
                    + [
                        {
                            "test_id": "tests/test_parallel.py::test_other",
                            "display_name": "test_other",
                            "status": "passed",
                            "started_at": started.isoformat(),
                            "finished_at": finished.isoformat(),
                            "duration_seconds": 1_800,
                        }
                    ],
                },
            )
        )

        fleet = self.records.fleet_overview(
            hours=24, now=hour + timedelta(minutes=45)
        )

        self.assertEqual(fleet["schema_version"], 2)
        self.assertEqual(fleet["repositories"][0]["repo_id"], self.repo_id)
        self.assertEqual(fleet["repositories"][0]["state"], "failing")
        self.assertEqual(fleet["summary"]["test_seconds"], 5_400)
        self.assertEqual(fleet["summary"]["parallel_efficiency_ratio"], 3.0)
        self.assertEqual(fleet["summary"]["flaky_test_count"], 1)
        self.assertFalse(fleet["summary"]["avoided_work"]["available"])
        self.assertEqual(
            sum(cell["test_seconds"] for cell in fleet["capacity"]), 5_400
        )
        self.assertGreater(
            max(cell["test_seconds"] for cell in fleet["capacity"]), 3_600
        )
        self.assertIsNotNone(
            next(
                cell["p95_queue_wait_seconds"]
                for cell in fleet["capacity"]
                if cell["test_count"]
            )
        )
        self.assertNotIn(str(self.root), json.dumps(fleet))
        self.assertLessEqual(len(fleet["attention"]), 25)

    def test_passed_run_rejects_failed_case(self) -> None:
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC)
        self.records.start(
            self.request(
                BrokerOperation.TEST_RUN_START,
                {
                    "agent": "unit-test",
                    "suite": "unit",
                    "run_kind": "test",
                    "selection": [],
                    "command_fingerprint": "b" * 64,
                    "started_at": started.isoformat(),
                },
                operation_id=run_id,
            )
        )
        with self.assertRaises(BrokerBackendError):
            self.records.finish(
                self.request(
                    BrokerOperation.TEST_RUN_FINISH,
                    {
                        "run_id": run_id,
                        "status": "passed",
                        "finished_at": (started + timedelta(seconds=1)).isoformat(),
                        "duration_seconds": 1,
                        "exit_code": 0,
                        "cases": [
                            {
                                "test_id": "broken",
                                "display_name": "broken",
                                "status": "failed",
                                "started_at": started.isoformat(),
                                "finished_at": (
                                    started + timedelta(seconds=1)
                                ).isoformat(),
                                "duration_seconds": 1,
                            }
                        ],
                    },
                )
            )

    def test_passed_run_rejects_nonzero_exit_code(self) -> None:
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC)
        self.records.start(
            self.request(
                BrokerOperation.TEST_RUN_START,
                {
                    "agent": "unit-test",
                    "suite": "unit",
                    "run_kind": "test",
                    "selection": [],
                    "command_fingerprint": "d" * 64,
                    "started_at": started.isoformat(),
                },
                operation_id=run_id,
            )
        )
        with self.assertRaises(BrokerBackendError):
            self.records.finish(
                self.request(
                    BrokerOperation.TEST_RUN_FINISH,
                    {
                        "run_id": run_id,
                        "status": "passed",
                        "finished_at": (started + timedelta(seconds=1)).isoformat(),
                        "duration_seconds": 1,
                        "exit_code": 1,
                        "cases": [],
                    },
                )
            )

    def test_manifest_rejects_cwd_escape(self) -> None:
        manifest_root = self.root / "repo"
        (manifest_root / ".codex").mkdir(parents=True)
        (manifest_root / ".codex" / "tests.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "groups": {
                        "escape": {
                            "kind": "automation",
                            "cwd": "..",
                            "argv": ["true"],
                        }
                    },
                    "profiles": {"all": ["escape"]},
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(TestHarnessError):
            load_manifest(manifest_root)

    def test_broker_authorizes_exact_repository_and_journals_lifecycle(self) -> None:
        backend = StoreBackedMutationBackend(self.persistence, object())  # type: ignore[arg-type]
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC)
        start_request = self.request(
            BrokerOperation.TEST_RUN_START,
            {
                "agent": "unit-test",
                "suite": "unit",
                "run_kind": "test",
                "selection": [],
                "command_fingerprint": "c" * 64,
                "started_at": started.isoformat(),
            },
            operation_id=run_id,
        )
        authorized = self.persistence.accept(
            start_request.peer, start_request.request
        )
        self.assertEqual(backend.execute(authorized)["status"], "running")

        finish_request = self.request(
            BrokerOperation.TEST_RUN_FINISH,
            {
                "run_id": run_id,
                "status": "passed",
                "finished_at": (started + timedelta(seconds=0.1)).isoformat(),
                "duration_seconds": 0.1,
                "exit_code": 0,
                "cases": [],
            },
        )
        authorized_finish = self.persistence.accept(
            finish_request.peer, finish_request.request
        )
        self.assertEqual(backend.execute(authorized_finish)["status"], "passed")

    def test_broker_authority_checks_immutable_preview_before_registration(self) -> None:
        manifest = parse_test_manifest(universal_manifest_document())

        def selected(root: Path):
            return create_test_plan(
                manifest,
                intent="release",
                source=SourceIdentity(
                    mode=SourceMode.IMMUTABLE,
                    repository_id=self.repo_id,
                    content_fingerprint="a" * 64,
                    original_root=str(root),
                    temporary_root=None,
                    snapshot_id="snapshot-" + "b" * 32,
                ),
            )

        valid_plane = PreviewTestPlane(selected(self.root))
        backend = StoreBackedMutationBackend(
            self.persistence,
            object(),  # type: ignore[arg-type]
            test_plane=valid_plane,  # type: ignore[arg-type]
        )
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW,
            self.preview_arguments("release"),
        )
        result = backend.execute(
            self.persistence.accept(preview.peer, preview.request)
        )
        self.assertEqual(result["plan_id"], valid_plane.selected_plan.plan_id)
        self.assertEqual(len(valid_plane.registered), 1)
        self.assertEqual(valid_plane.preview_calls[0]["access_uid"], preview.peer.uid)
        self.assertEqual(valid_plane.preview_calls[0]["owner_uid"], os.geteuid())
        replay = backend.execute(
            self.persistence.accept(preview.peer, preview.request)
        )
        self.assertEqual(replay["classification"], "test_plan_preview_completed")
        self.assertEqual(replay["plan_id"], valid_plane.selected_plan.plan_id)
        self.assertEqual(len(valid_plane.preview_calls), 1)

        invalid_plane = PreviewTestPlane(selected(self.root / "not-authorized"))
        invalid_backend = StoreBackedMutationBackend(
            self.persistence,
            object(),  # type: ignore[arg-type]
            test_plane=invalid_plane,  # type: ignore[arg-type]
        )
        invalid_preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW,
            self.preview_arguments("release"),
        )
        with self.assertLogs("devcoordinator.broker_backend", level="WARNING") as logs:
            with self.assertRaises(BrokerBackendError) as rejected:
                invalid_backend.execute(
                    self.persistence.accept(
                        invalid_preview.peer, invalid_preview.request
                    )
                )
        self.assertEqual(rejected.exception.code, "test_contract_invalid")
        self.assertIn(
            "plan source is not the exact accepted root repository",
            str(rejected.exception),
        )
        self.assertIn(invalid_preview.request.operation_id, "\n".join(logs.output))
        self.assertIn(
            "plan source is not the exact accepted root repository",
            "\n".join(logs.output),
        )
        self.assertEqual(invalid_plane.registered, [])

        fleet_request = self.request(
            BrokerOperation.TEST_FLEET_STATS_READ,
            {"hours": 24},
        )
        authorized_fleet = self.persistence.accept(
            fleet_request.peer, fleet_request.request
        )
        self.assertEqual(backend.execute(authorized_fleet)["schema_version"], 2)

        health_request = self.request(BrokerOperation.TEST_HEALTH, {})
        health = backend.execute(
            self.persistence.accept(health_request.peer, health_request.request)
        )
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["test_store_schema_version"], 6)
        self.assertEqual(health["store_generation"], "generation-tests")
        self.assertEqual(health["repository_id"], self.repo_id)

        wrong_resource = BrokerRequest.create(
            account_id="account-tests",
            project_id=self.repo_id,
            resource_id="another-repository",
            operation=BrokerOperation.TEST_STATS_READ,
            arguments={"days": 30, "limit": 25},
            authority_generation=self.generation,
        )
        with self.assertRaises(Exception):
            self.persistence.accept(start_request.peer, wrong_resource)

        with self.assertRaises(BrokerError):
            BrokerRequest.create(
                account_id="account-tests",
                project_id=self.repo_id,
                resource_id=self.repo_id,
                operation=BrokerOperation.TEST_FLEET_STATS_READ,
                arguments={"hours": 169},
                authority_generation=self.generation,
            )

    def test_fleet_projection_is_server_wide_for_every_trusted_local_peer(self) -> None:

        other_repo = "repo-private-other-account"
        other_uid = os.geteuid() + 10_000
        now = datetime.now(UTC).isoformat()
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO repositories(repo_id, host_id, canonical_root, display_name, state, created_at, updated_at) VALUES (?, 'host-tests', ?, 'Private Other', 'active', ?, ?)",
                    (other_repo, str(self.root / "other"), now, now),
                )
                connection.execute(
                    "INSERT INTO repository_installations(repo_id, status, startup_fenced, actor, updated_at) VALUES (?, 'installed', 0, 'test', ?)",
                    (other_repo, now),
                )

        unscoped = self.records.fleet_overview(hours=24)
        self.assertEqual(
            {item["repo_id"] for item in unscoped["repositories"]},
            {self.repo_id, other_repo},
        )
        trusted_local = self.records.fleet(
            self.request(BrokerOperation.TEST_FLEET_STATS_READ, {"hours": 24})
        )
        self.assertEqual(
            {item["repo_id"] for item in trusted_local["repositories"]},
            {self.repo_id, other_repo},
        )
        self.assertEqual(trusted_local["summary"]["repository_count"], 2)

    def test_snapshot_source_failure_exposes_only_actionable_bounded_detail(self) -> None:
        plane = PreviewTestPlane(object())
        plane.preview_error = TestPlaneTransportError(
            "test_plan_source_invalid",
            "snapshot file could not be opened safely: "
            "deploy/ceph-vault-probe/temporal_scope_probe.py: "
            "[Errno 13] Permission denied: 'temporal_scope_probe.py'",
        )
        backend = StoreBackedMutationBackend(
            self.persistence,
            object(),  # type: ignore[arg-type]
            test_plane=plane,  # type: ignore[arg-type]
        )
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW, self.preview_arguments("manual")
        )
        accepted = self.persistence.accept(preview.peer, preview.request)

        with self.assertRaises(BrokerBackendError) as raised:
            backend.execute(accepted)

        self.assertEqual(raised.exception.code, "test_plan_source_invalid")
        self.assertEqual(
            raised.exception.message,
            "Snapshot source path is unreadable: "
            "deploy/ceph-vault-probe/temporal_scope_probe.py.",
        )
        self.assertNotIn("Errno", raised.exception.message)
        persisted = self.persistence.existing_operation_disposition(accepted)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.state, "failed")
        self.assertEqual(persisted.error_code, "test_plan_source_invalid")

        plane.preview_error = TestPlaneTransportError(
            "test_plan_source_invalid", "unexpected secret at /outside/path"
        )
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW, self.preview_arguments("manual")
        )
        with self.assertRaises(BrokerBackendError) as opaque:
            backend.execute(self.persistence.accept(preview.peer, preview.request))
        self.assertNotIn("/outside/path", opaque.exception.message)

        plane.preview_error = TestPlaneTransportError(
            "snapshot_materialization_failed",
            "snapshot file is unavailable: tests.json: "
            "[Errno 2] No such file or directory: 'tests.json'",
        )
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW, self.preview_arguments("manual")
        )
        with self.assertRaises(BrokerBackendError) as missing:
            backend.execute(self.persistence.accept(preview.peer, preview.request))
        self.assertEqual(missing.exception.code, "test_plan_source_invalid")
        self.assertEqual(
            missing.exception.message,
            "Snapshot source path is unavailable: tests.json.",
        )
        self.assertIsNone(missing.exception.retry_after_seconds)

        plane.preview_error = TestPlaneTransportError(
            "not_found", "snapshot source vanished during preview"
        )
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW, self.preview_arguments("manual")
        )
        with self.assertRaises(BrokerBackendError) as vanished:
            backend.execute(self.persistence.accept(preview.peer, preview.request))
        self.assertEqual(vanished.exception.code, "test_plan_source_invalid")
        self.assertIn("writes stop", vanished.exception.message)
        self.assertNotEqual(vanished.exception.code, "test_scheduler_unavailable")

    def test_async_preview_is_exactly_repository_authorized_and_bounded(self) -> None:
        preview = self.request(
            BrokerOperation.TEST_PLAN_PREVIEW, self.preview_arguments("manual")
        )
        authorized = self.persistence.accept(preview.peer, preview.request)
        self.assertEqual(authorized.request.project_id, self.repo_id)
        self.assertEqual(authorized.request.resource_id, self.repo_id)
        self.assertEqual(
            authorized.request.arguments,
            {
                "intent": "manual",
                "temporary_root": None,
                "requested_targets": [],
                "execution_timeout_seconds": None,
                "launch_timeout_seconds": 300,
            },
        )

        with self.assertRaises(BrokerError):
            BrokerRequest.create(
                account_id="account-tests",
                project_id=self.repo_id,
                resource_id=self.repo_id,
                operation=BrokerOperation.TEST_PLAN_PREVIEW,
                arguments={"intent": "manual", "source": "client-selected"},
                authority_generation=self.generation,
            )
        with self.assertRaises(BrokerError):
            BrokerRequest.create(
                account_id="account-tests",
                project_id=self.repo_id,
                resource_id=self.repo_id,
                operation=BrokerOperation.TEST_RUN_SUBMIT,
                arguments={
                    "plan_id": "plan-1",
                    "expected_repository_id": "/client/path",
                },
                authority_generation=self.generation,
            )


if __name__ == "__main__":
    unittest.main()
