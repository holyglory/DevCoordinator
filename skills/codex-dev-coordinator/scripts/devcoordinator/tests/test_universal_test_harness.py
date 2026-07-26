from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerBackendError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.store import CoordinatorStore
from devcoordinator.test_records import CoordinatorTestRecords
from devcoordinator.test_runner import TestHarnessError, load_manifest


class UniversalTestHarnessTests(unittest.TestCase):
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
        self.persistence = BrokerPersistence(self.database)
        with CoordinatorStore.open(self.database) as store:
            now = datetime.now(UTC).isoformat()
            with store.immediate_transaction() as connection:
                self.generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT INTO broker_acl_principals(uid, account_id, enabled, updated_at) VALUES (?, 'account-tests', 1, ?)",
                    (os.geteuid(), now),
                )
                connection.execute(
                    "INSERT INTO broker_repository_enrollments(uid, repo_id, account_id, enabled, issued_at, valid_until_epoch, updated_at) VALUES (?, ?, 'account-tests', 1, ?, ?, ?)",
                    (os.geteuid(), self.repo_id, now, 4_102_444_800, now),
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
    ) -> AuthorizedBrokerRequest:
        return AuthorizedBrokerRequest(
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
        authorized = self.persistence.authorize(
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
        authorized_finish = self.persistence.authorize(
            finish_request.peer, finish_request.request
        )
        self.assertEqual(backend.execute(authorized_finish)["status"], "passed")

        wrong_resource = BrokerRequest.create(
            account_id="account-tests",
            project_id=self.repo_id,
            resource_id="another-repository",
            operation=BrokerOperation.TEST_STATS_READ,
            arguments={"days": 30, "limit": 25},
            authority_generation=self.generation,
        )
        with self.assertRaises(Exception):
            self.persistence.authorize(start_request.peer, wrong_resource)


if __name__ == "__main__":
    unittest.main()
