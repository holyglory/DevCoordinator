from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest

from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.store import CoordinatorStore
from devcoordinator.universal_test_transport import TestPlaneTransportError


UTC = timezone.utc
TEST_ACTOR = "codex:result-binding"


class ResultPlane:
    def __init__(self) -> None:
        self.source_run_id = "run-authorized"
        self.repository_id = "repo-tests"
        self.overrides: dict[str, dict[str, object]] = {}
        self.status_calls: list[tuple[str, str | None]] = []
        self.plan_repository_calls: list[tuple[str, str]] = []
        self.submit_calls = 0
        self.downstream_calls: list[str] = []
        self.status_error: Exception | None = None
        self.artifact_error: Exception | None = None

    def plan_repository(self, *, plan_id: str, repository_id: str) -> str:
        self.plan_repository_calls.append((plan_id, repository_id))
        return self.repository_id

    def submit(self, **_arguments):
        self.submit_calls += 1
        return {
            "schema_version": 1,
            "run_id": "run-created",
            "repository_id": self.repository_id,
            "state": "queued",
        }

    def status(self, *, run_id: str, repository_id: str):
        self.status_calls.append((run_id, repository_id))
        if self.status_error is not None:
            raise self.status_error
        override = self.overrides.get(f"status:{run_id}")
        if override is not None:
            return override
        return {
            "schema_version": 1,
            "run_id": run_id,
            "repository_id": self.repository_id,
            "state": "failed",
        }

    def runs(self, **_arguments):
        return self.overrides.get(
            "runs",
            {
                "schema_version": 1,
                "repository_id": self.repository_id,
                "runs": [
                    {
                        "run_id": self.source_run_id,
                        "repository_id": self.repository_id,
                    }
                ],
                "next_cursor": None,
            },
        )

    def events(self, **_arguments):
        return self.overrides.get(
            "events",
            {
                "schema_version": 1,
                "repository_id": self.repository_id,
                "events": [
                    {
                        "event_id": 1,
                        "repository_id": self.repository_id,
                        "run_id": self.source_run_id,
                    }
                ],
                "next_cursor": None,
            },
        )

    def summary(self, *, run_id: str, repository_id: str):
        self.downstream_calls.append("summary")
        return self.overrides.get(
            "summary",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": repository_id,
                "conclusion": "failed",
            },
        )

    def failures(self, *, run_id: str, **_arguments):
        self.downstream_calls.append("failures")
        return self.overrides.get(
            "failures",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": _arguments["repository_id"],
                "failures": [],
                "next_cursor": None,
            },
        )

    def artifacts(self, *, run_id: str, **_arguments):
        self.downstream_calls.append("artifacts")
        return self.overrides.get(
            "artifacts",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": _arguments["repository_id"],
                "artifacts": [],
                "next_cursor": None,
            },
        )

    def artifact(self, *, run_id: str, repository_id: str, artifact_id: str):
        self.downstream_calls.append("artifact")
        if self.artifact_error is not None:
            raise self.artifact_error
        return self.overrides.get(
            "artifact",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": repository_id,
                "artifact": {
                    "artifact_id": artifact_id,
                    "verified": 1,
                    "sha256": "a" * 64,
                    "storage_handle": f"test-artifact://{artifact_id}/" + "a" * 64,
                },
            },
        )

    def cases(self, *, run_id: str, **_arguments):
        self.downstream_calls.append("cases")
        return self.overrides.get(
            "cases",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": _arguments["repository_id"],
                "cases": [],
                "next_cursor": None,
            },
        )

    def cancel(self, *, run_id: str, **_arguments):
        self.downstream_calls.append("cancel")
        return self.overrides.get(
            "cancel",
            {
                "schema_version": 1,
                "run_id": run_id,
                "repository_id": _arguments["repository_id"],
                "state": "cancelled",
            },
        )

class UniversalTestResultBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "coordinator.sqlite3"
        now = datetime.now(UTC).isoformat()
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "INSERT INTO hosts(host_id, machine_fingerprint, platform, hostname, created_at, updated_at) VALUES ('host-tests', 'machine-tests', 'linux', 'tests', ?, ?)",
                    (now, now),
                )
                connection.execute(
                    "INSERT INTO repositories(repo_id, host_id, canonical_root, display_name, state, created_at, updated_at) VALUES ('repo-tests', 'host-tests', ?, 'Tests', 'active', ?, ?)",
                    (str(self.root), now, now),
                )
                connection.execute(
                    "INSERT INTO repository_installations(repo_id, status, startup_fenced, actor, updated_at) VALUES ('repo-tests', 'installed', 0, 'test', ?)",
                    (now,),
                )
        self.persistence = BrokerPersistence(self.database)
        with CoordinatorStore.open(self.database) as store:
            with store.read_transaction() as connection:
                self.generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
        self.plane = ResultPlane()
        self.backend = StoreBackedMutationBackend(
            self.persistence,
            object(),  # type: ignore[arg-type]
            test_plane=self.plane,  # type: ignore[arg-type]
        )

    def request(
        self, operation: BrokerOperation, arguments: dict[str, object]
    ) -> AcceptedBrokerRequest:
        request = BrokerRequest.create(
            account_id="account-tests",
            project_id="repo-tests",
            resource_id="repo-tests",
            operation=operation,
            arguments=arguments,
            authority_generation=self.generation,
        )
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        return self.persistence.accept(peer, request)

    def execute(self, operation: BrokerOperation, arguments: dict[str, object]):
        return self.backend.execute(self.request(operation, arguments))

    def test_submit_rejects_declared_repository_mismatch_before_plan_lookup(self) -> None:
        with self.assertRaises(BrokerBackendError) as raised:
            self.execute(
                BrokerOperation.TEST_RUN_SUBMIT,
                {
                    "plan_id": "plan-authorized",
                    "expected_repository_id": "repo-foreign",
                    "actor": TEST_ACTOR,
                },
            )

        self.assertEqual(raised.exception.code, "test_repository_mismatch")
        self.assertEqual(self.plane.plan_repository_calls, [])
        self.assertEqual(self.plane.submit_calls, 0)

    def test_submit_rejects_resolved_plan_repository_mismatch_before_creation(self) -> None:
        self.plane.repository_id = "repo-foreign"

        with self.assertRaises(BrokerBackendError) as raised:
            self.execute(
                BrokerOperation.TEST_RUN_SUBMIT,
                {
                    "plan_id": "plan-foreign",
                    "expected_repository_id": "repo-tests",
                    "actor": TEST_ACTOR,
                },
            )

        self.assertEqual(raised.exception.code, "test_repository_mismatch")
        self.assertEqual(
            self.plane.plan_repository_calls,
            [("plan-foreign", "repo-tests")],
        )
        self.assertEqual(self.plane.submit_calls, 0)

    def test_nested_run_pages_cannot_cross_repository_boundary(self) -> None:
        self.plane.overrides["runs"] = {
            "schema_version": 1,
            "repository_id": "repo-tests",
            "runs": [{"run_id": "run-foreign", "repository_id": "repo-foreign"}],
            "next_cursor": None,
        }
        with self.assertRaises(BrokerBackendError) as runs:
            self.execute(BrokerOperation.TEST_RUN_LIST, {"limit": 25})
        self.assertEqual(runs.exception.code, "test_repository_mismatch")

        with self.assertRaises(ValueError):
            BrokerOperation("test.events_read")

    def test_run_specific_reads_and_cancel_require_exact_returned_run(self) -> None:
        cases = (
            (BrokerOperation.TEST_RUN_SUMMARY, "summary", {}),
            (BrokerOperation.TEST_RUN_FAILURES, "failures", {"limit": 25}),
            (BrokerOperation.TEST_RUN_ARTIFACTS, "artifacts", {"limit": 25}),
            (
                BrokerOperation.TEST_ARTIFACT_RESOLVE,
                "artifact",
                {"artifact_id": "artifact-a"},
            ),
            (
                BrokerOperation.TEST_RUN_CANCEL,
                "cancel",
                {"reason": "operator request", "actor": TEST_ACTOR},
            ),
        )
        for operation, method, extra in cases:
            with self.subTest(operation=operation.value):
                self.plane.overrides[method] = {
                    "schema_version": 1,
                    "run_id": "run-foreign",
                    "repository_id": "repo-tests",
                }
                with self.assertRaises(BrokerBackendError) as raised:
                    self.execute(
                        operation,
                        {"run_id": self.plane.source_run_id, **extra},
                    )
                self.assertEqual(raised.exception.code, "test_run_mismatch")
                del self.plane.overrides[method]

    def test_run_specific_reads_and_cancel_reject_foreign_returned_repository(self) -> None:
        cases = (
            (BrokerOperation.TEST_RUN_SUMMARY, "summary", {}),
            (BrokerOperation.TEST_RUN_FAILURES, "failures", {"limit": 25}),
            (BrokerOperation.TEST_RUN_ARTIFACTS, "artifacts", {"limit": 25}),
            (
                BrokerOperation.TEST_ARTIFACT_RESOLVE,
                "artifact",
                {"artifact_id": "artifact-a"},
            ),
            (
                BrokerOperation.TEST_RUN_CANCEL,
                "cancel",
                {"reason": "operator request", "actor": TEST_ACTOR},
            ),
        )
        for operation, method, extra in cases:
            with self.subTest(operation=operation.value):
                self.plane.overrides[method] = {
                    "schema_version": 1,
                    "run_id": self.plane.source_run_id,
                    "repository_id": "repo-foreign",
                }
                with self.assertRaises(BrokerBackendError) as raised:
                    self.execute(
                        operation,
                        {"run_id": self.plane.source_run_id, **extra},
                    )
                self.assertEqual(raised.exception.code, "test_repository_mismatch")
                del self.plane.overrides[method]

    def test_foreign_run_binding_blocks_every_opaque_path_before_downstream_work(self) -> None:
        cases = (
            (BrokerOperation.TEST_RUN_STATUS, {}),
            (BrokerOperation.TEST_RUN_SUMMARY, {}),
            (BrokerOperation.TEST_RUN_FAILURES, {"limit": 25}),
            (BrokerOperation.TEST_RUN_ARTIFACTS, {"limit": 25}),
            (
                BrokerOperation.TEST_ARTIFACT_RESOLVE,
                {"artifact_id": "artifact-a"},
            ),
            (
                BrokerOperation.TEST_RUN_CANCEL,
                {"reason": "operator request", "actor": TEST_ACTOR},
            ),
        )
        self.plane.repository_id = "repo-foreign"

        for operation, extra in cases:
            with self.subTest(operation=operation.value):
                self.plane.status_calls.clear()
                self.plane.downstream_calls.clear()
                with self.assertRaises(BrokerBackendError) as raised:
                    self.execute(
                        operation,
                        {"run_id": self.plane.source_run_id, **extra},
                    )
                self.assertEqual(raised.exception.code, "test_repository_mismatch")
                self.assertEqual(
                    self.plane.status_calls,
                    [(self.plane.source_run_id, "repo-tests")],
                )
                self.assertEqual(self.plane.downstream_calls, [])

    def test_retry_result_is_reauthorized_against_new_run_repository(self) -> None:
        with self.assertRaises(ValueError):
            BrokerOperation("test.run_retry")

    def test_remote_not_found_is_not_reported_as_scheduler_unavailable(self) -> None:
        self.plane.status_error = TestPlaneTransportError(
            "not_found", "test run does not exist"
        )

        with self.assertRaises(BrokerBackendError) as raised:
            self.execute(
                BrokerOperation.TEST_RUN_STATUS,
                {"run_id": "run-missing"},
            )

        self.assertEqual(raised.exception.code, "test_run_not_found")

    def test_missing_artifact_is_not_mislabeled_as_missing_run(self) -> None:
        self.plane.artifact_error = TestPlaneTransportError(
            "not_found", "test artifact does not exist"
        )

        with self.assertRaises(BrokerBackendError) as raised:
            self.execute(
                BrokerOperation.TEST_ARTIFACT_RESOLVE,
                {"run_id": self.plane.source_run_id, "artifact_id": "artifact-missing"},
            )

        self.assertEqual(raised.exception.code, "test_artifact_not_found")
        self.assertEqual(
            self.plane.status_calls,
            [(self.plane.source_run_id, "repo-tests")],
        )

    def test_valid_results_preserve_public_contract(self) -> None:
        listed = self.execute(BrokerOperation.TEST_RUN_LIST, {"limit": 25})
        self.assertEqual(listed["runs"][0]["run_id"], self.plane.source_run_id)
        summary = self.execute(
            BrokerOperation.TEST_RUN_SUMMARY, {"run_id": self.plane.source_run_id}
        )
        self.assertEqual(summary["repository_id"], "repo-tests")
        artifact = self.execute(
            BrokerOperation.TEST_ARTIFACT_RESOLVE,
            {"run_id": self.plane.source_run_id, "artifact_id": "artifact-a"},
        )
        self.assertEqual(artifact["artifact"]["artifact_id"], "artifact-a")
        self.assertEqual(artifact["repository_id"], "repo-tests")

    def test_retired_evidence_consumption_is_not_a_broker_operation(self) -> None:
        with self.assertRaises(ValueError):
            BrokerOperation("test.evidence_consume")


if __name__ == "__main__":
    unittest.main()
