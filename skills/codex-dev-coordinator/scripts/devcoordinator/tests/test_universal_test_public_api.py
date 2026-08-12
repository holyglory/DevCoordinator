from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
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
from devcoordinator.broker_backend import (
    _require_preview_source_policy,
    _test_run_actor,
)
from devcoordinator.universal_test_contract import SourceMode
from devcoordinator.universal_test_planner import SourceIdentity
from devcoordinator.universal_test_store import TestStoreContractError
from devcoordinator.tests.test_universal_test_store_reads import selected_plan
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_store import UniversalTestStore
from devcoordinator.universal_test_transport import (
    TEST_EVENTS_READ,
    TEST_ARTIFACT_RESOLVE,
    TEST_PLAN_REPOSITORY,
    TEST_RUN_ARTIFACTS,
    TEST_RUN_CANCEL,
    TEST_RUN_CASES,
    TEST_RUN_FAILURES,
    TEST_RUN_LIST,
    TEST_RUN_RETRY,
    TEST_RUN_STATUS,
    TEST_RUN_SUMMARY,
    TestPlaneDispatcher,
)


def operation_id() -> str:
    return str(uuid.uuid4())


def broker_request(
    operation: BrokerOperation, arguments: dict[str, object]
) -> BrokerRequest:
    return BrokerRequest.create(
        account_id="account-tests",
        project_id="repo-tests",
        resource_id="repo-tests",
        operation=operation,
        arguments=arguments,
        authority_generation="generation-tests",
    )


class UniversalTestPublicReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = UniversalTestStore.create(
            Path(self.temporary.name) / "tests.sqlite3"
        )
        self.adapter = StoreTestPlaneAdapter(self.store)
        self.plan = selected_plan()
        self.adapter.register_plan(self.plan.to_document())
        self.submission = self.adapter.submit(
            plan_id=self.plan.plan_id,
            repository_id="repo-tests",
            operation_id=operation_id(),
            actor="codex:test",
            owner_uid=1001,
        )

    def test_adapter_projects_run_history_cases_and_events(self) -> None:
        run_id = str(self.submission["run_id"])
        history = self.adapter.runs(repository_id="repo-tests", limit=1)
        self.assertEqual(history["repository_id"], "repo-tests")
        self.assertEqual(history["runs"][0]["run_id"], run_id)
        self.assertEqual(history["next_cursor"], run_id)

        cases = self.adapter.cases(
            run_id=run_id,
            repository_id="repo-tests",
            after=0,
            limit=25,
        )
        self.assertEqual(cases, {
            "schema_version": 1,
            "repository_id": "repo-tests",
            "run_id": run_id,
            "cases": [],
            "next_cursor": None,
        })
        events = self.adapter.events(
            repository_id="repo-tests", after_event_id=0, limit=200
        )
        self.assertEqual(events["repository_id"], "repo-tests")
        self.assertGreaterEqual(len(events["events"]), 1)
        self.assertIsNone(events["next_cursor"])

    def test_transport_dispatches_cursorable_public_reads(self) -> None:
        run_id = str(self.submission["run_id"])
        dispatcher = TestPlaneDispatcher(self.adapter)

        def dispatch(operation: str, arguments: dict[str, object]):
            response = dispatcher.dispatch(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": operation_id(),
                        "operation": operation,
                        "arguments": arguments,
                    }
                ).encode(),
                peer_uid=1001,
            )
            self.assertTrue(response["ok"], response)
            return response["result"]

        self.assertEqual(
            dispatch(
                TEST_RUN_LIST,
                {"repository_id": "repo-tests", "limit": 25},
            )["runs"][0]["run_id"],
            run_id,
        )
        self.assertEqual(
            dispatch(TEST_RUN_CASES, {
                "run_id": run_id,
                "repository_id": "repo-tests",
                "after": 0,
                "limit": 25,
            })[
                "cases"
            ],
            [],
        )
        self.assertEqual(
            dispatch(
                TEST_EVENTS_READ,
                {"repository_id": "repo-tests", "after_event_id": 0, "limit": 200},
            )["repository_id"],
            "repo-tests",
        )

    def test_transport_rejects_every_unscoped_plan_and_run_operation(self) -> None:
        dispatcher = TestPlaneDispatcher(self.adapter)
        old_arguments = (
            (TEST_PLAN_REPOSITORY, {"plan_id": self.plan.plan_id}),
            (TEST_RUN_STATUS, {"run_id": str(self.submission["run_id"])}),
            (TEST_RUN_SUMMARY, {"run_id": str(self.submission["run_id"])}),
            (TEST_RUN_FAILURES, {"run_id": str(self.submission["run_id"])}),
            (TEST_RUN_ARTIFACTS, {"run_id": str(self.submission["run_id"])}),
            (
                TEST_ARTIFACT_RESOLVE,
                {
                    "run_id": str(self.submission["run_id"]),
                    "artifact_id": "artifact-retired",
                },
            ),
            (TEST_RUN_CASES, {"run_id": str(self.submission["run_id"])}),
            (
                TEST_RUN_CANCEL,
                {
                    "run_id": str(self.submission["run_id"]),
                    "actor": "codex:test",
                    "reason": "retired contract",
                    "operation_id": operation_id(),
                },
            ),
            (
                TEST_RUN_RETRY,
                {
                    "run_id": str(self.submission["run_id"]),
                    "actor": "codex:test",
                    "failed_only": True,
                    "operation_id": operation_id(),
                },
            ),
        )
        for operation, arguments in old_arguments:
            with self.subTest(operation=operation):
                response = dispatcher.dispatch(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "request_id": operation_id(),
                            "operation": operation,
                            "arguments": arguments,
                        }
                    ).encode(),
                    peer_uid=1001,
                )
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], "invalid_request")

    def test_broker_arguments_are_exact_and_bounded(self) -> None:
        listed = broker_request(BrokerOperation.TEST_RUN_LIST, {})
        self.assertEqual(listed.arguments, {"limit": 50})
        events = broker_request(BrokerOperation.TEST_EVENTS_READ, {})
        self.assertEqual(events.arguments, {"after_event_id": 0, "limit": 200})
        cases = broker_request(
            BrokerOperation.TEST_RUN_CASES,
            {"run_id": "run-tests", "after": 41, "limit": 25},
        )
        self.assertEqual(cases.arguments["after"], 41)
        delegated = BrokerRequest.create(
            account_id="devcoordinator-api",
            project_id="repo-tests",
            resource_id="repo-tests",
            operation=BrokerOperation.TEST_RUN_SUBMIT,
            arguments={
                "plan_id": "plan-tests",
                "expected_repository_id": "repo-tests",
                "actor": "google:user@example.com",
            },
        )
        self.assertEqual(
            delegated.arguments["actor"], "google:user@example.com"
        )
        cancelled = broker_request(
            BrokerOperation.TEST_RUN_CANCEL,
            {
                "run_id": "run-tests",
                "reason": "requested",
                "actor": "codex:thread-1",
            },
        )
        retried = broker_request(
            BrokerOperation.TEST_RUN_RETRY,
            {
                "run_id": "run-tests",
                "failed_only": True,
                "actor": "codex:thread-1",
            },
        )
        self.assertEqual(cancelled.arguments["actor"], "codex:thread-1")
        self.assertEqual(retried.arguments["actor"], "codex:thread-1")

        with self.assertRaises(BrokerError):
            broker_request(BrokerOperation.TEST_RUN_LIST, {"limit": 201})
        with self.assertRaises(BrokerError):
            broker_request(BrokerOperation.TEST_EVENTS_READ, {"after_event_id": -1})
        with self.assertRaises(BrokerError):
            broker_request(
                BrokerOperation.TEST_RUN_CASES,
                {"run_id": "run-tests", "after": "41"},
            )
        with self.assertRaises(BrokerError):
            broker_request(
                BrokerOperation.TEST_RUN_SUBMIT,
                {
                    "plan_id": "plan-tests",
                    "expected_repository_id": "repo-tests",
                    "actor": "x" * 257,
                },
            )
        with self.assertRaises(BrokerError):
            broker_request(
                BrokerOperation.TEST_RUN_SUBMIT,
                {
                    "plan_id": "plan-tests",
                    "expected_repository_id": "repo-tests",
                    "actor": "codex:thread-1",
                    "requested_actor": "codex:retired",
                },
            )

        missing_actor_cases = (
            (
                BrokerOperation.TEST_RUN_SUBMIT,
                {
                    "plan_id": "plan-tests",
                    "expected_repository_id": "repo-tests",
                },
            ),
            (
                BrokerOperation.TEST_RUN_CANCEL,
                {"run_id": "run-tests", "reason": "requested"},
            ),
            (
                BrokerOperation.TEST_RUN_RETRY,
                {"run_id": "run-tests", "failed_only": True},
            ),
        )
        for operation, arguments in missing_actor_cases:
            with self.subTest(operation=operation.value), self.assertRaises(
                BrokerError
            ) as raised:
                broker_request(operation, arguments)
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_google_actor_delegation_is_bound_to_the_protected_api_account(self) -> None:
        peer = PeerCredentials(uid=1234, gid=1234, pid=99)

        def authorized(
            account_id: str,
            actor: str,
            operation: BrokerOperation = BrokerOperation.TEST_RUN_SUBMIT,
        ):
            arguments = (
                {
                    "plan_id": "plan-tests",
                    "expected_repository_id": "repo-tests",
                }
                if operation is BrokerOperation.TEST_RUN_SUBMIT
                else (
                    {"run_id": "run-tests", "reason": "requested"}
                    if operation is BrokerOperation.TEST_RUN_CANCEL
                    else {"run_id": "run-tests", "failed_only": True}
                )
            )
            arguments["actor"] = actor
            return AcceptedBrokerRequest(
                peer=peer,
                request=BrokerRequest.create(
                    account_id=account_id,
                    project_id="repo-tests",
                    resource_id="repo-tests",
                    operation=operation,
                    arguments=arguments,
                ),
            )

        self.assertEqual(
            _test_run_actor(authorized("account-tests", "codex:thread-1")),
            "codex:thread-1",
        )
        self.assertEqual(
            _test_run_actor(authorized("devcoordinator-api", "codex:thread-2")),
            "codex:thread-2",
        )
        self.assertEqual(
            _test_run_actor(authorized("devcoordinator-api", "codex:uid:1234")),
            "codex:uid:1234",
        )
        for operation in (
            BrokerOperation.TEST_RUN_CANCEL,
            BrokerOperation.TEST_RUN_RETRY,
        ):
            with self.subTest(operation=operation):
                self.assertEqual(
                    _test_run_actor(
                        authorized("account-tests", "codex:thread-1", operation)
                    ),
                    "codex:thread-1",
                )
        self.assertEqual(
            _test_run_actor(
                authorized("devcoordinator-api", "google:user+console@example.com")
            ),
            "google:user+console@example.com",
        )
        with self.assertRaises(BrokerBackendError) as denied:
            _test_run_actor(authorized("account-tests", "google:user@example.com"))
        self.assertEqual(
            denied.exception.code, "test_google_actor_delegation_denied"
        )
        with self.assertRaises(BrokerBackendError) as invalid:
            _test_run_actor(
                authorized("devcoordinator-api", "google:User@example.com")
            )
        self.assertEqual(invalid.exception.code, "test_actor_invalid")
        for actor in ("codex:has space", "codex:/root", "agent", "codex:"):
            with self.subTest(actor=actor), self.assertRaises(
                BrokerBackendError
            ) as malformed:
                _test_run_actor(authorized("devcoordinator-api", actor))
            self.assertEqual(malformed.exception.code, "test_actor_invalid")

        registration = AcceptedBrokerRequest(
            peer=peer,
            request=BrokerRequest.create(
                account_id="devcoordinator-api",
                project_id="repo-tests",
                resource_id="repo-tests",
                operation=BrokerOperation.TEST_PLAN_REGISTER,
                arguments={
                    "plan": {},
                    "manifest": {},
                    "actor": "software-owned-delivery",
                },
            ),
        )
        self.assertEqual(
            _test_run_actor(registration),
            "broker:devcoordinator-api:uid:1234",
        )

    def test_preview_source_policy_matches_intent_without_accepting_browser_paths(self) -> None:
        live = SourceIdentity(
            mode=SourceMode.LIVE,
            repository_id="repo-tests",
            content_fingerprint="1" * 64,
            original_root="/srv/repo-tests",
            temporary_root=None,
            snapshot_id=None,
        )
        immutable = SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id="repo-tests",
            content_fingerprint="2" * 64,
            original_root="/srv/repo-tests",
            temporary_root=None,
            snapshot_id="snapshot-" + "3" * 32,
        )
        for intent, source in (
            ("change", live),
            ("checkpoint", live),
            ("handoff", immutable),
            ("release", immutable),
            ("manual", immutable),
        ):
            _require_preview_source_policy(
                SimpleNamespace(intent=intent, source=source)
            )

        with self.assertRaises(TestStoreContractError):
            _require_preview_source_policy(
                SimpleNamespace(intent="change", source=immutable)
            )
        with self.assertRaises(TestStoreContractError):
            _require_preview_source_policy(
                SimpleNamespace(intent="manual", source=live)
            )
        with self.assertRaises(TestStoreContractError):
            _require_preview_source_policy(
                SimpleNamespace(
                    intent="manual",
                    source=SourceIdentity(
                        mode=SourceMode.LIVE,
                        repository_id="repo-tests",
                        content_fingerprint="4" * 64,
                        original_root="/srv/repo-tests",
                        temporary_root="/srv/repo-tests-worktree",
                        snapshot_id=None,
                    ),
                )
            )


if __name__ == "__main__":
    unittest.main()
