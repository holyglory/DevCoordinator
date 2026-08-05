"""Broker-level admission drain and exact-resume regression tests."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.broker_persistence import StoreBackedAuthorizer  # noqa: E402
from devcoordinator.store import CoordinatorStore  # noqa: E402
from devcoordinator.universal_test_admission import (  # noqa: E402
    TestSubmissionAdmissionGate,
    install_legacy_test_admission_schema,
)
from devcoordinator.tests.test_broker import (  # noqa: E402
    PROJECT_ID,
    peer_for,
    request_for,
    seed_store_backed_broker,
)


class _SubmissionPlane:
    def __init__(self) -> None:
        self.submissions = 0

    def plan_repository(self, *, plan_id: str, repository_id: str) -> str:
        if plan_id != "plan-current":
            raise AssertionError("unexpected plan")
        if repository_id != PROJECT_ID:
            raise AssertionError("unexpected repository")
        return PROJECT_ID

    def submit(self, **_arguments):
        self.submissions += 1
        return {
            "schema_version": 1,
            "repository_id": PROJECT_ID,
            "run_id": f"run-{self.submissions}",
            "state": "queued",
        }


class BrokerTestAdmissionDrainTests(unittest.TestCase):
    def test_broker_rejects_submissions_while_fenced_and_exact_clear_resumes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".broker-admission-test-", dir=Path.cwd()
        ) as temporary:
            root = Path(temporary).resolve()
            persistence, actions = seed_store_backed_broker(root)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                generation = store.metadata.database_generation
                with store.immediate_transaction() as connection:
                    install_legacy_test_admission_schema(connection)

            gate = TestSubmissionAdmissionGate()
            plane = _SubmissionPlane()
            backend = StoreBackedMutationBackend(
                persistence,
                actions,
                test_plane=plane,
                test_submission_gate=gate,
            )
            service = BrokerService(
                StoreBackedAuthorizer(persistence),
                SerializedMutationWriter(backend, test_submission_gate=gate),
            )
            peer = peer_for()

            begin = BrokerRequest.create(
                account_id="devcoordinator-authority",
                project_id="authority",
                resource_id="test-admission",
                repository_generation=0,
                authority_generation=generation,
                operation=BrokerOperation.TEST_ADMISSION_DRAIN_BEGIN,
                arguments={"purpose": "legacy-test-history-cutover"},
            )
            begin_reply = service.reply_for_document(peer, begin.to_wire())
            self.assertTrue(begin_reply["ok"], begin_reply)
            proof = begin_reply["result"]["proof"]
            self.assertEqual(begin_reply["result"]["state"], "drained")
            self.assertEqual(proof["authority_generation"], generation)
            self.assertEqual(proof["activated_by_uid"], os.geteuid())
            self.assertEqual(proof["observed_inflight_submissions"], 0)

            blocked = request_for(
                BrokerOperation.TEST_RUN_SUBMIT,
                resource_id=PROJECT_ID,
                arguments={
                    "plan_id": "plan-current",
                    "expected_repository_id": PROJECT_ID,
                    "actor": "codex:admission-test",
                },
            )
            blocked_reply = service.reply_for_document(peer, blocked.to_wire())
            self.assertFalse(blocked_reply["ok"])
            self.assertEqual(
                blocked_reply["error"]["code"], "test_admission_drained"
            )
            self.assertEqual(plane.submissions, 0)

            stale_clear = BrokerRequest.create(
                account_id="devcoordinator-authority",
                project_id="authority",
                resource_id="test-admission",
                repository_generation=0,
                authority_generation=generation,
                operation=BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR,
                arguments={
                    "drain_id": proof["drain_id"],
                    "proof_sha256": "0" * 64,
                },
            )
            stale_reply = service.reply_for_document(peer, stale_clear.to_wire())
            self.assertFalse(stale_reply["ok"])
            self.assertEqual(
                stale_reply["error"]["code"], "test_admission_fence_conflict"
            )

            still_blocked = request_for(
                BrokerOperation.TEST_RUN_SUBMIT,
                resource_id=PROJECT_ID,
                arguments={
                    "plan_id": "plan-current",
                    "expected_repository_id": PROJECT_ID,
                    "actor": "codex:admission-test",
                },
            )
            self.assertEqual(
                service.reply_for_document(peer, still_blocked.to_wire())["error"][
                    "code"
                ],
                "test_admission_drained",
            )

            clear = BrokerRequest.create(
                account_id="devcoordinator-authority",
                project_id="authority",
                resource_id="test-admission",
                repository_generation=0,
                authority_generation=generation,
                operation=BrokerOperation.TEST_ADMISSION_DRAIN_CLEAR,
                arguments={
                    "drain_id": proof["drain_id"],
                    "proof_sha256": proof["proof_sha256"],
                },
            )
            clear_reply = service.reply_for_document(peer, clear.to_wire())
            self.assertTrue(clear_reply["ok"], clear_reply)
            self.assertEqual(clear_reply["result"]["state"], "open")

            resumed = request_for(
                BrokerOperation.TEST_RUN_SUBMIT,
                resource_id=PROJECT_ID,
                arguments={
                    "plan_id": "plan-current",
                    "expected_repository_id": PROJECT_ID,
                    "actor": "codex:admission-test",
                },
            )
            resumed_reply = service.reply_for_document(peer, resumed.to_wire())
            self.assertTrue(resumed_reply["ok"], resumed_reply)
            self.assertEqual(resumed_reply["result"]["run_id"], "run-1")
            self.assertEqual(plane.submissions, 1)


if __name__ == "__main__":
    unittest.main()
