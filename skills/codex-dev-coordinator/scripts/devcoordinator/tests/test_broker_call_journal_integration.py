from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
)
from devcoordinator.call_journal import RollingCallJournal, read_call_records


class _Authorizer:
    def authorize(
        self, peer: PeerCredentials, request: BrokerRequest
    ) -> AuthorizedBrokerRequest:
        return AuthorizedBrokerRequest(peer=peer, request=request)


class _Writer:
    def execute(self, authorized: AuthorizedBrokerRequest) -> dict[str, object]:
        return {
            "state": "complete",
            "run_id": authorized.request.arguments.get("run_id", "run-none"),
        }


class _ExplodingJournal:
    def record(self, record: object) -> bool:
        del record
        raise OSError("journal unavailable")


class _TypedAdoptionFailureWriter:
    def execute(self, authorized: AuthorizedBrokerRequest) -> dict[str, object]:
        raise BrokerError(
            "repository_context_changed",
            "The proven repository context changed before adoption.",
            operation_id=authorized.request.operation_id,
        )


class BrokerCallJournalIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-broker-call-journal-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "calls.jsonl"
        self.peer = PeerCredentials(uid=1000, gid=1003, pid=12345)

    def _service(self) -> BrokerService:
        return BrokerService(
            _Authorizer(),
            _Writer(),
            call_journal=RollingCallJournal(
                self.path,
                max_bytes=8192,
                backups=1,
            ),
        )

    def _records(self) -> list[dict[str, object]]:
        return list(read_call_records(self.path, backups=1))

    def test_decoded_call_records_received_and_completed_with_one_call_id(self) -> None:
        request = BrokerRequest.create(
            account_id="account-a",
            project_id="project-a",
            resource_id="resource-a",
            operation=BrokerOperation.TEST_RUN_STATUS,
            arguments={"run_id": "run-a"},
            repository_generation=7,
        )

        reply = self._service().reply_for_document(self.peer, request.to_wire())

        self.assertTrue(reply["ok"])
        records = self._records()
        self.assertEqual(
            [record["phase"] for record in records], ["received", "completed"]
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[1]["operation"], "test.run_status")
        self.assertEqual(records[1]["project_id"], "project-a")
        self.assertEqual(records[1]["request"], {"run_id": "run-a"})
        self.assertEqual(records[1]["result"], {"run_id": "run-a", "state": "complete"})

    def test_malformed_payload_is_recorded_without_the_raw_payload(self) -> None:
        payload = b'{"authorization":"Bearer definitely-secret"'

        reply = json.loads(self._service().reply_for_payload(self.peer, payload))

        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "invalid_json")
        records = self._records()
        self.assertEqual(
            [record["phase"] for record in records], ["received", "rejected"]
        )
        self.assertEqual(records[-1]["code"], "invalid_json")
        retained = "\n".join(
            path.read_text() for path in self.path.parent.glob("calls.jsonl*")
        )
        self.assertNotIn("definitely-secret", retained)
        self.assertNotIn("authorization", retained.lower())

    def test_transport_rejections_cover_peer_frame_timeout_and_capacity(self) -> None:
        service = self._service()
        for index, code in enumerate(
            (
                "peer_credentials_unavailable",
                "frame_too_large",
                "request_timeout",
                "server_busy",
            )
        ):
            service.record_transport_rejection(
                peer=None,
                call_id=f"transport-{index}",
                started_at=time.monotonic(),
                code=code,
                message="bounded transport rejection",
            )

        records = self._records()
        rejected = [record for record in records if record["phase"] == "rejected"]
        self.assertEqual(
            [record["code"] for record in rejected],
            [
                "peer_credentials_unavailable",
                "frame_too_large",
                "request_timeout",
                "server_busy",
            ],
        )
        self.assertEqual(rejected[-2]["outcome"], "timeout")
        self.assertEqual(rejected[-1]["outcome"], "busy")

    def test_journal_failure_does_not_change_call_outcome(self) -> None:
        service = BrokerService(
            _Authorizer(),
            _Writer(),
            call_journal=_ExplodingJournal(),  # type: ignore[arg-type]
        )
        request = BrokerRequest.create(
            account_id="account-a",
            project_id="project-a",
            resource_id="resource-a",
            operation=BrokerOperation.TEST_RUN_STATUS,
            arguments={"run_id": "run-a"},
        )

        with self.assertLogs("devcoordinator.broker", level="ERROR") as captured:
            reply = service.reply_for_document(self.peer, request.to_wire())

        self.assertTrue(reply["ok"])
        self.assertEqual(len(captured.records), 2)

    def test_repository_adoption_journal_preserves_actionable_broker_failure(self) -> None:
        service = BrokerService(
            _Authorizer(),
            _TypedAdoptionFailureWriter(),
            call_journal=RollingCallJournal(
                self.path,
                max_bytes=8192,
                backups=1,
            ),
        )
        operation_id = "00000000-0000-4000-8000-000000000099"
        request = BrokerRequest.create(
            account_id="account-a",
            project_id="project-a",
            resource_id="project-a",
            operation=BrokerOperation.REPOSITORY_ENSURE,
            arguments={
                "agent": "codex:task:first-use",
                "canonical_root": "/repo/new-project",
                "owner_uid": 1000,
                "project_kind": "primary",
            },
            operation_id=operation_id,
        )

        reply = service.reply_for_document(self.peer, request.to_wire())

        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "repository_context_changed")
        completed = self._records()[-1]
        self.assertEqual(completed["operation"], "repository.ensure")
        self.assertEqual(completed["operation_id"], operation_id)
        self.assertEqual(completed["code"], "repository_context_changed")
        self.assertEqual(
            completed["message"],
            "The proven repository context changed before adoption.",
        )
        self.assertNotEqual(completed["code"], "mutation_failed")


if __name__ == "__main__":
    unittest.main()
