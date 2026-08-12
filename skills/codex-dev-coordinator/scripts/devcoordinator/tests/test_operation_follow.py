"""Focused contracts for the schema-free durable operation projection."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import BrokerError, BrokerOperation  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    OPERATION_FOLLOW_MAX_BYTES,
)
from devcoordinator.broker_profile import (  # noqa: E402
    BrokerClientProfile,
    BrokerRepositoryProfile,
)
from devcoordinator.store import CoordinatorStore  # noqa: E402
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    CONTAINER_ID,
    PROJECT_ID,
    peer_for,
    request_for,
    seed_store_backed_broker,
    store_backed_service,
)


FOLLOWED_OPERATION_ID = "11111111-1111-4111-8111-111111111111"
FOLLOW_REQUEST_ID = "22222222-2222-4222-8222-222222222222"
PLAN_ID = "33333333-3333-4333-8333-333333333333"
RUN_ID = "44444444-4444-4444-8444-444444444444"


class OperationFollowWireTests(unittest.TestCase):
    def test_wire_requires_one_exact_canonical_operation_id(self) -> None:
        request = request_for(
            BrokerOperation.OPERATION_FOLLOW,
            resource_id=PROJECT_ID,
            arguments={"operation_id": FOLLOWED_OPERATION_ID},
        )
        self.assertEqual(
            request.arguments, {"operation_id": FOLLOWED_OPERATION_ID}
        )

        invalid_arguments = (
            {},
            {"operation_id": FOLLOWED_OPERATION_ID, "path": "/private"},
            {"operation_id": "not-a-uuid"},
            {"operation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".upper()},
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments), self.assertRaises(
                BrokerError
            ) as raised:
                request_for(
                    BrokerOperation.OPERATION_FOLLOW,
                    resource_id=PROJECT_ID,
                    arguments=arguments,
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")


class OperationFollowPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-operation-follow-", dir="/tmp"
        )
        self.persistence, actions = seed_store_backed_broker(
            Path(self.temporary.name)
        )
        self.service = store_backed_service(self.persistence, actions)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reserve_operation(self) -> None:
        mutation = request_for(
            BrokerOperation.DOCKER_STOP,
            resource_id=CONTAINER_ID,
            operation_id=FOLLOWED_OPERATION_ID,
        )
        authorized = self.persistence.accept(peer_for(), mutation)
        disposition = self.persistence.reserve_operation(authorized)
        self.assertEqual(disposition.state, "execute")

    def follow_request(self):
        return request_for(
            BrokerOperation.OPERATION_FOLLOW,
            resource_id=PROJECT_ID,
            arguments={"operation_id": FOLLOWED_OPERATION_ID},
            operation_id=FOLLOW_REQUEST_ID,
        )

    def follow(self) -> dict[str, object]:
        return self.service.reply_for_document(
            peer_for(), self.follow_request().to_wire()
        )

    def test_terminal_projection_is_bounded_path_free_and_read_only(self) -> None:
        self.reserve_operation()
        self.persistence.finish_operation(
            FOLLOWED_OPERATION_ID,
            result={
                "plan_id": PLAN_ID,
                "run_id": RUN_ID,
                "path": "/private/repository/secret.log",
                "payload": "sensitive" * 4_096,
            },
        )
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                for ordinal in range(1, 25):
                    connection.execute(
                        """
                        INSERT INTO operation_targets(
                            operation_id, ordinal, target_kind, target_id,
                            action, immutable_fingerprint, phase, status
                        ) VALUES (?, ?, 'container', ?, 'docker.stop', ?,
                                  'completed', 'succeeded')
                        """,
                        (
                            FOLLOWED_OPERATION_ID,
                            ordinal,
                            f"target-{ordinal}-" + "x" * 96,
                            f"fingerprint-{ordinal}",
                        ),
                    )

        with mock.patch.object(
            self.persistence,
            "operation_follow",
            wraps=self.persistence.operation_follow,
        ) as followed:
            first = self.follow()
            second = self.follow()

        self.assertTrue(first["ok"], first)
        self.assertEqual(second, first)
        self.assertEqual(followed.call_count, 2)
        self.assertEqual(first["operation_id"], FOLLOW_REQUEST_ID)
        result = first["result"]
        self.assertEqual(result["operation_id"], FOLLOWED_OPERATION_ID)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["phase"], "completed")
        self.assertEqual(result["kind"], "broker.docker.stop")
        self.assertEqual(result["plan_id"], PLAN_ID)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["outcome_certainty"], "certain")
        self.assertIsNone(result["error_classification"])
        self.assertIsNone(result["next_transition"])
        self.assertEqual(result["target_count"], 25)
        self.assertTrue(result["target_ids_truncated"])
        self.assertLess(len(result["target_ids"]), result["target_count"])
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), OPERATION_FOLLOW_MAX_BYTES)
        self.assertNotIn(b"/private", encoded)
        self.assertNotIn(b"sensitive", encoded)
        self.assertNotIn(b"payload", encoded)

    def test_running_and_uncertain_states_expose_only_next_decision(self) -> None:
        self.reserve_operation()

        running = self.follow()
        self.assertTrue(running["ok"], running)
        self.assertEqual(running["result"]["status"], "running")
        self.assertEqual(running["result"]["outcome_certainty"], "pending")
        self.assertEqual(running["result"]["next_transition"], "wait")
        self.assertNotIn("plan_id", running["result"])
        self.assertNotIn("run_id", running["result"])

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE operations
                    SET status = 'needs_attention',
                        phase = 'reconciliation_required',
                        error_code = 'operation_outcome_uncertain',
                        error_message = '/private/uncertain.log'
                    WHERE operation_id = ?
                    """,
                    (FOLLOWED_OPERATION_ID,),
                )
                connection.execute(
                    """
                    UPDATE operation_targets
                    SET status = 'failed', phase = 'reconciliation_required'
                    WHERE operation_id = ?
                    """,
                    (FOLLOWED_OPERATION_ID,),
                )

        uncertain = self.follow()
        self.assertTrue(uncertain["ok"], uncertain)
        result = uncertain["result"]
        self.assertEqual(result["error_classification"], "outcome_uncertain")
        self.assertEqual(result["outcome_certainty"], "uncertain")
        self.assertEqual(result["next_transition"], "reconcile")
        self.assertNotIn("/private", json.dumps(result, sort_keys=True))

    def test_follow_is_host_wide_for_trusted_local_callers(self) -> None:
        self.reserve_operation()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_operation_requests SET account_id = ?
                    WHERE operation_id = ?
                    """,
                    ("another-account", FOLLOWED_OPERATION_ID),
                )
        cross_account = self.follow()
        unknown = request_for(
            BrokerOperation.OPERATION_FOLLOW,
            resource_id=PROJECT_ID,
            arguments={
                "operation_id": "55555555-5555-4555-8555-555555555555"
            },
        )
        unknown_reply = self.service.reply_for_document(
            peer_for(), unknown.to_wire()
        )

        self.assertTrue(cross_account["ok"], cross_account)
        self.assertEqual(
            cross_account["result"]["operation_id"], FOLLOWED_OPERATION_ID
        )
        self.assertFalse(unknown_reply["ok"], unknown_reply)
        self.assertEqual(
            unknown_reply["error"]["code"], "operation_follow_unavailable"
        )


class OperationFollowProfileTests(unittest.TestCase):
    def test_profile_targets_exact_repository_and_returns_projection(self) -> None:
        repository = BrokerRepositoryProfile(
            canonical_root="/repositories/alpha",
            repo_id=PROJECT_ID,
            generation=0,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        expected = {"operation_id": FOLLOWED_OPERATION_ID, "status": "running"}
        profile = mock.Mock()
        profile.call.return_value = (FOLLOW_REQUEST_ID, expected)

        result = BrokerClientProfile.operation_follow(
            profile,
            repository=repository,
            operation_id=FOLLOWED_OPERATION_ID,
        )

        self.assertEqual(result, expected)
        profile.call.assert_called_once_with(
            repository=repository,
            resource_id=PROJECT_ID,
            operation=BrokerOperation.OPERATION_FOLLOW,
            arguments={"operation_id": FOLLOWED_OPERATION_ID},
        )


if __name__ == "__main__":
    unittest.main()
