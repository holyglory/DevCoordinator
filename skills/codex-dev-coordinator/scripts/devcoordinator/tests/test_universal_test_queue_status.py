from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest import mock

from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
    _broker_client_timeout_seconds,
)
from devcoordinator.universal_test_service import (
    MAX_TEST_PLANE_RESPONSE_BYTES,
    StoreTestPlaneAdapter,
)
from devcoordinator.universal_test_store import (
    TestStoreContractError,
    UniversalTestStore,
)
from devcoordinator.universal_test_transport import (
    TEST_QUEUE_STATUS,
    TEST_QUEUE_STATUS_READ_TIMEOUT_SECONDS,
    TestPlaneDispatcher,
    UnixTestPlaneClient,
)


REPOSITORY_ID = "repo-queue-status"


def accepted_queue_request(*, expected_repository_id: str) -> AcceptedBrokerRequest:
    return AcceptedBrokerRequest(
        peer=PeerCredentials(uid=1001, gid=1001, pid=123),
        request=BrokerRequest.create(
            account_id="local",
            project_id=REPOSITORY_ID,
            repository_generation=7,
            resource_id=REPOSITORY_ID,
            operation=BrokerOperation.TEST_QUEUE_STATUS,
            arguments={"expected_repository_id": expected_repository_id},
            authority_generation="generation-queue-status",
        ),
    )


def backend_for(test_plane: object) -> StoreBackedMutationBackend:
    backend = object.__new__(StoreBackedMutationBackend)
    backend._test_plane = test_plane
    backend._persistence = SimpleNamespace()
    return backend


class QueueStatusSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = UniversalTestStore.create(
            Path(self.temporary.name) / "tests.sqlite3"
        )
        self.adapter = StoreTestPlaneAdapter(self.store)
        self.repository = BrokerRepositoryProfile(
            canonical_root="/srv/repo-queue-status",
            repo_id=REPOSITORY_ID,
            generation=7,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        self.profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=Path("/run/devcoordinator-authority.sock"),
                database_generation="generation-queue-status",
            ),
            repositories={self.repository.canonical_root: self.repository},
        )

    def test_profile_broker_backend_and_store_preserve_exact_repository(self) -> None:
        backend = backend_for(self.adapter)
        calls: list[dict[str, object]] = []

        def route(
            _profile: BrokerClientProfile,
            *,
            repository: BrokerRepositoryProfile,
            resource_id: str,
            operation: BrokerOperation,
            arguments=None,
            operation_id=None,
            transport_timeout_seconds=None,
        ):
            calls.append(
                {
                    "repository": repository,
                    "resource_id": resource_id,
                    "operation": operation,
                    "arguments": arguments,
                    "transport_timeout_seconds": transport_timeout_seconds,
                }
            )
            request = BrokerRequest.create(
                account_id="local",
                project_id=repository.repo_id,
                repository_generation=repository.generation,
                resource_id=resource_id,
                operation=operation,
                arguments=arguments,
                operation_id=operation_id,
                authority_generation="generation-queue-status",
            )
            accepted = AcceptedBrokerRequest(
                peer=PeerCredentials(uid=1001, gid=1001, pid=123),
                request=request,
            )
            return request.operation_id, dict(backend._execute_async_test(accepted))

        with mock.patch.object(
            BrokerClientProfile, "call", autospec=True, side_effect=route
        ):
            result = self.profile.test_queue_status(repository=REPOSITORY_ID)

        self.assertEqual(result["repository_id"], REPOSITORY_ID)
        self.assertEqual(result["phase"], "idle")
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0]["operation"], BrokerOperation.TEST_QUEUE_STATUS)
        self.assertEqual(calls[0]["resource_id"], REPOSITORY_ID)
        self.assertEqual(
            calls[0]["arguments"],
            {"expected_repository_id": REPOSITORY_ID},
        )
        self.assertEqual(
            _broker_client_timeout_seconds(
                BrokerOperation.TEST_QUEUE_STATUS,
                arguments={"expected_repository_id": REPOSITORY_ID},
            ),
            60.0,
        )

    def test_broker_validation_and_backend_repository_binding(self) -> None:
        request = accepted_queue_request(expected_repository_id=REPOSITORY_ID)
        self.assertEqual(
            dict(request.request.arguments),
            {"expected_repository_id": REPOSITORY_ID},
        )
        for arguments in ({}, {"expected_repository_id": REPOSITORY_ID, "limit": 1}):
            with self.subTest(arguments=arguments), self.assertRaises(BrokerError):
                BrokerRequest.create(
                    account_id="local",
                    project_id=REPOSITORY_ID,
                    resource_id=REPOSITORY_ID,
                    operation=BrokerOperation.TEST_QUEUE_STATUS,
                    arguments=arguments,
                )

        with self.assertRaises(BrokerBackendError) as raised:
            backend_for(self.adapter)._execute_async_test(
                accepted_queue_request(expected_repository_id="repo-other")
            )
        self.assertEqual(raised.exception.code, "test_repository_mismatch")

    def test_backend_and_profile_reject_cross_wired_results(self) -> None:
        wrong_plane = SimpleNamespace(
            queue_status=lambda **_arguments: {"repository_id": "repo-other"}
        )
        with self.assertRaises(BrokerBackendError) as raised:
            backend_for(wrong_plane)._execute_async_test(
                accepted_queue_request(expected_repository_id=REPOSITORY_ID)
            )
        self.assertEqual(raised.exception.code, "test_repository_mismatch")

        with (
            mock.patch.object(
                BrokerClientProfile,
                "call",
                autospec=True,
                return_value=(str(uuid.uuid4()), {"repository_id": "repo-other"}),
            ),
            self.assertRaises(BrokerProfileError),
        ):
            self.profile.test_queue_status(repository=REPOSITORY_ID)

    def test_transport_mapping_uses_a_sixty_second_read(self) -> None:
        dispatcher = TestPlaneDispatcher(self.adapter)
        response = dispatcher.dispatch(
            json.dumps(
                {
                    "schema_version": 1,
                    "request_id": str(uuid.uuid4()),
                    "operation": TEST_QUEUE_STATUS,
                    "arguments": {"repository_id": REPOSITORY_ID},
                }
            ).encode("utf-8"),
            peer_uid=1001,
        )
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["repository_id"], REPOSITORY_ID)

        client = UnixTestPlaneClient(Path("/run/unused-testd.sock"))
        with mock.patch.object(
            client, "_call", return_value=response["result"]
        ) as call:
            client_result = client.queue_status(repository_id=REPOSITORY_ID)
        self.assertEqual(client_result["repository_id"], REPOSITORY_ID)
        call.assert_called_once_with(
            TEST_QUEUE_STATUS,
            {"repository_id": REPOSITORY_ID},
            timeout_seconds=TEST_QUEUE_STATUS_READ_TIMEOUT_SECONDS,
        )

    def test_adapter_rejects_result_over_shared_response_bound(self) -> None:
        oversized = {
            "repository_id": REPOSITORY_ID,
            "padding": "x" * MAX_TEST_PLANE_RESPONSE_BYTES,
        }
        with (
            mock.patch.object(self.store, "queue_status", return_value=oversized),
            self.assertRaises(TestStoreContractError),
        ):
            self.adapter.queue_status(repository_id=REPOSITORY_ID)


if __name__ == "__main__":
    unittest.main()
