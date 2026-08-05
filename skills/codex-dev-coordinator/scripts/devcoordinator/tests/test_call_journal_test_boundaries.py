from __future__ import annotations

import errno
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock
import uuid

from devcoordinator.call_journal import RollingCallJournal, read_call_records
from devcoordinator.broker import BrokerOperation
from devcoordinator.universal_test_broker import BrokerConnection, _InternalBrokerCalls
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_snapshot_service import (
    SnapshotServiceRemoteError,
    UnixSnapshotServiceClient,
    UnixSnapshotServiceServer,
)
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    UniversalTestStore,
)
from devcoordinator.universal_test_transport import (
    TEST_HEALTH,
    TestPlaneDispatcher,
    TestPlaneTransportError,
    UnixTestPlaneClient,
    UnixTestPlaneServer,
)


class _FailingSnapshotService:
    def setup(self, _arguments):
        return {"schema_version": 1, "status": "ready"}

    def resolve(self, _arguments):
        try:
            raise PermissionError(
                errno.EACCES,
                "permission denied token=must-not-leak",
                "/home/private/.venv-v2/bin/python",
            )
        except PermissionError as error:
            raise TestStoreConflict(
                "immutable Python dependency executable is unavailable"
            ) from error


class _ReplyingBrokerClient:
    def __init__(self, _socket_path, **_arguments):
        pass

    def call(self, request):
        return {
            "ok": True,
            "operation_id": request.operation_id,
            "result": {
                "run_id": request.arguments["run_id"],
                "state": "running",
                "secret": "must-not-be-recorded",
            },
        }


class _TimingOutBrokerClient:
    def __init__(self, _socket_path, **_arguments):
        pass

    def call(self, _request):
        raise TimeoutError("authority did not reply before the transport slice")


class CallJournalTestBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.journal_path = self.root / "calls.jsonl"
        self.journal = RollingCallJournal(self.journal_path)

    def records(self):
        return list(read_call_records(self.journal_path))

    def test_test_plane_records_success_and_malformed_rejection(self) -> None:
        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(self.root / "tests.sqlite3")
        )
        dispatcher = TestPlaneDispatcher(adapter, call_journal=self.journal)
        request_id = str(uuid.uuid4())
        response = dispatcher.dispatch(
            json.dumps(
                {
                    "schema_version": 1,
                    "request_id": request_id,
                    "operation": TEST_HEALTH,
                    "arguments": {},
                }
            ).encode("utf-8"),
            peer_uid=1001,
            peer_gid=1003,
            peer_pid=4242,
        )
        rejected = dispatcher.dispatch(b"not-json", peer_uid=1001)

        self.assertTrue(response["ok"])
        self.assertFalse(rejected["ok"])
        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [
                ("received", "received"),
                ("completed", "ok"),
                ("received", "received"),
                ("rejected", "rejected"),
            ],
        )
        self.assertEqual(records[0]["request_id"], request_id)
        self.assertEqual(records[0]["operation"], TEST_HEALTH)
        self.assertEqual(records[0]["peer_uid"], 1001)
        self.assertEqual(records[0]["peer_gid"], 1003)
        self.assertEqual(records[0]["peer_pid"], 4242)
        self.assertEqual(records[-1]["code"], "invalid_json")
        self.assertGreaterEqual(records[1]["duration_ms"], 0)
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[2]["call_id"], records[3]["call_id"])

    def test_snapshot_rejection_keeps_typed_path_free_diagnostic(self) -> None:
        server = UnixSnapshotServiceServer(
            mock.Mock(),
            _FailingSnapshotService(),  # type: ignore[arg-type]
            allowed_peer_uid=1001,
            call_journal=self.journal,
        )
        request_id = str(uuid.uuid4())
        response = mock.Mock()
        request = {
            "schema_version": 1,
            "request_id": request_id,
            "operation": "resolve",
            "arguments": {
                "candidate": {
                    "repository_id": "repo-globalfinance",
                    "run_id": "run-123",
                },
                "lease": {
                    "run_id": "run-123",
                    "attempt_id": "attempt-456",
                },
                "plan": {"repository_id": "repo-globalfinance"},
            },
        }
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_identity",
                return_value=(4242, 1001, 1003),
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                return_value=request,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send",
                response,
            ),
        ):
            server.serve_connection(mock.Mock())

        document = response.call_args.args[1]
        self.assertFalse(document["ok"])
        self.assertEqual(
            document["error"]["code"],
            "snapshot_python_dependency_unavailable",
        )
        self.assertEqual(
            document["error"]["diagnostic"],
            {
                "stage": "resolve.python_dependency",
                "subject": "python_dependency_executable",
                "exception_type": "TestStoreConflict",
                "root_exception_type": "PermissionError",
                "errno": "EACCES",
            },
        )
        records = self.records()
        self.assertEqual([record["phase"] for record in records], ["received", "rejected"])
        terminal = records[-1]
        self.assertEqual(terminal["request_id"], request_id)
        self.assertEqual(terminal["repository_id"], "repo-globalfinance")
        self.assertEqual(terminal["run_id"], "run-123")
        self.assertEqual(terminal["attempt_id"], "attempt-456")
        self.assertEqual(terminal["peer_pid"], 4242)
        self.assertEqual(terminal["diagnostic"]["errno"], "EACCES")
        retained = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn("/home/private", retained)
        self.assertNotIn("must-not-leak", retained)
        self.assertNotIn('"candidate":', retained)
        self.assertNotIn('"lease":', retained)

    def test_snapshot_success_records_native_identity_and_duration(self) -> None:
        server = UnixSnapshotServiceServer(
            mock.Mock(),
            _FailingSnapshotService(),  # type: ignore[arg-type]
            allowed_peer_uid=1001,
            call_journal=self.journal,
        )
        request_id = str(uuid.uuid4())
        sent = mock.Mock()
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_identity",
                return_value=(55, 1001, 1003),
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                return_value={
                    "schema_version": 1,
                    "request_id": request_id,
                    "operation": "setup",
                    "arguments": {
                        "repository_id": "repo-globalfinance",
                        "owner_uid": 1001,
                    },
                },
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send", sent
            ),
        ):
            server.serve_connection(mock.Mock())

        self.assertTrue(sent.call_args.args[1]["ok"])
        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [("received", "received"), ("completed", "ok")],
        )
        self.assertEqual(records[-1]["request_id"], request_id)
        self.assertEqual(records[-1]["repository_id"], "repo-globalfinance")
        self.assertGreaterEqual(records[-1]["duration_ms"], 0)

    def test_snapshot_client_connect_failure_is_correlated_and_path_free(self) -> None:
        client = UnixSnapshotServiceClient(
            self.root / "snapshot.sock",
            call_journal=self.journal,
        )
        connection = mock.MagicMock()
        connection.connect.side_effect = ConnectionRefusedError(
            errno.ECONNREFUSED,
            "connection refused token=must-not-leak",
            "/home/private/snapshot.sock",
        )
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.socket.socket",
            return_value=connection,
        ):
            with self.assertRaises(ConnectionRefusedError):
                client._call(
                    "resolve",
                    {
                        "candidate": {
                            "repository_id": "repo-globalfinance",
                            "run_id": "run-123",
                        },
                        "lease": {
                            "run_id": "run-123",
                            "attempt_id": "attempt-456",
                        },
                        "plan": {"repository_id": "repo-globalfinance"},
                    },
                )

        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [("received", "received"), ("completed", "unavailable")],
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[0]["request_id"], records[1]["request_id"])
        self.assertEqual(records[-1]["boundary"], "snapshot_client")
        self.assertEqual(records[-1]["repository_id"], "repo-globalfinance")
        self.assertEqual(records[-1]["run_id"], "run-123")
        self.assertEqual(records[-1]["attempt_id"], "attempt-456")
        self.assertEqual(records[-1]["code"], "snapshot_transport_unavailable")
        self.assertEqual(records[-1]["diagnostic"]["errno"], "ECONNREFUSED")
        retained = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn("/home/private", retained)
        self.assertNotIn("must-not-leak", retained)
        self.assertNotIn('"candidate":', retained)

    def test_test_plane_reply_delivery_failure_supersedes_success(self) -> None:
        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(self.root / "delivery.sqlite3")
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        server = UnixTestPlaneServer(
            listener,
            adapter,
            call_journal=self.journal,
        )
        request_id = str(uuid.uuid4())
        with (
            mock.patch(
                "devcoordinator.universal_test_transport._peer_identity",
                return_value=(44, 1001, 1003),
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._receive_frame",
                return_value=json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": request_id,
                        "operation": TEST_HEALTH,
                        "arguments": {},
                    }
                ).encode("utf-8"),
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._send_frame",
                side_effect=BrokenPipeError(errno.EPIPE, "closed"),
            ),
        ):
            server.serve_connection(mock.Mock())

        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [
                ("received", "received"),
                ("completed", "ok"),
                ("completed", "unavailable"),
            ],
        )
        self.assertEqual(len({record["call_id"] for record in records}), 1)
        self.assertEqual(records[-1]["request_id"], request_id)
        self.assertEqual(records[-1]["code"], "reply_delivery_failed")

    def test_test_plane_client_connect_failure_is_correlated_and_path_free(self) -> None:
        client = UnixTestPlaneClient(
            self.root / "testd.sock",
            call_journal=self.journal,
        )
        connection = mock.MagicMock()
        connection.connect.side_effect = ConnectionRefusedError(
            errno.ECONNREFUSED,
            "connection refused token=must-not-leak",
            "/home/private/testd.sock",
        )
        with mock.patch(
            "devcoordinator.universal_test_transport.socket.socket",
            return_value=connection,
        ):
            with self.assertRaises(TestPlaneTransportError) as raised:
                client._call(
                    TEST_HEALTH,
                    {
                        "repository_id": "repo-globalfinance",
                        "run_id": "run-123",
                        "attempt_id": "attempt-456",
                    },
                )

        self.assertEqual(raised.exception.code, "transport_unavailable")
        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [("received", "received"), ("completed", "unavailable")],
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[0]["request_id"], records[1]["request_id"])
        self.assertEqual(records[-1]["boundary"], "test_plane_client")
        self.assertEqual(records[-1]["repository_id"], "repo-globalfinance")
        self.assertEqual(records[-1]["run_id"], "run-123")
        self.assertEqual(records[-1]["attempt_id"], "attempt-456")
        self.assertEqual(records[-1]["code"], "transport_unavailable")
        self.assertEqual(records[-1]["diagnostic"]["errno"], "ECONNREFUSED")
        retained = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn("/home/private", retained)
        self.assertNotIn("must-not-leak", retained)
        self.assertNotIn('"arguments":', retained)

    def test_test_plane_client_records_successful_validation(self) -> None:
        connection = mock.MagicMock()
        client = UnixTestPlaneClient(
            self.root / "testd.sock",
            connection_factory=lambda: connection,
            call_journal=self.journal,
        )
        sent = mock.Mock()

        def receive_with_request_identity(_connection):
            return json.dumps(
                {
                    "schema_version": 1,
                    "request_id": sent.call_args.args[1]["request_id"],
                    "ok": True,
                    "result": {
                        "repository_id": "repo-globalfinance",
                        "run_id": "run-123",
                        "attempt_id": "attempt-456",
                    },
                }
            ).encode("utf-8")

        with (
            mock.patch(
                "devcoordinator.universal_test_transport._peer_uid",
                return_value=0,
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._send_frame", sent
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._receive_frame",
                side_effect=receive_with_request_identity,
            ),
        ):
            result = client._call(TEST_HEALTH, {})

        self.assertEqual(result["run_id"], "run-123")
        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [("received", "received"), ("completed", "ok")],
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[-1]["peer_uid"], 0)
        self.assertEqual(records[-1]["repository_id"], "repo-globalfinance")
        self.assertEqual(records[-1]["run_id"], "run-123")
        self.assertEqual(records[-1]["attempt_id"], "attempt-456")

    def test_test_plane_receive_abort_is_logged_and_does_not_escape(self) -> None:
        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(self.root / "receive-abort.sqlite3")
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        server = UnixTestPlaneServer(
            listener,
            adapter,
            call_journal=self.journal,
        )
        connection = mock.MagicMock()
        with (
            mock.patch(
                "devcoordinator.universal_test_transport._peer_identity",
                return_value=(44, 1001, 1003),
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._receive_frame",
                side_effect=ConnectionResetError(
                    errno.ECONNRESET,
                    "closed token=must-not-leak",
                    "/home/private/testd.sock",
                ),
            ),
            mock.patch(
                "devcoordinator.universal_test_transport._send_frame"
            ) as send,
        ):
            self.assertIsNone(server.serve_connection(connection))

        send.assert_not_called()
        connection.close.assert_called_once_with()
        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [("received", "received"), ("rejected", "unavailable")],
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[-1]["code"], "transport_aborted")
        self.assertEqual(records[-1]["peer_uid"], 1001)
        self.assertEqual(records[-1]["diagnostic"]["errno"], "ECONNRESET")
        retained = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn("/home/private", retained)
        self.assertNotIn("must-not-leak", retained)

    def test_snapshot_reply_delivery_failure_supersedes_success(self) -> None:
        server = UnixSnapshotServiceServer(
            mock.Mock(),
            _FailingSnapshotService(),  # type: ignore[arg-type]
            allowed_peer_uid=1001,
            call_journal=self.journal,
        )
        request_id = str(uuid.uuid4())
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_identity",
                return_value=(55, 1001, 1003),
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                return_value={
                    "schema_version": 1,
                    "request_id": request_id,
                    "operation": "setup",
                    "arguments": {
                        "repository_id": "repo-globalfinance",
                        "owner_uid": 1001,
                    },
                },
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send",
                side_effect=BrokenPipeError(errno.EPIPE, "closed"),
            ),
        ):
            server.serve_connection(mock.Mock())

        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [
                ("received", "received"),
                ("completed", "ok"),
                ("completed", "unavailable"),
            ],
        )
        self.assertEqual(len({record["call_id"] for record in records}), 1)
        self.assertEqual(records[-1]["request_id"], request_id)
        self.assertEqual(records[-1]["repository_id"], "repo-globalfinance")
        self.assertEqual(records[-1]["code"], "reply_delivery_failed")

    def test_snapshot_accept_loop_retries_listener_timeout(self) -> None:
        listener = mock.Mock()
        listener.accept.side_effect = [socket.timeout(), RuntimeError("stop")]
        server = UnixSnapshotServiceServer(
            listener,
            _FailingSnapshotService(),  # type: ignore[arg-type]
            allowed_peer_uid=1001,
            call_journal=self.journal,
        )
        with self.assertRaisesRegex(RuntimeError, "stop"):
            server.serve_forever()
        self.assertEqual(listener.accept.call_count, 2)

    def test_remote_snapshot_code_survives_client_and_dispatcher(self) -> None:
        client = UnixSnapshotServiceClient(self.root / "snapshot.sock")
        connection = mock.MagicMock()
        response = {
            "schema_version": 1,
            "request_id": "replaced-with-the-client-request-id",
            "ok": False,
            "error": {
                "code": "snapshot_python_dependency_unavailable",
                "message": "immutable Python dependency executable is unavailable",
                "diagnostic": {
                    "stage": "resolve.python_dependency",
                    "subject": "python_dependency_executable",
                    "exception_type": "TestStoreConflict",
                    "root_exception_type": "PermissionError",
                    "errno": "EACCES",
                },
            },
        }

        def receive_with_request_identity(_connection):
            return {**response, "request_id": sent.call_args.args[1]["request_id"]}

        sent = mock.Mock()
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.socket.socket",
                return_value=connection,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._peer_uid",
                return_value=0,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._send", sent
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._receive",
                side_effect=receive_with_request_identity,
            ),
        ):
            with self.assertRaises(SnapshotServiceRemoteError) as raised:
                client._call("resolve", {})

        self.assertEqual(
            raised.exception.code, "snapshot_python_dependency_unavailable"
        )
        self.assertEqual(raised.exception.diagnostic["errno"], "EACCES")

        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(self.root / "typed.sqlite3")
        )
        dispatcher = TestPlaneDispatcher(adapter)
        with mock.patch.object(adapter, "health", side_effect=raised.exception):
            result = dispatcher.dispatch(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": str(uuid.uuid4()),
                        "operation": TEST_HEALTH,
                        "arguments": {},
                    }
                ).encode("utf-8")
            )
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["error"]["code"],
            "snapshot_python_dependency_unavailable",
        )

    def test_testd_authority_client_records_success_and_timeout(self) -> None:
        connection = BrokerConnection(
            self.root / "authority.sock",
            authority_generation="generation-current",
        )
        successful = _InternalBrokerCalls(
            connection,
            client_factory=_ReplyingBrokerClient,  # type: ignore[arg-type]
            call_journal=self.journal,
        )
        result = successful.call(
            repository_id="repo-globalfinance",
            repository_generation=7,
            resource_id="resource-test-runner",
            operation=BrokerOperation.TEST_RUN_STATUS,
            arguments={"run_id": "run-123"},
        )
        self.assertEqual(result["state"], "running")

        timing_out = _InternalBrokerCalls(
            connection,
            client_factory=_TimingOutBrokerClient,  # type: ignore[arg-type]
            call_journal=self.journal,
        )
        with self.assertRaises(TimeoutError):
            timing_out.call(
                repository_id="repo-globalfinance",
                repository_generation=7,
                resource_id="resource-test-runner",
                operation=BrokerOperation.TEST_RUN_STATUS,
                arguments={"run_id": "run-456"},
                timeout_seconds=0.1,
            )

        records = self.records()
        self.assertEqual(
            [(record["phase"], record["outcome"]) for record in records],
            [
                ("received", "received"),
                ("completed", "ok"),
                ("received", "received"),
                ("completed", "timeout"),
            ],
        )
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[2]["call_id"], records[3]["call_id"])
        self.assertEqual(records[0]["repository_id"], "repo-globalfinance")
        self.assertEqual(records[0]["run_id"], "run-123")
        self.assertEqual(records[-1]["code"], "transport_unavailable")
        retained = self.journal_path.read_text(encoding="utf-8")
        self.assertNotIn("must-not-be-recorded", retained)


if __name__ == "__main__":
    unittest.main()
