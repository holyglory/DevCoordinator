from __future__ import annotations

import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import unittest
from unittest import mock

from devcoordinator import universal_test_transport as transport
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_snapshot import SnapshotMaterializationError
from devcoordinator.universal_test_store import (
    TestStoreContractError,
    UniversalTestStore,
)
from devcoordinator.universal_test_transport import (
    TestPlaneTransportError,
    UnixTestPlaneClient,
    UnixTestPlaneServer,
    _decode,
    _receive_frame,
)


class SlowSetupAdapter(StoreTestPlaneAdapter):
    def __init__(self, store: UniversalTestStore) -> None:
        super().__init__(store)
        self.first_started = threading.Event()
        self.release_first = threading.Event()
        self._calls_lock = threading.Lock()
        self._calls = 0

    def setup(self, *, repository_id, owner_uid, timeout_seconds=None):
        del owner_uid, timeout_seconds
        with self._calls_lock:
            self._calls += 1
            call = self._calls
        if call == 1:
            self.first_started.set()
            if not self.release_first.wait(5):
                raise TimeoutError("slow catalog fixture was not released")
        return {
            "schema_version": 1,
            "repository_id": repository_id,
            "status": "ready",
        }


class InaccessibleRepositoryPreviewer:
    def preview_as_owner(self, **_arguments):
        raise SnapshotMaterializationError(
            "Git snapshot inspection failed: permission denied"
        )

    def setup_as_owner(self, **_arguments):
        raise SnapshotMaterializationError(
            "repository manifest inspection failed: permission denied"
        )


class OpaqueRunStatusAdapter(StoreTestPlaneAdapter):
    def __init__(self, store: UniversalTestStore) -> None:
        super().__init__(store)
        self.calls: list[tuple[str, str]] = []

    def status(self, *, run_id: str, repository_id: str):
        self.calls.append((run_id, repository_id))
        return {
            "schema_version": 1,
            "run_id": run_id,
            "repository_id": "repo-resolved",
            "state": "queued",
        }


class InMemoryUnixListener:
    """AF_UNIX listener double for sandboxes that prohibit path socket binds."""

    family = socket.AF_UNIX
    type = socket.SOCK_STREAM

    def __init__(self) -> None:
        self._connections: queue.Queue[socket.socket | None] = queue.Queue()
        self._closed = threading.Event()
        self._timeout = 0.5

    def settimeout(self, value: float) -> None:
        self._timeout = value

    def accept(self):
        if self._closed.is_set():
            raise OSError("listener closed")
        try:
            connection = self._connections.get(timeout=self._timeout)
        except queue.Empty as error:
            raise socket.timeout from error
        if connection is None:
            raise OSError("listener closed")
        return connection, ""

    def connect(self) -> socket.socket:
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._connections.put(server)
        return client

    def close(self) -> None:
        if not self._closed.is_set():
            self._closed.set()
            self._connections.put(None)


class UniversalTestTransportIsolationTests(unittest.TestCase):
    def test_catalog_transport_was_removed(self) -> None:
        self.assertFalse(hasattr(UnixTestPlaneClient(self.root / "testd.sock"), "repository_catalog"))

    def test_setup_forwards_explicit_nested_read_deadline(self) -> None:
        client = UnixTestPlaneClient(self.root / "testd.sock")
        with mock.patch.object(
            client,
            "_call",
            return_value={"repository_id": "repo-ready", "status": "ready"},
        ) as call:
            client.setup(
                repository_id="repo-ready",
                owner_uid=os.geteuid(),
                timeout_seconds=transport.TEST_SETUP_READ_TIMEOUT_SECONDS,
            )

        call.assert_called_once_with(
            transport.TEST_REPOSITORY_SETUP,
            {"repository_id": "repo-ready", "owner_uid": os.geteuid()},
            timeout_seconds=transport.TEST_SETUP_READ_TIMEOUT_SECONDS,
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = UniversalTestStore.create(self.root / "tests.sqlite3")

    def start_server(self, adapter, *, concurrency: int):
        listener = InMemoryUnixListener()
        server = UnixTestPlaneServer(
            listener,  # type: ignore[arg-type]
            adapter,
            peer_resolver=lambda _connection: os.geteuid(),
            max_concurrent_requests=concurrency,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.close)
        client = UnixTestPlaneClient(
            Path("/unused/in-memory-test-plane.sock"),
            timeout_seconds=2,
            connection_factory=listener.connect,
        )
        return server, thread, client

    def test_connected_local_peer_uid_is_attribution_not_authorization(self) -> None:
        listener = InMemoryUnixListener()
        server = UnixTestPlaneServer(
            listener,  # type: ignore[arg-type]
            StoreTestPlaneAdapter(self.store),
            peer_resolver=lambda _connection: os.geteuid() + 20_000,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.close)
        client = UnixTestPlaneClient(
            Path("/unused/in-memory-test-plane.sock"),
            expected_server_uid=os.geteuid() + 30_000,
            timeout_seconds=2,
            connection_factory=listener.connect,
        )

        result = client.health()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(client.last_peer_uid, os.geteuid())

    def test_missing_socket_is_reported_as_typed_transport_unavailability(self) -> None:
        client = UnixTestPlaneClient(self.root / "missing-testd.sock")

        with self.assertRaises(TestPlaneTransportError) as raised:
            client.health()

        self.assertEqual(raised.exception.code, "transport_unavailable")
        self.assertEqual(
            raised.exception.message, "test-plane socket is unavailable"
        )

    def test_plan_preview_uses_caller_launch_bound_without_relaxing_short_reads(self) -> None:
        client = UnixTestPlaneClient(
            self.root / "unused.sock",
            timeout_seconds=2,
            preview_timeout_seconds=180,
            connection_factory=mock.Mock(),
        )
        with (
            mock.patch.object(client, "_call", return_value={}) as call,
            mock.patch.object(transport.time, "monotonic", return_value=100.0),
        ):
            client.preview(
                repository_id="repo-tests",
                launch_timeout_seconds=987,
                launch_deadline_monotonic=500.0,
            )
            preview_call = call.call_args
            client.health()
            health_call = call.call_args

        self.assertEqual(preview_call.kwargs["timeout_seconds"], 1047)
        self.assertEqual(
            preview_call.args[1]["launch_deadline_monotonic"], 500.0
        )
        self.assertNotIn("timeout_seconds", health_call.kwargs)

    def test_plan_preview_without_caller_bound_retains_compatibility_default(self) -> None:
        client = UnixTestPlaneClient(
            self.root / "unused.sock",
            timeout_seconds=2,
            preview_timeout_seconds=180,
            connection_factory=mock.Mock(),
        )
        with mock.patch.object(client, "_call", return_value={}) as call:
            client.preview(repository_id="repo-tests")

        self.assertEqual(call.call_args.kwargs["timeout_seconds"], 180)

    def test_plan_preview_rejects_invalid_caller_launch_bound_before_transport(self) -> None:
        client = UnixTestPlaneClient(
            self.root / "unused.sock",
            connection_factory=mock.Mock(),
        )
        for invalid in (True, 0, 3_601, 30.0):
            with self.subTest(invalid=invalid), self.assertRaises(
                TestStoreContractError
            ), mock.patch.object(client, "_call") as call:
                client.preview(
                    repository_id="repo-tests",
                    launch_timeout_seconds=invalid,
                )
            call.assert_not_called()

    def test_bind_accepts_trusted_local_mode_without_authorization_policy(self) -> None:
        listener = InMemoryUnixListener()
        listener.set_inheritable = mock.Mock()  # type: ignore[attr-defined]
        listener.bind = mock.Mock()  # type: ignore[attr-defined]
        listener.listen = mock.Mock()  # type: ignore[attr-defined]
        socket_path = self.root / "trusted-local.sock"
        with (
            mock.patch.object(transport.socket, "socket", return_value=listener),
            mock.patch.object(transport.os, "chmod") as chmod,
        ):
            server = UnixTestPlaneServer.bind(
                socket_path,
                StoreTestPlaneAdapter(self.store),
                socket_mode=0o666,
            )
        self.addCleanup(server.close)

        listener.bind.assert_called_once_with(str(socket_path))  # type: ignore[attr-defined]
        chmod.assert_called_once_with(socket_path, 0o666)

    def test_slow_handler_does_not_block_an_independent_request(self) -> None:
        adapter = SlowSetupAdapter(self.store)
        _server, _thread, client = self.start_server(adapter, concurrency=2)
        first_result: list[object] = []

        def slow_request() -> None:
            first_result.append(
                client.setup(repository_id="repo-slow", owner_uid=os.geteuid())
            )

        slow = threading.Thread(target=slow_request)
        slow.start()
        self.assertTrue(adapter.first_started.wait(1))

        second_result: list[object] = []
        fast = threading.Thread(
            target=lambda: second_result.append(
                client.setup(repository_id="repo-fast", owner_uid=os.geteuid())
            )
        )
        fast.start()
        fast.join(1)
        self.assertFalse(
            fast.is_alive(),
            "an unrelated test-plane read waited behind one slow repository handler",
        )
        self.assertEqual(
            second_result[0]["repository_id"],  # type: ignore[index]
            "repo-fast",
        )

        adapter.release_first.set()
        slow.join(1)
        self.assertFalse(slow.is_alive())
        self.assertEqual(
            first_result[0]["repository_id"],  # type: ignore[index]
            "repo-slow",
        )

    def test_repository_source_failure_is_not_reported_as_scheduler_outage(
        self,
    ) -> None:
        adapter = StoreTestPlaneAdapter(
            self.store,
            previewer=InaccessibleRepositoryPreviewer(),
        )
        _server, _thread, client = self.start_server(adapter, concurrency=1)

        with self.assertRaises(TestPlaneTransportError) as raised:
            client.preview(
                repository_id="repo-inaccessible",
                intent="manual",
                actor="codex:test",
                owner_uid=os.geteuid(),
                temporary_root=None,
                requested_targets=(),
            )

        self.assertEqual(raised.exception.code, "test_plan_source_invalid")
        self.assertIn("permission denied", raised.exception.message)

    def test_opaque_run_status_requires_repository_over_real_transport(
        self,
    ) -> None:
        adapter = OpaqueRunStatusAdapter(self.store)
        _server, _thread, client = self.start_server(adapter, concurrency=1)

        result = client.status(
            run_id="run-opaque",
            repository_id="repo-resolved",
        )

        self.assertEqual(result["run_id"], "run-opaque")
        self.assertEqual(result["repository_id"], "repo-resolved")
        self.assertEqual(adapter.calls, [("run-opaque", "repo-resolved")])

    def test_capacity_is_rejected_immediately_instead_of_queued(self) -> None:
        adapter = SlowSetupAdapter(self.store)
        _server, _thread, client = self.start_server(adapter, concurrency=1)
        slow = threading.Thread(
            target=lambda: client.setup(repository_id="repo-slow", owner_uid=os.geteuid())
        )
        slow.start()
        self.assertTrue(adapter.first_started.wait(1))

        with self.assertRaises(TestPlaneTransportError) as raised:
            client.setup(repository_id="repo-busy", owner_uid=os.geteuid())
        self.assertEqual(raised.exception.code, "server_busy")

        adapter.release_first.set()
        slow.join(1)
        self.assertFalse(slow.is_alive())

    def test_silent_saturated_peer_cannot_stall_the_accept_loop(self) -> None:
        adapter = SlowSetupAdapter(self.store)
        server, _thread, client = self.start_server(adapter, concurrency=1)
        slow = threading.Thread(
            target=lambda: client.setup(repository_id="repo-slow", owner_uid=os.geteuid())
        )
        slow.start()
        self.assertTrue(adapter.first_started.wait(1))

        listener = server.listener
        self.assertIsInstance(listener, InMemoryUnixListener)
        silent = listener.connect()
        with silent:
            silent.settimeout(0.5)
            response = _decode(_receive_frame(silent))
        self.assertFalse(response["ok"])
        self.assertIsNone(response["request_id"])
        self.assertEqual(response["error"]["code"], "server_busy")

        # A later saturated client still receives backpressure immediately;
        # the silent peer above consumed no accept-loop wait budget.
        with self.assertRaises(TestPlaneTransportError) as raised:
            client.setup(repository_id="repo-still-busy", owner_uid=os.geteuid())
        self.assertEqual(raised.exception.code, "server_busy")

        adapter.release_first.set()
        slow.join(1)
        self.assertFalse(slow.is_alive())

    def test_concurrency_contract_is_strictly_bounded(self) -> None:
        adapter = SlowSetupAdapter(self.store)
        listener = InMemoryUnixListener()
        self.addCleanup(listener.close)
        for value in (0, 129, True):
            with self.subTest(value=value):
                with self.assertRaises(TestStoreContractError):
                    UnixTestPlaneServer(
                        listener,
                        adapter,
                        max_concurrent_requests=value,
                    )


if __name__ == "__main__":
    unittest.main()
