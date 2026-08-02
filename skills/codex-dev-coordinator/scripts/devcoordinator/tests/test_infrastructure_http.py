"""Authenticated, fixed-scope HTTP bridge tests for infrastructure reads."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import dev_coordinator
from devcoordinator.broker import (
    BrokerOperation,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
    UnixBrokerServer,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import (
    BrokerPersistence,
    StoreBackedAuthorizer,
)
from devcoordinator.broker_profile import BrokerServiceProfile
from devcoordinator.infrastructure_observation import (
    INFRASTRUCTURE_BROKER_PROJECT_ID,
    INFRASTRUCTURE_READ_RESOURCE_ID,
    InfrastructureObservationAuthority,
)


HOST_A = "00000000-0000-4000-8000-000000000001"
HOST_B = "00000000-0000-4000-8000-000000000002"


def projection(arguments: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "spectre.infrastructure.projection.v1",
        "generated_at": "2026-07-29T12:00:00Z",
        "observation_cadence_seconds": 60,
        "stale_after_seconds": 180,
        "sort": "host_id",
        "after_host_id": arguments["after_host_id"],
        "host_limit": arguments["host_limit"],
        "vm_limit_per_host": arguments["vm_limit_per_host"],
        "rejection_limit_per_host": arguments["rejection_limit_per_host"],
        "hosts": [{"host_id": HOST_A}, {"host_id": HOST_B}],
        "has_more": False,
        "next_after_host_id": None,
    }


class InfrastructureHttpTests(unittest.TestCase):
    def test_query_is_closed_and_bounded(self) -> None:
        parsed = dev_coordinator.parse_infrastructure_query(
            "host_limit=100&vm_limit_per_host=256"
            "&rejection_limit_per_host=20&after_host_id=" + HOST_A
        )
        self.assertEqual(
            parsed,
            {
                "after_host_id": HOST_A,
                "host_limit": 100,
                "vm_limit_per_host": 256,
                "rejection_limit_per_host": 20,
            },
        )
        for raw in (
            "host_limit=101",
            "vm_limit_per_host=257",
            "rejection_limit_per_host=21",
            "after_host_id=not-a-guid",
            "host_limit=1&host_limit=2",
            "operation=infrastructure.ingest",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                dev_coordinator.parse_infrastructure_query(raw)

    def test_bridge_calls_only_the_fixed_read_scope(self) -> None:
        profile = SimpleNamespace(
            service=SimpleNamespace(socket_path="/fixture/broker.sock"),
            account_id="console-infrastructure-reader",
        )
        expected = projection(dev_coordinator.parse_infrastructure_query(""))
        with (
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=profile
            ),
            mock.patch.object(
                dev_coordinator,
                "call_broker",
                return_value=("operation-1", expected),
            ) as call,
        ):
            result = dev_coordinator.coordinated_infrastructure_read(
                dev_coordinator.parse_infrastructure_query("")
            )
        self.assertEqual(result, expected)
        self.assertEqual(
            call.call_args.kwargs,
            {
                "service": profile.service,
                "account_id": profile.account_id,
                "repo_id": INFRASTRUCTURE_BROKER_PROJECT_ID,
                "repository_generation": 0,
                "resource_id": INFRASTRUCTURE_READ_RESOURCE_ID,
                "operation": BrokerOperation.INFRASTRUCTURE_READ,
                "arguments": dev_coordinator.parse_infrastructure_query(""),
            },
        )

    def test_http_read_traverses_real_unix_broker_reader_authority(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".infrastructure-http-authority-",
            dir=str(Path.home()),
        ) as temporary:
            root = Path(temporary)
            database = root / "coordinator.sqlite3"
            staging = root / "staging"
            artifacts = root / "artifacts"
            staging.mkdir(mode=0o700)
            artifacts.mkdir(mode=0o700)
            InfrastructureObservationAuthority(
                database,
                ingress_staging_root=staging,
                broker_artifact_root=artifacts,
            )
            persistence = BrokerPersistence(database)
            reader_uid = 20_002
            reader_account = "console-http-reader"
            now_epoch = 1_800_000_000
            persistence.administer_infrastructure_reader_access(
                {
                    "schema": "spectre.infrastructure.reader-access.v1",
                    "request_id": "00000000-0000-4000-8000-000000000201",
                    "action": "reader.replace",
                    "payload": {
                        "service_account": "console-http-fixture",
                        "uid": reader_uid,
                        "account_id": reader_account,
                        "valid_until_epoch": now_epoch + 600,
                    },
                },
                operator_uid=0,
                now_epoch=now_epoch,
            )
            backend = StoreBackedMutationBackend(
                persistence,
                object(),
                infrastructure_ingress_staging_root=staging,
                infrastructure_broker_artifact_root=artifacts,
            )
            broker_service = BrokerService(
                StoreBackedAuthorizer(persistence),
                SerializedMutationWriter(backend),
            )
            socket_path = root / "broker.sock"
            broker_server = UnixBrokerServer(
                socket_path,
                broker_service,
                socket_mode=0o600,
                peer_resolver=lambda _connection: PeerCredentials(
                    uid=reader_uid,
                    gid=reader_uid,
                    pid=456,
                ),
            )
            broker_server.start()
            self.addCleanup(broker_server.close)
            profile = SimpleNamespace(
                service=BrokerServiceProfile(
                    socket_path=socket_path,
                    service_uid=os.geteuid(),
                    socket_gid=os.getegid(),
                    socket_mode=0o600,
                    database_generation=persistence.database_generation(),
                ),
                account_id=reader_account,
            )
            http_server = dev_coordinator.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                dev_coordinator.ApiHandler,
                token="infrastructure-token",
            )
            http_thread = threading.Thread(
                target=http_server.serve_forever,
                daemon=True,
            )
            http_thread.start()
            self.addCleanup(http_thread.join, 5)
            self.addCleanup(http_server.server_close)
            self.addCleanup(http_server.shutdown)

            connection = http.client.HTTPConnection(
                "127.0.0.1",
                int(http_server.server_address[1]),
                timeout=5,
            )
            try:
                with mock.patch.object(
                    dev_coordinator,
                    "configured_broker_profile",
                    return_value=profile,
                ):
                    connection.request(
                        "GET",
                        "/v1/infrastructure",
                        headers={
                            "Authorization": "Bearer infrastructure-token"
                        },
                    )
                    response = connection.getresponse()
                    body = json.loads(response.read().decode("utf-8"))
            finally:
                connection.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(
                body,
                {
                    "schema": "spectre.infrastructure.projection.v1",
                    "generated_at": body["generated_at"],
                    "observation_cadence_seconds": 60,
                    "stale_after_seconds": 180,
                    "sort": "host_id",
                    "after_host_id": None,
                    "host_limit": 50,
                    "vm_limit_per_host": 128,
                    "rejection_limit_per_host": 1,
                    "hosts": [],
                    "has_more": False,
                    "next_after_host_id": None,
                },
            )

    def test_http_auth_method_and_route_inventory_fail_closed(self) -> None:
        server = dev_coordinator.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            dev_coordinator.ApiHandler,
            token="infrastructure-token",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])

        def request(
            method: str, path: str, *, token: str | None
        ) -> tuple[int, dict[str, object], str | None]:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            headers = (
                {"Authorization": f"Bearer {token}"} if token is not None else {}
            )
            try:
                connection.request(method, path, headers=headers)
                response = connection.getresponse()
                body = json.loads(response.read().decode("utf-8"))
                return response.status, body, response.getheader("Allow")
            finally:
                connection.close()

        try:
            with mock.patch.object(
                dev_coordinator,
                "coordinated_infrastructure_read",
                side_effect=lambda arguments: projection(dict(arguments)),
            ) as read:
                status, body, _allow = request(
                    "GET", "/v1/infrastructure", token=None
                )
                self.assertEqual(status, 401)
                self.assertEqual(body, {"error": "unauthorized"})
                self.assertEqual(read.call_count, 0)

                status, body, _allow = request(
                    "GET",
                    "/v1/infrastructure?host_limit=2"
                    "&vm_limit_per_host=1&rejection_limit_per_host=0",
                    token="infrastructure-token",
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    [host["host_id"] for host in body["hosts"]],
                    [HOST_A, HOST_B],
                )
                self.assertEqual(
                    read.call_args.args[0],
                    {
                        "after_host_id": None,
                        "host_limit": 2,
                        "vm_limit_per_host": 1,
                        "rejection_limit_per_host": 0,
                    },
                )

                status, body, allow = request(
                    "POST", "/v1/infrastructure", token="infrastructure-token"
                )
                self.assertEqual(status, 405)
                self.assertEqual(allow, "GET")
                self.assertEqual(body, {"error": "method not allowed"})

                status, body, _allow = request(
                    "GET",
                    "/v1/infrastructure/ingest",
                    token="infrastructure-token",
                )
                self.assertEqual(status, 404)
                self.assertEqual(body, {"error": "not found"})

                status, body, _allow = request(
                    "GET",
                    "/v1/infrastructure?host_limit=101",
                    token="infrastructure-token",
                )
                self.assertEqual(status, 400)
                self.assertIn("host_limit", str(body["error"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_infrastructure_http_is_compact_utf8_and_uses_authority_byte_bound(
        self,
    ) -> None:
        server = dev_coordinator.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            dev_coordinator.ApiHandler,
            token="infrastructure-token",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        value = projection(dev_coordinator.parse_infrastructure_query(""))
        value["hosts"] = [
            {
                "host_id": HOST_A,
                "display_name": "РЛС «Север»",
            }
        ]

        def raw_request() -> tuple[int, bytes, int]:
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                port,
                timeout=5,
            )
            try:
                connection.request(
                    "GET",
                    "/v1/infrastructure",
                    headers={
                        "Authorization": "Bearer infrastructure-token",
                    },
                )
                response = connection.getresponse()
                body = response.read()
                return (
                    response.status,
                    body,
                    int(response.getheader("Content-Length", "-1")),
                )
            finally:
                connection.close()

        try:
            with mock.patch.object(
                dev_coordinator,
                "coordinated_infrastructure_read",
                return_value=value,
            ):
                status, body, content_length = raw_request()
                self.assertEqual(status, 200)
                self.assertEqual(content_length, len(body))
                self.assertIn("РЛС «Север»".encode("utf-8"), body)
                self.assertNotIn(b"\\u", body)
                self.assertNotIn(b"\n", body)

                with mock.patch.object(
                    dev_coordinator,
                    "MAX_PROJECTION_BYTES",
                    len(body) - 1,
                ):
                    status, rejected, _length = raw_request()
                self.assertEqual(status, 500)
                self.assertNotIn("РЛС «Север»".encode("utf-8"), rejected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
