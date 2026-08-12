"""Maintenance marker trust and client-facing wait-response regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest import mock
import uuid

import devcoordinator.maintenance as maintenance_module

from devcoordinator.broker import (
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
)
from devcoordinator.maintenance import (
    CONTROL_PLANE_MAINTENANCE_SCOPE,
    MAINTENANCE_MARKER_MODE,
    MaintenanceMarkerError,
    PUBLIC_MAINTENANCE_MESSAGE,
    activate_maintenance,
    clear_maintenance,
    load_maintenance_state,
)


class MaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="coordinator-maintenance-"
        )
        self.runtime = Path(self.temporary.name)
        self.runtime.chmod(0o700)
        self.broker_runtime = self.runtime / "broker-runtime"
        self.broker_runtime.mkdir(mode=0o700)
        self.maintenance_runtime = self.runtime / "maintenance-runtime"
        self.maintenance_runtime.mkdir(mode=0o700)
        self.socket = self.broker_runtime / "broker.sock"
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(
        self,
        document: dict[str, object],
        *,
        mode: int = MAINTENANCE_MARKER_MODE,
    ) -> Path:
        marker = self.maintenance_runtime / "maintenance.json"
        marker.write_text(json.dumps(document) + "\n", encoding="utf-8")
        marker.chmod(mode)
        return marker

    def _document(self) -> dict[str, object]:
        return {
            "version": 1,
            "status": "active",
            "deployment_id": str(uuid.uuid4()),
            "message": PUBLIC_MAINTENANCE_MESSAGE,
            "retry_after_seconds": 30,
            "started_at": "2026-07-26T19:00:00Z",
        }

    def _request(self, operation: BrokerOperation) -> BrokerRequest:
        run_id = str(uuid.uuid4())
        return BrokerRequest.create(
            account_id="account",
            project_id="project",
            resource_id=(
                run_id
                if operation is BrokerOperation.EPHEMERAL_SECRET_FD
                else "resource"
            ),
            operation=operation,
            arguments=(
                {
                    "template_id": "template-alpha",
                    "run_id": run_id,
                    "request_id": str(uuid.uuid4()),
                }
                if operation is BrokerOperation.EPHEMERAL_SECRET_FD
                else {}
            ),
        )

    def _client(self) -> BrokerClient:
        return BrokerClient(
            self.socket,
            maintenance_root=self.maintenance_runtime,
        )

    def test_absent_marker_does_not_change_broker_admission(self) -> None:
        self.assertIsNone(
            load_maintenance_state(maintenance_root=self.maintenance_runtime)
        )

    def test_marker_identity_mapping_does_not_affect_clients(self) -> None:
        document = self._document()
        marker = self._write(document)
        real_lstat = Path.lstat

        def unmapped_root(path: Path) -> os.stat_result:
            metadata = real_lstat(path)
            if path in {self.maintenance_runtime, marker}:
                fields = list(metadata)
                fields[4] = 65534
                fields[5] = 65534
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(
            maintenance_module, "MAINTENANCE_ROOT", self.maintenance_runtime
        ), mock.patch.object(Path, "lstat", new=unmapped_root):
            state = load_maintenance_state(
                maintenance_root=self.maintenance_runtime,
            )

        self.assertIsNotNone(state)
        self.assertEqual(state.deployment_id, document["deployment_id"])

        with mock.patch.object(Path, "lstat", new=unmapped_root):
            custom = load_maintenance_state(
                maintenance_root=self.maintenance_runtime,
            )
        self.assertIsNotNone(custom)
        self.assertEqual(custom.deployment_id, document["deployment_id"])

    def test_trusted_marker_blocks_before_socket_access_with_retry(self) -> None:
        marker = self._write({
            **self._document(),
            "message": "Refreshing GlobalFinance Coinbase capture",
        })
        started = time.monotonic()
        with self.assertRaises(BrokerError) as caught:
            self._client().call(self._request(BrokerOperation.INVENTORY_READ))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(caught.exception.code, "maintenance_in_progress")
        self.assertEqual(caught.exception.retry_after_seconds, 30)
        self.assertEqual(caught.exception.message, PUBLIC_MAINTENANCE_MESSAGE)
        self.assertNotIn("GlobalFinance", caught.exception.message)
        self.assertTrue(marker.exists())

    def test_marker_gid_is_independent_of_socket_access_gid(self) -> None:
        marker = self._write(self._document())
        unrelated_socket_gid = marker.stat().st_gid + 1
        client = BrokerClient(
            self.socket,
            maintenance_root=self.maintenance_runtime,
        )

        self.assertNotEqual(marker.stat().st_gid, unrelated_socket_gid)
        with self.assertRaises(BrokerError) as caught:
            client.call(self._request(BrokerOperation.INVENTORY_READ))

        self.assertEqual(caught.exception.code, "maintenance_in_progress")

    def test_marker_owner_is_not_a_local_authorization_gate(self) -> None:
        marker = self._write(self._document())
        real_lstat = Path.lstat

        def foreign_marker_owner(path: Path) -> os.stat_result:
            metadata = real_lstat(path)
            if path == marker:
                fields = list(metadata)
                fields[4] = self.uid + 1
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(Path, "lstat", new=foreign_marker_owner):
            with self.assertRaises(BrokerError) as caught:
                self._client().call(
                    self._request(BrokerOperation.INVENTORY_READ)
                )

        self.assertEqual(caught.exception.code, "maintenance_in_progress")

    def test_activation_is_reserved_for_fixed_control_plane_scope_and_copy(self) -> None:
        document = self._document()
        common = {
            "expected_uid": self.uid,
            "expected_gid": self.gid,
            "deployment_id": str(document["deployment_id"]),
            "retry_after_seconds": int(document["retry_after_seconds"]),
            "started_at": str(document["started_at"]),
            "maintenance_root": self.maintenance_runtime,
        }
        with self.assertRaisesRegex(MaintenanceMarkerError, "server-wide authority"):
            activate_maintenance(
                **common,
                scope="project-deployment",
                message=PUBLIC_MAINTENANCE_MESSAGE,
            )
        with self.assertRaisesRegex(MaintenanceMarkerError, "fixed public"):
            activate_maintenance(
                **common,
                scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
                message="Refreshing GlobalFinance Coinbase capture",
            )
        self.assertFalse((self.maintenance_runtime / "maintenance.json").exists())

    def test_marker_mode_is_ignored_but_malformed_content_fails_closed(self) -> None:
        self._write(self._document(), mode=0o666)
        with self.assertRaises(BrokerError) as active:
            self._client().call(self._request(BrokerOperation.INVENTORY_READ))
        self.assertEqual(active.exception.code, "maintenance_in_progress")

        cases = (
            (
                {**self._document(), "retry_after_seconds": True},
                MAINTENANCE_MARKER_MODE,
            ),
            ({**self._document(), "extra": "field"}, MAINTENANCE_MARKER_MODE),
        )
        for document, mode in cases:
            with self.subTest(document=document, mode=oct(mode)):
                (self.maintenance_runtime / "maintenance.json").unlink(
                    missing_ok=True
                )
                self._write(document, mode=mode)
                with self.assertRaises(BrokerError) as caught:
                    self._client().call(
                        self._request(BrokerOperation.INVENTORY_READ)
                    )
                self.assertEqual(
                    caught.exception.code, "maintenance_state_invalid"
                )
                self.assertEqual(caught.exception.retry_after_seconds, 60)

    def test_missing_maintenance_directory_fails_closed(self) -> None:
        self.maintenance_runtime.rmdir()
        with self.assertRaises(BrokerError) as caught:
            self._client().call(self._request(BrokerOperation.INVENTORY_READ))
        self.assertEqual(caught.exception.code, "maintenance_state_invalid")

    def test_symlink_marker_is_never_followed(self) -> None:
        target = self.maintenance_runtime / "foreign.json"
        target.write_text(json.dumps(self._document()), encoding="utf-8")
        target.chmod(0o640)
        (self.maintenance_runtime / "maintenance.json").symlink_to(target)
        with self.assertRaises(BrokerError) as caught:
            self._client().call(self._request(BrokerOperation.INVENTORY_READ))
        self.assertEqual(caught.exception.code, "maintenance_state_invalid")

    def test_descriptor_transport_is_also_fenced_before_connect(self) -> None:
        if not hasattr(socket, "SCM_RIGHTS"):
            self.skipTest("descriptor transport is unavailable")
        self._write(self._document())
        with self.assertRaises(BrokerError) as caught:
            self._client().retrieve_ephemeral_secret_fd(
                self._request(BrokerOperation.EPHEMERAL_SECRET_FD)
            )
        self.assertEqual(caught.exception.code, "maintenance_in_progress")

    def test_publication_is_idempotent_and_clear_is_owner_bound(self) -> None:
        document = self._document()
        arguments = {
            "expected_uid": self.uid,
            "expected_gid": self.gid,
            "deployment_id": str(document["deployment_id"]),
            "scope": CONTROL_PLANE_MAINTENANCE_SCOPE,
            "message": str(document["message"]),
            "retry_after_seconds": int(document["retry_after_seconds"]),
            "started_at": str(document["started_at"]),
            "maintenance_root": self.maintenance_runtime,
        }
        first = activate_maintenance(**arguments)
        self.assertEqual(
            (self.maintenance_runtime / "maintenance.json").stat().st_mode
            & 0o777,
            MAINTENANCE_MARKER_MODE,
        )
        second = activate_maintenance(**arguments)
        self.assertEqual(first, second)
        with self.assertRaisesRegex(
            MaintenanceMarkerError, "another deployment"
        ):
            clear_maintenance(
                expected_uid=self.uid,
                expected_gid=self.gid,
                deployment_id=str(uuid.uuid4()),
                maintenance_root=self.maintenance_runtime,
            )
        self.assertTrue(
            clear_maintenance(
                expected_uid=self.uid,
                expected_gid=self.gid,
                deployment_id=str(document["deployment_id"]),
                maintenance_root=self.maintenance_runtime,
            )
        )
        self.assertFalse(
            clear_maintenance(
                expected_uid=self.uid,
                expected_gid=self.gid,
                deployment_id=str(document["deployment_id"]),
                maintenance_root=self.maintenance_runtime,
            )
        )

    def test_concurrent_publication_never_overwrites_existing_owner(self) -> None:
        first = self._document()
        activate_maintenance(
            expected_uid=self.uid,
            expected_gid=self.gid,
            deployment_id=str(first["deployment_id"]),
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=str(first["message"]),
            retry_after_seconds=int(first["retry_after_seconds"]),
            started_at=str(first["started_at"]),
            maintenance_root=self.maintenance_runtime,
        )
        with self.assertRaisesRegex(
            MaintenanceMarkerError, "already owns"
        ):
            activate_maintenance(
                expected_uid=self.uid,
                expected_gid=self.gid,
                deployment_id=str(uuid.uuid4()),
                scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
                message=str(first["message"]),
                retry_after_seconds=int(first["retry_after_seconds"]),
                started_at=str(first["started_at"]),
                maintenance_root=self.maintenance_runtime,
            )
        current = load_maintenance_state(maintenance_root=self.maintenance_runtime)
        self.assertIsNotNone(current)
        self.assertEqual(current.deployment_id, first["deployment_id"])

    def test_broker_runtime_removal_does_not_clear_maintenance(self) -> None:
        document = self._document()
        activate_maintenance(
            expected_uid=self.uid,
            expected_gid=self.gid,
            deployment_id=str(document["deployment_id"]),
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=str(document["message"]),
            retry_after_seconds=int(document["retry_after_seconds"]),
            started_at=str(document["started_at"]),
            maintenance_root=self.maintenance_runtime,
        )
        self.broker_runtime.rmdir()
        with self.assertRaises(BrokerError) as caught:
            self._client().call(self._request(BrokerOperation.INVENTORY_READ))
        self.assertEqual(caught.exception.code, "maintenance_in_progress")
        self.assertTrue((self.maintenance_runtime / "maintenance.json").is_file())


if __name__ == "__main__":
    unittest.main()
