"""Focused exact-identity contracts for broker-owned runtime log capture."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.broker_host import LocalBrokerHostMutations  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    RuntimeDockerMutationTarget,
    RuntimeServiceLogTarget,
    StoreBackedRequestAcceptor,
)
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.runtime_artifacts import (  # noqa: E402
    RUNTIME_LOG_MAX_BYTES,
    RUNTIME_LOG_MAX_LINES,
)
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    CONTAINER_ID,
    HOST_ID,
    PROJECT_ID,
    SERVER_ID,
    CanonicalTemporaryDirectory,
    peer_for,
    request_for,
    seed_store_backed_broker,
)
from devcoordinator.tests.test_broker_runtime import runtime_arguments  # noqa: E402


_FULL_CONTAINER_ID = "a" * 64


def _runtime_target() -> RuntimeDockerMutationTarget:
    return RuntimeDockerMutationTarget(
        resource_kind="docker",
        resource_id=CONTAINER_ID,
        docker_resource_id=CONTAINER_ID,
        full_container_id=_FULL_CONTAINER_ID,
        database_binding_id=None,
        database_name=None,
        observation_revision=11,
        control_generation=7,
        immutable_fingerprint="sha256:" + "b" * 64,
    )


class BrokerHostRuntimeLogCaptureTests(unittest.TestCase):
    def test_postgres_helper_timeout_kills_private_process_group_and_stays_uncertain(
        self,
    ) -> None:
        process = mock.Mock()
        process.pid = 4123
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(("postgres-helper",), 9),
            ("", ""),
        ]
        process.returncode = -signal.SIGTERM
        with mock.patch(
            "devcoordinator.broker_host.subprocess.Popen", return_value=process
        ) as popen, mock.patch(
            "devcoordinator.broker_host.os.killpg"
        ) as killpg:
            with self.assertRaises(BrokerBackendError) as raised:
                LocalBrokerHostMutations._run_postgres_tool(
                    ("/trusted/postgres-helper", "backup"),
                    9,
                    {"PATH": "/usr/bin"},
                )

        self.assertEqual(raised.exception.code, "operation_outcome_uncertain")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(4123, signal.SIGTERM)

    def test_capture_invokes_only_the_full_immutable_id_with_fixed_bounds(self) -> None:
        calls: list[tuple[tuple[str, ...], float, int]] = []

        def runner(
            command: tuple[str, ...], timeout: float, maximum_buffer: int
        ) -> tuple[bytes, int]:
            calls.append((command, timeout, maximum_buffer))
            return b"bounded log\n", 17

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_log_runner=runner,
        )

        payload, discarded = host.docker_capture_logs(_runtime_target())

        self.assertEqual(payload, b"bounded log\n")
        self.assertEqual(discarded, 17)
        self.assertEqual(
            calls,
            [
                (
                    (
                        "/trusted/docker",
                        "logs",
                        "--tail",
                        str(RUNTIME_LOG_MAX_LINES),
                        "--timestamps",
                        _FULL_CONTAINER_ID,
                    ),
                    9.0,
                    RUNTIME_LOG_MAX_BYTES + 64 * 1024,
                )
            ],
        )

    def test_capture_rejects_a_name_or_short_id_before_host_invocation(self) -> None:
        called = False

        def runner(
            _command: tuple[str, ...], _timeout: float, _maximum_buffer: int
        ) -> tuple[bytes, int]:
            nonlocal called
            called = True
            return b"", 0

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_log_runner=runner
        )
        with self.assertRaises(BrokerError) as raised:
            host.docker_capture_logs(
                replace(_runtime_target(), full_container_id="friendly-name")
            )

        self.assertEqual(raised.exception.code, "runtime_log_identity_invalid")
        self.assertFalse(called)


class BrokerRuntimeLogCaptureTests(unittest.TestCase):
    def test_wire_allows_read_only_capture_for_exact_runtime_targets(self) -> None:
        arguments = runtime_arguments(action="capture_logs")
        request = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=CONTAINER_ID,
            arguments=arguments,
        )
        self.assertEqual(request.arguments, arguments)

        service = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=CONTAINER_ID,
            arguments=runtime_arguments(
                action="capture_logs", target_kind="service"
            ),
        )
        self.assertEqual(service.arguments["target_kind"], "service")
        with self.assertRaises(BrokerError):
            request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=CONTAINER_ID,
                arguments=runtime_arguments(
                    action="capture_logs", ttl_seconds=1
                ),
            )

if __name__ == "__main__":
    unittest.main()
