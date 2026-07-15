from __future__ import annotations

import socket
import subprocess
import tempfile
from pathlib import Path
import unittest

from devcoordinator.broker import BrokerBackendError
from devcoordinator.broker_host import LocalBrokerHostMutations, _port_available
from devcoordinator.broker_persistence import DockerMutationTarget


class BrokerHostMutationTests(unittest.TestCase):
    def test_listener_adoption_requires_exact_typed_repository_evidence(self) -> None:
        root = str(Path(tempfile.gettempdir()).resolve())
        calls: list[tuple[int, str]] = []

        def verifier(port: int, canonical_root: str) -> dict[str, object]:
            calls.append((port, canonical_root))
            return {
                "pid": 123,
                "process_identity": "fixture:123:1",
                "cwd": canonical_root,
                "canonical_root": canonical_root,
                "port": port,
                "protocol": "tcp",
            }

        host = LocalBrokerHostMutations(listener_verifier=verifier)
        evidence = host.verify_owned_tcp_listener(port=41001, canonical_root=root)
        self.assertEqual(evidence["pid"], 123)
        self.assertEqual(calls, [(41001, root)])

        foreign = LocalBrokerHostMutations(
            listener_verifier=lambda port, canonical_root: {
                "pid": 456,
                "process_identity": "fixture:456:1",
                "cwd": "/foreign",
                "canonical_root": "/foreign",
                "port": port,
                "protocol": "tcp",
            }
        )
        with self.assertRaises(BrokerBackendError):
            foreign.verify_owned_tcp_listener(port=41001, canonical_root=root)

    def test_port_selection_uses_only_typed_authorized_candidates(self) -> None:
        calls: list[tuple[int, str]] = []

        def probe(port: int, protocol: str) -> bool:
            calls.append((port, protocol))
            return port == 41002

        host = LocalBrokerHostMutations(port_probe=probe)
        self.assertEqual(
            host.select_available_port(candidates=(41001, 41002, 41003), protocol="tcp"),
            41002,
        )
        self.assertEqual(calls, [(41001, "tcp"), (41002, "tcp")])
        with self.assertRaises(ValueError):
            host.select_available_port(candidates=(41001, 41001), protocol="tcp")
        with self.assertRaises(ValueError):
            host.select_available_port(candidates=(41001,), protocol="sctp")

    def test_real_port_probe_catches_an_occupied_listener(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("0.0.0.0", 0))
            listener.listen()
            port = int(listener.getsockname()[1])
            self.assertFalse(_port_available(port, "tcp"))

    def test_docker_mutation_uses_full_immutable_id_and_fixed_action(self) -> None:
        calls: list[tuple[tuple[str, ...], float]] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append((command, timeout))
            return subprocess.CompletedProcess(command, 0, stdout="container-id\n", stderr="")

        target = DockerMutationTarget("docker-resource", "a" * 64, 11, 7)
        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_runner=runner,
        )
        result = host.docker_restart(target)
        self.assertEqual(calls, [(('/trusted/docker', 'restart', 'a' * 64), 9.0)])
        self.assertEqual(result["resource_id"], "docker-resource")
        self.assertEqual(result["full_container_id"], "a" * 64)
        self.assertEqual(result["observation_revision"], 11)
        self.assertNotIn("command", result)

    def test_docker_mutation_rejects_name_or_short_id_before_runner(self) -> None:
        called = False

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal called
            called = True
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(ValueError):
            host.docker_start(DockerMutationTarget("docker-resource", "friendly-name", 1, 1))
        self.assertFalse(called)

    def test_docker_failure_retains_bounded_diagnostic(self) -> None:
        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="not found")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaisesRegex(RuntimeError, "not found"):
            host.docker_stop(DockerMutationTarget("docker-resource", "b" * 64, 1, 1))


if __name__ == "__main__":
    unittest.main()
