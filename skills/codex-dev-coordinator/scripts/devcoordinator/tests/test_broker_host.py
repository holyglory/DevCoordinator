from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import unittest
from unittest import mock

from devcoordinator.broker import BrokerBackendError
from devcoordinator import broker_host as broker_host_module
from devcoordinator.broker_host import LocalBrokerHostMutations, _port_available
from devcoordinator.broker_persistence import DockerMutationTarget


class BrokerHostMutationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs observer")
    def test_linux_listener_proof_does_not_depend_on_lsof(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".broker-proc-listener-", dir=str(Path.home().resolve())
        ) as raw_root:
            root = Path(raw_root).resolve()
            ready = root / "listener.ready"
            fixture = (
                "import os,signal,socket,sys;"
                "sock=socket.socket();"
                "sock.bind(('127.0.0.1',0));"
                "sock.listen();"
                "open(sys.argv[1],'w').write(str(sock.getsockname()[1]));"
                "signal.pause()"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", fixture, str(ready)],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("listener fixture did not become ready")
                    time.sleep(0.02)
                self.assertIsNone(process.poll())
                port = int(ready.read_text(encoding="utf-8"))
                with mock.patch.object(
                    broker_host_module,
                    "_resolve_lsof_executable",
                    side_effect=AssertionError("Linux listener proof reached lsof"),
                ):
                    evidence = broker_host_module._verify_owned_tcp_listener(
                        port, str(root)
                    )
                self.assertEqual(evidence["pid"], process.pid)
                self.assertEqual(evidence["cwd"], str(root))
                self.assertEqual(evidence["owner_uid"], os.geteuid())
                foreign = root / "foreign"
                foreign.mkdir()
                with self.assertRaisesRegex(
                    BrokerBackendError, "another repository"
                ):
                    broker_host_module._verify_owned_tcp_listener(
                        port, str(foreign)
                    )
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

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
