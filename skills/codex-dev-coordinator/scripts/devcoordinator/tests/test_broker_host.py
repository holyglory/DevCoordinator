from __future__ import annotations

import json
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
from devcoordinator.broker_host import (
    EPHEMERAL_DOCKER_LABELS,
    EphemeralDockerContainerTarget,
    EphemeralDockerCreateTarget,
    EphemeralDockerIdentity,
    LocalBrokerHostMutations,
    _port_available,
)
from devcoordinator.broker_persistence import DockerMutationTarget, EphemeralImageTarget
from devcoordinator.ephemeral_secrets import EphemeralSecretMount, EphemeralSecretPolicy
from devcoordinator.worker_native import project_repository_slice


_RUN_ID = "12345678-1234-4234-8234-123456789abc"
_RUN_HEX = _RUN_ID.replace("-", "")
_NONCE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
_FULL_ID = "a" * 64
_IMAGE_REF = "registry.example/artifact@sha256:" + "b" * 64
_PROJECT_SLICE = project_repository_slice(uid=501, repository_id="repo-123")


def _docker_target(
    full_id: str, observation_revision: int = 1, control_generation: int = 1
) -> DockerMutationTarget:
    return DockerMutationTarget(
        "docker-resource",
        full_id,
        observation_revision,
        control_generation,
        repo_id="repo-123",
        owner_uid=501,
    )


def _ephemeral_identity() -> EphemeralDockerIdentity:
    return EphemeralDockerIdentity(
        run_id=_RUN_ID,
        creation_nonce=_NONCE,
        repository_id="repo-123",
        template_id="artifact-postgres",
        definition_fingerprint="sha256:" + "f" * 64,
    )


def _ephemeral_create_target(**overrides: object) -> EphemeralDockerCreateTarget:
    values: dict[str, object] = {
        "identity": _ephemeral_identity(),
        "owner_uid": 501,
        "container_name": f"devcoordinator-artifact-postgres-{_RUN_HEX}",
        "image_ref": "postgres@sha256:" + "b" * 64,
        "command": ("postgres", "-c", "fsync=off"),
        "environment": (("POSTGRES_PASSWORD", "top secret"),),
        "memory_bytes": 512 * 1024 * 1024,
        "cpu_limit": "1.50",
        "host_tcp_port": 55439,
        "container_tcp_port": 5432,
    }
    values.update(overrides)
    return EphemeralDockerCreateTarget(**values)  # type: ignore[arg-type]


def _ephemeral_image_target() -> EphemeralImageTarget:
    return EphemeralImageTarget(
        template_id="artifact-postgres",
        repo_id="repo-123",
        image_ref=_IMAGE_REF,
        template_fingerprint="sha256:" + "f" * 64,
    )


def _image_inspect_stdout(
    *, config_volumes: object | None = None, **overrides: object
) -> str:
    evidence: dict[str, object] = {
        "Id": "sha256:" + "c" * 64,
        "RepoDigests": [_IMAGE_REF],
        "Os": "linux",
        "Architecture": "amd64",
    }
    if config_volumes is not None:
        evidence["Config"] = {"Volumes": config_volumes}
    evidence.update(overrides)
    return json.dumps(evidence, separators=(",", ":"))


def _ephemeral_inspect_stdout(
    *,
    full_id: str = _FULL_ID,
    identity: EphemeralDockerIdentity | None = None,
    status: str = "created",
    running: bool = False,
    restart_policy: str = "no",
    privileged: bool = False,
    binds: object = None,
    mounts: object = None,
    cap_add: object = None,
    devices: object = None,
    network_mode: str = "bridge",
    pid_mode: str = "",
    state_pid: int = 0,
    networks: object | None = None,
) -> str:
    source = identity or _ephemeral_identity()
    labels = dict(
        zip(
            EPHEMERAL_DOCKER_LABELS,
            (
                source.run_id,
                source.creation_nonce,
                source.repository_id,
                source.template_id,
                source.definition_fingerprint,
            ),
        )
    )
    return "\t".join(
        json.dumps(value, separators=(",", ":"))
        for value in (
            full_id,
            status,
            running,
            restart_policy,
            labels,
            privileged,
            binds,
            mounts,
            cap_add,
            devices,
            network_mode,
            pid_mode,
            state_pid,
            {} if networks is None else networks,
        )
    )


def _anonymous_image_volume_mount(
    destination: str, *, name: str = "c" * 64
) -> dict[str, object]:
    return {
        "Type": "volume",
        "Name": name,
        "Source": f"/var/lib/docker/volumes/{name}/_data",
        "Destination": destination,
        "Driver": "local",
        "RW": True,
    }


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
                self.assertNotIn("owner_uid", evidence)
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

    def test_local_file_exchange_does_not_require_owner_or_mode_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "service.log"
            log.write_bytes(b"first\nsecond\n")
            log.chmod(0o666)
            payload, discarded, identity = (
                LocalBrokerHostMutations._read_bounded_service_log(
                    str(log), maximum_buffer=7
                )
            )
            self.assertEqual(payload, b"second\n")
            self.assertEqual(discarded, 6)
            self.assertRegex(identity, r"^sha256:[0-9a-f]{64}$")

            output = root / "shared-output"
            output.mkdir(mode=0o777)
            output.chmod(0o777)
            self.assertEqual(
                broker_host_module._require_service_output_root(str(output)),
                output,
            )

    def test_local_postgres_password_mount_ignores_owner_mode_and_link_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "material"
            source.mkdir()
            source.chmod(0o777)
            password = source / "postgres-initdb-password"
            password.write_bytes(b"not-a-real-password")
            password.chmod(0o666)
            os.link(password, source / "same-material")
            mount = EphemeralSecretMount(
                policy=EphemeralSecretPolicy(
                    kind="postgres_initdb_password_file_v1",
                    binding_id="0d5cc838-1c5e-440b-a286-819d60efcb8a",
                ),
                source_directory=source,
            )
            self.assertIs(
                broker_host_module._validate_ephemeral_secret_mount(
                    mount, require_material=True
                ),
                mount,
            )

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
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(_PROJECT_SLICE), stderr=""
                )
            return subprocess.CompletedProcess(command, 0, stdout="container-id\n", stderr="")

        target = _docker_target("a" * 64, 11, 7)
        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_runner=runner,
        )
        result = host.docker_restart(target)
        self.assertEqual(
            calls,
            [
                ((
                    "/trusted/docker",
                    "inspect",
                    "--format",
                    "{{json .HostConfig.CgroupParent}}",
                    "a" * 64,
                ), 9.0),
                (("/trusted/docker", "restart", "a" * 64), 9.0),
            ],
        )
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
            host.docker_start(_docker_target("friendly-name"))
        self.assertFalse(called)

    def test_docker_start_refuses_container_outside_repository_slice(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(command: tuple[str, ...], timeout: float):
            del timeout
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps("system.slice"),
                stderr="",
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_start(_docker_target("e" * 64))
        self.assertEqual(raised.exception.code, "project_isolation_mismatch")
        self.assertEqual(len(calls), 1, "unsafe container reached a start mutation")

    def test_docker_nonzero_exit_is_outcome_uncertain_without_host_diagnostic(
        self,
    ) -> None:
        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(_PROJECT_SLICE), stderr=""
                )
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="not found")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_stop(_docker_target("b" * 64))
        self.assertEqual(raised.exception.code, "operation_outcome_uncertain")
        self.assertNotIn("not found", raised.exception.message)

    def test_docker_timeout_is_outcome_uncertain(self) -> None:
        def runner(command: tuple[str, ...], timeout: float):
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(_PROJECT_SLICE), stderr=""
                )
            raise subprocess.TimeoutExpired(command, timeout)

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_restart(
                _docker_target("c" * 64)
            )
        self.assertEqual(raised.exception.code, "operation_outcome_uncertain")

    def test_docker_runner_exception_is_outcome_uncertain(self) -> None:
        def runner(command: tuple[str, ...], timeout: float):
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(_PROJECT_SLICE), stderr=""
                )
            raise OSError("sensitive host diagnostic")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_start(
                _docker_target("d" * 64)
            )
        self.assertEqual(raised.exception.code, "operation_outcome_uncertain")
        self.assertNotIn("sensitive", raised.exception.message)

    def test_ephemeral_image_status_requires_exact_digest_platform_proof(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(
                command, 0, stdout=_image_inspect_stdout() + "\n", stderr=""
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        result = host.docker_inspect_ephemeral_image(_ephemeral_image_target())

        self.assertEqual(
            calls,
            [
                (
                    "/trusted/docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    _IMAGE_REF,
                )
            ],
        )
        self.assertEqual(result["repo_digest"], _IMAGE_REF)
        self.assertEqual(result["os"], "linux")
        self.assertEqual(result["architecture"], "amd64")

    def test_ephemeral_image_status_rejects_missing_or_wrong_proof(self) -> None:
        invalid = (
            {"RepoDigests": []},
            {"Id": "sha256:" + "A" * 64},
            {"Os": "darwin"},
            {"Architecture": "arm64"},
            {"RepoDigests": [_IMAGE_REF + "-other"]},
        )
        for evidence in invalid:
            with self.subTest(evidence=evidence):
                host = LocalBrokerHostMutations(
                    docker_executable="/trusted/docker",
                    docker_runner=lambda command, timeout: subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=_image_inspect_stdout(**evidence),
                        stderr="",
                    ),
                )
                with self.assertRaises(BrokerBackendError) as raised:
                    host.docker_inspect_ephemeral_image(_ephemeral_image_target())
                self.assertEqual(
                    raised.exception.code, "ephemeral_image_inspect_unobservable"
                )

    def test_ephemeral_image_prefetch_pulls_only_known_absence_and_rechecks(self) -> None:
        calls: list[tuple[str, ...]] = []
        inspections = 0

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal inspections
            calls.append(command)
            if command[1:3] == ("image", "inspect"):
                inspections += 1
                if inspections == 1:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        stdout="",
                        stderr=f"Error response from daemon: No such image: {_IMAGE_REF}\n",
                    )
                return subprocess.CompletedProcess(
                    command, 0, stdout=_image_inspect_stdout(), stderr=""
                )
            self.assertEqual(command, ("/trusted/docker", "pull", "--quiet", _IMAGE_REF))
            return subprocess.CompletedProcess(command, 0, stdout="ignored", stderr="")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        result = host.docker_prefetch_ephemeral_image(_ephemeral_image_target())

        self.assertEqual(result["cache_origin"], "pulled")
        self.assertTrue(result["changed"])
        self.assertEqual(
            [command[1] for command in calls], ["image", "pull", "image"]
        )

    def test_ephemeral_image_prefetch_never_classifies_generic_failure_as_absence(self) -> None:
        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="temporary daemon failure"
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_prefetch_ephemeral_image(_ephemeral_image_target())
        self.assertEqual(raised.exception.code, "ephemeral_image_inspect_unobservable")
        self.assertNotIn("temporary daemon failure", raised.exception.message)

    def test_ephemeral_create_uses_sealed_fixed_argv_and_stays_stopped(self) -> None:
        calls: list[tuple[str, ...]] = []
        environment_payloads: list[bytes] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            self.assertEqual(timeout, 9.0)
            calls.append(command)
            if command[1] == "create":
                env_path = command[command.index("--env-file") + 1]
                environment_payloads.append(Path(env_path).read_bytes())
                return subprocess.CompletedProcess(
                    command, 0, stdout=_FULL_ID + "\n", stderr=""
                )
            self.assertEqual(command[1:4], ("inspect", "--type", "container"))
            return subprocess.CompletedProcess(
                command, 0, stdout=_ephemeral_inspect_stdout() + "\n", stderr=""
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_runner=runner,
        )
        result = host.docker_create_ephemeral(_ephemeral_create_target())

        create = calls[0]
        self.assertEqual(
            create[:19],
            (
                "/trusted/docker",
                "create",
                "--name",
                f"devcoordinator-artifact-postgres-{_RUN_HEX}",
                "--pull",
                "never",
                "--restart",
                "no",
                "--network",
                "bridge",
                "--memory",
                str(512 * 1024 * 1024),
                "--cpus",
                "1.5",
                "--pids-limit",
                "4096",
                "--cgroup-parent",
                _PROJECT_SLICE,
                "--label",
            ),
        )
        expected_labels = dict(
            zip(
                EPHEMERAL_DOCKER_LABELS,
                (
                    _RUN_ID,
                    _NONCE,
                    "repo-123",
                    "artifact-postgres",
                    "sha256:" + "f" * 64,
                ),
            )
        )
        label_arguments = tuple(
            create[index + 1]
            for index, value in enumerate(create)
            if value == "--label"
        )
        self.assertEqual(
            label_arguments,
            tuple(f"{name}={value}" for name, value in expected_labels.items()),
        )
        self.assertIn("127.0.0.1:55439:5432/tcp", create)
        self.assertNotIn("top secret", create)
        self.assertEqual(environment_payloads, [b"POSTGRES_PASSWORD=top secret\n"])
        self.assertEqual(result["full_container_id"], _FULL_ID)
        self.assertFalse(result["running"])
        self.assertEqual(result["action"], "create")

    def test_ephemeral_create_preserves_secret_mount_for_post_create_proof(self) -> None:
        """A policy-backed create must prove its one expected read-only mount."""

        with tempfile.TemporaryDirectory() as directory:
            source_directory = Path(directory) / "material"
            source_directory.mkdir(mode=0o700)
            password = source_directory / "postgres-initdb-password"
            password.write_bytes(b"not-a-real-password")
            password.chmod(0o400)
            secret_mount = EphemeralSecretMount(
                policy=EphemeralSecretPolicy(
                    kind="postgres_initdb_password_file_v1",
                    binding_id="0d5cc838-1c5e-440b-a286-819d60efcb8a",
                ),
                source_directory=source_directory,
            )
            calls: list[tuple[str, ...]] = []

            def runner(
                command: tuple[str, ...], timeout: float
            ) -> subprocess.CompletedProcess[str]:
                self.assertEqual(timeout, 9.0)
                calls.append(command)
                if command[1] == "create":
                    self.assertIn("--mount", command)
                    self.assertIn("readonly", command[command.index("--mount") + 1])
                    env_path = command[command.index("--env-file") + 1]
                    self.assertEqual(
                        Path(env_path).read_bytes(),
                        b"POSTGRES_PASSWORD_FILE="
                        b"/run/devcoordinator-credentials/postgres-initdb-password\n",
                    )
                    return subprocess.CompletedProcess(
                        command, 0, stdout=_FULL_ID + "\n", stderr=""
                    )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=_ephemeral_inspect_stdout(
                        mounts=[
                            {
                                "Type": "bind",
                                "Source": str(source_directory),
                                "Destination": secret_mount.container_directory,
                                "RW": False,
                            }
                        ]
                    )
                    + "\n",
                    stderr="",
                )

            host = LocalBrokerHostMutations(
                docker_executable="/trusted/docker",
                docker_timeout_seconds=9,
                docker_runner=runner,
            )
            result = host.docker_create_ephemeral(
                _ephemeral_create_target(
                    environment=secret_mount.environment, secret_mount=secret_mount
                )
            )

        self.assertEqual(result["full_container_id"], _FULL_ID)
        self.assertEqual([command[1] for command in calls], ["create", "inspect"])
        inspect_format = calls[1][calls[1].index("--format") + 1]
        self.assertIn("{{json .Mounts}}", inspect_format)
        self.assertNotIn("{{json .HostConfig.Mounts}}", inspect_format)

    def test_ephemeral_secret_mount_rejects_host_config_mount_shape(self) -> None:
        """Only Docker's realized top-level mount schema can prove read-only."""

        with tempfile.TemporaryDirectory() as directory:
            source_directory = Path(directory) / "material"
            source_directory.mkdir(mode=0o700)
            secret_mount = EphemeralSecretMount(
                policy=EphemeralSecretPolicy(
                    kind="postgres_initdb_password_file_v1",
                    binding_id="0d5cc838-1c5e-440b-a286-819d60efcb8a",
                ),
                source_directory=source_directory,
            )

            def runner(
                command: tuple[str, ...], timeout: float
            ) -> subprocess.CompletedProcess[str]:
                self.assertEqual(timeout, 9.0)
                inspect_format = command[command.index("--format") + 1]
                self.assertIn("{{json .Mounts}}", inspect_format)
                self.assertNotIn("{{json .HostConfig.Mounts}}", inspect_format)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=_ephemeral_inspect_stdout(
                        mounts=[
                            {
                                "Type": "bind",
                                "Source": str(source_directory),
                                "Target": secret_mount.container_directory,
                                "ReadOnly": True,
                            }
                        ]
                    ),
                    stderr="",
                )

            host = LocalBrokerHostMutations(
                docker_executable="/trusted/docker",
                docker_timeout_seconds=9,
                docker_runner=runner,
            )
            with self.assertRaises(BrokerBackendError) as raised:
                host.docker_inspect_ephemeral(
                    EphemeralDockerContainerTarget(
                        _ephemeral_identity(), _FULL_ID, secret_mount
                    )
                )

        self.assertEqual(
            raised.exception.code,
            "ephemeral_docker_safety_profile_mismatch",
        )

    def test_ephemeral_create_accepts_image_declared_anonymous_volume_and_removes_it(
        self,
    ) -> None:
        """An image-declared local anonymous volume is sealed, not a host mount."""

        destination = "/var/lib/postgresql/data"
        with tempfile.TemporaryDirectory() as directory:
            source_directory = Path(directory) / "material"
            source_directory.mkdir(mode=0o700)
            password = source_directory / "postgres-initdb-password"
            password.write_bytes(b"not-a-real-password")
            password.chmod(0o400)
            secret_mount = EphemeralSecretMount(
                policy=EphemeralSecretPolicy(
                    kind="postgres_initdb_password_file_v1",
                    binding_id="0d5cc838-1c5e-440b-a286-819d60efcb8a",
                ),
                source_directory=source_directory,
            )
            calls: list[tuple[str, ...]] = []

            def runner(
                command: tuple[str, ...], timeout: float
            ) -> subprocess.CompletedProcess[str]:
                self.assertEqual(timeout, 9.0)
                calls.append(command)
                if command[1] == "create":
                    self.assertNotIn("--volume", command)
                    self.assertEqual(command.count("--mount"), 1)
                    return subprocess.CompletedProcess(
                        command, 0, stdout=_FULL_ID + "\n", stderr=""
                    )
                if command[1] == "image":
                    self.assertEqual(command[-1], _IMAGE_REF)
                    self.assertNotIn("pull", command)
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=_image_inspect_stdout(
                            config_volumes={destination: {}}
                        ),
                        stderr="",
                    )
                if command[1] == "inspect":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=_ephemeral_inspect_stdout(
                            mounts=[
                                {
                                    "Type": "bind",
                                    "Source": str(source_directory),
                                    "Destination": secret_mount.container_directory,
                                    "RW": False,
                                },
                                _anonymous_image_volume_mount(destination),
                            ]
                        )
                        + "\n",
                        stderr="",
                    )
                if command[1] == "rm":
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
                self.fail(f"unexpected Docker command: {command!r}")

            host = LocalBrokerHostMutations(
                docker_executable="/trusted/docker",
                docker_timeout_seconds=9,
                docker_runner=runner,
            )
            result = host.docker_create_ephemeral(
                _ephemeral_create_target(
                    image_ref=_IMAGE_REF,
                    environment=secret_mount.environment,
                    secret_mount=secret_mount,
                )
            )
            removed = host.docker_remove_ephemeral(
                EphemeralDockerContainerTarget(
                    _ephemeral_identity(),
                    _FULL_ID,
                    secret_mount,
                    image_ref=_IMAGE_REF,
                )
            )

        self.assertEqual(result["full_container_id"], _FULL_ID)
        self.assertTrue(removed["removed"])
        self.assertEqual(
            [command[1] for command in calls],
            ["create", "inspect", "image", "inspect", "rm"],
        )
        self.assertEqual(calls[-1], ("/trusted/docker", "rm", "--volumes", _FULL_ID))

    def test_ephemeral_profile_rejects_unsealed_implicit_volumes(self) -> None:
        """A Docker volume is accepted only when every sealed fact matches."""

        destination = "/var/lib/postgresql/data"
        valid = _anonymous_image_volume_mount(destination)
        too_many = {f"/data/{index}": {} for index in range(9)}
        cases: tuple[tuple[str, list[dict[str, object]], object], ...] = (
            ("named", [{**valid, "Name": "named-data"}], {destination: {}}),
            (
                "wrong-destination",
                [_anonymous_image_volume_mount("/other")],
                {destination: {}},
            ),
            (
                "extra-volume",
                [
                    valid,
                    _anonymous_image_volume_mount("/other", name="d" * 64),
                ],
                {destination: {}},
            ),
            ("readonly", [{**valid, "RW": False}], {destination: {}}),
            ("nonlocal-driver", [{**valid, "Driver": "nfs"}], {destination: {}}),
            ("wrong-source", [{**valid, "Source": "/outside"}], {destination: {}}),
            ("undeclared", [valid], {}),
            ("malformed-declaration", [valid], [destination]),
            ("relative-declaration", [valid], {"relative": {}}),
            ("too-many-declarations", [valid], too_many),
            ("non-object-options", [valid], {destination: []}),
        )
        for case, mounts, config_volumes in cases:
            with self.subTest(case=case):

                def runner(
                    command: tuple[str, ...], timeout: float
                ) -> subprocess.CompletedProcess[str]:
                    self.assertEqual(timeout, 9.0)
                    if command[1] == "image":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=_image_inspect_stdout(
                                config_volumes=config_volumes
                            ),
                            stderr="",
                        )
                    self.assertEqual(command[1], "inspect")
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=_ephemeral_inspect_stdout(mounts=mounts),
                        stderr="",
                    )

                host = LocalBrokerHostMutations(
                    docker_executable="/trusted/docker",
                    docker_timeout_seconds=9,
                    docker_runner=runner,
                )
                with self.assertRaises(BrokerBackendError) as raised:
                    host.docker_inspect_ephemeral(
                        EphemeralDockerContainerTarget(
                            _ephemeral_identity(), _FULL_ID, image_ref=_IMAGE_REF
                        )
                    )
                self.assertEqual(
                    raised.exception.code,
                    "ephemeral_docker_safety_profile_mismatch",
                )

    def test_ephemeral_profile_rejects_implicit_volume_without_pinned_image(
        self,
    ) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            self.assertEqual(timeout, 9.0)
            calls.append(command)
            self.assertEqual(command[1], "inspect")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_ephemeral_inspect_stdout(
                    mounts=[_anonymous_image_volume_mount("/var/lib/postgresql/data")]
                ),
                stderr="",
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_timeout_seconds=9,
            docker_runner=runner,
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_inspect_ephemeral(
                EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
            )

        self.assertEqual(
            raised.exception.code,
            "ephemeral_docker_safety_profile_mismatch",
        )
        self.assertEqual([command[1] for command in calls], ["inspect"])

    def test_ephemeral_create_rejects_option_shaped_image_before_runner(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "image reference"):
            host.docker_create_ephemeral(
                _ephemeral_create_target(image_ref="--privileged")
            )
        self.assertFalse(called)

    def test_ephemeral_create_requires_full_run_uuid_name_suffix(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "container name"):
            host.docker_create_ephemeral(
                _ephemeral_create_target(
                    container_name="devcoordinator-artifact-postgres-12345678"
                )
            )
        self.assertFalse(called)

    def test_ephemeral_create_accepts_persisted_template_slug_charset(self) -> None:
        target = _ephemeral_create_target(
            container_name=f"devcoordinator-artifact.db_test-{_RUN_HEX}"
        )
        normalized = broker_host_module._validate_ephemeral_create_target(target)
        self.assertEqual(len(normalized["labels"]), len(EPHEMERAL_DOCKER_LABELS))

    def test_ephemeral_create_failure_is_structured_and_redacts_diagnostics(self) -> None:
        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command,
                125,
                stdout="",
                stderr="POSTGRES_PASSWORD=top secret",
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertLogs("devcoordinator.broker_host", level="ERROR") as logs:
            with self.assertRaises(BrokerBackendError) as raised:
                host.docker_create_ephemeral(_ephemeral_create_target())
        self.assertEqual(
            raised.exception.code, "ephemeral_docker_create_outcome_unknown"
        )
        self.assertNotIn("top secret", raised.exception.message)
        self.assertIn("phase=create", "\n".join(logs.output))
        self.assertIn("returncode=125", "\n".join(logs.output))
        self.assertNotIn("top secret", "\n".join(logs.output))

    def test_ephemeral_create_runner_exception_is_structured_and_recoverable(self) -> None:
        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(command, timeout, stderr="secret diagnostic")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertLogs("devcoordinator.broker_host", level="ERROR") as logs:
            with self.assertRaises(BrokerBackendError) as raised:
                host.docker_create_ephemeral(_ephemeral_create_target())
        self.assertEqual(
            raised.exception.code, "ephemeral_docker_create_outcome_unknown"
        )
        self.assertIn("reconciliation by persisted labels", raised.exception.message)
        self.assertNotIn("secret diagnostic", raised.exception.message)
        self.assertIn("exception=TimeoutExpired", "\n".join(logs.output))
        self.assertNotIn("secret diagnostic", "\n".join(logs.output))

    def test_ephemeral_cleanup_failure_retains_body_and_cleanup_failures(self) -> None:
        body = BrokerBackendError(
            "ephemeral_docker_create_outcome_unknown",
            "Docker create outcome is unknown.",
        )
        combined = broker_host_module._ephemeral_environment_cleanup_failure(
            body,
            body_completed=False,
        )
        self.assertEqual(
            combined.code,
            "ephemeral_docker_create_outcome_unknown_and_environment_cleanup_failed",
        )
        self.assertIn("Docker create outcome is unknown", combined.message)
        self.assertIn("environment also could not be removed", combined.message)

        completed = broker_host_module._ephemeral_environment_cleanup_failure(
            None,
            body_completed=True,
        )
        self.assertEqual(
            completed.code,
            "ephemeral_docker_create_outcome_unknown_and_environment_cleanup_failed",
        )
        self.assertIn("may have produced", completed.message)

    def test_ephemeral_find_uses_every_label_then_exact_inspect(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command[1:3] == ("container", "ls"):
                return subprocess.CompletedProcess(
                    command, 0, stdout=_FULL_ID + "\n", stderr=""
                )
            return subprocess.CompletedProcess(
                command, 0, stdout=_ephemeral_inspect_stdout(), stderr=""
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        found = host.docker_find_ephemeral(_ephemeral_identity())
        self.assertTrue(found["found"])
        filters = tuple(
            calls[0][index + 1]
            for index, value in enumerate(calls[0])
            if value == "--filter"
        )
        self.assertEqual(len(filters), 5)
        for name in EPHEMERAL_DOCKER_LABELS:
            self.assertTrue(any(item.startswith(f"label={name}=") for item in filters))
        self.assertEqual(calls[1][-1], _FULL_ID)

    def test_ephemeral_mutation_refuses_wrong_labels_before_action(self) -> None:
        calls: list[tuple[str, ...]] = []
        foreign = EphemeralDockerIdentity(
            run_id=_RUN_ID,
            creation_nonce=_NONCE,
            repository_id="repo-foreign",
            template_id="artifact-postgres",
            definition_fingerprint="sha256:" + "f" * 64,
        )

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_ephemeral_inspect_stdout(identity=foreign),
                stderr="",
            )

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        with self.assertRaises(BrokerBackendError) as raised:
            host.docker_start_ephemeral(
                EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
            )
        self.assertEqual(raised.exception.code, "ephemeral_docker_identity_mismatch")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "inspect")

    def test_ephemeral_start_and_stop_verify_exact_state_transitions(self) -> None:
        calls: list[tuple[str, ...]] = []
        running = False

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal running
            calls.append(command)
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=_ephemeral_inspect_stdout(
                        status="running" if running else "exited",
                        running=running,
                    ),
                    stderr="",
                )
            if command[1] == "start":
                running = True
            elif command[1] == "stop":
                running = False
            return subprocess.CompletedProcess(command, 0, stdout=_FULL_ID, stderr="")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        target = EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
        started = host.docker_start_ephemeral(target)
        stopped = host.docker_stop_ephemeral(target)
        self.assertTrue(started["changed"])
        self.assertTrue(stopped["changed"])
        mutation_calls = tuple(call for call in calls if call[1] != "inspect")
        self.assertEqual(
            mutation_calls,
            (
                ("/trusted/docker", "start", _FULL_ID),
                ("/trusted/docker", "stop", "--time", "10", _FULL_ID),
            ),
        )

    def test_ephemeral_inspect_rejects_each_unsafe_host_profile(self) -> None:
        unsafe = (
            {"restart_policy": "always"},
            {"privileged": True},
            {"binds": ["/host:/mnt"]},
            {"mounts": [{"Type": "bind", "Source": "/host"}]},
            {"cap_add": ["SYS_ADMIN"]},
            {"devices": [{"PathOnHost": "/dev/kvm"}]},
            {"network_mode": "host"},
            {"pid_mode": "host"},
        )
        for override in unsafe:
            with self.subTest(override=override):
                host = LocalBrokerHostMutations(
                    docker_executable="/trusted/docker",
                    docker_runner=(
                        lambda command, timeout, override=override: (
                            subprocess.CompletedProcess(
                                command,
                                0,
                                stdout=_ephemeral_inspect_stdout(**override),
                                stderr="",
                            )
                        )
                    ),
                )
                with self.assertRaises(BrokerBackendError) as raised:
                    host.docker_inspect_ephemeral(
                        EphemeralDockerContainerTarget(
                            _ephemeral_identity(), _FULL_ID
                        )
                    )
                self.assertEqual(
                    raised.exception.code,
                    "ephemeral_docker_safety_profile_mismatch",
                )

    def test_ephemeral_remove_requires_stopped_and_removes_anonymous_volumes(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command, 0, stdout=_ephemeral_inspect_stdout(), stderr=""
                )
            return subprocess.CompletedProcess(command, 0, stdout=_FULL_ID, stderr="")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        result = host.docker_remove_ephemeral(
            EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
        )
        self.assertTrue(result["removed"])
        self.assertEqual(
            calls[-1], ("/trusted/docker", "rm", "--volumes", _FULL_ID)
        )
        self.assertNotIn("--force", calls[-1])
        self.assertIn("--volumes", calls[-1])

        running_host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker",
            docker_runner=lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                stdout=_ephemeral_inspect_stdout(status="running", running=True),
                stderr="",
            ),
        )
        with self.assertRaises(BrokerBackendError) as raised:
            running_host.docker_remove_ephemeral(
                EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
            )
        self.assertEqual(
            raised.exception.code, "ephemeral_docker_remove_requires_stopped"
        )

    def test_ephemeral_cleanup_tolerates_profile_drift_and_disables_restart(self) -> None:
        calls: list[tuple[str, ...]] = []
        running = True
        restart_policy = "always"

        def runner(
            command: tuple[str, ...], timeout: float
        ) -> subprocess.CompletedProcess[str]:
            nonlocal running, restart_policy
            calls.append(command)
            if command[1] == "inspect":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=_ephemeral_inspect_stdout(
                        status="running" if running else "exited",
                        running=running,
                        restart_policy=restart_policy,
                        privileged=True,
                        binds=["/host:/mnt"],
                        mounts=[{"Type": "bind", "Source": "/host"}],
                        cap_add=["SYS_ADMIN"],
                        devices=[{"PathOnHost": "/dev/kvm"}],
                        network_mode="host",
                        pid_mode="host",
                    ),
                    stderr="",
                )
            if command[1] == "update":
                restart_policy = "no"
            elif command[1] == "stop":
                running = False
            return subprocess.CompletedProcess(command, 0, stdout=_FULL_ID, stderr="")

        host = LocalBrokerHostMutations(
            docker_executable="/trusted/docker", docker_runner=runner
        )
        target = EphemeralDockerContainerTarget(_ephemeral_identity(), _FULL_ID)
        stopped = host.docker_stop_ephemeral(target)
        removed = host.docker_remove_ephemeral(target)

        self.assertTrue(stopped["changed"])
        self.assertTrue(stopped["restart_policy_changed"])
        self.assertTrue(removed["removed"])
        mutation_calls = tuple(call for call in calls if call[1] != "inspect")
        self.assertEqual(
            mutation_calls,
            (
                ("/trusted/docker", "update", "--restart", "no", _FULL_ID),
                ("/trusted/docker", "stop", "--time", "10", _FULL_ID),
                ("/trusted/docker", "rm", "--volumes", _FULL_ID),
            ),
        )


if __name__ == "__main__":
    unittest.main()
