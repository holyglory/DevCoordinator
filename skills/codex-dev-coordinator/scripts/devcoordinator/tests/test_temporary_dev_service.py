from __future__ import annotations

from datetime import datetime, timezone
import errno
import os
from pathlib import Path
import pwd
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest import mock

from devcoordinator import agent_cli
from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    PeerCredentials,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import DurableOperationDisposition
from devcoordinator.temporary_dev_service import (
    TemporaryDevServiceError,
    TemporaryDevServiceManager,
    TemporaryDevServiceRequest,
    public_temporary_dev_service_error,
    temporary_dev_service_id,
    validate_temporary_dev_service_definition,
)


def _request(root: Path, *, operation_id: str | None = None, cwd: str = ".") -> TemporaryDevServiceRequest:
    return TemporaryDevServiceRequest(
        operation_id=operation_id or str(uuid.uuid4()),
        repository_id="repo-temporary-service",
        repository_root=str(root),
        repository_generation=3,
        execution_uid=os.getuid(),
        agent="codex:test",
        name="prototype",
        argv=(
            "npm",
            "run",
            "dev",
            "--",
            "--host",
            "0.0.0.0",
            "--port",
            "4173",
            "--strictPort",
        ),
        cwd=cwd,
        port=4173,
        ttl_seconds=3600,
        kill_after_run=False,
        launch_timeout_seconds=30,
    )


class _Runner:
    def __init__(
        self, *, active_initially: bool = False, active_state: str = "active"
    ) -> None:
        self.active = active_initially
        self.active_state = active_state
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self, argv: tuple[str, ...] | list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append(command)
        if command[:2] == ("/usr/bin/systemctl", "show"):
            if self.active:
                output = (
                    "LoadState=loaded\nActiveState="
                    + self.active_state
                    + "\nSubState=running\n"
                    "MainPID=123\nControlGroup=/devcoordinator/test.service\n"
                    "InvocationID=abcdef0123456789\n"
                )
            else:
                output = "LoadState=not-found\n"
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[0] == "/usr/bin/systemd-run":
            self.active = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ("/usr/bin/systemctl", "stop"):
            self.active = False
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ("/usr/bin/systemctl", "restart"):
            self.active = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == "/usr/bin/journalctl":
            return subprocess.CompletedProcess(command, 0, "diagnostic", "")
        raise AssertionError(command)


class TemporaryDevServiceManagerTests(unittest.TestCase):
    def test_retained_unit_supports_logs_stop_and_restart(self) -> None:
        unit = "devcoordinator-dev-" + "1" * 32 + ".service"
        runner = _Runner(active_initially=True)
        manager = TemporaryDevServiceManager(
            runner=runner,
            port_probe=lambda _port: runner.active,
            listener_ownership_probe=lambda _port, _state: True,
            process_uid_probe=lambda pid, uid: pid == 123 and uid == os.getuid(),
            monotonic=iter((0.0, 0.1)).__next__,
            sleep=lambda _seconds: None,
        )

        capture = manager.capture_logs(unit=unit, port=4173)
        restarted = manager.restart(
            unit=unit, port=4173, execution_uid=os.getuid()
        )
        stopped = manager.stop(unit=unit, port=4173)

        self.assertEqual(capture["raw"], b"diagnostic\n")
        self.assertTrue(capture["source_identity"].startswith("sha256:"))
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(restarted["state"], "running")
        self.assertTrue(restarted["ready"])

    def test_public_launch_diagnostic_is_bounded_and_redacted(self) -> None:
        error = TemporaryDevServiceError(
            "temporary_service_launch_failed",
            "systemd rejected the bounded temporary service",
            diagnostic=(
                "actual npm failure newest password=super-secret "
                "/home/developer/project/server.log "
                + "x" * 2_000
            ),
        )
        message = public_temporary_dev_service_error(error)
        self.assertLessEqual(len(message), 512)
        self.assertIn("password=[REDACTED]", message)
        self.assertIn("actual npm failure newest", message)
        self.assertIn("[PATH]", message)
        self.assertNotIn("super-secret", message)
        self.assertNotIn("/home/developer", message)

    def test_launch_uses_exact_structured_command_and_ttl_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            account_gid = pwd.getpwuid(os.getuid()).pw_gid
            runner = _Runner()
            probes = iter((False, True))
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: next(probes),
                listener_ownership_probe=lambda port, state: (
                    port == 4173
                    and state.get("ControlGroup") == "/devcoordinator/test.service"
                ),
                process_uid_probe=lambda pid, uid: (
                    pid == 123 and uid == os.getuid()
                ),
                monotonic=iter((0.0, 0.1)).__next__,
                sleep=lambda _seconds: None,
                wall_time=lambda: datetime(2026, 8, 4, tzinfo=timezone.utc),
            )

            with mock.patch(
                "devcoordinator.temporary_dev_service._execution_supplementary_gids",
                return_value=(1003, 1006),
            ):
                result = manager.start(_request(root))

        launch = next(call for call in runner.calls if call[0] == "/usr/bin/systemd-run")
        self.assertNotIn("--quiet", launch)
        self.assertIn("--property=RuntimeMaxSec=3600s", launch)
        self.assertIn("--property=KillMode=control-group", launch)
        self.assertFalse(any(item.startswith("--property=UMask=") for item in launch))
        self.assertIn("--working-directory=/", launch)
        self.assertIn("--setenv=PWD=" + str(root), launch)
        separator = launch.index("--")
        self.assertEqual(
            launch[separator + 1 :],
            (
                "/usr/bin/setpriv",
                "--reuid=" + str(os.getuid()),
                "--regid=" + str(account_gid),
                "--groups=1003,1006",
                "--inh-caps=-all",
                "--no-new-privs",
                "--",
                "/usr/bin/env",
                "--chdir=" + str(root),
                "--",
                *_request(root).argv,
            ),
        )
        self.assertFalse(
            any(
                item.startswith("--uid=") or item.startswith("--gid=")
                for item in launch[:separator]
            )
        )
        self.assertNotIn("--reuid=0", launch)
        self.assertNotIn("--regid=0", launch)
        self.assertNotIn("--groups=0", launch)
        self.assertFalse(any(item in {"sh", "bash", "/bin/sh", "/bin/bash"} for item in launch))
        self.assertEqual(result["port"], 4173)
        self.assertEqual(result["execution_uid"], os.getuid())
        self.assertEqual(result["cleanup"]["owner"], "systemd")
        self.assertEqual(result["cleanup"]["ttl_seconds"], 3600)
        self.assertTrue(result["isolation"]["listener_owner_proven"])
        self.assertTrue(result["isolation"]["actual_caller_uid_proven"])
        self.assertEqual(result["isolation"]["execution_uid"], os.getuid())
        self.assertEqual(
            result["isolation"]["control_group"],
            "/devcoordinator/test.service",
        )
        self.assertTrue(result["isolation"]["slice"].endswith(".slice"))
        self.assertEqual(result["expires_at"], "2026-08-04T01:00:00Z")
        self.assertFalse(result["reused"])


    def test_pre_catalog_systemd_rejection_falls_back_to_native_journal(self) -> None:
        class RejectingRunner(_Runner):
            def __call__(
                self, argv: tuple[str, ...] | list[str], *, timeout: float
            ) -> subprocess.CompletedProcess[str]:
                command = tuple(argv)
                self.calls.append(command)
                if command[:2] == ("/usr/bin/systemctl", "show"):
                    return subprocess.CompletedProcess(
                        command, 0, "LoadState=not-found\n", ""
                    )
                if command[0] == "/usr/bin/systemd-run":
                    return subprocess.CompletedProcess(command, 1, "", "")
                if command[0] == "/usr/bin/journalctl":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        "Failed at step GROUP spawning /usr/bin/env: Permission denied",
                        "",
                    )
                raise AssertionError(command)

        with tempfile.TemporaryDirectory() as directory:
            runner = RejectingRunner()
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: False,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(_request(Path(directory)))

        self.assertEqual(raised.exception.code, "temporary_service_launch_failed")
        self.assertIn("Failed at step GROUP", raised.exception.diagnostic or "")
        self.assertTrue(any(call[0] == "/usr/bin/journalctl" for call in runner.calls))

    def test_systemd_rejection_prefers_native_journal_over_generic_stderr(self) -> None:
        class RejectingRunner(_Runner):
            def __call__(
                self, argv: tuple[str, ...] | list[str], *, timeout: float
            ) -> subprocess.CompletedProcess[str]:
                command = tuple(argv)
                self.calls.append(command)
                if command[:2] == ("/usr/bin/systemctl", "show"):
                    return subprocess.CompletedProcess(
                        command, 0, "LoadState=not-found\n", ""
                    )
                if command[0] == "/usr/bin/systemd-run":
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "Job failed. See journalctl for details.",
                    )
                if command[0] == "/usr/bin/journalctl":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        "Failed at step CHDIR spawning /usr/bin/env: Permission denied",
                        "",
                    )
                raise AssertionError(command)

        with tempfile.TemporaryDirectory() as directory:
            manager = TemporaryDevServiceManager(
                runner=RejectingRunner(),
                port_probe=lambda _port: False,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(_request(Path(directory)))

        diagnostic = raised.exception.diagnostic or ""
        self.assertTrue(diagnostic.startswith("Failed at step CHDIR"))
        self.assertIn("See journalctl", diagnostic)

    def test_diagnostic_query_failure_preserves_definite_launch_rejection(self) -> None:
        class RejectingRunner(_Runner):
            def __call__(
                self, argv: tuple[str, ...] | list[str], *, timeout: float
            ) -> subprocess.CompletedProcess[str]:
                command = tuple(argv)
                self.calls.append(command)
                if command[:2] == ("/usr/bin/systemctl", "show"):
                    return subprocess.CompletedProcess(
                        command, 0, "LoadState=not-found\n", ""
                    )
                if command[0] == "/usr/bin/systemd-run":
                    return subprocess.CompletedProcess(
                        command, 1, "", "native systemd-run rejection"
                    )
                if command[0] == "/usr/bin/journalctl":
                    raise subprocess.TimeoutExpired(command, timeout)
                raise AssertionError(command)

        with tempfile.TemporaryDirectory() as directory:
            manager = TemporaryDevServiceManager(
                runner=RejectingRunner(),
                port_probe=lambda _port: False,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(_request(Path(directory)))

        self.assertEqual(raised.exception.code, "temporary_service_launch_failed")
        self.assertEqual(
            raised.exception.diagnostic,
            "native systemd-run rejection",
        )

    def test_exact_port_collision_never_launches_or_hops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = _Runner()
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: True,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(_request(Path(directory)))

        self.assertEqual(raised.exception.code, "port_in_use")
        self.assertIn("no fallback port", str(raised.exception))
        self.assertFalse(any(call[0] == "/usr/bin/systemd-run" for call in runner.calls))

    def test_listener_race_stops_unit_when_owner_is_not_the_launched_cgroup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = _Runner()
            probes = iter((False, True))
            request = _request(Path(directory))
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: next(probes),
                listener_ownership_probe=lambda _port, _state: False,
                monotonic=iter((0.0, 0.1)).__next__,
                sleep=lambda _seconds: None,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(request)

        self.assertEqual(raised.exception.code, "port_ownership_mismatch")
        self.assertIn(
            ("/usr/bin/systemctl", "stop", request.unit_name),
            runner.calls,
        )

    def test_execution_uid_mismatch_stops_the_launched_unit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = _Runner()
            probes = iter((False, True))
            request = _request(Path(directory))
            uid_probes: list[tuple[int, int]] = []

            def reject_uid(pid: int, uid: int) -> bool:
                uid_probes.append((pid, uid))
                return False

            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: next(probes),
                listener_ownership_probe=lambda _port, _state: True,
                process_uid_probe=reject_uid,
                monotonic=iter((0.0, 0.1)).__next__,
                sleep=lambda _seconds: None,
            )
            with self.assertRaises(TemporaryDevServiceError) as raised:
                manager.start(request)

        self.assertEqual(
            raised.exception.code,
            "temporary_service_execution_identity_mismatch",
        )
        self.assertEqual(uid_probes, [(123, request.execution_uid)])
        self.assertIn(
            ("/usr/bin/systemctl", "stop", request.unit_name),
            runner.calls,
        )
        self.assertFalse(runner.active)

    def test_exact_operation_replay_reuses_only_owned_ready_unit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = _Runner(active_initially=True)
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: True,
                listener_ownership_probe=lambda _port, _state: True,
                process_uid_probe=lambda pid, uid: (
                    pid == 123 and uid == os.getuid()
                ),
                wall_time=lambda: datetime(2026, 8, 4, tzinfo=timezone.utc),
            )
            operation_id = str(uuid.uuid4())
            result = manager.start(_request(Path(directory), operation_id=operation_id))

        self.assertTrue(result["reused"])
        self.assertEqual(result["operation_id"], operation_id)
        self.assertFalse(any(call[0] == "/usr/bin/systemd-run" for call in runner.calls))

    def test_replay_joins_activating_unit_without_stopping_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = _Runner(active_initially=True, active_state="activating")
            probes = iter((False, True))
            manager = TemporaryDevServiceManager(
                runner=runner,
                port_probe=lambda _port: next(probes),
                listener_ownership_probe=lambda _port, _state: True,
                process_uid_probe=lambda pid, uid: (
                    pid == 123 and uid == os.getuid()
                ),
                monotonic=iter((0.0, 0.1, 0.2)).__next__,
                sleep=lambda _seconds: None,
                wall_time=lambda: datetime(2026, 8, 4, tzinfo=timezone.utc),
            )

            result = manager.start(_request(Path(directory)))

        self.assertTrue(result["reused"])
        self.assertFalse(
            any(call[:2] == ("/usr/bin/systemctl", "stop") for call in runner.calls)
        )

    def test_catalog_identity_is_stable_while_session_and_unit_are_per_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _request(root, operation_id=str(uuid.uuid4()))
            second = _request(root, operation_id=str(uuid.uuid4()))

        self.assertEqual(first.service_id, second.service_id)
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertNotEqual(first.unit_name, second.unit_name)

    def test_definition_rejects_shell_and_repository_escape_before_launch(self) -> None:
        with self.assertRaises(TemporaryDevServiceError) as shell:
            validate_temporary_dev_service_definition(
                name="prototype",
                argv=("bash", "-lc", "npm run dev"),
                cwd=".",
                port=4173,
                ttl_seconds=60,
                kill_after_run=False,
                launch_timeout_seconds=30,
            )
        self.assertEqual(shell.exception.code, "shell_forbidden")

        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "escape").symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaises(TemporaryDevServiceError) as escaped:
                _request(root, cwd="escape").resolved_cwd()
        self.assertEqual(escaped.exception.code, "cwd_escape")


def _runtime_arguments(**changes: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "action": "temporary_start",
        "agent": "codex:test",
        "root_repo_id": "repo-alpha",
        "temporary_repo_id": None,
        "target_kind": "service",
        "purpose": "temporary",
        "ttl_seconds": 3600,
        "kill_after_run": False,
        "name": "prototype",
        "argv": ["npm", "run", "dev", "--", "--strictPort"],
        "cwd": ".",
        "port": 4173,
        "launch_timeout_seconds": 30,
    }
    arguments.update(changes)
    return arguments


class TemporaryDevServiceWireTests(unittest.TestCase):
    def _wire(self, arguments: dict[str, object]) -> BrokerRequest:
        return BrokerRequest.create(
            account_id="account-current",
            project_id="repo-alpha",
            repository_generation=0,
            resource_id="repo-alpha",
            operation=BrokerOperation.RUNTIME_REQUEST,
            arguments=arguments,
            authority_generation="unbound-static-test",
        )

    def test_wire_accepts_exact_temporary_service_contract(self) -> None:
        request = self._wire(_runtime_arguments())
        self.assertEqual(request.arguments["port"], 4173)
        self.assertEqual(request.arguments["argv"][0], "npm")
        self.assertEqual(request.arguments["cwd"], ".")

    def test_temporary_service_stop_uses_transient_manager_not_worker_id(self) -> None:
        operation_id = str(uuid.uuid4())
        service_id = temporary_dev_service_id("repo-alpha", "prototype")
        request = BrokerRequest.create(
            account_id="account-current",
            project_id="repo-alpha",
            repository_generation=0,
            resource_id=service_id,
            operation=BrokerOperation.RUNTIME_REQUEST,
            operation_id=operation_id,
            arguments={
                "action": "stop",
                "agent": "codex:test",
                "root_repo_id": "repo-alpha",
                "temporary_repo_id": None,
                "target_kind": "service",
                "purpose": "development",
                "ttl_seconds": None,
                "kill_after_run": False,
                "keep_alive": None,
                "rearm_crash_loop": False,
                "restart_limit": None,
                "restart_window_seconds": None,
            },
            authority_generation="unbound-static-test",
        )
        authorized = AcceptedBrokerRequest(
            peer=PeerCredentials(uid=os.getuid(), gid=os.getgid(), pid=os.getpid()),
            request=request,
        )

        class Persistence:
            completed = None

            def existing_operation_disposition(self, _authorized):
                return None

            def reserve_operation(self, _authorized):
                return DurableOperationDisposition("execute")

            def finish_operation(self, _operation_id, *, result):
                self.completed = result

        manager = mock.Mock()
        manager.stop.return_value = {
            "state": "stopped",
            "ready": False,
            "main_pid": 0,
        }
        persistence = Persistence()
        backend = object.__new__(StoreBackedMutationBackend)
        backend._persistence = persistence
        backend._temporary_dev_services = manager
        temporary = {
            "unit": "devcoordinator-dev-" + "1" * 32 + ".service",
            "port": 4173,
            "execution_uid": os.getuid(),
            "expired": False,
        }
        with (
            mock.patch(
                "devcoordinator.broker_backend.load_broker_runtime_snapshot",
                return_value=object(),
            ),
            mock.patch(
                "devcoordinator.broker_backend.build_broker_runtime_snapshot_report",
                side_effect=lambda _authorized, snapshot, action_result: dict(action_result),
            ),
        ):
            result = backend._execute_temporary_service_runtime_request(
                authorized, temporary=temporary
            )

        self.assertEqual(result["state"], "stopped")
        self.assertTrue(result["ok"])
        self.assertIs(persistence.completed, result)
        manager.stop.assert_called_once_with(
            unit=temporary["unit"], port=4173
        )

    def test_durable_operation_target_uses_stable_catalog_service_identity(self) -> None:
        from devcoordinator.store import CoordinatorStore
        from devcoordinator.tests.test_broker import (
            PROJECT_ID,
            peer_for,
            request_for,
            seed_store_backed_broker,
        )

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory).resolve()
            persistence, _actions = seed_store_backed_broker(root)
            request = request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=PROJECT_ID,
                arguments=_runtime_arguments(),
                operation_id=str(uuid.uuid4()),
            )
            authorized = persistence.accept(peer_for(), request)
            disposition = persistence.reserve_operation(authorized)
            self.assertEqual(disposition.state, "execute")
            expires_at, _remaining = persistence.temporary_service_launch_deadline(
                authorized
            )
            service_id = temporary_dev_service_id(PROJECT_ID, "prototype")
            session_id = "session-" + uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator:dev-session:" + request.operation_id,
            ).hex
            result = {
                "schema_version": 1,
                "ok": True,
                "operation_id": request.operation_id,
                "session_id": session_id,
                "service_id": service_id,
                "repository_id": PROJECT_ID,
                "repository_generation": 0,
                "execution_uid": authorized.peer.uid,
                "agent": "codex:test",
                "name": "prototype",
                "unit": "devcoordinator-dev-"
                + request.operation_id.replace("-", "")
                + ".service",
                "main_pid": 123,
                "port": 4173,
                "url": "http://127.0.0.1:4173",
                "expires_at": expires_at,
                "state": "running",
                "cleanup": {
                    "owner": "systemd",
                    "kill_mode": "control-group",
                    "ttl_seconds": 3600,
                    "kill_after_run": False,
                },
                "isolation": {
                    "manager": "systemd",
                    "slice": "devcoordinator-projects-test.slice",
                    "control_group": "/devcoordinator/test.service",
                    "listener_owner_proven": True,
                    "execution_uid": authorized.peer.uid,
                    "actual_caller_uid_proven": True,
                },
            }
            first = persistence.finish_temporary_dev_service(
                authorized, result=result
            )
            replay = persistence.finish_temporary_dev_service(
                authorized, result=result
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.read_transaction() as connection:
                    target = connection.execute(
                        """
                        SELECT target_kind, target_id, action
                        FROM operation_targets WHERE operation_id = ?
                        """,
                        (request.operation_id,),
                    ).fetchone()
                    session_count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM runtime_sessions WHERE operation_id = ?",
                            (request.operation_id,),
                        ).fetchone()[0]
                    )

        self.assertIsNotNone(target)
        self.assertEqual(first, replay)
        self.assertEqual(session_count, 1)
        self.assertEqual(str(target["target_kind"]), "service")
        self.assertEqual(
            str(target["target_id"]),
            service_id,
        )
        self.assertEqual(str(target["action"]), "runtime.temporary_start")


    def test_wire_rejects_shell_absolute_cwd_missing_ttl_and_invalid_port(self) -> None:
        invalid = (
            _runtime_arguments(argv=["sh", "-c", "npm run dev"]),
            _runtime_arguments(cwd="/tmp"),
            _runtime_arguments(ttl_seconds=None),
            _runtime_arguments(port=70000),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(BrokerError):
                    self._wire(arguments)

    def test_backend_persists_and_returns_only_sanitized_launch_diagnostic(self) -> None:
        class Persistence:
            def __init__(self, root: str) -> None:
                self.root = root
                self.finished: list[dict[str, object]] = []

            def existing_operation_disposition(self, _authorized: object) -> None:
                return None

            def reserve_operation(self, _authorized: object) -> DurableOperationDisposition:
                return DurableOperationDisposition("execute")

            def temporary_service_execution_context(
                self, _authorized: object
            ) -> object:
                return SimpleNamespace(
                    canonical_root=self.root,
                    execution_uid=os.getuid(),
                    generation=0,
                )

            def temporary_service_launch_deadline(
                self, _authorized: object
            ) -> tuple[str, int]:
                return "2026-08-04T01:00:00Z", 3600

            def temporary_service_predecessor(self, _authorized: object) -> None:
                return None

            def finish_operation(self, operation_id: str, **fields: object) -> None:
                self.finished.append({"operation_id": operation_id, **fields})

        class FailingManager:
            def start(self, _request: object) -> dict[str, object]:
                raise TemporaryDevServiceError(
                    "temporary_service_launch_failed",
                    "systemd rejected the bounded temporary service",
                    diagnostic="token=secret-value /home/developer/project/log.txt",
                )

        with tempfile.TemporaryDirectory() as directory:
            persistence = Persistence(directory)
            backend = object.__new__(StoreBackedMutationBackend)
            backend._persistence = persistence
            backend._temporary_dev_services = FailingManager()
            request = self._wire(_runtime_arguments())
            authorized = AcceptedBrokerRequest(
                peer=PeerCredentials(uid=os.getuid(), gid=os.getgid(), pid=os.getpid()),
                request=request,
            )
            with self.assertRaises(BrokerBackendError) as raised:
                backend._execute_temporary_dev_service(authorized)

        self.assertEqual(raised.exception.code, "temporary_service_launch_failed")
        self.assertIn("token=[REDACTED]", str(raised.exception))
        self.assertIn("[PATH]", str(raised.exception))
        self.assertNotIn("secret-value", str(raised.exception))
        self.assertEqual(
            persistence.finished[-1]["error_message"], str(raised.exception)
        )

    def test_pending_or_reconcile_replay_converges_through_deterministic_manager(self) -> None:
        for retained_state in ("pending", "reconcile"):
            with self.subTest(retained_state=retained_state), tempfile.TemporaryDirectory() as directory:
                class Persistence:
                    def existing_operation_disposition(self, _authorized: object) -> DurableOperationDisposition:
                        return DurableOperationDisposition(retained_state)

                    def temporary_service_launch_deadline(self, _authorized: object) -> tuple[str, int]:
                        return "2026-08-04T01:00:00Z", 120

                    def temporary_service_predecessor(self, _authorized: object) -> None:
                        return None

                    def temporary_service_execution_context(self, _authorized: object) -> object:
                        return SimpleNamespace(
                            canonical_root=directory,
                            execution_uid=os.getuid(),
                            generation=0,
                        )

                    def finish_temporary_dev_service(self, _authorized: object, *, result: dict[str, object]) -> dict[str, object]:
                        return result

                class Manager:
                    request: TemporaryDevServiceRequest | None = None

                    def start(self, request: TemporaryDevServiceRequest) -> dict[str, object]:
                        self.request = request
                        return {
                            "ok": True,
                            "operation_id": request.operation_id,
                            "session_id": request.session_id,
                            "service_id": request.service_id,
                            "repository_id": request.repository_id,
                            "repository_generation": request.repository_generation,
                            "execution_uid": request.execution_uid,
                            "agent": request.agent,
                            "name": request.name,
                            "unit": request.unit_name,
                            "main_pid": 123,
                            "port": request.port,
                            "url": f"http://127.0.0.1:{request.port}",
                            "state": "running",
                            "cleanup": {
                                "owner": "systemd",
                                "kill_mode": "control-group",
                                "ttl_seconds": request.ttl_seconds,
                                "kill_after_run": request.kill_after_run,
                            },
                            "isolation": {
                                "manager": "systemd",
                                "slice": "devcoordinator-projects-test.slice",
                                "control_group": "/devcoordinator/test.service",
                                "listener_owner_proven": True,
                                "execution_uid": request.execution_uid,
                                "actual_caller_uid_proven": True,
                            },
                        }

                persistence = Persistence()
                manager = Manager()
                backend = object.__new__(StoreBackedMutationBackend)
                backend._persistence = persistence
                backend._temporary_dev_services = manager
                request = self._wire(_runtime_arguments())
                authorized = AcceptedBrokerRequest(
                    peer=PeerCredentials(uid=os.getuid(), gid=os.getgid(), pid=os.getpid()),
                    request=request,
                )

                result = backend._execute_temporary_dev_service(authorized)

                self.assertEqual(result["operation_id"], request.operation_id)
                self.assertIsNotNone(manager.request)
                self.assertEqual(manager.request.ttl_seconds, 120)
                self.assertEqual(manager.request.execution_uid, os.getuid())
                self.assertEqual(result["execution_uid"], os.getuid())
                self.assertTrue(
                    result["isolation"]["actual_caller_uid_proven"]
                )

    def test_crashed_same_name_predecessor_does_not_block_fresh_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            class Persistence:
                def existing_operation_disposition(self, _authorized: object) -> None:
                    return None

                def reserve_operation(self, _authorized: object) -> DurableOperationDisposition:
                    return DurableOperationDisposition("execute")

                def temporary_service_launch_deadline(self, _authorized: object) -> tuple[str, int]:
                    return "2026-08-04T01:00:00Z", 120

                def temporary_service_predecessor(self, _authorized: object) -> dict[str, object]:
                    return {
                        "unit": "devcoordinator-dev-" + "1" * 32 + ".service",
                        "port": 4173,
                    }

                def temporary_service_execution_context(self, _authorized: object) -> object:
                    return SimpleNamespace(
                        canonical_root=directory,
                        execution_uid=os.getuid(),
                        generation=0,
                    )

                def finish_temporary_dev_service(self, _authorized: object, *, result: dict[str, object]) -> dict[str, object]:
                    return result

            class Manager:
                started = False

                def status(self, *, unit: str, port: int) -> dict[str, object]:
                    return {"state": "stopped", "ready": False, "main_pid": 0}

                def start(self, request: TemporaryDevServiceRequest) -> dict[str, object]:
                    self.started = True
                    return {
                        "ok": True,
                        "operation_id": request.operation_id,
                        "session_id": request.session_id,
                        "service_id": request.service_id,
                        "repository_id": request.repository_id,
                        "repository_generation": request.repository_generation,
                        "execution_uid": request.execution_uid,
                        "agent": request.agent,
                        "name": request.name,
                        "unit": request.unit_name,
                        "main_pid": 456,
                        "port": request.port,
                        "url": f"http://127.0.0.1:{request.port}",
                        "state": "running",
                        "cleanup": {
                            "owner": "systemd",
                            "kill_mode": "control-group",
                            "ttl_seconds": request.ttl_seconds,
                            "kill_after_run": request.kill_after_run,
                        },
                        "isolation": {
                            "manager": "systemd",
                            "slice": "devcoordinator-projects-test.slice",
                            "control_group": "/devcoordinator/test.service",
                            "listener_owner_proven": True,
                            "execution_uid": request.execution_uid,
                            "actual_caller_uid_proven": True,
                        },
                    }

            manager = Manager()
            backend = object.__new__(StoreBackedMutationBackend)
            backend._persistence = Persistence()
            backend._temporary_dev_services = manager
            request = self._wire(_runtime_arguments())
            authorized = AcceptedBrokerRequest(
                peer=PeerCredentials(uid=os.getuid(), gid=os.getgid(), pid=os.getpid()),
                request=request,
            )

            result = backend._execute_temporary_dev_service(authorized)

        self.assertTrue(manager.started)
        self.assertEqual(result["state"], "running")


class _Profile:
    def __init__(self, root: str) -> None:
        self.root = root
        self.configured: dict[str, SimpleNamespace] = {}
        self.ensure_mutations: list[tuple[str, str]] = []
        self.ensure_arguments: list[dict[str, object]] = []
        self.runtime_calls: list[dict[str, object]] = []

    def repository_if_configured(self, root: str) -> object | None:
        return self.configured.get(root)

    def ensure_repository_with_outcome(
        self, **arguments: object
    ) -> tuple[object, bool]:
        self.ensure_arguments.append(dict(arguments))
        root = str(arguments["canonical_root"])
        existing = self.configured.get(root)
        if existing is not None:
            return existing, False
        repository = SimpleNamespace(repo_id="repo-adopted", generation=7)
        self.configured[root] = repository
        self.ensure_mutations.append((root, str(arguments["operation_id"])))
        return repository, True

    def repository(self, root: str) -> object:
        return self.configured[root]

    def resolve_repository(self, root: str) -> object | None:
        return self.configured.get(root)

    def call(self, **arguments: object) -> tuple[str, dict[str, object]]:
        self.runtime_calls.append(dict(arguments))
        operation_id = str(arguments["operation_id"])
        return operation_id, {
            "ok": True,
            "operation_id": operation_id,
            "service_id": "service-fixed",
            "session_id": "session-fixed",
            "state": "running",
            "port": 4173,
        }


class TemporaryDevServiceAgentCliTests(unittest.TestCase):
    def test_launch_failures_return_code_specific_recovery_guidance(self) -> None:
        cases = {
            "temporary_service_launch_failed": "missing executable",
            "temporary_service_exited": "exited before it opened",
            "temporary_service_readiness_timeout": "--launch-timeout-seconds",
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                action = agent_cli._next_action_for_failure(
                    code=code,
                    broker_contacted=True,
                    continuation=None,
                    outcome="failed",
                    phase="launch",
                )
                self.assertIn(expected, action)

    def test_pre_reply_timeout_and_incomplete_request_leave_contact_unknown(self) -> None:
        for code in ("request_timeout", "incomplete_request"):
            with self.subTest(code=code):
                self.assertIsNone(
                    agent_cli._broker_contact_from_error(
                        BrokerError(code, "pre-reply failure")
                    )
                )
        self.assertTrue(
            agent_cli._broker_contact_from_error(
                BrokerError("port_in_use", "typed authority rejection")
            )
        )

    def test_port_collision_reports_exact_contact_and_adoption_mutation(self) -> None:
        operation_id = str(uuid.uuid4())
        error = BrokerError(
            "port_in_use",
            "the exact requested port is already in use",
            operation_id=operation_id,
        )
        existing = agent_cli._failure(
            error,
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=True,
            observed_mutation=False,
        )
        adopted = agent_cli._failure(
            error,
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=True,
            observed_mutation=True,
        )

        self.assertTrue(existing["broker_contacted"])
        self.assertFalse(existing["mutation_performed"])
        self.assertTrue(adopted["mutation_performed"])
        self.assertFalse(existing["retryable"])
        self.assertIn("did not choose another", existing["next_action"])

    def test_ambiguous_transport_reports_unknown_contact_and_mutation(self) -> None:
        operation_id = str(uuid.uuid4())
        document = agent_cli._failure(
            TimeoutError("timed out"),
            mutation_attempted=True,
            operation_id_hint=operation_id,
            broker_contacted=None,
            observed_mutation=False,
        )
        self.assertIsNone(document["broker_contacted"])
        self.assertIsNone(document["mutation_performed"])
        self.assertEqual(document["outcome"], "uncertain")
        self.assertIn("Follow this exact operation", document["next_action"])

    def test_one_command_adopts_then_replays_one_exact_runtime_operation(self) -> None:
        root = "/tmp/zero-commit-repository"
        scope = SimpleNamespace(canonical_root=root, root_owner_uid=os.getuid())
        context = SimpleNamespace(root=scope, effective=scope, temporary=None)
        profile = _Profile(root)
        operation_id = str(uuid.uuid4())
        namespace = SimpleNamespace(
            action="serve",
            kind=None,
            desired=None,
            keep_alive=None,
            rearm_crash_loop=False,
            purpose="temporary",
            ttl_seconds=3600,
            cwd=".",
            port=4173,
            launch_timeout_seconds=30,
            kill_after_run="false",
            argv=["npm", "run", "dev", "--", "--strictPort"],
            operation_id=operation_id,
            selector="prototype",
        )
        state: dict[str, bool | None] = {
            "broker_contacted": True,
            "mutation_performed": False,
        }

        with mock.patch.object(agent_cli, "_attribution", return_value="codex:test"):
            first = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=context,
                execution_state=state,
            )
            second = agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=context,
                execution_state=state,
            )

        self.assertEqual(len(profile.ensure_mutations), 1)
        self.assertEqual(
            profile.ensure_arguments[0]["transport_timeout_seconds"],
            60.0,
        )
        ensure_operation = profile.ensure_mutations[0][1]
        self.assertNotEqual(ensure_operation, operation_id)
        self.assertEqual(len(profile.runtime_calls), 2)
        self.assertTrue(all(call["operation_id"] == operation_id for call in profile.runtime_calls))
        self.assertEqual(first["operation_id"], operation_id)
        self.assertEqual(second["operation_id"], operation_id)
        self.assertTrue(first["broker_contacted"])
        self.assertTrue(first["mutation_performed"])

    def test_expired_exact_service_id_refreshes_retained_repository_identity(self) -> None:
        root = "/tmp/retained-temporary-service"
        initial = SimpleNamespace(
            server_ids={}, container_ids={}, compose_container_ids=frozenset()
        )
        retained = SimpleNamespace(
            server_ids={"prototype": "service-retained"},
            container_ids={},
            compose_container_ids=frozenset(),
        )
        profile = mock.Mock()
        profile.resolve_repository.return_value = initial
        profile.refresh_repository.return_value = retained
        scope = SimpleNamespace(canonical_root=root)

        with mock.patch.object(
            agent_cli,
            "_target_projection",
            side_effect=AssertionError("expired exact status must not depend on active inventory"),
        ):
            selected = agent_cli._runtime_target(
                profile=profile,
                context=SimpleNamespace(effective=scope),
                selector="service-retained",
                kind="service",
            )

        self.assertEqual(selected, {"kind": "service", "id": "service-retained"})
        profile.refresh_repository.assert_called_once_with(root)

    def test_broker_resolved_existing_repository_is_not_reported_as_adoption(self) -> None:
        root = "/tmp/resolved-existing-repository"
        scope = SimpleNamespace(canonical_root=root, root_owner_uid=os.getuid())

        class BrokerResolvedProfile(_Profile):
            def repository_if_configured(self, _root: str) -> object | None:
                return None

            def ensure_repository_with_outcome(
                self, **arguments: object
            ) -> tuple[object, bool]:
                canonical_root = str(arguments["canonical_root"])
                repository = SimpleNamespace(repo_id="repo-existing", generation=4)
                self.configured[canonical_root] = repository
                return repository, False

            def call(self, **arguments: object) -> tuple[str, dict[str, object]]:
                raise BrokerError(
                    "port_in_use",
                    "the exact requested port is already in use",
                    operation_id=str(arguments["operation_id"]),
                )

        profile = BrokerResolvedProfile(root)
        state: dict[str, bool | None] = {
            "broker_contacted": True,
            "mutation_performed": False,
        }
        namespace = SimpleNamespace(
            action="serve",
            kind=None,
            desired=None,
            keep_alive=None,
            rearm_crash_loop=False,
            purpose="temporary",
            ttl_seconds=3600,
            cwd=".",
            port=4173,
            launch_timeout_seconds=30,
            kill_after_run="false",
            argv=["npm", "run", "dev", "--", "--strictPort"],
            operation_id=str(uuid.uuid4()),
            selector="prototype",
        )
        with (
            mock.patch.object(agent_cli, "_attribution", return_value="codex:test"),
            self.assertRaises(BrokerError) as raised,
        ):
            agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=SimpleNamespace(root=scope, effective=scope, temporary=None),
                execution_state=state,
            )

        self.assertEqual(raised.exception.code, "port_in_use")
        self.assertTrue(state["broker_contacted"])
        self.assertFalse(state["mutation_performed"])

    def test_invalid_shell_is_rejected_before_repository_adoption(self) -> None:
        root = "/tmp/zero-commit-repository"
        scope = SimpleNamespace(canonical_root=root, root_owner_uid=os.getuid())
        profile = _Profile(root)
        namespace = SimpleNamespace(
            action="serve",
            kind=None,
            desired=None,
            keep_alive=None,
            rearm_crash_loop=False,
            purpose="temporary",
            ttl_seconds=60,
            cwd=".",
            port=4173,
            launch_timeout_seconds=30,
            kill_after_run="false",
            argv=["bash", "-lc", "npm run dev"],
            operation_id=str(uuid.uuid4()),
            selector="prototype",
        )
        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=SimpleNamespace(root=scope, effective=scope, temporary=None),
                execution_state={
                    "broker_contacted": True,
                    "mutation_performed": False,
                },
            )
        self.assertEqual(raised.exception.code, "shell_forbidden")
        self.assertEqual(profile.ensure_mutations, [])

    def test_explicit_zero_launch_timeout_is_not_replaced_by_default(self) -> None:
        root = "/tmp/zero-timeout-repository"
        scope = SimpleNamespace(canonical_root=root, root_owner_uid=os.getuid())
        profile = _Profile(root)
        namespace = SimpleNamespace(
            action="serve",
            kind=None,
            desired=None,
            keep_alive=None,
            rearm_crash_loop=False,
            purpose="temporary",
            ttl_seconds=60,
            cwd=".",
            port=4173,
            launch_timeout_seconds=0,
            kill_after_run="false",
            argv=["npm", "run", "dev"],
            operation_id=str(uuid.uuid4()),
            selector="prototype",
        )
        with self.assertRaises(agent_cli.AgentCliError) as raised:
            agent_cli._runtime(
                namespace,
                profile=profile,
                capabilities={"runtime": {"actions": ["serve"]}},
                context=SimpleNamespace(root=scope, effective=scope, temporary=None),
                execution_state={
                    "broker_contacted": True,
                    "mutation_performed": False,
                },
            )
        self.assertEqual(raised.exception.code, "launch_timeout_invalid")
        self.assertEqual(profile.ensure_mutations, [])


if __name__ == "__main__":
    unittest.main()
