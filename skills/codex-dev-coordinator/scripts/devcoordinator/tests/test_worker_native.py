from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

from devcoordinator import worker_native
from devcoordinator.worker_native import (
    LaunchdWorkerManager,
    SystemdWorkerManager,
    WorkerNativeError,
    project_repository_slice,
)


class FakeRunner:
    def __init__(self, outputs: list[tuple[int, str, str]] | None = None) -> None:
        self.outputs = list(outputs or [])
        self.calls: list[list[str]] = []
        self.kwargs: list[dict[str, object]] = []

    def __call__(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        self.kwargs.append(dict(kwargs))
        code, stdout, stderr = self.outputs.pop(0) if self.outputs else (0, "", "")
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


@contextmanager
def local_identity(
    uid: int = 501, gid: int = 20, *, primary_gid: int | None = None
):
    user = SimpleNamespace(
        pw_uid=uid,
        pw_gid=gid if primary_gid is None else primary_gid,
        pw_name="worker-user",
    )
    group = SimpleNamespace(gr_gid=gid, gr_name="worker-group")
    with (
        mock.patch("devcoordinator.worker_native.pwd.getpwuid", return_value=user),
        mock.patch("devcoordinator.worker_native.grp.getgrgid", return_value=group),
    ):
        yield


class WorkerNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.script = self._program("dev_coordinator.py")
        self.python = self._program("python3")
        self.systemd_run = self._program("systemd-run")
        self.systemctl = self._program("systemctl")
        self.launchctl = self._program("launchctl")
        self.worker_id = str(uuid.uuid4())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _program(self, name: str) -> Path:
        path = self.root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def _systemd(self, runner: FakeRunner) -> SystemdWorkerManager:
        return SystemdWorkerManager(
            coordinator_script=self.script,
            python_executable=str(self.python),
            systemd_run_executable=str(self.systemd_run),
            systemctl_executable=str(self.systemctl),
            runner=runner,
        )

    def _launchd(
        self, runner: FakeRunner, *, system_domain: bool = False
    ) -> LaunchdWorkerManager:
        return LaunchdWorkerManager(
            coordinator_script=self.script,
            state_root=self.root / "launchd",
            python_executable=str(self.python),
            launchctl_executable=str(self.launchctl),
            runner=runner,
            system_domain=system_domain,
        )

    def test_project_slice_is_deterministic_and_separates_uid_and_repository(self) -> None:
        first = project_repository_slice(uid=501, repository_id="repo-one")
        self.assertEqual(
            first,
            project_repository_slice(uid=501, repository_id="repo-one"),
        )
        self.assertNotEqual(
            first,
            project_repository_slice(uid=501, repository_id="repo-two"),
        )
        self.assertNotEqual(
            first,
            project_repository_slice(uid=502, repository_id="repo-one"),
        )
        self.assertTrue(first.startswith("devcoordinator-projects-uid501-repo"))
        self.assertTrue(first.endswith(".slice"))

    def test_systemd_uses_only_fixed_runner_contract_and_verified_identity(self) -> None:
        runner = FakeRunner(
            [
                (0, "", ""),
                (
                    0,
                    "LoadState=loaded\nActiveState=active\nSubState=running\n"
                    "MainPID=4312\nExecMainStatus=0\n",
                    "",
                ),
                (
                    0,
                    "LoadState=loaded\n"
                    f"Slice={project_repository_slice(uid=501, repository_id='repo-one')}\n",
                    "",
                ),
            ]
        )
        manager = self._systemd(runner)
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=0), local_identity():
            state = manager.start(
                worker_id=self.worker_id,
                uid=501,
                gid=20,
                repository_id="repo-one",
            )

        self.assertEqual(
            runner.calls[0],
            [
                str(self.systemd_run.resolve()),
                "--quiet",
                "--collect",
                f"--unit=devcoordinator-worker-{self.worker_id}.service",
                "--uid=501",
                "--gid=20",
                f"--slice={project_repository_slice(uid=501, repository_id='repo-one')}",
                "--service-type=exec",
                "--property=Restart=on-failure",
                "--property=RestartSec=2s",
                "--property=KillMode=mixed",
                "--property=NoNewPrivileges=yes",
                "--property=PrivateTmp=yes",
                "--property=ProtectControlGroups=yes",
                "--property=CPUWeight=100",
                "--property=IOWeight=100",
                "--property=MemoryHigh=16G",
                "--property=MemoryMax=20G",
                "--property=TasksMax=4096",
                "--property=OOMPolicy=stop",
                "--property=UMask=0077",
                "--property=TimeoutStopSec=30s",
                "--property=StandardOutput=journal",
                "--property=StandardError=journal",
                str(self.python.resolve()),
                "-I",
                "-B",
                str(self.script.resolve()),
                "worker",
                "runner",
                "--worker-id",
                self.worker_id,
            ],
        )
        self.assertEqual(runner.calls[1][0], str(self.systemctl.resolve()))
        self.assertEqual(
            runner.calls[2],
            [
                str(self.systemctl.resolve()),
                "show",
                f"devcoordinator-worker-{self.worker_id}.service",
                "--property=LoadState",
                "--property=Slice",
                "--no-pager",
            ],
        )
        self.assertNotIn("shell", runner.kwargs[0])
        self.assertEqual(runner.kwargs[0]["stdin"], subprocess.DEVNULL)
        self.assertEqual(
            runner.kwargs[0]["env"],
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
        self.assertTrue(state.active)
        self.assertEqual(state.pid, 4312)

    def test_systemd_rejects_non_root_manager_and_root_worker(self) -> None:
        manager = self._systemd(FakeRunner())
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=501):
            with self.assertRaisesRegex(WorkerNativeError, "root authority"):
                manager.start(
                    worker_id=self.worker_id,
                    uid=501,
                    gid=20,
                    repository_id="repo-one",
                )
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "non-root"):
                manager.start(
                    worker_id=self.worker_id,
                    uid=0,
                    gid=0,
                    repository_id="repo-one",
                )

    def test_systemd_rejects_loaded_worker_outside_repository_slice(self) -> None:
        runner = FakeRunner(
            [(0, "LoadState=loaded\nSlice=system.slice\n", "")]
        )
        manager = self._systemd(runner)
        with self.assertRaisesRegex(WorkerNativeError, "not isolated"):
            manager.require_project_isolation(
                worker_id=self.worker_id,
                uid=501,
                repository_id="repo-one",
            )

    def test_systemd_rejects_client_shaped_worker_id_and_unsafe_programs(self) -> None:
        manager = self._systemd(FakeRunner())
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=0), local_identity():
            with self.assertRaises(ValueError):
                manager.start(
                    worker_id="../../client-command",
                    uid=501,
                    gid=20,
                    repository_id="repo-one",
                )

        self.script.chmod(0o722)
        self._systemd(FakeRunner())
        self.script.chmod(0o700)
        self.python.chmod(0o600)
        with self.assertRaisesRegex(WorkerNativeError, "must be executable"):
            self._systemd(FakeRunner())

    def test_systemd_resolves_fixed_python_symlink_before_trusting_target(self) -> None:
        python_link = self.root / "python-link"
        python_link.symlink_to(self.python)

        manager = SystemdWorkerManager(
            coordinator_script=self.script,
            python_executable=str(python_link),
            systemd_run_executable=str(self.systemd_run),
            systemctl_executable=str(self.systemctl),
            runner=FakeRunner(),
        )
        self.assertEqual(manager.python_executable, str(self.python.resolve()))

        self.python.chmod(0o722)
        manager = SystemdWorkerManager(
            coordinator_script=self.script,
            python_executable=str(python_link),
            systemd_run_executable=str(self.systemd_run),
            systemctl_executable=str(self.systemctl),
            runner=FakeRunner(),
        )
        self.assertEqual(manager.python_executable, str(self.python.resolve()))

    def test_systemd_missing_is_distinct_from_permission_and_malformed_status(self) -> None:
        missing = self._systemd(
            FakeRunner([(4, "", "Unit x.service could not be found")])
        ).status(worker_id=self.worker_id, allow_missing=True)
        self.assertFalse(missing.loaded)

        denied = self._systemd(FakeRunner([(1, "", "Access denied")]))
        with self.assertRaisesRegex(WorkerNativeError, "Access denied"):
            denied.status(worker_id=self.worker_id, allow_missing=True)

        malformed = self._systemd(FakeRunner([(0, "LoadState=loaded\n", "")]))
        with self.assertRaisesRegex(WorkerNativeError, "incomplete"):
            malformed.status(worker_id=self.worker_id)

    def test_systemd_remove_stops_and_collects_exact_transient_unit(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "LoadState=loaded\nActiveState=active\nSubState=running\n"
                    "MainPID=4312\nExecMainStatus=0\n",
                    "",
                ),
                (0, "", ""),
                (
                    0,
                    "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    "MainPID=0\nExecMainStatus=0\n",
                    "",
                ),
                (0, "", ""),
                (4, "", "Unit could not be found"),
            ]
        )
        manager = self._systemd(runner)
        state = manager.remove(worker_id=self.worker_id)

        unit = f"devcoordinator-worker-{self.worker_id}.service"
        self.assertFalse(state.loaded)
        self.assertEqual(
            runner.calls,
            [
                [
                    str(self.systemctl.resolve()),
                    "show",
                    unit,
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                    "--property=ExecMainStatus",
                    "--no-pager",
                ],
                [str(self.systemctl.resolve()), "stop", unit],
                [
                    str(self.systemctl.resolve()),
                    "show",
                    unit,
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                    "--property=ExecMainStatus",
                    "--no-pager",
                ],
                [str(self.systemctl.resolve()), "reset-failed", unit],
                [
                    str(self.systemctl.resolve()),
                    "show",
                    unit,
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                    "--property=ExecMainStatus",
                    "--no-pager",
                ],
            ],
        )

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_user_job_is_atomic_fixed_and_run_at_load(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        runner = FakeRunner(
            [
                (113, "", "Could not find service in domain"),
                (0, "", ""),
                (0, "state = spawn scheduled\npid = 9001\nlast exit code = 0\n", ""),
            ]
        )
        manager = self._launchd(runner)
        with local_identity(uid, gid):
            state = manager.start(
                worker_id=self.worker_id,
                uid=uid,
                gid=gid,
                repository_id="repo-one",
            )

        target = self.root / "launchd" / f"{manager.label(self.worker_id)}.plist"
        document = plistlib.loads(target.read_bytes())
        self.assertEqual(
            document["ProgramArguments"],
            [
                str(self.python.resolve()),
                "-I",
                "-B",
                str(self.script.resolve()),
                "worker",
                "runner",
                "--worker-id",
                self.worker_id,
            ],
        )
        self.assertNotIn("UserName", document)
        self.assertNotIn("GroupName", document)
        self.assertEqual(document["KeepAlive"], {"SuccessfulExit": False})
        self.assertTrue(document["RunAtLoad"])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(
            [call[1] for call in runner.calls], ["print", "bootstrap", "print"]
        )
        self.assertTrue(state.active)
        self.assertEqual(state.state, "spawn scheduled")

    def test_launchd_system_document_uses_verified_names_and_fixed_argv(self) -> None:
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=0):
            manager = self._launchd(FakeRunner(), system_domain=True)
        identity = worker_native._LocalIdentity(501, 20, "worker-user", "worker-group")
        document = manager._plist_document(
            worker_id=self.worker_id, identity=identity
        )
        self.assertEqual(document["UserName"], "worker-user")
        self.assertEqual(document["GroupName"], "worker-group")
        self.assertEqual(document["ProgramArguments"][-3:], ["runner", "--worker-id", self.worker_id])

    def test_launchd_system_domain_rejects_non_root_authority(self) -> None:
        with mock.patch("devcoordinator.worker_native.os.geteuid", return_value=501):
            with self.assertRaisesRegex(WorkerNativeError, "root authority"):
                self._launchd(FakeRunner(), system_domain=True)

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_replaces_loaded_job_without_ignored_manager_errors(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        runner = FakeRunner(
            [
                (0, "state = running\npid = 77\n", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "state = running\npid = 78\n", ""),
            ]
        )
        manager = self._launchd(runner)
        with local_identity(uid, gid):
            state = manager.start(
                worker_id=self.worker_id,
                uid=uid,
                gid=gid,
                repository_id="repo-one",
            )
        self.assertEqual(
            [call[1] for call in runner.calls],
            ["print", "bootout", "bootstrap", "print"],
        )
        self.assertEqual(state.pid, 78)

        denied = self._launchd(FakeRunner([(1, "", "Operation not permitted")]))
        with self.assertRaisesRegex(WorkerNativeError, "Operation not permitted"):
            denied.status(worker_id=self.worker_id, uid=uid)
        malformed = self._launchd(FakeRunner([(0, "pid = 42\n", "")]))
        with self.assertRaisesRegex(WorkerNativeError, "incomplete"):
            malformed.status(worker_id=self.worker_id, uid=uid)

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_missing_stop_is_idempotent(self) -> None:
        uid = os.geteuid()
        runner = FakeRunner([(113, "", "Could not find service in domain")])
        state = self._launchd(runner).stop(worker_id=self.worker_id, uid=uid)
        self.assertFalse(state.loaded)
        self.assertEqual(len(runner.calls), 1)

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_remove_unloads_and_unlinks_only_exact_private_plist(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        manager = self._launchd(FakeRunner())
        state_root = self.root / "launchd"
        state_root.mkdir(mode=0o700)
        target = state_root / f"{manager.label(self.worker_id)}.plist"
        target.write_bytes(b"safe")
        target.chmod(0o600)
        runner = FakeRunner(
            [
                (0, "state = running\npid = 77\n", ""),
                (0, "", ""),
            ]
        )
        manager = self._launchd(runner)
        with local_identity(uid, gid):
            state = manager.remove(worker_id=self.worker_id, uid=uid)

        self.assertFalse(state.loaded)
        self.assertFalse(target.exists())
        self.assertEqual([call[1] for call in runner.calls], ["print", "bootout"])

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_remove_accepts_readable_plist_metadata(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        manager = self._launchd(FakeRunner([(113, "", "Could not find service")]))
        state_root = self.root / "launchd"
        state_root.mkdir(mode=0o700)
        target = state_root / f"{manager.label(self.worker_id)}.plist"
        target.write_bytes(b"unsafe")
        target.chmod(0o644)

        with local_identity(uid, gid):
            manager.remove(worker_id=self.worker_id, uid=uid)
        self.assertFalse(target.exists())

    @unittest.skipIf(os.geteuid() == 0, "per-user launchd requires a non-root test account")
    def test_launchd_accepts_state_root_metadata_and_preserves_old_plist_on_failure(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        state_root = self.root / "launchd"
        state_root.mkdir(mode=0o755)
        state_root.chmod(0o755)
        manager = self._launchd(FakeRunner())
        with local_identity(uid, gid):
            manager._write_plist(worker_id=self.worker_id, uid=uid, gid=gid)

        state_root.chmod(0o700)
        target = state_root / f"{manager.label(self.worker_id)}.plist"
        target.write_bytes(b"old-safe-plist")
        target.chmod(0o600)
        with local_identity(uid, gid), mock.patch(
            "devcoordinator.worker_native.os.replace", side_effect=OSError("replace failed")
        ):
            with self.assertRaisesRegex(WorkerNativeError, "replace failed"):
                manager._write_plist(worker_id=self.worker_id, uid=uid, gid=gid)
        self.assertEqual(target.read_bytes(), b"old-safe-plist")
        self.assertEqual(list(state_root.glob(".worker-*")), [])


if __name__ == "__main__":
    unittest.main()
