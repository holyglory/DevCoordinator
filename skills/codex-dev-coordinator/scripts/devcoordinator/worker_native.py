"""OS-owned runner isolation for durable managed-worker supervision.

The broker never forks an configured user's arbitrary command.  It asks the
native service manager to execute one fixed Python entrypoint under the
configured UID; that runner obtains a generation-bound launch ticket from the
Coordinator authority and is the parent of the actual worker process.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import grp
import hashlib
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Sequence
import uuid


_UNIT_PREFIX = "devcoordinator-worker-"
_SAFE_STATE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
_MAX_MANAGER_OUTPUT = 1024 * 1024
_PROJECT_CPU_WEIGHT = 100
_PROJECT_IO_WEIGHT = 100
_PROJECT_MEMORY_HIGH = "16G"
_PROJECT_MEMORY_MAX = "20G"
_PROJECT_TASKS_MAX = 4096


class WorkerNativeError(RuntimeError):
    """The native runner boundary could not be proved or changed safely."""


class _NativeCommandError(WorkerNativeError):
    """A fixed native-manager command completed unsuccessfully."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        detail = (stderr or stdout or "").strip()[:2048]
        super().__init__(
            "native worker manager refused the operation: "
            + (detail or f"exit {returncode}")
        )


@dataclass(frozen=True)
class NativeWorkerState:
    worker_id: str
    manager: str
    unit: str
    loaded: bool
    active: bool
    state: str
    pid: int | None
    exit_status: int | None
    control_group: str | None = None
    cgroup_populated: bool | None = None
    termination_method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "manager": self.manager,
            "unit": self.unit,
            "loaded": self.loaded,
            "active": self.active,
            "state": self.state,
            "pid": self.pid,
            "exit_status": self.exit_status,
            "control_group": self.control_group,
            "cgroup_populated": self.cgroup_populated,
            "termination_method": self.termination_method,
        }


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _worker_id(value: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("worker_id must be a canonical UUID") from error
    canonical = str(parsed)
    if canonical != str(value):
        raise ValueError("worker_id must be a canonical UUID")
    return canonical


def project_repository_slice(*, uid: int, repository_id: str) -> str:
    """Return an opaque deterministic slice below devcoordinator-projects."""

    _positive_id(uid, "uid")
    if (
        not isinstance(repository_id, str)
        or not repository_id
        or len(repository_id.encode("utf-8")) > 256
        or "\x00" in repository_id
    ):
        raise ValueError("worker repository ID must be one bounded string")
    repository = hashlib.sha256(repository_id.encode("utf-8")).hexdigest()[:20]
    return f"devcoordinator-projects-uid{uid}-repo{repository}.slice"


@dataclass(frozen=True)
class _LocalIdentity:
    uid: int
    gid: int
    user: str
    group: str


def _positive_id(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"worker {name} must be a positive non-root integer")
    return value


def _identity(uid: int, gid: int) -> _LocalIdentity:
    uid = _positive_id(uid, "uid")
    gid = _positive_id(gid, "gid")
    try:
        user = pwd.getpwuid(uid)
        group = grp.getgrgid(gid)
    except KeyError as error:
        raise WorkerNativeError("worker UID/GID has no local account identity") from error
    if user.pw_uid != uid or group.gr_gid != gid:
        raise WorkerNativeError("worker UID/GID local account identity is invalid")
    return _LocalIdentity(uid=uid, gid=gid, user=user.pw_name, group=group.gr_name)


def _trusted_file(path: Path, *, description: str, executable: bool = False) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise WorkerNativeError(f"{description} must be an absolute path")
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise WorkerNativeError(f"{description} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise WorkerNativeError(f"{description} must be a regular non-symlink file")
    if executable and metadata.st_mode & 0o111 == 0:
        raise WorkerNativeError(f"{description} must be executable")
    return candidate.resolve(strict=True)


def _trusted_script(path: Path) -> Path:
    return _trusted_file(path, description="worker runner script")


def _trusted_executable(path: str | Path, *, description: str) -> str:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise WorkerNativeError(f"{description} must be an absolute path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise WorkerNativeError(f"{description} is unavailable: {error}") from error
    return str(_trusted_file(resolved, description=description, executable=True))


def _run(
    runner: Runner,
    argv: Sequence[str],
    *,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[str]:
    if (
        not argv
        or any(
            type(argument) is not str
            or not argument
            or "\x00" in argument
            or len(argument) > 4096
            for argument in argv
        )
        or sum(len(argument) for argument in argv) > 32768
    ):
        raise WorkerNativeError("native worker manager received an invalid fixed argv")
    try:
        completed = runner(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkerNativeError(f"native worker manager invocation failed: {error}") from error
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        raise WorkerNativeError("native worker manager returned non-text output")
    if len(completed.stdout) + len(completed.stderr) > _MAX_MANAGER_OUTPUT:
        raise WorkerNativeError("native worker manager returned excessive output")
    if completed.returncode != 0:
        raise _NativeCommandError(
            completed.returncode, completed.stdout, completed.stderr
        )
    return completed


def _is_missing(error: _NativeCommandError) -> bool:
    detail = f"{error.stderr}\n{error.stdout}".lower()
    return error.returncode in {3, 4, 113} and any(
        phrase in detail
        for phrase in (
            "could not find service",
            "could not be found",
            "no such service",
            "not loaded",
            "not found",
        )
    )


class SystemdWorkerManager:
    """Create transient runner units without writing client-controlled unit files."""

    def __init__(
        self,
        *,
        coordinator_script: Path,
        python_executable: str = "/usr/bin/python3",
        systemd_run_executable: str = "/usr/bin/systemd-run",
        systemctl_executable: str = "/usr/bin/systemctl",
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        runner: Runner = subprocess.run,
    ) -> None:
        self.coordinator_script = _trusted_script(coordinator_script)
        self.python_executable = _trusted_executable(
            python_executable, description="Python executable"
        )
        self.systemd_run_executable = _trusted_executable(
            systemd_run_executable, description="systemd-run executable"
        )
        self.systemctl_executable = _trusted_executable(
            systemctl_executable, description="systemctl executable"
        )
        self.cgroup_root = cgroup_root
        self.runner = runner

    @staticmethod
    def unit(worker_id: str) -> str:
        return _UNIT_PREFIX + _worker_id(worker_id) + ".service"

    def start(
        self, *, worker_id: str, uid: int, gid: int, repository_id: str
    ) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        if os.geteuid() != 0:
            raise WorkerNativeError(
                "systemd cross-account worker supervision requires root authority"
            )
        identity = _identity(uid, gid)
        unit = self.unit(worker_id)
        repository_slice = project_repository_slice(
            uid=identity.uid, repository_id=repository_id
        )
        argv = [
            self.systemd_run_executable,
            "--quiet",
            "--collect",
            f"--unit={unit}",
            f"--uid={identity.uid}",
            f"--gid={identity.gid}",
            f"--slice={repository_slice}",
            "--service-type=exec",
            "--property=Restart=on-failure",
            "--property=RestartSec=2s",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=ProtectControlGroups=yes",
            f"--property=CPUWeight={_PROJECT_CPU_WEIGHT}",
            f"--property=IOWeight={_PROJECT_IO_WEIGHT}",
            f"--property=MemoryHigh={_PROJECT_MEMORY_HIGH}",
            f"--property=MemoryMax={_PROJECT_MEMORY_MAX}",
            f"--property=TasksMax={_PROJECT_TASKS_MAX}",
            "--property=OOMPolicy=stop",
            "--property=UMask=0077",
            "--property=TimeoutStopSec=30s",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            self.python_executable,
            "-I",
            "-B",
            str(self.coordinator_script),
            "worker",
            "runner",
            "--worker-id",
            worker_id,
        ]
        _run(self.runner, argv)
        state = self.status(worker_id=worker_id)
        if (
            not state.loaded
            or state.control_group is None
            or state.cgroup_populated is not True
        ):
            raise WorkerNativeError(
                "systemd did not prove one populated private worker control group"
            )
        try:
            self.require_project_isolation(
                worker_id=worker_id,
                uid=identity.uid,
                repository_id=repository_id,
            )
        except BaseException:
            # A successfully launched but mis-scoped worker is more dangerous
            # than a failed launch. Remove the exact transient registration
            # before returning the contract failure.
            self.remove(worker_id=worker_id)
            raise
        return state

    def require_project_isolation(
        self, *, worker_id: str, uid: int, repository_id: str
    ) -> str:
        """Prove the loaded unit belongs to its deterministic repository slice."""

        worker_id = _worker_id(worker_id)
        expected = project_repository_slice(uid=uid, repository_id=repository_id)
        unit = self.unit(worker_id)
        completed = _run(
            self.runner,
            [
                self.systemctl_executable,
                "show",
                unit,
                "--property=LoadState",
                "--property=Slice",
                "--no-pager",
            ],
        )
        values: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        if values != {"LoadState": "loaded", "Slice": expected}:
            raise WorkerNativeError(
                "systemd worker is not isolated in its attributed repository slice"
            )
        return expected

    def stop(self, *, worker_id: str) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        unit = self.unit(worker_id)
        current = self.status(worker_id=worker_id, allow_missing=True)
        if not current.loaded:
            return current
        terminated_control_group: str | None = None
        if current.active:
            if current.control_group is None:
                raise WorkerNativeError(
                    "systemd did not expose the worker control group before termination"
                )
            terminated_control_group = current.control_group
        _run(self.runner, [self.systemctl_executable, "stop", unit])
        stopped = self.status(worker_id=worker_id, allow_missing=True)
        if stopped.active:
            _run(
                self.runner,
                [
                    self.systemctl_executable,
                    "kill",
                    "--kill-whom=all",
                    "--signal=KILL",
                    unit,
                ],
            )
            _run(self.runner, [self.systemctl_executable, "stop", unit])
            stopped = self.status(worker_id=worker_id, allow_missing=True)
        if stopped.active:
            raise WorkerNativeError(
                "systemd did not prove the worker runner stopped"
            )
        if terminated_control_group is not None:
            populated = self._control_group_populated(
                terminated_control_group, allow_missing=True
            )
            if populated:
                raise WorkerNativeError(
                    "worker control group remained populated after systemd stop"
                )
            stopped = replace(
                stopped,
                control_group=terminated_control_group,
                cgroup_populated=False,
                termination_method="systemd-control-group",
            )
        return stopped

    def remove(self, *, worker_id: str) -> NativeWorkerState:
        """Stop and collect the exact transient runner registration."""

        worker_id = _worker_id(worker_id)
        unit = self.unit(worker_id)
        stopped = self.stop(worker_id=worker_id)
        if not stopped.loaded:
            return stopped
        if stopped.active:
            raise WorkerNativeError(
                "systemd did not prove the worker runner stopped before removal"
            )
        _run(self.runner, [self.systemctl_executable, "reset-failed", unit])
        removed = self.status(worker_id=worker_id, allow_missing=True)
        if removed.loaded:
            raise WorkerNativeError(
                "systemd did not collect the exact transient worker runner"
            )
        if stopped.termination_method is not None:
            removed = replace(
                removed,
                control_group=stopped.control_group,
                cgroup_populated=False,
                termination_method=stopped.termination_method,
            )
        return removed

    def _control_group_path(self, control_group: str) -> Path:
        if (
            not isinstance(control_group, str)
            or not control_group.startswith("/")
            or "\x00" in control_group
            or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
        ):
            raise WorkerNativeError("systemd returned an invalid worker control group")
        return self.cgroup_root.joinpath(*control_group.split("/")[1:])

    def _control_group_populated(
        self, control_group: str, *, allow_missing: bool = False
    ) -> bool:
        events = self._control_group_path(control_group) / "cgroup.events"
        try:
            payload = events.read_text(encoding="ascii")
        except FileNotFoundError:
            if allow_missing:
                return False
            raise WorkerNativeError("worker cgroup.events is unavailable")
        except OSError as error:
            raise WorkerNativeError("worker cgroup.events is unavailable") from error
        values = dict(
            line.split(" ", 1)
            for line in payload.splitlines()
            if " " in line
        )
        if values.get("populated") not in {"0", "1"}:
            raise WorkerNativeError("worker cgroup.events has invalid populated evidence")
        return values["populated"] == "1"

    def status(
        self, *, worker_id: str, allow_missing: bool = False
    ) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        unit = self.unit(worker_id)
        try:
            completed = _run(
                self.runner,
                [
                    self.systemctl_executable,
                    "show",
                    unit,
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                    "--property=ExecMainStatus",
                    "--property=ControlGroup",
                    "--no-pager",
                ],
            )
        except _NativeCommandError as error:
            if not allow_missing or not _is_missing(error):
                raise
            return NativeWorkerState(
                worker_id, "systemd", unit, False, False, "not-found", None, None
            )
        values: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        required = {"LoadState", "ActiveState", "SubState", "MainPID"}
        if not required.issubset(values):
            raise WorkerNativeError("systemd returned an incomplete unit status")
        load_state = values["LoadState"]
        active_state = values["ActiveState"]
        sub_state = values["SubState"]
        if not all(
            _SAFE_STATE.fullmatch(value)
            for value in (load_state, active_state, sub_state)
        ):
            raise WorkerNativeError("systemd returned an invalid unit state")
        pid_text = values["MainPID"]
        if not pid_text.isdigit() or int(pid_text) > 2**31 - 1:
            raise WorkerNativeError("systemd returned an invalid runner PID")
        pid_value = int(pid_text)
        pid = pid_value or None
        status_text = values.get("ExecMainStatus")
        if status_text not in {None, ""} and (
            not status_text.lstrip("-").isdigit()
            or not -255 <= int(status_text) <= 255
        ):
            raise WorkerNativeError("systemd returned an invalid exit status")
        exit_status = int(status_text) if status_text not in {None, ""} else None
        control_group = values.get("ControlGroup") or None
        populated = (
            None
            if control_group is None
            else self._control_group_populated(control_group, allow_missing=True)
        )
        return NativeWorkerState(
            worker_id=worker_id,
            manager="systemd",
            unit=unit,
            loaded=load_state == "loaded",
            active=active_state
            in {"active", "activating", "deactivating", "reloading"},
            state=sub_state,
            pid=pid,
            exit_status=exit_status,
            control_group=control_group,
            cgroup_populated=populated,
        )


class LaunchdWorkerManager:
    """Manage root-owned or per-user launchd runner plists with fixed argv."""

    def __init__(
        self,
        *,
        coordinator_script: Path,
        state_root: Path,
        python_executable: str = "/usr/bin/python3",
        launchctl_executable: str = "/bin/launchctl",
        runner: Runner = subprocess.run,
        system_domain: bool | None = None,
    ) -> None:
        self.coordinator_script = _trusted_script(coordinator_script)
        self.state_root = state_root.expanduser()
        if not self.state_root.is_absolute():
            raise WorkerNativeError("launchd worker state root must be absolute")
        self.python_executable = _trusted_executable(
            python_executable, description="Python executable"
        )
        self.launchctl_executable = _trusted_executable(
            launchctl_executable, description="launchctl executable"
        )
        self.runner = runner
        self.system_domain = os.geteuid() == 0 if system_domain is None else system_domain
        if self.system_domain and os.geteuid() != 0:
            raise WorkerNativeError("the launchd system domain requires root authority")

    @staticmethod
    def label(worker_id: str) -> str:
        return "org.openai.devcoordinator.worker." + _worker_id(worker_id)

    def _domain(self, uid: int) -> str:
        uid = _positive_id(uid, "uid")
        if self.system_domain:
            if os.geteuid() != 0:
                raise WorkerNativeError(
                    "the launchd system domain requires root authority"
                )
            return "system"
        if not self.system_domain and uid != os.geteuid():
            raise WorkerNativeError("a user launchd manager cannot manage another UID")
        return f"gui/{uid}"

    def _plist_path(self, worker_id: str) -> Path:
        return self.state_root / (self.label(worker_id) + ".plist")

    def _plist_document(
        self, *, worker_id: str, identity: _LocalIdentity
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "Label": self.label(worker_id),
            "ProgramArguments": [
                self.python_executable,
                "-I",
                "-B",
                str(self.coordinator_script),
                "worker",
                "runner",
                "--worker-id",
                worker_id,
            ],
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Background",
            "Umask": 0o077,
            "ThrottleInterval": 2,
        }
        if self.system_domain:
            document["UserName"] = identity.user
            document["GroupName"] = identity.group
        return document

    def _write_plist(self, *, worker_id: str, uid: int, gid: int) -> Path:
        identity = _identity(uid, gid)
        self._domain(identity.uid)
        try:
            self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise WorkerNativeError(
                f"launchd worker state root could not be created: {error}"
            ) from error
        document = self._plist_document(worker_id=worker_id, identity=identity)
        payload = plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)
        target = self._plist_path(worker_id)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(self.state_root, flags)
        except OSError as error:
            raise WorkerNativeError(f"launchd worker state root is unsafe: {error}") from error
        temp_name = f".worker-{uuid.uuid4()}"
        target_name = target.name
        try:
            metadata = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
            ):
                raise WorkerNativeError("launchd worker state root is not a directory")
            try:
                old = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                old = None
            if old is not None and (
                not stat.S_ISREG(old.st_mode)
            ):
                raise WorkerNativeError("existing launchd worker plist is unsafe")
            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            create_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(temp_name, create_flags, 0o600, dir_fd=directory_fd)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    fd = -1
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(
                    temp_name,
                    target_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                temp_name = ""
                os.fsync(directory_fd)
                final = os.stat(
                    target_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(final.st_mode)
                ):
                    raise WorkerNativeError("written launchd worker plist is unsafe")
            finally:
                if fd >= 0:
                    os.close(fd)
        except WorkerNativeError:
            raise
        except OSError as error:
            raise WorkerNativeError(
                f"launchd worker plist could not be persisted atomically: {error}"
            ) from error
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except OSError:
                    pass
            os.close(directory_fd)
        return target

    def start(
        self, *, worker_id: str, uid: int, gid: int, repository_id: str
    ) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        if not isinstance(repository_id, str) or not repository_id:
            raise ValueError("worker repository ID must be one bounded string")
        identity = _identity(uid, gid)
        target = self._write_plist(worker_id=worker_id, uid=uid, gid=gid)
        domain = self._domain(identity.uid)
        label = self.label(worker_id)
        current = self.status(worker_id=worker_id, uid=identity.uid)
        if current.loaded:
            _run(
                self.runner,
                [self.launchctl_executable, "bootout", f"{domain}/{label}"],
            )
        _run(
            self.runner,
            [self.launchctl_executable, "bootstrap", domain, str(target)],
        )
        state = self.status(worker_id=worker_id, uid=identity.uid)
        if not state.loaded:
            raise WorkerNativeError("launchd accepted the runner but did not load its job")
        return state

    def stop(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        domain = self._domain(uid)
        label = self.label(worker_id)
        current = self.status(worker_id=worker_id, uid=uid)
        if not current.loaded:
            return current
        _run(
            self.runner,
            [self.launchctl_executable, "bootout", f"{domain}/{label}"],
        )
        return NativeWorkerState(
            worker_id, "launchd", label, False, False, "unloaded", None, 0
        )

    def remove(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        """Unload the exact job and durably remove its private fixed plist."""

        worker_id = _worker_id(worker_id)
        state = self.stop(worker_id=worker_id, uid=uid)
        if state.active or state.loaded:
            raise WorkerNativeError(
                "launchd did not prove the worker runner unloaded before removal"
            )
        self._unlink_plist(worker_id)
        return state

    def _unlink_plist(self, worker_id: str) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(self.state_root, flags)
        except FileNotFoundError:
            return
        except OSError as error:
            raise WorkerNativeError(
                f"launchd worker state root is unsafe: {error}"
            ) from error
        try:
            directory = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(directory.st_mode)
            ):
                raise WorkerNativeError("launchd worker state root is not a directory")
            target_name = self._plist_path(worker_id).name
            try:
                target = os.stat(
                    target_name, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(target.st_mode)
            ):
                raise WorkerNativeError("existing launchd worker plist is unsafe")
            os.unlink(target_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except WorkerNativeError:
            raise
        except OSError as error:
            raise WorkerNativeError(
                f"launchd worker plist could not be removed durably: {error}"
            ) from error
        finally:
            os.close(directory_fd)

    def status(self, *, worker_id: str, uid: int) -> NativeWorkerState:
        worker_id = _worker_id(worker_id)
        label = self.label(worker_id)
        domain = self._domain(uid)
        try:
            completed = _run(
                self.runner,
                [self.launchctl_executable, "print", f"{domain}/{label}"],
            )
        except _NativeCommandError as error:
            if not _is_missing(error):
                raise
            return NativeWorkerState(
                worker_id, "launchd", label, False, False, "unloaded", None, None
            )
        state = "unknown"
        saw_state = False
        pid: int | None = None
        exit_status: int | None = None
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("state = "):
                candidate = line.partition("=")[2].strip()
                if _SAFE_STATE.fullmatch(candidate):
                    state = candidate
                    saw_state = True
            elif line.startswith("pid = "):
                candidate = line.partition("=")[2].strip()
                pid = (
                    int(candidate)
                    if candidate.isdigit() and 0 < int(candidate) <= 2**31 - 1
                    else None
                )
            elif line.startswith("last exit code = "):
                candidate = line.partition("=")[2].strip()
                exit_status = (
                    int(candidate)
                    if candidate.lstrip("-").isdigit()
                    and -255 <= int(candidate) <= 255
                    else None
                )
        if not saw_state:
            raise WorkerNativeError("launchd returned an incomplete job status")
        return NativeWorkerState(
            worker_id=worker_id,
            manager="launchd",
            unit=label,
            loaded=True,
            active=state in {"running", "spawn scheduled"},
            state=state,
            pid=pid,
            exit_status=exit_status,
        )


def native_worker_manager(
    *, coordinator_script: Path, state_root: Path | None = None, runner: Runner = subprocess.run
) -> SystemdWorkerManager | LaunchdWorkerManager:
    """Select a supported native manager; never fall back to an ad-hoc daemon."""

    if sys.platform.startswith("linux"):
        systemd_run = next(
            (path for path in ("/usr/bin/systemd-run", "/bin/systemd-run") if Path(path).is_file()),
            None,
        )
        systemctl = next(
            (path for path in ("/usr/bin/systemctl", "/bin/systemctl") if Path(path).is_file()),
            None,
        )
        if systemd_run is None or systemctl is None:
            raise WorkerNativeError("systemd-run and systemctl are required for worker supervision")
        return SystemdWorkerManager(
            coordinator_script=coordinator_script,
            systemd_run_executable=systemd_run,
            systemctl_executable=systemctl,
            runner=runner,
        )
    if sys.platform == "darwin":
        root = state_root or Path(
            "/var/run/devcoordinator/workers"
            if os.geteuid() == 0
            else "~/Library/Application Support/DevCoordinator/Workers"
        ).expanduser()
        return LaunchdWorkerManager(
            coordinator_script=coordinator_script,
            state_root=root,
            runner=runner,
        )
    raise WorkerNativeError(f"worker supervision is unsupported on {sys.platform}")
