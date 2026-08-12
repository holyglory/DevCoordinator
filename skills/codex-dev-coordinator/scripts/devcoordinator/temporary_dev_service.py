"""Broker-owned, bounded temporary development services.

The caller supplies structured argv, never a shell command.  The broker runs
the process as the actual non-root caller, binds it to one exact port, a
repository-relative working directory, and a positive systemd lifetime.  The
operation UUID names the transient unit deterministically so a lost reply
cannot create a second server.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import socket
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

from .call_journal import sanitized_bounded_text
from .worker_native import project_repository_slice


_SERVICE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,62}[a-z0-9])?")
_UNIT_NAME = re.compile(r"devcoordinator-dev-[0-9a-f]{32}\.service")
_SHELL_NAMES = frozenset({"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"})
MAX_ARGV_ITEMS = 256
MAX_ARGV_BYTES = 32 * 1024
MAX_TTL_SECONDS = 7 * 24 * 60 * 60


def temporary_dev_service_id(repository_id: str, name: str) -> str:
    """Return the stable catalog identity for one repository/name pair."""

    return "service-" + uuid.uuid5(
        uuid.NAMESPACE_URL,
        "devcoordinator:dev-service:" + repository_id + ":" + name,
    ).hex


class TemporaryDevServiceError(RuntimeError):
    """One typed pre-launch or launch failure."""

    def __init__(self, code: str, message: str, *, diagnostic: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostic = diagnostic


def public_temporary_dev_service_error(error: TemporaryDevServiceError) -> str:
    """Return one bounded safe broker/client message with launch evidence."""

    message = sanitized_bounded_text(str(error), limit=180)
    if not error.diagnostic:
        return message
    prefix = message + "; launch diagnostic: "
    diagnostic = sanitized_bounded_text(error.diagnostic, limit=1024)
    budget = 512 - len(prefix)
    # ``_diagnostic`` asks journalctl for reverse order, so the newest native
    # process/systemd cause is first. Preserve that actionable block instead
    # of spending the public bound on the older generated command identity.
    return prefix + diagnostic[:budget]


class CommandRunner(Protocol):
    def __call__(
        self, argv: Sequence[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]: ...


def validate_temporary_dev_service_definition(
    *,
    name: object,
    argv: object,
    cwd: object,
    port: object,
    ttl_seconds: object,
    kill_after_run: object,
    launch_timeout_seconds: object,
) -> None:
    """Validate caller-controlled launch fields before any adoption mutation."""

    if not isinstance(name, str) or _SERVICE_NAME.fullmatch(name) is None:
        raise TemporaryDevServiceError(
            "service_name_invalid",
            "temporary service name must be a bounded lowercase identifier",
        )
    if (
        not isinstance(argv, (tuple, list))
        or not argv
        or len(argv) > MAX_ARGV_ITEMS
        or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > 8192
            for item in argv
        )
        or sum(len(item.encode("utf-8")) for item in argv) > MAX_ARGV_BYTES
    ):
        raise TemporaryDevServiceError(
            "argv_invalid", "argv must be a bounded non-empty string array"
        )
    executable = PurePosixPath(argv[0]).name
    if executable in _SHELL_NAMES:
        raise TemporaryDevServiceError(
            "shell_forbidden", "temporary services require structured argv, not a shell"
        )
    if not isinstance(cwd, str) or not cwd:
        raise TemporaryDevServiceError(
            "cwd_invalid", "cwd must be a repository-relative path"
        )
    relative = PurePosixPath(cwd)
    if relative.is_absolute() or any(part in {"", ".."} for part in relative.parts):
        raise TemporaryDevServiceError(
            "cwd_invalid", "cwd must be a repository-relative path"
        )
    if type(port) is not int or not 1 <= port <= 65535:
        raise TemporaryDevServiceError(
            "port_invalid", "port must be one exact TCP port from 1 through 65535"
        )
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise TemporaryDevServiceError(
            "ttl_invalid", "ttl_seconds must be positive and no greater than seven days"
        )
    if type(kill_after_run) is not bool:
        raise TemporaryDevServiceError(
            "kill_after_run_invalid", "kill_after_run must be a boolean"
        )
    if (
        type(launch_timeout_seconds) is not int
        or not 1 <= launch_timeout_seconds <= 300
    ):
        raise TemporaryDevServiceError(
            "launch_timeout_invalid",
            "launch_timeout_seconds must be from 1 through 300",
        )


@dataclass(frozen=True)
class TemporaryDevServiceRequest:
    operation_id: str
    repository_id: str
    repository_root: str
    repository_generation: int
    execution_uid: int
    agent: str
    name: str
    argv: tuple[str, ...]
    cwd: str
    port: int
    ttl_seconds: int
    kill_after_run: bool
    launch_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        try:
            canonical_operation = str(uuid.UUID(self.operation_id))
        except (AttributeError, ValueError) as error:
            raise TemporaryDevServiceError(
                "operation_id_invalid", "operation_id must be a canonical UUID"
            ) from error
        if canonical_operation != self.operation_id:
            raise TemporaryDevServiceError(
                "operation_id_invalid", "operation_id must be a canonical UUID"
            )
        if not self.repository_id or not self.repository_id.isascii():
            raise TemporaryDevServiceError(
                "repository_identity_invalid", "repository identity is invalid"
            )
        if type(self.repository_generation) is not int or self.repository_generation < 0:
            raise TemporaryDevServiceError(
                "repository_generation_invalid", "repository generation is invalid"
            )
        if type(self.execution_uid) is not int or self.execution_uid <= 0:
            raise TemporaryDevServiceError(
                "execution_identity_invalid",
                "temporary services require the actual non-root caller UID",
            )
        validate_temporary_dev_service_definition(
            name=self.name,
            argv=self.argv,
            cwd=self.cwd,
            port=self.port,
            ttl_seconds=self.ttl_seconds,
            kill_after_run=self.kill_after_run,
            launch_timeout_seconds=self.launch_timeout_seconds,
        )

    @property
    def unit_name(self) -> str:
        return "devcoordinator-dev-" + self.operation_id.replace("-", "") + ".service"

    @property
    def session_id(self) -> str:
        return "session-" + uuid.uuid5(
            uuid.NAMESPACE_URL, "devcoordinator:dev-session:" + self.operation_id
        ).hex

    @property
    def service_id(self) -> str:
        return temporary_dev_service_id(self.repository_id, self.name)

    def resolved_cwd(self) -> Path:
        try:
            root = Path(self.repository_root).resolve(strict=True)
            target = (root / self.cwd).resolve(strict=True)
        except OSError as error:
            raise TemporaryDevServiceError(
                "cwd_unavailable", "temporary service working directory is unavailable"
            ) from error
        try:
            target.relative_to(root)
        except ValueError as error:
            raise TemporaryDevServiceError(
                "cwd_escape", "temporary service working directory escapes the repository"
            ) from error
        if not target.is_dir():
            raise TemporaryDevServiceError(
                "cwd_invalid", "temporary service working directory is not a directory"
            )
        return target


def _default_runner(
    argv: Sequence[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def _default_port_probe(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _listening_socket_inodes(port: int) -> set[str]:
    encoded_port = f"{port:04X}"
    inodes: set[str] = set()
    for source in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = source.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            _address, separator, candidate_port = fields[1].rpartition(":")
            if separator and candidate_port.upper() == encoded_port and fields[3] == "0A":
                inodes.add(fields[9])
    return inodes


def _default_listener_ownership_probe(
    port: int, state: Mapping[str, str]
) -> bool:
    """Prove a listener PID is inside the transient unit's exact cgroup."""

    control_group = str(state.get("ControlGroup") or "")
    if not control_group.startswith("/"):
        return False
    inodes = _listening_socket_inodes(port)
    if not inodes:
        return False
    try:
        process_paths = tuple(Path("/proc").iterdir())
    except OSError:
        return False
    for process_path in process_paths:
        if not process_path.name.isdigit():
            continue
        try:
            cgroups = (process_path / "cgroup").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue
        owned = any(
            line.rpartition(":")[2] == control_group
            or line.rpartition(":")[2].startswith(control_group.rstrip("/") + "/")
            for line in cgroups.splitlines()
        )
        if not owned:
            continue
        try:
            descriptors = tuple((process_path / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                return True
    return False


def _execution_supplementary_gids(
    account: pwd.struct_passwd,
) -> tuple[int, ...]:
    """Return the execution account's ordinary supplementary groups.

    The set is explicit so the credential-drop shim never inherits service
    process groups. Group zero and the primary group are omitted because
    setpriv carries the primary group separately.
    """

    try:
        gids = {
            int(gid)
            for gid in os.getgrouplist(account.pw_name, account.pw_gid)
        }
    except (OSError, ValueError) as error:
        raise TemporaryDevServiceError(
            "execution_identity_unavailable",
            "temporary service caller groups could not be resolved",
        ) from error
    gids.difference_update({0, int(account.pw_gid)})
    return tuple(sorted(gids))


def _default_process_uid_probe(pid: int, expected_uid: int) -> bool:
    """Prove all four Linux process UIDs match without accepting PID reuse."""

    if type(pid) is not int or pid <= 1 or type(expected_uid) is not int:
        return False
    process = Path("/proc") / str(pid)
    try:
        before = process.stat(follow_symlinks=False)
        status = (process / "status").read_text(
            encoding="utf-8", errors="replace"
        )
        after = process.stat(follow_symlinks=False)
    except OSError:
        return False
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        return False
    for line in status.splitlines():
        fields = line.split()
        if fields[:1] != ["Uid:"]:
            continue
        if len(fields) != 5:
            return False
        try:
            uids = tuple(int(value) for value in fields[1:])
        except ValueError:
            return False
        return uids == (expected_uid,) * 4
    return False


def _systemd_properties(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            values[key] = value
    return values


class TemporaryDevServiceManager:
    """Launch one exact transient systemd unit and prove its listener is ready."""

    def __init__(
        self,
        *,
        runner: CommandRunner = _default_runner,
        port_probe: Callable[[int], bool] = _default_port_probe,
        listener_ownership_probe: Callable[
            [int, Mapping[str, str]], bool
        ] = _default_listener_ownership_probe,
        process_uid_probe: Callable[[int, int], bool] = _default_process_uid_probe,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall_time: Callable[[], datetime] | None = None,
    ) -> None:
        self._runner = runner
        self._port_probe = port_probe
        self._listener_ownership_probe = listener_ownership_probe
        self._process_uid_probe = process_uid_probe
        self._monotonic = monotonic
        self._sleep = sleep
        self._wall_time = wall_time or (lambda: datetime.now(timezone.utc))

    def _show(self, unit: str) -> dict[str, str]:
        result = self._runner(
            (
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--property=ControlGroup",
                "--property=InvocationID",
            ),
            timeout=5.0,
        )
        if result.returncode != 0:
            return {"LoadState": "not-found"}
        return _systemd_properties(result.stdout)

    def _diagnostic(self, unit: str) -> str:
        try:
            result = self._runner(
                (
                    "/usr/bin/journalctl",
                    "--unit",
                    unit,
                    "--lines=40",
                    "--reverse",
                    "--output=cat",
                    "--no-pager",
                ),
                timeout=5.0,
            )
        except (OSError, subprocess.SubprocessError):
            # Diagnostic collection must never replace the definite launch or
            # lifecycle failure it was meant to explain.
            return ""
        text = (result.stdout + "\n" + result.stderr).strip()
        return text[:4096]

    def status(self, *, unit: str, port: int) -> dict[str, Any]:
        """Inspect one broker-created transient unit without mutating it."""

        if _UNIT_NAME.fullmatch(unit) is None:
            raise TemporaryDevServiceError(
                "temporary_service_identity_invalid",
                "temporary service unit identity is invalid",
            )
        if type(port) is not int or not 1 <= port <= 65535:
            raise TemporaryDevServiceError(
                "port_invalid", "temporary service port is invalid"
            )
        state = self._show(unit)
        active = state.get("ActiveState") in {"active", "activating"}
        listening = active and self._port_probe(port)
        owned = listening and self._listener_ownership_probe(port, state)
        if owned:
            lifecycle = "running"
        elif active:
            lifecycle = "starting"
        else:
            lifecycle = "stopped"
        return {
            "state": lifecycle,
            "ready": lifecycle == "running",
            "main_pid": int(state.get("MainPID") or 0),
        }

    def capture_logs(self, *, unit: str, port: int) -> dict[str, Any]:
        """Capture bounded journal input for one retained transient unit."""

        status = self.status(unit=unit, port=port)
        state = self._show(unit)
        if state.get("LoadState") == "not-found":
            raise TemporaryDevServiceError(
                "temporary_service_logs_unavailable",
                "the retained temporary service unit is no longer available",
            )
        result = self._runner(
            (
                "/usr/bin/journalctl",
                "--unit",
                unit,
                "--lines=2000",
                "--output=cat",
                "--no-pager",
            ),
            timeout=10.0,
        )
        if result.returncode != 0:
            raise TemporaryDevServiceError(
                "temporary_service_logs_unavailable",
                "system authority could not read the retained temporary service journal",
                diagnostic=(result.stdout + "\n" + result.stderr).strip()[:4096],
            )
        invocation = str(state.get("InvocationID") or "unavailable")
        return {
            **status,
            "raw": (result.stdout + "\n" + result.stderr).encode("utf-8"),
            "source_identity": "sha256:"
            + hashlib.sha256((unit + "\0" + invocation).encode("utf-8")).hexdigest(),
        }

    def stop(self, *, unit: str, port: int) -> dict[str, Any]:
        """Stop one exact retained transient unit and prove it inactive."""

        before = self.status(unit=unit, port=port)
        if before["state"] == "stopped":
            return {**before, "reused": True}
        result = self._runner(
            ("/usr/bin/systemctl", "stop", unit), timeout=15.0
        )
        if result.returncode != 0:
            raise TemporaryDevServiceError(
                "temporary_service_stop_failed",
                "system authority could not stop the retained temporary service",
                diagnostic=(result.stdout + "\n" + result.stderr).strip()[:4096],
            )
        after = self.status(unit=unit, port=port)
        if after["state"] != "stopped":
            raise TemporaryDevServiceError(
                "operation_outcome_uncertain",
                "the temporary service stop did not reach a provable inactive state",
            )
        return {**after, "reused": False}

    def restart(
        self,
        *,
        unit: str,
        port: int,
        execution_uid: int,
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        """Restart one still-retained transient unit and prove its listener."""

        before = self._show(unit)
        if before.get("LoadState") == "not-found":
            raise TemporaryDevServiceError(
                "temporary_service_definition_expired",
                "the transient unit definition is no longer retained; launch the service again",
            )
        result = self._runner(
            ("/usr/bin/systemctl", "restart", unit), timeout=15.0
        )
        if result.returncode != 0:
            raise TemporaryDevServiceError(
                "temporary_service_restart_failed",
                "system authority could not restart the retained temporary service",
                diagnostic=(result.stdout + "\n" + result.stderr).strip()[:4096],
            )
        deadline = self._monotonic() + timeout_seconds
        while self._monotonic() < deadline:
            state = self._show(unit)
            if state.get("ActiveState") in {"failed", "inactive"}:
                raise TemporaryDevServiceError(
                    "temporary_service_exited",
                    "the temporary service exited during restart",
                    diagnostic=self._diagnostic(unit),
                )
            if self._port_probe(port):
                if not self._listener_ownership_probe(port, state):
                    raise TemporaryDevServiceError(
                        "port_ownership_mismatch",
                        "the restarted listener does not belong to the retained temporary service",
                    )
                main_pid = int(state.get("MainPID") or 0)
                if main_pid <= 1 or not self._process_uid_probe(
                    main_pid, execution_uid
                ):
                    self._runner(
                        ("/usr/bin/systemctl", "stop", unit), timeout=15.0
                    )
                    raise TemporaryDevServiceError(
                        "temporary_service_execution_identity_mismatch",
                        "Coordinator stopped the temporary service because its actual-caller UID could not be proven",
                    )
                return {
                    "state": "running",
                    "ready": True,
                    "main_pid": main_pid,
                    "reused": False,
                }
            self._sleep(0.1)
        raise TemporaryDevServiceError(
            "temporary_service_readiness_timeout",
            "the restarted temporary service did not become ready before the bounded deadline",
            diagnostic=self._diagnostic(unit),
        )

    def _require_execution_identity(
        self,
        request: TemporaryDevServiceRequest,
        *,
        state: Mapping[str, str],
    ) -> None:
        try:
            main_pid = int(state.get("MainPID") or 0)
        except (TypeError, ValueError):
            main_pid = 0
        if main_pid > 1 and self._process_uid_probe(
            main_pid, request.execution_uid
        ):
            return
        self._runner(
            ("/usr/bin/systemctl", "stop", request.unit_name), timeout=15.0
        )
        raise TemporaryDevServiceError(
            "temporary_service_execution_identity_mismatch",
            "Coordinator stopped the temporary service because its actual-caller UID could not be proven",
        )

    def start(self, request: TemporaryDevServiceRequest) -> dict[str, Any]:
        cwd = request.resolved_cwd()
        existing = self._show(request.unit_name)
        if existing.get("ActiveState") in {"active", "activating"}:
            # Broker restart may replay while systemd is still activating the
            # exact deterministic unit.  Join that launch instead of killing
            # healthy in-flight work merely because the listener is not ready
            # at the first observation.
            deadline = self._monotonic() + request.launch_timeout_seconds
            state = existing
            while self._monotonic() < deadline:
                if state.get("ActiveState") in {"failed", "inactive"}:
                    raise TemporaryDevServiceError(
                        "temporary_service_exited",
                        "the temporary service exited before its exact port became ready",
                        diagnostic=self._diagnostic(request.unit_name),
                    )
                if self._port_probe(request.port):
                    if not self._listener_ownership_probe(request.port, state):
                        raise TemporaryDevServiceError(
                            "port_ownership_mismatch",
                            "a listener on the exact port does not belong to the retained temporary service",
                        )
                    self._require_execution_identity(request, state=state)
                    return self._result(
                        request, cwd=cwd, reused=True, state=state
                    )
                self._sleep(0.1)
                state = self._show(request.unit_name)
            raise TemporaryDevServiceError(
                "temporary_service_readiness_timeout",
                "the retained temporary service is still not ready; replay the same operation ID",
                diagnostic=self._diagnostic(request.unit_name),
            )
        if existing.get("LoadState") not in {None, "not-found"}:
            raise TemporaryDevServiceError(
                "operation_outcome_uncertain",
                "the deterministic temporary service unit exists in a non-running state",
                diagnostic=self._diagnostic(request.unit_name),
            )
        if self._port_probe(request.port):
            raise TemporaryDevServiceError(
                "port_in_use",
                "the exact requested port is already in use; no fallback port was selected",
            )

        try:
            account = pwd.getpwuid(request.execution_uid)
        except KeyError as error:
            raise TemporaryDevServiceError(
                "execution_identity_unavailable",
                "temporary service caller account no longer exists",
            ) from error
        supplementary_gids = _execution_supplementary_gids(account)
        command = (
            "/usr/bin/systemd-run",
            "--collect",
            "--unit=" + request.unit_name,
            "--slice="
            + project_repository_slice(
                uid=request.execution_uid, repository_id=request.repository_id
            ),
            # PID 1 starts only the fixed trusted setpriv shim from root. The
            # shim applies the actual caller identity and explicit groups
            # before env enters the already-proven repository cwd and before
            # any request-controlled argv executes.
            "--working-directory=/",
            "--property=Type=exec",
            "--property=Restart=no",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=10s",
            "--property=RuntimeMaxSec=" + str(request.ttl_seconds) + "s",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            "--setenv=HOME=" + account.pw_dir,
            "--setenv=USER=" + account.pw_name,
            "--setenv=LOGNAME=" + account.pw_name,
            "--setenv=HOST=0.0.0.0",
            "--setenv=PORT=" + str(request.port),
            "--setenv=PWD=" + str(cwd),
            "--setenv=DEVCOORDINATOR_OPERATION_ID=" + request.operation_id,
            "--setenv=DEVCOORDINATOR_SESSION_ID=" + request.session_id,
            "--setenv=DEVCOORDINATOR_SERVICE_ID=" + request.service_id,
            "--",
            "/usr/bin/setpriv",
            "--reuid=" + str(request.execution_uid),
            "--regid=" + str(account.pw_gid),
            *(
                ("--groups=" + ",".join(str(gid) for gid in supplementary_gids),)
                if supplementary_gids
                else ("--clear-groups",)
            ),
            "--inh-caps=-all",
            "--no-new-privs",
            "--",
            "/usr/bin/env",
            "--chdir=" + str(cwd),
            "--",
            *request.argv,
        )
        launched = self._runner(command, timeout=15.0)
        if launched.returncode != 0:
            stream_detail = (launched.stdout + "\n" + launched.stderr).strip()
            journal_detail = self._diagnostic(request.unit_name)
            # systemd-run commonly returns only "See journalctl". Put the
            # journal first so the bounded public envelope retains the native
            # setup failure rather than truncating it behind generic advice.
            detail = "\n".join(
                item
                for item in (journal_detail, stream_detail)
                if item
            )[:4096]
            if not detail:
                detail = (
                    "systemd-run exited with status "
                    + str(launched.returncode)
                    + " without returning a native diagnostic"
                )
            raise TemporaryDevServiceError(
                "temporary_service_launch_failed",
                "systemd rejected the bounded temporary service",
                diagnostic=detail,
            )

        deadline = self._monotonic() + request.launch_timeout_seconds
        state: dict[str, str] = {}
        while self._monotonic() < deadline:
            state = self._show(request.unit_name)
            if state.get("ActiveState") in {"failed", "inactive"}:
                raise TemporaryDevServiceError(
                    "temporary_service_exited",
                    "the temporary service exited before its exact port became ready",
                    diagnostic=self._diagnostic(request.unit_name),
                )
            if self._port_probe(request.port):
                if not self._listener_ownership_probe(request.port, state):
                    self._runner(
                        ("/usr/bin/systemctl", "stop", request.unit_name),
                        timeout=15.0,
                    )
                    raise TemporaryDevServiceError(
                        "port_ownership_mismatch",
                        "a listener appeared on the exact port but did not belong to the launched service; the service was stopped",
                    )
                self._require_execution_identity(request, state=state)
                return self._result(request, cwd=cwd, reused=False, state=state)
            self._sleep(0.1)

        self._runner(
            ("/usr/bin/systemctl", "stop", request.unit_name), timeout=15.0
        )
        raise TemporaryDevServiceError(
            "temporary_service_readiness_timeout",
            "the temporary service did not listen on the exact requested port before the launch deadline",
            diagnostic=self._diagnostic(request.unit_name),
        )

    def _result(
        self,
        request: TemporaryDevServiceRequest,
        *,
        cwd: Path,
        reused: bool,
        state: Mapping[str, str],
    ) -> dict[str, Any]:
        expires = (
            self._wall_time() + timedelta(seconds=request.ttl_seconds)
        ).replace(microsecond=0)
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
            "port": request.port,
            "url": f"http://127.0.0.1:{request.port}/",
            "state": "running",
            "main_pid": int(state.get("MainPID") or 0),
            "reused": reused,
            "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cleanup": {
                "owner": "systemd",
                "kill_mode": "control-group",
                "ttl_seconds": request.ttl_seconds,
                "kill_after_run": request.kill_after_run,
            },
            "isolation": {
                "manager": "systemd",
                "slice": project_repository_slice(
                    uid=request.execution_uid,
                    repository_id=request.repository_id,
                ),
                "control_group": str(state.get("ControlGroup") or ""),
                "listener_owner_proven": True,
                "execution_uid": request.execution_uid,
                "actual_caller_uid_proven": True,
            },
            # Return only repository-relative cwd; host paths stay internal.
            "cwd": os.path.relpath(cwd, request.repository_root),
        }


__all__ = [
    "TemporaryDevServiceError",
    "TemporaryDevServiceManager",
    "TemporaryDevServiceRequest",
    "public_temporary_dev_service_error",
    "validate_temporary_dev_service_definition",
]
