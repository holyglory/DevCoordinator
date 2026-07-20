"""Exact host-boundary adapter for repository lifecycle operations."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Protocol, Sequence

from .repository_lifecycle import (
    CapturedStartupPolicyState,
    ExactResourceRef,
    LifecycleError,
    OwnershipError,
    PlanDriftError,
    PolicyKind,
    PolicyObservation,
    ResourceKind,
    ResourceObservation,
    RunningState,
    StartupPolicyRef,
)


_RESTORABLE_SYSTEMD_UNIT_FILE_STATES = frozenset(
    {
        "disabled",
        "enabled",
        "enabled-runtime",
        "masked-runtime",
        "static",
        "indirect",
        "generated",
        "transient",
        "alias",
    }
)


@dataclass(frozen=True)
class ServerBoundary:
    observable: bool
    identity_matches: bool
    running_state: RunningState
    listener_observable: bool
    listener_active: bool | None


@dataclass(frozen=True)
class ContainerBoundary:
    observable: bool
    full_container_id: str | None
    running: bool | None
    restart_policy: str | None


@dataclass(frozen=True)
class SupervisorBoundary:
    observable: bool
    identity_matches: bool
    active: bool | None
    enabled: bool | None
    manager: str | None = None
    unit_file_state: str | None = None
    loaded: bool | None = None


class NativeLifecycleBackend(Protocol):
    def observe_server(self, identity: Mapping[str, str]) -> ServerBoundary:
        ...

    def stop_server(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        ...

    def observe_container(self, full_container_id: str) -> ContainerBoundary:
        ...

    def disable_container_restart(self, full_container_id: str) -> Mapping[str, Any]:
        ...

    def restore_container_restart(
        self, full_container_id: str, restart_policy: str
    ) -> Mapping[str, Any]:
        ...

    def stop_container(self, full_container_id: str) -> Mapping[str, Any]:
        ...

    def observe_supervisor(self, identity: Mapping[str, str]) -> SupervisorBoundary:
        ...

    def disable_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        ...

    def restore_supervisor(
        self,
        identity: Mapping[str, str],
        captured: CapturedStartupPolicyState,
    ) -> Mapping[str, Any]:
        ...

    def stop_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        ...


class CoordinatorHostLifecycleAdapter:
    """Translate normalized exact targets into bounded host operations."""

    def __init__(self, backend: NativeLifecycleBackend | None = None) -> None:
        self.backend = backend or LocalHostLifecycleBackend()

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        native = _native(target)
        if target.kind is ResourceKind.CONTAINER:
            full_id = _require_native(native, "full_container_id")
            state = self.backend.observe_container(full_id)
            identity_matches = (
                state.observable
                and state.full_container_id is not None
                and state.full_container_id.lower() == full_id.lower()
            )
            policies = self._policy_observations(target, state, None)
            return ResourceObservation(
                target.resource_id,
                target.kind,
                state.observable,
                target.immutable_fingerprint if identity_matches else _observed_identity(state.full_container_id),
                state.observable and identity_matches,
                target.ownership_fingerprint if identity_matches else None,
                (
                    RunningState.RUNNING
                    if state.running is True
                    else RunningState.STOPPED
                    if state.running is False
                    else RunningState.UNKNOWN
                ),
                container_running=state.running,
                replacement_fingerprint=(
                    None if identity_matches else _observed_identity(state.full_container_id)
                ),
                policies=policies,
            )
        if target.kind is ResourceKind.SERVER:
            state = self.backend.observe_server(native)
            supervisor = (
                self.backend.observe_supervisor(native)
                if any(policy.kind is PolicyKind.SUPERVISOR for policy in target.policies)
                else None
            )
            policies = self._policy_observations(target, None, supervisor)
            return ResourceObservation(
                target.resource_id,
                target.kind,
                state.observable,
                target.immutable_fingerprint if state.identity_matches else "observed:server-mismatch",
                state.observable and state.identity_matches,
                target.ownership_fingerprint if state.identity_matches else None,
                state.running_state,
                listener_active=(
                    state.listener_active if state.listener_observable else None
                ),
                replacement_fingerprint=(
                    None if state.identity_matches else "observed:server-mismatch"
                ),
                policies=policies,
            )
        state = self.backend.observe_supervisor(native)
        policies = self._policy_observations(target, None, state)
        running = (
            RunningState.RUNNING
            if state.active is True
            else RunningState.STOPPED
            if state.active is False
            else RunningState.UNKNOWN
        )
        return ResourceObservation(
            target.resource_id,
            target.kind,
            state.observable,
            target.immutable_fingerprint if state.identity_matches else "observed:supervisor-mismatch",
            state.observable and state.identity_matches,
            target.ownership_fingerprint if state.identity_matches else None,
            running,
            supervisor_active=state.active,
            replacement_fingerprint=(
                None if state.identity_matches else "observed:supervisor-mismatch"
            ),
            policies=policies,
        )

    def disable_startup_policy(
        self, target: ExactResourceRef, policy: StartupPolicyRef
    ) -> Mapping[str, Any]:
        native = _native(target)
        if policy.kind is PolicyKind.DOCKER_RESTART:
            if target.kind is not ResourceKind.CONTAINER:
                raise PlanDriftError("Docker restart policy is attached to a non-container")
            return self.backend.disable_container_restart(
                _require_native(native, "full_container_id")
            )
        if policy.kind is PolicyKind.SUPERVISOR:
            return self.backend.disable_supervisor(native)
        if policy.kind in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
            # The database fence already prevents Coordinator start, register,
            # Compose, and lease reservations.  Persisting the policy's
            # disabled value happens only after the engine verifies this phase.
            return {"disabled_by": "durable_repository_fence"}
        raise LifecycleError(f"unsupported startup policy {policy.kind.value}")

    def restore_startup_policy(
        self,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
    ) -> Mapping[str, Any]:
        native = _native(target)
        if captured.policy_id != policy.policy_id:
            raise PlanDriftError("captured startup policy identity changed")
        if captured.policy_immutable_fingerprint != policy.immutable_fingerprint:
            raise PlanDriftError("captured startup policy fingerprint changed")
        if policy.kind is PolicyKind.DOCKER_RESTART:
            if target.kind is not ResourceKind.CONTAINER:
                raise PlanDriftError("Docker restart policy is attached to a non-container")
            value = captured.docker_restart_policy
            if not value or value != captured.captured_value:
                raise LifecycleError("captured Docker restart policy is incomplete")
            return self.backend.restore_container_restart(
                _require_native(native, "full_container_id"), value
            )
        if policy.kind is PolicyKind.SUPERVISOR:
            return self.backend.restore_supervisor(native, captured)
        if policy.kind in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
            # Clearing the repository fence is the only host-independent
            # policy effect.  The normalized current value is committed only
            # after the lifecycle engine verifies this exact capture.
            return {"restored_by": "guarded_explicit_start"}
        raise LifecycleError(f"unsupported startup policy {policy.kind.value}")

    def stop_exact(self, target: ExactResourceRef) -> Mapping[str, Any]:
        native = _native(target)
        if target.kind is ResourceKind.CONTAINER:
            return self.backend.stop_container(_require_native(native, "full_container_id"))
        if target.kind is ResourceKind.SERVER:
            return self.backend.stop_server(native)
        return self.backend.stop_supervisor(native)

    @staticmethod
    def _policy_observations(
        target: ExactResourceRef,
        container: ContainerBoundary | None,
        supervisor: SupervisorBoundary | None,
    ) -> Mapping[str, PolicyObservation]:
        result: dict[str, PolicyObservation] = {}
        for policy in target.policies:
            if policy.kind is PolicyKind.DOCKER_RESTART:
                observable = container is not None and container.observable
                value = container.restart_policy if container is not None else None
                disabled = observable and value == policy.disabled_value
            elif policy.kind is PolicyKind.SUPERVISOR:
                observable = supervisor is not None and supervisor.observable
                value = supervisor.unit_file_state if supervisor is not None else None
                disabled = False
                if observable and supervisor is not None:
                    if supervisor.manager == "systemd":
                        # A persistent mask is the required decommission
                        # boundary. `disabled` is only the first half of the
                        # disable->mask sequence, and a runtime-only mask would
                        # disappear on reboot.
                        disabled = (
                            supervisor.enabled is False
                            and supervisor.unit_file_state == "masked"
                        )
                    elif supervisor.manager == "launchd":
                        disabled = supervisor.enabled is False
                    if disabled:
                        value = policy.disabled_value
            else:
                # These are enforced by the durable repository/resource fence,
                # which always precedes host observation.
                observable = True
                value = policy.disabled_value
                disabled = True
            result[policy.policy_id] = PolicyObservation(
                policy.policy_id,
                policy.immutable_fingerprint,
                observable,
                disabled,
                value,
                docker_restart_policy=(
                    container.restart_policy
                    if policy.kind is PolicyKind.DOCKER_RESTART and container is not None
                    else None
                ),
                supervisor_manager=(
                    supervisor.manager
                    if policy.kind is PolicyKind.SUPERVISOR and supervisor is not None
                    else None
                ),
                supervisor_unit_file_state=(
                    supervisor.unit_file_state
                    if policy.kind is PolicyKind.SUPERVISOR and supervisor is not None
                    else None
                ),
                supervisor_loaded=(
                    supervisor.loaded
                    if policy.kind is PolicyKind.SUPERVISOR and supervisor is not None
                    else None
                ),
                supervisor_enabled=(
                    supervisor.enabled
                    if policy.kind is PolicyKind.SUPERVISOR and supervisor is not None
                    else None
                ),
            )
        return result


class LocalHostLifecycleBackend:
    """Bounded local implementation using pidfds, Docker IDs, and exact units."""

    def __init__(
        self,
        *,
        docker_executable: str | None = None,
        command_timeout: float = 15.0,
        stop_timeout: float = 10.0,
    ) -> None:
        self.docker_executable = docker_executable or _resolve_executable(
            "docker",
            (
                "/usr/local/bin/docker",
                "/opt/homebrew/bin/docker",
                "/usr/bin/docker",
                "/Applications/Docker.app/Contents/Resources/bin/docker",
            ),
        )
        self.command_timeout = float(command_timeout)
        self.stop_timeout = float(stop_timeout)

    def observe_server(self, identity: Mapping[str, str]) -> ServerBoundary:
        raw_pid = identity.get("pid")
        expected_start = identity.get("process_start_time")
        listener_host = identity.get("listener_host")
        raw_port = identity.get("listener_port")
        if raw_pid is None:
            listener_observable, listener_pid = self._listener(
                listener_host, raw_port, None
            )
            return ServerBoundary(
                observable=listener_observable,
                identity_matches=listener_pid is None,
                running_state=RunningState.STOPPED,
                listener_observable=listener_observable,
                listener_active=listener_pid is not None if listener_observable else None,
            )
        try:
            pid = int(raw_pid)
        except ValueError:
            return ServerBoundary(False, False, RunningState.UNKNOWN, False, None)
        exists, zombie, observed_start, observable = _process_identity(pid)
        if not observable:
            return ServerBoundary(False, False, RunningState.UNKNOWN, False, None)
        identity_matches = not exists or (
            expected_start is not None and observed_start == expected_start
        )
        listener_observable, listener_pid = self._listener(
            listener_host, raw_port, pid
        )
        if exists and listener_pid is not None and listener_pid != pid:
            identity_matches = False
        state = (
            RunningState.STOPPED
            if not exists
            else RunningState.ZOMBIE
            if zombie
            else RunningState.RUNNING
        )
        return ServerBoundary(
            observable=True,
            identity_matches=identity_matches,
            running_state=state,
            listener_observable=listener_observable,
            listener_active=(listener_pid is not None if listener_observable else None),
        )

    def stop_server(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        raw_pid = identity.get("pid")
        if raw_pid is None:
            return {"status": "already_stopped"}
        pid = int(raw_pid)
        expected_start = _require_native(identity, "process_start_time")
        exists, zombie, observed_start, observable = _process_identity(pid)
        if not observable:
            raise OwnershipError("process identity is unobservable")
        if not exists or zombie:
            return {"status": "already_stopped"}
        if observed_start != expected_start:
            raise PlanDriftError("PID was reused by another process")
        if sys.platform.startswith("linux"):
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise LifecycleError("safe Linux process stop requires pidfd signaling")
            descriptor = os.pidfd_open(pid, 0)
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                if not _wait_pidfd(descriptor, self.stop_timeout):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    if not _wait_pidfd(descriptor, min(2.0, self.stop_timeout)):
                        raise LifecycleError("exact process did not exit after SIGKILL")
            finally:
                os.close(descriptor)
        else:
            os.kill(pid, signal.SIGTERM)
            if not _wait_process(pid, expected_start, self.stop_timeout):
                exists, zombie, current_start, observable = _process_identity(pid)
                if not observable:
                    raise OwnershipError("process identity became unobservable before SIGKILL")
                if exists and not zombie:
                    if current_start != expected_start:
                        raise PlanDriftError("PID was reused before SIGKILL")
                    os.kill(pid, signal.SIGKILL)
                    if not _wait_process(pid, expected_start, min(2.0, self.stop_timeout)):
                        raise LifecycleError("exact process did not exit after SIGKILL")
        return {"status": "stopped", "pid": pid}

    def observe_container(self, full_container_id: str) -> ContainerBoundary:
        try:
            payload = self._docker_inspect(full_container_id)
        except LifecycleError:
            return ContainerBoundary(False, None, None, None)
        actual = str(payload.get("Id") or "").lower()
        running = (payload.get("State") or {}).get("Running")
        restart_config = (payload.get("HostConfig") or {}).get("RestartPolicy") or {}
        restart = restart_config.get("Name")
        maximum = restart_config.get("MaximumRetryCount")
        if restart == "on-failure" and maximum not in {None, 0, "0"}:
            restart = f"on-failure:{maximum}"
        return ContainerBoundary(
            True,
            actual or None,
            bool(running) if isinstance(running, bool) else None,
            str(restart or "no"),
        )

    def disable_container_restart(self, full_container_id: str) -> Mapping[str, Any]:
        before = self._docker_inspect(full_container_id)
        self._require_container_id(before, full_container_id)
        self._run((self._docker(), "update", "--restart=no", full_container_id))
        after = self._docker_inspect(full_container_id)
        self._require_container_id(after, full_container_id)
        policy = ((after.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name")
        if str(policy or "no") != "no":
            raise LifecycleError("Docker restart policy did not become 'no'")
        return {"restart_policy": "no", "container_id": full_container_id}

    def restore_container_restart(
        self, full_container_id: str, restart_policy: str
    ) -> Mapping[str, Any]:
        if not _valid_docker_restart_policy(restart_policy):
            raise LifecycleError("captured Docker restart policy is invalid")
        before = self._docker_inspect(full_container_id)
        self._require_container_id(before, full_container_id)
        self._run(
            (
                self._docker(),
                "update",
                "--restart",
                restart_policy,
                full_container_id,
            )
        )
        after = self._docker_inspect(full_container_id)
        self._require_container_id(after, full_container_id)
        raw = (after.get("HostConfig") or {}).get("RestartPolicy") or {}
        actual = str(raw.get("Name") or "no")
        maximum = raw.get("MaximumRetryCount")
        if actual == "on-failure" and maximum not in {None, 0, "0"}:
            actual = f"on-failure:{maximum}"
        if actual != restart_policy:
            raise LifecycleError("Docker restart policy did not match captured state")
        return {
            "restart_policy": actual,
            "container_id": full_container_id,
            "host_may_have_started": False,
        }

    def stop_container(self, full_container_id: str) -> Mapping[str, Any]:
        before = self._docker_inspect(full_container_id)
        self._require_container_id(before, full_container_id)
        if (before.get("State") or {}).get("Running") is not True:
            return {"status": "already_stopped", "container_id": full_container_id}
        self._run(
            (
                self._docker(),
                "stop",
                "--time",
                str(max(1, int(self.stop_timeout))),
                full_container_id,
            ),
            timeout=self.stop_timeout + 5,
        )
        after = self._docker_inspect(full_container_id)
        self._require_container_id(after, full_container_id)
        if (after.get("State") or {}).get("Running") is not False:
            raise LifecycleError("exact Docker container remains running")
        return {"status": "stopped", "container_id": full_container_id}

    def observe_supervisor(self, identity: Mapping[str, str]) -> SupervisorBoundary:
        manager = identity.get("manager")
        unit = identity.get("unit")
        if not manager or not unit:
            return SupervisorBoundary(False, False, None, None)
        if manager == "systemd":
            command = ["systemctl"]
            if identity.get("scope") == "user":
                command.append("--user")
            command.extend(
                [
                    "show",
                    unit,
                    "--no-pager",
                    "--property=Id",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=UnitFileState",
                ]
            )
            completed = self._run(tuple(command), allow=(0, 1, 3, 4))
            fields = _key_values(completed.stdout)
            observable = (
                completed.returncode in {0, 3}
                and bool(fields.get("Id"))
                and fields.get("LoadState") != "not-found"
            )
            return SupervisorBoundary(
                observable,
                fields.get("Id") == unit,
                fields.get("ActiveState") in {"active", "activating", "reloading"}
                if observable
                else None,
                fields.get("UnitFileState")
                not in {"disabled", "masked", "masked-runtime"}
                if observable
                else None,
                "systemd" if observable else None,
                fields.get("UnitFileState") if observable else None,
                fields.get("LoadState") == "loaded" if observable else None,
            )
        if manager == "launchd":
            target = _launchd_target(identity)
            completed = self._run(("launchctl", "print", target), allow=(0, 3, 64, 113))
            loaded = completed.returncode == 0
            active = _launchd_active(completed.stdout) if loaded else False
            disabled = self._launchd_disabled(identity)
            return SupervisorBoundary(
                disabled is not None and active is not None,
                True,
                active if disabled is not None else None,
                not disabled if disabled is not None else None,
                "launchd" if disabled is not None else None,
                ("disabled" if disabled else "enabled")
                if disabled is not None
                else None,
                loaded if disabled is not None else None,
            )
        return SupervisorBoundary(False, False, None, None)

    def disable_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        manager = _require_native(identity, "manager")
        unit = _require_native(identity, "unit")
        if manager == "systemd":
            command = ["systemctl"]
            if identity.get("scope") == "user":
                command.append("--user")
            command.extend(["disable", unit])
            self._run(tuple(command), allow=(0, 1))
            mask = ["systemctl"]
            if identity.get("scope") == "user":
                mask.append("--user")
            mask.extend(["mask", unit])
            self._run(tuple(mask))
        elif manager == "launchd":
            self._run(("launchctl", "disable", _launchd_target(identity)))
        else:
            raise LifecycleError(f"unsupported supervisor manager {manager}")
        observed = self.observe_supervisor(identity)
        if (
            not observed.observable
            or observed.enabled is not False
            or (
                manager == "systemd"
                and observed.unit_file_state != "masked"
            )
        ):
            raise LifecycleError("supervisor policy did not become disabled")
        return {"manager": manager, "unit": unit, "enabled": False}

    def restore_supervisor(
        self,
        identity: Mapping[str, str],
        captured: CapturedStartupPolicyState,
    ) -> Mapping[str, Any]:
        manager = _require_native(identity, "manager")
        unit = _require_native(identity, "unit")
        if captured.supervisor_manager != manager:
            raise PlanDriftError("captured supervisor manager changed")
        host_may_have_started = False
        if manager == "systemd":
            expected = captured.supervisor_unit_file_state
            if expected not in _RESTORABLE_SYSTEMD_UNIT_FILE_STATES:
                raise LifecycleError(
                    f"captured systemd unit state {expected!r} cannot be restored exactly"
                )
            if captured.captured_value != expected:
                raise LifecycleError(
                    "captured systemd policy value does not match its unit-file state"
                )
            if (
                expected in {"disabled", "masked-runtime"}
                and captured.supervisor_enabled is not False
            ):
                raise LifecycleError(
                    "captured disabled systemd policy has inconsistent enabled state"
                )
            if (
                expected not in {"disabled", "masked-runtime"}
                and captured.supervisor_enabled is not True
            ):
                raise LifecycleError("supervisor restore was not captured as enabled")
            prefix = ["systemctl"]
            if identity.get("scope") == "user":
                prefix.append("--user")
            self._run(tuple([*prefix, "unmask", unit]), allow=(0, 1))
            if expected == "disabled":
                pass
            elif expected == "masked-runtime":
                self._run(tuple([*prefix, "mask", "--runtime", unit]))
            elif expected == "enabled":
                self._run(tuple([*prefix, "enable", unit]))
            elif expected == "enabled-runtime":
                self._run(tuple([*prefix, "enable", "--runtime", unit]))
        elif manager == "launchd":
            if (
                captured.supervisor_enabled is not True
                or captured.supervisor_unit_file_state != "enabled"
                or captured.captured_value != "enabled"
                or type(captured.supervisor_loaded) is not bool
            ):
                raise LifecycleError(
                    "captured launchd policy state is incomplete or inconsistent"
                )
            target = _launchd_target(identity)
            self._run(("launchctl", "enable", target))
        else:
            raise LifecycleError(f"unsupported supervisor manager {manager}")
        observed = self.observe_supervisor(identity)
        if (
            not observed.observable
            or not observed.identity_matches
            or observed.enabled is not captured.supervisor_enabled
            or observed.unit_file_state != captured.supervisor_unit_file_state
        ):
            raise LifecycleError("supervisor policy did not match exact captured state")
        return {
            "manager": manager,
            "unit": unit,
            "unit_file_state": observed.unit_file_state,
            "loaded": observed.loaded,
            "enabled": observed.enabled,
            "host_may_have_started": host_may_have_started,
        }

    @staticmethod
    def _verified_launchd_plist(identity: Mapping[str, str]) -> str:
        raw_path = _require_native(identity, "plist_path")
        expected_sha256 = _require_native(identity, "plist_sha256").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise OwnershipError("launchd plist provenance has an invalid SHA-256")
        path = Path(raw_path)
        if not path.is_absolute():
            raise OwnershipError("launchd plist path is not absolute")
        current = path
        while True:
            try:
                metadata = current.lstat()
            except OSError as error:
                raise OwnershipError("launchd plist provenance is unobservable") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise OwnershipError("launchd plist path contains a symbolic link")
            if current.parent == current:
                break
            current = current.parent
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise OwnershipError("launchd plist cannot be opened exactly") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OwnershipError("launchd plist is not a regular file")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != expected_sha256:
            raise PlanDriftError("launchd plist content changed after policy capture")
        return str(path)

    def stop_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        manager = _require_native(identity, "manager")
        unit = _require_native(identity, "unit")
        if manager == "systemd":
            command = ["systemctl"]
            if identity.get("scope") == "user":
                command.append("--user")
            command.extend(["stop", unit])
            self._run(tuple(command))
        elif manager == "launchd":
            completed = self._run(
                ("launchctl", "kill", "SIGTERM", _launchd_target(identity)),
                allow=(0, 3, 64, 113),
            )
            if completed.returncode not in {0, 3, 113}:
                raise LifecycleError("launchd job could not be stopped")
        else:
            raise LifecycleError(f"unsupported supervisor manager {manager}")
        deadline = time.monotonic() + self.stop_timeout
        while time.monotonic() < deadline:
            observed = self.observe_supervisor(identity)
            if observed.observable and observed.active is False:
                return {"manager": manager, "unit": unit, "status": "stopped"}
            time.sleep(0.05)
        raise LifecycleError("exact supervisor unit remains active")

    def _docker(self) -> str:
        if not self.docker_executable:
            raise LifecycleError("Docker CLI is unavailable")
        return self.docker_executable

    def _docker_inspect(self, full_container_id: str) -> Mapping[str, Any]:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", full_container_id):
            raise PlanDriftError("Docker lifecycle requires an immutable full container ID")
        completed = self._run(
            (self._docker(), "inspect", "--format", "{{json .}}", full_container_id)
        )
        try:
            payload = json.loads(completed.stdout.strip())
        except (json.JSONDecodeError, TypeError) as error:
            raise LifecycleError("Docker inspect returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise LifecycleError("Docker inspect did not return one container object")
        return payload

    @staticmethod
    def _require_container_id(payload: Mapping[str, Any], expected: str) -> None:
        actual = str(payload.get("Id") or "")
        if actual.lower() != expected.lower():
            raise PlanDriftError("Docker immutable container ID changed")

    def _listener(
        self,
        host: str | None,
        raw_port: str | None,
        expected_pid: int | None,
    ) -> tuple[bool, int | None]:
        if raw_port is None:
            return True, None
        try:
            port = int(raw_port)
        except ValueError:
            return False, None
        if sys.platform.startswith("linux") and Path("/proc/net/tcp").exists():
            proc_result = _linux_listener_observation(
                str(host or "127.0.0.1"), port, expected_pid
            )
            if proc_result is not None:
                return proc_result
        command = ["lsof", "-nP", "-a"]
        # Query the endpoint globally. Filtering by the retained PID would miss
        # a foreign replacement listener after the exact process exits.
        command.extend([f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"])
        try:
            completed = self._run(tuple(command), timeout=3, allow=(0, 1))
        except LifecycleError:
            return False, None
        if completed.returncode == 1 and completed.stderr.strip():
            return False, None
        for line in completed.stdout.splitlines():
            if line.startswith("p") and line[1:].isdigit():
                return True, int(line[1:])
        return True, None

    def _launchd_disabled(self, identity: Mapping[str, str]) -> bool | None:
        domain = identity.get("domain")
        unit = identity.get("unit")
        if not domain or not unit:
            return None
        completed = self._run(("launchctl", "print-disabled", domain), allow=(0, 64, 113))
        if completed.returncode != 0:
            return None
        pattern = re.compile(rf'"{re.escape(unit)}"\s*=>\s*(true|false)')
        match = pattern.search(completed.stdout)
        return match.group(1) == "true" if match else False

    def _run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        allow: Sequence[int] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout or self.command_timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LifecycleError(f"host command failed: {argv[0]}: {error}") from error
        if completed.returncode not in set(allow):
            detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
            raise LifecycleError(
                f"host command {argv[0]} returned {completed.returncode}: {detail}"
            )
        return completed


def _native(target: ExactResourceRef) -> dict[str, str]:
    return {str(key): str(value) for key, value in target.native_identity}


def _require_native(identity: Mapping[str, str], key: str) -> str:
    value = str(identity.get(key) or "").strip()
    if not value:
        raise OwnershipError(f"exact host identity is missing {key}")
    return value


def _observed_identity(value: str | None) -> str:
    return f"observed:{value}" if value else "observed:unavailable"


def _valid_docker_restart_policy(value: str) -> bool:
    return bool(
        re.fullmatch(r"(?:always|unless-stopped|on-failure(?::[1-9][0-9]*)?)", value)
    )


def _resolve_executable(name: str, fallbacks: Sequence[str]) -> str | None:
    discovered = shutil.which(name)
    if discovered:
        return discovered
    for candidate in fallbacks:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _process_identity(pid: int) -> tuple[bool, bool, str | None, bool]:
    if sys.platform.startswith("linux"):
        try:
            text = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            return False, False, None, True
        except OSError:
            return False, False, None, False
        prefix, separator, suffix = text.rpartition(") ")
        fields = suffix.split() if separator else []
        if len(fields) < 20:
            return False, False, None, False
        state = fields[0]
        # /proc/PID/stat field 22; suffix starts at field 3.
        start_ticks = fields[19]
        return True, state in {"Z", "X"}, start_ticks, True
    try:
        completed = subprocess.run(
            ["ps", "-o", "stat=", "-o", "lstart=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, False, None, False
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines and completed.returncode in {0, 1} and not completed.stderr.strip():
        return False, False, None, True
    if not lines:
        return False, False, None, False
    state, _, started = lines[0].partition(" ")
    return True, state[0].upper() in {"Z", "X"}, started.strip(), True


def _linux_listener_observation(
    host: str, port: int, expected_pid: int | None
) -> tuple[bool, int | None] | None:
    """Observe one Linux endpoint without converting procfs denial to no-match.

    ``-1`` is an internal sentinel meaning a listener exists but is not owned
    by the expected process.  Callers use only equality/active checks and never
    pass the sentinel to a signal path.
    """

    requested = _host_addresses(host)
    listener_inodes: set[str] = set()
    readable = False
    for path, ipv6 in ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True)):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
            readable = True
        except FileNotFoundError:
            continue
        except OSError:
            return None
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            address_hex, separator, port_hex = fields[1].rpartition(":")
            if not separator:
                continue
            try:
                local_port = int(port_hex, 16)
                listener_address = _decode_proc_address(address_hex, ipv6=ipv6)
            except (ValueError, OSError):
                continue
            if local_port == port and _endpoint_address_matches(
                requested, listener_address
            ):
                listener_inodes.add(fields[9])
    if not readable:
        return None
    if not listener_inodes:
        return True, None
    if expected_pid is None:
        return True, -1
    fd_root = Path("/proc") / str(expected_pid) / "fd"
    try:
        entries = list(os.scandir(fd_root))
    except FileNotFoundError:
        return True, -1
    except PermissionError:
        return False, None
    except OSError:
        return False, None
    denied = False
    targets = {f"socket:[{inode}]" for inode in listener_inodes}
    for entry in entries:
        try:
            destination = os.readlink(entry.path)
        except PermissionError:
            denied = True
            continue
        except OSError:
            continue
        if destination in targets:
            return True, expected_pid
    if denied:
        return False, None
    return True, -1


def _decode_proc_address(value: str, *, ipv6: bool) -> str:
    payload = bytes.fromhex(value)
    if ipv6:
        payload = b"".join(
            payload[offset : offset + 4][::-1] for offset in range(0, 16, 4)
        )
        return socket.inet_ntop(socket.AF_INET6, payload)
    return socket.inet_ntop(socket.AF_INET, payload[::-1])


def _host_addresses(host: str) -> set[str]:
    candidate = str(host or "127.0.0.1").strip().strip("[]")
    if candidate in {"0.0.0.0", "::", "*"}:
        return {"*"}
    if candidate.lower() == "localhost":
        return {"127.0.0.1", "::1"}
    addresses: set[str] = set()
    try:
        socket.inet_pton(socket.AF_INET, candidate)
        return {candidate}
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, candidate)
        return {candidate}
    except OSError:
        pass
    try:
        for result in socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM):
            addresses.add(result[4][0])
    except OSError:
        return set()
    return addresses


def _endpoint_address_matches(requested: set[str], listener: str) -> bool:
    if not requested:
        return False
    if "*" in requested:
        return True
    try:
        socket.inet_pton(
            socket.AF_INET6 if ":" in listener else socket.AF_INET, listener
        )
    except OSError:
        return False
    if listener in {"0.0.0.0", "::"}:
        family_is_v6 = ":" in listener
        return any((":" in item) == family_is_v6 for item in requested)
    return listener in requested


def _wait_pidfd(descriptor: int, timeout: float) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    return bool(poller.poll(max(1, int(timeout * 1000))))


def _wait_process(pid: int, expected_start: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exists, zombie, current_start, observable = _process_identity(pid)
        if observable and (not exists or zombie):
            return True
        if observable and current_start != expected_start:
            return True
        time.sleep(0.05)
    return False


def _key_values(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in value.splitlines():
        key, separator, item = line.partition("=")
        if separator:
            result[key.strip()] = item.strip()
    return result


def _launchd_active(value: str) -> bool | None:
    match = re.search(r"(?m)^\s*state\s*=\s*([A-Za-z_-]+)\s*$", value)
    if match is None:
        return None
    return match.group(1).lower() in {"running", "spawned"}


def _launchd_target(identity: Mapping[str, str]) -> str:
    domain = _require_native(identity, "domain")
    unit = _require_native(identity, "unit")
    return f"{domain}/{unit}"


__all__ = [
    "ContainerBoundary",
    "CoordinatorHostLifecycleAdapter",
    "LocalHostLifecycleBackend",
    "NativeLifecycleBackend",
    "ServerBoundary",
    "SupervisorBoundary",
]
