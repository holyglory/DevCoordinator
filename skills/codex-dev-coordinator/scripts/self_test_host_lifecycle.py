#!/usr/bin/env python3
"""Exact-ID and policy-boundary tests for the production host adapter."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from devcoordinator.host_lifecycle import (  # noqa: E402
    ContainerBoundary,
    CoordinatorHostLifecycleAdapter,
    LocalHostLifecycleBackend,
    ServerBoundary,
    SupervisorBoundary,
)
from devcoordinator.repository_lifecycle import (  # noqa: E402
    CapturedStartupPolicyState,
    ExactResourceRef,
    OwnershipError,
    PlanDriftError,
    PolicyKind,
    ResourceKind,
    RunningState,
    StartupPolicyRef,
)


CONTAINER_ID = "d" * 64


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeNativeBackend:
    def __init__(self) -> None:
        self.container = ContainerBoundary(True, CONTAINER_ID, True, "always")
        self.server = ServerBoundary(True, True, RunningState.RUNNING, True, True)
        self.supervisor = SupervisorBoundary(True, True, True, True)
        self.calls: list[str] = []

    def observe_server(self, identity: Mapping[str, str]) -> ServerBoundary:
        self.calls.append(f"observe-server:{identity.get('server_definition_id')}")
        return self.server

    def stop_server(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        self.calls.append(f"stop-server:{identity.get('server_definition_id')}")
        self.server = ServerBoundary(True, True, RunningState.STOPPED, True, False)
        return {"stopped": True}

    def observe_container(self, full_container_id: str) -> ContainerBoundary:
        self.calls.append(f"observe-container:{full_container_id}")
        return self.container

    def disable_container_restart(self, full_container_id: str) -> Mapping[str, Any]:
        self.calls.append(f"disable-container:{full_container_id}")
        self.container = ContainerBoundary(
            True, self.container.full_container_id, self.container.running, "no"
        )
        return {"restart_policy": "no"}

    def restore_container_restart(
        self, full_container_id: str, restart_policy: str
    ) -> Mapping[str, Any]:
        self.calls.append(f"restore-container:{full_container_id}:{restart_policy}")
        self.container = ContainerBoundary(
            True, self.container.full_container_id, self.container.running, restart_policy
        )
        return {"restart_policy": restart_policy}

    def stop_container(self, full_container_id: str) -> Mapping[str, Any]:
        self.calls.append(f"stop-container:{full_container_id}")
        self.container = ContainerBoundary(
            True, self.container.full_container_id, False, self.container.restart_policy
        )
        return {"stopped": True}

    def observe_supervisor(self, identity: Mapping[str, str]) -> SupervisorBoundary:
        self.calls.append(f"observe-supervisor:{identity.get('unit')}")
        return self.supervisor

    def disable_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        self.calls.append(f"disable-supervisor:{identity.get('unit')}")
        self.supervisor = SupervisorBoundary(
            True, True, self.supervisor.active, False
        )
        return {"enabled": False}

    def restore_supervisor(
        self, identity: Mapping[str, str], captured: CapturedStartupPolicyState
    ) -> Mapping[str, Any]:
        self.calls.append(f"restore-supervisor:{identity.get('unit')}")
        self.supervisor = SupervisorBoundary(
            True,
            True,
            self.supervisor.active,
            captured.supervisor_enabled,
            captured.supervisor_manager,
            captured.supervisor_unit_file_state,
            captured.supervisor_loaded,
        )
        return {"enabled": captured.supervisor_enabled}

    def stop_supervisor(self, identity: Mapping[str, str]) -> Mapping[str, Any]:
        self.calls.append(f"stop-supervisor:{identity.get('unit')}")
        self.supervisor = SupervisorBoundary(True, True, False, False)
        return {"stopped": True}


def container_target(full_id: str = CONTAINER_ID) -> ExactResourceRef:
    policy = StartupPolicyRef(
        "policy-container", PolicyKind.DOCKER_RESTART, "policy-fp", "no"
    )
    return ExactResourceRef(
        "docker-resource",
        ResourceKind.CONTAINER,
        "membership-fp",
        "binding-container",
        "ownership-container",
        (policy,),
        (),
        (("full_container_id", full_id),),
    )


def test_container_uses_full_immutable_id_and_verifies_restart_policy() -> None:
    backend = FakeNativeBackend()
    adapter = CoordinatorHostLifecycleAdapter(backend)
    target = container_target()
    before = adapter.observe_exact(target)
    policy = before.policies["policy-container"]
    expect(policy.disabled is False and policy.value == "always", "restart=always was missed")
    adapter.disable_startup_policy(target, target.policies[0])
    after_policy = adapter.observe_exact(target)
    expect(after_policy.policies["policy-container"].disabled is True, "restart=no not verified")
    adapter.stop_exact(target)
    after_stop = adapter.observe_exact(target)
    expect(after_stop.container_running is False, "container stopped boundary was missed")
    mutations = [item for item in backend.calls if item.startswith(("disable-", "stop-"))]
    expect(
        mutations == [
            f"disable-container:{CONTAINER_ID}",
            f"stop-container:{CONTAINER_ID}",
        ],
        f"adapter did not use exact full container ID: {mutations}",
    )


def test_container_recreation_and_unknown_observer_fail_closed() -> None:
    backend = FakeNativeBackend()
    backend.container = ContainerBoundary(True, "e" * 64, True, "always")
    observation = CoordinatorHostLifecycleAdapter(backend).observe_exact(container_target())
    expect(not observation.ownership_observable, "replacement container retained ownership")
    expect(
        observation.replacement_fingerprint == f"observed:{'e' * 64}",
        "replacement immutable ID was not exposed",
    )
    backend.container = ContainerBoundary(False, None, None, None)
    observation = CoordinatorHostLifecycleAdapter(backend).observe_exact(container_target())
    expect(not observation.identity_observable, "unobservable Docker became stopped")
    expect(observation.running_state is RunningState.UNKNOWN, "unknown Docker became stopped")


def test_server_supervisor_policy_is_observed_and_disabled_before_stop() -> None:
    backend = FakeNativeBackend()
    adapter = CoordinatorHostLifecycleAdapter(backend)
    policy = StartupPolicyRef(
        "policy-unit", PolicyKind.SUPERVISOR, "policy-unit-fp", "disabled"
    )
    target = ExactResourceRef(
        "server-def",
        ResourceKind.SERVER,
        "server-fp",
        "binding-server",
        "ownership-server",
        (policy,),
        (),
        (
            ("server_definition_id", "server-def"),
            ("manager", "systemd"),
            ("unit", "example.service"),
        ),
    )
    before = adapter.observe_exact(target)
    expect(before.policies[policy.policy_id].disabled is False, "enabled supervisor was missed")
    adapter.disable_startup_policy(target, policy)
    expect(
        adapter.observe_exact(target).policies[policy.policy_id].disabled is True,
        "disabled supervisor was not verified",
    )
    adapter.stop_exact(target)
    expect(adapter.observe_exact(target).running_state is RunningState.STOPPED, "server remains running")
    disable_index = backend.calls.index("disable-supervisor:example.service")
    stop_index = backend.calls.index("stop-server:server-def")
    expect(disable_index < stop_index, "supervisor was stopped before autostart was disabled")


def test_server_identity_mismatch_and_unknown_are_not_actionable() -> None:
    backend = FakeNativeBackend()
    target = ExactResourceRef(
        "server-def",
        ResourceKind.SERVER,
        "server-fp",
        "binding-server",
        "ownership-server",
        (),
        (),
        (("server_definition_id", "server-def"),),
    )
    backend.server = ServerBoundary(True, False, RunningState.RUNNING, True, True)
    observed = CoordinatorHostLifecycleAdapter(backend).observe_exact(target)
    expect(not observed.ownership_observable, "PID mismatch retained ownership")
    backend.server = ServerBoundary(False, False, RunningState.UNKNOWN, False, None)
    observed = CoordinatorHostLifecycleAdapter(backend).observe_exact(target)
    expect(not observed.identity_observable, "unknown process was actionable")


class ScriptedDockerBackend(LocalHostLifecycleBackend):
    def __init__(self) -> None:
        super().__init__(docker_executable="/exact/docker", command_timeout=1, stop_timeout=1)
        self.running = True
        self.restart = "always"
        self.commands: list[tuple[str, ...]] = []

    def _run(
        self,
        argv: Any,
        *,
        timeout: float | None = None,
        allow: Any = (0,),
    ) -> subprocess.CompletedProcess[str]:
        del timeout, allow
        command = tuple(argv)
        self.commands.append(command)
        if "inspect" in command:
            payload = {
                "Id": CONTAINER_ID,
                "State": {"Running": self.running},
                "HostConfig": {"RestartPolicy": {"Name": self.restart}},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if "update" in command:
            if "--restart" in command:
                self.restart = command[command.index("--restart") + 1]
            else:
                self.restart = next(
                    value.split("=", 1)[1]
                    for value in command
                    if value.startswith("--restart=")
                )
        if "stop" in command:
            self.running = False
        return subprocess.CompletedProcess(command, 0, "", "")


class ScriptedSystemdBackend(LocalHostLifecycleBackend):
    def __init__(self) -> None:
        super().__init__(docker_executable="/exact/docker", command_timeout=1, stop_timeout=1)
        self.active = True
        self.unit_state = "enabled"
        self.commands: list[tuple[str, ...]] = []

    def _run(
        self,
        argv: Any,
        *,
        timeout: float | None = None,
        allow: Any = (0,),
    ) -> subprocess.CompletedProcess[str]:
        del timeout, allow
        command = tuple(argv)
        self.commands.append(command)
        if "show" in command:
            payload = (
                "Id=example.service\n"
                "LoadState=loaded\n"
                f"ActiveState={'active' if self.active else 'inactive'}\n"
                f"UnitFileState={self.unit_state}\n"
            )
            return subprocess.CompletedProcess(command, 0, payload, "")
        if "disable" in command:
            self.unit_state = "disabled"
        if "unmask" in command:
            self.unit_state = "disabled"
        if "enable" in command:
            self.unit_state = "enabled-runtime" if "--runtime" in command else "enabled"
        if "mask" in command:
            self.unit_state = "masked"
        if "stop" in command:
            self.active = False
        return subprocess.CompletedProcess(command, 0, "", "")


class ScriptedLaunchdBackend(LocalHostLifecycleBackend):
    def __init__(self) -> None:
        super().__init__(docker_executable="/exact/docker", command_timeout=1, stop_timeout=1)
        self.disabled = False
        self.loaded = True
        self.active = True
        self.commands: list[tuple[str, ...]] = []

    @staticmethod
    def _verified_launchd_plist(identity: Mapping[str, str]) -> str:
        if identity.get("plist_sha256") != "f" * 64:
            raise AssertionError("test launchd plist provenance was not exact")
        return str(identity["plist_path"])

    def _run(
        self,
        argv: Any,
        *,
        timeout: float | None = None,
        allow: Any = (0,),
    ) -> subprocess.CompletedProcess[str]:
        del timeout, allow
        command = tuple(argv)
        self.commands.append(command)
        if "print-disabled" in command:
            value = "true" if self.disabled else "false"
            return subprocess.CompletedProcess(
                command, 0, f'{{\n  "com.example.app" => {value}\n}}\n', ""
            )
        if "print" in command:
            if not self.loaded:
                return subprocess.CompletedProcess(command, 113, "", "not found")
            state = "running" if self.active else "exited"
            return subprocess.CompletedProcess(command, 0, f"state = {state}\n", "")
        if "disable" in command:
            self.disabled = True
        if "enable" in command:
            self.disabled = False
        if "kill" in command:
            self.active = False
        if "bootstrap" in command:
            self.loaded = True
            self.active = True
        return subprocess.CompletedProcess(command, 0, "", "")


def test_local_docker_backend_never_falls_back_to_name_or_short_alias() -> None:
    backend = ScriptedDockerBackend()
    backend.disable_container_restart(CONTAINER_ID)
    backend.stop_container(CONTAINER_ID)
    expect(
        all(command[-1] == CONTAINER_ID for command in backend.commands),
        f"Docker command lost immutable ID: {backend.commands}",
    )
    command_count = len(backend.commands)
    try:
        backend.stop_container("friendly-container-name")
    except PlanDriftError:
        pass
    else:
        raise AssertionError("Docker backend accepted a display name")
    expect(len(backend.commands) == command_count, "invalid Docker alias reached the CLI")
    try:
        backend.stop_container(CONTAINER_ID[:12])
    except PlanDriftError:
        pass
    else:
        raise AssertionError("Docker backend accepted a short mutable alias")
    expect(len(backend.commands) == command_count, "short Docker alias reached the CLI")


def test_local_docker_backend_restores_exact_captured_restart_policy_without_start() -> None:
    backend = ScriptedDockerBackend()
    backend.disable_container_restart(CONTAINER_ID)
    backend.restore_container_restart(CONTAINER_ID, "unless-stopped")
    expect(backend.restart == "unless-stopped", backend.restart)
    mutations = [command for command in backend.commands if "update" in command]
    expect(
        mutations[-1]
        == ("/exact/docker", "update", "--restart", "unless-stopped", CONTAINER_ID),
        mutations,
    )
    expect(not any("start" in command for command in backend.commands), backend.commands)


def test_local_systemd_backend_disables_and_masks_before_stop() -> None:
    backend = ScriptedSystemdBackend()
    identity = {"manager": "systemd", "scope": "user", "unit": "example.service"}
    backend.disable_supervisor(identity)
    backend.stop_supervisor(identity)
    mutations = [
        command
        for command in backend.commands
        if "disable" in command or "mask" in command or "stop" in command
    ]
    expect(
        [next(value for value in ("disable", "mask", "stop") if value in command) for command in mutations]
        == ["disable", "mask", "stop"],
        f"systemd policy/stop ordering is unsafe: {mutations}",
    )
    expect(all("example.service" in command for command in mutations), "wrong systemd unit")


def test_local_systemd_backend_restores_only_exact_captured_unit_file_state() -> None:
    backend = ScriptedSystemdBackend()
    identity = {"manager": "systemd", "scope": "user", "unit": "example.service"}
    backend.disable_supervisor(identity)
    backend.stop_supervisor(identity)
    captured = CapturedStartupPolicyState(
        "policy-unit",
        "repo",
        ResourceKind.SUPERVISOR,
        "example.service",
        PolicyKind.SUPERVISOR,
        "policy-fp",
        "target-fp",
        "binding",
        "ownership",
        "native-fp",
        "enabled",
        True,
        "captured",
        supervisor_manager="systemd",
        supervisor_unit_file_state="enabled",
        supervisor_loaded=True,
        supervisor_enabled=True,
    )
    result = backend.restore_supervisor(identity, captured)
    expect(result["unit_file_state"] == "enabled", result)
    mutations = [
        command
        for command in backend.commands
        if any(value in command for value in ("unmask", "enable", "start"))
    ]
    expect(
        [next(value for value in ("unmask", "enable") if value in command) for command in mutations]
        == ["unmask", "enable"],
        mutations,
    )
    expect(not any("start" in command for command in mutations), mutations)
    unsupported = replace(captured, supervisor_unit_file_state="linked")
    count = len(backend.commands)
    try:
        backend.restore_supervisor(identity, unsupported)
    except Exception as error:
        expect("cannot be restored exactly" in str(error), error)
    else:
        raise AssertionError("unsupported systemd state was guessed")
    expect(len(backend.commands) == count, "unknown systemd state reached host mutation")


def test_local_launchd_backend_restores_captured_enable_and_loaded_state() -> None:
    backend = ScriptedLaunchdBackend()
    identity = {
        "manager": "launchd",
        "domain": "gui/501",
        "unit": "com.example.app",
        "plist_path": "/exact/com.example.app.plist",
        "plist_sha256": "f" * 64,
    }
    observed = backend.observe_supervisor(identity)
    expect(observed.enabled is True and observed.loaded is True and observed.active is True, observed)
    backend.disable_supervisor(identity)
    backend.stop_supervisor(identity)
    captured = CapturedStartupPolicyState(
        "policy-launchd",
        "repo",
        ResourceKind.SUPERVISOR,
        "com.example.app",
        PolicyKind.SUPERVISOR,
        "policy-fp",
        "target-fp",
        "binding",
        "ownership",
        "native-fp",
        "enabled",
        True,
        "captured",
        supervisor_manager="launchd",
        supervisor_unit_file_state="enabled",
        supervisor_loaded=True,
        supervisor_enabled=True,
    )
    result = backend.restore_supervisor(identity, captured)
    expect(result["enabled"] is True and result["loaded"] is True, result)
    expect(result["host_may_have_started"] is False, result)
    expect(not any("bootstrap" in command for command in backend.commands), backend.commands)
    backend.disable_supervisor(identity)
    backend.active = False
    backend.loaded = False
    result = backend.restore_supervisor(identity, captured)
    expect(result["host_may_have_started"] is True, result)
    bootstrap = [command for command in backend.commands if "bootstrap" in command]
    expect(
        bootstrap[-1]
        == (
            "launchctl",
            "bootstrap",
            "gui/501",
            "/exact/com.example.app.plist",
        ),
        bootstrap,
    )


def test_launchd_bootstrap_rejects_changed_or_symlinked_plist_provenance() -> None:
    with tempfile.TemporaryDirectory(prefix=".launchd-plist-", dir=Path.home()) as raw:
        root = Path(raw).resolve()
        plist = root / "job.plist"
        plist.write_text("exact plist", encoding="utf-8")
        identity = {
            "plist_path": str(plist),
            "plist_sha256": "0" * 64,
        }
        try:
            LocalHostLifecycleBackend._verified_launchd_plist(identity)
        except PlanDriftError:
            pass
        else:
            raise AssertionError("changed launchd plist passed immutable provenance")
        identity["plist_sha256"] = hashlib.sha256(plist.read_bytes()).hexdigest()
        expect(
            LocalHostLifecycleBackend._verified_launchd_plist(identity) == str(plist),
            identity,
        )
        alias = root / "alias.plist"
        alias.symlink_to(plist)
        identity["plist_path"] = str(alias)
        try:
            LocalHostLifecycleBackend._verified_launchd_plist(identity)
        except OwnershipError:
            pass
        else:
            raise AssertionError("symlinked launchd plist passed exact provenance")


def test_missing_native_identity_is_rejected_before_host_mutation() -> None:
    backend = FakeNativeBackend()
    adapter = CoordinatorHostLifecycleAdapter(backend)
    target = container_target("")
    try:
        adapter.stop_exact(target)
    except OwnershipError:
        pass
    else:
        raise AssertionError("container without a full ID reached the backend")
    expect(not backend.calls, "missing identity caused a host call")


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"host lifecycle self-test passed ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
