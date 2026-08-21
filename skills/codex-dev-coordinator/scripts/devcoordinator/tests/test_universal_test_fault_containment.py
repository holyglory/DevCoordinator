from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from devcoordinator.universal_test_result_package import RESULT_PACKAGE_FILE_NAME
from devcoordinator.universal_test_runtime import (
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)


SKILL_ROOT = Path(__file__).resolve().parents[3]
PACKAGED_DEPLOY = SKILL_ROOT / "references" / "fault-containment-systemd"
SOURCE_ROOT = SKILL_ROOT.parents[1]
SOURCE_SKILL = SOURCE_ROOT / "skills" / "codex-dev-coordinator"
FAULT_CONTAINMENT_UNITS = (
    "devcoordinator-edge.service",
    "devcoordinator-api.service",
    "devcoordinator-testd.service",
    "devcoordinator-control.slice",
    "devcoordinator-background.slice",
    "devcoordinator-projects.slice",
)


def _directives(path: Path, section: str) -> dict[str, list[str]]:
    current: str | None = None
    values: dict[str, list[str]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section and "=" in line:
            name, value = line.split("=", 1)
            values.setdefault(name, []).append(value)
    return values


class UniversalTestFaultContainmentTests(unittest.TestCase):
    def fault_containment_deploy(self) -> Path:
        """Return the explicit packaged unit contract and reject source drift."""

        for name in FAULT_CONTAINMENT_UNITS:
            packaged = PACKAGED_DEPLOY / name
            self.assertTrue(
                packaged.is_file() and not packaged.is_symlink(),
                f"packaged fault-containment unit is missing or unsafe: {packaged}",
            )

        # The standalone skill has no repository-level deploy directory.  In
        # the canonical source tree, require the packaged contract to remain
        # byte-identical to every production template so this test continues
        # to guard the architecture rather than validating a stale fixture.
        try:
            in_source_tree = SOURCE_SKILL.resolve(strict=True) == SKILL_ROOT
        except FileNotFoundError:
            in_source_tree = False
        if in_source_tree:
            source_deploy = SOURCE_ROOT / "deploy"
            for name in FAULT_CONTAINMENT_UNITS:
                source = source_deploy / name
                self.assertTrue(
                    source.is_file() and not source.is_symlink(),
                    f"production fault-containment unit is missing or unsafe: {source}",
                )
                self.assertEqual(
                    source.read_bytes(),
                    (PACKAGED_DEPLOY / name).read_bytes(),
                    f"packaged fault-containment contract drifted from deploy/{name}",
                )
        return PACKAGED_DEPLOY

    def descriptor(self, *, repository_id: str = "hostile-repo") -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            execution_id="execution-hostile-containment",
            target_id="target-hostile-containment",
            run_id="run-hostile-containment",
            repository_id=repository_id,
            repository_generation=1,
            owner_uid=os.geteuid(),
            generation=1,
            source_mode="live",
            snapshot_id=None,
            original_root="/home/example/hostile-repo",
            temporary_root=None,
            execution_root="/home/example/hostile-repo",
            worktree_key="/home/example/hostile-repo",
            target_name="hostile",
            shard_index=0,
            shard_count=1,
            argv=(
                "/usr/bin/python3",
                "-c",
                "import os;[(lambda:os.fork())() for _ in iter(int,1)]",
            ),
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="none",
            ttl_seconds=37,
        )

    def prepared_runtime(
        self,
        raw: str,
        *,
        runner,
        populated: bool,
    ) -> tuple[SystemdTestAttemptManager, str, Path]:
        """Publish the exact descriptor and native identity observed by status."""

        root = Path(raw)
        attempt_root = root / "attempts"
        cgroup_root = root / "cgroup"
        cgroup_root.mkdir(mode=0o700)
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=root / "artifacts",
            result_package_root=root / "result-packages",
            cgroup_root=cgroup_root,
            runner=runner,
        )
        descriptor = self.descriptor()
        runtime_id = manager._runtime_id(descriptor)
        state = attempt_root / runtime_id
        state.mkdir(parents=True, mode=0o700)
        launch_path, result_path = manager._publish_runner_launch(
            descriptor,
            state=state,
            execution_root=Path(descriptor.execution_root),
            owner_gid=os.getegid(),
        )
        self.assertEqual(launch_path, state / "launch.json")
        self.assertEqual(result_path, state / "output" / RESULT_PACKAGE_FILE_NAME)
        control_group = f"/tests.slice/{runtime_id}.service"
        manager._publish_native_evidence(
            runtime_id,
            descriptor,
            invocation_id="test-invocation-" + "1" * 32,
            prepared_at=1.0,
            started_at=2.0,
            control_group=control_group,
        )
        events = manager._control_group_path(control_group) / "cgroup.events"
        events.parent.mkdir(parents=True, mode=0o700)
        events.write_text(
            f"populated {1 if populated else 0}\n",
            encoding="ascii",
        )
        return manager, runtime_id, events

    def test_attempts_keep_ttl_and_isolation_without_resource_quotas(self) -> None:
        descriptor = self.descriptor()
        properties = set(
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=Path(descriptor.execution_root),
                output_root=Path("/var/lib/devcoordinator-test-runs/attempt/output"),
            )
        )
        self.assertIn("--property=KillMode=control-group", properties)
        self.assertIn("--property=RuntimeMaxSec=67s", properties)
        self.assertIn("--property=CPUAccounting=yes", properties)
        self.assertIn("--property=MemoryAccounting=yes", properties)
        self.assertFalse(any("CPUQuota=" in value for value in properties))
        self.assertFalse(any("MemoryMax=" in value for value in properties))
        self.assertFalse(any("TasksMax=" in value for value in properties))
        self.assertIn("--property=ProtectControlGroups=yes", properties)
        self.assertIn("--property=NoNewPrivileges=yes", properties)
        self.assertIn("--property=PrivateNetwork=yes", properties)
        self.assertIn("--property=IPAddressDeny=any", properties)
        self.assertTrue(
            any("docker.sock" in value for value in properties),
            "hostile tests retained direct container-daemon authority",
        )

        slice_name = SystemdTestAttemptManager._repository_slice(descriptor)
        self.assertTrue(slice_name.startswith("devcoordinator-tests-uid"))
        self.assertEqual(
            slice_name,
            SystemdTestAttemptManager._repository_slice(self.descriptor()),
        )
        self.assertNotEqual(
            slice_name,
            SystemdTestAttemptManager._repository_slice(
                self.descriptor(repository_id="unrelated-repo")
            ),
        )

    def test_terminal_systemd_evidence_distinguishes_timeout_oom_and_signal(self) -> None:
        scenarios = (
            ("timeout", "no", "1", "15", "timeout", False),
            ("oom-kill", "yes", "2", "9", "oom_kill", True),
            ("signal", "no", "2", "15", "signal", False),
        )
        for result, oom, code, status, reason, oom_killed in scenarios:
            with self.subTest(result=result, oom=oom):
                def runner(argv, **_kwargs):
                    self.assertIn("--property=Result", argv)
                    self.assertIn("--property=ExecMainCode", argv)
                    self.assertIn("--property=OOMKilled", argv)
                    self.assertIn("--property=CPUUsageNSec", argv)
                    self.assertIn("--property=MemoryPeak", argv)
                    self.assertIn("--property=MemoryCurrent", argv)
                    stdout = "\n".join((
                        "LoadState=loaded",
                        "ActiveState=failed",
                        "SubState=failed",
                        f"Result={result}",
                        f"ExecMainCode={code}",
                        f"ExecMainStatus={status}",
                        f"OOMKilled={oom}",
                        "CPUUsageNSec=1250000000",
                        "MemoryPeak=104857600",
                        "ActiveEnterTimestampMonotonic=1",
                        "InactiveEnterTimestampMonotonic=2",
                    ))
                    return subprocess.CompletedProcess(argv, 0, stdout, "")

                with tempfile.TemporaryDirectory(prefix="test-systemd-result-") as raw:
                    manager, runtime_id, _events = self.prepared_runtime(
                        raw,
                        runner=runner,
                        populated=False,
                    )
                    state = manager.status(runtime_id)
                self.assertFalse(state.active)
                self.assertEqual(state.systemd_result, result)
                self.assertEqual(state.exec_main_code, int(code))
                self.assertEqual(state.termination_reason, reason)
                self.assertEqual(state.oom_killed, oom_killed)
                self.assertEqual(state.cpu_seconds, 1.25)
                self.assertEqual(state.peak_memory_bytes, 104857600)

    def test_unavailable_systemd_usage_remains_null(self) -> None:
        def runner(argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=inactive",
                "SubState=dead",
                "Result=success",
                "ExecMainCode=1",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=[not set]",
                "MemoryPeak=[not set]",
            ))
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="test-systemd-usage-null-") as raw:
            manager, runtime_id, _events = self.prepared_runtime(
                raw,
                runner=runner,
                populated=False,
            )
            state = manager.status(runtime_id)
        self.assertIsNone(state.cpu_seconds)
        self.assertIsNone(state.peak_memory_bytes)

    def test_active_systemd_usage_reports_current_memory(self) -> None:
        def runner(argv, **_kwargs):
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=active",
                "SubState=running",
                "Result=success",
                "ExecMainCode=0",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=250000000",
                "MemoryPeak=134217728",
                "MemoryCurrent=100663296",
            ))
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="test-systemd-current-usage-") as raw:
            manager, runtime_id, _events = self.prepared_runtime(
                raw,
                runner=runner,
                populated=True,
            )
            state = manager.status(runtime_id)
        self.assertTrue(state.active)
        self.assertEqual(state.current_memory_bytes, 96 * 1024 * 1024)

    def test_starting_unit_without_terminal_properties_remains_observable(self) -> None:
        def runner(argv, **_kwargs):
            self.assertIn("--all", argv)
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=activating",
                "SubState=start",
                "CPUUsageNSec=[not set]",
                "MemoryPeak=[not set]",
                "MemoryCurrent=[not set]",
            ))
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="test-systemd-starting-") as raw:
            manager, runtime_id, _events = self.prepared_runtime(
                raw,
                runner=runner,
                populated=True,
            )
            state = manager.status(runtime_id)

        self.assertTrue(state.loaded)
        self.assertTrue(state.active)
        self.assertEqual(state.state, "running")
        self.assertIsNone(state.exit_status)
        self.assertIsNone(state.systemd_result)
        self.assertIsNone(state.termination_reason)

    def test_deactivating_unit_waits_for_runner_result_before_terminalizing(self) -> None:
        def runner(argv, **_kwargs):
            self.assertIn("--all", argv)
            stdout = "\n".join((
                "LoadState=loaded",
                "ActiveState=deactivating",
                "SubState=stop-sigterm",
                "Result=success",
                "ExecMainCode=0",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=250000000",
                "MemoryPeak=134217728",
                "MemoryCurrent=100663296",
            ))
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="test-systemd-deactivating-") as raw:
            manager, runtime_id, _events = self.prepared_runtime(
                raw,
                runner=runner,
                populated=True,
            )
            runtime_root = manager.attempt_root / runtime_id
            marker = runtime_root / "still-draining"
            marker.write_text("preserve", encoding="utf-8")
            state = manager.status(runtime_id)

            self.assertTrue(state.loaded)
            self.assertTrue(state.active)
            self.assertEqual(state.state, "running")
            self.assertIsNone(state.exit_status)
            self.assertIsNone(state.systemd_result)
            self.assertIsNone(state.termination_reason)
            self.assertEqual(state.current_memory_bytes, 96 * 1024 * 1024)
            self.assertTrue(marker.is_file())

    def test_cancellation_force_kills_only_the_exact_still_active_unit(self) -> None:
        calls: list[list[str]] = []
        observations = iter(("active", "inactive", "inactive"))

        def runner(argv, **_kwargs):
            calls.append(list(argv))
            if "show" not in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            active = next(observations)
            if active == "inactive":
                events.write_text("populated 0\n", encoding="ascii")
            stdout = "\n".join((
                "LoadState=loaded",
                f"ActiveState={active}",
                "SubState=running" if active == "active" else "SubState=dead",
                "Result=" if active == "active" else "Result=signal",
                "ExecMainCode=" if active == "active" else "ExecMainCode=2",
                "ExecMainStatus=" if active == "active" else "ExecMainStatus=9",
                "OOMKilled=no",
                "CPUUsageNSec=1000000",
                "MemoryPeak=1048576",
                "MemoryCurrent=0",
            ))
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="test-systemd-force-cancel-") as raw:
            manager, runtime_id, events = self.prepared_runtime(
                raw,
                runner=runner,
                populated=True,
            )
            state = manager.cancel(runtime_id)

        self.assertFalse(state.active)
        self.assertEqual(
            [call for call in calls if "kill" in call],
            [[
                manager.systemctl,
                "kill",
                "--kill-whom=all",
                "--signal=KILL",
                f"{runtime_id}.service",
            ]],
        )
        self.assertTrue(
            all(
                f"{runtime_id}.service" in call
                for call in calls
            )
        )

    def test_test_crash_loop_has_no_dependency_path_into_control_plane(self) -> None:
        deploy = self.fault_containment_deploy()
        edge = _directives(deploy / "devcoordinator-edge.service", "Service")
        api = _directives(deploy / "devcoordinator-api.service", "Service")
        testd = _directives(deploy / "devcoordinator-testd.service", "Service")

        self.assertEqual(edge["Slice"], ["devcoordinator-control.slice"])
        self.assertEqual(api["Slice"], ["devcoordinator-control.slice"])
        self.assertEqual(testd["Slice"], ["devcoordinator-background.slice"])
        self.assertEqual(testd["Restart"], ["always"])
        self.assertEqual(testd["RestartSec"], ["3"])
        self.assertEqual(testd["KillMode"], ["control-group"])
        self.assertEqual(testd["ProtectSystem"], ["full"])
        self.assertEqual(
            testd["ReadWritePaths"],
            ["/var/lib/devcoordinator-testd /run/devcoordinator-testd"],
        )
        edge_unit = _directives(deploy / "devcoordinator-edge.service", "Unit")
        api_unit = _directives(deploy / "devcoordinator-api.service", "Unit")
        testd_unit = _directives(deploy / "devcoordinator-testd.service", "Unit")
        control_dependencies = " ".join(
            value
            for unit in (edge_unit, api_unit)
            for values in unit.values()
            for value in values
        )
        background_dependencies = " ".join(
            value for values in testd_unit.values() for value in values
        )
        self.assertNotIn("devcoordinator-testd", control_dependencies)
        self.assertNotIn("devcoordinator-project", control_dependencies)
        self.assertNotIn("devcoordinator-edge", background_dependencies)
        self.assertNotIn("devcoordinator-api.service", background_dependencies)

        control_slice = _directives(
            deploy / "devcoordinator-control.slice", "Slice"
        )
        background_slice = _directives(
            deploy / "devcoordinator-background.slice", "Slice"
        )
        project_slice = _directives(
            deploy / "devcoordinator-projects.slice", "Slice"
        )
        self.assertEqual(control_slice["CPUWeight"], ["10000"])
        self.assertIn("MemoryLow", control_slice)
        self.assertEqual(background_slice["CPUWeight"], ["200"])
        self.assertIn("CPUQuota", background_slice)
        self.assertIn("MemoryMax", background_slice)
        self.assertIn("TasksMax", background_slice)
        self.assertEqual(project_slice["CPUWeight"], ["100"])
        self.assertIn("MemoryMax", project_slice)
        self.assertIn("TasksMax", project_slice)


if __name__ == "__main__":
    unittest.main()
