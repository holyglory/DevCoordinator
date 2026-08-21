from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from devcoordinator.universal_test_result_package import (
    RESULT_PACKAGE_FILE_NAME,
    ResultPackageArtifact,
    publish_result_package,
)
from devcoordinator.universal_test_runtime import (
    BrokerTestAttemptCoordinator,
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from devcoordinator.universal_test_store import TestStoreConflict


class UniversalTestRuntimeV8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.attempt_root = self.base / "attempts"
        self.artifact_root = self.base / "artifacts"
        self.package_root = self.base / "packages"
        self.cgroup_root = self.base / "cgroup"
        self.cgroup_root.mkdir(mode=0o700)
        self.descriptor = TestAttemptDescriptor(
            execution_id="execution-runtime-v8",
            target_id="target-runtime-v8",
            run_id="run-runtime-v8",
            repository_id="repo-runtime-v8",
            repository_generation=8,
            owner_uid=os.geteuid(),
            generation=3,
            source_mode="live",
            snapshot_id=None,
            original_root=str(self.repository),
            temporary_root=None,
            execution_root=str(self.repository),
            worktree_key=str(self.repository),
            target_name="runtime-v8",
            shard_index=0,
            shard_count=1,
            argv=("/usr/bin/python3", "-c", "pass"),
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="none",
            ttl_seconds=30,
        )
        self.runtime_id = SystemdTestAttemptManager._runtime_id(self.descriptor)
        self.control_group = "/tests.slice/" + self.runtime_id + ".service"

    def manager(self, runner) -> SystemdTestAttemptManager:
        return SystemdTestAttemptManager(
            attempt_root=self.attempt_root,
            artifact_root=self.artifact_root,
            result_package_root=self.package_root,
            cgroup_root=self.cgroup_root,
            runner=runner,
            clock=lambda: 100.0,
        )

    def show_result(self, *, active: str = "inactive", sub: str = "dead") -> str:
        return "\n".join(
            (
                "LoadState=loaded",
                f"ActiveState={active}",
                f"SubState={sub}",
                "Result=success",
                "ExecMainCode=1",
                "ExecMainStatus=0",
                "OOMKilled=no",
                "CPUUsageNSec=500000000",
                "MemoryPeak=4096",
                "MemoryCurrent=1024",
                f"ControlGroup={self.control_group}",
            )
        )

    def prepare_attempt(
        self,
        manager: SystemdTestAttemptManager,
        *,
        populated: bool,
        publish_package: bool,
    ) -> Path:
        state = self.attempt_root / self.runtime_id
        state.mkdir(parents=True, mode=0o700)
        _launch, result_path = manager._publish_runner_launch(
            self.descriptor,
            state=state,
            execution_root=self.repository,
            owner_gid=os.getegid(),
        )
        manager._publish_native_evidence(
            self.runtime_id,
            self.descriptor,
            invocation_id="test-invocation-" + "1" * 32,
            prepared_at=90.0,
            started_at=91.0,
            control_group=self.control_group,
        )
        events = self.cgroup_root.joinpath(*self.control_group.split("/")[1:])
        events.mkdir(parents=True, mode=0o700)
        (events / "cgroup.events").write_text(
            f"populated {1 if populated else 0}\n", encoding="ascii"
        )
        if publish_package:
            stdout = state / "output" / "stdout.log"
            stderr = state / "output" / "stderr.log"
            stdout.write_bytes(b"out")
            stderr.write_bytes(b"err")
            artifacts = []
            captures = {}
            for index, (name, path) in enumerate(
                (("stdout", stdout), ("stderr", stderr)), start=1
            ):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                artifact_id = f"artifact-{index:032x}"
                artifacts.append(
                    ResultPackageArtifact(
                        artifact_id=artifact_id,
                        kind="log",
                        storage_handle=(
                            f"test-artifact://{artifact_id}/{digest}"
                        ),
                        sha256=digest,
                        size_bytes=path.stat().st_size,
                        source_path=path,
                    )
                )
                captures[name] = {
                    "artifact_id": artifact_id,
                    "sha256": digest,
                    "retained_sha256": digest,
                    "size_bytes": path.stat().st_size,
                    "observed_bytes": path.stat().st_size,
                    "truncated": False,
                    "secret_redacted": False,
                }
            publish_result_package(
                result_path,
                identity=manager._package_identity(self.descriptor),
                outcome={
                    "returncode": 0,
                    "duration_seconds": 1.0,
                    "incomplete_reporting": False,
                    "reporter_complete": True,
                    "terminal_outcome": "succeeded",
                },
                resource_usage={"peak_memory_bytes": 2048, "cpu_seconds": 0.25},
                captures=captures,
                cases=(),
                failures=(),
                artifacts=artifacts,
            )
        return result_path

    @staticmethod
    def completed(argv, returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def test_launch_descriptor_and_systemd_contract_use_one_package(self) -> None:
        manager = self.manager(lambda argv, **_kwargs: self.completed(argv))
        state = self.attempt_root / self.runtime_id
        state.mkdir(parents=True)
        launch, result = manager._publish_runner_launch(
            self.descriptor,
            state=state,
            execution_root=self.repository,
            owner_gid=os.getegid(),
        )
        self.assertEqual(result.name, RESULT_PACKAGE_FILE_NAME)
        self.assertEqual(
            json.loads(launch.read_text(encoding="utf-8"))["result_path"],
            str(result),
        )
        properties = manager._systemd_properties(
            self.descriptor,
            execution_root=self.repository,
            output_root=state / "output",
        )
        self.assertIn("--property=RemainAfterExit=yes", properties)
        self.assertIn("--property=KillMode=control-group", properties)
        self.assertIn("--property=TimeoutStopSec=30s", properties)
        self.assertIn("--property=RuntimeMaxSec=60s", properties)
        self.assertFalse(any("CollectMode" in value for value in properties))
        self.assertFalse(
            any(
                marker in value
                for marker in ("CPUQuota", "MemoryHigh", "MemoryMax", "TasksMax")
                for value in properties
            )
        )

    def test_inactive_empty_unit_publishes_verified_package_and_artifacts(self) -> None:
        def runner(argv, **_kwargs):
            if len(argv) > 1 and argv[1] == "show":
                return self.completed(argv, stdout=self.show_result())
            return self.completed(argv)

        manager = self.manager(runner)
        self.prepare_attempt(manager, populated=False, publish_package=True)

        state = manager.status(self.runtime_id)

        self.assertFalse(state.active)
        self.assertFalse(state.cgroup_populated)
        self.assertIsNotNone(state.result_package)
        assert state.result_package is not None
        retained = manager.resolve_result_package(
            str(state.result_package["storage_handle"])
        )
        self.assertEqual(retained.evidence.identity, manager._package_identity(self.descriptor))
        self.assertEqual(len(tuple(self.artifact_root.glob("*.blob"))), 2)

    def test_deactivating_populated_unit_never_exposes_package(self) -> None:
        manager = self.manager(
            lambda argv, **_kwargs: self.completed(
                argv,
                stdout=self.show_result(active="deactivating", sub="stop-sigterm"),
            )
        )
        self.prepare_attempt(manager, populated=True, publish_package=True)

        state = manager.status(self.runtime_id)

        self.assertTrue(state.active)
        self.assertTrue(state.cgroup_populated)
        self.assertIsNone(state.result_package)
        self.assertFalse(self.package_root.exists())

    def test_stop_uses_systemd_then_fixed_kill_only_while_transitional(self) -> None:
        calls: list[tuple[str, ...]] = []
        observations = [
            self.show_result(active="deactivating", sub="stop-sigterm"),
            self.show_result(active="inactive", sub="dead"),
        ]

        def runner(argv, **_kwargs):
            calls.append(tuple(argv))
            if len(argv) > 1 and argv[1] == "show":
                value = observations.pop(0)
                if not observations:
                    events = self.cgroup_root.joinpath(
                        *self.control_group.split("/")[1:]
                    ) / "cgroup.events"
                    events.write_text("populated 0\n", encoding="ascii")
                return self.completed(argv, stdout=value)
            return self.completed(argv)

        manager = self.manager(runner)
        self.prepare_attempt(manager, populated=True, publish_package=False)
        native = manager._read_native_evidence(self.runtime_id)

        manager._stop_exact_unit(self.runtime_id, native=native)

        actions = [call[1] for call in calls]
        self.assertEqual(actions, ["stop", "show", "kill", "stop", "show"])
        kill = calls[2]
        self.assertIn("--kill-whom=all", kill)
        self.assertIn("--signal=KILL", kill)
        self.assertFalse(any("cgroup.kill" in value for call in calls for value in call))

    def test_native_invocation_evidence_is_exact_and_recoverable(self) -> None:
        manager = self.manager(lambda argv, **_kwargs: self.completed(argv))
        self.prepare_attempt(manager, populated=False, publish_package=False)

        native = manager._read_native_evidence(self.runtime_id)

        self.assertEqual(native["systemd_unit"], f"{self.runtime_id}.service")
        self.assertEqual(native["control_group"], self.control_group)
        self.assertEqual(native["started_at"], 91.0)
        self.assertEqual(native["descriptor_sha256"], self.descriptor.fingerprint)

    def test_prepared_invocation_recovers_exact_loaded_control_group(self) -> None:
        manager = self.manager(
            lambda argv, **_kwargs: self.completed(argv, stdout=self.show_result())
        )
        self.prepare_attempt(manager, populated=False, publish_package=False)
        manager._publish_native_evidence(
            self.runtime_id,
            self.descriptor,
            invocation_id="test-invocation-" + "2" * 32,
            prepared_at=89.0,
            started_at=None,
            control_group=None,
        )

        descriptor, native = manager._native_context(self.runtime_id)

        self.assertEqual(descriptor, self.descriptor)
        self.assertEqual(native["control_group"], self.control_group)
        self.assertEqual(native["started_at"], 89.0)

    def test_package_identity_mismatch_fails_before_retention(self) -> None:
        manager = self.manager(
            lambda argv, **_kwargs: self.completed(argv, stdout=self.show_result())
        )
        result_path = self.prepare_attempt(
            manager, populated=False, publish_package=True
        )
        payload = bytearray(result_path.read_bytes())
        payload[700] ^= 1
        result_path.write_bytes(payload)

        with self.assertRaises(TestStoreConflict):
            manager.status(self.runtime_id)
        self.assertFalse(self.package_root.exists())

    def test_broker_projection_returns_only_native_and_package_facts(self) -> None:
        manager = self.manager(
            lambda argv, **_kwargs: self.completed(argv, stdout=self.show_result())
        )
        self.prepare_attempt(manager, populated=False, publish_package=True)
        coordinator = BrokerTestAttemptCoordinator(manager, clock=lambda: 100.0)
        coordinator._recovered_runtimes[self.runtime_id] = self.descriptor

        observed = coordinator.observe(self.runtime_id)

        self.assertEqual(observed["execution_id"], self.descriptor.execution_id)
        self.assertNotIn("attempt_id", observed)
        self.assertEqual(observed["generation"], self.descriptor.generation)
        self.assertEqual(observed["state"], "exited")
        self.assertTrue(observed["unit_inactive"])
        self.assertTrue(observed["cgroup_empty"])
        self.assertIsInstance(observed["result_package"], dict)
        self.assertNotIn("conclusion", observed)
        self.assertNotIn("result", observed)
        self.assertNotIn("result_chunk", observed)

    def test_never_launched_terminal_execution_collects_from_exact_absence(self) -> None:
        def absent(argv, **_kwargs):
            self.assertIn("show", argv)
            return subprocess.CompletedProcess(
                argv,
                1,
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
                "unit not found",
            )

        coordinator = BrokerTestAttemptCoordinator(
            self.manager(absent), clock=lambda: 100.0
        )

        self.assertEqual(
            coordinator.collect(
                self.runtime_id,
                expected_execution_id=self.descriptor.execution_id,
                expected_repository_id=self.descriptor.repository_id,
                expected_repository_generation=self.descriptor.repository_generation,
            ),
            {"runtime_id": self.runtime_id, "collected": True},
        )
        self.assertFalse((self.attempt_root / self.runtime_id).exists())


if __name__ == "__main__":
    unittest.main()
