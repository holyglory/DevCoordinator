from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from devcoordinator.broker import BrokerOperation
from devcoordinator.universal_test_broker import (
    BrokerConnection,
    CoordinatorRuntimeRequestSubmitter,
)
from devcoordinator.universal_test_result_package import (
    RESULT_PACKAGE_FILE_NAME,
    ResultPackageArtifact,
    publish_result_package,
    validate_result_package,
)
from devcoordinator.universal_test_store import ExecutionGrant, TestStoreConflict
from devcoordinator.universal_testd import (
    BrokerLaunchTicket,
    TestdLaunchAdapter,
    TransientRunnerRequest,
)


class FakeCalls:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.status: dict[str, object] | None = None

    def call(self, **values):
        self.calls.append(dict(values))
        operation = values["operation"]
        arguments = values["arguments"]
        if operation is BrokerOperation.TEST_ATTEMPT_LAUNCH:
            execution_id = str(arguments["execution_id"])
            return {
                "execution_id": execution_id,
                "generation": arguments["generation"],
                "systemd_unit": arguments["systemd_unit"],
                "launch_ack_id": "launch-" + execution_id,
            }
        if operation is BrokerOperation.TEST_ATTEMPT_STATUS:
            assert self.status is not None
            return dict(self.status)
        if operation is BrokerOperation.TEST_ATTEMPT_CANCEL:
            return {
                "execution_id": arguments["execution_id"],
                "generation": arguments["generation"],
                "systemd_unit": arguments["systemd_unit"],
                "cancelled": True,
                "absent": False,
            }
        if operation is BrokerOperation.TEST_ATTEMPT_COLLECT:
            return {
                "execution_id": arguments["execution_id"],
                "generation": arguments["generation"],
                "systemd_unit": arguments["systemd_unit"],
                "collected": True,
            }
        raise AssertionError(operation)


class BrokerV8AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.result_root = Path(self.temporary.name) / "results"
        self.result_root.mkdir()
        self.execution = ExecutionGrant(
            execution_id="execution-broker-v8",
            target_id="target-broker-v8",
            run_id="run-broker-v8",
            target_name="unit",
            shard_index=0,
            shard_count=1,
            generation=1,
            systemd_unit=(
                "devcoordinator-test-"
                + hashlib.sha256(b"execution-broker-v8").hexdigest()[:32]
                + ".service"
            ),
            launch_operation_id=str(uuid.uuid4()),
        )
        self.ticket = BrokerLaunchTicket(
            ticket_id="test-ticket-broker-v8",
            execution_id=self.execution.execution_id,
            target_id=self.execution.target_id,
            run_id=self.execution.run_id,
            repository_id="repo-broker-v8",
            repository_generation=7,
            owner_uid=1001,
            root_repo="/srv/repo",
            temporary_repo=None,
            execution_root="/srv/snapshot/root",
            argv=("python3", "-m", "unittest"),
            cwd="tests",
            environment={},
            intent="change",
            driver="automation",
            reporter="jsonl",
            artifacts=(),
            fixtures=(),
            credentials=(),
            network="none",
            ttl_seconds=30,
            worktree_key="/srv/snapshot/root",
            issued_at=1.0,
            expires_at=60.0,
        )
        self.request = TransientRunnerRequest(
            ticket=self.ticket,
            execution=self.execution,
            target_name="unit",
            descriptor_fingerprint="a" * 64,
        )
        self.calls = FakeCalls()
        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/run/fake.sock"), "generation-v8"),
            result_package_root=self.result_root,
        )
        submitter.calls = self.calls
        self.adapter = TestdLaunchAdapter(submitter)

    def running_status(self) -> dict[str, object]:
        return {
            "execution_id": self.execution.execution_id,
            "generation": 1,
            "repository_id": self.ticket.repository_id,
            "repository_generation": self.ticket.repository_generation,
            "systemd_unit": self.execution.systemd_unit,
            "systemd_invocation_id": "invocation-v8",
            "state": "running",
            "unit_inactive": False,
            "cgroup_empty": False,
            "launch_confirmed": True,
            "started_at": 2.0,
            "finished_at": None,
            "result_package": None,
            "exit": None,
            "resource_usage": {"current_memory_bytes": 4096},
            "progress": {
                "stdout_bytes": 10,
                "stderr_bytes": 0,
                "stdout_retained_bytes": 10,
                "stderr_retained_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "last_output_at": 3.0,
                "observed_at": 3.0,
            },
        }

    def test_prepare_start_and_running_observation_preserve_exact_identity(self) -> None:
        prepared = self.adapter.prepare(self.request)
        self.assertNotIn("attempt_id", self.request.to_document()["execution"])
        self.assertFalse(prepared.launch_confirmed)
        started = self.adapter.start(self.request, prepared)
        self.assertTrue(started.launch_confirmed)
        self.calls.status = self.running_status()
        observed = self.adapter.observe(started)
        self.assertEqual(observed.state, "running")
        self.assertEqual(observed.current_memory_bytes, 4096)
        self.assertEqual(observed.systemd_invocation_id, "invocation-v8")
        launch = next(
            call for call in self.calls.calls
            if call["operation"] is BrokerOperation.TEST_ATTEMPT_LAUNCH
        )
        self.assertEqual(launch["operation_id"], self.execution.launch_operation_id)
        self.assertEqual(launch["resource_id"], self.execution.execution_id)
        self.assertEqual(
            set(launch["arguments"]),
            {"ticket_id", "execution_id", "generation", "systemd_unit"},
        )
        for alias in ("attempt_id", "runtime_id", "invocation_id"):
            with self.subTest(alias=alias):
                self.calls.status = {**self.running_status(), alias: "legacy"}
                with self.assertRaises(TestStoreConflict):
                    self.adapter.observe(started)

    def test_attach_stop_and_collect_use_the_retained_execution_binding(self) -> None:
        handle = self.adapter.attach(
            {
                "execution_id": self.execution.execution_id,
                "generation": 1,
                "target_id": self.execution.target_id,
                "run_id": self.execution.run_id,
                "repository_id": self.ticket.repository_id,
                "repository_generation": self.ticket.repository_generation,
                "systemd_unit": self.execution.systemd_unit,
                "launch_operation_id": self.execution.launch_operation_id,
                "state": "running",
            }
        )
        stopped = self.running_status()
        stopped.update(
            {
                "state": "exited",
                "unit_inactive": True,
                "cgroup_empty": True,
                "resource_usage": {"peak_memory_bytes": 8192, "cpu_seconds": 0.5},
                "progress": None,
                "exit": {"status": 0},
            }
        )
        self.calls.status = stopped
        observation = self.adapter.stop(handle, reason="cancelled")
        self.assertTrue(observation.unit_inactive)
        self.assertTrue(observation.cgroup_empty)
        self.assertTrue(self.adapter.collect(handle))

    def test_atomic_package_resolution_reads_only_the_verified_shared_file(self) -> None:
        prepared = self.adapter.prepare(self.request)
        started = self.adapter.start(self.request, prepared)
        output = Path(self.temporary.name) / "output"
        output.mkdir()
        capture = output / "capture.log"
        capture.write_bytes(b"bounded\n")
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        artifact_id = "artifact-" + "1" * 32
        artifact = ResultPackageArtifact(
            artifact_id=artifact_id,
            kind="log",
            storage_handle=f"test-artifact://{artifact_id}/{digest}",
            sha256=digest,
            size_bytes=capture.stat().st_size,
            source_path=capture,
        )
        identity = {
            "execution_id": self.execution.execution_id,
            "target_id": self.execution.target_id,
            "run_id": self.execution.run_id,
            "repository_id": self.ticket.repository_id,
            "repository_generation": self.ticket.repository_generation,
            "generation": 1,
            "descriptor_sha256": "a" * 64,
        }
        published = publish_result_package(
            output / RESULT_PACKAGE_FILE_NAME,
            identity=identity,
            outcome={
                "returncode": 0,
                "duration_seconds": 1.0,
                "incomplete_reporting": False,
                "reporter_complete": True,
                "terminal_outcome": "succeeded",
            },
            resource_usage={"peak_memory_bytes": 8192, "cpu_seconds": 0.5},
            captures={
                stream: {
                    "artifact_id": artifact_id,
                    "sha256": digest,
                    "retained_sha256": digest,
                    "size_bytes": capture.stat().st_size,
                    "observed_bytes": capture.stat().st_size,
                    "truncated": False,
                    "secret_redacted": False,
                }
                for stream in ("stdout", "stderr")
            },
            cases=[{
                "case_id": "case-v8",
                "display_name": "case v8",
                "status": "passed",
                "duration_seconds": 1.0,
                "location": None,
            }],
            failures=[],
            artifacts=[artifact],
        )
        retained = self.result_root / f"{published.package_id}-{published.sha256}.tar"
        (output / RESULT_PACKAGE_FILE_NAME).replace(retained)
        package = validate_result_package(retained)
        raw_metadata = {
            "schema_version": 1,
            "package_id": published.package_id,
            "storage_handle": f"test-result-package://{published.package_id}/{published.sha256}",
            "sha256": published.sha256,
            "size_bytes": published.size_bytes,
            "manifest_sha256": published.manifest_sha256,
            "identity": dict(published.identity),
            "manifest": dict(package.manifest),
            "outcome": dict(package.manifest["outcome"]),
            "counts": dict(published.counts),
        }
        exited = self.running_status()
        exited.update(
            {
                "state": "exited",
                "unit_inactive": True,
                "cgroup_empty": True,
                "result_package": raw_metadata,
                "resource_usage": {"peak_memory_bytes": 8192, "cpu_seconds": 0.5},
                "progress": None,
                "exit": {"status": 0},
            }
        )
        self.calls.status = exited
        metadata = self.adapter.observe(started).result_package
        assert metadata is not None
        resolved = self.adapter.resolve_package(started, metadata)
        self.assertEqual(resolved.package_id, published.package_id)
        self.assertEqual(len(resolved.cases), 1)
        self.assertEqual(resolved.artifacts[0].artifact_id, artifact_id)


if __name__ == "__main__":
    unittest.main()
