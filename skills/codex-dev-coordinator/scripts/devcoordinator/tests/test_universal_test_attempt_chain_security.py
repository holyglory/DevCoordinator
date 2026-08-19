from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import uuid

from devcoordinator.broker import BrokerError
from devcoordinator.universal_test_contract import SourceMode, parse_test_manifest
from devcoordinator.universal_test_broker import (
    BrokerConnection,
    CoordinatorBrokerTicketIssuer,
    CoordinatorRuntimeRequestSubmitter,
)
from devcoordinator.universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    SourceIdentity,
    create_test_plan,
)
from devcoordinator.universal_test_repository_binding import (
    resolve_immutable_repository_binding,
)
from devcoordinator.universal_test_runtime import (
    BrokerTestAttemptCoordinator,
    NativeTestAttemptState,
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
    TestAttemptLaunchUncertain,
    TestAttemptRuntimeNotFound,
)
from devcoordinator.universal_test_spool import ActiveAttemptEnvelope
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    UniversalTestStore,
)
from devcoordinator.universal_testd import (
    RunnerRecoveryContext,
    _attempt_result_chunk,
)


def _operation_id() -> str:
    return str(uuid.uuid4())


def _plan(repository_id: str, root: Path, fingerprint: str):
    manifest = parse_test_manifest(
        {
            "schema_version": 3,
            "defaults": {
                "timeout_seconds": 60,
                "network": "none",
                "environment": {},
            },
            "global_inputs": [".codex/tests.json"],
            "intents": {
                "change": {"source_mode": "live", "allow_reuse": False}
            },
            "fixtures": {},
            "targets": {
                "unit": {
                    "driver": "automation",
                    "reporter": "automation-events",
                    "argv": ["/usr/bin/true"],
                    "cwd": ".",
                    "inputs": ["src/**"],
                    "depends_on": [],
                    "intents": ["change"],
                    "retry": {
                        "max_attempts": 2,
                        "retry_on": ["lease_expired_before_launch"],
                    },
                }
            },
            "evidence_policies": {},
        }
    )
    return create_test_plan(
        manifest,
        intent="change",
        source=SourceIdentity(
            mode=SourceMode.LIVE,
            repository_id=repository_id,
            content_fingerprint=fingerprint,
            original_root=str(root),
            temporary_root=None,
            snapshot_id=None,
        ),
        changes=(ChangedPath("src/change.py", ChangeStatus.MODIFIED),),
    )


class _FakeNativeManager:
    def __init__(self) -> None:
        self.started: list[TestAttemptDescriptor] = []
        self.cancelled: list[str] = []
        self.collected: list[str] = []
        self.states: dict[str, NativeTestAttemptState] = {}
        self.chunks: dict[tuple[str, int], dict[str, object]] = {}
        self.launch_tickets: dict[str, str] = {}

    def start(self, descriptor: TestAttemptDescriptor) -> NativeTestAttemptState:
        self.started.append(descriptor)
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            descriptor.attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        state = NativeTestAttemptState(
            runtime_id=runtime_id,
            loaded=True,
            active=True,
            state="running",
            exit_status=None,
            started_at=1.0,
        )
        self.states[runtime_id] = state
        return state

    def start_bound(
        self, descriptor: TestAttemptDescriptor, *, launch_ticket_id: str
    ) -> NativeTestAttemptState:
        state = self.start(descriptor)
        self.launch_tickets[state.runtime_id] = launch_ticket_id
        return state

    def status(self, runtime_id: str) -> NativeTestAttemptState:
        return self.states[runtime_id]

    def read_result_chunk(
        self, runtime_id: str, chunk_index: int
    ) -> dict[str, object] | None:
        return self.chunks.get((runtime_id, chunk_index))

    def cancel(self, runtime_id: str) -> NativeTestAttemptState:
        self.cancelled.append(runtime_id)
        self.states[runtime_id] = replace(
            self.states[runtime_id], active=False, state="exited", exit_status=1
        )
        return self.states[runtime_id]

    def collect(self, runtime_id: str) -> None:
        self.collected.append(runtime_id)

    def recover_descriptor(self, runtime_id: str) -> TestAttemptDescriptor:
        for descriptor in self.started:
            expected = "devcoordinator-test-" + hashlib.sha256(
                descriptor.attempt_id.encode("utf-8")
            ).hexdigest()[:32]
            if expected == runtime_id:
                return descriptor
        raise TestStoreConflict("test attempt runtime is unknown")

    def recover_launch_binding(
        self, runtime_id: str
    ) -> tuple[TestAttemptDescriptor, str | None]:
        return self.recover_descriptor(runtime_id), self.launch_tickets.get(runtime_id)

    def finish(
        self,
        runtime_id: str,
        descriptor: TestAttemptDescriptor,
        chunk: dict[str, object],
    ) -> None:
        self.chunks[(runtime_id, 0)] = chunk
        self.states[runtime_id] = NativeTestAttemptState(
            runtime_id=runtime_id,
            loaded=True,
            active=False,
            state="exited",
            exit_status=0,
            started_at=1.0,
            finished_at=2.0,
            result_document={
                "schema_version": 3,
                "attempt_id": descriptor.attempt_id,
                "generation": descriptor.generation,
                "returncode": 0,
                "duration_seconds": 1.0,
                "peak_memory_bytes": 8 * 1024 * 1024,
                "cpu_seconds": 0.25,
                "incomplete_reporting": False,
                "terminal_outcome": "succeeded",
                "captures": {},
                "artifact_sources": [],
                "chunk_manifest": [{"chunk_index": 0}],
            },
        )


class UniversalTestAttemptChainSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="test-attempt-chain-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo_a = self.root / "repo-a"
        self.repo_b = self.root / "repo-b"
        self.repo_a.mkdir(mode=0o700)
        self.repo_b.mkdir(mode=0o700)
        self.store = UniversalTestStore.create(self.root / "tests.sqlite3")

    def _submit_and_lease(self, repository_id: str, root: Path, owner_uid: int):
        submission = self.store.submit_plan(
            _plan(repository_id, root, hashlib.sha256(repository_id.encode()).hexdigest()),
            operation_id=_operation_id(),
            actor="codex:security-test",
            owner_uid=owner_uid,
        )
        candidate = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == submission.run_id
        )
        lease = self.store.lease_target(
            candidate.target_id,
            lease_owner="devcoordinator-testd",
            operation_id=_operation_id(),
        )
        return candidate, lease

    @staticmethod
    def _descriptor(candidate, lease, root: Path) -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            attempt_id=lease.attempt_id,
            target_id=candidate.target_id,
            run_id=candidate.run_id,
            repository_id=candidate.repository_id,
            repository_generation=7,
            owner_uid=candidate.owner_uid,
            generation=lease.generation,
            source_mode="live",
            snapshot_id=None,
            original_root=str(root),
            temporary_root=None,
            execution_root=str(root),
            worktree_key=str(root),
            target_name=candidate.target_name,
            shard_index=candidate.shard_index,
            shard_count=candidate.shard_count,
            argv=("/usr/bin/true",),
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="none",
            ttl_seconds=60,
        )

    def _collect_verified_artifact(
        self, descriptor: TestAttemptDescriptor
    ) -> tuple[dict[str, object], SystemdTestAttemptManager]:
        attempt_root = self.root / "attempts"
        artifact_root = self.root / "artifacts"
        runtime_id = "devcoordinator-test-chain-artifact"
        output = attempt_root / runtime_id / "output"
        output.mkdir(mode=0o700, parents=True)
        payload = b"repository-a exact evidence\n"
        source = output / "report.log"
        source.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = "artifact-" + hashlib.md5(payload).hexdigest()
        handle = f"test-artifact://{artifact_id}/{digest}"
        launch_path = attempt_root / runtime_id / "launch.json"
        launch_path.write_text(
            json.dumps({"descriptor": descriptor.to_document()}), encoding="utf-8"
        )
        launch_path.chmod(0o400)
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=artifact_root,
        )
        source_entry = {
            "artifact_id": artifact_id,
            "storage_handle": handle,
            "kind": "log",
            "scope": "output",
            "relative_path": "report.log",
            "packaged_from": None,
            "sha256": digest,
            "size_bytes": len(payload),
        }
        manager._collect_result_artifacts(
            runtime_id, {"artifact_sources": [source_entry]}
        )
        self.assertEqual(
            manager.resolve_artifact(handle, expected_size=len(payload)).read_bytes(),
            payload,
        )
        return (
            {
                "artifact_id": artifact_id,
                "kind": "log",
                "storage_handle": handle,
                "sha256": digest,
                "size_bytes": len(payload),
                "verified": True,
            },
            manager,
        )

    def test_cross_uid_ticket_launch_ingest_and_artifact_substitution_fail_closed(self) -> None:
        candidate_a, lease_a = self._submit_and_lease(
            "repo-a", self.repo_a, os.geteuid()
        )
        candidate_b, lease_b = self._submit_and_lease(
            "repo-b", self.repo_b, os.geteuid() + 10_000
        )
        descriptor_a = self._descriptor(candidate_a, lease_a, self.repo_a)
        descriptor_b = self._descriptor(candidate_b, lease_b, self.repo_b)
        artifact, resolver = self._collect_verified_artifact(descriptor_a)

        native = _FakeNativeManager()
        coordinator = BrokerTestAttemptCoordinator(native, clock=lambda: 9.0)
        ticket_a = coordinator.issue(descriptor_a)
        ticket_b = coordinator.issue(descriptor_b)

        with self.assertRaisesRegex(TestStoreConflict, "generation is stale"):
            coordinator.launch(
                ticket_id=ticket_a["ticket_id"],
                attempt_id=descriptor_b.attempt_id,
                generation=descriptor_b.generation,
            )
        self.assertEqual(native.started, [])

        launch = coordinator.launch(
            ticket_id=ticket_a["ticket_id"],
            attempt_id=descriptor_a.attempt_id,
            generation=descriptor_a.generation,
        )
        self.assertEqual(native.started, [descriptor_a])
        self.store.acknowledge_launch(
            lease_a.attempt_id,
            generation=lease_a.generation,
            launch_ack_id=launch["launch_ack_id"],
            operation_id=_operation_id(),
        )
        chunk_document = {
            "chunk_id": "chunk-repo-a-0",
            "chunk_index": 0,
            "cases": [],
            "failures": [],
            "artifacts": [artifact],
            "reporter_complete": True,
        }
        native.finish(launch["runtime_id"], descriptor_a, chunk_document)
        observation = coordinator.observe(launch["runtime_id"])
        self.assertEqual(
            (observation["attempt_id"], observation["repository_id"]),
            (descriptor_a.attempt_id, "repo-a"),
        )
        self.assertEqual(
            observation["resource_usage"],
            {
                "peak_memory_bytes": 8 * 1024 * 1024,
                "cpu_seconds": 0.25,
            },
        )
        chunk = _attempt_result_chunk(observation["result_chunk"])

        with self.assertRaisesRegex(TestStoreConflict, "generation is stale"):
            self.store.append_result_chunk(
                lease_b.attempt_id,
                generation=lease_b.generation + 1,
                chunk=chunk,
            )
        self.store.append_result_chunk(
            lease_a.attempt_id,
            generation=lease_a.generation,
            chunk=chunk,
        )

        self.assertEqual(len(self.store.artifacts(run_id=candidate_a.run_id)), 1)
        self.assertEqual(self.store.artifacts(run_id=candidate_b.run_id), ())
        valid_handle = artifact["storage_handle"]
        with self.assertRaises(TestStoreConflict):
            resolver.resolve_artifact(
                valid_handle[:-1] + ("0" if valid_handle[-1] != "0" else "1")
            )
        with self.assertRaises(TestStoreConflict):
            resolver.resolve_artifact(valid_handle, expected_size=artifact["size_bytes"] + 1)

        foreign_runtime = "devcoordinator-test-foreign-artifact"
        foreign_output = self.root / "attempts" / foreign_runtime / "output"
        foreign_output.mkdir(mode=0o700, parents=True)
        foreign_source = foreign_output / "report.log"
        foreign_source.write_bytes(b"foreign")
        foreign_digest = hashlib.sha256(b"foreign").hexdigest()
        foreign_id = "artifact-" + hashlib.md5(b"foreign").hexdigest()
        foreign_launch = self.root / "attempts" / foreign_runtime / "launch.json"
        foreign_launch.write_text(
            json.dumps({"descriptor": descriptor_b.to_document()}), encoding="utf-8"
        )
        foreign_handle = f"test-artifact://{foreign_id}/{foreign_digest}"
        resolver._collect_result_artifacts(
            foreign_runtime,
            {
                "artifact_sources": [
                    {
                        "artifact_id": foreign_id,
                        "storage_handle": foreign_handle,
                        "kind": "log",
                        "scope": "output",
                        "relative_path": "report.log",
                        "packaged_from": None,
                        "sha256": foreign_digest,
                        "size_bytes": len(b"foreign"),
                    }
                ]
            },
        )
        self.assertEqual(resolver.resolve_artifact(foreign_handle).read_bytes(), b"foreign")

    def test_observation_uses_live_memory_and_preserves_native_terminal_usage(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-resource-observation", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        coordinator = BrokerTestAttemptCoordinator(native, clock=lambda: 9.0)
        ticket = coordinator.issue(descriptor)
        launch = coordinator.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = launch["runtime_id"]
        native.states[runtime_id] = replace(
            native.states[runtime_id],
            current_memory_bytes=48 * 1024 * 1024,
            output_progress={
                "stdout_bytes": 5 * 1024 * 1024,
                "stderr_bytes": 256,
                "stdout_retained_bytes": 4 * 1024 * 1024,
                "stderr_retained_bytes": 256,
                "stdout_truncated": True,
                "stderr_truncated": False,
                "last_output_at": 8.0,
                "observed_at": 9.0,
            },
        )

        active = coordinator.observe(runtime_id)
        self.assertEqual(
            active["resource_usage"],
            {"current_memory_bytes": 48 * 1024 * 1024},
        )
        self.assertEqual(active["progress"]["stdout_bytes"], 5 * 1024 * 1024)
        self.assertEqual(
            active["progress"]["stdout_retained_bytes"], 4 * 1024 * 1024
        )
        self.assertTrue(active["progress"]["stdout_truncated"])
        self.assertEqual(active["progress"]["stderr_bytes"], 256)

        native.finish(
            runtime_id,
            descriptor,
            {
                "chunk_id": "chunk-resource-observation-0",
                "chunk_index": 0,
                "cases": [],
                "failures": [],
                "artifacts": [],
                "reporter_complete": True,
            },
        )
        native.states[runtime_id] = replace(
            native.states[runtime_id],
            loaded=False,
            state="collected",
            peak_memory_bytes=64 * 1024 * 1024,
            cpu_seconds=1.5,
        )

        terminal = coordinator.observe(runtime_id)
        self.assertEqual(
            terminal["resource_usage"],
            {"peak_memory_bytes": 64 * 1024 * 1024, "cpu_seconds": 1.5},
        )
        self.assertIsNone(terminal["progress"])

    def test_atomic_runner_result_drains_before_stopping_lingering_native_unit(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-lingering-result", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        coordinator = BrokerTestAttemptCoordinator(native, clock=lambda: 9.0)
        ticket = coordinator.issue(descriptor)
        launch = coordinator.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = launch["runtime_id"]
        chunk = {
            "chunk_id": "chunk-lingering-result-0",
            "chunk_index": 0,
            "cases": [],
            "failures": [],
            "artifacts": [],
            "reporter_complete": True,
        }
        native.finish(runtime_id, descriptor, chunk)
        second_chunk = {
            **chunk,
            "chunk_id": "chunk-lingering-result-1",
            "chunk_index": 1,
        }
        native.chunks[(runtime_id, 1)] = second_chunk
        native.states[runtime_id] = replace(
            native.states[runtime_id],
            active=True,
            state="deactivating",
            exit_status=None,
            finished_at=None,
            result_document={
                **(native.states[runtime_id].result_document or {}),
                "chunk_manifest": [
                    {"chunk_index": 0},
                    {"chunk_index": 1},
                ],
            },
        )

        first = coordinator.observe(runtime_id, result_chunk_index=0)
        second = coordinator.observe(runtime_id, result_chunk_index=1)

        self.assertEqual(first["result_chunk"], chunk)
        self.assertEqual(second["result_chunk"], second_chunk)
        self.assertEqual(native.cancelled, [])

        observed = coordinator.observe(runtime_id, result_chunk_index=2)

        self.assertEqual(observed["state"], "exited")
        self.assertIsNone(observed["result_chunk"])
        self.assertEqual(observed["exit_status"], 0)
        self.assertEqual(native.cancelled, [])

        collected = coordinator.collect(
            runtime_id,
            expected_attempt_id=descriptor.attempt_id,
            expected_repository_id=descriptor.repository_id,
            expected_repository_generation=descriptor.repository_generation,
        )

        self.assertTrue(collected["collected"])
        self.assertEqual(native.cancelled, [runtime_id])
        self.assertEqual(native.collected, [runtime_id])

    def test_active_attempt_is_cancelled_at_inclusive_execution_deadline(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-execution-deadline", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        now = [60.999]
        coordinator = BrokerTestAttemptCoordinator(
            native, clock=lambda: now[0]
        )
        ticket = coordinator.issue(descriptor)
        launch = coordinator.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = launch["runtime_id"]

        before = coordinator.observe(runtime_id)
        self.assertEqual(before["state"], "running")
        self.assertEqual(native.cancelled, [])

        now[0] = 61.0
        expired = coordinator.observe(runtime_id)

        self.assertEqual(expired["state"], "exited")
        self.assertEqual(expired["exit_status"], 124)
        self.assertEqual(expired["termination"]["reason"], "timeout")
        self.assertEqual(native.cancelled, [runtime_id])

    def test_atomic_result_published_during_deadline_cancel_wins_timeout(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-deadline-result-race", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        coordinator = BrokerTestAttemptCoordinator(native, clock=lambda: 61.0)
        ticket = coordinator.issue(descriptor)
        launch = coordinator.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = launch["runtime_id"]
        chunk = {
            "chunk_id": "chunk-deadline-result-race-0",
            "chunk_index": 0,
            "cases": [],
            "failures": [],
            "artifacts": [],
            "reporter_complete": True,
        }

        def publish_then_cancel(selected_runtime_id: str):
            native.cancelled.append(selected_runtime_id)
            native.finish(selected_runtime_id, descriptor, chunk)
            return native.states[selected_runtime_id]

        native.cancel = publish_then_cancel  # type: ignore[method-assign]

        observed = coordinator.observe(runtime_id)

        self.assertEqual(observed["state"], "exited")
        self.assertEqual(observed["result_chunk"], chunk)
        self.assertEqual(observed["termination"]["reason"], "success")
        self.assertEqual(native.cancelled, [runtime_id])

    def test_active_attempt_without_durable_start_cannot_be_heartbeated(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-missing-execution-origin", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        coordinator = BrokerTestAttemptCoordinator(native, clock=lambda: 2.0)
        ticket = coordinator.issue(descriptor)
        launch = coordinator.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )
        runtime_id = launch["runtime_id"]
        native.states[runtime_id] = replace(
            native.states[runtime_id], started_at=None
        )

        with self.assertRaisesRegex(
            TestStoreConflict, "execution deadline is unavailable"
        ):
            coordinator.observe(runtime_id)
        self.assertEqual(native.cancelled, [])

    def test_launch_ticket_outlives_caller_launch_deadline(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-ticket-lifetime", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        coordinator = BrokerTestAttemptCoordinator(
            _FakeNativeManager(), clock=lambda: 100.0, ticket_seconds=60
        )

        ticket = coordinator.issue(descriptor, launch_timeout_seconds=900)

        self.assertEqual(ticket["issued_at"], 100.0)
        self.assertEqual(ticket["expires_at"], 1_030.0)

    def test_runtime_timeout_becomes_timeout_instead_of_generic_infrastructure_failure(self) -> None:
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            b"attempt-timeout"
        ).hexdigest()[:32]

        class Calls:
            def call(self, *, operation, **_kwargs):
                if operation.value == "test.attempt_launch":
                    return {
                        "runtime_id": runtime_id,
                        "launch_ack_id": "test-launch-ticket-timeout",
                    }
                if operation.value == "test.attempt_status":
                    return {
                        "state": "exited",
                        "exit_status": 15,
                        "result": None,
                        "result_chunk": None,
                        "termination": {
                            "reason": "timeout",
                            "systemd_result": "timeout",
                            "exec_main_code": 2,
                            "oom_killed": False,
                        },
                        "resource_usage": {
                            "peak_memory_bytes": 32 * 1024 * 1024,
                            "cpu_seconds": 2.5,
                        },
                    }
                raise AssertionError(f"unexpected operation: {operation}")

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            clock=lambda: 10.0,
        )
        submitter.calls = Calls()
        launch = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "ticket-timeout",
                    "attempt_id": "attempt-timeout",
                    "repository_id": "repo-timeout",
                    "repository_generation": 4,
                    "generation": 2,
                }
            }
        )
        self.assertEqual(launch["runtime_id"], runtime_id)
        observed = submitter.observe(runtime_id)
        self.assertEqual(observed["state"], "exited")
        self.assertEqual(
            observed["exit_envelope"]["conclusion"],
            "timed_out",
        )
        self.assertEqual(
            observed["exit_envelope"]["peak_memory_bytes"],
            32 * 1024 * 1024,
        )
        self.assertEqual(observed["exit_envelope"]["cpu_seconds"], 2.5)

    def test_trusted_runner_infrastructure_outcome_survives_broker_transport(self) -> None:
        attempt_id = "attempt-runner-bootstrap-failure"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]

        class Calls:
            def call(self, *, operation, arguments=None, **_kwargs):
                if operation.value == "test.attempt_launch":
                    return {
                        "runtime_id": runtime_id,
                        "launch_ack_id": "test-launch-bootstrap-failure",
                    }
                if operation.value == "test.attempt_status":
                    index = int(arguments["result_chunk_index"])
                    return {
                        "state": "exited",
                        "exit_status": 1,
                        "result": {
                            "schema_version": 3,
                            "attempt_id": attempt_id,
                            "generation": 1,
                            "returncode": 1,
                            "duration_seconds": 0.25,
                            "incomplete_reporting": False,
                            "terminal_outcome": "infrastructure_failed",
                            "captures": {},
                            "chunk_count": 1,
                        },
                        "result_chunk": (
                            {
                                "chunk_id": "chunk-bootstrap-failure-0",
                                "chunk_index": 0,
                                "cases": [],
                                "failures": [
                                    {
                                        "failure_id": "failure-bootstrap-failure",
                                        "classification": "infrastructure_failure",
                                        "message": "trusted restore could not start",
                                        "case_id": None,
                                        "location": "runner/dotnet-bootstrap",
                                        "artifact_id": None,
                                    }
                                ],
                                "artifacts": [],
                                "reporter_complete": True,
                            }
                            if index == 0
                            else None
                        ),
                        "termination": {
                            "reason": "exit_code",
                            "systemd_result": "exit-code",
                            "exec_main_code": 1,
                            "oom_killed": False,
                        },
                        "resource_usage": {
                            "peak_memory_bytes": 16 * 1024 * 1024,
                            "cpu_seconds": 0.1,
                        },
                    }
                raise AssertionError(f"unexpected operation: {operation}")

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            clock=lambda: 10.0,
        )
        submitter.calls = Calls()
        launch = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-bootstrap-failure",
                    "attempt_id": attempt_id,
                    "repository_id": "repo-bootstrap-failure",
                    "repository_generation": 1,
                    "generation": 1,
                }
            }
        )
        first = submitter.observe(launch["runtime_id"])
        terminal = submitter.observe(launch["runtime_id"])

        self.assertEqual(first["state"], "result")
        self.assertEqual(
            first["result_chunk"]["failures"][0]["classification"],
            "infrastructure_failure",
        )
        self.assertEqual(terminal["state"], "exited")
        self.assertEqual(
            terminal["exit_envelope"]["conclusion"],
            "infrastructure_failed",
        )

    def test_launch_timeout_replays_exact_operation_without_duplicate_launch(self) -> None:
        requests = []
        client_timeouts = []
        backend_launches = 0
        expected_runtime_id = "devcoordinator-test-" + hashlib.sha256(
            b"attempt-replayed"
        ).hexdigest()[:32]
        cached_reply = {
            "ok": True,
            "result": {
                "runtime_id": expected_runtime_id,
                "launch_ack_id": "test-launch-replayed",
            },
        }

        class Client:
            def __init__(self, _path, **kwargs):
                client_timeouts.append(kwargs.get("timeout_seconds"))

            def call(self, request):
                nonlocal backend_launches
                requests.append(request)
                if len(requests) == 1:
                    # The backend committed one launch, but its reply was lost.
                    backend_launches += 1
                    raise BrokerError("request_timeout", "reply was lost")
                return cached_reply

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            launch_request_timeout_seconds=47.5,
        )
        result = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-replayed",
                    "attempt_id": "attempt-replayed",
                    "repository_id": "repo-replayed",
                    "repository_generation": 4,
                    "generation": 2,
                }
            }
        )

        self.assertEqual(
            {key: result[key] for key in ("runtime_id", "launch_ack_id")},
            cached_reply["result"],
        )
        self.assertTrue(result["launch_confirmed"])
        self.assertEqual(backend_launches, 1)
        self.assertEqual(client_timeouts, [47.5, 47.5])
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].to_wire(), requests[1].to_wire())
        self.assertEqual(requests[0].operation_id, requests[1].operation_id)

    def test_default_launch_transport_wait_is_a_short_retry_slice(self) -> None:
        client_timeouts = []
        expected_runtime_id = "devcoordinator-test-" + hashlib.sha256(
            b"attempt-default-slice"
        ).hexdigest()[:32]

        class Client:
            def __init__(self, _path, **kwargs):
                client_timeouts.append(kwargs.get("timeout_seconds"))

            def call(self, _request):
                return {
                    "ok": True,
                    "result": {
                        "runtime_id": expected_runtime_id,
                        "launch_ack_id": "test-launch-default-slice",
                    },
                }

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
        )

        result = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-default-slice",
                    "attempt_id": "attempt-default-slice",
                    "repository_id": "repo-default-slice",
                    "repository_generation": 1,
                    "generation": 1,
                },
                "lifecycle": {"launch_timeout_seconds": 3_600},
            }
        )

        self.assertTrue(result["launch_confirmed"])
        self.assertEqual(client_timeouts, [10.0])

    def test_prepare_has_no_rpc_and_replay_does_not_reset_launch_deadline(self) -> None:
        now = [10.0]
        requests = []

        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(self, request):
                requests.append(request)
                raise AssertionError("expired prepared launch must not make an RPC")

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            clock=lambda: now[0],
        )
        document = {
            "ticket": {
                "ticket_id": "test-ticket-no-deadline-reset",
                "attempt_id": "attempt-no-deadline-reset",
                "repository_id": "repo-no-deadline-reset",
                "repository_generation": 1,
                "generation": 1,
            },
            "lifecycle": {"launch_timeout_seconds": 30},
        }

        first = submitter.prepare(document)
        self.assertEqual(requests, [])
        now[0] = 45.0
        replayed = submitter.prepare(document)
        pending = submitter.launch_prepared(str(replayed["runtime_id"]))

        self.assertEqual(first, replayed)
        self.assertFalse(pending["launch_confirmed"])
        self.assertEqual(requests, [])

    def test_unresolved_launch_timeout_is_retained_and_reconciled_by_observe(self) -> None:
        requests = []
        expected_runtime_id = (
            "devcoordinator-test-"
            + hashlib.sha256(b"attempt-pending").hexdigest()[:32]
        )
        expected_launch_ack_id = "test-launch-pending"

        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(self, request):
                requests.append(request)
                launch_calls = [
                    value
                    for value in requests
                    if value.operation.value == "test.attempt_launch"
                ]
                if request.operation.value == "test.attempt_launch":
                    if len(launch_calls) <= 2:
                        raise BrokerError("request_timeout", "reply remains uncertain")
                    return {
                        "ok": True,
                        "result": {
                            "runtime_id": expected_runtime_id,
                            "launch_ack_id": expected_launch_ack_id,
                        },
                    }
                if request.operation.value == "test.attempt_status":
                    return {
                        "ok": True,
                        "result": {
                            "state": "running",
                            "exit_status": None,
                            "result": None,
                            "result_chunk": None,
                            "termination": None,
                            "resource_usage": {"current_memory_bytes": None},
                        },
                    }
                raise AssertionError(f"unexpected operation: {request.operation}")

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            launch_request_timeout_seconds=0.25,
        )
        launch = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-pending",
                    "attempt_id": "attempt-pending",
                    "repository_id": "repo-pending",
                    "repository_generation": 5,
                    "generation": 3,
                }
            }
        )

        self.assertEqual(launch["runtime_id"], expected_runtime_id)
        self.assertEqual(launch["launch_ack_id"], expected_launch_ack_id)
        self.assertFalse(launch["launch_confirmed"])
        observed = submitter.observe(expected_runtime_id)
        self.assertEqual(observed["state"], "running")
        launch_requests = [
            request
            for request in requests
            if request.operation.value == "test.attempt_launch"
        ]
        self.assertEqual(len(launch_requests), 3)
        self.assertEqual(
            {request.operation_id for request in launch_requests},
            {launch_requests[0].operation_id},
        )
        self.assertTrue(
            all(
                request.to_wire() == launch_requests[0].to_wire()
                for request in launch_requests
            )
        )

    def test_authority_restart_unknown_ticket_response_remains_pending(self) -> None:
        requests = []

        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(self, request):
                requests.append(request)
                return {
                    "ok": False,
                    "error": {
                        "code": "test_attempt_launch_uncertain",
                        "message": "native launch outcome is not yet observable",
                    },
                }

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            clock=lambda: 10.0,
        )
        launch = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-authority-restart-uncertain",
                    "attempt_id": "attempt-authority-restart-uncertain",
                    "repository_id": "repo-authority-restart-uncertain",
                    "repository_generation": 3,
                    "generation": 2,
                },
                "lifecycle": {"launch_timeout_seconds": 300},
            }
        )

        self.assertFalse(launch["launch_confirmed"])
        self.assertEqual(submitter.observe(launch["runtime_id"])["state"], "running")
        self.assertEqual(len(requests), 4)
        self.assertEqual(len({request.operation_id for request in requests}), 1)

    def test_pending_launch_spool_survives_restart_and_replays_exact_operation(self) -> None:
        requests = []
        expected_runtime_id = "devcoordinator-test-" + hashlib.sha256(
            b"attempt-restart-pending"
        ).hexdigest()[:32]

        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(self, request):
                requests.append(request)
                launch_count = sum(
                    value.operation.value == "test.attempt_launch"
                    for value in requests
                )
                if request.operation.value == "test.attempt_launch":
                    if launch_count <= 2:
                        raise BrokerError("request_timeout", "lost launch reply")
                    return {
                        "ok": True,
                        "result": {
                            "runtime_id": expected_runtime_id,
                            "launch_ack_id": "test-launch-restart-pending",
                        },
                    }
                return {
                    "ok": True,
                    "result": {
                        "state": "running",
                        "exit_status": None,
                        "result": None,
                        "result_chunk": None,
                        "termination": None,
                        "resource_usage": {"current_memory_bytes": None},
                    },
                }

        original = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            clock=lambda: 10.0,
        )
        launch = original.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-restart-pending",
                    "attempt_id": "attempt-restart-pending",
                    "repository_id": "repo-restart-pending",
                    "repository_generation": 6,
                    "generation": 4,
                },
                "lifecycle": {"launch_timeout_seconds": 90},
            }
        )
        envelope = ActiveAttemptEnvelope(
            attempt_id="attempt-restart-pending",
            generation=4,
            candidate={},
            lease={},
            runtime_id=launch["runtime_id"],
            launch_ack_id=launch["launch_ack_id"],
            repository_generation=6,
            launched_at=10.0,
            next_source_check_at=15.0,
            launch_ticket_id=launch["launch_ticket_id"],
            launch_operation_id=launch["launch_operation_id"],
            launch_timeout_seconds=launch["launch_timeout_seconds"],
            launch_confirmed=launch["launch_confirmed"],
        )
        retained = ActiveAttemptEnvelope.from_document(envelope.to_document())
        replacement = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            clock=lambda: 10.0,
        )
        replacement.recover(
            retained.runtime_id,
            context=RunnerRecoveryContext(
                repository_id="repo-restart-pending",
                repository_generation=retained.repository_generation,
                attempt_id=retained.attempt_id,
                generation=retained.generation,
                started_at=retained.launched_at,
                launch_ticket_id=retained.launch_ticket_id,
                launch_operation_id=retained.launch_operation_id,
                launch_timeout_seconds=retained.launch_timeout_seconds,
                launch_confirmed=retained.launch_confirmed,
            ),
        )

        self.assertEqual(replacement.observe(retained.runtime_id)["state"], "running")
        launch_requests = [
            value for value in requests
            if value.operation.value == "test.attempt_launch"
        ]
        self.assertEqual(len(launch_requests), 3)
        self.assertEqual(
            {value.operation_id for value in launch_requests},
            {retained.launch_operation_id},
        )

    def test_definitive_launch_rejection_emits_infrastructure_failure_evidence(self) -> None:
        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(self, _request):
                return {
                    "ok": False,
                    "error": {
                        "code": "test_attempt_contract_invalid",
                        "message": "snapshot materialization failed",
                    },
                }

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            client_factory=Client,
            clock=lambda: 20.0,
        )
        launch = submitter.submit(
            {
                "ticket": {
                    "ticket_id": "test-ticket-definitive-failure",
                    "attempt_id": "attempt-definitive-failure",
                    "repository_id": "repo-definitive-failure",
                    "repository_generation": 1,
                    "generation": 1,
                },
                "lifecycle": {"launch_timeout_seconds": 30},
            }
        )
        first = submitter.observe(launch["runtime_id"])
        second = submitter.observe(launch["runtime_id"])

        self.assertEqual(first["state"], "result")
        self.assertEqual(
            first["result_chunk"]["failures"][0]["classification"],
            "infrastructure_failure",
        )
        self.assertIn("snapshot materialization failed", first["result_chunk"]["failures"][0]["message"])
        self.assertEqual(second["state"], "exited")
        self.assertEqual(
            second["exit_envelope"]["conclusion"], "infrastructure_failed"
        )

    def test_launch_descriptor_is_cross_account_readable_but_not_writable(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-readable-launch", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        state = self.root / "readable-launch-state"
        state.mkdir(mode=0o711)
        manager = SystemdTestAttemptManager(
            attempt_root=self.root / "unused-attempts",
            artifact_root=self.root / "unused-artifacts",
        )
        launch_path, _result_path = manager._publish_runner_launch(
            descriptor,
            state=state,
            execution_root=self.repo_a,
            owner_gid=os.getegid(),
        )
        mode = stat.S_IMODE(launch_path.stat().st_mode)
        self.assertEqual(mode, 0o444)
        self.assertTrue(mode & stat.S_IROTH)
        self.assertFalse(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        self.assertIn(b'"schema_version":1', launch_path.read_bytes())

    def test_complete_non_secret_launch_path_is_repository_uid_traversable(self) -> None:
        attempt_root = self.root / "cross-account-attempts"
        attempt_root.mkdir(mode=0o700)
        attempt_root.chmod(0o700)
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=self.root / "unused-cross-account-artifacts",
        )
        state = manager._prepare_attempt_state(
            "devcoordinator-test-cross-account-traversal"
        )

        self.assertEqual(stat.S_IMODE(attempt_root.stat().st_mode), 0o711)
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o711)
        self.assertTrue(attempt_root.stat().st_mode & stat.S_IXOTH)
        self.assertTrue(state.stat().st_mode & stat.S_IXOTH)

    def test_attempt_materialization_falls_back_without_reflink_support(self) -> None:
        snapshot_id = "snapshot-" + "a" * 32
        snapshot_root = self.root / "portable-snapshots"
        source = snapshot_root / snapshot_id / "root"
        source.mkdir(parents=True)
        (source / "payload.txt").write_text("immutable source\n", encoding="utf-8")
        commands: list[list[str]] = []

        def copy_without_reflink(argv, **_kwargs):
            commands.append(list(argv))
            shutil.copytree(Path(argv[-2]), Path(argv[-1]), dirs_exist_ok=True)
            return subprocess.CompletedProcess(argv, 0, "", "")

        manager = SystemdTestAttemptManager(
            snapshot_root=snapshot_root,
            attempt_root=self.root / "portable-attempts",
            artifact_root=self.root / "portable-artifacts",
            runner=copy_without_reflink,
        )
        candidate, lease = self._submit_and_lease(
            "repo-portable-copy", self.repo_a, os.geteuid()
        )
        descriptor = replace(
            self._descriptor(candidate, lease, self.repo_a),
            source_mode="immutable",
            snapshot_id=snapshot_id,
            execution_root=str(source),
            source_provenance={
                "complete": True,
                "content_fingerprint": "b" * 64,
                "manifest_fingerprint": "c" * 64,
                "dependency_locks": {},
                "toolchain": {},
            },
        )
        state = manager._prepare_attempt_state(manager._runtime_id(descriptor))

        previous_umask = os.umask(0o077)
        try:
            destination = manager._prepare_attempt_root(
                descriptor,
                state=state,
                owner_gid=os.getegid(),
            )
        finally:
            os.umask(previous_umask)

        self.assertEqual(commands[0][1:3], ["--archive", "--reflink=auto"])
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o711)
        self.assertTrue(destination.parent.stat().st_mode & stat.S_IXOTH)
        self.assertEqual(
            (destination / "payload.txt").read_text(encoding="utf-8"),
            "immutable source\n",
        )
        binding = resolve_immutable_repository_binding(destination)
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.repository_id, descriptor.repository_id)
        self.assertEqual(binding.original_root, descriptor.original_root)
        (destination / "payload.txt").write_text("attempt copy\n", encoding="utf-8")
        self.assertEqual(
            (source / "payload.txt").read_text(encoding="utf-8"),
            "immutable source\n",
        )

    def test_native_manager_failure_retains_bounded_stderr(self) -> None:
        def refused(argv, **_kwargs):
            return subprocess.CompletedProcess(
                argv,
                1,
                "",
                "Changing to the requested working directory failed: Permission denied\n",
            )

        manager = SystemdTestAttemptManager(
            attempt_root=self.root / "diagnostic-attempts",
            artifact_root=self.root / "diagnostic-artifacts",
            runner=refused,
        )
        with self.assertLogs(
            "devcoordinator.universal_test_runtime", level="ERROR"
        ) as captured, self.assertRaisesRegex(
            TestStoreConflict, "working directory failed: Permission denied"
        ):
            manager._run(["/usr/bin/systemd-run", "--quiet"])
        self.assertIn("returncode=1", "\n".join(captured.output))

    def test_successful_native_start_does_not_depend_on_immediate_observation(self) -> None:
        commands: list[list[str]] = []

        def start_succeeds_observation_fails(argv, **_kwargs):
            commands.append(list(argv))
            if argv[0] == "/usr/bin/systemd-run":
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "/usr/bin/systemctl":
                return subprocess.CompletedProcess(
                    argv, 1, "", "unit was collected\n"
                )
            raise AssertionError(f"unexpected native command: {argv!r}")

        manager = SystemdTestAttemptManager(
            attempt_root=self.root / "post-launch-attempts",
            artifact_root=self.root / "post-launch-artifacts",
            runner=start_succeeds_observation_fails,
            clock=lambda: 123.0,
        )
        candidate, lease = self._submit_and_lease(
            "repo-post-launch-observation", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)

        launched = manager.start_bound(
            descriptor,
            launch_ticket_id="test-ticket-post-launch-observation",
        )

        self.assertTrue(launched.loaded)
        self.assertTrue(launched.active)
        self.assertEqual(launched.state, "running")
        self.assertEqual(launched.started_at, 123.0)
        self.assertEqual(
            sum(command[0] == "/usr/bin/systemd-run" for command in commands), 1
        )
        self.assertEqual(
            sum(command[0] == "/usr/bin/systemctl" for command in commands), 0
        )

        observed = manager.status(launched.runtime_id)
        self.assertFalse(observed.loaded)
        self.assertFalse(observed.active)
        self.assertEqual(observed.state, "not-found")
        self.assertEqual(
            sum(command[0] == "/usr/bin/systemd-run" for command in commands), 1
        )

    def test_protected_launch_evidence_retains_exact_broker_ticket(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-ticket-evidence", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            descriptor.attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        state = self.root / "ticket-evidence" / runtime_id
        state.mkdir(mode=0o711, parents=True)
        manager = SystemdTestAttemptManager(
            attempt_root=state.parent,
            artifact_root=self.root / "unused-ticket-artifacts",
        )
        ticket_id = "test-ticket-persisted-before-native-start"
        launch_path, _result_path = manager._publish_runner_launch(
            descriptor,
            state=state,
            execution_root=self.repo_a,
            owner_gid=os.getegid(),
            launch_ticket_id=ticket_id,
        )

        recovered_descriptor, recovered_ticket = manager.recover_launch_binding(
            runtime_id
        )

        self.assertEqual(recovered_descriptor, descriptor)
        self.assertEqual(recovered_ticket, ticket_id)
        self.assertIn(b'"schema_version":2', launch_path.read_bytes())

    def test_broker_ticket_intent_and_credentials_survive_testd_adapter(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-ticket-contract", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        returned = BrokerTestAttemptCoordinator(_FakeNativeManager()).issue(descriptor)

        class Resolver:
            timeouts: list[float] = []

            def resolve_as_owner(self, **kwargs):
                self.timeouts.append(kwargs["timeout_seconds"])
                return descriptor.to_document()

            def observe_live_source_as_owner(self, **_kwargs):
                return "a" * 64

        class Calls:
            requests: list[dict[str, object]] = []

            def call(self, **kwargs):
                self.requests.append(dict(kwargs))
                if len(self.requests) == 1:
                    raise BrokerError("request_timeout", "injected timeout")
                return returned

        clock = lambda: 1_000.0
        resolver = Resolver()
        issuer = CoordinatorBrokerTicketIssuer(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            resolver,
            clock=clock,
        )
        calls = Calls()
        issuer.calls = calls
        selected_plan = _plan(
            candidate.repository_id,
            self.repo_a,
            hashlib.sha256(candidate.repository_id.encode()).hexdigest(),
        )

        ticket = issuer.issue(
            candidate=candidate,
            lease=lease,
            plan_document=selected_plan.to_document(),
            launch_deadline=clock() + 300,
        )

        self.assertEqual(ticket.intent, "change")
        self.assertEqual(ticket.credentials, ())
        self.assertEqual(ticket.public_document()["credentials"], [])
        self.assertEqual(resolver.timeouts, [300])
        self.assertEqual(len(calls.requests), 2)
        self.assertEqual(
            calls.requests[0]["operation_id"], calls.requests[1]["operation_id"]
        )
        self.assertEqual(calls.requests[0]["arguments"], calls.requests[1]["arguments"])
        self.assertEqual(calls.requests[0]["timeout_seconds"], 10.0)

    def test_broker_restart_recovers_runtime_from_protected_native_identity(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-recovery", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        original = BrokerTestAttemptCoordinator(native, clock=lambda: 9.0)
        ticket = original.issue(descriptor)
        launch = original.launch(
            ticket_id=ticket["ticket_id"],
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )

        replacement = BrokerTestAttemptCoordinator(native, clock=lambda: 9.0)

        self.assertEqual(
            replacement.runtime_descriptor(launch["runtime_id"]), descriptor
        )
        self.assertEqual(
            replacement.observe(launch["runtime_id"])["state"], "running"
        )

    def test_authority_restart_replays_lost_launch_without_duplicate_execution(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-authority-restart", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        original = BrokerTestAttemptCoordinator(native)
        ticket = original.issue(descriptor, launch_timeout_seconds=300)
        committed = original.launch(
            ticket_id=str(ticket["ticket_id"]),
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
            expected_repository_id=descriptor.repository_id,
            expected_repository_generation=descriptor.repository_generation,
        )

        # The launch reply is lost and the authority process restarts. Its
        # in-memory ticket/runtime maps are gone, but the native launch record
        # retains the exact ticket binding published before systemd start.
        replacement = BrokerTestAttemptCoordinator(native)
        replayed = replacement.launch(
            ticket_id=str(ticket["ticket_id"]),
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
            expected_repository_id=descriptor.repository_id,
            expected_repository_generation=descriptor.repository_generation,
        )

        self.assertEqual(replayed, committed)
        self.assertEqual(native.started, [descriptor])

    def test_authority_restart_rejects_forged_recovery_ticket(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-recovery-ticket", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)
        native = _FakeNativeManager()
        original = BrokerTestAttemptCoordinator(native)
        ticket = original.issue(descriptor)
        original.launch(
            ticket_id=str(ticket["ticket_id"]),
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )

        replacement = BrokerTestAttemptCoordinator(native)
        with self.assertRaisesRegex(TestStoreConflict, "ticket identity"):
            replacement.launch(
                ticket_id="test-ticket-forged-recovery",
                attempt_id=descriptor.attempt_id,
                generation=descriptor.generation,
                expected_repository_id=descriptor.repository_id,
                expected_repository_generation=descriptor.repository_generation,
            )
        self.assertEqual(native.started, [descriptor])

    def test_authority_restart_rejects_mismatched_recovered_descriptor(self) -> None:
        candidate, lease = self._submit_and_lease(
            "repo-recovery-descriptor", self.repo_a, os.geteuid()
        )
        descriptor = self._descriptor(candidate, lease, self.repo_a)

        class MismatchedNative(_FakeNativeManager):
            def recover_launch_binding(
                self, runtime_id: str
            ) -> tuple[TestAttemptDescriptor, str | None]:
                recovered, ticket_id = super().recover_launch_binding(runtime_id)
                return replace(recovered, repository_id="repo-forged"), ticket_id

        native = MismatchedNative()
        original = BrokerTestAttemptCoordinator(native)
        ticket = original.issue(descriptor)
        original.launch(
            ticket_id=str(ticket["ticket_id"]),
            attempt_id=descriptor.attempt_id,
            generation=descriptor.generation,
        )

        replacement = BrokerTestAttemptCoordinator(native)
        with self.assertRaisesRegex(TestStoreConflict, "binding is contradictory"):
            replacement.launch(
                ticket_id=str(ticket["ticket_id"]),
                attempt_id=descriptor.attempt_id,
                generation=descriptor.generation,
                expected_repository_id=descriptor.repository_id,
                expected_repository_generation=descriptor.repository_generation,
            )
        self.assertEqual(native.started, [descriptor])

    def test_unknown_ticket_without_native_evidence_stays_uncertain(self) -> None:
        attempt_id = "attempt-not-yet-observable"

        class MissingNative(_FakeNativeManager):
            def recover_launch_binding(
                self, _runtime_id: str
            ) -> tuple[TestAttemptDescriptor, str | None]:
                raise TestAttemptRuntimeNotFound("launch evidence is absent")

        coordinator = BrokerTestAttemptCoordinator(MissingNative())
        with self.assertRaisesRegex(TestAttemptLaunchUncertain, "not yet observable"):
            coordinator.launch(
                ticket_id="test-ticket-not-yet-observable",
                attempt_id=attempt_id,
                generation=1,
                expected_repository_id="repo-not-yet-observable",
                expected_repository_generation=1,
            )

    def test_exact_native_absence_is_a_typed_successful_cleanup(self) -> None:
        attempt_id = "attempt-confirmed-absent"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]

        class AbsentNative(_FakeNativeManager):
            def recover_descriptor(self, _runtime_id: str) -> TestAttemptDescriptor:
                raise TestAttemptRuntimeNotFound("launch evidence is absent")

            def status(self, observed_runtime_id: str) -> NativeTestAttemptState:
                return NativeTestAttemptState(
                    runtime_id=observed_runtime_id,
                    loaded=False,
                    active=False,
                    state="not-found",
                    exit_status=None,
                )

            def cancel(self, _runtime_id: str) -> NativeTestAttemptState:
                raise AssertionError("an absent native runtime must not be stopped")

        coordinator = BrokerTestAttemptCoordinator(AbsentNative())

        self.assertEqual(
            coordinator.cancel(
                runtime_id,
                reason="launch deadline exceeded",
                expected_attempt_id=attempt_id,
                expected_repository_id="repo-confirmed-absent",
                expected_repository_generation=7,
            ),
            {"runtime_id": runtime_id, "cancelled": True, "absent": True},
        )

    def test_generic_descriptor_failure_never_proves_runtime_cleanup(self) -> None:
        attempt_id = "attempt-damaged-evidence"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]

        class DamagedNative(_FakeNativeManager):
            def recover_descriptor(self, _runtime_id: str) -> TestAttemptDescriptor:
                raise TestStoreConflict("launch evidence is damaged")

            def status(self, observed_runtime_id: str) -> NativeTestAttemptState:
                return NativeTestAttemptState(
                    runtime_id=observed_runtime_id,
                    loaded=False,
                    active=False,
                    state="not-found",
                    exit_status=None,
                )

        coordinator = BrokerTestAttemptCoordinator(DamagedNative())

        with self.assertRaisesRegex(TestStoreConflict, "evidence is damaged"):
            coordinator.cancel(
                runtime_id,
                reason="launch deadline exceeded",
                expected_attempt_id=attempt_id,
                expected_repository_id="repo-damaged-evidence",
                expected_repository_generation=7,
            )

    def test_absence_cannot_hide_an_active_native_runtime(self) -> None:
        attempt_id = "attempt-active-without-evidence"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]

        class ActiveNative(_FakeNativeManager):
            def recover_descriptor(self, _runtime_id: str) -> TestAttemptDescriptor:
                raise TestAttemptRuntimeNotFound("launch evidence is absent")

            def status(self, observed_runtime_id: str) -> NativeTestAttemptState:
                return NativeTestAttemptState(
                    runtime_id=observed_runtime_id,
                    loaded=True,
                    active=True,
                    state="running",
                    exit_status=None,
                )

        coordinator = BrokerTestAttemptCoordinator(ActiveNative())

        with self.assertRaisesRegex(TestStoreConflict, "active without recoverable"):
            coordinator.cancel(
                runtime_id,
                reason="launch deadline exceeded",
                expected_attempt_id=attempt_id,
                expected_repository_id="repo-active-without-evidence",
                expected_repository_generation=7,
            )

    def test_deadline_cleanup_requires_exact_typed_cancel_result(self) -> None:
        attempt_id = "attempt-deadline-cleanup-proof"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            clock=lambda: 100.0,
        )
        submitter.recover(
            runtime_id,
            context=RunnerRecoveryContext(
                repository_id="repo-deadline-cleanup-proof",
                repository_generation=2,
                attempt_id=attempt_id,
                generation=3,
                started_at=1.0,
            ),
        )
        context = submitter._runtimes[runtime_id]

        class GenericFailureCalls:
            def call(self, **_kwargs):
                raise BrokerError(
                    "test_attempt_contract_invalid",
                    "generic contract failure",
                )

        submitter.calls = GenericFailureCalls()
        self.assertFalse(
            submitter._deadline_cleanup_proven(
                runtime_id=runtime_id, context=context
            )
        )
        self.assertFalse(context.cancelled)

        class ExactAbsenceCalls:
            def call(self, **_kwargs):
                return {
                    "runtime_id": runtime_id,
                    "cancelled": True,
                    "absent": True,
                }

        submitter.calls = ExactAbsenceCalls()
        self.assertTrue(
            submitter._deadline_cleanup_proven(
                runtime_id=runtime_id, context=context
            )
        )
        self.assertTrue(context.cancelled)

    def test_cancel_timeout_retries_one_deterministic_bounded_operation(self) -> None:
        attempt_id = "attempt-cancel-uncertain"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1")
        )
        submitter.recover(
            runtime_id,
            context=RunnerRecoveryContext(
                repository_id="repo-cancel-uncertain",
                repository_generation=4,
                attempt_id=attempt_id,
                generation=5,
                started_at=1.0,
            ),
        )
        requests: list[dict[str, object]] = []

        class Calls:
            def call(self, **kwargs):
                requests.append(dict(kwargs))
                if len(requests) <= 2:
                    raise BrokerError("request_timeout", "cancel reply was lost")
                return {
                    "runtime_id": runtime_id,
                    "cancelled": True,
                    "absent": False,
                }

        submitter.calls = Calls()
        reason = "run cancellation requested"

        self.assertEqual(
            submitter.cancel(runtime_id, reason=reason), {"cancelled": False}
        )
        self.assertEqual(
            submitter.cancel(runtime_id, reason=reason), {"cancelled": True}
        )
        self.assertEqual(len(requests), 3)
        self.assertEqual(len({item["operation_id"] for item in requests}), 1)
        self.assertEqual(
            {item["timeout_seconds"] for item in requests}, {10.0}
        )
        self.assertEqual(
            {tuple(sorted(item["arguments"].items())) for item in requests},
            {
                tuple(
                    sorted({"runtime_id": runtime_id, "reason": reason}.items())
                )
            },
        )

    def test_published_runner_outcome_wins_cancellation_race(self) -> None:
        attempt_id = "attempt-cancel-result-race"
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            attempt_id.encode("utf-8")
        ).hexdigest()[:32]
        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            clock=lambda: 10.0,
        )
        submitter.recover(
            runtime_id,
            context=RunnerRecoveryContext(
                repository_id="repo-cancel-result-race",
                repository_generation=1,
                attempt_id=attempt_id,
                generation=1,
                started_at=1.0,
            ),
        )
        submitter._runtimes[runtime_id].cancelled = True

        class Calls:
            def call(self, *, arguments, **_kwargs):
                index = int(arguments["result_chunk_index"])
                return {
                    "state": "exited",
                    "exit_status": 1,
                    "result": {
                        "schema_version": 3,
                        "attempt_id": attempt_id,
                        "generation": 1,
                        "returncode": 1,
                        "duration_seconds": 2.0,
                        "incomplete_reporting": False,
                        "terminal_outcome": "test_failed",
                        "captures": {},
                        "chunk_count": 1,
                    },
                    "result_chunk": (
                        {
                            "chunk_id": "chunk-cancel-result-race",
                            "chunk_index": 0,
                            "cases": [],
                            "failures": [],
                            "artifacts": [],
                            "reporter_complete": True,
                        }
                        if index == 0
                        else None
                    ),
                    "termination": {
                        "reason": "exit_code",
                        "systemd_result": "exit-code",
                        "exec_main_code": 1,
                        "oom_killed": False,
                    },
                    "resource_usage": {
                        "peak_memory_bytes": 1024,
                        "cpu_seconds": 0.5,
                    },
                }

        submitter.calls = Calls()

        self.assertEqual(submitter.observe(runtime_id)["state"], "result")
        terminal = submitter.observe(runtime_id)
        self.assertEqual(terminal["state"], "exited")
        self.assertEqual(terminal["exit_envelope"]["conclusion"], "test_failed")

    def test_native_exit_without_result_streams_bounded_failure_then_exact_exit(self) -> None:
        runtime_id = "devcoordinator-test-" + hashlib.sha256(
            b"attempt-recovered"
        ).hexdigest()[:32]

        class Calls:
            def call(self, *, operation, **_kwargs):
                if operation.value == "test.attempt_status":
                    return {
                        "state": "exited",
                        "exit_status": 0,
                        "result": None,
                        "result_chunk": None,
                        "termination": {
                            "reason": "signal",
                            "systemd_result": "signal\n" + ("x" * 10_000),
                            "exec_main_code": 2,
                            "oom_killed": False,
                        },
                        "resource_usage": {
                            "peak_memory_bytes": None,
                            "cpu_seconds": None,
                        },
                    }
                raise AssertionError(f"unexpected operation: {operation}")

        submitter = CoordinatorRuntimeRequestSubmitter(
            BrokerConnection(Path("/tmp/devcoordinator-unused.sock"), "authority-1"),
            clock=lambda: 12.0,
        )
        submitter.calls = Calls()
        submitter.recover(
            runtime_id,
            context=RunnerRecoveryContext(
                repository_id="repo-recovered",
                repository_generation=5,
                attempt_id="attempt-recovered",
                generation=3,
                started_at=10.0,
            ),
        )

        failure = submitter.observe(runtime_id)
        terminal = submitter.observe(runtime_id)
        replayed = submitter.observe(runtime_id)

        self.assertEqual(failure["state"], "result")
        self.assertTrue(failure["launch_confirmed"])
        chunk = failure["result_chunk"]
        self.assertEqual(chunk["chunk_index"], 0)
        self.assertTrue(chunk["reporter_complete"])
        self.assertEqual(len(chunk["failures"]), 1)
        evidence = chunk["failures"][0]
        self.assertEqual(evidence["classification"], "infrastructure_failure")
        self.assertEqual(evidence["location"], "runner")
        self.assertIn("exit_status=0", evidence["message"])
        self.assertIn("reason=signal", evidence["message"])
        self.assertIn("systemd_result=signal", evidence["message"])
        self.assertIn("exec_main_code=2", evidence["message"])
        self.assertIn("oom_killed=false", evidence["message"])
        self.assertLessEqual(len(evidence["message"]), 8192)

        self.assertEqual(terminal, replayed)
        self.assertEqual(terminal["state"], "exited")
        self.assertTrue(terminal["launch_confirmed"])
        self.assertEqual(
            terminal["exit_envelope"]["conclusion"], "infrastructure_failed"
        )
        self.assertEqual(
            terminal["exit_envelope"]["result_chunk_ids"],
            [chunk["chunk_id"]],
        )


if __name__ == "__main__":
    unittest.main()
