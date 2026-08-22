from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from unittest import mock

from devcoordinator.universal_test_contract import (
    SourceMode,
    evidence_policy_fingerprint,
    parse_test_manifest,
)
from devcoordinator.universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    SourceIdentity,
    create_test_plan,
)
from devcoordinator.universal_test_scheduler import (
    ActiveAllocation,
    HostMemorySnapshot,
    WeightedFairScheduler,
)
from devcoordinator.universal_test_service import (
    RepositoryUIDPlanPreviewer,
    StoreTestPlaneAdapter,
    verified_artifact_chunk,
    verified_text_artifact_content,
    TestPlaneClient,
    TestPlanPreviewUnavailable,
    decode_test_plan_document,
)
from devcoordinator.universal_test_spool import (
    AttemptExitEnvelope,
    DurableAttemptSpool,
)
from devcoordinator.universal_test_store import (
    ArtifactMetadata,
    AttemptConclusion,
    AttemptResultChunk,
    CaseResult,
    FailureClassification,
    FailureRecord,
    LiveRetryReplanRequired,
    MAX_EXPIRED_ATTEMPTS_PER_REAP,
    RunnableTarget,
    TargetResources,
    TEST_STORE_SCHEMA_VERSION,
    TestStoreConflict,
    TestStoreContractError,
    TestStoreNotFound,
    UniversalTestStore,
    _attempt_progress_document,
    prepare_test_store_schema,
)


def operation_id() -> str:
    return str(uuid.uuid4())


def manifest_document() -> dict[str, object]:
    return {
        "schema_version": 3,
        "defaults": {
            "timeout_seconds": 300,
            "network": "none",
            "environment": {},
        },
        "global_inputs": [".codex/tests.json", "pyproject.toml"],
        "intents": {
            "change": {"source_mode": "live", "allow_reuse": False},
            "release": {"source_mode": "immutable", "allow_reuse": False},
        },
        "fixtures": {},
        "targets": {
            "lint": {
                "driver": "automation",
                "reporter": "automation-events",
                "argv": ["./scripts/lint"],
                "cwd": ".",
                "inputs": ["src/**"],
                "depends_on": [],
                "intents": ["change", "release"],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
            "unit": {
                "driver": "pytest",
                "reporter": "pytest-events",
                "argv": ["{python}", "-m", "pytest", "tests"],
                "cwd": ".",
                "inputs": ["src/**", "tests/**"],
                "depends_on": ["lint"],
                "intents": ["change", "release"],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
        },
        "evidence_policies": {
            "release": {
                "intent": "release",
                "required_targets": ["lint", "unit"],
                "max_age_seconds": 60,
                "allow_reuse": False,
            }
        },
    }


def setup_document(repository_id: str = "repo-tests") -> dict[str, object]:
    manifest = parse_test_manifest(manifest_document())
    return {
        "schema_version": 1,
        "repository_id": repository_id,
        "ok": True,
        "status": "ready",
        "manifest_schema": manifest.schema_version,
        "manifest_fingerprint": manifest.fingerprint,
        "targets": [
            {
                "name": "lint",
                "driver": "automation",
                "reporter": "automation-events",
                "network": "none",
                "fixtures": [],
                "depends_on": [],
            },
            {
                "name": "unit",
                "driver": "pytest",
                "reporter": "pytest-events",
                "network": "none",
                "fixtures": [],
                "depends_on": ["lint"],
            },
        ],
        "target_graph": {"lint": [], "unit": ["lint"]},
        "input_coverage": {
            "global_input_count": 2,
            "target_input_count": 3,
            "targets_with_inputs": 2,
        },
        "input_coverage_gaps": [],
        "intents": ["change", "release"],
        "evidence_policies": ["release"],
        "fixtures": [],
        "network_requirements": ["none"],
        "isolation": {
            "network": "none",
            "private_scratch": True,
            "kill_after_run": True,
        },
        "issues": [],
    }


def plan(
    *,
    mode: SourceMode = SourceMode.IMMUTABLE,
    fingerprint: str = "a" * 64,
    changed: bool = True,
    temporary_root: str | None = None,
    execution_timeout_seconds: int | None = None,
    launch_timeout_seconds: int = 300,
):
    manifest = parse_test_manifest(manifest_document())
    source = SourceIdentity(
        mode=mode,
        repository_id="repo-tests",
        content_fingerprint=fingerprint,
        original_root="/home/example/repo",
        temporary_root=(
            temporary_root
            if temporary_root is not None
            else ("/home/example/worktree" if mode is SourceMode.LIVE else None)
        ),
        snapshot_id=("snapshot-" + fingerprint[:16] if mode is SourceMode.IMMUTABLE else None),
    )
    return create_test_plan(
        manifest,
        intent="release" if mode is SourceMode.IMMUTABLE else "change",
        source=source,
        changes=(
            ()
            if mode is SourceMode.IMMUTABLE or not changed
            else (ChangedPath("src/change.py", ChangeStatus.MODIFIED),)
        ),
        execution_timeout_seconds=execution_timeout_seconds,
        launch_timeout_seconds=launch_timeout_seconds,
    )


class MutableClock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class StoreFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock()
        self.path = Path(self.temporary.name) / "test-plane.sqlite3"
        self.store = UniversalTestStore.create(self.path, clock=self.clock)

    def submit(self, *, selected_plan=None, resources=None, operation=None):
        return self.store.submit_plan(
            selected_plan or plan(),
            operation_id=operation or operation_id(),
            actor="codex:test",
            owner_uid=1001,
            target_resources=resources,
        )

    def lease_lint(self, run_id: str, *, seconds: int = 30):
        candidates = self.store.runnable_targets()
        lint = next(item for item in candidates if item.target_name == "lint")
        return self.store.lease_target(
            lint.target_id,
            lease_owner="testd",
            lease_seconds=seconds,
            operation_id=operation_id(),
        )

    def complete(
        self,
        grant,
        *,
        conclusion: AttemptConclusion = AttemptConclusion.SUCCEEDED,
        duration: float = 2.0,
        cases: tuple[CaseResult, ...] = (),
    ):
        self.store.acknowledge_launch(
            grant.attempt_id,
            generation=grant.generation,
            launch_ack_id="launch-" + grant.attempt_id,
            operation_id=operation_id(),
        )
        self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=AttemptResultChunk(
                chunk_id="chunk-" + grant.attempt_id,
                chunk_index=0,
                cases=cases,
                reporter_complete=True,
            ),
        )
        return self.store.terminalize_attempt(
            grant.attempt_id,
            generation=grant.generation,
            conclusion=conclusion,
            duration_seconds=duration,
            operation_id=operation_id(),
        )


class UniversalTestStoreTests(StoreFixture):
    def test_legacy_attempt_progress_is_readable_after_schema_expansion(self) -> None:
        legacy = {
            "stdout_bytes": 4 * 1024 * 1024,
            "stderr_bytes": 64,
            "current_memory_bytes": 512 * 1024 * 1024,
            "last_output_at": 100.0,
            "observed_at": 101.0,
        }

        normalized = _attempt_progress_document(legacy)

        self.assertEqual(normalized["stdout_retained_bytes"], 4 * 1024 * 1024)
        self.assertEqual(normalized["stderr_retained_bytes"], 64)
        self.assertFalse(normalized["stdout_truncated"])
        self.assertFalse(normalized["stderr_truncated"])
        with self.assertRaisesRegex(
            TestStoreContractError,
            "retained attempt output progress is invalid",
        ):
            _attempt_progress_document({**legacy, "unexpected": True})

    def test_queue_status_needs_no_run_handle_and_reports_typed_blockers(self) -> None:
        submitted = self.submit()

        queued = self.store.queue_status(repository_id="repo-tests")

        self.assertEqual(queued["phase"], "scheduler")
        self.assertEqual(queued["global_targets"]["queued"], 2)
        self.assertEqual(queued["repository_targets"]["queued"], 2)
        self.assertEqual(queued["repository_runnable_targets"], 1)
        self.assertEqual(queued["approximate_first_position"], 1)
        self.assertEqual(
            queued["blockers"],
            [{"code": "dependency_wave", "target_count": 1}],
        )
        self.assertEqual(queued["worker_capacity"]["limit"], None)

        grant = self.lease_lint(submitted.run_id)
        self.store.acknowledge_launch(
            grant.attempt_id,
            generation=grant.generation,
            launch_ack_id="launch-" + grant.attempt_id,
            operation_id=operation_id(),
        )
        running = self.store.queue_status(repository_id="repo-tests")
        self.assertEqual(running["phase"], "execution")
        self.assertEqual(running["repository_targets"]["running"], 1)

    def test_schema_preparation_attests_fresh_v5_and_replays(self) -> None:
        mutation = operation_id()
        first = prepare_test_store_schema(
            self.path,
            operation_id=mutation,
        )
        replay = prepare_test_store_schema(
            self.path,
            operation_id=mutation,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first["action"], "attested-fresh")
        self.assertEqual(first["journal_kind"], "schema_readiness")
        self.assertEqual(first["store"]["schema_version"], 6)

    def test_schema_preparation_fresh_v5_interruption_rolls_back(self) -> None:
        mutation = operation_id()

        def interrupt(stage: str) -> None:
            if stage == "before_commit":
                raise RuntimeError("injected readiness interruption")

        with self.assertRaisesRegex(RuntimeError, "readiness interruption"):
            prepare_test_store_schema(
                self.path,
                operation_id=mutation,
                checkpoint=interrupt,
            )
        connection = sqlite3.connect(self.path)
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM test_mutation_journal WHERE operation_id = ?",
                (mutation,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 0)
        recovered = prepare_test_store_schema(
            self.path,
            operation_id=mutation,
        )
        self.assertEqual(recovered["action"], "attested-fresh")

    def test_schema_preparation_rejects_noncurrent_with_fresh_store_instruction(self) -> None:
        path = Path(self.temporary.name) / "obsolete.sqlite3"
        UniversalTestStore.create(path)
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                "UPDATE test_store_metadata SET schema_version = 4 WHERE singleton = 1"
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            TestStoreConflict,
                "initialize a fresh current store",
        ):
            prepare_test_store_schema(path, operation_id=operation_id())
        unchanged = sqlite3.connect(path)
        try:
            self.assertEqual(
                unchanged.execute(
                    "SELECT schema_version FROM test_store_metadata WHERE singleton = 1"
                ).fetchone()[0],
                4,
            )
        finally:
            unchanged.close()

    def test_open_validates_without_implicit_creation_or_migration(self) -> None:
        self.assertEqual(
            UniversalTestStore.open(self.path).verify()["schema_version"],
            TEST_STORE_SCHEMA_VERSION,
        )
        with self.assertRaisesRegex(TestStoreConflict, "already exists"):
            UniversalTestStore.create(self.path)

        malformed = Path(self.temporary.name) / "malformed.sqlite3"
        connection = sqlite3.connect(malformed)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.close()
        with self.assertRaises(TestStoreConflict):
            UniversalTestStore.open(malformed)
        unchanged = sqlite3.connect(malformed)
        try:
            self.assertEqual(
                unchanged.execute(
                    "SELECT name FROM sqlite_master WHERE name='test_runs'"
                ).fetchone(),
                None,
            )
        finally:
            unchanged.close()

        legacy = Path(self.temporary.name) / "legacy-v3.sqlite3"
        UniversalTestStore.create(legacy)
        connection = sqlite3.connect(legacy)
        try:
            connection.execute(
                "UPDATE test_store_metadata SET schema_version = 3 WHERE singleton = 1"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            TestStoreConflict,
                "initialize a fresh current store",
        ):
            UniversalTestStore.open(legacy)

    def test_immutable_temporary_root_is_retained_as_execution_provenance(self) -> None:
        selected = plan(temporary_root="/var/lib/devcoordinator/snapshots/repo-tests")
        submitted = self.submit(selected_plan=selected)

        retained = self.store.get_plan_document(selected.plan_id)
        self.assertEqual(
            retained["source"]["temporary_root"],
            "/var/lib/devcoordinator/snapshots/repo-tests",
        )
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["source_mode"], "immutable")
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute(
                "SELECT temporary_root FROM test_snapshots WHERE snapshot_id = ?",
                (selected.source.snapshot_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(
            row,
            ("/var/lib/devcoordinator/snapshots/repo-tests",),
        )

    def test_submission_is_idempotent_and_active_immutable_jobs_deduplicate(self) -> None:
        mutation = operation_id()
        first = self.submit(operation=mutation)
        replay = self.submit(operation=mutation)
        self.assertEqual(first, replay)
        self.assertFalse(first.deduplicated)

        duplicate = self.submit()
        self.assertTrue(duplicate.deduplicated)
        self.assertEqual(duplicate.run_id, first.run_id)

        other = self.submit(selected_plan=plan(fingerprint="b" * 64))
        self.assertNotEqual(other.run_id, first.run_id)

        with self.assertRaisesRegex(TestStoreConflict, "different mutation"):
            self.store.submit_plan(
                plan(),
                operation_id=mutation,
                actor="another-agent",
                owner_uid=1001,
            )

    def test_live_jobs_never_deduplicate(self) -> None:
        selected = plan(mode=SourceMode.LIVE)
        first = self.submit(selected_plan=selected)
        second = self.submit(selected_plan=selected)
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertFalse(second.deduplicated)
        self.assertEqual(first.state, "queued")

        no_work = self.submit(
            selected_plan=plan(mode=SourceMode.LIVE, changed=False)
        )
        self.assertEqual(no_work.state, "succeeded")
        self.assertEqual(self.store.get_run(no_work.run_id)["targets"], [])

    def test_dependency_waves_and_generation_fenced_lease_lifecycle(self) -> None:
        submitted = self.submit()
        runnable = self.store.runnable_targets()
        self.assertEqual([item.target_name for item in runnable], ["lint"])
        lease_operation = operation_id()
        lint = runnable[0]
        grant = self.store.lease_target(
            lint.target_id,
            lease_owner="testd",
            operation_id=lease_operation,
        )
        replayed_grant = self.store.lease_target(
            lint.target_id,
            lease_owner="testd",
            operation_id=lease_operation,
        )
        self.assertEqual(grant, replayed_grant)
        connection = sqlite3.connect(self.path)
        journal = connection.execute(
            "SELECT result_json FROM test_mutation_journal WHERE operation_id = ?",
            (lease_operation,),
        ).fetchone()[0]
        connection.close()
        self.assertNotIn('"token"', journal)
        self.assertNotIn("lease_token", journal)

        heartbeat_operation = operation_id()
        heartbeat = self.store.heartbeat_attempt(
            grant.attempt_id,
            generation=grant.generation,
            lease_seconds=40,
            operation_id=heartbeat_operation,
        )
        self.assertEqual(
            heartbeat,
            self.store.heartbeat_attempt(
                grant.attempt_id,
                generation=grant.generation,
                lease_seconds=40,
                operation_id=heartbeat_operation,
            ),
        )
        with self.assertRaisesRegex(TestStoreConflict, "stale"):
            self.store.heartbeat_attempt(
                grant.attempt_id,
                generation=grant.generation + 1,
                operation_id=operation_id(),
            )
        self.complete(grant)
        self.assertEqual(
            [item.target_name for item in self.store.runnable_targets()], ["unit"]
        )

    def test_failed_independent_branch_does_not_suppress_ready_dependency_branch(
        self,
    ) -> None:
        document = manifest_document()
        targets = document["targets"]
        assert isinstance(targets, dict)
        targets["fixture-check"] = {
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/check-fixture"],
            "cwd": ".",
            "inputs": ["fixtures/**"],
            "depends_on": [],
            "intents": ["release"],
            "retry": {"max_attempts": 1, "retry_on": []},
        }
        manifest = parse_test_manifest(document)
        selected_plan = create_test_plan(
            manifest,
            intent="release",
            source=SourceIdentity(
                mode=SourceMode.IMMUTABLE,
                repository_id="repo-tests",
                content_fingerprint="d" * 64,
                original_root="/home/example/repo",
                snapshot_id="snapshot-independent-branch",
            ),
        )
        submitted = self.submit(selected_plan=selected_plan)
        first_wave = {
            item.target_name: item for item in self.store.runnable_targets()
        }
        self.assertEqual(set(first_wave), {"fixture-check", "lint"})

        fixture = self.store.lease_target(
            first_wave["fixture-check"].target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.complete(fixture, conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED)
        self.assertEqual(
            [item.target_name for item in self.store.runnable_targets()], ["lint"]
        )

        lint = self.lease_lint(submitted.run_id)
        self.complete(lint)
        self.assertEqual(
            [item.target_name for item in self.store.runnable_targets()], ["unit"]
        )
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "running")

    def test_terminalization_is_idempotent_after_lease_closes(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=AttemptResultChunk(
                chunk_id="final",
                chunk_index=0,
                reporter_complete=True,
            ),
        )
        terminal_operation = operation_id()
        first = self.store.terminalize_attempt(
            grant.attempt_id,
            generation=grant.generation,
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=3,
            operation_id=terminal_operation,
        )
        replay = self.store.terminalize_attempt(
            grant.attempt_id,
            generation=grant.generation,
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=3,
            operation_id=terminal_operation,
        )
        self.assertEqual(first, replay)

    def test_reporter_chunks_are_contiguous_and_final_is_sealed(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        with self.assertRaisesRegex(TestStoreConflict, "expected 0"):
            self.store.append_result_chunk(
                grant.attempt_id,
                generation=grant.generation,
                chunk=AttemptResultChunk(chunk_id="late", chunk_index=1),
            )
        self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=AttemptResultChunk(
                chunk_id="final", chunk_index=0, reporter_complete=True
            ),
        )
        with self.assertRaisesRegex(TestStoreConflict, "final chunk"):
            self.store.append_result_chunk(
                grant.attempt_id,
                generation=grant.generation,
                chunk=AttemptResultChunk(chunk_id="extra", chunk_index=1),
            )

    def test_bounded_chunk_ingestion_is_exactly_once_and_progressively_disclosed(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        self.store.acknowledge_launch(
            grant.attempt_id,
            generation=grant.generation,
            launch_ack_id="launch-lint",
            operation_id=operation_id(),
        )
        chunk = AttemptResultChunk(
            chunk_id="chunk-1",
            chunk_index=0,
            cases=(CaseResult("case-1", "one case", "failed", 1.25, "tests/a.py:1"),),
            failures=(
                FailureRecord(
                    "failure-1",
                    FailureClassification.TEST_FAILURE,
                    "expected true",
                    case_id="case-1",
                    location="tests/a.py:1",
                    artifact_id="artifact-1",
                ),
            ),
            artifacts=(
                ArtifactMetadata(
                    "artifact-1",
                    "log",
                    "test-artifact://artifact-1/" + "f" * 64,
                    "f" * 64,
                    123,
                ),
            ),
            reporter_complete=True,
        )
        first = self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=chunk,
        )
        replay = self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=chunk,
        )
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.store.failures(run_id=submitted.run_id)[0]["failure_id"], "failure-1")
        live_status = StoreTestPlaneAdapter(self.store).status(
            run_id=submitted.run_id,
            repository_id="repo-tests",
        )
        self.assertEqual(live_status["state"], "running")
        self.assertEqual(live_status["failure_count"], 1)
        self.assertEqual(live_status["counts"]["attempts"], 1)
        self.assertEqual(live_status["counts"]["failed"], 1)
        self.assertIn("aggregate_test_seconds", live_status["timing"])
        self.assertEqual(self.store.artifacts(run_id=submitted.run_id)[0]["artifact_id"], "artifact-1")
        resolved = self.store.artifact(
            run_id=submitted.run_id, artifact_id="artifact-1"
        )
        self.assertEqual(resolved["sha256"], "f" * 64)
        self.assertEqual(
            resolved["storage_handle"],
            "test-artifact://artifact-1/" + "f" * 64,
        )
        with self.assertRaises(TestStoreNotFound):
            self.store.artifact(run_id="run-foreign", artifact_id="artifact-1")
        with self.store._transaction() as connection:
            connection.execute(
                "UPDATE test_artifacts SET verified = 0 WHERE artifact_id = 'artifact-1'"
            )
        self.assertEqual(self.store.artifacts(run_id=submitted.run_id), ())
        with self.assertRaisesRegex(TestStoreConflict, "not been verified"):
            self.store.artifact(
                run_id=submitted.run_id, artifact_id="artifact-1"
            )
        with self.store._transaction() as connection:
            connection.execute(
                "UPDATE test_artifacts SET verified = 1 WHERE artifact_id = 'artifact-1'"
            )

        conflicting = AttemptResultChunk(
            chunk_id="chunk-1",
            chunk_index=0,
            cases=(CaseResult("case-2", "different", "passed", 0.1),),
        )
        with self.assertRaisesRegex(TestStoreConflict, "different results"):
            self.store.append_result_chunk(
                grant.attempt_id,
                generation=grant.generation,
                chunk=conflicting,
            )
        oversized = AttemptResultChunk(
            chunk_id="chunk-big",
            chunk_index=1,
            cases=tuple(
                CaseResult(f"case-{index}", "x", "passed", 0)
                for index in range(501)
            ),
        )
        with self.assertRaisesRegex(TestStoreContractError, "too many cases"):
            self.store.append_result_chunk(
                grant.attempt_id,
                generation=grant.generation,
                chunk=oversized,
            )
        self.store.terminalize_attempt(
            grant.attempt_id,
            generation=grant.generation,
            conclusion=AttemptConclusion.TEST_FAILED,
            duration_seconds=1.5,
            operation_id=operation_id(),
            expected_result_chunk_ids=("chunk-1",),
        )
        terminal_replay = self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=chunk,
        )
        self.assertTrue(terminal_replay["replayed"])

    def test_adapter_returns_integrity_verified_bounded_text_artifact_tail(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        self.store.acknowledge_launch(
            grant.attempt_id,
            generation=grant.generation,
            launch_ack_id="launch-artifact-tail",
            operation_id=operation_id(),
        )
        payload = b"discarded-prefix\n" + b"x" * 5000 + b"\nexact-tail\n"
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = "artifact-" + uuid.uuid4().hex
        artifact_root = Path(self.temporary.name) / "artifacts"
        artifact_root.mkdir()
        (artifact_root / f"{artifact_id}-{digest}.blob").write_bytes(payload)
        self.store.append_result_chunk(
            grant.attempt_id,
            generation=grant.generation,
            chunk=AttemptResultChunk(
                chunk_id="artifact-tail",
                chunk_index=0,
                artifacts=(
                    ArtifactMetadata(
                        artifact_id,
                        "log",
                        f"test-artifact://{artifact_id}/{digest}",
                        digest,
                        len(payload),
                    ),
                ),
                reporter_complete=True,
            ),
        )
        adapter = StoreTestPlaneAdapter(self.store)

        resolved = adapter.artifact(
            run_id=submitted.run_id,
            repository_id="repo-tests",
            artifact_id=artifact_id,
        )

        self.assertTrue(resolved["ok"])
        self.assertNotIn("artifact_content", resolved)
        content = verified_text_artifact_content(
            resolved["artifact"], artifact_root=artifact_root
        )
        self.assertEqual(content["artifact_id"], artifact_id)
        self.assertEqual(content["sha256"], digest)
        self.assertEqual(content["size_bytes"], len(payload))
        self.assertTrue(content["truncated"])
        self.assertTrue(content["text"].endswith("exact-tail\n"))
        self.assertNotIn("discarded-prefix", content["text"])
        first = verified_artifact_chunk(
            resolved["artifact"],
            offset=0,
            length=17,
            artifact_root=artifact_root,
        )
        second = verified_artifact_chunk(
            resolved["artifact"],
            offset=17,
            length=1024 * 1024,
            artifact_root=artifact_root,
        )
        self.assertEqual(base64.b64decode(first["data_base64"]), payload[:17])
        self.assertEqual(base64.b64decode(second["data_base64"]), payload[17:])
        self.assertEqual(first["content_identity"], second["content_identity"])
        self.assertFalse(first["eof"])
        self.assertTrue(second["eof"])
        self.assertEqual(second["next_offset"], len(payload))

    def test_status_exposes_advancing_active_attempt_liveness(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id, seconds=30)
        self.store.acknowledge_launch(
            grant.attempt_id,
            generation=grant.generation,
            launch_ack_id="launch-liveness",
            operation_id=operation_id(),
        )
        adapter = StoreTestPlaneAdapter(self.store)
        before = adapter.status(
            run_id=submitted.run_id, repository_id="repo-tests"
        )
        self.clock.advance(5)
        self.store.record_attempt_progress(
            grant.attempt_id,
            generation=grant.generation,
            stdout_bytes=5 * 1024 * 1024,
            stderr_bytes=64,
            stdout_retained_bytes=4 * 1024 * 1024,
            stderr_retained_bytes=64,
            stdout_truncated=True,
            stderr_truncated=False,
            current_memory_bytes=8 * 1024 * 1024,
            last_output_at=self.clock(),
            observed_at=self.clock(),
        )
        self.store.heartbeat_attempt(
            grant.attempt_id,
            generation=grant.generation,
            lease_seconds=30,
            operation_id=operation_id(),
        )
        after = adapter.status(
            run_id=submitted.run_id, repository_id="repo-tests"
        )
        before_active = next(
            item["active_attempt"]
            for item in before["targets"]
            if item["target_name"] == "lint"
        )
        after_active = next(
            item["active_attempt"]
            for item in after["targets"]
            if item["target_name"] == "lint"
        )
        self.assertEqual(after_active["attempt_id"], grant.attempt_id)
        self.assertGreater(
            after_active["heartbeat_at"], before_active["heartbeat_at"]
        )
        self.assertGreater(
            after_active["lease_expires_at"], before_active["lease_expires_at"]
        )
        self.assertEqual(
            after_active["output_progress"]["stdout_bytes"],
            5 * 1024 * 1024,
        )
        self.assertEqual(
            after_active["output_progress"]["stdout_retained_bytes"],
            4 * 1024 * 1024,
        )
        self.assertTrue(after_active["output_progress"]["stdout_truncated"])
        self.assertEqual(after_active["output_progress"]["stderr_bytes"], 64)
        self.assertEqual(
            after_active["output_progress"]["current_memory_bytes"],
            8 * 1024 * 1024,
        )
        self.assertGreater(after["sampled_at"], before["sampled_at"])
        self.assertEqual(after_active["supervision"]["state"], "current")
        self.clock.advance(31)
        degraded = adapter.status(
            run_id=submitted.run_id, repository_id="repo-tests"
        )
        degraded_active = next(
            item["active_attempt"]
            for item in degraded["targets"]
            if item["target_name"] == "lint"
        )
        self.assertEqual(degraded_active["supervision"]["state"], "degraded")
        self.assertEqual(
            degraded_active["supervision"]["code"],
            "lease_expired_without_terminal_evidence",
        )

    def test_incomplete_reporting_is_not_published_as_success(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        result = self.store.terminalize_attempt(
            grant.attempt_id,
            generation=grant.generation,
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=1,
            operation_id=operation_id(),
        )
        self.assertEqual(result["state"], "incomplete")
        self.assertEqual(result["classification"], "incomplete_reporting")
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "incomplete")

    def test_rollups_preserve_parallel_test_time_above_one_hour(self) -> None:
        resources = {
            "lint": TargetResources(worktree_key="/tmp/lint"),
            "unit": TargetResources(worktree_key="/tmp/unit"),
        }
        # Two independent one-target plans are completed within the same hour.
        first = self.submit(resources=resources)
        first_grant = self.lease_lint(first.run_id)
        self.complete(
            first_grant,
            duration=2_200,
            cases=(CaseResult("lint-case", "lint", "passed", 2_200),),
        )
        # Finish the dependent target in the same hour too.
        unit = self.store.runnable_targets()[0]
        unit_grant = self.store.lease_target(
            unit.target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.complete(
            unit_grant,
            duration=2_200,
            cases=(CaseResult("unit-case", "unit", "passed", 2_200),),
        )
        rollup = self.store.rollups(repository_id="repo-tests", grain="hourly")[0]
        self.assertEqual(rollup["attempt_count"], 2)
        self.assertGreater(rollup["aggregate_test_seconds"], 3_600)
        self.assertEqual(rollup["passed_count"], 2)
        self.assertEqual(self.store.get_run(first.run_id)["state"], "succeeded")

    def test_history_sharding_requires_complete_history_and_clamps_to_ceiling(self) -> None:
        self.assertEqual(
            self.store.recommend_shard_count(
                repository_id="repo-tests", target_name="unit", ceiling=4
            ),
            1,
        )
        for index, marker in enumerate(("1", "2", "3")):
            selected = self.submit(
                selected_plan=plan(fingerprint=marker * 64),
                resources={
                    "lint": TargetResources(worktree_key=f"/tmp/lint-{index}"),
                    "unit": TargetResources(worktree_key=f"/tmp/unit-{index}"),
                },
            )
            self.complete(self.lease_lint(selected.run_id), duration=1)
            unit_target = self.store.runnable_targets()[0]
            unit = self.store.lease_target(
                unit_target.target_id,
                lease_owner="testd",
                operation_id=operation_id(),
            )
            self.complete(
                unit,
                duration=90,
                cases=tuple(
                    CaseResult(
                        f"unit-case-{case_index}",
                        f"unit case {case_index}",
                        "passed",
                        0.5,
                    )
                    for case_index in range(100)
                ),
            )
        self.assertEqual(
            self.store.recommend_shard_count(
                repository_id="repo-tests", target_name="unit", ceiling=4
            ),
            3,
        )
        self.assertEqual(
            self.store.recommend_shard_count(
                repository_id="repo-tests", target_name="unit", ceiling=2
            ),
            2,
        )

        adapter = StoreTestPlaneAdapter(self.store)
        next_plan = plan(fingerprint="4" * 64)
        adapter.register_plan(
            next_plan.to_document(),
            target_resources={
                "lint": TargetResources(worktree_key="/tmp/lint-next"),
                "unit": TargetResources(
                    estimated_seconds=90,
                    shard_count=4,
                    worktree_key="/tmp/unit-next",
                ),
            },
        )
        submitted = adapter.submit(
            plan_id=next_plan.plan_id,
            repository_id="repo-tests",
            operation_id=operation_id(),
            actor="codex:test",
            owner_uid=1001,
        )
        targets = self.store.get_run(str(submitted["run_id"]))["targets"]
        unit_targets = [target for target in targets if target["target_name"] == "unit"]
        self.assertEqual([target["shard_index"] for target in unit_targets], [0, 1, 2])
        self.assertTrue(all(target["shard_count"] == 3 for target in unit_targets))
        self.assertTrue(all(target["estimated_seconds"] == 30 for target in unit_targets))

    def test_rollups_separate_run_wall_queue_and_avoided_work(self) -> None:
        selected = self.submit(
            selected_plan=plan(fingerprint="c" * 64),
            resources={
                "lint": TargetResources(worktree_key="/tmp/lint"),
                "unit": TargetResources(worktree_key="/tmp/unit"),
            },
        )
        self.clock.advance(5)
        lint = self.lease_lint(selected.run_id)
        self.store.acknowledge_launch(
            lint.attempt_id,
            generation=lint.generation,
            launch_ack_id="launch-" + lint.attempt_id,
            operation_id=operation_id(),
        )
        self.clock.advance(10)
        self.store.append_result_chunk(
            lint.attempt_id,
            generation=lint.generation,
            chunk=AttemptResultChunk(
                chunk_id="chunk-" + lint.attempt_id,
                chunk_index=0,
                reporter_complete=True,
            ),
        )
        self.store.terminalize_attempt(
            lint.attempt_id,
            generation=lint.generation,
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=100,
            operation_id=operation_id(),
        )
        unit_target = self.store.runnable_targets()[0]
        unit = self.store.lease_target(
            unit_target.target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.store.acknowledge_launch(
            unit.attempt_id,
            generation=unit.generation,
            launch_ack_id="launch-" + unit.attempt_id,
            operation_id=operation_id(),
        )
        self.clock.advance(10)
        self.store.append_result_chunk(
            unit.attempt_id,
            generation=unit.generation,
            chunk=AttemptResultChunk(
                chunk_id="chunk-" + unit.attempt_id,
                chunk_index=0,
                reporter_complete=True,
            ),
        )
        self.store.terminalize_attempt(
            unit.attempt_id,
            generation=unit.generation,
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=100,
            operation_id=operation_id(),
        )
        no_work = self.submit(
            selected_plan=plan(
                mode=SourceMode.LIVE,
                fingerprint="d" * 64,
                changed=False,
            )
        )
        self.assertEqual(no_work.state, "succeeded")

        rollup = self.store.rollups(
            repository_id="repo-tests", grain="hourly"
        )[0]
        self.assertEqual(rollup["run_count"], 2)
        self.assertEqual(rollup["attempt_count"], 2)
        self.assertEqual(rollup["attempt_wall_seconds"], 200)
        self.assertEqual(rollup["aggregate_test_seconds"], 200)
        self.assertEqual(rollup["wall_seconds"], 20)
        self.assertEqual(rollup["queue_seconds"], 5)
        self.assertEqual(rollup["selected_target_count"], 2)
        self.assertEqual(rollup["eligible_target_count"], 4)
        self.assertEqual(rollup["avoided_target_count"], 2)
        detail = self.store.repository_rollup_detail(
            repository_id="repo-tests", grain="hourly", since=0
        )
        self.assertEqual(detail["efficiency"]["parallelism_ratio"], 10)
        self.assertEqual(detail["efficiency"]["selection_savings_ratio"], 0.5)

    def test_rollup_rebuild_is_cursor_bounded_and_resumes_after_interruption(self) -> None:
        def complete_run(fingerprint: str) -> None:
            submitted = self.submit(
                selected_plan=plan(fingerprint=fingerprint),
                resources={
                    "lint": TargetResources(worktree_key="/tmp/lint"),
                    "unit": TargetResources(worktree_key="/tmp/unit"),
                },
            )
            self.complete(self.lease_lint(submitted.run_id), duration=3)
            unit_target = self.store.runnable_targets()[0]
            unit = self.store.lease_target(
                unit_target.target_id,
                lease_owner="testd",
                operation_id=operation_id(),
            )
            self.complete(unit, duration=5)

        complete_run("1" * 64)
        self.clock.advance(3_700)
        complete_run("2" * 64)
        expected_hourly = self.store.rollups(
            repository_id="repo-tests", grain="hourly"
        )
        expected_daily = self.store.rollups(
            repository_id="repo-tests", grain="daily"
        )
        self.assertEqual(len(expected_hourly), 2)

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE test_rollup_hourly SET aggregate_test_seconds = 999999"
            )
            connection.execute(
                "UPDATE test_rollup_daily SET aggregate_test_seconds = 999999"
            )
            connection.commit()
        finally:
            connection.close()

        cursor = self.store.begin_rollup_rebuild()
        first = self.store.rebuild_rollup_batch(cursor, batch_size=1)
        self.assertEqual(first["processed"], 1)
        self.assertFalse(first["complete"])

        # The cursor is a process-independent checkpoint.  A replacement
        # store owner can resume without clearing already-retained rollups.
        replacement = UniversalTestStore.open(self.path, clock=self.clock)
        second = replacement.rebuild_rollup_batch(
            first["cursor"],  # type: ignore[arg-type]
            batch_size=1,
        )
        self.assertEqual(second["processed"], 1)
        self.assertTrue(second["complete"])
        self.assertEqual(
            replacement.rollups(repository_id="repo-tests", grain="hourly"),
            expected_hourly,
        )
        self.assertEqual(
            replacement.rollups(repository_id="repo-tests", grain="daily"),
            expected_daily,
        )

        forged = dict(second["cursor"])  # type: ignore[arg-type]
        forged["store_generation"] = "forged-generation"
        with self.assertRaisesRegex(TestStoreConflict, "generation changed"):
            replacement.rebuild_rollup_batch(forged, batch_size=1)

    def test_test_failure_blocks_later_wave_and_retains_failure_class(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        self.complete(grant, conclusion=AttemptConclusion.TEST_FAILED)
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "failed")
        self.assertEqual(run["failure_classification"], "test_failure")
        self.assertEqual(
            {target["target_name"]: target["state"] for target in run["targets"]},
            {"lint": "test_failed", "unit": "cancelled"},
        )

    def test_failed_only_retry_is_idempotent_and_preserves_exact_plan(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        self.complete(grant, conclusion=AttemptConclusion.TEST_FAILED)
        retry_operation = operation_id()
        retry = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry",
            failed_only=True,
            operation_id=retry_operation,
        )
        replay = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry",
            failed_only=True,
            operation_id=retry_operation,
        )
        self.assertEqual(retry, replay)
        source = self.store.get_run(submitted.run_id)
        retried = self.store.get_run(retry.run_id)
        self.assertEqual(source["plan_id"], retried["plan_id"])
        self.assertEqual(
            [target["target_name"] for target in retried["targets"]],
            ["lint", "unit"],
        )
        deduplicated = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry",
            failed_only=True,
            operation_id=operation_id(),
        )
        self.assertTrue(deduplicated.deduplicated)
        self.assertEqual(deduplicated.run_id, retry.run_id)

    def test_live_failed_only_retry_requires_fresh_plan_without_new_run(self) -> None:
        submitted = self.submit(selected_plan=plan(mode=SourceMode.LIVE))
        grant = self.lease_lint(submitted.run_id)
        self.complete(grant, conclusion=AttemptConclusion.TEST_FAILED)
        before = tuple(
            item["run_id"]
            for item in self.store.runs(repository_id="repo-tests", limit=50)
        )

        with self.assertRaisesRegex(
            LiveRetryReplanRequired,
            "fresh current-source plan",
        ):
            self.store.retry_run(
                submitted.run_id,
                actor="codex:retry-live",
                failed_only=True,
                operation_id=operation_id(),
            )

        after = tuple(
            item["run_id"]
            for item in self.store.runs(repository_id="repo-tests", limit=50)
        )
        self.assertEqual(after, before)

    def test_failed_only_retry_densifies_wave_after_succeeded_dependency(self) -> None:
        submitted = self.submit()
        lint = self.lease_lint(submitted.run_id)
        self.complete(lint)
        unit_target = next(
            target
            for target in self.store.runnable_targets()
            if target.run_id == submitted.run_id and target.target_name == "unit"
        )
        unit = self.store.lease_target(
            unit_target.target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.complete(unit, conclusion=AttemptConclusion.TEST_FAILED)

        retry = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry-downstream",
            failed_only=True,
            operation_id=operation_id(),
        )

        retried = self.store.get_run(retry.run_id)
        self.assertEqual(
            [
                (target["target_name"], target["wave_index"], target["state"])
                for target in retried["targets"]
            ],
            [("unit", 0, "queued")],
        )
        runnable = [
            target
            for target in self.store.runnable_targets()
            if target.run_id == retry.run_id
        ]
        self.assertEqual(
            [(target.target_name, target.wave_index) for target in runnable],
            [("unit", 0)],
        )
        queue = self.store.queue_status(repository_id="repo-tests")
        self.assertFalse(
            any(blocker["code"] == "dependency_wave" for blocker in queue["blockers"])
        )

    def test_evidence_policy_is_exact_snapshot_bounded_and_expiring(self) -> None:
        selected = plan()

        def complete_run(run_id: str) -> None:
            lint = self.lease_lint(run_id)
            self.complete(lint)
            unit_target = next(
                target
                for target in self.store.runnable_targets()
                if target.run_id == run_id
            )
            unit = self.store.lease_target(
                unit_target.target_id,
                lease_owner="testd",
                operation_id=operation_id(),
            )
            self.complete(unit)

        submitted = self.submit(selected_plan=selected)
        complete_run(submitted.run_id)
        policy_fingerprint = evidence_policy_fingerprint(
            selected.evidence_policies["release"]
        )
        automatic = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
        )
        self.assertFalse(automatic["satisfied"])
        self.assertFalse(automatic["reusable"])
        self.assertTrue(automatic["requires_consumption"])
        self.assertTrue(automatic["consumable"])
        attestation = self.store.issue_evidence_attestation(
            submitted.run_id,
            policy_name="release",
            policy_fingerprint=policy_fingerprint,
            required_targets=("lint", "unit"),
            max_age_seconds=60,
            operation_id=operation_id(),
        )
        self.assertTrue(attestation["satisfied"])
        consume_operation = operation_id()
        consumed = self.store.consume_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
            operation_id=consume_operation,
        )
        self.assertTrue(consumed["satisfied"])
        self.assertTrue(consumed["consumed"])
        self.assertEqual(consumed["run_id"], submitted.run_id)
        self.assertEqual(
            self.store.consume_evidence_policy(
                repository_id="repo-tests",
                snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
                policy_name="release",
                operation_id=consume_operation,
            ),
            consumed,
        )
        with self.assertRaisesRegex(TestStoreConflict, "different mutation"):
            self.store.consume_evidence_policy(
                repository_id="repo-tests",
                snapshot_id="snapshot-bbbbbbbbbbbbbbbb",
                policy_name="release",
                operation_id=consume_operation,
            )
        checked_after_use = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
        )
        self.assertFalse(checked_after_use["satisfied"])
        self.assertFalse(checked_after_use["consumable"])
        with self.assertRaisesRegex(TestStoreConflict, "no unconsumed"):
            self.store.consume_evidence_policy(
                repository_id="repo-tests",
                snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
                policy_name="release",
                operation_id=operation_id(),
            )

        fresh = self.submit(selected_plan=selected)
        complete_run(fresh.run_id)
        fresh_check = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
        )
        self.assertTrue(fresh_check["consumable"])
        fresh_consumed = self.store.consume_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
            operation_id=operation_id(),
        )
        self.assertEqual(fresh_consumed["run_id"], fresh.run_id)
        self.assertNotEqual(
            fresh_consumed["attestation_id"], consumed["attestation_id"]
        )

        expiring = self.submit(selected_plan=selected)
        complete_run(expiring.run_id)
        self.assertTrue(
            self.store.check_evidence_policy(
                repository_id="repo-tests",
                snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
                policy_name="release",
            )["consumable"]
        )
        wrong_snapshot = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-bbbbbbbbbbbbbbbb",
            policy_name="release",
        )
        self.assertFalse(wrong_snapshot["satisfied"])
        self.clock.advance(61)
        expired = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-aaaaaaaaaaaaaaaa",
            policy_name="release",
        )
        self.assertFalse(expired["satisfied"])
        self.assertFalse(expired["consumable"])
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM test_evidence_attestations"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM test_evidence_consumptions"
                ).fetchone()[0],
                2,
            )
        finally:
            connection.close()

    def test_reusable_evidence_remains_read_only_and_cannot_be_consumed(self) -> None:
        document = manifest_document()
        document["intents"]["handoff"] = {
            "source_mode": "immutable",
            "allow_reuse": True,
        }
        for target in document["targets"].values():
            target["intents"] = sorted({*target["intents"], "handoff"})
        document["evidence_policies"]["handoff"] = {
            "intent": "handoff",
            "required_targets": ["lint", "unit"],
            "max_age_seconds": 60,
            "allow_reuse": True,
        }
        manifest = parse_test_manifest(document)
        selected = create_test_plan(
            manifest,
            intent="handoff",
            source=SourceIdentity(
                mode=SourceMode.IMMUTABLE,
                repository_id="repo-tests",
                content_fingerprint="c" * 64,
                original_root="/home/example/project",
                snapshot_id="snapshot-cccccccccccccccc",
            ),
        )
        submitted = self.submit(selected_plan=selected)
        lint = self.lease_lint(submitted.run_id)
        self.complete(lint)
        unit_target = next(
            target
            for target in self.store.runnable_targets()
            if target.run_id == submitted.run_id
        )
        unit = self.store.lease_target(
            unit_target.target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.complete(unit)

        checked = self.store.check_evidence_policy(
            repository_id="repo-tests",
            snapshot_id="snapshot-cccccccccccccccc",
            policy_name="handoff",
        )
        self.assertTrue(checked["satisfied"])
        self.assertTrue(checked["reusable"])
        self.assertFalse(checked["requires_consumption"])
        with self.assertRaisesRegex(TestStoreConflict, "must be checked"):
            self.store.consume_evidence_policy(
                repository_id="repo-tests",
                snapshot_id="snapshot-cccccccccccccccc",
                policy_name="handoff",
                operation_id=operation_id(),
            )

    def test_reaper_requeues_only_never_launched_work(self) -> None:
        submitted = self.submit()
        leased = self.lease_lint(submitted.run_id, seconds=5)
        self.clock.advance(6)
        result = self.store.reap_expired_attempts()
        self.assertEqual(result["requeued_attempt_ids"], [leased.attempt_id])
        self.assertEqual(
            result["lease_expired_before_launch_attempt_ids"],
            [leased.attempt_id],
        )
        self.assertEqual(result["running_heartbeat_lost_attempt_ids"], [])
        self.assertEqual(
            result["outcomes"],
            [
                {
                    "attempt_id": leased.attempt_id,
                    "run_id": submitted.run_id,
                    "reason": "lease_expired_before_launch",
                    "requeued": True,
                }
            ],
        )
        first_evidence = self.store.get_run(submitted.run_id)[
            "lease_expiry_evidence"
        ]
        self.assertEqual(first_evidence["visible_count"], 1)
        self.assertFalse(first_evidence["truncated"])
        self.assertEqual(
            first_evidence["events"][0]["reason"],
            "lease_expired_before_launch",
        )
        self.assertTrue(first_evidence["events"][0]["requeued"])
        replacement = self.lease_lint(submitted.run_id, seconds=5)
        self.assertEqual(replacement.generation, 2)
        self.store.acknowledge_launch(
            replacement.attempt_id,
            generation=replacement.generation,
            launch_ack_id="launch-replacement",
            operation_id=operation_id(),
        )
        self.clock.advance(6)
        result = self.store.reap_expired_attempts()
        self.assertEqual(result["abandoned_attempt_ids"], [replacement.attempt_id])
        self.assertEqual(result["lease_expired_before_launch_attempt_ids"], [])
        self.assertEqual(
            result["running_heartbeat_lost_attempt_ids"],
            [replacement.attempt_id],
        )
        self.assertEqual(
            result["outcomes"][0]["reason"], "running_heartbeat_lost"
        )
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "abandoned")
        self.assertEqual(
            [item["reason"] for item in run["lease_expiry_evidence"]["events"]],
            ["lease_expired_before_launch", "running_heartbeat_lost"],
        )
        status = StoreTestPlaneAdapter(self.store).status(
            run_id=submitted.run_id,
            repository_id="repo-tests",
        )
        self.assertEqual(
            status["lease_expiry_evidence"], run["lease_expiry_evidence"]
        )
        expiry_events = [
            event
            for event in self.store.events(repository_id="repo-tests")
            if event["event_type"] == "test.attempt_lease_expired"
        ]
        self.assertEqual(
            [event["detail"]["reason"] for event in expiry_events],
            ["lease_expired_before_launch", "running_heartbeat_lost"],
        )
        self.assertIsNone(expiry_events[0]["detail"]["last_heartbeat_at"])
        self.assertIsNotNone(expiry_events[1]["detail"]["last_heartbeat_at"])
        with self.assertRaisesRegex(TestStoreConflict, "no longer active"):
            self.store.terminalize_attempt(
                replacement.attempt_id,
                generation=replacement.generation,
                conclusion=AttemptConclusion.SUCCEEDED,
                duration_seconds=1,
                operation_id=operation_id(),
            )

    def test_reaper_batches_overload_and_repeated_calls_converge_without_skips(
        self,
    ) -> None:
        attempt_ids: list[str] = []
        total = MAX_EXPIRED_ATTEMPTS_PER_REAP + 5
        for index in range(total):
            selected = plan(
                mode=SourceMode.LIVE,
                fingerprint=f"{index + 1:064x}",
            )
            submitted = self.submit(selected_plan=selected)
            target = next(
                item
                for item in self.store.runnable_targets()
                if item.run_id == submitted.run_id and item.target_name == "lint"
            )
            grant = self.store.lease_target(
                target.target_id,
                lease_owner="testd",
                lease_seconds=5,
                operation_id=operation_id(),
            )
            attempt_ids.append(grant.attempt_id)
        self.clock.advance(6)

        first = self.store.reap_expired_attempts()
        self.assertEqual(
            first["processed_attempt_count"], MAX_EXPIRED_ATTEMPTS_PER_REAP
        )
        self.assertEqual(first["batch_limit"], MAX_EXPIRED_ATTEMPTS_PER_REAP)
        self.assertTrue(first["more_expired"])
        self.assertIsNotNone(first["convergence_cursor"])
        self.assertEqual(
            first["convergence_cursor"]["attempt_id"],
            sorted(attempt_ids)[MAX_EXPIRED_ATTEMPTS_PER_REAP - 1],
        )
        self.assertEqual(
            first["requeued_attempt_ids"],
            sorted(attempt_ids)[:MAX_EXPIRED_ATTEMPTS_PER_REAP],
        )

        second = self.store.reap_expired_attempts()
        self.assertEqual(second["processed_attempt_count"], 5)
        self.assertFalse(second["more_expired"])
        self.assertEqual(
            second["convergence_cursor"]["attempt_id"], sorted(attempt_ids)[-1]
        )
        self.assertEqual(
            second["requeued_attempt_ids"],
            sorted(attempt_ids)[MAX_EXPIRED_ATTEMPTS_PER_REAP:],
        )
        self.assertEqual(
            set(first["requeued_attempt_ids"])
            | set(second["requeued_attempt_ids"]),
            set(attempt_ids),
        )
        self.assertFalse(
            set(first["requeued_attempt_ids"])
            & set(second["requeued_attempt_ids"])
        )

        converged = self.store.reap_expired_attempts()
        self.assertEqual(converged["processed_attempt_count"], 0)
        self.assertFalse(converged["more_expired"])
        self.assertIsNone(converged["convergence_cursor"])

    def test_run_lease_expiry_evidence_projection_is_bounded(self) -> None:
        submitted = self.submit()
        with self.store._transaction() as connection:
            for index in range(70):
                self.store._event(
                    connection,
                    event_type="test.attempt_lease_expired",
                    repository_id="repo-tests",
                    run_id=submitted.run_id,
                    attempt_id=f"attempt-bounded-{index:03d}",
                    detail={
                        "schema_version": 1,
                        "reason": "running_heartbeat_lost",
                        "previous_state": "running",
                        "requeued": False,
                        "observed_at": self.clock(),
                    },
                    created_at=self.clock(),
                )

        evidence = self.store.get_run(submitted.run_id)["lease_expiry_evidence"]
        self.assertEqual(evidence["visible_count"], 64)
        self.assertTrue(evidence["truncated"])
        self.assertEqual(len(evidence["events"]), 64)
        self.assertEqual(
            evidence["events"][0]["attempt_id"], "attempt-bounded-006"
        )
        self.assertEqual(
            evidence["events"][-1]["attempt_id"], "attempt-bounded-069"
        )

    def test_cancel_and_live_supersession_return_exact_active_attempts(self) -> None:
        submitted = self.submit()
        grant = self.lease_lint(submitted.run_id)
        result = self.store.request_cancel(
            submitted.run_id,
            actor="user@example.com",
            reason="manual stop",
            operation_id=operation_id(),
        )
        self.assertEqual(result["state"], "cancelling")
        self.assertEqual(result["active_attempt_ids"], [grant.attempt_id])

        live = self.submit(selected_plan=plan(mode=SourceMode.LIVE))
        superseded = self.store.mark_superseded(
            live.run_id,
            observed_source_fingerprint="b" * 64,
            operation_id=operation_id(),
        )
        self.assertEqual(superseded["state"], "superseded")
        with self.assertRaisesRegex(TestStoreConflict, "immutable"):
            self.store.mark_superseded(
                submitted.run_id,
                observed_source_fingerprint="b" * 64,
                operation_id=operation_id(),
            )


class TestPlaneServiceBoundaryTests(StoreFixture):
    class _Previewer:
        def __init__(self, selected) -> None:
            self.selected = selected
            self.calls: list[dict[str, object]] = []
            self.setup_calls: list[dict[str, object]] = []

        def preview_as_owner(self, **values):
            self.calls.append(dict(values))
            return self.selected.to_document()

        def setup_as_owner(self, **values):
            self.setup_calls.append(dict(values))
            return setup_document(str(values["repository_id"]))

    def test_adapter_routes_cancellation_through_injected_testd_engine(self) -> None:
        submitted = self.submit()
        calls: list[dict[str, object]] = []

        def cancel(**arguments):
            calls.append(dict(arguments))
            return {
                "run_id": submitted.run_id,
                "state": "cancelled",
                "active_attempt_ids": [],
                "cancelled_attempt_ids": ["attempt-exact"],
                "unresolved_attempt_ids": [],
            }

        adapter = StoreTestPlaneAdapter(self.store, canceller=cancel)
        operation = operation_id()
        result = adapter.cancel(
            run_id=submitted.run_id,
            repository_id="repo-tests",
            actor="codex:adapter",
            reason="stop exact run",
            operation_id=operation,
        )

        self.assertEqual(
            calls,
            [{
                "run_id": submitted.run_id,
                "actor": "codex:adapter",
                "reason": "stop exact run",
                "operation_id": operation,
            }],
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["cancelled_attempt_ids"], ["attempt-exact"])

    def test_plan_wire_codec_round_trips_and_rejects_tampering(self) -> None:
        selected = plan()
        document = selected.to_document()
        self.assertEqual(decode_test_plan_document(document), selected)
        tampered = copy.deepcopy(document)
        tampered["selected_targets"] = ["lint"]
        with self.assertRaisesRegex(TestStoreContractError, "cover"):
            decode_test_plan_document(tampered)
        tampered = copy.deepcopy(document)
        tampered["fingerprint"] = "f" * 64
        with self.assertRaisesRegex(TestStoreContractError, "identity"):
            decode_test_plan_document(tampered)

    def test_plan_wire_codec_round_trips_only_the_current_intent_policy(self) -> None:
        document = manifest_document()
        document["intents"]["handoff"] = {
            "source_mode": "immutable",
            "allow_reuse": True,
        }
        for target in document["targets"].values():
            target["intents"] = sorted({*target["intents"], "handoff"})
        document["evidence_policies"]["handoff"] = {
            "intent": "handoff",
            "required_targets": ["unit", "lint"],
            "max_age_seconds": 3_600,
            "allow_reuse": True,
        }
        manifest = parse_test_manifest(document)

        for intent in ("handoff", "release"):
            with self.subTest(intent=intent):
                selected = create_test_plan(
                    manifest,
                    intent=intent,
                    source=SourceIdentity(
                        mode=SourceMode.IMMUTABLE,
                        repository_id="repo-tests",
                        content_fingerprint=("c" if intent == "handoff" else "d")
                        * 64,
                        original_root="/home/example/project",
                        snapshot_id=f"snapshot-{intent}",
                    ),
                )
                self.assertEqual(tuple(selected.evidence_policies), (intent,))
                self.assertEqual(
                    decode_test_plan_document(selected.to_document()), selected
                )

    def test_adapter_is_the_bounded_broker_facing_store_owner(self) -> None:
        adapter = StoreTestPlaneAdapter(self.store)
        self.assertIsInstance(adapter, TestPlaneClient)
        selected = plan()
        registered = adapter.register_plan(selected.to_document())
        self.assertTrue(registered["registered"])
        self.assertEqual(registered["repository_id"], "repo-tests")
        self.assertEqual(
            adapter.plan_repository(
                plan_id=selected.plan_id,
                repository_id="repo-tests",
            ),
            "repo-tests",
        )
        self.assertFalse(adapter.register_plan(selected.to_document())["registered"])
        with self.assertRaisesRegex(TestStoreConflict, "does not match"):
            adapter.submit(
                plan_id=selected.plan_id,
                repository_id="repo-other",
                operation_id=operation_id(),
                actor="codex:adapter",
                owner_uid=1001,
            )
        submitted = adapter.submit(
            plan_id=selected.plan_id,
            repository_id="repo-tests",
            operation_id=operation_id(),
            actor="codex:adapter",
            owner_uid=1001,
        )
        with self.assertRaisesRegex(TestStoreConflict, "requested repository"):
            adapter.plan_repository(
                plan_id=selected.plan_id,
                repository_id="repo-other",
            )
        foreign_calls = (
            lambda: adapter.status(
                run_id=submitted["run_id"], repository_id="repo-other"
            ),
            lambda: adapter.summary(
                run_id=submitted["run_id"], repository_id="repo-other"
            ),
            lambda: adapter.failures(
                run_id=submitted["run_id"], repository_id="repo-other"
            ),
            lambda: adapter.artifacts(
                run_id=submitted["run_id"], repository_id="repo-other"
            ),
            lambda: adapter.artifact(
                run_id=submitted["run_id"],
                repository_id="repo-other",
                artifact_id="artifact-other",
            ),
            lambda: adapter.cases(
                run_id=submitted["run_id"], repository_id="repo-other"
            ),
            lambda: adapter.cancel(
                run_id=submitted["run_id"],
                repository_id="repo-other",
                actor="codex:adapter",
                reason="test",
                operation_id=operation_id(),
            ),
            lambda: adapter.retry(
                run_id=submitted["run_id"],
                repository_id="repo-other",
                actor="codex:adapter",
                failed_only=True,
                operation_id=operation_id(),
            ),
        )
        for invoke in foreign_calls:
            with self.assertRaises(TestStoreNotFound):
                invoke()
        self.assertEqual(
            self.store.get_run(str(submitted["run_id"]))["state"],
            "queued",
        )
        status = adapter.status(
            run_id=submitted["run_id"], repository_id="repo-tests"
        )
        self.assertEqual(status["state"], "queued")
        self.assertEqual(submitted["repository_id"], "repo-tests")
        self.assertEqual(status["progress"], {"completed_targets": 0, "total_targets": 2})
        cancelled = adapter.cancel(
            run_id=submitted["run_id"],
            repository_id="repo-tests",
            actor="codex:adapter",
            reason="test",
            operation_id=operation_id(),
        )
        self.assertEqual(cancelled["state"], "cancelled")

    def test_unregistered_plan_cannot_submit_after_testd_replacement(self) -> None:
        adapter = StoreTestPlaneAdapter(self.store)
        with self.assertRaisesRegex(TestStoreConflict, "not registered"):
            adapter.submit(
                plan_id=plan().plan_id,
                repository_id="repo-tests",
                operation_id=operation_id(),
                actor="codex:adapter",
                owner_uid=1001,
            )

    def test_registered_plan_survives_testd_adapter_replacement(self) -> None:
        selected = plan()
        first = StoreTestPlaneAdapter(self.store)
        with mock.patch.object(
            self.store,
            "recommend_shard_count",
            side_effect=lambda *, repository_id, target_name, ceiling: ceiling,
        ):
            first.register_plan(
                selected.to_document(),
                target_resources={
                    "lint": TargetResources(
                        estimated_seconds=17,
                        max_attempts=2,
                        worktree_key="/var/lib/devcoordinator-snapshots/exact",
                        exclusive_resources=("shared-cache",),
                    ),
                    "unit": TargetResources(
                        estimated_seconds=33,
                        shard_count=2,
                        max_attempts=3,
                        worktree_key="/var/lib/devcoordinator-snapshots/exact",
                        exclusive_resources=("database", "shared-cache"),
                    ),
                },
            )

        replacement = StoreTestPlaneAdapter(self.store)
        self.assertEqual(
            replacement.plan_repository(
                plan_id=selected.plan_id,
                repository_id="repo-tests",
            ),
            "repo-tests",
        )
        submitted = replacement.submit(
            plan_id=selected.plan_id,
            repository_id="repo-tests",
            operation_id=operation_id(),
            actor="codex:replacement",
            owner_uid=1001,
        )
        self.assertEqual(submitted["state"], "queued")
        targets = self.store.get_run(str(submitted["run_id"]))["targets"]
        self.assertEqual(len(targets), 3)
        self.assertEqual(
            {str(target["worktree_key"]) for target in targets},
            {"/var/lib/devcoordinator-snapshots/exact"},
        )
        unit_targets = [
            target for target in targets if target["target_name"] == "unit"
        ]
        self.assertEqual([target["shard_count"] for target in unit_targets], [2, 2])
        self.assertEqual(
            [target["max_attempts"] for target in unit_targets], [3, 3]
        )
        restored = self.store.get_plan_target_resources(selected.plan_id)
        self.assertIsNotNone(restored)
        self.assertEqual(
            restored["unit"].exclusive_resources,
            ("database", "shared-cache"),
        )

    def test_manual_preview_requires_broker_registration_after_authority_check(self) -> None:
        selected = plan()
        previewer = self._Previewer(selected)
        self.assertIsInstance(previewer, RepositoryUIDPlanPreviewer)
        adapter = StoreTestPlaneAdapter(self.store, previewer=previewer)
        result = adapter.preview(
            repository_id="repo-tests",
            intent="release",
            actor="user@example.com",
            owner_uid=1001,
        )
        self.assertEqual(result["plan"]["plan_id"], selected.plan_id)
        self.assertFalse(result["registered"])
        self.assertEqual(
            previewer.calls,
            [
                {
                    "repository_id": "repo-tests",
                    "intent": "release",
                    "actor": "user@example.com",
                    "owner_uid": 1001,
                    "temporary_root": None,
                    "requested_targets": (),
                    "execution_timeout_seconds": None,
                    "launch_timeout_seconds": 300,
                    "launch_deadline_monotonic": None,
                }
            ],
        )
        adapter.register_plan(result["plan"])
        replacement = StoreTestPlaneAdapter(self.store)
        self.assertEqual(
            replacement.plan_repository(
                plan_id=selected.plan_id,
                repository_id="repo-tests",
            ),
            "repo-tests",
        )

    def test_repository_setup_is_owner_delegated_and_sanitized(self) -> None:
        previewer = self._Previewer(plan())
        adapter = StoreTestPlaneAdapter(self.store, previewer=previewer)
        result = adapter.setup(repository_id="repo-tests", owner_uid=1001)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["target_graph"], {"lint": [], "unit": ["lint"]})
        self.assertEqual(result["input_coverage"]["targets_with_inputs"], 2)
        self.assertEqual(previewer.setup_calls, [
            {"repository_id": "repo-tests", "owner_uid": 1001}
        ])
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn("environment", encoded)

    def test_manual_preview_is_typed_unavailable_without_uid_helper(self) -> None:
        with self.assertRaises(TestPlanPreviewUnavailable) as captured:
            StoreTestPlaneAdapter(self.store).preview(
                repository_id="repo-tests",
                intent="manual",
                actor="user@example.com",
                owner_uid=1001,
            )
        self.assertEqual(captured.exception.code, "test_plan_preview_unavailable")

    def test_agent_summary_and_rollup_views_are_bounded_materialized_projections(self) -> None:
        adapter = StoreTestPlaneAdapter(self.store)
        selected = plan()
        adapter.register_plan(selected.to_document())
        submitted = adapter.submit(
            plan_id=selected.plan_id,
            repository_id="repo-tests",
            operation_id=operation_id(),
            actor="codex:adapter",
            owner_uid=1001,
        )
        lint = self.lease_lint(str(submitted["run_id"]))
        self.complete(lint, duration=2_000)
        unit_target = self.store.runnable_targets()[0]
        unit = self.store.lease_target(
            unit_target.target_id,
            lease_owner="testd",
            operation_id=operation_id(),
        )
        self.complete(unit, duration=2_000)
        summary = adapter.summary(
            run_id=str(submitted["run_id"]),
            repository_id="repo-tests",
        )
        self.assertLessEqual(
            len(json.dumps(summary, separators=(",", ":")).encode("utf-8")),
            8 * 1024,
        )
        self.assertEqual(summary["counts"]["attempts"], 2)
        fleet = adapter.fleet_overview(grain="hourly", since=0)
        self.assertEqual(fleet["repositories"][0]["repository_id"], "repo-tests")
        self.assertGreater(fleet["repositories"][0]["aggregate_test_seconds"], 3_600)
        self.assertTrue(fleet["cells"])
        detail = adapter.repository_detail(
            repository_id="repo-tests", grain="hourly", since=0
        )
        self.assertGreater(detail["totals"]["aggregate_test_seconds"], 3_600)


def candidate(
    identifier: str,
    *,
    uid: int,
    repo: str,
    worktree: str | None = None,
    priority: int = 0,
    estimated: float = 1,
    exclusive: tuple[str, ...] = (),
) -> RunnableTarget:
    return RunnableTarget(
        target_id=identifier,
        run_id="run-" + identifier,
        repository_id=repo,
        owner_uid=uid,
        priority=priority,
        queued_at=1,
        target_name="unit",
        wave_index=0,
        shard_index=0,
        shard_count=1,
        estimated_seconds=estimated,
        worktree_key=worktree or "/work/" + identifier,
        source_mode="live",
        exclusive_resources=exclusive,
        memory_estimate_mib=512,
        memory_estimate_source="learned_peak",
        memory_sample_count=1,
    )


class WeightedFairSchedulerTests(unittest.TestCase):
    def scheduler(
        self, *, total_mib: int = 65_536, available_mib: int = 65_536
    ) -> WeightedFairScheduler:
        return WeightedFairScheduler(
            memory_probe=lambda: HostMemorySnapshot(
                total_mib=total_mib,
                available_mib=available_mib,
                observed_at=1.0,
            )
        )

    def test_weighted_fairness_interleaves_uid_and_repository(self) -> None:
        scheduler = self.scheduler()
        decision = scheduler.select(
            (
                candidate("a1", uid=1, repo="repo-a"),
                candidate("a2", uid=1, repo="repo-a"),
                candidate("b1", uid=2, repo="repo-b"),
                candidate("b2", uid=2, repo="repo-b"),
            ),
            launch_batch=4,
        )
        self.assertEqual(
            [item.owner_uid for item in decision.selected], [1, 2, 1, 2]
        )

    def test_admission_enforces_worktree_exclusive_and_live_memory(self) -> None:
        scheduler = self.scheduler(total_mib=8_192, available_mib=1_800)
        active = (
            ActiveAllocation(
                "attempt-existing",
                "target-existing",
                "repo-a",
                1,
                "/work/shared",
                "live",
                ("database",),
                current_memory_bytes=512 * 1024 * 1024,
            ),
        )
        decision = scheduler.select(
            (
                candidate("worktree", uid=2, repo="repo-b", worktree="/work/shared"),
                candidate("exclusive", uid=2, repo="repo-b", exclusive=("database",)),
                candidate("admitted", uid=2, repo="repo-b"),
                candidate("capacity", uid=3, repo="repo-c"),
            ),
            active=active,
        )
        self.assertEqual([item.target_id for item in decision.selected], ["admitted"])
        reasons = {item.target_id: item.reason for item in decision.rejected}
        self.assertEqual(reasons["worktree"], "exact_worktree_busy")
        self.assertEqual(reasons["exclusive"], "exclusive_resource_busy")
        self.assertEqual(reasons["capacity"], "host_memory")

    def test_cpu_and_pid_declarations_are_absent_from_admission(self) -> None:
        scheduler = self.scheduler()
        extreme = candidate("extreme", uid=1, repo="repo-a")
        decision = scheduler.select((extreme,), launch_batch=1)
        self.assertEqual([item.target_id for item in decision.selected], ["extreme"])
        self.assertEqual(decision.rejected, ())
        self.assertFalse(
            {"cpu_millis", "memory_mib", "pids"} & set(extreme.__dict__)
        )

    def test_never_seen_targets_are_not_serialized_when_memory_is_available(self) -> None:
        scheduler = self.scheduler(total_mib=16_384, available_mib=8_192)
        first = candidate("cold-a", uid=1, repo="repo-a")
        second = candidate("cold-b", uid=2, repo="repo-b")
        first = RunnableTarget(
            **{**first.__dict__, "memory_sample_count": 0,
               "memory_estimate_source": "cold_start_default"}
        )
        second = RunnableTarget(
            **{**second.__dict__, "memory_sample_count": 0,
               "memory_estimate_source": "cold_start_default"}
        )

        decision = scheduler.select((first, second), launch_batch=2)

        self.assertEqual(
            {item.target_id for item in decision.selected}, {"cold-a", "cold-b"}
        )
        self.assertEqual(decision.rejected, ())

    def test_immutable_targets_share_a_snapshot_without_false_worktree_serialization(self) -> None:
        scheduler = self.scheduler()
        shared_snapshot = "/var/lib/devcoordinator-testd/snapshots/content-1"
        first = candidate("immutable-a", uid=1, repo="repo-a", worktree=shared_snapshot)
        second = candidate("immutable-b", uid=1, repo="repo-a", worktree=shared_snapshot)
        first = RunnableTarget(**{**first.__dict__, "source_mode": "immutable"})
        second = RunnableTarget(**{**second.__dict__, "source_mode": "immutable"})

        decision = scheduler.select((first, second), launch_batch=2)

        self.assertEqual(
            [item.target_id for item in decision.selected],
            ["immutable-a", "immutable-b"],
        )
        self.assertEqual(decision.rejected, ())

    def test_active_immutable_attempt_does_not_block_another_snapshot_target(self) -> None:
        scheduler = self.scheduler()
        shared_snapshot = "/var/lib/devcoordinator-testd/snapshots/content-1"
        active = ActiveAllocation(
            "attempt-existing",
            "target-existing",
            "repo-a",
            1,
            shared_snapshot,
            "immutable",
        )
        pending = candidate(
            "immutable-next", uid=1, repo="repo-a", worktree=shared_snapshot
        )
        pending = RunnableTarget(
            **{**pending.__dict__, "source_mode": "immutable"}
        )

        decision = scheduler.select((pending,), active=(active,))

        self.assertEqual([item.target_id for item in decision.selected], ["immutable-next"])

    def test_active_commitment_reserves_only_memory_not_yet_in_memavailable(self) -> None:
        scheduler = self.scheduler(total_mib=8_192, available_mib=2_500)
        active = ActiveAllocation(
            "attempt-ramping",
            "target-ramping",
            "repo-a",
            1,
            "/work/ramping",
            "immutable",
            memory_commitment_mib=1_024,
            current_memory_bytes=128 * 1024 * 1024,
        )
        later = candidate("later", uid=2, repo="repo-b")
        later = RunnableTarget(
            **{**later.__dict__, "memory_estimate_mib": 600}
        )

        decision = scheduler.select((later,), active=(active,))

        self.assertEqual(decision.selected, ())
        self.assertEqual(decision.active_memory_reservation_mib, 896)
        rejection = decision.rejected[0]
        self.assertEqual(rejection.reason, "host_memory")
        self.assertEqual(rejection.available_mib, 580)

    def test_realized_active_memory_is_not_double_counted(self) -> None:
        scheduler = self.scheduler(total_mib=8_192, available_mib=2_500)
        active = ActiveAllocation(
            "attempt-established",
            "target-established",
            "repo-a",
            1,
            "/work/established",
            "immutable",
            memory_commitment_mib=1_024,
            current_memory_bytes=800 * 1024 * 1024,
        )
        later = candidate("later-large", uid=2, repo="repo-b")
        later = RunnableTarget(
            **{**later.__dict__, "memory_estimate_mib": 1_200}
        )

        decision = scheduler.select((later,), active=(active,))

        self.assertEqual(
            [item.target_id for item in decision.selected], ["later-large"]
        )
        self.assertEqual(decision.active_memory_reservation_mib, 224)


class DurableAttemptSpoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.spool = DurableAttemptSpool.create(Path(self.temporary.name) / "spool")

    def envelope(self) -> AttemptExitEnvelope:
        return AttemptExitEnvelope(
            envelope_id="exit-1",
            attempt_id="attempt-1",
            generation=1,
            operation_id=str(uuid.uuid4()),
            conclusion=AttemptConclusion.SUCCEEDED,
            duration_seconds=1.5,
            result_chunk_ids=("chunk-1",),
            peak_memory_bytes=64 * 1024 * 1024,
            cpu_seconds=1.25,
        )

    def test_open_initializes_every_queue_for_a_fresh_private_root(self) -> None:
        root = Path(self.temporary.name) / "fresh-spool"
        root.mkdir(mode=0o700)

        spool = DurableAttemptSpool.open(root)

        self.assertEqual(
            {path.name for path in root.iterdir()},
            {
                "active",
                "pending",
                "processed",
                "terminal-conflicts",
                "result-pending",
                "result-processed",
            },
        )
        spool.verify()

    def test_resource_measurements_round_trip_and_unavailable_stays_null(self) -> None:
        measured = AttemptExitEnvelope.from_document(self.envelope().to_document())
        self.assertEqual(measured.peak_memory_bytes, 64 * 1024 * 1024)
        self.assertEqual(measured.cpu_seconds, 1.25)

        unavailable = AttemptExitEnvelope(
            envelope_id="exit-null-usage",
            attempt_id="attempt-null-usage",
            generation=1,
            operation_id=str(uuid.uuid4()),
            conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED,
            duration_seconds=0.0,
        )
        document = unavailable.to_document()
        self.assertIsNone(document["peak_memory_bytes"])
        self.assertIsNone(document["cpu_seconds"])
        self.assertIsNone(
            AttemptExitEnvelope.from_document(document).peak_memory_bytes
        )

    def test_failed_import_is_retained_and_successful_replay_removes_it(self) -> None:
        envelope = self.envelope()
        first_path = self.spool.append(envelope)
        self.assertEqual(self.spool.append(envelope), first_path)
        failed = self.spool.replay(lambda _value: (_ for _ in ()).throw(RuntimeError("down")))
        self.assertEqual(len(failed["failed"]), 1)
        self.assertEqual(len(self.spool.pending_envelopes()), 1)
        imported: list[str] = []
        success = self.spool.replay(lambda value: imported.append(value.attempt_id))
        self.assertEqual(imported, ["attempt-1"])
        self.assertEqual(success["imported_envelope_ids"], ["exit-1"])
        self.assertEqual(self.spool.pending_envelopes(), ())

    def test_priority_replay_bypasses_an_older_full_page(self) -> None:
        paths: dict[str, Path] = {}
        for index in range(3):
            envelope = AttemptExitEnvelope(
                envelope_id=f"exit-{index}",
                attempt_id=f"attempt-{index}",
                generation=1,
                operation_id=str(uuid.uuid4()),
                conclusion=AttemptConclusion.SUCCEEDED,
                duration_seconds=1.0,
            )
            paths[self.spool.append(envelope).name] = envelope
        priority_name = sorted(paths)[-1]
        imported: list[str] = []

        replay = self.spool.replay(
            lambda value: imported.append(value.attempt_id),
            limit=2,
            priority_names=(priority_name,),
        )

        self.assertEqual(imported[0], paths[priority_name].attempt_id)
        self.assertEqual(len(replay["imported_envelope_ids"]), 2)
        self.assertEqual(len(self.spool.pending_envelopes()), 1)

    def test_conflicting_duplicate_terminal_identity_leaves_one_hot_copy(self) -> None:
        operation = str(uuid.uuid4())
        first = AttemptExitEnvelope(
            envelope_id="exit-conflicting-retry",
            attempt_id="attempt-conflicting-retry",
            generation=1,
            operation_id=operation,
            conclusion=AttemptConclusion.CANCELLED,
            duration_seconds=1.0,
        )
        second = AttemptExitEnvelope(
            envelope_id=first.envelope_id,
            attempt_id=first.attempt_id,
            generation=first.generation,
            operation_id=first.operation_id,
            conclusion=first.conclusion,
            duration_seconds=2.0,
        )
        self.spool.append(first)
        self.spool.append(second)
        imported: list[str] = []

        def unavailable(value: AttemptExitEnvelope) -> None:
            imported.append(value.envelope_id)
            raise RuntimeError("still unavailable")

        replay = self.spool.replay(unavailable)

        self.assertEqual(imported, [first.envelope_id])
        self.assertEqual(replay["imported_envelope_ids"], [])
        self.assertEqual(
            replay["quarantined_conflicting_envelope_ids"],
            [first.envelope_id],
        )
        self.assertEqual(len(self.spool.pending_envelopes()), 1)
        self.assertEqual(
            len(tuple(self.spool.terminal_conflicts.glob("*.json"))), 1
        )

    def test_digest_tampering_fails_closed_without_deleting_evidence(self) -> None:
        path = self.spool.append(self.envelope())
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
        result = self.spool.replay(lambda _value: None)
        self.assertEqual(result["failed"][0]["error_type"], "TestStoreContractError")
        self.assertTrue(path.exists())

    def test_legacy_bearer_envelope_is_not_a_supported_runtime_contract(self) -> None:
        document = self.envelope().to_document()
        document["schema_version"] = 1
        document["lease_token"] = "retired-secret"
        with self.assertRaisesRegex(TestStoreContractError, "fields are invalid"):
            AttemptExitEnvelope.from_document(document)


if __name__ == "__main__":
    unittest.main()
