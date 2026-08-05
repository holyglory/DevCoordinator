from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp
from devcoordinator.worker_supervision import (
    WorkerCircuitOpen,
    WorkerLaunchFenced,
    WorkerSupervision,
    WorkerSupervisionConflict,
)


class MutableClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class WorkerSupervisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        self.clock = MutableClock()
        self.store = AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        )
        self.host_id = self.store.ensure_local_host()
        self.repo_id = self._insert_repository("project", self.project)
        self.server_id = self._insert_server(self.repo_id, "worker")
        self.service = WorkerSupervision(self.store, clock=self.clock)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _insert_repository(self, name: str, root: Path) -> str:
        timestamp = utc_timestamp(self.clock.value)
        repo_id = deterministic_id("test-worker-repository", self.host_id, name)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                """,
                (repo_id, self.host_id, str(root), name, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'test', ?)
                """,
                (repo_id, timestamp),
            )
        return repo_id

    def _insert_server(self, repo_id: str, name: str) -> str:
        timestamp = utc_timestamp(self.clock.value)
        server_id = deterministic_id("test-worker", repo_id, name)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, role, cwd,
                    health_url_template, log_path, definition_fingerprint,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'worker', ?, NULL, ?, ?, 0, ?, ?)
                """,
                (
                    server_id,
                    repo_id,
                    name,
                    str(self.project),
                    str(self.root / f"{name}.log"),
                    f"sha256:{name}",
                    timestamp,
                    timestamp,
                ),
            )
            connection.executemany(
                """
                INSERT INTO server_command_arguments(
                    server_definition_id, ordinal, argument
                ) VALUES (?, ?, ?)
                """,
                ((server_id, 0, "python3"), (server_id, 1, f"{name}.py")),
            )
            connection.execute(
                """
                INSERT INTO server_environment(server_definition_id, name, value)
                VALUES (?, 'WORKER_TEST', '1')
                """,
                (server_id,),
            )
        return server_id

    def _operation(self, suffix: str, *, repo_id: str | None = None) -> str:
        target_repo = self.repo_id if repo_id is None else repo_id
        operation_id = deterministic_id("test-worker-operation", suffix)
        timestamp = utc_timestamp(self.clock.value)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'worker.test', 'running', 'test',
                          0, ?, ?, 'test-agent', ?, ?)
                """,
                (
                    operation_id,
                    target_repo,
                    deterministic_id("test-operation-fingerprint", suffix),
                    os.geteuid(),
                    timestamp,
                    timestamp,
                ),
            )
        return operation_id

    def _configure_and_start(
        self,
        *,
        server_id: str | None = None,
        keep_alive: bool = True,
        crash_limit: int = 10,
        crash_window_seconds: int = 300,
        suffix: str = "start",
    ) -> dict[str, object]:
        target = self.server_id if server_id is None else server_id
        self.service.configure_policy(
            server_definition_id=target,
            actor="test-agent",
            execution_uid=os.geteuid(),
            keep_alive=keep_alive,
            crash_limit=crash_limit,
            crash_window_seconds=crash_window_seconds,
        )
        operation_id = self._operation(suffix)
        return self.service.request_start(
            server_definition_id=target,
            actor="test-agent",
            operation_id=operation_id,
        )

    def _fence_candidate(
        self, epoch: str = "supervisor-1", *, server_id: str | None = None
    ) -> dict[str, object]:
        target = self.server_id if server_id is None else server_id
        candidates = self.service.fence_startup(supervisor_epoch=epoch)
        return next(
            candidate
            for candidate in candidates
            if candidate["server_definition_id"] == target
        )

    def _begin(
        self,
        candidate: dict[str, object],
        suffix: str,
    ) -> dict[str, object]:
        return self.service.begin_attempt(
            server_definition_id=str(candidate["server_definition_id"]),
            begin_request_id=f"begin-{suffix}",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            expected_definition_generation=int(
                candidate["definition_generation"]
            ),
            expected_policy_generation=int(candidate["policy_generation"]),
            expected_supervisor_generation=int(
                candidate["supervisor_generation"]
            ),
        )

    def _launch_and_exit(
        self,
        candidate: dict[str, object],
        suffix: str,
        *,
        at: float,
    ) -> dict[str, object]:
        self.clock.value = at
        attempt = self._begin(candidate, suffix)
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id=f"launch-{suffix}",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=10_000 + int(suffix),
            process_start_time=f"process-start-{suffix}",
            process_fingerprint=f"process-fingerprint-{suffix}",
        )
        return self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id=f"exit-{suffix}",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=1,
            occurred_at_epoch=at,
        )

    def test_tenth_crash_at_inclusive_window_boundary_trips(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        times = [1_000.0, *[1_001.0 + index for index in range(8)], 1_300.0]
        results = [
            self._launch_and_exit(candidate, str(index), at=at)
            for index, at in enumerate(times, start=1)
        ]
        self.assertEqual(len(results), 10)
        self.assertEqual(results[-2]["crash_count_in_window"], 9)
        self.assertFalse(results[-2]["breaker_tripped_now"])
        self.assertTrue(results[-1]["breaker_tripped_now"])
        self.assertEqual(results[-1]["crash_count_in_window"], 10)
        self.assertFalse(results[-1]["restart_allowed"])
        policy = self.service.policy(self.server_id)
        self.assertEqual(policy["breaker_state"], "tripped")
        self.assertEqual(policy["supervisor_state"], "tripped")
        self.assertEqual(policy["last_trip_attempt_id"], results[-1]["attempt_id"])
        self.assertEqual(policy["last_trip_event_id"], results[-1]["crash_event_id"])

    def test_crash_older_than_window_boundary_does_not_trip(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        times = [1_000.0, *[1_001.0 + index for index in range(8)], 1_300.001]
        result: dict[str, object] | None = None
        for index, at in enumerate(times, start=1):
            result = self._launch_and_exit(candidate, str(index), at=at)
        self.assertIsNotNone(result)
        self.assertEqual(result["crash_count_in_window"], 9)
        self.assertFalse(result["breaker_tripped_now"])
        self.assertTrue(result["restart_allowed"])
        self.assertEqual(self.service.policy(self.server_id)["breaker_state"], "armed")

    def test_explicit_rearm_is_required_and_preserves_trip_evidence(self) -> None:
        self._configure_and_start(crash_limit=1)
        candidate = self._fence_candidate()
        crash = self._launch_and_exit(candidate, "1", at=1_000.0)
        tripped = self.service.policy(self.server_id)
        blocked_operation = self._operation("blocked-start")
        with self.assertRaises(WorkerCircuitOpen):
            self.service.request_start(
                server_definition_id=self.server_id,
                actor="test-agent",
                operation_id=blocked_operation,
            )
        rearm_operation = self._operation("explicit-rearm")
        rearmed = self.service.request_start(
            server_definition_id=self.server_id,
            actor="test-agent",
            operation_id=rearm_operation,
            rearm=True,
            expected_generation=int(tripped["generation"]),
        )
        self.assertEqual(rearmed["breaker_state"], "armed")
        self.assertEqual(rearmed["desired_state"], "running")
        self.assertEqual(rearmed["last_trip_attempt_id"], crash["attempt_id"])
        self.assertEqual(rearmed["last_trip_event_id"], crash["crash_event_id"])
        self.assertEqual(rearmed["last_rearm_operation_id"], rearm_operation)
        self.assertEqual(len(self.service.fence_startup(supervisor_epoch="supervisor-2")), 1)

    def test_intentional_stop_does_not_count_as_crash(self) -> None:
        self._configure_and_start(crash_limit=1)
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "intentional")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-intentional",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_001,
            process_start_time="intentional-start",
            process_fingerprint="intentional-fingerprint",
        )
        stop_operation = self._operation("intentional-stop")
        stopped = self.service.request_stop(
            server_definition_id=self.server_id,
            actor="test-agent",
            operation_id=stop_operation,
        )
        self.assertEqual(stopped["supervisor_state"], "stopping")
        exit_result = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-intentional",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="signal",
            exit_signal=15,
            occurred_at_epoch=1_001.0,
        )
        self.assertEqual(exit_result["exit_classification"], "intentional")
        self.assertTrue(exit_result["expected_exit"])
        self.assertFalse(exit_result["counts_toward_breaker"])
        self.assertIsNone(exit_result["crash_event_id"])
        policy = self.service.policy(self.server_id)
        self.assertEqual(policy["breaker_state"], "armed")
        self.assertEqual(policy["supervisor_state"], "stopped")

    def test_keep_alive_toggle_does_not_stop_or_replace_active_attempt(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "keep-alive-toggle")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-keep-alive-toggle",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_023,
            process_start_time="keep-alive-toggle-start",
            process_fingerprint="keep-alive-toggle-fingerprint",
        )
        before = self.service.policy(self.server_id)
        disabled = self.service.configure_policy(
            server_definition_id=self.server_id,
            actor="test-agent",
            execution_uid=os.geteuid(),
            keep_alive=False,
            crash_limit=int(before["crash_limit"]),
            crash_window_seconds=int(before["crash_window_seconds"]),
            expected_generation=int(before["generation"]),
            operation_id=self._operation("keep-alive-toggle"),
        )
        self.assertFalse(disabled["keep_alive"])
        self.assertEqual(disabled["supervisor_state"], "running")
        self.assertEqual(disabled["current_attempt_id"], launched["attempt_id"])
        exit_result = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-keep-alive-toggle",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=2,
            occurred_at_epoch=1_006.0,
        )
        self.assertEqual(exit_result["exit_classification"], "stale_generation")
        self.assertFalse(exit_result["restart_allowed"])
        self.assertFalse(exit_result["counts_toward_breaker"])

    def test_launch_and_exit_keep_the_canonical_worker_observation_current(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "observation")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-observation",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_021,
            process_start_time="observation-start",
            process_fingerprint="observation-fingerprint",
        )
        with self.store.read_transaction() as connection:
            observation = connection.execute(
                """
                SELECT lifecycle, pid, process_start_time, process_fingerprint,
                       health_classification, health_ok, stopped_at
                FROM server_observations
                WHERE server_definition_id = ?
                """,
                (self.server_id,),
            ).fetchone()
        self.assertIsNotNone(observation)
        self.assertEqual(observation["lifecycle"], "running")
        self.assertEqual(observation["pid"], 20_021)
        self.assertEqual(observation["process_start_time"], "observation-start")
        self.assertEqual(
            observation["process_fingerprint"], "observation-fingerprint"
        )
        self.assertEqual(
            observation["health_classification"], "supervised_process_running"
        )
        self.assertEqual(observation["health_ok"], 1)
        self.assertIsNone(observation["stopped_at"])

        self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-observation",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=9,
            occurred_at_epoch=1_004.0,
        )
        with self.store.read_transaction() as connection:
            stopped = connection.execute(
                """
                SELECT lifecycle, pid, process_start_time, process_fingerprint,
                       health_classification, health_ok, stopped_at,
                       stopped_reason
                FROM server_observations
                WHERE server_definition_id = ?
                """,
                (self.server_id,),
            ).fetchone()
        self.assertEqual(stopped["lifecycle"], "stopped")
        self.assertIsNone(stopped["pid"])
        self.assertIsNone(stopped["process_start_time"])
        self.assertIsNone(stopped["process_fingerprint"])
        self.assertEqual(stopped["health_classification"], "crash")
        self.assertEqual(stopped["health_ok"], 0)
        self.assertIsNotNone(stopped["stopped_at"])
        self.assertIn("retained attempt log", stopped["stopped_reason"])

    def test_duplicate_exit_replay_returns_same_event_and_artifact(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "replay")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-replay",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_002,
            process_start_time="replay-start",
            process_fingerprint="replay-fingerprint",
        )
        artifact = {
            "artifact_id": "artifact-replay",
            "path": str(self.root / "worker-crash.log"),
            "sha256": "a" * 64,
        }
        first = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-replay",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=17,
            log_artifact=artifact,
            occurred_at_epoch=1_002.0,
        )
        self.clock.value = 9_999.0
        replay = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-replay",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=17,
            log_artifact=artifact,
        )
        self.assertEqual(first["exit_fingerprint"], replay["exit_fingerprint"])
        self.assertEqual(first["crash_event_id"], replay["crash_event_id"])
        self.assertEqual(replay["log_artifact"], artifact)
        self.assertIs(replay["restart_allowed"], True)

    def test_exit_replay_keeps_original_restart_decision_after_manual_rearm(self) -> None:
        self._configure_and_start(crash_limit=1)
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "stable-decision")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-stable-decision",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_022,
            process_start_time="stable-decision-start",
            process_fingerprint="stable-decision-fingerprint",
        )
        first = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-stable-decision",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=1,
            occurred_at_epoch=1_005.0,
        )
        self.assertFalse(first["restart_allowed"])
        self.assertTrue(first["breaker_tripped_now"])
        self.assertEqual(first["crash_count_in_window"], 1)
        tripped = self.service.policy(self.server_id)
        self.service.request_start(
            server_definition_id=self.server_id,
            actor="test-agent",
            operation_id=self._operation("stable-decision-rearm"),
            rearm=True,
            expected_generation=int(tripped["generation"]),
        )

        replay = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-stable-decision",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=1,
            occurred_at_epoch=1_005.0,
        )
        self.assertTrue(replay["exit_decision_known"])
        self.assertFalse(replay["restart_allowed"])
        self.assertTrue(replay["breaker_tripped_now"])
        self.assertEqual(replay["crash_count_in_window"], 1)
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE event_kind = 'worker.crashed'"
                ).fetchone()[0],
                1,
            )

    def test_inventory_projects_keep_alive_breaker_and_crash_log_evidence(self) -> None:
        self._configure_and_start(crash_limit=1)
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "inventory")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-inventory",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=20_020,
            process_start_time="inventory-start",
            process_fingerprint="inventory-fingerprint",
        )
        occurred_at = time.time()
        artifact = {
            "artifact_id": "artifact-inventory",
            "path": str(self.root / "inventory-crash.log"),
            "sha256": "b" * 64,
        }
        self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-inventory",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=23,
            log_artifact=artifact,
            occurred_at_epoch=occurred_at,
        )

        graph = self.store.inventory_v2()
        compatibility = next(
            item
            for item in graph["v1_compatibility"]["servers"]
            if item["id"] == self.server_id
        )
        normalized = next(
            item
            for item in graph["resources"]["servers"]
            if item["server_definition_id"] == self.server_id
        )
        for item in (compatibility, normalized):
            supervision = item["supervision"]
            self.assertTrue(supervision["keep_alive"])
            self.assertEqual(supervision["state"], "tripped")
            self.assertEqual(supervision["breaker"]["crash_count_in_window"], 1)
            self.assertEqual(supervision["breaker"]["crash_limit"], 1)
            self.assertEqual(supervision["last_attempt"]["exit_code"], 23)
            self.assertEqual(supervision["last_attempt"]["log"], artifact)
            self.assertEqual(len(supervision["recent_crashes"]), 1)

    def test_old_supervisor_exit_is_traced_but_cannot_trip_new_generation(self) -> None:
        self._configure_and_start(crash_limit=1)
        old = self._fence_candidate("supervisor-old")
        attempt = self._begin(old, "old")
        launched = self.service.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id="launch-old",
            supervisor_epoch="supervisor-old",
            supervisor_generation=int(old["supervisor_generation"]),
            pid=20_003,
            process_start_time="old-start",
            process_fingerprint="old-fingerprint",
        )
        self.assertEqual(
            self.service.fence_startup(supervisor_epoch="supervisor-new"), []
        )
        result = self.service.record_attempt_exit(
            attempt_id=str(launched["attempt_id"]),
            exit_report_id="exit-old",
            supervisor_epoch="supervisor-old",
            supervisor_generation=int(old["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=2,
            occurred_at_epoch=1_003.0,
        )
        self.assertEqual(result["exit_classification"], "stale_generation")
        self.assertFalse(result["counts_toward_breaker"])
        self.assertIsNotNone(result["crash_event_id"])
        policy = self.service.policy(self.server_id)
        self.assertEqual(policy["breaker_state"], "armed")
        self.assertEqual(policy["supervisor_epoch"], "supervisor-new")
        candidates = self.service.startup_candidates(
            supervisor_epoch="supervisor-new"
        )
        self.assertEqual([item["server_definition_id"] for item in candidates], [self.server_id])

    def test_startup_candidates_require_keep_alive_running_and_unfenced_scope(self) -> None:
        self._configure_and_start()
        non_kept = self._insert_server(self.repo_id, "non-kept")
        self._configure_and_start(
            server_id=non_kept, keep_alive=False, suffix="non-kept-start"
        )
        stopped = self._insert_server(self.repo_id, "stopped")
        self.service.configure_policy(
            server_definition_id=stopped,
            actor="test-agent",
            execution_uid=os.geteuid(),
            keep_alive=True,
        )
        archived = self._insert_server(self.repo_id, "archived")
        self._configure_and_start(server_id=archived, suffix="archived-start")
        timestamp = utc_timestamp(self.clock.value)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO resource_retirements(
                    host_resource_id, resource_kind, immutable_fingerprint,
                    status, reason, actor, started_at, updated_at
                ) VALUES (?, 'server', ?, 'retired', 'obsolete', 'test', ?, ?)
                """,
                (archived, "sha256:archived", timestamp, timestamp),
            )
        candidates = self.service.fence_startup(supervisor_epoch="startup")
        self.assertEqual([item["server_definition_id"] for item in candidates], [self.server_id])
        candidate = candidates[0]
        self.assertEqual(candidate["root_repo_id"], self.repo_id)
        self.assertEqual(candidate["repo_id"], self.repo_id)
        self.assertEqual(candidate["project_kind"], "primary")
        self.assertEqual(candidate["argv"], ("python3", "worker.py"))
        self.assertEqual(candidate["environment"], {"WORKER_TEST": "1"})
        manual = self.service.launch_candidate(
            server_definition_id=non_kept, supervisor_epoch="startup"
        )
        self.assertFalse(manual["keep_alive"])
        self.assertEqual(manual["server_definition_id"], non_kept)

    def test_archive_race_cancels_reserved_attempt_before_launch(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        attempt = self._begin(candidate, "archive-race")
        timestamp = utc_timestamp(self.clock.value)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO resource_retirements(
                    host_resource_id, resource_kind, immutable_fingerprint,
                    status, reason, actor, started_at, updated_at
                ) VALUES (?, 'server', ?, 'disabling', 'archive', 'test', ?, ?)
                """,
                (self.server_id, "sha256:archive-race", timestamp, timestamp),
            )
        with self.assertRaises(WorkerLaunchFenced) as raised:
            self.service.mark_attempt_launched(
                attempt_id=str(attempt["attempt_id"]),
                launch_report_id="launch-archive-race",
                supervisor_epoch=str(candidate["supervisor_epoch"]),
                supervisor_generation=int(candidate["supervisor_generation"]),
                pid=20_004,
                process_start_time="must-not-launch",
                process_fingerprint="must-not-launch",
            )
        self.assertEqual(raised.exception.reason, "resource_archived")
        self.assertEqual(raised.exception.attempt["state"], "exited")
        self.assertIsNone(raised.exception.attempt["pid"])
        self.assertEqual(
            raised.exception.attempt["exit_classification"], "fenced"
        )

    def test_tombstone_prevents_new_attempt_and_purge_retains_attempt_evidence(self) -> None:
        self._configure_and_start()
        candidate = self._fence_candidate()
        crash = self._launch_and_exit(candidate, "1", at=1_010.0)
        tombstone_operation = self._operation("tombstone")
        timestamp = utc_timestamp(self.clock.value)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO cleanup_tombstones(
                    target_kind, target_id, repo_id, immutable_fingerprint,
                    operation_id, actor, reason, evidence_json, removed_at
                ) VALUES ('server', ?, ?, ?, ?, 'test-agent', 'obsolete', '{}', ?)
                """,
                (
                    self.server_id,
                    self.repo_id,
                    "sha256:tombstone",
                    tombstone_operation,
                    timestamp,
                ),
            )
        with self.assertRaises(WorkerSupervisionConflict):
            self.service.begin_attempt(
                server_definition_id=self.server_id,
                begin_request_id="begin-after-tombstone",
                supervisor_epoch=str(candidate["supervisor_epoch"]),
                expected_definition_generation=int(
                    candidate["definition_generation"]
                ),
                expected_policy_generation=int(candidate["policy_generation"]),
                expected_supervisor_generation=int(
                    candidate["supervisor_generation"]
                ),
            )
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "DELETE FROM server_definitions WHERE server_definition_id = ?",
                (self.server_id,),
            )
        project_operation = self._operation("project-tombstone")
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE repository_installations
                SET status = 'disabled', startup_fenced = 1,
                    disabled_at = ?, updated_at = ?
                WHERE repo_id = ?
                """,
                (timestamp, timestamp, self.repo_id),
            )
            connection.execute(
                """
                UPDATE repositories
                SET state = 'missing', generation = generation + 1, updated_at = ?
                WHERE repo_id = ?
                """,
                (timestamp, self.repo_id),
            )
            connection.execute(
                """
                INSERT INTO cleanup_tombstones(
                    target_kind, target_id, repo_id, immutable_fingerprint,
                    operation_id, actor, reason, evidence_json, removed_at
                ) VALUES ('project', ?, ?, ?, ?, 'test-agent', 'obsolete', '{}', ?)
                """,
                (
                    self.repo_id,
                    self.repo_id,
                    "sha256:project-tombstone",
                    project_operation,
                    timestamp,
                ),
            )
        with self.store.read_transaction() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM worker_policies WHERE server_definition_id = ?",
                    (self.server_id,),
                ).fetchone()
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM worker_supervisor_states WHERE server_definition_id = ?",
                    (self.server_id,),
                ).fetchone()
            )
            retained = connection.execute(
                """
                SELECT crash_event_id FROM worker_attempts WHERE attempt_id = ?
                """,
                (crash["attempt_id"],),
            ).fetchone()
            self.assertIsNotNone(retained)
            self.assertEqual(retained["crash_event_id"], crash["crash_event_id"])
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM events WHERE event_id = ?",
                    (crash["crash_event_id"],),
                ).fetchone()
            )

    def test_project_tombstone_fences_stale_generation_but_not_explicit_reinstall(
        self,
    ) -> None:
        self.service.configure_policy(
            server_definition_id=self.server_id,
            actor="test-agent",
            execution_uid=os.geteuid(),
            keep_alive=True,
            crash_limit=3,
            crash_window_seconds=300,
        )
        tombstone_operation = self._operation("project-generation-tombstone")
        timestamp = utc_timestamp(self.clock.value)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE repositories SET generation = 1, updated_at = ? WHERE repo_id = ?",
                (timestamp, self.repo_id),
            )
            connection.execute(
                """
                INSERT INTO cleanup_tombstones(
                    target_kind, target_id, target_generation, repo_id,
                    immutable_fingerprint, operation_id, actor, reason,
                    evidence_json, removed_at
                ) VALUES ('project', ?, 0, ?, ?, ?, 'test-agent',
                          'obsolete', '{}', ?)
                """,
                (
                    self.repo_id,
                    self.repo_id,
                    "sha256:project-generation-tombstone",
                    tombstone_operation,
                    timestamp,
                ),
            )

        with self.assertRaisesRegex(WorkerSupervisionConflict, "resource_removed"):
            self.service.request_start(
                server_definition_id=self.server_id,
                actor="test-agent",
                operation_id=self._operation("stale-generation-start"),
            )

        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE repositories SET generation = 2, updated_at = ? WHERE repo_id = ?",
                (timestamp, self.repo_id),
            )
        result = self.service.request_start(
            server_definition_id=self.server_id,
            actor="test-agent",
            operation_id=self._operation("reinstalled-generation-start"),
        )
        self.assertEqual(result["desired_state"], "running")

    def test_previous_schema_requires_explicit_offline_migration_without_writes(self) -> None:
        self.store.close()
        database = self.home / "coordinator.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TABLE worker_exit_decisions")
            connection.execute("DROP TABLE worker_supervisor_states")
            connection.execute("DROP TABLE worker_attempts")
            connection.execute("DROP TABLE worker_policies")
            connection.execute(
                "UPDATE schema_metadata SET schema_version = 9 WHERE singleton = 1"
            )
            connection.commit()
        finally:
            connection.close()
        before = database.read_bytes()
        with self.assertRaisesRegex(
            RuntimeError, "unsupported coordinator database schema 9"
        ):
            AccountStore.open_default(self.home, effective_uid=os.geteuid())
        self.assertEqual(database.read_bytes(), before)
        with sqlite3.connect(database) as current:
            version = int(
                current.execute(
                    "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
                ).fetchone()[0]
            )
            tables = {
                str(row[0])
                for row in current.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name LIKE 'worker_%'
                    """
                )
            }
        self.assertEqual(version, 9)
        self.assertEqual(tables, set())

    def test_optimized_mode_has_no_assert_dependent_worker_guards(self) -> None:
        source = Path(
            __file__
        ).parents[1] / "worker_supervision.py"
        text = source.read_text(encoding="utf-8")
        self.assertNotIn("assert ", text)
        self.assertNotIn("__debug__", text)


if __name__ == "__main__":
    unittest.main()
