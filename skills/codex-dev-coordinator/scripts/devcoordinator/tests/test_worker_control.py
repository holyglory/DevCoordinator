from __future__ import annotations

import os
from pathlib import Path
import pwd
import tempfile
import unittest

from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp
from devcoordinator.worker_control import (
    WorkerControlError,
    WorkerController,
    WorkerReplaceError,
)
from devcoordinator.worker_native import NativeWorkerState
from devcoordinator.worker_supervision import WorkerSupervision


class FakeNativeManager:
    def __init__(self, supervision: WorkerSupervision) -> None:
        self.supervision = supervision
        self.active = False
        self.attempt: dict[str, object] | None = None
        self.start_calls = 0
        self.stop_calls = 0
        self.remove_calls = 0
        self.fail_next_starts = 0
        self.on_start_failure = None
        self.on_remove = None

    def status(
        self, *, worker_id: str, allow_missing: bool = False
    ) -> NativeWorkerState:
        del allow_missing
        return NativeWorkerState(
            worker_id=worker_id,
            manager="fake",
            unit=f"fake-{worker_id}",
            loaded=self.active,
            active=self.active,
            state="running" if self.active else "not-found",
            pid=31_000 if self.active else None,
            exit_status=None,
        )

    def start(self, *, worker_id: str, uid: int, gid: int) -> NativeWorkerState:
        del uid, gid
        self.start_calls += 1
        if self.fail_next_starts:
            self.fail_next_starts -= 1
            if self.on_start_failure is not None:
                callback = self.on_start_failure
                self.on_start_failure = None
                callback()
            raise RuntimeError("injected native start failure")
        policy = self.supervision.policy(worker_id)
        candidate = self.supervision.launch_candidate(
            server_definition_id=worker_id,
            supervisor_epoch=str(policy["supervisor_epoch"]),
        )
        attempt = self.supervision.begin_attempt(
            server_definition_id=worker_id,
            begin_request_id=f"fake-begin-{self.start_calls}",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            expected_definition_generation=int(candidate["definition_generation"]),
            expected_policy_generation=int(candidate["policy_generation"]),
            expected_supervisor_generation=int(candidate["supervisor_generation"]),
        )
        self.attempt = self.supervision.mark_attempt_launched(
            attempt_id=str(attempt["attempt_id"]),
            launch_report_id=f"fake-launch-{self.start_calls}",
            supervisor_epoch=str(candidate["supervisor_epoch"]),
            supervisor_generation=int(candidate["supervisor_generation"]),
            pid=31_000 + self.start_calls,
            process_start_time=f"fake-start-{self.start_calls}",
            process_fingerprint=f"fake-fingerprint-{self.start_calls}",
        )
        self.active = True
        return self.status(worker_id=worker_id)

    def stop(self, *, worker_id: str) -> NativeWorkerState:
        self.stop_calls += 1
        if self.attempt is not None and self.active:
            self.supervision.record_attempt_exit(
                attempt_id=str(self.attempt["attempt_id"]),
                exit_report_id=f"fake-stop-{self.stop_calls}",
                supervisor_epoch=str(self.attempt["supervisor_epoch"]),
                supervisor_generation=int(self.attempt["supervisor_generation"]),
                exit_kind="signal",
                exit_signal=15,
            )
        self.active = False
        return self.status(worker_id=worker_id)

    def remove(self, *, worker_id: str) -> NativeWorkerState:
        self.remove_calls += 1
        if self.active:
            self.stop(worker_id=worker_id)
        if self.on_remove is not None:
            callback = self.on_remove
            self.on_remove = None
            callback()
        return self.status(worker_id=worker_id)

    def crash(self, *, worker_id: str, exit_code: int = 1) -> dict[str, object]:
        if self.attempt is None or not self.active:
            raise RuntimeError("fake worker is not active")
        result = self.supervision.record_attempt_exit(
            attempt_id=str(self.attempt["attempt_id"]),
            exit_report_id=f"fake-crash-{self.start_calls}",
            supervisor_epoch=str(self.attempt["supervisor_epoch"]),
            supervisor_generation=int(self.attempt["supervisor_generation"]),
            exit_kind="exit_code",
            exit_code=exit_code,
        )
        self.active = False
        return result


class WorkerControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        self.store = AccountStore.open_default(
            self.root / "coordinator", effective_uid=os.geteuid()
        )
        host_id = self.store.ensure_local_host()
        now = utc_timestamp()
        self.repo_id = deterministic_id("worker-control-repository", host_id)
        self.worker_id = deterministic_id(
            "server-definition", self.repo_id, "queue-worker"
        )
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'Project', 'active', 0, ?, ?)
                """,
                (self.repo_id, host_id, str(self.project), now, now),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                """,
                (self.repo_id, now),
            )
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, role, cwd,
                    definition_fingerprint, generation, created_at, updated_at
                ) VALUES (?, ?, 'queue-worker', 'worker', ?, ?, 0, ?, ?)
                """,
                (
                    self.worker_id,
                    self.repo_id,
                    str(self.project),
                    "sha256:" + "3" * 64,
                    now,
                    now,
                ),
            )
            connection.executemany(
                """
                INSERT INTO server_command_arguments(
                    server_definition_id, ordinal, argument
                ) VALUES (?, ?, ?)
                """,
                (
                    (self.worker_id, 0, "/usr/bin/python3"),
                    (self.worker_id, 1, "worker.py"),
                ),
            )
            connection.execute(
                """
                INSERT INTO server_environment(server_definition_id, name, value)
                VALUES (?, 'ORIGINAL', 'yes')
                """,
                (self.worker_id,),
            )
        self.supervision = WorkerSupervision(self.store)
        self.manager = FakeNativeManager(self.supervision)
        script = Path(__file__).parents[2] / "dev_coordinator.py"
        self.execution_uid = os.geteuid()
        if self.execution_uid == 0:
            try:
                self.execution_uid = int(pwd.getpwnam("nobody").pw_uid)
            except KeyError:
                self.execution_uid = next(
                    int(account.pw_uid)
                    for account in pwd.getpwall()
                    if int(account.pw_uid) > 0
                )
        self.controller = WorkerController(
            self.store,
            coordinator_script=script,
            manager_factory=lambda **_kwargs: self.manager,
            execution_uid=self.execution_uid,
            sleeper=lambda _seconds: None,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _start(self, *, keep_alive: bool | None = True) -> dict[str, object]:
        return self.controller.start(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            keep_alive=keep_alive,
            timeout_seconds=0.1,
        )

    def _replace(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "worker_id": self.worker_id,
            "canonical_repository": str(self.project),
            "name": "queue-worker",
            "actor": "test-agent",
            "expected_generation": 0,
            "argv": ["/usr/bin/python3", "replacement.py"],
            "cwd": str(self.project),
            "environment": {"REPLACED": "yes"},
            "keep_alive": True,
            "timeout_seconds": 0.1,
        }
        values.update(overrides)
        return self.controller.replace(**values)

    def _definition(self) -> dict[str, object]:
        with self.store.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM server_definitions WHERE server_definition_id = ?",
                (self.worker_id,),
            ).fetchone()
            arguments = [
                str(item[0])
                for item in connection.execute(
                    """
                    SELECT argument FROM server_command_arguments
                    WHERE server_definition_id = ? ORDER BY ordinal
                    """,
                    (self.worker_id,),
                )
            ]
            environment = {
                str(item[0]): str(item[1])
                for item in connection.execute(
                    """
                    SELECT name, value FROM server_environment
                    WHERE server_definition_id = ? ORDER BY name
                    """,
                    (self.worker_id,),
                )
            }
        result = dict(row)
        result["argv"] = arguments
        result["environment"] = environment
        return result

    def test_start_is_exact_idempotent_and_stop_is_separate(self) -> None:
        started = self._start()
        self.assertTrue(started["ok"])
        self.assertEqual(started["status"], "running")
        self.assertTrue(started["supervision"]["keep_alive"])
        self.assertEqual(self.manager.start_calls, 1)

        replay = self._start(keep_alive=None)
        self.assertTrue(replay["ok"])
        self.assertEqual(self.manager.start_calls, 1, "must not duplicate the runner")

        stopped = self.controller.stop(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            timeout_seconds=0.1,
        )
        self.assertEqual(stopped["status"], "stopped")
        self.assertEqual(self.manager.stop_calls, 1)
        self.assertFalse(self.supervision.attempt(str(self.manager.attempt["attempt_id"]))["counts_toward_breaker"])

    def test_keep_alive_off_leaves_current_attempt_running_then_prevents_restart(self) -> None:
        self._start()
        disabled = self._start(keep_alive=False)
        self.assertEqual(disabled["status"], "running")
        self.assertFalse(disabled["supervision"]["keep_alive"])
        self.assertEqual(self.manager.start_calls, 1)
        crash = self.manager.crash(worker_id=self.worker_id)
        self.assertFalse(crash["restart_allowed"])
        self.assertEqual(self.supervision.policy(self.worker_id)["supervisor_state"], "idle")

    def test_first_supervised_start_requires_explicit_policy_and_worker_role(self) -> None:
        with self.assertRaisesRegex(WorkerControlError, "explicit keep_alive"):
            self._start(keep_alive=None)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE server_definitions SET role='web' WHERE server_definition_id=?",
                (self.worker_id,),
            )
        with self.assertRaisesRegex(WorkerControlError, "worker-role"):
            self._start(keep_alive=True)

    def test_unregister_commits_stopped_state_and_removes_native_registration(self) -> None:
        self._start()
        result = self.controller.unregister(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            timeout_seconds=0.1,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "stopped")
        self.assertTrue(result["native_registration_removed"])
        self.assertEqual(self.manager.remove_calls, 1)
        policy = self.supervision.policy(self.worker_id)
        self.assertEqual(policy["desired_state"], "stopped")
        self.assertIsNone(policy["current_attempt_id"])

        replay = self.controller.unregister(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            timeout_seconds=0.1,
        )
        self.assertTrue(replay["native_registration_removed"])
        self.assertEqual(self.manager.remove_calls, 2)

    def test_unregister_remains_available_after_repository_startup_is_fenced(self) -> None:
        self._start()
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE repository_installations
                SET status = 'disabled', startup_fenced = 1
                WHERE repo_id = ?
                """,
                (self.repo_id,),
            )

        result = self.controller.unregister(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            timeout_seconds=0.1,
        )
        self.assertTrue(result["native_registration_removed"])
        self.assertEqual(result["status"], "stopped")
        with self.assertRaisesRegex(WorkerControlError, "not installed and startable"):
            self._start(keep_alive=True)

    def test_replace_atomically_updates_exact_definition_then_starts_it(self) -> None:
        self._start()
        nested = self.project / "worker"
        nested.mkdir()

        result = self._replace(
            argv=["/usr/bin/python3", "replacement.py", "--serve"],
            cwd=str(nested),
            environment={"MODE": "replacement", "WORKERS": "2"},
            keep_alive=False,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["replacement"]["generation"], 1)
        self.assertTrue(result["replacement"]["native_registration_replaced"])
        self.assertEqual(self.manager.remove_calls, 1)
        self.assertEqual(self.manager.start_calls, 2)
        definition = self._definition()
        self.assertEqual(definition["cwd"], str(nested))
        self.assertEqual(
            definition["argv"],
            ["/usr/bin/python3", "replacement.py", "--serve"],
        )
        self.assertEqual(
            definition["environment"],
            {"MODE": "replacement", "WORKERS": "2"},
        )
        self.assertTrue(str(definition["definition_fingerprint"]).startswith("sha256:"))
        self.assertFalse(self.supervision.policy(self.worker_id)["keep_alive"])

    def test_replace_rejects_invalid_scope_argv_and_environment_before_stop(self) -> None:
        self._start()
        outside = self.root / "outside"
        outside.mkdir()
        invalid_cases = (
            {"cwd": str(outside)},
            {"argv": []},
            {"environment": {"INVALID=NAME": "value"}},
            {"environment": {"VALID": "nul\x00value"}},
        )
        for options in invalid_cases:
            with self.subTest(options=options):
                with self.assertRaises(WorkerControlError):
                    self._replace(**options)
        self.assertTrue(self.manager.active)
        self.assertEqual(self.manager.remove_calls, 0)
        self.assertEqual(self._definition()["generation"], 0)

    def test_replace_rejects_stale_and_concurrent_generations_without_overwrite(self) -> None:
        self._start()
        with self.assertRaisesRegex(WorkerControlError, "generation changed"):
            self._replace(expected_generation=9)
        self.assertTrue(self.manager.active)
        self.assertEqual(self.manager.remove_calls, 0)

        def concurrent_change() -> None:
            with self.store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET generation = generation + 1, updated_at = ?
                    WHERE server_definition_id = ?
                    """,
                    (utc_timestamp(), self.worker_id),
                )

        self.manager.on_remove = concurrent_change
        with self.assertRaises(WorkerReplaceError) as raised:
            self._replace()
        self.assertEqual(
            raised.exception.payload["classification"],
            "reconciliation_required",
        )
        self.assertFalse(raised.exception.payload["rollback"]["definition_mutated"])
        definition = self._definition()
        self.assertEqual(definition["generation"], 1)
        self.assertEqual(
            definition["argv"], ["/usr/bin/python3", "worker.py"]
        )
        self.assertFalse(self.manager.active)

    def test_replace_failure_restores_definition_policy_and_prior_native_state(self) -> None:
        self._start()
        before = self._definition()
        self.manager.fail_next_starts = 1

        with self.assertRaises(WorkerReplaceError) as raised:
            self._replace(
                argv=["/usr/bin/python3", "broken.py"],
                environment={"BROKEN": "yes"},
                keep_alive=False,
            )

        evidence = raised.exception.payload
        self.assertEqual(
            evidence["classification"], "replacement_failed_rolled_back"
        )
        self.assertTrue(evidence["rollback"]["ok"])
        self.assertTrue(evidence["rollback"]["definition_restored"])
        self.assertTrue(evidence["rollback"]["policy_restored"])
        self.assertTrue(evidence["rollback"]["native_state_restored"])
        restored = self._definition()
        self.assertEqual(restored["cwd"], before["cwd"])
        self.assertEqual(restored["argv"], before["argv"])
        self.assertEqual(restored["environment"], before["environment"])
        self.assertEqual(
            restored["definition_fingerprint"], before["definition_fingerprint"]
        )
        self.assertEqual(restored["generation"], 2)
        policy = self.supervision.policy(self.worker_id)
        self.assertTrue(policy["keep_alive"])
        self.assertEqual(policy["desired_state"], "running")
        self.assertEqual(policy["supervisor_state"], "running")
        self.assertTrue(self.manager.active)

    def test_replace_requires_and_applies_explicit_rearm_for_tripped_worker(self) -> None:
        self.controller.start(
            worker_id=self.worker_id,
            canonical_repository=str(self.project),
            name="queue-worker",
            actor="test-agent",
            keep_alive=True,
            crash_limit=1,
            crash_window_seconds=300,
            timeout_seconds=0.1,
        )
        self.manager.crash(worker_id=self.worker_id)
        self.assertEqual(
            self.supervision.policy(self.worker_id)["breaker_state"], "tripped"
        )

        with self.assertRaisesRegex(WorkerControlError, "explicit rearm"):
            self._replace(crash_limit=1, crash_window_seconds=300)
        replaced = self._replace(
            crash_limit=1,
            crash_window_seconds=300,
            rearm=True,
        )
        self.assertEqual(replaced["status"], "running")
        self.assertEqual(
            self.supervision.policy(self.worker_id)["breaker_state"], "armed"
        )

    def test_replace_refuses_definition_mutation_when_process_absence_is_unproven(self) -> None:
        self._start()

        def leave_unproven_observation() -> None:
            with self.store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_observations
                    SET lifecycle = 'running', pid = 45555,
                        process_start_time = 'unproven-start',
                        process_fingerprint = 'unproven-fingerprint',
                        sampled_at = ?, observation_fingerprint = ?
                    WHERE server_definition_id = ?
                    """,
                    (utc_timestamp(), "unproven-observation", self.worker_id),
                )

        self.manager.on_remove = leave_unproven_observation
        with self.assertRaises(WorkerReplaceError) as raised:
            self._replace()
        self.assertEqual(
            raised.exception.payload["classification"],
            "reconciliation_required",
        )
        self.assertIn(
            "process absence is unproven",
            raised.exception.payload["replace_error"]["message"],
        )
        self.assertFalse(raised.exception.payload["rollback"]["definition_mutated"])
        self.assertEqual(self._definition()["generation"], 0)

    def test_replace_reports_incomplete_rollback_without_overwriting_newer_definition(self) -> None:
        self._start()
        self.manager.fail_next_starts = 1

        def concurrent_change_after_replacement() -> None:
            with self.store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET generation = generation + 1, updated_at = ?
                    WHERE server_definition_id = ?
                    """,
                    (utc_timestamp(), self.worker_id),
                )

        self.manager.on_start_failure = concurrent_change_after_replacement
        with self.assertRaises(WorkerReplaceError) as raised:
            self._replace(argv=["/usr/bin/python3", "newer.py"])

        evidence = raised.exception.payload
        self.assertEqual(evidence["classification"], "reconciliation_required")
        self.assertTrue(evidence["rollback"]["definition_mutated"])
        self.assertFalse(evidence["rollback"]["definition_restored"])
        self.assertTrue(
            any(
                item["phase"] == "definition_restore"
                for item in evidence["rollback"]["errors"]
            )
        )
        definition = self._definition()
        self.assertEqual(definition["generation"], 2)
        self.assertEqual(
            definition["argv"], ["/usr/bin/python3", "newer.py"]
        )


if __name__ == "__main__":
    unittest.main()
