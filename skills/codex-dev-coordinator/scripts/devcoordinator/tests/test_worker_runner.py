from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import threading
import time
import unittest
import uuid
from urllib.parse import quote
from unittest import mock

from devcoordinator.broker import BrokerError, BrokerOperation
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerRepositoryProfile,
)
from devcoordinator.server_credentials import server_credential_id
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp
from devcoordinator.worker_runner import (
    BrokerWorkerAuthority,
    DirectWorkerAuthority,
    WorkerAuthorityBlocked,
    WorkerAuthorityUnavailable,
    WorkerExitJournal,
    WorkerLogCapture,
    WorkerRunner,
    add_worker_cli_parser,
)
from devcoordinator.worker_supervision import WorkerLaunchFenced, WorkerSupervision


class WorkerRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        self.store = AccountStore.open_default(
            self.home, effective_uid=os.geteuid()
        )
        self.host_id = self.store.ensure_local_host()
        self.repo_id = deterministic_id("runner-repository", self.host_id, self.project)
        self.worker_id = deterministic_id("runner-worker", self.repo_id, "worker")
        self._insert_worker()
        self.supervision = WorkerSupervision(self.store, clock=lambda: 1_000.0)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _insert_worker(self) -> None:
        timestamp = utc_timestamp(1_000.0)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, 'runner-project', 'active', 0, ?, ?)
                """,
                (
                    self.repo_id,
                    self.host_id,
                    str(self.project),
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'runner-test', ?)
                """,
                (self.repo_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO server_definitions(
                    server_definition_id, repo_id, name, role, cwd,
                    health_url_template, log_path, definition_fingerprint,
                    generation, created_at, updated_at
                ) VALUES (?, ?, 'worker', 'worker', ?, NULL, ?, ?, 0, ?, ?)
                """,
                (
                    self.worker_id,
                    self.repo_id,
                    str(self.project),
                    str(self.home / "logs" / "legacy-worker.log"),
                    "sha256:runner-worker-definition",
                    timestamp,
                    timestamp,
                ),
            )

    def _set_command(
        self, argv: tuple[str, ...], environment: dict[str, str] | None = None
    ) -> None:
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "DELETE FROM server_command_arguments WHERE server_definition_id = ?",
                (self.worker_id,),
            )
            connection.executemany(
                """
                INSERT INTO server_command_arguments(
                    server_definition_id, ordinal, argument
                ) VALUES (?, ?, ?)
                """,
                [
                    (self.worker_id, index, argument)
                    for index, argument in enumerate(argv)
                ],
            )
            connection.execute(
                "DELETE FROM server_environment WHERE server_definition_id = ?",
                (self.worker_id,),
            )
            connection.executemany(
                """
                INSERT INTO server_environment(server_definition_id, name, value)
                VALUES (?, ?, ?)
                """,
                [
                    (self.worker_id, key, value)
                    for key, value in sorted((environment or {}).items())
                ],
            )

    def _set_credential(self, name: str, value: str) -> Path:
        credential_id = server_credential_id(self.worker_id, name)
        timestamp = utc_timestamp(1_000.0)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO server_environment_credentials(
                    server_definition_id,name,credential_id,created_at,updated_at
                ) VALUES (?,?,?,?,?)
                """,
                (self.worker_id, name, credential_id, timestamp, timestamp),
            )
        runtime = self.root / "systemd-credentials"
        runtime.mkdir(mode=0o700, exist_ok=True)
        runtime.chmod(0o700)
        material = runtime / credential_id
        material.write_text(value, encoding="utf-8")
        material.chmod(0o400)
        return runtime

    def _operation(self, name: str) -> str:
        operation_id = deterministic_id("runner-operation", name)
        timestamp = utc_timestamp(1_000.0)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, source_id, kind, status, phase,
                    generation, request_fingerprint, owner_uid, actor,
                    created_at, updated_at
                ) VALUES (?, ?, NULL, 'worker.runner.test', 'running', 'test',
                          0, ?, ?, 'runner-test', ?, ?)
                """,
                (
                    operation_id,
                    self.repo_id,
                    deterministic_id("runner-operation-fingerprint", name),
                    os.geteuid(),
                    timestamp,
                    timestamp,
                ),
            )
        return operation_id

    def _start_policy(
        self, *, keep_alive: bool, crash_limit: int = 10, name: str = "start"
    ) -> None:
        self.supervision.configure_policy(
            server_definition_id=self.worker_id,
            actor="runner-test",
            execution_uid=os.geteuid(),
            keep_alive=keep_alive,
            crash_limit=crash_limit,
            crash_window_seconds=300,
        )
        self.supervision.request_start(
            server_definition_id=self.worker_id,
            actor="runner-test",
            operation_id=self._operation(name),
        )
        self.supervision.fence_startup(supervisor_epoch="runner-epoch")

    def _runner(self, authority: object | None = None, **kwargs: object) -> WorkerRunner:
        return WorkerRunner(
            authority=authority or DirectWorkerAuthority(self.supervision),  # type: ignore[arg-type]
            artifact_root=self.home / "logs",
            restart_delay_seconds=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 1_000.0,
            **kwargs,  # type: ignore[arg-type]
        )

    def _broker_authority(
        self, handler: object
    ) -> tuple[BrokerWorkerAuthority, mock.Mock, BrokerRepositoryProfile]:
        repository = BrokerRepositoryProfile(
            canonical_root=str(self.project),
            repo_id=self.repo_id,
            generation=0,
            server_ids={"worker": self.worker_id},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        profile = mock.Mock(spec=BrokerClientProfile)
        profile.client_uid = os.geteuid()
        profile.repository_for_server_id.return_value = repository
        profile.worker_call.side_effect = handler
        authority = BrokerWorkerAuthority(
            profile=profile,
            worker_id=self.worker_id,
            effective_uid=os.geteuid(),
        )
        profile.repository_for_server_id.assert_called_once_with(self.worker_id)
        return authority, profile, repository

    def test_every_crash_is_persisted_and_second_crash_trips_before_restart(self) -> None:
        secret = "runner-secret-value"
        self._set_command(
            (
                sys.executable,
                "-c",
                (
                    "import os,sys; "
                    "print('password=hunter2'); "
                    "print(os.environ['RUNNER_SECRET']); "
                    "sys.exit(9)"
                ),
            ),
        )
        credential_directory = self._set_credential("RUNNER_SECRET", secret)
        self._start_policy(keep_alive=True, crash_limit=2)

        candidate = self.supervision.launch_candidate(
            server_definition_id=self.worker_id, supervisor_epoch="runner-epoch"
        )
        self.assertNotIn(secret, json.dumps(candidate, sort_keys=True))
        with mock.patch.dict(
            os.environ,
            {"CREDENTIALS_DIRECTORY": str(credential_directory)},
            clear=False,
        ):
            result = self._runner().run(worker_id=self.worker_id)

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempts"], 2)
        self.assertFalse(result["restart_allowed"])
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))
        self.assertEqual(result["repository"]["root_repo"], str(self.project))
        self.assertIsNone(result["repository"]["temporary_repo"])
        self.assertEqual(self.supervision.policy(self.worker_id)["breaker_state"], "tripped")
        with self.store.read_transaction() as connection:
            attempts = connection.execute(
                """
                SELECT state, exit_kind, exit_code, crash_event_id,
                       log_artifact_id, log_artifact_path, log_artifact_sha256
                FROM worker_attempts ORDER BY created_at, attempt_id
                """
            ).fetchall()
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(row["state"] == "exited" for row in attempts))
        self.assertTrue(all(row["exit_kind"] == "exit_code" for row in attempts))
        self.assertTrue(all(row["exit_code"] == 9 for row in attempts))
        self.assertTrue(all(row["crash_event_id"] for row in attempts))
        for row in attempts:
            path = Path(str(row["log_artifact_path"]))
            self.assertEqual(
                path.name,
                f"worker-attempt-{row['log_artifact_id']}.log",
            )
            payload = path.read_bytes()
            self.assertNotIn(secret.encode(), payload)
            self.assertNotIn(b"hunter2", payload)
            self.assertIn(b"password=[REDACTED]", payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), row["log_artifact_sha256"])
            self.assertLessEqual(len(payload), 1024 * 1024)

    def test_missing_systemd_credential_blocks_before_child_launch(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        credential_id = server_credential_id(self.worker_id, "DATABASE_URL")
        timestamp = utc_timestamp(1_000.0)
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO server_environment_credentials(
                    server_definition_id,name,credential_id,created_at,updated_at
                ) VALUES (?,?,?,?,?)
                """,
                (
                    self.worker_id,
                    "DATABASE_URL",
                    credential_id,
                    timestamp,
                    timestamp,
                ),
            )
        self._start_policy(keep_alive=False)
        with mock.patch.dict(os.environ, {}, clear=True):
            result = self._runner().run(worker_id=self.worker_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_credential_invalid")
        self.assertEqual(result["attempts"], 0)
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                0,
            )

    def test_manual_non_keep_alive_worker_runs_once(self) -> None:
        self._set_command((sys.executable, "-c", "print('finished')"))
        self._start_policy(keep_alive=False)

        result = self._runner().run(worker_id=self.worker_id)

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempts"], 1)
        self.assertFalse(result["restart_allowed"])
        with self.store.read_transaction() as connection:
            attempt = connection.execute(
                "SELECT * FROM worker_attempts"
            ).fetchone()
        self.assertEqual(attempt["exit_classification"], "crash")
        self.assertEqual(attempt["expected_exit"], 0)

    def test_minimal_account_environment_supports_home_and_path_without_ambient_secrets(self) -> None:
        ambient_secret = "must-not-reach-worker"
        self._set_command(
            (
                "sh",
                "-c",
                "printf '%s\\n%s\\n%s\\n' \"${AMBIENT_RUNNER_SECRET-MISSING}\" \"$HOME\" \"$PATH\"",
            )
        )
        self._start_policy(keep_alive=False)
        with mock.patch.dict(
            os.environ,
            {"AMBIENT_RUNNER_SECRET": ambient_secret},
            clear=False,
        ):
            result = self._runner().run(worker_id=self.worker_id)
        self.assertTrue(result["ok"])
        payload = Path(result["log_artifacts"][0]["path"]).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(ambient_secret, payload)
        self.assertIn("MISSING", payload)
        self.assertIn(pwd.getpwuid(os.geteuid()).pw_dir, payload)
        self.assertIn("/usr/bin:/bin", payload)

    def test_persisted_environment_cannot_replace_verified_account_identity(self) -> None:
        self._set_command(
            (sys.executable, "-c", "raise SystemExit(0)"),
            {"HOME": str(self.root / "attacker-home")},
        )
        self._start_policy(keep_alive=True)
        result = self._runner().run(worker_id=self.worker_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_candidate_invalid")
        self.assertIn("verified HOME", result["error"])
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                0,
            )

    def test_uncertain_begin_launch_and_exit_commits_are_replayed_not_duplicated(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(3)"))
        self._start_policy(keep_alive=False)
        direct = DirectWorkerAuthority(self.supervision)

        class UncertainAuthority:
            begin_calls = 0
            launch_calls = 0
            exit_calls = 0

            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                return direct.launch_candidate(**kwargs)  # type: ignore[arg-type]

            def begin_attempt(inner_self, **kwargs: object) -> object:
                inner_self.begin_calls += 1
                result = direct.begin_attempt(**kwargs)  # type: ignore[arg-type]
                if inner_self.begin_calls == 1:
                    raise WorkerAuthorityUnavailable("lost begin response")
                return result

            def mark_attempt_launched(inner_self, **kwargs: object) -> object:
                inner_self.launch_calls += 1
                result = direct.mark_attempt_launched(**kwargs)  # type: ignore[arg-type]
                if inner_self.launch_calls == 1:
                    raise WorkerAuthorityUnavailable("lost launch response")
                return result

            def record_attempt_exit(inner_self, **kwargs: object) -> object:
                inner_self.exit_calls += 1
                result = direct.record_attempt_exit(**kwargs)  # type: ignore[arg-type]
                if inner_self.exit_calls == 1:
                    raise WorkerAuthorityUnavailable("lost exit response")
                return result

        authority = UncertainAuthority()
        result = self._runner(authority).run(worker_id=self.worker_id)
        self.assertTrue(result["ok"], result)
        self.assertEqual(authority.begin_calls, 2)
        self.assertEqual(authority.launch_calls, 2)
        self.assertEqual(authority.exit_calls, 2)
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE event_kind = 'worker.crashed'"
                ).fetchone()[0],
                1,
            )

    def test_interrupted_broker_outage_replays_private_pending_exit_before_launch(self) -> None:
        marker = self.root / "worker-runs.txt"
        self._set_command(
            (
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    f"p=Path({str(marker)!r}); "
                    "p.write_text((p.read_text() if p.exists() else '') + 'run\\n'); "
                    "raise SystemExit(4)"
                ),
            )
        )
        self._start_policy(keep_alive=False)
        direct = DirectWorkerAuthority(self.supervision)

        class BrokerUnavailableAtExit:
            exit_calls = 0

            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                return direct.launch_candidate(**kwargs)  # type: ignore[arg-type]

            def begin_attempt(inner_self, **kwargs: object) -> object:
                return direct.begin_attempt(**kwargs)  # type: ignore[arg-type]

            def mark_attempt_launched(inner_self, **kwargs: object) -> object:
                return direct.mark_attempt_launched(**kwargs)  # type: ignore[arg-type]

            def record_attempt_exit(inner_self, **_kwargs: object) -> object:
                inner_self.exit_calls += 1
                raise WorkerAuthorityUnavailable("broker is offline")

        class SimulatedRunnerInterruption(RuntimeError):
            pass

        unavailable = BrokerUnavailableAtExit()
        interrupted = WorkerRunner(
            authority=unavailable,
            artifact_root=self.home / "logs",
            restart_delay_seconds=0,
            sleeper=lambda _seconds: (_ for _ in ()).throw(
                SimulatedRunnerInterruption("runner stopped during broker outage")
            ),
            clock=lambda: 1_000.0,
        )
        with self.assertRaises(SimulatedRunnerInterruption):
            interrupted.run(worker_id=self.worker_id)
        pending = list(
            (self.home / "logs").glob(
                f"worker-pending-exit-{self.worker_id}.json"
            )
        )
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].stat().st_mode & 0o777, 0o600)
        private_record = pending[0].read_text(encoding="utf-8")
        self.assertNotIn(str(self.project), private_record)
        self.assertNotIn(str(self.home / "logs"), private_record)

        recovered = self._runner().run(worker_id=self.worker_id)

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["attempts"], 0)
        self.assertEqual(recovered["classification"], "worker_stopped")
        self.assertEqual(marker.read_text(encoding="utf-8"), "run\n")
        self.assertFalse(pending[0].exists())
        with self.store.read_transaction() as connection:
            attempts = connection.execute(
                "SELECT exit_kind, exit_code FROM worker_attempts"
            ).fetchall()
        self.assertEqual(
            [(row["exit_kind"], row["exit_code"]) for row in attempts],
            [("exit_code", 4)],
        )

    def test_pending_exit_fenced_by_manager_is_acknowledged_without_rewriting_evidence(
        self,
    ) -> None:
        marker = self.root / "worker-runs.txt"
        self._set_command(
            (
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    f"p=Path({str(marker)!r}); "
                    "p.write_text((p.read_text() if p.exists() else '') + 'run\\n'); "
                    "raise SystemExit(4)"
                ),
            )
        )
        self._start_policy(keep_alive=False)
        direct = DirectWorkerAuthority(self.supervision)

        class BrokerUnavailableAtExit:
            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                return direct.launch_candidate(**kwargs)  # type: ignore[arg-type]

            def begin_attempt(inner_self, **kwargs: object) -> object:
                return direct.begin_attempt(**kwargs)  # type: ignore[arg-type]

            def mark_attempt_launched(inner_self, **kwargs: object) -> object:
                return direct.mark_attempt_launched(**kwargs)  # type: ignore[arg-type]

            def record_attempt_exit(inner_self, **_kwargs: object) -> object:
                raise WorkerAuthorityUnavailable("broker is offline")

        class SimulatedRunnerInterruption(RuntimeError):
            pass

        interrupted = WorkerRunner(
            authority=BrokerUnavailableAtExit(),
            artifact_root=self.home / "logs",
            restart_delay_seconds=0,
            sleeper=lambda _seconds: (_ for _ in ()).throw(
                SimulatedRunnerInterruption("runner stopped during broker outage")
            ),
            clock=lambda: 1_000.0,
        )
        with self.assertRaises(SimulatedRunnerInterruption):
            interrupted.run(worker_id=self.worker_id)

        pending = WorkerExitJournal(self.home / "logs").pending_path(
            worker_id=self.worker_id
        )
        self.assertTrue(pending.exists())
        old_attempt = self.supervision.policy(self.worker_id)["current_attempt_id"]
        self.assertIsInstance(old_attempt, str)
        attempt = self.supervision.attempt(str(old_attempt))
        self.supervision.fence_startup(supervisor_epoch="broker-restarted")
        fence_exit_id = str(uuid.uuid4())
        fenced = self.supervision.record_attempt_exit(
            attempt_id=str(attempt["attempt_id"]),
            exit_report_id=fence_exit_id,
            supervisor_epoch=str(attempt["supervisor_epoch"]),
            supervisor_generation=int(attempt["supervisor_generation"]),
            exit_kind="supervisor_lost",
            occurred_at_epoch=1_001.0,
        )
        self.assertEqual(fenced["exit_classification"], "stale_generation")

        recovered = self._runner().run(worker_id=self.worker_id)

        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["classification"], "worker_stopped")
        self.assertEqual(recovered["attempts"], 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "run\n")
        self.assertFalse(pending.exists())
        stored = self.supervision.attempt(str(attempt["attempt_id"]))
        self.assertEqual(stored["exit_report_id"], fence_exit_id)
        self.assertEqual(stored["exit_kind"], "supervisor_lost")
        self.assertEqual(stored["exit_classification"], "stale_generation")

    def test_authoritative_fence_reconciliation_rejects_an_ordinary_stale_exit(
        self,
    ) -> None:
        attempt_id = str(uuid.uuid4())

        class OrdinaryStaleExitAuthority:
            def read_attempt(inner_self, **_kwargs: object) -> object:
                return {
                    "attempt_id": attempt_id,
                    "server_definition_id": self.worker_id,
                    "supervisor_epoch": "old-supervisor",
                    "supervisor_generation": 7,
                    "state": "exited",
                    "exit_kind": "exit_code",
                    "exit_classification": "stale_generation",
                    "exit_decision_known": True,
                    "restart_allowed": True,
                }

        acknowledgement = self._runner(
            OrdinaryStaleExitAuthority()
        )._authoritative_fence_acknowledgement(
            worker_id=self.worker_id,
            document={
                "attempt_id": attempt_id,
                "supervisor_epoch": "old-supervisor",
                "supervisor_generation": 7,
            },
        )

        self.assertIsNone(acknowledgement)

    def test_corrupt_pending_exit_fails_closed_without_authority_or_launch(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        journal = WorkerExitJournal(self.home / "logs")
        corrupt = journal.pending_path(
            worker_id=self.worker_id,
        )
        corrupt.write_text("{", encoding="utf-8")
        os.chmod(corrupt, 0o600)

        class ForbiddenAuthority:
            def __getattr__(inner_self, name: str) -> object:
                raise AssertionError(
                    f"corrupt journal reached worker authority method {name}"
                )

        def forbidden_process(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("corrupt journal reached process launch")

        result = self._runner(
            ForbiddenAuthority(), process_factory=forbidden_process
        ).run(worker_id=self.worker_id)

        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_reconciliation_invalid")
        self.assertEqual(result["attempts"], 0)
        self.assertTrue(corrupt.exists())
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                0,
            )

    def test_stop_committed_before_exit_is_expected_and_never_restarts(self) -> None:
        self._set_command(
            (sys.executable, "-c", "import time; time.sleep(.5); print('done')")
        )
        self._start_policy(keep_alive=True, crash_limit=1)
        stop_operation = self._operation("stop")
        stopper_error: list[BaseException] = []

        def stop_after_launch() -> None:
            try:
                with AccountStore.open_default(
                    self.home, effective_uid=os.geteuid()
                ) as store:
                    supervision = WorkerSupervision(store, clock=lambda: 1_000.0)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        if supervision.policy(self.worker_id)["supervisor_state"] == "running":
                            supervision.request_stop(
                                server_definition_id=self.worker_id,
                                actor="runner-test",
                                operation_id=stop_operation,
                            )
                            return
                        time.sleep(0.01)
                    raise RuntimeError("worker attempt did not reach running state")
            except BaseException as error:
                stopper_error.append(error)

        thread = threading.Thread(target=stop_after_launch)
        thread.start()
        result = self._runner().run(worker_id=self.worker_id)
        thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        if stopper_error:
            raise stopper_error[0]
        self.assertTrue(result["ok"])
        self.assertEqual(result["attempts"], 1)
        with self.store.read_transaction() as connection:
            attempt = connection.execute("SELECT * FROM worker_attempts").fetchone()
        self.assertEqual(attempt["exit_classification"], "intentional")
        self.assertEqual(attempt["expected_exit"], 1)
        self.assertEqual(attempt["counts_toward_breaker"], 0)
        self.assertIsNone(attempt["crash_event_id"])

    def test_unclassified_candidate_fails_before_begin_or_process_launch(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        direct = DirectWorkerAuthority(self.supervision)

        class UnclassifiedAuthority:
            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                candidate = dict(direct.launch_candidate(**kwargs))  # type: ignore[arg-type]
                candidate["project_kind"] = "unknown"
                return candidate

            def __getattr__(inner_self, name: str) -> object:
                return getattr(direct, name)

        def forbidden_process(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("invalid candidate reached the process boundary")

        result = self._runner(
            UnclassifiedAuthority(), process_factory=forbidden_process
        ).run(worker_id=self.worker_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_candidate_invalid")
        self.assertEqual(result["attempts"], 0)
        with self.store.read_transaction() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                0,
            )

    def test_definition_generation_race_is_fenced_before_process_launch(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        direct = DirectWorkerAuthority(self.supervision)

        class StaleAuthority:
            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                candidate = direct.launch_candidate(**kwargs)  # type: ignore[arg-type]
                with self.store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE server_definitions SET generation = generation + 1,
                            updated_at = ? WHERE server_definition_id = ?
                        """,
                        (utc_timestamp(1_001.0), self.worker_id),
                    )
                return candidate

            def __getattr__(inner_self, name: str) -> object:
                return getattr(direct, name)

        def forbidden_process(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("stale generation reached the process boundary")

        result = self._runner(
            StaleAuthority(), process_factory=forbidden_process
        ).run(worker_id=self.worker_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_launch_fenced")
        self.assertEqual(result["attempts"], 0)

    def test_archive_race_after_spawn_terminates_child_and_keeps_fenced_evidence(self) -> None:
        self._set_command(
            (sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)")
        )
        self._start_policy(keep_alive=True)
        direct = DirectWorkerAuthority(self.supervision)
        launched_pid: list[int] = []

        class ArchiveAtLaunchAuthority:
            def active_attempt(inner_self, **kwargs: object) -> object:
                return direct.active_attempt(**kwargs)  # type: ignore[arg-type]

            def launch_candidate(inner_self, **kwargs: object) -> object:
                return direct.launch_candidate(**kwargs)  # type: ignore[arg-type]

            def begin_attempt(inner_self, **kwargs: object) -> object:
                return direct.begin_attempt(**kwargs)  # type: ignore[arg-type]

            def mark_attempt_launched(inner_self, **kwargs: object) -> object:
                launched_pid.append(int(kwargs["pid"]))
                timestamp = utc_timestamp(1_001.0)
                with self.store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO resource_retirements(
                            host_resource_id, resource_kind, immutable_fingerprint,
                            status, reason, actor, started_at, updated_at
                        ) VALUES (?, 'server', ?, 'disabling', 'archive-race',
                                  'runner-test', ?, ?)
                        """,
                        (
                            self.worker_id,
                            "sha256:archive-race",
                            timestamp,
                            timestamp,
                        ),
                    )
                return direct.mark_attempt_launched(**kwargs)  # type: ignore[arg-type]

            def record_attempt_exit(inner_self, **kwargs: object) -> object:
                return direct.record_attempt_exit(**kwargs)  # type: ignore[arg-type]

        result = self._runner(ArchiveAtLaunchAuthority()).run(
            worker_id=self.worker_id
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "worker_launch_fenced")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(len(launched_pid), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(launched_pid[0], 0)
        with self.store.read_transaction() as connection:
            attempt = connection.execute("SELECT * FROM worker_attempts").fetchone()
        self.assertEqual(attempt["state"], "exited")
        self.assertEqual(attempt["exit_classification"], "fenced")
        self.assertIsNone(attempt["pid"])

    def test_existing_unverifiable_process_identity_refuses_duplicate(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        candidate = self.supervision.launch_candidate(
            server_definition_id=self.worker_id,
            supervisor_epoch="runner-epoch",
        )
        attempt = self.supervision.begin_attempt(
            server_definition_id=self.worker_id,
            begin_request_id="existing-attempt",
            supervisor_epoch="runner-epoch",
            expected_definition_generation=candidate["definition_generation"],
            expected_policy_generation=candidate["policy_generation"],
            expected_supervisor_generation=candidate["supervisor_generation"],
        )
        self.supervision.mark_attempt_launched(
            attempt_id=attempt["attempt_id"],
            launch_report_id="existing-launch",
            supervisor_epoch="runner-epoch",
            supervisor_generation=candidate["supervisor_generation"],
            pid=99_999,
            process_start_time="old-start",
            process_fingerprint="sha256:" + "a" * 64,
        )

        def forbidden_process(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("unverifiable active identity launched a duplicate")

        result = self._runner(
            process_factory=forbidden_process,
            process_observer=lambda _pid, _start: "mismatch",
        ).run(worker_id=self.worker_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "worker_identity_unverifiable")
        self.assertEqual(self.supervision.attempt(attempt["attempt_id"])["state"], "running")

    def test_bounded_log_uses_uuid_filename_line_tail_and_redaction(self) -> None:
        worker_id = str(self.worker_id)
        attempt_id = deterministic_id("runner-artifact-attempt", worker_id)
        secret = "exact secret+/value"
        encoded = base64.b64encode(secret.encode()).decode()
        url_encoded = quote(secret, safe="")
        capture = WorkerLogCapture(
            root=self.home / "logs",
            worker_id=worker_id,
            attempt_id=attempt_id,
            maximum_bytes=4096,
            maximum_lines=6,
            redaction_request={
                "options": {"environment": {"SECRET": secret}}
            },
        )
        raw = (
            "first\nnon-secret\npassword=hunter2\n"
            f"{secret}\n{encoded}\n{url_encoded}\nlast\n"
        ).encode()
        os.write(
            capture.child_output_fd,
            raw,
        )
        capture.child_spawned()
        deadline = time.monotonic() + 1.0
        while capture._received < len(raw) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(capture._received, len(raw))
        self.assertEqual(capture.path.read_bytes(), b"")
        artifact = capture.finish()
        path = Path(artifact["path"])
        self.assertEqual(path.name, f"worker-attempt-{artifact['artifact_id']}.log")
        payload = path.read_bytes()
        self.assertNotIn(b"first", payload)
        self.assertNotIn(b"hunter2", payload)
        self.assertNotIn(secret.encode(), payload)
        self.assertNotIn(encoded.encode(), payload)
        self.assertNotIn(url_encoded.encode(), payload)
        self.assertIn(b"password=[REDACTED]", payload)
        self.assertIn(b"last", payload)
        self.assertLessEqual(len(payload.splitlines()), 6)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), artifact["sha256"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unfinished_log_capture_never_persists_buffered_secret(self) -> None:
        secret = b"unfinished-secret-value"
        capture = WorkerLogCapture(
            root=self.home / "logs",
            worker_id=str(self.worker_id),
            attempt_id=deterministic_id("runner-unfinished-attempt", self.worker_id),
            redaction_request={
                "options": {
                    "environment": {"DATABASE_PASSWORD": secret.decode()}
                }
            },
        )
        os.write(capture.child_output_fd, b"non-secret\n" + secret + b"\n")
        capture.child_spawned()
        deadline = time.monotonic() + 1.0
        while capture._received == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreater(capture._received, 0)
        self.assertEqual(capture.path.read_bytes(), b"")
        capture.abandon()
        self.assertEqual(capture.path.read_bytes(), b"")

    def test_internal_cli_accepts_only_worker_identity_not_json(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="group", required=True)
        add_worker_cli_parser(subparsers)
        namespace = parser.parse_args(
            ["worker", "runner", "--worker-id", self.worker_id]
        )
        self.assertEqual(namespace.group, "worker")
        self.assertEqual(namespace.action, "runner")
        self.assertEqual(namespace.worker_id, self.worker_id)
        self.assertTrue(namespace.compact_json)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "worker",
                        "runner",
                        "--worker-id",
                        self.worker_id,
                        "--request-json",
                        "{}",
                    ]
                )

    def test_main_dispatches_fixed_system_runner_and_terminal_block_exits_zero(self) -> None:
        import dev_coordinator

        parser = dev_coordinator.build_parser()
        args = parser.parse_args(
            ["worker", "runner", "--worker-id", self.worker_id]
        )
        authority = object()
        artifact_root = self.home / "broker-logs"
        terminal = {
            "schema_version": 1,
            "ok": False,
            "worker_id": self.worker_id,
            "classification": "worker_not_launchable",
            "restart_allowed": False,
        }
        with (
            mock.patch.object(
                dev_coordinator, "authority_mode", return_value="system"
            ),
            mock.patch.object(dev_coordinator, "clear_exec_capability_inheritance"),
            mock.patch.object(
                dev_coordinator.BrokerWorkerAuthority,
                "load",
                return_value=authority,
            ) as load,
            mock.patch.object(
                dev_coordinator,
                "worker_log_directory",
                return_value=artifact_root,
            ),
            mock.patch.object(
                dev_coordinator,
                "worker_runner_cli_result",
                return_value=terminal,
            ) as execute,
        ):
            result = dev_coordinator.handle_cli(args)
        self.assertIs(result, terminal)
        load.assert_called_once_with(worker_id=self.worker_id)
        execute.assert_called_once_with(
            worker_id=self.worker_id,
            authority=authority,
            artifact_root=artifact_root,
        )

        with (
            mock.patch.object(dev_coordinator, "handle_cli", return_value=terminal),
            mock.patch.object(dev_coordinator, "print_result"),
        ):
            self.assertEqual(
                dev_coordinator.main(
                    ["worker", "runner", "--worker-id", self.worker_id]
                ),
                0,
            )

    def test_main_transient_worker_authority_failure_exits_nonzero_for_native_retry(self) -> None:
        import dev_coordinator

        with (
            mock.patch.object(
                dev_coordinator,
                "handle_cli",
                side_effect=WorkerAuthorityUnavailable("broker offline"),
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                dev_coordinator.main(
                    ["worker", "runner", "--worker-id", self.worker_id]
                ),
                1,
            )

    def test_broker_authority_uses_exact_configuration_and_never_sends_log_path(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(7)"))
        self._start_policy(keep_alive=True)
        candidate = dict(
            self.supervision.launch_candidate(
                server_definition_id=self.worker_id,
                supervisor_epoch="runner-epoch",
            )
        )
        policy = dict(self.supervision.policy(self.worker_id))
        policy["current_attempt_id"] = None
        attempt_id = str(uuid.uuid4())
        attempt = {
            "attempt_id": attempt_id,
            "server_definition_id": self.worker_id,
            "repo_id": self.repo_id,
            "state": "reserved",
            "supervisor_epoch": candidate["supervisor_epoch"],
            "supervisor_generation": candidate["supervisor_generation"],
        }
        begin_id = str(uuid.uuid4())
        launch_id = str(uuid.uuid4())
        exit_id = str(uuid.uuid4())
        calls: list[dict[str, object]] = []

        def handler(**kwargs: object) -> tuple[str, dict[str, object]]:
            calls.append(dict(kwargs))
            operation = kwargs["operation"]
            operation_id = kwargs.get("operation_id") or str(uuid.uuid4())
            if operation is BrokerOperation.WORKER_POLICY_READ:
                return str(operation_id), {
                    "status": "current",
                    "policy": dict(policy),
                    "candidate": dict(candidate),
                    "launch_blocker": None,
                }
            if operation is BrokerOperation.WORKER_LAUNCH_TICKET:
                return str(operation_id), {
                    "status": "reserved",
                    "operation_id": operation_id,
                    "attempt": dict(attempt),
                    "candidate": dict(candidate),
                }
            if operation is BrokerOperation.WORKER_LAUNCHED:
                return str(operation_id), {
                    "status": "running",
                    "operation_id": operation_id,
                    "attempt": {**attempt, "state": "running"},
                }
            if operation is BrokerOperation.WORKER_EXIT:
                return str(operation_id), {
                    "status": "exited",
                    "operation_id": operation_id,
                    "attempt": {
                        **attempt,
                        "state": "exited",
                        "restart_allowed": True,
                        "breaker_tripped_now": False,
                        "crash_count_in_window": 1,
                    },
                    "restart_allowed": True,
                    "breaker_tripped_now": False,
                    "crash_count_in_window": 1,
                }
            raise AssertionError(f"unexpected broker operation: {operation}")

        authority, _profile, repository = self._broker_authority(handler)
        self.assertIsNone(authority.active_attempt(worker_id=self.worker_id))
        preview = authority.launch_candidate(worker_id=self.worker_id)
        reserved = authority.begin_attempt(
            candidate=preview,
            begin_request_id=begin_id,
        )
        running = authority.mark_attempt_launched(
            candidate=preview,
            attempt=reserved,
            launch_report_id=launch_id,
            pid=12_345,
            process_start_time="process-start",
            process_fingerprint="sha256:" + "a" * 64,
        )
        local_artifact = {
            "artifact_id": str(uuid.uuid4()),
            "path": str(self.home / "logs" / "must-not-cross-wire.log"),
            "sha256": "b" * 64,
        }
        exited = authority.record_attempt_exit(
            attempt=running,
            exit_report_id=exit_id,
            exit_kind="exit_code",
            exit_code=7,
            exit_signal=None,
            log_artifact=local_artifact,
            occurred_at_epoch=1_000.0,
        )

        self.assertTrue(exited["restart_allowed"])
        self.assertEqual(
            [call["operation"] for call in calls],
            [
                BrokerOperation.WORKER_POLICY_READ,
                BrokerOperation.WORKER_POLICY_READ,
                BrokerOperation.WORKER_LAUNCH_TICKET,
                BrokerOperation.WORKER_LAUNCHED,
                BrokerOperation.WORKER_EXIT,
            ],
        )
        self.assertTrue(
            all(call["repository"] is repository for call in calls)
        )
        self.assertTrue(
            all(call["server_id"] == self.worker_id for call in calls)
        )
        mutations = calls[-3:]
        self.assertEqual(
            [call["operation_id"] for call in mutations],
            [begin_id, launch_id, exit_id],
        )
        exit_wire = mutations[-1]["arguments"]
        self.assertIsInstance(exit_wire, dict)
        self.assertEqual(
            set(exit_wire["log_artifact"]),  # type: ignore[index]
            {"artifact_id", "sha256"},
        )
        self.assertNotIn("path", exit_wire["log_artifact"])  # type: ignore[operator,index]

    def test_broker_authority_recovers_durably_fenced_launch_attempt(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        candidate = dict(
            self.supervision.launch_candidate(
                server_definition_id=self.worker_id,
                supervisor_epoch="runner-epoch",
            )
        )
        attempt = {
            "attempt_id": str(uuid.uuid4()),
            "server_definition_id": self.worker_id,
            "repo_id": self.repo_id,
            "state": "reserved",
            "supervisor_epoch": candidate["supervisor_epoch"],
            "supervisor_generation": candidate["supervisor_generation"],
        }
        launch_id = str(uuid.uuid4())

        def handler(**kwargs: object) -> tuple[str, dict[str, object]]:
            operation = kwargs["operation"]
            operation_id = kwargs.get("operation_id") or str(uuid.uuid4())
            if operation is BrokerOperation.WORKER_LAUNCHED:
                raise BrokerError(
                    "worker_launch_fenced",
                    "desired state was stopped",
                    operation_id=str(operation_id),
                )
            if operation is BrokerOperation.WORKER_ATTEMPT_READ:
                return str(operation_id), {
                    "status": "current",
                    "policy": {},
                    "attempt": {**attempt, "state": "exited"},
                }
            raise AssertionError(f"unexpected broker operation: {operation}")

        authority, profile, _repository = self._broker_authority(handler)
        with self.assertRaises(WorkerLaunchFenced) as raised:
            authority.mark_attempt_launched(
                candidate=candidate,
                attempt=attempt,
                launch_report_id=launch_id,
                pid=12_346,
                process_start_time="process-start",
                process_fingerprint="sha256:" + "c" * 64,
            )
        self.assertEqual(raised.exception.attempt["attempt_id"], attempt["attempt_id"])
        self.assertEqual(raised.exception.attempt["state"], "exited")
        self.assertEqual(
            [call.kwargs["operation"] for call in profile.worker_call.call_args_list],
            [
                BrokerOperation.WORKER_LAUNCHED,
                BrokerOperation.WORKER_ATTEMPT_READ,
            ],
        )

    def test_broker_authority_maps_uncertain_mutation_for_same_id_retry(self) -> None:
        self._set_command((sys.executable, "-c", "raise SystemExit(0)"))
        self._start_policy(keep_alive=True)
        candidate = dict(
            self.supervision.launch_candidate(
                server_definition_id=self.worker_id,
                supervisor_epoch="runner-epoch",
            )
        )
        attempt = {
            "attempt_id": str(uuid.uuid4()),
            "server_definition_id": self.worker_id,
            "repo_id": self.repo_id,
            "state": "reserved",
            "supervisor_epoch": candidate["supervisor_epoch"],
            "supervisor_generation": candidate["supervisor_generation"],
        }
        begin_id = str(uuid.uuid4())
        call_count = 0

        def handler(**kwargs: object) -> tuple[str, dict[str, object]]:
            nonlocal call_count
            call_count += 1
            operation_id = str(kwargs["operation_id"])
            if call_count == 1:
                raise BrokerError(
                    "worker_operation_uncertain",
                    "reply was lost",
                    operation_id=operation_id,
                )
            return operation_id, {
                "status": "reserved",
                "operation_id": operation_id,
                "attempt": dict(attempt),
                "candidate": dict(candidate),
            }

        authority, profile, _repository = self._broker_authority(handler)
        with self.assertRaises(WorkerAuthorityUnavailable):
            authority.begin_attempt(
                candidate=candidate,
                begin_request_id=begin_id,
            )
        reserved = authority.begin_attempt(
            candidate=candidate,
            begin_request_id=begin_id,
        )
        self.assertEqual(reserved["attempt_id"], attempt["attempt_id"])
        self.assertEqual(
            [call.kwargs["operation_id"] for call in profile.worker_call.call_args_list],
            [begin_id, begin_id],
        )

    def test_broker_authority_treats_identity_or_contract_errors_as_durable_blocks(self) -> None:
        def handler(**kwargs: object) -> tuple[str, dict[str, object]]:
            raise BrokerError(
                "worker_execution_identity_mismatch",
                "wrong execution identity",
                operation_id=str(kwargs.get("operation_id") or uuid.uuid4()),
            )

        authority, _profile, _repository = self._broker_authority(handler)
        with self.assertRaises(WorkerAuthorityBlocked):
            authority.launch_candidate(worker_id=self.worker_id)

    def test_optimized_mode_has_no_assert_dependent_runner_guards(self) -> None:
        source = Path(__file__).parents[1] / "worker_runner.py"
        text = source.read_text(encoding="utf-8")
        self.assertNotIn("assert ", text)
        self.assertNotIn("__debug__", text)


if __name__ == "__main__":
    unittest.main()
