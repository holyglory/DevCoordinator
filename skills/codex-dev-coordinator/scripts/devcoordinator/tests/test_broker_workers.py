"""Authenticated broker contracts for fixed supervised-worker runners."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import time
import unittest
import uuid
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import (  # noqa: E402
    StoreBackedBrokerRuntime,
    StoreBackedMutationBackend,
)
from devcoordinator import broker_backend as broker_backend_module  # noqa: E402
from devcoordinator.broker_persistence import StoreBackedRequestAcceptor  # noqa: E402
from devcoordinator.broker_profile import (  # noqa: E402
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.server_credentials import server_credential_id  # noqa: E402
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.worker_supervision import WorkerSupervision  # noqa: E402
from devcoordinator.worker_native import WorkerNativeError  # noqa: E402
import devcoordinator.worker_artifacts as worker_artifacts  # noqa: E402
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    PROJECT_ID,
    SERVER_ID,
    CanonicalTemporaryDirectory,
    RecordingTypedHostActions,
    seed_store_backed_broker,
)


def worker_request(
    operation: BrokerOperation,
    *,
    authority_generation: str,
    resource_id: str = SERVER_ID,
    arguments: dict[str, object] | None = None,
    operation_id: str | None = None,
) -> BrokerRequest:
    return BrokerRequest.create(
        account_id=ACCOUNT_ID,
        project_id=PROJECT_ID,
        resource_id=resource_id,
        operation=operation,
        arguments=arguments or {},
        operation_id=operation_id,
        authority_generation=authority_generation,
    )


class WorkerBrokerWireTests(unittest.TestCase):
    def test_default_worker_log_root_stays_inside_authority_state(self) -> None:
        if sys.platform == "darwin":
            self.assertEqual(
                worker_artifacts.SYSTEM_WORKER_LOG_ROOT,
                Path(
                    "/Library/Application Support/DevCoordinator/Authority/worker-logs"
                ),
            )
        else:
            self.assertEqual(
                worker_artifacts.SYSTEM_WORKER_LOG_ROOT,
                Path("/var/lib/devcoordinator/worker-logs"),
            )
            self.assertNotEqual(
                worker_artifacts.SYSTEM_WORKER_LOG_ROOT,
                Path("/var/lib/devcoordinator-clients"),
            )

    def test_worker_wire_is_strict_and_never_accepts_launch_paths_or_commands(self) -> None:
        generation = "authority"
        ticket = {
            "supervisor_epoch": "broker-startup-1",
            "expected_definition_generation": 2,
            "expected_policy_generation": 3,
            "expected_supervisor_generation": 4,
        }
        parsed = worker_request(
            BrokerOperation.WORKER_LAUNCH_TICKET,
            authority_generation=generation,
            arguments=ticket,
        )
        self.assertEqual(dict(parsed.arguments), ticket)
        for forbidden in ("argv", "cwd", "environment", "path", "command"):
            with self.subTest(forbidden=forbidden), self.assertRaises(BrokerError) as raised:
                worker_request(
                    BrokerOperation.WORKER_LAUNCH_TICKET,
                    authority_generation=generation,
                    arguments={**ticket, forbidden: "/untrusted"},
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")
        with self.assertRaises(BrokerError) as raised:
            worker_request(
                BrokerOperation.WORKER_EXIT,
                authority_generation=generation,
                arguments={
                    **self._exit_arguments(),
                    "log_artifact": {
                        "artifact_id": str(uuid.uuid4()),
                        "sha256": "a" * 64,
                        "path": "/tmp/untrusted",
                    },
                },
            )
        self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_worker_wire_rejects_unbounded_and_incoherent_evidence(self) -> None:
        generation = "authority"
        invalid = (
            {"exit_kind": "signal", "exit_code": 1, "exit_signal": 9},
            {"exit_kind": "signal", "exit_code": None, "exit_signal": 0},
            {"exit_kind": "exit_code", "exit_code": None, "exit_signal": None},
            {"occurred_at_epoch": float("inf")},
            {
                "log_artifact": {
                    "artifact_id": str(uuid.uuid4()),
                    "sha256": "A" * 64,
                }
            },
        )
        for update in invalid:
            with self.subTest(update=update), self.assertRaises(BrokerError):
                worker_request(
                    BrokerOperation.WORKER_EXIT,
                    authority_generation=generation,
                    arguments={**self._exit_arguments(), **update},
                )

    def test_profile_worker_call_requires_an_exact_configured_server(self) -> None:
        repository = BrokerRepositoryProfile(
            canonical_root="/repos/alpha",
            repo_id=PROJECT_ID,
            generation=0,
            server_ids={"web": SERVER_ID},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=Path("/run/devcoordinator-authority.sock"),
                database_generation="authority",
            ),
            repositories={repository.canonical_root: repository},
        )
        self.assertIs(profile.repository_for_server_id(SERVER_ID), repository)
        with self.assertRaises(BrokerProfileError):
            profile.repository_for_server_id("server-not-configured")
        with mock.patch.object(
            BrokerClientProfile,
            "call",
            return_value=("operation", {"status": "current"}),
        ) as call:
            result = profile.worker_call(
                repository=repository,
                server_id=SERVER_ID,
                operation=BrokerOperation.WORKER_POLICY_READ,
            )
        self.assertEqual(result[1]["status"], "current")
        call.assert_called_once_with(
            repository=repository,
            resource_id=SERVER_ID,
            operation=BrokerOperation.WORKER_POLICY_READ,
            arguments=None,
            operation_id=None,
        )
        with self.assertRaises(BrokerProfileError):
            profile.worker_call(
                repository=repository,
                server_id="server-not-configured",
                operation=BrokerOperation.WORKER_POLICY_READ,
            )
        with self.assertRaises(ValueError):
            profile.worker_call(
                repository=repository,
                server_id=SERVER_ID,
                operation=BrokerOperation.DOCKER_STOP,
            )

        duplicate = BrokerRepositoryProfile(
            canonical_root="/repos/beta",
            repo_id="repo-beta",
            generation=0,
            server_ids={"worker": SERVER_ID},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        ambiguous = BrokerClientProfile(
            service=profile.service,
            repositories={
                repository.canonical_root: repository,
                duplicate.canonical_root: duplicate,
            },
        )
        with self.assertRaisesRegex(BrokerProfileError, "ambiguous"):
            ambiguous.repository_for_server_id(SERVER_ID)

    @staticmethod
    def _exit_arguments() -> dict[str, object]:
        return {
            "attempt_id": str(uuid.uuid4()),
            "supervisor_epoch": "broker-startup-1",
            "supervisor_generation": 1,
            "exit_kind": "exit_code",
            "exit_code": 1,
            "exit_signal": None,
            "log_artifact": None,
            "occurred_at_epoch": None,
        }


class WorkerBrokerStartupTests(unittest.TestCase):
    def test_broker_startup_uses_one_new_epoch_and_one_bounded_reconciliation(
        self,
    ) -> None:
        persistence = mock.Mock()
        persistence.database_path = Path("/service/coordinator.sqlite3")
        persistence.expected_uid = os.geteuid()
        persistence.busy_timeout_ms = 5_000
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = None
        fenced_epochs: list[str] = []
        autostart_epochs: list[str] = []
        testcase = self

        class FakeController:
            def __init__(self, received_store, **kwargs):
                testcase.assertIs(received_store, store)
                testcase.assertTrue(
                    Path(kwargs["coordinator_script"]).is_absolute()
                )

            def fence_startup(self, *, supervisor_epoch: str):
                fenced_epochs.append(supervisor_epoch)
                return {
                    "ok": True,
                    "supervisor_epoch": supervisor_epoch,
                    "fenced_old_runners": [SERVER_ID],
                    "autostart_expected": [SERVER_ID],
                    "started": [],
                    "errors": [],
                }

            def autostart_fenced(
                self, *, supervisor_epoch: str, expected_worker_ids: list[str]
            ):
                autostart_epochs.append(supervisor_epoch)
                testcase.assertEqual(expected_worker_ids, [SERVER_ID])
                return {
                    "ok": False,
                    "supervisor_epoch": supervisor_epoch,
                    "fenced_old_runners": [],
                    "started": [],
                    "errors": [
                        {
                            "worker_id": SERVER_ID,
                            "phase": "autostart",
                            "error": "native manager unavailable",
                        }
                    ],
                }

        runtime = StoreBackedBrokerRuntime(
            persistence=persistence,
            backend=mock.Mock(),
            writer=mock.Mock(),
            service=mock.Mock(),
            server=mock.Mock(),
        )
        with (
            mock.patch.object(
                broker_backend_module.AccountStore,
                "open",
                return_value=store,
            ) as opened,
            mock.patch.object(
                broker_backend_module, "WorkerController", FakeController
            ),
        ):
            result = runtime.reconcile_workers_on_startup()

        self.assertFalse(result["ok"])
        self.assertEqual(len(fenced_epochs), 1)
        self.assertEqual(fenced_epochs, autostart_epochs)
        self.assertEqual(str(uuid.UUID(fenced_epochs[0])), fenced_epochs[0])
        self.assertEqual(
            opened.call_args_list,
            [
                mock.call(
                    persistence.database_path,
                    expected_uid=persistence.expected_uid,
                    busy_timeout_ms=persistence.busy_timeout_ms,
                ),
                mock.call(
                    persistence.database_path,
                    expected_uid=persistence.expected_uid,
                    busy_timeout_ms=persistence.busy_timeout_ms,
                ),
            ],
        )



class WorkerBrokerBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.__enter__()
        self.persistence, _actions = seed_store_backed_broker(self.root)
        self.actions = RecordingTypedHostActions()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            self.authority_generation = store.metadata.database_generation
            with store.immediate_transaction() as connection:
                connection.executemany(
                    """
                    INSERT INTO server_command_arguments(
                        server_definition_id, ordinal, argument
                    ) VALUES (?, ?, ?)
                    """,
                    ((SERVER_ID, 0, "/usr/bin/python3"), (SERVER_ID, 1, "worker.py")),
                )
                connection.execute(
                    """
                    INSERT INTO server_environment(server_definition_id, name, value)
                    VALUES (?, 'WORKER_MODE', 'test')
                    """,
                    (SERVER_ID,),
                )
                self.credential_id = server_credential_id(
                    SERVER_ID, "DATABASE_URL"
                )
                connection.execute(
                    """
                    INSERT INTO server_environment_credentials(
                        server_definition_id,name,credential_id,created_at,updated_at
                    ) VALUES (?,?,?,?,?)
                    """,
                    (
                        SERVER_ID,
                        "DATABASE_URL",
                        self.credential_id,
                        utc_timestamp(),
                        utc_timestamp(),
                    ),
                )
            supervision = WorkerSupervision(store)
            supervision.configure_policy(
                server_definition_id=SERVER_ID,
                actor="fixture",
                execution_uid=os.geteuid(),
                keep_alive=True,
            )
            start_operation = str(uuid.uuid4())
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (?, ?, 'worker.start', 'succeeded', 'complete', 0,
                              'fixture', 'fixture', ?, ?)
                    """,
                    (start_operation, PROJECT_ID, now, now),
                )
            supervision.request_start(
                server_definition_id=SERVER_ID,
                actor="fixture",
                operation_id=start_operation,
            )
            self.candidate = supervision.fence_startup(
                supervisor_epoch="broker-startup-1"
            )[0]
        self.log_root = self.root / "client-journals"
        self.log_directory = self.log_root / str(os.geteuid()) / "logs"
        self.log_directory.mkdir(mode=0o700, parents=True)
        os.chmod(self.log_directory, 0o700)
        self.artifact_patch = mock.patch.object(
            worker_artifacts, "SYSTEM_WORKER_LOG_ROOT", self.log_root
        )
        self.artifact_patch.start()
        self.caller_patch = mock.patch(
            "devcoordinator.broker_workers.verify_systemd_worker_caller",
            return_value={"verified": True},
        )
        self.caller_proof = self.caller_patch.start()

    def tearDown(self) -> None:
        self.caller_patch.stop()
        self.artifact_patch.stop()
        self.temporary.__exit__(None, None, None)

    def _service(self) -> BrokerService:
        backend = StoreBackedMutationBackend(self.persistence, self.actions)
        return BrokerService(
            StoreBackedRequestAcceptor(self.persistence), SerializedMutationWriter(backend)
        )

    def _reply(
        self, service: BrokerService, peer: PeerCredentials, request: BrokerRequest
    ) -> dict[str, object]:
        return service.reply_for_document(peer, request.to_wire())

    def _ticket_request(self, operation_id: str | None = None) -> BrokerRequest:
        return worker_request(
            BrokerOperation.WORKER_LAUNCH_TICKET,
            authority_generation=self.authority_generation,
            operation_id=operation_id,
            arguments={
                "supervisor_epoch": self.candidate["supervisor_epoch"],
                "expected_definition_generation": self.candidate[
                    "definition_generation"
                ],
                "expected_policy_generation": self.candidate["policy_generation"],
                "expected_supervisor_generation": self.candidate[
                    "supervisor_generation"
                ],
            },
        )

    def test_ticket_launch_exit_and_restart_evidence_are_durable(self) -> None:
        service = self._service()
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        preview = self._reply(
            service,
            peer,
            worker_request(
                BrokerOperation.WORKER_POLICY_READ,
                authority_generation=self.authority_generation,
            ),
        )
        self.assertTrue(preview["ok"], preview)
        self.assertEqual(
            preview["result"]["candidate"]["server_definition_id"], SERVER_ID
        )
        self.assertIsNone(preview["result"]["launch_blocker"])
        ticket_request = self._ticket_request()
        ticket_reply = self._reply(service, peer, ticket_request)
        self.assertTrue(ticket_reply["ok"], ticket_reply)
        ticket = ticket_reply["result"]
        attempt = ticket["attempt"]
        candidate = ticket["candidate"]
        self.assertEqual(candidate, preview["result"]["candidate"])
        self.assertEqual(candidate["argv"], ["/usr/bin/python3", "worker.py"])
        self.assertEqual(candidate["environment"], {"WORKER_MODE": "test"})
        self.assertEqual(
            candidate["credential_bindings"],
            [{"name": "DATABASE_URL", "credential_id": self.credential_id}],
        )

        active_preview = self._reply(
            service,
            peer,
            worker_request(
                BrokerOperation.WORKER_POLICY_READ,
                authority_generation=self.authority_generation,
            ),
        )
        self.assertTrue(active_preview["ok"], active_preview)
        self.assertIsNone(active_preview["result"]["candidate"])
        self.assertEqual(
            active_preview["result"]["launch_blocker"]["code"],
            "worker_not_launchable",
        )

        launch_request = worker_request(
            BrokerOperation.WORKER_LAUNCHED,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "pid": 12_345,
                "process_start_time": "process-start-1",
                "process_fingerprint": "sha256:" + "a" * 64,
            },
        )
        launched = self._reply(service, peer, launch_request)
        self.assertTrue(launched["ok"], launched)
        self.assertEqual(launched["result"]["attempt"]["state"], "running")

        artifact_id = str(uuid.uuid4())
        log_path = Path(
            worker_artifacts.worker_log_artifact(os.geteuid(), artifact_id)["path"]
        )
        payload = b"worker failed\n"
        log_path.write_bytes(payload)
        os.chmod(log_path, 0o600)
        exit_request = worker_request(
            BrokerOperation.WORKER_EXIT,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "exit_kind": "exit_code",
                "exit_code": 1,
                "exit_signal": None,
                "log_artifact": {
                    "artifact_id": artifact_id,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                "occurred_at_epoch": time.time(),
            },
        )
        exited = self._reply(service, peer, exit_request)
        self.assertTrue(exited["ok"], exited)
        self.assertTrue(exited["result"]["restart_allowed"])
        self.assertEqual(
            exited["result"]["attempt"]["log_artifact"]["path"], str(log_path)
        )
        self.assertIsNotNone(exited["result"]["attempt"]["crash_event"])

        # A fresh backend (empty in-memory replay cache) returns the exact
        # durably committed ticket and exit evidence without another attempt.
        replay_ticket = self._reply(self._service(), peer, ticket_request)
        replay_exit = self._reply(self._service(), peer, exit_request)
        self.assertEqual(replay_ticket, ticket_reply)
        self.assertEqual(replay_exit, exited)

        changed_launch = worker_request(
            BrokerOperation.WORKER_LAUNCHED,
            authority_generation=self.authority_generation,
            operation_id=launch_request.operation_id,
            arguments={**dict(launch_request.arguments), "pid": 12_346},
        )
        conflicting_replay = self._reply(self._service(), peer, changed_launch)
        self.assertFalse(conflicting_replay["ok"])
        self.assertEqual(
            conflicting_replay["error"]["code"], "operation_id_conflict"
        )
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                    1,
                )

    def test_manual_runner_is_rejected_before_candidate_or_attempt_creation(self) -> None:
        self.caller_proof.side_effect = WorkerNativeError(
            "injected manual runner identity"
        )
        service = self._service()
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        preview = self._reply(
            service,
            peer,
            worker_request(
                BrokerOperation.WORKER_POLICY_READ,
                authority_generation=self.authority_generation,
            ),
        )
        self.assertFalse(preview["ok"])
        self.assertEqual(preview["error"]["code"], "worker_native_caller_invalid")
        ticket = self._reply(service, peer, self._ticket_request())
        self.assertFalse(ticket["ok"])
        self.assertEqual(ticket["error"]["code"], "worker_native_caller_invalid")
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM worker_attempts").fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM broker_worker_operation_requests"
                    ).fetchone()[0],
                    0,
                )

    def test_launch_report_is_durably_fenced_after_stop(self) -> None:
        service = self._service()
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        ticket = self._reply(service, peer, self._ticket_request())["result"]
        attempt = ticket["attempt"]

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            stop_operation = str(uuid.uuid4())
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (?, ?, 'worker.stop', 'succeeded', 'complete', 0,
                              'fixture', 'fixture', ?, ?)
                    """,
                    (stop_operation, PROJECT_ID, now, now),
                )
            WorkerSupervision(store).request_stop(
                server_definition_id=SERVER_ID,
                actor="fixture",
                operation_id=stop_operation,
            )

        launch_request = worker_request(
            BrokerOperation.WORKER_LAUNCHED,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "pid": 12_347,
                "process_start_time": "process-start-fenced",
                "process_fingerprint": "sha256:" + "c" * 64,
            },
        )
        fenced = self._reply(service, peer, launch_request)
        self.assertFalse(fenced["ok"])
        self.assertEqual(fenced["error"]["code"], "worker_launch_fenced")
        self.assertEqual(self._reply(self._service(), peer, launch_request), fenced)

        read = self._reply(
            service,
            peer,
            worker_request(
                BrokerOperation.WORKER_ATTEMPT_READ,
                authority_generation=self.authority_generation,
                arguments={"attempt_id": attempt["attempt_id"]},
            ),
        )
        self.assertTrue(read["ok"], read)
        self.assertEqual(read["result"]["attempt"]["state"], "exited")
        self.assertEqual(
            read["result"]["attempt"]["exit_classification"], "intentional"
        )

    def test_ticket_recovers_after_transition_commits_before_result_journal(self) -> None:
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        request = self._ticket_request()
        backend = StoreBackedMutationBackend(self.persistence, self.actions)
        interrupted = BrokerService(
            StoreBackedRequestAcceptor(self.persistence), SerializedMutationWriter(backend)
        )
        with mock.patch.object(
            backend._worker_operations,
            "_succeed",
            side_effect=RuntimeError("injected result-journal outage"),
        ):
            uncertain = self._reply(interrupted, peer, request)
        self.assertFalse(uncertain["ok"])
        self.assertEqual(
            uncertain["error"]["code"], "worker_operation_uncertain"
        )

        recovered = self._reply(self._service(), peer, request)
        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["result"]["candidate"]["argv"], [
            "/usr/bin/python3",
            "worker.py",
        ])
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM worker_attempts"
                    ).fetchone()[0],
                    1,
                )

    def test_exit_recovers_without_reopening_log_after_state_commit(self) -> None:
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        service = self._service()
        attempt = self._reply(service, peer, self._ticket_request())["result"][
            "attempt"
        ]
        launched = worker_request(
            BrokerOperation.WORKER_LAUNCHED,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "pid": 12_348,
                "process_start_time": "process-start-interrupted-exit",
                "process_fingerprint": "sha256:" + "d" * 64,
            },
        )
        self.assertTrue(self._reply(service, peer, launched)["ok"])

        artifact = worker_artifacts.worker_log_artifact(
            os.geteuid(), str(uuid.uuid4())
        )
        payload = b"durable crash evidence\n"
        path = Path(artifact["path"])
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        request = worker_request(
            BrokerOperation.WORKER_EXIT,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "exit_kind": "exit_code",
                "exit_code": 9,
                "exit_signal": None,
                "log_artifact": {
                    "artifact_id": artifact["artifact_id"],
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                "occurred_at_epoch": time.time(),
            },
        )
        backend = StoreBackedMutationBackend(self.persistence, self.actions)
        interrupted = BrokerService(
            StoreBackedRequestAcceptor(self.persistence), SerializedMutationWriter(backend)
        )
        with mock.patch.object(
            backend._worker_operations,
            "_succeed",
            side_effect=RuntimeError("injected result-journal outage"),
        ):
            uncertain = self._reply(interrupted, peer, request)
        self.assertFalse(uncertain["ok"])
        self.assertEqual(
            uncertain["error"]["code"], "worker_operation_uncertain"
        )

        path.unlink()
        recovered = self._reply(self._service(), peer, request)
        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(
            recovered["result"]["attempt"]["log_artifact"]["path"], str(path)
        )


    def test_artifact_id_path_and_digest_are_verified_without_mode_authorization(self) -> None:
        service = self._service()
        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        ticket = self._reply(service, peer, self._ticket_request())["result"]
        attempt = ticket["attempt"]
        artifact = worker_artifacts.worker_log_artifact(
            os.geteuid(), str(uuid.uuid4())
        )
        launched = worker_request(
            BrokerOperation.WORKER_LAUNCHED,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "pid": 12_346,
                "process_start_time": "process-start-2",
                "process_fingerprint": "sha256:" + "b" * 64,
            },
        )
        self.assertTrue(self._reply(service, peer, launched)["ok"])
        path = Path(artifact["path"])
        path.write_bytes(b"failure")
        os.chmod(path, 0o644)
        exit_request = worker_request(
            BrokerOperation.WORKER_EXIT,
            authority_generation=self.authority_generation,
            arguments={
                "attempt_id": attempt["attempt_id"],
                "supervisor_epoch": attempt["supervisor_epoch"],
                "supervisor_generation": attempt["supervisor_generation"],
                "exit_kind": "exit_code",
                "exit_code": 2,
                "exit_signal": None,
                "log_artifact": {
                    "artifact_id": artifact["artifact_id"],
                    "sha256": hashlib.sha256(b"failure").hexdigest(),
                },
                "occurred_at_epoch": None,
            },
        )
        accepted = self._reply(service, peer, exit_request)
        self.assertTrue(accepted["ok"], accepted)
        self.assertEqual(
            accepted["result"]["attempt"]["log_artifact"]["path"],
            str(path),
        )


if __name__ == "__main__":
    unittest.main()
