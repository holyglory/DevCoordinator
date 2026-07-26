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
from devcoordinator.broker_persistence import StoreBackedAuthorizer  # noqa: E402
from devcoordinator.broker_profile import (  # noqa: E402
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.worker_supervision import WorkerSupervision  # noqa: E402
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

    def test_profile_worker_call_requires_an_exact_enrolled_server(self) -> None:
        repository = BrokerRepositoryProfile(
            canonical_root="/repos/alpha",
            repo_id=PROJECT_ID,
            generation=0,
            server_ids={"web": SERVER_ID},
            container_ids={},
            compose_definition_id=None,
        )
        profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=Path("/run/devcoordinator/broker.sock"),
                service_uid=0,
                socket_gid=100,
                socket_mode=0o660,
                database_generation="authority",
            ),
            client_uid=os.geteuid(),
            account_id=ACCOUNT_ID,
            issued_at="2026-07-26T00:00:00Z",
            valid_until_epoch=int(time.time()) + 3600,
            repositories={repository.canonical_root: repository},
        )
        self.assertIs(profile.repository_for_server_id(SERVER_ID), repository)
        with self.assertRaises(BrokerProfileError):
            profile.repository_for_server_id("server-not-enrolled")
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
                server_id="server-not-enrolled",
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
        )
        ambiguous = BrokerClientProfile(
            service=profile.service,
            client_uid=profile.client_uid,
            account_id=profile.account_id,
            issued_at=profile.issued_at,
            valid_until_epoch=profile.valid_until_epoch,
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
        epochs: list[str] = []
        testcase = self

        class FakeController:
            def __init__(self, received_store, **kwargs):
                testcase.assertIs(received_store, store)
                testcase.assertTrue(
                    Path(kwargs["coordinator_script"]).is_absolute()
                )

            def reconcile_startup(self, *, supervisor_epoch: str):
                epochs.append(supervisor_epoch)
                return {
                    "ok": False,
                    "supervisor_epoch": supervisor_epoch,
                    "fenced_old_runners": [SERVER_ID],
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
        self.assertEqual(len(epochs), 1)
        self.assertEqual(str(uuid.UUID(epochs[0])), epochs[0])
        opened.assert_called_once_with(
            persistence.database_path,
            expected_uid=persistence.expected_uid,
            busy_timeout_ms=persistence.busy_timeout_ms,
        )


class WorkerBrokerMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.__enter__()
        self.persistence, _actions = seed_store_backed_broker(self.root)
        self.uid = os.geteuid()
        self.other_uid = self.uid + 10_001
        self.runtime_revoked = str(uuid.uuid4())
        self.non_worker = str(uuid.uuid4())
        self.worker_acl_revoked = str(uuid.uuid4())
        self.wrong_repo = str(uuid.uuid4())
        now = utc_timestamp()

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE server_definitions SET role = 'worker' "
                    "WHERE server_definition_id = ?",
                    (SERVER_ID,),
                )
                for server_id, name, role in (
                    (self.runtime_revoked, "runtime-revoked", "worker"),
                    (self.non_worker, "ordinary-web", "web"),
                    (self.worker_acl_revoked, "worker-acl-revoked", "worker"),
                ):
                    connection.execute(
                        """
                        INSERT INTO server_definitions(
                            server_definition_id, repo_id, name, role, cwd,
                            definition_fingerprint, generation,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, '/repos/alpha', ?, 0, ?, ?)
                        """,
                        (
                            server_id,
                            PROJECT_ID,
                            name,
                            role,
                            "definition-" + server_id,
                            now,
                            now,
                        ),
                    )
                host_id = str(
                    connection.execute(
                        "SELECT host_id FROM repositories WHERE repo_id = ?",
                        (PROJECT_ID,),
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, '/repos/wrong', 'Wrong', 'active', 0, ?, ?)
                    """,
                    (self.wrong_repo, host_id, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                    """,
                    (self.wrong_repo, now),
                )
            supervision = WorkerSupervision(store)
            for server_id in (
                SERVER_ID,
                self.runtime_revoked,
                self.non_worker,
                self.worker_acl_revoked,
            ):
                supervision.configure_policy(
                    server_definition_id=server_id,
                    actor="fixture",
                    execution_uid=self.uid,
                    keep_alive=True,
                )

        self.persistence.provision_principal(
            uid=self.other_uid, account_id=ACCOUNT_ID
        )
        for uid, repo_id in (
            (self.other_uid, PROJECT_ID),
            (self.uid, self.wrong_repo),
        ):
            self.persistence.provision_repository_enrollment(
                uid=uid,
                repo_id=repo_id,
                account_id=ACCOUNT_ID,
                issued_at=now,
                valid_until_epoch=int(time.time()) + 3600,
            )

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=self.uid
        ) as store:
            with store.immediate_transaction() as connection:
                rows: list[tuple[int, str, str, str, int, str]] = []
                for uid, repo_id, server_id in (
                    (self.uid, PROJECT_ID, SERVER_ID),
                    (self.uid, PROJECT_ID, self.runtime_revoked),
                    (self.uid, PROJECT_ID, self.non_worker),
                    (self.uid, PROJECT_ID, self.worker_acl_revoked),
                    (self.other_uid, PROJECT_ID, SERVER_ID),
                    (self.uid, self.wrong_repo, SERVER_ID),
                ):
                    for action in ("status", "start", "stop", "restart"):
                        enabled = int(
                            not (
                                server_id == self.runtime_revoked
                                and action == "restart"
                            )
                        )
                        rows.append(
                            (uid, repo_id, server_id, action, enabled, now)
                        )
                connection.executemany(
                    """
                    INSERT INTO broker_runtime_acl(
                        uid, repo_id, resource_kind, resource_id,
                        action, enabled, updated_at
                    ) VALUES (?, ?, 'service', ?, ?, ?, ?)
                    """,
                    rows,
                )
        self.persistence.grant_worker(
            uid=self.uid,
            repo_id=PROJECT_ID,
            server_definition_id=self.worker_acl_revoked,
            operation=BrokerOperation.WORKER_LAUNCH_TICKET,
            enabled=False,
        )

    def tearDown(self) -> None:
        self.temporary.__exit__(None, None, None)

    def test_worker_acl_upgrade_backfill_is_exact_revocation_safe_and_idempotent(
        self,
    ) -> None:
        for _run in range(2):
            self.persistence = type(self.persistence)(
                self.persistence.database_path, expected_uid=self.uid
            )

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=self.uid
        ) as store:
            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT uid, repo_id, server_definition_id,
                               operation, enabled
                        FROM broker_worker_acl
                        ORDER BY uid, repo_id, server_definition_id, operation
                        """
                    )
                )
        positive = [
            row
            for row in rows
            if int(row["uid"]) == self.uid
            and str(row["repo_id"]) == PROJECT_ID
            and str(row["server_definition_id"]) == SERVER_ID
        ]
        self.assertEqual(len(positive), 5)
        self.assertTrue(all(bool(row["enabled"]) for row in positive))
        self.assertFalse(
            any(str(row["server_definition_id"]) == self.runtime_revoked for row in rows)
        )
        self.assertFalse(
            any(str(row["server_definition_id"]) == self.non_worker for row in rows)
        )
        explicit_revocation = [
            row
            for row in rows
            if str(row["server_definition_id"]) == self.worker_acl_revoked
        ]
        self.assertEqual(len(explicit_revocation), 1)
        self.assertFalse(bool(explicit_revocation[0]["enabled"]))
        self.assertFalse(any(int(row["uid"]) == self.other_uid for row in rows))
        self.assertFalse(
            any(str(row["repo_id"]) == self.wrong_repo for row in rows)
        )


class WorkerBrokerBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.__enter__()
        self.persistence, _actions = seed_store_backed_broker(self.root)
        self.actions = RecordingTypedHostActions()
        self.persistence.replace_server_access(
            uid=os.geteuid(),
            repo_id=PROJECT_ID,
            server_definition_ids=(SERVER_ID,),
            start_port=3100,
            end_port=3199,
        )
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
            worker_artifacts, "SYSTEM_CLIENT_JOURNAL_ROOT", self.log_root
        )
        self.artifact_patch.start()

    def tearDown(self) -> None:
        self.artifact_patch.stop()
        self.temporary.__exit__(None, None, None)

    def _service(self) -> BrokerService:
        backend = StoreBackedMutationBackend(self.persistence, self.actions)
        return BrokerService(
            StoreBackedAuthorizer(self.persistence), SerializedMutationWriter(backend)
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
            StoreBackedAuthorizer(self.persistence), SerializedMutationWriter(backend)
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
            StoreBackedAuthorizer(self.persistence), SerializedMutationWriter(backend)
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

    def test_wrong_peer_and_cross_worker_attempt_fail_closed(self) -> None:
        service = self._service()
        request = self._ticket_request()
        wrong_uid = os.geteuid() + 10_000
        self.persistence.provision_principal(uid=wrong_uid, account_id=ACCOUNT_ID)
        self.persistence.provision_repository_enrollment(
            uid=wrong_uid,
            repo_id=PROJECT_ID,
            account_id=ACCOUNT_ID,
            issued_at=utc_timestamp(),
            valid_until_epoch=int(time.time()) + 3600,
        )
        self.persistence.grant_worker(
            uid=wrong_uid,
            repo_id=PROJECT_ID,
            server_definition_id=SERVER_ID,
            operation=BrokerOperation.WORKER_LAUNCH_TICKET,
        )
        wrong_peer = PeerCredentials(
            uid=wrong_uid, gid=os.getegid(), pid=os.getpid()
        )
        denied = self._reply(service, wrong_peer, request)
        self.assertFalse(denied["ok"])
        self.assertEqual(
            denied["error"]["code"], "worker_execution_identity_mismatch"
        )

        peer = PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid())
        ticket = self._reply(service, peer, request)["result"]
        other_server = str(uuid.uuid4())
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES (?, ?, 'other', '/repos/alpha', 'other', 0, ?, ?)
                    """,
                    (other_server, PROJECT_ID, now, now),
                )
            WorkerSupervision(store).configure_policy(
                server_definition_id=other_server,
                actor="fixture",
                execution_uid=os.geteuid(),
                keep_alive=True,
            )
        self.persistence.grant_worker(
            uid=os.geteuid(),
            repo_id=PROJECT_ID,
            server_definition_id=other_server,
            operation=BrokerOperation.WORKER_ATTEMPT_READ,
        )
        cross = worker_request(
            BrokerOperation.WORKER_ATTEMPT_READ,
            authority_generation=self.authority_generation,
            resource_id=other_server,
            arguments={"attempt_id": ticket["attempt"]["attempt_id"]},
        )
        denied = self._reply(service, peer, cross)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "worker_attempt_access_denied")

    def test_artifact_id_path_digest_and_permissions_are_broker_verified(self) -> None:
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
        denied = self._reply(service, peer, exit_request)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "worker_log_artifact_invalid")


if __name__ == "__main__":
    unittest.main()
