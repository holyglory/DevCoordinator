"""Focused contracts for the ID-only shared-authority runtime endpoint."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator import broker_backend as broker_backend_module  # noqa: E402
from devcoordinator.broker_persistence import StoreBackedAuthorizer  # noqa: E402
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.worker_control import WorkerReplaceError  # noqa: E402
from devcoordinator.worker_supervision import WorkerSupervision  # noqa: E402
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    CONTAINER_ID,
    DATABASE_ID,
    HOST_ID,
    PROJECT_ID,
    SERVER_ID,
    CanonicalTemporaryDirectory,
    _committed_available_observer,
    peer_for,
    request_for,
    seed_postgres_database,
    seed_store_backed_broker,
)


def runtime_arguments(
    *,
    action: str = "status",
    purpose: str = "development",
    ttl_seconds: int | None = None,
    temporary_repo_id: str | None = None,
    target_kind: str = "docker",
) -> dict[str, object]:
    return {
        "action": action,
        "agent": "runtime-test-agent",
        "root_repo_id": PROJECT_ID,
        "temporary_repo_id": temporary_repo_id,
        "target_kind": target_kind,
        "purpose": purpose,
        "ttl_seconds": ttl_seconds,
        "kill_after_run": False,
    }


class BrokerRuntimeWireTests(unittest.TestCase):
    def test_wire_accepts_only_ids_and_typed_policy(self) -> None:
        arguments = runtime_arguments()
        request = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=CONTAINER_ID,
            arguments=arguments,
        )

        self.assertEqual(request.arguments, arguments)
        self.assertNotIn("argv", request.to_wire()["arguments"])
        self.assertNotIn("cwd", request.to_wire()["arguments"])

        for forbidden in ("argv", "cwd", "environment", "port"):
            with self.subTest(forbidden=forbidden), self.assertRaises(BrokerError) as raised:
                request_for(
                    BrokerOperation.RUNTIME_REQUEST,
                    resource_id=CONTAINER_ID,
                    arguments={**arguments, forbidden: "client-controlled"},
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_wire_rejects_unsafe_actions_and_invalid_cleanup_policy(self) -> None:
        for action in ("run",):
            with self.subTest(action=action), self.assertRaises(BrokerError) as raised:
                request_for(
                    BrokerOperation.RUNTIME_REQUEST,
                    resource_id=CONTAINER_ID,
                    arguments={**runtime_arguments(), "action": action},
                )
            self.assertEqual(raised.exception.code, "unsupported_runtime_action")

        replacement = {
            **runtime_arguments(action="replace", target_kind="service"),
            "expected_definition_generation": 0,
            "argv": ["/usr/bin/python3", "worker.py"],
            "cwd": "/repos/alpha",
            "environment": {"MODE": "development"},
            "keep_alive": True,
        }
        accepted = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=SERVER_ID,
            arguments=replacement,
        )
        self.assertEqual(accepted.arguments, replacement)
        with self.assertRaises(BrokerError) as raised:
            request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=CONTAINER_ID,
                arguments={**replacement, "target_kind": "docker"},
            )
        self.assertEqual(raised.exception.code, "invalid_arguments")

        invalid_policies = (
            {"kill_after_run": 1},
            {"kill_after_run": True},
            {"ttl_seconds": 30},
            {"action": "start", "purpose": "test", "ttl_seconds": None},
        )
        for update in invalid_policies:
            with self.subTest(update=update), self.assertRaises(BrokerError):
                request_for(
                    BrokerOperation.RUNTIME_REQUEST,
                    resource_id=CONTAINER_ID,
                    arguments={**runtime_arguments(), **update},
                )

    def test_wire_accepts_only_typed_worker_supervision_policy(self) -> None:
        arguments = {
            **runtime_arguments(action="start", target_kind="service"),
            "keep_alive": True,
            "rearm_crash_loop": True,
            "restart_limit": 10,
            "restart_window_seconds": 300,
        }
        request = request_for(
            BrokerOperation.RUNTIME_REQUEST,
            resource_id=SERVER_ID,
            arguments=arguments,
        )
        self.assertEqual(request.arguments, arguments)

        for field, invalid in (
            ("keep_alive", 1),
            ("rearm_crash_loop", "yes"),
            ("restart_limit", 0),
            ("restart_window_seconds", 604_801),
        ):
            with self.subTest(field=field), self.assertRaises(BrokerError):
                request_for(
                    BrokerOperation.RUNTIME_REQUEST,
                    resource_id=SERVER_ID,
                    arguments={**arguments, field: invalid},
                )
        with self.assertRaises(BrokerError):
            request_for(
                BrokerOperation.RUNTIME_REQUEST,
                resource_id=CONTAINER_ID,
                arguments={
                    **runtime_arguments(action="start"),
                    "keep_alive": True,
                },
            )


class BrokerWorkerCleanupPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = object.__new__(StoreBackedMutationBackend)
        self.persistence = mock.Mock()
        self.backend._persistence = self.persistence
        self.authorized = SimpleNamespace(peer=SimpleNamespace(uid=501))

    def test_permanent_worker_cleanup_revokes_service_and_profile_before_unregister(self) -> None:
        plan = SimpleNamespace(
            action="purge",
            target_kind="server",
            target_id=SERVER_ID,
            repo_id=PROJECT_ID,
            plan_id="cleanup-plan-id",
            target_fingerprint="sha256:" + "a" * 64,
        )
        service_revocation = {
            "repo_id": PROJECT_ID,
            "server_definition_id": SERVER_ID,
            "server_name": "worker",
            "cleanup_operation_id": plan.plan_id,
            "immutable_fingerprint": plan.target_fingerprint,
        }
        calls: list[str] = []
        self.persistence.revoke_server_for_permanent_cleanup.side_effect = (
            lambda **_kwargs: calls.append("service") or service_revocation
        )
        self.persistence.database_generation.return_value = "generation"

        def unregister(_store, **arguments):
            calls.append("prepare_unregister")
            revocation = arguments["revoke"](
                SERVER_ID, PROJECT_ID, "authenticated-actor"
            )
            calls.append("native_unregister")
            return {"workers": [{"revocation": revocation}]}

        with (
            mock.patch.object(
                broker_backend_module,
                "revoke_server_from_protected_profile",
                side_effect=lambda **_kwargs: calls.append("profile")
                or {
                    **service_revocation,
                    "status": "revoked",
                },
            ) as revoke_profile,
            mock.patch.object(
                broker_backend_module,
                "configured_profile_path",
                return_value=Path("/protected/broker-profile.json"),
            ),
            mock.patch.object(
                broker_backend_module,
                "unregister_workers_for_plan",
                side_effect=unregister,
            ),
        ):
            result = self.backend._prepare_worker_lifecycle_apply(
                self.authorized,
                store=mock.Mock(),
                plan=plan,
                actor="authenticated-actor",
            )

        self.assertEqual(
            calls,
            ["prepare_unregister", "service", "profile", "native_unregister"],
        )
        self.persistence.revoke_server_for_permanent_cleanup.assert_called_once_with(
            repo_id=PROJECT_ID,
            server_definition_id=SERVER_ID,
            cleanup_operation_id=plan.plan_id,
            immutable_fingerprint=plan.target_fingerprint,
            actor="authenticated-actor",
        )
        revoke_profile.assert_called_once_with(
            profile_path=Path("/protected/broker-profile.json"),
            repo_id=PROJECT_ID,
            server_name="worker",
            server_definition_id=SERVER_ID,
            cleanup_operation_id=plan.plan_id,
            expected_database_generation="generation",
        )
        self.assertEqual(
            result["workers"][0]["revocation"]["service"], service_revocation
        )

    def test_archive_worker_cleanup_does_not_revoke_permanent_identity(self) -> None:
        plan = SimpleNamespace(
            action="archive",
            target_kind="server",
            target_id=SERVER_ID,
            repo_id=PROJECT_ID,
            plan_id="archive-plan-id",
        )

        def unregister(_store, **arguments):
            self.assertIsNone(arguments["revoke"])
            return {"workers": []}

        with mock.patch.object(
            broker_backend_module,
            "unregister_workers_for_plan",
            side_effect=unregister,
        ):
            self.backend._prepare_worker_lifecycle_apply(
                self.authorized,
                store=mock.Mock(),
                plan=plan,
                actor="authenticated-actor",
            )
        self.persistence.revoke_server_for_permanent_cleanup.assert_not_called()


class BrokerRuntimeAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.__enter__()
        self.persistence, self.actions = seed_store_backed_broker(self.root)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            self.authority_generation = store.metadata.database_generation

    def tearDown(self) -> None:
        self.temporary.__exit__(None, None, None)

    def _grant(
        self,
        action: str,
        *,
        uid: int | None = None,
        enabled: bool = True,
        resource_kind: str = "docker",
        resource_id: str = CONTAINER_ID,
    ) -> None:
        self.persistence.grant_runtime(
            uid=os.geteuid() if uid is None else uid,
            repo_id=PROJECT_ID,
            resource_kind=resource_kind,
            resource_id=resource_id,
            action=action,
            enabled=enabled,
        )

    @staticmethod
    def _seed_stopped_worker_observation(connection) -> None:
        """Make the worker a concrete member of the repository runtime tree."""

        timestamp = utc_timestamp()
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id, lifecycle, pid, listener_observable,
                health_classification, stopped_at, stopped_reason, sampled_at,
                observation_fingerprint
            ) VALUES (?, 'stopped', NULL, 1, 'stopped', ?,
                      'broker runtime worker fixture', ?, ?)
            """,
            (
                SERVER_ID,
                timestamp,
                timestamp,
                "broker-runtime-worker-stopped-observation",
            ),
        )

    def _prepare_worker_replacement(self, *, execution_uid: int | None = None) -> Path:
        repository = self.root / "worker-repository"
        repository.mkdir(mode=0o700, exist_ok=True)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE repositories SET canonical_root = ? WHERE repo_id = ?",
                    (str(repository), PROJECT_ID),
                )
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET role = 'worker', cwd = ?
                    WHERE server_definition_id = ?
                    """,
                    (str(repository), SERVER_ID),
                )
                self._seed_stopped_worker_observation(connection)
            WorkerSupervision(store).configure_policy(
                server_definition_id=SERVER_ID,
                actor="fixture",
                execution_uid=(
                    os.geteuid() if execution_uid is None else execution_uid
                ),
                keep_alive=True,
            )
        self._grant("replace", resource_kind="service", resource_id=SERVER_ID)
        return repository

    def _runtime_observer(
        self,
        store: CoordinatorStore,
        *,
        lifecycle: str | None = None,
        database_available: bool | None = None,
    ) -> dict[str, object]:
        """Publish a production-shaped full-Docker snapshot for the target."""

        evidence = dict(_committed_available_observer(store))
        if lifecycle is None and self.actions.calls:
            lifecycle = (
                "stopped" if self.actions.calls[-1][0] == "stop" else "running"
            )
        with store.immediate_transaction(revision_kind="observation") as connection:
            if lifecycle is not None:
                connection.execute(
                    """
                    UPDATE docker_observations
                    SET lifecycle = ?, sampled_at = ?,
                        observation_fingerprint = ?
                    WHERE docker_resource_id = ?
                    """,
                    (
                        lifecycle,
                        utc_timestamp(),
                        f"runtime-status-{lifecycle}",
                        CONTAINER_ID,
                    ),
                )
            database = connection.execute(
                """
                SELECT database_binding_id FROM database_bindings
                WHERE database_binding_id = ? AND docker_resource_id = ?
                """,
                (DATABASE_ID, CONTAINER_ID),
            ).fetchone()
            if database is not None:
                available = (
                    database_available
                    if database_available is not None
                    else lifecycle == "running"
                )
                connection.execute(
                    """
                    INSERT INTO database_observations(
                        database_binding_id, docker_resource_id, available,
                        size_bytes, error_code, error_message, sampled_at,
                        observation_fingerprint
                    ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)
                    ON CONFLICT(database_binding_id) DO UPDATE SET
                        docker_resource_id = excluded.docker_resource_id,
                        available = excluded.available,
                        size_bytes = NULL,
                        error_code = excluded.error_code,
                        error_message = excluded.error_message,
                        sampled_at = excluded.sampled_at,
                        observation_fingerprint = excluded.observation_fingerprint
                    """,
                    (
                        DATABASE_ID,
                        CONTAINER_ID,
                        int(available),
                        None if available else "database_absent",
                        None if available else "database unavailable",
                        evidence["completed_at"],
                        "runtime-database-available"
                        if available
                        else "runtime-database-unavailable",
                    ),
                )
            observation = connection.execute(
                """
                SELECT observation_fingerprint FROM docker_observations
                WHERE docker_resource_id = ?
                """,
                (CONTAINER_ID,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO observation_snapshot_resources(
                    snapshot_id, resource_kind, resource_id,
                    observation_fingerprint
                ) VALUES (?, 'container', ?, ?)
                """,
                (
                    evidence["snapshot_id"],
                    CONTAINER_ID,
                    observation["observation_fingerprint"],
                ),
            )
        return evidence

    def _service(self, *, observer=None, actions=None) -> BrokerService:
        backend = StoreBackedMutationBackend(
            self.persistence,
            actions or self.actions,
            observe_before_lifecycle_plan=(observer or self._runtime_observer),
        )
        return BrokerService(
            StoreBackedAuthorizer(self.persistence),
            SerializedMutationWriter(backend),
        )

    def _request(
        self,
        *,
        action: str = "status",
        purpose: str = "development",
        ttl_seconds: int | None = None,
        uid: int | None = None,
        account_id: str = ACCOUNT_ID,
        temporary_repo_id: str | None = None,
        target_kind: str = "docker",
        resource_id: str = CONTAINER_ID,
        operation_id: str | None = None,
    ) -> BrokerRequest:
        return BrokerRequest.create(
            account_id=account_id,
            project_id=PROJECT_ID,
            resource_id=resource_id,
            operation=BrokerOperation.RUNTIME_REQUEST,
            arguments=runtime_arguments(
                action=action,
                purpose=purpose,
                ttl_seconds=ttl_seconds,
                temporary_repo_id=temporary_repo_id,
                target_kind=target_kind,
            ),
            operation_id=operation_id,
            authority_generation=self.authority_generation,
        )

    def _reply(
        self,
        *,
        request: BrokerRequest | None = None,
        service: BrokerService | None = None,
        uid: int | None = None,
        **request_values: object,
    ) -> dict[str, object]:
        runtime_request = request or self._request(**request_values)
        return (service or self._service()).reply_for_document(
            peer_for(uid), runtime_request.to_wire()
        )

    def test_authorized_status_returns_concise_rich_repository_report(self) -> None:
        self._grant("status")

        reply = self._reply()

        self.assertTrue(reply["ok"], reply)
        report = reply["result"]
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["ready"])
        self.assertFalse(report["result"]["ready"])
        self.assertEqual(report["classification"], "observed_not_ready")
        self.assertEqual(
            report["repository"],
            {
                "family_id": PROJECT_ID,
                "root_repo_id": PROJECT_ID,
                "effective_repo_id": PROJECT_ID,
                "kind": "root",
                "root_repo": "/repos/alpha",
                "temporary_repo": None,
            },
        )
        self.assertEqual(report["target"], {"kind": "docker", "id": CONTAINER_ID})
        self.assertEqual(report["result"]["authority"], "broker")
        self.assertEqual(report["result"]["state"], "stopped")
        self.assertIsNotNone(report["result"]["observation"]["snapshot_id"])
        self.assertEqual(
            [
                item
                for item in report["resources"]
                if item["kind"] == "docker" and item["id"] == CONTAINER_ID
            ][0]["repo_id"],
            PROJECT_ID,
        )
        for key in (
            "ports",
            "domains",
            "totals",
            "stale_processes",
            "crashes",
            "artifacts",
        ):
            self.assertIn(key, report)

    def test_status_observes_before_reading_the_shared_snapshot(self) -> None:
        self._grant("status")

        def observe_running(store: CoordinatorStore) -> dict[str, object]:
            return self._runtime_observer(store, lifecycle="running")

        service = self._service(observer=observe_running)
        request = BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=PROJECT_ID,
            resource_id=CONTAINER_ID,
            operation=BrokerOperation.RUNTIME_REQUEST,
            arguments=runtime_arguments(),
            authority_generation=self.authority_generation,
        )

        reply = service.reply_for_document(peer_for(), request.to_wire())

        self.assertTrue(reply["ok"], reply)
        report = reply["result"]
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["ready"])
        self.assertTrue(report["result"]["ready"])
        self.assertEqual(report["result"]["state"], "running")
        self.assertTrue(report["result"]["observation"]["observed"])

    def test_family_unclassified_resource_blocks_shared_status(self) -> None:
        self._grant("status")
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES ('runtime-unassigned', ?, 'process',
                              'runtime-orphan', 'orphan worker', 'name_only',
                              'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply()

        self.assertTrue(reply["ok"], reply)
        report = reply["result"]
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["classification"], "unclassified_resource")
        self.assertEqual(
            report["result"]["evidence"][0]["resource_id"],
            "runtime-orphan",
        )
        self.assertEqual(self.actions.calls, [])

    def test_stopped_unassigned_container_does_not_block_shared_status(self) -> None:
        self._grant("status")
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                engine_id = str(
                    connection.execute(
                        "SELECT engine_id FROM docker_engines LIMIT 1"
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    INSERT INTO docker_resources(
                        docker_resource_id, engine_id, full_container_id,
                        current_name, created_at, updated_at
                    ) VALUES ('stopped-orphan-container', ?, ?,
                              'stopped-orphan', ?, ?)
                    """,
                    (engine_id, "f" * 64, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO docker_observations(
                        docker_resource_id, lifecycle, sampled_at,
                        observation_fingerprint
                    ) VALUES ('stopped-orphan-container', 'stopped', ?,
                              'stopped-orphan-observation')
                    """,
                    (now,),
                )
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES ('runtime-stopped-unassigned', ?, 'container',
                              'stopped-orphan-container', 'stopped orphan',
                              'name_only', 'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply()

        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "observed_not_ready")

    def test_explicit_foreign_path_unassigned_is_not_a_family_false_positive(self) -> None:
        self._grant("status")
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, suggested_root, status,
                        created_at, updated_at
                    ) VALUES ('runtime-foreign-unassigned', ?, 'process',
                              'foreign-worker', 'foreign worker', 'missing_repo',
                              '/repos/foreign', 'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply()

        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        self.assertFalse(reply["result"]["result"]["ready"])

    def test_relative_unassigned_path_fails_closed(self) -> None:
        self._grant("status")
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, suggested_root, status,
                        created_at, updated_at
                    ) VALUES ('runtime-relative-unassigned', ?, 'process',
                              'relative-worker', 'relative worker', 'missing_repo',
                              'relative/repository', 'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply()

        self.assertTrue(reply["ok"], reply)
        self.assertFalse(reply["result"]["ok"], reply)
        self.assertEqual(
            reply["result"]["classification"], "unclassified_resource"
        )

    def test_runtime_grant_is_live_and_revocation_takes_effect_immediately(self) -> None:
        self._grant("status")
        self.assertTrue(self._reply()["ok"])

        self._grant("status", enabled=False)
        rejected = self._reply()

        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["error"]["code"], "operation_access_denied")

    def test_ungranted_and_cross_uid_requests_do_not_inherit_access(self) -> None:
        ungranted = self._reply()
        self.assertFalse(ungranted["ok"], ungranted)
        self.assertEqual(ungranted["error"]["code"], "operation_access_denied")

        other_uid = os.geteuid() + 10_000
        other_account = "runtime-other-account"
        self.persistence.provision_principal(uid=other_uid, account_id=other_account)
        self.persistence.provision_repository_enrollment(
            uid=other_uid,
            repo_id=PROJECT_ID,
            account_id=other_account,
            issued_at=utc_timestamp(),
            valid_until_epoch=int(time.time()) + 3_600,
        )
        cross_uid = self._reply(uid=other_uid, account_id=other_account)

        self.assertFalse(cross_uid["ok"], cross_uid)
        self.assertEqual(cross_uid["error"]["code"], "operation_access_denied")

    def test_root_temporary_family_mismatch_fails_closed(self) -> None:
        self._grant("status")

        rejected = self._reply(temporary_repo_id="not-an-enrolled-worktree")

        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(
            rejected["error"]["code"], "runtime_repository_context_mismatch"
        )

    def test_status_survives_broker_writer_reconstruction(self) -> None:
        self._grant("status")

        first = self._reply()
        second = self._reply()

        self.assertTrue(first["ok"], first)
        self.assertTrue(second["ok"], second)
        self.assertEqual(first["result"]["resources"], second["result"]["resources"])

    def test_service_lifecycle_still_requires_peer_uid_supervisor(self) -> None:
        self._grant(
            "start", resource_kind="service", resource_id=SERVER_ID
        )

        reply = self._reply(
            action="start", target_kind="service", resource_id=SERVER_ID
        )

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "runtime_supervisor_required")
        self.assertEqual(self.actions.calls, [])

    def test_worker_service_lifecycle_routes_through_peer_uid_controller_and_replays(
        self,
    ) -> None:
        self._grant("start", resource_kind="service", resource_id=SERVER_ID)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE server_definitions SET role = 'worker' WHERE server_definition_id = ?",
                    (SERVER_ID,),
                )
                self._seed_stopped_worker_observation(connection)

        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(self, _store, **kwargs):
                calls.append(("init", kwargs["execution_uid"]))

            def start(self, **kwargs):
                calls.append(
                    (
                        "start",
                        kwargs["worker_id"],
                        kwargs["canonical_repository"],
                        kwargs["name"],
                        kwargs["keep_alive"],
                        kwargs["crash_limit"],
                        kwargs["crash_window_seconds"],
                        kwargs["rearm"],
                    )
                )
                return {
                    "ok": True,
                    "id": kwargs["worker_id"],
                    "name": kwargs["name"],
                    "project": kwargs["canonical_repository"],
                    "status": "running",
                    "health": {"ok": True, "classification": "supervised_process_running"},
                    "supervision": {"keep_alive": True, "supervisor_state": "running"},
                    "native_runner": {"active": True},
                }

        operation_id = "969f0091-8c0b-4dbf-a7d8-f7d9c5fc3cc3"
        request = BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=PROJECT_ID,
            resource_id=SERVER_ID,
            operation=BrokerOperation.RUNTIME_REQUEST,
            arguments={
                **runtime_arguments(action="start", target_kind="service"),
                "keep_alive": True,
                "rearm_crash_loop": True,
                "restart_limit": 10,
                "restart_window_seconds": 300,
            },
            operation_id=operation_id,
            authority_generation=self.authority_generation,
        )
        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            first = self._reply(request=request)
            replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first, replay)
        self.assertEqual(first["result"]["result"]["authority"], "broker_worker_supervisor")
        self.assertEqual(
            calls,
            [
                ("init", os.geteuid()),
                (
                    "start",
                    SERVER_ID,
                    "/repos/alpha",
                    "web",
                    True,
                    10,
                    300,
                    True,
                ),
            ],
        )

    def _worker_replace_request(
        self,
        repository: Path,
        *,
        operation_id: str,
        expected_generation: int = 0,
        cwd: Path | None = None,
    ) -> BrokerRequest:
        return BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=PROJECT_ID,
            resource_id=SERVER_ID,
            operation=BrokerOperation.RUNTIME_REQUEST,
            arguments={
                **runtime_arguments(action="replace", target_kind="service"),
                "expected_definition_generation": expected_generation,
                "argv": ["/usr/bin/python3", "worker.py"],
                "cwd": str(repository if cwd is None else cwd),
                "environment": {"MODE": "replacement"},
                "keep_alive": True,
            },
            operation_id=operation_id,
            authority_generation=self.authority_generation,
        )

    def test_worker_replace_is_repo_anchored_cas_and_durably_replayed(self) -> None:
        repository = self._prepare_worker_replacement()
        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(inner_self, store, **kwargs):
                inner_self.store = store
                calls.append(("init", kwargs["execution_uid"]))

            def replace(inner_self, **kwargs):
                calls.append(
                    (
                        "replace",
                        kwargs["expected_generation"],
                        tuple(kwargs["argv"]),
                        kwargs["cwd"],
                        dict(kwargs["environment"]),
                    )
                )
                with inner_self.store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE server_definitions
                        SET generation = 1,
                            definition_fingerprint = 'replacement-definition'
                        WHERE server_definition_id = ? AND generation = 0
                        """,
                        (SERVER_ID,),
                    )
                return {
                    "id": SERVER_ID,
                    "name": "web",
                    "project": str(repository),
                    "generation": 1,
                    "status": "running",
                    "health": {"ok": True},
                    "replacement": {
                        "previous_generation": 0,
                        "generation": 1,
                        "definition_fingerprint": "replacement-definition",
                    },
                }

        request = self._worker_replace_request(
            repository,
            operation_id="35b3380e-cb80-41d4-9042-00ad73e26548",
        )
        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            first = self._reply(request=request)
            replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertTrue(first["result"]["ok"], first)
        self.assertEqual(first, replay)
        self.assertEqual(
            calls,
            [
                ("init", os.geteuid()),
                (
                    "replace",
                    0,
                    ("/usr/bin/python3", "worker.py"),
                    str(repository),
                    {"MODE": "replacement"},
                ),
            ],
        )

    def test_worker_replace_rejects_wrong_uid_path_and_generation_before_control(self) -> None:
        repository = self._prepare_worker_replacement(
            execution_uid=os.geteuid() + 1
        )
        request = self._worker_replace_request(
            repository,
            operation_id="ad161c28-b685-43a5-b0ac-600b34107630",
        )
        with mock.patch.object(
            broker_backend_module,
            "WorkerController",
            side_effect=AssertionError("wrong UID crossed control boundary"),
        ):
            wrong_uid = self._reply(request=request)
        self.assertFalse(wrong_uid["ok"], wrong_uid)
        self.assertEqual(
            wrong_uid["error"]["code"], "worker_execution_uid_mismatch"
        )

        # Reconfigure the exact policy to the authenticated peer for the
        # independent path and generation guards.
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE worker_policies SET execution_uid = ? WHERE server_definition_id = ?",
                    (os.geteuid(), SERVER_ID),
                )
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        path_request = self._worker_replace_request(
            repository,
            cwd=outside,
            operation_id="24106bf9-d2ba-4dbd-a94c-97ab64d6f281",
        )
        with mock.patch.object(
            broker_backend_module,
            "WorkerController",
            side_effect=AssertionError("escaped path crossed control boundary"),
        ):
            denied_path = self._reply(request=path_request)
        self.assertFalse(denied_path["ok"], denied_path)
        self.assertEqual(
            denied_path["error"]["code"], "worker_replacement_path_denied"
        )

        stale_request = self._worker_replace_request(
            repository,
            expected_generation=9,
            operation_id="4fa0e922-fb33-49c9-8117-4ac0031a7386",
        )
        with mock.patch.object(
            broker_backend_module,
            "WorkerController",
            side_effect=AssertionError("stale generation crossed control boundary"),
        ):
            stale = self._reply(request=stale_request)
        self.assertFalse(stale["ok"], stale)
        self.assertEqual(stale["error"]["code"], "stale_resource_definition")

    def test_worker_replace_disconnect_never_reexecutes(self) -> None:
        repository = self._prepare_worker_replacement()
        calls: list[str] = []

        class FakeController:
            def __init__(inner_self, store, **_kwargs):
                inner_self.store = store

            def replace(inner_self, **_kwargs):
                calls.append("replace")
                with inner_self.store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE server_definitions
                        SET generation = 1,
                            definition_fingerprint = 'replacement-definition'
                        WHERE server_definition_id = ? AND generation = 0
                        """,
                        (SERVER_ID,),
                    )
                return {
                    "id": SERVER_ID,
                    "name": "web",
                    "project": str(repository),
                    "generation": 1,
                    "status": "running",
                    "health": {"ok": True},
                    "replacement": {
                        "generation": 1,
                        "definition_fingerprint": "replacement-definition",
                    },
                }

        request = self._worker_replace_request(
            repository,
            operation_id="8d90612f-5f6a-43ad-88fb-c78f4ac676fe",
        )
        service = self._service()
        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ), mock.patch.object(
            self.persistence,
            "finish_operation",
            side_effect=RuntimeError("injected response-loss window"),
        ):
            first = self._reply(request=request, service=service)
            replay = self._reply(request=request, service=service)

        self.assertFalse(first["ok"], first)
        self.assertEqual(first["error"]["code"], "worker_operation_uncertain")
        self.assertFalse(replay["ok"], replay)
        self.assertEqual(replay["error"]["code"], "worker_operation_uncertain")
        self.assertEqual(calls, ["replace"])

    def test_worker_replace_failure_payload_is_durable_and_replayed(self) -> None:
        repository = self._prepare_worker_replacement()
        calls: list[str] = []

        class FailingController:
            def __init__(self, _store, **_kwargs):
                pass

            def replace(self, **_kwargs):
                calls.append("replace")
                raise WorkerReplaceError(
                    "replacement rolled back",
                    payload={
                        "classification": "replacement_failed_rolled_back",
                        "rollback": {"ok": True, "restored_generation": 0},
                        "replace_error": {
                            "type": "RuntimeError",
                            "message": "worker crashed",
                        },
                    },
                )

        request = self._worker_replace_request(
            repository,
            operation_id="e93877fd-2132-4e93-947d-f8243397c619",
        )
        with mock.patch.object(
            broker_backend_module, "WorkerController", FailingController
        ):
            first = self._reply(request=request)
            replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertFalse(first["result"]["ok"], first)
        self.assertEqual(first, replay)
        self.assertEqual(calls, ["replace"])
        self.assertEqual(
            first["result"]["result"]["rollback"],
            {"ok": True, "restored_generation": 0},
        )

    def test_ttl_start_is_rejected_before_reservation_or_host_mutation(self) -> None:
        self._grant("start")

        reply = self._reply(
            action="start", purpose="test", ttl_seconds=30
        )

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(
            reply["error"]["code"], "runtime_cleanup_owner_required"
        )
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM runtime_sessions"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM operations WHERE kind = 'broker.runtime.request'"
                    ).fetchone()[0],
                    0,
                )
        self.assertEqual(self.actions.calls, [])

    def test_docker_start_stop_restart_use_exact_identity_and_terminal_proof(
        self,
    ) -> None:
        for action in ("start", "stop", "restart"):
            self._grant(action)
            with self.subTest(action=action):
                reply = self._reply(action=action)
                self.assertTrue(reply["ok"], reply)
                report = reply["result"]
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["action"], action)
                self.assertEqual(
                    report["result"]["terminal_state"]["observed_state"],
                    "stopped" if action == "stop" else "running",
                )
        self.assertEqual(
            [call[0] for call in self.actions.calls],
            ["start", "stop", "restart"],
        )
        self.assertTrue(
            all(call[2] == "a" * 64 for call in self.actions.calls)
        )

    def test_database_lifecycle_maps_binding_to_exact_container_and_readiness(
        self,
    ) -> None:
        seed_postgres_database(self.persistence)
        for action in ("start", "stop", "restart"):
            self._grant(
                action,
                resource_kind="database_stack",
                resource_id=DATABASE_ID,
            )
            with self.subTest(action=action):
                call_count_before = len(self.actions.calls)

                def observe_database_action(
                    store: CoordinatorStore,
                ) -> dict[str, object]:
                    action_completed = len(self.actions.calls) > call_count_before
                    lifecycle = (
                        "stopped"
                        if action_completed and action == "stop"
                        else "running"
                    )
                    return self._runtime_observer(
                        store,
                        lifecycle=lifecycle,
                        database_available=(
                            False
                            if action_completed and action == "stop"
                            else True
                        ),
                    )

                reply = self._reply(
                    action=action,
                    target_kind="database_stack",
                    resource_id=DATABASE_ID,
                    service=self._service(observer=observe_database_action),
                )
                self.assertTrue(reply["ok"], reply)
                report = reply["result"]
                self.assertTrue(report["ok"], report)
                terminal = report["result"]["terminal_state"]
                self.assertEqual(terminal["docker_resource_id"], CONTAINER_ID)
                self.assertEqual(
                    terminal["database_available"],
                    None if action == "stop" else True,
                )
                if action == "stop":
                    self.assertFalse(
                        any(
                            item["kind"] == "database_stack"
                            and item["id"] == DATABASE_ID
                            for item in report["resources"]
                        ),
                        "positive database absence must retire it from the current tree",
                    )
        self.assertEqual(
            [call[0] for call in self.actions.calls],
            ["start", "stop", "restart"],
        )
        self.assertTrue(
            all(call[1:] == (CONTAINER_ID, "a" * 64) for call in self.actions.calls)
        )

    def test_unclassified_family_blocks_lifecycle_before_reservation(self) -> None:
        self._grant("start")
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES ('runtime-start-orphan', ?, 'process', 'orphan',
                              'orphan', 'name_only', 'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply(action="start")

        self.assertTrue(reply["ok"], reply)
        self.assertFalse(reply["result"]["ok"], reply)
        self.assertEqual(
            reply["result"]["classification"], "unclassified_resource"
        )
        self.assertEqual(self.actions.calls, [])

    def test_unauthorized_and_family_mismatch_lifecycle_never_reach_host(self) -> None:
        unauthorized = self._reply(action="start")
        self.assertFalse(unauthorized["ok"], unauthorized)
        self.assertEqual(
            unauthorized["error"]["code"], "operation_access_denied"
        )

        self._grant("start")
        mismatch = self._reply(
            action="start", temporary_repo_id="not-an-enrolled-worktree"
        )
        self.assertFalse(mismatch["ok"], mismatch)
        self.assertEqual(
            mismatch["error"]["code"], "runtime_repository_context_mismatch"
        )
        self.assertEqual(self.actions.calls, [])

    def test_success_replays_durably_after_writer_reconstruction(self) -> None:
        self._grant("start")
        request = self._request(action="start")

        first = self._reply(request=request)
        second = self._reply(request=request, service=self._service())

        self.assertTrue(first["ok"], first)
        self.assertEqual(second, first)
        self.assertEqual(len(self.actions.calls), 1)

    def test_host_error_requires_reconciliation_and_is_never_reexecuted(
        self,
    ) -> None:
        class FailingActions(type(self.actions)):
            def docker_start(inner_self, target):
                inner_self.calls.append(
                    ("start", target.docker_resource_id, target.full_container_id)
                )
                raise BrokerError("docker_action_failed", "typed Docker failure")

        actions = FailingActions()
        self._grant("start")
        request = self._request(action="start")

        first = self._reply(
            request=request, service=self._service(actions=actions)
        )
        second = self._reply(
            request=request, service=self._service(actions=actions)
        )
        third = self._reply(
            request=request, service=self._service(actions=actions)
        )

        self.assertFalse(first["ok"], first)
        self.assertEqual(
            first["error"]["code"], "operation_outcome_uncertain"
        )
        self.assertFalse(second["ok"], second)
        self.assertEqual(
            second["error"]["code"], "lifecycle_target_not_ready"
        )
        self.assertEqual(third, second)
        self.assertEqual(len(actions.calls), 1)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT status, phase, error_code FROM operations "
                    "WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(
            dict(row),
            {
                "status": "failed",
                "phase": "reconciliation_failed",
                "error_code": "lifecycle_target_not_ready",
            },
        )

    def test_post_observation_failure_is_uncertain_and_replay_never_reexecutes(
        self,
    ) -> None:
        observations = 0

        def fail_after_action(store: CoordinatorStore) -> dict[str, object]:
            nonlocal observations
            observations += 1
            if observations == 2:
                raise RuntimeError("injected post-observation failure")
            return self._runtime_observer(store)

        self._grant("start")
        request = self._request(action="start")
        service = self._service(observer=fail_after_action)

        first = self._reply(request=request, service=service)
        second = self._reply(request=request, service=self._service())

        self.assertFalse(first["ok"], first)
        self.assertEqual(
            first["error"]["code"], "operation_outcome_uncertain"
        )
        self.assertTrue(second["ok"], second)
        self.assertTrue(
            second["result"]["result"]["reconciled_without_reexecution"]
        )
        self.assertEqual(len(self.actions.calls), 1)

    def test_startup_recovery_reconciles_runtime_request_without_host_reexecution(
        self,
    ) -> None:
        self._grant("start")
        request = self._request(action="start")
        authorized = self.persistence.authorize(peer_for(), request)
        self.assertEqual(
            self.persistence.reserve_operation(authorized).state, "execute"
        )

        recovered = self.persistence.recover_interrupted_docker_operations()
        self.assertEqual(recovered["operation_ids"], [request.operation_id])

        def observe_running(store: CoordinatorStore) -> dict[str, object]:
            return self._runtime_observer(store, lifecycle="running")

        reply = self._reply(
            request=request, service=self._service(observer=observe_running)
        )

        self.assertTrue(reply["ok"], reply)
        self.assertTrue(
            reply["result"]["result"]["reconciled_without_reexecution"]
        )
        self.assertEqual(self.actions.calls, [])

    def test_uncertain_restart_is_not_misreported_from_running_state(self) -> None:
        class UncertainRestart(type(self.actions)):
            def docker_restart(inner_self, target):
                inner_self.calls.append(
                    ("restart", target.docker_resource_id, target.full_container_id)
                )
                raise RuntimeError("restart result unavailable")

        def observe_running(store: CoordinatorStore) -> dict[str, object]:
            return self._runtime_observer(store, lifecycle="running")

        actions = UncertainRestart()
        self._grant("restart")
        request = self._request(action="restart")

        first = self._reply(
            request=request,
            service=self._service(observer=observe_running, actions=actions),
        )
        second = self._reply(
            request=request,
            service=self._service(observer=observe_running, actions=actions),
        )

        self.assertFalse(first["ok"], first)
        self.assertEqual(
            first["error"]["code"], "operation_outcome_uncertain"
        )
        self.assertFalse(second["ok"], second)
        self.assertEqual(
            second["error"]["code"], "operation_outcome_uncertain"
        )
        self.assertEqual(len(actions.calls), 1)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    "SELECT status, phase FROM operations WHERE operation_id = ?",
                    (request.operation_id,),
                ).fetchone()
        self.assertEqual(
            dict(row),
            {"status": "needs_attention", "phase": "reconciliation_required"},
        )

    def test_database_alias_and_docker_id_share_one_mutation_fence(self) -> None:
        seed_postgres_database(self.persistence)
        self._grant("start")
        self._grant(
            "stop", resource_kind="database_stack", resource_id=DATABASE_ID
        )
        docker_request = self._request(action="start")
        database_request = self._request(
            action="stop",
            target_kind="database_stack",
            resource_id=DATABASE_ID,
        )
        self.assertEqual(
            self.persistence.reserve_operation(
                self.persistence.authorize(peer_for(), docker_request)
            ).state,
            "execute",
        )

        with self.assertRaises(BrokerError) as blocked:
            self.persistence.reserve_operation(
                self.persistence.authorize(peer_for(), database_request)
            )

        self.assertEqual(blocked.exception.code, "docker_operation_pending")

    def test_final_state_and_identity_mismatch_fail_durably(self) -> None:
        self._grant("start")

        def remain_stopped(store: CoordinatorStore) -> dict[str, object]:
            return self._runtime_observer(store, lifecycle="stopped")

        state_reply = self._reply(
            action="start", service=self._service(observer=remain_stopped)
        )
        self.assertFalse(state_reply["ok"], state_reply)
        self.assertEqual(
            state_reply["error"]["code"], "lifecycle_target_not_ready"
        )

        identity_observations = 0

        def replace_identity(store: CoordinatorStore) -> dict[str, object]:
            nonlocal identity_observations
            identity_observations += 1
            evidence = self._runtime_observer(store)
            if identity_observations == 2:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE docker_resources SET full_container_id = ?, updated_at = ?
                        WHERE docker_resource_id = ?
                        """,
                        ("c" * 64, utc_timestamp(), CONTAINER_ID),
                    )
            return evidence

        identity_request = self._request(action="start")
        identity_reply = self._reply(
            request=identity_request,
            service=self._service(observer=replace_identity),
        )
        self.assertFalse(identity_reply["ok"], identity_reply)
        self.assertEqual(
            identity_reply["error"]["code"],
            "lifecycle_target_identity_changed",
        )
        replay = self._reply(
            request=identity_request, service=self._service()
        )
        self.assertEqual(replay, identity_reply)
        self.assertEqual(len(self.actions.calls), 2)


if __name__ == "__main__":
    unittest.main()
