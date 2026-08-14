"""Focused contracts for the ID-only shared-authority runtime endpoint."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import dev_coordinator  # noqa: E402
from devcoordinator.broker import (  # noqa: E402
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator import broker_backend as broker_backend_module  # noqa: E402
from devcoordinator.broker_persistence import StoreBackedRequestAcceptor  # noqa: E402
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
    RecordingPostgresHostActions,
    _committed_available_observer,
    peer_for,
    request_for,
    seed_postgres_database,
    seed_store_backed_broker,
)
from devcoordinator.tests.test_broker_assignment_compose import (  # noqa: E402
    rendered_fixture_model,
)


REPLACEMENT_COMPOSE_ID = "compose-runtime-replacement"
REPLACEMENT_RESOURCE_ID = "container-runtime-replacement"
REPLACEMENT_FULL_ID = "c" * 64


class RuntimeReplacementHostActions(RecordingPostgresHostActions):
    """Host fixture that exposes one exact Compose identity transition."""

    def __init__(self) -> None:
        super().__init__()
        self.recreated = False
        self.removed = False
        self.compose_calls: list[str] = []

    def compose_up(self, _target: object) -> dict[str, object]:
        self.compose_calls.append("up")
        self.recreated = True
        return {
            "action": "up",
            "returncode": 0,
            "phases": ["compose_up"],
        }

    def compose_stop(self, _target: object) -> dict[str, object]:
        raise AssertionError("replacement must not stop the Compose project")

    def compose_restart(self, _target: object) -> dict[str, object]:
        raise AssertionError("replacement must use exact service recreation")

    def compose_down(self, _target: object) -> dict[str, object]:
        raise AssertionError("replacement must not remove the Compose project")

    def postgres_reconcile_restore(
        self,
        _target: object,
        _backup: object,
        *,
        safety_output_root: str,
    ) -> None:
        del safety_output_root
        return None

    def remove(self, full_container_id: str) -> dict[str, object]:
        if full_container_id != REPLACEMENT_FULL_ID:
            raise AssertionError("cleanup selected another container identity")
        self.removed = True
        return {
            "action": "remove",
            "full_container_id": full_container_id,
            "removed": True,
        }


def runtime_arguments(
    *,
    action: str = "status",
    purpose: str = "development",
    ttl_seconds: int | None = None,
    temporary_repo_id: str | None = None,
    target_kind: str = "docker",
    kill_after_run: bool = False,
) -> dict[str, object]:
    return {
        "action": action,
        "agent": "runtime-test-agent",
        "root_repo_id": PROJECT_ID,
        "temporary_repo_id": temporary_repo_id,
        "target_kind": target_kind,
        "purpose": purpose,
        "ttl_seconds": ttl_seconds,
        "kill_after_run": kill_after_run,
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

    def test_wire_accepts_path_free_docker_replacement_only(self) -> None:
        for target_kind, resource_id in (
            ("docker", CONTAINER_ID),
            ("database_stack", DATABASE_ID),
        ):
            with self.subTest(target_kind=target_kind):
                arguments = runtime_arguments(
                    action="replace", target_kind=target_kind
                )
                request = request_for(
                    BrokerOperation.RUNTIME_REQUEST,
                    resource_id=resource_id,
                    arguments=arguments,
                )
                self.assertEqual(request.arguments, arguments)
                with self.assertRaises(BrokerError) as raised:
                    request_for(
                        BrokerOperation.RUNTIME_REQUEST,
                        resource_id=resource_id,
                        arguments={**arguments, "cwd": "/client/path"},
                    )
                self.assertEqual(raised.exception.code, "invalid_arguments")


class BrokerRuntimeOperationIdentityTests(unittest.TestCase):
    operation_id = "44444444-4444-4444-8444-444444444444"

    def request(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "action": "status",
            "agent": "runtime-operation-test",
            "root_repo": "/repositories/alpha",
            "temporary_repo": None,
            "target": {"kind": "docker", "id": CONTAINER_ID},
            "purpose": "development",
            "ttl_seconds": None,
            "kill_after_run": False,
            "options": {},
        }

    def profile(self) -> mock.Mock:
        repository = SimpleNamespace(repo_id=PROJECT_ID)
        profile = mock.Mock()
        profile.repository.return_value = repository
        profile.resolve_repository.return_value = repository
        profile.call.return_value = (
            self.operation_id,
            {
                "schema_version": 1,
                "ok": True,
                "action": "status",
                "repository": {
                    "root_repo_id": PROJECT_ID,
                    "effective_repo_id": PROJECT_ID,
                },
                "target": {"kind": "docker", "id": CONTAINER_ID},
            },
        )
        return profile

    def test_runtime_threads_one_operation_id_to_broker_and_success_envelope(
        self,
    ) -> None:
        profile = self.profile()
        with mock.patch.object(
            dev_coordinator, "state_backend", return_value="sqlite"
        ), mock.patch.object(
            dev_coordinator, "authority_mode", return_value="system"
        ), mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            result = dev_coordinator.coordinated_runtime_request(
                self.request(), operation_id=self.operation_id
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["operation_id"], self.operation_id)
        self.assertEqual(
            profile.call.call_args.kwargs["operation_id"], self.operation_id
        )
        profile.resolve_repository.assert_called_once_with("/repositories/alpha")

    def test_runtime_resolves_authority_repository_newer_than_installed_profile(
        self,
    ) -> None:
        profile = self.profile()
        profile.repository.side_effect = AssertionError(
            "runtime request consulted only the stale installed repository map"
        )
        with mock.patch.object(
            dev_coordinator, "state_backend", return_value="sqlite"
        ), mock.patch.object(
            dev_coordinator, "authority_mode", return_value="system"
        ), mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            result = dev_coordinator.coordinated_runtime_request(
                self.request(), operation_id=self.operation_id
            )

        self.assertTrue(result["ok"], result)
        profile.resolve_repository.assert_called_once_with("/repositories/alpha")
        profile.repository.assert_not_called()

    def test_account_docker_replace_delegates_without_opening_account_store(
        self,
    ) -> None:
        payload = self.request()
        payload["action"] = "replace"
        profile = self.profile()
        profile.call.return_value = (
            self.operation_id,
            {
                "schema_version": 1,
                "ok": True,
                "action": "replace",
                "repository": {
                    "root_repo_id": PROJECT_ID,
                    "effective_repo_id": PROJECT_ID,
                },
                "target": {"kind": "docker", "id": CONTAINER_ID},
                "replacement": {
                    "current": {"docker_resource_id": "container-new"}
                },
            },
        )
        with mock.patch.object(
            dev_coordinator, "state_backend", return_value="sqlite"
        ), mock.patch.object(
            dev_coordinator, "authority_mode", return_value="account"
        ), mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ), mock.patch.object(
            dev_coordinator.AccountStore,
            "open_default",
            side_effect=AssertionError(
                "Docker replacement must not open mutable account state"
            ),
        ):
            result = dev_coordinator.coordinated_runtime_request(
                payload, operation_id=self.operation_id
            )

        self.assertTrue(result["ok"], result)
        arguments = profile.call.call_args.kwargs["arguments"]
        self.assertEqual(arguments["action"], "replace")
        self.assertEqual(arguments["target_kind"], "docker")
        self.assertNotIn("cwd", arguments)
        self.assertNotIn("argv", arguments)
        self.assertNotIn("environment", arguments)

    def test_broker_failure_envelope_preserves_submitted_operation_id(self) -> None:
        profile = self.profile()
        profile.call.side_effect = BrokerError(
            "broker_unavailable",
            "Broker reply was unavailable.",
            operation_id=self.operation_id,
        )
        with mock.patch.object(
            dev_coordinator, "state_backend", return_value="sqlite"
        ), mock.patch.object(
            dev_coordinator, "authority_mode", return_value="system"
        ), mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ):
            result = dev_coordinator.coordinated_runtime_request(
                self.request(), operation_id=self.operation_id
            )

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["operation_id"], self.operation_id)
        self.assertEqual(result["evidence"]["operation_id"], self.operation_id)


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


class BrokerRuntimeTests(unittest.TestCase):
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

    @staticmethod
    def _seed_stopped_worker_observation(connection) -> None:
        """Make the worker a concrete part of the repository runtime tree."""

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

    def _prepare_worker_replacement(
        self, *, execution_uid: int | None = None, role: str = "worker"
    ) -> Path:
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
                    SET role = ?, cwd = ?
                    WHERE server_definition_id = ?
                    """,
                    (role, str(repository), SERVER_ID),
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

    def _prepare_compose_replacement(
        self, *, database: bool = False
    ) -> tuple[
        RuntimeReplacementHostActions,
        BrokerService,
        StoreBackedMutationBackend,
    ]:
        repository = self.root / "replacement-repository"
        repository.mkdir(mode=0o700, exist_ok=True)
        compose_file = repository / "compose.yml"
        service_name = "db" if database else "web"
        compose_file.write_text(
            f"services:\n  {service_name}:\n    image: example.invalid/{service_name}:test\n",
            encoding="utf-8",
        )
        self.persistence.compose_model_renderer = rendered_fixture_model
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
                    UPDATE docker_observations
                    SET lifecycle = 'running', health = 'healthy',
                        sampled_at = ?, observation_fingerprint = ?
                    WHERE docker_resource_id = ?
                    """,
                    (utc_timestamp(), "replacement-old-running", CONTAINER_ID),
                )
        self.persistence.provision_compose_definition(
            compose_definition_id=REPLACEMENT_COMPOSE_ID,
            repo_id=PROJECT_ID,
            cwd=repository,
            files=(compose_file,),
            services=(service_name,),
            project_name="runtime-replacement-stack",
        )
        if database:
            seed_postgres_database(self.persistence)

        actions = RuntimeReplacementHostActions()

        def observer(store: CoordinatorStore) -> dict[str, object]:
            evidence = dict(_committed_available_observer(store))
            snapshot_id = str(evidence["snapshot_id"])
            now = str(evidence["completed_at"])
            with store.immediate_transaction(
                revision_kind="observation"
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO broker_observation_compose_scope(
                        snapshot_id, assets_complete, observed_asset_count,
                        evidence_fingerprint, recorded_at
                    ) VALUES (?, 1, 0, ?, ?)
                    """,
                    (snapshot_id, "replacement-compose-scope", now),
                )
                if actions.recreated:
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, repo_id, full_container_id,
                            current_name, image, created_at, updated_at
                        ) SELECT ?, engine_id, ?, ?, ?, image, ?, ?
                          FROM docker_resources WHERE docker_resource_id = ?
                        ON CONFLICT(docker_resource_id) DO UPDATE SET
                            current_name = excluded.current_name,
                            updated_at = excluded.updated_at
                        """,
                        (
                            REPLACEMENT_RESOURCE_ID,
                            PROJECT_ID,
                            REPLACEMENT_FULL_ID,
                            service_name + "-replacement",
                            now,
                            now,
                            CONTAINER_ID,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO docker_observations(
                            docker_resource_id, lifecycle, health, sampled_at,
                            observation_fingerprint
                        ) VALUES (?, 'running', 'healthy', ?, ?)
                        ON CONFLICT(docker_resource_id) DO UPDATE SET
                            lifecycle = excluded.lifecycle,
                            health = excluded.health,
                            sampled_at = excluded.sampled_at,
                            observation_fingerprint =
                                excluded.observation_fingerprint
                        """,
                        (
                            REPLACEMENT_RESOURCE_ID,
                            now,
                            "replacement-new-running",
                        ),
                    )
                    if database:
                        database_name = connection.execute(
                            """
                            SELECT database_name FROM database_bindings
                            WHERE database_binding_id = ?
                            """,
                            (DATABASE_ID,),
                        ).fetchone()[0]
                        connection.execute(
                            """
                            INSERT INTO database_bindings(
                                database_binding_id, docker_resource_id,
                                repo_id, database_name, engine_kind,
                                created_at, updated_at
                            ) VALUES (
                                'database-runtime-replacement', ?, ?, ?,
                                'postgresql', ?, ?
                            ) ON CONFLICT(database_binding_id) DO UPDATE SET
                                docker_resource_id =
                                    excluded.docker_resource_id,
                                repo_id = excluded.repo_id,
                                updated_at = excluded.updated_at
                            """,
                            (
                                REPLACEMENT_RESOURCE_ID,
                                PROJECT_ID,
                                database_name,
                                now,
                                now,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO database_observations(
                                database_binding_id, docker_resource_id,
                                available, size_bytes, error_code,
                                error_message, sampled_at,
                                observation_fingerprint
                            ) VALUES (
                                'database-runtime-replacement', ?, 1, 4096,
                                NULL, NULL, ?, ?
                            ) ON CONFLICT(database_binding_id) DO UPDATE SET
                                docker_resource_id =
                                    excluded.docker_resource_id,
                                available = 1, size_bytes = 4096,
                                error_code = NULL, error_message = NULL,
                                sampled_at = excluded.sampled_at,
                                observation_fingerprint =
                                    excluded.observation_fingerprint
                            """,
                            (
                                REPLACEMENT_RESOURCE_ID,
                                now,
                                "replacement-database-available",
                            ),
                        )
                connection.execute(
                    """
                    DELETE FROM observation_snapshot_resources
                    WHERE snapshot_id = ? AND resource_kind = 'container'
                      AND resource_id IN (?, ?)
                    """,
                    (
                        snapshot_id,
                        CONTAINER_ID,
                        REPLACEMENT_RESOURCE_ID,
                    ),
                )
                if not actions.removed:
                    resource_id = (
                        REPLACEMENT_RESOURCE_ID
                        if actions.recreated
                        else CONTAINER_ID
                    )
                    full_id = (
                        REPLACEMENT_FULL_ID
                        if actions.recreated
                        else "a" * 64
                    )
                    observation = connection.execute(
                        """
                        SELECT observation_fingerprint
                        FROM docker_observations
                        WHERE docker_resource_id = ?
                        """,
                        (resource_id,),
                    ).fetchone()
                    connection.execute(
                        """
                        INSERT INTO observation_snapshot_resources(
                            snapshot_id, resource_kind, resource_id,
                            observation_fingerprint
                        ) VALUES (?, 'container', ?, ?)
                        """,
                        (
                            snapshot_id,
                            resource_id,
                            str(observation["observation_fingerprint"]),
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observed_compose_containers(
                            snapshot_id, docker_resource_id,
                            full_container_id, project_name, service_name,
                            lifecycle, association_state,
                            associated_repo_id,
                            observation_fingerprint
                        ) VALUES (
                            ?, ?, ?, 'runtime-replacement-stack', ?,
                            'running', 'exclusive', ?, ?
                        )
                        """,
                        (
                            snapshot_id,
                            resource_id,
                            full_id,
                            service_name,
                            PROJECT_ID,
                            "replacement-compose-container",
                        ),
                    )
            return evidence

        backend = StoreBackedMutationBackend(
            self.persistence,
            actions,
            observe_before_lifecycle_plan=observer,
            container_remover=actions.remove,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(backend),
        )
        return actions, service, backend

    def _service(self, *, observer=None, actions=None) -> BrokerService:
        backend = StoreBackedMutationBackend(
            self.persistence,
            actions or self.actions,
            observe_before_lifecycle_plan=(observer or self._runtime_observer),
        )
        return BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
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
        kill_after_run: bool = False,
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
                kill_after_run=kill_after_run,
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


    def test_unknown_optional_temporary_route_does_not_gate_root_status(self) -> None:
        reply = self._reply(temporary_repo_id="not-a-configured-worktree")

        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)

    def test_status_survives_broker_writer_reconstruction(self) -> None:

        first = self._reply()
        second = self._reply()

        self.assertTrue(first["ok"], first)
        self.assertTrue(second["ok"], second)
        self.assertEqual(first["result"]["resources"], second["result"]["resources"])

    def test_nonworker_service_uses_exact_peer_uid_supervisor(self) -> None:
        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(self, _store, **kwargs):
                calls.append(("init", kwargs["execution_uid"]))

            def start(self, **kwargs):
                calls.append(
                    (
                        "start",
                        kwargs["worker_id"],
                        kwargs["name"],
                        kwargs["keep_alive"],
                    )
                )
                return {
                    "ok": True,
                    "id": kwargs["worker_id"],
                    "name": kwargs["name"],
                    "project": kwargs["canonical_repository"],
                    "status": "running",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {
                        "keep_alive": False,
                        "supervisor_state": "running",
                    },
                    "native_runner": {"active": True},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                action="start", target_kind="service", resource_id=SERVER_ID
            )

        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        self.assertEqual(
            reply["result"]["result"]["authority"],
            "broker_service_supervisor",
        )
        self.assertEqual(
            calls,
            [
                ("init", os.geteuid()),
                ("start", SERVER_ID, "web", False),
            ],
        )
        self.assertEqual(self.actions.calls, [])

    def test_supervised_service_status_uses_live_worker_authority(self) -> None:
        self._prepare_worker_replacement()

        class FakeController:
            def __init__(self, _store, **_kwargs):
                pass

            def status(self, **kwargs):
                return {
                    "ok": True,
                    "id": kwargs["worker_id"],
                    "name": kwargs["name"],
                    "status": "running",
                    "pid": 42_010,
                    "process_start_time": "status-start-1",
                    "health": {"ok": True},
                    "supervision": {"supervisor_state": "running"},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                action="status", target_kind="service", resource_id=SERVER_ID
            )

        self.assertTrue(reply["ok"], reply)
        result = reply["result"]["result"]
        self.assertEqual(result["authority"], "broker_worker_supervisor")
        self.assertTrue(result["supervision_ready"])
        self.assertTrue(result["endpoint_ready"])
        self.assertTrue(result["ready"])

    def test_network_service_start_proves_listener_pid_identity_and_exact_cwd(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('runtime-network-web', ?, ?, 'web', 3105,
                              'active', 0, ?, ?)
                    """,
                    (HOST_ID, PROJECT_ID, utc_timestamp(), utc_timestamp()),
                )
        self.actions.listener_evidence = {
            "pid": 42_001,
            "process_identity": "linux:42001:listener-start-1",
            "cwd": "/repos/alpha",
            "canonical_root": "/repos/alpha",
            "port": 3105,
            "protocol": "tcp",
        }

        class FakeController:
            def __init__(self, _store, **_kwargs):
                pass

            def start(self, **kwargs):
                return {
                    "ok": True,
                    "id": kwargs["worker_id"],
                    "name": kwargs["name"],
                    "project": kwargs["canonical_repository"],
                    "status": "running",
                    "pid": 42_001,
                    "process_start_time": "listener-start-1",
                    "process_fingerprint": "listener-process-1",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {
                        "keep_alive": False,
                        "supervisor_state": "running",
                    },
                    "native_runner": {"active": True},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                action="start", target_kind="service", resource_id=SERVER_ID
            )

        self.assertTrue(reply["ok"], reply)
        proof = reply["result"]["result"]["endpoint_proof"]
        self.assertTrue(reply["result"]["result"]["supervision_ready"])
        self.assertTrue(reply["result"]["result"]["endpoint_ready"])
        self.assertTrue(reply["result"]["result"]["ready"])
        self.assertEqual(
            proof,
            {
                "certain": True,
                "listener_required": True,
                "state": "listening",
                "port": 3105,
                "pid": 42_001,
                "process_identity": "linux:42001:listener-start-1",
                "cwd_binding": "exact",
            },
        )
        self.assertEqual(
            self.actions.listener_observations,
            [(3105, "/repos/alpha", "tcp")],
        )

    def test_network_service_without_exact_port_binding_fails_before_launch(self) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET health_url_template = 'http://127.0.0.1:3109/health'
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                )

        class MustNotLaunch:
            def __init__(self, *_args, **_kwargs):
                raise AssertionError("network service launched without a port binding")

        with mock.patch.object(
            broker_backend_module, "WorkerController", MustNotLaunch
        ):
            reply = self._reply(
                action="start", target_kind="service", resource_id=SERVER_ID
            )

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(
            reply["error"]["code"], "service_endpoint_binding_unavailable"
        )

    def test_network_health_endpoint_must_match_exact_port_binding(self) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                now = utc_timestamp()
                connection.execute(
                    """
                    UPDATE server_definitions
                    SET health_url_template = 'http://127.0.0.1:3111/health'
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                )
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('runtime-health-web', ?, ?, 'web', 3110,
                              'active', 0, ?, ?)
                    """,
                    (HOST_ID, PROJECT_ID, now, now),
                )

        class MustNotLaunch:
            def __init__(self, *_args, **_kwargs):
                raise AssertionError("mismatched health endpoint launched")

        with mock.patch.object(
            broker_backend_module, "WorkerController", MustNotLaunch
        ):
            reply = self._reply(
                action="start", target_kind="service", resource_id=SERVER_ID
            )

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(
            reply["error"]["code"], "service_endpoint_binding_conflict"
        )

    def test_wrong_network_listener_rolls_back_exact_service_and_replays(self) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                now = utc_timestamp()
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('runtime-wrong-web', ?, ?, 'web', 3106,
                              'active', 0, ?, ?)
                    """,
                    (HOST_ID, PROJECT_ID, now, now),
                )
        self.actions.listener_evidence = {
            "pid": 99_999,
            "process_identity": "linux:99999:unrelated-start",
            "cwd": "/repos/alpha",
            "canonical_root": "/repos/alpha",
            "port": 3106,
            "protocol": "tcp",
        }
        calls: list[str] = []

        class FakeController:
            def __init__(self, _store, **_kwargs):
                pass

            def start(self, **kwargs):
                calls.append("start")
                return {
                    "ok": True,
                    "id": kwargs["worker_id"],
                    "name": kwargs["name"],
                    "status": "running",
                    "pid": 42_002,
                    "process_start_time": "listener-start-2",
                    "health": {"ok": True},
                    "supervision": {"supervisor_state": "running"},
                }

            def stop(self, **_kwargs):
                calls.append("stop")
                return {
                    "ok": True,
                    "status": "stopped",
                    "health": {"ok": False},
                    "terminal_process_proof": {
                        "certain": True,
                        "state": "absent",
                        "pid": 42_002,
                    },
                }

        request = self._request(
            action="start",
            target_kind="service",
            resource_id=SERVER_ID,
        )
        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            first = self._reply(request=request)
            replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first, replay)
        result = first["result"]["result"]
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["classification"], "service_endpoint_identity_unproven"
        )
        self.assertEqual(result["rollback"]["status"], "stopped")
        self.assertEqual(calls, ["start", "stop"])

    def test_network_endpoint_proof_rejects_wrong_exact_cwd(self) -> None:
        self.actions.listener_evidence = {
            "pid": 42_003,
            "process_identity": "linux:42003:listener-start-3",
            "cwd": "/repos/alpha/other",
            "canonical_root": "/repos/alpha",
            "port": 3107,
            "protocol": "tcp",
        }
        backend = StoreBackedMutationBackend(self.persistence, self.actions)

        with self.assertRaises(
            broker_backend_module.BrokerBackendError
        ) as raised:
            backend._runtime_service_endpoint_proof(
                endpoint_target=SimpleNamespace(
                    listener_required=True,
                    listener_port=3107,
                    canonical_root="/repos/alpha",
                    cwd="/repos/alpha",
                ),
                action="start",
                controlled={
                    "pid": 42_003,
                    "process_start_time": "listener-start-3",
                },
                operation_id="runtime-wrong-cwd",
            )

        self.assertEqual(
            raised.exception.code, "service_endpoint_identity_mismatch"
        )

    def test_network_endpoint_proof_waits_for_a_delayed_listener(self) -> None:
        class DelayedListener(type(self.actions)):
            def __init__(self):
                super().__init__()
                self.probes = 0

            def verify_owned_tcp_listener(self, *, port, canonical_root):
                self.probes += 1
                if self.probes < 3:
                    raise BrokerError(
                        "listener_identity_unavailable",
                        "listener has not bound yet",
                    )
                return {
                    "pid": 42_005,
                    "process_identity": "linux:42005:listener-start-5",
                    "cwd": "/repos/alpha",
                    "canonical_root": canonical_root,
                    "port": port,
                    "protocol": "tcp",
                }

        actions = DelayedListener()
        backend = StoreBackedMutationBackend(self.persistence, actions)
        with mock.patch.object(
            broker_backend_module, "_SERVICE_ENDPOINT_POLL_SECONDS", 0
        ):
            proof = backend._runtime_service_endpoint_proof(
                endpoint_target=SimpleNamespace(
                    listener_required=True,
                    listener_port=3112,
                    canonical_root="/repos/alpha",
                    cwd="/repos/alpha",
                ),
                action="start",
                controlled={
                    "pid": 42_005,
                    "process_start_time": "listener-start-5",
                },
                operation_id="runtime-delayed-listener",
            )

        self.assertEqual(actions.probes, 3)
        self.assertTrue(proof["certain"])
        self.assertEqual(proof["state"], "listening")

    def test_service_log_target_falls_back_to_latest_supervisor_artifact(self) -> None:
        self._prepare_worker_replacement()
        artifact = self.root / "worker-attempt.log"
        artifact.write_text("exact supervisor failure\n", encoding="utf-8")
        attempt_id = str(uuid.uuid4())
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                policy = connection.execute(
                    """
                    SELECT generation FROM worker_policies
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                ).fetchone()
                supervisor = connection.execute(
                    """
                    SELECT supervisor_generation, supervisor_epoch
                    FROM worker_supervisor_states
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                ).fetchone()
                connection.execute(
                    """
                    INSERT INTO worker_attempts(
                        attempt_id, begin_request_id, server_definition_id,
                        repo_id, definition_generation, policy_generation,
                        supervisor_generation, supervisor_epoch, state,
                        launch_report_id, exit_report_id, pid,
                        process_start_time, process_fingerprint, reserved_at,
                        launched_at, exited_at, exited_at_epoch, exit_kind,
                        exit_code, exit_classification, expected_exit,
                        counts_toward_breaker, log_artifact_id,
                        log_artifact_path, log_artifact_sha256,
                        exit_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, 'exited', ?, ?, 42006,
                              'start-42006', 'process-42006', ?, ?, ?, 1.0,
                              'exit_code', 1, 'crash', 0, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        "begin-" + attempt_id,
                        SERVER_ID,
                        PROJECT_ID,
                        int(policy["generation"]),
                        int(supervisor["supervisor_generation"]),
                        str(supervisor["supervisor_epoch"]),
                        "launch-" + attempt_id,
                        "exit-" + attempt_id,
                        now,
                        now,
                        now,
                        "artifact-" + attempt_id,
                        str(artifact),
                        "a" * 64,
                        "sha256:" + "b" * 64,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE worker_supervisor_states
                    SET state = 'stopped', current_attempt_id = NULL,
                        last_attempt_id = NULL
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                )
        request = self._request(
            action="capture_logs",
            target_kind="service",
            resource_id=SERVER_ID,
        )
        accepted = self.persistence.accept(peer_for(), request)

        target = self.persistence.runtime_service_log_target(accepted)

        self.assertEqual(target.log_path, str(artifact))
        self.assertEqual(target.owner_uid, os.geteuid())

    def test_network_stop_requires_listener_and_exact_process_absence(self) -> None:
        backend = StoreBackedMutationBackend(self.persistence, self.actions)
        endpoint = SimpleNamespace(
            listener_required=True,
            listener_port=3108,
            canonical_root="/repos/alpha",
            cwd="/repos/alpha",
        )

        proof = backend._runtime_service_endpoint_proof(
            endpoint_target=endpoint,
            action="stop",
            controlled={
                "terminal_process_proof": {
                    "certain": True,
                    "state": "pid_reused",
                    "pid": 42_004,
                }
            },
            operation_id="runtime-stop-proof",
        )

        self.assertEqual(proof["listener"], "absent")
        self.assertEqual(proof["process"]["state"], "pid_reused")
        blocked = StoreBackedMutationBackend(
            self.persistence,
            type(self.actions)(occupied_ports={3108}),
        )
        with self.assertRaises(
            broker_backend_module.BrokerBackendError
        ) as raised:
            blocked._runtime_service_endpoint_proof(
                endpoint_target=endpoint,
                action="stop",
                controlled={
                    "terminal_process_proof": {
                        "certain": True,
                        "state": "absent",
                    }
                },
                operation_id="runtime-stop-listener-still-bound",
            )
        self.assertEqual(raised.exception.code, "service_stop_identity_unproven")

    def test_network_service_stop_proves_process_and_assigned_port_absent(self) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                now = utc_timestamp()
                self._seed_stopped_worker_observation(connection)
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('runtime-stop-web', ?, ?, 'web', 3109,
                              'active', 0, ?, ?)
                    """,
                    (HOST_ID, PROJECT_ID, now, now),
                )
            WorkerSupervision(store).configure_policy(
                server_definition_id=SERVER_ID,
                actor="fixture",
                execution_uid=os.geteuid(),
                keep_alive=False,
            )

        class FakeController:
            def __init__(self, _store, **_kwargs):
                pass

            def stop(self, **_kwargs):
                return {
                    "ok": True,
                    "status": "stopped",
                    "health": {"ok": False, "classification": "stopped"},
                    "supervision": {"supervisor_state": "stopped"},
                    "terminal_process_proof": {
                        "certain": True,
                        "state": "absent",
                        "pid": 42_005,
                    },
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                action="stop", target_kind="service", resource_id=SERVER_ID
            )

        self.assertTrue(reply["ok"], reply)
        proof = reply["result"]["result"]["endpoint_proof"]
        self.assertEqual(proof["state"], "stopped")
        self.assertEqual(proof["listener"], "absent")
        self.assertEqual(proof["process"]["state"], "absent")
        self.assertIn(((3109,), "tcp"), self.actions.port_observations)

    def test_worker_service_lifecycle_uses_exact_worker_authority_and_replays(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE server_definitions SET role = 'worker' WHERE server_definition_id = ?",
                    (SERVER_ID,),
                )
                self._seed_stopped_worker_observation(connection)
            WorkerSupervision(store).configure_policy(
                server_definition_id=SERVER_ID,
                actor="fixture",
                execution_uid=os.geteuid(),
                keep_alive=True,
            )

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
        repository = self._prepare_worker_replacement(role="api")
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

    def test_worker_replace_uses_policy_uid_and_still_checks_path_and_generation(self) -> None:
        repository = self._prepare_worker_replacement(
            execution_uid=os.geteuid() + 1
        )
        request = self._worker_replace_request(
            repository,
            operation_id="ad161c28-b685-43a5-b0ac-600b34107630",
        )
        self.assertEqual(
            self.persistence.worker_execution_uid(
                self.persistence.accept(peer_for(), request)
            ),
            os.geteuid() + 1,
        )

        # Reconfigure the configured execution owner for the independent path
        # and generation guards; the caller UID remains attribution only.
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

    def test_database_replace_backs_up_restores_and_preserves_logical_id(self) -> None:
        actions, service, _backend = self._prepare_compose_replacement(
            database=True
        )
        request = self._request(
            action="replace",
            target_kind="database_stack",
            resource_id=DATABASE_ID,
        )

        reply = self._reply(request=request, service=service)
        replay = self._reply(request=request, service=service)

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply, replay)
        replacement = reply["result"]["replacement"]
        self.assertEqual(replacement["current"]["resource_id"], DATABASE_ID)
        self.assertTrue(replacement["data_preservation_verified"])
        self.assertEqual(
            [item[0] for item in actions.postgres_calls],
            ["backup", "restore"],
        )
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                binding = connection.execute(
                    """
                    SELECT docker_resource_id FROM database_bindings
                    WHERE database_binding_id = ?
                    """,
                    (DATABASE_ID,),
                ).fetchone()
                self.assertEqual(
                    binding["docker_resource_id"], REPLACEMENT_RESOURCE_ID
                )
                restore = connection.execute(
                    """
                    SELECT target_container_id FROM database_restore_events
                    WHERE restore_event_id = ?
                    """,
                    (
                        "database-restore-operation-"
                        + request.operation_id,
                    ),
                ).fetchone()
                if restore is None:
                    restore = connection.execute(
                        """
                        SELECT target_container_id
                        FROM database_restore_events
                        WHERE target_container_id = ?
                        """,
                        (REPLACEMENT_FULL_ID,),
                    ).fetchone()
                self.assertEqual(restore["target_container_id"], REPLACEMENT_FULL_ID)

    def test_replace_recovers_lost_terminal_commit_without_recreation(self) -> None:
        actions, service, _backend = self._prepare_compose_replacement()
        request = self._request(action="replace")
        original_finish = self.persistence.finish_runtime_replacement
        attempts = 0

        def finish_once_lost(*args: object, **kwargs: object) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("injected lost terminal commit")
            original_finish(*args, **kwargs)

        with mock.patch.object(
            self.persistence,
            "finish_runtime_replacement",
            side_effect=finish_once_lost,
        ):
            first = self._reply(request=request, service=service)
            replay = self._reply(request=request, service=service)

        self.assertFalse(first["ok"], first)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(actions.compose_calls, ["up"])
        self.assertEqual(attempts, 2)

    def test_database_replace_reconciles_lost_restore_result_without_reexecution(
        self,
    ) -> None:
        actions, service, backend = self._prepare_compose_replacement(
            database=True
        )
        request = self._request(
            action="replace",
            target_kind="database_stack",
            resource_id=DATABASE_ID,
        )
        original_restore = actions.postgres_restore
        recovered_result: dict[str, object] = {}

        def capture_restore(*args: object, **kwargs: object) -> dict[str, object]:
            result = dict(original_restore(*args, **kwargs))
            recovered_result.update(result)
            return result

        def reconcile_restore(
            _target: object,
            _backup: object,
            *,
            safety_output_root: str,
        ) -> dict[str, object]:
            del safety_output_root
            if not recovered_result:
                raise AssertionError("restore reconciliation ran before restore")
            return dict(recovered_result)

        original_save = self.persistence.save_runtime_replacement_restore_result
        save_attempts = 0

        def save_once_lost(*args: object, **kwargs: object) -> object:
            nonlocal save_attempts
            save_attempts += 1
            if save_attempts == 1:
                raise RuntimeError("injected lost restore-result commit")
            return original_save(*args, **kwargs)

        actions.postgres_restore = capture_restore  # type: ignore[method-assign]
        actions.postgres_reconcile_restore = (  # type: ignore[method-assign]
            reconcile_restore
        )
        with mock.patch.object(
            self.persistence,
            "save_runtime_replacement_restore_result",
            side_effect=save_once_lost,
        ):
            first = self._reply(request=request, service=service)
            restarted_service = BrokerService(
                StoreBackedRequestAcceptor(self.persistence),
                SerializedMutationWriter(backend),
            )
            replay = self._reply(request=request, service=restarted_service)

        self.assertFalse(first["ok"], first)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(actions.compose_calls, ["up"])
        self.assertEqual(
            [item[0] for item in actions.postgres_calls],
            ["backup", "restore"],
        )
        self.assertEqual(save_attempts, 2)

    def test_database_replace_never_reexecutes_unproved_prior_restore(self) -> None:
        actions, service, backend = self._prepare_compose_replacement(
            database=True
        )
        request = self._request(
            action="replace",
            target_kind="database_stack",
            resource_id=DATABASE_ID,
        )
        original_save = self.persistence.save_runtime_replacement_restore_result
        save_attempts = 0

        def lose_first_save(*args: object, **kwargs: object) -> object:
            nonlocal save_attempts
            save_attempts += 1
            if save_attempts == 1:
                raise RuntimeError("injected lost restore-result commit")
            return original_save(*args, **kwargs)

        with mock.patch.object(
            self.persistence,
            "save_runtime_replacement_restore_result",
            side_effect=lose_first_save,
        ):
            first = self._reply(request=request, service=service)
            restarted_service = BrokerService(
                StoreBackedRequestAcceptor(self.persistence),
                SerializedMutationWriter(backend),
            )
            replay = self._reply(request=request, service=restarted_service)

        self.assertFalse(first["ok"], first)
        self.assertFalse(replay["ok"], replay)
        self.assertEqual(
            replay["error"]["code"], "operation_outcome_uncertain"
        )
        self.assertEqual(
            [item[0] for item in actions.postgres_calls],
            ["backup", "restore"],
        )
        self.assertEqual(save_attempts, 1)

    def test_replace_preflight_rejects_unsealed_container_before_host_mutation(
        self,
    ) -> None:
        actions = RuntimeReplacementHostActions()
        service = self._service(actions=actions)

        reply = self._reply(action="replace", service=service)

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(
            reply["error"]["code"],
            "compose_collision_observation_incomplete",
        )
        self.assertEqual(actions.compose_calls, [])
        self.assertEqual(actions.postgres_calls, [])

    def test_ttl_start_is_durably_reaped_and_retains_borrowed_catalog(self) -> None:
        backend = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(backend),
        )
        request = self._request(
            action="start", purpose="test", ttl_seconds=30
        )
        reply = self._reply(request=request, service=service)
        replay = self._reply(request=request, service=service)

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(replay, reply)
        session_id = reply["result"]["run_id"]
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM runtime_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0],
                    "running",
                )
                resource_state = connection.execute(
                        """
                        SELECT cleanup_disposition, cleanup_state
                        FROM runtime_session_resources WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()
                self.assertEqual(
                    tuple(resource_state),
                    ("retained", "active"),
                )
                connection.execute(
                    """
                    UPDATE runtime_sessions SET expires_at = '2000-01-01T00:00:00Z'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )

        reaped = backend.reap_broker_runtime_sessions_once()
        repeated = backend.reap_broker_runtime_sessions_once()

        self.assertEqual(len(reaped), 1)
        self.assertEqual(reaped[0]["session_id"], session_id)
        self.assertEqual(reaped[0]["status"], "expired")
        self.assertEqual(repeated, [])
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM runtime_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0],
                    "expired",
                )
                self.assertEqual(
                    connection.execute(
                        """
                        SELECT cleanup_state FROM runtime_session_resources
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()[0],
                    "retained",
                )
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM docker_resources WHERE docker_resource_id = ?",
                        (CONTAINER_ID,),
                    ).fetchone()
                )
        self.assertEqual(
            [call[0] for call in self.actions.calls], ["start", "stop"]
        )

    def test_restarted_broker_background_reaper_recovers_departed_owner(self) -> None:
        original = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(original),
        )
        reply = self._reply(
            action="start",
            purpose="test",
            ttl_seconds=30,
            service=service,
        )
        self.assertTrue(reply["ok"], reply)
        session_id = reply["result"]["run_id"]
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_sessions
                    SET expires_at = '2000-01-01T00:00:00Z',
                        execution_owner_pid = 2147483647,
                        execution_owner_identity = 'departed-broker-owner'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )

        restarted = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        restarted.start_ephemeral_reaper()
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                with CoordinatorStore.open(
                    self.persistence.database_path, expected_uid=os.geteuid()
                ) as store:
                    with store.read_transaction() as connection:
                        status = connection.execute(
                            "SELECT status FROM runtime_sessions WHERE session_id = ?",
                            (session_id,),
                        ).fetchone()[0]
                if status == "expired":
                    break
                time.sleep(0.01)
            self.assertEqual(status, "expired")
        finally:
            restarted.stop_ephemeral_reaper(timeout_seconds=2.0)

        self.assertEqual(
            [call[0] for call in self.actions.calls], ["start", "stop"]
        )

    def test_restart_recovers_crash_after_ttl_intent_before_result_commit(self) -> None:
        request = self._request(
            action="start", purpose="test", ttl_seconds=30
        )
        authorized = self.persistence.accept(peer_for(), request)
        self.assertEqual(
            self.persistence.reserve_operation(authorized).state, "execute"
        )
        target = self.persistence.runtime_docker_target(authorized)
        session_id = self.persistence.begin_broker_runtime_session(
            authorized, target=target
        )
        self.actions.docker_start(target)

        recovered = self.persistence.recover_interrupted_docker_operations()
        self.assertEqual(recovered["operation_ids"], [request.operation_id])
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                session = connection.execute(
                    """
                    SELECT status FROM runtime_sessions WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                resource = connection.execute(
                    """
                    SELECT cleanup_state FROM runtime_session_resources
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                self.assertEqual(session["status"], "cleanup_pending")
                self.assertEqual(resource["cleanup_state"], "active")
                connection.execute(
                    """
                    UPDATE runtime_sessions
                    SET expires_at = '2000-01-01T00:00:00Z'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )

        restarted = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        result = restarted.reap_broker_runtime_sessions_once()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "expired")
        self.assertEqual(
            [call[0] for call in self.actions.calls], ["start", "stop"]
        )

    def test_newer_runtime_session_supersedes_older_ttl_cleanup(self) -> None:
        backend = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(backend),
        )
        expiring = self._reply(
            action="start",
            purpose="test",
            ttl_seconds=30,
            service=service,
        )
        persistent = self._reply(action="start", service=service)
        self.assertTrue(expiring["ok"], expiring)
        self.assertTrue(persistent["ok"], persistent)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_sessions SET expires_at = '2000-01-01T00:00:00Z'
                    WHERE session_id = ?
                    """,
                    (expiring["result"]["run_id"],),
                )

        reaped = backend.reap_broker_runtime_sessions_once()

        self.assertEqual(len(reaped), 1)
        self.assertEqual(
            reaped[0]["result"]["classification"],
            "superseded_by_newer_runtime_session",
        )
        self.assertEqual(
            [call[0] for call in self.actions.calls], ["start", "start"]
        )

    def test_database_ttl_cleanup_stops_container_and_retains_binding(self) -> None:
        seed_postgres_database(self.persistence)

        def observe_database(store: CoordinatorStore) -> dict[str, object]:
            stopped = bool(
                self.actions.calls and self.actions.calls[-1][0] == "stop"
            )
            return self._runtime_observer(
                store,
                lifecycle="stopped" if stopped else "running",
                database_available=not stopped,
            )

        backend = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=observe_database,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(backend),
        )
        reply = self._reply(
            action="start",
            purpose="temporary",
            ttl_seconds=30,
            target_kind="database_stack",
            resource_id=DATABASE_ID,
            service=service,
        )
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_sessions SET expires_at = '2000-01-01T00:00:00Z'
                    WHERE session_id = ?
                    """,
                    (reply["result"]["run_id"],),
                )
                session_state = connection.execute(
                    """
                    SELECT status, action, purpose, ttl_seconds, expires_at
                    FROM runtime_sessions WHERE session_id = ?
                    """,
                    (reply["result"]["run_id"],),
                ).fetchone()
                resource_state = connection.execute(
                    """
                    SELECT resource_kind, resource_id, cleanup_state
                    FROM runtime_session_resources WHERE session_id = ?
                    """,
                    (reply["result"]["run_id"],),
                ).fetchone()
                self.assertEqual(
                    tuple(session_state),
                    (
                        "running",
                        "start",
                        "temporary",
                        30,
                        "2000-01-01T00:00:00Z",
                    ),
                )
                self.assertEqual(
                    tuple(resource_state),
                    ("database_stack", DATABASE_ID, "active"),
                )

        reaped = backend.reap_broker_runtime_sessions_once()

        self.assertEqual(len(reaped), 1)
        self.assertEqual(reaped[0]["status"], "expired")
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertIsNotNone(
                    connection.execute(
                        """
                        SELECT 1 FROM database_bindings
                        WHERE database_binding_id = ? AND docker_resource_id = ?
                        """,
                        (DATABASE_ID, CONTAINER_ID),
                    ).fetchone()
                )
        self.assertEqual(
            [call[0] for call in self.actions.calls], ["start", "stop"]
        )

    def test_ttl_cleanup_fails_closed_on_immutable_container_drift(self) -> None:
        backend = StoreBackedMutationBackend(
            self.persistence,
            self.actions,
            observe_before_lifecycle_plan=self._runtime_observer,
        )
        service = BrokerService(
            StoreBackedRequestAcceptor(self.persistence),
            SerializedMutationWriter(backend),
        )
        reply = self._reply(
            action="start",
            purpose="test",
            ttl_seconds=30,
            service=service,
        )
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        session_id = reply["result"]["run_id"]
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE runtime_sessions SET expires_at = '2000-01-01T00:00:00Z'
                    WHERE session_id = ?
                    """,
                    (session_id,),
                )
                connection.execute(
                    """
                    UPDATE docker_resources SET full_container_id = ?, updated_at = ?
                    WHERE docker_resource_id = ?
                    """,
                    ("f" * 64, utc_timestamp(), CONTAINER_ID),
                )

        result = backend.reap_broker_runtime_sessions_once()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "cleanup_pending")
        self.assertEqual(
            result[0]["error"]["type"], "BrokerError"
        )
        self.assertEqual([call[0] for call in self.actions.calls], ["start"])
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM runtime_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0],
                    "cleanup_pending",
                )
                self.assertEqual(
                    connection.execute(
                        """
                        SELECT cleanup_state FROM runtime_session_resources
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()[0],
                    "failed",
                )

    def test_docker_start_stop_restart_use_exact_identity_and_terminal_proof(
        self,
    ) -> None:
        for action in ("start", "stop", "restart"):
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

    def test_unknown_optional_temporary_route_does_not_gate_root_lifecycle(self) -> None:
        reply = self._reply(
            action="start", temporary_repo_id="not-an-configured-worktree"
        )
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(reply["result"]["ok"], reply)
        self.assertEqual(len(self.actions.calls), 1)

    def test_success_replays_durably_after_writer_reconstruction(self) -> None:
        request = self._request(action="start")

        first = self._reply(request=request)
        second = self._reply(request=request, service=self._service())

        self.assertTrue(first["ok"], first)
        self.assertEqual(second, first)
        self.assertEqual(len(self.actions.calls), 1)

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
        request = self._request(action="start")
        authorized = self.persistence.accept(peer_for(), request)
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
        docker_request = self._request(action="start")
        database_request = self._request(
            action="stop",
            target_kind="database_stack",
            resource_id=DATABASE_ID,
        )
        self.assertEqual(
            self.persistence.reserve_operation(
                self.persistence.accept(peer_for(), docker_request)
            ).state,
            "execute",
        )

        with self.assertRaises(BrokerError) as blocked:
            self.persistence.reserve_operation(
                self.persistence.accept(peer_for(), database_request)
            )

        self.assertEqual(blocked.exception.code, "docker_operation_pending")

    def test_final_state_and_identity_mismatch_fail_durably(self) -> None:

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
