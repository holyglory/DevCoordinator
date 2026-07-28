"""Focused generic HTTP/broker lifecycle authority regressions."""

from __future__ import annotations

import os
from pathlib import Path
import time
import unittest
from unittest import mock

from devcoordinator import broker_backend as broker_backend_module
from devcoordinator.broker import (
    AuthorizedBrokerRequest,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import StoreBackedAuthorizer
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.cleanup_lifecycle import DockerCleanupBackend
from devcoordinator.repository_lifecycle import ResourceKind
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import CoordinatorStore, fingerprint, utc_timestamp
from devcoordinator.tests import test_broker as fixtures
import dev_coordinator


class RestorableLifecycleAdapter(fixtures.ExactLifecycleAdapter):
    def restore_startup_policy(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        self.calls.append("restore_policy")
        self.policy_disabled = False
        return {"status": "restored", "started": False}


def _service(
    persistence: object,
    actions: object,
    adapter: RestorableLifecycleAdapter,
    *,
    observer: object = fixtures._committed_available_observer,
) -> BrokerService:
    backend = StoreBackedMutationBackend(
        persistence,
        actions,
        lifecycle_adapter=adapter,
        observe_before_lifecycle_plan=observer,
    )
    return BrokerService(
        StoreBackedAuthorizer(persistence), SerializedMutationWriter(backend)
    )


def _grant_project_archive(persistence: object) -> None:
    for operation in (
        BrokerOperation.CLEANUP_PLAN,
        BrokerOperation.CLEANUP_APPLY,
        BrokerOperation.LIFECYCLE_RESTORE,
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
    ):
        persistence.grant_cleanup(
            uid=os.geteuid(), repo_id=fixtures.PROJECT_ID, operation=operation
        )
    for operation in (
        BrokerOperation.REPOSITORY_PLAN_REMOVE,
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.REPOSITORY_REINSTALL,
    ):
        persistence.grant_lifecycle(
            uid=os.geteuid(), repo_id=fixtures.PROJECT_ID, operation=operation
        )


class GenericLifecycleBrokerTests(unittest.TestCase):
    def test_service_observed_repository_member_can_receive_exact_cleanup_grant(
        self,
    ) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, _actions = fixtures.seed_store_backed_broker(root)
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE coordinator_sources SET effective_uid = 0"
                    )
                    connection.execute(
                        "UPDATE repository_memberships SET immutable_fingerprint = ? "
                        "WHERE host_resource_id = ?",
                        ("sha256:" + "a" * 64, fixtures.CONTAINER_ID),
                    )
                exact, repo_id = SQLiteLifecyclePersistence(store).resolve_resource(
                    ResourceKind.CONTAINER,
                    fixtures.CONTAINER_ID,
                    fixtures.CONTROL_ID,
                )

            persistence.grant_cleanup_resource(
                uid=os.geteuid(),
                repo_id=repo_id,
                resource_kind=exact.kind.value,
                resource_id=exact.resource_id,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.CLEANUP_PLAN,
            )

    def test_completed_permanent_cleanup_replay_does_not_resolve_deleted_resource(self) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, actions = fixtures.seed_store_backed_broker(root)
            plan_id = "6f070080-1da7-44bb-9e98-8ea43fcbeb34"
            plan_fingerprint = "sha256:" + "9" * 64
            confirmation = "PURGE SERVER obsolete-worker"
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO operations(
                            operation_id, repo_id, kind, status, phase,
                            generation, request_fingerprint, owner_uid, actor,
                            created_at, updated_at
                        ) VALUES (?, ?, 'cleanup:purge', 'succeeded', 'complete',
                                  0, ?, ?, 'fixture', ?, ?)
                        """,
                        (
                            plan_id,
                            fixtures.PROJECT_ID,
                            plan_fingerprint,
                            os.geteuid(),
                            now,
                            now,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO cleanup_plans(
                            plan_id, repo_id, target_kind, target_id, action,
                            target_fingerprint, plan_fingerprint,
                            confirmation_phrase, snapshot_json, status, phase,
                            actor, reason, created_at, updated_at
                        ) VALUES (?, ?, 'server', 'deleted-worker', 'purge',
                                  ?, ?, ?, '{}', 'succeeded', 'complete',
                                  'fixture', 'obsolete', ?, ?)
                        """,
                        (
                            plan_id,
                            fixtures.PROJECT_ID,
                            "sha256:" + "8" * 64,
                            plan_fingerprint,
                            confirmation,
                            now,
                            now,
                        ),
                    )
                backend = StoreBackedMutationBackend(
                    persistence,
                    actions,
                    lifecycle_adapter=RestorableLifecycleAdapter(),
                    observe_before_lifecycle_plan=fixtures._committed_available_observer,
                )
                request = fixtures.request_for(
                    BrokerOperation.CLEANUP_APPLY,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "plan_id": plan_id,
                        "plan_fingerprint": plan_fingerprint,
                        "confirmation_phrase": confirmation,
                    },
                )
                authorized = AuthorizedBrokerRequest(
                    peer=fixtures.peer_for(), request=request
                )
                cleanup = mock.Mock()
                cleanup.apply.return_value = {
                    "ok": True,
                    "status": "succeeded",
                    "plan_id": plan_id,
                }
                with mock.patch.object(
                    backend,
                    "_authorize_generic_cleanup_resource",
                    side_effect=AssertionError("deleted resource must not be resolved"),
                ), mock.patch.object(
                    backend,
                    "_observe_fresh_full_docker",
                    side_effect=AssertionError("completed replay must not observe host"),
                ):
                    result = backend._apply_generic_lifecycle(
                        authorized,
                        store=store,
                        cleanup=cleanup,
                        actor="fixture-replayer",
                    )
            self.assertTrue(result["ok"])
            self.assertTrue(result["replayed_after_completion"])
            self.assertIsNone(result["pre_apply_observation"])
            cleanup.apply.assert_called_once_with(
                plan_id=plan_id,
                plan_fingerprint=plan_fingerprint,
                confirmation_phrase=confirmation,
                actor="fixture-replayer",
            )

    def test_project_purge_observes_fresh_host_at_plan_and_apply(self) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, actions = fixtures.seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "DELETE FROM repository_memberships WHERE repo_id = ?",
                        (fixtures.PROJECT_ID,),
                    )
                    connection.execute(
                        "UPDATE leases SET status='released', updated_at=? WHERE repo_id=?",
                        (now, fixtures.PROJECT_ID),
                    )
                    connection.execute(
                        "UPDATE port_assignments SET status='inactive', updated_at=? WHERE repo_id=?",
                        (now, fixtures.PROJECT_ID),
                    )
                    connection.execute(
                        """
                        UPDATE repository_installations
                        SET status='disabled', startup_fenced=1,
                            disabled_at=?, reason='archived fixture', updated_at=?
                        WHERE repo_id=?
                        """,
                        (now, now, fixtures.PROJECT_ID),
                    )
            for operation in (
                BrokerOperation.CLEANUP_PLAN,
                BrokerOperation.CLEANUP_APPLY,
            ):
                persistence.grant_cleanup(
                    uid=os.geteuid(), repo_id=fixtures.PROJECT_ID, operation=operation
                )
            observations = 0

            def observe(store: CoordinatorStore) -> object:
                nonlocal observations
                observations += 1
                return fixtures._committed_available_observer(store)

            service = _service(
                persistence,
                actions,
                RestorableLifecycleAdapter(),
                observer=observe,
            )
            planned = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_PLAN,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "action": "purge",
                        "target_kind": "project",
                        "target_id": fixtures.PROJECT_ID,
                        "reason": "catalog cleanup",
                    },
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)
            self.assertEqual(observations, 1)
            self.assertTrue(planned["result"]["broker_observation"]["observed"])

            with (
                mock.patch.object(
                    broker_backend_module,
                    "configured_profile_path",
                    return_value=Path("/protected/profile.json"),
                ),
                mock.patch.object(
                    broker_backend_module,
                    "revoke_repository_from_protected_profile",
                    side_effect=lambda **arguments: {
                        "status": "revoked",
                        "repo_id": arguments["repo_id"],
                        "repository_generation": arguments[
                            "repository_generation"
                        ],
                        "cleanup_operation_id": arguments[
                            "cleanup_operation_id"
                        ],
                        "affected_client_uids": [os.geteuid()],
                        "profile_path": str(arguments["profile_path"]),
                    },
                ),
            ):
                applied = service.reply_for_document(
                    fixtures.peer_for(),
                    fixtures.request_for(
                        BrokerOperation.CLEANUP_APPLY,
                        resource_id=fixtures.PROJECT_ID,
                        arguments={
                            "plan_id": planned["result"]["plan_id"],
                            "plan_fingerprint": planned["result"]["plan_fingerprint"],
                            "confirmation_phrase": planned["result"]["confirmation_phrase"],
                        },
                    ).to_wire(),
                )
            self.assertTrue(applied["ok"], applied)
            self.assertEqual(observations, 2)
            self.assertTrue(applied["result"]["pre_apply_observation"]["observed"])

    def test_project_archive_apply_resolves_plan_after_inactive_transport_anchor(self) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, actions = fixtures.seed_store_backed_broker(root)
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE docker_observations SET restart_policy = 'always'"
                    )
                    for index, resource_id in enumerate(
                        (fixtures.CONTAINER_ID, fixtures.SECOND_CONTAINER_ID)
                    ):
                        connection.execute(
                            """
                            INSERT INTO startup_policies(
                                policy_id, repo_id, resource_kind, resource_id,
                                policy_kind, current_value, desired_disabled_value,
                                immutable_fingerprint, generation, updated_at
                            ) VALUES (?, ?, 'container', ?, 'docker_restart',
                                      'always', 'no', ?, 0, ?)
                            """,
                            (
                                f"generic-project-policy-{index}",
                                fixtures.PROJECT_ID,
                                resource_id,
                                "sha256:" + ("a" if index == 0 else "b") * 64,
                                now,
                            ),
                        )
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name, state,
                            generation, created_at, updated_at
                        ) VALUES ('repo-inactive-anchor', ?, '/repos/000-anchor',
                                  'Inactive Anchor', 'missing', 1, ?, ?)
                        """,
                        (fixtures.HOST_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation, actor,
                            disabled_at, reason, updated_at
                        ) VALUES ('repo-inactive-anchor', 'disabled', 1, 1,
                                  'fixture', ?, 'removed anchor', ?)
                        """,
                        (now, now),
                    )
            persistence.provision_repository_enrollment(
                uid=os.geteuid(),
                repo_id="repo-inactive-anchor",
                account_id=fixtures.ACCOUNT_ID,
                issued_at=utc_timestamp(),
                valid_until_epoch=int(time.time()) + 3_600,
            )
            persistence.grant_cleanup(
                uid=os.geteuid(),
                repo_id="repo-inactive-anchor",
                operation=BrokerOperation.CLEANUP_APPLY,
            )
            _grant_project_archive(persistence)
            adapter = RestorableLifecycleAdapter()
            service = _service(persistence, actions, adapter)

            planned = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_PLAN,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "action": "archive",
                        "target_kind": "project",
                        "target_id": fixtures.PROJECT_ID,
                        "reason": "generic project archive",
                    },
                ).to_wire(),
            )
            self.assertTrue(planned["ok"], planned)
            self.assertEqual(planned["result"]["confirmation_phrase"], "")

            applied_request = BrokerRequest.create(
                account_id=fixtures.ACCOUNT_ID,
                project_id="repo-inactive-anchor",
                resource_id="repo-inactive-anchor",
                operation=BrokerOperation.CLEANUP_APPLY,
                authority_generation=fixtures.CURRENT_AUTHORITY_GENERATION,
                arguments={
                    "plan_id": planned["result"]["plan_id"],
                    "plan_fingerprint": planned["result"]["plan_fingerprint"],
                    "confirmation_phrase": "",
                },
            )
            applied = service.reply_for_document(
                fixtures.peer_for(), applied_request.to_wire()
            )
            self.assertTrue(applied["ok"], applied)
            self.assertEqual(applied["result"]["action"], "archive")
            self.assertFalse(applied["result"]["started"])

            restored = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.LIFECYCLE_RESTORE,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "target_kind": "project",
                        "target_id": fixtures.PROJECT_ID,
                        "reason": "restore without starting",
                    },
                ).to_wire(),
            )
            self.assertTrue(restored["ok"], restored)
            self.assertFalse(restored["result"]["started"])
            self.assertFalse(adapter.running)

    @mock.patch.object(
        DockerCleanupBackend,
        "inspect",
        return_value={
            "full_container_id": "a" * 64,
            "running": False,
            "status": "exited",
            "mounts": [],
            "labels": {},
        },
    )
    def test_resource_archive_restore_and_purge_require_distinct_exact_grants(
        self, _inspect: object
    ) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, actions = fixtures.seed_store_backed_broker(root)
            now = utc_timestamp()
            immutable = "sha256:" + fingerprint(
                {
                    "resource_kind": "container",
                    "resource_id": fixtures.CONTAINER_ID,
                    "native_identity": {
                        "docker_resource_id": fixtures.CONTAINER_ID,
                        "engine_id": fixtures.ENGINE_ID,
                        "full_container_id": "a" * 64,
                    },
                }
            )
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE repository_memberships SET immutable_fingerprint = ? WHERE host_resource_id = ?",
                        (immutable, fixtures.CONTAINER_ID),
                    )
                    connection.execute(
                        "UPDATE docker_observations SET restart_policy = 'always' WHERE docker_resource_id = ?",
                        (fixtures.CONTAINER_ID,),
                    )
                    connection.execute(
                        """
                        INSERT INTO startup_policies(
                            policy_id, repo_id, resource_kind, resource_id,
                            policy_kind, current_value, desired_disabled_value,
                            immutable_fingerprint, generation, updated_at
                        ) VALUES ('generic-resource-policy', ?, 'container', ?,
                                  'docker_restart', 'always', 'no', ?, 0, ?)
                        """,
                        (
                            fixtures.PROJECT_ID,
                            fixtures.CONTAINER_ID,
                            "sha256:" + "a" * 64,
                            now,
                        ),
                    )
                exact, repo_id = SQLiteLifecyclePersistence(store).resolve_resource(
                    ResourceKind.CONTAINER,
                    fixtures.CONTAINER_ID,
                    fixtures.CONTROL_ID,
                )
            self.assertEqual(repo_id, fixtures.PROJECT_ID)
            for operation in (
                BrokerOperation.CLEANUP_PLAN,
                BrokerOperation.CLEANUP_APPLY,
                BrokerOperation.LIFECYCLE_RESTORE,
                BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                BrokerOperation.RESOURCE_ARCHIVE,
                BrokerOperation.RESOURCE_RESTORE,
            ):
                persistence.grant_cleanup(
                    uid=os.geteuid(), repo_id=fixtures.PROJECT_ID, operation=operation
                )
            for operation in (
                BrokerOperation.RESOURCE_PLAN_ARCHIVE,
                BrokerOperation.RESOURCE_ARCHIVE,
                BrokerOperation.RESOURCE_RESTORE,
            ):
                persistence.grant_cleanup_resource(
                    uid=os.geteuid(),
                    repo_id=fixtures.PROJECT_ID,
                    resource_kind="container",
                    resource_id=fixtures.CONTAINER_ID,
                    control_binding_id=exact.control_binding_id,
                    immutable_fingerprint=exact.immutable_fingerprint,
                    ownership_fingerprint=exact.ownership_fingerprint,
                    operation=operation,
                )
            adapter = RestorableLifecycleAdapter()
            service = _service(persistence, actions, adapter)

            archive_plan = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_PLAN,
                    resource_id=fixtures.CONTAINER_ID,
                    arguments={
                        "action": "archive",
                        "target_kind": "container",
                        "target_id": fixtures.CONTAINER_ID,
                        "reason": "generic resource archive",
                    },
                ).to_wire(),
            )
            self.assertTrue(archive_plan["ok"], archive_plan)
            archived = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_APPLY,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "plan_id": archive_plan["result"]["plan_id"],
                        "plan_fingerprint": archive_plan["result"]["plan_fingerprint"],
                        "confirmation_phrase": "",
                    },
                ).to_wire(),
            )
            self.assertTrue(archived["ok"], archived)
            self.assertFalse(archived["result"]["started"])

            purge_arguments = {
                "action": "purge",
                "target_kind": "container",
                "target_id": fixtures.CONTAINER_ID,
                "reason": "exact cleanup grant regression",
            }
            denied_plan = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_PLAN,
                    resource_id=fixtures.CONTAINER_ID,
                    arguments=purge_arguments,
                ).to_wire(),
            )
            self.assertFalse(denied_plan["ok"], denied_plan)
            self.assertEqual(denied_plan["error"]["code"], "resource_access_denied")

            persistence.grant_cleanup_resource(
                uid=os.geteuid(),
                repo_id=fixtures.PROJECT_ID,
                resource_kind="container",
                resource_id=fixtures.CONTAINER_ID,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.CLEANUP_PLAN,
            )
            persistence.grant_cleanup_resource(
                uid=os.geteuid(),
                repo_id=fixtures.PROJECT_ID,
                resource_kind="container",
                resource_id=fixtures.CONTAINER_ID,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.CLEANUP_APPLY,
            )
            purge_plan = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_PLAN,
                    resource_id=fixtures.CONTAINER_ID,
                    arguments=purge_arguments,
                ).to_wire(),
            )
            self.assertTrue(purge_plan["ok"], purge_plan)
            persistence.grant_cleanup_resource(
                uid=os.geteuid(),
                repo_id=fixtures.PROJECT_ID,
                resource_kind="container",
                resource_id=fixtures.CONTAINER_ID,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.CLEANUP_APPLY,
                enabled=False,
            )
            denied_apply = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CLEANUP_APPLY,
                    resource_id=fixtures.PROJECT_ID,
                    arguments={
                        "plan_id": purge_plan["result"]["plan_id"],
                        "plan_fingerprint": purge_plan["result"]["plan_fingerprint"],
                        "confirmation_phrase": purge_plan["result"]["confirmation_phrase"],
                    },
                ).to_wire(),
            )
            self.assertFalse(denied_apply["ok"], denied_apply)
            self.assertEqual(denied_apply["error"]["code"], "resource_access_denied")

            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE broker_cleanup_resource_acl
                        SET ownership_fingerprint = ?
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'container' AND resource_id = ?
                          AND operation = 'resource.restore'
                        """,
                        (
                            "sha256:" + "f" * 64,
                            os.geteuid(),
                            fixtures.PROJECT_ID,
                            fixtures.CONTAINER_ID,
                        ),
                    )
            denied_restore = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.LIFECYCLE_RESTORE,
                    resource_id=fixtures.CONTAINER_ID,
                    arguments={
                        "target_kind": "container",
                        "target_id": fixtures.CONTAINER_ID,
                        "reason": "stale exact restore grant must fail",
                    },
                ).to_wire(),
            )
            self.assertFalse(denied_restore["ok"], denied_restore)
            self.assertEqual(denied_restore["error"]["code"], "resource_access_denied")
            persistence.grant_cleanup_resource(
                uid=os.geteuid(),
                repo_id=fixtures.PROJECT_ID,
                resource_kind="container",
                resource_id=fixtures.CONTAINER_ID,
                control_binding_id=exact.control_binding_id,
                immutable_fingerprint=exact.immutable_fingerprint,
                ownership_fingerprint=exact.ownership_fingerprint,
                operation=BrokerOperation.RESOURCE_RESTORE,
            )
            restored = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.LIFECYCLE_RESTORE,
                    resource_id=fixtures.CONTAINER_ID,
                    arguments={
                        "target_kind": "container",
                        "target_id": fixtures.CONTAINER_ID,
                        "reason": "restore without starting",
                    },
                ).to_wire(),
            )
            self.assertTrue(restored["ok"], restored)
            self.assertFalse(restored["result"]["started"])
            self.assertFalse(adapter.running)
            self.assertFalse(adapter.policy_disabled)


class GenericLifecycleHttpTests(unittest.TestCase):
    def test_account_http_purge_observes_at_plan_and_apply(self) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, _actions = fixtures.seed_store_backed_broker(root)
            project_root = root / "project"
            project_root.mkdir()
            now = utc_timestamp()
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        "UPDATE repositories SET canonical_root=? WHERE repo_id=?",
                        (str(project_root), fixtures.PROJECT_ID),
                    )
                    connection.execute(
                        "DELETE FROM repository_memberships WHERE repo_id=?",
                        (fixtures.PROJECT_ID,),
                    )
                    connection.execute(
                        "UPDATE leases SET status='released', updated_at=? WHERE repo_id=?",
                        (now, fixtures.PROJECT_ID),
                    )
                    connection.execute(
                        "UPDATE port_assignments SET status='inactive', updated_at=? WHERE repo_id=?",
                        (now, fixtures.PROJECT_ID),
                    )
                    connection.execute(
                        """
                        UPDATE repository_installations
                        SET status='disabled', startup_fenced=1, disabled_at=?, updated_at=?
                        WHERE repo_id=?
                        """,
                        (now, now, fixtures.PROJECT_ID),
                    )
            observations = 0

            def observe(options: dict[str, object]) -> dict[str, object]:
                nonlocal observations
                observations += 1
                with CoordinatorStore.open(
                    persistence.database_path, expected_uid=os.geteuid()
                ) as observed_store:
                    evidence = dict(fixtures._committed_available_observer(observed_store))
                return {
                    **evidence,
                    "status": "completed",
                    "observed": True,
                    "joined": False,
                    "max_age_seconds": 0.0,
                    "request": {
                        "project": options["project"],
                        "agent": options["agent"],
                    },
                }

            patches = (
                mock.patch.object(dev_coordinator, "configured_broker_profile", return_value=None),
                mock.patch.object(dev_coordinator, "authority_mode", return_value="account"),
                mock.patch.object(
                    dev_coordinator,
                    "coordinator_home",
                    return_value=persistence.database_path.parent,
                ),
                mock.patch.object(dev_coordinator, "coordinated_observe_host", side_effect=observe),
            )
            with patches[0], patches[1], patches[2], patches[3]:
                planned = dev_coordinator.coordinated_lifecycle_plan(
                    {
                        "action": "purge",
                        "target_kind": "project",
                        "target_id": fixtures.PROJECT_ID,
                        "reason": "account HTTP cleanup",
                    }
                )
                self.assertEqual(observations, 1)
                applied = dev_coordinator.coordinated_lifecycle_apply(
                    {
                        "plan_id": planned["plan_id"],
                        "plan_fingerprint": planned["plan_fingerprint"],
                        "confirmation_phrase": planned["confirmation_phrase"],
                    }
                )
            self.assertTrue(applied["ok"])
            self.assertEqual(observations, 2)
            self.assertTrue(applied["pre_apply_observation"]["docker_available"])

    def test_expired_profile_fails_before_archive_broker_call(self) -> None:
        root = str(Path("/repos/expired").resolve())
        repository = BrokerRepositoryProfile(
            canonical_root=root,
            repo_id="repo-expired",
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
        )
        profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=Path("/run/devcoordinator/broker.sock"),
                service_uid=0,
                socket_gid=0,
                socket_mode=0o660,
                database_generation="generation-expired",
            ),
            client_uid=os.geteuid(),
            account_id="account-expired",
            issued_at="2026-07-18T00:00:00Z",
            valid_until_epoch=int(time.time()) - 1,
            repositories={root: repository},
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ), mock.patch.object(BrokerClientProfile, "call") as broker_call:
            with self.assertRaisesRegex(BrokerProfileError, "expired"):
                dev_coordinator.coordinated_list_archives()
        broker_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
