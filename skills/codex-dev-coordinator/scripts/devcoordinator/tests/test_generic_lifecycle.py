"""Focused generic HTTP/broker lifecycle authority regressions."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest import mock

from devcoordinator import broker_backend as broker_backend_module
from devcoordinator import lifecycle_cli as lifecycle_cli_module
from devcoordinator.broker import (
    AcceptedBrokerRequest,
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend
from devcoordinator.broker_persistence import StoreBackedRequestAcceptor
from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.cleanup_lifecycle import CleanupLifecycle, DockerCleanupBackend
from devcoordinator.repository_lifecycle import (
    ResourceKind,
    ResourceObservation,
    RunningState,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import CoordinatorStore, fingerprint, utc_timestamp
from devcoordinator.tests import test_broker as fixtures
import dev_coordinator


class RestorableLifecycleAdapter(fixtures.ExactLifecycleAdapter):
    def restore_startup_policy(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        self.calls.append("restore_policy")
        self.policy_disabled = False
        return {"status": "restored", "started": False}


class BrokerCleanupProjectionTests(unittest.TestCase):
    def test_cleanup_target_deduplicates_selected_same_repository_configurations(self) -> None:
        selected = mock.Mock(
            canonical_root="/repos/shared",
            repo_id="repo-shared",
            server_ids={"fixture": "service-shared"},
            container_ids={},
        )
        profile = mock.Mock()
        profile.repositories = {
            "account-a:/repos/shared": mock.Mock(canonical_root="/repos/shared"),
            "account-b:/repos/shared": mock.Mock(canonical_root="/repos/shared"),
        }
        profile.repository.return_value = selected
        profile.inventory.return_value = {
            "repository_trees": [
                {
                    "family_id": "family-shared",
                    "scopes": [
                        {
                            "repo_id": "repo-shared",
                            "kind": "root",
                            "canonical_root": "/repos/shared",
                            "server_ids": ["service-shared"],
                            "container_resource_ids": [],
                            "database_binding_ids": [],
                        }
                    ],
                }
            ],
            "resources": {
                "servers": [
                    {
                        "server_definition_id": "service-shared",
                        "name": "fixture",
                    }
                ],
                "docker": [],
                "databases": [],
            },
            "observations": {
                "servers": [
                    {
                        "server_definition_id": "service-shared",
                        "lifecycle": "running",
                    }
                ],
                "docker": [],
                "databases": [],
            },
        }

        repositories = dev_coordinator._cleanup_profile_repositories(profile)
        resolved = dev_coordinator._cleanup_profile_target_repository(
            profile,
            target_kind="server",
            target_id="service-shared",
        )

        self.assertEqual(repositories, (selected,))
        self.assertIs(resolved, selected)
        self.assertEqual(profile.repository.call_count, 4)
        profile.inventory.assert_called_once_with(canonical_root="/repos/shared")

    def test_cleanup_plan_resolves_current_inventory_not_stale_profile_ids(self) -> None:
        repository_a = mock.Mock(canonical_root="/repos/a", repo_id="repo-a")
        repository_b = mock.Mock(canonical_root="/repos/b", repo_id="repo-b")
        profile = mock.Mock()
        profile.repositories = {
            repository_a.canonical_root: repository_a,
            repository_b.canonical_root: repository_b,
        }
        profile.repository.side_effect = lambda root: profile.repositories[root]
        profile.inventory.return_value = {
            "repository_trees": [
                {
                    "family_id": "family-a",
                    "root_repository": {
                        "repo_id": repository_a.repo_id,
                        "canonical_root": repository_a.canonical_root,
                    },
                    "scopes": [
                        {
                            "repo_id": repository_a.repo_id,
                            "kind": "root",
                            "canonical_root": repository_a.canonical_root,
                            "server_ids": [],
                            "container_resource_ids": [],
                            "database_binding_ids": [],
                        }
                    ],
                },
                {
                    "family_id": "family-b",
                    "root_repository": {
                        "repo_id": repository_b.repo_id,
                        "canonical_root": repository_b.canonical_root,
                    },
                    "scopes": [
                        {
                            "repo_id": repository_b.repo_id,
                            "kind": "root",
                            "canonical_root": repository_b.canonical_root,
                            "server_ids": [],
                            "container_resource_ids": ["docker-current"],
                            "database_binding_ids": [],
                        }
                    ],
                },
            ],
            "resources": {
                "servers": [],
                "docker": [
                    {
                        "docker_resource_id": "docker-current",
                        "current_name": "current-container",
                    }
                ],
                "databases": [],
            },
            "observations": {
                "servers": [],
                "docker": [
                    {
                        "docker_resource_id": "docker-current",
                        "lifecycle": "stopped",
                    }
                ],
                "databases": [],
            },
        }
        profile.call.return_value = (
            "00000000-0000-4000-8000-000000000001",
            {"status": "planned"},
        )
        args = argparse.Namespace(
            group="cleanup",
            action="plan",
            target_kind="container",
            target_id="docker-current",
            lifecycle_action="purge",
            reason="obsolete exact container",
        )

        result = lifecycle_cli_module._handle_broker_cleanup(args, profile=profile)

        self.assertEqual(result["status"], "planned")
        self.assertIs(
            profile.call.call_args.kwargs["repository"], repository_b
        )
        self.assertEqual(
            profile.call.call_args.kwargs["resource_id"], "docker-current"
        )
        profile.inventory.assert_called_once_with(
            canonical_root=repository_a.canonical_root
        )


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
        StoreBackedRequestAcceptor(persistence), SerializedMutationWriter(backend)
    )


class GenericLifecycleBrokerTests(unittest.TestCase):
    def test_direct_container_backend_uses_one_forced_rm_without_volume_flag(self) -> None:
        full_container_id = "a" * 64
        backend = DockerCleanupBackend()
        backend.executable = "/usr/bin/docker"
        response = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "-f", full_container_id],
            0,
            full_container_id + "\n",
            "",
        )
        with mock.patch(
            "devcoordinator.cleanup_lifecycle.subprocess.run",
            return_value=response,
        ) as run:
            result = backend.remove(full_container_id)

        self.assertFalse(result["already_absent"])
        self.assertEqual(
            result["docker_argv_contract"],
            ["docker", "rm", "-f", "<exact-full-container-id>"],
        )
        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/docker", "rm", "-f", full_container_id],
        )
        self.assertNotIn("-v", run.call_args.args[0])

    def test_direct_container_backend_treats_already_absent_as_success(self) -> None:
        full_container_id = "a" * 64
        backend = DockerCleanupBackend()
        backend.executable = "/usr/bin/docker"
        response = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "-f", full_container_id],
            1,
            "",
            "Error: No such container: " + full_container_id,
        )
        with mock.patch(
            "devcoordinator.cleanup_lifecycle.subprocess.run",
            return_value=response,
        ) as run:
            result = backend.remove(full_container_id)

        self.assertTrue(result["already_absent"])
        self.assertEqual(result["full_container_id"], full_container_id)
        run.assert_called_once()

    def test_direct_container_removal_rejects_unresolved_target_before_docker(
        self,
    ) -> None:
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, actions = fixtures.seed_store_backed_broker(root)
            remover = mock.Mock()
            backend = StoreBackedMutationBackend(
                persistence, actions, container_remover=remover
            )
            service = BrokerService(
                StoreBackedRequestAcceptor(persistence),
                SerializedMutationWriter(backend),
            )

            reply = service.reply_for_document(
                fixtures.peer_for(),
                fixtures.request_for(
                    BrokerOperation.CONTAINER_REMOVE,
                    resource_id="missing-container",
                    arguments={
                        "target_id": "missing-container",
                        "reason": "obsolete historical initializer",
                    },
                ).to_wire(),
            )

            self.assertFalse(reply["ok"], reply)
            self.assertEqual(reply["error"]["code"], "resource_unavailable")
            remover.assert_not_called()

    def test_exact_volume_backend_uses_only_volume_rm_and_verifies_absence(self) -> None:
        volume_name = "alpha_data"
        backend = DockerCleanupBackend()
        backend.executable = "/usr/bin/docker"
        responses = [
            subprocess.CompletedProcess(
                ["/usr/bin/docker", "volume", "rm", volume_name],
                0,
                volume_name + "\n",
                "",
            ),
            subprocess.CompletedProcess(
                ["/usr/bin/docker", "volume", "inspect", volume_name],
                1,
                "",
                "Error: No such volume: alpha_data",
            ),
        ]
        with mock.patch(
            "devcoordinator.cleanup_lifecycle.subprocess.run",
            side_effect=responses,
        ) as run:
            result = backend.remove_volume(volume_name)

        self.assertFalse(result["already_absent"])
        self.assertEqual(
            result["docker_argv_contract"],
            ["docker", "volume", "rm", "<exact-volume-name>"],
        )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["/usr/bin/docker", "volume", "rm", volume_name],
                ["/usr/bin/docker", "volume", "inspect", volume_name],
            ],
        )

    def test_exact_detached_compose_volume_plan_apply_and_replay(self) -> None:
        volume_name = "alpha_data"
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, _actions = fixtures.seed_store_backed_broker(root)
            now = utc_timestamp()
            snapshot_id = "00000000-0000-4000-8000-000000000501"
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO broker_compose_definitions(
                            compose_definition_id, repo_id, cwd, project_name,
                            definition_fingerprint, enabled, generation,
                            created_at, updated_at
                        ) VALUES ('compose-alpha', ?, '/repos/alpha', 'alpha',
                                  'compose-definition', 1, 0, ?, ?)
                        """,
                        (fixtures.PROJECT_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                                  'volume-material', ?, ?)
                        """,
                        (snapshot_id, fixtures.HOST_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES (?, 'host-runtime-v2:full-docker', 1,
                                  'volume-capability', ?)
                        """,
                        (snapshot_id, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observation_compose_scope(
                            snapshot_id, assets_complete, observed_asset_count,
                            evidence_fingerprint, recorded_at
                        ) VALUES (?, 1, 1, 'volume-scope', ?)
                        """,
                        (snapshot_id, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observed_compose_assets(
                            snapshot_id, asset_kind, asset_id, project_name,
                            working_dir, observation_fingerprint
                        ) VALUES (?, 'volume', ?, 'alpha', '/repos/alpha',
                                  'volume-observation')
                        """,
                        (snapshot_id, volume_name),
                    )

                authorized = persistence.accept(
                    fixtures.peer_for(),
                    fixtures.request_for(
                        BrokerOperation.CLEANUP_PLAN,
                        resource_id=volume_name,
                        arguments={
                            "action": "purge",
                            "target_kind": "volume",
                            "target_id": volume_name,
                            "reason": "retired exact Compose volume",
                        },
                    ),
                )
                self.assertEqual(authorized.request.resource_id, volume_name)

                docker = mock.Mock(spec=DockerCleanupBackend)
                exact_identity = {
                    "volume_name": volume_name,
                    "created_at": "2026-08-09T20:00:00Z",
                    "driver": "local",
                    "scope": "local",
                    "labels_fingerprint": "sha256:" + "1" * 64,
                    "options_fingerprint": "sha256:" + "2" * 64,
                    "compose_project": "alpha",
                    "compose_volume": "data",
                    "reference_count": 0,
                    "references_fingerprint": "sha256:" + "3" * 64,
                }
                docker.inspect_volume.return_value = exact_identity

                def remove_volume(_name: str):
                    docker.inspect_volume.return_value = None
                    return {
                        "already_absent": False,
                        "volume_name": volume_name,
                        "docker_argv_contract": [
                            "docker",
                            "volume",
                            "rm",
                            "<exact-volume-name>",
                        ],
                    }

                docker.remove_volume.side_effect = remove_volume
                lifecycle = CleanupLifecycle(store, docker_backend=docker)
                plan = lifecycle.plan(
                    target_kind="volume",
                    target_id=volume_name,
                    actor="fixture",
                    reason="retired exact Compose volume",
                )
                self.assertEqual(plan.repo_id, fixtures.PROJECT_ID)
                self.assertEqual(plan.blockers, ())
                self.assertEqual(plan.confirmation_phrase, "PURGE VOLUME alpha_data")

                applied = lifecycle.apply(
                    plan_id=plan.plan_id,
                    plan_fingerprint=plan.plan_fingerprint,
                    confirmation_phrase=plan.confirmation_phrase,
                    actor="fixture",
                )
                replayed = lifecycle.apply(
                    plan_id=plan.plan_id,
                    plan_fingerprint=plan.plan_fingerprint,
                    confirmation_phrase=plan.confirmation_phrase,
                    actor="fixture",
                )

                self.assertTrue(applied["ok"])
                self.assertTrue(replayed["ok"])
                docker.remove_volume.assert_called_once_with(volume_name)
                tombstone = store.connection.execute(
                    """
                    SELECT immutable_fingerprint FROM cleanup_tombstones
                    WHERE target_kind = 'volume' AND target_id = ?
                    """,
                    (volume_name,),
                ).fetchone()
                self.assertIsNotNone(tombstone)
                self.assertEqual(tombstone["immutable_fingerprint"], plan.target_fingerprint)
                self.assertFalse(
                    any(
                        item["target_kind"] == "volume"
                        for item in lifecycle.list_archives(actor="fixture")["archives"]
                    ),
                    "storage tombstones must not become interactive lifecycle controls",
                )

    def test_exact_compose_volume_revalidates_zero_references_before_apply(self) -> None:
        volume_name = "alpha_data"
        with fixtures.CanonicalTemporaryDirectory() as root:
            persistence, _actions = fixtures.seed_store_backed_broker(root)
            now = utc_timestamp()
            snapshot_id = "00000000-0000-4000-8000-000000000502"
            with CoordinatorStore.open(
                persistence.database_path, expected_uid=os.geteuid()
            ) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO broker_compose_definitions(
                            compose_definition_id, repo_id, cwd, project_name,
                            definition_fingerprint, enabled, generation,
                            created_at, updated_at
                        ) VALUES ('compose-alpha', ?, '/repos/alpha', 'alpha',
                                  'compose-definition', 1, 0, ?, ?)
                        """,
                        (fixtures.PROJECT_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES (?, ?, 'host-runtime-v2:full-docker', 'completed',
                                  'volume-material', ?, ?)
                        """,
                        (snapshot_id, fixtures.HOST_ID, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES (?, 'host-runtime-v2:full-docker', 1,
                                  'volume-capability', ?)
                        """,
                        (snapshot_id, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observation_compose_scope(
                            snapshot_id, assets_complete, observed_asset_count,
                            evidence_fingerprint, recorded_at
                        ) VALUES (?, 1, 1, 'volume-scope', ?)
                        """,
                        (snapshot_id, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO broker_observed_compose_assets(
                            snapshot_id, asset_kind, asset_id, project_name,
                            working_dir, observation_fingerprint
                        ) VALUES (?, 'volume', ?, 'alpha', '/repos/alpha',
                                  'volume-observation')
                        """,
                        (snapshot_id, volume_name),
                    )
                docker = mock.Mock(spec=DockerCleanupBackend)
                base = {
                    "volume_name": volume_name,
                    "created_at": "2026-08-09T20:00:00Z",
                    "driver": "local",
                    "scope": "local",
                    "labels_fingerprint": "sha256:" + "1" * 64,
                    "options_fingerprint": "sha256:" + "2" * 64,
                    "compose_project": "alpha",
                    "compose_volume": "data",
                    "reference_count": 0,
                    "references_fingerprint": "sha256:" + "3" * 64,
                }
                docker.inspect_volume.return_value = base
                lifecycle = CleanupLifecycle(store, docker_backend=docker)
                plan = lifecycle.plan(
                    target_kind="volume",
                    target_id=volume_name,
                    actor="fixture",
                    reason="retired exact Compose volume",
                )
                docker.inspect_volume.return_value = {
                    **base,
                    "reference_count": 1,
                    "references_fingerprint": "sha256:" + "4" * 64,
                }
                with self.assertRaisesRegex(Exception, "identity changed|reference"):
                    lifecycle.apply(
                        plan_id=plan.plan_id,
                        plan_fingerprint=plan.plan_fingerprint,
                        confirmation_phrase=plan.confirmation_phrase,
                        actor="fixture",
                    )
                docker.remove_volume.assert_not_called()

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
                authorized = AcceptedBrokerRequest(
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
                    "_resolve_generic_cleanup_resource",
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

class GenericLifecycleHttpTests(unittest.TestCase):
    def test_profile_expiry_is_informational_for_local_archive_reads(self) -> None:
        root = str(Path("/repos/expired").resolve())
        repository = BrokerRepositoryProfile(
            canonical_root=root,
            repo_id="repo-expired",
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
            compose_container_ids=frozenset(),
            compose_run_once_services={},
            ephemeral_templates={},
            ephemeral_secret_policies={},
        )
        other = BrokerRepositoryProfile(
            canonical_root=str(Path("/repos/other").resolve()),
            repo_id="repo-other",
            generation=1,
            server_ids={},
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
                database_generation="generation-expired",
            ),
            repositories={root: repository, other.canonical_root: other},
        )
        with mock.patch.object(
            dev_coordinator, "configured_broker_profile", return_value=profile
        ), mock.patch.object(
            BrokerClientProfile,
            "call",
            return_value=(
                "archive-read-operation",
                {
                    "archives": [
                        {
                            "target_kind": "project",
                            "target_id": other.repo_id,
                            "project_id": other.repo_id,
                            "archived_at": "2026-08-12T00:00:00Z",
                        }
                    ]
                },
            ),
        ) as broker_call:
            result = dev_coordinator.coordinated_list_archives()
        self.assertEqual(result["archives"][0]["target_id"], other.repo_id)
        broker_call.assert_called_once()


if __name__ == "__main__":
    unittest.main()
