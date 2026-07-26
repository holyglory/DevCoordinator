"""Regressions for permanent revocation of non-worker server identities."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator import broker_backend as broker_backend_module  # noqa: E402
from devcoordinator.broker import AuthorizedBrokerRequest, BrokerOperation  # noqa: E402
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.cleanup_lifecycle import CleanupLifecycle  # noqa: E402
from devcoordinator.store import CoordinatorStore, fingerprint, utc_timestamp  # noqa: E402
from devcoordinator.tests.test_broker import (  # noqa: E402
    PROJECT_ID,
    SERVER_ID,
    CanonicalTemporaryDirectory,
    peer_for,
    request_for,
    seed_store_backed_broker,
)


class NonWorkerServerCleanupRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = CanonicalTemporaryDirectory()
        self.root = self.temporary.__enter__()
        self.persistence, self.actions = seed_store_backed_broker(self.root)
        self.backend = StoreBackedMutationBackend(self.persistence, self.actions)
        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE server_definitions SET role = 'web'
                    WHERE server_definition_id = ?
                    """,
                    (SERVER_ID,),
                )

    def tearDown(self) -> None:
        self.temporary.__exit__(None, None, None)

    def test_generic_purge_revokes_non_worker_service_and_profile_before_finalization(
        self,
    ) -> None:
        plan_id = str(uuid.uuid4())
        identity = {
            "resource_kind": "server",
            "resource_id": SERVER_ID,
            "control_binding_id": "server-control",
            "immutable_fingerprint": "sha256:" + "a" * 64,
            "ownership_fingerprint": "sha256:" + "b" * 64,
            "native_identity": {"server_definition_id": SERVER_ID},
            "running_state": "stopped",
            "listener_active": False,
        }
        target_fingerprint = "sha256:" + fingerprint(identity)
        plan_fingerprint = "sha256:" + "c" * 64
        confirmation = "PURGE SERVER web"
        snapshot = {
            "identity": identity,
            "repo_id": PROJECT_ID,
            "target": {
                "display_name": "web",
                "project_id": PROJECT_ID,
                "target_kind": "server",
            },
            "effects": ["retire_managed_server_from_active_projection"],
            "retained": ["cleanup_tombstone", "operation_evidence"],
            "deleted": ["active_server_projection"],
            "blockers": [],
        }
        now = utc_timestamp()
        calls: list[str] = []
        service_revocation = {
            "repo_id": PROJECT_ID,
            "server_definition_id": SERVER_ID,
            "server_name": "web",
            "cleanup_operation_id": plan_id,
            "immutable_fingerprint": target_fingerprint,
        }
        request = request_for(
            BrokerOperation.CLEANUP_APPLY,
            resource_id=PROJECT_ID,
            arguments={
                "plan_id": plan_id,
                "plan_fingerprint": plan_fingerprint,
                "confirmation_phrase": confirmation,
            },
        )
        authorized = AuthorizedBrokerRequest(peer=peer_for(), request=request)

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, owner_uid, actor, created_at, updated_at
                    ) VALUES (?, ?, 'cleanup:purge', 'planned', 'planned', 0,
                              ?, ?, 'fixture', ?, ?)
                    """,
                    (
                        plan_id,
                        PROJECT_ID,
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
                    ) VALUES (?, ?, 'server', ?, 'purge', ?, ?, ?, ?,
                              'planned', 'planned', 'fixture',
                              'permanent non-worker cleanup', ?, ?)
                    """,
                    (
                        plan_id,
                        PROJECT_ID,
                        SERVER_ID,
                        target_fingerprint,
                        plan_fingerprint,
                        confirmation,
                        json.dumps(snapshot, sort_keys=True),
                        now,
                        now,
                    ),
                )

            cleanup = CleanupLifecycle(
                store,
                authorize=lambda *_args: None,
                prepare_apply=lambda plan, actor: self.backend._prepare_worker_lifecycle_apply(
                    authorized,
                    store=store,
                    plan=plan,
                    actor=actor,
                ),
            )
            exact = SimpleNamespace(
                immutable_fingerprint=identity["immutable_fingerprint"],
                ownership_fingerprint=identity["ownership_fingerprint"],
            )
            with (
                mock.patch.object(
                    self.backend,
                    "_authorize_generic_cleanup_resource",
                    return_value=(exact, PROJECT_ID),
                ),
                mock.patch.object(
                    self.backend,
                    "_observe_fresh_full_docker",
                    return_value={"snapshot_id": "fresh-observation"},
                ),
                mock.patch.object(cleanup, "_snapshot", return_value=snapshot),
                mock.patch.object(
                    cleanup,
                    "_finalize_server",
                    side_effect=lambda *_args: calls.append("finalize"),
                ),
                mock.patch.object(
                    self.persistence,
                    "revoke_server_for_permanent_cleanup",
                    side_effect=lambda **_kwargs: calls.append("service")
                    or service_revocation,
                ) as revoke_service,
                mock.patch.object(
                    self.persistence,
                    "database_generation",
                    return_value="broker-generation",
                ),
                mock.patch.object(
                    broker_backend_module,
                    "configured_profile_path",
                    return_value=Path("/protected/broker-profile.json"),
                ),
                mock.patch.object(
                    broker_backend_module,
                    "revoke_server_from_protected_profile",
                    side_effect=lambda **_kwargs: calls.append("profile")
                    or {**service_revocation, "status": "revoked"},
                ) as revoke_profile,
            ):
                result = self.backend._apply_generic_lifecycle(
                    authorized,
                    store=store,
                    cleanup=cleanup,
                    actor="authenticated-cleanup-actor",
                )

        self.assertTrue(result["ok"])
        self.assertEqual(calls, ["service", "profile", "finalize"])
        revoke_service.assert_called_once_with(
            repo_id=PROJECT_ID,
            server_definition_id=SERVER_ID,
            cleanup_operation_id=plan_id,
            immutable_fingerprint=target_fingerprint,
            actor="authenticated-cleanup-actor",
        )
        revoke_profile.assert_called_once_with(
            profile_path=Path("/protected/broker-profile.json"),
            repo_id=PROJECT_ID,
            server_name="web",
            server_definition_id=SERVER_ID,
            cleanup_operation_id=plan_id,
            expected_database_generation="broker-generation",
        )

    def test_archive_of_non_worker_server_does_not_permanently_revoke_identity(
        self,
    ) -> None:
        plan = SimpleNamespace(
            action="archive",
            target_kind="server",
            target_id=SERVER_ID,
            repo_id=PROJECT_ID,
            plan_id=str(uuid.uuid4()),
        )
        authorized = SimpleNamespace(peer=SimpleNamespace(uid=os.geteuid()))

        with CoordinatorStore.open(
            self.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with (
                mock.patch.object(
                    self.persistence,
                    "revoke_server_for_permanent_cleanup",
                ) as revoke_service,
                mock.patch.object(
                    broker_backend_module,
                    "revoke_server_from_protected_profile",
                ) as revoke_profile,
            ):
                self.backend._prepare_worker_lifecycle_apply(
                    authorized,
                    store=store,
                    plan=plan,
                    actor="authenticated-archive-actor",
                )

        revoke_service.assert_not_called()
        revoke_profile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
