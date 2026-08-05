"""Exact runtime-manifest ownership reconstruction regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_enrollment import (
    _collect_observed_containers,
    _declared_container_names,
    reconcile_enrolled_runtime_container_declarations,
)
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.observation_freshness import FULL_DOCKER_OBSERVER_DOMAIN
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.repository_lifecycle import ResourceKind
from devcoordinator.schema import establish_repository_owner_authority
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp


class RuntimeManifestContainerReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _container(
        full_id: str,
        name: str,
        *,
        databases: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        return {
            "id": full_id,
            "full_id": full_id,
            "name": name,
            "image": "postgres:17",
            "status": "Up 1 minute",
            "running": True,
            "inspection_observable": True,
            "restart_policy": "unless-stopped",
            "labels": {},
            "port_bindings": [],
            "project": None,
            "metadata_source": "docker_labels",
            "databases": databases or [],
        }

    def _observe(
        self,
        store: AccountStore,
        host_id: str,
        containers: list[dict[str, object]],
    ) -> str:
        sample = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {
                    "available": True,
                    "containers": containers,
                    "postgres": [],
                },
            },
        }
        outcome = SingleFlightObserver(store).observe(
            host_id=host_id,
            observer_domain=FULL_DOCKER_OBSERVER_DOMAIN,
            sampler=lambda: sample,
            commit=lambda connection, snapshot_id, observed: (
                commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    observed,
                    host_id=host_id,
                    coordinator_home=str(self.home),
                    effective_uid=os.geteuid(),
                )
            ),
        )
        return outcome.snapshot_id

    @staticmethod
    def _insert_repository(
        store: AccountStore,
        *,
        host_id: str,
        root: Path,
        created_at: str,
        declared_container: str,
    ) -> str:
        root.mkdir()
        (root / ".git").mkdir()
        manifest_dir = root / ".codex"
        manifest_dir.mkdir()
        (manifest_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "dependencies": [
                        {"type": "docker", "container": declared_container}
                    ]
                }
            ),
            encoding="utf-8",
        )
        repo_id = deterministic_id("repository", host_id, str(root))
        with store.immediate_transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    repo_id, host_id, canonical_root, display_name, state,
                    generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                """,
                (repo_id, host_id, str(root), root.name, created_at, created_at),
            )
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, actor, updated_at
                ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                """,
                (repo_id, created_at),
            )
            establish_repository_owner_authority(
                connection,
                repository_id=repo_id,
                owner_uid=1000,
                repository_generation=0,
                operation_id=f"owner-{repo_id}",
                actor="fixture",
                reason="runtime manifest reconciliation fixture",
                timestamp=created_at,
                evidence={"kind": "fixture", "repository_id": repo_id},
            )
        return repo_id

    @staticmethod
    def _generations(
        store: AccountStore, repo_id: str
    ) -> tuple[int, int]:
        with store.read_transaction() as connection:
            row = connection.execute(
                """
                SELECT repository.generation,
                       owner.repository_generation
                FROM repositories repository
                JOIN repository_owners owner USING(repo_id)
                WHERE repository.repo_id = ?
                """,
                (repo_id,),
            ).fetchone()
        if row is None:
            raise AssertionError("repository owner fixture disappeared")
        return int(row[0]), int(row[1])

    def test_docker_only_declaration_and_unreadable_manifest_are_bounded(self) -> None:
        runtime_file = self.root / "docker-only.json"
        runtime_file.write_text(
            json.dumps(
                {
                    "docker": {
                        "containers": [
                            {"type": "docker", "container": "aerodb-pg"}
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            _declared_container_names(
                runtime_file,
                candidates=frozenset({"aerodb-pg"}),
            ),
            ("aerodb-pg",),
        )
        with mock.patch.object(
            Path,
            "lstat",
            side_effect=PermissionError("fixture unreadable"),
        ):
            with self.assertRaisesRegex(ValueError, "metadata cannot be read"):
                _declared_container_names(
                    runtime_file,
                    candidates=frozenset({"aerodb-pg"}),
                )

    def test_shared_declaration_repairs_parent_and_all_database_children(self) -> None:
        aerodb_id = "a" * 64
        manual_id = "b" * 64
        databases = [
            {"name": f"tenant_{index:03d}", "size_bytes": index}
            for index in range(94)
        ]
        containers = [
            self._container(aerodb_id, "aerodb-pg", databases=databases),
            self._container(manual_id, "manual-pg"),
        ]

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            primary_repo_id = self._insert_repository(
                store,
                host_id=host_id,
                root=self.root / "XFoilFOAM",
                created_at="2026-07-01T00:00:00.000Z",
                declared_container="aerodb-pg",
            )
            shared_repo_id = self._insert_repository(
                store,
                host_id=host_id,
                root=self.root / "XFoilFOAM-cell-modal",
                created_at="2026-07-02T00:00:00.000Z",
                declared_container="aerodb-pg",
            )

            snapshot_id = self._observe(store, host_id, containers)
            self.assertEqual(self._generations(store, primary_repo_id), (0, 0))

            repaired = reconcile_enrolled_runtime_container_declarations(
                store,
                snapshot_id=snapshot_id,
            )
            self.assertEqual(repaired["changed"], 1)
            aerodb_repair = next(
                item
                for item in repaired["bindings"]
                if item["container"] == "aerodb-pg"
            )
            self.assertEqual(aerodb_repair["owner_repo_id"], primary_repo_id)
            self.assertEqual(
                [item["repo_id"] for item in aerodb_repair["shared_references"]],
                [shared_repo_id],
            )
            self.assertEqual(
                self._generations(store, primary_repo_id),
                (0, 0),
                "observation-derived adoption must not stale installed profiles",
            )

            final_snapshot_id = self._observe(store, host_id, containers)
            with store.read_transaction() as connection:
                aerodb_resource = connection.execute(
                    """
                    SELECT resource.docker_resource_id, binding.binding_id,
                           binding.repo_id, binding.provenance
                    FROM docker_resources resource
                    JOIN control_bindings binding
                      ON binding.resource_kind = 'container'
                     AND binding.resource_id = resource.docker_resource_id
                    WHERE resource.full_container_id = ?
                    """,
                    (aerodb_id,),
                ).fetchone()
                membership = connection.execute(
                    """
                    SELECT repo_id FROM repository_memberships
                    WHERE resource_kind = 'container' AND host_resource_id = ?
                    """,
                    (str(aerodb_resource["docker_resource_id"]),),
                ).fetchone()
                database_owners = list(
                    connection.execute(
                        """
                        SELECT repo_id FROM database_bindings
                        WHERE docker_resource_id = ?
                        """,
                        (str(aerodb_resource["docker_resource_id"]),),
                    )
                )
                active_problem_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM unassigned_resources
                        WHERE resource_id = ? AND status = 'active'
                        """,
                        (str(aerodb_resource["docker_resource_id"]),),
                    ).fetchone()[0]
                )

            self.assertEqual(membership["repo_id"], primary_repo_id)
            self.assertEqual(aerodb_resource["repo_id"], primary_repo_id)
            self.assertEqual(aerodb_resource["provenance"], "runtime_manifest")
            self.assertEqual(len(database_owners), 94)
            self.assertTrue(
                all(row["repo_id"] == primary_repo_id for row in database_owners)
            )
            self.assertEqual(active_problem_count, 0)

            persistence = BrokerPersistence(
                store.database_path,
                expected_uid=os.geteuid(),
            )
            persistence.provision_principal(
                uid=os.geteuid(),
                account_id="runtime-manifest-fixture",
            )
            (
                aliases,
                identity_grants,
                runtime_grants,
                resource_grants,
            ) = _collect_observed_containers(
                persistence,
                repo_id=primary_repo_id,
                client_uid=os.geteuid(),
                snapshot_id=final_snapshot_id,
            )
            aerodb_resource_id = str(aerodb_resource["docker_resource_id"])
            self.assertEqual(aliases["aerodb-pg"], aerodb_resource_id)
            self.assertEqual(aliases[aerodb_id], aerodb_resource_id)
            self.assertIn(
                (final_snapshot_id, aerodb_resource_id, aerodb_id, False),
                identity_grants,
                "standalone manifest ownership must not be mislabeled Compose evidence",
            )
            self.assertEqual(
                {
                    action
                    for kind, resource_id, action in runtime_grants
                    if kind == "docker" and resource_id == aerodb_resource_id
                },
                {"status", "start", "stop", "restart"},
            )
            self.assertEqual(
                {
                    operation
                    for kind, resource_id, operation in resource_grants
                    if kind == "container" and resource_id == aerodb_resource_id
                },
                {
                    BrokerOperation.DOCKER_START,
                    BrokerOperation.DOCKER_STOP,
                    BrokerOperation.DOCKER_RESTART,
                },
            )
            persistence.grant_observation_derived_access_batch(
                uid=os.geteuid(),
                repo_id=primary_repo_id,
                container_identity_grants=identity_grants,
                runtime_grants=runtime_grants,
                resource_grants=resource_grants,
            )
            with store.read_transaction() as connection:
                persisted_runtime_actions = {
                    str(row["action"])
                    for row in connection.execute(
                        """
                        SELECT action FROM broker_runtime_acl
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'docker' AND resource_id = ?
                          AND enabled = 1
                        """,
                        (os.geteuid(), primary_repo_id, aerodb_resource_id),
                    )
                }
                persisted_resource_operations = {
                    str(row["operation"])
                    for row in connection.execute(
                        """
                        SELECT operation FROM broker_resource_acl
                        WHERE uid = ? AND repo_id = ?
                          AND resource_kind = 'container' AND resource_id = ?
                          AND enabled = 1
                        """,
                        (os.geteuid(), primary_repo_id, aerodb_resource_id),
                    )
                }
            self.assertEqual(
                persisted_runtime_actions,
                {"status", "start", "stop", "restart"},
            )
            self.assertEqual(
                persisted_resource_operations,
                {
                    BrokerOperation.DOCKER_START.value,
                    BrokerOperation.DOCKER_STOP.value,
                    BrokerOperation.DOCKER_RESTART.value,
                },
            )
            self.assertEqual(
                reconcile_enrolled_runtime_container_declarations(
                    store,
                    snapshot_id=final_snapshot_id,
                )["changed"],
                0,
                "the confirming observation must make reconciliation idempotent",
            )

            with store.read_transaction() as read_connection:
                manual_resource = read_connection.execute(
                    """
                    SELECT resource.docker_resource_id, binding.binding_id
                    FROM docker_resources resource
                    JOIN control_bindings binding
                      ON binding.resource_kind = 'container'
                     AND binding.resource_id = resource.docker_resource_id
                    WHERE resource.full_container_id = ?
                    """,
                    (manual_id,),
                ).fetchone()
            if manual_resource is None:
                self.fail("manual attachment fixture disappeared")
            lifecycle = SQLiteLifecyclePersistence(store)
            exact = lifecycle.resolve_standalone_resource(
                ResourceKind.CONTAINER,
                str(manual_resource["docker_resource_id"]),
                str(manual_resource["binding_id"]),
            )
            lifecycle.attach_resource(
                primary_repo_id,
                exact,
                actor="fixture-operator",
                reason="verify explicit attachment generation semantics",
            )
            self.assertEqual(
                self._generations(store, primary_repo_id),
                (1, 1),
                "explicit operator attachment must advance repository and owner together",
            )

    def test_invalid_earliest_manifest_defers_later_shared_owner(self) -> None:
        full_id = "c" * 64
        containers = [self._container(full_id, "shared-pg")]

        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            primary_root = self.root / "Primary"
            primary_repo_id = self._insert_repository(
                store,
                host_id=host_id,
                root=primary_root,
                created_at="2026-07-01T00:00:00.000Z",
                declared_container="shared-pg",
            )
            later_repo_id = self._insert_repository(
                store,
                host_id=host_id,
                root=self.root / "LaterSharedReference",
                created_at="2026-07-02T00:00:00.000Z",
                declared_container="shared-pg",
            )
            primary_manifest = primary_root / ".codex/dev-runtime.json"
            primary_manifest.write_text("{", encoding="utf-8")

            snapshot_id = self._observe(store, host_id, containers)
            deferred = reconcile_enrolled_runtime_container_declarations(
                store,
                snapshot_id=snapshot_id,
            )
            self.assertEqual(deferred["changed"], 0)
            self.assertEqual(
                deferred["skipped"],
                "enrolled_runtime_manifest_invalid",
            )
            self.assertEqual(
                [item["repo_id"] for item in deferred["invalid_manifests"]],
                [primary_repo_id],
            )
            self.assertEqual(
                deferred["bindings"][0]["status"],
                "reconciliation_deferred_invalid_manifest",
            )
            with store.read_transaction() as connection:
                premature_owner = connection.execute(
                    """
                    SELECT membership.repo_id
                    FROM docker_resources resource
                    LEFT JOIN repository_memberships membership
                      ON membership.resource_kind = 'container'
                     AND membership.host_resource_id =
                         resource.docker_resource_id
                    WHERE resource.full_container_id = ?
                    """,
                    (full_id,),
                ).fetchone()
            self.assertIsNone(premature_owner["repo_id"])

            primary_manifest.write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {"type": "docker", "container": "shared-pg"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            repaired = reconcile_enrolled_runtime_container_declarations(
                store,
                snapshot_id=snapshot_id,
            )
            self.assertEqual(repaired["changed"], 1)
            binding = repaired["bindings"][0]
            self.assertEqual(binding["owner_repo_id"], primary_repo_id)
            self.assertEqual(
                [item["repo_id"] for item in binding["shared_references"]],
                [later_repo_id],
            )


if __name__ == "__main__":
    unittest.main()
