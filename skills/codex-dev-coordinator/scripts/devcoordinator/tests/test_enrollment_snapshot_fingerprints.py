"""Enrollment snapshot scoping and schema-v4 fingerprint regressions."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from devcoordinator.broker import BrokerOperation
from devcoordinator.broker_enrollment import (
    _disable_observed_resource_grants,
    _grant_observed_cleanup_resources,
    _grant_observed_containers,
    _grant_observed_databases,
    _grant_observed_lifecycle_resources,
    _require_enrollment_snapshot,
)
from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.repository_lifecycle import ResourceKind
from devcoordinator.schema import SCHEMA_VERSION
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import AccountStore, deterministic_id, fingerprint, utc_timestamp


HOST_ID = "enrollment-host"
REPO_ID = "enrollment-repository"
SOURCE_ID = "enrollment-source"
ENGINE_ID = "enrollment-engine"
FULL_DOCKER_DOMAIN = "host-runtime-v2:full-docker"


def _private_test_root() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(
        prefix="devcoordinator-enrollment-fingerprints-",
        dir=Path.home().resolve(strict=True),
    )


class ObservationFingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = _private_test_root()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.home = self.root / "store"
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / ".git").mkdir()
        self.full_id = "a" * 64
        with AccountStore.open_default(self.home) as store:
            now = utc_timestamp()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'enrollment-machine', 'test', 'test', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _observe(self) -> str:
        sample = {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {
                    "available": True,
                    "containers": [
                        {
                            "id": self.full_id,
                            "full_id": self.full_id,
                            "name": "current-container",
                            "image": "example.invalid/current:test",
                            "status": "Up 1 minute",
                            "running": True,
                            "project": str(self.repository),
                            "metadata_source": "compose_label",
                            "inspection_observable": True,
                            "container_health": "healthy",
                            "restart_policy": "always",
                            "labels": {},
                            "port_bindings": [],
                            "databases": [],
                        }
                    ],
                    "postgres": [],
                },
            },
        }
        with AccountStore.open_default(self.home) as store:
            outcome = SingleFlightObserver(store).observe(
                host_id=HOST_ID,
                observer_domain=FULL_DOCKER_DOMAIN,
                sampler=lambda: sample,
                commit=lambda connection, snapshot_id, measured: (
                    commit_host_inventory_observation(
                        connection,
                        snapshot_id,
                        measured,
                        host_id=HOST_ID,
                        coordinator_home=str(self.home),
                    )
                ),
            )
        return outcome.snapshot_id

    def test_repeat_observation_emits_tagged_identities_and_refreshes_policy(self) -> None:
        first_snapshot = self._observe()
        engine_id = deterministic_id("docker-engine", HOST_ID, "default")
        resource_id = deterministic_id("docker-resource", engine_id, self.full_id)
        expected_membership = "sha256:" + fingerprint(
            {"engine_id": engine_id, "container_id": self.full_id}
        )
        expected_policy = "sha256:" + fingerprint(
            {
                "engine_id": engine_id,
                "full_container_id": self.full_id,
                "policy_kind": "docker_restart",
            }
        )
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                first = connection.execute(
                    """
                    SELECT m.immutable_fingerprint AS membership_fingerprint,
                           p.immutable_fingerprint AS policy_fingerprint,
                           p.generation
                    FROM repository_memberships m
                    JOIN startup_policies p
                      ON p.resource_kind = m.resource_kind
                     AND p.resource_id = m.host_resource_id
                    WHERE m.host_resource_id = ?
                    """,
                    (resource_id,),
                ).fetchone()
                self.assertIsNotNone(first)
                self.assertEqual(first["membership_fingerprint"], expected_membership)
                self.assertEqual(first["policy_fingerprint"], expected_policy)
                connection.execute(
                    """
                    UPDATE startup_policies
                    SET immutable_fingerprint = ?, generation = generation + 1
                    WHERE resource_id = ?
                    """,
                    ("sha256:" + "f" * 64, resource_id),
                )
                drifted_generation = int(first["generation"]) + 1

        second_snapshot = self._observe()

        self.assertNotEqual(first_snapshot, second_snapshot)
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                repeated = connection.execute(
                    """
                    SELECT m.immutable_fingerprint AS membership_fingerprint,
                           p.immutable_fingerprint AS policy_fingerprint,
                           p.generation
                    FROM repository_memberships m
                    JOIN startup_policies p
                      ON p.resource_kind = m.resource_kind
                     AND p.resource_id = m.host_resource_id
                    WHERE m.host_resource_id = ?
                    """,
                    (resource_id,),
                ).fetchone()
        self.assertIsNotNone(repeated)
        self.assertEqual(repeated["membership_fingerprint"], expected_membership)
        self.assertEqual(repeated["policy_fingerprint"], expected_policy)
        self.assertEqual(int(repeated["generation"]), drifted_generation + 1)


class SchemaV4FingerprintMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = _private_test_root()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.home = self.root / "store"
        self.database = self.home / "coordinator.sqlite3"
        self.membership_digest = "1" * 64
        self.policy_digest = "2" * 64
        self._seed_current_store()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_current_store(self) -> None:
        now = utc_timestamp()
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'schema-machine', 'test', 'test', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, '/schema/repository', 'schema', 'active',
                              0, ?, ?)
                    """,
                    (REPO_ID, HOST_ID, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (REPO_ID, now),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, created_at, updated_at
                    ) VALUES (?, ?, '/schema/source', '/schema/source/state', ?,
                              'imported', ?, ?)
                    """,
                    (SOURCE_ID, HOST_ID, os.geteuid(), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO control_bindings(
                        binding_id, repo_id, resource_kind, resource_id,
                        source_id, capability, provenance, authority_state,
                        priority, generation, created_at, updated_at
                    ) VALUES ('schema-binding', ?, 'container',
                              'schema-container', ?, 'lifecycle', 'test',
                              'authoritative', 100, 0, ?, ?)
                    """,
                    (REPO_ID, SOURCE_ID, now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_memberships(
                        membership_id, repo_id, resource_kind, host_resource_id,
                        immutable_fingerprint, control_binding_id, created_at
                    ) VALUES ('schema-membership', ?, 'container',
                              'schema-container', ?, 'schema-binding', ?)
                    """,
                    (REPO_ID, "sha256:" + self.membership_digest, now),
                )
                connection.execute(
                    """
                    INSERT INTO startup_policies(
                        policy_id, repo_id, resource_kind, resource_id,
                        policy_kind, current_value, desired_disabled_value,
                        immutable_fingerprint, generation, updated_at
                    ) VALUES ('schema-policy', ?, 'container',
                              'schema-container', 'docker_restart', 'always',
                              'no', ?, 0, ?)
                    """,
                    (REPO_ID, "sha256:" + self.policy_digest, now),
                )

    def _downgrade_v3(self, *, policy_fingerprint: str) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                "UPDATE repository_memberships SET immutable_fingerprint = ?",
                (self.membership_digest,),
            )
            connection.execute(
                "UPDATE startup_policies SET immutable_fingerprint = ?",
                (policy_fingerprint,),
            )
            connection.execute(
                "UPDATE schema_metadata SET schema_version = 3 WHERE singleton = 1"
            )

    def test_v3_store_atomically_prefixes_exact_bare_digests(self) -> None:
        self._downgrade_v3(policy_fingerprint=self.policy_digest)

        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                values = connection.execute(
                    """
                    SELECT
                      (SELECT immutable_fingerprint FROM repository_memberships),
                      (SELECT immutable_fingerprint FROM startup_policies),
                      (SELECT schema_version FROM schema_metadata WHERE singleton = 1)
                    """
                ).fetchone()

        self.assertEqual(values[0], "sha256:" + self.membership_digest)
        self.assertEqual(values[1], "sha256:" + self.policy_digest)
        self.assertEqual(int(values[2]), SCHEMA_VERSION)

    def test_v3_malformed_leftover_rolls_back_every_conversion(self) -> None:
        self._downgrade_v3(policy_fingerprint="sha256:" + "A" * 64)

        with self.assertRaisesRegex(RuntimeError, "rejected malformed"):
            AccountStore.open_default(self.home)

        with sqlite3.connect(self.database) as connection:
            values = connection.execute(
                """
                SELECT
                  (SELECT immutable_fingerprint FROM repository_memberships),
                  (SELECT immutable_fingerprint FROM startup_policies),
                  (SELECT schema_version FROM schema_metadata WHERE singleton = 1)
                """
            ).fetchone()
        self.assertEqual(values[0], self.membership_digest)
        self.assertEqual(values[1], "sha256:" + "A" * 64)
        self.assertEqual(int(values[2]), 3)


class EnrollmentSnapshotScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = _private_test_root()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.home = self.root / "store"
        self.database = self.home / "coordinator.sqlite3"
        self.uid = os.geteuid()
        self.resources = {
            "historical": ("historical-container", "a" * 64),
            "current": ("current-container", "b" * 64),
            "historical-orphan": ("historical-orphan", "c" * 64),
            "current-orphan": ("current-orphan", "d" * 64),
        }
        self._seed_observations()
        self.persistence = BrokerPersistence(
            self.database, expected_uid=self.uid
        )
        self.persistence.provision_principal(
            uid=self.uid, account_id="enrollment-account"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_observations(self) -> None:
        old_time = "2026-07-18T01:00:00Z"
        new_time = "2026-07-18T02:00:00Z"
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(
                        host_id, machine_fingerprint, platform, hostname,
                        created_at, updated_at
                    ) VALUES (?, 'scope-machine', 'test', 'test', ?, ?)
                    """,
                    (HOST_ID, old_time, new_time),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, '/scope/repository', 'scope', 'active', 0, ?, ?)
                    """,
                    (REPO_ID, HOST_ID, old_time, new_time),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (?, 'installed', 0, 0, 'test', ?)
                    """,
                    (REPO_ID, new_time),
                )
                connection.execute(
                    """
                    INSERT INTO coordinator_sources(
                        source_id, host_id, canonical_home, state_path,
                        effective_uid, status, created_at, updated_at
                    ) VALUES (?, ?, '/scope/source', '/scope/source/state', ?,
                              'imported', ?, ?)
                    """,
                    (SOURCE_ID, HOST_ID, self.uid, old_time, new_time),
                )
                connection.execute(
                    """
                    INSERT INTO docker_engines(
                        engine_id, host_id, context_identity, capability_state,
                        created_at, updated_at
                    ) VALUES (?, ?, 'default', 'available', ?, ?)
                    """,
                    (ENGINE_ID, HOST_ID, old_time, new_time),
                )
                for key, (name, full_id) in self.resources.items():
                    resource_id = self._resource_id(key)
                    repo_id = None if key.endswith("orphan") else REPO_ID
                    binding_id = self._binding_id(key)
                    connection.execute(
                        """
                        INSERT INTO docker_resources(
                            docker_resource_id, engine_id, full_container_id,
                            current_name, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (resource_id, ENGINE_ID, full_id, name, old_time, new_time),
                    )
                    connection.execute(
                        """
                        INSERT INTO docker_observations(
                            docker_resource_id, lifecycle, restart_policy,
                            sampled_at, observation_fingerprint
                        ) VALUES (?, 'running', 'always', ?, ?)
                        """,
                        (resource_id, new_time, "observed-" + key),
                    )
                    connection.execute(
                        """
                        INSERT INTO control_bindings(
                            binding_id, repo_id, resource_kind, resource_id,
                            source_id, capability, provenance, authority_state,
                            priority, generation, created_at, updated_at
                        ) VALUES (?, ?, 'container', ?, ?, 'lifecycle', 'test',
                                  'authoritative', 100, 0, ?, ?)
                        """,
                        (
                            binding_id,
                            repo_id,
                            resource_id,
                            SOURCE_ID,
                            old_time,
                            new_time,
                        ),
                    )
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
                            "policy-" + key,
                            repo_id,
                            resource_id,
                            "sha256:" + fingerprint({"policy": key}),
                            new_time,
                        ),
                    )
                    if repo_id is None:
                        connection.execute(
                            """
                            INSERT INTO unassigned_resources(
                                unassigned_id, host_id, resource_kind,
                                resource_id, display_name, reason_code, status,
                                created_at, updated_at
                            ) VALUES (?, ?, 'container', ?, ?, 'name_only',
                                      'active', ?, ?)
                            """,
                            (
                                "unassigned-" + key,
                                HOST_ID,
                                resource_id,
                                name,
                                old_time,
                                new_time,
                            ),
                        )
                    else:
                        connection.execute(
                            """
                            INSERT INTO repository_memberships(
                                membership_id, repo_id, resource_kind,
                                host_resource_id, immutable_fingerprint,
                                control_binding_id, created_at
                            ) VALUES (?, ?, 'container', ?, ?, ?, ?)
                            """,
                            (
                                "membership-" + key,
                                REPO_ID,
                                resource_id,
                                "sha256:" + fingerprint({"membership": key}),
                                binding_id,
                                old_time,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO database_bindings(
                                database_binding_id, docker_resource_id,
                                repo_id, database_name, engine_kind,
                                created_at, updated_at
                            ) VALUES (?, ?, ?, ?, 'postgresql', ?, ?)
                            """,
                            (
                                "database-" + key,
                                resource_id,
                                REPO_ID,
                                key + "-db",
                                old_time,
                                new_time,
                            ),
                        )
                for snapshot_id, completed_at, keys in (
                    ("historical-snapshot", old_time, ("historical", "historical-orphan")),
                    ("current-snapshot", new_time, ("current", "current-orphan")),
                ):
                    connection.execute(
                        """
                        INSERT INTO observation_snapshots(
                            snapshot_id, host_id, observer_domain, status,
                            material_fingerprint, started_at, completed_at
                        ) VALUES (?, ?, ?, 'completed', ?, ?, ?)
                        """,
                        (
                            snapshot_id,
                            HOST_ID,
                            FULL_DOCKER_DOMAIN,
                            self._material(snapshot_id),
                            completed_at,
                            completed_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO observation_capabilities(
                            snapshot_id, observer_domain, docker_available,
                            capability_fingerprint, committed_at
                        ) VALUES (?, ?, 1, ?, ?)
                        """,
                        (
                            snapshot_id,
                            FULL_DOCKER_DOMAIN,
                            self._capability(snapshot_id),
                            completed_at,
                        ),
                    )
                    for key in keys:
                        connection.execute(
                            """
                            INSERT INTO observation_snapshot_resources(
                                snapshot_id, resource_kind, resource_id,
                                observation_fingerprint
                            ) VALUES (?, 'container', ?, ?)
                            """,
                            (snapshot_id, self._resource_id(key), "snapshot-" + key),
                        )

    def _resource_id(self, key: str) -> str:
        return "resource-" + key

    def _binding_id(self, key: str) -> str:
        return "binding-" + key

    @staticmethod
    def _material(snapshot_id: str) -> str:
        return fingerprint({"material": snapshot_id})

    @staticmethod
    def _capability(snapshot_id: str) -> str:
        return "sha256:" + fingerprint({"capability": snapshot_id})

    def _evidence(self, snapshot_id: str, completed_at: str) -> dict[str, object]:
        return {
            "snapshot_id": snapshot_id,
            "host_id": HOST_ID,
            "observer_domain": FULL_DOCKER_DOMAIN,
            "docker_available": True,
            "material_fingerprint": self._material(snapshot_id),
            "capability_fingerprint": self._capability(snapshot_id),
            "completed_at": completed_at,
        }

    def _seed_stale_grants(self) -> None:
        self.persistence.grant_resource(
            uid=self.uid,
            repo_id=REPO_ID,
            resource_kind="container",
            resource_id=self._resource_id("historical"),
            operation=BrokerOperation.DOCKER_STOP,
        )
        self.persistence.grant_database(
            uid=self.uid,
            repo_id=REPO_ID,
            database_binding_id="database-historical",
            operation=BrokerOperation.DATABASE_BACKUP,
        )
        with AccountStore.open_default(self.home) as store:
            lifecycle = SQLiteLifecyclePersistence(store)
            historical = next(
                target
                for target in lifecycle.repository_snapshot(REPO_ID).targets
                if target.resource_id == self._resource_id("historical")
            )
            orphan = lifecycle.resolve_standalone_resource(
                ResourceKind.CONTAINER,
                self._resource_id("historical-orphan"),
                self._binding_id("historical-orphan"),
            )
        self.persistence.grant_cleanup_resource(
            uid=self.uid,
            repo_id=REPO_ID,
            resource_kind=historical.kind.value,
            resource_id=historical.resource_id,
            control_binding_id=historical.control_binding_id,
            immutable_fingerprint=historical.immutable_fingerprint,
            ownership_fingerprint=historical.ownership_fingerprint,
            operation=BrokerOperation.RESOURCE_ARCHIVE,
        )
        self.persistence.grant_lifecycle_resource(
            uid=self.uid,
            repo_id=REPO_ID,
            resource_kind=orphan.kind.value,
            resource_id=orphan.resource_id,
            control_binding_id=orphan.control_binding_id,
            immutable_fingerprint=orphan.immutable_fingerprint,
            ownership_fingerprint=orphan.ownership_fingerprint,
            operation=BrokerOperation.RESOURCE_ATTACH,
        )

    def test_enrollment_uses_only_returned_latest_snapshot_and_revokes_history(self) -> None:
        with AccountStore.open_default(self.home) as store:
            with self.assertRaisesRegex(RuntimeError, "not the latest"):
                _require_enrollment_snapshot(
                    store,
                    observation=self._evidence(
                        "historical-snapshot", "2026-07-18T01:00:00Z"
                    ),
                    host_id=HOST_ID,
                )
            snapshot_id = _require_enrollment_snapshot(
                store,
                observation=self._evidence(
                    "current-snapshot", "2026-07-18T02:00:00Z"
                ),
                host_id=HOST_ID,
            )
        self.assertEqual(snapshot_id, "current-snapshot")
        self._seed_stale_grants()

        _disable_observed_resource_grants(
            self.persistence, repo_id=REPO_ID, client_uid=self.uid
        )
        aliases = _grant_observed_containers(
            self.persistence,
            repo_id=REPO_ID,
            client_uid=self.uid,
            snapshot_id=snapshot_id,
        )
        _grant_observed_databases(
            self.persistence,
            repo_id=REPO_ID,
            client_uid=self.uid,
            snapshot_id=snapshot_id,
        )
        _grant_observed_lifecycle_resources(
            self.persistence,
            repo_id=REPO_ID,
            client_uid=self.uid,
            snapshot_id=snapshot_id,
        )
        _grant_observed_cleanup_resources(
            self.persistence,
            repo_id=REPO_ID,
            client_uid=self.uid,
            snapshot_id=snapshot_id,
        )

        current_name, current_full_id = self.resources["current"]
        self.assertEqual(
            aliases,
            {
                current_name: self._resource_id("current"),
                current_full_id: self._resource_id("current"),
            },
        )
        with AccountStore.open_default(self.home) as store:
            with store.read_transaction() as connection:
                active_containers = {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT DISTINCT resource_id FROM broker_resource_acl
                        WHERE uid = ? AND repo_id = ? AND enabled = 1
                          AND resource_kind = 'container'
                        """,
                        (self.uid, REPO_ID),
                    )
                }
                active_databases = {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT DISTINCT database_binding_id
                        FROM broker_database_acl
                        WHERE uid = ? AND repo_id = ? AND enabled = 1
                        """,
                        (self.uid, REPO_ID),
                    )
                }
                active_lifecycle = {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT DISTINCT resource_id
                        FROM broker_lifecycle_resource_acl
                        WHERE uid = ? AND repo_id = ? AND enabled = 1
                        """,
                        (self.uid, REPO_ID),
                    )
                }
                active_cleanup = {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT DISTINCT resource_id
                        FROM broker_cleanup_resource_acl
                        WHERE uid = ? AND repo_id = ? AND enabled = 1
                        """,
                        (self.uid, REPO_ID),
                    )
                }
        self.assertEqual(active_containers, {self._resource_id("current")})
        self.assertEqual(active_databases, {"database-current"})
        self.assertEqual(
            active_lifecycle, {self._resource_id("current-orphan")}
        )
        self.assertEqual(active_cleanup, {self._resource_id("current")})


if __name__ == "__main__":
    unittest.main()
