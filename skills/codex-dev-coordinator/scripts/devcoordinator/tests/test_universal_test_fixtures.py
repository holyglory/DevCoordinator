from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
import stat
import unittest

from devcoordinator.broker import BrokerBackendError, BrokerError
from devcoordinator.ephemeral_secrets import (
    POSTGRES_INITDB_PASSWORD_FILE_V1,
    VolatileRunSecretManager,
)
from devcoordinator.universal_test_fixtures import BrokerSealedFixtureProvider
from devcoordinator.universal_test_runtime import (
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from devcoordinator.universal_test_store import TestStoreConflict
from devcoordinator.store import CoordinatorStore, utc_timestamp
from devcoordinator.tests.test_ephemeral_containers import (
    EphemeralFixture,
    IMAGE,
    MultiEphemeralHost,
    TEMPLATE,
)


class FixtureHost(MultiEphemeralHost):
    def docker_test_fixture_namespace(self, target):
        container = self.containers[target.identity.run_id]
        self.assert_target = target
        path = Path(f"/proc/{os.getpid()}/ns/net")
        metadata = path.stat()
        process_stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
        fields = process_stat[process_stat.rfind(")") + 2 :].split()
        return {
            "full_container_id": container["full_container_id"],
            "pid": os.getpid(),
            "process_identity": f"linux:{os.getpid()}:{fields[19]}",
            "namespace_path": str(path),
            "namespace_device": metadata.st_dev,
            "namespace_inode": metadata.st_ino,
        }


class UniversalTestFixtureProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = EphemeralFixture()
        self.addCleanup(self.fixture.close)
        self.host = FixtureHost()
        self.secret_manager = VolatileRunSecretManager(
            runtime_root=self.fixture.root / "secrets",
            expected_uid=os.geteuid(),
            password_factory=lambda: b"fixture-password-never-in-json-1234567890",
        )
        self.state_root = self.fixture.root / "test-fixtures"
        self.credential_root = self.fixture.root / "test-credentials"

    def provider(self) -> BrokerSealedFixtureProvider:
        return BrokerSealedFixtureProvider(
            self.fixture.persistence,
            self.host,
            secret_manager=self.secret_manager,
            state_root=self.state_root,
            credential_root=self.credential_root,
        )

    def descriptor(self) -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            attempt_id="attempt-sealed-fixture",
            target_id="target-sealed-fixture",
            run_id="run-sealed-fixture",
            repository_id="repo-ephemeral",
            repository_generation=0,
            owner_uid=os.geteuid(),
            generation=1,
            source_mode="live",
            snapshot_id=None,
            original_root=str(self.fixture.root),
            temporary_root=None,
            execution_root=str(self.fixture.root),
            worktree_key=str(self.fixture.root),
            target_name="integration",
            shard_index=0,
            shard_count=1,
            argv=("/usr/bin/python3", "-c", "pass"),
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=("postgres",),
            fixture_bindings=(
                {
                    "name": "postgres",
                    "template": "artifact-postgres",
                    "network": "loopback",
                },
            ),
            network="loopback",
            ttl_seconds=300,
        )

    def test_sealed_fixture_lease_recovers_and_cleanup_is_exact(self) -> None:
        provider = self.provider()
        descriptor = self.descriptor()
        runtime_id = "devcoordinator-test-" + "1" * 32
        lease = provider.provision(descriptor, runtime_id=runtime_id)
        self.assertEqual(lease.environment, {})
        self.assertEqual(lease.fixtures, ("postgres",))
        self.assertIsNotNone(lease.network_namespace)
        self.assertEqual(
            {item["name"] for item in lease.credential_files},
            {"fixtures.json", "fixture-provenance.json"},
        )
        journal = self.state_root / f"{runtime_id}.json"
        self.assertNotIn("fixture-password", journal.read_text(encoding="utf-8"))

        restarted = self.provider()
        recovered = restarted.recover(runtime_id=runtime_id)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.descriptor_fingerprint, lease.descriptor_fingerprint)
        with self.assertRaisesRegex(TestStoreConflict, "stale"):
            restarted.cleanup(
                runtime_id=runtime_id,
                descriptor_fingerprint="0" * 64,
                reason="forged",
            )
        restarted.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )
        self.assertEqual(self.host.containers, {})
        self.assertFalse((self.credential_root / runtime_id).exists())
        restarted.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="idempotent",
        )

    def test_fixture_launch_prefetches_an_uncached_exact_sealed_image(self) -> None:
        class ColdFixtureHost(FixtureHost):
            def __init__(self) -> None:
                super().__init__()
                self.image_cached = False
                self.image_prefetches = []

            def docker_inspect_ephemeral_image(self, target):
                self.image_cache_checks.append(target)
                if not self.image_cached:
                    return {"cached": False, "image_ref": target.image_ref}
                return super().docker_inspect_ephemeral_image(target)

            def docker_prefetch_ephemeral_image(self, target):
                self.image_prefetches.append(target)
                self.image_cached = True
                return {
                    **self.docker_inspect_ephemeral_image(target),
                    "cache_origin": "pulled",
                    "changed": True,
                }

        self.host = ColdFixtureHost()
        provider = self.provider()
        runtime_id = "devcoordinator-test-" + "9" * 32

        lease = provider.provision(self.descriptor(), runtime_id=runtime_id)

        self.assertEqual(len(self.host.image_prefetches), 1)
        self.assertEqual(self.host.image_prefetches[0].template_id, TEMPLATE)
        self.assertEqual(self.host.image_prefetches[0].image_ref, IMAGE)
        self.assertEqual(lease.fixtures, ("postgres",))
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )

    def test_fixture_launch_rejects_mismatched_prefetch_evidence(self) -> None:
        class MismatchedPrefetchHost(FixtureHost):
            def docker_inspect_ephemeral_image(self, target):
                return {"cached": False, "image_ref": target.image_ref}

            def docker_prefetch_ephemeral_image(self, target):
                return {
                    "cached": True,
                    "image_ref": target.image_ref,
                    "image_id": "sha256:" + "c" * 64,
                    "repo_digest": "postgres@sha256:" + "d" * 64,
                    "os": "linux",
                    "architecture": "amd64",
                }

        self.host = MismatchedPrefetchHost()
        provider = self.provider()

        with self.assertRaisesRegex(TestStoreConflict, "exact sealed image"):
            provider.provision(
                self.descriptor(), runtime_id="devcoordinator-test-" + "8" * 32
            )

    def test_fixture_recovers_unknown_create_from_exact_labels(self) -> None:
        class UnknownReplyHost(FixtureHost):
            def __init__(self) -> None:
                super().__init__()
                self.create_calls = 0

            def docker_create_ephemeral(self, target):
                self.create_calls += 1
                super().docker_create_ephemeral(target)
                raise BrokerBackendError(
                    "ephemeral_docker_create_outcome_unknown",
                    "injected lost create reply",
                )

        self.host = UnknownReplyHost()
        provider = self.provider()
        runtime_id = "devcoordinator-test-" + "7" * 32

        lease = provider.provision(self.descriptor(), runtime_id=runtime_id)

        self.assertEqual(self.host.create_calls, 1)
        self.assertEqual(lease.fixtures, ("postgres",))
        journal = json.loads(
            (self.state_root / f"{runtime_id}.json").read_text(encoding="utf-8")
        )
        self.assertRegex(journal["fixtures"][0]["full_container_id"], r"^[0-9a-f]{64}$")
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )
        self.assertEqual(self.host.containers, {})

    def test_sealed_fixture_template_is_available_to_another_repository(self) -> None:
        consumer_root = self.fixture.root / "consumer"
        consumer_root.mkdir()
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'repo-consumer', 'host-ephemeral', ?, 'Consumer',
                        'active', 0, ?, ?
                    )
                    """,
                    (str(consumer_root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (
                        'repo-consumer', 'installed', 0, 0, 'fixture', ?
                    )
                    """,
                    (now,),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'repo-template-copy', 'host-ephemeral', ?, 'Template copy',
                        'active', 0, ?, ?
                    )
                    """,
                    (str(self.fixture.root / "template-copy"), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (
                        'repo-template-copy', 'installed', 0, 0, 'fixture', ?
                    )
                    """,
                    (now,),
                )
        self.fixture.persistence.provision_ephemeral_template(
            template_id="ephemeral-template-copy-postgres",
            repo_id="repo-template-copy",
            name="artifact-postgres",
            image_ref="postgres@sha256:" + "b" * 64,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
            default_ttl_seconds=1200,
            max_ttl_seconds=7200,
            container_tcp_port=5432,
            host_port_start=56000,
            host_port_end=56020,
            memory_bytes=512 * 1024 * 1024,
            cpu_millis=1500,
            max_concurrent_runs=9,
            max_concurrent_runs_per_uid=7,
            repo_max_active_runs=11,
            repo_memory_budget_bytes=12 * 1024 * 1024 * 1024,
            repo_cpu_budget_millis=24_000,
        )
        descriptor = replace(
            self.descriptor(),
            repository_id="repo-consumer",
            original_root=str(consumer_root),
            execution_root=str(consumer_root),
            worktree_key=str(consumer_root),
        )
        runtime_id = "devcoordinator-test-" + "5" * 32
        provider = self.provider()

        lease = provider.provision(descriptor, runtime_id=runtime_id)

        self.assertEqual(lease.fixtures, ("postgres",))
        self.assertEqual(lease.provenance[0]["template_id"], TEMPLATE)
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )
        self.assertEqual(self.host.containers, {})
        self.assertFalse((self.credential_root / runtime_id).exists())

    def test_equivalent_noncanonical_legacy_templates_ignore_quota_metadata(self) -> None:
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                for repo_id in (
                    "repo-legacy-a",
                    "repo-legacy-b",
                    "repo-legacy-consumer",
                ):
                    root = self.fixture.root / repo_id
                    root.mkdir()
                    connection.execute(
                        """
                        INSERT INTO repositories(
                            repo_id, host_id, canonical_root, display_name,
                            state, generation, created_at, updated_at
                        ) VALUES (?, 'host-ephemeral', ?, ?, 'active', 0, ?, ?)
                        """,
                        (repo_id, str(root), repo_id, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO repository_installations(
                            repo_id, status, startup_fenced, generation,
                            actor, updated_at
                        ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                        """,
                        (repo_id, now),
                    )
        for suffix, default_ttl, maximum_ttl, memory, cpu in (
            ("a", 300, 1800, 128 * 1024 * 1024, 500),
            ("b", 1200, 7200, 512 * 1024 * 1024, 1500),
        ):
            self.fixture.persistence.provision_ephemeral_template(
                template_id=f"legacy-template-{suffix}",
                repo_id=f"repo-legacy-{suffix}",
                name="legacy-postgres",
                image_ref=IMAGE,
                command=("postgres", "-c", "fsync=off"),
                environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
                default_ttl_seconds=default_ttl,
                max_ttl_seconds=maximum_ttl,
                container_tcp_port=5432,
                host_port_start=56100 if suffix == "a" else 56200,
                host_port_end=56110 if suffix == "a" else 56210,
                memory_bytes=memory,
                cpu_millis=cpu,
                max_concurrent_runs=2 if suffix == "a" else 8,
                max_concurrent_runs_per_uid=1 if suffix == "a" else 6,
                repo_max_active_runs=4 if suffix == "a" else 12,
                repo_memory_budget_bytes=4 * 1024 * 1024 * 1024,
                repo_cpu_budget_millis=8_000,
            )
        descriptor = replace(
            self.descriptor(),
            repository_id="repo-legacy-consumer",
            original_root=str(self.fixture.root / "repo-legacy-consumer"),
            execution_root=str(self.fixture.root / "repo-legacy-consumer"),
            worktree_key=str(self.fixture.root / "repo-legacy-consumer"),
            fixture_bindings=(
                {
                    "name": "postgres",
                    "template": "legacy-postgres",
                    "network": "loopback",
                },
            ),
        )
        provider = self.provider()
        runtime_id = "devcoordinator-test-" + "7" * 32

        lease = provider.provision(descriptor, runtime_id=runtime_id)

        self.assertEqual(
            lease.provenance[0]["template_id"], "legacy-template-a"
        )
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )

    def test_materially_different_fixture_name_reports_bounded_candidate_ids(self) -> None:
        other_root = self.fixture.root / "materially-different-repo"
        other_root.mkdir()
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'repo-materially-different', 'host-ephemeral', ?,
                        'Materially different', 'active', 0, ?, ?
                    )
                    """,
                    (str(other_root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (
                        'repo-materially-different', 'installed', 0, 0,
                        'fixture', ?
                    )
                    """,
                    (now,),
                )
        consumer_root = self.fixture.root / "materially-different-consumer"
        consumer_root.mkdir()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'repo-materially-consumer', 'host-ephemeral', ?,
                        'Materially different consumer', 'active', 0, ?, ?
                    )
                    """,
                    (str(consumer_root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (
                        'repo-materially-consumer', 'installed', 0, 0,
                        'fixture', ?
                    )
                    """,
                    (now,),
                )
        for template_id, image, repo_id in (
            ("materially-different-postgres", IMAGE, "repo-ephemeral"),
            (
                "materially-different-postgres-v2",
                "postgres@sha256:" + "b" * 64,
                "repo-materially-different",
            ),
        ):
            self.fixture.persistence.provision_ephemeral_template(
                template_id=template_id,
                repo_id=repo_id,
                name="ambiguous-postgres",
                image_ref=image,
                default_ttl_seconds=600,
                max_ttl_seconds=3600,
                memory_bytes=128 * 1024 * 1024,
                cpu_millis=500,
            )
        descriptor = replace(
            self.descriptor(),
            repository_id="repo-materially-consumer",
            original_root=str(consumer_root),
            execution_root=str(consumer_root),
            worktree_key=str(consumer_root),
            fixture_bindings=(
                {
                    "name": "postgres",
                    "template": "ambiguous-postgres",
                    "network": "loopback",
                },
            ),
        )

        with self.assertRaisesRegex(
            BrokerError,
            "materially-different-postgres,materially-different-postgres-v2",
        ):
            self.provider().provision(
                descriptor,
                runtime_id="devcoordinator-test-" + "8" * 32,
            )

    def test_duplicate_global_name_uses_repository_association_only_as_routing(self) -> None:
        consumer_root = self.fixture.root / "consumer-routing"
        consumer_root.mkdir()
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.database, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (
                        'repo-consumer', 'host-ephemeral', ?, 'Consumer',
                        'active', 0, ?, ?
                    )
                    """,
                    (str(consumer_root), now, now),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor,
                        updated_at
                    ) VALUES (
                        'repo-consumer', 'installed', 0, 0, 'fixture', ?
                    )
                    """,
                    (now,),
                )
        consumer_template = "ephemeral-template-consumer-postgres"
        self.fixture.persistence.provision_ephemeral_template(
            template_id=consumer_template,
            repo_id="repo-consumer",
            name="artifact-postgres",
            image_ref="postgres@sha256:" + "b" * 64,
            command=("postgres", "-c", "fsync=off"),
            environment={},
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            container_tcp_port=5432,
            host_port_start=55500,
            host_port_end=55510,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        descriptor = replace(
            self.descriptor(),
            repository_id="repo-consumer",
            original_root=str(consumer_root),
            execution_root=str(consumer_root),
            worktree_key=str(consumer_root),
        )
        runtime_id = "devcoordinator-test-" + "6" * 32
        provider = self.provider()

        lease = provider.provision(descriptor, runtime_id=runtime_id)

        self.assertEqual(lease.provenance[0]["template_id"], consumer_template)
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )

    def test_secret_is_loadcredential_file_only_and_never_journaled(self) -> None:
        self.fixture.persistence.provision_ephemeral_template(
            template_id=TEMPLATE,
            repo_id="repo-ephemeral",
            name="artifact-postgres",
            image_ref="postgres@sha256:" + "a" * 64,
            command=("postgres", "-c", "fsync=off"),
            environment={"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
            secret_policy_kind=POSTGRES_INITDB_PASSWORD_FILE_V1,
            default_ttl_seconds=600,
            max_ttl_seconds=3600,
            container_tcp_port=5432,
            host_port_start=55400,
            host_port_end=55410,
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=750,
        )
        provider = self.provider()
        runtime_id = "devcoordinator-test-" + "2" * 32
        lease = provider.provision(self.descriptor(), runtime_id=runtime_id)
        secret = next(
            item for item in lease.credential_files if str(item["name"]).startswith("fixture-secret-")
        )
        path = Path(str(secret["source_path"]))
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o400)
        self.assertEqual(path.read_bytes(), b"fixture-password-never-in-json-1234567890")
        self.assertNotIn(
            "fixture-password-never-in-json-1234567890",
            (self.state_root / f"{runtime_id}.json").read_text(encoding="utf-8"),
        )
        config = json.loads((path.parent / "fixtures.json").read_text(encoding="utf-8"))
        self.assertEqual(config[0]["host"], "127.0.0.1")
        self.assertEqual(config[0]["port"], 5432)
        self.assertEqual(config[0]["secret_credential"], secret["name"])
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )

    def test_multiple_fixtures_share_only_the_anchor_namespace(self) -> None:
        descriptor = replace(
            self.descriptor(),
            fixtures=("primary", "replica"),
            fixture_bindings=(
                {
                    "name": "primary",
                    "template": "artifact-postgres",
                    "network": "loopback",
                },
                {
                    "name": "replica",
                    "template": "artifact-postgres",
                    "network": "loopback",
                },
            ),
        )
        provider = self.provider()
        runtime_id = "devcoordinator-test-" + "3" * 32
        lease = provider.provision(descriptor, runtime_id=runtime_id)
        state = json.loads(
            (self.state_root / f"{runtime_id}.json").read_text(encoding="utf-8")
        )
        anchor, replica = state["fixtures"]
        self.assertIsNone(anchor["network_container_id"])
        self.assertEqual(
            replica["network_container_id"], anchor["full_container_id"]
        )
        replica_target = self.host.created_targets[replica["run_uuid"]]
        self.assertEqual(
            replica_target.network_container_id, anchor["full_container_id"]
        )
        connections = json.loads(
            next(
                Path(str(item["source_path"]))
                for item in lease.credential_files
                if item["name"] == "fixtures.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            [(item["name"], item["host"]) for item in connections],
            [("primary", "127.0.0.1"), ("replica", "127.0.0.1")],
        )
        provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="terminal",
        )
        self.assertEqual(self.host.containers, {})

    def test_restart_cleanup_does_not_require_a_live_fixture_namespace(self) -> None:
        provider = self.provider()
        descriptor = self.descriptor()
        runtime_id = "devcoordinator-test-" + "4" * 32
        provider.provision(descriptor, runtime_id=runtime_id)
        state = json.loads(
            (self.state_root / f"{runtime_id}.json").read_text(encoding="utf-8")
        )
        anchor = state["fixtures"][0]
        self.host.containers[anchor["run_uuid"]]["running"] = False
        self.host.containers[anchor["run_uuid"]]["status"] = "exited"

        restarted = self.provider()
        with self.assertRaisesRegex(TestStoreConflict, "not running"):
            restarted.recover(runtime_id=runtime_id)
        manager = SystemdTestAttemptManager(fixture_provider=restarted)
        manager._cleanup_fixtures(runtime_id, reason="broker_restart_terminal")
        self.assertEqual(self.host.containers, {})
        self.assertFalse((self.credential_root / runtime_id).exists())


if __name__ == "__main__":
    unittest.main()
