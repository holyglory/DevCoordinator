from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import hashlib
from unittest import mock

from devcoordinator.universal_test_capabilities import SealedTestCapabilityRegistry
from devcoordinator.universal_test_runtime import (
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
    TestFixtureLease,
)
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    TestStoreContractError,
)


class FakeFixtureProvider:
    def __init__(self) -> None:
        self.provisioned: list[str] = []
        self.cleaned: list[tuple[str, str, str]] = []
        self.fail_cleanup = False

    def provision(self, attempt, *, runtime_id):
        self.provisioned.append(runtime_id)
        return TestFixtureLease(
            runtime_id=runtime_id,
            descriptor_fingerprint=attempt.fingerprint,
            fixtures=attempt.fixtures,
            environment={"TEST_FIXTURE_POSTGRES_HOST": "127.0.0.1"},
        )

    def cleanup(self, *, runtime_id, descriptor_fingerprint, reason):
        if self.fail_cleanup:
            raise RuntimeError("cleanup unavailable")
        self.cleaned.append((runtime_id, descriptor_fingerprint, reason))


def descriptor(
    root: Path,
    *,
    network: str = "none",
    fixtures=(),
    credentials=(),
    intent: str | None = None,
):
    return TestAttemptDescriptor(
        attempt_id="attempt-capability",
        target_id="target-capability",
        run_id="run-capability",
        repository_id="repo-capability",
        repository_generation=7,
        owner_uid=os.geteuid(),
        generation=1,
        source_mode="live",
        snapshot_id=None,
        original_root=str(root),
        temporary_root=None,
        execution_root=str(root),
        worktree_key=str(root),
        target_name="network-test",
        shard_index=0,
        shard_count=1,
        argv=("/usr/bin/python3", "-c", "pass"),
        cwd=".",
        environment={},
        driver="automation",
        reporter="automation-events",
        artifacts=(),
        fixtures=tuple(fixtures),
        network=network,
        ttl_seconds=30,
        cpu_millis=1000,
        memory_mib=128,
        pids=32,
        intent=(
            intent
            if intent is not None
            else ("manual" if credentials or network == "host-loopback" else "change")
        ),
        credentials=tuple(credentials),
    )


class UniversalTestCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()

    def registry(self, generation: int = 7) -> SealedTestCapabilityRegistry:
        path = Path(self.temporary.name) / "capabilities.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "repository_id": "repo-capability",
                            "generation": generation,
                            "capabilities": [
                                "network.loopback",
                                "network.host-loopback",
                                "fixture.postgres-small",
                                "credential.skydive-health-sweep-admin-v1",
                            ],
                        }
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return SealedTestCapabilityRegistry.load(
            path, expected_uid=os.geteuid(), allow_missing=False
        )

    def test_manifest_network_and_fixture_requests_are_default_deny(self) -> None:
        empty = SealedTestCapabilityRegistry()
        with self.assertRaisesRegex(TestStoreConflict, "no sealed capability"):
            empty.authorize(descriptor(self.root))
        with self.assertRaisesRegex(TestStoreConflict, "no sealed capability"):
            empty.authorize(descriptor(self.root, network="loopback"))
        with self.assertRaisesRegex(TestStoreConflict, "no sealed capability"):
            empty.authorize(descriptor(self.root, fixtures=("postgres-small",)))

    def test_preflight_exposes_repository_generation_and_named_gaps(self) -> None:
        empty = SealedTestCapabilityRegistry()
        missing = empty.check_requests(
            repository_id="repo-capability",
            repository_generation=7,
            networks=("loopback",),
            fixtures=("postgres-small",),
        )
        self.assertFalse(missing["ok"])
        self.assertEqual(
            missing["missing"],
            [
                "repository-generation-grant",
                "fixture.postgres-small",
                "network.loopback",
            ],
        )
        approved = self.registry().check_requests(
            repository_id="repo-capability",
            repository_generation=7,
            networks=("none", "loopback"),
            fixtures=("postgres-small",),
        )
        self.assertTrue(approved["ok"])

    def test_policy_is_exact_repository_generation_and_named_capability(self) -> None:
        registry = self.registry()
        policy = registry.authorize(
            descriptor(
                self.root,
                network="loopback",
                fixtures=("postgres-small",),
            )
        )
        self.assertEqual(policy, registry.policy_fingerprint)
        with self.assertRaisesRegex(TestStoreConflict, "not administrator-approved"):
            registry.authorize(descriptor(self.root, network="external"))
        with self.assertRaisesRegex(TestStoreConflict, "repository generation"):
            self.registry(generation=6).authorize(
                descriptor(self.root, network="loopback")
            )

    def test_host_loopback_capability_is_generation_bound(self) -> None:
        attempt = descriptor(self.root, network="host-loopback")
        registry = self.registry()
        self.assertEqual(
            registry.authorize(attempt),
            registry.policy_fingerprint,
        )
        self.assertEqual(
            registry.check_requests(
                repository_id="repo-capability",
                repository_generation=7,
                networks=("host-loopback",),
            )["requested"],
            ["network.host-loopback"],
        )
        with self.assertRaisesRegex(TestStoreConflict, "repository generation"):
            self.registry(generation=6).authorize(attempt)

    def test_operational_credential_capability_is_named_and_default_deny(self) -> None:
        alias = "skydive-health-sweep-admin-v1"
        attempt = descriptor(self.root, credentials=(alias,))
        with self.assertRaisesRegex(TestStoreConflict, "no sealed capability"):
            SealedTestCapabilityRegistry().authorize(attempt)
        self.assertEqual(
            self.registry().authorize(attempt),
            self.registry().policy_fingerprint,
        )
        preflight = self.registry().check_requests(
            repository_id="repo-capability",
            repository_generation=7,
            credentials=(alias,),
        )
        self.assertTrue(preflight["ok"])
        self.assertEqual(
            preflight["requested"],
            [f"credential.{alias}"],
        )
        missing = self.registry().check_requests(
            repository_id="repo-capability",
            repository_generation=7,
            credentials=("skydive-unapproved-admin-v1",),
        )
        self.assertFalse(missing["ok"])
        self.assertEqual(
            missing["missing"],
            ["credential.skydive-unapproved-admin-v1"],
        )

    def test_policy_file_accepts_local_metadata_but_rejects_symlink(self) -> None:
        path = Path(self.temporary.name) / "capabilities.json"
        path.write_text(
            '{"schema_version":1,"repositories":[]}', encoding="utf-8"
        )
        path.chmod(0o644)
        loaded = SealedTestCapabilityRegistry.load(
            path, expected_uid=os.geteuid() + 1, allow_missing=False
        )
        self.assertEqual(loaded.repositories, {})
        alias = path.with_name("capabilities-link.json")
        alias.symlink_to(path)
        with self.assertRaisesRegex(TestStoreConflict, "unsafe"):
            SealedTestCapabilityRegistry.load(alias, allow_missing=False)

    def test_transient_unit_hides_direct_host_container_daemon_sockets(self) -> None:
        properties = SystemdTestAttemptManager._systemd_properties(
            descriptor(self.root),
            execution_root=self.root,
            output_root=Path(self.temporary.name) / "output",
        )
        inaccessible = next(
            item for item in properties if item.startswith("--property=InaccessiblePaths=")
        )
        self.assertIn("/run/docker.sock", inaccessible)
        self.assertIn("/var/run/docker.sock", inaccessible)
        self.assertIn("/run/containerd/containerd.sock", inaccessible)
        self.assertIn("--property=ProtectHome=tmpfs", properties)
        self.assertIn(f"--property=BindPaths={self.root}", properties)
        self.assertNotIn("--property=ProtectHome=read-only", properties)
        self.assertNotIn("--property=BindPaths=/home", properties)
        self.assertNotIn("--property=ReadWritePaths=/home", properties)
        self.assertIn("--property=PrivateNetwork=yes", properties)
        self.assertIn("--property=IPAddressDeny=any", properties)

    def test_cross_home_virtualenv_binds_only_exact_toolchain_read_only(self) -> None:
        toolchain = Path(
            "/home/shared/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu"
        )
        executable = toolchain / "bin/python3.12"
        stable_root = Path(
            "/home/shared/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu"
        )
        stable = stable_root / "bin/python3.12"
        with mock.patch.object(Path, "resolve", autospec=True) as resolve, mock.patch.object(
            Path, "is_symlink", autospec=True
        ) as is_symlink, mock.patch.object(
            Path, "lstat", autospec=True
        ) as lstat, mock.patch(
            "devcoordinator.universal_test_runtime.os.readlink",
            return_value=str(stable),
        ):
            def resolved(path, *, strict=False):
                del strict
                if str(path).endswith(".venv/bin/python"):
                    return executable
                return Path(str(path))

            resolve.side_effect = resolved
            is_symlink.side_effect = lambda path: str(path).endswith(
                ".venv/bin/python"
            )
            lstat.return_value = mock.Mock(st_mode=stat.S_IFDIR | 0o755)
            attempt = replace(
                descriptor(self.root),
                argv=(".venv/bin/python", "-m", "pytest"),
            )
            properties = SystemdTestAttemptManager._systemd_properties(
                attempt,
                execution_root=self.root,
                output_root=Path(self.temporary.name) / "output",
            )

        self.assertIn("--property=ProtectHome=tmpfs", properties)
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{toolchain}:{stable_root}",
            properties,
        )
        standard_library = toolchain / "lib/python3.12/os.py"
        self.assertIn(toolchain, standard_library.parents)
        self.assertNotIn("--property=BindReadOnlyPaths=/home", properties)
        self.assertNotIn(
            "--property=BindReadOnlyPaths=/home/shared", properties
        )

    def test_transient_attempt_uses_accounting_not_project_slice(self) -> None:
        value = SystemdTestAttemptManager._repository_slice(descriptor(self.root))
        self.assertTrue(value.startswith("devcoordinator-tests-uid"))
        self.assertTrue(value.endswith(".slice"))
        self.assertNotIn("devcoordinator-projects", value)
        self.assertNotIn("devcoordinator-background", value)

    def test_host_loopback_uses_host_namespace_with_loopback_address_filter(self) -> None:
        attempt = descriptor(self.root, network="host-loopback")
        properties = SystemdTestAttemptManager._systemd_properties(
            attempt,
            execution_root=self.root,
            output_root=Path(self.temporary.name) / "output",
        )
        self.assertNotIn("--property=PrivateNetwork=yes", properties)
        self.assertFalse(
            any(item.startswith("--property=NetworkNamespacePath=") for item in properties)
        )
        self.assertIn("--property=IPAddressDeny=any", properties)
        self.assertIn("--property=IPAddressAllow=localhost", properties)
        self.assertIn(
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            properties,
        )
        with self.assertRaisesRegex(
            TestStoreContractError, "manual intent without fixtures"
        ):
            descriptor(
                self.root,
                network="host-loopback",
                intent="change",
            )
        with self.assertRaisesRegex(
            TestStoreContractError, "manual intent without fixtures"
        ):
            descriptor(
                self.root,
                network="host-loopback",
                fixtures=("postgres-small",),
            )

    def test_systemd_bind_paths_fail_closed_when_property_parser_is_ambiguous(self) -> None:
        for name in (
            "repo with spaces",
            "repo:destination",
            r"repo\\escaped",
            "repo%specifier",
            "repo'quoted",
        ):
            root = Path(self.temporary.name) / name
            root.mkdir()
            with self.subTest(name=name), self.assertRaisesRegex(
                TestStoreConflict, "cannot be represented safely"
            ):
                SystemdTestAttemptManager._systemd_properties(
                    descriptor(root),
                    execution_root=root,
                    output_root=Path(self.temporary.name) / "output",
                )

    def test_fixtures_are_provisioned_as_nonsecret_leases_and_cleaned_exactly(self) -> None:
        attempt = descriptor(self.root, fixtures=("postgres-small",))
        runtime_id = SystemdTestAttemptManager._runtime_id(attempt)
        without_provider = SystemdTestAttemptManager()
        with self.assertRaisesRegex(TestStoreConflict, "fixture provider"):
            without_provider._provision_fixture_descriptor(
                attempt, runtime_id=runtime_id
            )

        provider = FakeFixtureProvider()
        manager = SystemdTestAttemptManager(fixture_provider=provider)
        effective = manager._provision_fixture_descriptor(
            attempt, runtime_id=runtime_id
        )
        self.assertEqual(provider.provisioned, [runtime_id])
        self.assertEqual(
            effective.environment,
            {"TEST_FIXTURE_POSTGRES_HOST": "127.0.0.1"},
        )
        manager._cleanup_fixtures(runtime_id, reason="attempt_terminal")
        self.assertEqual(
            provider.cleaned,
            [(runtime_id, attempt.fingerprint, "attempt_terminal")],
        )
        self.assertNotIn(runtime_id, manager._fixture_leases)

    def test_fixture_cleanup_failure_retains_exact_lease_for_retry(self) -> None:
        attempt = descriptor(self.root, fixtures=("postgres-small",))
        runtime_id = SystemdTestAttemptManager._runtime_id(attempt)
        provider = FakeFixtureProvider()
        manager = SystemdTestAttemptManager(fixture_provider=provider)
        manager._provision_fixture_descriptor(attempt, runtime_id=runtime_id)
        provider.fail_cleanup = True
        with self.assertRaisesRegex(TestStoreConflict, "cleanup failed"):
            manager._cleanup_fixtures(runtime_id, reason="attempt_terminal")
        self.assertIn(runtime_id, manager._fixture_leases)
        provider.fail_cleanup = False
        manager._cleanup_fixtures(runtime_id, reason="cleanup_retry")
        self.assertNotIn(runtime_id, manager._fixture_leases)

    def test_fixture_lease_rejects_secret_environment_names(self) -> None:
        with self.assertRaisesRegex(TestStoreContractError, "environment name is unsafe"):
            TestFixtureLease(
                runtime_id="runtime-fixture",
                descriptor_fingerprint="f" * 64,
                fixtures=("postgres-small",),
                environment={"DATABASE_PASSWORD": "forbidden"},
            )

    def test_fixture_namespace_and_loadcredential_are_bound_without_host_network(self) -> None:
        credential = Path(self.temporary.name) / "fixture-proof"
        credential.write_bytes(b"non-environment-secret-material")
        credential.chmod(0o400)
        namespace_path = Path(f"/proc/{os.getpid()}/ns/net")
        namespace = namespace_path.stat()
        process = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
        fields = process[process.rfind(")") + 2 :].split()
        lease = TestFixtureLease(
            runtime_id="devcoordinator-test-" + "a" * 32,
            descriptor_fingerprint="f" * 64,
            fixtures=("postgres-small",),
            environment={},
            credential_files=(
                {
                    "name": "fixture-secret-proof",
                    "source_path": str(credential),
                    "sha256": hashlib.sha256(credential.read_bytes()).hexdigest(),
                    "size_bytes": credential.stat().st_size,
                },
            ),
            network_namespace={
                "path": str(namespace_path),
                "device": namespace.st_dev,
                "inode": namespace.st_ino,
                "pid": os.getpid(),
                "process_identity": f"linux:{os.getpid()}:{fields[19]}",
            },
        )
        properties = SystemdTestAttemptManager._systemd_properties(
            descriptor(self.root, network="loopback", fixtures=("postgres-small",)),
            execution_root=self.root,
            output_root=Path(self.temporary.name) / "output",
            fixture_lease=lease,
        )
        self.assertIn(f"--property=NetworkNamespacePath={namespace_path}", properties)
        self.assertIn(
            f"--property=LoadCredential=fixture-secret-proof:{credential}", properties
        )
        self.assertIn("--property=IPAddressDeny=any", properties)
        self.assertIn("--property=IPAddressAllow=localhost", properties)
        self.assertNotIn("--property=PrivateNetwork=yes", properties)
        with self.assertRaisesRegex(
            TestStoreConflict, "cannot use a fixture network namespace"
        ):
            SystemdTestAttemptManager._systemd_properties(
                descriptor(self.root, network="host-loopback"),
                execution_root=self.root,
                output_root=Path(self.temporary.name) / "output",
                fixture_lease=lease,
            )
        stale_namespace_lease = TestFixtureLease(
            runtime_id=lease.runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            fixtures=lease.fixtures,
            environment={},
            credential_files=lease.credential_files,
            network_namespace={
                **lease.network_namespace,
                "inode": int(lease.network_namespace["inode"]) + 1,
            },
        )
        with self.assertRaisesRegex(TestStoreConflict, "network namespace changed"):
            SystemdTestAttemptManager._systemd_properties(
                descriptor(self.root, network="loopback", fixtures=("postgres-small",)),
                execution_root=self.root,
                output_root=Path(self.temporary.name) / "output",
                fixture_lease=stale_namespace_lease,
            )
        credential.chmod(0o600)
        credential.write_bytes(b"tampered-same-length-material!!")
        credential.chmod(0o400)
        with self.assertRaisesRegex(TestStoreConflict, "credential is unsafe"):
            SystemdTestAttemptManager._systemd_properties(
                descriptor(self.root, network="loopback", fixtures=("postgres-small",)),
                execution_root=self.root,
                output_root=Path(self.temporary.name) / "output",
                fixture_lease=lease,
            )


if __name__ == "__main__":
    unittest.main()
