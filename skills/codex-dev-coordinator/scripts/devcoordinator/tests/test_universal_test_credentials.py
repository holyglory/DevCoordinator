from __future__ import annotations

import base64
from contextlib import redirect_stdout
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from devcoordinator import universal_test_credentials as credentials_module
from devcoordinator import universal_test_runtime as runtime_module
from devcoordinator.universal_test_artifacts import package_directory
from devcoordinator.universal_test_credentials import (
    AdministratorOperationalCredentialStore,
    BrokerOperationalCredentialProvider,
    public_binding_document,
)
from devcoordinator.universal_test_runner import run
from devcoordinator.universal_test_runtime import (
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    TestStoreContractError,
)


class UniversalTestOperationalCredentialTests(unittest.TestCase):
    SECRET = b"health-sweep-secret-a1b2c3d4e5f6"
    ROTATED_SECRET = b"health-sweep-rotated-f6e5d4c3b2a1"
    ALIAS = "skydive-health-sweep-admin-v1"
    CREDENTIAL_NAME = "health-sweep-bearer"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.repository = self.root / "repository"
        self.repository.mkdir(mode=0o700)
        self.registry = self.root / "registry.json"
        self.material_root = self.root / "material"
        self.runtime_root = self.root / "runtime"
        self.source = self.root / "source.env"
        self.source.write_bytes(b"ADMIN_TOKEN=" + self.SECRET + b"\n")
        self.source.chmod(0o600)
        self.owner_uid = os.geteuid()
        self.store = AdministratorOperationalCredentialStore(
            registry_path=self.registry,
            material_root=self.material_root,
            expected_authority_uid=self.owner_uid,
            clock=lambda: 1_700_000_000,
        )
        self.provider = BrokerOperationalCredentialProvider(
            registry_path=self.registry,
            material_root=self.material_root,
            runtime_root=self.runtime_root,
            expected_authority_uid=self.owner_uid,
            clock=lambda: 1_700_000_000,
        )

    def descriptor(
        self,
        *,
        attempt_id: str = "attempt-health-sweep",
        repository_id: str = "repo-skydive",
        repository_generation: int = 7,
        owner_uid: int | None = None,
        target_name: str = "health-sweep-post-deploy",
        ttl_seconds: int = 60,
        argv: tuple[str, ...] = ("/usr/bin/python3", "-c", "pass"),
    ) -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            attempt_id=attempt_id,
            target_id="target-health-sweep",
            run_id="run-health-sweep",
            repository_id=repository_id,
            repository_generation=repository_generation,
            owner_uid=self.owner_uid if owner_uid is None else owner_uid,
            generation=1,
            source_mode="live",
            snapshot_id=None,
            original_root=str(self.repository),
            temporary_root=None,
            execution_root=str(self.repository),
            worktree_key=str(self.repository),
            target_name=target_name,
            shard_index=0,
            shard_count=1,
            argv=argv,
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="loopback",
            ttl_seconds=ttl_seconds,
            intent="manual",
            credentials=(self.ALIAS,),
        )

    def register(self):
        return self.store.register(
            alias=self.ALIAS,
            repository_id="repo-skydive",
            repository_generation=7,
            target_name="health-sweep-post-deploy",
            intent="manual",
            owner_uid=self.owner_uid,
            credential_name=self.CREDENTIAL_NAME,
            max_ttl_seconds=120,
            source_path=self.source,
            source_key="ADMIN_TOKEN",
            source_uid=self.owner_uid,
        )

    def test_registration_persists_only_sealed_metadata_and_opaque_alias(self) -> None:
        binding = self.register()

        registry_payload = self.registry.read_bytes()
        public_payload = json.dumps(
            dict(public_binding_document(binding)),
            sort_keys=True,
        ).encode("utf-8")
        descriptor_payload = json.dumps(
            self.descriptor().to_document(),
            sort_keys=True,
        ).encode("utf-8")
        source_path = str(self.source).encode("utf-8")
        for payload in (registry_payload, public_payload, descriptor_payload):
            self.assertNotIn(self.SECRET, payload)
            self.assertNotIn(source_path, payload)
        self.assertEqual(
            json.loads(descriptor_payload)["credentials"],
            [self.ALIAS],
        )
        self.assertEqual(
            set(public_binding_document(binding)),
            {
                "alias",
                "repository_id",
                "repository_generation",
                "target_name",
                "intent",
                "owner_uid",
                "credential_name",
                "max_ttl_seconds",
                "rotation_generation",
                "status",
            },
        )
        self.assertEqual(self.registry.stat().st_mode & 0o777, 0o600)
        material = self.material_root / binding.material_id
        self.assertEqual(material.read_bytes(), self.SECRET)
        self.assertEqual(material.stat().st_mode & 0o777, 0o400)

    def test_exact_binding_and_ttl_are_required(self) -> None:
        self.register()
        cases = (
            replace(self.descriptor(), repository_id="repo-other"),
            replace(self.descriptor(), repository_generation=8),
            replace(self.descriptor(), target_name="different-target"),
            replace(self.descriptor(), owner_uid=self.owner_uid + 1),
            replace(self.descriptor(), ttl_seconds=121),
            replace(
                self.descriptor(),
                credentials=("skydive-unknown-binding-v1",),
            ),
        )
        for index, descriptor in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    TestStoreConflict, "not accepted"
                ):
                    self.provider.provision(
                        descriptor,
                        runtime_id=f"devcoordinator-test-wrong-{index}",
                    )
        with self.assertRaisesRegex(TestStoreContractError, "manual"):
            replace(self.descriptor(), intent="change")

    def test_source_symlink_swap_and_malformed_dotenv_fail_closed(
        self,
    ) -> None:
        symlink = self.root / "source-link.env"
        symlink.symlink_to(self.source)
        with self.assertRaisesRegex(TestStoreConflict, "unsafe"):
            self.store.register(
                alias="symlink-source-v1",
                repository_id="repo-skydive",
                repository_generation=7,
                target_name="health-sweep-post-deploy",
                intent="manual",
                owner_uid=self.owner_uid,
                credential_name=self.CREDENTIAL_NAME,
                max_ttl_seconds=120,
                source_path=symlink,
                source_key="ADMIN_TOKEN",
                source_uid=self.owner_uid,
            )

        hardlink = self.root / "source-hardlink.env"
        os.link(self.source, hardlink)
        hardlink_binding = self.store.register(
            alias="hardlink-source-v1",
            repository_id="repo-skydive",
            repository_generation=7,
            target_name="health-sweep-post-deploy",
            intent="manual",
            owner_uid=self.owner_uid,
            credential_name=self.CREDENTIAL_NAME,
            max_ttl_seconds=120,
            source_path=hardlink,
            source_key="ADMIN_TOKEN",
            source_uid=self.owner_uid + 10_000,
        )
        self.assertEqual(hardlink_binding.source_identity["inode"], self.source.stat().st_ino)
        hardlink.unlink()

        replacement_source = self.root / "replacement.env"
        replacement_source.write_bytes(
            b"ADMIN_TOKEN=fixture-concurrent-replacement-1234567890\n"
        )
        replacement_source.chmod(0o600)
        original_source = self.root / "original.env"
        real_read = os.read
        swapped = False
        source_identity = (self.source.stat().st_dev, self.source.stat().st_ino)

        def swapping_read(descriptor: int, size: int) -> bytes:
            nonlocal swapped
            payload = real_read(descriptor, size)
            metadata = os.fstat(descriptor)
            if (
                payload
                and not swapped
                and (metadata.st_dev, metadata.st_ino) == source_identity
            ):
                swapped = True
                self.source.rename(original_source)
                replacement_source.rename(self.source)
            return payload

        with mock.patch(
            "devcoordinator.universal_test_credentials.os.read",
            side_effect=swapping_read,
        ):
            with self.assertRaisesRegex(TestStoreConflict, "changed during import"):
                self.store.register(
                    alias="swapped-source-v1",
                    repository_id="repo-skydive",
                    repository_generation=7,
                    target_name="health-sweep-post-deploy",
                    intent="manual",
                    owner_uid=self.owner_uid,
                    credential_name=self.CREDENTIAL_NAME,
                    max_ttl_seconds=120,
                    source_path=self.source,
                    source_key="ADMIN_TOKEN",
                    source_uid=self.owner_uid,
                )
        self.source.unlink()
        original_source.rename(self.source)

        malformed_values = (
            b"ADMIN_TOKEN=test-short\n",
            b"ADMIN_TOKEN=fixture-first-value-123456\nADMIN_TOKEN=fixture-second-value-123456\n",
            b"ADMIN_TOKEN=\"fixture-unsupported\\nvalue-123456\"\n",
            b"OTHER_TOKEN=fixture-sufficiently-long-value\n",
        )
        for index, payload in enumerate(malformed_values):
            with self.subTest(index=index):
                self.source.write_bytes(payload)
                self.source.chmod(0o600)
                with self.assertRaises(TestStoreContractError):
                    self.store.register(
                        alias=f"malformed-source-{index}",
                        repository_id="repo-skydive",
                        repository_generation=7,
                        target_name="health-sweep-post-deploy",
                        intent="manual",
                        owner_uid=self.owner_uid,
                        credential_name=self.CREDENTIAL_NAME,
                        max_ttl_seconds=120,
                        source_path=self.source,
                        source_key="ADMIN_TOKEN",
                        source_uid=self.owner_uid,
                    )

    def test_private_file_identity_and_leaf_presence_fail_closed(self) -> None:
        suffix = b"\nADMIN_TOKEN=" + self.SECRET + b"\n"
        padded = b"#" + b"a" * (70 * 1024) + suffix
        replacement = b"#" + b"b" * (70 * 1024) + suffix
        self.assertEqual(len(replacement), len(padded))
        self.source.write_bytes(padded)
        self.source.chmod(0o600)
        real_read = credentials_module.os.read
        mutated = False

        def mutate_in_place(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            value = real_read(descriptor, size)
            if value and not mutated:
                mutated = True
                self.source.write_bytes(replacement)
                self.source.chmod(0o600)
            return value

        with mock.patch.object(
            credentials_module.os,
            "read",
            side_effect=mutate_in_place,
        ):
            with self.assertRaisesRegex(
                TestStoreConflict,
                "changed during import",
            ):
                self.store.register(
                    alias="in-place-source-v1",
                    repository_id="repo-skydive",
                    repository_generation=7,
                    target_name="health-sweep-post-deploy",
                    intent="manual",
                    owner_uid=self.owner_uid,
                    credential_name=self.CREDENTIAL_NAME,
                    max_ttl_seconds=120,
                    source_path=self.source,
                    source_key="ADMIN_TOKEN",
                    source_uid=self.owner_uid,
                )

        dangling_target = self.root / "missing-registry-target"
        self.registry.symlink_to(dangling_target)
        with self.assertRaises(TestStoreConflict):
            self.store.load(allow_missing=True)
        self.registry.unlink()

        dangling_runtime_target = self.root / "missing-runtime-target"
        self.runtime_root.symlink_to(dangling_runtime_target)
        with self.assertRaises(TestStoreConflict):
            self.provider.cleanup(
                runtime_id="devcoordinator-test-dangling-runtime",
                descriptor_fingerprint="0" * 64,
                reason="presence-check",
            )

    def test_material_reconciliation_is_crash_consistent_and_revoke_idempotent(
        self,
    ) -> None:
        real_fsync_directory = credentials_module._fsync_directory

        def fail_registry_sync(path: Path, *, field: str) -> None:
            if field == "credential registry directory":
                raise TestStoreConflict("injected registry sync failure")
            real_fsync_directory(path, field=field)

        with mock.patch.object(
            credentials_module,
            "_fsync_directory",
            side_effect=fail_registry_sync,
        ):
            with self.assertRaisesRegex(
                TestStoreConflict,
                "injected registry sync failure",
            ):
                self.register()

        committed = self.store.load(allow_missing=False).bindings[self.ALIAS]
        committed_material = self.material_root / committed.material_id
        self.assertTrue(committed_material.is_file())
        self.assertEqual(committed_material.read_bytes(), self.SECRET)

        orphan = self.material_root / ("material-" + "f" * 64)
        orphan.write_bytes(b"orphaned-crash-material")
        orphan.chmod(0o400)
        revoked = self.store.revoke(
            alias=self.ALIAS,
            expected_rotation_generation=1,
        )
        self.assertEqual(revoked.status, "revoked")
        self.assertFalse(orphan.exists())
        self.assertFalse(committed_material.exists())

        before = self.registry.read_bytes()
        replay = self.store.revoke(
            alias=self.ALIAS,
            expected_rotation_generation=1,
        )
        self.assertEqual(replay, revoked)
        self.assertEqual(self.registry.read_bytes(), before)

    def test_prepared_lease_journal_recovers_partial_and_committed_crashes(
        self,
    ) -> None:
        self.register()
        descriptor = self.descriptor()
        partial_runtime = "devcoordinator-test-prepared-partial"
        real_write = credentials_module._write_new_private_file
        interrupted = False

        def crash_after_material(
            path: Path,
            payload: bytes,
            *,
            mode: int,
            expected_uid: int,
        ) -> None:
            nonlocal interrupted
            real_write(
                path,
                payload,
                mode=mode,
                expected_uid=expected_uid,
            )
            if (
                not interrupted
                and path.parent.name == partial_runtime
                and path.name.startswith("credential-")
            ):
                interrupted = True
                raise KeyboardInterrupt("injected process crash")

        with mock.patch.object(
            credentials_module,
            "_write_new_private_file",
            side_effect=crash_after_material,
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.provider.provision(
                    descriptor,
                    runtime_id=partial_runtime,
                )
        partial_directory = self.runtime_root / partial_runtime
        self.assertTrue(partial_directory.is_dir())
        self.assertTrue(self.provider._prepared_state_path(partial_runtime).is_file())

        recovered = BrokerOperationalCredentialProvider(
            registry_path=self.registry,
            material_root=self.material_root,
            runtime_root=self.runtime_root,
            expected_authority_uid=self.owner_uid,
        ).provision(descriptor, runtime_id=partial_runtime)
        self.assertEqual(recovered.runtime_id, partial_runtime)
        self.assertFalse(
            self.provider._prepared_state_path(partial_runtime).exists()
        )

        committed_runtime = "devcoordinator-test-prepared-committed"
        committed_provider = BrokerOperationalCredentialProvider(
            registry_path=self.registry,
            material_root=self.material_root,
            runtime_root=self.runtime_root,
            expected_authority_uid=self.owner_uid,
        )
        with mock.patch.object(
            committed_provider,
            "_remove_prepared_state",
            side_effect=KeyboardInterrupt("injected committed crash"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                committed_provider.provision(
                    descriptor,
                    runtime_id=committed_runtime,
                )
        replay = BrokerOperationalCredentialProvider(
            registry_path=self.registry,
            material_root=self.material_root,
            runtime_root=self.runtime_root,
            expected_authority_uid=self.owner_uid,
        ).provision(descriptor, runtime_id=committed_runtime)
        self.assertEqual(replay.runtime_id, committed_runtime)
        self.assertFalse(
            self.provider._prepared_state_path(committed_runtime).exists()
        )

    def test_not_found_terminal_state_cleans_recovered_credential_lease(
        self,
    ) -> None:
        self.register()
        descriptor = self.descriptor()
        runtime_id = SystemdTestAttemptManager._runtime_id(descriptor)
        lease = self.provider.provision(descriptor, runtime_id=runtime_id)
        lease_directory = Path(
            str(lease.credential_files[0]["source_path"])
        ).parent

        def unavailable_systemd(
            argv, **_values
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                list(argv),
                1,
                stdout="",
                stderr="unit not found",
            )

        manager = SystemdTestAttemptManager(
            attempt_root=self.root / "attempts",
            artifact_root=self.root / "artifacts",
            credential_provider=BrokerOperationalCredentialProvider(
                registry_path=self.registry,
                material_root=self.material_root,
                runtime_root=self.runtime_root,
                expected_authority_uid=self.owner_uid,
            ),
            runner=unavailable_systemd,
        )
        state = manager.status(runtime_id)
        self.assertEqual(state.state, "not-found")
        self.assertFalse(lease_directory.exists())

    def test_lease_is_transient_replay_safe_and_systemd_only(self) -> None:
        self.register()
        descriptor = self.descriptor()
        runtime_id = "devcoordinator-test-health-sweep"

        lease = self.provider.provision(descriptor, runtime_id=runtime_id)
        replay = self.provider.provision(descriptor, runtime_id=runtime_id)

        self.assertEqual(replay, lease)
        self.assertEqual(lease.bindings, (self.ALIAS,))
        credential_path = Path(str(lease.credential_files[0]["source_path"]))
        self.assertEqual(credential_path.read_bytes(), self.SECRET)
        self.assertEqual(credential_path.stat().st_mode & 0o777, 0o400)
        state_payload = (credential_path.parent / "lease.json").read_bytes()
        self.assertNotIn(self.SECRET, state_payload)
        with self.assertRaisesRegex(TestStoreConflict, "already bound"):
            self.provider.provision(
                replace(descriptor, attempt_id="attempt-replay"),
                runtime_id=runtime_id,
            )

        output = self.root / "output"
        output.mkdir(mode=0o700)
        properties = SystemdTestAttemptManager._systemd_properties(
            descriptor,
            execution_root=self.repository,
            output_root=output,
            credential_lease=lease,
        )
        serialized_properties = "\n".join(properties).encode("utf-8")
        self.assertIn(
            (
                "--property=LoadCredential="
                f"{self.CREDENTIAL_NAME}:{credential_path}"
            ).encode("utf-8"),
            serialized_properties,
        )
        self.assertNotIn(self.SECRET, serialized_properties)
        self.assertNotIn(self.SECRET, repr(descriptor.argv).encode("utf-8"))
        self.assertNotIn(self.SECRET, json.dumps(descriptor.environment).encode("utf-8"))

        recovered = BrokerOperationalCredentialProvider(
            registry_path=self.registry,
            material_root=self.material_root,
            runtime_root=self.runtime_root,
            expected_authority_uid=self.owner_uid,
        ).recover_for_cleanup(runtime_id=runtime_id)
        self.assertEqual(recovered, lease)
        with self.assertRaisesRegex(TestStoreConflict, "fingerprint is stale"):
            self.provider.cleanup(
                runtime_id=runtime_id,
                descriptor_fingerprint="0" * 64,
                reason="test",
            )
        self.provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="test",
        )
        self.assertFalse(credential_path.parent.exists())
        self.provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="idempotent",
        )

    def test_systemd_credential_copy_rejects_same_inode_same_size_mutation(
        self,
    ) -> None:
        self.register()
        descriptor = self.descriptor()
        lease = self.provider.provision(
            descriptor,
            runtime_id="devcoordinator-test-systemd-copy-race",
        )
        credential_path = Path(str(lease.credential_files[0]["source_path"]))
        output = self.root / "systemd-copy-output"
        output.mkdir(mode=0o700)
        real_read = runtime_module.os.read
        mutated = False

        def mutate_after_read(descriptor_fd: int, size: int) -> bytes:
            nonlocal mutated
            value = real_read(descriptor_fd, size)
            if value and not mutated:
                mutated = True
                credential_path.chmod(0o600)
                credential_path.write_bytes(b"x" * len(self.SECRET))
                credential_path.chmod(0o400)
            return value

        with mock.patch.object(
            runtime_module.os,
            "read",
            side_effect=mutate_after_read,
        ):
            with self.assertRaisesRegex(TestStoreConflict, "unsafe"):
                SystemdTestAttemptManager._systemd_properties(
                    descriptor,
                    execution_root=self.repository,
                    output_root=output,
                    credential_lease=lease,
                )

    def test_metadata_is_ignored_but_content_rotation_and_revocation_invalidate_launch(self) -> None:
        binding = self.register()
        descriptor = self.descriptor()
        old_lease = self.provider.provision(
            descriptor,
            runtime_id="devcoordinator-test-before-rotation",
        )

        durable_material = self.material_root / binding.material_id
        durable_material.chmod(0o600)
        metadata_tolerant_lease = self.provider.provision(
            descriptor,
            runtime_id="devcoordinator-test-shared-mode-material",
        )
        self.provider.cleanup(
            runtime_id=metadata_tolerant_lease.runtime_id,
            descriptor_fingerprint=metadata_tolerant_lease.descriptor_fingerprint,
            reason="test",
        )
        durable_material.write_bytes(b"x" * len(self.SECRET))
        with self.assertRaisesRegex(TestStoreConflict, "changed"):
            self.provider.provision(
                descriptor,
                runtime_id="devcoordinator-test-drifted-material",
            )
        durable_material.write_bytes(self.SECRET)
        durable_material.chmod(0o400)

        rotated_source = self.root / "rotated.env"
        rotated_source.write_bytes(
            b"ADMIN_TOKEN=" + self.ROTATED_SECRET + b"\n"
        )
        rotated_source.chmod(0o600)
        rotated = self.store.rotate(
            alias=self.ALIAS,
            expected_rotation_generation=1,
            source_path=rotated_source,
            source_key="ADMIN_TOKEN",
            source_uid=self.owner_uid,
        )
        self.assertEqual(rotated.rotation_generation, 2)
        with self.assertRaisesRegex(TestStoreConflict, "stale"):
            with self.provider.launch_guard(descriptor, old_lease):
                self.fail("a rotated credential lease must never launch")
        with self.assertRaisesRegex(TestStoreConflict, "already bound"):
            self.provider.provision(
                descriptor,
                runtime_id=old_lease.runtime_id,
            )

        rotated_lease = self.provider.provision(
            descriptor,
            runtime_id="devcoordinator-test-after-rotation",
        )
        self.assertEqual(
            Path(str(rotated_lease.credential_files[0]["source_path"])).read_bytes(),
            self.ROTATED_SECRET,
        )
        self.store.revoke(
            alias=self.ALIAS,
            expected_rotation_generation=2,
        )
        with self.assertRaisesRegex(TestStoreConflict, "not accepted"):
            with self.provider.launch_guard(descriptor, rotated_lease):
                self.fail("a revoked credential lease must never launch")
        with self.assertRaisesRegex(TestStoreConflict, "not accepted"):
            self.provider.provision(
                descriptor,
                runtime_id="devcoordinator-test-after-revoke",
            )

    def test_runner_strips_inherited_environment_and_redacts_exact_secret(self) -> None:
        credential_directory = self.root / "systemd-credentials"
        credential_directory.mkdir(mode=0o700)
        credential = credential_directory / self.CREDENTIAL_NAME
        credential.write_bytes(self.SECRET)
        credential.chmod(0o400)
        output = self.root / "runner-output"
        output.mkdir(mode=0o700)
        result_path = output / "result.json"

        inherited_probe = replace(
            self.descriptor(
                attempt_id="attempt-inherited-env",
                argv=(
                    "/usr/bin/python3",
                    "-c",
                    "import os;print(os.environ.get('ADMIN_TOKEN', 'missing'))",
                ),
            ),
            credentials=(),
            intent="manual",
        )
        with mock.patch.dict(
            os.environ,
            {"ADMIN_TOKEN": self.SECRET.decode("ascii")},
            clear=False,
        ):
            self.assertEqual(run(inherited_probe, output, result_path), 0)
        stdout = output / f"{inherited_probe.attempt_id}-stdout.log"
        self.assertEqual(stdout.read_text(encoding="utf-8").strip(), "missing")

        for index, expression in enumerate(
            (
                "open(os.path.join(os.environ['CREDENTIALS_DIRECTORY'],"
                "'health-sweep-bearer'),'rb').read()",
                "base64.b64encode(open(os.path.join("
                "os.environ['CREDENTIALS_DIRECTORY'],'health-sweep-bearer'),"
                "'rb').read())",
            )
        ):
            with self.subTest(index=index):
                attempt_output = self.root / f"secret-output-{index}"
                attempt_output.mkdir(mode=0o700)
                attempt_result = attempt_output / "result.json"
                descriptor = self.descriptor(
                    attempt_id=f"attempt-secret-output-{index}",
                    argv=(
                        "/usr/bin/python3",
                        "-c",
                        f"import base64,os,sys;sys.stdout.buffer.write({expression})",
                    ),
                )
                with mock.patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(credential_directory)},
                    clear=False,
                ):
                    self.assertEqual(
                        run(descriptor, attempt_output, attempt_result),
                        1,
                    )
                published = b"".join(
                    path.read_bytes()
                    for path in attempt_output.iterdir()
                    if path.is_file()
                )
                self.assertNotIn(self.SECRET, published)
                self.assertNotIn(base64.b64encode(self.SECRET), published)
                result = json.loads(attempt_result.read_text(encoding="utf-8"))
                self.assertTrue(result["incomplete_reporting"])
                chunks = [
                    json.loads(
                        (attempt_output / item["file_name"]).read_text(
                            encoding="utf-8"
                        )
                    )
                    for item in result["chunk_manifest"]
                ]
                failures = [
                    failure
                    for chunk in chunks
                    for failure in chunk["failures"]
                ]
                self.assertTrue(
                    any(
                        failure["message"]
                        == "test output contained protected credential material"
                        for failure in failures
                    )
                )

    def test_exact_secret_directory_artifact_content_paths_and_boundaries_are_blocked(
        self,
    ) -> None:
        credential_directory = self.root / "artifact-credentials"
        credential_directory.mkdir(mode=0o700)
        credential = credential_directory / self.CREDENTIAL_NAME
        credential.write_bytes(self.SECRET)
        credential.chmod(0o400)

        for label in ("boundary-content", "secret-path"):
            with self.subTest(label=label):
                reports = self.repository / f"reports-{label}"
                reports.mkdir()
                if label == "boundary-content":
                    split_at = 1024 * 1024 - 7
                    (reports / "payload.bin").write_bytes(
                        b"x" * split_at + self.SECRET + b"tail"
                    )
                else:
                    (reports / (self.SECRET.decode("ascii") + ".txt")).write_text(
                        "safe content",
                        encoding="utf-8",
                    )
                descriptor = replace(
                    self.descriptor(
                        attempt_id=f"attempt-directory-{label}",
                    ),
                    artifacts=(
                        {
                            "name": f"reports-{label}",
                            "path": reports.relative_to(self.repository).as_posix(),
                            "kind": "directory",
                            "required": True,
                            "max_bytes": 4 * 1024 * 1024,
                        },
                    ),
                )
                output = self.root / f"directory-output-{label}"
                output.mkdir(mode=0o700)
                result_path = output / "result.json"
                with mock.patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(credential_directory)},
                    clear=False,
                ):
                    self.assertEqual(run(descriptor, output, result_path), 1)
                result = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertFalse(
                    any(
                        item["kind"] == "directory"
                        for item in result["artifact_sources"]
                    )
                )
                failures = [
                    failure
                    for item in result["chunk_manifest"]
                    for failure in json.loads(
                        (output / item["file_name"]).read_text(encoding="utf-8")
                    )["failures"]
                ]
                self.assertTrue(
                    any("secret material" in failure["message"] for failure in failures)
                )

    def test_root_directory_repackaging_rechecks_exact_credential_sequences(
        self,
    ) -> None:
        self.register()
        reports = self.repository / "root-repackaged-reports"
        reports.mkdir()
        split_at = 1024 * 1024 - 5
        (reports / "payload.bin").write_bytes(
            b"z" * split_at + self.SECRET + b"tail"
        )
        descriptor = replace(
            self.descriptor(attempt_id="attempt-root-directory-repackage"),
            artifacts=(
                {
                    "name": "root-repackaged-reports",
                    "path": reports.relative_to(self.repository).as_posix(),
                    "kind": "directory",
                    "required": True,
                    "max_bytes": 4 * 1024 * 1024,
                },
            ),
        )
        runtime_id = SystemdTestAttemptManager._runtime_id(descriptor)
        lease = self.provider.provision(descriptor, runtime_id=runtime_id)

        attempt_root = self.root / "root-repackage-attempts"
        output = attempt_root / runtime_id / "output"
        output.mkdir(mode=0o700, parents=True)
        launch = attempt_root / runtime_id / "launch.json"
        launch.write_text(
            json.dumps({"descriptor": descriptor.to_document()}),
            encoding="utf-8",
        )
        archive = output / "untrusted-directory.tar"
        with archive.open("wb") as destination:
            evidence = package_directory(
                reports,
                destination,
                expected_uid=self.owner_uid,
                maximum_bytes=4 * 1024 * 1024,
            )
        artifact_id = "artifact-" + hashlib.sha256(
            b"root-repackage-exact-secret"
        ).hexdigest()[:32]
        handle = f"test-artifact://{artifact_id}/{evidence.sha256}"
        result = {
            "artifact_sources": [
                {
                    "artifact_id": artifact_id,
                    "storage_handle": handle,
                    "kind": "directory",
                    "scope": "output",
                    "relative_path": archive.name,
                    "packaged_from": reports.relative_to(self.repository).as_posix(),
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                }
            ]
        }
        manager = SystemdTestAttemptManager(
            attempt_root=attempt_root,
            artifact_root=self.root / "root-repackage-artifacts",
            credential_provider=BrokerOperationalCredentialProvider(
                registry_path=self.registry,
                material_root=self.material_root,
                runtime_root=self.runtime_root,
                expected_authority_uid=self.owner_uid,
            ),
        )
        with self.assertRaisesRegex(
            TestStoreContractError,
            "secret material",
        ):
            manager._collect_result_artifacts(runtime_id, result)
        self.provider.cleanup(
            runtime_id=runtime_id,
            descriptor_fingerprint=lease.descriptor_fingerprint,
            reason="test",
        )

    def test_authority_uid_is_compatibility_metadata_not_local_authorization(self) -> None:
        shared_account = AdministratorOperationalCredentialStore(
            registry_path=self.registry,
            material_root=self.material_root,
            expected_authority_uid=self.owner_uid + 1,
        )
        self.assertEqual(shared_account.load().authority_generation, 0)

    def test_administrator_cli_prints_only_public_binding_metadata(self) -> None:
        binding = self.register()
        skill_root = Path(__file__).resolve().parents[3]
        repository_root = skill_root.parent.parent
        configured_skill = repository_root / "skills" / skill_root.name
        script = repository_root / "scripts" / "manage_universal_test_credentials.py"
        try:
            source_tree_matches = configured_skill.samefile(skill_root)
        except OSError:
            source_tree_matches = False
        if not source_tree_matches or not script.is_file():
            self.skipTest(
                "repository-only CLI manage_universal_test_credentials.py is "
                "unavailable in a standalone skill copy"
            )
        specification = importlib.util.spec_from_file_location(
            "test_manage_universal_test_credentials",
            script,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)

        class FakeStore:
            def register(self, **_values):
                return binding

        output = io.StringIO()
        with (
            mock.patch.object(
                module,
                "AdministratorOperationalCredentialStore",
                return_value=FakeStore(),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(
                module.main(
                    [
                        "register",
                        "--alias",
                        self.ALIAS,
                        "--repository-id",
                        "repo-skydive",
                        "--repository-generation",
                        "7",
                        "--target",
                        "health-sweep-post-deploy",
                        "--owner-uid",
                        str(self.owner_uid),
                        "--credential-name",
                        self.CREDENTIAL_NAME,
                        "--max-ttl-seconds",
                        "120",
                        "--source-env-file",
                        str(self.source),
                        "--source-key",
                        "ADMIN_TOKEN",
                    ]
                ),
                0,
            )
        payload = output.getvalue().encode("utf-8")
        self.assertNotIn(self.SECRET, payload)
        self.assertNotIn(str(self.source).encode("utf-8"), payload)
        self.assertEqual(json.loads(payload)["alias"], self.ALIAS)


if __name__ == "__main__":
    unittest.main()
