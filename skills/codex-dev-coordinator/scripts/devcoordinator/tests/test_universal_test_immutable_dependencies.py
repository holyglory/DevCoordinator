from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zipfile

from devcoordinator import universal_test_runtime, universal_test_snapshot
from devcoordinator.universal_test_contract import parse_test_manifest
from devcoordinator.universal_test_runner import _immutable_python_launch_executable
from devcoordinator.universal_test_runtime import (
    _IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT,
    SystemdTestAttemptManager,
    TestAttemptDescriptor,
)
from devcoordinator.universal_test_snapshot_service import RootSnapshotService
from devcoordinator.universal_test_snapshot import (
    GitSnapshotSource,
    SnapshotMaterializationRequest,
)
from devcoordinator.universal_test_store import TestStoreConflict


def digest(path: Path) -> str:
    return universal_test_snapshot.snapshot_regular_file_digest(
        path.read_bytes(), executable=bool(path.stat().st_mode & 0o111)
    )


class ImmutableDependencyBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.original = self.base / "repository"
        self.materialized = self.base / "snapshot"
        self.original.mkdir()
        self.materialized.mkdir()

        (self.original / "uv.lock").write_text("python-lock\n", encoding="utf-8")
        (self.materialized / "uv.lock").write_text(
            "python-lock\n", encoding="utf-8"
        )
        python = self.original / ".venv-v2" / "bin" / "python"
        python.parent.mkdir(parents=True)
        python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        python.chmod(0o755)
        (self.original / ".venv-v2" / "pyvenv.cfg").write_text(
            "home = /usr/bin\n", encoding="utf-8"
        )
        dist_info = (
            self.original
            / ".venv-v2"
            / "lib"
            / "python3.13"
            / "site-packages"
            / "demo-1.0.dist-info"
        )
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(
            "Name: demo\nVersion: 1.0\n", encoding="utf-8"
        )
        (dist_info / "RECORD").write_text(
            "demo.py,,\n", encoding="utf-8"
        )

        (self.original / "ui" / "node_modules").mkdir(parents=True)
        (self.materialized / "ui").mkdir()
        (self.original / "ui" / "package-lock.json").write_text(
            '{"lockfileVersion":3}\n', encoding="utf-8"
        )
        (self.materialized / "ui" / "package-lock.json").write_text(
            '{"lockfileVersion":3}\n', encoding="utf-8"
        )
        (self.original / "ui" / "node_modules" / ".package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{}}\n', encoding="utf-8"
        )
        self.provenance = {
            "complete": True,
            "content_fingerprint": "a" * 64,
            "manifest_fingerprint": "b" * 64,
            "dependency_locks": {
                "uv.lock": digest(self.original / "uv.lock"),
                "ui/package-lock.json": digest(
                    self.original / "ui" / "package-lock.json"
                ),
            },
            "toolchain": {},
        }

    def derive(self, launch, *, account_uids=(), full=False):
        result = RootSnapshotService._immutable_dependencies(
            launch=launch,
            original_root=str(self.original),
            materialized_root=str(self.materialized),
            source_provenance=self.provenance,
            owner_uid=os.geteuid(),
            account_uids=account_uids,
        )
        return result if full else result[:3]

    def descriptor(self, *bindings) -> TestAttemptDescriptor:
        return TestAttemptDescriptor(
            execution_id="execution-dependencies",
            target_id="target-dependencies",
            run_id="run-dependencies",
            repository_id="repo-dependencies",
            repository_generation=1,
            owner_uid=os.geteuid(),
            generation=1,
            source_mode="immutable",
            snapshot_id="snapshot-" + "c" * 32,
            original_root=str(self.original),
            temporary_root=None,
            execution_root=str(self.materialized),
            worktree_key=str(self.materialized),
            target_name="immutable-dependencies",
            shard_index=0,
            shard_count=1,
            argv=(".venv-v2/bin/python", "-c", "pass"),
            cwd=".",
            environment={},
            driver="automation",
            reporter="automation-events",
            artifacts=(),
            fixtures=(),
            network="none",
            ttl_seconds=30,
            source_provenance=self.provenance,
            dependency_bindings=tuple(bindings),
        )

    def staged(self, *bindings):
        return tuple(
            RootSnapshotService._stage_python_dependency(
                binding,
                materialized_root=self.materialized,
            )
            for binding in bindings
        )

    def test_python_and_node_bindings_are_derived_from_locks_not_manifest_mounts(self) -> None:
        python_bindings, python_executable, _dotnet = self.derive(
            {
                "driver": "pytest",
                "cwd": ".",
                "argv": ["{python}", "-m", "pytest"],
            }
        )
        node_bindings, _unused, _dotnet = self.derive(
            {
                "driver": "automation",
                "cwd": "ui",
                "argv": ["npm", "test"],
            }
        )

        self.assertEqual(python_executable, ".venv-v2/bin/python")
        self.assertEqual(python_bindings[0]["kind"], "python-venv")
        self.assertEqual(python_bindings[0]["locks"], {
            "uv.lock": self.provenance["dependency_locks"]["uv.lock"]
        })
        self.assertEqual(node_bindings[0]["kind"], "node-modules")
        self.assertEqual(node_bindings[0]["destination"], "ui/node_modules")
        self.assertFalse((self.materialized / ".venv-v2").exists())
        self.assertFalse((self.materialized / "ui" / "node_modules").exists())
        rewritten = RootSnapshotService._argv(
            ["{python}", "-m", "pytest"],
            execution_id="execution-dependencies",
            shard_index=0,
            shard_count=1,
            python_executable=python_executable,
        )
        self.assertEqual(rewritten[0], ".venv-v2/bin/python")
        staged_python_bindings = self.staged(*python_bindings)
        round_trip = TestAttemptDescriptor.from_document(
            self.descriptor(*staged_python_bindings).to_document()
        )
        self.assertEqual(
            round_trip.dependency_bindings,
            self.descriptor(*staged_python_bindings).dependency_bindings,
        )
        before_fingerprint = round_trip.fingerprint
        metadata = (
            self.original
            / ".venv-v2/lib/python3.13/site-packages/demo-1.0.dist-info/METADATA"
        )
        metadata.write_text("Name: demo\nVersion: 1.1\n", encoding="utf-8")
        changed_bindings, _python, _dotnet = self.derive(
            {
                "driver": "pytest",
                "cwd": ".",
                "argv": ["{python}", "-m", "pytest"],
            }
        )
        self.assertNotEqual(
            before_fingerprint,
            self.descriptor(*changed_bindings).fingerprint,
        )

    def test_repository_sqlite_state_is_identity_pinned_and_bound_read_only(self) -> None:
        state = self.original / ".product-delivery"
        state.mkdir()
        database = state / "delivery.sqlite3"
        database.write_bytes(b"live authoritative state")
        bindings = RootSnapshotService._repository_state_bindings(
            {
                "state_handles": [
                    {
                        "name": "delivery-state",
                        "kind": "sqlite",
                        "path": ".product-delivery/delivery.sqlite3",
                        "environment": "DELIVERY_STATE_DATABASE",
                    }
                ]
            },
            original_root=str(self.original),
        )
        descriptor = replace(self.descriptor(), state_bindings=bindings)
        output = self.base / "output"
        output.mkdir()

        round_trip = TestAttemptDescriptor.from_document(descriptor.to_document())
        environment = SystemdTestAttemptManager._state_environment(round_trip)
        properties = SystemdTestAttemptManager._systemd_properties(
            round_trip,
            execution_root=self.materialized,
            output_root=output,
        )

        self.assertEqual(
            environment,
            {
                "DELIVERY_STATE_DATABASE": str(state / "delivery.sqlite3")
            },
        )
        self.assertIn(
            "--property=BindReadOnlyPaths=" + str(state),
            properties,
        )
        self.assertFalse((self.materialized / ".product-delivery").exists())

        database.unlink()
        database.write_bytes(b"substituted state")
        with self.assertRaisesRegex(TestStoreConflict, "changed after planning"):
            SystemdTestAttemptManager._state_environment(round_trip)

    def test_declared_installed_skill_is_pinned_and_bound_without_exposing_home(self) -> None:
        source = self.base / "source" / "formal-web-ui-verification"
        scripts = source / "scripts"
        scripts.mkdir(parents=True)
        (source / "SKILL.md").write_text("# Formal verifier\n", encoding="utf-8")
        verifier = scripts / "formal_web_ui_verify.mjs"
        verifier.write_text("export const version = 1;\n", encoding="utf-8")
        verifier.chmod(0o755)
        destination = self.base / "installed" / "formal-web-ui-verification"
        destination.parent.mkdir()
        destination.symlink_to(source, target_is_directory=True)
        launch = {
            "environment": {"FORMAL_WEB_UI_SKILL_DIR": str(destination)}
        }
        with mock.patch.object(
            RootSnapshotService,
            "_installed_skill_destination",
            return_value=True,
        ):
            bindings = RootSnapshotService._installed_skill_bindings(launch)
        with mock.patch.object(
            universal_test_runtime,
            "_installed_skill_destination",
            return_value=True,
        ):
            descriptor = replace(
                self.descriptor(),
                environment=dict(launch["environment"]),
                skill_bindings=bindings,
            )
            round_trip = TestAttemptDescriptor.from_document(
                descriptor.to_document()
            )
        output = self.base / "skill-output"
        output.mkdir()

        with mock.patch.object(
            universal_test_runtime,
            "_installed_skill_destination",
            return_value=True,
        ):
            properties = SystemdTestAttemptManager._systemd_properties(
                round_trip,
                execution_root=self.materialized,
                output_root=output,
            )

        self.assertIn(
            "--property=BindReadOnlyPaths="
            + f"{source}:{destination}",
            properties,
        )
        self.assertEqual(len(round_trip.skill_bindings), 1)
        verifier.write_text("export const version = 2;\n", encoding="utf-8")
        with (
            mock.patch.object(
                universal_test_runtime,
                "_installed_skill_destination",
                return_value=True,
            ),
            self.assertRaisesRegex(TestStoreConflict, "content changed"),
        ):
            SystemdTestAttemptManager._systemd_properties(
                round_trip,
                execution_root=self.materialized,
                output_root=output,
            )

    def test_preferred_python_environment_wins_over_retained_legacy_environment(self) -> None:
        legacy_python = self.original / ".venv" / "bin" / "python"
        legacy_python.parent.mkdir(parents=True)
        legacy_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        legacy_python.chmod(0o755)
        (self.original / ".venv" / "pyvenv.cfg").write_text(
            "home = /usr/bin\n", encoding="utf-8"
        )

        bindings, executable, _dotnet = self.derive(
            {
                "driver": "pytest",
                "cwd": ".",
                "argv": ["{python}", "-m", "pytest"],
            }
        )

        self.assertEqual(executable, ".venv-v2/bin/python")
        self.assertEqual(bindings[0]["destination"], ".venv-v2")

    def test_lock_digest_comes_from_a_real_snapshot_scan(self) -> None:
        manifest_document = {
            "schema_version": 4,
            "defaults": {
                "timeout_seconds": 30,
                "network": "none",
                "environment": {},
            },
            "global_inputs": [".codex/tests.json"],
            "intents": {
                "manual": {"source_mode": "immutable", "allow_reuse": False}
            },
            "fixtures": {},
            "targets": {
                "unit": {
                    "driver": "automation",
                    "reporter": "automation-events",
                    "argv": ["./test"],
                    "cwd": ".",
                    "inputs": ["**"],
                    "depends_on": [],
                    "intents": ["manual"],
                }
            },
            "evidence_policies": {},
        }
        manifest_path = self.original / ".codex" / "tests.json"
        manifest_path.parent.mkdir()
        manifest_path.write_text(json.dumps(manifest_document), encoding="utf-8")
        (self.original / ".gitignore").write_text(
            ".venv-v2/\nui/node_modules/\n", encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q"], cwd=self.original, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=self.original,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "DevCoordinator Test"],
            cwd=self.original,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.original, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "snapshot fixture"],
            cwd=self.original,
            check=True,
        )
        manifest = parse_test_manifest(
            manifest_document, repository_root=self.original
        )
        scan = GitSnapshotSource(enforce_process_uid=False).scan(
            SnapshotMaterializationRequest(
                repository_id="repo-scan-lock",
                original_root=str(self.original),
                temporary_root=None,
                manifest_fingerprint=manifest.fingerprint,
                intent="manual",
                owner_uid=os.geteuid(),
            )
        )
        self.assertEqual(
            scan.dependency_locks["uv.lock"],
            digest(self.original / "uv.lock"),
        )

    def test_stale_locks_and_substituted_dependency_roots_fail_before_launch(self) -> None:
        python_bindings, _python, _dotnet = self.derive(
            {
                "driver": "pytest",
                "cwd": ".",
                "argv": ["{python}", "-m", "pytest"],
            }
        )
        (self.materialized / "uv.lock").write_text("stale\n", encoding="utf-8")
        with self.assertRaisesRegex(TestStoreConflict, "lock changed"):
            self.derive(
                {
                    "driver": "pytest",
                    "cwd": ".",
                    "argv": ["{python}", "-m", "pytest"],
                }
            )
        (self.materialized / "uv.lock").write_text(
            "python-lock\n", encoding="utf-8"
        )
        node_modules = self.original / "ui" / "node_modules"
        moved = self.base / "substituted-node-modules"
        node_modules.rename(moved)
        node_modules.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(TestStoreConflict, "dependency root.*unsafe"):
            self.derive(
                {
                    "driver": "automation",
                    "cwd": "ui",
                    "argv": ["npm", "test"],
                }
            )

        original_venv = self.original / ".venv-v2"
        replaced_venv = self.base / "original-venv"
        original_venv.rename(replaced_venv)
        shutil.copytree(replaced_venv, original_venv)
        attempt_root = self.base / "substitution-attempt"
        attempt_root.mkdir()
        (attempt_root / "uv.lock").write_text("python-lock\n", encoding="utf-8")
        with self.assertRaisesRegex(TestStoreConflict, "root was substituted"):
            SystemdTestAttemptManager._prepare_dependency_mountpoints(
                self.descriptor(*self.staged(*python_bindings)),
                execution_root=attempt_root,
                owner_gid=os.getegid(),
            )

    def test_absolute_python_toolchain_link_is_recorded_and_revalidated(self) -> None:
        uid = os.geteuid()
        python_store = self.base / "developer-home" / ".local/share/uv/python"
        toolchain = python_store / "cpython-3.13.1-linux-x86_64-gnu"
        alias = python_store / "cpython-3.13-linux-x86_64-gnu"
        executable = toolchain / "bin" / "python3.13"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        standard_library = toolchain / "lib" / "python3.13"
        standard_library.mkdir(parents=True)
        for name in ("os.py", "site.py", "sysconfig.py"):
            (standard_library / name).write_text(f"# {name}\n", encoding="utf-8")
        alias.symlink_to(toolchain.name, target_is_directory=True)
        environment_python = self.original / ".venv-v2" / "bin" / "python"
        environment_python.unlink()
        environment_python.symlink_to(alias / "bin" / "python3.13")
        account = SimpleNamespace(
            pw_uid=uid,
            pw_gid=os.getegid(),
            pw_dir=str(self.base / "developer-home"),
        )
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            return_value=account,
        ):
            bindings, _python, _dotnet = self.derive(
                {
                    "driver": "pytest",
                    "cwd": ".",
                    "argv": ["{python}", "-m", "pytest"],
                },
                account_uids=(uid,),
            )
        binding = bindings[0]
        self.assertEqual(
            binding["toolchain"]["link_target"],
            str(alias / "bin" / "python3.13"),
        )
        descriptor = self.descriptor(*self.staged(*bindings))
        attempt_root = self.base / "python-toolchain-attempt"
        attempt_root.mkdir()
        (attempt_root / "uv.lock").write_text("python-lock\n", encoding="utf-8")
        SystemdTestAttemptManager._prepare_dependency_mountpoints(
            descriptor,
            execution_root=attempt_root,
            owner_gid=os.getegid(),
        )
        properties = SystemdTestAttemptManager._systemd_properties(
            descriptor,
            execution_root=attempt_root,
            output_root=self.base / "python-output",
        )
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{self.base / 'immutable-python-toolchain'}:"
            f"{_IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT}",
            properties,
        )
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{self.base / 'immutable-python-toolchain'}:{alias}",
            properties,
        )
        self.assertEqual(
            _immutable_python_launch_executable(descriptor),
            str(_IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT / "bin" / "python3.13"),
        )
        replacement_root = toolchain.parent / "replacement"
        replacement = replacement_root / "bin" / "python3.13"
        replacement.parent.mkdir(parents=True)
        replacement.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        replacement.chmod(0o755)
        alias.unlink()
        alias.symlink_to(replacement_root.name, target_is_directory=True)
        with self.assertRaisesRegex(TestStoreConflict, "toolchain link changed"):
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=self.base / "python-output",
            )

    def test_system_python_alias_is_validated_without_copying_system_root(self) -> None:
        system_root = self.base / "system-python"
        executable = system_root / "bin" / "python3.13"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        alias = system_root / "bin" / "python3"
        alias.symlink_to(executable.name)
        standard_library = system_root / "lib" / "python3.13"
        standard_library.mkdir(parents=True)
        for name in ("os.py", "site.py", "sysconfig.py"):
            (standard_library / name).write_text(f"# {name}\n", encoding="utf-8")
        environment_python = self.original / ".venv-v2" / "bin" / "python"
        environment_python.unlink()
        environment_python.symlink_to(alias)
        roots = frozenset({system_root})

        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service."
                "_SYSTEM_PYTHON_TOOLCHAIN_ROOTS",
                roots,
            ),
            mock.patch(
                "devcoordinator.universal_test_runtime."
                "_SYSTEM_PYTHON_TOOLCHAIN_ROOTS",
                roots,
            ),
            mock.patch(
                "devcoordinator.universal_test_runner."
                "_SYSTEM_PYTHON_TOOLCHAIN_ROOTS",
                roots,
            ),
        ):
            bindings, _python, _dotnet = self.derive(
                {
                    "driver": "automation",
                    "cwd": ".",
                    "argv": ["{python}", "harness.py", "node-suite"],
                }
            )
            binding = bindings[0]
            self.assertEqual(binding["toolchain"]["source_root"], str(system_root))
            self.assertEqual(
                binding["toolchain"]["resolved_executable"], str(executable)
            )
            descriptor = self.descriptor(*self.staged(*bindings))
            SystemdTestAttemptManager._prepare_dependency_mountpoints(
                descriptor,
                execution_root=self.materialized,
                owner_gid=os.getegid(),
            )
            properties = SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=self.materialized,
                output_root=self.base / "system-python-output",
            )
            self.assertFalse(
                any(
                    str(_IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT) in property_value
                    for property_value in properties
                )
            )
            self.assertEqual(
                _immutable_python_launch_executable(descriptor), str(executable)
            )
            replacement = system_root / "bin" / "python3.14"
            replacement.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            replacement.chmod(0o755)
            alias.unlink()
            alias.symlink_to(replacement.name)
            with self.assertRaisesRegex(TestStoreConflict, "toolchain link changed"):
                SystemdTestAttemptManager._systemd_properties(
                    descriptor,
                    execution_root=self.materialized,
                    output_root=self.base / "system-python-output",
                )

    def test_runtime_creates_only_empty_read_only_dependency_mount_destinations(self) -> None:
        python_bindings, _python, _dotnet = self.derive(
            {
                "driver": "pytest",
                "cwd": ".",
                "argv": ["{python}", "-m", "pytest"],
            }
        )
        node_bindings, _node, _dotnet = self.derive(
            {
                "driver": "automation",
                "cwd": "ui",
                "argv": ["npm", "test"],
            }
        )
        attempt_root = self.base / "attempts" / "private-attempt"
        attempt_root.mkdir(parents=True)
        (attempt_root / "uv.lock").write_text("python-lock\n", encoding="utf-8")
        (attempt_root / "ui").mkdir()
        (attempt_root / "ui" / "package-lock.json").write_text(
            '{"lockfileVersion":3}\n', encoding="utf-8"
        )
        source_native = self.original / ".venv-v2/lib/python3.13/site-packages/native.so"
        source_native.write_bytes(b"native")
        source_native.chmod(0o400)
        staged_bindings = self.staged(*python_bindings, *node_bindings)
        descriptor = self.descriptor(*staged_bindings)
        descriptor = replace(
            descriptor, supplementary_gids=(1003, 1004, 65534)
        )
        SystemdTestAttemptManager._prepare_dependency_mountpoints(
            descriptor,
            execution_root=attempt_root,
            owner_gid=os.getegid(),
        )
        self.assertEqual(list((attempt_root / ".venv-v2").iterdir()), [])
        self.assertEqual(list((attempt_root / "ui" / "node_modules").iterdir()), [])
        properties = SystemdTestAttemptManager._systemd_properties(
            descriptor,
            execution_root=attempt_root,
            output_root=self.base / "output",
        )
        self.assertIn("--property=ProtectHome=tmpfs", properties)
        self.assertIn(
            "--property=SupplementaryGroups=1003 1004 65534", properties
        )
        python_staged = Path(str(staged_bindings[0]["staged_root"]))
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{python_staged}:{attempt_root / '.venv-v2'}",
            properties,
        )
        staged_native = python_staged / "lib/python3.13/site-packages/native.so"
        self.assertTrue(stat.S_IMODE(staged_native.stat().st_mode) & stat.S_IRUSR)
        self.assertEqual(stat.S_IMODE(source_native.stat().st_mode), 0o400)
        staged_marker = python_staged / "pyvenv.cfg"
        staged_marker_payload = staged_marker.read_bytes()
        staged_marker.chmod(0o644)
        staged_marker.write_text("tampered = true\n", encoding="utf-8")
        with self.assertRaisesRegex(
            TestStoreConflict, "staged immutable Python dependency identity differs"
        ):
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=self.base / "output",
            )
        staged_marker.write_bytes(staged_marker_payload)
        staged_marker.chmod(0o444)
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{self.original / 'ui' / 'node_modules'}:"
            f"{attempt_root / 'ui' / 'node_modules'}",
            properties,
        )
        dependency_properties = [
            value
            for value in properties
            if value.startswith("--property=BindReadOnlyPaths=")
        ]
        self.assertNotIn("--property=BindReadOnlyPaths=/home", dependency_properties)
        self.assertFalse(
            any(value.startswith("--property=BindPaths=/home") for value in properties)
        )

        (self.original / ".venv-v2" / "pyvenv.cfg").write_text(
            "changed = true\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            TestStoreConflict, "installation changed"
        ):
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=self.base / "output",
            )

    def test_dotnet_cache_is_narrow_lock_bound_and_published_as_local_source(self) -> None:
        package_lock = self.original / "src" / "packages.lock.json"
        package_lock.parent.mkdir()
        lock_document = {
            "version": 1,
            "dependencies": {
                ".NETCoreApp,Version=v8.0": {
                    "GlobalFinance.GfCache": {
                        "type": "Project",
                        "dependencies": {"System.IO.Hashing": "[10.0.5, )"},
                    },
                    "System.IO.Hashing": {
                        "type": "Direct",
                        "resolved": "10.0.5",
                        "contentHash": "locked-content-hash==",
                    }
                }
            },
        }
        package_lock.write_text(json.dumps(lock_document), encoding="utf-8")
        materialized_lock = self.materialized / "src" / "packages.lock.json"
        materialized_lock.parent.mkdir()
        materialized_lock.write_text(json.dumps(lock_document), encoding="utf-8")
        self.provenance["dependency_locks"]["src/packages.lock.json"] = digest(
            package_lock
        )
        owner_uid = os.geteuid()
        alternate_uid = owner_uid + 101
        home = self.base / "owner-home"
        alternate_home = self.base / "alternate-home"
        (home / ".nuget" / "packages").mkdir(parents=True)
        packages = alternate_home / ".nuget" / "packages"
        package_root = packages / "system.io.hashing" / "10.0.5"
        package_root.mkdir(parents=True)
        archive = package_root / "system.io.hashing.10.0.5.nupkg"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(
                "System.IO.Hashing.nuspec",
                '<package><metadata><id>System.IO.Hashing</id>'
                '<version>10.0.5</version></metadata></package>',
            )
        (package_root / "system.io.hashing.10.0.5.nupkg.sha512").write_text(
            base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode(),
            encoding="utf-8",
        )
        (package_root / ".nupkg.metadata").write_text(
            json.dumps(
                {
                    "version": 2,
                    "contentHash": "locked-content-hash==",
                    "source": "unit-test",
                }
            ),
            encoding="utf-8",
        )
        dotnet = home / ".dotnet" / "dotnet"
        dotnet.parent.mkdir()
        dotnet.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        dotnet.chmod(0o755)
        def account(uid):
            selected_home = home if uid == owner_uid else alternate_home
            return SimpleNamespace(pw_uid=uid, pw_gid=uid, pw_dir=str(selected_home))

        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=account,
        ):
            bindings, _python, dotnet_executable = self.derive(
                {
                    "driver": "dotnet",
                    "cwd": ".",
                    "argv": ["{dotnet}", "test", "src/App.sln"],
                },
                account_uids=(owner_uid, alternate_uid),
            )
        unrelated = packages / "unrelated.package" / "9.9.9"
        unrelated.mkdir(parents=True)
        (unrelated / "unrelated.package.9.9.9.nupkg.sha512").write_text(
            "unrelated-archive-sha==", encoding="utf-8"
        )
        (unrelated / ".nupkg.metadata").write_text(
            '{"contentHash":"unrelated-content=="}', encoding="utf-8"
        )
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=account,
        ):
            unchanged_bindings, _python, unchanged_dotnet = self.derive(
                {
                    "driver": "dotnet",
                    "cwd": ".",
                    "argv": ["{dotnet}", "test", "src/App.sln"],
                },
                account_uids=(owner_uid, alternate_uid),
            )
        self.assertEqual(unchanged_bindings, bindings)
        self.assertEqual(unchanged_dotnet, dotnet_executable)
        self.assertIn("packages.lock.json", universal_test_snapshot._LOCK_NAMES)
        self.assertEqual(bindings[0]["kind"], "dotnet-packages")
        self.assertEqual(bindings[0]["source_root"], str(packages))
        self.assertEqual(
            bindings[0]["toolchain"]["installation_kind"],
            "dotnet-toolchain",
        )
        self.assertEqual(dotnet_executable, str(dotnet))
        rewritten = RootSnapshotService._argv(
            ["{dotnet}", "test", "src/App.sln"],
            execution_id="execution-dotnet",
            shard_index=0,
            shard_count=1,
            dotnet_executable=dotnet_executable,
        )
        self.assertEqual(rewritten[0], str(dotnet))
        self.assertEqual(
            bindings[0]["destination"],
            ".devcoordinator-dependencies/nuget-source",
        )
        self.assertEqual(bindings[0]["installation_kind"], "nuget-package-source")

        attempt_root = self.base / "dotnet-attempt"
        (attempt_root / "src").mkdir(parents=True)
        (attempt_root / "src" / "packages.lock.json").write_text(
            json.dumps(lock_document), encoding="utf-8"
        )
        local_accounts = [
            SimpleNamespace(pw_uid=owner_uid, pw_dir=str(home)),
            SimpleNamespace(pw_uid=alternate_uid, pw_dir=str(alternate_home)),
        ]
        with mock.patch(
            "devcoordinator.universal_test_runtime.pwd.getpwall",
            return_value=local_accounts,
        ):
            descriptor = self.descriptor(*bindings)
            descriptor = replace(
                descriptor,
                argv=(str(dotnet), "test", "src/App.sln"),
                driver="dotnet",
                reporter="trx",
            )
        SystemdTestAttemptManager._prepare_dependency_mountpoints(
            descriptor,
            execution_root=attempt_root,
            owner_gid=os.getegid(),
        )
        state = self.base / "dotnet-state"
        state.mkdir()
        manager = SystemdTestAttemptManager(
            attempt_root=self.base / "attempt-store",
            artifact_root=self.base / "artifact-store",
        )
        with mock.patch(
            "devcoordinator.universal_test_runtime.pwd.getpwall",
            return_value=local_accounts,
        ):
            manager._stage_dotnet_package_source(
                descriptor,
                state=state,
                execution_root=attempt_root,
            )
            staged_package = (
                state / "nuget-source" / "system.io.hashing" / "10.0.5"
            )
            expected_staged_files = {
                ".nupkg.metadata",
                "system.io.hashing.10.0.5.nupkg",
                "system.io.hashing.10.0.5.nupkg.sha512",
                "system.io.hashing.nuspec",
            }
            self.assertEqual(
                {item.name for item in staged_package.iterdir()},
                expected_staged_files,
            )
            self.assertTrue(
                all(
                    item.is_file() and stat.S_IMODE(item.stat().st_mode) == 0o644
                    for item in staged_package.iterdir()
                )
            )
            nuspec = staged_package / "system.io.hashing.nuspec"
            staged_nuspec = nuspec.read_bytes()
            self.assertIn(b"System.IO.Hashing", staged_nuspec)
            nuspec.write_bytes(b"<package />")
            with self.assertRaisesRegex(
                TestStoreConflict,
                "staged package manifest is invalid",
            ):
                manager._validated_staged_dotnet_source(
                    descriptor,
                    bindings[0],
                    state=state,
                )
            nuspec.write_bytes(staged_nuspec)
            nuspec.chmod(0o644)
            launch, _result = manager._publish_runner_launch(
                descriptor,
                state=state,
                execution_root=attempt_root,
                owner_gid=os.getegid(),
            )
            properties = SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=state / "output",
            )
        self.assertIn(
            f"--property=BindReadOnlyPaths={home / '.dotnet'}",
            properties,
        )
        self.assertNotIn(
            f"--property=BindReadOnlyPaths={home}",
            properties,
        )
        self.assertIn(
            "--property=BindReadOnlyPaths="
            f"{state / 'nuget-source'}:"
            f"{attempt_root / '.devcoordinator-dependencies' / 'nuget-source'}",
            properties,
        )
        document = json.loads(launch.read_text(encoding="utf-8"))
        self.assertEqual(
            document["descriptor"]["environment"]["DEVCOORDINATOR_NUGET_SOURCE"],
            str(attempt_root / ".devcoordinator-dependencies" / "nuget-source"),
        )

        # NuGet's raw archive SHA is intentionally different from the lock
        # content hash above.  Changing the metadata hash must still be
        # rejected with the exact package identity, both at launch
        # revalidation and when selecting a cache for a fresh descriptor.
        metadata = package_root / ".nupkg.metadata"
        metadata.write_text(
            json.dumps(
                {
                    "version": 2,
                    "contentHash": "different-package-content==",
                    "source": "unit-test",
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            TestStoreConflict,
            r"system\.io\.hashing/10\.0\.5 source does not match recorded locks",
        ):
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=self.base / "dotnet-output",
            )
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=account,
        ):
            with self.assertRaisesRegex(
                TestStoreConflict,
                r"uid .*package system\.io\.hashing/10\.0\.5",
            ):
                self.derive(
                    {
                        "driver": "dotnet",
                        "cwd": ".",
                        "argv": ["{dotnet}", "test", "src/App.sln"],
                    },
                    account_uids=(owner_uid, alternate_uid),
                )

        metadata.write_text(
            json.dumps(
                {
                    "version": 2,
                    "contentHash": "locked-content-hash==",
                    "source": "unit-test",
                }
            ),
            encoding="utf-8",
        )
        original_archive = archive.read_bytes()
        archive.write_bytes(original_archive + b"-tampered")
        with self.assertRaisesRegex(
            TestStoreConflict, "archive does not match its checksum"
        ):
            SystemdTestAttemptManager._systemd_properties(
                descriptor,
                execution_root=attempt_root,
                output_root=state / "output",
            )
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=account,
        ):
            with self.assertRaisesRegex(
                TestStoreConflict, r"archive does not match its checksum"
            ):
                self.derive(
                    {
                        "driver": "dotnet",
                        "cwd": ".",
                        "argv": ["{dotnet}", "test", "src/App.sln"],
                    },
                    account_uids=(owner_uid, alternate_uid),
                )
        archive.write_bytes(original_archive)
        archive.unlink()
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=account,
        ):
            with self.assertRaisesRegex(
                TestStoreConflict, r"missing source identity files"
            ):
                self.derive(
                    {
                        "driver": "dotnet",
                        "cwd": ".",
                        "argv": ["{dotnet}", "test", "src/App.sln"],
                    },
                    account_uids=(owner_uid, alternate_uid),
                )

    def test_lock_free_dotnet_target_retains_exact_read_only_toolchain(self) -> None:
        uid = os.geteuid()
        home = self.base / "dotnet-only-home"
        dotnet_root = home / ".dotnet"
        dotnet_root.mkdir(parents=True)
        dotnet = dotnet_root / "dotnet"
        dotnet.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        dotnet.chmod(0o755)
        account = SimpleNamespace(pw_uid=uid, pw_gid=os.getegid(), pw_dir=str(home))
        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            return_value=account,
        ):
            bindings, _python, executable, toolchains = self.derive(
                {
                    "driver": "dotnet",
                    "cwd": ".",
                    "argv": ["{dotnet}", "test", "src/App.sln"],
                },
                account_uids=(uid,),
                full=True,
            )
        self.assertEqual(bindings, ())
        self.assertEqual(executable, str(dotnet))
        self.assertEqual(len(toolchains), 1)
        descriptor = replace(
            self.descriptor(),
            argv=(str(dotnet), "test", "src/App.sln"),
            driver="dotnet",
            reporter="trx",
            toolchain_bindings=toolchains,
        )
        round_trip = TestAttemptDescriptor.from_document(descriptor.to_document())
        attempt_root = self.base / "dotnet-only-attempt"
        attempt_root.mkdir()
        properties = SystemdTestAttemptManager._systemd_properties(
            round_trip,
            execution_root=attempt_root,
            output_root=self.base / "dotnet-only-output",
        )
        self.assertIn("--property=ProtectHome=tmpfs", properties)
        self.assertIn(
            f"--property=BindReadOnlyPaths={dotnet_root}", properties
        )
        self.assertFalse(
            any(
                value == f"--property=BindReadOnlyPaths={home}"
                for value in properties
            )
        )

    def test_dotnet_target_selects_account_with_requested_sdk(self) -> None:
        owner_uid = 12001
        alternate_uid = 12002
        owner_home = self.base / "owner-dotnet-home"
        alternate_home = self.base / "alternate-dotnet-home"
        for home in (owner_home, alternate_home):
            executable = home / ".dotnet" / "dotnet"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        (alternate_home / ".dotnet" / "sdk" / "10.0.302").mkdir(parents=True)
        global_json = self.original / "global.json"
        global_json.write_text(
            '{"sdk":{"version":"10.0.302","rollForward":"disable"}}\n',
            encoding="utf-8",
        )
        (self.materialized / "global.json").write_bytes(global_json.read_bytes())
        self.provenance["dependency_locks"]["global.json"] = digest(global_json)
        accounts = {
            owner_uid: SimpleNamespace(pw_dir=str(owner_home)),
            alternate_uid: SimpleNamespace(pw_dir=str(alternate_home)),
        }

        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            side_effect=lambda uid: accounts[uid],
        ):
            _bindings, _python, executable, toolchains = self.derive(
                {
                    "driver": "dotnet",
                    "cwd": ".",
                    "argv": ["{dotnet}", "test", "src/App.sln"],
                },
                account_uids=(alternate_uid,),
                full=True,
            )

        expected = alternate_home / ".dotnet" / "dotnet"
        self.assertEqual(executable, str(expected))
        self.assertEqual(toolchains[0]["source_root"], str(expected.parent))

    def test_dotnet_target_uses_system_toolchain_for_requested_sdk(self) -> None:
        owner_uid = 12003
        owner_home = self.base / "incomplete-dotnet-home"
        owner_executable = owner_home / ".dotnet" / "dotnet"
        owner_executable.parent.mkdir(parents=True)
        owner_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        owner_executable.chmod(0o755)
        system_root = self.base / "system-dotnet"
        system_executable = system_root / "dotnet"
        system_executable.parent.mkdir(parents=True)
        system_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        system_executable.chmod(0o755)
        (system_root / "sdk" / "10.0.302").mkdir(parents=True)
        global_json = self.original / "global.json"
        global_json.write_text(
            '{"sdk":{"version":"10.0.302","rollForward":"disable"}}\n',
            encoding="utf-8",
        )
        (self.materialized / "global.json").write_bytes(global_json.read_bytes())
        account = SimpleNamespace(pw_dir=str(owner_home))

        with mock.patch(
            "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
            return_value=account,
        ), mock.patch(
            "devcoordinator.universal_test_snapshot_service.shutil.which",
            return_value=str(system_executable),
        ):
            _bindings, _python, executable, toolchains = self.derive(
                {
                    "driver": "dotnet",
                    "cwd": ".",
                    "argv": ["{dotnet}", "test", "src/App.sln"],
                },
                account_uids=(),
                full=True,
            )

        self.assertEqual(executable, str(system_executable))
        self.assertEqual(toolchains[0]["source_root"], str(system_root))


if __name__ == "__main__":
    unittest.main()
