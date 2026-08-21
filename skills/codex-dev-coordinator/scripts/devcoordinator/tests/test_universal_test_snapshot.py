from __future__ import annotations

import copy
from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from devcoordinator.universal_test_contract import SourceMode, parse_test_manifest
from devcoordinator.universal_test_planner import (
    ChangedPath,
    ChangeStatus,
    SourceIdentity,
    create_test_plan,
)
from devcoordinator.universal_test_repository_binding import (
    IMMUTABLE_REPOSITORY_BINDING_NAME,
    ImmutableRepositoryBindingError,
    resolve_immutable_repository_binding,
)
from devcoordinator.universal_test_snapshot import (
    FilesystemSnapshotMaterializer,
    GitSnapshotSource,
    ImmutableSnapshotPlanPreviewer,
    SnapshotMaterializationError,
    SnapshotMaterializationRequest,
    SnapshotRepositoryBinding,
    public_snapshot_source_diagnostic,
)
from devcoordinator.universal_test_service import (
    StoreTestPlaneAdapter,
    decode_repository_setup_document,
)
from devcoordinator.universal_test_snapshot_service import (
    RootSnapshotService,
    UIDDelegatedSnapshotSource,
    UIDHelperRunner,
    _dependency_account_uids,
)
from devcoordinator.universal_test_store import (
    TargetResources,
    TestStoreContractError,
    UniversalTestStore,
)
from devcoordinator.universal_test_uid_helper import execute as execute_uid_helper


def manifest_document() -> dict[str, object]:
    return {
        "schema_version": 4,
        "defaults": {
            "timeout_seconds": 300,
            "network": "none",
            "environment": {},
        },
        "global_inputs": [".codex/tests.json"],
        "intents": {
            "handoff": {"source_mode": "immutable", "allow_reuse": True},
            "release": {"source_mode": "immutable", "allow_reuse": False},
            "manual": {"source_mode": "immutable", "allow_reuse": False},
        },
        "fixtures": {},
        "targets": {
            "unit": {
                "driver": "automation",
                "reporter": "automation-events",
                "argv": ["./scripts/test"],
                "cwd": ".",
                "inputs": ["**"],
                "depends_on": [],
                "intents": ["handoff", "release", "manual"],
            }
        },
        "evidence_policies": {},
    }


class MutatingSource:
    def __init__(self, source: GitSnapshotSource, mutate_path: Path) -> None:
        self.source = source
        self.mutate_path = mutate_path
        self.mutated = False

    def scan(self, request):
        return self.source.scan(request)

    def copy_file(self, request, source, destination):
        result = self.source.copy_file(request, source, destination)
        if not self.mutated:
            self.mutate_path.write_text("changed during capture\n", encoding="utf-8")
            self.mutated = True
        return result


class SwapRegularFileForSymlinkAfterScan(GitSnapshotSource):
    def __init__(self, *, target: Path, link_target: str, clone_regular_file) -> None:
        super().__init__(clone_regular_file=clone_regular_file)
        self.target = target
        self.link_target = link_target
        self.armed = False
        self.swapped = False

    def scan(self, request):
        result = super().scan(request)
        self.armed = True
        return result

    def _read_file(self, root, relative, *, tracked):
        result = super()._read_file(root, relative, tracked=tracked)
        if self.armed and not self.swapped and root / relative == self.target:
            self.target.unlink()
            self.target.symlink_to(self.link_target)
            self.swapped = True
        return result


class ExactResolver:
    def __init__(self, binding: SnapshotRepositoryBinding) -> None:
        self.binding = binding
        self.calls: list[tuple[str, int]] = []

    def resolve_as_owner(
        self, *, repository_id: str, owner_uid: int
    ) -> SnapshotRepositoryBinding:
        self.calls.append((repository_id, owner_uid))
        return self.binding


class InProcessUIDHelper:
    def call(self, operation, *, owner_uid, arguments):
        return execute_uid_helper(
            {
                "operation": operation,
                "owner_uid": owner_uid,
                "arguments": arguments,
            }
        )


class FixedCopyResult:
    def copy_file(self, request, source, destination):
        del request, source, destination
        return "reflink"


class OwnerPreviewHelper(InProcessUIDHelper):
    def call(self, operation, *, owner_uid, arguments):
        if operation != "plan":
            return super().call(
                operation, owner_uid=owner_uid, arguments=arguments
            )
        root = Path(arguments["snapshot_root"])
        manifest = parse_test_manifest(
            json.loads((root / ".codex" / "tests.json").read_text()),
            repository_root=root,
        )
        source_value = arguments["source"]
        source = SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id=source_value["repository_id"],
            content_fingerprint=source_value["content_fingerprint"],
            original_root=source_value["original_root"],
            temporary_root=source_value["temporary_root"],
            snapshot_id=source_value["snapshot_id"],
        )
        selected = create_test_plan(
            manifest,
            intent=arguments["intent"],
            source=source,
            changes=[
                ChangedPath(
                    path=item["path"],
                    status=ChangeStatus(item["status"]),
                    previous_path=item["previous_path"],
                )
                for item in arguments.get("changes", ())
            ],
            requested_targets=arguments.get("requested_targets", ()),
        )
        resources = {}
        catalog = {}
        for name in selected.selected_targets:
            target = manifest.targets[name]
            resources[name] = {
                "estimated_seconds": float(target.timeout_seconds),
                "shard_count": 1,
                "worktree_key": str(root),
                "exclusive_resources": list(target.exclusive_resources),
                "ttl_seconds": target.timeout_seconds,
            }
            catalog[name] = {
                "driver": target.driver,
                "reporter": target.reporter,
                "argv": list(target.argv),
                "cwd": target.cwd,
                "environment": dict(target.environment),
                "network": target.network,
                "timeout_seconds": target.timeout_seconds,
                "fixtures": list(target.fixtures),
                "artifacts": [],
            }
        return {
            "plan": selected.to_document(),
            "target_resources": resources,
            "launch_catalog": catalog,
        }


class LiveAuthority:
    def __init__(self, *, repository_id, canonical_root, execution_root, owner_uid):
        self.repository_id = repository_id
        self.canonical_root = canonical_root
        self.execution_root = execution_root
        self.owner_uid = owner_uid

    def repository(self, *, repository_id, owner_uid):
        if repository_id != self.repository_id or owner_uid != self.owner_uid:
            raise AssertionError("unexpected repository authority lookup")
        return {
            "repository_id": repository_id,
            "canonical_root": self.canonical_root,
            "generation": 7,
            "owner_uid": owner_uid,
        }

    def live_execution_root(self, *, repository_id, owner_uid, temporary_root):
        result = self.repository(repository_id=repository_id, owner_uid=owner_uid)
        if temporary_root != self.execution_root:
            raise AssertionError("temporary worktree was not authority-bound")
        return {**result, "execution_root": self.execution_root}


class UniversalTestSnapshotTests(unittest.TestCase):
    def test_dependency_cache_candidates_include_the_source_owner(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw)
            caller_uid = os.geteuid() + 100
            accounts = [
                mock.Mock(pw_uid=1002, pw_dir="/home/axel", pw_shell="/bin/bash"),
                mock.Mock(pw_uid=1000, pw_dir="/home/holyglory", pw_shell="/bin/bash"),
                mock.Mock(pw_uid=0, pw_dir="/root", pw_shell="/bin/bash"),
                mock.Mock(pw_uid=985, pw_dir="/var/lib/testd", pw_shell="/bin/false"),
            ]

            with mock.patch(
                "devcoordinator.universal_test_snapshot_service.pwd.getpwall",
                return_value=accounts,
            ):
                self.assertEqual(
                    _dependency_account_uids(
                        candidate_owner_uid=caller_uid,
                        original_root=str(source),
                    ),
                    (caller_uid, 1000, 1002),
                )

    def test_read_only_uid_helper_runs_as_the_control_plane(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b'{"ok":true,"result":{"scanned":true}}',
            stderr=b"",
        )
        subprocess_runner = mock.Mock(return_value=completed)
        helper = object.__new__(UIDHelperRunner)
        helper.helper = Path("/immutable/devcoordinator-uid-helper.py")
        helper.python = "/usr/bin/python3"
        helper.runner = subprocess_runner
        owner = mock.Mock(pw_name="developer", pw_uid=1000, pw_gid=1003)
        control_plane = mock.Mock(pw_name="root", pw_uid=0, pw_gid=0)
        group_lookup = mock.Mock(return_value=[1003, 986])

        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
                side_effect=lambda uid: control_plane if uid == 0 else owner,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.os.getgrouplist",
                group_lookup,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service._snapshot_preview_timeout",
                return_value=17.5,
            ),
        ):
            result = helper.call("scan", owner_uid=1000, arguments={})

        self.assertEqual(result, {"scanned": True})
        self.assertEqual(subprocess_runner.call_args.kwargs["extra_groups"], ())
        self.assertEqual(subprocess_runner.call_args.kwargs["user"], 0)
        self.assertEqual(subprocess_runner.call_args.kwargs["group"], 0)
        self.assertEqual(subprocess_runner.call_args.kwargs["timeout"], 17.5)
        group_lookup.assert_not_called()

    def test_write_uid_helper_preserves_the_repository_owners_groups(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b'{"ok":true,"result":{"applied":true}}',
            stderr=b"",
        )
        subprocess_runner = mock.Mock(return_value=completed)
        helper = object.__new__(UIDHelperRunner)
        helper.helper = Path("/immutable/devcoordinator-uid-helper.py")
        helper.python = "/usr/bin/python3"
        helper.runner = subprocess_runner
        identity = mock.Mock(pw_name="developer", pw_uid=1000, pw_gid=1003)

        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.pwd.getpwuid",
                return_value=identity,
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.os.getgrouplist",
                return_value=[1003, 986, 1001, 986],
            ),
            mock.patch(
                "devcoordinator.universal_test_snapshot_service.pwd.getpwall",
                return_value=[
                    mock.Mock(pw_uid=983, pw_gid=983),
                    identity,
                    mock.Mock(pw_uid=1001, pw_gid=1004),
                    mock.Mock(pw_uid=65_534, pw_gid=65_534),
                ],
            ),
        ):
            result = helper.call("adoption_apply", owner_uid=1000, arguments={})

        self.assertEqual(result, {"applied": True})
        self.assertEqual(
            subprocess_runner.call_args.kwargs["extra_groups"],
            (986, 1001, 1004),
        )
        self.assertEqual(subprocess_runner.call_args.kwargs["user"], 1000)
        self.assertEqual(subprocess_runner.call_args.kwargs["group"], 1003)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.store = Path(self.temporary.name) / "snapshots"
        self.root.mkdir()
        (self.root / ".codex").mkdir()
        (self.root / "scripts").mkdir()
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest_document(), sort_keys=True), encoding="utf-8"
        )
        (self.root / "scripts" / "test").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("tracked v1\n", encoding="utf-8")
        (self.root / "staged.txt").write_text("staged v1\n", encoding="utf-8")
        (self.root / "both.txt").write_text("both v1\n", encoding="utf-8")
        (self.root / "deleted.txt").write_text("delete me\n", encoding="utf-8")
        (self.root / "package-lock.json").write_text("{}\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
        self._git("init", "--quiet")
        self._git("config", "user.email", "snapshot@example.invalid")
        self._git("config", "user.name", "Snapshot Tests")
        self._git("add", ".")
        self._git("commit", "--quiet", "-m", "initial")

    @unittest.skip("manual rerun replaced retained retry catalogs")
    def test_immutable_retry_derives_exact_catalog_from_source_plan(self) -> None:
        document = manifest_document()
        document["targets"] = {
            "build": {
                **document["targets"]["unit"],
                "depends_on": [],
            },
            "tests": {
                **document["targets"]["unit"],
                "depends_on": ["build"],
            },
        }
        manifest = parse_test_manifest(document, repository_root=self.root)
        source = SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id="repo-snapshot-tests",
            content_fingerprint="b" * 64,
            original_root=str(self.root),
            temporary_root=None,
            snapshot_id="snapshot-" + "a" * 32,
        )
        original = create_test_plan(
            manifest,
            intent="manual",
            source=source,
            requested_targets=("tests",),
        )
        _, _, _, retry_json = _retry_plan_projection(
            json.dumps(original.to_document(), sort_keys=True),
            selected_targets=("tests",),
        )
        retry_document = json.loads(retry_json)
        service = object.__new__(RootSnapshotService)
        service.catalog_root = Path(self.temporary.name) / "catalog"
        service.catalog_root.mkdir()
        original_catalog = {
            "schema_version": 1,
            "plan": original.to_document(),
            "repository_generation": 7,
            "owner_uid": os.geteuid(),
            "launch_catalog": {
                target: {"argv": ["./scripts/test"], "target": target}
                for target in original.selected_targets
            },
            "target_resources": {
                target: {"shard_count": 1, "worktree_key": str(self.root)}
                for target in original.selected_targets
            },
            "source_provenance": {
                "complete": True,
                "content_fingerprint": source.content_fingerprint,
            },
        }
        legacy_path = service._catalog_path(source.snapshot_id, original.plan_id)
        legacy_path.write_text(
            json.dumps(
                original_catalog,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        second_account_catalog = copy.deepcopy(original_catalog)
        second_account_catalog["owner_uid"] = os.geteuid() + 1
        service._publish_catalog(
            plan_id=original.plan_id,
            snapshot_id=source.snapshot_id,
            value=second_account_catalog,
        )
        owner_neutral = service._load_catalog(original.to_document())
        self.assertNotIn("owner_uid", owner_neutral)
        conflicting_catalog = copy.deepcopy(second_account_catalog)
        conflicting_catalog["launch_catalog"]["tests"]["argv"] = [
            "./scripts/different-test"
        ]
        with self.assertRaisesRegex(TestStoreContractError, "identity collided"):
            service._publish_catalog(
                plan_id=original.plan_id,
                snapshot_id=source.snapshot_id,
                value=conflicting_catalog,
            )

        derived = service._load_catalog(retry_document)
        replay = service._load_catalog(retry_document)

        self.assertEqual(derived, replay)
        self.assertNotIn("owner_uid", derived)
        self.assertEqual(derived["plan"], retry_document)
        self.assertEqual(set(derived["launch_catalog"]), {"tests"})
        self.assertEqual(set(derived["target_resources"]), {"tests"})
        self.assertTrue(
            (service.catalog_root / source.snapshot_id / f"{retry_document['plan_id']}.json").is_file()
        )

    def test_control_plane_identity_is_read_only_in_the_fixed_helper(self) -> None:
        request = {
            "operation": "setup",
            "owner_uid": 1000,
            "arguments": {"repository_root": str(self.root)},
        }
        with mock.patch(
            "devcoordinator.universal_test_uid_helper.os.geteuid", return_value=0
        ):
            result = execute_uid_helper(request)
            with self.assertRaisesRegex(
                SnapshotMaterializationError,
                "execution identity",
            ):
                execute_uid_helper(
                    {
                        "operation": "adoption_apply",
                        "owner_uid": 1000,
                        "arguments": {},
                    }
                )

        self.assertEqual(result["status"], "ready")

    def tearDown(self) -> None:
        for directory, child_directories, files in os.walk(
            Path(self.temporary.name), topdown=False, followlinks=False
        ):
            current = Path(directory)
            for name in files:
                path = current / name
                if not path.is_symlink():
                    path.chmod(0o600)
            for name in child_directories:
                path = current / name
                if not path.is_symlink():
                    path.chmod(0o700)
            current.chmod(0o700)
        self.temporary.cleanup()

    def _git_in(self, root: Path, *arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    def _git(self, *arguments: str) -> None:
        self._git_in(self.root, *arguments)

    @staticmethod
    def _emulate_reflink(source_descriptor: int, destination_descriptor: int) -> None:
        size = os.fstat(source_descriptor).st_size
        os.ftruncate(destination_descriptor, size)
        offset = 0
        while offset < size:
            chunk = os.pread(
                source_descriptor, min(1024 * 1024, size - offset), offset
            )
            if not chunk:
                raise AssertionError("emulated reflink source ended early")
            written = 0
            while written < len(chunk):
                count = os.pwrite(
                    destination_descriptor,
                    chunk[written:],
                    offset + written,
                )
                if count <= 0:
                    raise AssertionError("emulated reflink destination write failed")
                written += count
            offset += len(chunk)

    def _add_gitlink(self, name: str = "engine") -> tuple[Path, Path]:
        source = Path(self.temporary.name) / f"{name}-source"
        source.mkdir()
        (source / "model.txt").write_text("model v1\n", encoding="utf-8")
        (source / "staged.txt").write_text("staged v1\n", encoding="utf-8")
        (source / "deleted.txt").write_text("delete nested\n", encoding="utf-8")
        (source / "Cargo.lock").write_text("# nested lock\n", encoding="utf-8")
        self._git_in(source, "init", "--quiet")
        self._git_in(source, "config", "user.email", "nested@example.invalid")
        self._git_in(source, "config", "user.name", "Nested Snapshot Tests")
        self._git_in(source, "add", ".")
        self._git_in(source, "commit", "--quiet", "-m", "nested initial")
        self._git(
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            str(source),
            name,
        )
        nested = self.root / name
        self._git_in(nested, "config", "user.email", "nested@example.invalid")
        self._git_in(nested, "config", "user.name", "Nested Snapshot Tests")
        self._git("commit", "--quiet", "-m", f"add {name} gitlink")
        return nested, source

    def _request(self, *, owner_uid: int | None = None) -> SnapshotMaterializationRequest:
        manifest = parse_test_manifest(
            manifest_document(), repository_root=self.root
        )
        return SnapshotMaterializationRequest(
            repository_id="repo-snapshot-tests",
            original_root=str(self.root),
            temporary_root=None,
            manifest_fingerprint=manifest.fingerprint,
            intent="release",
            owner_uid=os.geteuid() if owner_uid is None else owner_uid,
        )

    def test_materializes_exact_git_worktree_content_and_provenance(self) -> None:
        (self.root / "tracked.txt").write_text("unstaged\n", encoding="utf-8")
        (self.root / "staged.txt").write_text("staged v2\n", encoding="utf-8")
        self._git("add", "staged.txt")
        (self.root / "both.txt").write_text("index version\n", encoding="utf-8")
        self._git("add", "both.txt")
        (self.root / "both.txt").write_text("worktree version\n", encoding="utf-8")
        (self.root / "deleted.txt").unlink()
        (self.root / "untracked.txt").write_text("included\n", encoding="utf-8")
        (self.root / "noise.ignored").write_text("excluded\n", encoding="utf-8")

        materializer = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        )
        provenance = materializer.materialize(self._request())
        materialized = Path(provenance.materialized_root)

        self.assertTrue(provenance.complete)
        self.assertEqual(provenance.untracked_count, 1)
        self.assertIn("package-lock.json", provenance.dependency_locks)
        self.assertIn("git_index_delta", provenance.toolchain)
        self.assertIn("git_worktree_delta", provenance.toolchain)
        self.assertEqual((materialized / "tracked.txt").read_text(), "unstaged\n")
        self.assertEqual((materialized / "staged.txt").read_text(), "staged v2\n")
        self.assertEqual((materialized / "both.txt").read_text(), "worktree version\n")
        self.assertEqual((materialized / "untracked.txt").read_text(), "included\n")
        self.assertFalse((materialized / "deleted.txt").exists())
        self.assertFalse((materialized / "noise.ignored").exists())
        self.assertFalse(materialized.stat().st_mode & 0o222)
        public = provenance.to_document()
        self.assertNotIn("materialized_root", public)
        self.assertEqual(public["source"]["mode"], "immutable")
        self.assertIn(
            public["materialization_mode"], {"copy", "reflink", "mixed"}
        )
        self.assertEqual(public["schema_version"], 2)
        binding = resolve_immutable_repository_binding(materialized / "tracked.txt")
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.repository_id, "repo-snapshot-tests")
        self.assertEqual(binding.original_root, str(self.root))
        self.assertEqual(binding.materialized_root, str(materialized))
        self.assertEqual(binding.content_fingerprint, provenance.content_fingerprint)
        self.assertEqual(
            (materialized.parent / IMMUTABLE_REPOSITORY_BINDING_NAME).stat().st_mode
            & 0o777,
            0o444,
        )
        self.assertEqual(
            materializer.materialize(self._request()), provenance
        )

    def test_immutable_repository_binding_ignores_permissions_but_rejects_unrelated_context(self) -> None:
        materializer = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        )
        provenance = materializer.materialize(self._request())
        materialized = Path(provenance.materialized_root)
        binding_path = materialized.parent / IMMUTABLE_REPOSITORY_BINDING_NAME
        binding_path.chmod(0o644)

        binding = resolve_immutable_repository_binding(materialized)
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.original_root, str(self.root))

        self.assertIsNone(resolve_immutable_repository_binding(self.root))

    def test_immutable_repository_binding_does_not_stat_an_inaccessible_route(self) -> None:
        inaccessible = Path("/another-account/private/repository")
        with (
            mock.patch.object(Path, "resolve", return_value=inaccessible),
            mock.patch.object(
                Path,
                "is_dir",
                side_effect=PermissionError(13, "permission denied"),
            ),
        ):
            self.assertIsNone(resolve_immutable_repository_binding(inaccessible))

    def test_scan_retries_when_an_ephemeral_untracked_sidecar_disappears(self) -> None:
        sidecar = self.root / ".test-tmp" / "events.sqlite3-shm"
        sidecar.parent.mkdir()
        sidecar.write_bytes(b"ephemeral")
        original = GitSnapshotSource._read_file
        removed = False

        def racing_read(root: Path, relative: str, *, tracked: bool):
            nonlocal removed
            if relative == ".test-tmp/events.sqlite3-shm" and not removed:
                removed = True
                sidecar.unlink()
            return original(root, relative, tracked=tracked)

        with mock.patch.object(
            GitSnapshotSource, "_read_file", side_effect=racing_read
        ):
            scan = GitSnapshotSource().scan(self._request())

        self.assertTrue(removed)
        self.assertNotIn(
            ".test-tmp/events.sqlite3-shm",
            {item.path for item in scan.files},
        )

    def test_manifest_contract_diagnostic_names_the_exact_safe_field(self) -> None:
        invalid = manifest_document()
        del invalid["targets"]["unit"]["argv"]
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(invalid), encoding="utf-8"
        )

        with self.assertRaises(SnapshotMaterializationError) as raised:
            GitSnapshotSource().scan(self._request())

        public = public_snapshot_source_diagnostic(raised.exception)
        self.assertIn("$.targets.unit", public)
        self.assertIn("missing required field 'argv'", public)
        self.assertNotIn(str(self.root), public)

    def test_materialization_uses_one_aggregate_caller_deadline(self) -> None:
        materializer = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        )
        with (
            mock.patch(
                "devcoordinator.universal_test_snapshot.time.monotonic",
                side_effect=[100.0, 102.0],
            ),
            self.assertRaisesRegex(
                SnapshotMaterializationError, "caller launch deadline"
            ),
        ):
            materializer.materialize_with_timeout(
                self._request(), timeout_seconds=1.0
            )

    def test_materialization_retries_one_complete_before_after_source_change(self) -> None:
        source = GitSnapshotSource(clone_regular_file=self._emulate_reflink)
        original_scan = source.scan
        scans = 0

        def racing_scan(request):
            nonlocal scans
            scans += 1
            if scans == 2:
                (self.root / "tracked.txt").write_text(
                    "stable after churn\n", encoding="utf-8"
                )
            return original_scan(request)

        source.scan = racing_scan  # type: ignore[method-assign]
        materializer = FilesystemSnapshotMaterializer(
            self.store,
            source=source,
            allow_unprotected_test_store=True,
        )

        provenance = materializer.materialize(self._request())

        self.assertEqual(scans, 4)
        self.assertEqual(
            (Path(provenance.materialized_root) / "tracked.txt").read_text(
                encoding="utf-8"
            ),
            "stable after churn\n",
        )
        self.assertEqual(
            [path.name for path in self.store.iterdir() if path.name.startswith(".snapshot-")],
            [],
        )

    def test_prefers_reflink_and_records_exact_materialization_mode(self) -> None:
        calls: list[tuple[int, int]] = []

        def clone(source_descriptor: int, destination_descriptor: int) -> None:
            calls.append((source_descriptor, destination_descriptor))
            self._emulate_reflink(source_descriptor, destination_descriptor)

        materializer = FilesystemSnapshotMaterializer(
            self.store,
            source=GitSnapshotSource(clone_regular_file=clone),
            allow_unprotected_test_store=True,
        )
        provenance = materializer.materialize(self._request())

        self.assertGreater(len(calls), 0)
        self.assertEqual(provenance.materialization_mode, "reflink")
        self.assertEqual(
            materializer.provenance(provenance.snapshot_id).materialization_mode,
            "reflink",
        )
        self.assertEqual(
            json.loads(
                (
                    self.store
                    / provenance.snapshot_id
                    / "provenance.json"
                ).read_text(encoding="utf-8")
            )["materialization_mode"],
            "reflink",
        )

    def test_uid_delegated_source_propagates_exact_copy_result(self) -> None:
        source = UIDDelegatedSnapshotSource(InProcessUIDHelper())
        source.copy_source = FixedCopyResult()  # type: ignore[assignment]

        self.assertEqual(
            source.copy_file(self._request(), object(), Path("unused")),
            "reflink",
        )

    def test_uid_delegated_scan_uses_access_uid_without_changing_owner(self) -> None:
        baseline = GitSnapshotSource().scan(self._request())
        helper = mock.Mock()
        helper.call.return_value = {"scan": baseline.to_document()}
        source = UIDDelegatedSnapshotSource(helper)
        request = SnapshotMaterializationRequest(
            repository_id="repo-snapshot-tests",
            original_root=str(self.root),
            temporary_root=None,
            manifest_fingerprint=baseline.manifest_fingerprint,
            intent="release",
            owner_uid=os.geteuid(),
            access_uid=os.geteuid() + 100,
        )

        observed = source.scan(request)

        self.assertEqual(observed.content_fingerprint, baseline.content_fingerprint)
        self.assertEqual(request.owner_uid, os.geteuid())
        self.assertEqual(request.inspection_uid, os.geteuid() + 100)
        self.assertEqual(helper.call.call_args.kwargs["owner_uid"], os.geteuid() + 100)

    def test_git_inspection_marks_only_the_exact_root_as_safe(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0)
        with mock.patch(
            "devcoordinator.universal_test_snapshot.subprocess.run",
            return_value=completed,
        ) as runner:
            self.assertEqual(
                GitSnapshotSource._git(self.root, ["status", "--porcelain"], maximum_bytes=1024),
                b"",
            )

        argv = runner.call_args.args[0]
        self.assertIn(f"safe.directory={self.root}", argv)
        self.assertEqual(argv[argv.index("-C") + 1], str(self.root))

    def test_public_snapshot_diagnostic_preserves_only_bounded_invariants(self) -> None:
        self.assertEqual(
            public_snapshot_source_diagnostic(
                "snapshot file could not be opened safely: "
                "deploy/ceph-vault-probe/temporal_scope_probe.py: "
                "[Errno 13] Permission denied: 'temporal_scope_probe.py'"
            ),
            "Snapshot source path is unreadable: "
            "deploy/ceph-vault-probe/temporal_scope_probe.py.",
        )
        self.assertEqual(
            public_snapshot_source_diagnostic(
                "Git snapshot inspection failed: fatal: secret /outside/path"
            ),
            "Git metadata inspection failed for the configured repository.",
        )
        self.assertEqual(
            public_snapshot_source_diagnostic(
                "snapshot file is unavailable: tests.json: "
                "[Errno 2] No such file or directory: 'tests.json'"
            ),
            "Snapshot source path is unavailable: tests.json.",
        )
        self.assertNotIn(
            "/outside/path",
            public_snapshot_source_diagnostic("unexpected failure at /outside/path"),
        )
        self.assertEqual(
            public_snapshot_source_diagnostic(
                "snapshot source changed during materialization; retry from a fresh plan"
            ),
            "Snapshot source changed during capture; retry after writes stop.",
        )

    def test_uid_delegated_copy_never_invokes_git_as_root(self) -> None:
        request = self._request()
        scanned_file = GitSnapshotSource._read_file(
            self.root,
            "tracked.txt",
            tracked=True,
        )
        destination = Path(self.temporary.name) / "delegated-copy" / "tracked.txt"
        source = UIDDelegatedSnapshotSource(InProcessUIDHelper())
        source.copy_source = GitSnapshotSource(
            enforce_process_uid=False,
            clone_regular_file=self._emulate_reflink,
        )

        with mock.patch.object(
            source.copy_source,
            "_git",
            side_effect=AssertionError("root-side copy must not invoke Git"),
        ) as git:
            result = source.copy_file(request, scanned_file, destination)

        git.assert_not_called()
        self.assertEqual(result, "reflink")
        self.assertEqual(destination.read_text(encoding="utf-8"), "tracked v1\n")

    def test_uid_delegated_copy_uses_execution_context_not_path_owner_metadata(self) -> None:
        scanned_file = GitSnapshotSource._read_file(
            self.root,
            "tracked.txt",
            tracked=True,
        )
        source = UIDDelegatedSnapshotSource(InProcessUIDHelper())
        destination = Path(self.temporary.name) / "metadata-independent-copy"

        with mock.patch.object(source.copy_source, "_git") as git:
            source.copy_file(
                self._request(owner_uid=os.geteuid() + 1),
                scanned_file,
                destination,
            )

        git.assert_not_called()
        self.assertEqual(destination.read_text(encoding="utf-8"), "tracked v1\n")

    def test_unsupported_reflink_falls_back_to_verified_copy(self) -> None:
        def unsupported(_source_descriptor: int, destination_descriptor: int) -> None:
            os.write(destination_descriptor, b"partial clone debris")
            raise OSError(errno.EOPNOTSUPP, "reflink unsupported")

        provenance = FilesystemSnapshotMaterializer(
            self.store,
            source=GitSnapshotSource(clone_regular_file=unsupported),
            allow_unprotected_test_store=True,
        ).materialize(self._request())

        self.assertEqual(provenance.materialization_mode, "copy")
        self.assertEqual(
            (Path(provenance.materialized_root) / "tracked.txt").read_text(
                encoding="utf-8"
            ),
            "tracked v1\n",
        )

    def test_mixed_reflink_support_is_recorded_without_overclaiming(self) -> None:
        calls = 0

        def partially_supported(
            source_descriptor: int, destination_descriptor: int
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self._emulate_reflink(source_descriptor, destination_descriptor)
                return
            raise OSError(errno.EXDEV, "cross-device clone")

        provenance = FilesystemSnapshotMaterializer(
            self.store,
            source=GitSnapshotSource(clone_regular_file=partially_supported),
            allow_unprotected_test_store=True,
        ).materialize(self._request())

        self.assertGreater(calls, 1)
        self.assertEqual(provenance.materialization_mode, "mixed")

    def test_unexpected_reflink_failure_fails_closed_without_publication(self) -> None:
        def io_failure(_source_descriptor: int, _destination_descriptor: int) -> None:
            raise OSError(errno.EIO, "reflink I/O failure")

        materializer = FilesystemSnapshotMaterializer(
            self.store,
            source=GitSnapshotSource(clone_regular_file=io_failure),
            allow_unprotected_test_store=True,
        )
        with self.assertRaisesRegex(
            SnapshotMaterializationError, "without a safe fallback"
        ):
            materializer.materialize(self._request())

        self.assertFalse(list(self.store.glob("snapshot-*")))
        self.assertFalse(list(self.store.glob(".snapshot-*")))

    def test_reflink_source_open_does_not_follow_a_raced_symlink(self) -> None:
        opened_sources: list[str] = []

        def clone(source_descriptor: int, destination_descriptor: int) -> None:
            opened_sources.append(os.readlink(f"/proc/self/fd/{source_descriptor}"))
            self._emulate_reflink(source_descriptor, destination_descriptor)

        source = SwapRegularFileForSymlinkAfterScan(
            target=self.root / "tracked.txt",
            link_target="/etc/passwd",
            clone_regular_file=clone,
        )
        materializer = FilesystemSnapshotMaterializer(
            self.store,
            source=source,
            allow_unprotected_test_store=True,
        )
        with self.assertRaisesRegex(
            SnapshotMaterializationError, "could not be opened safely"
        ):
            materializer.materialize(self._request())

        self.assertTrue(source.swapped)
        self.assertNotIn(str(self.root / "tracked.txt"), opened_sources)
        self.assertFalse(list(self.store.glob("snapshot-*")))

    def test_materializes_clean_gitlink_content_locks_without_git_metadata(self) -> None:
        self._add_gitlink()

        materializer = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        )
        provenance = materializer.materialize(self._request())
        materialized = Path(provenance.materialized_root)

        self.assertEqual((materialized / "engine" / "model.txt").read_text(), "model v1\n")
        self.assertIn("engine/Cargo.lock", provenance.dependency_locks)
        self.assertEqual(provenance.toolchain["gitlink_count"], "1")
        self.assertEqual(len(provenance.toolchain["gitlink_state"]), 64)
        self.assertFalse((materialized / "engine" / ".git").exists())
        self.assertEqual(list(materialized.rglob(".git")), [])

    def test_recursively_materializes_nested_gitlinks(self) -> None:
        nested, _source = self._add_gitlink()
        leaf_source = Path(self.temporary.name) / "leaf-source"
        leaf_source.mkdir()
        (leaf_source / "leaf.txt").write_text("recursive content\n", encoding="utf-8")
        (leaf_source / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
        self._git_in(leaf_source, "init", "--quiet")
        self._git_in(leaf_source, "config", "user.email", "leaf@example.invalid")
        self._git_in(leaf_source, "config", "user.name", "Leaf Snapshot Tests")
        self._git_in(leaf_source, "add", ".")
        self._git_in(leaf_source, "commit", "--quiet", "-m", "leaf initial")
        self._git_in(
            nested,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            str(leaf_source),
            "components/core",
        )
        self._git_in(nested, "commit", "--quiet", "-m", "add recursive gitlink")

        provenance = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        ).materialize(self._request())
        materialized = Path(provenance.materialized_root)

        self.assertEqual(
            (materialized / "engine" / "components" / "core" / "leaf.txt").read_text(),
            "recursive content\n",
        )
        self.assertEqual(provenance.toolchain["gitlink_count"], "2")
        self.assertIn(
            "engine/components/core/pnpm-lock.yaml",
            provenance.dependency_locks,
        )
        self.assertEqual(list(materialized.rglob(".git")), [])

    def test_dirty_gitlink_is_captured_and_reported_as_prefixed_live_changes(self) -> None:
        nested, _source = self._add_gitlink()
        source = GitSnapshotSource()
        clean = source.scan(self._request())
        (nested / "model.txt").write_text("model dirty\n", encoding="utf-8")
        (nested / "staged.txt").write_text("staged v2\n", encoding="utf-8")
        self._git_in(nested, "add", "staged.txt")
        (nested / "deleted.txt").unlink()
        (nested / "untracked.txt").write_text("nested untracked\n", encoding="utf-8")

        dirty = source.scan(self._request())
        changes = {
            (item.path, item.status, item.previous_path)
            for item in source.discover_live_changes(self._request())
        }

        self.assertNotEqual(clean.toolchain["gitlink_state"], dirty.toolchain["gitlink_state"])
        self.assertNotEqual(clean.content_fingerprint, dirty.content_fingerprint)
        self.assertIn(("engine/model.txt", ChangeStatus.MODIFIED, None), changes)
        self.assertIn(("engine/staged.txt", ChangeStatus.MODIFIED, None), changes)
        self.assertIn(("engine/deleted.txt", ChangeStatus.DELETED, None), changes)
        self.assertIn(("engine/untracked.txt", ChangeStatus.UNTRACKED, None), changes)

        provenance = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        ).materialize(self._request())
        materialized = Path(provenance.materialized_root)
        self.assertEqual((materialized / "engine" / "model.txt").read_text(), "model dirty\n")
        self.assertEqual((materialized / "engine" / "staged.txt").read_text(), "staged v2\n")
        self.assertEqual(
            (materialized / "engine" / "untracked.txt").read_text(),
            "nested untracked\n",
        )
        self.assertFalse((materialized / "engine" / "deleted.txt").exists())
        self.assertFalse((materialized / "engine" / ".git").exists())

    def test_advanced_gitlink_head_reports_prefixed_commit_changes(self) -> None:
        nested, _source = self._add_gitlink()
        snapshot_source = GitSnapshotSource()
        clean = snapshot_source.scan(self._request())
        (nested / "model.txt").write_text("committed nested change\n", encoding="utf-8")
        self._git_in(nested, "commit", "--quiet", "-am", "advance nested head")

        advanced = snapshot_source.scan(self._request())
        changes = {
            (item.path, item.status)
            for item in snapshot_source.discover_live_changes(self._request())
        }

        self.assertNotEqual(
            clean.toolchain["gitlink_state"],
            advanced.toolchain["gitlink_state"],
        )
        self.assertIn(("engine/model.txt", ChangeStatus.MODIFIED), changes)

    def test_rejects_missing_or_symlinked_gitlink_worktree(self) -> None:
        nested, source_repository = self._add_gitlink()
        snapshot_source = GitSnapshotSource()
        shutil.rmtree(nested)
        with self.assertRaisesRegex(
            SnapshotMaterializationError, "gitlink worktree is unavailable"
        ):
            snapshot_source.scan(self._request())

        nested.symlink_to(source_repository, target_is_directory=True)
        with self.assertRaisesRegex(
            SnapshotMaterializationError, "gitlink worktree must be one real directory"
        ):
            snapshot_source.scan(self._request())

    def test_rejects_unmerged_nested_gitlink_index(self) -> None:
        nested, _source = self._add_gitlink()
        base_branch = self._git_in(
            nested, "branch", "--show-current"
        ).decode("utf-8").strip()
        self._git_in(nested, "checkout", "--quiet", "-b", "conflicting")
        (nested / "model.txt").write_text("branch value\n", encoding="utf-8")
        self._git_in(nested, "commit", "--quiet", "-am", "branch change")
        self._git_in(nested, "checkout", "--quiet", base_branch)
        (nested / "model.txt").write_text("base value\n", encoding="utf-8")
        self._git_in(nested, "commit", "--quiet", "-am", "base change")
        conflict = subprocess.run(
            ["git", "-C", str(nested), "merge", "--no-edit", "conflicting"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(conflict.returncode, 0)

        with self.assertRaisesRegex(
            SnapshotMaterializationError, "unmerged entry"
        ):
            GitSnapshotSource().scan(self._request())

    def test_live_scan_fingerprints_and_classifies_head_relative_changes(self) -> None:
        manifest_value = manifest_document()
        manifest_value["intents"]["change"] = {  # type: ignore[index]
            "source_mode": "live",
            "allow_reuse": False,
        }
        manifest_value["targets"]["unit"]["intents"].append("change")  # type: ignore[index]
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest_value, sort_keys=True), encoding="utf-8"
        )
        self._git("mv", "tracked.txt", "renamed.txt")
        (self.root / "untracked.txt").write_text("new\n", encoding="utf-8")
        manifest = parse_test_manifest(manifest_value, repository_root=self.root)
        request = SnapshotMaterializationRequest(
            repository_id="repo-snapshot-tests",
            original_root=str(self.root),
            temporary_root=None,
            manifest_fingerprint=manifest.fingerprint,
            intent="change",
            owner_uid=os.geteuid(),
        )
        source = GitSnapshotSource()
        scan = source.scan(request)
        changes = source.discover_live_changes(request)
        self.assertEqual(len(scan.content_fingerprint), 64)
        self.assertIn(
            ("renamed.txt", ChangeStatus.RENAMED, "tracked.txt"),
            {(item.path, item.status, item.previous_path) for item in changes},
        )
        self.assertIn(
            ("untracked.txt", ChangeStatus.UNTRACKED, None),
            {(item.path, item.status, item.previous_path) for item in changes},
        )
        materialized = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        ).materialize(request)
        self.assertTrue(materialized.complete)
        self.assertEqual(materialized.repository_id, request.repository_id)
        self.assertEqual(materialized.content_fingerprint, scan.content_fingerprint)
        captured_root = Path(materialized.materialized_root)
        self.assertTrue((captured_root / "renamed.txt").is_file())
        self.assertTrue((captured_root / "untracked.txt").is_file())
        self.assertFalse((captured_root / "tracked.txt").exists())

        planned = execute_uid_helper(
            {
                "operation": "live_plan",
                "owner_uid": os.geteuid(),
                "arguments": {
                    "repository_id": "repo-snapshot-tests",
                    "original_root": str(self.root),
                    "execution_root": str(self.root),
                    "intent": "change",
                    "timeouts": {
                        "execution_seconds": 4_321,
                        "launch_seconds": 987,
                    },
                },
            }
        )
        self.assertEqual(planned["plan"]["source"]["mode"], "live")
        self.assertEqual(planned["plan"]["source"]["temporary_root"], None)
        self.assertEqual(
            planned["plan"]["source"]["content_fingerprint"],
            scan.content_fingerprint,
        )
        self.assertEqual(set(planned["launch_catalog"]), {"unit"})
        self.assertEqual(
            planned["plan"]["timeouts"],
            {"execution_seconds": 4_321, "launch_seconds": 987},
        )
        self.assertEqual(
            planned["target_resources"]["unit"]["estimated_seconds"], 4_321.0
        )
        self.assertEqual(
            planned["launch_catalog"]["unit"]["timeout_seconds"], 4_321
        )

    def test_uid_helper_live_plan_preserves_manifest_contract_location(self) -> None:
        manifest = manifest_document()
        manifest["defaults"]["resources"] = {  # type: ignore[index]
            "cpu_millis": 6000,
            "memory_mib": 12288,
            "pids": 2048,
        }
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )

        with self.assertRaisesRegex(
            SnapshotMaterializationError,
            r"snapshot test manifest is invalid: \$\.defaults: unknown field",
        ):
            execute_uid_helper(
                {
                    "operation": "live_plan",
                    "owner_uid": os.geteuid(),
                    "arguments": {
                        "repository_id": "repo-snapshot-tests",
                        "original_root": str(self.root),
                        "execution_root": str(self.root),
                        "intent": "change",
                    },
                }
            )

    def test_uid_helper_scan_accepts_the_typed_request_source_root(self) -> None:
        request = self._request()
        result = execute_uid_helper(
            {
                "operation": "scan",
                "owner_uid": request.owner_uid,
                "arguments": {
                    "repository_id": request.repository_id,
                    "original_root": request.original_root,
                    "temporary_root": request.temporary_root,
                    "manifest_fingerprint": request.manifest_fingerprint,
                    "intent": request.intent,
                },
            }
        )

        self.assertEqual(set(result), {"scan"})
        self.assertEqual(
            result["scan"]["manifest_fingerprint"],
            request.manifest_fingerprint,
        )
        self.assertEqual(len(result["scan"]["content_fingerprint"]), 64)

    def test_root_control_plane_scan_can_read_for_a_different_owner(self) -> None:
        request = self._request(owner_uid=os.geteuid() + 1)

        with mock.patch(
            "devcoordinator.universal_test_uid_helper.os.geteuid", return_value=0
        ):
            result = execute_uid_helper(
                {
                    "operation": "scan",
                    "owner_uid": request.owner_uid,
                    "arguments": {
                        "repository_id": request.repository_id,
                        "original_root": request.original_root,
                        "temporary_root": request.temporary_root,
                        "manifest_fingerprint": request.manifest_fingerprint,
                        "intent": request.intent,
                    },
                }
            )

        self.assertEqual(set(result), {"scan"})
        self.assertEqual(
            result["scan"]["manifest_fingerprint"], request.manifest_fingerprint
        )

    def test_root_control_plane_live_plan_can_read_for_a_different_owner(self) -> None:
        manifest_value = manifest_document()
        manifest_value["intents"]["change"] = {  # type: ignore[index]
            "source_mode": "live",
            "allow_reuse": False,
        }
        manifest_value["targets"]["unit"]["intents"].append("change")  # type: ignore[index]
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest_value, sort_keys=True), encoding="utf-8"
        )
        owner_uid = os.geteuid() + 1

        with mock.patch(
            "devcoordinator.universal_test_uid_helper.os.geteuid", return_value=0
        ):
            result = execute_uid_helper(
                {
                    "operation": "live_plan",
                    "owner_uid": owner_uid,
                    "arguments": {
                        "repository_id": "repo-snapshot-tests",
                        "original_root": str(self.root),
                        "execution_root": str(self.root),
                        "intent": "change",
                    },
                }
            )

        self.assertEqual(result["plan"]["source"]["mode"], "live")
        self.assertEqual(set(result["launch_catalog"]), {"unit"})

    def test_non_root_control_plane_reads_reject_a_different_owner(self) -> None:
        effective_uid = os.geteuid()
        owner_uid = effective_uid + 1
        requests = {
            "scan": {
                "repository_id": "repo-snapshot-tests",
                "original_root": str(self.root),
                "temporary_root": None,
                "manifest_fingerprint": self._request().manifest_fingerprint,
                "intent": "release",
            },
            "live_plan": {
                "repository_id": "repo-snapshot-tests",
                "original_root": str(self.root),
                "execution_root": str(self.root),
                "intent": "change",
            },
        }

        with mock.patch(
            "devcoordinator.universal_test_uid_helper.os.geteuid",
            return_value=effective_uid,
        ):
            for operation, arguments in requests.items():
                with self.subTest(operation=operation), self.assertRaisesRegex(
                    SnapshotMaterializationError, "execution identity"
                ):
                    execute_uid_helper(
                        {
                            "operation": operation,
                            "owner_uid": owner_uid,
                            "arguments": arguments,
                        }
                    )

    def test_live_selection_is_immutably_captured_and_registered(self) -> None:
        temporary_root = Path(self.temporary.name) / "temporary-repo"
        completed = subprocess.run(
            ["git", "clone", "--quiet", str(self.root), str(temporary_root)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))
        manifest_value = manifest_document()
        manifest_value["intents"]["change"] = {  # type: ignore[index]
            "source_mode": "live",
            "allow_reuse": False,
        }
        manifest_value["targets"]["unit"]["intents"].append("change")  # type: ignore[index]
        (temporary_root / ".codex" / "tests.json").write_text(
            json.dumps(manifest_value, sort_keys=True), encoding="utf-8"
        )
        owner_uid = os.geteuid()
        (temporary_root / "src.txt").write_text("changed\n", encoding="utf-8")
        helper = OwnerPreviewHelper()
        service = object.__new__(RootSnapshotService)
        service.authority = LiveAuthority(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            execution_root=str(temporary_root),
            owner_uid=owner_uid,
        )
        service.helper = helper
        service.materializer = FilesystemSnapshotMaterializer(
            Path(self.temporary.name) / "captured-live-preview-store",
            allow_unprotected_test_store=True,
        )
        published: list[dict[str, object]] = []
        service._publish_catalog = lambda **values: published.append(values)
        planned = service.preview(
            {
                "repository_id": "repo-snapshot-tests",
                "intent": "change",
                "actor": "codex:captured-change",
                "owner_uid": owner_uid,
                "temporary_root": str(temporary_root),
            }
        )
        self.assertEqual(planned["plan"]["source"]["mode"], "immutable")
        self.assertTrue(
            planned["plan"]["source"]["snapshot_id"].startswith("snapshot-")
        )
        self.assertTrue(planned["plan"]["changes"])
        resources = {
            name: TargetResources(
                estimated_seconds=value["estimated_seconds"],
                shard_count=value["shard_count"],
                worktree_key=value["worktree_key"],
                exclusive_resources=tuple(value["exclusive_resources"]),
                ttl_seconds=value["ttl_seconds"],
            )
            for name, value in planned["target_resources"].items()
        }
        database = Path(self.temporary.name) / "registered-live.sqlite3"
        store = UniversalTestStore.create(database)
        adapter = StoreTestPlaneAdapter(store)
        registered = adapter.register_plan(
            planned["plan"], target_resources=resources
        )
        self.assertTrue(registered["registered"])
        submitted = adapter.submit(
            plan_id=registered["plan_id"],
            repository_id="repo-snapshot-tests",
            operation_id="11111111-1111-4111-8111-111111111111",
            actor="codex:temporary-integration",
            owner_uid=owner_uid,
        )
        self.assertTrue(submitted["run_id"].startswith("run-"))
        self.assertEqual(
            store.get_run(submitted["run_id"])["source_mode"], "immutable"
        )
        self.assertEqual(len(published), 1)

    def test_immutable_temporary_manual_preview_materializes_and_selects_target(self) -> None:
        temporary_root = Path(self.temporary.name) / "temporary-immutable"
        completed = subprocess.run(
            ["git", "clone", "--quiet", str(self.root), str(temporary_root)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            self.fail(completed.stderr.decode("utf-8", errors="replace"))
        owner_uid = os.geteuid()
        service = object.__new__(RootSnapshotService)
        service.authority = LiveAuthority(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            execution_root=str(temporary_root),
            owner_uid=owner_uid,
        )
        service.helper = OwnerPreviewHelper()
        service.materializer = FilesystemSnapshotMaterializer(
            Path(self.temporary.name) / "immutable-preview-store",
            allow_unprotected_test_store=True,
        )
        published: list[dict[str, object]] = []
        service._publish_catalog = lambda **values: published.append(values)
        preview = service.preview(
            {
                "repository_id": "repo-snapshot-tests",
                "intent": "manual",
                "actor": "codex:manual-preview",
                "owner_uid": owner_uid,
                "temporary_root": str(temporary_root),
                "requested_targets": ["unit"],
            }
        )
        selected = preview["plan"]
        self.assertEqual(selected["source"]["mode"], "immutable")
        self.assertEqual(
            selected["source"]["temporary_root"], str(temporary_root)
        )
        self.assertTrue(selected["source"]["snapshot_id"].startswith("snapshot-"))
        self.assertEqual(selected["selected_targets"], ["unit"])
        self.assertIn("requested", selected["selection"]["unit"])
        self.assertEqual(set(preview["target_resources"]), {"unit"})
        self.assertEqual(len(published), 1)

    def test_preview_preserves_an_expired_forwarded_launch_deadline(self) -> None:
        owner_uid = os.geteuid()
        temporary_root = self.root / "expired-preview-worktree"
        temporary_root.mkdir()
        service = object.__new__(RootSnapshotService)
        service.authority = LiveAuthority(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            execution_root=str(temporary_root),
            owner_uid=owner_uid,
        )
        service.helper = OwnerPreviewHelper()
        service.materializer = FilesystemSnapshotMaterializer(
            Path(self.temporary.name) / "expired-preview-store",
            allow_unprotected_test_store=True,
        )
        service._publish_catalog = mock.Mock()
        with self.assertRaisesRegex(
            SnapshotMaterializationError, "caller launch deadline"
        ):
            service.preview(
                {
                    "repository_id": "repo-snapshot-tests",
                    "intent": "manual",
                    "actor": "codex:expired-preview",
                    "owner_uid": owner_uid,
                    "temporary_root": str(temporary_root),
                    "launch_timeout_seconds": 300,
                    "launch_deadline_monotonic": 0.001,
                }
            )
        service._publish_catalog.assert_not_called()

    def test_uid_previewer_resolves_root_internally_and_returns_immutable_plan(self) -> None:
        binding = SnapshotRepositoryBinding(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            owner_uid=os.geteuid(),
        )
        resolver = ExactResolver(binding)
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            resolver,
        )
        document = previewer.preview_as_owner(
            repository_id=binding.repository_id,
            intent="release",
            actor="broker:test",
            owner_uid=binding.owner_uid,
        )
        self.assertEqual(resolver.calls, [(binding.repository_id, binding.owner_uid)])
        plan = document["plan"]
        self.assertEqual(plan["repository_id"], binding.repository_id)
        self.assertEqual(plan["intent"], "release")
        self.assertEqual(plan["source"]["mode"], "immutable")
        self.assertTrue(str(plan["source"]["snapshot_id"]).startswith("snapshot-"))
        self.assertEqual(set(document["target_resources"]), set(plan["selected_targets"]))

    def test_uid_previewer_preserves_manifest_contract_location(self) -> None:
        manifest = manifest_document()
        manifest["defaults"]["resources"] = {  # type: ignore[index]
            "cpu_millis": 6000,
            "memory_mib": 12288,
            "pids": 2048,
        }
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        binding = SnapshotRepositoryBinding(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            owner_uid=os.geteuid(),
        )
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            ExactResolver(binding),
        )

        with self.assertRaisesRegex(
            SnapshotMaterializationError,
            r"snapshot test manifest is invalid: \$\.defaults: unknown field",
        ):
            previewer.preview_as_owner(
                repository_id=binding.repository_id,
                intent="release",
                actor="broker:test",
                owner_uid=binding.owner_uid,
            )

    def test_uid_previewer_setup_includes_target_fixture_bindings(self) -> None:
        manifest = manifest_document()
        manifest["fixtures"] = {
            "postgres": {"template": "postgres-template", "network": "loopback"}
        }
        target = manifest["targets"]["unit"]  # type: ignore[index]
        target["network"] = "loopback"
        target["fixtures"] = ["postgres"]
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        binding = SnapshotRepositoryBinding(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            owner_uid=os.geteuid(),
        )
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            ExactResolver(binding),
        )

        setup = previewer.setup_as_owner(
            repository_id=binding.repository_id,
            owner_uid=binding.owner_uid,
        )
        decoded = decode_repository_setup_document(
            setup, expected_repository_id=binding.repository_id
        )
        self.assertEqual(decoded["targets"][0]["fixtures"], ["postgres"])

    def test_shard_ceiling_never_duplicates_an_unpartitioned_argv(self) -> None:
        manifest = manifest_document()
        manifest["targets"]["unit"]["shard"] = {  # type: ignore[index]
            "mode": "history",
            "max_shards": 8,
        }
        (self.root / ".codex" / "tests.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        binding = SnapshotRepositoryBinding(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            owner_uid=os.geteuid(),
        )
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            ExactResolver(binding),
        )
        document = previewer.preview_as_owner(
            repository_id=binding.repository_id,
            intent="release",
            actor="broker:test",
            owner_uid=binding.owner_uid,
        )
        self.assertEqual(document["target_resources"]["unit"]["shard_count"], 1)

    def test_test_plane_preview_is_registered_only_after_authority_check(self) -> None:
        binding = SnapshotRepositoryBinding(
            repository_id="repo-snapshot-tests",
            canonical_root=str(self.root),
            owner_uid=os.geteuid(),
        )
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            ExactResolver(binding),
        )
        database = Path(self.temporary.name) / "test-plane.sqlite3"
        adapter = StoreTestPlaneAdapter(
            UniversalTestStore.create(database), previewer=previewer
        )
        result = adapter.preview(
            repository_id=binding.repository_id,
            intent="release",
            actor="broker:test",
            owner_uid=binding.owner_uid,
        )
        self.assertEqual(result["repository_id"], binding.repository_id)
        self.assertFalse(result["registered"])
        self.assertEqual(result["plan"]["source"]["mode"], "immutable")
        adapter.register_plan(result["plan"])
        self.assertEqual(
            adapter.plan_repository(
                plan_id=result["plan"]["plan_id"],
                repository_id=binding.repository_id,
            ),
            binding.repository_id,
        )

    def test_uid_previewer_rejects_contradictory_authority_binding(self) -> None:
        resolver = ExactResolver(
            SnapshotRepositoryBinding(
                repository_id="repo-other",
                canonical_root=str(self.root),
                owner_uid=os.geteuid(),
            )
        )
        previewer = ImmutableSnapshotPlanPreviewer(
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ),
            resolver,
        )
        with self.assertRaisesRegex(SnapshotMaterializationError, "contradictory"):
            previewer.preview_as_owner(
                repository_id="repo-snapshot-tests",
                intent="release",
                actor="broker:test",
                owner_uid=os.geteuid(),
            )

    def test_rejects_repository_escape_and_wrong_owner(self) -> None:
        escape = self.root / "escape"
        escape.symlink_to("/etc/passwd")
        self._git("add", "escape")
        with self.assertRaisesRegex(SnapshotMaterializationError, "absolute symlink"):
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ).materialize(self._request())

        escape.unlink()
        with self.assertRaisesRegex(SnapshotMaterializationError, "owner"):
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ).materialize(
                self._request(owner_uid=os.geteuid() + 1)
            )

    def test_store_metadata_is_not_a_local_authorization_boundary(self) -> None:
        self.store.mkdir()
        self.store.chmod(0o777)
        provenance = FilesystemSnapshotMaterializer(self.store).materialize(
            self._request()
        )
        self.assertTrue(Path(provenance.materialized_root).is_dir())

    def test_rejects_symlink_to_content_excluded_from_snapshot(self) -> None:
        (self.root / "private.ignored").write_text("excluded\n", encoding="utf-8")
        (self.root / "included-link").symlink_to("private.ignored")
        self._git("add", "included-link")
        with self.assertRaisesRegex(SnapshotMaterializationError, "excluded or incomplete"):
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ).materialize(self._request())

    def test_provenance_rejects_snapshot_path_escape(self) -> None:
        materializer = FilesystemSnapshotMaterializer(
            self.store, allow_unprotected_test_store=True
        )
        with self.assertRaisesRegex(SnapshotMaterializationError, "invalid format"):
            materializer.provenance("snapshot-../../outside")

    def test_source_mutation_during_copy_fails_without_publication(self) -> None:
        source = MutatingSource(GitSnapshotSource(), self.root / "tracked.txt")
        materializer = FilesystemSnapshotMaterializer(
            self.store,
            source=source,
            allow_unprotected_test_store=True,
        )
        with self.assertRaisesRegex(SnapshotMaterializationError, "changed"):
            materializer.materialize(self._request())
        self.assertFalse(list(self.store.glob("snapshot-*")))
        self.assertFalse(list(self.store.glob(".snapshot-*")))

    def test_missing_tracked_content_is_incomplete_not_a_deletion(self) -> None:
        self._git("update-index", "--skip-worktree", "tracked.txt")
        (self.root / "tracked.txt").unlink()
        with self.assertRaisesRegex(SnapshotMaterializationError, "unavailable"):
            FilesystemSnapshotMaterializer(
                self.store, allow_unprotected_test_store=True
            ).materialize(self._request())


if __name__ == "__main__":
    unittest.main()
