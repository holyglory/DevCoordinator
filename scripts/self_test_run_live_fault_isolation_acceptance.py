#!/usr/bin/env python3
"""Focused tests for immutable live-fault request construction."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/run_live_fault_isolation_acceptance.py"
SPEC = importlib.util.spec_from_file_location(
    "run_live_fault_isolation_acceptance", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("live-fault acceptance wrapper could not be loaded")
wrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wrapper)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)


class LiveFaultRequestBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.repository = self.root / "repository"
        self.unrelated = self.root / "unrelated"
        self.repository.mkdir()
        self.unrelated.mkdir()

    def tearDown(self) -> None:
        for target in sorted(self.root.rglob("*"), reverse=True):
            try:
                if target.is_dir() and not target.is_symlink():
                    target.chmod(0o700)
                elif target.exists() and not target.is_symlink():
                    target.chmod(0o600)
            except OSError:
                pass
        self.root.chmod(0o700)
        self.temporary.cleanup()

    @staticmethod
    def _different_digest(value: str) -> str:
        return ("0" if value[0] != "0" else "1") + value[1:]

    def _release_fixture(self, marker: bytes = b"one") -> tuple[Path, Path, Path]:
        immutable_root = self.root / "releases"
        immutable_root.mkdir(exist_ok=True)
        payloads = {
            path.as_posix(): marker + b":" + name.encode("ascii")
            for name, path in wrapper.RELEASE_FILE_PATHS.items()
        }
        entries = [
            {
                "path": path,
                "sha256": wrapper.hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": "0444",
                "kind": "source",
            }
            for path, payload in sorted(payloads.items())
        ]
        digest = wrapper._digest({"schema_version": 1, "files": entries})
        release = immutable_root / digest
        release.mkdir()
        for relative, payload in payloads.items():
            target = release / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(0o444)
        manifest = {
            "schema_version": 1,
            "release_digest": digest,
            "release_directory": None,
            "source_identity": {"fixture": True},
            "files": entries,
            "capabilities": {"live_fault_isolation_acceptance": True},
        }
        manifest_path = release / "release-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest_path.chmod(0o444)
        for directory in sorted(
            [item for item in release.rglob("*") if item.is_dir()], reverse=True
        ):
            directory.chmod(0o555)
        release.chmod(0o555)
        return release, immutable_root, release / wrapper.RELEASE_FILE_PATHS["executor"]

    def _authority_fixture(self) -> Path:
        database = self.root / "authority.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                """
                CREATE TABLE schema_metadata(
                    singleton INTEGER PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL,
                    state_revision INTEGER NOT NULL,
                    migration_state TEXT NOT NULL
                );
                CREATE TABLE hosts(host_id TEXT PRIMARY KEY);
                CREATE TABLE repositories(
                    repo_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    canonical_root TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    state TEXT NOT NULL
                );
                CREATE TABLE repository_installations(
                    repo_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    startup_fenced INTEGER NOT NULL
                );
                CREATE TABLE repository_owners(
                    repo_id TEXT PRIMARY KEY,
                    owner_uid INTEGER NOT NULL,
                    repository_generation INTEGER NOT NULL,
                    authority_generation INTEGER NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    operation_id TEXT NOT NULL
                );
                CREATE TABLE repository_owner_transfers(
                    repo_id TEXT NOT NULL,
                    owner_uid INTEGER NOT NULL,
                    repository_generation INTEGER NOT NULL,
                    authority_generation INTEGER NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    operation_id TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO schema_metadata VALUES(1, 13, 'generation-seven', 23, 'ready')"
            )
            connection.execute("INSERT INTO hosts VALUES('host-one')")
            for repository_id, root in (
                ("repo-target", self.repository),
                ("repo-unrelated", self.unrelated),
            ):
                connection.execute(
                    "INSERT INTO repositories VALUES(?, 'host-one', ?, 7, 'active')",
                    (repository_id, str(root)),
                )
                connection.execute(
                    "INSERT INTO repository_installations VALUES(?, 'installed', 0)",
                    (repository_id,),
                )
                evidence = "sha256:" + ("a" * 64)
                operation = "owner-" + repository_id
                connection.execute(
                    "INSERT INTO repository_owners VALUES(?, ?, 7, 1, ?, ?)",
                    (repository_id, self.uid, evidence, operation),
                )
                connection.execute(
                    "INSERT INTO repository_owner_transfers VALUES(?, ?, 7, 1, ?, ?)",
                    (repository_id, self.uid, evidence, operation),
                )
            connection.commit()
        finally:
            connection.close()
        database.chmod(0o600)
        return database

    def _cutover_evidence(
        self, release: dict[str, object], *, prefix: str = "valid"
    ) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
        activation_values = {field: None for field in wrapper.cutover.ACTIVATION_FIELDS}
        activation_values.update(
            {
                "release_digest": release["digest"],
                "executor_release": release["root"],
            }
        )
        activated = wrapper.cutover.seal(
            wrapper.cutover.ACTIVATION_KIND, activation_values
        )
        live_values = {
            field: None for field in wrapper.cutover.LIVE_ROLLBACK_REHEARSAL_FIELDS
        }
        live_values.update(
            {
                "activation_sha256": activated["document_sha256"],
                "release_digest": release["digest"],
                "executor_release": release["root"],
            }
        )
        live = wrapper.cutover.seal(
            wrapper.cutover.LIVE_ROLLBACK_REHEARSAL_KIND, live_values
        )
        activation_path = self.private / f"{prefix}-activation.json"
        live_path = self.private / f"{prefix}-live.json"
        wrapper.write_private_json(activation_path, activated, expected_uid=self.uid)
        wrapper.write_private_json(live_path, live, expected_uid=self.uid)
        return activation_path, live_path, activated, live

    @staticmethod
    def _release_contract(digest: str = "a" * 64) -> dict[str, object]:
        root = Path("/opt/devcoordinator/releases") / digest
        return {
            "root": str(root),
            "digest": digest,
            "executor": str(root / wrapper.RELEASE_FILE_PATHS["executor"]),
            "executor_sha256": "b" * 64,
            "fault_helper": str(root / wrapper.RELEASE_FILE_PATHS["fault_helper"]),
            "fault_helper_sha256": "c" * 64,
            "runner": str(root / wrapper.RELEASE_FILE_PATHS["runner"]),
            "runner_sha256": "d" * 64,
        }

    def _build_arguments(self) -> wrapper.argparse.Namespace:
        return wrapper.parse_args(
            [
                "build-request",
                "--operation-id",
                str(uuid.UUID(int=1)),
                "--cutover-id",
                "schema13-cutover",
                "--release",
                "/opt/devcoordinator/releases/" + ("a" * 64),
                "--activation",
                "/private/activation.json",
                "--live-rollback-rehearsal",
                "/private/live.json",
                "--authority-database",
                "/private/authority.sqlite3",
                "--authority-owner-uid",
                "990",
                "--repository-root",
                "/srv/repos/project",
                "--inventory-publication",
                "/private/inventory.json",
                "--inventory-owner-uid",
                "991",
                "--edge-cgroup-procs",
                "/sys/fs/cgroup/devcoordinator-control.slice/edge.service/cgroup.procs",
                "--api-cgroup-procs",
                "/sys/fs/cgroup/devcoordinator-control.slice/api.service/cgroup.procs",
                "--authority-cgroup-procs",
                "/sys/fs/cgroup/devcoordinator-control.slice/authority.service/cgroup.procs",
                "--console-cgroup-procs",
                "/sys/fs/cgroup/devcoordinator-control.slice/console.service/cgroup.procs",
                "--console-url",
                "https://console.example/",
                "--board-url",
                "https://board.example/",
                "--api-url",
                "https://console.example/healthz",
                "--project-url",
                "https://project.example/",
                "--websocket-url",
                "wss://project.example/events",
                "--output",
                "/private/request.json",
            ]
        )

    def test_release_binding_hashes_exact_manifest_files_and_rejects_cross_release(self) -> None:
        release, immutable_root, executor = self._release_fixture()
        binding = wrapper._derive_release_binding(
            release,
            executable=executor,
            expected_uid=self.uid,
            expected_gid=self.gid,
            immutable_root=immutable_root,
        )
        self.assertEqual(binding["digest"], release.name)
        for name in wrapper.RELEASE_FILE_PATHS:
            self.assertEqual(
                binding[f"{name}_sha256"],
                wrapper._sha256_file(Path(str(binding[name])), expected_uid=self.uid),
            )
        other_release, _, other_executor = self._release_fixture(b"two")
        self.assertNotEqual(other_release, release)
        with self.assertRaisesRegex(wrapper.FaultAcceptanceError, "selected release"):
            wrapper._derive_release_binding(
                release,
                executable=other_executor,
                expected_uid=self.uid,
                expected_gid=self.gid,
                immutable_root=immutable_root,
            )

    def test_schema13_owner_is_derived_and_filesystem_owner_mismatch_fails(self) -> None:
        database = self._authority_fixture()
        authority, repository = wrapper._read_authority_repository_binding(
            database,
            repository_root=self.repository,
            expected_database_uid=self.uid,
        )
        self.assertEqual(authority["database_generation"], "generation-seven")
        self.assertEqual(repository["repository_id"], "repo-target")
        self.assertEqual(repository["owner_uid"], self.uid)
        self.assertEqual(repository["unrelated_repository_ids"], ["repo-unrelated"])
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "UPDATE repository_owners SET owner_uid = ? WHERE repo_id = 'repo-target'",
                (self.uid + 1,),
            )
            connection.execute(
                "UPDATE repository_owner_transfers SET owner_uid = ? WHERE repo_id = 'repo-target'",
                (self.uid + 1,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            wrapper.FaultAcceptanceError, "filesystem owner differs"
        ):
            wrapper._read_authority_repository_binding(
                database,
                repository_root=self.repository,
                expected_database_uid=self.uid,
            )

    def test_cutover_binding_rejects_cross_release_and_cross_activation(self) -> None:
        release = self._release_contract()
        activation_path, live_path, activated, live = self._cutover_evidence(release)
        binding = wrapper._read_cutover_binding(
            cutover_id="schema13-cutover",
            activation_path=activation_path,
            live_rollback_path=live_path,
            release=release,
            expected_uid=self.uid,
        )
        self.assertEqual(binding["activation_sha256"], activated["document_sha256"])
        other_release = dict(release)
        other_release["digest"] = self._different_digest(str(release["digest"]))
        with self.assertRaisesRegex(wrapper.FaultAcceptanceError, "another release"):
            wrapper._read_cutover_binding(
                cutover_id="schema13-cutover",
                activation_path=activation_path,
                live_rollback_path=live_path,
                release=other_release,
                expected_uid=self.uid,
            )
        live_values = {
            key: value
            for key, value in live.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        live_values["activation_sha256"] = self._different_digest(
            str(activated["document_sha256"])
        )
        crossed = wrapper.cutover.seal(
            wrapper.cutover.LIVE_ROLLBACK_REHEARSAL_KIND, live_values
        )
        crossed_path = self.private / "crossed-live.json"
        wrapper.write_private_json(crossed_path, crossed, expected_uid=self.uid)
        with self.assertRaisesRegex(wrapper.FaultAcceptanceError, "another activation"):
            wrapper._read_cutover_binding(
                cutover_id="schema13-cutover",
                activation_path=activation_path,
                live_rollback_path=crossed_path,
                release=release,
                expected_uid=self.uid,
            )

    def test_build_request_cli_constructs_only_fixed_inputs(self) -> None:
        arguments = self._build_arguments()
        release = self._release_contract()
        cutover_binding = {
            "cutover_id": "schema13-cutover",
            "activation_sha256": "e" * 64,
            "live_rollback_rehearsal_sha256": "f" * 64,
        }
        authority = {
            "host_id": "host-one",
            "host_boot_id": str(uuid.UUID(int=2)),
            "database_generation": "generation-seven",
            "state_revision": 23,
        }
        repository = {
            "repository_id": "repo-target",
            "generation": 7,
            "owner_uid": self.uid,
            "root": "/srv/repos/project",
            "unrelated_repository_ids": ["repo-unrelated"],
        }
        inventory = {
            "publication": "/private/inventory.json",
            "expected_owner_uid": 991,
        }
        with (
            mock.patch.object(wrapper, "_derive_release_binding", return_value=release),
            mock.patch.object(wrapper, "_read_cutover_binding", return_value=cutover_binding),
            mock.patch.object(
                wrapper,
                "_read_authority_repository_binding",
                return_value=(authority, repository),
            ),
            mock.patch.object(wrapper, "_inventory_binding", return_value=inventory),
            mock.patch.object(wrapper, "write_private_json") as publish,
        ):
            result = wrapper._build_request(
                arguments, effective_uid=0, created_at=NOW
            )
        self.assertTrue(result["ok"])
        request = publish.call_args.args[1]
        self.assertEqual(publish.call_count, 1)
        self.assertEqual(publish.call_args.kwargs["expected_uid"], 0)
        self.assertEqual(request["repository"], repository)
        self.assertEqual(request["cutover"], cutover_binding)
        self.assertEqual(len(request["scenarios"]), 6)
        self.assertEqual(
            [item["target_id"] for item in request["probe_targets"]["http"]],
            ["api", "board", "console", "project"],
        )
        encoded = wrapper._canonical(request)
        for forbidden in (b'"argv"', b'"command"', b'"docker"', b'"mounts"'):
            self.assertNotIn(forbidden, encoded)

    def test_request_publication_is_root_private_and_no_clobber(self) -> None:
        output = self.private / "request.json"
        wrapper.write_private_json(output, {"ok": True}, expected_uid=self.uid)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaisesRegex(wrapper.FaultAcceptanceError, "already exists"):
            wrapper.write_private_json(output, {"ok": False}, expected_uid=self.uid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
