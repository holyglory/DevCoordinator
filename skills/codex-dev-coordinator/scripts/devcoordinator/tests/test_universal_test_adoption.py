from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import uuid

from devcoordinator.universal_test_adoption import TestManifestAdoptionManager
from devcoordinator.universal_test_cli import _manifest_template
from devcoordinator.universal_test_snapshot import SnapshotMaterializationError
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    TestStoreContractError,
)
from devcoordinator import universal_test_uid_helper as uid_helper


class _RepositoryCLIUnavailable:
    def __init__(self, filename: str) -> None:
        self.filename = filename

    def __getattr__(self, name: str):
        del name
        raise unittest.SkipTest(
            f"repository-only CLI {self.filename} is unavailable in a standalone skill copy"
        )


def _load_repository_cli(*, test_file: Path, filename: str, module_name: str):
    """Load a repository CLI only when this skill belongs to that source tree."""

    skill_root = test_file.resolve().parents[3]
    repository_root = skill_root.parent.parent
    configured_skill = repository_root / "skills" / skill_root.name
    cli_path = repository_root / "scripts" / filename
    try:
        source_tree_matches = configured_skill.samefile(skill_root)
    except OSError:
        source_tree_matches = False
    if not source_tree_matches or not cli_path.is_file():
        return _RepositoryCLIUnavailable(filename)
    spec = importlib.util.spec_from_file_location(module_name, cli_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load repository CLI {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adoption_cli = _load_repository_cli(
    test_file=Path(__file__),
    filename="manage_universal_test_adoption.py",
    module_name="manage_universal_test_adoption_test",
)


class FakeAuthority:
    def __init__(self, records: dict[str, dict[str, object]]) -> None:
        self.records = records

    def repository(self, *, repository_id: str):
        return dict(self.records[repository_id])


class LocalUIDHelper:
    def call(self, operation: str, *, owner_uid: int, arguments):
        return uid_helper.execute(
            {
                "operation": operation,
                "owner_uid": owner_uid,
                "arguments": dict(arguments),
            }
        )


class FailingSecondApplyHelper(LocalUIDHelper):
    def __init__(self, failing_root: Path) -> None:
        self.failing_root = str(failing_root)

    def call(self, operation: str, *, owner_uid: int, arguments):
        if operation == "adoption_apply" and arguments["repository_root"] == self.failing_root:
            raise SnapshotMaterializationError("injected second-repository failure")
        return super().call(operation, owner_uid=owner_uid, arguments=arguments)


class WriteThenFailHelper(LocalUIDHelper):
    def __init__(self, failing_root: Path) -> None:
        self.failing_root = str(failing_root)

    def call(self, operation: str, *, owner_uid: int, arguments):
        result = super().call(operation, owner_uid=owner_uid, arguments=arguments)
        if operation == "adoption_apply" and arguments["repository_root"] == self.failing_root:
            raise SnapshotMaterializationError("injected uncertain apply reply")
        return result


class FailingSecondApplyAndRollbackOnceHelper(FailingSecondApplyHelper):
    def __init__(self, failing_root: Path) -> None:
        super().__init__(failing_root)
        self.rollback_failed = False

    def call(self, operation: str, *, owner_uid: int, arguments):
        if operation == "adoption_rollback" and not self.rollback_failed:
            self.rollback_failed = True
            raise SnapshotMaterializationError("injected rollback interruption")
        return super().call(operation, owner_uid=owner_uid, arguments=arguments)


class RollbackWriteThenFailOnceHelper(LocalUIDHelper):
    def __init__(self) -> None:
        self.failed = False

    def call(self, operation: str, *, owner_uid: int, arguments):
        result = super().call(operation, owner_uid=owner_uid, arguments=arguments)
        if operation == "adoption_rollback" and not self.failed:
            self.failed = True
            raise SnapshotMaterializationError("injected uncertain rollback reply")
        return result


class MutatingCatalogHelper(LocalUIDHelper):
    def __init__(self) -> None:
        self.mutated = False

    def call(self, operation: str, *, owner_uid: int, arguments):
        result = super().call(operation, owner_uid=owner_uid, arguments=arguments)
        if operation == "adoption_catalog" and not self.mutated:
            self.mutated = True
            root = Path(arguments["repository_root"])
            (root / ".codex" / "tests.json").write_text(
                '{"schema_version":1}\n', encoding="utf-8"
            )
        return result


class UnreadableTrackedSafetyHelper(LocalUIDHelper):
    def call(self, operation: str, *, owner_uid: int, arguments):
        result = super().call(operation, owner_uid=owner_uid, arguments=arguments)
        if operation == "adoption_safety_identity":
            return {
                **result,
                "unreadable_tracked_count": 1,
                "unreadable_tracked_sample": ["0" * 16],
                "unreadable_tracked_entries_complete": False,
                "unreadable_tracked_entries": [],
            }
        return result




class UniversalTestManifestAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep fixture creation deterministic. Metadata is diagnostic on this
        # trusted local server, while later tests deliberately vary modes to
        # prove they do not become authorization policy again.
        previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, previous_umask)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.evidence = self.base / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.records: dict[str, dict[str, object]] = {}

    def repository(self, repository_id: str, generation: int = 0) -> Path:
        root = self.base / repository_id
        root.mkdir(mode=0o755)
        (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Manifest adoption test",
                "-c",
                "user.email=manifest-adoption@example.invalid",
                "-C",
                str(root),
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            check=True,
        )
        self.records[repository_id] = {
            "repository_id": repository_id,
            "canonical_root": str(root),
            "generation": generation,
        }
        return root

    def git_repository(self, repository_id: str, generation: int = 0) -> Path:
        return self.repository(repository_id, generation=generation)

    def authority_export(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": 1,
            "kind": "devcoordinator-authority-repository-export",
            "authority_generation": "authority-generation-test",
            "repositories": [
                {
                    "repository_id": repository_id,
                    "repository_generation": record["generation"],
                }
                for repository_id, record in sorted(self.records.items())
            ],
            "exported_at": "2026-07-28T00:00:00Z",
        }
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        document["document_sha256"] = hashlib.sha256(payload).hexdigest()
        return document

    def test_repository_cli_discovery_fails_closed_after_skill_relocation(self) -> None:
        relocated = self.base / "standalone" / "codex-dev-coordinator"
        relocated_test = (
            relocated
            / "scripts"
            / "devcoordinator"
            / "tests"
            / Path(__file__).name
        )
        relocated_test.parent.mkdir(parents=True)
        relocated_test.touch()
        unavailable = _load_repository_cli(
            test_file=relocated_test,
            filename="manage_universal_test_adoption.py",
            module_name="relocated_manage_universal_test_adoption_test",
        )
        with self.assertRaises(unittest.SkipTest):
            unavailable._write_private_once

    def manager(self, helper=None) -> TestManifestAdoptionManager:
        return TestManifestAdoptionManager(
            authority=FakeAuthority(self.records),
            helper=helper or LocalUIDHelper(),
            evidence_root=self.evidence,
            execution_uid=self.uid,
            expected_evidence_uid=self.uid,
        )

    def request(self, proposals: dict[str, dict[str, object]]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "operation_id": str(uuid.uuid4()),
            "excluded_repositories": [],
            "repositories": [
                {
                    "repository_id": repository_id,
                    "repository_generation": self.records[repository_id]["generation"],
                    "execution_uid": self.uid,
                    "manifest": proposal,
                }
                for repository_id, proposal in sorted(proposals.items())
            ],
        }

    def test_missing_and_invalid_manifests_apply_with_private_exact_rollback(self) -> None:
        missing = self.repository("repo-missing")
        invalid = self.repository("repo-invalid")
        invalid_manifest = invalid / ".codex" / "tests.json"
        invalid_manifest.parent.mkdir(mode=0o755)
        legacy = b'{"schema_version":1,"groups":{"legacy":{}}}\n'
        invalid_manifest.write_bytes(legacy)
        proposal = _manifest_template()
        manager = self.manager()

        plan = manager.plan(
            self.request({"repo-invalid": proposal, "repo-missing": proposal})
        )
        self.assertEqual(
            [(item["repository_id"], item["status"], item["action"]) for item in plan["repositories"]],
            [
                ("repo-invalid", "invalid", "migrate"),
                ("repo-missing", "missing", "initialize"),
            ],
        )
        private_plan = self.evidence / plan["plan_id"] / "plan.json"
        self.assertEqual(stat.S_IMODE(private_plan.stat().st_mode), 0o600)
        self.assertIn("current_payload_base64", private_plan.read_text(encoding="utf-8"))
        self.assertNotIn("current_payload_base64", json.dumps(plan))

        applied = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["state"], "applied")
        self.assertNotIn(str(self.base), json.dumps(applied))
        self.assertEqual(
            uid_helper._setup(missing)["status"],  # type: ignore[attr-defined]
            "ready",
        )
        self.assertEqual(
            uid_helper._setup(invalid)["status"],  # type: ignore[attr-defined]
            "ready",
        )

        rolled_back = manager.rollback(
            plan_id=plan["plan_id"], result_sha256=applied["result_sha256"]
        )
        self.assertTrue(rolled_back["ok"])
        self.assertFalse((missing / ".codex" / "tests.json").exists())
        self.assertEqual(invalid_manifest.read_bytes(), legacy)

    def test_sealed_fleet_catalog_and_request_preparation_are_exact(self) -> None:
        invalid = self.repository("repo-invalid")
        missing = self.repository("repo-missing")
        ready = self.repository("repo-ready")
        (invalid / ".codex").mkdir()
        (invalid / ".codex" / "tests.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        existing = _manifest_template()
        (ready / ".codex").mkdir()
        (ready / ".codex" / "tests.json").write_text(
            json.dumps(existing, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manager = self.manager()
        authority_export = self.authority_export()

        catalog = manager.catalog(authority_export)
        self.assertEqual(
            catalog["counts"], {"ready": 1, "missing": 1, "invalid": 1}
        )
        self.assertNotIn(str(self.base), json.dumps(catalog, sort_keys=True))
        self.assertEqual(
            [item["repository_id"] for item in catalog["repositories"]],
            ["repo-invalid", "repo-missing", "repo-ready"],
        )

        proposal = _manifest_template()
        manifest_set = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [
                {"repository_id": "repo-invalid", "manifest": proposal},
                {"repository_id": "repo-missing", "manifest": proposal},
            ],
        }
        prepared = manager.prepare_request(authority_export, manifest_set)
        rows = {
            item["repository_id"]: item for item in prepared["repositories"]
        }
        self.assertEqual(rows["repo-ready"]["manifest"], existing)
        self.assertEqual(rows["repo-invalid"]["manifest"], proposal)
        self.assertEqual(rows["repo-missing"]["repository_generation"], 0)
        plan = manager.plan(prepared)
        self.assertEqual(
            [(item["repository_id"], item["action"]) for item in plan["repositories"]],
            [
                ("repo-invalid", "migrate"),
                ("repo-missing", "initialize"),
                ("repo-ready", "preserve_valid"),
            ],
        )

    def test_request_preparation_requires_every_nonready_explicit_document(self) -> None:
        self.repository("repo-missing")
        manager = self.manager()
        authority_export = self.authority_export()
        empty = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [],
        }
        with self.assertRaisesRegex(
            TestStoreContractError, "explicit documents exactly"
        ):
            manager.prepare_request(authority_export, empty)

        corrupt = copy.deepcopy(authority_export)
        corrupt["authority_generation"] = "tampered"
        with self.assertRaisesRegex(TestStoreContractError, "digest"):
            manager.catalog(corrupt)

    def test_catalog_accepts_shared_local_manifest_directory_metadata(self) -> None:
        shared = self.repository("repo-shared")
        shared_directory = shared / ".codex"
        shared_directory.mkdir(mode=0o755)
        shared_directory.chmod(0o775)
        self.repository("repo-missing")
        manager = self.manager()
        authority_export = self.authority_export()

        catalog = manager.catalog(authority_export)
        self.assertEqual(
            catalog["counts"], {"ready": 0, "missing": 2, "invalid": 0}
        )
        rows = {
            item["repository_id"]: item for item in catalog["repositories"]
        }
        self.assertEqual(
            rows["repo-shared"]["problem_code"],
            None,
        )
        self.assertEqual(rows["repo-shared"]["status"], "missing")
        self.assertFalse(rows["repo-shared"]["has_readability_blockers"])
        self.assertNotIn(str(shared), json.dumps(catalog, sort_keys=True))

        manifest_set = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [
                {"repository_id": "repo-missing", "manifest": _manifest_template()},
                {"repository_id": "repo-shared", "manifest": _manifest_template()},
            ],
        }
        prepared = manager.prepare_request(authority_export, manifest_set)
        self.assertEqual(
            [item["repository_id"] for item in prepared["repositories"]],
            ["repo-missing", "repo-shared"],
        )


    def test_git_proven_tracked_deletion_is_not_an_ownership_blocker(self) -> None:
        root = self.git_repository("repo-deletion")
        (root / "tracked.txt").unlink()
        manager = self.manager()
        authority_export = self.authority_export()

        catalog = manager.catalog(authority_export)
        row = catalog["repositories"][0]
        self.assertEqual(row["status"], "missing")
        self.assertEqual(row["readability_status"], "clean")
        self.assertTrue(row["deletion_scan_complete"])
        self.assertEqual(row["deleted_tracked_count"], 1)
        self.assertEqual(row["unreadable_tracked_count"], 0)
        self.assertFalse(row["has_readability_blockers"])

        manifest_set = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [
                {"repository_id": "repo-deletion", "manifest": _manifest_template()}
            ],
        }
        prepared = manager.prepare_request(authority_export, manifest_set)
        self.assertEqual(prepared["repositories"][0]["repository_id"], "repo-deletion")

    def test_catalog_and_prepare_fail_closed_on_unreadable_tracked_tree(self) -> None:
        self.repository("repo-blocked")
        manager = self.manager(UnreadableTrackedSafetyHelper())
        authority_export = self.authority_export()

        catalog = manager.catalog(authority_export)
        row = catalog["repositories"][0]
        self.assertEqual(row["status"], "missing")
        self.assertEqual(row["readability_status"], "blocked")
        self.assertFalse(row["adoption_ready"])
        self.assertTrue(row["has_readability_blockers"])
        self.assertEqual(row["unreadable_tracked_count"], 1)
        self.assertIn(
            "unreadable_tracked_entries", row["readability_blocker_codes"]
        )

        manifest_set = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [],
        }
        prepared = manager.prepare_request(authority_export, manifest_set)
        self.assertEqual(prepared["repositories"], [])
        self.assertEqual(
            [item["repository_id"] for item in prepared["excluded_repositories"]],
            ["repo-blocked"],
        )
        plan = manager.plan(prepared)
        self.assertEqual(plan["repositories"], [])
        self.assertEqual(
            [item["repository_id"] for item in plan["excluded_repositories"]],
            ["repo-blocked"],
        )
        applied = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["state"], "applied")
        self.assertEqual(
            [item["repository_id"] for item in applied["excluded_repositories"]],
            ["repo-blocked"],
        )

    def test_prepared_request_is_written_once_private_and_digest_bound(self) -> None:
        output_parent = self.base / "private-output"
        output_parent.mkdir(mode=0o700)
        output = output_parent / "request.json"
        self.repository("repo-a")
        request = self.request({"repo-a": _manifest_template()})
        digest = adoption_cli._write_private_once(
            output, request, expected_uid=self.uid
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(digest, hashlib.sha256(output.read_bytes()).hexdigest())
        initial = output.stat()
        replay_digest = adoption_cli._write_private_once(
            output, request, expected_uid=self.uid
        )
        replayed = output.stat()
        self.assertEqual(replay_digest, digest)
        self.assertEqual(
            (replayed.st_dev, replayed.st_ino),
            (initial.st_dev, initial.st_ino),
        )

        conflicting = copy.deepcopy(request)
        conflicting["operation_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(TestStoreContractError, "another request"):
            adoption_cli._write_private_once(
                output, conflicting, expected_uid=self.uid
            )

    def test_request_preparation_rejects_catalog_to_parse_content_drift(self) -> None:
        root = self.repository("repo-ready")
        (root / ".codex").mkdir()
        (root / ".codex" / "tests.json").write_text(
            json.dumps(_manifest_template(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        authority_export = self.authority_export()
        manifest_set = {
            "schema_version": 1,
            "authority_export_sha256": authority_export["document_sha256"],
            "operation_id": str(uuid.uuid4()),
            "manifests": [],
        }
        with self.assertRaisesRegex(TestStoreConflict, "changed during"):
            self.manager(MutatingCatalogHelper()).prepare_request(
                authority_export, manifest_set
            )

    def test_valid_final_manifest_is_never_overwritten(self) -> None:
        root = self.repository("repo-ready")
        original = _manifest_template()
        (root / ".codex").mkdir(mode=0o755)
        manifest_path = root / ".codex" / "tests.json"
        manifest_path.write_text(
            json.dumps(original, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        before = manifest_path.read_bytes()
        proposed = copy.deepcopy(original)
        proposed["targets"]["tests"]["timeout_seconds"] = 601  # type: ignore[index]
        manager = self.manager()

        plan = manager.plan(self.request({"repo-ready": proposed}))
        self.assertEqual(plan["repositories"][0]["status"], "ready")
        self.assertEqual(plan["repositories"][0]["action"], "preserve_valid")
        self.assertFalse(plan["repositories"][0]["proposed_matches"])
        applied = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertEqual(applied["applied"], [])
        self.assertEqual(manifest_path.read_bytes(), before)

    def test_symlink_and_generation_drift_fail_closed(self) -> None:
        escaped = self.repository("repo-symlink")
        outside = self.base / "outside"
        outside.mkdir()
        (escaped / ".codex").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(SnapshotMaterializationError, "unsafe"):
            self.manager().plan(self.request({"repo-symlink": _manifest_template()}))

        generation = self.repository("repo-generation", generation=7)
        manager = self.manager()
        plan = manager.plan(self.request({"repo-generation": _manifest_template()}))
        self.records["repo-generation"]["generation"] = 8
        with self.assertRaisesRegex(TestStoreConflict, "authority changed"):
            manager.apply(plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"])
        self.assertFalse((generation / ".codex" / "tests.json").exists())

    def test_content_drift_blocks_before_any_write(self) -> None:
        root = self.repository("repo-drift")
        manager = self.manager()
        plan = manager.plan(self.request({"repo-drift": _manifest_template()}))
        (root / ".codex").mkdir(mode=0o755)
        manifest = root / ".codex" / "tests.json"
        manifest.write_text("legacy changed after planning\n", encoding="utf-8")

        with self.assertRaisesRegex(TestStoreConflict, "content drifted"):
            manager.apply(plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"])
        self.assertEqual(manifest.read_text(encoding="utf-8"), "legacy changed after planning\n")

    def test_partial_failure_automatically_rolls_back_prior_repositories(self) -> None:
        first = self.repository("repo-a")
        second = self.repository("repo-b")
        manager = self.manager(FailingSecondApplyHelper(second))
        plan = manager.plan(
            self.request({"repo-a": _manifest_template(), "repo-b": _manifest_template()})
        )

        result = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(
            [item["repository_id"] for item in result["automatic_rollback"]],
            ["repo-a"],
        )
        self.assertFalse((first / ".codex" / "tests.json").exists())
        self.assertFalse((second / ".codex" / "tests.json").exists())

    def test_uncertain_reply_detects_exact_write_and_rolls_back_everything(self) -> None:
        first = self.repository("repo-uncertain-a")
        second = self.repository("repo-uncertain-b")
        manager = self.manager(WriteThenFailHelper(second))
        plan = manager.plan(
            self.request(
                {
                    "repo-uncertain-a": _manifest_template(),
                    "repo-uncertain-b": _manifest_template(),
                }
            )
        )

        result = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(
            {item["repository_id"] for item in result["automatic_rollback"]},
            {"repo-uncertain-a", "repo-uncertain-b"},
        )
        self.assertFalse((first / ".codex" / "tests.json").exists())
        self.assertFalse((second / ".codex" / "tests.json").exists())

    def test_apply_resumes_exact_owner_write_after_root_process_crash(self) -> None:
        root = self.repository("repo-resume")
        helper = LocalUIDHelper()
        manager = self.manager(helper)
        plan = manager.plan(self.request({"repo-resume": _manifest_template()}))
        private = json.loads(
            (self.evidence / plan["plan_id"] / "plan.json").read_text(
                encoding="utf-8"
            )
        )
        entry = private["repositories"][0]
        inspection = entry["inspection"]
        helper.call(
            "adoption_apply",
            owner_uid=self.uid,
            arguments={
                "repository_root": entry["canonical_root"],
                "expected_status": inspection["status"],
                "expected_current_digest": inspection["current_digest"],
                "proposed_manifest": entry["proposed_manifest"],
                "expected_proposed_digest": inspection["proposed_digest"],
                "operation_id": private["operation_id"],
            },
        )
        self.assertEqual(uid_helper._setup(root)["status"], "ready")  # type: ignore[attr-defined]

        resumed = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertTrue(resumed["ok"])
        self.assertEqual(
            [item["repository_id"] for item in resumed["applied"]],
            ["repo-resume"],
        )
        manager.rollback(
            plan_id=plan["plan_id"], result_sha256=resumed["result_sha256"]
        )
        self.assertFalse((root / ".codex" / "tests.json").exists())

    def test_incomplete_automatic_rollback_can_be_finished_exactly(self) -> None:
        first = self.repository("repo-a")
        second = self.repository("repo-b")
        helper = FailingSecondApplyAndRollbackOnceHelper(second)
        manager = self.manager(helper)
        plan = manager.plan(
            self.request({"repo-a": _manifest_template(), "repo-b": _manifest_template()})
        )

        result = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "rollback_incomplete")
        restored = manager.rollback(
            plan_id=plan["plan_id"], result_sha256=result["result_sha256"]
        )
        self.assertTrue(restored["ok"])
        self.assertFalse((first / ".codex" / "tests.json").exists())
        self.assertFalse((second / ".codex" / "tests.json").exists())

    def test_manual_rollback_resumes_after_uncertain_owner_reply(self) -> None:
        root = self.repository("repo-rollback-resume")
        helper = RollbackWriteThenFailOnceHelper()
        manager = self.manager(helper)
        plan = manager.plan(self.request({"repo-rollback-resume": _manifest_template()}))
        result = manager.apply(
            plan_id=plan["plan_id"], plan_sha256=plan["plan_sha256"]
        )
        with self.assertRaisesRegex(SnapshotMaterializationError, "uncertain"):
            manager.rollback(
                plan_id=plan["plan_id"], result_sha256=result["result_sha256"]
            )
        self.assertFalse((root / ".codex" / "tests.json").exists())
        resumed = manager.rollback(
            plan_id=plan["plan_id"], result_sha256=result["result_sha256"]
        )
        self.assertTrue(resumed["ok"])


if __name__ == "__main__":
    unittest.main()
