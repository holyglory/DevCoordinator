from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import random
import stat
import tempfile
import unittest
from unittest import mock

from devcoordinator.universal_test_contract import (
    MANIFEST_SCHEMA_VERSION,
    MAX_MANIFEST_BYTES,
    ManifestContractError,
    NON_AUTHORITATIVE_RESOURCES,
    SourceMode,
    load_test_manifest,
    manifest_to_document,
    parse_test_manifest,
    repository_glob_matches,
    resolve_contained_repository_path,
)
from devcoordinator.universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    MAX_SELECTION_REASONS,
    SourceIdentity,
    TestPlanError,
    create_test_plan,
    fingerprint_source_content,
)
from devcoordinator.universal_test_service import decode_test_plan_document
from devcoordinator.universal_test_summary import (
    AgentRunSummary,
    AgentSummaryError,
    ArtifactSummary,
    FailureSummary,
    MAX_AGENT_SUMMARY_BYTES,
    agent_summary_json,
    compact_agent_summary,
)
from devcoordinator.universal_test_uid_helper import _plan_documents


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "defaults": {
            "timeout_seconds": 900,
            "network": "none",
            "environment": {"LOG_LEVEL": "warning"},
        },
        "global_inputs": [
            ".codex/tests.json",
            "pyproject.toml",
            "**/package-lock.json",
        ],
        "intents": {
            "change": {"source_mode": "live", "allow_reuse": False},
            "checkpoint": {"source_mode": "live", "allow_reuse": False},
            "handoff": {"source_mode": "immutable", "allow_reuse": True},
            "release": {"source_mode": "immutable", "allow_reuse": False},
            "manual": {"source_mode": "immutable", "allow_reuse": False},
        },
        "fixtures": {
            "database": {"template": "artifact-db", "network": "loopback"}
        },
        "targets": {
            "lint": {
                "driver": "automation",
                "reporter": "automation-events",
                "argv": ["./scripts/lint"],
                "cwd": ".",
                "inputs": ["src/**", "scripts/lint"],
                "depends_on": [],
                "intents": [
                    "change",
                    "checkpoint",
                    "handoff",
                    "release",
                    "manual",
                ],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
            "unit": {
                "driver": "pytest",
                "reporter": "pytest-events",
                "argv": ["{python}", "-m", "pytest", "tests/unit"],
                "cwd": ".",
                "inputs": ["src/**", "tests/unit/**"],
                "depends_on": ["lint"],
                "intents": [
                    "change",
                    "checkpoint",
                    "handoff",
                    "release",
                    "manual",
                ],
                "shard": {"mode": "history", "max_shards": 8},
                "environment": {"PYTHONWARNINGS": "error"},
                "artifacts": [
                    {
                        "name": "coverage",
                        "path": "test-results/coverage.xml",
                        "kind": "coverage",
                        "required": False,
                        "max_bytes": 8_388_608,
                    }
                ],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
            "integration": {
                "driver": "automation",
                "reporter": "jsonl",
                "argv": ["./scripts/integration", "{events}"],
                "cwd": ".",
                "inputs": ["integration/**"],
                "depends_on": ["unit"],
                "intents": ["handoff", "release", "manual"],
                "fixtures": ["database"],
                "network": "loopback",
                "exclusive_resources": ["integration-db"],
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            },
        },
        "evidence_policies": {
            "handoff": {
                "intent": "handoff",
                "required_targets": ["lint", "unit", "integration"],
                "max_age_seconds": 86_400,
                "allow_reuse": True,
            },
            "release": {
                "intent": "release",
                "required_targets": ["lint", "unit", "integration"],
                "max_age_seconds": 3_600,
                "allow_reuse": False,
            },
        },
    }


def source(mode: SourceMode, fingerprint: str = "a" * 64) -> SourceIdentity:
    return SourceIdentity(
        mode=mode,
        repository_id="repo-tests",
        content_fingerprint=fingerprint,
        original_root="/home/example/repo",
        temporary_root="/home/example/worktree" if mode is SourceMode.LIVE else None,
        snapshot_id="snapshot-123" if mode is SourceMode.IMMUTABLE else None,
    )


class ManifestContractTests(unittest.TestCase):
    def test_normalizes_complete_schema_three_contract(self) -> None:
        contract = parse_test_manifest(valid_manifest())
        self.assertEqual(contract.schema_version, MANIFEST_SCHEMA_VERSION)
        self.assertEqual(contract.intents["handoff"].source_mode, SourceMode.IMMUTABLE)
        self.assertEqual(contract.targets["unit"].resources, NON_AUTHORITATIVE_RESOURCES)
        self.assertEqual(
            contract.targets["integration"].resources,
            NON_AUTHORITATIVE_RESOURCES,
        )
        self.assertEqual(
            dict(contract.targets["unit"].environment),
            {"LOG_LEVEL": "warning", "PYTHONWARNINGS": "error"},
        )
        self.assertEqual(len(contract.fingerprint), 64)
        canonical = manifest_to_document(contract)
        self.assertNotIn("resources", canonical["defaults"])
        self.assertTrue(
            all("resources" not in target for target in canonical["targets"].values())
        )
        self.assertEqual(
            parse_test_manifest(canonical).fingerprint,
            contract.fingerprint,
        )

    def test_rejects_obsolete_repository_resource_quotas(self) -> None:
        defaults_document = valid_manifest()
        defaults_document["defaults"]["resources"] = {  # type: ignore[index]
            "cpu_millis": 1_000,
            "memory_mib": 1_024,
            "pids": 256,
        }
        with self.assertRaisesRegex(ManifestContractError, "unknown field.*resources"):
            parse_test_manifest(defaults_document)

        target_document = valid_manifest()
        target_document["targets"]["unit"]["resources"] = {  # type: ignore[index]
            "cpu_millis": 1_000,
            "memory_mib": 1_024,
            "pids": 256,
        }
        with self.assertRaisesRegex(ManifestContractError, "unknown field.*resources"):
            parse_test_manifest(target_document)

    def test_fingerprint_ignores_json_object_key_order(self) -> None:
        first = valid_manifest()
        second = json.loads(json.dumps(first, sort_keys=True))
        self.assertEqual(
            parse_test_manifest(first).fingerprint,
            parse_test_manifest(second).fingerprint,
        )

    def test_rejects_unknown_fields_and_old_contract(self) -> None:
        old = {"schema_version": 1, "groups": {}, "profiles": {}}
        with self.assertRaisesRegex(ManifestContractError, "unknown field"):
            parse_test_manifest(old)
        document = valid_manifest()
        document["commands"] = {}  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "unknown field"):
            parse_test_manifest(document)

    def test_rejects_shell_or_environment_trampoline(self) -> None:
        for executable in ("bash", "/bin/sh", "/usr/bin/env"):
            with self.subTest(executable=executable):
                document = valid_manifest()
                document["targets"]["lint"]["argv"] = [  # type: ignore[index]
                    executable,
                    "-c",
                    "true",
                ]
                with self.assertRaisesRegex(ManifestContractError, "forbidden"):
                    parse_test_manifest(document)
        document = valid_manifest()
        document["targets"]["lint"]["shell"] = True  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "unknown field"):
            parse_test_manifest(document)

    def test_allows_repeated_argv_tokens_without_relaxing_set_fields(self) -> None:
        document = valid_manifest()
        document["targets"]["lint"]["argv"] = [  # type: ignore[index]
            "docker",
            "compose",
            "-f",
            "deploy/base.yml",
            "-f",
            "deploy/test.yml",
            "--profile",
            "test",
            "--profile",
            "capture",
            "config",
        ]
        contract = parse_test_manifest(document)
        self.assertEqual(contract.targets["lint"].argv.count("-f"), 2)
        self.assertEqual(contract.targets["lint"].argv.count("--profile"), 2)

        document = valid_manifest()
        document["targets"]["unit"]["inputs"] = ["src/**", "src/**"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "duplicate items"):
            parse_test_manifest(document)

    def test_rejects_path_escape_and_symlink_escape(self) -> None:
        document = valid_manifest()
        document["targets"]["lint"]["cwd"] = "../outside"  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "inside the repository"):
            parse_test_manifest(document)
        document = valid_manifest()
        document["targets"]["lint"]["inputs"] = ["src/./**"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "normalized"):
            parse_test_manifest(document)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repo"
            root.mkdir()
            (root / "escape").symlink_to(base)
            document = valid_manifest()
            document["targets"]["lint"]["cwd"] = "escape/work"  # type: ignore[index]
            with self.assertRaisesRegex(ManifestContractError, "symlink"):
                parse_test_manifest(document, repository_root=root)
            document = valid_manifest()
            document["targets"]["lint"]["inputs"] = ["escape/**"]  # type: ignore[index]
            with self.assertRaisesRegex(ManifestContractError, "symlink"):
                parse_test_manifest(document, repository_root=root)
            with self.assertRaisesRegex(ManifestContractError, "symlink"):
                resolve_contained_repository_path(root, "escape/dynamic-result.xml")

    def test_manifest_loader_rejects_leaf_and_parent_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside"
            outside.mkdir()
            outside_manifest = outside / "tests.json"
            outside_manifest.write_text(json.dumps(valid_manifest()), encoding="utf-8")

            leaf_root = base / "leaf-root"
            (leaf_root / ".codex").mkdir(parents=True)
            (leaf_root / ".codex" / "tests.json").symlink_to(outside_manifest)
            with self.assertRaisesRegex(ManifestContractError, "symlink"):
                load_test_manifest(leaf_root)

            parent_root = base / "parent-root"
            parent_root.mkdir()
            (parent_root / ".codex").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ManifestContractError, "symlink"):
                load_test_manifest(parent_root)

    def test_manifest_loader_detects_concurrent_same_inode_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / ".codex" / "tests.json").write_text(
                json.dumps(valid_manifest()), encoding="utf-8"
            )
            real_fstat = os.fstat
            regular_observations = 0

            def drifting_fstat(descriptor: int):
                nonlocal regular_observations
                observed = real_fstat(descriptor)
                if stat.S_ISREG(observed.st_mode):
                    regular_observations += 1
                    if regular_observations == 2:
                        fields = list(observed)
                        fields[6] += 1
                        return os.stat_result(fields)
                return observed

            with mock.patch(
                "devcoordinator.universal_test_contract.os.fstat",
                side_effect=drifting_fstat,
            ):
                with self.assertRaisesRegex(ManifestContractError, "changed"):
                    load_test_manifest(root)

    def test_manifest_loader_enforces_byte_limit_on_open_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / ".codex" / "tests.json").write_bytes(
                b" " * (MAX_MANIFEST_BYTES + 1)
            )
            with self.assertRaisesRegex(ManifestContractError, "exceeds"):
                load_test_manifest(root)

    def test_seeded_manifest_fuzz_corpus_fails_closed(self) -> None:
        rng = random.Random(0xD3C00D)
        wrong_container_values = [None, True, False, 0, 1.5, "", [], ["x"]]
        required_object_fields = [
            "defaults",
            "intents",
            "fixtures",
            "targets",
            "evidence_policies",
        ]
        unsafe_paths = [
            "../escape",
            "/absolute",
            "src/./file.py",
            "src\\file.py",
            "src/\x00file.py",
            "src/\nfile.py",
        ]
        for index in range(256):
            document = copy.deepcopy(valid_manifest())
            mutation = index % 8
            if mutation == 0:
                del document[rng.choice(tuple(document))]
            elif mutation == 1:
                document[rng.choice(required_object_fields)] = rng.choice(
                    wrong_container_values
                )
            elif mutation == 2:
                document["global_inputs"] = rng.choice(wrong_container_values)
            elif mutation == 3:
                document["schema_version"] = rng.choice(
                    [None, True, False, -1, 0, 1, 2, 4, 1.5, "3"]
                )
            elif mutation == 4:
                document["unknown_" + rng.randbytes(6).hex()] = {
                    "nested": ["\u2603", "\x00", rng.randrange(1_000_000)]
                }
            elif mutation == 5:
                document["targets"]["unit"][  # type: ignore[index]
                    "unknown_" + rng.randbytes(4).hex()
                ] = True
            elif mutation == 6:
                document["targets"]["unit"]["inputs"] = [  # type: ignore[index]
                    rng.choice(unsafe_paths)
                ]
            else:
                document["targets"]["unit"]["depends_on"] = [  # type: ignore[index]
                    rng.choice(["unit", "missing-" + rng.randbytes(4).hex()])
                ]
            with self.subTest(index=index, mutation=mutation):
                with self.assertRaises(ManifestContractError):
                    parse_test_manifest(document)

    def test_rejects_dependency_cycles(self) -> None:
        document = valid_manifest()
        document["targets"]["lint"]["depends_on"] = ["integration"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "dependency cycle"):
            parse_test_manifest(document)

    def test_schema_three_retry_policy_is_infrastructure_only(self) -> None:
        document = valid_manifest()
        document["targets"]["unit"]["retry"] = {  # type: ignore[index]
            "max_attempts": 1,
            "retry_on": [],
        }
        contract = parse_test_manifest(document)
        self.assertEqual(contract.targets["unit"].retry.max_attempts, 1)
        self.assertEqual(contract.targets["unit"].retry.retry_on, ())
        planned = create_test_plan(
            contract,
            intent="manual",
            source=source(SourceMode.IMMUTABLE),
            requested_targets=("unit",),
        )
        execution = _plan_documents(contract, planned, Path("/tmp/execution"))
        self.assertEqual(
            execution["target_resources"]["unit"]["max_attempts"], 1
        )

        document = valid_manifest()
        document["targets"]["unit"]["retry"] = {  # type: ignore[index]
            "max_attempts": 2,
            "retry_on": ["test_failure"],
        }
        with self.assertRaisesRegex(
            ManifestContractError, "unsupported automatic retry"
        ):
            parse_test_manifest(document)

        document = valid_manifest()
        del document["targets"]["unit"]["retry"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "explicit retry policy"):
            parse_test_manifest(document)

        document = valid_manifest()
        del document["targets"]["unit"]["retry"]["retry_on"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "retry policy is missing"):
            parse_test_manifest(document)

    def test_rejects_schema_two_even_with_explicit_retry(self) -> None:
        document = valid_manifest()
        document["schema_version"] = 2
        with self.assertRaisesRegex(ManifestContractError, "only manifest schema 3"):
            parse_test_manifest(document)

    def test_rejects_unknown_fixture_and_secret_environment(self) -> None:
        document = valid_manifest()
        document["targets"]["unit"]["fixtures"] = ["missing"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "unknown fixture"):
            parse_test_manifest(document)
        document = valid_manifest()
        document["targets"]["unit"]["environment"] = {"API_TOKEN": "nope"}  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "secret-like"):
            parse_test_manifest(document)

    def test_operational_credentials_are_opaque_and_manual_only(self) -> None:
        document = valid_manifest()
        document["credentials"] = {
            "health-sweep-admin": {
                "binding": "skydive-health-sweep-admin-v1",
            }
        }
        document["targets"]["health-sweep"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/health-sweep"],
            "cwd": ".",
            "inputs": ["scripts/health-sweep"],
            "depends_on": [],
            "intents": ["manual"],
            "credentials": ["health-sweep-admin"],
            "network": "external",
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }

        contract = parse_test_manifest(document)

        self.assertEqual(
            contract.credentials["health-sweep-admin"].binding,
            "skydive-health-sweep-admin-v1",
        )
        self.assertEqual(
            contract.targets["health-sweep"].credentials,
            ("health-sweep-admin",),
        )
        canonical = manifest_to_document(contract)
        credential_json = json.dumps(canonical["credentials"], sort_keys=True)
        self.assertEqual(
            canonical["credentials"],
            {
                "health-sweep-admin": {
                    "binding": "skydive-health-sweep-admin-v1",
                }
            },
        )
        for forbidden in ("value", "secret", "token", "path", "file", "env"):
            self.assertNotIn(forbidden, credential_json.lower())

    def test_operational_credentials_reject_values_unknowns_and_broad_intents(self) -> None:
        for forbidden_field in ("value", "path", "source", "credential_name"):
            with self.subTest(forbidden_field=forbidden_field):
                document = valid_manifest()
                document["credentials"] = {
                    "health-sweep-admin": {
                        "binding": "skydive-health-sweep-admin-v1",
                        forbidden_field: "must-not-be-accepted",
                    }
                }
                with self.assertRaisesRegex(ManifestContractError, "unknown field"):
                    parse_test_manifest(document)

        document = valid_manifest()
        document["targets"]["integration"]["credentials"] = ["unknown"]  # type: ignore[index]
        with self.assertRaisesRegex(
            ManifestContractError, "unknown operational credential"
        ):
            parse_test_manifest(document)

        document = valid_manifest()
        document["credentials"] = {
            "health-sweep-admin": {
                "binding": "skydive-health-sweep-admin-v1",
            }
        }
        document["targets"]["integration"]["credentials"] = [  # type: ignore[index]
            "health-sweep-admin"
        ]
        with self.assertRaisesRegex(ManifestContractError, "manual-only"):
            parse_test_manifest(document)

        document["targets"]["integration"]["intents"] = ["manual"]  # type: ignore[index]
        document["targets"]["integration"]["credentials"] = [  # type: ignore[index]
            "health-sweep-admin",
            "health-sweep-admin",
        ]
        with self.assertRaisesRegex(ManifestContractError, "duplicate items"):
            parse_test_manifest(document)

    def test_host_loopback_is_manual_only_fixture_free_and_canonical(self) -> None:
        document = valid_manifest()
        document["targets"]["host-health"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/host-health"],
            "cwd": ".",
            "inputs": ["scripts/host-health"],
            "depends_on": [],
            "intents": ["manual"],
            "network": "host-loopback",
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }
        contract = parse_test_manifest(document)
        self.assertEqual(contract.targets["host-health"].network, "host-loopback")
        self.assertEqual(contract.targets["host-health"].credentials, ())
        self.assertEqual(
            parse_test_manifest(manifest_to_document(contract)).fingerprint,
            contract.fingerprint,
        )

        credential_document = copy.deepcopy(document)
        credential_document["credentials"] = {
            "host-health": {"binding": "host-health-admin-v1"}
        }
        credential_document["targets"]["host-health"]["credentials"] = [  # type: ignore[index]
            "host-health"
        ]
        self.assertEqual(
            parse_test_manifest(credential_document)
            .targets["host-health"]
            .credentials,
            ("host-health",),
        )

        broad = copy.deepcopy(document)
        broad["targets"]["host-health"]["intents"] = [  # type: ignore[index]
            "manual",
            "handoff",
        ]
        with self.assertRaisesRegex(ManifestContractError, "manual-only"):
            parse_test_manifest(broad)

        fixture_bound = copy.deepcopy(document)
        fixture_bound["targets"]["host-health"]["fixtures"] = ["database"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "cannot declare fixtures"):
            parse_test_manifest(fixture_bound)

        fixture_mode = copy.deepcopy(document)
        fixture_mode["fixtures"]["database"]["network"] = "host-loopback"  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "fixture network"):
            parse_test_manifest(fixture_mode)

    def test_rejects_live_reuse_and_release_reuse(self) -> None:
        document = valid_manifest()
        document["intents"]["change"]["allow_reuse"] = True  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "live intent"):
            parse_test_manifest(document)
        document = valid_manifest()
        document["intents"]["release"]["allow_reuse"] = True  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "release evidence"):
            parse_test_manifest(document)
        document = valid_manifest()
        document["evidence_policies"]["change-proof"] = {  # type: ignore[index]
            "intent": "change",
            "required_targets": ["unit"],
            "max_age_seconds": 60,
            "allow_reuse": False,
        }
        with self.assertRaisesRegex(ManifestContractError, "immutable intent"):
            parse_test_manifest(document)

    def test_repository_globs_are_slash_aware(self) -> None:
        self.assertTrue(repository_glob_matches("src/**", "src/a/b.py"))
        self.assertTrue(repository_glob_matches("**/package-lock.json", "package-lock.json"))
        self.assertTrue(
            repository_glob_matches("**/package-lock.json", "web/package-lock.json")
        )
        self.assertTrue(repository_glob_matches("tests/*.py", "tests/test_one.py"))
        self.assertFalse(repository_glob_matches("tests/*.py", "tests/unit/test_one.py"))

    def test_repository_paths_treat_brackets_as_literal_characters(self) -> None:
        changed = ChangedPath(
            "frontend/app/[lang]/page.tsx",
            ChangeStatus.MODIFIED,
        )
        self.assertEqual(
            "frontend/app/[lang]/page.tsx",
            changed.path,
        )
        self.assertTrue(
            repository_glob_matches(
                "frontend/app/[lang]/**",
                "frontend/app/[lang]/page.tsx",
            )
        )
        self.assertFalse(
            repository_glob_matches(
                "frontend/app/[lang]/**",
                "frontend/app/l/page.tsx",
            )
        )
        document = valid_manifest()
        document["targets"]["unit"]["inputs"] = ["src/**suffix"]  # type: ignore[index]
        with self.assertRaisesRegex(ManifestContractError, "complete path segment"):
            parse_test_manifest(document)


class TestPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = parse_test_manifest(valid_manifest())

    def test_live_change_includes_dependency_and_reverse_dependents(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("tests/unit/test_core.py", ChangeStatus.MODIFIED)],
        )
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))
        self.assertEqual(plan.dependency_waves, (("lint",), ("unit",), ("integration",)))
        self.assertIn("input:tests/unit/test_core.py", plan.selection["unit"].reasons)
        self.assertIn("dependency-of:unit", plan.selection["lint"].reasons)
        self.assertIn("dependent-of:unit", plan.selection["integration"].reasons)
        self.assertFalse(plan.complete_intent_fallback)

    def test_dependency_declaration_order_has_one_canonical_plan_identity(self) -> None:
        first = valid_manifest()
        first["targets"]["integration"]["depends_on"] = ["unit", "lint"]  # type: ignore[index]
        second = copy.deepcopy(first)
        second["targets"]["integration"]["depends_on"] = ["lint", "unit"]  # type: ignore[index]
        first_contract = parse_test_manifest(first)
        second_contract = parse_test_manifest(second)

        first_plan = create_test_plan(
            first_contract,
            intent="manual",
            source=source(SourceMode.IMMUTABLE),
            requested_targets=("integration",),
        )
        second_plan = create_test_plan(
            second_contract,
            intent="manual",
            source=source(SourceMode.IMMUTABLE),
            requested_targets=("integration",),
        )

        self.assertEqual(first_contract.fingerprint, second_contract.fingerprint)
        self.assertEqual(first_plan.to_document(), second_plan.to_document())
        self.assertEqual(first_plan.dependencies["integration"], ("lint", "unit"))
        self.assertEqual(
            decode_test_plan_document(first_plan.to_document()),
            first_plan,
        )

    def test_unmapped_change_fails_toward_complete_intent(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("unknown/new.file", ChangeStatus.UNTRACKED)],
        )
        self.assertTrue(plan.complete_intent_fallback)
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))
        self.assertTrue(
            any(
                reason.startswith("unmapped-input:")
                for reason in plan.selection["unit"].reasons
            )
        )

    def test_live_change_never_selects_disconnected_other_intent_target(self) -> None:
        document = valid_manifest()
        document["targets"]["manual-probe"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/manual-probe"],
            "cwd": ".",
            "inputs": ["scripts/manual-probe"],
            "depends_on": [],
            "intents": ["manual"],
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }
        contract = parse_test_manifest(document)

        plan = create_test_plan(
            contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("scripts/manual-probe", ChangeStatus.MODIFIED)],
        )

        self.assertTrue(plan.complete_intent_fallback)
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))
        self.assertNotIn("manual-probe", plan.eligible_targets)
        self.assertTrue(set(plan.selected_targets) <= set(plan.eligible_targets))

    def test_global_input_fails_toward_complete_intent(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("pyproject.toml", ChangeStatus.MODIFIED)],
        )
        self.assertTrue(plan.complete_intent_fallback)
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))

    def test_protected_lock_and_build_changes_always_fail_toward_complete_intent(self) -> None:
        cases = (
            ChangedPath("nested/CMakeLists.txt", ChangeStatus.ADDED),
            ChangedPath("nested/package-lock.json", ChangeStatus.MODIFIED),
            ChangedPath("nested/project.csproj", ChangeStatus.DELETED),
            ChangedPath(".github/workflows/tests.yml", ChangeStatus.UNTRACKED),
            ChangedPath(
                "nested/pnpm-lock.yaml",
                ChangeStatus.RENAMED,
                previous_path="nested/old.lock",
            ),
        )
        for change in cases:
            with self.subTest(change=change):
                plan = create_test_plan(
                    self.contract,
                    intent="change",
                    source=source(SourceMode.LIVE),
                    changes=[change],
                )
                self.assertTrue(plan.complete_intent_fallback)
                self.assertEqual(
                    plan.selected_targets, ("integration", "lint", "unit")
                )
                self.assertTrue(
                    any(
                        reason.startswith("protected-input:")
                        for reason in plan.selection["unit"].reasons
                    )
                )

    def test_rename_requires_both_paths_to_be_mapped(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[
                ChangedPath(
                    "unknown/new.py",
                    ChangeStatus.RENAMED,
                    previous_path="src/old.py",
                )
            ],
        )
        self.assertTrue(plan.complete_intent_fallback)

    def test_immutable_intent_selects_complete_intent_and_can_reuse(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="handoff",
            source=source(SourceMode.IMMUTABLE),
        )
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))
        self.assertTrue(plan.reusable)
        release = create_test_plan(
            self.contract,
            intent="release",
            source=source(SourceMode.IMMUTABLE),
        )
        self.assertFalse(release.reusable)

    def test_plan_includes_only_evidence_policies_for_its_intent(self) -> None:
        handoff = create_test_plan(
            self.contract,
            intent="handoff",
            source=source(SourceMode.IMMUTABLE),
        )
        release = create_test_plan(
            self.contract,
            intent="release",
            source=source(SourceMode.IMMUTABLE),
        )

        self.assertEqual(tuple(handoff.evidence_policies), ("handoff",))
        self.assertEqual(tuple(release.evidence_policies), ("release",))
        self.assertEqual(
            handoff.evidence_policies["handoff"].required_targets,
            ("integration", "lint", "unit"),
        )
        self.assertEqual(
            release.evidence_policies["release"].required_targets,
            ("integration", "lint", "unit"),
        )

    def test_live_without_changes_selects_nothing(self) -> None:
        plan = create_test_plan(
            self.contract,
            intent="checkpoint",
            source=source(SourceMode.LIVE),
        )
        self.assertEqual(plan.selected_targets, ())
        self.assertEqual(plan.dependency_waves, ())

    def test_manual_explicit_target_still_applies_full_closure(self) -> None:
        document = valid_manifest()
        document["targets"]["docs"] = {  # type: ignore[index]
            "driver": "automation",
            "reporter": "automation-events",
            "argv": ["./scripts/docs-check"],
            "cwd": ".",
            "inputs": ["docs/**"],
            "depends_on": [],
            "intents": ["manual"],
            "retry": {
                "max_attempts": 2,
                "retry_on": ["lease_expired_before_launch"],
            },
        }
        contract = parse_test_manifest(document)
        plan = create_test_plan(
            contract,
            intent="manual",
            source=source(SourceMode.IMMUTABLE),
            requested_targets=["unit"],
        )
        # The explicitly requested connected component is complete in both
        # dependency directions, while an independent manual target stays out.
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))

    def test_rejects_source_mode_mismatch_and_immutable_changes(self) -> None:
        document = valid_manifest()
        document["intents"]["manual"]["source_mode"] = "live"  # type: ignore[index]
        with self.assertRaisesRegex(
            ManifestContractError,
            "handoff, release, and manual intents must use immutable",
        ):
            parse_test_manifest(document)
        with self.assertRaisesRegex(TestPlanError, "requires immutable"):
            create_test_plan(
                self.contract,
                intent="release",
                source=source(SourceMode.LIVE),
            )
        with self.assertRaisesRegex(TestPlanError, "do not accept live change"):
            create_test_plan(
                self.contract,
                intent="handoff",
                source=source(SourceMode.IMMUTABLE),
                changes=[ChangedPath("src/a.py", ChangeStatus.MODIFIED)],
            )

    def test_plan_fingerprint_is_deterministic(self) -> None:
        changes = [
            ChangedPath("tests/unit/b.py", ChangeStatus.MODIFIED),
            ChangedPath("src/a.py", ChangeStatus.MODIFIED),
        ]
        first = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=changes,
        )
        second = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=list(reversed(changes)),
        )
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.plan_id, second.plan_id)
        different = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE, fingerprint="b" * 64),
            changes=changes,
        )
        self.assertNotEqual(first.fingerprint, different.fingerprint)

    def test_large_change_set_emits_bounded_decodable_selection_reasons(self) -> None:
        changes = [
            ChangedPath(f"src/generated/module-{index:04d}.py", ChangeStatus.UNTRACKED)
            for index in range(1_302)
        ]

        plan = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=changes,
            launch_timeout_seconds=300,
        )

        self.assertEqual(len(plan.changes), 1_302)
        self.assertEqual(plan.selected_targets, ("integration", "lint", "unit"))
        for selection in plan.selection.values():
            self.assertLessEqual(len(selection.reasons), MAX_SELECTION_REASONS)
            if selection.reasons[0].startswith("additional-reasons:"):
                self.assertGreater(int(selection.reasons[0].split(":", 1)[1]), 0)
        decoded = decode_test_plan_document(plan.to_document())
        self.assertEqual(decoded.to_document(), plan.to_document())

    def test_caller_timeouts_are_bound_into_plan_and_execution_identity(self) -> None:
        base = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("src/a.py", ChangeStatus.MODIFIED)],
        )
        overridden = create_test_plan(
            self.contract,
            intent="change",
            source=source(SourceMode.LIVE),
            changes=[ChangedPath("src/a.py", ChangeStatus.MODIFIED)],
            execution_timeout_seconds=7_200,
            launch_timeout_seconds=900,
        )

        self.assertEqual(
            base.timeouts.to_document(),
            {"execution_seconds": None, "launch_seconds": 300},
        )
        self.assertEqual(
            overridden.timeouts.to_document(),
            {"execution_seconds": 7_200, "launch_seconds": 900},
        )
        self.assertNotEqual(base.fingerprint, overridden.fingerprint)
        self.assertNotEqual(base.execution_fingerprint, overridden.execution_fingerprint)
        self.assertNotEqual(base.plan_id, overridden.plan_id)

        with self.assertRaisesRegex(TestPlanError, "execution timeout"):
            create_test_plan(
                self.contract,
                intent="change",
                source=source(SourceMode.LIVE),
                execution_timeout_seconds=86_401,
            )
        with self.assertRaisesRegex(TestPlanError, "launch timeout"):
            create_test_plan(
                self.contract,
                intent="change",
                source=source(SourceMode.LIVE),
                launch_timeout_seconds=3_601,
            )

    def test_source_content_fingerprint_is_order_independent(self) -> None:
        first = fingerprint_source_content(
            files={"src/b.py": "b" * 64, "src/a.py": "a" * 64},
            manifest_fingerprint=self.contract.fingerprint,
            dependency_locks={"requirements.lock": "c" * 64},
            toolchain={"python": "3.13.5", "platform": "linux-x86_64"},
        )
        second = fingerprint_source_content(
            files={"src/a.py": "a" * 64, "src/b.py": "b" * 64},
            manifest_fingerprint=self.contract.fingerprint,
            dependency_locks={"requirements.lock": "c" * 64},
            toolchain={"platform": "linux-x86_64", "python": "3.13.5"},
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_execution_fingerprint_deduplicates_equal_immutable_content(self) -> None:
        first_source = source(SourceMode.IMMUTABLE)
        second_source = SourceIdentity(
            mode=SourceMode.IMMUTABLE,
            repository_id=first_source.repository_id,
            content_fingerprint=first_source.content_fingerprint,
            original_root=first_source.original_root,
            temporary_root="/home/example/another-worktree",
            snapshot_id="snapshot-other-provenance",
        )
        first = create_test_plan(
            self.contract, intent="handoff", source=first_source
        )
        second = create_test_plan(
            self.contract, intent="handoff", source=second_source
        )
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.execution_fingerprint, second.execution_fingerprint)


class AgentSummaryTests(unittest.TestCase):
    def test_summary_is_stable_bounded_and_progressively_disclosed(self) -> None:
        summary = AgentRunSummary(
            run_id="run-123",
            conclusion="failed",
            intent="handoff",
            source=source(SourceMode.IMMUTABLE),
            selected_targets=[f"target-{index}" for index in range(200)],
            selection_reasons={
                f"target-{index}": ["input:" + "x" * 2_000 for _ in range(20)]
                for index in range(200)
            },
            progress={"completed": 197, "total": 200, "percent": 98.5},
            counts={"passed": 10_000, "failed": 4, "skipped": 2},
            timing={"queue_seconds": 0.25, "wall_seconds": 42.5},
            failures=[
                FailureSummary(
                    target=f"target-{index}",
                    message="failure " + "detail " * 2_000,
                    location=f"tests/test_{index}.py:10",
                    artifact_id=f"artifact-{index}",
                )
                for index in range(20)
            ],
            artifacts=[
                ArtifactSummary(
                    artifact_id=f"artifact-{index}",
                    kind="log",
                    target=f"target-{index}",
                )
                for index in range(100)
            ],
            detail_command=(
                "test failures --repository-id repo-tests --run-id run-123"
            ),
        )
        encoded = agent_summary_json(summary)
        self.assertLessEqual(len(encoded.encode("utf-8")), MAX_AGENT_SUMMARY_BYTES)
        self.assertEqual(encoded, agent_summary_json(summary))
        document = json.loads(encoded)
        self.assertEqual(len(document["failures"]), 3)
        self.assertEqual(document["failure_count"], 20)
        self.assertEqual(document["artifact_count"], 100)
        self.assertTrue(document["selection"]["truncated"])
        self.assertIn("test failures", document["next"])

    def test_summary_honors_smaller_valid_bound(self) -> None:
        summary = AgentRunSummary(
            run_id="run-1",
            conclusion="passed",
            intent="change",
            source=source(SourceMode.LIVE),
            selected_targets=["unit"],
            selection_reasons={"unit": ["input:src/a.py"]},
            progress={"completed": 1, "total": 1},
            counts={"passed": 1},
            timing={"wall_seconds": 0.1},
            failures=[],
            artifacts=[],
            detail_command=(
                "test status --repository-id repo-tests --run-id run-1"
            ),
        )
        encoded = agent_summary_json(summary, max_bytes=1_024)
        self.assertLessEqual(len(encoded.encode("utf-8")), 1_024)
        self.assertEqual(
            compact_agent_summary(summary, max_bytes=1_024)["conclusion"], "passed"
        )

    def test_summary_rejects_non_finite_numbers_or_tiny_budget(self) -> None:
        summary = AgentRunSummary(
            run_id="run-1",
            conclusion="running",
            intent="change",
            source=source(SourceMode.LIVE),
            selected_targets=[],
            selection_reasons={},
            progress={"percent": float("nan")},
            counts={},
            timing={},
            failures=[],
            artifacts=[],
            detail_command="test status --repository-id repo-tests --run-id run-1",
        )
        with self.assertRaisesRegex(AgentSummaryError, "finite"):
            compact_agent_summary(summary)
        clean = copy.copy(summary)
        object.__setattr__(clean, "progress", {})
        with self.assertRaisesRegex(AgentSummaryError, "at least"):
            compact_agent_summary(clean, max_bytes=100)


if __name__ == "__main__":
    unittest.main()
