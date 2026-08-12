#!/usr/bin/env python3
"""Regression guard for non-duplicating universal-harness validation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(
    0, str(ROOT / "skills" / "codex-dev-coordinator" / "scripts")
)

import run_coordinator_test_partition as COORDINATOR_PARTITIONS  # noqa: E402
from devcoordinator.universal_test_contract import (  # noqa: E402
    SourceMode,
    load_test_manifest,
)
from devcoordinator.universal_test_planner import (  # noqa: E402
    ChangeStatus,
    ChangedPath,
    SourceIdentity,
    create_test_plan,
)

SPEC = importlib.util.spec_from_file_location(
    "devcoordinator_validate_harness_mode",
    ROOT / "scripts" / "validate.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("validation module could not be loaded")
VALIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATE)

CONSOLE_SPEC = importlib.util.spec_from_file_location(
    "devcoordinator_console_test_entrypoint",
    ROOT / "scripts" / "run_console_unit_tests.py",
)
if CONSOLE_SPEC is None or CONSOLE_SPEC.loader is None:
    raise RuntimeError("Console test entrypoint could not be loaded")
CONSOLE_TESTS = importlib.util.module_from_spec(CONSOLE_SPEC)
CONSOLE_SPEC.loader.exec_module(CONSOLE_TESTS)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def exercise_normalized_skip() -> None:
    with tempfile.TemporaryDirectory(prefix="validate-harness-mode-") as raw:
        skill = Path(raw) / "codex-dev-coordinator"
        scripts = skill / "scripts"
        tests = scripts / "devcoordinator" / "tests"
        tests.mkdir(parents=True)
        for name in (
            "sqlite_store_test.py",
            "self_test_sqlite_cutover.py",
            "self_test_multi_runtime.py",
            "self_test_repository_lifecycle.py",
            "self_test_sqlite_lifecycle.py",
            "self_test_host_lifecycle.py",
            "self_test_lifecycle_action_guard.py",
            "self_test_broker_cross_uid.py",
            "capability_integration_test.py",
        ):
            (scripts / name).write_text("# fixture\n", encoding="utf-8")

        calls: list[list[str]] = []
        original = VALIDATE.run
        VALIDATE.run = lambda argv, **_kwargs: calls.append([str(item) for item in argv])
        try:
            VALIDATE.run_normalized_coordinator_tests(
                skill,
                skip_normal_unit_pass=True,
            )
        finally:
            VALIDATE.run = original

        unit_calls = [
            call
            for call in calls
            if "-m" in call and "unittest" in call and "discover" in call
        ]
        expect(len(unit_calls) == 1, "harness mode must retain exactly one unit pass")
        expect("-O" in unit_calls[0], "harness mode must retain the optimized unit pass")
        expect(
            sum("capability_integration_test.py" in " ".join(call) for call in calls) == 2,
            "capability preflight must remain covered in normal and optimized modes",
        )


def exercise_console_delegation() -> None:
    calls: list[list[str]] = []
    original = VALIDATE.run
    VALIDATE.run = lambda argv, **_kwargs: calls.append([str(item) for item in argv])
    try:
        VALIDATE.check_devops_console(run_tests=False)
    finally:
        VALIDATE.run = original
    expect(
        not any(call[:2] == ["npm", "test"] for call in calls),
        "harness mode must delegate the Console test pass",
    )
    expect(
        any(call[:2] == ["node", "--check"] for call in calls),
        "harness mode must retain Console syntax and structural checks",
    )
    discovered = set(CONSOLE_TESTS.discover_tests())
    package_public = set(
        (ROOT / "apps" / "DevOpsConsole" / "test").glob("*.test.mjs")
    )
    expect(
        discovered == package_public,
        "the harness-owned Console target must cover the package-public suite",
    )
    expected_contracts = {
        "browser.server-project-disclosures.test.mjs",
        "e2e.stack.test.mjs",
        "integration.console-slot-cutover.test.mjs",
        "integration.edge-isolation.test.mjs",
        "integration.telegram-console.test.mjs",
    }
    expect(
        expected_contracts <= {path.name for path in discovered},
        "the harness-owned Console target omitted an integration contract",
    )


def exercise_coordinator_fast_bind_guard() -> None:
    good = """
def serve_api(host, port):
    listener = inherited_listener()
    server = BoundedThreadingHTTPServer(
        (host, port),
        ApiHandler,
        listener=listener,
    )
    return server
"""
    expect(
        not VALIDATE.coordinator_api_fast_bind_errors(good),
        "fast-bind guard rejected the multiline inherited-listener control",
    )
    must_catch = (
        good.replace("BoundedThreadingHTTPServer", "ThreadingHTTPServer"),
        good.replace("(host, port)", "(host, 0)"),
        good.replace("ApiHandler", "UnboundedHandler"),
        good.replace("listener=listener", "listener=other_listener"),
        good.replace("listener=listener", "token=token, listener=listener"),
        """
def serve_api(host, port):
    def decoy():
        server = BoundedThreadingHTTPServer(
            (host, port), ApiHandler, listener=listener
        )
    return ThreadingHTTPServer((host, port), ApiHandler)
""",
    )
    expect(
        all(VALIDATE.coordinator_api_fast_bind_errors(source) for source in must_catch),
        "fast-bind guard missed a wrong server, endpoint, handler, listener, obsolete token, or decoy",
    )


def exercise_dogfood_partition_contract() -> None:
    manifest = load_test_manifest(ROOT)
    partition_targets = {
        "coordinator-broker-authority",
        "coordinator-resources-storage",
        "coordinator-runtime-lifecycle",
        "coordinator-universal-harness",
    }
    expected_all = partition_targets | {"console-tests", "repository-validation"}
    runner_probe = "software-delivery-runner-probe"
    expect(
        not COORDINATOR_PARTITIONS.partition_contract_errors(),
        "Coordinator test partition ownership is incomplete or ambiguous",
    )
    grouped = COORDINATOR_PARTITIONS.partitioned_modules()
    expect(
        COORDINATOR_PARTITIONS.non_gate_compatibility_modules()
        == ("test_universal_test_migration",),
        "legacy test-history migration must remain explicit operator-only coverage",
    )
    expect(
        "test_universal_test_migration"
        not in {module for modules in grouped.values() for module in modules},
        "legacy test-history migration leaked into normal evidence gates",
    )
    expect(
        "test_universal_test_fresh_store" in grouped["universal-harness"],
        "fresh test-store initialization is missing from normal harness evidence",
    )
    expect(
        sum(len(modules) for modules in grouped.values())
        == len(COORDINATOR_PARTITIONS.discovered_modules()),
        "Coordinator partition runner does not cover the discovered suite exactly once",
    )
    for name in partition_targets:
        target = manifest.targets[name]
        expect(
            set(target.intents)
            == {"change", "checkpoint", "handoff", "release", "manual"},
            f"{name} does not retain full immutable evidence intents",
        )
    expect(
        manifest.targets["coordinator-universal-harness"].network == "loopback",
        "universal harness must permit isolated loopback for preflight socket cases",
    )
    expect(
        manifest.targets["coordinator-runtime-lifecycle"].network == "loopback",
        "runtime lifecycle partition must permit isolated loopback for socket cases",
    )
    for name in ("handoff", "release"):
        expect(
            set(manifest.evidence_policies[name].required_targets) == expected_all,
            f"{name} evidence policy omits a dogfood partition",
        )

    live_source = SourceIdentity(
        mode=SourceMode.LIVE,
        repository_id="dogfood-repository",
        content_fingerprint="a" * 64,
        original_root=str(ROOT),
    )
    representatives = {
        "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py": {
            "coordinator-broker-authority"
        },
        "skills/codex-dev-coordinator/scripts/devcoordinator/ephemeral_containers.py": {
            "coordinator-resources-storage"
        },
        "skills/codex-dev-coordinator/scripts/devcoordinator/runtime_api.py": {
            "coordinator-runtime-lifecycle"
        },
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_planner.py": {
            "coordinator-universal-harness"
        },
    }
    for path, expected in representatives.items():
        plan = create_test_plan(
            manifest,
            intent="change",
            source=live_source,
            changes=(ChangedPath(path, ChangeStatus.MODIFIED),),
        )
        expect(
            set(plan.selected_targets) == expected,
            f"live change {path} selected {plan.selected_targets}, expected {sorted(expected)}",
        )
        expect(
            not plan.complete_intent_fallback,
            f"mapped live change {path} unexpectedly used complete fallback",
        )

    shared_plan = create_test_plan(
        manifest,
        intent="checkpoint",
        source=live_source,
        changes=(
            ChangedPath(
                "skills/codex-dev-coordinator/scripts/devcoordinator/schema.py",
                ChangeStatus.MODIFIED,
            ),
        ),
    )
    expect(
        set(shared_plan.selected_targets) == partition_targets,
        "shared Coordinator authority changes must select every Coordinator partition",
    )
    expect(
        not shared_plan.complete_intent_fallback,
        "shared Coordinator authority mapping must remain explicit",
    )

    immutable_source = SourceIdentity(
        mode=SourceMode.IMMUTABLE,
        repository_id="dogfood-repository",
        content_fingerprint="b" * 64,
        original_root=str(ROOT),
        snapshot_id="snapshot-dogfood",
    )
    for intent in ("handoff", "release", "manual"):
        plan = create_test_plan(
            manifest,
            intent=intent,
            source=immutable_source,
        )
        expected = expected_all | ({runner_probe} if intent == "manual" else set())
        expect(
            set(plan.selected_targets) == expected,
            f"immutable {intent} omitted full dogfood evidence",
        )
    probe_plan = create_test_plan(
        manifest,
        intent="manual",
        source=immutable_source,
        requested_targets=(runner_probe,),
    )
    expect(
        tuple(probe_plan.selected_targets) == (runner_probe,),
        "manual delivery acceptance did not select only its runner probe",
    )


def main() -> int:
    arguments = VALIDATE.parse_args(["--skip-macos-app", "--harness-mode"])
    expect(arguments.skip_macos_app, "native gate flag was not preserved")
    expect(arguments.harness_mode, "harness mode flag was not parsed")
    manifest = json.loads((ROOT / ".codex" / "tests.json").read_text(encoding="utf-8"))
    validation = manifest["targets"]["repository-validation"]["argv"]
    expect(
        validation == ["{python}", "scripts/run_fast_repository_validation.py"],
        "dogfood validation target does not use the software-owned fast gate",
    )
    exercise_normalized_skip()
    exercise_console_delegation()
    exercise_coordinator_fast_bind_guard()
    exercise_dogfood_partition_contract()
    print("validation harness-mode self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
