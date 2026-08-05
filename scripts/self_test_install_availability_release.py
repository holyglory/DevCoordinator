#!/usr/bin/env python3
"""Deterministic tests for content-addressed availability releases."""

from __future__ import annotations

import ast
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/install_availability_release.py"
SPEC = importlib.util.spec_from_file_location("install_availability_release", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import immutable release installer")
INSTALLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALLER
SPEC.loader.exec_module(INSTALLER)

OWNER_AUTHORITY_SOURCE = "scripts/migrate_repository_owner_authority.py"
OWNER_AUTHORITY_WRAPPER = "bin/devcoordinator-repository-owner-authority"
AUTHORITY_READINESS_SOURCE = "scripts/orchestrate_availability_cutover.py"
AUTHORITY_READINESS_WRAPPER = "bin/devcoordinator-authority-readiness"
AUTHORITY_READINESS_REBIND_WRAPPER = (
    "bin/devcoordinator-authority-readiness-rebind"
)
AUTHORITY_READINESS_REATTEST_WRAPPER = (
    "bin/devcoordinator-authority-readiness-reattest"
)
AUTHORITY_REPOSITORY_REPAIR_WRAPPER = (
    "bin/devcoordinator-authority-repository-repair"
)
SCHEMA12_BRIDGE_SOURCE = "scripts/bridge_schema12_legacy_broker.py"
SCHEMA12_BRIDGE_WRAPPER = "bin/devcoordinator-schema12-bridge"
BROKER_UNIT_SOURCE = "deploy/devcoordinator-broker.service"
INSTALLER_FENCE_SOURCE = "scripts/server_wide_installer_fence.py"
DOCKER_ADMISSION_SOURCE = "scripts/manage_docker_admission.py"
DOCKER_ADMISSION_WRAPPER = "bin/devcoordinator-docker-admission"
MAINTENANCE_SOURCE = "scripts/manage_maintenance_mode.py"
MAINTENANCE_WRAPPER = "bin/devcoordinator-maintenance"
TEST_CREDENTIAL_SOURCE = "scripts/manage_universal_test_credentials.py"
TEST_CREDENTIAL_WRAPPER = "bin/devcoordinator-test-credential"
AGENT_CLIENT_SOURCE = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py"
)
AGENT_CLIENT_CONTRACT = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_contract.py"
)
AGENT_CLIENT_WRAPPER = "bin/devcoordinator"
AGENT_MCP_SOURCE = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_mcp.py"
)
AGENT_MCP_WRAPPER = "bin/devcoordinator-mcp"
BUG_REGISTRY_SOURCE = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/bug_registry.py"
)
BUG_REGISTRY_WRAPPER = "bin/devcoordinator-bug"
CALL_LOG_SOURCE = "scripts/read_coordinator_call_log.py"
CALL_LOG_WRAPPER = "bin/devcoordinator-call-log"
READ_ONLY_RULE_SOURCE = "deploy/devcoordinator-read-only.rules"
PORT_RESERVATIONS_WRAPPER = "bin/devcoordinator-port-reservations"
ATOMIC_BINDINGS_WRAPPER = "bin/devcoordinator-first-adoption-bindings"
RUNBOOK = ROOT / "docs/architecture/availability-foundation.md"
PLAYWRIGHT_PACKAGE_SOURCE = "ci/playwright/package.json"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (INSTALLER.ReleaseError, OSError, ValueError, json.JSONDecodeError):
        return
    raise AssertionError(f"unsafe immutable release condition was accepted: {label}")


def copy_release_source(destination: Path) -> None:
    destination.mkdir(mode=0o755)
    for source_root in INSTALLER.SOURCE_ROOTS:
        shutil.copytree(ROOT / source_root, destination / source_root)
    standalone = set(INSTALLER.SOURCE_FILES)
    standalone.add(INSTALLER.TEST_CAPABILITY_SOURCE)
    standalone.update(
        Path(source_name)
        for source_name, _mode in INSTALLER.RELEASE_COPIES.values()
    )
    for relative in sorted(standalone, key=lambda item: item.as_posix()):
        target = destination / relative
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def agent_runtime_relative_dependency_paths() -> set[str]:
    """Return the current local-import closure of the declared agent graph."""

    module_root = (
        ROOT / "skills/codex-dev-coordinator/scripts/devcoordinator"
    )
    prefix = "skills/codex-dev-coordinator/scripts/devcoordinator/"
    pending = list(INSTALLER.AGENT_CLIENT_RUNTIME_PATHS)
    visited: set[str] = set()
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        visited.add(relative)
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level != 1:
                continue
            candidates = (
                [node.module.split(".", 1)[0]]
                if node.module
                else [alias.name.split(".", 1)[0] for alias in node.names]
            )
            for candidate in candidates:
                target = module_root / f"{candidate}.py"
                dependency = prefix + f"{candidate}.py"
                if target.is_file() and dependency not in visited:
                    pending.append(dependency)
    return visited


def write_port_reservations(
    root: Path,
    release_digest: str,
    *,
    name: str = "port-reservations.json",
    update=None,
) -> tuple[Path, str, dict[str, object]]:
    operation_id = "12345678-1234-4234-8234-123456789abc"
    created_at = "2099-01-01T00:00:00.000Z"
    expires_at = "2099-01-01T01:00:00.000Z"
    ports = {
        "console_outer": 30443,
        "console_inner": 30444,
        "handoff_http": 38080,
        "handoff_https": 38443,
        "handoff_api": 39876,
    }
    reservations = {}
    for index, (role, port) in enumerate(ports.items(), start=1):
        reservations[role] = {
            "lease_id": f"00000000-0000-4000-8000-{index:012d}",
            "port": port,
            "agent": f"cutover:first-adoption:{operation_id}",
            "purpose": f"first-adoption:{release_digest}:{role}",
            "status": "active",
            "expires_at": None if role.startswith("console_") else expires_at,
        }
    authority_database = root / "authority.sqlite3"
    authority_database.touch(exist_ok=True)
    canonical_root = root / "canonical-repository"
    canonical_root.mkdir(exist_ok=True)
    document: dict[str, object] = {
        "schema_version": 1,
        "kind": INSTALLER.PORT_RESERVATIONS_KIND,
        "operation_id": operation_id,
        "release_digest": release_digest,
        "authority_database": str(authority_database),
        "authority_generation": "authority-generation-7",
        "authority_state_revision_before": 41,
        "authority_state_revision_after": 42,
        "repository_id": "repository-stable-id",
        "repository_generation": 3,
        "canonical_root": str(canonical_root),
        "port_range": {"start": 30000, "end": 60999},
        "handoff_ttl_seconds": 3600,
        "reservations": reservations,
        "transaction_journal_sha256": "a" * 64,
        "service_unit": "devcoordinator-broker.service",
        "service_restored": True,
        "maintenance_cleared": True,
        "created_at": created_at,
        "completed_at": "2099-01-01T00:00:01.000Z",
    }
    if update is not None:
        update(document)
    document["document_sha256"] = hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    destination = root / name
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    destination.chmod(0o600)
    return destination, str(document["document_sha256"]), document


def verify_runbook_command_contract() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    marker = "## First-deployment and cutover runbook"
    expect(text.count(marker) == 1, "availability runbook boundary is ambiguous")
    runbook = text.split(marker, 1)[1]
    for forbidden in (
        "python3 scripts/",
        "python scripts/",
        "/home/DevCoordinator",
        "scripts/orchestrate_availability_cutover.py",
        "scripts/migrate_repository_owner_authority.py",
    ):
        expect(
            forbidden not in runbook,
            f"availability runbook executes mutable source: {forbidden}",
        )
    required = {
        "devcoordinator-cutover": 4,
        "devcoordinator-availability-activate": 1,
        "devcoordinator-repository-owner-authority": 2,
        "devcoordinator-authority-readiness": 1,
        "devcoordinator-authority-readiness-reattest": 1,
        "devcoordinator-first-adoption-bindings": 3,
        "devcoordinator-authority-repository-repair": 1,
    }
    for wrapper, minimum_count in required.items():
        expect(
            runbook.count(f"/bin/{wrapper}") >= minimum_count,
            f"availability runbook omits immutable wrapper {wrapper}",
        )
    blocks = re.findall(r"```bash\n(.*?)```", runbook, flags=re.DOTALL)
    expect(len(blocks) >= 4, "availability runbook command-block inventory is incomplete")
    command_lines = [
        line
        for block in blocks
        for line in block.splitlines()
        if line and not line[0].isspace()
    ]
    expect(command_lines, "availability runbook contains no executable commands")
    expect(
        all(
            line.startswith("/opt/devcoordinator/releases/<digest>/bin/")
            or line == "sudo -n -H -u devcoordinator-testd \\"
            for line in command_lines
        ),
        "availability runbook contains a command outside the verified release",
    )


def main() -> int:
    verify_runbook_command_contract()
    first = INSTALLER.plan_release(ROOT, Path("/opt/devcoordinator/releases"))
    second = INSTALLER.plan_release(ROOT, Path("/opt/devcoordinator/releases"))
    expect(first["release_digest"] == second["release_digest"], "release digest is not deterministic")
    paths = {entry["path"] for entry in first["files"]}
    entries = {entry["path"]: entry for entry in first["files"]}
    expect("bin/devcoordinator-edge" in paths, "release omitted stable edge wrapper")
    expect("bin/devcoordinator-console" in paths, "release omitted Console wrapper")
    expect(
        INSTALLER.WRAPPERS.get("devcoordinator")
        == ("python", AGENT_CLIENT_SOURCE, ()),
        "stable agent wrapper does not target devcoordinator.agent_cli",
    )
    required_agent_paths = set(INSTALLER.AGENT_CLIENT_RUNTIME_PATHS)
    dependency_paths = agent_runtime_relative_dependency_paths()
    expect(
        dependency_paths.issubset(required_agent_paths),
        "agent capability evidence omits current local runtime dependencies: "
        + repr(sorted(dependency_paths - required_agent_paths)),
    )
    expect(
        {
            AGENT_CLIENT_SOURCE,
            AGENT_CLIENT_CONTRACT,
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_projection.py",
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_test.py",
            "skills/codex-dev-coordinator/scripts/devcoordinator/capabilities.py",
            "skills/codex-dev-coordinator/scripts/devcoordinator/call_journal.py",
            "skills/codex-dev-coordinator/scripts/devcoordinator/runtime_ensure.py",
        }.issubset(required_agent_paths),
        "agent capability evidence omits a required narrow runtime module",
    )
    expect(
        {
            "agent_cli",
            "agent_contract",
            "agent_projection",
            "agent_test",
            "capabilities",
            "call_journal",
            "runtime_ensure",
        }.issubset(set(INSTALLER.AGENT_NARROW_IMPORT_MODULES)),
        "release smoke omits a required narrow runtime module import",
    )
    agent_source_present = (ROOT / AGENT_CLIENT_SOURCE).is_file()
    expected_agent_capability = all(
        (ROOT / path).is_file() for path in required_agent_paths
    )
    expect(
        first["capabilities"]["immutable_agent_client"]
        is expected_agent_capability
        and (AGENT_CLIENT_WRAPPER in paths) is agent_source_present,
        "release did not truthfully project thin-agent-client availability",
    )
    if expected_agent_capability:
        expect(
            ({AGENT_CLIENT_WRAPPER} | required_agent_paths).issubset(paths),
            "complete thin agent client was not bound into the release",
        )
    expect(
        INSTALLER.WRAPPERS.get("devcoordinator-mcp")
        == ("python", AGENT_MCP_SOURCE, ()),
        "stable MCP wrapper does not target devcoordinator.agent_mcp",
    )
    expect(
        INSTALLER.WRAPPERS.get("devcoordinator-bug")
        == ("python", BUG_REGISTRY_SOURCE, ()),
        "out-of-band bug wrapper does not target the immutable registry",
    )
    expect(
        INSTALLER.AGENT_MCP_RUNTIME_PATH == AGENT_MCP_SOURCE,
        "MCP capability evidence points at the wrong transport module",
    )
    expected_mcp_capability = expected_agent_capability and (
        ROOT / AGENT_MCP_SOURCE
    ).is_file()
    expect(
        first["capabilities"]["immutable_agent_mcp"]
        is expected_mcp_capability
        and (AGENT_MCP_WRAPPER in paths) is (ROOT / AGENT_MCP_SOURCE).is_file(),
        "release did not truthfully project immutable MCP availability",
    )
    if expected_mcp_capability:
        expect(
            (
                {AGENT_MCP_SOURCE, AGENT_MCP_WRAPPER}
                | required_agent_paths
            ).issubset(paths),
            "complete MCP agent transport was not bound into the release",
        )
    expected_bug_capability = all(
        (ROOT / path).is_file()
        for path in (
            *required_agent_paths,
            AGENT_MCP_SOURCE,
            "deploy/devcoordinator-availability.tmpfiles.conf",
            "deploy/devcoordinator-console@.service",
        )
    ) and {AGENT_CLIENT_WRAPPER, AGENT_MCP_WRAPPER, BUG_REGISTRY_WRAPPER}.issubset(
        paths
    )
    expect(
        first["capabilities"]["out_of_band_bug_registry"]
        is expected_bug_capability,
        "release did not truthfully project outage-safe bug reporting",
    )
    if expected_bug_capability:
        expect(
            {BUG_REGISTRY_SOURCE, BUG_REGISTRY_WRAPPER}.issubset(paths),
            "complete bug registry was not bound into the release",
        )
    expected_read_only_access = all(
        (ROOT / path).is_file()
        for path in (
            *required_agent_paths,
            CALL_LOG_SOURCE,
            READ_ONLY_RULE_SOURCE,
        )
    )
    expect(
        first["capabilities"]["immutable_read_only_agent_access"]
        is expected_read_only_access,
        "release did not truthfully project immutable read-only agent access",
    )
    if expected_read_only_access:
        expect(
            {
                AGENT_CLIENT_WRAPPER,
                CALL_LOG_WRAPPER,
                READ_ONLY_RULE_SOURCE,
            }.issubset(paths)
            and entries[READ_ONLY_RULE_SOURCE]["kind"] == "source",
            "read-only client launchers and policy were not manifest-bound",
        )
    agent_wrapper_payload = INSTALLER.wrapper_payload(
        "devcoordinator", *INSTALLER.WRAPPERS["devcoordinator"]
    )
    expect(
        b"runpy.run_module" in agent_wrapper_payload
        and b"'devcoordinator.agent_cli'" in agent_wrapper_payload
        and b"DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl"
        in agent_wrapper_payload,
        "stable agent wrapper is not isolated, package-aware, and journaled",
    )
    mcp_wrapper_payload = INSTALLER.wrapper_payload(
        "devcoordinator-mcp", *INSTALLER.WRAPPERS["devcoordinator-mcp"]
    )
    expect(
        b"runpy.run_module" in mcp_wrapper_payload
        and b"'devcoordinator.agent_mcp'" in mcp_wrapper_payload
        and b"DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl"
        in mcp_wrapper_payload,
        "stable MCP wrapper is not isolated, package-aware, and journaled",
    )
    bug_wrapper_payload = INSTALLER.wrapper_payload(
        "devcoordinator-bug", *INSTALLER.WRAPPERS["devcoordinator-bug"]
    )
    expect(
        b"runpy.run_module" in bug_wrapper_payload
        and b"'devcoordinator.bug_registry'" in bug_wrapper_payload
        and b"DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl"
        in bug_wrapper_payload,
        "out-of-band bug wrapper is not isolated, package-aware, and journaled",
    )
    with tempfile.TemporaryDirectory(
        prefix="availability-incomplete-agent-client-"
    ) as incomplete_raw:
        incomplete_root = Path(incomplete_raw)
        incomplete_source = incomplete_root / "source"
        copy_release_source(incomplete_source)
        missing_runtime_path = (
            incomplete_source
            / "skills/codex-dev-coordinator/scripts/devcoordinator/agent_projection.py"
        )
        missing_runtime_path.unlink()
        incomplete_plan = INSTALLER.plan_release(
            incomplete_source,
            incomplete_root / "releases",
        )
        incomplete_paths = {
            entry["path"] for entry in incomplete_plan["files"]
        }
        expect(
            {AGENT_CLIENT_WRAPPER, AGENT_MCP_WRAPPER}.issubset(
                incomplete_paths
            )
            and incomplete_plan["capabilities"]["immutable_agent_client"]
            is False
            and incomplete_plan["capabilities"]["immutable_agent_mcp"]
            is False
            and incomplete_plan["capabilities"]["out_of_band_bug_registry"]
            is False,
            "agent capabilities remained true with a runtime module missing",
        )
    expect(
        "bin/devcoordinator-availability-activate" in paths
        and first["capabilities"]["evidence_gated_activation"] is True,
        "release omitted the evidence-gated activation executor",
    )
    expect(
        "scripts/install_availability_release.py" in paths,
        "release omitted the verifier loaded by immutable cutover commands",
    )
    expect(
        INSTALLER_FENCE_SOURCE in paths,
        "release omitted the shared server-wide installer fence",
    )
    expect(
        "bin/devcoordinator-testd" in paths
        and "bin/devcoordinator-test-snapshotd" in paths,
        "release omitted the asynchronous test-plane wrappers",
    )
    expect(
        "libexec/universal_test_uid_helper.py" in paths,
        "release omitted the immutable per-UID snapshot helper",
    )
    expect(
        {OWNER_AUTHORITY_SOURCE, OWNER_AUTHORITY_WRAPPER}.issubset(paths),
        "release omitted repository-owner map preparation",
    )
    expect(
        AUTHORITY_READINESS_WRAPPER in paths
        and first["capabilities"]["authority_readiness_recovery"] is True,
        "release omitted the authority readiness recovery gate",
    )
    expect(
        AUTHORITY_READINESS_REBIND_WRAPPER in paths
        and first["capabilities"]["authority_readiness_rebind"] is True,
        "release omitted the authority readiness rebind gate",
    )
    expect(
        AUTHORITY_READINESS_REATTEST_WRAPPER in paths
        and first["capabilities"]["authority_readiness_reattestation"] is True,
        "release omitted the no-mutation authority readiness re-attestation gate",
    )
    expect(
        ATOMIC_BINDINGS_WRAPPER in paths
        and first["capabilities"]["atomic_first_adoption_bindings"] is True,
        "release omitted atomic first-adoption readiness/port bindings",
    )
    expect(
        {SCHEMA12_BRIDGE_SOURCE, SCHEMA12_BRIDGE_WRAPPER}.issubset(paths)
        and first["capabilities"]["schema12_legacy_writer_handoff"] is True,
        "release omitted the schema-12 legacy-writer handoff gate",
    )
    expect(
        first["capabilities"]["schema12_clean_bridge_successor"] is True,
        "release omitted the clean schema-12 bridge successor primitive",
    )
    expect(
        first["capabilities"][
            "schema12_policy_reconciled_restored_recovery"
        ]
        is True,
        "release omitted the policy-reconciled restored-bridge recovery gate",
    )
    expect(
        first["capabilities"][
            "schema12_lifecycle_crash_loop_quiescence"
        ]
        is True,
        "release omitted the lifecycle crash-loop quiescence gate",
    )
    expect(
        BROKER_UNIT_SOURCE in paths
        and entries[BROKER_UNIT_SOURCE]["kind"] == "source",
        "release omitted the manifest-bound canonical broker unit",
    )
    expect(
        {MAINTENANCE_SOURCE, MAINTENANCE_WRAPPER}.issubset(paths)
        and first["capabilities"]["typed_maintenance_control"] is True,
        "release omitted immutable typed maintenance control",
    )
    expect(
        "bin/devcoordinator-live-fault-acceptance" not in paths
        and "live_fault_isolation_acceptance" not in first["capabilities"],
        "ordinary release still publishes the destructive live fault campaign",
    )
    expect(
        "bin/devcoordinator-browser-lcp" in paths
        and first["capabilities"]["browser_lcp_acceptance"] is True,
        "release omitted the release-bound browser LCP acceptance gate",
    )
    expect(
        INSTALLER.WRAPPERS.get("devcoordinator-browser-accounting")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
            (),
        )
        and "bin/devcoordinator-browser-accounting" in paths
        and "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py"
        in paths
        and first["capabilities"]["headless_browser_accounting"] is True,
        "release omitted immutable headless-browser accounting tooling",
    )
    with tempfile.TemporaryDirectory(
        prefix="availability-incomplete-browser-accounting-"
    ) as incomplete_raw:
        incomplete_root = Path(incomplete_raw)
        incomplete_source = incomplete_root / "source"
        copy_release_source(incomplete_source)
        (
            incomplete_source
            / "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py"
        ).unlink()
        incomplete = INSTALLER.plan_release(
            incomplete_source,
            incomplete_root / "releases",
        )
        incomplete_paths = {entry["path"] for entry in incomplete["files"]}
        expect(
            incomplete["capabilities"]["headless_browser_accounting"] is False
            and "bin/devcoordinator-browser-accounting" not in incomplete_paths,
            "partial browser accounting package advertised a live capability",
        )
    expect(
        {
            "scripts/browser_lcp_acceptance.py",
            "apps/DevOpsConsole/Tools/browser-lcp-producer.mjs",
        }.issubset(paths),
        "release omitted browser LCP producer sources",
    )
    expect(
        {
            "bin/devcoordinator-production-browser-session",
            "bin/devcoordinator-production-console-acceptance",
            "apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs",
            "apps/DevOpsConsole/Tools/production-console-acceptance.mjs",
            PLAYWRIGHT_PACKAGE_SOURCE,
        }.issubset(paths)
        and entries[PLAYWRIGHT_PACKAGE_SOURCE]["kind"] == "source"
        and first["capabilities"]["production_console_playwright_acceptance"] is True,
        "release omitted immutable production Playwright acceptance tools or locked manifest",
    )
    expect(
        {DOCKER_ADMISSION_SOURCE, DOCKER_ADMISSION_WRAPPER}.issubset(paths)
        and first["capabilities"]["broker_only_docker_admission"] is True,
        "release omitted rollback-safe broker-only Docker admission",
    )
    expect(
        {
            "scripts/install_availability_release.py",
            "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py",
        }.issubset(paths),
        "Docker admission release omitted profile/release trust anchors",
    )
    docker_admission_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-docker-admission"
    ]
    expect(
        docker_admission_wrappers
        == [
            (
                "devcoordinator-docker-admission",
                "python",
                DOCKER_ADMISSION_SOURCE,
                (),
            )
        ],
        "Docker admission must have one fixed immutable wrapper",
    )
    docker_admission_payload = INSTALLER.wrapper_payload(
        *docker_admission_wrappers[0]
    )
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/manage_docker_admission.py"'
        in docker_admission_payload,
        "Docker admission wrapper does not fix its isolated interpreter and script",
    )
    expect(
        entries[DOCKER_ADMISSION_WRAPPER]["kind"] == "wrapper",
        "Docker admission wrapper is not manifest-bound",
    )
    owner_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if target == OWNER_AUTHORITY_SOURCE
    ]
    expect(
        owner_wrappers
        == [
            (
                "devcoordinator-repository-owner-authority",
                "python",
                OWNER_AUTHORITY_SOURCE,
                (),
            )
        ],
        "repository-owner map preparation must have one fixed wrapper",
    )
    readiness_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-authority-readiness"
    ]
    expect(
        readiness_wrappers
        == [
            (
                "devcoordinator-authority-readiness",
                "python",
                AUTHORITY_READINESS_SOURCE,
                ("recover-authority-readiness",),
            )
        ],
        "authority readiness recovery must have one fixed immutable wrapper",
    )
    owner_source_payload = (ROOT / OWNER_AUTHORITY_SOURCE).read_bytes()
    owner_wrapper_payload = INSTALLER.wrapper_payload(*owner_wrappers[0])
    expect(
        entries[OWNER_AUTHORITY_SOURCE] == {
            "path": OWNER_AUTHORITY_SOURCE,
            "sha256": hashlib.sha256(owner_source_payload).hexdigest(),
            "size": len(owner_source_payload),
            "mode": "0444",
            "kind": "source",
        },
        "repository-owner source is not exactly manifest-bound",
    )
    expect(
        entries[OWNER_AUTHORITY_WRAPPER] == {
            "path": OWNER_AUTHORITY_WRAPPER,
            "sha256": hashlib.sha256(owner_wrapper_payload).hexdigest(),
            "size": len(owner_wrapper_payload),
            "mode": "0555",
            "kind": "wrapper",
        },
        "repository-owner wrapper is not exactly manifest-bound",
    )
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/migrate_repository_owner_authority.py"'
        in owner_wrapper_payload,
        "repository-owner wrapper does not fix its isolated interpreter and script",
    )
    readiness_wrapper_payload = INSTALLER.wrapper_payload(*readiness_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py" \'recover-authority-readiness\''
        in readiness_wrapper_payload,
        "authority readiness wrapper does not fix its interpreter, script, and action",
    )
    rebind_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-authority-readiness-rebind"
    ]
    expect(
        rebind_wrappers
        == [
            (
                "devcoordinator-authority-readiness-rebind",
                "python",
                AUTHORITY_READINESS_SOURCE,
                ("rebind-authority-readiness",),
            )
        ],
        "authority readiness rebind must have one fixed immutable wrapper",
    )
    rebind_wrapper_payload = INSTALLER.wrapper_payload(*rebind_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py" \'rebind-authority-readiness\''
        in rebind_wrapper_payload,
        "authority readiness rebind wrapper does not fix its interpreter, script, and action",
    )
    expect(
        entries[AUTHORITY_READINESS_REBIND_WRAPPER]["kind"] == "wrapper",
        "authority readiness rebind wrapper is not manifest-bound",
    )
    reattest_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-authority-readiness-reattest"
    ]
    expect(
        reattest_wrappers
        == [
            (
                "devcoordinator-authority-readiness-reattest",
                "python",
                AUTHORITY_READINESS_SOURCE,
                ("reattest-authority-readiness",),
            )
        ],
        "authority readiness re-attestation must have one fixed immutable wrapper",
    )
    reattest_wrapper_payload = INSTALLER.wrapper_payload(
        *reattest_wrappers[0]
    )
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py" \'reattest-authority-readiness\''
        in reattest_wrapper_payload,
        "authority readiness re-attestation wrapper does not fix its interpreter, script, and action",
    )
    expect(
        entries[AUTHORITY_READINESS_REATTEST_WRAPPER]["kind"] == "wrapper",
        "authority readiness re-attestation wrapper is not manifest-bound",
    )
    bridge_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-schema12-bridge"
    ]
    expect(
        bridge_wrappers
        == [
            (
                "devcoordinator-schema12-bridge",
                "python",
                SCHEMA12_BRIDGE_SOURCE,
                (),
            )
        ],
        "schema-12 handoff must have one fixed immutable wrapper",
    )
    bridge_wrapper_payload = INSTALLER.wrapper_payload(*bridge_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/bridge_schema12_legacy_broker.py"'
        in bridge_wrapper_payload,
        "schema-12 handoff wrapper does not fix its interpreter and script",
    )
    expect(
        entries[SCHEMA12_BRIDGE_WRAPPER]["kind"] == "wrapper",
        "schema-12 handoff wrapper is not manifest-bound",
    )
    maintenance_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-maintenance"
    ]
    expect(
        maintenance_wrappers
        == [
            (
                "devcoordinator-maintenance",
                "python",
                MAINTENANCE_SOURCE,
                (),
            )
        ],
        "typed maintenance must have one fixed immutable wrapper",
    )
    maintenance_payload = INSTALLER.wrapper_payload(*maintenance_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/manage_maintenance_mode.py"'
        in maintenance_payload,
        "maintenance wrapper does not fix its isolated interpreter and script",
    )
    expect(
        entries[MAINTENANCE_WRAPPER]["kind"] == "wrapper",
        "maintenance wrapper is not manifest-bound",
    )
    maintenance_source_payload = (ROOT / MAINTENANCE_SOURCE).read_text(
        encoding="utf-8"
    )
    expect(
        "return 0, 0" in maintenance_source_payload
        and "devcoordinator-clients" not in maintenance_source_payload,
        "maintenance control still depends on the retired shared-client group",
    )
    credential_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-test-credential"
    ]
    expect(
        credential_wrappers
        == [
            (
                "devcoordinator-test-credential",
                "python",
                TEST_CREDENTIAL_SOURCE,
                (),
            )
        ],
        "operational test credentials must have one fixed immutable wrapper",
    )
    credential_wrapper_payload = INSTALLER.wrapper_payload(
        *credential_wrappers[0]
    )
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/manage_universal_test_credentials.py"'
        in credential_wrapper_payload,
        "credential wrapper does not fix its isolated interpreter and script",
    )
    expect(
        entries[TEST_CREDENTIAL_WRAPPER]["kind"] == "wrapper",
        "credential wrapper is not manifest-bound",
    )
    repair_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-authority-repository-repair"
    ]
    expect(
        repair_wrappers
        == [
            (
                "devcoordinator-authority-repository-repair",
                "python",
                AUTHORITY_READINESS_SOURCE,
                ("recover-authority-repository-disable",),
            )
        ],
        "authority repository repair must have one fixed immutable wrapper",
    )
    repair_wrapper_payload = INSTALLER.wrapper_payload(*repair_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py" \'recover-authority-repository-disable\''
        in repair_wrapper_payload,
        "authority repository repair wrapper does not fix its interpreter, script, and action",
    )
    expect(
        entries[AUTHORITY_REPOSITORY_REPAIR_WRAPPER]["kind"] == "wrapper",
        "authority repository repair wrapper is not manifest-bound",
    )
    reservation_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-port-reservations"
    ]
    expect(
        reservation_wrappers
        == [
            (
                "devcoordinator-port-reservations",
                "python",
                AUTHORITY_READINESS_SOURCE,
                ("reserve-first-adoption-ports",),
            )
        ],
        "first-adoption port reservation must have one fixed immutable wrapper",
    )
    reservation_wrapper_payload = INSTALLER.wrapper_payload(
        *reservation_wrappers[0]
    )
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py" \'reserve-first-adoption-ports\''
        in reservation_wrapper_payload,
        "port reservation wrapper does not fix its interpreter, script, and action",
    )
    expect(
        entries[PORT_RESERVATIONS_WRAPPER]["kind"] == "wrapper",
        "port reservation wrapper is not manifest-bound",
    )
    atomic_wrappers = [
        (name, kind, target, prefix)
        for name, (kind, target, prefix) in INSTALLER.WRAPPERS.items()
        if name == "devcoordinator-first-adoption-bindings"
    ]
    expect(
        atomic_wrappers
        == [
            (
                "devcoordinator-first-adoption-bindings",
                "python",
                AUTHORITY_READINESS_SOURCE,
                (),
            )
        ],
        "atomic first-adoption bindings must have one generic immutable wrapper",
    )
    atomic_wrapper_payload = INSTALLER.wrapper_payload(*atomic_wrappers[0])
    expect(
        b'/usr/bin/python3 -I -B "$ROOT/scripts/orchestrate_availability_cutover.py"'
        in atomic_wrapper_payload,
        "atomic binding wrapper does not fix its isolated interpreter and script",
    )
    expect(
        entries[ATOMIC_BINDINGS_WRAPPER]["kind"] == "wrapper",
        "atomic binding wrapper is not manifest-bound",
    )
    expect(
        "apps/DevOpsConsole/edge/devcoordinator-edge.mjs" in paths,
        "release omitted stable edge executable",
    )
    expect(
        {f"deploy/{name}" for name in INSTALLER.AVAILABILITY_TEMPLATES}.issubset(paths),
        "release omitted content-addressed availability templates",
    )
    expect(
        "deploy/devcoordinator-broker.service" in paths,
        "release omitted the broker unit required by crash-loop quiescence",
    )
    expect(
        not any("/certs/" in f"/{item}/" or item.endswith((".env", ".key", ".pem")) for item in paths),
        "release captured credentials or mutable configuration",
    )
    expect(first["capabilities"]["edge_systemd_sockets"] is True, "edge capability was hidden")
    expect(
        first["capabilities"]["authority_systemd_socket"] is True
        and first["capabilities"]["api_systemd_socket"] is True,
        "release hid native inherited-listener support",
    )
    expect(
        first["capabilities"]["console_parallel_writer_safe"] is True,
        "release hid the supervised single-writer Console cutover",
    )
    expect(
        first["capabilities"]["observer_projection"] is True,
        "release hid the distinct retained inventory projection",
    )
    expect(
        first["capabilities"]["project_runtime_isolation"] is True,
        "release omitted fail-closed project process/container isolation",
    )
    expect(
        first["capabilities"]["asynchronous_test_plane"] is True
        and first["capabilities"]["sealed_test_capability_policy"] is True
        and first["capabilities"]["sealed_operational_test_credentials"] is True,
        "release omitted production test-plane composition",
    )
    expect(
        first["capabilities"]["repository_owner_map_preparation"] is True,
        "release hid immutable repository-owner map preparation",
    )
    expect(
        first["capabilities"]["authority_readiness_recovery"] is True,
        "release hid authority readiness recovery",
    )
    expect(
        first["capabilities"]["authority_readiness_rebind"] is True,
        "release hid authority readiness rebind",
    )
    expect(
        first["capabilities"]["authority_readiness_reattestation"] is True,
        "release hid no-mutation authority readiness re-attestation",
    )
    with tempfile.TemporaryDirectory(prefix="availability-trusted-source-") as raw_source:
        trusted_source = Path(raw_source) / "source"
        copy_release_source(trusted_source)
        trusted_source.chmod(0o777)
        trusted_result = INSTALLER.stage_release(
            trusted_source,
            Path(raw_source) / "releases",
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(
            trusted_result["created"] is True,
            "trusted local source metadata still blocked immutable staging",
        )

    with tempfile.TemporaryDirectory(
        prefix="availability-default-ancestry-"
    ) as raw_default:
        root = Path(raw_default)
        root.chmod(0o755)
        trusted_parent = root / "opt"
        trusted_parent.mkdir(mode=0o755)
        trusted_parent.chmod(0o755)
        dedicated_root = trusted_parent / "devcoordinator"
        dedicated_root.mkdir(mode=0o700)
        releases = dedicated_root / "releases"
        with mock.patch.object(
            INSTALLER, "DEFAULT_RELEASE_ROOT", releases
        ):
            result = INSTALLER.stage_release(
                ROOT,
                releases,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )
            release = Path(result["release_directory"])
            expect(
                stat.S_IMODE(dedicated_root.lstat().st_mode) == 0o755
                and stat.S_IMODE(releases.lstat().st_mode) == 0o755,
                "default release staging did not reconcile public ancestry",
            )
            dedicated_root.chmod(0o700)
            must_fail(
                lambda: INSTALLER.verify_release(
                    release,
                    owner_uid=os.geteuid(),
                    owner_gid=os.getegid(),
                ),
                "non-traversable default release ancestry",
            )
            replayed = INSTALLER.stage_release(
                ROOT,
                releases,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )
            expect(
                replayed["created"] is False
                and stat.S_IMODE(dedicated_root.lstat().st_mode) == 0o755,
                "default release replay did not repair ancestry before verify",
            )
            if os.geteuid() == 0:
                account = pwd.getpwnam("nobody")
                unprivileged = subprocess.run(
                    [
                        "/usr/bin/setpriv",
                        "--reuid",
                        str(account.pw_uid),
                        "--regid",
                        str(account.pw_gid),
                        "--clear-groups",
                        "--reset-env",
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        str(
                            release
                            / "scripts/bridge_schema12_legacy_broker.py"
                        ),
                        "--help",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                    cwd="/",
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                    },
                )
                expect(
                    unprivileged.returncode == 0,
                    "an unprivileged UID could not execute the immutable "
                    "bridge through default release ancestry: "
                    + unprivileged.stderr.decode(
                        "utf-8", errors="replace"
                    ),
                )

    with tempfile.TemporaryDirectory(prefix="availability-release-test-") as raw:
        root = Path(raw)
        # Exercise the long immutable-release cycle against a private source
        # snapshot.  Repository-wide validation may run beside other agents;
        # staging directly from their live checkout makes a legitimate source
        # edit look like an idempotence defect halfway through this test.
        source = root / "source"
        copy_release_source(source)
        releases = root / "releases"
        snapshot_entries = {
            entry["path"]: entry
            for entry in INSTALLER.plan_release(source, releases)["files"]
        }
        result = INSTALLER.stage_release(
            source,
            releases,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(result["created"] is True, "first stage did not create a release")
        release = Path(result["release_directory"])
        expect(
            release.name == result["release_digest"]
            and INSTALLER.RELEASE_RE.fullmatch(release.name),
            "stage did not publish its exact content digest",
        )
        expect(stat.S_IMODE(release.stat().st_mode) == 0o555, "release root remains writable")
        for target in release.rglob("*"):
            info = target.lstat()
            expect(not stat.S_ISLNK(info.st_mode), f"release contains symlink: {target}")
            expect(stat.S_IMODE(info.st_mode) & 0o222 == 0, f"release entry is writable: {target}")
        expect(
            INSTALLER.verify_release(
                release,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )["ok"],
            "fresh release did not verify",
        )
        staged_broker_unit = release / BROKER_UNIT_SOURCE
        expect(
            staged_broker_unit.is_file()
            and not staged_broker_unit.is_symlink()
            and staged_broker_unit.read_bytes()
            == (source / BROKER_UNIT_SOURCE).read_bytes()
            and hashlib.sha256(staged_broker_unit.read_bytes()).hexdigest()
            == snapshot_entries[BROKER_UNIT_SOURCE]["sha256"],
            "staged release did not retain the exact manifest-bound broker unit",
        )
        staged_playwright_package = release / PLAYWRIGHT_PACKAGE_SOURCE
        expect(
            staged_playwright_package.is_file()
            and not staged_playwright_package.is_symlink()
            and staged_playwright_package.read_bytes()
            == (source / PLAYWRIGHT_PACKAGE_SOURCE).read_bytes()
            and hashlib.sha256(staged_playwright_package.read_bytes()).hexdigest()
            == snapshot_entries[PLAYWRIGHT_PACKAGE_SOURCE]["sha256"],
            "staged release did not retain the exact locked Playwright manifest",
        )
        self_verification = subprocess.run(
            [
                sys.executable,
                str(release / "scripts/install_availability_release.py"),
                "verify",
                "--release",
                str(release),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        expect(
            self_verification.returncode == 0,
            "release self-verification failed: "
            + self_verification.stderr.decode("utf-8", errors="replace"),
        )
        expect(
            not any(path.name == "__pycache__" for path in release.rglob("__pycache__")),
            "release self-verification created derived Python bytecode",
        )
        manifest = json.loads(
            (release / "release-manifest.json").read_text(encoding="utf-8")
        )
        manifest_entries = {entry["path"]: entry for entry in manifest["files"]}
        expect(
            manifest_entries[INSTALLER_FENCE_SOURCE]["sha256"]
            == hashlib.sha256(
                (source / INSTALLER_FENCE_SOURCE).read_bytes()
            ).hexdigest(),
            "release did not bind the exact installer fence module",
        )
        for relative, wanted_mode in (
            (OWNER_AUTHORITY_SOURCE, 0o444),
            (OWNER_AUTHORITY_WRAPPER, 0o555),
            (AUTHORITY_READINESS_WRAPPER, 0o555),
            (MAINTENANCE_SOURCE, 0o444),
            (MAINTENANCE_WRAPPER, 0o555),
        ):
            target = release / relative
            info = target.lstat()
            expect(
                info.st_uid == os.geteuid()
                and info.st_gid == os.getegid()
                and stat.S_IMODE(info.st_mode) == wanted_mode,
                f"immutable repository-owner entry has unsafe metadata: {relative}",
            )
            expect(
                manifest_entries[relative]["sha256"]
                == hashlib.sha256(target.read_bytes()).hexdigest(),
                f"immutable repository-owner entry escaped its digest: {relative}",
            )
        must_fail(
            lambda: INSTALLER.verify_release(
                release,
                owner_uid=os.geteuid() + 1,
                owner_gid=os.getegid(),
            ),
            "repository-owner release ownership mismatch",
        )
        release_alias = root / "release-alias"
        release_alias.symlink_to(release, target_is_directory=True)
        must_fail(
            lambda: INSTALLER.verify_release(release_alias),
            "symlinked repository-owner release root",
        )
        release_alias.unlink()
        manifest_path = release / "release-manifest.json"
        manifest_path.chmod(0o644)
        must_fail(
            lambda: INSTALLER.verify_release(release),
            "writable repository-owner release manifest",
        )
        manifest_path.chmod(0o444)
        for wrapper_name in (
            "devcoordinator-testd",
            "devcoordinator-test-snapshotd",
            "devcoordinator-repository-owner-authority",
            "devcoordinator-authority-readiness-rebind",
            "devcoordinator-authority-readiness-reattest",
            "devcoordinator-schema12-bridge",
            "devcoordinator-maintenance",
            "devcoordinator-test-credential",
        ):
            wrapper_probe = subprocess.run(
                [str(release / "bin" / wrapper_name), "--help"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            expect(
                wrapper_probe.returncode == 0,
                f"{wrapper_name} could not import as a package entrypoint: "
                + wrapper_probe.stderr.decode("utf-8", errors="replace"),
            )
        policy_recovery_probe = subprocess.run(
            [
                str(release / "bin/devcoordinator-schema12-bridge"),
                "recover-policy-reconciled-restored",
                "--help",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        expect(
            policy_recovery_probe.returncode == 0
            and b"--predecessor-journal-raw-sha256"
            in policy_recovery_probe.stdout
            and b"--policy-result-document-sha256"
            in policy_recovery_probe.stdout,
            "installed schema-12 wrapper omitted policy recovery dispatch",
        )
        lifecycle_quiesce_probe = subprocess.run(
            [
                str(release / "bin/devcoordinator-schema12-bridge"),
                "quiesce-lifecycle-recovery-crash-loop",
                "--help",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        expect(
            lifecycle_quiesce_probe.returncode == 0
            and b"--lifecycle-result-raw-sha256"
            in lifecycle_quiesce_probe.stdout
            and b"--lifecycle-service-result"
            in lifecycle_quiesce_probe.stdout,
            "installed schema-12 wrapper omitted lifecycle quiesce dispatch",
        )
        python_wrappers = sorted(
            name
            for name, (kind, _target, _prefix) in INSTALLER.WRAPPERS.items()
            if kind == "python"
        )
        for wrapper_name in python_wrappers:
            wrapper = release / "bin" / wrapper_name
            expect(
                b"/usr/bin/python3 -I -B" in wrapper.read_bytes(),
                f"{wrapper_name} does not disable bytecode writes",
            )
        release_directories = [
            release,
            *(path for path in release.rglob("*") if path.is_dir()),
        ]
        release_inventory_before = {
            path.relative_to(release).as_posix()
            for path in release.rglob("*")
        }
        try:
            # A root process can write through 0555 directory modes. Making
            # the staged tree owner-writable gives this ordinary-user test the
            # same ability and proves the entrypoint, rather than DAC, prevents
            # derived bytecode from entering the immutable release.
            for directory in release_directories:
                directory.chmod(0o755)
            for wrapper_name in python_wrappers:
                wrapper_probe = subprocess.run(
                    [str(release / "bin" / wrapper_name), "--help"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                    cwd="/",
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "PYTHONDONTWRITEBYTECODE": "0",
                    },
                )
                expect(
                    wrapper_probe.returncode == 0,
                    f"{wrapper_name} root-equivalent import probe failed: "
                    + wrapper_probe.stderr.decode("utf-8", errors="replace"),
                )
        finally:
            for directory in sorted(
                (path for path in release.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                directory.chmod(0o555)
            release.chmod(0o555)
        expect(
            {
                path.relative_to(release).as_posix()
                for path in release.rglob("*")
            }
            == release_inventory_before,
            "root-equivalent Python wrapper execution mutated the immutable release",
        )
        helper = release / "libexec/universal_test_uid_helper.py"
        helper_probe = subprocess.run(
            [sys.executable, "-I", "-B", str(helper)],
            input=b"{}",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        expect(
            helper_probe.returncode == 1 and helper_probe.stderr == b"",
            "immutable per-UID helper did not fail closed through its JSON protocol",
        )
        try:
            helper_response = json.loads(helper_probe.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(
                "immutable per-UID helper could not import its release package"
            ) from error
        expect(
            isinstance(helper_response, dict)
            and helper_response.get("ok") is False
            and isinstance(helper_response.get("error"), dict),
            "immutable per-UID helper did not return a structured refusal",
        )

        repeated = INSTALLER.stage_release(
            source,
            releases,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(repeated["created"] is False, "idempotent stage replaced an immutable release")

        reservation_bundle, reservation_sha256, reservation_document = (
            write_port_reservations(root, release.name)
        )
        validated_reservations = INSTALLER.validated_port_reservations(
            reservation_bundle,
            expected_document_sha256=reservation_sha256,
            release_digest=release.name,
        )
        expect(
            validated_reservations == reservation_document,
            "private port reservation bundle did not round-trip",
        )

        maintenance_root = root / "maintenance"
        maintenance_root.mkdir()

        def prepare_bundle(document: dict[str, object]) -> None:
            document["kind"] = INSTALLER.PREPARED_PORT_RESERVATIONS_KIND
            document["port_journal_sha256"] = document.pop(
                "transaction_journal_sha256"
            )
            document["atomic_transaction_journal_sha256"] = "b" * 64
            document["service_stopped"] = True
            document.pop("service_restored")
            document.pop("maintenance_cleared")
            document["maintenance"] = {
                "root": str(maintenance_root),
                "gid": 986,
                "deployment_id": "23456789-2345-4234-8234-23456789abcd",
                "message": "Coordinator maintenance",
                "retry_after_seconds": 5,
                "started_at": "2099-01-01T00:00:00.000Z",
            }

        prepared_bundle, prepared_sha256, prepared_document = (
            write_port_reservations(
                root,
                release.name,
                name="prepared-port-reservations.json",
                update=prepare_bundle,
            )
        )
        with mock.patch.object(
            INSTALLER, "_verify_prepared_port_reservation_fence"
        ) as prepared_fence:
            validated_prepared = INSTALLER.validated_port_reservations(
                prepared_bundle,
                expected_document_sha256=prepared_sha256,
                release_digest=release.name,
            )
        expect(
            validated_prepared == prepared_document,
            "prepared port reservation bundle did not round-trip",
        )
        prepared_fence.assert_called_once()
        marker = mock.Mock(
            deployment_id=prepared_document["maintenance"]["deployment_id"],
            message=prepared_document["maintenance"]["message"],
            retry_after_seconds=prepared_document["maintenance"][
                "retry_after_seconds"
            ],
            started_at=prepared_document["maintenance"]["started_at"],
        )
        stopped = mock.Mock(returncode=3)
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.object(
            INSTALLER.subprocess, "run", return_value=stopped
        ) as systemctl, mock.patch.object(
            INSTALLER, "load_maintenance_state", return_value=marker
        ) as maintenance_reader:
            INSTALLER._verify_prepared_port_reservation_fence(
                prepared_document
            )
        systemctl.assert_called_once()
        maintenance_reader.assert_called_once_with(
            expected_uid=0,
            expected_gid=986,
            maintenance_root=maintenance_root,
        )
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.object(
            INSTALLER.subprocess, "run", return_value=mock.Mock(returncode=0)
        ):
            must_fail(
                lambda: INSTALLER._verify_prepared_port_reservation_fence(
                    prepared_document
                ),
                "prepared bundle with active legacy broker",
            )
        with mock.patch.object(
            INSTALLER, "_verify_prepared_port_reservation_fence"
        ):
            prepared_render = INSTALLER.render_units(
                release,
                root / "rendered-prepared",
                total_memory_bytes=8 * INSTALLER.GIB,
                host_cpu_count=8,
                port_reservations=prepared_bundle,
                port_reservations_sha256=prepared_sha256,
            )
        expect(
            prepared_render["activation_ready"] is True
            and prepared_render["port_reservations_sha256"]
            == prepared_sha256,
            "unit rendering rejected exact prepared binding evidence",
        )
        must_fail(
            lambda: INSTALLER.validated_port_reservations(
                reservation_bundle,
                expected_document_sha256="f" * 64,
                release_digest=release.name,
            ),
            "mismatched port reservation digest",
        )
        reservation_bundle.chmod(0o644)
        must_fail(
            lambda: INSTALLER.validated_port_reservations(
                reservation_bundle,
                expected_document_sha256=reservation_sha256,
                release_digest=release.name,
            ),
            "public port reservation bundle",
        )
        reservation_bundle.chmod(0o600)
        bad_reservations, bad_reservations_sha256, _bad_document = (
            write_port_reservations(
                root,
                release.name,
                name="duplicate-port-reservations.json",
                update=lambda document: document["reservations"]["console_inner"].__setitem__(
                    "port",
                    document["reservations"]["console_outer"]["port"],
                ),
            )
        )
        must_fail(
            lambda: INSTALLER.validated_port_reservations(
                bad_reservations,
                expected_document_sha256=bad_reservations_sha256,
                release_digest=release.name,
            ),
            "duplicated broker-leased port",
        )
        bad_expiry, bad_expiry_sha256, _bad_expiry_document = (
            write_port_reservations(
                root,
                release.name,
                name="bad-expiry-port-reservations.json",
                update=lambda document: document["reservations"]["handoff_api"].__setitem__(
                    "expires_at", "2099-01-01T02:00:00.000Z"
                ),
            )
        )
        must_fail(
            lambda: INSTALLER.validated_port_reservations(
                bad_expiry,
                expected_document_sha256=bad_expiry_sha256,
                release_digest=release.name,
            ),
            "non-uniform handoff lease expiry",
        )

        rendered = root / "rendered"
        render_result = INSTALLER.render_units(
            release,
            rendered,
            total_memory_bytes=8 * INSTALLER.GIB,
            host_cpu_count=8,
            port_reservations=reservation_bundle,
            port_reservations_sha256=reservation_sha256,
        )
        expect(render_result["activation_ready"] is True, "complete availability release was not activatable")
        expect(
            render_result["handoff_ports"]
            == {"http": 38080, "https": 38443, "api": 39876}
            and render_result["port_reservations_sha256"]
            == reservation_sha256,
            "unit rendering did not derive its ports from the sealed bundle",
        )
        edge_unit = (rendered / "devcoordinator-edge.service").read_text(encoding="utf-8")
        expect("RELEASE_DIGEST" not in edge_unit, "rendered edge retained placeholder digest")
        expect(f"/releases/{release.name}/bin/devcoordinator-edge" in edge_unit, "edge unit selected another release")
        capacity = render_result["capacity"]
        expect(
            capacity["os_reserve_bytes"]
            + capacity["control_memory_low_bytes"]
            + capacity["background_memory_max_bytes"]
            + capacity["project_memory_max_bytes"]
            == capacity["host_memory_bytes"],
            "derived slice capacities overcommitted the host",
        )
        expect(
            str(capacity["project_memory_max_bytes"])
            in (rendered / "devcoordinator-projects.slice").read_text(encoding="utf-8"),
            "rendered project slice did not bind the derived host capacity",
        )
        expect(
            not any(field.startswith("testd_") for field in capacity),
            "availability capacity still exposes fixed test scheduler budgets",
        )
        rendered_testd = (rendered / "devcoordinator-testd.service").read_text(
            encoding="utf-8"
        )
        expect(
            not any(
                flag in rendered_testd
                for flag in (
                    "--max-jobs",
                    "--host-cpu-millis",
                    "--host-memory-mib",
                    "--host-pids",
                    "--per-uid-jobs",
                    "--per-repository-jobs",
                )
            ),
            "rendered testd retained a fixed resource or concurrency budget",
        )
        rendered_tests_slice = (rendered / "devcoordinator-tests.slice").read_text(
            encoding="utf-8"
        )
        expect(
            all(
                f"{key}=yes" in rendered_tests_slice
                for key in (
                    "CPUAccounting",
                    "MemoryAccounting",
                    "IOAccounting",
                    "TasksAccounting",
                )
            )
            and not any(
                key in rendered_tests_slice
                for key in (
                    "CPUQuota=",
                    "CPUWeight=",
                    "MemoryHigh=",
                    "MemoryMax=",
                    "TasksMax=",
                    "IOWeight=",
                )
            ),
            "rendered test-attempt slice is not accounting-only",
        )
        for total in (3 * INSTALLER.GIB, 8 * INSTALLER.GIB, 64 * INSTALLER.GIB):
            derived = INSTALLER.derive_slice_capacity(
                total,
                cpu_count=8,
            )
            expect(
                derived["background_memory_high_bytes"]
                < derived["background_memory_max_bytes"]
                and derived["project_memory_high_bytes"]
                < derived["project_memory_max_bytes"],
                "derived high/max ordering is contradictory",
            )
        expect(
            {
                "devcoordinator-testd.service",
                "devcoordinator-testd.socket",
                "devcoordinator-test-snapshotd.service",
                "devcoordinator-test-snapshotd.socket",
                "devcoordinator-tests.slice",
            }.issubset(set(render_result["files"])),
            "rendered topology omitted testd, snapshotd, or the test accounting slice",
        )

        policy_parent = root / "etc-devcoordinator"
        policy_parent.mkdir(mode=0o700)
        policy = policy_parent / "test-execution-capabilities.json"
        installed_policy = INSTALLER.install_test_capability_policy(
            ROOT / INSTALLER.TEST_CAPABILITY_SOURCE,
            policy,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(
            installed_policy["created"] is True
            and installed_policy["changed"] is True
            and stat.S_IMODE(policy.stat().st_mode) == 0o600,
            "sealed test capability policy was not installed privately",
        )
        expect(
            INSTALLER.install_test_capability_policy(
                ROOT / INSTALLER.TEST_CAPABILITY_SOURCE,
                policy,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )["changed"]
            is False,
            "sealed test capability policy installation was not idempotent",
        )

        observer_state = root / "observer-state"
        observer_state.mkdir(mode=0o700)
        publication = observer_state / "inventory.publication"
        initialized = INSTALLER.initialize_observer_projection(
            release,
            publication,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(initialized["created"] is True, "retained projection was not initialized")
        expect(initialized["generation"] == 1, "retained projection started at another generation")
        expect(
            not any(
                path.name == "__pycache__"
                for path in release.rglob("__pycache__")
            ),
            "retained projection initialization mutated the immutable release",
        )
        expect(
            INSTALLER.initialize_observer_projection(
                release,
                publication,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )["created"] is False,
            "retained projection initialization was not idempotent",
        )

        slot = root / "console-slots" / f"{release.name}.env"
        slot_result = INSTALLER.render_console_slot(
            release,
            slot,
            port_reservations=reservation_bundle,
            port_reservations_sha256=reservation_sha256,
        )
        expect(slot_result["created"] is True, "Console candidate slot was not created")
        expect(
            slot_result["port"] == 30443
            and slot_result["inner_port"] == 30444
            and slot_result["port_reservations_sha256"] == reservation_sha256,
            "Console candidate did not derive its ports from the sealed bundle",
        )
        expect(slot_result["parallel_writer_safe"] is True, "slot hid single-writer supervision")
        expect(
            slot.read_text(encoding="utf-8").splitlines()
            == [
                "# Generated immutable Console candidate slot.",
                "BIND_HOST=127.0.0.1",
                "DEV_HTTP=0",
                "HTTP_PORT=0",
                "HTTPS_PORT=30443",
                f"DEVCOORDINATOR_RELEASE_DIGEST={release.name}",
                "DEVCOORDINATOR_CONSOLE_INNER_PORT=30444",
                f"DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET=/run/devcoordinator-console/{release.name}.sock",
                "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE=/var/lib/devcoordinator-console/supervisor",
                "DEVCOORDINATOR_CONSOLE_RUNTIME=/run/devcoordinator-console",
                "DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE=0",
            ],
            "Console slot contains mutable or unexpected configuration",
        )
        expect(
            INSTALLER.render_console_slot(
                release,
                slot,
                port_reservations=reservation_bundle,
                port_reservations_sha256=reservation_sha256,
            )["created"] is False,
            "identical Console slot render was not idempotent",
        )
        conflicting_reservations, conflicting_sha256, _conflicting_document = (
            write_port_reservations(
                root,
                release.name,
                name="conflicting-port-reservations.json",
                update=lambda document: (
                    document["reservations"]["console_outer"].__setitem__(
                        "port", 30445
                    ),
                    document["reservations"]["console_inner"].__setitem__(
                        "port", 30446
                    ),
                ),
            )
        )
        must_fail(
            lambda: INSTALLER.render_console_slot(
                release,
                slot,
                port_reservations=conflicting_reservations,
                port_reservations_sha256=conflicting_sha256,
            ),
            "conflicting Console slot port",
        )
        must_fail(
            lambda: INSTALLER.render_console_slot(
                release,
                root / "console-slots" / f"{release.name}.env",
                port_reservations=bad_reservations,
                port_reservations_sha256=bad_reservations_sha256,
            ),
            "identical outer and inner Console ports",
        )

        derived_parent = (
            release
            / "skills/codex-dev-coordinator/scripts/devcoordinator"
        )
        derived_parent.chmod(0o755)
        derived_directory = derived_parent / "__pycache__"
        derived_directory.mkdir(mode=0o700)
        derived_file = derived_directory / "unsupported.cpython-313.pyc"
        derived_file.write_bytes(b"unsupported derived bytecode")
        derived_parent.chmod(0o555)
        must_fail(
            lambda: INSTALLER.verify_release(release),
            "post-publication derived Python bytecode",
        )
        derived_parent.chmod(0o755)
        derived_file.unlink()
        derived_directory.rmdir()
        derived_parent.chmod(0o555)
        expect(
            INSTALLER.verify_release(release)["ok"],
            "derived-file rejection did not preserve the staged release",
        )

        target = release / OWNER_AUTHORITY_SOURCE
        target.chmod(0o644)
        target.write_bytes(target.read_bytes() + b"\n")
        target.chmod(0o444)
        must_fail(
            lambda: INSTALLER.verify_release(release),
            "post-publication repository-owner source drift",
        )

    with tempfile.TemporaryDirectory(prefix="availability-release-race-") as raw:
        root = Path(raw)
        mutable_source = root / "source"
        copy_release_source(mutable_source)
        releases = root / "releases"
        planned = INSTALLER.plan_release(mutable_source, releases)
        changed_source = mutable_source / "apps/DevOpsConsole/package.json"
        original_source_payload = changed_source.read_bytes()
        original_install_bytes = INSTALLER._install_bytes
        mutated = False

        def mutate_during_copy(*args, **kwargs):
            nonlocal mutated
            if not mutated:
                mutated = True
                changed_source.write_bytes(original_source_payload + b"\n")
            return original_install_bytes(*args, **kwargs)

        INSTALLER._install_bytes = mutate_during_copy
        try:
            must_fail(
                lambda: INSTALLER.stage_release(
                    mutable_source,
                    releases,
                    owner_uid=os.geteuid(),
                    owner_gid=os.getegid(),
                ),
                "source mutation during release copy",
            )
        finally:
            INSTALLER._install_bytes = original_install_bytes
        expect(mutated, "release mutation regression did not exercise the copy window")
        expect(
            not Path(planned["release_directory"]).exists(),
            "source mutation published the planned content-addressed destination",
        )
        expect(
            not list(releases.glob("*.partial")) and not list(releases.glob(".*.partial")),
            "source mutation left a partial release behind",
        )

        changed_source.write_bytes(original_source_payload)
        staged = INSTALLER.stage_release(
            mutable_source,
            releases,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        immutable_release = Path(staged["release_directory"])
        expect(
            (
                immutable_release
                / "deploy"
                / "devcoordinator-broker.service"
            ).is_file(),
            "staged release omitted its manifest-bound broker unit",
        )
        template_name = "devcoordinator-edge.service"
        immutable_template = (
            immutable_release / "deploy" / template_name
        ).read_text(encoding="utf-8")
        (mutable_source / "deploy" / template_name).write_text(
            "MUTABLE TEMPLATE MUST NEVER BE RENDERED\n", encoding="utf-8"
        )
        rendered = root / "rendered-from-release"
        reservation_bundle, reservation_sha256, _reservation_document = (
            write_port_reservations(
                root,
                immutable_release.name,
                name="immutable-port-reservations.json",
            )
        )
        INSTALLER.render_units(
            immutable_release,
            rendered,
            port_reservations=reservation_bundle,
            port_reservations_sha256=reservation_sha256,
        )
        expect(
            (rendered / template_name).read_text(encoding="utf-8")
            == immutable_template.replace("RELEASE_DIGEST", immutable_release.name),
            "unit rendering read a mutable repository template",
        )

    print("immutable availability release self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
