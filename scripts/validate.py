#!/usr/bin/env python3
"""Repo-level validation for Holy Skills."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "full_repo_harness"
SKILLS = [
    ROOT / "skills" / "codex-dev-coordinator",
    ROOT / "skills" / "formal-web-ui-verification",
    ROOT / "skills" / "full-repo-audit",
    ROOT / "skills" / "full-repo-test-coverage-audit",
    ROOT / "skills" / "postgres-docker-backup",
    ROOT / "skills" / "trace-fix-root-causes",
    ROOT / "skills" / "ui-implementation-audit",
    ROOT / "skills" / "user-journey-docs-audit",
]
HARNESS_SKILLS = [
    ROOT / "skills" / "full-repo-audit",
    ROOT / "skills" / "full-repo-test-coverage-audit",
    ROOT / "skills" / "ui-implementation-audit",
]


def run(args: list[str], *, cwd: Path = ROOT) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=cwd, check=True)


def tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    source_files = []
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        if "__pycache__" in item.parts or item.suffix == ".pyc":
            continue
        source_files.append(item)
    for file_path in sorted(source_files):
        rel = file_path.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def check_vendor_sync() -> None:
    expected = tree_digest(HARNESS)
    for skill in HARNESS_SKILLS:
        vendor = skill / "scripts" / "_vendor" / "full_repo_harness"
        if not vendor.is_dir():
            raise SystemExit(f"Missing vendored harness: {vendor}")
        actual = tree_digest(vendor)
        if actual != expected:
            raise SystemExit(f"Vendored harness is stale: {vendor}")


def check_standalone_skill(skill: Path) -> None:
    tmp = Path(tempfile.mkdtemp(prefix=f"{skill.name}-standalone-"))
    try:
        if skill in HARNESS_SKILLS:
            stale_parent_harness = tmp / "full_repo_harness"
            stale_parent_harness.mkdir()
            (stale_parent_harness / "__init__.py").write_text("", encoding="utf-8")
            (stale_parent_harness / "queue.py").write_text(
                "raise RuntimeError('stale parent harness imported')\n",
                encoding="utf-8",
            )
        copied = tmp / skill.name
        shutil.copytree(skill, copied)
        run([sys.executable, str(copied / "scripts" / "self_test.py")])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_include_glob_exclusions() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="include-glob-exclusion-"))
    try:
        repo = tmp / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "node_modules" / "pkg").mkdir(parents=True)
        (repo / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
        (repo / "node_modules" / "pkg" / "index.py").write_text("print(2)\n", encoding="utf-8")
        run(["git", "init", "-q"], cwd=repo)
        run(["git", "add", "src/app.py"], cwd=repo)
        run(
            [
                "git",
                "-c",
                "user.name=Holy Skills Test",
                "-c",
                "user.email=holyskills-test@example.invalid",
                "commit",
                "-q",
                "-m",
                "init",
            ],
            cwd=repo,
        )

        broad_out = tmp / "broad"
        run(
            [
                sys.executable,
                "skills/full-repo-audit/scripts/build_audit_batches.py",
                "--repo",
                str(repo),
                "--out",
                str(broad_out),
                "--include-glob",
                "**/*.py",
            ]
        )
        broad_manifest = json.loads((broad_out / "manifest.json").read_text(encoding="utf-8"))
        broad_files = {item["rel_path"] for item in broad_manifest["source_files"]}
        if "node_modules/pkg/index.py" in broad_files:
            raise SystemExit("Broad --include-glob unexpectedly included vendor path node_modules/pkg/index.py")

        explicit_out = tmp / "explicit"
        run(
            [
                sys.executable,
                "skills/full-repo-audit/scripts/build_audit_batches.py",
                "--repo",
                str(repo),
                "--out",
                str(explicit_out),
                "--include-glob",
                "node_modules/**/*.py",
            ]
        )
        explicit_manifest = json.loads((explicit_out / "manifest.json").read_text(encoding="utf-8"))
        explicit_files = {item["rel_path"] for item in explicit_manifest["source_files"]}
        if "node_modules/pkg/index.py" not in explicit_files:
            raise SystemExit("Explicit --include-glob should include targeted vendor path node_modules/pkg/index.py")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_ops_console_interaction_guardrails(*, run_macos_app_checks: bool = True) -> None:
    ops_console = ROOT / "apps" / "CodexOpsConsole"
    if not ops_console.is_dir():
        return

    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ops_console / "Sources" / "CodexOpsConsole").glob("*.swift"))
    )
    views = (ops_console / "Sources" / "CodexOpsConsole" / "Views.swift").read_text(encoding="utf-8")
    store = (ops_console / "Sources" / "CodexOpsConsole" / "OpsStore.swift").read_text(encoding="utf-8")
    models = (ops_console / "Sources" / "CodexOpsConsole" / "Models.swift").read_text(encoding="utf-8")
    snapshot_main = (ops_console / "Tools" / "SnapshotMain.swift").read_text(encoding="utf-8")
    menu_snapshot = (ops_console / "Tools" / "MenuBarSnapshotMain.swift").read_text(encoding="utf-8")
    snapshot_provenance = (ops_console / "Tools" / "SnapshotProvenance.swift").read_text(encoding="utf-8")
    split_sizing = (ops_console / "Tools" / "SplitSizingTest.swift").read_text(encoding="utf-8")
    core_tests = (ops_console / "Tests" / "CodexOpsConsoleTests" / "CoreTests.swift").read_text(encoding="utf-8")
    coordinator = (ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py").read_text(encoding="utf-8")
    coordinator_self_test = (ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "self_test.py").read_text(encoding="utf-8")
    coordinator_skill = (ROOT / "skills" / "codex-dev-coordinator" / "SKILL.md").read_text(encoding="utf-8")

    required = {
        "left pane splitter": "SplitHandle(width: $sidebarWidth",
        "right pane splitter": "SplitHandle(width: $inspectorWidth",
        "thin splitter width": "let splitHandleWidth: CGFloat = 8",
        "absolute pane layout": "ZStack(alignment: .topLeading)",
        "exact main pane frame": ".frame(width: layout.mainWidth, height:",
        "positioned main pane": ".position(x: mainX +",
        "global splitter drag": "DragGesture(minimumDistance: 0, coordinateSpace: .global)",
        "stable splitter math": "resizedPaneWidth(",
        "responsive console layout": "func consoleLayout(",
        "minimum readable sidebar": "minimumReadableSidebarWidth",
        "responsive toolbar": "private var compactToolbar",
        "compact toolbar search": "SearchField(text: $store.searchText, compact: true)",
        "readable inspector minimum": "let minimumInspectorWidth: CGFloat = 320",
        "vertical-only service map scroll": "ScrollView(.vertical)",
        "expandable sidebar tree": "expandedProjects",
        "sidebar selection": "sidebarSelection",
        "canonical project grouping": "func projectKey(fromResourceName",
        "resource leaf prefix removal": "resourceDisplayName(",
        "typed sidebar leaves": "enum MapLeafKind",
        "sidebar leaf actions": "SidebarActionButton",
        "safe sidebar footer": "SidebarFooterView",
        "explicit sidebar footer width": "sidebarFooterContentWidth(totalWidth:",
        "sidebar footer geometry": "GeometryReader { proxy in",
        "sidebar source management": "CoordinatorSourcesSheet",
        "typed source configuration save": "saveCoordinatorConfiguration",
        "server sidebar toggle": "func toggle(_ server",
        "docker sidebar toggle": "func toggleDocker",
        "combined presentation reducer UI": "presentationSnapshot",
        "compact source health chip": "SourceHealthChip",
        "inventory state banner": "InventoryStateBanner",
        "partial capability warning": "Server and port lease actions remain available",
        "launch-safe command environment": "enum CommandEnvironment",
        "macOS system path discovery": "/etc/paths.d",
        "every process receives resolved environment": "process.environment = environment",
        "project Docker capability gate": "func projectMutationAvailability",
        "partial project runtime evidence": "var partial: Bool?",
        "minimal-path command environment regression": "testCommandEnvironmentBuildsLaunchSafePathFromAbsoluteInheritedAndSystemEntries",
        "Docker-backed project gating regression": "testDockerBackedProjectMutationRequiresDockerButStatusAndServerOnlyProjectsRemainAvailable",
        "failed project refresh regression": "testNonzeroProjectActionRetainsPartialEvidenceAndAlwaysRefreshesInventory",
        "thrown project refresh regression": "testThrownProjectActionFailureStillRefreshesInventory",
        "source provenance badges": "SourceBadge",
        "mutation availability UI gating": "actionAllowed(store, kind:",
        "complete server action gating": "serverActionAllowed",
        "complete docker action gating": "dockerActionAllowed",
        "complete database action gating": "databaseProtectionActionAllowed",
        "retained action result drawer": "ActionResultDrawer",
        "terminal action result dismissal": "dismissActionResult",
        "action issue copy": "copyIssueDetails",
        "action issue dismissal": "dismissActionIssue",
        "exact lease result card": "LeaseResultCard",
        "all active lease management": "ManagedLeasesPanel",
        "discovered lease import": "LeaseActionResult(origin: origin, lease: lease",
        "lease attachment state": "pendingOperationID",
        "lease start eligibility": "canStartServer",
        "lease release eligibility": "canReleaseDirectly",
        "lease release attribution": "\"--agent\", agentID",
        "lease release project binding": "\"--project\", project",
        "scope-aware lease absence": "isAuthoritativelyAbsent",
        "lease port copy": "copyLeasePort",
        "lease-bound start action": "Start using lease",
        "multi-source action selector": "ActionSourcePicker",
        "start source binding": "selection: $store.startDraft.origin",
        "lease source binding": "selection: $store.leaseOrigin",
        "explicit bulk selection": "BulkSelectionCheckbox",
        "bulk stop review": "BulkStopReviewSheet",
        "bounded bulk plan preparation": "prepareBulkStop()",
        "bounded bulk execution": "executeBulkStop(planID:",
        "database checksum evidence": "Checksum verified",
        "database restore-test evidence": "Restore tested",
        "database restore confirmation": "DatabaseRestoreSheet",
        "structured executable field": "startDraft.executable",
        "structured argument rows": "startDraft.argumentRows",
        "stable command argument rows": "ForEach($store.startDraft.argumentRows)",
        "stable coordinator source rows": "ForEach($sourceRows)",
        "resource tabs": "ResourceTabBar",
        "resizable table columns": "ResizableHeaderCell",
        "column resize helper": "func resizedColumnWidth(",
        "global column drag": "resizedColumnWidth(start: start, startX: value.startLocation.x, currentX: value.location.x)",
        "wide column drag target": ".frame(width: 14)",
        "column resize cursor": "NSCursor.resizeLeftRight.push()",
        "full-height resource table": "GeometryReader { proxy in",
        "full-size tab body": ".frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)",
        "details-only right rail": "DetailsRailView",
        "server logs sheet": "ServerLogsSheet",
        "server logs action": "func showServerLogs",
        "server stop reason": "stoppedReason",
        "coordinator server logs": "def server_logs(",
        "docker start action": "func startDocker",
        "exact preferred port model": "preferredPort",
        "server preferred port flag": "\"--preferred\"",
        "structured server argv": "\"--argv\", encodedArgv",
        "docker all inventory": "docker_ps_inventory(*, all_containers: bool = True, state:",
        "docker ps all command": "args.append(\"--all\")",
        "docker stats command": "\"docker\", \"stats\", \"--no-stream\"",
        "docker stats history": "stats_history",
        "docker stats model": "struct DockerStats",
        "docker telemetry sparkline": "MetricSparkCell",
        "docker telemetry panel": "DockerTelemetryPanel",
        "configured auto refresh": "Task.sleep(nanoseconds: intervalNanoseconds)",
        "project runtime command parser": "project_sub = project.add_subparsers",
        "project runtime status": "def project_runtime_status(",
        "project runtime start": "def project_runtime_start(",
        "launch-safe Docker executable resolution": "def resolve_docker_executable(",
        "bounded Docker subprocess execution": "def execute_docker_subprocess(",
        "project Docker capability preflight": "def preflight_project_docker(",
        "safe Compose restart planning": "def compose_restart_service_plan(",
        "minimal-path Docker capability regression": "launchd-minimal PATH without Docker must fail capability preflight",
        "multicall Docker entrypoint regression": "Docker multicall execution must retain argv0=docker",
        "pre-mutation Docker capability regression": "daemon/Compose capability probes must precede every server mutation",
        "bounded Docker timeout regression": "Docker lifecycle timeout must be bounded and structured",
        "Docker-free restart dry-run regression": "restart dry-run should expose one semantic Compose action without Docker",
        "project runtime declaration": "PROJECT_RUNTIME_FILES",
        "project dependency classification": "stopped_container",
        "project runtime skill workflow": "project start --agent \"$USER\" --project \"$PROJECT_ROOT\"",
        "canonical project root workflow": "PROJECT_ROOT=\"$(git rev-parse --show-toplevel 2>/dev/null || pwd)\"",
        "server register command": "server register",
        "server register parser": "server_sub.add_parser(\"register\")",
        "server adoption marker": "\"adopted\": True",
        "missing command marker": "\"missing_command\"",
        "docker register command": "docker register",
        "docker register parser": "docker_sub.add_parser(\"register\")",
        "docker sidecar metadata": "coordinator_sidecar",
        "docker metadata store": "docker_metadata_store",
        "runtime docker metadata adoption": "ensure_runtime_docker_metadata",
        "stale fixed-port lease reclaim": "reclaim_stale_leases_for_port",
        "undeclared compose autostart guard": "\"autostart\": compose_declared",
        "undeclared compose skill policy": "`project start` must not run `docker\ncompose up` from that discovery",
        "docker identity enforcement": "requires --agent so the coordinator can attribute the action",
        "project runtime model": "struct ProjectRuntimeReport",
        "project path grouping": "projectPathForGroup(",
        "project start UI action": "func startProject(_ group",
        "project restart UI action": "func restartProject(_ group",
        "project stop UI action": "func stopProject(_ group",
        "project runtime inspector": "ProjectRuntimeSummary",
        "wrapped inspector details": "fixedSize(horizontal: false, vertical: true)",
        "stacked inspector actions": "InspectorActionStack",
        "shared app store": "@StateObject private var store = OpsStore()",
        "console accepts shared store": "@ObservedObject var store: OpsStore",
        "menu bar status item": "NSStatusBar.system.statusItem",
        "menu bar popover": "NSPopover",
        "menu bar runtime view": "MenuBarRuntimeView",
        "menu bar project rows": "MenuProjectRow",
        "menu bar task rows": "MenuTaskRow",
        "menu bar vertical scroll": "ScrollView(.vertical, showsIndicators: true)",
        "menu bar shared project grouping": "projectGroups(from: store.inventory)",
        "menu bar hoverable actions": "@State private var isHovering = false",
        "menu bar action hit shape": ".contentShape(RoundedRectangle(cornerRadius: 7))",
        "menu bar action hit priority": ".zIndex(20)",
        "menu bar row action cluster": ".fixedSize()",
        "menu bar error details panel": "MenuBarErrorPanel",
        "menu bar copied failure details": "copyLastErrorDetails",
        "menu bar combined source summary": "MenuBarSourceSummary",
        "menu bar retained result": "MenuBarActionResultPanel",
        "menu bar source badges": "MenuSourceBadge",
        "persistent action error details": "lastErrorDetails",
        "command failure detail builder": "commandFailureDetails",
        "shell quoted command details": "func shellCommand(",
        "menu bar error qa mode": "mode == \"error\"",
        "menu snapshot uses production menu": "let view = MenuBarRuntimeView(",
        "menu snapshot disables live inventory": "loadsInventoryOnAppear: false",
        "snapshot renderer source provenance": "SnapshotSourceProvenance",
        "snapshot source hash": "source_sha256",
        "discovered lease recall test": "testDiscoveredInventoryLeaseBecomesManageableWithoutSessionCreation",
        "multi-source selection recall test": "testMultiSourceLeaseHonorsExplicitOriginInsteadOfGuessing",
        "stable editor row regression": "testEditableRowsKeepStableIdentityAcrossValueChangesAndRemoval",
        "incomplete action argument regression": "testVisibleActionGatesRejectIncompleteResourceArguments",
        "bound lease action regression": "testBoundLeaseCannotBeStartedAgainOrReleasedDirectly",
        "scoped lease reconciliation regression": "testScopedRefreshDoesNotMisclassifyOtherProjectLeaseAsReleased",
        "lease draft reset regression": "testGenericStartClearsEveryLeaseDerivedPortField",
        "cross-action conflict regression": "testConflictingMutationsAreBlockedAcrossKindsAndDatabaseContainerIdentity",
        "source selection rebinding regression": "testSourceSelectionsRebindToCurrentOriginValues",
        "retained lease rebinding regression": "testRetainedLeaseRebindsToCurrentSourcePresentation",
        "action request source provenance": "let origin: CoordinatorOrigin?",
        "action issue result binding": "relatedActionID",
        "menu current action issue priority": "MenuBarActionIssuePanel",
        "cross-kind action conflict keys": "actionConflictKeys",
        "project-child conflict domain": "projectPathForConflict",
        "start draft conflict identity": "startDraftResourceIdentity",
        "status item app bridge": "StatusBarController.shared.install(store: store)",
        "window accessor bridge": "WindowAccessor",
        "minimize to menu bar": "minimizeToMenuBar",
        "hide window activation policy": "NSApp.setActivationPolicy(.accessory)",
        "restore window activation policy": "NSApp.setActivationPolicy(.regular)",
        "adopted server pid fallback": "os.kill(pid, signal.SIGTERM)",
        "server listener identity": "def server_listener_identity(",
        "listener ownership guard": "listener_belongs_to_project(",
        "stale foreign pid stop guard": "linked server process belongs to a different project",
        "current url marker": "url_is_current",
        "port reuse owner marker": "port_reused_by",
        "strict default http health": "200 <= status < 400",
        "404 health self-test": "HTTP 404 health checks should not be treated as healthy",
        "strict health skill policy": "Default HTTP health accepts 2xx and 3xx responses",
        "foreign adoption self-test": "wrong-project adoption should report stale coordinator metadata",
        "foreign register self-test": "server register should reject a listener owned by another project",
        "stale url reuse self-test": "stopped historical URL should be marked non-current when another project reuses its port",
        "skill listener ownership policy": "listener PID can be attributed to the canonical project root",
        "menu current url action": "openAction: server.currentURL == nil",
        "stopped server cannot stop": "if isStoppedStatus(server.status)",
        "server restart keeps agent": "\"agent\": agent, \"project\": project, \"name\": name, \"release_port\": True",
        "adopted restart self-test": "adopted fixed-port server restart should recover cleanly",
        "coordinator server record dedupe": "def deduplicate_server_records(",
        "server start reuses logical record": "server_id = existing_id or str(uuid.uuid4())",
        "inventory logical server row self-test": "inventory should expose one row per logical server",
        "inventory duplicate URL self-test": "inventory URLs should not duplicate stale logical servers",
        "skill logical server inventory contract": "Inventory must show one current row per logical server identity",
        "swift managed server dedupe": "func deduplicatedManagedServers(",
        "swift xfoilfoam duplicate regression": "project tree should not show duplicate api server rows",
        "coordinator process table": "def read_process_table(",
        "coordinator process tree usage": "def annotate_server_process_usage(",
        "coordinator project usage rollup": "def build_project_usage(",
        "inventory project usage": "\"project_usage\": project_usage",
        "bounded socket http health": "socket.create_connection((parsed.hostname, port), timeout=timeout)",
        "http health timeout classification": "\"classification\": \"timeout\"",
        "project usage model": "struct ProjectUsage",
        "process usage model": "struct ProcessUsage",
        "project load strip": "ProjectUsageStrip",
        "project load hot process": "hotProcessLabel(",
        "multi coordinator origin discovery": "FileSystemCoordinatorOriginDiscovery",
        "coordinator env per inventory": "CODEX_AGENT_COORDINATOR_HOME",
        "process usage self-test": "inventory should expose project usage rollups",
        "hanging health self-test": "hanging HTTP health checks should be bounded",
        "project resource skill contract": "per-server process CPU/RSS",
    }
    haystacks = "\n".join(
        [
            source_text,
            views,
            store,
            models,
            snapshot_main,
            menu_snapshot,
            snapshot_provenance,
            split_sizing,
            core_tests,
            coordinator,
            coordinator_self_test,
            coordinator_skill,
        ]
    )
    missing = [label for label, needle in required.items() if needle not in haystacks]
    if missing:
        raise SystemExit("CodexOpsConsole interaction guardrail failed: " + ", ".join(missing))

    prohibited = {
        "sidebar category rows": "MapCategory",
        "action queue panel": "ACTION QUEUE",
        "recent events panel": "RECENT EVENTS",
        "synthetic recommendation queue": "visibleQueueItems",
        "inspect recommendations": "Inspect ",
        "action item model": "ActionItem",
        "old action rail": "ActionRailView",
        "fake docker restarts column": "\"Restarts\"",
        "fake usage bar": "UsageBar",
        "fake usage seed": "usageSeed",
        "unused group by control": "\"Group by\"",
        "unused group state": "groupBy",
        "legacy shell command server start": "\"--cmd\"",
        "snapshot-only duplicate menu shell": "MenuBarSnapshotRuntimeView",
        "global one-click stop all": "Stop all",
        "legacy stop-all entry point": "func stopAll()",
        "obsolete stop-all button style": "SidebarStopAllButtonStyle",
        "binary connected UI state": "store.connected",
        "raw command text draft": "startDraft.command",
        "boolean backup protection label": "BackupSafetyLabel(hasBackup:",
        "fake traffic-light controls": "WindowDots",
        "index-based command rows": "Array(store.startDraft.arguments.indices)",
        "index-based source rows": "Array(draft.sources.indices)",
        "unattributed lease release": "arguments: [\"port\", \"release\", \"--lease-id\", lease.leaseID]",
    }
    prohibited_haystack = "\n".join([source_text, snapshot_main, menu_snapshot, snapshot_provenance])
    present = [label for label, needle in prohibited.items() if needle in prohibited_haystack]
    if present:
        raise SystemExit("CodexOpsConsole interaction guardrail found prohibited pattern: " + ", ".join(present))

    if not run_macos_app_checks:
        return

    qa_dir = ops_console / ".build" / "qa"
    qa_dir.mkdir(parents=True, exist_ok=True)
    split_test = qa_dir / "SplitSizingTest"
    menu_snapshot = qa_dir / "MenuBarSnapshot"
    run(
        [
            "swiftc",
            "-parse-as-library",
            "-o",
            str(split_test),
            "Sources/CodexOpsConsole/Models.swift",
            "Sources/CodexOpsConsole/OpsStore.swift",
            "Sources/CodexOpsConsole/Views.swift",
            "Tools/SplitSizingTest.swift",
        ],
        cwd=ops_console,
    )
    run([str(split_test)], cwd=ops_console)
    run(
        [
            "swiftc",
            "-parse-as-library",
            "-o",
            str(menu_snapshot),
            "Sources/CodexOpsConsole/Models.swift",
            "Sources/CodexOpsConsole/OpsStore.swift",
            "Sources/CodexOpsConsole/Views.swift",
            "Sources/CodexOpsConsole/MenuBarViews.swift",
            "Tools/SnapshotProvenance.swift",
            "Tools/MenuBarSnapshotMain.swift",
        ],
        cwd=ops_console,
    )


def check_interaction_label_parity() -> None:
    """The interaction checklist labels must live only in the shared harness.

    They are the single source of truth for the UI 'hard reporting gate'. If a
    verifier hardcodes its own copy of the tuple, the gate can silently drift
    between skills, so fail if the canonical constant name appears anywhere but
    the shared harness (root + vendored copies).
    """
    canonical = HARNESS / "verify_common.py"
    text = canonical.read_text(encoding="utf-8")
    labels = [
        "badge-detail",
        "row-hit-target",
        "navigation-cursor",
        "transient-disclosure",
        "disclosure-scrollbar",
        "icon-meaning",
        "stable-expansion-width",
        "hover-copy",
        "status-summary",
        "message-metadata",
    ]
    for label in labels:
        if label not in text:
            raise SystemExit(f"Canonical interaction checklist label missing from verify_common.py: {label}")
    for skill in SKILLS:
        for verifier in (skill / "scripts").glob("verify_*.py"):
            body = verifier.read_text(encoding="utf-8")
            if "INTERACTION_CHECKLIST_LABELS" in body:
                raise SystemExit(
                    f"{verifier} redefines INTERACTION_CHECKLIST_LABELS; import it from full_repo_harness.verify_common instead"
                )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Holy Skills and Codex Ops Console.")
    parser.add_argument(
        "--skip-macos-app",
        action="store_true",
        help=(
            "run all skill and static Board checks but skip Swift compilation, XCTest, "
            "native snapshots, and app packaging; use Build macOS Apps for those checks"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    check_vendor_sync()
    check_interaction_label_parity()
    check_include_glob_exclusions()
    check_ops_console_interaction_guardrails(run_macos_app_checks=not args.skip_macos_app)
    run([sys.executable, str(ROOT / "scripts" / "self_test_manage_skill_links.py")])
    run([sys.executable, str((ROOT / "scripts" / "merge_findings_self_test.py"))])
    run([sys.executable, str(ROOT / "scripts" / "self_test_public_artifact_guard.py")])
    run([sys.executable, str(ROOT / "scripts" / "public_artifact_guard.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_snapshot_artifacts.py")])
    snapshot_arguments = [sys.executable, str(ROOT / "scripts" / "verify_snapshot_artifacts.py")]
    if args.skip_macos_app:
        snapshot_arguments.append("--skip-source-freshness")
    run(snapshot_arguments)
    run(
        [
            sys.executable,
            str(ROOT / "skills" / "postgres-docker-backup" / "scripts" / "p0_regression_test.py"),
        ]
    )
    for skill in SKILLS:
        run([sys.executable, str(skill.relative_to(ROOT) / "scripts" / "self_test.py")])
    run(
        [
            sys.executable,
            "-m",
            "compileall",
            "scripts",
            "full_repo_harness",
            "skills/codex-dev-coordinator/scripts",
            "skills/formal-web-ui-verification/scripts",
            "skills/full-repo-audit/scripts",
            "skills/full-repo-test-coverage-audit/scripts",
            "skills/postgres-docker-backup/scripts",
            "skills/trace-fix-root-causes/scripts",
            "skills/ui-implementation-audit/scripts",
            "skills/user-journey-docs-audit/scripts",
            "apps/CodexOpsConsole/Tools",
        ]
    )
    for skill in SKILLS:
        check_standalone_skill(skill)
    ops_console = ROOT / "apps" / "CodexOpsConsole"
    if ops_console.is_dir():
        # This provenance/tamper suite is deliberately Python-only. Keep it in
        # the safe validation path so stale Swift binaries cannot evade the
        # guardrail merely because the required native plugin is unavailable.
        run([sys.executable, "Tools/self_test_package_app.py"], cwd=ops_console)
    if ops_console.is_dir() and not args.skip_macos_app:
        run(["swift", "build"], cwd=ops_console)
        run(["swift", "test"], cwd=ops_console)
    if args.skip_macos_app:
        print("validation ok (macOS app checks skipped; run them through Build macOS Apps)")
    else:
        print("validation ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
