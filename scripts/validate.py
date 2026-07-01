#!/usr/bin/env python3
"""Repo-level validation for Holy Skills."""

from __future__ import annotations

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
        run(["git", "commit", "-q", "-m", "init"], cwd=repo)

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


def check_ops_console_interaction_guardrails() -> None:
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
    menu_snapshot = (ops_console / "Tools" / "MenuBarSnapshotMain.swift").read_text(encoding="utf-8")
    split_sizing = (ops_console / "Tools" / "SplitSizingTest.swift").read_text(encoding="utf-8")
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
        "sidebar stop all constrained frame": ".frame(maxWidth: .infinity, minHeight: 30)",
        "sidebar footer icon fixed frame": ".frame(width: 24, height: 24)",
        "server sidebar toggle": "func toggle(_ server",
        "docker sidebar toggle": "func toggleDocker",
        "stop all action": "func stopAll()",
        "stop all button": "Stop all",
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
        "docker all inventory": "docker_ps_inventory(*, all_containers: bool = True, state:",
        "docker ps all command": "args.append(\"--all\")",
        "docker stats command": "\"docker\", \"stats\", \"--no-stream\"",
        "docker stats history": "stats_history",
        "docker stats model": "struct DockerStats",
        "docker telemetry sparkline": "MetricSparkCell",
        "docker telemetry panel": "DockerTelemetryPanel",
        "docker auto refresh": "Task.sleep(nanoseconds: 2_500_000_000)",
        "project runtime command parser": "project_sub = project.add_subparsers",
        "project runtime status": "def project_runtime_status(",
        "project runtime start": "def project_runtime_start(",
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
        "persistent action error details": "lastErrorDetails",
        "command failure detail builder": "commandFailureDetails",
        "shell quoted command details": "func shellCommand(",
        "menu bar error qa mode": "mode == \"error\"",
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
        "strict default http health": "200 <= response.status < 400",
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
    }
    haystacks = "\n".join([source_text, views, store, models, menu_snapshot, split_sizing, coordinator, coordinator_self_test, coordinator_skill])
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
    }
    present = [label for label, needle in prohibited.items() if needle in haystacks]
    if present:
        raise SystemExit("CodexOpsConsole interaction guardrail found prohibited pattern: " + ", ".join(present))

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
            "Tools/MenuBarSnapshotMain.swift",
        ],
        cwd=ops_console,
    )


def main() -> int:
    check_vendor_sync()
    check_include_glob_exclusions()
    check_ops_console_interaction_guardrails()
    for skill in SKILLS:
        run([sys.executable, str(skill.relative_to(ROOT) / "scripts" / "self_test.py")])
    run(
        [
            sys.executable,
            "-m",
            "compileall",
            "full_repo_harness",
            "skills/codex-dev-coordinator/scripts",
            "skills/full-repo-audit/scripts",
            "skills/full-repo-test-coverage-audit/scripts",
            "skills/postgres-docker-backup/scripts",
            "skills/trace-fix-root-causes/scripts",
            "skills/ui-implementation-audit/scripts",
            "skills/user-journey-docs-audit/scripts",
        ]
    )
    for skill in SKILLS:
        check_standalone_skill(skill)
    ops_console = ROOT / "apps" / "CodexOpsConsole"
    if ops_console.is_dir():
        run(["swift", "build"], cwd=ops_console)
    print("validation ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
