#!/usr/bin/env python3
"""Repo-level validation for Holy Skills."""

from __future__ import annotations

import hashlib
import json
import re
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
        # Explicit identity so the test does not depend on a machine-global
        # git user.name/user.email being configured.
        git_identity = [
            "-c", "user.name=holyskills-validate",
            "-c", "user.email=validate@holyskills.local",
        ]
        run(["git", "init", "-q"], cwd=repo)
        run(["git", "add", "src/app.py"], cwd=repo)
        run(["git", *git_identity, "commit", "-q", "-m", "init"], cwd=repo)

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
    ops_console = ROOT / "apps" / "DevOpsBoard"
    if not ops_console.is_dir():
        return

    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ops_console / "Sources" / "DevOpsBoard").glob("*.swift"))
    )
    views = (ops_console / "Sources" / "DevOpsBoard" / "Views.swift").read_text(encoding="utf-8")
    store = (ops_console / "Sources" / "DevOpsBoard" / "OpsStore.swift").read_text(encoding="utf-8")
    models = (ops_console / "Sources" / "DevOpsBoard" / "Models.swift").read_text(encoding="utf-8")
    menu_snapshot = (ops_console / "Tools" / "MenuBarSnapshotMain.swift").read_text(encoding="utf-8")
    split_sizing = (ops_console / "Tools" / "SplitSizingTest.swift").read_text(encoding="utf-8")
    # Read (and thereby existence-gate) the window snapshot tool too; it is
    # referenced by Package.swift but not compiled by the swiftc QA step.
    window_snapshot = (ops_console / "Tools" / "SnapshotMain.swift").read_text(encoding="utf-8")
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
        "grouping consumes coordinator membership rows": "func makeProjectGroups(from inventory: Inventory)",
        "usage key membership decoding": "case usageKey = \"usage_key\"",
        "server membership decoding": "case serverIDs = \"server_ids\"",
        "container membership decoding": "case containerNames = \"container_names\"",
        "group identity prefers usage key": "row.usageKey ?? row.project ?? row.projectKey",
        "stray items fallback group": "strayProjectGroupID",
        "membership union across coordinator homes": "seenServerIDs.insert(serverID).inserted",
        "board name-claim divergence must-catch": "grouprepo-db must display under the path-keyed GroupRepo group",
        "board ambiguity divergence must-catch": "must stay out of the repo group whose actions do not touch it",
        "board stray visibility must-catch": "must stay visible in the stray fallback group",
        "resource leaf prefix removal": "resourceDisplayName(",
        "typed sidebar leaves": "enum MapLeafKind",
        "sidebar leaf actions": "SidebarActionButton",
        "safe sidebar footer": "SidebarFooterView",
        "explicit sidebar footer width": "sidebarFooterContentWidth(totalWidth:",
        "sidebar footer geometry": "sidebarFooterContentWidth(totalWidth: proxy.size.width)",
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
        "wide column drag target": ".frame(width: 14)\n                .contentShape(Rectangle())",
        "column resize cursor": "NSCursor.resizeLeftRight.push()",
        "full-height resource table": "let tableWidth = max(totalWidth, proxy.size.width)",
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
        "visibility gated auto refresh": "func setSurfaceVisible(",
        "window visibility drives refresh gating": "store.setSurfaceVisible(.window, visible)",
        "popover visibility drives refresh gating": "store?.setSurfaceVisible(.popover, true)",
        "auto refresh interval": "static let autoRefreshInterval",
        "auto refresh pauses when hidden": "autoRefreshTask?.cancel()",
        "window occlusion tracking": "windowDidChangeOcclusionState",
        "popover visibility tracking": "popoverDidClose",
        "coalesced inventory refresh": "followUpRequested",
        "publish inventory only on change": "guard decoded != inventory else { return }",
        "cached project groups": "@Published private(set) var projectGroups",
        "non-blocking process wait": "process.terminationHandler",
        "bounded subprocess watchdog": "watchdog.cancel()",
        "inventory subprocess timeout": "timeout: .seconds(60)",
        "deterministic failure ordering": "failures.sorted { $0.index < $1.index }",
        "project panel usage-key path fallback": "projectPath(fromUsageKey: name)",
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
        "durable port assignment writer": "def record_port_assignment(",
        "durable port assignment removal is explicit": "def unassign_port(",
        "durable port assignment migration seeding": "def seed_port_assignments(",
        "foreign assigned ports refused with owner named": "is durably assigned to",
        "assignment survival self-test": "assignment must survive server stop and stopped-record pruning",
        "pinned restart self-test": "server start after record pruning must land on the durably assigned port",
        "undeclared compose autostart guard": "\"autostart\": compose_declared",
        "undeclared compose skill policy": "`project start` must not run `docker\ncompose up` from that discovery",
        "docker identity enforcement": "requires --agent so the coordinator can attribute the action",
        "project runtime model": "struct ProjectRuntimeReport",
        "project action path from membership row": "projectPath: row.project",
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
        "menu bar shared project grouping": "store.projectGroups",
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
        "inventory servers deduplicated at load": "decoded.servers = deduplicatedManagedServers(decoded.servers)",
        "swift xfoilfoam duplicate regression": "project tree should not show duplicate api server rows",
        "coordinator process table": "def read_process_table(",
        "coordinator process tree usage": "def annotate_server_process_usage(",
        "coordinator project usage rollup": "def build_project_usage(",
        "inventory project usage": "\"project_usage\": project_usage",
        "unified container membership attribution": "def container_project_attribution(",
        "membership claim set shared by display and actions": "def known_project_paths(",
        "ambiguous container name match stays unclaimed": "\"ambiguous_name\" if claimants else \"unclaimed\"",
        "membership divergence must-catch fixture": "must-catch: unattributed grouprepo-db must display under the path-keyed repo",
        "membership blast radius skill contract": "shows exactly the blast radius",
        "bounded socket http health": "socket.create_connection((parsed.hostname, port), timeout=timeout)",
        # macOS runners black-hole reverse DNS: a stock HTTPServer.server_bind
        # stalls ~30s in socket.getfqdn between bind() and listen(). The API
        # server must bind without name resolution, and serve_api must use it.
        "coordinator api server skips getfqdn": "socketserver.TCPServer.server_bind(self)",
        "coordinator api server fast-bind use": "server = FastBindThreadingHTTPServer((host, port), ApiHandler)",
        "http health timeout classification": "\"classification\": \"timeout\"",
        "project usage model": "struct ProjectUsage",
        "process usage model": "struct ProcessUsage",
        "project load strip": "ProjectUsageStrip",
        "project load hot process": "hotProcessLabel(",
        "multi coordinator home discovery": "discoveredCoordinatorHomes",
        "coordinator env per inventory": "CODEX_AGENT_COORDINATOR_HOME",
        "process usage self-test": "inventory should expose project usage rollups",
        "hanging health self-test": "hanging HTTP health checks should be bounded",
        "project resource skill contract": "per-server process CPU/RSS",
    }
    haystacks = "\n".join([source_text, views, store, models, menu_snapshot, split_sizing, window_snapshot, coordinator, coordinator_self_test, coordinator_skill])
    missing = [label for label, needle in required.items() if needle not in haystacks]
    if missing:
        raise SystemExit("DevOpsBoard interaction guardrail failed: " + ", ".join(missing))

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
        # Grouping is consumed from coordinator project_usage membership; any
        # client-side re-derivation of repo identity from resource names is
        # the display/action divergence class fixed on 2026-07-07.
        "client-side name-key grouping heuristic": "projectKey(fromResourceName",
        "client-side project path guessing": "projectPathForGroup(",
    }
    present = [label for label, needle in prohibited.items() if needle in haystacks]
    if present:
        raise SystemExit("DevOpsBoard interaction guardrail found prohibited pattern: " + ", ".join(present))

    if shutil.which("swiftc") is None:
        print("skipping DevOpsBoard swiftc QA tools (no Swift toolchain on this host)")
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
            "Sources/DevOpsBoard/Models.swift",
            "Sources/DevOpsBoard/OpsStore.swift",
            "Sources/DevOpsBoard/Views.swift",
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
            "Sources/DevOpsBoard/Models.swift",
            "Sources/DevOpsBoard/OpsStore.swift",
            "Sources/DevOpsBoard/Views.swift",
            "Sources/DevOpsBoard/MenuBarViews.swift",
            "Tools/MenuBarSnapshotMain.swift",
        ],
        cwd=ops_console,
    )


def check_devops_console() -> None:
    """Deterministic guardrails for the DevOpsConsole web app (apps/DevOpsConsole).

    Text anchors are tied to the security invariants in the app's
    docs/architecture.md; removing any of them is a policy regression, not a
    refactor. Also enforces the zero-third-party-dependency rule and runs the
    app's full node:test suite.
    """
    console = ROOT / "apps" / "DevOpsConsole"
    if not console.is_dir():
        return

    src_files = sorted((console / "src").rglob("*.mjs")) + sorted((console / "bin").glob("*.mjs"))
    source_text = "\n".join(path.read_text(encoding="utf-8") for path in src_files)
    app_js = (console / "src" / "ui" / "app.js").read_text(encoding="utf-8")
    app_css = (console / "src" / "ui" / "app.css").read_text(encoding="utf-8")
    index_html = (console / "src" / "ui" / "index.html").read_text(encoding="utf-8")
    # The CI-critical TLS fixture generator lives under test/, which is
    # otherwise outside the needle haystack; read it explicitly so both its
    # deletion and its generation contract are gated.
    dev_cert_helper = (console / "test" / "helpers" / "dev-cert.mjs").read_text(encoding="utf-8")
    package_json = json.loads((console / "package.json").read_text(encoding="utf-8"))

    required = {
        "routes default to login-required": "def.auth === undefined || def.auth === null ? 'google'",
        "timing-safe session compare": "crypto.timingSafeEqual(given, expected)",
        "proxy pinned to loopback": "const LOOPBACK = '127.0.0.1'",
        "hop-by-hop header stripping": "HOP_BY_HOP",
        "oidc nonce enforcement": "id_token nonce mismatch",
        "oidc verified-email enforcement": "payload.email_verified !== true",
        "csrf origin check on mutations": "mutating && !guard.checkOrigin(req)",
        # Pin the guarding CODE, not its comment: inverting this line makes
        # unknown slugs enumerable while the comment would survive.
        "no slug enumeration for anonymous users": "const needAuth = !route || route.auth !== 'public';",
        "segmented-control overlap allowance annotated": "data-ui-allow-overlap",
        "coordinator caches invalidated on mutations": "if (isMutation(method, apiPath)) invalidateCaches();",
        "metrics ring buffer bounded": "points.splice(0, points.length - maxPoints)",
        "metrics project series keyed by unique usage_key": "row?.usage_key ?? row?.project_key",
        "port release requires explicit lease id": "requireString(body.lease_id, 'lease_id')",
        "pinned ports card rendered from inventory": "function buildAssignments(",
        "pinned ports card wired into render loop": "setSection('assignments-body'",
        "pin removal confirmed in UI": "Unassign port ${a.port} from server",
        "whole-project runtime control endpoint": "'/api/projects/action'",
        "ui prefs persisted server-side": "ui-prefs.json",
        "hidden items auto-reveal when running": "async function autoUnhide(",
        "hidden items auto-reveal wired into overview refresh": "autoUnhide(data);",
        "project grouping uses coordinator membership": "function projectGroupsOf(",
        "hamburger nav aria wiring": 'aria-controls="site-nav"',
        "charts built without innerHTML": "document.createElementNS(SVG_NS",
        "fast close clears drain timers": "clearTimeout(killTimer)",
        "test TLS fixture generated on demand": "execFileSync('openssl', [",
        # Docker-hosted web servers (v1.4.0): published-port parsing feeds
        # both the docker route resolver and the Servers-page rows; the
        # resolver must keep screening against the coordinator API port.
        "docker published-port parser": "export function parsePublishedPorts(",
        "docker route resolves published host port": "publishedHostPort(parsePublishedPorts(found.ports), route.containerPort)",
        "docker route resolution guards coordinator port": "guardCoordinatorPort(hostPort, { container })",
        "docker subdomain endpoint": "'/api/docker/subdomain'",
        "docker subdomain demands one published port": "pass \"port\" to choose one",
        "servers page lists docker web servers": "visible.push(dockerServerItem(o, c, isHidden));",
        "docker server rows detected by published ports or route": "function isWebServerContainer(",
        "docker server row actions hit docker endpoint": "'data-fk': `srv-dock-${action}:${name}`",
        # Stable ordering contract (docs/journeys.md): list order never keys
        # on live metrics, or every poll reshuffles the page under the user.
        "stable project-group comparator": "function projectGroupOrder(",
        "project groups sorted through the stable comparator": "groups.sort(projectGroupOrder)",
        # Single-row header: no status sentence, one needs-attention badge
        # whose popover carries facts, instructions and actions per problem.
        "header problems collector": "function headerProblems(",
        "header alert badge wired": "'data-fk': 'hdr-alert'",
        # Projects tree: identical Start/Restart/Stop slots on every row so
        # action buttons align into columns; colors carry meaning.
        "uniform tree action slots": "function treeActionSlots(",
        "action color code map": "const ACTION_CLS = { start: 'act-start', restart: 'act-restart', stop: 'act-stop' };",
        # Whole-machine health (v1.6.0): host probe sampled independently of
        # coordinator health, exposed via metrics history, rendered on the
        # Performance page.
        "host probe with injectable readers": "export function createHostProbe(",
        "host sampled before coordinator inventory": "await sampleHost();",
        "host snapshot in metrics history": "host: hostNow,",
        "performance page machine panel": "function hostPanel(",
    }
    haystack = "\n".join([source_text, app_js, app_css, index_html, dev_cert_helper])
    missing = [label for label, needle in required.items() if needle not in haystack]
    if missing:
        raise SystemExit("DevOpsConsole guardrail failed: " + ", ".join(missing))

    for banned in ("TODO", "FIXME", "wired later"):
        if banned in source_text or banned in app_js or banned in app_css or banned in index_html:
            raise SystemExit(f"DevOpsConsole guardrail found prohibited marker: {banned}")

    # Live CPU/memory readings must never be a list ordering key — that
    # class reshuffled the Servers page on every poll (2026-07-07 incident;
    # see test/unit.uiorder.test.mjs for the behavioral guardrail).
    ui_prohibited = {
        "group order keyed on live cpu": "cpu_percent || 0) - (a",
        "performance cards ordered by current load": "lastCpu(b) - lastCpu(a)",
    }
    ui_present = [label for label, needle in ui_prohibited.items() if needle in app_js]
    if ui_present:
        raise SystemExit("DevOpsConsole guardrail found prohibited pattern: " + ", ".join(ui_present))

    if package_json.get("dependencies") or package_json.get("devDependencies"):
        raise SystemExit("DevOpsConsole must stay zero-dependency; package.json declares dependencies")

    import_pattern = re.compile(r"""(?:import\s[^'\"]*?from\s*|import\(|require\()\s*['\"]([^'\"]+)['\"]""")
    for path in src_files:
        for spec in import_pattern.findall(path.read_text(encoding="utf-8")):
            if not spec.startswith(("node:", ".", "file:")):
                raise SystemExit(f"DevOpsConsole {path.relative_to(console)} imports a non-stdlib module: {spec}")

    innerhtml_assignments = re.findall(r"\.innerHTML\s*=", app_js)
    if len(innerhtml_assignments) != 1 or "span.innerHTML = ICONS[name] || ''" not in app_js:
        raise SystemExit("DevOpsConsole app.js may assign innerHTML only for the static ICONS map")

    for path in [*src_files, console / "src" / "ui" / "app.js"]:
        run(["node", "--check", str(path)])
    run(["node", "--test", "test/"], cwd=console)


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


def main() -> int:
    check_vendor_sync()
    check_interaction_label_parity()
    check_include_glob_exclusions()
    check_ops_console_interaction_guardrails()
    check_devops_console()
    run([sys.executable, str((ROOT / "scripts" / "merge_findings_self_test.py"))])
    for skill in SKILLS:
        run([sys.executable, str(skill.relative_to(ROOT) / "scripts" / "self_test.py")])
    run(
        [
            sys.executable,
            "-m",
            "compileall",
            "full_repo_harness",
            "skills/codex-dev-coordinator/scripts",
            "skills/formal-web-ui-verification/scripts",
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
    ops_console = ROOT / "apps" / "DevOpsBoard"
    if ops_console.is_dir():
        if shutil.which("swift"):
            run(["swift", "build"], cwd=ops_console)
        else:
            print("skipping DevOpsBoard swift build (no Swift toolchain on this host)")
    print("validation ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
