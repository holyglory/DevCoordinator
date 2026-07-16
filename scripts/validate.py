#!/usr/bin/env python3
"""Validate the independent DevCoordinator repository."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS = [
    ROOT / "skills" / "codex-dev-coordinator",
    ROOT / "skills" / "postgres-docker-backup",
]

DECISION_ENTRY_HEADER = re.compile(r"^## (DC-[A-Z0-9-]+) — ([^\n]+)$", re.MULTILINE)
DECISION_METADATA = re.compile(
    r"^ID: (DC-[A-Z0-9-]+) · Details: "
    r"\[supporting record\]\(DecisionDetails/(DC-[A-Z0-9-]+)\.md\)$"
)
DECISION_INDEX_BOILERPLATE = (
    "the selected contract replaces the earlier behavior documented in the linked record",
    "that record retains the concrete failure",
)


def duplicate_literal_dict_key_errors(source: str, *, label: str) -> list[str]:
    """Find duplicate literal keys that Python would silently overwrite."""

    errors: list[str] = []
    for node in ast.walk(ast.parse(source, filename=label)):
        if not isinstance(node, ast.Dict):
            continue
        seen: dict[tuple[type[object], object], int] = {}
        for key in node.keys:
            if not isinstance(key, ast.Constant):
                continue
            value = key.value
            try:
                hash(value)
            except TypeError:
                continue
            identity = (type(value), value)
            prior = seen.get(identity)
            if prior is not None:
                errors.append(
                    f"{label}:{key.lineno}: duplicate literal dictionary key "
                    f"{value!r} (first declared at line {prior})"
                )
            else:
                seen[identity] = int(key.lineno)
    return errors


def check_duplicate_literal_dict_keys() -> None:
    good = "value = {'starts_resources': False, dynamic: 1, other: 2}\n"
    bad = "value = {'starts_resources': False, 'starts_resources': False}\n"
    if duplicate_literal_dict_key_errors(good, label="good.py"):
        raise SystemExit("duplicate-dict-key detector rejected its false-positive control")
    if not duplicate_literal_dict_key_errors(bad, label="bad.py"):
        raise SystemExit("duplicate-dict-key detector missed a realistic overwritten key")
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        errors.extend(
            duplicate_literal_dict_key_errors(
                path.read_text(encoding="utf-8"),
                label=str(path.relative_to(ROOT)),
            )
        )
    if errors:
        raise SystemExit("duplicate literal dictionary keys:\n" + "\n".join(errors))


def decision_history_contract_errors(history: str, detail_names: set[str]) -> list[str]:
    """Return dense-index contract violations without reading implementation evidence.

    DecisionHistory is intentionally small enough for routine context. Detailed
    evidence belongs in one matching DecisionDetails file, so the index format
    is deliberately strict and mechanically checkable.
    """

    errors: list[str] = []
    if history.count("# Decision History") != 1:
        errors.append("history must contain exactly one top-level Decision History heading")
    if history.count("## Direction") != 1:
        errors.append("history must contain exactly one Direction synthesis")

    matches = list(DECISION_ENTRY_HEADER.finditer(history))
    if not matches:
        errors.append("history must contain at least one stable decision entry")
        return errors

    direction_offset = history.find("## Direction")
    direction_cited_ids: set[str] = set()
    if direction_offset < 0 or direction_offset > matches[0].start():
        errors.append("Direction must precede every decision entry")
    else:
        direction = history[direction_offset + len("## Direction") : matches[0].start()].strip()
        if not direction:
            errors.append("Direction synthesis must not be empty")
        if "Confirmed" not in direction:
            errors.append("Direction must distinguish confirmed user intent")
        direction_cited_ids = set(
            re.findall(r"DecisionDetails/(DC-[A-Z0-9-]+)\.md", direction)
        )
        if not direction_cited_ids:
            errors.append("Direction must cite supporting decision IDs")

    indexed_ids: list[str] = []
    for index, match in enumerate(matches):
        decision_id = match.group(1)
        indexed_ids.append(decision_id)
        end = matches[index + 1].start() if index + 1 < len(matches) else len(history)
        block = history[match.start() : end].strip()
        lines = block.splitlines()
        nonblank = [line for line in lines if line.strip()]
        if len(nonblank) != 4:
            errors.append(
                f"{decision_id} must contain only its heading, metadata, Decision, and Why"
            )
            continue

        metadata_match = DECISION_METADATA.fullmatch(nonblank[1])
        if metadata_match is None:
            errors.append(f"{decision_id} metadata/link does not match the stable ID")
        elif metadata_match.group(1) != decision_id or metadata_match.group(2) != decision_id:
            errors.append(f"{decision_id} metadata/link points at another decision")

        decision_line, why_line = nonblank[2], nonblank[3]
        if not decision_line.startswith("Decision: ") or len(decision_line) <= len("Decision: "):
            errors.append(f"{decision_id} must have one non-empty Decision line")
        if not why_line.startswith("Why: ") or len(why_line) <= len("Why: "):
            errors.append(f"{decision_id} must have one non-empty Why line")
        for label, line in (("Decision", decision_line), ("Why", why_line)):
            lowered = line.lower()
            if "…" in line or "..." in line:
                errors.append(f"{decision_id} {label} is truncated with an ellipsis")
            if f"{label.lower()}: {label.lower()}:" in lowered:
                errors.append(f"{decision_id} repeats its {label} label")
            if any(boilerplate in lowered for boilerplate in DECISION_INDEX_BOILERPLATE):
                errors.append(f"{decision_id} uses generic detail-file boilerplate")
            if len(line) > 1_000:
                errors.append(f"{decision_id} {label} is not a concise index summary")

    duplicate_ids = sorted({item for item in indexed_ids if indexed_ids.count(item) > 1})
    if duplicate_ids:
        errors.append("duplicate decision IDs: " + ", ".join(duplicate_ids))

    indexed = set(indexed_ids)
    unknown_direction_citations = sorted(direction_cited_ids - indexed)
    if unknown_direction_citations:
        errors.append(
            "Direction cites unknown decision IDs: "
            + ", ".join(unknown_direction_citations)
        )
    missing_details = sorted(indexed - detail_names)
    unindexed_details = sorted(detail_names - indexed)
    if missing_details:
        errors.append("decision entries without detail files: " + ", ".join(missing_details))
    if unindexed_details:
        errors.append("detail files without decision entries: " + ", ".join(unindexed_details))
    return errors


def check_decision_history_contract() -> None:
    """Prove the index detector's recall/precision, then validate real records."""

    good = """# Decision History

## Direction

Confirmed user intent keeps one authority; see [DC-TEST-01](DecisionDetails/DC-TEST-01.md).

## DC-TEST-01 — One authority

ID: DC-TEST-01 · Details: [supporting record](DecisionDetails/DC-TEST-01.md)

Decision: Keep one canonical authority.

Why: Separate writable stores can disagree; one authority preserves identity.
"""
    good_details = {"DC-TEST-01"}
    if decision_history_contract_errors(good, good_details):
        raise SystemExit("DecisionHistory false-positive control is invalid")

    must_catch = {
        "missing Why": good.replace(
            "\nWhy: Separate writable stores can disagree; one authority preserves identity.\n",
            "\n",
        ),
        "wrong detail link": good.replace("DecisionDetails/DC-TEST-01.md", "DecisionDetails/DC-WRONG.md", 1),
        "extra evidence in index": good.replace(
            "\nWhy: Separate writable stores can disagree; one authority preserves identity.\n",
            "\nWhy: Separate writable stores can disagree; one authority preserves identity.\n\nEvidence: log\n",
        ),
        "truncated summary": good.replace("canonical authority.", "canonical authority…"),
        "generic boilerplate": good.replace(
            "Keep one canonical authority.",
            "The selected contract replaces the earlier behavior documented in the linked record.",
        ),
        "repeated label": good.replace(
            "Decision: Keep one canonical authority.",
            "Decision: Decision: Keep one canonical authority.",
        ),
    }
    for label, broken in must_catch.items():
        if not decision_history_contract_errors(broken, good_details):
            raise SystemExit(f"DecisionHistory detector missed must-catch fixture: {label}")
    if not decision_history_contract_errors(good, {"DC-TEST-01", "DC-ORPHAN"}):
        raise SystemExit("DecisionHistory detector missed an unindexed detail file")

    history_path = ROOT / "DecisionHistory.md"
    detail_dir = ROOT / "DecisionDetails"
    detail_names = {path.stem for path in detail_dir.glob("DC-*.md") if path.is_file()}
    errors = decision_history_contract_errors(
        history_path.read_text(encoding="utf-8"),
        detail_names,
    )
    if errors:
        raise SystemExit("DecisionHistory contract failed:\n- " + "\n- ".join(errors))


def run(
    args: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=cwd, env=env, check=True)


def source_region(source: str, start: str, end: str) -> str:
    start_index = source.find(start)
    end_index = source.find(end, start_index + len(start))
    if start_index < 0 or end_index <= start_index:
        raise SystemExit(f"DevOpsBoard geometry guard could not locate {start!r} through {end!r}")
    return source[start_index:end_index]


def check_devops_board_center_pane_geometry(
    views: str,
    split_sizing: str,
    vertical_layout_tests: str,
) -> None:
    """Keep intrinsic children from widening or vertically center-cropping the main pane.

    The reported window was 1180 points wide with a user-resized 380-point
    sidebar and the 320-point inspector. That leaves a 464-point main pane,
    rather than the 524 points produced by the default-sidebar fixture. The
    executable sizing check carries both that must-catch geometry and a wider
    control where the same preferred maxima legitimately fit. The vertical
    fixture models the dense six-project, 19-server, attention, and Activity
    state that used to exceed the minimum window height and become centered
    inside the exact-height pane before clipping.
    """

    split_width = 8
    narrow_main_width = 1180 - 380 - split_width - 320 - split_width
    narrow_body_width = narrow_main_width - 28
    narrow_toolbar_width = narrow_main_width - 24
    wide_main_width = 1440 - 380 - split_width - 320 - split_width
    wide_body_width = wide_main_width - 28
    wide_toolbar_width = wide_main_width - 24
    legacy_compact_toolbar = 132 + 120 + 88 + (3 * 32) + (5 * 6)
    adaptive_narrow_toolbar = 108 + 72 + 44 + (3 * 32) + (5 * 6)
    normal_filter = 32 + 220 + 78 + (3 * 12)
    bulk_filter = normal_filter + 64 + 108 + (2 * 12)
    legacy_empty_state = 28 + 250 + 148 + (3 * 12)
    geometry_recall = {
        "fixed 520-point tabs overflow the real narrow fixture": 520 > narrow_body_width,
        "legacy compact toolbar overflows the real narrow fixture": (
            legacy_compact_toolbar > narrow_toolbar_width
        ),
        "adaptive narrow toolbar fits the real narrow fixture": (
            adaptive_narrow_toolbar <= narrow_toolbar_width
        ),
        "ordinary filters fit the real narrow fixture": normal_filter <= narrow_body_width,
        "bulk filters require an adaptive row": bulk_filter > narrow_body_width,
        "legacy empty-state actions require an adaptive row": legacy_empty_state > narrow_body_width,
        "520-point tab maximum is valid at wider width": 520 <= wide_body_width,
        "legacy compact-toolbar footprint is valid at wider width": (
            legacy_compact_toolbar <= wide_toolbar_width
        ),
    }
    broken_geometry_checks = [label for label, condition in geometry_recall.items() if not condition]
    if broken_geometry_checks:
        raise SystemExit(
            "DevOpsBoard center-pane geometry recall/control fixture is invalid: "
            + ", ".join(broken_geometry_checks)
        )

    minimum_window_height = 760
    fixed_toolbar_height = 54
    toolbar_divider_height = 1
    activity_height = 34
    status_divider_height = 1
    status_height = 38
    variable_body_viewport = minimum_window_height - (
        fixed_toolbar_height
        + toolbar_divider_height
        + activity_height
        + status_divider_height
        + status_height
    )
    dense_variable_body_minimum = (
        28  # body padding
        + 62  # attention banner
        + 19
        + (6 * 34)  # project-load heading and six rows
        + 32  # filters
        + 28  # resource tabs
        + 30
        + 340  # resource heading and table minimum
        + (4 * 12)  # inter-section spacing
    )
    sparse_variable_body_control = (
        28
        + 19
        + 34  # one project-load row, without an attention banner
        + 32
        + 28
        + 30
        + 340
        + (3 * 12)
    )
    legacy_dense_intrinsic_height = (
        fixed_toolbar_height
        + toolbar_divider_height
        + dense_variable_body_minimum
        + activity_height
        + status_divider_height
        + status_height
    )
    vertical_geometry_recall = {
        "dense variable body exceeds its minimum-window viewport": (
            dense_variable_body_minimum > variable_body_viewport
        ),
        "legacy dense intrinsic pane exceeds the minimum window": (
            legacy_dense_intrinsic_height > minimum_window_height
        ),
        "centered legacy pane crops a fixed edge by more than the realistic shift": (
            (legacy_dense_intrinsic_height - minimum_window_height) / 2 > 48
        ),
        "sparse body remains a false-positive control": (
            sparse_variable_body_control <= variable_body_viewport
        ),
        "fixed chrome leaves a usable resource viewport": variable_body_viewport >= 340,
    }
    broken_vertical_checks = [
        label for label, condition in vertical_geometry_recall.items() if not condition
    ]
    if broken_vertical_checks:
        raise SystemExit(
            "DevOpsBoard vertical center-crop recall/control fixture is invalid: "
            + ", ".join(broken_vertical_checks)
        )

    sizing_contract = {
        "real 1180-point center-pane fixture": (
            "consoleLayout(totalWidth: 1180, sidebarPreference: 380, inspectorPreference: 320)"
        ),
        "fixed-tab overflow must-catch": (
            "guard must catch the legacy fixed resource tabs that widened and cropped the 1180-point main pane"
        ),
        "compact-toolbar overflow must-catch": (
            "guard must catch the compact toolbar action cluster clipped in the reported 1180-point window"
        ),
        "bulk-filter overflow must-catch": (
            "guard must keep the bulk-selection filter row on an adaptive layout path"
        ),
        "wider-layout false-positive control": (
            "consoleLayout(totalWidth: 1440, sidebarPreference: 380, inspectorPreference: 320)"
        ),
    }
    missing_sizing = [label for label, needle in sizing_contract.items() if needle not in split_sizing]
    if missing_sizing:
        raise SystemExit(
            "DevOpsBoard center-pane geometry guard is missing realistic coverage: "
            + ", ".join(missing_sizing)
        )

    resource_tabs = source_region(views, "struct ResourceTabBar: View", "struct ToolbarView: View")
    toolbar = source_region(views, "struct ToolbarView: View", "struct FilterRow: View")
    filters = source_region(views, "struct FilterRow: View", "struct SourceHealthChip: View")
    empty_state = source_region(views, "struct DevServersEmptyState: View", "struct ResourceEmptyState: View")

    if ".frame(width: 520" in resource_tabs:
        raise SystemExit(
            "DevOpsBoard center-pane geometry guard caught the 520-point fixed ResourceTabBar regression"
        )
    if ".frame(minWidth: 280, maxWidth: 520" not in resource_tabs:
        raise SystemExit("DevOpsBoard ResourceTabBar must retain its bounded flexible width")

    if ".frame(width: 360" in filters:
        raise SystemExit("DevOpsBoard center-pane geometry guard caught the fixed-width FilterRow regression")
    if ".frame(minWidth: 220, maxWidth: 360" not in filters:
        raise SystemExit("DevOpsBoard FilterRow picker must retain its bounded flexible width")
    if "ViewThatFits(in: .horizontal)" not in filters:
        raise SystemExit(
            "DevOpsBoard FilterRow must retain an adaptive bulk-selection layout at the 1180-point fixture"
        )

    adaptive_toolbar_contract = [
        "if proxy.size.width < 520",
        "narrowToolbar",
        ".frame(width: 108)",
        ".frame(minWidth: 72, maxWidth: .infinity)",
        "SourceHealthChip(store: store, compact: true, minimal: true)",
    ]
    has_adaptive_toolbar = (
        "ViewThatFits(in: .horizontal)" in toolbar
        or all(needle in toolbar for needle in adaptive_toolbar_contract)
    )
    if not has_adaptive_toolbar:
        raise SystemExit(
            "DevOpsBoard compact toolbar must retain an adaptive fallback for the reported 1180-point fixture"
        )

    if "ViewThatFits(in: .horizontal)" not in empty_state:
        raise SystemExit(
            "DevOpsBoard dev-server empty state must retain its adaptive action layout at narrow pane widths"
        )

    ops_console = source_region(views, "struct OpsConsoleView: View", "struct SplitHandle: View")
    main_board = source_region(views, "struct MainBoardView: View", "struct ProjectUsageStrip: View")

    if "HStack(alignment: .top, spacing: 0)" not in ops_console:
        raise SystemExit(
            "DevOpsBoard split shell must lay out panes consecutively from the top; "
            "the absolute-positioned clipped ZStack can crop only the middle pane"
        )
    if ".position(" in ops_console:
        raise SystemExit(
            "DevOpsBoard split shell must not absolutely position pane contents inside its clipped frame"
        )

    exact_pane_frame = re.search(
        r"MainBoardView\(store: store\)\s*"
        r"\.frame\(\s*"
        r"width: layout\.mainWidth,\s*"
        r"height: proxy\.size\.height,\s*"
        r"alignment: \.topLeading\s*"
        r"\)",
        ops_console,
    )
    if exact_pane_frame is None:
        raise SystemExit(
            "DevOpsBoard MainBoardView must retain its exact width/height frame with "
            "top-leading alignment to prevent vertical center-cropping"
        )

    scroll_start = main_board.find("ScrollView(.vertical)")
    scroll_body_end = main_board.find('.accessibilityIdentifier("main-board-scroll-body")')
    toolbar_index = main_board.find("ToolbarView(store: store)")
    activity_index = main_board.find("ActionResultDrawer(")
    status_index = main_board.find("StatusBar(store: store)")
    fixed_chrome_order = [toolbar_index, scroll_start, scroll_body_end, activity_index, status_index]
    if any(index < 0 for index in fixed_chrome_order) or fixed_chrome_order != sorted(fixed_chrome_order):
        raise SystemExit(
            "DevOpsBoard MainBoardView must keep the toolbar before, and Activity/status after, "
            "the variable-body vertical ScrollView"
        )

    variable_body = main_board[scroll_start:scroll_body_end]
    variable_body_contract = {
        "inventory attention banner": "InventoryStateBanner(",
        "project-load rows": "ProjectUsageStrip(store: store)",
        "managed leases": "ManagedLeasesPanel(store: store)",
        "filters": "FilterRow(",
        "resource tabs": "ResourceTabBar(store: store)",
        "active resource section": "switch store.activeTab",
    }
    missing_variable_body = [
        label for label, needle in variable_body_contract.items() if needle not in variable_body
    ]
    if missing_variable_body:
        raise SystemExit(
            "DevOpsBoard variable-body ScrollView is missing vertically scrollable content: "
            + ", ".join(missing_variable_body)
        )

    fixed_chrome_contract = {
        "toolbar anchor": '.accessibilityIdentifier("main-board-toolbar")',
        "scroll-body anchor": '.accessibilityIdentifier("main-board-scroll-body")',
        "status anchor": '.accessibilityIdentifier("main-board-status")',
    }
    missing_fixed_chrome = [
        label for label, needle in fixed_chrome_contract.items() if needle not in views
    ]
    if missing_fixed_chrome:
        raise SystemExit(
            "DevOpsBoard vertical crop detector is missing stable production anchors: "
            + ", ".join(missing_fixed_chrome)
        )

    full_shell_test_contract = {
        "full three-pane production render": (
            "testFullThreePaneMinimumWindowKeepsTheMiddlePaneEdgesAndPrimaryContentVisible"
        ),
        "real split shell renderer": "renderOpsConsole(",
        "middle-pane extraction": "raster.cropped(",
        "fixed-edge assertion": "assessment.hasBothFixedEdges",
        "primary-content assertion": "assessment.bodyHasVisibleContent",
    }
    missing_full_shell_checks = [
        label
        for label, needle in full_shell_test_contract.items()
        if needle not in vertical_layout_tests
    ]
    if missing_full_shell_checks:
        raise SystemExit(
            "DevOpsBoard crop detector must exercise the real three-pane shell, not only MainBoardView: "
            + ", ".join(missing_full_shell_checks)
        )

    vertical_xctest_contract = {
        "native SwiftUI/AppKit raster test": "NSHostingView(rootView: view)",
        "minimum 760-point window": "private let minimumWindowHeight = 760",
        "dense six-repository assertion": (
            "XCTAssertEqual(fixture.store.projectGroups.filter(\\.isRepository).count, 6)"
        ),
        "dense unassigned false-positive guard": (
            "XCTAssertFalse(fixture.store.projectGroups.contains { !$0.isRepository })"
        ),
        "dense 19-server assertion": "XCTAssertEqual(fixture.store.filteredServers.count, 19)",
        "attention-state assertion": "XCTAssertNotNil(fixture.store.actionIssue)",
        "Activity-state assertion": "XCTAssertEqual(fixture.store.actionResults.count, 1)",
        "fixed-edge production assertion": "assessment.statusIsVisible",
        "center-only upward-crop must-catch": "testDetectorCatchesRealisticCenterOnlyUpwardCrop",
        "realistic 48-point shift": "intact.shiftedUp(by: 48)",
        "must-catch failure assertion": "XCTAssertFalse(\n            assessment.hasBothFixedEdges",
        "inner-scroll and empty-body controls": (
            "testDetectorAllowsIntentionalInnerTableScrollingAndEmptyBody"
        ),
        "inner-scroll false-positive control": "scrollingOnlyVariableBody(upBy: 72)",
        "empty-body false-positive control": "clearingOnlyVariableBody()",
        "banner-and-Activity-only content-loss must-catch": (
            "testDetectorRejectsBannerAndActivityWithoutPrimaryDecisionContent"
        ),
        "realistic erased primary viewport": "clearingPrimaryContent(yRange: 151..<678)",
        "former detector miss proof": "legacyBodyObservation.meetsVariableBodyMinimum",
        "empty resource rows false-positive control": "clearingResourceRows(yRange: 505..<678)",
        "inner-scroll primary-content control": (
            "MainBoardEdgeDetector.assess(internallyScrolled).bodyHasVisibleContent"
        ),
    }
    missing_vertical_xctest = [
        label
        for label, needle in vertical_xctest_contract.items()
        if needle not in vertical_layout_tests
    ]
    if missing_vertical_xctest:
        raise SystemExit(
            "DevOpsBoard vertical center-crop guard is missing realistic XCTest recall/control coverage: "
            + ", ".join(missing_vertical_xctest)
        )


def check_standalone_skill(skill: Path) -> None:
    tmp = Path(tempfile.mkdtemp(prefix=f"{skill.name}-standalone-")).resolve(strict=True)
    try:
        copied = tmp / skill.name
        shutil.copytree(skill, copied)
        run([sys.executable, str(copied / "scripts" / "self_test.py")])
        if copied.name == "codex-dev-coordinator":
            run_normalized_coordinator_tests(copied)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_broker_tests(skill: Path) -> None:
    tests = skill / "scripts" / "devcoordinator" / "tests"
    if not tests.is_dir():
        raise SystemExit(f"normalized broker tests are missing: {tests}")
    for optimization in ([], ["-O"]):
        run(
            [
                sys.executable,
                *optimization,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(tests),
                "-p",
                "test_broker.py",
                "-v",
            ]
        )


def run_normalized_coordinator_tests(skill: Path) -> None:
    scripts = skill / "scripts"
    standalone_suites = [
        "sqlite_store_test.py",
        "self_test_sqlite_cutover.py",
        "self_test_multi_runtime.py",
        "self_test_repository_lifecycle.py",
        "self_test_sqlite_lifecycle.py",
        "self_test_host_lifecycle.py",
        "self_test_lifecycle_action_guard.py",
        "self_test_broker_cross_uid.py",
    ]
    for script_name in standalone_suites:
        script = scripts / script_name
        if not script.is_file():
            raise SystemExit(f"normalized coordinator test is missing: {script}")
        run([sys.executable, str(script)])
        run([sys.executable, "-O", str(script)])

    capability_fixture = scripts / "capability_integration_test.py"
    if not capability_fixture.is_file():
        raise SystemExit(
            f"coordinator capability integration is missing: {capability_fixture}"
        )
    for optimization in ([], ["-O"]):
        run(
            [
                sys.executable,
                *optimization,
                str(capability_fixture),
                "--normalized-relocation-preflight",
            ]
        )

    tests = scripts / "devcoordinator" / "tests"
    if not tests.is_dir():
        raise SystemExit(f"normalized coordinator unit tests are missing: {tests}")
    for optimization in ([], ["-O"]):
        run(
            [
                sys.executable,
                *optimization,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(tests),
                "-p",
                "test_*.py",
                "-v",
            ]
        )


def menu_source_summary_toggle_errors(source: str) -> list[str]:
    """Require the complete Sources row—not only its label—to toggle details."""

    start = source.find("struct MenuBarSourceSummary: View")
    end = source.find("\nstruct ", start + 1)
    if start < 0 or end <= start:
        return ["MenuBarSourceSummary production section is missing"]
    section = source[start:end]
    pattern = re.compile(
        r"Button\s*\{\s*expanded\.toggle\(\)\s*\}\s*label:\s*\{"
        r"[\s\S]*?Text\(expanded \? \"Hide\" : \"View details\"\)"
        r"[\s\S]*?\.contentShape\(Rectangle\(\)\)"
        r"[\s\S]*?\}\s*\.buttonStyle\(\.plain\)"
    )
    errors: list[str] = []
    if pattern.search(section) is None:
        errors.append(
            "MenuBarSourceSummary must wrap the full source row in one plain Button "
            "whose expanded toggle has a rectangular hit shape"
        )
    if 'accessibilityIdentifier("menu-source-summary-toggle")' not in section:
        errors.append("MenuBarSourceSummary toggle accessibility identity is missing")
    return errors


def check_menu_source_summary_toggle(source: str) -> None:
    good = '''
struct MenuBarSourceSummary: View {
    @State private var expanded = false
    var body: some View {
        Button {
            expanded.toggle()
        } label: {
            HStack {
                Text(expanded ? "Hide" : "View details")
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("menu-source-summary-toggle")
    }
}
struct Next: View {}
'''
    if menu_source_summary_toggle_errors(good):
        raise SystemExit("menu source-details toggle false-positive control is invalid")
    broken_hit_area = good.replace("            .contentShape(Rectangle())\n", "")
    if not menu_source_summary_toggle_errors(broken_hit_area):
        raise SystemExit("menu source-details toggle detector missed the label-only hit-area regression")
    misplaced_control = good.replace(
        "struct MenuBarSourceSummary: View",
        "struct AnotherControl: View",
        1,
    ).replace(
        "struct Next: View {}",
        '''struct MenuBarSourceSummary: View {
    var body: some View { Text("View details") }
}
struct Next: View {}''',
    )
    if not menu_source_summary_toggle_errors(misplaced_control):
        raise SystemExit("menu source-details toggle detector accepted a control outside the source row")
    errors = menu_source_summary_toggle_errors(source)
    if errors:
        raise SystemExit("DevOpsBoard source-details toggle guard failed: " + "; ".join(errors))


def check_ops_console_interaction_guardrails(*, run_macos_app_checks: bool = True) -> None:
    ops_console = ROOT / "apps" / "DevOpsBoard"
    if not ops_console.is_dir():
        return

    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ops_console / "Sources" / "DevOpsBoard").glob("*.swift"))
    )
    views = (ops_console / "Sources" / "DevOpsBoard" / "Views.swift").read_text(encoding="utf-8")
    menu_bar_views = (
        ops_console / "Sources" / "DevOpsBoard" / "MenuBarViews.swift"
    ).read_text(encoding="utf-8")
    store = (ops_console / "Sources" / "DevOpsBoard" / "OpsStore.swift").read_text(encoding="utf-8")
    models = (ops_console / "Sources" / "DevOpsBoard" / "Models.swift").read_text(encoding="utf-8")
    repository_catalog = (
        ops_console / "Sources" / "DevOpsBoard" / "RepositoryCatalog.swift"
    ).read_text(encoding="utf-8")
    snapshot_main = (ops_console / "Tools" / "SnapshotMain.swift").read_text(encoding="utf-8")
    menu_snapshot = (ops_console / "Tools" / "MenuBarSnapshotMain.swift").read_text(encoding="utf-8")
    launch_readiness = (ops_console / "Tools" / "verify_launch_readiness.py").read_text(
        encoding="utf-8"
    )
    launch_readiness_tests = (
        ops_console / "Tools" / "self_test_verify_launch_readiness.py"
    ).read_text(encoding="utf-8")
    snapshot_provenance = (ops_console / "Tools" / "SnapshotProvenance.swift").read_text(encoding="utf-8")
    split_sizing = (ops_console / "Tools" / "SplitSizingTest.swift").read_text(encoding="utf-8")
    core_tests = (ops_console / "Tests" / "DevOpsBoardTests" / "CoreTests.swift").read_text(encoding="utf-8")
    repository_catalog_tests = (
        ops_console / "Tests" / "DevOpsBoardTests" / "RepositoryCatalogTests.swift"
    ).read_text(encoding="utf-8")
    project_group_presentation_tests = (
        ops_console / "Tests" / "DevOpsBoardTests" / "ProjectGroupPresentationTests.swift"
    ).read_text(encoding="utf-8")
    vertical_layout_tests_path = (
        ops_console / "Tests" / "DevOpsBoardTests" / "MainBoardVerticalLayoutTests.swift"
    )
    if not vertical_layout_tests_path.is_file():
        raise SystemExit(
            "DevOpsBoard vertical center-crop guard requires MainBoardVerticalLayoutTests.swift"
        )
    vertical_layout_tests = vertical_layout_tests_path.read_text(encoding="utf-8")
    coordinator = (ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "dev_coordinator.py").read_text(encoding="utf-8")
    coordinator_self_test = (ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "self_test.py").read_text(encoding="utf-8")
    coordinator_capability_test = (ROOT / "skills" / "codex-dev-coordinator" / "scripts" / "capability_integration_test.py").read_text(encoding="utf-8")
    coordinator_skill = (ROOT / "skills" / "codex-dev-coordinator" / "SKILL.md").read_text(encoding="utf-8")

    check_devops_board_center_pane_geometry(views, split_sizing, vertical_layout_tests)
    check_menu_source_summary_toggle(menu_bar_views)

    required = {
        "left pane splitter": "SplitHandle(width: $sidebarWidth",
        "right pane splitter": "SplitHandle(width: $inspectorWidth",
        "thin splitter width": "let splitHandleWidth: CGFloat = 8",
        "consecutive top-aligned pane layout": "HStack(alignment: .top, spacing: 0)",
        "exact main pane height": "height: proxy.size.height,",
        "top-leading main pane frame": "alignment: .topLeading",
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
        "canonical repository identity": "struct RepositoryIdentity",
        "source-independent project group identity": "guard usageKey.hasPrefix(\"path:\") else { return unassignedProjectGroupID }",
        "global physical Docker reconciliation": "let physicalDocker = Dictionary(grouping: pendingDocker)",
        "whole-runtime control intersection": "candidates.formIntersection(constraint)",
        "unassigned resource aggregate": "name: \"Unassigned Resources\"",
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
        "explicit bulk stop review": "BulkStopReviewSheet",
        "sidebar footer icon fixed frame": ".frame(width: 24, height: 24)",
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
        "structured server argv": "\"--argv\", encodedArgv",
        "docker all inventory": "def docker_ps_inventory(\n    *,\n    all_containers: bool = True,",
        "docker ps all command": "args.append(\"--all\")",
        "docker stats command": "\"docker\", \"stats\", \"--no-stream\"",
        "docker stats history": "stats_history",
        "docker stats model": "struct DockerStats",
        "docker telemetry sparkline": "MetricSparkCell",
        "docker telemetry panel": "DockerTelemetryPanel",
        "visibility gated auto refresh": "func setSurfaceVisible(",
        "window visibility drives refresh gating": "store.setSurfaceVisible(.window, visible)",
        "popover visibility drives refresh gating": "store?.setSurfaceVisible(.popover, true)",
        "configured auto refresh interval": "var refreshIntervalSeconds: Double?",
        "auto refresh pauses when hidden": "autoRefreshTask?.cancel()",
        "window occlusion tracking": "windowDidChangeOcclusionState",
        "popover visibility tracking": "popoverDidClose",
        "coalesced inventory refresh": "followUpRequested",
        "publish inventory and repository catalog atomically": "publishInventory(decoded, catalog: catalog)",
        "cached project groups": "@Published private(set) var projectGroups",
        "main-actor-safe detached command execution": "let worker = Task.detached(priority: .userInitiated)",
        "pre-launch subprocess completion handler": "process.terminationHandler = { finished in",
        "bounded subprocess watchdog": "processExit.wait(timeout:",
        "event-driven output limit": "SpoolBudget(limit: request.maxOutputBytes) {",
        "realistic large inventory transport regression": "testRealisticLargeInventoryTraversesProductionExecutorAndLoadsStore",
        "ordinary coordinator output limit control": "testOrdinaryCoordinatorOutputOverOneMiBRemainsTruncated",
        "inventory-specific bounded output budget": "inventoryMaxOutputBytes",
        "compact bounded inventory request": "--stats-history-limit",
        "background-decoded normalized inventory handoff": "case success(NormalizedBoardProjection)",
        "sendable normalized inventory value graph": "struct NormalizedInventoryGraph: Decodable, Sendable",
        "direct schema-v2 inventory decoder": "NormalizedInventoryGraph.self",
        "direct schema-v2 Board projection": "graph.boardProjection(origin: origin)",
        "schema-v2 fail-closed guard": "guard schemaVersion == 2 else",
        "normalized repository identity decoding": "case repoID = \"repo_id\"",
        "normalized database observation decoding": "case servers, docker, databases, telemetry, snapshots",
        "normalized restorable backup registry": "case databaseBackups = \"database_backups\"",
        "database identity requires authoritative ownership": "guard ownershipError == nil,\n              let origin",
        "database UI ownership gate": "guard database.ownershipError == nil,",
        "database operation rechecks current ownership": "currentAuthoritativeDatabase(matching:",
        "whole-project definition membership coverage": "requiredMembershipKeys.isSubset(of: presentMembershipKeys)",
        "v1-only production rejection regression": "testV1OnlyPayloadCannotMasqueradeAsNormalizedInventory",
        "poisoned v1 identity isolation regression": "testDirectV2ProjectionUsesDurableIdentitiesAndIgnoresEveryPoisonedV1Field",
        "missing repository membership control regression": "testRepositoryControlRequiresCompleteAuthoritativeMembershipCoverage",
        "non-database Docker membership regression": "testNonDatabaseDockerResourceRequiresMembershipBeforeProjectControl",
        "uncontrolled database protection regression": "testDatabaseProtectionFailsClosedWhenCurrentOwnershipIsNotAuthoritative",
        "normalized database observation regression": "testFailedDatabaseObservationRetainsRuntimeSnapshotAndDegradesOnlyDatabaseCapability",
        "normalized fence violation regression": "testRunningDisabledRepositoryResourceIsOnlyAnExactUnassignedFenceViolation",
        "bounded command default timeout": "timeout: TimeInterval = 120",
        "concurrent source refresh": "let outcomes = await withTaskGroup(",
        "deterministic source refresh order": "ordered[outcome.index] = outcome",
        "project panel usage-key path fallback": "projectPath(fromUsageKey: name)",
        "configured auto refresh": "Task.sleep(for: .seconds(interval))",
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
        "project action path from canonical group": "nativeID: projectPath",
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
        "menu bar combined source summary": "MenuBarSourceSummary",
        "menu bar retained result": "MenuBarActionResultPanel",
        "menu bar source badges": "MenuSourceBadge",
        "persistent action error details": "lastErrorDetails",
        "command failure detail builder": "commandFailureDetails",
        "shell quoted command details": "func shellCommand(",
        "menu bar error qa mode": "mode == \"error\"",
        "menu snapshot uses production menu": "let view = MenuBarRuntimeView(",
        "menu snapshot uses isolated fixture inventory": "let fixture = try menuFixtureInventory()",
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
        "strict registration PID ownership": "def registration_pid_identity(",
        "direct proc cwd observation": "def process_cwd_from_proc(",
        "tri-state process cwd observation": "def process_cwd_observation(",
        "tri-state lsof cwd observation": "def _lsof_process_cwd_observation(",
        "managed lsof denial recall": "managed server lsof denial signalled its PID or released its lease",
        "managed lsof empty recall": "managed server empty lsof cwd signalled its PID or released its lease",
        "zombie PID recall": "zombie PID must not be treated as a live managed process",
        "endpoint-specific registration ownership": "def _listening_inodes_for_endpoint(",
        "API capability inheritance clear": "def clear_exec_capability_inheritance(",
        "registration PID false-positive guard": "registration accepted invalid PID",
        "changed owner replacement lease": "changed listener owner must receive a replacement lease",
        "unobservable listener preservation": (
            "pure API inventory did not preserve the cached unknown observation and active lease"
        ),
        "pre-guard identity no-write": (
            "no-cap registration wrote lifecycle or operation state before "
        ),
        "unobservable lifecycle fail closed": "signalled, launched, or changed the registration graph",
        "unobservable project atomicity": "partially mutated before identity proof",
        "read-only lifecycle conflict priority": "def require_operation_slot(",
        "manager bounding ceiling preserved": "capability API narrowed the host's preexisting bounding ceiling",
        "child bounding ceiling inherited": "managed child capability ceiling did not inherit the API's default ceiling",
        "relocation replacement lease linkage": "replacement lease must link server, PID, purpose, and assignment",
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
        "ambiguous container name match stays unclaimed": "\"ambiguous_name\"",
        "membership divergence must-catch fixture": "must-catch: unattributed grouprepo-db must remain visible as read-only evidence",
        "membership blast radius skill contract": "shows exactly the blast radius",
        "bounded socket http health": "socket.create_connection((parsed.hostname, port), timeout=timeout)",
        # macOS runners black-hole reverse DNS: a stock HTTPServer.server_bind
        # stalls ~30s in socket.getfqdn between bind() and listen(). The API
        # server must bind without name resolution, and serve_api must use it.
        "coordinator api server skips getfqdn": "socketserver.TCPServer.server_bind(self)",
        "coordinator api server fast-bind use": "server = BoundedThreadingHTTPServer((host, port), ApiHandler, token=token)",
        "http health timeout classification": "\"classification\": \"timeout\"",
        "project usage model": "struct ProjectUsage",
        "process usage model": "struct ProcessUsage",
        "project load strip": "ProjectUsageStrip",
        "project load hot process": "hotProcessLabel(",
        "multi coordinator origin discovery": "FileSystemCoordinatorOriginDiscovery",
        "three-source repository UI regression": "testThreeSourceRepositoryPublishesOneNevodProjectAndRoutesOneProjectAction",
        "cross-project Docker conflict regression": "testDockerMembershipConflictBlocksBothOtherwiseControlledProjectActionsAndHealthIsNotNominal",
        "cross-project server conflict regression": "testSameActivePhysicalServerClaimedByTwoRepositoriesBlocksBothProjects",
        "usage-only unassigned regression": "testUsageOnlyNameEvidenceStillProducesOneUnassignedPresentation",
        "catalog conflict health regression": "testCatalogOwnershipConflictMakesPublishedHealthNonNominalEvenWithoutResourceIdentity",
        "privacy-safe attention readiness telemetry": "attention_items=\\(attentionItems, privacy: .public)",
        "generic attention readiness rejection": "reports generic duplicated attention",
        "missing attention item readiness rejection": "without a concrete attention item",
        "missing resolution target readiness rejection": "without a resolution target",
        "production-shaped generic attention fixture": "generic-unhealthy-attention.log",
        "actionable unhealthy readiness control": "actionable-unhealthy-service.log",
        "shared review target readiness control": "shared-attention-review-target.log",
        "action-in-progress readiness control": "actionable-busy-state.log",
        "nominal attention readiness control": "nominal-phantom-attention.log",
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
            repository_catalog,
            snapshot_main,
            menu_snapshot,
            launch_readiness,
            launch_readiness_tests,
            snapshot_provenance,
            split_sizing,
            core_tests,
            repository_catalog_tests,
            project_group_presentation_tests,
            coordinator,
            coordinator_self_test,
            coordinator_capability_test,
            coordinator_skill,
        ]
    )
    missing = [label for label, needle in required.items() if needle not in haystacks]
    if missing:
        raise SystemExit("DevOpsBoard interaction guardrail failed: " + ", ".join(missing))

    merge_start = store.find("for outcome in outcomes {")
    merge_end = store.find("sourceStates = states", merge_start)
    if merge_start < 0 or merge_end <= merge_start:
        raise SystemExit("DevOpsBoard interaction guardrail could not locate the inventory merge boundary")
    if "JSONDecoder().decode(Inventory.self" in store[merge_start:merge_end]:
        raise SystemExit(
            "DevOpsBoard interaction guardrail failed: inventory was decoded again on the main-actor merge path"
        )

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
        "blocking subprocess wait": ".waitUntilExit(",
        "blocking subprocess poll": "usleep(",
    }
    prohibited_haystack = "\n".join([source_text, snapshot_main, menu_snapshot, snapshot_provenance])
    present = [label for label, needle in prohibited.items() if needle in prohibited_haystack]
    if present:
        raise SystemExit("DevOpsBoard interaction guardrail found prohibited pattern: " + ", ".join(present))

    normalized_store_prohibited = {
        "production v1 Inventory transport decoder": "JSONDecoder().decode(Inventory.self",
        "production v1 compatibility lookup": "v1_compatibility",
        "second no-Docker inventory request": '"--no-docker"',
        "Board-side backup directory enrichment": '"--backup-dir"',
        "Board-side database rediscovery": "discoverDatabases(",
    }
    normalized_present = [
        label for label, needle in normalized_store_prohibited.items() if needle in store
    ]
    if normalized_present:
        raise SystemExit(
            "DevOpsBoard normalized-v2 guard found prohibited pattern: "
            + ", ".join(normalized_present)
        )

    if run_macos_app_checks:
        raise SystemExit(
            "DevOps Board native validation is owned by Build macOS Apps; "
            "run this repository gate with --skip-macos-app"
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
    server_bind_test = (console / "test" / "unit.server-bind.test.mjs").read_text(encoding="utf-8")
    package_json = json.loads((console / "package.json").read_text(encoding="utf-8"))

    required = {
        "routes default to login-required": "def.auth === undefined || def.auth === null ? 'google'",
        "timing-safe session compare": "crypto.timingSafeEqual(given, expected)",
        "proxy pinned to loopback": "const LOOPBACK = '127.0.0.1'",
        "hop-by-hop header stripping": "HOP_BY_HOP",
        "parent-domain auth cookies stripped from upstream requests": "const protectedCookieNames = new Set([sessionCookieName, FLOW_COOKIE_NAME]);",
        "parent-domain auth cookies stripped from HTTP responses": "filterResponseHeaders(r.headers, protectedCookieNames)",
        "parent-domain auth cookies stripped from WebSocket responses": "appendSafeRawHeaders(lines, upstreamRes.rawHeaders, protectedCookieNames)",
        "proxy receives configured session-cookie identity": "sessionCookieName: config.cookieName",
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
        "private per-user access policy store": "access-control.json",
        "configured-owner access administration": "if (!accessStore?.isAdmin(session?.email))",
        "exact route grants checked at edge": "guard.hasAccess(session, routeGrant(slug))",
        "route rename moves access grants": "accessStore.moveResource(routeGrant(existing.slug), routeGrant(route.slug))",
        "route deletion clears access grants": "accessStore.clearResource(routeGrant(removed.slug))",
        "access collection page": "function buildAccess(",
        "access add dialog wired": "function wireAccessDialog(",
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
        "explicit production IPv4 listener": "config.bindHost ?? '0.0.0.0'",
        "production listener behavior test": "production TLS binds the explicit IPv4 wildcard",
    }
    haystack = "\n".join([source_text, app_js, app_css, index_html, dev_cert_helper, server_bind_test])
    missing = [label for label, needle in required.items() if needle not in haystack]
    if missing:
        raise SystemExit("DevOpsConsole guardrail failed: " + ", ".join(missing))

    if source_text.count("!guard.hasAccess(session, routeGrant(slug))") < 2:
        raise SystemExit("DevOpsConsole guardrail requires exact route grants on HTTP and WebSocket paths")

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
    # Exercise the package's public test entry point. The explicit `.test.mjs`
    # glob in package.json is portable across Node 20-22; Node 22 treats a
    # bare `test/` directory argument as a missing CommonJS module.
    run(["npm", "test"], cwd=console)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate DevCoordinator, DevOps Board, and DevOps Console.")
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
    if not args.skip_macos_app:
        raise SystemExit(
            "native validation must run through Build macOS Apps; "
            "this CLI only supports --skip-macos-app"
        )
    check_duplicate_literal_dict_keys()
    check_decision_history_contract()
    run([sys.executable, str(ROOT / "scripts" / "check_repository_freshness_self_test.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_repository_boundaries.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_production_layout.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_migrate_legacy_console_runtime.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_verify_legacy_cutover_boundary.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_terminate_captured_legacy_process.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_coordinator_auth_boundary.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_coordinator_auth_boundary.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_post_cutover_registration.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_post_cutover_registration.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_retired_assignment_cleanup.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_retired_assignment_cleanup.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_restore_coordinator_state.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_console_registration_ready.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_console_registration_ready.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_write_cutover_phase_marker.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_check_legacy_cutover_stopped.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_check_legacy_cutover_stopped.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_legacy_console_rollback_ready.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_legacy_console_rollback_ready.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_loaded_systemd_paths.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_server_wide_install.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_cutover_helper_cli_contracts.py")])
    run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_cutover_helper_cli_contracts.py")])
    run([sys.executable, str(ROOT / "scripts" / "check_repository_boundaries.py"), "--repo", str(ROOT)])
    check_ops_console_interaction_guardrails(run_macos_app_checks=False)
    check_devops_console()
    run([sys.executable, str(ROOT / "scripts" / "self_test_manage_skill_links.py")])
    run([sys.executable, str(ROOT / "scripts" / "self_test_public_artifact_guard.py")])
    run([sys.executable, str(ROOT / "scripts" / "public_artifact_guard.py"), "--repo", str(ROOT)])
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
    run_normalized_coordinator_tests(ROOT / "skills" / "codex-dev-coordinator")
    run(
        [
            sys.executable,
            "-m",
            "compileall",
            "scripts",
            "skills/codex-dev-coordinator/scripts",
            "skills/postgres-docker-backup/scripts",
            "apps/DevOpsBoard/Tools",
        ]
    )
    for skill in SKILLS:
        check_standalone_skill(skill)
    ops_console = ROOT / "apps" / "DevOpsBoard"
    if ops_console.is_dir():
        # This provenance/tamper suite is deliberately Python-only. Keep it in
        # the safe validation path so stale Swift binaries cannot evade the
        # guardrail merely because the required native plugin is unavailable.
        run([sys.executable, "Tools/self_test_package_app.py"], cwd=ops_console)
        launch_readiness_self_test = [
            sys.executable,
            "Tools/self_test_verify_launch_readiness.py",
        ]
        run(launch_readiness_self_test, cwd=ops_console)
        var_tmp = Path("/var/tmp")
        if not var_tmp.is_dir():
            raise SystemExit("launch-readiness alias regression requires /var/tmp")
        run(
            launch_readiness_self_test,
            cwd=ops_console,
            env={**os.environ, "TMPDIR": str(var_tmp)},
        )
    print("validation ok (native DevOps Board gate remains Build macOS Apps-owned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
