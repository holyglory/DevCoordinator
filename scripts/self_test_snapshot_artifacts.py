#!/usr/bin/env python3
"""Recall and false-positive tests for canonical snapshot geometry checks."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from shutil import rmtree


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_snapshot_artifacts.py"
SPEC = importlib.util.spec_from_file_location("verify_snapshot_artifacts", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load snapshot verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


def chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def write_png(
    path: Path,
    *,
    rgba: bool,
    transparent: bool = False,
    sparse: bool = False,
    fragmented_chrome: bool = False,
) -> None:
    width, height = 120, 80
    channels = 4 if rgba else 3
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            in_marker = ((x % 30) < 8 and (y % 20) < 6) or ((y < 6 or y >= 74) and (x % 15) < 8)
            if sparse:
                base = (0, 0, 0)
                in_marker = in_marker and x < 60 and y < 40
            elif fragmented_chrome:
                # Mirrors the reported broken render: enough disconnected
                # fragments remain in every broad quadrant to satisfy the old
                # detector, while top/bottom chrome anchors are absent.
                base = (15, 17, 18)
                in_marker = ((10 <= y < 30) or (45 <= y < 65)) and (x % 30) < 15
            else:
                base = (15, 17, 18)
            color = (180, 190, 200) if in_marker else base
            rows.extend(color)
            if rgba:
                rows.append(0 if transparent else 255)
    color_type = 6 if rgba else 2
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b""))


def write_control_band_png(path: Path, *, control_y: int) -> None:
    """Render two text/control rows without coupling the fixture to verifier code."""

    width, height = 120, 80
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            in_first_row = control_y <= y < control_y + 6
            in_second_row = control_y + 12 <= y < control_y + 18
            is_control_pixel = (in_first_row or in_second_row) and (x % 16) < 12
            rows.extend((180, 190, 200) if is_control_pixel else (15, 17, 18))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(rows)))
        + chunk(b"IEND", b"")
    )


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="snapshot-artifact-self-test-")).resolve(strict=True)
    try:
        regions = (
            VERIFIER.RegionSpec("top-left", 0, 0, 60, 40, 16),
            VERIFIER.RegionSpec("top-right", 60, 0, 60, 40, 16),
            VERIFIER.RegionSpec("bottom-left", 0, 40, 60, 40, 16),
            VERIFIER.RegionSpec("bottom-right", 60, 40, 60, 40, 16),
        )
        anchors = (
            VERIFIER.AnchorSpec("top-window-chrome", 0, 0, 120, 10, 100, 6, 1),
            VERIFIER.AnchorSpec("bottom-status-chrome", 0, 70, 120, 10, 100, 6, 1),
        )
        spec = VERIFIER.ArtifactSpec(120, 80, 0.85, regions, anchors)

        good_rgb = temporary / "good-rgb.png"
        write_png(good_rgb, rgba=False)
        check(not VERIFIER.verify_image(good_rgb, spec), "intentional opaque dark UI fixture should pass")

        good_rgba = temporary / "good-rgba.png"
        write_png(good_rgba, rgba=True)
        rgba_rules = {finding.rule for finding in VERIFIER.verify_image(good_rgba, spec)}
        check(
            "snapshot-renderer-unsafe-alpha" in rgba_rules,
            "nominally opaque RGBA snapshots must be rejected because downstream viewers can fragment them",
        )

        transparent = temporary / "transparent.png"
        write_png(transparent, rgba=True, transparent=True)
        transparent_rules = {finding.rule for finding in VERIFIER.verify_image(transparent, spec)}
        check("snapshot-non-opaque" in transparent_rules, "transparent chrome must be caught")
        check("snapshot-renderer-unsafe-alpha" in transparent_rules, "RGBA channel safety must be caught independently of alpha values")

        fragmented = temporary / "fragmented-chrome.png"
        write_png(fragmented, rgba=False, fragmented_chrome=True)
        fragmented_rules = {finding.rule for finding in VERIFIER.verify_image(fragmented, spec)}
        check(
            "snapshot-missing-semantic-anchor" in fragmented_rules,
            "fragmented header/footer chrome must be caught even when broad regions contain content",
        )
        check("snapshot-sparse" not in fragmented_rules, "fragmented dark UI fixture should retain normal background coverage")
        check("snapshot-empty-region" not in fragmented_rules, "fixture must prove the old broad-region checks would pass")

        # Removing a false alert legitimately moves the filter and resource-tab
        # rows upward. The recalibrated semantic anchor must accept those intact
        # rows, while still catching controls displaced below their expected
        # first-viewport area.
        control_anchor_spec = VERIFIER.ArtifactSpec(
            120,
            80,
            0.85,
            (),
            (VERIFIER.AnchorSpec("filters-and-resource-tabs", 0, 10, 120, 40, 500, 12, 3),),
        )
        upward_controls = temporary / "intact-upward-controls.png"
        write_control_band_png(upward_controls, control_y=14)
        check(
            not VERIFIER.verify_image(upward_controls, control_anchor_spec),
            "intact controls shifted upward after false-alert removal should pass",
        )

        # The reported cold-capture failure erased only the top toolbar while
        # leaving bright controls elsewhere. Split the toolbar into three
        # independent anchors and prove a bottom-edge decoy cannot satisfy any
        # of them through an accidental vertical flip.
        toolbar_anchor_spec = VERIFIER.ArtifactSpec(
            120,
            80,
            0.85,
            (),
            (
                VERIFIER.AnchorSpec("toolbar-environment", 0, 0, 40, 10, 100, 3, 1),
                VERIFIER.AnchorSpec("toolbar-search", 40, 0, 40, 10, 100, 3, 1),
                VERIFIER.AnchorSpec("toolbar-actions", 80, 0, 40, 10, 100, 3, 1),
            ),
        )
        intact_toolbar = temporary / "intact-split-toolbar.png"
        write_control_band_png(intact_toolbar, control_y=1)
        check(
            not VERIFIER.verify_image(intact_toolbar, toolbar_anchor_spec),
            "an intact compact toolbar should satisfy all three independent anchors",
        )
        footer_toolbar_decoy = temporary / "footer-toolbar-decoy.png"
        write_control_band_png(footer_toolbar_decoy, control_y=62)
        toolbar_findings = [
            finding
            for finding in VERIFIER.verify_image(footer_toolbar_decoy, toolbar_anchor_spec)
            if finding.rule == "snapshot-missing-semantic-anchor"
        ]
        check(
            len(toolbar_findings) == 3,
            "footer controls must not masquerade as any top-toolbar anchor",
        )

        misplaced_controls = temporary / "misplaced-lower-controls.png"
        write_control_band_png(misplaced_controls, control_y=54)
        misplaced_rules = {
            finding.rule for finding in VERIFIER.verify_image(misplaced_controls, control_anchor_spec)
        }
        check(
            "snapshot-missing-semantic-anchor" in misplaced_rules,
            "controls displaced below the expected filter/tab area must be caught",
        )

        sparse = temporary / "sparse.png"
        write_png(sparse, rgba=False, sparse=True)
        sparse_rules = {finding.rule for finding in VERIFIER.verify_image(sparse, spec)}
        check("snapshot-sparse" in sparse_rules, "mostly missing render must be caught")
        check("snapshot-empty-region" in sparse_rules, "missing required UI regions must be caught")

        source_root = temporary / "app"
        (source_root / "Sources" / "DevOpsBoard").mkdir(parents=True)
        (source_root / "Tools").mkdir(parents=True)
        package_source = source_root / "Package.swift"
        view_source = source_root / "Sources" / "DevOpsBoard" / "Views.swift"
        generation_source = source_root / "Tools" / "CanonicalSnapshotGenerationTests.swift"
        renderer_source = source_root / "Tools" / "SnapshotMain.swift"
        package_source.write_text(
            '.testTarget(name: "DevOpsBoardSnapshotTests", sources: ["CanonicalSnapshotGenerationTests.swift"])\n',
            encoding="utf-8",
        )
        view_source.write_text("struct ViewFixture {}\n", encoding="utf-8")
        generation_source.write_text('let state = "servers"\nlet width = 1440\n', encoding="utf-8")
        renderer_source.write_text("struct RendererFixture {}\n", encoding="utf-8")
        expected_files = (
            "Package.swift",
            "Sources/DevOpsBoard/Views.swift",
            "Tools/CanonicalSnapshotGenerationTests.swift",
            "Tools/SnapshotMain.swift",
        )
        provenance_path = Path(f"{good_rgb}.provenance.json")

        def write_source_provenance() -> None:
            provenance_path.write_text(
                json.dumps(
                    {
                        "source_files": sorted(expected_files),
                        "source_sha256": VERIFIER.source_fingerprint(source_root, expected_files),
                    }
                ),
                encoding="utf-8",
            )

        write_source_provenance()
        check(
            not VERIFIER.verify_source_binding(good_rgb, source_root, expected_files),
            "current renderer source with exact portable provenance should pass",
        )

        view_source.write_text("struct ViewFixture { let changed = true }\n", encoding="utf-8")
        stale_rules = {
            finding.rule for finding in VERIFIER.verify_source_binding(good_rgb, source_root, expected_files)
        }
        check(
            "snapshot-stale-source" in stale_rules,
            "a realistic UI source edit after rendering must make the committed snapshot stale",
        )

        view_source.write_text("struct ViewFixture {}\n", encoding="utf-8")
        write_source_provenance()
        generation_source.write_text('let state = "servers"\nlet width = 1280\n', encoding="utf-8")
        generation_rules = {
            finding.rule for finding in VERIFIER.verify_source_binding(good_rgb, source_root, expected_files)
        }
        check(
            "snapshot-stale-source" in generation_rules,
            "changing the authoritative snapshot mode or dimensions must make the artifact stale",
        )

        generation_source.write_text('let state = "servers"\nlet width = 1440\n', encoding="utf-8")
        write_source_provenance()
        package_source.write_text(
            '.testTarget(name: "DevOpsBoardSnapshotTests", sources: ["SnapshotMain.swift"])\n',
            encoding="utf-8",
        )
        package_rules = {
            finding.rule for finding in VERIFIER.verify_source_binding(good_rgb, source_root, expected_files)
        }
        check(
            "snapshot-stale-source" in package_rules,
            "changing SwiftPM snapshot-target membership must make the artifact stale",
        )

        package_source.write_text(
            '.testTarget(name: "DevOpsBoardSnapshotTests", sources: ["CanonicalSnapshotGenerationTests.swift"])\n',
            encoding="utf-8",
        )
        provenance_path.write_text(json.dumps({"source_sha256": "0" * 64}), encoding="utf-8")
        missing_binding_rules = {
            finding.rule for finding in VERIFIER.verify_source_binding(good_rgb, source_root, expected_files)
        }
        check(
            "snapshot-missing-source-provenance" in missing_binding_rules,
            "a PNG hash alone must not satisfy renderer-source provenance",
        )

        print("snapshot artifact verifier self-test ok")
        return 0
    finally:
        rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
