#!/usr/bin/env python3
"""Verify canonical snapshots are renderer-safe and contain required UI chrome."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = ROOT / "apps" / "CodexOpsConsole"


@dataclass(frozen=True)
class RegionSpec:
    name: str
    x: int
    y: int
    width: int
    height: int
    minimum_bright_pixels: int


@dataclass(frozen=True)
class AnchorSpec:
    name: str
    x: int
    y: int
    width: int
    height: int
    minimum_bright_pixels: int
    minimum_active_x_bins: int
    minimum_active_y_bins: int


@dataclass(frozen=True)
class ArtifactSpec:
    width: int
    height: int
    minimum_nonblack_ratio: float
    regions: tuple[RegionSpec, ...]
    anchors: tuple[AnchorSpec, ...] = ()


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    detail: str


@dataclass(frozen=True)
class DecodedPNG:
    width: int
    height: int
    channels: int
    pixels: bytes


BOARD_SPEC = ArtifactSpec(
    width=1440,
    height=1024,
    minimum_nonblack_ratio=0.85,
    regions=(
        RegionSpec("window-header", 0, 0, 1440, 60, 250),
        RegionSpec("service-map", 0, 60, 325, 900, 450),
        RegionSpec("board-toolbar", 327, 0, 785, 240, 900),
        RegionSpec("resource-table", 327, 175, 785, 220, 700),
        RegionSpec("details-inspector", 1125, 0, 315, 970, 500),
        RegionSpec("status-footer", 0, 970, 1440, 54, 150),
    ),
    anchors=(
        AnchorSpec("window-title", 0, 0, 325, 60, 500, 12, 2),
        AnchorSpec("global-toolbar", 327, 0, 785, 60, 1_200, 30, 3),
        AnchorSpec("service-map-heading", 0, 60, 325, 45, 120, 5, 1),
        AnchorSpec("project-tree", 0, 95, 325, 200, 900, 10, 6),
        AnchorSpec("project-load-summary", 327, 60, 785, 80, 900, 20, 3),
        AnchorSpec("filters-and-complete-tabs", 327, 130, 785, 90, 2_500, 20, 4),
        AnchorSpec("details-heading", 1125, 0, 315, 80, 300, 6, 2),
        AnchorSpec("sidebar-footer", 0, 920, 325, 104, 400, 10, 4),
        AnchorSpec("center-status-footer", 327, 970, 785, 54, 500, 20, 2),
    ),
)

MENU_SPEC = ArtifactSpec(
    width=430,
    height=600,
    minimum_nonblack_ratio=0.85,
    regions=(
        RegionSpec("menu-header", 0, 0, 430, 55, 100),
        RegionSpec("task-list", 0, 55, 430, 190, 250),
        RegionSpec("error-panel", 0, 360, 430, 195, 300),
        RegionSpec("menu-footer", 0, 555, 430, 45, 80),
    ),
    anchors=(
        AnchorSpec("menu-title", 0, 0, 250, 55, 350, 8, 2),
        AnchorSpec("menu-actions", 330, 0, 100, 55, 40, 2, 2),
        AnchorSpec("project-row", 0, 55, 430, 50, 250, 8, 2),
        AnchorSpec("task-rows", 0, 100, 430, 125, 800, 12, 5),
        AnchorSpec("error-heading", 0, 360, 430, 72, 500, 12, 2),
        AnchorSpec("error-details", 0, 430, 430, 125, 650, 12, 4),
        AnchorSpec("menu-footer", 0, 555, 430, 45, 250, 12, 1),
    ),
)

CANONICAL_SPECS = {
    "dev-servers.png": BOARD_SPEC,
    "docker-board.png": BOARD_SPEC,
    "databases.png": BOARD_SPEC,
    "menu-action-error.png": MENU_SPEC,
}

BOARD_SOURCE_FILES = (
    "Sources/CodexOpsConsole/Models.swift",
    "Sources/CodexOpsConsole/OpsStore.swift",
    "Sources/CodexOpsConsole/Views.swift",
    "Tools/SnapshotMain.swift",
    "Tools/SnapshotProvenance.swift",
)
MENU_SOURCE_FILES = (
    "Sources/CodexOpsConsole/Models.swift",
    "Sources/CodexOpsConsole/OpsStore.swift",
    "Sources/CodexOpsConsole/Views.swift",
    "Sources/CodexOpsConsole/MenuBarViews.swift",
    "Tools/MenuBarSnapshotMain.swift",
    "Tools/SnapshotProvenance.swift",
)
CANONICAL_SOURCE_FILES = {
    "dev-servers.png": BOARD_SOURCE_FILES,
    "docker-board.png": BOARD_SOURCE_FILES,
    "databases.png": BOARD_SOURCE_FILES,
    "menu-action-error.png": MENU_SOURCE_FILES,
}


def _paeth(left: int, up: int, upper_left: int) -> int:
    estimate = left + up - upper_left
    left_distance = abs(estimate - left)
    up_distance = abs(estimate - up)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= up_distance and left_distance <= upper_left_distance:
        return left
    if up_distance <= upper_left_distance:
        return up
    return upper_left


def decode_png(path: Path) -> DecodedPNG:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("invalid PNG signature")
    offset = len(PNG_SIGNATURE)
    width = height = color_type = bit_depth = interlace = None
    compressed = bytearray()
    saw_end = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        chunk_end = payload_end + 4
        if chunk_end > len(data):
            raise ValueError("truncated PNG payload")
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack(">I", data[payload_end:chunk_end])[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            raise ValueError("invalid PNG chunk CRC")
        if kind == b"IHDR":
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            if compression != 0 or filtering != 0:
                raise ValueError("unsupported PNG compression or filter method")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            saw_end = True
            break
        offset = chunk_end
    if not saw_end or None in (width, height, color_type, bit_depth, interlace):
        raise ValueError("PNG is missing required chunks")
    if bit_depth != 8 or color_type not in (2, 6) or interlace != 0:
        raise ValueError("snapshot verifier supports only non-interlaced 8-bit RGB/RGBA PNGs")

    channels = 3 if color_type == 2 else 4
    stride = width * channels
    raw = zlib.decompress(bytes(compressed))
    expected_length = height * (stride + 1)
    if len(raw) != expected_length:
        raise ValueError("PNG scanline length does not match IHDR")
    pixels = bytearray(width * height * channels)
    previous = bytearray(stride)
    input_offset = 0
    output_offset = 0
    for _ in range(height):
        filter_type = raw[input_offset]
        input_offset += 1
        encoded = raw[input_offset : input_offset + stride]
        input_offset += stride
        row = bytearray(stride)
        for index, value in enumerate(encoded):
            left = row[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                decoded = value
            elif filter_type == 1:
                decoded = value + left
            elif filter_type == 2:
                decoded = value + up
            elif filter_type == 3:
                decoded = value + ((left + up) // 2)
            elif filter_type == 4:
                decoded = value + _paeth(left, up, upper_left)
            else:
                raise ValueError(f"unsupported PNG row filter {filter_type}")
            row[index] = decoded & 0xFF
        pixels[output_offset : output_offset + stride] = row
        output_offset += stride
        previous = row
    return DecodedPNG(width=width, height=height, channels=channels, pixels=bytes(pixels))


def verify_image(path: Path, spec: ArtifactSpec) -> list[Finding]:
    findings: list[Finding] = []
    try:
        image = decode_png(path)
    except (OSError, ValueError, zlib.error) as exc:
        return [Finding("snapshot-invalid", path.as_posix(), str(exc))]
    if (image.width, image.height) != (spec.width, spec.height):
        findings.append(
            Finding(
                "snapshot-dimensions",
                path.as_posix(),
                f"expected {spec.width}x{spec.height}, got {image.width}x{image.height}",
            )
        )
        return findings

    # AppKit's nominally opaque RGBA snapshots have rendered as disconnected
    # fragments in downstream viewers. Canonical public artifacts therefore
    # use RGB PNGs, not merely alpha=255 RGBA PNGs.
    if image.channels != 3:
        findings.append(
            Finding(
                "snapshot-renderer-unsafe-alpha",
                path.as_posix(),
                "canonical snapshot must use RGB PNG encoding without an alpha channel",
            )
        )

    total_pixels = image.width * image.height
    nonblack = 0
    transparent = 0
    for pixel_index in range(total_pixels):
        offset = pixel_index * image.channels
        red, green, blue = image.pixels[offset : offset + 3]
        if max(red, green, blue) > 5:
            nonblack += 1
        if image.channels == 4 and image.pixels[offset + 3] != 255:
            transparent += 1
    if transparent:
        findings.append(
            Finding(
                "snapshot-non-opaque",
                path.as_posix(),
                f"{transparent} pixels are not fully opaque",
            )
        )
    ratio = nonblack / total_pixels
    if ratio < spec.minimum_nonblack_ratio:
        findings.append(
            Finding(
                "snapshot-sparse",
                path.as_posix(),
                f"non-black coverage {ratio:.3f} is below {spec.minimum_nonblack_ratio:.3f}",
            )
        )

    for region in spec.regions:
        bright = 0
        for y in range(region.y, region.y + region.height):
            for x in range(region.x, region.x + region.width):
                offset = (y * image.width + x) * image.channels
                if max(image.pixels[offset : offset + 3]) >= 80:
                    bright += 1
        if bright < region.minimum_bright_pixels:
            findings.append(
                Finding(
                    "snapshot-empty-region",
                    path.as_posix(),
                    f"{region.name} has {bright} bright pixels; expected at least {region.minimum_bright_pixels}",
                )
            )
    for anchor in spec.anchors:
        bright = 0
        active_x_bins: set[int] = set()
        active_y_bins: set[int] = set()
        for y in range(anchor.y, anchor.y + anchor.height):
            for x in range(anchor.x, anchor.x + anchor.width):
                offset = (y * image.width + x) * image.channels
                if max(image.pixels[offset : offset + 3]) >= 80:
                    bright += 1
                    active_x_bins.add((x - anchor.x) // 8)
                    active_y_bins.add((y - anchor.y) // 8)
        if (
            bright < anchor.minimum_bright_pixels
            or len(active_x_bins) < anchor.minimum_active_x_bins
            or len(active_y_bins) < anchor.minimum_active_y_bins
        ):
            findings.append(
                Finding(
                    "snapshot-missing-semantic-anchor",
                    path.as_posix(),
                    f"{anchor.name} lacks expected chrome/text spread "
                    f"(bright={bright}, x-bins={len(active_x_bins)}, y-bins={len(active_y_bins)})",
                )
            )
    return findings


def source_fingerprint(source_root: Path, relative_paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    resolved_root = source_root.resolve()
    for relative_path in sorted(relative_paths):
        path = (resolved_root / relative_path).resolve()
        try:
            path.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"source path escapes source root: {relative_path}") from exc
        if not path.is_file():
            raise ValueError(f"snapshot source file is missing: {relative_path}")
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_source_binding(path: Path, source_root: Path, expected_files: tuple[str, ...]) -> list[Finding]:
    provenance_path = Path(f"{path}.provenance.json")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding("snapshot-missing-source-provenance", path.as_posix(), f"cannot read provenance source binding: {exc}")]
    recorded_files = provenance.get("source_files")
    expected_list = sorted(expected_files)
    if recorded_files != expected_list:
        return [
            Finding(
                "snapshot-missing-source-provenance",
                path.as_posix(),
                "provenance source_files do not exactly name the canonical renderer inputs",
            )
        ]
    try:
        current = source_fingerprint(source_root, expected_files)
    except (OSError, ValueError) as exc:
        return [Finding("snapshot-source-unavailable", path.as_posix(), str(exc))]
    recorded = provenance.get("source_sha256")
    if not isinstance(recorded, str) or len(recorded) != 64 or recorded != current:
        return [
            Finding(
                "snapshot-stale-source",
                path.as_posix(),
                "canonical snapshot was generated from different UI or renderer source bytes",
            )
        ]
    return []


def verify_canonical(
    directory: Path,
    *,
    source_root: Path = DEFAULT_SOURCE_ROOT,
    require_source_freshness: bool = True,
) -> dict[str, object]:
    findings: list[Finding] = []
    for filename, spec in CANONICAL_SPECS.items():
        path = directory / filename
        if not path.is_file():
            findings.append(Finding("snapshot-missing", path.as_posix(), "canonical snapshot is missing"))
            continue
        findings.extend(verify_image(path, spec))
        if require_source_freshness:
            findings.extend(verify_source_binding(path, source_root, CANONICAL_SOURCE_FILES[filename]))
    findings.sort(key=lambda value: (value.path, value.rule, value.detail))
    return {
        "ok": not findings,
        "artifact_count": len(CANONICAL_SPECS),
        "source_freshness": "required" if require_source_freshness else "skipped",
        "findings": [asdict(value) for value in findings],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        default="apps/CodexOpsConsole/Artifacts/Canonical",
        help="directory containing the four canonical PNGs",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--source-root",
        default=str(DEFAULT_SOURCE_ROOT),
        help="CodexOpsConsole directory containing Sources/ and Tools/",
    )
    parser.add_argument(
        "--skip-source-freshness",
        action="store_true",
        help="run pixel/geometry checks without claiming the PNGs match current native source",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = verify_canonical(
        Path(args.directory).resolve(),
        source_root=Path(args.source_root).resolve(),
        require_source_freshness=not args.skip_source_freshness,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ok"]:
        suffix = "" if report["source_freshness"] == "required" else "; source freshness explicitly skipped"
        print(f"snapshot artifact verification ok ({report['artifact_count']} artifacts{suffix})")
    else:
        for finding in report["findings"]:
            print(f"{finding['path']}: {finding['rule']}: {finding['detail']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
