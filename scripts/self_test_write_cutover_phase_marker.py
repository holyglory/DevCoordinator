#!/usr/bin/env python3
"""Durability/refusal tests for private cutover phase markers."""

from __future__ import annotations

import json
import stat
import tempfile
from pathlib import Path

from secure_cutover_io import SecureIOError
from write_cutover_phase_marker import MarkerError, write_marker


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cutover-phase-marker-") as raw:
        root = Path(raw).resolve(strict=True)
        marker = root / "relocation.attempted"
        report = write_marker(marker, "relocation-attempted")
        if report["phase"] != "relocation-attempted":
            raise AssertionError("marker recorded the wrong phase")
        if stat.S_IMODE(marker.stat().st_mode) != 0o600:
            raise AssertionError("marker is not private")
        if json.loads(marker.read_text(encoding="utf-8"))["phase"] != "relocation-attempted":
            raise AssertionError("marker contents were not durable")
        try:
            write_marker(marker, "relocation-attempted")
        except MarkerError as error:
            if "already exists" not in str(error):
                raise
        else:
            raise AssertionError("existing phase marker was overwritten")

        real = root / "real"
        real.mkdir(mode=0o700)
        linked = root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        try:
            write_marker(linked / "state-migration.attempted", "state-migration-attempted")
        except SecureIOError as error:
            if "symlink" not in str(error):
                raise
        else:
            raise AssertionError("symlinked marker parent was accepted")

    print("cutover phase marker self-test ok (durable, exclusive, no-follow)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
