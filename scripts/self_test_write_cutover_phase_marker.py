#!/usr/bin/env python3
"""Durability/refusal tests for private cutover phase markers."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from secure_cutover_io import SecureIOError
from write_cutover_phase_marker import MarkerError, SUPPORTED_PHASES, write_marker


SCRIPT = Path(__file__).with_name("write_cutover_phase_marker.py")
EXPECTED_PHASES = (
    "cutover-run-started",
    "service-stop-attempted",
    "state-migration-attempted",
    "relocation-attempted",
    "cutover-success",
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cutover-phase-marker-") as raw:
        root = Path(raw).resolve(strict=True)
        if SUPPORTED_PHASES != EXPECTED_PHASES:
            raise AssertionError(
                "marker lifecycle contract changed: "
                f"expected {EXPECTED_PHASES}, found {SUPPORTED_PHASES}"
            )
        direct = root / "direct"
        direct.mkdir(mode=0o700)
        for phase in EXPECTED_PHASES:
            marker = direct / f"{phase}.json"
            report = write_marker(marker, phase)
            if report["phase"] != phase:
                raise AssertionError(f"marker recorded the wrong phase for {phase}")
            if stat.S_IMODE(marker.stat().st_mode) != 0o600:
                raise AssertionError(f"marker is not private for {phase}")
            if json.loads(marker.read_text(encoding="utf-8"))["phase"] != phase:
                raise AssertionError(f"marker contents were not durable for {phase}")

        marker = direct / "relocation-attempted.json"
        try:
            write_marker(marker, "relocation-attempted")
        except MarkerError as error:
            if "already exists" not in str(error):
                raise
        else:
            raise AssertionError("existing phase marker was overwritten")

        # Exercise the exact subprocess CLI used by a private cutover script.
        # Direct-function coverage alone cannot catch stale argparse choices.
        cli = root / "cli"
        cli.mkdir(mode=0o700)
        for phase in EXPECTED_PHASES:
            cli_marker = cli / f"{phase}.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--marker",
                    str(cli_marker),
                    "--phase",
                    phase,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"marker CLI rejected supported phase {phase}: {completed.stderr}"
                )
            output = json.loads(completed.stdout)
            if output.get("ok") is not True or output.get("phase") != phase:
                raise AssertionError(f"marker CLI returned wrong output for {phase}: {output}")
            if json.loads(cli_marker.read_text(encoding="utf-8"))["phase"] != phase:
                raise AssertionError(f"marker CLI wrote the wrong phase for {phase}")

        try:
            write_marker(root / "unsupported.json", "unsupported-phase")
        except MarkerError as error:
            if "unsupported cutover phase" not in str(error):
                raise
        else:
            raise AssertionError("unsupported cutover phase was accepted")

        # Recall proof: reproduce the shipped regression shape by removing the
        # service-stop phase from a copied helper. The independently declared
        # lifecycle contract must make the copied self-test fail before it can
        # report success.
        mutation = root / "missing-service-stop-phase"
        mutation.mkdir(mode=0o700)
        helper_text = SCRIPT.read_text(encoding="utf-8")
        needle = '    "service-stop-attempted",\n'
        if helper_text.count(needle) != 1:
            raise AssertionError("phase mutation fixture cannot identify the helper contract")
        (mutation / SCRIPT.name).write_text(
            helper_text.replace(needle, ""),
            encoding="utf-8",
        )
        copied_self_test = mutation / Path(__file__).name
        copied_self_test.write_bytes(Path(__file__).read_bytes())
        mutation_env = os.environ.copy()
        mutation_env["PYTHONPATH"] = str(SCRIPT.parent)
        missing_phase = subprocess.run(
            [sys.executable, str(copied_self_test)],
            check=False,
            capture_output=True,
            text=True,
            env=mutation_env,
        )
        if missing_phase.returncode == 0:
            raise AssertionError("self-test missed a helper with service-stop phase removed")
        if "marker lifecycle contract changed" not in missing_phase.stderr:
            raise AssertionError(
                "missing-phase mutation failed for the wrong reason: "
                f"{missing_phase.stdout}{missing_phase.stderr}"
            )

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

    print("cutover phase marker self-test ok (full CLI lifecycle, durable, exclusive, no-follow)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
