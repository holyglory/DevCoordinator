#!/usr/bin/env python3
"""Behavioral self-test for the source-side agent-client efficiency gate."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_agent_client_efficiency.py"
MAX_REPORT_BYTES = 8 * 1024
EXPECTED_SURFACES = [
    "capabilities",
    "targets",
    "runtime_ensure",
    "operation_follow",
    "test_enqueue",
    "test_follow",
]


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def invoke(prefix: Sequence[str], *arguments: str) -> tuple[int, dict[str, Any], bytes]:
    completed = subprocess.run(
        [*prefix, str(CHECKER), "--samples", "3", *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=90,
    )
    expect(completed.stdout.endswith(b"\n"), "checker output lacks one final newline")
    expect(
        len(completed.stdout) <= MAX_REPORT_BYTES,
        "checker exceeded its final output byte contract",
    )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"checker did not return JSON: {completed.stdout[:512]!r}"
        ) from error
    expect(isinstance(document, dict), "checker JSON is not an object")
    return completed.returncode, document, completed.stderr


def validate_success(document: dict[str, Any]) -> None:
    expect(document.get("ok") is True, f"checker failed: {document}")
    expect(document.get("schema_version") == 1, "checker schema changed")
    methodology = document.get("methodology")
    expect(isinstance(methodology, dict), "methodology is absent")
    expect(
        methodology.get("provider_tokens_measured") is False,
        "byte proxy was misrepresented as provider token measurement",
    )
    shapes = document.get("command_shapes")
    expect(isinstance(shapes, dict), "command-shape report is absent")
    rows = shapes.get("surfaces")
    expect(isinstance(rows, list), "command-shape rows are absent")
    expect(
        [row.get("surface") for row in rows if isinstance(row, dict)]
        == EXPECTED_SURFACES,
        "caller surfaces or their stable order changed",
    )
    for row in rows:
        expect(isinstance(row, dict), "command-shape row is malformed")
        expect(
            row.get("caller_launcher_invocations") == 1,
            "caller needs more than one invocation",
        )
        expect(row.get("ok") is True, "one caller command shape is not executable")
        proxy = row.get("token_proxy")
        expect(isinstance(proxy, dict), "command token proxy is absent")
        expect(proxy.get("provider_tokens_measured") is False, "proxy is labelled as measurement")

    compact = document.get("compact_outputs")
    expect(isinstance(compact, dict), "compact output report is absent")
    output_rows = compact.get("surfaces")
    expect(isinstance(output_rows, list), "compact output rows are absent")
    expect(
        [row.get("surface") for row in output_rows if isinstance(row, dict)]
        == EXPECTED_SURFACES,
        "compact output surfaces changed",
    )
    for row in output_rows:
        expect(isinstance(row, dict), "compact output row is malformed")
        expect(row.get("fixture_bytes", 1) > 0, "fixture bytes were not observed")
        expect(row.get("fixture_bytes") <= row.get("ceiling_bytes"), "fixture exceeds ceiling")
        expect(row.get("ok") is True, "compact output contract failed")

    timings = document.get("timing")
    expect(isinstance(timings, list) and len(timings) == 2, "timing report is incomplete")
    for timing in timings:
        expect(isinstance(timing, dict), "timing row is malformed")
        observed = timing.get("observed_ms")
        contract = timing.get("contract")
        expect(isinstance(observed, dict), "observed timing is absent")
        expect(isinstance(contract, dict), "timing contract is absent")
        expect(len(observed.get("samples", [])) == 3, "timing sample count changed")
        expect(contract.get("statistic") == "median", "timing threshold is not robust median")


def run_mode(prefix: Sequence[str]) -> None:
    success_code, success, stderr = invoke(
        prefix,
        "--max-help-median-ms",
        "10000",
        "--max-import-median-ms",
        "10000",
    )
    expect(success_code == 0, f"success gate exited {success_code}: {stderr!r}")
    validate_success(success)

    failure_code, failure, stderr = invoke(
        prefix,
        "--max-help-median-ms",
        "0.001",
        "--max-import-median-ms",
        "10000",
    )
    expect(failure_code == 1, f"must-fail gate exited {failure_code}: {stderr!r}")
    expect(failure.get("ok") is False, "must-fail threshold returned ok")
    expect(
        "devcoordinator_help_timing_contract_exceeded" in failure.get("failures", []),
        "must-fail timing threshold was not identified",
    )
    expect(
        failure.get("classification") == "agent_client_efficiency_contract_failed",
        "threshold failure was confused with checker execution failure",
    )


def main() -> int:
    expect(CHECKER.is_file(), "agent-client efficiency checker is missing")
    # Exercise the checker under both Python semantic modes.  The self-test
    # itself also avoids assert so running this file with -O remains meaningful.
    run_mode([sys.executable])
    run_mode([sys.executable, "-O"])
    print("agent client efficiency self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
