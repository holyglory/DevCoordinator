#!/usr/bin/env python3
"""Deterministic source-side efficiency contracts for the thin agent client.

This gate measures elapsed wall time, bytes, and launcher command shapes.  It
does not have access to provider-native model counters and therefore never
reports model tokens as measured.  The token ranges below are deliberately
labelled byte-derived proxies (UTF-8 bytes divided by two through six).

Each timing sample starts a fresh Python interpreter.  This is a cold process
measurement, not a claim that the operating-system page cache is cold.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import time
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"

SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 8 * 1024
DEFAULT_SAMPLES = 5
DEFAULT_MAX_HELP_MEDIAN_MS = 2_000.0
DEFAULT_MAX_IMPORT_MEDIAN_MS = 500.0
EXPECTED_AGGREGATE_OUTPUT_CEILING_BYTES = 18 * 1024
TOKEN_PROXY_MIN_BYTES_PER_TOKEN = 2
TOKEN_PROXY_MAX_BYTES_PER_TOKEN = 6
SUBPROCESS_TIMEOUT_SECONDS = 15

OPERATION_ID = "11111111-1111-4111-8111-111111111111"
RUN_ID = "run-" + "r" * 80
PLAN_ID = "plan-" + "p" * 80
TARGET_SELECTOR = "worker-api"


class GateError(RuntimeError):
    """The source-side agent contract is absent or internally contradictory."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GateError(message)


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a finite positive number") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def _sample_count(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer from 3 through 15") from error
    if not 3 <= parsed <= 15:
        raise argparse.ArgumentTypeError("must be an integer from 3 through 15")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    parser.add_argument("--samples", type=_sample_count, default=DEFAULT_SAMPLES)
    parser.add_argument(
        "--max-help-median-ms",
        type=_positive_float,
        default=DEFAULT_MAX_HELP_MEDIAN_MS,
    )
    parser.add_argument(
        "--max-import-median-ms",
        type=_positive_float,
        default=DEFAULT_MAX_IMPORT_MEDIAN_MS,
    )
    parser.add_argument(
        "--max-aggregate-output-bytes",
        type=int,
        default=EXPECTED_AGGREGATE_OUTPUT_CEILING_BYTES,
    )
    return parser


def _token_proxy(byte_count: int) -> dict[str, Any]:
    if type(byte_count) is not int or byte_count < 0:
        raise GateError("token proxy byte count must be a non-negative integer")
    return {
        "basis": "utf8_bytes_divided_by_2_to_6_not_provider_tokens",
        "maximum": math.ceil(byte_count / TOKEN_PROXY_MIN_BYTES_PER_TOKEN),
        "minimum": math.ceil(byte_count / TOKEN_PROXY_MAX_BYTES_PER_TOKEN),
        "provider_tokens_measured": False,
    }


def _source_environment() -> dict[str, str]:
    environment = dict(os.environ)
    prior = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(MODULE_ROOT) if not prior else str(MODULE_ROOT) + os.pathsep + prior
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _measure(command: Sequence[str], *, samples: int) -> list[float]:
    observed: list[float] = []
    for _index in range(samples):
        started = time.perf_counter_ns()
        completed = subprocess.run(
            list(command),
            cwd=ROOT,
            env=_source_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[:512]
            raise GateError(
                f"timing subprocess exited {completed.returncode}: {detail.strip()}"
            )
        observed.append(round(elapsed_ms, 3))
    return observed


def _timing_result(
    *, name: str, command: Sequence[str], samples: int, maximum_median_ms: float
) -> dict[str, Any]:
    values = _measure(command, samples=samples)
    median = round(float(statistics.median(values)), 3)
    return {
        "contract": {
            "maximum_median_ms": maximum_median_ms,
            "statistic": "median",
        },
        "measurement": "fresh_python_process_wall_time_page_cache_unspecified",
        "name": name,
        "observed_ms": {
            "maximum": max(values),
            "median": median,
            "minimum": min(values),
            "samples": values,
        },
        "ok": median <= maximum_median_ms,
    }


def _command_definitions() -> list[tuple[str, list[str], tuple[str, str]]]:
    return [
        ("capabilities", ["devcoordinator", "capabilities"], ("command", "capabilities")),
        (
            "targets",
            ["devcoordinator", "targets", TARGET_SELECTOR, "--kind", "service"],
            ("command", "targets"),
        ),
        (
            "runtime_ensure",
            [
                "devcoordinator",
                "runtime",
                "ensure",
                TARGET_SELECTOR,
                "--desired",
                "ready",
                "--kind",
                "service",
                "--operation-id",
                OPERATION_ID,
            ],
            ("command", "runtime"),
        ),
        (
            "operation_follow",
            [
                "devcoordinator",
                "operation",
                "follow",
                f"dc1:operation:{OPERATION_ID}",
            ],
            ("command", "operation"),
        ),
        (
            "test_enqueue",
            [
                "devcoordinator",
                "test",
                "enqueue",
                "--intent",
                "change",
                "--operation-id",
                OPERATION_ID,
            ],
            ("command", "test"),
        ),
        (
            "test_follow",
            [
                "devcoordinator",
                "test",
                "follow",
                f"dc1:run:{RUN_ID}",
                "--wait-seconds",
                "30",
            ],
            ("command", "test"),
        ),
    ]


def _command_shapes() -> tuple[list[dict[str, Any]], int]:
    if str(MODULE_ROOT) not in sys.path:
        sys.path.insert(0, str(MODULE_ROOT))
    from devcoordinator import agent_cli

    parser = agent_cli._parser()
    results: list[dict[str, Any]] = []
    total_bytes = 0
    for surface, argv, (field, expected) in _command_definitions():
        namespace = parser.parse_args(argv[1:])
        accepted = getattr(namespace, field, None) == expected
        launcher_invocations = sum(item == "devcoordinator" for item in argv)
        serialized = shlex.join(argv).encode("utf-8")
        byte_count = len(serialized)
        total_bytes += byte_count
        ok = accepted and launcher_invocations == 1
        results.append(
            {
                "argv": argv,
                "caller_launcher_invocations": launcher_invocations,
                "command_utf8_bytes": byte_count,
                "contract_maximum_launcher_invocations": 1,
                "ok": ok,
                "surface": surface,
                "token_proxy": _token_proxy(byte_count),
            }
        )
    return results, total_bytes


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise GateError("efficiency report contains invalid JSON") from error


def _fixture_capabilities() -> dict[str, Any]:
    from devcoordinator.capabilities import broker_capabilities

    return {
        "schema_version": 1,
        "ok": True,
        "repository": {
            "generation": 9_223_372_036_854_775_807,
            "id": "repository-" + "r" * 96,
            "kind": "temporary",
        },
        "capabilities": broker_capabilities(
            protocol_version=1,
            authority_schema_version=13,
            authority_generation="generation-" + "g" * 96,
            active_release_digest="f" * 64,
        ),
    }


def _fixture_targets() -> dict[str, Any]:
    from devcoordinator.agent_projection import project_targets

    identities = [f"service-{index:02d}-" + "i" * 100 for index in range(16)]
    names = [f"worker-{index:02d}-" + "n" * 80 for index in range(16)]
    return project_targets(
        {
            "repository_trees": [
                {
                    "family_id": "family-" + "f" * 64,
                    "root_repository": {"repo_id": "repository-" + "r" * 64},
                    "scopes": [
                        {
                            "repo_id": "repository-" + "r" * 64,
                            "kind": "root",
                            "canonical_root": "/fixture/repository",
                            "server_ids": identities,
                            "container_resource_ids": [],
                            "database_binding_ids": [],
                        }
                    ],
                }
            ],
            "resources": {
                "servers": [
                    {"server_definition_id": identity, "name": name}
                    for identity, name in zip(identities, names, strict=True)
                ],
                "docker": [],
                "databases": [],
            },
            "observations": {
                "servers": [
                    {"server_definition_id": identity, "lifecycle": "running"}
                    for identity in identities
                ],
                "docker": [],
                "databases": [],
            },
        },
        effective_root="/fixture/repository",
        limit=16,
    )


def _fixture_runtime_ensure() -> dict[str, Any]:
    from devcoordinator.runtime_ensure import (
        build_runtime_ensure_result,
        decide_runtime_ensure,
    )

    before = {
        "exact": True,
        "resource_kind": "service",
        "lifecycle": "stopped",
        "health_ok": False,
    }
    after = {
        "exact": True,
        "resource_kind": "service",
        "lifecycle": "running",
        "health_ok": True,
        "health_classification": "healthy-" + "h" * 96,
    }
    return build_runtime_ensure_result(
        operation_id=OPERATION_ID,
        repository_id="repository-" + "r" * 96,
        repository_generation=9_223_372_036_854_775_807,
        resource_kind="service",
        resource_id="service-" + "s" * 112,
        desired_state="ready",
        decision=decide_runtime_ensure(
            before, desired_state="ready", family_classified=True
        ),
        mutation_performed=True,
        terminal_observation=after,
        snapshot_id="snapshot-" + "x" * 96,
        proof_source="broker_runtime_ensure_terminal_observation",
    )


def _fixture_operation_follow(inner_ceiling: int) -> dict[str, Any]:
    from devcoordinator.agent_contract import continuation_handle

    operation: dict[str, Any] = {
        "error_classification": None,
        "kind": "broker.runtime.ensure",
        "next_transition": None,
        "operation_id": OPERATION_ID,
        "outcome_certainty": "certain",
        "phase": "completed",
        "status": "succeeded",
        "target_count": 64,
        "target_ids": [],
        "target_ids_truncated": True,
    }
    for index in range(64):
        candidate = dict(operation)
        candidate["target_ids"] = [
            *operation["target_ids"],
            f"target-{index:02d}-" + "t" * 100,
        ]
        if len(_canonical_bytes(candidate)) > inner_ceiling:
            break
        operation = candidate
    run_handle = continuation_handle("run", RUN_ID)
    return {
        "schema_version": 1,
        "ok": True,
        "classification": "operation_terminal",
        "continuation": continuation_handle("operation", OPERATION_ID),
        "operation": operation,
        "plan_handle": continuation_handle("plan", PLAN_ID),
        "run_handle": run_handle,
        "next_command": f"devcoordinator test follow {run_handle}",
    }


def _fixture_test_enqueue(ceiling: int) -> dict[str, Any]:
    from devcoordinator.agent_contract import continuation_handle
    from devcoordinator.agent_test import child_operation_id

    run_handle = continuation_handle("run", RUN_ID)
    selection: list[str] = []
    base: dict[str, Any] = {
        "schema_version": 1,
        "ok": True,
        "classification": "test_enqueued",
        "continuation": run_handle,
        "operation_id": OPERATION_ID,
        "plan": {
            "fingerprint": "f" * 64,
            "id": PLAN_ID,
            "intent": "change",
            "selection": {"count": 16, "targets": selection, "truncated": False},
            "source": {"mode": "working_tree", "snapshot_id": "snapshot-" + "x" * 80},
        },
        "repository_id": "repository-" + "r" * 96,
        "run": {"id": RUN_ID, "state": "queued"},
        "submission_operation_id": child_operation_id(OPERATION_ID, "submit"),
        "submission_performed": True,
        "next_command": f"devcoordinator test follow {run_handle}",
    }
    for index in range(16):
        candidate = json.loads(_canonical_bytes(base))
        candidate["plan"]["selection"]["targets"] = [
            *selection,
            f"target-{index:02d}-" + "t" * 100,
        ]
        if len(_canonical_bytes(candidate)) > ceiling:
            base["plan"]["selection"]["truncated"] = True
            break
        selection = candidate["plan"]["selection"]["targets"]
        base = candidate
    base["plan"]["selection"]["targets"] = selection
    return base


def _fixture_test_follow() -> dict[str, Any]:
    from devcoordinator.agent_test import project_test_follow

    numeric = {f"metric-{index}-" + "m" * 48: 10**12 + index for index in range(12)}
    failures = [
        {
            "artifact_id": f"artifact-{index}-" + "a" * 240,
            "classification": f"test-failure-{index}-" + "c" * 240,
            "location": f"suite-{index}-" + "l" * 240,
            "message": f"failure-{index}-" + "m" * 320,
            "target": f"target-{index}-" + "t" * 240,
        }
        for index in range(3)
    ]
    return project_test_follow(
        {"run_id": RUN_ID, "state": "failed", "wait_timed_out": False},
        run_id=RUN_ID,
        summary={
            "conclusion": "failed",
            "counts": {**numeric, **{f"count-{index}": index for index in range(4)}},
            "failure_count": 3,
            "failures": failures,
            "progress": numeric,
            "run_id": RUN_ID,
            "timing": numeric,
        },
    )


def _output_contracts(
    *, maximum_aggregate_bytes: int
) -> tuple[dict[str, Any], list[str]]:
    if str(MODULE_ROOT) not in sys.path:
        sys.path.insert(0, str(MODULE_ROOT))
    from devcoordinator.agent_cli import (
        MAX_CAPABILITIES_RESULT_BYTES,
        MAX_OPERATION_FOLLOW_RESULT_BYTES,
    )
    from devcoordinator.agent_projection import MAX_TARGET_RESULT_BYTES
    from devcoordinator.agent_test import MAX_TEST_RESULT_BYTES
    from devcoordinator.broker_persistence import OPERATION_FOLLOW_MAX_BYTES
    from devcoordinator.runtime_ensure import RUNTIME_ENSURE_RESULT_MAX_BYTES

    definitions = [
        ("capabilities", MAX_CAPABILITIES_RESULT_BYTES, _fixture_capabilities()),
        ("targets", MAX_TARGET_RESULT_BYTES, _fixture_targets()),
        (
            "runtime_ensure",
            RUNTIME_ENSURE_RESULT_MAX_BYTES,
            _fixture_runtime_ensure(),
        ),
        (
            "operation_follow",
            MAX_OPERATION_FOLLOW_RESULT_BYTES,
            _fixture_operation_follow(OPERATION_FOLLOW_MAX_BYTES),
        ),
        ("test_enqueue", MAX_TEST_RESULT_BYTES, _fixture_test_enqueue(MAX_TEST_RESULT_BYTES)),
        ("test_follow", MAX_TEST_RESULT_BYTES, _fixture_test_follow()),
    ]
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    aggregate_ceiling = 0
    aggregate_fixture = 0
    for surface, ceiling, fixture in definitions:
        fixture_bytes = len(_canonical_bytes(fixture))
        aggregate_ceiling += ceiling
        aggregate_fixture += fixture_bytes
        ok = fixture_bytes <= ceiling
        if not ok:
            failures.append(f"{surface}_fixture_exceeds_output_ceiling")
        row: dict[str, Any] = {
            "ceiling_bytes": ceiling,
            "fixture_bytes": fixture_bytes,
            "fixture_headroom_bytes": ceiling - fixture_bytes,
            "ok": ok,
            "surface": surface,
            "token_proxy_at_ceiling": _token_proxy(ceiling),
            "token_proxy_for_fixture": _token_proxy(fixture_bytes),
        }
        if surface == "operation_follow":
            row["authority_projection_ceiling_bytes"] = OPERATION_FOLLOW_MAX_BYTES
        rows.append(row)
    aggregate_ok = (
        aggregate_ceiling <= maximum_aggregate_bytes
        and maximum_aggregate_bytes > 0
    )
    if not aggregate_ok:
        failures.append("aggregate_output_ceiling_exceeded")
    return (
        {
            "aggregate": {
                "ceiling_bytes": aggregate_ceiling,
                "contract_maximum_ceiling_bytes": maximum_aggregate_bytes,
                "fixture_bytes": aggregate_fixture,
                "ok": aggregate_ok,
                "token_proxy_at_ceiling": _token_proxy(aggregate_ceiling),
                "token_proxy_for_fixture": _token_proxy(aggregate_fixture),
            },
            "surfaces": rows,
        },
        failures,
    )


def build_report(namespace: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    timings = [
        _timing_result(
            name="devcoordinator_help",
            command=[sys.executable, "-m", "devcoordinator.agent_cli", "--help"],
            samples=namespace.samples,
            maximum_median_ms=namespace.max_help_median_ms,
        ),
        _timing_result(
            name="devcoordinator_package_import",
            command=[sys.executable, "-c", "import devcoordinator"],
            samples=namespace.samples,
            maximum_median_ms=namespace.max_import_median_ms,
        ),
    ]
    for timing in timings:
        if timing["ok"] is not True:
            failures.append(f"{timing['name']}_timing_contract_exceeded")

    shapes, shape_bytes = _command_shapes()
    for shape in shapes:
        if shape["ok"] is not True:
            failures.append(f"{shape['surface']}_command_shape_invalid")
    outputs, output_failures = _output_contracts(
        maximum_aggregate_bytes=namespace.max_aggregate_output_bytes
    )
    failures.extend(output_failures)

    document: dict[str, Any] = {
        "classification": (
            "agent_client_efficiency_contract_satisfied"
            if not failures
            else "agent_client_efficiency_contract_failed"
        ),
        "command_shapes": {
            "aggregate_command_utf8_bytes": shape_bytes,
            "aggregate_token_proxy": _token_proxy(shape_bytes),
            "surfaces": shapes,
        },
        "compact_outputs": outputs,
        "failures": sorted(set(failures)),
        "methodology": {
            "provider_tokens_measured": False,
            "timing": "fresh_process_wall_time_page_cache_unspecified",
            "token_proxy": "ceil(utf8_bytes/6)..ceil(utf8_bytes/2)",
        },
        "ok": not failures,
        "schema_version": SCHEMA_VERSION,
        "timing": timings,
    }
    return document


def _emit(document: dict[str, Any]) -> None:
    payload = _canonical_bytes(document) + b"\n"
    if len(payload) > MAX_REPORT_BYTES:
        raise GateError(
            f"efficiency report exceeds its {MAX_REPORT_BYTES}-byte output contract"
        )
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        namespace = _parser().parse_args(list(argv) if argv is not None else None)
        if namespace.max_aggregate_output_bytes <= 0:
            raise GateError("aggregate output byte threshold must be positive")
        report = build_report(namespace)
    except (GateError, OSError, subprocess.SubprocessError, ValueError) as error:
        report = {
            "classification": "agent_client_efficiency_gate_error",
            "error": " ".join(str(error).split())[:512],
            "failures": ["gate_execution_failed"],
            "methodology": {
                "provider_tokens_measured": False,
                "token_proxy": "not_available",
            },
            "ok": False,
            "schema_version": SCHEMA_VERSION,
        }
    try:
        _emit(report)
    except GateError as error:
        # Contract drift must still produce one small machine-readable failure,
        # rather than a traceback or an unbounded copy of the oversized report.
        report = {
            "classification": "agent_client_efficiency_gate_error",
            "error": " ".join(str(error).split())[:512],
            "failures": ["gate_output_contract_failed"],
            "methodology": {
                "provider_tokens_measured": False,
                "token_proxy": "not_available",
            },
            "ok": False,
            "schema_version": SCHEMA_VERSION,
        }
        _emit(report)
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
