#!/usr/bin/env python3
"""Run the fast release gate without replaying harness-owned test suites.

The five ordinary harness targets own Console and Coordinator behavioral tests.
This command owns only cheap repository-wide release checks: diff cleanliness,
immutable-release syntax, the test manifest/partition contract, skill metadata,
availability topology, and repository boundaries.  Compatibility, provenance,
legacy migration, and destructive recovery suites remain explicit manual or
nightly validation and are intentionally absent here.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = ROOT / "scripts"
COORDINATOR_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
for path in (SCRIPT_ROOT, COORDINATOR_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import install_availability_release as release_installer  # noqa: E402
import run_coordinator_test_partition as coordinator_partitions  # noqa: E402
from devcoordinator.universal_test_contract import load_test_manifest  # noqa: E402


MAX_DETAIL = 16 * 1024


@dataclass(frozen=True)
class Result:
    name: str
    ok: bool
    duration_ms: int
    detail: str


def bounded(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_DETAIL:
        return encoded.decode("utf-8", errors="replace")
    return encoded[:MAX_DETAIL].decode("utf-8", errors="replace") + "\n[truncated]"


def external(name: str, argv: Sequence[str]) -> Result:
    started = time.monotonic()
    completed = subprocess.run(
        list(argv),
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    detail = "\n".join(
        item for item in (completed.stdout.strip(), completed.stderr.strip()) if item
    )
    return Result(
        name=name,
        ok=completed.returncode == 0,
        duration_ms=int((time.monotonic() - started) * 1000),
        detail=bounded(detail),
    )


def internal(name: str, operation: Callable[[], str]) -> Result:
    started = time.monotonic()
    try:
        detail = operation()
        ok = True
    except BaseException as error:  # collect every independent gate in one pass
        detail = f"{type(error).__name__}: {error}"
        ok = False
    return Result(
        name=name,
        ok=ok,
        duration_ms=int((time.monotonic() - started) * 1000),
        detail=bounded(detail),
    )


def release_syntax() -> str:
    entries, payloads = release_installer.release_inputs(ROOT)
    python_count = 0
    javascript: list[Path] = []
    json_count = 0
    errors: list[str] = []
    for entry in entries:
        relative = Path(str(entry["path"]))
        payload = payloads[relative.as_posix()]
        if relative.suffix == ".py":
            python_count += 1
            try:
                compile(payload, str(relative), "exec", dont_inherit=True)
            except (SyntaxError, ValueError, TypeError) as error:
                errors.append(f"{relative}: {error}")
        elif relative.suffix in {".js", ".mjs"}:
            javascript.append(ROOT / relative)
        elif relative.suffix == ".json":
            json_count += 1
            try:
                json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                errors.append(f"{relative}: {error}")
    for path in javascript:
        completed = subprocess.run(
            ["/usr/bin/node", "--check", str(path)],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            errors.append(f"{path.relative_to(ROOT)}: {completed.stderr.strip()}")
    if errors:
        raise RuntimeError("; ".join(errors))
    return (
        f"immutable release syntax ok: {python_count} Python, "
        f"{len(javascript)} JavaScript, {json_count} JSON files"
    )


def manifest_contract() -> str:
    manifest = load_test_manifest(ROOT)
    evidence_targets = {
        "console-tests",
        "coordinator-broker-authority",
        "coordinator-resources-storage",
        "coordinator-runtime-lifecycle",
        "coordinator-universal-harness",
        "repository-validation",
    }
    if set(manifest.evidence_policies["handoff"].required_targets) != evidence_targets:
        raise RuntimeError("handoff evidence target set is incomplete")
    if set(manifest.evidence_policies["release"].required_targets) != evidence_targets:
        raise RuntimeError("release evidence target set is incomplete")
    probe = manifest.targets.get("software-delivery-runner-probe")
    if (
        probe is None
        or tuple(probe.argv)
        != ("{python}", "scripts/self_test_software_owned_delivery.py")
        or tuple(probe.intents) != ("manual",)
    ):
        raise RuntimeError("software delivery runner probe is not manual-only")
    validation = manifest.targets["repository-validation"]
    if tuple(validation.argv) != ("{python}", "scripts/run_fast_repository_validation.py"):
        raise RuntimeError("repository-validation still invokes a legacy/full validation path")
    partition_errors = coordinator_partitions.partition_contract_errors()
    if partition_errors:
        raise RuntimeError("; ".join(partition_errors))
    if coordinator_partitions.non_gate_compatibility_modules() != (
        "test_universal_test_migration",
    ):
        raise RuntimeError("legacy test-history migration is not isolated from normal gates")
    return "manifest, six evidence targets, and manual runner probe ok"


def skill_contract() -> str:
    checked: list[str] = []
    for name in ("codex-dev-coordinator", "postgres-docker-backup"):
        root = ROOT / "skills" / name
        skill = root / "SKILL.md"
        if not skill.is_file() or skill.is_symlink():
            raise RuntimeError(f"canonical skill source is unavailable: {skill}")
        lines = skill.read_text(encoding="utf-8").splitlines()
        if len(lines) < 4 or lines[0] != "---":
            raise RuntimeError(f"{name} skill frontmatter is missing")
        try:
            end = lines.index("---", 1)
        except ValueError as error:
            raise RuntimeError(f"{name} skill frontmatter is unterminated") from error
        metadata: dict[str, str] = {}
        for line in lines[1:end]:
            key, separator, value = line.partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
        if metadata.get("name") != name or not metadata.get("description"):
            raise RuntimeError(f"{name} skill name/description is invalid")
        scripts = root / "scripts"
        if not scripts.is_dir() or not any(scripts.glob("*.py")):
            raise RuntimeError(f"{name} skill has no executable scripts")
        checked.append(name)
    return "canonical skill metadata ok: " + ", ".join(checked)


def emit_cases(results: Sequence[Result]) -> None:
    raw = os.environ.get("DEVCOORDINATOR_TEST_EVENTS")
    if not raw:
        return
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeError("DEVCOORDINATOR_TEST_EVENTS must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(
                json.dumps(
                    {
                        "case_id": f"repository-validation::{result.name}",
                        "name": result.name,
                        "status": "passed" if result.ok else "failed",
                        "duration_seconds": result.duration_ms / 1000,
                        **({} if result.ok else {"message": result.detail}),
                    },
                    sort_keys=True,
                )
                + "\n"
            )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-diff",
        action="store_true",
        help="omit git diff --check when an outer delivery batch already owns it",
    )
    parser.add_argument("--max-parallel", type=int, default=4)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    checks: list[tuple[str, Callable[[], Result]]] = [
        ("release-syntax", lambda: internal("release-syntax", release_syntax)),
        ("test-manifest", lambda: internal("test-manifest", manifest_contract)),
        ("skill-contract", lambda: internal("skill-contract", skill_contract)),
        (
            "availability-topology",
            lambda: external(
                "availability-topology",
                [sys.executable, "scripts/check_availability_topology.py", "--json"],
            ),
        ),
        (
            "single-developer-local-trust",
            lambda: external(
                "single-developer-local-trust",
                [
                    sys.executable,
                    "scripts/check_single_developer_local_trust.py",
                    "--json",
                ],
            ),
        ),
        (
            "repository-boundaries",
            lambda: external(
                "repository-boundaries",
                [
                    sys.executable,
                    "scripts/check_repository_boundaries.py",
                    "--repo",
                    str(ROOT),
                ],
            ),
        ),
    ]
    if not args.skip_diff and (ROOT / ".git").exists():
        checks.insert(
            0,
            (
                "diff-check",
                lambda: external("diff-check", ["/usr/bin/git", "diff", "--check"]),
            ),
        )
    ordered: dict[int, Result] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(int(args.max_parallel), 8))) as pool:
        futures = {
            pool.submit(operation): index
            for index, (_name, operation) in enumerate(checks)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                ordered[index] = future.result()
            except BaseException as error:
                ordered[index] = Result(
                    name=checks[index][0],
                    ok=False,
                    duration_ms=0,
                    detail=bounded(f"{type(error).__name__}: {error}"),
                )
    results = [ordered[index] for index in range(len(checks))]
    emit_cases(results)
    payload = {
        "ok": all(result.ok for result in results),
        "checks": [
            {
                "name": result.name,
                "ok": result.ok,
                "duration_ms": result.duration_ms,
                "detail": result.detail,
            }
            for result in results
        ],
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
