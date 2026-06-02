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


def main() -> int:
    check_vendor_sync()
    check_include_glob_exclusions()
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
            "skills/trace-fix-root-causes/scripts",
            "skills/ui-implementation-audit/scripts",
            "skills/user-journey-docs-audit/scripts",
        ]
    )
    for skill in SKILLS:
        check_standalone_skill(skill)
    print("validation ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
