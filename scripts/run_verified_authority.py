#!/usr/bin/env python3
"""Verify every authority-runtime byte, then execute its pinned interpreter."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PYTHON = Path("/opt/devcoordinator-authority/bin/python")
VERIFIER = ROOT / "scripts/verify_authority_runtime.py"
SAFE_ENVIRONMENT = {
    "DEVCOORDINATOR_AUTHORITY": "service",
    "DOCKER_CONFIG": "/var/lib/devcoordinator/docker",
    "HOME": "/root",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "authority_arguments",
        nargs=argparse.REMAINDER,
        help="arguments after --, beginning with the reviewed Python script",
    )
    value = parser.parse_args(argv)
    if (
        not value.authority_arguments
        or value.authority_arguments[0] != "--"
        or len(value.authority_arguments) < 2
    ):
        parser.error("supply -- followed by one reviewed authority script")
    value.authority_arguments = value.authority_arguments[1:]
    return value


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("verified authority execution requires root", file=sys.stderr)
        return 2
    if not VERIFIER.is_file() or VERIFIER.is_symlink():
        print("authority runtime verifier is missing or linked", file=sys.stderr)
        return 2
    completed = subprocess.run(
        ["/usr/bin/python3", "-I", "-B", str(VERIFIER), "verify"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    if completed.returncode != 0:
        detail = completed.stdout.strip() or completed.stderr.strip()
        print(
            "authority runtime verification failed before execution"
            + (f": {detail}" if detail else ""),
            file=sys.stderr,
        )
        return 1
    arguments = parse_args(argv).authority_arguments
    os.execve(
        str(SYSTEM_PYTHON),
        [str(SYSTEM_PYTHON), "-I", "-B", *arguments],
        dict(SAFE_ENVIRONMENT),
    )
    raise AssertionError("os.execve unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
