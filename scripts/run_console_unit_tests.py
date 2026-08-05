#!/usr/bin/env python3
"""Run the complete non-browser DevOps Console suite without shell globbing."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "apps" / "DevOpsConsole" / "test"


def discover_tests() -> tuple[Path, ...]:
    """Return the package-public Console test set in deterministic order."""

    return tuple(sorted(TEST_ROOT.glob("*.test.mjs")))


def main() -> int:
    # Keep the manifest-owned Console target identical to the package's public
    # test entrypoint.  Restricting discovery to ``unit*.test.mjs`` silently
    # omitted the browser-fixture, end-to-end, cutover, edge-isolation and
    # Telegram integration contracts when repository validation ran in
    # harness mode.
    tests = discover_tests()
    if not tests:
        print("no DevOps Console tests were discovered", file=sys.stderr)
        return 2
    completed = subprocess.run(
        ["node", "--test", *(str(path.relative_to(ROOT)) for path in tests)],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
