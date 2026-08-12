#!/usr/bin/env python3
"""Run the complete DevOps Console suite with the installed browser runtime."""

from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "apps" / "DevOpsConsole" / "test"
DEFAULT_BROWSER_RUNTIME_LOCK = Path("/etc/devcoordinator/browser-runtime-lock.json")


def discover_tests() -> tuple[Path, ...]:
    """Return the package-public Console test set in deterministic order."""

    return tuple(sorted(TEST_ROOT.glob("*.test.mjs")))


def test_runtime() -> tuple[str, dict[str, str]]:
    """Return Node and environment bound to the installed locked Playwright tree."""

    environment = dict(os.environ)
    node = "node"
    try:
        document = json.loads(DEFAULT_BROWSER_RUNTIME_LOCK.read_text(encoding="utf-8"))
        locked_node = document["node"]["executable"]
        playwright_root = document["playwright"]["runtime_root"]
        browser = document["browser"]["executable"]
        if not all(isinstance(value, str) and Path(value).is_absolute() for value in (
            locked_node,
            playwright_root,
            browser,
        )):
            raise ValueError("browser runtime paths are invalid")
        if not Path(locked_node).is_file() or not Path(playwright_root).is_dir() \
                or not Path(browser).is_file():
            raise ValueError("browser runtime is incomplete")
        node = locked_node
        environment["NODE_PATH"] = str(Path(playwright_root) / "node_modules")
        environment["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"] = browser
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        # A source-only checkout may supply the same locked dependency through
        # NODE_PATH or ci/playwright/node_modules. Browser tests still validate
        # the exact package version and report a precise missing-runtime error.
        pass
    return node, environment


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
    node, environment = test_runtime()
    completed = subprocess.run(
        [node, "--test", *(str(path.relative_to(ROOT)) for path in tests)],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
