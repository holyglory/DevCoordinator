#!/usr/bin/env python3
"""Run the read-only production Console Playwright journey once.

The browser runtime lock is treated as a local software inventory document,
not an inter-account authorization boundary.  The acceptance crawler itself
blocks every mutating browser request and covers every Console route at all
supported desktop/mobile viewports.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping, Sequence


DEFAULT_RUNTIME_LOCK = Path("/var/lib/devcoordinator/browser/runtime-lock.json")
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")


class AcceptanceError(RuntimeError):
    pass


def read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError(f"{label} is unavailable: {error}") from error
    if not isinstance(value, Mapping):
        raise AcceptanceError(f"{label} is not a JSON object")
    return dict(value)


def runtime_paths(path: Path) -> tuple[Path, Path, Path]:
    document = read_object(path, "browser runtime lock")
    node = document.get("node")
    playwright = document.get("playwright")
    browser = document.get("browser")
    if not all(isinstance(item, Mapping) for item in (node, playwright, browser)):
        raise AcceptanceError("browser runtime lock fields are invalid")
    values = (
        Path(str(node.get("executable"))),
        Path(str(playwright.get("runtime_root"))),
        Path(str(browser.get("executable"))),
    )
    if any(not value.is_absolute() for value in values):
        raise AcceptanceError("browser runtime paths must be absolute")
    node_path, playwright_root, browser_path = values
    if not node_path.is_file() or not browser_path.is_file() or not playwright_root.is_dir():
        raise AcceptanceError("browser runtime paths are unavailable")
    return values


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--release", type=Path, required=True)
    result.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    result.add_argument("--output-dir", type=Path, required=True)
    result.add_argument("--base-url", default="https://console.vr.ae/")
    return result


def run(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    release = args.release.expanduser().resolve(strict=True)
    if RELEASE_RE.fullmatch(release.name) is None:
        raise AcceptanceError("release path does not end in one immutable digest")
    output = args.output_dir.expanduser().absolute()
    if output.exists():
        raise AcceptanceError("production acceptance output already exists")
    output.mkdir(parents=True, mode=0o700)
    storage = output / "storage-state.json"
    node, playwright_root, browser = runtime_paths(args.runtime_lock)
    session_tool = release / "apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs"
    acceptance_tool = release / "apps/DevOpsConsole/Tools/production-console-acceptance.mjs"
    for tool in (session_tool, acceptance_tool):
        if not tool.is_file():
            raise AcceptanceError(f"immutable production acceptance tool is missing: {tool}")
    environment = {
        **os.environ,
        "NODE_PATH": str(playwright_root / "node_modules"),
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH": str(browser),
    }
    try:
        session = subprocess.run(
            [str(node), str(session_tool), "--output", str(storage)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=environment,
        )
        if session.returncode != 0:
            raise AcceptanceError(session.stderr.strip() or "browser session preparation failed")
        completed = subprocess.run(
            [
                str(node),
                str(acceptance_tool),
                "--base-url",
                args.base_url,
                "--storage-state",
                str(storage),
                "--output-dir",
                str(output / "playwright"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=environment,
        )
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        return int(completed.returncode)
    finally:
        storage.unlink(missing_ok=True)


def main() -> int:
    try:
        return run()
    except (AcceptanceError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
