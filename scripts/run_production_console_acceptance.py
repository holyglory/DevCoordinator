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
import stat
import subprocess
import sys
from typing import Mapping, Sequence


DEFAULT_RUNTIME_LOCK = Path("/etc/devcoordinator/browser-runtime-lock.json")
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_STORAGE_STATE_BYTES = 1024 * 1024


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


def validated_storage_state(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise AcceptanceError(f"browser storage state is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceError("browser storage state must be one regular non-symlink file")
    if metadata.st_uid != os.getuid():
        raise AcceptanceError("browser storage state is not owned by the acceptance caller")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AcceptanceError("browser storage state must have mode 0600")
    if not 1 <= metadata.st_size <= MAX_STORAGE_STATE_BYTES:
        raise AcceptanceError("browser storage state has an invalid bounded size")
    document = read_object(candidate, "browser storage state")
    if (
        set(document) != {"cookies", "origins"}
        or not isinstance(document.get("cookies"), list)
        or not isinstance(document.get("origins"), list)
    ):
        raise AcceptanceError("browser storage state fields are invalid")
    return candidate


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--release", type=Path, required=True)
    result.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    result.add_argument("--output-dir", type=Path, required=True)
    result.add_argument("--storage-state", type=Path)
    result.add_argument("--consume-storage-state", action="store_true")
    result.add_argument("--base-url", default="https://console.vr.ae/")
    return result


def execute_acceptance(
    *,
    release: Path,
    output: Path,
    storage: Path,
    runtime_lock: Path,
    base_url: str,
    generated_storage: bool,
) -> int:
    node, playwright_root, browser = runtime_paths(runtime_lock)
    session_tool = release / "apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs"
    acceptance_tool = release / "apps/DevOpsConsole/Tools/production-console-acceptance.mjs"
    required_tools = (
        (session_tool, acceptance_tool)
        if generated_storage
        else (acceptance_tool,)
    )
    for tool in required_tools:
        if not tool.is_file():
            raise AcceptanceError(f"immutable production acceptance tool is missing: {tool}")
    environment = {
        **os.environ,
        "NODE_PATH": str(playwright_root / "node_modules"),
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH": str(browser),
    }
    if generated_storage:
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
            raise AcceptanceError(
                session.stderr.strip() or "browser session preparation failed"
            )
    completed = subprocess.run(
        [
            str(node),
            str(acceptance_tool),
            "--base-url",
            base_url,
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


def run(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    release = args.release.expanduser().resolve(strict=True)
    if RELEASE_RE.fullmatch(release.name) is None:
        raise AcceptanceError("release path does not end in one immutable digest")
    output = args.output_dir.expanduser().absolute()
    if output.exists():
        raise AcceptanceError("production acceptance output already exists")
    output.mkdir(parents=True, mode=0o700)
    if args.consume_storage_state and args.storage_state is None:
        raise AcceptanceError("--consume-storage-state requires --storage-state")
    generated_storage = args.storage_state is None
    storage = (
        output / "storage-state.json"
        if generated_storage
        else validated_storage_state(args.storage_state)
    )
    try:
        return execute_acceptance(
            release=release,
            output=output,
            storage=storage,
            runtime_lock=args.runtime_lock,
            base_url=args.base_url,
            generated_storage=generated_storage,
        )
    finally:
        if generated_storage or args.consume_storage_state:
            storage.unlink(missing_ok=True)


def main() -> int:
    try:
        return run()
    except (AcceptanceError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
