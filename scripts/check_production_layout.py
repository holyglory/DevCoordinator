#!/usr/bin/env python3
"""Validate private, external DevCoordinator production paths before cutover."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


class LayoutError(RuntimeError):
    pass


def within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def lexical_path(raw: str, *, home: Path, base: Path | None = None) -> Path:
    value = raw.strip()
    if value == "~":
        return home
    if value.startswith("~/"):
        return home / value[2:]
    path = Path(value)
    if not path.is_absolute():
        if base is None:
            raise LayoutError(f"production path must be absolute or home-relative: {raw!r}")
        path = base / path
    return path


def no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise LayoutError(f"production path contains a symlink component: {current}")


def require_directory(path: Path, mode: int, label: str) -> Path:
    no_symlink_components(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise LayoutError(f"{label} directory is missing: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise LayoutError(f"{label} must be a real directory: {path}")
    actual = stat.S_IMODE(metadata.st_mode)
    if actual != mode:
        raise LayoutError(f"{label} mode must be {mode:04o}, got {actual:04o}: {path}")
    if metadata.st_uid != os.getuid():
        raise LayoutError(f"{label} is not owned by the service user: {path}")
    return path.resolve(strict=True)


def require_file(path: Path, mode: int, label: str) -> Path:
    no_symlink_components(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise LayoutError(f"{label} file is missing: {path}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LayoutError(f"{label} must be a regular non-symlink file: {path}")
    actual = stat.S_IMODE(metadata.st_mode)
    if actual != mode:
        raise LayoutError(f"{label} mode must be {mode:04o}, got {actual:04o}: {path}")
    if metadata.st_uid != os.getuid():
        raise LayoutError(f"{label} is not owned by the service user: {path}")
    return path.resolve(strict=True)


def require_private_tree(root: Path, label: str) -> None:
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise LayoutError(f"{label} contains a symlink: {path}")
            if metadata.st_uid != os.getuid():
                raise LayoutError(f"{label} contains an object not owned by the service user: {path}")
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o077:
                raise LayoutError(f"{label} contains a group/world-accessible object ({mode:04o}): {path}")


def parse_env_paths(path: Path) -> dict[str, str]:
    selected = {
        "ACME_WEBROOT",
        "CODEX_AGENT_COORDINATOR_HOME",
        "STATE_DIR",
    }
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, value = line.split("=", 1)
        key = key.strip()
        if key in selected:
            values[key] = value.strip().strip("\"'")
    return values


def check_layout(
    *,
    repo_root: Path,
    home: Path,
    env_file: Path,
    state_dir: Path,
    acme_webroot: Path,
    coordinator_home: Path,
) -> dict[str, object]:
    no_symlink_components(repo_root)
    repo = repo_root.resolve(strict=True)
    if not repo.is_dir() or not (repo / "apps/DevOpsConsole").is_dir():
        raise LayoutError(f"DevCoordinator repository is invalid: {repo}")

    env = require_file(env_file, 0o600, "Console environment")
    state = require_directory(state_dir, 0o700, "Console state")
    acme = require_directory(acme_webroot, 0o700, "ACME webroot")
    coordinator = require_directory(coordinator_home, 0o700, "coordinator home")
    require_private_tree(state, "Console state")
    require_private_tree(coordinator, "coordinator home")

    named = {
        "environment": env,
        "state": state,
        "acme": acme,
        "coordinator_home": coordinator,
    }
    for label, path in named.items():
        if within(path, repo):
            raise LayoutError(f"{label} path must stay outside Git: {path}")
    if not within(acme, state):
        raise LayoutError(f"ACME webroot must be inside the external Console state directory: {acme}")

    app_root = repo / "apps/DevOpsConsole"
    for key, raw in parse_env_paths(env).items():
        if not raw:
            continue
        configured = lexical_path(raw, home=home, base=app_root).resolve(strict=False)
        if within(configured, repo):
            raise LayoutError(f"{key} in the preserved environment points inside Git")

    return {
        "ok": True,
        "paths": {key: str(value) for key, value in named.items()},
        "modes": {"environment": "0600", "state": "0700", "acme": "0700", "coordinator_home": "0700"},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--acme-webroot", required=True)
    parser.add_argument("--coordinator-home", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    home = Path(args.home).expanduser().absolute()
    try:
        report = check_layout(
            repo_root=lexical_path(args.repo_root, home=home),
            home=home,
            env_file=lexical_path(args.env_file, home=home),
            state_dir=lexical_path(args.state_dir, home=home),
            acme_webroot=lexical_path(args.acme_webroot, home=home),
            coordinator_home=lexical_path(args.coordinator_home, home=home),
        )
    except (LayoutError, OSError, UnicodeDecodeError) as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}, indent=2, sort_keys=True))
        else:
            print(f"production layout preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else "production layout preflight ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
