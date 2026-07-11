#!/usr/bin/env python3
"""Safety and false-positive tests for the production layout preflight."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path
from shutil import rmtree


SCRIPT = Path(__file__).with_name("check_production_layout.py")
spec = importlib.util.spec_from_file_location("check_production_layout", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot import production layout guard")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def expect_error(call, contains: str) -> None:
    try:
        call()
    except guard.LayoutError as error:
        if contains.lower() not in str(error).lower():
            raise AssertionError(f"expected {contains!r} in {error!r}") from error
        return
    raise AssertionError("expected production layout rejection")


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="devcoordinator-production-layout-"))
    try:
        repo = root / "DevCoordinator"
        mkdir(repo / "apps/DevOpsConsole", 0o755)
        home = root / "home/operator"
        config = home / ".config/devops-console"
        state = home / ".local/state/devops-console"
        acme = state / "acme"
        coordinator = home / ".codex/agent-coordinator"
        for directory in (config, state, acme, coordinator):
            mkdir(directory)
        env = config / "console.env"
        token = coordinator / "api-token"
        write(
            env,
            "STATE_DIR=~/.local/state/devops-console\n"
            "ACME_WEBROOT=~/.local/state/devops-console/acme\n"
            "COORDINATOR_TOKEN_FILE=~/.codex/agent-coordinator/api-token\n",
            0o600,
        )
        write(token, "fixture-private-token-value\n", 0o600)

        def check(**overrides):
            values = {
                "repo_root": repo,
                "home": home,
                "env_file": env,
                "state_dir": state,
                "acme_webroot": acme,
                "coordinator_home": coordinator,
                "token_file": token,
                "require_token": True,
                **overrides,
            }
            return guard.check_layout(**values)

        assert check()["ok"] is True

        token.unlink()
        assert check(require_token=False)["ok"] is True
        expect_error(lambda: check(require_token=True), "token file is missing")
        write(token, "fixture-private-token-value\n", 0o600)

        env.chmod(0o644)
        expect_error(check, "mode must be 0600")
        env.chmod(0o600)
        state.chmod(0o755)
        expect_error(check, "mode must be 0700")
        state.chmod(0o700)

        exposed = coordinator / "logs/exposed.log"
        write(exposed, "not private\n", 0o644)
        expect_error(check, "group/world-accessible")
        exposed.chmod(0o600)
        exposed.parent.chmod(0o700)

        linked_child = state / "linked-child"
        os.symlink(root / "outside", linked_child)
        expect_error(check, "contains a symlink")
        linked_child.unlink()

        inside = repo / "state"
        mkdir(inside)
        expect_error(lambda: check(state_dir=inside, acme_webroot=inside), "outside Git")

        write(env, "STATE_DIR=state\n", 0o600)
        expect_error(check, "STATE_DIR")
        write(env, "STATE_DIR=~/.local/state/devops-console\n", 0o600)

        linked = home / "linked-state"
        os.symlink(state, linked)
        expect_error(lambda: check(state_dir=linked, acme_webroot=acme), "symlink")

        print("production layout preflight self-test ok")
        return 0
    finally:
        rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
