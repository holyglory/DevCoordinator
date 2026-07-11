#!/usr/bin/env python3
"""Behavioral self-test for check_repository_freshness.py.

The fixtures are real Git repositories with a bare remote. They model the
ways working copies actually become stale instead of mocking detector output.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DETECTOR = ROOT / "scripts" / "check_repository_freshness.py"
GIT_IDENTITY = [
    "-c",
    "user.name=freshness-self-test",
    "-c",
    "user.email=freshness-self-test@devcoordinator.invalid",
]


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def commit(repo: Path, message: str, filename: str, body: str) -> str:
    (repo / filename).write_text(body, encoding="utf-8")
    git(repo, "add", filename)
    git(repo, *GIT_IDENTITY, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@dataclass(frozen=True)
class World:
    remote: Path
    target: Path
    peer: Path


def make_world(parent: Path) -> World:
    remote = parent / "origin.git"
    seed = parent / "seed"
    target = parent / "target"
    peer = parent / "peer"
    parent.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "-q", "--bare", "--initial-branch=main", str(remote)],
        check=True,
    )
    subprocess.run(
        ["git", "clone", "-q", str(remote), str(seed)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    commit(seed, "initial", "tracked.txt", "initial\n")
    git(seed, "push", "-q", "-u", "origin", "main")
    subprocess.run(
        ["git", "clone", "-q", str(remote), str(target)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["git", "clone", "-q", str(remote), str(peer)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return World(remote=remote, target=target, peer=peer)


def detect(repo: Path, *, branch: str | None = "main") -> tuple[int, dict[str, object]]:
    command = [
        sys.executable,
        str(DETECTOR),
        "--repo",
        str(repo),
        "--remote",
        "origin",
        "--json",
    ]
    if branch is not None:
        command.extend(["--branch", branch])
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not completed.stdout.strip():
        raise AssertionError(
            f"detector returned no JSON (exit {completed.returncode}): {completed.stderr.strip()}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"detector output is not JSON: {completed.stdout!r}") from exc
    return completed.returncode, payload


def expect(
    repo: Path,
    status: str,
    relation: str,
    exit_code: int,
    *,
    dirty: bool,
    branch: str | None = "main",
) -> dict[str, object]:
    actual_exit, payload = detect(repo, branch=branch)
    assert actual_exit == exit_code, (status, actual_exit, payload)
    assert payload["status"] == status, payload
    assert payload["relation"] == relation, payload
    assert payload["dirty"] is dirty, payload
    assert isinstance(payload["ahead"], int), payload
    assert isinstance(payload["behind"], int), payload
    return payload


def main() -> int:
    if not DETECTOR.is_file():
        raise AssertionError(f"freshness detector is missing: {DETECTOR}")

    with tempfile.TemporaryDirectory(prefix="repository-freshness-self-test-") as raw_tmp:
        tmp = Path(raw_tmp).resolve(strict=True)

        current = make_world(tmp / "current")
        # Default-branch discovery is part of the public CLI contract.
        payload = expect(current.target, "current", "current", 0, dirty=False, branch=None)
        assert payload["ahead"] == 0 and payload["behind"] == 0, payload

        dirty_current = make_world(tmp / "dirty-current")
        (dirty_current.target / "tracked.txt").write_text("intentional local edit\n", encoding="utf-8")
        expect(dirty_current.target, "current", "current", 0, dirty=True)

        ahead = make_world(tmp / "ahead")
        commit(ahead.target, "local improvement", "local.txt", "local\n")
        payload = expect(ahead.target, "ahead", "ahead", 0, dirty=False)
        assert payload["ahead"] == 1 and payload["behind"] == 0, payload

        behind = make_world(tmp / "behind")
        commit(behind.peer, "remote improvement", "remote.txt", "remote\n")
        git(behind.peer, "push", "-q", "origin", "main")
        payload = expect(behind.target, "behind", "behind", 2, dirty=False)
        assert payload["ahead"] == 0 and payload["behind"] == 1, payload

        dirty_behind = make_world(tmp / "dirty-behind")
        commit(dirty_behind.peer, "new architecture", "remote.txt", "remote\n")
        git(dirty_behind.peer, "push", "-q", "origin", "main")
        tracked = dirty_behind.target / "tracked.txt"
        tracked.write_text("valuable uncommitted work\n", encoding="utf-8")
        untracked = dirty_behind.target / "untracked.txt"
        untracked.write_text("keep me\n", encoding="utf-8")
        before_head = git(dirty_behind.target, "rev-parse", "HEAD")
        payload = expect(
            dirty_behind.target,
            "dirty-on-stale-base",
            "behind",
            2,
            dirty=True,
        )
        assert payload["behind"] == 1, payload
        assert git(dirty_behind.target, "rev-parse", "HEAD") == before_head
        assert tracked.read_text(encoding="utf-8") == "valuable uncommitted work\n"
        assert untracked.read_text(encoding="utf-8") == "keep me\n"

        diverged = make_world(tmp / "diverged")
        commit(diverged.target, "local branch", "local.txt", "local\n")
        commit(diverged.peer, "remote branch", "remote.txt", "remote\n")
        git(diverged.peer, "push", "-q", "origin", "main")
        payload = expect(diverged.target, "diverged", "diverged", 2, dirty=False)
        assert payload["ahead"] == 1 and payload["behind"] == 1, payload

        unavailable = make_world(tmp / "unavailable")
        git(unavailable.target, "remote", "set-url", "origin", str(tmp / "does-not-exist.git"))
        payload = expect(
            unavailable.target,
            "remote-unavailable",
            "unknown",
            3,
            dirty=False,
        )
        assert payload["remote_head"] is None, payload

        no_remote = make_world(tmp / "no-remote")
        git(no_remote.target, "remote", "remove", "origin")
        payload = expect(
            no_remote.target,
            "remote-unavailable",
            "unknown",
            3,
            dirty=False,
        )
        assert payload["remote_head"] is None, payload
        assert "not configured" in str(payload["detail"]), payload

    print("repository freshness self-test ok (8 realistic cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
