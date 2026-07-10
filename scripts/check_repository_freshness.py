#!/usr/bin/env python3
"""Compare a working copy with the freshly fetched remote default branch.

This preflight is intentionally non-destructive: it may update remote-tracking
refs through ``git fetch``, but it never checks out, resets, rebases, merges,
stashes, cleans, or changes working-tree files.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SAFE_STATUSES = {"current", "ahead"}
STALE_EXIT = 2
REMOTE_UNAVAILABLE_EXIT = 3
USAGE_ERROR_EXIT = 4


class GitError(RuntimeError):
    """A local Git query failed."""


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed with exit code {completed.returncode}")
    return completed


def resolve_remote_branch(repo: Path, remote: str, requested: str | None) -> str:
    if requested:
        return requested.removeprefix("refs/heads/")

    symbolic = git(
        repo,
        "symbolic-ref",
        "--quiet",
        "--short",
        f"refs/remotes/{remote}/HEAD",
        check=False,
    )
    if symbolic.returncode == 0 and symbolic.stdout.strip().startswith(f"{remote}/"):
        return symbolic.stdout.strip()[len(remote) + 1 :]

    advertised = git(repo, "ls-remote", "--symref", remote, "HEAD", check=False)
    if advertised.returncode == 0:
        for line in advertised.stdout.splitlines():
            if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
                return line.removeprefix("ref: refs/heads/").removesuffix("\tHEAD")

    upstream = git(
        repo,
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
        check=False,
    )
    if upstream.returncode == 0 and upstream.stdout.strip().startswith(f"{remote}/"):
        return upstream.stdout.strip()[len(remote) + 1 :]

    for conventional in ("main", "master"):
        candidate = f"refs/remotes/{remote}/{conventional}"
        if git(repo, "show-ref", "--verify", "--quiet", candidate, check=False).returncode == 0:
            return conventional

    raise GitError(f"could not determine {remote}'s default branch")


def base_payload(repo: Path, remote: str, dirty: bool, head: str | None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "remote-unavailable",
        "relation": "unknown",
        "ok": False,
        "repo": str(repo),
        "remote": remote,
        "branch": None,
        "remote_ref": None,
        "head": head,
        "remote_head": None,
        "merge_base": None,
        "ahead": 0,
        "behind": 0,
        "dirty": dirty,
        "fetched": False,
        "detail": None,
    }


def inspect_repository(repo: Path, remote: str, branch: str | None) -> tuple[int, dict[str, Any]]:
    repo = repo.expanduser().resolve()
    if not repo.is_dir():
        payload = base_payload(repo, remote, False, None)
        payload.update(status="invalid-repository", detail="repository directory does not exist")
        return USAGE_ERROR_EXIT, payload

    top_level = git(repo, "rev-parse", "--show-toplevel", check=False)
    if top_level.returncode != 0:
        payload = base_payload(repo, remote, False, None)
        payload.update(status="invalid-repository", detail="path is not inside a Git working tree")
        return USAGE_ERROR_EXIT, payload

    canonical_repo = Path(top_level.stdout.strip()).resolve()
    head_result = git(canonical_repo, "rev-parse", "HEAD", check=False)
    head = head_result.stdout.strip() if head_result.returncode == 0 else None
    dirty = bool(git(canonical_repo, "status", "--porcelain=v1", "--untracked-files=normal").stdout)
    payload = base_payload(canonical_repo, remote, dirty, head)

    if head is None:
        payload.update(status="invalid-repository", detail="repository has no HEAD commit")
        return USAGE_ERROR_EXIT, payload

    if git(canonical_repo, "remote", "get-url", remote, check=False).returncode != 0:
        payload["detail"] = f"remote {remote!r} is not configured"
        return REMOTE_UNAVAILABLE_EXIT, payload

    fetched = git(
        canonical_repo,
        "fetch",
        "--quiet",
        "--prune",
        "--no-tags",
        remote,
        check=False,
    )
    if fetched.returncode != 0:
        payload["detail"] = f"fetch from remote {remote!r} failed with exit code {fetched.returncode}"
        return REMOTE_UNAVAILABLE_EXIT, payload
    payload["fetched"] = True

    try:
        remote_branch = resolve_remote_branch(canonical_repo, remote, branch)
    except GitError as exc:
        payload["detail"] = str(exc)
        return REMOTE_UNAVAILABLE_EXIT, payload

    remote_ref = f"refs/remotes/{remote}/{remote_branch}"
    remote_head_result = git(canonical_repo, "rev-parse", "--verify", remote_ref, check=False)
    if remote_head_result.returncode != 0:
        payload.update(
            branch=remote_branch,
            remote_ref=remote_ref,
            detail=f"remote branch {remote_branch!r} was not found after fetch",
        )
        return REMOTE_UNAVAILABLE_EXIT, payload

    remote_head = remote_head_result.stdout.strip()
    counts = git(canonical_repo, "rev-list", "--left-right", "--count", f"HEAD...{remote_ref}")
    try:
        ahead_text, behind_text = counts.stdout.strip().split()
        ahead = int(ahead_text)
        behind = int(behind_text)
    except (ValueError, TypeError) as exc:
        raise GitError("git rev-list returned malformed ancestry counts") from exc

    merge_base_result = git(canonical_repo, "merge-base", "HEAD", remote_ref, check=False)
    merge_base = merge_base_result.stdout.strip() if merge_base_result.returncode == 0 else None

    if ahead == 0 and behind == 0:
        relation = "current"
    elif ahead > 0 and behind == 0:
        relation = "ahead"
    elif ahead == 0 and behind > 0:
        relation = "behind"
    else:
        relation = "diverged"

    status = "dirty-on-stale-base" if dirty and relation in {"behind", "diverged"} else relation
    ok = status in SAFE_STATUSES
    payload.update(
        status=status,
        relation=relation,
        ok=ok,
        branch=remote_branch,
        remote_ref=remote_ref,
        remote_head=remote_head,
        merge_base=merge_base,
        ahead=ahead,
        behind=behind,
        detail=(
            "working tree changes were preserved; integrate the fetched remote in an isolated checkout"
            if status == "dirty-on-stale-base"
            else None
        ),
    )
    return (0 if ok else STALE_EXIT), payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and classify repository ancestry before broad repository work."
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="working tree to inspect")
    parser.add_argument("--remote", default="origin", help="remote name (default: origin)")
    parser.add_argument("--branch", help="remote branch; defaults to the remote's HEAD branch")
    parser.add_argument("--json", action="store_true", help="emit the complete machine-readable report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        exit_code, payload = inspect_repository(args.repo, args.remote, args.branch)
    except GitError as exc:
        canonical = args.repo.expanduser().resolve()
        payload = base_payload(canonical, args.remote, False, None)
        payload.update(status="invalid-repository", detail=str(exc))
        exit_code = USAGE_ERROR_EXIT

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        counts = f"ahead={payload['ahead']} behind={payload['behind']}"
        dirty = " dirty=yes" if payload["dirty"] else " dirty=no"
        print(f"{payload['status']}: {payload['repo']} ({counts}{dirty})")
        if payload.get("detail"):
            print(payload["detail"], file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
