#!/usr/bin/env python3
"""Recall and false-positive controls for ``check_cleanup_contract.py``."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Callable

from check_cleanup_contract import cleanup_contract_errors


LIFECYCLE_CLI = r'''
import argparse

REPOSITORY_PLAN_ARCHIVE_ALIASES = frozenset({"plan-remove", "plan-archive"})
REPOSITORY_ARCHIVE_ALIASES = frozenset({"remove", "archive"})
REPOSITORY_LIST_ARCHIVED_ALIASES = frozenset({"list-removed", "list-archived"})
REPOSITORY_RESTORE_ALIASES = frozenset({"reinstall", "restore"})
PURGE_TARGET_KINDS = ("project", "server", "container", "worktree")


def add_lifecycle_parsers(subparsers):
    repository = subparsers.add_parser("repository", help="reversible repository archive lifecycle")
    repository_sub = repository.add_subparsers(dest="action", required=True)
    for action in (
        "plan-remove", "plan-archive", "remove", "archive",
        "list-removed", "list-archived", "reinstall", "restore",
    ):
        repository_sub.add_parser(action)

    resource = subparsers.add_parser("resource")
    resource_sub = resource.add_subparsers(dest="action", required=True)
    for action in ("plan-archive", "archive", "restore"):
        resource_sub.add_parser(action)

    cleanup = subparsers.add_parser("cleanup")
    cleanup_sub = cleanup.add_subparsers(dest="cleanup_action", required=True)
    plan = cleanup_sub.add_parser("plan")
    plan.add_argument("--action", choices=("purge",), required=True)
    plan.add_argument("--target-kind", choices=("project", "server", "container", "worktree"), required=True)
    apply = cleanup_sub.add_parser("apply")
    apply.add_argument("--plan-id", required=True)
    apply.add_argument("--plan-fingerprint", required=True)
    apply.add_argument("--confirmation-phrase", required=True)
'''


REPOSITORY_LIFECYCLE = r'''
RETAINED_DATA = (
    "repository_files", "containers", "volumes", "databases",
    "backups", "audit_history",
)


class RepositoryDecommissionPlan:
    pass


def reinstall_repository():
    """Clear the reversible archive fence without starting anything."""
    return {"started": False}
'''


CLEANUP_LIFECYCLE = r'''
import os
import subprocess


class CleanupLifecycle:
    def plan(self, *, target_kind, target_id, actor, reason):
        snapshot = self._snapshot(target_kind, target_id)
        material = {
            "action": "purge",
            "target_kind": target_kind,
            "target_id": target_id,
            "actor": actor,
            "reason": reason,
            "snapshot": snapshot,
        }
        plan_fingerprint = fingerprint(material)
        return self._save_plan(plan_fingerprint, actor=actor, reason=reason)

    def apply(self, *, plan_id, plan_fingerprint, confirmation_phrase, actor):
        plan = self.load_plan(plan_id)
        current = self._snapshot(plan.target_kind, plan.target_id, allow_absent=True)
        if current.get("absent"):
            if self._phase_status(plan.plan_id, "host_remove") == "running":
                self._finish_phase(
                    plan.plan_id,
                    "host_remove",
                    {"recovered_after_interruption": True, "target_absent": True},
                )
            else:
                raise RuntimeError("target disappeared before host_remove started")
        self._mark_running(plan, actor)
        if plan.target_kind == "container":
            self._start_phase(plan.plan_id, "host_remove")
            evidence = self.docker_backend.remove(plan.full_container_id)
            self._finish_phase(plan.plan_id, "host_remove", evidence)
        elif plan.target_kind == "worktree":
            self._start_phase(plan.plan_id, "host_remove")
            evidence = self._remove_worktree(plan)
            self._finish_phase(plan.plan_id, "host_remove", evidence)
        self._insert_tombstone(plan)

    def _mark_running(self, plan, actor):
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE cleanup_plans SET status = 'running' WHERE plan_id = ?",
                (plan.plan_id,),
            )

    def _start_phase(self, plan_id, phase):
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "INSERT INTO cleanup_phase_evidence(plan_id, phase, status) VALUES (?, ?, 'running')",
                (plan_id, phase),
            )

    def _finish_phase(self, plan_id, phase, evidence):
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "UPDATE cleanup_phase_evidence SET status = 'succeeded' WHERE plan_id = ? AND phase = ?",
                (plan_id, phase),
            )

    def _container_blockers(self, docker):
        blockers = []
        if docker.get("mounts"):
            blockers.append(_blocker("mounted_container", "mounted containers stay retained"))
        labels = docker.get("labels", {})
        if labels.get("com.docker.compose.project"):
            blockers.append(_blocker("compose_owned", "Compose owns this container"))
        return blockers

    def _remove_worktree(self, plan):
        return subprocess.run(
            ["git", "worktree", "remove", "--", plan.canonical_root], check=True
        )

    def _insert_tombstone(self, plan):
        with self.store.immediate_transaction() as connection:
            connection.execute(
                "INSERT INTO cleanup_tombstones(target_kind, target_id, actor, reason) VALUES (?, ?, ?, ?)",
                (plan.target_kind, plan.target_id, plan.actor, plan.reason),
            )

    def list_archives(self, *, actor):
        rows = []
        with self.store.read_transaction() as connection:
            for row in connection.execute(
                "SELECT target_kind, target_id, removed_at FROM cleanup_tombstones"
            ):
                rows.append({
                    "target_kind": row["target_kind"],
                    "target_id": row["target_id"],
                    "removed_at": row["removed_at"],
                    "status": "removed",
                    "restorable": False,
                    "removable": False,
                })
        return {"archives": rows}


def _inspect_linked_worktree(root):
    blockers = []
    root_stat = root.lstat()
    if root_stat.st_uid == 0:
        blockers.append(_blocker("root_owned_worktree", "root-owned worktrees stay retained"))
    return blockers
'''


HTTP_API = r'''
import hmac
import re
import subprocess
import uuid

CLEANUP_PLAN_FIELDS = {"action", "target_kind", "target_id", "reason"}
CLEANUP_APPLY_FIELDS = {"plan_id", "plan_fingerprint", "confirmation_phrase"}
INACTIVE_LIFECYCLE_STATUSES = frozenset({"archived", "removed"})
# A production validator may name rejected argv without executing it.  The
# command detector must follow execution calls instead of banning vocabulary.
REJECTED_COMMAND_CONTROLS = (
    ("rm", "-rf"),
    ("docker", "container", "rm", "--volumes"),
)

API_GET_ROUTES = frozenset({"/v1/archives"})
API_POST_ROUTES = frozenset({
    "/v1/lifecycle/plan", "/v1/lifecycle/apply", "/v1/lifecycle/restore",
})


def _canonical_uuid_argument(value):
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError("plan_id must be a canonical UUID")
    return value


def _sha256_fingerprint_argument(value):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("plan_fingerprint must be SHA-256")
    return value


def validate_lifecycle_apply(payload, plan):
    if set(payload) != CLEANUP_APPLY_FIELDS:
        raise ValueError("apply fields are not exact")
    plan_id = _canonical_uuid_argument(payload["plan_id"])
    plan_fingerprint = _sha256_fingerprint_argument(payload["plan_fingerprint"])
    if plan.action == "purge":
        expected = f"PURGE {plan.target_kind} {plan.target_id}"
        if not hmac.compare_digest(payload["confirmation_phrase"], expected):
            raise ValueError("confirmation_phrase does not match")
    return plan_id, plan_fingerprint


def lifecycle_record_is_active(row):
    if row.get("status") in INACTIVE_LIFECYCLE_STATUSES:
        return row.get("start_fence_violated") is True
    return True


def apply_exact_cleanup(exact):
    # Exact stopped identities only; no force, volume, image, or prune flags.
    subprocess.run(["git", "worktree", "remove", "--", exact.worktree], check=True)
    subprocess.run(["docker", "container", "rm", exact.container_id], check=True)
    subprocess.run(["docker", "compose", "down"], check=True)


def ordinary_runtime_stop(exact):
    subprocess.run(["docker", "stop", exact.container_id], check=True)


def ordinary_compose_operations(exact):
    subprocess.run(["docker", "compose", "up", "-d"], check=True)
    subprocess.run(["docker", "compose", "restart", exact.service], check=True)
    subprocess.run(["docker", "compose", "ps"], check=True)
    subprocess.run(["docker", "compose", "logs", exact.service], check=True)


class ApiHandler:
    def _handle_post(self, path, payload):
        if path == "/v1/lifecycle/plan":
            if set(payload) != CLEANUP_PLAN_FIELDS:
                raise ValueError("typed plan fields required")
            return lifecycle_plan(payload)
        if path == "/v1/lifecycle/apply":
            return lifecycle_apply(payload)
        if path == "/v1/lifecycle/restore":
            return lifecycle_restore(payload)
        raise ValueError("not found")
'''


CONSOLE_API = r'''
function requireAccessAdmin(session) {
  if (!session?.accessAdmin) throw new Error('owner only');
}

function requireLifecycleOwner(session) {
  requireAccessAdmin(session);
}

async function handleLifecycleList(res, session) {
  requireLifecycleOwner(session);
  return coordinator.lifecycleArchives();
}

async function handleLifecyclePlan(req, res, session) {
  requireLifecycleOwner(session);
  const body = await readJsonBody(req);
  return coordinator.lifecyclePlan({
    action: body.action,
    target_kind: body.target_kind,
    target_id: body.target_id,
    reason: body.reason,
  });
}

async function handleLifecycleApply(req, res, session) {
  requireLifecycleOwner(session);
  const body = await readJsonBody(req);
  return coordinator.lifecycleApply({
    plan_id: body.plan_id,
    plan_fingerprint: body.plan_fingerprint,
    confirmation_phrase: body.confirmation_phrase,
  });
}

async function handleLifecycleRestore(req, res, session) {
  requireLifecycleOwner(session);
  const body = await readJsonBody(req);
  return coordinator.lifecycleRestore({
    target_kind: body.target_kind,
    target_id: body.target_id,
    reason: body.reason,
  });
}

async function dispatch(method, pathname, req, res, session) {
  if (method === 'GET' && pathname === '/api/lifecycle/list') {
    return handleLifecycleList(res, session);
  }
  if (method === 'POST' && pathname === '/api/lifecycle/plan') {
    return handleLifecyclePlan(req, res, session);
  }
  if (method === 'POST' && pathname === '/api/lifecycle/apply') {
    return handleLifecycleApply(req, res, session);
  }
  if (method === 'POST' && pathname === '/api/lifecycle/restore') {
    return handleLifecycleRestore(req, res, session);
  }
}

// Ordinary route deletion is not a host-resource purge and is intentionally
// not forced through the lifecycle owner helper.
async function handleRouteDelete(slug) {
  return routes.remove(slug);
}
'''


CONSOLE_UI = r'''
function applyHiddenPreference(id) {
  return h('button', { onclick: () => api('/api/prefs', {
    method: 'PATCH', body: { hide: { server: [id] } },
  }) }, 'Hide');
}

function archiveButton(target) {
  return h('button', {
    onclick: () => api('/api/lifecycle/plan', {
      method: 'POST', body: { action: 'archive', target_kind: target.kind, target_id: target.id },
    }),
  }, 'Archive');
}

function ordinaryRemoveWording() {
  return 'remove a route from this hostname';
}
'''


DOC_FALSE_POSITIVE = r'''
# Operator notes

Never run `rm -rf`, `git worktree remove --force`, `docker rm -fv`,
`docker compose down --volumes --rmi all --remove-orphans`, or
`docker image prune` from a cleanup implementation.
'''


TEST_FALSE_POSITIVE = r'''
def test_detector_fixture_words_only():
    examples = [
        ["rm", "-rf", "/tmp/example"],
        ["git", "worktree", "remove", "--force", "/tmp/worktree"],
        ["docker", "container", "rm", "-fv", "container"],
        ["docker", "volume", "prune"],
    ]
    assert examples
'''


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_fixture(root: Path) -> None:
    _write(
        root / "skills/codex-dev-coordinator/scripts/devcoordinator/lifecycle_cli.py",
        LIFECYCLE_CLI,
    )
    _write(
        root / "skills/codex-dev-coordinator/scripts/devcoordinator/repository_lifecycle.py",
        REPOSITORY_LIFECYCLE,
    )
    _write(
        root / "skills/codex-dev-coordinator/scripts/devcoordinator/cleanup_lifecycle.py",
        CLEANUP_LIFECYCLE,
    )
    _write(root / "skills/codex-dev-coordinator/scripts/dev_coordinator.py", HTTP_API)
    _write(root / "apps/DevOpsConsole/src/api.mjs", CONSOLE_API)
    _write(root / "apps/DevOpsConsole/src/ui/app.js", CONSOLE_UI)
    _write(root / "docs/destructive-command-examples.md", DOC_FALSE_POSITIVE)
    _write(
        root / "skills/codex-dev-coordinator/scripts/devcoordinator/tests/test_cleanup_words.py",
        TEST_FALSE_POSITIVE,
    )


def _replace(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    if old not in source:
        raise RuntimeError(f"self-test mutation needle is absent from {path}: {old!r}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def _expect_failure(
    label: str,
    mutation: Callable[[Path], None],
    expected_code: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="cleanup-contract-bad-") as temporary:
        root = Path(temporary)
        build_fixture(root)
        mutation(root)
        errors = cleanup_contract_errors(root)
        marker = f"[{expected_code}]"
        if not any(marker in error for error in errors):
            raise RuntimeError(
                f"cleanup-contract detector missed {label}; expected {marker}, got {errors}"
            )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cleanup-contract-good-") as temporary:
        root = Path(temporary)
        build_fixture(root)
        errors = cleanup_contract_errors(root)
        if errors:
            raise RuntimeError(
                "cleanup-contract false-positive fixture was rejected:\n- "
                + "\n- ".join(errors)
            )

    cli = Path("skills/codex-dev-coordinator/scripts/devcoordinator/lifecycle_cli.py")
    api = Path("skills/codex-dev-coordinator/scripts/dev_coordinator.py")
    cleanup = Path(
        "skills/codex-dev-coordinator/scripts/devcoordinator/cleanup_lifecycle.py"
    )
    console_api = Path("apps/DevOpsConsole/src/api.mjs")
    console_ui = Path("apps/DevOpsConsole/src/ui/app.js")

    _expect_failure(
        "legacy repository remove no longer aliases reversible archive",
        lambda root: _replace(
            root / cli,
            'REPOSITORY_ARCHIVE_ALIASES = frozenset({"remove", "archive"})',
            'REPOSITORY_ARCHIVE_ALIASES = frozenset({"archive"})',
        ),
        "legacy-archive-alias",
    )
    _expect_failure(
        "raw rm -rf",
        lambda root: _replace(
            root / api,
            '["git", "worktree", "remove", "--", exact.worktree]',
            '["rm", "-rf", exact.worktree]',
        ),
        "raw-rm-rf",
    )
    _expect_failure(
        "forced Git worktree removal",
        lambda root: _replace(
            root / api,
            '["git", "worktree", "remove", "--", exact.worktree]',
            '["git", "worktree", "remove", "--force", "--", exact.worktree]',
        ),
        "git-worktree-force",
    )
    for label, flag in (
        ("forced Docker removal", "--force"),
        ("short forced Docker removal", "-f"),
        ("Docker anonymous-volume deletion", "-v"),
        ("Docker long volume deletion", "--volumes"),
    ):
        _expect_failure(
            label,
            lambda root, flag=flag: _replace(
                root / api,
                '["docker", "container", "rm", exact.container_id]',
                f'["docker", "container", "rm", "{flag}", exact.container_id]',
            ),
            "docker-remove-flags",
        )
    for label, flag in (
        ("Compose volume deletion", "--volumes"),
        ("Compose image deletion", "--rmi"),
        ("Compose orphan deletion", "--remove-orphans"),
    ):
        _expect_failure(
            label,
            lambda root, flag=flag: _replace(
                root / api,
                '["docker", "compose", "down"]',
                f'["docker", "compose", "down", "{flag}"]',
            ),
            "compose-destructive-flags",
        )
    for domain in ("image", "volume", "network"):
        _expect_failure(
            f"implicit Docker {domain} prune",
            lambda root, domain=domain: _replace(
                root / api,
                '["docker", "compose", "down"]',
                f'["docker", "{domain}", "prune"]',
            ),
            "implicit-prune",
        )
    for field in ("path", "command", "argv"):
        _expect_failure(
            f"client-supplied {field}",
            lambda root, field=field: _replace(
                root / api,
                'CLEANUP_PLAN_FIELDS = {"action", "target_kind", "target_id", "reason"}',
                f'CLEANUP_PLAN_FIELDS = {{"action", "target_kind", "target_id", "reason", "{field}"}}',
            ),
            "client-execution-input",
        )
    _expect_failure(
        "client target_id passed directly to filesystem command",
        lambda root: _replace(
            root / api,
            "return lifecycle_apply(payload)",
            '''return subprocess.run(
                ["git", "worktree", "remove", "--", payload["target_id"]],
                check=True,
            )''',
        ),
        "client-execution-input",
    )
    _expect_failure(
        "purge without exact typed confirmation",
        lambda root: _replace(
            root / api,
            'if not hmac.compare_digest(payload["confirmation_phrase"], expected):',
            'if False:',
        ),
        "purge-confirmation-contract",
    )
    _expect_failure(
        "apply without exact confirmation field set",
        lambda root: _replace(
            root / api,
            'CLEANUP_APPLY_FIELDS = {"plan_id", "plan_fingerprint", "confirmation_phrase"}',
            'CLEANUP_APPLY_FIELDS = {"plan_id", "plan_fingerprint"}',
        ),
        "purge-confirmation-contract",
    )

    def remove_uuid_validation(root: Path) -> None:
        _replace(
            root / api,
            '''def _canonical_uuid_argument(value):
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError("plan_id must be a canonical UUID")
    return value''',
            '''def parse_plan_id(value):
    return value''',
        )
        _replace(
            root / api,
            '_canonical_uuid_argument(payload["plan_id"])',
            'parse_plan_id(payload["plan_id"])',
        )

    _expect_failure(
        "apply without canonical UUID validation",
        remove_uuid_validation,
        "plan-uuid",
    )

    def remove_sha_validation(root: Path) -> None:
        _replace(
            root / api,
            '''def _sha256_fingerprint_argument(value):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("plan_fingerprint must be SHA-256")
    return value''',
            '''def parse_plan_fingerprint(value):
    return value''',
        )
        _replace(
            root / api,
            '_sha256_fingerprint_argument(payload["plan_fingerprint"])',
            'parse_plan_fingerprint(payload["plan_fingerprint"])',
        )

    _expect_failure(
        "apply without SHA-256 fingerprint validation",
        remove_sha_validation,
        "plan-sha256",
    )
    _expect_failure(
        "Hide preference relabeled Archive",
        lambda root: _replace(root / console_ui, "}, 'Hide');", "}, 'Archive');"),
        "hide-is-not-archive",
    )
    _expect_failure(
        "Console purge lifecycle apply outside owner gate",
        lambda root: _replace(
            root / console_api,
            '''async function handleLifecycleApply(req, res, session) {
  requireLifecycleOwner(session);''',
            '''async function handleLifecycleApply(req, res, session) {''',
        ),
        "console-owner-gate",
    )
    _expect_failure(
        "archived row included without fence-violation marker",
        lambda root: _replace(
            root / api,
            'return row.get("start_fence_violated") is True',
            'return False',
        ),
        "active-lifecycle-projection",
    )
    _expect_failure(
        "cleanup plan fingerprint omits actor",
        lambda root: _replace(
            root / cleanup,
            '            "actor": actor,\n',
            "",
        ),
        "plan-actor-reason-binding",
    )
    _expect_failure(
        "cleanup plan fingerprint omits reason",
        lambda root: _replace(
            root / cleanup,
            '            "reason": reason,\n',
            "",
        ),
        "plan-actor-reason-binding",
    )
    _expect_failure(
        "apply overwrites plan-bound actor",
        lambda root: _replace(
            root / cleanup,
            "UPDATE cleanup_plans SET status = 'running' WHERE plan_id = ?",
            "UPDATE cleanup_plans SET status = 'running', actor = ? WHERE plan_id = ?",
        ),
        "plan-actor-reason-binding",
    )
    _expect_failure(
        "tombstone records apply actor instead of plan actor",
        lambda root: _replace(
            root / cleanup,
            "(plan.target_kind, plan.target_id, plan.actor, plan.reason)",
            "(plan.target_kind, plan.target_id, actor, plan.reason)",
        ),
        "plan-actor-reason-binding",
    )
    _expect_failure(
        "Docker host effect starts before durable phase journal",
        lambda root: _replace(
            root / cleanup,
            '''            self._start_phase(plan.plan_id, "host_remove")
            evidence = self.docker_backend.remove(plan.full_container_id)''',
            '''            evidence = self.docker_backend.remove(plan.full_container_id)
            self._start_phase(plan.plan_id, "host_remove")''',
        ),
        "cleanup-effect-journal",
    )
    _expect_failure(
        "host effect phase is not durably marked running",
        lambda root: _replace(
            root / cleanup,
            "VALUES (?, ?, 'running')",
            "VALUES (?, ?, 'planned')",
        ),
        "cleanup-effect-journal",
    )
    _expect_failure(
        "absent host effect has no reconciliation evidence",
        lambda root: _replace(
            root / cleanup,
            '''                self._finish_phase(
                    plan.plan_id,
                    "host_remove",
                    {"recovered_after_interruption": True, "target_absent": True},
                )''',
            '''                raise RuntimeError("host effect outcome is unknown")''',
        ),
        "cleanup-effect-reconciliation",
    )
    _expect_failure(
        "root-owned worktree is allowed",
        lambda root: _replace(
            root / cleanup,
            '''    if root_stat.st_uid == 0:
        blockers.append(_blocker("root_owned_worktree", "root-owned worktrees stay retained"))''',
            '''    if root_stat.st_uid == 0:
        pass''',
        ),
        "root-owned-worktree",
    )
    _expect_failure(
        "mounted container is allowed",
        lambda root: _replace(
            root / cleanup,
            '_blocker("mounted_container", "mounted containers stay retained")',
            '_blocker("mount_observed", "mount is only informational")',
        ),
        "mounted-container",
    )
    _expect_failure(
        "live Compose-owned container is allowed",
        lambda root: _replace(
            root / cleanup,
            '_blocker("compose_owned", "Compose owns this container")',
            '_blocker("compose_observed", "Compose ownership is only informational")',
        ),
        "compose-owned-container",
    )
    _expect_failure(
        "removed tombstone disappears from the lifecycle projection",
        lambda root: _replace(
            root / cleanup,
            '                    "status": "removed",',
            '                    "status": "archived",',
        ),
        "removed-tombstone-projection",
    )

    print("cleanup-contract self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
