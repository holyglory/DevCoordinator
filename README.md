# DevCoordinator

DevCoordinator is the host authority for local development runtimes shared by
multiple Codex, Claude, desktop, and OS-user sessions. It owns attributed port
leases, processes, Docker/Compose resources, local database stacks, telemetry,
logs, lifecycle evidence, short-lived workload policy, repository-scoped test
records, and cleanup.

The repository also contains:

- `codex-dev-coordinator`, the agent-facing runtime skill and Python API.
- `postgres-docker-backup`, verified PostgreSQL-in-Docker backup and restore.
- `DevOpsBoard`, the native macOS operations interface.
- `DevOpsConsole`, the authenticated web interface and routing edge.

## Architecture

- One peer-authenticated broker and WAL SQLite store are the host authority.
- One canonical Git worktree is one repository/project.
- Repository families present an original checkout with its temporary linked
  worktrees without collapsing their identities.
- Python owns observation, membership, lifecycle, TTL cleanup, diagnostics,
  totals, and the `repository_trees` UI model.
- Inventory is a pure read; explicit observation updates host evidence.
- Unknown ownership, stale identity, and partial cleanup fail closed.

Enrolled system clients use stored repository/resource IDs with live ACL,
family-wide classification, and exact membership checks. The broker provides
durable worker status/start/stop/restart/replacement, keep-alive supervision,
and staged removal under the authenticated peer UID. It also provides exact-ID
start/stop/restart for enrolled Docker/database targets. Other service roles,
shared TTL/run work, and Docker/database replacement fail closed; the isolated
account implementation is not a host-wide fallback. Remaining work is listed
in `CompletionLedger.md`.

## Agent quick start

Use the unified runtime API; do not coordinate individual commands in shell:

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime status \
  --agent "$AGENT" --root-repo "$ROOT_REPO" --no-temporary-repo \
  --target-kind service --target-id "$RESOURCE_ID" --target-name worker \
  --purpose development --no-ttl --kill-after-run false
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  runtime --request-file /absolute/request.json
```

Use flags for routine existing-target status/start/stop/restart/remove calls;
reserve request files for structured definitions, replacement, and bounded
run commands. Every request includes the agent, original root repository,
explicit nullable temporary repository, immutable target identity, and
`kill_after_run` boolean. Test and temporary start-like actions also require a
TTL; status, removal, and explicit stop do not. See
[Agent Runtime API](skills/codex-dev-coordinator/references/runtime-api.md).

The API fails closed for unfinished action-kind combinations. In particular,
Docker and database-stack `replace` currently return
`unsupported_safe_replace` before store or host access; see
`CompletionLedger.md`.

## Install the skills

This checkout is the only writable source. Preview and apply direct absolute
links with the repository manager:

```bash
python3 scripts/manage_skill_links.py plan \
  --repo-root "$PWD" --target-root /absolute/runtime/skills

python3 scripts/manage_skill_links.py apply \
  --repo-root "$PWD" --target-root /absolute/runtime/skills \
  --transaction-dir /private/path/outside-git
```

Use `scripts/manage_skill_links.py --help` for verification, rollback, and
multi-runtime options. Server-wide installation is exposed by
`scripts/install_server_wide_coordinator.py --help`.

## Layout

- `skills/` — canonical skills and coordinator implementation
- `apps/DevOpsBoard/` — SwiftPM macOS app
- `apps/DevOpsConsole/` — Node 20 Console
- `scripts/` — installation, verification, migration, and release tools
- `docs/` — API, architecture, history, and operational references
- `DecisionHistory.md` — compact architecture/product decision index
- `CompletionLedger.md` — current unresolved delivery work only

## Verification

Run the non-native repository gate:

```bash
python3 scripts/validate.py --skip-macos-app
```

DevOps Board build, XCTest, launch, and packaging must run through the Build
macOS Apps workflow. Release checks also require:

```bash
python3 scripts/check_repository_freshness.py --repo "$PWD" --json
python3 scripts/check_repository_boundaries.py --repo "$PWD"
```

Operational and product detail lives beside the owning executable:

- [Coordinator skill](skills/codex-dev-coordinator/README.md)
- [PostgreSQL backup skill](skills/postgres-docker-backup/README.md)
- [DevOps Board](apps/DevOpsBoard/README.md)
- [DevOps Console](apps/DevOpsConsole/README.md)
- [Repository history](docs/history/README.md)
