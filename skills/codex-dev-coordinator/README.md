# Codex Dev Coordinator

This skill routes local runtime and test work through one attributed Python
authority. It coordinates repository/worktree identity, ports, supported
process and Docker/database lifecycle, telemetry, crash/log evidence, bounded
temporary work, tests, and cleanup across agents and OS accounts.

## Agent entrypoint

```bash
COORDINATOR="skills/codex-dev-coordinator/scripts/dev_coordinator.py"
python3 "$COORDINATOR" runtime --help
python3 "$COORDINATOR" runtime status \
  --agent "$AGENT" --root-repo "$ROOT_REPO" --no-temporary-repo \
  --target-kind service --target-id "$RESOURCE_ID" --target-name web \
  --purpose development --no-ttl --kill-after-run false
```

Use flags for normal status/start/stop/restart/remove calls. Use a request file
only for a structured definition, replacement, or bounded `run`. Requests
always identify the agent, original root repository, explicit nullable
temporary repository, immutable target, KillAfterRun policy, and—when test or
temporary work starts—a positive TTL.

The compact response includes state/readiness, immutable IDs, ports/domains,
resource and repository-family CPU/memory totals, stale processes, crashes,
cleanup, and typed log links. Treat `ok=false` as failure.

Worker removal stages Archive then exact permanent cleanup, unregisters native
startup and active projections, and retains audit/crash/log evidence. Explicit
reinstall creates a new immutable incarnation. Persistent Keep Alive workers
record every crash and stop behind a manually re-armed crash-loop breaker.

See [the runtime API reference](references/runtime-api.md). Current lower-level
and administrative contracts live in each command's `--help`.

## Authority and hierarchy

Managed hosts use one service-owned SQLite/WAL database behind a
peer-authenticated Unix socket. Client journals are evidence, not another
inventory authority. One canonical worktree is one project; Python proves
root/temporary relationships and publishes the `repository_trees` model used
by Board and Console. Names and UI heuristics never establish ownership.

System API authorization is loaded from the protected client profile before
binding. A stable atomic profile replacement produces `api.profile_changed`
and a clean supervised exit so `Restart=always` reloads it; malformed state
fails startup without exposing profile contents. Installer-detected profile/
database drift blocks broker restart until exact offline reconciliation passes.

Offline upgrades publish `/run/devcoordinator-maintenance/maintenance.json` before
quiescing the broker. Clients check this broker-independent path before
socket access and receive a typed wait/retry response; malformed state fails closed.
One foreground rollback transaction clears its ID only after readiness or verified rollback.

## Temporary containers and tests

Server-wide ephemeral containers come only from administrator-sealed,
digest-pinned `.codex/dev-runtime.json` templates with explicit TTL, port,
CPU/memory, and concurrency limits. The broker precommits creation, uses an
operation UUID for idempotent recovery, and retains owner-scoped status/finish
cleanup access after ordinary enrollment revocation.

Repositories declare structured test commands in `.codex/tests.json`. The
non-root runner executes argv without a shell; the broker owns admission,
repository attribution, idempotency, and durable session/group/case results.
Use `ephemeral --help` and `test --help` for the short-lived container and test
interfaces.

## Installation and verification

Install canonical links only through the repository tooling:

```bash
python3 scripts/manage_skill_links.py --help
python3 scripts/install_server_wide_coordinator.py --help
```

Run focused tests in normal and optimized Python, repository boundaries, and
the applicable validation gate. Build macOS Apps owns native Board validation.
