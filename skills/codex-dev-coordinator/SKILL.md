---
name: codex-dev-coordinator
description: Coordinate attributed host-visible development runtimes through the server-wide DevCoordinator, including services, ports, health, logs, Docker or Compose resources, database stacks, temporary runtimes, and exact runtime operations across repositories or local accounts. Use when Codex must observe or change shared host runtime state, a coding sandbox cannot bind a development port, a valid Git repository needs first-use runtime adoption, or an uncertain runtime operation must be followed. Do not use for ordinary source inspection, editing, Git work, static checks, or governed test execution; use codex-governed-tests for tests.
---

# DevCoordinator Runtime

Use the installed `devcoordinator` client for host-visible runtime work. Keep
ordinary source work, Git inspection, formatting, and static checks local.
Use `$codex-governed-tests` for repository test selection, execution, and
evidence, including tests that need shared runtime state.

## Choose the stable runtime surface

Run from the intended Git worktree. Python derives the canonical root,
temporary-worktree relationship, caller attribution, release contract, and
immutable resource identities.

```bash
devcoordinator capabilities
devcoordinator targets web --kind service
devcoordinator runtime status web --kind service
devcoordinator runtime ensure web --kind service --desired ready
devcoordinator runtime capture_logs web --kind service
```

Use command-scoped `--project /absolute/worktree` only when the process is not
inside that worktree. Do not supply a separate root, temporary repository, or
attribution override to the stable client. Supply `--operation-id` only to
replay the exact prior mutation after an uncertain reply.

`runtime ensure` owns fresh observation, exact target binding, no-op detection,
safe start or stop selection, convergence, and terminal proof. Use explicit
`runtime start|stop|restart` only when that transition is the requested
semantic action. Treat `ok=false`, stale identity, unknown ownership,
unclassified state, or incomplete cleanup as unresolved.

## Start a first-use development server

Discovery is non-mutating. A valid new Git worktree returns
`repository.state=unenrolled`; do not ask an administrator to enroll it or
enable local fallback.

If direct npm, Vite, Python, or similar startup reports `EACCES`, `EPERM`, or a
host-port bind failure inside the coding sandbox, stop that direct attempt. No
Coordinator call occurred. “Local fallback is disabled” is an intentional
boundary, never an instruction to enable it.

Use one structured, TTL-owned start:

```bash
devcoordinator runtime serve prototype \
  --cwd . --port 4173 --ttl-seconds 3600 \
  --kill-after-run false --launch-timeout-seconds 30 -- \
  npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

`--cwd` is repository-relative, the port is exact and never silently changes,
the TTL is positive, `--kill-after-run` is explicit, and argv after `--` runs
without a shell. The broker atomically adopts the repository when needed and
executes repository code as the attributed non-root caller.

Interpret a rejection literally:

- `broker_contacted=false`, `mutation_performed=false`: local validation failed.
  Run `devcoordinator runtime serve --help`, correct the named field, and retry.
- `broker_contacted=true`: the broker returned the typed cause. For
  `port_in_use`, keep the assigned port and stop or wait for its exact owner.
- A null contact or mutation outcome is uncertain. Run the exact returned
  `devcoordinator operation follow dc1:operation:…` command; never invent a new
  operation UUID.

## Preserve runtime controls

- Target exact immutable IDs; names are convenience selectors, not identity.
- Keep generation fences and exact operation replay on replacement or mutation.
- Let systemd own each process cgroup, TERM/KILL escalation, TTL, and
  `populated=0` cleanup proof. Never write `cgroup.kill` directly.
- Run repository code only as the recorded non-root caller, never root or the
  control plane.
- Keep working directories and file operations inside validated repository or
  service-owned roots; do not follow caller-selected symlinks.
- Keep credentials out of argv, literal `--env`, manifests, results, and logs.
  Use only the sealed named credential transport.
- Never use direct `ps`, `systemctl`, Docker/Compose, port probes, or database
  inspection as a parallel lifecycle authority.

Stable sealed host operations include Docker storage inventory and exact
container removal, confirmation-bound volume cleanup, database backup and
retirement, Compose service recreation, ephemeral image status/prefetch, and
generation-fenced supervision. Read their help before use; arbitrary host
commands, paths, images, and Docker arguments remain unsupported.

## Report runtime-tool failures

Report a typed Coordinator tool or infrastructure defect through the
broker-independent launcher before dependent work continues:

```bash
devcoordinator-bug report \
  --component runtime --summary "typed runtime operation failed" \
  --expected "the exact target reaches the requested state" \
  --actual "TYPE: bounded failure" \
  --step "Run from the affected repository root." \
  --step "Invoke the structured command once." \
  --command-arg=devcoordinator --command-arg=runtime
```

Include available call and operation IDs. Do not report invalid caller
arguments or a direct sandbox bind that never contacted Coordinator. Do not
guess or auto-message another Codex task; resolve the exact active task and its
matching blocker first, or give the user a copyable notice.

## Use advanced interfaces only when required

The lower-level structured runtime contract remains:

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help
```

Its requests carry `root_repo`, explicit nullable `temporary_repo`, immutable
target identity, purpose, TTL where required, and `kill_after_run`. Routine
status/start/stop/restart/remove calls use flags; structured definitions,
replacement, and bounded run may use a request file. Do not hand-build routine
JSON or duplicate lifecycle logic in shell.

For DevCoordinator itself, never use the installed runtime or test surface to
validate or install the product under repair. Use
`python3 scripts/software_owned_delivery.py run --help`.

## References

- Read [the stable runtime client](references/agent-client.md) for command,
  result-bound, continuation, and MCP details.
- Read [the runtime API](references/runtime-api.md) only for structured runtime
  definitions and lower-level lifecycle calls.
- Read [server-wide administration](references/admin-operations.md) only for
  release, authority, policy, commissioning, or recovery work.
