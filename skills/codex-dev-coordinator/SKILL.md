---
name: codex-dev-coordinator
description: Use when coding agents in one or multiple apps, sessions, or OS accounts need attributed local service, Docker/Compose, database-stack, port, health, log, telemetry, test, or temporary-runtime lifecycle control.
---

# Codex Dev Coordinator

Use this skill before inspecting or changing a local development runtime.
Python owns discovery, ownership, ports, lifecycle, telemetry, crash evidence,
and cleanup; do not reproduce those decisions in shell or helper scripts.

## Required entrypoint

Resolve the canonical script from this skill directory:

```bash
COORDINATOR="scripts/dev_coordinator.py"
python3 scripts/dev_coordinator.py runtime --help
python3 "$COORDINATOR" runtime status \
  --agent "$AGENT" --root-repo "$ROOT_REPO" --no-temporary-repo \
  --target-kind service --target-id "$RESOURCE_ID" --target-name web \
  --purpose development --no-ttl --kill-after-run false
python3 "$COORDINATOR" runtime --request-file /absolute/request.json
```

Use flags for ordinary existing-target status/start/stop/restart/remove work.
Use a request file only for a structured definition, replacement, or bounded
`run`; never hand-build JSON in routine Python or shell wrappers. Both forms
enter the same validator. Every request includes:

- `schema_version: 1` and the current agent/session identity;
- the canonical original `root_repo` and explicit nullable `temporary_repo`;
- purpose plus target kind and immutable target ID;
- explicit `kill_after_run`, and a positive bounded TTL for test/temporary
  start-like work. Status and explicit stop use no TTL.

Docker and database-stack replacement currently fails before host access with
`unsupported_safe_replace`. Do not emulate it with lower-level commands.

For a persistent worker, first start sets `--keep-alive true|false`. Keep Alive
restarts traced crashes. Ten crashes in an inclusive 300-second window trip
the default non-expiring breaker; after fixing the worker, explicitly start
with `--rearm-crash-loop true`.

Worker `remove` is staged: obtain and then apply the Archive plan, then obtain
and apply the distinct permanent-cleanup plan with its exact ID, fingerprint,
and confirmation phrase. Removal unregisters native startup and active
catalog/policy/ACL state while retaining tombstone, crash, operation, and log
evidence. Only `broker enroll --explicit-reinstall` creates a new incarnation.

## Interpret the result

The compact response reports `ok`, classification, readiness, operation and
repository context, immutable resources, ports/domains, CPU/memory breakdowns
and family totals, stale processes, crashes, cleanup, and typed log links.
Treat `ok=false` as failure even when a URL answers. Preserve its blocker,
operation ID, cleanup state, and artifacts.

An unclassified active family resource is a pre-mutation error. Unknown
listener ownership, stale fingerprints, partial mutation, and incomplete
cleanup also fail closed.

## Rules agents retain

- One canonical Git worktree is one project. Python proves and publishes the
  original-root -> temporary-worktree -> service hierarchy.
- Use immutable IDs. Names, images, ports, remotes, and path resemblance are
  not ownership evidence.
- Never try the default port and silently move after a collision. Durable
  assignment and leasing belong to the Coordinator.
- Register an already-running, provably owned resource rather than launching a
  duplicate. Use `server register` or `docker register` only when exact
  ownership evidence permits it.
- Do not run package-manager servers, Docker/Compose, or local database stacks
  directly. Use a lower-level Coordinator command only when the runtime result
  identifies that repair and its `--help` confirms the authority.
- For root-only `broker publish-image` apply/rollback, activate the shared
  maintenance marker first and stop **only** `devcoordinator-broker.service`.
  Keep `dev-coordinator.service` and `devops-console.service` running so every
  Console and agent receives the bounded maintenance response. Always restart
  the broker and clear the exact maintenance deployment ID in a `finally`
  path. The command rejects mutation when either safeguard is absent.
- Before destructive PostgreSQL-in-Docker work, invoke
  `postgres-docker-backup` against the verified immutable container ID.

## Shared authority and profile reload

Managed hosts use one service-owned SQLite/WAL authority through an
OS-peer-authenticated Unix socket. Clients never open its database; private
per-user journals hold launch/log/reconciliation evidence only. Explicit
account authority is isolated compatibility/test scope, never host-global
evidence.

The broker rechecks peer UID, protected profile, repository generation and
family, exact membership, and action grants. Worker-role services support
peer-UID lifecycle and generation-checked replacement through the fixed
runner. Enrolled Docker/database targets support exact-ID status/start/stop/
restart. Unsupported service roles and shared TTL/`run` work fail closed; do
not switch authority modes as a workaround.

In system mode the API validates the protected profile before binding and
watches only its publication identity. After a stable atomic replacement it
logs one `api.profile_changed` event and exits cleanly so `Restart=always`
reloads strict authorization. It never logs profile contents or restarts the
broker/Public Console; malformed replacements fail the supervised startup
gate. Authorization/schema drift must be repaired offline through the
installer's documented plan/verify workflow before restarting the broker.

During an administrator-owned offline upgrade, every new client call first
checks the protected broker-independent maintenance marker. A trusted active
marker returns classification `maintenance`, code `maintenance_in_progress`,
and a bounded retry interval before any socket connection. Invalid marker
identity, mode, or content fails closed as `maintenance_state_invalid`. Wait
and retry through this skill; never bypass the fence with direct state, Docker,
database, process, or socket access. The marker remains available when systemd
removes the broker's separate runtime directory and only its deployment owner
may clear it after service and registration verification or healthy rollback.

Inventory is a pure read. Runtime performs any required bounded observation
before action and returns committed evidence. Board and Console consume
Python-produced `repository_trees`; they never infer grouping.

## Broker-owned ephemeral containers

Server-wide temporary containers use administrator-sealed
`.codex/dev-runtime.json` `ephemeral_containers` templates. Templates pin the
image digest, argv/non-secret environment, TTL, loopback port range, CPU,
memory, and repository/per-UID concurrency budgets. Agents cannot supply
images, commands, mounts, privileges, secrets, or arbitrary Docker flags.

```bash
python3 "$COORDINATOR" ephemeral start \
  --agent "$AGENT" --project "$ROOT_REPO" --template artifact-db \
  --ttl-seconds 1800 --operation-id "$OPERATION_UUID"
python3 "$COORDINATOR" ephemeral status \
  --project "$ROOT_REPO" --run-id "$RUN_ID"
python3 "$COORDINATOR" ephemeral renew \
  --agent "$AGENT" --project "$ROOT_REPO" --run-id "$RUN_ID" \
  --ttl-seconds 1800 --operation-id "$OPERATION_UUID"
python3 "$COORDINATOR" ephemeral finish \
  --agent "$AGENT" --project "$ROOT_REPO" --run-id "$RUN_ID" \
  --reason "validation complete" --operation-id "$OPERATION_UUID"
```

Retain one operation UUID per mutation and replay uncertain outcomes with the
same inputs. Status/finish retain exact owner cleanup access after ordinary
enrollment revocation; they never revive a template or broaden authority.
Creation is precommitted and recovered only from the full sealed label set and
immutable container identity. The optional PostgreSQL password-file policy is
the only broker-owned secret capability; credential bytes never enter argv,
ordinary environment, SQLite, profiles, logs, or replies.

## Universal test harness

When a repository declares `.codex/tests.json`, use its structured harness
instead of invoking the underlying framework directly:

```bash
python3 "$COORDINATOR" test run \
  --agent "$AGENT" --project "$ROOT_REPO" --profile all
python3 "$COORDINATOR" test stats \
  --project "$ROOT_REPO" --days 30 --limit 25
```

Profiles select declared groups; a single pytest group may receive exact
`--select` node IDs. The non-root client runner executes structured argv
without a shell. The broker owns admission, attribution, idempotency, durable
session/group/case records, and statistics; raw commands, environment values,
child output, credentials, and failure payloads stay out of the service log.

## Further help

- Runtime contract: [references/runtime-api.md](references/runtime-api.md)
- Skill overview: [README.md](README.md)
- Current schemas and operations: `python3 scripts/dev_coordinator.py --help`
  and the relevant subcommand `--help`
- Installation: `python3 scripts/install_server_wide_coordinator.py --help`
- Validation: `python3 scripts/validate.py --skip-macos-app`

Keep this file below 300 lines. Put evolving detail in executable help,
focused tests, or the linked reference.
