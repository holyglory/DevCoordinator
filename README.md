# DevCoordinator

DevCoordinator is the host authority for local development runtimes shared by
multiple Codex, Claude, desktop, and OS-user sessions. It owns attributed port
leases, processes, Docker/Compose resources, local database stacks, telemetry,
logs, lifecycle evidence, short-lived workload policy, repository-scoped test
admission, and cleanup. A separate bounded test plane owns high-volume test
history, artifacts, and rollups.

The repository also contains:

- `codex-dev-coordinator`, the agent-facing runtime skill and Python API.
- `postgres-docker-backup`, verified PostgreSQL-in-Docker backup and restore.
- `DevOpsBoard`, the native macOS operations interface.
- `DevOpsConsole`, the authenticated web interface and routing edge.

## Architecture

- One local broker and authority WAL store own exact repository/resource
  identity, lifecycle policy, and generation fences; test, inventory, and
  Console state live in separate stores. Multiple Unix accounts are trusted
  execution contexts for one developer, not tenants; filesystem metadata is
  not an authorization boundary.
- A stable TLS/auth/routing edge and socket-owned listeners keep public routes
  and retained Console content available across backend replacement.
- The asynchronous test scheduler launches generation-fenced per-UID attempts
  outside the protected control slice and returns submissions immediately.
- Manifest-sealed Compose one-shots accept only an exact enrolled service,
  bounded timeout, and replay UUID; the broker publishes a typed receipt and
  never exposes raw process streams.
- One canonical Git worktree is one repository/project; repository families
  retain exact original and temporary-worktree identities.
- Python owns observation, membership, lifecycle, cleanup, diagnostics, and
  the `repository_trees` UI model.
- Inventory is a pure read; explicit observation updates host evidence.
- Unknown ownership, stale identity, and partial cleanup fail closed.

See [Single-developer local trust](docs/architecture/single-developer-local-trust.md)
for the deliberately simple same-server authorization model.

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

Evidence-producing repository tests use the asynchronous harness:

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py test manifest validate \
  --root-repo "$PWD"
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py test plan \
  --agent "$AGENT" --root-repo "$PWD" --no-temporary-repo --intent change \
  --execution-timeout-seconds 1800 --launch-timeout-seconds 300 \
  --operation-id "$PLAN_OPERATION_UUID"
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py test submit \
  --repository-id "$REPOSITORY_ID" --plan-id "$PLAN_ID" --operation-id "$OPERATION_UUID"
```

The execution timeout caps selected test processes; omitting it uses each manifest target's deadline. The launch timeout
separately bounds immutable materialization, startup, and lost-reply reconciliation. Every advanced submit, run read,
run control, artifact, and wait command carries the immutable repository ID returned by planning; opaque continuation
IDs never select repository scope. `test wait --timeout-seconds` controls only caller patience (up to 86,400 seconds),
never either execution deadline. Immutable plan preview uses the same launch budget because materialization is launch work.

The complete production contract is
[Universal test harness and control-plane isolation](docs/architecture/universal-test-harness.md).

Operators can correlate an actual Coordinator request without reading service
journals or caller-local filesystem metadata:

```bash
devcoordinator-call-log --failures-only --limit 100
devcoordinator-call-log --operation-id "$OPERATION_UUID" --limit 20
devcoordinator-call-log --run-id "$RUN_ID" --limit 20
```

The authority, API, scheduler, and snapshot boundaries share one JSONL journal
that rotates at a fixed size and retains only sanitized call stages, durations,
correlation IDs, and outcomes. Raw request payloads, environment values, and
credentials are not recorded.

Coordinator infrastructure and tool failures use a separate outage-safe,
open-only bug channel. It does not depend on repository enrollment, profiles,
the broker, API, authority, testd, or the call journal:

```bash
devcoordinator-bug report \
  --component test-harness --summary "launch failed before tests ran" \
  --expected "enqueue starts selected targets" \
  --actual "infrastructure_failure during launch" \
  --step "Run from the affected repository root." \
  --step "Invoke the command once." \
  --command-arg=devcoordinator --command-arg=test \
  --command-arg=enqueue --command-arg=--intent --command-arg=change
devcoordinator-bug list --limit 20
devcoordinator-bug close BUG_ID
```

Include every available call, operation, run, and attempt correlation. The
equivalent integrated form is `devcoordinator bug report|list|close`. Do not
auto-message a guessed Codex task. Closing physically removes the current open
record; there is no closed-report archive. Report only typed Coordinator tool
or infrastructure behavior: invalid caller arguments and direct sandbox
binds/probes that never contacted Coordinator are caller misuse, not
automatically Coordinator bugs.

If only the governed test harness fails, report it first and keep coding with
repository-native isolated unit/static checks labelled
`local/advisory — non-governed; not Coordinator evidence`. They never establish
handoff or release readiness and the governed tests must run after repair. This
fallback never covers host listeners, Docker/Compose, databases, shared
processes, or host mutation. Ordinary measured assertion failures are project
bugs, not Coordinator bugs. See
[DC-2026-08-04-BUG-INTAKE-01](DecisionDetails/DC-2026-08-04-BUG-INTAKE-01.md)
and the confirmed [security assumptions](security-assumptions.md).

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

Operational detail lives with the [Coordinator skill](skills/codex-dev-coordinator/README.md), [PostgreSQL backup skill](skills/postgres-docker-backup/README.md), [DevOps Board](apps/DevOpsBoard/README.md), [DevOps Console](apps/DevOpsConsole/README.md), and [repository history](docs/history/README.md).
