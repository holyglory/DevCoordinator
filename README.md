# DevCoordinator

DevCoordinator is the server-wide Python authority for attributed local
runtimes and governed asynchronous test evidence across repositories, agents,
and trusted local accounts.

## Architecture

- One canonical Git worktree is one project; linked worktrees remain children.
- Immutable IDs, generations, operation UUIDs, and lifecycle state—not names,
  paths, ports, images, or local account—select work.
- Repository code runs as the recorded non-root caller in systemd cgroups with
  bounded TTL and cleanup.
- Testd and its isolated Test Store own plans, runs, attempts, deadlines,
  ordered results, conclusions, and same-schema recovery.
- Credentials use separate sealed transport and never ordinary metadata, argv,
  results, or logs.
- Public identity and route grants remain authorization boundaries. Local Unix
  identities are attribution and execution domains on this single-developer
  host.

See [single-developer local trust](docs/architecture/single-developer-local-trust.md)
and the [universal test harness](docs/architecture/universal-test-harness.md).

## Agent quick start

Ordinary source inspection, editing, Git work, formatting, and static checks do
not need Coordinator.

For host-visible runtime work, use `$codex-dev-coordinator`:

```bash
devcoordinator capabilities
devcoordinator targets web --kind service
devcoordinator runtime status web --kind service
devcoordinator runtime ensure web --kind service --desired ready
```

For a new development server, use one contained, exact-port, TTL-owned start:

```bash
devcoordinator runtime serve prototype --cwd . --port 4173 \
  --ttl-seconds 3600 --kill-after-run false --launch-timeout-seconds 30 -- \
  npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

For repository tests, use `$codex-governed-tests`. A local invocation is allowed
only when proven before launch to collect at most 20 cases, enforce at most 10
seconds, need no shared runtime, and not split a larger suite. Otherwise:

```bash
devcoordinator test enqueue --intent change
devcoordinator test follow dc1:run:RUN_ID --wait-seconds 30
```

Handoff and release enqueue return a plan for review; run the exact returned
`devcoordinator test submit dc1:plan:…` command. Stable diagnostics remain
`queue-status`, `failures`, `cases`, `artifact`, `artifact-export`, and `retry`;
`cancel` targets one exact run.

## Failure handling

Report a typed Coordinator infrastructure/tool failure through the independent
open-only registry:

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

Do not auto-message a guessed task. After a harness report, bounded local checks
may continue only as `local/advisory — non-governed; not Coordinator evidence`;
they never prove handoff or release and never cover listeners, Docker/Compose,
databases, shared processes, or host mutation.

## Install the skills

This checkout is the only writable source for `codex-dev-coordinator`,
`codex-governed-tests`, and `postgres-docker-backup`:

```bash
python3 scripts/manage_skill_links.py plan \
  --repo-root "$PWD" --target-root /absolute/runtime/skills
python3 scripts/manage_skill_links.py apply \
  --repo-root "$PWD" --target-root /absolute/runtime/skills \
  --transaction-dir /private/path/outside-git
```

## Verification

DevCoordinator never tests or installs itself through its installed runtime or
test surface. Use the repository-owned workflow:

```bash
python3 scripts/check_repository_freshness.py --repo "$PWD" --json
python3 scripts/run_fast_repository_validation.py
python3 scripts/software_owned_delivery.py run --help
```

Board build, XCTest, launch, and packaging run through Build macOS Apps. The
full non-native gate remains `python3 scripts/validate.py --skip-macos-app`.

Canonical code lives in `skills/codex-dev-coordinator/scripts`; skills live in
`skills/`, applications in `apps/`, release/verification tools in `scripts/`,
and durable architecture records in `docs/` and `DecisionHistory.md`.
