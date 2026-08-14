---
name: codex-dev-coordinator
description: Manage attributed local services, Docker or Compose resources, database stacks, ports, health, logs, telemetry, temporary runtimes, and evidence-producing asynchronous tests through the server-wide DevCoordinator. Use when work must observe or change host runtime state across repositories or accounts, including when a coding sandbox cannot bind a development port or a valid Git repository is not yet enrolled. Also use for any test invocation that may collect more than 20 cases, may run longer than 10 seconds, cannot prove both bounds before launch, or must produce durable shared evidence. Do not use for ordinary source inspection or editing, Git review, local static checks, or a proven bounded test that touches no shared runtime.
---

# DevCoordinator

Use DevCoordinator for host-visible runtime work, durable shared test evidence,
and test execution beyond the local feedback bounds below. Keep ordinary
source work, static checks, and proven bounded tests local and direct.

## Start with the intent client

Run `devcoordinator` from the active Git worktree. It derives the canonical
root/temporary-worktree context and attribution, validates the installed client
against the active authority, resolves a unique selector to an immutable target
ID, and returns bounded JSON.

```bash
devcoordinator capabilities
devcoordinator targets web --kind service
devcoordinator runtime status web --kind service
devcoordinator runtime ensure web --kind service --desired ready
devcoordinator storage inventory
```

`capabilities.efficiency` is optional. When present, an installed
delivery-efficiency recorder automatically publishes its current account's
bounded cumulative repository snapshot after a terminal declaration. Agents do
not copy raw ledgers, paths, prompts, or counters into Coordinator, and a
missing or failed projection never changes the recorder outcome. The Console
owns repository-level viewing; use `devcoordinator efficiency ingest` directly
only for recorder integration tests or recovery diagnostics.

Use command-scoped `--project /absolute/worktree` only when the process is not
running inside the intended worktree. The intent client accepts no separate
root-repository, temporary-repository, or attribution override; Python derives
them. Supply `--operation-id` only to replay the exact prior mutation UUID after
an uncertain reply; never mint a new UUID for the retry.

### First use and development servers

Discovery never changes repository or host state. In a valid new Git worktree,
`devcoordinator capabilities` and `devcoordinator targets` report
`repository.state=unenrolled` and explain that first-use adoption is supported.
Do not ask an administrator to enroll it, enable local fallback, or try to bind
the port inside the coding sandbox.

If a direct `npm`, Vite, Python, or similar command reports `EACCES`, `EPERM`,
or that it cannot bind a host port in the coding sandbox, stop that direct
launch attempt. This is the expected sandbox boundary, not an application-port
defect and not evidence that the broker is down. No Coordinator call occurred.
Use the single `runtime serve` call below. Likewise, “local fallback is
disabled” describes an intentional boundary; it is never an instruction to
enable fallback. For a valid unenrolled Git root, use `runtime serve` so the
broker adopts and launches it in one operation.

Start a new bounded development server with one structured call:

```bash
devcoordinator runtime serve prototype \
  --cwd . --port 4173 --ttl-seconds 3600 \
  --kill-after-run false --launch-timeout-seconds 30 -- \
  npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

Use `--project /absolute/worktree` when outside that worktree. `--cwd` is
repository-relative; `--port` is the exact requested port and never silently
hops; argv after `--` is executed without a shell. A positive TTL is mandatory,
and `kill-after-run` must be explicit. This single caller command owns the
idempotent adoption-and-launch workflow, starts the service as the attributed
local account, and returns operation/session/service handles, URL, PID, expiry,
and cleanup ownership. If adoption succeeds but launch is rejected, the error
truthfully reports that durable mutation instead of pretending the whole call
was unchanged. Python generates the operation ID; pass `--operation-id` only
when replaying the exact same request after an uncertain reply.

Every rejected call states its phase, whether the broker was contacted, whether
mutation occurred, whether an exact retry is useful, and the next command or
corrective action. Do not infer a broker outage from a client-side validation
failure. Follow an uncertain operation handle; correct a certain invalid request
before retrying it.

Interpret the envelope literally:

- `broker_contacted=false` and `mutation_performed=false`: context or command
  validation failed locally. Run the returned help command, correct the call,
  and retry; do not change enrollment, fallback, or host permissions.
- `broker_contacted=true`: the broker returned the typed cause. For
  `port_in_use`, keep the exact port, stop or wait for its known owner, then use
  a fresh operation. On first use, `mutation_performed=true` may truthfully mean
  repository adoption succeeded even though service launch did not.
- A `null` contact or mutation outcome is uncertain. Run the exact returned
  `devcoordinator operation follow dc1:operation:…` command; never invent a new
  operation ID.

For a malformed serve call, run `devcoordinator runtime serve --help`. Required
inputs are a lowercase name, repository-relative `--cwd`, one exact `--port`, a
positive `--ttl-seconds`, explicit `--kill-after-run true|false`, bounded
`--launch-timeout-seconds`, and structured argv after `--`.

`runtime ensure` owns fresh observation, exact target binding, no-op detection,
the safe start/stop choice, convergence, and terminal proof. It returns
attention instead of guessing when identity, health, ownership, or the final
state is uncertain. When an enrolled repository declares a sealed Compose
dependency that has not been observed yet, `ensure --desired ready` performs
the deterministic first-use Compose bootstrap, refreshes the authoritative
target, and then proves readiness in the same caller workflow. Use explicit
`runtime start|stop|restart` only when that transition itself is the requested
semantic action. Use `runtime capture_logs` for one exact target rather than
reading host logs directly.

Replace one persistent service definition through the structured CLI. The
expected generation is a compare-and-swap fence, not an access grant:

```bash
devcoordinator runtime replace worker --kind service --cwd . \
  --expected-generation 4 --env MODE=dev -- \
  /usr/bin/python3 worker.py
```

Local Unix accounts on this single-developer server share enrolled exact
runtime grants. The kernel caller remains attribution, while repository
membership, exact resource identity, action, generation, and idempotent
operation identity remain authoritative.

Docker storage inventory and mutations are broker-owned surfaces. Writable
layers, logs, and named volumes are measured directly; image attribution is
logical and may share layers. The host total is Docker's own system-wide
storage summary. On this confirmed single-developer server, the agent or user
owns the semantic container-deletion decision:

```bash
devcoordinator storage inventory
devcoordinator storage remove container EXACT_RESOURCE_ID --reason "obsolete one-off"
devcoordinator storage plan volume EXACT_VOLUME_NAME --reason "retired project volume"
devcoordinator storage apply --plan PLAN_UUID --fingerprint sha256:PLAN_HASH --confirm "EXACT PHRASE"
```

The first inventory call may truthfully return `collecting`; repeat after the
bounded background sample completes. `storage remove container` is one direct
attributed removal. It does not consult repository association, cleanup grants,
archive state, running or mount state, Compose role, database bindings,
fingerprints, a cleanup plan, a confirmation phrase, or a second observation.
Python resolves the selected current target to its full native ID and invokes
only `docker rm -f <64-character-id>` without `-v`. It may therefore terminate
a running container and discard its writable layer, but it does not remove
named or anonymous volumes.

Volume plan/apply remains separate because volume deletion is a data-retention
decision. It requires the current exact volume plan and returned confirmation.
Images and build-cache rows remain read-only accounting candidates. Never use
Docker prune or whole-project Compose teardown as a substitute.

If a mutation reply is lost or uncertain, follow its returned handle:

```bash
devcoordinator operation follow dc1:operation:00000000-0000-4000-8000-000000000000
```

The installed client fails before dependent work when its release, authority
generation, broker protocol, result schema, or required 8 KiB result envelope
disagrees with the active authority. Do not bypass a mismatch through another
interface.

## Route tests by scope

Local test execution is for narrow feedback, not whole suites. A direct local
test invocation is permitted only when all of these facts are established
before launch:

- it needs no host-visible or shared runtime, listener, container, database, or
  process;
- its selector collects at most 20 test cases;
- a runner deadline prevents it from executing for more than 10 seconds; and
- it is one focused invocation, not one fragment of a suite split into repeated
  local commands.

Unit-test isolation does not make a broad invocation locally eligible. Use an
explicit selector plus runner collection metadata or a prior measurement to
establish the case bound. If either bound is unknown, collection would exceed
20 cases, execution may exceed 10 seconds, the runner cannot enforce the
deadline, or the result must become shared evidence, use one governed batch.
Static analysis and formatting checks are not test cases and remain local.

Boundary examples are deterministic: one explicitly selected test with no more
than 20 collected cases and a 10-second runner deadline may stay local; 21
collected cases, an 11-second execution allowance, unknown case or runtime
scope, an unfiltered runner, and a thousand-case suite all use Coordinator.

When `.codex/tests.json` exists, enqueue the policy-derived workflow once:

```bash
devcoordinator test enqueue --intent change
devcoordinator test follow dc1:run:RUN_ID --wait-seconds 30
```

Do not recreate the selected batch by invoking its test files, packages, or
targets one at a time locally. If `.codex/tests.json` is absent or invalid, a
test beyond the local bounds is a governed-test setup gap; run only a bounded
focused subset locally and report the missing manifest instead of silently
running the broad suite.

`change`, `checkpoint`, and `manual` plan and submit in one caller invocation.
For `manual`, repeat `--target NAME` to select declared targets. `handoff` and
`release` intentionally stop after immutable plan creation; review the returned
plan, then execute its exact `next_command`:

```bash
devcoordinator test enqueue --intent release
devcoordinator test submit dc1:plan:PLAN_ID
```

Submission is asynchronous. Follow only the returned run handle. A bounded wait
controls caller patience; it neither changes nor cancels the run. Python owns
manifest validation, prerequisite and plan selection, routine submission,
bounded follow projection, durable launch reconciliation, and the manifest's
safe retry policy. Manifest schema 3 is the only accepted schema and requires
an explicit retry policy per target. Automatic retry is limited to an expired
lease before launch; test failures are never retried as infrastructure.
Targets that request no protected capability do not need a capability grant;
network, fixture, secret, and other declared capabilities remain policy-gated.

## Report Coordinator failures without blocking source work

An ordinary measured assertion failure is a project bug, not a Coordinator
bug. Fix the project or its test and use the returned governed evidence; do not
file a Coordinator report merely because a test failed.

On any Coordinator infrastructure or tool failure, first create one structured
open report through the broker-independent launcher. Include a concise summary,
expected behavior, the exact typed actual failure, ordered reproduction steps,
the original argv as repeated structured arguments, and every correlation the
failure made available:

```bash
devcoordinator-bug report \
  --component test-harness \
  --summary "governed tests failed before any measured attempt" \
  --expected "enqueue starts the selected governed targets" \
  --actual "infrastructure_failure: snapshot service unavailable" \
  --step "Run from the affected repository root." \
  --step "Invoke the command once and follow the returned run." \
  --command-arg=devcoordinator --command-arg=test \
  --command-arg=enqueue --command-arg=--intent --command-arg=change \
  --classification infrastructure_failure --stage launch \
  --call-id CALL_ID --operation-id OPERATION_ID --run-id RUN_ID
```

Omit correlation flags that were not returned; add `--attempt-id` when one was.
`devcoordinator bug report ...` is the equivalent integrated form. Intake does
not require repository discovery, a profile, broker, API, authority, testd, or
call-journal availability. Do not auto-message another Codex task or guess
which task owns the affected repository; return the report ID and a copyable
notice to the user instead.

Write every report so another Coordinator server can reproduce it without the
original repository checkout. Use `$REPOSITORY` in ordered steps and structured
argv instead of private absolute paths, name the required project state and
tool versions in plain text, and include the typed failure plus every returned
correlation. Do not refer only to a local log file, temporary path, task, or
agent memory. Console exports preserve the source server and bug identity;
imports remain visibly remote and never merge with a matching local report.

In a Codex filesystem sandbox, invoke the installed launcher through the
already-approved actual-caller/host execution path. `EACCES` or `EROFS` for
`/var/lib/devcoordinator-bugs` means the exact command was run in the wrong
execution context; retry the same structured argv as the actual caller. Do not
relocate the registry, weaken its contract, or turn that retry into a repeated
user approval.

Report only a typed Coordinator tool or infrastructure behavior failure. An
invalid caller argument rejected before Coordinator contact, or a direct
sandbox bind/probe that produced no Coordinator result, is caller misuse—not
automatically a Coordinator bug. Correct the invocation instead of filing a
report merely because the direct probe failed.

The registry contains current open reports only:

```bash
devcoordinator-bug list --limit 20
devcoordinator-bug close BUG_ID
```

Closing physically removes the report; there is no closed-report history,
tombstone, or hidden archive. A later recurrence receives a new identity.

A Coordinator test-harness failure blocks governed evidence, not source
development. After filing the report, continue repository-native static checks
and test invocations that still satisfy the same local limit of at most 20
collected cases and at most 10 seconds of execution, when they need no
host-visible or shared state. Do not split a larger suite into repeated bounded
local invocations. Label every such result exactly `local/advisory —
non-governed; not Coordinator evidence`, keep it out of Coordinator statistics,
never claim handoff or release readiness from it, and rerun the governed
workflow after repair. If useful, record that advisory check with
`--local-fallback-status`, repeated `--local-test-command-arg`, and
`--local-fallback-summary` on the report.

This fallback never permits tests or runtime work requiring host listeners,
Docker or Compose, databases, shared processes, or any host mutation. Those
remain Coordinator-owned and wait for repair. The boundary follows
[DC-2026-08-04-BUG-INTAKE-01](../../DecisionDetails/DC-2026-08-04-BUG-INTAKE-01.md),
[security-assumptions.md](../../security-assumptions.md),
`UIL-DOCUMENTATION-002`, `UIL-TESTING-006`, and `UIL-TESTING-011`.

## Optional MCP surface

When the calling environment supports MCP stdio, `devcoordinator-mcp` exposes
the path-free runtime/test tools `capabilities`, `targets`, `runtime_status`,
`runtime_ensure`, `operation_follow`, `test_enqueue`, `test_submit`, and
`test_follow`. It also exposes the outage-independent `bug_report`, `bug_list`,
and `bug_close` tools. Those bug tools use the same open-only registry as
`devcoordinator-bug`; they do not load repository context, profiles, or
Coordinator services, and `bug_close` physically removes the exact report.

The server accepts MCP protocol `2025-11-25` only and rejects every other
requested version. Prefer the interface already integrated with the calling
environment. Runtime/test CLI and MCP share context discovery, contract fences,
target resolution, operation identity, and result bounds; bug CLI and MCP share
the independent bounded report/list/close contract.

## Agent decisions versus Python execution

The agent or user chooses the goal, desired state, test intent, material target
selection, semantic deadlines, and every destructive, handoff, or release
approval. Python owns mechanical discovery, exact IDs, validation, planning,
routine execution/following, supported cleanup/recovery/supersession, and
desired-state convergence. Do not recreate that machinery in shell, prose, or
model-authored JSON.

Advanced `dev_coordinator.py`, `devcoordinator-test`, and lower-level project,
server, Docker, port, broker, archive, backup, and recovery commands are
separate current capabilities for structured definitions, replacement, bounded
run, removal, manifest authoring/doctoring, exact artifact drill-down, or
administrator work outside the intent client. Read the relevant `--help` and
[references/admin-operations.md](references/admin-operations.md) only when one
of those cases is actually required.

The advanced structured executable contract is
`python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help`;
its structured lifecycle schema explicitly carries `root_repo`,
`temporary_repo`, `kill_after_run`, and `status/start/stop/restart/remove`.

## Safety and evidence

- Never use `ps`, `systemctl`, Docker/Compose, port probes, or direct database
  inspection as a parallel lifecycle authority.
- One canonical Git worktree is one project. Python owns the root repository →
  temporary repository → resource hierarchy. Names, paths, ports, images, and
  UI grouping are not ownership evidence.
- Treat `ok=false`, typed attention, unknown ownership, stale identity,
  unclassified resources, or incomplete cleanup as unresolved.
- Register a provably owned running resource rather than launching a duplicate.
  Do not change ports after a collision unless the user changes the assignment.
- A tripped persistent-worker crash loop stays stopped until the worker is
  repaired and an explicit action re-arms it.
- Before destructive PostgreSQL-in-Docker work, use `postgres-docker-backup`
  against the verified immutable container ID.
- On this confirmed single-developer host, local Unix identity is attribution,
  not a new authorization gate. Do not preflight UID/GID/mode/ACL, path
  traversal, local executable visibility, or socket ownership. Attempt the
  typed call and use its evidence.

For a failed or apparently absent call, correlate the operation/run through the
bounded shared call journal instead of inferring from caller-side filesystem
state:

```bash
devcoordinator-call-log --operation-id OPERATION_UUID --limit 20
devcoordinator-call-log --run-id RUN_ID --limit 20
```

Report the outcome, immutable handle/ID, one relevant URL or artifact, and one
next command. Do not paste raw logs or large case lists into model context.

## Deliver DevCoordinator changes

For this repository, run the repository-owned workflow once after the complete
edit batch:

```bash
python3 scripts/software_owned_delivery.py run --help
```

It owns source verification, immutable packaging, deployment, acceptance,
durable evidence, and concise reporting. Do not reconstruct that flow manually.

## Further help

- Intent-client contract, bounds, calls, and ownership:
  [references/agent-client.md](references/agent-client.md)
- Advanced runtime schema and lifecycle details:
  [references/runtime-api.md](references/runtime-api.md)
- Rare server-wide procedures:
  [references/admin-operations.md](references/admin-operations.md)
