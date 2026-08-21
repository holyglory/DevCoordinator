---
name: codex-governed-tests
description: Run and inspect repository tests through DevCoordinator's governed asynchronous test harness, and decide when a direct local test is allowed. Use when a test may collect more than 20 cases, may run longer than 10 seconds, cannot prove both bounds before launch, needs a shared listener, container, database, process, or durable evidence, requires handoff or release plan review, or needs follow, cancellation, bounded failures or cases, artifact retrieval or export, or test-harness failure recovery. Do not use for static checks or one focused local test proven before launch to collect at most 20 cases, finish within a runner-enforced 10-second deadline, and touch no shared runtime.
---

# Codex Governed Tests

Use DevCoordinator for asynchronous, attributed, bounded-evidence repository
tests. Testd and its isolated Test Store own plan, run, attempt, deadline,
result-order, conclusion, and lease semantics; calling agents do not recreate
them in shell or prose.

## Route the test before launch

A direct local test is allowed only when all facts are proven before launch:

- one focused selector collects at most 20 cases;
- a runner-enforced deadline caps execution at 10 seconds;
- no listener, container, database, shared process, or host mutation is needed;
- the command is not one fragment of a larger suite split across local calls;
  and
- durable, handoff, release, or shared evidence is not required.

Static analysis and formatting remain local. Unit-test isolation alone does not
prove eligibility. Route 21 cases, an 11-second allowance, unknown scope, an
unfiltered runner, and a thousand-case suite to one governed enqueue.

If `.codex/tests.json` is missing or invalid, report the setup gap. Run only a
focused test that still satisfies the local bounds. Do not silently run the
broad suite or reproduce it target by target.

Never use the installed governed harness to validate DevCoordinator itself.
This repository uses `python3 scripts/software_owned_delivery.py run --help` so
the product under repair is not its own evidence authority.

## Use the stable test journey

For change, checkpoint, or manual work:

```bash
devcoordinator test enqueue --intent change
devcoordinator test follow dc1:run:RUN_ID --wait-seconds 30
```

Enqueue emits a replay-safe acknowledgement before slow snapshot planning. It
includes the exact operation identity, replay command, and bounded
`queue-status` continuation; stdout still ends with one complete JSON result.

For handoff or release, enqueue stops after registered immutable plan creation.
Review the plan and execute its exact returned command:

```bash
devcoordinator test enqueue --intent release
devcoordinator test submit dc1:plan:PLAN_ID
```

`submission_performed=false` means no run was created. Never auto-submit a
handoff or release plan. Cancel only the exact returned run:

```bash
devcoordinator test cancel dc1:run:RUN_ID --reason "superseded by current work"
```

Use command-scoped `--project /absolute/worktree` from another cwd. Every
generated plan, run, operation, and diagnostic continuation includes that
canonical project when known and remains shell-safe for paths with spaces.

## Follow bounded evidence

The stable actions are exactly:

```text
enqueue  submit  follow  queue-status  failures
cases    artifact  artifact-export  cancel  retry
```

`follow` always returns one non-empty bounded JSON decision with `ok: true`,
state, timeout truth, continuation, and next command. For active attempts it
shows bounded exact attempt identity, start, heartbeat, lease/deadline, memory,
and content-free output progress. An advancing heartbeat is progress even when
case counts have not changed.

A bounded wait treats scheduler replacement, maintenance, saturation,
connection reset, and transport timeout as transient reads until its caller
deadline. It preserves the last valid status, never resubmits, and reserves
time to return one final decision. A zero-wait follow is one observation.

Read every returned failure or case page using `next_cursor`; pages remain under
the 8 KiB envelope and preserve every retained failure without gaps or
duplicates. A failed run conclusion is separate from command success.

Use `artifact` for verified metadata and bounded textual tails. Use
`artifact-export` for complete text, binary, or directory-archive bytes:

```bash
devcoordinator test artifact-export \
  dc1:run:RUN_ID dc1:artifact:ARTIFACT_ID \
  --output /canonical/new/evidence.tar
```

The output parent must be a canonical real directory and the destination must
not exist. The client verifies stable identity, contiguous chunks, total size,
and full SHA-256, then atomically publishes mode `0600`. Artifact bytes never
enter agent JSON, the call journal, Console, or public HTTP.

## Handle harness failures truthfully

An assertion or measured test failure is a project result, not a Coordinator
defect. For a typed Coordinator tool, admission, scheduling, launch, collection,
or evidence failure, file one structured report before fallback.

After reporting a harness failure, local development may continue only with the
same bounded tests and static checks. Label every result exactly
`local/advisory — non-governed; not Coordinator evidence`. Never ingest it into
Coordinator statistics or use it for handoff/release readiness. Rerun the
governed workflow after repair.

Fallback never authorizes listeners, Docker/Compose, databases, shared
processes, host mutation, a broad suite, or repeated bounded fragments. Do not
guess or auto-message another Codex task; prove the active task, repository, and
current blocker or give the user a copyable notice.

## References

- Read [the governed test client](references/governed-test-client.md) for exact
  commands, continuations, bounds, liveness, replacement, and MCP behavior.
- Read [manifest and evidence](references/manifest-and-evidence.md) for schema,
  drivers, retry, capability, state-handle, secret, and artifact contracts.
- Read [failure intake](references/failure-intake.md) for the copyable bug
  report, advisory fallback, task-routing rule, and fresh production bug audit.
