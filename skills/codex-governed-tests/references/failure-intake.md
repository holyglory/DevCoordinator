# Failure Intake and Advisory Fallback

Use this workflow for a typed Coordinator tool or infrastructure failure, not
for an assertion or ordinary project test failure.

## Contents

- [Report first](#report-first)
- [Classify correctly](#classify-correctly)
- [Continue bounded local work](#continue-bounded-local-work)
- [Route notices safely](#route-notices-safely)
- [Inspect, close, and audit](#inspect-close-and-audit)

## Report first

The standalone launcher remains available without repository discovery,
profiles, broker, API, authority, testd, or call-journal health:

```bash
devcoordinator-bug report \
  --component test-harness \
  --summary "governed tests failed before any measured execution" \
  --expected "enqueue starts the selected governed targets" \
  --actual "infrastructure_failure: snapshot service unavailable" \
  --step "Run from the affected repository root." \
  --step "Invoke the command once and follow the returned run." \
  --command-arg=devcoordinator --command-arg=test \
  --command-arg=enqueue --command-arg=--intent --command-arg=change \
  --classification infrastructure_failure --stage launch \
  --call-id CALL_ID --operation-id OPERATION_ID --run-id RUN_ID \
  --attempt-id ATTEMPT_ID
```

Required fields are component, summary, expected behavior, actual typed
failure, and at least one ordered step. Repeat `--command-arg=ARG` in exact argv
order, using the equals form when an argument begins with `-`. Include every
available call, operation, run, and execution ID; omit correlations not returned.
The current bug CLI names the execution-correlation option `--attempt-id`; that
field is diagnostic attribution and does not imply a lease or recoverable
multi-attempt test lifecycle.
`devcoordinator bug report ...` is the equivalent integrated form when the
stable client remains available.

Write a cross-server reproducer. Replace private roots with `$REPOSITORY`, name
required project state and versions, and never depend only on a private log,
temporary path, task, or agent memory. Exclude raw logs, environment dumps,
credentials, and secrets.

## Classify correctly

Report only a typed Coordinator behavior failure in validation, admission,
scheduling, launch, collection, evidence, or its tools. An invalid caller
argument rejected before contact is caller misuse. A direct sandbox bind or
probe with no Coordinator result is also caller misuse, not automatically a
Coordinator bug.

An actually measured assertion, test failure, or project process exit is a
project result. Fix the project or test and use governed evidence.

## Continue bounded local work

After filing a harness report, source development may continue with static
checks and repository-native tests only when each invocation still:

- collects at most 20 cases;
- enforces at most 10 seconds of execution;
- needs no listener, container, database, shared process, or host mutation; and
- is not one fragment of a broad suite.

Label every result exactly:

```text
local/advisory — non-governed; not Coordinator evidence
```

These results never enter Coordinator statistics, establish immutable source,
or prove handoff/release readiness. Rerun the governed workflow after repair.
The report may record `--local-fallback-status`, repeated
`--local-test-command-arg=ARG`, and `--local-fallback-summary`.

## Route notices safely

Do not auto-message a remembered Codex task. Resolve current task metadata and
require one exact match on active status, repository, and most recent blocker.
If zero or multiple tasks match, send nothing; return the report ID and a
copyable notice to the user. Never infer a destination from repository name or
agent memory.

## Inspect, close, and audit

The registry contains current open reports only:

```bash
devcoordinator-bug list --limit 20
devcoordinator-bug close BUG_ID
```

Closing physically removes the exact open report; there is no closed history,
archive, or tombstone. Close only after reproducing, fixing, deploying, and
verifying that report through its original surface.

A zero-bug completion claim requires one fresh authenticated read from the
exact production `/api/bugs` authority and one rendered `#/bugs` check from the
same base URL and release. Local CLI output, cached state, or an earlier
screenshot is insufficient. Any returned report keeps readiness open.
