# Governed Test Client

The stable `devcoordinator test` surface composes testd operations and emits
bounded decisions. It does not own a second run state machine.

## Contents

- [Command surface](#command-surface)
- [Enqueue and submission](#enqueue-and-submission)
- [Follow and replacement](#follow-and-replacement)
- [Diagnostics and bounds](#diagnostics-and-bounds)
- [Identity and compatibility](#identity-and-compatibility)
- [Optional MCP](#optional-mcp)

## Command surface

| Action | Purpose |
| --- | --- |
| `enqueue` | Validate manifest, create/register a policy-derived plan, and submit routine intents |
| `submit PLAN` | Submit one reviewed handoff/release plan |
| `follow RUN` | Read immediately or wait for one bounded decision |
| `queue-status` | Read bounded planning, scheduler, blocker, active-attempt, and capacity state without a run |
| `failures RUN` | Read one ordered cursor-bounded failure page |
| `cases RUN` | Read one ordered cursor-bounded case page |
| `artifact RUN ARTIFACT` | Resolve exact verified metadata and a bounded text tail where supported |
| `artifact-export RUN ARTIFACT --output FILE` | Verify and atomically materialize complete bytes locally |
| `cancel RUN --reason TEXT` | Request exact idempotent cancellation |
| `retry RUN --failed-only` | Create only a valid failed-work retry under retained policy |

The routine parser intentionally has no separate `status`, `summary`, or
`wait` aliases. `follow` owns immediate observation, bounded waiting, and the
terminal summary. The advanced administrative CLI may retain those exact reads
as thin mappings, but it cannot invent different lifecycle semantics.

## Enqueue and submission

`change`, `checkpoint`, and `manual` may preview and submit in one invocation.
`manual` accepts repeated declared `--target` values. `handoff` and `release`
create an immutable registered plan and return `dc1:plan:...`,
`submission_performed=false`, and the exact submit command.

The client generates the operation UUID before repository discovery. A prompt
acknowledgement is written before snapshot work and includes:

- the exact operation identity and typed continuation;
- the exact replay command using that same UUID; and
- a project-scoped `queue-status` command.

Repeating the UUID with identical input reconciles the original operation;
reusing it for different input is rejected. A lost acknowledgement never
authorizes a second plan or run.

## Follow and replacement

`follow --wait-seconds 0` performs one status read. A positive wait is bounded
caller patience, not an execution timeout and not cancellation.

Every successful path emits exactly one complete JSON result containing
`ok: true`, exact run identity, current state, `wait_timed_out`, continuation,
and next command. Terminal run conclusion remains a separate value.

While active, representative attempts expose bounded identity and liveness:
attempt ID, start, last heartbeat, lease expiry, target deadline, elapsed time,
current memory when known, and observed/retained output counters without output
text. Live failure-record count is read from retained failures and cannot be
reported as zero while the failure index is populated.

During a same-schema authority or testd replacement, follow tolerates typed
scheduler unavailability, maintenance, saturation, reset, and timeout until its
deadline. Each nested read uses no more than the remaining budget minus a final
response margin. It preserves the last valid observation, never resubmits, and
returns either the recovered truth or a bounded timed-out decision.

## Diagnostics and bounds

The absolute compact result ceiling is 8 KiB; enqueue, submit, and follow use a
4 KiB projection. Errors remain inside the absolute bound.

Failure and case pages return the largest ordered non-empty prefix that fits.
When either the store has more rows or a requested page was shortened by size,
`next_cursor` names the last returned record. Null appears only after complete
exhaustion. Every successful read or mutation explicitly sets `ok: true`.

Queue status distinguishes snapshot planning, scheduler wait, active execution,
current blockers, and memory-derived capacity. Unknown capacity stays null or
typed unknown; it is never fabricated.

## Identity and compatibility

Every plan/run/artifact operation carries the current authority-resolved
repository ID plus its exact opaque identity. A canonical root may dynamically
resolve authority enrollment even when a fresh local profile has zero or
duplicate stale routing rows; testd rejects cross-repository identities.

Generated continuations carry `--project` whenever repository context is known.
Opaque handles are references, not credentials, and never imply repository
scope.

Read-only follow, queue, failure, case, and artifact operations may cross a
same-schema release digest change only when protocol, authority generation,
schema, result bounds, capabilities, and exact requested identity still match. Enqueue,
submit, cancel, retry, and every non-test command retain exact release matching.

## Optional MCP

`devcoordinator-mcp` accepts protocol `2025-11-25` only. Its governed-test tools
map to the same stable parser: `test_enqueue`, `test_submit`, `test_follow`,
`test_cancel`, and exact artifact retrieval where advertised. MCP adds no plan,
submission, follow, retry, or conclusion semantics. Complete artifact export is
CLI-only because it writes an explicit local destination.
