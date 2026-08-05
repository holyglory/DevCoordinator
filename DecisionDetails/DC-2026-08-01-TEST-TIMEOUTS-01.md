# DC-2026-08-01-TEST-TIMEOUTS-01 — Caller deadlines are semantic and launch replay is durable

## Context

Skydive.Live run `run-59dd34a81df8d388af157b47dc7f5582`
failed after about ten seconds with `request_timeout`, zero measured attempts,
zero cases, and no artifacts. The target itself never returned a test result.
The generic broker deadline covered immutable materialization, launch metadata,
`systemd-run`, and initial observation even though native launch subprocesses
already allowed longer execution.

A reply timeout is outcome-uncertain: the authority can start a runner just
before the client stops waiting. Treating that event as proof that nothing
started can both misreport the run and lose supervision of a live process.

## Selected contract

- `test plan --execution-timeout-seconds N` optionally overrides the actual
  runtime cap of selected targets for that plan. Omission retains each manifest
  target's declared timeout.
- `test plan --launch-timeout-seconds N` selects the total materialization,
  transient-start, and definitive-launch-reconciliation budget. The default is
  300 seconds.
- `test wait --timeout-seconds N` remains caller patience only, bounded to one
  day per invocation. It never changes or cancels the run.
- Queue expiry is not introduced. Queue age remains observable; a future expiry
  policy requires a separate user decision.
- Raw broker and test-plane socket timeouts are internal retry slices and are
  never mapped directly to a terminal test conclusion. One absolute launch
  deadline starts before repository-UID snapshot resolution. Snapshot, ticket,
  and runtime-launch calls receive only its remaining budget; deterministic
  ticket retries freeze both the operation ID and complete request arguments,
  so shrinking transport slices cannot change idempotency. Confirmed-status
  and cancellation reads remain bounded retry operations. `test wait`
  independently caps each status read to its remaining caller wait and returns
  `wait_timed_out` at that deadline even when an uncertain native attempt must
  remain supervised in the background.

The plan document binds the timeout policy into deterministic fingerprints.
Ticket and lease lifetimes cannot expire before the launch budget. Every launch
uses one deterministic operation UUID; a lost reply replays the identical
request. Pending launch identity is spooled before the first host RPC and
survives testd restart. The authority persists the exact broker ticket in the
launch record before native startup, so an authority restart can recover an
already-started deterministic runtime without starting it twice. Missing or
not-yet-observable launch evidence remains pending until the caller's launch
deadline. A definitive launch failure becomes a project-local
infrastructure diagnostic; uncertainty remains supervised rather than being
reported as a completed failure.

Private immutable attempt materialization prefers a filesystem reflink and
falls back to an independent byte copy when cloning is unsupported. Snapshot
size is bounded before materialization, so clone capability is an optimization,
not an admission condition.

Native observation requires only the unit's load, activity, and substate.
Terminal result, exit, OOM, and accounting fields are recorded when systemd
provides them, but empty terminal-only properties on a starting unit never turn
a successful native launch into a contract failure.

The protected publisher and trusted runner share one exact versioned launch
document contract. A broker-bound schema-2 document carries the retained launch
ticket; the runner validates and accepts it without receiving any secret. A
native process that exits before publishing its normal result produces one
deterministic, bounded infrastructure failure before the terminal envelope.

The authority owns verification and retention of runner artifacts. Its strict
systemd namespace therefore creates and grants write access to
`/var/lib/devcoordinator-test-artifacts`. A transient artifact-store `OSError`
is returned as a typed retriable attempt-runtime error rather than an internal
traceback; the same exact status request can converge after storage recovers.

## Trust assumptions

This change follows [security-assumptions.md](../security-assumptions.md): all
local accounts are the same developer and ordinary launch metadata contains no
secrets. A root-owned launch descriptor may therefore be readable by local
repository accounts while remaining non-writable; operational credentials stay
on their separate systemd credential transport.

## Verification

- Delay launch beyond the first socket retry slice and prove replay performs one
  host start and returns one handle.
- Spend part of the launch budget in repository-UID snapshot/ticket work and
  prove only the remaining budget reaches transient runtime submission.
- Make every wait status read exceed its transport slice and prove the command
  returns at the caller's independent wait deadline without inventing a
  terminal run state.
- Restart testd while launch acknowledgement is uncertain and prove the same
  operation converges without duplicate execution or false terminalization.
- Restart the authority after native startup but before its reply and prove the
  persisted ticket recovers the same runtime without another native start.
- Prove caller execution and launch timeouts survive plan encoding, preview,
  registration, ticketing, and runner launch.
- Prove a repository-UID runner reads but cannot modify its root-published
  launch descriptor.
- Observe a newly starting transient unit with empty or unavailable
  terminal-only systemd properties and keep it supervised as active.
- Round-trip the exact protected launch document through the trusted runner
  loader, and prove an early native exit retains one actionable failure row.
- Remove artifact-store creation or write access from the authority service and
  require topology validation to fail; inject a transient artifact-store error
  and prove a typed retry succeeds without error-log spam.
- Make software-owned delivery submit one real immutable, cross-account probe
  and require measured usage, a passed case, and captured artifacts before
  readiness.
