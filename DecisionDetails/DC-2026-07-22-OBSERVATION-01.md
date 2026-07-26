# DC-2026-07-22-OBSERVATION-01 — Metrics is the sole periodic host observer

## Context

Production logs showed Telegram host-observation failures about every 5.5
seconds, followed by “maximum number of host observation callers” errors.
Metrics and Telegram independently invoked the same serialized host-wide Docker
observation. The Console aborted its HTTP wait at 60 seconds while the
Python-to-broker operation could remain valid for up to 11 minutes; aborting
the outer request did not cancel that admitted broker caller. Repetition filled
the broker's four-caller ceiling and denied unrelated Console work.

## Decision

- Metrics is the only periodic host observer. Telegram retains explicit
  observation before approving a new recipient, then consumes durable events.
- Concurrent Console observations with the same exact project share one
  in-flight HTTP request; different projects remain isolated and a completed or
  failed flight is removed before a later retry.
- `/v1/observe` receives a 720,000ms client deadline, longer than the broker's
  bounded host-observation operation without widening ordinary controls.
- A required production Console completes self-registration and exposes its
  ready marker before any metrics or Telegram broker loop starts. Those loops
  are deferred for 90 seconds, beyond the installed 80-second external
  registration checker, so readiness inventory cannot be starved by background
  observation or event ingestion.
- The external registration check gives its single authenticated inventory read
  the entire remaining monotonic startup budget. The former three-second
  per-request cap abandoned valid broker work, retried while that work remained
  active, and produced an 84-restart amplification incident even though each
  Console had registered successfully.
- Metrics never holds the host/inventory sampler lock while observation is in
  flight. After failure, it retries after one sampling interval measured from
  failure completion and doubles to a 300,000ms cap. Host sampling and pure
  committed-inventory reads continue on every tick, and independent observation
  and inventory failures remain visible together.

## Alternatives rejected

Restarting the broker was rejected because its production cutover is still
blocked by quiescence and database terminality/replay work. Removing periodic
observation would leave current Docker presence dependent on unrelated agents.
Retrying every metrics or Telegram tick recreates caller exhaustion. Globally
coalescing different projects would collapse distinct authorization scopes.

## Guard evidence

Coordinator tests prove the 12-minute deadline, same-project joining,
different-project isolation, and retry after failure. Metrics tests prove a
slow observation cannot block later host/inventory ticks, backoff begins at
failure completion, then doubles and resets after success, and simultaneous
boundary failures remain visible. A production-entrypoint guard proves metrics
and Telegram cannot start before registration and that the deferred window
outlasts the external checker. A real delayed HTTP fixture takes longer than
the former three-second cap and proves the checker completes exactly one read
within its global deadline. Telegram tests prove eligible recipients continue to
consume events without issuing a second periodic observation while approval
still observes before advancing its durable cursor.
