# Protected profile publication reloads loopback readers

## Context

On 2026-07-24, `dev-coordinator.service` had been running since 09:36 UTC. The
strict repository-profile reader changed at 20:32, and the protected profile
was atomically republished at 20:47 with additive ephemeral-policy fields. The
broker later restarted onto current source, but the independent loopback API
did not. Its old in-memory reader returned HTTP 500 with `broker repository
profile fields are invalid` for inventory, servers, and events while anonymous
`/healthz` still returned 200. The public Console remained available but could
not display Coordinator data, and Telegram ingestion retried the same failure.

## Decision

In server-wide mode, the loopback API validates that it can parse one stable
protected-profile identity before it binds. It watches only publication
metadata—device, inode, size, modification time, ownership, group, and
permissions—and never exposes or logs profile contents. Two consecutive
changed observations are required. A stable replacement emits one structured
journal event, closes the listener, and exits cleanly; the existing
`Restart=always` unit reloads current source and revalidates the new profile.

The restart boundary remains the loopback API only. It does not restart the
server-wide broker or public Console, mutate the authority database, change
grants, or publish another profile.

## Options considered

- **Keep manual restart instructions.** Rejected because an otherwise healthy
  deployment can republish authority data hours after a reader starts, leaving
  authenticated requests broken until a human notices.
- **Ignore unknown repository fields.** Rejected because the protected profile
  is an authorization boundary; silently accepting unreviewed fields weakens
  strict schema validation and can hide a writer/reader contract error.
- **Restart the broker and Console with every profile publication.** Rejected
  because those are independent availability boundaries and neither process
  needs replacement to reload the loopback reader.
- **Validate on startup and restart the loopback API after stable identity
  replacement.** Selected because it preserves strict parsing, bounds the
  restart to the stale process, and makes atomic publication self-healing.

## Verification

Deterministic tests prove a stable atomic replacement requests exactly one
shutdown, unchanged identity does not restart, and a validation-time identity
race is retried in normal and optimized Python. The full 29-test profile trust
suite passes in both modes. Production verification proved a new API MainPID,
authenticated inventory/events HTTP 200, Docker availability with current
containers, continued public Console TLS health, and sustained Console and
Telegram polling without the prior profile error.
