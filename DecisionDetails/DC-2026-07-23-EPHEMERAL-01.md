# Broker-owned ephemeral Docker admission

## Context

A running container appeared under **Unassigned Resources** because Docker had
been invoked before Coordinator had durable repository ownership evidence. A
later name match cannot safely repair that gap: container names are mutable and
another local account can choose the same or a misleading name.

## Decision

All new short-lived agent containers use administrator-sealed repository
templates and the server-wide broker. Before Docker is invoked, the broker
commits the authenticated UID/account, repository and template IDs, a UUID run
ID, an unguessable creation nonce, the exact definition fingerprint, resource
limits, TTL, quota admission, port lease, and cleanup policy. Docker receives
all five ownership values as labels, creates the container stopped, returns its
full immutable ID, and only then may the broker start it.

If Docker accepted create/start but the caller lost the reply, later recording
is permitted only when one container matches all five precommitted labels and
the full immutable identity. This is recovery of an existing authorization
decision, not a new ownership claim. An unrelated already-running container can
be attached only through the explicit administrator journey using fresh
inventory plus its immutable resource, controller, and ownership fingerprints.

Cleanup intent is durable and dominates restart/recovery. A Finish request,
expiry, revocation, crash, safety-profile drift, or a late create observed after
the absence grace period can only progress toward exact stop/removal and lease
release. Generic Docker lifecycle, archive, and route controls cannot mutate a
broker-owned ephemeral container.

## Options considered

- **Infer the repository from the container name.** Rejected because names are
  neither immutable nor authoritative and can cross account/project boundaries.
- **Create first and register by name afterward.** Technically possible but
  rejected as the normal protocol because cancellation, crash, or restart can
  leave a live unattributed workload in the gap.
- **Create first, then recover by full ID without a reservation.** Rejected
  because an ID proves which container exists, not who authorized or owns it.
- **Precommit ownership, create stopped, then start.** Selected because it
  removes the unattributed-running window and makes post-call recovery exact.
- **Allow raw Docker as a parallel agent path.** Retained only as an explicitly
  reported activation blocker while existing workloads migrate; exclusive
  broker admission is required before the prevention guarantee is live.

## Security and operational consequences

- Images are pinned by digest; clients cannot supply images, argv, environment,
  mounts, privileges, capabilities, devices, networks, or Docker flags.
- Inline environment is non-secret configuration; credential-looking fields
  are rejected because manifests and durable state retain these values.
- Template, per-UID, repository CPU/memory/count, and fixed host-wide quotas are
  checked atomically before a run row is inserted.
- Recovery proves the strict safety profile before keeping or starting a found
  container. Cleanup separately requires exact identity but tolerates profile
  drift so it can still disable restart, stop, and remove the resource and its
  anonymous volumes.
- A bounded reaper observes running containers, records crash/failure events,
  cleans early exits, retries with durable backoff, and participates in the
  broker's full shutdown deadline.

## Verification boundary

Deterministic coverage exercises normal start/renew/finish, reply loss,
late-create recovery, partial/mismatched labels, deterministic failure replay,
cleanup-intent survival across stop failures, strict-profile drift, revocation,
expiry, port and quota races, host command redaction, observer attribution,
shutdown drainage, and schema migration. Production activation additionally
requires the controlled broker/schema migration, exact enrollment/profile
verification, removal of direct agent Docker admission, and a live run observed
under its repository rather than **Unassigned Resources**.
