# Ready-authority release re-attestation

## Decision

An already-ready schema-12 authority may be rebound to a successor immutable
availability release only through a root-owned, no-mutation re-attestation.
The operation consumes the exact atomic prepared/quiescence seal, original
readiness result, retained verified backup, database identity, schema and
generation, the intentional post-port state revision, active maintenance
marker, and stopped-writer lock. It observes the database through an anchored
descriptor, binds the successor release path and digest, and publishes
mode-0600 sealed intent and result artifacts. Exact replay is permitted;
identity, evidence, database, release, quiescence, or maintenance drift fails
closed.

The re-attestation performs no readiness SQL and no service mutation.
Initialization consumes the post-reservation result and rechecks its referenced
evidence while the writer remains stopped.

## Why

The original empty-to-ready transaction cannot truthfully be rerun against an
already-populated ready authority. A second service-wrapped migration would add
mutation and outage risk without changing database state. Reusing only the
pre-port readiness result would leave the deliberately committed port
reservation outside the authority state bound to first adoption.

Descriptor-anchored read-only re-attestation was selected because it preserves
the already-proven database, covers the complete post-port state, detects path
replacement and time-of-check/time-of-use drift, and gives cutover an immutable
release binding without broadening the transaction's authority.

## Verification contract

- Normal and optimized focused tests cover success, exact replay, interrupted
  intent recovery, missing or tampered prior evidence, backup and release
  drift, active-writer and maintenance failures, non-ready schema state,
  database inode replacement, descriptor path races, and operation-level
  time-of-check/time-of-use changes.
- Tests assert that no SQL write or service mutation occurs.
- Fresh initialization and atomic finalization consume the post-port
  re-attestation rather than silently accepting the older readiness boundary.
