# DC-2026-08-09-STORAGE-CLEANUP-01 — Exact Docker storage retirement

## Context

The project storage inventory already measured containers, images, named
volumes, and build cache. Durable plan/apply supported exact stopped container
cleanup, but a detached Compose volume remained a read-only candidate. Bug
`bug-04d9d6248f2e4879bd0f8d6958cb7a54` recorded that an exclusively owned
project volume could therefore be retired only by bypassing Coordinator.

The confirmed deployment has one developer across local accounts, while
project databases and source may be valuable. Exact identity, project
ownership, stale-request fencing, and explicit destructive approval remain
required mistake-prevention boundaries. See `security-assumptions.md` under
“Assets and sensitivity,” “Credible failures and adversaries,” and “Required
gates.”

## Decision

The stable storage surface supports two apply-capable kinds:

- An exact stopped, unmounted standalone container or Compose one-off.
- An exact named Compose volume that a fresh complete host observation binds
  to one active or retained project claim, whose native Docker labels agree
  with that project, whose created-at/driver/scope plus label and option
  fingerprints form a complete identity, and which has zero container
  references.

Planning persists the repository, exact identity, effects, deleted/retained
data classes, actor, reason, fingerprint, and target-bound confirmation phrase.
Apply reauthorizes the repository, takes another complete host observation,
re-inspects native identity and references, and invokes only `docker rm
<full-container-id>` or `docker volume rm <exact-volume-name>`. It verifies
absence and writes a tombstone generation derived from the exact volume
identity so a lost reply is idempotent while a later recreated same-name
volume remains a distinct target.

No automatic cleanup is introduced. The inventory remains read-only for
images, build cache, shared or unclassified volumes, referenced volumes,
ordinary Compose services, mounted containers, and database-bound containers.
No prune, force removal, anonymous-volume flag, or Compose teardown is used.
The caller still makes the destructive decision by supplying the exact durable
plan fingerprint and generated confirmation phrase. This preserves the
project-data assumption rather than treating discovery as deletion authority.

## Alternatives considered

- Keep volume cleanup read-only: safest but leaves the reported end-to-end
  retirement journey incomplete and forces an authority bypass.
- Run direct `docker volume rm`: exact at the Docker surface but lacks project
  authorization, durable replay, and fresh ownership/identity proof.
- Use `docker compose down --volumes`: couples one object retirement to an
  entire Compose project and can delete unrelated volumes, networks, or
  containers.
- Use Docker prune: target selection and guaranteed reclaim are too broad and
  cannot preserve exact project attribution.
- Add an automatic backup of every volume: would materially expand scope,
  storage cost, restore semantics, and maintenance without a confirmed
  requirement. Explicit plan/apply remains the approved deletion boundary;
  database-bound containers remain separately blocked.

## Verification

The focused regression cycle covers project attribution, stable-client
capabilities and parsing, broker repository authorization, exact host argv,
zero-reference revalidation, wrong/stale identity refusal, durable replay,
identity-scoped tombstones, and the sealed schema-12 to schema-13 constraint
widening. Repository-owned delivery remains the final source, packaging,
deployment, and installed-surface evidence authority.
