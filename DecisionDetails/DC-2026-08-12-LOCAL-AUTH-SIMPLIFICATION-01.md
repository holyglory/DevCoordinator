# DC-2026-08-12-LOCAL-AUTH-SIMPLIFICATION-01

## Context

The production server is owned by one developer. Its Unix accounts and agents
are attribution, execution, accounting, and crash domains, not mutually
distrusting tenants. The retained broker nevertheless modeled repository-level
cleanup permissions, per-resource ACLs, repository memberships, controller and
source authority, per-account enrollment allowlists, and group policy. Those
records blocked commands that the confirmed trust model intended to allow and
made ordinary lifecycle operations depend on administrator provisioning.

## Decision

Remove local authorization from DevCoordinator. Any trusted local agent may
invoke every supported command against any current resource on the server.
Local request admission does not consult repository, account, UID, GID, group,
action, resource, enrollment, membership, controller, source, or grant records.

Repository association may remain only as optional ordinary data for display,
routing, accounting, execution context, and cleanup scope. It is not called
membership and cannot allow or deny a command. Commands resolve globally unique
immutable resource IDs. Controller/source provenance may remain only as
non-authorizing observation evidence when it has product value.

This does not remove public Console authentication and grants, domain/upstream
authorization, secret isolation, typed payload validation, immutable native
identity, stale generation/fingerprint fences, path containment, idempotent
operation identity, valid lifecycle transitions, non-root execution
attribution, TTL cleanup, crash containment, or explicit confirmation for
destructive retained-data operations. Those controls address external trust,
secrets, stale work, ambiguity, safety, or data retention rather than local
tenant authorization.

## Options and rationale

Keeping the current fine-grained model, merely unioning grants across local
accounts, and removing local authorization entirely were considered. Keeping or
unioning the model preserves extensive schema and code whose only observable
effect on this server is false denial, provisioning work, and failure modes.
Removing it matches the confirmed one-developer threat model and makes the
broker a typed global coordinator instead of a local tenant policy engine.

## Migration and verification

The authority schema and broker/client/API/UI surfaces will remove local ACL,
grant, repository-membership, and controller/source-authorization concepts.
Installed clients may use repository context to discover or group targets, but
exact resource identity is sufficient to operate them. Migration retains
resource, operation, observation, execution, test, cleanup, and tombstone
evidence while translating any needed resource-to-repository association into
ordinary nullable attributes.

Verification exercises the same exact resource from agents in different Unix
accounts and repositories and proves identical command behavior. Negative
tests retain rejection for malformed or oversized payloads, stale identities or
generations, ambiguous selectors, path escapes, replay conflicts, invalid
lifecycle transitions, public access failures, secret-policy violations, and
destructive-data confirmation failures.
