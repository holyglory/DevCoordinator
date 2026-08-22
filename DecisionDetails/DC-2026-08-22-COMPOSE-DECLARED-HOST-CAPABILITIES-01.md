# DC-2026-08-22-COMPOSE-DECLARED-HOST-CAPABILITIES-01

## Context

DevCoordinator already renders and seals a repository's complete Compose model,
pins its images, validates its structure and bounds, and executes it only
through the typed broker. On the confirmed single-developer server, requiring a
second, one-time fingerprint approval solely because that sealed model contains
a host bind mount or `cap_add` created repeated operational friction without
separating mutually distrusting users or repositories. The user explicitly
removed those two approval requirements on 2026-08-22.

## Decision

`host_bind_mount` (the service-level bind-mount classification) and
`added_capabilities` remain truthful effective-model risk
classifications and remain part of immutable model evidence, but they are not
approval-required risks. A model containing either or both can be sealed,
persisted, reconciled and started without an approval row, approval flag,
wrapper call or additional prompt.

This does not remove Compose model parsing, field/type/size validation,
repository declaration, pinned-image checks, exact definition fingerprints,
operation idempotency, replay fencing, lifecycle evidence or broker ownership.
It also does not change the approval boundary for local volume-driver binds
(`volume_driver_bind`), non-loopback/public publication, devices, privileged
mode, host namespaces, Docker-socket access, unconfined security or other
separately classified host-equivalent features.

## Options and rationale

Keeping the fingerprint approval, deleting the entire host-access approval
system, and exempting only bind mounts plus added capabilities were considered.
Keeping it repeats a decision the single developer has already made for routine
declared development models. Deleting the whole system would also remove
distinct public, device, namespace and privileged boundaries that the user did
not retract. The narrow exemption removes the reported friction while keeping
the rest of the established safety contract unchanged.

## Security assumptions and accepted risk

This relies on `security-assumptions.md`: one developer owns the host and its
local repositories/accounts; they are not mutually distrusting tenants. The
developer accepts that a declared bind mount exposes its selected host path with
the declared mount mode and that an added Linux capability expands the
container's kernel authority. Revisit this decision before hosting mutually
distrusting repositories or people. Public identity, secrets, devices,
privileged/host namespace access and non-loopback exposure remain separate
boundaries.

## Verification

Tests seal bind-only, capability-only and combined models without approval
state, then prove enrollment, resealing, first-use bootstrap and replay succeed.
The effective evidence continues to report both risk categories. Negative tests
retain malformed-model, stale-generation, path/model drift, unpinned-image and
all remaining approval-required risk failures. Documentation and packaged
wrappers describe only the risks that still require approval.
