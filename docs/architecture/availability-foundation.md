# Availability foundation

## Current delivery model

DevCoordinator is delivered as an immutable release behind stable systemd
units. One server-wide broker owns mutations and lifecycle coordination. The
Console, authenticated API, test plane, observation services, and broker are
separately supervised so one component can restart without erasing retained
state or making unrelated reads unavailable.

The current authority schema is 15 and the current installed routing profile
schema is 2. The local trust model has no repository/account authorization,
membership, controller binding, source permission, client allowlist, or group
policy. A release must not recreate those artifacts.

## Initial installation

The immutable-release installer stages files but does not start or switch a
service. The current-format release switch installs the fixed systemd topology,
creates missing service-owned directories and empty current stores, activates
the release, and verifies health. There is no clean-adoption product, legacy
checkout migration, bridge daemon, handoff listener, or dual-write period.

## Same-schema delivery

`scripts/software_owned_delivery.py` owns production delivery. It runs the
source validation cycle, packages an immutable release, performs the
current-format runtime transition, verifies stable services and API contracts,
executes production-shaped Console/browser journeys, and preserves rollback
evidence until the new release is healthy.

`scripts/switch_same_schema_release.py` performs the bounded release switch.
It never writes application state directly and never hand-manages processes or
containers. Failed convergence retains exact artifacts and restores the prior
release when the verified rollback contract permits it.

## Schema changes

Startup creates schema 16 only for an empty database and refuses every other
schema. There is no in-place upgrade or legacy importer. The one reviewed
schema-15 transition stops every authority writer and direct test-plane reader,
backs up the authority/profile/Console files, rebuilds only the allowlisted
durable controls at schema 16, and can restore the exact predecessor before any
old writer restarts. Operational, observation, test, request, and migration
history does not cross that boundary.

## Readiness

Readiness requires:

- exact release and database generation agreement;
- stable broker/API/Console/test services;
- successful broker and authenticated API canaries;
- current schema and routing profile contracts;
- repository boundary and public-artifact checks;
- complete governed source validation;
- production-shaped browser acceptance;
- no open production bug report related to the delivery;
- no request-related completion-ledger item.

Process liveness alone is not readiness. A failed canary, stale generation,
invalid schema, incomplete cleanup, or unclassified resource is a failure with
retained evidence.

## Rollback and retained state

Releases are immutable and selected by a stable current-release pointer.
Rollback restores that pointer only after the prior release and schema contract
are verified compatible. User settings and project runtime state are retained.
Test history is always disposable and may be reset during delivery. Credentials,
logs, backups, runtime state, and acceptance screenshots remain outside Git.

## External boundaries

Trusted-local command access does not weaken public or secret-bearing
boundaries. Google sign-in, public route grants, upstream credentials, Telegram
subscriber approval, non-loopback exposure, and destructive-data confirmation
retain their separate controls. See `security-assumptions.md`.
