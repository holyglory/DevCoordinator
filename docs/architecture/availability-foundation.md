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

## Clean adoption

`scripts/clean_adopt_availability.py` installs a host with no prior supported
authority. It:

1. verifies the immutable candidate release and current host topology;
2. creates service-owned state directories and one host-wide routing profile;
3. initializes schema 15 and catalogs configured repositories as operational
   inventory, without owner/member/grant rows;
4. installs and starts the stable services through systemd;
5. verifies the broker, API, Console, test plane, and cross-repository command
   routing from an unrelated local UID;
6. records an exact rollback boundary until readiness is proved.

The host-wide routing profile is readable by local accounts and contains only
the broker socket and database generation. It is not a credential.

## Same-schema delivery

`scripts/software_owned_delivery.py` owns production delivery. It runs the
source validation cycle, packages an immutable release, asks the Coordinator
to perform the runtime transition, verifies stable services and API contracts,
executes production-shaped Console/browser journeys, and preserves rollback
evidence until the new release is healthy.

`scripts/switch_same_schema_release.py` performs the bounded release switch.
It never writes application state directly and never hand-manages processes or
containers. Failed convergence retains exact artifacts and restores the prior
release when the verified rollback contract permits it.

## Schema migration

Schema 15 accepts legacy schemas 12–14 only through the one transactional
trusted-local migration in `devcoordinator/schema.py`. Useful direct repository
association is copied into current resource rows. Obsolete local authorization
tables and columns are then dropped. No bridge daemon, shadow broker, legacy
client enrollment, or dual-write period exists.

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
are verified compatible. User settings and project runtime state are retained;
test history is disposable unless explicitly requested otherwise. Credentials,
logs, backups, runtime state, and acceptance screenshots remain outside Git.

## External boundaries

Trusted-local command access does not weaken public or secret-bearing
boundaries. Google sign-in, public route grants, upstream credentials, Telegram
subscriber approval, non-loopback exposure, and destructive-data confirmation
retain their separate controls. See `security-assumptions.md`.
