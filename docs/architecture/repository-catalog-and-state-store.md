# Repository catalog and state store

## Purpose

DevCoordinator keeps one server-wide SQLite state store. It catalogs local Git
worktrees and the services, containers, ports, tests, and cleanup state that the
Coordinator manages. The catalog is operational metadata, not an access-control
database.

Any trusted local agent can invoke every supported Coordinator command for any
current repository or resource. There are no repository members, grants,
owners, controller permissions, source permissions, client enrollments, or
group policies.

## Repository association

A repository row gives a stable `repo_id`, canonical root, display name,
generation, and lifecycle state. Resources carry `repo_id` directly when they
are associated with a repository. Association is used for presentation,
routing, accounting, execution context, test selection, and cleanup. It never
decides whether the caller is allowed to act.

An observed resource may be unassigned when no exact repository association is
known. It remains visible and may be attached using its exact current identity.
Conflicting path evidence is reported as association ambiguity; it is not an
authorization failure.

## Command routing

The installed client talks to the one server-wide broker. Source and endpoint
metadata are observational routing details only. They are not active-controller
or authoritative-source permissions. A command may fail when its target or
endpoint cannot be resolved, but never because the caller lacks repository
membership or a source grant.

## Correctness controls

Mutations continue to validate:

- exact opaque resource IDs;
- immutable native identity;
- current observation generation for stale-work detection;
- repository and installation generation where lifecycle state depends on it;
- canonical path containment and symlink safety;
- typed payloads, bounded values, idempotency keys, and replay consistency;
- explicit disabled/fenced lifecycle state;
- backup and confirmation requirements for destructive data operations.

These checks prevent stale, malformed, or mis-targeted work. They do not grant
or deny access to a local caller.

## Current schema

Schema 16 is the trusted-local model. It contains repositories, direct resource
associations, runtime definitions and observations, leases and port
assignments, non-secret persistent-server credential bindings, operations,
tests, cleanup state, and evidence. Credential material is not a database
collection. The schema does not contain repository membership, control-binding,
local ACL/grant, owner-transfer, client-enrollment, or group-policy tables.

There is no migration chain or legacy importer. The one reviewed schema-15
boundary rebuilds a fresh schema-16 authority from an exact retained-control
allowlist while writers are stopped, advances mutable control generations, and
discards operations, observations, tests, request history, and retired migration
state. A credential-bearing legacy server environment entry becomes an opaque
binding and an exact root-owned material file outside SQLite; database/profile,
material publication, and rollback are one replayable transaction. Fresh
databases are created directly at schema 16.

## Inventory contract

Normalized inventory schema 3 exposes repositories, resources with direct
`repo_id` association, observations, leases, port assignments, backups, events,
unassigned resources, lifecycle violations, tests, and compatibility data. It
does not expose membership or controller-binding collections.

Board and Console render this graph. They may use an observation endpoint to
send a command to the broker, but they do not calculate authorization and do
not block a command based on an account, repository, group, controller, or
source permission.

## Remaining security boundaries

The trusted-local model does not remove unrelated boundaries. Public Console
identity and route grants, upstream credentials, Telegram subscriber approval,
secret transport, non-loopback exposure, and destructive-data confirmation
remain governed by their own requirements. See
[`security-assumptions.md`](../../security-assumptions.md) and
[`single-developer-local-trust.md`](single-developer-local-trust.md).

Persistent managed-server launch candidates contain only ordered environment
name/credential identifiers. The root manager validates the exact private
material and supplies it to that server's fixed non-root systemd unit with
`LoadCredential`. The runner never returns the value or includes it in a
descriptor, fingerprint, database, profile, journal, or result; it reads the
unit-private credential only at child launch and keeps the value in memory for
child environment injection and log redaction. Missing, extra, substituted, or
unsafe material fails before repository code starts. Literal secret-shaped
environment values, command arguments, and health URLs are rejected at
repository configuration, direct lifecycle, and runtime replacement boundaries.
The replay transaction may retain exact hashes beside the root-readable material
for crash recovery, but CLI and delivery output expose only counts and status.
