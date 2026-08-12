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

Schema 15 is the trusted-local model. It contains repositories, direct resource
associations, runtime definitions and observations, leases and port
assignments, operations, tests, cleanup state, and evidence. It does not contain
repository membership, control-binding, local ACL/grant, owner-transfer,
client-enrollment, or group-policy tables.

Migration from schemas 12–14 copies any useful repository association into
current resource rows, removes obsolete local-authorization tables and columns,
and advances the database generation atomically. Fresh databases are created
directly at schema 15.

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
