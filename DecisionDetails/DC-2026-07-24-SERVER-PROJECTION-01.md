# DC-2026-07-24-SERVER-PROJECTION-01 — Server collections require lifecycle evidence

## Decision

Keep enrolled server definitions available as normalized control identities for
exact port lease and assignment authorization, but project a server instance
only after the Coordinator has a concrete lifecycle observation. Operational
collections accept `running`, `starting`, `unhealthy`, `stopping`, or `stopped`;
unknown and `unobserved` definitions do not enter Servers, Projects,
`project_usage.server_ids`, running counts, Unassigned Resources, routes, or
server controls. The Console repeats this predicate so a rolling upgrade does
not expose older broker output.

Actual retained servers continue to use the existing exact Archive/Restore and
Purge lifecycles. Short-lived containers use the broker-owned ephemeral
Start/Status/Renew/Finish state machine. A port lease TTL is not represented as
a temporary server and does not promise automatic process termination.

## Why

The GlobalFinance runtime deliberately declares seven names with role
`validation-port-lease`; smoke automation uses their immutable definition IDs
to acquire and release preferred validation ports. On 2026-07-24, server-wide
inventory showed every definition with no PID, port, URL, command, log, or
process fingerprint and status `unobserved`. A fresh full-Docker observation
completed at revision 15349, after which exact `server status` lookups found no
matching operational server. The rows existed only because
`_current_server_resource_ids` treated broker ACL and port-policy evidence as
current management evidence and the compatibility projector reused that set as
physical server membership.

Deleting or archiving the definitions would break the exact lease ACLs; a UI
hide preference would keep false data semantics; matching the project-specific
role string would be brittle; and treating every non-`stopped` status as
running inflated the group to `7 of 7 running`. A separate compatibility
instance predicate retains the normalized definitions and lease workflow while
making current server collections reflect real runtime evidence. Focused
must-catch tests cover broker-policy-only and assignment-only definitions, and
the Console rejects unobserved rows even when an older producer still emits
them.
