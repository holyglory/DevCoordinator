# DC-2026-07-21-CONSOLE-DATA-01 — Observations and interfaces stay truthful and bounded

## Durable decision

The server-side metrics loop is the sole periodic host observer; explicit
authorization-bound observation remains available, while other consumers read
durable events and snapshots. Exact-project work coalesces, host-wide work is
serialized, retries are scheduled after completion with bounded exponential
backoff, and pure committed-inventory sampling continues without multiplying
observer calls. Inventory itself remains a pure read. Current presence and
telemetry are joined only by immutable resource identity within the host's
latest completed Docker-available snapshot. Observation failure retains the
last committed inventory and reports that it is stale or unavailable rather
than erasing it or inventing fresh state. Retained historical records never
outrank a proven live replacement.

Board and Console consume the same Python-produced repository tree. A current
resource without proved membership remains explicit diagnostic evidence; the
clients do not assign it by similar names or paths. Docker-hosted HTTP services
remain first-class services when the producer proves their container, port,
health, route, and lifecycle relationship.

Enrollment-only server definitions remain exact control identities for port
leases and assignments but do not enter operational Servers, membership,
counts, Unassigned Resources, or actions until a concrete running, starting,
unhealthy, stopping, or stopped observation exists. Public TLS terminates at
the Console and routed HTTP/WebSocket traffic goes only to an explicitly
selected application HTTP listener; protocol is never guessed from a port.

## Presentation direction

- Put the named collection and its honest loading, error, empty, or populated
  state first.
- Keep cached content visible during background refresh. Schedule the next poll
  only after completion, run it only while an aggregate surface is visible, and
  coalesce equivalent work.
- Mount only the active Console page, page large collections, and allow one
  bounded project/server disclosure at a time.
- Keep every nonempty project group discoverable, while responsive rows protect
  resource identity, essential facts, and local actions before optional
  telemetry yields at narrow widths.
- Keep destructive cleanup fail closed until the complete host capability is
  explicitly activated after matching migration and authorization readiness.
- Sort by stable identity and lifecycle fields, never rapidly changing CPU or
  memory samples.
- Collection badges count the collection they name.
- Show global non-nominal status only when current evidence identifies the
  affected resource or operation and a safe route the user can take.
- Keep inventory transport bounded and compact, decode large payloads off the
  native main actor, and retain source-bound production snapshots for wide and
  narrow layouts.

## Alternatives rejected

Pure reads without an observer left removed containers current indefinitely,
while independent periodic observers and short client deadlines created a
retry storm. Treating policies or leases as instances produced phantom
servers, and routing plaintext HTTP to a TLS-only upstream broke the public
route. Joining old samples, filtering by display names, or preferring newest
history regardless of lifecycle invents current state. Rapid start-to-start
polling, loading-state replacement, metric sorting, and unbounded expansion
create high CPU use, permanent Updating badges, clipped content, and unstable
operator focus. Deleting absent history would sacrifice auditability without
fixing the read model.

## Verification contract

Console coordinator, project-membership, DOM-budget, lifecycle, and canonical
artifact tests cover the read model and bounded interface. DevOps Board core and
vertical-layout tests cover exact tree consumption, stable grouping, and center
pane geometry. Canonical artifacts remain bound to current renderer inputs and
source hashes.
