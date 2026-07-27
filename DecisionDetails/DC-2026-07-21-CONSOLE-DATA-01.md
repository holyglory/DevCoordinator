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

A database binding remains current after a catalog-discovery failure because
that failure is unknown presence. A completed catalog observation with
`database_absent` is positive absence: the binding and observation remain
durable history but leave normalized current resources, repository scopes, and
current observations until the database is proved present again.

Board and Console consume the same Python-produced repository tree. A current
resource without proved membership remains explicit diagnostic evidence; the
clients do not assign it by similar names or paths. Docker-hosted HTTP services
remain first-class services when the producer proves their container, port,
health, route, and lifecycle relationship.

The Console overview is a latency-sensitive projection, not another observer.
It returns a current snapshot immediately, serves a bounded-stale snapshot
while one coalesced refresh continues, and waits at most 40 ms when the cache
is cold. Every route displayed in that response resolves from the exact same
snapshot; a failed inventory read never fans out into another server or Docker
request. Browser boot starts overview and locally retained metrics together,
so the Performance page can paint machine and history data while current
repository usage is still loading. A few bounded follow-ups collect a newly
warmed snapshot without waiting for the normal poll, and immutable text assets
negotiate Brotli or gzip with encoding-specific validators.

The Tests page has the same independence contract. Repository selection comes
from a lightweight protected-profile catalog, with recently retained project
metrics as a rolling-deployment fallback, and test statistics use a bounded,
repository-scoped cached read. Neither list population nor the first test-data
paint waits for host observation or the heavyweight repository inventory. Its
primary operational view is a seven-day UTC hourly heatmap built from exact
case intervals split across clock-hour boundaries. Parallel intervals add, so
an hour may truthfully exceed 60 aggregate test-minutes; blue covers 0–60,
amber 60–120, and red more than 120, with failures marked independently. The
selected period is compared with the immediately preceding equal period for
daily trend and suite-level dynamics.

Enrollment-only server definitions remain exact control identities for port
leases and assignments. Every current normalized definition is classified
exactly once under its repository scope, but definitions do not enter
compatibility Servers, operational counts, Unassigned Resources, or actions
until a concrete running, starting, unhealthy, stopping, or stopped observation
exists. The authoritative tree is a complete ownership graph, while its usage
fields and compatibility projection remain lifecycle-only. Public TLS
terminates at the Console and routed HTTP/WebSocket traffic goes only to an
explicitly selected application HTTP listener; protocol is never guessed from
a port.

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
- Keep document and overview first-byte work below 100 ms in the ordinary and
  dependency-degraded paths, and keep Performance's first meaningful paint
  independent of the Coordinator so its largest content can render within one
  second on the production route.
- Keep the Tests repository selector and first statistics paint independent of
  inventory, with a one-second authenticated browser regression budget. Lead
  with hourly load, period comparison, pass rate, failed runs, and the largest
  suite dynamics rather than raw record tables.

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
fixing the read model. Deriving authoritative tree membership from
lifecycle-only compatibility usage was also rejected after production schema
activation exposed the contradiction: it left current normalized control
definitions uncovered and correctly triggered the Console's fail-closed
inventory guard. Treating every binding of a running PostgreSQL container as a
current database was likewise rejected: three positively absent historical
databases remained normalized without a repository or explicit ownership
problem, producing the same contract failure.

## Verification contract

Console coordinator, overview first-byte, static-compression,
project-membership, test-dashboard first-paint, DOM-budget, lifecycle, and
canonical artifact tests cover the read model and bounded interface. DevOps Board core and
vertical-layout tests cover exact tree consumption, stable grouping, and center
pane geometry. A producer regression fixture must keep a current definition
with exact control evidence in `resources.servers` and one repository scope,
while proving it remains absent from compatibility servers and project-usage
server IDs without lifecycle evidence. Database fixtures must separately prove
that positive catalog absence exits current resources/tree/observations while
catalog-discovery failure preserves them. Canonical artifacts remain bound to
current renderer inputs and source hashes.

Test statistics fixtures must prove interval splitting at UTC hour boundaries,
parallel aggregation above 3,600 seconds per hour, failure marking, previous
period comparison, and responsive dashboard geometry.

Production verification on 2026-07-26 exercised the authenticated
`/v1/inventory` response with the exact deployed Console
`repositoryTreeContractProblemsOf` validator and returned HTTP 200 with no
problems. The fresh graph classified all 15 normalized server definitions and
all 188 current database bindings exactly once. GlobalFinance retained seven
`validation-port-lease` definitions in normalized resources and its repository
scope while exposing zero compatibility/project-usage servers; two live
running servers and five retained stopped servers remained visible through the
lifecycle projection.
